#!/usr/bin/env bash
set -euo pipefail

# witness/lib.sh — shared helpers for the kernel QEMU witness scripts (#546).
# Source, don't execute. Every witness script preserves the exact assertions of
# the ci.yml kernel job it was extracted from; edit assertions in ONE place
# (here or the owning script), never in ci.yml/.kanon-ci.toml — the extraction
# guard (scripts/check-witness-extraction.sh) fails on inline drift.
#
# Contract for callers (ci.yml steps, .kanon-ci.toml stages):
#   THUMOS_KERNEL_DIR  — path to crates/thumos (default: <repo>/crates/thumos)
#   THUMOS_QEMU_TIMEOUT — runner timeout seconds (default: 60)
#   THUMOS_INIT_VARIANT — init-harness variant for probe scripts
# Exit codes: 0 pass; non-zero fail with a named assertion (never a bare timeout).
#
# WARNING: under `set -e`, `x=$(grep -c pat log)` or a piped
# `x=$(grep -oE pat log | head -1 | grep -oE '[0-9]+')` aborts the WHOLE
# script at the assignment when the pattern has zero matches (grep's/the
# pipe's nonzero status is the assignment's own status) — before the
# caller's own `test "$x" -eq N || { echo FAIL...; exit 1; }` ever runs,
# losing the named assertion. Callers that read a count/value this way
# before testing it guard the assignment with `|| true` so the intended
# custom FAIL message still fires.

set -euo pipefail

REPO_ROOT=$(git rev-parse --show-toplevel)
KERNEL_DIR="${THUMOS_KERNEL_DIR:-$REPO_ROOT/crates/thumos}"
RUNNER="$REPO_ROOT/scripts/qemu-runner.sh"
TIMEOUT="${THUMOS_QEMU_TIMEOUT:-60}"
BIN=target/armv7a-none-eabi/release/thumos

witness_deps() {
    command -v qemu-system-arm >/dev/null || {
        echo "FAIL: qemu-system-arm not installed (ubuntu: apt-get install qemu-system-arm; fedora: dnf install qemu-system-arm)" >&2
        exit 1
    }
    rustup target list --installed 2>/dev/null | grep -q '^armv7a-none-eabi$' || {
        echo "FAIL: rust target armv7a-none-eabi not installed (rustup target add armv7a-none-eabi)" >&2
        exit 1
    }
    [[ -x "$RUNNER" ]] || { echo "FAIL: runner missing/not executable: $RUNNER" >&2; exit 1; }
}

# build_kernel <feature-flags> — release cross-compile for the qemu board.
#
# WHY it delegates rather than calling cargo: kernel-build.sh is the one place
# the kernel is built, because it strips RUSTFLAGS from the environment. An env
# RUSTFLAGS REPLACES the rustflags in crates/thumos/.cargo/config.toml rather
# than merging, so a direct cargo call here builds without the link script and
# without the -D warnings gate whenever the caller's environment carries one.
# The --target, --locked (#757) and jobs handling live there too.
build_kernel() {
    local features="${1:-qemu}"
    "$REPO_ROOT/scripts/kernel-build.sh" "$features" \
        || { echo "FAIL: kernel build failed (features=$features)"; exit 1; }
}

# run_qemu <logfile> — run the built image, print the log always, return runner rc.
run_qemu() {
    local log="$1"
    local rc=0
    (cd "$KERNEL_DIR" && THUMOS_INIT_VARIANT="${THUMOS_INIT_VARIANT:-}" THUMOS_QEMU_TIMEOUT="$TIMEOUT" \
        "$RUNNER" "$BIN") | tee "$log" || rc=$?
    echo "=== $log (runner rc=$rc) ==="; cat "$log"; echo "=== end $log ==="
    return "$rc"
}

# start_pylon_bridge [pylon-bridge args...] — build + launch the host
# pylon-bridge (crates/metaxu, pylon-bin feature) FIRST (deterministic
# ordering, #544): it binds its listener and prints its port BEFORE qemu
# starts, so the guest's outbound UART1 TCP client never races an unbound
# host socket. Extra args pass through to the pylon-bridge binary (e.g.
# --tamper-mac, #544 negative-case witness). Sets PYLON_LOG, PYLON_PID,
# PYLON_PORT for the caller.
#
# WHY --locked (#757): this resolves against the root workspace lockfile;
# without --locked a manifest/lock disagreement is silently resolved and
# rewritten instead of failing the build.
start_pylon_bridge() {
    (cd "$REPO_ROOT" && cargo build --release --locked --features metaxu/pylon-bin --bin pylon-bridge \
        --jobs "${THUMOS_BUILD_JOBS:-8}") \
        || { echo "FAIL: pylon-bridge build failed"; exit 1; }
    local bin="$REPO_ROOT/target/release/pylon-bridge"
    [[ -x "$bin" ]] || { echo "FAIL: pylon-bridge binary missing at $bin"; exit 1; }
    PYLON_LOG=$(mktemp)
    "$bin" "$@" >"$PYLON_LOG" 2>&1 &
    PYLON_PID=$!
    PYLON_PORT=""
    for _ in $(seq 1 50); do
        if grep -q '^PYLON_PORT=' "$PYLON_LOG" 2>/dev/null; then
            PYLON_PORT=$(grep '^PYLON_PORT=' "$PYLON_LOG" | head -1 | cut -d= -f2)
            break
        fi
        kill -0 "$PYLON_PID" 2>/dev/null || { echo "FAIL: pylon-bridge exited before printing its port"; cat "$PYLON_LOG"; exit 1; }
        sleep 0.1
    done
    [[ -n "$PYLON_PORT" ]] || { echo "FAIL: pylon-bridge never printed PYLON_PORT="; cat "$PYLON_LOG"; exit 1; }
    echo "=== pylon-bridge listening on 127.0.0.1:$PYLON_PORT (pid $PYLON_PID) ==="
}

# stop_pylon_bridge — terminate the process started by start_pylon_bridge.
# Idempotent (safe on an already-dead PID). Does NOT touch PYLON_LOG: a
# negative-case witness asserts on its content (or the absence of a marker
# line) after stopping, before removing it.
stop_pylon_bridge() {
    kill "$PYLON_PID" 2>/dev/null || true  # WHY: idempotent -- PID may already be dead
}
