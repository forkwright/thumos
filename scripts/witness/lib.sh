#!/usr/bin/env bash
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

set -uo pipefail

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
build_kernel() {
    local features="${1:-qemu}"
    (cd "$KERNEL_DIR" && cargo build --release --target armv7a-none-eabi --features "$features" --jobs "${THUMOS_BUILD_JOBS:-8}") \
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
