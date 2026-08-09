#!/usr/bin/env bash
# kernel-clippy.sh — kernel crate clippy gate (#663). The kernel crate is
# excluded from the workspace, so every --workspace clippy invocation in the
# repo silently skips it. Shared by ci.yml and .kanon-ci.toml so the
# admission gate and the PR gate execute the identical check.
set -uo pipefail

REPO_ROOT=$(git rev-parse --show-toplevel)
KERNEL_DIR="${THUMOS_KERNEL_DIR:-$REPO_ROOT/crates/thumos}"

rustup target list --installed 2>/dev/null | grep -q '^i686-unknown-linux-gnu$' || {
    echo "FAIL: rust target i686-unknown-linux-gnu not installed (rustup target add i686-unknown-linux-gnu)" >&2
    exit 1
}
# WHY the cd: cargo discovers Cargo.toml from the INVOCATION cwd, and the
# kernel crate has no host target -- clippy must be pointed at i686
# explicitly from inside crates/thumos, the same way kernel-host-tests.sh
# and kernel-build.sh do.
# WHY --bin + --tests, not --all-targets (#673): --all-targets is additive,
# not a narrowing of --bin -- it drags in examples/qemu_smoke.rs, an armv7
# QEMU smoke test that references ARM registers (r0/r1) and cannot compile
# for i686 by construction. That is a defect in the gate, not debt in the
# crate: a gate with a guaranteed-red target trains people to ignore it.
# --tests covers the #[cfg(test)] unit tests kernel-host-tests.sh exercises
# on this exact target; build.rs stays in scope regardless of target
# selection, since a build script is always a prerequisite of the bin.
#
# WHY a second, --features qemu pass (#672): the pass above never sets that
# feature, so every #[cfg(feature = "qemu")] item is stripped before clippy
# ever sees it -- a lint cannot report on code the compiler never compiled.
# kardia.rs::firewall_boot_smoke carried the identical `uptime_ms() as i64`
# pattern as three already-fixed siblings and never appeared on any #672
# site list, purely because of this gap. The second pass reuses the i686
# target already built above (incremental, not a fresh cross-compile), so
# it is comparatively cheap. Each pass's output is tagged with its own
# configuration below so a merged list does not reintroduce, one level
# down, the same ambiguity #672 exists to close.
(cd "$KERNEL_DIR" && cargo clippy --bin thumos --tests --target i686-unknown-linux-gnu -- -D warnings) 2>&1 \
    | sed 's/^/[default] /'
pass1=${PIPESTATUS[0]}

(cd "$KERNEL_DIR" && cargo clippy --bin thumos --tests --features qemu --target i686-unknown-linux-gnu -- -D warnings) 2>&1 \
    | sed 's/^/[qemu]    /'
pass2=${PIPESTATUS[0]}

if [ "$pass1" -ne 0 ] || [ "$pass2" -ne 0 ]; then
    echo "FAIL: kernel clippy failed (default config rc=$pass1, --features qemu config rc=$pass2)" >&2
    exit 1
fi
