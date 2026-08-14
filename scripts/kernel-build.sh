#!/usr/bin/env bash
set -euo pipefail

# kernel-build.sh — canonical kernel cross-compile (#546). crates/thumos/
# .cargo/config.toml already pins the armv7a target, the link script, and the
# -D warnings zero-warning gate (#431), so the canonical build is a plain
# release build from the kernel directory. NEVER pass RUSTFLAGS through the
# environment — env rustflags CLOBBER the config's and silently drop the
# zero-warning gate (the live drift this script exists to kill).
#
# Usage: kernel-build.sh [feature[,feature...]]
#
# WHY this is the ONE place the kernel is built: an env RUSTFLAGS REPLACES the
# config's rustflags rather than merging with them, so a kernel build that
# inherits the variable loses BOTH the link script and the zero-warning gate.
# Only the link loss is loud (undefined linker symbols); a dropped warning gate
# ships silently. A single stripped invocation is the only shape that keeps that
# true, and check-kernel-build-entrypoint.sh fails the gate if a second appears.
#
# WHY --locked (#757): crates/thumos keeps its own lockfile; without --locked
# a manifest/lock disagreement here is silently resolved and rewritten
# instead of failing the build.

REPO_ROOT=$(git rev-parse --show-toplevel)
KERNEL_DIR="${THUMOS_KERNEL_DIR:-$REPO_ROOT/crates/thumos}"
FEATURES="${1:-}"

rustup target list --installed 2>/dev/null | grep -q '^armv7a-none-eabi$' || {
    echo "FAIL: rust target armv7a-none-eabi not installed (rustup target add armv7a-none-eabi)" >&2
    exit 1
}
ARGS=(build --release --locked --jobs "${THUMOS_BUILD_JOBS:-8}")
if [[ -n "$FEATURES" ]]; then
    ARGS+=(--features "$FEATURES")
fi
# WHY the cd: cargo discovers .cargo/config.toml from the INVOCATION cwd, not
# from --manifest-path's directory. Building from anywhere but the kernel dir
# silently drops the armv7a target, the link script, and the -D warnings gate.
(cd "$KERNEL_DIR" && env -u RUSTFLAGS cargo "${ARGS[@]}")
