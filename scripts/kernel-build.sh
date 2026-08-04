#!/usr/bin/env bash
# kernel-build.sh — canonical kernel cross-compile (#546). crates/thumos/
# .cargo/config.toml already pins the armv7a target, the link script, and the
# -D warnings zero-warning gate (#431), so the canonical build is a plain
# release build from the kernel directory. NEVER pass RUSTFLAGS through the
# environment — env rustflags CLOBBER the config's and silently drop the
# zero-warning gate (the live drift this script exists to kill).
set -uo pipefail

REPO_ROOT=$(git rev-parse --show-toplevel)
KERNEL_DIR="${THUMOS_KERNEL_DIR:-$REPO_ROOT/crates/thumos}"

rustup target list --installed 2>/dev/null | grep -q '^armv7a-none-eabi$' || {
    echo "FAIL: rust target armv7a-none-eabi not installed (rustup target add armv7a-none-eabi)" >&2
    exit 1
}
# WHY the cd: cargo discovers .cargo/config.toml from the INVOCATION cwd, not
# from --manifest-path's directory. Building from anywhere but the kernel dir
# silently drops the armv7a target, the link script, and the -D warnings gate.
(cd "$KERNEL_DIR" && env -u RUSTFLAGS cargo build --release --jobs "${THUMOS_BUILD_JOBS:-8}")
