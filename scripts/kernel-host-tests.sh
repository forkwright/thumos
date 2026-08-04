#!/usr/bin/env bash
# kernel-host-tests.sh — kernel i686 host test suite (#546). The kernel crate
# is excluded from the workspace, so its host unit tests (i686, u32-faithful
# ABI) run against the 32-bit target. Shared by ci.yml and .kanon-ci.toml so
# the admission gate and the PR gate execute the identical suite.
set -uo pipefail

REPO_ROOT=$(git rev-parse --show-toplevel)
KERNEL_DIR="${THUMOS_KERNEL_DIR:-$REPO_ROOT/crates/thumos}"

rustup target list --installed 2>/dev/null | grep -q '^i686-unknown-linux-gnu$' || {
    echo "FAIL: rust target i686-unknown-linux-gnu not installed (rustup target add i686-unknown-linux-gnu)" >&2
    exit 1
}
# Linking the i686 test binary needs the multilib crt objects. Probe the real
# capability (distros scatter 32-bit libc paths too widely to file-guess):
# compile + link a trivial i686 program.
probe_dir=$(mktemp -d)
printf 'fn main() {}\n' > "$probe_dir/probe.rs"
if ! rustc --target i686-unknown-linux-gnu "$probe_dir/probe.rs" -o "$probe_dir/probe" 2>"$probe_dir/err.log"; then
    echo "FAIL: 32-bit link support missing (ubuntu: gcc-multilib; fedora: glibc-devel.i686):" >&2
    cat "$probe_dir/err.log" >&2
    rm -rf "$probe_dir"
    exit 1
fi
rm -rf "$probe_dir"
command -v cargo-nextest >/dev/null || { echo "FAIL: cargo-nextest not installed" >&2; exit 1; }

(cd "$KERNEL_DIR" && cargo nextest run --bin thumos --target i686-unknown-linux-gnu \
    --build-jobs "${THUMOS_BUILD_JOBS:-8}" --test-threads "${THUMOS_TEST_THREADS:-8}")
