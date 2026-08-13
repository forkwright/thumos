#!/usr/bin/env bash
set -euo pipefail

# kernel-host-tests.sh — kernel i686 host test suite (#546). The kernel crate
# is excluded from the workspace, so its host unit tests (i686, u32-faithful
# ABI) run against the 32-bit target. Shared by ci.yml and .kanon-ci.toml so
# the admission gate and the PR gate execute the identical suite.
#
# WHY --locked (#757): crates/thumos keeps its own lockfile; without --locked
# a manifest/lock disagreement here is silently resolved and rewritten
# instead of failing the build.

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

pass1=0
(cd "$KERNEL_DIR" && cargo nextest run --bin thumos --target i686-unknown-linux-gnu --locked \
    --build-jobs "${THUMOS_BUILD_JOBS:-8}" --test-threads "${THUMOS_TEST_THREADS:-8}") || pass1=$?

# WHY (#459): the debug console is now host-testable (heap/page/process stub
# pattern), but its tests only exist under `--features debug-console`. A
# second pass runs them — and asserts they actually execute, since this class
# of bug is "tests never ran" (the gate left them dead source for weeks).
pass2=0
out=$(cd "$KERNEL_DIR" && cargo nextest run --bin thumos --target i686-unknown-linux-gnu --locked \
    --features debug-console --build-jobs "${THUMOS_BUILD_JOBS:-8}" --test-threads "${THUMOS_TEST_THREADS:-8}" 2>&1) || pass2=$?
printf '%s\n' "$out"
# WHY a herestring, not a pipe: under `set -o pipefail`, `printf | grep -q`
# returns 141 when grep exits on the first match and printf dies of SIGPIPE —
# the guard would fire on the very success it checks for (#459's own witness).
grep -q 'console::tests' <<<"$out" || {
    echo "FAIL #459: --features debug-console pass ran zero console::tests — the tests are dead again" >&2
    exit 1
}
# WHY (#616): pass1/pass2 are captured via `|| pass=$?`, not left to fall out
# the bottom — without that, the script's own exit code was the grep's,
# letting a failing test pass ship rc=0 to CI. The explicit capture is also
# what keeps both passes running to completion under `set -e` (a red main
# pass must not hide the debug-console witness output).
if [[ "$pass1" -ne 0 ]] || [[ "$pass2" -ne 0 ]]; then
    echo "FAIL: kernel host tests failed (main pass rc=$pass1, debug-console pass rc=$pass2)" >&2
    exit 1
fi
