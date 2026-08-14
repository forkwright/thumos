#!/usr/bin/env bash
set -euo pipefail

# check-kernel-build-entrypoint.sh — the kernel is built in exactly one place.
#
# WHY: an env RUSTFLAGS REPLACES the rustflags in crates/thumos/.cargo/
# config.toml rather than merging with them, so any kernel build inheriting the
# variable loses both `-C link-arg=-Tlink.ld` and the `-D warnings` gate (#431).
# Only the link loss is loud. A dropped warning gate ships a warning-carrying
# kernel with every check still green, which is the drift kernel-build.sh (#546)
# exists to kill — and a guard that holds at one site while a second site builds
# unguarded is not a guard, it is a coincidence.
#
# The rule is deny-by-default: every `cargo build`/`cargo rustc` under scripts/
# must either BE the entrypoint or be listed in ALLOWED below with a reason.
# Matching the cargo call itself (not the kernel path next to it) is deliberate
# — a build that reaches the kernel dir through a variable, a helper, or a
# continued line is still caught.
#
# What this CANNOT see: a kernel build outside scripts/ (a workflow `run:` step
# calling cargo directly, or a Makefile). Those are covered by review, not here.

REPO_ROOT=$(git rev-parse --show-toplevel)
cd "$REPO_ROOT"

ENTRYPOINT="scripts/kernel-build.sh"
SELF="scripts/check-kernel-build-entrypoint.sh"

# Substrings that mark a cargo build as NOT a kernel build. Each needs a reason.
#   pylon-bridge: a host binary built from the root workspace, which declares no
#   .cargo/config.toml rustflags — there is nothing for an env RUSTFLAGS to
#   clobber, and `-D warnings` on the host build is wanted.
ALLOWED=("--bin pylon-bridge")

[[ -f "$ENTRYPOINT" ]] || { echo "FAIL: missing $ENTRYPOINT" >&2; exit 1; }

# The entrypoint must still carry the guard and still build. Without these two
# assertions the check passes while the thing it protects has been gutted.
grep -q 'env -u RUSTFLAGS' "$ENTRYPOINT" || {
    echo "FAIL: $ENTRYPOINT no longer strips RUSTFLAGS from the environment" >&2
    echo "      That strip is the whole mechanism: env rustflags REPLACE the config's." >&2
    exit 1
}
grep -qE '(^|[^#])(ARGS=\(build|cargo build)\b' "$ENTRYPOINT" || {
    echo "FAIL: $ENTRYPOINT no longer runs a cargo build -- it is not an entrypoint" >&2
    exit 1
}

# Refuse to pass vacuously: if the scan matches nothing, the pattern is wrong.
scanned=$(find scripts -name '*.sh' -type f | wc -l)
(( scanned >= 2 )) || {
    echo "FAIL: scanned $scanned script(s) -- refusing to report a clean tree" >&2
    exit 1
}

offenders=""
while IFS= read -r hit; do
    [[ -z "$hit" ]] && continue
    [[ "$hit" == "$ENTRYPOINT":* ]] && continue
    # WHY self-exclusion: this file describes the rule in prose and in its own
    # failure messages, so it matches its own pattern. It invokes no cargo.
    [[ "$hit" == "$SELF":* ]] && continue
    # A comment ABOUT a kernel build is not a kernel build.
    [[ "${hit#*:*:}" =~ ^[[:space:]]*# ]] && continue
    allowed=0
    for pattern in "${ALLOWED[@]}"; do
        [[ "$hit" == *"$pattern"* ]] && { allowed=1; break; }
    done
    (( allowed )) || offenders+="$hit"$'\n'
done < <(grep -rn --include='*.sh' -E '\bcargo[[:space:]]+(build|rustc)\b' scripts/ || true)

if [[ -n "$offenders" ]]; then
    echo "FAIL: cargo build outside $ENTRYPOINT (env RUSTFLAGS would replace the kernel's config rustflags):" >&2
    printf '%s' "$offenders" >&2
    echo "      Route it through $ENTRYPOINT, or add it to ALLOWED with a reason." >&2
    exit 1
fi

echo "OK: kernel builds route through $ENTRYPOINT (scanned $scanned scripts)"
