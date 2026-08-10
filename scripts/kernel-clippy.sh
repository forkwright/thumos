#!/usr/bin/env bash
# kernel-clippy.sh — kernel crate clippy gate (#663, #704). The kernel crate is
# excluded from the workspace, so every --workspace clippy invocation in the
# repo silently skips it. Shared by ci.yml and .kanon-ci.toml so the
# admission gate and the PR gate execute the identical check.
set -uo pipefail

REPO_ROOT=$(git rev-parse --show-toplevel)
KERNEL_DIR="${THUMOS_KERNEL_DIR:-$REPO_ROOT/crates/thumos}"
MANIFEST="$KERNEL_DIR/Cargo.toml"

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
# WHY per-feature passes, not one --workspace-style invocation (#672, #704):
# a feature that is never SET never has its #[cfg(feature = "...")] code
# handed to clippy at all -- a lint cannot report on code the compiler never
# compiled. kardia.rs::firewall_boot_smoke carried the identical
# `uptime_ms() as i64` pattern as three already-fixed siblings and never
# appeared on any #672 site list, purely because the qemu-gated pass did not
# exist yet. #704 generalises this from 2 hand-written invocations to one
# per declared feature so the same gap cannot reopen one feature at a time.

# WHY parsed, not restated (#704): the [features] table in Cargo.toml is the
# single source of truth for which configurations exist. A feature added
# there without a matching pass here must be a parse-time fact, not a
# silent gap -- the exact shape #704 exists to close (#672 closed at zero
# findings across only 2 of the 6 features declared at the time).
mapfile -t KERNEL_FEATURES < <(
    awk '
        /^\[features\]/ { infeat = 1; next }
        /^\[/            { infeat = 0 }
        infeat && match($0, /^[A-Za-z0-9_-]+/) { print substr($0, RSTART, RLENGTH) }
    ' "$MANIFEST"
)
[ "${#KERNEL_FEATURES[@]}" -gt 0 ] || {
    echo "FAIL: parsed zero features from $MANIFEST's [features] table -- the awk parser or the manifest shape drifted" >&2
    exit 1
}

# WHY this envelope, not all 64 combinations (#704): 6 features is 64
# combinations -- exhaustive coverage is a build-time question, not a
# correctness one. This script runs [default] (no features) plus exactly
# one pass per declared feature, EXCEPT where the feature is never built any
# other way in this repo, in which case it is paired with its required
# companion instead of tested alone:
#   - kfault-probe, crashloop-probe: only ever built with qemu, in
#     scripts/witness/{kfault,crashloop}.sh -- their Cargo.toml comments say
#     "only meaningful with qemu", and for kfault-probe that is structural:
#     its one feature-gated site (kinit.rs) is ALSO target_arch = "arm"-
#     gated, so a solo i686 pass would exercise zero additional code and
#     silently look like coverage it is not.
#   - metaxu-probe: CANNOT build alone -- main.rs's own
#     `#[cfg(all(feature = "metaxu-probe", not(feature = "qemu")))]
#     compile_error!` refuses it.
# debug-console and production are the two features this repo DOES build
# standalone (kernel-host-tests.sh; scripts/witness/trust-anchor.sh), so
# they get solo passes, same as qemu itself falls out of this loop as a
# solo pass identical to the original #672 invocation.
# NOT covered: every other multi-feature combination this repo does not
# build anywhere (e.g. qemu+kfault-probe+crashloop-probe together). A
# future feature with no entry below is picked up as its own solo pass
# automatically -- silence here means "buildable alone", not "unseen".
declare -A REQUIRES=(
    [kfault-probe]="qemu"
    [crashloop-probe]="qemu"
    [metaxu-probe]="qemu"
)

declare -a PASS_TAGS=("default")
declare -a PASS_FEATURES=("")
for f in "${KERNEL_FEATURES[@]}"; do
    if [ -n "${REQUIRES[$f]:-}" ]; then
        PASS_TAGS+=("${REQUIRES[$f]}+$f")
        PASS_FEATURES+=("${REQUIRES[$f]},$f")
    else
        PASS_TAGS+=("$f")
        PASS_FEATURES+=("$f")
    fi
done

# WHY (#233, #704): `production` is refused at build.rs time without a
# provisioned THUMOS_BOOT_KEY_PUB -- a deliberate security invariant
# (scripts/witness/trust-anchor.sh proves keyless-refuse, dev-key-refuse,
# real-key-accept). A keyless clippy pass under this feature would be a
# permanent by-design build.rs failure, not a lint finding, so this
# provisions the same shape of throwaway ephemeral key trust-anchor.sh
# proves a real key is accepted with, generated lazily (only if a
# `production` pass is actually in the list above) and scoped to this run.
PRODUCTION_KEY_DIR=""
production_key() {
    if [ -z "$PRODUCTION_KEY_DIR" ]; then
        PRODUCTION_KEY_DIR=$(mktemp -d)
        openssl genpkey -algorithm ed25519 -out "$PRODUCTION_KEY_DIR/ci-boot.pem" 2>/dev/null
        openssl pkey -in "$PRODUCTION_KEY_DIR/ci-boot.pem" -pubout -outform DER \
            | tail -c 32 | od -An -tx1 | tr -d ' \n' > "$PRODUCTION_KEY_DIR/ci-boot.pub"
    fi
    printf '%s' "$PRODUCTION_KEY_DIR/ci-boot.pub"
}
cleanup() { [ -n "$PRODUCTION_KEY_DIR" ] && rm -rf "$PRODUCTION_KEY_DIR"; }
trap cleanup EXIT

# WHY dynamic column width, not the original hand-picked padding (#704):
# the original [default]/[qemu] tags were manually padded to line up. That
# does not scale to a feature-derived tag list of unknown length, so the
# width is computed from whatever tags actually exist this run.
tagwidth=0
for t in "${PASS_TAGS[@]}"; do
    [ "${#t}" -gt "$tagwidth" ] && tagwidth=${#t}
done

declare -a RCS=()
for i in "${!PASS_TAGS[@]}"; do
    tag="${PASS_TAGS[$i]}"
    features="${PASS_FEATURES[$i]}"
    label=$(printf '[%s]' "$tag")
    label=$(printf '%-*s' "$((tagwidth + 3))" "$label")

    if [ "$tag" = "production" ]; then
        out=$(cd "$KERNEL_DIR" && THUMOS_BOOT_KEY_PUB="$(production_key)" cargo clippy --bin thumos --tests \
            --features "$features" --target i686-unknown-linux-gnu -- -D warnings 2>&1)
    elif [ -n "$features" ]; then
        out=$(cd "$KERNEL_DIR" && cargo clippy --bin thumos --tests \
            --features "$features" --target i686-unknown-linux-gnu -- -D warnings 2>&1)
    else
        out=$(cd "$KERNEL_DIR" && cargo clippy --bin thumos --tests \
            --target i686-unknown-linux-gnu -- -D warnings 2>&1)
    fi
    rc=$?
    printf '%s\n' "$out" | sed "s/^/${label}/"
    RCS+=("$rc")
done

failures=()
for i in "${!PASS_TAGS[@]}"; do
    [ "${RCS[$i]}" -ne 0 ] && failures+=("${PASS_TAGS[$i]} rc=${RCS[$i]}")
done

if [ "${#failures[@]}" -gt 0 ]; then
    IFS=', '
    echo "FAIL: kernel clippy failed (${failures[*]})" >&2
    exit 1
fi
