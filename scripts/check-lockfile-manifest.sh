#!/usr/bin/env bash
set -euo pipefail

# check-lockfile-manifest.sh — drift guard for the lockfile scan manifest (#547).
# Fails when the tracked Cargo.lock set and scripts/lockfile-scan-manifest.txt
# disagree in either direction: an unscanned new lockfile, or a manifest entry
# whose lockfile no longer exists.

repo=$(git rev-parse --show-toplevel)
manifest="$repo/scripts/lockfile-scan-manifest.txt"

drift=$(comm -3 \
    <(git -C "$repo" ls-files -- '*Cargo.lock' | sort) \
    <(grep -vE '^[[:space:]]*(#|$)' "$manifest" | cut -d'|' -f1 | sed 's/[[:space:]]//g' | sort))
if [[ -n "$drift" ]]; then
    printf 'lockfile-scan manifest drift — every tracked Cargo.lock must be classified in %s:\n%s\n' \
        "$manifest" "$drift" >&2
    exit 1
fi
printf 'lockfile-scan manifest: %d graphs classified, no drift\n' \
    "$(git -C "$repo" ls-files -- '*Cargo.lock' | wc -l)"
