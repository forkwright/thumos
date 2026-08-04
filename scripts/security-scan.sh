#!/usr/bin/env bash
# security-scan.sh <deny|audit|osv> [osv-binary] — run one scanner over every
# graph in scripts/lockfile-scan-manifest.txt (#547). One code path per tool so
# findings are attributed per-graph and no graph can be silently skipped.
# Exclusion lines (`| excluded: reason`) are honored and reported, not scanned.
set -euo pipefail

mode="${1:?usage: security-scan.sh <deny|audit|osv> [osv-binary]}"
repo=$(git rev-parse --show-toplevel)
manifest="$repo/scripts/lockfile-scan-manifest.txt"
rc=0

while IFS='|' read -r lockfile label disposition; do
    case "$lockfile" in ''|\#*) continue ;; esac
    lockfile=$(printf '%s' "$lockfile" | sed 's/[[:space:]]//g')
    label=$(printf '%s' "$label" | sed 's/^ *//; s/ *$//')
    disposition=$(printf '%s' "$disposition" | sed 's/^ *//; s/ *$//')
    case "$disposition" in
        excluded:*)
            printf '== %s (%s) — EXCLUDED: %s\n' "$lockfile" "$label" "${disposition#excluded: }"
            continue
            ;;
    esac
    printf '== %s (%s)\n' "$lockfile" "$label"
    case "$mode" in
        deny)
            manifest_dir=$(dirname "$lockfile")
            cargo deny --manifest-path "$repo/$manifest_dir/Cargo.toml" \
                check --config "$repo/deny.toml" advisories licenses bans sources || rc=1
            ;;
        audit)
            # .cargo/audit.toml at the repo root holds the ignore SSOT; advisory
            # ignores are inert on graphs that do not contain the crate.
            (cd "$repo" && cargo audit --file "$lockfile" \
                --deny unmaintained --deny unsound --deny yanked) || rc=1
            ;;
        osv)
            osv_bin="${2:?osv mode needs the scanner binary path as \$2}"
            "$osv_bin" --lockfile="$repo/$lockfile" --config="$repo/osv-scanner.toml" || rc=1
            ;;
        *)
            printf 'unknown mode: %s\n' "$mode" >&2
            exit 2
            ;;
    esac
done < "$manifest"

exit "$rc"
