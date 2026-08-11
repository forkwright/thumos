#!/usr/bin/env bash
set -euo pipefail

# check-pr-title.sh — validates a PR title against the conventional-commit
# grammar (#665). The repo squash-merges, so the title becomes main's commit
# message and release-please parses it for the changelog and version bump;
# an unvalidated title is silently invisible to both.
# WHY: `type` is derived from CLAUDE.md's `commit_types:` frontmatter line —
# the sole declaration — so this script never hand-carries its own copy.

REPO_ROOT=$(git rev-parse --show-toplevel)
TITLE="${1:-}"

if [[ -z "$TITLE" ]]; then
    echo "PR TITLE: no title given" >&2
    exit 1
fi

type_csv=$(sed -n 's/^commit_types: *//p' "$REPO_ROOT/CLAUDE.md")
if [[ -z "$type_csv" ]]; then
    echo "PR TITLE: CLAUDE.md has no 'commit_types:' line to derive the accepted type list from" >&2
    exit 1
fi
type_alt=$(echo "$type_csv" | tr ',' '|')

# INVARIANT: the type alternation is exact literals, not a generic \w+ — a
# bare scope in the type position (e.g. `sms: ...`) must fail. That shape
# produced 11 of the last 20 commits invisible to the changelog (#665);
# anchoring to the declared literal set is what rejects it.
pattern="^(${type_alt})(\([a-zA-Z0-9_./-]+\))?!?: .+"

if echo "$TITLE" | grep -qE "$pattern"; then
    echo "PR TITLE: ok — '$TITLE'"
    exit 0
fi

echo "PR TITLE: '$TITLE' does not match the conventional-commit grammar." >&2
echo "Expected: <type>(<scope>)<!>: <description>, type one of: $(echo "$type_csv" | tr ',' ' ')" >&2
exit 1
