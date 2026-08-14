#!/usr/bin/env bash
set -euo pipefail

# check-llm-issue-refs.sh — every issue number the _llm/ corpus names must
# still be open.
#
# WHY: llms.txt points agents at `_llm/current_state.toml` for "phase,
# blockers, and open threads", and that file is hand-maintained
# (`generated = false`). Its `[[open_threads]]` block listed three issues and
# TWO of them had been closed for weeks — #461 and #528 — while the corpus
# still presented them as live. A machine-readable file reads as data rather
# than as prose, so a stale entry there is trusted harder than the same claim
# in a paragraph would be.
#
# This is the same decay that hit the kanon-side STATE.md, whose fix was to
# stop restating issue lists entirely. The corpus keeps a narrow exception —
# threads blocked on PHYSICAL hardware, which an agent cannot discover by
# reading the tree — so this check is what keeps that exception honest.
#
# WHY open-vs-closed rather than existence: an issue number that resolves is
# not the property that matters. A closed issue presented as an open thread
# sends an agent to work that is already done, or worse, to plan around a
# blocker that was lifted.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

refs=$(grep -rhoE '^issue = [0-9]+' _llm/*.toml 2>/dev/null | grep -oE '[0-9]+' | sort -u || true)

if [ -z "$refs" ]; then
  echo "== _llm issue refs: none declared =="
  exit 0
fi

count=$(printf '%s\n' "$refs" | wc -l | tr -d ' ')
echo "== _llm issue refs: checking $count =="

stale=""
for n in $refs; do
  state=$(gh issue view "$n" --repo forkwright/thumos --json state --jq .state 2>/dev/null || echo "UNKNOWN")
  case "$state" in
    OPEN)
      echo "  #$n open"
      ;;
    UNKNOWN)
      # WHY fail rather than skip: an unresolvable number is either a typo or
      # a reference to another repo, and both are wrong in a file that claims
      # to describe this repo's live threads.
      stale="$stale\n  #$n — could not resolve (typo, or not a thumos issue)"
      ;;
    *)
      stale="$stale\n  #$n — $state, but the corpus presents it as a live thread"
      ;;
  esac
done

if [ -n "$stale" ]; then
  echo
  echo "STALE _llm ISSUE REFS: the corpus names issues that are not open."
  echo "llms.txt points agents here for current blockers, so this misdirects them."
  # shellcheck disable=SC2059
  printf "$stale\n"
  echo
  echo "Fix by removing the entry — the live list is a query:"
  echo "  gh issue list --repo forkwright/thumos"
  exit 1
fi

echo "all _llm issue refs are open"
