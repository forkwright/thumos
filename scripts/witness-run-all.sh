#!/usr/bin/env bash
# witness-run-all.sh — run every kernel QEMU witness in canonical order (#546).
# Used by the forge admission gate (.kanon-ci.toml); ci.yml calls the same
# scripts step-by-step so GitHub's UI shows per-witness status. Any failure
# stops the run with the witness's own named assertion.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
for w in boot kfault sleep fork exec forkexec guard brk signal crashloop; do
    echo "===== witness: $w ====="
    "$HERE/witness/$w.sh" || exit 1
done
echo "ALL KERNEL QEMU WITNESSES: PASS"
