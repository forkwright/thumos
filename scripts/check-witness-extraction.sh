#!/usr/bin/env bash
set -euo pipefail

# check-witness-extraction.sh — drift guard for the witness extraction (#546).
# Kernel witness logic must live ONLY in scripts/witness/*.sh; ci.yml and
# .kanon-ci.toml call those scripts, never inline the assertions. Fails when:
#   (a) a known witness marker appears inline in ci.yml or .kanon-ci.toml
#       (assertion logic living outside the scripts), or
#   (b) ci.yml's kernel steps stop calling the scripts, or
#   (c) .kanon-ci.toml loses the kernel stages.

REPO_ROOT=$(git rev-parse --show-toplevel)
CI="$REPO_ROOT/.github/workflows/ci.yml"
KCI="$REPO_ROOT/.kanon-ci.toml"
rc=0

# (a) Assertion markers that must exist only inside scripts/witness/.
for marker in 'painted_px=' 'fork isolation intact' 'init2: reached via exec' 'guard child killed' 'supervisor giving up' 'KERNEL UNDEFINED INSTRUCTION' 'init: woke' 'signal: flows complete' 'signal: trampoline rx enforced' 'THUMOS_BOOT_KEY_PUB=keys/dev'; do
    if grep -qF "$marker" "$CI" || grep -qF "$marker" "$KCI"; then
        echo "DRIFT: witness assertion marker '$marker' is inline in a CI surface (must live in scripts/witness/)" >&2
        rc=1
    fi
done

# (b) ci.yml kernel job must call the scripts, per witness.
for w in boot watchdog kfault uaccess sleep fork exec forkexec guard brk signal crashloop metaxu metaxu-negative; do
    grep -q "scripts/witness/$w.sh" "$CI" || { echo "DRIFT: ci.yml no longer calls scripts/witness/$w.sh" >&2; rc=1; }
done
grep -q 'scripts/witness/trust-anchor.sh' "$CI" || { echo "DRIFT: ci.yml no longer calls scripts/witness/trust-anchor.sh" >&2; rc=1; }
grep -q 'scripts/kernel-host-tests.sh' "$CI" || { echo "DRIFT: ci.yml no longer calls scripts/kernel-host-tests.sh" >&2; rc=1; }

# (c) .kanon-ci.toml must carry the kernel stages that call the same scripts.
for stage in 'kernel host tests' 'kernel qemu witnesses' 'kernel build' 'kernel trust anchor'; do
    grep -q "\"$stage\"" "$KCI" || { echo "DRIFT: .kanon-ci.toml lost stage \"$stage\"" >&2; rc=1; }
done
for s in kernel-host-tests.sh witness-run-all.sh witness/trust-anchor.sh; do
    grep -q "$s" "$KCI" || { echo "DRIFT: .kanon-ci.toml stage no longer calls $s" >&2; rc=1; }
done

[[ "$rc" -eq 0 ]] && echo "witness extraction: no drift (ci.yml + .kanon-ci.toml call scripts/witness verbatim)"
exit "$rc"
