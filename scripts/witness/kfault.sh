#!/usr/bin/env bash
# witness/kfault.sh — kernel-fault halts witness (#546), verbatim from ci.yml.
# The other half of the safety property: a deliberate PL1 `udf` after
# boot-complete must take the KERNEL branch: qemu exit 4, no service-loop
# resume. If fault handling ever wrongly "recovers" a kernel fault, the boot
# continues to ticks=/exit 0 and this reds.
set -uo pipefail
source "$(dirname "$0")/lib.sh"

witness_deps
build_kernel qemu,kfault-probe
krc=0
run_qemu kfault.log || krc=$?
echo "=== kernel-fault probe: runner rc=$krc (want 4) ==="
test "$krc" -eq 4 || { echo "FAIL kfault: PL1 udf did not halt with exit 4 (rc=$krc) -- a kernel fault must NEVER be gracefully recovered"; exit 1; }
grep -q 'KERNEL UNDEFINED INSTRUCTION' kfault.log || { echo 'FAIL kfault: missing kernel-fault banner'; exit 1; }
! grep -q 'THUMOS-QEMU: service-loop ticks=' kfault.log || { echo 'FAIL kfault: service loop ran past a KERNEL fault (fault was masked)'; exit 1; }
! grep -q 'USERFAULT:' kfault.log || { echo 'FAIL kfault: a PL1 fault took the USER kill branch (mode check broken)'; exit 1; }
echo "kfault witness: PASS"
