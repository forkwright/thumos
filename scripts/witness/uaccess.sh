#!/usr/bin/env bash
set -euo pipefail

# witness/uaccess.sh — #871 caller-VAS + fault-contained copy witness.
#
# The userspace half drives real syscalls over adjacent anonymous mappings:
# RW is a positive control; PROT_NONE and unmapped pages reject data access;
# inexpressible ARMv7 execute-only is refused; read-only remains a valid source
# but rejects clock_gettime copyout; and a valid-first-page/invalid-tail range
# rejects as a whole. The kernel feature half deliberately bypasses preflight
# and faults the actual LDRBT/STRBT instructions, proving the abort fixups.
source "$(dirname "$0")/lib.sh"

witness_deps
THUMOS_INIT_VARIANT=uaccess build_kernel qemu,uaccess-probe
urc=0
THUMOS_INIT_VARIANT=uaccess run_qemu uaccess.log || urc=$?
echo "=== uaccess probe: runner rc=$urc (want 0) ==="
test "$urc" -eq 0 || { echo "FAIL #871: kernel did not survive contained uaccess faults (rc=$urc; 2=data abort, 124=hang)"; exit 1; }

grep -q 'THUMOS-QEMU: uaccess fault fixups recovered' uaccess.log || { echo 'FAIL #871: raw LDRBT/STRBT post-validation fault fixups did not both recover'; exit 1; }
grep -q 'uaccess: anonymous RW controls passed' uaccess.log || { echo 'FAIL #871: low anonymous RW mapping was not accepted in both syscall directions'; exit 1; }
grep -q 'uaccess: PROT_NONE and cross-page rejected' uaccess.log || { echo 'FAIL #871: PROT_NONE source / partial-validity syscall matrix did not complete'; exit 1; }
grep -q 'uaccess: execute-only mapping refused' uaccess.log || { echo 'FAIL #871: inexpressible execute-only mapping was not refused'; exit 1; }
grep -q 'uaccess: read-only source accepted' uaccess.log || { echo 'FAIL #871: a read-only mapping was not accepted as a copyin source'; exit 1; }
grep -q 'uaccess: direction split enforced' uaccess.log || { echo 'FAIL #871: read-only source/destination permission split was not enforced'; exit 1; }
grep -q 'uaccess: unmapped and cross-page rejected' uaccess.log || { echo 'FAIL #871: unmapped source / cross-boundary syscall matrix did not complete'; exit 1; }
grep -q 'uaccess: syscall boundaries contained' uaccess.log || { echo 'FAIL #871: userspace did not continue after every EFAULT'; exit 1; }
! grep -q 'FAIL uaccess:' uaccess.log || { echo 'FAIL #871: guest uaccess assertion fired'; exit 1; }
! grep -q 'KERNEL DATA ABORT' uaccess.log || { echo 'FAIL #871: a uaccess fault escaped its exact-PC fixup and halted PL1'; exit 1; }
! grep -q 'USERFAULT:' uaccess.log || { echo 'FAIL #871: syscall validation/fixup killed the caller instead of returning EFAULT'; exit 1; }
grep -q 'THUMOS-QEMU: service-loop ticks=' uaccess.log || { echo 'FAIL #871: service loop did not survive the syscall fault matrix'; exit 1; }
echo "uaccess witness: PASS"
