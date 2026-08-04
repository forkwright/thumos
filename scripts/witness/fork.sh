#!/usr/bin/env bash
# witness/fork.sh — QEMU fork correctness + isolation (#478), verbatim from
# ci.yml. A PL0 fork must give the child its OWN deep-copied memory: distinct
# parent/child markers prove the r0 split; the child mutates canaries the
# parent then verifies untouched; child exit + waitpid proves exit_cleanup
# freed the CHILD's frames, not the parent's.
set -uo pipefail
source "$(dirname "$0")/lib.sh"

witness_deps
THUMOS_INIT_VARIANT=fork build_kernel qemu
frc=0
THUMOS_INIT_VARIANT=fork run_qemu fork.log || frc=$?
echo "=== fork: runner rc=$frc (want 0) ==="
test "$frc" -eq 0 || { echo "FAIL fork: kernel did not survive (rc=$frc; 124=hang 2/3/4=abort)"; exit 1; }
grep -q 'init: fork parent' fork.log || { echo 'FAIL fork: no parent branch (fork did not return the child pid)'; exit 1; }
grep -q 'init: fork child' fork.log || { echo 'FAIL fork: no child branch (child did not resume at the fork return with r0=0 -- the #478 ctx seed)'; exit 1; }
grep -q 'init: fork isolation intact' fork.log || { echo 'FAIL fork: child writes reached the parent (SHARED PAGES -- deep copy broken)'; exit 1; }
! grep -q 'init: fork isolation BROKEN' fork.log || { echo 'FAIL fork: explicit isolation break'; exit 1; }
! grep -q 'init: fork FAILED' fork.log || { echo 'FAIL fork: fork returned an error'; exit 1; }
! grep -q 'USERFAULT:' fork.log || { echo 'FAIL fork: a process faulted (bad child frame, bad mapping, or parent stack freed by the child exit)'; exit 1; }
grep -q 'init: hello from userspace' fork.log || { echo 'FAIL fork: parent did not continue past the harness'; exit 1; }
grep -q 'THUMOS-QEMU: service-loop ticks=' fork.log || { echo 'FAIL fork: kernel did not survive'; exit 1; }
grep -q 'shell: hello from userspace' fork.log || { echo 'FAIL fork: /shell (PID 2) did not run alongside the forking /init (#526 coexistence)'; exit 1; }
echo "fork witness: PASS"
