#!/usr/bin/env bash
set -euo pipefail

# witness/forkexec.sh — QEMU fork+exec composes, per-process images (#502),
# verbatim from ci.yml. /init forks; the CHILD execs /init2 (its OWN image,
# not a re-run of /init — the fork bomb is dead); the exec marker appears
# EXACTLY ONCE; the parent's own image frame is never touched.
source "$(dirname "$0")/lib.sh"

witness_deps
THUMOS_INIT_VARIANT=forkexec build_kernel qemu
ferc=0
THUMOS_INIT_VARIANT=forkexec run_qemu forkexec.log || ferc=$?
echo "=== forkexec: runner rc=$ferc (want 0) ==="
test "$ferc" -eq 0 || { echo "FAIL forkexec: kernel did not survive (rc=$ferc; 124=hang 2/3=abort)"; exit 1; }
grep -q 'forkexec: start' forkexec.log || { echo 'FAIL forkexec: harness never started'; exit 1; }
grep -q 'forkexec: parent waiting' forkexec.log || { echo 'FAIL forkexec: no parent branch (fork did not return the child pid)'; exit 1; }
! grep -q 'forkexec: fork FAILED' forkexec.log || { echo 'FAIL forkexec: fork returned an error'; exit 1; }
! grep -q 'forkexec: child exec FAILED' forkexec.log || { echo 'FAIL forkexec: the child execve returned an error (per-process image load broken)'; exit 1; }
grep -q 'init2: reached via exec' forkexec.log || { echo 'FAIL forkexec: the child never ran /init2 -- exec did not load the new per-process image'; exit 1; }
xc=$(grep -c 'forkexec: child exec-ing /init2' forkexec.log || true)
test "$xc" -eq 1 || { echo "FAIL forkexec: the exec marker appeared $xc times (want 1) -- a FORK BOMB re-ran /init instead of /init2 (#502 regressed)"; exit 1; }
grep -q 'forkexec: parent integrity ok' forkexec.log || { echo 'FAIL forkexec: parent .data was corrupted by the child exec (per-process image isolation broken)'; exit 1; }
! grep -q 'forkexec: parent integrity BROKEN' forkexec.log || { echo 'FAIL forkexec: explicit parent-integrity break'; exit 1; }
! grep -q 'init2: PRIVILEGED' forkexec.log || { echo 'FAIL forkexec: the exec-d child ran at PL1 (mode drop across exec broken -- SECURITY)'; exit 1; }
grep -q 'THUMOS-QEMU: service-loop ticks=' forkexec.log || { echo 'FAIL forkexec: kernel did not survive'; exit 1; }
grep -q 'shell: hello from userspace' forkexec.log || { echo 'FAIL forkexec: /shell (PID 2) did not run alongside the fork+exec /init (#526 coexistence)'; exit 1; }
echo "forkexec witness: PASS"
