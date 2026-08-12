#!/usr/bin/env bash
# witness/exec.sh — QEMU exec correctness + PL0 (#489), verbatim from ci.yml.
# PL0 execve must REPLACE the caller's image with a new one that runs at PL0:
# the NEW image's _start runs (remap + ACTIVE_FRAME install), its privileged
# cp15 read UNDEF-faults at PL0 (unprivileged proof), the OLD image is gone,
# and the kernel survives.
set -euo pipefail
source "$(dirname "$0")/lib.sh"

witness_deps
THUMOS_INIT_VARIANT=exec build_kernel qemu
erc=0
THUMOS_INIT_VARIANT=exec run_qemu exec.log || erc=$?
echo "=== exec: runner rc=$erc (want 0) ==="
test "$erc" -eq 0 || { echo "FAIL exec: kernel did not survive (rc=$erc; 124=hang 2/3=abort)"; exit 1; }
grep -q 'init: exec-ing /init2' exec.log || { echo 'FAIL exec: /init never called execve'; exit 1; }
grep -q 'init2: reached via exec' exec.log || { echo 'FAIL exec: the new image never ran (remap or ACTIVE_FRAME install broken -- exec did not transfer control)'; exit 1; }
! grep -q 'init: exec FAILED' exec.log || { echo 'FAIL exec: execve returned an error'; exit 1; }
grep -Eq 'USERFAULT: pid=1 kind=undefined-instruction .*killed' exec.log || { echo 'FAIL exec: the exec-d image did not UNDEF on its cp15 probe (PL0 proof missing)'; exit 1; }
! grep -q 'init2: PRIVILEGED' exec.log || { echo 'FAIL exec: the exec-d image ran at PL1 (mode drop across exec broken -- SECURITY)'; exit 1; }
! grep -q 'init: hello from userspace' exec.log || { echo 'FAIL exec: the OLD image kept running after exec (control not transferred)'; exit 1; }
grep -q 'THUMOS-QEMU: service-loop ticks=' exec.log || { echo 'FAIL exec: kernel did not survive the exec-d process fault'; exit 1; }
grep -q 'shell: hello from userspace' exec.log || { echo 'FAIL exec: /shell (PID 2) did not run alongside the exec-ing /init (#526 coexistence)'; exit 1; }
echo "exec witness: PASS"
