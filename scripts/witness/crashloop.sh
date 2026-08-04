#!/usr/bin/env bash
# witness/crashloop.sh — QEMU PID-0 fault supervisor + crash-loop rate limit
# (#492), verbatim from ci.yml. The crashloop-probe feature makes kinit spawn
# + supervise /crasher, a program that data-aborts on EVERY launch: launch,
# restart x3, give up — the counts are the assertion. #526 reconciliation: a
# CLEAN exit (/shell) must NEVER be restarted; /init is deliberately
# unsupervised and must be unaffected.
set -uo pipefail
source "$(dirname "$0")/lib.sh"

witness_deps
build_kernel qemu,crashloop-probe
crc=0
run_qemu crashloop.log || crc=$?
echo "=== crashloop: runner rc=$crc (want 0) ==="
test "$crc" -eq 0 || { echo "FAIL #492: kernel did not survive the crash loop (rc=$crc; 124=hang 2/3=abort)"; exit 1; }
! grep -q 'crasher: NOT killed' crashloop.log || { echo 'FAIL #492: /crasher read kernel memory WITHOUT faulting (ISOLATION BROKEN)'; exit 1; }
! grep -q 'supervisor FAILED to restart' crashloop.log || { echo 'FAIL #492: a relaunch failed (ramfs re-plan / load_confined under the kernel L1 broke)'; exit 1; }
starts=$(grep -c 'crasher: start' crashloop.log)
test "$starts" -eq 4 || { echo "FAIL #492: /crasher ran $starts times (want 4 = initial + 3 restarts) -- the restart policy or the relaunched image is wrong"; exit 1; }
restarts=$(grep -c 'kardia: supervisor restarted /crasher' crashloop.log)
test "$restarts" -eq 3 || { echo "FAIL #492: $restarts restarts (want 3 = MAX_RESTARTS)"; exit 1; }
audited=$(grep -c 'kardia: fault audited pid=' crashloop.log)
test "$audited" -eq 4 || { echo "FAIL #492: $audited faults audited (want 4) -- every report must reach the audit trail"; exit 1; }
grep -q 'kardia: supervisor giving up on /crasher after 3 restarts' crashloop.log || { echo 'FAIL #492: the crash loop was never rate-limited (no give-up)'; exit 1; }
faults=$(grep -c 'USERFAULT:.*kind=data-abort.*killed' crashloop.log)
test "$faults" -eq 4 || { echo "FAIL #492: $faults data-abort kills (want 4) -- a 5th means give-up did not stop the loop"; exit 1; }
! grep -q 'supervisor restarted /shell' crashloop.log || { echo 'FAIL #492: /shell exited CLEANLY and was restarted -- the supervisor is keying on Dead state, not on fault reports'; exit 1; }
shells=$(grep -c 'shell: hello from userspace' crashloop.log)
test "$shells" -eq 1 || { echo "FAIL #492: /shell ran $shells times (want 1) -- a clean exit must not be relaunched"; exit 1; }
grep -q 'init: hello from userspace' crashloop.log || { echo 'FAIL #492: /init did not run (unsupervised, must be unaffected)'; exit 1; }
grep -q 'kardia: reaped' crashloop.log || { echo 'FAIL #492: the reaper stopped reclaiming slots (the supervisor must not replace it)'; exit 1; }
echo "crashloop witness: PASS"
