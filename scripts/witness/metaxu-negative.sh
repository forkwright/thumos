#!/usr/bin/env bash
# witness/metaxu-negative.sh — the #544 negative-case coverage metaxu.sh
# does not exercise: metaxu.sh proves the happy path only, which passes
# against a bridge that accepts anything. Three distinct outcomes, one
# script (mirrors trust-anchor.sh's shape: several typed outcomes proven
# in sequence, not one):
#
#   1. tampered response       -> METAXU_MAC_FAILED (a frame DOES reach the
#      host bridge; the bridge's answer is corrupted in transit).
#   2. expired grant            -> METAXU_DENIED_LOCALLY, nothing transmitted.
#   3. capability absent        -> METAXU_DENIED_LOCALLY, nothing transmitted.
#
# Cases 2 and 3 are OBSERVATIONALLY IDENTICAL from the probe's own output
# (evaluate_submission collapses every local-denial reason to the SAME
# METAXU_DENIED_LOCALLY code -- see metaxu_bridge.rs's module doc: "no case
# this function can forget to deny"). Each still gets its OWN kernel build
# (metaxu-probe-expired-grant / metaxu-probe-no-capability), because each
# proves a DIFFERENT branch inside evaluate_submission denies through the
# REAL syscall dispatch under a real boot, not just the offline host unit
# test (metaxu_bridge.rs's `tests` module already covers both offline).
#
# Case 1 needs no new kernel feature: metaxu-probe's dev grant is
# well-formed, so the frame is submitted normally; only the host
# pylon-bridge behaves differently (--tamper-mac). Cases 2/3 need no host
# behavior change: evaluate_submission's Err arm never calls write_frame,
# so the kernel never touches UART1 regardless of feature -- pylon-bridge
# runs unmodified and its silence (no "PYLON: frame received" line) is the
# proof nothing crossed the wire.
set -uo pipefail
source "$(dirname "$0")/lib.sh"

witness_deps

# ---------------------------------------------------------------------------
# Case 1: tampered response -> MAC_FAILED (a frame reaches the bridge; the
# bridge's answer is corrupted before the client verifies it).
# ---------------------------------------------------------------------------
start_pylon_bridge --tamper-mac
trap 'stop_pylon_bridge; rm -f "$PYLON_LOG"' EXIT

build_kernel qemu,metaxu-probe
mrc=0
THUMOS_QEMU_METAXU_PORT="$PYLON_PORT" run_qemu metaxu-negative-mac.log || mrc=$?
stop_pylon_bridge
echo "=== case 1 (tampered MAC): runner rc=$mrc (want 0) ==="
test "$mrc" -eq 0 || { echo "FAIL #544 case1: runner exit $mrc"; exit 1; }
grep -q 'THUMOS-QEMU: boot-complete' metaxu-negative-mac.log || { echo 'FAIL #544 case1: boot did not complete'; exit 1; }
grep -q '/metaxu_probe spawned PL0' metaxu-negative-mac.log || { echo 'FAIL #544 case1: /metaxu_probe did not spawn'; exit 1; }
grep -q 'metaxu: request submitted' metaxu-negative-mac.log || { echo 'FAIL #544 case1: request never submitted (a well-formed grant must still reach the wire)'; exit 1; }
! grep -q 'metaxu: round trip accepted' metaxu-negative-mac.log || { echo 'FAIL #544 case1: a tampered response was ACCEPTED -- MAC verification is not being checked'; exit 1; }
grep -q 'metaxu: round trip mac verification failed' metaxu-negative-mac.log || { echo 'FAIL #544 case1: the client did not report MAC_FAILED for a tampered response'; exit 1; }
grep -q 'PYLON: frame received and answered' "$PYLON_LOG" || { echo 'FAIL #544 case1: the host bridge never saw a frame -- the tamper path was not actually exercised'; exit 1; }
echo "=== case 1 pylon-bridge log ==="; cat "$PYLON_LOG"; echo "=== end ==="
echo "case 1 (tampered MAC -> MAC_FAILED): PASS"

# ---------------------------------------------------------------------------
# Case 2: expired grant -> DENIED_LOCALLY, nothing transmitted.
# ---------------------------------------------------------------------------
start_pylon_bridge
trap 'stop_pylon_bridge; rm -f "$PYLON_LOG"' EXIT

build_kernel qemu,metaxu-probe-expired-grant
mrc=0
THUMOS_QEMU_METAXU_PORT="$PYLON_PORT" run_qemu metaxu-negative-expired.log || mrc=$?
stop_pylon_bridge
echo "=== case 2 (expired grant): runner rc=$mrc (want 0) ==="
test "$mrc" -eq 0 || { echo "FAIL #544 case2: runner exit $mrc"; exit 1; }
grep -q 'THUMOS-QEMU: boot-complete' metaxu-negative-expired.log || { echo 'FAIL #544 case2: boot did not complete'; exit 1; }
grep -q '/metaxu_probe spawned PL0' metaxu-negative-expired.log || { echo 'FAIL #544 case2: /metaxu_probe did not spawn'; exit 1; }
grep -q 'metaxu: submit denied locally' metaxu-negative-expired.log || { echo 'FAIL #544 case2: an expired grant was not denied locally'; exit 1; }
! grep -q 'metaxu: request submitted' metaxu-negative-expired.log || { echo 'FAIL #544 case2: a request was submitted despite an expired grant -- the local check ran AFTER transmission, not before'; exit 1; }
! grep -q 'PYLON: frame received and answered' "$PYLON_LOG" || { echo 'FAIL #544 case2: the host bridge received a frame for an expired grant -- a local denial reached the transport'; exit 1; }
echo "=== case 2 pylon-bridge log ==="; cat "$PYLON_LOG"; echo "=== end ==="
echo "case 2 (expired grant -> DENIED_LOCALLY, nothing transmitted): PASS"

# ---------------------------------------------------------------------------
# Case 3: capability absent from the grant -> DENIED_LOCALLY, nothing
# transmitted.
# ---------------------------------------------------------------------------
start_pylon_bridge
trap 'stop_pylon_bridge; rm -f "$PYLON_LOG"' EXIT

build_kernel qemu,metaxu-probe-no-capability
mrc=0
THUMOS_QEMU_METAXU_PORT="$PYLON_PORT" run_qemu metaxu-negative-nocap.log || mrc=$?
stop_pylon_bridge
echo "=== case 3 (capability absent): runner rc=$mrc (want 0) ==="
test "$mrc" -eq 0 || { echo "FAIL #544 case3: runner exit $mrc"; exit 1; }
grep -q 'THUMOS-QEMU: boot-complete' metaxu-negative-nocap.log || { echo 'FAIL #544 case3: boot did not complete'; exit 1; }
grep -q '/metaxu_probe spawned PL0' metaxu-negative-nocap.log || { echo 'FAIL #544 case3: /metaxu_probe did not spawn'; exit 1; }
grep -q 'metaxu: submit denied locally' metaxu-negative-nocap.log || { echo 'FAIL #544 case3: a capability absent from the grant was not denied locally'; exit 1; }
! grep -q 'metaxu: request submitted' metaxu-negative-nocap.log || { echo 'FAIL #544 case3: a request was submitted despite lacking the required capability -- the local check ran AFTER transmission, not before'; exit 1; }
! grep -q 'PYLON: frame received and answered' "$PYLON_LOG" || { echo 'FAIL #544 case3: the host bridge received a frame for a capability-denied request -- METAXU_DENIED_LOCALLY reached the transport'; exit 1; }
echo "=== case 3 pylon-bridge log ==="; cat "$PYLON_LOG"; echo "=== end ==="
echo "case 3 (capability absent -> DENIED_LOCALLY, nothing transmitted): PASS"

echo "metaxu-negative witness: PASS"
