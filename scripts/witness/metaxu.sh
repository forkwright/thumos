#!/usr/bin/env bash
set -euo pipefail

# witness/metaxu.sh — the #544 on-device round trip: a real Thumos
# userspace process (/metaxu_probe) drives an authenticated metaxu-core
# request over the second PL011 to a real host `pylon-bridge` process (the
# SAME reference endpoint the adversarial witness in crates/metaxu runs
# against) and back.
#
# Orchestration (deterministic, no race): the pylon-bridge binds its
# listener and prints the port BEFORE qemu starts; qemu's second UART
# chardev connects OUT to that port as a client (THUMOS_QEMU_METAXU_PORT,
# read by scripts/qemu-runner.sh), so the guest never races an unbound
# host socket.
set -euo pipefail
source "$(dirname "$0")/lib.sh"

REPO_ROOT=$(git rev-parse --show-toplevel)

witness_deps

start_pylon_bridge
trap 'stop_pylon_bridge; rm -f "$PYLON_LOG"' EXIT

build_kernel qemu,metaxu-probe
mrc=0
THUMOS_QEMU_METAXU_PORT="$PYLON_PORT" run_qemu metaxu.log || mrc=$?
echo "=== metaxu round trip: runner rc=$mrc (want 0) ==="
test "$mrc" -eq 0 || { echo "FAIL #544: runner exit $mrc (0=ok 5=loop-stall 1=panic 2/3/4=abort 124=hang)"; exit 1; }
grep -q 'THUMOS-QEMU: boot-complete' metaxu.log || { echo 'FAIL #544: boot did not complete'; exit 1; }
grep -q '/metaxu_probe spawned PL0' metaxu.log || { echo 'FAIL #544: /metaxu_probe did not spawn (absent from ramfs or spawn regressed)'; exit 1; }
grep -q 'metaxu: request submitted' metaxu.log || { echo 'FAIL #544: /metaxu_probe never submitted a request (MetaxuSubmit syscall path broken)'; exit 1; }
grep -q 'metaxu: round trip accepted' metaxu.log || {
    echo 'FAIL #544: the authenticated round trip was not accepted'
    grep -q 'metaxu: round trip rejected' metaxu.log && echo '  (pylon rejected the request)'
    grep -q 'metaxu: round trip mac verification failed' metaxu.log && echo '  (response MAC did not verify)'
    grep -q 'metaxu: round trip transport error' metaxu.log && echo '  (transport/encode/decode error)'
    grep -q 'metaxu: round trip timed out' metaxu.log && echo '  (no response arrived within the poll budget)'
    exit 1
}
echo "=== pylon-bridge log ==="; cat "$PYLON_LOG"; echo "=== end pylon-bridge log ==="
echo "metaxu witness: PASS"
