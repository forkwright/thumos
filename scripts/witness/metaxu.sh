#!/usr/bin/env bash
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
set -uo pipefail
source "$(dirname "$0")/lib.sh"

REPO_ROOT=$(git rev-parse --show-toplevel)

witness_deps

# Build + launch the host pylon-bridge FIRST (deterministic ordering).
(cd "$REPO_ROOT" && cargo build --release --features metaxu/pylon-bin --bin pylon-bridge \
    --jobs "${THUMOS_BUILD_JOBS:-8}") \
    || { echo "FAIL: pylon-bridge build failed"; exit 1; }
PYLON_BIN="$REPO_ROOT/target/release/pylon-bridge"
[[ -x "$PYLON_BIN" ]] || { echo "FAIL: pylon-bridge binary missing at $PYLON_BIN"; exit 1; }

PYLON_LOG=$(mktemp)
"$PYLON_BIN" >"$PYLON_LOG" 2>&1 &
PYLON_PID=$!
trap 'kill "$PYLON_PID" 2>/dev/null || true; rm -f "$PYLON_LOG"' EXIT

PORT=""
for _ in $(seq 1 50); do
    if grep -q '^PYLON_PORT=' "$PYLON_LOG" 2>/dev/null; then
        PORT=$(grep '^PYLON_PORT=' "$PYLON_LOG" | head -1 | cut -d= -f2)
        break
    fi
    kill -0 "$PYLON_PID" 2>/dev/null || { echo "FAIL: pylon-bridge exited before printing its port"; cat "$PYLON_LOG"; exit 1; }
    sleep 0.1
done
[[ -n "$PORT" ]] || { echo "FAIL: pylon-bridge never printed PYLON_PORT="; cat "$PYLON_LOG"; exit 1; }
echo "=== pylon-bridge listening on 127.0.0.1:$PORT (pid $PYLON_PID) ==="

build_kernel qemu,metaxu-probe
mrc=0
THUMOS_QEMU_METAXU_PORT="$PORT" run_qemu metaxu.log || mrc=$?
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
