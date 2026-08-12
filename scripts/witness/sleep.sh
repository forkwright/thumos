#!/usr/bin/env bash
set -euo pipefail

# witness/sleep.sh — userspace sleep really yields (#477), verbatim from ci.yml.
# A userspace nanosleep/Sleep must YIELD (switch away, resume after the
# interval), not busy-wait. The old busy-wait ran IRQ-masked in the SVC trap,
# so ticks() froze and the WHOLE kernel hung. The sleep /init variant sleeps
# 30ms between "sleeping" and "woke": a real yield lets the service loop run
# meanwhile and /init resume; a busy-wait hangs the kernel -> runner timeout.
source "$(dirname "$0")/lib.sh"

witness_deps
THUMOS_INIT_VARIANT=sleep build_kernel qemu
src=0
THUMOS_INIT_VARIANT=sleep run_qemu sleep.log || src=$?
echo "=== sleep probe: runner rc=$src (want 0) ==="
test "$src" -eq 0 || { echo "FAIL sleep: kernel did not survive a userspace sleep (rc=$src; 124=hang -> busy-wait deadlock regression)"; exit 1; }
grep -q 'init: sleeping' sleep.log || { echo 'FAIL sleep: /init did not reach the sleep'; exit 1; }
grep -q 'init: woke' sleep.log || { echo 'FAIL sleep: /init never resumed from sleep (busy-wait deadlock or lost wake)'; exit 1; }
grep -q 'THUMOS-QEMU: service-loop ticks=' sleep.log || { echo 'FAIL sleep: service loop did not run (kernel hung during the sleep)'; exit 1; }
grep -q 'shell: hello from userspace' sleep.log || { echo 'FAIL sleep: /shell (PID 2) did not run alongside the sleeping /init (#526 coexistence)'; exit 1; }
echo "sleep witness: PASS"
