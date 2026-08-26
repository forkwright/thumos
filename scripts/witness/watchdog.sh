#!/usr/bin/env bash
set -euo pipefail

# witness/watchdog.sh — controlled-reboot and falsifying liveness witnesses
# (#875). The first boot enters the production shutdown coordinator from the
# live PID-0 loop and must terminate through the QEMU reset backend. The second
# freezes only PID 0 after a healthy prefix while scheduler epochs continue.
# The third enters the real coordinator, injects reset-backend failure, and
# proves the immutable grace still ends in watchdog expiry. Both negative boots
# require the real timer-IRQ gate to refuse pets and the model to expire.
source "$(dirname "$0")/lib.sh"

witness_deps

# Keep generated transcripts under the already-ignored build tree instead of
# leaving watchdog-*.log artifacts in the repository root after a local run.
LOG_DIR="$KERNEL_DIR/target/witness/watchdog"
mkdir -p "$LOG_DIR"
REBOOT_LOG="$LOG_DIR/reboot.log"
STALL_LOG="$LOG_DIR/stall.log"
SHUTDOWN_HANG_LOG="$LOG_DIR/shutdown-hang.log"

build_kernel qemu,watchdog-reboot-probe
reboot_rc=0
run_qemu "$REBOOT_LOG" || reboot_rc=$?
test "$reboot_rc" -eq 8 || {
    echo "FAIL #875 reboot: runner exit $reboot_rc (want 8=controlled reboot)"
    exit 1
}
grep -q 'THUMOS-QEMU: boot-complete' "$REBOOT_LOG" || {
    echo 'FAIL #875 reboot: probe did not reach the live post-boot service loop'
    exit 1
}
grep -q 'THUMOS-QEMU: watchdog probe entering controlled reboot' "$REBOOT_LOG" || {
    echo 'FAIL #875 reboot: service loop never invoked the shutdown coordinator'
    exit 1
}
grep -q 'THUMOS-QEMU: controlled reboot requested' "$REBOOT_LOG" || {
    echo 'FAIL #875 reboot: coordinator never reached the board reset backend'
    exit 1
}
! grep -q 'THUMOS-QEMU: emulated watchdog expired' "$REBOOT_LOG" || {
    echo 'FAIL #875 reboot: controlled reset fell through to watchdog expiry'
    exit 1
}

build_kernel qemu,watchdog-stall-probe
stall_rc=0
run_qemu "$STALL_LOG" || stall_rc=$?
test "$stall_rc" -eq 7 || {
    echo "FAIL #875 stall: runner exit $stall_rc (want 7=modeled watchdog expiry)"
    exit 1
}
grep -q 'THUMOS-QEMU: boot-complete' "$STALL_LOG" || {
    echo 'FAIL #875 stall: probe did not reach the live post-boot service loop'
    exit 1
}
grep -q 'THUMOS-QEMU: watchdog probe froze service-loop' "$STALL_LOG" || {
    echo 'FAIL #875 stall: PID-0 progress fault was never injected'
    exit 1
}
grep -q 'WATCHDOG WITHHELD: service-loop' "$STALL_LOG" || {
    echo 'FAIL #875 stall: timer-IRQ liveness gate did not refuse the frozen owner'
    exit 1
}
grep -q 'THUMOS-QEMU: emulated watchdog expired since_pet=500' "$STALL_LOG" || {
    echo 'FAIL #875 stall: refused pets produced no observable reset outcome'
    exit 1
}
! grep -q 'THUMOS-QEMU: controlled reboot requested' "$STALL_LOG" || {
    echo 'FAIL #875 stall: negative witness escaped through the controlled-reset path'
    exit 1
}
! grep -q 'THUMOS-QEMU: service-loop ticks=' "$STALL_LOG" || {
    echo 'FAIL #875 stall: fault-injected boot reported the ordinary success marker'
    exit 1
}

build_kernel qemu,watchdog-shutdown-hang-probe
shutdown_hang_rc=0
run_qemu "$SHUTDOWN_HANG_LOG" || shutdown_hang_rc=$?
test "$shutdown_hang_rc" -eq 7 || {
    echo "FAIL #875 hung shutdown: runner exit $shutdown_hang_rc (want 7=modeled watchdog expiry)"
    exit 1
}
grep -q 'THUMOS-QEMU: boot-complete' "$SHUTDOWN_HANG_LOG" || {
    echo 'FAIL #875 hung shutdown: probe did not reach the live post-boot service loop'
    exit 1
}
grep -q 'THUMOS-QEMU: watchdog probe entering controlled reboot' "$SHUTDOWN_HANG_LOG" || {
    echo 'FAIL #875 hung shutdown: service loop never invoked the shutdown coordinator'
    exit 1
}
grep -q 'THUMOS-QEMU: controlled reboot requested' "$SHUTDOWN_HANG_LOG" || {
    echo 'FAIL #875 hung shutdown: coordinator never reached the board reset backend'
    exit 1
}
grep -q 'THUMOS-QEMU: controlled reboot reset failure injected' "$SHUTDOWN_HANG_LOG" || {
    echo 'FAIL #875 hung shutdown: reset backend did not exercise its failure path'
    exit 1
}
grep -q 'THUMOS-QEMU: shutdown grace final pet elapsed=500' "$SHUTDOWN_HANG_LOG" || {
    echo 'FAIL #875 hung shutdown: target did not observe the final permitted grace pet'
    exit 1
}
grep -q 'THUMOS-QEMU: shutdown grace immutable elapsed=501 last_pet_elapsed=500' "$SHUTDOWN_HANG_LOG" || {
    echo 'FAIL #875 hung shutdown: late re-entry extended or obscured the accepted grace deadline'
    exit 1
}
grep -q 'WATCHDOG WITHHELD: shutdown has not advanced for 501 ticks' "$SHUTDOWN_HANG_LOG" || {
    echo 'FAIL #875 hung shutdown: timer-IRQ gate did not withhold at grace expiry'
    exit 1
}
grep -q 'THUMOS-QEMU: emulated watchdog expired since_pet=500' "$SHUTDOWN_HANG_LOG" || {
    echo 'FAIL #875 hung shutdown: withholding did not produce a bounded reset outcome'
    exit 1
}
! grep -q 'THUMOS-QEMU: watchdog probe failure:' "$SHUTDOWN_HANG_LOG" || {
    echo 'FAIL #875 hung shutdown: an injected-path invariant failed before expiry'
    exit 1
}
! grep -q 'THUMOS-QEMU: service-loop ticks=' "$SHUTDOWN_HANG_LOG" || {
    echo 'FAIL #875 hung shutdown: fault-injected boot reported the ordinary success marker'
    exit 1
}

echo 'watchdog witness: PASS (reset + owner stall + immutable hung-shutdown expiry)'
