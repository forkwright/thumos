#!/usr/bin/env bash
# witness/signal.sh — userspace signal delivery end-to-end (#446), verbatim
# from ci.yml. /init installs SIGUSR1/SIGUSR2 handlers, raises BOTH against
# itself, then yields. The kernel must rewrite the IRQ trap frame into the
# handler (handler marker prints), the sigreturn trampoline must restore the
# interrupted context (the flow continues to "flows complete"), and USR2's
# marker must appear AFTER USR1's -- its pending bit surviving USR1's
# delivery is the exact-clear contract (the old clear-any-pending could wipe
# the wrong signal).
set -euo pipefail
source "$(dirname "$0")/lib.sh"

witness_deps
THUMOS_INIT_VARIANT=signal build_kernel qemu
src=0
THUMOS_INIT_VARIANT=signal run_qemu signal.log || src=$?
echo "=== signal probe: runner rc=$src (want 0) ==="
test "$src" -eq 0 || { echo "FAIL signal: kernel did not survive userspace signal delivery (rc=$src; 124=hang)"; exit 1; }

usr1_line=$(awk '/signal: handler usr1/ {print NR; exit}' signal.log)
usr2_line=$(awk '/signal: handler usr2/ {print NR; exit}' signal.log)
flows_line=$(awk '/signal: flows complete/ {print NR; exit}' signal.log)
test -n "$usr1_line" || { echo 'FAIL signal: SIGUSR1 handler never ran (frame rewrite into the handler is broken)'; exit 1; }
test -n "$usr2_line" || { echo 'FAIL signal: SIGUSR2 handler never ran (pending bit lost -- exact-clear contract broken)'; exit 1; }
test -n "$flows_line" || { echo 'FAIL signal: flows never completed (sigreturn did not restore the interrupted context)'; exit 1; }
test "$usr1_line" -lt "$usr2_line" || { echo "FAIL signal: delivery out of order (usr1@$usr1_line, usr2@$usr2_line; lowest-signum-first contract broken)"; exit 1; }
test "$usr2_line" -lt "$flows_line" || { echo "FAIL signal: flows complete preceded the USR2 handler (usr2@$usr2_line, flows@$flows_line)"; exit 1; }
# DFSR 0x80f = WnR (bit 11: a WRITE faulted) | 0x0f (permission fault, page)
# — the exact signature of a PL0 write denied by an RX mapping.
grep -qE 'USERFAULT: pid=[0-9]+ kind=data-abort addr=0x7feff000 status=0x0000080f killed' signal.log || { echo 'FAIL signal: the trampoline-page write did not die to a write-denied data-abort PERMISSION fault (page missing, or W^X broken)'; exit 1; }
grep -q 'signal: trampoline rx enforced' signal.log || { echo 'FAIL signal: rx probe child was not fault-killed with status 139 (trampoline page writable?)'; exit 1; }
grep -q 'signal: trampoline WRITEABLE' signal.log && { echo 'FAIL signal: PL0 wrote the sigreturn trampoline page — W^X broken'; exit 1; }
grep -q 'THUMOS-QEMU: service-loop ticks=' signal.log || { echo 'FAIL signal: service loop did not run (kernel hung during the yield windows)'; exit 1; }
echo "signal witness: PASS"
