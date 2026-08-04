#!/usr/bin/env bash
# witness/guard.sh — QEMU PROT_NONE guard pages survive fork (#496), verbatim
# from ci.yml. /init mmaps a PROT_NONE guard, forks, and the CHILD reads it.
# The load-bearing assertion is the DFSR status: 0x0f = PERMISSION fault (the
# child HAS its own copy — the fix); 0x07 = TRANSLATION fault (the page was
# DROPPED from the deep-copy — the #496 bug regressed). The parent reaps
# (SIGSEGV=139) and mprotects NONE->READ.
set -uo pipefail
source "$(dirname "$0")/lib.sh"

witness_deps
THUMOS_INIT_VARIANT=guard build_kernel qemu
grc=0
THUMOS_INIT_VARIANT=guard run_qemu guard.log || grc=$?
echo "=== guard: runner rc=$grc (want 0) ==="
test "$grc" -eq 0 || { echo "FAIL guard: kernel did not survive (rc=$grc; 124=hang 2/3=abort)"; exit 1; }
grep -q 'init: guard mapped' guard.log || { echo 'FAIL #496: mmap(PROT_NONE) was rejected -- the guard-page gate regressed (or mmap cannot shatter its section)'; exit 1; }
! grep -q 'init: guard mmap FAILED' guard.log || { echo 'FAIL #496: mmap(PROT_NONE) returned MAP_FAILED'; exit 1; }
! grep -q 'init: guard fork FAILED' guard.log || { echo 'FAIL #496: fork failed in the guard harness'; exit 1; }
! grep -q 'init: guard NOT enforced' guard.log || { echo 'FAIL #496: the child READ the PROT_NONE guard without faulting -- PL0 access was not denied (SECURITY)'; exit 1; }
grep -Eq 'USERFAULT: pid=[0-9]+ kind=data-abort addr=0x20000000 status=0x0000000f killed' guard.log || { echo 'FAIL #496: no PERMISSION data-abort at the guard VA -- the forked child did not get its own PROT_NONE page'; exit 1; }
! grep -q 'USERFAULT.*addr=0x20000000 status=0x00000007' guard.log || { echo 'FAIL #496: TRANSLATION fault at the guard VA -- fork DROPPED the PROT_NONE page from the deep-copy (the #496 bug regressed)'; exit 1; }
gufc=$(grep -c 'USERFAULT:' guard.log)
test "$gufc" -eq 1 || { echo "FAIL #496: expected exactly 1 USERFAULT, got $gufc"; exit 1; }
grep -q 'init: guard child killed status=139' guard.log || { echo 'FAIL #496: the guard-faulting child did not exit SIGSEGV(139) / was not reaped by the parent'; exit 1; }
grep -q 'init: guard readable after mprotect' guard.log || { echo 'FAIL #496: mprotect(PROT_NONE -> PROT_READ) failed, or the guard frame did not survive'; exit 1; }
grep -q 'shell: hello from userspace' guard.log || { echo 'FAIL #496: /shell did not coexist (#526)'; exit 1; }
grep -q 'THUMOS-QEMU: service-loop ticks=' guard.log || { echo 'FAIL #496: kernel did not survive the guard fault'; exit 1; }
echo "guard witness: PASS"
