#!/usr/bin/env bash
set -euo pipefail

# witness/brk.sh — QEMU brk heap growth on a real page table (#533), verbatim
# from ci.yml. sys_brk growth maps into the heap window (mb 0x100), covered by
# a 1 MB identity SECTION on every real process L1 — and map_page refuses to
# overlay a section, so brk growth failed on every real boot while host tests
# (absent-entry fixture) stayed green. This witness is the only real-table
# proof for heap growth: grow two pages, canary R/W at PL0, shrink back.
source "$(dirname "$0")/lib.sh"

witness_deps
THUMOS_INIT_VARIANT=brk build_kernel qemu
brc=0
THUMOS_INIT_VARIANT=brk run_qemu brk.log || brc=$?
echo "=== brk: runner rc=$brc (want 0) ==="
test "$brc" -eq 0 || { echo "FAIL #533: kernel did not survive (rc=$brc; 124=hang 2/3=abort)"; exit 1; }
grep -q 'init: brk grown' brk.log || { echo 'FAIL #533: brk grow did not advance the break on a real table (section-overlay bug)'; exit 1; }
! grep -q 'init: brk grow FAILED' brk.log || { echo 'FAIL #533: sys_brk grow returned the unchanged break -- map_page could not overlay the heap section'; exit 1; }
grep -q 'init: brk canary ok' brk.log || { echo 'FAIL #533: heap canary readback failed -- the grown pages are not PL0-accessible'; exit 1; }
! grep -q 'init: brk canary BROKEN' brk.log || { echo 'FAIL #533: explicit heap canary mismatch'; exit 1; }
! grep -q 'USERFAULT:' brk.log || { echo 'FAIL #533: touching the grown heap faulted -- the user grant never landed'; exit 1; }
grep -q 'init: brk shrunk' brk.log || { echo 'FAIL #533: brk shrink back to the initial break failed'; exit 1; }
grep -q 'init: hello from userspace' brk.log || { echo 'FAIL #533: /init did not continue past the brk harness'; exit 1; }
grep -q 'shell: hello from userspace' brk.log || { echo 'FAIL #533: /shell (PID 2) did not coexist (#526)'; exit 1; }
grep -q 'THUMOS-QEMU: service-loop ticks=' brk.log || { echo 'FAIL #533: kernel did not survive the brk harness'; exit 1; }
echo "brk witness: PASS"
