#!/usr/bin/env bash
# witness/boot.sh — kernel QEMU boot + service-loop witness (#546), extracted
# verbatim from the ci.yml kernel job. The `qemu` feature retargets peripherals
# to the virt board; the REAL kinit boots, hands off to kardia (PID 0), and
# exits via semihosting after QEMU_TICK_CAP serviced ticks. Every grep below is
# a named assertion from the original inline block — same markers, same counts.
# Runner exit codes: 0=loop ran; 5=service-loop stalled (#461 tick-source
# class); 1=panic; 2/3/4=aborts; 124=hang (runner timeout).
set -uo pipefail
source "$(dirname "$0")/lib.sh"

witness_deps
build_kernel qemu
rc=0
run_qemu boot.log || rc=$?
test "$rc" -eq 0 || { echo "FAIL: runner exit $rc (0=ok 5=loop-stall#461 1=panic 2/3/4=abort 124=hang)"; exit 1; }
grep -q 'THUMOS v0.1.0' boot.log || { echo 'FAIL: missing banner'; exit 1; }
grep -q 'THUMOS-QEMU: boot-complete' boot.log || { echo 'FAIL: boot did not complete'; exit 1; }
grep -q 'THUMOS-QEMU: service-loop ticks=' boot.log || { echo 'FAIL: service loop never serviced a tick'; exit 1; }
# Fail-closed (#217): no boot medium -> degraded-LOCKED, MEDIUM-trust steps refused.
grep -q 'Secure boot: DEGRADED' boot.log || { echo 'FAIL: untrusted boot did not report degraded (fail-closed regression)'; exit 1; }
grep -q 'Passphrase entry refused' boot.log || { echo 'FAIL: passphrase not refused on an untrusted boot (fail-OPEN regression)'; exit 1; }
grep -q 'Audit log deferred' boot.log || { echo 'FAIL: audit not deferred on an untrusted boot (fail-OPEN regression)'; exit 1; }
# Measured userspace (#480): initramfs signature verified AND /init executed a syscall.
grep -q 'image-resident initramfs signature verified' boot.log || { echo 'FAIL: initramfs signature was not verified (measured-userspace regression)'; exit 1; }
grep -q '/init spawned' boot.log || { echo 'FAIL: /init did not spawn from the verified initramfs'; exit 1; }
grep -q 'init: hello from userspace' boot.log || { echo 'FAIL: userspace /init did not run + syscall (PL0->dispatch->UART)'; exit 1; }
# #526/#502: /init AND /shell coexist in their OWN per-process frames (anti-clobber).
grep -q '/shell spawned PL0' boot.log || { echo 'FAIL #526: /shell did not spawn (absent from ramfs or spawn regressed)'; exit 1; }
grep -q 'shell: hello from userspace' boot.log || { echo 'FAIL #526: /shell did not run + syscall from its own frame'; exit 1; }
grep -q '2 userspace ELF processes running' boot.log || { echo 'FAIL #526: kinit did not report both userspace processes running'; exit 1; }
ic=$(grep -c 'init: hello from userspace' boot.log); test "$ic" -eq 1 || { echo "FAIL #526: 'init: hello' x$ic (want 1) -- per-process image-frame clobber regressed (#502)"; exit 1; }
sc=$(grep -c 'shell: hello from userspace' boot.log); test "$sc" -eq 1 || { echo "FAIL #526: 'shell: hello' x$sc (want 1) -- per-process image-frame clobber regressed (#502)"; exit 1; }
# #400 render foundation through the real screen-dispatch path.
grep -q 'kardia: frame rendered painted_px=' boot.log || { echo 'FAIL #400: service loop never rendered a frame (render path dead)'; exit 1; }
px=$(grep -oE 'painted_px=[0-9]+' boot.log | head -1 | grep -oE '[0-9]+'); test "${px:-0}" -gt 0 || { echo "FAIL #400: rendered frame is BLANK (painted_px=${px:-0}) -- screen draw produced nothing"; exit 1; }
# #400 input + navigation round trip.
grep -q 'kardia: nav Home -> Search' boot.log || { echo 'FAIL #400: synthetic input did not navigate Home->Search (input dispatch / on_key broken)'; exit 1; }
grep -q 'kardia: nav Search -> Home' boot.log || { echo 'FAIL #400: back-navigation did not return to Home (screen stack broken)'; exit 1; }
# #402 clock trust hierarchy wired + seeded + driving the display.
grep -q 'kardia: clock src=manual' boot.log || { echo 'FAIL #402: ClockManager not wired/seeded (no manual source)'; exit 1; }
wall=$(grep -oE 'clock src=manual wall=[0-9]+' boot.log | head -1 | grep -oE '[0-9]+$'); test "${wall:-0}" -gt 1700000000 || { echo "FAIL #402: wall clock is not a real epoch (wall=${wall:-0}) -- ClockManager not driving time"; exit 1; }
# #461 clock health witness: elapsed_ms must advance under virt (measured
# root cause 2026-08-04); a counter/frequency regression reds here instead
# of silently hanging the wait loops that consume elapsed_ms.
grep -q 'kardia: timer elapsed_ms=advancing' boot.log || { echo 'FAIL #461: elapsed_ms not advancing under qemu (CNTFRQ/CNTPCT regression)'; exit 1; }
# #506 CLOCK_REALTIME unification: the kardia once-per-second wiring feeds
# ClockManager time into set_realtime_offset; the emitted offset must be a
# real ~2025+ epoch (an unwired offset would stay at its small default).
grep -qE 'kardia: realtime offset=[0-9]+' boot.log || { echo 'FAIL #506: kardia never emitted its realtime offset (set_realtime_offset not wired)'; exit 1; }
off=$(grep -oE 'kardia: realtime offset=[0-9]+' boot.log | head -1 | grep -oE '[0-9]+$'); test "${off:-0}" -gt 1700000000 || { echo "FAIL #506: realtime offset is not the ClockManager epoch (offset=${off:-0})"; exit 1; }
# #398 telephony: seeded mock transport, LIVE stack, Registered.
grep -q 'kardia: modem ready state=Registered' boot.log || { echo 'FAIL #398: Telephony did not initialize to Registered (AT state machine / mock wiring broken)'; exit 1; }
# #399 audio session manager + mic audit.
grep -qE 'kardia: audio ready sessions=[1-9][0-9]* mic_entries=[1-9][0-9]*' boot.log || { echo 'FAIL #399: audio session manager / mic audit not wired (no session opened or mic not logged)'; exit 1; }
# #404 status bar driven by telephony registration + security mode.
grep -q 'kardia: statusbar net=Lte' boot.log || { echo 'FAIL #404: status bar network not driven by telephony registration (modem-state bridge broken)'; exit 1; }
# #398 ring->audio integration.
grep -qE 'kardia: incoming call -> ringtone sessions=[1-9]' boot.log || { echo 'FAIL #398: incoming call did not open a ringtone session (telephony->audio integration broken)'; exit 1; }
# #398 SIM/SMS over the modem transport.
grep -qE 'kardia: sim iccid_len=[1-9][0-9]* sms_inbox=[1-9] sim_ready=true signal_bars=[1-9] operator_len=[1-9] sms_sent=true' boot.log || { echo 'FAIL #398: SIM/SMS not fully wired (ICCID/PIN/signal/operator/SMS recv+send)'; exit 1; }
# #401 BT A2DP profile + SBC/config state machine.
grep -q 'kardia: bt_audio sample_rate=44100 channels=2' boot.log || { echo 'FAIL #401: A2DP profile not wired / config state machine broken'; exit 1; }
# #404 RAT parsing drives the network label.
grep -qF 'kardia: netrat rat=Some(EUtran) net=Lte' boot.log || { echo 'FAIL #404: network label not derived from parsed +CREG <AcT> (RAT parsing broken)'; exit 1; }
# #400 heorte manager + calendar screen.
grep -qE 'kardia: heorte events=[1-9][0-9]* alarms=[1-9][0-9]* calendar_rows=[1-9][0-9]* timer_armed=true' boot.log || { echo 'FAIL #400: heorte manager not wired (events/alarms/calendar/timer)'; exit 1; }
# #403 loop-persistent firewall + verified HMAC audit chain.
grep -qE 'kardia: firewall rules=[1-9][0-9]* allowed=[1-9][0-9]* denied=[1-9][0-9]* audit_events=2 chain=ok' boot.log || { echo 'FAIL #403: firewall not loop-persistent / policy+audit path broken'; exit 1; }
# #518 FM radio: FmRadio<BootFmHw> instantiated in KernelState (NullFmHw under
# qemu), powered + tuned at smoke, FM screen fed from it.
grep -qE 'kardia: fm powered=true freq_khz=[0-9]+ rssi=-?[0-9]+ volume=[0-9]+' boot.log || { echo 'FAIL #518: FM radio controller not wired (BootFmHw/KernelState/screen feed broken)'; exit 1; }
# #737 threat monitor: log substrate fed from the real SMS surveillance
# classification path (#662); composite score is a log-derived heuristic,
# explicitly uncalibrated (sema stays unwired -- not a thumos dependency).
grep -qE 'kardia: threat alerts=[1-9][0-9]* score=[0-9]+ uncalibrated=true modem_power=true' boot.log || { echo 'FAIL #737: threat monitor log/score not wired (SMS classification -> alert -> score path broken)'; exit 1; }

# PL0 isolation + graceful user-fault kill (#487 + fault handling): each probe
# variant attempts one PL0-illegal op; the kernel must fault it, kill only the
# faulting process, and SURVIVE to the tick cap. cp15 stays the linchpin: it
# SUCCEEDS at PL1, so a broken mode-drop is a visible red, not a silent pass.
for probe in kread:data-abort kwrite:data-abort kexec:prefetch-abort cp15:undefined-instruction; do
    variant="${probe%%:*}"; kind="${probe##*:}"
    THUMOS_INIT_VARIANT="$variant" build_kernel qemu
    prc=0
    THUMOS_INIT_VARIANT="$variant" run_qemu "probe-$variant.log" || prc=$?
    echo "=== isolation probe '$variant': runner rc=$prc (want 0: kernel survives the kill) ==="
    test "$prc" -eq 0 || { echo "FAIL isolation[$variant]: kernel did not survive the PL0 fault (rc=$prc; 2/3/4=halted-in-handler 5=loop-stall 1=panic 124=hang)"; exit 1; }
    grep -q '/init spawned PL0' "probe-$variant.log" || { echo "FAIL isolation[$variant]: /init did not spawn PL0 (cannot test isolation)"; exit 1; }
    grep -q "PROBE: $variant" "probe-$variant.log" || { echo "FAIL isolation[$variant]: the wrong probe variant was built (no 'PROBE: $variant' marker -- a cfg mixup)"; exit 1; }
    grep -Eq "USERFAULT: pid=[0-9]+ kind=$kind .*killed" "probe-$variant.log" || { echo "FAIL isolation[$variant]: no USERFAULT $kind kill marker -- PL0 op did not fault (ISOLATION BROKEN) or the kill path broke"; exit 1; }
    ufc=$(grep -c 'USERFAULT:' "probe-$variant.log")
    test "$ufc" -eq 1 || { echo "FAIL isolation[$variant]: expected exactly 1 USERFAULT, got $ufc (a re-fault loop or double kill)"; exit 1; }
    grep -q 'kardia: reaped .* fault-killed' "probe-$variant.log" || { echo "FAIL isolation[$variant]: fault-killed process was not reaped (PCB-slot leak -- table exhausts at MAX_PROCS)"; exit 1; }
    ! grep -q 'init: hello from userspace' "probe-$variant.log" || { echo "FAIL isolation[$variant]: /init reached the write -- the PL0 op did NOT fault (ISOLATION BROKEN)"; exit 1; }
    grep -q 'THUMOS-QEMU: service-loop ticks=' "probe-$variant.log" || { echo "FAIL isolation[$variant]: service loop never resumed after the kill (kernel did not survive)"; exit 1; }
    grep -q 'shell: hello from userspace' "probe-$variant.log" || { echo "FAIL isolation[$variant]: /shell (PID 2) did not run -- killing /init took down its sibling (#526)"; exit 1; }
done
echo "PL0 isolation + graceful kill + reap verified: every PL0-illegal op faults, the process is killed AND reaped, the kernel survives"
echo "boot witness: PASS"
