//! Kardia -- the kernel heartbeat: post-boot KernelState + service loop.
//!
//! `kinit::run()` hands its fn-scope subsystem state to [`KernelState`], and
//! the boot context (PID 0, the kernel/idle process created by
//! `process::init`) becomes [`service_loop`]. Each wake: drain the reflex
//! fast-path FIRST (reflex.rs), then on a new 100 Hz tick poll every
//! persisted subsystem non-blockingly, render if dirty, then idle until the
//! next interrupt. Userspace runs by PREEMPTING this loop -- the timer IRQ's
//! scheduler round-robins away from PID 0 and back; the loop itself never
//! calls `process::schedule()`.
//!
//! Coexistence is VERIFIED (#482/#487 + fault handling): the qemu isolation
//! matrix boots a real PL0 `/init`, so the timer IRQ preempts PID 0 into
//! userspace, `process::switch_to`'s taken branch runs, the process faults, the
//! kernel kills + reaps it, and control round-robins back to this loop (which
//! then services ticks to the cap). That is the two-process preempt-and-return
//! soak TODO(#420) asked for, now permanent in CI.
//!
//! WHY WFI (not WFE) for the phone idle (#461): WFE has no configured event
//! source (no SEV/SEVONPEND) and parks forever under qemu-virt; WFI wakes on
//! the 100 Hz timer IRQ on both targets. The idle WFI is issued IRQ-masked
//! (see [`service_loop`]) so a reflex IRQ that fires+retires in the check ->
//! idle window cannot be lost. WHY `exceptions::ticks()`, not
//! `timer::elapsed_ms()`, as the tick source (#461): the CNTPCT-backed
//! elapsed_ms does not advance under qemu-virt, while the IRQ-incremented
//! tick counter does.

use core::fmt::Write;

use crate::audio::AudioManager;
use crate::audio_codec::BootCodec;
use crate::audio_route::RouteManager;
use crate::bluetooth::BootBtHw;
use crate::bt_audio::A2dpProfile;
use crate::clock::ClockManager;
use crate::device::DeviceRegistry;
use crate::exceptions;
use crate::kinit::BootState;
use crate::mic_audit::MicAuditLog;
use crate::power::PowerManager;
use crate::reflex;
use crate::screen_dialer::DialerScreen;
use crate::screen_home::{HomeScreen, HomeScreenState, OperatingMode};
use crate::screen_messages::MessagesScreen;
use crate::screen_search::SearchScreen;
use crate::screen_settings::SettingsMenuScreen;
use crate::security_mode::ModeManager;
use crate::sim::SimManager;
use crate::sms::SmsManager;
use crate::status_bar::{KernelStatusBar, NetworkService, StatusBarState};
#[cfg(feature = "qemu")]
use crate::telephony::RadioAccessTech;
use crate::telephony::{BootModemTransport, RatGeneration, Telephony};
use crate::uart::Uart;
use crate::ui::{Screen, ScreenId, UiManager};

/// Timer ticks per wall-clock second (exceptions.rs TICK_MS = 10).
const TICKS_PER_SECOND: u64 = 100;

/// Milliseconds per timer tick (exceptions.rs TICK_MS). `ticks * TICK_MS` is the
/// monotonic ms the ClockManager needs -- via the IRQ tick counter, which
/// advances under qemu-virt (unlike CNTPCT, #461).
const TICK_MS: u64 = 10;

/// Boot wall-clock epoch (2025-01-01 UTC) -- matches time::REALTIME_OFFSET_SECS.
/// Seeds ClockManager as a Manual (lowest-trust) source until a trusted source
/// (GPS #129 / NTP / modem RTC #398) lands; on device the modem RTC replaces
/// this at boot.
const BOOT_WALL_EPOCH: u64 = 1_735_603_200;

/// QEMU CI cap: serviced ticks before a clean semihosting-exit 0. Proves the
/// service loop RUNS -- ticks advance and the loop body executes repeatedly
/// -- not merely that boot reached its end.
///
/// NOTE: this is 50 *serviced ticks*, NOT a wall-clock duration. Under
/// qemu-virt the generic-timer CNTFRQ is uncalibrated (#461), so the tick
/// rate is not a true 100 Hz; do not read this as "500 ms".
#[cfg(feature = "qemu")]
const QEMU_TICK_CAP: u32 = 50;

/// QEMU stall escape: a hard ceiling on total loop wakes. Under qemu the idle
/// is a busy-poll (not WFI -- see [`service_loop`]) so the loop always keeps
/// spinning; if `exceptions::ticks()` ever stalls (the #461 class: timer IRQ
/// stops / a frozen counter), the serviced-tick cap can never be reached, so
/// this ceiling forces a FAST exit with a distinct diagnostic code instead of
/// a 60 s runner timeout (which is indistinguishable from CI infra flake).
/// Far above `QEMU_TICK_CAP` so healthy runs never hit it.
#[cfg(feature = "qemu")]
const QEMU_WAKE_CEILING: u32 = 5_000_000;

/// Owned post-boot kernel state: every subsystem that must outlive
/// `kinit::run()`'s init blocks lives here, moved in at the boot->service
/// handoff and owned exclusively by the service loop.
///
/// INVARIANT (load-bearing -- the whole point of this struct): a subsystem
/// may be a `KernelState` field ONLY if it is never mutated in IRQ context.
/// Single-ownership by the loop is what makes plain (unsynchronized) access
/// race-free. An IRQ-fed subsystem (the CCCI modem's CLDMA RX, a RING URC, a
/// network device's RX -- i.e. exactly #398/#402) MUST NOT be a bare field:
/// it hands data to the loop through an `IrqSpinlock`-guarded structure (the
/// [`reflex`] mechanism, generalised to carry payloads), not by the loop and
/// an ISR both touching the same object. IRQ handlers communicate with this
/// struct through reflex flags ONLY.
///
/// Follow-on wirings (#398, #400-#404) each add their subsystem as a field
/// plus one non-blocking step in [`Self::poll_all`] -- subject to the
/// invariant above.
///
/// NOTE (power split-brain, #404): `power` is persisted here, but the timer
/// IRQ independently drives DVFS/core-parking/backlight on `power`-module
/// statics. #404 must unify these into a single owner (loop-owned here, IRQ
/// enqueuing) rather than double-managing two `PowerManager`s.
pub(crate) struct KernelState {
    pub(crate) boot: BootState,
    #[expect(
        dead_code,
        reason = "device lifecycle steps land with the subsystem wirings (#398, #400-#404)"
    )]
    pub(crate) devices: DeviceRegistry,
    #[expect(
        dead_code,
        reason = "radio-policy service steps land with the security-mode wiring (#404)"
    )]
    pub(crate) power: PowerManager,
    pub(crate) mode: ModeManager,
    /// UI manager: owns the active-screen selection + navigation stack (#400).
    ui: UiManager,
    /// The home screen, re-stated + drawn each dirty tick.
    home: HomeScreen,
    /// The screens reachable from Home (#400). Each is dependency-free to
    /// construct; subsystem wirings later feed their content (#398 dialer,
    /// #402 clock into home, etc.). Screens not held here fall back to Home in
    /// the dispatch match until their subsystem PR adds the field + arm.
    messages: MessagesScreen,
    search: SearchScreen,
    dialer: DialerScreen,
    settings: SettingsMenuScreen,
    /// Cursor into the qemu synthetic-input script. Real keypad decode is
    /// hardware-gated + net-new (no KPD model on -machine virt, no decoder
    /// in-tree); #400 input dispatch is CI-verified via a scripted key sequence
    /// under qemu, exercising the exact on_key -> ScreenAction -> apply_action
    /// -> navigation path the real keypad will drive.
    #[cfg(feature = "qemu")]
    input_cursor: usize,
    /// Wall clock (#402): the trust-hierarchy time source (GPS > NTP > modem
    /// RTC > Manual). Seeded Manual at boot; the loop evaluates it each second.
    clock: ClockManager,
    /// Last computed wall-clock epoch (seconds), fed to the home-screen display
    /// each render. Replaces the previously-hardcoded 0.
    wall_clock: u64,
    /// The AT/call telephony stack (#398), or None when no initialized modem is
    /// available (a device boot where the CCCI link/AT layer did not come up).
    /// Under qemu it is a seeded mock stack; the loop drains its URCs each tick.
    telephony: Option<Telephony<BootModemTransport>>,
    /// SIM state manager (#398): PIN/ICCID/signal, queried over the modem
    /// transport Telephony owns (via `transport_mut`).
    sim: SimManager,
    /// SMS manager (#398): incoming PDU decode + inbox, outgoing send over the
    /// modem transport.
    sms: SmsManager,
    /// Audio session manager (#399): priority-preemptive sessions over the
    /// codec (NullCodec under qemu, real MT6357 on device). Event-driven -- no
    /// tick source; sessions open on ring/media/alarm events.
    audio: AudioManager<BootCodec>,
    /// Audio route arbitration (earpiece/speaker/BT/...) for the audio manager.
    route: RouteManager,
    /// Microphone access audit trail (#399): every mic-using session is
    /// recorded for the privacy dashboard.
    mic_audit: MicAuditLog,
    /// Bluetooth A2DP audio profile (#401): SBC-encoded stereo streaming over
    /// the BT HCI transport (NullBtHw under qemu; real WMT/STP on device -- the
    /// RF/HCI link is hardware-gated, so only the local profile state machine +
    /// SBC framing run in emulation).
    bt_audio: A2dpProfile<BootBtHw>,
    /// Render target: the hardware framebuffer (FB_BASE) on device, a synthetic
    /// heap buffer under qemu (the virt machine models no display), or None when
    /// no display path exists. Wiring the render loop through this makes the UI
    /// surface CI-verifiable in emulation for the first time (#400).
    fb: Option<&'static mut [u16]>,
    /// Last whole second observed, for once-per-second dirty marking.
    last_second: u64,
}

impl KernelState {
    /// Take ownership of the boot-built subsystem state. `fb` is the render
    /// target the caller resolved (hardware framebuffer, qemu synthetic buffer,
    /// or None); the UI manager + home screen are constructed here (both are
    /// dependency-free).
    pub(crate) fn new(
        boot: BootState,
        devices: DeviceRegistry,
        power: PowerManager,
        mode: ModeManager,
        fb: Option<&'static mut [u16]>,
        telephony: Option<Telephony<BootModemTransport>>,
    ) -> Self {
        Self {
            boot,
            devices,
            power,
            mode,
            ui: UiManager::new(),
            clock: {
                // Seed Manual at boot (tick_ms 0) so QEMU + a fresh device have
                // a wall clock before any trusted source is available.
                let mut c = ClockManager::new();
                c.set_manual(BOOT_WALL_EPOCH, 0);
                c
            },
            wall_clock: BOOT_WALL_EPOCH,
            telephony,
            sim: SimManager::new(),
            sms: SmsManager::new(),
            audio: AudioManager::new(BootCodec::new()),
            route: RouteManager::new(),
            mic_audit: MicAuditLog::new(),
            bt_audio: A2dpProfile::new(BootBtHw::new()),
            home: HomeScreen::new(),
            messages: MessagesScreen::new(),
            search: SearchScreen::new(),
            dialer: DialerScreen::new(),
            settings: SettingsMenuScreen::new(),
            fb,
            last_second: 0,
            #[cfg(feature = "qemu")]
            input_cursor: 0,
        }
    }

    /// The active screen as a `&mut dyn Screen`, for input dispatch (#400).
    /// Screens not yet wired as fields fall back to Home (their subsystem PR
    /// adds the field + arm); the qemu input script only navigates to wired
    /// screens, so the fallback is never exercised in CI.
    fn active_screen_mut(&mut self) -> &mut dyn Screen {
        match self.ui.active_screen() {
            ScreenId::Messages => &mut self.messages,
            ScreenId::Search => &mut self.search,
            ScreenId::Dialer => &mut self.dialer,
            ScreenId::Settings => &mut self.settings,
            _ => &mut self.home,
        }
    }

    /// Drain one synthetic key (qemu) and dispatch it through the active
    /// screen's `on_key` -> `ScreenAction` -> `UiManager::apply_action`
    /// navigation path (#400). Returns `Some((from, to))` when navigation
    /// changed the active screen, so the caller can log + re-render. On device
    /// this is a no-op until the keypad driver lands (hardware-gated).
    pub(crate) fn poll_input(&mut self) -> Option<(ScreenId, ScreenId)> {
        #[cfg(feature = "qemu")]
        {
            // A scripted round trip proving the dispatch pipeline end-to-end:
            // Home --Rsk--> Search --End--> Home. Rsk/End are the standard
            // navigate/back keys (HomeScreen::on_key, SearchScreen::on_key).
            const NAV_SCRIPT: [crate::ui::Key; 2] = [crate::ui::Key::Rsk, crate::ui::Key::End];
            let key = *NAV_SCRIPT.get(self.input_cursor)?;
            self.input_cursor += 1;
            let from = self.ui.active_screen();
            let action = self.active_screen_mut().on_key(key);
            self.ui.apply_action(action);
            let to = self.ui.active_screen();
            if from != to {
                return Some((from, to));
            }
        }
        None
    }

    /// Poll every persisted subsystem once for tick `now`. Returns true when
    /// the active screen should re-render.
    ///
    /// INVARIANT: no step may block or wait -- poll(now)/tick(now)-style calls
    /// only; anything slower belongs in a budgeted state machine inside its
    /// subsystem.
    pub(crate) fn poll_all(&mut self, now: u64) -> bool {
        // #398: drain modem URCs (RING/CLIP/CREG/CSQ) each tick, non-blocking.
        // An incoming call opens a ringtone audio session -- the phone-rings
        // integration across the wired telephony (#398) + audio (#399) stacks.
        let mut incoming_call = false;
        if let Some(t) = self.telephony.as_mut() {
            while let Some(ev) = t.poll() {
                if matches!(ev, crate::telephony::TelephonyEvent::IncomingCall { .. }) {
                    incoming_call = true;
                }
            }
        }
        if incoming_call {
            // telephony borrow released above; open the ringtone on the audio
            // manager (Idempotent-ish: a second RING while ringing is a no-op
            // preempt at the same priority).
            let route = self
                .route
                .default_route_for(crate::audio_route::SessionKind::Ringtone);
            self.audio
                .open_session(crate::audio_route::SessionKind::Ringtone, route)
                .ok();
        }
        // NOTE(foundation): the home clock (once per second) is the only
        // persisted render input; each subsystem wiring adds its step here.
        let second = now / TICKS_PER_SECOND;
        if second != self.last_second {
            self.last_second = second;
            // #402: advance the trust-hierarchy clock and cache the wall time
            // for the render. now_ms via the IRQ tick counter (advances under
            // qemu, #461). evaluate() re-checks source validity/staleness.
            let now_ms = now * TICK_MS;
            self.clock.evaluate(now_ms);
            self.wall_clock = self.clock.get_wall_clock(now_ms);
            return true;
        }
        false
    }

    /// The cellular network service shown in the status bar (#404), derived from
    /// the wired telephony registration + its radio access technology. The RAT
    /// comes from the `+CREG` `<AcT>` field: 2G shows `Edge`, 3G `ThreeG`, 4G
    /// `Lte`. A registered modem that reports no `<AcT>` falls back to `Lte`
    /// (the device requests LTE-only via `AT+COPS=0,,,7`); unregistered or no
    /// modem is `NoService`.
    fn status_network(&self) -> NetworkService {
        match self.telephony.as_ref() {
            Some(t) if t.is_registered() => match t.rat().map(|rat| rat.generation()) {
                Some(RatGeneration::TwoG) => NetworkService::Edge,
                Some(RatGeneration::ThreeG) => NetworkService::ThreeG,
                Some(RatGeneration::FourG) | None => NetworkService::Lte,
            },
            _ => NetworkService::NoService,
        }
    }

    /// Render the active screen to the framebuffer (#400). Called when the frame
    /// is dirty (and once at loop entry for the initial frame). No-op when there
    /// is no render target.
    ///
    /// The status badge + operating mode are read LIVE from the security-mode
    /// manager (#404), and the wall-clock epoch from the ClockManager trust
    /// hierarchy (#402) -- both formerly hardcoded.
    pub(crate) fn render_if_dirty(&mut self) -> Option<usize> {
        // Computed before the fb borrow: status_network() reads &self as a whole
        // (returns a Copy), which cannot coexist with the &mut self.fb below.
        let network = self.status_network();
        let fb = self.fb.as_deref_mut()?;
        let status = StatusBarState {
            network,
            battery_pct: 0,
            mode_char: self.mode.mode_char(),
            mode_badge: Some(self.mode.status_badge()),
            mode_badge_color: Some(self.mode.status_badge_color()),
            threat_high: !self.boot.modem_ok,
            ..StatusBarState::default()
        };
        self.home.update_state(HomeScreenState {
            epoch_secs: self.wall_clock,
            carrier: "",
            mode: OperatingMode::from(self.mode.mode()),
            unread_count: 0,
        });
        // Dispatch to the ACTIVE screen (#400): the loop renders whatever the
        // navigation stack has selected, not just Home. Inlined (not
        // active_screen_mut) because fb already holds a &mut borrow of self.fb;
        // this immutable match over disjoint screen fields coexists with it.
        let screen: &dyn Screen = match self.ui.active_screen() {
            ScreenId::Messages => &self.messages,
            ScreenId::Search => &self.search,
            ScreenId::Dialer => &self.dialer,
            ScreenId::Settings => &self.settings,
            _ => &self.home,
        };
        self.ui
            .render(screen, |s| KernelStatusBar::draw(s, &status), fb);
        // Returns the painted (non-blank) pixel count so the caller (which owns
        // serial) can emit the #400 CI witness. The render path was DEAD under
        // qemu until now (display_ok is always false on -machine virt); a
        // non-zero count proves the frame rendered CONTENT, not just that the
        // loop ticked. On device the count is unused (the caller drops it).
        Some(fb.iter().filter(|&&px| px != 0).count())
    }

    /// Boot-time audio smoke (#399, qemu): open a VoiceCall session -- which
    /// powers the codec + arbitrates a route + records mic access -- then close
    /// it. Exercises the session manager, RouteManager, and MicAuditLog with the
    /// NullCodec (no real MT6357 I/O). Returns (peak session count, mic-audit
    /// entries) for the CI witness. On device this smoke is not run; real audio
    /// sessions open on ring/media events.
    #[cfg(feature = "qemu")]
    pub(crate) fn audio_boot_smoke(&mut self) -> (usize, usize) {
        use crate::audio_route::SessionKind;
        let route = self.route.default_route_for(SessionKind::VoiceCall);
        let opened = self.audio.open_session(SessionKind::VoiceCall, route);
        let mic_id = self
            .mic_audit
            .log_start(SessionKind::VoiceCall, b"boot-smoke", 0);
        let sessions = self.audio.session_count();
        let mic_entries = self.mic_audit.len();
        if let Ok(id) = opened {
            self.audio.close_session(id).ok();
        }
        self.mic_audit.log_end(mic_id, 10).ok();
        (sessions, mic_entries)
    }

    /// Boot-time SIM/SMS smoke (#398, qemu): query the SIM ICCID over the modem
    /// transport (mock-seeded response), then decode + file a known incoming SMS
    /// PDU. Returns (ICCID byte length, inbox message count) for the CI witness,
    /// exercising both managers against the wired modem transport.
    #[cfg(feature = "qemu")]
    pub(crate) fn sim_sms_boot_smoke(&mut self) -> (usize, usize) {
        // SIM: query the ICCID over Telephony's owned transport.
        let iccid_len = if let Some(t) = self.telephony.as_mut() {
            self.sim.query_iccid(t.transport_mut()).ok();
            self.sim.sim_info().iccid_len as usize
        } else {
            0
        };
        // SMS: decode a known SMS-DELIVER PDU ("Hello" from +1234567890) + file it.
        const PDU: &[u8] = &[
            0x00, 0x00, 0x0A, 0x91, 0x21, 0x43, 0x65, 0x87, 0x09, 0x00, 0x00, 0x32, 0x10, 0x51,
            0x21, 0x03, 0x00, 0x00, 0x05, 0xC8, 0x32, 0x9B, 0xFD, 0x06,
        ];
        if let Ok(msg) = SmsManager::handle_incoming(PDU) {
            self.sms.receive(msg).ok();
        }
        (iccid_len, self.sms.inbox().len())
    }

    /// Boot-time BT A2DP smoke (#401, qemu): configure the A2DP profile (SBC
    /// framing at 44.1 kHz stereo) and report the resulting sample rate +
    /// channels. Proves the profile state machine + SBC encoder are instantiated
    /// + functional; the RF/HCI link is hardware-gated (NullBtHw yields no
    /// controller events, so no connection completes).
    #[cfg(feature = "qemu")]
    pub(crate) fn bt_audio_boot_smoke(&mut self) -> (u32, u8) {
        self.bt_audio.configure(44_100, 2).ok();
        (self.bt_audio.sample_rate(), self.bt_audio.channels())
    }

    /// Boot-time RAT smoke (#404, qemu): report the radio access technology the
    /// wired modem registered on -- parsed from the seeded `+CREG` `<AcT>` --
    /// and the status-bar network label it drives. Proves the label is derived
    /// from a real parsed `<AcT>` (only the parse path yields `EUtran`), not a
    /// constant `Lte`.
    #[cfg(feature = "qemu")]
    pub(crate) fn netrat_boot_smoke(&self) -> (Option<RadioAccessTech>, NetworkService) {
        let rat = self.telephony.as_ref().and_then(Telephony::rat);
        (rat, self.status_network())
    }

    /// Execute pending reflex fast-path events in privileged (loop) context.
    pub(crate) fn handle_reflex(&mut self, pending: reflex::Pending, serial: &mut Uart) {
        if pending.panic_wipe {
            let _ = serial.write_str("[kardia] REFLEX panic-wipe\r\n"); // WHY: best-effort loop diagnostic; must not block on a failed UART write
            // TODO(#404)[deliberate-prudent]: invoke panic_wipe via the persisted key manager.
        }
        if pending.duress {
            let _ = serial.write_str("[kardia] REFLEX duress\r\n"); // WHY: best-effort loop diagnostic; must not block on a failed UART write
            // TODO(#404)[deliberate-prudent]: duress transition via self.mode + wipe policy.
        }
        if pending.incoming_ring {
            let _ = serial.write_str("[kardia] REFLEX incoming-ring\r\n"); // WHY: best-effort loop diagnostic; must not block on a failed UART write
            // TODO(#398)[deliberate-prudent]: ring UI + audio route via persisted telephony.
        }
    }
}

/// Name a `ScreenId` for the #400 qemu navigation CI marker.
#[cfg(feature = "qemu")]
fn screen_id_name(id: ScreenId) -> &'static str {
    match id {
        ScreenId::Home => "Home",
        ScreenId::Search => "Search",
        ScreenId::Messages => "Messages",
        ScreenId::Dialer => "Dialer",
        ScreenId::Settings => "Settings",
        _ => "Other",
    }
}

/// Emit one CI-witness line atomically under an IRQ mask.
///
/// WHY (#513): userspace `/init` preempts this PID-0 loop and shares the single
/// UART, so an unmasked multi-byte `write!` can be split mid-line by a timer IRQ
/// -> scheduler -> userspace write, corrupting the `kardia:` marker the CI greps
/// match. Masking IRQs for the one line keeps it intact; the line is short and
/// the UART write is non-blocking, so the masked section is bounded.
#[cfg(feature = "qemu")]
fn emit_marker(serial: &mut Uart, args: core::fmt::Arguments) {
    let _guard = crate::irq::IrqGuard::new();
    serial.write_fmt(args).ok();
}

/// The kernel service loop -- PID 0's body. Never returns (on the phone).
///
/// INVARIANT: entered with scheduling already enabled (kinit calls
/// `process::enable_scheduling()` first); everything here tolerates preemption
/// at any instruction outside an `IrqSpinlock` critical section.
pub(crate) fn service_loop(mut kernel: KernelState, mut serial: Uart) -> ! {
    let _ = serial.write_str("[kardia] service loop running\r\n"); // WHY: best-effort loop diagnostic; must not block on a failed UART write
    // #400: paint the initial home frame immediately, rather than waiting for
    // the first once-per-second dirty tick.
    #[cfg(not(feature = "qemu"))]
    kernel.render_if_dirty();
    // Loop-entry CI witnesses (#398-#404). Do the real work FIRST, unmasked:
    // paint the initial home frame + run each boot-smoke, capturing values.
    // Then emit the whole marker burst under an IRQ mask (below) -- userspace
    // /init preempts this PID-0 loop and shares the single UART, so an unmasked
    // burst can be split mid-line (the #513 flake: `init: hello from userspace`
    // interleaved into a `kardia: netrat` line, breaking the grep).
    #[cfg(feature = "qemu")]
    {
        // #400: paint the initial home frame immediately (not waiting for the
        // first once-per-second dirty tick).
        let painted = kernel.render_if_dirty();
        // #402: trust-hierarchy clock wired + seeded (source None -> Manual, a
        // real ~2025 epoch driving the home display). Per-second advancement is
        // a get_wall_clock property (unit tested); the boot proves the WIRING.
        let clock_src = kernel.clock.current_source();
        let wall = kernel.wall_clock;
        // #399: audio session manager + route + mic audit wired -- a VoiceCall
        // session opens + a mic-access entry is recorded (impossible before).
        let (sessions, mic_entries) = kernel.audio_boot_smoke();
        // #404: status-bar cellular field driven by the wired telephony
        // registration (was hardcoded); mode char by the security-mode manager.
        let net = kernel.status_network();
        let mode_char = kernel.mode.mode_char();
        // #398: SIM + SMS wired -- ICCID queried over the modem transport + a
        // known incoming SMS PDU decoded into the inbox.
        let (iccid_len, sms_inbox) = kernel.sim_sms_boot_smoke();
        // #401: BT A2DP profile wired + its SBC/config state machine runs
        // (44.1 kHz stereo). RF/HCI is hardware-gated.
        let (bt_rate, bt_ch) = kernel.bt_audio_boot_smoke();
        // #404: status-bar network label derived from the parsed +CREG <AcT>
        // (EUtran can only come from the parse path), not a constant.
        let (rat, netrat_net) = kernel.netrat_boot_smoke();

        // Emit each witness line atomically (emit_marker masks IRQs per line)
        // so userspace /init cannot split a `kardia:` line mid-write (#513).
        if let Some(px) = painted {
            emit_marker(
                &mut serial,
                format_args!("kardia: frame rendered painted_px={px}\r\n"),
            );
        }
        emit_marker(
            &mut serial,
            format_args!("kardia: clock src={clock_src} wall={wall}\r\n"),
        );
        emit_marker(
            &mut serial,
            format_args!("kardia: audio ready sessions={sessions} mic_entries={mic_entries}\r\n"),
        );
        emit_marker(
            &mut serial,
            format_args!("kardia: statusbar net={net:?} mode={mode_char}\r\n"),
        );
        emit_marker(
            &mut serial,
            format_args!("kardia: sim iccid_len={iccid_len} sms_inbox={sms_inbox}\r\n"),
        );
        emit_marker(
            &mut serial,
            format_args!("kardia: bt_audio sample_rate={bt_rate} channels={bt_ch}\r\n"),
        );
        emit_marker(
            &mut serial,
            format_args!("kardia: netrat rat={rat:?} net={netrat_net:?}\r\n"),
        );
    }
    let mut last_tick = exceptions::ticks();
    #[cfg(feature = "qemu")]
    let mut serviced: u32 = 0;
    #[cfg(feature = "qemu")]
    let mut wakes: u32 = 0;
    // #398: emit the ring->audio CI witness once, when the seeded RING URC has
    // driven the loop to open a ringtone session.
    #[cfg(feature = "qemu")]
    let mut ring_logged = false;
    loop {
        #[cfg(feature = "qemu")]
        {
            wakes += 1;
            if wakes >= QEMU_WAKE_CEILING {
                // ticks() stalled before QEMU_TICK_CAP -- fail FAST with a
                // distinct code rather than let the runner time out (#461).
                let _ = write!(
                    serial,
                    "THUMOS-QEMU: service-loop STALLED wakes={wakes} ticks={serviced}\r\n"
                );
                crate::qemu::request_exit(5);
            }
        }

        // Reflex fast-path FIRST -- drained on every wake, ahead of the tick
        // test, so a raised flag is handled promptly. Re-loop after handling
        // so a reflex handler that raises another is serviced immediately.
        let pending = reflex::drain();
        if pending.any() {
            kernel.handle_reflex(pending, &mut serial);
            continue;
        }

        let now = exceptions::ticks();
        if now != last_tick {
            // NOTE: a preemption gap of K ticks collapses to ONE service pass
            // with the latest `now` -- poll(now) interfaces are time-based, so
            // catch-up replay is unnecessary.
            last_tick = now;
            // WHY (#491 review): PID 0 is the parent of every spawned process,
            // so it reaps fault-killed (and exited) children each tick --
            // otherwise a fault-killed PCB slot leaks and the process table
            // exhausts at MAX_PROCS after repeated user faults. The marker is
            // the reaped-half witness the CI isolation matrix asserts.
            let reaped = crate::process::reap_dead_children();
            if reaped > 0 {
                let _ = write!(
                    serial,
                    "kardia: reaped {reaped} fault-killed process(es)\r\n"
                ); // WHY: best-effort diagnostic + CI marker
            }
            // #400: drive input each tick through the active screen's on_key ->
            // ScreenAction -> navigation path; a navigation change re-renders.
            let nav = kernel.poll_input();
            #[cfg(feature = "qemu")]
            if let Some((from, to)) = nav {
                // WHY: #400 CI witness -- proves synthetic input drove navigation.
                emit_marker(
                    &mut serial,
                    format_args!(
                        "kardia: nav {} -> {}\r\n",
                        screen_id_name(from),
                        screen_id_name(to)
                    ),
                );
            }
            let ticked = kernel.poll_all(now);
            #[cfg(feature = "qemu")]
            if !ring_logged && kernel.audio.session_count() > 0 {
                ring_logged = true;
                emit_marker(
                    &mut serial,
                    format_args!(
                        "kardia: incoming call -> ringtone sessions={}\r\n",
                        kernel.audio.session_count()
                    ),
                );
            }
            if ticked || nav.is_some() {
                #[cfg(feature = "qemu")]
                if let Some(px) = kernel.render_if_dirty() {
                    // WHY: #400 CI witness.
                    emit_marker(
                        &mut serial,
                        format_args!("kardia: frame rendered painted_px={px}\r\n"),
                    );
                }
                #[cfg(not(feature = "qemu"))]
                kernel.render_if_dirty();
            }
            #[cfg(feature = "qemu")]
            {
                serviced += 1;
                if serviced >= QEMU_TICK_CAP {
                    let _ = write!(serial, "THUMOS-QEMU: service-loop ticks={serviced}\r\n"); // WHY: best-effort CI marker; exit follows regardless
                    crate::qemu::request_exit(0);
                }
            }
            continue;
        }

        // Idle: no reflex, no new tick.
        idle(last_tick);
    }
}

/// Idle until the next interrupt.
///
/// On the phone: IRQ-masked WFI. WHY masked (closes the lost-wakeup window):
/// a reflex IRQ that fires+retires between the unmasked `drain` above and the
/// WFI would, with IRQs enabled, leave WFI waiting for an interrupt that
/// already passed -- degrading the fast-path to the 10 ms tick cadence it
/// exists to beat, and hiding a dependency on the timer never being gated (a
/// future tickless idle would then hang). Masking + re-checking under the
/// mask + WFI-while-masked (ARM WFI wakes on a GIC-pending interrupt
/// regardless of CPSR.I) closes it: either the re-check sees the flag/tick, or
/// the pending IRQ wakes the WFI; unmasking on guard drop takes it.
///
/// Under qemu: a busy-poll (`spin_loop`), NOT WFI, so the loop keeps spinning
/// and [`QEMU_WAKE_CEILING`] can always fire a fast diagnostic exit if ticks
/// stall (#461) -- termination must not itself depend on WFI waking.
fn idle(last_tick: u64) {
    #[cfg(feature = "qemu")]
    {
        let _ = last_tick;
        core::hint::spin_loop();
    }
    #[cfg(not(feature = "qemu"))]
    {
        let _guard = crate::irq::IrqGuard::new();
        // Re-check under the mask: a reflex flag set by an IRQ that already
        // retired, or a tick that advanced, means there is work -- skip WFI.
        if !reflex::peek_pending() && exceptions::ticks() == last_tick {
            crate::power::idle();
        }
        // _guard drops here -> IRQs unmask -> any GIC-pending IRQ is taken.
    }
}
