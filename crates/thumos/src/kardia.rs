//! Kardia -- the kernel heartbeat: post-boot `KernelState` + service loop.
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
//! soak, permanent in CI.
//!
//! WHY WFI (not WFE) for the phone idle (#461): WFE has no configured event
//! source (no SEV/SEVONPEND) and parks forever under qemu-virt; WFI wakes on
//! the 100 Hz timer IRQ on both targets. The idle WFI is issued IRQ-masked
//! (see [`service_loop`]) so a reflex IRQ that fires+retires in the check ->
//! idle window cannot be lost. WHY `exceptions::ticks()`, not
//! `timer::elapsed_ms()`, as the tick source (#461): the CNTPCT-backed
//! `elapsed_ms` does not advance under qemu-virt, while the IRQ-incremented
//! tick counter does.

use core::fmt::Write;

use crate::audio::AudioManager;
use crate::audio_codec::BootCodec;
use crate::audio_route::RouteManager;
use crate::audit::AuditLog;
use crate::bluetooth::BootBtHw;
use crate::bt_audio::A2dpProfile;
use crate::clock::ClockManager;
use crate::device::DeviceRegistry;
use crate::exceptions;
use crate::fm_radio::{BootFmHw, FmRadio};
use crate::heorte::HeorteManager;
use crate::key_manager::SecureKey;
use crate::kinit_plan::BootState;
use crate::mic_audit::MicAuditLog;
use crate::net::{BootNetDevice, FirewallDevice, NetworkStack};
use crate::power::PowerManager;
use crate::reflex;
use crate::screen_calendar::CalendarScreen;
use crate::screen_dialer::DialerScreen;
use crate::screen_fm::FmScreen;
use crate::screen_home::{HomeScreen, HomeScreenState, OperatingMode};
use crate::screen_messages::MessagesScreen;
use crate::screen_privacy::PrivacyScreen;
use crate::screen_radio::RadioControlScreen;
use crate::screen_search::SearchScreen;
use crate::screen_settings::SettingsMenuScreen;
use crate::screen_threat::{ThreatLevel, ThreatMonitor};
// WHY(#737): the alert constructors are reachable only from the qemu boot
// smoke; production has no detector feeding this screen yet (see the
// no-detector-vs-no-alerts gap filed alongside this change).
#[cfg(feature = "qemu")]
use crate::screen_threat::{ThreatAlert, ThreatAlertType};
use crate::screen_unimplemented::UnimplementedScreen;
use crate::security::{KEY_SIZE, SHA256_DIGEST_LEN};
use crate::security_mode::ModeManager;
use crate::sim::SimManager;
use crate::sms::SmsManager;
use crate::status_bar::{KernelStatusBar, NetworkService, StatusBarState};
use crate::telephony::{BootModemTransport, RadioAccessTech, RatGeneration, Telephony};
use crate::uart::Uart;
use crate::ui::{Screen, ScreenId, ScreenKind, UiManager, screen_kind};

/// Timer ticks per wall-clock second (exceptions.rs `TICK_MS` = 10).
const TICKS_PER_SECOND: u64 = 100;

/// Milliseconds per timer tick (exceptions.rs `TICK_MS`). `ticks * TICK_MS` is the
/// monotonic ms the `ClockManager` needs -- via the IRQ tick counter, which
/// advances under qemu-virt (unlike CNTPCT, #461).
const TICK_MS: u64 = 10;

/// Boot wall-clock epoch (2025-01-01 UTC) -- matches `time::REALTIME_OFFSET_SECS`.
/// Seeds `ClockManager` as its lowest-precedence Manual source until another
/// source explicitly updates it. GPS, NTP, and modem RTC are all unauthenticated
/// inputs (#861), and no production call site supplies any of them today;
/// modem transport/source acquisition remain #398/#753 work.
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
/// Follow-on wirings (#398, #753, #862, #863, #874, #879) add or complete their subsystem
/// plus one non-blocking step in [`Self::poll_all`] -- subject to the
/// invariant above.
///
/// NOTE: Power policy is held here, while the timer IRQ
/// independently owns only display-timeout request bookkeeping in
/// `power`-module statics.
/// CPU DVFS/core-parking calls are absent pending #879's source-grounded
/// policy and actuator. #874 owns requested/applied/observed radio state;
/// #862 is limited to the PMIC/PWRAP transaction seam.
pub(crate) struct KernelState {
    pub(crate) boot: BootState,
    #[expect(
        dead_code,
        reason = "device lifecycle steps land with the subsystem wirings (#398, #753, #862, #863, #874, #879)"
    )]
    pub(crate) devices: DeviceRegistry,
    #[expect(
        dead_code,
        reason = "radio-policy effects require requested/applied/observed wiring (#874) and a valid PWRAP seam (#862)"
    )]
    pub(crate) power: PowerManager,
    pub(crate) mode: ModeManager,
    /// UI manager: owns the active-screen selection + navigation stack (#400).
    ui: UiManager,
    /// The home screen, re-stated + drawn each dirty tick.
    home: HomeScreen,
    /// The screens reachable from Home (#400). Each is dependency-free to
    /// construct; subsystem wirings later feed their content (#398 dialer,
    /// #402 clock into home, etc.). A `ScreenId` not held here as a field
    /// classifies as [`ScreenKind::NotImplemented`] and renders through
    /// [`Self::not_implemented`] until its subsystem PR adds the field + arm
    /// (#730 -- this used to silently fall back to Home instead).
    messages: MessagesScreen,
    search: SearchScreen,
    dialer: DialerScreen,
    settings: SettingsMenuScreen,
    /// Calendar screen (#400): renders the agenda fed by `heorte`. Reachable via
    /// the screen stack; content comes from the heorte manager each render.
    calendar: CalendarScreen,
    /// FM radio controller + screen (#518): the `FmRadio<BootFmHw>` state
    /// machine runs under emulation (`NullFmHw`) and feeds `fm_screen`; the
    /// non-test WMT backend is still a software stub tracked by #129.
    fm: FmRadio<BootFmHw>,
    fm_screen: FmScreen,
    /// Privacy dashboard (#737): the data-category list is self-managed
    /// (no subsystem feeds it yet -- populating sizes from `lfs.rs` inode
    /// metadata is separate follow-on work). The purge-confirmation gate
    /// needs a SHA-256 hash of the device's configured purge passphrase to
    /// compare against; no such passphrase reaches `KernelState` today (the
    /// boot-time passphrase subsystem, #446/#618, runs only on real
    /// hardware under `secure_boot_ok` and never persists its key material
    /// past `kinit`'s local scope -- see `kinit.rs`'s own `LockScreen::new`
    /// call sites, which face the identical gap and use the same all-zero
    /// placeholder for the same reason). `[0u8; SHA256_DIGEST_LEN]` cannot
    /// be produced by hashing any digit sequence a user could enter, so the
    /// gate fails closed (purge permanently refused) rather than accepting
    /// a fabricated credential.
    privacy: PrivacyScreen,
    /// Radio control panel (#737): sets a DESIRED radio preset
    /// (COVERT LOCK / STEALTH / RESTORE); genuinely self-contained --
    /// there is no radio-policy manager anywhere in the kernel that reads
    /// this state and applies it to wifi/gps/bluetooth/cellular hardware.
    /// WiFi/GPS/Bluetooth production backends remain software work under #129
    /// before hardware qualification, and none touches `KernelState`; the
    /// Bluetooth adapter is local to kinit. The screen owns and renders its own state, exactly
    /// like Messages/Search/Dialer/Settings before any subsystem fed them.
    radio: RadioControlScreen,
    /// Threat monitor (#737): score as a lens over the log, not either
    /// alone (operator decision). The alert log is fed from the real SMS
    /// surveillance classification path (#662,
    /// `ThreatAlertType::from_message_class`); the composite score is
    /// derived from that log by `recompute_score_from_log`, a heuristic
    /// explicitly labelled "UNCAL" in the rendered UI -- NOT sema's
    /// detector engine, which is not a thumos dependency and cannot reach
    /// this state (see `screen_threat.rs`'s module doc; #555 calibrated
    /// sema's own corpus, it did not wire sema into thumos).
    threat: ThreatMonitor,
    /// Fallback for any `ScreenId` [`screen_kind`] classifies as
    /// [`ScreenKind::NotImplemented`] (#730): renders an unmistakable,
    /// screen-naming "NOT IMPLEMENTED" state instead of the render
    /// dispatch silently falling through to Home. `active_screen_mut` and
    /// `render_if_dirty` both call `set_screen` on this before selecting
    /// it, so the label always names the screen actually requested.
    not_implemented: UnimplementedScreen,
    /// Cursor into the qemu synthetic-input script. The non-qemu service-loop
    /// input path is still a software stub (#753); later M7 qualification also
    /// needs the physical KPD because -machine virt has no KPD model. #400 input
    /// dispatch is CI-verified via a scripted key sequence
    /// under qemu, exercising the exact `on_key` -> `ScreenAction` -> `apply_action`
    /// -> navigation path the real keypad will drive.
    #[cfg(feature = "qemu")]
    input_cursor: usize,
    /// Wall clock (#402): current freshness selector (GPS > plain NTP > modem
    /// RTC > Manual). Its external inputs are unauthenticated; #861 owns the
    /// trust-policy correction before automatic acquisition is wired.
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
    /// codec (`NullCodec` under qemu; fail-closed `Mt6357Codec` on M7 until
    /// #862 provides a source-grounded PMIC transport).
    audio: AudioManager<BootCodec>,
    /// Audio route arbitration (earpiece/speaker/BT/...) for the audio manager.
    route: RouteManager,
    /// Microphone audit object (#399). The QEMU smoke records one row manually;
    /// `AudioManager` does not yet enforce an audit record on every mic transition.
    mic_audit: MicAuditLog,
    /// Bluetooth A2DP profile (#401): QEMU reaches configuration over `NullBtHw`.
    /// `StubSbcEncoder` still emits zero audio, and #129 owns the non-test HCI/ACL
    /// backend before any WMT/STP/RF qualification.
    bt_audio: A2dpProfile<BootBtHw>,
    /// Calendar/alarm/timer/stopwatch manager (#400): holds scheduled events +
    /// alarms; the loop checks alarms once per second and the calendar screen
    /// renders its agenda. Pure tick-based logic (no hardware).
    heorte: HeorteManager,
    /// Loop-persistent network stack (#403): the SINGLE kernel firewall lives
    /// inside this device wrapper, taking runtime policy via `add_rule` and
    /// emitting Log/Deny audit events at the packet drop-site.
    ///
    /// INVARIANT-SAFE as a bare field: the device is synchronous/polled (the
    /// loopback in-memory queue today; a polled `WiFi` adapter later) and is
    /// mutated only from loop context. If a future NIC becomes IRQ-fed (#129),
    /// its ISR MUST deposit frames into an `IrqSpinlock`/reflex ring that the
    /// loop drains -- this field never becomes IRQ-touched.
    net: NetworkStack<FirewallDevice<BootNetDevice>>,
    /// Per-boot HMAC-chain audit trail (#403), loop-owned. #863 owns the
    /// persistent key/head/epoch needed for rollback and truncation evidence.
    /// Firewall Log/Deny events drain into it each tick.
    audit: AuditLog,
    /// Interim session audit HMAC key (#403): CSPRNG-seeded in kinit, volatile
    /// (RAM-only, zeroized on drop). All-zero when the CSPRNG was unavailable --
    /// `log_event` then fails closed (`NoKey`). Replaced by the key-hierarchy
    /// audit key when persistent audit integration lands (#863).
    audit_key: SecureKey<KEY_SIZE>,
    /// Render target: the hardware framebuffer (`FB_BASE`) on device, a synthetic
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
        net: NetworkStack<FirewallDevice<BootNetDevice>>,
        audit_key: [u8; KEY_SIZE],
    ) -> Self {
        // #874: CCCI boot-path availability is the only status known here.
        // Initialize it on every target; the monitor's fail-closed default is
        // only for callers with no boot receipt.
        let threat = ThreatMonitor::new_with_modem_path(boot.modem_ok);

        Self {
            boot,
            devices,
            power,
            mode,
            net,
            audit: AuditLog::new(),
            audit_key: SecureKey::new(audit_key),
            ui: UiManager::new(),
            clock: {
                // Seed Manual at boot (tick_ms 0) so QEMU + a fresh device have
                // a wall clock before any higher-precedence source is available.
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
            heorte: HeorteManager::new(),
            home: HomeScreen::new(),
            messages: MessagesScreen::new(),
            search: SearchScreen::new(),
            dialer: DialerScreen::new(),
            settings: SettingsMenuScreen::new(),
            calendar: CalendarScreen::new(),
            fm: FmRadio::new(BootFmHw::new()),
            fm_screen: FmScreen::new(),
            // WHY the all-zero hash: see the `privacy` field doc above --
            // no provisioned purge/unlock passphrase reaches KernelState,
            // so this is an intentionally unsatisfiable placeholder, not a
            // working credential.
            privacy: PrivacyScreen::new([0u8; SHA256_DIGEST_LEN]),
            radio: RadioControlScreen::new(),
            threat,
            not_implemented: UnimplementedScreen::new(),
            fb,
            last_second: 0,
            #[cfg(feature = "qemu")]
            input_cursor: 0,
        }
    }

    /// The active screen as a `&mut dyn Screen`, for input dispatch (#400).
    /// Classified through [`screen_kind`] -- the same table `render_if_dirty`
    /// matches on -- so the input and render dispatches cannot silently
    /// disagree about which `ScreenId`s are wired (#730: `FmRadio` used to
    /// take input while Home stayed painted, because this match and the
    /// render match were two independent, drifted tables).
    fn active_screen_mut(&mut self) -> &mut dyn Screen {
        let id = self.ui.active_screen();
        match screen_kind(id) {
            ScreenKind::Home => &mut self.home,
            ScreenKind::Messages => &mut self.messages,
            ScreenKind::Search => &mut self.search,
            ScreenKind::Dialer => &mut self.dialer,
            ScreenKind::Settings => &mut self.settings,
            ScreenKind::Calendar => &mut self.calendar,
            ScreenKind::FmRadio => &mut self.fm_screen,
            ScreenKind::Privacy => &mut self.privacy,
            ScreenKind::RadioControl => &mut self.radio,
            ScreenKind::ThreatMonitor => &mut self.threat,
            ScreenKind::NotImplemented => {
                self.not_implemented.set_screen(id);
                &mut self.not_implemented
            }
        }
    }

    /// Drain one synthetic key (qemu) and dispatch it through the active
    /// screen's `on_key` -> `ScreenAction` -> `UiManager::apply_action`
    /// navigation path (#400). Returns `Some((from, to))` when navigation
    /// changed the active screen, so the caller can log + re-render. On device
    /// this remains a software no-op until the service-loop input path is wired
    /// to the existing boot-time keypad path (#753), before M7 qualification.
    // WHY: under `feature = "qemu"` this fully uses self (input_cursor, ui,
    // active_screen_mut()); only the non-qemu build reduces to the
    // documented `None` stub above, where self genuinely goes unused until
    // the service-loop input path lands. Scope the allow to that build only.
    #[cfg_attr(not(feature = "qemu"), allow(clippy::unused_self))]
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
        // now_ms via the IRQ tick counter (advances under qemu, #461).
        let now_ms = now * TICK_MS;
        // #403: drive the loop-persistent net stack + commit firewall Log/Deny
        // events to the audit trail every tick. poll() with zero configured
        // sockets is O(1), and the drain is a no-op when the event queue is
        // empty; the firewall evaluation itself is clock-free.
        //
        // INVARIANT: `now_ms` is a device-uptime millisecond count
        // (tick count x TICK_MS); `i64::MAX` ms is ~292 million years of
        // uptime, so this bit-reinterpretation (required by smoltcp's
        // `Instant::from_millis(i64)`) cannot flip sign.
        self.net
            .poll(crate::net::instant_from_millis(now_ms.cast_signed()));
        let Self {
            net,
            audit,
            audit_key,
            ..
        } = self;
        crate::firewall::flush_packet_audit(
            net.device_mut().firewall_mut(),
            audit,
            audit_key.as_bytes(),
            now_ms,
        );
        // NOTE(foundation): the home clock (once per second) is the only
        // persisted render input; each subsystem wiring adds its step here.
        let second = now / TICKS_PER_SECOND;
        if second != self.last_second {
            self.last_second = second;
            // #402: apply the clock's source-precedence policy and cache the wall
            // time for the render. evaluate() re-checks validity/staleness; it
            // does not authenticate GPS, NTP, or modem RTC (#861).
            self.clock.evaluate(now_ms);
            self.wall_clock = self.clock.get_wall_clock(now_ms);
            // #506: keep the userspace CLOCK_REALTIME view unified with the
            // ClockManager source selection — sys_clock_gettime(CLOCK_REALTIME)
            // must read this same wall time, not an independently-seeded
            // offset. The #461 Step-5 witness proves the CNTPCT and IRQ-tick
            // bases agree under virt, so set_realtime_offset's internal
            // monotonic_secs() basis is sound. An ImplausibleEpoch rejection
            // is the hostile-modem guard: fail closed, keep the old offset.
            // SAFETY: called from the loop's privileged context, single-core.
            unsafe {
                let _ = crate::time::set_realtime_offset(self.wall_clock); // kanon:ignore RUST/no-silent-result-swallow -- fail-closed by design: an ImplausibleEpoch rejection (see WHY above) keeps the prior offset, nothing to do with an error here
            }
            // #400: check scheduled alarms against the fresh wall time + advance
            // the countdown timer. The firing IDs / expiry have no sink yet
            // (notification routing is a follow-on); the calls still advance
            // one-shot auto-disable + timer countdown state.
            self.heorte.check_alarms(self.wall_clock);
            self.heorte.timer_mut().update(now_ms);
            // #442: enforce the A2DP Connecting deadline against the loop's
            // IRQ-tick base — a peer that never finishes signaling moves to
            // Error(Timeout) instead of hanging the profile forever.
            self.bt_audio.check_timeout(now_ms);
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
            Some(t) if t.is_registered() => match t.rat().map(RadioAccessTech::generation) {
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
    /// manager (#404), and the wall-clock epoch from `ClockManager`'s provisional
    /// source precedence (#402/#861) -- both formerly hardcoded.
    pub(crate) fn render_if_dirty(&mut self) -> Option<usize> {
        // Computed before the fb borrow: status_network() reads &self as a whole
        // (returns a Copy), which cannot coexist with the &mut self.fb below.
        let network = self.status_network();
        // #400: feed the calendar screen's agenda from the heorte manager before
        // the fb borrow (both disjoint from self.fb). Cheap for the small event
        // set; keeps the screen current whenever it is the active render target.
        self.calendar.update(&self.heorte, self.wall_clock);
        let active = self.ui.active_screen();
        // #730: cheap regardless of whether the placeholder is actually the
        // render target this pass -- mirrors the calendar.update() pattern
        // above (feed screens their content before the fb borrow, unconditionally).
        self.not_implemented.set_screen(active);
        let fb = self.fb.as_deref_mut()?;
        let status = StatusBarState {
            network,
            battery_pct: 0,
            mode_char: self.mode.mode_char(),
            mode_badge: Some(self.mode.status_badge()),
            mode_badge_color: Some(self.mode.status_badge_color()),
            // #874: CCCI boot-path availability is not a threat level or a
            // modem-rail observation. Only an online detector's High/Critical
            // state drives the threat indicator.
            threat_high: self.threat.detector_online()
                && matches!(
                    self.threat.threat_level(),
                    ThreatLevel::High | ThreatLevel::Critical
                ),
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
        //
        // Classified through the SAME [`screen_kind`] table `active_screen_mut`
        // matches on (#730) -- this match has no catch-all, so a `ScreenId`
        // with no arm here is a compile error, not a silent Home render.
        let screen: &dyn Screen = match screen_kind(active) {
            ScreenKind::Home => &self.home,
            ScreenKind::Messages => &self.messages,
            ScreenKind::Search => &self.search,
            ScreenKind::Dialer => &self.dialer,
            ScreenKind::Settings => &self.settings,
            ScreenKind::Calendar => &self.calendar,
            ScreenKind::FmRadio => &self.fm_screen,
            ScreenKind::Privacy => &self.privacy,
            ScreenKind::RadioControl => &self.radio,
            ScreenKind::ThreatMonitor => &self.threat,
            ScreenKind::NotImplemented => &self.not_implemented,
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

    /// Install the baseline firewall policy through the production `add_rule`
    /// path at loop entry (#403). Runs on both targets -- this is the single
    /// seam where runtime policy reaches the loop-persistent firewall's rule
    /// set. Returns the resulting rule count.
    ///
    /// SECURITY INVARIANT: `Log` = allow + audit, so a `Log` rule is permitted
    /// ONLY on flows the default policy already allows -- Outbound
    /// (`default_outbound = Allow`). An Inbound `Log` rule would turn
    /// default-deny into allow-with-audit and is forbidden here.
    pub(crate) fn apply_firewall_policy(&mut self) -> usize {
        use crate::firewall::{Action, Direction, FilterRule};
        let fw = self.net.device_mut().firewall_mut();
        // Audit all outbound DNS egress (port 53). Safe on three axes: outbound
        // is already default-allowed, so this only ADDS an audit record; the DNS
        // surveillance blocklist runs BEFORE rule evaluation, so this rule cannot
        // bypass it; and no inbound rule is installed, so inbound stays
        // default-deny.
        fw.add_rule(FilterRule {
            direction: Direction::Outbound,
            protocol: None,
            src_addr: None,
            dst_addr: None,
            dst_port: Some(53),
            action: Action::Log,
        });
        fw.rule_count()
    }

    /// Boot-time audio smoke (#399, qemu): open a `VoiceCall` session -- which
    /// powers the codec + arbitrates a route + records mic access -- then close
    /// it. Exercises the session manager, `RouteManager`, and `MicAuditLog` with the
    /// `NullCodec` (no real MT6357 I/O). Returns (peak session count, mic-audit
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

    /// Boot-time SIM/SMS smoke (#398, qemu): exercise the SIM-management API over
    /// the modem transport (mock-seeded) -- ICCID query, PIN status, signal
    /// strength, operator name -- then decode + file a known incoming SMS PDU.
    /// Returns (ICCID len, inbox count, SIM ready, signal bars, operator name
    /// len) for the CI witness, exercising both managers against the wired
    /// transport. All SIM queries are `ModemTransport`-abstracted, so the mock
    /// exercises them fully under qemu; only the returned values are hardware.
    #[cfg(feature = "qemu")]
    pub(crate) fn sim_sms_boot_smoke(&mut self) -> (usize, usize, bool, u8, usize, bool) {
        // SMS receive: decode a known SMS-DELIVER PDU ("Hello" from +1234567890).
        const PDU: &[u8] = &[
            0x00, 0x00, 0x0A, 0x91, 0x21, 0x43, 0x65, 0x87, 0x09, 0x00, 0x00, 0x32, 0x10, 0x51,
            0x21, 0x03, 0x00, 0x00, 0x05, 0xC8, 0x32, 0x9B, 0xFD, 0x06,
        ];

        // SIM + SMS-send: query ICCID + PIN status + signal + operator and send
        // an outgoing SMS over Telephony's owned transport, in the order the mock
        // queues the responses.
        let (iccid_len, sim_ready, signal_bars, operator_len, sms_sent) =
            if let Some(t) = self.telephony.as_mut() {
                self.sim.query_iccid(t.transport_mut()).ok();
                // PIN status (AT+CPIN?): READY => no PIN required => ready.
                let ready = self.sim.check_pin(t.transport_mut()).unwrap_or(false);
                // Signal (AT+CSQ): first poll fires immediately (last tick is None).
                self.sim.poll_signal(t.transport_mut(), 0);
                // Operator name (AT+COPS?).
                let mut op_name = [0u8; 32];
                let op_len = SimManager::query_operator(t.transport_mut(), &mut op_name)
                    .unwrap_or(0) as usize;
                // SMS send: GSM-7 encode + AT+CMGS PDU-mode transmit.
                let sent = SmsManager::send(t.transport_mut(), "+1234567890", "Boot check").is_ok();
                (
                    self.sim.sim_info().iccid_len as usize,
                    ready,
                    self.sim.signal_info().bars,
                    op_len,
                    sent,
                )
            } else {
                (0, false, 0, 0, false)
            };
        // File the decoded PDU.
        if let Ok(msg) = SmsManager::handle_incoming(PDU) {
            self.sms.receive(msg).ok();
        }
        (
            iccid_len,
            self.sms.inbox().len(),
            sim_ready,
            signal_bars,
            operator_len,
            sms_sent,
        )
    }

    /// Boot-time BT A2DP smoke (#401, qemu): configure the A2DP profile (SBC
    /// framing at 44.1 kHz stereo) and report the resulting sample rate and
    /// channels. Proves only construction and local configuration: the encoder
    /// remains a zero-audio stub (#401), while the non-test HCI/ACL backend is
    /// software work under #129 before any RF witness.
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

    /// Boot-time firewall smoke (#403, qemu): exercise the loop-persistent
    /// firewall end to end. Pushes one synthetic Ethernet(IPv4/TCP dst-port 53)
    /// frame through the device: the TX drop-site matches the outbound `Log`
    /// rule (allow + audit), the looped-back inbound copy hits default-deny at
    /// the RX drop-site, and both events drain onto the HMAC audit chain via the
    /// production path. Returns (rule count, `packets_allowed`, `packets_denied`,
    /// audit entries appended, chain-verified) for the CI witness.
    #[cfg(feature = "qemu")]
    pub(crate) fn firewall_boot_smoke(&mut self) -> (usize, u64, u64, usize, bool) {
        use smoltcp::phy::{Device as _, TxToken as _};
        // 54-byte Ethernet(IPv4/TCP) frame, src 10.0.0.1:49152 -> 9.9.9.9:53,
        // empty TCP payload (a control segment the DNS blocklist passes, so rule
        // evaluation is reached). Inlined: the firewall.rs/net.rs frame builders
        // are #[cfg(test)]-only.
        const FRAME: [u8; 54] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // eth dst
            0x02, 0x00, 0x00, 0x00, 0x00, 0x01, // eth src (locally administered)
            0x08, 0x00, // ethertype IPv4
            0x45, 0x00, 0x00, 0x28, // ver/ihl, dscp, total length 40
            0x00, 0x00, 0x00, 0x00, 0x00, // id, flags/frag, ttl
            0x06, // protocol TCP
            0x00, 0x00, // header checksum
            0x0a, 0x00, 0x00, 0x01, // src 10.0.0.1
            0x09, 0x09, 0x09, 0x09, // dst 9.9.9.9
            0xc0, 0x00, // tcp src port 49152
            0x00, 0x35, // tcp dst port 53
            0x00, 0x00, 0x00, 0x00, // seq
            0x00, 0x00, 0x00, 0x00, // ack
            0x50, 0x00, // data offset 5 (20-byte header), flags
            0x00, 0x00, // window
            0x00, 0x00, // checksum
            0x00, 0x00, // urgent
        ];
        // INVARIANT: `uptime_ms()` is a device-uptime millisecond count;
        // `i64::MAX` ms is ~292 million years of uptime, so this
        // bit-reinterpretation (required by smoltcp's
        // `Instant::from_millis(i64)`) cannot flip sign.
        let now = crate::net::instant_from_millis(crate::exceptions::uptime_ms().cast_signed());
        // TX drop-site: outbound eval matches the Log rule -> forwarded to the
        // loopback queue + a PacketLog event queued.
        if let Some(tx) = self.net.device_mut().transmit(now) {
            tx.consume(FRAME.len(), |buf| buf.copy_from_slice(&FRAME));
        }
        // RX drop-site: the looped-back frame is inbound; no inbound rule matches
        // -> default-deny consumes it (returns None) + a PacketDeny event queued.
        let denied_rx = self.net.device_mut().receive(now).is_none();
        // Production drain: commit both events to the HMAC audit chain.
        let now_ms = crate::exceptions::uptime_ms();
        let Self {
            net,
            audit,
            audit_key,
            ..
        } = self;
        let fw = net.device_mut().firewall_mut();
        let appended = crate::firewall::flush_packet_audit(fw, audit, audit_key.as_bytes(), now_ms);
        let stats = fw.stats().clone();
        let chain_ok = denied_rx && audit.verify_chain(audit_key.as_bytes()).is_ok();
        (
            fw.rule_count(),
            stats.packets_allowed,
            stats.packets_denied,
            appended,
            chain_ok,
        )
    }

    /// Boot-time heorte smoke (#400, qemu): seed a calendar event + an alarm,
    /// check alarms, arm the countdown timer + stopwatch, and feed the calendar
    /// screen from the manager. Returns (event count, alarm count, calendar
    /// agenda rows, timer armed) for the CI witness -- proves `HeorteManager` +
    /// its Timer/Stopwatch are instantiated + hold state and the calendar screen
    /// renders that state (rows > 0). Pure tick logic; no hardware.
    #[cfg(feature = "qemu")]
    pub(crate) fn heorte_boot_smoke(&mut self) -> (usize, usize, usize, bool) {
        let now_ms = self.wall_clock * 1000;
        self.heorte
            .add_event(b"Boot check", self.wall_clock + 3600, 30, false);
        self.heorte.add_alarm(7, 30, b"Wake", true, 0);
        self.heorte.check_alarms(self.wall_clock);
        // Arm the countdown timer (60 s) + start the stopwatch (heorte_timer.rs).
        self.heorte.timer_mut().set_duration(60);
        self.heorte.timer_mut().start(now_ms);
        self.heorte.stopwatch_mut().start(now_ms);
        let timer_armed = !self.heorte.timer().expired();
        self.calendar.update(&self.heorte, self.wall_clock);
        (
            self.heorte.events().len(),
            self.heorte.alarms().len(),
            self.calendar.row_count(),
            timer_armed,
        )
    }

    /// Boot-time FM smoke (#518, qemu): power on via the `BootFmHw` path, tune
    /// to a seeded frequency, feed the FM screen from the controller state,
    /// and return (powered, tuned, `freq_khz`, rssi, volume) for the CI
    /// witness -- proves `FmRadio<BootFmHw>` is instantiated in
    /// `KernelState` and the FM screen renders its state. Pure state logic;
    /// no hardware.
    #[cfg(feature = "qemu")]
    pub(crate) fn fm_boot_smoke(&mut self) -> (bool, bool, u32, i8, u8) {
        let powered = self.fm.power_on().is_ok();
        // WHY: kernel code denies clippy::expect-used (zero-panic policy,
        // #663) -- an `.expect()` here would fail the kernel clippy gate,
        // not just be poor style. Captured as a bool and threaded into the
        // witness line instead: scripts/witness/boot.sh now asserts
        // `tuned=true` explicitly, so a tune() regression fails the CI
        // witness on the exact signal, rather than being masked by a
        // freq_khz value the old regex only checked the SHAPE of.
        let tuned = self.fm.tune(103_300).is_ok();
        let freq = self.fm.frequency().unwrap_or(0);
        let rssi = self.fm.rssi();
        let volume = self.fm.volume();
        let mut presets_u32 = [0u32; 6];
        for (i, p) in self.fm.presets().iter().enumerate() {
            presets_u32[i] = p.unwrap_or(0);
        }
        let preset_count = self.fm.preset_count();
        self.fm_screen
            .update_from_state(self.fm.state(), rssi, &presets_u32, preset_count, volume);
        (powered, tuned, freq, rssi, volume)
    }

    /// Boot-time threat monitor smoke (#737, qemu): decode a second
    /// synthetic SMS-DELIVER PDU whose PID marks it Silent (Type 0, the
    /// covert location-ping -- #662) through the SAME real classification
    /// path a production incoming SMS takes (`SmsManager::handle_incoming`
    /// -> `ThreatAlertType::from_message_class`), push the resulting alert
    /// onto the threat log, and derive the composite score from the log
    /// via `recompute_score_from_log` -- score as a lens over the log, NOT
    /// sema (which is not a thumos dependency and cannot reach
    /// `KernelState`; see `screen_threat.rs`'s module doc). Returns
    /// (`detector_before`, `alert_count`, score, `modem_path_available`) for
    /// the CI witness -- proves
    /// `ThreatMonitor` is instantiated in `KernelState`, fed from a real
    /// (if boot-seeded) classification, and its score derives from that
    /// log rather than an unwired detector.
    #[cfg(feature = "qemu")]
    pub(crate) fn threat_boot_smoke(&mut self) -> (bool, usize, u32, bool) {
        // Identical to sim_sms_boot_smoke's PDU except the PID byte (index
        // 9): 0x40 marks Type 0 (silent) per #662's classification, the
        // same PID value sms.rs's
        // handle_incoming_classifies_silent_sms_and_keeps_the_message
        // verifies decodes to MessageClass::Silent.
        const SILENT_SMS_PDU: &[u8] = &[
            0x00, 0x00, 0x0A, 0x91, 0x21, 0x43, 0x65, 0x87, 0x09, 0x40, 0x00, 0x32, 0x10, 0x51,
            0x21, 0x03, 0x00, 0x00, 0x05, 0xC8, 0x32, 0x9B, 0xFD, 0x06,
        ];
        // WHY(#743): captured BEFORE seeding. A fresh ThreatMonitor has no
        // detector, and the witness asserts that state as well as the
        // seeded one -- otherwise the no-detector path is never exercised
        // and could regress to rendering a reassuring score silently.
        let detector_before = self.threat.detector_online();
        if let Ok(msg) = SmsManager::handle_incoming(SILENT_SMS_PDU)
            && let Some(alert_type) = ThreatAlertType::from_message_class(msg.class)
        {
            self.threat.push_alert(ThreatAlert::from_sms_classification(
                self.wall_clock * 1000,
                alert_type,
            ));
        }
        self.threat.recompute_score_from_log();
        (
            detector_before,
            self.threat.alert_count(),
            self.threat.threat_score(),
            self.threat.modem_path_available(),
        )
    }

    /// Execute pending reflex fast-path events in privileged (loop) context.
    // WHY: all three arms are TODO stubs today, but two are explicitly
    // documented to need self once implemented -- the duress arm (#863)
    // transitions via self.mode + wipe policy, the incoming-ring arm (#398)
    // routes UI + audio via self's persisted telephony. Called instance-style
    // (`kernel.handle_reflex(..)`) from the production run loop; dropping
    // &mut self now would just be re-added when those TODOs land.
    #[expect(
        clippy::unused_self,
        reason = "all three arms are TODO stubs today, but two are explicitly documented to need self once implemented -- the duress arm (#863) transitions via self.mode + wipe policy, the incoming-ring arm (#398) routes UI + audio via self's persisted telephony; called instance-style (kernel.handle_reflex(..)) from the production run loop"
    )]
    pub(crate) fn handle_reflex(&mut self, pending: reflex::Pending, serial: &mut Uart) {
        if pending.panic_wipe {
            let _ = serial.write_str("[kardia] REFLEX panic-wipe\r\n"); // WHY: best-effort loop diagnostic; must not block on a failed UART write
            // TODO(#863)[deliberate-prudent]: invoke panic_wipe via the persisted key manager.
        }
        if pending.duress {
            let _ = serial.write_str("[kardia] REFLEX duress\r\n"); // WHY: best-effort loop diagnostic; must not block on a failed UART write
            // TODO(#863)[deliberate-prudent]: duress transition via self.mode + wipe policy.
        }
        if pending.incoming_ring {
            let _ = serial.write_str("[kardia] REFLEX incoming-ring\r\n"); // WHY: best-effort loop diagnostic; must not block on a failed UART write
            // TODO(#398)[deliberate-prudent]: ring UI + audio route via persisted telephony.
        }
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
/// Relaunch a supervised service from the boot ramfs (#492); returns its new pid.
///
/// A restart cannot be reconstructed from the dead PCB -- it retains no image
/// identity (no path, no entry, no image frame) -- so it re-plans from the ramfs
/// by name, exactly as kinit's original spawn did.
///
/// WHY the explicit kernel-L1 switch under an `IrqGuard`: `switch_to` SKIPS the
/// TTBR0 write for PID 0 (its `page_table_phys` is 0), so the service loop runs
/// under whatever table the last user process installed -- but
/// `elf::load_confined` writes the fresh image frame through raw PHYSICAL
/// addresses and requires the identity kernel L1 (the #497 aliasing class).
/// Nothing needs restoring afterwards: the kernel table IS PID 0's canonical
/// table, and the next `switch_to` installs the successor's. The guard keeps the
/// load+spawn window atomic against preemption.
fn restart_supervised(path: &'static str) -> Option<crate::process::Pid> {
    let _irq = crate::irq::IrqGuard::new();
    // SAFETY: table_base() is the always-valid identity kernel L1; PID 0 owns no
    // table of its own, so there is nothing to restore.
    unsafe {
        crate::mmu::switch_addr_space(crate::mmu::table_base());
    }
    let crate::kinit_plan::UserspaceSpawnPlan::Elf(elf_data) =
        crate::kinit_plan::plan_userspace_spawn_from_vfs(path)
    else {
        return None;
    };
    // SAFETY: the identity kernel L1 is live (switched above), satisfying
    // load_confined's TTBR0 precondition.
    let loaded = unsafe {
        crate::elf::load_confined(
            elf_data,
            crate::board::USER_TEXT_BASE,
            crate::board::RAM_END,
        )
    }
    .ok()?;
    let pid = crate::process::spawn_user(&loaded)?;
    // #492: record the new pid BEFORE the guard drops -- spawn-then-register must
    // be ATOMIC against preemption. The relaunched service is by definition one
    // that crashes; if the timer IRQ landed between the spawn and this write, the
    // scheduler could run it and its fault would resolve to no claim
    // (service=None), so the crash would be audited but never counted against the
    // budget -- silently ending supervision without ever reaching give-up. The
    // early returns above leave the claim as the fault path already released it
    // (None), which is correct: no relaunch happened.
    crate::supervisor::set_current_pid(path, Some(pid));
    Some(pid)
}

pub(crate) fn service_loop(mut kernel: KernelState, mut serial: Uart) -> ! {
    let _ = serial.write_str("[kardia] service loop running\r\n"); // WHY: best-effort loop diagnostic; must not block on a failed UART write
    // #403: install the runtime firewall policy through the production add_rule
    // path on BOTH targets -- the seam that makes the loop-persistent firewall's
    // rule set policy-driven (and the production caller that un-deads add_rule /
    // Action::Log).
    kernel.apply_firewall_policy();
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
        // #402: source-precedence clock wired + seeded (source None -> Manual, a
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
        // #398: SIM + SMS wired -- ICCID / PIN status / signal / operator queried
        // over the modem transport + a known incoming SMS PDU decoded into the
        // inbox.
        let (iccid_len, sms_inbox, sim_ready, signal_bars, operator_len, sms_sent) =
            kernel.sim_sms_boot_smoke();
        // #401: BT A2DP profile wired + its SBC/config state machine runs
        // (44.1 kHz stereo). The non-test HCI/ACL backend is software work under
        // #129 before RF/PMIC/antenna qualification.
        let (bt_rate, bt_ch) = kernel.bt_audio_boot_smoke();
        // #404: status-bar network label derived from the parsed +CREG <AcT>
        // (EUtran can only come from the parse path), not a constant.
        let (rat, netrat_net) = kernel.netrat_boot_smoke();
        // #400: heorte manager (+ its Timer/Stopwatch) instantiated + holds
        // seeded events/alarms, and the calendar screen renders that state.
        let (heorte_events, heorte_alarms, calendar_rows, timer_armed) = kernel.heorte_boot_smoke();
        // #403: the loop-persistent firewall took a runtime rule (add_rule),
        // Log-audited an outbound packet + default-denied its looped-back copy,
        // and both events landed on a verified HMAC audit chain.
        let (fw_rules, fw_allowed, fw_denied, fw_audit, fw_chain) = kernel.firewall_boot_smoke();

        // #506: seed the userspace CLOCK_REALTIME offset from the seeded
        // ClockManager at loop start — the offset must be correct from tick
        // 0, not one second late; poll_all's once-per-second branch then
        // keeps it fresh. The #461 witness (Step 5) proves the CNTPCT and
        // IRQ-tick bases agree under virt, so the internal monotonic_secs()
        // basis is sound; an ImplausibleEpoch rejection fails closed.
        // SAFETY: loop start, single-core, before userspace runs.
        unsafe {
            let _ = crate::time::set_realtime_offset(kernel.wall_clock); // kanon:ignore RUST/no-silent-result-swallow -- fail-closed by design: an ImplausibleEpoch rejection (see WHY above) keeps the prior offset, nothing to do with an error here
        }

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
        // #506 witness: the offset the userspace CLOCK_REALTIME view is
        // built from, just seeded above (sys_clock_gettime adds monotonic
        // seconds to it; a real epoch here proves the unification).
        emit_marker(
            &mut serial,
            format_args!("kardia: realtime offset={wall}\r\n"),
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
            format_args!(
                "kardia: sim iccid_len={iccid_len} sms_inbox={sms_inbox} sim_ready={sim_ready} signal_bars={signal_bars} operator_len={operator_len} sms_sent={sms_sent}\r\n"
            ),
        );
        emit_marker(
            &mut serial,
            format_args!("kardia: bt_audio sample_rate={bt_rate} channels={bt_ch}\r\n"),
        );
        emit_marker(
            &mut serial,
            format_args!("kardia: netrat rat={rat:?} net={netrat_net:?}\r\n"),
        );
        emit_marker(
            &mut serial,
            format_args!(
                "kardia: heorte events={heorte_events} alarms={heorte_alarms} calendar_rows={calendar_rows} timer_armed={timer_armed}\r\n"
            ),
        );
        let fw_chain_str = if fw_chain { "ok" } else { "err" };
        emit_marker(
            &mut serial,
            format_args!(
                "kardia: firewall rules={fw_rules} allowed={fw_allowed} denied={fw_denied} audit_events={fw_audit} chain={fw_chain_str}\r\n"
            ),
        );
        // #518: FM radio controller instantiated via BootFmHw (NullFmHw under
        // qemu), powered + tuned at smoke, and the FM screen fed from it.
        #[cfg(feature = "qemu")]
        {
            let (fm_powered, fm_tuned, fm_freq, fm_rssi, fm_vol) = kernel.fm_boot_smoke();
            emit_marker(
                &mut serial,
                format_args!(
                    "kardia: fm powered={fm_powered} tuned={fm_tuned} freq_khz={fm_freq} rssi={fm_rssi} volume={fm_vol}\r\n"
                ),
            );
        }
        // #737: threat monitor fed from the real SMS surveillance
        // classification path (#662) -- the log is the substrate; the
        // composite score is a log-derived heuristic, explicitly
        // uncalibrated (sema stays unwired, not a thumos dependency).
        #[cfg(feature = "qemu")]
        {
            let (threat_detector_before, threat_alerts, threat_score, modem_path_available) =
                kernel.threat_boot_smoke();
            emit_marker(
                &mut serial,
                format_args!(
                    "kardia: threat detector_before={threat_detector_before} alerts={threat_alerts} score={threat_score} uncalibrated=true modem_path_available={modem_path_available}\r\n"
                ),
            );
        }
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
    #[cfg(feature = "qemu")]
    let mut realtime_logged = false;
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
            // #492: drain the fault ring BEFORE the reaper frees any slot, so a
            // drained report's pid cannot alias a slot this same pass reuses.
            // Every report is audit-logged; a SUPERVISED service that crashed is
            // relaunched, rate-limited. The supervisor keys on fault reports and
            // never on PCB Dead state, so a service that exits CLEANLY (as /shell
            // does today) is provably never relaunched.
            while let Some(report) = crate::supervisor::pop_report() {
                let (detail, detail_len) = crate::supervisor::audit_detail(&report);
                {
                    // Split the borrow: log_event needs &mut audit AND &audit_key.
                    let KernelState {
                        audit, audit_key, ..
                    } = &mut kernel;
                    let _ = audit.log_event(
                        crate::audit::AuditEventType::UserFault,
                        u32::from(report.pid),
                        &detail[..detail_len],
                        now,
                        audit_key.as_bytes(),
                    );
                }
                let _ = write!(
                    serial,
                    "kardia: fault audited pid={} kind={}\r\n",
                    report.pid, report.kind
                ); // WHY: best-effort diagnostic + the #492 audit witness
                match crate::supervisor::decide(&report, now) {
                    crate::supervisor::Decision::None => {}
                    crate::supervisor::Decision::Restart(path) => {
                        // restart_supervised records the new pid itself, inside its
                        // IrqGuard -- spawn-then-register must be atomic (see there).
                        let new_pid = restart_supervised(path);
                        match new_pid {
                            Some(pid) => {
                                let _ = write!(
                                    serial,
                                    "kardia: supervisor restarted {path} (PID {pid})\r\n"
                                );
                            }
                            None => {
                                let _ = write!(
                                    serial,
                                    "kardia: supervisor FAILED to restart {path}\r\n"
                                );
                            }
                        }
                    }
                    crate::supervisor::Decision::GiveUp(path) => {
                        let _ = write!(
                            serial,
                            "kardia: supervisor giving up on {path} after {} restarts\r\n",
                            crate::supervisor::max_restarts()
                        );
                    }
                }
            }
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
                        crate::ui::screen_label(from),
                        crate::ui::screen_label(to)
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
            // #506 witness: poll_all's once-per-second branch just refreshed
            // the offset — log it the first time so a stuck offset is visible
            // next to the seed witness above.
            #[cfg(feature = "qemu")]
            if ticked && !realtime_logged {
                realtime_logged = true;
                emit_marker(
                    &mut serial,
                    format_args!("kardia: realtime offset={}\r\n", kernel.wall_clock),
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
