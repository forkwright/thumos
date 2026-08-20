//! Power management: requested radio policy and display timeout requests.
//!
//! Two concerns live here:
//!
//! 1. **Radio policy state** — requested states for cellular, `WiFi`, BT,
//!    GPS, FM, and mesh. These are in-memory today, not GPIO/physical kills.
//!    The M7 has no established physical switches, and #862 owns a valid
//!    PWRAP/driver enforcement seam before any PMIC claim.
//!
//! 2. **Display timeout requests** — an input hook can record activity, but no
//!    production input caller is wired yet (#753). The timer IRQ records a
//!    sleep request before the unresolved display transport runs (#854); this
//!    module has no panel/backlight readback. CPU DVFS and core-parking
//!    actuation are absent from every runtime build: #879 must source-ground
//!    the OPP, efuse/binning, voltage/clock, acknowledgement, timeout,
//!    rollback, and readback contracts before a device backend exists.

/// Logical performance levels used only to test the unaccepted policy
/// candidate. They do not name frequencies or encode device register values.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum CandidatePerformanceLevel {
    Minimum,
    Reduced,
    Elevated,
    Maximum,
}

#[cfg(test)]
impl CandidatePerformanceLevel {
    /// Return the next lower logical level, or `None` if already minimum.
    fn step_down(self) -> Option<Self> {
        match self {
            Self::Maximum => Some(Self::Elevated),
            Self::Elevated => Some(Self::Reduced),
            Self::Reduced => Some(Self::Minimum),
            Self::Minimum => None,
        }
    }

    /// Return the next higher logical level, or `None` if already maximum.
    fn step_up(self) -> Option<Self> {
        match self {
            Self::Minimum => Some(Self::Reduced),
            Self::Reduced => Some(Self::Elevated),
            Self::Elevated => Some(Self::Maximum),
            Self::Maximum => None,
        }
    }
}

/// Logical core request used only by the test-only policy candidate.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CandidateCoreRequest {
    BootCoreOnly,
    AllAvailable,
}

/// Rolling load history depth for the test-only candidate.
#[cfg(test)]
const LOAD_HISTORY_LEN: usize = 4;

/// Host-test-only CPU policy candidate.
///
/// This state is deliberately separate from runtime display/power state so no
/// device or QEMU build can treat an unaccepted heuristic as requested or
/// applied CPU behavior (#879).
#[cfg(test)]
struct CandidateCpuPolicy {
    requested_performance: CandidatePerformanceLevel,
    requested_cores: CandidateCoreRequest,
    load_history: [u8; LOAD_HISTORY_LEN],
    load_idx: usize,
    load_samples: usize,
}

#[cfg(test)]
impl CandidateCpuPolicy {
    const fn new() -> Self {
        Self {
            requested_performance: CandidatePerformanceLevel::Maximum,
            requested_cores: CandidateCoreRequest::AllAvailable,
            load_history: [0u8; LOAD_HISTORY_LEN],
            load_idx: 0,
            load_samples: 0,
        }
    }

    fn requested_performance(&self) -> CandidatePerformanceLevel {
        self.requested_performance
    }

    fn requested_cores(&self) -> CandidateCoreRequest {
        self.requested_cores
    }
}

// ---------------------------------------------------------------------------
// Display backlight timeout (30 s at 10 ms/tick = 3 000 ticks)
// ---------------------------------------------------------------------------

/// Default backlight timeout: 30 seconds at 10 ms per tick.
const BACKLIGHT_TIMEOUT_TICKS: u64 = 3_000;

/// Display timeout request bookkeeping, not physical panel/backlight state.
///
/// One global instance is accessed only from non-reentrant IRQ context on
/// single-core `ARMv7`; IRQs are disabled during each handler, so no lock is
/// needed. The timer IRQ is wired; [`notify_input`] remains an unwired hook.
struct DisplayTimeoutState {
    /// Last recorded backlight request; not hardware readback.
    backlight_requested_on: bool,
    /// Tick timestamp of the last input event.
    last_input_tick: u64,
    /// Backlight off timeout in ticks.
    backlight_timeout_ticks: u64,
}

impl DisplayTimeoutState {
    /// Create timeout bookkeeping with an initial requested-on state.
    const fn new() -> Self {
        Self {
            backlight_requested_on: true,
            last_input_tick: 0,
            backlight_timeout_ticks: BACKLIGHT_TIMEOUT_TICKS,
        }
    }

    /// Last recorded backlight request; not applied or observed state.
    #[cfg(test)]
    fn backlight_requested_on(&self) -> bool {
        self.backlight_requested_on
    }
}

/// Global display-timeout requests, written only from IRQ context.
static mut DISPLAY_TIMEOUT: DisplayTimeoutState = DisplayTimeoutState::new();

/// Execute `wfi` and suspend the CPU until the next interrupt.
///
/// Called when the scheduler finds no runnable process.
///
/// # Safety
///
/// `wfi` is a hint instruction available in all ARM privilege levels.
/// No memory is accessed; the CPU enters a low-power wait state until
/// an interrupt fires.
#[inline(always)]
pub(crate) fn idle() {
    #[cfg(target_arch = "arm")]
    // SAFETY: wfi is a harmless hint — the core resumes at the next interrupt.
    unsafe {
        core::arch::asm!("wfi");
    }
}

/// Record input and request the backlight on.
///
/// No production caller is wired yet (#753). A future keypad/touch IRQ path
/// may call this only after its input producer and display transport are
/// accepted; the request is not panel/backlight readback (#854).
///
/// # Safety
///
/// Called from an IRQ handler (interrupts disabled, single-core).
pub(crate) fn notify_input(current_tick: u64) {
    // SAFETY: DISPLAY_TIMEOUT is only accessed from non-reentrant IRQ context.
    let state = unsafe { &mut *core::ptr::addr_of_mut!(DISPLAY_TIMEOUT) };
    let wake_requested = state.record_input_request(current_tick);
    if wake_requested {
        // SAFETY: DSI0 is active when display is in Suspended state and
        // the display subsystem has been initialised.  The resume sequence
        // exits Sleep-In mode per GC9306 datasheet §8.2.
        unsafe {
            display_wake();
        }
    }
}

/// Check whether the timeout elapsed and record a display-sleep request.
///
/// Call this once per scheduler tick.
///
/// # Safety
///
/// Called from the timer IRQ handler (interrupts disabled, single-core).
pub(crate) fn check_backlight_timeout(current_tick: u64) {
    // SAFETY: DISPLAY_TIMEOUT is only accessed from the timer IRQ handler.
    let state = unsafe { &mut *core::ptr::addr_of_mut!(DISPLAY_TIMEOUT) };
    let sleep_requested = state.record_timeout_request(current_tick);
    if sleep_requested {
        // SAFETY: DSI0 is active and the display pipeline is in Active state.
        // Sleep-In sequence follows GC9306 datasheet §8.1.
        unsafe {
            display_sleep();
        }
    }
}

// ---------------------------------------------------------------------------
// Display helpers (hardware stubs)
// ---------------------------------------------------------------------------

/// Send the MIPI DCS Sleep-In command sequence to the GC9306 panel.
///
/// Register sequence mirrors `Gc9306::suspend()` in display.rs.
///
/// # Safety
///
/// DSI0 must be active and the display pipeline must be in `Active` state.
unsafe fn display_sleep() {
    // DSI0 command FIFO base.  Commands are routed through dcs_write_cmd0
    // in the display driver; here we duplicate the bare MMIO sequence
    // because power.rs has no direct dependency on the display driver type.
    //
    // GC9306 sleep sequence (GC9306-INIT.md §3):
    //   0xFE — Inter register enable 1
    //   0xEF — Inter register enable 2
    //   0x10 — Sleep In
    //
    // SAFETY: caller guarantees DSI0 is active.
    unsafe {
        dcs_cmd0(0xFE);
        dcs_cmd0(0xEF);
        dcs_cmd0(0x10);
    }
}

/// Send the MIPI DCS Sleep-Out command sequence to the GC9306 panel.
///
/// # Safety
///
/// DSI0 must be active and the panel must be in sleep mode.
unsafe fn display_wake() {
    // GC9306 sleep-out sequence (GC9306-INIT.md §4):
    //   0xFE — Inter register enable 1
    //   0xEF — Inter register enable 2
    //   0x11 — Sleep Out (120 ms stabilisation in hardware; driver polls)
    //
    // SAFETY: caller guarantees DSI0 is active.
    unsafe {
        dcs_cmd0(0xFE);
        dcs_cmd0(0xEF);
        dcs_cmd0(0x11);
    }
}

/// Write a zero-parameter DCS command to DSI0.
///
/// DSI0 `CMD_FIFO` register: `0x1400_D000` + offset 0x200.
/// Format: bits [7:0] = DCS opcode, bit 8 = last-byte flag.
unsafe fn dcs_cmd0(cmd: u8) {
    // WHY(qemu): virt models no DSI0 block; the FIFO write would data-abort
    // inside the timer IRQ (backlight-timeout path).
    #[cfg(feature = "qemu")]
    let _ = cmd;
    #[cfg(not(feature = "qemu"))]
    {
        // SAFETY: DSI0_CMD_FIFO is a valid MMIO register within the DSI0
        // address space at 0x1400_D000.  Volatile access required for hardware.

        unsafe {
            crate::mmio::write32(crate::board::DSI0_CMD_FIFO, u32::from(cmd) | 0x100);
        }
    }
}

/// Radio subsystem identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Radio {
    /// Cellular modem (LTE/3G/2G).
    Cellular,
    /// `WiFi` 802.11.
    Wifi,
    /// Bluetooth.
    Bluetooth,
    /// `GPS`/GLONASS/BeiDou.
    Gps,
    /// FM radio receiver.
    Fm,
    /// Mesh (`LoRa`/Meshtastic) transceiver.
    Mesh,
    /// All radios.
    All,
}

/// Requested/recorded policy state for a radio.
///
/// The variant names predate the current truth boundary. No variant is
/// physical readback: On/Off are desired states and the two terminal variants
/// are sticky software markers. #862 owns PMIC/driver actuation and
/// observation; #874 owns requested/applied/observed/failed state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PowerState {
    /// Requested enabled.
    On,
    /// Requested disabled.
    Off,
    /// Sticky simulated/future-switch marker; not current GPIO readback.
    HardwareKilled,
    /// Sticky modem-cut request marker; not proof that a PMIC rail changed.
    PowerCutRequested,
}

impl PowerState {
    /// Whether this sticky terminal marker must survive later policy requests.
    const fn is_terminal(self) -> bool {
        matches!(self, Self::HardwareKilled | Self::PowerCutRequested)
    }
}

/// Requested system radio-policy mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerMode {
    /// Request all radios enabled.
    Full,
    /// Request cellular enabled and the other radios disabled.
    CellOnly,
    /// Request every radio disabled; this does not prove RF silence.
    Silent,
    /// Airplane mode with `WiFi` (for local network only).
    LocalOnly,
}

/// Power manager state.
pub(crate) struct PowerManager {
    states: [(Radio, PowerState); 6],
    mode: PowerMode,
}

impl PowerManager {
    /// Create a new power manager with every radio marked requested-off.
    pub(crate) fn new() -> Self {
        Self {
            states: [
                (Radio::Cellular, PowerState::Off),
                (Radio::Wifi, PowerState::Off),
                (Radio::Bluetooth, PowerState::Off),
                (Radio::Gps, PowerState::Off),
                (Radio::Fm, PowerState::Off),
                (Radio::Mesh, PowerState::Off),
            ],
            mode: PowerMode::Silent,
        }
    }

    /// Get the recorded requested/marker state of a radio.
    pub(crate) fn state(&self, radio: Radio) -> PowerState {
        if radio == Radio::All {
            // All is recorded On only if every radio is recorded On.
            if self.states.iter().all(|(_, s)| *s == PowerState::On) {
                PowerState::On
            } else {
                PowerState::Off
            }
        } else {
            self.states
                .iter()
                .find(|(r, _)| *r == radio)
                .map_or(PowerState::Off, |(_, s)| *s)
        }
    }

    /// Set the recorded policy state of a radio.
    /// Returns false if a sticky terminal marker prevents it.
    ///
    /// INVARIANT: the first [`PowerState::HardwareKilled`] or
    /// [`PowerState::PowerCutRequested`] marker wins. No later policy or
    /// terminal-marker request can replace it (#345). Only a fresh
    /// [`PowerManager`] (i.e. a reboot) clears it.
    pub(crate) fn set_state(&mut self, radio: Radio, state: PowerState) -> bool {
        if radio == Radio::All {
            let mut all_ok = true;
            for (_, s) in &mut self.states {
                if s.is_terminal() {
                    if state != *s {
                        all_ok = false;
                    }
                } else {
                    *s = state;
                }
            }
            return all_ok;
        }

        for (r, s) in &mut self.states {
            if *r == radio {
                // INVARIANT: a sticky terminal marker cannot be overwritten
                // through this in-memory policy API.
                if s.is_terminal() {
                    return state == *s;
                }
                *s = state;
                return true;
            }
        }
        false
    }

    /// Record a requested power-mode preset.
    ///
    /// Returns true if every in-memory entry accepted its target marker.
    /// This is not an actuation/readback receipt. A sticky marker can reject
    /// the request; then `mode()` retains the prior requested preset.
    pub(crate) fn apply_mode(&mut self, mode: PowerMode) -> bool {
        let all_ok = match mode {
            PowerMode::Full => self.set_state(Radio::All, PowerState::On),
            PowerMode::CellOnly => {
                let mut ok = self.set_state(Radio::Cellular, PowerState::On);
                ok &= self.set_state(Radio::Wifi, PowerState::Off);
                ok &= self.set_state(Radio::Bluetooth, PowerState::Off);
                ok &= self.set_state(Radio::Gps, PowerState::Off);
                ok &= self.set_state(Radio::Fm, PowerState::Off);
                ok &= self.set_state(Radio::Mesh, PowerState::Off);
                ok
            }
            PowerMode::Silent => self.set_state(Radio::All, PowerState::Off),
            PowerMode::LocalOnly => {
                let mut ok = self.set_state(Radio::Cellular, PowerState::Off);
                ok &= self.set_state(Radio::Wifi, PowerState::On);
                ok &= self.set_state(Radio::Bluetooth, PowerState::On);
                ok &= self.set_state(Radio::Gps, PowerState::Off);
                ok &= self.set_state(Radio::Fm, PowerState::Off);
                ok &= self.set_state(Radio::Mesh, PowerState::Off);
                ok
            }
        };

        if all_ok {
            self.mode = mode;
        }
        all_ok
    }

    /// Get the current power mode.
    pub(crate) fn mode(&self) -> PowerMode {
        self.mode
    }

    /// Record a simulated hardware-kill state for policy/tests.
    /// This performs no GPIO or power operation.
    pub(crate) fn hardware_kill(&mut self, radio: Radio) {
        if radio == Radio::All {
            for (_, s) in &mut self.states {
                if !s.is_terminal() {
                    *s = PowerState::HardwareKilled;
                }
            }
        } else {
            for (r, s) in &mut self.states {
                if *r == radio && !s.is_terminal() {
                    *s = PowerState::HardwareKilled;
                }
            }
        }
    }

    /// Record a sticky modem-cut request without touching hardware.
    ///
    /// Sets the cellular radio to [`PowerState::PowerCutRequested`] as
    /// requested-state bookkeeping. #862 must provide a source-grounded PWRAP
    /// transaction and independent readback before any caller may report a
    /// physical modem cut.
    pub(crate) fn request_modem_power_cut(&mut self) {
        for (r, s) in &mut self.states {
            if *r == Radio::Cellular && !s.is_terminal() {
                *s = PowerState::PowerCutRequested;
            }
        }
    }

    /// Whether software recorded the sticky modem-cut request marker.
    pub(crate) fn is_modem_cut_requested(&self) -> bool {
        self.states
            .iter()
            .any(|(r, s)| *r == Radio::Cellular && *s == PowerState::PowerCutRequested)
    }

    /// Count radios currently marked requested-on.
    pub(crate) fn active_count(&self) -> usize {
        self.states
            .iter()
            .filter(|(_, s)| *s == PowerState::On)
            .count()
    }
}

impl Default for PowerManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Record a security mode's requested radio policy in a power manager.
///
/// Maps boolean enable/disable flags from a [`ModePolicy`] to
/// [`PowerState::On`] / [`PowerState::Off`] and calls
/// [`PowerManager::set_state`] for each radio, including Mesh/LoRa (#254).
/// FM is always turned off in security mode transitions (not a
/// security-relevant radio).
///
/// Used by the boot sequence (Wave 8) and by [`ModeManager`] on mode
/// transitions to record policy without coupling `security_mode` directly to
/// `PowerManager` internals. No driver or PMIC actuation occurs here (#874).
pub(crate) fn apply_mode_policy(policy: &crate::security_mode::ModePolicy, pm: &mut PowerManager) {
    let to_state = |enabled: bool| -> PowerState {
        if enabled {
            PowerState::On
        } else {
            PowerState::Off
        }
    };

    pm.set_state(Radio::Cellular, to_state(policy.cellular_enabled));
    pm.set_state(Radio::Wifi, to_state(policy.wifi_enabled));
    pm.set_state(Radio::Bluetooth, to_state(policy.bluetooth_enabled));
    pm.set_state(Radio::Gps, to_state(policy.gps_enabled));
    pm.set_state(Radio::Mesh, to_state(policy.mesh_enabled));
    // FM is always off during security mode transitions.
    pm.set_state(Radio::Fm, PowerState::Off);
}

#[cfg(test)]
impl CandidateCpuPolicy {
    /// Update the logical performance request without touching hardware.
    ///
    /// This four-sample, 30/70 deadband policy is a candidate retained for host
    /// tests only. It is not compiled into QEMU or device runtimes and is not
    /// an accepted MT6739 request or actuation contract (#879).
    fn update_performance_request(&mut self, load_percent: u8) -> CandidatePerformanceLevel {
        self.load_history[self.load_idx] = load_percent;
        self.load_idx = (self.load_idx + 1) % LOAD_HISTORY_LEN;
        if self.load_samples < LOAD_HISTORY_LEN {
            self.load_samples += 1;
        }

        // WHY: averaging the filled portion preserves the candidate's intended
        // smoothing without diluting warm-up samples with phantom zeros. During
        // warm-up, load_idx writes sequentially from zero, so [..load_samples]
        // contains exactly the initialized slots.
        let sum: usize = self.load_history[..self.load_samples]
            .iter()
            .map(|&l| usize::from(l))
            .sum();
        let avg_load = sum / self.load_samples;

        let new_request = if avg_load < 30 {
            self.requested_performance
                .step_down()
                .unwrap_or(self.requested_performance)
        } else if avg_load > 70 {
            self.requested_performance
                .step_up()
                .unwrap_or(self.requested_performance)
        } else {
            self.requested_performance
        };
        self.requested_performance = new_request;
        new_request
    }

    /// Update the logical core request without touching hardware.
    fn update_core_request(&mut self, runnable_count: usize) -> CandidateCoreRequest {
        let new_request = if runnable_count <= 1 {
            CandidateCoreRequest::BootCoreOnly
        } else {
            CandidateCoreRequest::AllAvailable
        };
        self.requested_cores = new_request;
        new_request
    }
}

impl DisplayTimeoutState {
    /// Record timeout policy. Returns `true` for a new sleep request.
    fn record_timeout_request(&mut self, current_tick: u64) -> bool {
        if self.backlight_requested_on
            && current_tick.saturating_sub(self.last_input_tick) > self.backlight_timeout_ticks
        {
            self.backlight_requested_on = false;
            return true;
        }
        false
    }

    /// Record input policy. Returns `true` for a new wake request.
    fn record_input_request(&mut self, current_tick: u64) -> bool {
        self.last_input_tick = current_tick;
        if !self.backlight_requested_on {
            self.backlight_requested_on = true;
            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_policy_steps_down_on_low_load() {
        let mut gov = CandidateCpuPolicy::new();
        assert_eq!(
            gov.requested_performance(),
            CandidatePerformanceLevel::Maximum
        );
        let request = gov.update_performance_request(20);
        assert_eq!(
            request,
            CandidatePerformanceLevel::Elevated,
            "low load must step the logical request down"
        );
    }

    #[test]
    fn candidate_policy_steps_up_on_high_load() {
        let mut gov = CandidateCpuPolicy::new();
        gov.requested_performance = CandidatePerformanceLevel::Minimum;
        let request = gov.update_performance_request(80);
        assert_eq!(
            request,
            CandidatePerformanceLevel::Reduced,
            "high load must step the logical request up"
        );
    }

    #[test]
    fn candidate_policy_holds_on_mid_load() {
        let mut gov = CandidateCpuPolicy::new();
        gov.requested_performance = CandidatePerformanceLevel::Elevated;
        let request = gov.update_performance_request(50);
        assert_eq!(
            request,
            CandidatePerformanceLevel::Elevated,
            "mid load must hold the logical request"
        );
    }

    #[test]
    fn candidate_policy_floor_at_minimum() {
        let mut gov = CandidateCpuPolicy::new();
        gov.requested_performance = CandidatePerformanceLevel::Minimum;
        let request = gov.update_performance_request(0);
        assert_eq!(
            request,
            CandidatePerformanceLevel::Minimum,
            "logical request must not step below minimum"
        );
    }

    #[test]
    fn candidate_policy_ceiling_at_maximum() {
        let mut gov = CandidateCpuPolicy::new();
        let request = gov.update_performance_request(100);
        assert_eq!(
            request,
            CandidatePerformanceLevel::Maximum,
            "logical request must not step above maximum"
        );
    }

    #[test]
    fn candidate_core_policy_requests_boot_core_when_one_runnable() {
        let mut gov = CandidateCpuPolicy::new();
        assert_eq!(
            gov.requested_cores(),
            CandidateCoreRequest::AllAvailable,
            "candidate initially requests all available cores"
        );
        let request = gov.update_core_request(1);
        assert_eq!(request, CandidateCoreRequest::BootCoreOnly);
    }

    #[test]
    fn candidate_core_policy_requests_all_when_multiple_runnable() {
        let mut gov = CandidateCpuPolicy::new();
        gov.update_core_request(1);
        let request = gov.update_core_request(4);
        assert_eq!(request, CandidateCoreRequest::AllAvailable);
    }

    #[test]
    fn timeout_records_display_sleep_request() {
        let mut state = DisplayTimeoutState::new();
        state.last_input_tick = 0;
        state.backlight_timeout_ticks = 3_000;
        // WHY: Tick 3_001 crosses the configured `> 3_000` threshold.
        let requested = state.record_timeout_request(3_001);
        assert!(requested, "timeout must record a new sleep request");
        assert!(
            !state.backlight_requested_on(),
            "recorded request must be off"
        );
    }

    #[test]
    fn timeout_boundary_keeps_display_wake_request() {
        let mut state = DisplayTimeoutState::new();
        state.last_input_tick = 0;
        state.backlight_timeout_ticks = 3_000;
        // WHY: At the exact boundary the `> 3_000` condition remains false.
        let requested = state.record_timeout_request(3_000);
        assert!(!requested, "boundary must not record a sleep request");
        assert!(
            state.backlight_requested_on(),
            "recorded request must remain on"
        );
    }

    #[test]
    fn input_records_display_wake_request_and_resets_timer() {
        let mut state = DisplayTimeoutState::new();
        // WHY: Start from a previously recorded display-sleep request.
        state.backlight_requested_on = false;
        state.last_input_tick = 0;
        let requested = state.record_input_request(5_000);
        assert!(requested, "input must record a new wake request");
        assert!(
            state.backlight_requested_on(),
            "recorded request must be on after input"
        );
        assert_eq!(
            state.last_input_tick, 5_000,
            "last_input_tick must be updated"
        );
    }

    #[test]
    fn input_while_wake_already_requested_only_updates_tick() {
        let mut state = DisplayTimeoutState::new();
        // WHY: The initial request already keeps the display awake.
        let requested = state.record_input_request(500);
        assert!(!requested, "no new wake request when already requested on");
        assert_eq!(state.last_input_tick, 500);
    }

    #[test]
    fn candidate_policy_averages_instead_of_reacting_to_a_single_spike() {
        let mut gov = CandidateCpuPolicy::new();
        gov.requested_performance = CandidatePerformanceLevel::Reduced;
        // WHY: Three steady-state samples followed by one high spike exercise
        // the four-sample rolling average. The average keeps the spike from
        // single-handedly stepping the logical request up: avg =
        // (50+50+50+100)/4 = 62, still inside the 30-70 hold band. The
        // previous (buggy) instantaneous-load logic would have reacted to
        // the raw 100% sample alone and stepped up a logical level.
        gov.update_performance_request(50);
        gov.update_performance_request(50);
        gov.update_performance_request(50);
        let request = gov.update_performance_request(100);
        assert_eq!(
            request,
            CandidatePerformanceLevel::Reduced,
            "a single-tick spike must be smoothed by the rolling average, not react raw"
        );
    }

    #[test]
    fn candidate_policy_walks_down_then_up_through_every_logical_level() {
        let mut gov = CandidateCpuPolicy::new();
        assert_eq!(
            gov.requested_performance(),
            CandidatePerformanceLevel::Maximum
        );

        // WHY: Sustained low samples remain below the threshold throughout
        // warm-up because the average includes only initialized slots. The
        // candidate therefore steps through one logical level per sample.
        assert_eq!(
            gov.update_performance_request(10),
            CandidatePerformanceLevel::Elevated
        );
        assert_eq!(
            gov.update_performance_request(10),
            CandidatePerformanceLevel::Reduced
        );
        assert_eq!(
            gov.update_performance_request(10),
            CandidatePerformanceLevel::Minimum
        );
        assert_eq!(
            gov.update_performance_request(10),
            CandidatePerformanceLevel::Minimum,
            "must not step below the minimum logical level"
        );

        // WHY: sustained high load must first flush the stale low-load window
        // (LOAD_HISTORY_LEN ticks) before the rolling average clears the
        // >70 step-up threshold, then walk back up through every level.
        for _ in 0..LOAD_HISTORY_LEN {
            gov.update_performance_request(90);
        }
        assert_eq!(
            gov.requested_performance(),
            CandidatePerformanceLevel::Reduced,
            "after the window flushes to sustained high load, must have stepped up once"
        );
        assert_eq!(
            gov.update_performance_request(90),
            CandidatePerformanceLevel::Elevated
        );
        assert_eq!(
            gov.update_performance_request(90),
            CandidatePerformanceLevel::Maximum
        );
        assert_eq!(
            gov.update_performance_request(90),
            CandidatePerformanceLevel::Maximum,
            "must not step above the maximum logical level"
        );
    }

    #[test]
    fn candidate_policy_holds_at_exact_deadband_boundaries() {
        let mut lower = CandidateCpuPolicy::new();
        lower.requested_performance = CandidatePerformanceLevel::Elevated;
        assert_eq!(
            lower.update_performance_request(30),
            CandidatePerformanceLevel::Elevated,
            "exactly 30 must hold"
        );

        let mut upper = CandidateCpuPolicy::new();
        upper.requested_performance = CandidatePerformanceLevel::Reduced;
        assert_eq!(
            upper.update_performance_request(70),
            CandidatePerformanceLevel::Reduced,
            "exactly 70 must hold"
        );
    }

    #[test]
    fn starts_silent() {
        let pm = PowerManager::new();
        assert_eq!(pm.mode(), PowerMode::Silent);
        assert_eq!(pm.active_count(), 0);
    }

    #[test]
    fn full_mode() {
        let mut pm = PowerManager::new();
        pm.apply_mode(PowerMode::Full);
        assert_eq!(pm.active_count(), 6);
        assert_eq!(pm.state(Radio::Cellular), PowerState::On);
        assert_eq!(pm.state(Radio::Wifi), PowerState::On);
        assert_eq!(
            pm.state(Radio::Mesh),
            PowerState::On,
            "Full mode must enable mesh (#254)"
        );
    }

    #[test]
    fn cell_only_mode() {
        let mut pm = PowerManager::new();
        pm.apply_mode(PowerMode::CellOnly);
        assert_eq!(pm.active_count(), 1);
        assert_eq!(pm.state(Radio::Cellular), PowerState::On);
        assert_eq!(pm.state(Radio::Wifi), PowerState::Off);
    }

    #[test]
    fn hardware_kill_prevents_software_on() {
        let mut pm = PowerManager::new();
        pm.hardware_kill(Radio::Cellular);
        assert_eq!(pm.state(Radio::Cellular), PowerState::HardwareKilled);
        let result = pm.set_state(Radio::Cellular, PowerState::On);
        assert!(!result, "should not be able to override hardware kill");
        assert_eq!(pm.state(Radio::Cellular), PowerState::HardwareKilled);
    }

    #[test]
    fn hardware_kill_all() {
        let mut pm = PowerManager::new();
        pm.apply_mode(PowerMode::Full);
        pm.hardware_kill(Radio::All);
        assert_eq!(pm.active_count(), 0);
        assert_eq!(pm.state(Radio::All), PowerState::Off);
    }

    #[test]
    fn hardware_kill_survives_software_off_then_on() {
        // Regression test for #345: previously any set_state call with a
        // target other than On silently erased terminal request markers.
        let mut pm = PowerManager::new();
        pm.apply_mode(PowerMode::Full);
        pm.hardware_kill(Radio::Cellular);
        assert_eq!(pm.state(Radio::Cellular), PowerState::HardwareKilled);

        let off_result = pm.set_state(Radio::Cellular, PowerState::Off);
        assert!(
            !off_result,
            "software Off must not succeed over a hardware kill"
        );
        assert_eq!(
            pm.state(Radio::Cellular),
            PowerState::HardwareKilled,
            "hardware kill must survive a software Off"
        );

        let on_result = pm.set_state(Radio::Cellular, PowerState::On);
        assert!(!on_result);
        assert_eq!(pm.state(Radio::Cellular), PowerState::HardwareKilled);

        pm.request_modem_power_cut();
        assert_eq!(
            pm.state(Radio::Cellular),
            PowerState::HardwareKilled,
            "a later modem-cut request must not replace the first terminal marker"
        );
    }

    #[test]
    fn hardware_kill_all_survives_apply_mode_silent() {
        // Regression test for #345: the Radio::All branch had the same bug
        // — apply_mode(Silent) -> set_state(All, Off) erased every kill.
        let mut pm = PowerManager::new();
        pm.apply_mode(PowerMode::Full);
        pm.hardware_kill(Radio::All);

        let radios = [
            Radio::Cellular,
            Radio::Wifi,
            Radio::Bluetooth,
            Radio::Gps,
            Radio::Fm,
            Radio::Mesh,
        ];
        for radio in radios {
            assert_eq!(pm.state(radio), PowerState::HardwareKilled);
        }

        pm.apply_mode(PowerMode::Silent);

        for radio in radios {
            assert_eq!(
                pm.state(radio),
                PowerState::HardwareKilled,
                "{radio:?} must remain hardware-killed after apply_mode(Silent)"
            );
        }
    }

    #[test]
    fn local_only_mode() {
        let mut pm = PowerManager::new();
        pm.apply_mode(PowerMode::LocalOnly);
        assert_eq!(pm.state(Radio::Wifi), PowerState::On);
        assert_eq!(pm.state(Radio::Bluetooth), PowerState::On);
        assert_eq!(pm.state(Radio::Cellular), PowerState::Off);
        assert_eq!(pm.state(Radio::Gps), PowerState::Off);
    }

    #[test]
    fn apply_mode_does_not_commit_on_partial_failure() {
        let mut pm = PowerManager::new();
        pm.apply_mode(PowerMode::Full);
        pm.hardware_kill(Radio::Cellular);

        // CellOnly requires turning Cellular On, which the hardware kill blocks.
        let ok = pm.apply_mode(PowerMode::CellOnly);
        assert!(
            !ok,
            "apply_mode must report failure when a radio cannot reach its target state"
        );
        assert_eq!(
            pm.mode(),
            PowerMode::Full,
            "mode() must not record CellOnly when it was only partially applied"
        );
    }

    // -----------------------------------------------------------------------
    // apply_mode_policy tests (Phase 08 Wave 8)
    // -----------------------------------------------------------------------

    #[test]
    fn mode_policy_applies_radio_state_sentinel() {
        use crate::security::SleepTier;
        use crate::security_mode::ModePolicy;

        let mut pm = PowerManager::new();
        pm.apply_mode(PowerMode::Full);

        // Sentinel policy: cellular/wifi/bt off, GPS on.
        let sentinel_policy = ModePolicy {
            cellular_enabled: false,
            wifi_enabled: false,
            bluetooth_enabled: false,
            gps_enabled: true,
            mesh_enabled: true,
            sleep_tier: SleepTier::Long,
            scan_interval_ms: 10_000,
        };

        apply_mode_policy(&sentinel_policy, &mut pm);

        assert_eq!(
            pm.state(Radio::Cellular),
            PowerState::Off,
            "Sentinel must disable cellular"
        );
        assert_eq!(
            pm.state(Radio::Wifi),
            PowerState::Off,
            "Sentinel must disable WiFi"
        );
        assert_eq!(
            pm.state(Radio::Bluetooth),
            PowerState::Off,
            "Sentinel must disable Bluetooth"
        );
        assert_eq!(
            pm.state(Radio::Gps),
            PowerState::On,
            "Sentinel must keep GPS on"
        );
        assert_eq!(
            pm.state(Radio::Fm),
            PowerState::Off,
            "FM must always be off in security modes"
        );
        assert_eq!(
            pm.state(Radio::Mesh),
            PowerState::On,
            "Sentinel must keep mesh on (#254)"
        );
    }

    #[test]
    fn mode_policy_applies_radio_state_daily() {
        use crate::security::SleepTier;
        use crate::security_mode::ModePolicy;

        let mut pm = PowerManager::new();

        // Daily policy: all radios on.
        let daily_policy = ModePolicy {
            cellular_enabled: true,
            wifi_enabled: true,
            bluetooth_enabled: true,
            gps_enabled: true,
            mesh_enabled: true,
            sleep_tier: SleepTier::Short,
            scan_interval_ms: 60_000,
        };

        apply_mode_policy(&daily_policy, &mut pm);

        assert_eq!(
            pm.state(Radio::Cellular),
            PowerState::On,
            "Daily must enable cellular"
        );
        assert_eq!(
            pm.state(Radio::Wifi),
            PowerState::On,
            "Daily must enable WiFi"
        );
        assert_eq!(
            pm.state(Radio::Bluetooth),
            PowerState::On,
            "Daily must enable Bluetooth"
        );
        assert_eq!(
            pm.state(Radio::Gps),
            PowerState::On,
            "Daily must enable GPS"
        );
        assert_eq!(
            pm.state(Radio::Mesh),
            PowerState::On,
            "Daily must enable mesh (#254)"
        );
    }

    #[test]
    fn mode_policy_applies_radio_state_panic_disables_mesh() {
        use crate::security::SleepTier;
        use crate::security_mode::ModePolicy;

        let mut pm = PowerManager::new();
        pm.apply_mode(PowerMode::Full);

        // Panic policy: everything off, including mesh (#254).
        let panic_policy = ModePolicy {
            cellular_enabled: false,
            wifi_enabled: false,
            bluetooth_enabled: false,
            gps_enabled: false,
            mesh_enabled: false,
            sleep_tier: SleepTier::Long,
            scan_interval_ms: 0,
        };

        apply_mode_policy(&panic_policy, &mut pm);

        assert_eq!(
            pm.state(Radio::Mesh),
            PowerState::Off,
            "Panic must disable mesh/LoRa (#254)"
        );
    }

    // -----------------------------------------------------------------------
    // Modem power-cut request tests (Phase 10 Wave 3)
    // -----------------------------------------------------------------------

    #[test]
    fn cut_request_prevents_individual_software_on() {
        let mut pm = PowerManager::new();
        pm.request_modem_power_cut();
        assert_eq!(pm.state(Radio::Cellular), PowerState::PowerCutRequested);
        let result = pm.set_state(Radio::Cellular, PowerState::On);
        assert!(!result, "cannot erase the sticky request via software");
        assert_eq!(pm.state(Radio::Cellular), PowerState::PowerCutRequested);
    }

    #[test]
    fn modem_cut_request_is_false_initially() {
        let pm = PowerManager::new();
        assert!(
            !pm.is_modem_cut_requested(),
            "no modem-cut request marker initially"
        );
    }

    #[test]
    fn modem_cut_request_is_sticky_after_recording() {
        let mut pm = PowerManager::new();
        pm.request_modem_power_cut();
        assert!(
            pm.is_modem_cut_requested(),
            "request must record the sticky modem-cut marker"
        );
        assert_eq!(pm.state(Radio::Cellular), PowerState::PowerCutRequested);
        assert!(
            !pm.set_state(Radio::Cellular, PowerState::On),
            "ordinary policy updates must not erase the cut request"
        );
        pm.hardware_kill(Radio::Cellular);
        assert_eq!(
            pm.state(Radio::Cellular),
            PowerState::PowerCutRequested,
            "a later simulated hardware marker must not replace the first terminal marker"
        );
    }

    #[test]
    fn cut_request_prevents_all_radios_on() {
        let mut pm = PowerManager::new();
        pm.apply_mode(PowerMode::Full);
        pm.request_modem_power_cut();
        // Attempt to turn all on.
        let result = pm.set_state(Radio::All, PowerState::On);
        assert!(
            !result,
            "cannot set_state All On when one has a sticky cut request"
        );
        assert_eq!(
            pm.state(Radio::Cellular),
            PowerState::PowerCutRequested,
            "sticky modem-cut request marker must reject an On request"
        );
    }
}
