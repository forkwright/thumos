//! Power management: radio kill switches and CPU power governor.
//!
//! Two concerns live here:
//!
//! 1. **Radio kill switches** — GPIO-controlled power gates for cellular,
//!    WiFi, BT, GPS, FM.  When off the hardware is physically disconnected
//!    from power; software cannot override a hardware kill.
//!
//! 2. **CPU power governor** (REQ-19) — DVFS, core parking, and display
//!    backlight timeout for the MT6739 Cortex-A53 cluster.
//!
//! ## MT6739 register map (governor)
//!
//! | Register      | Address       | Purpose                              |
//! |---------------|---------------|--------------------------------------|
//! | ARMPLL_CON1   | 0x1000_C104   | CPU PLL divider → frequency          |
//! | MCDI_BASE     | 0x1000_DC00   | Multi-Core Deep Idle control block   |
//! | MCDI_CORE_EN  | 0x1000_DC04   | Per-core power-down enable bitmask   |
//!
//! ARMPLL_CON1 encoding used here matches the four frequency steps
//! supported by the MT6739 stock DVFS table (1500 / 1200 / 900 / 600 MHz).
//! The exact PCW (post-divider control word) values are documented in the
//! MT6739 Clock Management Unit (CMU) specification rev 1.3 §4.2.

// ---------------------------------------------------------------------------
// MT6739 governor registers
// ---------------------------------------------------------------------------

/// ARMPLL_CON1: CPU PLL control register.
/// Bits [21:0] = PCW (integer + fractional divider).
/// The four values below are approximate; production firmware reads them
/// from the efuse-calibrated OPP table.
const ARMPLL_CON1: usize = 0x1000_C104;

/// MCDI (Multi-Core Deep Idle) base address.
const MCDI_BASE: usize = 0x1000_DC00;

/// MCDI_CORE_EN: per-core power-down enable register.
/// Bit N = 1 → core N is powered down.
#[expect(
    dead_code,
    reason = "reserved for per-core power-down; wired in follow-up"
)]
const MCDI_CORE_EN: usize = MCDI_BASE + 0x04;

// ---------------------------------------------------------------------------
// CPU frequency steps
// ---------------------------------------------------------------------------

/// CPU frequency operating points.
///
/// `repr(u32)` values are written directly to ARMPLL_CON1.  The PCW
/// values are truncated approximations; a production kernel reads the
/// exact values from the efuse OPP table during boot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u32)]
pub enum CpuFreq {
    /// 1 500 MHz — full performance (PCW 0x009_6000 ≈ 0x0096_0000).
    Mhz1500 = 0x0096_0000,
    /// 1 200 MHz — mid-high (PCW ≈ 0x0078_0000).
    Mhz1200 = 0x0078_0000,
    /// 900 MHz — mid-low (PCW ≈ 0x005A_0000).
    Mhz900 = 0x005A_0000,
    /// 600 MHz — low power (PCW ≈ 0x003C_0000).
    Mhz600 = 0x003C_0000,
}

impl CpuFreq {
    /// Return the next lower frequency step, or `None` if already minimum.
    fn step_down(self) -> Option<Self> {
        match self {
            Self::Mhz1500 => Some(Self::Mhz1200),
            Self::Mhz1200 => Some(Self::Mhz900),
            Self::Mhz900 => Some(Self::Mhz600),
            Self::Mhz600 => None,
        }
    }

    /// Return the next higher frequency step, or `None` if already maximum.
    fn step_up(self) -> Option<Self> {
        match self {
            Self::Mhz600 => Some(Self::Mhz900),
            Self::Mhz900 => Some(Self::Mhz1200),
            Self::Mhz1200 => Some(Self::Mhz1500),
            Self::Mhz1500 => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Display backlight timeout (30 s at 10 ms/tick = 3 000 ticks)
// ---------------------------------------------------------------------------

/// Default backlight timeout: 30 seconds at 10 ms per tick.
const BACKLIGHT_TIMEOUT_TICKS: u64 = 3_000;

// ---------------------------------------------------------------------------
// CPU governor state
// ---------------------------------------------------------------------------

/// Rolling load history depth (ticks).
const LOAD_HISTORY_LEN: usize = 4;

/// CPU governor and display timeout state.
///
/// One global instance is accessed from the timer IRQ handler only
/// (single-core ARMv7, IRQs disabled during the handler).  No lock needed.
pub(crate) struct CpuGovernor {
    /// Current CPU frequency operating point.
    current_freq: CpuFreq,
    /// Active core bitmask.  Bit 0 = core 0 (always on), bits 1-3 = secondary.
    cores_active: u8,
    /// Display backlight on/off.
    backlight_on: bool,
    /// Tick timestamp of the last input event.
    last_input_tick: u64,
    /// Backlight off timeout in ticks.
    backlight_timeout_ticks: u64,
    /// Rolling CPU load history (load % per tick, most-recent last).
    load_history: [u8; LOAD_HISTORY_LEN],
    /// Write pointer into load_history (circular).
    load_idx: usize,
}

impl CpuGovernor {
    /// Create a new governor starting at full performance, all cores active,
    /// backlight on.
    pub(crate) const fn new() -> Self {
        Self {
            current_freq: CpuFreq::Mhz1500,
            cores_active: 0b0000_1111, // cores 0-3 active
            backlight_on: true,
            last_input_tick: 0,
            backlight_timeout_ticks: BACKLIGHT_TIMEOUT_TICKS,
            load_history: [0u8; LOAD_HISTORY_LEN],
            load_idx: 0,
        }
    }

    /// Current CPU frequency.
    pub(crate) fn current_freq(&self) -> CpuFreq {
        self.current_freq
    }

    /// Current active-core bitmask.
    pub(crate) fn cores_active(&self) -> u8 {
        self.cores_active
    }

    /// Whether the display backlight is on.
    pub(crate) fn backlight_on(&self) -> bool {
        self.backlight_on
    }
}

// ---------------------------------------------------------------------------
// Global governor instance
// ---------------------------------------------------------------------------

/// Global CPU governor.  Written only from the timer IRQ handler on a
/// single-core ARMv7 with interrupts disabled — no lock needed.
static mut GOVERNOR: CpuGovernor = CpuGovernor::new();

// ---------------------------------------------------------------------------
// Public API — called from scheduler / timer IRQ handler
// ---------------------------------------------------------------------------

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

/// DVFS governor: adjust CPU frequency based on load.
///
/// `load_percent` is the fraction of the last tick the CPU was running a
/// non-idle process (0–100).  The threshold governor:
///
/// * load < 30% → step frequency down one OPP
/// * load > 70% → step frequency up one OPP
/// * 30%–70% → hold current OPP
///
/// The new OPP is written to `ARMPLL_CON1`.
///
/// # Safety
///
/// Called from the timer IRQ handler (interrupts disabled, single-core).
pub(crate) fn evaluate_dvfs(load_percent: u8) {
    // SAFETY: GOVERNOR is only accessed from the timer IRQ handler.
    let gov = unsafe { &mut *core::ptr::addr_of_mut!(GOVERNOR) };
    let prev_freq = gov.current_freq;
    let new_freq = gov.apply_dvfs(load_percent);

    if new_freq != prev_freq {
        // SAFETY: ARMPLL_CON1 is a valid MMIO register on the MT6739 CMU
        // block at 0x1000_C104.  Volatile write is required for hardware
        // registers.  Called with IRQs disabled so no torn write.
        unsafe {
            crate::mmio::write32(ARMPLL_CON1, new_freq as u32);
        }
    }
}

/// Core-parking governor: power down unused secondary cores.
///
/// When only one process is runnable, cores 1-3 can be parked.  The
/// `cores_active` bitmask is updated and stubbed MCDI register writes
/// are issued.  Bit 0 (core 0) is never cleared — the boot core always
/// stays on.
///
/// MT6739 MCDI register addresses:
/// * `0x1000_DC00` — MCDI_BASE
/// * `0x1000_DC04` — MCDI_CORE_EN: bit N=1 powers down core N
///
/// # Safety
///
/// Called from the timer IRQ handler (interrupts disabled, single-core).
pub(crate) fn evaluate_core_parking(runnable_count: usize) {
    // SAFETY: GOVERNOR is only accessed from the timer IRQ handler.
    let gov = unsafe { &mut *core::ptr::addr_of_mut!(GOVERNOR) };
    let prev_mask = gov.cores_active;
    let new_mask = gov.apply_core_parking(runnable_count);

    if new_mask != prev_mask {
        // Write inverse mask to MCDI_CORE_EN: bit N=1 → power down core N.
        // Core 0 is never set here (bit 0 of the inverse is always 0).
        let park_mask = u32::from(!new_mask & 0b0000_1110);
        // SAFETY: MCDI_CORE_EN is a valid MMIO register on the MT6739 MCDI
        // block at 0x1000_DC04.  Stub write — production MCDI handshake
        // requires additional synchronisation with each core's reset handler,
        // which is not yet wired.
        unsafe {
            crate::mmio::write32(MCDI_CORE_EN, park_mask);
        }
    }
}

/// Reset the backlight timeout on keypad or touch input.
///
/// Call this from the keypad / touch interrupt handler whenever the user
/// produces input.
///
/// # Safety
///
/// Called from an IRQ handler (interrupts disabled, single-core).
pub(crate) fn notify_input(current_tick: u64) {
    // SAFETY: GOVERNOR is only accessed from IRQ context.
    let gov = unsafe { &mut *core::ptr::addr_of_mut!(GOVERNOR) };
    let woke = gov.apply_notify_input(current_tick);
    if woke {
        // SAFETY: DSI0 is active when display is in Suspended state and
        // the display subsystem has been initialised.  The resume sequence
        // exits Sleep-In mode per GC9306 datasheet §8.2.
        unsafe {
            display_wake();
        }
    }
}

/// Check whether the backlight timeout has elapsed and sleep the display.
///
/// Call this once per scheduler tick.
///
/// # Safety
///
/// Called from the timer IRQ handler (interrupts disabled, single-core).
pub(crate) fn check_backlight_timeout(current_tick: u64) {
    // SAFETY: GOVERNOR is only accessed from the timer IRQ handler.
    let gov = unsafe { &mut *core::ptr::addr_of_mut!(GOVERNOR) };
    let turned_off = gov.apply_backlight_timeout(current_tick);
    if turned_off {
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
/// DSI0 CMD_FIFO register: 0x1400_D000 + offset 0x200.
/// Format: bits [7:0] = DCS opcode, bit 8 = last-byte flag.
#[expect(
    dead_code,
    reason = "DSI0 init helper; invoked by panel bring-up in follow-up"
)]
unsafe fn dcs_cmd0(cmd: u8) {
    // SAFETY: DSI0_CMD_FIFO is a valid MMIO register within the DSI0
    // address space at 0x1400_D000.  Volatile access required for hardware.
    const DSI0_CMD_FIFO: usize = 0x1400_D200;
    unsafe {
        crate::mmio::write32(DSI0_CMD_FIFO, u32::from(cmd) | 0x100);
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

/// Power state of a radio.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PowerState {
    /// Powered on and active.
    On,
    /// Powered off (kill switch or software).
    Off,
    /// Hardware kill switch active (software cannot override).
    HardwareKilled,
    /// Power cut via PMIC LDO disable (hardware kill, requires reboot).
    PmicKilled,
}

/// System power mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerMode {
    /// All radios on, full performance.
    Full,
    /// Cellular only, everything else off.
    CellOnly,
    /// All radios off, RF silent.
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
    /// Create a new power manager with all radios off.
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

    /// Get the power state of a radio.
    pub(crate) fn state(&self, radio: Radio) -> PowerState {
        if radio == Radio::All {
            // All is "on" only if every radio is on
            if self.states.iter().all(|(_, s)| *s == PowerState::On) {
                PowerState::On
            } else {
                PowerState::Off
            }
        } else {
            self.states
                .iter()
                .find(|(r, _)| *r == radio)
                .map(|(_, s)| *s)
                .unwrap_or(PowerState::Off)
        }
    }

    /// Set the power state of a radio.
    /// Returns false if hardware kill switch or PMIC kill prevents the change.
    ///
    /// INVARIANT: once a radio reaches [`PowerState::HardwareKilled`] or
    /// [`PowerState::PmicKilled`], no software `set_state` call — for ANY
    /// target state, not only `On` — can move it out of that state (#345).
    /// Only a fresh [`PowerManager`] (i.e. a reboot) clears a kill.
    pub(crate) fn set_state(&mut self, radio: Radio, state: PowerState) -> bool {
        if radio == Radio::All {
            let mut all_ok = true;
            for (_, s) in &mut self.states {
                if *s == PowerState::HardwareKilled || *s == PowerState::PmicKilled {
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
                // INVARIANT: hardware/PMIC kill cannot be overridden by
                // software, for any target state (not just On) — see the
                // doc comment above.
                if *s == PowerState::HardwareKilled || *s == PowerState::PmicKilled {
                    return state == *s;
                }
                *s = state;
                return true;
            }
        }
        false
    }

    /// Apply a power mode preset.
    pub(crate) fn apply_mode(&mut self, mode: PowerMode) {
        match mode {
            PowerMode::Full => {
                self.set_state(Radio::All, PowerState::On);
            }
            PowerMode::CellOnly => {
                self.set_state(Radio::Cellular, PowerState::On);
                self.set_state(Radio::Wifi, PowerState::Off);
                self.set_state(Radio::Bluetooth, PowerState::Off);
                self.set_state(Radio::Gps, PowerState::Off);
                self.set_state(Radio::Fm, PowerState::Off);
                self.set_state(Radio::Mesh, PowerState::Off);
            }
            PowerMode::Silent => {
                self.set_state(Radio::All, PowerState::Off);
            }
            PowerMode::LocalOnly => {
                self.set_state(Radio::Cellular, PowerState::Off);
                self.set_state(Radio::Wifi, PowerState::On);
                self.set_state(Radio::Bluetooth, PowerState::On);
                self.set_state(Radio::Gps, PowerState::Off);
                self.set_state(Radio::Fm, PowerState::Off);
                self.set_state(Radio::Mesh, PowerState::Off);
            }
        }
        self.mode = mode;
    }

    /// Get the current power mode.
    pub(crate) fn mode(&self) -> PowerMode {
        self.mode
    }

    /// Simulate hardware kill switch activation for a radio.
    /// Once killed by hardware, only hardware can re-enable.
    pub(crate) fn hardware_kill(&mut self, radio: Radio) {
        if radio == Radio::All {
            for (_, s) in &mut self.states {
                *s = PowerState::HardwareKilled;
            }
        } else {
            for (r, s) in &mut self.states {
                if *r == radio {
                    *s = PowerState::HardwareKilled;
                }
            }
        }
    }

    /// Execute a modem PMIC power cut.
    ///
    /// Sets the cellular radio to [`PowerState::PmicKilled`] and triggers
    /// the hardware power cut via PMIC VMODEM LDO disable.  After this call
    /// the modem is physically unpowered and cannot be restarted without a
    /// full system reboot.
    ///
    /// # Safety
    ///
    /// PMIC registers must be mapped.  Caller must be in privileged context.
    pub unsafe fn modem_power_cut(&mut self) {
        for (r, s) in &mut self.states {
            if *r == Radio::Cellular {
                *s = PowerState::PmicKilled;
            }
        }
        // SAFETY: caller guarantees PMIC registers are mapped.
        unsafe {
            crate::ccci_logger::modem_power_cut();
        }
    }

    /// Whether the modem has been PMIC-killed.
    pub(crate) fn is_modem_pmic_killed(&self) -> bool {
        self.states
            .iter()
            .any(|(r, s)| *r == Radio::Cellular && *s == PowerState::PmicKilled)
    }

    /// Count radios currently on.
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

/// Apply a security mode's radio policy to a power manager.
///
/// Maps boolean enable/disable flags from a [`ModePolicy`] to
/// [`PowerState::On`] / [`PowerState::Off`] and calls
/// [`PowerManager::set_state`] for each radio, including Mesh/LoRa (#254).
/// FM is always turned off in security mode transitions (not a
/// security-relevant radio).
///
/// Used by the boot sequence (Wave 8) and by [`ModeManager`] on mode
/// transitions to enforce radio policy without coupling security_mode
/// directly to PowerManager internals.
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

// ---------------------------------------------------------------------------
// Testable governor logic (no MMIO side-effects)
// ---------------------------------------------------------------------------

impl CpuGovernor {
    /// Apply DVFS logic and return the new frequency without touching hardware.
    ///
    /// Used by unit tests and as the pure core called by `evaluate_dvfs`.
    pub(crate) fn apply_dvfs(&mut self, load_percent: u8) -> CpuFreq {
        self.load_history[self.load_idx] = load_percent;
        self.load_idx = (self.load_idx + 1) % LOAD_HISTORY_LEN;

        let new_freq = if load_percent < 30 {
            self.current_freq.step_down().unwrap_or(self.current_freq)
        } else if load_percent > 70 {
            self.current_freq.step_up().unwrap_or(self.current_freq)
        } else {
            self.current_freq
        };
        self.current_freq = new_freq;
        new_freq
    }

    /// Apply core-parking logic and return the new bitmask without touching hardware.
    pub(crate) fn apply_core_parking(&mut self, runnable_count: usize) -> u8 {
        let new_mask: u8 = if runnable_count <= 1 {
            0b0000_0001
        } else {
            0b0000_1111
        };
        self.cores_active = new_mask;
        new_mask
    }

    /// Apply backlight timeout logic.  Returns `true` if the backlight just
    /// turned off.
    pub(crate) fn apply_backlight_timeout(&mut self, current_tick: u64) -> bool {
        if self.backlight_on
            && current_tick.saturating_sub(self.last_input_tick) > self.backlight_timeout_ticks
        {
            self.backlight_on = false;
            return true;
        }
        false
    }

    /// Record input and return `true` if the display was woken.
    pub(crate) fn apply_notify_input(&mut self, current_tick: u64) -> bool {
        self.last_input_tick = current_tick;
        if !self.backlight_on {
            self.backlight_on = true;
            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Governor tests (REQ-19)
    // -----------------------------------------------------------------------

    #[test]
    fn dvfs_scales_down_on_low_load() {
        let mut gov = CpuGovernor::new();
        assert_eq!(gov.current_freq(), CpuFreq::Mhz1500);
        let freq = gov.apply_dvfs(20); // load 20% < 30%
        assert_eq!(freq, CpuFreq::Mhz1200, "low load must step frequency down");
    }

    #[test]
    fn dvfs_scales_up_on_high_load() {
        let mut gov = CpuGovernor::new();
        // Start at minimum so there is room to scale up.
        gov.current_freq = CpuFreq::Mhz600;
        let freq = gov.apply_dvfs(80); // load 80% > 70%
        assert_eq!(freq, CpuFreq::Mhz900, "high load must step frequency up");
    }

    #[test]
    fn dvfs_holds_on_mid_load() {
        let mut gov = CpuGovernor::new();
        gov.current_freq = CpuFreq::Mhz1200;
        let freq = gov.apply_dvfs(50); // 30% ≤ 50% ≤ 70%
        assert_eq!(
            freq,
            CpuFreq::Mhz1200,
            "mid load must hold current frequency"
        );
    }

    #[test]
    fn dvfs_floor_at_minimum() {
        let mut gov = CpuGovernor::new();
        gov.current_freq = CpuFreq::Mhz600;
        let freq = gov.apply_dvfs(0); // already at minimum, cannot go lower
        assert_eq!(freq, CpuFreq::Mhz600, "frequency must not go below minimum");
    }

    #[test]
    fn dvfs_ceiling_at_maximum() {
        let mut gov = CpuGovernor::new(); // starts at Mhz1500
        let freq = gov.apply_dvfs(100); // already at maximum
        assert_eq!(freq, CpuFreq::Mhz1500, "frequency must not exceed maximum");
    }

    #[test]
    fn core_parking_disables_cores_when_one_runnable() {
        let mut gov = CpuGovernor::new();
        assert_eq!(
            gov.cores_active(),
            0b0000_1111,
            "all cores active initially"
        );
        let mask = gov.apply_core_parking(1);
        assert_eq!(mask, 0b0000_0001, "only core 0 must remain active");
    }

    #[test]
    fn core_parking_keeps_all_cores_when_multiple_runnable() {
        let mut gov = CpuGovernor::new();
        gov.apply_core_parking(1); // park first
        let mask = gov.apply_core_parking(4); // then unpark
        assert_eq!(
            mask, 0b0000_1111,
            "all cores must be active for >1 runnable"
        );
    }

    #[test]
    fn backlight_timeout_triggers() {
        let mut gov = CpuGovernor::new();
        gov.last_input_tick = 0;
        gov.backlight_timeout_ticks = 3_000;
        // At tick 3_001 the timeout threshold (> 3_000) is crossed.
        let turned_off = gov.apply_backlight_timeout(3_001);
        assert!(turned_off, "backlight must turn off after timeout");
        assert!(!gov.backlight_on(), "backlight_on must be false");
    }

    #[test]
    fn backlight_no_timeout_before_threshold() {
        let mut gov = CpuGovernor::new();
        gov.last_input_tick = 0;
        gov.backlight_timeout_ticks = 3_000;
        // Exactly at the boundary (== 3_000) the condition is `> 3_000` → false.
        let turned_off = gov.apply_backlight_timeout(3_000);
        assert!(!turned_off, "backlight must not turn off before threshold");
        assert!(gov.backlight_on(), "backlight_on must still be true");
    }

    #[test]
    fn input_resets_backlight_timer() {
        let mut gov = CpuGovernor::new();
        // Simulate the backlight having been off.
        gov.backlight_on = false;
        gov.last_input_tick = 0;
        let woke = gov.apply_notify_input(5_000);
        assert!(woke, "input must wake the display");
        assert!(gov.backlight_on(), "backlight must be on after input");
        assert_eq!(
            gov.last_input_tick, 5_000,
            "last_input_tick must be updated"
        );
    }

    #[test]
    fn input_while_backlight_on_just_updates_tick() {
        let mut gov = CpuGovernor::new();
        // Backlight already on.
        let woke = gov.apply_notify_input(500);
        assert!(!woke, "no wake event when backlight is already on");
        assert_eq!(gov.last_input_tick, 500);
    }

    // -----------------------------------------------------------------------
    // Original PowerManager tests (radio kill switches)
    // -----------------------------------------------------------------------

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
        // target other than On silently erased HardwareKilled/PmicKilled.
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
    // PmicKilled tests (Phase 10 Wave 3)
    // -----------------------------------------------------------------------

    #[test]
    fn pmic_killed_prevents_software_on() {
        let mut pm = PowerManager::new();
        // Simulate PMIC kill on cellular.
        for (r, s) in &mut pm.states {
            if *r == Radio::Cellular {
                *s = PowerState::PmicKilled;
            }
        }
        assert_eq!(pm.state(Radio::Cellular), PowerState::PmicKilled);
        let result = pm.set_state(Radio::Cellular, PowerState::On);
        assert!(!result, "cannot override PMIC kill via software");
        assert_eq!(pm.state(Radio::Cellular), PowerState::PmicKilled);
    }

    #[test]
    fn is_modem_pmic_killed_false_initially() {
        let pm = PowerManager::new();
        assert!(
            !pm.is_modem_pmic_killed(),
            "modem not PMIC-killed initially"
        );
    }

    #[test]
    fn is_modem_pmic_killed_after_kill() {
        let mut pm = PowerManager::new();
        for (r, s) in &mut pm.states {
            if *r == Radio::Cellular {
                *s = PowerState::PmicKilled;
            }
        }
        assert!(pm.is_modem_pmic_killed(), "modem must be PMIC-killed");
    }

    #[test]
    fn pmic_killed_all_prevents_individual_on() {
        let mut pm = PowerManager::new();
        pm.apply_mode(PowerMode::Full);
        // PMIC kill on cellular only.
        for (r, s) in &mut pm.states {
            if *r == Radio::Cellular {
                *s = PowerState::PmicKilled;
            }
        }
        // Attempt to turn all on.
        let result = pm.set_state(Radio::All, PowerState::On);
        assert!(!result, "cannot set_state All On when one is PmicKilled");
        assert_eq!(
            pm.state(Radio::Cellular),
            PowerState::PmicKilled,
            "PMIC-killed radio must stay killed"
        );
    }
}
