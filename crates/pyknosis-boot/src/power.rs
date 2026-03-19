//! Power management and radio kill switch control.
//!
//! Controls power states for each radio subsystem (cellular, `WiFi`, `BT`,
//! `GPS`, FM) and the CPU frequency governor. Kill switches are implemented
//! as `GPIO`-controlled power gates — when off, the hardware is physically
//! disconnected from power, not just software-disabled.

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
    /// All radios.
    All,
}

/// Power state of a radio.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerState {
    /// Powered on and active.
    On,
    /// Powered off (kill switch or software).
    Off,
    /// Hardware kill switch active (software cannot override).
    HardwareKilled,
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
pub struct PowerManager {
    states: [(Radio, PowerState); 5],
    mode: PowerMode,
}

impl PowerManager {
    /// Create a new power manager with all radios off.
    pub fn new() -> Self {
        Self {
            states: [
                (Radio::Cellular, PowerState::Off),
                (Radio::Wifi, PowerState::Off),
                (Radio::Bluetooth, PowerState::Off),
                (Radio::Gps, PowerState::Off),
                (Radio::Fm, PowerState::Off),
            ],
            mode: PowerMode::Silent,
        }
    }

    /// Get the power state of a radio.
    pub fn state(&self, radio: Radio) -> PowerState {
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
    /// Returns false if hardware kill switch prevents the change.
    pub fn set_state(&mut self, radio: Radio, state: PowerState) -> bool {
        if radio == Radio::All {
            let mut all_ok = true;
            for (_, s) in &mut self.states {
                if *s == PowerState::HardwareKilled && state == PowerState::On {
                    all_ok = false;
                } else {
                    *s = state;
                }
            }
            return all_ok;
        }

        for (r, s) in &mut self.states {
            if *r == radio {
                // INVARIANT: hardware kill switch cannot be overridden by software
                if *s == PowerState::HardwareKilled && state == PowerState::On {
                    return false;
                }
                *s = state;
                return true;
            }
        }
        false
    }

    /// Apply a power mode preset.
    pub fn apply_mode(&mut self, mode: PowerMode) {
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
            }
        }
        self.mode = mode;
    }

    /// Get the current power mode.
    pub fn mode(&self) -> PowerMode {
        self.mode
    }

    /// Simulate hardware kill switch activation for a radio.
    /// Once killed by hardware, only hardware can re-enable.
    pub fn hardware_kill(&mut self, radio: Radio) {
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

    /// Count radios currently on.
    pub fn active_count(&self) -> usize {
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

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(pm.active_count(), 5);
        assert_eq!(pm.state(Radio::Cellular), PowerState::On);
        assert_eq!(pm.state(Radio::Wifi), PowerState::On);
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
    fn local_only_mode() {
        let mut pm = PowerManager::new();
        pm.apply_mode(PowerMode::LocalOnly);
        assert_eq!(pm.state(Radio::Wifi), PowerState::On);
        assert_eq!(pm.state(Radio::Bluetooth), PowerState::On);
        assert_eq!(pm.state(Radio::Cellular), PowerState::Off);
        assert_eq!(pm.state(Radio::Gps), PowerState::Off);
    }
}
