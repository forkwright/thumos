//! Panic trigger configuration and evaluation.
//!
//! A [`TriggerConfig`] maps one or more [`PanicTrigger`]s to [`WipeLevel`]s.
//! Call [`TriggerConfig::check_trigger`] with the current [`TriggerInput`] to
//! learn whether a wipe should be initiated.

use std::time::Duration;

use crate::targets::WipeLevel;

// ----- Types ----------------------------------------------------------------

/// A condition that activates a wipe.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum PanicTrigger {
    /// A specific key-code sequence held simultaneously.
    KeyCombo(Vec<u8>),
    /// A timer that fires after the given duration has elapsed.
    Timer(Duration),
    /// A signal or out-of-band remote command identified by number.
    Remote(u32),
}

/// The event or state snapshot passed to [`TriggerConfig::check_trigger`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum TriggerInput<'a> {
    /// Active key codes at the time of evaluation.
    Keys(&'a [u8]),
    /// Signal number received.
    Signal(u32),
    /// Time elapsed since the trigger was armed.
    Elapsed(Duration),
}

/// Maps [`PanicTrigger`]s to [`WipeLevel`]s.
///
/// The first matching trigger wins. Use [`TriggerConfig::add`] to build up the
/// configuration and [`TriggerConfig::check_trigger`] to evaluate it.
#[derive(Debug, Default)]
pub struct TriggerConfig {
    entries: Vec<(PanicTrigger, WipeLevel)>,
}

// ----- Impls: inherent ------------------------------------------------------

impl TriggerConfig {
    /// Create an empty configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `trigger` to activate `level`.
    pub fn add(&mut self, trigger: PanicTrigger, level: WipeLevel) {
        self.entries.push((trigger, level));
    }

    /// Evaluate `input` against all registered triggers.
    ///
    /// Returns the [`WipeLevel`] for the first matching trigger, or `None` if
    /// no trigger matches.
    #[must_use]
    pub fn check_trigger(&self, input: &TriggerInput<'_>) -> Option<WipeLevel> {
        for (trigger, level) in &self.entries {
            if trigger_matches(trigger, input) {
                return Some(*level);
            }
        }
        None
    }
}

// ----- Free functions -------------------------------------------------------

/// Returns `true` when `trigger` fires for the given `input`.
fn trigger_matches(trigger: &PanicTrigger, input: &TriggerInput<'_>) -> bool {
    match (trigger, input) {
        (PanicTrigger::KeyCombo(keys), TriggerInput::Keys(pressed)) => keys.as_slice() == *pressed,
        (PanicTrigger::Remote(expected), TriggerInput::Signal(received)) => expected == received,
        (PanicTrigger::Timer(threshold), TriggerInput::Elapsed(elapsed)) => elapsed >= threshold,
        // Mismatched variant pairs: no match.
        _ => false,
    }
}

// ----- Tests ----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_combo_fires_on_exact_match() {
        let mut cfg = TriggerConfig::new();
        cfg.add(PanicTrigger::KeyCombo(vec![1, 2, 3]), WipeLevel::Keys);
        let result = cfg.check_trigger(&TriggerInput::Keys(&[1, 2, 3]));
        assert_eq!(
            result,
            Some(WipeLevel::Keys),
            "exact key combo must trigger the configured level"
        );
    }

    #[test]
    fn key_combo_no_match_on_different_keys() {
        let mut cfg = TriggerConfig::new();
        cfg.add(PanicTrigger::KeyCombo(vec![1, 2, 3]), WipeLevel::Keys);
        let result = cfg.check_trigger(&TriggerInput::Keys(&[4, 5, 6]));
        assert!(result.is_none(), "wrong key combo must not trigger");
    }

    #[test]
    fn key_combo_no_match_on_partial_prefix() {
        let mut cfg = TriggerConfig::new();
        cfg.add(PanicTrigger::KeyCombo(vec![1, 2, 3]), WipeLevel::Keys);
        let result = cfg.check_trigger(&TriggerInput::Keys(&[1, 2]));
        assert!(result.is_none(), "partial key sequence must not trigger");
    }

    #[test]
    fn remote_signal_fires_on_matching_number() {
        let mut cfg = TriggerConfig::new();
        cfg.add(PanicTrigger::Remote(42), WipeLevel::Everything);
        let result = cfg.check_trigger(&TriggerInput::Signal(42));
        assert_eq!(
            result,
            Some(WipeLevel::Everything),
            "matching signal must trigger the configured level"
        );
    }

    #[test]
    fn remote_signal_no_match_on_different_number() {
        let mut cfg = TriggerConfig::new();
        cfg.add(PanicTrigger::Remote(42), WipeLevel::Everything);
        let result = cfg.check_trigger(&TriggerInput::Signal(99));
        assert!(result.is_none(), "wrong signal number must not trigger");
    }

    #[test]
    fn timer_fires_when_elapsed_meets_threshold() {
        let mut cfg = TriggerConfig::new();
        cfg.add(
            PanicTrigger::Timer(Duration::from_secs(30)),
            WipeLevel::UserData,
        );
        let result = cfg.check_trigger(&TriggerInput::Elapsed(Duration::from_secs(30)));
        assert_eq!(
            result,
            Some(WipeLevel::UserData),
            "elapsed == threshold must trigger"
        );
    }

    #[test]
    fn timer_fires_when_elapsed_exceeds_threshold() {
        let mut cfg = TriggerConfig::new();
        cfg.add(
            PanicTrigger::Timer(Duration::from_secs(30)),
            WipeLevel::UserData,
        );
        let result = cfg.check_trigger(&TriggerInput::Elapsed(Duration::from_secs(60)));
        assert_eq!(
            result,
            Some(WipeLevel::UserData),
            "elapsed > threshold must trigger"
        );
    }

    #[test]
    fn timer_no_trigger_when_elapsed_below_threshold() {
        let mut cfg = TriggerConfig::new();
        cfg.add(
            PanicTrigger::Timer(Duration::from_secs(30)),
            WipeLevel::UserData,
        );
        let result = cfg.check_trigger(&TriggerInput::Elapsed(Duration::from_secs(10)));
        assert!(result.is_none(), "elapsed < threshold must not trigger");
    }

    #[test]
    fn first_matching_trigger_wins() {
        let mut cfg = TriggerConfig::new();
        cfg.add(PanicTrigger::KeyCombo(vec![7, 8]), WipeLevel::Messages);
        cfg.add(PanicTrigger::KeyCombo(vec![7, 8]), WipeLevel::Everything);
        let result = cfg.check_trigger(&TriggerInput::Keys(&[7, 8]));
        assert_eq!(
            result,
            Some(WipeLevel::Messages),
            "first registered matching trigger must win"
        );
    }

    #[test]
    fn empty_config_never_triggers() {
        let cfg = TriggerConfig::new();
        assert!(
            cfg.check_trigger(&TriggerInput::Keys(&[1, 2, 3])).is_none(),
            "empty config must never trigger"
        );
    }

    #[test]
    fn mismatched_input_type_does_not_fire() {
        let mut cfg = TriggerConfig::new();
        cfg.add(PanicTrigger::KeyCombo(vec![1]), WipeLevel::Keys);
        // Supply a Signal input against a KeyCombo trigger — must not fire.
        let result = cfg.check_trigger(&TriggerInput::Signal(1));
        assert!(
            result.is_none(),
            "mismatched input type must not fire trigger"
        );
    }
}
