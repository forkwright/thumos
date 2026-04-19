//! Nous: AI entity capability map and management.
//!
//! νοῦς = "mind, intellect, reason." In Platonic philosophy, the
//! highest faculty of the soul — the part that apprehends truth
//! directly. For thumos: the intelligence layer that bridges Cody
//! with AI assistants (nous entities) via Matrix.
//!
//! # Architecture
//!
//! Each nous entity is a Matrix user on the conduwuit homeserver.
//! Entities have capability presets that gate what actions they can
//! propose and auto-execute on the device. The [`NousManager`]
//! tracks registered entities and the currently active one.
//!
//! # Capability model
//!
//! [`CapabilityPreset`] defines a trust hierarchy from `Off` (no
//! interaction) through `Autonomous` (full device authority). The
//! preset governs two permission gates:
//!
//! - **Propose**: can the entity suggest actions (via
//!   [`ActionProposal`][crate::ekphrasis::ActionProposal])?
//! - **Auto-execute**: can the entity's proposals be applied
//!   without explicit user confirmation?
//!
//! The hierarchy is intentionally coarse — fine-grained ACLs add
//! complexity that doesn't serve a single-user device. Cody picks
//! the preset per entity and can change it at any time.
//!
//! # Default entities
//!
//! Three entities are pre-configured from the brainstorm:
//!
//! - **Syn** (σύν, "together"): primary general-purpose assistant.
//!   Default active entity. Preset: `Advisor`.
//! - **Phrouros** (φρουρός, "guard"): security and field operations.
//!   Preset: `Observer` (elevated to `Agent` only when in the field).
//! - **Paideia** (παιδεία, "education"): learning and research.
//!   Preset: `Assistant`.
//!
//! # Matrix integration
//!
//! Each entity has a Matrix user ID (`@syn:thumos.lan`, etc.) on the
//! local conduwuit instance. Messages are exchanged via dedicated
//! Matrix rooms — one per entity. The [`crate::harmostes`] module
//! handles the CS API transport; nous only manages identity and
//! capability gating.

// WHY: nous created in Phase 09 Wave 8, full Matrix room wiring pending.
#![expect(
    dead_code,
    reason = "Nous created in Phase 09 Wave 8, Matrix room wiring pending"
)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of registered nous entities.
const MAX_ENTITIES: usize = 16;

/// Maximum length of an entity name in bytes.
const MAX_NAME_LEN: usize = 32;

/// Default Matrix homeserver domain for nous entities.
const DEFAULT_HOMESERVER: &str = "thumos.lan";

// ---------------------------------------------------------------------------
// Capability preset
// ---------------------------------------------------------------------------

/// Trust level for a nous entity, gating what actions it can take.
///
/// Ordered from least to most permissive. The ordering is significant:
/// higher presets subsume the capabilities of lower ones.
///
/// # Safety model
///
/// - `Off` and `Observer` cannot propose any actions.
/// - `Assistant` can propose but requires explicit confirmation for all.
/// - `Advisor` can auto-execute low-risk actions (timers, alarms, etc.)
///   but requires confirmation for high-risk (calls, messages, radio).
/// - `Agent` can auto-execute most actions except destructive ones
///   (wipe, mode changes, radio kill).
/// - `Autonomous` can do everything including destructive actions.
///   This is explicitly opt-in and should never be the default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[must_use]
#[non_exhaustive]
pub enum CapabilityPreset {
    /// No interaction — entity is registered but inactive.
    #[default]
    Off = 0,
    /// Read-only — entity can observe state but not propose actions.
    Observer = 1,
    /// Can propose actions; all require explicit user confirmation.
    Assistant = 2,
    /// Can propose actions; low-risk actions auto-execute.
    Advisor = 3,
    /// Can execute most actions without confirmation.
    Agent = 4,
    /// Full device authority. Dangerous; explicitly opted in.
    Autonomous = 5,
}

impl CapabilityPreset {
    /// Whether this preset allows the entity to propose actions.
    ///
    /// `Off` and `Observer` cannot propose; all others can.
    #[must_use]
    pub(crate) const fn can_propose(self) -> bool {
        matches!(
            self,
            Self::Assistant | Self::Advisor | Self::Agent | Self::Autonomous
        )
    }

    /// Whether this preset allows auto-execution of low-risk actions.
    ///
    /// Only `Advisor`, `Agent`, and `Autonomous` can auto-execute.
    /// `Assistant` always requires confirmation.
    #[must_use]
    pub(crate) const fn can_auto_execute(self) -> bool {
        matches!(self, Self::Advisor | Self::Agent | Self::Autonomous)
    }

    /// Whether this preset allows auto-execution of high-risk actions.
    ///
    /// Only `Agent` and `Autonomous` can auto-execute high-risk actions
    /// (calls, messages, radio toggles).
    #[must_use]
    pub(crate) const fn can_auto_execute_high_risk(self) -> bool {
        matches!(self, Self::Agent | Self::Autonomous)
    }

    /// Whether this preset allows destructive actions (wipe, panic mode).
    ///
    /// Only `Autonomous` can execute destructive actions.
    #[must_use]
    pub(crate) const fn can_execute_destructive(self) -> bool {
        matches!(self, Self::Autonomous)
    }

    /// Return the next preset in the hierarchy (wraps around).
    ///
    /// Used for cycling through presets in the settings UI.
    pub(crate) const fn next(self) -> Self {
        match self {
            Self::Off => Self::Observer,
            Self::Observer => Self::Assistant,
            Self::Assistant => Self::Advisor,
            Self::Advisor => Self::Agent,
            Self::Agent => Self::Autonomous,
            Self::Autonomous => Self::Off,
        }
    }

    /// Return the previous preset in the hierarchy (wraps around).
    pub(crate) const fn prev(self) -> Self {
        match self {
            Self::Off => Self::Autonomous,
            Self::Observer => Self::Off,
            Self::Assistant => Self::Observer,
            Self::Advisor => Self::Assistant,
            Self::Agent => Self::Advisor,
            Self::Autonomous => Self::Agent,
        }
    }

    /// Human-readable label for the preset.
    #[must_use]
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Off => "OFF",
            Self::Observer => "OBSERVER",
            Self::Assistant => "ASSISTANT",
            Self::Advisor => "ADVISOR",
            Self::Agent => "AGENT",
            Self::Autonomous => "AUTONOMOUS",
        }
    }

    /// Short description of what this preset allows.
    #[must_use]
    pub(crate) const fn description(self) -> &'static str {
        match self {
            Self::Off => "No interaction",
            Self::Observer => "Read-only, no actions",
            Self::Assistant => "Propose actions with confirmation",
            Self::Advisor => "Auto-execute low-risk actions",
            Self::Agent => "Execute most actions",
            Self::Autonomous => "Full authority (dangerous)",
        }
    }

    /// Numeric trust level (0-5) for comparison and serialization.
    #[must_use]
    pub(crate) const fn level(self) -> u8 {
        self as u8
    }

    /// Construct a preset from a numeric trust level.
    ///
    /// Returns `None` for values outside 0-5.
    #[must_use]
    pub(crate) const fn from_level(level: u8) -> Option<Self> {
        match level {
            0 => Some(Self::Off),
            1 => Some(Self::Observer),
            2 => Some(Self::Assistant),
            3 => Some(Self::Advisor),
            4 => Some(Self::Agent),
            5 => Some(Self::Autonomous),
            _ => None,
        }
    }
}

impl fmt::Display for CapabilityPreset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}


// ---------------------------------------------------------------------------
// Nous entity
// ---------------------------------------------------------------------------

/// Error type for nous operations.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
#[non_exhaustive]
pub enum NousError {
    /// The entity name exceeds [`MAX_NAME_LEN`].
    NameTooLong {
        /// The length that was attempted.
        len: usize,
    },
    /// The entity list is full (at [`MAX_ENTITIES`]).
    TooManyEntities,
    /// The specified entity index is out of bounds.
    InvalidIndex {
        /// The index that was requested.
        index: usize,
        /// The number of registered entities.
        count: usize,
    },
    /// An entity with this name already exists.
    DuplicateName,
    /// The entity cannot perform this action at its current preset.
    InsufficientCapability {
        /// The entity name.
        entity: &'static str,
        /// The required preset level.
        required: &'static str,
        /// The entity's current preset level.
        current: &'static str,
    },
}

impl fmt::Display for NousError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NameTooLong { len } => {
                write!(f, "entity name too long ({len} bytes, max {MAX_NAME_LEN})")
            }
            Self::TooManyEntities => {
                write!(f, "too many entities (max {MAX_ENTITIES})")
            }
            Self::InvalidIndex { index, count } => {
                write!(f, "entity index {index} out of bounds (have {count})")
            }
            Self::DuplicateName => write!(f, "entity with this name already exists"),
            Self::InsufficientCapability {
                entity,
                required,
                current,
            } => {
                write!(
                    f,
                    "{entity} requires {required} capability, has {current}"
                )
            }
        }
    }
}

/// A nous entity — an AI agent Cody interacts with via Matrix.
///
/// Each entity has a fixed-size name buffer (for no-heap contexts),
/// a Matrix user ID (on the conduwuit homeserver), and a capability
/// preset that gates its actions on the device.
#[derive(Debug, Clone)]
#[must_use]
pub struct NousEntity {
    /// Entity name stored in a fixed-size buffer.
    pub name: [u8; MAX_NAME_LEN],
    /// Number of valid bytes in `name`.
    pub name_len: u8,
    /// Matrix user ID (e.g., "@syn:thumos.lan").
    pub matrix_id: String,
    /// Capability preset governing what this entity can do.
    pub capability_preset: CapabilityPreset,
}

impl NousEntity {
    /// Create a new nous entity.
    ///
    /// # Errors
    ///
    /// Returns [`NousError::NameTooLong`] if `name` exceeds [`MAX_NAME_LEN`].
    pub(crate) fn new(
        name: &str,
        matrix_id: String,
        preset: CapabilityPreset,
    ) -> Result<Self, NousError> {
        let name_bytes = name.as_bytes();
        if name_bytes.len() > MAX_NAME_LEN {
            return Err(NousError::NameTooLong {
                len: name_bytes.len(),
            });
        }

        let mut name_buf = [0u8; MAX_NAME_LEN];
        name_buf[..name_bytes.len()].copy_from_slice(name_bytes);

        Ok(Self {
            name: name_buf,
            name_len: name_bytes.len() as u8,
            matrix_id,
            capability_preset: preset,
        })
    }

    /// Return the entity name as a string slice.
    #[must_use]
    pub(crate) fn name_str(&self) -> &str {
        // SAFETY: name is always written from a valid &str in new().
        // name_len is set from the source string's byte length and
        // never modified afterward, so the slice is always valid UTF-8.
        core::str::from_utf8(&self.name[..self.name_len as usize]).unwrap_or("?")
    }

    /// Whether this entity can propose actions at its current preset.
    #[must_use]
    pub(crate) const fn can_propose(&self) -> bool {
        self.capability_preset.can_propose()
    }

    /// Whether this entity can auto-execute low-risk actions.
    #[must_use]
    pub(crate) const fn can_auto_execute(&self) -> bool {
        self.capability_preset.can_auto_execute()
    }

    /// Return the short display label for this entity's capability level.
    #[must_use]
    pub(crate) const fn capability_label(&self) -> &'static str {
        self.capability_preset.label()
    }
}

impl fmt::Display for NousEntity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} ({}) [{}]",
            self.name_str(),
            self.matrix_id,
            self.capability_preset
        )
    }
}

impl PartialEq for NousEntity {
    fn eq(&self, other: &Self) -> bool {
        self.name[..self.name_len as usize] == other.name[..other.name_len as usize]
            && self.matrix_id == other.matrix_id
            && self.capability_preset == other.capability_preset
    }
}

impl Eq for NousEntity {}

// ---------------------------------------------------------------------------
// Default entities
// ---------------------------------------------------------------------------

/// Create the default Syn entity (primary general-purpose assistant).
pub(crate) fn default_syn() -> NousEntity {
    // Syn is always valid — name is 3 bytes, well under MAX_NAME_LEN.
    NousEntity::new(
        "Syn",
        String::from("@syn:thumos.lan"),
        CapabilityPreset::Advisor,
    )
    .unwrap_or_else(|_| {
        // This path is unreachable for "Syn" but satisfies no-panic contract.
        let mut name = [0u8; MAX_NAME_LEN];
        name[0] = b'?';
        NousEntity {
            name,
            name_len: 1,
            matrix_id: String::from("@syn:thumos.lan"),
            capability_preset: CapabilityPreset::Off,
        }
    })
}

/// Create the default Phrouros entity (security/field operations).
pub(crate) fn default_phrouros() -> NousEntity {
    NousEntity::new(
        "Phrouros",
        String::from("@phrouros:thumos.lan"),
        CapabilityPreset::Observer,
    )
    .unwrap_or_else(|_| {
        let mut name = [0u8; MAX_NAME_LEN];
        name[0] = b'?';
        NousEntity {
            name,
            name_len: 1,
            matrix_id: String::from("@phrouros:thumos.lan"),
            capability_preset: CapabilityPreset::Off,
        }
    })
}

/// Create the default Paideia entity (learning/research).
pub(crate) fn default_paideia() -> NousEntity {
    NousEntity::new(
        "Paideia",
        String::from("@paideia:thumos.lan"),
        CapabilityPreset::Assistant,
    )
    .unwrap_or_else(|_| {
        let mut name = [0u8; MAX_NAME_LEN];
        name[0] = b'?';
        NousEntity {
            name,
            name_len: 1,
            matrix_id: String::from("@paideia:thumos.lan"),
            capability_preset: CapabilityPreset::Off,
        }
    })
}

// ---------------------------------------------------------------------------
// Nous manager
// ---------------------------------------------------------------------------

/// Manages registered nous entities and tracks the active one.
///
/// The manager pre-populates with the three default entities (Syn,
/// Phrouros, Paideia) and allows adding custom entities up to
/// [`MAX_ENTITIES`].
pub(crate) struct NousManager {
    /// Registered nous entities.
    entities: Vec<NousEntity>,
    /// Index of the currently active entity.
    active_entity: usize,
}

impl NousManager {
    /// Create a new manager with the three default entities.
    ///
    /// Syn is the default active entity (index 0).
    #[must_use]
    pub(crate) fn new() -> Self {
        let entities = alloc::vec![
            default_syn(),
            default_phrouros(),
            default_paideia(),
        ];
        Self {
            entities,
            active_entity: 0,
        }
    }

    /// Create an empty manager with no entities.
    ///
    /// Useful for testing or when defaults are not wanted.
    #[must_use]
    pub(crate) fn empty() -> Self {
        Self {
            entities: Vec::new(),
            active_entity: 0,
        }
    }

    /// Return a reference to the currently active entity.
    ///
    /// Returns `None` if no entities are registered.
    #[must_use]
    pub(crate) fn active(&self) -> Option<&NousEntity> {
        self.entities.get(self.active_entity)
    }

    /// Return a mutable reference to the currently active entity.
    ///
    /// Returns `None` if no entities are registered.
    pub(crate) fn active_mut(&mut self) -> Option<&mut NousEntity> {
        self.entities.get_mut(self.active_entity)
    }

    /// Return the index of the currently active entity.
    #[must_use]
    pub(crate) fn active_index(&self) -> usize {
        self.active_entity
    }

    /// Return the number of registered entities.
    #[must_use]
    pub(crate) fn entity_count(&self) -> usize {
        self.entities.len()
    }

    /// Return a reference to an entity by index.
    ///
    /// Returns `None` if the index is out of bounds.
    #[must_use]
    pub(crate) fn entity(&self, index: usize) -> Option<&NousEntity> {
        self.entities.get(index)
    }

    /// Return a slice of all registered entities.
    pub(crate) fn entities(&self) -> &[NousEntity] {
        &self.entities
    }

    /// Switch the active entity to the given index.
    ///
    /// # Errors
    ///
    /// Returns [`NousError::InvalidIndex`] if the index is out of bounds.
    pub(crate) fn switch(&mut self, index: usize) -> Result<(), NousError> {
        if index >= self.entities.len() {
            return Err(NousError::InvalidIndex {
                index,
                count: self.entities.len(),
            });
        }
        self.active_entity = index;
        Ok(())
    }

    /// Cycle to the next entity (wraps around).
    ///
    /// Does nothing if no entities are registered.
    pub(crate) fn cycle_next(&mut self) {
        if !self.entities.is_empty() {
            self.active_entity = (self.active_entity + 1) % self.entities.len();
        }
    }

    /// Add a new entity to the manager.
    ///
    /// # Errors
    ///
    /// - [`NousError::TooManyEntities`] if the entity list is full.
    /// - [`NousError::DuplicateName`] if an entity with the same name exists.
    pub(crate) fn add_entity(&mut self, entity: NousEntity) -> Result<(), NousError> {
        if self.entities.len() >= MAX_ENTITIES {
            return Err(NousError::TooManyEntities);
        }

        // Check for duplicate name.
        let new_name = entity.name_str();
        for existing in &self.entities {
            if existing.name_str() == new_name {
                return Err(NousError::DuplicateName);
            }
        }

        self.entities.push(entity);
        Ok(())
    }

    /// Remove an entity by index.
    ///
    /// Adjusts the active entity index if needed. Cannot remove the last
    /// entity (the manager must always have at least one, or be empty).
    ///
    /// # Errors
    ///
    /// Returns [`NousError::InvalidIndex`] if the index is out of bounds.
    pub(crate) fn remove_entity(&mut self, index: usize) -> Result<NousEntity, NousError> {
        if index >= self.entities.len() {
            return Err(NousError::InvalidIndex {
                index,
                count: self.entities.len(),
            });
        }

        let removed = self.entities.remove(index);

        // Adjust active entity if needed.
        if self.entities.is_empty() {
            self.active_entity = 0;
        } else if self.active_entity >= self.entities.len() {
            self.active_entity = self.entities.len() - 1;
        } else if self.active_entity > index {
            self.active_entity -= 1;
        }

        Ok(removed)
    }

    /// Set the capability preset for an entity by index.
    ///
    /// # Errors
    ///
    /// Returns [`NousError::InvalidIndex`] if the index is out of bounds.
    pub(crate) fn set_preset(
        &mut self,
        index: usize,
        preset: CapabilityPreset,
    ) -> Result<(), NousError> {
        match self.entities.get_mut(index) {
            Some(entity) => {
                entity.capability_preset = preset;
                Ok(())
            }
            None => Err(NousError::InvalidIndex {
                index,
                count: self.entities.len(),
            }),
        }
    }

    /// Find an entity by name.
    ///
    /// Returns the index and a reference to the entity, or `None`.
    #[must_use]
    pub(crate) fn find_by_name(&self, name: &str) -> Option<(usize, &NousEntity)> {
        self.entities
            .iter()
            .enumerate()
            .find(|(_, e)| e.name_str() == name)
    }

    /// Find an entity by Matrix ID.
    ///
    /// Returns the index and a reference to the entity, or `None`.
    #[must_use]
    pub(crate) fn find_by_matrix_id(&self, matrix_id: &str) -> Option<(usize, &NousEntity)> {
        self.entities
            .iter()
            .enumerate()
            .find(|(_, e)| e.matrix_id == matrix_id)
    }

    /// Check whether the active entity can propose actions.
    ///
    /// Returns `false` if no entities are registered.
    #[must_use]
    pub(crate) fn active_can_propose(&self) -> bool {
        self.active()
            .is_some_and(|e| e.capability_preset.can_propose())
    }

    /// Check whether the active entity can auto-execute actions.
    ///
    /// Returns `false` if no entities are registered.
    #[must_use]
    pub(crate) fn active_can_auto_execute(&self) -> bool {
        self.active()
            .is_some_and(|e| e.capability_preset.can_auto_execute())
    }
}

impl fmt::Display for NousManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "NousManager({} entities, active={})",
            self.entities.len(),
            self.active()
                .map_or("none", |e| e.name_str())
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- CapabilityPreset tests ---

    #[test]
    fn preset_ordering() {
        assert!(CapabilityPreset::Off < CapabilityPreset::Observer);
        assert!(CapabilityPreset::Observer < CapabilityPreset::Assistant);
        assert!(CapabilityPreset::Assistant < CapabilityPreset::Advisor);
        assert!(CapabilityPreset::Advisor < CapabilityPreset::Agent);
        assert!(CapabilityPreset::Agent < CapabilityPreset::Autonomous);
    }

    #[test]
    fn preset_level_roundtrip() {
        for level in 0..=5u8 {
            let preset = CapabilityPreset::from_level(level);
            assert!(preset.is_some(), "level {level} must parse");
            assert_eq!(
                preset.map(|p| p.level()),
                Some(level),
                "level roundtrip for {level}"
            );
        }
        assert!(CapabilityPreset::from_level(6).is_none());
        assert!(CapabilityPreset::from_level(255).is_none());
    }

    #[test]
    fn preset_propose_gating() {
        assert!(
            !CapabilityPreset::Off.can_propose(),
            "Off must not propose"
        );
        assert!(
            !CapabilityPreset::Observer.can_propose(),
            "Observer must not propose"
        );
        assert!(
            CapabilityPreset::Assistant.can_propose(),
            "Assistant must propose"
        );
        assert!(
            CapabilityPreset::Advisor.can_propose(),
            "Advisor must propose"
        );
        assert!(
            CapabilityPreset::Agent.can_propose(),
            "Agent must propose"
        );
        assert!(
            CapabilityPreset::Autonomous.can_propose(),
            "Autonomous must propose"
        );
    }

    #[test]
    fn preset_auto_execute_gating() {
        assert!(
            !CapabilityPreset::Off.can_auto_execute(),
            "Off must not auto-execute"
        );
        assert!(
            !CapabilityPreset::Observer.can_auto_execute(),
            "Observer must not auto-execute"
        );
        assert!(
            !CapabilityPreset::Assistant.can_auto_execute(),
            "Assistant must not auto-execute"
        );
        assert!(
            CapabilityPreset::Advisor.can_auto_execute(),
            "Advisor must auto-execute"
        );
        assert!(
            CapabilityPreset::Agent.can_auto_execute(),
            "Agent must auto-execute"
        );
        assert!(
            CapabilityPreset::Autonomous.can_auto_execute(),
            "Autonomous must auto-execute"
        );
    }

    #[test]
    fn preset_high_risk_gating() {
        assert!(!CapabilityPreset::Off.can_auto_execute_high_risk());
        assert!(!CapabilityPreset::Observer.can_auto_execute_high_risk());
        assert!(!CapabilityPreset::Assistant.can_auto_execute_high_risk());
        assert!(!CapabilityPreset::Advisor.can_auto_execute_high_risk());
        assert!(CapabilityPreset::Agent.can_auto_execute_high_risk());
        assert!(CapabilityPreset::Autonomous.can_auto_execute_high_risk());
    }

    #[test]
    fn preset_destructive_gating() {
        assert!(!CapabilityPreset::Off.can_execute_destructive());
        assert!(!CapabilityPreset::Observer.can_execute_destructive());
        assert!(!CapabilityPreset::Assistant.can_execute_destructive());
        assert!(!CapabilityPreset::Advisor.can_execute_destructive());
        assert!(!CapabilityPreset::Agent.can_execute_destructive());
        assert!(CapabilityPreset::Autonomous.can_execute_destructive());
    }

    #[test]
    fn preset_next_cycles() {
        let start = CapabilityPreset::Off;
        let mut current = start;
        let mut seen = alloc::vec::Vec::new();
        for _ in 0..6 {
            seen.push(current);
            current = current.next();
        }
        assert_eq!(current, start, "next must wrap around to Off");
        assert_eq!(seen.len(), 6, "must visit all 6 presets");
    }

    #[test]
    fn preset_prev_cycles() {
        let start = CapabilityPreset::Off;
        let mut current = start;
        let mut seen = alloc::vec::Vec::new();
        for _ in 0..6 {
            seen.push(current);
            current = current.prev();
        }
        assert_eq!(current, start, "prev must wrap around to Off");
    }

    #[test]
    fn preset_display() {
        assert_eq!(
            alloc::format!("{}", CapabilityPreset::Advisor),
            "ADVISOR"
        );
        assert_eq!(
            alloc::format!("{}", CapabilityPreset::Autonomous),
            "AUTONOMOUS"
        );
    }

    #[test]
    fn preset_default_is_off() {
        assert_eq!(CapabilityPreset::default(), CapabilityPreset::Off);
    }

    // --- NousEntity tests ---

    #[test]
    fn entity_creation() {
        let entity = NousEntity::new(
            "TestBot",
            String::from("@testbot:thumos.lan"),
            CapabilityPreset::Assistant,
        );
        assert!(entity.is_ok());
        let entity = entity.unwrap_or_else(|_| unreachable!());
        assert_eq!(entity.name_str(), "TestBot");
        assert_eq!(entity.matrix_id, "@testbot:thumos.lan");
        assert_eq!(entity.capability_preset, CapabilityPreset::Assistant);
    }

    #[test]
    fn entity_name_too_long() {
        let long_name = "a]".repeat(20); // 40 bytes > MAX_NAME_LEN (32)
        let result = NousEntity::new(
            &long_name,
            String::from("@long:thumos.lan"),
            CapabilityPreset::Off,
        );
        assert!(result.is_err());
        match result {
            Err(NousError::NameTooLong { len }) => {
                assert!(len > MAX_NAME_LEN);
            }
            _ => panic!("expected NameTooLong error"),
        }
    }

    #[test]
    fn entity_max_name_length() {
        // Exactly MAX_NAME_LEN bytes should succeed.
        let name: String = core::iter::repeat_n('x', MAX_NAME_LEN).collect();
        let result = NousEntity::new(
            &name,
            String::from("@max:thumos.lan"),
            CapabilityPreset::Off,
        );
        assert!(result.is_ok(), "exactly MAX_NAME_LEN must succeed");
    }

    #[test]
    fn entity_propose_reflects_preset() {
        let observer = NousEntity::new(
            "Obs",
            String::from("@obs:thumos.lan"),
            CapabilityPreset::Observer,
        )
        .unwrap_or_else(|_| unreachable!());
        assert!(!observer.can_propose());

        let assistant = NousEntity::new(
            "Ast",
            String::from("@ast:thumos.lan"),
            CapabilityPreset::Assistant,
        )
        .unwrap_or_else(|_| unreachable!());
        assert!(assistant.can_propose());
    }

    #[test]
    fn entity_display() {
        let entity = default_syn();
        let display = alloc::format!("{entity}");
        assert!(display.contains("Syn"), "display must contain name");
        assert!(
            display.contains("@syn:thumos.lan"),
            "display must contain matrix id"
        );
        assert!(
            display.contains("ADVISOR"),
            "display must contain preset"
        );
    }

    #[test]
    fn entity_equality() {
        let a = default_syn();
        let b = default_syn();
        assert_eq!(a, b, "identical entities must be equal");

        let c = default_phrouros();
        assert_ne!(a, c, "different entities must not be equal");
    }

    // --- Default entity tests ---

    #[test]
    fn default_entities_valid() {
        let syn = default_syn();
        assert_eq!(syn.name_str(), "Syn");
        assert_eq!(syn.capability_preset, CapabilityPreset::Advisor);
        assert!(syn.can_propose());
        assert!(syn.can_auto_execute());

        let phrouros = default_phrouros();
        assert_eq!(phrouros.name_str(), "Phrouros");
        assert_eq!(phrouros.capability_preset, CapabilityPreset::Observer);
        assert!(!phrouros.can_propose());

        let paideia = default_paideia();
        assert_eq!(paideia.name_str(), "Paideia");
        assert_eq!(paideia.capability_preset, CapabilityPreset::Assistant);
        assert!(paideia.can_propose());
        assert!(!paideia.can_auto_execute());
    }

    // --- NousManager tests ---

    #[test]
    fn manager_defaults() {
        let mgr = NousManager::new();
        assert_eq!(mgr.entity_count(), 3, "must have 3 default entities");
        assert_eq!(mgr.active_index(), 0, "Syn must be active by default");

        let active = mgr.active();
        assert!(active.is_some());
        assert_eq!(
            active.map(|e| e.name_str()),
            Some("Syn"),
            "active must be Syn"
        );
    }

    #[test]
    fn manager_empty() {
        let mgr = NousManager::empty();
        assert_eq!(mgr.entity_count(), 0);
        assert!(mgr.active().is_none());
        assert!(!mgr.active_can_propose());
        assert!(!mgr.active_can_auto_execute());
    }

    #[test]
    fn manager_switch() {
        let mut mgr = NousManager::new();
        assert!(mgr.switch(1).is_ok(), "switch to index 1 must succeed");
        assert_eq!(
            mgr.active().map(|e| e.name_str()),
            Some("Phrouros"),
            "active must be Phrouros after switch(1)"
        );

        assert!(mgr.switch(2).is_ok());
        assert_eq!(
            mgr.active().map(|e| e.name_str()),
            Some("Paideia"),
        );

        // Out of bounds.
        let err = mgr.switch(99);
        assert!(err.is_err(), "switch to invalid index must fail");
        match err {
            Err(NousError::InvalidIndex { index, count }) => {
                assert_eq!(index, 99);
                assert_eq!(count, 3);
            }
            _ => panic!("expected InvalidIndex error"),
        }
    }

    #[test]
    fn manager_cycle_next() {
        let mut mgr = NousManager::new();
        assert_eq!(mgr.active_index(), 0);

        mgr.cycle_next();
        assert_eq!(mgr.active_index(), 1);

        mgr.cycle_next();
        assert_eq!(mgr.active_index(), 2);

        mgr.cycle_next();
        assert_eq!(mgr.active_index(), 0, "must wrap around");
    }

    #[test]
    fn manager_cycle_next_empty() {
        let mut mgr = NousManager::empty();
        mgr.cycle_next(); // Must not panic.
        assert_eq!(mgr.active_index(), 0);
    }

    #[test]
    fn manager_add_entity() {
        let mut mgr = NousManager::new();
        let custom = NousEntity::new(
            "Custom",
            String::from("@custom:thumos.lan"),
            CapabilityPreset::Agent,
        )
        .unwrap_or_else(|_| unreachable!());

        assert!(mgr.add_entity(custom).is_ok());
        assert_eq!(mgr.entity_count(), 4);
    }

    #[test]
    fn manager_add_duplicate_name() {
        let mut mgr = NousManager::new();
        let dup = NousEntity::new(
            "Syn",
            String::from("@syn2:thumos.lan"),
            CapabilityPreset::Off,
        )
        .unwrap_or_else(|_| unreachable!());

        let err = mgr.add_entity(dup);
        assert!(matches!(err, Err(NousError::DuplicateName)));
    }

    #[test]
    fn manager_remove_entity() {
        let mut mgr = NousManager::new();
        assert_eq!(mgr.entity_count(), 3);

        let removed = mgr.remove_entity(1);
        assert!(removed.is_ok());
        assert_eq!(
            removed.map(|e| String::from(e.name_str())),
            Ok(String::from("Phrouros")),
        );
        assert_eq!(mgr.entity_count(), 2);
    }

    #[test]
    fn manager_remove_active_adjusts() {
        let mut mgr = NousManager::new();
        // Switch to last entity (index 2 = Paideia).
        mgr.switch(2).unwrap_or_else(|_| unreachable!());
        assert_eq!(mgr.active_index(), 2);

        // Remove entity at index 2.
        let _ = mgr.remove_entity(2);
        assert!(
            mgr.active_index() < mgr.entity_count(),
            "active index must be clamped after removal"
        );
    }

    #[test]
    fn manager_remove_invalid_index() {
        let mut mgr = NousManager::new();
        let err = mgr.remove_entity(99);
        assert!(matches!(
            err,
            Err(NousError::InvalidIndex { index: 99, .. })
        ));
    }

    #[test]
    fn manager_set_preset() {
        let mut mgr = NousManager::new();
        assert!(mgr.set_preset(0, CapabilityPreset::Agent).is_ok());
        assert_eq!(
            mgr.entity(0).map(|e| e.capability_preset),
            Some(CapabilityPreset::Agent),
        );
    }

    #[test]
    fn manager_set_preset_invalid_index() {
        let mut mgr = NousManager::new();
        let err = mgr.set_preset(99, CapabilityPreset::Off);
        assert!(matches!(
            err,
            Err(NousError::InvalidIndex { index: 99, .. })
        ));
    }

    #[test]
    fn manager_find_by_name() {
        let mgr = NousManager::new();
        let result = mgr.find_by_name("Phrouros");
        assert!(result.is_some());
        assert_eq!(result.map(|(i, _)| i), Some(1));
        assert!(mgr.find_by_name("Nonexistent").is_none());
    }

    #[test]
    fn manager_find_by_matrix_id() {
        let mgr = NousManager::new();
        let result = mgr.find_by_matrix_id("@paideia:thumos.lan");
        assert!(result.is_some());
        assert_eq!(result.map(|(i, _)| i), Some(2));
        assert!(mgr.find_by_matrix_id("@unknown:thumos.lan").is_none());
    }

    #[test]
    fn manager_active_can_propose() {
        let mgr = NousManager::new();
        // Syn is Advisor, which can propose.
        assert!(mgr.active_can_propose());
    }

    #[test]
    fn manager_active_can_auto_execute() {
        let mgr = NousManager::new();
        // Syn is Advisor, which can auto-execute low-risk.
        assert!(mgr.active_can_auto_execute());
    }

    #[test]
    fn manager_active_observer_cannot_propose() {
        let mut mgr = NousManager::new();
        // Switch to Phrouros (Observer).
        mgr.switch(1).unwrap_or_else(|_| unreachable!());
        assert!(!mgr.active_can_propose());
        assert!(!mgr.active_can_auto_execute());
    }

    #[test]
    fn manager_display() {
        let mgr = NousManager::new();
        let display = alloc::format!("{mgr}");
        assert!(display.contains("3 entities"));
        assert!(display.contains("Syn"));
    }

    #[test]
    fn nous_error_display() {
        let err = NousError::NameTooLong { len: 64 };
        let display = alloc::format!("{err}");
        assert!(display.contains("64"));
        assert!(display.contains("32"));

        let err = NousError::TooManyEntities;
        let display = alloc::format!("{err}");
        assert!(display.contains("16"));

        let err = NousError::InvalidIndex {
            index: 5,
            count: 3,
        };
        let display = alloc::format!("{err}");
        assert!(display.contains("5"));
        assert!(display.contains("3"));

        let err = NousError::DuplicateName;
        assert!(!alloc::format!("{err}").is_empty());

        let err = NousError::InsufficientCapability {
            entity: "Phrouros",
            required: "ASSISTANT",
            current: "OBSERVER",
        };
        let display = alloc::format!("{err}");
        assert!(display.contains("Phrouros"));
        assert!(display.contains("ASSISTANT"));
        assert!(display.contains("OBSERVER"));
    }
}
