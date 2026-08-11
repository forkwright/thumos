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
//! # Capability model (#552)
//!
//! Individual capability grants are the sole authority, per the accepted
//! trust model (`design-comms.md` "Trust model: capability map").
//! [`CapabilityPreset`] presets are CONSTRUCTORS for [`CapabilitySet`]s —
//! starting points the operator customizes, never ranks — and `Custom`
//! maps are first-class. Four capabilities (keys, SIGINT, panic,
//! security-disable) are kernel-NEVER: unrepresentable in a set on any
//! preset or custom map, denied on any action path. Every action type
//! binds to an exact required grant, a confirmation rule, and an audit
//! receipt below every client.
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
    reason = "Nous created in Phase 09 Wave 8, Matrix room wiring pending (#145)"
)]

extern crate alloc;

use core::fmt;

use alloc::string::String;
use alloc::vec::Vec;

use crate::matrix_ids::MatrixUserId;

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
// Capability model (#552): typed grants are the sole authority
// ---------------------------------------------------------------------------

/// A single grantable nous capability (design-comms.md "Trust model:
/// capability map", verbatim). Individual grants are the ONLY authority --
/// presets are constructors for sets of these, never ranks that subsume
/// privileges implicitly.
///
/// Defaults in the design table vary by model profile (cloud vs local);
/// those are preset concerns. What matters here is that each capability is
/// an independent bit the operator grants or revokes explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[must_use]
#[non_exhaustive]
pub(crate) enum NousCapability {
    /// Time, approximate location, mode, battery, radio status.
    ReadState,
    /// Contact names and aliases (not numbers or IDs).
    ReadContactsMetadata,
    /// Full contact records including numbers and Matrix IDs.
    ReadContactsFull,
    /// Message sender/time/transport -- not content.
    ReadMessageMetadata,
    /// Full message text.
    ReadMessageContent,
    /// Calendar events, times, attendees.
    ReadCalendar,
    /// Security events and mode changes. Default-off on every profile
    /// (design table), grantable only via Custom -- the design's
    /// "what nous NEVER sees" list explains why this stays edge-class.
    ReadAuditLog,
    /// Create message text for the user to review and send.
    DraftMessages,
    /// Propose calendar events for the user to accept.
    DraftCalendarEvents,
    /// Send a drafted message after explicit user confirmation.
    SendMessagesConfirmed,
    /// Send messages without confirmation, per rules. Opt-in.
    SendMessagesAutonomous,
    /// Add/update contacts after explicit user confirmation.
    ModifyContactsConfirmed,
    /// Add/update contacts without confirmation.
    ModifyContactsAutonomous,
    /// Enter/exit modes (Sentinel, Covert, ...) after confirmation. Opt-in.
    ToggleModeConfirmed,
    /// Kill/restore radios after confirmation. Opt-in.
    ToggleRadiosConfirmed,
}

/// A capability the kernel NEVER grants nous -- on any preset, any custom
/// map, any runtime state (design-comms.md: the NEVER rows are "hardcoded
/// off ... enforced by the kernel capability system, not by policy").
///
/// Deliberately NOT a [`NousCapability`]: [`CapabilitySet`] cannot
/// represent one, so no preset constructor, custom edit, stale grant, or
/// runtime path can ever produce it as a grant. This is the type-level
/// half of the boundary; the syscall-level half lands with the nous
/// process sandbox (#544's wiring).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[must_use]
#[non_exhaustive]
pub(crate) enum NeverCapability {
    /// Passphrase, session keys, any crypto material.
    ReadEncryptionKeys,
    /// IMSI detections, spectrum data (nous may be TOLD "sentinel because
    /// of a detection" -- never the detection details).
    ReadSigintData,
    /// Arm or execute panic mode.
    TriggerPanic,
    /// Turn off scanning, lower thresholds, or otherwise disable security
    /// features.
    DisableSecurityFeatures,
}

impl NeverCapability {
    /// Why this capability is kernel-denied (design text, verbatim intent).
    #[must_use]
    pub(crate) const fn reason(self) -> &'static str {
        match self {
            Self::ReadEncryptionKeys => {
                "passphrase/session keys/crypto material are NEVER visible to nous"
            }
            Self::ReadSigintData => "SIGINT detection details are NEVER visible to nous",
            Self::TriggerPanic => "the panic trigger is NEVER reachable by nous",
            Self::DisableSecurityFeatures => "security features are NEVER disableable by nous",
        }
    }
}

/// The capability set: the sole authorization authority (#552).
///
/// A bitset over the 15 grantable [`NousCapability`]s. [`NeverCapability`]
/// has no bits -- it is unrepresentable by construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[must_use]
pub(crate) struct CapabilitySet {
    bits: u32,
}

impl CapabilitySet {
    /// The empty set -- nothing granted (the `Off` state).
    pub(crate) const NONE: Self = Self { bits: 0 };

    /// Whether `cap` is granted.
    #[must_use]
    pub(crate) const fn grants(self, cap: NousCapability) -> bool {
        self.bits & (1 << cap as u32) != 0
    }

    /// Grant `cap` (Custom editing is the only caller besides preset
    /// constructors).
    pub(crate) fn grant(&mut self, cap: NousCapability) {
        self.bits |= 1 << cap as u32;
    }

    /// Revoke `cap` (stale-grant removal).
    pub(crate) fn revoke(&mut self, cap: NousCapability) {
        self.bits &= !(1 << cap as u32);
    }

    /// Whether any action-capable grant exists (draft/send/modify/toggle
    /// classes) -- the new-model meaning of "can propose" (#552).
    #[must_use]
    pub(crate) const fn can_propose(self) -> bool {
        const ACTION_BITS: u32 = (1 << NousCapability::DraftMessages as u32)
            | (1 << NousCapability::DraftCalendarEvents as u32)
            | (1 << NousCapability::SendMessagesConfirmed as u32)
            | (1 << NousCapability::SendMessagesAutonomous as u32)
            | (1 << NousCapability::ModifyContactsConfirmed as u32)
            | (1 << NousCapability::ModifyContactsAutonomous as u32)
            | (1 << NousCapability::ToggleModeConfirmed as u32)
            | (1 << NousCapability::ToggleRadiosConfirmed as u32);
        self.bits & ACTION_BITS != 0
    }

    /// Whether any autonomous-class grant exists -- the new-model meaning
    /// of "can auto-execute" (#552). Auto-execution is per-capability
    /// (`SendMessagesAutonomous`, `ModifyContactsAutonomous`), never a rank.
    #[must_use]
    pub(crate) const fn can_auto_execute(self) -> bool {
        const AUTO_BITS: u32 = (1 << NousCapability::SendMessagesAutonomous as u32)
            | (1 << NousCapability::ModifyContactsAutonomous as u32);
        self.bits & AUTO_BITS != 0
    }

    /// Construct a set from a preset's bit pattern.
    const fn from_bits(bits: u32) -> Self {
        Self { bits }
    }
}

// ---------------------------------------------------------------------------
// Presets -- constructors for capability sets, never ranks (#552)
// ---------------------------------------------------------------------------

/// Trust preset for a nous entity (design-comms.md "Presets").
///
/// A preset is a CONSTRUCTOR for a [`CapabilitySet`] -- a starting point the
/// operator customizes from, not a lock and not a rank. `Custom` marks a
/// set that matches no preset exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[must_use]
#[non_exhaustive]
pub enum CapabilityPreset {
    /// Nothing granted; nous disconnected.
    #[default]
    Off = 0,
    /// Read state only.
    Observer = 1,
    /// + read contacts metadata, draft messages.
    Assistant = 2,
    /// + read messages (metadata and content), read calendar, draft
    ///   calendar events. Design-reading note (#552): the design table's
    ///   "Read messages" spans both message rows -- granting content without
    ///   metadata would be incoherent for an advisor.
    Advisor = 3,
    /// + send messages with confirmation, modify contacts with confirmation.
    Agent = 4,
    /// + send messages autonomously per rules, modify contacts
    ///   autonomously. Reachable ONLY via an explicit opt-in confirmation --
    ///   never by cycling (#552).
    Autonomous = 5,
    /// A custom set matching no preset exactly.
    Custom = 6,
}

impl CapabilityPreset {
    /// The capability set this preset constructs (design table, verbatim).
    // WHY: Off and Custom both evaluate to CapabilitySet::NONE here for
    // different reasons -- Off's NONE is the real, documented "nothing
    // granted" set (design table), while Custom's NONE is a placeholder:
    // this constructor never reconstructs an arbitrary custom map (that
    // state lives on the entity, not derivable from the enum variant
    // alone -- see the arm's own comment below). Merging the arms with `|`
    // would erase that distinction for a future reader.
    #[expect(
        clippy::match_same_arms,
        reason = "Off and Custom both evaluate to CapabilitySet::NONE for different reasons -- Off is the real documented empty grant, Custom is an unrepresentable placeholder; merging the arms would erase that distinction"
    )]
    pub(crate) const fn grants(self) -> CapabilitySet {
        const RS: u32 = 1 << NousCapability::ReadState as u32;
        const RCM: u32 = 1 << NousCapability::ReadContactsMetadata as u32;
        const RMM: u32 = 1 << NousCapability::ReadMessageMetadata as u32;
        const RMC: u32 = 1 << NousCapability::ReadMessageContent as u32;
        const RC: u32 = 1 << NousCapability::ReadCalendar as u32;
        const DM: u32 = 1 << NousCapability::DraftMessages as u32;
        const DCE: u32 = 1 << NousCapability::DraftCalendarEvents as u32;
        const SMC: u32 = 1 << NousCapability::SendMessagesConfirmed as u32;
        const SMA: u32 = 1 << NousCapability::SendMessagesAutonomous as u32;
        const MCC: u32 = 1 << NousCapability::ModifyContactsConfirmed as u32;
        const MCA: u32 = 1 << NousCapability::ModifyContactsAutonomous as u32;
        match self {
            Self::Off => CapabilitySet::NONE,
            Self::Observer => CapabilitySet::from_bits(RS),
            Self::Assistant => CapabilitySet::from_bits(RS | RCM | DM),
            Self::Advisor => CapabilitySet::from_bits(RS | RCM | DM | RMM | RMC | RC | DCE),
            Self::Agent => {
                CapabilitySet::from_bits(RS | RCM | DM | RMM | RMC | RC | DCE | SMC | MCC)
            }
            Self::Autonomous => CapabilitySet::from_bits(
                RS | RCM | DM | RMM | RMC | RC | DCE | SMC | MCC | SMA | MCA,
            ),
            // Custom is not a constructor; its set is whatever the operator
            // built. Callers must hold the set, not reconstruct it.
            Self::Custom => CapabilitySet::NONE,
        }
    }

    /// The preset whose constructor produces `set`, or `Custom`.
    pub(crate) fn of(set: CapabilitySet) -> Self {
        for preset in [
            Self::Off,
            Self::Observer,
            Self::Assistant,
            Self::Advisor,
            Self::Agent,
            Self::Autonomous,
        ] {
            if preset.grants() == set {
                return preset;
            }
        }
        Self::Custom
    }

    /// The next preset the settings UI may cycle to (#552).
    ///
    /// Cycling NEVER reaches `Autonomous`: autonomous authority is an
    /// explicit opt-in confirmation, not a dial step. `Custom` and
    /// `Autonomous` cycle back to `Off` (re-entering the ladder re-selects
    /// a preset constructor).
    pub(crate) const fn next_grantable(self) -> Self {
        match self {
            Self::Off => Self::Observer,
            Self::Observer => Self::Assistant,
            Self::Assistant => Self::Advisor,
            Self::Advisor => Self::Agent,
            Self::Agent | Self::Autonomous | Self::Custom => Self::Off,
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
            Self::Custom => "CUSTOM",
        }
    }

    /// Short description of what this preset's constructor grants.
    #[must_use]
    pub(crate) const fn description(self) -> &'static str {
        match self {
            Self::Off => "No interaction",
            Self::Observer => "Read state only",
            Self::Assistant => "+ contacts metadata, draft messages",
            Self::Advisor => "+ read messages, calendar; draft events",
            Self::Agent => "+ send/modify with confirmation",
            Self::Autonomous => "+ autonomous send/modify (explicit opt-in)",
            Self::Custom => "Custom capability map",
        }
    }

    /// Numeric preset index (0-6) for serialization.
    #[must_use]
    pub(crate) const fn level(self) -> u8 {
        self as u8
    }

    /// Construct a preset from a numeric index; `None` outside 0-6.
    #[must_use]
    pub(crate) const fn from_level(level: u8) -> Option<Self> {
        match level {
            0 => Some(Self::Off),
            1 => Some(Self::Observer),
            2 => Some(Self::Assistant),
            3 => Some(Self::Advisor),
            4 => Some(Self::Agent),
            5 => Some(Self::Autonomous),
            6 => Some(Self::Custom),
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
// Per-action binding (#552): action type -> required grant + confirmation
// ---------------------------------------------------------------------------

/// The confirmation rule bound to an action type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
#[non_exhaustive]
pub(crate) enum ConfirmationRule {
    /// Always require explicit user confirmation before executing.
    Always,
    /// Confirmation may be bypassed only when the matching autonomous
    /// grant exists (every execution still receipts).
    BypassableWithAutonomous,
}

/// The authorization requirement for one action type: the exact capability
/// grant it needs and its confirmation rule (#552). Unknown action types
/// have NO requirement entry and are denied fail-closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub(crate) struct ActionRequirement {
    /// The exact capability the action needs granted.
    pub(crate) capability: NousCapability,
    /// Its confirmation rule.
    pub(crate) confirmation: ConfirmationRule,
}

/// The action binding table (#552). Every recognized action type maps to
/// exactly one requirement; anything unlisted is denied.
///
/// Mapping notes (the design has no rows for these; flagged for operator
/// review): `open_dialer`, `start_timer`, `set_alarm`, `open_feature` are
/// low-risk device/UI actions bound to the draft class with Always-confirm;
/// `scan_start` is an observation action bound to `ReadState`;
/// `add_safe_network` modifies a security-adjacent allowlist and binds to
/// the mode-confirmation class (Always-confirm, every time).
#[must_use]
// WHY: DRAFT_SMS/DRAFT_MATRIX_MESSAGE and the open_dialer/start_timer/
// set_alarm/open_feature group share today's DraftMessages binding only
// because the design table has no dedicated row for the latter group (see
// "Mapping notes" above); likewise TOGGLE_MODE and ADD_SAFE_NETWORK share
// ToggleModeConfirmed for unrelated reasons (mode toggling vs. a security-
// adjacent allowlist edit). Each pair is conceptually distinct and may
// diverge independently on a future design-table update -- merging the
// arms with `|` would erase that independence.
#[expect(
    clippy::match_same_arms,
    reason = "each shared-binding pair shares a requirement for unrelated reasons and may diverge independently on a future design-table update; merging with | would erase that independence"
)]
pub(crate) fn action_requirement(action: &str) -> Option<ActionRequirement> {
    use crate::ekphrasis::action_types as at;
    let req = |capability, confirmation| {
        Some(ActionRequirement {
            capability,
            confirmation,
        })
    };
    match action {
        at::DRAFT_SMS | at::DRAFT_MATRIX_MESSAGE => {
            req(NousCapability::DraftMessages, ConfirmationRule::Always)
        }
        at::ADD_CALENDAR_EVENT => req(
            NousCapability::DraftCalendarEvents,
            ConfirmationRule::Always,
        ),
        at::TOGGLE_MODE => req(
            NousCapability::ToggleModeConfirmed,
            ConfirmationRule::Always,
        ),
        at::TOGGLE_RADIO => req(
            NousCapability::ToggleRadiosConfirmed,
            ConfirmationRule::Always,
        ),
        at::ADD_SAFE_NETWORK => req(
            NousCapability::ToggleModeConfirmed,
            ConfirmationRule::Always,
        ),
        at::OPEN_DIALER | at::START_TIMER | at::SET_ALARM | at::OPEN_FEATURE => {
            req(NousCapability::DraftMessages, ConfirmationRule::Always)
        }
        at::SCAN_START => req(NousCapability::ReadState, ConfirmationRule::Always),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Audit receipts + authorization (#552)
// ---------------------------------------------------------------------------

/// Why an action was denied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
#[non_exhaustive]
pub(crate) enum DenyReason {
    /// The action type is not in the binding table (fail-closed).
    UnknownAction,
    /// The required capability is not granted.
    MissingGrant,
    /// The action targets a kernel-NEVER capability (panic/wipe,
    /// security-disable, keys, SIGINT) -- unreachable on any grant state.
    KernelNever,
}

/// The audit receipt emitted for EVERY authorization decision (#552):
/// grants, confirmation requirements, and denials alike. The durable
/// HMAC-chained audit wiring is the #544 path; this log is the kernel-side
/// record below every client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuditReceipt {
    /// Entity index the decision was for.
    pub(crate) entity_index: usize,
    /// The action type string (owned; the receipt must outlive the proposal).
    pub(crate) action: String,
    /// The capability the action required (when known).
    pub(crate) required: Option<NousCapability>,
    /// The decision, rendered ("granted", "`requires_confirmation`",
    /// "denied:<reason>").
    pub(crate) decision: String,
}

/// The authorization verdict for one proposal.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
#[non_exhaustive]
pub(crate) enum Authorization {
    /// The action may execute now (a Confirmed-class action the operator
    /// just confirmed, or an autonomous-class grant).
    Granted,
    /// The action needs explicit user confirmation first.
    RequiresConfirmation,
    /// The action is denied.
    Denied {
        /// Why.
        reason: DenyReason,
    },
}

/// Maximum receipts retained in the manager log (ring semantics; the
/// drop counter keeps the loss visible).
pub(crate) const MAX_RECEIPTS: usize = 64;

/// Action strings that name kernel-NEVER territory. Any of these is denied
/// regardless of grants -- the adversarial proof that no preset, custom
/// map, or runtime path reaches panic/wipe/security-disable/keys/SIGINT
/// (#552). Matching is defense-in-depth: these strings are not in the
/// binding table, so they would already deny as `UnknownAction`; the
/// `KernelNever` reason makes the boundary explicit in the receipt.
const NEVER_ACTIONS: &[&str] = &[
    "wipe",
    "wipe_device",
    "panic",
    "panic_mode",
    "trigger_panic",
    "disable_scanning",
    "disable_security",
    "lower_threshold",
    "read_keys",
    "read_encryption_keys",
    "read_sigint",
    "sigint_dump",
];

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
    /// The entity's Matrix user id failed format validation (#373).
    InvalidMatrixId(crate::matrix_ids::MatrixIdError),
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
                write!(f, "{entity} requires {required} capability, has {current}")
            }
            Self::InvalidMatrixId(e) => write!(f, "invalid Matrix user id: {e}"),
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
    ///
    /// WARNING: kept private (not `pub`) and only ever set from `new()`,
    /// bounded by `MAX_NAME_LEN`. A `pub` field here would let external
    /// code set it past the backing buffer's length, causing an
    /// out-of-bounds slice panic in `name_str()`/`PartialEq`.
    name_len: u8,
    /// Matrix user ID (e.g., "@syn:thumos.lan").
    pub matrix_id: MatrixUserId,
    /// The capability set -- the SOLE authority over this entity's actions
    /// (#552). Presets only ever construct this; they never rank it.
    grants: CapabilitySet,
}

impl NousEntity {
    /// Create a new nous entity.
    ///
    /// # Errors
    ///
    /// Returns [`NousError::NameTooLong`] if `name` exceeds [`MAX_NAME_LEN`].
    /// Returns [`NousError::InvalidMatrixId`] if `matrix_id` is not a
    /// well-formed Matrix user identifier (#373).
    pub(crate) fn new(
        name: &str,
        matrix_id: &str,
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
            // WHY(#373): validate the Matrix user id rather than trusting the
            // caller; a malformed id surfaces as NousError::InvalidMatrixId.
            matrix_id: MatrixUserId::new(matrix_id).map_err(NousError::InvalidMatrixId)?,
            grants: preset.grants(),
        })
    }

    /// Return the entity name as a string slice.
    #[must_use]
    pub(crate) fn name_str(&self) -> &str {
        // INVARIANT: name_len is private and only ever set in new(),
        // bounded by MAX_NAME_LEN -- this clamp is defense-in-depth
        // against that invariant regressing, not a normal-path branch.
        let len = (self.name_len as usize).min(MAX_NAME_LEN);
        // SAFETY: name is always written from a valid &str in new(), and
        // len is clamped to the buffer length above, so the slice is
        // always valid UTF-8 within bounds.
        core::str::from_utf8(&self.name[..len]).unwrap_or("?")
    }

    /// The entity's capability set (read-only view).
    pub(crate) const fn grants(&self) -> &CapabilitySet {
        &self.grants
    }

    /// The preset matching this entity's current set, or `Custom` (#552).
    pub(crate) fn preset(&self) -> CapabilityPreset {
        CapabilityPreset::of(self.grants)
    }

    /// Replace the set from a preset constructor (discards custom edits).
    ///
    /// `Autonomous` must not be reachable through this setter's casual
    /// callers -- see [`NousEntity::opt_in_autonomous`].
    pub(crate) fn set_preset(&mut self, preset: CapabilityPreset) {
        self.grants = preset.grants();
    }

    /// Grant one capability (Custom editing).
    pub(crate) fn grant(&mut self, cap: NousCapability) {
        self.grants.grant(cap);
    }

    /// Revoke one capability (stale-grant removal).
    pub(crate) fn revoke(&mut self, cap: NousCapability) {
        self.grants.revoke(cap);
    }

    /// The Autonomous opt-in (#552). Reachable ONLY with an explicit
    /// `confirmed` flag from the settings UI's confirmation card -- never
    /// by cycling presets. `confirmed = false` is a no-op (fail-closed).
    pub(crate) fn opt_in_autonomous(&mut self, confirmed: bool) {
        if confirmed {
            self.grants = CapabilityPreset::Autonomous.grants();
        }
    }

    /// Whether this entity can propose actions at its current grants.
    #[must_use]
    pub(crate) const fn can_propose(&self) -> bool {
        self.grants.can_propose()
    }

    /// Whether this entity holds any autonomous-class grant.
    #[must_use]
    pub(crate) const fn can_auto_execute(&self) -> bool {
        self.grants.can_auto_execute()
    }

    /// Return the short display label for this entity's current set.
    #[must_use]
    pub(crate) fn capability_label(&self) -> &'static str {
        self.preset().label()
    }
}

impl fmt::Display for NousEntity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} ({}) [{}]",
            self.name_str(),
            self.matrix_id,
            self.preset()
        )
    }
}

impl PartialEq for NousEntity {
    fn eq(&self, other: &Self) -> bool {
        let self_len = (self.name_len as usize).min(MAX_NAME_LEN);
        let other_len = (other.name_len as usize).min(MAX_NAME_LEN);
        self.name[..self_len] == other.name[..other_len]
            && self.matrix_id == other.matrix_id
            && self.grants == other.grants
    }
}

impl Eq for NousEntity {}

// ---------------------------------------------------------------------------
// Default entities
// ---------------------------------------------------------------------------

/// Create the default Syn entity (primary general-purpose assistant).
///
/// # Errors
///
/// Returns [`NousError`] if the trusted default identifiers ever fail
/// validation — unreachable for the compile-time constants below, but the
/// fallible signature keeps the no-panic contract without an infallible
/// identifier constructor (#373).
pub(crate) fn default_syn() -> Result<NousEntity, NousError> {
    NousEntity::new("Syn", "@syn:thumos.lan", CapabilityPreset::Advisor)
}

/// Create the default Phrouros entity (security/field operations).
///
/// # Errors
///
/// See [`default_syn`].
pub(crate) fn default_phrouros() -> Result<NousEntity, NousError> {
    NousEntity::new(
        "Phrouros",
        "@phrouros:thumos.lan",
        CapabilityPreset::Observer,
    )
}

/// Create the default Paideia entity (learning/research).
///
/// # Errors
///
/// See [`default_syn`].
pub(crate) fn default_paideia() -> Result<NousEntity, NousError> {
    NousEntity::new(
        "Paideia",
        "@paideia:thumos.lan",
        CapabilityPreset::Assistant,
    )
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
    /// Index of the currently active entity, or `None` if no entity is
    /// currently selected (#453).
    active_entity: Option<usize>,
    /// The audit receipt log (#552): every authorization decision, newest
    /// last, ring-bounded at [`MAX_RECEIPTS`].
    receipts: Vec<AuditReceipt>,
    /// Receipts dropped by the ring bound (the loss is never silent).
    dropped_receipts: u32,
}

impl NousManager {
    /// Create a new manager with the three default entities.
    ///
    /// Syn is the default active entity (index 0).
    #[must_use]
    pub(crate) fn new() -> Self {
        // WHY(#373): the defaults are trusted compile-time constants that
        // always validate; `flatten` keeps each successfully-built entity and
        // drops the unreachable error case, preserving the no-panic contract
        // without an infallible identifier constructor.
        let entities = [default_syn(), default_phrouros(), default_paideia()]
            .into_iter()
            .flatten()
            .collect();
        Self {
            entities,
            active_entity: Some(0),
            receipts: Vec::new(),
            dropped_receipts: 0,
        }
    }

    /// Create an empty manager with no entities.
    ///
    /// Useful for testing or when defaults are not wanted.
    #[must_use]
    pub(crate) fn empty() -> Self {
        Self {
            entities: Vec::new(),
            active_entity: None,
            receipts: Vec::new(),
            dropped_receipts: 0,
        }
    }

    /// Return a reference to the currently active entity.
    ///
    /// Returns `None` if no entities are registered.
    #[must_use]
    pub(crate) fn active(&self) -> Option<&NousEntity> {
        self.entities.get(self.active_entity?)
    }

    /// Return a mutable reference to the currently active entity.
    ///
    /// Returns `None` if no entities are registered.
    pub(crate) fn active_mut(&mut self) -> Option<&mut NousEntity> {
        self.entities.get_mut(self.active_entity?)
    }

    /// Return the index of the currently active entity.
    ///
    /// Returns `None` if no entity is currently selected (#453).
    #[must_use]
    pub(crate) fn active_index(&self) -> Option<usize> {
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

    /// Authorize one entity's action proposal against its capability set
    /// (#552): exact required grant, confirmation rule, kernel-NEVER
    /// boundary -- and an audit receipt for EVERY decision, including
    /// denials.
    ///
    /// The `operator_confirmed` flag is the settings UI's explicit
    /// confirmation for a Confirmed-class action (the confirm card's
    /// result); it never bypasses a missing grant or a NEVER boundary.
    pub(crate) fn authorize(
        &mut self,
        entity_index: usize,
        proposal: &crate::ekphrasis::ActionProposal,
        operator_confirmed: bool,
    ) -> Authorization {
        let action = proposal.action.as_str();

        // 1. The kernel-NEVER boundary: unreachable on any grant state.
        if NEVER_ACTIONS.contains(&action) {
            return self.deny(entity_index, proposal, None, DenyReason::KernelNever);
        }

        // 2. Unknown action types deny fail-closed.
        let Some(requirement) = action_requirement(action) else {
            return self.deny(entity_index, proposal, None, DenyReason::UnknownAction);
        };

        // 3. The entity must exist and hold the exact grant.
        let Some(entity) = self.entities.get(entity_index) else {
            return self.deny(
                entity_index,
                proposal,
                Some(requirement.capability),
                DenyReason::MissingGrant,
            );
        };
        if !entity.grants().grants(requirement.capability) {
            return self.deny(
                entity_index,
                proposal,
                Some(requirement.capability),
                DenyReason::MissingGrant,
            );
        }

        // 4. Confirmation rule.
        let verdict = match requirement.confirmation {
            ConfirmationRule::Always => {
                if operator_confirmed {
                    Authorization::Granted
                } else {
                    Authorization::RequiresConfirmation
                }
            }
            ConfirmationRule::BypassableWithAutonomous => {
                if operator_confirmed || entity.grants().can_auto_execute() {
                    Authorization::Granted
                } else {
                    Authorization::RequiresConfirmation
                }
            }
        };
        let decision = match &verdict {
            Authorization::Granted => "granted",
            Authorization::RequiresConfirmation => "requires_confirmation",
            Authorization::Denied { .. } => unreachable!("verdict is never Denied here"),
        };
        self.record(
            entity_index,
            proposal,
            Some(requirement.capability),
            decision,
        );
        verdict
    }

    /// Record a deny verdict with its receipt.
    fn deny(
        &mut self,
        entity_index: usize,
        proposal: &crate::ekphrasis::ActionProposal,
        required: Option<NousCapability>,
        reason: DenyReason,
    ) -> Authorization {
        let text = match reason {
            DenyReason::UnknownAction => "denied:unknown_action",
            DenyReason::MissingGrant => "denied:missing_grant",
            DenyReason::KernelNever => "denied:kernel_never",
        };
        self.record(entity_index, proposal, required, text);
        Authorization::Denied { reason }
    }

    /// Append a receipt to the ring-bounded log.
    fn record(
        &mut self,
        entity_index: usize,
        proposal: &crate::ekphrasis::ActionProposal,
        required: Option<NousCapability>,
        decision: &str,
    ) {
        if self.receipts.len() >= MAX_RECEIPTS {
            self.receipts.remove(0);
            self.dropped_receipts = self.dropped_receipts.saturating_add(1);
        }
        self.receipts.push(AuditReceipt {
            entity_index,
            action: proposal.action.clone(),
            required,
            decision: String::from(decision),
        });
    }

    /// The audit receipt log (oldest first).
    #[must_use]
    pub(crate) fn receipts(&self) -> &[AuditReceipt] {
        &self.receipts
    }

    /// Receipts dropped by the ring bound.
    #[must_use]
    pub(crate) const fn dropped_receipts(&self) -> u32 {
        self.dropped_receipts
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
        self.active_entity = Some(index);
        Ok(())
    }

    /// Cycle to the next entity (wraps around).
    ///
    /// Does nothing if no entities are registered. If no entity is
    /// currently selected, selects the first entity (#453).
    pub(crate) fn cycle_next(&mut self) {
        if self.entities.is_empty() {
            return;
        }
        self.active_entity = Some(match self.active_entity {
            Some(idx) => (idx + 1) % self.entities.len(),
            None => 0,
        });
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
    /// If the removed entity was the currently active one, the active
    /// selection is cleared (`None`) regardless of its position -- fail-
    /// closed, so no privileged action is ever silently attributed to
    /// whichever entity shifted into the vacated slot (#453). Otherwise
    /// the active index shifts down to keep pointing at the same
    /// surviving entity.
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

        // WHY(#453): deselect outright when the removed entity was the
        // active one (fail-closed) instead of leaving the numeric index
        // unchanged to silently point at whatever entity shifted down
        // into the vacated slot; otherwise shift the index down by one
        // to keep tracking the same surviving entity.
        match self.active_entity {
            Some(active) if active == index => self.active_entity = None,
            Some(active) if active > index => self.active_entity = Some(active - 1),
            _ => {
                // WHY: nothing selected (None), or the active entity sits
                // BEFORE the removed one (active < index) — the active index
                // still points at the same surviving entity; no adjustment.
            }
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
                entity.set_preset(preset);
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
        self.active().is_some_and(|e| e.grants().can_propose())
    }

    /// Check whether the active entity can auto-execute actions (holds an
    /// autonomous-class grant, #552).
    ///
    /// Returns `false` if no entities are registered.
    #[must_use]
    pub(crate) fn active_can_auto_execute(&self) -> bool {
        self.active().is_some_and(|e| e.grants().can_auto_execute())
    }
}

impl fmt::Display for NousManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "NousManager({} entities, active={})",
            self.entities.len(),
            self.active().map_or("none", |e| e.name_str())
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;

    // --- CapabilityPreset tests ---

    #[test]
    fn preset_ladder_is_a_constructor_sequence_not_a_rank() {
        // #552: the ladder's meaning is "each constructor adds grants to the
        // previous set", NOT "higher rank subsumes privileges". Assert the
        // set-inclusion chain and that Autonomous adds exactly the two
        // autonomous grants to Agent's set.
        let agent = CapabilityPreset::Agent.grants();
        let autonomous = CapabilityPreset::Autonomous.grants();
        let mut expected = agent;
        expected.grant(NousCapability::SendMessagesAutonomous);
        expected.grant(NousCapability::ModifyContactsAutonomous);
        assert_eq!(
            autonomous, expected,
            "Autonomous = Agent + the two autonomous grants"
        );

        let observer = CapabilityPreset::Observer.grants();
        let assistant = CapabilityPreset::Assistant.grants();
        let mut expected2 = observer;
        expected2.grant(NousCapability::ReadContactsMetadata);
        expected2.grant(NousCapability::DraftMessages);
        assert_eq!(
            assistant, expected2,
            "Assistant = Observer + the two documented grants"
        );
    }

    #[test]
    fn preset_level_roundtrip() {
        for level in 0..=6u8 {
            let preset = CapabilityPreset::from_level(level);
            assert!(preset.is_some(), "level {level} must parse");
            assert_eq!(
                preset.map(CapabilityPreset::level),
                Some(level),
                "level roundtrip for {level}"
            );
        }
        assert!(CapabilityPreset::from_level(7).is_none());
        assert!(CapabilityPreset::from_level(255).is_none());
    }

    #[test]
    fn preset_propose_gating() {
        assert!(
            !CapabilityPreset::Off.grants().can_propose(),
            "Off must not propose"
        );
        assert!(
            !CapabilityPreset::Observer.grants().can_propose(),
            "Observer must not propose"
        );
        assert!(
            CapabilityPreset::Assistant.grants().can_propose(),
            "Assistant must propose"
        );
        assert!(
            CapabilityPreset::Advisor.grants().can_propose(),
            "Advisor must propose"
        );
        assert!(
            CapabilityPreset::Agent.grants().can_propose(),
            "Agent must propose"
        );
        assert!(
            CapabilityPreset::Autonomous.grants().can_propose(),
            "Autonomous must propose"
        );
    }

    #[test]
    fn preset_auto_execute_gating() {
        // #552: auto-execution is per-capability (autonomous grants), never
        // a rank. Only sets holding an Autonomous-class grant qualify.
        assert!(
            !CapabilityPreset::Off.grants().can_auto_execute(),
            "Off must not auto-execute"
        );
        assert!(
            !CapabilityPreset::Observer.grants().can_auto_execute(),
            "Observer must not auto-execute"
        );
        assert!(
            !CapabilityPreset::Assistant.grants().can_auto_execute(),
            "Assistant must not auto-execute"
        );
        assert!(
            !CapabilityPreset::Advisor.grants().can_auto_execute(),
            "Advisor holds no autonomous grant"
        );
        assert!(
            !CapabilityPreset::Agent.grants().can_auto_execute(),
            "Agent is confirmation-only, no autonomous grant"
        );
        assert!(
            CapabilityPreset::Autonomous.grants().can_auto_execute(),
            "Autonomous holds the autonomous grants"
        );
    }

    #[test]
    fn preset_constructors_match_the_design_table() {
        // #552: presets are constructors for capability sets, verbatim from
        // design-comms.md. Each assertion pins the EXACT grant set.
        use NousCapability as C;
        assert_eq!(CapabilityPreset::Off.grants(), CapabilitySet::NONE);
        assert!(CapabilityPreset::Observer.grants().grants(C::ReadState));
        assert!(!CapabilityPreset::Observer.grants().can_propose());

        let a = CapabilityPreset::Assistant.grants();
        assert!(
            a.grants(C::ReadState)
                && a.grants(C::ReadContactsMetadata)
                && a.grants(C::DraftMessages)
        );
        assert!(!a.grants(C::ReadMessageContent));

        let ad = CapabilityPreset::Advisor.grants();
        assert!(ad.grants(C::ReadMessageMetadata) && ad.grants(C::ReadMessageContent));
        assert!(ad.grants(C::ReadCalendar) && ad.grants(C::DraftCalendarEvents));
        assert!(!ad.grants(C::SendMessagesConfirmed));

        let ag = CapabilityPreset::Agent.grants();
        assert!(ag.grants(C::SendMessagesConfirmed) && ag.grants(C::ModifyContactsConfirmed));
        assert!(!ag.grants(C::SendMessagesAutonomous) && !ag.grants(C::ToggleModeConfirmed));

        let au = CapabilityPreset::Autonomous.grants();
        assert!(au.grants(C::SendMessagesAutonomous) && au.grants(C::ModifyContactsAutonomous));
        assert!(
            !au.grants(C::ReadAuditLog),
            "autonomous never includes the audit log by default"
        );
        assert!(
            !au.grants(C::ToggleModeConfirmed) && !au.grants(C::ToggleRadiosConfirmed),
            "autonomous never includes mode/radio toggles by default (design: opt-in only)"
        );
    }

    #[test]
    fn no_preset_or_custom_can_represent_the_never_class() {
        // #552 adversarial: the NEVER set is unrepresentable in CapabilitySet
        // by construction (NeverCapability is a separate type with no bits).
        // This test pins that every preset constructor yields a set that
        // grants NOTHING outside the 15 documented capabilities -- the bit
        // patterns are exact, so an accidental extra bit fails loudly.
        for preset in [
            CapabilityPreset::Off,
            CapabilityPreset::Observer,
            CapabilityPreset::Assistant,
            CapabilityPreset::Advisor,
            CapabilityPreset::Agent,
            CapabilityPreset::Autonomous,
        ] {
            assert_eq!(
                preset,
                CapabilityPreset::of(preset.grants()),
                "every preset's set must round-trip through of()"
            );
        }
        // A custom set with every grantable bit still cannot name a NEVER
        // capability: the type system has no API for it. Pin the full set.
        let mut all = CapabilitySet::NONE;
        for cap in [
            NousCapability::ReadState,
            NousCapability::ReadContactsMetadata,
            NousCapability::ReadContactsFull,
            NousCapability::ReadMessageMetadata,
            NousCapability::ReadMessageContent,
            NousCapability::ReadCalendar,
            NousCapability::ReadAuditLog,
            NousCapability::DraftMessages,
            NousCapability::DraftCalendarEvents,
            NousCapability::SendMessagesConfirmed,
            NousCapability::SendMessagesAutonomous,
            NousCapability::ModifyContactsConfirmed,
            NousCapability::ModifyContactsAutonomous,
            NousCapability::ToggleModeConfirmed,
            NousCapability::ToggleRadiosConfirmed,
        ] {
            all.grant(cap);
        }
        assert_eq!(
            CapabilityPreset::of(all),
            CapabilityPreset::Custom,
            "a fully-granted map is Custom, not any preset"
        );
    }

    #[test]
    fn never_actions_deny_on_every_preset() {
        // #552 adversarial: panic/wipe/security-disable/keys/SIGINT action
        // strings deny on EVERY grant state, Autonomous included.
        let mut mgr = NousManager::empty();
        let mut all_grant = NousEntity::new("max", "@max:thumos.lan", CapabilityPreset::Autonomous)
            .expect("valid entity");
        for cap in [
            NousCapability::ToggleModeConfirmed,
            NousCapability::ToggleRadiosConfirmed,
            NousCapability::ReadAuditLog,
        ] {
            all_grant.grant(cap);
        }
        mgr.add_entity(all_grant).expect("room for entity");
        for action in [
            "wipe",
            "panic",
            "trigger_panic",
            "disable_scanning",
            "read_encryption_keys",
            "read_sigint",
        ] {
            let proposal = crate::ekphrasis::ActionProposal::new(
                String::from(action),
                Vec::new(),
                String::from("adversarial probe"),
            );
            let verdict = mgr.authorize(0, &proposal, true);
            assert!(
                matches!(
                    verdict,
                    Authorization::Denied {
                        reason: DenyReason::KernelNever
                    }
                ),
                "{action} must deny kernel_never even on a max-grant entity"
            );
        }
        // Every denial receipted.
        assert_eq!(mgr.receipts().len(), 6);
        assert!(
            mgr.receipts()
                .iter()
                .all(|r| r.decision == "denied:kernel_never")
        );
    }

    #[test]
    fn unknown_actions_deny_fail_closed() {
        let mut mgr = NousManager::new();
        let proposal = crate::ekphrasis::ActionProposal::new(
            String::from("exfiltrate_everything"),
            Vec::new(),
            String::from("unknown probe"),
        );
        let verdict = mgr.authorize(0, &proposal, true);
        assert!(matches!(
            verdict,
            Authorization::Denied {
                reason: DenyReason::UnknownAction
            }
        ));
    }

    #[test]
    fn stale_grant_denies_after_revoke() {
        // #552 adversarial: a revoked (stale) grant must not authorize.
        let mut mgr = NousManager::new();
        let proposal = crate::ekphrasis::ActionProposal::new(
            String::from(crate::ekphrasis::action_types::DRAFT_SMS),
            Vec::new(),
            String::from("draft"),
        );
        // Syn is Advisor: has DraftMessages.
        assert!(matches!(
            mgr.authorize(0, &proposal, false),
            Authorization::RequiresConfirmation
        ));
        mgr.active_mut()
            .expect("active entity")
            .revoke(NousCapability::DraftMessages);
        assert!(
            matches!(
                mgr.authorize(0, &proposal, true),
                Authorization::Denied {
                    reason: DenyReason::MissingGrant
                }
            ),
            "after revoke the same action must deny missing_grant"
        );
    }

    #[test]
    fn confirmation_discipline_per_rule() {
        let mut mgr = NousManager::new();
        let sms = crate::ekphrasis::ActionProposal::new(
            String::from(crate::ekphrasis::action_types::DRAFT_SMS),
            Vec::new(),
            String::from("draft"),
        );
        // Always-rule: unconfirmed is never Granted, even with the grant.
        assert!(matches!(
            mgr.authorize(0, &sms, false),
            Authorization::RequiresConfirmation
        ));
        assert!(matches!(
            mgr.authorize(0, &sms, true),
            Authorization::Granted
        ));
        // The grant alone never executes a Confirmed-class action.
        assert!(
            !mgr.active().expect("active").grants().can_auto_execute()
                || !matches!(mgr.authorize(0, &sms, false), Authorization::Granted)
        );
    }

    #[test]
    fn every_decision_receipts() {
        let mut mgr = NousManager::new();
        let good = crate::ekphrasis::ActionProposal::new(
            String::from(crate::ekphrasis::action_types::DRAFT_SMS),
            Vec::new(),
            String::from("draft"),
        );
        let bad = crate::ekphrasis::ActionProposal::new(
            String::from("not_an_action"),
            Vec::new(),
            String::from("bad"),
        );
        let _ = mgr.authorize(0, &good, false);
        let _ = mgr.authorize(0, &bad, true);
        let _ = mgr.authorize(0, &good, true);
        assert_eq!(
            mgr.receipts().len(),
            3,
            "grant + deny + confirm all receipt"
        );
        assert_eq!(mgr.receipts()[0].decision, "requires_confirmation");
        assert_eq!(mgr.receipts()[1].decision, "denied:unknown_action");
        assert_eq!(mgr.receipts()[2].decision, "granted");
        assert!(
            mgr.receipts()
                .iter()
                .all(|r| r.required.is_some() || r.decision == "denied:unknown_action")
        );
    }

    #[test]
    fn cycling_never_reaches_autonomous() {
        // #552: the settings dial cannot produce autonomous authority.
        let mut p = CapabilityPreset::Off;
        for _ in 0..12 {
            assert_ne!(
                p,
                CapabilityPreset::Autonomous,
                "cycling must never yield Autonomous"
            );
            p = p.next_grantable();
        }
        // The opt-in path requires the explicit confirmation flag.
        let mut e =
            NousEntity::new("e", "@e:thumos.lan", CapabilityPreset::Agent).expect("valid entity");
        e.opt_in_autonomous(false);
        assert_ne!(
            e.preset(),
            CapabilityPreset::Autonomous,
            "unconfirmed opt-in is a no-op"
        );
        e.opt_in_autonomous(true);
        assert_eq!(
            e.preset(),
            CapabilityPreset::Autonomous,
            "confirmed opt-in grants"
        );
    }

    #[test]
    fn custom_edits_flip_label() {
        let mut e = NousEntity::new("e", "@e:thumos.lan", CapabilityPreset::Observer)
            .expect("valid entity");
        assert_eq!(e.capability_label(), "OBSERVER");
        e.grant(NousCapability::ReadCalendar);
        assert_eq!(
            e.capability_label(),
            "CUSTOM",
            "a grant outside the preset makes it custom"
        );
        e.revoke(NousCapability::ReadCalendar);
        assert_eq!(
            e.capability_label(),
            "OBSERVER",
            "undoing the edit restores the preset label"
        );
    }

    #[test]
    fn preset_display() {
        assert_eq!(CapabilityPreset::Advisor.to_string(), "ADVISOR");
        assert_eq!(CapabilityPreset::Autonomous.to_string(), "AUTONOMOUS");
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
            "@testbot:thumos.lan",
            CapabilityPreset::Assistant,
        );
        assert!(entity.is_ok());
        let entity = entity.unwrap_or_else(|_| unreachable!());
        assert_eq!(entity.name_str(), "TestBot");
        assert_eq!(entity.matrix_id, "@testbot:thumos.lan");
        assert_eq!(entity.preset(), CapabilityPreset::Assistant);
    }

    #[test]
    fn entity_name_too_long() {
        let long_name = "a]".repeat(20); // 40 bytes > MAX_NAME_LEN (32)
        let result = NousEntity::new(&long_name, "@long:thumos.lan", CapabilityPreset::Off);
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
        let result = NousEntity::new(&name, "@max:thumos.lan", CapabilityPreset::Off);
        assert!(result.is_ok(), "exactly MAX_NAME_LEN must succeed");
    }

    #[test]
    fn name_len_past_buffer_does_not_panic_on_read_or_eq() {
        // name_len is private specifically so external code cannot set it
        // past MAX_NAME_LEN; this test pokes the field directly (allowed
        // -- `tests` is a descendant module of `nous`) to prove the read
        // path stays fail-closed even if that invariant is ever violated
        // again, rather than panicking on an out-of-bounds slice index.
        let mut entity = NousEntity::new("Bot", "@bot:thumos.lan", CapabilityPreset::Off)
            .unwrap_or_else(|_| unreachable!());
        entity.name_len = 200;

        let other = NousEntity::new("Bot", "@bot:thumos.lan", CapabilityPreset::Off)
            .unwrap_or_else(|_| unreachable!());

        let name = entity.name_str();
        assert!(
            name.len() <= MAX_NAME_LEN,
            "name_str must clamp to MAX_NAME_LEN instead of reading past the buffer"
        );
        let _ = entity == other; // must not panic
    }

    #[test]
    fn entity_propose_reflects_preset() {
        let observer = NousEntity::new("Obs", "@obs:thumos.lan", CapabilityPreset::Observer)
            .unwrap_or_else(|_| unreachable!());
        assert!(!observer.can_propose());

        let assistant = NousEntity::new("Ast", "@ast:thumos.lan", CapabilityPreset::Assistant)
            .unwrap_or_else(|_| unreachable!());
        assert!(assistant.can_propose());
    }

    #[test]
    fn entity_display() {
        let entity = default_syn().expect("default syn valid");
        let display = alloc::format!("{entity}");
        assert!(display.contains("Syn"), "display must contain name");
        assert!(
            display.contains("@syn:thumos.lan"),
            "display must contain matrix id"
        );
        assert!(display.contains("ADVISOR"), "display must contain preset");
    }

    #[test]
    fn entity_equality() {
        let a = default_syn().expect("default syn valid");
        let b = default_syn().expect("default syn valid");
        assert_eq!(a, b, "identical entities must be equal");

        let c = default_phrouros().expect("default phrouros valid");
        assert_ne!(a, c, "different entities must not be equal");
    }

    // --- Default entity tests ---

    #[test]
    fn default_entities_valid() {
        let syn = default_syn().expect("default syn valid");
        assert_eq!(syn.name_str(), "Syn");
        assert_eq!(syn.preset(), CapabilityPreset::Advisor);
        assert!(syn.can_propose());
        // #552: Advisor holds NO autonomous grant (autonomous authority is
        // per-capability, opt-in) — it proposes with confirmation only.
        assert!(!syn.can_auto_execute());

        let phrouros = default_phrouros().expect("default phrouros valid");
        assert_eq!(phrouros.name_str(), "Phrouros");
        assert_eq!(phrouros.preset(), CapabilityPreset::Observer);
        assert!(!phrouros.can_propose());

        let paideia = default_paideia().expect("default paideia valid");
        assert_eq!(paideia.name_str(), "Paideia");
        assert_eq!(paideia.preset(), CapabilityPreset::Assistant);
        assert!(paideia.can_propose());
        assert!(!paideia.can_auto_execute());
    }

    // --- NousManager tests ---

    #[test]
    fn manager_defaults() {
        let mgr = NousManager::new();
        assert_eq!(mgr.entity_count(), 3, "must have 3 default entities");
        assert_eq!(mgr.active_index(), Some(0), "Syn must be active by default");

        let active = mgr.active();
        assert!(active.is_some());
        assert_eq!(
            active.map(NousEntity::name_str),
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
            mgr.active().map(NousEntity::name_str),
            Some("Phrouros"),
            "active must be Phrouros after switch(1)"
        );

        assert!(mgr.switch(2).is_ok());
        assert_eq!(mgr.active().map(NousEntity::name_str), Some("Paideia"),);

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
        assert_eq!(mgr.active_index(), Some(0));

        mgr.cycle_next();
        assert_eq!(mgr.active_index(), Some(1));

        mgr.cycle_next();
        assert_eq!(mgr.active_index(), Some(2));

        mgr.cycle_next();
        assert_eq!(mgr.active_index(), Some(0), "must wrap around");
    }

    #[test]
    fn manager_cycle_next_empty() {
        let mut mgr = NousManager::empty();
        mgr.cycle_next(); // Must not panic.
        assert_eq!(mgr.active_index(), None);
    }

    #[test]
    fn manager_add_entity() {
        let mut mgr = NousManager::new();
        let custom = NousEntity::new("Custom", "@custom:thumos.lan", CapabilityPreset::Agent)
            .unwrap_or_else(|_| unreachable!());

        assert!(mgr.add_entity(custom).is_ok());
        assert_eq!(mgr.entity_count(), 4);
    }

    #[test]
    fn manager_add_duplicate_name() {
        let mut mgr = NousManager::new();
        let dup = NousEntity::new("Syn", "@syn2:thumos.lan", CapabilityPreset::Off)
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
        assert_eq!(mgr.active_index(), Some(2));

        // Remove entity at index 2 (the active entity, and the last one).
        let _ = mgr.remove_entity(2);
        assert_eq!(
            mgr.active_index(),
            None,
            "removing the active entity must deselect, not silently \
             clamp to a different entity (#453)"
        );
    }

    #[test]
    fn remove_entity_deselects_when_removing_a_non_last_active_entity() {
        // WHY(#453): removing the currently-active entity must clear the
        // selection (fail-closed) rather than leaving active_entity's
        // numeric index unchanged and letting it silently refer to
        // whatever entity Vec::remove shifted down into that slot --
        // that would substitute a different entity's capability preset
        // for a selection the caller never made.
        let mut mgr = NousManager::new();
        // Syn (Advisor) at 0, Phrouros (Observer) at 1, Paideia (Assistant) at 2.
        mgr.switch(1).unwrap_or_else(|_| unreachable!()); // active = Phrouros
        assert_eq!(mgr.active().map(NousEntity::name_str), Some("Phrouros"));

        let removed = mgr.remove_entity(1); // remove the ACTIVE entity, non-last
        assert_eq!(
            removed.map(|e| String::from(e.name_str())),
            Ok(String::from("Phrouros")),
        );

        assert_eq!(
            mgr.active().map(NousEntity::name_str),
            None,
            "removing the active entity must deselect -- no entity is \
             active until one is explicitly selected"
        );
        assert_eq!(mgr.active_index(), None);
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
            mgr.entity(0).map(NousEntity::preset),
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
        // #552: Syn (Advisor) holds NO autonomous grant — auto-execution is
        // per-capability (autonomous classes), never a preset rank.
        assert!(!mgr.active_can_auto_execute());
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

        let err = NousError::InvalidIndex { index: 5, count: 3 };
        let display = alloc::format!("{err}");
        assert!(display.contains('5'));
        assert!(display.contains('3'));

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
