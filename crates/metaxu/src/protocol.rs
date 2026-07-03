//! Wire protocol types for the Aletheia/Thumos bridge.

use compact_str::CompactString;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;
use ulid::Ulid;

use crate::error::{EncodeSnafu, Result};

mod ulid_bytes {
    use serde::{Deserialize as _, Serialize as _, Serializer};
    use ulid::Ulid;

    pub(crate) fn serialize<S>(id: &Ulid, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        id.to_bytes().serialize(serializer)
    }

    pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<Ulid, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = <[u8; 16]>::deserialize(deserializer)?;
        Ok(Ulid::from_bytes(bytes))
    }
}

/// Capability classes that a runtime task may exercise through Thumos.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Capability {
    /// Send an SMS through the telephony stack.
    SmsSend,
    /// Place an outbound voice call.
    CallDial,
    /// Read contact records.
    ContactsRead,
    /// Capture microphone audio.
    AudioCapture,
    /// Play audio through the device speaker or receiver path.
    AudioPlayback,
    /// Reference the device identity handle without exposing raw identifiers.
    DeviceIdentityReference,
}

/// Wire claim that a task was issued one bridge capability.
///
/// `metaxu` does not authenticate or authorize grants. Thumos policy or the
/// Menos-facing runtime must validate issuer, grant id, expiration, and any
/// cryptographic proof before performing a device action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityGrant {
    /// Capability being granted.
    pub capability: Capability,
    /// Opaque issuer handle from Thumos policy.
    pub issuer: CompactString,
    /// Optional task-scoped grant identifier.
    pub grant_id: CompactString,
    /// Optional expiration timestamp for the external policy verifier.
    pub expires_at: Option<Timestamp>,
}

impl CapabilityGrant {
    /// Construct a non-expiring capability grant.
    #[must_use]
    pub fn new(
        capability: Capability,
        issuer: impl Into<CompactString>,
        grant_id: impl Into<CompactString>,
    ) -> Self {
        Self {
            capability,
            issuer: issuer.into(),
            grant_id: grant_id.into(),
            expires_at: None,
        }
    }

    /// Construct a capability grant with an absolute expiration.
    #[must_use]
    pub fn expiring(
        capability: Capability,
        issuer: impl Into<CompactString>,
        grant_id: impl Into<CompactString>,
        expires_at: Timestamp,
    ) -> Self {
        Self {
            capability,
            issuer: issuer.into(),
            grant_id: grant_id.into(),
            expires_at: Some(expires_at),
        }
    }
}

/// Kind of identity handle referenced by a task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum IdentityKind {
    /// Stable local device handle.
    Device,
    /// Per-session pseudonymous handle.
    Session,
    /// Per-capability pseudonymous handle.
    Capability,
}

/// Opaque reference to device identity state.
///
/// This type deliberately carries a handle and attestation digest instead of
/// raw IMEI, IMSI, MAC, Bluetooth address, or similar hardware identifiers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceIdentityRef {
    /// Identity reference class.
    pub kind: IdentityKind,
    /// Opaque handle generated inside Thumos.
    pub handle: CompactString,
    /// Digest binding this handle to local policy state.
    pub attestation_digest: [u8; 32],
}

impl DeviceIdentityRef {
    /// Construct an opaque device identity reference.
    #[must_use]
    pub fn new(
        kind: IdentityKind,
        handle: impl Into<CompactString>,
        attestation_digest: [u8; 32],
    ) -> Self {
        Self {
            kind,
            handle: handle.into(),
            attestation_digest,
        }
    }
}

/// Audio route requested by an audio task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum AudioMode {
    /// Microphone capture.
    Capture,
    /// Playback to the current policy-selected output.
    Playback,
}

/// Typed task request sent from Thumos to the runtime boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum TaskRequest {
    /// Send an SMS message.
    SendSms {
        /// Request identifier.
        #[serde(with = "ulid_bytes")]
        request_id: Ulid,
        /// Opaque device identity reference.
        identity: DeviceIdentityRef,
        /// Capability grants attached to the task.
        grants: Vec<CapabilityGrant>,
        /// Destination address or contact-resolved route.
        to: CompactString,
        /// SMS body text.
        body: CompactString,
    },
    /// Place an outbound call.
    PlaceCall {
        /// Request identifier.
        #[serde(with = "ulid_bytes")]
        request_id: Ulid,
        /// Opaque device identity reference.
        identity: DeviceIdentityRef,
        /// Capability grants attached to the task.
        grants: Vec<CapabilityGrant>,
        /// Destination number or contact-resolved route.
        to: CompactString,
    },
    /// Query local contacts through a capability-gated view.
    LookupContact {
        /// Request identifier.
        #[serde(with = "ulid_bytes")]
        request_id: Ulid,
        /// Opaque device identity reference.
        identity: DeviceIdentityRef,
        /// Capability grants attached to the task.
        grants: Vec<CapabilityGrant>,
        /// Search query.
        query: CompactString,
    },
    /// Request an audio capture or playback session.
    AudioSession {
        /// Request identifier.
        #[serde(with = "ulid_bytes")]
        request_id: Ulid,
        /// Opaque device identity reference.
        identity: DeviceIdentityRef,
        /// Capability grants attached to the task.
        grants: Vec<CapabilityGrant>,
        /// Audio operation mode.
        mode: AudioMode,
        /// Maximum duration in milliseconds.
        max_duration_ms: u32,
    },
}

impl TaskRequest {
    /// Return the task request identifier.
    #[must_use]
    pub const fn request_id(&self) -> Ulid {
        match self {
            Self::SendSms { request_id, .. }
            | Self::PlaceCall { request_id, .. }
            | Self::LookupContact { request_id, .. }
            | Self::AudioSession { request_id, .. } => *request_id,
        }
    }

    /// Return the identity reference carried by the task.
    #[must_use]
    pub const fn identity(&self) -> &DeviceIdentityRef {
        match self {
            Self::SendSms { identity, .. }
            | Self::PlaceCall { identity, .. }
            | Self::LookupContact { identity, .. }
            | Self::AudioSession { identity, .. } => identity,
        }
    }

    /// Return the capability grants carried by the task.
    #[must_use]
    pub fn grants(&self) -> &[CapabilityGrant] {
        match self {
            Self::SendSms { grants, .. }
            | Self::PlaceCall { grants, .. }
            | Self::LookupContact { grants, .. }
            | Self::AudioSession { grants, .. } => grants,
        }
    }

    /// Return the capability required by this task.
    #[must_use]
    pub const fn required_capability(&self) -> Capability {
        match self {
            Self::SendSms { .. } => Capability::SmsSend,
            Self::PlaceCall { .. } => Capability::CallDial,
            Self::LookupContact { .. } => Capability::ContactsRead,
            Self::AudioSession { mode, .. } => match mode {
                AudioMode::Capture => Capability::AudioCapture,
                AudioMode::Playback => Capability::AudioPlayback,
            },
        }
    }

    /// Return whether a grant for the required capability is attached.
    ///
    /// This is a local preflight check only. It does not prove authorization or
    /// enforce expiration; the runtime/policy verifier remains authoritative.
    #[must_use]
    pub fn has_required_capability(&self) -> bool {
        let required = self.required_capability();
        self.grants()
            .iter()
            .any(|grant| grant.capability == required)
    }
}

/// Contact result returned from the runtime boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContactSummary {
    /// Stable contact handle, not a raw storage key.
    pub contact_ref: CompactString,
    /// Display name.
    pub display_name: CompactString,
    /// Preferred dial or message route.
    pub preferred_route: Option<CompactString>,
}

/// Device-side action accepted by the runtime boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum DeviceAction {
    /// No device action is required.
    None,
    /// SMS may be queued locally.
    SmsQueued {
        /// Runtime correlation reference for the queued SMS.
        runtime_ref: CompactString,
    },
    /// Call may be requested locally.
    CallRequested {
        /// Runtime correlation reference for the call.
        runtime_ref: CompactString,
    },
    /// Contacts resolved by the runtime boundary.
    Contacts {
        /// Matching contacts.
        contacts: Vec<ContactSummary>,
    },
    /// Audio session may be opened locally.
    AudioSession {
        /// Runtime correlation reference for the audio session.
        runtime_ref: CompactString,
        /// Audio operation mode.
        mode: AudioMode,
    },
}

/// Runtime response status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum TaskStatus {
    /// Request accepted with a device-side action.
    Accepted {
        /// Action for the device side.
        action: DeviceAction,
    },
    /// Request rejected by bridge/runtime policy.
    Rejected {
        /// Human-readable policy reason.
        reason: CompactString,
    },
}

/// Response returned from the runtime boundary to Thumos.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskResponse {
    /// Request identifier this response answers.
    #[serde(with = "ulid_bytes")]
    pub request_id: Ulid,
    /// Response status.
    pub status: TaskStatus,
}

impl TaskResponse {
    /// Construct an accepted response.
    #[must_use]
    pub const fn accepted(request_id: Ulid, action: DeviceAction) -> Self {
        Self {
            request_id,
            status: TaskStatus::Accepted { action },
        }
    }

    /// Construct a rejected response.
    #[must_use]
    pub fn rejected(request_id: Ulid, reason: impl Into<CompactString>) -> Self {
        Self {
            request_id,
            status: TaskStatus::Rejected {
                reason: reason.into(),
            },
        }
    }
}

/// Serialize a task request for transport.
pub(crate) fn encode_request(request: &TaskRequest) -> Result<Vec<u8>> {
    postcard::to_allocvec(request).context(EncodeSnafu)
}

/// Deserialize a task request from transport bytes.
pub(crate) fn decode_request(bytes: &[u8]) -> Result<TaskRequest> {
    postcard::from_bytes(bytes).context(crate::error::DecodeSnafu)
}

/// Serialize a task response for transport.
pub(crate) fn encode_response(response: &TaskResponse) -> Result<Vec<u8>> {
    postcard::to_allocvec(response).context(EncodeSnafu)
}

/// Deserialize a task response from transport bytes.
pub(crate) fn decode_response(bytes: &[u8]) -> Result<TaskResponse> {
    postcard::from_bytes(bytes).context(crate::error::DecodeSnafu)
}

#[cfg(test)]
mod tests {
    use ulid::Ulid;

    use super::{
        AudioMode, Capability, CapabilityGrant, DeviceIdentityRef, IdentityKind, TaskRequest,
        decode_request, encode_request,
    };

    fn identity_ref() -> DeviceIdentityRef {
        DeviceIdentityRef::new(IdentityKind::Device, "device-ref", [4; 32])
    }

    #[test]
    fn place_call_round_trips() {
        let request = TaskRequest::PlaceCall {
            request_id: Ulid::from_bytes([5; 16]),
            identity: identity_ref(),
            grants: vec![CapabilityGrant::new(
                Capability::CallDial,
                "policy",
                "grant-call",
            )],
            to: "+15559876543".into(),
        };

        let round_tripped = encode_request(&request)
            .ok()
            .and_then(|bytes| decode_request(&bytes).ok());

        assert_eq!(round_tripped, Some(request));
    }

    #[test]
    fn audio_session_round_trips() {
        let request = TaskRequest::AudioSession {
            request_id: Ulid::from_bytes([6; 16]),
            identity: identity_ref(),
            grants: vec![CapabilityGrant::new(
                Capability::AudioCapture,
                "policy",
                "grant-audio",
            )],
            mode: AudioMode::Capture,
            max_duration_ms: 30_000,
        };

        let round_tripped = encode_request(&request)
            .ok()
            .and_then(|bytes| decode_request(&bytes).ok());

        assert_eq!(round_tripped, Some(request));
    }
}
