//! Bluetooth A2DP audio source profile.
//!
//! Implements the A2DP (Advanced Audio Distribution Profile) source role for
//! streaming audio to Bluetooth headphones and speakers.  Builds on the HCI
//! layer in `bluetooth.rs`.
//!
//! ## Protocol stack
//!
//! ```text
//! Application (PCM audio)
//!        |
//!   SBC encoder  (sub-band coding, mandatory A2DP codec)
//!        |
//!   AVDTP        (Audio/Video Distribution Transport Protocol)
//!        |
//!   L2CAP        (encapsulated in HCI ACL packets)
//!        |
//!   HCI          (bluetooth.rs)
//! ```
//!
//! ## Module structure
//!
//! SBC codec (frame header, encoder trait, stub encoder) is in [`crate::sbc`].
//! AVDTP message builder is in [`crate::avdtp`].
//!
//! ## Integration
//!
//! Used by the audio session manager (`audio.rs`) when the output route is
//! `AudioRoute::BluetoothA2dp`.  Connects to the BT adapter via `bluetooth.rs`.

// WHY: A2DP profile not yet wired to audio session manager (Wave 8, kinit pending).
#![expect(
    dead_code,
    reason = "A2DP profile created in Phase 07 Wave 8, audio manager wiring pending"
)]

extern crate alloc;

use crate::avdtp::{
    AVDTP_MAX_TRANSACTION_LABEL, AVDTP_SIGNAL_DISCOVER, AVDTP_SIGNAL_GET_CAPABILITIES,
    AVDTP_SIGNAL_OPEN, AVDTP_SIGNAL_SET_CONFIGURATION, AVDTP_SIGNAL_START, AvdtpMessage,
};
use crate::bluetooth::{BtError, BtHwOps, hci_acl_data};
// WHY cfg(test): the avdtp/sbc glob re-exports are used only by this
// module's tests (via super::*); unused in the shipped build.
#[cfg(test)]
pub(crate) use crate::avdtp::*;
use crate::sbc::{
    SBC_FREQ_44100, SBC_FREQ_48000, SBC_MAX_FRAME_SIZE, SbcEncoder, SbcFrameHeader, StubSbcEncoder,
};

// Re-export SBC and AVDTP types so external callers can still use crate::bt_audio::*.

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Bluetooth audio (A2DP) errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BtAudioError {
    /// The A2DP profile is not in a valid state for this operation.
    InvalidState,
    /// Bluetooth HCI layer error.
    HciError(BtError),
    /// AVDTP signaling failed or was rejected by the remote peer.
    AvdtpError,
    /// SBC encoding error (e.g., invalid parameters).
    SbcError,
    /// The peer does not support SBC (mandatory codec).
    CodecNotSupported,
    /// Buffer too small for the encoded output.
    BufferTooSmall,
    /// No peer device configured.
    NoPeer,
}

impl core::fmt::Display for BtAudioError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidState => write!(f, "A2DP invalid state"),
            Self::HciError(e) => write!(f, "A2DP HCI error: {e}"),
            Self::AvdtpError => write!(f, "AVDTP signaling error"),
            Self::SbcError => write!(f, "SBC encoding error"),
            Self::CodecNotSupported => write!(f, "SBC codec not supported by peer"),
            Self::BufferTooSmall => write!(f, "output buffer too small"),
            Self::NoPeer => write!(f, "no peer device configured"),
        }
    }
}

impl From<BtError> for BtAudioError {
    fn from(e: BtError) -> Self {
        Self::HciError(e)
    }
}

// ---------------------------------------------------------------------------
// A2DP state machine
// ---------------------------------------------------------------------------

/// A2DP source profile connection state.
///
/// Follows the AVDTP signaling lifecycle:
/// `Disconnected -> Connecting -> Connected -> Streaming`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum A2dpState {
    /// No active A2DP connection.
    #[default]
    Disconnected,
    /// AVDTP signaling in progress (Discover -> `SetConfiguration` -> Open).
    Connecting,
    /// AVDTP stream is configured and open, ready to start.
    Connected,
    /// Audio is actively streaming to the remote sink.
    Streaming,
    /// An error occurred during signaling or streaming.
    Error(BtAudioError),
}

impl core::fmt::Display for A2dpState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Disconnected => write!(f, "disconnected"),
            Self::Connecting => write!(f, "connecting"),
            Self::Connected => write!(f, "connected"),
            Self::Streaming => write!(f, "streaming"),
            Self::Error(e) => write!(f, "error: {e}"),
        }
    }
}

// ---------------------------------------------------------------------------
// A2DP profile
// ---------------------------------------------------------------------------

/// A2DP source profile.
///
/// Manages the A2DP connection lifecycle and AVDTP signaling for streaming
/// audio to a Bluetooth sink (headphones, speaker).
///
/// Generic over the BT hardware backend (`H: BtHwOps`) for testability.
pub(crate) struct A2dpProfile<H: BtHwOps> {
    /// Current A2DP state.
    state: A2dpState,
    /// Bluetooth device address of the peer sink.
    peer_addr: Option<[u8; 6]>,
    /// Configured sample rate (44100 or 48000 Hz).
    sample_rate: u32,
    /// Number of audio channels (1 = mono, 2 = stereo).
    channels: u8,
    /// SBC encoder for audio framing.
    encoder: StubSbcEncoder,
    /// AVDTP transaction label counter (0-15, wraps).
    transaction_label: u8,
    /// Remote stream endpoint ID discovered during signaling.
    remote_seid: u8,
    /// Local stream endpoint ID.
    local_seid: u8,
    /// AVDTP signal ID whose response is currently awaited during the
    /// Connecting sequence (Discover -> GetCapabilities ->
    /// SetConfiguration -> Open -> Start) or during resume(). `None`
    /// when no signaling response is outstanding.
    pending_signal: Option<u8>,
    /// Bluetooth hardware backend.
    hw: H,
}

impl<H: BtHwOps> A2dpProfile<H> {
    /// Create a new A2DP source profile with default settings.
    ///
    /// Default: 44100 Hz, stereo, SBC high-quality.
    #[must_use]
    pub(crate) fn new(hw: H) -> Self {
        Self {
            state: A2dpState::Disconnected,
            peer_addr: None,
            sample_rate: 44100,
            channels: 2,
            encoder: StubSbcEncoder::default_a2dp(),
            transaction_label: 0,
            remote_seid: 0,
            local_seid: 1,
            pending_signal: None,
            hw,
        }
    }

    /// Return the current A2DP state.
    #[must_use]
    pub(crate) fn state(&self) -> A2dpState {
        self.state
    }

    /// Return the peer device address, if set.
    #[must_use]
    pub(crate) fn peer_addr(&self) -> Option<&[u8; 6]> {
        self.peer_addr.as_ref()
    }

    /// Return the configured sample rate.
    #[must_use]
    pub(crate) fn sample_rate(&self) -> u32 {
        self.sample_rate
    }

    /// Return the configured channel count.
    #[must_use]
    pub(crate) fn channels(&self) -> u8 {
        self.channels
    }

    /// Set the peer device address for A2DP connection.
    pub(crate) fn set_peer(&mut self, addr: [u8; 6]) {
        self.peer_addr = Some(addr);
    }

    /// Configure the audio parameters.
    ///
    /// Must be called before `connect()`. Only 44100 and 48000 Hz are
    /// supported; other values default to 44100.
    ///
    /// # Errors
    ///
    /// - [`BtAudioError::InvalidState`] -- not in Disconnected state. Changing
    ///   SBC parameters once signaling has started would silently diverge the
    ///   local encoder from the format already negotiated with the peer via
    ///   `SetConfiguration`.
    #[must_use]
    pub(crate) fn configure(&mut self, sample_rate: u32, channels: u8) -> Result<(), BtAudioError> {
        if self.state != A2dpState::Disconnected {
            return Err(BtAudioError::InvalidState);
        }

        self.sample_rate = if sample_rate == 48000 { 48000 } else { 44100 };
        self.channels = if channels >= 2 { 2 } else { 1 };

        let header = if self.channels == 1 {
            SbcFrameHeader::mono(self.sample_rate)
        } else {
            let freq = if self.sample_rate == 48000 {
                SBC_FREQ_48000
            } else {
                SBC_FREQ_44100
            };
            SbcFrameHeader {
                sampling_freq: freq,
                ..SbcFrameHeader::default_a2dp()
            }
        };
        self.encoder = StubSbcEncoder::new(header);
        Ok(())
    }

    /// Initiate A2DP connection to the configured peer.
    ///
    /// Sends the AVDTP Discover command to begin the signaling sequence.
    /// The full sequence (Discover -> `GetCapabilities` -> `SetConfiguration` ->
    /// Open -> Start) is driven by calling `process_signaling()` after each
    /// response.
    ///
    /// # Errors
    ///
    /// - [`BtAudioError::InvalidState`] -- not in Disconnected state.
    /// - [`BtAudioError::NoPeer`] -- no peer address configured.
    /// - [`BtAudioError::HciError`] -- HCI send failed.
    #[must_use]
    pub(crate) fn connect(&mut self) -> Result<(), BtAudioError> {
        if self.state != A2dpState::Disconnected {
            return Err(BtAudioError::InvalidState);
        }
        if self.peer_addr.is_none() {
            return Err(BtAudioError::NoPeer);
        }

        self.state = A2dpState::Connecting;

        // Send AVDTP Discover command.
        let label = self.next_transaction_label();
        let discover = AvdtpMessage::discover(label);
        self.hw
            .send_command(&discover)
            .map_err(BtAudioError::from)?;
        self.pending_signal = Some(AVDTP_SIGNAL_DISCOVER);

        Ok(())
    }

    /// Advance the AVDTP signaling state machine.
    ///
    /// Called when an AVDTP response is received from the peer.
    /// Drives the signaling sequence to completion:
    ///
    /// 1. After Discover response: send `GetCapabilities`
    /// 2. After `GetCapabilities` response: send `SetConfiguration`
    /// 3. After `SetConfiguration` response: send Open
    /// 4. After Open response: send Start
    /// 5. After Start response: transition to Streaming
    ///
    /// # Errors
    ///
    /// - [`BtAudioError::InvalidState`] -- not in Connecting state.
    /// - [`BtAudioError::AvdtpError`] -- unknown or unexpected signal ID.
    /// - [`BtAudioError::HciError`] -- HCI send failed.
    #[must_use]
    pub(crate) fn advance_signaling(&mut self, signal: u8) -> Result<(), BtAudioError> {
        if !matches!(self.state, A2dpState::Connecting | A2dpState::Connected) {
            return Err(BtAudioError::InvalidState);
        }

        // WARNING(security): dispatching purely on the peer-supplied
        // `signal` ID with no ordering check let a malicious/misbehaving
        // peer inject e.g. AVDTP_SIGNAL_START as the very first response
        // and jump straight from Connecting to Streaming, skipping SBC
        // codec negotiation entirely. `pending_signal` tracks which
        // response this profile is actually waiting for (set by
        // connect()/resume() and advanced below); any other signal is a
        // protocol violation and is rejected here, before the dispatch.
        if self.pending_signal != Some(signal) {
            self.state = A2dpState::Error(BtAudioError::AvdtpError);
            return Err(BtAudioError::AvdtpError);
        }

        match signal {
            AVDTP_SIGNAL_DISCOVER => {
                // Received Discover response -- send GetCapabilities.
                let label = self.next_transaction_label();
                let msg = AvdtpMessage::get_capabilities(label, self.remote_seid);
                self.hw.send_command(&msg).map_err(BtAudioError::from)?;
                self.pending_signal = Some(AVDTP_SIGNAL_GET_CAPABILITIES);
            }
            AVDTP_SIGNAL_GET_CAPABILITIES => {
                // Received GetCapabilities response -- send SetConfiguration.
                let label = self.next_transaction_label();
                let header = *self.encoder.header();
                let msg = AvdtpMessage::set_configuration(
                    label,
                    self.remote_seid,
                    self.local_seid,
                    &header,
                );
                self.hw.send_command(&msg).map_err(BtAudioError::from)?;
                self.pending_signal = Some(AVDTP_SIGNAL_SET_CONFIGURATION);
            }
            AVDTP_SIGNAL_SET_CONFIGURATION => {
                // Received SetConfiguration response -- send Open.
                let label = self.next_transaction_label();
                let msg = AvdtpMessage::open(label, self.remote_seid);
                self.hw.send_command(&msg).map_err(BtAudioError::from)?;
                self.pending_signal = Some(AVDTP_SIGNAL_OPEN);
            }
            AVDTP_SIGNAL_OPEN => {
                // Received Open response -- send Start, then commit the
                // Connected transition once the send succeeds (the stream is
                // now configured and open per the documented lifecycle).
                let label = self.next_transaction_label();
                let msg = AvdtpMessage::start(label, self.remote_seid);
                self.hw.send_command(&msg).map_err(BtAudioError::from)?;
                self.state = A2dpState::Connected;
                self.pending_signal = Some(AVDTP_SIGNAL_START);
            }
            AVDTP_SIGNAL_START => {
                // Received Start response -- streaming is active.
                self.state = A2dpState::Streaming;
                self.pending_signal = None;
            }
            _ => {
                // Unknown or unexpected signal.
                self.state = A2dpState::Error(BtAudioError::AvdtpError);
                return Err(BtAudioError::AvdtpError);
            }
        }

        Ok(())
    }

    /// Send an SBC-encoded audio frame.
    ///
    /// Encodes the PCM data and sends it as HCI ACL data (the L2CAP/AVDTP
    /// media transport channel) -- never the HCI command channel, which the
    /// controller decodes as command opcodes, not payload.
    ///
    /// # Errors
    ///
    /// - [`BtAudioError::InvalidState`] -- not in Streaming state.
    /// - [`BtAudioError::SbcError`] -- SBC encoding failed.
    /// - [`BtAudioError::BufferTooSmall`] -- internal frame buffer too small.
    /// - [`BtAudioError::HciError`] -- HCI send failed.
    #[must_use]
    pub(crate) fn send_audio(&mut self, pcm: &[i16]) -> Result<usize, BtAudioError> {
        if self.state != A2dpState::Streaming {
            return Err(BtAudioError::InvalidState);
        }

        let mut frame_buf = [0u8; SBC_MAX_FRAME_SIZE];
        let frame_len = self.encoder.encode(pcm, &mut frame_buf)?;

        // NOTE: the ACL connection handle for the AVDTP transport channel is
        // not yet tracked (BR/EDR Create Connection / Connection Complete
        // wiring is a known gap, same class as the HCI cmd TX stub in
        // bluetooth.rs). Handle 0 is a placeholder within the legal 12-bit
        // range until that lands.
        let acl_frame = hci_acl_data(0, &frame_buf[..frame_len]);
        self.hw
            .send_acl_data(&acl_frame)
            .map_err(BtAudioError::from)?;

        Ok(frame_len)
    }

    /// Suspend the active audio stream.
    ///
    /// Transitions from Streaming to Connected (stream is open but paused).
    ///
    /// # Errors
    ///
    /// - [`BtAudioError::InvalidState`] -- not in Streaming state.
    /// - [`BtAudioError::HciError`] -- HCI send failed.
    #[must_use]
    pub(crate) fn suspend(&mut self) -> Result<(), BtAudioError> {
        if self.state != A2dpState::Streaming {
            return Err(BtAudioError::InvalidState);
        }

        let label = self.next_transaction_label();
        let msg = AvdtpMessage::suspend(label, self.remote_seid);
        self.hw.send_command(&msg).map_err(BtAudioError::from)?;

        self.state = A2dpState::Connected;
        Ok(())
    }

    /// Resume a suspended audio stream.
    ///
    /// Sends AVDTP Start to the peer. Mirrors the initial connect-to-
    /// streaming transition: this does NOT advance the state to
    /// Streaming by itself -- call `advance_signaling(AVDTP_SIGNAL_START)`
    /// when the peer's Start response arrives, exactly as after the
    /// initial Start sent during signaling (see the `AVDTP_SIGNAL_OPEN`
    /// arm of `advance_signaling`). Keeping Streaming gated behind the
    /// same single peer-ACK path avoids a second path that granted it on
    /// local send alone, inconsistent with every other transition into
    /// Streaming.
    ///
    /// # Errors
    ///
    /// - [`BtAudioError::InvalidState`] -- not in Connected state.
    /// - [`BtAudioError::HciError`] -- HCI send failed.
    #[must_use]
    pub(crate) fn resume(&mut self) -> Result<(), BtAudioError> {
        if self.state != A2dpState::Connected {
            return Err(BtAudioError::InvalidState);
        }

        let label = self.next_transaction_label();
        let msg = AvdtpMessage::start(label, self.remote_seid);
        self.hw.send_command(&msg).map_err(BtAudioError::from)?;
        self.pending_signal = Some(AVDTP_SIGNAL_START);

        Ok(())
    }

    /// Disconnect the A2DP session.
    ///
    /// Sends AVDTP Close (if connected/streaming) and cleans up state.
    ///
    /// # Errors
    ///
    /// Currently infallible but returns `Result` for API consistency.
    #[must_use]
    #[expect(
        clippy::unnecessary_wraps,
        reason = "returns Result for API consistency with other lifecycle methods"
    )]
    pub(crate) fn disconnect(&mut self) -> Result<(), BtAudioError> {
        match self.state {
            A2dpState::Streaming => {
                // Suspend first, then close.
                let label = self.next_transaction_label();
                let suspend_msg = AvdtpMessage::suspend(label, self.remote_seid);
                // Best-effort suspend; continue to close even if it fails.
                let _ = self.hw.send_command(&suspend_msg); // WHY: best-effort hardware write; failure is non-fatal in this context

                let label = self.next_transaction_label();
                let close_msg = AvdtpMessage::close(label, self.remote_seid);
                let _ = self.hw.send_command(&close_msg); // WHY: best-effort hardware write; failure is non-fatal in this context
            }
            A2dpState::Connected | A2dpState::Connecting => {
                let label = self.next_transaction_label();
                let close_msg = AvdtpMessage::close(label, self.remote_seid);
                let _ = self.hw.send_command(&close_msg); // WHY: best-effort hardware write; failure is non-fatal in this context
            }
            A2dpState::Disconnected | A2dpState::Error(_) => {
                // Already disconnected or errored, nothing to send.
            }
        }

        self.state = A2dpState::Disconnected;
        self.remote_seid = 0;
        Ok(())
    }

    /// Set the remote stream endpoint ID (normally discovered via AVDTP).
    pub(crate) fn set_remote_seid(&mut self, seid: u8) {
        self.remote_seid = seid;
    }

    /// Get the next AVDTP transaction label (0-15, wrapping).
    fn next_transaction_label(&mut self) -> u8 {
        let label = self.transaction_label;
        self.transaction_label = (self.transaction_label + 1) & AVDTP_MAX_TRANSACTION_LABEL;
        label
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bluetooth::MockBtHw;

    /// Helper: create a fresh A2DP profile with a mock BT backend.
    fn make_a2dp() -> A2dpProfile<MockBtHw> {
        A2dpProfile::new(MockBtHw::new())
    }

    #[test]
    fn a2dp_starts_disconnected() {
        let profile = make_a2dp();
        assert_eq!(
            profile.state(),
            A2dpState::Disconnected,
            "new A2DP profile must start in Disconnected state"
        );
        assert!(
            profile.peer_addr().is_none(),
            "peer address must be None initially"
        );
    }

    #[test]
    fn connect_transitions_state() {
        let mut profile = make_a2dp();
        let peer = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        profile.set_peer(peer);

        let result = profile.connect();
        assert!(result.is_ok(), "connect must succeed with peer set");
        assert_eq!(
            profile.state(),
            A2dpState::Connecting,
            "state must be Connecting after connect()"
        );
    }

    #[test]
    fn connect_without_peer_returns_error() {
        let mut profile = make_a2dp();
        let result = profile.connect();
        assert_eq!(
            result,
            Err(BtAudioError::NoPeer),
            "connect without peer must return NoPeer error"
        );
        assert_eq!(
            profile.state(),
            A2dpState::Disconnected,
            "state must remain Disconnected"
        );
    }

    #[test]
    fn disconnect_cleans_up() {
        let mut profile = make_a2dp();
        let peer = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        profile.set_peer(peer);
        profile.connect().ok();

        // Walk through signaling to Streaming.
        profile.set_remote_seid(1);
        profile.advance_signaling(AVDTP_SIGNAL_DISCOVER).ok();
        profile
            .advance_signaling(AVDTP_SIGNAL_GET_CAPABILITIES)
            .ok();
        profile
            .advance_signaling(AVDTP_SIGNAL_SET_CONFIGURATION)
            .ok();
        profile.advance_signaling(AVDTP_SIGNAL_OPEN).ok();
        profile.advance_signaling(AVDTP_SIGNAL_START).ok();
        assert_eq!(profile.state(), A2dpState::Streaming);

        // Disconnect.
        let result = profile.disconnect();
        assert!(result.is_ok(), "disconnect must succeed");
        assert_eq!(
            profile.state(),
            A2dpState::Disconnected,
            "state must be Disconnected after disconnect"
        );
    }

    #[test]
    fn full_signaling_sequence_reaches_streaming() {
        let mut profile = make_a2dp();
        let peer = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];
        profile.set_peer(peer);
        profile.set_remote_seid(2);
        profile.connect().ok();

        assert_eq!(profile.state(), A2dpState::Connecting);

        // Drive the full signaling sequence.
        profile.advance_signaling(AVDTP_SIGNAL_DISCOVER).ok();
        assert_eq!(
            profile.state(),
            A2dpState::Connecting,
            "still connecting after discover"
        );

        profile
            .advance_signaling(AVDTP_SIGNAL_GET_CAPABILITIES)
            .ok();
        assert_eq!(
            profile.state(),
            A2dpState::Connecting,
            "still connecting after get_caps"
        );

        profile
            .advance_signaling(AVDTP_SIGNAL_SET_CONFIGURATION)
            .ok();
        assert_eq!(
            profile.state(),
            A2dpState::Connecting,
            "still connecting after set_config"
        );

        profile.advance_signaling(AVDTP_SIGNAL_OPEN).ok();
        assert_eq!(
            profile.state(),
            A2dpState::Connected,
            "connection completes on the Open response, before auto-continuing to Start"
        );

        profile.advance_signaling(AVDTP_SIGNAL_START).ok();
        assert_eq!(
            profile.state(),
            A2dpState::Streaming,
            "must be Streaming after Start response"
        );
    }

    #[test]
    fn advance_signaling_rejects_out_of_order_start_before_negotiation() {
        let mut profile = make_a2dp();
        let peer = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];
        profile.set_peer(peer);
        profile.set_remote_seid(2);
        profile.connect().ok();
        assert_eq!(profile.state(), A2dpState::Connecting);

        // A malicious/misbehaving peer sends Start as if it were the
        // very first signaling response, skipping GetCapabilities ->
        // SetConfiguration -> Open. Before the fix, advance_signaling()
        // dispatched purely on the signal ID with no ordering check, so
        // this reached Streaming without ever negotiating the SBC codec.
        let result = profile.advance_signaling(AVDTP_SIGNAL_START);
        assert_eq!(
            result,
            Err(BtAudioError::AvdtpError),
            "an out-of-order Start response must be rejected, not fast-forward to Streaming"
        );
        assert_ne!(
            profile.state(),
            A2dpState::Streaming,
            "must never reach Streaming without codec negotiation"
        );
    }

    #[test]
    fn open_response_reaches_connected_via_normal_sequence() {
        let mut profile = make_a2dp();
        let peer = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        profile.set_peer(peer);
        profile.set_remote_seid(1);
        profile.connect().ok();
        profile.advance_signaling(AVDTP_SIGNAL_DISCOVER).ok();
        profile
            .advance_signaling(AVDTP_SIGNAL_GET_CAPABILITIES)
            .ok();
        profile
            .advance_signaling(AVDTP_SIGNAL_SET_CONFIGURATION)
            .ok();

        let result = profile.advance_signaling(AVDTP_SIGNAL_OPEN);
        assert!(
            result.is_ok(),
            "advancing past the Open response must succeed"
        );
        assert_eq!(
            profile.state(),
            A2dpState::Connected,
            "Connected must be reachable via the normal connection sequence, \
             not only via suspend() from Streaming"
        );
    }

    #[test]
    fn advance_signaling_in_disconnected_state_returns_invalid_state() {
        let mut profile = make_a2dp();
        // No connect() call -- profile is still Disconnected.
        let result = profile.advance_signaling(AVDTP_SIGNAL_DISCOVER);
        assert_eq!(
            result,
            Err(BtAudioError::InvalidState),
            "advance_signaling before connect() (Disconnected state) must return InvalidState"
        );
    }

    #[test]
    fn suspend_and_resume() {
        let mut profile = make_a2dp();
        let peer = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        profile.set_peer(peer);
        profile.set_remote_seid(1);
        profile.connect().ok();
        profile.advance_signaling(AVDTP_SIGNAL_DISCOVER).ok();
        profile
            .advance_signaling(AVDTP_SIGNAL_GET_CAPABILITIES)
            .ok();
        profile
            .advance_signaling(AVDTP_SIGNAL_SET_CONFIGURATION)
            .ok();
        profile.advance_signaling(AVDTP_SIGNAL_OPEN).ok();
        profile.advance_signaling(AVDTP_SIGNAL_START).ok();

        // Suspend.
        let result = profile.suspend();
        assert!(result.is_ok(), "suspend must succeed");
        assert_eq!(profile.state(), A2dpState::Connected);

        // Resume: sends Start but does not itself grant Streaming --
        // that requires the peer's ACK via advance_signaling(), exactly
        // like the initial connect-to-streaming transition.
        let result = profile.resume();
        assert!(result.is_ok(), "resume must succeed");
        assert_eq!(
            profile.state(),
            A2dpState::Connected,
            "resume() alone must not grant Streaming without a peer ACK"
        );

        let result = profile.advance_signaling(AVDTP_SIGNAL_START);
        assert!(
            result.is_ok(),
            "advancing past the peer's Start ACK must succeed"
        );
        assert_eq!(profile.state(), A2dpState::Streaming);
    }

    #[test]
    fn suspend_and_resume_invalid_state_return_error() {
        let mut profile = make_a2dp();

        // suspend() outside Streaming (Disconnected).
        assert_eq!(
            profile.suspend(),
            Err(BtAudioError::InvalidState),
            "suspend from Disconnected must return InvalidState"
        );
        assert_eq!(profile.state(), A2dpState::Disconnected);

        // resume() outside Connected (Disconnected).
        assert_eq!(
            profile.resume(),
            Err(BtAudioError::InvalidState),
            "resume from Disconnected must return InvalidState"
        );

        let peer = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        profile.set_peer(peer);
        profile.connect().ok();
        assert_eq!(profile.state(), A2dpState::Connecting);

        // suspend()/resume() while Connecting -- neither Streaming nor Connected.
        assert_eq!(
            profile.suspend(),
            Err(BtAudioError::InvalidState),
            "suspend from Connecting must return InvalidState"
        );
        assert_eq!(
            profile.resume(),
            Err(BtAudioError::InvalidState),
            "resume from Connecting must return InvalidState"
        );

        // Drive to Streaming, then resume() must be rejected there too
        // (only Connected is valid for resume()).
        profile.set_remote_seid(1);
        profile.advance_signaling(AVDTP_SIGNAL_DISCOVER).ok();
        profile
            .advance_signaling(AVDTP_SIGNAL_GET_CAPABILITIES)
            .ok();
        profile
            .advance_signaling(AVDTP_SIGNAL_SET_CONFIGURATION)
            .ok();
        profile.advance_signaling(AVDTP_SIGNAL_OPEN).ok();
        profile.advance_signaling(AVDTP_SIGNAL_START).ok();
        assert_eq!(profile.state(), A2dpState::Streaming);
        assert_eq!(
            profile.resume(),
            Err(BtAudioError::InvalidState),
            "resume while already Streaming must return InvalidState"
        );
    }

    #[test]
    fn send_audio_requires_streaming() {
        let mut profile = make_a2dp();
        let pcm = [0i16; 128];
        let result = profile.send_audio(&pcm);
        assert_eq!(
            result,
            Err(BtAudioError::InvalidState),
            "send_audio in Disconnected state must return InvalidState"
        );
    }

    #[test]
    fn configure_clamps_parameters() {
        let mut profile = make_a2dp();
        profile.configure(96000, 5).ok();
        assert_eq!(
            profile.sample_rate(),
            44100,
            "invalid sample rate must default to 44100"
        );
        assert_eq!(profile.channels(), 2, "channels > 2 must clamp to 2");

        profile.configure(48000, 1).ok();
        assert_eq!(profile.sample_rate(), 48000);
        assert_eq!(profile.channels(), 1);
    }

    #[test]
    fn configure_rejected_outside_disconnected_state() {
        let mut profile = make_a2dp();
        let peer = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        profile.set_peer(peer);
        profile.connect().ok();
        assert_eq!(profile.state(), A2dpState::Connecting);

        let before_rate = profile.sample_rate();
        let before_channels = profile.channels();

        let result = profile.configure(48000, 1);
        assert_eq!(
            result,
            Err(BtAudioError::InvalidState),
            "configure outside Disconnected must not silently diverge the SBC \
             encoder from the negotiated stream format"
        );
        assert_eq!(
            profile.sample_rate(),
            before_rate,
            "sample rate must be unchanged when configure is rejected"
        );
        assert_eq!(
            profile.channels(),
            before_channels,
            "channel count must be unchanged when configure is rejected"
        );
    }

    #[test]
    fn connect_in_wrong_state_returns_error() {
        let mut profile = make_a2dp();
        let peer = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        profile.set_peer(peer);
        profile.connect().ok();

        // Already connecting -- second connect must fail.
        let result = profile.connect();
        assert_eq!(
            result,
            Err(BtAudioError::InvalidState),
            "connect while Connecting must return InvalidState"
        );
    }

    #[test]
    fn transaction_label_wraps() {
        let mut profile = make_a2dp();
        for _ in 0..20 {
            let label = profile.next_transaction_label();
            assert!(
                label <= AVDTP_MAX_TRANSACTION_LABEL,
                "transaction label {label} must be <= {AVDTP_MAX_TRANSACTION_LABEL}"
            );
        }
    }

    #[test]
    fn disconnect_from_disconnected_is_ok() {
        let mut profile = make_a2dp();
        let result = profile.disconnect();
        assert!(
            result.is_ok(),
            "disconnect from Disconnected must succeed (no-op)"
        );
    }

    #[test]
    fn codec_not_supported_error_display() {
        // BtAudioError::CodecNotSupported is returned during AVDTP capability
        // negotiation when the remote sink does not support SBC. This requires
        // a real BT peer, so we verify the variant is constructable and displays.
        let err = BtAudioError::CodecNotSupported;
        let msg = alloc::format!("{err}");
        assert_eq!(msg, "SBC codec not supported by peer");
    }

    #[test]
    fn send_audio_routes_through_acl_not_command_channel() {
        let mut profile = make_a2dp();
        let peer = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        profile.set_peer(peer);
        profile.set_remote_seid(1);
        profile.connect().ok();
        profile.advance_signaling(AVDTP_SIGNAL_DISCOVER).ok();
        profile
            .advance_signaling(AVDTP_SIGNAL_GET_CAPABILITIES)
            .ok();
        profile
            .advance_signaling(AVDTP_SIGNAL_SET_CONFIGURATION)
            .ok();
        profile.advance_signaling(AVDTP_SIGNAL_OPEN).ok();
        profile.advance_signaling(AVDTP_SIGNAL_START).ok();
        assert_eq!(profile.state(), A2dpState::Streaming);

        let commands_before = profile.hw.sent_commands.len();
        let pcm = [0i16; 128];
        let result = profile.send_audio(&pcm);
        assert!(result.is_ok(), "send_audio must succeed while Streaming");

        assert_eq!(
            profile.hw.sent_commands.len(),
            commands_before,
            "audio frames must never be sent on the HCI command channel"
        );
        assert_eq!(
            profile.hw.sent_acl_data.len(),
            1,
            "audio frame must be sent as exactly one ACL data packet"
        );
        assert_eq!(
            profile.hw.sent_acl_data[0][0], 0x02,
            "ACL data packet must use H4 type 0x02, not H4 command type 0x01"
        );
    }

    #[test]
    fn disconnect_from_connected_sends_avdtp_close() {
        let mut profile = make_a2dp();
        let peer = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        profile.set_peer(peer);
        profile.set_remote_seid(1);
        profile.connect().ok();
        profile.advance_signaling(AVDTP_SIGNAL_DISCOVER).ok();
        profile
            .advance_signaling(AVDTP_SIGNAL_GET_CAPABILITIES)
            .ok();
        profile
            .advance_signaling(AVDTP_SIGNAL_SET_CONFIGURATION)
            .ok();
        profile.advance_signaling(AVDTP_SIGNAL_OPEN).ok();
        assert_eq!(profile.state(), A2dpState::Connected);

        let result = profile.disconnect();
        assert!(result.is_ok(), "disconnect from Connected must succeed");
        assert_eq!(profile.state(), A2dpState::Disconnected);

        let last_signal = profile
            .hw
            .sent_commands
            .last()
            .and_then(|cmd| cmd.get(1).copied());
        assert_eq!(
            last_signal,
            Some(AVDTP_SIGNAL_CLOSE),
            "disconnect from Connected must send exactly an AVDTP Close command"
        );
    }
}
