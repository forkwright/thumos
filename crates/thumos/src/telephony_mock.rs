//! Mock modem transport for telephony unit testing.
//!
//! Provides [`MockModemTransport`] which records sent AT commands and replays
//! pre-configured responses. Used by telephony, SIM, and SMS test suites.

extern crate alloc;
use alloc::vec::Vec;

use crate::telephony::{MAX_LINE_LEN, ModemTransport, TelephonyError};

/// Mock modem transport for unit testing.
///
/// Records sent commands and replays pre-configured responses.
pub(crate) struct MockModemTransport {
    /// AT commands sent via `send_at`.
    pub sent_commands: Vec<Vec<u8>>,
    /// Response lines to return from `recv_line`, in FIFO order.
    pub response_lines: Vec<Vec<u8>>,
    /// URC lines to return from `poll_urc_line`, in FIFO order.
    pub urc_lines: Vec<Vec<u8>>,
    /// Whether send_at should succeed.
    pub send_ok: bool,
    /// Number of upcoming `recv_line` calls that must fail with
    /// `TransportError` regardless of queued lines, decrementing on each
    /// call. Simulates a transient failure (e.g. a real-hardware timeout
    /// that races a response already in flight) independent of whether a
    /// response is queued -- see `fail_next_recv`.
    pub inject_recv_failures: usize,
}

impl MockModemTransport {
    /// Create a new mock transport with all operations succeeding.
    pub(crate) fn new() -> Self {
        Self {
            sent_commands: Vec::new(),
            response_lines: Vec::new(),
            urc_lines: Vec::new(),
            send_ok: true,
            inject_recv_failures: 0,
        }
    }

    /// Make the next `n` `recv_line` calls fail with `TransportError`,
    /// regardless of queued response lines.
    pub(crate) fn fail_next_recv(&mut self, n: usize) {
        self.inject_recv_failures = n;
    }

    /// Queue a response line to be returned by `recv_line`.
    pub(crate) fn queue_response(&mut self, line: &[u8]) {
        self.response_lines.push(line.to_vec());
    }

    /// Queue a URC line to be returned by `poll_urc_line`.
    pub(crate) fn queue_urc(&mut self, line: &[u8]) {
        self.urc_lines.push(line.to_vec());
    }

    /// Queue a simple "OK" response.
    pub(crate) fn queue_ok(&mut self) {
        self.queue_response(b"OK");
    }

    /// Queue an info line followed by "OK".
    pub(crate) fn queue_info_ok(&mut self, info: &[u8]) {
        self.queue_response(info);
        self.queue_response(b"OK");
    }

    /// A mock pre-seeded with the full successful 10-step `Telephony::initialize`
    /// AT sequence (#398): registers home on a LTE-only network with a READY
    /// SIM. Lets a qemu kernel bring up a real, initialized Telephony stack
    /// (the non-test analogue of the test-only `mock_for_init`).
    #[cfg(feature = "qemu")]
    pub(crate) fn seeded_for_boot() -> Self {
        let mut mock = Self::new();
        mock.queue_ok(); // 1: AT
        mock.queue_ok(); // 2: ATE0
        mock.queue_ok(); // 3: AT+CFUN=1
        mock.queue_info_ok(b"+CPIN: READY"); // 4: AT+CPIN?
        mock.queue_ok(); // 5: AT+COPS=0,,,7 (LTE only / refuse 2G)
        mock.queue_info_ok(b"+COPS: 0,0,\"T-Mobile\""); // 6: AT+COPS?
        mock.queue_ok(); // 7: AT+CREG=1
        mock.queue_ok(); // 8: AT+CLIP=1
        mock.queue_info_ok(b"+CSQ: 18,99"); // 9: AT+CSQ
        // 10: AT+CREG? (registered home on E-UTRAN/LTE, <AcT>=7) -- the <AcT>
        // field lets a booted qemu kernel exercise the RAT-parsing path so the
        // status bar's network label is RAT-derived, not hardcoded.
        mock.queue_info_ok(b"+CREG: 1,1,\"1A2B\",\"0100CE01\",7");
        // A queued ICCID response for the boot-time SimManager query (#398).
        mock.queue_info_ok(b"+ICCID: 8901410321111851072");
        // Post-init responses for the boot-time SIM-management smoke (#398), in
        // the order sim_sms_boot_smoke queries them over the same transport:
        // check_pin (AT+CPIN?), poll_signal->query_signal (AT+CSQ), and
        // query_operator (AT+COPS?).
        mock.queue_info_ok(b"+CPIN: READY");
        mock.queue_info_ok(b"+CSQ: 18,99");
        mock.queue_info_ok(b"+COPS: 0,0,\"T-Mobile\"");
        // Post-init responses for the boot-time SMS-send smoke (#398): the
        // AT+CMGS PDU-mode send sequence -- AT+CMGF=0 -> OK, AT+CMGS=<len> -> '>'
        // prompt, then PDU+Ctrl-Z -> +CMGS reference + OK.
        mock.queue_response(b"OK");
        mock.queue_response(b">");
        mock.queue_info_ok(b"+CMGS: 42");
        // A queued RING URC so a booted qemu kernel exercises the incoming-call
        // -> ringtone-audio integration path (#398): poll() surfaces it as an
        // IncomingCall event after init.
        mock.queue_urc(b"RING");
        mock
    }
}

impl ModemTransport for MockModemTransport {
    fn send_at(&mut self, command: &str) -> Result<(), TelephonyError> {
        if !self.send_ok {
            return Err(TelephonyError::TransportError);
        }
        self.sent_commands.push(command.as_bytes().to_vec());
        Ok(())
    }

    fn recv_line(
        &mut self,
        buf: &mut [u8; MAX_LINE_LEN],
        _timeout_ms: u32,
    ) -> Result<usize, TelephonyError> {
        if self.inject_recv_failures > 0 {
            self.inject_recv_failures -= 1;
            return Err(TelephonyError::TransportError);
        }
        if let Some(line) = self.response_lines.first() {
            let len = line.len().min(MAX_LINE_LEN);
            buf[..len].copy_from_slice(&line[..len]);
            self.response_lines.remove(0);
            Ok(len)
        } else {
            Err(TelephonyError::Timeout)
        }
    }

    fn poll_urc_line(&mut self, buf: &mut [u8; MAX_LINE_LEN]) -> Option<usize> {
        if let Some(line) = self.urc_lines.first() {
            let len = line.len().min(MAX_LINE_LEN);
            buf[..len].copy_from_slice(&line[..len]);
            self.urc_lines.remove(0);
            Some(len)
        } else {
            None
        }
    }
}
