//! Mock modem transport for telephony unit testing.
//!
//! Provides [`MockModemTransport`] which records sent AT commands and replays
//! pre-configured responses. Used by telephony, SIM, and SMS test suites.

extern crate alloc;
use alloc::vec::Vec;

use crate::telephony::{ModemTransport, TelephonyError, MAX_LINE_LEN};

/// Mock modem transport for unit testing.
///
/// Records sent commands and replays pre-configured responses.
pub struct MockModemTransport {
    /// AT commands sent via `send_at`.
    pub sent_commands: Vec<Vec<u8>>,
    /// Response lines to return from `recv_line`, in FIFO order.
    pub response_lines: Vec<Vec<u8>>,
    /// URC lines to return from `poll_urc_line`, in FIFO order.
    pub urc_lines: Vec<Vec<u8>>,
    /// Whether send_at should succeed.
    pub send_ok: bool,
}

impl MockModemTransport {
    /// Create a new mock transport with all operations succeeding.
    pub fn new() -> Self {
        Self {
            sent_commands: Vec::new(),
            response_lines: Vec::new(),
            urc_lines: Vec::new(),
            send_ok: true,
        }
    }

    /// Queue a response line to be returned by `recv_line`.
    pub fn queue_response(&mut self, line: &[u8]) {
        self.response_lines.push(line.to_vec());
    }

    /// Queue a URC line to be returned by `poll_urc_line`.
    pub fn queue_urc(&mut self, line: &[u8]) {
        self.urc_lines.push(line.to_vec());
    }

    /// Queue a simple "OK" response.
    pub fn queue_ok(&mut self) {
        self.queue_response(b"OK");
    }

    /// Queue an info line followed by "OK".
    pub fn queue_info_ok(&mut self, info: &[u8]) {
        self.queue_response(info);
        self.queue_response(b"OK");
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
