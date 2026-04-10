//! AT command transport layer and session management.
//!
//! [`ModemTransport`] abstracts the byte-stream channel to the modem (in
//! practice a CCCI char device such as `/dev/ccci_uart1`). [`AtSession`]
//! wraps a transport with the AT line protocol: it sends commands, collects
//! multi-line responses up to the final result code, and surfaces unsolicited
//! result codes (URCs).

use snafu::ensure;

use crate::at::{self, Response, Urc};
use crate::error::{NotReadySnafu, ParseSnafu, Result, UnexpectedResponseSnafu};

// ─── Trait ────────────────────────────────────────────────────────────────────

/// Byte-stream transport to and FROM the modem.
///
/// Implementors map this onto a CCCI char device, a UART, or a test fixture.
pub trait ModemTransport {
    /// Write `data` to the modem.
    ///
    /// # Errors
    ///
    /// Returns an error when the underlying channel is unavailable or the
    /// write fails.
    fn send(&mut self, data: &[u8]) -> Result<()>;

    /// Read up to `buf.len()` bytes FROM the modem INTO `buf`.
    ///
    /// Returns the number of bytes actually read. Implementations may return
    /// `0` to signal a transient "no data" condition.
    ///
    /// # Errors
    ///
    /// Returns an error when the underlying channel is unavailable.
    fn recv(&mut self, buf: &mut [u8]) -> Result<usize>;
}

// ─── Types ────────────────────────────────────────────────────────────────────

/// The full response to a single AT command: zero or more informational lines
/// followed by a final result code.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CommandResponse {
    /// Informational text lines that preceded the final result code.
    ///
    /// For example, `AT+CSQ` returns `["+CSQ: 18,99"]` before `OK`.
    pub info: Vec<String>,
    /// Final result code (`OK`, `ERROR`, `+CME ERROR: n`, or `+CMS ERROR: n`).
    pub result: Response,
}

/// AT command session over a [`ModemTransport`].
///
/// Manages a byte receive buffer so that partial lines are preserved across
/// calls to [`AtSession::read_line`].
pub struct AtSession<T: ModemTransport> {
    transport: T,
    /// Bytes received but not yet consumed as a complete line.
    rx_buf: Vec<u8>,
}

impl<T: ModemTransport> AtSession<T> {
    /// Wrap a transport in an AT session.
    #[must_use]
    pub const fn new(transport: T) -> Self {
        Self {
            transport,
            rx_buf: Vec::new(),
        }
    }

    /// Send an AT command and collect the full response.
    ///
    /// Appends `\r\n` to `cmd`, writes it to the transport, then reads lines
    /// until a final result code (`OK`, `ERROR`, `+CME ERROR`, `+CMS ERROR`)
    /// is received. Any informational lines received before the result code
    /// are returned in [`CommandResponse::info`].
    ///
    /// # Errors
    ///
    /// - [`crate::error::Error::Ccci`] / [`crate::error::Error::NotReady`]
    ///   on transport failure.
    /// - [`crate::error::Error::Parse`] on malformed line data.
    pub fn send_command(&mut self, cmd: &str) -> Result<CommandResponse> {
        let frame = format!("{cmd}\r\n");
        self.transport.send(frame.as_bytes())?;

        let mut info = Vec::new();
        loop {
            let line = self.read_line()?;
            if line.is_empty() {
                // Blank lines between echo and response are normal; skip them.
                continue;
            }
            if let Ok((_, result)) = at::parse_final_result(&line) {
                return Ok(CommandResponse { info, result });
            }
            info.push(line);
        }
    }

    /// Block until the next unsolicited result code (URC) arrives.
    ///
    /// Reads lines FROM the transport and attempts to parse each one as a
    /// known URC. Non-URC lines (blank lines, unrecognised text) are skipped.
    ///
    /// # Errors
    ///
    /// - [`crate::error::Error::Ccci`] / [`crate::error::Error::NotReady`]
    ///   on transport failure.
    /// - [`crate::error::Error::Parse`] on malformed line data.
    /// - [`crate::error::Error::UnexpectedResponse`] when the transport
    ///   returns only empty data with no URC.
    pub fn wait_urc(&mut self) -> Result<Urc> {
        // Limit iterations so callers are not surprised by silent loops during
        // tests; real drivers would add a deadline here.
        const MAX_ATTEMPTS: usize = 1024;
        let mut attempts: usize = 0;
        loop {
            ensure!(
                attempts < MAX_ATTEMPTS,
                UnexpectedResponseSnafu {
                    response: "no URC received within attempt LIMIT".to_owned()
                }
            );
            attempts += 1;

            let line = self.read_line()?;
            if line.is_empty() {
                continue;
            }

            if let Ok((_, urc)) = at::parse_ring(&line) {
                return Ok(urc);
            }
            if let Ok((_, urc)) = at::parse_creg(&line) {
                return Ok(urc);
            }
            if let Ok((_, urc)) = at::parse_cmti(&line) {
                return Ok(urc);
            }
            if let Ok((_, (rssi, ber))) = at::parse_csq(&line) {
                return Ok(Urc::Csq { rssi, ber });
            }
            // Unrecognised line; keep reading.
        }
    }

    /// Read one CR/LF-terminated line FROM the transport.
    ///
    /// Bytes are appended to the internal receive buffer until `\n` is found,
    /// then the line is decoded as UTF-8 and returned without the terminator.
    ///
    /// # Errors
    ///
    /// - [`crate::error::Error::NotReady`] when the transport returns 0 bytes.
    /// - [`crate::error::Error::Parse`] on non-UTF-8 byte sequences.
    fn read_line(&mut self) -> Result<String> {
        let mut byte = [0u8; 1];
        loop {
            // Check if we already have a newline buffered.
            if let Some(pos) = self.rx_buf.iter().position(|&b| b == b'\n') {
                let mut line = self.rx_buf.drain(..=pos).collect::<Vec<u8>>();
                // Drop the \n (and optional preceding \r).
                line.pop();
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                return String::from_utf8(line).map_err(|e| {
                    ParseSnafu {
                        message: format!("non-UTF-8 AT line: {e}"),
                    }
                    .build()
                });
            }
            let n = self.transport.recv(&mut byte)?;
            ensure!(n > 0, NotReadySnafu);
            self.rx_buf.push(byte.first().copied().unwrap_or_default());
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;
    use crate::at::RegStatus;

    // ── Mock transport ──────────────────────────────────────────────────────

    struct MockTransport {
        /// Bytes the modem would send back, pre-loaded in FIFO ORDER.
        inbound: VecDeque<u8>,
        /// Bytes received FROM the AP (captured for inspection).
        outbound: Vec<u8>,
    }

    impl MockTransport {
        fn with_response(data: &[u8]) -> Self {
            Self {
                inbound: VecDeque::from(data.to_vec()),
                outbound: Vec::new(),
            }
        }
    }

    impl ModemTransport for MockTransport {
        fn send(&mut self, data: &[u8]) -> Result<()> {
            self.outbound.extend_from_slice(data);
            Ok(())
        }

        fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
            let n = buf.len().min(self.inbound.len());
            for b in buf.iter_mut().take(n) {
                *b = self.inbound.pop_front().unwrap_or_default();
            }
            Ok(n)
        }
    }

    // ── Tests ───────────────────────────────────────────────────────────────

    #[test]
    fn at_session_simple_ok_response() {
        // Modem echoes nothing and responds with OK.
        let transport = MockTransport::with_response(b"OK\r\n");
        let mut session = AtSession::new(transport);
        let resp = session.send_command("AT").unwrap_or_default();
        assert_eq!(resp.result, Response::Ok, "result must be OK");
        assert!(resp.info.is_empty(), "no info lines expected for bare AT");
    }

    #[test]
    fn at_session_multi_line_response() {
        // AT+CSQ returns an info line then OK.
        let transport = MockTransport::with_response(b"+CSQ: 18,99\r\nOK\r\n");
        let mut session = AtSession::new(transport);
        let resp = session
            .send_command("AT+CSQ")
            .unwrap_or_default();
        assert_eq!(resp.result, Response::Ok, "result must be OK");
        assert_eq!(resp.info.len(), 1, "one info line expected");
        assert_eq!(
            resp.info.first().map_or("", String::as_str),
            "+CSQ: 18,99",
            "info line must match modem output"
        );
    }

    #[test]
    fn at_session_cme_error_response() {
        let transport = MockTransport::with_response(b"+CME ERROR: 10\r\n");
        let mut session = AtSession::new(transport);
        let resp = session
            .send_command("AT+CPIN?")
            .unwrap_or_default();
        assert_eq!(
            resp.result,
            Response::CmeError(10),
            "CME error code must be preserved"
        );
    }

    #[test]
    fn at_session_sends_crlf_terminated_command() {
        let transport = MockTransport::with_response(b"OK\r\n");
        let mut session = AtSession::new(transport);
        session.send_command("AT+CSQ").unwrap_or_default();
        let sent = String::from_utf8(session.transport.outbound.clone())
            .unwrap_or_default();
        assert!(
            sent.ends_with("\r\n"),
            "command must be terminated with CR LF, got: {sent:?}"
        );
    }

    #[test]
    fn wait_urc_detects_ring() {
        let transport = MockTransport::with_response(b"RING\r\n");
        let mut session = AtSession::new(transport);
        let urc = session.wait_urc().unwrap_or_default();
        assert_eq!(urc, Urc::Ring, "URC must be Ring");
    }

    #[test]
    fn wait_urc_detects_creg() {
        let transport = MockTransport::with_response(b"+CREG: 1\r\n");
        let mut session = AtSession::new(transport);
        let urc = session.wait_urc().unwrap_or_default();
        assert_eq!(
            urc,
            Urc::Creg {
                stat: RegStatus::RegisteredHome,
                lac: None,
                ci: None,
            },
            "URC must be Creg(RegisteredHome)"
        );
    }

    #[test]
    fn at_session_skips_blank_lines() {
        // Modem may emit blank lines between response sections.
        let transport = MockTransport::with_response(b"\r\n\r\n+CSQ: 7,0\r\nOK\r\n");
        let mut session = AtSession::new(transport);
        let resp = session
            .send_command("AT+CSQ")
            .unwrap_or_default();
        assert_eq!(resp.result, Response::Ok, "result must be OK");
        assert_eq!(
            resp.info.len(),
            1,
            "blank lines must not appear as info lines"
        );
    }
}
