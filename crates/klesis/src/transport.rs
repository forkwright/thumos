//! AT command transport layer and session management.
//!
//! [`ModemTransport`] abstracts the byte-stream channel to the modem (in
//! practice a CCCI char device such as `/dev/ccci_uart1`). [`AtSession`]
//! wraps a transport with the AT line protocol: it sends commands, collects
//! multi-line responses up to the final result code, and surfaces unsolicited
//! result codes (URCs).

use snafu::ensure;

use crate::at::{self, Response, Urc};
use crate::error::{NotReadySnafu, ParseSnafu, Result, TimeoutSnafu, UnexpectedResponseSnafu};

/// Maximum informational lines collected before a final result code, per
/// AT command.
///
/// SECURITY: the CCCI/AT channel is untrusted (rogue or malfunctioning
/// baseband). Without this bound, a modem that never returns a final
/// result code keeps `AtSession::send_command` looping forever and grows
/// its `info` `Vec` without bound -- a heap-exhaustion `DoS`. Mirrors
/// `wait_urc`'s `MAX_ATTEMPTS` below.
///
/// WHY: matches the kernel's `telephony::MAX_RESPONSE_LINES`, which was
/// deliberately narrowed from 64 (issue #282 finding 14) to shrink the
/// worst-case block time a modem pacing junk lines just under a command's
/// timeout can impose. A looser bound here would reopen that window on
/// this side of the split AT-parsing path.
const MAX_INFO_LINES: usize = 16;

/// Maximum bytes buffered for a single AT line before giving up.
///
/// SECURITY: bounds heap growth from a hostile/malfunctioning modem that
/// never emits `\n`. 256 bytes generously covers any real AT response.
const MAX_LINE_LEN: usize = 256;

/// Wall-clock budget for a single line, independent of byte count.
///
/// SECURITY: `MAX_LINE_LEN` alone bounds space, not time -- a byte trickle
/// that stays under the cap but never completes would otherwise block
/// `read_line` (and therefore the whole AT session) indefinitely. Shortened
/// under `#[cfg(test)]` so tests exercising this path stay fast.
#[cfg(not(test))]
const READ_LINE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
#[cfg(test)]
const READ_LINE_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(50);

// ─── Trait ────────────────────────────────────────────────────────────────────

/// Byte-stream transport to and FROM the modem.
///
/// Implementors map this onto a CCCI char device, a UART, or a test fixture.
pub(crate) trait ModemTransport {
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
pub(crate) struct CommandResponse {
    /// Informational text lines that preceded the final result code.
    ///
    /// For example, `AT+CSQ` returns `["+CSQ: 18,99"]` before `OK`.
    pub(crate) info: Vec<String>,
    /// Final result code (`OK`, `ERROR`, `+CME ERROR: n`, or `+CMS ERROR: n`).
    pub(crate) result: Response,
}

/// AT command session over a [`ModemTransport`].
///
/// Manages a byte receive buffer so that partial lines are preserved across
/// calls to [`AtSession::read_line`].
pub(crate) struct AtSession<T: ModemTransport> {
    transport: T,
    /// Bytes received but not yet consumed as a complete line.
    rx_buf: Vec<u8>,
}

impl<T: ModemTransport> AtSession<T> {
    /// Wrap a transport in an AT session.
    #[must_use]
    pub(crate) const fn new(transport: T) -> Self {
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
    /// - [`crate::error::Error::Timeout`] when a line does not complete
    ///   before [`READ_LINE_TIMEOUT`].
    pub(crate) fn send_command(&mut self, cmd: &str) -> Result<CommandResponse> {
        let frame = format!("{cmd}\r\n");
        self.transport.send(frame.as_bytes())?;

        let mut info = Vec::new();
        loop {
            ensure!(
                info.len() < MAX_INFO_LINES,
                UnexpectedResponseSnafu {
                    response: format!("no final result after {MAX_INFO_LINES} info lines")
                }
            );

            let line = self.read_line()?;
            if line.is_empty() {
                // Blank lines between echo and response are normal; skip them.
                continue;
            }
            if let Some(result) = at::parse_final_result(&line) {
                return Ok(CommandResponse { info, result });
            }
            info.push(line);
        }
    }

    /// Poll for the next unsolicited result code (URC).
    ///
    /// Reads lines FROM the transport and attempts to parse each one as a
    /// known URC. Non-URC lines (blank lines, unrecognised text) are
    /// skipped. This does NOT block waiting for bytes to arrive: a
    /// transport that currently has no data (`recv` returning `0`)
    /// surfaces immediately as [`crate::error::Error::NotReady`] -- callers
    /// running a scheduler/poll loop must retry the call, not assume it
    /// parks until a URC shows up.
    ///
    /// # Errors
    ///
    /// - [`crate::error::Error::NotReady`] when the transport currently has
    ///   no data available (transient; retry).
    /// - [`crate::error::Error::Ccci`] on a hard transport failure.
    /// - [`crate::error::Error::Parse`] on malformed line data.
    /// - [`crate::error::Error::Timeout`] when a line does not complete
    ///   before [`READ_LINE_TIMEOUT`].
    /// - [`crate::error::Error::UnexpectedResponse`] when `MAX_ATTEMPTS`
    ///   unmatched lines are read without finding a URC.
    pub(crate) fn wait_urc(&mut self) -> Result<Urc> {
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

            if let Some(urc) = at::parse_ring(&line) {
                return Ok(urc);
            }
            if let Ok((_, urc)) = at::parse_creg(&line) {
                return Ok(urc);
            }
            if let Ok((_, urc)) = at::parse_cmti(&line) {
                return Ok(urc);
            }
            if let Some((rssi, ber)) = at::parse_csq(&line) {
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
    /// - [`crate::error::Error::Parse`] on non-UTF-8 byte sequences or a line
    ///   exceeding [`MAX_LINE_LEN`].
    /// - [`crate::error::Error::Timeout`] when no complete line arrives
    ///   before [`READ_LINE_TIMEOUT`].
    fn read_line(&mut self) -> Result<String> {
        let deadline = std::time::Instant::now() + READ_LINE_TIMEOUT;
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

            if self.rx_buf.len() >= MAX_LINE_LEN {
                self.rx_buf.clear();
                return ParseSnafu {
                    message: format!("AT line exceeds maximum length ({MAX_LINE_LEN} bytes)"),
                }
                .fail();
            }
            if std::time::Instant::now() >= deadline {
                self.rx_buf.clear();
                return TimeoutSnafu {
                    // WHY try_from + saturate, not `as`: READ_LINE_TIMEOUT is
                    // a compile-time Duration (30s or the cfg(test) 50ms);
                    // try_from cannot fail for either, but a fallback keeps
                    // this total rather than reachable-panicking on a future
                    // constant change.
                    timeout_ms: u64::try_from(READ_LINE_TIMEOUT.as_millis()).unwrap_or(u64::MAX),
                }
                .fail();
            }

            let n = self.transport.recv(&mut byte)?;
            ensure!(n > 0, NotReadySnafu);
            // WHY: recv fills exactly byte[0] when n > 0; ensure!(n > 0) above
            // guarantees a valid byte exists.
            if let Some(b) = byte.first().copied() {
                self.rx_buf.push(b);
            }
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
                if let Some(byte) = self.inbound.pop_front() {
                    *b = byte;
                }
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
        let resp = session.send_command("AT+CSQ").unwrap_or_default();
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
        let resp = session.send_command("AT+CPIN?").unwrap_or_default();
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
        let sent = String::from_utf8(session.transport.outbound.clone()).unwrap_or_default();
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
    fn wait_urc_detects_cmti() {
        let transport = MockTransport::with_response(b"+CMTI: \"SM\",3\r\n");
        let mut session = AtSession::new(transport);
        let urc = session.wait_urc().unwrap_or_default();
        assert_eq!(
            urc,
            Urc::Cmti {
                storage: "SM".to_owned(),
                index: 3,
            },
            "URC must be Cmti(SM,3)"
        );
    }

    #[test]
    fn wait_urc_exhausts_max_attempts() {
        // WHY: MAX_ATTEMPTS bounds wait_urc against a modem that never
        // emits a recognised URC line, mirroring send_command's
        // MAX_INFO_LINES guard.
        let mut data = Vec::new();
        for _ in 0..1024 {
            data.extend_from_slice(b"\r\n");
        }
        let transport = MockTransport::with_response(&data);
        let mut session = AtSession::new(transport);
        let result = session.wait_urc();
        assert!(
            result.is_err(),
            "wait_urc must error after MAX_ATTEMPTS unmatched lines, not loop forever"
        );
    }

    #[test]
    fn at_session_skips_blank_lines() {
        // Modem may emit blank lines between response sections.
        let transport = MockTransport::with_response(b"\r\n\r\n+CSQ: 7,0\r\nOK\r\n");
        let mut session = AtSession::new(transport);
        let resp = session.send_command("AT+CSQ").unwrap_or_default();
        assert_eq!(resp.result, Response::Ok, "result must be OK");
        assert_eq!(
            resp.info.len(),
            1,
            "blank lines must not appear as info lines"
        );
    }

    #[test]
    fn send_command_bounds_info_lines_against_flood() {
        // 1000 info lines, never a final result code.
        let mut data = Vec::new();
        for _ in 0..1000 {
            data.extend_from_slice(b"+CSQ: 1,1\r\n");
        }
        let transport = MockTransport::with_response(&data);
        let mut session = AtSession::new(transport);
        let result = session.send_command("AT+CSQ");
        assert!(
            result.is_err(),
            "send_command must error rather than buffer 1000 info lines"
        );
    }

    #[test]
    fn send_command_bounds_matches_kernel_hardened_limit() {
        // WHY (#685): MAX_INFO_LINES was reconciled to the kernel's
        // MAX_RESPONSE_LINES = 16 (deliberately narrowed from 64 there, per
        // issue #282 finding 14, to shrink a modem's worst-case block-time
        // window). This exercises the boundary directly: a response with
        // one more info line than the hardened bound, followed by OK, must
        // still fail -- against the pre-reconciliation bound of 64 this
        // response fits comfortably and would have succeeded.
        let mut data = Vec::new();
        for _ in 0..17 {
            data.extend_from_slice(b"+CSQ: 1,1\r\n");
        }
        data.extend_from_slice(b"OK\r\n");
        let transport = MockTransport::with_response(&data);
        let mut session = AtSession::new(transport);
        let result = session.send_command("AT+CSQ");
        assert!(
            result.is_err(),
            "17 info lines must exceed the hardened 16-line bound shared with the kernel"
        );
    }

    #[test]
    fn send_command_errors_when_no_final_result_ever_arrives() {
        let mut data = Vec::new();
        for _ in 0..100 {
            data.extend_from_slice(b"+CSQ: 1,1\r\n");
        }
        let transport = MockTransport::with_response(&data);
        let mut session = AtSession::new(transport);
        let result = session.send_command("AT+CSQ");
        assert!(
            result.is_err(),
            "send_command must not loop indefinitely when no final result code arrives"
        );
    }

    #[test]
    fn read_line_rejects_oversized_line() {
        // No newline anywhere; stream exceeds MAX_LINE_LEN (256) bytes.
        let data = vec![b'X'; 300];
        let transport = MockTransport::with_response(&data);
        let mut session = AtSession::new(transport);
        let result = session.send_command("AT");
        assert!(
            result.is_err(),
            "a line exceeding MAX_LINE_LEN with no newline must error, not grow forever"
        );
    }

    #[test]
    fn read_line_times_out_on_slow_trickle() {
        // Yields one byte per call with a small real delay each time -- a
        // slow, steady trickle that never completes a line and never fills
        // MAX_LINE_LEN. Under the #[cfg(test)] short READ_LINE_TIMEOUT this
        // must return Err well before 1000 iterations could complete.
        struct SlowTrickle {
            remaining: u32,
        }
        impl ModemTransport for SlowTrickle {
            fn send(&mut self, _data: &[u8]) -> Result<()> {
                Ok(())
            }
            fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
                std::thread::sleep(std::time::Duration::from_millis(5)); // kanon:ignore TESTING/sleep-in-test -- exercises the real wall-clock READ_LINE_TIMEOUT deadline (read_line reads Instant::now() directly, no injectable clock); a 5ms/byte trickle against the cfg(test) 50ms timeout deterministically forces the timeout before the 1000-byte budget and keeps the test ~50ms
                if buf.is_empty() || self.remaining == 0 {
                    return Ok(0);
                }
                self.remaining -= 1;
                buf[0] = b'X'; // never '\n'
                Ok(1)
            }
        }

        let transport = SlowTrickle { remaining: 1000 };
        let mut session = AtSession::new(transport);
        let result = session.send_command("AT");
        // WHY a variant match, not a wall-clock bound: the structural
        // property under test is "the READ_LINE_TIMEOUT deadline branch
        // fired", not "the test finished quickly". `Error::Timeout` is only
        // reachable from that branch -- the 1000-byte budget (which would
        // instead surface `Error::NotReady` once SlowTrickle exhausts and
        // returns `Ok(0)`) is never reached at 5ms/byte against a 50ms
        // deadline, so this also proves the timeout fired well before the
        // budget, without measuring elapsed time to prove it.
        assert!(
            matches!(result, Err(crate::error::Error::Timeout { .. })),
            "a slow byte trickle that never completes a line must time out: {result:?}"
        );
    }
}
