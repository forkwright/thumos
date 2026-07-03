//! Minimal HTTP/1.1 client — transport layer only.
//!
//! Builds and parses HTTP/1.1 wire format for the Matrix Client-Server API.
//! This module does **not** perform TCP I/O. It serializes [`HttpRequest`]
//! into bytes for the caller to send via smoltcp TCP sockets, and parses
//! raw bytes from the network into [`HttpResponse`].
//!
//! # Architecture
//!
//! Same pattern as `dns.rs` and `dns_tls.rs`: raw protocol over the kernel's
//! network stack. The caller (future `harmostes` module) manages the TCP
//! connection lifecycle — connect, send request bytes, receive response
//! bytes, close. This module only handles serialization/deserialization.
//!
//! # Supported features
//!
//! - HTTP/1.1 request serialization (GET, POST, PUT, DELETE)
//! - HTTP/1.1 response parsing (status line, headers, body)
//! - Content-Length–based body framing (chunked transfer not implemented)
//! - Helper constructors for common Matrix API request shapes
//!
//! # Limitations
//!
//! - No chunked transfer-encoding (Matrix homeservers use Content-Length)
//! - No HTTP/2 or connection upgrade (WebSocket deferred to Wave 6)
//! - No redirect following (Matrix CS API doesn't redirect)
//! - No cookie handling

// WHY: HTTP client created in Phase 09 Wave 1, integration pending in Wave 2.
#![expect(
    dead_code,
    reason = "HTTP client created in Phase 09 Wave 1, harmostes integration pending"
)]

extern crate alloc;

use core::fmt;

use alloc::string::String;
use alloc::vec::Vec;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// HTTP version string used in request lines.
const HTTP_VERSION: &str = "HTTP/1.1";

/// Default Content-Type for JSON request bodies.
const CONTENT_TYPE_JSON: &str = "application/json";

/// Carriage-return + line-feed, the HTTP line terminator.
const CRLF: &[u8] = b"\r\n";

/// Maximum number of headers we will parse from a response.
/// Prevents unbounded allocation from a malicious server.
const MAX_RESPONSE_HEADERS: usize = 64;

/// Maximum response header block size (before body). 16 KiB is generous
/// for Matrix CS API responses, which have small header sets.
const MAX_HEADER_BLOCK_SIZE: usize = 16_384;

/// Maximum response body size. 1 MiB covers large sync responses.
/// Callers needing more must stream in chunks (not yet implemented).
const MAX_BODY_SIZE: usize = 1_048_576;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors from HTTP request building and response parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HttpError {
    /// The response data is incomplete — needs more bytes.
    Incomplete,
    /// The status line is missing or malformed.
    MalformedStatusLine,
    /// A header line is malformed (missing `:` separator).
    MalformedHeader,
    /// The status code is not a valid 3-digit number.
    InvalidStatusCode,
    /// Too many headers in the response (exceeds [`MAX_RESPONSE_HEADERS`]).
    TooManyHeaders,
    /// The header block exceeds [`MAX_HEADER_BLOCK_SIZE`].
    HeaderBlockTooLarge,
    /// The Content-Length value is not a valid number.
    InvalidContentLength,
    /// The response body exceeds [`MAX_BODY_SIZE`].
    BodyTooLarge,
    /// The host field in a request is empty.
    EmptyHost,
    /// The path field in a request is empty.
    EmptyPath,
    /// The path field contains a CR or LF byte (CRLF/header injection).
    InvalidPath,
    /// The host field contains a CR or LF byte (CRLF/header injection).
    InvalidHost,
    /// A header name or value contains a CR or LF byte (CRLF/header
    /// injection).
    InvalidHeader,
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Incomplete => write!(f, "incomplete HTTP response"),
            Self::MalformedStatusLine => write!(f, "malformed HTTP status line"),
            Self::MalformedHeader => write!(f, "malformed HTTP header"),
            Self::InvalidStatusCode => write!(f, "invalid HTTP status code"),
            Self::TooManyHeaders => write!(f, "too many response headers"),
            Self::HeaderBlockTooLarge => write!(f, "header block too large"),
            Self::InvalidContentLength => write!(f, "invalid Content-Length value"),
            Self::BodyTooLarge => write!(f, "response body too large"),
            Self::EmptyHost => write!(f, "empty host in HTTP request"),
            Self::EmptyPath => write!(f, "empty path in HTTP request"),
            Self::InvalidPath => write!(f, "path contains CR or LF (CRLF injection)"),
            Self::InvalidHost => write!(f, "host contains CR or LF (CRLF injection)"),
            Self::InvalidHeader => write!(f, "header contains CR or LF (CRLF injection)"),
        }
    }
}

// ---------------------------------------------------------------------------
// HTTP method
// ---------------------------------------------------------------------------

/// HTTP request methods supported by the Matrix CS API client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HttpMethod {
    /// GET — retrieve a resource.
    Get,
    /// POST — create or submit data.
    Post,
    /// PUT — create or replace a resource (Matrix uses PUT for sending events).
    Put,
    /// DELETE — remove a resource.
    Delete,
}

impl HttpMethod {
    /// Return the method as its HTTP wire-format string.
    fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
        }
    }
}

impl fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// HTTP request
// ---------------------------------------------------------------------------

/// An HTTP/1.1 request, ready to be serialized to wire format.
///
/// The caller builds an `HttpRequest`, calls [`build_raw`](Self::build_raw)
/// to get the bytes, and sends them over a TCP socket. This struct does not
/// own a connection.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct HttpRequest {
    /// The HTTP method (GET, POST, PUT, DELETE).
    pub method: HttpMethod,
    /// The request path (e.g., `/_matrix/client/v3/sync`).
    pub path: String,
    /// The Host header value (e.g., `matrix.example.com`).
    pub host: String,
    /// Additional headers as (name, value) pairs.
    pub headers: Vec<(String, String)>,
    /// Optional request body (for POST/PUT).
    pub body: Option<Vec<u8>>,
}

/// Return true if `s` contains a bare CR (`\r`) or LF (`\n`) byte.
///
/// WHY: any caller-supplied field written into the HTTP wire buffer
/// without this check enables CRLF/header injection (CWE-93) — see
/// issue #289.
fn contains_crlf(s: &str) -> bool {
    s.bytes().any(|b| b == b'\r' || b == b'\n')
}

impl HttpRequest {
    /// Create a new request with the given method, host, and path.
    ///
    /// Headers and body start empty. Use the builder methods or set
    /// fields directly to add them.
    #[must_use]
    pub(crate) fn new(method: HttpMethod, host: String, path: String) -> Self {
        Self {
            method,
            path,
            host,
            headers: Vec::new(),
            body: None,
        }
    }

    /// Add a header to the request.
    pub(crate) fn add_header(&mut self, name: String, value: String) {
        self.headers.push((name, value));
    }

    /// Set the request body.
    pub(crate) fn set_body(&mut self, body: Vec<u8>) {
        self.body = Some(body);
    }

    /// Serialize this request to HTTP/1.1 wire format.
    ///
    /// Produces bytes like:
    /// ```text
    /// GET /_matrix/client/v3/sync HTTP/1.1\r\n
    /// Host: matrix.example.com\r\n
    /// Content-Length: 42\r\n
    /// \r\n
    /// <body>
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`HttpError::EmptyHost`] if `self.host` is empty, or
    /// [`HttpError::EmptyPath`] if `self.path` is empty.
    #[must_use]
    pub(crate) fn build_raw(&self) -> Result<Vec<u8>, HttpError> {
        if self.host.is_empty() {
            return Err(HttpError::EmptyHost);
        }
        if self.path.is_empty() {
            return Err(HttpError::EmptyPath);
        }
        // WHY: reject CR/LF in any caller-supplied field before it is
        // written to the wire buffer. An untrusted value (e.g. a Matrix
        // room ID from a hostile homeserver) containing "\r\n" could
        // otherwise inject additional request headers (CWE-93, #289).
        if contains_crlf(&self.path) {
            return Err(HttpError::InvalidPath);
        }
        if contains_crlf(&self.host) {
            return Err(HttpError::InvalidHost);
        }
        for (name, value) in &self.headers {
            if contains_crlf(name) || contains_crlf(value) {
                return Err(HttpError::InvalidHeader);
            }
        }

        // Estimate capacity: request line + host header + other headers + body.
        let body_len = self.body.as_ref().map_or(0, Vec::len);
        let estimated = 128 + self.headers.len() * 64 + body_len;
        let mut buf = Vec::with_capacity(estimated);

        // Request line: METHOD /path HTTP/1.1\r\n
        buf.extend_from_slice(self.method.as_str().as_bytes());
        buf.push(b' ');
        buf.extend_from_slice(self.path.as_bytes());
        buf.push(b' ');
        buf.extend_from_slice(HTTP_VERSION.as_bytes());
        buf.extend_from_slice(CRLF);

        // Host header (always first, per HTTP/1.1 spec).
        buf.extend_from_slice(b"Host: ");
        buf.extend_from_slice(self.host.as_bytes());
        buf.extend_from_slice(CRLF);

        // Content-Length if there is a body, but only if not already
        // specified in custom headers.
        let has_content_length = self
            .headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("content-length"));

        if body_len > 0 && !has_content_length {
            buf.extend_from_slice(b"Content-Length: ");
            write_usize_to_buf(&mut buf, body_len);
            buf.extend_from_slice(CRLF);
        }

        // Additional headers.
        for (name, value) in &self.headers {
            buf.extend_from_slice(name.as_bytes());
            buf.extend_from_slice(b": ");
            buf.extend_from_slice(value.as_bytes());
            buf.extend_from_slice(CRLF);
        }

        // End of headers.
        buf.extend_from_slice(CRLF);

        // Body (if present).
        if let Some(body) = &self.body {
            buf.extend_from_slice(body);
        }

        Ok(buf)
    }
}

impl fmt::Display for HttpRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {}", self.method, self.path, HTTP_VERSION)
    }
}

// ---------------------------------------------------------------------------
// HTTP response
// ---------------------------------------------------------------------------

/// A parsed HTTP/1.1 response.
///
/// Produced by [`HttpResponse::parse`] from raw response bytes received
/// over a TCP socket. The caller is responsible for accumulating enough
/// bytes before calling parse (the parser returns [`HttpError::Incomplete`]
/// if the headers or body are not fully received).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct HttpResponse {
    /// The HTTP status code (e.g., 200, 401, 429).
    pub status: u16,
    /// Response headers as (name, value) pairs, in wire order.
    pub headers: Vec<(String, String)>,
    /// The response body (may be empty).
    pub body: Vec<u8>,
    /// Total bytes consumed from the raw input by [`parse`](Self::parse)
    /// (header block + `\r\n\r\n` + body). Backing store for
    /// [`total_bytes`](Self::total_bytes).
    pub(crate) consumed: usize,
}

impl HttpResponse {
    /// Parse a complete HTTP/1.1 response from raw bytes.
    ///
    /// Expects the full response (headers + body) in `data`. Uses
    /// Content-Length to determine body extent. If Content-Length is
    /// absent, the body is assumed to be everything after the header
    /// block (connection-close semantics).
    ///
    /// # Errors
    ///
    /// - [`HttpError::Incomplete`] — the header block is not fully received
    ///   (no `\r\n\r\n` found).
    /// - [`HttpError::MalformedStatusLine`] — the status line cannot be
    ///   parsed.
    /// - [`HttpError::InvalidStatusCode`] — the status code is not a
    ///   3-digit number.
    /// - [`HttpError::MalformedHeader`] — a header line has no `:`.
    /// - [`HttpError::TooManyHeaders`] — more than [`MAX_RESPONSE_HEADERS`].
    /// - [`HttpError::HeaderBlockTooLarge`] — header block exceeds limit.
    /// - [`HttpError::InvalidContentLength`] — Content-Length is not a
    ///   valid number.
    /// - [`HttpError::BodyTooLarge`] — body exceeds [`MAX_BODY_SIZE`].
    #[must_use]
    pub(crate) fn parse(data: &[u8]) -> Result<Self, HttpError> {
        // Find the end of the header block: \r\n\r\n.
        let header_end = find_header_end(data).ok_or(HttpError::Incomplete)?;

        if header_end > MAX_HEADER_BLOCK_SIZE {
            return Err(HttpError::HeaderBlockTooLarge);
        }

        let header_block = &data[..header_end];
        let body_start = header_end + 4; // Skip \r\n\r\n.

        // Parse the status line (first line).
        let (status, first_line_end) = parse_status_line(header_block)?;

        // Parse headers (remaining lines).
        let headers = parse_headers(&header_block[first_line_end..])?;

        // Determine body length from Content-Length header.
        let content_length = find_content_length(&headers)?;

        let body = match content_length {
            Some(len) => {
                if len > MAX_BODY_SIZE {
                    return Err(HttpError::BodyTooLarge);
                }
                let available = data.len().saturating_sub(body_start);
                if available < len {
                    return Err(HttpError::Incomplete);
                }
                data[body_start..body_start + len].to_vec()
            }
            None => {
                // No Content-Length: treat remaining data as body
                // (connection-close framing).
                let remaining = &data[body_start..];
                if remaining.len() > MAX_BODY_SIZE {
                    return Err(HttpError::BodyTooLarge);
                }
                remaining.to_vec()
            }
        };

        let consumed = body_start + body.len();

        Ok(Self {
            status,
            headers,
            body,
            consumed,
        })
    }

    /// Return the value of the first header matching `name` (case-insensitive).
    ///
    /// Returns `None` if no matching header exists.
    #[must_use]
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Return the Content-Length value, if present and valid.
    #[must_use]
    pub(crate) fn content_length(&self) -> Option<usize> {
        self.header("content-length")
            .and_then(|v| v.trim().parse::<usize>().ok())
    }

    /// Return true if the response indicates success (2xx status).
    #[must_use]
    pub(crate) fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// Return the body as a UTF-8 string, if valid.
    #[must_use]
    pub(crate) fn body_as_str(&self) -> Option<&str> {
        core::str::from_utf8(&self.body).ok()
    }

    /// Total bytes consumed by this response (headers + body).
    ///
    /// Useful for the caller to know how many bytes to drain from
    /// the receive buffer after a successful parse.
    #[must_use]
    pub(crate) fn total_bytes(&self) -> usize {
        self.consumed
    }
}

impl fmt::Display for HttpResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HTTP {} ({} bytes body)", self.status, self.body.len())
    }
}

// ---------------------------------------------------------------------------
// Convenience constructors
// ---------------------------------------------------------------------------

/// Build a GET request for the given host and path.
///
/// The request has no body and includes only the Host header.
/// The caller can add Authorization or other headers before
/// calling [`HttpRequest::build_raw`].
#[must_use]
pub(crate) fn get(host: &str, path: &str) -> HttpRequest {
    HttpRequest::new(HttpMethod::Get, String::from(host), String::from(path))
}

/// Build a POST request with a JSON body.
///
/// Sets `Content-Type: application/json` automatically.
#[must_use]
pub(crate) fn post_json(host: &str, path: &str, body: &[u8]) -> HttpRequest {
    let mut req = HttpRequest::new(HttpMethod::Post, String::from(host), String::from(path));
    req.add_header(
        String::from("Content-Type"),
        String::from(CONTENT_TYPE_JSON),
    );
    req.set_body(body.to_vec());
    req
}

/// Build a PUT request with a JSON body.
///
/// Sets `Content-Type: application/json` automatically.
/// Matrix uses PUT for sending room events (m.room.message).
#[must_use]
pub(crate) fn put_json(host: &str, path: &str, body: &[u8]) -> HttpRequest {
    let mut req = HttpRequest::new(HttpMethod::Put, String::from(host), String::from(path));
    req.add_header(
        String::from("Content-Type"),
        String::from(CONTENT_TYPE_JSON),
    );
    req.set_body(body.to_vec());
    req
}

/// Build a DELETE request for the given host and path.
///
/// No body. Used for Matrix room leave, etc.
#[must_use]
pub(crate) fn delete(host: &str, path: &str) -> HttpRequest {
    HttpRequest::new(HttpMethod::Delete, String::from(host), String::from(path))
}

/// Build a request with a Bearer token Authorization header.
///
/// Convenience for Matrix CS API calls that require an access token.
/// Modifies `req` in-place and returns it for chaining.
pub(crate) fn with_auth(req: &mut HttpRequest, token: &str) {
    let mut value = String::from("Bearer ");
    value.push_str(token);
    req.add_header(String::from("Authorization"), value);
}

// ---------------------------------------------------------------------------
// Internal parsing helpers
// ---------------------------------------------------------------------------

/// Find the position of `\r\n\r\n` in `data`, which marks the end of
/// the HTTP header block. Returns the index of the first `\r` in the
/// terminating sequence.
fn find_header_end(data: &[u8]) -> Option<usize> {
    if data.len() < 4 {
        return None;
    }
    for i in 0..data.len() - 3 {
        if data[i] == b'\r' && data[i + 1] == b'\n' && data[i + 2] == b'\r' && data[i + 3] == b'\n'
        {
            return Some(i);
        }
    }
    None
}

/// Parse the HTTP status line and return (status_code, bytes_consumed).
///
/// Expects: `HTTP/1.1 200 OK\r\n` (or similar).
/// The bytes_consumed includes the trailing `\r\n`.
fn parse_status_line(header_block: &[u8]) -> Result<(u16, usize), HttpError> {
    // Find the first \r\n — that's the end of the status line.
    let line_end = find_crlf(header_block).ok_or(HttpError::MalformedStatusLine)?;
    let line = &header_block[..line_end];

    // Status line format: HTTP/1.x SP status-code SP reason-phrase
    // We need at least "HTTP/1.x 200" = 12 characters.
    if line.len() < 12 {
        return Err(HttpError::MalformedStatusLine);
    }

    // Verify it starts with HTTP/
    if !line.starts_with(b"HTTP/") {
        return Err(HttpError::MalformedStatusLine);
    }

    // Find the first space (after HTTP/1.x).
    let first_space = memchr_byte(b' ', line).ok_or(HttpError::MalformedStatusLine)?;

    // Status code is the 3 characters after the first space.
    let code_start = first_space + 1;
    if code_start + 3 > line.len() {
        return Err(HttpError::MalformedStatusLine);
    }

    let code_bytes = &line[code_start..code_start + 3];
    let status = parse_u16_from_ascii(code_bytes).ok_or(HttpError::InvalidStatusCode)?;

    // Validation check: HTTP status codes are 100-599.
    if !(100..=599).contains(&status) {
        return Err(HttpError::InvalidStatusCode);
    }

    // Consumed: line + \r\n.
    Ok((status, line_end + 2))
}

/// Parse header lines from the header block (after the status line).
///
/// Each line is `Name: Value\r\n`. Leading/trailing whitespace on values
/// is trimmed per HTTP spec.
fn parse_headers(data: &[u8]) -> Result<Vec<(String, String)>, HttpError> {
    let mut headers = Vec::new();
    let mut pos = 0;

    while pos < data.len() {
        // Skip leading \r\n if present (between headers).
        if data[pos..].starts_with(CRLF) {
            pos += 2;
            continue;
        }

        // Find end of this header line.
        let line_end = match find_crlf(&data[pos..]) {
            Some(offset) => pos + offset,
            None => data.len(), // Last line without \r\n.
        };

        let line = &data[pos..line_end];
        if line.is_empty() {
            pos = line_end + 2;
            continue;
        }

        // Find the colon separator.
        let colon = memchr_byte(b':', line).ok_or(HttpError::MalformedHeader)?;
        if colon == 0 {
            return Err(HttpError::MalformedHeader);
        }

        let name = core::str::from_utf8(&line[..colon]).map_err(|_| HttpError::MalformedHeader)?;
        let value_bytes = &line[colon + 1..];
        let value = core::str::from_utf8(value_bytes).map_err(|_| HttpError::MalformedHeader)?;

        headers.push((String::from(name.trim()), String::from(value.trim())));

        if headers.len() > MAX_RESPONSE_HEADERS {
            return Err(HttpError::TooManyHeaders);
        }

        pos = if line_end + 2 <= data.len() {
            line_end + 2
        } else {
            data.len()
        };
    }

    Ok(headers)
}

/// Find the Content-Length value from parsed headers.
///
/// Returns `None` if the header is not present. Returns an error if
/// the value is present but not a valid number.
fn find_content_length(headers: &[(String, String)]) -> Result<Option<usize>, HttpError> {
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("content-length") {
            let len: usize = value
                .trim()
                .parse()
                .map_err(|_| HttpError::InvalidContentLength)?;
            return Ok(Some(len));
        }
    }
    Ok(None)
}

/// Find the first `\r\n` in `data` and return its offset.
fn find_crlf(data: &[u8]) -> Option<usize> {
    if data.len() < 2 {
        return None;
    }
    for i in 0..data.len() - 1 {
        if data[i] == b'\r' && data[i + 1] == b'\n' {
            return Some(i);
        }
    }
    None
}

/// Find the first occurrence of `needle` in `haystack`.
fn memchr_byte(needle: u8, haystack: &[u8]) -> Option<usize> {
    haystack.iter().position(|&b| b == needle)
}

/// Parse a 3-digit ASCII number into a u16.
fn parse_u16_from_ascii(bytes: &[u8]) -> Option<u16> {
    if bytes.len() != 3 {
        return None;
    }
    let h = digit_value(bytes[0])?;
    let t = digit_value(bytes[1])?;
    let o = digit_value(bytes[2])?;
    Some(h * 100 + t * 10 + o)
}

/// Convert an ASCII digit byte to its numeric value.
fn digit_value(b: u8) -> Option<u16> {
    if b.is_ascii_digit() {
        Some(u16::from(b - b'0'))
    } else {
        None
    }
}

/// Write a usize as ASCII decimal digits into a byte buffer.
/// WHY: no_std environment — we can't use format!() in the hot path
/// of request serialization without pulling in alloc::format.
fn write_usize_to_buf(buf: &mut Vec<u8>, mut n: usize) {
    if n == 0 {
        buf.push(b'0');
        return;
    }
    // Write digits in reverse, then reverse the appended slice.
    let start = buf.len();
    while n > 0 {
        buf.push(b'0' + (n % 10) as u8);
        n /= 10;
    }
    buf[start..].reverse();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;

    // -- HttpMethod Display --

    #[test]
    fn method_display() {
        assert_eq!(HttpMethod::Get.to_string(), "GET");
        assert_eq!(HttpMethod::Post.to_string(), "POST");
        assert_eq!(HttpMethod::Put.to_string(), "PUT");
        assert_eq!(HttpMethod::Delete.to_string(), "DELETE");
    }

    // -- HttpRequest::build_raw --

    #[test]
    fn build_get_request() {
        let req = get("matrix.example.com", "/_matrix/client/v3/sync");
        let raw = req.build_raw();
        assert!(raw.is_ok());
        let raw = raw.ok().unwrap(); // ok: test
        let text = core::str::from_utf8(&raw).ok().unwrap(); // ok: test

        assert!(text.starts_with("GET /_matrix/client/v3/sync HTTP/1.1\r\n"));
        assert!(text.contains("Host: matrix.example.com\r\n"));
        assert!(text.ends_with("\r\n\r\n")); // No body.
    }

    #[test]
    fn build_post_json_request() {
        let body = b"{\"user\":\"@alice:example.com\"}";
        let req = post_json("matrix.example.com", "/_matrix/client/v3/login", body);
        let raw = req.build_raw();
        assert!(raw.is_ok());
        let raw = raw.ok().unwrap(); // ok: test
        let text = core::str::from_utf8(&raw).ok().unwrap(); // ok: test

        assert!(text.starts_with("POST /_matrix/client/v3/login HTTP/1.1\r\n"));
        assert!(text.contains("Host: matrix.example.com\r\n"));
        assert!(text.contains("Content-Type: application/json\r\n"));
        // Body is 29 bytes: {"user":"@alice:example.com"}
        assert!(text.contains("Content-Length: 29\r\n"));
        assert!(text.ends_with("{\"user\":\"@alice:example.com\"}"));
    }

    #[test]
    fn build_put_json_request() {
        let body = b"{\"msgtype\":\"m.text\",\"body\":\"hello\"}";
        let req = put_json(
            "matrix.example.com",
            "/_matrix/client/v3/rooms/!abc:example.com/send/m.room.message/txn1",
            body,
        );
        let raw = req.build_raw();
        assert!(raw.is_ok());
        let raw = raw.ok().unwrap(); // ok: test
        let text = core::str::from_utf8(&raw).ok().unwrap(); // ok: test

        assert!(text.starts_with("PUT "));
        assert!(text.contains("Content-Type: application/json\r\n"));
        // Body is {"msgtype":"m.text","body":"hello"} = 34 bytes.
        let cl = alloc::format!("Content-Length: {}\r\n", body.len());
        assert!(text.contains(&cl));
    }

    #[test]
    fn build_delete_request() {
        let req = delete(
            "matrix.example.com",
            "/_matrix/client/v3/rooms/!abc:ex/leave",
        );
        let raw = req.build_raw();
        assert!(raw.is_ok());
        let raw = raw.ok().unwrap(); // ok: test
        let text = core::str::from_utf8(&raw).ok().unwrap(); // ok: test

        assert!(text.starts_with("DELETE "));
        assert!(!text.contains("Content-Length")); // No body.
    }

    #[test]
    fn build_request_with_auth() {
        let mut req = get("matrix.example.com", "/_matrix/client/v3/sync");
        with_auth(&mut req, "syt_test_token_1234");
        let raw = req.build_raw();
        assert!(raw.is_ok());
        let raw = raw.ok().unwrap(); // ok: test
        let text = core::str::from_utf8(&raw).ok().unwrap(); // ok: test

        assert!(text.contains("Authorization: Bearer syt_test_token_1234\r\n"));
    }

    #[test]
    fn build_request_empty_host_errors() {
        let req = get("", "/path");
        let result = req.build_raw();
        assert_eq!(result, Err(HttpError::EmptyHost));
    }

    #[test]
    fn build_request_empty_path_errors() {
        let req = get("host.example.com", "");
        let result = req.build_raw();
        assert_eq!(result, Err(HttpError::EmptyPath));
    }

    #[test]
    fn build_request_rejects_crlf_in_path() {
        let req = get("matrix.example.com", "/path\r\nX-Injected: evil");
        let result = req.build_raw();
        assert_eq!(result, Err(HttpError::InvalidPath));
    }

    #[test]
    fn build_request_rejects_bare_lf_in_path() {
        // A bare LF (no CR) is also a valid line terminator for many
        // lenient HTTP parsers — must be rejected too, not just CRLF pairs.
        let req = get("matrix.example.com", "/path\nX-Injected: evil");
        let result = req.build_raw();
        assert_eq!(result, Err(HttpError::InvalidPath));
    }

    #[test]
    fn build_request_rejects_crlf_in_host() {
        let req = get("matrix.example.com\r\nX-Injected: evil", "/path");
        let result = req.build_raw();
        assert_eq!(result, Err(HttpError::InvalidHost));
    }

    #[test]
    fn build_request_rejects_crlf_in_header_name() {
        let mut req = get("matrix.example.com", "/path");
        req.add_header(String::from("X-Evil\r\nX-Injected"), String::from("value"));
        let result = req.build_raw();
        assert_eq!(result, Err(HttpError::InvalidHeader));
    }

    #[test]
    fn build_request_rejects_crlf_in_header_value() {
        let mut req = get("matrix.example.com", "/path");
        req.add_header(
            String::from("X-Custom"),
            String::from("value\r\nX-Injected: evil"),
        );
        let result = req.build_raw();
        assert_eq!(result, Err(HttpError::InvalidHeader));
    }

    // -- HttpResponse::parse --

    #[test]
    fn parse_simple_response() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 15\r\nContent-Type: application/json\r\n\r\n{\"status\":\"ok\"}";
        let resp = HttpResponse::parse(raw);
        assert!(resp.is_ok());
        let resp = resp.ok().unwrap(); // ok: test
        assert_eq!(resp.status, 200);
        assert!(resp.is_success());
        assert_eq!(resp.body, b"{\"status\":\"ok\"}");
        assert_eq!(resp.header("content-type"), Some("application/json"));
        assert_eq!(resp.content_length(), Some(15));
    }

    #[test]
    fn total_bytes_matches_input_length() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 15\r\nContent-Type: application/json\r\n\r\n{\"status\":\"ok\"}";
        let resp = HttpResponse::parse(raw).ok().unwrap(); // ok: test
        assert_eq!(
            resp.total_bytes(),
            raw.len(),
            "total_bytes() must equal the exact input-slice length for a well-formed response"
        );
    }

    #[test]
    fn total_bytes_excludes_trailing_bytes_after_body() {
        // Bytes after the Content-Length-bounded body (e.g. the start of
        // a second pipelined/forged response, issue #294) must not be
        // counted as consumed.
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 15\r\n\r\n{\"status\":\"ok\"}TRAILING";
        let resp = HttpResponse::parse(raw).ok().unwrap(); // ok: test
        assert_eq!(
            resp.total_bytes(),
            raw.len() - b"TRAILING".len(),
            "total_bytes() must not include bytes past the parsed body"
        );
    }

    #[test]
    fn parse_response_no_content_length() {
        // Connection-close framing: body is everything after headers.
        let raw = b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\nhello world";
        let resp = HttpResponse::parse(raw);
        assert!(resp.is_ok());
        let resp = resp.ok().unwrap(); // ok: test
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"hello world");
    }

    #[test]
    fn parse_response_401_unauthorized() {
        let raw = b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n";
        let resp = HttpResponse::parse(raw);
        assert!(resp.is_ok());
        let resp = resp.ok().unwrap(); // ok: test
        assert_eq!(resp.status, 401);
        assert!(!resp.is_success());
        assert!(resp.body.is_empty());
    }

    #[test]
    fn parse_response_429_rate_limited() {
        let body = b"{\"errcode\":\"M_LIMIT_EXCEEDED\",\"retry_after_ms\":2000}";
        let mut raw = Vec::from(&b"HTTP/1.1 429 Too Many Requests\r\nContent-Length: "[..]);
        write_usize_to_buf(&mut raw, body.len());
        raw.extend_from_slice(b"\r\n\r\n");
        raw.extend_from_slice(body);

        let resp = HttpResponse::parse(&raw);
        assert!(resp.is_ok());
        let resp = resp.ok().unwrap(); // ok: test
        assert_eq!(resp.status, 429);
        assert!(!resp.is_success());
    }

    #[test]
    fn parse_response_empty_body() {
        let raw = b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n";
        let resp = HttpResponse::parse(raw);
        assert!(resp.is_ok());
        let resp = resp.ok().unwrap(); // ok: test
        assert_eq!(resp.status, 204);
        assert!(resp.body.is_empty());
    }

    #[test]
    fn parse_incomplete_response() {
        // No \r\n\r\n yet — headers incomplete.
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n";
        let result = HttpResponse::parse(raw);
        assert_eq!(result, Err(HttpError::Incomplete));
    }

    #[test]
    fn parse_incomplete_body() {
        // Headers complete but body is short.
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort";
        let result = HttpResponse::parse(raw);
        assert_eq!(result, Err(HttpError::Incomplete));
    }

    #[test]
    fn parse_malformed_status_line() {
        let raw = b"NOT-HTTP\r\nContent-Length: 0\r\n\r\n";
        let result = HttpResponse::parse(raw);
        assert_eq!(result, Err(HttpError::MalformedStatusLine));
    }

    #[test]
    fn parse_invalid_status_code() {
        let raw = b"HTTP/1.1 xyz OK\r\nContent-Length: 0\r\n\r\n";
        let result = HttpResponse::parse(raw);
        assert_eq!(result, Err(HttpError::InvalidStatusCode));
    }

    #[test]
    fn parse_multiple_headers() {
        let raw = b"HTTP/1.1 200 OK\r\nX-One: alpha\r\nX-Two: beta\r\nX-Three: gamma\r\nContent-Length: 0\r\n\r\n";
        let resp = HttpResponse::parse(raw);
        assert!(resp.is_ok());
        let resp = resp.ok().unwrap(); // ok: test
        assert_eq!(resp.headers.len(), 4);
        assert_eq!(resp.header("x-one"), Some("alpha"));
        assert_eq!(resp.header("x-two"), Some("beta"));
        assert_eq!(resp.header("x-three"), Some("gamma"));
    }

    #[test]
    fn parse_header_value_whitespace_trimmed() {
        let raw = b"HTTP/1.1 200 OK\r\nX-Padded:   value   \r\nContent-Length: 0\r\n\r\n";
        let resp = HttpResponse::parse(raw);
        assert!(resp.is_ok());
        let resp = resp.ok().unwrap(); // ok: test
        assert_eq!(resp.header("x-padded"), Some("value"));
    }

    #[test]
    fn parse_response_rejects_header_block_exceeding_max_size() {
        // header_end (the position of the \r\n\r\n terminator) must exceed
        // MAX_HEADER_BLOCK_SIZE to trip the guard before any header parsing.
        let mut raw = Vec::from(&b"HTTP/1.1 200 OK\r\nX-Pad: "[..]);
        raw.extend(core::iter::repeat(b'a').take(MAX_HEADER_BLOCK_SIZE + 16));
        raw.extend_from_slice(b"\r\n\r\n");

        let result = HttpResponse::parse(&raw);
        assert_eq!(
            result,
            Err(HttpError::HeaderBlockTooLarge),
            "a header block exceeding MAX_HEADER_BLOCK_SIZE must be rejected before parsing headers"
        );
    }

    #[test]
    fn parse_response_rejects_content_length_exceeding_max_body_size() {
        let mut raw = Vec::from(&b"HTTP/1.1 200 OK\r\nContent-Length: "[..]);
        write_usize_to_buf(&mut raw, MAX_BODY_SIZE + 1);
        raw.extend_from_slice(b"\r\n\r\n");
        // No actual body bytes needed -- the declared-length check fires
        // before the available-bytes check.

        let result = HttpResponse::parse(&raw);
        assert_eq!(
            result,
            Err(HttpError::BodyTooLarge),
            "a declared Content-Length exceeding MAX_BODY_SIZE must be rejected"
        );
    }

    #[test]
    fn parse_response_rejects_oversized_body_without_content_length() {
        // Connection-close framing (a header, but no Content-Length): the
        // raw remaining-bytes size must be checked against MAX_BODY_SIZE
        // too, not just the declared-length path above.
        let mut raw = Vec::from(&b"HTTP/1.1 200 OK\r\nServer: x\r\n\r\n"[..]);
        raw.extend(core::iter::repeat(b'a').take(MAX_BODY_SIZE + 1));

        let result = HttpResponse::parse(&raw);
        assert_eq!(
            result,
            Err(HttpError::BodyTooLarge),
            "a connection-close body exceeding MAX_BODY_SIZE must be rejected"
        );
    }

    #[test]
    fn parse_response_rejects_too_many_headers() {
        let mut raw = Vec::from(&b"HTTP/1.1 200 OK\r\n"[..]);
        for i in 0..=MAX_RESPONSE_HEADERS {
            raw.extend_from_slice(b"X-H");
            write_usize_to_buf(&mut raw, i);
            raw.extend_from_slice(b": v\r\n");
        }
        raw.extend_from_slice(b"\r\n");

        let result = HttpResponse::parse(&raw);
        assert_eq!(
            result,
            Err(HttpError::TooManyHeaders),
            "more than MAX_RESPONSE_HEADERS header lines must be rejected"
        );
    }

    #[test]
    fn parse_response_rejects_non_numeric_content_length() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: not-a-number\r\n\r\n";
        let result = HttpResponse::parse(raw);
        assert_eq!(
            result,
            Err(HttpError::InvalidContentLength),
            "a non-numeric Content-Length value must be rejected"
        );
    }

    // -- Convenience constructors --

    #[test]
    fn get_constructor_fields() {
        let req = get("host.example.com", "/path");
        assert_eq!(req.method, HttpMethod::Get);
        assert_eq!(req.host, "host.example.com");
        assert_eq!(req.path, "/path");
        assert!(req.body.is_none());
    }

    #[test]
    fn post_json_constructor_fields() {
        let req = post_json("host.example.com", "/path", b"{}");
        assert_eq!(req.method, HttpMethod::Post);
        assert!(req.body.is_some());
        assert_eq!(req.body.as_ref().map(Vec::as_slice), Some(b"{}".as_slice()));
    }

    #[test]
    fn put_json_constructor_fields() {
        let req = put_json("host.example.com", "/path", b"{}");
        assert_eq!(req.method, HttpMethod::Put);
        assert!(req.body.is_some());
    }

    #[test]
    fn delete_constructor_fields() {
        let req = delete("host.example.com", "/path");
        assert_eq!(req.method, HttpMethod::Delete);
        assert!(req.body.is_none());
    }

    // -- Display impls --

    #[test]
    fn request_display() {
        let req = get("host.example.com", "/sync");
        let s = req.to_string();
        assert_eq!(s, "GET /sync HTTP/1.1");
    }

    #[test]
    fn response_display() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let resp = HttpResponse::parse(raw).ok().unwrap(); // ok: test
        let s = resp.to_string();
        assert!(s.contains("200"));
        assert!(s.contains("5 bytes"));
    }

    #[test]
    fn error_display() {
        let e = HttpError::Incomplete;
        assert_eq!(e.to_string(), "incomplete HTTP response");
    }

    // -- Internal helpers --

    #[test]
    fn write_usize_zero() {
        let mut buf = Vec::new();
        write_usize_to_buf(&mut buf, 0);
        assert_eq!(&buf, b"0");
    }

    #[test]
    fn write_usize_single_digit() {
        let mut buf = Vec::new();
        write_usize_to_buf(&mut buf, 7);
        assert_eq!(&buf, b"7");
    }

    #[test]
    fn write_usize_multi_digit() {
        let mut buf = Vec::new();
        write_usize_to_buf(&mut buf, 12345);
        assert_eq!(&buf, b"12345");
    }

    #[test]
    fn find_header_end_present() {
        let data = b"HTTP/1.1 200 OK\r\nHost: x\r\n\r\nbody";
        let pos = find_header_end(data);
        // "HTTP/1.1 200 OK" (15) + "\r\n" (2) + "Host: x" (7) = 24.
        // The \r\n\r\n starts at position 24.
        assert_eq!(pos, Some(24));
    }

    #[test]
    fn find_header_end_missing() {
        let data = b"HTTP/1.1 200 OK\r\nHost: x\r\n";
        let pos = find_header_end(data);
        assert_eq!(pos, None);
    }

    // -- Round-trip: build request, verify wire format --

    #[test]
    fn roundtrip_matrix_sync_request() {
        let mut req = get("matrix.local.lan", "/_matrix/client/v3/sync?timeout=30000");
        with_auth(&mut req, "syt_abc123");
        let raw = req.build_raw().ok().unwrap(); // ok: test
        let text = core::str::from_utf8(&raw).ok().unwrap(); // ok: test

        // Verify exact wire format structure.
        let lines: Vec<&str> = text.split("\r\n").collect();
        assert_eq!(
            lines[0],
            "GET /_matrix/client/v3/sync?timeout=30000 HTTP/1.1"
        );
        assert_eq!(lines[1], "Host: matrix.local.lan");
        assert!(lines.contains(&"Authorization: Bearer syt_abc123"));
        // Final \r\n\r\n produces two empty strings at end.
        assert!(lines[lines.len() - 1].is_empty());
        assert!(lines[lines.len() - 2].is_empty());
    }

    #[test]
    fn roundtrip_matrix_send_message() {
        let body = b"{\"msgtype\":\"m.text\",\"body\":\"Hello from Thumos\"}";
        let mut req = put_json(
            "matrix.local.lan",
            "/_matrix/client/v3/rooms/!room:example.com/send/m.room.message/txn42",
            body,
        );
        with_auth(&mut req, "syt_xyz789");
        let raw = req.build_raw().ok().unwrap(); // ok: test
        let text = core::str::from_utf8(&raw).ok().unwrap(); // ok: test

        assert!(text.starts_with("PUT /_matrix/client/v3/rooms/"));
        assert!(text.contains("Content-Type: application/json\r\n"));
        assert!(text.contains(&alloc::format!("Content-Length: {}\r\n", body.len())));
        assert!(text.contains("Authorization: Bearer syt_xyz789\r\n"));
        assert!(text.ends_with(core::str::from_utf8(body).ok().unwrap())); // ok: test
    }

    // -- Response body_as_str --

    #[test]
    fn body_as_str_valid_utf8() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}";
        let resp = HttpResponse::parse(raw).ok().unwrap(); // ok: test
        assert_eq!(resp.body_as_str(), Some("{}"));
    }

    #[test]
    fn body_as_str_invalid_utf8() {
        let mut raw = Vec::from(&b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n"[..]);
        raw.extend_from_slice(&[0xFF, 0xFE]); // Invalid UTF-8.
        let resp = HttpResponse::parse(&raw).ok().unwrap(); // ok: test
        assert_eq!(resp.body_as_str(), None);
    }
}
