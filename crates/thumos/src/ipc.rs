//! Inter-process communication via message passing.
//!
//! Processes communicate by sending fixed-size messages through channels.
//! Each process has an inbox (bounded ring buffer). Sending to a full
//! inbox blocks the sender. Receiving FROM an empty inbox blocks the receiver.
//!
//! This is synchronous, rendezvous-style IPC inspired by seL4 and QNX.
//! Asynchronous notifications (for interrupts) can be added later.

extern crate alloc;

use crate::process::{self, Pid};

/// Maximum message payload size in bytes.
pub const MSG_MAX_SIZE: usize = 256;

/// Number of messages per inbox.
const INBOX_SIZE: usize = 16;

/// A message between processes.
#[derive(Clone)]
pub struct Message {
    /// Sender process ID.
    pub from: Pid,
    /// Message type tag (application-defined).
    pub tag: u32,
    /// Payload length.
    pub len: usize,
    /// Payload data.
    pub data: [u8; MSG_MAX_SIZE],
}

impl Message {
    /// Create a new message with the given tag and data.
    pub fn new(tag: u32, payload: &[u8]) -> Self {
        let mut msg = Self {
            from: 0,
            tag,
            len: payload.len().min(MSG_MAX_SIZE),
            data: [0; MSG_MAX_SIZE],
        };
        msg.data[..msg.len].copy_from_slice(&payload[..msg.len]);
        msg
    }

    /// Get the payload as a byte slice.
    pub fn payload(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

/// Per-process message inbox (ring buffer).
pub struct Inbox {
    messages: [Option<Message>; INBOX_SIZE],
    head: usize,
    tail: usize,
    count: usize,
}

impl Inbox {
    /// Create an empty inbox.
    pub const fn new() -> Self {
        const NONE: Option<Message> = None;
        Self {
            messages: [NONE; INBOX_SIZE],
            head: 0,
            tail: 0,
            count: 0,
        }
    }

    /// Push a message INTO the inbox. Returns false if full.
    pub fn push(&mut self, msg: Message) -> bool {
        if self.count >= INBOX_SIZE {
            return false;
        }
        self.messages[self.tail] = Some(msg);
        self.tail = (self.tail + 1) % INBOX_SIZE;
        self.count += 1;
        true
    }

    /// Pop a message FROM the inbox. Returns None if empty.
    pub fn pop(&mut self) -> Option<Message> {
        if self.count == 0 {
            return None;
        }
        let msg = self.messages[self.head].take();
        self.head = (self.head + 1) % INBOX_SIZE;
        self.count -= 1;
        msg
    }

    /// Check if the inbox is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Check if the inbox is full.
    pub fn is_full(&self) -> bool {
        self.count >= INBOX_SIZE
    }
}

/// Number of inbox slots, matching the maximum number of processes.
const MAX_INBOX_PROCS: usize = 16;

/// Error code for "no such process" (ESRCH equivalent for ARM Linux).
pub const ESRCH: i32 = -3;

/// Process inboxes. Indexed by PID.
static mut INBOXES: [Inbox; MAX_INBOX_PROCS] = {
    const NEW_INBOX: Inbox = Inbox::new();
    [NEW_INBOX; MAX_INBOX_PROCS]
};

/// Validate a PID is within the inbox array bounds.
///
/// Returns the PID as a `usize` index, or `Err(ESRCH)` if the PID
/// cannot be converted or exceeds the maximum process count.
fn validate_pid(pid: Pid) -> Result<usize, i32> {
    let idx = usize::from(pid);
    if idx >= MAX_INBOX_PROCS {
        return Err(ESRCH);
    }
    Ok(idx)
}

/// Send a message to a process. Non-blocking: returns false if inbox full
/// or the target PID is invalid.
pub fn send(to: Pid, mut msg: Message) -> bool {
    let idx = match validate_pid(to) {
        Ok(i) => i,
        Err(_) => return false,
    };
    msg.from = process::current_pid();
    // SAFETY: INBOXES is a static array indexed by PID. addr_of_mut! avoids
    // creating an intermediate reference to the static mut. Single-core kernel
    // with interrupts disabled at call sites ensures exclusive access.
    unsafe {
        let inboxes = &mut *core::ptr::addr_of_mut!(INBOXES);
        inboxes[idx].push(msg)
    }
}

/// Receive a message FROM our inbox. Non-blocking: returns None if empty
/// or current PID is invalid.
pub fn recv() -> Option<Message> {
    let pid = process::current_pid();
    let idx = validate_pid(pid).ok()?;
    // SAFETY: INBOXES is a static array indexed by PID. addr_of_mut! avoids
    // creating an intermediate reference to the static mut. Single-core kernel
    // with interrupts disabled at call sites ensures exclusive access.
    unsafe {
        let inboxes = &mut *core::ptr::addr_of_mut!(INBOXES);
        inboxes[idx].pop()
    }
}

/// Check if our inbox has messages. Returns false if the current PID is invalid.
pub fn has_messages() -> bool {
    let pid = process::current_pid();
    let idx = match validate_pid(pid) {
        Ok(i) => i,
        Err(_) => return false,
    };
    // SAFETY: INBOXES is a static array indexed by PID. addr_of! avoids
    // creating an intermediate reference to the static mut. Read-only access
    // here; single-core kernel ensures no concurrent mutation.
    unsafe {
        let inboxes = &*core::ptr::addr_of!(INBOXES);
        !inboxes[idx].is_empty()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_pid_accepts_valid_pids() {
        for pid in 0..MAX_INBOX_PROCS as u8 {
            assert!(
                validate_pid(pid).is_ok(),
                "pid {pid} should be valid"
            );
            assert_eq!(validate_pid(pid), Ok(pid as usize));
        }
    }

    #[test]
    fn validate_pid_rejects_out_of_range() {
        // PIDs at or above MAX_INBOX_PROCS must be rejected.
        assert_eq!(validate_pid(MAX_INBOX_PROCS as u8), Err(ESRCH));
        assert_eq!(validate_pid(u8::MAX), Err(ESRCH));
        assert_eq!(validate_pid(200), Err(ESRCH));
    }

    #[test]
    fn validate_pid_never_routes_to_zero() {
        // The old bug: invalid PIDs silently routed to pid 0 (init).
        // Verify that an invalid PID returns an error, not Ok(0).
        let result = validate_pid(MAX_INBOX_PROCS as u8);
        assert!(result.is_err(), "invalid PID must not succeed");
        assert_ne!(result, Ok(0), "invalid PID must never route to pid 0");
    }

    #[test]
    fn inbox_push_pop_round_trips() {
        let mut inbox = Inbox::new();
        assert!(inbox.is_empty());

        let msg = Message::new(42, b"hello");
        assert!(inbox.push(msg));
        assert!(!inbox.is_empty());

        let popped = inbox.pop();
        assert!(popped.is_some());
        let popped = popped.as_ref();
        assert_eq!(popped.map(|m| m.tag), Some(42));
        assert_eq!(popped.map(|m| m.payload()), Some(b"hello".as_slice()));
        assert!(inbox.is_empty());
    }

    #[test]
    fn inbox_rejects_when_full() {
        let mut inbox = Inbox::new();
        for i in 0..INBOX_SIZE {
            let msg = Message::new(i as u32, &[]);
            assert!(inbox.push(msg), "push {i} should succeed");
        }
        assert!(inbox.is_full());

        let msg = Message::new(999, &[]);
        assert!(!inbox.push(msg), "push to full inbox must return false");
    }

    #[test]
    fn inbox_pop_empty_returns_none() {
        let mut inbox = Inbox::new();
        assert!(inbox.pop().is_none());
    }
}
