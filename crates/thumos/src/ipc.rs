//! Inter-process communication via message passing.
//!
//! Processes communicate by sending fixed-size messages through per-process
//! inboxes (bounded ring buffers). Delivery is non-blocking on both ends:
//! [`send`] fails immediately with [`IpcSendError::InboxFull`] rather than
//! blocking the sender when the target inbox is at capacity, and [`recv`]
//! returns `None` immediately rather than blocking the receiver when the
//! inbox is empty. This is asynchronous mailbox-style IPC, not the
//! synchronous rendezvous this doc previously (incorrectly) claimed.
//!
//! Asynchronous notifications (for interrupts) can be added later.

extern crate alloc;

use crate::irq;
use crate::process::{self, Pid};

/// Maximum message payload size in bytes.
pub(crate) const MSG_MAX_SIZE: usize = 256;

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
    ///
    /// # WHY silent truncation is safe here
    ///
    /// `payload` longer than [`MSG_MAX_SIZE`] is truncated rather than
    /// rejected. This is safe only because every current caller already
    /// bounds `payload` to `MSG_MAX_SIZE` before calling: the `Send`
    /// syscall handler caps the copied length with `len.min(ipc::MSG_MAX_SIZE)`
    /// before it ever reaches here (see `syscall::dispatch`), and
    /// `process::notify_fault`'s payload is a fixed 9 bytes. Verify that
    /// invariant before adding a new call site that does not pre-bound its
    /// payload -- it would silently lose data with no signal.
    pub(crate) fn new(tag: u32, payload: &[u8]) -> Self {
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
    pub(crate) fn payload(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

/// Per-process message inbox (ring buffer).
pub(crate) struct Inbox {
    messages: [Option<Message>; INBOX_SIZE],
    head: usize,
    tail: usize,
    count: usize,
}

impl Inbox {
    /// Create an empty inbox.
    pub(crate) const fn new() -> Self {
        const NONE: Option<Message> = None;
        Self {
            messages: [NONE; INBOX_SIZE],
            head: 0,
            tail: 0,
            count: 0,
        }
    }

    /// Push a message INTO the inbox. Returns false if full.
    pub(crate) fn push(&mut self, msg: Message) -> bool {
        if self.count >= INBOX_SIZE {
            return false;
        }
        self.messages[self.tail] = Some(msg);
        self.tail = (self.tail + 1) % INBOX_SIZE;
        self.count += 1;
        true
    }

    /// Pop a message FROM the inbox. Returns None if empty.
    pub(crate) fn pop(&mut self) -> Option<Message> {
        if self.count == 0 {
            return None;
        }
        let msg = self.messages[self.head].take();
        self.head = (self.head + 1) % INBOX_SIZE;
        self.count -= 1;
        msg
    }

    /// Check if the inbox is empty.
    pub(crate) fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Check if the inbox is full.
    pub(crate) fn is_full(&self) -> bool {
        self.count >= INBOX_SIZE
    }
}

/// Number of inbox slots, matching the maximum number of processes.
const MAX_INBOX_PROCS: usize = 16;

/// Error code for "no such process" (ESRCH equivalent for ARM Linux).
pub(crate) const ESRCH: i32 = -3;

/// Process inboxes. Indexed by PID.
static mut INBOXES: [Inbox; MAX_INBOX_PROCS] = {
    const NEW_INBOX: Inbox = Inbox::new();
    [NEW_INBOX; MAX_INBOX_PROCS]
};

/// WHY (#322/#331 class): an `irq::IrqSpinlock`, not the bare
/// single-core-cooperative reasoning the accessors below previously
/// relied on alone -- `send`/`recv`/`has_messages` can be reached from
/// IRQ context as well as ordinary kernel-mode code (e.g. a fault handler
/// relaying a report to PID 0 via `process::notify_fault`), and nothing
/// enforced that the two paths could never interleave. Masking IRQ
/// delivery for the access is what actually prevents an interrupting
/// handler from touching INBOXES while a caller it interrupted is
/// mid-mutation.
static INBOXES_LOCK: irq::IrqSpinlock = irq::IrqSpinlock::new();

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

/// Reasons [`send`] can fail to deliver a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IpcSendError {
    /// `to` does not name a live process.
    InvalidTarget,
    /// The target's inbox is at capacity.
    InboxFull,
}

/// Send a message to a process.
///
/// Non-blocking: fails immediately rather than blocking if the target's
/// inbox is full.
///
/// NOTE: this primitive performs no capability/authorization check by
/// design -- it is also used by trusted kernel-internal callers (e.g.
/// `process::notify_fault`, which relays a fault report to PID 0 on behalf
/// of the faulting process). The untrusted-facing authorization gate for
/// PID 0 as a target lives at the syscall boundary instead: see
/// `syscall::dispatch`'s `Syscall::Send` arm and
/// `capability::Capabilities::IPC_INIT` (#371).
///
/// # Errors
///
/// Returns [`IpcSendError::InvalidTarget`] if `to` does not name a live
/// process, or [`IpcSendError::InboxFull`] if the target's inbox is at
/// capacity. These were previously conflated into a single `bool` (issue
/// #282 finding 14), discarding the distinction `validate_pid` already
/// computes internally.
pub(crate) fn send(to: Pid, mut msg: Message) -> Result<(), IpcSendError> {
    let idx = validate_pid(to).map_err(|_| IpcSendError::InvalidTarget)?;
    msg.from = process::current_pid();
    // SAFETY: INBOXES is a static array indexed by PID. addr_of_mut! avoids
    // creating an intermediate reference to the static mut. INBOXES_LOCK
    // masks IRQ delivery for the access, so an IRQ-context caller cannot
    // interleave with a non-IRQ caller mid-mutation (#322/#331 class).
    let _guard = INBOXES_LOCK.lock();
    let delivered = unsafe {
        let inboxes = &mut *core::ptr::addr_of_mut!(INBOXES);
        inboxes[idx].push(msg)
    };
    if delivered {
        Ok(())
    } else {
        Err(IpcSendError::InboxFull)
    }
}

/// Receive a message FROM our inbox. Non-blocking: returns None if empty
/// or current PID is invalid.
pub(crate) fn recv() -> Option<Message> {
    let pid = process::current_pid();
    let idx = validate_pid(pid).ok()?;
    // SAFETY: INBOXES is a static array indexed by PID. addr_of_mut! avoids
    // creating an intermediate reference to the static mut. INBOXES_LOCK
    // masks IRQ delivery for the access (#322/#331 class).
    let _guard = INBOXES_LOCK.lock();
    unsafe {
        let inboxes = &mut *core::ptr::addr_of_mut!(INBOXES);
        inboxes[idx].pop()
    }
}

/// Check if our inbox has messages. Returns false if the current PID is invalid.
pub(crate) fn has_messages() -> bool {
    let pid = process::current_pid();
    let idx = match validate_pid(pid) {
        Ok(i) => i,
        Err(_) => return false,
    };
    // SAFETY: INBOXES is a static array indexed by PID. addr_of! avoids
    // creating an intermediate reference to the static mut. INBOXES_LOCK
    // masks IRQ delivery for the read (#322/#331 class).
    let _guard = INBOXES_LOCK.lock();
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

    #[test]
    fn send_reports_invalid_target_distinctly() {
        let msg = Message::new(1, b"x");
        assert_eq!(
            send(MAX_INBOX_PROCS as u8, msg),
            Err(IpcSendError::InvalidTarget)
        );
    }

    #[test]
    fn send_reports_inbox_full_distinctly_from_invalid_target() {
        for _ in 0..INBOX_SIZE {
            assert_eq!(send(1, Message::new(1, b"x")), Ok(()));
        }
        assert_eq!(send(1, Message::new(1, b"x")), Err(IpcSendError::InboxFull));
    }

    use super::*;

    #[test]
    fn validate_pid_accepts_valid_pids() {
        for pid in 0..MAX_INBOX_PROCS as u8 {
            assert!(validate_pid(pid).is_ok(), "pid {pid} should be valid");
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

    #[test]
    fn message_new_truncates_oversized_payload_to_max_size() {
        let oversized = [0xABu8; MSG_MAX_SIZE + 64];
        let msg = Message::new(7, &oversized);
        assert_eq!(
            msg.len, MSG_MAX_SIZE,
            "payload must truncate to MSG_MAX_SIZE"
        );
        assert_eq!(msg.payload().len(), MSG_MAX_SIZE);
        assert!(msg.payload().iter().all(|&b| b == 0xAB));
    }
}
