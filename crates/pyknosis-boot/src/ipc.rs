//! Inter-process communication via message passing.
//!
//! Processes communicate by sending fixed-size messages through channels.
//! Each process has an inbox (bounded ring buffer). Sending to a full
//! inbox blocks the sender. Receiving from an empty inbox blocks the receiver.
//!
//! This is synchronous, rendezvous-style IPC inspired by seL4 and QNX.
//! Asynchronous notifications (for interrupts) can be added later.

extern crate alloc;

use crate::process::{self, Pid, State};

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

    /// Push a message into the inbox. Returns false if full.
    pub fn push(&mut self, msg: Message) -> bool {
        if self.count >= INBOX_SIZE {
            return false;
        }
        self.messages[self.tail] = Some(msg);
        self.tail = (self.tail + 1) % INBOX_SIZE;
        self.count += 1;
        true
    }

    /// Pop a message from the inbox. Returns None if empty.
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

/// Process inboxes. Indexed by PID.
static mut INBOXES: [Inbox; 16] = {
    const NEW_INBOX: Inbox = Inbox::new();
    [NEW_INBOX; 16]
};

/// Send a message to a process. Non-blocking: returns false if inbox full.
pub fn send(to: Pid, mut msg: Message) -> bool {
    msg.from = process::current_pid();
    unsafe {
        let inboxes = &mut *core::ptr::addr_of_mut!(INBOXES);
        inboxes[to as usize].push(msg)
    }
}

/// Receive a message from our inbox. Non-blocking: returns None if empty.
pub fn recv() -> Option<Message> {
    let pid = process::current_pid();
    unsafe {
        let inboxes = &mut *core::ptr::addr_of_mut!(INBOXES);
        inboxes[pid as usize].pop()
    }
}

/// Check if our inbox has messages.
pub fn has_messages() -> bool {
    let pid = process::current_pid();
    unsafe {
        let inboxes = &*core::ptr::addr_of!(INBOXES);
        !inboxes[pid as usize].is_empty()
    }
}
