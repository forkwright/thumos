//! Bounds-checked forward reader over PDU bytes ([`Cursor`]).
//!
//! Every read is fallible: the underlying bytes come from the modem, so a
//! truncated PDU must surface as an error rather than an index panic.

use crate::{CoreError, Result};

/// A bounds-checked forward reader over PDU bytes.
///
/// Every read is fallible: the underlying bytes come from the modem, so a
/// truncated PDU must surface as an error rather than an index panic.
#[derive(Debug)]
pub struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    /// Start a cursor at the beginning of `data`.
    #[must_use]
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Current byte offset.
    #[must_use]
    pub const fn pos(&self) -> usize {
        self.pos
    }

    /// The bytes not yet consumed.
    #[must_use]
    pub fn remaining(&self) -> &'a [u8] {
        self.data.get(self.pos..).unwrap_or(&[])
    }

    /// Read one byte and advance.
    ///
    /// # Errors
    ///
    /// [`CoreError::Truncated`] at end of input.
    pub fn read_byte(&mut self) -> Result<u8> {
        let b = self
            .data
            .get(self.pos)
            .copied()
            .ok_or(CoreError::Truncated { offset: self.pos })?;
        self.pos += 1;
        Ok(b)
    }

    /// Read `n` bytes and advance.
    ///
    /// # Errors
    ///
    /// [`CoreError::Truncated`] when fewer than `n` bytes remain.
    pub fn read_slice(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(CoreError::Truncated { offset: self.pos })?;
        let s = self
            .data
            .get(self.pos..end)
            .ok_or(CoreError::Truncated { offset: self.pos })?;
        self.pos = end;
        Ok(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ok;

    #[test]
    fn cursor_reads_are_bounds_checked() {
        let mut cur = Cursor::new(&[0x01, 0x02]);
        assert_eq!(ok(cur.read_byte()), 0x01);
        assert_eq!(ok(cur.read_slice(1)), &[0x02]);
        assert!(
            cur.read_byte().is_err(),
            "reading past the end must error, not panic"
        );
    }

    #[test]
    fn read_slice_rejects_a_length_that_overflows_the_position() {
        // #833: `pos + n` is a checked add. Without it, a length near
        // usize::MAX wraps to a small end offset and the slice read succeeds
        // against a range the caller never asked for.
        let data = [0u8; 8];
        let mut cur = Cursor::new(&data);
        let _ = ok(cur.read_slice(4));
        let err = cur.read_slice(usize::MAX);
        assert!(
            matches!(err, Err(CoreError::Truncated { .. })),
            "a length that overflows the cursor position must be Truncated, not a wrapped read"
        );
    }
}
