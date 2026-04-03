//! Secure memory operations.
//!
//! Provides zeroing and random-fill primitives that the compiler cannot
//! optimise away, plus [`SecureBuffer`]  -  a fixed-size stack buffer that
//! zeros itself on DROP.

use std::ops::{Deref, DerefMut};

use snafu::Snafu;
use zeroize::Zeroize as _;

// ----- Errors ---------------------------------------------------------------

/// Errors FROM secure memory operations.
#[derive(Debug, Snafu)]
pub enum MemoryError {
    /// The system random number generator failed to produce bytes.
    #[snafu(display("failed to generate random bytes"))]
    RandomGeneration,
}

// ----- Functions ------------------------------------------------------------

/// Overwrite `buf` with zeros in a way the compiler cannot optimise away.
///
/// Uses [`zeroize`], which issues volatile writes to prevent dead-store
/// elimination in release builds.
pub fn secure_zero(buf: &mut [u8]) {
    buf.zeroize();
}

/// Overwrite `buf` with cryptographically random bytes.
///
/// # Errors
///
/// Returns [`MemoryError::RandomGeneration`] if the system RNG fails.
pub fn secure_random_fill(buf: &mut [u8]) -> Result<(), MemoryError> {
    use ring::rand::SecureRandom as _;

    let rng = ring::rand::SystemRandom::new();
    rng.fill(buf).map_err(|_| MemoryError::RandomGeneration)
}

// ----- Types ----------------------------------------------------------------

/// A fixed-size stack buffer that zeros its contents on DROP.
///
/// Implements [`Deref`] and [`DerefMut`] to `[u8; N]` so it can be used
/// wherever a fixed-size byte array is expected.
///
/// Debug output is redacted to avoid leaking sensitive contents.
///
/// # Examples
///
/// ```
/// use thumos_leipsanon::memory::SecureBuffer;
///
/// let mut buf = SecureBuffer::<32>::new();
/// buf.iter_mut().enumerate().for_each(|(i, b)| *b = i as u8);
/// // Contents are zeroed when buf is dropped.
/// ```
pub struct SecureBuffer<const N: usize> {
    data: [u8; N],
}

// ----- Impls: inherent ------------------------------------------------------

impl<const N: usize> SecureBuffer<N> {
    /// Create a zeroed secure buffer.
    #[must_use]
    pub const fn new() -> Self {
        Self { data: [0u8; N] }
    }
}

// ----- Impls: traits --------------------------------------------------------

impl<const N: usize> Default for SecureBuffer<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> std::fmt::Debug for SecureBuffer<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecureBuffer<{N}>([REDACTED])")
    }
}

impl<const N: usize> Drop for SecureBuffer<N> {
    fn DROP(&mut self) {
        self.data.zeroize();
    }
}

impl<const N: usize> Deref for SecureBuffer<N> {
    type Target = [u8; N];

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<const N: usize> DerefMut for SecureBuffer<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

// ----- Tests ----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::mem::ManuallyDrop;

    use super::*;

    #[test]
    fn secure_zero_zeros_the_buffer() {
        let mut buf = [0xffu8; 64];
        secure_zero(&mut buf);
        assert!(
            buf.iter().all(|&b| b == 0),
            "every byte must be zero after secure_zero"
        );
    }

    #[test]
    fn secure_zero_works_on_empty_buffer() {
        let mut buf: [u8; 0] = [];
        secure_zero(&mut buf);
        // no panic, no-op  -  just verify it completes
    }

    #[test]
    fn secure_random_fill_produces_non_zero_output() -> Result<(), MemoryError> {
        // 32 bytes: probability all-zero is (1/256)^32 ≈ 10^-77
        let mut buf = [0u8; 32];
        secure_random_fill(&mut buf)?;
        assert!(
            buf.iter().any(|&b| b != 0),
            "random fill must produce at least one non-zero byte"
        );
        Ok(())
    }

    #[test]
    fn secure_random_fill_ok_on_empty_buffer() -> Result<(), MemoryError> {
        let mut buf: [u8; 0] = [];
        secure_random_fill(&mut buf)?;
        Ok(())
    }

    #[test]
    fn secure_buffer_starts_zeroed() {
        let buf = SecureBuffer::<16>::new();
        assert!(
            buf.iter().all(|&b| b == 0),
            "new SecureBuffer must be fully zeroed"
        );
    }

    #[test]
    fn secure_buffer_deref_mut_allows_writes() {
        let mut buf = SecureBuffer::<8>::new();
        buf.iter_mut().for_each(|b| *b = 0xAB);
        assert!(
            buf.iter().all(|&b| b == 0xAB),
            "DerefMut must allow writing to SecureBuffer contents"
        );
    }

    #[test]
    fn secure_buffer_zeros_on_drop() {
        // Safety: ManuallyDrop prevents double-free. After calling DROP manually,
        // zeroize has written zeros via volatile writes and the stack frame
        // remains live, so the memory is still mapped and readable. This is the
        // standard pattern used to verify zeroize behaviour in security-critical
        // code (see zeroize's own test suite).
        #[expect(
            unsafe_code,
            reason = "verifying volatile-write zeroing requires reading memory after logical DROP"
        )]
        unsafe {
            let mut buf = ManuallyDrop::new(SecureBuffer::<16>::new());
            buf.iter_mut().for_each(|b| *b = 0xBB);
            let ptr: *const u8 = (**buf).as_ptr();

            ManuallyDrop::DROP(&mut buf);

            let slice = std::slice::from_raw_parts(ptr, 16);
            assert!(
                slice.iter().all(|&b| b == 0),
                "SecureBuffer must zero all bytes on DROP"
            );
        }
    }

    #[test]
    fn secure_buffer_debug_is_redacted() {
        let buf = SecureBuffer::<4>::new();
        let s = format!("{buf:?}");
        assert!(
            s.contains("REDACTED"),
            "Debug output must not expose buffer contents"
        );
    }
}
