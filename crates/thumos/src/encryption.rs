//! Encrypted block device layer.
//!
//! Wraps a [`BlockDevice`] with transparent AES-256-XTS encryption.
//! Reads decrypt ciphertext from the underlying device; writes encrypt
//! plaintext before storing to the device. Uses the sector LBA as the
//! XTS tweak, matching dm-crypt behavior.
//!
//! The encryption operates at 4 KiB block granularity (8 sectors per
//! block). Individual sector reads/writes are buffered into full 4 KiB
//! blocks for encryption/decryption, since AES-XTS operates on complete
//! blocks.

extern crate alloc;

use aes::{Aes256, cipher::KeyInit};
use xts_mode::Xts128;

use crate::block::{BLOCK_SIZE, BlockDevice, BlockError, SECTOR_SIZE, SECTORS_PER_BLOCK};
use crate::key_manager::SecureKey;
use crate::security::{SecurityError, XTS_KEY_SIZE};

// ---------------------------------------------------------------------------
// EncryptedBlockDevice
// ---------------------------------------------------------------------------

/// A block device wrapper that transparently encrypts/decrypts data
/// using AES-256-XTS.
///
/// The XTS tweak is derived from the logical block number, matching
/// dm-crypt sector-level encryption semantics. Each 4 KiB block is
/// encrypted independently with the block number as tweak.
///
/// # Key format
///
/// The key is 64 bytes: two concatenated AES-256 keys (key1 || key2).
/// `key1` is used for the block cipher, `key2` for the tweak cipher.
pub(crate) struct EncryptedBlockDevice<'a> {
    /// The underlying (raw) block device.
    inner: &'a mut dyn BlockDevice,
    /// XTS key: two AES-256 keys concatenated (64 bytes). Wrapped in
    /// `SecureKey` so the master partition-encryption key is
    /// `write_volatile`-zeroized on drop, matching the `key_manager`
    /// zeroization discipline (#332).
    key: SecureKey<XTS_KEY_SIZE>,
}

impl<'a> EncryptedBlockDevice<'a> {
    /// Create a new encrypted block device wrapping `inner` with the given key.
    ///
    /// The key must be 64 bytes (two AES-256 keys for XTS mode).
    pub(crate) fn new(inner: &'a mut dyn BlockDevice, key: [u8; XTS_KEY_SIZE]) -> Self {
        Self {
            inner,
            key: SecureKey::new(key),
        }
    }

    /// Build the XTS cipher from the stored key.
    ///
    /// # Errors
    ///
    /// Returns [`BlockError::InvalidArgument`] if the key is malformed
    /// (should not happen with a valid 64-byte key).
    fn make_xts(&self) -> Result<Xts128<Aes256>, BlockError> {
        let (k1, k2) = self.key.as_bytes().split_at(32);
        let c1 = Aes256::new_from_slice(k1).map_err(|_| BlockError::InvalidArgument)?;
        let c2 = Aes256::new_from_slice(k2).map_err(|_| BlockError::InvalidArgument)?;
        Ok(Xts128::new(c1, c2))
    }

    /// Convert a block number to an XTS tweak (16-byte LE sector index).
    fn block_to_tweak(block_num: u64) -> [u8; 16] {
        let mut tweak = [0u8; 16];
        tweak[..8].copy_from_slice(&block_num.to_le_bytes());
        tweak
    }

    /// Encrypt a 4 KiB block in-place.
    fn encrypt_block_inplace(
        &self,
        block_num: u64,
        data: &mut [u8; BLOCK_SIZE],
    ) -> Result<(), BlockError> {
        let xts = self.make_xts()?;
        let tweak = Self::block_to_tweak(block_num);
        xts.encrypt_sector(data, tweak);
        Ok(())
    }

    /// Decrypt a 4 KiB block in-place.
    fn decrypt_block_inplace(
        &self,
        block_num: u64,
        data: &mut [u8; BLOCK_SIZE],
    ) -> Result<(), BlockError> {
        let xts = self.make_xts()?;
        let tweak = Self::block_to_tweak(block_num);
        xts.decrypt_sector(data, tweak);
        Ok(())
    }
}

impl fmt::Display for EncryptedBlockDevice<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EncryptedBlockDevice(sectors={})",
            self.inner.sector_count()
        )
    }
}

impl fmt::Debug for EncryptedBlockDevice<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedBlockDevice")
            .field("sectors", &self.inner.sector_count())
            .field("key", &"[REDACTED]")
            .finish()
    }
}

use core::fmt;

impl BlockDevice for EncryptedBlockDevice<'_> {
    /// Read sectors from the encrypted device, decrypting on the fly.
    ///
    /// Reads are buffered to 4 KiB block boundaries. For each 4 KiB block
    /// that overlaps the requested sector range, the full block is read from
    /// the underlying device, decrypted, and the relevant sectors are copied
    /// to `buf`.
    ///
    /// # Errors
    ///
    /// Returns [`BlockError`] if the underlying device read fails or the
    /// sector range is invalid.
    fn read_sectors(&self, lba: u64, count: u32, buf: &mut [u8]) -> Result<(), BlockError> {
        // WHY (finding 3): count is caller-controlled and SECTOR_SIZE is a
        // compile-time constant -- on a 32-bit target (usize == u32) count
        // * SECTOR_SIZE can wrap, letting an oversized buf.len() slip past
        // this check instead of being rejected. checked_mul rejects the
        // wrap instead of silently admitting it.
        let count_usize = usize::try_from(count).map_err(|_| BlockError::InvalidArgument)?;
        let expected_len = count_usize
            .checked_mul(SECTOR_SIZE)
            .ok_or(BlockError::InvalidArgument)?;
        if buf.len() != expected_len {
            return Err(BlockError::InvalidArgument);
        }
        if count == 0 {
            return Ok(());
        }

        // Check bounds.
        let end_lba = lba
            .checked_add(u64::from(count))
            .ok_or(BlockError::OutOfBounds)?;
        if end_lba > self.inner.sector_count() {
            return Err(BlockError::OutOfBounds);
        }

        let sectors_per_block = SECTORS_PER_BLOCK as u64;
        let mut buf_offset = 0usize;
        let mut current_lba = lba;
        let mut remaining = u64::from(count);

        while remaining > 0 {
            // Which 4K block does this LBA fall in?
            let block_num = current_lba / sectors_per_block;
            let block_start_lba = block_num * sectors_per_block;
            let offset_in_block = (current_lba - block_start_lba) as usize;

            // Read the full 4K block from the underlying device.
            let mut block_buf = [0u8; BLOCK_SIZE];
            self.inner
                .read_sectors(block_start_lba, SECTORS_PER_BLOCK as u32, &mut block_buf)?;

            // Decrypt the block.
            let xts = self.make_xts()?;
            let tweak = Self::block_to_tweak(block_num);
            xts.decrypt_sector(&mut block_buf, tweak);

            // Copy the relevant sectors from the decrypted block to buf.
            let sectors_available = SECTORS_PER_BLOCK - offset_in_block;
            let sectors_to_copy = (remaining as usize).min(sectors_available);
            let byte_offset = offset_in_block * SECTOR_SIZE;
            let byte_count = sectors_to_copy * SECTOR_SIZE;

            buf[buf_offset..buf_offset + byte_count]
                .copy_from_slice(&block_buf[byte_offset..byte_offset + byte_count]);

            buf_offset += byte_count;
            current_lba += sectors_to_copy as u64;
            remaining -= sectors_to_copy as u64;
        }

        Ok(())
    }

    /// Write sectors to the encrypted device, encrypting on the fly.
    ///
    /// Writes are buffered to 4 KiB block boundaries. For partial blocks
    /// (when the write does not align to 4 KiB boundaries), a read-modify-write
    /// is performed: the existing block is read, the relevant sectors are
    /// overwritten with plaintext, the full block is encrypted, and written back.
    ///
    /// # Errors
    ///
    /// Returns [`BlockError`] if the underlying device I/O fails or the
    /// sector range is invalid.
    fn write_sectors(&mut self, lba: u64, count: u32, buf: &[u8]) -> Result<(), BlockError> {
        // WHY (finding 3): same overflow guard as read_sectors -- count is
        // caller-controlled and SECTOR_SIZE is a compile-time constant; on
        // a 32-bit target (usize == u32) count * SECTOR_SIZE can wrap.
        let count_usize = usize::try_from(count).map_err(|_| BlockError::InvalidArgument)?;
        let expected_len = count_usize
            .checked_mul(SECTOR_SIZE)
            .ok_or(BlockError::InvalidArgument)?;
        if buf.len() != expected_len {
            return Err(BlockError::InvalidArgument);
        }
        if count == 0 {
            return Ok(());
        }

        // Check bounds.
        let end_lba = lba
            .checked_add(u64::from(count))
            .ok_or(BlockError::OutOfBounds)?;
        if end_lba > self.inner.sector_count() {
            return Err(BlockError::OutOfBounds);
        }

        let sectors_per_block = SECTORS_PER_BLOCK as u64;
        let mut buf_offset = 0usize;
        let mut current_lba = lba;
        let mut remaining = u64::from(count);

        while remaining > 0 {
            // Which 4K block does this LBA fall in?
            let block_num = current_lba / sectors_per_block;
            let block_start_lba = block_num * sectors_per_block;
            let offset_in_block = (current_lba - block_start_lba) as usize;

            let sectors_available = SECTORS_PER_BLOCK - offset_in_block;
            let sectors_to_write = (remaining as usize).min(sectors_available);
            let byte_offset = offset_in_block * SECTOR_SIZE;
            let byte_count = sectors_to_write * SECTOR_SIZE;

            let mut block_buf = [0u8; BLOCK_SIZE];

            // If this is a partial block write, read the existing block first
            // (read-modify-write) so we don't corrupt the unwritten sectors.
            if offset_in_block != 0 || sectors_to_write != SECTORS_PER_BLOCK {
                self.inner.read_sectors(
                    block_start_lba,
                    SECTORS_PER_BLOCK as u32,
                    &mut block_buf,
                )?;
                // Decrypt existing data so we can merge plaintext.
                self.decrypt_block_inplace(block_num, &mut block_buf)?;
            }

            // Merge the new plaintext sectors into the block.
            block_buf[byte_offset..byte_offset + byte_count]
                .copy_from_slice(&buf[buf_offset..buf_offset + byte_count]);

            // Encrypt the full block.
            self.encrypt_block_inplace(block_num, &mut block_buf)?;

            // Write the encrypted block to the underlying device.
            self.inner
                .write_sectors(block_start_lba, SECTORS_PER_BLOCK as u32, &block_buf)?;

            buf_offset += byte_count;
            current_lba += sectors_to_write as u64;
            remaining -= sectors_to_write as u64;
        }

        Ok(())
    }

    fn sector_count(&self) -> u64 {
        // Round down to the nearest full block boundary so that partial
        // trailing blocks are not exposed (they cannot be encrypted).
        let inner_sectors = self.inner.sector_count();
        let full_blocks = inner_sectors / SECTORS_PER_BLOCK as u64;
        full_blocks * SECTORS_PER_BLOCK as u64
    }
}

/// Convert a [`SecurityError`] to a [`BlockError`] for use in the
/// encryption layer.
impl From<SecurityError> for BlockError {
    fn from(e: SecurityError) -> Self {
        // WHY (finding 4): the old `_ => IoError` catch-all collapsed
        // ZeroIterations, HkdfOutputTooLong, and InvalidBlockSize --
        // caller/parameter validation failures, not I/O faults -- into the
        // same opaque IoError as a genuine CipherError. Map each variant by
        // its actual failure class: malformed/caller-controlled input maps
        // to InvalidArgument, and only a true cipher-operation failure maps
        // to IoError.
        match e {
            SecurityError::InvalidKeyLength
            | SecurityError::ZeroIterations
            | SecurityError::HkdfOutputTooLong
            | SecurityError::InvalidBlockSize => BlockError::InvalidArgument,
            SecurityError::CipherError => BlockError::IoError,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::block::MemBlockDevice;

    /// Create a test XTS key (64 bytes) with a simple pattern.
    fn sample_xts_key() -> [u8; XTS_KEY_SIZE] {
        let mut key = [0u8; XTS_KEY_SIZE];
        for (i, b) in key.iter_mut().enumerate() {
            *b = (i & 0xFF) as u8;
        }
        key
    }

    /// Create a second test key that differs from the first.
    fn alternate_sample_xts_key() -> [u8; XTS_KEY_SIZE] {
        let mut key = [0u8; XTS_KEY_SIZE];
        for (i, b) in key.iter_mut().enumerate() {
            *b = ((i + 0x80) & 0xFF) as u8;
        }
        key
    }

    /// Create a test plaintext pattern (4 KiB = 8 sectors).
    fn sample_plaintext() -> [u8; BLOCK_SIZE] {
        let mut buf = [0u8; BLOCK_SIZE];
        for (i, b) in buf.iter_mut().enumerate() {
            *b = (i & 0xFF) as u8;
        }
        buf
    }

    // 16 sectors = 2 full blocks
    const TEST_SECTORS: u64 = 16;

    #[test]
    fn encrypted_write_then_read_round_trips() {
        let mut dev = MemBlockDevice::new(TEST_SECTORS).expect("create device");
        let key = sample_xts_key();
        let plaintext = sample_plaintext();

        // Write plaintext through the encrypted layer.
        {
            let mut enc = EncryptedBlockDevice::new(&mut dev, key);
            enc.write_sectors(0, SECTORS_PER_BLOCK as u32, &plaintext)
                .expect("encrypted write failed");
        }

        // Read it back through the encrypted layer.
        {
            let enc = EncryptedBlockDevice::new(&mut dev, key);
            let mut readback = [0u8; BLOCK_SIZE];
            enc.read_sectors(0, SECTORS_PER_BLOCK as u32, &mut readback)
                .expect("encrypted read failed");

            assert_eq!(
                readback, plaintext,
                "decrypted data must match original plaintext"
            );
        }
    }

    #[test]
    fn encrypted_data_differs_from_plaintext() {
        let mut dev = MemBlockDevice::new(TEST_SECTORS).expect("create device");
        let key = sample_xts_key();
        let plaintext = sample_plaintext();

        // Write plaintext through the encrypted layer.
        {
            let mut enc = EncryptedBlockDevice::new(&mut dev, key);
            enc.write_sectors(0, SECTORS_PER_BLOCK as u32, &plaintext)
                .expect("encrypted write failed");
        }

        // Read raw ciphertext directly from the underlying device.
        let mut raw = [0u8; BLOCK_SIZE];
        dev.read_sectors(0, SECTORS_PER_BLOCK as u32, &mut raw)
            .expect("raw read failed");

        assert_ne!(
            raw, plaintext,
            "ciphertext on disk must differ from plaintext"
        );
    }

    #[test]
    fn different_keys_produce_different_ciphertext() {
        let plaintext = sample_plaintext();

        // Encrypt with key 1.
        let mut dev1 = MemBlockDevice::new(TEST_SECTORS).expect("create device");
        {
            let mut enc = EncryptedBlockDevice::new(&mut dev1, sample_xts_key());
            enc.write_sectors(0, SECTORS_PER_BLOCK as u32, &plaintext)
                .expect("write key1");
        }
        let mut ct1 = [0u8; BLOCK_SIZE];
        dev1.read_sectors(0, SECTORS_PER_BLOCK as u32, &mut ct1)
            .expect("raw read key1");

        // Encrypt with key 2.
        let mut dev2 = MemBlockDevice::new(TEST_SECTORS).expect("create device");
        {
            let mut enc = EncryptedBlockDevice::new(&mut dev2, alternate_sample_xts_key());
            enc.write_sectors(0, SECTORS_PER_BLOCK as u32, &plaintext)
                .expect("write key2");
        }
        let mut ct2 = [0u8; BLOCK_SIZE];
        dev2.read_sectors(0, SECTORS_PER_BLOCK as u32, &mut ct2)
            .expect("raw read key2");

        assert_ne!(ct1, ct2, "different keys must produce different ciphertext");
    }

    #[test]
    fn sector_alignment_handled_correctly() {
        // Write a partial block (less than 8 sectors) and verify round-trip.
        let mut dev = MemBlockDevice::new(TEST_SECTORS).expect("create device");
        let key = sample_xts_key();

        // Write 2 sectors starting at LBA 0.
        let write_data = vec![0xABu8; 2 * SECTOR_SIZE];
        {
            let mut enc = EncryptedBlockDevice::new(&mut dev, key);
            enc.write_sectors(0, 2, &write_data)
                .expect("partial write failed");
        }

        // Read back the same 2 sectors.
        let mut read_data = vec![0u8; 2 * SECTOR_SIZE];
        {
            let enc = EncryptedBlockDevice::new(&mut dev, key);
            enc.read_sectors(0, 2, &mut read_data)
                .expect("partial read failed");
        }

        assert_eq!(
            read_data, write_data,
            "partial sector read must match write"
        );
    }

    #[test]
    fn multi_block_write_read() {
        // Write two full blocks and verify each decrypts correctly.
        let mut dev = MemBlockDevice::new(TEST_SECTORS).expect("create device");
        let key = sample_xts_key();

        let mut data = vec![0u8; 2 * BLOCK_SIZE];
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i & 0xFF) as u8;
        }

        {
            let mut enc = EncryptedBlockDevice::new(&mut dev, key);
            enc.write_sectors(0, (2 * SECTORS_PER_BLOCK) as u32, &data)
                .expect("multi-block write failed");
        }

        let mut readback = vec![0u8; 2 * BLOCK_SIZE];
        {
            let enc = EncryptedBlockDevice::new(&mut dev, key);
            enc.read_sectors(0, (2 * SECTORS_PER_BLOCK) as u32, &mut readback)
                .expect("multi-block read failed");
        }

        assert_eq!(readback, data, "multi-block round-trip must match");
    }

    #[test]
    fn cross_block_boundary_write() {
        // Write sectors that span a block boundary (sectors 6-9 cross block 0/1).
        let mut dev = MemBlockDevice::new(TEST_SECTORS).expect("create device");
        let key = sample_xts_key();

        let write_data = vec![0xCDu8; 4 * SECTOR_SIZE];
        {
            let mut enc = EncryptedBlockDevice::new(&mut dev, key);
            enc.write_sectors(6, 4, &write_data)
                .expect("cross-boundary write failed");
        }

        let mut read_data = vec![0u8; 4 * SECTOR_SIZE];
        {
            let enc = EncryptedBlockDevice::new(&mut dev, key);
            enc.read_sectors(6, 4, &mut read_data)
                .expect("cross-boundary read failed");
        }

        assert_eq!(
            read_data, write_data,
            "cross-block-boundary round-trip must match"
        );
    }

    #[test]
    fn out_of_bounds_returns_error() {
        let mut dev = MemBlockDevice::new(TEST_SECTORS).expect("create device");
        let key = sample_xts_key();

        let enc = EncryptedBlockDevice::new(&mut dev, key);
        let mut buf = vec![0u8; SECTOR_SIZE];
        let result = enc.read_sectors(TEST_SECTORS, 1, &mut buf);
        assert_eq!(result, Err(BlockError::OutOfBounds));
    }

    #[test]
    fn write_sectors_length_mismatch_returns_error() {
        // Done-when (finding 21): a buffer whose length doesn't match
        // count * SECTOR_SIZE must be rejected before any write happens.
        let mut dev = MemBlockDevice::new(TEST_SECTORS).expect("create device");
        let key = sample_xts_key();
        let mut enc = EncryptedBlockDevice::new(&mut dev, key);

        let short_buf = vec![0u8; SECTOR_SIZE - 1];
        let result = enc.write_sectors(0, 1, &short_buf);
        assert_eq!(result, Err(BlockError::InvalidArgument));

        let long_buf = vec![0u8; SECTOR_SIZE + 1];
        let result = enc.write_sectors(0, 1, &long_buf);
        assert_eq!(result, Err(BlockError::InvalidArgument));
    }

    #[test]
    fn write_sectors_out_of_bounds_returns_error() {
        // Done-when (finding 21): a write past the device's sector count
        // must be rejected, mirroring the existing read_sectors OOB
        // coverage.
        let mut dev = MemBlockDevice::new(TEST_SECTORS).expect("create device");
        let key = sample_xts_key();
        let mut enc = EncryptedBlockDevice::new(&mut dev, key);

        let buf = vec![0u8; SECTOR_SIZE];
        let result = enc.write_sectors(TEST_SECTORS, 1, &buf);
        assert_eq!(result, Err(BlockError::OutOfBounds));
    }

    #[test]
    fn sector_count_rounds_to_block_boundary() {
        // 13 sectors -> 8 usable sectors (1 full block)
        let mut dev = MemBlockDevice::new(13).expect("create device");
        let key = sample_xts_key();
        let enc = EncryptedBlockDevice::new(&mut dev, key);
        assert_eq!(
            enc.sector_count(),
            8,
            "sector count must round down to block boundary"
        );
    }

    #[test]
    fn zero_count_succeeds() {
        let mut dev = MemBlockDevice::new(TEST_SECTORS).expect("create device");
        let key = sample_xts_key();
        let enc = EncryptedBlockDevice::new(&mut dev, key);
        let mut buf = vec![];
        enc.read_sectors(0, 0, &mut buf)
            .expect("zero-count read must succeed");
    }

    #[test]
    fn key_is_a_zeroizable_secure_key() {
        // Regression test for #332: the XTS key must be a SecureKey (which
        // write_volatile-zeroizes on drop), not a bare array. Verified via
        // direct field access — the tests submodule can see private fields
        // of its ancestor module, same pattern key_manager.rs itself uses.
        let mut dev = MemBlockDevice::new(TEST_SECTORS).expect("create device");
        let key = sample_xts_key();
        let mut enc = EncryptedBlockDevice::new(&mut dev, key);
        assert!(
            !enc.key.is_zero(),
            "key must hold the real XTS key before zeroize"
        );
        enc.key.zeroize();
        assert!(
            enc.key.is_zero(),
            "SecureKey::zeroize must clear the XTS key"
        );
    }

    #[test]
    fn encrypted_block_device_display() {
        let mut dev = MemBlockDevice::new(TEST_SECTORS).expect("create device");
        let key = sample_xts_key();
        let enc = EncryptedBlockDevice::new(&mut dev, key);
        let s = alloc::format!("{enc}");
        assert!(
            s.contains("EncryptedBlockDevice"),
            "display must contain type name"
        );
    }
}
