//! Block device abstraction layer.
//!
//! Defines the [`BlockDevice`] trait for sector-based I/O and provides two
//! implementations:
//!
//! - [`MemBlockDevice`]: in-memory mock backed by `Vec<u8>`, available in all
//!   builds including tests.
//! - [`MsdcBlockDevice`]: wraps the MT6739 MSDC controller from [`crate::emmc`],
//!   available only in non-test builds.
//!
//! All operations use 512-byte sector granularity. Higher layers (block cache,
//! filesystem) operate at 4 KiB logical-block granularity by issuing multiple
//! sector operations.

extern crate alloc;
use core::fmt;

use alloc::vec;
use alloc::vec::Vec;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Sector size in bytes (eMMC / SD standard).
pub(crate) const SECTOR_SIZE: usize = 512;

/// Logical block size in bytes (filesystem granularity).
pub(crate) const BLOCK_SIZE: usize = 4096;

/// Number of 512-byte sectors per 4 KiB logical block.
pub(crate) const SECTORS_PER_BLOCK: usize = BLOCK_SIZE / SECTOR_SIZE;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur during block device operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BlockError {
    /// A low-level I/O error occurred during the transfer.
    IoError,
    /// The requested sector range extends beyond the device boundary.
    OutOfBounds,
    /// An argument (buffer size, count, etc.) is invalid.
    InvalidArgument,
    /// The device has not been initialized or is not ready for I/O.
    DeviceNotReady,
}

impl fmt::Display for BlockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IoError => write!(f, "block I/O error"),
            Self::OutOfBounds => write!(f, "sector range out of bounds"),
            Self::InvalidArgument => write!(f, "invalid argument"),
            Self::DeviceNotReady => write!(f, "device not ready"),
        }
    }
}

// ---------------------------------------------------------------------------
// BlockDevice trait
// ---------------------------------------------------------------------------

/// Trait for sector-addressed block devices.
///
/// All implementations operate at [`SECTOR_SIZE`]-byte granularity. The `buf`
/// slice must be exactly `count * sector_size()` bytes.
pub(crate) trait BlockDevice {
    /// Read `count` contiguous sectors starting at logical block address `lba`.
    ///
    /// # Errors
    ///
    /// - [`BlockError::OutOfBounds`] if `lba + count` exceeds `sector_count()`.
    /// - [`BlockError::InvalidArgument`] if `buf.len() != count * sector_size()`.
    /// - [`BlockError::IoError`] on hardware failure.
    fn read_sectors(&self, lba: u64, count: u32, buf: &mut [u8]) -> Result<(), BlockError>;

    /// Write `count` contiguous sectors starting at logical block address `lba`.
    ///
    /// # Errors
    ///
    /// - [`BlockError::OutOfBounds`] if `lba + count` exceeds `sector_count()`.
    /// - [`BlockError::InvalidArgument`] if `buf.len() != count * sector_size()`.
    /// - [`BlockError::IoError`] on hardware failure.
    fn write_sectors(&mut self, lba: u64, count: u32, buf: &[u8]) -> Result<(), BlockError>;

    /// Total number of sectors on the device.
    fn sector_count(&self) -> u64;

    /// Bytes per sector. Defaults to 512.
    fn sector_size(&self) -> usize {
        SECTOR_SIZE
    }
}

// ---------------------------------------------------------------------------
// MemBlockDevice — in-memory mock
// ---------------------------------------------------------------------------

/// In-memory block device backed by a `Vec<u8>`.
///
/// All data starts zeroed. Used as the test double for filesystem and cache
/// testing without requiring real hardware.
#[derive(Debug)]
pub struct MemBlockDevice {
    /// Backing storage: `sector_count * SECTOR_SIZE` bytes.
    data: Vec<u8>,
    /// Number of sectors.
    sectors: u64,
}

impl MemBlockDevice {
    /// Create a new zeroed device with `sector_count` sectors.
    ///
    /// # Errors
    ///
    /// Returns [`BlockError::InvalidArgument`] if `sector_count` is zero.
    #[must_use]
    pub(crate) fn new(sector_count: u64) -> Result<Self, BlockError> {
        if sector_count == 0 {
            return Err(BlockError::InvalidArgument);
        }
        let size = sector_count as usize * SECTOR_SIZE;
        Ok(Self {
            data: vec![0u8; size],
            sectors: sector_count,
        })
    }

    /// Validate that an LBA range is within device bounds.
    fn validate_range(&self, lba: u64, count: u32) -> Result<(), BlockError> {
        let end = lba.checked_add(u64::from(count)).ok_or(BlockError::OutOfBounds)?;
        if end > self.sectors {
            return Err(BlockError::OutOfBounds);
        }
        Ok(())
    }

    /// Validate that a buffer has the correct size for the sector count.
    fn validate_buf_len(&self, buf_len: usize, count: u32) -> Result<(), BlockError> {
        let expected = count as usize * SECTOR_SIZE;
        if buf_len != expected {
            return Err(BlockError::InvalidArgument);
        }
        Ok(())
    }

    /// Byte offset for a given LBA.
    fn offset(&self, lba: u64) -> usize {
        lba as usize * SECTOR_SIZE
    }
}

impl BlockDevice for MemBlockDevice {
    fn read_sectors(&self, lba: u64, count: u32, buf: &mut [u8]) -> Result<(), BlockError> {
        self.validate_range(lba, count)?;
        self.validate_buf_len(buf.len(), count)?;

        let start = self.offset(lba);
        let len = count as usize * SECTOR_SIZE;
        buf.copy_from_slice(&self.data[start..start + len]);
        Ok(())
    }

    fn write_sectors(&mut self, lba: u64, count: u32, buf: &[u8]) -> Result<(), BlockError> {
        self.validate_range(lba, count)?;
        self.validate_buf_len(buf.len(), count)?;

        let start = self.offset(lba);
        let len = count as usize * SECTOR_SIZE;
        self.data[start..start + len].copy_from_slice(buf);
        Ok(())
    }

    fn sector_count(&self) -> u64 {
        self.sectors
    }
}

// ---------------------------------------------------------------------------
// MsdcBlockDevice — hardware wrapper (non-test only)
// ---------------------------------------------------------------------------

#[cfg(not(test))]
mod msdc_wrapper {
    use super::{BlockDevice, BlockError, SECTOR_SIZE};
    use crate::emmc::MsdcController;

    /// Block device backed by the MT6739 MSDC eMMC controller.
    ///
    /// Wraps [`MsdcController`] to provide the [`BlockDevice`] trait. Each
    /// read/write call issues single-sector PIO transfers in a loop.
    ///
    /// The controller must be initialized via [`MsdcBlockDevice::init`] before
    /// any I/O. Sector count is fixed at construction (read from CSD or
    /// hard-coded for the known eMMC part).
    pub(crate) struct MsdcBlockDevice {
        /// The underlying MSDC controller.
        controller: MsdcController,
        /// Total sector count of the eMMC device.
        sector_count: u64,
    }

    impl MsdcBlockDevice {
        /// Create a new MSDC block device with a known sector count.
        ///
        /// The controller is NOT initialized — call [`MsdcBlockDevice::init`]
        /// before issuing any I/O.
        pub(crate) fn new(sector_count: u64) -> Self {
            Self {
                controller: MsdcController::new(),
                sector_count,
            }
        }

        /// Initialize the underlying MSDC controller.
        ///
        /// # Safety
        ///
        /// Must be called exactly once after power-on. The MSDC register block
        /// must be mapped and accessible.
        ///
        /// # Errors
        ///
        /// Returns [`BlockError::DeviceNotReady`] if hardware initialization fails.
        #[expect(unsafe_code, reason = "MMIO register access requires raw pointer dereference")]
        pub unsafe fn init(&mut self) -> Result<(), BlockError> {
            // SAFETY: caller guarantees the MSDC register block is mapped, and
            // this is called exactly once after power-on per the function contract.
            unsafe {
                self.controller.init().map_err(|_| BlockError::DeviceNotReady)
            }
        }
    }

    impl BlockDevice for MsdcBlockDevice {
        #[expect(unsafe_code, reason = "MMIO register access requires raw pointer dereference")]
        fn read_sectors(&self, lba: u64, count: u32, buf: &mut [u8]) -> Result<(), BlockError> {
            if !self.controller.is_initialized() {
                return Err(BlockError::DeviceNotReady);
            }

            let end = lba
                .checked_add(u64::from(count))
                .ok_or(BlockError::OutOfBounds)?;
            if end > self.sector_count {
                return Err(BlockError::OutOfBounds);
            }
            let expected_len = count as usize * SECTOR_SIZE;
            if buf.len() != expected_len {
                return Err(BlockError::InvalidArgument);
            }

            for i in 0..count {
                let sector_lba = lba + u64::from(i);
                // The MSDC controller uses u32 LBAs. For eMMC parts on MT6739,
                // this is always sufficient (max ~128 GiB with sector addressing).
                let lba32 = u32::try_from(sector_lba).map_err(|_| BlockError::OutOfBounds)?;
                let offset = i as usize * SECTOR_SIZE;
                let sector_buf: &mut [u8; SECTOR_SIZE] = (&mut buf[offset..offset + SECTOR_SIZE])
                    .try_into()
                    .map_err(|_| BlockError::InvalidArgument)?;

                // SAFETY: controller.is_initialized() was verified above.
                // The register block is valid for the lifetime of the device
                // (hardware is memory-mapped and never unmapped on this SoC).
                unsafe {
                    self.controller
                        .read_sector(lba32, sector_buf)
                        .map_err(|_| BlockError::IoError)?;
                }
            }
            Ok(())
        }

        #[expect(unsafe_code, reason = "MMIO register access requires raw pointer dereference")]
        fn write_sectors(&mut self, lba: u64, count: u32, buf: &[u8]) -> Result<(), BlockError> {
            if !self.controller.is_initialized() {
                return Err(BlockError::DeviceNotReady);
            }

            let end = lba
                .checked_add(u64::from(count))
                .ok_or(BlockError::OutOfBounds)?;
            if end > self.sector_count {
                return Err(BlockError::OutOfBounds);
            }
            let expected_len = count as usize * SECTOR_SIZE;
            if buf.len() != expected_len {
                return Err(BlockError::InvalidArgument);
            }

            for i in 0..count {
                let sector_lba = lba + u64::from(i);
                let lba32 = u32::try_from(sector_lba).map_err(|_| BlockError::OutOfBounds)?;
                let offset = i as usize * SECTOR_SIZE;
                let sector_buf: &[u8; SECTOR_SIZE] = (&buf[offset..offset + SECTOR_SIZE])
                    .try_into()
                    .map_err(|_| BlockError::InvalidArgument)?;

                // SAFETY: controller.is_initialized() was verified above.
                // The register block is valid for the lifetime of the device.
                unsafe {
                    self.controller
                        .write_sector(lba32, sector_buf)
                        .map_err(|_| BlockError::IoError)?;
                }
            }
            Ok(())
        }

        fn sector_count(&self) -> u64 {
            self.sector_count
        }
    }
}

#[cfg(not(test))]
pub(crate) use msdc_wrapper::MsdcBlockDevice;

// ---------------------------------------------------------------------------
// Block-level I/O helpers
// ---------------------------------------------------------------------------

/// Read one 4 KiB logical block from a block device.
///
/// Reads [`SECTORS_PER_BLOCK`] sectors starting at the sector address
/// corresponding to `block_num`.
///
/// # Errors
///
/// Returns [`BlockError`] if the underlying sector read fails or the
/// block address is out of bounds.
#[must_use]
pub(crate) fn read_block(
    dev: &dyn BlockDevice,
    block_num: u64,
    buf: &mut [u8; BLOCK_SIZE],
) -> Result<(), BlockError> {
    let lba = block_num * SECTORS_PER_BLOCK as u64;
    dev.read_sectors(lba, SECTORS_PER_BLOCK as u32, buf)
}

/// Write one 4 KiB logical block to a block device.
///
/// Writes [`SECTORS_PER_BLOCK`] sectors starting at the sector address
/// corresponding to `block_num`.
///
/// # Errors
///
/// Returns [`BlockError`] if the underlying sector write fails or the
/// block address is out of bounds.
#[must_use]
pub(crate) fn write_block(
    dev: &mut dyn BlockDevice,
    block_num: u64,
    buf: &[u8; BLOCK_SIZE],
) -> Result<(), BlockError> {
    let lba = block_num * SECTORS_PER_BLOCK as u64;
    dev.write_sectors(lba, SECTORS_PER_BLOCK as u32, buf)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    #[test]
    fn create_mem_device_with_correct_size() {
        let dev = MemBlockDevice::new(16).expect("failed to create device");
        assert_eq!(dev.sector_count(), 16);
        assert_eq!(dev.sector_size(), SECTOR_SIZE);
        assert_eq!(dev.data.len(), 16 * SECTOR_SIZE);
    }

    #[test]
    fn read_returns_zeroes_on_fresh_device() {
        let dev = MemBlockDevice::new(8).expect("failed to create device");
        let mut buf = vec![0xFFu8; SECTOR_SIZE];
        dev.read_sectors(0, 1, &mut buf).expect("read failed");
        assert!(buf.iter().all(|&b| b == 0), "fresh device should be zeroed");
    }

    #[test]
    fn write_then_read_returns_same_data() {
        let mut dev = MemBlockDevice::new(8).expect("failed to create device");
        let write_data: Vec<u8> = (0..SECTOR_SIZE).map(|i| (i & 0xFF) as u8).collect();
        dev.write_sectors(0, 1, &write_data).expect("write failed");

        let mut read_buf = vec![0u8; SECTOR_SIZE];
        dev.read_sectors(0, 1, &mut read_buf).expect("read failed");
        assert_eq!(read_buf, write_data);
    }

    #[test]
    fn read_out_of_bounds_returns_error() {
        let dev = MemBlockDevice::new(4).expect("failed to create device");
        let mut buf = vec![0u8; SECTOR_SIZE];
        let result = dev.read_sectors(4, 1, &mut buf);
        assert_eq!(result, Err(BlockError::OutOfBounds));
    }

    #[test]
    fn write_out_of_bounds_returns_error() {
        let mut dev = MemBlockDevice::new(4).expect("failed to create device");
        let buf = vec![0u8; SECTOR_SIZE];
        let result = dev.write_sectors(4, 1, &buf);
        assert_eq!(result, Err(BlockError::OutOfBounds));
    }

    #[test]
    fn read_multi_sector_returns_correct_data() {
        let mut dev = MemBlockDevice::new(8).expect("failed to create device");
        // Write distinct patterns to sectors 2 and 3.
        let s2: Vec<u8> = vec![0xAA; SECTOR_SIZE];
        let s3: Vec<u8> = vec![0xBB; SECTOR_SIZE];
        dev.write_sectors(2, 1, &s2).expect("write s2 failed");
        dev.write_sectors(3, 1, &s3).expect("write s3 failed");

        // Read both sectors in one call.
        let mut buf = vec![0u8; 2 * SECTOR_SIZE];
        dev.read_sectors(2, 2, &mut buf).expect("multi-read failed");
        assert!(buf[..SECTOR_SIZE].iter().all(|&b| b == 0xAA));
        assert!(buf[SECTOR_SIZE..].iter().all(|&b| b == 0xBB));
    }

    #[test]
    fn invalid_buf_size_returns_error() {
        let dev = MemBlockDevice::new(4).expect("failed to create device");
        // Buffer too small for 1 sector.
        let mut buf = vec![0u8; SECTOR_SIZE - 1];
        let result = dev.read_sectors(0, 1, &mut buf);
        assert_eq!(result, Err(BlockError::InvalidArgument));
    }

    #[test]
    fn zero_count_read_succeeds() {
        let dev = MemBlockDevice::new(4).expect("failed to create device");
        let mut buf = vec![];
        dev.read_sectors(0, 0, &mut buf).expect("zero-count read should succeed");
    }

    #[test]
    fn zero_sector_count_device_fails() {
        let result = MemBlockDevice::new(0);
        assert!(result.is_err(), "zero-sector device should fail");
        assert_eq!(
            result.err(),
            Some(BlockError::InvalidArgument),
            "should return InvalidArgument"
        );
    }

    // -- FailingBlockDevice: test mock that returns IoError --

    /// A block device mock that returns [`BlockError::IoError`] on reads/writes
    /// to specific sectors, and [`BlockError::DeviceNotReady`] when not initialized.
    struct FailingBlockDevice {
        /// Whether the device has been "initialized".
        ready: bool,
        /// Sector that triggers an `IoError` (all others succeed like `MemBlockDevice`).
        fail_sector: u64,
        /// Total sector count.
        sectors: u64,
        /// Backing storage.
        data: Vec<u8>,
    }

    impl FailingBlockDevice {
        fn new(sector_count: u64, fail_sector: u64) -> Self {
            let size = sector_count as usize * SECTOR_SIZE;
            Self {
                ready: false,
                fail_sector,
                sectors: sector_count,
                data: vec![0u8; size],
            }
        }
    }

    impl BlockDevice for FailingBlockDevice {
        fn read_sectors(&self, lba: u64, count: u32, buf: &mut [u8]) -> Result<(), BlockError> {
            if !self.ready {
                return Err(BlockError::DeviceNotReady);
            }
            // Check if any requested sector is the failing one.
            for i in 0..u64::from(count) {
                if lba + i == self.fail_sector {
                    return Err(BlockError::IoError);
                }
            }
            let end = lba.checked_add(u64::from(count)).ok_or(BlockError::OutOfBounds)?;
            if end > self.sectors {
                return Err(BlockError::OutOfBounds);
            }
            let expected = count as usize * SECTOR_SIZE;
            if buf.len() != expected {
                return Err(BlockError::InvalidArgument);
            }
            let start = lba as usize * SECTOR_SIZE;
            buf.copy_from_slice(&self.data[start..start + expected]);
            Ok(())
        }

        fn write_sectors(&mut self, lba: u64, count: u32, buf: &[u8]) -> Result<(), BlockError> {
            if !self.ready {
                return Err(BlockError::DeviceNotReady);
            }
            for i in 0..u64::from(count) {
                if lba + i == self.fail_sector {
                    return Err(BlockError::IoError);
                }
            }
            let end = lba.checked_add(u64::from(count)).ok_or(BlockError::OutOfBounds)?;
            if end > self.sectors {
                return Err(BlockError::OutOfBounds);
            }
            let expected = count as usize * SECTOR_SIZE;
            if buf.len() != expected {
                return Err(BlockError::InvalidArgument);
            }
            let start = lba as usize * SECTOR_SIZE;
            self.data[start..start + expected].copy_from_slice(buf);
            Ok(())
        }

        fn sector_count(&self) -> u64 {
            self.sectors
        }
    }

    #[test]
    fn read_on_not_ready_device_returns_error() {
        let dev = FailingBlockDevice::new(8, 99);
        // Device is not ready (ready=false).
        let mut buf = vec![0u8; SECTOR_SIZE];
        let result = dev.read_sectors(0, 1, &mut buf);
        assert_eq!(result, Err(BlockError::DeviceNotReady));
    }

    #[test]
    fn io_error_propagates_on_failing_sector() {
        let mut dev = FailingBlockDevice::new(8, 3);
        dev.ready = true;

        // Read from the failing sector.
        let mut buf = vec![0u8; SECTOR_SIZE];
        let result = dev.read_sectors(3, 1, &mut buf);
        assert_eq!(result, Err(BlockError::IoError));

        // Write to the failing sector.
        let buf = vec![0xAA; SECTOR_SIZE];
        let result = dev.write_sectors(3, 1, &buf);
        assert_eq!(result, Err(BlockError::IoError));

        // Non-failing sectors should still work.
        let mut read_buf = vec![0u8; SECTOR_SIZE];
        let result = dev.read_sectors(0, 1, &mut read_buf);
        assert_eq!(result, Ok(()));
    }
}
