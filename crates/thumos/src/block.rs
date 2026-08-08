//! Block device abstraction layer.
//!
//! Defines the [`BlockDevice`] trait for sector-based I/O and provides two
//! implementations:
//!
//! - [`MemBlockDevice`]: in-memory mock backed by `Vec<u8>`, available in all
//!   builds including tests.
//! - [`MsdcBlockDevice`]: generic over `crate::emmc::MsdcOps` (#631), wrapping
//!   the real MT6739 MSDC controller on hardware and a fake under test/qemu
//!   -- available, and host-tested, on every target.
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

/// Mutable references forward to the underlying device so views compose
/// over `&mut dyn BlockDevice` (#467's boot-partition view). A shared
/// reference gets no impl by design: `write_sectors` cannot honestly
/// forward through one.
impl<D: BlockDevice + ?Sized> BlockDevice for &mut D {
    fn read_sectors(&self, lba: u64, count: u32, buf: &mut [u8]) -> Result<(), BlockError> {
        (**self).read_sectors(lba, count, buf)
    }
    fn write_sectors(&mut self, lba: u64, count: u32, buf: &[u8]) -> Result<(), BlockError> {
        (**self).write_sectors(lba, count, buf)
    }
    fn sector_count(&self) -> u64 {
        (**self).sector_count()
    }
}

// ---------------------------------------------------------------------------
// PartitionBlockDevice — partition view over a physical device (#603)
// ---------------------------------------------------------------------------

/// A partition view over a physical [`BlockDevice`]: view LBAs `[0, len)`
/// map onto `base_lba + lba` of the inner device, and every access is
/// bounds-checked against the partition length — never the whole device.
///
/// WHY (#603): `MsdcBlockDevice` addressed the eMMC from physical sector 0,
/// so the LFS mount path would have written the GPT/boot region instead of
/// the userdata partition (`LFS_PARTITION_START` had no consumer). The view
/// makes partition addressing explicit and host-testable: a
/// `MemBlockDevice` stands in as the physical device, the view as the
/// partition. The #449 secrets preamble is a second view onto the same
/// userdata partition's head sectors.
///
/// WHY the gate: the only production consumer today is the eMMC/LFS mount
/// path, which is M7-only (#534) — on virt the view would be dead surface.
#[cfg(not(feature = "qemu"))]
pub(crate) struct PartitionBlockDevice<D: BlockDevice> {
    /// The physical device this view carves from.
    inner: D,
    /// First physical sector of the partition.
    base_lba: u64,
    /// Partition length in sectors.
    sector_count: u64,
}

#[cfg(not(feature = "qemu"))]
impl<D: BlockDevice> PartitionBlockDevice<D> {
    /// Create a partition view `[base_lba, base_lba + sector_count)` of
    /// `inner`. `base_lba` must be within the inner device's bounds; every
    /// I/O revalidates the range against the partition length.
    pub(crate) const fn new(inner: D, base_lba: u64, sector_count: u64) -> Self {
        Self {
            inner,
            base_lba,
            sector_count,
        }
    }

    /// Consume the view and return the physical device.
    #[cfg(test)]
    pub(crate) fn into_inner(self) -> D {
        self.inner
    }

    /// Translate a view `[lba, lba+count)` to its physical base LBA,
    /// bounds-checked against the partition length (and u64 overflow).
    fn translate(&self, lba: u64, count: u32) -> Result<u64, BlockError> {
        let end = lba
            .checked_add(u64::from(count))
            .ok_or(BlockError::OutOfBounds)?;
        if end > self.sector_count {
            return Err(BlockError::OutOfBounds);
        }
        self.base_lba
            .checked_add(lba)
            .ok_or(BlockError::OutOfBounds)
    }
}

#[cfg(not(feature = "qemu"))]
impl<D: BlockDevice> BlockDevice for PartitionBlockDevice<D> {
    fn read_sectors(&self, lba: u64, count: u32, buf: &mut [u8]) -> Result<(), BlockError> {
        let phys = self.translate(lba, count)?;
        self.inner.read_sectors(phys, count, buf)
    }

    fn write_sectors(&mut self, lba: u64, count: u32, buf: &[u8]) -> Result<(), BlockError> {
        let phys = self.translate(lba, count)?;
        self.inner.write_sectors(phys, count, buf)
    }

    /// The PARTITION length in sectors — never the physical device's.
    fn sector_count(&self) -> u64 {
        self.sector_count
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
        let end = lba
            .checked_add(u64::from(count))
            .ok_or(BlockError::OutOfBounds)?;
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
// MsdcBlockDevice — MSDC/eMMC wrapper (#631)
// ---------------------------------------------------------------------------
//
// Generic over `MsdcOps` so this typestate and the read/write bounds/
// overflow/narrowing logic below run against `crate::emmc::FakeMsdc` on
// every target. `C` defaults to `BootMsdc` (the real controller on
// hardware, the fake under test/qemu), so every existing production call
// site (`MsdcBlockDeviceUninit::new(sector_count)`, `MsdcBlockDevice` used
// bare as a type) keeps compiling unchanged.

// WHY (#631): gated on the qemu feature ALONE, not on `test`. A host test
// build selects the m7 board, so this wrapper compiles and its logic is
// exercised off-hardware -- which is the entire point of the seam. The virt
// board QEMU runs models no MSDC at all, so there is nothing here to back.
#[cfg(not(feature = "qemu"))]
mod msdc_wrapper {
    use super::{BlockDevice, BlockError, SECTOR_SIZE};
    use crate::emmc::{BootMsdc, MsdcOps};

    /// An MSDC block device that has not been initialized yet.
    ///
    /// WHY (#619): this type exists so that "constructed but never initialized"
    /// cannot reach an I/O call. It deliberately does NOT implement
    /// [`BlockDevice`], and [`MsdcBlockDevice`] has no public constructor, so
    /// the only route to a usable device is [`Self::init`]. A call site that
    /// forgets to initialize now fails to compile rather than returning
    /// [`BlockError::DeviceNotReady`] at the first read — which, at the
    /// secure-boot GPT read, presented as an unconditional boot halt.
    ///
    /// Sector count is fixed at construction (read from CSD or hard-coded for
    /// the known eMMC part) and carried through initialization.
    pub(crate) struct MsdcBlockDeviceUninit<C: MsdcOps = BootMsdc> {
        /// The underlying MSDC controller, not yet initialized.
        controller: C,
        /// Total sector count of the eMMC device.
        sector_count: u64,
    }

    impl MsdcBlockDeviceUninit<BootMsdc> {
        /// Create an uninitialized MSDC block device with a known sector
        /// count, backed by the boot-wired controller (the real
        /// `crate::emmc::MsdcController` on hardware,
        /// `crate::emmc::FakeMsdc` under test/qemu).
        pub(crate) fn new(sector_count: u64) -> Self {
            Self {
                controller: BootMsdc::default(),
                sector_count,
            }
        }
    }

    impl<C: MsdcOps> MsdcBlockDeviceUninit<C> {
        /// Construct an uninitialized device around a specific controller
        /// instance (#631 test seam): lets a test pre-configure a
        /// `crate::emmc::FakeMsdc`'s failure knobs before calling
        /// [`Self::init`].
        #[cfg(test)]
        pub(crate) fn with_controller(controller: C, sector_count: u64) -> Self {
            Self {
                controller,
                sector_count,
            }
        }

        /// Initialize the controller, yielding a usable [`MsdcBlockDevice`].
        ///
        /// Consumes `self`, so the uninitialized handle is gone on success and
        /// cannot be used afterwards.
        ///
        /// # Safety
        ///
        /// Must be called exactly once after power-on. The MSDC register block
        /// must be mapped and accessible.
        ///
        /// # Errors
        ///
        /// Returns [`BlockError::DeviceNotReady`] if hardware initialization
        /// fails. No [`MsdcBlockDevice`] is produced in that case.
        #[expect(
            unsafe_code,
            reason = "MMIO register access requires raw pointer dereference"
        )]
        pub unsafe fn init(mut self) -> Result<MsdcBlockDevice<C>, BlockError> {
            // SAFETY: caller guarantees the MSDC register block is mapped, and
            // this is called exactly once after power-on per the function contract.
            unsafe {
                self.controller
                    .init()
                    .map_err(|_| BlockError::DeviceNotReady)?;
            }
            Ok(MsdcBlockDevice {
                controller: self.controller,
                sector_count: self.sector_count,
            })
        }
    }

    /// Block device backed by an [`MsdcOps`] controller.
    ///
    /// Wraps the controller to provide the [`BlockDevice`] trait. Each
    /// read/write call issues single-sector PIO transfers in a loop. `C`
    /// defaults to `BootMsdc` (#631): the real `crate::emmc::MsdcController`
    /// on hardware, `crate::emmc::FakeMsdc` under test/qemu, so this logic
    /// runs and is asserted against on every target.
    ///
    /// INVARIANT: the controller is initialized. The only constructor is
    /// [`MsdcBlockDeviceUninit::init`], which returns this type solely on the
    /// success path, so holding an `MsdcBlockDevice` is itself the proof that
    /// initialization ran and succeeded. The read/write paths therefore carry
    /// no `is_initialized()` guard: it could not fail, and a check that cannot
    /// fail reports the same green whether the property holds or not.
    pub(crate) struct MsdcBlockDevice<C: MsdcOps = BootMsdc> {
        /// The underlying MSDC controller, initialized per the type invariant.
        controller: C,
        /// Total sector count of the eMMC device.
        sector_count: u64,
    }

    impl<C: MsdcOps> BlockDevice for MsdcBlockDevice<C> {
        #[expect(
            unsafe_code,
            reason = "MMIO register access requires raw pointer dereference"
        )]
        fn read_sectors(&self, lba: u64, count: u32, buf: &mut [u8]) -> Result<(), BlockError> {
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

                // SAFETY: the controller is initialized per this type's
                // invariant — `MsdcBlockDeviceUninit::init` is its only
                // constructor and yields it only on success. The register
                // block is valid for the lifetime of the device (hardware is
                // memory-mapped and never unmapped on this SoC).
                unsafe {
                    self.controller
                        .read_sector(lba32, sector_buf)
                        .map_err(|_| BlockError::IoError)?;
                }
            }
            Ok(())
        }

        #[expect(
            unsafe_code,
            reason = "MMIO register access requires raw pointer dereference"
        )]
        fn write_sectors(&mut self, lba: u64, count: u32, buf: &[u8]) -> Result<(), BlockError> {
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

                // SAFETY: the controller is initialized per this type's
                // invariant — `MsdcBlockDeviceUninit::init` is its only
                // constructor and yields it only on success. The register
                // block is valid for the lifetime of the device.
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

#[cfg(not(feature = "qemu"))]
pub(crate) use msdc_wrapper::{MsdcBlockDevice, MsdcBlockDeviceUninit};

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
pub(crate) mod tests {
    use alloc::vec;

    use super::*;

    // -- PartitionBlockDevice (#603): partition addressing is real ---------

    /// A sector-sized pattern buffer for view tests.
    fn pattern(fill: u8) -> alloc::vec::Vec<u8> {
        vec![fill; SECTOR_SIZE]
    }

    #[test]
    fn partition_view_translates_view_lba_to_physical() {
        let mut phys = MemBlockDevice::new(32).expect("phys device");
        let mut view = PartitionBlockDevice::new(phys, 10, 5);

        // Write two sectors at view lba 1; they must land at physical 11.
        let mut two = pattern(0xA5);
        two.extend_from_within(..);
        view.write_sectors(1, 2, &two).expect("view write");

        // Read back through the view.
        let mut got = vec![0u8; 2 * SECTOR_SIZE];
        view.read_sectors(1, 2, &mut got).expect("view read");
        assert_eq!(got, two, "view read must return what the view wrote");
    }

    #[test]
    fn partition_view_never_touches_below_base() {
        let mut phys = MemBlockDevice::new(32).expect("phys device");
        // Pre-fill the whole physical device with a marker.
        let marker = pattern(0x11);
        for lba in 0..32 {
            phys.write_sectors(lba, 1, &marker).expect("pre-fill");
        }
        let mut view = PartitionBlockDevice::new(phys, 10, 5);
        view.write_sectors(0, 1, &pattern(0xFF))
            .expect("view write");

        // The inner device is moved into the view; verify via the view that
        // the write went to view lba 0 (physical 10) only — and that a view
        // of the region BELOW the partition is untouched (physical 0..10).
        let mut got = vec![0u8; SECTOR_SIZE];
        view.read_sectors(0, 1, &mut got).expect("read back");
        assert_eq!(got, pattern(0xFF));

        let below = PartitionBlockDevice::new(view.into_inner(), 0, 10);
        let mut below_buf = vec![0u8; SECTOR_SIZE];
        below
            .read_sectors(9, 1, &mut below_buf)
            .expect("read below base");
        assert_eq!(
            below_buf,
            pattern(0x11),
            "physical sectors below the partition base must be untouched"
        );
    }

    #[test]
    fn partition_view_bounds_check_uses_partition_length() {
        let phys = MemBlockDevice::new(32).expect("phys device");
        let mut view = PartitionBlockDevice::new(phys, 10, 5);

        // lba 4 is the last in-partition sector; lba 5 is out even though
        // the physical device has plenty of room past it.
        assert!(view.write_sectors(4, 1, &pattern(0x77)).is_ok());
        assert_eq!(
            view.write_sectors(5, 1, &pattern(0x77)).err(),
            Some(BlockError::OutOfBounds),
            "past-partition write must fail even with physical space left"
        );
        let mut buf = vec![0u8; 2 * SECTOR_SIZE];
        assert_eq!(
            view.read_sectors(4, 2, &mut buf).err(),
            Some(BlockError::OutOfBounds),
            "a range crossing the partition end must fail"
        );
    }

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
        dev.read_sectors(0, 0, &mut buf)
            .expect("zero-count read should succeed");
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
    pub(crate) struct FailingBlockDevice {
        /// Whether the device has been "initialized".
        pub(crate) ready: bool,
        /// Sector that triggers an `IoError` (all others succeed like `MemBlockDevice`).
        fail_sector: u64,
        /// Total sector count.
        sectors: u64,
        /// Backing storage.
        data: Vec<u8>,
    }

    impl FailingBlockDevice {
        pub(crate) fn new(sector_count: u64, fail_sector: u64) -> Self {
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
            let end = lba
                .checked_add(u64::from(count))
                .ok_or(BlockError::OutOfBounds)?;
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
            let end = lba
                .checked_add(u64::from(count))
                .ok_or(BlockError::OutOfBounds)?;
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

    // -- MsdcBlockDevice wrapper logic (#631) --
    //
    // The wrapper used to be gated to non-test, non-qemu builds on the real
    // MsdcController, so none of this logic -- the bounds check, the
    // checked_add overflow guard, the buffer-length validation, the u32 LBA
    // narrowing, or the #619 typestate transition -- had ever run under any
    // automated check. FakeMsdc (crate::emmc) stands in for the real
    // controller so it runs here.

    use crate::emmc::{FakeMsdc, MsdcError};

    /// Build an initialized `MsdcBlockDevice<FakeMsdc>` around `fake`.
    fn init_fake_device(fake: FakeMsdc, sector_count: u64) -> MsdcBlockDevice<FakeMsdc> {
        let uninit = MsdcBlockDeviceUninit::with_controller(fake, sector_count);
        // SAFETY: FakeMsdc touches no real MMIO; this is the host test seam
        // #631 exists to create.
        unsafe { uninit.init() }.expect("fake init succeeds unless force_init_failure is set")
    }

    #[test]
    fn msdc_read_past_sector_count_rejected() {
        let dev = init_fake_device(FakeMsdc::new(), 4);
        let mut buf = vec![0u8; SECTOR_SIZE];
        let result = dev.read_sectors(4, 1, &mut buf);
        assert_eq!(
            result,
            Err(BlockError::OutOfBounds),
            "lba == sector_count is one past the last valid sector"
        );
    }

    #[test]
    fn msdc_read_checked_add_overflow_rejected() {
        let dev = init_fake_device(FakeMsdc::new(), 4);
        let mut buf = vec![0u8; SECTOR_SIZE];
        // lba + count overflows u64: the bounds check must reject via
        // checked_add, not panic (debug builds) or silently wrap (release).
        let result = dev.read_sectors(u64::MAX, 1, &mut buf);
        assert_eq!(
            result,
            Err(BlockError::OutOfBounds),
            "lba + count overflow must be rejected, not panic or wrap"
        );
    }

    #[test]
    fn msdc_write_buf_len_mismatch_rejected() {
        let mut dev = init_fake_device(FakeMsdc::new(), 4);
        let buf = vec![0u8; SECTOR_SIZE - 1];
        let result = dev.write_sectors(0, 1, &buf);
        assert_eq!(result, Err(BlockError::InvalidArgument));
    }

    #[test]
    fn msdc_lba_u32_narrowing_boundary_rejected() {
        // sector_count is large enough that lba = u32::MAX + 1 passes the
        // sector_count bounds check, so only the per-sector u32::try_from
        // narrowing can reject it -- the arithmetic #619's typestate cannot
        // express, since it needs no runtime.
        let lba = u64::from(u32::MAX) + 1;
        let sector_count = lba + 1;
        let dev = init_fake_device(FakeMsdc::new(), sector_count);
        let mut buf = vec![0u8; SECTOR_SIZE];
        let result = dev.read_sectors(lba, 1, &mut buf);
        assert_eq!(
            result,
            Err(BlockError::OutOfBounds),
            "an lba past u32::MAX must be rejected by the narrowing, not silently truncated"
        );
    }

    #[test]
    fn msdc_read_sector_error_propagates_as_io_error() {
        let mut fake = FakeMsdc::new();
        fake.fail_at_sector = Some(2);
        let dev = init_fake_device(fake, 4);

        let mut buf = vec![0u8; SECTOR_SIZE];
        assert_eq!(
            dev.read_sectors(2, 1, &mut buf),
            Err(BlockError::IoError),
            "the fake's per-sector failure must surface as IoError"
        );

        // A non-failing sector on the same device still succeeds.
        assert_eq!(dev.read_sectors(0, 1, &mut buf), Ok(()));
    }

    #[test]
    fn msdc_init_failure_yields_no_device() {
        // #619 typestate transition: a controller that fails init must not
        // produce an MsdcBlockDevice at all -- MsdcBlockDeviceUninit::init
        // consumes self either way, so the failure path is the ONLY way to
        // observe "never initialized" and it must map to DeviceNotReady with
        // no device escaping.
        let mut fake = FakeMsdc::new();
        fake.force_init_failure = Some(MsdcError::CardNotPresent);
        let uninit = MsdcBlockDeviceUninit::with_controller(fake, 4);
        // SAFETY: FakeMsdc touches no real MMIO.
        let result = unsafe { uninit.init() };
        assert_eq!(
            result.err(),
            Some(BlockError::DeviceNotReady),
            "init failure must map to DeviceNotReady, not silently succeed"
        );
    }
}
