//! Device filesystem (devfs): provides `/dev` with static device nodes.
//!
//! Implements the `Filesystem` trait for a fixed set of device nodes:
//!
//! | Inode | Name      | Type        | Behavior                              |
//! |-------|-----------|-------------|---------------------------------------|
//! | 0     | (root)    | Directory   | Contains all device entries            |
//! | 1     | `null`    | `CharDevice`  | Write discards, read returns EOF      |
//! | 2     | `zero`    | `CharDevice`  | Write discards, read fills with 0x00  |
//! | 3     | `urandom` | `CharDevice`  | Write discards, read returns PRNG     |
//! | 4     | `ttyMT0`  | `CharDevice`  | Stub: read/write return Ok(0)         |
//! | 5     | `fb0`     | `CharDevice`  | Stub: read/write return Ok(0)         |
//! | 6     | `bt0`     | `CharDevice`  | BT control (ioctl for scan)           |
//! | 7     | `gps0`    | `CharDevice`  | GPS data (read returns position)      |
//!
//! No dynamic device registration. The devfs is read-only: `create`, `unlink`,
//! and `truncate` always return `PermissionDenied`.
//!
//! # PRNG for `/dev/urandom`
//!
//! Uses xorshift64 for simplicity. In a production kernel, this would be
//! backed by the CSPRNG in `csprng.rs`, but xorshift is sufficient for
//! the filesystem bring-up phase and avoids coupling to the CSPRNG init
//! sequence.

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

use crate::vfs::{DirEntry, Filesystem, InodeStat, InodeType, VfsError};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Root directory inode (always 0).
const ROOT_INODE: u32 = 0;
/// `/dev/null` inode.
const NULL_INODE: u32 = 1;
/// `/dev/zero` inode.
const ZERO_INODE: u32 = 2;
/// `/dev/urandom` inode.
const URANDOM_INODE: u32 = 3;
/// `/dev/ttyMT0` inode (UART stub).
const TTYMT0_INODE: u32 = 4;
/// `/dev/fb0` inode (framebuffer stub).
const FB0_INODE: u32 = 5;
/// `/dev/bt0` inode (Bluetooth control).
const BT0_INODE: u32 = 6;
/// `/dev/gps0` inode (GPS data).
const GPS0_INODE: u32 = 7;

/// Number of device inodes (root dir + 7 devices).
const NUM_INODES: u32 = 8;

/// Device name table, indexed by inode number (skipping inode 0 = root dir).
const DEVICE_NAMES: [&str; 7] = ["null", "zero", "urandom", "ttyMT0", "fb0", "bt0", "gps0"];

// ---------------------------------------------------------------------------
// xorshift64 PRNG
// ---------------------------------------------------------------------------

/// Minimal xorshift64 PRNG state.
///
/// Used to generate pseudo-random bytes for `/dev/urandom`. Not
/// cryptographically secure; adequate for filesystem testing and
/// early boot entropy.
struct Xorshift64 {
    /// Current PRNG state. Must never be zero.
    state: u64,
}

impl Xorshift64 {
    /// Create a new xorshift64 PRNG with the given seed.
    ///
    /// If `seed` is 0, it is replaced with a non-zero default to satisfy the
    /// xorshift64 invariant (state must never be zero).
    const fn new(seed: u64) -> Self {
        let state = if seed == 0 {
            0xDEAD_BEEF_CAFE_BABE
        } else {
            seed
        };
        Self { state }
    }

    /// Generate the next pseudo-random u64 value.
    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    /// Fill a byte buffer with pseudo-random data.
    fn fill_bytes(&mut self, buf: &mut [u8]) {
        let mut i = 0;
        while i < buf.len() {
            let val = self.next_u64();
            let bytes = val.to_le_bytes();
            let remaining = buf.len() - i;
            let chunk = remaining.min(8);
            buf[i..i + chunk].copy_from_slice(&bytes[..chunk]);
            i += chunk;
        }
    }
}

// ---------------------------------------------------------------------------
// DevFs
// ---------------------------------------------------------------------------

/// Device filesystem providing static device nodes at `/dev`.
///
/// Implements the `Filesystem` trait with a fixed set of character devices.
/// The filesystem is read-only: mutation operations return `PermissionDenied`.
pub(crate) struct DevFs {
    /// PRNG state for `/dev/urandom`.
    rng: Xorshift64,
}

impl DevFs {
    /// Create a new devfs instance.
    ///
    /// The `seed` parameter initializes the xorshift64 PRNG used by
    /// `/dev/urandom`. Pass a timer-derived value for real boots or a
    /// fixed value for deterministic testing.
    pub(crate) fn new(seed: u64) -> Self {
        Self {
            rng: Xorshift64::new(seed),
        }
    }

    /// Check if an inode ID is valid.
    fn valid_inode(inode_id: u32) -> bool {
        inode_id < NUM_INODES
    }
}

impl Filesystem for DevFs {
    /// Returns 0, the root directory inode.
    fn root_inode(&self) -> u32 {
        ROOT_INODE
    }

    /// Return metadata for a device inode.
    ///
    /// - Inode 0: directory (root `/dev`).
    /// - Inodes 1-5: character devices with size 0.
    ///
    /// # Errors
    ///
    /// Returns `VfsError::NotFound` if `inode_id` is out of range.
    fn stat(&self, inode_id: u32) -> Result<InodeStat, VfsError> {
        if !Self::valid_inode(inode_id) {
            return Err(VfsError::NotFound);
        }

        let inode_type = if inode_id == ROOT_INODE {
            InodeType::Directory
        } else {
            InodeType::CharDevice
        };

        let link_count = if inode_id == ROOT_INODE { 2 } else { 1 };

        Ok(InodeStat {
            inode_id,
            inode_type,
            size: 0,
            link_count,
            block_count: 0,
        })
    }

    /// Look up a device by name in the root directory.
    ///
    /// # Errors
    ///
    /// - `VfsError::NotADirectory` if `dir_inode` is not the root (0).
    /// - `VfsError::NotFound` if `name` does not match any device.
    fn lookup(&self, dir_inode: u32, name: &str) -> Result<u32, VfsError> {
        if dir_inode != ROOT_INODE {
            return Err(VfsError::NotADirectory);
        }

        for (i, dev_name) in DEVICE_NAMES.iter().enumerate() {
            if *dev_name == name {
                // Device inodes start at 1 (index 0 in DEVICE_NAMES = inode 1).
                return Ok(i as u32 + 1);
            }
        }

        Err(VfsError::NotFound)
    }

    /// Read from a device (immutable access).
    ///
    /// - `/dev/null` (1): always returns `Ok(0)` (EOF).
    /// - `/dev/zero` (2): fills buffer with `0x00`, returns `Ok(buf.len())`.
    /// - `/dev/urandom` (3): returns `Err(VfsError::RequiresMut)` — use
    ///   `read_mut` when mutable access is available.
    /// - `/dev/ttyMT0` (4): stub, returns `Ok(0)`.
    /// - `/dev/fb0` (5): stub, returns `Ok(0)`.
    /// - `/dev/bt0` (6): stub, returns `Ok(0)`.
    /// - `/dev/gps0` (7): stub, returns `Ok(0)`.
    ///
    /// # Errors
    ///
    /// - `VfsError::IsADirectory` if `inode_id` is the root directory (0).
    /// - `VfsError::NotFound` if `inode_id` is out of range.
    /// - `VfsError::RequiresMut` for urandom (PRNG needs `&mut self`; call
    ///   `read_mut` instead).
    fn read(&self, inode_id: u32, _offset: u64, buf: &mut [u8]) -> Result<usize, VfsError> {
        match inode_id {
            ROOT_INODE => Err(VfsError::IsADirectory),
            ZERO_INODE => {
                for b in buf.iter_mut() {
                    *b = 0;
                }
                Ok(buf.len())
            }
            // urandom needs &mut self for PRNG; callers must use read_mut().
            URANDOM_INODE => Err(VfsError::RequiresMut),
            NULL_INODE | TTYMT0_INODE | FB0_INODE | BT0_INODE | GPS0_INODE => Ok(0),
            _ => Err(VfsError::NotFound),
        }
    }

    /// Read from a device, with mutable access for PRNG state.
    ///
    /// The only path that can serve `/dev/urandom`: the trait's `read()`
    /// (which takes `&self`) cannot mutate the PRNG and returns
    /// `VfsError::RequiresMut` for that inode instead. Every other inode
    /// delegates to `read()`.
    ///
    /// # Errors
    ///
    /// Same as `read()`, minus `RequiresMut` (this method serves every inode
    /// `read()` can, plus urandom).
    fn read_mut(&mut self, inode_id: u32, offset: u64, buf: &mut [u8]) -> Result<usize, VfsError> {
        match inode_id {
            URANDOM_INODE => {
                self.rng.fill_bytes(buf);
                Ok(buf.len())
            }
            _ => self.read(inode_id, offset, buf),
        }
    }

    /// Write to a device.
    ///
    /// - `/dev/null` (1): discards data, returns `Ok(buf.len())`.
    /// - `/dev/zero` (2): discards data, returns `Ok(buf.len())`.
    /// - `/dev/urandom` (3): discards data, returns `Ok(buf.len())`.
    /// - `/dev/ttyMT0` (4): stub, returns `Ok(0)`.
    /// - `/dev/fb0` (5): stub, returns `Ok(0)`.
    /// - `/dev/bt0` (6): stub, returns `Ok(0)`.
    /// - `/dev/gps0` (7): stub, returns `Ok(0)`.
    ///
    /// # Errors
    ///
    /// - `VfsError::IsADirectory` if `inode_id` is the root directory (0).
    /// - `VfsError::NotFound` if `inode_id` is out of range.
    fn write(&mut self, inode_id: u32, _offset: u64, buf: &[u8]) -> Result<usize, VfsError> {
        match inode_id {
            ROOT_INODE => Err(VfsError::IsADirectory),
            NULL_INODE | ZERO_INODE | URANDOM_INODE => Ok(buf.len()),
            TTYMT0_INODE | FB0_INODE | BT0_INODE | GPS0_INODE => Ok(0),
            _ => Err(VfsError::NotFound),
        }
    }

    /// Creating device nodes is not supported.
    ///
    /// # Errors
    ///
    /// Always returns `VfsError::PermissionDenied`.
    fn create(
        &mut self,
        _dir_inode: u32,
        _name: &str,
        _inode_type: InodeType,
    ) -> Result<u32, VfsError> {
        Err(VfsError::PermissionDenied)
    }

    /// Removing device nodes is not supported.
    ///
    /// # Errors
    ///
    /// Always returns `VfsError::PermissionDenied`.
    fn unlink(&mut self, _dir_inode: u32, _name: &str) -> Result<(), VfsError> {
        Err(VfsError::PermissionDenied)
    }

    /// List all device entries in the root directory.
    ///
    /// # Errors
    ///
    /// - `VfsError::NotADirectory` if `dir_inode` is not the root (0).
    fn readdir(&self, dir_inode: u32) -> Result<Vec<DirEntry>, VfsError> {
        if dir_inode != ROOT_INODE {
            return Err(VfsError::NotADirectory);
        }

        let entries = DEVICE_NAMES
            .iter()
            .enumerate()
            .map(|(i, name)| DirEntry {
                name: String::from(*name),
                inode_id: i as u32 + 1,
                inode_type: InodeType::CharDevice,
            })
            .collect();

        Ok(entries)
    }

    /// Truncating device nodes is not supported.
    ///
    /// # Errors
    ///
    /// Always returns `VfsError::PermissionDenied`.
    fn truncate(&mut self, _inode_id: u32, _size: u64) -> Result<(), VfsError> {
        Err(VfsError::PermissionDenied)
    }

    /// No-op sync: devfs has no backing store.
    ///
    /// # Errors
    ///
    /// Always returns `Ok(())`.
    fn sync(&mut self) -> Result<(), VfsError> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_read_returns_eof() {
        let devfs = DevFs::new(42);
        let mut buf = [0u8; 16];
        let result = devfs.read(NULL_INODE, 0, &mut buf);
        assert_eq!(result, Ok(0), "/dev/null read must return 0 (EOF)");
    }

    #[test]
    fn null_write_discards() {
        let mut devfs = DevFs::new(42);
        let data = [1u8, 2, 3, 4];
        let result = devfs.write(NULL_INODE, 0, &data);
        assert_eq!(
            result,
            Ok(data.len()),
            "/dev/null write must accept all bytes"
        );
    }

    #[test]
    fn zero_read_fills_zeroes() {
        let devfs = DevFs::new(42);
        let mut buf = [0xFFu8; 32];
        let result = devfs.read(ZERO_INODE, 0, &mut buf);
        assert_eq!(result, Ok(32), "/dev/zero must fill the entire buffer");
        assert!(
            buf.iter().all(|&b| b == 0),
            "/dev/zero must fill buffer with 0x00"
        );
    }

    #[test]
    fn urandom_read_returns_bytes() {
        let mut devfs = DevFs::new(42);
        let mut buf = [0u8; 32];
        let result = devfs.read_mut(URANDOM_INODE, 0, &mut buf);
        assert_eq!(result, Ok(32), "/dev/urandom must fill the entire buffer");
        // With seed 42, the output should not be all zeros.
        assert!(
            !buf.iter().all(|&b| b == 0),
            "/dev/urandom output must not be all zeros"
        );
    }

    #[test]
    fn urandom_read_immutable_returns_requires_mut() {
        let devfs = DevFs::new(42);
        let mut buf = [0u8; 8];
        let result = devfs.read(URANDOM_INODE, 0, &mut buf);
        assert_eq!(
            result,
            Err(VfsError::RequiresMut),
            "/dev/urandom via the immutable read() must signal RequiresMut, not a generic IoError"
        );
    }

    #[test]
    fn read_mut_non_urandom_delegates_to_read() {
        let mut devfs = DevFs::new(42);
        let mut buf = [0xFFu8; 8];
        let result = devfs.read_mut(ZERO_INODE, 0, &mut buf);
        assert_eq!(result, Ok(8));
        assert!(
            buf.iter().all(|&b| b == 0),
            "read_mut must delegate ZERO_INODE to read()'s zero-fill behavior"
        );
    }

    #[test]
    fn lookup_finds_all_devices() {
        let devfs = DevFs::new(42);
        assert_eq!(devfs.lookup(0, "null"), Ok(NULL_INODE));
        assert_eq!(devfs.lookup(0, "zero"), Ok(ZERO_INODE));
        assert_eq!(devfs.lookup(0, "urandom"), Ok(URANDOM_INODE));
        assert_eq!(devfs.lookup(0, "ttyMT0"), Ok(TTYMT0_INODE));
        assert_eq!(devfs.lookup(0, "fb0"), Ok(FB0_INODE));
        assert_eq!(devfs.lookup(0, "bt0"), Ok(BT0_INODE));
        assert_eq!(devfs.lookup(0, "gps0"), Ok(GPS0_INODE));
    }

    #[test]
    fn lookup_returns_not_found_for_unknown() {
        let devfs = DevFs::new(42);
        assert_eq!(devfs.lookup(0, "unknown"), Err(VfsError::NotFound));
        assert_eq!(devfs.lookup(0, "stdin"), Err(VfsError::NotFound));
    }

    #[test]
    fn readdir_lists_all_devices() {
        let devfs = DevFs::new(42);
        let entries = devfs.readdir(ROOT_INODE).expect("readdir on root");
        assert_eq!(entries.len(), 7, "devfs root must have 7 device entries");

        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"null"), "must list null");
        assert!(names.contains(&"zero"), "must list zero");
        assert!(names.contains(&"urandom"), "must list urandom");
        assert!(names.contains(&"ttyMT0"), "must list ttyMT0");
        assert!(names.contains(&"fb0"), "must list fb0");
        assert!(names.contains(&"bt0"), "must list bt0");
        assert!(names.contains(&"gps0"), "must list gps0");

        // All entries must be CharDevice type.
        assert!(
            entries
                .iter()
                .all(|e| e.inode_type == InodeType::CharDevice),
            "all device entries must be CharDevice"
        );
    }

    #[test]
    fn create_returns_permission_denied() {
        let mut devfs = DevFs::new(42);
        let result = devfs.create(0, "new_device", InodeType::CharDevice);
        assert_eq!(result, Err(VfsError::PermissionDenied));
    }

    #[test]
    fn stat_returns_char_device_type() {
        let devfs = DevFs::new(42);

        // Root should be Directory.
        let root_stat = devfs.stat(ROOT_INODE).expect("stat root");
        assert_eq!(root_stat.inode_type, InodeType::Directory);

        // All devices should be CharDevice.
        for inode in 1..NUM_INODES {
            let st = devfs.stat(inode).expect("stat device");
            assert_eq!(
                st.inode_type,
                InodeType::CharDevice,
                "inode {inode} must be CharDevice"
            );
        }

        // Out-of-range inode.
        assert_eq!(devfs.stat(99), Err(VfsError::NotFound));
    }

    // -- Additional coverage --

    #[test]
    fn unlink_returns_permission_denied() {
        let mut devfs = DevFs::new(42);
        assert_eq!(devfs.unlink(0, "null"), Err(VfsError::PermissionDenied));
    }

    #[test]
    fn truncate_returns_permission_denied() {
        let mut devfs = DevFs::new(42);
        assert_eq!(
            devfs.truncate(NULL_INODE, 0),
            Err(VfsError::PermissionDenied)
        );
    }

    #[test]
    fn sync_succeeds() {
        let mut devfs = DevFs::new(42);
        assert_eq!(devfs.sync(), Ok(()));
    }

    #[test]
    fn readdir_non_root_returns_error() {
        let devfs = DevFs::new(42);
        assert_eq!(devfs.readdir(NULL_INODE), Err(VfsError::NotADirectory));
    }

    #[test]
    fn lookup_non_root_returns_not_a_directory() {
        let devfs = DevFs::new(42);
        assert_eq!(
            devfs.lookup(NULL_INODE, "foo"),
            Err(VfsError::NotADirectory)
        );
    }

    #[test]
    fn root_inode_is_zero() {
        let devfs = DevFs::new(42);
        assert_eq!(devfs.root_inode(), 0);
    }

    #[test]
    fn write_to_zero_discards() {
        let mut devfs = DevFs::new(42);
        let data = [1u8; 64];
        let result = devfs.write(ZERO_INODE, 0, &data);
        assert_eq!(result, Ok(64), "/dev/zero write must discard all bytes");
    }

    #[test]
    fn write_to_urandom_discards() {
        let mut devfs = DevFs::new(42);
        let data = [0xABu8; 16];
        let result = devfs.write(URANDOM_INODE, 0, &data);
        assert_eq!(result, Ok(16), "/dev/urandom write must discard all bytes");
    }

    #[test]
    fn stub_devices_read_return_zero() {
        let devfs = DevFs::new(42);
        let mut buf = [0xFFu8; 8];

        let tty_result = devfs.read(TTYMT0_INODE, 0, &mut buf);
        assert_eq!(tty_result, Ok(0), "ttyMT0 stub read returns 0");

        let fb_result = devfs.read(FB0_INODE, 0, &mut buf);
        assert_eq!(fb_result, Ok(0), "fb0 stub read returns 0");
    }

    #[test]
    fn stub_devices_write_return_zero() {
        let mut devfs = DevFs::new(42);
        let data = [1u8; 8];

        let tty_result = devfs.write(TTYMT0_INODE, 0, &data);
        assert_eq!(tty_result, Ok(0), "ttyMT0 stub write returns 0");

        let fb_result = devfs.write(FB0_INODE, 0, &data);
        assert_eq!(fb_result, Ok(0), "fb0 stub write returns 0");
    }

    #[test]
    fn xorshift_produces_different_values() {
        let mut rng = Xorshift64::new(12345);
        let a = rng.next_u64();
        let b = rng.next_u64();
        assert_ne!(a, b, "consecutive xorshift outputs must differ");
    }

    #[test]
    fn xorshift_zero_seed_uses_default() {
        let mut rng = Xorshift64::new(0);
        let val = rng.next_u64();
        assert_ne!(val, 0, "xorshift with zero seed must still produce output");
    }

    #[test]
    fn read_root_returns_is_a_directory() {
        let devfs = DevFs::new(42);
        let mut buf = [0u8; 8];
        assert_eq!(
            devfs.read(ROOT_INODE, 0, &mut buf),
            Err(VfsError::IsADirectory)
        );
    }

    #[test]
    fn write_root_returns_is_a_directory() {
        let mut devfs = DevFs::new(42);
        assert_eq!(
            devfs.write(ROOT_INODE, 0, &[1]),
            Err(VfsError::IsADirectory)
        );
    }

    #[test]
    fn read_invalid_inode_returns_not_found() {
        let devfs = DevFs::new(42);
        let mut buf = [0u8; 8];
        assert_eq!(devfs.read(99, 0, &mut buf), Err(VfsError::NotFound));
    }

    #[test]
    fn write_invalid_inode_returns_not_found() {
        let mut devfs = DevFs::new(42);
        assert_eq!(devfs.write(99, 0, &[1]), Err(VfsError::NotFound));
    }
}
