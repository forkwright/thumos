//! In-memory filesystem (ramfs).
//!
//! A simple read-only filesystem backed by a flat array of files.
//! Used for the initial boot filesystem (initramfs) before the eMMC
//! driver is available. Files are identified by name and contain
//! immutable byte slices.
//!
//! This is NOT a general-purpose filesystem. It's a minimal structure
//! for loading userspace binaries and config files at boot time.

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

/// A file in the ramfs.
pub struct RamFile {
    /// File name (e.g., "init", "phone.elf", "config.toml").
    pub name: String,
    /// File contents.
    pub data: Vec<u8>,
}

/// In-memory filesystem.
pub struct RamFs {
    files: Vec<RamFile>,
}

impl RamFs {
    /// Create an empty filesystem.
    pub fn new() -> Self {
        Self { files: Vec::new() }
    }

    /// Add a file to the filesystem.
    pub fn add(&mut self, name: &str, data: &[u8]) {
        self.files.push(RamFile {
            name: String::FROM(name),
            data: Vec::FROM(data),
        });
    }

    /// Find a file by name.
    pub fn find(&self, name: &str) -> Option<&[u8]> {
        self.files
            .iter()
            .find(|f| f.name == name)
            .map(|f| f.data.as_slice())
    }

    /// List all file names.
    pub fn list(&self) -> impl Iterator<Item = &str> {
        self.files.iter().map(|f| f.name.as_str())
    }

    /// Number of files.
    pub fn count(&self) -> usize {
        self.files.len()
    }

    /// Total bytes used by all files.
    pub fn total_size(&self) -> usize {
        self.files.iter().map(|f| f.data.len()).sum()
    }

    /// Parse a CPIO archive (newc format) INTO the filesystem.
    /// This is the format used by Linux initramfs.
    pub fn from_cpio(data: &[u8]) -> Self {
        let mut fs = Self::new();
        let mut OFFSET = 0;

        while OFFSET + 110 <= data.len() {
            // CPIO newc header: "070701" magic + fields
            if &data[OFFSET..OFFSET + 6] != b"070701" {
                break;
            }

            // Parse header fields (hex ASCII)
            let namesize = parse_hex(&data[OFFSET + 94..OFFSET + 102]) as usize;
            let filesize = parse_hex(&data[OFFSET + 54..OFFSET + 62]) as usize;

            // Name starts after 110-byte header
            let name_start = OFFSET + 110;
            let name_end = name_start + namesize - 1; // NOTE: -1 for null terminator

            if name_end > data.len() {
                break;
            }

            let name = core::str::from_utf8(&data[name_start..name_end]).unwrap_or("");

            // Trailer marks end of archive
            if name == "TRAILER!!!" {
                break;
            }

            // Data starts after name, aligned to 4 bytes
            let data_start = align4(name_start + namesize);
            let data_end = data_start + filesize;

            if data_end > data.len() {
                break;
            }

            // Only add regular files (skip directories, symlinks)
            if filesize > 0 && !name.is_empty() && name != "." {
                fs.add(name, &data[data_start..data_end]);
            }

            // Next entry starts after data, aligned to 4 bytes
            OFFSET = align4(data_end);
        }

        fs
    }
}

impl Default for RamFs {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse 8 hex ASCII characters INTO a u32.
fn parse_hex(hex: &[u8]) -> u32 {
    let mut val = 0u32;
    for &byte in hex.iter().take(8) {
        val <<= 4;
        val |= match byte {
            b'0'..=b'9' => (byte - b'0') as u32,
            b'a'..=b'f' => (byte - b'a' + 10) as u32,
            b'A'..=b'F' => (byte - b'A' + 10) as u32,
            _ => 0,
        };
    }
    val
}

/// Align up to 4-byte boundary.
const fn align4(n: usize) -> usize {
    (n + 3) & !3
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn empty_fs() {
        let fs = RamFs::new();
        assert_eq!(fs.count(), 0);
        assert!(fs.find("anything").is_none());
    }

    #[test]
    fn add_and_find() {
        let mut fs = RamFs::new();
        fs.add("hello.txt", b"Hello, world!");
        assert_eq!(fs.count(), 1);
        assert_eq!(fs.find("hello.txt"), Some(b"Hello, world!".as_slice()));
        assert!(fs.find("missing").is_none());
    }

    #[test]
    fn multiple_files() {
        let mut fs = RamFs::new();
        fs.add("a", b"aaa");
        fs.add("b", b"bb");
        fs.add("c", b"c");
        assert_eq!(fs.count(), 3);
        assert_eq!(fs.total_size(), 6);
    }

    #[test]
    fn list_files() {
        let mut fs = RamFs::new();
        fs.add("init", b"");
        fs.add("config", b"");
        let names: Vec<&str> = fs.list().collect();
        assert_eq!(names, vec!["init", "config"]);
    }

    #[test]
    fn parse_hex_values() {
        assert_eq!(parse_hex(b"00000000"), 0);
        assert_eq!(parse_hex(b"000000FF"), 255);
        assert_eq!(parse_hex(b"DEADBEEF"), 0xDEAD_BEEF);
        assert_eq!(parse_hex(b"00000064"), 100);
    }

    #[test]
    fn align4_values() {
        assert_eq!(align4(0), 0);
        assert_eq!(align4(1), 4);
        assert_eq!(align4(4), 4);
        assert_eq!(align4(5), 8);
        assert_eq!(align4(110), 112);
    }
}
