//! Minimal ELF loader for userspace binaries.
//!
//! Parses ELF32 headers and loads PT_LOAD segments INTO memory.
//! Only supports statically-linked ARM ELF binaries (what our userspace
//! crates compile to with `armv7-unknown-linux-musleabihf` target).
//!
//! The loader allocates pages for each segment, copies the data,
//! and returns the entry point address for process creation.

#[cfg(not(test))]
use crate::page;

/// ELF magic: 0x7F 'E' 'L' 'F'
const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];

/// ELF class: 32-bit
const ELFCLASS32: u8 = 1;

/// ELF data: little-endian
const ELFDATA2LSB: u8 = 1;

/// ELF machine: ARM
const EM_ARM: u16 = 40;

/// Program header type: loadable segment
const PT_LOAD: u32 = 1;

/// ELF32 header.
///
/// Mirrors the ELF32 specification layout; splitting would break #[repr(C,
/// packed)] binary compatibility.
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Elf32Ehdr { // kanon:ignore RUST/struct-too-many-fields -- ELF32 spec layout; see doc comment
    e_ident: [u8; 16],
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u32,
    e_phoff: u32,
    e_shoff: u32,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
}

/// ELF32 program header.
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Elf32Phdr {
    p_type: u32,
    p_offset: u32,
    p_vaddr: u32,
    p_paddr: u32,
    p_filesz: u32,
    p_memsz: u32,
    p_flags: u32,
    p_align: u32,
}

/// Result of loading an ELF binary.
#[cfg(not(test))]
pub(crate) struct LoadedElf {
    /// Entry point address.
    pub entry: usize,
    /// Number of pages allocated.
    pub pages_used: usize,
}

/// Error FROM ELF loading.
#[derive(Debug, PartialEq, Eq)]
pub enum ElfError {
    /// Not a valid ELF file.
    BadMagic,
    /// Not a 32-bit ELF.
    Not32Bit,
    /// Not little-endian.
    NotLittleEndian,
    /// Not an ARM binary.
    NotArm,
    /// Out of memory during loading.
    OutOfMemory,
    /// Binary too large or has invalid segment.
    InvalidSegment,
}

/// Validate an ELF binary header and iterate its program headers.
///
/// Performs all header validation (magic, class, endianness, machine type)
/// and verifies that each program header is within `data` bounds.
/// Returns the entry point, program header metadata, and validated segment
/// descriptors for each PT_LOAD segment.
///
/// This function is pure (no page allocation or memory writes) and is
/// therefore safe to call in test builds.
fn validate(data: &[u8]) -> Result<(usize, ValidatedElf), ElfError> {
    if data.len() < core::mem::size_of::<Elf32Ehdr>() {
        return Err(ElfError::BadMagic);
    }

    // Parse ELF header
    // SAFETY: data.len() >= size_of::<Elf32Ehdr>() was verified above.
    // read_unaligned is used because the ELF header is packed and the byte
    // slice may not be aligned to Elf32Ehdr's natural alignment.
    let ehdr: Elf32Ehdr = unsafe { core::ptr::read_unaligned(data.as_ptr().cast()) };

    // Validate
    if ehdr.e_ident[0..4] != ELF_MAGIC {
        return Err(ElfError::BadMagic);
    }
    if ehdr.e_ident.get(4).copied().unwrap_or_default() != ELFCLASS32 {
        return Err(ElfError::Not32Bit);
    }
    if ehdr.e_ident.get(5).copied().unwrap_or_default() != ELFDATA2LSB {
        return Err(ElfError::NotLittleEndian);
    }
    if ehdr.e_machine != EM_ARM {
        return Err(ElfError::NotArm);
    }

    let entry = ehdr.e_entry as usize;
    let phoff = ehdr.e_phoff as usize;
    let phnum = ehdr.e_phnum as usize;
    let phentsize = ehdr.e_phentsize as usize;

    let mut segments = ValidatedElf {
        segments: [(0, 0, 0, 0); 16],
        count: 0,
    };

    // Process program headers
    for i in 0..phnum {
        let offset = phoff + i * phentsize;
        if offset + phentsize > data.len() {
            return Err(ElfError::InvalidSegment);
        }

        // SAFETY: offset + phentsize <= data.len() was verified above.
        // read_unaligned is used because the program header is packed and
        // the byte slice offset may not satisfy Elf32Phdr's alignment.
        let phdr: Elf32Phdr =
            unsafe { core::ptr::read_unaligned(data.as_ptr().add(offset).cast()) };

        if phdr.p_type != PT_LOAD {
            continue;
        }

        let vaddr = phdr.p_vaddr as usize;
        let memsz = phdr.p_memsz as usize;
        let filesz = phdr.p_filesz as usize;
        let file_offset = phdr.p_offset as usize;

        if file_offset + filesz > data.len() {
            return Err(ElfError::InvalidSegment);
        }

        if segments.count < 16 {
            segments.segments[segments.count] = (vaddr, memsz, filesz, file_offset);
            segments.count += 1;
        }
    }

    Ok((entry, segments))
}

/// Validated ELF segment descriptors (output of header validation).
#[derive(Debug)]
struct ValidatedElf {
    /// `(vaddr, memsz, filesz, file_offset)` for each PT_LOAD segment.
    segments: [(usize, usize, usize, usize); 16],
    /// Number of valid entries in `segments`.
    count: usize,
}

/// Load an ELF binary FROM a byte slice INTO memory.
///
/// Allocates pages for each PT_LOAD segment, copies data, zeros BSS.
/// Returns the entry point for process creation.
///
/// # Safety
///
/// The loaded code will execute with kernel privileges until we implement
/// user/kernel memory separation (Wave 4+).
#[cfg(not(test))]
pub(crate) fn load(data: &[u8]) -> Result<LoadedElf, ElfError> {
    let (entry, validated) = validate(data)?;
    let mut pages_used = 0;

    for idx in 0..validated.count {
        let (vaddr, memsz, filesz, file_offset) = validated.segments[idx];

        // Allocate pages for this segment
        let num_pages = (memsz + page::PAGE_SIZE - 1) / page::PAGE_SIZE;
        for p in 0..num_pages {
            let page_addr = page::alloc_page().ok_or(ElfError::OutOfMemory)?;
            pages_used += 1;

            // NOTE: identity-mapped, so we can write directly to physical addresses
            // The segment's virtual address must match our identity mapping range
            let dest = vaddr + p * page::PAGE_SIZE;
            let dest_ptr = dest as *mut u8;

            // Copy file data INTO this page
            let page_start = p * page::PAGE_SIZE;
            let page_end = (page_start + page::PAGE_SIZE).min(memsz);

            for byte_offset in page_start..page_end {
                let val = if byte_offset < filesz {
                    data[file_offset + byte_offset]
                } else {
                    0 // BSS: zero-filled
                };
                // SAFETY: dest (vaddr) is identity-mapped DRAM within the MMU's
                // normal RAM region. byte_offset - page_start < PAGE_SIZE, so
                // the write stays within the allocated page.
                unsafe {
                    dest_ptr.add(byte_offset - page_start).write(val);
                }
            }

            // NOTE: page_addr is unused because we write to vaddr directly
            // In a real implementation with separate page tables per process,
            // we'd map page_addr to vaddr in the process's page table
            let _ = page_addr;
        }
    }

    Ok(LoadedElf { entry, pages_used })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Size of an ELF32 header in bytes.
    const ELF32_EHDR_SIZE: usize = 52;
    /// Size of an ELF32 program header in bytes.
    const ELF32_PHDR_SIZE: usize = 32;

    /// Build a minimal valid ELF32 LE ARM header (52 bytes).
    ///
    /// Returns a byte array with all validation-critical fields set correctly:
    /// magic, class=32, data=LE, machine=ARM. `e_phnum` is set to 0 so
    /// no segments are loaded (avoids page allocation in tests).
    fn make_valid_ehdr() -> [u8; ELF32_EHDR_SIZE] {
        let mut h = [0u8; ELF32_EHDR_SIZE];
        // e_ident[0..4]: magic
        h[0] = 0x7F;
        h[1] = b'E';
        h[2] = b'L';
        h[3] = b'F';
        // e_ident[4]: class = ELFCLASS32
        h[4] = 1;
        // e_ident[5]: data = ELFDATA2LSB
        h[5] = 1;
        // e_ident[6]: version = EV_CURRENT
        h[6] = 1;
        // e_type (offset 16): ET_EXEC = 2 (LE)
        h[16] = 2;
        h[17] = 0;
        // e_machine (offset 18): EM_ARM = 40 (LE)
        h[18] = 40;
        h[19] = 0;
        // e_version (offset 20): EV_CURRENT = 1
        h[20] = 1;
        // e_entry (offset 24): 0x8000 (typical ARM entry)
        h[24] = 0x00;
        h[25] = 0x80;
        h[26] = 0x00;
        h[27] = 0x00;
        // e_phoff (offset 28): 52 (right after ehdr)
        h[28] = ELF32_EHDR_SIZE as u8;
        // e_ehsize (offset 40): 52
        h[40] = ELF32_EHDR_SIZE as u8;
        // e_phentsize (offset 42): 32
        h[42] = ELF32_PHDR_SIZE as u8;
        // e_phnum (offset 44): 0 (no segments to load)
        h[44] = 0;
        h
    }

    #[test]
    fn parse_rejects_bad_magic() {
        let data = [0x00; ELF32_EHDR_SIZE];
        assert_eq!(validate(&data).unwrap_err(), ElfError::BadMagic);
    }

    #[test]
    fn parse_rejects_too_short_data() {
        // Data shorter than the ELF header must return BadMagic.
        let data = [0x7F, b'E', b'L', b'F'];
        assert_eq!(validate(&data).unwrap_err(), ElfError::BadMagic);
    }

    #[test]
    fn parse_rejects_non_32bit() {
        let mut h = make_valid_ehdr();
        // Set class to ELFCLASS64 (2) instead of ELFCLASS32 (1).
        h[4] = 2;
        assert_eq!(validate(&h).unwrap_err(), ElfError::Not32Bit);
    }

    #[test]
    fn parse_rejects_non_little_endian() {
        let mut h = make_valid_ehdr();
        // Set data to ELFDATA2MSB (2) instead of ELFDATA2LSB (1).
        h[5] = 2;
        assert_eq!(validate(&h).unwrap_err(), ElfError::NotLittleEndian);
    }

    #[test]
    fn parse_rejects_non_arm() {
        let mut h = make_valid_ehdr();
        // Set machine to EM_386 (3) instead of EM_ARM (40).
        h[18] = 3;
        h[19] = 0;
        assert_eq!(validate(&h).unwrap_err(), ElfError::NotArm);
    }

    #[test]
    fn parse_rejects_invalid_segment() {
        let mut h = make_valid_ehdr();
        // Set phnum=1 so the loader tries to read a program header,
        // but the data is only ehdr-sized — the phdr offset is out of bounds.
        h[44] = 1;
        assert_eq!(validate(&h).unwrap_err(), ElfError::InvalidSegment);
    }

    #[test]
    fn parse_accepts_valid_elf() {
        // A valid ELF header with phnum=0 should parse successfully
        // without triggering any page allocation (no PT_LOAD segments).
        let h = make_valid_ehdr();
        let (entry, validated) = validate(&h)
            .expect("valid ELF header with no segments must parse");
        assert_eq!(entry, 0x8000, "entry point must match e_entry");
        assert_eq!(validated.count, 0, "no PT_LOAD segments expected");
    }
}
