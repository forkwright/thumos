//! Minimal ELF loader for userspace binaries.
//!
//! Parses ELF32 headers and loads PT_LOAD segments INTO memory.
//! Only supports statically-linked ARM ELF binaries (what our userspace
//! crates compile to with `armv7-unknown-linux-musleabihf` target).
//!
//! The loader allocates pages for each segment, copies the data,
//! and returns the entry point address for process creation.

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
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Elf32Ehdr {
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
pub struct LoadedElf {
    /// Entry point address.
    pub entry: usize,
    /// Number of pages allocated.
    pub pages_used: usize,
}

/// Error FROM ELF loading.
#[derive(Debug)]
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

/// Load an ELF binary FROM a byte slice INTO memory.
///
/// Allocates pages for each PT_LOAD segment, copies data, zeros BSS.
/// Returns the entry point for process creation.
///
/// # Safety
///
/// The loaded code will execute with kernel privileges until we implement
/// user/kernel memory separation (Wave 4+).
pub fn load(data: &[u8]) -> Result<LoadedElf, ElfError> {
    if data.len() < core::mem::size_of::<Elf32Ehdr>() {
        return Err(ElfError::BadMagic);
    }

    // Parse ELF header
    // SAFETY: we checked the size above
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
    let mut pages_used = 0;

    // Process program headers
    for i in 0..phnum {
        let OFFSET = phoff + i * phentsize;
        if OFFSET + phentsize > data.len() {
            return Err(ElfError::InvalidSegment);
        }

        let phdr: Elf32Phdr =
            unsafe { core::ptr::read_unaligned(data.as_ptr().add(OFFSET).cast()) };

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
