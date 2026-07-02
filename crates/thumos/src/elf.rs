//! Minimal ELF loader for userspace binaries.
//!
//! Parses ELF32 headers and loads PT_LOAD segments INTO memory.
//! Only supports statically-linked ARM ELF binaries (what our userspace
//! crates compile to with `armv7-unknown-linux-musleabihf` target).
//!
//! The loader validates a per-image page budget (#327) and writes each
//! segment's data directly to its identity-mapped virtual address (#318),
//! then returns the entry point address for process creation.

use crate::memguard::validate_user_buffer;
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

/// Size of an on-disk `Elf32Phdr`: eight `u32` fields = 32 bytes.
///
/// WHY size_of, not the header-declared `e_phentsize` (#317): the phdr read
/// in `validate()` always consumes exactly this many bytes regardless of
/// what the attacker-controlled `e_phentsize` claims, so both the entsize
/// floor and the per-header bounds check must be pinned to the type's
/// actual size.
const PHDR_SIZE: usize = core::mem::size_of::<Elf32Phdr>();

/// Maximum total PT_LOAD segment memory, in pages, a single ELF image may
/// declare (#327).
///
/// WHY 2048 (8 MB): generous headroom for a statically-linked ARM musl
/// binary's .text+.data+.bss on this device, while bounding a crafted
/// `p_memsz` from driving an unbounded page-count computation or physical
/// page exhaustion on this 1 GB device.
const MAX_ELF_PAGES: usize = 2048;

/// Result of loading an ELF binary.
#[derive(Debug)]
pub(crate) struct LoadedElf {
    /// Entry point address.
    pub entry: usize,
    /// Number of pages written (#328: no longer a count of
    /// `page::alloc_page()` reservations — see `load()`'s doc comment).
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
        total_pages: 0,
    };

    // WHY (#317): e_phentsize is attacker-controlled but the read below
    // always consumes exactly PHDR_SIZE bytes. Reject up front if the
    // header declares a stride narrower than what will actually be read,
    // rather than trusting phentsize as the read width.
    if phnum > 0 && phentsize < PHDR_SIZE {
        return Err(ElfError::InvalidSegment);
    }

    // Process program headers
    for i in 0..phnum {
        // WHY (#316): phoff/phentsize are attacker-controlled u32 header
        // fields; plain addition/multiplication can wrap a 32-bit usize
        // target and bypass the bounds check below. checked_mul/checked_add
        // reject a header that would wrap instead of silently admitting it.
        let offset = match i
            .checked_mul(phentsize)
            .and_then(|stride| stride.checked_add(phoff))
        {
            Some(o) => o,
            None => return Err(ElfError::InvalidSegment),
        };
        // WHY (#317): bounds-check against PHDR_SIZE (the bytes actually
        // read below), not phentsize (the attacker-controlled stride) — a
        // phentsize >= PHDR_SIZE is enforced above, but the read width
        // itself must never depend on the untrusted field.
        let offset_end = match offset.checked_add(PHDR_SIZE) {
            Some(e) => e,
            None => return Err(ElfError::InvalidSegment),
        };
        if offset_end > data.len() {
            return Err(ElfError::InvalidSegment);
        }

        // SAFETY: offset + PHDR_SIZE <= data.len() was verified above.
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

        // WHY (#316): file_offset/filesz are attacker-controlled; checked_add
        // rejects a wrap instead of letting it bypass this guard.
        let file_end = match file_offset.checked_add(filesz) {
            Some(e) => e,
            None => return Err(ElfError::InvalidSegment),
        };
        if file_end > data.len() {
            return Err(ElfError::InvalidSegment);
        }

        // WHY (#318): p_vaddr is a fully attacker-controlled physical write
        // target — load() below writes segment bytes directly to vaddr
        // (identity-mapped, no per-process page table yet). Reject any
        // segment whose [vaddr, vaddr+memsz) falls outside sanctioned
        // user-accessible DRAM before a single byte is written, closing the
        // arbitrary-write primitive.
        if !validate_user_buffer(vaddr, memsz) {
            return Err(ElfError::InvalidSegment);
        }

        // WHY (#327): bound this segment's page count, and the running
        // total across all segments, via checked arithmetic (memsz +
        // PAGE_SIZE - 1 can itself overflow a 32-bit usize) before any page
        // is allocated.
        let seg_pages = match memsz
            .checked_add(page::PAGE_SIZE - 1)
            .map(|rounded| rounded / page::PAGE_SIZE)
        {
            Some(n) => n,
            None => return Err(ElfError::InvalidSegment),
        };
        segments.total_pages = match segments.total_pages.checked_add(seg_pages) {
            Some(t) if t <= MAX_ELF_PAGES => t,
            _ => return Err(ElfError::InvalidSegment),
        };

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
    /// Sum of each segment's page count (`ceil(memsz / PAGE_SIZE)`),
    /// already bounded by `MAX_ELF_PAGES` (#327). `load()`'s single
    /// up-front OOM precheck (#328) uses this instead of allocating a page
    /// per iteration.
    total_pages: usize,
}

/// Load an ELF binary FROM a byte slice INTO memory.
///
/// Writes each PT_LOAD segment directly to its identity-mapped `vaddr`
/// (validated by `validate()`'s load-region check, #318), zeroing BSS.
/// Returns the entry point for process creation. #328: does not call
/// `page::alloc_page()` per segment page — nothing would ever free such a
/// reservation, since the write target is `vaddr`, not the allocated
/// frame — so the only physical-memory gate is the up-front `free_count()`
/// budget check below.
///
/// # Safety
///
/// The loaded code will execute with kernel privileges until we implement
/// user/kernel memory separation (Wave 4+).
pub(crate) fn load(data: &[u8]) -> Result<LoadedElf, ElfError> {
    let (entry, validated) = validate(data)?;

    // WHY (#328): a single up-front budget check replaces the old per-page
    // page::alloc_page() reservation. That reservation's returned address
    // was immediately discarded — segment data is written straight to the
    // identity-mapped vaddr, validated above by #318 — and never freed,
    // leaking pages_used physical frames on every load. validated.total_pages
    // is already bounded by MAX_ELF_PAGES (#327), so this is a bounded,
    // one-shot check rather than an unbounded leak.
    if page::free_count() < validated.total_pages {
        return Err(ElfError::OutOfMemory);
    }

    let mut pages_used = 0;

    for idx in 0..validated.count {
        let (vaddr, memsz, filesz, file_offset) = validated.segments[idx];

        // WHY: identical to the checked computation validate() already
        // performed for this same memsz while building validated.total_pages
        // (#327) — if it did not overflow there, it cannot overflow here —
        // so plain arithmetic is safe without re-deriving the check.
        let num_pages = (memsz + page::PAGE_SIZE - 1) / page::PAGE_SIZE;
        for p in 0..num_pages {
            pages_used += 1;

            // NOTE: identity-mapped, so we write directly to the
            // page::PAGE_SIZE-aligned physical address vaddr + p*PAGE_SIZE.
            // #318 validated [vaddr, vaddr+memsz) above, so this offset
            // cannot leave that range or overflow.
            let dest = vaddr + p * page::PAGE_SIZE;
            let dest_ptr = dest as *mut u8;

            // Copy file data INTO this page
            let page_start = p * page::PAGE_SIZE;
            let page_end = (page_start + page::PAGE_SIZE).min(memsz);

            for byte_offset in page_start..page_end {
                // WHY (#316): file_offset + byte_offset cannot overflow —
                // validate() proved file_offset + filesz <= data.len() via
                // checked_add, and byte_offset < filesz here — but
                // checked_add plus a safe fallback keeps this line's
                // arithmetic self-evidently guarded rather than leaning on
                // a fact proven elsewhere.
                let val = if byte_offset < filesz {
                    match file_offset.checked_add(byte_offset).and_then(|i| data.get(i)) {
                        Some(&b) => b,
                        None => 0, // INVARIANT: unreachable per validate()'s file_end check
                    }
                } else {
                    0 // BSS: zero-filled
                };
                // SAFETY: dest (vaddr) is identity-mapped DRAM within
                // user-accessible RAM (validated by #318's
                // validate_user_buffer check above). byte_offset -
                // page_start < PAGE_SIZE, so the write stays within the
                // segment's declared page range.
                unsafe {
                    dest_ptr.add(byte_offset - page_start).write(val);
                }
            }
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

    /// #316: e_phoff chosen so `phoff + i*phentsize` would wrap a 32-bit
    /// usize (this crate's host tests run on i686, so the wrap reproduces
    /// without a target-width mock) and bypass the bounds guard.
    #[test]
    fn parse_rejects_phoff_overflow_near_u32_max() {
        let mut h = make_valid_ehdr();
        h[44] = 1; // e_phnum = 1
        // e_phoff (offset 28): chosen so phoff + i*phentsize wraps a 32-bit usize.
        h[28..32].copy_from_slice(&0xFFFF_FFF0u32.to_le_bytes());
        assert_eq!(validate(&h).unwrap_err(), ElfError::InvalidSegment);
    }

    /// #316: p_offset/p_filesz chosen so `file_offset + filesz` would wrap
    /// a 32-bit usize, attempting to smuggle a bogus segment past the
    /// file-extent bounds guard.
    #[test]
    fn parse_rejects_file_extent_overflow() {
        let mut buf = [0u8; ELF32_EHDR_SIZE + ELF32_PHDR_SIZE];
        let h = make_valid_ehdr();
        buf[..ELF32_EHDR_SIZE].copy_from_slice(&h);
        buf[44] = 1; // e_phnum = 1

        // Elf32Phdr at offset 52: p_type = PT_LOAD (1).
        buf[52..56].copy_from_slice(&1u32.to_le_bytes());
        // p_offset (offset 56): chosen so file_offset + filesz wraps a 32-bit usize.
        buf[56..60].copy_from_slice(&0xFFFF_FFF0u32.to_le_bytes());
        // p_filesz (offset 68) and p_memsz (offset 72): 0x100.
        buf[68..72].copy_from_slice(&0x100u32.to_le_bytes());
        buf[72..76].copy_from_slice(&0x100u32.to_le_bytes());

        assert_eq!(validate(&buf).unwrap_err(), ElfError::InvalidSegment);
    }

    /// #317: e_phentsize smaller than size_of::<Elf32Phdr>() must be
    /// rejected before any phdr is read, not admitted by a bounds check
    /// that trusts the attacker-controlled stride.
    #[test]
    fn parse_rejects_phentsize_smaller_than_phdr() {
        let mut h = make_valid_ehdr();
        h[44] = 1; // e_phnum = 1
        // e_phentsize (offset 42): 16, well under the real 32-byte Elf32Phdr.
        h[42] = 16;
        assert_eq!(validate(&h).unwrap_err(), ElfError::InvalidSegment);
    }

    /// #318: a PT_LOAD segment whose p_vaddr lies outside the sanctioned
    /// user-accessible DRAM load region must be rejected before any byte
    /// is written.
    #[test]
    fn parse_rejects_vaddr_outside_load_region() {
        let mut buf = [0u8; ELF32_EHDR_SIZE + ELF32_PHDR_SIZE];
        let h = make_valid_ehdr();
        buf[..ELF32_EHDR_SIZE].copy_from_slice(&h);
        buf[44] = 1; // e_phnum = 1

        // Elf32Phdr at offset 52: p_type = PT_LOAD (1).
        buf[52..56].copy_from_slice(&1u32.to_le_bytes());
        // p_vaddr (offset 60): well below user-accessible DRAM.
        buf[60..64].copy_from_slice(&0x1000u32.to_le_bytes());
        // p_memsz (offset 72): 0x1000.
        buf[72..76].copy_from_slice(&0x1000u32.to_le_bytes());

        assert_eq!(validate(&buf).unwrap_err(), ElfError::InvalidSegment);
    }

    /// #327: a PT_LOAD segment declaring memory far beyond the configured
    /// per-image budget must be rejected before any page is allocated.
    #[test]
    fn parse_rejects_segment_memory_over_budget() {
        let mut buf = [0u8; ELF32_EHDR_SIZE + ELF32_PHDR_SIZE];
        let h = make_valid_ehdr();
        buf[..ELF32_EHDR_SIZE].copy_from_slice(&h);
        buf[44] = 1; // e_phnum = 1

        // Elf32Phdr at offset 52: p_type = PT_LOAD (1).
        buf[52..56].copy_from_slice(&1u32.to_le_bytes());
        // p_vaddr (offset 60): kconfig::KERNEL_END, inside the allowed load
        // region so #318's check does not fire first.
        buf[60..64].copy_from_slice(&0x4010_0000u32.to_le_bytes());
        // p_memsz (offset 72): 32 MB, comfortably inside RAM but four times
        // over MAX_ELF_PAGES (2048 pages = 8 MB).
        buf[72..76].copy_from_slice(&0x0200_0000u32.to_le_bytes());

        assert_eq!(validate(&buf).unwrap_err(), ElfError::InvalidSegment);
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

    // ---- #328: load() must not leak physical pages ----

    /// #328: a successful load must not permanently consume physical pages
    /// from the allocator — the old per-page `page::alloc_page()` call
    /// reserved a frame whose address was immediately discarded (data is
    /// written to `vaddr`, not the reserved frame) and never freed it,
    /// leaking one page per loaded page on every exec.
    #[cfg(target_pointer_width = "32")]
    #[test]
    fn load_does_not_leak_pages_on_success() {
        // WHY function-local `static mut`: load() writes segment bytes
        // directly to the ELF's p_vaddr. This binary's PIE image (hence any
        // `static`) loads inside [kconfig::KERNEL_END, kconfig::RAM_END) on
        // this host toolchain, so its address passes validate_user_buffer
        // and is safe to dereference — unlike a fabricated physical address
        // or a stack array (glibc places thread stacks above RAM_END).
        static mut BUF: [u8; 16] = [0u8; 16];
        // WHY no unsafe: addr_of_mut! only forms the static's address; it
        // does not dereference it, so this line needs no unsafe block —
        // only reading/writing through the resulting pointer would.
        let vaddr = core::ptr::addr_of_mut!(BUF) as *mut u8 as usize;

        let mut data = [0u8; ELF32_EHDR_SIZE + ELF32_PHDR_SIZE + 4];
        let h = make_valid_ehdr();
        data[..ELF32_EHDR_SIZE].copy_from_slice(&h);
        data[44] = 1; // e_phnum = 1

        // Elf32Phdr at offset 52: p_type = PT_LOAD (1).
        data[52..56].copy_from_slice(&1u32.to_le_bytes());
        // p_offset (offset 56): file data starts right after the phdr.
        let file_offset = (ELF32_EHDR_SIZE + ELF32_PHDR_SIZE) as u32;
        data[56..60].copy_from_slice(&file_offset.to_le_bytes());
        // p_vaddr (offset 60): the scratch buffer's real address.
        data[60..64].copy_from_slice(&(vaddr as u32).to_le_bytes());
        // p_filesz (offset 68): 4 bytes of real content.
        data[68..72].copy_from_slice(&4u32.to_le_bytes());
        // p_memsz (offset 72): 16 bytes total (12 bytes BSS beyond filesz).
        data[72..76].copy_from_slice(&16u32.to_le_bytes());
        data[84..88].copy_from_slice(b"TEST");

        // Free pool large enough for the 1 page this segment rounds up to.
        // SAFETY: test-only page-allocator state; single-threaded per test
        // (matches the established page::init() test precedent).
        unsafe {
            page::init(0x4000_0000, 0x4000_0000 + 8 * page::PAGE_SIZE, 0x4000_0000 + 4 * page::PAGE_SIZE);
        }
        let free_before = page::free_count();
        assert_eq!(free_before, 4, "test setup must yield exactly 4 free pages");

        let loaded = load(&data).expect("well-formed single-page segment must load");
        assert_eq!(loaded.pages_used, 1, "a 16-byte segment must round up to exactly 1 page");

        // SAFETY: BUF is a private test-only static, read after load() wrote
        // to its address.
        unsafe {
            assert_eq!(&BUF[..4], b"TEST", "file bytes must be copied to vaddr");
            assert_eq!(&BUF[4..16], &[0u8; 12], "bytes beyond filesz must be BSS-zeroed");
        }

        assert_eq!(
            page::free_count(), free_before,
            "a successful load must not permanently consume any page from the allocator (#328)"
        );
    }

    /// #328: when the free pool is smaller than the segment budget, load()
    /// must reject up front (before writing anything) rather than fail
    /// partway through — there is no partial state to roll back because no
    /// allocation happens until after this check passes.
    #[cfg(target_pointer_width = "32")]
    #[test]
    fn load_oom_precheck_rejects_before_any_write() {
        static mut BUF: [u8; 16] = [0u8; 16];
        // WHY no unsafe: addr_of_mut! only forms the static's address; it
        // does not dereference it, so this line needs no unsafe block —
        // only reading/writing through the resulting pointer would.
        let vaddr = core::ptr::addr_of_mut!(BUF) as *mut u8 as usize;

        let mut data = [0u8; ELF32_EHDR_SIZE + ELF32_PHDR_SIZE];
        let h = make_valid_ehdr();
        data[..ELF32_EHDR_SIZE].copy_from_slice(&h);
        data[44] = 1; // e_phnum = 1
        data[52..56].copy_from_slice(&1u32.to_le_bytes()); // p_type = PT_LOAD
        data[60..64].copy_from_slice(&(vaddr as u32).to_le_bytes());
        data[72..76].copy_from_slice(&16u32.to_le_bytes()); // p_memsz = 16

        // Empty free pool: usable range collapses to zero pages.
        // SAFETY: test-only page-allocator state; single-threaded per test.
        unsafe {
            page::init(0x4000_0000, 0x4000_0000, 0x4000_0000);
        }
        assert_eq!(page::free_count(), 0, "test setup must yield zero free pages");

        let result = load(&data);
        assert_eq!(result.unwrap_err(), ElfError::OutOfMemory,
            "a segment budget exceeding the free pool must be rejected up front");

        assert_eq!(unsafe { BUF }, [0u8; 16], "no byte may be written before the OOM precheck passes");
    }
}
