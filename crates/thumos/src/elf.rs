//! Minimal ELF loader for userspace binaries.
//!
//! Parses ELF32 headers and loads `PT_LOAD` segments INTO memory.
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

/// `PT_LOAD` segment permission flags (ELF32 program header `p_flags`).
const PF_X: u32 = 0x1;
const PF_W: u32 = 0x2;
const PF_R: u32 = 0x4;

/// Translate ELF `p_flags` to POSIX prot bits for `mmu::prot_to_l2_flags`
/// (#482), so a spawned process's segments get W^X user page permissions
/// (text RX, rodata RO, data/bss RW+XN; a W|X segment degrades to RW+XN
/// because `prot_to_l2_flags` forces XN whenever `PROT_WRITE` is set).
pub(crate) fn flags_to_prot(p_flags: u32) -> u32 {
    let mut prot = 0;
    if p_flags & PF_R != 0 {
        prot |= crate::mmu::prot::PROT_READ;
    }
    if p_flags & PF_W != 0 {
        prot |= crate::mmu::prot::PROT_WRITE;
    }
    if p_flags & PF_X != 0 {
        prot |= crate::mmu::prot::PROT_EXEC;
    }
    prot
}

/// ELF32 header.
///
/// Mirrors the ELF32 specification layout; splitting would break #[repr(C,
/// packed)] binary compatibility.
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Elf32Ehdr {
    // kanon:ignore RUST/struct-too-many-fields -- ELF32 spec layout; see doc comment
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
/// WHY `size_of`, not the header-declared `e_phentsize` (#317): the phdr read
/// in `validate()` always consumes exactly this many bytes regardless of
/// what the attacker-controlled `e_phentsize` claims, so both the entsize
/// floor and the per-header bounds check must be pinned to the type's
/// actual size.
const PHDR_SIZE: usize = core::mem::size_of::<Elf32Phdr>();

/// Maximum total `PT_LOAD` segment memory, in pages, a single ELF image may
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
    /// `(vaddr, memsz, p_flags)` per `PT_LOAD` segment (#482), so `spawn_user`
    /// can map each segment PL0-accessible with W^X permissions derived from
    /// `p_flags`. The link address is `vaddr`; the LOAD address is
    /// `image_phys + (vaddr - image_lo)` (#502, no longer identity).
    segments: [(usize, usize, u32); 16],
    /// Number of valid entries in `segments`.
    seg_count: usize,
    /// Physical base of the per-process image frame the segments were loaded
    /// into (#502). `USER_TEXT_BASE` maps here (non-identity), so each process
    /// gets its own image. On the host and for the unconfined `load()` this is
    /// `image_lo` (identity), preserving host-test behaviour.
    pub image_phys: usize,
    /// Lowest segment `vaddr` -- the link-address base the image frame anchors
    /// at. `image_phys` corresponds to `image_lo`.
    pub image_lo: usize,
    /// Contiguous page count of the image frame (`validated.total_pages`), for
    /// freeing it on a map failure / exec teardown.
    pub image_pages: usize,
}

impl LoadedElf {
    /// The loaded `PT_LOAD` segments as `(vaddr, memsz, p_flags)` (#482).
    pub(crate) fn segments(&self) -> &[(usize, usize, u32)] {
        &self.segments[..self.seg_count]
    }

    /// Construct a `LoadedElf` from parts for tests (no ELF parsing), so
    /// `process::spawn_user` can be host-tested against known segment layouts.
    #[cfg(test)]
    pub(crate) fn for_test(entry: usize, segments: &[(usize, usize, u32)]) -> Self {
        let mut segs = [(0usize, 0usize, 0u32); 16];
        for (i, s) in segments.iter().enumerate().take(16) {
            segs[i] = *s;
        }
        // Identity image (image_phys == image_lo) so map_user_image maps
        // va -> va in host tests, matching the pre-#502 behaviour.
        let image_lo = segments.iter().map(|s| s.0).min().unwrap_or(0);
        Self {
            entry,
            pages_used: 0,
            segments: segs,
            seg_count: segments.len().min(16),
            image_phys: image_lo,
            image_lo,
            image_pages: 0,
        }
    }
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
/// descriptors for each `PT_LOAD` segment.
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
        segments: [(0, 0, 0, 0, 0); 16],
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
        let seg_flags = phdr.p_flags;

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

        // WHY (finding 2): the fixed-capacity `segments` array holds at
        // most 16 PT_LOAD descriptors -- a 17th+ segment was previously
        // dropped silently here while `total_pages` above still counted
        // its page budget, so `load()` would report success while never
        // writing that segment's bytes to memory. Reject the image
        // outright instead; this coexists with the #327 budget check above
        // and the finding-49 entry-in-segment check below, which still run
        // against whatever segments were recorded before this one is
        // rejected.
        if segments.count >= 16 {
            return Err(ElfError::InvalidSegment);
        }
        segments.segments[segments.count] = (vaddr, memsz, filesz, file_offset, seg_flags);
        segments.count += 1;
    }

    // WHY (finding 49): e_entry is a fully attacker-controlled u32 header
    // field, entirely independent of the PT_LOAD segments validated above.
    // Both callers (kinit.rs's boot-time spawn of /init and /shell, and
    // syscall.rs's sys_execve) transmute this address straight to a
    // callable function pointer and jump to it -- an entry point outside
    // every loaded segment is an arbitrary jump/code-execution primitive,
    // not merely a crash. Require entry to fall within a segment that was
    // actually loaded before it is ever handed back to a caller.
    let entry_in_loaded_segment = (0..segments.count).any(|i| {
        let (vaddr, memsz, _, _, _) = segments.segments[i];
        entry >= vaddr && entry < vaddr.saturating_add(memsz)
    });
    if !entry_in_loaded_segment {
        return Err(ElfError::InvalidSegment);
    }

    Ok((entry, segments))
}

/// Validated ELF segment descriptors (output of header validation).
#[derive(Debug)]
struct ValidatedElf {
    /// `(vaddr, memsz, filesz, file_offset, p_flags)` for each `PT_LOAD` segment.
    segments: [(usize, usize, usize, usize, u32); 16],
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
/// Writes each `PT_LOAD` segment directly to its identity-mapped `vaddr`
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
/// Load an ELF image (no placement restriction) -- for host tests that write
/// to real host addresses. Kernel spawn paths use `load_confined`.
pub(crate) fn load(data: &[u8]) -> Result<LoadedElf, ElfError> {
    load_impl(data, None)
}

/// `load()`, but reject any `PT_LOAD` segment outside `[lo, hi)` -- the reserved
/// user-image window (#489) -- BEFORE writing a byte, and (#502) load into a
/// freshly-allocated per-process image frame rather than the identity vaddr.
/// A single `validate()` pass gates both format and placement, so a boot/exec
/// image can never write into page-allocator RAM or escape the exec revocation
/// surface, and fail-before-destroy holds. Every authored image links at
/// `USER_TEXT_BASE` (init.ld). The returned `LoadedElf` carries the image frame
/// base (`image_phys`/`image_lo`/`image_pages`) for `map_user_image` + teardown.
///
/// # Safety
///
/// The CURRENT TTBR0 must be the kernel L1 (`mmu::table_base()`). On arm this
/// writes segment bytes to the freshly-allocated `image_phys` and reads the
/// kernel-heap-backed `data` slice through raw physical addresses; a forked
/// caller's TTBR0 user-remaps allocator-range VAs, so writing/reading under it
/// could alias another process's memory (the #497 zero-on-free hazard class).
/// kinit runs under the kernel L1; `sys_execve` switches to it before calling.
pub(crate) unsafe fn load_confined(
    data: &[u8],
    lo: usize,
    hi: usize,
) -> Result<LoadedElf, ElfError> {
    load_impl(data, Some((lo, hi)))
}

/// #502 CONFINED-load pre-pass: validate every segment lands in `[lo, hi)`,
/// prove the segments tile a gapless span (`span == total_pages`), and allocate
/// the contiguous per-process image frame. Returns `(image_phys, image_lo)`.
///
/// WHY its own `#[inline(never)]` function: see the call site in `load_impl` --
/// keeping this out of `load_impl`'s frame is what prevents the armv7 exec-path
/// codegen from corrupting the returned `ValidatedElf`.
#[inline(never)]
fn plan_confined_image(
    validated: &ValidatedElf,
    lo: usize,
    hi: usize,
) -> Result<(usize, usize), ElfError> {
    let mut lo_img = usize::MAX;
    let mut max_end = 0usize;
    for idx in 0..validated.count {
        let (vaddr, memsz, _, _, _) = validated.segments[idx];
        // Fully inside [lo, hi). Rejecting here (before alloc/write) keeps
        // fail-before-destroy AND makes the (vaddr - lo_img) offset in load_impl
        // non-negative (vaddr >= lo_img). vaddr + memsz cannot overflow:
        // validate() proved it via #318. Per-segment PAGE alignment is enforced
        // by map_user_image (process.rs) -- a non-aligned image fails there
        // cleanly (the image frame is freed on the spawn/exec map-failure path),
        // so it is not re-checked here (which would also reject the host test's
        // arbitrary-aligned static-buffer vaddr).
        if vaddr < lo || vaddr + memsz > hi {
            return Err(ElfError::InvalidSegment);
        }
        lo_img = lo_img.min(vaddr);
        max_end = max_end.max(vaddr + memsz);
    }
    // INVARIANT (#502): span == Σ ceil(memsz/PAGE) (= total_pages) means, by
    // pigeonhole, the segments tile the span with NO gaps and NO overlaps -- so
    // the contiguous image frame maps exactly, every allocated page is mapped,
    // and the L2 walk is a complete ownership record. validate() rejects a
    // segmentless confined image (its entry must fall inside a loaded segment),
    // so count >= 1 here.
    let span_pages = (max_end - lo_img).div_ceil(page::PAGE_SIZE);
    if span_pages != validated.total_pages {
        return Err(ElfError::InvalidSegment);
    }
    // Allocate the contiguous per-process image frame (arm only; host
    // load_confined writes to real host addresses at identity vaddr).
    #[cfg(target_arch = "arm")]
    let phys = page::alloc_contiguous(validated.total_pages).ok_or(ElfError::OutOfMemory)?;
    #[cfg(not(target_arch = "arm"))]
    let phys = lo_img;
    Ok((phys, lo_img))
}

fn load_impl(data: &[u8], placement: Option<(usize, usize)>) -> Result<LoadedElf, ElfError> {
    let (entry, validated) = validate(data)?;

    // #489: enforce the placement window BEFORE any write (fail-before-destroy).
    // A single validate() feeds both this and the write loop -- no second
    // validate pass (a distinct `peek()` here corrupted the parse on the exec
    // path, so placement is folded into load itself).

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

    // #502: for a CONFINED image, validate placement + allocate a per-process
    // image frame BEFORE any write (fail-before-destroy), then load INTO that
    // frame instead of the identity vaddr, so every process gets its own image.
    // This pre-pass REPLACES the old in-write-loop per-segment placement check.
    let (image_phys, image_lo) = match placement {
        // WHY a separate #[inline(never)] call (#502): folding this placement +
        // allocation logic inline inflated load_impl's stack frame enough that,
        // on the register-pressured exec path, armv7 codegen corrupted the
        // `validated` segment array `validate()` had just returned (each
        // segment's recorded memsz came back == its vaddr, overshooting the
        // window and spuriously rejecting a valid image). Giving the pre-pass its
        // own frame keeps load_impl shallow and `validated` intact.
        Some((lo, hi)) => plan_confined_image(&validated, lo, hi)?,
        // Unconfined load() (host tests): identity write to vaddr, no image frame.
        None => (0, 0),
    };

    let mut pages_used = 0;

    for idx in 0..validated.count {
        let (vaddr, memsz, filesz, file_offset, flags) = validated.segments[idx];

        // #502: physical write target. A confined image writes into its
        // per-process frame (arm: image_phys + (vaddr - image_lo)); host and the
        // unconfined load() write identity vaddr. Placement was fully validated
        // in the pre-pass above, so no per-segment check here.
        #[cfg(target_arch = "arm")]
        let seg_dest = if placement.is_some() {
            image_phys + (vaddr - image_lo)
        } else {
            vaddr
        };
        #[cfg(not(target_arch = "arm"))]
        let seg_dest = vaddr;

        // WHY: identical to the checked computation validate() already
        // performed for this same memsz while building validated.total_pages
        // (#327) — if it did not overflow there, it cannot overflow here —
        // so plain arithmetic is safe without re-deriving the check.
        let num_pages = (memsz + page::PAGE_SIZE - 1) / page::PAGE_SIZE;
        for p in 0..num_pages {
            pages_used += 1;

            // #502: write to the per-process image frame (or identity vaddr on
            // host / unconfined). The pre-pass validated [vaddr, vaddr+memsz) is
            // in-window, so seg_dest + p*PAGE stays within the allocated frame.
            let dest = seg_dest + p * page::PAGE_SIZE;
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
                    match file_offset
                        .checked_add(byte_offset)
                        .and_then(|i| data.get(i))
                    {
                        Some(&b) => b,
                        None => 0, // INVARIANT: unreachable per validate()'s file_end check
                    }
                } else {
                    0 // BSS: zero-filled
                };
                // SAFETY: dest is a page-aligned address in the per-process
                // image frame (arm confined) -- a freshly alloc_contiguous'd
                // frame the caller guarantees is identity-mapped under the LIVE
                // kernel L1 (load_confined's `unsafe` precondition, #502) -- or
                // an identity user vaddr (host / unconfined load()). byte_offset
                // - page_start < PAGE_SIZE, so the write stays within the
                // segment's declared page range.
                unsafe {
                    dest_ptr.add(byte_offset - page_start).write(val);
                }
            }
        }

        // #498: the D-side writes above can leave stale I-cache lines at
        // seg_dest on real hardware for an executable segment (PF_X).
        // seg_dest is a kernel-identity VA here -- load_confined's `unsafe`
        // contract requires the current TTBR0 to be the kernel L1, and the
        // unconfined load() (host tests) writes the identity vaddr directly
        // -- so it is valid to sync at seg_dest for both paths. Calling
        // unconditionally (mirroring flush_tlb_all/switch_addr_space): the
        // arm/host split lives inside sync_icache_range itself, which is a
        // no-op on non-ARM builds.
        if flags & PF_X != 0 {
            // SAFETY: see the comment above; seg_dest names memsz freshly
            // D-side-written bytes of this segment, validly mapped under the
            // active kernel-identity TTBR0.
            unsafe {
                crate::mmu::sync_icache_range(seg_dest, memsz);
            }
        }
    }

    // Carry per-segment (vaddr, memsz, p_flags) so spawn_user can map each
    // segment PL0-accessible with W^X permissions (#482).
    let mut segments = [(0usize, 0usize, 0u32); 16];
    for i in 0..validated.count {
        let (vaddr, memsz, _, _, flags) = validated.segments[i];
        segments[i] = (vaddr, memsz, flags);
    }
    Ok(LoadedElf {
        entry,
        pages_used,
        segments,
        seg_count: validated.count,
        image_phys,
        image_lo,
        image_pages: validated.total_pages,
    })
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

    /// #316: `e_phoff` chosen so `phoff + i*phentsize` would wrap a 32-bit
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

    /// #316: `p_offset/p_filesz` chosen so `file_offset + filesz` would wrap
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

    /// #317: `e_phentsize` smaller than `size_of::`<Elf32Phdr>() must be
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

    /// #318: a `PT_LOAD` segment whose `p_vaddr` lies outside the sanctioned
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

    /// #327: a `PT_LOAD` segment declaring memory far beyond the configured
    /// per-image budget must be rejected before any page is allocated.
    #[test]
    fn parse_rejects_segment_memory_over_budget() {
        let mut buf = [0u8; ELF32_EHDR_SIZE + ELF32_PHDR_SIZE];
        let h = make_valid_ehdr();
        buf[..ELF32_EHDR_SIZE].copy_from_slice(&h);
        buf[44] = 1; // e_phnum = 1

        // Elf32Phdr at offset 52: p_type = PT_LOAD (1).
        buf[52..56].copy_from_slice(&1u32.to_le_bytes());
        // p_vaddr (offset 60): board::KERNEL_END, inside the allowed load
        // region so #318's check does not fire first.
        buf[60..64].copy_from_slice(&0x4010_0000u32.to_le_bytes());
        // p_memsz (offset 72): 32 MB, comfortably inside RAM but four times
        // over MAX_ELF_PAGES (2048 pages = 8 MB).
        buf[72..76].copy_from_slice(&0x0200_0000u32.to_le_bytes());

        assert_eq!(validate(&buf).unwrap_err(), ElfError::InvalidSegment);
    }

    /// finding 2: a 17th `PT_LOAD` segment must be rejected, not silently
    /// dropped from the fixed 16-slot `segments` array while `total_pages`
    /// still counted its budget -- the old behavior let `load()` report
    /// success while never writing that segment's bytes to memory.
    #[test]
    fn parse_rejects_more_than_sixteen_pt_load_segments() {
        const N: usize = 17;
        let mut buf = [0u8; ELF32_EHDR_SIZE + N * ELF32_PHDR_SIZE];
        let h = make_valid_ehdr();
        buf[..ELF32_EHDR_SIZE].copy_from_slice(&h);
        // e_phnum (offset 44, u16 LE): 17 program headers.
        buf[44] = 17;
        buf[45] = 0;

        for i in 0..N {
            let off = ELF32_EHDR_SIZE + i * ELF32_PHDR_SIZE;
            // p_type = PT_LOAD (1).
            buf[off..off + 4].copy_from_slice(&1u32.to_le_bytes());
            // p_vaddr: inside the allowed load region.
            buf[off + 8..off + 12].copy_from_slice(&0x4010_0000u32.to_le_bytes());
            // p_memsz: 1 page, well under the MAX_ELF_PAGES budget even x17.
            buf[off + 20..off + 24].copy_from_slice(&0x1000u32.to_le_bytes());
        }

        assert_eq!(
            validate(&buf).unwrap_err(),
            ElfError::InvalidSegment,
            "a 17th PT_LOAD segment must be rejected, not silently dropped"
        );
    }

    #[test]
    fn parse_accepts_valid_elf() {
        // A valid ELF with one PT_LOAD segment covering e_entry must parse
        // successfully. WHY a real segment (finding 49): entry is no
        // longer accepted merely because the header is well-formed -- it
        // must fall within a segment that was actually loaded, or the
        // address handed to kinit.rs's transmute+call would be
        // unmapped/arbitrary. A phnum=0 image (no code loaded at all) can
        // no longer have any valid entry point.
        let mut buf = [0u8; ELF32_EHDR_SIZE + ELF32_PHDR_SIZE];
        let h = make_valid_ehdr();
        buf[..ELF32_EHDR_SIZE].copy_from_slice(&h);
        buf[44] = 1; // e_phnum = 1
        // e_entry (offset 24): moved to the start of the PT_LOAD segment below.
        buf[24..28].copy_from_slice(&0x4010_0000u32.to_le_bytes());

        // Elf32Phdr at offset 52: p_type = PT_LOAD (1).
        buf[52..56].copy_from_slice(&1u32.to_le_bytes());
        // p_vaddr (offset 60): inside the allowed load region, matching e_entry.
        buf[60..64].copy_from_slice(&0x4010_0000u32.to_le_bytes());
        // p_memsz (offset 72): small, just needs to contain e_entry.
        buf[72..76].copy_from_slice(&0x1000u32.to_le_bytes());

        let (entry, validated) =
            validate(&buf).expect("valid ELF with entry inside a loaded segment must parse");
        assert_eq!(entry, 0x4010_0000, "entry point must match e_entry");
        assert_eq!(validated.count, 1, "one PT_LOAD segment expected");
    }

    /// #501 regression: the exec-path mis-read (a segment's (vaddr, memsz)
    /// coming back field-shifted, e.g. (0x7ff00000, 0x40) -> (0x0, 0x7ff00000))
    /// came from a SEPARATE pre-pass that re-parsed via a second `validate()`
    /// "peek", now removed -- placement is folded into `load()`'s single write
    /// loop. Guard both halves of the Done-when: (1) reading validated.segments
    /// in a standalone pre-pass yields the exact tuple values the write loop's
    /// destructure yields (no field shift), and (2) a second `validate()` over
    /// the same bytes is idempotent (the peek scenario). Two distinct segments
    /// so any single-field shift is visible.
    #[test]
    fn validate_prepass_and_second_pass_read_segments_identically() {
        let mut buf = [0u8; ELF32_EHDR_SIZE + 2 * ELF32_PHDR_SIZE];
        buf[..ELF32_EHDR_SIZE].copy_from_slice(&make_valid_ehdr());
        buf[44] = 2; // e_phnum = 2
        buf[24..28].copy_from_slice(&0x4010_0000u32.to_le_bytes()); // e_entry in seg 0

        // Segment 0: PT_LOAD, vaddr 0x40100000, memsz 0x1000.
        let off0 = ELF32_EHDR_SIZE;
        buf[off0..off0 + 4].copy_from_slice(&1u32.to_le_bytes());
        buf[off0 + 8..off0 + 12].copy_from_slice(&0x4010_0000u32.to_le_bytes());
        buf[off0 + 20..off0 + 24].copy_from_slice(&0x1000u32.to_le_bytes());
        // Segment 1: PT_LOAD, vaddr 0x40102000, memsz 0x2000 (distinct values).
        let off1 = ELF32_EHDR_SIZE + ELF32_PHDR_SIZE;
        buf[off1..off1 + 4].copy_from_slice(&1u32.to_le_bytes());
        buf[off1 + 8..off1 + 12].copy_from_slice(&0x4010_2000u32.to_le_bytes());
        buf[off1 + 20..off1 + 24].copy_from_slice(&0x2000u32.to_le_bytes());

        let (_e1, v1) = validate(&buf).expect("first validate must succeed");
        assert_eq!(v1.count, 2, "two PT_LOAD segments expected");

        // (1) Standalone pre-pass: the tuple layout is
        // (vaddr, memsz, filesz, file_offset, flags) -- the exact destructure
        // load_impl's write loop uses. Confirm no field shift.
        let (v0, m0, _, _, _) = v1.segments[0];
        assert_eq!(
            (v0, m0),
            (0x4010_0000, 0x1000),
            "segment 0 (vaddr, memsz) must read unshifted in a standalone pre-pass (#501)"
        );
        let (v1a, m1, _, _, _) = v1.segments[1];
        assert_eq!(
            (v1a, m1),
            (0x4010_2000, 0x2000),
            "segment 1 (vaddr, memsz) must read unshifted in a standalone pre-pass (#501)"
        );

        // (2) A second validate() (the root-cause peek) must be idempotent.
        let (_e2, v2) = validate(&buf).expect("second validate must succeed");
        assert_eq!(
            v2.count, v1.count,
            "segment count must match across validate passes"
        );
        for idx in 0..v1.count {
            assert_eq!(
                v1.segments[idx], v2.segments[idx],
                "segment {idx} must read identically across validate passes (#501)"
            );
        }
    }

    /// finding 49: `e_entry` outside every loaded `PT_LOAD` segment must be
    /// rejected -- kinit.rs and syscall.rs's `sys_execve` both transmute this
    /// address straight to a callable function pointer, so an unvalidated
    /// entry point is an arbitrary jump/code-execution primitive, not just
    /// a crash.
    #[test]
    fn parse_rejects_entry_outside_loaded_segment() {
        let mut buf = [0u8; ELF32_EHDR_SIZE + ELF32_PHDR_SIZE];
        let h = make_valid_ehdr();
        buf[..ELF32_EHDR_SIZE].copy_from_slice(&h);
        buf[44] = 1; // e_phnum = 1
        // e_entry (offset 24): left at make_valid_ehdr()'s 0x8000 default,
        // which is NOT inside the segment below.

        // Elf32Phdr at offset 52: p_type = PT_LOAD (1).
        buf[52..56].copy_from_slice(&1u32.to_le_bytes());
        // p_vaddr (offset 60): inside the allowed load region, but does not
        // contain e_entry (0x8000).
        buf[60..64].copy_from_slice(&0x4010_0000u32.to_le_bytes());
        buf[72..76].copy_from_slice(&0x1000u32.to_le_bytes());

        assert_eq!(validate(&buf).unwrap_err(), ElfError::InvalidSegment);
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
        // `static`) loads inside [board::KERNEL_END, board::RAM_END) on
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
        // e_entry (offset 24): must fall within the PT_LOAD segment below
        // (finding 49) -- reuse the segment's own vaddr as the entry point.
        data[24..28].copy_from_slice(&(vaddr as u32).to_le_bytes());

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
            page::init(
                0x4000_0000,
                0x4000_0000 + 8 * page::PAGE_SIZE,
                0x4000_0000 + 4 * page::PAGE_SIZE,
            );
        }
        let free_before = page::free_count();
        assert_eq!(free_before, 4, "test setup must yield exactly 4 free pages");

        let loaded = load(&data).expect("well-formed single-page segment must load");
        assert_eq!(
            loaded.pages_used, 1,
            "a 16-byte segment must round up to exactly 1 page"
        );

        // SAFETY: BUF is a private test-only static, read after load() wrote
        // to its address.
        unsafe {
            assert_eq!(&BUF[..4], b"TEST", "file bytes must be copied to vaddr");
            assert_eq!(
                &BUF[4..16],
                &[0u8; 12],
                "bytes beyond filesz must be BSS-zeroed"
            );
        }

        assert_eq!(
            page::free_count(),
            free_before,
            "a successful load must not permanently consume any page from the allocator (#328)"
        );
    }

    #[test]
    fn load_confined_rejects_out_of_window_placement_before_writing() {
        // #489: load_confined must reject a segment outside [lo, hi) -- the
        // reserved user-image window -- and it must do so BEFORE writing a byte
        // (fail-before-destroy), so a boot/exec image can never write into
        // page-allocator RAM or escape the exec revocation surface.
        static mut BUF: [u8; 16] = [0xEE; 16];
        let vaddr = core::ptr::addr_of_mut!(BUF) as *mut u8 as usize;

        let mut data = [0u8; ELF32_EHDR_SIZE + ELF32_PHDR_SIZE + 4];
        let h = make_valid_ehdr();
        data[..ELF32_EHDR_SIZE].copy_from_slice(&h);
        data[44] = 1; // e_phnum = 1
        data[24..28].copy_from_slice(&(vaddr as u32).to_le_bytes()); // e_entry
        data[52..56].copy_from_slice(&1u32.to_le_bytes()); // p_type = PT_LOAD
        let file_offset = (ELF32_EHDR_SIZE + ELF32_PHDR_SIZE) as u32;
        data[56..60].copy_from_slice(&file_offset.to_le_bytes()); // p_offset
        data[60..64].copy_from_slice(&(vaddr as u32).to_le_bytes()); // p_vaddr
        data[68..72].copy_from_slice(&4u32.to_le_bytes()); // p_filesz
        data[72..76].copy_from_slice(&4u32.to_le_bytes()); // p_memsz
        data[ELF32_EHDR_SIZE + ELF32_PHDR_SIZE..].copy_from_slice(b"TEST");

        // Free pool large enough that the OOM check passes and the placement
        // check (in the write loop) is reached.
        // SAFETY: test-only page-allocator state; single-threaded per test.
        unsafe {
            page::init(
                0x4000_0000,
                0x4000_0000 + 8 * page::PAGE_SIZE,
                0x4000_0000 + 4 * page::PAGE_SIZE,
            );
        }

        // SAFETY: read the test-only static (addr_of! + read copies it).
        let before = unsafe { core::ptr::addr_of!(BUF).read() };
        // A window that EXCLUDES the segment's real address -> reject.
        let lo = vaddr.wrapping_add(0x1_0000);
        let hi = lo.wrapping_add(0x1_0000);
        // SAFETY: on host, load_confined writes identity to real host addresses
        // (no per-process frame, no TTBR0) -- the arm kernel-L1 precondition is
        // vacuous here.
        let r = unsafe { load_confined(&data, lo, hi) };
        assert!(
            matches!(r, Err(ElfError::InvalidSegment)),
            "an out-of-window segment must be rejected, got {r:?} (vaddr={vaddr:#x} lo={lo:#x} hi={hi:#x})"
        );
        // SAFETY: read the test-only static; the reject must have skipped the
        // write, so its bytes are unchanged.
        let after = unsafe { core::ptr::addr_of!(BUF).read() };
        assert_eq!(after, before, "reject must not have written the segment");

        // The SAME image loads when the window includes it (plain load / a
        // window that contains vaddr) -- proving the gate is placement, not format.
        // SAFETY: as above -- host identity write, no TTBR0 precondition.
        assert!(unsafe { load_confined(&data, vaddr, vaddr.wrapping_add(0x1000)) }.is_ok());
    }

    /// #328: when the free pool is smaller than the segment budget, `load()`
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
        // e_entry (offset 24): must fall within the PT_LOAD segment below
        // (finding 49) -- reuse the segment's own vaddr as the entry point.
        data[24..28].copy_from_slice(&(vaddr as u32).to_le_bytes());
        data[52..56].copy_from_slice(&1u32.to_le_bytes()); // p_type = PT_LOAD
        data[60..64].copy_from_slice(&(vaddr as u32).to_le_bytes());
        data[72..76].copy_from_slice(&16u32.to_le_bytes()); // p_memsz = 16

        // Empty free pool: usable range collapses to zero pages.
        // SAFETY: test-only page-allocator state; single-threaded per test.
        unsafe {
            page::init(0x4000_0000, 0x4000_0000, 0x4000_0000);
        }
        assert_eq!(
            page::free_count(),
            0,
            "test setup must yield zero free pages"
        );

        let result = load(&data);
        assert_eq!(
            result.unwrap_err(),
            ElfError::OutOfMemory,
            "a segment budget exceeding the free pool must be rejected up front"
        );

        assert_eq!(
            unsafe { BUF },
            [0u8; 16],
            "no byte may be written before the OOM precheck passes"
        );
    }
}
