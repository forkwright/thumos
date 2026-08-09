//! Process abstraction, context switching, and two-process isolation.
//!
//! Each process has a saved register context, a stack, a process ID,
//! a state, and its own L1 page table. The scheduler selects the next
//! ready process and context-switches to it on each timer tick, swapping
//! TTBR0 so each process has an independent virtual address space.
//!
//! On `ARMv7` (#465), a context switch is a FULL trap-frame swap: the exception
//! stub (exceptions.rs) captures the interrupted register file (r0-r12, banked
//! sp/lr, resume pc, cpsr) into a `Context` on the handler stack, `switch_to`
//! copies that into the current PCB and loads the next process's `Context`
//! into the frame, and the stub epilogue exception-returns into it. This works
//! preemptively (from the timer IRQ, anywhere in a process) and cooperatively
//! (Yield/Exit/futex from an SVC trap) through one mechanism.

use core::ptr::addr_of_mut;

use crate::ipc;
use crate::mmu;
use crate::page;
use crate::signal::{Signal, SignalAction, SignalState};

/// Maximum number of processes.
const MAX_PROCS: usize = 16;

/// Process ID type.
pub(crate) type Pid = u8;

/// Process state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Not allocated.
    Free,
    /// Ready to run (in the ready queue).
    Ready,
    /// Currently running on a core.
    Running,
    /// Blocked waiting for an event.
    Blocked,
    /// Sleeping until `wake_tick` (set by nanosleep).
    Sleeping,
    /// Terminated, awaiting cleanup.
    Dead,
}

/// Fault kind delivered to the kinit supervisor when a process faults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultKind {
    /// ARM data abort (load/store to unmapped or protected address).
    DataAbort { fault_addr: u32, fault_status: u32 },
    /// ARM prefetch abort (instruction fetch FROM unmapped address).
    PrefetchAbort { fault_addr: u32, fault_status: u32 },
    /// Undefined instruction executed.
    UndefinedInstruction,
}

/// Disposition of a CPU fault, decided from the trap frame's saved CPSR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultDisposition {
    /// Fault came from User mode (PL0): kill the process; the kernel and every
    /// other process continue.
    KillUser,
    /// Fault came from any PL1 mode: a kernel bug -- halt, never recover.
    KernelHalt,
}

/// CPSR mode field mask (ARM ARM B1.3.1, M[4:0]).
const CPSR_MODE_MASK: u32 = 0x1F;
/// User mode (PL0) CPSR mode value.
const CPSR_MODE_USER: u32 = 0x10;

/// Kill-vs-halt decision for a fault, from the SAVED CPSR in the trap frame.
///
/// ONLY User mode (0x10) is killable: scheduled processes run at User
/// (`spawn_user/exec`) or System (PID 0 + spawn kernel threads), and System-mode
/// code is kernel code in the kernel address space, so its faults are kernel
/// bugs. A saved exception mode (SVC/IRQ/ABT/UND/FIQ) means a HANDLER faulted
/// -- also a kernel bug; ABT/UND halting here is what bounds recursion if the
/// kill path itself faults. Fail-closed: anything unrecognized halts.
pub(crate) fn fault_disposition(saved_cpsr: u32) -> FaultDisposition {
    if saved_cpsr & CPSR_MODE_MASK == CPSR_MODE_USER {
        FaultDisposition::KillUser
    } else {
        FaultDisposition::KernelHalt
    }
}

/// Exit status for a fault-killed process: 128 + POSIX signal number
/// (SIGSEGV=11 for aborts -> 139, SIGILL=4 for undef -> 132), so a wait-based
/// supervisor can distinguish fault kills from voluntary exits.
pub(crate) fn fault_exit_status(kind: FaultKind) -> i32 {
    match kind {
        FaultKind::DataAbort { .. } | FaultKind::PrefetchAbort { .. } => 139,
        FaultKind::UndefinedInstruction => 132,
    }
}

/// Kill the CURRENT process for `kind`, from abort/undef trap context: notify
/// PID 0 (Dead + fd drain + IPC, via `notify_fault`), then run the exit path
/// (`exit_current`: resource teardown + trap-frame swap to the successor). On
/// return the trap frame holds the successor's context and the stub epilogue
/// exception-returns into it -- the same unwind contract as the Exit syscall.
///
/// INVARIANT: `exit_current` frees the victim's L1 while TTBR0 still points at
/// it; safe because `free_addr_space` only clears a pool bit (tables are zeroed
/// at ALLOC, not free) and nothing allocates before `switch_to`'s TTBR0 +
/// TLBIALL -- the exact pattern the Exit-syscall path already relies on.
pub(crate) fn fault_exit_current(kind: FaultKind) {
    notify_fault(current_pid(), kind);
    let _ = exit_current(fault_exit_status(kind)); // WHY: exit_current returns the SVC-return-value convention (u32, not a Result); the abort path has no syscall caller to return it to
}

/// Full trap-frame CPU context, captured at exception entry (#465).
///
/// WARNING: THIS LAYOUT IS ABI. The exception stubs in `exceptions.rs` build
/// this exact 68-byte frame on the handler stack and index it by the byte
/// offsets asserted below -- changing a field's size/order without updating the
/// asm silently corrupts every context switch. A preemptive switch must
/// capture the WHOLE interrupted register file (r0-r12, banked sp/lr, resume
/// pc, cpsr), not just callee-saved registers, because the interrupt can land
/// anywhere.
#[repr(C)]
#[derive(Clone, Copy)]
#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
pub struct Context {
    /// r0-r12 (offsets 0..=48).
    pub r: [u32; 13],
    /// Banked user/system sp (offset 52).
    pub sp: u32,
    /// Banked user/system lr (offset 56).
    pub lr: u32,
    /// Resume address (offset 60).
    pub pc: u32,
    /// Saved CPSR = SPSR at exception entry (offset 64).
    pub cpsr: u32,
}

const _: () = assert!(core::mem::size_of::<Context>() == 68);
const _: () = assert!(core::mem::offset_of!(Context, sp) == 52);
const _: () = assert!(core::mem::offset_of!(Context, lr) == 56);
const _: () = assert!(core::mem::offset_of!(Context, pc) == 60);
const _: () = assert!(core::mem::offset_of!(Context, cpsr) == 64);

impl Context {
    const fn zero() -> Self {
        Self {
            r: [0; 13],
            sp: 0,
            lr: 0,
            pc: 0,
            cpsr: 0,
        }
    }

    /// Build the initial context for a fresh process entered at `entry` with
    /// stack top `sp`, in CPU mode `mode` (0x1F System for spawn, 0x10 User for
    /// exec). Derives Thumb state from the entry LSB (T-bit) so a Thumb image
    /// is entered correctly even though build.rs currently emits ARM.
    fn initial(entry: u32, sp: u32, mode: u32) -> Self {
        Self {
            r: [0; 13],
            sp,
            lr: 0,
            pc: entry & !1,
            cpsr: mode | ((entry & 1) << 5),
        }
    }
}

/// Maximum number of tracked anonymous mappings per process.
/// WHY: fixed-size array avoids heap allocation in the kernel's process table.
/// 32 mappings is sufficient for early userspace (libc typically needs ~10).
pub(crate) const MAX_MAPPINGS: usize = 32;

/// A tracked virtual memory region created by mmap or brk.
#[derive(Clone, Copy)]
pub struct VmMapping {
    /// Starting virtual address (page-aligned).
    pub start: usize,
    /// Number of 4 KB pages in this mapping.
    pub pages: usize,
    /// POSIX protection flags (`PROT_READ` | `PROT_WRITE` | `PROT_EXEC`).
    pub prot: u32,
}

/// Default initial program break for new processes.
/// WHY: `0x1000_0000` is above device MMIO (0x0-0x2FFF_FFFF) but below DRAM
/// (`0x4000_0000`), providing a clean region for the user heap that won't
/// conflict with kernel data structures or device mappings.
pub(crate) const DEFAULT_HEAP_BREAK: usize = 0x1000_0000;

/// Base address for mmap allocations, above the heap region.
/// WHY: `0x2000_0000` provides 256 MB of VA space for mmap before hitting
/// the modem region, keeping mmap and brk regions non-overlapping.
pub(crate) const MMAP_BASE: usize = 0x2000_0000;

/// Process control block.
pub(crate) struct Process {
    // kanon:ignore RUST/struct-too-many-fields -- standard Unix PCB fields; each models a distinct process resource
    pub pid: Pid,
    pub state: State,
    pub ctx: Context,
    /// Parent PID, if this process was created via `fork()`.
    pub parent: Option<Pid>,
    /// Exit status SET by `exit_with_status()` / `exit_cleanup()`.
    pub exit_status: i32,
    /// Physical address of this process's L1 page table.
    /// 0 means "use kernel global L1" (process 0 / kinit).
    pub page_table_phys: usize,
    /// Base address of the stack allocation (for freeing).
    stack_base: usize,
    /// Number of pages allocated for the stack.
    stack_pages: usize,
    /// Current program break (heap boundary), page-aligned.
    /// Managed by the brk syscall.
    pub heap_break: usize,
    /// Tracked anonymous memory mappings (mmap regions).
    pub mappings: [Option<VmMapping>; MAX_MAPPINGS],
    /// Signal handlers and pending-signal bitmask for this process.
    pub signal_state: SignalState,
    /// User identity: 0 = root (kinit/kernel), 1+ = unprivileged userspace.
    /// WHY: process 0 (kinit) is UID 0. Forked children inherit the parent's
    /// UID. A future setuid syscall can lower (but not raise) this value.
    pub uid: u32,
    /// Tick count at which this process should wake from Sleeping state.
    /// Only meaningful when state == Sleeping. Set by `sys_nanosleep`;
    /// the scheduler transitions the process to Ready when `ticks()` >= `wake_tick`.
    pub wake_tick: u64,
    /// Capability bitfield: which sensitive kernel operations this process may
    /// invoke. kinit (PID 0) holds ALL capabilities. Forked children inherit a
    /// policy-defined subset (default: ALL minus MODEM and AUDIT).
    /// See `capability::Capabilities` for bit definitions (REQ-09).
    pub capabilities: u32,
    /// Per-process fd table (#267): fd number -> shared open-file
    /// description. Owned by the PCB so its lifetime is the process's
    /// lifetime by construction -- no stale-table window on slot reuse.
    pub fds: crate::fd::FdTable,
    /// Per-process current working directory (#437): owned by the PCB, so a
    /// chdir in one process never leaks into another. Initialized to "/",
    /// inherited across fork (POSIX).
    pub cwd: [u8; crate::fd::CWD_MAX],
    /// Length of the path stored in `cwd`.
    pub cwd_len: usize,
}

/// Process table.
static mut PROCS: [Option<Process>; MAX_PROCS] = {
    const NONE: Option<Process> = None;
    [NONE; MAX_PROCS]
};

/// Currently running process ID.
static mut CURRENT: Pid = 0;

/// Whether the scheduler may context-switch. WHY: `kinit` runs in the bare
/// boot context (not a scheduled process), so a timer-IRQ context switch
/// during init would abandon the boot mid-sequence -- a timing-dependent
/// hang (the tick lands at a non-deterministic point). Boot enables
/// scheduling via `enable_scheduling()` once userspace has been spawned and
/// the boot context becomes the kardia service loop (PID 0's body).
static SCHEDULING_ENABLED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Enable scheduler context switches. Called exactly once from `kinit`, after
/// userspace spawn, before the boot context enters the kardia service loop.
pub(crate) fn enable_scheduling() {
    SCHEDULING_ENABLED.store(true, core::sync::atomic::Ordering::Release);
}

/// Whether the scheduler may context-switch (false throughout `kinit`).
pub(crate) fn scheduling_enabled() -> bool {
    SCHEDULING_ENABLED.load(core::sync::atomic::Ordering::Acquire)
}

/// Stack size per process: 16 KB (4 pages).
const STACK_PAGES: usize = 4;

/// Initialize the process subsystem.
/// Creates process 0 (the kernel/idle process) FROM the current execution context.
///
/// # Safety
///
/// Must be called once during kernel init.
pub unsafe fn init() {
    // SAFETY: called once during kernel init before any other process code runs.
    // PROCS and CURRENT are static mut; no concurrent access is possible at
    // this point because the scheduler has not started yet.
    unsafe {
        let proc0 = Process {
            pid: 0,
            state: State::Running,
            ctx: Context::zero(), // NOTE: kernel process context is "current CPU state"
            parent: None,
            exit_status: 0,
            page_table_phys: mmu::table_base(), // NOTE: kernel global L1
            stack_base: 0,                      // NOTE: uses the boot stack, not allocated
            stack_pages: 0,
            heap_break: DEFAULT_HEAP_BREAK,
            mappings: [None; MAX_MAPPINGS],
            signal_state: SignalState::new(),
            uid: 0,
            wake_tick: 0,
            // kinit (PID 0) has all capabilities (REQ-09).
            capabilities: crate::capability::Capabilities::ALL,
            fds: crate::fd::FdTable::new(),
            cwd: crate::fd::DEFAULT_CWD,
            cwd_len: 1,
        };
        let procs = &mut *addr_of_mut!(PROCS);
        procs[0] = Some(proc0);
        CURRENT = 0;
    }
}

/// Create a new process that starts executing at `entry_point`.
/// Returns the PID, or None if the process table is full or OOM.
pub(crate) fn spawn(entry_point: fn() -> !) -> Option<Pid> {
    // SAFETY: current process PCB pointer is valid; set by the scheduler on
    // context switch. addr_of_mut! is used throughout to avoid creating
    // references to static mut globals, satisfying Rust's aliasing rules.
    unsafe {
        // Find a free slot
        let procs = &mut *addr_of_mut!(PROCS);
        let slot = procs.iter().position(|p| p.is_none())?;
        let pid = slot as Pid;

        // Allocate new address space cloned FROM kernel table
        let new_pt = mmu::alloc_addr_space()?;
        mmu::clone_addr_space(mmu::table_base(), new_pt);

        // Allocate stack
        // WHY array-tracked (#251): page::alloc_page() is a bitmap scanner
        // with no contiguity guarantee; an OOM rollback that assumes
        // `stack_base + j * PAGE_SIZE` names the j-th allocated page can free
        // an unrelated live page. Recording each returned address makes the
        // rollback exact regardless of fragmentation.
        let mut stack_pages_alloc: [usize; STACK_PAGES] = [0; STACK_PAGES];
        for i in 0..STACK_PAGES {
            match page::alloc_page() {
                Some(page) => stack_pages_alloc[i] = page,
                None => {
                    // OOM: roll back exactly the pages allocated so far.
                    for j in 0..i {
                        page::free_page(stack_pages_alloc[j]);
                    }
                    mmu::free_addr_space(new_pt);
                    return None;
                }
            }
        }
        let stack_base = stack_pages_alloc[0];
        let stack_top = stack_base + page::PAGE_SIZE * STACK_PAGES;

        // Set up initial context. First context switch exception-returns to
        // `entry` in System mode (0x1F, PL1, IRQs enabled) on the fresh stack.
        let ctx = Context::initial(entry_point as u32, stack_top as u32, 0x1F);

        let parent_pid = CURRENT;
        let proc = Process {
            pid,
            state: State::Ready,
            ctx,
            parent: Some(parent_pid),
            exit_status: 0,
            page_table_phys: new_pt,
            stack_base,
            stack_pages: STACK_PAGES,
            heap_break: DEFAULT_HEAP_BREAK,
            mappings: [None; MAX_MAPPINGS],
            signal_state: SignalState::new(),
            uid: 1, // spawned userspace processes get UID 1+
            wake_tick: 0,
            // Spawned processes receive the default fork policy (REQ-09).
            capabilities: crate::capability::Capabilities::FORK_DEFAULT,
            fds: crate::fd::FdTable::new(),
            cwd: crate::fd::DEFAULT_CWD,
            cwd_len: 1,
        };

        procs[slot] = Some(proc);
        Some(pid)
    }
}

/// Map a loaded ELF's `PT_LOAD` segments PL0-accessible at their identity VAs in
/// process page table `pt`, with W^X page permissions from each segment's ELF
/// flags (#482): text RX, rodata RO+XN, data/bss RW+XN. Fails closed on an
/// unaligned segment vaddr (a page would carry two permission classes) or
/// L2-pool exhaustion.
///
/// # Safety
/// `pt` must be a caller-owned process L1 not currently live in TTBR0.
unsafe fn map_user_image(pt: usize, loaded: &crate::elf::LoadedElf) -> bool {
    for &(vaddr, memsz, flags) in loaded.segments() {
        // INVARIANT: init.ld ALIGN(4096) page-aligns each permission class, so
        // a segment vaddr must be page-aligned; reject a foreign image that
        // violates it rather than granting a mixed-permission page.
        if vaddr % page::PAGE_SIZE != 0 {
            return false;
        }
        let attrs = mmu::prot_to_l2_flags(crate::elf::flags_to_prot(flags));
        let pages = memsz.div_ceil(page::PAGE_SIZE);
        for p in 0..pages {
            let va = vaddr + p * page::PAGE_SIZE;
            // #502: map va -> the process's OWN image frame, not identity.
            // load_confined wrote the segment bytes to
            // image_phys + (vaddr - image_lo); the mapping MUST use the same
            // base (single source of truth) so the process reads what was
            // written. va >= vaddr >= image_lo, so the offset never underflows.
            let phys = loaded.image_phys + (va - loaded.image_lo);
            // SAFETY: pt is caller-owned; phys is the freshly-allocated image
            // frame (arm) or identity (host). Shatter the MB to a
            // fully-populated L2, then grant PL0 to this page.
            unsafe {
                if !mmu::shatter_section(pt, va) || !mmu::map_page(pt, va, phys, attrs) {
                    return false;
                }
            }
        }
    }
    true
}

/// Map `pages` contiguous stack frames from `stack_base` PL0 read/write +
/// execute-never at their identity VAs (#482/#489).
///
/// # Safety
/// `pt` is a caller-owned process L1; `stack_base` begins a contiguous run.
unsafe fn map_user_stack(pt: usize, stack_base: usize, pages: usize) -> bool {
    let attrs = mmu::prot_to_l2_flags(mmu::prot::PROT_READ | mmu::prot::PROT_WRITE);
    for i in 0..pages {
        let va = stack_base + i * page::PAGE_SIZE;
        // SAFETY: pt caller-owned; va is a contiguous stack frame in DRAM.
        unsafe {
            if !mmu::shatter_section(pt, va) || !mmu::map_page(pt, va, va, attrs) {
                return false;
            }
        }
    }
    true
}

/// Map the per-process sigreturn trampoline page (#446): one fresh frame at
/// the fixed `SIGNAL_TRAMPOLINE_VA` slot with PL0 read+execute / PL1
/// read-write permissions, then the trampoline bytes written through the
/// kernel's identity mapping. Returns the frame's physical address for
/// rollback, or `None` on OOM / L2-pool exhaustion (already cleaned up).
///
/// WHY PL0-RX and not on-stack code: the user stack is RW+XN (#482 W^X), so
/// an on-stack trampoline prefetch-aborts when the handler returns into it
/// — the QEMU signal witness caught exactly that. The RX page survives exec
/// (it sits below USER_TEXT_BASE's rebuilt section), is deep-copied by fork,
/// and is reclaimed by exit's all-user-pages walk.
///
/// # Safety
/// `pt` is a caller-owned process L1 not currently live in TTBR0; the caller
/// runs under the kernel identity L1 (the trampoline write targets phys).
#[cfg(target_arch = "arm")]
unsafe fn map_signal_trampoline(pt: usize) -> Option<usize> {
    let phys = page::alloc_page()?;
    let attrs = mmu::prot_to_l2_flags(mmu::prot::PROT_READ | mmu::prot::PROT_EXEC);
    // SAFETY: pt caller-owned; SIGNAL_TRAMPOLINE_VA is the reserved slot
    // below USER_TEXT_BASE (signal.rs documents why nothing else maps there).
    unsafe {
        if !mmu::shatter_section(pt, crate::signal::SIGNAL_TRAMPOLINE_VA)
            || !mmu::map_page(pt, crate::signal::SIGNAL_TRAMPOLINE_VA, phys, attrs)
        {
            page::free_page(phys);
            return None;
        }
        crate::signal::write_trampoline_page(phys);
    }
    Some(phys)
}

/// No-op trampoline mapping for non-ARM (host test) builds: host page frames
/// are simulated addresses — never dereference-able — and fork's deep-copy
/// walk WOULD deref every user page's phys, so mapping a simulated frame
/// here segfaults the host fork tests. The `map_page/shatter` composition is
/// host-covered in mmu.rs's own tests; the real grant is covered end-to-end
/// by the QEMU signal witness. `Some(0)` keeps `spawn_user`'s rollback shape
/// (`free_page` validates allocator range, so 0 is a safe no-op there).
#[cfg(not(target_arch = "arm"))]
unsafe fn map_signal_trampoline(_pt: usize) -> Option<usize> {
    Some(0)
}

/// Drop the PL0 grant on `pages` frames from `base` in `pt`: rewrite each L2
/// entry back to the identity `KERNEL_DEFAULT_PAGE` (PL1-only, #489). NOT
/// `unmap_page` (zeroing an entry inside a shattered identity MB would fault the
/// kernel on its next access there), and NOT `reset_shattered_section` for a
/// stack (old and new exec stacks can share an allocator MB, so a whole-MB
/// reset would revoke the new stack's grants). The caller flushes the TLB.
///
/// # Safety
/// `pt` is a caller-owned L1; each VA was granted via `map_user_stack/image`.
unsafe fn revoke_user_pages(pt: usize, base: usize, pages: usize) {
    for i in 0..pages {
        let va = base + i * page::PAGE_SIZE;
        // SAFETY: the entry exists (was granted); update preserves the identity
        // phys and demotes attrs to PL1-only.
        unsafe {
            mmu::update_page_prot(pt, va, mmu::KERNEL_DEFAULT_PAGE);
        }
    }
}

/// Create a PL0 (User mode) process from a loaded ELF image (#482).
///
/// Like [`spawn`], but enters at cpsr 0x10 (User/PL0) and grants the process
/// PL0 access to EXACTLY its own image (per-segment W^X) and stack -- nothing
/// else. Kernel .text/.data/stacks and device MMIO stay mapped PL1-only via the
/// kernel-L1 clone (#323), so the kernel still runs when the process traps
/// (svc/IRQ) while the process data/prefetch-aborts on any access to kernel
/// memory. The #465 trap frame carries the per-process cpsr, so switching
/// between PID 0 (System) and a PL0 process needs no asm change.
/// Free the image frame `load_confined` allocated for an ELF that will NOT be
/// spawned (#502).
///
/// INVARIANT: the page table takes ownership of that frame only once
/// `map_user_image` succeeds -- after which exit's L2 walk reclaims it. EVERY
/// `spawn_user` failure return before that point must come through here, or the
/// run is orphaned for the rest of the boot: there is no PCB and no page table
/// left that could ever reclaim it.
///
/// WHY this matters now (#492): `spawn_user` used to be called only by kinit's
/// one-shot boot spawns, where a full process table / exhausted address-space
/// pool is not a realistic condition. The fault supervisor relaunches a
/// crash-looping service through the same path repeatedly, so a leak per
/// attempt is a real drain under pressure.
///
/// # Safety
///
/// `loaded.image_phys` must name the still-unmapped contiguous run
/// `load_confined` allocated, and the caller must run under the identity kernel
/// L1 (the zero-on-free writes through raw physical addresses).
unsafe fn free_unspawned_image(loaded: &crate::elf::LoadedElf) {
    if loaded.image_pages > 0 {
        // SAFETY: per this function's contract.
        unsafe { page::free_contiguous(loaded.image_phys, loaded.image_pages) };
    }
}

pub(crate) fn spawn_user(loaded: &crate::elf::LoadedElf) -> Option<Pid> {
    // SAFETY: PROCS/CURRENT via the established addr_of_mut! pattern; single
    // core, no concurrent access at spawn.
    unsafe {
        let procs = &mut *addr_of_mut!(PROCS);
        let Some(slot) = procs.iter().position(|p| p.is_none()) else {
            free_unspawned_image(loaded); // process table full
            return None;
        };
        let pid = slot as Pid;

        let Some(new_pt) = mmu::alloc_addr_space() else {
            free_unspawned_image(loaded); // address-space pool exhausted
            return None;
        };
        mmu::clone_addr_space(mmu::table_base(), new_pt);

        // Stack: a CONTIGUOUS run (#475) so stack_top arithmetic and
        // exit_cleanup's free loop (base + i*PAGE_SIZE) hold, and the PL0 stack
        // has no unmapped hole SP could descend into.
        let Some(stack_base) = page::alloc_contiguous(STACK_PAGES) else {
            free_unspawned_image(loaded);
            mmu::free_addr_space(new_pt);
            return None;
        };
        let stack_top = stack_base + page::PAGE_SIZE * STACK_PAGES;

        // #446: the sigreturn trampoline page (PL0-RX) every signal delivery
        // returns through. Mapped before image+stack so a failure anywhere
        // below has one uniform rollback.
        let tramp_phys = map_signal_trampoline(new_pt);

        if tramp_phys.is_none()
            || !map_user_image(new_pt, loaded)
            || !map_user_stack(new_pt, stack_base, STACK_PAGES)
        {
            if let Some(phys) = tramp_phys {
                page::free_page(phys);
            }
            // free_addr_space also reclaims the L2 tables the shatters allocated
            // (the shared KERNEL_L2 is skipped -- free_l2_table no-ops on
            // non-pool addresses).
            free_unspawned_image(loaded);
            page::free_contiguous(stack_base, STACK_PAGES);
            mmu::free_addr_space(new_pt);
            return None;
        }

        // 0x10 = User mode (PL0), IRQs enabled; T-bit from the entry LSB.
        let ctx = Context::initial(loaded.entry as u32, stack_top as u32, 0x10);

        let proc = Process {
            pid,
            state: State::Ready,
            ctx,
            parent: Some(CURRENT),
            exit_status: 0,
            page_table_phys: new_pt,
            stack_base,
            stack_pages: STACK_PAGES,
            heap_break: DEFAULT_HEAP_BREAK,
            mappings: [None; MAX_MAPPINGS],
            signal_state: SignalState::new(),
            uid: 1,
            wake_tick: 0,
            capabilities: crate::capability::Capabilities::FORK_DEFAULT,
            fds: crate::fd::FdTable::new(),
            cwd: crate::fd::DEFAULT_CWD,
            cwd_len: 1,
        };
        procs[slot] = Some(proc);
        Some(pid)
    }
}

/// Free every PL0-mapped frame of `pt` back to the allocator (#478).
///
/// `try_free_page`'s own validation makes this exact: a `spawn_user` image at
/// `USER_TEXT_BASE` lies OUTSIDE the allocator range (kinit passes `USER_TEXT_BASE`
/// as the upper bound) and is rejected as a no-op, while fork-copied image
/// pages, stack backing, and heap/mmap frames are allocator pages freed exactly
/// once. Ownership derives from the page table, not a separate record.
///
/// # Safety
/// `pt` is a valid L1; the current TTBR0 must be the KERNEL table (`try_free_page`
/// zeroes the frame through the live TTBR0, so a user-remapped VA would alias).
unsafe fn free_user_pages(pt: usize) {
    // SAFETY: caller guarantees pt valid + kernel TTBR0; try_free_page validates
    // each frame (out-of-range / not-allocated = no-op false).
    unsafe {
        mmu::for_each_user_page(pt, |_va, phys, _attrs| {
            let _ = page::try_free_page(phys); // WHY: bool no-op on a non-allocator/already-free frame; fire-and-forget by design
            true
        });
    }
}

/// Deep-copy every PL0 page of `parent_pt` into `child_pt`: a fresh frame, the
/// parent's content copied, mapped at the SAME VA with the SAME attributes
/// (#478). Returns false (with exact rollback) on OOM, a non-DRAM user page, or
/// L2-pool exhaustion.
///
/// Runs under the KERNEL address space: fork executes with the parent's TTBR0
/// live, where an allocator page's physical address can alias a VA the parent
/// (a forked ancestor) user-remapped -- a raw phys write through such a VA would
/// corrupt live memory. The kernel L1 maps all DRAM identity with no user
/// remaps, so phys == VA holds for every access here, including the zero-on-free
/// inside the rollback. IRQs are masked for the whole SVC, so the window is
/// atomic.
///
/// # Safety
/// Trap context (IRQs masked); `parent_pt` valid + live; `child_pt` a fresh
/// kernel-clone not yet live in TTBR0.
unsafe fn fork_copy_phase(parent_pt: usize, child_pt: usize) -> bool {
    // SAFETY: see the doc invariants; all page-table/frame ops are validated.
    unsafe {
        mmu::switch_addr_space(mmu::table_base());
        let ok = mmu::for_each_user_page(parent_pt, |va, parent_phys, attrs| {
            // Fail closed: only DRAM-backed user pages are copyable. A
            // device-mapped user page has no copy semantics -- refuse the whole
            // fork rather than share or skip it.
            if !(crate::board::RAM_START..crate::board::RAM_END).contains(&parent_phys) {
                return false;
            }
            let Some(child_page) = page::alloc_page() else {
                return false;
            };
            // WHY(arm-only): host "phys" values are bitmap fictions, never valid
            // host pointers (same gating as the #208 stack copy). On ARM both
            // sides are identity DRAM under the kernel L1.
            #[cfg(target_arch = "arm")]
            core::ptr::copy_nonoverlapping(
                parent_phys as *const u8,
                child_page as *mut u8,
                page::PAGE_SIZE,
            );
            // #498: the D-side copy above can leave a stale I-cache line at
            // child_page on real hardware for an executable page (XN unset).
            // child_page is a kernel-identity VA under the table just
            // switched to above, so it is valid to sync here. Calling
            // unconditionally: sync_icache_range no-ops on non-ARM builds
            // (child_page is a host bitmap fiction there, same as the
            // gated copy above, but the no-op never dereferences it).
            if attrs & mmu::page_flags::XN == 0 {
                mmu::sync_icache_range(child_page, page::PAGE_SIZE);
            }
            if !mmu::shatter_section(child_pt, va)
                || !mmu::map_page(child_pt, va, child_page, attrs)
            {
                // Not yet recorded in child_pt's L2 -- free inline; the walk
                // rollback below covers the pages already mapped.
                page::free_page(child_page);
                return false;
            }
            true
        });
        if !ok {
            // Exact rollback needs no tracking array: every allocated page was
            // mapped into child_pt immediately, so the child's own L2 entries
            // ARE the allocation record. Still under the kernel map.
            free_user_pages(child_pt);
        }
        mmu::switch_addr_space(parent_pt);
        ok
    }
}

/// The PL0 (userspace) fork path (#478): a fresh isolated address space with the
/// parent's user pages DEEP-COPIED (fresh frames, content copied, same VA + same
/// W^X attrs). Never shares the parent's L2 tables.
///
/// # Safety
/// Trap context; `procs`/`slot`/`parent_pid` valid; `parent_pt` is the parent's
/// live L1; `child_ctx` seeded from the trap frame with r0 = 0.
unsafe fn fork_pl0(
    procs: &mut [Option<Process>; MAX_PROCS],
    slot: usize,
    child_pid: Pid,
    parent_pid: Pid,
    parent_pt: usize,
    child_ctx: Context,
) -> Option<Pid> {
    // SAFETY: delegated to fork_copy_phase / mmu; procs indexing is bounded.
    unsafe {
        // A PL0 process must own its L1 (spawn_user gives it one); a User-mode
        // frame without a per-process table is an invariant break.
        if parent_pt == 0 || parent_pt == mmu::table_base() {
            return None;
        }
        let child_pt = mmu::alloc_addr_space()?;
        // KERNEL entries only, like spawn_user -- NOT the parent's user L2
        // pointers (which the shallow clone would alias).
        mmu::clone_addr_space(mmu::table_base(), child_pt);
        if !fork_copy_phase(parent_pt, child_pt) {
            mmu::free_addr_space(child_pt); // reclaims the child's shatter L2s
            return None;
        }
        let parent_ref = procs[usize::from(parent_pid)].as_ref();
        // stack_base/stack_pages are the STACK VA RANGE (== the parent's -- same
        // VA, different phys); the backing frames live only in the child's L2
        // entries and are freed by exit_cleanup's table walk, never by identity.
        let child = Process {
            pid: child_pid,
            state: State::Ready,
            ctx: child_ctx,
            parent: Some(parent_pid),
            exit_status: 0,
            page_table_phys: child_pt,
            stack_base: parent_ref.map_or(0, |p| p.stack_base),
            stack_pages: parent_ref.map_or(0, |p| p.stack_pages),
            heap_break: parent_ref.map_or(DEFAULT_HEAP_BREAK, |p| p.heap_break),
            mappings: parent_ref.map_or([None; MAX_MAPPINGS], |p| p.mappings),
            signal_state: parent_ref.map_or(SignalState::new(), |p| {
                let mut s = p.signal_state;
                s.pending = 0; // POSIX: child starts with a clean pending mask
                s
            }),
            uid: parent_ref.map_or(1, |p| p.uid),
            wake_tick: 0,
            capabilities: parent_ref.map_or(crate::capability::Capabilities::FORK_DEFAULT, |p| {
                p.capabilities
            }) & crate::capability::Capabilities::FORK_DEFAULT,
            fds: parent_ref.map_or_else(crate::fd::FdTable::new, |p| crate::fd::fork_table(&p.fds)),
            cwd: parent_ref.map_or(crate::fd::DEFAULT_CWD, |p| p.cwd),
            cwd_len: parent_ref.map_or(1, |p| p.cwd_len),
        };
        procs[slot] = Some(child);
        Some(child_pid)
    }
}

/// Create a child process (POSIX fork).
///
/// A PL0 (userspace) parent gets a fresh ISOLATED address space with its user
/// pages deep-copied (#478, `fork_pl0`). A PL1 parent (PID 0 / spawn kernel
/// threads / host tests) takes the legacy path: shallow L1 clone + fresh
/// translated stack (correct because kernel threads share the kernel identity
/// map and their stacks are sections, not L2 mappings).
///
/// NOTE: unlike POSIX `fork()`, both parent and child continue FROM the next
/// scheduler tick; the child resumes at the fork return (its ctx is seeded from
/// the live trap frame) with r0 = 0, the parent with r0 = `child_pid`.
pub(crate) fn fork() -> Option<Pid> {
    // SAFETY: current process PCB pointer is valid; set by the scheduler on
    // context switch. addr_of_mut! avoids intermediate references to static mut.
    // Page table manipulation is safe because mmu functions validate their inputs.
    unsafe {
        let procs = &mut *addr_of_mut!(PROCS);

        // Find a free process slot
        let slot = procs.iter().position(|p| p.is_none())?;
        let child_pid = slot as Pid;
        let parent_pid = CURRENT;

        let parent_ref0 = procs[usize::from(parent_pid)].as_ref();
        let parent_pt = parent_ref0.map_or(0, |p| p.page_table_phys);
        let parent_pcb_ctx = parent_ref0.map(|p| p.ctx).unwrap_or_else(Context::zero);

        // #478: seed the child from the LIVE trap frame (the in-flight fork
        // SVC), not the PCB's stale switch-OUT snapshot; the child resumes at
        // the fork return with r0 = 0. The parent's r0 (= child_pid) is written
        // by svc_handler_rust after dispatch returns -- fork never switch_to's,
        // so FRAME_SWITCHED stays false. The saved cpsr mode is the path
        // selector: User (0x10) => PL0 deep-copy, else legacy PL1.
        let mut child_ctx = active_frame_ctx_or(parent_pcb_ctx);
        child_ctx.r[0] = 0;

        if child_ctx.cpsr & CPSR_MODE_MASK == CPSR_MODE_USER {
            return fork_pl0(procs, slot, child_pid, parent_pid, parent_pt, child_ctx);
        }

        // === PL1 legacy path (PID 0 / spawn kernel threads / host tests) ===
        // Kernel threads share the kernel identity map; their stacks are 1 MB
        // sections, invisible to the user-page walk, so a shallow clone + fresh
        // translated stack is correct for them.

        // Allocate child address space
        let child_pt = mmu::alloc_addr_space()?;

        // Clone parent mappings INTO child (use kernel table as base if parent has none)
        let src_pt = if parent_pt == 0 {
            mmu::table_base()
        } else {
            parent_pt
        };
        mmu::clone_addr_space(src_pt, child_pt);

        // Allocate child stack pages
        // WHY array-tracked (#251): page::alloc_page() is a bitmap scanner
        // with no contiguity guarantee; an OOM rollback that assumes
        // `stack_base + j * PAGE_SIZE` names the j-th allocated page can free
        // an unrelated live page. Recording each returned address makes the
        // rollback exact regardless of fragmentation. #208 fixed only the
        // SUCCESS path (translated sp + stack image copy); its rollback still
        // assumed contiguity.
        let mut child_stack_pages_alloc: [usize; STACK_PAGES] = [0; STACK_PAGES];
        for i in 0..STACK_PAGES {
            match page::alloc_page() {
                Some(page) => child_stack_pages_alloc[i] = page,
                None => {
                    // OOM: roll back exactly the pages allocated so far, then
                    // the child's address space.
                    for j in 0..i {
                        page::free_page(child_stack_pages_alloc[j]);
                    }
                    mmu::free_addr_space(child_pt);
                    return None;
                }
            }
        }
        let stack_base = child_stack_pages_alloc[0];

        // Inherit parent memory layout (child_ctx is already seeded from the
        // trap frame above -- for a real PL1 fork, i.e. host tests, no frame is
        // installed, so child_ctx == the parent's PCB ctx).
        let parent_ref = procs[usize::from(parent_pid)].as_ref();
        let parent_break = parent_ref.map_or(DEFAULT_HEAP_BREAK, |p| p.heap_break);

        // WHY(#208): the child MUST run on its OWN freshly-allocated stack, not
        // the parent's. Inheriting the parent's saved context verbatim would
        // leave ctx.sp pointing into the PARENT's stack, so the child would
        // corrupt the parent as soon as it ran, while exit_cleanup freed the
        // untouched `stack_base` pages instead of the ones the child ran on.
        // Retarget ctx.sp into the child's stack, preserving the parent's
        // offset-within-stack so the child resumes at the equivalent frame.
        // NOTE: the child stack needs no explicit page mapping — DRAM is
        // identity-mapped as 1 MB L1 sections (see mmu::init_and_enable), which
        // the cloned address space inherits; map_page would in fact refuse to
        // overlay a section descriptor. Isolation is by distinct sp + distinct
        // physical pages, matching how spawn() sets up kernel-thread stacks.
        let parent_stack_base = parent_ref.map_or(0, |p| p.stack_base);
        let parent_stack_pages = parent_ref.map_or(0, |p| p.stack_pages);
        child_ctx.sp = translate_stack_pointer(
            child_ctx.sp,
            parent_stack_base,
            parent_stack_pages,
            stack_base,
        );

        // WHY(#208): clone_addr_space copies only L1 page-table entries, never
        // the stack's backing RAM, so the child's freshly allocated pages are
        // uninitialised. Copy the parent's live stack image into them so the
        // translated sp lands on the SAME frame the parent had, not on garbage.
        // Only meaningful when the parent owns a real stack (PID 0 runs on the
        // boot stack with stack_pages == 0 — nothing to copy).
        // WHY(arm-only): on the host, stack_base is a bitmap-allocator physical
        // address that is never a valid host pointer; the context switch is a
        // no-op stub there, so the child is never resumed and the copy is both
        // unnecessary and unsound. On ARM these are identity-mapped DRAM.
        // SAFETY: parent_stack_base and stack_base are distinct, page-aligned
        // physical addresses of STACK_PAGES identity-mapped DRAM pages each
        // (separate allocations — no overlap). The length is clamped to the
        // child's stack so the copy never runs past its freshly allocated pages.
        // Executes inside fork()'s outer `unsafe` block (like page::free_page /
        // clone_addr_space above).
        #[cfg(target_arch = "arm")]
        if parent_stack_pages > 0 {
            core::ptr::copy_nonoverlapping(
                parent_stack_base as *const u8,
                stack_base as *mut u8,
                parent_stack_pages.min(STACK_PAGES) * page::PAGE_SIZE,
            );
        }

        let parent_mappings = parent_ref.map_or([None; MAX_MAPPINGS], |p| p.mappings);
        // WHY: children inherit signal handlers from parent (POSIX fork semantics).
        // Pending signals are NOT inherited — the child starts with a clean pending mask.
        let parent_signal_handlers = parent_ref.map_or(SignalState::new(), |p| {
            let mut s = p.signal_state;
            s.pending = 0; // clear pending — child starts clean
            s
        });

        let parent_uid = parent_ref.map_or(1, |p| p.uid);

        // WHY: forked children receive a policy-defined capability subset of the
        // parent. The default policy strips MODEM and AUDIT from the parent's set
        // rather than blindly inheriting ALL, so that baseline userspace processes
        // cannot access the baseband or audit log without an explicit grant (REQ-09).
        let parent_caps = parent_ref.map_or(crate::capability::Capabilities::FORK_DEFAULT, |p| {
            p.capabilities
        });
        let child_caps = parent_caps & crate::capability::Capabilities::FORK_DEFAULT;

        // #267: the child gets a COPY of the parent's fd table -- the same
        // OFD references with refcounts bumped -- NOT a shared index space.
        let child_fds =
            parent_ref.map_or_else(crate::fd::FdTable::new, |p| crate::fd::fork_table(&p.fds));

        let child = Process {
            pid: child_pid,
            state: State::Ready,
            ctx: child_ctx,
            parent: Some(parent_pid),
            exit_status: 0,
            page_table_phys: child_pt,
            stack_base,
            stack_pages: STACK_PAGES,
            heap_break: parent_break,
            mappings: parent_mappings,
            signal_state: parent_signal_handlers,
            uid: parent_uid,
            wake_tick: 0,
            capabilities: child_caps,
            fds: child_fds,
            cwd: parent_ref.map_or(crate::fd::DEFAULT_CWD, |p| p.cwd),
            cwd_len: parent_ref.map_or(1, |p| p.cwd_len),
        };

        procs[slot] = Some(child);
        Some(child_pid)
    }
}

/// Retarget a saved stack pointer FROM the parent's stack region INTO the
/// child's freshly-allocated stack, preserving the offset-within-stack.
///
/// WHY(#208): `fork()` inherits the parent's saved context so the child resumes
/// at the equivalent call frame, but the child must run on its OWN stack. This
/// maps `parent_sp` (an offset within the parent's stack) to the same offset
/// within the child's stack. If `parent_sp` does not lie inside the parent's
/// stack region — e.g. PID 0 / kinit runs on the boot stack with
/// `parent_stack_pages == 0`, or an exec'd image resized its stack — the child
/// starts at the base of its fresh stack.
///
/// INVARIANT: the result always lies in
/// `[child_stack_base, child_stack_base + STACK_PAGES * PAGE_SIZE)`, so the
/// child never aliases the parent's stack and `exit_cleanup` frees exactly the
/// pages that back the returned sp.
fn translate_stack_pointer(
    parent_sp: u32,
    parent_stack_base: usize,
    parent_stack_pages: usize,
    child_stack_base: usize,
) -> u32 {
    let child_stack_size = (STACK_PAGES * page::PAGE_SIZE) as u32;
    let parent_base = parent_stack_base as u32;
    let parent_span = (parent_stack_pages * page::PAGE_SIZE) as u32;
    let child_base = child_stack_base as u32;

    if parent_stack_pages > 0 && parent_sp >= parent_base {
        let offset = parent_sp - parent_base;
        // The offset must name a location inside BOTH the parent's stack (so it
        // is a real translated frame) and the child's stack (so the invariant
        // holds). Child stacks are STACK_PAGES; a same-sized parent makes these
        // two bounds identical.
        if offset < parent_span && offset < child_stack_size {
            return child_base + offset;
        }
    }
    child_base
}

/// Non-blocking wait for a child exit status.
/// Returns Some(status) if the child is Dead, None if still running or not a
/// child. Reaps the child's process-table slot on success (#218, #224): once
/// the parent has collected the exit status the slot is returned to the free
/// pool, matching POSIX wait semantics, so a Dead-but-unreaped PCB does not
/// permanently occupy a process-table slot.
pub(crate) fn waitpid(child_pid: Pid) -> Option<i32> {
    // SAFETY: current process PCB pointer is valid; set by the scheduler on
    // context switch. A single mutable borrow covers both the read (exit
    // status, parent check) and the reap (clearing the slot) so no
    // immutable/mutable aliasing of the static PROCS table occurs.
    unsafe {
        // #232: bound-check before indexing the fixed-size table — child_pid
        // is a userspace-controlled value with no upper-bound guarantee.
        let idx = usize::from(child_pid);
        if idx >= MAX_PROCS {
            return None;
        }
        let procs = &mut *addr_of_mut!(PROCS);
        let child = procs[idx].as_ref()?;
        // INVARIANT: only the direct parent may retrieve the exit status.
        if child.parent != Some(CURRENT) {
            return None;
        }
        if child.state != State::Dead {
            return None;
        }
        let status = child.exit_status;
        procs[idx] = None; // reap (#218/#224)
        Some(status)
    }
}

/// Reap every Dead child of the CURRENT process, returning each PCB slot to the
/// free pool; returns the count reaped.
///
/// WHY (#491 review): a fault-killed process is marked Dead by the abort
/// handler (`fault_exit_current`), but its PCB slot is only reclaimed by waitpid,
/// which is otherwise reachable only via the SVC Waitpid syscall. The kardia
/// service loop (PID 0, the parent of every spawned process) calls this each
/// tick so a fault-killed slot does not leak -- without it the process table
/// monotonically exhausts at `MAX_PROCS` after repeated user faults, and every
/// subsequent spawn/fork silently fails while the kernel still appears alive.
/// Scan-based (not fault-inbox-driven) so it reaps every Dead child even if the
/// fault notification was dropped on a full inbox, and without consuming any
/// non-fault IPC a userspace process may have sent PID 0.
pub(crate) fn reap_dead_children() -> usize {
    let mut reaped = 0;
    for pid in 0..MAX_PROCS {
        // waitpid reaps only a Dead child of CURRENT; live/non-child PIDs (and
        // PID 0 itself, whose parent is None) return None and are skipped.
        // MAX_PROCS (16) fits Pid (u8), so the cast is total.
        if let Ok(p) = Pid::try_from(pid) {
            if waitpid(p).is_some() {
                reaped += 1;
            }
        }
    }
    reaped
}

/// Notify PID 0 that process `faulting_pid` has faulted.
///
/// Marks the faulting process Dead (releasing its fds) and pushes a
/// [`crate::supervisor::FaultReport`] onto the dedicated fault ring, which the
/// service loop drains once per tick: it audit-logs every report and applies the
/// restart policy to a supervised service (#492).
///
/// WHY the ring and not PID 0's IPC inbox (#492): the old protocol
/// `ipc::send(0, ..)`-ed a 9-byte payload that NOTHING ever drained, so reports
/// accumulated until the inbox filled -- after which both the reports and any
/// legitimate userspace `send(0, ..)` were rejected. Draining the inbox instead
/// is not an option: `ipc::recv` pops the FRONT regardless of tag, so it would
/// discard real user->PID0 IPC. A separate channel is what makes the drain safe,
/// and it removes the `CURRENT`-swap this function needed only so `ipc::send`
/// would stamp the faulting pid as the sender.
pub(crate) fn notify_fault(faulting_pid: Pid, kind: FaultKind) {
    let (tag, fault_addr, fault_status) = match kind {
        FaultKind::DataAbort {
            fault_addr,
            fault_status,
        } => (1u8, fault_addr, fault_status),
        FaultKind::PrefetchAbort {
            fault_addr,
            fault_status,
        } => (2u8, fault_addr, fault_status),
        FaultKind::UndefinedInstruction => (3u8, 0u32, 0u32),
    };

    // SAFETY: the PCB table is only mutated from kernel mode on this single-core
    // kernel, and this runs in abort context with IRQs masked.
    unsafe {
        let procs = &mut *addr_of_mut!(PROCS);
        if let Some(ref mut proc) = procs[usize::from(faulting_pid)] {
            proc.state = State::Dead;
            // #267: a faulted process never reaches exit_cleanup -- release
            // its fds here so OFDs (and pipe/socket ends) do not leak.
            crate::fd::close_all(&mut proc.fds);
        }
    }

    // A full ring drops the report (and says so on the UART); the scan-based
    // reaper still reclaims the slot, so only the notification is lost.
    crate::supervisor::report_fault(faulting_pid, tag, fault_addr, fault_status);
}

/// Perform exit teardown without the diverging `-> !` signature.
/// Marks the process Dead, reclaims its page table, and frees stack pages.
pub(crate) fn exit_cleanup(status: i32) {
    // #492: this pid is about to be reusable -- drop any supervised claim on it,
    // so a service that exits CLEANLY (and therefore files no fault report) does
    // not leave a stale pid an unrelated process could inherit and alias into a
    // spurious restart. A fault-exit reaches here too, but `report_fault` already
    // released the claim in abort context, so this is a no-op on that path.
    crate::supervisor::clear_pid(current_pid());
    // SAFETY: current process PCB pointer is valid; set by the scheduler on
    // context switch. Page table and stack pages are reclaimed only after
    // marking the process Dead; mmu::free_addr_space validates its input.
    unsafe {
        // WHY (#478): every free below may zero the frame through the CURRENT
        // TTBR0 (page.rs zero-on-free); a forked child's table user-remaps
        // allocator-range VAs, so a raw phys write could alias another
        // process's memory. The kernel L1 maps all DRAM identity with no user
        // remaps, so we tear down under it; switch_to installs the successor's
        // table afterward, and only kernel memory is touched in between. (This
        // supersedes fault_exit_current's freed-L1-while-live note -- we no
        // longer run teardown on the dying process's own table.)
        mmu::switch_addr_space(mmu::table_base());
        let cur = usize::from(CURRENT);
        let procs = &mut *addr_of_mut!(PROCS);
        if let Some(ref mut proc) = procs[cur] {
            proc.exit_status = status;
            proc.state = State::Dead;

            // #267: close-on-exit is mandatory -- drop every fd reference,
            // releasing shared OFDs (and pipe/socket ends) at refcount zero.
            crate::fd::close_all(&mut proc.fds);

            let pt = proc.page_table_phys;
            let own_table = pt != 0 && pt != mmu::table_base();
            // WHY (#478): a PL0 process's memory is exactly what its table maps
            // PL0 -- image copies, stack backing, heap/mmap frames. The table
            // is the ownership record; walk it to free those frames (also
            // retires the old exit leak of heap/mmap frames, which
            // free_addr_space reclaimed the L2 TABLES of but not their backing).
            // A stack that is L2-backed (a PL0 process, incl. a forked child
            // whose stack VA's identity phys belongs to an ANCESTOR) must NOT
            // be freed by the identity loop below -- the walk already freed its
            // real frames.
            let stack_l2_backed = own_table
                && mmu::read_l2_entry(pt, proc.stack_base).is_some_and(mmu::l2_entry_is_user);
            if own_table {
                free_user_pages(pt);
                mmu::free_addr_space(pt);
            }
            proc.page_table_phys = 0;

            // Free stack pages -- identity-stack (PL1) processes only. A PL0
            // stack's frames were freed by the walk above.
            let base = proc.stack_base;
            let pages = proc.stack_pages;
            proc.stack_pages = 0;
            if !stack_l2_backed {
                for i in 0..pages {
                    page::free_page(base + i * page::PAGE_SIZE);
                }
            }
        }
        // WHY: a self-exiting process cannot itself be blocked in
        // sys_futex_wait (blocked processes do not run), but sweep
        // defensively so every Dead-transition path shares the same
        // invariant (#364).
        crate::futex::free_waiters_for_pid(u32::from(CURRENT));
        // WHY (finding 45): clear this PID's inbox at exit teardown so a
        // future process that reuses the slot does not inherit messages
        // left behind by the previous occupant (PID-reuse leak).
        ipc::clear_inbox(CURRENT);
    }
}

/// Exit the current process from SYSCALL context (#465): tear it down, switch
/// the trap frame to the next process, and RETURN so the SVC stub's exception
/// return resumes the successor. Returns the (ignored) syscall return value.
///
/// WHY not `-> !` + wfi: the SVC handler runs with IRQs masked, so an in-handler
/// wfi loop never takes the timer IRQ -- it would deadlock. Exit must UNWIND
/// the SVC stack (like Yield) so the frame swap takes effect.
pub(crate) fn exit_current(status: i32) -> u32 {
    exit_cleanup(status);
    let next = schedule();
    if next != current_pid() {
        // SAFETY: trap context; the now-Dead PCB harmlessly absorbs the
        // frame save, and the successor's context loads into the trap frame.
        unsafe { switch_to(next) };
        return 0;
    }
    // Unreachable by design: PID 0 (the service loop) never exits and is Ready
    // whenever it is not CURRENT, so a non-PID-0 exit always finds a successor.
    // Defensive fallback: restore the kernel address space, unmask IRQs so the
    // timer keeps running, and park.
    #[cfg(target_arch = "arm")]
    // SAFETY: the process is Dead and freed; parking with IRQs live is safe.
    unsafe {
        mmu::switch_addr_space(mmu::table_base());
        core::arch::asm!("cpsie i");
        loop {
            core::arch::asm!("wfi");
        }
    }
    #[cfg(not(target_arch = "arm"))]
    0
}

/// Get the current process ID.
pub(crate) fn current_pid() -> Pid {
    // SAFETY: CURRENT is a static mut Pid written only by the scheduler and
    // notify_fault. Read is atomic on ARM (single word); no torn read possible.
    unsafe { CURRENT }
}

/// Count processes in Ready or Running state.
///
/// Used by the power governor to decide how many cores to keep active.
/// Called from the timer IRQ handler with interrupts disabled — safe to
/// read PROCS without a lock on single-core `ARMv7`.
pub(crate) fn runnable_count() -> usize {
    // SAFETY: called from timer IRQ handler (single-core, IRQs disabled).
    // addr_of! avoids an intermediate reference to the static mut.
    unsafe {
        let procs = &*core::ptr::addr_of!(PROCS);
        procs
            .iter()
            .flatten()
            .filter(|p| p.state == State::Ready || p.state == State::Running)
            .count()
    }
}

/// Simple round-robin scheduler. Called FROM the timer tick handler.
/// Returns the PID to switch to (may be the same as current).
///
/// Also wakes any Sleeping processes whose `wake_tick` has been reached,
/// transitioning them to Ready so they can be scheduled next tick.
pub(crate) fn schedule() -> Pid {
    // SAFETY: called from the timer IRQ handler with interrupts disabled on
    // a single-core ARMv7. PROCS is accessed exclusively via addr_of_mut!
    // to avoid intermediate references to the static mut.
    unsafe {
        let cur = usize::from(CURRENT);
        let procs = &mut *addr_of_mut!(PROCS);

        // First pass: wake any sleeping processes whose timer has elapsed.
        // WHY: we import exceptions::ticks() lazily here to avoid a circular
        // dependency (exceptions imports process). We call it only during the
        // scheduler, which runs after exceptions is fully initialized.
        let now = crate::exceptions::ticks();
        for slot in procs.iter_mut().flatten() {
            if slot.state == State::Sleeping && now >= slot.wake_tick {
                slot.state = State::Ready;
            }
        }

        // Second pass: round-robin among Ready processes.
        let procs_ro = &*core::ptr::addr_of!(PROCS);
        for offset in 1..MAX_PROCS {
            let idx = (cur + offset) % MAX_PROCS;
            if let Some(ref proc) = procs_ro[idx] {
                if proc.state == State::Ready {
                    return proc.pid;
                }
            }
        }
        // No other ready process  -  stay on current
        CURRENT
    }
}

/// The trap frame the exception stub built on the handler stack for the
/// in-flight exception, or null outside trap context (e.g. host tests).
///
/// WHY a single static is sound: exceptions never nest. ARM masks CPSR.I on
/// every exception entry, and no handler re-enables it (the only `cpsie` sites
/// are boot init and `IrqGuard`, which restores prior state), so at most one
/// trap frame is ever live.
static mut ACTIVE_FRAME: *mut Context = core::ptr::null_mut();

/// Set true by `switch_to` when it swaps the active frame to another process,
/// so the SVC handler knows not to clobber the successor's r0 with a return
/// value meant for the (switched-away) caller.
static mut FRAME_SWITCHED: bool = false;

/// Publish the in-flight trap frame. Called by the exception handlers before
/// dispatching; cleared by `trap_leave` after.
///
/// # Safety
/// `frame` must be the valid, unaliased Context the stub built for this trap.
pub(crate) unsafe fn trap_enter(frame: *mut Context) {
    // SAFETY: single-writer during a non-nesting trap.
    unsafe {
        ACTIVE_FRAME = frame;
        FRAME_SWITCHED = false;
    }
}

/// Clear the in-flight trap frame after the handler returns.
pub(crate) fn trap_leave() {
    // SAFETY: single-writer during a non-nesting trap.
    unsafe { ACTIVE_FRAME = core::ptr::null_mut() }
}

/// Did the current trap switch to a different process? If so the stub epilogue
/// will exception-return into the successor, and the SVC handler must not write
/// a return value into the (now successor's) frame.
pub(crate) fn trap_switched() -> bool {
    // SAFETY: read of a single word written only within this trap.
    unsafe { FRAME_SWITCHED }
}

/// The in-flight trap frame's register file, or `fallback` outside trap context
/// (#478). On ARM, fork is only reachable through the SVC trap, where
/// `trap_enter` published the frame; the fallback serves host tests that call
/// `fork()` without installing a mock frame.
fn active_frame_ctx_or(fallback: Context) -> Context {
    // SAFETY: ACTIVE_FRAME is null or the valid, unaliased in-flight frame; the
    // by-value copy does not alias.
    unsafe { ACTIVE_FRAME.as_ref().map_or(fallback, |f| *f) }
}

/// Deposit a syscall return value into the CURRENT process's live frame BEFORE
/// switching away, so that when this process is later resumed (its saved frame
/// exception-returns to the instruction after `svc`) it observes `val` in r0.
/// No-op outside trap context (host tests), where there is no frame.
pub(crate) fn set_trap_return(val: u32) {
    // SAFETY: ACTIVE_FRAME is either null or the valid in-flight frame.
    unsafe {
        if let Some(frame) = ACTIVE_FRAME.as_mut() {
            frame.r[0] = val;
        }
    }
}

/// Switch the active trap frame FROM the current process to `next_pid`: copy
/// the interrupted register file into the current PCB, load the next process's
/// saved context into the frame, and switch TTBR0. Control transfers when the
/// exception stub's epilogue reloads the frame and exception-returns, so
/// callers MUST unwind promptly after this (do not spin/WFI).
///
/// Serves BOTH the preemptive (timer IRQ) and cooperative (Yield/Exit/futex,
/// from SVC) paths -- both enter through an exception stub that established
/// `ACTIVE_FRAME`.
///
/// # Safety
/// Must be called from trap context (`ACTIVE_FRAME` live) with interrupts masked.
pub unsafe fn switch_to(next_pid: Pid) {
    // SAFETY: trap context; PROCS/CURRENT are accessed with interrupts masked
    // and no concurrent access on this single core.
    unsafe {
        let cur_pid = usize::from(CURRENT);
        let next = usize::from(next_pid);

        if cur_pid == next {
            return;
        }

        let frame = ACTIVE_FRAME;
        let procs = &mut *addr_of_mut!(PROCS);

        // Save the interrupted register file into the current PCB.
        if let Some(ref mut cur_proc) = procs[cur_pid] {
            if !frame.is_null() {
                cur_proc.ctx = *frame;
            }
            if cur_proc.state == State::Running {
                cur_proc.state = State::Ready;
            }
        }

        // Load the next process's context into the frame; the stub epilogue
        // exception-returns into it.
        if let Some(ref mut next_proc) = procs[next] {
            next_proc.state = State::Running;
            CURRENT = next_pid;
            // WHY: switch TTBR0 before the epilogue restores the new context.
            if next_proc.page_table_phys != 0 {
                mmu::switch_addr_space(next_proc.page_table_phys);
            }
            if !frame.is_null() {
                *frame = next_proc.ctx;
                FRAME_SWITCHED = true;
            }
        }
    }
}

// --- Memory management accessors ---
// WHY: syscall handlers need to read/modify the current process's heap break,
// page table, and mappings. These functions centralize access to the process
// table so syscall.rs doesn't need to manipulate PROCS directly.

/// Run `f` on the CURRENT process's fd table (#267). Returns None (fail
/// closed) when the current PCB slot is absent -- fd syscalls map that to
/// EBADF, matching the `current_uid()` posture (#282).
///
/// INVARIANT: `f` must not re-enter `process::` accessors -- PROCS is
/// mutably borrowed for the duration of the closure.
pub(crate) fn with_current_fds<R>(f: impl FnOnce(&mut crate::fd::FdTable) -> R) -> Option<R> {
    // SAFETY: current process PCB pointer is valid; set by the scheduler on
    // context switch. Mutation via addr_of_mut! avoids an intermediate
    // reference to the static mut; called from syscall context (single-core).
    unsafe {
        let procs = &mut *addr_of_mut!(PROCS);
        let cur = usize::from(CURRENT);
        procs[cur].as_mut().map(|p| f(&mut p.fds))
    }
}

/// Read the current process's working directory (#437). `f` receives the path
/// bytes (length `cwd_len`). Returns None when there is no current process.
///
/// INVARIANT: as `with_current_fds` — `f` must not re-enter `process::` accessors.
pub(crate) fn with_current_cwd<R>(f: impl FnOnce(&[u8]) -> R) -> Option<R> {
    // SAFETY: current process PCB pointer is valid; read-only access to the
    // current PCB's cwd via addr_of_mut! (no mutation of PROCS itself).
    unsafe {
        let procs = &mut *addr_of_mut!(PROCS);
        let cur = usize::from(CURRENT);
        procs[cur].as_ref().map(|p| f(&p.cwd[..p.cwd_len]))
    }
}

/// Set the current process's working directory (#437), truncating to `CWD_MAX`.
/// Returns None when there is no current process.
pub(crate) fn set_current_cwd(path: &str) -> Option<()> {
    // SAFETY: current process PCB pointer is valid; mutation via addr_of_mut!,
    // single-core syscall context.
    unsafe {
        let procs = &mut *addr_of_mut!(PROCS);
        let cur = usize::from(CURRENT);
        procs[cur].as_mut().map(|p| {
            let copy_len = path.len().min(crate::fd::CWD_MAX);
            p.cwd[..copy_len].copy_from_slice(&path.as_bytes()[..copy_len]);
            p.cwd_len = copy_len;
        })
    }
}

/// Get the current process's page table physical address.
/// Returns 0 if the current process is not found (should not happen).
pub(crate) fn current_page_table() -> usize {
    // SAFETY: current process PCB pointer is valid; set by the scheduler on
    // context switch. Read-only access via addr_of!; no mutation occurs here.
    unsafe {
        let procs = &*core::ptr::addr_of!(PROCS);
        let cur = usize::from(CURRENT);
        procs[cur].as_ref().map_or(0, |p| p.page_table_phys)
    }
}

/// Get the current process's heap break.
pub(crate) fn current_heap_break() -> usize {
    // SAFETY: current process PCB pointer is valid; set by the scheduler on
    // context switch. Read-only access via addr_of!; no mutation occurs here.
    unsafe {
        let procs = &*core::ptr::addr_of!(PROCS);
        let cur = usize::from(CURRENT);
        procs[cur]
            .as_ref()
            .map_or(DEFAULT_HEAP_BREAK, |p| p.heap_break)
    }
}

/// Set the current process's heap break.
pub(crate) fn set_heap_break(new_break: usize) {
    // SAFETY: current process PCB pointer is valid; set by the scheduler on
    // context switch. Mutation via addr_of_mut! avoids an intermediate
    // reference to the static mut; called from syscall context (single-core).
    unsafe {
        let procs = &mut *addr_of_mut!(PROCS);
        let cur = usize::from(CURRENT);
        if let Some(ref mut proc) = procs[cur] {
            proc.heap_break = new_break;
        }
    }
}

/// Find a free mapping slot in the current process and insert a new mapping.
/// Returns the index on success, None if all slots are full.
pub(crate) fn add_mapping(mapping: VmMapping) -> Option<usize> {
    // SAFETY: current process PCB pointer is valid; set by the scheduler on
    // context switch. Mutation via addr_of_mut!; called from syscall context.
    unsafe {
        let procs = &mut *addr_of_mut!(PROCS);
        let cur = usize::from(CURRENT);
        let proc = procs[cur].as_mut()?;
        let slot = proc.mappings.iter().position(|m| m.is_none())?;
        proc.mappings[slot] = Some(mapping);
        Some(slot)
    }
}

/// Remove a mapping that starts at the given address.
/// Returns the removed mapping, or None if not found.
pub(crate) fn remove_mapping(start_addr: usize) -> Option<VmMapping> {
    // SAFETY: current process PCB pointer is valid; set by the scheduler on
    // context switch. Mutation via addr_of_mut!; called from syscall context.
    unsafe {
        let procs = &mut *addr_of_mut!(PROCS);
        let cur = usize::from(CURRENT);
        let proc = procs[cur].as_mut()?;
        for slot in proc.mappings.iter_mut() {
            if let Some(m) = slot {
                if m.start == start_addr {
                    return slot.take();
                }
            }
        }
        None
    }
}

/// Find a mapping that starts at the given address.
/// Returns a copy of the mapping, or None if not found.
pub(crate) fn find_mapping(start_addr: usize) -> Option<VmMapping> {
    // SAFETY: current process PCB pointer is valid; set by the scheduler on
    // context switch. Read-only access via addr_of!; no mutation occurs here.
    unsafe {
        let procs = &*core::ptr::addr_of!(PROCS);
        let cur = usize::from(CURRENT);
        let proc = procs[cur].as_ref()?;
        for slot in &proc.mappings {
            if let Some(m) = slot {
                if m.start == start_addr {
                    return Some(*m);
                }
            }
        }
        None
    }
}

/// Update the protection flags on an existing mapping.
/// Returns true if the mapping was found and updated.
pub(crate) fn update_mapping_prot(start_addr: usize, new_prot: u32) -> bool {
    // SAFETY: current process PCB pointer is valid; set by the scheduler on
    // context switch. Mutation via addr_of_mut!; called from syscall context.
    unsafe {
        let procs = &mut *addr_of_mut!(PROCS);
        let cur = usize::from(CURRENT);
        let Some(proc) = procs[cur].as_mut() else {
            return false;
        };
        for slot in proc.mappings.iter_mut() {
            if let Some(m) = slot {
                if m.start == start_addr {
                    m.prot = new_prot;
                    return true;
                }
            }
        }
        false
    }
}

/// Get a snapshot of all active mappings for the current process.
/// Used by mmap to find free virtual address regions.
pub(crate) fn current_mappings() -> [Option<VmMapping>; MAX_MAPPINGS] {
    // SAFETY: current process PCB pointer is valid; set by the scheduler on
    // context switch. Read-only access via addr_of!; no mutation occurs here.
    unsafe {
        let procs = &*core::ptr::addr_of!(PROCS);
        let cur = usize::from(CURRENT);
        procs[cur]
            .as_ref()
            .map_or([None; MAX_MAPPINGS], |p| p.mappings)
    }
}

/// Get the current process's UID.
///
/// Returns `None` if the current process's PCB slot is absent -- this must
/// never silently resolve to UID 0 (root): a missing PCB is a scheduler
/// invariant violation, and treating it as root would grant full privilege
/// to whatever code path hit the gap (fail-open privilege escalation,
/// issue #282, process.rs).
pub(crate) fn current_uid() -> Option<u32> {
    // SAFETY: current process PCB pointer is valid; set by the scheduler on
    // context switch. Read-only access via addr_of!; no mutation occurs here.
    unsafe {
        let procs = &*core::ptr::addr_of!(PROCS);
        let cur = usize::from(CURRENT);
        procs[cur].as_ref().map(|p| p.uid)
    }
}

/// Get the current process's capability bitfield.
///
/// Returns `Capabilities::ALL` for PID 0 (kinit) and `Capabilities::FORK_DEFAULT`
/// as a safe fallback if the current PCB is unexpectedly absent.
/// Called by `capability::check` and `capability::has` (REQ-09).
pub(crate) fn current_capabilities() -> u32 {
    // SAFETY: current process PCB pointer is valid; set by the scheduler on
    // context switch. Read-only access via addr_of!; no mutation occurs here.
    unsafe {
        let procs = &*core::ptr::addr_of!(PROCS);
        let cur = usize::from(CURRENT);
        procs[cur]
            .as_ref()
            .map_or(crate::capability::Capabilities::FORK_DEFAULT, |p| {
                p.capabilities
            })
    }
}

/// Set the current process's `wake_tick` and transition it to Sleeping.
///
/// Called by `sys_nanosleep` after computing the target tick count.
/// The scheduler will transition this process back to Ready when
/// `exceptions::ticks() >= wake_tick`.
pub(crate) fn set_wake_tick(wake_tick: u64) {
    // SAFETY: called from syscall context (single-threaded; IRQs are disabled
    // during SVC on ARMv7). addr_of_mut! avoids an intermediate reference to
    // the static mut PROCS.
    unsafe {
        let procs = &mut *addr_of_mut!(PROCS);
        let cur = usize::from(CURRENT);
        if let Some(ref mut proc) = procs[cur] {
            proc.wake_tick = wake_tick;
            proc.state = State::Sleeping;
        }
    }
}

/// Clear the Sleeping state after the process wakes, transitioning to Running.
///
/// Called by `sys_nanosleep` after the busy-wait loop confirms the wake tick
/// has elapsed. Resets `wake_tick` to 0 and marks the process Running again.
pub(crate) fn clear_wake_tick() {
    // SAFETY: same as set_wake_tick — called from syscall context only.
    unsafe {
        let procs = &mut *addr_of_mut!(PROCS);
        let cur = usize::from(CURRENT);
        if let Some(ref mut proc) = procs[cur] {
            proc.wake_tick = 0;
            proc.state = State::Running;
        }
    }
}

// ---------------------------------------------------------------------------
// Signal accessors
// ---------------------------------------------------------------------------

/// Set the signal action for the current process.
///
/// # Safety
///
/// Must be called from syscall context (single-core, no preemption during SVC).
pub unsafe fn set_signal_action(sig: Signal, action: SignalAction) {
    unsafe {
        let procs = &mut *addr_of_mut!(PROCS);
        let cur = usize::from(CURRENT);
        if let Some(ref mut proc) = procs[cur] {
            proc.signal_state.set_action(sig, action);
        }
    }
}

/// Get the signal action for the current process.
///
/// # Safety
///
/// Must be called from a context with exclusive access to the process table.
pub unsafe fn get_signal_action(sig: Signal) -> SignalAction {
    unsafe {
        let procs = &*core::ptr::addr_of!(PROCS);
        let cur = usize::from(CURRENT);
        procs[cur]
            .as_ref()
            .map_or(SignalAction::Default, |p| p.signal_state.action(sig))
    }
}

/// Deliver a signal to a specific process by PID.
///
/// Handler registered → mark pending (delivered before next user-mode return).
/// Default action → apply immediately (Terminate or Ignore).
/// SIGKILL → always terminates, regardless of any registered handler.
///
/// Returns 0 on success, ESRCH if PID not found or Dead.
///
/// # Safety
///
/// Must be called from syscall context (single-core).
pub unsafe fn deliver_signal_to(pid: Pid, sig: Signal) -> u32 {
    const ESRCH: u32 = 0u32.wrapping_sub(3);
    // WHY (#269): PID 0 (kinit) is the fault supervisor and process-hierarchy
    // anchor; it must never be a userspace signal target, regardless of
    // capability or self-signal status. sys_kill enforces the same rule as a
    // belt-and-suspenders check before this function is ever reached.
    const EPERM: u32 = 0u32.wrapping_sub(1);
    if pid == 0 {
        return EPERM;
    }
    unsafe {
        let procs = &mut *addr_of_mut!(PROCS);
        let idx = usize::try_from(pid).unwrap_or(MAX_PROCS);
        if idx >= MAX_PROCS {
            return ESRCH;
        }
        let Some(ref mut proc) = procs[idx] else {
            return ESRCH;
        };
        if proc.state == State::Dead {
            return ESRCH;
        }
        // SIGKILL always terminates — handler cannot override.
        if sig == Signal::Sigkill {
            proc.state = State::Dead;
            // #267: every Dead transition drains the fd table.
            crate::fd::close_all(&mut proc.fds);
            // WHY: a process killed while blocked in sys_futex_wait would
            // otherwise leave its waiter slot permanently occupied — nothing
            // wakes a dead process, and sys_futex_wake only frees a slot on
            // a matching wake (#364).
            crate::futex::free_waiters_for_pid(u32::from(pid));
            // #492: every Dead transition also releases the pid's supervised
            // claim. A KILLED service files no fault report (so report_fault
            // never releases it) and never runs exit_cleanup, so without this a
            // stale claim would misattribute a later fault on the reused pid to
            // this service -- the pid-reuse class the fault-time resolution and
            // exit_cleanup's clear_pid close on the other two death paths.
            crate::supervisor::clear_pid(pid);
            return 0;
        }
        match proc.signal_state.action(sig) {
            SignalAction::Handler(_) => {
                proc.signal_state.set_pending(sig);
            }
            SignalAction::Ignore => {}
            SignalAction::Default => match sig.default_action() {
                crate::signal::DefaultAction::Terminate => {
                    proc.state = State::Dead;
                    // #267: every Dead transition drains the fd table.
                    crate::fd::close_all(&mut proc.fds);
                    // WHY: see the SIGKILL branch above (#364).
                    crate::futex::free_waiters_for_pid(u32::from(pid));
                    // #492: release the supervised claim -- see the SIGKILL
                    // branch above (a default-Terminate is the same death path
                    // for supervision purposes: no fault report, no exit_cleanup).
                    crate::supervisor::clear_pid(pid);
                }
                crate::signal::DefaultAction::Ignore => {}
            },
        }
        0
    }
}

/// Reset all signal handlers and the pending mask for the current process.
///
/// Called by `sys_execve` (POSIX: exec resets all signal dispositions to `SIG_DFL`
/// and clears any pending signals that were set by a handler).
///
/// # Safety
///
/// Must be called from syscall context (single-core, no preemption during SVC).
pub unsafe fn reset_signal_state() {
    // SAFETY: addr_of_mut! avoids an intermediate reference to the static mut.
    // Called from syscall context; no concurrent mutation of PROCS.
    unsafe {
        let procs = &mut *addr_of_mut!(PROCS);
        let cur = usize::from(CURRENT);
        if let Some(ref mut proc) = procs[cur] {
            proc.signal_state = SignalState::new();
        }
    }
}

/// Replace the current process's kernel context (entry point and stack pointer)
/// for exec-style image replacement.
///
/// Sets `ctx.lr` to `entry_point` and `ctx.sp` to `stack_top`, ready for the
/// next context switch or exception return to resume at the new entry point.
///
/// Also updates `stack_base`/`stack_pages` so that subsequent cleanup (exit,
/// another exec) frees the correct pages.
///
/// # Safety
///
/// Must be called from syscall context after the new stack pages have been
/// allocated and `loaded` is the validated + loaded ELF image.
///
/// Returns `false` if the new image/stack could not be mapped (L2-pool
/// exhaustion). The old image is already gone by then, so the caller MUST kill
/// the process (it is unrecoverable); the PCB is left consistent for
/// `exit_cleanup`'s page-table walk.
#[must_use]
pub unsafe fn exec_replace_context(
    loaded: &crate::elf::LoadedElf,
    stack_top: usize,
    new_stack_base: usize,
    new_stack_pages: usize,
) -> bool {
    // SAFETY: addr_of_mut! avoids an intermediate reference to the static mut.
    // Called from execve syscall with interrupts disabled (SVC mode, ARMv7).
    unsafe {
        let procs = &mut *addr_of_mut!(PROCS);
        let cur = usize::from(CURRENT);
        let Some(proc) = procs[cur].as_mut() else {
            return false;
        };
        let pt = proc.page_table_phys;
        let old_base = proc.stack_base;
        let old_pages = proc.stack_pages;
        let old_heap_break = proc.heap_break;
        let old_mappings = proc.mappings;

        // WHY (#489): the destructive + mapping phase runs under the KERNEL L1.
        // exec mutates the LIVE process table, and every free zeroes a frame
        // through the current TTBR0 (page.rs zero-on-free); a forked-then-exec'd
        // process user-remaps allocator-range VAs, so a raw phys write could
        // alias another mapping. The kernel L1 maps all DRAM identity with no
        // user remaps, so phys == VA for every access here. Page-table WRITES
        // (revoke/map) target L2 pool tables, which are kernel statics mapped in
        // every space, so they are valid under the kernel L1 too. IRQs are
        // masked (SVC), so this is atomic.
        mmu::switch_addr_space(mmu::table_base());

        // 0. (#502) Free the OLD image's per-process frame(s) BEFORE revoking the
        //    L2. Post-#502 the old image lives at its OWN allocator frame(s) --
        //    contiguous for a spawned process, alloc_page-scattered for a forked
        //    one -- recorded ONLY in the USER_TEXT MB's L2. reset_shattered_section
        //    (step 1) erases that record and map_user_image rewrites it, so
        //    capture-and-free MUST precede the reset. Freeing by the ACTUAL L2
        //    phys handles both layouts identically. try_free_page no-ops a
        //    non-allocated / already-free frame. Under the kernel L1 (identity
        //    zero-on-free) + IRQ-masked; the NEW image frame was already allocated
        //    by load_confined (allocator-disjoint), so no free hits it.
        //    INVARIANT: alloc+load-new strictly before free-old (holds -- load
        //    ran in sys_execve before this call).
        {
            // The image window is exactly one 1 MB section (256 4 KB pages).
            let image_end = crate::board::USER_TEXT_BASE + 0x10_0000;
            let mut va = crate::board::USER_TEXT_BASE;
            while va < image_end {
                if let Some(entry) = mmu::read_l2_entry(pt, va)
                    && mmu::l2_entry_is_user(entry)
                    && let Some(phys) = mmu::read_l2_phys(pt, va)
                {
                    page::try_free_page(phys);
                }
                va += page::PAGE_SIZE;
            }
        }

        // 1. Revoke the old image's PL0 windows: reset the whole USER_TEXT MB's
        //    L2 entries to identity KERNEL_DEFAULT (keeps the L2 table), so no
        //    stale PL0 image window survives and map_user_image re-maps into the
        //    SAME L2 (no fresh alloc -> infallible). A live PL0 caller always has
        //    a shattered image MB, so false here is an invariant break.
        let image_was_mapped = mmu::reset_shattered_section(pt, crate::board::USER_TEXT_BASE);
        debug_assert!(
            image_was_mapped,
            "exec: caller's image MB must be shattered"
        );

        // 2. Revoke + free the old stack (revoke BEFORE free so no stale PL0-RW
        //    window outlives the frame's return to the allocator). Free by the
        //    L2-mapped PHYSICAL frame (a forked child's stack VA != its phys).
        revoke_user_pages(pt, old_base, old_pages);
        for i in 0..old_pages {
            let vaddr = old_base + i * page::PAGE_SIZE;
            if let Some(phys) = mmu::read_l2_phys(pt, vaddr) {
                mmu::unmap_page(pt, vaddr);
                page::free_page(phys);
            }
        }

        // 3. Free the old mmap regions + grown heap (their VAs are below RAM,
        //    non-identity -- read_l2_phys resolves the real frame). #225.
        for mapping in old_mappings.iter().flatten() {
            for i in 0..mapping.pages {
                let vaddr = mapping.start + i * page::PAGE_SIZE;
                if let Some(phys) = mmu::read_l2_phys(pt, vaddr) {
                    mmu::unmap_page(pt, vaddr);
                    page::free_page(phys);
                }
            }
        }
        let mut heap_vaddr = DEFAULT_HEAP_BREAK;
        while heap_vaddr < old_heap_break {
            if let Some(phys) = mmu::read_l2_phys(pt, heap_vaddr) {
                mmu::unmap_page(pt, heap_vaddr);
                page::free_page(phys);
            }
            heap_vaddr += page::PAGE_SIZE;
        }

        // 4. Map the new image (W^X per segment) + the new stack (RW+XN). The
        //    new image bytes were already written to the per-process image frame
        //    (loaded.image_phys) by elf::load_confined (#502); argv was written
        //    to the new stack frames under the kernel L1. Mapping grants PL0 and
        //    points USER_TEXT_BASE at loaded.image_phys. map_user_image reuses
        //    the image L2 (infallible); only map_user_stack's fresh-MB shatter
        //    can fail (L2-pool exhaustion). `&` runs BOTH regardless.
        let remap_ok =
            map_user_image(pt, loaded) & map_user_stack(pt, new_stack_base, new_stack_pages);

        // 5. Back to the process table (switch_addr_space does TTBR0 + TLBIALL),
        //    then flush the branch predictor too (the executable image at
        //    USER_TEXT changed identity).
        mmu::switch_addr_space(pt);
        mmu::flush_tlb_all();

        // The old stack / mmap / heap were freed above and are gone from the
        // table; the heap/mmap tracking is reset for the new image.
        proc.heap_break = DEFAULT_HEAP_BREAK;
        proc.mappings = [None; MAX_MAPPINGS];

        if !remap_ok {
            // The old image is already destroyed (elf::load) -- the process is
            // unrecoverable. Free the ENTIRE new stack here: for a fresh exec
            // stack the frame IS its identity VA, so free_page(va) reclaims each
            // frame whether or not map_user_stack got to map it (a partial map
            // would otherwise leak the unmapped tail -- the walk in exit_cleanup
            // only sees MAPPED pages). unmap first so exit_cleanup's walk cannot
            // double-free, and zero stack_pages so its stack loop skips it.
            for i in 0..new_stack_pages {
                let va = new_stack_base + i * page::PAGE_SIZE;
                mmu::unmap_page(pt, va);
                page::free_page(va);
            }
            proc.stack_base = 0;
            proc.stack_pages = 0;
            // sys_execve kills the process (exit_current).
            return false;
        }
        proc.stack_base = new_stack_base;
        proc.stack_pages = new_stack_pages;

        // #498: sync the I-cache for the new image's executable segments now
        // that `pt` is the live TTBR0 (switch_addr_space above) and
        // map_user_image (step 4, remap_ok) has granted every segment --
        // USER_TEXT_BASE resolves to loaded.image_phys (the frame
        // elf::load_confined wrote) only under THIS table, so this is the
        // first point in exec where the real execution VA is valid to hand
        // to sync_icache_range. On real hardware this clears any I-cache
        // line the OLD image left behind at the same VA. Calling
        // unconditionally: sync_icache_range no-ops on non-ARM builds.
        for &(seg_va, seg_memsz, seg_flags) in loaded.segments() {
            if crate::elf::flags_to_prot(seg_flags) & mmu::prot::PROT_EXEC != 0 {
                // SAFETY: pt is the live TTBR0; map_user_image already
                // granted seg_va..+seg_memsz (remap_ok proved every segment
                // mapped, or this line is unreached). Already inside this
                // function's outer unsafe block -- no nested block needed.
                mmu::sync_icache_range(seg_va, seg_memsz);
            }
        }

        // 6. Install the new context -- into the PCB AND the live trap frame.
        //    THE linchpin (#489): the SVC epilogue exception-returns into
        //    ACTIVE_FRAME, not proc.ctx; without the frame write exec "returns"
        //    0 into the OLD image at the instruction after `svc` (now overwritten
        //    -> wild PL0 execution). FRAME_SWITCHED stays false (exec does not
        //    switch_to), so dispatch's return 0 is the correct fresh-image r0.
        proc.ctx = Context::initial(
            u32::try_from(loaded.entry).unwrap_or(0u32),
            u32::try_from(stack_top).unwrap_or(0u32),
            0x10,
        );
        if let Some(frame) = ACTIVE_FRAME.as_mut() {
            *frame = proc.ctx;
        }
        true
    }
}

/// Clear the lowest-numbered pending signal for the current process.
/// Called by `sys_sigreturn` after the handler returns.
///
/// # Safety
///
/// Must be called from syscall context.
pub unsafe fn clear_any_pending() {
    unsafe {
        let procs = &mut *addr_of_mut!(PROCS);
        let cur = usize::from(CURRENT);
        if let Some(ref mut proc) = procs[cur] {
            if let Some(sig) = proc.signal_state.next_pending() {
                proc.signal_state.clear_pending(sig);
            }
        }
    }
}

/// Clear the pending bit for EXACTLY `sig` on the current process (#446).
/// Called at dispatch time by `signal::deliver`, so the handler runs once per
/// raise; distinct from `clear_any_pending` (next-pending semantics), which
/// can clear the wrong signal when several are pending at once.
pub(crate) fn clear_pending_for_current(sig: crate::signal::Signal) {
    // SAFETY: current process PCB pointer is valid; mutation via addr_of_mut!,
    // single-core.
    unsafe {
        let procs = &mut *addr_of_mut!(PROCS);
        let cur = usize::from(CURRENT);
        if let Some(ref mut proc) = procs[cur] {
            proc.signal_state.clear_pending(sig);
        }
    }
}

/// Check for a pending signal that has a user-space handler.
/// Returns `Some((sig, handler_addr))` for the first such signal.
///
/// Called from the exception return path before resuming user mode.
pub(crate) fn check_pending_signal() -> Option<(Signal, u32)> {
    // SAFETY: read-only access via addr_of!; no mutation occurs here.
    unsafe {
        let procs = &*core::ptr::addr_of!(PROCS);
        let cur = usize::from(CURRENT);
        let proc = procs[cur].as_ref()?;
        let sig = proc.signal_state.next_pending()?;
        if let SignalAction::Handler(addr) = proc.signal_state.action(sig) {
            Some((sig, addr))
        } else {
            None
        }
    }
}

/// Get the pending-signal bitmask for a PID (test helper).
///
/// # Safety
///
/// Must be called from a context with exclusive access.
pub unsafe fn get_pending_mask(pid: Pid) -> u32 {
    unsafe {
        let procs = &*core::ptr::addr_of!(PROCS);
        let idx = usize::try_from(pid).unwrap_or(MAX_PROCS);
        if idx >= MAX_PROCS {
            return 0;
        }
        procs[idx].as_ref().map_or(0, |p| p.signal_state.pending)
    }
}

/// Get the state of a process by PID (test helper).
///
/// # Safety
///
/// Must be called from a context with exclusive access.
pub unsafe fn get_state(pid: Pid) -> Option<State> {
    unsafe {
        let procs = &*core::ptr::addr_of!(PROCS);
        let idx = usize::try_from(pid).unwrap_or(MAX_PROCS);
        if idx >= MAX_PROCS {
            return None;
        }
        procs[idx].as_ref().map(|p| p.state)
    }
}

/// Set the state of a process by PID.
///
/// Used by the futex subsystem to block (→ Blocked) and wake (→ Ready)
/// processes without going through the full scheduler path.
///
/// # Safety
///
/// Must be called from a context with exclusive access to PROCS (single-core
/// cooperative kernel: any syscall handler qualifies).
pub unsafe fn set_state(pid: Pid, state: State) {
    // SAFETY: caller holds exclusive access; addr_of_mut! avoids intermediate
    // reference to the static mut.
    unsafe {
        let procs = &mut *core::ptr::addr_of_mut!(PROCS);
        let idx = usize::try_from(pid).unwrap_or(MAX_PROCS);
        if idx >= MAX_PROCS {
            return;
        }
        if let Some(ref mut p) = procs[idx] {
            p.state = state;
        }
    }
}

/// Reset all process subsystem state for testing.
/// Creates process 0 (kernel) with a valid page table and resets the
/// page allocator.
///
/// # Safety
///
/// Must only be called in test code. Invalidates all process state.
#[cfg(test)]
pub(crate) unsafe fn reset_for_test() {
    // SAFETY: must only be called in test code. Invalidates all process state
    // by zeroing PROCS and reinitialising with a fresh page table. No
    // concurrent access is possible in single-threaded test execution.
    unsafe {
        let procs = &mut *core::ptr::addr_of_mut!(PROCS);
        for p in procs.iter_mut() {
            *p = None;
        }
        CURRENT = 0;
        mmu::reset_addr_space_pool();
        mmu::reset_l2_pool();
        page::init(0x4000_0000, 0x8000_0000, 0x4010_0000);

        let pt = mmu::alloc_addr_space().unwrap_or_default();
        procs[0] = Some(Process {
            pid: 0,
            state: State::Running,
            ctx: Context::zero(),
            parent: None,
            exit_status: 0,
            page_table_phys: pt,
            stack_base: 0,
            stack_pages: 0,
            heap_break: DEFAULT_HEAP_BREAK,
            mappings: [None; MAX_MAPPINGS],
            signal_state: SignalState::new(),
            uid: 0,
            wake_tick: 0,
            capabilities: crate::capability::Capabilities::ALL,
            fds: crate::fd::FdTable::new(),
            cwd: crate::fd::DEFAULT_CWD,
            cwd_len: 1,
        });
    }
}

/// Point CURRENT at `pid` so fd-isolation tests can act as another process.
///
/// # Safety
///
/// Test-only; single-threaded test execution.
#[cfg(test)]
pub(crate) unsafe fn set_current_for_test(pid: Pid) {
    // SAFETY: single-threaded test execution.
    unsafe {
        CURRENT = pid;
    }
}

/// Test-only PCB builder: kinit-like defaults (pid 0, Running, root uid, ALL
/// capabilities, empty fd table) over `page_table_phys`. Tests override only
/// the fields they exercise via struct-update syntax
/// (`Process { pid: 1, parent: Some(0), ..test_process(pt) }`), collapsing the
/// otherwise-identical 14-field literal at every test site (#267).
#[cfg(test)]
pub(crate) fn test_process(page_table_phys: usize) -> Process {
    Process {
        pid: 0,
        state: State::Running,
        ctx: Context::zero(),
        parent: None,
        exit_status: 0,
        page_table_phys,
        stack_base: 0,
        stack_pages: 0,
        heap_break: DEFAULT_HEAP_BREAK,
        mappings: [None; MAX_MAPPINGS],
        signal_state: SignalState::new(),
        uid: 0,
        wake_tick: 0,
        capabilities: crate::capability::Capabilities::ALL,
        fds: crate::fd::FdTable::new(),
        cwd: crate::fd::DEFAULT_CWD,
        cwd_len: 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mmu;
    use crate::page;

    /// Reset all global state before each test.
    unsafe fn reset_all() {
        // Zero process table
        let procs = &mut *core::ptr::addr_of_mut!(PROCS);
        for p in procs.iter_mut() {
            *p = None;
        }
        CURRENT = 0;

        // Reset address space pool
        mmu::reset_addr_space_pool();

        // Reset page allocator with a modest test pool
        // WHY: 0x4000_0000..0x8000_0000 is DRAM; kernel_end just above base so
        // pages FROM 0x4010_0000 onward are available.
        page::init(0x4000_0000, 0x8000_0000, 0x4010_0000);

        // Reset IPC inboxes by re-initialising as process 0 and draining
        // (no direct reset API; we just reconstruct process 0 and let
        // tests ignore stale messages  -  each test calls reset_all fresh)
    }

    // WHY (#465): first host coverage of the preemptive switch data path -- the
    // frame swap that switch_to performs on behalf of the exception stubs.
    // Previously untestable (the cooperative save/restore was pure asm).
    #[test]
    fn switch_to_swaps_full_trap_frame() {
        // SAFETY: test-only; reset_all reinitialises global state; single-threaded.
        unsafe {
            reset_all();
            let procs = &mut *core::ptr::addr_of_mut!(PROCS);
            let pt0 = mmu::alloc_addr_space().unwrap();
            let pt1 = mmu::alloc_addr_space().unwrap();
            procs[0] = Some(test_process(pt0));
            procs[1] = Some(Process {
                pid: 1,
                parent: Some(0),
                ..test_process(pt1)
            });
            procs[0].as_mut().unwrap().state = State::Running;
            procs[1].as_mut().unwrap().state = State::Ready;
            // PID 1's saved context: what switch_to must load into the frame.
            let next_ctx = Context {
                r: [11; 13],
                sp: 0x4020_0000,
                lr: 0xBEEF,
                pc: 0x4010_0000,
                cpsr: 0x1F,
            };
            procs[1].as_mut().unwrap().ctx = next_ctx;
            CURRENT = 0;

            // The interrupted frame the exception stub would have built for PID 0.
            let mut frame = Context {
                r: [7; 13],
                sp: 0x4008_0000,
                lr: 0xCAFE,
                pc: 0x4009_0000,
                cpsr: 0x1F,
            };
            let interrupted = frame;

            trap_enter(&mut frame as *mut Context);
            assert!(!trap_switched(), "trap_enter must reset the swapped flag");
            switch_to(1);

            // The frame now holds PID 1's context (the stub returns into it).
            assert_eq!(frame, next_ctx, "frame must load the next process ctx");
            // PID 0's PCB captured the interrupted register file verbatim.
            assert_eq!(
                procs[0].as_ref().unwrap().ctx,
                interrupted,
                "current PCB must save the interrupted frame"
            );
            let current = CURRENT;
            assert_eq!(current, 1);
            assert_eq!(procs[0].as_ref().unwrap().state, State::Ready);
            assert_eq!(procs[1].as_ref().unwrap().state, State::Running);
            assert!(trap_switched(), "switch must set the swapped flag");
            trap_leave();
        }
    }

    #[test]
    fn set_trap_return_writes_active_frame_and_noops_when_null() {
        // SAFETY: test-only; nextest runs each test in its own process, so
        // ACTIVE_FRAME starts null.
        unsafe {
            reset_all();
            trap_leave(); // ensure no active frame
            set_trap_return(42); // must be a harmless no-op with no frame

            let mut frame = Context::zero();
            trap_enter(&mut frame as *mut Context);
            set_trap_return(0xABC);
            assert_eq!(frame.r[0], 0xABC, "return value deposited into frame r0");
            trap_leave();
        }
    }

    #[test]
    fn switch_to_same_pid_is_noop() {
        // SAFETY: test-only; single-threaded.
        unsafe {
            reset_all();
            let procs = &mut *core::ptr::addr_of_mut!(PROCS);
            procs[0] = Some(test_process(mmu::alloc_addr_space().unwrap()));
            CURRENT = 0;
            let mut frame = Context::zero();
            frame.r[0] = 0x1234;
            trap_enter(&mut frame as *mut Context);
            switch_to(0);
            assert!(!trap_switched(), "self-switch must not flag a swap");
            assert_eq!(frame.r[0], 0x1234, "self-switch must not touch the frame");
            trap_leave();
        }
    }

    #[test]
    fn spawn_user_builds_pl0_context_and_isolated_space() {
        // #482: spawn_user must build a PL0 (User mode, cpsr 0x10) process in
        // its OWN address space, with the image mapped W^X user-accessible,
        // the stack user-RW+XN, and kernel MMIO still PL1-only (PL0 faults).
        // SAFETY: test-only; single-threaded (nextest process-per-test).
        unsafe {
            reset_all();
            mmu::init_and_enable(); // populate the kernel L1 with SECTION descriptors

            // .text RX (p_flags R|X = 0x5), .data RW (R|W = 0x6), at the
            // page-aligned user VAs init.ld produces.
            let loaded = crate::elf::LoadedElf::for_test(
                0x7FF0_0000,
                &[(0x7FF0_0000, 0x100, 0x5), (0x7FF0_1000, 0x100, 0x6)],
            );
            let pid = spawn_user(&loaded).expect("spawn_user must succeed");

            let procs = &*core::ptr::addr_of!(PROCS);
            let proc = procs[usize::from(pid)].as_ref().expect("pid must be live");
            assert_eq!(proc.ctx.cpsr, 0x10, "must enter at PL0 (User mode)");
            assert_eq!(proc.ctx.pc, 0x7FF0_0000, "entry pc");
            let pt = proc.page_table_phys;
            assert_ne!(pt, mmu::table_base(), "must have its own address space");

            // .text page: user RX (0x46E); .data page: user RW+XN (0x47F). Both
            // carry the #496 NG (USER_OWNED) tag at bit 11 (0x800), so enumeration
            // sees them by ownership rather than by AP: 0x46E|0x800 = 0xC6E,
            // 0x47F|0x800 = 0xC7F.
            assert_eq!(
                mmu::read_l2_entry(pt, 0x7FF0_0000).unwrap(),
                0x7FF0_0000u32 | 0xC6E,
                ".text must be user read-execute + USER_OWNED-tagged"
            );
            assert_eq!(
                mmu::read_l2_entry(pt, 0x7FF0_1000).unwrap(),
                0x7FF0_1000u32 | 0xC7F,
                ".data must be user read-write + execute-never + USER_OWNED-tagged"
            );
            // Device MMIO stays a PL1-only SECTION (never a user page table) --
            // a PL0 access to it faults. (Extends the #323 regression.)
            assert!(
                mmu::read_l2_entry(pt, 0x1100_0000).is_none(),
                "MMIO must not be a user-accessible page table"
            );
        }
    }

    #[test]
    fn fault_disposition_kills_only_user_mode() {
        // The killable set is EXACTLY User (0x10). System (0x1F) is PID 0 +
        // spawn() kernel threads; SVC/IRQ/ABT/UND/FIQ mean a handler faulted.
        // ABT/UND halting is the recursion breaker: if the kill path itself
        // faults, the nested trap's saved mode is ABT/UND.
        assert_eq!(fault_disposition(0x10), FaultDisposition::KillUser);
        // The decision masks to M[4:0] -- flag/IT/E/T bits are ignored.
        assert_eq!(fault_disposition(0x6000_0010), FaultDisposition::KillUser);
        assert_eq!(fault_disposition(0x0000_0030), FaultDisposition::KillUser); // User + Thumb
        for cpsr in [0x1Fu32, 0x13, 0x12, 0x17, 0x1B, 0x11, 0x16, 0x1A, 0x00] {
            assert_eq!(
                fault_disposition(cpsr),
                FaultDisposition::KernelHalt,
                "saved mode {cpsr:#x} is not User -- must halt, never recover a kernel fault"
            );
        }
    }

    #[test]
    fn fault_exit_status_uses_posix_signal_convention() {
        assert_eq!(
            fault_exit_status(FaultKind::DataAbort {
                fault_addr: 0,
                fault_status: 0
            }),
            139
        );
        assert_eq!(
            fault_exit_status(FaultKind::PrefetchAbort {
                fault_addr: 0,
                fault_status: 0
            }),
            139
        );
        assert_eq!(fault_exit_status(FaultKind::UndefinedInstruction), 132);
    }

    #[test]
    fn fault_exit_current_kills_notifies_and_swaps_to_successor() {
        fn fault_test_entry() -> ! {
            loop {}
        }
        // The composed abort-path kill the ARM stubs rely on, end to end: Dead +
        // fault status + resource teardown + PID-0 IPC + frame swap.
        // SAFETY: test-only; reset_all reinitialises global state; nextest runs
        // each test in its own process.
        unsafe {
            reset_all();
            let procs = &mut *core::ptr::addr_of_mut!(PROCS);
            procs[0] = Some(test_process(mmu::alloc_addr_space().unwrap()));
            let pid0_ctx = Context {
                r: [3; 13],
                sp: 0x4300_0000,
                lr: 0x1,
                pc: 0x4000_9000,
                cpsr: 0x1F,
            };
            procs[0].as_mut().unwrap().ctx = pid0_ctx;
            let pid = spawn(fault_test_entry).expect("spawn victim");
            let free_before_kill = page::free_count();
            let procs = &mut *core::ptr::addr_of_mut!(PROCS);
            procs[usize::from(pid)].as_mut().unwrap().state = State::Running;
            procs[0].as_mut().unwrap().state = State::Ready;
            CURRENT = pid;

            let mut frame = Context {
                cpsr: 0x10,
                ..Context::zero()
            };
            trap_enter(&mut frame as *mut Context);
            fault_exit_current(FaultKind::DataAbort {
                fault_addr: 0xDEAD_0000,
                fault_status: 0x80D,
            });

            let procs = &*core::ptr::addr_of!(PROCS);
            let victim = procs[usize::from(pid)].as_ref().unwrap();
            assert_eq!(victim.state, State::Dead, "faulter must die");
            assert_eq!(
                victim.exit_status, 139,
                "fault kill must carry the SIGSEGV-style status"
            );
            assert_eq!(victim.page_table_phys, 0, "address space must be reclaimed");
            assert_eq!(
                page::free_count(),
                free_before_kill + STACK_PAGES,
                "victim stack pages must return to the pool"
            );
            assert_eq!(
                frame, pid0_ctx,
                "trap frame must hold the successor (PID 0)"
            );
            let current = CURRENT;
            assert_eq!(current, 0, "PID 0 must be the successor");
            assert!(
                trap_switched(),
                "the stub epilogue must see a swapped frame"
            );
            // #492: the notification lands on the fault ring the service loop
            // drains, carrying the full report (kind + addr + status).
            let report =
                crate::supervisor::pop_report().expect("PID 0 must receive the fault notification");
            assert_eq!(report.kind, 1, "DataAbort is kind 1");
            assert_eq!(report.pid, pid, "the report names the faulting PID");
            assert_eq!(
                report.fault_addr, 0xDEAD_0000,
                "the report carries the addr"
            );
            assert_eq!(report.fault_status, 0x80D, "the report carries the status");
            trap_leave();
        }
    }

    #[test]
    fn reap_dead_children_frees_only_dead_children_of_current() {
        // #491 review: the fix for the PCB-slot leak. reap_dead_children (run by
        // PID 0's service loop) must free a Dead child's slot, leave a Running
        // child alone, and never touch PID 0 itself.
        // SAFETY: test-only; reset_all reinitialises global state; single-threaded.
        unsafe {
            reset_all();
            let procs = &mut *core::ptr::addr_of_mut!(PROCS);
            procs[0] = Some(test_process(mmu::alloc_addr_space().unwrap()));
            CURRENT = 0;
            // A Dead child (fault-killed) + a Running child, both of PID 0.
            let dead = Process {
                pid: 1,
                parent: Some(0),
                state: State::Dead,
                exit_status: 139,
                ..test_process(mmu::alloc_addr_space().unwrap())
            };
            let running = Process {
                pid: 2,
                parent: Some(0),
                state: State::Running,
                ..test_process(mmu::alloc_addr_space().unwrap())
            };
            procs[1] = Some(dead);
            procs[2] = Some(running);

            let reaped = reap_dead_children();

            let procs = &*core::ptr::addr_of!(PROCS);
            assert_eq!(reaped, 1, "exactly the one Dead child is reaped");
            assert!(procs[1].is_none(), "the Dead child's slot must be freed");
            assert!(procs[2].is_some(), "the Running child must be left alone");
            assert!(procs[0].is_some(), "PID 0 must never be reaped");
        }
    }

    #[test]
    fn reap_dead_children_ignores_a_dead_non_child() {
        // A Dead process that is NOT a child of CURRENT must not be reaped by
        // CURRENT (only the direct parent reaps).
        // SAFETY: test-only; single-threaded.
        unsafe {
            reset_all();
            let procs = &mut *core::ptr::addr_of_mut!(PROCS);
            procs[0] = Some(test_process(mmu::alloc_addr_space().unwrap()));
            CURRENT = 0;
            let orphan = Process {
                pid: 3,
                parent: Some(2), // not a child of CURRENT (0)
                state: State::Dead,
                ..test_process(mmu::alloc_addr_space().unwrap())
            };
            procs[3] = Some(orphan);

            assert_eq!(reap_dead_children(), 0, "a non-child Dead is not reaped");
            let procs = &*core::ptr::addr_of!(PROCS);
            assert!(procs[3].is_some(), "the non-child Dead slot is untouched");
        }
    }

    #[test]
    fn fork_creates_new_process() {
        // SAFETY: test-only; reset_all reinitialises global state. Single-threaded
        // test execution ensures no concurrent access to PROCS or CURRENT.
        unsafe {
            reset_all();
            // Construct a minimal process 0
            let procs = &mut *core::ptr::addr_of_mut!(PROCS);
            let pt = mmu::alloc_addr_space().unwrap();
            procs[0] = Some(test_process(pt));
            CURRENT = 0;

            let child_pid = fork().unwrap_or_default();
            let procs = &*core::ptr::addr_of!(PROCS);
            assert!(
                procs[usize::from(child_pid)].is_some(),
                "child slot must be populated"
            );
        }
    }

    #[test]
    fn fork_pl0_deep_copies_user_pages_fresh_frames_same_attrs() {
        // #478: a PL0 fork gives the child its OWN address space with the
        // parent's user pages DEEP-COPIED -- fresh frames (distinct phys), the
        // SAME VAs, the SAME W^X attrs -- never sharing the parent's L2 tables.
        // The child's ctx is seeded from the trap frame with r0 = 0.
        // SAFETY: test-only; single-threaded; reset_all reinitialises state.
        unsafe {
            reset_all();
            mmu::init_and_enable();
            // A PL0 parent like spawn_user builds: .text RX + .data RW + stack.
            let loaded = crate::elf::LoadedElf::for_test(
                0x7FF0_0000,
                &[(0x7FF0_0000, 0x100, 0x5), (0x7FF0_1000, 0x100, 0x6)],
            );
            let ppid = spawn_user(&loaded).expect("spawn PL0 parent");
            CURRENT = ppid;
            let parent_pt = {
                let procs = &*core::ptr::addr_of!(PROCS);
                procs[usize::from(ppid)].as_ref().unwrap().page_table_phys
            };

            // Install a User-mode trap frame with distinctive registers.
            let mut frame = Context {
                r: [9; 13],
                sp: 0x7F00_0000,
                lr: 0xC0DE,
                pc: 0x7FF0_0010,
                cpsr: 0x10,
            };
            trap_enter(&mut frame as *mut Context);
            let child_pid = fork().expect("PL0 fork must deep-copy");
            trap_leave();

            let procs = &*core::ptr::addr_of!(PROCS);
            let child = procs[usize::from(child_pid)].as_ref().unwrap();
            // Child resumes at the fork return (frame) with r0 = 0.
            assert_eq!(child.ctx.pc, 0x7FF0_0010, "child resumes at the fork site");
            assert_eq!(child.ctx.r[0], 0, "child returns 0 from fork");
            let child_pt = child.page_table_phys;
            assert_ne!(child_pt, parent_pt, "child has its OWN address space");

            for va in [0x7FF0_0000usize, 0x7FF0_1000] {
                let pe = mmu::read_l2_entry(parent_pt, va).unwrap();
                let ce = mmu::read_l2_entry(child_pt, va).unwrap();
                assert_eq!(pe & 0xFFF, ce & 0xFFF, "same attrs at {va:#x}");
                assert_ne!(
                    pe & 0xFFFF_F000,
                    ce & 0xFFFF_F000,
                    "child page {va:#x} must be a DIFFERENT frame (deep copy)"
                );
            }
            // MMIO stays PL1-only in the child (never a user page table).
            assert!(mmu::read_l2_entry(child_pt, 0x1100_0000).is_none());
        }
    }

    #[test]
    fn fork_pl0_oom_rolls_back_exactly() {
        // #478: a PL0 fork that OOMs mid-copy must leave the allocator + address
        // space pools exactly as before -- no leaked child frames or L2s.
        // SAFETY: test-only; single-threaded.
        unsafe {
            reset_all();
            mmu::init_and_enable();
            let loaded = crate::elf::LoadedElf::for_test(
                0x7FF0_0000,
                &[(0x7FF0_0000, 0x100, 0x5), (0x7FF0_1000, 0x100, 0x6)],
            );
            let ppid = spawn_user(&loaded).expect("spawn PL0 parent");
            CURRENT = ppid;
            let free_before = page::free_count();

            // Drain the page pool so the copy phase OOMs after 0..n pages.
            let mut hog = alloc::vec::Vec::new();
            while let Some(p) = page::alloc_page() {
                hog.push(p);
            }
            let mut frame = Context {
                cpsr: 0x10,
                ..Context::zero()
            };
            trap_enter(&mut frame as *mut Context);
            assert!(fork().is_none(), "fork must fail closed on OOM");
            trap_leave();

            for p in hog {
                page::free_page(p);
            }
            assert_eq!(
                page::free_count(),
                free_before,
                "a rolled-back fork must leak no frames"
            );
        }
    }

    #[test]
    fn fork_pl0_child_exit_frees_own_frames_not_parents() {
        // #478 (review): a forked child's exit must free the child's OWN
        // deep-copied frames (via exit_cleanup's page-table WALK), never the
        // parent's -- the child's stack_base is the parent's VA, so an
        // identity free would free the parent's live stack.
        // SAFETY: test-only; single-threaded.
        unsafe {
            reset_all();
            mmu::init_and_enable();
            let loaded = crate::elf::LoadedElf::for_test(
                0x7FF0_0000,
                &[(0x7FF0_0000, 0x100, 0x5), (0x7FF0_1000, 0x100, 0x6)],
            );
            let ppid = spawn_user(&loaded).expect("spawn PL0 parent");
            CURRENT = ppid;
            let (parent_pt, parent_stack_base) = {
                let procs = &*core::ptr::addr_of!(PROCS);
                let p = procs[usize::from(ppid)].as_ref().unwrap();
                (p.page_table_phys, p.stack_base)
            };
            // The parent's real stack frame (identity == its L2 mapping).
            let parent_stack_frame = mmu::read_l2_phys(parent_pt, parent_stack_base).unwrap();

            let mut frame = Context {
                cpsr: 0x10,
                ..Context::zero()
            };
            trap_enter(&mut frame as *mut Context);
            let cpid = fork().expect("PL0 fork");
            trap_leave();

            let free_before_exit = page::free_count();
            // Count the child's deep-copied frames (image + stack pages).
            let child_pt = {
                let procs = &*core::ptr::addr_of!(PROCS);
                procs[usize::from(cpid)].as_ref().unwrap().page_table_phys
            };
            let mut child_frames = 0usize;
            mmu::for_each_user_page(child_pt, |_v, _p, _a| {
                child_frames += 1;
                true
            });
            assert!(child_frames > 0);

            CURRENT = cpid;
            exit_cleanup(0);

            // The child's frames are returned; the parent's stack frame is NOT.
            assert_eq!(
                page::free_count(),
                free_before_exit + child_frames,
                "child exit frees exactly its own deep-copied frames"
            );
            // try_free_page returns true iff the frame was still ALLOCATED (and
            // frees it); asserting true confirms the child exit did NOT free the
            // parent's frame -- a wrongly-freed frame would already be free
            // (returns false) and fail here.
            assert!(
                page::try_free_page(parent_stack_frame),
                "parent's live stack frame must NOT have been freed by the child exit"
            );
        }
    }

    #[test]
    fn exec_replace_frees_forked_childs_real_stack_not_parents() {
        // #478 CRITICAL (review): exec on a forked child must free the child's
        // REAL stack frames (resolved via the page table), not the parent's
        // live frame at the shared stack VA.
        // SAFETY: test-only; single-threaded.
        unsafe {
            reset_all();
            mmu::init_and_enable();
            let loaded = crate::elf::LoadedElf::for_test(
                0x7FF0_0000,
                &[(0x7FF0_0000, 0x100, 0x5), (0x7FF0_1000, 0x100, 0x6)],
            );
            let ppid = spawn_user(&loaded).expect("spawn PL0 parent");
            CURRENT = ppid;
            let (parent_pt, parent_stack_base) = {
                let procs = &*core::ptr::addr_of!(PROCS);
                let p = procs[usize::from(ppid)].as_ref().unwrap();
                (p.page_table_phys, p.stack_base)
            };
            let parent_stack_frame = mmu::read_l2_phys(parent_pt, parent_stack_base).unwrap();

            let mut frame = Context {
                cpsr: 0x10,
                ..Context::zero()
            };
            trap_enter(&mut frame as *mut Context);
            let cpid = fork().expect("PL0 fork");
            trap_leave();

            // The child's real stack frame (a fresh deep-copied page).
            let child_pt = {
                let procs = &*core::ptr::addr_of!(PROCS);
                procs[usize::from(cpid)].as_ref().unwrap().page_table_phys
            };
            let child_stack_frame = mmu::read_l2_phys(child_pt, parent_stack_base).unwrap();
            assert_ne!(child_stack_frame, parent_stack_frame, "distinct frames");

            // Exec the child onto a fresh stack.
            CURRENT = cpid;
            let new_stack = page::alloc_contiguous(2).unwrap();
            let new_image =
                crate::elf::LoadedElf::for_test(0x7FF0_0000, &[(0x7FF0_0000, 0x100, 0x5)]);
            assert!(exec_replace_context(
                &new_image,
                new_stack + 2 * page::PAGE_SIZE,
                new_stack,
                2
            ));

            // The parent's live stack frame must NOT be freed (the critical bug).
            // Asserting still-allocated (returns true) catches a wrongly-freed
            // parent frame (which would already be free -> false).
            assert!(
                page::try_free_page(parent_stack_frame),
                "the parent's live stack frame must NOT be freed by the child's exec"
            );
            // The child's OLD stack frame WAS freed by exec, so it is now free --
            // try_free_page returns false (already free), not true (was allocated).
            assert!(
                !page::try_free_page(child_stack_frame),
                "the child's old stack frame must be freed by exec (no leak)"
            );
        }
    }

    #[test]
    fn fork_assigns_separate_page_tables() {
        // SAFETY: test-only; reset_all reinitialises global state. Single-threaded
        // test execution ensures no concurrent access to PROCS or CURRENT.
        unsafe {
            reset_all();
            let procs = &mut *core::ptr::addr_of_mut!(PROCS);
            let pt = mmu::alloc_addr_space().unwrap();
            procs[0] = Some(test_process(pt));
            CURRENT = 0;

            let child_pid = fork().unwrap_or_default();
            let procs = &*core::ptr::addr_of!(PROCS);
            let parent_pt = procs[0].as_ref().unwrap().page_table_phys;
            let child_pt = procs[usize::from(child_pid)]
                .as_ref()
                .unwrap()
                .page_table_phys;
            assert_ne!(
                parent_pt, child_pt,
                "parent and child must have distinct page tables"
            );
        }
    }

    #[test]
    fn fork_child_has_correct_parent() {
        // SAFETY: test-only; reset_all reinitialises global state. Single-threaded
        // test execution ensures no concurrent access to PROCS or CURRENT.
        unsafe {
            reset_all();
            let procs = &mut *core::ptr::addr_of_mut!(PROCS);
            let pt = mmu::alloc_addr_space().unwrap();
            procs[0] = Some(test_process(pt));
            CURRENT = 0;

            let child_pid = fork().unwrap_or_default();
            let procs = &*core::ptr::addr_of!(PROCS);
            let child_parent = procs[usize::from(child_pid)].as_ref().unwrap().parent;
            assert_eq!(child_parent, Some(0u8), "child.parent must be parent PID");
        }
    }

    /// `fork()` must NOT let the child inherit a signal that was pending in the
    /// parent at fork time: signal HANDLERS are inherited but the pending mask
    /// is cleared (process.rs `fork()`, `s.pending = 0`), matching POSIX
    /// `fork()` semantics.
    #[test]
    fn fork_clears_child_pending_signal_mask() {
        // SAFETY: test-only; reset_all reinitialises global state. Single-threaded
        // test execution ensures no concurrent access to PROCS or CURRENT.
        unsafe {
            reset_all();
            let procs = &mut *core::ptr::addr_of_mut!(PROCS);
            let pt = mmu::alloc_addr_space().unwrap_or_default();
            let mut parent_signal_state = SignalState::new();
            parent_signal_state.set_pending(crate::signal::Signal::Sigusr1);
            procs[0] = Some(Process {
                signal_state: parent_signal_state,
                ..test_process(pt)
            });
            CURRENT = 0;

            let child_pid = fork().unwrap_or_default();

            let child_pending = get_pending_mask(child_pid);
            let parent_pending = get_pending_mask(0);
            assert_eq!(
                child_pending, 0,
                "child must start with a clean pending-signal mask even though the parent had SIGUSR1 pending at fork time"
            );
            assert_ne!(
                parent_pending, 0,
                "fork must not clear the PARENT's own pending-signal mask"
            );
        }
    }

    #[test]
    fn fork_strips_privileged_capabilities() {
        // SAFETY: test-only; reset_all reinitialises global state. Single-threaded
        // test execution ensures no concurrent access to PROCS or CURRENT.
        unsafe {
            reset_all();
            let procs = &mut *core::ptr::addr_of_mut!(PROCS);
            let pt = mmu::alloc_addr_space().unwrap();
            procs[0] = Some(test_process(pt));
            CURRENT = 0;

            let child_pid = fork().unwrap_or_default();
            let procs = &*core::ptr::addr_of!(PROCS);
            let parent_caps = procs[0].as_ref().unwrap().capabilities;
            let child_caps = procs[usize::from(child_pid)].as_ref().unwrap().capabilities;

            // WHY: production computes child_caps = parent_caps & FORK_DEFAULT
            // (process.rs). A `|`-for-`&` slip would grant the child every
            // parent capability, including MODEM (baseband) and AUDIT (log).
            assert_eq!(
                child_caps,
                parent_caps & crate::capability::Capabilities::FORK_DEFAULT,
                "child capabilities must equal parent_caps & FORK_DEFAULT"
            );
            assert_eq!(
                child_caps & crate::capability::Capabilities::MODEM,
                0,
                "MODEM must be stripped from a forked child"
            );
            assert_eq!(
                child_caps & crate::capability::Capabilities::AUDIT,
                0,
                "AUDIT must be stripped from a forked child"
            );
        }
    }

    #[test]
    fn address_space_independence() {
        // SAFETY: test-only; reset_all reinitialises global state. Single-threaded
        // test execution ensures no concurrent access to PROCS or CURRENT.
        // Page table pointer writes are to isolated test allocations verified
        // to be distinct L1 tables.
        unsafe {
            reset_all();
            let procs = &mut *core::ptr::addr_of_mut!(PROCS);
            let pt = mmu::alloc_addr_space().unwrap();
            procs[0] = Some(test_process(pt));
            CURRENT = 0;

            let child_pid = fork().unwrap_or_default();
            let procs = &*core::ptr::addr_of!(PROCS);
            let parent_pt = procs[0].as_ref().unwrap().page_table_phys;
            let child_pt = procs[usize::from(child_pid)]
                .as_ref()
                .unwrap()
                .page_table_phys;

            // Write INTO entry 100 in the child's table
            (child_pt as *mut u32).add(100).write(0xCAFE_BABE);
            // Parent's entry 100 must be unchanged
            let parent_val = (parent_pt as *const u32).add(100).read();
            assert_ne!(
                parent_val, 0xCAFE_BABE,
                "writing to child table must not affect parent table (separate L1s)"
            );
        }
    }

    /// #251: an OOM partway through `spawn()`'s stack allocation must roll
    /// back exactly the pages allocated so far, verified against the bitmap
    /// free-count (not assumed physically contiguous).
    #[test]
    fn spawn_oom_rollback_frees_exact_allocated_pages() {
        fn spawn_test_entry() -> ! {
            loop {}
        }
        unsafe {
            reset_all();
            let procs = &mut *core::ptr::addr_of_mut!(PROCS);
            let pt = mmu::alloc_addr_space().unwrap();
            procs[0] = Some(test_process(pt));
            CURRENT = 0;

            // Shrink the free pool to exactly 2 pages so the 4-page stack
            // allocation (STACK_PAGES = 4) OOMs on the 3rd page.
            page::init(
                0x4000_0000,
                0x4000_0000 + 6 * page::PAGE_SIZE,
                0x4000_0000 + 4 * page::PAGE_SIZE,
            );
            let free_before = page::free_count();
            assert_eq!(free_before, 2, "test setup must yield exactly 2 free pages");

            let result = spawn(spawn_test_entry);
            assert!(
                result.is_none(),
                "spawn must fail when the stack allocation OOMs"
            );

            let free_after = page::free_count();
            assert_eq!(
                free_after, free_before,
                "OOM rollback must return exactly the pages allocated before the failure, leaving free-count unchanged (#251)"
            );
        }
    }

    /// #251: an OOM partway through `fork()`'s child-stack allocation must roll
    /// back exactly the pages allocated so far. #208 rewrote `fork()`'s SUCCESS
    /// path (translated sp + stack copy) but left the rollback assuming
    /// physical contiguity; this guards the re-derived array-tracked rollback.
    #[test]
    fn fork_oom_rollback_frees_exact_allocated_pages() {
        unsafe {
            reset_all();
            let procs = &mut *core::ptr::addr_of_mut!(PROCS);
            let pt = mmu::alloc_addr_space().unwrap();
            procs[0] = Some(test_process(pt));
            CURRENT = 0;

            // Shrink the free pool to exactly 2 pages so the 4-page child
            // stack allocation (STACK_PAGES = 4) OOMs on the 3rd page.
            page::init(
                0x4000_0000,
                0x4000_0000 + 6 * page::PAGE_SIZE,
                0x4000_0000 + 4 * page::PAGE_SIZE,
            );
            let free_before = page::free_count();
            assert_eq!(free_before, 2, "test setup must yield exactly 2 free pages");

            let result = fork();
            assert!(
                result.is_none(),
                "fork must fail when the child stack allocation OOMs"
            );

            let free_after = page::free_count();
            assert_eq!(
                free_after, free_before,
                "OOM rollback must return exactly the pages allocated before the failure, leaving free-count unchanged (#251)"
            );
        }
    }

    #[test]
    fn waitpid_returns_none_while_running() {
        // SAFETY: test-only; reset_all reinitialises global state. Single-threaded
        // test execution ensures no concurrent access to PROCS or CURRENT.
        unsafe {
            reset_all();
            let procs = &mut *core::ptr::addr_of_mut!(PROCS);
            let pt = mmu::alloc_addr_space().unwrap();
            procs[0] = Some(test_process(pt));
            CURRENT = 0;

            let child_pid = fork().unwrap_or_default();
            // Child is Ready, not Dead  -  waitpid must return None
            assert_eq!(
                waitpid(child_pid),
                None,
                "should return None while child is alive"
            );
        }
    }

    /// #232: waitpid must reject any PID >= `MAX_PROCS` instead of indexing
    /// the fixed-size table out of bounds.
    #[test]
    fn waitpid_rejects_out_of_bounds_pid() {
        unsafe {
            reset_all();
            let procs = &mut *core::ptr::addr_of_mut!(PROCS);
            let pt = mmu::alloc_addr_space().unwrap();
            procs[0] = Some(test_process(pt));
            CURRENT = 0;

            assert_eq!(
                waitpid(200),
                None,
                "waitpid must reject an out-of-bounds PID instead of panicking"
            );
            assert_eq!(
                waitpid(255),
                None,
                "waitpid must reject PID 255 (u8::MAX) instead of panicking"
            );
        }
    }

    /// #218/#224: fork/exit/waitpid `MAX_PROCS` times must leave every
    /// non-init slot reaped (None), and a further fork must then succeed —
    /// not permanently exhaust the table with Dead-but-unreaped PCBs.
    #[test]
    fn waitpid_reaps_dead_child_and_frees_the_slot() {
        unsafe {
            reset_all();
            let procs = &mut *core::ptr::addr_of_mut!(PROCS);
            let pt = mmu::alloc_addr_space().unwrap();
            procs[0] = Some(test_process(pt));
            CURRENT = 0;

            for _ in 0..(MAX_PROCS - 1) {
                assert!(fork().is_some(), "fork must succeed while slots remain");
            }
            assert!(
                fork().is_none(),
                "fork must fail once the process table is full"
            );

            for pid in 1..MAX_PROCS as Pid {
                CURRENT = pid;
                exit_cleanup(0);
            }
            CURRENT = 0;
            for pid in 1..MAX_PROCS as Pid {
                assert_eq!(
                    waitpid(pid),
                    Some(0),
                    "waitpid must return the exit status for each Dead child"
                );
            }

            let procs_ro = &*core::ptr::addr_of!(PROCS);
            for pid in 1..MAX_PROCS {
                assert!(
                    procs_ro[pid].is_none(),
                    "reaped slot {pid} must be None, not a lingering Dead PCB"
                );
            }
            assert!(
                fork().is_some(),
                "fork must succeed again once reaped slots are available (#224)"
            );
        }
    }

    #[test]
    fn waitpid_returns_status_when_dead() {
        // SAFETY: test-only; reset_all reinitialises global state. Single-threaded
        // test execution ensures no concurrent access to PROCS or CURRENT.
        unsafe {
            reset_all();
            let procs = &mut *core::ptr::addr_of_mut!(PROCS);
            let pt = mmu::alloc_addr_space().unwrap();
            procs[0] = Some(test_process(pt));
            CURRENT = 0;

            let child_pid = fork().unwrap_or_default();

            // Manually mark child as dead with exit status 42
            let procs = &mut *core::ptr::addr_of_mut!(PROCS);
            if let Some(ref mut child) = procs[usize::from(child_pid)] {
                child.state = State::Dead;
                child.exit_status = 42;
            }

            assert_eq!(waitpid(child_pid), Some(42), "should return exit status 42");
        }
    }

    #[test]
    fn exit_cleanup_marks_dead_and_reclaims_pages() {
        // SAFETY: test-only; reset_all reinitialises global state. Single-threaded
        // test execution ensures no concurrent access to PROCS or CURRENT.
        unsafe {
            reset_all();
            let procs = &mut *core::ptr::addr_of_mut!(PROCS);
            let pt = mmu::alloc_addr_space().unwrap();
            procs[0] = Some(test_process(pt));
            CURRENT = 0;

            let child_pid = fork().unwrap_or_default();

            let free_before = page::free_count();

            // Switch CURRENT to child and call exit_cleanup
            CURRENT = child_pid;
            exit_cleanup(0);

            let procs = &*core::ptr::addr_of!(PROCS);
            let child = procs[usize::from(child_pid)].as_ref().unwrap();
            assert_eq!(
                child.state,
                State::Dead,
                "exit_cleanup must mark state Dead"
            );

            let free_after = page::free_count();
            assert!(
                free_after > free_before,
                "exit_cleanup must reclaim stack pages"
            );
        }
    }

    #[test]
    fn notify_fault_marks_process_dead() {
        // SAFETY: test-only; reset_all reinitialises global state. Single-threaded
        // test execution ensures no concurrent access to PROCS or CURRENT.
        unsafe {
            reset_all();
            let procs = &mut *core::ptr::addr_of_mut!(PROCS);

            // Process 0: kinit supervisor
            let pt0 = mmu::alloc_addr_space().unwrap();
            procs[0] = Some(test_process(pt0));

            // Process 1: faulting process
            let pt1 = mmu::alloc_addr_space().unwrap();
            procs[1] = Some(Process {
                pid: 1,
                parent: Some(0),
                ..test_process(pt1)
            });
            CURRENT = 0;

            notify_fault(
                1,
                FaultKind::DataAbort {
                    fault_addr: 0xDEAD,
                    fault_status: 0x05,
                },
            );

            let procs = &*core::ptr::addr_of!(PROCS);
            assert_eq!(
                procs[1].as_ref().unwrap().state,
                State::Dead,
                "faulting process must be marked Dead"
            );
        }
    }

    #[test]
    fn notify_fault_reports_to_the_fault_ring_not_the_ipc_inbox() {
        // #492: the report goes on the dedicated fault ring the service loop
        // drains -- NOT PID 0's IPC inbox, which nothing drained (so reports
        // accumulated until it filled and legitimate user->PID0 IPC then failed).
        // SAFETY: test-only; reset_all reinitialises global state. Single-threaded
        // test execution ensures no concurrent access to PROCS or CURRENT.
        unsafe {
            reset_all();
            crate::supervisor::reset();
            let procs = &mut *core::ptr::addr_of_mut!(PROCS);

            let pt0 = mmu::alloc_addr_space().unwrap();
            procs[0] = Some(test_process(pt0));
            let pt1 = mmu::alloc_addr_space().unwrap();
            procs[1] = Some(Process {
                pid: 1,
                parent: Some(0),
                ..test_process(pt1)
            });
            CURRENT = 0;

            notify_fault(1, FaultKind::UndefinedInstruction);

            let report = crate::supervisor::pop_report()
                .expect("an UndefinedInstruction fault must reach the fault ring");
            assert_eq!(report.pid, 1, "the report names the faulting PID");
            assert_eq!(report.kind, 3, "UndefinedInstruction is kind 3");

            // PID 0's IPC inbox must be untouched -- fault reports no longer
            // compete with real userspace IPC for its 16 slots.
            CURRENT = 0;
            assert!(
                ipc::recv().is_none(),
                "a fault must not consume a PID 0 IPC inbox slot"
            );
        }
    }

    #[test]
    fn notify_fault_full_inbox_does_not_panic() {
        // WHY: regression test for #252 — ipc::send's bool return was
        // previously discarded inside notify_fault; a full kinit inbox must
        // not panic, and the faulting process must still be marked Dead
        // even when the notification itself is dropped.
        // SAFETY: test-only; reset_all reinitialises global state. Single-threaded
        // test execution ensures no concurrent access to PROCS or CURRENT.
        unsafe {
            reset_all();
            let procs = &mut *core::ptr::addr_of_mut!(PROCS);

            let pt0 = mmu::alloc_addr_space().unwrap();
            procs[0] = Some(test_process(pt0));
            let pt1 = mmu::alloc_addr_space().unwrap();
            procs[1] = Some(Process {
                pid: 1,
                parent: Some(0),
                ..test_process(pt1)
            });
            CURRENT = 0;

            // Saturate PID 0's inbox so ipc::send(0, ...) returns false.
            for _ in 0..20 {
                ipc::send(0, ipc::Message::new(99, b"fill"));
            }

            // Must not panic even though the fault notification cannot be delivered.
            notify_fault(1, FaultKind::UndefinedInstruction);

            let procs = &*core::ptr::addr_of!(PROCS);
            assert_eq!(
                procs[1].as_ref().unwrap().state,
                State::Dead,
                "faulting process must still be marked Dead when the fault notification is dropped"
            );
        }
    }

    #[test]
    fn page_table_teardown_on_exit() {
        // SAFETY: test-only; reset_all reinitialises global state. Single-threaded
        // test execution ensures no concurrent access to PROCS or CURRENT.
        unsafe {
            reset_all();
            let procs = &mut *core::ptr::addr_of_mut!(PROCS);
            let pt = mmu::alloc_addr_space().unwrap();
            procs[0] = Some(test_process(pt));
            CURRENT = 0;

            let child_pid = fork().unwrap_or_default();
            let procs_ref = &*core::ptr::addr_of!(PROCS);
            let child_pt = procs_ref[usize::from(child_pid)]
                .as_ref()
                .unwrap()
                .page_table_phys;

            // Exit the child  -  should free its page table slot
            CURRENT = child_pid;
            exit_cleanup(0);

            // Allocate again  -  must get the same address (slot was reclaimed)
            let new_pt = mmu::alloc_addr_space().unwrap_or_default();
            assert_eq!(new_pt, child_pt, "reclaimed table slot must be reused");

            mmu::free_addr_space(new_pt);
        }
    }

    /// #225: `exec_replace_context` must unmap and free every previously
    /// tracked mmap page and every grown heap page, not just reset the
    /// tracking state and leak the physical frames.
    #[test]
    fn exec_replace_context_frees_mmap_and_heap_pages() {
        unsafe {
            reset_all();
            let procs = &mut *core::ptr::addr_of_mut!(PROCS);
            let pt = mmu::alloc_addr_space().unwrap();
            procs[0] = Some(test_process(pt));
            CURRENT = 0;

            // Simulate one mmap'd page.
            let mmap_phys = page::alloc_page().unwrap();
            let mmap_vaddr = MMAP_BASE;
            let l2_attrs = mmu::prot_to_l2_flags(mmu::prot::PROT_READ | mmu::prot::PROT_WRITE);
            assert!(mmu::map_page(pt, mmap_vaddr, mmap_phys, l2_attrs));
            add_mapping(VmMapping {
                start: mmap_vaddr,
                pages: 1,
                prot: mmu::prot::PROT_READ | mmu::prot::PROT_WRITE,
            });

            // Simulate one grown heap page.
            let heap_phys = page::alloc_page().unwrap();
            assert!(mmu::map_page(pt, DEFAULT_HEAP_BREAK, heap_phys, l2_attrs));
            set_heap_break(DEFAULT_HEAP_BREAK + page::PAGE_SIZE);

            // A real exec caller has a shattered image MB with the OLD per-process
            // image mapped (exec_replace_context asserts it). map_page shatters
            // USER_TEXT's MB; this frame is the old image, which #502's exec
            // teardown (the pre-reset L2 walk, step 0) FREES -- so it IS part of
            // the freed-frame delta measured below.
            let img_phys = page::alloc_page().unwrap();
            assert!(mmu::map_page(
                pt,
                crate::board::USER_TEXT_BASE,
                img_phys,
                l2_attrs
            ));

            // Capture the baseline AFTER allocating the new stack so the delta
            // measures exactly the frames exec frees, not the new stack alloc.
            let new_stack_phys = page::alloc_page().unwrap();
            let free_before = page::free_count();

            // Empty image (no segments): this test exercises the mmap/heap +
            // old-image FREE path, which runs regardless of whether the remap
            // succeeds. On this synthetic bare table the new stack MB is not a
            // shatterable section, so map_user_stack fails, remap returns false,
            // and the failure path ALSO frees the whole new stack (1 page) -- so
            // exec frees the 1 mmap + 1 heap + 1 old-image (#502 step-0 walk) +
            // 1 new-stack page = 4. The full success remap is proven by the QEMU
            // exec /init variant.
            let new_image = crate::elf::LoadedElf::for_test(0x1000, &[]);
            let remapped = exec_replace_context(
                &new_image,
                new_stack_phys + page::PAGE_SIZE,
                new_stack_phys,
                1,
            );
            assert!(!remapped, "bare-table remap cannot shatter the stack MB");

            let free_after = page::free_count();
            assert_eq!(
                free_after,
                free_before + 4,
                "exec frees 1 mmap + 1 heap + 1 old-image (#502 teardown) + 1 new-stack (failure path)"
            );

            let procs_ro = &*core::ptr::addr_of!(PROCS);
            let proc = procs_ro[0].as_ref().unwrap();
            assert!(
                proc.mappings.iter().all(|m| m.is_none()),
                "mappings must be cleared"
            );
            assert_eq!(
                proc.heap_break, DEFAULT_HEAP_BREAK,
                "heap break must reset to default"
            );
        }
    }

    /// kinit (PID 0) must have UID 0 (root).
    #[test]
    fn getuid_returns_zero_for_init() {
        // SAFETY: test-only; reset_all reinitialises global state.
        unsafe {
            reset_all();
            let procs = &mut *core::ptr::addr_of_mut!(PROCS);
            let pt = mmu::alloc_addr_space().unwrap();
            procs[0] = Some(test_process(pt));
            CURRENT = 0;
            assert_eq!(current_uid(), Some(0), "kinit (PID 0) must have UID 0");
        }
    }

    /// A missing PCB slot must fail closed: `current_uid` must never
    /// resolve an absent process to UID 0 (root), since every caller of
    /// `current_uid` would then treat a scheduler-invariant gap as full
    /// privilege (issue #282, process.rs).
    #[test]
    fn getuid_returns_none_when_pcb_absent_never_zero() {
        // SAFETY: test-only; reset_all reinitialises global state and
        // leaves every PROCS slot empty.
        unsafe {
            reset_all();
            CURRENT = 0;
            assert_eq!(
                current_uid(),
                None,
                "an absent PCB must fail closed with None, never fall back to UID 0"
            );
        }
    }

    /// `set_wake_tick` transitions the process to Sleeping with the correct tick.
    #[test]
    fn nanosleep_sets_wake_time() {
        // SAFETY: test-only; reset_all reinitialises global state.
        unsafe {
            reset_all();
            let procs = &mut *core::ptr::addr_of_mut!(PROCS);
            let pt = mmu::alloc_addr_space().unwrap();
            procs[0] = Some(test_process(pt));
            CURRENT = 0;

            let target_tick: u64 = 12345;
            set_wake_tick(target_tick);

            let procs_ro = &*core::ptr::addr_of!(PROCS);
            let p = procs_ro[0].as_ref().unwrap();
            assert_eq!(
                p.state,
                State::Sleeping,
                "process must be Sleeping after set_wake_tick"
            );
            assert_eq!(
                p.wake_tick, target_tick,
                "wake_tick must match the requested value"
            );
        }
    }

    /// `clear_wake_tick` returns the process to Running state.
    #[test]
    fn clear_wake_tick_restores_running() {
        // SAFETY: test-only; reset_all reinitialises global state.
        unsafe {
            reset_all();
            let procs = &mut *core::ptr::addr_of_mut!(PROCS);
            let pt = mmu::alloc_addr_space().unwrap();
            procs[0] = Some(test_process(pt));
            CURRENT = 0;

            set_wake_tick(9999);
            clear_wake_tick();

            let procs_ro = &*core::ptr::addr_of!(PROCS);
            let p = procs_ro[0].as_ref().unwrap();
            assert_eq!(
                p.state,
                State::Running,
                "process must return to Running after clear_wake_tick"
            );
            assert_eq!(p.wake_tick, 0, "wake_tick must be reset to 0");
        }
    }

    /// `schedule()`'s first pass wakes a Sleeping process once its `wake_tick` has
    /// elapsed (`now >= wake_tick`), transitioning it to Ready; a process whose
    /// `wake_tick` has NOT yet elapsed must stay Sleeping. `exceptions::ticks()`
    /// is only ever written FROM the real timer IRQ handler, so it reads 0 for
    /// the life of the host test binary -- `wake_tick` 0 is therefore already due.
    #[test]
    fn schedule_wakes_sleeping_process_past_wake_tick() {
        // SAFETY: test-only; reset_all reinitialises global state. Single-threaded
        // test execution ensures no concurrent access to PROCS or CURRENT.
        unsafe {
            reset_all();
            let procs = &mut *core::ptr::addr_of_mut!(PROCS);

            let pt0 = mmu::alloc_addr_space().unwrap_or_default();
            procs[0] = Some(Process {
                state: State::Sleeping,
                ..test_process(pt0)
            });

            let pt1 = mmu::alloc_addr_space().unwrap_or_default();
            procs[1] = Some(Process {
                pid: 1,
                state: State::Sleeping,
                parent: Some(0),
                wake_tick: u64::MAX,
                ..test_process(pt1)
            });
            CURRENT = 0;

            schedule();

            assert_eq!(
                get_state(0),
                Some(State::Ready),
                "a Sleeping process whose wake_tick has elapsed must transition to Ready"
            );
            assert_eq!(
                get_state(1),
                Some(State::Sleeping),
                "a Sleeping process whose wake_tick has NOT elapsed must remain Sleeping"
            );
        }
    }
    // -----------------------------------------------------------------------
    // Signal integration tests (REQ-08, REQ-14)
    // These live in process.rs because crate::process is #[cfg(not(test))]
    // gated in main.rs, making it unavailable to signal.rs tests.
    // -----------------------------------------------------------------------

    #[test]
    fn sigaction_registers_handler() {
        // SAFETY: test-only; reset_all reinitialises global state.
        unsafe {
            reset_all();
            let procs = &mut *core::ptr::addr_of_mut!(PROCS);
            let pt = mmu::alloc_addr_space().unwrap();
            procs[0] = Some(test_process(pt));
            CURRENT = 0;

            let handler_addr: u32 = 0x4020_0000;
            let stored = get_signal_action(crate::signal::Signal::Sigusr1);
            assert_eq!(
                stored,
                crate::signal::SignalAction::Default,
                "initial action should be Default"
            );

            set_signal_action(
                crate::signal::Signal::Sigusr1,
                crate::signal::SignalAction::Handler(handler_addr),
            );
            let stored2 = get_signal_action(crate::signal::Signal::Sigusr1);
            assert_eq!(
                stored2,
                crate::signal::SignalAction::Handler(handler_addr),
                "handler should be stored in PCB"
            );
        }
    }

    #[test]
    fn kill_sets_pending_bit() {
        // SAFETY: test-only; reset_all reinitialises global state.
        unsafe {
            reset_all();
            let procs = &mut *core::ptr::addr_of_mut!(PROCS);
            let pt = mmu::alloc_addr_space().unwrap();
            procs[0] = Some(test_process(pt));
            CURRENT = 0;

            // Target a non-zero PID (#269 guards PID 0 against deliver_signal_to).
            let child_pid = fork().unwrap_or_default();

            // Install a handler so kill marks it pending (not terminate).
            CURRENT = child_pid;
            let handler_addr: u32 = 0x4020_0000;
            set_signal_action(
                crate::signal::Signal::Sigusr1,
                crate::signal::SignalAction::Handler(handler_addr),
            );
            CURRENT = 0;

            let ret = deliver_signal_to(child_pid, crate::signal::Signal::Sigusr1);
            assert_eq!(ret, 0, "deliver_signal_to should succeed");

            let pending = get_pending_mask(child_pid);
            let expected_bit = 1u32 << (crate::signal::Signal::Sigusr1 as u32);
            assert_ne!(
                pending & expected_bit,
                0,
                "SIGUSR1 pending bit should be set after kill"
            );
        }
    }

    #[test]
    fn check_pending_signal_returns_handler() {
        // SAFETY: test-only; reset_all reinitialises global state. Single-threaded
        // test execution ensures no concurrent access to PROCS or CURRENT.
        unsafe {
            reset_all();
            let procs = &mut *core::ptr::addr_of_mut!(PROCS);
            let pt = mmu::alloc_addr_space().unwrap();
            procs[0] = Some(test_process(pt));
            CURRENT = 0;

            let child_pid = fork().unwrap_or_default();

            // NOTE: install the handler on the child (set_signal_action acts on CURRENT).
            CURRENT = child_pid;
            let handler_addr: u32 = 0x4020_0000;
            set_signal_action(
                crate::signal::Signal::Sigusr1,
                crate::signal::SignalAction::Handler(handler_addr),
            );
            CURRENT = 0;

            // WHY: with a Handler action installed, deliver_signal_to marks the
            // signal pending (rather than applying the default Terminate).
            let ret = deliver_signal_to(child_pid, crate::signal::Signal::Sigusr1);
            assert_eq!(ret, 0, "deliver_signal_to should succeed");

            // NOTE: check_pending_signal reads CURRENT's state — switch to the
            // child as the exception-return path does after scheduling it.
            CURRENT = child_pid;
            let result = check_pending_signal();
            assert_eq!(
                result,
                Some((crate::signal::Signal::Sigusr1, handler_addr)),
                "a pending signal with a Handler action must yield (sig, handler_addr)"
            );
        }
    }

    #[test]
    fn check_pending_signal_none_when_clear() {
        // SAFETY: test-only; reset_all reinitialises global state.
        unsafe {
            reset_all();
            let procs = &mut *core::ptr::addr_of_mut!(PROCS);
            let pt = mmu::alloc_addr_space().unwrap();
            procs[0] = Some(test_process(pt));
            CURRENT = 0;

            let result = check_pending_signal();
            assert_eq!(result, None, "no pending signal must yield None");
        }
    }

    #[test]
    fn default_action_terminates() {
        // SAFETY: test-only; reset_all reinitialises global state.
        unsafe {
            reset_all();
            let procs = &mut *core::ptr::addr_of_mut!(PROCS);
            let pt = mmu::alloc_addr_space().unwrap();
            procs[0] = Some(test_process(pt));
            CURRENT = 0;

            // Target a non-zero PID (#269 guards PID 0 against deliver_signal_to).
            let child_pid = fork().unwrap_or_default();

            // No handler for SIGTERM — default is Terminate.
            let ret = deliver_signal_to(child_pid, crate::signal::Signal::Sigterm);
            assert_eq!(ret, 0, "deliver_signal_to should return 0");

            let state = get_state(child_pid);
            assert_eq!(
                state,
                Some(State::Dead),
                "process should be Dead after default SIGTERM"
            );
        }
    }

    #[test]
    fn sigchld_default_ignored() {
        // SAFETY: test-only; reset_all reinitialises global state.
        unsafe {
            reset_all();
            let procs = &mut *core::ptr::addr_of_mut!(PROCS);
            let pt = mmu::alloc_addr_space().unwrap();
            procs[0] = Some(test_process(pt));
            CURRENT = 0;

            // Target a non-zero PID (#269 guards PID 0 against deliver_signal_to).
            let child_pid = fork().unwrap_or_default();
            let state_before = get_state(child_pid);

            // No handler for SIGCHLD — default is Ignore.
            let ret = deliver_signal_to(child_pid, crate::signal::Signal::Sigchld);
            assert_eq!(ret, 0, "deliver_signal_to should return 0");

            let state = get_state(child_pid);
            assert_eq!(
                state, state_before,
                "process state should be unchanged after default-Ignore SIGCHLD"
            );

            let pending = get_pending_mask(child_pid);
            let sigchld_bit = 1u32 << (crate::signal::Signal::Sigchld as u32);
            assert_eq!(
                pending & sigchld_bit,
                0,
                "SIGCHLD should not be pending when default action is Ignore"
            );
        }
    }

    // -----------------------------------------------------------------------
    // fork() stack-isolation tests (#208)
    // These pin the invariants the #208 defect violated: the child ran on the
    // PARENT's stack (ctx.sp inherited verbatim) and exit_cleanup freed the
    // wrong pages. The host cannot execute the context switch (a no-op stub),
    // but it can verify these PCB/allocator invariants directly.
    // -----------------------------------------------------------------------

    /// Install PID 0 with a REAL allocated `STACK_PAGES` stack whose saved sp
    /// sits `sp_page_offset` pages FROM the stack base. Returns
    /// `(stack_base, sp)`.
    ///
    /// WHY: the #208 tests need a parent whose stack is a concrete physical
    /// region so the child's sp can be checked against it — the default proc 0
    /// runs on the boot stack (`stack_pages` == 0) and has no range to alias.
    unsafe fn install_parent_with_stack(sp_page_offset: usize) -> (usize, u32) {
        // SAFETY: test-only; caller has run reset_all(). Single-threaded test
        // execution ensures no concurrent access to PROCS or CURRENT.
        unsafe {
            let procs = &mut *core::ptr::addr_of_mut!(PROCS);
            let pt = mmu::alloc_addr_space().unwrap();
            let mut stack_base = 0usize;
            for i in 0..STACK_PAGES {
                let pg = page::alloc_page().unwrap();
                if i == 0 {
                    stack_base = pg;
                }
            }
            let sp = (stack_base + sp_page_offset * page::PAGE_SIZE) as u32;
            let mut ctx = Context::zero();
            ctx.sp = sp;
            procs[0] = Some(Process {
                ctx,
                stack_base,
                stack_pages: STACK_PAGES,
                ..test_process(pt)
            });
            CURRENT = 0;
            (stack_base, sp)
        }
    }

    /// #208 invariant 1: the child's sp lands in the child's OWN stack, NOT the
    /// parent's, and preserves the parent's offset-within-stack.
    #[test]
    fn fork_child_sp_in_own_stack_not_parent() {
        // SAFETY: test-only; reset_all reinitialises global state. Single-threaded.
        unsafe {
            reset_all();
            let (parent_base, parent_sp) = install_parent_with_stack(3);
            let parent_top = parent_base + STACK_PAGES * page::PAGE_SIZE;

            let child_pid = fork().unwrap_or_default();
            let procs = &*core::ptr::addr_of!(PROCS);
            let child = procs[usize::from(child_pid)].as_ref().unwrap();
            let child_base = child.stack_base;
            let child_top = child_base + STACK_PAGES * page::PAGE_SIZE;
            let child_sp = child.ctx.sp as usize;

            // Half-open: within the child's own stack region.
            assert!(
                child_sp >= child_base && child_sp < child_top,
                "child.ctx.sp must lie within [child.stack_base, +STACK_PAGES)"
            );
            // The #208 corruption: sp must NOT alias the parent's stack.
            assert!(
                child_sp < parent_base || child_sp >= parent_top,
                "child.ctx.sp must NOT alias the parent's stack (#208)"
            );
            // Offset-within-stack preserved -> same frame depth as the parent.
            assert_eq!(
                child_sp - child_base,
                parent_sp as usize - parent_base,
                "child sp must preserve the parent's offset-within-stack"
            );
        }
    }

    /// #208 invariant 2: the child's stack pages are distinct physical pages
    /// FROM the parent's — no aliasing of the parent stack.
    #[test]
    fn fork_child_stack_pages_distinct_from_parent() {
        // SAFETY: test-only; reset_all reinitialises global state. Single-threaded.
        unsafe {
            reset_all();
            let (parent_base, _sp) = install_parent_with_stack(2);
            let parent_top = parent_base + STACK_PAGES * page::PAGE_SIZE;

            let child_pid = fork().unwrap_or_default();
            let procs = &*core::ptr::addr_of!(PROCS);
            let child = procs[usize::from(child_pid)].as_ref().unwrap();
            let child_base = child.stack_base;
            let child_top = child_base + STACK_PAGES * page::PAGE_SIZE;

            assert_ne!(
                child_base, parent_base,
                "child stack must start at a different physical page"
            );
            // Ranges must not overlap in either direction.
            assert!(
                child_top <= parent_base || parent_top <= child_base,
                "child stack pages must be physically distinct from the parent's"
            );
        }
    }

    /// #208 invariant 3: fork then `exit_cleanup(child)` returns EXACTLY
    /// `STACK_PAGES` pages, leaves the parent's stack pages untouched, and the
    /// second free of the child's stack is a rejected no-op (no double-free).
    #[test]
    fn fork_then_exit_frees_exactly_child_stack() {
        // SAFETY: test-only; reset_all reinitialises global state. Single-threaded.
        unsafe {
            reset_all();
            let (parent_base, _sp) = install_parent_with_stack(3);

            let child_pid = fork().unwrap_or_default();
            let child_base = {
                let procs = &*core::ptr::addr_of!(PROCS);
                procs[usize::from(child_pid)].as_ref().unwrap().stack_base
            };

            // Free count AFTER fork: both parent and child stacks are allocated.
            let free_before = page::free_count();

            CURRENT = child_pid;
            exit_cleanup(0);

            let free_after = page::free_count();
            // Exactly the child's STACK_PAGES returned — not 0 (wrong pages
            // freed), not 2x (parent's freed too).
            assert_eq!(
                free_after - free_before,
                STACK_PAGES,
                "exit_cleanup must return exactly the child's STACK_PAGES"
            );

            // Double-free guard: the child's stack is already free, so a second
            // free is a rejected no-op that does not inflate the pool (#208's
            // potential double-free).
            let count = page::free_count();
            assert!(
                !page::try_free_page(child_base),
                "double-free of the child stack must be rejected"
            );
            assert_eq!(
                page::free_count(),
                count,
                "a rejected free must not change the free-page count"
            );

            // The parent's stack pages were NOT touched by the child's exit:
            // parent_base is still allocated, so try_free_page succeeds here
            // (returns true) — had the child freed the parent's stack, this page
            // would already be free and the call would be rejected.
            assert!(
                page::try_free_page(parent_base),
                "parent stack page must remain allocated after the child exits (#208)"
            );
        }
    }

    /// #269: kinit (PID 0) must never be a valid `deliver_signal_to` target,
    /// even for SIGKILL.
    #[test]
    fn deliver_signal_to_rejects_pid_zero() {
        unsafe {
            reset_all();
            let procs = &mut *core::ptr::addr_of_mut!(PROCS);
            let pt = mmu::alloc_addr_space().unwrap();
            procs[0] = Some(test_process(pt));
            CURRENT = 0;

            const EPERM: u32 = 0u32.wrapping_sub(1);
            let ret = deliver_signal_to(0, crate::signal::Signal::Sigkill);
            assert_eq!(ret, EPERM, "deliver_signal_to(0, ...) must return EPERM");

            let state = get_state(0);
            assert_eq!(state, Some(State::Running), "PID 0 must stay alive");
        }
    }

    #[test]
    fn sigkill_frees_futex_waiter_slots_for_dying_pid() {
        // SAFETY: test-only; reset_all reinitialises global state. nextest
        // runs each test in its own process, so FUTEX_WAITERS also starts
        // zeroed here (#364).
        unsafe {
            reset_all();
            let procs = &mut *core::ptr::addr_of_mut!(PROCS);
            let pt = mmu::alloc_addr_space().unwrap();
            procs[0] = Some(test_process(pt));
            CURRENT = 0;

            let child_pid = fork().unwrap_or_default();

            // Simulate the child being blocked in sys_futex_wait when
            // killed — seed a waiter slot for it directly, bypassing the
            // host-untestable #[cfg(not(test))] block path in
            // sys_futex_wait.
            crate::futex::insert_waiter_for_test(0x1000, u32::from(child_pid));
            assert!(
                crate::futex::has_waiter_for_pid(u32::from(child_pid)),
                "waiter must be seeded before the kill"
            );

            let ret = deliver_signal_to(child_pid, crate::signal::Signal::Sigkill);
            assert_eq!(ret, 0, "SIGKILL delivery should succeed");

            assert!(
                !crate::futex::has_waiter_for_pid(u32::from(child_pid)),
                "SIGKILL must free the dying process's futex waiter slot"
            );
        }
    }

    #[test]
    fn sigkill_releases_the_dying_pids_supervised_claim() {
        // #492: a KILLED service files no fault report and never runs
        // exit_cleanup, so the signal path is the ONLY place that can release its
        // supervised claim. Without this, the claim outlives the process and a
        // later fault on the REUSED pid resolves to the dead service -- the
        // pid-reuse misattribution the fault-time resolution + exit_cleanup's
        // clear_pid close on the other two death paths.
        // SAFETY: test-only; reset_all reinitialises global state; nextest runs
        // each test in its own process.
        unsafe {
            reset_all();
            crate::supervisor::reset();
            let procs = &mut *core::ptr::addr_of_mut!(PROCS);
            let pt = mmu::alloc_addr_space().unwrap();
            procs[0] = Some(test_process(pt));
            CURRENT = 0;

            let child_pid = fork().unwrap_or_default();
            crate::supervisor::register("/svc", child_pid);

            let ret = deliver_signal_to(child_pid, crate::signal::Signal::Sigkill);
            assert_eq!(ret, 0, "SIGKILL delivery should succeed");

            // The pid is now reusable: a fault on it must resolve to NOTHING.
            crate::supervisor::report_fault(child_pid, 1, 0, 0);
            let report = crate::supervisor::pop_report().expect("report");
            assert_eq!(
                report.service, None,
                "SIGKILL must release the supervised claim, so a reused pid cannot \
                 misattribute a later fault to the killed service"
            );
        }
    }

    /// #269: `sys_kill` must reject PID 0 outright, even for a self-signal
    /// from kinit, before any capability check.
    #[test]
    fn sys_kill_rejects_pid_zero_even_for_self() {
        unsafe {
            reset_all();
            let procs = &mut *core::ptr::addr_of_mut!(PROCS);
            let pt = mmu::alloc_addr_space().unwrap();
            procs[0] = Some(test_process(pt));
            CURRENT = 0;

            const EPERM: u32 = 0u32.wrapping_sub(1);
            let ret = crate::signal::sys_kill(0, crate::signal::Signal::Sigkill as u32);
            assert_eq!(
                ret, EPERM,
                "sys_kill(0, ...) must return EPERM regardless of caller"
            );
        }
    }

    /// #379 (REQ-09): a process without `CAP_KILL` may not signal a
    /// different, non-zero process -- `sys_kill` must return EPERM and the
    /// target must be left untouched.
    #[test]
    fn sys_kill_cross_process_denied_without_cap_kill() {
        unsafe {
            reset_all();
            let procs = &mut *core::ptr::addr_of_mut!(PROCS);

            let pt1 = mmu::alloc_addr_space().unwrap();
            procs[1] = Some(Process {
                pid: 1,
                parent: Some(0),
                uid: 1,
                // No KILL bit -- mirrors capability::tests::kill_requires_cap_kill's
                // "process without KILL cap" fixture.
                capabilities: crate::capability::Capabilities::CRYPTO
                    | crate::capability::Capabilities::RADIO,
                ..test_process(pt1)
            });

            let pt2 = mmu::alloc_addr_space().unwrap();
            procs[2] = Some(Process {
                pid: 2,
                parent: Some(0),
                uid: 2,
                capabilities: crate::capability::Capabilities::FORK_DEFAULT,
                ..test_process(pt2)
            });
            CURRENT = 1;

            const EPERM: u32 = 0u32.wrapping_sub(1);
            let ret = crate::signal::sys_kill(2, crate::signal::Signal::Sigterm as u32);
            assert_eq!(
                ret, EPERM,
                "sys_kill from a process without CAP_KILL targeting a different PID must return EPERM"
            );

            let procs = &*core::ptr::addr_of!(PROCS);
            assert_eq!(
                procs[2].as_ref().map(|p| p.state),
                Some(State::Running),
                "the denied kill must not touch the target process's state"
            );
        }
    }

    /// #379 (REQ-09): a process holding `CAP_KILL` may signal a different,
    /// non-zero process -- `sys_kill` succeeds and the default action
    /// (SIGTERM -> terminate) is applied to the target.
    #[test]
    fn sys_kill_cross_process_allowed_with_cap_kill() {
        unsafe {
            reset_all();
            let procs = &mut *core::ptr::addr_of_mut!(PROCS);

            let pt1 = mmu::alloc_addr_space().unwrap();
            procs[1] = Some(Process {
                pid: 1,
                parent: Some(0),
                uid: 1,
                capabilities: crate::capability::Capabilities::KILL,
                ..test_process(pt1)
            });

            let pt2 = mmu::alloc_addr_space().unwrap();
            procs[2] = Some(Process {
                pid: 2,
                parent: Some(0),
                uid: 2,
                capabilities: crate::capability::Capabilities::FORK_DEFAULT,
                ..test_process(pt2)
            });
            CURRENT = 1;

            let ret = crate::signal::sys_kill(2, crate::signal::Signal::Sigterm as u32);
            assert_eq!(
                ret, 0,
                "sys_kill from a process holding CAP_KILL targeting a different PID must succeed"
            );

            let procs = &*core::ptr::addr_of!(PROCS);
            assert_eq!(
                procs[2].as_ref().map(|p| p.state),
                Some(State::Dead),
                "SIGTERM's default action (terminate) must be applied to the target"
            );
        }
    }

    /// #371: `sys_send` (`Syscall::Send`) targeting PID 0 must be denied when
    /// the sender lacks `CAP_IPC_INIT`, and the message must not be
    /// delivered into kinit's inbox.
    #[test]
    fn sys_send_to_pid_zero_denied_without_ipc_init_cap() {
        unsafe {
            reset_all();
            let procs = &mut *core::ptr::addr_of_mut!(PROCS);

            let pt0 = mmu::alloc_addr_space().unwrap();
            procs[0] = Some(test_process(pt0));

            let pt1 = mmu::alloc_addr_space().unwrap();
            procs[1] = Some(Process {
                pid: 1,
                parent: Some(0),
                uid: 1,
                // Generic fork-default userspace process: no CAP_IPC_INIT.
                capabilities: crate::capability::Capabilities::FORK_DEFAULT,
                ..test_process(pt1)
            });
            CURRENT = 1;

            let ret = crate::syscall::dispatch(crate::syscall::Syscall::Send.as_u32(), 0, 42, 0, 0);
            assert_eq!(
                ret,
                u32::MAX,
                "send to PID 0 without CAP_IPC_INIT must be denied"
            );

            CURRENT = 0;
            assert!(
                crate::ipc::recv().is_none(),
                "denied send must not deliver a message into PID 0's inbox"
            );
        }
    }

    /// #371: a process explicitly granted `CAP_IPC_INIT` may message PID 0,
    /// and the delivered message carries the sender's PID and tag.
    #[test]
    fn sys_send_to_pid_zero_allowed_with_ipc_init_cap() {
        unsafe {
            reset_all();
            let procs = &mut *core::ptr::addr_of_mut!(PROCS);

            let pt0 = mmu::alloc_addr_space().unwrap();
            procs[0] = Some(test_process(pt0));

            let pt1 = mmu::alloc_addr_space().unwrap();
            procs[1] = Some(Process {
                pid: 1,
                parent: Some(0),
                uid: 1,
                capabilities: crate::capability::Capabilities::IPC_INIT,
                ..test_process(pt1)
            });
            CURRENT = 1;

            let ret = crate::syscall::dispatch(crate::syscall::Syscall::Send.as_u32(), 0, 42, 0, 0);
            assert_eq!(ret, 0, "send to PID 0 with CAP_IPC_INIT must succeed");

            CURRENT = 0;
            let msg = crate::ipc::recv();
            assert!(
                msg.is_some(),
                "allowed send must deliver a message into PID 0's inbox"
            );
            assert_eq!(
                msg.map(|m| (m.tag, m.from)),
                Some((42, 1)),
                "delivered message must carry the sender's tag and PID"
            );
        }
    }
}
