//! Process abstraction, context switching, and two-process isolation.
//!
//! Each process has a saved register context, a stack, a process ID,
//! a state, and its own L1 page table. The scheduler selects the next
//! ready process and context-switches to it on each timer tick, swapping
//! TTBR0 so each process has an independent virtual address space.
//!
//! On ARMv7 (#465), a context switch is a FULL trap-frame swap: the exception
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
    /// Sleeping until wake_tick (set by nanosleep).
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
    /// POSIX protection flags (PROT_READ | PROT_WRITE | PROT_EXEC).
    pub prot: u32,
}

/// Default initial program break for new processes.
/// WHY: 0x1000_0000 is above device MMIO (0x0-0x2FFF_FFFF) but below DRAM
/// (0x4000_0000), providing a clean region for the user heap that won't
/// conflict with kernel data structures or device mappings.
pub(crate) const DEFAULT_HEAP_BREAK: usize = 0x1000_0000;

/// Base address for mmap allocations, above the heap region.
/// WHY: 0x2000_0000 provides 256 MB of VA space for mmap before hitting
/// the modem region, keeping mmap and brk regions non-overlapping.
pub(crate) const MMAP_BASE: usize = 0x2000_0000;

/// Process control block.
pub(crate) struct Process {
    // kanon:ignore RUST/struct-too-many-fields -- standard Unix PCB fields; each models a distinct process resource
    pub pid: Pid,
    pub state: State,
    pub ctx: Context,
    /// Parent PID, if this process was created via fork().
    pub parent: Option<Pid>,
    /// Exit status SET by exit_with_status() / exit_cleanup().
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
    /// Only meaningful when state == Sleeping. Set by sys_nanosleep;
    /// the scheduler transitions the process to Ready when ticks() >= wake_tick.
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
        };

        procs[slot] = Some(proc);
        Some(pid)
    }
}

/// Create a child process by cloning the current process's address space.
/// Returns Some(child_pid) to the parent on success, or None on OOM.
///
/// NOTE: unlike POSIX fork(), both parent and child continue FROM the next
/// scheduler tick. The child inherits the parent's saved context exactly.
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

        // Get parent's page table
        let parent_pt = procs[usize::from(parent_pid)]
            .as_ref()
            .map(|p| p.page_table_phys)
            .unwrap_or(0);

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

        // Inherit parent context and memory layout (child resumes FROM same saved state)
        let parent_ref = procs[usize::from(parent_pid)].as_ref();
        let parent_ctx = parent_ref.map(|p| p.ctx).unwrap_or_else(Context::zero);
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
        let mut child_ctx = parent_ctx;
        child_ctx.sp = translate_stack_pointer(
            parent_ctx.sp,
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

/// Notify kinit (PID 0) that process `faulting_pid` has faulted.
/// Marks the faulting process Dead and delivers a fault message to PID 0's inbox.
///
/// Payload layout (9 bytes): [pid:1, fault_addr:4 LE, fault_status:4 LE]
pub(crate) fn notify_fault(faulting_pid: Pid, kind: FaultKind) {
    let (tag, fault_addr, fault_status) = match kind {
        FaultKind::DataAbort {
            fault_addr,
            fault_status,
        } => (1u32, fault_addr, fault_status),
        FaultKind::PrefetchAbort {
            fault_addr,
            fault_status,
        } => (2u32, fault_addr, fault_status),
        FaultKind::UndefinedInstruction => (3u32, 0u32, 0u32),
    };

    let payload: [u8; 9] = [
        faulting_pid,
        (fault_addr & 0xFF) as u8,
        ((fault_addr >> 8) & 0xFF) as u8,
        ((fault_addr >> 16) & 0xFF) as u8,
        ((fault_addr >> 24) & 0xFF) as u8,
        (fault_status & 0xFF) as u8,
        ((fault_status >> 8) & 0xFF) as u8,
        ((fault_status >> 16) & 0xFF) as u8,
        ((fault_status >> 24) & 0xFF) as u8,
    ];

    let msg = ipc::Message::new(tag, &payload);

    // SAFETY: current process PCB pointer is valid; set by the scheduler on
    // context switch. Temporarily mutating CURRENT to deliver the fault message
    // with the faulting PID as sender; CURRENT is restored before returning.
    let sent = unsafe {
        let procs = &mut *addr_of_mut!(PROCS);
        if let Some(ref mut proc) = procs[usize::from(faulting_pid)] {
            proc.state = State::Dead;
            // #267: a faulted process never reaches exit_cleanup -- release
            // its fds here so OFDs (and pipe/socket ends) do not leak.
            crate::fd::close_all(&mut proc.fds);
        }
        // WHY: ipc::send stamps msg.from = current_pid(); temporarily set CURRENT
        // to faulting_pid so the message arrives with the correct sender identity.
        let saved = CURRENT;
        CURRENT = faulting_pid;
        let sent = ipc::send(0, msg).is_ok();
        CURRENT = saved;
        sent
    };

    // WHY: kinit (PID 0) is the userspace fault supervisor; a full inbox
    // means this fault notification is silently lost and the Dead process
    // (already marked above) is never reaped (#252). Surface the drop on
    // UART, matching the CAPDEN diagnostic pattern in capability.rs.
    if !sent {
        use core::fmt::Write;

        use crate::uart::Uart;
        let mut serial = Uart::new();
        write!(
            serial,
            "FAULTDROP pid={faulting_pid} tag={tag} kinit-inbox-full\r\n"
        )
        .ok();
    }
}

/// Perform exit teardown without the diverging `-> !` signature.
/// Marks the process Dead, reclaims its page table, and frees stack pages.
pub(crate) fn exit_cleanup(status: i32) {
    // SAFETY: current process PCB pointer is valid; set by the scheduler on
    // context switch. Page table and stack pages are reclaimed only after
    // marking the process Dead; mmu::free_addr_space validates its input.
    unsafe {
        let cur = usize::from(CURRENT);
        let procs = &mut *addr_of_mut!(PROCS);
        if let Some(ref mut proc) = procs[cur] {
            proc.exit_status = status;
            proc.state = State::Dead;

            // #267: close-on-exit is mandatory -- drop every fd reference,
            // releasing shared OFDs (and pipe/socket ends) at refcount zero.
            crate::fd::close_all(&mut proc.fds);

            // Reclaim page table (but never free the kernel's global L1)
            let pt = proc.page_table_phys;
            if pt != 0 && pt != mmu::table_base() {
                mmu::free_addr_space(pt);
            }
            proc.page_table_phys = 0;

            // Free stack pages
            let base = proc.stack_base;
            let pages = proc.stack_pages;
            proc.stack_pages = 0;
            for i in 0..pages {
                page::free_page(base + i * page::PAGE_SIZE);
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
/// read PROCS without a lock on single-core ARMv7.
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
/// Also wakes any Sleeping processes whose wake_tick has been reached,
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
/// ACTIVE_FRAME.
///
/// # Safety
/// Must be called from trap context (ACTIVE_FRAME live) with interrupts masked.
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
/// EBADF, matching the current_uid() posture (#282).
///
/// INVARIANT: `f` must not re-enter process:: accessors -- PROCS is
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

/// Set the current process's wake_tick and transition it to Sleeping.
///
/// Called by sys_nanosleep after computing the target tick count.
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
/// Called by sys_nanosleep after the busy-wait loop confirms the wake tick
/// has elapsed. Resets wake_tick to 0 and marks the process Running again.
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
                }
                crate::signal::DefaultAction::Ignore => {}
            },
        }
        0
    }
}

/// Reset all signal handlers and the pending mask for the current process.
///
/// Called by sys_execve (POSIX: exec resets all signal dispositions to SIG_DFL
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
/// allocated and `entry_point` is the validated ELF entry address.
pub unsafe fn exec_replace_context(
    entry_point: usize,
    stack_top: usize,
    new_stack_base: usize,
    new_stack_pages: usize,
) {
    // SAFETY: addr_of_mut! avoids an intermediate reference to the static mut.
    // Called from execve syscall with interrupts disabled (SVC mode, ARMv7).
    unsafe {
        let procs = &mut *addr_of_mut!(PROCS);
        let cur = usize::from(CURRENT);
        if let Some(ref mut proc) = procs[cur] {
            // WHY cpsr 0x10 (User mode, IRQs enabled): execve transfers control
            // to an unprivileged userspace binary. Contrast with spawn() which
            // uses 0x1F (System mode) for kernel-internal threads. The full
            // register file is reset -- exec starts a fresh image, not a
            // continuation.
            // SAFETY: ARMv7 target has 32-bit usize; try_from cannot fail
            // in production. On 64-bit test hosts the addresses are
            // test-controlled and verified to fit via the test setup.
            proc.ctx = Context::initial(
                u32::try_from(entry_point).unwrap_or(0u32),
                u32::try_from(stack_top).unwrap_or(0u32),
                0x10,
            );
            // Free the old stack (replaced by exec).
            let old_base = proc.stack_base;
            let old_pages = proc.stack_pages;
            proc.stack_base = new_stack_base;
            proc.stack_pages = new_stack_pages;
            // WHY: free old pages AFTER updating PCB so that any fault during
            // free does not leave the PCB pointing at freed memory.
            for i in 0..old_pages {
                page::free_page(old_base + i * page::PAGE_SIZE);
            }

            // WHY (#225): the page table is REUSED across exec (same
            // page_table_phys), so the previous image's mmap regions and grown
            // heap pages are still mapped at their old virtual addresses. Unmap
            // and free each one before resetting the tracking state below, or
            // the physical frames leak permanently and the new image can read
            // the previous image's residual contents at the same VAs.
            let pt = proc.page_table_phys;
            for mapping in proc.mappings.iter().flatten() {
                for i in 0..mapping.pages {
                    let vaddr = mapping.start + i * page::PAGE_SIZE;
                    if let Some(phys) = mmu::read_l2_phys(pt, vaddr) {
                        mmu::unmap_page(pt, vaddr);
                        mmu::flush_tlb_page(vaddr);
                        page::free_page(phys);
                    }
                }
            }
            let old_heap_break = proc.heap_break;
            let mut heap_vaddr = DEFAULT_HEAP_BREAK;
            while heap_vaddr < old_heap_break {
                if let Some(phys) = mmu::read_l2_phys(pt, heap_vaddr) {
                    mmu::unmap_page(pt, heap_vaddr);
                    mmu::flush_tlb_page(heap_vaddr);
                    page::free_page(phys);
                }
                heap_vaddr += page::PAGE_SIZE;
            }

            // Reset heap break to default for the new image.
            proc.heap_break = DEFAULT_HEAP_BREAK;
            // Clear all tracked mmap mappings — the new image has a fresh VA space.
            proc.mappings = [None; MAX_MAPPINGS];
        }
    }
}

/// Clear the lowest-numbered pending signal for the current process.
/// Called by sys_sigreturn after the handler returns.
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

    /// fork() must NOT let the child inherit a signal that was pending in the
    /// parent at fork time: signal HANDLERS are inherited but the pending mask
    /// is cleared (process.rs fork(), `s.pending = 0`), matching POSIX
    /// fork() semantics.
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

    /// #251: an OOM partway through spawn()'s stack allocation must roll
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

    /// #251: an OOM partway through fork()'s child-stack allocation must roll
    /// back exactly the pages allocated so far. #208 rewrote fork()'s SUCCESS
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

    /// #232: waitpid must reject any PID >= MAX_PROCS instead of indexing
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

    /// #218/#224: fork/exit/waitpid MAX_PROCS times must leave every
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
    fn notify_fault_sends_to_pid0() {
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

            notify_fault(1, FaultKind::UndefinedInstruction);

            // PID 0 receives the message; tag must be 3 (UndefinedInstruction)
            CURRENT = 0;
            let msg =
                ipc::recv().expect("UndefinedInstruction fault must deliver a message to pid 0");
            assert_eq!(msg.tag, 3, "UndefinedInstruction tag must be 3");
            assert_eq!(
                msg.payload()[0],
                1u8,
                "first payload byte must be faulting PID"
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

    /// #225: exec_replace_context must unmap and free every previously
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

            // Capture the baseline AFTER allocating the new stack so the delta
            // measures exactly the frames exec frees, not the new stack alloc.
            let new_stack_phys = page::alloc_page().unwrap();
            let free_before = page::free_count();

            exec_replace_context(0x1000, new_stack_phys + page::PAGE_SIZE, new_stack_phys, 1);

            let free_after = page::free_count();
            assert_eq!(
                free_after,
                free_before + 2,
                "exec must free exactly the 1 mmap page + 1 heap page from the old image"
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

    /// set_wake_tick transitions the process to Sleeping with the correct tick.
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

    /// clear_wake_tick returns the process to Running state.
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

    /// schedule()'s first pass wakes a Sleeping process once its wake_tick has
    /// elapsed (`now >= wake_tick`), transitioning it to Ready; a process whose
    /// wake_tick has NOT yet elapsed must stay Sleeping. exceptions::ticks()
    /// is only ever written FROM the real timer IRQ handler, so it reads 0 for
    /// the life of the host test binary -- wake_tick 0 is therefore already due.
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

    /// #269: kinit (PID 0) must never be a valid deliver_signal_to target,
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

    /// #269: sys_kill must reject PID 0 outright, even for a self-signal
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

    /// #379 (REQ-09): a process without CAP_KILL may not signal a
    /// different, non-zero process -- sys_kill must return EPERM and the
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

    /// #379 (REQ-09): a process holding CAP_KILL may signal a different,
    /// non-zero process -- sys_kill succeeds and the default action
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

    /// #371: sys_send (Syscall::Send) targeting PID 0 must be denied when
    /// the sender lacks CAP_IPC_INIT, and the message must not be
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

    /// #371: a process explicitly granted CAP_IPC_INIT may message PID 0,
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
