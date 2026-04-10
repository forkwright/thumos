//! Process abstraction, context switching, and two-process isolation.
//!
//! Each process has a saved register context, a stack, a process ID,
//! a state, and its own L1 page table. The scheduler selects the next
//! ready process and context-switches to it on each timer tick, swapping
//! TTBR0 so each process has an independent virtual address space.
//!
//! On ARMv7, context switch saves/restores r4-r11 (callee-saved),
//! sp, lr, and cpsr. Registers r0-r3, r12, lr, pc, cpsr are saved
//! by the exception entry/exit code.

use crate::ipc;
use crate::mmu;
use crate::page;
use crate::signal::{Signal, SignalAction, SignalState};
use core::ptr::addr_of_mut;

/// Maximum number of processes.
const MAX_PROCS: usize = 16;

/// Process ID type.
pub type Pid = u8;

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

/// Saved CPU context for context switching.
/// Only callee-saved registers need explicit saving  -  the IRQ entry
/// stub already saves r0-r3, r12, lr on the IRQ stack.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Context {
    pub r4: u32,
    pub r5: u32,
    pub r6: u32,
    pub r7: u32,
    pub r8: u32,
    pub r9: u32,
    pub r10: u32,
    pub r11: u32,
    pub sp: u32,
    pub lr: u32,
    pub cpsr: u32,
}

impl Context {
    const fn zero() -> Self {
        Self {
            r4: 0,
            r5: 0,
            r6: 0,
            r7: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            sp: 0,
            lr: 0,
            cpsr: 0,
        }
    }
}

/// Maximum number of tracked anonymous mappings per process.
/// WHY: fixed-size array avoids heap allocation in the kernel's process table.
/// 32 mappings is sufficient for early userspace (libc typically needs ~10).
pub const MAX_MAPPINGS: usize = 32;

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
pub const DEFAULT_HEAP_BREAK: usize = 0x1000_0000;

/// Base address for mmap allocations, above the heap region.
/// WHY: 0x2000_0000 provides 256 MB of VA space for mmap before hitting
/// the modem region, keeping mmap and brk regions non-overlapping.
pub const MMAP_BASE: usize = 0x2000_0000;

/// Process control block.
pub struct Process {
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
}

/// Process table.
static mut PROCS: [Option<Process>; MAX_PROCS] = {
    const NONE: Option<Process> = None;
    [NONE; MAX_PROCS]
};

/// Currently running process ID.
static mut CURRENT: Pid = 0;

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
            stack_base: 0,                       // NOTE: uses the boot stack, not allocated
            stack_pages: 0,
            heap_break: DEFAULT_HEAP_BREAK,
            mappings: [None; MAX_MAPPINGS],
            signal_state: SignalState::new(),
            uid: 0,
            wake_tick: 0,
            // kinit (PID 0) has all capabilities (REQ-09).
            capabilities: crate::capability::Capabilities::ALL,
        };
        let procs = &mut *addr_of_mut!(PROCS);
        procs[0] = Some(proc0);
        CURRENT = 0;
    }
}

/// Create a new process that starts executing at `entry_point`.
/// Returns the PID, or None if the process table is full or OOM.
pub fn spawn(entry_point: fn() -> !) -> Option<Pid> {
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
        let mut stack_base: usize = 0;
        for i in 0..STACK_PAGES {
            match page::alloc_page() {
                Some(page) => {
                    if i == 0 { stack_base = page; }
                }
                None => {
                    // OOM: roll back already-allocated pages
                    for j in 0..i {
                        page::free_page(stack_base + j * page::PAGE_SIZE);
                    }
                    mmu::free_addr_space(new_pt);
                    return None;
                }
            }
        }
        let stack_top = stack_base + page::PAGE_SIZE * STACK_PAGES;

        // Set up initial context
        // WHY: "return address" is the entry point; first context switch lands here.
        let ctx = Context {
            r4: 0,
            r5: 0,
            r6: 0,
            r7: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            sp: stack_top as u32,
            lr: entry_point as u32,
            cpsr: 0x1F, // NOTE: system mode, IRQs enabled
        };

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
pub fn fork() -> Option<Pid> {
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
        let parent_pt = procs[usize::try_from(parent_pid).unwrap_or_default()]
            .as_ref()
            .map(|p| p.page_table_phys)
            .unwrap_or(0);

        // Allocate child address space
        let child_pt = mmu::alloc_addr_space()?;

        // Clone parent mappings INTO child (use kernel table as base if parent has none)
        let src_pt = if parent_pt == 0 { mmu::table_base() } else { parent_pt };
        mmu::clone_addr_space(src_pt, child_pt);

        // Allocate child stack pages
        let mut stack_base: usize = 0;
        for i in 0..STACK_PAGES {
            match page::alloc_page() {
                Some(page) => {
                    if i == 0 { stack_base = page; }
                }
                None => {
                    // OOM: roll back pages then table
                    for j in 0..i {
                        page::free_page(stack_base + j * page::PAGE_SIZE);
                    }
                    mmu::free_addr_space(child_pt);
                    return None;
                }
            }
        }

        // Inherit parent context and memory layout (child resumes FROM same saved state)
        let parent_ref = procs[usize::try_from(parent_pid).unwrap_or_default()].as_ref();
        let parent_ctx = parent_ref.map(|p| p.ctx).unwrap_or_else(Context::zero);
        let parent_break = parent_ref.map_or(DEFAULT_HEAP_BREAK, |p| p.heap_break);
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
        let parent_caps = parent_ref.map_or(crate::capability::Capabilities::FORK_DEFAULT, |p| p.capabilities);
        let child_caps = parent_caps & crate::capability::Capabilities::FORK_DEFAULT;

        let child = Process {
            pid: child_pid,
            state: State::Ready,
            ctx: parent_ctx,
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
        };

        procs[slot] = Some(child);
        Some(child_pid)
    }
}

/// Non-blocking wait for a child exit status.
/// Returns Some(status) if the child is Dead, None if still running or not a child.
pub fn waitpid(child_pid: Pid) -> Option<i32> {
    // SAFETY: current process PCB pointer is valid; set by the scheduler on
    // context switch. Read-only access via addr_of!; no mutation occurs here.
    unsafe {
        let procs = &*core::ptr::addr_of!(PROCS);
        let child = procs[usize::try_from(child_pid).unwrap_or_default()].as_ref()?;
        // INVARIANT: only the direct parent may retrieve the exit status.
        if child.parent != Some(CURRENT) {
            return None;
        }
        if child.state == State::Dead {
            Some(child.exit_status)
        } else {
            None
        }
    }
}

/// Notify kinit (PID 0) that process `faulting_pid` has faulted.
/// Marks the faulting process Dead and delivers a fault message to PID 0's inbox.
///
/// Payload layout (9 bytes): [pid:1, fault_addr:4 LE, fault_status:4 LE]
pub fn notify_fault(faulting_pid: Pid, kind: FaultKind) {
    let (tag, fault_addr, fault_status) = match kind {
        FaultKind::DataAbort { fault_addr, fault_status } => (1u32, fault_addr, fault_status),
        FaultKind::PrefetchAbort { fault_addr, fault_status } => (2u32, fault_addr, fault_status),
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
    unsafe {
        let procs = &mut *addr_of_mut!(PROCS);
        if let Some(ref mut proc) = procs[usize::try_from(faulting_pid).unwrap_or_default()] {
            proc.state = State::Dead;
        }
        // WHY: ipc::send stamps msg.from = current_pid(); temporarily set CURRENT
        // to faulting_pid so the message arrives with the correct sender identity.
        let saved = CURRENT;
        CURRENT = faulting_pid;
        ipc::send(0, msg);
        CURRENT = saved;
    }
}

/// Perform exit teardown without the diverging `-> !` signature.
/// Marks the process Dead, reclaims its page table, and frees stack pages.
pub(crate) fn exit_cleanup(status: i32) {
    // SAFETY: current process PCB pointer is valid; set by the scheduler on
    // context switch. Page table and stack pages are reclaimed only after
    // marking the process Dead; mmu::free_addr_space validates its input.
    unsafe {
        let cur = usize::try_from(CURRENT).unwrap_or_default();
        let procs = &mut *addr_of_mut!(PROCS);
        if let Some(ref mut proc) = procs[cur] {
            proc.exit_status = status;
            proc.state = State::Dead;

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
    }
}

/// Exit the current process with a given status code.
/// Tears down the address space and stack, then halts this process.
pub fn exit_with_status(status: i32) -> ! {
    exit_cleanup(status);
    #[cfg(target_arch = "arm")]
    // SAFETY: process has been marked Dead and its resources freed by
    // exit_cleanup. Switching to the kernel address space and spinning on
    // wfi is safe; this path never returns.
    unsafe {
        mmu::switch_addr_space(mmu::table_base());
        loop {
            core::arch::asm!("wfi");
        }
    }
    // WHY: non-ARM test builds diverge via unreachable! since ARM wfi is unavailable
    #[cfg(not(target_arch = "arm"))]
    unreachable!("exit_with_status called in non-ARM build")
}

/// Mark the current process as dead and yield to the scheduler.
/// Thin wrapper over exit_with_status for the zero-status case.
pub fn exit() -> ! {
    exit_with_status(0)
}

/// Get the current process ID.
pub fn current_pid() -> Pid {
    // SAFETY: CURRENT is a static mut Pid written only by the scheduler and
    // notify_fault. Read is atomic on ARM (single word); no torn read possible.
    unsafe { CURRENT }
}

/// Count processes in Ready or Running state.
///
/// Used by the power governor to decide how many cores to keep active.
/// Called from the timer IRQ handler with interrupts disabled — safe to
/// read PROCS without a lock on single-core ARMv7.
pub fn runnable_count() -> usize {
    // SAFETY: called from timer IRQ handler (single-core, IRQs disabled).
    // addr_of! avoids an intermediate reference to the static mut.
    unsafe {
        let procs = &*core::ptr::addr_of!(PROCS);
        procs.iter().flatten().filter(|p| {
            p.state == State::Ready || p.state == State::Running
        }).count()
    }
}

/// Simple round-robin scheduler. Called FROM the timer tick handler.
/// Returns the PID to switch to (may be the same as current).
///
/// Also wakes any Sleeping processes whose wake_tick has been reached,
/// transitioning them to Ready so they can be scheduled next tick.
pub fn schedule() -> Pid {
    // SAFETY: called from the timer IRQ handler with interrupts disabled on
    // a single-core ARMv7. PROCS is accessed exclusively via addr_of_mut!
    // to avoid intermediate references to the static mut.
    unsafe {
        let cur = usize::try_from(CURRENT).unwrap_or_default();
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

/// Perform a context switch FROM current process to `next_pid`.
/// Also switches TTBR0 so the next process gets its own address space.
///
/// # Safety
///
/// Must be called FROM the timer IRQ handler (in IRQ mode with
/// interrupts disabled).
pub unsafe fn switch_to(next_pid: Pid) {
    // SAFETY: register state was saved by the exception handler. Stack pointer
    // is valid for the target process. Called from the timer IRQ handler with
    // interrupts disabled; no concurrent access to PROCS or CURRENT.
    unsafe {
        let cur_pid = usize::try_from(CURRENT).unwrap_or_default();
        let next = usize::try_from(next_pid).unwrap_or_default();

        if cur_pid == next {
            return;
        }

        // Save current context
        let procs = &mut *addr_of_mut!(PROCS);
        if let Some(ref mut cur_proc) = procs[cur_pid] {
            save_context(&mut cur_proc.ctx);
            if cur_proc.state == State::Running {
                cur_proc.state = State::Ready;
            }
        }

        // Switch address space then restore next context
        if let Some(ref mut next_proc) = procs[next] {
            next_proc.state = State::Running;
            CURRENT = next_pid;
            // WHY: switch TTBR0 before executing any instruction in the new process
            if next_proc.page_table_phys != 0 {
                mmu::switch_addr_space(next_proc.page_table_phys);
            }
            restore_context(&next_proc.ctx);
        }
    }
}

/// Save callee-saved registers INTO the context struct.
#[inline(always)]
unsafe fn save_context(ctx: &mut Context) {
    #[cfg(target_arch = "arm")]
    // SAFETY: register state was saved by the exception handler. ctx points to
    // the current process's Context within PROCS, which is valid for the
    // duration of the IRQ handler. Offsets match the #[repr(C)] Context layout.
    unsafe {
        core::arch::asm!(
            "str r4, [{ctx}, #0]",
            "str r5, [{ctx}, #4]",
            "str r6, [{ctx}, #8]",
            "str r7, [{ctx}, #12]",
            "str r8, [{ctx}, #16]",
            "str r9, [{ctx}, #20]",
            "str r10, [{ctx}, #24]",
            "str r11, [{ctx}, #28]",
            "str sp, [{ctx}, #32]",
            "str lr, [{ctx}, #36]",
            "mrs {tmp}, cpsr",
            "str {tmp}, [{ctx}, #40]",
            ctx = in(reg) ctx as *mut Context,
            tmp = out(reg) _,
        );
    }
    // WHY: suppress unused-variable warning on non-ARM hosts
    #[cfg(not(target_arch = "arm"))]
    let _ = ctx;
}

/// Restore callee-saved registers FROM the context struct.
#[inline(always)]
unsafe fn restore_context(ctx: &Context) {
    #[cfg(target_arch = "arm")]
    // SAFETY: register state was saved by the exception handler. Stack pointer
    // is valid for the target process. ctx points to the next process's Context
    // within PROCS; address space has already been switched via TTBR0.
    unsafe {
        core::arch::asm!(
            "ldr r4, [{ctx}, #0]",
            "ldr r5, [{ctx}, #4]",
            "ldr r6, [{ctx}, #8]",
            "ldr r7, [{ctx}, #12]",
            "ldr r8, [{ctx}, #16]",
            "ldr r9, [{ctx}, #20]",
            "ldr r10, [{ctx}, #24]",
            "ldr r11, [{ctx}, #28]",
            "ldr sp, [{ctx}, #32]",
            "ldr lr, [{ctx}, #36]",
            "ldr {tmp}, [{ctx}, #40]",
            "msr cpsr_c, {tmp}",
            ctx = in(reg) ctx as *const Context,
            tmp = out(reg) _,
        );
    }
    // WHY: suppress unused-variable warning on non-ARM hosts
    #[cfg(not(target_arch = "arm"))]
    let _ = ctx;
}

// --- Memory management accessors ---
// WHY: syscall handlers need to read/modify the current process's heap break,
// page table, and mappings. These functions centralize access to the process
// table so syscall.rs doesn't need to manipulate PROCS directly.

/// Get the current process's page table physical address.
/// Returns 0 if the current process is not found (should not happen).
pub fn current_page_table() -> usize {
    // SAFETY: current process PCB pointer is valid; set by the scheduler on
    // context switch. Read-only access via addr_of!; no mutation occurs here.
    unsafe {
        let procs = &*core::ptr::addr_of!(PROCS);
        let cur = usize::try_from(CURRENT).unwrap_or_default();
        procs[cur].as_ref().map_or(0, |p| p.page_table_phys)
    }
}

/// Get the current process's heap break.
pub fn current_heap_break() -> usize {
    // SAFETY: current process PCB pointer is valid; set by the scheduler on
    // context switch. Read-only access via addr_of!; no mutation occurs here.
    unsafe {
        let procs = &*core::ptr::addr_of!(PROCS);
        let cur = usize::try_from(CURRENT).unwrap_or_default();
        procs[cur].as_ref().map_or(DEFAULT_HEAP_BREAK, |p| p.heap_break)
    }
}

/// Set the current process's heap break.
pub fn set_heap_break(new_break: usize) {
    // SAFETY: current process PCB pointer is valid; set by the scheduler on
    // context switch. Mutation via addr_of_mut! avoids an intermediate
    // reference to the static mut; called from syscall context (single-core).
    unsafe {
        let procs = &mut *addr_of_mut!(PROCS);
        let cur = usize::try_from(CURRENT).unwrap_or_default();
        if let Some(ref mut proc) = procs[cur] {
            proc.heap_break = new_break;
        }
    }
}

/// Find a free mapping slot in the current process and insert a new mapping.
/// Returns the index on success, None if all slots are full.
pub fn add_mapping(mapping: VmMapping) -> Option<usize> {
    // SAFETY: current process PCB pointer is valid; set by the scheduler on
    // context switch. Mutation via addr_of_mut!; called from syscall context.
    unsafe {
        let procs = &mut *addr_of_mut!(PROCS);
        let cur = usize::try_from(CURRENT).unwrap_or_default();
        let proc = procs[cur].as_mut()?;
        let slot = proc.mappings.iter().position(|m| m.is_none())?;
        proc.mappings[slot] = Some(mapping);
        Some(slot)
    }
}

/// Remove a mapping that starts at the given address.
/// Returns the removed mapping, or None if not found.
pub fn remove_mapping(start_addr: usize) -> Option<VmMapping> {
    // SAFETY: current process PCB pointer is valid; set by the scheduler on
    // context switch. Mutation via addr_of_mut!; called from syscall context.
    unsafe {
        let procs = &mut *addr_of_mut!(PROCS);
        let cur = usize::try_from(CURRENT).unwrap_or_default();
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
pub fn find_mapping(start_addr: usize) -> Option<VmMapping> {
    // SAFETY: current process PCB pointer is valid; set by the scheduler on
    // context switch. Read-only access via addr_of!; no mutation occurs here.
    unsafe {
        let procs = &*core::ptr::addr_of!(PROCS);
        let cur = usize::try_from(CURRENT).unwrap_or_default();
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
pub fn update_mapping_prot(start_addr: usize, new_prot: u32) -> bool {
    // SAFETY: current process PCB pointer is valid; set by the scheduler on
    // context switch. Mutation via addr_of_mut!; called from syscall context.
    unsafe {
        let procs = &mut *addr_of_mut!(PROCS);
        let cur = usize::try_from(CURRENT).unwrap_or_default();
        let Some(proc) = procs[cur].as_mut() else { return false };
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
pub fn current_mappings() -> [Option<VmMapping>; MAX_MAPPINGS] {
    // SAFETY: current process PCB pointer is valid; set by the scheduler on
    // context switch. Read-only access via addr_of!; no mutation occurs here.
    unsafe {
        let procs = &*core::ptr::addr_of!(PROCS);
        let cur = usize::try_from(CURRENT).unwrap_or_default();
        procs[cur]
            .as_ref()
            .map_or([None; MAX_MAPPINGS], |p| p.mappings)
    }
}

/// Get the current process's UID.
/// Returns 0 (root) if the current process is not found (should not happen).
pub fn current_uid() -> u32 {
    // SAFETY: current process PCB pointer is valid; set by the scheduler on
    // context switch. Read-only access via addr_of!; no mutation occurs here.
    unsafe {
        let procs = &*core::ptr::addr_of!(PROCS);
        let cur = usize::try_from(CURRENT).unwrap_or_default();
        procs[cur].as_ref().map_or(0, |p| p.uid)
    }
}

/// Get the current process's capability bitfield.
///
/// Returns `Capabilities::ALL` for PID 0 (kinit) and `Capabilities::FORK_DEFAULT`
/// as a safe fallback if the current PCB is unexpectedly absent.
/// Called by `capability::check` and `capability::has` (REQ-09).
pub fn current_capabilities() -> u32 {
    // SAFETY: current process PCB pointer is valid; set by the scheduler on
    // context switch. Read-only access via addr_of!; no mutation occurs here.
    unsafe {
        let procs = &*core::ptr::addr_of!(PROCS);
        let cur = usize::try_from(CURRENT).unwrap_or_default();
        procs[cur]
            .as_ref()
            .map_or(crate::capability::Capabilities::FORK_DEFAULT, |p| p.capabilities)
    }
}

/// Set the current process's wake_tick and transition it to Sleeping.
///
/// Called by sys_nanosleep after computing the target tick count.
/// The scheduler will transition this process back to Ready when
/// `exceptions::ticks() >= wake_tick`.
pub fn set_wake_tick(wake_tick: u64) {
    // SAFETY: called from syscall context (single-threaded; IRQs are disabled
    // during SVC on ARMv7). addr_of_mut! avoids an intermediate reference to
    // the static mut PROCS.
    unsafe {
        let procs = &mut *addr_of_mut!(PROCS);
        let cur = usize::try_from(CURRENT).unwrap_or_default();
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
pub fn clear_wake_tick() {
    // SAFETY: same as set_wake_tick — called from syscall context only.
    unsafe {
        let procs = &mut *addr_of_mut!(PROCS);
        let cur = usize::try_from(CURRENT).unwrap_or_default();
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
        let cur = usize::try_from(CURRENT).unwrap_or_default();
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
        let cur = usize::try_from(CURRENT).unwrap_or_default();
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
        let cur = usize::try_from(CURRENT).unwrap_or_default();
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
pub unsafe fn exec_replace_context(entry_point: usize, stack_top: usize,
    new_stack_base: usize, new_stack_pages: usize) {
    // SAFETY: addr_of_mut! avoids an intermediate reference to the static mut.
    // Called from execve syscall with interrupts disabled (SVC mode, ARMv7).
    unsafe {
        let procs = &mut *addr_of_mut!(PROCS);
        let cur = usize::try_from(CURRENT).unwrap_or_default();
        if let Some(ref mut proc) = procs[cur] {
            // WHY cpsr 0x10 (User mode, IRQs enabled): execve transfers control
            // to an unprivileged userspace binary. User mode (0x10) is the correct
            // CPSR for the new image. Contrast with spawn() which uses 0x1F (System
            // mode) for kernel-internal threads.
            proc.ctx.lr = u32::try_from(entry_point).unwrap_or_default();
            proc.ctx.sp = u32::try_from(stack_top).unwrap_or_default();
            proc.ctx.cpsr = 0x10; // User mode, IRQs enabled
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
        let cur = usize::try_from(CURRENT).unwrap_or_default();
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
pub fn check_pending_signal() -> Option<(Signal, u32)> {
    // SAFETY: read-only access via addr_of!; no mutation occurs here.
    unsafe {
        let procs = &*core::ptr::addr_of!(PROCS);
        let cur = usize::try_from(CURRENT).unwrap_or_default();
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
        });
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

    #[test]
    fn fork_creates_new_process() {
        // SAFETY: test-only; reset_all reinitialises global state. Single-threaded
        // test execution ensures no concurrent access to PROCS or CURRENT.
        unsafe {
            reset_all();
            // Construct a minimal process 0
            let procs = &mut *core::ptr::addr_of_mut!(PROCS);
            let pt = mmu::alloc_addr_space().unwrap();
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
            });
            CURRENT = 0;

            let child_pid = fork().unwrap_or_default();
            let procs = &*core::ptr::addr_of!(PROCS);
            assert!(procs[usize::try_from(child_pid).unwrap_or_default()].is_some(), "child slot must be populated");
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
            });
            CURRENT = 0;

            let child_pid = fork().unwrap_or_default();
            let procs = &*core::ptr::addr_of!(PROCS);
            let parent_pt = procs.get(0).copied().unwrap_or_default().as_ref().unwrap().page_table_phys;
            let child_pt = procs[usize::try_from(child_pid).unwrap_or_default()].as_ref().unwrap().page_table_phys;
            assert_ne!(parent_pt, child_pt, "parent and child must have distinct page tables");
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
            });
            CURRENT = 0;

            let child_pid = fork().unwrap_or_default();
            let procs = &*core::ptr::addr_of!(PROCS);
            let child_parent = procs[usize::try_from(child_pid).unwrap_or_default()].as_ref().unwrap().parent;
            assert_eq!(child_parent, Some(0u8), "child.parent must be parent PID");
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
            });
            CURRENT = 0;

            let child_pid = fork().unwrap_or_default();
            let procs = &*core::ptr::addr_of!(PROCS);
            let parent_pt = procs.get(0).copied().unwrap_or_default().as_ref().unwrap().page_table_phys;
            let child_pt = procs[usize::try_from(child_pid).unwrap_or_default()].as_ref().unwrap().page_table_phys;

            // Write INTO entry 100 in the child's table
            (child_pt as *mut u32).add(100).write(0xCAFE_BABE);
            // Parent's entry 100 must be unchanged
            let parent_val = (parent_pt as *const u32).add(100).read();
            assert_ne!(parent_val, 0xCAFE_BABE,
                "writing to child table must not affect parent table (separate L1s)");
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
            });
            CURRENT = 0;

            let child_pid = fork().unwrap_or_default();
            // Child is Ready, not Dead  -  waitpid must return None
            assert_eq!(waitpid(child_pid), None, "should return None while child is alive");
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
            });
            CURRENT = 0;

            let child_pid = fork().unwrap_or_default();

            // Manually mark child as dead with exit status 42
            let procs = &mut *core::ptr::addr_of_mut!(PROCS);
            if let Some(ref mut child) = procs[usize::try_from(child_pid).unwrap_or_default()] {
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
            });
            CURRENT = 0;

            let child_pid = fork().unwrap_or_default();

            let free_before = page::free_count();

            // Switch CURRENT to child and call exit_cleanup
            CURRENT = child_pid;
            exit_cleanup(0);

            let procs = &*core::ptr::addr_of!(PROCS);
            let child = procs[usize::try_from(child_pid).unwrap_or_default()].as_ref().unwrap();
            assert_eq!(child.state, State::Dead, "exit_cleanup must mark state Dead");

            let free_after = page::free_count();
            assert!(free_after > free_before, "exit_cleanup must reclaim stack pages");
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
            procs[0] = Some(Process {
                pid: 0,
                state: State::Running,
                ctx: Context::zero(),
                parent: None,
                exit_status: 0,
                page_table_phys: pt0,
                stack_base: 0,
                stack_pages: 0,
                heap_break: DEFAULT_HEAP_BREAK,
                mappings: [None; MAX_MAPPINGS],
                signal_state: SignalState::new(),
                uid: 0,
                wake_tick: 0,
                capabilities: crate::capability::Capabilities::ALL,
            });

            // Process 1: faulting process
            let pt1 = mmu::alloc_addr_space().unwrap();
            procs[1] = Some(Process {
                pid: 1,
                state: State::Running,
                ctx: Context::zero(),
                parent: Some(0),
                exit_status: 0,
                page_table_phys: pt1,
                stack_base: 0,
                stack_pages: 0,
                heap_break: DEFAULT_HEAP_BREAK,
                mappings: [None; MAX_MAPPINGS],
                signal_state: SignalState::new(),
                uid: 0,
                wake_tick: 0,
                capabilities: crate::capability::Capabilities::ALL,
            });
            CURRENT = 0;

            notify_fault(1, FaultKind::DataAbort { fault_addr: 0xDEAD, fault_status: 0x05 });

            let procs = &*core::ptr::addr_of!(PROCS);
            assert_eq!(procs.get(1).copied().unwrap_or_default().as_ref().unwrap().state, State::Dead,
                "faulting process must be marked Dead");
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
            procs[0] = Some(Process {
                pid: 0,
                state: State::Running,
                ctx: Context::zero(),
                parent: None,
                exit_status: 0,
                page_table_phys: pt0,
                stack_base: 0,
                stack_pages: 0,
                heap_break: DEFAULT_HEAP_BREAK,
                mappings: [None; MAX_MAPPINGS],
                signal_state: SignalState::new(),
                uid: 0,
                wake_tick: 0,
                capabilities: crate::capability::Capabilities::ALL,
            });
            let pt1 = mmu::alloc_addr_space().unwrap();
            procs[1] = Some(Process {
                pid: 1,
                state: State::Running,
                ctx: Context::zero(),
                parent: Some(0),
                exit_status: 0,
                page_table_phys: pt1,
                stack_base: 0,
                stack_pages: 0,
                heap_break: DEFAULT_HEAP_BREAK,
                mappings: [None; MAX_MAPPINGS],
                signal_state: SignalState::new(),
                uid: 0,
                wake_tick: 0,
                capabilities: crate::capability::Capabilities::ALL,
            });
            CURRENT = 0;

            notify_fault(1, FaultKind::UndefinedInstruction);

            // PID 0 receives the message; tag must be 3 (UndefinedInstruction)
            CURRENT = 0;
            let msg = ipc::recv().unwrap_or_default();
            assert_eq!(msg.tag, 3, "UndefinedInstruction tag must be 3");
            assert_eq!(msg.payload()[0], 1u8, "first payload byte must be faulting PID");
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
            });
            CURRENT = 0;

            let child_pid = fork().unwrap_or_default();
            let procs_ref = &*core::ptr::addr_of!(PROCS);
            let child_pt = procs_ref[usize::try_from(child_pid).unwrap_or_default()].as_ref().unwrap().page_table_phys;

            // Exit the child  -  should free its page table slot
            CURRENT = child_pid;
            exit_cleanup(0);

            // Allocate again  -  must get the same address (slot was reclaimed)
            let new_pt = mmu::alloc_addr_space().unwrap_or_default();
            assert_eq!(new_pt, child_pt, "reclaimed table slot must be reused");

            mmu::free_addr_space(new_pt);
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
            });
            CURRENT = 0;
            assert_eq!(current_uid(), 0, "kinit (PID 0) must have UID 0");
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
            });
            CURRENT = 0;

            let target_tick: u64 = 12345;
            set_wake_tick(target_tick);

            let procs_ro = &*core::ptr::addr_of!(PROCS);
            let p = procs_ro[0].as_ref().unwrap();
            assert_eq!(p.state, State::Sleeping, "process must be Sleeping after set_wake_tick");
            assert_eq!(p.wake_tick, target_tick, "wake_tick must match the requested value");
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
            });
            CURRENT = 0;

            set_wake_tick(9999);
            clear_wake_tick();

            let procs_ro = &*core::ptr::addr_of!(PROCS);
            let p = procs_ro[0].as_ref().unwrap();
            assert_eq!(p.state, State::Running, "process must return to Running after clear_wake_tick");
            assert_eq!(p.wake_tick, 0, "wake_tick must be reset to 0");
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
            });
            CURRENT = 0;

            let handler_addr: u32 = 0x4020_0000;
            let stored = get_signal_action(crate::signal::Signal::Sigusr1);
            assert_eq!(stored, crate::signal::SignalAction::Default,
                "initial action should be Default");

            set_signal_action(
                crate::signal::Signal::Sigusr1,
                crate::signal::SignalAction::Handler(handler_addr),
            );
            let stored2 = get_signal_action(crate::signal::Signal::Sigusr1);
            assert_eq!(stored2, crate::signal::SignalAction::Handler(handler_addr),
                "handler should be stored in PCB");
        }
    }

    #[test]
    fn kill_sets_pending_bit() {
        // SAFETY: test-only; reset_all reinitialises global state.
        unsafe {
            reset_all();
            let procs = &mut *core::ptr::addr_of_mut!(PROCS);
            let pt = mmu::alloc_addr_space().unwrap();
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
            });
            CURRENT = 0;

            // Install a handler so kill marks it pending (not terminate).
            let handler_addr: u32 = 0x4020_0000;
            set_signal_action(
                crate::signal::Signal::Sigusr1,
                crate::signal::SignalAction::Handler(handler_addr),
            );

            let ret = deliver_signal_to(0, crate::signal::Signal::Sigusr1);
            assert_eq!(ret, 0, "deliver_signal_to should succeed");

            let pending = get_pending_mask(0);
            let expected_bit = 1u32 << (crate::signal::Signal::Sigusr1 as u32);
            assert_ne!(pending & expected_bit, 0,
                "SIGUSR1 pending bit should be set after kill");
        }
    }

    #[test]
    fn default_action_terminates() {
        // SAFETY: test-only; reset_all reinitialises global state.
        unsafe {
            reset_all();
            let procs = &mut *core::ptr::addr_of_mut!(PROCS);
            let pt = mmu::alloc_addr_space().unwrap();
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
            });
            CURRENT = 0;

            // No handler for SIGTERM — default is Terminate.
            let ret = deliver_signal_to(0, crate::signal::Signal::Sigterm);
            assert_eq!(ret, 0, "deliver_signal_to should return 0");

            let state = get_state(0);
            assert_eq!(state, Some(State::Dead),
                "process should be Dead after default SIGTERM");
        }
    }

    #[test]
    fn sigchld_default_ignored() {
        // SAFETY: test-only; reset_all reinitialises global state.
        unsafe {
            reset_all();
            let procs = &mut *core::ptr::addr_of_mut!(PROCS);
            let pt = mmu::alloc_addr_space().unwrap();
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
            });
            CURRENT = 0;

            // No handler for SIGCHLD — default is Ignore.
            let ret = deliver_signal_to(0, crate::signal::Signal::Sigchld);
            assert_eq!(ret, 0, "deliver_signal_to should return 0");

            let state = get_state(0);
            assert_eq!(state, Some(State::Running),
                "process should still be Running after default SIGCHLD");

            let pending = get_pending_mask(0);
            let sigchld_bit = 1u32 << (crate::signal::Signal::Sigchld as u32);
            assert_eq!(pending & sigchld_bit, 0,
                "SIGCHLD should not be pending when default action is Ignore");
        }
    }

}
