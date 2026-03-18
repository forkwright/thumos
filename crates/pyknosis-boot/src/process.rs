//! Process abstraction and context switching.
//!
//! Each process has a saved register context, a stack, a process ID,
//! and a state (running, ready, blocked). The scheduler selects the
//! next ready process and context-switches to it on each timer tick.
//!
//! On ARMv7, context switch saves/restores r4-r11 (callee-saved),
//! sp, lr, and cpsr. Registers r0-r3, r12, lr, pc, cpsr are saved
//! by the exception entry/exit code.

use crate::page;
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
    /// Terminated, awaiting cleanup.
    Dead,
}

/// Saved CPU context for context switching.
/// Only callee-saved registers need explicit saving — the IRQ entry
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

/// Process control block.
pub struct Process {
    pub pid: Pid,
    pub state: State,
    pub ctx: Context,
    /// Base address of the stack allocation (for freeing).
    stack_base: usize,
    /// Number of pages allocated for the stack.
    stack_pages: usize,
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
/// Creates process 0 (the kernel/idle process) from the current execution context.
///
/// # Safety
///
/// Must be called once during kernel init.
pub unsafe fn init() {
    unsafe {
        let proc0 = Process {
            pid: 0,
            state: State::Running,
            ctx: Context::zero(), // NOTE: kernel process context is "current CPU state"
            stack_base: 0,        // NOTE: uses the boot stack, not allocated
            stack_pages: 0,
        };
        let procs = &mut *addr_of_mut!(PROCS);
        procs[0] = Some(proc0);
        CURRENT = 0;
    }
}

/// Create a new process that starts executing at `entry_point`.
/// Returns the PID, or None if the process table is full.
pub fn spawn(entry_point: fn() -> !) -> Option<Pid> {
    unsafe {
        // Find a free slot
        let procs = &mut *addr_of_mut!(PROCS);
        let slot = procs.iter().position(|p| p.is_none())?;
        let pid = slot as Pid;

        // Allocate stack
        let mut stack_top: usize = 0;
        for i in 0..STACK_PAGES {
            let page = page::alloc_page()?;
            if i == 0 {
                stack_top = page + page::PAGE_SIZE * STACK_PAGES;
            }
        }

        // Set up initial context
        // When we context-switch to this process, it will "return" to entry_point
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
            lr: entry_point as u32, // NOTE: "return address" is the entry point
            cpsr: 0x1F,             // NOTE: system mode, IRQs enabled
        };

        let proc = Process {
            pid,
            state: State::Ready,
            ctx,
            stack_base: stack_top - page::PAGE_SIZE * STACK_PAGES,
            stack_pages: STACK_PAGES,
        };

        procs[slot] = Some(proc);
        Some(pid)
    }
}

/// Get the current process ID.
pub fn current_pid() -> Pid {
    unsafe { CURRENT }
}

/// Simple round-robin scheduler. Called from the timer tick handler.
/// Returns the PID to switch to (may be the same as current).
pub fn schedule() -> Pid {
    unsafe {
        let cur = CURRENT as usize;
        // Round-robin: find next ready process after current
        let procs = &*core::ptr::addr_of!(PROCS);
        for offset in 1..MAX_PROCS {
            let idx = (cur + offset) % MAX_PROCS;
            if let Some(ref proc) = procs[idx] {
                if proc.state == State::Ready {
                    return proc.pid;
                }
            }
        }
        // No other ready process — stay on current
        CURRENT
    }
}

/// Perform a context switch from current process to `next_pid`.
///
/// # Safety
///
/// Must be called from the timer IRQ handler (in IRQ mode with
/// interrupts disabled).
pub unsafe fn switch_to(next_pid: Pid) {
    unsafe {
        let cur_pid = CURRENT as usize;
        let next = next_pid as usize;

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

        // Restore next context
        if let Some(ref mut next_proc) = procs[next] {
            next_proc.state = State::Running;
            CURRENT = next_pid;
            restore_context(&next_proc.ctx);
        }
    }
}

/// Save callee-saved registers into the context struct.
#[inline(always)]
unsafe fn save_context(ctx: &mut Context) {
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
}

/// Restore callee-saved registers from the context struct.
#[inline(always)]
unsafe fn restore_context(ctx: &Context) {
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
}

/// Mark the current process as dead and yield to the scheduler.
pub fn exit() -> ! {
    unsafe {
        let cur = CURRENT as usize;
        let procs = &mut *addr_of_mut!(PROCS);
        if let Some(ref mut proc) = procs[cur] {
            proc.state = State::Dead;
        }
        // NOTE: next timer tick will schedule away from this dead process
        loop {
            core::arch::asm!("wfi");
        }
    }
}
