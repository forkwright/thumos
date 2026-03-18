//! Syscall interface.
//!
//! Userspace processes invoke kernel services via the SVC (supervisor call)
//! instruction. The SVC number is encoded in the instruction immediate field.
//! The handler extracts it, dispatches to the appropriate kernel function,
//! and returns the result in r0.
//!
//! Syscall convention (thumos-specific):
//! - SVC #N where N is the syscall number
//! - Arguments in r0-r3 (up to 4 args)
//! - Return value in r0 (0 = success, negative = error)
//! - r1-r3 may carry additional return values

use crate::process;
use crate::uart::Uart;
use core::fmt::Write;

/// Syscall numbers.
pub mod nr {
    /// Exit the current process.
    pub const EXIT: u32 = 0;
    /// Write bytes to the UART console.
    pub const WRITE: u32 = 1;
    /// Yield the CPU to the scheduler.
    pub const YIELD: u32 = 2;
    /// Get the current process ID.
    pub const GETPID: u32 = 3;
    /// Allocate a physical page.
    pub const ALLOC_PAGE: u32 = 4;
    /// Free a physical page.
    pub const FREE_PAGE: u32 = 5;
    /// Get uptime in milliseconds.
    pub const UPTIME: u32 = 6;
    /// Sleep for N milliseconds (approximate, tick-based).
    pub const SLEEP: u32 = 7;
}

/// Syscall dispatch. Called from the SVC handler in exceptions.rs.
///
/// # Arguments
///
/// - `num`: syscall number (from SVC instruction)
/// - `arg0`-`arg3`: arguments from r0-r3
///
/// # Returns
///
/// Value to place in r0 on return to userspace.
pub fn dispatch(num: u32, arg0: u32, arg1: u32, _arg2: u32, _arg3: u32) -> u32 {
    match num {
        nr::EXIT => {
            process::exit();
        }
        nr::WRITE => {
            // arg0 = pointer to buffer, arg1 = length
            let ptr = arg0 as *const u8;
            let len = arg1 as usize;
            // SAFETY: we trust the userspace pointer for now.
            // Wave 4 adds proper address validation.
            let slice = unsafe { core::slice::from_raw_parts(ptr, len) };
            let mut serial = Uart::new();
            for &byte in slice {
                serial.putc(byte);
            }
            len as u32
        }
        nr::YIELD => {
            // Voluntary yield — schedule immediately
            let next = process::schedule();
            if next != process::current_pid() {
                unsafe {
                    process::switch_to(next);
                }
            }
            0
        }
        nr::GETPID => process::current_pid() as u32,
        nr::ALLOC_PAGE => {
            match crate::page::alloc_page() {
                Some(addr) => addr as u32,
                None => u32::MAX, // NOTE: error indicator
            }
        }
        nr::FREE_PAGE => {
            unsafe {
                crate::page::free_page(arg0 as usize);
            }
            0
        }
        nr::UPTIME => crate::exceptions::uptime_ms() as u32,
        nr::SLEEP => {
            // NOTE: approximate sleep via busy-wait on tick counter
            // A proper implementation would block the process and wake on tick
            let target = crate::exceptions::uptime_ms() + arg0 as u64;
            while crate::exceptions::uptime_ms() < target {
                unsafe {
                    core::arch::asm!("wfe");
                }
            }
            0
        }
        _ => {
            let mut serial = Uart::new();
            write!(serial, "Unknown syscall: {num}\r\n").ok();
            u32::MAX
        }
    }
}
