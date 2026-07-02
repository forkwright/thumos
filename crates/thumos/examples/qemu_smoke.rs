//! QEMU smoke-test example — proof-of-concept for the kernel QEMU runner.
//!
//! Purpose: demonstrate end-to-end that a bare-metal `armv7a-none-eabi`
//! binary can boot under `qemu-system-arm -machine virt`, execute Rust
//! code, and report a pass/fail exit code back to the host via ARM
//! semihosting. This is the minimum viable proof that the test runner
//! infrastructure (scripts/qemu-runner.sh + .cargo/config.toml runner)
//! works.
//!
//! Invocation (from `crates/thumos/`):
//!   cargo run --example qemu_smoke --release
//!
//! Expected behavior:
//!   - Boot stub sets up the stack and zeros BSS (mirrors `main.rs`).
//!   - `run` writes "qemu_smoke: pass" to UART0 (PL011 on virt @ 0x09000000)
//!     then issues semihosting SYS_EXIT with status 0.
//!   - `qemu-runner.sh` observes QEMU exit code 0 -> cargo reports success.
//!
//! This example is intentionally self-contained so it has no dependency on
//! the kernel's runtime (kinit, GIC, MMU). Once this PoC is green, the
//! follow-up is to convert the 1,113 `#[cfg(test)]` unit tests in the
//! kernel crate to a `custom_test_frameworks` harness that runs under this
//! same runner (tracked separately from issue #117).

#![no_std]
#![no_main]

use core::panic::PanicInfo;

// -----------------------------------------------------------------------------
// Boot stub (mirror of src/main.rs; kept inline so this example has no
// runtime dependency on kernel modules).
// -----------------------------------------------------------------------------

core::arch::global_asm!(
    ".section .text.boot, \"ax\"",
    ".global _start",
    ".arm",
    "_start:",
    "    cpsid   if",               // disable interrupts
    "    ldr     sp, =__stack_top", // stack
    "    ldr     r0, =__bss_start", // zero BSS
    "    ldr     r1, =__bss_end",
    "    mov     r2, #0",
    "1:  cmp     r0, r1",
    "    strlt   r2, [r0], #4",
    "    blt     1b",
    "    bl      run",
    "2:  wfe",
    "    b       2b",
);

// -----------------------------------------------------------------------------
// UART (PL011 on QEMU `-machine virt`)
// -----------------------------------------------------------------------------

// WHY: QEMU's `virt` board wires PL011 UART0 at 0x09000000. The kernel
// runtime target is MT6739 (different UART base), but for the QEMU smoke
// test we use the virt-board UART so the runner can observe output.
const VIRT_UART0: usize = 0x0900_0000;

/// Writes a single byte to the PL011 data register. Blocking; does not
/// consult the TX-FIFO-full flag because QEMU's emulated UART drains
/// fast enough for a short smoke message.
///
/// # Safety
/// Caller must guarantee the binary is running on a platform where
/// `VIRT_UART0` points to a valid PL011 data register (i.e. under
/// `qemu-system-arm -machine virt`).
unsafe fn uart_write_byte(b: u8) {
    // SAFETY: VIRT_UART0 is a valid MMIO address on QEMU virt; caller
    // contract enforces platform.
    unsafe {
        core::ptr::write_volatile(VIRT_UART0 as *mut u8, b);
    }
}

/// Writes a NUL-terminated-ish byte slice to UART0.
///
/// # Safety
/// See `uart_write_byte`.
unsafe fn uart_write_str(s: &str) {
    for b in s.bytes() {
        // SAFETY: forwarded from caller.
        unsafe {
            uart_write_byte(b);
        }
    }
}

// -----------------------------------------------------------------------------
// ARM semihosting — SYS_EXIT
// -----------------------------------------------------------------------------

// SYS_EXIT_EXTENDED (angel_SWIreason_ReportExceptionExtended). WHY: on AArch32
// the plain SYS_EXIT (0x18) call takes the reason code DIRECTLY in r1 and cannot
// convey an explicit status; only SYS_EXIT_EXTENDED (0x20) accepts a
// [reason, exit_code] parameter block, so pass (0) and fail (1) are
// distinguishable. On A64 SYS_EXIT already takes the block, but this example is
// A32-only.
const SYS_EXIT_EXTENDED: u32 = 0x20;
const ADP_STOPPED_APPLICATION_EXIT: u32 = 0x2002_6;

/// Triggers a clean QEMU exit via ARM semihosting. Exit code 0 means
/// "passed"; any other value the runner translates to "failed".
///
/// This never returns.
fn semihost_exit(status: u32) -> ! {
    let params = [ADP_STOPPED_APPLICATION_EXIT, status];
    // WHY: the AArch32 semihosting trap instruction is `svc 0x123456`. QEMU does
    // NOT treat `bkpt 0xAB` as a semihosting call in ARM state, so a bkpt-based
    // exit is never serviced — the guest faults and hangs until the runner times
    // out. `svc 0x123456` is the architecturally-defined A32 trap.
    // SAFETY: inline asm performs the deterministic AArch32 semihosting trap;
    // QEMU handles it and terminates the guest, so control never returns.
    unsafe {
        core::arch::asm!(
            "svc #0x123456",
            in("r0") SYS_EXIT_EXTENDED,
            in("r1") params.as_ptr(),
            options(noreturn, nostack),
        );
    }
}

// -----------------------------------------------------------------------------
// Entry
// -----------------------------------------------------------------------------

/// Called from the boot stub after stack + BSS setup.
///
/// Writes a known marker string and exits cleanly. A failing variant of
/// this smoke test would `semihost_exit(1)` instead (or panic, which the
/// panic handler also routes to a non-zero exit).
#[unsafe(no_mangle)]
pub extern "C" fn run() -> ! {
    // SAFETY: running under `qemu-system-arm -machine virt`; VIRT_UART0
    // is valid on that platform.
    unsafe {
        uart_write_str("qemu_smoke: pass\n");
    }
    semihost_exit(0);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    // WHY: any panic during the smoke test means the harness is broken;
    // report a distinct non-zero status so the runner can tell panic
    // from a normal failing assertion.
    semihost_exit(1);
}
