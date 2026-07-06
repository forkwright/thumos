//! QEMU semihosting harness for the `qemu` bring-up feature.
//!
//! AArch32 semihosting (`svc #0x123456`) against `qemu-system-arm
//! -semihosting-config enable=on,target=native`. Mirrors the calls proven
//! by `examples/qemu_smoke.rs`. Compiled only under `--features qemu`.
//!
//! Exit-code contract (asserted by CI): 0 = boot-complete, 1 = panic,
//! 2 = data abort, 3 = prefetch abort, 4 = undefined instruction.

/// SYS_EXIT_EXTENDED semihosting operation.
///
/// WHY: plain SYS_EXIT (0x18) on AArch32 takes the reason code directly in
/// r1 and cannot carry an exit status; the extended form takes a
/// [reason, status] block, so pass/fail/abort codes reach the runner.
const SYS_EXIT_EXTENDED: u32 = 0x20;

/// SYS_WRITE0 semihosting operation (write NUL-terminated string).
const SYS_WRITE0: u32 = 0x04;

/// ADP_Stopped_ApplicationExit reason code.
const ADP_STOPPED_APPLICATION_EXIT: u32 = 0x2_0026;

/// Terminate the guest; `status` becomes the QEMU process exit code.
fn exit(status: u32) -> ! {
    let params = [ADP_STOPPED_APPLICATION_EXIT, status];
    // SAFETY: `svc #0x123456` is the architecturally-defined A32 semihosting
    // trap. QEMU services it host-side and terminates the guest, so control
    // never returns; `params` outlives the call because the call never
    // returns.
    unsafe {
        core::arch::asm!(
            "svc #0x123456",
            in("r0") SYS_EXIT_EXTENDED,
            in("r1") params.as_ptr(),
            options(noreturn, nostack),
        );
    }
}

/// Unit-typed wrapper over [`exit`].
///
/// WHY: callers sit at points where the non-qemu build continues (idle
/// loops, exception hang loops). A `-> !` call there marks the shared tail
/// unreachable and trips `unreachable_code` whenever the feature is on;
/// this wrapper never returns at runtime but does not poison the caller's
/// control-flow analysis.
pub(crate) fn request_exit(status: u32) {
    exit(status);
}

/// Write a NUL-terminated string to the QEMU host console.
///
/// Works before UART/MMU init -- the only dependency is the semihosting
/// trap, so it is the earliest available boot instrumentation.
pub(crate) fn write0(msg: &core::ffi::CStr) {
    // SAFETY: msg is NUL-terminated (CStr invariant) and lives in mapped
    // kernel memory; QEMU reads it host-side up to the NUL. r0 carries the
    // semihosting result on return and is declared clobbered.
    unsafe {
        core::arch::asm!(
            "svc #0x123456",
            inlateout("r0") SYS_WRITE0 => _,
            in("r1") msg.as_ptr(),
            options(nostack, readonly),
        );
    }
}
