//! QEMU semihosting harness for the `qemu` bring-up feature.
//!
//! `AArch32` semihosting (`svc #0x123456`) against `qemu-system-arm
//! -semihosting-config enable=on,target=native`. Mirrors the calls proven
//! by `examples/qemu_smoke.rs`. Compiled only under `--features qemu`.
//!
//! Exit-code contract (asserted by CI): 0 = boot-complete, 1 = panic,
//! 2 = data abort, 3 = prefetch abort, 4 = undefined instruction.
//!
//! WHY(#692): the semihosting trap below binds `r0`/`r1` as explicit asm
//! operands, which is AArch32-only -- `r0`/`r1` are not registers on the
//! i686 host target `scripts/kernel-clippy.sh` lints this module against
//! under `--features qemu`. Every function is therefore split
//! `target_arch = "arm"` / `not(target_arch = "arm")`, so the public API
//! (`request_exit`, `write0`) type-checks identically on both targets while
//! only the ARM half ever performs a real semihosting call. See each
//! host-target fn's own WHY for why panicking, not a silent no-op, is the
//! correct fallback.

/// SYS_EXIT_EXTENDED semihosting operation.
///
/// WHY: plain SYS_EXIT (0x18) on AArch32 takes the reason code directly in
/// r1 and cannot carry an exit status; the extended form takes a
/// [reason, status] block, so pass/fail/abort codes reach the runner.
#[cfg(target_arch = "arm")]
const SYS_EXIT_EXTENDED: u32 = 0x20;

/// SYS_WRITE0 semihosting operation (write NUL-terminated string).
#[cfg(target_arch = "arm")]
const SYS_WRITE0: u32 = 0x04;

/// ADP_Stopped_ApplicationExit reason code.
#[cfg(target_arch = "arm")]
const ADP_STOPPED_APPLICATION_EXIT: u32 = 0x2_0026;

/// Terminate the guest; `status` becomes the QEMU process exit code.
#[cfg(target_arch = "arm")]
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

/// Host-target stand-in for [`exit`].
///
/// WHY(#692): semihosting exit has no host-target equivalent -- there is no
/// QEMU guest to terminate and no `r0`/`r1` on `i686/x86_64`. This arm exists
/// only so `--features qemu` lint/check passes on the host target (see the
/// module WHY); `kernel-build.sh` only ever links `armv7a-none-eabi`
/// artifacts, so this function is unreachable in every real boot. It
/// panics rather than returning so a hypothetical host call fails loudly
/// instead of reporting a fabricated QEMU exit status.
#[cfg(not(target_arch = "arm"))]
fn exit(status: u32) -> ! {
    unreachable!("semihosting exit (status={status}) is ARM-only; unreachable on the host target")
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
#[cfg(target_arch = "arm")]
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

/// Host-target stand-in for [`write0`].
///
/// WHY(#692): see [`exit`]'s host-target stand-in -- same architecture
/// mismatch, same reasoning. A silent no-op would let a caller believe the
/// host console write happened when nothing was ever emitted; panicking
/// keeps that failure visible instead of manufacturing success.
#[cfg(not(target_arch = "arm"))]
pub(crate) fn write0(msg: &core::ffi::CStr) {
    let _ = msg;
    unreachable!("semihosting write0 is ARM-only; unreachable on the host target")
}
