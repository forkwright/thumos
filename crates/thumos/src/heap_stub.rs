//! Host-test stub for the ARM-target `heap` module (#459).
//!
//! The real `heap` module initializes the slab allocator over kernel page
//! tables, which do not exist on the host test target (host tests link the
//! std allocator). Under test this stub exposes only the `stats()` surface
//! host-testable modules (the debug console's `cmd_mem`) reference.
//!
//! WHY(pattern): a gated-out hardware dependency is made test-visible by a
//! parallel `#[cfg(test)] #[path = "..._stub.rs"] mod x;` binding in main.rs
//! (see `exceptions_stub.rs` / `timer_stub.rs` / `uart_stub.rs`).

/// Return `(total_allocs, total_frees)` for leak detection.
///
/// The stub reports a balanced `(0, 0)`: no kernel heap exists on the host
/// target, so nothing can leak from it, and callers comparing the two values
/// for equality (the leak check) see the correct zero-leak answer.
pub(crate) fn stats() -> (u64, u64) {
    (0, 0)
}
