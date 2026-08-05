# Kernel Wiring Audit

Superseded by [`capability-inventory.toml`](capability-inventory.toml) (issue
#550): the machine-checked capability-reachability inventory. The hand counts
that lived here drifted — the module set, the `expect(dead_code)` shape, and
the wiring state all moved while the prose did not.

The inventory classifies every `main.rs` module into compiled-only /
kernel-wired / emulated-mock-proven / hardware-proven, and
`scripts/check-wiring-inventory.sh` fails CI on drift in either direction
(unclassified modules, phantom entries, witness markers claimed but not
asserted, or asserted but not fired in the QEMU boot log). Its accounting
rules are unchanged: compiled+tested means the Rust surface exists; it does
not imply boot, userspace, or hardware readiness.
