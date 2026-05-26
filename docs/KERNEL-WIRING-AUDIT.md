# Kernel Wiring Audit

This is the issue #145 reality check for advertised kernel capabilities that compile but are not yet fully wired into boot, userspace, or hardware-backed runtime paths.

The counts below are from `origin/main` as checked on 2026-05-26:

```bash
rg '^#!\[expect\(dead_code' crates/thumos/src | wc -l
rg '^\s*#\[expect\(dead_code' crates/thumos/src | wc -l
```

Current result: 8 crate-level expectations and 48 item-level expectations.

## Crate-Level Expectations

| Module | Current reality |
|---|---|
| `ui.rs` | `kinit` renders an initial home/status frame, but full screen routing and input dispatch through `UiManager` are not wired. |
| `heorte.rs` | Calendar/alarm/timer/stopwatch engine compiles and has tests, but no boot-time runtime manager owns the state. |
| `heorte_timer.rs` | Timer/stopwatch logic compiles and has tests, but runtime ownership is pending with `heorte`. |
| `screen_calendar.rs` | Renderable screen exists, but there is no `kinit` route/input path to show it. |
| `screen_alarm.rs` | Renderable alarm/timer/stopwatch screen exists, but there is no `kinit` route/input path to show it. |
| `clock.rs` | Wall-clock trust policy exists, but kernel time and userspace syscalls still use lower-level timer/time paths. |
| `bluetooth.rs` | `kinit` attempts adapter initialization, but userspace control and higher-level audio/profile paths are not wired. |
| `gps.rs` | `kinit` attempts receiver initialization, but userspace access and clock/topos integration are not wired. |

## Item-Level Expectations

These are lower-level dead-code suppressions, not proof that whole advertised features are production-ready.

| File | Count | Meaning |
|---|---:|---|
| `audio_codec.rs` | 1 | Reserved register constant for future gain control. |
| `device.rs` | 15 | Canonical address constants retained while drivers use local or `kconfig` constants. |
| `emmc.rs` | 20 | Reserved register fields and commands for diagnostics, tuning, boot mode, CID/CSD readback, and storage-layer follow-up. |
| `firewall.rs` | 3 | Dynamic policy and audit-key plumbing are not connected at the net device hook. |
| `kinit.rs` | 2 | Boot progress types are tested but not yet emitted as runtime progress reporting. |
| `power.rs` | 2 | Per-core power-down and DSI0 helper are reserved for follow-up hardware bring-up. |
| `screen_home.rs` | 2 | Home screen modes await security-mode manager state wiring. |
| `status_bar.rs` | 3 | Service-level badges await modem registration state wiring. |

## Accounting Rules

- A module being compiled and tested means the Rust surface exists; it does not imply boot reachability, userspace reachability, or hardware readiness.
- Hardware/radio claims should be treated as ready only when the driver has a production call path and identity-protection behavior at the driver boundary.
- Issue #143 owns the network path, issue #144 owns userspace spawn, and issue #141 owns the agent runtime bridge. This audit does not reclassify those paths as ready.
