# AGENTS.md - Thumos

Cross-tool guide for AI coding agents (Claude Code, Cursor, Windsurf, Copilot, etc.) working on the Thumos mobile OS. Authoritative agent orientation (phase status, Greek naming rationale, constraints) lives in [CLAUDE.md](CLAUDE.md); this file captures build/lint invariants and the non-obvious rules that differ from a standard Rust workspace.

## Build, test, lint

```bash
cargo check --workspace              # userspace crates only (host build)
cargo test --workspace               # workspace test suite
cargo clippy --workspace -- -D warnings   # zero warnings required

# Kernel is excluded from workspace; cross-compiles for armv7a-none-eabi
cd crates/thumos && cargo build --release
```

The `thumos` crate is the bare-metal kernel binary and is **excluded from the workspace** (`exclude = ["crates/thumos"]`). Workspace commands never touch the kernel; kernel commands must `cd crates/thumos` first. Kernel tests run on host via `cargo test` inside `crates/thumos/` (uses conditional compilation to stub MMIO).

Boot image is produced with `mkbootimg` and flashed via mtkclient BROM exploit. See [docs/KERNEL-BUILD.md](docs/KERNEL-BUILD.md).

## Key patterns

- **Errors:** `snafu` with `.context()` and `Location` tracking. No `unwrap()` / `expect()` / `panic!()` in library code; all three are `deny` at the workspace level (kernel crate relaxes where the hardware contract makes a return impossible).
- **Allocator:** kernel has its own slab allocator; `alloc`-only in `no_std` contexts. Do not introduce `std` deps into `no_std` crates.
- **Unsafe:** `unsafe_code = "warn"` (not deny) because bare-metal kernel plus crypto/memory operations in `stegnos`/`leipsanon` legitimately need unsafe. Every `unsafe` block requires a `// SAFETY:` comment.
- **Async:** Tokio only for userspace daemons; the kernel is synchronous with cooperative yields.
- **IDs / time / strings:** `ulid`, `jiff`, `compact_str` to match aletheia conventions.
- **Lints:** `#[expect(lint, reason = "...")]` over `#[allow]` so stale suppressions warn.
- **Visibility:** `pub(crate)` default. `pub` only for the crate's documented API surface.
- **Naming:** Greek names (see [CLAUDE.md § Naming](CLAUDE.md#naming)). English for code identifiers.
- **Commits:** `type(scope): description`. Scope = crate name (`klesis`, `aither`, `eidolon`, ...) or `kernel` for `crates/thumos/`.

## Where to add things

| Task | Location | Registration |
|------|----------|-------------|
| Kernel subsystem (new syscall, driver, allocator) | `crates/thumos/src/<module>/` | Monolithic kernel; add a module, not a new crate |
| New userspace domain crate | `crates/<greek-name>/` | Register in workspace `Cargo.toml` members |
| Hardware driver (protocol logic) | Workspace crate (e.g. `aither`, `pteron`) | If it touches MMIO registers, put it in the kernel instead |
| Radio analysis feature | `crates/sema/` | IMSI catcher heuristics, rogue AP detection |
| UI widget | `crates/eidolon/` | 240x320 framebuffer, T9 input |
| Panic / wipe trigger | `crates/leipsanon/` | Priority-ordered scrubbing |
| Packet filter rule | `crates/asphaleia/` | DNS blocklist + IPv4/TCP/UDP matcher |

Crate tree and layer rules: [ARCHITECTURE.md](ARCHITECTURE.md). Hardware register maps: [docs/DRIVER-INTERFACES.md](docs/DRIVER-INTERFACES.md).

## Device identity protection

All hardware identifiers (WiFi MAC, BT MAC, IMEI, IMSI, probe requests, BLE addresses) are treated as sensitive. New radio code MUST randomize or suppress identifiers at the driver layer, not in userspace, because userspace filtering is bypassable by a compromised component. Reference the table in [CLAUDE.md § Device identity protection](CLAUDE.md#device-identity-protection) before adding any radio feature. The IMEI filter lives at the CCCI kernel boundary; do not relocate it upward.

## TODO convention

`TODO(#issue): description` or `TODO(category): description`. Categories: `hw` (hardware-dependent), `crypto` (needs primitives), `phase07`/`phase08` (deferred phase). Raw `TODO` without a tag is lint-rejected.

## Common mistakes

- **Do not add `std` to `no_std` kernel modules.** The kernel targets `armv7a-none-eabi`; pulling `std` silently fails cross-compilation long after CI would catch a host test.
- **Do not build the kernel via `cargo build --workspace`.** It is excluded intentionally. See Build section above.
- **Do not skip MAC/BT randomization.** LE Privacy rotates every 15 min; WiFi MAC rotates per connection. Hard-coded MACs leak identity.
- **Do not hand-roll AT command parsing outside `klesis`.** `klesis` owns the AT parser, CCCI/CLDMA framing, and SMS PDU codec.
- **Do not add dependencies that require a C toolchain.** Pure Rust only: `rustls` not openssl, `fjall` or in-memory over SQLite, `RustCrypto` over `ring` where possible.

## Gates

Before pushing: `cargo fmt --check`, `cargo clippy --workspace -- -D warnings`, `cargo test --workspace`, plus `cd crates/thumos && cargo check --release --target armv7a-none-eabi` if the kernel was touched.
