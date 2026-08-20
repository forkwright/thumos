# _llm/ - Thumos on-demand agent reference

On-demand reference for AI agents. CLAUDE.md is instructions (always loaded, short). This directory is reference (loaded when the task needs it, no size limit).

## Why this exists

Thumos is a Rust workspace plus an excluded bare-metal kernel crate. The crate roster in `architecture.toml` is kept 1:1 with `Cargo.toml` workspace members plus that kernel by `../scripts/check-doc-inventory.sh`; derive module counts from the tree when needed. Loading every crate-level doc for every task burns tokens on context the task does not need. This directory compresses canonical repository state into TOML views that scan fast and diff mechanically against the source.

## Files

| File | Contents | Source |
|------|----------|--------|
| `README.md` | Loading order and format rules | Authored |
| `current_state.toml` | Current phase/acceptance truth and selected software-to-hardware boundary threads | Compressed from canonical Kanon state, `../README.md`, and `../docs/capability-inventory.toml` |
| `architecture.toml` | Crate roster and layer roles | Compressed from `../ARCHITECTURE.md` |
| `decisions.toml` | Technology choices with rationale (Rust-only, no Linux, pure-Rust crypto, monolithic kernel) | Compressed from `../CLAUDE.md` + workspace `Cargo.toml` |
| `glossary.toml` | Project vocabulary | Authored projection; canonical source wins where named |

## Loading order

1. **Cold start on any thumos task:** read `current_state.toml`, then `architecture.toml`. The first states the live acceptance boundary; the second maps crate and layer roles.
2. **Before planning a capability change:** read `../docs/capability-inventory.toml` and the live issue. The inventory is the machine-checked reachability source; the tracker owns unfinished work.
3. **Working on a specific crate:** load `architecture.toml` plus the crate's `CLAUDE.md` (per-crate files live in `crates/<name>/CLAUDE.md` when present) plus source.
4. **Hardware / driver work:** load `../docs/HARDWARE.md` for device facts and `../docs/DRIVER-INTERFACES.md` for register maps and init sequences.
5. **Technology choice questions (why snafu? why no openssl?):** load `decisions.toml`. Every decision records the alternative considered and why the project rejected it.
6. **Implementation detail:** read the source directly. These TOML files compress doc content, not code.

## Format rules

- **TOML over markdown** for structured data. Token-efficient and machine-parseable.
- **Cite source docs** in every file header. If the compressed view drifts from the canonical doc, the canonical doc wins. Open an issue. Do not silently align the TOML.
- **No derivable metrics** (crate counts, LOC, test counts). Those rot. Document the command that produces them instead. See `../CLAUDE.md` for current phase status.
- **One fact per row.** `[[crate]]` and `[[decision]]` arrays make diffs mechanical when architecture evolves.

## Regeneration

These files are hand-maintained. When architecture or decisions change, update the TOML in the same PR that changes the canonical doc. The `[[crate]]` arrays should map 1:1 with `Cargo.toml` workspace members plus the excluded kernel crate.
