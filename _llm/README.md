# _llm/ - Thumos on-demand agent reference

On-demand reference for AI agents. CLAUDE.md is instructions (always loaded, short). This directory is reference (loaded when the task needs it, no size limit).

## Why this exists

Thumos is a 13-crate workspace (12 userspace + 1 bare-metal kernel) with a large kernel surface across 107 modules (run `cargo metadata` and `find crates/thumos/src -name '*.rs' | wc -l` for current counts). Loading every crate-level doc for every task burns tokens on context the task does not need. This directory compresses the canonical `docs/` markdown into TOML views that scan fast and diff mechanically against the source.

## Files

| File | Contents | Source |
|------|----------|--------|
| `README.md` | Loading order and format rules | Authored |
| `architecture.toml` | Crate tree, layers, dependency direction | Compressed from `../ARCHITECTURE.md` |
| `decisions.toml` | Technology choices with rationale (Rust-only, no Linux, pure-Rust crypto, monolithic kernel) | Compressed from `../CLAUDE.md` + workspace `Cargo.toml` |

## Loading order

1. **Cold start on any thumos task:** read `architecture.toml` first. It has the crate tree and layer rules, which prevent dependency violations the compiler cannot catch (e.g. `haphe` depending on `eidolon`).
2. **Working on a specific crate:** load `architecture.toml` plus the crate's `CLAUDE.md` (per-crate files live in `crates/<name>/CLAUDE.md` when present) plus source.
3. **Hardware / driver work:** load `../docs/HARDWARE.md` for device facts and `../docs/DRIVER-INTERFACES.md` for register maps and init sequences.
4. **Technology choice questions (why snafu? why no openssl?):** load `decisions.toml`. Every decision records the alternative considered and why it was rejected.
5. **Implementation detail:** read the source directly. These TOML files compress doc content, not code.

## Format rules

- **TOML over markdown** for structured data. Token-efficient and machine-parseable.
- **Cite source docs** in every file header. If the compressed view drifts from the canonical doc, the canonical doc wins. Open an issue; do not silently align the TOML.
- **No derivable metrics** (crate counts, LOC, test counts). Those rot. Document the command that produces them instead. See `../CLAUDE.md` for current phase status.
- **One fact per row.** `[[crate]]` and `[[decision]]` arrays make diffs mechanical when architecture evolves.

## Regeneration

These files are hand-maintained. When architecture or decisions change, update the TOML in the same PR that changes the canonical doc. The `[[crate]]` arrays should map 1:1 with `Cargo.toml` workspace members plus the excluded kernel crate.
