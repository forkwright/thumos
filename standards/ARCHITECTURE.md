# Architecture

> Structural standards for multi-crate workspaces, module organization, and system design. Language-agnostic principles with Rust-specific guidance where noted.

---

## Dependency direction

Dependencies flow one way. Lower layers never import higher layers.

```
Leaf (types, errors, utilities)
  ↓
Low (storage, providers, config)
  ↓
Mid (domain logic, orchestration)
  ↓
High (API surface, handlers)
  ↓
Top (binary entrypoint)
```

Every import must go downward. If a lower crate needs behavior from a higher crate, define a trait in the lower crate and implement it in the higher crate. Dependency inversion, not dependency violation.

No circular dependencies. `cargo tree` must show a DAG. If crate A depends on B and B depends on A, one of them is wrong.

---

## Crate boundaries

Each crate owns one concern. The name states the concern. If you can't name the concern in one word, the crate does too much.

### When to split a crate

- Two modules have no shared types and no mutual imports
- A module could be used by a different project without modification
- Compile times are dominated by one crate (split reduces incremental rebuild scope)

### When NOT to split

- The modules share internal types extensively
- Splitting would require duplicating types or adding a "types" crate
- The split would create a crate with <200 lines

---

## API surface

### Minimize public surface

Default to private. Promote to `pub(crate)` when another module needs it. Promote to `pub` only when another crate needs it.

Every `pub` item is a commitment. Downstream code can depend on it, blocking refactors. A function that's `pub` but only used within the crate is a maintenance liability.

### Thin binaries

The binary crate (top layer) is a thin shell. It parses arguments, wires dependencies together, and delegates to library crates. Business logic never lives in the binary.

Target: binary entrypoint under 100 lines. Each subcommand in its own file.

### Re-exports

Explicit re-exports over wildcards. `pub use types::Fact;` not `pub use types::*;`. Wildcard re-exports leak internal module structure and make it impossible to know what's public without reading the submodule.

---

## Error boundaries

### One error type per crate

Each library crate defines one `Error` enum (or struct). The binary crate uses `anyhow` for top-level aggregation. Library crates never use `anyhow`.

### Context at every boundary

When an error crosses a crate boundary, wrap it with context. The caller should see what the callee was trying to do, not just what went wrong.

```rust
store.open(&path).context(OpenStoreSnafu { path })?;
```

### No error enum explosion

If a crate has 30+ error variants, consider whether a structured diagnostic (single struct with severity + message + trace) would scale better than an enum. Enums are good for 5-15 variants. Beyond that, they become maintenance burden.

---

## Configuration

### Inject, don't global

Configuration flows through function parameters or trait implementations, not global state or environment reads deep in library code. The binary reads config; libraries accept config as arguments.

### Feature flags for optional capabilities

Heavy dependencies (ML models, GUI frameworks, optional integrations) go behind feature flags. A minimal `cargo build` compiles only the core. Default features include what most users need. Optional features require explicit opt-in.

---

## Module organization

**Principle:** Cognitive load determines unit size. A reader should grasp a file's purpose without scrolling, and a function's logic without losing context. The numbers below are guidelines derived from this principle, not rigid limits.

### File size

~800 lines per file guideline. If a file exceeds this, split by logical concern into submodules. The parent module re-exports the public API.

**Explicit exceptions:**
- Data tables, flag definitions, and constant registries where splitting would scatter related data
- Generated code (derive output, schema dumps) that is not human-maintained
- Test fixture files with many small test cases that share setup

### Function size

~50 lines per function guideline. Functions over 50 lines should be split unless:
- **Hot loops** where splitting would hurt cache locality or add function call overhead
- **Data-driven initialization** where the structure is the logic (e.g., a long match/switch mapping inputs to outputs)
- **Sequential pipelines** where each step is one line and extracting would add indirection without clarity

### One module per concern

Each `.rs` file handles one concern. If a file has `struct Foo`, `impl Foo`, and tests for `Foo`, that's one concern. If it also has `struct Bar` with its own impl and tests, split into `foo.rs` and `bar.rs`.

---

## Versioning

### Single workspace version

Multi-crate workspaces use one version in the root `Cargo.toml`. All crates inherit it. One version to bump, one changelog, no per-crate drift.

### Semantic versioning

Pre-1.0: any change can break the API. Post-1.0: breaking changes bump major. Adding variants to a `#[non_exhaustive]` enum is not breaking.

---

## Documentation

### Architecture doc required

Every multi-crate project has an `ARCHITECTURE.md` documenting:
- Crate dependency graph
- Layer boundaries
- Extension points (where to add new functionality)
- Key architectural decisions and their rationale

### Per-crate navigation

Each library crate has a `CLAUDE.md` (or equivalent) with:
- One-line purpose
- Key types and where to find them
- Common tasks ("to add X, modify Y")
- Dependencies (what this crate uses and what uses it)

---

## Compile-time architecture enforcement

Use `clippy.toml` with `disallowed-methods` and `disallowed-types` to enforce architectural boundaries at compile time.

Each crate can have its own `clippy.toml` banning patterns specific to its layer:

```toml
# crates/handlers/clippy.toml
disallowed-methods = [
  { path = "std::fs::read_to_string", reason = "use FileSystem trait" },
  { path = "reqwest::Client::new", reason = "use HttpClient wrapper" },
  { path = "std::process::exit", reason = "use graceful shutdown" },
]
```

This catches architecture violations at compile time. Stronger than code review.

## System abstraction traits

All system operations (filesystem, time, environment, networking) go through trait abstractions, not direct `std::` calls. This enables:
- Cross-platform testing without real filesystem
- Deterministic time in tests (no `sleep`, no wall clock)
- Mockable network for integration tests

Define traits in the lowest common crate. Implement concretely in the binary. Mock in tests.

## Cleanup registration

Register cleanup callbacks at setup time, not drop time. Drop order depends on field declaration order (fragile). Async cleanup in Drop is impossible.

Pattern: explicit callback list registered during initialization, executed in declared order during graceful shutdown.

---

## Scaling patterns (100K+ lOC)

### Flat module layout

Prefer `src/{a,b,c}.rs` over `src/{a/{x,y}}`. Flat structure:
- search (grep finds everything at one depth)
- Clear ownership (one file = one concern)
- to move modules between crates later
- Prevents "mega-modules" that hide complexity

When a module exceeds 800 lines, split into sibling files, not nested directories.

### Glossary

Every multi-crate project maintains a glossary defining project-specific terms. Greek names, domain concepts, runtime abstractions, pipeline stages: all defined in one document. Prevents contributors from using terms inconsistently.

### Test-support feature gates

Mock providers, test fixtures, and helper functions go behind `feature = "test-support"`. Production binary doesn't compile test infrastructure. Test features cascade: `editor/test-support` depends on `text/test-support`.

### Smart CI filtering

Map changed files to changed crates. Run tests for changed crates plus their reverse dependencies. Full suite runs on main/release branches. PR context runs only affected tests.

```
cargo nextest --filter-expr 'rdeps(changed_crates)'
```

### Compile time budget

At 100K+ LOC, compile time matters. Budget strategies:
- `codegen-units = 16` for dev (parallel compilation)
- `codegen-units = 1` for release (better output)
- Proc-macro crates: `opt-level = 3` (they run at compile time)
- Incremental compilation for dev builds
- sccache or similar for CI caching across platforms
