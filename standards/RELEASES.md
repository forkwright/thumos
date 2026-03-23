# Releases

> Standards for versioning, release process, changelog format, and binary distribution. Applies to all shipped software across all forkwright repositories.

---

## Versioning

### SemVer 2.0

All projects follow [Semantic Versioning 2.0.0](https://semver.org/). Version format: `MAJOR.MINOR.PATCH`.

| Component | Meaning |
|-----------|---------|
| MAJOR | Incompatible API changes |
| MINOR | New functionality, backward-compatible |
| PATCH | Backward-compatible bug fixes |

### Pre-1.0 convention

Pre-1.0 projects use `0.MINOR.PATCH`:

| Bump | When | Examples |
|------|------|---------|
| PATCH (0.x.Y) | Bug fixes, security patches, doc fixes, test additions, lint compliance. No API or behavioral change. | Fix SQLite busy_timeout, fix TUI scroll, add missing_docs |
| MINOR (0.X.0) | New features, architectural changes, breaking internal API changes, crate splits, new crate additions. | Mneme split, desktop views, new tool types, embedding model upgrade |

MAJOR remains 0 until the project commits to a stable public API.

### Post-1.0 convention

| Bump | When |
|------|------|
| PATCH | Bug fixes, security patches, documentation corrections |
| MINOR | New features, deprecations (old API still works) |
| MAJOR | Removed or changed public API surface |

---

## When to bump

Version bumps happen **per-wave, not per-PR**. A wave is a coherent batch of work with a unifying theme (e.g. "Wave 10: Desktop + Mneme Split").

Exceptions:
- **Security fixes** get an immediate PATCH bump and release.
- **Critical runtime bugs** (data loss, crash on startup) get an immediate PATCH bump.

The version bump is a dedicated commit at the wave boundary:
1. Update `workspace.package.version` in root `Cargo.toml`
2. Let release-please handle CHANGELOG generation from conventional commits
3. Review and merge the release-please PR
4. Tag triggers binary build + publish

---

## Release process

### Automation via release-please

Every repository uses [release-please](https://github.com/googleapis/release-please) for automated release management. The flow:

1. Conventional commits land on main (`feat:`, `fix:`, `docs:`, etc.)
2. release-please opens (or updates) a single PR bumping version + updating CHANGELOG.md
3. Operator reviews the generated CHANGELOG, edits if needed, merges
4. Merge creates a git tag (`vX.Y.Z`)
5. Tag triggers `release.yml` workflow: build binaries, attach to GitHub release

release-please PRs are **never auto-merged**. They are the version gate requiring operator sign-off.

### Trigger frequency

Run release-please on an **hourly schedule**, not on every push to main. During active dispatch batches we merge 10-30 PRs/hour; running release-please per-push wastes CI minutes and creates noise. The hourly run picks up all accumulated commits and updates the single release PR.

Also enable `workflow_dispatch` for manual trigger when cutting a release immediately.

```yaml
on:
  schedule:
    - cron: "0 * * * *"
  workflow_dispatch:
```

### Changelog visibility

Show `feat`, `fix`, `perf`, `refactor`, and `docs` in the changelog. Hide `test`, `chore`, `ci`, `style`. Refactors and documentation are substantial work in this ecosystem (crate extractions, architecture changes, standards updates) -- hiding them misrepresents the release.

### Required configuration files

Every released repository must have:

| File | Purpose |
|------|---------|
| `release-please-config.json` | Package type, changelog sections, bump rules |
| `.release-please-manifest.json` | Current version (`{".": "X.Y.Z"}`) |
| `.github/workflows/release-please.yml` | Hourly schedule + workflow_dispatch trigger |
| `.github/workflows/release.yml` | Workflow that builds and publishes on tag creation |

### Version source of truth

`workspace.package.version` in the root `Cargo.toml` is the single version source. All crates in the workspace inherit it via `version.workspace = true`. Never version crates independently within a workspace.

---

## CHANGELOG format

release-please generates changelog entries from conventional commits. The format follows [Keep a Changelog](https://keepachangelog.com/):

```markdown
## [0.14.0] -- 2026-XX-XX

### Added
- Mneme crate split: eidos, krites, graphe, episteme
- Desktop app: 7 views with real functionality

### Changed
- theatron-core extracted from theatron-tui

### Fixed
- SQLite busy_timeout race under concurrent access

### Removed
- Legacy webchat shim
```

Sections used: **Added**, **Changed**, **Fixed**, **Removed**. Empty sections are omitted.

Commit types map to changelog sections:

| Commit type | CHANGELOG section |
|-------------|-------------------|
| `feat` | Added |
| `fix` | Fixed |
| `refactor`, `perf` | Changed |
| `docs`, `test`, `chore`, `ci` | Hidden (not in CHANGELOG) |
| `revert` | Removed or Changed (context-dependent) |

---

## Binary distribution

### Tarball structure

Each release produces tarballs, one per target:

```
aletheia-0.13.0-x86_64-unknown-linux-musl.tar.gz
├── aletheia              # Static binary
└── instance.example/     # Example config directory structure
```

Binary name matches the repository name. No version in the binary filename.

### Checksums

Every tarball has a matching SHA256 checksum file:

```
aletheia-0.13.0-x86_64-unknown-linux-musl.tar.gz.sha256
```

Checksum format: `<hash> <filename>` (two-space separator, matching `sha256sum` output).

### SBOM

Each release attaches a Software Bill of Materials in SPDX JSON format. Generated via `cargo sbom` or equivalent tooling.

---

## Target matrix

### Minimum (all shipped projects)

| Target | Runner | Method |
|--------|--------|--------|
| `x86_64-unknown-linux-musl` | `ubuntu-latest` | cross |
| `aarch64-apple-darwin` | `macos-latest` | native (cargo build) |

musl produces fully static Linux binaries. macOS aarch64 covers Apple Silicon.

### Extended (when user demand exists)

| Target | Runner | Method |
|--------|--------|--------|
| `aarch64-unknown-linux-musl` | `ubuntu-latest` | cross |
| `x86_64-apple-darwin` | `macos-13` | native |

Add targets only when there are users on that platform. Do not speculatively build for platforms nobody uses.

---

## Named versions

Post-1.0, major versions get Greek names following the gnomon naming system. The name captures the essential character of the release, not a marketing slogan.

Pre-1.0 versions are numbered only.

---

## Rollback

Every release preserves the previous binary. The rollback procedure:

1. Stop service
2. Swap binary (previous version is at a known path or in the prior GitHub release)
3. Start service
4. Health check

Database migrations are forward-only. Rollback SQL is documented per migration but treated as emergency-only. Design migrations to be backward-compatible where possible.

---

## Pre-release checklist

Before merging a release-please PR:

- [ ] All CI checks pass on main
- [ ] CHANGELOG entries accurately describe the wave's changes
- [ ] No unreleased breaking changes hiding behind feature flags
- [ ] Version bump magnitude matches the nature of changes
- [ ] Security advisories addressed (no unpatched CVEs in release)
