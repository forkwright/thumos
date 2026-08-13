# Contributing to Thumos

Thumos is a privacy-first Rust mobile OS targeting the AGM M7 (MediaTek MT6739). It is hardware-adjacent and embedded - contributions are welcome from external researchers, radio hackers, and anyone interested in a Rust-from-kernel-to-UI mobile stack.

The repo is public and GitHub is the contribution surface. `origin` is `https://github.com/forkwright/thumos.git`; PRs are opened, reviewed, and merged there, and CI runs on GitHub-hosted runners.

## Opening a PR

```bash
git push origin HEAD:refs/heads/<branch>
gh pr create --base main --head <branch> --title "..." --body "..."
```

The title matters: the repo squash-merges, so a PR title becomes `main`'s commit message and release-please parses it for the changelog and the version bump. `.github/workflows/pr-title.yml` validates it against `CLAUDE.md`'s grammar as a required check.

## Review

Comments and approvals land through stoa. The merge button activates when all gates report green:

- CI status `Pass` (every stage in `.kanon-ci.toml` exits zero, or the stage's `fail_on` predicate reports success).
- Independent verifier `Ok` (03f-e reproduces the headline claims from a fresh checkout of the head sha).
- The `Gate Attestation` check (`.github/workflows/gate-attestation.yml`) reports success. A `Gate-Passed: kanon <version>` trailer on the tip commit takes the fast path; without one, the check runs a real `cargo fmt`/`check`/`clippy`/`nextest` build against the branch instead (skipped only for docs-only PRs). The AI-attribution check always runs, trailer or not, and no trailer is appended by the merge itself. **This check, and `.kanon-ci.toml`'s fmt/check/clippy/nextest stages, do not cover the kernel crate** (`crates/thumos`, excluded from the Cargo workspace) — the `CI` workflow's `kernel` job exercises it (i686 host tests, armv7a cross-compile, QEMU boot and witnesses, and a zero-warning clippy gate across every declared feature configuration). That job **is** a required check, so a red kernel blocks the merge; but a green `Gate Attestation` on its own still does not attest the kernel, because the two cover different trees.

## Merging

```bash
kanon pr merge <pr_number>
```

or the GitHub merge button. Default strategy is `squash`; `--strategy ff` or `--strategy rebase` are supported. A squash merge does not carry the source branch's `Gate-Passed` trailer forward — squashing drops per-commit trailers by construction, so no commit on `main` has one. That absence is expected, not a gap: `Gate Attestation`'s `push`-to-`main` trigger re-runs the full build against the merge commit itself, which is what actually attests `main`.

Branch protection gates the merge: `cargo audit`, `cargo deny`, `gate / gate`, `conventional-commit grammar`, and the `kernel` job must all report success, and `enforce_admins` is on, so the checks bind every merge rather than only external ones.

## Releases

Release authority is declared in `basanos/standards/RELEASES.md`: the operator cuts MAJOR, an agent cuts MINOR and PATCH with no operator interaction required. Read it there.

release-please builds the changelog and computes the version bump entirely from squashed commit messages, i.e. PR titles. A required check (`.github/workflows/pr-title.yml`) validates every PR title against `CLAUDE.md`'s grammar before merge, so a non-conforming title can no longer land silently. `0.1.18`'s release notes predate that check and are known-incomplete: 11 of the 20 commits since `v0.1.17` used a bare scope in the type position and were dropped from both the changelog and the version-bump computation (#665).

One mechanical step is specific to this repo's GitHub mirror and is expected on every cut. A release-please PR is authored by `GITHUB_TOKEN`, and GitHub does not run `on: pull_request` workflows for events its own token triggered — the recursion guard that stops a workflow from endlessly retriggering itself. The branch-protection required checks therefore never execute, and the PR sits with `mergeStateStatus: BLOCKED` reporting no checks at all rather than failing ones.

Re-trigger them as a real-user actor, which is not subject to the guard:

```bash
gh run list --repo forkwright/thumos --branch release-please--branches--main \
  --json databaseId,name,conclusion --jq '.[] | select(.conclusion=="action_required")'
gh run rerun <id> --repo forkwright/thumos   # once per suppressed run
```

Then merge on green, as with any PR. The required contexts are `cargo audit`, `cargo deny`, `gate / gate`, `conventional-commit grammar`, and `kernel (i686 tests + armv7a build)` — read them from branch protection rather than trusting this list. `Dependabot Auto-Merge` stays `action_required` and is *not* required, so `UNSTABLE` with those five green is the expected terminal state for a release PR.

The merge is not the release: release-please's `push`-to-`main` trigger creates the tag and GitHub release afterwards, and that run is not suppressed because a real user performed the merge. Confirm the tag exists before calling a release done.

### `extra-files` jsonpath limitation: no `@.name` equality filters against TOML

`release-please-config.json`'s `extra-files` entries patch first-party version pins in `Cargo.lock`/`Cargo.toml` on every release. For a TOML target, an `@.name == '...'`/`@.name != '...'` equality-or-inequality filter against a `[[package]]` array silently does not do what it looks like it does — release-please's TOML jsonpath evaluation does not correctly compare `@.name` against a string literal there (upstream: [googleapis/release-please#2455](https://github.com/googleapis/release-please/issues/2455), confirmed against an equivalent case on `uv.lock`). Two symptoms follow from the same defect depending on where the broken clause sits:

- As the **sole** predicate (`fuzz/Cargo.lock`'s three original per-crate entries, #768): the filter matches nothing, the extra-file update is a silent no-op, and the field is never touched — proven here across two real releases (0.6.1, 0.6.2) that landed after the selector existed and never touched the file.
- As a **secondary clause in a compound filter** (`crates/thumos/Cargo.lock`'s old `!@.source && @.name != 'thumos'`, #650/#757): the broken comparison makes the exclusion clause always pass, so the intended-to-be-excluded entry gets swept in with everything else anyway — proven by watching `thumos`'s own lock entry get bumped despite the `!= 'thumos'` clause.

Use only existence-style predicates (`!@.source`) for these files, never a name comparison. If one entry in the array (a crate's own self-package, e.g. `thumos`/`peirama`) must not silently drift when the existence-only wildcard sweeps it in too, give that crate's own `Cargo.toml` its own `extra-files` entry (`$.package.version`) so its manifest tracks the same version the wildcard is going to set the lock to — don't try to exclude it from the lock's own selector.

## External contributors

Radio, baseband, and MTK tooling folks: there is nothing special to do. Fork on GitHub and open a PR against `forkwright/thumos:main` as you would on any other project. Review, CI, and the merge all happen there.

The merge commit carries no `Gate-Passed` trailer — squash merges drop per-commit trailers by construction — so `Gate Attestation` re-runs against the merge commit when it lands on `main` via the `push` trigger. That absence is expected, not a gap.

## CI configuration

`.kanon-ci.toml` at the repo root defines the pipeline. Thumos runs the full Rust gate:

- `cargo fmt --all -- --check`
- `cargo check --workspace --all-targets`
- `cd crates/thumos && cargo build --release --target armv7a-none-eabi`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cd crates/thumos && cargo clippy --bin thumos --tests --target i686-unknown-linux-gnu -- -D warnings`
- `cargo nextest run --workspace`
- `kanon lint . --summary`

Per-stage build and test concurrency is pinned to 8 jobs - without this cap, rustc and nextest peak over 100 GB of RSS on the 32-core forge host and collide with other fleet work. See comments in `.kanon-ci.toml` for the budget rationale; keep it in sync with `crates/archeion/src/ci_config.rs::default_rust_gate` if the upstream default shifts.

The kernel binary (`thumos`) lives outside the workspace and has its own build path; CI also cross-compiles it for `armv7a-none-eabi` so workspace-only gates cannot hide no-std or target drift.

## Branch naming and commit format

Branch prefixes and PR title format both follow the `commit_types` grammar declared in `CLAUDE.md`'s Git section — read it there rather than here, so this doc cannot drift from it a second time. Squash merges keep `main` linear, which is why the PR title matters: it becomes `main`'s commit message, and a required check (`.github/workflows/pr-title.yml`) validates every title against that grammar before merge.
