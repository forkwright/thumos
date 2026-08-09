# Contributing to Thumos

Thumos is a privacy-first Rust mobile OS targeting the AGM M7 (MediaTek MT6739). It is hardware-adjacent and embedded - contributions are welcome from external researchers, radio hackers, and anyone interested in a Rust-from-kernel-to-UI mobile stack.

The repo uses the self-hosted kanon forge as the authoritative PR surface. GitHub stays bidirectionally mirrored for external discoverability, but PRs live on the forge.

## Push target

```
origin = http://kanon.lan/forkwright/thumos.git   (authoritative)
github = git@github.com:forkwright/thumos.git     (mirror)
```

Push to `origin`. The forge post-receive hook runs CI (`.kanon-ci.toml`) and mirrors merge commits to GitHub via the pr-sync worker.

## Opening a PR

Two paths, same effect:

**Stoa UI.** Open `http://kanon.lan/prs/forkwright/thumos`, click "New PR", pick base + head refs, review diff, submit.

**CLI.**

```bash
git push origin HEAD:refs/heads/<branch>
kanon pr open <branch> --title "..." --body "..."
```

`kanon pr open` prints the new PR number and its forge URL.

## Review

Comments and approvals land through stoa. The merge button activates when all gates report green:

- CI status `Pass` (every stage in `.kanon-ci.toml` exits zero, or the stage's `fail_on` predicate reports success).
- Independent verifier `Ok` (03f-e reproduces the headline claims from a fresh checkout of the head sha).
- The `Gate Attestation` check (`.github/workflows/gate-attestation.yml`) reports success. A `Gate-Passed: kanon <version>` trailer on the tip commit takes the fast path; without one, the check runs a real `cargo fmt`/`check`/`clippy`/`nextest` build against the branch instead (skipped only for docs-only PRs). The AI-attribution check always runs, trailer or not, and no trailer is appended by the merge itself. **This check, and `.kanon-ci.toml`'s fmt/check/clippy/nextest stages, do not cover the kernel crate** (`crates/thumos`, excluded from the Cargo workspace) — only the separate, non-required `CI` workflow's kernel job (i686 host tests, armv7a cross-compile, QEMU boot) exercises it. A green `Gate Attestation` check does not attest the kernel.

## Merging

```bash
kanon pr merge <pr_number>
```

or the forge merge button. Default strategy is `squash`; `--strategy ff` or `--strategy rebase` are supported. A squash merge does not carry the source branch's `Gate-Passed` trailer forward — squashing drops per-commit trailers by construction, so no commit on `main` has one. That absence is expected, not a gap: `Gate Attestation`'s `push`-to-`main` trigger re-runs the full build against the merge commit itself, which is what actually attests `main`.

Do not merge via GitHub. The GitHub mirror is read-only from the contributor's perspective: any merge performed there races the forge pr-sync worker.

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

Then merge on green, as with any PR. The three required contexts are `cargo audit`, `cargo deny`, and `gate / gate` — read them from branch protection rather than trusting this list. `Dependabot Auto-Merge` stays `action_required` and is *not* required, so `UNSTABLE` with those three green is the expected terminal state for a release PR.

The merge is not the release: release-please's `push`-to-`main` trigger creates the tag and GitHub release afterwards, and that run is not suppressed because a real user performed the merge. Confirm the tag exists before calling a release done.

## External contributors

Thumos has a real external-contributor path - radio, baseband, and MTK tooling folks without kanon.lan access. The GitHub mirror at `github.com/forkwright/thumos` is fully functional for you:

1. Fork on GitHub, open a PR against `forkwright/thumos:main` as you would on any OSS project.
2. The 05d bidirectional sync ingests the PR into the forge. Review, CI, and the verifier all run there.
3. Discussion may happen on either side; the forge thread is authoritative. The mirror sync relays merge state back to GitHub once the forge merges.
4. The merge always happens on the forge; CI artifacts from that run are preserved there. The merge commit itself carries no `Gate-Passed` trailer — squash merges drop it — so `Gate Attestation` independently re-verifies the merge commit when it lands on `main` via GitHub's `push` trigger. GitHub closes your PR when the mirror sync observes the merge commit on `main`.

You do not need a kanon.lan account to contribute. The GitHub path is a first-class inbound route, not a courtesy.

## Fallback

If the forge is unreachable from within the fleet, push to `github` and open a GitHub PR. When the forge is back, its pr-sync worker picks up the PR and continues from there. This is an escape hatch for fleet operators, not a preferred path - use it only when kanon.lan is actually down.

## CI configuration

`.kanon-ci.toml` at the repo root defines the pipeline. Thumos runs the full Rust gate:

- `cargo fmt --all -- --check`
- `cargo check --workspace --all-targets`
- `cd crates/thumos && cargo build --release --target armv7a-none-eabi`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo nextest run --workspace`
- `kanon lint . --summary`

Per-stage build and test concurrency is pinned to 8 jobs - without this cap, rustc and nextest peak over 100 GB of RSS on the 32-core forge host and collide with other fleet work. See comments in `.kanon-ci.toml` for the budget rationale; keep it in sync with `crates/archeion/src/ci_config.rs::default_rust_gate` if the upstream default shifts.

The kernel binary (`thumos`) lives outside the workspace and has its own build path; CI also cross-compiles it for `armv7a-none-eabi` so workspace-only gates cannot hide no-std or target drift.

## Branch naming and commit format

Branch prefixes and PR title format both follow the `commit_types` grammar declared in `CLAUDE.md`'s Git section — read it there rather than here, so this doc cannot drift from it a second time. Squash merges keep `main` linear, which is why the PR title matters: it becomes `main`'s commit message, and a required check (`.github/workflows/pr-title.yml`) validates every title against that grammar before merge.
