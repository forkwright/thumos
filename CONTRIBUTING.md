# Contributing to Thumos

Thumos is a sovereign, privacy-first Rust mobile OS targeting the AGM M7 (MediaTek MT6739). It is hardware-adjacent and embedded - contributions are welcome from external researchers, radio hackers, and anyone interested in a Rust-from-kernel-to-UI mobile stack.

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
- A `Gate-Passed: kanon <version>` trailer is present on the tip commit of the PR branch, or the merge will append one.

## Merging

```bash
kanon pr merge <pr_number>
```

or the forge merge button. Default strategy is `squash`; `--strategy ff` or `--strategy rebase` are supported. The merge commit carries the `Gate-Passed` trailer.

Do not merge via GitHub. The GitHub mirror is read-only from the contributor's perspective: any merge performed there races the forge pr-sync worker and drops the trailer.

## External contributors

Thumos has a real external-contributor path - radio, baseband, and MTK tooling folks without kanon.lan access. The GitHub mirror at `github.com/forkwright/thumos` is fully functional for you:

1. Fork on GitHub, open a PR against `forkwright/thumos:main` as you would on any OSS project.
2. The 05d bidirectional sync ingests the PR into the forge. Review, CI, and the verifier all run there.
3. Discussion may happen on either side; the forge thread is authoritative. The mirror sync relays merge state back to GitHub once the forge merges.
4. The merge always happens on the forge so the `Gate-Passed` trailer and CI artifacts are preserved. GitHub closes your PR when the mirror sync observes the merge commit on `main`.

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

Per `CLAUDE.md`: `feat/`, `fix/`, `docs/`, `refactor/`, `test/`, `cleanup/`, `chore/`. Commit messages are `category(scope): description`. Squash merges keep main linear.
