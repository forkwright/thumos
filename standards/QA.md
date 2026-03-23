# QA

> The audit playbook. Defines what a periodic audit and a full audit contain, how findings are captured, and how the process improves itself. Per-PR checks are handled by the dispatch pipeline and CI, not this document.

---

## Purpose

The goal is perfection. Every audit asks: is this the best it can be? If not, file the issue. The backlog is the distance between where the code is and where it should be. Measuring that distance honestly is the audit's job.

## Principles

**The standard is perfection.** Audit against the full standards in this directory. Every rule in every standard document applies. Reference standards by name (RUST.md, WRITING.md, SECURITY.md, etc.) rather than restating rules here. This document defines process. The criteria live in the standards.

**Every finding becomes a structured issue.** A well-researched GitHub issue on the relevant repository with: what's wrong, where it is (file + line), which standard it violates, and how to fix it. If the finding is about tooling or standards, log it on kanon.

**Every audit produces training data.** Each audit writes structured JSON to `workflow/training/audits/` capturing findings, scores, and context. This data trains future models to audit better, write cleaner code, and align with ecosystem standards. See [Training data output](#training-data-output).

**The audit audits itself.** If the linter misses something a standard requires, file on kanon. If a standard is ambiguous or missing a case, file on kanon. If the audit process is inefficient, file on kanon. Tooling and standards improve every cycle.

**Verify, don't trust.** If a doc says the system does X, check the code. If an issue is closed, verify the fix exists. If the linter says clean, check whether it's running all rules.

**Nothing is too small.** Every violation gets filed. Dismissing things as minor means they never get fixed.

**DRY applies to everything.** Duplicated constants, repeated boilerplate, copy-pasted logic, redundant documentation, restated rules: all are audit targets. Parameterize. Modularize. Reference, don't restate.

**Audit from every angle.** Mechanical linting catches syntax. LLM review catches design and prose quality. User testing catches UX. External comparison catches ambition gaps. Closed-issue verification catches regressions.

**Compare against the best.** Audit against best-in-class projects in the same domain. File issues for every gap. Update standards with every new pattern.

**Test from the user's seat.** Deploy the system. Use it as an operator would. File every friction point.

**Question your own completeness.** After every pass: what haven't I checked? What angle haven't I considered? The audit is done when you can't think of another question.

---

## Per-PR checks (handled by dispatch)

Format, clippy, tests, commit lint, and CI security scans run automatically via the kanon dispatch pipeline and GitHub CI. Not part of QA audits. See `crates/phronesis/` and `.github/workflows/`.

---

## Periodic audit

Covers what dispatch does NOT check: violation trends, privacy drift, and standards enforcement gaps.

### 1. violation baseline

```bash
kanon lint /path/to/repo --summary
```

All checker modules. Compare violation count against tracking issue baseline. Direction matters: trending down?

### 2. privacy and secrets

```bash
kanon scan /path/to/repo
gitleaks detect --source /path/to/repo
```

- No API keys, tokens, or credentials (even example ones that look real)
- No personal identifiers in code, comments, test fixtures, or commit messages
- No internal hostnames, IPs, or infrastructure details
- No customer data or employer-identifying information
- No private file paths revealing system layout
- `.gitignore` covers: `.env`, `credentials/`, `*.key`, `*.pem`, `instance/`

Public repo: assume everything committed is permanently visible.

### 3. standards enforcement gap

Compare standards docs against `crates/basanos/src/rules/` modules. Any rule without a linter check needs a kanon issue explaining why it can't be automated or tracking the work to automate it.

---

## Full audit

All phases of the periodic audit, plus the following.

### Phase 1: automated

#### 1.1 full test suite

```bash
cargo test --workspace --all-features
```

Per-crate if all-features OOMs. Document which commands produce full coverage.

#### 1.2 fuzz targets

```bash
cargo fuzz list
cargo fuzz run <target> -- -max_total_time=60
```

Each target 60 seconds. Crashes are bugs.

#### 1.3 binary smoke test

Build release binary. Init. Start. Health check. Create session. Send message. Verify response. Stop. The full deploy pipeline end-to-end.

#### 1.4 dependency audit

```bash
cargo tree -d
cargo outdated
```

Flag duplicates. Flag stale deps.

### Phase 2: writing and docs (LLM-assisted)

#### 2.1 writing quality

Linter writing checks, then LLM review of: AI pattern detection beyond keywords, information density, opening sentence quality, verb strength, hedging. Sample: changed files since last audit plus 5 random unchanged files.

#### 2.2 doc accuracy

Changed docs since last audit: do code references point to real files? Do numbers match reality? Are examples runnable?

#### 2.3 cLAUDE.md freshness

Does CLAUDE.md match the codebase? Paths correct? CLI subcommands current?

### Phase 3: code quality (LLM-assisted)

#### 3.1 dead code

`#[allow(dead_code)]` justified? Commented-out blocks deletable? TODOs reference open issues? Empty match arms explained?

#### 3.2 error handling

Sample 10 error paths. Each: explains what went wrong AND how to fix it? Context propagates correctly?

#### 3.3 unsafe audit

Every `unsafe` block: SAFETY comment? Invariant correct? Replaceable with safe code?

#### 3.4 public API surface

New public items justified? Could any be `pub(crate)`? Documented?

### Phase 4: architecture (LLM-assisted)

#### 4.1 dependency direction

No upward dependencies. Check with `cargo tree`.

#### 4.2 crate boundary review

Any crate past 800 files or 50K lines?

#### 4.3 per-crate cLAUDE.md accuracy

Referenced types exist? Module paths correct? Common tasks accurate?

#### 4.4 repository structure audit

See STANDARDS.md § Repository Hygiene for the principles. Check:
- Every root file justified? (required at root by its consuming tool?)
- Shell scripts that should be native subcommands?
- Config files that belong with their consuming system?
- Empty directories, orphaned files, stale templates?
- Operational artifacts mixed with source code?
- Standards/data files separated from the tool that uses them?

### Phase 5: security (LLM-assisted)

#### 5.1 credential handling

New credential paths using 0600? Secrets redacted in logs? `std::fs::write` to config paths without explicit permissions?

#### 5.2 input validation

New HTTP endpoints validate at boundary? New tool inputs check allowed_roots? New queries parameterized?

#### 5.3 sandbox

New `tokio::spawn` without `.instrument()`? New process spawning without ProcessGuard? New file ops bypassing FileSystem trait?

### Phase 6: operational readiness

Runbook covers new components? New features emit metrics? Backup restore tested?

### Phase 7: regression

#### 7.1 closed issue verification

Sample 10 recently closed issues. Verify fix exists in current code.

#### 7.2 unported feature check

Review open unported-feature issues. Any inadvertently implemented? Close if so.

### Phase 8: external benchmark

Pick one well-respected project. Audit against kanon standards. Compare. File gaps. Update standards.

---

## Audit outputs

Every audit produces three things:

### 1. issues on the target repo

Each finding: GitHub issue with title (conventional format), body (what's wrong, file + line, standard violated, fix). One issue per finding. Reference standard by name.

### 2. issues on kanon

Standards unclear or missing a case. Linter rule that should exist. Audit step that was inefficient. Standard that contradicts another. Tool that's broken or gives false positives.

### 3. training data

Each audit writes a JSONL file to `workflow/training/audits/`:

**Filename:** `{repo}_{date}_{tier}.jsonl` (e.g., `aletheia_2026-03-20_full.jsonl`)

**Schema (one line per finding):**

```json
{
  "ts": "2026-03-20T14:30:00Z",
  "repo": "forkwright/aletheia",
  "tier": "full",
  "phase": "3.1",
  "rule": "RUST.md/dead-code",
  "file": "crates/nous/src/recall.rs",
  "line": 142,
  "severity": "medium",
  "finding": "Commented-out code block (15 lines) with no TODO or issue reference",
  "fix": "Delete or file issue with reference",
  "context": "fn score_candidates() contains disabled similarity threshold logic"
}
```

**Summary record (last line):**

```json
{
  "ts": "2026-03-20T16:00:00Z",
  "repo": "forkwright/aletheia",
  "tier": "full",
  "type": "summary",
  "version": "v0.13.0",
  "violations_total": 2221,
  "violations_delta": -126,
  "issues_filed": 15,
  "kanon_issues_filed": 3,
  "phases_completed": [1,2,3,4,5,6,7],
  "scores": {
    "writing": "A-",
    "safety": "A",
    "architecture": "B+",
    "testing": "B",
    "security": "B+",
    "operations": "B"
  }
}
```

This data feeds model fine-tuning for: code review, standards compliance detection, issue writing, and audit automation. Every audit makes the next audit's tooling better.

---

## Standards reference

Audit checks compliance against the full kanon standards library:

| Standard | Scope |
|----------|-------|
| STANDARDS.md | Universal principles |
| RUST.md | Rust language |
| PYTHON.md | Python language |
| SHELL.md | Shell scripts |
| WRITING.md | All prose and documentation |
| ARCHITECTURE.md | Structure, dependencies, API surface |
| TESTING.md | Test organization, coverage, infrastructure |
| SECURITY.md | Credentials, validation, sandboxing |
| OPERATIONS.md | Runbooks, monitoring, backup, deployment |
| API.md | HTTP endpoints, CLI, error responses |
| CI.md | Required checks, release process |
| YAML.md | YAML formatting, GitHub Actions workflow structure |
| PERFORMANCE.md | Resource budgets, benchmarks |
| STORAGE.md | Database, migrations, connections |
| TOML.md | TOML formatting, structure, Cargo.toml conventions |
| PROTOBUF.md | Protobuf schema design, naming, compatibility |

The standards are the criteria. This document is the process.
