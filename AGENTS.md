<!--
scope: thumos repo cross-tool agent guide (Claude Code, Kimi, Codex, Cursor, Windsurf, Copilot)
generated_by: kanon docs sync
defers_to: CLAUDE.md for Claude Code-specific behavior; ~/menos-ops/CLAUDE.md for machine + service topology
tightens: ~/metis-ops/projects/kanon/workflow/AGENTS-mcp-tools.md catalog routing; ~/metis-ops/projects/kanon/crates/basanos/standards/AGENT-DOCS.md authoring rules
-->

# thumos

Kanon-managed forkwright repository `thumos`.

## Commands

Run `kanon --help` for all kanon-managed workflow commands. Run project-local
build, test, and lint commands from this repository root.

- `kanon gate` - full local gate for kanon-managed PRs
- `kanon lint --fix` - deterministic standards fixes
- `kanon lint --explain <RULE>` - rule rationale and fix guidance
- `kanon pr open <head_ref> --title "..."` - open a forge PR
- `kanon pr merge <N> [--strategy squash|ff|rebase]` - merge after CI and gate checks
- `kanon docs sync --check --repo thumos` - verify derived bootstrap docs
- `kanon docs sync --apply --repo thumos` - regenerate derived bootstrap docs

For agent-native operations, prefer the `mcp__kanon__*` tool family. See
[~/metis-ops/projects/kanon/workflow/AGENTS-mcp-tools.md](~/metis-ops/projects/kanon/workflow/AGENTS-mcp-tools.md) for routing and fallback rules.

## Standards

Read `crates/basanos/standards/STANDARDS.md` § Philosophy before writing code. Key principles:
no workarounds, define once, reference everywhere, no shortcuts, no compromise on quality.
Rust work also reads `crates/basanos/standards/RUST.md` before editing Rust code.

## Rules

- Structured comment tags only: WHY, NOTE, WARNING, PERF, SAFETY, INVARIANT, TODO(#NNN), FIXME(#NNN)
- Conventional commits: `type(scope): description`
- Add `Gate-Passed: kanon 0.1.0` to validated commit bodies
- Never add `#[allow]` suppressions; use `#[expect(lint, reason = "...")]` only when justified
- Prefer MCP tools first; CLI commands are resilience fallbacks

## Architecture

- Registry name: `thumos`
- Forge repo: `forkwright/thumos`
- Kanon prefix: `th`
- Config source: `workflow/kanon.toml [projects.thumos]`

## Boundaries

Always: run the applicable gate before pushing, stay inside the declared blast radius.
Ask first: workflow, service, credential, schema, or deployment changes.
Never: bypass CI, push to protected upstream refs, commit secrets, or suppress warnings.

## Blast zone

- Paths explicitly named by the rendered prompt, role, or template input.

## Acceptance verifier

```bash
kanon gate
```
