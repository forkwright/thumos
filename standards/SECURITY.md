# Security

> Standards for secure code, credential handling, input validation, and threat mitigation. Applies to all languages and all codebases.

---

## Credentials

### Storage

- Never store credentials in source code, config files, or environment variable defaults
- Credential files: 0600 permissions (owner-read-only). Verify on write, not just creation.
- Use `SecretString` (or language equivalent) for in-memory credential handling. Zeroize on drop.
- No credentials in log output. Redact at the tracing layer, not at each call site.

### Rotation

- OAuth tokens: auto-refresh before expiry. Log refresh failures at WARN.
- API keys: support multiple active keys for zero-downtime rotation.
- JWT signing keys: document rotation procedure in runbook. Never embed in service files.

### Transmission

- TLS for all credential transmission. No HTTP fallback.
- Token prefix in logs (first 8 chars) for debugging. Never full token.
- Credential source (oauth, api-key, file) logged at INFO on startup.

---

## Input validation

### Trust boundaries

Validate at system boundaries only. Internal function calls between trusted modules don't need re-validation.

| Boundary | Validate |
|----------|----------|
| HTTP request body | Schema, size limits, type coercion |
| CLI arguments | Format, range, existence |
| File paths from LLM/user | Canonicalize, check allowed roots, reject symlinks in sensitive paths |
| Database query parameters | Parameterized queries only. Never string concatenation. |
| Tool inputs from agents | Schema validation + path validation + size limits |

### Path validation

```
normalize -> check allowed_roots -> canonicalize -> re-check allowed_roots
```

This sequence catches symlink-based escapes. For writes to sensitive locations, use `O_NOFOLLOW` to prevent symlink following after validation.

### Size limits

Every input has a maximum size. Define it explicitly:

| Input | Limit |
|-------|-------|
| HTTP request body | Configurable (default 1MB) |
| Tool write content | Configurable (default 10MB) |
| Tool exec command | 10KB |
| Datalog query | 10KB |
| File read | 50MB |

Enforce server-side. Client-side limits are UX, not security.

---

## Sandboxing

### Defense in depth

No single security layer. Stack them:

1. **Filesystem** (Landlock on Linux): restrict read/write/exec to declared paths
2. **Syscalls** (seccomp): block dangerous syscalls (exec, mount, ptrace)
3. **Network** (namespace or firewall): restrict egress to declared destinations
4. **Process** (cgroups or rlimit): cap CPU, memory, open files, child processes

### Fail closed

If the sandbox can't be applied (old kernel, missing capability), deny the operation. Don't fall back to unsandboxed execution without explicit operator opt-in.

Log sandbox enforcement status at startup: ENFORCING, PERMISSIVE, or UNAVAILABLE.

---

## Session and identity

### Token generation

Use cryptographically random tokens (128+ bits of entropy). ULIDs (80 bits random + 48 bits time) are insufficient for security-sensitive identifiers when auth is disabled.

Prefer `uuid::Uuid::new_v4()` (128-bit random) or `rand::OsRng` with 256-bit output for session tokens.

### CSRF

State-changing endpoints (POST, PUT, DELETE, PATCH) require CSRF protection. When auth is disabled, CSRF should also be disabled (no circular dependency where the token is only available via an authenticated endpoint).

---

## Error messages

### To users/operators

Include: what failed, how to fix it. Exclude: stack traces, internal paths, database schema.

### To lLM/agents

Return generic "access denied" for path validation failures. Don't reveal whether a path exists. Don't include the rejected path.

### To logs

Full detail: stack trace, paths, parameters, timing. This is where debugging happens.

---

## Dependency supply chain

- `cargo-deny` (or language equivalent) runs on every PR
- Known CVEs tracked in allow list with justification and review date
- No pre-1.0 crates with <1000 monthly downloads in critical paths
- Lockfiles committed for all binary crates
- Verify new dependency exists before adding (AI tools hallucinate package names)

---

## Audit

Every deployed system should have:
- Automated secret scanning (gitleaks, trufflehog) in CI
- Dependency vulnerability scanning in CI
- Manual security review for: auth flows, credential handling, sandbox boundaries, input validation
- Documented threat model: what are we protecting, from whom, at what cost

---

## Plugin/extension security

### Capability-based access

Extensions declare capabilities in their manifest. The host enforces both:
1. What the extension CLAIMS to need (manifest)
2. What the user GRANTS (settings/permissions)

No capability is implicit. Extensions can't escalate privileges at runtime.

### WASM sandboxing

WASM plugins run in sandboxed runtimes (Wasmtime, wasmer). They cannot:
- Access the filesystem beyond preopened directories
- Make network calls except through host-provided imports
- Execute subprocesses except through declared capabilities
- Access memory outside their linear memory space

### Version embedding

Plugin API version is embedded in the WASM binary as a custom section, not just the manifest. This prevents version spoofing (manifest is editable, binary section is not).

### Async isolation

Plugins run on their own task, not the host thread. Communication is via message queue. A stalled plugin cannot freeze the host. Epoch-based yielding prevents infinite loops.
