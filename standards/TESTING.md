# Testing

> Additive to STANDARDS.md. Covers testing strategy, organization, and expectations across all languages.

---

See STANDARDS.md § Testing for core principles.

---

## When to test

| Situation | Required | Type |
|-----------|----------|------|
| Public API function | Yes | Unit |
| Error path / edge case | Yes | Unit |
| Cross-module interaction | Yes | Integration |
| User-visible workflow | Yes | Integration or E2E |
| Pure internal helper | No (unless complex) | Unit if needed |
| Rendering / UI layout | No (use snapshots sparingly) | Visual regression |
| Performance-sensitive path | Yes | Benchmark |

Don't test private functions directly. Test them through the public API. If a private function is complex enough to need its own tests, it should be a public function in a smaller module.

## When NOT to test

- getters/setters
- Direct delegation (fn that calls one other fn and returns)
- Generated code (macros, derive)
- Third-party library behavior (test your usage, not their code)

---

## Organization

### Colocated tests (preferred)

```rust
// In the same file as the code
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn rejects_empty_input() { /* ... */ }
}
```

Tests live next to the code they test. One `#[cfg(test)]` block per file. No separate `tests/` directory for unit tests.

### Integration tests

For cross-crate behavior, use a dedicated `tests/` directory or integration test crate. Integration tests exercise the public API as an external consumer would.

### Test naming

Name tests for the behavior, not the function:

| Bad | Good |
|-----|------|
| `test_parse` | `parses_valid_toml` |
| `test_error` | `rejects_negative_timeout` |
| `test_new` | `default_config_uses_port_18789` |

Pattern: `verb_condition` or `condition_produces_result`.

---

## Test quality

### One assertion per behavior

A test should verify one behavior. Multiple assertions are acceptable when they verify facets of the same behavior, not when they test unrelated things.

### No test interdependence

Tests must pass in any order, in isolation, and in parallel. No shared mutable state between tests. No test that depends on another test having run first.

### Deterministic

No sleep, no wall-clock time, no network calls, no filesystem race conditions. Use:
- `tokio::time::pause()` for async timing
- Temp directories for filesystem
- Mock servers for HTTP
- Fixed seeds for random

A flaky test is a bug. Fix or delete it.

### Real over mock

Prefer real implementations over mocks when practical. A test hitting a real SQLite database catches more bugs than a mock that returns hardcoded data. Mock only at boundaries you don't control (external APIs, hardware).

### Error paths are paths

Test error cases with the same rigor as success cases. Every `Result::Err` variant should have at least one test that triggers it.

---

## Coverage expectations

No numeric coverage target. Coverage metrics reward testing code and penalize testing complex code. Instead:

- Every public function has at least one test
- Every error variant has at least one test that produces it
- Every match arm with non-logic has a test
- Critical paths (auth, payment, data persistence) have integration tests

---

## Fuzz testing

Parsers, serializers, and any code that handles untrusted input should have fuzz targets. Use `cargo fuzz` with `libfuzzer`. Maintain a corpus directory with seed inputs.

Run fuzz targets periodically (CI nightly or pre-release), not on every PR.

---

## Benchmarks

Performance-sensitive code gets benchmarks, not just tests. Use `criterion` or `divan`. Benchmarks live in `benches/` and run separately from tests.

Benchmark before optimizing. Benchmark after optimizing. Commit both results.

---

## Component spec validation

Define compliance specs for each component type. After every test, automatically validate that required metrics, events, and traces were produced.

```rust
pub async fn assert_component_compliance<T>(spec: &ComponentSpec, f: impl Future<Output = T>) -> T {
    init_test();
    let result = f.await;
    spec.assert();  // Validates metrics + events were emitted
    result
}
```

This catches observability regressions: if a refactor removes a metric emission, the test fails even though the functional behavior is unchanged.

## Mock components as real implementations

Mocks implement the same traits as production code. They compose into real topologies for integration testing. A mock that returns hardcoded data through a different interface than production code tests the mock, not the system.

Pattern: `MockProvider` implements `LlmProvider`. `MockStore` implements `SessionStore`. Both plug into real pipelines.

## Property-based testing

For stateful systems, use property-based testing with action sequence generation:

1. Define possible actions (create, read, update, delete, etc.)
2. Generate random action sequences
3. Sanitize sequences to only valid combinations
4. Execute against system under test AND in-memory model
5. Assert system state matches model state

Persist regression corpus (minimal failing cases) in git via `proptest-regressions/`.

## Test runner configuration

Use nextest for Rust projects:

```toml
# .config/nextest.toml
[profile.default]
retries = 3
slow-timeout = { period = "30s", terminate-after = 4 }
failure-output = "immediate-final"
junit.path = "junit.xml"
```

Benefits over `cargo test`: retries, timeouts, JUnit output, per-test parallelism, better failure reporting.

## Async test utilities

Build reusable async wait helpers instead of `sleep()`:

```rust
pub async fn wait_for<F, Fut>(f: F)
where F: Fn() -> Fut, Fut: Future<Output = bool> {
    let mut delay = 5; // ms
    loop {
        if f().await { return; }
        tokio::time::sleep(Duration::from_millis(delay)).await;
        delay = (delay * 2).min(500);
    }
}
```

Exponential backoff from 5ms to 500ms. No arbitrary `sleep(1s)`.
