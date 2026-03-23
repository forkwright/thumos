# Performance

> Standards for performance-aware development. Not premature optimization: measured, intentional performance decisions.

---

## Philosophy

Don't optimize without measuring. Don't measure without a reason. The default is "fast enough." Optimize only when evidence shows a bottleneck.

---

## Measurement

### Before optimizing

1. Define the metric (latency, throughput, memory, binary size)
2. Measure the baseline (with the current code, in realistic conditions)
3. Set the target (what "fast enough" means for this use case)
4. Profile to find the bottleneck (don't guess)

### After optimizing

1. Measure again (same conditions as baseline)
2. Verify the target is met
3. Commit the benchmark alongside the optimization
4. Document why in the commit message

---

## Resource budgets

Define explicit resource budgets for deployed services:

| Resource | Budget | Enforcement |
|----------|--------|-------------|
| Memory (RSS) | Documented per service | Monitor, alert at 80% |
| Startup time | < 5 seconds (excluding model loading) | CI benchmark |
| Request latency (p99) | Documented per endpoint | Prometheus alert |
| Binary size | Documented, tracked per release | CI size check |
| Database size | Documented growth rate | Maintenance task alerts |

Budgets are documented in the runbook and enforced by monitoring.

---

## Benchmarks

### Infrastructure

Use `criterion` (Rust), `pytest-benchmark` (Python), or equivalent. Benchmarks live in `benches/` and run separately from tests.

### What to benchmark

- Hot paths (request handling, parsing, serialization)
- Startup time
- Memory allocation patterns in loops
- Database query patterns under load

### What NOT to benchmark

- Cold paths (config loading, one-time initialization)
- I/O-bound operations (network, disk) unless testing batching/buffering
- operations where the overhead of benchmarking exceeds the operation

---

## Common patterns

### Avoid allocation in hot loops

Pre-allocate buffers. Reuse `Vec`, `String`, `HashMap` across iterations. Use `with_capacity()` when the size is known.

### Prefer streaming over buffering

Process data as it arrives. Don't accumulate entire responses in memory when streaming is possible. This applies to: LLM responses, file I/O, HTTP responses, database result sets.

### Lazy initialization

Expensive resources (embedding models, database connections, large indices) initialize on first use, not at startup. Use `LazyLock` or equivalent.

### Feature-gate heavy dependencies

ML models, GUI frameworks, and optional integrations behind feature flags. A minimal build should be fast to compile and small to deploy.
