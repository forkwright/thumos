# Operations

> Standards for deployment, monitoring, backup, incident response, and operational readiness. If it runs in production, these rules apply.

---

## Runbooks

Every deployed service has a runbook covering:

| Section | Contents |
|---------|----------|
| Architecture | What runs, what it depends on, how components connect |
| Start/stop | Exact commands for service lifecycle |
| Health check | How to verify the service is working |
| Common issues | Top 5 failure modes with resolution steps |
| Credential rotation | Step-by-step for each credential type |
| Database inspection | How to query, verify integrity, repair |
| Backup/restore | How to create, verify, and restore from backup |
| Performance debugging | How to identify and resolve latency/memory/CPU issues |
| Escalation | Who to contact, when to escalate |

A runbook is complete when an on-call engineer who has never seen the service can diagnose and resolve the top 5 issues without help.

---

## Monitoring

### Required health checks

Every service exposes:
- Liveness endpoint (is the process running?)
- Readiness endpoint (can it handle requests?)
- Dependency checks (are database, cache, external APIs reachable?)

### Required metrics

| Metric | Type | Purpose |
|--------|------|---------|
| Request latency (p50, p95, p99) | Histogram | Performance regression detection |
| Error rate by type | Counter | Reliability tracking |
| Active connections/sessions | Gauge | Capacity planning |
| Dependency latency | Histogram | Bottleneck identification |
| Resource usage (CPU, memory, disk) | Gauge | Capacity planning |

### Alerting thresholds

Document alerting thresholds in the runbook. At minimum:
- Error rate > 5% sustained for 5 minutes
- p99 latency > 10x baseline for 5 minutes
- Disk usage > 80%
- Health check failure for 3 consecutive checks

---

## Backup

### Automated schedule

Every persistent data store has automated backups. No manual-only backup processes.

| Frequency | Retention | Verification |
|-----------|-----------|-------------|
| Daily | 7 days | Automated restore test weekly |
| Weekly | 4 weeks | Manual restore test monthly |
| Pre-upgrade | Until next successful upgrade | Verify before upgrading |

### Restore verification

A backup you've never restored from is not a backup. Test restores on a schedule. Document the restore procedure. Time the restore. Include the time in the runbook.

### What to back up

- Database files (SQLite, Postgres dumps)
- Knowledge stores (vector indices, graph databases)
- Configuration (encrypted credentials, TOML config)
- Agent state (workspace files, memory)

What NOT to back up: logs (ephemeral), build artifacts (reproducible), cache (rebuildable).

---

## Deployment

### Upgrade procedure

1. Back up (verify backup integrity before proceeding)
2. Stop service
3. Replace binary (verify checksum)
4. Start service
5. Health check (automated, with timeout)
6. Smoke test (one real request through the system)

### Rollback

Every deployment is rollback-safe. The rollback procedure is tested and documented.

Requirements:
- Previous binary preserved (not overwritten)
- Database migrations are forward-only with documented rollback SQL
- Rollback script tested against actual deployment

### Zero-downtime (when applicable)

For services requiring uptime:
- Blue-green deployment OR rolling restart
- Health check gates before traffic shift
- Automatic rollback on health check failure

---

## Incident response

### Severity levels

| Level | Definition | Response time |
|-------|-----------|---------------|
| P0 | Service down, data loss risk | Immediate |
| P1 | Degraded, user impact | 1 hour |
| P2 | Degraded, no user impact | Next business day |
| P3 | Cosmetic or minor | Next sprint |

### Post-incident

Every P0/P1 incident gets a post-mortem within 48 hours:
- Timeline (what happened, when)
- Root cause (not "human error" but what made the error possible)
- Action items (what changes prevent recurrence)
- Owner and deadline for each action item

---

## Config validation

### Pre-flight checks

Before starting a service, validate not just config syntax but resource availability:

| Check | What | Why |
|-------|------|-----|
| Disk space | Data directories have sufficient free space | Prevents write failures mid-operation |
| Port availability | Listen ports are free | Prevents bind errors at startup |
| Credential validity | Auth tokens work (single probe request) | Prevents cryptic 401s after minutes of operation |
| Network reachability | External dependencies respond | Surfaces network issues before user traffic |

### Hot reload

File-based config should support hot reload:
1. File watcher (inotify/kqueue) with debounce (1 second minimum)
2. Config loaded and validated before applying
3. Diff against running config: only changed components restart
4. Rollback on validation failure (keep running config)
5. Log what changed and what restarted

### Environment variable interpolation

Config values support variable expansion: `${VAR}`, `${VAR:-default}`, `${VAR:?error}`.
Reject multiline values to prevent config injection.

## Observability patterns

### Internal events

Every significant internal event co-emits a structured log AND a metric counter. They are coupled, not separate concerns. Pattern:

```
event happens -> emit(InternalEvent) -> log at appropriate level + increment counter
```

This prevents drift between what logs say and what metrics measure.

### Circuit breaker

External service calls use a 3-state circuit breaker:
- **Closed**: normal operation
- **Open**: N consecutive failures, all calls rejected (backoff with jitter)
- **HalfOpen**: after backoff, probe single request. Success closes, failure reopens.

Prevents thundering herd on recovery.

### Adaptive concurrency

Long-running services adjust concurrent request limits based on response latency:
- Start at 1
- Increase gradually while latency stays within bounds
- Decrease on latency spikes (EWMA smoothing)
- Hard cap at configured maximum

### Backpressure

Every buffered channel has explicit capacity. When full:
- **Block** (default): upstream pauses, backpressure propagates
- **Drop**: excess events dropped, counter incremented

No unbounded channels in production.
