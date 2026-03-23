# Storage

> Standards for database access, migrations, connection management, and data integrity. Applies to any persistent storage layer.

---

## Migrations

### Versioned and checksummed

Every schema change is a numbered migration file. Applied migrations are recorded with:
- Version number (monotonic)
- SHA-384 checksum of the SQL/DDL text
- Applied timestamp
- Success flag

On startup, verify all applied migration checksums match source files. A mismatch means someone edited an applied migration. Fail loudly.

### Forward-only by default

Migrations add, never remove or modify existing columns in the same migration. Pattern for safe schema evolution:
1. Add column as nullable (old code compatible)
2. Deploy new code that writes to new column
3. Backfill existing rows
4. In separate migration, add NOT NULL constraint

### Reversible when needed

Reversible migrations have explicit UP and DOWN scripts. DOWN must be tested. Don't assume a DOWN migration that's never been run will work.

### Locking

Only one migration runs at a time. Use advisory locks (Postgres) or PRAGMA (SQLite) to prevent concurrent schema changes.

---

## Connection management

### Pooling

Every database connection goes through a pool. Never open connections directly in application code.

Pool configuration:
- **max_connections**: hard limit respecting database server limits
- **min_connections**: pre-opened for fast startup
- **acquire_timeout**: fail fast if no connection available
- **idle_timeout**: close idle connections to free resources
- **max_lifetime**: rotate connections to prevent stale TCP state

### Lifecycle callbacks

Pools support three hooks:
- **after_connect**: run once per new connection (PRAGMA setup, session variables)
- **before_acquire**: health-check before giving to caller (reject stale connections)
- **after_release**: reset state after caller returns connection

### Statement caching

Frequently-used queries get prepared statement caching. LRU eviction with bounded size (default 100 per connection). Key is the full query text.

---

## Query safety

### Parameterized only

All user-influenced values go through parameterized queries. Never string-concatenate values into SQL, Datalog, or any query language. This includes values from LLM/agent tool calls.

### Compile-time validation (when available)

Prefer compile-time query checking over runtime validation. If the query language supports it (SQL via sqlx, GraphQL via cynic), validate at build time. Cache query metadata for offline CI.

### Size limits

Every query has a timeout. Every result set has a row limit. Unbounded queries against large tables will eventually OOM.

---

## Transactions

### Explicit scope

Transactions have explicit begin/commit/rollback. No implicit transaction management hidden in ORM layers.

### Auto-rollback on drop

If a transaction goes out of scope without explicit commit, it rolls back. This prevents partial writes from leaked transactions.

### Savepoints for nesting

Nested transactions use savepoints. Track transaction depth to distinguish between outer transaction and inner savepoints.

---

## Data integrity

### Backup before migrate

Automated backup runs before every migration. If migration fails, restore is documented and tested.

### Checksum verification

Data integrity checks run periodically (not just on open). For SQLite: `PRAGMA integrity_check`. For custom stores: consistency verification between indices and source data.

### Index consistency

If an index can diverge from its source (e.g., search index vs database), the system must detect and repair divergence. A fact in the database but missing from the search index is a silent recall failure.

---

## Error handling

### is_transient()

Database errors classify as transient (retry-safe) or permanent (don't retry). Connection drops, lock timeouts, and temporary unavailability are transient. Constraint violations, type mismatches, and syntax errors are permanent.

### Context at boundary

When a database error crosses a module boundary, wrap it with context: what operation was attempted, on what data, for what purpose. Raw "SQLITE_BUSY" helps nobody.

---

## Vector index patterns (from qdrant)

### HNSW construction

Single-threaded bootstrap for the first N points (prevents disconnected graph components), then parallel insertion. Track node readiness via atomic bitfield. Skip unindexed nodes during traversal.

### Visited-list pool

Pre-allocate per-thread visited lists for HNSW search. Counter-based marking (increment counter per search, compare to mark) avoids O(n) reset between searches. Pool bounded by thread count.

### Memory-mapped vectors

For datasets exceeding RAM, use mmap with access pattern hints:
- Random access mmap for individual vector lookups
- Sequential mmap for batch scanning
- Separate mmap'd deletion bitfield

Rely on OS page cache, not application-level LRU. Call `madvise(DONTNEED)` after batch operations.

### Adaptive search strategy

Select search algorithm at query time based on:
- Filter selectivity (cardinality estimation)
- Result set size vs full_scan_threshold
- Whether exact search is requested

Small result sets: plain scan. Large unfiltered: HNSW. Large filtered: HNSW with in-graph filtering.

### Atomic persistence

Write graph state to temp file, fsync, rename. Never overwrite the active file in place. Track operation versions for point-level error recovery.
