//! Wipe execution engine.
//!
//! [`WipeEngine`] iterates a wipe plan produced by [`crate::targets::plan`]
//! and executes each [`WipeAction`]. In dry-run mode no I/O is performed,
//! making the engine fully testable without hardware.

use std::io::{self, Seek as _, SeekFrom, Write as _};
use std::path::Path;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use snafu::Snafu;

use crate::config::{Config, DEFAULT_CHUNK_SIZE};
use crate::memory::{MemoryError, secure_random_fill};
use crate::targets::{WipeAction, WipeMethod};

// ----- Constants ------------------------------------------------------------

/// Default overwrite-chunk size in bytes.
///
/// Preserved as a `pub(crate) const` alias of
/// [`crate::config::DEFAULT_CHUNK_SIZE`] for backward compatibility. The
/// runtime-tunable entry point is [`Config::chunk_size`].
pub(crate) const CHUNK_SIZE: usize = DEFAULT_CHUNK_SIZE;

/// Upper bound on how long [`wipe_file`] waits FOR a single target's
/// overwrite-and-sync to finish before giving up on it.
///
/// WHY(#280): `write_all`/`sync_all` on a `std::fs::File` have no OS-level
/// cancellation available to this crate (no `io_uring` / async-I/O
/// dependency) — a wedged block device can block either call
/// indefinitely. The work runs on a detached worker thread; this is the
/// deadline the ENGINE waits FOR before moving on, bounding how long one
/// stuck target can stall the rest of the wipe plan. It does NOT stop the
/// worker thread itself, which keeps running in the background — genuine
/// syscall cancellation would need an async-I/O runtime this crate does
/// not depend on (see `wipe_file`'s doc comment).
const WIPE_TARGET_TIMEOUT: Duration = Duration::from_secs(60);

// ----- Errors ---------------------------------------------------------------

#[derive(Debug, Snafu)]
pub(crate) enum WipeError {
    #[snafu(display("failed to open {path} for wiping: {source}"))]
    Open { path: String, source: io::Error },

    #[snafu(display("failed to write to {path}: {source}"))]
    Write { path: String, source: io::Error },

    #[snafu(display("failed to sync {path}: {source}"))]
    Sync { path: String, source: io::Error },

    #[snafu(display("failed to generate random fill for {path}: {source}"))]
    Random { path: String, source: MemoryError },

    #[snafu(display(
        "wipe of {path} exceeded the {timeout:?} bound; abandoning the wait (worker continues in the background)"
    ))]
    Timeout { path: String, timeout: Duration },
}

// ----- Types ----------------------------------------------------------------

/// Summary of a completed wipe plan execution.
#[derive(Debug, Clone)]
pub(crate) struct WipeResult {
    /// Number of actions that completed successfully (or were dry-run).
    pub(crate) actions_completed: usize,
    /// Number of actions that encountered an I/O error.
    pub(crate) actions_failed: usize,
    /// Number of actions whose target path did not exist on the filesystem.
    /// Distinct FROM `actions_completed` — a missing target was never
    /// destroyed BY this run, so counting it as a completed wipe would let
    /// a caller believe a panic-wipe succeeded when the data may simply be
    /// at a different (unwiped) path (#280).
    pub(crate) actions_missing: usize,
    /// Number of PRIORITY-1 (key-wipe) actions that failed. Destroying key
    /// material is what actually renders encrypted data unrecoverable, so
    /// this must be checked independently of `actions_failed` — a caller
    /// gating on `actions_failed == 0` cannot otherwise tell a catastrophic
    /// key-wipe failure apart from a benign lower-priority one (#244).
    pub(crate) critical_failures: usize,
    /// Total bytes actually written (zero in dry-run mode).
    pub(crate) bytes_wiped: u64,
    /// Wall-clock time FROM first to last action.
    pub(crate) elapsed: Duration,
}

impl WipeResult {
    /// Whether a priority-1 (key-wipe) action failed.
    #[must_use]
    pub(crate) const fn has_critical_failure(&self) -> bool {
        self.critical_failures > 0
    }
}

/// Executes wipe plans produced by [`crate::targets::plan`].
pub(crate) struct WipeEngine {
    dry_run: bool,
    chunk_size: usize,
}

// ----- Impls: inherent ------------------------------------------------------

impl WipeEngine {
    /// Create an engine with the default [`Config`]. Set `dry_run = true` for
    /// testing: actions are logged but no I/O is performed.
    #[must_use]
    pub(crate) fn new(dry_run: bool) -> Self {
        Self::new_with_config(dry_run, &Config::default())
    }

    /// Create an engine using an explicit [`Config`].
    #[must_use]
    pub(crate) fn new_with_config(dry_run: bool, config: &Config) -> Self {
        Self {
            dry_run,
            chunk_size: config.chunk_size(),
        }
    }

    /// Whether this engine runs in dry-run mode.
    #[must_use]
    pub(crate) const fn is_dry_run(&self) -> bool {
        self.dry_run
    }

    /// Overwrite-chunk size this engine was constructed with.
    #[must_use]
    pub(crate) const fn chunk_size(&self) -> usize {
        self.chunk_size
    }

    /// Execute `plan`, returning a [`WipeResult`] with completion statistics.
    ///
    /// Actions are executed in the ORDER supplied. Callers should pass a plan
    /// sorted by ascending priority (as returned by [`crate::targets::plan`]).
    ///
    /// In dry-run mode all actions are counted as completed with zero bytes
    /// wiped. In real mode, actions on paths that do not exist are counted
    /// in `actions_missing` — NOT as completed and NOT as failed, because a
    /// missing target was never destroyed by this run (#280).
    ///
    /// Time: O(a + Σ `len_i`) where a is `plan.len()` and, in non-dry-run
    /// mode, `len_i` is the i-th target's byte length being overwritten
    /// (`wipe_file_blocking`'s loop, chunked by `self.chunk_size`) — the
    /// total cost is dominated by the SUM of every wiped target's length,
    /// not merely the action count, so a plan with one large block-device
    /// target costs far more than a alone. Dry-run mode short-circuits to
    /// O(a), since no I/O is performed.
    /// Space: O(1) auxiliary beyond the fixed summary counters — the
    /// `chunk_size`-byte overwrite buffer allocated in
    /// `wipe_file_blocking` is reused across all chunks of one target and
    /// is not proportional to a target's length or to a.
    pub(crate) fn execute(&mut self, plan: &[WipeAction]) -> WipeResult {
        let start = Instant::now();
        let mut completed: usize = 0;
        let mut failed: usize = 0;
        let mut missing: usize = 0;
        let mut critical_failed: usize = 0;
        let mut bytes_wiped: u64 = 0;

        for action in plan {
            if self.dry_run {
                log::debug!(
                    "[dry-run] would wipe {} via {:?} (priority {})",
                    action.path.display(),
                    action.method,
                    action.priority,
                );
                completed = completed.saturating_add(1);
            } else {
                match wipe_path(&action.path, action.method, self.chunk_size) {
                    Ok(Some(bytes)) => {
                        log::info!("wiped {} bytes FROM {}", bytes, action.path.display());
                        completed = completed.saturating_add(1);
                        bytes_wiped = bytes_wiped.saturating_add(bytes);
                    }
                    Ok(None) => {
                        log::warn!(
                            "wipe target missing FROM {} (not counted as wiped)",
                            action.path.display()
                        );
                        missing = missing.saturating_add(1);
                    }
                    Err(ref e) => {
                        log::error!("wipe failed for {}: {}", action.path.display(), e);
                        failed = failed.saturating_add(1);
                        if action.priority == 1 {
                            critical_failed = critical_failed.saturating_add(1);
                        }
                    }
                }
            }
        }

        WipeResult {
            actions_completed: completed,
            actions_failed: failed,
            actions_missing: missing,
            critical_failures: critical_failed,
            bytes_wiped,
            elapsed: start.elapsed(),
        }
    }
}

// ----- Free functions -------------------------------------------------------

/// Wipe `path` using `method`. Returns `Ok(Some(bytes))` when the target
/// existed and was wiped, or `Ok(None)` when `path` does not exist — a
/// missing target has nothing to destroy, so it is NOT reported as bytes
/// written (#280).
fn wipe_path(path: &Path, method: WipeMethod, chunk_size: usize) -> Result<Option<u64>, WipeError> {
    let path_str = path.display().to_string();

    let mut file = match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            log::warn!("wipe target not found (skipping): {path_str}");
            return Ok(None);
        }
        Err(e) => {
            return Err(WipeError::Open {
                path: path_str,
                source: e,
            });
        }
    };

    // WHY(#214): metadata().len() reports 0 for block-device special files
    // (POSIX stat st_size == 0), so the emergency full-device wipe of
    // /dev/mmcblk0 would write nothing yet be counted a success. Seeking to
    // the end returns the true size for both block devices and regular
    // files; wipe_file seeks back to 0 before writing.
    let len = file.seek(SeekFrom::End(0)).map_err(|e| WipeError::Open {
        path: path_str.clone(),
        source: e,
    })?;

    wipe_file(file, len, method, &path_str, chunk_size).map(Some)
}

/// Run `f` on a detached worker thread, waiting up to `timeout` FOR it to
/// finish. Returns `None` if the deadline elapses first.
///
/// WHY(#280): this is the seam that lets [`wipe_file`] bound a blocking
/// `write_all`/`sync_all` without needing an async-I/O runtime. The
/// worker is NOT force-stopped on timeout — Rust/std has no mechanism to
/// cancel an in-flight blocking syscall — it keeps running in the
/// background and its eventual result (if any) is dropped along with the
/// disconnected channel. This bounds how long the CALLER waits, not how
/// long the underlying I/O actually takes.
fn run_with_timeout<T, F>(timeout: Duration, f: F) -> Option<T>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = tx.send(f()); // WHY: send fails only if the receiver already timed out and dropped rx; the worker result is then unobservable by design, nothing to recover.
    });
    rx.recv_timeout(timeout).ok()
}

/// Overwrite `file` (of known `len`) using `method`, then sync.
///
/// Bounded by [`WIPE_TARGET_TIMEOUT`] via [`run_with_timeout`]: if the
/// worker has not finished by the deadline this returns
/// [`WipeError::Timeout`] rather than blocking the wipe engine
/// indefinitely on one stuck target (#280). See `run_with_timeout`'s doc
/// comment for why the worker itself cannot be force-cancelled.
fn wipe_file(
    mut file: std::fs::File,
    len: u64,
    method: WipeMethod,
    path: &str,
    chunk_size: usize,
) -> Result<u64, WipeError> {
    let path_owned = path.to_owned();
    run_with_timeout(WIPE_TARGET_TIMEOUT, move || {
        wipe_file_blocking(&mut file, len, method, &path_owned, chunk_size)
    })
    .unwrap_or_else(|| {
        Err(WipeError::Timeout {
            path: path.to_owned(),
            timeout: WIPE_TARGET_TIMEOUT,
        })
    })
}

/// The actual overwrite-and-sync loop, run on [`wipe_file`]'s worker
/// thread. Split out so [`run_with_timeout`] can be unit-tested against a
/// plain closure without needing real (potentially slow) file I/O.
fn wipe_file_blocking(
    file: &mut std::fs::File,
    len: u64,
    method: WipeMethod,
    path: &str,
    chunk_size: usize,
) -> Result<u64, WipeError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|e| WipeError::Write {
            path: path.to_owned(),
            source: e,
        })?;

    let mut written: u64 = 0;
    // WHY: heap allocation rather than stack array — chunk_size is now
    // runtime-configurable (see crate::config::Config).
    let mut chunk = vec![0u8; chunk_size];
    // usize -> u64 is lossless on every supported target (32/64-bit); the
    // unwrap_or fallback is unreachable and only satisfies the no-as-cast rule.
    let chunk_size_u64 = u64::try_from(chunk_size).unwrap_or(u64::MAX);

    while written < len {
        let remaining = len.saturating_sub(written);
        // WHY(#242): cap to chunk_size BEFORE narrowing to usize. On the
        // 32-bit armv7 target usize::try_from(remaining) fails when
        // remaining > u32::MAX (a >4 GiB eMMC), aborting the emergency wipe
        // before a single byte is written. Taking the min on u64 first
        // guarantees the result always fits usize.
        let chunk_len = usize::try_from(remaining.min(chunk_size_u64)).unwrap_or(chunk_size);
        let buf = &mut chunk[..chunk_len];

        match method {
            WipeMethod::Zero => {
                buf.fill(0);
            }
            WipeMethod::Random => {
                secure_random_fill(buf).map_err(|e| WipeError::Random {
                    path: path.to_owned(),
                    source: e,
                })?;
            }
            WipeMethod::Deallocate => {
                // TRIM/punch-hole requires ioctl; fall back to zero-fill for
                // platforms WHERE TRIM is not available.
                buf.fill(0);
            }
        }

        file.write_all(buf).map_err(|e| WipeError::Write {
            path: path.to_owned(),
            source: e,
        })?;

        // chunk_len <= chunk_size; usize -> u64 widening is lossless.
        written = written.saturating_add(u64::try_from(chunk_len).unwrap_or(u64::MAX));
    }

    file.sync_all().map_err(|e| WipeError::Sync {
        path: path.to_owned(),
        source: e,
    })?;

    Ok(written)
}

// ----- Tests ----------------------------------------------------------------

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test code — expect is intentional for asserting fixture setup/read/cleanup succeeded"
)]
mod tests {
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use crate::targets::{WipeLevel, plan};

    use super::*;

    #[test]
    fn dry_run_completes_all_actions() {
        let p = plan(WipeLevel::UserData);
        let action_count = p.len();
        let mut engine = WipeEngine::new(true);
        let result = engine.execute(&p);
        assert_eq!(
            result.actions_completed, action_count,
            "dry-run must complete every action in the plan"
        );
    }

    #[test]
    fn dry_run_reports_zero_failures() {
        let p = plan(WipeLevel::Everything);
        let mut engine = WipeEngine::new(true);
        let result = engine.execute(&p);
        assert_eq!(
            result.actions_failed, 0,
            "dry-run must report zero failures"
        );
    }

    #[test]
    fn dry_run_reports_zero_bytes_wiped() {
        let p = plan(WipeLevel::UserData);
        let mut engine = WipeEngine::new(true);
        let result = engine.execute(&p);
        assert_eq!(
            result.bytes_wiped, 0,
            "dry-run must report zero bytes wiped (no I/O performed)"
        );
    }

    #[test]
    fn dry_run_records_elapsed_time() {
        let p = plan(WipeLevel::Keys);
        let mut engine = WipeEngine::new(true);
        let result = engine.execute(&p);
        assert!(
            result.elapsed < Duration::from_secs(1),
            "dry-run of a small plan must complete in under one second"
        );
    }

    #[test]
    fn empty_plan_produces_zero_stats() {
        let mut engine = WipeEngine::new(true);
        let result = engine.execute(&[]);
        assert_eq!(result.actions_completed, 0, "empty plan: zero completed");
        assert_eq!(result.actions_failed, 0, "empty plan: zero failed");
        assert_eq!(result.bytes_wiped, 0, "empty plan: zero bytes");
    }

    #[test]
    fn is_dry_run_reflects_construction() {
        assert!(
            WipeEngine::new(true).is_dry_run(),
            "dry_run=true must be reflected"
        );
        assert!(
            !WipeEngine::new(false).is_dry_run(),
            "dry_run=false must be reflected"
        );
    }

    #[test]
    fn default_engine_uses_default_chunk_size() {
        let engine = WipeEngine::new(true);
        assert_eq!(
            engine.chunk_size(),
            CHUNK_SIZE,
            "default engine must use DEFAULT_CHUNK_SIZE"
        );
    }

    #[test]
    fn wipe_target_timeout_is_positive() {
        assert!(
            WIPE_TARGET_TIMEOUT > Duration::from_secs(0),
            "WIPE_TARGET_TIMEOUT must be a real bound, not disabled/zero (#280)"
        );
    }

    #[test]
    fn run_with_timeout_returns_none_when_worker_exceeds_deadline() {
        // WHY(#280): this is the seam wipe_file uses to bound a blocking
        // write_all/sync_all — the caller must not block past the deadline
        // even though the worker itself keeps running in the background.
        // The worker blocks on a channel we hold open so it deterministically
        // outlives the deadline WITHOUT a wall-clock sleep; dropping block_tx
        // after the assertion lets the worker exit cleanly (no leaked thread).
        let (block_tx, block_rx) = std::sync::mpsc::channel::<()>();
        let result = run_with_timeout(Duration::from_millis(20), move || {
            block_rx.recv().ok();
            42u32
        });
        assert_eq!(
            result, None,
            "a worker slower than the deadline must yield None, not block the caller"
        );
        drop(block_tx);
    }

    #[test]
    fn run_with_timeout_returns_result_when_worker_finishes_in_time() {
        let result = run_with_timeout(Duration::from_secs(1), || 7u32);
        assert_eq!(
            result,
            Some(7),
            "a worker finishing within the deadline must return its result"
        );
    }

    #[test]
    fn critical_failure_distinguishes_key_wipe_from_benign_failure() {
        // A priority-1 (key) action targeting a real directory (not a
        // regular file) fails to open for write (EISDIR on Linux) — a
        // deterministic, non-NotFound failure that reaches the Err arm
        // rather than the silent "missing target, skip" path.
        let plan = vec![WipeAction {
            path: PathBuf::from("/"),
            method: WipeMethod::Zero,
            priority: 1,
        }];
        let mut engine = WipeEngine::new(false);
        let result = engine.execute(&plan);
        assert_eq!(result.actions_failed, 1);
        assert_eq!(
            result.critical_failures, 1,
            "priority-1 failure must be counted as critical"
        );
        assert!(result.has_critical_failure());
    }

    #[test]
    fn benign_failure_does_not_count_as_critical() {
        let plan = vec![WipeAction {
            path: PathBuf::from("/proc"),
            method: WipeMethod::Zero,
            priority: 5,
        }];
        let mut engine = WipeEngine::new(false);
        let result = engine.execute(&plan);
        assert_eq!(result.actions_failed, 1);
        assert_eq!(
            result.critical_failures, 0,
            "a lower-priority failure must not count as critical"
        );
        assert!(!result.has_critical_failure());
    }

    #[test]
    fn custom_config_changes_chunk_size() {
        // WHY: prove Config.chunk_size flows through to the engine and alters
        // observable state. 8 KiB is accepted; 64 is clamped to the default.
        let engine = WipeEngine::new_with_config(true, &Config { chunk_size: 8192 });
        assert_eq!(
            engine.chunk_size(),
            8192,
            "engine must report the configured chunk size"
        );

        let clamped = WipeEngine::new_with_config(true, &Config { chunk_size: 64 });
        assert_eq!(
            clamped.chunk_size(),
            CHUNK_SIZE,
            "too-small chunk_size must clamp to the default"
        );
    }

    /// Deletes its backing file on drop so a fixture is cleaned up even if
    /// an assertion later in the test panics.
    struct TempFile {
        path: PathBuf,
    }

    static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

    impl TempFile {
        fn with_contents(label: &str, contents: &[u8]) -> Self {
            let n = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "leipsanon_wipe_test_{label}_{}_{n}",
                std::process::id()
            ));
            std::fs::write(&path, contents).expect("write test fixture");
            Self { path }
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    #[test]
    fn real_wipe_zero_overwrites_file_contents() {
        let original = vec![0xABu8; CHUNK_SIZE * 2 + 37];
        let fixture = TempFile::with_contents("zero", &original);

        let plan = vec![WipeAction {
            path: fixture.path.clone(),
            method: WipeMethod::Zero,
            priority: 1,
        }];
        let mut engine = WipeEngine::new(false);
        let result = engine.execute(&plan);

        let wiped = std::fs::read(&fixture.path).expect("read wiped fixture");

        assert_eq!(result.actions_completed, 1, "the wipe action must complete");
        assert_eq!(result.actions_failed, 0, "the wipe action must not fail");
        assert_eq!(
            result.bytes_wiped,
            original.len() as u64,
            "bytes_wiped must equal the file size for a full-file Zero wipe"
        );
        assert!(
            wiped.iter().all(|&b| b == 0),
            "every byte must be zero after a Zero-method wipe"
        );
        assert_ne!(
            wiped, original,
            "wiped content must differ from the original fixture content"
        );
    }

    #[test]
    fn real_wipe_random_overwrites_file_contents() {
        let original = vec![0x55u8; CHUNK_SIZE * 2 + 37];
        let fixture = TempFile::with_contents("random", &original);

        let plan = vec![WipeAction {
            path: fixture.path.clone(),
            method: WipeMethod::Random,
            priority: 1,
        }];
        let mut engine = WipeEngine::new(false);
        let result = engine.execute(&plan);

        let wiped = std::fs::read(&fixture.path).expect("read wiped fixture");

        assert_eq!(result.actions_completed, 1, "the wipe action must complete");
        assert_eq!(result.actions_failed, 0, "the wipe action must not fail");
        assert_eq!(
            result.bytes_wiped,
            original.len() as u64,
            "bytes_wiped must equal the file size for a full-file Random wipe"
        );
        assert_ne!(
            wiped, original,
            "wiped content must no longer match the original fixture content after a Random-method wipe"
        );
    }

    #[test]
    fn real_wipe_uses_full_file_length_across_chunks() {
        // #214/#242: the wipe length is taken from the target's real size
        // (seek-to-end) and the overwrite loop runs to completion across
        // multiple chunks, writing every byte. The 32-bit >4 GiB truncation
        // and block-device (stat st_size == 0) edges are not host-
        // reproducible; this covers the shared regular-file path both fixes
        // route through.
        let original = vec![0xABu8; CHUNK_SIZE * 3 + 11];
        let fixture = TempFile::with_contents("full_len", &original);

        let plan = vec![WipeAction {
            path: fixture.path.clone(),
            method: WipeMethod::Zero,
            priority: 1,
        }];
        let mut engine = WipeEngine::new(false);
        let result = engine.execute(&plan);

        let wiped = std::fs::read(&fixture.path).expect("read wiped fixture");
        assert_eq!(result.actions_completed, 1);
        assert_eq!(
            result.bytes_wiped,
            original.len() as u64,
            "every byte of the multi-chunk file must be wiped, not aborted early"
        );
        assert_eq!(wiped.len(), original.len(), "file length must be preserved");
        assert!(wiped.iter().all(|&b| b == 0), "all bytes must be zeroed");
    }

    #[test]
    fn real_wipe_zero_length_file_completes_without_error() {
        // #214: a genuinely zero-length regular file has nothing to
        // overwrite; the wipe must complete cleanly (0 bytes) rather than
        // error.
        let fixture = TempFile::with_contents("empty", &[]);
        let plan = vec![WipeAction {
            path: fixture.path.clone(),
            method: WipeMethod::Zero,
            priority: 1,
        }];
        let mut engine = WipeEngine::new(false);
        let result = engine.execute(&plan);
        assert_eq!(result.actions_failed, 0, "empty-file wipe must not fail");
        assert_eq!(result.bytes_wiped, 0, "an empty file wipes zero bytes");
    }

    #[test]
    fn missing_wipe_target_counts_as_missing_not_completed() {
        // WHY(#280): a wipe target absent FROM the filesystem must NOT be
        // reported as a completed wipe — the panic-wipe contract is that
        // `actions_completed` means data was actually destroyed. A missing
        // target is counted in `actions_missing` instead, distinct FROM
        // both success and I/O failure.
        let missing = std::env::temp_dir().join(format!(
            "leipsanon_missing_wipe_target_{}_{}",
            std::process::id(),
            TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let plan = vec![WipeAction {
            path: missing,
            method: WipeMethod::Zero,
            priority: 1,
        }];
        let mut engine = WipeEngine::new(false);
        let result = engine.execute(&plan);
        assert_eq!(
            result.actions_completed, 0,
            "a missing wipe target must NOT be counted as completed"
        );
        assert_eq!(
            result.actions_missing, 1,
            "a missing wipe target must be counted in actions_missing"
        );
        assert_eq!(
            result.actions_failed, 0,
            "a missing wipe target is not an I/O failure either"
        );
        assert_eq!(
            result.bytes_wiped, 0,
            "a missing wipe target has nothing to write, so zero bytes are wiped"
        );
    }
}
