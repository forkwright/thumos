//! Wipe execution engine.
//!
//! [`WipeEngine`] iterates a wipe plan produced by [`crate::targets::plan`]
//! and executes each [`WipeAction`]. In dry-run mode no I/O is performed,
//! making the engine fully testable without hardware.

use std::io::{self, Seek as _, SeekFrom, Write as _};
use std::path::Path;
use std::time::{Duration, Instant};

use snafu::Snafu;

use crate::memory::{MemoryError, secure_random_fill};
use crate::targets::{WipeAction, WipeMethod};

// ----- Constants ------------------------------------------------------------

const CHUNK_SIZE: usize = 4096;

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
}

// ----- Types ----------------------------------------------------------------

/// Summary of a completed wipe plan execution.
#[derive(Debug, Clone)]
pub struct WipeResult {
    /// Number of actions that completed successfully (or were dry-run).
    pub actions_completed: usize,
    /// Number of actions that encountered an I/O error.
    pub actions_failed: usize,
    /// Total bytes actually written (zero in dry-run mode).
    pub bytes_wiped: u64,
    /// Wall-clock time FROM first to last action.
    pub elapsed: Duration,
}

/// Executes wipe plans produced by [`crate::targets::plan`].
pub struct WipeEngine {
    dry_run: bool,
}

// ----- Impls: inherent ------------------------------------------------------

impl WipeEngine {
    /// Create an engine. Set `dry_run = true` for testing: actions are logged
    /// but no I/O is performed.
    #[must_use]
    pub const fn new(dry_run: bool) -> Self {
        Self { dry_run }
    }

    /// Whether this engine runs in dry-run mode.
    #[must_use]
    pub const fn is_dry_run(&self) -> bool {
        self.dry_run
    }

    /// Execute `plan`, returning a [`WipeResult`] with completion statistics.
    ///
    /// Actions are executed in the ORDER supplied. Callers should pass a plan
    /// sorted by ascending priority (as returned by [`crate::targets::plan`]).
    ///
    /// In dry-run mode all actions are counted as completed with zero bytes
    /// wiped. In real mode, actions on paths that do not exist are silently
    /// skipped (not counted as failures).
    pub fn execute(&mut self, plan: &[WipeAction]) -> WipeResult {
        let start = Instant::now();
        let mut completed: usize = 0;
        let mut failed: usize = 0;
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
                match wipe_path(&action.path, action.method) {
                    Ok(bytes) => {
                        log::info!("wiped {} bytes FROM {}", bytes, action.path.display());
                        completed = completed.saturating_add(1);
                        bytes_wiped = bytes_wiped.saturating_add(bytes);
                    }
                    Err(ref e) => {
                        log::error!("wipe failed for {}: {}", action.path.display(), e);
                        failed = failed.saturating_add(1);
                    }
                }
            }
        }

        WipeResult {
            actions_completed: completed,
            actions_failed: failed,
            bytes_wiped,
            elapsed: start.elapsed(),
        }
    }
}

// ----- Free functions -------------------------------------------------------

/// Wipe `path` using `method`. Returns bytes written. Missing paths return 0.
fn wipe_path(path: &Path, method: WipeMethod) -> Result<u64, WipeError> {
    let path_str = path.display().to_string();

    let file = match std::fs::OpenOptions::new().write(true).open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            log::warn!("wipe target not found (skipping): {path_str}");
            return Ok(0);
        }
        Err(e) => {
            return Err(WipeError::Open {
                path: path_str,
                source: e,
            });
        }
    };

    let len = file
        .metadata()
        .map_err(|e| WipeError::Open {
            path: path_str.clone(),
            source: e,
        })?
        .len();

    wipe_file(file, len, method, &path_str)
}

/// Overwrite `file` (of known `len`) using `method`, then sync.
fn wipe_file(
    mut file: std::fs::File,
    len: u64,
    method: WipeMethod,
    path: &str,
) -> Result<u64, WipeError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|e| WipeError::Write {
            path: path.to_owned(),
            source: e,
        })?;

    let mut written: u64 = 0;
    let mut chunk = [0u8; CHUNK_SIZE];

    while written < len {
        let remaining = len.saturating_sub(written);
        let chunk_len = (usize::try_from(remaining).unwrap_or_default()).min(CHUNK_SIZE);
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

        written = written.saturating_add(u64::try_from(chunk_len).unwrap_or_default());
    }

    file.sync_all().map_err(|e| WipeError::Sync {
        path: path.to_owned(),
        source: e,
    })?;

    Ok(written)
}

// ----- Tests ----------------------------------------------------------------

#[cfg(test)]
mod tests {
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
        // elapsed is non-negative (Duration can't be negative)
        let _ = result.elapsed; // just verify the field is accessible
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
}
