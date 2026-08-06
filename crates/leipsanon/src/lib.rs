#![deny(missing_docs)]
#![expect(
    dead_code,
    reason = "API surface pending convergence — tracked in docs/convergence.toml (#545)"
)]
#![allow(unfulfilled_lint_expectations)]
//! Emergency data destruction. Selective wipe of sensitive partitions
//! (contacts, messages, keys), memory scrubbing, secure delete.
//!
//! # Overview
//!
//! 1. Choose a [`targets::WipeLevel`] (e.g. `Keys`, `UserData`, `Everything`).
//! 2. Generate a plan with [`targets::plan`] — an ordered list of
//!    [`targets::WipeAction`]s, keys first.
//! 3. Execute with [`engine::WipeEngine`]. Use `dry_run = true` for testing.
//! 4. Configure panic triggers via [`trigger::TriggerConfig`] and evaluate
//!    incoming events with [`trigger::TriggerConfig::check_trigger`].

pub mod config;
pub mod engine;
pub mod memory;
pub mod targets;
pub mod trigger;
