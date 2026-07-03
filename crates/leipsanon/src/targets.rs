//! Wipe level definitions and action planning.
//!
//! Defines what data gets destroyed at each [`WipeLevel`] and produces an
//! ordered [`WipeAction`] list for the engine to execute.

use std::path::PathBuf;

// ----- Types ----------------------------------------------------------------

/// Scope of data to destroy in a panic wipe.
///
/// Variants are ordered from least to most destructive. Keys are always wiped
/// first regardless of level, because destroying key material renders
/// encrypted data unrecoverable without any further I/O.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) enum WipeLevel {
    /// Cryptographic key material only. Fastest; disables decryption.
    Keys,
    /// Contact database.
    Contacts,
    /// Message store.
    Messages,
    /// All user-generated data: keys, contacts, messages, and app data.
    UserData,
    /// Everything: user data plus OS configuration and logs, then block device.
    Everything,
}

/// How to overwrite a path or region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) enum WipeMethod {
    /// Overwrite with zeros.
    Zero,
    /// Overwrite with cryptographically random bytes.
    Random,
    /// Punch holes / TRIM (flash storage; relies on the storage controller).
    Deallocate,
}

/// A single item in a wipe execution plan.
#[derive(Debug, Clone)]
pub(crate) struct WipeAction {
    /// Filesystem path or block device to wipe.
    pub(crate) path: PathBuf,
    /// Erasure method to apply.
    pub(crate) method: WipeMethod,
    /// Execution priority: 1 = immediate (always keys), higher = later.
    pub(crate) priority: u8,
}

// ----- Functions ------------------------------------------------------------

/// Build an ordered wipe plan for `level`.
///
/// Keys are always included at priority 1 (wiped first) regardless of level.
/// The returned list is ordered by ascending priority.
#[must_use]
pub(crate) fn plan(level: WipeLevel) -> Vec<WipeAction> {
    match level {
        WipeLevel::Keys => key_actions(),

        WipeLevel::Contacts => {
            let mut actions = key_actions();
            actions.extend(contacts_actions());
            actions
        }

        WipeLevel::Messages => {
            let mut actions = key_actions();
            actions.extend(messages_actions());
            actions
        }

        WipeLevel::UserData => {
            let mut actions = key_actions();
            actions.extend(contacts_actions());
            actions.extend(messages_actions());
            actions.push(WipeAction {
                path: PathBuf::from("/data/app"),
                method: WipeMethod::Zero,
                priority: 3,
            });
            actions
        }

        WipeLevel::Everything => {
            let mut actions = plan(WipeLevel::UserData);
            actions.extend([
                WipeAction {
                    path: PathBuf::from("/etc"),
                    method: WipeMethod::Zero,
                    priority: 5,
                },
                WipeAction {
                    path: PathBuf::from("/var/log"),
                    method: WipeMethod::Random,
                    priority: 5,
                },
                WipeAction {
                    path: PathBuf::from("/dev/mmcblk0"),
                    method: WipeMethod::Random,
                    priority: 10,
                },
            ]);
            actions
        }
    }
}

/// Key material paths, always wiped first (priority 1).
fn key_actions() -> Vec<WipeAction> {
    vec![
        WipeAction {
            path: PathBuf::from("/data/keys"),
            method: WipeMethod::Zero,
            priority: 1,
        },
        WipeAction {
            path: PathBuf::from("/data/keys.bak"),
            method: WipeMethod::Zero,
            priority: 1,
        },
    ]
}

fn contacts_actions() -> Vec<WipeAction> {
    vec![WipeAction {
        path: PathBuf::from("/data/contacts"),
        method: WipeMethod::Zero,
        priority: 2,
    }]
}

fn messages_actions() -> Vec<WipeAction> {
    vec![WipeAction {
        path: PathBuf::from("/data/messages"),
        method: WipeMethod::Zero,
        priority: 2,
    }]
}

// ----- Tests ----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    #[test]
    fn keys_plan_is_non_empty() {
        let p = plan(WipeLevel::Keys);
        assert!(!p.is_empty(), "Keys plan must contain at least one action");
    }

    #[test]
    fn keys_plan_all_priority_one() {
        let p = plan(WipeLevel::Keys);
        assert!(
            p.iter().all(|a| a.priority == 1),
            "all key actions must have priority 1"
        );
    }

    #[test]
    fn contacts_plan_targets_contacts_path() {
        let p = plan(WipeLevel::Contacts);
        let found = p.iter().any(|a| a.path == Path::new("/data/contacts"));
        assert!(found, "Contacts plan must include /data/contacts");
    }

    #[test]
    fn messages_plan_targets_messages_path() {
        let p = plan(WipeLevel::Messages);
        let found = p.iter().any(|a| a.path == Path::new("/data/messages"));
        assert!(found, "Messages plan must include /data/messages");
    }

    #[test]
    fn contacts_plan_wipes_keys_first() {
        let p = plan(WipeLevel::Contacts);
        assert_eq!(
            p.first().map(|a| a.priority),
            Some(1),
            "Contacts plan must wipe keys (priority 1) first"
        );
        assert!(
            p.first().is_some_and(|a| a.path.starts_with("/data/keys")),
            "Contacts plan's first action must target /data/keys"
        );
    }

    #[test]
    fn messages_plan_wipes_keys_first() {
        let p = plan(WipeLevel::Messages);
        assert_eq!(
            p.first().map(|a| a.priority),
            Some(1),
            "Messages plan must wipe keys (priority 1) first"
        );
        assert!(
            p.first().is_some_and(|a| a.path.starts_with("/data/keys")),
            "Messages plan's first action must target /data/keys"
        );
    }

    #[test]
    fn user_data_includes_keys_contacts_messages() {
        let p = plan(WipeLevel::UserData);
        let has_keys = p.iter().any(|a| a.path.starts_with("/data/keys"));
        let has_contacts = p.iter().any(|a| a.path == Path::new("/data/contacts"));
        let has_messages = p.iter().any(|a| a.path == Path::new("/data/messages"));
        assert!(has_keys, "UserData plan must include key paths");
        assert!(has_contacts, "UserData plan must include /data/contacts");
        assert!(has_messages, "UserData plan must include /data/messages");
    }

    #[test]
    fn keys_first_in_user_data_plan() {
        let p = plan(WipeLevel::UserData);
        let first_priority = p.first().map(|a| a.priority);
        assert_eq!(
            first_priority,
            Some(1),
            "first action in UserData plan must have priority 1 (keys)"
        );
    }

    #[test]
    fn everything_is_superset_of_user_data() {
        let user = plan(WipeLevel::UserData);
        let everything = plan(WipeLevel::Everything);
        assert!(
            everything.len() > user.len(),
            "Everything plan must cover more targets than UserData"
        );
    }

    #[test]
    fn everything_plan_includes_block_device() {
        let p = plan(WipeLevel::Everything);
        let has_block = p.iter().any(|a| a.path.starts_with("/dev"));
        assert!(
            has_block,
            "Everything plan must target at least one block device"
        );
    }

    #[test]
    fn everything_keys_have_priority_one() {
        let p = plan(WipeLevel::Everything);
        let key_actions: Vec<_> = p
            .iter()
            .filter(|a| a.path.starts_with("/data/keys"))
            .collect();
        assert!(
            !key_actions.is_empty(),
            "Everything plan must include key actions"
        );
        assert!(
            key_actions.iter().all(|a| a.priority == 1),
            "key actions in Everything plan must retain priority 1"
        );
    }

    #[test]
    fn plan_priorities_are_ascending_for_every_level() {
        // WHY: `plan`'s doc comment (see above) contracts the returned list
        // is ordered by ascending priority; WipeEngine::execute relies on
        // this to wipe keys before anything else. The contract was
        // previously unverified — a future level that pushed actions out of
        // priority order would silently break it.
        let levels = [
            WipeLevel::Keys,
            WipeLevel::Contacts,
            WipeLevel::Messages,
            WipeLevel::UserData,
            WipeLevel::Everything,
        ];
        for level in levels {
            let p = plan(level);
            let priorities: Vec<u8> = p.iter().map(|a| a.priority).collect();
            assert!(
                priorities.is_sorted(),
                "plan({level:?}) must be ordered by ascending priority, got {priorities:?}"
            );
        }
    }
}
