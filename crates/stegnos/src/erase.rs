//! Secure erasure primitives and wipe-target planning for panic-mode wiping.

use std::path::PathBuf;

use zeroize::Zeroize;

/// Zero `buf` in a way that the compiler cannot optimise away.
///
/// Uses the [`zeroize`] crate, which issues volatile writes to prevent dead-store
/// elimination in release builds.
pub fn secure_zero(buf: &mut [u8]) {
    buf.zeroize();
}

/// What data should be erased during a wipe operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum WipeTarget {
    /// Cryptographic key material only (fastest; disables decryption).
    Keys,
    /// Contact database.
    Contacts,
    /// Message store.
    Messages,
    /// All user-generated data (keys, contacts, messages, app data).
    AllUserData,
    /// Everything: user data plus OS configuration and logs.
    Everything,
}

/// How a path or partition should be wiped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum WipeMethod {
    /// Overwrite with zeros.
    Zero,
    /// Overwrite with cryptographically random bytes.
    Random,
    /// Punch holes / TRIM (for flash storage; relies on the storage controller).
    Deallocate,
}

/// A single target in a wipe plan.
#[derive(Debug, Clone)]
pub struct WipePath {
    /// Filesystem path or block device to wipe.
    pub path: PathBuf,
    /// Erasure method to apply.
    pub method: WipeMethod,
    /// Execution priority: lower numbers run first.
    pub priority: u8,
}

/// Generate the ordered list of paths and partitions to wipe for `target`.
///
/// Returns paths in priority ORDER (lowest number = highest priority). The caller
/// is responsible for executing the wipe in priority ORDER and applying the
/// specified method to each path.
#[must_use]
pub fn wipe_plan(target: WipeTarget) -> Vec<WipePath> {
    match target {
        WipeTarget::Keys => key_paths(),

        WipeTarget::Contacts => vec![WipePath {
            path: PathBuf::from("/data/contacts"),
            method: WipeMethod::Zero,
            priority: 2,
        }],

        WipeTarget::Messages => vec![WipePath {
            path: PathBuf::from("/data/messages"),
            method: WipeMethod::Zero,
            priority: 2,
        }],

        WipeTarget::AllUserData => {
            let mut plan = key_paths();
            plan.extend([
                WipePath {
                    path: PathBuf::from("/data/contacts"),
                    method: WipeMethod::Zero,
                    priority: 2,
                },
                WipePath {
                    path: PathBuf::from("/data/messages"),
                    method: WipeMethod::Zero,
                    priority: 2,
                },
                WipePath {
                    path: PathBuf::from("/data/app"),
                    method: WipeMethod::Zero,
                    priority: 3,
                },
                WipePath {
                    path: PathBuf::from("/data/media"),
                    method: WipeMethod::Deallocate,
                    priority: 4,
                },
            ]);
            plan
        }

        WipeTarget::Everything => {
            let mut plan = wipe_plan(WipeTarget::AllUserData);
            plan.extend([
                WipePath {
                    path: PathBuf::from("/etc"),
                    method: WipeMethod::Zero,
                    priority: 5,
                },
                WipePath {
                    path: PathBuf::from("/var/log"),
                    method: WipeMethod::Random,
                    priority: 5,
                },
                WipePath {
                    path: PathBuf::from("/dev/mmcblk0"),
                    method: WipeMethod::Random,
                    priority: 10,
                },
            ]);
            plan
        }
    }
}

/// Key material paths, always wiped first (highest priority).
fn key_paths() -> Vec<WipePath> {
    vec![
        WipePath {
            path: PathBuf::from("/data/keys"),
            method: WipeMethod::Zero,
            priority: 1,
        },
        WipePath {
            path: PathBuf::from("/data/keys.bak"),
            method: WipeMethod::Zero,
            priority: 1,
        },
    ]
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    #[test]
    fn secure_zero_zeros_the_buffer() {
        let mut buf = [0xffu8; 64];
        secure_zero(&mut buf);
        assert!(
            buf.iter().all(|&b| b == 0),
            "every byte must be zero after secure_zero"
        );
    }

    #[test]
    fn secure_zero_works_on_empty_buffer() {
        let mut buf: [u8; 0] = [];
        secure_zero(&mut buf);
        // no panic, no-op
    }

    #[test]
    fn wipe_plan_keys_is_non_empty() {
        let plan = wipe_plan(WipeTarget::Keys);
        assert!(
            !plan.is_empty(),
            "Keys wipe plan must contain at least one target"
        );
    }

    #[test]
    fn wipe_plan_keys_has_highest_priority() {
        let plan = wipe_plan(WipeTarget::Keys);
        assert!(
            plan.iter().all(|p| p.priority == 1),
            "all key targets must have priority 1 (highest)"
        );
    }

    #[test]
    fn wipe_plan_everything_is_superset_of_all_user_data() {
        let all_user = wipe_plan(WipeTarget::AllUserData);
        let everything = wipe_plan(WipeTarget::Everything);
        assert!(
            everything.len() > all_user.len(),
            "Everything wipe must cover more targets than AllUserData"
        );
    }

    #[test]
    fn wipe_plan_everything_includes_block_device() {
        let plan = wipe_plan(WipeTarget::Everything);
        let has_block_dev = plan.iter().any(|p| p.path.starts_with("/dev"));
        assert!(
            has_block_dev,
            "Everything wipe must target at least one block device"
        );
    }

    #[test]
    fn wipe_plan_all_user_data_includes_keys_contacts_messages() {
        let plan = wipe_plan(WipeTarget::AllUserData);
        let has_keys = plan.iter().any(|p| p.path.starts_with("/data/keys"));
        let has_contacts = plan.iter().any(|p| p.path == Path::new("/data/contacts"));
        let has_messages = plan.iter().any(|p| p.path == Path::new("/data/messages"));
        assert!(has_keys, "AllUserData plan must include key paths");
        assert!(has_contacts, "AllUserData plan must include contacts path");
        assert!(has_messages, "AllUserData plan must include messages path");
    }
}
