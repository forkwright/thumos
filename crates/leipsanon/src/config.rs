//! Behavioral tuning parameters for the panic-mode wipe engine.
//!
//! The only tunable knob today is the overwrite chunk size. Protocol
//! invariants (priority ordering of wipe targets, the enumerated
//! [`crate::targets::WipeMethod`] variants) remain in [`crate::targets`].

/// Default overwrite-chunk size in bytes.
///
/// Source: 4 KiB matches the MT6739 eMMC internal block boundary and the
/// Linux page cache; larger chunks waste stack/heap without throughput gain,
/// smaller chunks issue more syscalls per wiped byte.
pub(crate) const DEFAULT_CHUNK_SIZE: usize = 4096;

/// Minimum accepted chunk size.
///
/// Source: below 512 bytes we descend into sub-sector writes that the eMMC
/// firmware must internally merge; this produces write amplification rather
/// than finer-grain wipe resolution.
pub(crate) const MIN_CHUNK_SIZE: usize = 512;

/// Maximum accepted chunk size.
///
/// Source: 1 MiB bounds worst-case heap pressure in the wipe path. Larger
/// buffers do not improve throughput on eMMC and risk OOM on the 1 GB device.
pub(crate) const MAX_CHUNK_SIZE: usize = 1024 * 1024;

/// Runtime-tunable knobs for the [`crate::engine::WipeEngine`].
///
/// [`Default`] reproduces the historical `const` behaviour, so adopting
/// `Config` is a no-op for callers that do not override anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Config {
    /// Overwrite-chunk size in bytes.
    ///
    /// **Affects:** memory footprint during wipe, write amplification.
    /// **Evidence:** measured wipe throughput at different chunk sizes on
    /// the target eMMC device.
    /// **Bounds:** `[MIN_CHUNK_SIZE, MAX_CHUNK_SIZE]`.
    pub(crate) chunk_size: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chunk_size: DEFAULT_CHUNK_SIZE,
        }
    }
}

impl Config {
    /// Chunk size clamped to the accepted domain range.
    ///
    /// Falls back to [`DEFAULT_CHUNK_SIZE`] for out-of-range values.
    #[must_use]
    pub(crate) fn chunk_size(&self) -> usize {
        let v = self.chunk_size;
        if (MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&v) {
            v
        } else {
            log::warn!(
                "chunk_size={v} out of range [{MIN_CHUNK_SIZE}, {MAX_CHUNK_SIZE}]; \
                 using default {DEFAULT_CHUNK_SIZE}",
            );
            DEFAULT_CHUNK_SIZE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_matches_historical_const() {
        assert_eq!(Config::default().chunk_size, 4096);
    }

    #[test]
    fn accessor_clamps_below_minimum() {
        let c = Config { chunk_size: 64 };
        assert_eq!(c.chunk_size(), DEFAULT_CHUNK_SIZE);
    }

    #[test]
    fn accessor_clamps_above_maximum() {
        let c = Config {
            chunk_size: 1 << 30,
        };
        assert_eq!(c.chunk_size(), DEFAULT_CHUNK_SIZE);
    }

    #[test]
    fn accessor_passes_valid_values() {
        let c = Config { chunk_size: 8192 };
        assert_eq!(c.chunk_size(), 8192);
    }
}
