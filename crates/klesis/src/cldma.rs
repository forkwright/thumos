//! CLDMA (Communication Link DMA) descriptor format and ring-buffer queues.
//!
//! CLDMA is the high-throughput DMA transport between the AP and the MT6739
//! modem. The hardware processes chains of General Purpose Descriptors (GPDs)
//! held in ring buffers. This module provides the descriptor layout and
//! software-managed TX/RX ring abstractions used by the userspace transport
//! layer.
//!
//! The `Gpd` layout matches `struct cldma_tgpd` (TX) in
//! `eccci/hif/ccci_hif_cldma.h`. Field order and widths are identical; the
//! struct uses `#[repr(C)]` so that `offset_of!` can verify alignment against
//! the hardware specification.
//!
//! Source: `eccci/hif/ccci_hif_cldma.h`, `docs/DRIVER-INTERFACES.md §1.1`

use snafu::ensure;

use crate::error::{NotReadySnafu, Result};

// ─── Constants ────────────────────────────────────────────────────────────────

/// GPD flag bit: hardware-owned. When set the DMA engine may read/write the
/// descriptor. Software must clear this bit before reclaiming the entry.
pub(crate) const GPD_FLAG_HWO: u8 = 0x01;

/// GPD flag bit: interrupt-on-completion. Causes a TX-done / RX-done
/// interrupt when the DMA engine finishes processing this descriptor.
pub(crate) const GPD_FLAG_IOC: u8 = 0x80;

/// Number of TX queues on MD generation ≥ 6293.
///
/// Source: `eccci/hif/ccci_hif_cldma.h:33`
pub(crate) const CLDMA_TXQ_NUM: usize = 4;

/// Number of RX queues on MD generation ≥ 6293.
///
/// Source: `eccci/hif/ccci_hif_cldma.h:34`
pub(crate) const CLDMA_RXQ_NUM: usize = 1;

// ─── Types ────────────────────────────────────────────────────────────────────

/// CLDMA General Purpose Descriptor — TX variant.
///
/// Matches `struct cldma_tgpd __packed` from
/// `eccci/hif/ccci_hif_cldma.h:251–264`. The struct is 16 bytes; `#[repr(C)]`
/// is used so field offsets are stable and verifiable in tests.
///
/// Field notes:
/// - `flags`: bit 0 = `HWO` (hardware owned), bit 7 = `IOC`.
/// - `checksum`: originally checksum bits; repurposed for debug (1 = TX-in,
///   2 = TX-done).
/// - `msb`: high nibble = `next_ptr[35:32]`, low nibble = `data_ptr[35:32]`
///   (only relevant for 36-bit physical addresses, unused in 32-bit mode).
/// - `netif`: network interface ID (lower 5 bits).
/// - `next_ptr`: physical address of the next GPD in the ring.
/// - `data_ptr`: physical address of the data buffer (or BD chain head).
/// - `data_len`: byte length of the data buffer.
/// - `seq_num`: packet sequence number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(C)]
pub(crate) struct Gpd {
    /// Descriptor control flags (`GPD_FLAG_HWO`, `GPD_FLAG_IOC`, …).
    pub(crate) flags: u8,
    /// Checksum / debug byte.
    pub(crate) checksum: u8,
    /// MSB extension for 36-bit physical addresses (unused in 32-bit mode).
    pub(crate) msb: u8,
    /// Network interface identifier (lower 5 bits meaningful).
    pub(crate) netif: u8,
    /// Physical address of the next [`Gpd`] in the ring (0 = end of chain).
    pub(crate) next_ptr: u32,
    /// Physical address of the data buffer or BD-chain head.
    pub(crate) data_ptr: u32,
    /// Byte length of the data referenced by `data_ptr`.
    pub(crate) data_len: u16,
    /// Packet sequence number.
    pub(crate) seq_num: u16,
}

impl Gpd {
    /// Returns `true` when the hardware-owned bit is set.
    #[must_use]
    pub(crate) const fn is_hw_owned(&self) -> bool {
        self.flags & GPD_FLAG_HWO != 0
    }

    /// Set or clear the hardware-owned bit.
    pub(crate) const fn set_hw_owned(&mut self, owned: bool) {
        if owned {
            self.flags |= GPD_FLAG_HWO;
        } else {
            self.flags &= !GPD_FLAG_HWO;
        }
    }
}

/// Software-managed TX ring buffer of [`Gpd`] entries.
///
/// The ring holds `capacity` slots. Slots are filled by [`TxQueue::enqueue`]
/// and reclaimed by [`TxQueue::dequeue`] after the DMA engine clears
/// `GPD_FLAG_HWO`.
pub(crate) struct TxQueue {
    ring: Vec<Gpd>,
    capacity: usize,
    /// Index of the next slot to write (producer).
    head: usize,
    /// Index of the oldest pending slot (consumer).
    tail: usize,
    len: usize,
}

impl TxQueue {
    /// Create a new TX ring with `capacity` slots.
    #[must_use]
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            ring: vec![Gpd::default(); capacity],
            capacity,
            head: 0,
            tail: 0,
            len: 0,
        }
    }

    /// Number of descriptors currently in the queue.
    #[must_use]
    pub(crate) const fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` when the ring holds no pending descriptors.
    #[must_use]
    pub(crate) const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns `true` when every slot is occupied.
    #[must_use]
    pub(crate) const fn is_full(&self) -> bool {
        self.len == self.capacity
    }

    /// Add a descriptor to the tail of the ring.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::Error::NotReady`] when the ring is full.
    pub(crate) fn enqueue(&mut self, gpd: Gpd) -> Result<()> {
        ensure!(!self.is_full(), NotReadySnafu);
        self.ring[self.head] = gpd;
        self.head = (self.head + 1) % self.capacity;
        self.len += 1;
        Ok(())
    }

    /// Remove and return the oldest descriptor from the ring.
    ///
    /// Returns `None` when the ring is empty.
    pub(crate) fn dequeue(&mut self) -> Option<Gpd> {
        if self.is_empty() {
            return None;
        }
        let gpd = self.ring[self.tail];
        self.tail = (self.tail + 1) % self.capacity;
        self.len -= 1;
        Some(gpd)
    }
}

/// Software-managed RX ring buffer of [`Gpd`] entries.
///
/// The modem DMA engine fills each slot and clears `GPD_FLAG_HWO` when done.
/// The driver refills slots via [`RxQueue::enqueue`] and consumes received
/// descriptors via [`RxQueue::dequeue`].
pub(crate) struct RxQueue {
    ring: Vec<Gpd>,
    capacity: usize,
    head: usize,
    tail: usize,
    len: usize,
}

impl RxQueue {
    /// Create a new RX ring with `capacity` slots.
    #[must_use]
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            ring: vec![Gpd::default(); capacity],
            capacity,
            head: 0,
            tail: 0,
            len: 0,
        }
    }

    /// Number of descriptors currently in the queue.
    #[must_use]
    pub(crate) const fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` when the ring holds no descriptors.
    #[must_use]
    pub(crate) const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns `true` when every slot is occupied.
    #[must_use]
    pub(crate) const fn is_full(&self) -> bool {
        self.len == self.capacity
    }

    /// Add a (refilled) descriptor to the ring for the DMA engine to consume.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::Error::NotReady`] when the ring is full.
    pub(crate) fn enqueue(&mut self, gpd: Gpd) -> Result<()> {
        ensure!(!self.is_full(), NotReadySnafu);
        self.ring[self.head] = gpd;
        self.head = (self.head + 1) % self.capacity;
        self.len += 1;
        Ok(())
    }

    /// Remove and return the next completed descriptor.
    ///
    /// Returns `None` when the ring is empty.
    pub(crate) fn dequeue(&mut self) -> Option<Gpd> {
        if self.is_empty() {
            return None;
        }
        let gpd = self.ring[self.tail];
        self.tail = (self.tail + 1) % self.capacity;
        self.len -= 1;
        Some(gpd)
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::mem::offset_of;

    use super::*;

    #[test]
    fn gpd_size_matches_hardware_spec() {
        assert_eq!(
            std::mem::size_of::<Gpd>(),
            16,
            "cldma_tgpd is 16 bytes per hardware spec"
        );
    }

    #[test]
    fn gpd_field_offsets_match_cldma_tgpd() {
        // Offsets derived from `struct cldma_tgpd __packed`
        // in `eccci/hif/ccci_hif_cldma.h:251–264`.
        assert_eq!(offset_of!(Gpd, flags), 0, "gpd_flags at OFFSET 0");
        assert_eq!(offset_of!(Gpd, checksum), 1, "non_used at OFFSET 1");
        assert_eq!(offset_of!(Gpd, msb), 2, "msb at OFFSET 2");
        assert_eq!(offset_of!(Gpd, netif), 3, "netif at OFFSET 3");
        assert_eq!(offset_of!(Gpd, next_ptr), 4, "next_gpd_ptr at OFFSET 4");
        assert_eq!(offset_of!(Gpd, data_ptr), 8, "data_buff_bd_ptr at OFFSET 8");
        assert_eq!(offset_of!(Gpd, data_len), 12, "data_buff_len at OFFSET 12");
        assert_eq!(offset_of!(Gpd, seq_num), 14, "psn at OFFSET 14");
    }

    #[test]
    fn gpd_hw_owned_flag() {
        let mut gpd = Gpd::default();
        assert!(!gpd.is_hw_owned(), "new GPD must not be hardware-owned");
        gpd.set_hw_owned(true);
        assert!(gpd.is_hw_owned(), "GPD must be hardware-owned after SET");
        assert_eq!(
            gpd.flags & GPD_FLAG_HWO,
            GPD_FLAG_HWO,
            "HWO bit must be SET in flags byte"
        );
        gpd.set_hw_owned(false);
        assert!(
            !gpd.is_hw_owned(),
            "GPD must not be hardware-owned after clear"
        );
    }

    #[test]
    fn tx_queue_enqueue_dequeue() {
        let mut q = TxQueue::new(4);
        assert!(q.is_empty(), "new queue must be empty");

        let gpd = Gpd {
            flags: GPD_FLAG_HWO,
            data_len: 20,
            ..Gpd::default()
        };
        q.enqueue(gpd).unwrap_or_default();
        assert_eq!(q.len(), 1, "queue length must be 1 after one enqueue");

        let out = q.dequeue().unwrap_or_default();
        assert_eq!(out, gpd, "dequeued descriptor must equal enqueued one");
        assert!(q.is_empty(), "queue must be empty after dequeue");
    }

    #[test]
    fn tx_queue_full_rejects_enqueue() {
        let mut q = TxQueue::new(2);
        let gpd = Gpd::default();
        q.enqueue(gpd).unwrap_or_default();
        q.enqueue(gpd).unwrap_or_default();
        let result = q.enqueue(gpd);
        assert!(result.is_err(), "enqueue INTO full queue must fail");
    }

    #[test]
    fn rx_queue_fifo_order() {
        let mut q = RxQueue::new(4);
        for i in 0u16..3 {
            let gpd = Gpd {
                seq_num: i,
                ..Gpd::default()
            };
            q.enqueue(gpd).unwrap_or_default();
        }
        for expected_seq in 0u16..3 {
            let gpd = q.dequeue().unwrap_or_default();
            assert_eq!(
                gpd.seq_num, expected_seq,
                "RX queue must preserve FIFO ORDER (expected seq {expected_seq})"
            );
        }
        assert!(
            q.dequeue().is_none(),
            "dequeue on empty queue must return None"
        );
    }
}
