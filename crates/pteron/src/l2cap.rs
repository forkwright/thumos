//! L2CAP fixed-channel framing and ACL fragment reassembly (#635).
//!
//! Basic L2CAP mode (Core Spec Vol 3, Part A §3.1) frames every PDU as
//! `[Length(2 LE)][CID(2 LE)][payload...]` — the L2CAP Basic header — before
//! handing it to the Controller for transmission. On the wire that PDU
//! travels inside one or more HCI ACL Data packets
//! ([`crate::hci::decode_acl_data`]); when a PDU is larger than one ACL
//! packet can carry, the sender splits it using `PB_Flag`
//! ([`crate::hci::PbFlag`]): the first fragment carries the L2CAP Basic
//! header, later Continuation fragments carry only payload bytes (Vol 4
//! Part E §5.4.2).
//!
//! [`AclReassembler`] reverses that split for received data, keyed by
//! connection handle so multiple simultaneous LE links reassemble
//! independently without cross-contaminating each other's buffers.
//! [`FixedChannel::from_cid`] demuxes a reassembled SDU to the fixed
//! channel it targets — today only CID `0x0006` (LE SMP) is routed; any
//! other CID surfaces as [`FixedChannel::Unrouted`] rather than being
//! silently misinterpreted as SMP.

use std::collections::HashMap;

use snafu::Snafu;

use crate::hci::{AclDataPacket, PbFlag};

// ── Constants ──────────────────────────────────────────────────────────────────

/// L2CAP Basic header size: 2-byte Length + 2-byte CID (Vol 3 Part A §3.1).
const L2CAP_HEADER_LEN: usize = 4;

/// CID for the LE Security Manager Protocol fixed channel (Vol 3 Part A,
/// Table 2.1) — the only channel this driver routes today. Consumed by the
/// pairing state machine, forkwright/thumos#636.
pub(crate) const CID_SMP: u16 = 0x0006;

/// Upper bound on a reassembled L2CAP SDU this driver accepts.
///
/// WHY: the Basic header's 16-bit Length field allows up to 65535 bytes,
/// but nothing this crate consumes today (SMP PDUs top out around 65 bytes)
/// needs more than a small fraction of that. Capping reassembly bounds
/// worst-case per-connection memory against a peer that declares an
/// oversized PDU and only ever trickles continuation fragments.
const MAX_L2CAP_SDU_LEN: usize = 2048;

/// Maximum connection handles with an in-flight reassembly tracked at once.
///
/// WHY: bounds memory from a peer opening many spurious connection handles;
/// pteron manages at most a handful of simultaneous LE links on this
/// hardware.
const MAX_CONCURRENT_REASSEMBLIES: usize = 4;

// ── Error type ─────────────────────────────────────────────────────────────────

/// Errors FROM L2CAP framing and ACL fragment reassembly.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub(crate) enum Error {
    /// A first/complete ACL fragment's payload was too short to hold the
    /// 4-byte L2CAP Basic header.
    #[snafu(display("L2CAP header truncated: need {min} bytes, got {actual}"))]
    HeaderTruncated {
        /// Minimum bytes required.
        min: usize,
        /// Actual bytes available.
        actual: usize,
    },

    /// The L2CAP Length field declared a PDU larger than this driver accepts.
    #[snafu(display("L2CAP PDU length {declared} exceeds accepted maximum {max}"))]
    PduTooLarge {
        /// Length the peer declared.
        declared: usize,
        /// The accepted ceiling ([`MAX_L2CAP_SDU_LEN`]).
        max: usize,
    },

    /// A Continuation fragment (`PB_Flag = 0b01`) arrived for a connection
    /// handle with no in-progress reassembly — either the start fragment
    /// was lost, or the peer never sent one.
    #[snafu(display("ACL continuation with no start fragment, handle 0x{handle:04X}"))]
    OrphanContinuation {
        /// The connection handle the orphan continuation named.
        handle: u16,
    },

    /// A fragment pushed the accumulated payload past the L2CAP Length the
    /// start fragment declared.
    #[snafu(display(
        "L2CAP reassembly overrun on handle 0x{handle:04X}: expected {expected}, got {actual}"
    ))]
    ReassemblyOverrun {
        /// The connection handle.
        handle: u16,
        /// Bytes declared by the L2CAP Length field.
        expected: usize,
        /// Bytes actually accumulated when the overrun was detected.
        actual: usize,
    },

    /// Too many connection handles already have an in-flight reassembly.
    #[snafu(display("too many concurrent ACL reassemblies (max {max})"))]
    TooManyReassemblies {
        /// The concurrent-reassembly ceiling ([`MAX_CONCURRENT_REASSEMBLIES`]).
        max: usize,
    },
}

/// Result alias for this module.
pub(crate) type Result<T> = std::result::Result<T, Error>;

// ── Types ──────────────────────────────────────────────────────────────────────

/// A fully-reassembled L2CAP SDU delivered on a fixed channel.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) struct L2capSdu {
    /// The connection handle it arrived on.
    pub(crate) handle: u16,
    /// The fixed-channel CID it targets.
    pub(crate) cid: u16,
    /// The reassembled payload — excludes the 4-byte L2CAP Basic header.
    pub(crate) payload: Vec<u8>,
}

/// A fixed channel identified by CID (Vol 3 Part A §2.1, Table 2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) enum FixedChannel {
    /// LE Security Manager Protocol, CID `0x0006` — the only channel this
    /// driver routes today (#635; consumed by the pairing state machine,
    /// forkwright/thumos#636).
    Smp,
    /// A CID this driver does not route anywhere yet.
    Unrouted(u16),
}

impl FixedChannel {
    /// Resolve a CID to the fixed channel it names.
    pub(crate) const fn from_cid(cid: u16) -> Self {
        match cid {
            CID_SMP => Self::Smp,
            other => Self::Unrouted(other),
        }
    }
}

/// State for one connection handle's in-progress L2CAP reassembly.
struct PartialSdu {
    cid: u16,
    expected_len: usize,
    buf: Vec<u8>,
}

/// Reassembles L2CAP Basic-mode SDUs FROM HCI ACL Data packet fragments,
/// tracking one in-progress reassembly per connection handle.
#[derive(Default)]
pub(crate) struct AclReassembler {
    partials: HashMap<u16, PartialSdu>,
}

impl AclReassembler {
    /// Construct an empty reassembler.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Feed one decoded ACL Data packet in.
    ///
    /// Returns `Ok(Some(sdu))` once `pkt`'s connection handle has a
    /// complete L2CAP SDU (either a single-fragment PDU, or the fragment
    /// that closes out a multi-fragment one). Returns `Ok(None)` while more
    /// Continuation fragments are still expected.
    ///
    /// # Errors
    ///
    /// See the [`Error`] variants. Any error drops the in-progress
    /// reassembly for `pkt.handle`, so a subsequent Continuation for the
    /// same handle correctly surfaces [`Error::OrphanContinuation`] rather
    /// than silently resuming a buffer that is already known-corrupt.
    pub(crate) fn feed(&mut self, pkt: &AclDataPacket<'_>) -> Result<Option<L2capSdu>> {
        if pkt.pb_flag == PbFlag::Continuation {
            self.feed_continuation(pkt)
        } else {
            self.feed_start(pkt)
        }
    }

    /// Handle a fragment that starts a new L2CAP PDU — any `PbFlag` other
    /// than `Continuation` carries the 4-byte L2CAP Basic header first.
    fn feed_start(&mut self, pkt: &AclDataPacket<'_>) -> Result<Option<L2capSdu>> {
        if pkt.data.len() < L2CAP_HEADER_LEN {
            // WHY: a stale in-progress reassembly for this handle, if any,
            // cannot be trusted to resume correctly once a malformed start
            // fragment has been seen on the same handle.
            self.partials.remove(&pkt.handle);
            return Err(Error::HeaderTruncated {
                min: L2CAP_HEADER_LEN,
                actual: pkt.data.len(),
            });
        }
        let l2cap_len = usize::from(u16::from_le_bytes([
            pkt.data.first().copied().unwrap_or_default(),
            pkt.data.get(1).copied().unwrap_or_default(),
        ]));
        let cid = u16::from_le_bytes([
            pkt.data.get(2).copied().unwrap_or_default(),
            pkt.data.get(3).copied().unwrap_or_default(),
        ]);

        if l2cap_len > MAX_L2CAP_SDU_LEN {
            self.partials.remove(&pkt.handle);
            return Err(Error::PduTooLarge {
                declared: l2cap_len,
                max: MAX_L2CAP_SDU_LEN,
            });
        }

        // WHY: a fresh start fragment always replaces any prior in-progress
        // reassembly for this handle — receiving a new start can only mean
        // the previous PDU (if any) was abandoned by the peer, and holding
        // onto it would either leak memory or let stray continuation bytes
        // splice onto the wrong PDU.
        self.partials.remove(&pkt.handle);

        let body = pkt.data.get(L2CAP_HEADER_LEN..).unwrap_or(&[]);
        if body.len() > l2cap_len {
            return Err(Error::ReassemblyOverrun {
                handle: pkt.handle,
                expected: l2cap_len,
                actual: body.len(),
            });
        }
        if body.len() == l2cap_len {
            return Ok(Some(L2capSdu {
                handle: pkt.handle,
                cid,
                payload: body.to_vec(),
            }));
        }

        if self.partials.len() >= MAX_CONCURRENT_REASSEMBLIES {
            return Err(Error::TooManyReassemblies {
                max: MAX_CONCURRENT_REASSEMBLIES,
            });
        }
        self.partials.insert(
            pkt.handle,
            PartialSdu {
                cid,
                expected_len: l2cap_len,
                buf: body.to_vec(),
            },
        );
        Ok(None)
    }

    /// Handle a Continuation fragment (`PbFlag::Continuation`) — raw
    /// payload bytes with no L2CAP header, appended to the in-progress
    /// buffer for this handle.
    fn feed_continuation(&mut self, pkt: &AclDataPacket<'_>) -> Result<Option<L2capSdu>> {
        let Some(partial) = self.partials.get_mut(&pkt.handle) else {
            return Err(Error::OrphanContinuation { handle: pkt.handle });
        };
        partial.buf.extend_from_slice(pkt.data);

        if partial.buf.len() > partial.expected_len {
            let (expected, actual) = (partial.expected_len, partial.buf.len());
            self.partials.remove(&pkt.handle);
            return Err(Error::ReassemblyOverrun {
                handle: pkt.handle,
                expected,
                actual,
            });
        }
        if partial.buf.len() == partial.expected_len {
            let Some(done) = self.partials.remove(&pkt.handle) else {
                unreachable!("handle was just resolved via get_mut above");
            };
            return Ok(Some(L2capSdu {
                handle: pkt.handle,
                cid: done.cid,
                payload: done.buf,
            }));
        }
        Ok(None)
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn start_pkt(cid: u16, l2cap_len: u16, body: &[u8]) -> Vec<u8> {
        let mut data = Vec::with_capacity(L2CAP_HEADER_LEN + body.len());
        data.extend_from_slice(&l2cap_len.to_le_bytes());
        data.extend_from_slice(&cid.to_le_bytes());
        data.extend_from_slice(body);
        data
    }

    fn acl(handle: u16, pb_flag: PbFlag, data: &[u8]) -> AclDataPacket<'_> {
        AclDataPacket {
            handle,
            pb_flag,
            bc_flag: 0b00,
            data,
        }
    }

    // ── single-fragment PDUs ──

    #[test]
    fn single_fragment_pdu_completes_immediately() -> Result<()> {
        let mut r = AclReassembler::new();
        let raw = start_pkt(CID_SMP, 3, &[0x01, 0x02, 0x03]);
        let pkt = acl(0x0001, PbFlag::FirstNonFlushable, &raw);
        let Some(sdu) = r.feed(&pkt)? else {
            unreachable!("single-fragment PDU with matching length must complete immediately");
        };
        assert_eq!(sdu.handle, 0x0001);
        assert_eq!(sdu.cid, CID_SMP);
        assert_eq!(sdu.payload, vec![0x01, 0x02, 0x03]);
        Ok(())
    }

    #[test]
    fn complete_flushable_pb_flag_also_completes_in_one_fragment() -> Result<()> {
        // PB=0b11 (CompleteFlushable, Controller-to-Host only) still carries
        // the L2CAP header on its one and only fragment.
        let mut r = AclReassembler::new();
        let raw = start_pkt(CID_SMP, 2, &[0xAA, 0xBB]);
        let pkt = acl(0x0002, PbFlag::CompleteFlushable, &raw);
        let Some(sdu) = r.feed(&pkt)? else {
            unreachable!("CompleteFlushable single fragment must complete immediately");
        };
        assert_eq!(sdu.payload, vec![0xAA, 0xBB]);
        Ok(())
    }

    #[test]
    fn empty_payload_pdu_completes_with_zero_length() -> Result<()> {
        let mut r = AclReassembler::new();
        let raw = start_pkt(CID_SMP, 0, &[]);
        let pkt = acl(0x0001, PbFlag::FirstNonFlushable, &raw);
        let Some(sdu) = r.feed(&pkt)? else {
            unreachable!("a zero-length L2CAP PDU is a valid, immediately-complete SDU");
        };
        assert!(sdu.payload.is_empty());
        Ok(())
    }

    // ── multi-fragment reassembly ──

    #[test]
    fn pdu_split_across_two_fragments_reassembles() -> Result<()> {
        let mut r = AclReassembler::new();
        // L2CAP length=5, but the start fragment only carries 2 payload bytes.
        let start_raw = start_pkt(CID_SMP, 5, &[0x01, 0x02]);
        let start = acl(0x0040, PbFlag::FirstNonFlushable, &start_raw);
        assert_eq!(
            r.feed(&start)?,
            None,
            "start fragment shorter than declared length must not complete yet"
        );

        let cont = acl(0x0040, PbFlag::Continuation, &[0x03, 0x04, 0x05]);
        let Some(sdu) = r.feed(&cont)? else {
            unreachable!("continuation completing the declared length must yield the SDU");
        };
        assert_eq!(sdu.handle, 0x0040);
        assert_eq!(sdu.cid, CID_SMP);
        assert_eq!(sdu.payload, vec![0x01, 0x02, 0x03, 0x04, 0x05]);
        Ok(())
    }

    #[test]
    fn pdu_split_across_three_fragments_reassembles_in_order() -> Result<()> {
        let mut r = AclReassembler::new();
        let start_raw = start_pkt(CID_SMP, 6, &[0xAA]);
        let start = acl(0x0007, PbFlag::FirstFlushable, &start_raw);
        assert_eq!(r.feed(&start)?, None);

        let cont1 = acl(0x0007, PbFlag::Continuation, &[0xBB, 0xCC]);
        assert_eq!(r.feed(&cont1)?, None, "still short of the declared length");

        let cont2 = acl(0x0007, PbFlag::Continuation, &[0xDD, 0xEE, 0xFF]);
        let Some(sdu) = r.feed(&cont2)? else {
            unreachable!("third fragment completes the declared 6-byte length");
        };
        assert_eq!(sdu.payload, vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        Ok(())
    }

    // ── the three required edge cases ──

    #[test]
    fn continuation_with_no_start_is_rejected() {
        let mut r = AclReassembler::new();
        let cont = acl(0x0099, PbFlag::Continuation, &[0x01, 0x02]);
        let result = r.feed(&cont);
        assert!(
            matches!(result, Err(Error::OrphanContinuation { handle: 0x0099 })),
            "a continuation fragment with no prior start must be rejected, not treated as a new PDU"
        );
    }

    #[test]
    fn over_long_l2cap_length_field_is_rejected() {
        let mut r = AclReassembler::new();
        // Declares a PDU far larger than MAX_L2CAP_SDU_LEN; body doesn't
        // need to actually be that long since the check is on the declared
        // field before any accumulation happens.
        let start_raw = start_pkt(CID_SMP, 0xFFFF, &[0x00; 8]);
        let start = acl(0x0001, PbFlag::FirstNonFlushable, &start_raw);
        let result = r.feed(&start);
        assert!(
            matches!(
                result,
                Err(Error::PduTooLarge {
                    declared: 0xFFFF,
                    max: MAX_L2CAP_SDU_LEN
                })
            ),
            "an L2CAP Length field beyond the accepted ceiling must be rejected up front"
        );
    }

    #[test]
    fn pdu_split_across_packets_edge_case_leaves_no_residual_state() -> Result<()> {
        // Re-affirms the split-PDU case with an assertion on cleanup: after
        // completion, the handle must not still be tracked as in-progress
        // (a later continuation on the same handle must now be orphaned).
        let mut r = AclReassembler::new();
        let start_raw = start_pkt(CID_SMP, 4, &[0x01, 0x02]);
        let start = acl(0x0010, PbFlag::FirstNonFlushable, &start_raw);
        r.feed(&start)?;
        let cont = acl(0x0010, PbFlag::Continuation, &[0x03, 0x04]);
        assert!(r.feed(&cont)?.is_some(), "PDU should complete");

        let stray = acl(0x0010, PbFlag::Continuation, &[0xFF]);
        let result = r.feed(&stray);
        assert!(
            matches!(result, Err(Error::OrphanContinuation { handle: 0x0010 })),
            "a completed reassembly must not leave residual state a stray continuation can attach to"
        );
        Ok(())
    }

    // ── additional robustness cases ──

    #[test]
    fn header_truncated_start_fragment_is_rejected() {
        let mut r = AclReassembler::new();
        // Only 3 bytes: not enough for the 4-byte L2CAP Basic header.
        let start = acl(0x0001, PbFlag::FirstNonFlushable, &[0x01, 0x02, 0x03]);
        let result = r.feed(&start);
        assert!(
            matches!(
                result,
                Err(Error::HeaderTruncated {
                    min: L2CAP_HEADER_LEN,
                    actual: 3
                })
            ),
            "a start fragment too short for the L2CAP header must be rejected"
        );
    }

    #[test]
    fn single_fragment_body_exceeding_declared_length_is_rejected() {
        let mut r = AclReassembler::new();
        // Declares length=2 but carries 4 body bytes.
        let raw = start_pkt(CID_SMP, 2, &[0x01, 0x02, 0x03, 0x04]);
        let start = acl(0x0001, PbFlag::FirstNonFlushable, &raw);
        let result = r.feed(&start);
        assert!(
            matches!(
                result,
                Err(Error::ReassemblyOverrun {
                    handle: 0x0001,
                    expected: 2,
                    actual: 4
                })
            ),
            "a first fragment carrying more body than its own declared length must be rejected"
        );
    }

    #[test]
    fn continuation_overrun_past_declared_length_is_rejected() -> Result<()> {
        let mut r = AclReassembler::new();
        let start_raw = start_pkt(CID_SMP, 3, &[0x01]);
        let start = acl(0x0001, PbFlag::FirstNonFlushable, &start_raw);
        r.feed(&start)?;

        // Declared length is 3; this continuation alone brings the total to 5.
        let cont = acl(0x0001, PbFlag::Continuation, &[0x02, 0x03, 0x04, 0x05]);
        let result = r.feed(&cont);
        assert!(
            matches!(
                result,
                Err(Error::ReassemblyOverrun {
                    handle: 0x0001,
                    expected: 3,
                    actual: 5
                })
            ),
            "continuation bytes pushing total past the declared length must be rejected"
        );
        Ok(())
    }

    #[test]
    fn fresh_start_fragment_discards_stale_partial_for_same_handle() -> Result<()> {
        let mut r = AclReassembler::new();
        // Begin a 5-byte PDU but never finish it.
        let stale_raw = start_pkt(CID_SMP, 5, &[0x01, 0x02]);
        let stale_start = acl(0x0001, PbFlag::FirstNonFlushable, &stale_raw);
        r.feed(&stale_start)?;

        // A new start fragment on the same handle replaces the abandoned one.
        let fresh_raw = start_pkt(CID_SMP, 2, &[0xAA, 0xBB]);
        let fresh_start = acl(0x0001, PbFlag::FirstNonFlushable, &fresh_raw);
        let Some(sdu) = r.feed(&fresh_start)? else {
            unreachable!("fresh start with matching length must complete immediately");
        };
        assert_eq!(
            sdu.payload,
            vec![0xAA, 0xBB],
            "the fresh PDU's bytes must win, not a splice with the abandoned one"
        );
        Ok(())
    }

    #[test]
    fn independent_connection_handles_do_not_cross_contaminate() -> Result<()> {
        let mut r = AclReassembler::new();

        let a_start_raw = start_pkt(CID_SMP, 4, &[0xA1, 0xA2]);
        let a_start = acl(0x0001, PbFlag::FirstNonFlushable, &a_start_raw);
        assert_eq!(r.feed(&a_start)?, None);

        // Handle B completes fully while A is still in progress.
        let b_raw = start_pkt(CID_SMP, 2, &[0xB1, 0xB2]);
        let b_start = acl(0x0002, PbFlag::FirstNonFlushable, &b_raw);
        let Some(b_sdu) = r.feed(&b_start)? else {
            unreachable!("handle B's single-fragment PDU must complete on its own");
        };
        assert_eq!(b_sdu.handle, 0x0002);
        assert_eq!(b_sdu.payload, vec![0xB1, 0xB2]);

        // Handle A's continuation must still complete correctly afterward.
        let a_cont = acl(0x0001, PbFlag::Continuation, &[0xA3, 0xA4]);
        let Some(a_sdu) = r.feed(&a_cont)? else {
            unreachable!("handle A's continuation must complete independently of B");
        };
        assert_eq!(a_sdu.handle, 0x0001);
        assert_eq!(a_sdu.payload, vec![0xA1, 0xA2, 0xA3, 0xA4]);
        Ok(())
    }

    #[test]
    fn too_many_concurrent_reassemblies_is_rejected() -> Result<()> {
        let mut r = AclReassembler::new();
        // Open MAX_CONCURRENT_REASSEMBLIES distinct handles, each needing a
        // continuation (so none complete immediately and all stay tracked).
        for h in 0..u16::try_from(MAX_CONCURRENT_REASSEMBLIES).unwrap_or_default() {
            let raw = start_pkt(CID_SMP, 2, &[0x01]);
            let start = acl(h, PbFlag::FirstNonFlushable, &raw);
            assert_eq!(
                r.feed(&start)?,
                None,
                "handle {h} should need a continuation"
            );
        }

        // One more distinct handle must be rejected: no room to track it.
        let extra_handle = u16::try_from(MAX_CONCURRENT_REASSEMBLIES).unwrap_or_default();
        let extra_raw = start_pkt(CID_SMP, 2, &[0x01]);
        let extra_start = acl(extra_handle, PbFlag::FirstNonFlushable, &extra_raw);
        let result = r.feed(&extra_start);
        assert!(
            matches!(
                result,
                Err(Error::TooManyReassemblies {
                    max: MAX_CONCURRENT_REASSEMBLIES
                })
            ),
            "a reassembly beyond the concurrent-handle ceiling must be rejected"
        );
        Ok(())
    }

    #[test]
    fn completing_a_reassembly_frees_capacity_for_a_new_one() -> Result<()> {
        let mut r = AclReassembler::new();
        for h in 0..u16::try_from(MAX_CONCURRENT_REASSEMBLIES).unwrap_or_default() {
            let raw = start_pkt(CID_SMP, 2, &[0x01]);
            let start = acl(h, PbFlag::FirstNonFlushable, &raw);
            r.feed(&start)?;
        }

        // Complete handle 0's reassembly, freeing a slot.
        let cont = acl(0, PbFlag::Continuation, &[0x02]);
        assert!(r.feed(&cont)?.is_some());

        // A brand-new handle should now fit.
        let new_handle = u16::try_from(MAX_CONCURRENT_REASSEMBLIES).unwrap_or_default();
        let raw = start_pkt(CID_SMP, 2, &[0x01]);
        let start = acl(new_handle, PbFlag::FirstNonFlushable, &raw);
        assert_eq!(
            r.feed(&start)?,
            None,
            "freed capacity should admit a new in-progress reassembly"
        );
        Ok(())
    }

    // ── FixedChannel demux ──

    #[test]
    fn fixed_channel_routes_smp_cid() {
        assert_eq!(FixedChannel::from_cid(CID_SMP), FixedChannel::Smp);
    }

    #[test]
    fn fixed_channel_reports_unrouted_cid() {
        // CID 0x0004 is ATT — not routed by this driver yet (#635 scope is
        // SMP only).
        assert_eq!(
            FixedChannel::from_cid(0x0004),
            FixedChannel::Unrouted(0x0004)
        );
    }
}
