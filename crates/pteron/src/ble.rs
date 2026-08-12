//! BLE advertising data parsing, iBeacon detection, and scan parameter helpers.
//!
//! Advertising payloads are encoded as a sequence of *AD structures*, each
//! consisting of a length byte, a type byte, and zero or more data bytes.
//! This module parses that format and identifies Apple iBeacon packets.
//!
//! Scan parameter helpers always set `Own_Address_Type = 0x01` (Random) to
//! avoid broadcasting the permanent `BD_ADDR` during passive or active scanning.

// ── Constants ──────────────────────────────────────────────────────────────────

const AD_TYPE_FLAGS: u8 = 0x01;
const AD_TYPE_INCOMPLETE_UUID16: u8 = 0x02;
const AD_TYPE_COMPLETE_UUID16: u8 = 0x03;
const AD_TYPE_SHORT_NAME: u8 = 0x08;
const AD_TYPE_COMPLETE_NAME: u8 = 0x09;
const AD_TYPE_TX_POWER_LEVEL: u8 = 0x0A;
const AD_TYPE_MANUFACTURER_DATA: u8 = 0xFF;

// Own_Address_Type = 0x01 (Random) — used in all LE scanning commands.
//
// WHY: always use the random address when scanning to prevent the permanent
// BD_ADDR from being exposed in scan requests or connection initiations.
const OWN_ADDR_TYPE_RANDOM: u8 = 0x01;

// iBeacon constants
const APPLE_COMPANY_ID_LO: u8 = 0x4C;
const APPLE_COMPANY_ID_HI: u8 = 0x00;
const IBEACON_TYPE: u8 = 0x02;
const IBEACON_LENGTH: u8 = 0x15; // 21 bytes: UUID(16) + major(2) + minor(2) + tx_power(1)
const IBEACON_UUID_LEN: usize = 16;

// Offsets within manufacturer data payload (after company ID 2 bytes)
const IBEACON_TYPE_OFFSET: usize = 2;
const IBEACON_LEN_OFFSET: usize = 3;
const IBEACON_UUID_OFFSET: usize = 4;
const IBEACON_MAJOR_OFFSET: usize = 20;
const IBEACON_MINOR_OFFSET: usize = 22;
const IBEACON_TX_POWER_OFFSET: usize = 24;
const IBEACON_TOTAL_LEN: usize = 25; // company_id(2) + type(1) + len(1) + UUID(16) + major(2) + minor(2) + tx_power(1)

// ── Types ──────────────────────────────────────────────────────────────────────

/// Known BLE AD type codes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) enum AdType {
    /// Flags (AD type `0x01`).
    #[default]
    Flags,
    /// Shortened local name (AD type `0x08`).
    ShortName,
    /// Complete local name (AD type `0x09`).
    CompleteName,
    /// TX power level (AD type `0x0A`).
    TxPowerLevel,
    /// List of service UUIDs — complete or incomplete (AD types `0x02`/`0x03`).
    ServiceUuids,
    /// Manufacturer-specific data (AD type `0xFF`).
    ManufacturerData,
    /// Any other AD type not explicitly recognised.
    Unknown(u8),
}

/// A single AD structure extracted from a BLE advertising payload.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) struct AdStructure {
    /// The AD type of this structure.
    pub(crate) ad_type: AdType,
    /// Raw data bytes (everything after the type byte).
    pub(crate) data: Vec<u8>,
}

/// Parsed BLE advertising payload, consisting of zero or more AD structures.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub(crate) struct AdvertisingData {
    /// AD structures parsed from the raw payload.
    pub(crate) structures: Vec<AdStructure>,
}

/// Apple iBeacon payload extracted from a manufacturer-specific AD structure.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) struct IBeacon {
    /// 128-bit proximity UUID.
    pub(crate) uuid: [u8; IBEACON_UUID_LEN],
    /// Major grouping identifier.
    pub(crate) major: u16,
    /// Minor sub-grouping identifier.
    pub(crate) minor: u16,
    /// Measured TX power at 1 metre (dBm), used for ranging.
    pub(crate) tx_power: i8,
}

// ── AdType impl ────────────────────────────────────────────────────────────────

impl AdType {
    const fn from_byte(b: u8) -> Self {
        match b {
            AD_TYPE_FLAGS => Self::Flags,
            AD_TYPE_INCOMPLETE_UUID16 | AD_TYPE_COMPLETE_UUID16 => Self::ServiceUuids,
            AD_TYPE_SHORT_NAME => Self::ShortName,
            AD_TYPE_COMPLETE_NAME => Self::CompleteName,
            AD_TYPE_TX_POWER_LEVEL => Self::TxPowerLevel,
            AD_TYPE_MANUFACTURER_DATA => Self::ManufacturerData,
            other => Self::Unknown(other),
        }
    }
}

// ── AdvertisingData impl ───────────────────────────────────────────────────────

impl AdvertisingData {
    /// Construct an [`AdvertisingData`] from pre-parsed AD structures.
    pub(crate) const fn new(structures: Vec<AdStructure>) -> Self {
        Self { structures }
    }

    /// Parse raw advertising payload bytes into an [`AdvertisingData`].
    ///
    /// Parsing is best-effort: if a structure is truncated, parsing stops and
    /// whatever was already decoded is returned.
    pub(crate) fn parse(data: &[u8]) -> Self {
        Self {
            structures: parse_ad_structures(data),
        }
    }
}

/// Scan parameter set for passive BLE scanning with random address.
///
/// All fields use the recommended defaults from the BLE spec and Thumos
/// privacy policy: passive scan, random own address, no filter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScanParameters {
    /// Scan type: `0x00` = passive, `0x01` = active.
    pub(crate) scan_type: u8,
    /// Scan interval in 0.625 ms units.
    pub(crate) scan_interval: u16,
    /// Scan window in 0.625 ms units.
    pub(crate) scan_window: u16,
    /// Own address type: always `0x01` (Random).
    pub(crate) own_address_type: u8,
    /// Scanning filter policy: `0x00` = accept all.
    pub(crate) filter_policy: u8,
}

impl ScanParameters {
    /// Construct passive scan parameters with random own address type.
    ///
    /// WHY: passive scanning does not transmit scan requests, so the scanner's
    /// address is never broadcast; combined with a random own address type,
    /// this eliminates `BD_ADDR` exposure during discovery.
    pub(crate) const fn passive_random() -> Self {
        Self {
            scan_type: 0x00,       // passive
            scan_interval: 0x0010, // 10 ms
            scan_window: 0x0010,   // 10 ms
            own_address_type: OWN_ADDR_TYPE_RANDOM,
            filter_policy: 0x00, // accept all
        }
    }
}

// ── Free functions ─────────────────────────────────────────────────────────────

/// Parse a BLE advertising payload into a list of [`AdStructure`]s.
///
/// The format is a packed sequence of length-type-value triples:
/// - `length` (1 byte): number of following bytes, including the type byte
/// - `type` (1 byte): AD type code
/// - `data` (`length - 1` bytes): payload
///
/// Parsing is best-effort — a zero-length entry or truncated payload stops
/// iteration; whatever was decoded up to that point is returned.
pub(crate) fn parse_ad_structures(data: &[u8]) -> Vec<AdStructure> {
    let mut structures = Vec::new();
    let mut pos = 0;

    loop {
        let length = match data.get(pos).copied() {
            Some(0) | None => break, // zero-length or end of buffer
            Some(l) => usize::from(l),
        };
        pos += 1;

        // type byte + (length - 1) data bytes
        let Some(ad_type_byte) = data.get(pos).copied() else {
            break; // truncated
        };
        pos += 1;

        let data_len = length.saturating_sub(1);
        let payload = match data.get(pos..pos + data_len) {
            Some(s) => s.to_vec(),
            None => break, // truncated data
        };
        pos += data_len;

        structures.push(AdStructure {
            ad_type: AdType::from_byte(ad_type_byte),
            data: payload,
        });
    }

    structures
}

/// Detect an Apple iBeacon in parsed advertising data.
///
/// Searches the AD structures for a `ManufacturerData` entry that matches the
/// iBeacon format (Apple company ID `0x004C`, type `0x02`, length `0x15`).
/// Returns `None` if no iBeacon is found.
///
/// Time: O(s) where s is the number of AD structures in `ad.structures` —
/// each structure is checked once, and `try_parse_ibeacon` does a fixed
/// number of comparisons against the (constant-size) iBeacon layout.
/// Space: O(1) — no allocation; the returned [`IBeacon`] is a fixed-size
/// value copied out of the matched structure's bytes.
pub(crate) fn is_ibeacon(ad: &AdvertisingData) -> Option<IBeacon> {
    for structure in &ad.structures {
        if structure.ad_type != AdType::ManufacturerData {
            continue;
        }
        if let Some(beacon) = try_parse_ibeacon(&structure.data) {
            return Some(beacon);
        }
    }
    None
}

fn try_parse_ibeacon(data: &[u8]) -> Option<IBeacon> {
    if data.len() < IBEACON_TOTAL_LEN {
        return None;
    }
    // Check Apple company ID (little-endian 0x004C)
    if data.first().copied()? != APPLE_COMPANY_ID_LO {
        return None;
    }
    if data.get(1).copied()? != APPLE_COMPANY_ID_HI {
        return None;
    }
    // iBeacon type and length
    if data.get(IBEACON_TYPE_OFFSET).copied()? != IBEACON_TYPE {
        return None;
    }
    if data.get(IBEACON_LEN_OFFSET).copied()? != IBEACON_LENGTH {
        return None;
    }

    // UUID (16 bytes, big-endian as stored)
    let uuid_slice = data.get(IBEACON_UUID_OFFSET..IBEACON_UUID_OFFSET + IBEACON_UUID_LEN)?;
    let mut uuid = [0u8; IBEACON_UUID_LEN];
    uuid.copy_from_slice(uuid_slice);

    // Major (2 bytes, big-endian)
    let major_hi = data.get(IBEACON_MAJOR_OFFSET).copied()?;
    let major_lo = data.get(IBEACON_MAJOR_OFFSET + 1).copied()?;
    let major = u16::from_be_bytes([major_hi, major_lo]);

    // Minor (2 bytes, big-endian)
    let minor_hi = data.get(IBEACON_MINOR_OFFSET).copied()?;
    let minor_lo = data.get(IBEACON_MINOR_OFFSET + 1).copied()?;
    let minor = u16::from_be_bytes([minor_hi, minor_lo]);

    // TX Power (1 byte, signed)
    let tx_power = data.get(IBEACON_TX_POWER_OFFSET).copied()?.cast_signed();

    Some(IBeacon {
        uuid,
        major,
        minor,
        tx_power,
    })
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_ad_structures ──

    #[test]
    fn parse_empty_payload_returns_no_structures() {
        let result = parse_ad_structures(&[]);
        assert!(
            result.is_empty(),
            "empty payload should produce no AD structures"
        );
    }

    #[test]
    fn parse_complete_name_ad_structure() {
        // Length=5, Type=0x09 (CompleteName), data="Test" (4 bytes)
        let data = [0x05, 0x09, b'T', b'e', b's', b't'];
        let result = parse_ad_structures(&data);
        assert_eq!(result.len(), 1, "should parse exactly one AD structure");
        assert_eq!(
            result.first().cloned().unwrap_or_default().ad_type,
            AdType::CompleteName,
            "AD type should be CompleteName (0x09)"
        );
        assert_eq!(
            result.first().cloned().unwrap_or_default().data,
            b"Test",
            "data should be the 4 name bytes"
        );
    }

    #[test]
    fn parse_multiple_ad_structures() {
        // Flags: len=2, type=0x01, data=0x06
        // TxPower: len=2, type=0x0A, data=0xF0
        let data = [0x02, 0x01, 0x06, 0x02, 0x0A, 0xF0];
        let result = parse_ad_structures(&data);
        assert_eq!(result.len(), 2, "should parse two AD structures");
        assert_eq!(
            result.first().cloned().unwrap_or_default().ad_type,
            AdType::Flags,
            "first structure should be Flags"
        );
        assert_eq!(
            result.get(1).cloned().unwrap_or_default().ad_type,
            AdType::TxPowerLevel,
            "second structure should be TxPowerLevel"
        );
    }

    #[test]
    fn parse_truncated_payload_returns_partial_results() {
        // One valid structure then truncated second
        let data = [0x02, 0x01, 0x06, 0x05, 0x09]; // second AD claims 5 bytes but only type follows
        let result = parse_ad_structures(&data);
        assert_eq!(
            result.len(),
            1,
            "only the complete AD structure should be returned when data is truncated"
        );
    }

    #[test]
    fn parse_zero_length_entry_stops_iteration() {
        // Valid structure, then zero-length terminator
        let data = [0x02, 0x01, 0x06, 0x00, 0x02, 0x01, 0x06];
        let result = parse_ad_structures(&data);
        assert_eq!(
            result.len(),
            1,
            "parsing should stop at a zero-length AD entry"
        );
    }

    #[test]
    fn parse_unknown_ad_type_is_preserved() {
        // Type=0x42 is not in our known set
        let data = [0x03, 0x42, 0xAB, 0xCD];
        let result = parse_ad_structures(&data);
        assert_eq!(
            result.len(),
            1,
            "unknown type should still produce one structure"
        );
        assert_eq!(
            result.first().cloned().unwrap_or_default().ad_type,
            AdType::Unknown(0x42),
            "unknown type byte should be wrapped in AdType::Unknown"
        );
        assert_eq!(
            result.first().cloned().unwrap_or_default().data,
            &[0xAB, 0xCD],
            "data bytes should be preserved"
        );
    }

    #[test]
    fn parse_manufacturer_data_ad_type() {
        // Type=0xFF, 3 bytes of data
        let data = [0x04, 0xFF, 0x4C, 0x00, 0x02];
        let result = parse_ad_structures(&data);
        assert_eq!(
            result.len(),
            1,
            "should parse one manufacturer data structure"
        );
        assert_eq!(
            result.first().cloned().unwrap_or_default().ad_type,
            AdType::ManufacturerData,
            "type 0xFF should map to ManufacturerData"
        );
    }

    // ── is_ibeacon ──

    fn ibeacon_ad_data() -> Vec<u8> {
        // Manufacturer data for a standard iBeacon:
        //   company_id = 0x004C (Apple), type=0x02, len=0x15
        //   UUID = 550e8400-e29b-41d4-a716-446655440000
        //   major = 1, minor = 2, tx_power = -59 (0xC5)
        let mut d = vec![
            0x4C, 0x00, // Apple company ID
            0x02, // iBeacon type
            0x15, // iBeacon length (21)
        ];
        // UUID bytes (big-endian)
        d.extend_from_slice(&[
            0x55, 0x0E, 0x84, 0x00, 0xE2, 0x9B, 0x41, 0xD4, 0xA7, 0x16, 0x44, 0x66, 0x55, 0x44,
            0x00, 0x00,
        ]);
        d.extend_from_slice(&[0x00, 0x01]); // major = 1
        d.extend_from_slice(&[0x00, 0x02]); // minor = 2
        d.push(0xC5_u8); // tx_power = -59
        d
    }

    #[test]
    fn is_ibeacon_detects_valid_ibeacon() {
        let mfr_data = ibeacon_ad_data();
        let ad = AdvertisingData::new(vec![AdStructure {
            ad_type: AdType::ManufacturerData,
            data: mfr_data,
        }]);
        let Some(beacon) = is_ibeacon(&ad) else {
            unreachable!("valid iBeacon data should be detected");
        };
        assert_eq!(beacon.major, 1, "major should be 1");
        assert_eq!(beacon.minor, 2, "minor should be 2");
        assert_eq!(beacon.tx_power, -59_i8, "tx_power should be -59 dBm");
        assert_eq!(
            beacon.uuid.first().copied().unwrap_or_default(),
            0x55,
            "first UUID byte should be 0x55"
        );
    }

    #[test]
    fn is_ibeacon_returns_none_for_non_apple_manufacturer_data() {
        // Same structure but with a different company ID
        let mut data = ibeacon_ad_data();
        data[0] = 0x00; // not Apple
        let ad = AdvertisingData::new(vec![AdStructure {
            ad_type: AdType::ManufacturerData,
            data,
        }]);
        assert!(
            is_ibeacon(&ad).is_none(),
            "non-Apple company ID should not be detected as iBeacon"
        );
    }

    #[test]
    fn is_ibeacon_returns_none_when_no_manufacturer_data() {
        let ad = AdvertisingData::new(vec![AdStructure {
            ad_type: AdType::CompleteName,
            data: b"NotABeacon".to_vec(),
        }]);
        assert!(
            is_ibeacon(&ad).is_none(),
            "advertising data with no ManufacturerData should not match iBeacon"
        );
    }

    #[test]
    fn is_ibeacon_returns_none_for_wrong_ibeacon_type_byte() {
        let mut data = ibeacon_ad_data();
        data[2] = 0x03; // type != 0x02
        let ad = AdvertisingData::new(vec![AdStructure {
            ad_type: AdType::ManufacturerData,
            data,
        }]);
        assert!(
            is_ibeacon(&ad).is_none(),
            "wrong iBeacon type byte should not be detected"
        );
    }

    #[test]
    fn advertising_data_parse_roundtrip() {
        // Build raw bytes: CompleteName "Hi" + TxPower -70
        let raw = [0x03, 0x09, b'H', b'i', 0x02, 0x0A, 0xBA];
        let ad = AdvertisingData::parse(&raw);
        assert_eq!(
            ad.structures.len(),
            2,
            "should parse two structures FROM the raw bytes"
        );
        assert_eq!(
            ad.structures.first().cloned().unwrap_or_default().ad_type,
            AdType::CompleteName,
            "first structure should be CompleteName"
        );
        assert_eq!(
            ad.structures.get(1).cloned().unwrap_or_default().ad_type,
            AdType::TxPowerLevel,
            "second structure should be TxPowerLevel"
        );
    }
}
