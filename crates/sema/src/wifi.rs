//! `WiFi` access point types, MAC address parsing, and channel/frequency utilities.

use std::fmt;
use std::str::FromStr;

use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use snafu::Snafu;

const BAND_2_4_GHZ_FREQ_OFFSET: u32 = 2407;
const BAND_2_4_GHZ_CHANNEL_14_FREQ: u32 = 2484;
const BAND_5_GHZ_FREQ_OFFSET: u32 = 5000;
const CHANNEL_STEP_MHZ: u32 = 5;
const MAC_BYTE_COUNT: usize = 6;

/// Error type for MAC address parsing.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub(crate) enum ParseError {
    /// Input does not have exactly 6 colon-separated segments.
    #[snafu(display("invalid MAC address format: expected AA:BB:CC:DD:EE:FF, got '{input}'"))]
    InvalidMacFormat {
        /// The full input string that failed to parse.
        input: String,
    },

    /// A single byte segment is not valid hexadecimal.
    #[snafu(display("invalid MAC address byte: '{byte}' is not valid hex"))]
    InvalidMacByte {
        /// The byte string that failed to parse.
        byte: String,
    },
}

/// A `WiFi` MAC address (`BSSID`), stored as six raw bytes.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(crate) struct Bssid([u8; MAC_BYTE_COUNT]);

/// Wireless encryption mode reported by an access point.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub(crate) enum Encryption {
    /// No encryption; network is open.
    Open,
    /// Wired Equivalent Privacy (legacy, broken).
    Wep,
    /// WPA2 with a pre-shared key.
    Wpa2Personal,
    /// WPA2 with 802.1X enterprise authentication.
    Wpa2Enterprise,
    /// WPA3 (SAE).
    Wpa3,
    /// Encryption type could not be determined.
    Unknown,
}

/// The RF frequency band a channel belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub(crate) enum Band {
    /// 2.4 GHz band (channels 1–14).
    Band2_4Ghz,
    /// 5 GHz band (channels 36–165).
    Band5Ghz,
}

/// A `WiFi` access point observed during a scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub(crate) struct AccessPoint {
    /// Hardware MAC address of the AP radio.
    pub(crate) bssid: Bssid,
    /// Network name (SSID).
    pub(crate) ssid: String,
    /// Channel number (1–14 for 2.4 GHz; 36–165 for 5 GHz).
    pub(crate) channel: u8,
    /// Center frequency in MHz.
    pub(crate) frequency_mhz: u32,
    /// Received signal strength in dBm (higher is stronger; typical range −30 to −90).
    pub(crate) signal_dbm: i32,
    /// Encryption mode advertised in beacon frames.
    pub(crate) encryption: Encryption,
    /// Wall-clock time when this AP was last seen.
    pub(crate) last_seen: Timestamp,
}

impl Bssid {
    /// Parse a MAC address FROM a colon-separated hex string (e.g., `"AA:BB:CC:DD:EE:FF"`).
    ///
    /// The string is case-insensitive; `"aa:bb:cc:dd:ee:ff"` and `"AA:BB:CC:DD:EE:FF"`
    /// produce the same value.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::InvalidMacFormat`] if the input does not have exactly six
    /// colon-separated segments.
    ///
    /// Returns [`ParseError::InvalidMacByte`] if any segment is not valid hexadecimal.
    ///
    /// Internal callers parse display-order addresses such as
    /// `AA:BB:CC:DD:EE:FF`.
    pub(crate) fn parse(s: &str) -> Result<Self, ParseError> {
        s.parse()
    }

    /// Return the raw bytes of this MAC address.
    #[must_use]
    pub(crate) const fn as_bytes(&self) -> &[u8; MAC_BYTE_COUNT] {
        &self.0
    }
}

impl FromStr for Bssid {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != MAC_BYTE_COUNT {
            return Err(ParseError::InvalidMacFormat {
                input: s.to_owned(),
            });
        }
        let mut bytes = [0u8; MAC_BYTE_COUNT];
        for (byte, part) in bytes.iter_mut().zip(parts.iter()) {
            *byte = u8::from_str_radix(part, 16).map_err(|_| ParseError::InvalidMacByte {
                byte: (*part).to_owned(),
            })?;
        }
        Ok(Self(bytes))
    }
}

impl fmt::Display for Bssid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [b0, b1, b2, b3, b4, b5] = self.0;
        write!(f, "{b0:02X}:{b1:02X}:{b2:02X}:{b3:02X}:{b4:02X}:{b5:02X}")
    }
}

impl fmt::Debug for Bssid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Bssid({self})")
    }
}

impl fmt::Display for Encryption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Open => "Open",
            Self::Wep => "WEP",
            Self::Wpa2Personal => "WPA2-Personal",
            Self::Wpa2Enterprise => "WPA2-Enterprise",
            Self::Wpa3 => "WPA3",
            Self::Unknown => "Unknown",
        };
        f.write_str(s)
    }
}

impl fmt::Display for Band {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Band2_4Ghz => "2.4 GHz",
            Self::Band5Ghz => "5 GHz",
        };
        f.write_str(s)
    }
}

impl AccessPoint {
    /// Construct an [`AccessPoint`] with all fields.
    pub(crate) fn new(
        bssid: Bssid,
        ssid: impl Into<String>,
        channel: u8,
        frequency_mhz: u32,
        signal_dbm: i32,
        encryption: Encryption,
        last_seen: Timestamp,
    ) -> Self {
        Self {
            bssid,
            ssid: ssid.into(),
            channel,
            frequency_mhz,
            signal_dbm,
            encryption,
            last_seen,
        }
    }
}

/// Convert a `WiFi` channel number to its center frequency in MHz.
///
/// Supports 2.4 GHz channels 1–13 and the special channel 14 (Japan only),
/// plus 5 GHz channels 36–165. Returns `None` for all other VALUES.
///
/// Internal callers use this to map channels 1, 6, 14, and 36 to 2412,
/// 2437, 2484, and 5180 MHz respectively.
#[must_use]
pub(crate) fn channel_to_frequency(channel: u8) -> Option<u32> {
    match channel {
        1..=13 => {
            let ch = u32::from(channel);
            let offset = ch.checked_mul(CHANNEL_STEP_MHZ)?;
            BAND_2_4_GHZ_FREQ_OFFSET.checked_add(offset)
        }
        14 => Some(BAND_2_4_GHZ_CHANNEL_14_FREQ),
        36..=165 => {
            let ch = u32::from(channel);
            let offset = ch.checked_mul(CHANNEL_STEP_MHZ)?;
            BAND_5_GHZ_FREQ_OFFSET.checked_add(offset)
        }
        _ => None,
    }
}

/// Convert a center frequency in MHz to a `WiFi` channel number.
///
/// Recognises standard 2.4 GHz frequencies (2412–2484 MHz) and 5 GHz frequencies
/// (5180–5825 MHz). Returns `None` for frequencies that do not align with a
/// channel boundary or fall outside recognised bands.
///
/// Internal callers use this to reverse the standard channel-to-frequency
/// mapping and reject out-of-band frequencies.
#[must_use]
pub(crate) fn frequency_to_channel(freq_mhz: u32) -> Option<u8> {
    if freq_mhz == BAND_2_4_GHZ_CHANNEL_14_FREQ {
        return Some(14);
    }
    if (2412..=2472).contains(&freq_mhz) {
        let offset = freq_mhz.checked_sub(BAND_2_4_GHZ_FREQ_OFFSET)?;
        if offset % CHANNEL_STEP_MHZ != 0 {
            return None;
        }
        return u8::try_from(offset / CHANNEL_STEP_MHZ).ok(); // kanon:ignore RUST/silent-error-ok -- channels 1..=13 always fit in u8; try_from failure is structurally unreachable given the range guard above
    }
    if (5180..=5825).contains(&freq_mhz) {
        let offset = freq_mhz.checked_sub(BAND_5_GHZ_FREQ_OFFSET)?;
        if offset % CHANNEL_STEP_MHZ != 0 {
            return None;
        }
        return u8::try_from(offset / CHANNEL_STEP_MHZ).ok(); // kanon:ignore RUST/silent-error-ok -- channels 36..=165 always fit in u8; try_from failure is structurally unreachable given the range guard above
    }
    None
}

/// Return the frequency band for a given channel number, or `None` if unrecognised.
///
/// Channels 1-14 map to 2.4 GHz, channels 36-165 map to 5 GHz, and
/// unrecognised channels return `None`.
#[must_use]
pub(crate) const fn channel_band(channel: u8) -> Option<Band> {
    match channel {
        1..=14 => Some(Band::Band2_4Ghz),
        36..=165 => Some(Band::Band5Ghz),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bssid_parses_valid_uppercase() -> Result<(), ParseError> {
        let bssid = Bssid::parse("AA:BB:CC:DD:EE:FF")?;
        assert_eq!(
            bssid.as_bytes(),
            &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            "parsed bytes should match input hex VALUES"
        );
        Ok(())
    }

    #[test]
    fn bssid_parses_valid_lowercase() -> Result<(), ParseError> {
        let bssid = Bssid::parse("aa:bb:cc:dd:ee:ff")?;
        assert_eq!(
            bssid.as_bytes(),
            &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            "lowercase should produce same bytes as uppercase"
        );
        Ok(())
    }

    #[test]
    fn bssid_parses_valid_mixed_case() -> Result<(), ParseError> {
        let bssid = Bssid::parse("Aa:bB:cC:dD:Ee:fF")?;
        assert_eq!(
            bssid.as_bytes(),
            &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            "mixed case should produce same bytes as uppercase"
        );
        Ok(())
    }

    #[test]
    fn bssid_rejects_too_few_segments() {
        let result = Bssid::parse("AA:BB:CC:DD:EE");
        assert!(
            result.is_err(),
            "MAC with only 5 segments should be rejected"
        );
    }

    #[test]
    fn bssid_rejects_too_many_segments() {
        let result = Bssid::parse("AA:BB:CC:DD:EE:FF:00");
        assert!(result.is_err(), "MAC with 7 segments should be rejected");
    }

    #[test]
    fn bssid_rejects_invalid_hex_byte() {
        let result = Bssid::parse("ZZ:BB:CC:DD:EE:FF");
        assert!(result.is_err(), "non-hex byte 'ZZ' should be rejected");
    }

    #[test]
    fn bssid_display_formats_uppercase_colon_separated() {
        let bssid = Bssid([0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E]);
        assert_eq!(
            bssid.to_string(),
            "00:1A:2B:3C:4D:5E",
            "Display should produce uppercase colon-separated hex"
        );
    }

    #[test]
    fn bssid_from_str_trait_works() -> Result<(), ParseError> {
        let bssid: Bssid = "DE:AD:BE:EF:00:01".parse()?;
        assert_eq!(
            bssid.to_string(),
            "DE:AD:BE:EF:00:01",
            "roundtrip through FromStr should preserve value"
        );
        Ok(())
    }

    #[test]
    fn channel_to_frequency_2_4ghz_channel_1_is_2412() {
        assert_eq!(
            channel_to_frequency(1),
            Some(2412),
            "channel 1 should map to 2412 MHz"
        );
    }

    #[test]
    fn channel_to_frequency_2_4ghz_channel_6_is_2437() {
        assert_eq!(
            channel_to_frequency(6),
            Some(2437),
            "channel 6 should map to 2437 MHz"
        );
    }

    #[test]
    fn channel_to_frequency_2_4ghz_channel_13_is_2472() {
        assert_eq!(
            channel_to_frequency(13),
            Some(2472),
            "channel 13 should map to 2472 MHz"
        );
    }

    #[test]
    fn channel_to_frequency_2_4ghz_channel_14_is_2484() {
        assert_eq!(
            channel_to_frequency(14),
            Some(2484),
            "channel 14 (Japan) should map to 2484 MHz"
        );
    }

    #[test]
    fn channel_to_frequency_5ghz_channel_36_is_5180() {
        assert_eq!(
            channel_to_frequency(36),
            Some(5180),
            "channel 36 should map to 5180 MHz"
        );
    }

    #[test]
    fn channel_to_frequency_5ghz_channel_165_is_5825() {
        assert_eq!(
            channel_to_frequency(165),
            Some(5825),
            "channel 165 should map to 5825 MHz"
        );
    }

    #[test]
    fn channel_to_frequency_invalid_channels_return_none() {
        assert_eq!(
            channel_to_frequency(0),
            None,
            "channel 0 should return None"
        );
        assert_eq!(
            channel_to_frequency(15),
            None,
            "channel 15 is unused, should return None"
        );
        assert_eq!(
            channel_to_frequency(35),
            None,
            "channel 35 is unused, should return None"
        );
        assert_eq!(
            channel_to_frequency(166),
            None,
            "channel 166 is above range, should return None"
        );
    }

    #[test]
    fn frequency_to_channel_2_4ghz_roundtrips() -> Result<(), String> {
        for ch in 1u8..=13 {
            let freq = channel_to_frequency(ch)
                .ok_or_else(|| format!("channel {ch} should have a frequency"))?;
            let back = frequency_to_channel(freq)
                .ok_or_else(|| format!("frequency {freq} should map back to a channel"))?;
            assert_eq!(back, ch, "channel {ch} should roundtrip through frequency");
        }
        Ok(())
    }

    #[test]
    fn frequency_to_channel_channel_14_roundtrips() -> Result<(), String> {
        let freq = channel_to_frequency(14)
            .ok_or_else(|| "channel 14 should have a frequency".to_owned())?;
        let back = frequency_to_channel(freq)
            .ok_or_else(|| "channel 14 frequency should convert back".to_owned())?;
        assert_eq!(back, 14, "channel 14 should roundtrip through frequency");
        Ok(())
    }

    #[test]
    fn frequency_to_channel_5ghz_roundtrips() -> Result<(), String> {
        for ch in [36u8, 40, 44, 48, 100, 149, 165] {
            let freq = channel_to_frequency(ch)
                .ok_or_else(|| format!("5 GHz channel {ch} should have a frequency"))?;
            let back = frequency_to_channel(freq)
                .ok_or_else(|| format!("5 GHz frequency {freq} should map back to a channel"))?;
            assert_eq!(
                back, ch,
                "5 GHz channel {ch} should roundtrip through frequency"
            );
        }
        Ok(())
    }

    #[test]
    fn frequency_to_channel_non_channel_aligned_frequency_returns_none() {
        assert_eq!(
            frequency_to_channel(2413),
            None,
            "2413 MHz does not align with any channel boundary"
        );
    }

    #[test]
    fn frequency_to_channel_out_of_band_frequency_returns_none() {
        assert_eq!(
            frequency_to_channel(9999),
            None,
            "9999 MHz is outside any recognised WiFi band"
        );
    }
}
