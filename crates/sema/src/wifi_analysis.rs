//! `WiFi` scan result analysis: evil twin detection, rogue AP identification,
//! channel utilisation, signal mapping, and open network enumeration.

use std::collections::HashMap;

use crate::wifi::{AccessPoint, Bssid, Encryption};

/// Detect potential evil twin attacks.
///
/// An evil twin is an AP that shares an SSID with another AP but uses a different BSSID.
/// This function returns every pair of APs that share an SSID with distinct BSSIDs.
///
/// Note: legitimate networks may have multiple APs with the same SSID (e.g., 2.4/5 GHz
/// radios on the same router). Callers should apply additional heuristics (signal delta,
/// channel, vendor OUI) to reduce false positives.
///
/// # Examples
///
/// ```
/// use thumos_sema::wifi::{AccessPoint, Bssid, Encryption};
/// use thumos_sema::wifi_analysis::detect_evil_twin;
/// use jiff::Timestamp;
///
/// let ts = Timestamp::UNIX_EPOCH;
/// let real = AccessPoint::new(
///     Bssid::parse("AA:BB:CC:DD:EE:01").unwrap(),
///     "Corp-WiFi", 6, 2437, -65, Encryption::Wpa2Enterprise, ts,
/// );
/// let twin = AccessPoint::new(
///     Bssid::parse("AA:BB:CC:DD:EE:02").unwrap(),
///     "Corp-WiFi", 6, 2437, -40, Encryption::Open, ts,
/// );
/// let aps = [real, twin];
/// let pairs = detect_evil_twin(&aps);
/// assert_eq!(pairs.len(), 1);
/// ```
#[must_use]
pub fn detect_evil_twin(aps: &[AccessPoint]) -> Vec<(&AccessPoint, &AccessPoint)> {
    let mut by_ssid: HashMap<&str, Vec<&AccessPoint>> = HashMap::new();
    for ap in aps {
        by_ssid.entry(ap.ssid.as_str()).or_default().push(ap);
    }

    let mut pairs = Vec::new();
    for group in by_ssid.values() {
        for (i, a) in group.iter().enumerate() {
            for b in group.iter().skip(i.saturating_add(1)) {
                if a.bssid != b.bssid {
                    pairs.push((*a, *b));
                }
            }
        }
    }
    pairs
}

/// Detect rogue access points: APs whose BSSID is not in the known-good list.
///
/// # Examples
///
/// ```
/// use thumos_sema::wifi::{AccessPoint, Bssid, Encryption};
/// use thumos_sema::wifi_analysis::detect_rogue_ap;
/// use jiff::Timestamp;
///
/// let ts = Timestamp::UNIX_EPOCH;
/// let known = Bssid::parse("AA:BB:CC:DD:EE:01").unwrap();
/// let rogue_bssid = Bssid::parse("FF:FF:FF:FF:FF:FF").unwrap();
/// let ap = AccessPoint::new(rogue_bssid, "Corp-WiFi", 6, 2437, -70, Encryption::Wpa2Personal, ts);
/// let aps = [ap];
/// let known_list = [known];
/// let rogues = detect_rogue_ap(&aps, &known_list);
/// assert_eq!(rogues.len(), 1);
/// ```
#[must_use]
pub fn detect_rogue_ap<'a>(aps: &'a [AccessPoint], known_bssids: &[Bssid]) -> Vec<&'a AccessPoint> {
    aps.iter()
        .filter(|ap| !known_bssids.contains(&ap.bssid))
        .collect()
}

/// Count the number of APs operating on each channel.
///
/// Returns a map from channel number to AP count. Channels with high counts
/// may be congested, leading to interference.
///
/// # Examples
///
/// ```
/// use thumos_sema::wifi::{AccessPoint, Bssid, Encryption};
/// use thumos_sema::wifi_analysis::channel_utilization;
/// use jiff::Timestamp;
///
/// let ts = Timestamp::UNIX_EPOCH;
/// let ap1 = AccessPoint::new(Bssid::parse("AA:BB:CC:DD:EE:01").unwrap(), "A", 6, 2437, -70, Encryption::Wpa2Personal, ts);
/// let ap2 = AccessPoint::new(Bssid::parse("AA:BB:CC:DD:EE:02").unwrap(), "B", 6, 2437, -75, Encryption::Wpa2Personal, ts);
/// let ap3 = AccessPoint::new(Bssid::parse("AA:BB:CC:DD:EE:03").unwrap(), "C", 11, 2462, -80, Encryption::Open, ts);
/// let counts = channel_utilization(&[ap1, ap2, ap3]);
/// assert_eq!(counts[&6], 2);
/// assert_eq!(counts[&11], 1);
/// ```
#[must_use]
pub fn channel_utilization(aps: &[AccessPoint]) -> HashMap<u8, usize> {
    let mut counts: HashMap<u8, usize> = HashMap::new();
    for ap in aps {
        let entry = counts.entry(ap.channel).or_insert(0);
        *entry = entry.saturating_add(1);
    }
    counts
}

/// Sort APs by signal strength, strongest first (highest dBm value).
///
/// The first element in the returned slice is the AP with the best signal;
/// the last is the weakest.
///
/// # Examples
///
/// ```
/// use thumos_sema::wifi::{AccessPoint, Bssid, Encryption};
/// use thumos_sema::wifi_analysis::signal_map;
/// use jiff::Timestamp;
///
/// let ts = Timestamp::UNIX_EPOCH;
/// let weak = AccessPoint::new(Bssid::parse("AA:BB:CC:DD:EE:01").unwrap(), "Weak", 6, 2437, -85, Encryption::Wpa2Personal, ts);
/// let strong = AccessPoint::new(Bssid::parse("AA:BB:CC:DD:EE:02").unwrap(), "Strong", 6, 2437, -40, Encryption::Wpa2Personal, ts);
/// let aps = [weak, strong];
/// let sorted = signal_map(&aps);
/// assert_eq!(sorted[0].ssid, "Strong");
/// ```
#[must_use]
pub fn signal_map(aps: &[AccessPoint]) -> Vec<&AccessPoint> {
    let mut sorted: Vec<&AccessPoint> = aps.iter().collect();
    sorted.sort_by(|a, b| b.signal_dbm.cmp(&a.signal_dbm));
    sorted
}

/// Return all unencrypted (open) access points.
///
/// Open networks have no encryption and are potential honeypots or
/// misconfigured corporate APs.
///
/// # Examples
///
/// ```
/// use thumos_sema::wifi::{AccessPoint, Bssid, Encryption};
/// use thumos_sema::wifi_analysis::open_networks;
/// use jiff::Timestamp;
///
/// let ts = Timestamp::UNIX_EPOCH;
/// let secured = AccessPoint::new(Bssid::parse("AA:BB:CC:DD:EE:01").unwrap(), "Safe", 6, 2437, -70, Encryption::Wpa2Personal, ts);
/// let open = AccessPoint::new(Bssid::parse("AA:BB:CC:DD:EE:02").unwrap(), "Free WiFi", 6, 2437, -60, Encryption::Open, ts);
/// let aps = [secured, open];
/// let result = open_networks(&aps);
/// assert_eq!(result.len(), 1);
/// assert_eq!(result[0].ssid, "Free WiFi");
/// ```
#[must_use]
pub fn open_networks(aps: &[AccessPoint]) -> Vec<&AccessPoint> {
    aps.iter()
        .filter(|ap| ap.encryption == Encryption::Open)
        .collect()
}

#[cfg(test)]
mod tests {
    use jiff::Timestamp;

    use super::*;
    use crate::wifi::{AccessPoint, Bssid, Encryption};

    fn ts() -> Timestamp {
        Timestamp::UNIX_EPOCH
    }

    fn ap(
        bssid: &str,
        ssid: &str,
        channel: u8,
        signal_dbm: i32,
        encryption: Encryption,
    ) -> Result<AccessPoint, crate::wifi::ParseError> {
        let freq = crate::wifi::channel_to_frequency(channel).unwrap_or(2437);
        Ok(AccessPoint::new(
            Bssid::parse(bssid)?,
            ssid,
            channel,
            freq,
            signal_dbm,
            encryption,
            ts(),
        ))
    }

    #[test]
    fn evil_twin_detected_when_same_ssid_different_bssid() -> Result<(), crate::wifi::ParseError> {
        let aps = [
            ap(
                "AA:BB:CC:DD:EE:01",
                "Corp",
                6,
                -65,
                Encryption::Wpa2Enterprise,
            )?,
            ap("AA:BB:CC:DD:EE:02", "Corp", 6, -40, Encryption::Open)?,
        ];
        let pairs = detect_evil_twin(&aps);
        assert_eq!(pairs.len(), 1, "one evil-twin pair should be detected");
        Ok(())
    }

    #[test]
    fn evil_twin_not_detected_when_same_ssid_same_bssid() -> Result<(), crate::wifi::ParseError> {
        let aps = [
            ap(
                "AA:BB:CC:DD:EE:01",
                "Corp",
                6,
                -65,
                Encryption::Wpa2Enterprise,
            )?,
            ap(
                "AA:BB:CC:DD:EE:01",
                "Corp",
                11,
                -70,
                Encryption::Wpa2Enterprise,
            )?,
        ];
        let pairs = detect_evil_twin(&aps);
        assert_eq!(
            pairs.len(),
            0,
            "same BSSID should not be flagged as evil twin"
        );
        Ok(())
    }

    #[test]
    fn evil_twin_not_detected_when_different_ssids() -> Result<(), crate::wifi::ParseError> {
        let aps = [
            ap(
                "AA:BB:CC:DD:EE:01",
                "NetworkA",
                6,
                -65,
                Encryption::Wpa2Personal,
            )?,
            ap(
                "AA:BB:CC:DD:EE:02",
                "NetworkB",
                6,
                -65,
                Encryption::Wpa2Personal,
            )?,
        ];
        let pairs = detect_evil_twin(&aps);
        assert_eq!(
            pairs.len(),
            0,
            "different SSIDs should not produce evil-twin pairs"
        );
        Ok(())
    }

    #[test]
    fn rogue_ap_detected_when_bssid_not_in_known_list() -> Result<(), crate::wifi::ParseError> {
        let aps = [ap(
            "FF:FF:FF:FF:FF:FF",
            "Corp",
            6,
            -70,
            Encryption::Wpa2Personal,
        )?];
        let known = [Bssid::parse("AA:BB:CC:DD:EE:01")?];
        let rogues = detect_rogue_ap(&aps, &known);
        assert_eq!(rogues.len(), 1, "unlisted BSSID should be flagged as rogue");
        Ok(())
    }

    #[test]
    fn rogue_ap_not_detected_when_bssid_in_known_list() -> Result<(), crate::wifi::ParseError> {
        let bssid = "AA:BB:CC:DD:EE:01";
        let aps = [ap(bssid, "Corp", 6, -70, Encryption::Wpa2Personal)?];
        let known = [Bssid::parse(bssid)?];
        let rogues = detect_rogue_ap(&aps, &known);
        assert_eq!(
            rogues.len(),
            0,
            "known BSSID should not be flagged as rogue"
        );
        Ok(())
    }

    #[test]
    fn channel_utilization_counts_aps_per_channel() -> Result<(), crate::wifi::ParseError> {
        let aps = [
            ap("AA:BB:CC:DD:EE:01", "A", 6, -70, Encryption::Wpa2Personal)?,
            ap("AA:BB:CC:DD:EE:02", "B", 6, -75, Encryption::Wpa2Personal)?,
            ap("AA:BB:CC:DD:EE:03", "C", 11, -80, Encryption::Open)?,
        ];
        let counts = channel_utilization(&aps);
        assert_eq!(counts[&6], 2, "channel 6 should have 2 APs");
        assert_eq!(counts[&11], 1, "channel 11 should have 1 AP");
        assert!(
            !counts.contains_key(&1),
            "channel 1 should not appear in results"
        );
        Ok(())
    }

    #[test]
    fn signal_map_returns_aps_sorted_strongest_first() -> Result<(), crate::wifi::ParseError> {
        let aps = [
            ap(
                "AA:BB:CC:DD:EE:01",
                "Weak",
                6,
                -85,
                Encryption::Wpa2Personal,
            )?,
            ap(
                "AA:BB:CC:DD:EE:02",
                "Strong",
                6,
                -40,
                Encryption::Wpa2Personal,
            )?,
            ap(
                "AA:BB:CC:DD:EE:03",
                "Medium",
                6,
                -65,
                Encryption::Wpa2Personal,
            )?,
        ];
        let sorted = signal_map(&aps);
        assert_eq!(sorted.len(), 3, "all APs should be in the result");
        assert_eq!(sorted[0].ssid, "Strong", "strongest AP should be first");
        assert_eq!(sorted[2].ssid, "Weak", "weakest AP should be last");
        Ok(())
    }

    #[test]
    fn open_networks_returns_only_unencrypted_aps() -> Result<(), crate::wifi::ParseError> {
        let aps = [
            ap(
                "AA:BB:CC:DD:EE:01",
                "Safe",
                6,
                -70,
                Encryption::Wpa2Personal,
            )?,
            ap("AA:BB:CC:DD:EE:02", "Free WiFi", 6, -60, Encryption::Open)?,
            ap(
                "AA:BB:CC:DD:EE:03",
                "Enterprise",
                6,
                -65,
                Encryption::Wpa2Enterprise,
            )?,
        ];
        let open = open_networks(&aps);
        assert_eq!(open.len(), 1, "only the open network should be returned");
        assert_eq!(
            open[0].ssid, "Free WiFi",
            "the open network SSID should match"
        );
        Ok(())
    }
}
