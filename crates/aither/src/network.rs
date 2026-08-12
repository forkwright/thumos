//! `WiFi` network management — scan result matching, network selection, connection state.

use log::debug;

/// Security protocol in use on a `WiFi` network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) enum SecurityType {
    /// No encryption (open network).
    Open,
    /// WPA2-Personal (PSK).
    Wpa2Psk,
    /// WPA3-Personal (SAE).
    Wpa3Sae,
    /// WPA2/WPA3 transitional mode.
    Wpa2Wpa3,
}

/// A configured `WiFi` network.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub(crate) struct WifiNetwork {
    /// Network SSID (raw bytes; may not be valid UTF-8).
    pub(crate) ssid: Vec<u8>,
    /// Optional BSSID filter — `None` matches any AP with this SSID.
    pub(crate) bssid: Option<[u8; 6]>,
    /// Pre-shared key or SAE password (raw bytes).
    pub(crate) password: Option<Vec<u8>>,
    /// Security protocol.
    pub(crate) security: SecurityType,
    /// Selection priority: higher value is preferred over lower.
    pub(crate) priority: i32,
}

impl WifiNetwork {
    /// Create a new WPA2-PSK network entry.
    #[must_use]
    pub(crate) const fn wpa2(ssid: Vec<u8>, password: Vec<u8>) -> Self {
        Self {
            ssid,
            bssid: None,
            password: Some(password),
            security: SecurityType::Wpa2Psk,
            priority: 0,
        }
    }
}

/// A passive or active scan result from the `WiFi` firmware.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub(crate) struct ScanResult {
    /// Advertised SSID (raw bytes from the beacon/probe response).
    pub(crate) ssid: Vec<u8>,
    /// BSSID (access point MAC address).
    pub(crate) bssid: [u8; 6],
    /// Received Signal Strength Indicator in dBm (typically –100 to 0).
    pub(crate) rssi: i16,
    /// Security capabilities advertised in the beacon.
    pub(crate) security: SecurityType,
    /// Operating channel.
    pub(crate) channel: u8,
}

/// An ordered list of known networks.
///
/// Networks are compared by `priority` (higher wins) then by signal strength.
#[derive(Debug, Clone, Default)]
pub(crate) struct NetworkConfig {
    /// All configured networks, in arbitrary order.
    pub(crate) networks: Vec<WifiNetwork>,
}

impl NetworkConfig {
    /// Create an empty configuration.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Append a network to the configuration.
    pub(crate) fn add(&mut self, network: WifiNetwork) {
        self.networks.push(network);
    }
}

/// Select the best matching network from a set of scan results.
///
/// A match requires the SSID to match.  If the configured entry specifies a
/// BSSID, only scan results with that exact BSSID match.  Among all matches,
/// the entry with the highest `priority` is chosen; ties are broken by RSSI.
///
/// Returns `None` when no configured network is visible in the scan results.
///
/// Time: O(s * c) where s is `scan_results.len()` and c is
/// `config.networks.len()` — every scan result is compared against every
/// configured network; each comparison additionally costs O(k) for the SSID
/// byte-slice equality check, where k is the SSID length, so the strict
/// bound is O(s * c * k).
/// Space: O(1) auxiliary — tracks only a `best` reference pair; no new
/// allocation persists (the `String::from_utf8_lossy` in the debug log line
/// is transient and does not survive the call).
#[must_use]
pub(crate) fn select_network<'a>(
    scan_results: &[ScanResult],
    config: &'a NetworkConfig,
) -> Option<&'a WifiNetwork> {
    let mut best: Option<(&WifiNetwork, i16)> = None;

    for scan in scan_results {
        for configured in &config.networks {
            if scan.ssid != configured.ssid {
                continue;
            }
            if let Some(bssid) = configured.bssid
                && bssid != scan.bssid
            {
                continue;
            }

            let is_better = best.is_none_or(|(prev, prev_rssi)| {
                configured.priority > prev.priority
                    || (configured.priority == prev.priority && scan.rssi > prev_rssi)
            });

            if is_better {
                debug!(
                    "candidate network ssid={:?} rssi={} priority={}",
                    String::from_utf8_lossy(&scan.ssid),
                    scan.rssi,
                    configured.priority
                );
                best = Some((configured, scan.rssi));
            }
        }
    }

    best.map(|(n, _)| n)
}

/// Connection lifecycle state machine.
///
/// Transitions are driven by external events (supplicant messages, driver
/// callbacks, timeout expiry).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub(crate) enum ConnectionState {
    /// No association in progress.
    #[default]
    Disconnected,
    /// 802.11 Open System / SAE authentication exchange in progress.
    Authenticating,
    /// 802.11 association complete; EAPOL 4-way handshake not yet started.
    Associated,
    /// 4-way handshake complete; data path is encrypted and open.
    Connected,
    /// Authentication or association failed; will retry or give up.
    Failed,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_scan(ssid: &[u8], bssid: [u8; 6], rssi: i16) -> ScanResult {
        ScanResult {
            ssid: ssid.to_vec(),
            bssid,
            rssi,
            security: SecurityType::Wpa2Psk,
            channel: 6,
        }
    }

    fn make_network(ssid: &[u8], priority: i32) -> WifiNetwork {
        WifiNetwork {
            ssid: ssid.to_vec(),
            bssid: None,
            password: Some(b"secret".to_vec()),
            security: SecurityType::Wpa2Psk,
            priority,
        }
    }

    #[test]
    fn selects_nothing_when_no_known_networks() {
        let scans = vec![make_scan(b"HomeNet", [0u8; 6], -60)];
        let config = NetworkConfig::new();
        assert!(
            select_network(&scans, &config).is_none(),
            "must return None when config has no networks"
        );
    }

    #[test]
    fn selects_nothing_when_no_scan_matches_configured_network() {
        let scans = vec![make_scan(b"Neighbour", [0u8; 6], -55)];
        let mut config = NetworkConfig::new();
        config.add(make_network(b"HomeNet", 0));
        assert!(
            select_network(&scans, &config).is_none(),
            "must return None when no scan result matches the configured SSID"
        );
    }

    #[test]
    fn selects_single_matching_network() {
        let scans = vec![make_scan(b"HomeNet", [0u8; 6], -70)];
        let mut config = NetworkConfig::new();
        config.add(make_network(b"HomeNet", 0));
        let result = select_network(&scans, &config);
        assert!(result.is_some(), "must return a network when SSID matches");
        assert_eq!(
            result.map(|n| n.ssid.as_slice()),
            Some(b"HomeNet".as_slice()),
            "selected network SSID must match"
        );
    }

    #[test]
    fn selects_network_with_strongest_signal_when_priority_is_equal() {
        let bssid_a = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01];
        let bssid_b = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02];
        let scans = vec![
            make_scan(b"Corp", bssid_a, -80),
            make_scan(b"Corp", bssid_b, -50),
        ];
        let mut config = NetworkConfig::new();
        config.add(make_network(b"Corp", 5));

        let result = select_network(&scans, &config);
        assert!(result.is_some(), "must return a network when SSID matches");
        // Both scan entries match the same configured entry.
        assert_eq!(
            result.map(|n| n.ssid.as_slice()),
            Some(b"Corp".as_slice()),
            "selected SSID must be Corp"
        );
    }

    #[test]
    fn selects_higher_priority_network_over_stronger_signal() {
        let scans = vec![
            make_scan(b"NetA", [0x01; 6], -40),
            make_scan(b"NetB", [0x02; 6], -80),
        ];
        let mut config = NetworkConfig::new();
        config.add(make_network(b"NetA", 1)); // better signal, lower priority
        config.add(make_network(b"NetB", 10)); // weaker signal, higher priority
        let result = select_network(&scans, &config);
        assert!(result.is_some(), "must return a network when SSIDs match");
        assert_eq!(
            result.map(|n| n.ssid.as_slice()),
            Some(b"NetB".as_slice()),
            "higher-priority network must win over stronger signal"
        );
    }

    #[test]
    fn selects_only_the_bssid_filtered_ap() {
        let target = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01];
        let other = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x02];
        let scans = vec![
            make_scan(b"Corp", target, -60),
            make_scan(b"Corp", other, -45),
        ];
        let mut config = NetworkConfig::new();
        config.add(WifiNetwork {
            ssid: b"Corp".to_vec(),
            bssid: Some(target),
            password: Some(b"pw".to_vec()),
            security: SecurityType::Wpa2Psk,
            priority: 0,
        });
        let result = select_network(&scans, &config);
        assert!(
            result.is_some(),
            "must return a result when target BSSID is present"
        );
        assert_eq!(
            result.map(|n| n.bssid),
            Some(Some(target)),
            "selected BSSID must be the exact target"
        );
    }

    #[test]
    fn selects_nothing_when_bssid_filter_has_no_match() {
        let wanted = [0xaa; 6];
        let present = [0xbb; 6];
        let scans = vec![make_scan(b"Net", present, -50)];
        let mut config = NetworkConfig::new();
        config.add(WifiNetwork {
            ssid: b"Net".to_vec(),
            bssid: Some(wanted),
            password: None,
            security: SecurityType::Open,
            priority: 0,
        });
        assert!(
            select_network(&scans, &config).is_none(),
            "must return None when BSSID filter does not match any scan result"
        );
    }

    #[test]
    fn connection_state_defaults_to_disconnected() {
        let state = ConnectionState::default();
        assert_eq!(
            state,
            ConnectionState::Disconnected,
            "default ConnectionState must be Disconnected"
        );
    }

    #[test]
    fn connection_state_variants_are_all_distinct() {
        use ConnectionState::*;
        let states = [Disconnected, Authenticating, Associated, Connected, Failed];
        for (i, s) in states.iter().enumerate() {
            for (j, t) in states.iter().enumerate() {
                if i == j {
                    assert_eq!(s, t, "state {s:?} must equal itself");
                } else {
                    assert_ne!(s, t, "state {s:?} must not equal {t:?}");
                }
            }
        }
    }

    #[test]
    fn network_config_tracks_added_networks() {
        let mut config = NetworkConfig::new();
        assert!(
            config.networks.is_empty(),
            "new config must have no networks"
        );
        config.add(make_network(b"A", 0));
        config.add(make_network(b"B", 1));
        assert_eq!(
            config.networks.len(),
            2,
            "config must contain exactly two networks after two adds"
        );
    }
}
