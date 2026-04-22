//! Geographic position types.

/// A geographic coordinate with latitude, longitude, and optional altitude.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Position {
    /// Latitude in decimal degrees. Positive = North, negative = South.
    pub(crate) lat: f64,
    /// Longitude in decimal degrees. Positive = East, negative = West.
    pub(crate) lon: f64,
    /// Altitude above mean sea level in meters. None if not available.
    pub(crate) alt: Option<f64>,
}

/// GPS fix quality indicator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) enum FixQuality {
    /// No fix.
    NoFix,
    /// Standard GPS fix.
    Gps,
    /// Differential GPS fix.
    Dgps,
    /// PPS fix.
    Pps,
    /// Real-Time Kinematic.
    Rtk,
    /// Float RTK.
    FloatRtk,
    /// Estimated (dead reckoning).
    Estimated,
    /// Manual input mode.
    Manual,
    /// Simulation mode.
    Simulation,
}

impl From<u8> for FixQuality {
    fn from(val: u8) -> Self {
        match val {
            1 => Self::Gps,
            2 => Self::Dgps,
            3 => Self::Pps,
            4 => Self::Rtk,
            5 => Self::FloatRtk,
            6 => Self::Estimated,
            7 => Self::Manual,
            8 => Self::Simulation,
            _ => Self::NoFix,
        }
    }
}

/// A complete GPS fix with position, quality, and satellite info.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Fix {
    /// Geographic position.
    pub(crate) position: Position,
    /// Fix quality.
    pub(crate) quality: FixQuality,
    /// Number of satellites in use.
    pub(crate) satellites: u8,
    /// Horizontal dilution of precision.
    pub(crate) hdop: Option<f64>,
    /// Speed over ground in knots.
    pub(crate) speed_knots: Option<f64>,
    /// Course over ground in degrees true.
    pub(crate) course: Option<f64>,
}
