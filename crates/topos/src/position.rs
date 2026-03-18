//! Geographic position types.

/// A geographic coordinate with latitude, longitude, and optional altitude.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Position {
    /// Latitude in decimal degrees. Positive = North, negative = South.
    pub lat: f64,
    /// Longitude in decimal degrees. Positive = East, negative = West.
    pub lon: f64,
    /// Altitude above mean sea level in meters. None if not available.
    pub alt: Option<f64>,
}

/// GPS fix quality indicator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixQuality {
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
            0 => Self::NoFix,
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
pub struct Fix {
    /// Geographic position.
    pub position: Position,
    /// Fix quality.
    pub quality: FixQuality,
    /// Number of satellites in use.
    pub satellites: u8,
    /// Horizontal dilution of precision.
    pub hdop: Option<f64>,
    /// Speed over ground in knots.
    pub speed_knots: Option<f64>,
    /// Course over ground in degrees true.
    pub course: Option<f64>,
}
