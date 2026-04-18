use serde::{Deserialize, Serialize};

/// A single forensic timestamp event — the atomic unit of a super timeline.
/// All timestamps are UTC nanoseconds since Unix epoch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    /// UTC timestamp in nanoseconds since Unix epoch
    pub timestamp_ns: i64,
    /// MACB flags: M=Modified, A=Accessed, C=Changed($SI), B=Born(created)
    pub macb: String,
    /// Parser/source that produced this event
    pub source: String,
    /// Artifact type (e.g. "$MFT", "EVTX", "PREFETCH")
    pub artifact: String,
    /// Full file path or key path of the artifact
    pub artifact_path: String,
    /// Human-readable description of the event
    pub message: String,
    /// Hostname extracted from the source (if available)
    pub hostname: Option<String>,
    /// Source timezone offset in seconds (0 = UTC)
    pub tz_offset_secs: i32,
    /// Whether this timestamp came from $FILE_NAME (vs $STANDARD_INFORMATION)
    /// Used for timestomp detection
    pub is_fn_timestamp: bool,
    /// SHA-256 of the source artifact block (for integrity)
    pub source_hash: Option<String>,
    /// Extra structured fields (event ID, username, SID, etc.)
    pub extra: Option<serde_json::Value>,
}

impl TimelineEvent {
    pub fn timestamp_iso(&self) -> String {
        use chrono::{Utc, TimeZone};
        let secs = self.timestamp_ns / 1_000_000_000;
        let nanos = (self.timestamp_ns % 1_000_000_000) as u32;
        match Utc.timestamp_opt(secs, nanos) {
            chrono::LocalResult::Single(dt) => dt.format("%Y-%m-%dT%H:%M:%S%.9fZ").to_string(),
            _ => "1601-01-01T00:00:00.000000000Z".to_string(),
        }
    }
}

/// FILETIME (Windows) to nanoseconds since Unix epoch
/// FILETIME = 100-nanosecond intervals since 1601-01-01
pub fn filetime_to_unix_ns(filetime: u64) -> i64 {
    // 116444736000000000 = number of 100-ns intervals between 1601 and 1970
    const EPOCH_DIFF_100NS: u64 = 116_444_736_000_000_000;
    if filetime < EPOCH_DIFF_100NS {
        return 0;
    }
    // Convert 100-ns intervals to nanoseconds
    ((filetime - EPOCH_DIFF_100NS) * 100) as i64
}

/// POSIX timestamp (seconds) to nanoseconds since Unix epoch
pub fn unix_secs_to_ns(secs: i64) -> i64 {
    secs * 1_000_000_000
}
