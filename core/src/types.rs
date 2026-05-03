use serde::{Deserialize, Serialize};

/// Parser-specific structured fields carried alongside a TimelineEvent.
/// Each variant matches exactly one artifact type; the event_to_dict function
/// in each parser module pattern-matches on this to emit typed Python fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventExtra {
    Mft      { mft_entry: u64 },
    Evtx     { event_id: u32, channel: String, level: u8 },
    Prefetch { exe_name: String, exe_path: String, run_count: u32, prefetch_hash: String, version: u32 },
    Lnk      { target_path: String, drive_type: u32, drive_serial: String, volume_label: String },
    Usn      { reasons: String, file_attributes: u32 },
    JumpList { target_path: String, destlist_version: Option<u32> },
}

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
    /// Parser-specific structured fields (typed, not JSON)
    pub extra: Option<EventExtra>,
}

impl TimelineEvent {
    pub fn timestamp_iso(&self) -> String {
        crate::utils::timestamps::ns_to_iso(self.timestamp_ns)
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
