use chrono::{Utc, TimeZone};

/// Trim trailing zeros from the fractional seconds portion of an ISO timestamp.
/// "2024-01-01T12:00:00.000000000Z" → "2024-01-01T12:00:00Z"
/// "2024-01-01T12:00:00.123456700Z" → "2024-01-01T12:00:00.1234567Z"
pub fn trim_iso_nanos(s: String) -> String {
    if let Some(dot) = s.find('.') {
        let (before, from_dot) = s.split_at(dot);
        let frac = from_dot[1..from_dot.len() - 1].trim_end_matches('0'); // strip dot and trailing Z
        if frac.is_empty() {
            format!("{}Z", before)
        } else {
            format!("{}.{}Z", before, frac)
        }
    } else {
        s
    }
}

pub fn ns_to_iso(ns: i64) -> String {
    let secs = ns / 1_000_000_000;
    let nanos = (ns % 1_000_000_000).unsigned_abs() as u32;
    match Utc.timestamp_opt(secs, nanos) {
        chrono::LocalResult::Single(dt) => {
            trim_iso_nanos(dt.format("%Y-%m-%dT%H:%M:%S%.9fZ").to_string())
        }
        _ => "1601-01-01T00:00:00Z".to_string(),
    }
}
