use chrono::{Utc, TimeZone};

pub fn ns_to_iso(ns: i64) -> String {
    let secs = ns / 1_000_000_000;
    let nanos = (ns % 1_000_000_000).unsigned_abs() as u32;
    match Utc.timestamp_opt(secs, nanos) {
        chrono::LocalResult::Single(dt) => dt.format("%Y-%m-%dT%H:%M:%S%.9fZ").to_string(),
        _ => "1601-01-01T00:00:00.000000000Z".to_string(),
    }
}
