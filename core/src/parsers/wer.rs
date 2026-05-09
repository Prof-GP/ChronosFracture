use pyo3::prelude::*;
use pyo3::types::{PyList, PyDict};
use std::fs;

use crate::types::filetime_to_unix_ns;

/// Parse a Windows Error Reporting .wer file (text key=value format).
/// Emits one event per file: crash timestamp, app name, event type.
#[pyfunction]
pub fn parse_wer_file(py: Python<'_>, file_path: &str) -> PyResult<Py<PyList>> {
    let list = PyList::empty_bound(py);

    let raw = match fs::read(file_path) {
        Ok(b) => b,
        Err(_) => return Ok(list.into()),
    };
    // WER files are UTF-16 LE with BOM (0xFF 0xFE) on modern Windows.
    let content = if raw.starts_with(&[0xFF, 0xFE]) {
        let u16_units: Vec<u16> = raw[2..]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&u16_units)
    } else {
        String::from_utf8_lossy(&raw).into_owned()
    };

    let mut event_time_ns: i64 = 0;
    let mut event_type    = String::new();
    let mut app_name      = String::new();
    let mut app_version   = String::new();

    for line in content.lines() {
        let line = line.trim_start_matches('\u{feff}').trim(); // strip UTF-8 BOM if present
        if let Some((key, val)) = line.split_once('=') {
            let key = key.trim();
            let val = val.trim();
            match key {
                "EventTime" => {
                    if let Ok(ft) = val.parse::<u64>() {
                        event_time_ns = filetime_to_unix_ns(ft);
                    }
                }
                "EventType" => {
                    event_type = val.to_owned();
                }
                // Sig[0].Value is typically the application name
                "Sig[0].Value" => {
                    if app_name.is_empty() {
                        app_name = val.to_owned();
                    }
                }
                // Sig[1].Value is typically the application version
                "Sig[1].Value" => {
                    if app_version.is_empty() {
                        app_version = val.to_owned();
                    }
                }
                _ => {}
            }
        }
    }

    if event_time_ns == 0 {
        return Ok(list.into());
    }

    let display_name = if !app_name.is_empty() {
        app_name.clone()
    } else {
        std::path::Path::new(file_path)
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_owned()
    };

    let mut msg_parts = vec![format!("Crash: {}", display_name)];
    if !event_type.is_empty() {
        msg_parts.push(format!("type={}", event_type));
    }
    if !app_version.is_empty() {
        msg_parts.push(format!("ver={}", app_version));
    }
    let message = msg_parts.join(" | ");

    let d = PyDict::new_bound(py);
    d.set_item("timestamp_ns",    event_time_ns)?;
    d.set_item("timestamp_iso",   crate::utils::timestamps::ns_to_iso(event_time_ns))?;
    d.set_item("macb",            "M")?;
    d.set_item("source",          "WER")?;
    d.set_item("artifact",        "WER Crash Report")?;
    d.set_item("file_path",       file_path)?;
    d.set_item("message",         message)?;
    d.set_item("is_fn_timestamp", false)?;
    d.set_item("tz_offset_secs",  0i32)?;
    list.append(d)?;

    Ok(list.into())
}
