use pyo3::prelude::*;
use pyo3::types::{PyList, PyDict};
use std::fs;
use std::time::UNIX_EPOCH;

/// Parse a PowerShell ConsoleHost_history.txt file.
/// Each non-empty, non-comment line is a command; all events share the file's mtime.
#[pyfunction]
pub fn parse_pshistory_file(py: Python<'_>, file_path: &str) -> PyResult<Py<PyList>> {
    let list = PyList::empty_bound(py);

    let meta = match fs::metadata(file_path) {
        Ok(m) => m,
        Err(_) => return Ok(list.into()),
    };

    let mtime_ns: i64 = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0);

    if mtime_ns == 0 {
        return Ok(list.into());
    }

    let content = match fs::read_to_string(file_path) {
        Ok(s) => s,
        Err(_) => {
            // Try lossy UTF-8 from raw bytes (file may have mixed encoding)
            match fs::read(file_path) {
                Ok(b) => String::from_utf8_lossy(&b).into_owned(),
                Err(_) => return Ok(list.into()),
            }
        }
    };

    let ts_iso = crate::utils::timestamps::ns_to_iso(mtime_ns);

    for line in content.lines() {
        let cmd = line.trim();
        if cmd.is_empty() || cmd.starts_with('#') {
            continue;
        }

        let d = PyDict::new_bound(py);
        d.set_item("timestamp_ns",    mtime_ns)?;
        d.set_item("timestamp_iso",   &ts_iso)?;
        d.set_item("macb",            "M")?;
        d.set_item("source",          "PSHISTORY")?;
        d.set_item("artifact",        "PowerShell History")?;
        d.set_item("file_path",       file_path)?;
        d.set_item("message",         cmd)?;
        d.set_item("is_fn_timestamp", false)?;
        d.set_item("tz_offset_secs",  0i32)?;
        list.append(d)?;
    }

    Ok(list.into())
}
