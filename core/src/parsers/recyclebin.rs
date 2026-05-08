use pyo3::prelude::*;
use pyo3::types::{PyList, PyDict};
use std::fs;
use std::path::Path;
use rayon::prelude::*;

use crate::types::filetime_to_unix_ns;
use super::read_helpers::{r_u64, r_u32, r_utf16_null};

/// Parse a single $I file's bytes.
/// Returns (deletion_time_ns, original_path, file_size_bytes) on success.
fn parse_i_bytes(data: &[u8]) -> Option<(i64, String, u64)> {
    if data.len() < 24 { return None; }
    let version     = r_u64(data, 0);
    let file_size   = r_u64(data, 8);
    let deletion_ft = r_u64(data, 16);
    if deletion_ft == 0 { return None; }
    let ns = filetime_to_unix_ns(deletion_ft);
    if ns == 0 { return None; }

    let orig_path = match version {
        1 => {
            // Vista/7: fixed 520-byte (260 char) UTF-16LE path at offset 24
            if data.len() < 26 { return None; }
            r_utf16_null(data, 24)
        }
        2 => {
            // Win8+: path_char_count (u32) at offset 24, path starts at offset 28
            if data.len() < 28 { return None; }
            let chars = r_u32(data, 24) as usize;
            if chars == 0 || data.len() < 28 + chars.saturating_mul(2) { return None; }
            r_utf16_null(data, 28)
        }
        _ => return None,
    };

    if orig_path.is_empty() { return None; }
    Some((ns, orig_path, file_size))
}

fn collect_i_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else { return; };
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_dir() {
            collect_i_files(&p, out);
        } else if p.file_name()
            .and_then(|n| n.to_str())
            .map(|n| n.len() > 2 && n[..2].eq_ignore_ascii_case("$I"))
            .unwrap_or(false)
        {
            out.push(p);
        }
    }
}

fn fmt_size(bytes: u64) -> String {
    match bytes {
        b if b >= 1_073_741_824 => format!("{:.1} GB", b as f64 / 1_073_741_824.0),
        b if b >= 1_048_576     => format!("{:.1} MB", b as f64 / 1_048_576.0),
        b if b >= 1_024         => format!("{} KB", b / 1_024),
        b                       => format!("{} bytes", b),
    }
}

/// Parse all $I* files found under a $Recycle.Bin directory (recursively).
/// Handles both Vista/7 (version 1) and Win8+ (version 2) formats.
#[pyfunction]
pub fn parse_recyclebin_dir(py: Python<'_>, dir_path: &str) -> PyResult<Py<PyList>> {
    let mut i_files = Vec::new();
    collect_i_files(Path::new(dir_path), &mut i_files);

    let results: Vec<(i64, String, u64)> = i_files
        .par_iter()
        .filter_map(|p| {
            let data = fs::read(p).ok()?;
            parse_i_bytes(&data)
        })
        .collect();

    let list = PyList::empty_bound(py);
    for (ns, orig_path, file_size) in results {
        let message = format!("Deleted: {} ({})", orig_path, fmt_size(file_size));
        let d = PyDict::new_bound(py);
        d.set_item("timestamp_ns",    ns)?;
        d.set_item("timestamp_iso",   crate::utils::timestamps::ns_to_iso(ns))?;
        d.set_item("macb",            "M")?;
        d.set_item("source",          "RECYCLEBIN")?;
        d.set_item("artifact",        "Recycle Bin")?;
        d.set_item("file_path",       &orig_path)?;
        d.set_item("message",         message)?;
        d.set_item("is_fn_timestamp", false)?;
        d.set_item("tz_offset_secs",  0i32)?;
        list.append(d)?;
    }

    Ok(list.into())
}
