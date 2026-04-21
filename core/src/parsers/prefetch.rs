use pyo3::prelude::*;
use pyo3::types::{PyList, PyDict};
use std::fs;
use std::path::Path;
use rayon::prelude::*;

use crate::types::{TimelineEvent, filetime_to_unix_ns};
use crate::utils::lzxpress;

// Prefetch version bytes — retained as named constants for format documentation
#[allow(dead_code)]
const PF_VERSION_V17: u8 = 0x11; // XP/2003
#[allow(dead_code)]
const PF_VERSION_V23: u8 = 0x17; // Vista/7
#[allow(dead_code)]
const PF_VERSION_V26: u8 = 0x1A; // Win8
#[allow(dead_code)]
const PF_VERSION_V30: u8 = 0x1E; // Win10

const MAM_MAGIC: &[u8; 4] = b"MAM\x04"; // Compressed prefetch (Win10)

fn read_u32_le(data: &[u8], off: usize) -> u32 {
    if off + 4 > data.len() { return 0; }
    u32::from_le_bytes([data[off], data[off+1], data[off+2], data[off+3]])
}

fn read_u64_le(data: &[u8], off: usize) -> u64 {
    if off + 8 > data.len() { return 0; }
    u64::from_le_bytes([
        data[off], data[off+1], data[off+2], data[off+3],
        data[off+4], data[off+5], data[off+6], data[off+7],
    ])
}

fn read_utf16_le(data: &[u8], off: usize, max_chars: usize) -> String {
    let mut units = Vec::new();
    let mut i = off;
    while i + 1 < data.len() && units.len() < max_chars {
        let c = u16::from_le_bytes([data[i], data[i+1]]);
        if c == 0 { break; }
        units.push(c);
        i += 2;
    }
    String::from_utf16_lossy(&units).to_string()
}

struct PrefetchRecord {
    exe_name: String,
    run_count: u32,
    last_run_times: Vec<u64>, // FILETIME values
    hash: u32,
    version: u8,
}

fn parse_prefetch_bytes(data: &[u8], _file_path: &str) -> Option<PrefetchRecord> {
    if data.len() < 84 {
        return None;
    }

    // MAM = compressed prefetch (Win10). Decompressor not yet implemented.
    if &data[0..4] == MAM_MAGIC {
        return None;
    }

    let version = data[0];

    // Exe name at offset 16 (UTF-16LE, up to 29 characters)
    let exe_name = read_utf16_le(data, 16, 29);
    if exe_name.is_empty() {
        return None;
    }

    let hash = read_u32_le(data, 76);
    // Run count offset is version-specific.
    // V30 (Win10) / V26 (Win8): 0xD0 (confirmed against windowsprefetch).
    // V23 (Vista/7): single run time at 0x78, run count follows at 0x90.
    // V17 (XP): run count at 0x90.
    let run_count = match version {
        0x1A | 0x1E => read_u32_le(data, 0xD0), // V26/V30
        _           => read_u32_le(data, 0x90),  // V17/V23 fallback
    };

    // Last run times depend on version:
    // V17 (XP): single timestamp at offset 80
    // V23 (7):  single timestamp at offset 0x78
    // V26 (8):  8 timestamps at offset 0x80
    // V30 (10): 8 timestamps at offset 0x80
    let mut last_run_times = Vec::new();

    match version {
        0x11 if data.len() > 80 => { // V17 - XP/2003
            last_run_times.push(read_u64_le(data, 80));
        }
        0x11 => {}
        0x17 if data.len() > 0x78 + 8 => { // V23 - Vista/7
            last_run_times.push(read_u64_le(data, 0x78));
        }
        0x17 => {}
        0x1A | 0x1E => { // V26/V30 - Win8/10 - up to 8 run times
            let base = if version == 0x1A { 0x80 } else { 0x80 };
            for i in 0..8usize {
                let off = base + i * 8;
                if off + 8 > data.len() { break; }
                let ft = read_u64_le(data, off);
                if ft > 0 {
                    last_run_times.push(ft);
                }
            }
        }
        _ => {}
    }

    Some(PrefetchRecord {
        exe_name,
        run_count,
        last_run_times,
        hash,
        version,
    })
}

fn events_from_record(rec: PrefetchRecord, path_str: &str) -> Vec<TimelineEvent> {
    rec.last_run_times.iter()
        .filter(|&&ft| ft > 0)
        .map(|&ft| TimelineEvent {
            timestamp_ns:    filetime_to_unix_ns(ft),
            macb:            "M".to_string(),
            source:          "PREFETCH".to_string(),
            artifact:        "Prefetch".to_string(),
            artifact_path:   path_str.to_string(),
            message:         format!("{} - Executed (run count: {})", rec.exe_name, rec.run_count),
            hostname:        None,
            tz_offset_secs:  0,
            is_fn_timestamp: false,
            source_hash:     None,
            extra:           Some(serde_json::json!({
                "exe_name":       rec.exe_name,
                "run_count":      rec.run_count,
                "prefetch_hash":  format!("{:08X}", rec.hash),
                "version":        rec.version,
            })),
        })
        .collect()
}

fn parse_single_prefetch(path: &Path) -> Vec<TimelineEvent> {
    let raw = match fs::read(path) {
        Ok(d) => d,
        Err(_) => return vec![],
    };

    let path_str = path.to_string_lossy().to_string();

    // Decompress MAM (Win10/11) using the native Rust LZXPRESS Huffman decoder.
    // This is fully cross-platform — no Windows API dependency.
    let data: Vec<u8>;
    let bytes: &[u8] = if raw.starts_with(b"MAM\x04") {
        match lzxpress::decompress_mam(&raw) {
            Ok(d)  => { data = d; &data }
            Err(e) => {
                log::warn!("MAM decompression failed for {}: {}", path_str, e);
                return vec![];
            }
        }
    } else {
        &raw
    };

    match parse_prefetch_bytes(bytes, &path_str) {
        Some(rec) => events_from_record(rec, &path_str),
        None      => vec![],
    }
}

/// Parse a single prefetch file from already-decompressed bytes.
/// Called by the Python wrapper after MAM decompression.
#[pyfunction]
pub fn parse_prefetch_bytes_decompressed(
    py: Python<'_>,
    data: &[u8],
    artifact_path: &str,
) -> PyResult<Py<PyList>> {
    let events = match parse_prefetch_bytes(data, artifact_path) {
        Some(rec) => events_from_record(rec, artifact_path),
        None      => vec![],
    };

    let list = PyList::empty_bound(py);
    for ev in &events {
        let dict = PyDict::new_bound(py);
        dict.set_item("timestamp_ns",    ev.timestamp_ns)?;
        dict.set_item("timestamp_iso",   ev.timestamp_iso())?;
        dict.set_item("macb",            &ev.macb)?;
        dict.set_item("source",          &ev.source)?;
        dict.set_item("artifact",        &ev.artifact)?;
        dict.set_item("artifact_path",   &ev.artifact_path)?;
        dict.set_item("message",         &ev.message)?;
        dict.set_item("is_fn_timestamp", ev.is_fn_timestamp)?;
        dict.set_item("tz_offset_secs",  ev.tz_offset_secs)?;
        if let Some(extra) = &ev.extra {
            dict.set_item("exe_name",   extra["exe_name"].as_str().unwrap_or(""))?;
            dict.set_item("run_count",  extra["run_count"].as_u64().unwrap_or(0))?;
        }
        list.append(dict)?;
    }
    Ok(list.into())
}

/// Parse all .pf files in a directory in parallel.
#[pyfunction]
pub fn parse_prefetch_dir(py: Python<'_>, dir_path: &str) -> PyResult<Py<PyList>> {
    let dir = Path::new(dir_path);

    let entries: Vec<_> = fs::read_dir(dir)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path().extension()
                .and_then(|x| x.to_str())
                .map(|x| x.eq_ignore_ascii_case("pf"))
                .unwrap_or(false)
        })
        .map(|e| e.path())
        .collect();

    let all_events: Vec<TimelineEvent> = entries
        .par_iter()
        .flat_map(|p| parse_single_prefetch(p))
        .collect();

    let list = PyList::empty_bound(py);
    for ev in &all_events {
        let dict = PyDict::new_bound(py);
        dict.set_item("timestamp_ns", ev.timestamp_ns)?;
        dict.set_item("timestamp_iso", ev.timestamp_iso())?;
        dict.set_item("macb", &ev.macb)?;
        dict.set_item("source", &ev.source)?;
        dict.set_item("artifact", &ev.artifact)?;
        dict.set_item("artifact_path", &ev.artifact_path)?;
        dict.set_item("message", &ev.message)?;
        dict.set_item("is_fn_timestamp", ev.is_fn_timestamp)?;
        dict.set_item("tz_offset_secs", ev.tz_offset_secs)?;
        if let Some(extra) = &ev.extra {
            dict.set_item("exe_name", extra["exe_name"].as_str().unwrap_or(""))?;
            dict.set_item("run_count", extra["run_count"].as_u64().unwrap_or(0))?;
        }
        list.append(dict)?;
    }

    Ok(list.into())
}

#[pyclass]
pub struct PrefetchParser {
    dir_path: String,
}

#[pymethods]
impl PrefetchParser {
    #[new]
    pub fn new(dir_path: &str) -> Self {
        PrefetchParser { dir_path: dir_path.to_string() }
    }

    pub fn parse<'py>(&self, py: Python<'py>) -> PyResult<Py<PyList>> {
        parse_prefetch_dir(py, &self.dir_path)
    }
}
