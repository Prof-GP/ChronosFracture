use pyo3::prelude::*;
use pyo3::types::{PyList, PyDict};
use memmap2::Mmap;
use rayon::prelude::*;
use std::fs::File;

use crate::types::{TimelineEvent, filetime_to_unix_ns};

// USN_RECORD_V2 minimum size
const USN_RECORD_MIN_SIZE: usize = 60;

// USN reason flags
const USN_REASON_DATA_OVERWRITE:     u32 = 0x00000001;
const USN_REASON_DATA_EXTEND:        u32 = 0x00000002;
const USN_REASON_DATA_TRUNCATION:    u32 = 0x00000004;
const USN_REASON_NAMED_DATA_OVERWRITE: u32 = 0x00000010;
const USN_REASON_FILE_CREATE:        u32 = 0x00000100;
const USN_REASON_FILE_DELETE:        u32 = 0x00000200;
const USN_REASON_EA_CHANGE:          u32 = 0x00000400;
const USN_REASON_SECURITY_CHANGE:    u32 = 0x00000800;
const USN_REASON_RENAME_OLD_NAME:    u32 = 0x00001000;
const USN_REASON_RENAME_NEW_NAME:    u32 = 0x00002000;
const USN_REASON_BASIC_INFO_CHANGE:  u32 = 0x00008000;
const USN_REASON_HARD_LINK_CHANGE:   u32 = 0x00010000;
const USN_REASON_COMPRESSION_CHANGE: u32 = 0x00020000;
const USN_REASON_ENCRYPTION_CHANGE:  u32 = 0x00040000;
const USN_REASON_OBJECT_ID_CHANGE:   u32 = 0x00080000;
const USN_REASON_REPARSE_POINT_CHANGE: u32 = 0x00100000;
const USN_REASON_STREAM_CHANGE:      u32 = 0x00200000;
const USN_REASON_CLOSE:              u32 = 0x80000000;

fn reasons_to_string(reasons: u32) -> String {
    let mut parts = Vec::new();
    if reasons & USN_REASON_FILE_CREATE != 0     { parts.push("FILE_CREATE"); }
    if reasons & USN_REASON_FILE_DELETE != 0     { parts.push("FILE_DELETE"); }
    if reasons & USN_REASON_DATA_OVERWRITE != 0  { parts.push("DATA_OVERWRITE"); }
    if reasons & USN_REASON_DATA_EXTEND != 0     { parts.push("DATA_EXTEND"); }
    if reasons & USN_REASON_DATA_TRUNCATION != 0 { parts.push("DATA_TRUNCATION"); }
    if reasons & USN_REASON_RENAME_OLD_NAME != 0 { parts.push("RENAME_OLD"); }
    if reasons & USN_REASON_RENAME_NEW_NAME != 0 { parts.push("RENAME_NEW"); }
    if reasons & USN_REASON_SECURITY_CHANGE != 0 { parts.push("SECURITY_CHANGE"); }
    if reasons & USN_REASON_BASIC_INFO_CHANGE != 0 { parts.push("BASIC_INFO_CHANGE"); }
    if reasons & USN_REASON_CLOSE != 0           { parts.push("CLOSE"); }
    if parts.is_empty() {
        format!("0x{:08X}", reasons)
    } else {
        parts.join("|")
    }
}

fn read_u16_le(data: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([data[off], data[off+1]])
}

fn read_u32_le(data: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([data[off], data[off+1], data[off+2], data[off+3]])
}

fn read_u64_le(data: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        data[off], data[off+1], data[off+2], data[off+3],
        data[off+4], data[off+5], data[off+6], data[off+7],
    ])
}

/// Scan a buffer for USN V2 records.
/// Returns a Vec of (TimelineEvent, file_name) pairs so callers can emit file_path.
fn scan_usn_records(data: &[u8], artifact_path: &str) -> Vec<(TimelineEvent, String)> {
    let mut events = Vec::new();
    let mut offset = 0usize;

    while offset + USN_RECORD_MIN_SIZE <= data.len() {
        let rec_len = read_u32_le(data, offset) as usize;

        // Skip zero padding blocks between USN records
        if rec_len == 0 {
            offset += 8;
            continue;
        }

        if rec_len < USN_RECORD_MIN_SIZE || offset + rec_len > data.len() {
            offset += 8;
            continue;
        }

        let major_ver = read_u16_le(data, offset + 4);
        if major_ver != 2 {
            offset += if rec_len > 0 { rec_len } else { 8 };
            continue;
        }

        let timestamp  = read_u64_le(data, offset + 8);
        let reasons    = read_u32_le(data, offset + 40);
        let file_attrs = read_u32_le(data, offset + 52);
        let name_len   = read_u16_le(data, offset + 56) as usize;
        let name_off   = read_u16_le(data, offset + 58) as usize;

        let file_name = if name_off + name_len <= rec_len && offset + name_off + name_len <= data.len() {
            let name_bytes = &data[offset + name_off .. offset + name_off + name_len];
            let utf16: Vec<u16> = name_bytes.chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            String::from_utf16_lossy(&utf16).to_string()
        } else {
            String::from("<unknown>")
        };

        let is_dir = (file_attrs & 0x10) != 0;
        let kind = if is_dir { "Directory" } else { "File" };
        let reason_str = reasons_to_string(reasons);

        events.push((
            TimelineEvent {
                timestamp_ns: filetime_to_unix_ns(timestamp),
                macb: "M".to_string(),
                source: "$UsnJrnl:$J".to_string(),
                artifact: "$UsnJrnl".to_string(),
                artifact_path: artifact_path.to_string(),
                message: format!("{} {} - {}", kind, file_name, reason_str),
                hostname: None,
                tz_offset_secs: 0,
                is_fn_timestamp: false,
                source_hash: None,
                extra: Some(crate::types::EventExtra::Usn {
                    reasons:         reason_str.to_string(),
                    file_attributes: file_attrs,
                }),
            },
            file_name,
        ));

        offset += rec_len;
    }

    events
}

#[pyfunction]
pub fn parse_usnjrnl_file(py: Python<'_>, path: &str) -> PyResult<Py<PyList>> {
    let file = File::open(path)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;

    let mmap = unsafe { Mmap::map(&file) }
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;

    // Split into 64MB chunks and process in parallel
    let chunk_size = 64 * 1024 * 1024usize;
    let data: &[u8] = &mmap;

    let all_events: Vec<(TimelineEvent, String)> = data
        .par_chunks(chunk_size)
        .flat_map(|chunk| scan_usn_records(chunk, path))
        .collect();

    let list = PyList::empty_bound(py);
    for (ev, file_name) in &all_events {
        let dict = PyDict::new_bound(py);
        dict.set_item("timestamp_ns", ev.timestamp_ns)?;
        dict.set_item("timestamp_iso", ev.timestamp_iso())?;
        dict.set_item("macb", &ev.macb)?;
        dict.set_item("source", &ev.source)?;
        dict.set_item("artifact", &ev.artifact)?;
        dict.set_item("artifact_path", &ev.artifact_path)?;
        dict.set_item("file_path", file_name.as_str())?;
        dict.set_item("message", &ev.message)?;
        dict.set_item("is_fn_timestamp", ev.is_fn_timestamp)?;
        dict.set_item("tz_offset_secs", ev.tz_offset_secs)?;
        list.append(dict)?;
    }

    Ok(list.into())
}

#[pyclass]
pub struct UsnJrnlParser {
    path: String,
}

#[pymethods]
impl UsnJrnlParser {
    #[new]
    pub fn new(path: &str) -> Self {
        UsnJrnlParser { path: path.to_string() }
    }

    pub fn parse<'py>(&self, py: Python<'py>) -> PyResult<Py<PyList>> {
        parse_usnjrnl_file(py, &self.path)
    }
}
