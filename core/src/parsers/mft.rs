use pyo3::prelude::*;
use pyo3::types::PyList;
use memmap2::Mmap;
use rayon::prelude::*;
use std::fs::File;

use crate::types::{TimelineEvent, filetime_to_unix_ns};

// MFT entry is always 1024 bytes on standard NTFS volumes
const MFT_ENTRY_SIZE: usize = 1024;
const MFT_SIGNATURE: &[u8; 4] = b"FILE";

// Attribute type codes
const ATTR_STANDARD_INFORMATION: u32 = 0x10;
const ATTR_FILE_NAME: u32 = 0x30;
const ATTR_END: u32 = 0xFFFFFFFF;

// MFT entry flags
const FLAG_IN_USE: u16 = 0x01;
const FLAG_IS_DIRECTORY: u16 = 0x02;

#[repr(C, packed)]
#[derive(Copy, Clone)]
struct MftEntryHeader {
    signature: [u8; 4],        // "FILE"
    _fixup_offset: u16,
    _fixup_count: u16,
    _log_seq_num: u64,
    _sequence_num: u16,
    _hard_link_count: u16,
    attr_offset: u16,          // offset to first attribute
    flags: u16,                // 0x01=in use, 0x02=directory
    _used_size: u32,
    _alloc_size: u32,
    _base_record: u64,
    _next_attr_id: u16,
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
struct AttrHeader {
    attr_type: u32,
    attr_len: u32,
    non_resident: u8,
    name_len: u8,
    name_offset: u16,
    _flags: u16,
    _attr_id: u16,
    // resident only:
    content_len: u32,
    content_offset: u16,
}

/// $STANDARD_INFORMATION timestamps (always resident, always present)
#[repr(C, packed)]
#[derive(Copy, Clone)]
struct StandardInformation {
    created: u64,
    modified: u64,
    mft_modified: u64,
    accessed: u64,
}

/// $FILE_NAME timestamps + name (always resident)
#[repr(C, packed)]
#[derive(Copy, Clone)]
struct FileNameAttr {
    parent_ref: u64,
    created: u64,
    modified: u64,
    mft_modified: u64,
    accessed: u64,
    alloc_size: u64,
    real_size: u64,
    flags: u32,
    _reparse: u32,
    name_len: u8,    // in UTF-16 code units
    _namespace: u8,
}

fn read_u16_le(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

fn read_u32_le(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
}

fn read_u64_le(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        data[offset], data[offset+1], data[offset+2], data[offset+3],
        data[offset+4], data[offset+5], data[offset+6], data[offset+7],
    ])
}

fn parse_utf16_name(data: &[u8], offset: usize, len_units: usize) -> String {
    let byte_len = len_units * 2;
    if offset + byte_len > data.len() {
        return String::from("<invalid name>");
    }
    let utf16: Vec<u16> = (0..len_units)
        .map(|i| read_u16_le(data, offset + i * 2))
        .collect();
    String::from_utf16_lossy(&utf16).to_string()
}

/// Group four MACB timestamps into deduplicated events.
/// Timestamps with the same nanosecond value are merged into one event with
/// combined MACB flags (e.g. "MACB", "M.C.", ".A.B") instead of four separate rows.
fn build_macb_events(
    timestamps: [u64; 4], // [created, modified, mft_mod, accessed]
    artifact_path: &str,
    source: &str,
    artifact: &str,
    file_name: &str,
    entry_index: u64,
    is_fn: bool,
) -> Vec<TimelineEvent> {
    // flag indices: 0=M(modified), 1=A(accessed), 2=C(mft_mod), 3=B(created)
    let flag_map = [
        (timestamps[0], 3usize), // created  → B
        (timestamps[1], 0usize), // modified → M
        (timestamps[2], 2usize), // mft_mod  → C
        (timestamps[3], 1usize), // accessed → A
    ];

    let mut groups: std::collections::HashMap<i64, [bool; 4]> = std::collections::HashMap::new();
    for (ft, flag_idx) in &flag_map {
        let ns = filetime_to_unix_ns(*ft);
        if ns <= 0 {
            continue;
        }
        groups.entry(ns).or_insert([false; 4])[*flag_idx] = true;
    }

    let mut sorted_ns: Vec<i64> = groups.keys().cloned().collect();
    sorted_ns.sort_unstable();

    sorted_ns
        .into_iter()
        .map(|ns| {
            let f = groups[&ns];
            let macb = format!(
                "{}{}{}{}",
                if f[0] { 'M' } else { '.' },
                if f[1] { 'A' } else { '.' },
                if f[2] { 'C' } else { '.' },
                if f[3] { 'B' } else { '.' },
            );
            TimelineEvent {
                timestamp_ns: ns,
                macb,
                source: source.to_string(),
                artifact: artifact.to_string(),
                artifact_path: artifact_path.to_string(),
                message: file_name.to_string(),
                hostname: None,
                tz_offset_secs: 0,
                is_fn_timestamp: is_fn,
                source_hash: None,
                extra: Some(serde_json::json!({ "mft_entry": entry_index })),
            }
        })
        .collect()
}

/// Parse a single MFT entry (1024 bytes), returning 0–8 timeline events.
/// Returns None if the entry is not in use or has no valid signature.
fn parse_mft_entry(entry: &[u8], entry_index: u64, artifact_path: &str) -> Vec<TimelineEvent> {
    let mut events = Vec::with_capacity(8);

    if entry.len() < MFT_ENTRY_SIZE {
        return events;
    }

    // Check FILE signature
    if &entry[0..4] != MFT_SIGNATURE {
        return events;
    }

    let flags = read_u16_le(entry, 22);
    let in_use = (flags & FLAG_IN_USE) != 0;
    if !in_use {
        return events;
    }

    let mut attr_offset = read_u16_le(entry, 20) as usize;

    let mut si_timestamps: Option<[u64; 4]> = None;
    let mut fn_timestamps: Option<[u64; 4]> = None;
    let mut file_name = format!("MFT entry #{}", entry_index);

    // Walk attribute list
    loop {
        if attr_offset + 8 > MFT_ENTRY_SIZE {
            break;
        }

        let attr_type = read_u32_le(entry, attr_offset);
        if attr_type == ATTR_END {
            break;
        }

        let attr_len = read_u32_le(entry, attr_offset + 4) as usize;
        if attr_len == 0 || attr_offset + attr_len > MFT_ENTRY_SIZE {
            break;
        }

        let non_resident = entry[attr_offset + 8];

        if non_resident == 0 {
            let content_len = read_u32_le(entry, attr_offset + 16) as usize;
            let content_off = read_u16_le(entry, attr_offset + 20) as usize;
            let data_start = attr_offset + content_off;

            match attr_type {
                ATTR_STANDARD_INFORMATION => {
                    if content_len >= 32 && data_start + 32 <= MFT_ENTRY_SIZE {
                        si_timestamps = Some([
                            read_u64_le(entry, data_start),      // created
                            read_u64_le(entry, data_start + 8),  // modified
                            read_u64_le(entry, data_start + 16), // mft modified
                            read_u64_le(entry, data_start + 24), // accessed
                        ]);
                    }
                }
                ATTR_FILE_NAME => {
                    if content_len >= 66 && data_start + 66 <= MFT_ENTRY_SIZE {
                        let name_len = entry[data_start + 64] as usize;
                        let namespace = entry[data_start + 65];
                        // Prefer POSIX (0) or Win32 (1) namespaces over DOS (2) or Win32&DOS (3)
                        if namespace != 2 {
                            if data_start + 66 + name_len * 2 <= MFT_ENTRY_SIZE {
                                file_name = parse_utf16_name(entry, data_start + 66, name_len);
                            }
                            fn_timestamps = Some([
                                read_u64_le(entry, data_start + 8),  // created
                                read_u64_le(entry, data_start + 16), // modified
                                read_u64_le(entry, data_start + 24), // mft modified
                                read_u64_le(entry, data_start + 32), // accessed
                            ]);
                        }
                    }
                }
                _ => {}
            }
        }

        attr_offset += attr_len;
    }

    // Emit $STANDARD_INFORMATION timestamps — deduplicated by ns value
    if let Some([created, modified, mft_mod, accessed]) = si_timestamps {
        events.extend(build_macb_events(
            [created, modified, mft_mod, accessed],
            artifact_path, "$MFT", "$STANDARD_INFORMATION",
            &file_name, entry_index, false,
        ));
    }

    // Emit $FILE_NAME timestamps — critical for timestomp detection
    if let Some([created, modified, mft_mod, accessed]) = fn_timestamps {
        events.extend(build_macb_events(
            [created, modified, mft_mod, accessed],
            artifact_path, "$MFT", "$FILE_NAME",
            &file_name, entry_index, true,
        ));
    }

    events
}

/// Parse an extracted $MFT file in parallel using memory mapping + rayon.
/// Returns all timeline events as a list of dicts for Python.
#[pyfunction]
pub fn parse_mft_file(py: Python<'_>, path: &str) -> PyResult<Py<PyList>> {
    let file = File::open(path)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;

    let mmap = unsafe { Mmap::map(&file) }
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;

    let total_entries = mmap.len() / MFT_ENTRY_SIZE;

    // Parallel parse: each chunk of entries processed by a rayon thread
    let all_events: Vec<TimelineEvent> = (0..total_entries)
        .into_par_iter()
        .flat_map(|i| {
            let start = i * MFT_ENTRY_SIZE;
            let end = start + MFT_ENTRY_SIZE;
            if end > mmap.len() {
                return vec![];
            }
            parse_mft_entry(&mmap[start..end], i as u64, path)
        })
        .collect();

    let list = PyList::empty_bound(py);
    for ev in &all_events {
        let dict = pyo3::types::PyDict::new_bound(py);
        dict.set_item("timestamp_ns", ev.timestamp_ns)?;
        dict.set_item("timestamp_iso", ev.timestamp_iso())?;
        dict.set_item("macb", &ev.macb)?;
        dict.set_item("source", &ev.source)?;
        dict.set_item("artifact", &ev.artifact)?;
        dict.set_item("artifact_path", &ev.artifact_path)?;
        dict.set_item("message", &ev.message)?;
        dict.set_item("is_fn_timestamp", ev.is_fn_timestamp)?;
        dict.set_item("tz_offset_secs", ev.tz_offset_secs)?;
        list.append(dict)?;
    }

    Ok(list.into())
}

#[pyclass]
pub struct MftParser {
    path: String,
}

#[pymethods]
impl MftParser {
    #[new]
    pub fn new(path: &str) -> Self {
        MftParser { path: path.to_string() }
    }

    pub fn event_count(&self) -> PyResult<usize> {
        let file = File::open(&self.path)
            .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;
        let meta = file.metadata()
            .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;
        Ok((meta.len() as usize / MFT_ENTRY_SIZE) * 8)
    }

    pub fn parse<'py>(&self, py: Python<'py>) -> PyResult<Py<PyList>> {
        parse_mft_file(py, &self.path)
    }
}
