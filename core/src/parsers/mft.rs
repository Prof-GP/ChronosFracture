use pyo3::prelude::*;
use pyo3::types::PyList;
use memmap2::Mmap;
use rayon::prelude::*;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fs::File;

use crate::types::{TimelineEvent, filetime_to_unix_ns};

const MFT_ENTRY_SIZE: usize = 1024;
const MFT_SIGNATURE: &[u8; 4] = b"FILE";
const ATTR_STANDARD_INFORMATION: u32 = 0x10;
const ATTR_FILE_NAME: u32 = 0x30;
const ATTR_END: u32 = 0xFFFFFFFF;
const FLAG_IN_USE: u16 = 0x01;
const FLAG_IS_DIRECTORY: u16 = 0x02;
// MFT entry number of the volume root directory
const ROOT_ENTRY: u64 = 5;
// Mask to extract the 48-bit MFT record number from a FILE_REFERENCE u64
const ENTRY_NUM_MASK: u64 = 0x0000_FFFF_FFFF_FFFF;

#[repr(C, packed)]
#[derive(Copy, Clone)]
struct MftEntryHeader {
    signature: [u8; 4],
    _fixup_offset: u16,
    _fixup_count: u16,
    _log_seq_num: u64,
    _sequence_num: u16,
    _hard_link_count: u16,
    attr_offset: u16,
    flags: u16,
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
    content_len: u32,
    content_offset: u16,
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
struct StandardInformation {
    created: u64,
    modified: u64,
    mft_modified: u64,
    accessed: u64,
}

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
    name_len: u8,
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
fn build_macb_events(
    timestamps: [u64; 4],
    artifact_path: &str,
    source: &str,
    artifact: &str,
    file_name: &str,
    entry_index: u64,
    is_fn: bool,
) -> Vec<TimelineEvent> {
    let flag_map = [
        (timestamps[0], 3usize), // created  → B
        (timestamps[1], 0usize), // modified → M
        (timestamps[2], 2usize), // mft_mod  → C
        (timestamps[3], 1usize), // accessed → A
    ];

    let mut groups: std::collections::HashMap<i64, [bool; 4]> = std::collections::HashMap::new();
    for (ft, flag_idx) in &flag_map {
        let ns = filetime_to_unix_ns(*ft);
        if ns <= 0 { continue; }
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
                extra: Some(crate::types::EventExtra::Mft { mft_entry: entry_index }),
            }
        })
        .collect()
}

/// Raw data extracted from one MFT entry during Phase 1 (parallel scan).
struct RawEntryData {
    entry_index: u64,
    /// Filename component only (e.g. "ntoskrnl.exe")
    name: String,
    /// Parent MFT record number (sequence bits already stripped)
    parent_entry: u64,
    si_timestamps: Option<[u64; 4]>,
    fn_timestamps: Option<[u64; 4]>,
}

/// Phase 1: extract raw data from one MFT entry.
/// Returns None for free/unused entries and entries with no readable attributes.
fn parse_mft_entry_raw(entry: &[u8], entry_index: u64) -> Option<RawEntryData> {
    if entry.len() < MFT_ENTRY_SIZE || &entry[0..4] != MFT_SIGNATURE {
        return None;
    }
    let flags = read_u16_le(entry, 22);
    if (flags & FLAG_IN_USE) == 0 {
        return None;
    }

    let mut attr_offset = read_u16_le(entry, 20) as usize;
    let mut si_timestamps: Option<[u64; 4]> = None;
    let mut fn_timestamps: Option<[u64; 4]> = None;
    let mut file_name = String::new();
    let mut parent_entry: u64 = ROOT_ENTRY; // default: root

    loop {
        if attr_offset + 8 > MFT_ENTRY_SIZE { break; }
        let attr_type = read_u32_le(entry, attr_offset);
        if attr_type == ATTR_END { break; }
        let attr_len = read_u32_le(entry, attr_offset + 4) as usize;
        if attr_len == 0 || attr_offset + attr_len > MFT_ENTRY_SIZE { break; }

        if entry[attr_offset + 8] == 0 {
            let content_len = read_u32_le(entry, attr_offset + 16) as usize;
            let content_off = read_u16_le(entry, attr_offset + 20) as usize;
            let data_start = attr_offset + content_off;

            match attr_type {
                ATTR_STANDARD_INFORMATION
                    if content_len >= 32 && data_start + 32 <= MFT_ENTRY_SIZE =>
                {
                    si_timestamps = Some([
                        read_u64_le(entry, data_start),
                        read_u64_le(entry, data_start + 8),
                        read_u64_le(entry, data_start + 16),
                        read_u64_le(entry, data_start + 24),
                    ]);
                }
                ATTR_FILE_NAME
                    if content_len >= 66 && data_start + 66 <= MFT_ENTRY_SIZE =>
                {
                    let parent_ref = read_u64_le(entry, data_start);
                    let name_len = entry[data_start + 64] as usize;
                    let namespace = entry[data_start + 65];
                    // Prefer Win32 (1) or POSIX (0) over DOS (2) or Win32&DOS (3)
                    if namespace != 2 && data_start + 66 + name_len * 2 <= MFT_ENTRY_SIZE {
                        file_name = parse_utf16_name(entry, data_start + 66, name_len);
                        fn_timestamps = Some([
                            read_u64_le(entry, data_start + 8),
                            read_u64_le(entry, data_start + 16),
                            read_u64_le(entry, data_start + 24),
                            read_u64_le(entry, data_start + 32),
                        ]);
                        parent_entry = parent_ref & ENTRY_NUM_MASK;
                    }
                }
                _ => {}
            }
        }

        attr_offset += attr_len;
    }

    // Keep the entry in the map even without timestamps — needed as intermediate
    // directory nodes for path resolution of deeper entries.
    if file_name.is_empty() {
        file_name = format!("entry#{}", entry_index);
    }

    Some(RawEntryData {
        entry_index,
        name: file_name,
        parent_entry,
        si_timestamps,
        fn_timestamps,
    })
}

/// Phase 2: walk the parent chain for one entry to build its full volume-relative path.
/// Returns a path like `\Windows\System32\ntoskrnl.exe`.
fn resolve_path(entry_index: u64, name_map: &HashMap<u64, (String, u64)>) -> String {
    let mut parts: Vec<String> = Vec::new();
    let mut current = entry_index;
    let mut seen: HashSet<u64> = HashSet::new();

    loop {
        if current == ROOT_ENTRY || seen.len() >= 64 {
            break;
        }
        if !seen.insert(current) {
            break; // cycle
        }
        match name_map.get(&current) {
            Some((name, parent)) => {
                parts.push(name.clone());
                let p = *parent;
                if p == current || p == ROOT_ENTRY || p == 0 {
                    break;
                }
                current = p;
            }
            None => break,
        }
    }

    parts.reverse();
    if parts.is_empty() {
        String::from("\\")
    } else {
        format!("\\{}", parts.join("\\"))
    }
}

/// Parse an extracted $MFT file in parallel using memory mapping + rayon.
///
/// Two-pass algorithm:
///   Pass 1 (parallel) — extract (name, parent_ref, timestamps) from every entry.
///   Pass 2 (parallel) — resolve full volume-relative paths via parent-chain walk,
///                        then emit MACB events with `file_path` set to the full path.
#[pyfunction]
pub fn parse_mft_file(py: Python<'_>, path: &str) -> PyResult<Py<PyList>> {
    let file = File::open(path)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;

    let mmap = unsafe { Mmap::map(&file) }
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;

    let total_entries = mmap.len() / MFT_ENTRY_SIZE;

    // ── Pass 1: parallel scan ─────────────────────────────────────────────────
    let raw_entries: Vec<RawEntryData> = (0..total_entries)
        .into_par_iter()
        .filter_map(|i| {
            let start = i * MFT_ENTRY_SIZE;
            let end = start + MFT_ENTRY_SIZE;
            if end > mmap.len() { return None; }
            parse_mft_entry_raw(&mmap[start..end], i as u64)
        })
        .collect();

    // ── Build name map: entry_num → (name, parent_entry_num) ─────────────────
    // Includes ALL in-use entries so intermediate directories can be resolved.
    let name_map: HashMap<u64, (String, u64)> = raw_entries
        .iter()
        .map(|e| (e.entry_index, (e.name.clone(), e.parent_entry)))
        .collect();

    // ── Pass 2: resolve paths + emit events (parallel, name_map is read-only) ─
    let all_events: Vec<(TimelineEvent, String)> = raw_entries
        .par_iter()
        .filter(|e| e.si_timestamps.is_some() || e.fn_timestamps.is_some())
        .flat_map(|entry| {
            let file_path = resolve_path(entry.entry_index, &name_map);
            let mut evts: Vec<(TimelineEvent, String)> = Vec::new();

            if let Some([created, modified, mft_mod, accessed]) = entry.si_timestamps {
                for ev in build_macb_events(
                    [created, modified, mft_mod, accessed],
                    path, "$MFT", "$STANDARD_INFORMATION",
                    &entry.name, entry.entry_index, false,
                ) {
                    evts.push((ev, file_path.clone()));
                }
            }

            if let Some([created, modified, mft_mod, accessed]) = entry.fn_timestamps {
                for ev in build_macb_events(
                    [created, modified, mft_mod, accessed],
                    path, "$MFT", "$FILE_NAME",
                    &entry.name, entry.entry_index, true,
                ) {
                    evts.push((ev, file_path.clone()));
                }
            }

            evts
        })
        .collect();

    // ── Convert to Python dicts ───────────────────────────────────────────────
    let list = PyList::empty_bound(py);
    for (ev, file_path) in &all_events {
        let dict = pyo3::types::PyDict::new_bound(py);
        dict.set_item("timestamp_ns", ev.timestamp_ns)?;
        dict.set_item("timestamp_iso", ev.timestamp_iso())?;
        dict.set_item("macb", &ev.macb)?;
        dict.set_item("source", &ev.source)?;
        dict.set_item("artifact", &ev.artifact)?;
        dict.set_item("artifact_path", &ev.artifact_path)?;
        dict.set_item("file_path", file_path)?;
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
