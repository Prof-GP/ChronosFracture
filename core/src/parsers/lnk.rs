use pyo3::prelude::*;
use pyo3::types::{PyList, PyDict};
use std::fs;
use std::path::Path;
use rayon::prelude::*;

use crate::types::{TimelineEvent, filetime_to_unix_ns};

// LNK header is always exactly 76 (0x4C) bytes
const LNK_HEADER_LEN: usize = 76;

// CLSID for Shell Link: {00021401-0000-0000-C000-000000000046} in LE byte order
const LNK_CLSID: [u8; 16] = [
    0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];

// LinkFlags (offset 0x14 in header)
const FL_HAS_ID_LIST:      u32 = 0x0001;
const FL_HAS_LINK_INFO:    u32 = 0x0002;
const FL_HAS_NAME:         u32 = 0x0004;
const FL_HAS_REL_PATH:     u32 = 0x0008;
const FL_HAS_WORKING_DIR:  u32 = 0x0010;
const FL_HAS_ARGUMENTS:    u32 = 0x0020;
const FL_IS_UNICODE:       u32 = 0x0080;

fn drive_type_str(t: u32) -> &'static str {
    match t {
        2 => "Removable",
        3 => "Fixed",
        4 => "Network",
        5 => "CDROM",
        6 => "RAMDisk",
        _ => "Unknown",
    }
}

fn r_u16(d: &[u8], o: usize) -> u16 {
    if o + 2 > d.len() { return 0; }
    u16::from_le_bytes([d[o], d[o + 1]])
}
fn r_u32(d: &[u8], o: usize) -> u32 {
    if o + 4 > d.len() { return 0; }
    u32::from_le_bytes([d[o], d[o+1], d[o+2], d[o+3]])
}
fn r_u64(d: &[u8], o: usize) -> u64 {
    if o + 8 > d.len() { return 0; }
    u64::from_le_bytes([d[o],d[o+1],d[o+2],d[o+3],d[o+4],d[o+5],d[o+6],d[o+7]])
}
fn r_utf16_null(d: &[u8], off: usize) -> String {
    let mut units = Vec::new();
    let mut i = off;
    while i + 1 < d.len() {
        let c = u16::from_le_bytes([d[i], d[i+1]]);
        if c == 0 { break; }
        units.push(c);
        i += 2;
        if units.len() > 512 { break; }
    }
    String::from_utf16_lossy(&units).to_string()
}
fn r_utf16_counted(d: &[u8], off: usize, n: usize) -> String {
    let end = (off + n * 2).min(d.len());
    if off >= end { return String::new(); }
    let pairs: Vec<u16> = d[off..end]
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .collect();
    String::from_utf16_lossy(&pairs).to_string()
}
fn r_ascii_null(d: &[u8], off: usize) -> String {
    let n = d[off..].iter().take(512).position(|&b| b == 0).unwrap_or(512);
    String::from_utf8_lossy(&d[off..off + n]).to_string()
}

pub struct LnkParsed {
    pub target_path:    String,
    pub drive_type:     u32,
    pub drive_serial:   u32,
    pub volume_label:   String,
    /// Embedded target FILETIME values: (creation, access, write)
    pub target_times:   (u64, u64, u64),
}

/// Parse raw LNK bytes.  Returns None if data is not a valid Shell Link file.
pub fn parse_lnk_bytes_inner(data: &[u8]) -> Option<LnkParsed> {
    if data.len() < LNK_HEADER_LEN { return None; }
    if r_u32(data, 0x00) != 0x4C { return None; }
    if data[0x04..0x14] != LNK_CLSID { return None; }

    let flags            = r_u32(data, 0x14);
    let target_create_ft = r_u64(data, 0x1C);
    let target_access_ft = r_u64(data, 0x24);
    let target_write_ft  = r_u64(data, 0x2C);

    let mut off = LNK_HEADER_LEN;

    // Skip LinkTargetIDList
    if flags & FL_HAS_ID_LIST != 0 {
        let sz = r_u16(data, off) as usize;
        off += 2 + sz;
    }

    let mut target_path  = String::new();
    let mut drive_type   = 0u32;
    let mut drive_serial = 0u32;
    let mut volume_label = String::new();

    // Parse LinkInfo
    if flags & FL_HAS_LINK_INFO != 0 && off + 4 <= data.len() {
        let li_start  = off;
        let li_size   = r_u32(data, li_start) as usize;
        let li_hdr_sz = r_u32(data, li_start + 0x04) as usize;
        let li_flags  = r_u32(data, li_start + 0x08);
        let vol_off   = r_u32(data, li_start + 0x0C) as usize;
        let base_off  = r_u32(data, li_start + 0x10) as usize;

        if li_size >= 28 && li_start + li_size <= data.len() {
            // Prefer Unicode local base path (LinkInfoHeader >= 0x24)
            if li_hdr_sz >= 0x24 {
                let ub_off = r_u32(data, li_start + 0x20) as usize;
                if ub_off > 0 {
                    let p = r_utf16_null(data, li_start + ub_off);
                    if !p.is_empty() { target_path = p; }
                }
            }
            // ASCII fallback
            if target_path.is_empty() && base_off > 0 {
                target_path = r_ascii_null(data, li_start + base_off);
            }

            // VolumeID block (LinkInfoFlags bit 0 = VolumeIDAndLocalBasePath)
            if li_flags & 1 != 0 && vol_off > 0 && li_start + vol_off + 16 <= data.len() {
                let vi       = li_start + vol_off;
                let vi_hsz   = r_u32(data, vi) as usize;
                drive_type   = r_u32(data, vi + 0x04);
                drive_serial = r_u32(data, vi + 0x08);
                let lbl_off  = r_u32(data, vi + 0x0C) as usize;

                // Unicode volume label (VolumeIDHeader >= 0x14)
                let mut got_lbl = false;
                if vi_hsz >= 0x14 {
                    let lbl_u = r_u32(data, vi + 0x10) as usize;
                    if lbl_u > 0 && vi + lbl_u < data.len() {
                        let l = r_utf16_null(data, vi + lbl_u);
                        if !l.is_empty() { volume_label = l; got_lbl = true; }
                    }
                }
                if !got_lbl && lbl_off > 0 && vi + lbl_off < data.len() {
                    volume_label = r_ascii_null(data, vi + lbl_off);
                }
            }
        }
        off = li_start + li_size;
    }

    // StringData: try to get RelativePath if still no target
    if target_path.is_empty() {
        let is_uni = flags & FL_IS_UNICODE != 0;

        // Skip NameString
        if flags & FL_HAS_NAME != 0 && off + 2 <= data.len() {
            let n = r_u16(data, off) as usize;
            off += 2 + if is_uni { n * 2 } else { n };
        }
        // RelativePath
        if flags & FL_HAS_REL_PATH != 0 && off + 2 <= data.len() {
            let n = r_u16(data, off) as usize;
            off += 2;
            if n > 0 {
                target_path = if is_uni {
                    r_utf16_counted(data, off, n)
                } else {
                    r_ascii_null(data, off)
                };
            }
        }
    }

    Some(LnkParsed {
        target_path,
        drive_type,
        drive_serial,
        volume_label,
        target_times: (target_create_ft, target_access_ft, target_write_ft),
    })
}

pub fn events_from_lnk(parsed: LnkParsed, lnk_path: &str) -> Vec<TimelineEvent> {
    let (create_ft, access_ft, write_ft) = parsed.target_times;

    // Nothing useful if no timestamps and no path
    if create_ft == 0 && access_ft == 0 && write_ft == 0 && parsed.target_path.is_empty() {
        return Vec::new();
    }

    let target = if parsed.target_path.is_empty() {
        "(unknown target)".to_string()
    } else {
        parsed.target_path.clone()
    };

    let vol_info = if parsed.drive_serial != 0 {
        let lbl = if parsed.volume_label.is_empty() {
            String::new()
        } else {
            format!("; vol:{}", parsed.volume_label)
        };
        format!(" [{} {:08X}{}]", drive_type_str(parsed.drive_type), parsed.drive_serial, lbl)
    } else {
        String::new()
    };

    let make = |ft: u64, macb: &'static str, verb: &'static str| -> Option<TimelineEvent> {
        if ft == 0 { return None; }
        let ns = filetime_to_unix_ns(ft);
        if ns == 0 { return None; }
        Some(TimelineEvent {
            timestamp_ns:    ns,
            macb:            macb.to_string(),
            source:          "LNK".to_string(),
            artifact:        "LNK".to_string(),
            artifact_path:   lnk_path.to_string(),
            message:         format!("{}: {}{}", verb, target, vol_info),
            hostname:        None,
            tz_offset_secs:  0,
            is_fn_timestamp: false,
            source_hash:     None,
            extra:           Some(serde_json::json!({
                "target_path":   &parsed.target_path,
                "drive_type":    parsed.drive_type,
                "drive_serial":  format!("{:08X}", parsed.drive_serial),
                "volume_label":  &parsed.volume_label,
            })),
        })
    };

    vec![
        make(create_ft, "B", "LNK target born"),
        make(access_ft, "A", "LNK target last accessed"),
        make(write_ft,  "M", "LNK target last modified"),
    ]
    .into_iter()
    .flatten()
    .collect()
}

fn event_to_dict<'py>(py: Python<'py>, ev: &TimelineEvent) -> PyResult<Bound<'py, PyDict>> {
    let d = PyDict::new_bound(py);
    d.set_item("timestamp_ns",    ev.timestamp_ns)?;
    d.set_item("timestamp_iso",   ev.timestamp_iso())?;
    d.set_item("macb",            &ev.macb)?;
    d.set_item("source",          &ev.source)?;
    d.set_item("artifact",        &ev.artifact)?;
    d.set_item("artifact_path",   &ev.artifact_path)?;
    d.set_item("message",         &ev.message)?;
    d.set_item("is_fn_timestamp", ev.is_fn_timestamp)?;
    d.set_item("tz_offset_secs",  ev.tz_offset_secs)?;
    if let Some(x) = &ev.extra {
        d.set_item("target_path",  x["target_path"].as_str().unwrap_or(""))?;
        d.set_item("drive_type",   x["drive_type"].as_u64().unwrap_or(0))?;
        d.set_item("drive_serial", x["drive_serial"].as_str().unwrap_or(""))?;
        d.set_item("volume_label", x["volume_label"].as_str().unwrap_or(""))?;
    }
    Ok(d)
}

/// Parse a single LNK file from bytes and return timeline events as Python dicts.
#[pyfunction]
pub fn parse_lnk_bytes(py: Python<'_>, data: &[u8], lnk_path: &str) -> PyResult<Py<PyList>> {
    let list = PyList::empty_bound(py);
    if let Some(parsed) = parse_lnk_bytes_inner(data) {
        for ev in events_from_lnk(parsed, lnk_path) {
            list.append(event_to_dict(py, &ev)?)?;
        }
    }
    Ok(list.into())
}

/// Walk a directory for *.lnk files, parse all in parallel.
#[pyfunction]
pub fn parse_lnk_dir(py: Python<'_>, dir_path: &str) -> PyResult<Py<PyList>> {
    let paths: Vec<_> = fs::read_dir(Path::new(dir_path))
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path().extension()
                .and_then(|x| x.to_str())
                .map(|x| x.eq_ignore_ascii_case("lnk"))
                .unwrap_or(false)
        })
        .map(|e| e.path())
        .collect();

    let events: Vec<TimelineEvent> = paths
        .par_iter()
        .flat_map(|p| {
            fs::read(p).ok()
                .and_then(|d| parse_lnk_bytes_inner(&d))
                .map(|parsed| events_from_lnk(parsed, p.to_str().unwrap_or("")))
                .unwrap_or_default()
        })
        .collect();

    let list = PyList::empty_bound(py);
    for ev in &events {
        list.append(event_to_dict(py, ev)?)?;
    }
    Ok(list.into())
}
