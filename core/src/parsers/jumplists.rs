/// Jump List parser — handles both formats:
///   .automaticDestinations-ms  — OLE/CFB compound document; each numbered stream is an LNK
///   .customDestinations-ms     — flat concatenation of LNK records
use pyo3::prelude::*;
use pyo3::types::{PyList, PyDict};

use crate::types::{TimelineEvent, EventExtra};
use super::lnk::{parse_lnk_bytes_inner, events_from_lnk};
use super::read_helpers::{r_u16, r_u32, r_u64, r_utf16_counted};

// ── CFB (OLE Compound File Binary) constants ──────────────────────────────────

const CFB_MAGIC: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

const ENDOFCHAIN: u32 = 0xFFFFFFFE;
const DIFSECT:    u32 = 0xFFFFFFFC;

// Directory entry object types
const OBJ_STREAM:  u8 = 2;


// ── CFB reader ────────────────────────────────────────────────────────────────

struct Cfb<'a> {
    data:             &'a [u8],
    sector_size:      usize,
    mini_sector_size: usize,
    mini_cutoff:      u32,
    fat:              Vec<u32>,
    mini_fat:         Vec<u32>,
    /// Root entry's start sector and stream size (the mini-stream host)
    root_start:       u32,
    root_size:        u64,
}

impl<'a> Cfb<'a> {
    fn new(data: &'a [u8]) -> Option<Self> {
        if data.len() < 512 { return None; }
        if data[0..8] != CFB_MAGIC { return None; }

        // MS-CFB header layout:
        //   0x18 MinorVersion, 0x1A MajorVersion, 0x1C ByteOrder (0xFFFE)
        //   0x1E SectorSizePower (9 => 512B, 12 => 4096B)
        //   0x20 MiniSectorSizePower (6 => 64B)
        let sector_size_shift      = r_u16(data, 0x1E) as u32;
        let mini_sector_size_shift = r_u16(data, 0x20) as u32;
        let sector_size            = 1usize << sector_size_shift.min(16);
        let mini_sector_size       = 1usize << mini_sector_size_shift.min(12);

        let num_fat_sectors        = r_u32(data, 0x2C);
        let first_dir_sector       = r_u32(data, 0x30);
        let mini_cutoff            = r_u32(data, 0x38); // typically 0x1000 = 4096
        let first_mini_fat_sector  = r_u32(data, 0x3C);
        let num_mini_fat_sectors   = r_u32(data, 0x40);
        let first_difat_sector     = r_u32(data, 0x44);

        // Collect FAT sector numbers from the header DIFAT array (109 entries at 0x4C)
        let mut fat_sectors: Vec<u32> = Vec::new();
        for i in 0..109usize {
            let s = r_u32(data, 0x4C + i * 4);
            if s >= DIFSECT { break; }
            fat_sectors.push(s);
        }

        // Follow DIFAT chain if needed
        let mut difat = first_difat_sector;
        while difat < DIFSECT {
            let off = Self::sector_off_static(difat, sector_size);
            if off + sector_size > data.len() { break; }
            let entries = (sector_size - 4) / 4;
            for i in 0..entries {
                let s = r_u32(data, off + i * 4);
                if s >= DIFSECT { break; }
                fat_sectors.push(s);
            }
            difat = r_u32(data, off + sector_size - 4);
        }

        // Build FAT — cap hint to prevent OOM on malformed input
        let fat_cap = (num_fat_sectors as usize).min(4096) * (sector_size / 4);
        let mut fat: Vec<u32> = Vec::with_capacity(fat_cap);
        for &s in &fat_sectors {
            let off = Self::sector_off_static(s, sector_size);
            if off + sector_size > data.len() { break; }
            for i in 0..(sector_size / 4) {
                fat.push(r_u32(data, off + i * 4));
            }
        }

        // Build mini FAT — cap hint to prevent OOM on malformed input
        let mini_fat_cap = (num_mini_fat_sectors as usize).min(4096) * (sector_size / 4);
        let mut mini_fat: Vec<u32> = Vec::with_capacity(mini_fat_cap);
        let mut ms = first_mini_fat_sector;
        while ms < ENDOFCHAIN {
            let off = Self::sector_off_static(ms, sector_size);
            if off + sector_size > data.len() { break; }
            for i in 0..(sector_size / 4) {
                mini_fat.push(r_u32(data, off + i * 4));
            }
            ms = fat.get(ms as usize).copied().unwrap_or(ENDOFCHAIN);
        }

        // Read root directory entry to get mini-stream start + size
        let dir_data = Self::read_chain_static(data, first_dir_sector, sector_size, &fat);
        if dir_data.len() < 128 { return None; }
        let root_start = r_u32(&dir_data, 0x74);
        let root_size  = r_u64(&dir_data, 0x78);

        Some(Cfb {
            data, sector_size, mini_sector_size, mini_cutoff,
            fat, mini_fat, root_start, root_size,
        })
    }

    fn sector_off_static(sector: u32, sector_size: usize) -> usize {
        512 + sector as usize * sector_size
    }

    fn read_chain_static(data: &[u8], start: u32, sector_size: usize, fat: &[u32]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut cur = start;
        let mut guard = 0usize;
        while cur < ENDOFCHAIN && guard < 65536 {
            let off = Self::sector_off_static(cur, sector_size);
            if off + sector_size > data.len() { break; }
            out.extend_from_slice(&data[off..off + sector_size]);
            cur = fat.get(cur as usize).copied().unwrap_or(ENDOFCHAIN);
            guard += 1;
        }
        out
    }

    fn read_chain(&self, start: u32) -> Vec<u8> {
        Self::read_chain_static(self.data, start, self.sector_size, &self.fat)
    }

    fn read_mini_chain(&self, start: u32, size: u64, mini_stream: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut cur = start;
        let mut guard = 0usize;
        while cur < ENDOFCHAIN && guard < 65536 {
            let off = cur as usize * self.mini_sector_size;
            if off + self.mini_sector_size > mini_stream.len() { break; }
            out.extend_from_slice(&mini_stream[off..off + self.mini_sector_size]);
            cur = self.mini_fat.get(cur as usize).copied().unwrap_or(ENDOFCHAIN);
            guard += 1;
        }
        out.truncate(size as usize);
        out
    }

    /// Return the mini-stream data (the root entry's stream).
    fn mini_stream(&self) -> Vec<u8> {
        let raw = self.read_chain(self.root_start);
        let sz = self.root_size.min(raw.len() as u64) as usize;
        raw[..sz].to_vec()
    }

    /// Iterate all directory entries, returning (name, data) for every stream.
    /// Callers filter by name: hex strings = LNK entries; "DestList" = metadata.
    pub fn all_streams(&self) -> Vec<(String, Vec<u8>)> {
        let dir_data = Self::read_chain_static(
            self.data, r_u32(self.data, 0x30), self.sector_size, &self.fat
        );
        let mini_stream = self.mini_stream();
        let mut results = Vec::new();
        let entry_count = dir_data.len() / 128;

        for i in 0..entry_count {
            let e = &dir_data[i * 128..(i + 1) * 128];
            if e[0x42] != OBJ_STREAM { continue; }

            let name_len = r_u16(e, 0x40) as usize;
            if name_len < 2 { continue; }
            let name = String::from_utf16_lossy(
                &e[0..name_len.min(64)]
                    .chunks_exact(2)
                    .map(|b| u16::from_le_bytes([b[0], b[1]]))
                    .take_while(|&c| c != 0)
                    .collect::<Vec<_>>()
            ).to_string();

            let start = r_u32(e, 0x74);
            let size  = r_u64(e, 0x78);
            if start >= ENDOFCHAIN || size == 0 { continue; }

            let stream_data = if size < self.mini_cutoff as u64 {
                self.read_mini_chain(start, size, &mini_stream)
            } else {
                let mut d = self.read_chain(start);
                d.truncate(size as usize);
                d
            };

            results.push((name, stream_data));
        }
        results
    }
}

// ── Event extraction ──────────────────────────────────────────────────────────

/// Parse the DestList stream from an automaticDestinations Jump List.
///
/// DestList contains per-entry last-access timestamps and target paths.
/// Entry layout by version (empirically validated on Windows 10/11):
///   v3 (Win7/8):  FILETIME at 0x20, path_len(u16) at 0x30, path at 0x32
///   v4 (Win10+):  FILETIME at 0x64, path_len(u16) at 0x82, path at 0x84
///
/// Entry advancement: fixed_path_offset + 2 (path_len u16) + path_len * 2 + 2 (null)
fn parse_destlist(data: &[u8], _artifact_path: &str) -> Vec<TimelineEvent> {
    if data.len() < 32 { return Vec::new(); }

    let version     = r_u32(data, 0);
    let num_entries = r_u32(data, 4) as usize;
    if num_entries == 0 || num_entries > 5000 { return Vec::new(); }

    // (filetime_off, path_len_off, path_off) relative to entry start
    let layout = match version {
        3 => (0x20usize, 0x30usize, 0x32usize),
        4 => (0x64usize, 0x82usize, 0x84usize),
        // Unknown version: scan for FILETIME in first 200 bytes then adjacent path
        _ => {
            return parse_destlist_scan(data, _artifact_path, num_entries);
        }
    };
    let (ft_off, pl_off, path_off) = layout;

    let mut events = Vec::new();
    let mut pos = 32usize; // skip DestList header

    for _ in 0..num_entries {
        if pos + path_off + 2 > data.len() { break; }

        let ft       = r_u64(data, pos + ft_off);
        let path_len = r_u16(data, pos + pl_off) as usize;

        if path_len == 0 || path_len > 512 { break; }
        if pos + path_off + path_len * 2 > data.len() { break; }

        let target = r_utf16_counted(data, pos + path_off, path_len);
        let ns     = crate::types::filetime_to_unix_ns(ft);

        if ns > 0 && !target.is_empty() {
            events.push(TimelineEvent {
                timestamp_ns:    ns,
                macb:            "A".to_string(),
                source:          "JUMPLIST".to_string(),
                artifact:        "JumpList".to_string(),
                message:         format!("JumpList accessed: {}", target),
                hostname:        None,
                tz_offset_secs:  0,
                is_fn_timestamp: false,
                source_hash:     None,
                extra: Some(EventExtra::JumpList {
                    target_path:      target.clone(),
                    destlist_version: Some(version),
                }),
            });
        }

        // Advance: path_off includes the path_len uint16, then path_len chars + null
        pos += path_off + 2 + path_len * 2;
    }
    events
}

/// Fallback DestList parser for unknown versions: scan for valid FILETIME values
/// followed by a uint16 length-prefixed UTF-16LE string.
fn parse_destlist_scan(data: &[u8], _artifact_path: &str, max_entries: usize) -> Vec<TimelineEvent> {
    // Valid FILETIME range: year 2000 to 2040
    const MIN_FT: u64 = 125_911_584_000_000_000;
    const MAX_FT: u64 = 137_919_648_000_000_000;

    let mut events = Vec::new();
    let mut i = 32usize; // skip header

    while i + 8 < data.len() && events.len() < max_entries {
        let val = r_u64(data, i);
        if (MIN_FT..=MAX_FT).contains(&val) {
            let ns = crate::types::filetime_to_unix_ns(val);
            // Scan up to 64 bytes after the FILETIME for a counted UTF-16LE string
            let scan_end = (i + 8 + 64).min(data.len().saturating_sub(2));
            for k in (i + 8..scan_end).step_by(2) {
                let len = r_u16(data, k) as usize;
                if len > 0 && len < 256 && k + 2 + len * 2 <= data.len() {
                    let s = r_utf16_counted(data, k + 2, len);
                    if s.len() >= 3 && s.contains('\\') {
                        events.push(TimelineEvent {
                            timestamp_ns:    ns,
                            macb:            "A".to_string(),
                            source:          "JUMPLIST".to_string(),
                            artifact:        "JumpList".to_string(),
                                        message:         format!("JumpList accessed: {}", s),
                            hostname:        None,
                            tz_offset_secs:  0,
                            is_fn_timestamp: false,
                            source_hash:     None,
                            extra: Some(EventExtra::JumpList {
                                target_path:      s.clone(),
                                destlist_version: None,
                            }),
                        });
                        i = k + 2 + len * 2;
                        break;
                    }
                }
            }
        }
        i += 4;
    }
    events
}

fn parse_auto_destinations(data: &[u8], file_path: &str) -> Vec<TimelineEvent> {
    let cfb = match Cfb::new(data) {
        Some(c) => c,
        None    => return Vec::new(),
    };

    let mut events = Vec::new();

    for (name, stream) in cfb.all_streams() {
        if name.eq_ignore_ascii_case("DestList") {
            // Primary source: access timestamps + target paths
            events.extend(parse_destlist(&stream, file_path));
        } else if name.chars().all(|c| c.is_ascii_hexdigit()) {
            // LNK stream: use embedded timestamps only if non-zero
            if let Some(parsed) = parse_lnk_bytes_inner(&stream) {
                events.extend(events_from_lnk(parsed, file_path));
            }
        }
    }
    events
}

/// Parse a .customDestinations-ms file.
/// Format: concatenated LNK records (each starts with 4C 00 00 00).
/// Scan for LNK headers rather than rely on a fixed framing structure.
fn parse_custom_destinations(data: &[u8], file_path: &str) -> Vec<TimelineEvent> {
    let mut events = Vec::new();
    let mut i = 0usize;

    while i + 4 < data.len() {
        // LNK header starts with HeaderSize = 0x0000004C
        if data[i..i+4] == [0x4C, 0x00, 0x00, 0x00] {
            let slice = &data[i..];
            if let Some(parsed) = parse_lnk_bytes_inner(slice) {
                events.extend(events_from_lnk(parsed, file_path));
                // Advance past this LNK (minimum 76 bytes + at least one section)
                i += 76;
                continue;
            }
        }
        i += 4;
    }
    events
}

/// Parse Jump List bytes, auto-detecting format (CFB or custom destinations).
pub fn parse_jumplist_bytes_inner(data: &[u8], file_path: &str) -> Vec<TimelineEvent> {
    if data.len() < 8 { return Vec::new(); }

    if data[0..8] == CFB_MAGIC {
        parse_auto_destinations(data, file_path)
    } else {
        parse_custom_destinations(data, file_path)
    }
}

// ── Python interface ──────────────────────────────────────────────────────────

fn event_to_dict<'py>(py: Python<'py>, ev: &TimelineEvent) -> PyResult<Bound<'py, PyDict>> {
    let d = PyDict::new_bound(py);
    d.set_item("timestamp_ns",    ev.timestamp_ns)?;
    d.set_item("timestamp_iso",   ev.timestamp_iso())?;
    d.set_item("macb",            &ev.macb)?;
    d.set_item("source",          &ev.source)?;
    d.set_item("artifact",        &ev.artifact)?;
    d.set_item("message",         &ev.message)?;
    d.set_item("is_fn_timestamp", ev.is_fn_timestamp)?;
    d.set_item("tz_offset_secs",  ev.tz_offset_secs)?;
    if let Some(EventExtra::JumpList { target_path, destlist_version }) = &ev.extra {
        d.set_item("file_path",   target_path.as_str())?;
        d.set_item("target_path", target_path.as_str())?;
        if let Some(v) = destlist_version {
            d.set_item("destlist_version", v)?;
        }
    }
    Ok(d)
}

/// Parse a Jump List file (.automaticDestinations-ms or .customDestinations-ms) from bytes.
#[pyfunction]
pub fn parse_jumplist_bytes(
    py: Python<'_>,
    data: &[u8],
    file_path: &str,
) -> PyResult<Py<PyList>> {
    let events = parse_jumplist_bytes_inner(data, file_path);
    let list = PyList::empty_bound(py);
    for ev in &events {
        list.append(event_to_dict(py, ev)?)?;
    }
    Ok(list.into())
}
