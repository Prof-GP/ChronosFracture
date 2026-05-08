use pyo3::prelude::*;
use pyo3::types::{PyList, PyDict};
use std::collections::HashMap;
use std::fs;

use crate::types::filetime_to_unix_ns;

// ── Registry hive primitives ──────────────────────────────────────────────────

#[inline] fn r16(d: &[u8], o: usize) -> u16 {
    if o + 2 > d.len() { return 0; }
    u16::from_le_bytes([d[o], d[o+1]])
}
#[inline] fn r32(d: &[u8], o: usize) -> u32 {
    if o + 4 > d.len() { return 0; }
    u32::from_le_bytes([d[o], d[o+1], d[o+2], d[o+3]])
}
#[inline] fn r64(d: &[u8], o: usize) -> u64 {
    if o + 8 > d.len() { return 0; }
    u64::from_le_bytes([d[o],d[o+1],d[o+2],d[o+3],d[o+4],d[o+5],d[o+6],d[o+7]])
}

fn ascii_str(d: &[u8], off: usize, len: usize) -> String {
    let end = (off + len).min(d.len());
    if off >= end { return String::new(); }
    String::from_utf8_lossy(&d[off..end]).to_string()
}
fn utf16_null(d: &[u8], off: usize) -> String {
    let mut u: Vec<u16> = Vec::new();
    let mut i = off;
    while i + 1 < d.len() {
        let c = u16::from_le_bytes([d[i], d[i+1]]);
        if c == 0 { break; }
        u.push(c); i += 2;
        if u.len() > 512 { break; }
    }
    String::from_utf16_lossy(&u).to_string()
}
fn ascii_null(d: &[u8], off: usize) -> String {
    if off >= d.len() { return String::new(); }
    let s = &d[off..];
    let n = s.iter().take(512).position(|&b| b == 0).unwrap_or_else(|| s.len().min(512));
    String::from_utf8_lossy(&s[..n]).to_string()
}

// ── NK cell index ─────────────────────────────────────────────────────────────

// NK cell offsets (verified against Python registry.py):
// nk_off = cell_off + 4  (content = past the 4-byte cell size)
// +0x00  sig 'nk'
// +0x02  u16 flags    (0x04=root, 0x20=ASCII name)
// +0x04  u64 last_write (FILETIME)
// +0x10  u32 parent_rel (hive-area-relative = abs - 4096)
// +0x14  u32 subkey_count
// +0x1C  u32 subkeys_list_rel (hive-area-relative)
// +0x24  u32 values_count
// +0x28  u32 values_list_rel
// +0x48  u16 name_len
// +0x4A  u16 name_flags (ASCII if flags & 0x20)
// +0x4C  name bytes

struct Nk {
    flags:           u16,
    last_write_ns:   i64,
    subkey_count:    u32,
    subkeys_list:    u32,
    values_count:    u32,
    values_list:     u32,
    name:            String,
}

/// Parse all allocated NK cells → HashMap<rel_off, Nk>
/// rel_off = cell position in hive data area (= abs_file_offset − 4096)
fn parse_nk_index(data: &[u8]) -> HashMap<u32, Nk> {
    let mut idx: HashMap<u32, Nk> = HashMap::new();
    let mut off = 4096usize;
    while off + 32 < data.len() {
        if &data[off..off+4] != b"hbin" { break; }
        let hbin_sz = r32(data, off + 8) as usize;
        if hbin_sz < 32 || off + hbin_sz > data.len() { break; }

        let mut c = off + 32;
        while c + 4 < off + hbin_sz {
            let sz_raw = i32::from_le_bytes([data[c], data[c+1], data[c+2], data[c+3]]);
            if sz_raw == 0 { break; }
            let allocated = sz_raw < 0;
            let sz = sz_raw.unsigned_abs() as usize;
            if sz < 4 { break; }

            if allocated {
                let n = c + 4; // NK content start
                if n + 0x4C < data.len() && &data[n..n+2] == b"nk" {
                    let flags       = r16(data, n + 0x02);
                    let last_ft     = r64(data, n + 0x04);
                    let subkey_cnt  = r32(data, n + 0x14);
                    let subkeys_lst = r32(data, n + 0x1C);
                    let val_cnt     = r32(data, n + 0x24);
                    let val_lst     = r32(data, n + 0x28);
                    let name_len    = r16(data, n + 0x48) as usize;
                    if n + 0x4C + name_len <= data.len() {
                        let name = if flags & 0x20 != 0 {
                            ascii_str(data, n + 0x4C, name_len)
                        } else {
                            let u16s: Vec<u16> = data[n+0x4C..n+0x4C+name_len]
                                .chunks_exact(2)
                                .map(|b| u16::from_le_bytes([b[0], b[1]]))
                                .collect();
                            String::from_utf16_lossy(&u16s).to_string()
                        };
                        let rel = (c - 4096) as u32;
                        idx.insert(rel, Nk {
                            flags,
                            last_write_ns: filetime_to_unix_ns(last_ft),
                            subkey_count:  subkey_cnt,
                            subkeys_list:  subkeys_lst,
                            values_count:  val_cnt,
                            values_list:   val_lst,
                            name,
                        });
                    }
                }
            }
            c += sz;
        }
        off += hbin_sz;
    }
    idx
}

// ── Subkey list traversal ─────────────────────────────────────────────────────
// Cells: lf/lh (8-byte entries: [rel u32][hash u32])
//        li    (4-byte entries: [rel u32])
//        ri    (4-byte entries: [block_rel u32] — indirect, each block is lf/lh/li)
// All rels are hive-area-relative (abs = rel + 4096 + 4 to reach cell content)

fn subkey_rels(data: &[u8], nk: &Nk) -> Vec<u32> {
    let mut out = Vec::new();
    if nk.subkey_count == 0 || nk.subkeys_list == 0 || nk.subkeys_list == 0xFFFF_FFFF {
        return out;
    }
    read_list_block(data, nk.subkeys_list, &mut out);
    out
}

fn read_list_block(data: &[u8], list_rel: u32, out: &mut Vec<u32>) {
    let abs = list_rel as usize + 4096 + 4;
    if abs + 4 > data.len() { return; }
    let sig = &data[abs..abs+2];
    let count = r16(data, abs + 2) as usize;
    let entries = abs + 4;
    match sig {
        b"lf" | b"lh" => {
            for i in 0..count {
                let rel = r32(data, entries + i * 8);
                if rel != 0 && rel != 0xFFFF_FFFF { out.push(rel); }
            }
        }
        b"li" => {
            for i in 0..count {
                let rel = r32(data, entries + i * 4);
                if rel != 0 && rel != 0xFFFF_FFFF { out.push(rel); }
            }
        }
        b"ri" => {
            for i in 0..count {
                let sub_rel = r32(data, entries + i * 4);
                if sub_rel != 0 && sub_rel != 0xFFFF_FFFF {
                    read_list_block(data, sub_rel, out);
                }
            }
        }
        _ => {}
    }
}

// ── Value list traversal ──────────────────────────────────────────────────────
// Returns (name, raw_bytes) for each VK cell under this NK.

fn nk_values(data: &[u8], nk: &Nk) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    if nk.values_count == 0 || nk.values_list == 0 || nk.values_list == 0xFFFF_FFFF {
        return out;
    }
    let vl_abs = nk.values_list as usize + 4096 + 4;
    let vl_end = vl_abs + nk.values_count as usize * 4;
    if vl_end > data.len() { return out; }

    for i in 0..nk.values_count as usize {
        let vk_rel = r32(data, vl_abs + i * 4);
        if vk_rel == 0 || vk_rel == 0xFFFF_FFFF { continue; }
        let vk = vk_rel as usize + 4096 + 4;
        if vk + 20 > data.len() || &data[vk..vk+2] != b"vk" { continue; }

        let name_len     = r16(data, vk + 2) as usize;
        let data_len_raw = r32(data, vk + 4);
        let data_off_raw = r32(data, vk + 8);
        let vk_flags     = r16(data, vk + 16);

        let vname = if name_len == 0 {
            String::new()
        } else if vk_flags & 0x01 != 0 {
            ascii_str(data, vk + 20, name_len)
        } else {
            let end = (vk + 20 + name_len).min(data.len());
            let u16s: Vec<u16> = data[vk+20..end].chunks_exact(2)
                .map(|b| u16::from_le_bytes([b[0], b[1]])).collect();
            String::from_utf16_lossy(&u16s).to_string()
        };

        let inline     = data_len_raw & 0x8000_0000 != 0;
        let actual_len = (data_len_raw & 0x7FFF_FFFF) as usize;
        let raw: Vec<u8> = if actual_len == 0 {
            Vec::new()
        } else if inline {
            data_off_raw.to_le_bytes()[..actual_len.min(4)].to_vec()
        } else {
            let ra = data_off_raw as usize + 4096 + 4;
            if ra + actual_len <= data.len() { data[ra..ra+actual_len].to_vec() } else { Vec::new() }
        };

        out.push((vname, raw));
    }
    out
}

// ── Key navigation ────────────────────────────────────────────────────────────

fn find_child(data: &[u8], idx: &HashMap<u32, Nk>, parent_rel: u32, name: &str) -> Option<u32> {
    let parent = idx.get(&parent_rel)?;
    let upper = name.to_ascii_uppercase();
    for child_rel in subkey_rels(data, parent) {
        if let Some(child) = idx.get(&child_rel) {
            if child.name.to_ascii_uppercase() == upper {
                return Some(child_rel);
            }
        }
    }
    None
}

fn navigate(data: &[u8], idx: &HashMap<u32, Nk>, root_rel: u32, path: &[&str]) -> Option<u32> {
    let mut cur = root_rel;
    for seg in path { cur = find_child(data, idx, cur, seg)?; }
    Some(cur)
}

// ── Shell item decoding ───────────────────────────────────────────────────────
// A BagMRU value is a single-item IDList: [item_size u16][item_body...][00 00]
// decode_shell_item receives the raw value bytes (starts at offset 0 = size u16).
// item[2] = type byte, item[14..] = short name for file/folder items.

/// Scan for a printable UTF-16LE null-terminated string starting at `off`.
fn try_utf16(d: &[u8], off: usize) -> String {
    let mut u: Vec<u16> = Vec::new();
    let mut i = off;
    while i + 1 < d.len() {
        let c = u16::from_le_bytes([d[i], d[i+1]]);
        if c == 0 { break; }
        if c < 0x20 && c != 0x09 { return String::new(); }
        u.push(c); i += 2;
        if u.len() > 260 { return String::new(); }
    }
    if u.is_empty() { return String::new(); }
    let s = String::from_utf16_lossy(&u).to_string();
    if s.chars().any(|c| c.is_alphanumeric()) { s } else { String::new() }
}

/// Extract the long filename from a BEEF0004 extension block embedded in a shell item.
/// The block signature 0xBEEF0004 in LE = bytes [04 00 EF BE].
/// Layout from block start (b):
///   b+0  u16 size,  b+2 u16 version,  b+4 u32 0xBEEF0004
///   b+8  4×u16 FAT dates/times,  b+16 u16 identifier
///   v3–6 → long name (UTF-16LE) starts at b+18
///   v7+  → b+18 u16, b+20 u64 ntfs_ref, b+28 u64 filetime, b+36 u64 unk
///           → long name starts at b+42 (some builds b+44; try both)
fn long_name_beef0004(item: &[u8]) -> Option<String> {
    let mut i = 14usize;
    while i + 8 < item.len() {
        if item[i] == 0x04 && item[i+1] == 0x00 && item[i+2] == 0xEF && item[i+3] == 0xBE {
            if i < 4 { i += 1; continue; }
            let b       = i - 4; // block start
            let version = r16(item, b + 2);
            let candidates: &[usize] = if version >= 7 { &[b+42, b+44, b+18] }
                                       else if version >= 3 { &[b+18, b+20] }
                                       else { i += 1; continue; };
            for &off in candidates {
                if off + 2 > item.len() { continue; }
                let s = try_utf16(item, off);
                if !s.is_empty() { return Some(s); }
            }
        }
        i += 1;
    }
    None
}

fn decode_shell_item(item: &[u8]) -> String {
    if item.len() < 3 { return String::new(); }
    let t = item[2]; // type byte at offset 2 (past u16 size)

    // Root / My Computer (0x1F)
    if t == 0x1F { return "My Computer".to_string(); }

    // Volume / drive (0x20–0x2F): drive letter byte at offset 3
    if t >= 0x20 && t <= 0x2F {
        if item.len() > 3 {
            let c = item[3] as char;
            if c.is_ascii_alphabetic() {
                return format!("{}:", c.to_ascii_uppercase());
            }
        }
        return String::new(); // skip unrecognised volume items
    }

    // File / folder items: class nibble 0x3x, 0x7x, 0xBx
    let class = t & 0x70;
    if class == 0x30 || class == 0x70 || class == 0xB0 {
        // Try BEEF0004 extension for long (Unicode) name first
        if let Some(long) = long_name_beef0004(item) { return long; }
        // Fall back to short name at offset 14
        if item.len() <= 14 { return String::new(); }
        // Unicode short name when type has bit 0x04 set or is specifically 0xB1
        if t & 0x04 != 0 || t == 0xB1 {
            utf16_null(item, 14)
        } else {
            ascii_null(item, 14)
        }
    }
    // Network share / server (0x40–0x4F): ASCII name at offset 5
    else if class == 0x40 {
        if item.len() > 5 { ascii_null(item, 5) } else { String::new() }
    }
    else { String::new() }
}

// ── BagMRU tree walk ──────────────────────────────────────────────────────────

fn walk(
    data:     &[u8],
    idx:      &HashMap<u32, Nk>,
    cur_rel:  u32,
    cur_path: String,
    events:   &mut Vec<(i64, String)>,
    depth:    usize,
) {
    if depth > 30 { return; }

    let Some(nk) = idx.get(&cur_rel) else { return };

    // Build value_index: numeric value name → decoded path component
    let mut vi: HashMap<u32, String> = HashMap::new();
    for (vname, raw) in nk_values(data, nk) {
        if vname.eq_ignore_ascii_case("MRUListEx") || vname.eq_ignore_ascii_case("MRUList") {
            continue;
        }
        if let Ok(n) = vname.parse::<u32>() {
            let comp = decode_shell_item(&raw);
            if !comp.is_empty() { vi.insert(n, comp); }
        }
    }

    // Recurse into each child subkey
    for child_rel in subkey_rels(data, nk) {
        let Some(child_nk) = idx.get(&child_rel) else { continue };

        // Child name is numeric — look up decoded component in parent's values
        let idx_num: Option<u32> = child_nk.name.parse().ok();
        let decoded = idx_num.and_then(|n| vi.get(&n)).map(String::as_str);
        // Skip children whose shell item couldn't be decoded (no fallback to numeric name)
        let component = match decoded {
            Some(s) => s,
            None => continue,
        };

        let child_path = if cur_path.is_empty() {
            component.to_string()
        } else {
            format!("{}\\{}", cur_path, component)
        };

        if child_nk.last_write_ns > 0 && !child_path.is_empty() {
            events.push((child_nk.last_write_ns, child_path.clone()));
        }

        walk(data, idx, child_rel, child_path, events, depth + 1);
    }
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Parse ShellBags from a registry hive (UsrClass.dat or NTUSER.DAT).
/// Each event records when a folder was last browsed in Explorer.
#[pyfunction]
pub fn parse_shellbags(py: Python<'_>, hive_path: &str) -> PyResult<Py<PyList>> {
    let list = PyList::empty_bound(py);

    let data = match fs::read(hive_path) {
        Ok(d) => d,
        Err(_) => return Ok(list.into()),
    };
    if data.len() < 4096 || &data[..4] != b"regf" { return Ok(list.into()); }

    let idx = parse_nk_index(&data);

    // Find root NK (NK_FLAG_ROOT = 0x04)
    let root_rel = match idx.iter().find(|(_, nk)| nk.flags & 0x04 != 0) {
        Some((&rel, _)) => rel,
        None => return Ok(list.into()),
    };

    // BagMRU lives at different paths depending on the hive.
    // UsrClass.dat root == HKCU\Software\Classes, so path starts at Local Settings\.
    // NTUSER.DAT root == HKCU, so path starts at Software\.
    let paths: &[&[&str]] = &[
        // UsrClass.dat (Win8+, primary shellbag location)
        &["Local Settings", "Software", "Microsoft", "Windows", "Shell", "BagMRU"],
        // NTUSER.DAT (Win7 and secondary)
        &["Software", "Microsoft", "Windows", "Shell", "BagMRU"],
        // NTUSER.DAT alternate
        &["Software", "Microsoft", "Windows", "ShellNoRoam", "BagMRU"],
    ];

    let bagmru_rel = paths.iter().find_map(|p| navigate(&data, &idx, root_rel, p));
    let Some(bagmru_rel) = bagmru_rel else { return Ok(list.into()); };

    let mut events: Vec<(i64, String)> = Vec::new();
    walk(&data, &idx, bagmru_rel, String::new(), &mut events, 0);

    events.sort_unstable_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    events.dedup_by_key(|(ts, path)| (*ts, path.clone()));

    for (ts_ns, path) in events {
        let d = PyDict::new_bound(py);
        d.set_item("timestamp_ns",    ts_ns)?;
        d.set_item("timestamp_iso",   crate::utils::timestamps::ns_to_iso(ts_ns))?;
        d.set_item("macb",            "M")?;
        d.set_item("source",          "SHELLBAG")?;
        d.set_item("artifact",        "ShellBag")?;
        d.set_item("file_path",       &path)?;
        d.set_item("message",         format!("ShellBag: {}", path))?;
        d.set_item("is_fn_timestamp", false)?;
        d.set_item("tz_offset_secs",  0i32)?;
        list.append(d)?;
    }

    Ok(list.into())
}
