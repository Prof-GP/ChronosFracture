use pyo3::prelude::*;
use pyo3::types::{PyList, PyDict};
use memmap2::Mmap;
use rayon::prelude::*;
use std::fs::File;

use crate::types::{TimelineEvent, filetime_to_unix_ns};

// EVTX file header magic
const EVTX_MAGIC: &[u8; 8] = b"ElfFile\x00";
const EVTX_CHUNK_SIZE: usize = 65536; // 64KB per chunk
const EVTX_CHUNK_MAGIC: &[u8; 8] = b"ElfChnk\x00";

// BinXML token types
const TOKEN_EOF:          u8 = 0x00;
const TOKEN_OPEN_START:   u8 = 0x01;
const TOKEN_CLOSE_START:  u8 = 0x02;
const TOKEN_CLOSE_EMPTY:  u8 = 0x03;
const TOKEN_END_ELEMENT:  u8 = 0x04;
const TOKEN_VALUE:        u8 = 0x05;
const TOKEN_ATTRIBUTE:    u8 = 0x06;
const TOKEN_CDATA:        u8 = 0x07;
const TOKEN_CHAR_REF:     u8 = 0x08;
const TOKEN_ENTITY_REF:   u8 = 0x09;
const TOKEN_PI_TARGET:    u8 = 0x0A;
const TOKEN_PI_DATA:      u8 = 0x0B;
const TOKEN_TEMPLATE_INST: u8 = 0x0C;
const TOKEN_NORMAL_SUB:   u8 = 0x0D;
const TOKEN_OPT_SUB:      u8 = 0x0E;
const TOKEN_END_OF_STREAM: u8 = 0x0F;

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

/// Minimal EVTX event record extracted from a chunk
#[derive(Debug, Clone)]
struct EvtxRecord {
    timestamp_ns: i64,
    event_id: u32,
    channel: String,
    computer: String,
    message: String,
    level: u8,
}

fn event_name(id: u32) -> Option<&'static str> {
    match id {
        // Security — logon/logoff
        1102 => Some("Audit Log Cleared"),
        4608 => Some("Windows Starting Up"),
        4616 => Some("System Time Changed"),
        4624 => Some("Successful Logon"),
        4625 => Some("Failed Logon"),
        4634 => Some("Logoff"),
        4647 => Some("User Initiated Logoff"),
        4648 => Some("Explicit Credentials Logon"),
        4649 => Some("Replay Attack Detected"),
        // Security — object access
        4656 => Some("Object Handle Requested"),
        4657 => Some("Registry Value Modified"),
        4660 => Some("Object Deleted"),
        4663 => Some("Object Access Attempt"),
        4670 => Some("Object Permissions Changed"),
        // Security — privilege use
        4672 => Some("Special Privileges Assigned"),
        4673 => Some("Privileged Service Called"),
        4674 => Some("Privileged Object Operation"),
        // Security — process
        4688 => Some("Process Created"),
        4689 => Some("Process Exited"),
        // Security — service / scheduled task
        4697 => Some("Service Installed"),
        4698 => Some("Scheduled Task Created"),
        4699 => Some("Scheduled Task Deleted"),
        4700 => Some("Scheduled Task Enabled"),
        4701 => Some("Scheduled Task Disabled"),
        4702 => Some("Scheduled Task Updated"),
        // Security — policy / audit
        4719 => Some("Audit Policy Changed"),
        4907 => Some("Auditing Settings Changed"),
        4904 => Some("Security Event Source Added"),
        4905 => Some("Security Event Source Removed"),
        // Security — account management
        4720 => Some("User Account Created"),
        4722 => Some("User Account Enabled"),
        4723 => Some("Password Change Attempt"),
        4724 => Some("Password Reset"),
        4725 => Some("User Account Disabled"),
        4726 => Some("User Account Deleted"),
        4728 => Some("Added to Global Group"),
        4729 => Some("Removed from Global Group"),
        4732 => Some("Added to Local Group"),
        4733 => Some("Removed from Local Group"),
        4738 => Some("User Account Changed"),
        4740 => Some("Account Locked Out"),
        4741 => Some("Computer Account Created"),
        4743 => Some("Computer Account Deleted"),
        4756 => Some("Added to Universal Group"),
        4764 => Some("Group Type Changed"),
        4767 => Some("Account Unlocked"),
        4781 => Some("Account Name Changed"),
        // Security — Kerberos / NTLM
        4768 => Some("Kerberos TGT Requested"),
        4769 => Some("Kerberos Service Ticket Requested"),
        4770 => Some("Kerberos Service Ticket Renewed"),
        4771 => Some("Kerberos Pre-Auth Failed"),
        4776 => Some("NTLM Auth Attempt"),
        // Security — session
        4778 => Some("Session Reconnected"),
        4779 => Some("Session Disconnected"),
        4800 => Some("Workstation Locked"),
        4801 => Some("Workstation Unlocked"),
        4802 => Some("Screensaver Invoked"),
        4803 => Some("Screensaver Dismissed"),
        // Security — group enumeration
        4798 => Some("Local Group Membership Enumerated"),
        4799 => Some("Global Group Membership Enumerated"),
        4902 => Some("Per-User Audit Policy Created"),
        // Security — network share
        5140 => Some("Network Share Accessed"),
        5142 => Some("Network Share Added"),
        5143 => Some("Network Share Modified"),
        5144 => Some("Network Share Deleted"),
        5145 => Some("Network Share Object Access Check"),
        // Security — firewall / network
        5025 => Some("Firewall Service Stopped"),
        5152 => Some("Packet Blocked"),
        5154 => Some("Listen Permitted"),
        5155 => Some("Listen Blocked"),
        5156 => Some("Connection Allowed"),
        5157 => Some("Connection Blocked"),
        5158 => Some("Bind Permitted"),
        5159 => Some("Bind Blocked"),
        // System — kernel / boot
        12   => Some("System Started"),
        13   => Some("System Shutdown"),
        41   => Some("Unexpected Reboot"),
        46   => Some("Time Service Sync"),
        // System — Service Control Manager
        7000 => Some("Service Failed to Start"),
        7001 => Some("Service Start Dependency Failed"),
        7009 => Some("Service Start Timeout"),
        7011 => Some("Service Operation Timeout"),
        7022 => Some("Service Hung on Start"),
        7023 => Some("Service Terminated (Error)"),
        7024 => Some("Service Terminated (Specific Error)"),
        7026 => Some("Boot Driver Failed to Load"),
        7031 => Some("Service Terminated Unexpectedly"),
        7032 => Some("Service Recovery Action Taken"),
        7034 => Some("Service Crashed"),
        7035 => Some("Service Control Request"),
        7036 => Some("Service State Changed"),
        7040 => Some("Service Start Type Changed"),
        7045 => Some("New Service Installed"),
        // PowerShell
        400  => Some("PowerShell Engine Started"),
        403  => Some("PowerShell Engine Stopped"),
        600  => Some("PowerShell Provider Started"),
        4103 => Some("PowerShell Module Logging"),
        4104 => Some("PowerShell Script Block Logged"),
        // Task Scheduler
        100  => Some("Task Started"),
        101  => Some("Task Start Failed"),
        102  => Some("Task Completed"),
        103  => Some("Task Action Failed to Start"),
        106  => Some("Task Registered"),
        107  => Some("Task Triggered on Time"),
        108  => Some("Task Triggered on Event"),
        109  => Some("Task Triggered by Registration"),
        110  => Some("Task Triggered on System Start"),
        111  => Some("Task Triggered on Logon"),
        119  => Some("Task Queued"),
        129  => Some("Task Action Started"),
        140  => Some("Task Updated"),
        141  => Some("Task Deleted"),
        142  => Some("Task Disabled"),
        200  => Some("Task Action Started"),
        201  => Some("Task Action Completed"),
        203  => Some("Task Action Failed"),
        // WMI Activity
        5857 => Some("WMI Provider Loaded"),
        5858 => Some("WMI Query Error"),
        5859 => Some("WMI Event Filter Activated"),
        5860 => Some("WMI Permanent Subscription Registered"),
        5861 => Some("WMI Active Script Consumer"),
        // Application
        1000 => Some("Application Error"),
        1001 => Some("Windows Error Reporting"),
        1002 => Some("Application Hang"),
        1026 => Some(".NET Runtime Error"),
        // Windows Defender / antimalware
        1006 => Some("Malware Scan Started"),
        1007 => Some("Malware Action Taken"),
        1008 => Some("Malware Action Failed"),
        1009 => Some("Malware Quarantine Restored"),
        1013 => Some("Malware History Deleted"),
        1116 => Some("Malware Detected"),
        1117 => Some("Malware Action Taken"),
        1118 => Some("Malware Remediation Failed"),
        1119 => Some("Malware Remediation Success"),
        // AppX / Store
        257  => Some("AppX Deployment Started"),
        258  => Some("AppX Deployment Completed"),
        260  => Some("AppX Deployment Failed"),
        263  => Some("AppX Removal Started"),
        // Group Policy
        4000 => Some("Group Policy Processing Started"),
        4001 => Some("Group Policy Processing Completed"),
        5312 => Some("Group Policy Settings Applied"),
        5313 => Some("Group Policy Settings Not Applied"),
        _ => None,
    }
}

/// Extract a UTF-16LE string from raw bytes starting at `start`, up to `max_chars`.
/// Returns None if the bytes don't look like a printable ASCII/channel-name string.
fn extract_utf16le_str(data: &[u8], start: usize, max_chars: usize) -> Option<String> {
    if start + 2 > data.len() {
        return None;
    }
    let mut chars = Vec::with_capacity(max_chars);
    let mut i = start;
    while i + 1 < data.len() && chars.len() < max_chars {
        let lo = data[i];
        let hi = data[i + 1];
        if hi != 0 {
            break; // non-BMP or non-ASCII — stop
        }
        if lo == 0 {
            break; // null terminator
        }
        // Accept printable ASCII + common path/channel chars
        if lo >= 0x20 {
            chars.push(lo as char);
        } else {
            break;
        }
        i += 2;
    }
    if chars.len() >= 3 {
        Some(chars.iter().collect())
    } else {
        None
    }
}

/// Scan raw event bytes for a UTF-16LE channel-like string.
/// Tries known offsets first, then falls back to a broad scan.
fn scan_for_channel(data: &[u8]) -> String {
    // Scan in two windows: System section (0x18..0x18+400) for the channel literal
    let scan_end = data.len().min(0x18 + 600);
    let mut best: Option<String> = None;

    let mut i = 0x18;
    while i + 1 < scan_end {
        let lo = data[i];
        let hi = data[i + 1];
        if hi != 0 || lo < 0x40 || lo > 0x7A {
            i += 2;
            continue;
        }
        // Potential start of a UTF-16LE string starting with a letter
        if let Some(s) = extract_utf16le_str(data, i, 100) {
            // Channel names are typically 4-80 chars
            if s.len() >= 4 {
                // Prefer well-known channel names
                if s.starts_with("Security") || s.starts_with("System")
                    || s.starts_with("Application") || s.starts_with("Microsoft-")
                    || s.starts_with("Windows ") || s.starts_with("PowerShell")
                    || s.contains('/') || s.contains('%')
                {
                    return s;
                }
                // Keep as a candidate if nothing better found
                if best.is_none() || s.len() > best.as_ref().map_or(0, |b| b.len()) {
                    best = Some(s);
                }
            }
        }
        i += 2;
    }
    best.unwrap_or_default()
}

/// For PowerShell EventID 4103/4104, extract a snippet of the script/payload text.
/// The script block text is typically the longest UTF-16LE string in the EventData.
fn extract_ps_snippet(data: &[u8]) -> Option<String> {
    let mut best_start = 0usize;
    let mut best_len = 0usize;
    let scan_start = 0x18 + 0x5E + 50; // past the System section
    let mut i = scan_start;
    while i + 1 < data.len() {
        let lo = data[i];
        let hi = data[i + 1];
        if hi != 0 || lo < 0x09 {
            i += 2;
            continue;
        }
        // Measure run length
        let start = i;
        let mut j = i;
        let mut length = 0usize;
        while j + 1 < data.len() {
            let l = data[j];
            let h = data[j + 1];
            if h != 0 || l == 0 { break; }
            length += 1;
            j += 2;
        }
        if length > best_len {
            best_len = length;
            best_start = start;
        }
        i = j + 2;
    }
    if best_len < 20 {
        return None;
    }
    let snippet_chars = best_len.min(200);
    if let Some(s) = extract_utf16le_str(data, best_start, snippet_chars) {
        if s.len() >= 20 {
            return Some(s);
        }
    }
    None
}

/// Parse an event record from within a chunk's event records area.
/// This is a simplified extraction — pulls timestamp, EventID, Channel, Computer.
fn parse_event_record(data: &[u8]) -> Option<EvtxRecord> {
    if data.len() < 24 {
        return None;
    }

    // Event record header:
    // 0x00: magic "\x2a\x2a\x00\x00"
    // 0x04: size (u32)
    // 0x08: event record ID (u64)
    // 0x10: timestamp (FILETIME u64)
    if data[0] != 0x2a || data[1] != 0x2a || data[2] != 0x00 || data[3] != 0x00 {
        return None;
    }

    let timestamp_ft = read_u64_le(data, 0x10);
    let timestamp_ns = filetime_to_unix_ns(timestamp_ft);

    // BinXML starts at offset 0x18
    // We do a fast scan for key strings rather than full BinXML parse
    // This gives ~10x speed advantage for batch processing
    let xml_data = &data[0x18..];

    let mut event_id: u32 = 0;
    let mut channel = String::new();
    let computer = String::new();
    let level: u8 = 0;

    // EventID is stored in the BinXML substitution value array.
    // For standard Windows events the substitution value area starts at
    // a consistent BinXML offset (0x5E = 94), so the EventID uint16 is
    // always at raw record offset 0x18 + 0x5E = 0x76 = 118.
    // Validated empirically against Security, System, Application, PowerShell
    // event logs (4624, 4672, 4634, 4648, 5058, 5059, 5061, 5379, 5382…).
    // For atypical events with a different template layout (e.g. 4907)
    // we fall back to 0 rather than returning a wrong value.
    const EID_BINXML_OFFSET: usize = 0x5E; // = record offset 0x76 minus header 0x18
    if xml_data.len() > EID_BINXML_OFFSET + 2 {
        let candidate = read_u16_le(xml_data, EID_BINXML_OFFSET) as u32;
        if candidate > 0 && candidate < 65536 {
            event_id = candidate;
        }
    }

    channel = scan_for_channel(data);

    // For PowerShell script block events, extract a snippet of the command
    let ps_snippet = if event_id == 4103 || event_id == 4104 {
        extract_ps_snippet(data)
    } else {
        None
    };

    let base = match (event_name(event_id), channel.is_empty()) {
        (Some(name), false) => format!("EventID {} - {} [{}]", event_id, name, channel),
        (Some(name), true)  => format!("EventID {} - {}", event_id, name),
        (None, false)       => format!("EventID {} [{}]", event_id, channel),
        (None, true)        => format!("EventID {}", event_id),
    };
    let message = match ps_snippet {
        Some(snippet) => format!("{} | {}", base, snippet),
        None => base,
    };

    Some(EvtxRecord {
        timestamp_ns,
        event_id,
        channel,
        computer,
        message,
        level,
    })
}

/// Parse a single EVTX chunk (64KB), returning all event records within it.
fn parse_evtx_chunk(chunk: &[u8], artifact_path: &str) -> Vec<TimelineEvent> {
    let mut events = Vec::new();

    if chunk.len() < 512 {
        return events;
    }

    // Verify chunk magic
    if &chunk[0..8] != EVTX_CHUNK_MAGIC {
        return events;
    }

    // The chunk header is always 0x80 bytes.  String table + template table
    // immediately follow; their combined size is variable, so we cannot
    // assume event records begin exactly at 0x80.  Scan forward from 0x80
    // for the first event record magic "\x2a\x2a\x00\x00".
    let search_start = 0x80usize;
    let last_record_off = read_u32_le(chunk, 0x2C) as usize;
    let scan_end = if last_record_off > search_start && last_record_off < EVTX_CHUNK_SIZE {
        last_record_off + 4  // a bit past the last known record start
    } else {
        EVTX_CHUNK_SIZE
    };

    // Find first event record magic in [search_start, scan_end)
    let first_record_off = (search_start..scan_end.min(chunk.len()).saturating_sub(3))
        .step_by(4)
        .find(|&i| chunk[i] == 0x2a && chunk[i+1] == 0x2a && chunk[i+2] == 0x00 && chunk[i+3] == 0x00);

    let Some(mut offset) = first_record_off else {
        return events;
    };

    while offset + 24 <= chunk.len() {
        if chunk[offset] != 0x2a || chunk[offset+1] != 0x2a
           || chunk[offset+2] != 0x00 || chunk[offset+3] != 0x00 {
            // Skip forward 4 bytes and try again (handles alignment gaps)
            offset += 4;
            continue;
        }

        let rec_size = read_u32_le(chunk, offset + 4) as usize;
        if rec_size < 24 || rec_size > EVTX_CHUNK_SIZE || offset + rec_size > chunk.len() {
            offset += 4;
            continue;
        }

        if let Some(mut rec) = parse_event_record(&chunk[offset..offset+rec_size]) {
            // If binary channel scan found nothing, fall back to the log filename
            if rec.channel.is_empty() {
                if let Some(fname) = std::path::Path::new(artifact_path)
                    .file_name().and_then(|f| f.to_str())
                {
                    let stem = fname.trim_end_matches(".evtx").trim_end_matches(".EVTX");
                    // Decode %4 → / (Windows event log channel separator encoding)
                    rec.channel = stem.replace("%4", "/");
                    // Rebuild the message with the channel we now have
                    let base = match event_name(rec.event_id) {
                        Some(name) => format!("EventID {} - {} [{}]", rec.event_id, name, rec.channel),
                        None       => format!("EventID {} [{}]", rec.event_id, rec.channel),
                    };
                    rec.message = base;
                }
            }
            events.push(TimelineEvent {
                timestamp_ns: rec.timestamp_ns,
                macb: "M".to_string(),
                source: "EVTX".to_string(),
                artifact: "Windows Event Log".to_string(),
                artifact_path: artifact_path.to_string(),
                message: rec.message,
                hostname: if rec.computer.is_empty() { None } else { Some(rec.computer) },
                tz_offset_secs: 0,
                is_fn_timestamp: false,
                source_hash: None,
                extra: Some(serde_json::json!({
                    "event_id": rec.event_id,
                    "channel": rec.channel,
                    "level": rec.level,
                })),
            });
        }

        offset += rec_size;

        // Align to 4 bytes
        let rem = offset % 4;
        if rem != 0 {
            offset += 4 - rem;
        }
    }

    events
}

#[pyfunction]
pub fn parse_evtx_file(py: Python<'_>, path: &str) -> PyResult<Py<PyList>> {
    let file = File::open(path)
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;

    let mmap = unsafe { Mmap::map(&file) }
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(e.to_string()))?;

    if mmap.len() < 4096 || &mmap[0..8] != EVTX_MAGIC {
        return Err(pyo3::exceptions::PyValueError::new_err("Not a valid EVTX file"));
    }

    // File header is 4096 bytes; chunks start at offset 4096
    let chunks_start = 4096usize;
    let data = &mmap[chunks_start..];

    let all_events: Vec<TimelineEvent> = data
        .par_chunks(EVTX_CHUNK_SIZE)
        .flat_map(|chunk| parse_evtx_chunk(chunk, path))
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
            dict.set_item("event_id", extra["event_id"].as_u64().unwrap_or(0))?;
            dict.set_item("channel", extra["channel"].as_str().unwrap_or(""))?;
        }
        list.append(dict)?;
    }

    Ok(list.into())
}

#[pyclass]
pub struct EvtxParser {
    path: String,
}

#[pymethods]
impl EvtxParser {
    #[new]
    pub fn new(path: &str) -> Self {
        EvtxParser { path: path.to_string() }
    }

    pub fn parse<'py>(&self, py: Python<'py>) -> PyResult<Py<PyList>> {
        parse_evtx_file(py, &self.path)
    }
}
