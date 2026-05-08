use pyo3::prelude::*;
use pyo3::types::{PyList, PyDict};
use std::fs;
use std::path::{Path, PathBuf};
use rayon::prelude::*;
use quick_xml::events::Event;
use quick_xml::Reader;
use chrono::NaiveDateTime;

#[derive(Default)]
struct TaskRecord {
    date_ns:       i64,
    command:       String,
    arguments:     String,
    author:        String,
    trigger_start: String,
    trigger_type:  String,
}

/// Parse "2023-01-15T10:30:00[.0000000][Z]" → nanoseconds since Unix epoch (UTC).
fn parse_iso_dt(s: &str) -> i64 {
    let s = s.trim().trim_end_matches('Z');
    for fmt in &[
        "%Y-%m-%dT%H:%M:%S%.f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M",
    ] {
        if let Ok(dt) = NaiveDateTime::parse_from_str(s, fmt) {
            return dt.and_utc().timestamp_nanos_opt().unwrap_or(0);
        }
    }
    0
}

fn collect_task_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else { return; };
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_dir() {
            collect_task_files(&p, out);
        } else if p.is_file() {
            // Task files have no extension but we also skip known non-task files
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if !name.ends_with(".job") {  // .job are legacy AT tasks, skip for now
                out.push(p);
            }
        }
    }
}

fn task_relative_path(file: &Path, root: &Path) -> String {
    file.strip_prefix(root)
        .map(|p| format!("\\{}", p.to_string_lossy().replace('/', "\\")))
        .unwrap_or_else(|_| file.to_string_lossy().into_owned())
}

fn parse_task_xml(data: &str) -> Option<TaskRecord> {
    let mut rec = TaskRecord::default();
    let mut reader = Reader::from_str(data);
    reader.config_mut().trim_text(true);

    // Track element depth context using a small stack of tag names
    let mut stack: Vec<String> = Vec::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let tag = String::from_utf8_lossy(e.local_name().as_ref()).into_owned();
                // Track trigger type (first trigger element wins)
                if rec.trigger_type.is_empty() && tag.ends_with("Trigger") {
                    rec.trigger_type = tag.clone();
                }
                stack.push(tag);
            }
            Ok(Event::End(_)) => {
                stack.pop();
            }
            Ok(Event::Text(e)) => {
                let text = e.unescape().unwrap_or_default().trim().to_string();
                if text.is_empty() {
                    continue;
                }
                let path: Vec<&str> = stack.iter().map(|s| s.as_str()).collect();
                match path.as_slice() {
                    [.., "RegistrationInfo", "Date"]   => {
                        if rec.date_ns == 0 { rec.date_ns = parse_iso_dt(&text); }
                    }
                    [.., "RegistrationInfo", "Author"] => {
                        if rec.author.is_empty() { rec.author = text; }
                    }
                    [.., "Exec", "Command"]   => {
                        if rec.command.is_empty() { rec.command = text; }
                    }
                    [.., "Exec", "Arguments"] => {
                        if rec.arguments.is_empty() { rec.arguments = text; }
                    }
                    [.., "StartBoundary"] => {
                        if rec.trigger_start.is_empty() { rec.trigger_start = text; }
                    }
                    _ => {}
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
    }

    // Need at least a timestamp to produce a useful event
    if rec.date_ns == 0 && rec.trigger_start.is_empty() {
        return None;
    }
    Some(rec)
}

/// Parse all scheduled task XML files under a Tasks directory recursively.
/// Emits one event per task (RegistrationInfo/Date) plus a trigger event when
/// StartBoundary is present and differs from the registration date.
#[pyfunction]
pub fn parse_tasks_dir(py: Python<'_>, dir_path: &str) -> PyResult<Py<PyList>> {
    let list = PyList::empty_bound(py);
    let root = Path::new(dir_path);

    let mut files = Vec::new();
    collect_task_files(root, &mut files);

    let parsed: Vec<(String, TaskRecord)> = files
        .par_iter()
        .filter_map(|p| {
            let raw = fs::read(p).ok()?;
            // Task files may be UTF-16LE (BOM EF BB BF = UTF-8 BOM, FF FE = UTF-16LE)
            let text = if raw.starts_with(&[0xFF, 0xFE]) {
                let u16s: Vec<u16> = raw[2..]
                    .chunks_exact(2)
                    .map(|b| u16::from_le_bytes([b[0], b[1]]))
                    .collect();
                String::from_utf16_lossy(&u16s)
            } else {
                String::from_utf8_lossy(&raw).into_owned()
            };
            let rec = parse_task_xml(&text)?;
            let rel = task_relative_path(p, root);
            Some((rel, rec))
        })
        .collect();

    for (task_name, rec) in parsed {
        // Build action string
        let action = if rec.command.is_empty() {
            "(no action)".to_owned()
        } else if rec.arguments.is_empty() {
            rec.command.clone()
        } else {
            format!("{} {}", rec.command, rec.arguments)
        };

        // Build trigger string
        let trigger_label = if !rec.trigger_type.is_empty() {
            rec.trigger_type
                .trim_end_matches("Trigger")
                .to_lowercase()
        } else {
            String::new()
        };
        let trigger_str = match (trigger_label.as_str(), rec.trigger_start.as_str()) {
            ("", "") => String::new(),
            (t, "") => format!("Trigger: {}", t),
            ("", s) => format!("Trigger: {}", &s[..s.len().min(16)]),
            (t, s)  => format!("Trigger: {} @ {}", t, &s[..s.len().min(16)]),
        };

        let author_str = if rec.author.is_empty() {
            String::new()
        } else {
            format!(" | Author: {}", rec.author)
        };

        // Registration event (when the task was created/modified)
        let ts_ns = if rec.date_ns != 0 {
            rec.date_ns
        } else {
            parse_iso_dt(&rec.trigger_start)
        };

        if ts_ns == 0 {
            continue;
        }

        let mut msg = format!("Task: {} | Action: {}", task_name, action);
        if !trigger_str.is_empty() { msg.push_str(" | "); msg.push_str(&trigger_str); }
        if !author_str.is_empty()  { msg.push_str(&author_str); }

        let d = PyDict::new_bound(py);
        d.set_item("timestamp_ns",    ts_ns)?;
        d.set_item("timestamp_iso",   crate::utils::timestamps::ns_to_iso(ts_ns))?;
        d.set_item("macb",            "M")?;
        d.set_item("source",          "TASK")?;
        d.set_item("artifact",        "Scheduled Task")?;
        d.set_item("file_path",       &task_name)?;
        d.set_item("message",         msg)?;
        d.set_item("is_fn_timestamp", false)?;
        d.set_item("tz_offset_secs",  0i32)?;
        list.append(d)?;

        // Trigger event (when the task is scheduled to fire) — only if it differs
        if !rec.trigger_start.is_empty() && rec.date_ns != 0 {
            let trig_ns = parse_iso_dt(&rec.trigger_start);
            if trig_ns != 0 && trig_ns != rec.date_ns {
                let trig_msg = format!(
                    "Task Trigger: {} | Action: {} | {}",
                    task_name, action, trigger_str
                );
                let d2 = PyDict::new_bound(py);
                d2.set_item("timestamp_ns",    trig_ns)?;
                d2.set_item("timestamp_iso",   crate::utils::timestamps::ns_to_iso(trig_ns))?;
                d2.set_item("macb",            "M")?;
                d2.set_item("source",          "TASK")?;
                d2.set_item("artifact",        "Scheduled Task Trigger")?;
                d2.set_item("file_path",       &task_name)?;
                d2.set_item("message",         trig_msg)?;
                d2.set_item("is_fn_timestamp", false)?;
                d2.set_item("tz_offset_secs",  0i32)?;
                list.append(d2)?;
            }
        }
    }

    Ok(list.into())
}
