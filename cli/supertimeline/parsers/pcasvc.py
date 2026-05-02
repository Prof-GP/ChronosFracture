"""
PcaSvc (Program Compatibility Assistant Service) parser.
Windows 11 22H2+ execution artifact.

Files parsed:
  PcaAppLaunchDic.txt  — ANSI CP-1252, pipe-delimited; path|last_exec_timestamp (UTC)
  PcaGeneralDb0.txt    — UTF-16LE, pipe-delimited; 8 fields including timestamp + detail
  PcaGeneralDb1.txt    — Same format as PcaGeneralDb0; backup file (rotated at ~2 MB)

Limitations:
  - Only captures GUI-launched executables (Explorer, RDP, downloads, installers).
  - Does NOT capture command-line, PowerShell, WMI, or scheduled-task execution.
  - Paths are lowercased and partially redacted (%USERNAME%, %USERPROFILE%).
  - Non-ANSI characters in PcaAppLaunchDic.txt may truncate subsequent entries.
"""

from __future__ import annotations

import datetime
import logging
from pathlib import Path
from typing import List, Dict, Any

from supertimeline.utils.timestamps import unix_ns_to_iso

log = logging.getLogger(__name__)

# PcaGeneralDb run-status codes
_STATUS_NAMES: Dict[int, str] = {
    0: "Install failure",
    1: "Driver/kernel block",
    2: "Abnormal exit",
    3: "PCA resolver invoked",
    4: "Unset",
}


def _parse_timestamp(ts: str) -> int:
    """Parse 'YYYY-MM-DD HH:MM:SS.fff' UTC → nanoseconds since Unix epoch. Returns 0 on failure."""
    ts = ts.strip()
    try:
        dt = datetime.datetime.strptime(ts, "%Y-%m-%d %H:%M:%S.%f")
        return int(dt.replace(tzinfo=datetime.timezone.utc).timestamp() * 1_000_000_000)
    except ValueError:
        pass
    try:
        dt = datetime.datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
        return int(dt.replace(tzinfo=datetime.timezone.utc).timestamp() * 1_000_000_000)
    except ValueError:
        return 0


def _parse_app_launch_dic(path: str) -> List[Dict[str, Any]]:
    """
    Parse PcaAppLaunchDic.txt.
    Encoding: ANSI CP-1252. Format: <exe_path>|<UTC timestamp>
    """
    events: List[Dict[str, Any]] = []
    try:
        text = Path(path).read_text(encoding="cp1252", errors="replace")
    except OSError as exc:
        log.warning("PcaSvc: cannot read %s — %s", path, exc)
        return events

    for lineno, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split("|", 1)
        if len(parts) != 2:
            log.debug("PcaSvc AppLaunchDic line %d: unexpected format %r", lineno, line)
            continue

        exe_path, ts_str = parts[0].strip(), parts[1].strip()
        ns = _parse_timestamp(ts_str)
        if ns == 0:
            log.debug("PcaSvc AppLaunchDic line %d: unparseable timestamp %r", lineno, ts_str)
            continue

        events.append({
            "timestamp_ns":    ns,
            "timestamp_iso":   unix_ns_to_iso(ns),
            "macb":            "M",
            "source":          "PCASVC",
            "artifact":        "PcaAppLaunchDic",
            "file_path":       exe_path,
            "message":         f"Executed (GUI): {exe_path}",
            "is_fn_timestamp": False,
            "tz_offset_secs":  0,
        })

    log.debug("PcaSvc AppLaunchDic: %d events from %s", len(events), path)
    return events


def _parse_general_db(path: str) -> List[Dict[str, Any]]:
    """
    Parse PcaGeneralDb0.txt or PcaGeneralDb1.txt.
    Encoding: UTF-16LE. Format: 8 pipe-delimited fields.
    Field order: timestamp|status_code|exe_path|description|company|version|program_id|exit_info
    NOTE: field order is empirically derived; treat non-timestamp fields as best-effort.
    """
    events: List[Dict[str, Any]] = []
    try:
        text = Path(path).read_text(encoding="utf-16-le", errors="replace")
    except (OSError, UnicodeDecodeError):
        try:
            # Some files have a UTF-16LE BOM (FF FE) — let Python auto-detect
            text = Path(path).read_text(encoding="utf-16", errors="replace")
        except OSError as exc:
            log.warning("PcaSvc: cannot read %s — %s", path, exc)
            return events

    for lineno, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip().lstrip("\ufeff")  # strip BOM if present on first line
        if not line:
            continue

        parts = line.split("|")
        if len(parts) < 3:
            continue

        ts_str    = parts[0].strip()
        ns = _parse_timestamp(ts_str)
        if ns == 0:
            log.debug("PcaSvc GeneralDb %s line %d: unparseable timestamp %r", path, lineno, ts_str)
            continue

        try:
            status_code = int(parts[1].strip())
        except (ValueError, IndexError):
            status_code = -1
        status_name = _STATUS_NAMES.get(status_code, f"status={status_code}")

        exe_path    = parts[2].strip() if len(parts) > 2 else ""
        company     = parts[4].strip() if len(parts) > 4 else ""
        version     = parts[5].strip() if len(parts) > 5 else ""
        exit_info   = parts[7].strip() if len(parts) > 7 else ""

        detail_parts = [f"Status: {status_name}"]
        if exe_path:
            detail_parts.append(f"Path: {exe_path}")
        if company:
            detail_parts.append(f"By: {company}")
        if version:
            detail_parts.append(f"v{version}")
        if exit_info:
            detail_parts.append(exit_info)

        events.append({
            "timestamp_ns":    ns,
            "timestamp_iso":   unix_ns_to_iso(ns),
            "macb":            "M",
            "source":          "PCASVC",
            "artifact":        "PcaGeneralDb",
            "file_path":       exe_path,
            "message":         "PCA: " + " | ".join(detail_parts),
            "is_fn_timestamp": False,
            "tz_offset_secs":  0,
        })

    log.debug("PcaSvc GeneralDb: %d events from %s", len(events), path)
    return events


def parse(pca_path: str) -> List[Dict[str, Any]]:
    """
    Entry point. Dispatches to the appropriate sub-parser based on filename.
    """
    name = Path(pca_path).name.lower()
    if name == "pcaapplaunchdic.txt":
        return _parse_app_launch_dic(pca_path)
    if name in ("pcageneraldb0.txt", "pcageneraldb1.txt"):
        return _parse_general_db(pca_path)
    log.debug("PcaSvc: unrecognised file %s — skipping", pca_path)
    return []
