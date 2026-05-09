"""
Windows Timeline parser — ActivitiesCache.db (SQLite).

Located at: AppData/Local/ConnectedDevicesPlatform/{profile}/ActivitiesCache.db
Tables: Activity, ActivityOperation

Key columns in Activity:
  AppId             TEXT  — JSON array: [{"platform":"...", "application":"..."}]
  ActivityType      INT   — 5=app focus, 6=clipboard, 11=user-engaged
  LastModifiedTime  INT   — Unix seconds (not ms)
  StartTime         INT   — Unix seconds
  EndTime           INT   — Unix seconds
  Payload           TEXT  — JSON with file paths, content, display text
  ClipboardPayload  TEXT  — JSON with clipboard content (type 6)
"""

import sqlite3
import shutil
import tempfile
import os
import json
import logging
from pathlib import Path
from typing import List, Dict, Any

log = logging.getLogger(__name__)

_ACTIVITY_TYPES = {
    5:  "App Focus",
    6:  "Clipboard",
    11: "User Engaged",
    12: "Copy/Paste",
    15: "User Activity",
    16: "Background Activity",
}


def _unix_s_to_ns(secs: int) -> int:
    if not secs or secs <= 0:
        return 0
    return secs * 1_000_000_000


def _extract_app_name(app_id_json: str) -> str:
    """Parse AppId JSON array and return the most descriptive application name."""
    try:
        entries = json.loads(app_id_json)
        if not isinstance(entries, list):
            return ""
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            app = entry.get("application", "") or ""
            if app and "\\" in app:
                return Path(app).name
            if app:
                return app
        return ""
    except Exception:
        return ""


def _extract_payload_info(payload_json: str) -> str:
    """Pull display text or file path from the Payload JSON blob."""
    if not payload_json:
        return ""
    try:
        data = json.loads(payload_json)
        if not isinstance(data, dict):
            return ""
        # Common keys in timeline payload
        for key in ("displayText", "description", "contentUri", "activationUri"):
            val = data.get(key, "")
            if val and isinstance(val, str):
                return val.strip()
        # Nested: userTimeline > payload > displayText
        inner = data.get("userTimeline") or data.get("payload") or {}
        if isinstance(inner, str):
            try:
                inner = json.loads(inner)
            except Exception:
                return ""
        if isinstance(inner, dict):
            for key in ("displayText", "description", "contentUri"):
                val = inner.get(key, "")
                if val and isinstance(val, str):
                    return val.strip()
    except Exception:
        pass
    return ""


def parse_wintimeline(db_path: str) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    conn = tmp = None
    try:
        fd, tmp = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        shutil.copy2(db_path, tmp)
        conn = sqlite3.connect(tmp)
        conn.row_factory = sqlite3.Row

        cur = conn.execute(
            "SELECT AppId, ActivityType, StartTime, EndTime, LastModifiedTime, Payload "
            "FROM Activity "
            "WHERE StartTime > 0 OR LastModifiedTime > 0 "
            "ORDER BY StartTime DESC LIMIT 100000"
        )
        for row in cur:
            ts_ns = _unix_s_to_ns(row["StartTime"] or row["LastModifiedTime"])
            if ts_ns == 0:
                continue

            app_name   = _extract_app_name(row["AppId"] or "")
            act_type   = _ACTIVITY_TYPES.get(row["ActivityType"], f"Type{row['ActivityType']}")
            payload    = _extract_payload_info(row["Payload"] or "")
            file_path  = payload if payload else db_path

            msg_parts = [f"Timeline: {act_type}"]
            if app_name:
                msg_parts.append(f"app={app_name}")
            if payload:
                msg_parts.append(payload[:120])

            events.append({
                "timestamp_ns":    ts_ns,
                "macb":            "M",
                "source":          "WINTIMELINE",
                "artifact":        "Windows Timeline",
                "file_path":       file_path,
                "message":         " | ".join(msg_parts),
                "is_fn_timestamp": False,
                "tz_offset_secs":  0,
            })

    except Exception as e:
        log.warning("Windows Timeline parse failed for %s: %s", db_path, e)
    finally:
        if conn:
            conn.close()
        if tmp and os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass

    return events
