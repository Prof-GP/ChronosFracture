"""
Browser artifact parser — Chrome, Edge (Chromium), Firefox.

Chrome/Edge History SQLite:
  urls(id, url, title, visit_count, last_visit_time)  — last_visit_time: WebKit epoch (microseconds since 1601-01-01)
  visits(id, url, visit_time, ...)
  downloads(id, current_path, target_path, start_time, end_time, site_url, tab_url, received_bytes, total_bytes, state)

Firefox places.sqlite:
  moz_places(id, url, title, visit_count, last_visit_date)  — last_visit_date: microseconds since Unix epoch
  moz_historyvisits(id, place_id, visit_date, visit_type)
"""

import sqlite3
import shutil
import tempfile
import os
import logging
from pathlib import Path
from typing import List, Dict, Any

log = logging.getLogger(__name__)

# WebKit epoch: microseconds since 1601-01-01 00:00:00 UTC
_WEBKIT_EPOCH_US = 11_644_473_600 * 1_000_000


def _webkit_us_to_ns(webkit_us: int) -> int:
    """Convert WebKit timestamp (µs since 1601-01-01) to nanoseconds since Unix epoch."""
    if not webkit_us or webkit_us <= 0:
        return 0
    unix_us = webkit_us - _WEBKIT_EPOCH_US
    if unix_us <= 0:
        return 0
    return unix_us * 1000


def _unix_us_to_ns(unix_us: int) -> int:
    """Convert Unix microseconds to nanoseconds."""
    if not unix_us or unix_us <= 0:
        return 0
    return unix_us * 1000


def _open_db_copy(db_path: str):
    """
    Open a SQLite DB via a temp copy — the original may be locked by a running browser.
    Returns (connection, temp_path). Caller must close conn and delete temp_path.
    """
    tmp = tempfile.mktemp(suffix=".db")
    shutil.copy2(db_path, tmp)
    conn = sqlite3.connect(tmp)
    conn.row_factory = sqlite3.Row
    return conn, tmp


def _parse_chromium_history(db_path: str, browser: str) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    conn = tmp = None
    try:
        conn, tmp = _open_db_copy(db_path)

        # Visit events from moz_historyvisits-equivalent (visits table)
        try:
            cur = conn.execute(
                "SELECT v.visit_time, u.url, u.title "
                "FROM visits v JOIN urls u ON v.url = u.id "
                "WHERE v.visit_time > 0 "
                "ORDER BY v.visit_time DESC LIMIT 50000"
            )
            for row in cur:
                ts_ns = _webkit_us_to_ns(row[0])
                if ts_ns == 0:
                    continue
                url   = row[1] or ""
                title = row[2] or ""
                msg   = f"Browser Visit: {url}"
                if title and title != url:
                    msg += f' - "{title}"'
                msg += f" [{browser}]"
                events.append({
                    "timestamp_ns":    ts_ns,
                    "macb":            "M",
                    "source":          "BROWSER",
                    "artifact":        f"Browser Visit ({browser})",
                    "file_path":       url,
                    "message":         msg,
                    "is_fn_timestamp": False,
                    "tz_offset_secs":  0,
                })
        except sqlite3.Error as e:
            log.debug("[%s] visits query failed: %s", browser, e)

        # Download events
        try:
            cur = conn.execute(
                "SELECT start_time, target_path, tab_url, received_bytes, total_bytes "
                "FROM downloads WHERE start_time > 0"
            )
            for row in cur:
                ts_ns = _webkit_us_to_ns(row[0])
                if ts_ns == 0:
                    continue
                target  = row[1] or ""
                src_url = row[2] or ""
                size    = row[3] or row[4] or 0
                fname   = Path(target).name if target else "unknown"
                msg = f"Browser Download: {fname}"
                if src_url:
                    msg += f" from {src_url}"
                msg += f" [{browser}]"
                if size:
                    msg += f" ({size:,} bytes)"
                events.append({
                    "timestamp_ns":    ts_ns,
                    "macb":            "M",
                    "source":          "BROWSER",
                    "artifact":        f"Browser Download ({browser})",
                    "file_path":       target or src_url,
                    "message":         msg,
                    "is_fn_timestamp": False,
                    "tz_offset_secs":  0,
                })
        except sqlite3.Error as e:
            log.debug("[%s] downloads query failed: %s", browser, e)

    except Exception as e:
        log.warning("[%s] failed to parse %s: %s", browser, db_path, e)
    finally:
        if conn:
            conn.close()
        if tmp and os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass

    return events


def _parse_firefox_places(db_path: str) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    conn = tmp = None
    try:
        conn, tmp = _open_db_copy(db_path)

        # Visit events
        try:
            cur = conn.execute(
                "SELECT h.visit_date, p.url, p.title "
                "FROM moz_historyvisits h JOIN moz_places p ON h.place_id = p.id "
                "WHERE h.visit_date > 0 "
                "ORDER BY h.visit_date DESC LIMIT 50000"
            )
            for row in cur:
                ts_ns = _unix_us_to_ns(row[0])
                if ts_ns == 0:
                    continue
                url   = row[1] or ""
                title = row[2] or ""
                msg   = f"Browser Visit: {url}"
                if title and title != url:
                    msg += f' - "{title}"'
                msg += " [Firefox]"
                events.append({
                    "timestamp_ns":    ts_ns,
                    "macb":            "M",
                    "source":          "BROWSER",
                    "artifact":        "Browser Visit (Firefox)",
                    "file_path":       url,
                    "message":         msg,
                    "is_fn_timestamp": False,
                    "tz_offset_secs":  0,
                })
        except sqlite3.Error as e:
            log.debug("[Firefox] visits query failed: %s", e)

        # Downloads via moz_annos (modern Firefox stores downloads inline in places)
        try:
            cur = conn.execute(
                "SELECT a.dateAdded, p.url, a.content "
                "FROM moz_annos a JOIN moz_places p ON a.place_id = p.id "
                "WHERE a.anno_attribute_id IN ("
                "  SELECT id FROM moz_anno_attributes WHERE name='downloads/destinationFileURI'"
                ") AND a.dateAdded > 0"
            )
            for row in cur:
                ts_ns = _unix_us_to_ns(row[0])
                if ts_ns == 0:
                    continue
                src_url  = row[1] or ""
                dest_uri = row[2] or ""
                # dest_uri is like file:///C:/Users/.../file.ext
                dest = dest_uri.replace("file:///", "").replace("/", "\\") if dest_uri else ""
                fname = Path(dest).name if dest else "unknown"
                msg = f"Browser Download: {fname} from {src_url} [Firefox]"
                events.append({
                    "timestamp_ns":    ts_ns,
                    "macb":            "M",
                    "source":          "BROWSER",
                    "artifact":        "Browser Download (Firefox)",
                    "file_path":       dest or src_url,
                    "message":         msg,
                    "is_fn_timestamp": False,
                    "tz_offset_secs":  0,
                })
        except sqlite3.Error as e:
            log.debug("[Firefox] downloads query failed: %s", e)

    except Exception as e:
        log.warning("[Firefox] failed to parse %s: %s", db_path, e)
    finally:
        if conn:
            conn.close()
        if tmp and os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass

    return events


def parse_browser_db(db_path: str) -> List[Dict[str, Any]]:
    """Dispatch to the right parser based on path heuristics."""
    p = Path(db_path)
    lower = str(p).lower()

    if "firefox" in lower or p.name.lower() == "places.sqlite":
        return _parse_firefox_places(db_path)

    if "edge" in lower:
        return _parse_chromium_history(db_path, "Edge")

    # Default: Chrome
    return _parse_chromium_history(db_path, "Chrome")
