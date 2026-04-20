"""
SRUM (System Resource Usage Monitor) parser.
Reads SRUDB.dat (ESE/JET database) via pyesedb.

Tables parsed:
  {D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}  Application Timeline
  {973F5D5C-1D90-4944-BE8E-24B94231A174}  Network Usage
  SruDbIdMapTable                          ID → path/SID resolution
"""

from __future__ import annotations

import logging
from typing import List, Dict, Any, Optional

log = logging.getLogger(__name__)

# GUID prefixes (uppercase, no braces) that identify each table
_APP_TIMELINE_GUID = "D10CA2FE"
_NETWORK_USAGE_GUID = "973F5D5C"

# ── ESE helpers ───────────────────────────────────────────────────────────────

def _column_map(table) -> Dict[str, int]:
    """Return {column_name_lower: column_index} for a pyesedb table."""
    m: Dict[str, int] = {}
    for i in range(table.get_number_of_columns()):
        col = table.get_column(i)
        m[col.name.lower()] = i
    return m


def _column_types(table) -> Dict[int, int]:
    """Return {column_index: pyesedb_column_type} for a table."""
    m: Dict[int, int] = {}
    for i in range(table.get_number_of_columns()):
        m[i] = table.get_column(i).type
    return m


# pyesedb column type 8 = JET_coltypDateTime (OLE Automation Date, 64-bit double)
_ESE_COLTYPE_DATETIME = 8
# OLE Automation Date epoch offset vs Unix epoch (days)
_OLE_UNIX_EPOCH_DAYS = 25569.0


def _ole_date_to_unix_ns(raw: bytes) -> int:
    """Convert 8-byte little-endian OLE Automation Date to Unix nanoseconds."""
    import struct
    if len(raw) != 8:
        return 0
    ole_days = struct.unpack("<d", raw)[0]
    if ole_days <= 0:
        return 0
    unix_secs = (ole_days - _OLE_UNIX_EPOCH_DAYS) * 86400.0
    if unix_secs < 0:
        return 0
    return int(unix_secs * 1_000_000_000)


def _timestamp_val(record, idx: int, col_types: Dict[int, int]) -> int:
    """
    Read a timestamp column as Unix nanoseconds.
    Handles both OLE Automation Date (type 8) and FILETIME integer columns.
    """
    raw = None
    try:
        raw = record.get_value_data(idx)
    except Exception:
        return 0
    if not raw:
        return 0
    if col_types.get(idx) == _ESE_COLTYPE_DATETIME:
        return _ole_date_to_unix_ns(raw)
    # Fall back: treat as little-endian FILETIME integer
    import struct
    from supertimeline.utils.timestamps import filetime_to_unix_ns
    try:
        ft = struct.unpack("<Q", raw)[0]
        return filetime_to_unix_ns(ft)
    except Exception:
        return 0


def _int_val(record, idx: int) -> Optional[int]:
    try:
        return record.get_value_data_as_integer(idx)
    except Exception:
        return None


def _str_val(record, idx: int) -> Optional[str]:
    try:
        raw = record.get_value_data(idx)
        if raw is None:
            return None
        # UTF-16LE strings (paths in IdBlob)
        if len(raw) >= 2 and raw[1] == 0:
            return raw.decode("utf-16-le", errors="replace").rstrip("\x00")
        return raw.decode("utf-8", errors="replace").rstrip("\x00")
    except Exception:
        return None


def _decode_sid(raw: bytes) -> Optional[str]:
    """
    Decode a Windows binary SID (variable length) to its string form S-1-5-...
    Binary layout: [revision:1][sub_count:1][authority:6][sub_auth*4 each]
    """
    try:
        if len(raw) < 8:
            return None
        revision = raw[0]
        sub_count = raw[1]
        # IdentifierAuthority: 6 bytes, big-endian
        authority = int.from_bytes(raw[2:8], "big")
        if len(raw) < 8 + sub_count * 4:
            return None
        subs = [
            int.from_bytes(raw[8 + i*4 : 12 + i*4], "little")
            for i in range(sub_count)
        ]
        parts = [str(revision), str(authority)] + [str(s) for s in subs]
        return "S-" + "-".join(parts)
    except Exception:
        return None


def _float_val(record, idx: int) -> Optional[float]:
    try:
        raw = record.get_value_data(idx)
        if raw is None:
            return None
        import struct
        if len(raw) == 8:
            return struct.unpack("<d", raw)[0]
        if len(raw) == 4:
            return struct.unpack("<f", raw)[0]
        return None
    except Exception:
        return None


# ── ID map ────────────────────────────────────────────────────────────────────

def _build_id_map(db) -> Dict[int, str]:
    """
    Read SruDbIdMapTable and return {integer_id: display_string}.

    Columns of interest:
      IdIndex  — INTEGER (the key used in other tables)
      IdType   — 0 = path/exe, 1 = SID
      IdBlob   — UTF-16LE encoded string
    """
    id_map: Dict[int, str] = {}
    try:
        table = db.get_table_by_name("SruDbIdMapTable")
    except Exception:
        # Try iterating to find it
        table = None
        for i in range(db.get_number_of_tables()):
            t = db.get_table(i)
            if t.name == "SruDbIdMapTable":
                table = t
                break
    if table is None:
        return id_map

    cols = _column_map(table)
    idx_index = cols.get("idindex")
    idx_type  = cols.get("idtype")
    idx_blob  = cols.get("idblob")
    if idx_index is None or idx_blob is None:
        return id_map

    for rec_i in range(table.get_number_of_records()):
        try:
            record = table.get_record(rec_i)
            id_val   = _int_val(record, idx_index)
            id_type  = _int_val(record, idx_type) if idx_type is not None else 0
            raw_blob = record.get_value_data(idx_blob) if idx_blob is not None else None
            if id_val is None or raw_blob is None:
                continue

            if id_type == 3:
                # Binary SID blob (IdType=3)
                display = _decode_sid(raw_blob) or raw_blob.hex()
            else:
                # IdType=0 (auto-generated path) or IdType=1 (service name) — both UTF-16LE
                display = _str_val(record, idx_blob) or ""
                # Strip SRUM auto-path prefix: "!!filename!timestamp!hash!group" → "filename"
                if display.startswith("!!"):
                    parts = display.split("!")
                    display = parts[2] if len(parts) > 2 else display.lstrip("!")

            if display:
                id_map[id_val] = display
        except Exception:
            continue

    log.debug("SRUM id_map: %d entries", len(id_map))
    return id_map


# ── Application Timeline parser ───────────────────────────────────────────────

def _parse_app_timeline(table, id_map: Dict[int, str], srum_path: str) -> List[Dict[str, Any]]:
    from supertimeline.utils.timestamps import unix_ns_to_iso

    cols = _column_map(table)
    ctypes = _column_types(table)
    # Required
    idx_ts     = cols.get("timestamp")
    idx_app    = cols.get("appid")
    if idx_ts is None or idx_app is None:
        log.warning("SRUM AppTimeline: missing expected columns, got: %s", list(cols))
        return []

    # Optional metrics
    idx_user       = cols.get("userid")
    idx_fg_cpu     = cols.get("foregroundcycletime")
    idx_bg_cpu     = cols.get("backgroundcycletime")
    idx_fg_ctx     = cols.get("foregroundcontextswitches")
    idx_bg_ctx     = cols.get("backgroundcontextswitches")
    idx_fg_bytes   = cols.get("foregroundbytesread")
    idx_bg_bytes   = cols.get("backgroundbytesread")
    idx_fg_write   = cols.get("foregroundbyteswritten")
    idx_bg_write   = cols.get("backgroundbyteswritten")

    events: List[Dict[str, Any]] = []
    n_records = table.get_number_of_records()

    for rec_i in range(n_records):
        try:
            record = table.get_record(rec_i)

            ts_ns = _timestamp_val(record, idx_ts, ctypes)
            if ts_ns == 0:
                continue

            app_id_raw = _int_val(record, idx_app)
            app_name   = id_map.get(app_id_raw, str(app_id_raw)) if app_id_raw is not None else "Unknown"

            user_id_raw = _int_val(record, idx_user) if idx_user is not None else None
            user_name   = id_map.get(user_id_raw, str(user_id_raw)) if user_id_raw is not None else ""

            # Build metric string from whatever columns are present
            metrics: List[str] = []
            fg_cpu = _int_val(record, idx_fg_cpu) if idx_fg_cpu is not None else None
            bg_cpu = _int_val(record, idx_bg_cpu) if idx_bg_cpu is not None else None
            if fg_cpu is not None:
                metrics.append(f"fg_cycles={fg_cpu:,}")
            if bg_cpu is not None:
                metrics.append(f"bg_cycles={bg_cpu:,}")
            fg_br = _int_val(record, idx_fg_bytes) if idx_fg_bytes is not None else None
            bg_br = _int_val(record, idx_bg_bytes) if idx_bg_bytes is not None else None
            fg_bw = _int_val(record, idx_fg_write) if idx_fg_write is not None else None
            bg_bw = _int_val(record, idx_bg_write) if idx_bg_write is not None else None
            if fg_br is not None:
                metrics.append(f"fg_read={fg_br:,}B")
            if bg_br is not None:
                metrics.append(f"bg_read={bg_br:,}B")
            if fg_bw is not None:
                metrics.append(f"fg_write={fg_bw:,}B")
            if bg_bw is not None:
                metrics.append(f"bg_write={bg_bw:,}B")

            msg_parts = [f"App: {app_name}"]
            if user_name:
                msg_parts.append(f"User: {user_name}")
            if metrics:
                msg_parts.append("  ".join(metrics))

            events.append({
                "timestamp_ns":    ts_ns,
                "timestamp_iso":   unix_ns_to_iso(ts_ns),
                "macb":            "M",
                "source":          "SRUM",
                "artifact":        "SRUM AppTimeline",
                "artifact_path":   srum_path,
                "message":         "  |  ".join(msg_parts),
                "is_fn_timestamp": False,
                "tz_offset_secs":  0,
            })
        except Exception as exc:
            log.debug("SRUM AppTimeline record %d error: %s", rec_i, exc)
            continue

    return events


# ── Network Usage parser ──────────────────────────────────────────────────────

def _parse_network_usage(table, id_map: Dict[int, str], srum_path: str) -> List[Dict[str, Any]]:
    from supertimeline.utils.timestamps import unix_ns_to_iso

    cols = _column_map(table)
    ctypes = _column_types(table)
    idx_ts   = cols.get("timestamp")
    idx_app  = cols.get("appid")
    if idx_ts is None or idx_app is None:
        log.warning("SRUM Network: missing expected columns, got: %s", list(cols))
        return []

    idx_user  = cols.get("userid")
    idx_sent  = cols.get("bytessent")
    idx_recv  = cols.get("bytesrecvd")
    idx_iface = cols.get("interfaceluid")

    events: List[Dict[str, Any]] = []
    n_records = table.get_number_of_records()

    for rec_i in range(n_records):
        try:
            record = table.get_record(rec_i)

            ts_ns = _timestamp_val(record, idx_ts, ctypes)
            if ts_ns == 0:
                continue

            app_id_raw = _int_val(record, idx_app)
            app_name   = id_map.get(app_id_raw, str(app_id_raw)) if app_id_raw is not None else "Unknown"

            user_id_raw = _int_val(record, idx_user) if idx_user is not None else None
            user_name   = id_map.get(user_id_raw, str(user_id_raw)) if user_id_raw is not None else ""

            sent = _int_val(record, idx_sent) if idx_sent is not None else None
            recv = _int_val(record, idx_recv) if idx_recv is not None else None

            msg_parts = [f"App: {app_name}"]
            if user_name:
                msg_parts.append(f"User: {user_name}")
            if sent is not None:
                msg_parts.append(f"sent={sent:,}B")
            if recv is not None:
                msg_parts.append(f"recv={recv:,}B")

            events.append({
                "timestamp_ns":    ts_ns,
                "timestamp_iso":   unix_ns_to_iso(ts_ns),
                "macb":            "M",
                "source":          "SRUM",
                "artifact":        "SRUM Network",
                "artifact_path":   srum_path,
                "message":         "  |  ".join(msg_parts),
                "is_fn_timestamp": False,
                "tz_offset_secs":  0,
            })
        except Exception as exc:
            log.debug("SRUM Network record %d error: %s", rec_i, exc)
            continue

    return events


# ── Public entry point ────────────────────────────────────────────────────────

def parse(srum_path: str) -> List[Dict[str, Any]]:
    """
    Parse SRUDB.dat. Returns empty list if pyesedb is unavailable.
    Requires: pip install libyal-python  (provides pyesedb)
    """
    try:
        import pyesedb
    except ImportError:
        log.debug("pyesedb not available — SRUM parser skipped")
        return []

    events: List[Dict[str, Any]] = []
    try:
        db = pyesedb.open(srum_path)
    except Exception as exc:
        log.warning("SRUM: could not open %s — %s", srum_path, exc)
        return []

    # Build ID resolution map first
    id_map = _build_id_map(db)

    n_tables = db.get_number_of_tables()
    for i in range(n_tables):
        try:
            table = db.get_table(i)
            name_upper = table.name.upper()

            if _APP_TIMELINE_GUID in name_upper:
                tbl_events = _parse_app_timeline(table, id_map, srum_path)
                log.info("SRUM AppTimeline: %d events", len(tbl_events))
                events.extend(tbl_events)

            elif _NETWORK_USAGE_GUID in name_upper:
                tbl_events = _parse_network_usage(table, id_map, srum_path)
                log.info("SRUM Network: %d events", len(tbl_events))
                events.extend(tbl_events)

        except Exception as exc:
            log.warning("SRUM: error reading table %d — %s", i, exc)
            continue

    log.info("SRUM total: %d events from %s", len(events), srum_path)
    return events
