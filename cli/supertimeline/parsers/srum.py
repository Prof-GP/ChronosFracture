"""
SRUM (System Resource Usage Monitor) parser.
Reads SRUDB.dat (ESE/JET database).

Primary backend: dissect.esedb (fox-it, pure Python, handles Win10/11 ESE format)
Fallback:        pyesedb (libyal, works on older Windows versions)

Tables parsed:
  {D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}  Application Timeline
  {973F5D5C-1D90-4944-BE8E-24B94231A174}  Network Usage
  SruDbIdMapTable                          ID → path/SID resolution
"""

from __future__ import annotations

import datetime as _dt
import logging
import os
import shutil
import struct
import subprocess
import sys
from typing import Any, Dict, List, Optional

log = logging.getLogger(__name__)

try:
    from dissect.esedb import EseDB as _DissectEseDB
    _HAS_DISSECT = True
except ImportError:
    _HAS_DISSECT = False

try:
    import pyesedb as _pyesedb
    _HAS_PYESEDB = True
except ImportError:
    _HAS_PYESEDB = False

_APP_TIMELINE_GUID       = "D10CA2FE"
_NETWORK_USAGE_GUID      = "973F5D5C"
_NETWORK_CONN_GUID       = "DD6636C4"

_OLE_UNIX_EPOCH_DAYS  = 25569.0
_ESE_COLTYPE_DATETIME = 8  # JET_coltypDateTime

# Well-known Windows SIDs → display names
_KNOWN_SIDS: Dict[str, str] = {
    "S-1-0-0":   "Null Authority",
    "S-1-1-0":   "Everyone",
    "S-1-2-0":   "Local",
    "S-1-3-0":   "Creator Owner",
    "S-1-3-1":   "Creator Group",
    "S-1-5-1":   "Dialup",
    "S-1-5-2":   "Network",
    "S-1-5-3":   "Batch",
    "S-1-5-4":   "Interactive",
    "S-1-5-6":   "Service",
    "S-1-5-7":   "Anonymous",
    "S-1-5-9":   "Enterprise Domain Controllers",
    "S-1-5-10":  "Principal Self",
    "S-1-5-11":  "Authenticated Users",
    "S-1-5-12":  "Restricted Code",
    "S-1-5-13":  "Terminal Server Users",
    "S-1-5-14":  "Remote Interactive Logon",
    "S-1-5-15":  "This Organization",
    "S-1-5-17":  "IUSR",
    "S-1-5-18":  "SYSTEM",
    "S-1-5-19":  "LOCAL SERVICE",
    "S-1-5-20":  "NETWORK SERVICE",
    "S-1-5-32-544": "Administrators",
    "S-1-5-32-545": "Users",
    "S-1-5-32-546": "Guests",
    "S-1-5-32-547": "Power Users",
    "S-1-5-32-548": "Account Operators",
    "S-1-5-32-549": "Server Operators",
    "S-1-5-32-550": "Print Operators",
    "S-1-5-32-551": "Backup Operators",
    "S-1-5-32-552": "Replicators",
    "S-1-5-32-555": "Remote Desktop Users",
    "S-1-5-32-556": "Network Configuration Operators",
    "S-1-5-32-558": "Performance Monitor Users",
    "S-1-5-32-559": "Performance Log Users",
    "S-1-5-32-568": "IIS_IUSRS",
    "S-1-5-32-580": "Remote Management Users",
}

# Column name variations across Windows versions / dissect versions
_TS_COLUMN_VARIANTS = ("TimeStamp", "Timestamp", "timestamp", "EventTime", "eventtime")


def _resolve_sid(sid: str) -> str:
    """Return display name for well-known SIDs, original string otherwise."""
    if not sid:
        return sid
    known = _KNOWN_SIDS.get(sid)
    if known:
        return known
    # Domain RID 500 = Administrator, 501 = Guest, 1000+ = regular users
    parts = sid.split("-")
    if len(parts) >= 2 and parts[-1] == "500":
        return f"Administrator ({sid})"
    if len(parts) >= 2 and parts[-1] == "501":
        return f"Guest ({sid})"
    return sid


# ── Portable record abstraction ───────────────────────────────────────────────

class _DissectRecord:
    """Column accessor for a dissect.esedb record."""

    def __init__(self, rec, col_map: Dict[str, str]):
        self._r = rec
        self._col_map = col_map  # lowercase → actual name

    def _col(self, name: str) -> str:
        return self._col_map.get(name.lower(), name)

    def get_int(self, col: str) -> Optional[int]:
        try:
            v = self._r[self._col(col)]
            return int(v) if v is not None else None
        except Exception:
            return None

    def get_bytes(self, col: str) -> Optional[bytes]:
        try:
            v = self._r[self._col(col)]
            if v is None:
                return None
            if isinstance(v, (bytes, bytearray, memoryview)):
                return bytes(v)
            return None
        except Exception:
            return None

    def get_str(self, col: str) -> Optional[str]:
        try:
            v = self._r[self._col(col)]
            if v is None:
                return None
            if isinstance(v, str):
                return v
            raw = bytes(v) if isinstance(v, (bytearray, memoryview)) else v
            if isinstance(raw, bytes):
                if len(raw) >= 2 and raw[1] == 0:
                    return raw.decode("utf-16-le", errors="replace").rstrip("\x00")
                return raw.decode("utf-8", errors="replace").rstrip("\x00")
            return str(v)
        except Exception:
            return None

    def get_timestamp_ns(self, col: str) -> int:
        from supertimeline.utils.timestamps import filetime_to_unix_ns as _ft2ns
        variants = [col] + [v for v in _TS_COLUMN_VARIANTS if v != col]
        for name in variants:
            mapped = self._col_map.get(name.lower(), name)
            try:
                v = self._r[mapped]
                if v is None:
                    continue

                # datetime: Windows raises OSError for pre-1970 dates — guard it
                if isinstance(v, _dt.datetime):
                    if v.tzinfo is None:
                        v = v.replace(tzinfo=_dt.timezone.utc)
                    try:
                        unix_secs = v.timestamp()
                    except (OSError, OverflowError, ValueError):
                        continue
                    ns = int(unix_secs * 1_000_000_000)
                    if ns > 0:
                        return ns
                    continue

                # float: OLE date (days since 1899-12-30)
                if isinstance(v, float) and not isinstance(v, bool):
                    if 1.0 <= v <= 120_000.0:
                        unix_secs = (v - _OLE_UNIX_EPOCH_DAYS) * 86400.0
                        ns = int(unix_secs * 1_000_000_000)
                        if ns > 0:
                            return ns
                    continue

                # int: dissect returns JET_coltypDateTime as int64 (the raw IEEE 754 bits)
                # Reinterpret those bits as float64 first; if the result is a valid OLE date
                # range (1900–2228) it's an OLE Automation date.  Otherwise fall through to
                # FILETIME interpretation.
                try:
                    int_v = int(v)
                except (TypeError, ValueError, OverflowError):
                    continue
                if isinstance(v, bool):
                    continue
                try:
                    f = struct.unpack("<d", struct.pack("<q", int_v))[0]
                    if 1.0 <= f <= 120_000.0:
                        unix_secs = (f - _OLE_UNIX_EPOCH_DAYS) * 86400.0
                        ns = int(unix_secs * 1_000_000_000)
                        if ns > 0:
                            return ns
                        continue
                except (struct.error, OverflowError, ValueError):
                    pass
                # Fallback: treat as FILETIME
                ns = _ft2ns(int_v)
                if ns > 0:
                    return ns

            except Exception:
                continue
        return 0


class _PyesedbRecord:
    """Column accessor for a pyesedb record."""

    def __init__(self, rec, col_map: Dict[str, int], col_types: Dict[int, int]):
        self._r = rec
        self._col_map = col_map    # lowercase name → index
        self._col_types = col_types  # index → ESE type

    def _idx(self, col: str) -> Optional[int]:
        return self._col_map.get(col.lower())

    def get_int(self, col: str) -> Optional[int]:
        idx = self._idx(col)
        if idx is None:
            return None
        try:
            return self._r.get_value_data_as_integer(idx)
        except Exception:
            return None

    def get_bytes(self, col: str) -> Optional[bytes]:
        idx = self._idx(col)
        if idx is None:
            return None
        try:
            raw = self._r.get_value_data(idx)
            return bytes(raw) if raw is not None else None
        except Exception:
            return None

    def get_str(self, col: str) -> Optional[str]:
        idx = self._idx(col)
        if idx is None:
            return None
        try:
            raw = self._r.get_value_data(idx)
            if raw is None:
                return None
            raw = bytes(raw)
            if len(raw) >= 2 and raw[1] == 0:
                return raw.decode("utf-16-le", errors="replace").rstrip("\x00")
            return raw.decode("utf-8", errors="replace").rstrip("\x00")
        except Exception:
            return None

    def get_timestamp_ns(self, col: str) -> int:
        variants = [col] + [v for v in _TS_COLUMN_VARIANTS if v != col]
        for name in variants:
            idx = self._col_map.get(name.lower())
            if idx is None:
                continue
            try:
                raw = self._r.get_value_data(idx)
                if not raw:
                    continue
                raw = bytes(raw)
                if self._col_types.get(idx) == _ESE_COLTYPE_DATETIME:
                    if len(raw) != 8:
                        continue
                    ole = struct.unpack("<d", raw)[0]
                    if ole <= 0:
                        continue
                    unix_secs = (ole - _OLE_UNIX_EPOCH_DAYS) * 86400.0
                    ns = max(0, int(unix_secs * 1_000_000_000))
                    if ns > 0:
                        return ns
                    continue
                from supertimeline.utils.timestamps import filetime_to_unix_ns
                ft = struct.unpack("<Q", raw)[0]
                ns = filetime_to_unix_ns(ft)
                if ns > 0:
                    return ns
            except Exception:
                continue
        return 0


# ── Backend table readers ─────────────────────────────────────────────────────

def _dissect_records(table) -> List[_DissectRecord]:
    try:
        col_map = {c.name.lower(): c.name for c in table.columns}
    except Exception:
        col_map = {}
    return [_DissectRecord(r, col_map) for r in table.records()]


def _pyesedb_records(table) -> List[_PyesedbRecord]:
    col_map: Dict[str, int] = {}
    col_types: Dict[int, int] = {}
    for i in range(table.get_number_of_columns()):
        col = table.get_column(i)
        col_map[col.name.lower()] = i
        col_types[i] = col.type
    return [
        _PyesedbRecord(table.get_record(i), col_map, col_types)
        for i in range(table.get_number_of_records())
    ]


def _get_records(db, backend: str, table_name: str):
    """Return list of portable records for *table_name*, or [] on failure."""
    if backend == "dissect":
        try:
            return _dissect_records(db.table(table_name))
        except Exception as exc:
            log.debug("SRUM: dissect could not read table %s: %s", table_name, exc)
            return []
    # pyesedb
    try:
        table = db.get_table_by_name(table_name)
        if table is not None:
            return _pyesedb_records(table)
    except Exception:
        pass
    # Fall back to iteration (some pyesedb builds lack get_table_by_name)
    for i in range(db.get_number_of_tables()):
        try:
            t = db.get_table(i)
            if t.name == table_name:
                return _pyesedb_records(t)
        except Exception:
            continue
    return []


def _get_all_table_names(db, backend: str) -> List[str]:
    if backend == "dissect":
        try:
            return [t.name for t in db.tables()]
        except Exception:
            return []
    return [db.get_table(i).name for i in range(db.get_number_of_tables())]


def _get_table_records_by_name(db, backend: str, name: str):
    """Like _get_records but used when iterating all tables."""
    if backend == "dissect":
        try:
            tbl = db.table(name)
            return _dissect_records(tbl)
        except Exception as exc:
            log.debug("SRUM: dissect table %s error: %s", name, exc)
            return []
    # pyesedb — find by name
    for i in range(db.get_number_of_tables()):
        try:
            t = db.get_table(i)
            if t.name == name:
                return _pyesedb_records(t)
        except Exception:
            continue
    return []


# ── Open helpers ──────────────────────────────────────────────────────────────

def _open_db(srum_path: str):
    """
    Try dissect.esedb first, then pyesedb.
    Returns (db, backend, file_handle_or_None).
    Raises RuntimeError if no backend can open the file.
    """
    if _HAS_DISSECT:
        fh = None
        try:
            fh = open(srum_path, "rb")
            db = _DissectEseDB(fh)
            # Force a read to catch format errors early
            list(db.tables())
            log.debug("SRUM: opened with dissect.esedb")
            return db, "dissect", fh
        except Exception as exc:
            if fh:
                try:
                    fh.close()
                except Exception:
                    pass
            log.debug("SRUM: dissect.esedb open failed for %s: %s", srum_path, exc)
            raise

    if _HAS_PYESEDB:
        db = _pyesedb.open(srum_path)
        log.debug("SRUM: opened with pyesedb")
        return db, "pyesedb", None

    raise RuntimeError(
        "No ESE backend available — install dissect.esedb: pip install dissect.esedb"
    )


def _close_db(db, fh):
    try:
        if fh:
            fh.close()
    except Exception:
        pass
    try:
        if hasattr(db, "close"):
            db.close()
    except Exception:
        pass


# ── ESE recovery ──────────────────────────────────────────────────────────────

def _ese_recover(db_path: str) -> bool:
    """Soft ESE recovery (esentutl /r) — Windows only."""
    if sys.platform != "win32":
        log.warning(
            "SRUM: SRUDB.dat is in a dirty-shutdown state and requires esentutl "
            "recovery, which is only available on Windows. "
            "Copy the sru/ directory (including *.log files) to a Windows machine "
            "and run: esentutl /r sru /i"
        )
        return False
    esentutl = shutil.which("esentutl")
    if not esentutl:
        log.warning("SRUM: esentutl not found — cannot recover SRUDB.dat")
        return False
    db_dir = os.path.dirname(os.path.abspath(db_path))
    try:
        result = subprocess.run(
            [esentutl, "/r", "sru", "/i", "/l", db_dir, "/s", db_dir],
            capture_output=True, timeout=120, cwd=db_dir,
        )
        if result.returncode == 0:
            log.info("SRUM: soft recovery succeeded for %s", db_path)
            return True
        log.debug("SRUM: soft recovery returned %d — %s",
                  result.returncode, result.stderr.decode(errors="replace").strip())
    except Exception as exc:
        log.debug("SRUM: soft recovery error — %s", exc)
    return False


def _ese_hard_repair(db_path: str) -> bool:
    """Hard ESE repair (esentutl /p) — Windows only."""
    if sys.platform != "win32":
        return False
    esentutl = shutil.which("esentutl")
    if not esentutl:
        return False
    try:
        result = subprocess.run(
            [esentutl, "/p", db_path, "/o"],
            capture_output=True, timeout=120,
        )
        if result.returncode == 0:
            log.info("SRUM: hard repair succeeded for %s", db_path)
            return True
        log.warning("SRUM: hard repair failed (rc=%d) for %s — %s",
                    result.returncode, db_path,
                    result.stderr.decode(errors="replace").strip())
    except Exception as exc:
        log.warning("SRUM: hard repair error — %s", exc)
    return False


# ── SID decoder ───────────────────────────────────────────────────────────────

def _decode_sid(raw: bytes) -> Optional[str]:
    """Decode a Windows binary SID to its S-1-... string form."""
    try:
        if len(raw) < 8:
            return None
        revision  = raw[0]
        sub_count = raw[1]
        authority = int.from_bytes(raw[2:8], "big")
        if len(raw) < 8 + sub_count * 4:
            return None
        subs = [int.from_bytes(raw[8 + i*4: 12 + i*4], "little") for i in range(sub_count)]
        return "S-" + "-".join([str(revision), str(authority)] + [str(s) for s in subs])
    except Exception:
        return None


# ── ID map ────────────────────────────────────────────────────────────────────

def _build_id_map(records) -> Dict[int, str]:
    """Build {integer_id: display_string} from SruDbIdMapTable records."""
    id_map: Dict[int, str] = {}
    for rec in records:
        try:
            id_val  = rec.get_int("IdIndex")
            id_type = rec.get_int("IdType") or 0
            if id_val is None:
                continue

            if id_type == 3:
                raw = rec.get_bytes("IdBlob")
                display = _decode_sid(raw) if raw else None
            else:
                display = rec.get_str("IdBlob")
                if display and display.startswith("!!"):
                    parts = display.split("!")
                    display = parts[2] if len(parts) > 2 else display.lstrip("!")

            if display:
                id_map[id_val] = display
        except Exception:
            continue

    log.debug("SRUM id_map: %d entries", len(id_map))
    return id_map


# ── Application Timeline ──────────────────────────────────────────────────────

def _parse_app_timeline(records, id_map: Dict[int, str], srum_path: str) -> List[Dict[str, Any]]:
    from supertimeline.utils.timestamps import unix_ns_to_iso

    events: List[Dict[str, Any]] = []
    for rec in records:
        try:
            ts_ns = rec.get_timestamp_ns("TimeStamp")
            if ts_ns <= 0:
                continue

            app_id   = rec.get_int("AppId")
            app_name = id_map.get(app_id, str(app_id)) if app_id is not None else "Unknown"

            user_id   = rec.get_int("UserId")
            user_name = _resolve_sid(id_map.get(user_id, str(user_id))) if user_id is not None else ""

            metrics: List[str] = []
            fg_cpu = rec.get_int("ForegroundCycleTime")
            bg_cpu = rec.get_int("BackgroundCycleTime")
            fg_br  = rec.get_int("ForegroundBytesRead")
            bg_br  = rec.get_int("BackgroundBytesRead")
            fg_bw  = rec.get_int("ForegroundBytesWritten")
            bg_bw  = rec.get_int("BackgroundBytesWritten")

            if fg_cpu: metrics.append(f"fg_cycles={fg_cpu:,}")
            if bg_cpu: metrics.append(f"bg_cycles={bg_cpu:,}")
            if fg_br:  metrics.append(f"fg_read={fg_br:,}B")
            if bg_br:  metrics.append(f"bg_read={bg_br:,}B")
            if fg_bw:  metrics.append(f"fg_write={fg_bw:,}B")
            if bg_bw:  metrics.append(f"bg_write={bg_bw:,}B")

            parts = [f"App: {app_name}"]
            if user_name:
                parts.append(f"User: {user_name}")
            if metrics:
                parts.append("  ".join(metrics))

            events.append({
                "timestamp_ns":    ts_ns,
                "timestamp_iso":   unix_ns_to_iso(ts_ns),
                "macb":            "M",
                "source":          "SRUM",
                "artifact":        "SRUM AppTimeline",
                "file_path":       app_name,
                "message":         "  |  ".join(parts),
                "is_fn_timestamp": False,
                "tz_offset_secs":  0,
            })
        except Exception as exc:
            log.debug("SRUM AppTimeline record error: %s", exc)

    return events


# ── Network Usage ─────────────────────────────────────────────────────────────

def _parse_network_usage(records, id_map: Dict[int, str], srum_path: str) -> List[Dict[str, Any]]:
    from supertimeline.utils.timestamps import unix_ns_to_iso

    events: List[Dict[str, Any]] = []
    for rec in records:
        try:
            ts_ns = rec.get_timestamp_ns("TimeStamp")
            if ts_ns <= 0:
                continue

            app_id   = rec.get_int("AppId")
            app_name = id_map.get(app_id, str(app_id)) if app_id is not None else "Unknown"

            user_id   = rec.get_int("UserId")
            user_name = _resolve_sid(id_map.get(user_id, str(user_id))) if user_id is not None else ""

            sent = rec.get_int("BytesSent")
            recv = rec.get_int("BytesRecvd")

            parts = [f"App: {app_name}"]
            if user_name:
                parts.append(f"User: {user_name}")
            if sent:
                parts.append(f"sent={sent:,}B")
            if recv:
                parts.append(f"recv={recv:,}B")

            events.append({
                "timestamp_ns":    ts_ns,
                "timestamp_iso":   unix_ns_to_iso(ts_ns),
                "macb":            "M",
                "source":          "SRUM",
                "artifact":        "SRUM Network",
                "file_path":       app_name,
                "message":         "  |  ".join(parts),
                "is_fn_timestamp": False,
                "tz_offset_secs":  0,
            })
        except Exception as exc:
            log.debug("SRUM Network record error: %s", exc)

    return events


# ── Public entry point ────────────────────────────────────────────────────────

def parse(srum_path: str) -> List[Dict[str, Any]]:
    """
    Parse SRUDB.dat.  Tries dissect.esedb first (handles Win10/11), then
    pyesedb as a fallback for older systems.
    """
    if not _HAS_DISSECT and not _HAS_PYESEDB:
        log.debug("SRUM: no ESE backend available — skipped (pip install dissect.esedb)")
        return []

    # Attempt to open, with ESE recovery on failure
    db = backend = fh = None
    last_err = None

    for attempt in range(3):
        try:
            db, backend, fh = _open_db(srum_path)
            break
        except Exception as exc:
            last_err = exc
            if attempt == 0:
                log.warning("SRUM: could not open %s — %s — attempting ESE soft recovery",
                            srum_path, exc)
                _ese_recover(srum_path)
            elif attempt == 1:
                log.warning("SRUM: still cannot open after soft recovery — trying hard repair")
                _ese_hard_repair(srum_path)
            else:
                log.warning("SRUM: still cannot open after recovery — %s", last_err)
                return []

    if db is None:
        return []

    try:
        id_records = _get_records(db, backend, "SruDbIdMapTable")
        id_map     = _build_id_map(id_records)

        events: List[Dict[str, Any]] = []
        for tbl_name in _get_all_table_names(db, backend):
            name_upper = tbl_name.upper()
            try:
                if _APP_TIMELINE_GUID in name_upper:
                    recs = _get_table_records_by_name(db, backend, tbl_name)
                    tbl_events = _parse_app_timeline(recs, id_map, srum_path)
                    log.info("SRUM AppTimeline: %d events", len(tbl_events))
                    events.extend(tbl_events)
                elif _NETWORK_USAGE_GUID in name_upper:
                    recs = _get_table_records_by_name(db, backend, tbl_name)
                    tbl_events = _parse_network_usage(recs, id_map, srum_path)
                    log.info("SRUM Network: %d events", len(tbl_events))
                    events.extend(tbl_events)
            except Exception as exc:
                log.warning("SRUM: error reading table %s — %s", tbl_name, exc)

        log.info("SRUM total: %d events from %s (backend: %s)", len(events), srum_path, backend)
        return events
    finally:
        _close_db(db, fh)
