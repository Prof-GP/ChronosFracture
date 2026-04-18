"""
Amcache.hve parser — extracts execution timestamps and SHA1 hashes.

Navigates Root->InventoryApplicationFile (Win10+):
  - FileId value: SHA1 hash (strip leading "0000")
  - LowerCaseLongPath / Name: file path
  - Key last-write time: used as the event timestamp (= installation/execution time)

Legacy Win7 structure: Root->{GUID}->{GUID} with numeric value names.
Uses python-registry, falls back gracefully when unavailable.
"""

import datetime
import struct
from pathlib import Path
from typing import List, Dict, Any, Optional

# FILETIME epoch offset in microseconds from Unix epoch
_FT_EPOCH_US = 11644473600 * 1_000_000


def _filetime_to_ns(ft: int) -> int:
    if ft == 0:
        return 0
    us = ft // 10 - 11644473600 * 1_000_000
    return us * 1000


def _hexft_to_ns(hex_str: str) -> int:
    """Convert a hex-encoded FILETIME string (e.g. '01D9AB12...') to nanoseconds."""
    try:
        ft = int(hex_str.strip(), 16)
        return _filetime_to_ns(ft)
    except (ValueError, OverflowError):
        return 0


def _regtime_to_ns(regtime) -> int:
    """Convert a python-registry FILETIME (int or datetime) to nanoseconds."""
    try:
        if isinstance(regtime, datetime.datetime):
            ts = regtime.replace(tzinfo=datetime.timezone.utc).timestamp()
            return int(ts * 1_000_000_000)
        if isinstance(regtime, int):
            return _filetime_to_ns(regtime)
    except Exception:
        pass
    return 0


def _safe_value(key, name: str, default=None):
    try:
        return key.value(name).value()
    except Exception:
        return default


def _parse_inventory_application_file(root_key, artifact_path: str) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []

    # Win10+: hive root -> "Root" -> "InventoryApplicationFile"
    inv_key = None
    for path in (
        ["InventoryApplicationFile"],
        ["Root", "InventoryApplicationFile"],
    ):
        try:
            k = root_key
            for part in path:
                k = k.subkey(part)
            inv_key = k
            break
        except Exception:
            continue

    if inv_key is None:
        return events

    for app_key in inv_key.subkeys():
        try:
            full_path = (
                _safe_value(app_key, "LowerCaseLongPath")
                or _safe_value(app_key, "FullPath")
                or _safe_value(app_key, "Name")
                or app_key.name()
            )
            sha1 = _safe_value(app_key, "FileId") or ""
            if sha1.startswith("0000"):
                sha1 = sha1[4:]

            # Key last-write time = when this entry was recorded (install/first exec)
            ts_ns = _regtime_to_ns(app_key.timestamp())
            if ts_ns == 0:
                continue

            sha1_str = f" SHA1={sha1}" if sha1 else ""
            events.append({
                "timestamp_ns": ts_ns,
                "macb": "M",
                "source": "AMCACHE",
                "artifact": "Amcache.hve InventoryApplicationFile",
                "artifact_path": artifact_path,
                "message": f"{full_path}{sha1_str}",
                "is_fn_timestamp": False,
            })
        except Exception:
            continue

    return events


def _parse_legacy_amcache(root_key, artifact_path: str) -> List[Dict[str, Any]]:
    """Win7-era Amcache: Root/{GUID}/{GUID}/... with numeric value names."""
    events: List[Dict[str, Any]] = []

    for vol_key in root_key.subkeys():
        if not vol_key.name().startswith("{"):
            continue
        for file_key in vol_key.subkeys():
            if not file_key.name().startswith("{"):
                continue
            try:
                full_path = _safe_value(file_key, "15") or file_key.name()
                sha1 = _safe_value(file_key, "101") or ""
                if sha1.startswith("0000"):
                    sha1 = sha1[4:]

                # Value 17 is a FILETIME as integer
                ft_raw = _safe_value(file_key, "17") or 0
                ts_ns = _filetime_to_ns(ft_raw) if isinstance(ft_raw, int) else 0
                if ts_ns == 0:
                    ts_ns = _regtime_to_ns(file_key.timestamp())
                if ts_ns == 0:
                    continue

                sha1_str = f" SHA1={sha1}" if sha1 else ""
                events.append({
                    "timestamp_ns": ts_ns,
                    "macb": "M",
                    "source": "AMCACHE",
                    "artifact": "Amcache.hve Legacy",
                    "artifact_path": artifact_path,
                    "message": f"{full_path}{sha1_str}",
                    "is_fn_timestamp": False,
                })
            except Exception:
                continue

    return events


def parse_amcache(path: str) -> List[Dict[str, Any]]:
    """Parse Amcache.hve and return timeline events."""
    try:
        from Registry import Registry  # python-registry
    except ImportError:
        return []

    events: List[Dict[str, Any]] = []
    try:
        reg = Registry.Registry(path)
        root = reg.root()

        # Win10+ path
        events.extend(_parse_inventory_application_file(root, path))

        # Win7 legacy path
        if not events:
            events.extend(_parse_legacy_amcache(root, path))

    except Exception:
        pass

    return events
