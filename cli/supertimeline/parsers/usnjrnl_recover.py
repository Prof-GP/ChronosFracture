"""
USN Journal carver — recovers USN v2 records from:
  1. Unallocated filesystem clusters (post-deletion / post-wipe)
  2. The allocated $J stream when it has been zeroed in-place

Recovered events are tagged with artifact="$J (Recovered)" so analysts
can distinguish them from live $J records in the timeline.

Requires: pytsk3, pyewf (for E01) or a raw image path.
"""

from __future__ import annotations

import struct
import logging
from pathlib import Path
from typing import List, Dict, Any, Iterator

log = logging.getLogger(__name__)

# USN v2 record constants
USN_RECORD_MIN_SIZE = 60
FILETIME_EPOCH      = 116_444_736_000_000_000  # 100ns ticks from 1601 to 1970

REASON_MAP = {
    0x00000001: "DATA_OVERWRITE",
    0x00000002: "DATA_EXTEND",
    0x00000004: "DATA_TRUNCATION",
    0x00000100: "FILE_CREATE",
    0x00000200: "FILE_DELETE",
    0x00000800: "SECURITY_CHANGE",
    0x00001000: "RENAME_OLD",
    0x00002000: "RENAME_NEW",
    0x00008000: "BASIC_INFO_CHANGE",
    0x80000000: "CLOSE",
}


def _reasons_str(reasons: int) -> str:
    parts = [v for k, v in REASON_MAP.items() if reasons & k]
    return "|".join(parts) if parts else f"0x{reasons:08X}"


def _filetime_to_ns(ft: int) -> int:
    if ft <= FILETIME_EPOCH:
        return 0
    return (ft - FILETIME_EPOCH) * 100


def _ns_to_iso(ns: int) -> str:
    if ns == 0:
        return ""
    from datetime import datetime, timezone
    try:
        dt = datetime.fromtimestamp(ns / 1e9, tz=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ns % 1_000_000_000:09d}Z"
    except (OSError, OverflowError, ValueError):
        return ""


def _scan_buffer(data: bytes, artifact_path: str) -> List[Dict[str, Any]]:
    """Scan a raw bytes buffer for USN v2 records."""
    events = []
    offset = 0
    length = len(data)

    while offset + USN_RECORD_MIN_SIZE <= length:
        rec_len = struct.unpack_from("<I", data, offset)[0]

        if rec_len == 0:
            offset += 8
            continue

        if rec_len < USN_RECORD_MIN_SIZE or rec_len > 65536 or rec_len % 8 != 0:
            offset += 8
            continue

        if offset + rec_len > length:
            break

        major = struct.unpack_from("<H", data, offset + 4)[0]
        minor = struct.unpack_from("<H", data, offset + 6)[0]
        if major != 2 or minor != 0:
            offset += 8
            continue

        filetime  = struct.unpack_from("<Q", data, offset + 16)[0]
        reasons   = struct.unpack_from("<I", data, offset + 40)[0]
        file_attr = struct.unpack_from("<I", data, offset + 52)[0]
        name_len  = struct.unpack_from("<H", data, offset + 56)[0]
        name_off  = struct.unpack_from("<H", data, offset + 58)[0]

        if name_len == 0 or name_off + name_len > rec_len:
            offset += rec_len
            continue

        try:
            name_bytes = data[offset + name_off: offset + name_off + name_len]
            file_name  = name_bytes.decode("utf-16-le", errors="replace")
        except Exception:
            offset += rec_len
            continue

        is_dir     = bool(file_attr & 0x10)
        kind       = "Directory" if is_dir else "File"
        reason_str = _reasons_str(reasons)
        ns         = _filetime_to_ns(filetime)
        iso        = _ns_to_iso(ns)

        events.append({
            "timestamp_ns":    ns,
            "timestamp_iso":   iso,
            "macb":            "M",
            "source":          "$UsnJrnl:$J",
            "artifact":        "$J (Recovered)",
            "artifact_path":   artifact_path,
            "message":         f"{kind} {file_name} - {reason_str}",
            "is_fn_timestamp": False,
            "tz_offset_secs":  0,
        })

        offset += rec_len

    return events


def _open_image(image_path: str):
    """Return a pytsk3 Img_Info for E01 or raw image."""
    import pytsk3

    path = str(image_path)
    if path.lower().endswith((".e01", ".ex01")):
        import pyewf
        handles = pyewf.glob(path)
        h = pyewf.handle()
        h.open(handles)

        class _EwfBridge(pytsk3.Img_Info):
            def __init__(self, ewf):
                self._h = ewf
                super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)
            def read(self, offset, length):
                self._h.seek(offset)
                return self._h.read(length)
            def get_size(self):
                return self._h.get_media_size()

        return _EwfBridge(h)

    return pytsk3.Img_Info(path)


def _iter_image_chunks(img, chunk_size: int = 64 * 1024 * 1024) -> Iterator[bytes]:
    """
    Yield raw chunks from a pytsk3 Img_Info object.
    Reads the entire image linearly — catches unallocated, slack, and
    any other regions that may contain USN record fragments.
    """
    total  = img.get_size()
    offset = 0
    while offset < total:
        read_len = min(chunk_size, total - offset)
        try:
            data = img.read(offset, read_len)
            if data:
                yield data
        except Exception:
            pass
        offset += read_len


def recover_from_zeroed_j_image(image_path: str) -> List[Dict[str, Any]]:
    """
    Read $UsnJrnl:$J directly from a forensic image and scan for USN records.
    Handles the case where the extractor skipped the file because it was all-zero
    (sparse-aware mode removes fully-zeroed outputs).
    """
    try:
        import pytsk3
    except ImportError:
        log.warning("pytsk3 not available — zeroed $J recovery skipped")
        return []

    events = []
    chunk_size = 64 * 1024 * 1024

    try:
        img = _open_image(image_path)
        fs  = pytsk3.FS_Info(img)
        # Navigate by inode: walk root → $Extend → $UsnJrnl
        # (path-based open is unreliable across pytsk3 versions/platforms)
        f = None
        try:
            root = fs.open_dir("/")
            for entry in root:
                name = entry.info.name.name if entry.info.name else b""
                if name == b"$Extend" and entry.info.meta:
                    extend_dir = fs.open_dir(inode=entry.info.meta.addr)
                    for sub in extend_dir:
                        sname = sub.info.name.name if sub.info.name else b""
                        if sname == b"$UsnJrnl" and sub.info.meta:
                            f = fs.open_meta(inode=sub.info.meta.addr)
                            break
                    break
        except Exception as e:
            log.warning("USN zeroed-$J: could not navigate to $UsnJrnl: %s", e)
            return []

        if f is None:
            log.info("USN zeroed-$J: $UsnJrnl not found on image")
            return []

        j_attr_id = None
        j_size    = 0
        for attr in f:
            if attr.info.name == b"$J":
                j_attr_id = attr.info.id
                j_size    = attr.info.size
                break

        if j_attr_id is None or j_size == 0:
            return []

        log.info("USN zeroed-$J recovery: $J size=%d bytes in %s", j_size, image_path)

        offset = 0
        while offset < j_size:
            read_len = min(chunk_size, j_size - offset)
            try:
                data = f.read_random(offset, read_len, 128, j_attr_id)
            except Exception:
                offset += read_len
                continue
            if any(b != 0 for b in data):
                found = _scan_buffer(data, image_path)
                events.extend(found)
            offset += read_len

    except Exception as e:
        log.warning("USN zeroed-$J image recovery failed: %s", e)

    log.info("USN zeroed-$J recovery: %d records found", len(events))
    return events


def recover_from_image(image_path: str) -> List[Dict[str, Any]]:
    """
    Scan the raw image for USN v2 records outside of the live $J stream.
    Reads the entire image linearly — catches unallocated clusters, file slack,
    and any other regions containing USN record fragments.
    """
    try:
        import pytsk3
    except ImportError:
        log.warning("pytsk3 not available — USN image recovery skipped")
        return []

    events = []
    label  = str(image_path)

    try:
        img = _open_image(image_path)
    except Exception as e:
        log.warning("USN recovery: cannot open image %s: %s", image_path, e)
        return []

    log.info("USN recovery: scanning raw image %s (%d bytes)", image_path, img.get_size())
    chunks_scanned = 0
    for chunk in _iter_image_chunks(img):
        found = _scan_buffer(chunk, label)
        events.extend(found)
        chunks_scanned += 1
        if chunks_scanned % 10 == 0:
            log.debug("USN recovery: %d chunks scanned, %d records found", chunks_scanned, len(events))

    log.info("USN recovery: %d records recovered from %d chunks", len(events), chunks_scanned)
    return events


def recover_from_zeroed_j(j_path: str) -> List[Dict[str, Any]]:
    """
    Scan an extracted $J file that may have been zeroed in-place.
    Skips leading zero blocks and scans the rest for USN signatures.
    Useful when $J exists but the live parser returned 0 events.
    """
    events = []
    chunk_size = 64 * 1024 * 1024  # 64MB

    try:
        with open(j_path, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                if any(b != 0 for b in chunk):
                    found = _scan_buffer(chunk, j_path)
                    events.extend(found)
    except Exception as e:
        log.warning("USN zeroed-$J recovery failed for %s: %s", j_path, e)

    return events
