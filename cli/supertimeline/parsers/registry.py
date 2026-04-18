"""
Windows Registry hive parser.
Extracts last-written timestamps from NK records, building full key paths
by traversing the parent chain so each event shows the complete path
(e.g. HKLM\\SYSTEM\\ControlSet001\\Services\\Tcpip\\Parameters).
"""
import struct
from pathlib import Path
from typing import List, Dict, Any, Tuple
from supertimeline.utils.timestamps import filetime_to_unix_ns, unix_ns_to_iso

REGF_MAGIC = b"regf"
HBIN_MAGIC = b"hbin"
NK_MAGIC   = b"nk"

# NK flags
NK_FLAG_ASCII_NAME = 0x20
NK_FLAG_ROOT       = 0x04


def _read_u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]

def _read_u64(data: bytes, off: int) -> int:
    return struct.unpack_from("<Q", data, off)[0]

def _read_utf16(data: bytes, off: int, length: int) -> str:
    try:
        return data[off:off+length].decode("utf-16-le", errors="replace").rstrip("\x00")
    except Exception:
        return ""

def _hive_root_name(hive_path: str) -> str:
    name = Path(hive_path).name.upper()
    return {
        "SYSTEM":       "HKLM\\SYSTEM",
        "SOFTWARE":     "HKLM\\SOFTWARE",
        "SAM":          "HKLM\\SAM",
        "SECURITY":     "HKLM\\SECURITY",
        "NTUSER.DAT":   "HKCU",
        "USRCLASS.DAT": "HKCU\\Software\\Classes",
    }.get(name, f"HIVE[{name}]")


def _build_full_path(nk_index: dict, start_rel_off: int, hive_root: str) -> str:
    """Follow parent chain from NK to root, building the full registry key path."""
    parts: List[str] = []
    current = start_rel_off
    seen: set = set()
    for _ in range(256):
        if current in seen:
            break
        seen.add(current)
        entry = nk_index.get(current)
        if not entry:
            break
        name, parent_rel_off, flags, _ = entry
        if flags & NK_FLAG_ROOT:
            break  # root key name is an internal artifact name — skip it
        parts.append(name)
        current = parent_rel_off
    parts.reverse()
    return hive_root + ("\\" + "\\".join(parts) if parts else "")


def parse(hive_path: str) -> List[Dict[str, Any]]:
    """
    Parse a registry hive and return one timeline event per NK (registry key),
    with the full key path in the message field.
    """
    events: List[Dict[str, Any]] = []
    try:
        with open(hive_path, "rb") as f:
            data = f.read()
    except OSError:
        return events

    if len(data) < 4096 or data[:4] != REGF_MAGIC:
        return events

    hive_root = _hive_root_name(hive_path)

    # ── Pass 1: index every NK cell ──────────────────────────────────────────
    # key   = cell relative offset  (= file_offset_of_cell_size - 4096)
    # value = (key_name, parent_cell_rel_offset, flags, last_write_ns)
    nk_index: Dict[int, Tuple[str, int, int, int]] = {}

    offset = 4096
    while offset + 32 < len(data):
        if data[offset:offset+4] != HBIN_MAGIC:
            break
        hbin_size = _read_u32(data, offset + 8)
        if hbin_size < 32 or offset + hbin_size > len(data):
            break

        cell_off = offset + 32
        while cell_off + 4 < offset + hbin_size:
            cell_size_raw = struct.unpack_from("<i", data, cell_off)[0]
            if cell_size_raw == 0:
                break
            allocated = cell_size_raw < 0
            cell_size = abs(cell_size_raw)
            if cell_size < 4:
                break

            if allocated:
                nk_off = cell_off + 4  # NK record content
                if (nk_off + 2 <= len(data) and
                        data[nk_off:nk_off+2] == NK_MAGIC and
                        nk_off + 76 <= len(data)):

                    flags      = struct.unpack_from("<H", data, nk_off + 2)[0]
                    last_write = _read_u64(data, nk_off + 4)
                    parent_rel = _read_u32(data, nk_off + 0x10)
                    name_len   = struct.unpack_from("<H", data, nk_off + 72)[0]
                    rel_off    = cell_off - 4096

                    if nk_off + 76 + name_len <= len(data):
                        if flags & NK_FLAG_ASCII_NAME:
                            name = data[nk_off+76:nk_off+76+name_len].decode("ascii", errors="replace")
                        else:
                            name = _read_utf16(data, nk_off + 76, name_len)

                        ns = filetime_to_unix_ns(last_write) if last_write else 0
                        nk_index[rel_off] = (name, parent_rel, flags, ns)

            cell_off += cell_size
        offset += hbin_size

    # ── Pass 2: emit events with full key paths ───────────────────────────────
    for rel_off, (_name, _parent, _flags, ns) in nk_index.items():
        if ns == 0:
            continue
        full_path = _build_full_path(nk_index, rel_off, hive_root)
        events.append({
            "timestamp_ns":    ns,
            "timestamp_iso":   unix_ns_to_iso(ns),
            "macb":            "M",
            "source":          "REGISTRY",
            "artifact":        "Registry Key",
            "artifact_path":   hive_path,
            "message":         full_path,
            "is_fn_timestamp": False,
            "tz_offset_secs":  0,
        })

    return events
