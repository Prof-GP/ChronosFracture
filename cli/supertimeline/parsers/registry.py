"""
Windows Registry hive parser.
Extracts last-written timestamps from NK records, building full key paths
by traversing the parent chain so each event shows the complete path
(e.g. HKLM\\SYSTEM\\ControlSet001\\Services\\Tcpip\\Parameters).
Each event also lists the key's values (name=data) for quick forensic context.
"""
import struct
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional
from supertimeline.utils.timestamps import filetime_to_unix_ns, unix_ns_to_iso

REGF_MAGIC = b"regf"
HBIN_MAGIC = b"hbin"
NK_MAGIC   = b"nk"
VK_MAGIC   = b"vk"

# NK flags
NK_FLAG_ASCII_NAME = 0x20
NK_FLAG_ROOT       = 0x04

# VK flags
VK_FLAG_ASCII_NAME = 0x01


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


def _decode_reg_value(val_type: int, raw: bytes) -> str:
    """Decode raw registry value bytes to a display string."""
    if val_type in (1, 2, 6):  # REG_SZ, REG_EXPAND_SZ, REG_LINK
        try:
            return raw.decode("utf-16-le", errors="replace").rstrip("\x00")
        except Exception:
            return raw.hex()
    if val_type == 4:  # REG_DWORD
        if len(raw) >= 4:
            return str(struct.unpack_from("<I", raw)[0])
        return raw.hex()
    if val_type == 5:  # REG_DWORD_BE
        if len(raw) >= 4:
            return str(struct.unpack_from(">I", raw)[0])
        return raw.hex()
    if val_type == 11:  # REG_QWORD
        if len(raw) >= 8:
            return str(struct.unpack_from("<Q", raw)[0])
        return raw.hex()
    if val_type == 7:  # REG_MULTI_SZ
        try:
            decoded = raw.decode("utf-16-le", errors="replace")
            parts = [p for p in decoded.split("\x00") if p]
            return " | ".join(parts[:5])
        except Exception:
            return raw.hex()
    if val_type == 3:  # REG_BINARY
        return raw[:16].hex() + ("..." if len(raw) > 16 else "")
    return raw.hex() if raw else ""


def _read_nk_values(data: bytes, nk_off: int) -> List[Tuple[str, str]]:
    """
    Parse all value (VK) cells for the NK at nk_off.
    Returns a list of (value_name, decoded_value) pairs.
    """
    if nk_off + 0x2C > len(data):
        return []
    # NK structure (offsets from cell content):
    #   0x20 unknown, 0x24 number_of_values, 0x28 values_list_offset
    values_count = _read_u32(data, nk_off + 0x24)
    if values_count == 0 or values_count > 10000:
        return []
    vl_rel = _read_u32(data, nk_off + 0x28)
    if vl_rel == 0 or vl_rel == 0xFFFF_FFFF:
        return []

    # Values list cell content: file_offset = vl_rel + 4096 + 4 (skip 4-byte cell size)
    vl_abs = vl_rel + 4096 + 4
    vl_end = vl_abs + values_count * 4
    if vl_end > len(data):
        return []

    results: List[Tuple[str, str]] = []
    for idx in range(values_count):
        vk_rel = _read_u32(data, vl_abs + idx * 4)
        if vk_rel == 0 or vk_rel == 0xFFFF_FFFF:
            continue
        vk_off = vk_rel + 4096 + 4  # VK cell content
        if vk_off + 20 > len(data):
            continue
        if data[vk_off:vk_off + 2] != VK_MAGIC:
            continue

        name_len    = struct.unpack_from("<H", data, vk_off + 2)[0]
        data_len_raw = _read_u32(data, vk_off + 4)
        data_off_raw = _read_u32(data, vk_off + 8)
        val_type    = _read_u32(data, vk_off + 12)
        vk_flags    = struct.unpack_from("<H", data, vk_off + 16)[0]

        # Value name
        if name_len == 0:
            vname = "(default)"
        elif vk_flags & VK_FLAG_ASCII_NAME:
            vname = data[vk_off + 20:vk_off + 20 + name_len].decode("ascii", errors="replace")
        else:
            vname = _read_utf16(data, vk_off + 20, name_len)

        # Value data: high bit in data_len_raw means data is stored inline
        inline     = bool(data_len_raw & 0x8000_0000)
        actual_len = data_len_raw & 0x7FFF_FFFF

        if actual_len == 0:
            raw = b""
        elif inline:
            raw = data_off_raw.to_bytes(4, "little")[:actual_len]
        else:
            raw_abs = data_off_raw + 4096 + 4
            if raw_abs + actual_len <= len(data):
                raw = data[raw_abs:raw_abs + actual_len]
            else:
                raw = b""

        val_str = _decode_reg_value(val_type, raw)
        # Truncate very long values
        if len(val_str) > 80:
            val_str = val_str[:80] + "..."
        results.append((vname, val_str))

    return results


def parse(hive_path: str) -> List[Dict[str, Any]]:
    """
    Parse a registry hive and return one timeline event per NK (registry key),
    with the full key path and its values in the message field.
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

    # ── Pass 1: index every NK cell + collect its values ─────────────────────
    # nk_index: rel_off → (key_name, parent_rel_off, flags, last_write_ns)
    nk_index: Dict[int, Tuple[str, int, int, int]] = {}
    # nk_values: rel_off → [(value_name, decoded_value)]
    nk_values: Dict[int, List[Tuple[str, str]]] = {}

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
                        nk_values[rel_off] = _read_nk_values(data, nk_off)

            cell_off += cell_size
        offset += hbin_size

    # ── Pass 2: emit events with full key paths + value summaries ─────────────
    for rel_off, (_name, _parent, _flags, ns) in nk_index.items():
        if ns == 0:
            continue
        full_path = _build_full_path(nk_index, rel_off, hive_root)
        values    = nk_values.get(rel_off, [])

        if values:
            cap = 6
            parts = [f"{n}={v}" for n, v in values[:cap]]
            suffix = " | " + ", ".join(parts)
            if len(values) > cap:
                suffix += f", +{len(values) - cap} more"
            message = full_path + suffix
        else:
            message = full_path

        events.append({
            "timestamp_ns":    ns,
            "timestamp_iso":   unix_ns_to_iso(ns),
            "macb":            "M",
            "source":          "REGISTRY",
            "artifact":        "Registry Key",
            "message":         message,
            "is_fn_timestamp": False,
            "tz_offset_secs":  0,
        })

    return events
