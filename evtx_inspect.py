#!/usr/bin/env python3
"""
evtx_inspect.py — EVTX event inspector for parser debugging.

Usage:
  python evtx_inspect.py <file.evtx>                        # summary table
  python evtx_inspect.py <file.evtx> --id 4624              # filter by EventID
  python evtx_inspect.py <file.evtx> --id 4624 --id 4625    # multiple IDs
  python evtx_inspect.py <file.evtx> --search "DESKTOP"     # text search in XML
  python evtx_inspect.py <file.evtx> --xml 3                # full XML of record #3
  python evtx_inspect.py <file.evtx> --raw 3                # hex dump of record #3
  python evtx_inspect.py <file.evtx> --strings 3            # UTF-16LE string scan of record #3
  python evtx_inspect.py <file.evtx> --id 4624 --limit 20   # limit rows

Options:
  --id <N>         Filter by EventID (repeatable)
  --limit <N>      Max events to show in table (default 50)
  --xml <N>        Dump full XML of the Nth matched record (1-based)
  --raw <N>        Hex dump of the Nth matched record (1-based)
  --strings <N>    Scan UTF-16LE strings in the Nth matched record (1-based)
  --search <text>  Only show events whose XML contains text (case-insensitive)
  --offset <N>     Skip first N matched records (pagination)
"""

import sys
import argparse
import struct
import textwrap
from pathlib import Path

try:
    import Evtx.Evtx as evtx_lib
    import Evtx.Views as evtx_views
    from lxml import etree
except ImportError:
    print("ERROR: python-evtx not installed.  Run:  pip install python-evtx lxml")
    sys.exit(1)


# ── XML helpers ──────────────────────────────────────────────────────────────

def record_to_xml(record) -> str:
    try:
        return record.xml()
    except Exception as e:
        return f"<error>{e}</error>"

def xml_field(xml_str: str, field: str) -> str:
    try:
        root = etree.fromstring(xml_str.encode("utf-8", errors="replace"))
        ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
        for el in root.iter():
            name = el.get("Name", "")
            if name == field and el.text:
                return el.text.strip()
            tag = el.tag.split("}")[-1] if "}" in el.tag else el.tag
            if tag == field and el.text:
                return el.text.strip()
    except Exception:
        pass
    return ""

def xml_fields(xml_str: str, *fields) -> dict:
    result = {f: "" for f in fields}
    try:
        root = etree.fromstring(xml_str.encode("utf-8", errors="replace"))
        for el in root.iter():
            name = el.get("Name", "")
            tag  = el.tag.split("}")[-1] if "}" in el.tag else el.tag
            for f in fields:
                if (name == f or tag == f) and el.text and not result[f]:
                    result[f] = el.text.strip()
    except Exception:
        pass
    return result


# ── UTF-16LE string scanner (mirrors Rust parser logic) ──────────────────────

def measure_utf16le_run(data: bytes, start: int):
    """Return (char_count, end_byte_offset) of a UTF-16LE run starting at start."""
    i = start
    count = 0
    while i + 1 < len(data):
        lo, hi = data[i], data[i + 1]
        if hi != 0:
            break
        c = chr(lo)
        if not (c.isalnum() or c in "_-. @"):
            break
        count += 1
        i += 2
    return count, i

def scan_utf16le_strings(data: bytes, min_len=4, max_len=64):
    """Yield (offset, string) for all UTF-16LE runs in data."""
    i = 0
    while i + 1 < len(data):
        lo, hi = data[i], data[i + 1]
        if hi == 0 and (chr(lo).isalnum() or chr(lo) in "_-."):
            length, end = measure_utf16le_run(data, i)
            if min_len <= length <= max_len:
                raw = data[i:i + length * 2]
                try:
                    s = raw.decode("utf-16-le", errors="replace")
                    yield i, s
                except Exception:
                    pass
                i = end
                continue
        i += 1


# ── Hex dump ─────────────────────────────────────────────────────────────────

def hex_dump(data: bytes, base_offset: int = 0, width: int = 16):
    lines = []
    for row in range(0, len(data), width):
        chunk = data[row:row + width]
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        asc_part = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
        lines.append(f"  {base_offset + row:06X}  {hex_part:<{width*3}}  {asc_part}")
    return "\n".join(lines)


# ── Main ─────────────────────────────────────────────────────────────────────

def build_parser():
    p = argparse.ArgumentParser(
        description="EVTX inspector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("evtx_file")
    p.add_argument("--id",      dest="ids",    type=int, action="append", default=[])
    p.add_argument("--limit",   type=int, default=50)
    p.add_argument("--offset",  type=int, default=0)
    p.add_argument("--xml",     type=int, default=None, metavar="N")
    p.add_argument("--raw",     type=int, default=None, metavar="N")
    p.add_argument("--strings", type=int, default=None, metavar="N")
    p.add_argument("--search",  type=str, default=None)
    return p

def main():
    args = build_parser().parse_args()
    path = Path(args.evtx_file)
    if not path.exists():
        print(f"File not found: {path}")
        sys.exit(1)

    id_filter  = set(args.ids)
    search_str = args.search.lower() if args.search else None

    # Modes that need a specific record
    need_record = args.xml or args.raw or args.strings

    matched_idx = 0   # 1-based index of matched records
    shown       = 0

    # Column widths for table
    COL = {"#": 5, "Rec": 7, "EventID": 8, "Timestamp": 24, "Provider": 36, "Summary": 55}

    def print_header():
        row = "  ".join(f"{k:<{v}}" for k, v in COL.items())
        print(row)
        print("-" * len(row))

    printed_header = False

    with evtx_lib.Evtx(str(path)) as log:
        for chunk in log.chunks():
            for record in chunk.records():
                xml_str = record_to_xml(record)

                # EventID filter
                eid_str = xml_field(xml_str, "EventID")
                try:
                    eid = int(eid_str)
                except ValueError:
                    eid = -1
                if id_filter and eid not in id_filter:
                    continue

                # Text search filter
                if search_str and search_str not in xml_str.lower():
                    continue

                matched_idx += 1

                # -- Specific record modes (--xml, --raw, --strings) -----------
                if need_record:
                    target = need_record
                    if matched_idx != target:
                        continue

                    rec_data = record.data()

                    if args.xml:
                        print(f"\n=== XML: record #{matched_idx}  (EventID {eid}) ===\n")
                        try:
                            root = etree.fromstring(xml_str.encode())
                            pretty = etree.tostring(root, pretty_print=True).decode()
                            print(pretty)
                        except Exception:
                            print(xml_str)

                    if args.raw:
                        print(f"\n=== Raw bytes: record #{matched_idx}  (EventID {eid})  [{len(rec_data)} bytes] ===\n")
                        print(hex_dump(rec_data))

                    if args.strings:
                        print(f"\n=== UTF-16LE strings: record #{matched_idx}  (EventID {eid}) ===\n")
                        print(f"  {'Offset':<8}  {'Len':<5}  String")
                        print(f"  {'-'*8}  {'-'*5}  {'-'*50}")
                        for off, s in scan_utf16le_strings(rec_data):
                            print(f"  0x{off:04X}     {len(s):<5}  {s!r}")

                    return  # done after showing the requested record

                # -- Table mode ------------------------------------------------
                if matched_idx <= args.offset:
                    continue
                if shown >= args.limit:
                    continue

                if not printed_header:
                    print(f"\n  File: {path}")
                    if id_filter:
                        print(f"  Filter: EventID in {sorted(id_filter)}")
                    if search_str:
                        print(f"  Search: {args.search!r}")
                    print()
                    print_header()
                    printed_header = True

                rec_num = record.record_num()
                ts      = xml_field(xml_str, "TimeCreated") or xml_field(xml_str, "SystemTime")
                # lop off nanoseconds / timezone for display
                ts_short = ts[:23] if ts else ""
                provider = xml_field(xml_str, "Provider") or xml_field(xml_str, "Name")
                # summary: grab a few useful Data fields
                flds = xml_fields(xml_str,
                    "SubjectUserName", "TargetUserName", "WorkstationName",
                    "IpAddress", "ProcessName", "TargetObject",
                    "LogonType", "Status", "FailureReason",
                    "ObjectName", "ServiceName", "CommandLine")
                parts = []
                for k, v in flds.items():
                    if v and v not in ("-", "%%", "0x0", "0", ""):
                        parts.append(f"{k}={v}")
                summary = "  ".join(parts)[:COL["Summary"]]

                print("  ".join([
                    f"{matched_idx:<{COL['#']}}",
                    f"{rec_num:<{COL['Rec']}}",
                    f"{eid:<{COL['EventID']}}",
                    f"{ts_short:<{COL['Timestamp']}}",
                    f"{provider[:COL['Provider']]:<{COL['Provider']}}",
                    summary,
                ]))
                shown += 1

    if not printed_header and not need_record:
        print("No matching events found.")
    elif need_record and matched_idx < (args.xml or args.raw or args.strings or 0):
        print(f"Only {matched_idx} matching records found (requested #{need_record}).")
    elif shown == args.limit:
        remaining = matched_idx - shown - args.offset
        print(f"\n  ... {matched_idx} total matched, showing {args.offset+1}–{args.offset+shown}."
              f"  Use --offset {args.offset + args.limit} to continue.")


if __name__ == "__main__":
    main()
