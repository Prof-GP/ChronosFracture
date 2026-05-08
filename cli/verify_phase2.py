"""Quick verification of Phase 2 features against real data."""
import sys
from pathlib import Path
import supertimeline_core as core

errors = []

# ── 2.2 Prefetch modules ────────────────────────────────────────────────────
pf_dir = r"C:\Windows\Prefetch"
if Path(pf_dir).exists():
    try:
        events = list(core.parse_prefetch_dir(pf_dir))
    except OSError:
        events = []
    if events:
        ev = events[0]
        if "modules" not in ev:
            errors.append("2.2 FAIL: modules field missing from prefetch event")
        elif not isinstance(ev["modules"], list):
            errors.append(f"2.2 FAIL: modules is {type(ev['modules'])} not list")
        else:
            print(f"2.2 OK  Prefetch modules: {len(ev['modules'])} loaded for {ev.get('exe_name','?')}")
            print(f"        first: {ev['modules'][0] if ev['modules'] else '(none)'}")
    else:
        print("2.2 SKIP No .pf files on this machine")
else:
    print("2.2 SKIP No Prefetch dir on this machine")

# ── 2.4 LNK arguments ───────────────────────────────────────────────────────
import struct

def make_lnk(flags, write_ft, li_bytes, sd_bytes):
    hdr  = struct.pack("<I", 0x4C)
    hdr += bytes([0x01,0x14,0x02,0x00,0x00,0x00,0x00,0x00,
                  0xC0,0x00,0x00,0x00,0x00,0x00,0x00,0x46])
    hdr += struct.pack("<I", flags)
    hdr += struct.pack("<I", 0x20)   # FileAttributes
    hdr += struct.pack("<Q", 0)      # Create
    hdr += struct.pack("<Q", 0)      # Access
    hdr += struct.pack("<Q", write_ft)
    hdr += b"\x00" * 24
    return hdr + li_bytes + sd_bytes

# Minimal LinkInfo (28 bytes)
li = b"".join([struct.pack("<I", 28), struct.pack("<I", 28),
               struct.pack("<I", 0), struct.pack("<I", 0),
               struct.pack("<I", 0), struct.pack("<I", 0), struct.pack("<I", 0)])

args_str    = "/silent /norestart"
args_utf16  = args_str.encode("utf-16-le")
# FL_HAS_LINK_INFO=0x02, FL_HAS_ARGUMENTS=0x20, FL_IS_UNICODE=0x80
flags_args  = 0x0002 | 0x0020 | 0x0080
sd          = struct.pack("<H", len(args_str)) + args_utf16
lnk_bytes   = make_lnk(flags_args, 133_000_000_000_000_000, li, sd)

events = list(core.parse_lnk_bytes(lnk_bytes, "test.lnk"))
if not events:
    errors.append("2.4 FAIL: no events from LNK with arguments")
else:
    ev = events[0]
    if "arguments" not in ev:
        errors.append("2.4 FAIL: arguments field missing")
    elif ev["arguments"] != args_str:
        errors.append(f"2.4 FAIL: arguments={ev['arguments']!r} expected {args_str!r}")
    elif args_str not in ev["message"]:
        errors.append(f"2.4 FAIL: args not in message: {ev['message']!r}")
    else:
        print(f"2.4 OK  LNK arguments: {ev['arguments']!r}")
        print(f"        message: {ev['message']}")

# ── 2.5 LNK DROID TrackerDataBlock ─────────────────────────────────────────
# Build a LNK with a TrackerDataBlock in ExtraData
machine = b"WORKSTATION01\x00\x00\x00"  # 16 bytes
vol_guid = bytes(range(16))
file_guid = bytes(range(16, 32))
# TrackerDataBlock: size=96, sig=0xA0000003, length=88, version=0
# +0 BlockSize(4) +4 BlockSig(4) +8 Length(4) +12 Version(4)
# +16 MachineID(16) +32 Droid[0](16) +48 Droid[1](16) +64 DroidBirth[0](16) +80 DroidBirth[1](16)
tdb  = struct.pack("<I", 96)           # BlockSize
tdb += struct.pack("<I", 0xA0000003)   # BlockSignature
tdb += struct.pack("<I", 88)           # Length
tdb += struct.pack("<I", 0)            # Version
tdb += machine                          # MachineID (16 bytes)
tdb += vol_guid                         # Droid[0]
tdb += file_guid                        # Droid[1]
tdb += bytes(16)                        # DroidBirth[0]
tdb += bytes(16)                        # DroidBirth[1]
assert len(tdb) == 96

flags_droid = 0x0002 | 0x0080  # HAS_LINK_INFO | IS_UNICODE
lnk_droid   = make_lnk(flags_droid, 133_000_000_000_000_000, li, tdb)

events = list(core.parse_lnk_bytes(lnk_droid, "test_droid.lnk"))
if not events:
    errors.append("2.5 FAIL: no events from LNK with TrackerDataBlock")
else:
    ev = events[0]
    if "machine_id" not in ev:
        errors.append("2.5 FAIL: machine_id field missing")
    elif "droid_file_id" not in ev:
        errors.append("2.5 FAIL: droid_file_id field missing")
    elif ev["machine_id"] != "WORKSTATION01":
        errors.append(f"2.5 FAIL: machine_id={ev['machine_id']!r}")
    else:
        print(f"2.5 OK  DROID machine_id={ev['machine_id']!r}")
        print(f"        droid_file_id={ev['droid_file_id']!r}")
        print(f"        message: {ev['message']}")

# ── Summary ─────────────────────────────────────────────────────────────────
print()
if errors:
    for e in errors: print(f"FAIL: {e}")
    sys.exit(1)
else:
    print("All Phase 2 field verifications passed.")
