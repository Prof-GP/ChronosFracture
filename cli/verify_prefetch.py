"""Test prefetch modules field with synthetic V26 prefetch bytes."""
import struct, time
import supertimeline_core as core

exe_name = "NOTEPAD.EXE"
exe_utf16 = exe_name.encode("utf-16-le")

sec_c = b""
for path in [
    r"\DEVICE\HARDDISKVOLUME3\WINDOWS\SYSTEM32\NOTEPAD.EXE",
    r"\DEVICE\HARDDISKVOLUME3\WINDOWS\SYSTEM32\USER32.DLL",
    r"\DEVICE\HARDDISKVOLUME3\WINDOWS\SYSTEM32\KERNEL32.DLL",
]:
    sec_c += (path + "\x00").encode("utf-16-le")

data = bytearray(512)
data[0] = 0x1A  # V26
for i, b in enumerate(exe_utf16[:58]):
    data[16 + i] = b
struct.pack_into("<I", data, 76, 0xDEADBEEF)  # hash
sec_c_off = 512
struct.pack_into("<I", data, 0x64, sec_c_off)   # Section C offset
struct.pack_into("<I", data, 0x68, len(sec_c))  # Section C length
struct.pack_into("<I", data, 0xD0, 42)           # run_count
ft = int((time.time() + 11644473600) * 10_000_000)
struct.pack_into("<Q", data, 0x80, ft)
struct.pack_into("<Q", data, 0x88, ft - 10_000_000_000)

full_data = bytes(data) + sec_c
events = list(core.parse_prefetch_bytes_decompressed(full_data, "NOTEPAD.EXE-DEADBEEF.pf"))
print(f"Events returned: {len(events)}")
if not events:
    print("FAIL: no events")
else:
    ev = events[0]
    mods = ev.get("modules")
    print(f"exe_name   : {ev.get('exe_name')}")
    print(f"exe_path   : {ev.get('exe_path')}")
    print(f"run_count  : {ev.get('run_count')}")
    print(f"modules    : {mods}")
    if mods is None:
        print("FAIL: modules field missing")
    elif len(mods) == 0:
        print("FAIL: modules is empty")
    elif not any("NOTEPAD" in m for m in mods):
        print(f"FAIL: expected NOTEPAD in modules, got {mods}")
    else:
        print(f"PASS: {len(mods)} modules, first={mods[0]}")
