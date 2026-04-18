"""
$MFT Parser — unit tests.

Tests verify:
  1. Timestamp accuracy (FILETIME → UTC nanosecond conversion)
  2. Correct MACB flag assignment
  3. $SI vs $FN timestamp separation (timestomp detection integrity)
  4. Handling of invalid/corrupt entries (no crash, empty result)
  5. Handling of zero-length and minimum-length input
"""
import struct
import pytest

from supertimeline.utils.timestamps import filetime_to_unix_ns, unix_ns_to_iso

# ── FILETIME conversion tests ──────────────────────────────────────────────────

class TestFiletimeConversion:
    """FILETIME to Unix nanosecond conversion must be bit-exact."""

    def test_known_timestamp(self):
        # 2024-01-15 12:00:00 UTC
        # Unix seconds: 1705320000
        # FILETIME = 1705320000 * 10_000_000 + 116_444_736_000_000_000
        ft = 1_705_320_000 * 10_000_000 + 116_444_736_000_000_000
        ns = filetime_to_unix_ns(ft)
        iso = unix_ns_to_iso(ns)
        assert iso.startswith("2024-01-15T12:00:00"), f"Got {iso}"

    def test_epoch_boundary(self):
        # FILETIME for Unix epoch (1970-01-01 00:00:00 UTC)
        # = 116444736000000000
        ft = 116_444_736_000_000_000
        ns = filetime_to_unix_ns(ft)
        assert ns == 0, f"Expected 0, got {ns}"

    def test_pre_epoch_filetime(self):
        # FILETIME before Unix epoch → should return 0, not negative/crash
        ft = 100_000_000_000_000_000  # 1969
        ns = filetime_to_unix_ns(ft)
        assert ns == 0, "Pre-epoch FILETIME must return 0, not negative"

    def test_zero_filetime(self):
        # Zero FILETIME (1601-01-01) → must not crash
        ns = filetime_to_unix_ns(0)
        assert ns == 0

    def test_max_filetime(self):
        # Maximum FILETIME (year ~30828) → must not overflow or crash
        ft = 0x7FFF_FFFF_FFFF_FFFF
        ns = filetime_to_unix_ns(ft)
        assert isinstance(ns, int)
        assert ns >= 0

    def test_100ns_precision(self):
        # Two FILETIMEs 100ns apart must produce different nanosecond values
        ft1 = 133_499_040_000_000_000
        ft2 = 133_499_040_000_000_001  # +100ns
        assert filetime_to_unix_ns(ft2) - filetime_to_unix_ns(ft1) == 100


# ── MFT entry structure helpers ────────────────────────────────────────────────

MFT_ENTRY_SIZE = 1024
FILETIME_EPOCH = 116_444_736_000_000_000

def make_mft_entry(
    created:    int = FILETIME_EPOCH + 1_000_000_000,  # 100s after epoch
    modified:   int = FILETIME_EPOCH + 2_000_000_000,
    mft_mod:    int = FILETIME_EPOCH + 3_000_000_000,
    accessed:   int = FILETIME_EPOCH + 4_000_000_000,
    fn_created: int = FILETIME_EPOCH + 1_000_000_000,
    name:       str = "test.txt",
    in_use:     bool = True,
    is_dir:     bool = False,
) -> bytes:
    """
    Build a minimal but valid MFT entry for testing.
    Structure follows NTFS specification (1024-byte entry).
    """
    entry = bytearray(MFT_ENTRY_SIZE)

    # Header: FILE signature
    entry[0:4] = b"FILE"

    # Fixup array offset and count (not validated by parser)
    struct.pack_into("<H", entry, 4, 48)   # fixup offset
    struct.pack_into("<H", entry, 6, 3)    # fixup count

    # Flags: 0x01 = in use, 0x02 = directory
    flags = 0
    if in_use:  flags |= 0x01
    if is_dir:  flags |= 0x02
    struct.pack_into("<H", entry, 22, flags)

    # First attribute offset
    attr_offset = 56
    struct.pack_into("<H", entry, 20, attr_offset)

    # ── $STANDARD_INFORMATION (type 0x10) ──────────────────────────────
    si_content_off = 24  # resident content offset within attr header
    si_content = struct.pack("<QQQQ", created, modified, mft_mod, accessed)
    si_len = si_content_off + len(si_content)
    # Pad to 8-byte boundary
    si_len = (si_len + 7) & ~7

    struct.pack_into("<I", entry, attr_offset,     0x10)          # attr type
    struct.pack_into("<I", entry, attr_offset + 4, si_len)        # attr length
    entry[attr_offset + 8] = 0                                     # resident
    entry[attr_offset + 9] = 0                                     # no name
    struct.pack_into("<I", entry, attr_offset + 16, len(si_content))  # content len
    struct.pack_into("<H", entry, attr_offset + 20, si_content_off)   # content off
    entry[attr_offset + si_content_off : attr_offset + si_content_off + len(si_content)] = si_content

    # ── $FILE_NAME (type 0x30) ─────────────────────────────────────────
    fn_offset = attr_offset + si_len
    name_utf16 = name.encode("utf-16-le")
    fn_fixed = struct.pack(
        "<QQQQQQQIIBB",
        0,          # parent MFT ref  (u64)
        fn_created, # created         (u64)
        fn_created, # modified        (u64)
        fn_created, # mft modified    (u64)
        fn_created, # accessed        (u64)
        0,          # alloc size      (u64)
        0,          # real size       (u64)
        0x20,       # flags archive   (u32)
        0,          # reparse         (u32)
        len(name),  # name len units  (u8)
        1,          # namespace Win32 (u8)
    )
    fn_content = fn_fixed + name_utf16
    fn_content_off = 24
    fn_attr_len = fn_content_off + len(fn_content)
    fn_attr_len = (fn_attr_len + 7) & ~7

    struct.pack_into("<I", entry, fn_offset,     0x30)
    struct.pack_into("<I", entry, fn_offset + 4, fn_attr_len)
    entry[fn_offset + 8] = 0
    entry[fn_offset + 9] = 0
    struct.pack_into("<I", entry, fn_offset + 16, len(fn_content))
    struct.pack_into("<H", entry, fn_offset + 20, fn_content_off)
    entry[fn_offset + fn_content_off : fn_offset + fn_content_off + len(fn_content)] = fn_content

    # End-of-attributes marker
    end_offset = fn_offset + fn_attr_len
    if end_offset + 4 <= MFT_ENTRY_SIZE:
        struct.pack_into("<I", entry, end_offset, 0xFFFFFFFF)

    return bytes(entry)


# ── Integration tests (require compiled Rust core) ────────────────────────────

try:
    import supertimeline_core as _core
    RUST_AVAILABLE = True
except ImportError:
    RUST_AVAILABLE = False

rust_only = pytest.mark.skipif(not RUST_AVAILABLE, reason="Rust core not compiled")


@rust_only
class TestMftParser:
    """Integration tests for the Rust $MFT parser."""

    def _write_mft(self, tmp_path, entries: list[bytes]) -> str:
        """Write a list of MFT entries to a temp file and return its path."""
        mft_file = tmp_path / "$MFT"
        with open(mft_file, "wb") as f:
            for e in entries:
                assert len(e) == MFT_ENTRY_SIZE
                f.write(e)
        return str(mft_file)

    def test_basic_file_entry(self, tmp_path):
        """A single valid in-use file entry yields 8 events (4 SI + 4 FN)."""
        entry = make_mft_entry()
        path = self._write_mft(tmp_path, [entry])
        events = _core.parse_mft_file(path)
        assert len(events) == 8, f"Expected 8 events, got {len(events)}"

    def test_si_fn_separation(self, tmp_path):
        """SI and FN events are correctly flagged."""
        entry = make_mft_entry()
        path = self._write_mft(tmp_path, [entry])
        events = _core.parse_mft_file(path)
        si_events = [e for e in events if not e["is_fn_timestamp"]]
        fn_events = [e for e in events if e["is_fn_timestamp"]]
        assert len(si_events) == 4, "Expected 4 $SI events"
        assert len(fn_events) == 4, "Expected 4 $FN events"

    def test_macb_flags_present(self, tmp_path):
        """All MACB flag types (M, A, C, B) appear in events."""
        entry = make_mft_entry()
        path = self._write_mft(tmp_path, [entry])
        events = _core.parse_mft_file(path)
        macb_flags = {e["macb"] for e in events}
        assert macb_flags == {"M", "A", "C", "B"}, f"Got flags: {macb_flags}"

    def test_not_in_use_skipped(self, tmp_path):
        """Entries with in_use=False must produce zero events."""
        entry = make_mft_entry(in_use=False)
        path = self._write_mft(tmp_path, [entry])
        events = _core.parse_mft_file(path)
        assert len(events) == 0, "Deleted entries must be skipped"

    def test_invalid_signature_skipped(self, tmp_path):
        """Entries with wrong signature must produce zero events (no crash)."""
        entry = bytearray(make_mft_entry())
        entry[0:4] = b"BAAD"  # corrupt signature
        path = self._write_mft(tmp_path, [bytes(entry)])
        events = _core.parse_mft_file(path)
        assert len(events) == 0

    def test_timestamp_accuracy(self, tmp_path):
        """Timestamps must survive the FILETIME → nanosecond round-trip exactly."""
        # 2024-01-15 12:00:00.000000000 UTC
        # Unix seconds: 1705320000 → FILETIME = unix * 10_000_000 + epoch_diff
        ft = 1_705_320_000 * 10_000_000 + 116_444_736_000_000_000
        entry = make_mft_entry(created=ft, modified=ft, mft_mod=ft, accessed=ft)
        path = self._write_mft(tmp_path, [entry])
        events = _core.parse_mft_file(path)
        si_b = next(e for e in events if e["macb"] == "B" and not e["is_fn_timestamp"])
        assert si_b["timestamp_iso"].startswith("2024-01-15T12:00:00"), \
            f"Timestamp incorrect: {si_b['timestamp_iso']}"

    def test_multiple_entries(self, tmp_path):
        """N entries must yield 8*N events."""
        entries = [make_mft_entry(name=f"file{i}.txt") for i in range(10)]
        path = self._write_mft(tmp_path, entries)
        events = _core.parse_mft_file(path)
        assert len(events) == 80, f"Expected 80, got {len(events)}"

    def test_directory_entry_flagged(self, tmp_path):
        """Directory entries must include 'Directory' in their message."""
        entry = make_mft_entry(is_dir=True, name="TestDir")
        path = self._write_mft(tmp_path, [entry])
        events = _core.parse_mft_file(path)
        assert all("Directory" in e["message"] for e in events)

    def test_source_field(self, tmp_path):
        """All MFT events must have source='$MFT'."""
        entry = make_mft_entry()
        path = self._write_mft(tmp_path, [entry])
        events = _core.parse_mft_file(path)
        assert all(e["source"] == "$MFT" for e in events)

    def test_artifact_types(self, tmp_path):
        """Artifact field must be '$STANDARD_INFORMATION' or '$FILE_NAME'."""
        entry = make_mft_entry()
        path = self._write_mft(tmp_path, [entry])
        events = _core.parse_mft_file(path)
        valid_artifacts = {"$STANDARD_INFORMATION", "$FILE_NAME"}
        for e in events:
            assert e["artifact"] in valid_artifacts, f"Unknown artifact: {e['artifact']}"
