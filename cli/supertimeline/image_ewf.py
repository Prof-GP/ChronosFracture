"""
Minimal EWF (Expert Witness Format / EnCase E01) reader — pure Python, zero deps.

Implements enough of the EWF specification to:
  - Parse the section list (header, volume, table, data, hash, done)
  - Read logical disk sectors via the chunk/table lookup
  - Decompress zlib-compressed chunks

Compatible with EWF1 format (.E01) created by EnCase, FTK Imager, and similar tools.
Does NOT support EWF2 (.Ex01) — that requires a separate reader.

Reference: https://github.com/libyal/libewf/blob/main/documentation/Expert%20Witness%20Compression%20Format%20(EWF).asciidoc
"""

import struct
import zlib
import os
from typing import Optional, List, Tuple


# ── EWF constants ─────────────────────────────────────────────────────────────

EWF_SIGNATURE     = b"EVF\x09\x0d\x0a\xff\x00"   # 8 bytes
EWF1_FIELDS_SIZE  = 1                              # fields_version (1 byte)
SECTOR_SIZE       = 512
DEFAULT_CHUNK_SECS = 64                            # 64 sectors per chunk = 32768 bytes

# Section type strings (13 bytes, null-padded)
SEC_HEADER  = b"header\x00\x00\x00\x00\x00\x00\x00"
SEC_HEADER2 = b"header2\x00\x00\x00\x00\x00\x00"
SEC_VOLUME  = b"volume\x00\x00\x00\x00\x00\x00\x00"
SEC_DISK    = b"disk\x00\x00\x00\x00\x00\x00\x00\x00\x00"
SEC_TABLE   = b"table\x00\x00\x00\x00\x00\x00\x00\x00"
SEC_TABLE2  = b"table2\x00\x00\x00\x00\x00\x00\x00"
SEC_DATA    = b"data\x00\x00\x00\x00\x00\x00\x00\x00\x00"
SEC_SECTORS = b"sectors\x00\x00\x00\x00\x00\x00"
SEC_HASH    = b"hash\x00\x00\x00\x00\x00\x00\x00\x00\x00"
SEC_DONE    = b"done\x00\x00\x00\x00\x00\x00\x00\x00\x00"
SEC_NEXT    = b"next\x00\x00\x00\x00\x00\x00\x00\x00\x00"


def _u16(b: bytes, o: int) -> int:
    return struct.unpack_from("<H", b, o)[0]

def _u32(b: bytes, o: int) -> int:
    return struct.unpack_from("<I", b, o)[0]

def _u64(b: bytes, o: int) -> int:
    return struct.unpack_from("<Q", b, o)[0]


class EwfReader:
    """
    Reads logical disk sectors from an EWF1 image (.E01).
    Handles single-segment files (no .E02/.E03 multi-segment support yet).
    """

    def __init__(self, path: str):
        self._path = path
        self._f = open(path, "rb")
        self._chunk_size_bytes: int = DEFAULT_CHUNK_SECS * SECTOR_SIZE
        self._sector_count: int = 0
        self._sectors_per_chunk: int = DEFAULT_CHUNK_SECS
        self._chunk_offsets: List[int] = []     # file offsets to each chunk
        self._chunk_flags:   List[int] = []     # bit 0 = compressed
        self._data_section_offset: int = 0
        self._open()

    def _open(self):
        # Verify signature
        sig = self._f.read(8)
        if sig != EWF_SIGNATURE:
            raise ValueError(f"Not an EWF file (bad signature: {sig.hex()})")

        # Skip EWF segment header (fields_start=1, fields_version=1, segment_number=u16, fields_end=1)
        # Total EWF file header = 13 bytes
        self._f.seek(13)

        # Walk section list
        self._walk_sections()

    def _walk_sections(self):
        """Walk the EWF section list starting at offset 13."""
        offset = 13

        while True:
            self._f.seek(offset)
            sec_hdr = self._f.read(76)
            if len(sec_hdr) < 76:
                break

            sec_type = sec_hdr[0:16]
            next_offset = _u64(sec_hdr, 16)
            sec_size    = _u64(sec_hdr, 24)
            # sec_hdr[32:76] = checksum area

            sec_type_stripped = sec_type.rstrip(b"\x00")

            if sec_type_stripped == b"volume" or sec_type_stripped == b"disk":
                self._parse_volume_section(offset + 76)

            elif sec_type_stripped == b"table" or sec_type_stripped == b"table2":
                self._parse_table_section(offset + 76, sec_size)

            elif sec_type_stripped == b"sectors":
                self._data_section_offset = offset + 76

            elif sec_type_stripped in (b"done", b""):
                break

            if next_offset == 0 or next_offset == offset:
                break
            offset = next_offset

    def _parse_volume_section(self, data_offset: int):
        """Parse volume/disk section to get chunk geometry."""
        self._f.seek(data_offset)
        vol = self._f.read(94)
        if len(vol) < 94:
            return

        # EWF volume section layout (EWF1):
        #   0:  media_type         (u8)
        #   1:  unknown            (3 bytes)
        #   4:  chunk_count        (u32)
        #   8:  sectors_per_chunk  (u32)
        #  12:  bytes_per_sector   (u32)
        #  16:  sector_count       (u64)
        #  24:  cylinders          (u32)
        #  28:  heads              (u32)
        #  32:  sectors_per_track  (u32)
        #  36:  media_flags        (u8)
        #  37:  unknown2           (3 bytes)
        #  40:  palm_volume_start_sector (u32)
        #  44:  unknown3           (4 bytes)
        #  48:  smart_logs_start_sector  (u32)
        #  52:  compression_level  (u8)
        #  53:  unknown4           (3 bytes)
        #  56:  error_block_size   (u32)
        #  60:  unknown5           (4 bytes)
        #  64:  uuid               (16 bytes)
        #  80:  signature          (16 bytes ... )

        sectors_per_chunk = _u32(vol, 8)
        bytes_per_sector  = _u32(vol, 12)
        sector_count      = _u64(vol, 16)

        if sectors_per_chunk > 0:
            self._sectors_per_chunk = sectors_per_chunk
        if bytes_per_sector > 0:
            self._chunk_size_bytes = sectors_per_chunk * bytes_per_sector
        if sector_count > 0:
            self._sector_count = sector_count

    def _parse_table_section(self, data_offset: int, sec_size: int):
        """Parse table section to build chunk→file-offset lookup."""
        self._f.seek(data_offset)

        # Table header (24 bytes):
        #   0:  chunk_count   (u32)
        #   4:  padding       (16 bytes)
        #  20:  crc           (u32)
        tbl_hdr = self._f.read(24)
        if len(tbl_hdr) < 24:
            return

        chunk_count = _u32(tbl_hdr, 0)
        if chunk_count == 0 or chunk_count > 10_000_000:
            return

        # Table entries: each is a u32 (file offset with bit 31 = compression flag)
        entries_data = self._f.read(chunk_count * 4)
        if len(entries_data) < chunk_count * 4:
            return

        base_offset = self._data_section_offset

        for i in range(chunk_count):
            raw = _u32(entries_data, i * 4)
            compressed = bool(raw & 0x80000000)
            file_offset = (raw & 0x7FFFFFFF) + base_offset
            self._chunk_offsets.append(file_offset)
            self._chunk_flags.append(1 if compressed else 0)

    def get_size(self) -> int:
        """Return logical disk size in bytes."""
        if self._sector_count > 0:
            return self._sector_count * SECTOR_SIZE
        if self._chunk_offsets:
            return len(self._chunk_offsets) * self._chunk_size_bytes
        # Fall back to file size estimate
        self._f.seek(0, 2)
        return self._f.tell()

    def read(self, offset: int, length: int) -> bytes:
        """Read `length` bytes from logical disk offset `offset`."""
        result = bytearray()
        remaining = length
        pos = offset

        while remaining > 0:
            chunk_idx = pos // self._chunk_size_bytes
            chunk_off = pos % self._chunk_size_bytes

            if chunk_idx >= len(self._chunk_offsets):
                break

            chunk_data = self._read_chunk(chunk_idx)
            available = len(chunk_data) - chunk_off
            if available <= 0:
                break

            take = min(remaining, available)
            result.extend(chunk_data[chunk_off:chunk_off + take])
            pos += take
            remaining -= take

        return bytes(result)

    def _read_chunk(self, idx: int) -> bytes:
        """Read and optionally decompress one chunk."""
        file_off = self._chunk_offsets[idx]
        compressed = bool(self._chunk_flags[idx])

        # Determine chunk data size
        if idx + 1 < len(self._chunk_offsets):
            next_off = self._chunk_offsets[idx + 1]
            raw_size = next_off - file_off
        else:
            # Last chunk — read up to chunk_size_bytes
            raw_size = self._chunk_size_bytes + 8  # +8 for zlib overhead

        self._f.seek(file_off)
        raw = self._f.read(raw_size)

        if compressed:
            try:
                return zlib.decompress(raw)
            except zlib.error:
                # Try with negative window (raw deflate)
                try:
                    return zlib.decompress(raw, -15)
                except zlib.error:
                    return b"\x00" * self._chunk_size_bytes
        else:
            return raw[:self._chunk_size_bytes]

    def close(self):
        self._f.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class EwfImgInfoBridge:
    """
    Duck-type pytsk3.Img_Info interface backed by our pure-Python EwfReader.
    Lets pytsk3 read from an E01 file without libewf.
    """

    def __init__(self, ewf_reader: EwfReader):
        self._reader = ewf_reader

    def read(self, offset: int, length: int) -> bytes:
        return self._reader.read(offset, length)

    def get_size(self) -> int:
        return self._reader.get_size()


def open_ewf_for_tsk(path: str):
    """
    Open an EWF file and return a pytsk3-compatible image handle.
    Uses pyewf if available, otherwise falls back to our pure-Python reader.
    """
    # Try pyewf first (most complete EWF support)
    try:
        import pyewf
        filenames = pyewf.glob(path)
        handle = pyewf.handle()
        handle.open(filenames)

        # Wrap in pytsk3's external image interface
        import pytsk3

        class _PyEwfBridge(pytsk3.Img_Info):
            def __init__(self, h):
                self._h = h
                super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)
            def read(self, offset, length):
                self._h.seek(offset)
                return self._h.read(length)
            def get_size(self):
                return self._h.get_media_size()

        return _PyEwfBridge(handle)
    except ImportError:
        pass

    # Pure-Python EWF reader → pytsk3 external bridge
    try:
        import pytsk3

        ewf = EwfReader(path)

        class _PurePyBridge(pytsk3.Img_Info):
            def __init__(self, r):
                self._r = r
                super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)
            def read(self, offset, length):
                return self._r.read(offset, length)
            def get_size(self):
                return self._r.get_size()

        return _PurePyBridge(ewf)
    except ImportError:
        pass

    # No pytsk3 at all — return raw EwfReader (limited use)
    return EwfImgInfoBridge(EwfReader(path))
