"""
$LogFile (NTFS transaction log) parser.

Extracts file creation/deletion/rename events from RCRD pages.
Each 4096-byte page has a USA fix-up applied across 8 x 512-byte sectors.

LFS record layout (56-byte header) → NTFS client data:
  redo_op / undo_op codes of interest:
    0x02  InitializeFileRecordSegment  — file created/overwritten, redo contains MFT record
    0x03  DeallocateFileRecordSegment  — file deleted
    0x13  UpdateFileNameRoot           — rename/hardlink in index root
    0x14  UpdateFileNameAllocation     — rename/hardlink in index allocation
"""

import struct
import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

# Page size and sector size constants
PAGE_SIZE = 4096
SECTOR_SIZE = 512
SECTORS_PER_PAGE = PAGE_SIZE // SECTOR_SIZE  # 8

# LFS record header size (3*u64 + 4*u32 + u16 + 6-byte-pad = 48 bytes)
LFS_RECORD_HEADER_SIZE = 48

# NTFS client data header size (fixed fields before redo/undo data)
NTFS_CLIENT_DATA_HEADER_SIZE = 32

# NTFS operation codes
OP_NOOP                           = 0x00
OP_COMPENSATION_LOG_RECORD        = 0x01
OP_INITIALIZE_FILE_RECORD_SEGMENT = 0x02
OP_DEALLOCATE_FILE_RECORD_SEGMENT = 0x03
OP_WRITE_END_OF_FILE_RECORD_SEGMENT = 0x04
OP_CREATE_ATTRIBUTE               = 0x05
OP_DELETE_ATTRIBUTE               = 0x06
OP_UPDATE_RESIDENT_VALUE          = 0x07
OP_UPDATE_NONRESIDENT_VALUE       = 0x08
OP_UPDATE_MAPPING_PAIRS           = 0x09
OP_DELETE_DIRTY_CLUSTERS          = 0x0A
OP_SET_NEW_ATTRIBUTE_SIZES        = 0x0B
OP_ADD_INDEX_ENTRY_ROOT           = 0x0C
OP_DELETE_INDEX_ENTRY_ROOT        = 0x0D
OP_ADD_INDEX_ENTRY_ALLOCATION     = 0x0E
OP_DELETE_INDEX_ENTRY_ALLOCATION  = 0x0F
OP_WRITE_END_OF_INDEX_BUFFER      = 0x10
OP_SET_INDEX_ENTRY_VCN_ALLOCATION = 0x11
OP_UPDATE_FILE_NAME_ROOT          = 0x12
OP_UPDATE_FILE_NAME_ALLOCATION    = 0x13
OP_SET_BITS_IN_NONRESIDENT_BIT_MAP = 0x15
OP_CLEAR_BITS_IN_NONRESIDENT_BIT_MAP = 0x16
OP_HOT_FIX                        = 0x17
OP_END_TOP_LEVEL_ACTION           = 0x18
OP_PREPARE_TRANSACTION            = 0x19
OP_COMMIT_TRANSACTION             = 0x1A
OP_FORGET_TRANSACTION             = 0x1B
OP_OPEN_NONRESIDENT_ATTRIBUTE     = 0x1C
OP_DIRTY_PAGE_TABLE_DUMP          = 0x1F
OP_TRANSACTION_TABLE_DUMP         = 0x20
OP_UPDATE_RECORD_DATA_ROOT        = 0x21


def _filetime_to_dt(ft: int) -> Optional[datetime.datetime]:
    if ft == 0:
        return None
    try:
        EPOCH = 116444736000000000
        us = (ft - EPOCH) // 10
        return datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(microseconds=us)
    except (OverflowError, OSError, ValueError):
        return None


_MAX_VALID_NS = 7_258_118_400_000_000_000  # year 2200 in nanoseconds

def _filetime_to_ns(ft: int) -> int:
    if ft == 0:
        return 0
    EPOCH = 116444736000000000
    if ft < EPOCH:
        return 0
    ns = (ft - EPOCH) * 100
    if ns > _MAX_VALID_NS:
        return 0
    return ns


def _apply_usa(page: bytearray, usa_off: int, usa_count: int) -> bool:
    """Apply Update Sequence Array fix-up in-place. Returns False if sequence number mismatch."""
    if usa_off + usa_count * 2 > len(page):
        return False
    seq_number = struct.unpack_from("<H", page, usa_off)[0]
    # usa_count includes the sequence number itself; the replacements are the remaining entries
    for i in range(1, usa_count):
        sector_end = i * SECTOR_SIZE - 2
        if sector_end + 2 > len(page):
            break
        # Verify the sector ends with the sequence number
        sector_seq = struct.unpack_from("<H", page, sector_end)[0]
        if sector_seq != seq_number:
            # Already fixed or corrupted — still proceed
            pass
        replacement = struct.unpack_from("<H", page, usa_off + i * 2)[0]
        struct.pack_into("<H", page, sector_end, replacement)
    return True


def _parse_mft_record(data: bytes, artifact_path: str) -> List[Dict[str, Any]]:
    """
    Parse an embedded MFT FILE record from $LogFile redo data.
    Extract timestamps and filename from $STANDARD_INFORMATION (0x10) and $FILE_NAME (0x30).
    """
    events: List[Dict[str, Any]] = []

    if len(data) < 48:
        return events
    if data[:4] != b"FILE":
        return events

    # MFT record header (48 bytes minimum):
    # 0x00: magic "FILE"
    # 0x04: usa_offset (u16)
    # 0x06: usa_count (u16)
    # 0x08: $LogFile LSN (u64)
    # 0x10: sequence number (u16)
    # 0x12: link count (u16)
    # 0x14: first_attr_offset (u16)
    # 0x16: flags (u16)  0x01=in use, 0x02=directory
    # 0x18: bytes_in_use (u32)
    # 0x1C: bytes_allocated (u32)
    # 0x20: base_mft_ref (u64)
    # 0x28: next_attr_id (u16)

    try:
        usa_off, usa_cnt = struct.unpack_from("<HH", data, 4)
        first_attr_off = struct.unpack_from("<H", data, 0x14)[0]
        flags = struct.unpack_from("<H", data, 0x16)[0]
    except struct.error:
        return events

    record = bytearray(data)
    if usa_off > 0 and usa_cnt > 0:
        _apply_usa(record, usa_off, usa_cnt)

    if first_attr_off < 48 or first_attr_off >= len(record):
        return events

    si_times: List[int] = []
    fn_name: str = ""
    fn_times: List[int] = []
    is_dir = bool(flags & 0x02)

    off = first_attr_off
    while off + 8 <= len(record):
        attr_type = struct.unpack_from("<I", record, off)[0]
        if attr_type == 0xFFFFFFFF:
            break

        if off + 8 > len(record):
            break
        attr_len = struct.unpack_from("<I", record, off + 4)[0]
        if attr_len < 8 or off + attr_len > len(record):
            break

        # Only resident attributes carry inline data we can parse
        non_resident = record[off + 8]
        if non_resident == 0:
            content_off = struct.unpack_from("<H", record, off + 20)[0]
            content_len = struct.unpack_from("<I", record, off + 16)[0]
            content_start = off + content_off
            content_end = content_start + content_len

            if content_end <= len(record) and content_off > 0:
                attr_data = bytes(record[content_start:content_end])

                if attr_type == 0x10 and len(attr_data) >= 48:
                    # $STANDARD_INFORMATION: created, modified, mft_modified, accessed (8 bytes each)
                    c, m, x, a = struct.unpack_from("<QQQQ", attr_data, 0)
                    si_times = [c, m, x, a]

                elif attr_type == 0x30 and len(attr_data) >= 66:
                    # $FILE_NAME:
                    # 0x00: parent MFT ref (u64)
                    # 0x08: created (u64)
                    # 0x10: modified (u64)
                    # 0x18: mft_modified (u64)
                    # 0x20: accessed (u64)
                    # 0x28: alloc_size (u64)
                    # 0x30: real_size (u64)
                    # 0x38: flags (u32)
                    # 0x3C: reparse (u32)
                    # 0x40: name_len (u8)  — in characters
                    # 0x41: namespace (u8)
                    # 0x42: name (UTF-16LE)
                    fc, fm, fx, fa = struct.unpack_from("<QQQQ", attr_data, 8)
                    fn_times = [fc, fm, fx, fa]
                    name_len = attr_data[0x40]
                    if len(attr_data) >= 0x42 + name_len * 2:
                        fn_name = attr_data[0x42:0x42 + name_len * 2].decode("utf-16-le", errors="replace")

        off += attr_len

    # Use $FILE_NAME times preferentially (MACB), fall back to $SI
    times = fn_times if fn_times else si_times
    if not times or not fn_name:
        return events

    labels = ["M", "A", "C", "B"]  # modified, accessed, $MFT-modified, birth(created)
    attr_labels = [0, 3, 2, 1]     # MACB → indices: modified=0,accessed=3,$MFT=2,birth=1

    for i, (label, t_idx) in enumerate(zip(labels, [1, 3, 2, 0])):
        if t_idx >= len(times):
            continue
        ft = times[t_idx]
        ts_ns = _filetime_to_ns(ft)
        if ts_ns == 0:
            continue
        macb = label
        events.append({
            "timestamp_ns": ts_ns,
            "macb": macb,
            "source": "LOGFILE",
            "artifact": "$LogFile MFT Record",
            "message": f"{'[DIR] ' if is_dir else ''}{fn_name}",
            "is_fn_timestamp": True,
        })

    return events


def _parse_file_name_from_data(data: bytes, artifact_path: str, op_label: str) -> List[Dict[str, Any]]:
    """
    Parse a $FILE_NAME attribute structure directly from redo/undo data
    (used by UpdateFileNameRoot/Alloc).
    """
    events: List[Dict[str, Any]] = []
    if len(data) < 66:
        return events

    try:
        fc, fm, fx, fa = struct.unpack_from("<QQQQ", data, 8)
        name_len = data[0x40]
        if len(data) < 0x42 + name_len * 2:
            return events
        fn_name = data[0x42:0x42 + name_len * 2].decode("utf-16-le", errors="replace")
    except (struct.error, IndexError):
        return events

    times = [fc, fm, fx, fa]
    for label, t_idx in zip(["M", "A", "C", "B"], [1, 3, 2, 0]):
        ft = times[t_idx]
        ts_ns = _filetime_to_ns(ft)
        if ts_ns == 0:
            continue
        events.append({
            "timestamp_ns": ts_ns,
            "macb": label,
            "source": "LOGFILE",
            "artifact": f"$LogFile {op_label}",
            "message": fn_name,
            "is_fn_timestamp": True,
        })

    return events


def parse_logfile(path: str) -> List[Dict[str, Any]]:
    """
    Parse a $LogFile extracted from NTFS and return timeline events.
    """
    events: List[Dict[str, Any]] = []

    try:
        raw = Path(path).read_bytes()
    except OSError:
        return events

    if len(raw) < PAGE_SIZE * 3:
        return events

    num_pages = len(raw) // PAGE_SIZE

    # Pages 0 and 1 are RSTR (restart) — skip them
    for page_idx in range(2, num_pages):
        page_start = page_idx * PAGE_SIZE
        page_end = page_start + PAGE_SIZE
        page = bytearray(raw[page_start:page_end])

        # Verify RCRD magic
        if page[:4] != b"RCRD":
            continue

        # Read USA fields
        if len(page) < 8:
            continue
        usa_off = struct.unpack_from("<H", page, 4)[0]
        usa_cnt = struct.unpack_from("<H", page, 6)[0]

        if usa_off == 0 or usa_cnt == 0 or usa_cnt > SECTORS_PER_PAGE + 1:
            continue

        _apply_usa(page, usa_off, usa_cnt)

        # next_record_offset at 0x18: first free byte (where records end)
        # Log records always start at 0x40 in Windows LFS pages (fixed header size)
        if len(page) < 0x40:
            continue

        next_rec_off = struct.unpack_from("<H", page, 0x18)[0]
        data_off = 0x40  # Windows LFS page header is always 64 bytes

        if next_rec_off == 0 or next_rec_off > PAGE_SIZE:
            next_rec_off = PAGE_SIZE

        off = data_off
        while off + LFS_RECORD_HEADER_SIZE <= next_rec_off:
            # LFS log record header (48 bytes):
            # 0x00: this_lsn (u64)
            # 0x08: client_previous_lsn (u64)
            # 0x10: client_undo_next_lsn (u64)
            # 0x18: client_data_length (u32)
            # 0x1C: client_id (u32)
            # 0x20: record_type (u32)  1=client data, 2=client restart
            # 0x24: transaction_id (u32)
            # 0x28: flags (u16)
            # 0x2A: reserved (6 bytes)
            # Total: 0x30 = 48 bytes

            try:
                this_lsn = struct.unpack_from("<Q", page, off)[0]
                client_data_len = struct.unpack_from("<I", page, off + 0x18)[0]
                record_type = struct.unpack_from("<I", page, off + 0x20)[0]
            except struct.error:
                break

            # Sanity checks
            if this_lsn == 0 and client_data_len == 0:
                break  # empty slot

            if record_type not in (1, 2):
                # Not a valid client record type — advance by 8 (alignment unit)
                off += 8
                continue

            if client_data_len == 0 or client_data_len > PAGE_SIZE:
                off += LFS_RECORD_HEADER_SIZE
                continue

            client_data_start = off + LFS_RECORD_HEADER_SIZE
            client_data_end = client_data_start + client_data_len

            if client_data_end > PAGE_SIZE:
                # Record spans pages — skip (multi-page records are rare and complex)
                off += LFS_RECORD_HEADER_SIZE
                continue

            client_data = bytes(page[client_data_start:client_data_end])

            if len(client_data) >= NTFS_CLIENT_DATA_HEADER_SIZE:
                evts = _parse_ntfs_client_data(client_data, path)
                events.extend(evts)

            # Advance: LFS header + client data, aligned to 8 bytes
            total = LFS_RECORD_HEADER_SIZE + client_data_len
            aligned = (total + 7) & ~7
            off += aligned

    return events


def _parse_ntfs_client_data(data: bytes, artifact_path: str) -> List[Dict[str, Any]]:
    """
    Parse NTFS client data from an LFS log record.

    NTFS client data header (32 bytes):
      0x00: redo_op (u16)
      0x02: undo_op (u16)
      0x04: redo_offset (u16)
      0x06: redo_length (u16)
      0x08: undo_offset (u16)
      0x0A: undo_length (u16)
      0x0C: target_attribute (u16)
      0x0E: lcns_to_follow (u16)
      0x10: record_offset (u16)
      0x12: attribute_offset (u16)
      0x14: cluster_block_offset (u16)
      0x16: reserved (u16)
      0x18: target_vcn (u64)  — 8 bytes
      After header (0x20): lcn_array (u64 * lcns_to_follow)
      After lcn_array: redo_data at redo_offset from start of client_data
    """
    events: List[Dict[str, Any]] = []

    if len(data) < NTFS_CLIENT_DATA_HEADER_SIZE:
        return events

    try:
        redo_op = struct.unpack_from("<H", data, 0x00)[0]
        undo_op = struct.unpack_from("<H", data, 0x02)[0]
        redo_off = struct.unpack_from("<H", data, 0x04)[0]
        redo_len = struct.unpack_from("<H", data, 0x06)[0]
        lcns_to_follow = struct.unpack_from("<H", data, 0x0E)[0]
    except struct.error:
        return events

    # Redo data starts at redo_off from start of this client data block
    if redo_off > 0 and redo_len > 0:
        redo_start = redo_off
        redo_end = redo_off + redo_len
        if redo_end <= len(data):
            redo_data = data[redo_start:redo_end]
        else:
            redo_data = b""
    else:
        redo_data = b""

    if redo_op == OP_INITIALIZE_FILE_RECORD_SEGMENT and len(redo_data) >= 48:
        # redo_data is a complete MFT FILE record
        evts = _parse_mft_record(redo_data, artifact_path)
        events.extend(evts)

    elif redo_op == OP_DEALLOCATE_FILE_RECORD_SEGMENT:
        pass  # No timestamp available in this record

    elif redo_op in (OP_UPDATE_FILE_NAME_ROOT, OP_UPDATE_FILE_NAME_ALLOCATION):
        if len(redo_data) >= 66:
            label = "UpdateFN-Root" if redo_op == OP_UPDATE_FILE_NAME_ROOT else "UpdateFN-Alloc"
            evts = _parse_file_name_from_data(redo_data, artifact_path, label)
            events.extend(evts)

    elif redo_op in (OP_ADD_INDEX_ENTRY_ROOT, OP_ADD_INDEX_ENTRY_ALLOCATION):
        # redo_data is an INDEX_ENTRY; FILE_NAME starts at offset 0x10
        if len(redo_data) >= 0x10 + 66:
            fn_data = redo_data[0x10:]
            label = "AddIdx-Root" if redo_op == OP_ADD_INDEX_ENTRY_ROOT else "AddIdx-Alloc"
            evts = _parse_file_name_from_data(fn_data, artifact_path, label)
            events.extend(evts)

    return events
