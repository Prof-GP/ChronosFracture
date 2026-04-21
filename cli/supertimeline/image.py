"""
Forensic image abstraction layer.

Supports:
  - Mounted volumes / directories (always, no extra deps)
  - Raw / dd images     (requires pytsk3)
  - E01 / EWF images   (requires pytsk3 + libewf)
  - VMDK images         (requires pytsk3 + libvmdk)
  - VHD / VHDX images  (requires pytsk3 + libvhdi)

If pytsk3 is not installed the tool prints a clear message and lists
the Arsenal Image Mounter / ewfmount commands to pre-mount the image.
"""

from __future__ import annotations

import os
import struct
import tempfile
import shutil
from pathlib import Path
from typing import Iterator, Optional, Dict, Tuple
from dataclasses import dataclass, field
from enum import Enum, auto

# ── Image format detection ────────────────────────────────────────────────────

class ImageFormat(Enum):
    DIRECTORY  = auto()   # already mounted / plain directory
    RAW        = auto()   # raw dd / .img / .bin
    EWF        = auto()   # Expert Witness Format (.E01, .Ex01, .L01)
    VMDK       = auto()   # VMware virtual disk
    VHD        = auto()   # Microsoft VHD
    VHDX       = auto()   # Microsoft VHDX
    QCOW2      = auto()   # QEMU QCOW2
    UNKNOWN    = auto()

# Magic bytes for image format identification
_MAGIC: list[Tuple[bytes, int, ImageFormat]] = [
    (b"EVF",                    0, ImageFormat.EWF),    # EnCase E01
    (b"SMART",                  0, ImageFormat.EWF),    # SMART E01
    (b"LVF",                    0, ImageFormat.EWF),    # L01 logical
    (b"KDMV",                   0, ImageFormat.VMDK),   # VMDK sparse
    (b"COWD",                   0, ImageFormat.VMDK),   # VMDK COWD
    (b"conectix",               0, ImageFormat.VHD),    # VHD footer
    (b"vhdxfile",               0, ImageFormat.VHDX),   # VHDX
    (b"\x51\xfb\x52\x02\x00",  0, ImageFormat.QCOW2),  # QCOW2
]

_EWF_EXTENSIONS  = {".e01",".ex01",".l01",".lx01",".s01",".sx01"}
_VMDK_EXTENSIONS = {".vmdk"}
_VHD_EXTENSIONS  = {".vhd"}
_VHDX_EXTENSIONS = {".vhdx"}
_RAW_EXTENSIONS  = {".dd",".raw",".img",".bin",".001"}


def detect_format(path: str) -> ImageFormat:
    p = Path(path)

    if p.is_dir():
        return ImageFormat.DIRECTORY

    ext = p.suffix.lower()
    if ext in _EWF_EXTENSIONS:
        return ImageFormat.EWF
    if ext in _VMDK_EXTENSIONS:
        return ImageFormat.VMDK
    if ext in _VHD_EXTENSIONS:
        return ImageFormat.VHD
    if ext in _VHDX_EXTENSIONS:
        return ImageFormat.VHDX

    # Try magic bytes (first 16 bytes)
    try:
        with open(path, "rb") as f:
            header = f.read(16)
        for magic, offset, fmt in _MAGIC:
            if header[offset:offset+len(magic)] == magic:
                return fmt
    except OSError:
        pass

    # Windows drive letter (e.g. "E:\") or root "/" → treat as mounted
    if str(p) in ("/",) or (len(p.parts) == 1 and str(p).endswith(("\\", "/"))):
        return ImageFormat.DIRECTORY

    # Assume raw if it's a large file with no recognised magic
    if ext in _RAW_EXTENSIONS:
        return ImageFormat.RAW

    return ImageFormat.UNKNOWN


# ── pytsk3 availability check ────────────────────────────────────────────────

try:
    import pytsk3
    _TSK_AVAILABLE = True
except ImportError:
    _TSK_AVAILABLE = False

try:
    import pyewf  # type: ignore[import]
    _EWF_AVAILABLE = True
except ImportError:
    _EWF_AVAILABLE = False


# ── EWF image handle (bridges pyewf → pytsk3) ────────────────────────────────

def _make_ewf_img_info(ewf_handle):
    """Build a pytsk3.Img_Info subclass backed by a pyewf handle (avoids class-time import)."""
    class _EwfImgInfo(pytsk3.Img_Info):
        def __init__(self, h):
            self._h = h
            super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)
        def read(self, offset: int, length: int) -> bytes:
            self._h.seek(offset)
            return self._h.read(length)
        def get_size(self) -> int:
            return self._h.get_media_size()
    return _EwfImgInfo(ewf_handle)


# ── Artifact extraction using pytsk3 ─────────────────────────────────────────

# Paths to extract from NTFS (relative to partition root)
_EXTRACT_TARGETS: Dict[str, str] = {
    "$MFT":                        "MFT",
    "$LogFile":                    "LogFile",          # NTFS transaction log
    "$Extend/$UsnJrnl:$J":         "UsnJrnl_J",        # USN change journal (sparse)
    "$Extend/$UsnJrnl:$Max":       "UsnJrnl_Max",      # USN journal config
    "Windows/System32/winevt/Logs": "evtx",
    "Windows/Prefetch":             "Prefetch",
    "Windows/System32/config/SYSTEM":   "SYSTEM",
    "Windows/System32/config/SOFTWARE": "SOFTWARE",
    "Windows/System32/config/SAM":      "SAM",
    "Windows/System32/config/SECURITY": "SECURITY",
    "Windows/System32/sru/SRUDB.dat":   "SRUDB.dat",
    "Windows/AppCompat/Programs/Amcache.hve": "Amcache.hve",
    "Windows/appcompat/pca/PcaAppLaunchDic.txt": "PcaAppLaunchDic.txt",
    "Windows/appcompat/pca/PcaGeneralDb0.txt":   "PcaGeneralDb0.txt",
    "Windows/appcompat/pca/PcaGeneralDb1.txt":   "PcaGeneralDb1.txt",
    # Per-user Recent dirs are extracted dynamically by _tsk_extract_user_recent()
    # into Recent/<username>/ and registered here as a single directory target.
}

# Maps extracted flat name → (artifact_type, is_directory)
# Mirrors _EXTRACT_TARGETS so the orchestrator can discover from a temp dir
EXTRACTED_ARTIFACT_MAP: Dict[str, Tuple[str, bool]] = {
    "MFT":          ("MFT",       False),
    "LogFile":      ("LOGFILE",   False),
    "UsnJrnl_J":    ("USNJRNL",   False),
    "UsnJrnl_Max":  ("USNJRNL",   False),   # config header, parsed alongside $J
    "evtx":         ("EVTX",      True),
    "Prefetch":     ("PREFETCH",  True),
    "SYSTEM":       ("REGISTRY",  False),
    "SOFTWARE":     ("REGISTRY",  False),
    "SAM":          ("REGISTRY",  False),
    "SECURITY":     ("REGISTRY",  False),
    "SRUDB.dat":    ("SRUM",      False),
    "Amcache.hve":           ("AMCACHE",  False),
    "PcaAppLaunchDic.txt":   ("PCASVC",   False),
    "PcaGeneralDb0.txt":     ("PCASVC",   False),
    "PcaGeneralDb1.txt":     ("PCASVC",   False),
    "Recent":       ("LNK",       True),    # per-user Recent dirs, extracted dynamically
}


def _tsk_extract_file(fs_obj, inode_path: str, dest_path: str,
                      sparse_aware: bool = False) -> bool:
    """
    Extract a single file from a pytsk3 filesystem object.

    sparse_aware=True skips zero-filled sparse regions — required for
    $UsnJrnl:$J which is a sparse file whose allocated clusters are at
    a high logical offset (the tail of the journal).  Without this,
    read_random() returns zeros for every unallocated byte and the
    extracted file would be gigabytes of nothing.

    When sparse_aware is set we read each 1 MiB block and skip it if
    entirely zero.  This preserves real data while discarding the
    sparse prefix, producing a compact file that parsers can handle.
    """
    try:
        f = fs_obj.open(inode_path)
        size = f.info.meta.size
        if size == 0:
            return False
        chunk = 1024 * 1024
        with open(dest_path, "wb") as out:
            offset = 0
            wrote_any = False
            while offset < size:
                read_len = min(chunk, size - offset)
                data = f.read_random(offset, read_len)
                if not data:
                    break
                if sparse_aware and not any(data):
                    offset += len(data)
                    continue
                out.write(data)
                wrote_any = True
                offset += len(data)
        if sparse_aware and not wrote_any:
            # All sparse — remove the empty file
            try:
                os.remove(dest_path)
            except OSError:
                pass
            return False
        return True
    except Exception:
        return False


def _tsk_extract_dir(fs_obj, inode_path: str, dest_dir: str) -> int:
    """Recursively extract a directory from a pytsk3 filesystem object."""
    count = 0
    try:
        d = fs_obj.open_dir(inode_path)
        os.makedirs(dest_dir, exist_ok=True)
        for entry in d:
            name = entry.info.name.name
            if isinstance(name, bytes):
                name = name.decode("utf-8", errors="replace")
            if name in (".", ".."):
                continue
            dest = os.path.join(dest_dir, name)
            try:
                if entry.info.meta and entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                    count += _tsk_extract_dir(fs_obj, f"{inode_path}/{name}", dest)
                else:
                    if _tsk_extract_file(fs_obj, f"{inode_path}/{name}", dest):
                        count += 1
            except Exception:
                continue
    except Exception:
        pass
    return count


def _tsk_extract_user_recent(fs_obj, tmp_dir: str) -> int:
    """
    Enumerate Users/ on the filesystem and extract each user's Recent/ directory.

    Output structure:
        <tmp_dir>/Recent/<username>/
            *.lnk
            AutomaticDestinations/*.automaticDestinations-ms
            CustomDestinations/*.customDestinations-ms
    """
    count = 0
    dest_root = os.path.join(tmp_dir, "Recent")
    try:
        users_dir = fs_obj.open_dir("Users")
    except Exception:
        return 0

    for entry in users_dir:
        name = entry.info.name.name
        if isinstance(name, bytes):
            name = name.decode("utf-8", errors="replace")
        if name in (".", "..", "All Users", "Default", "Default User", "Public"):
            continue
        if not (entry.info.meta and entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR):
            continue

        recent_src = f"Users/{name}/AppData/Roaming/Microsoft/Windows/Recent"
        recent_dst = os.path.join(dest_root, name)
        try:
            n = _tsk_extract_dir(fs_obj, recent_src, recent_dst)
            if n > 0:
                count += n
        except Exception:
            continue

    return count


def _get_partition_offset(img_info) -> int:
    """
    Return byte offset of the largest NTFS partition.
    Tries pytsk3.Volume_Info first; falls back to MBR parsing.
    """
    # Try pytsk3 volume scanner
    try:
        vol = pytsk3.Volume_Info(img_info)
        best_offset = 0
        best_size = 0
        for part in vol:
            if part.flags != pytsk3.TSK_VS_PART_FLAG_ALLOC:
                continue
            fs_offset = part.start * 512
            try:
                pytsk3.FS_Info(img_info, offset=fs_offset)
                # Pick the largest accessible partition (main OS volume)
                if part.len > best_size:
                    best_size = part.len
                    best_offset = fs_offset
            except Exception:
                continue
        if best_offset > 0:
            return best_offset
    except Exception:
        pass

    # Fall back: parse MBR manually and pick largest type-07 (NTFS) partition
    try:
        mbr = img_info.read(0, 512)
        if mbr[510:512] == b"\x55\xaa":
            best_start = 0
            best_size  = 0
            for i in range(4):
                pe     = mbr[446 + i * 16 : 446 + i * 16 + 16]
                ptype  = pe[4]
                start  = int.from_bytes(pe[8:12],  "little")
                size   = int.from_bytes(pe[12:16], "little")
                # 0x07 = NTFS/exFAT, 0x0B/0x0C = FAT32
                if ptype in (0x07, 0x0B, 0x0C) and size > best_size:
                    best_size  = size
                    best_start = start
            if best_start > 0:
                return best_start * 512
    except Exception:
        pass

    return 0


def extract_artifacts_from_image(image_path: str, fmt: ImageFormat,
                                  progress_cb=None) -> Optional[str]:
    """
    Extract forensic artifacts from an image file into a temp directory.

    Returns the temp directory path (caller must delete it), or None on failure.
    Requires pytsk3 (and pyewf for E01 images).
    """
    if not _TSK_AVAILABLE:
        return None

    tmp_dir = tempfile.mkdtemp(prefix="supertimeline_extracted_")

    try:
        import sys
        img_info = None
        last_err = ""

        # ── EWF: must use pyewf bridge — pytsk3.Img_Info reads raw EWF ──────
        if fmt == ImageFormat.EWF and _EWF_AVAILABLE:
            try:
                ewf_path = image_path.replace("/", "\\") if sys.platform == "win32" else image_path
                filenames = pyewf.glob(ewf_path)
                ewf_handle = pyewf.handle()
                ewf_handle.open(filenames)
                img_info = _make_ewf_img_info(ewf_handle)
            except Exception as e:
                last_err = str(e)

        # ── Raw / VMDK / VHD: try pytsk3 direct ─────────────────────────────
        if img_info is None and fmt != ImageFormat.EWF:
            try:
                img_info = pytsk3.Img_Info(image_path)
            except Exception as e:
                last_err = str(e)

        if img_info is None:
            raise RuntimeError(f"Could not open image: {last_err}")

        # Find NTFS partition
        fs_offset = _get_partition_offset(img_info)
        fs = pytsk3.FS_Info(img_info, offset=fs_offset)

        # $J is a sparse file — the journal entries live at the tail of a huge
        # logical address space.  Read in sparse-aware mode so we skip the
        # zero-filled prefix and only write the allocated (non-zero) blocks.
        _SPARSE_TARGETS = {"$Extend/$UsnJrnl:$J"}

        # Directories to recurse into
        _DIR_TARGETS = {"Windows/System32/winevt/Logs", "Windows/Prefetch"}

        for src_path, dest_name in _EXTRACT_TARGETS.items():
            if progress_cb:
                progress_cb(src_path)
            dest = os.path.join(tmp_dir, dest_name)
            if src_path in _DIR_TARGETS:
                _tsk_extract_dir(fs, src_path, dest)
            else:
                sparse = src_path in _SPARSE_TARGETS
                _tsk_extract_file(fs, src_path, dest, sparse_aware=sparse)

        # Per-user Recent directories (LNK files + Jump Lists)
        if progress_cb:
            progress_cb("Users/*/AppData/Roaming/Microsoft/Windows/Recent")
        _tsk_extract_user_recent(fs, tmp_dir)

        return tmp_dir

    except Exception as e:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise RuntimeError(f"Failed to extract artifacts from image: {e}") from e


# ── Public API ────────────────────────────────────────────────────────────────

MOUNT_INSTRUCTIONS = {
    ImageFormat.EWF: """
  Arsenal Image Mounter (Windows):
    ArsenalImageMounter.exe /mount /filename "{path}" /readonly /letter X

  ewfmount (Linux):
    ewfmount "{path}" /mnt/ewf && \
    mount -o ro,loop,offset=$(partx -o START -g -s /mnt/ewf/ewf1 | head -1) \
          /mnt/ewf/ewf1 /mnt/image

  Then run:
    supertimeline X:\\ -o timeline.parquet          # Windows
    supertimeline /mnt/image -o timeline.parquet    # Linux
""",
    ImageFormat.VMDK: """
  Arsenal Image Mounter (Windows):
    ArsenalImageMounter.exe /mount /filename "{path}" /readonly /letter X

  vmware-mount (Linux):
    vmware-mount "{path}" /mnt/vmdk -r
    mount -o ro /mnt/vmdk/...

  VBoxManage (Linux):
    VBoxManage internalcommands createrawvmdk -filename /tmp/raw.vmdk \\
               -rawdisk "{path}"
    mount ...

  Then run:
    supertimeline X:\\ -o timeline.parquet
""",
    ImageFormat.VHD: """
  Windows (diskpart):
    diskpart
    > SELECT VDISK FILE="{path}"
    > ATTACH VDISK READONLY
    > LIST VOLUME   (note new drive letter)

  Linux:
    modprobe nbd max_part=8
    qemu-nbd --connect=/dev/nbd0 -r "{path}"
    mount /dev/nbd0p1 /mnt/vhd

  Then run:
    supertimeline X:\\ -o timeline.parquet
""",
    ImageFormat.VHDX: """
  Same as VHD — Windows diskpart or Linux qemu-nbd support VHDX.
""",
    ImageFormat.RAW: """
  For raw/dd images with pytsk3 not installed:

    Linux (loopback):
      OFFSET=$(fdisk -l "{path}" | grep Linux | awk '{{print $2 * 512}}')
      mount -o ro,loop,offset=$OFFSET "{path}" /mnt/raw

    Windows (Arsenal Image Mounter):
      ArsenalImageMounter.exe /mount /filename "{path}" /readonly /letter X

  Then run:
    supertimeline /mnt/raw -o timeline.parquet
""",
}


def open_image(path: str, progress_cb=None) -> Tuple[str, ImageFormat, Optional[str]]:
    """
    Resolve an image path to a root directory for artifact discovery.

    Returns:
        (root_path, format, temp_dir_or_None)
        temp_dir must be deleted by caller when done.

    Raises:
        RuntimeError if the image cannot be opened.
    """
    fmt = detect_format(path)

    if fmt == ImageFormat.DIRECTORY:
        return path, fmt, None

    # Try direct extraction via pytsk3
    if _TSK_AVAILABLE and fmt in (ImageFormat.RAW, ImageFormat.EWF,
                                   ImageFormat.VMDK, ImageFormat.VHD,
                                   ImageFormat.VHDX):
        tmp = extract_artifacts_from_image(path, fmt, progress_cb=progress_cb)
        if tmp:
            return tmp, fmt, tmp

    # No pytsk3 or extraction failed — print mount instructions
    instructions = MOUNT_INSTRUCTIONS.get(fmt, "")
    instructions = instructions.format(path=path)
    raise RuntimeError(
        f"Cannot read '{path}' directly (format: {fmt.name}, pytsk3={'yes' if _TSK_AVAILABLE else 'no'}).\n\n"
        f"Options:\n"
        f"  1) Install pytsk3:  pip install pytsk3\n"
        f"     For E01 also:    pip install pyewf\n"
        f"  2) Mount manually and pass the mount point:\n"
        f"{instructions}"
    )
