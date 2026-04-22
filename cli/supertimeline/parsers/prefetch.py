"""
Prefetch parser — supports Windows and Linux.

Priority chain:
  1. pyscca (libscca) — Linux/cross-platform, handles MAM natively
  2. windowsprefetch DecompressWin10 + Rust parser — Windows primary
  3. WSL interop (Windows Python) — Linux fallback for MAM decompression
"""

import sys
import logging
from pathlib import Path
from typing import List, Dict, Any

from supertimeline.parsers.prefetch_decompress import is_mam_compressed

log = logging.getLogger(__name__)

try:
    import supertimeline_core as _core
    _RUST = True
except ImportError:
    _RUST = False
    _core = None

try:
    import pyscca
    _PYSCCA = True
except ImportError:
    _PYSCCA = False


def parse_dir(prefetch_dir: str) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    dir_path = Path(prefetch_dir)

    if not dir_path.exists():
        log.debug("Prefetch directory not found: %s", prefetch_dir)
        return events

    for pf_path in dir_path.iterdir():
        if pf_path.suffix.lower() != ".pf" or not pf_path.is_file():
            continue
        try:
            events.extend(_parse_one(pf_path))
        except Exception as exc:
            log.warning("Skipping %s: %s", pf_path.name, exc)

    return events


def _parse_one(pf_path: Path) -> List[Dict[str, Any]]:
    # pyscca handles MAM decompression + parsing natively (Linux primary)
    if _PYSCCA:
        result = _parse_via_pyscca(pf_path)
        if result:
            return result
        # pyscca returned nothing (e.g. old libscca can't handle this MAM variant)
        # fall through to the Rust native decompressor below

    # Decompress MAM if needed (Rust native first, then platform-specific fallbacks)
    raw = pf_path.read_bytes()
    if is_mam_compressed(raw):
        data = _decompress_mam_file(pf_path, raw)
        if not data:
            return []
    else:
        data = raw

    if not _RUST:
        log.debug("Rust core not available; skipping %s", pf_path.name)
        return []

    return list(_core.parse_prefetch_bytes_decompressed(bytes(data), str(pf_path)))


def _parse_via_pyscca(pf_path: Path) -> List[Dict[str, Any]]:
    """Parse using libscca — handles MAM decompression natively."""
    import datetime
    import os

    scca = pyscca.file()
    try:
        # Suppress libscca's C-level error output — it writes directly to stderr
        devnull = os.open(os.devnull, os.O_WRONLY)
        old_stderr = os.dup(2)
        os.dup2(devnull, 2)
        try:
            scca.open(str(pf_path))
        finally:
            os.dup2(old_stderr, 2)
            os.close(old_stderr)
            os.close(devnull)
    except Exception as exc:
        log.debug("pyscca cannot open %s: %s", pf_path.name, exc)
        return []

    try:
        exe_name  = scca.get_executable_filename() or pf_path.stem
        run_count = scca.get_run_count() or 0
        events    = []

        for i in range(8):
            dt = scca.get_last_run_time(i)
            if not dt:
                continue
            if isinstance(dt, datetime.datetime):
                ts_ns = int(dt.timestamp() * 1_000_000_000)
                ts_iso = dt.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
            else:
                continue

            if ts_ns <= 0:
                continue

            events.append({
                "timestamp_ns":    ts_ns,
                "timestamp_iso":   ts_iso,
                "macb":            "....",
                "source":          "PREFETCH",
                "artifact":        "PREFETCH",
                "artifact_path":   str(pf_path),
                "message":         f"{exe_name} (run {i+1}/{run_count})",
                "is_fn_timestamp": False,
                "tz_offset_secs":  0,
            })

        return events
    finally:
        scca.close()


def _decompress_mam_file(pf_path: Path, raw: bytes) -> bytes:
    # Cross-platform: Rust native LZXPRESS Huffman decompressor (no OS deps).
    # Tried first on all platforms; falls through to platform-specific paths on failure.
    if _RUST:
        try:
            return bytes(_core.decompress_mam_py(raw))
        except Exception as exc:
            log.debug("Rust MAM decompression failed for %s: %s", pf_path.name, exc)

    # Windows: windowsprefetch uses ntdll
    try:
        from windowsprefetch.utils import DecompressWin10
        return bytes(DecompressWin10().decompress(str(pf_path)))
    except ImportError:
        pass
    except Exception as exc:
        log.warning("DecompressWin10 failed for %s: %s", pf_path.name, exc)
        return b""

    # Linux/WSL: call Windows Python via WSL interop
    try:
        import subprocess, shutil
        win_python = shutil.which("python.exe")
        if win_python:
            script = (
                "import sys; from windowsprefetch.utils import DecompressWin10; "
                f"data = DecompressWin10().decompress(r'{pf_path}'); "
                "sys.stdout.buffer.write(bytes(data))"
            )
            result = subprocess.run([win_python, "-c", script],
                                    capture_output=True, timeout=10)
            if result.returncode == 0 and result.stdout:
                return result.stdout
    except Exception as exc:
        log.warning("WSL interop decompression failed for %s: %s", pf_path.name, exc)

    log.warning("%s: MAM decompression unavailable on this platform. Skipping.", pf_path.name)
    return b""
