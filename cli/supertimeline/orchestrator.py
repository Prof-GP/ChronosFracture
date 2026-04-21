"""
Artifact discovery and parallel parser dispatch.

Key behaviours:
  - Accepts mounted drives, directories, raw/dd images, E01, VMDK, VHD/VHDX
  - Missing artifacts are SKIPPED — a run never stops because one file is absent
  - Parser exceptions are caught per-artifact — one corrupt file cannot kill the run
  - All parsers run concurrently (ThreadPoolExecutor, Rust releases GIL)
  - Events stream to the writer as each parser completes (no full-load wait)
"""

from __future__ import annotations

import os
import sys
import glob
import time
import logging
import shutil
import concurrent.futures
from pathlib import Path
from typing import Iterator, List, Dict, Any, Callable, Optional
from dataclasses import dataclass, field

log = logging.getLogger(__name__)

# ── Rust core (optional — graceful fallback to Python parsers) ────────────────
try:
    import supertimeline_core as _core
    RUST_AVAILABLE = True
except ImportError:
    RUST_AVAILABLE = False
    _core = None

# ── Artifact location patterns (Windows volume-relative) ──────────────────────
# Each entry: (artifact_type, path_pattern, is_directory)
# Patterns use forward slashes; * = glob wildcard; dir=True = whole directory
ARTIFACT_PATTERNS: List[tuple[str, str, bool]] = [
    # NTFS journal artifacts (highest event density)
    ("MFT",       "$MFT",                                                  False),
    ("USNJRNL",   "$Extend/$UsnJrnl:$J",                                   False),
    ("USNJRNL",   "$Extend/$J",                                             False),

    # Event logs (typically the largest source)
    ("EVTX",      "Windows/System32/winevt/Logs/*.evtx",                   False),

    # Execution artifacts
    ("PREFETCH",  "Windows/Prefetch/",                                      True),
    ("SRUM",      "Windows/System32/sru/SRUDB.dat",                        False),
    ("AMCACHE",   "Windows/AppCompat/Programs/Amcache.hve",                 False),

    # User activity artifacts (per-user, wildcard paths)
    ("LNK",       "Users/*/AppData/Roaming/Microsoft/Windows/Recent/",     True),

    # Registry hives
    ("REGISTRY",  "Windows/System32/config/SYSTEM",                        False),
    ("REGISTRY",  "Windows/System32/config/SOFTWARE",                      False),
    ("REGISTRY",  "Windows/System32/config/SAM",                           False),
    ("REGISTRY",  "Windows/System32/config/SECURITY",                      False),
    ("REGISTRY",  "Users/*/NTUSER.DAT",                                    False),
    ("REGISTRY",  "Users/*/AppData/Local/Microsoft/Windows/UsrClass.dat",  False),

]


@dataclass
class ArtifactJob:
    artifact_type: str
    path: str           # absolute path to file or directory (may be a temp extraction path)
    size_bytes: int = 0
    is_directory: bool = False
    logical_path: str = ""  # evidence-relative path (e.g. "$MFT", "Windows\System32\winevt\Logs\System.evtx")


@dataclass
class ParseResult:
    artifact_type: str
    path: str
    event_count: int
    elapsed_secs: float
    events: List[Dict[str, Any]] = field(default_factory=list)
    error: str = ""
    skipped: bool = False   # True when artifact was not found (normal — not an error)


# ── Artifact discovery ────────────────────────────────────────────────────────

def _glob_ci(pattern: str) -> List[str]:
    """
    Case-insensitive glob — required on Linux where NTFS mounts via ntfs-3g
    preserve Windows mixed case (e.g. 'Windows' not 'windows').
    On Windows, the filesystem is already case-insensitive so standard glob works.
    """
    if sys.platform == "win32":
        return glob.glob(pattern, recursive=False)

    # On Linux: try exact case first, then walk parent and match case-insensitively
    exact = glob.glob(pattern, recursive=False)
    if exact:
        return exact

    # Build a case-insensitive version of the pattern
    import re
    parts = Path(pattern).parts
    current_paths = [Path(parts[0])]
    for part in parts[1:]:
        next_paths = []
        for base in current_paths:
            if not base.exists():
                continue
            if "*" in part:
                # Expand glob case-insensitively
                pat = re.compile("^" + re.escape(part).replace(r"\*", ".*") + "$", re.IGNORECASE)
                try:
                    for child in base.iterdir():
                        if pat.match(child.name):
                            next_paths.append(child)
                except OSError:
                    pass
            else:
                # Case-insensitive directory/file name match
                try:
                    for child in base.iterdir():
                        if child.name.lower() == part.lower():
                            next_paths.append(child)
                            break
                except OSError:
                    pass
        current_paths = next_paths

    return [str(p) for p in current_paths]


def discover_artifacts(root: str) -> List[ArtifactJob]:
    """
    Walk root and find all known forensic artifacts.
    Missing files are silently skipped — never raises.
    Uses case-insensitive path matching on Linux (NTFS mounts via ntfs-3g).
    Returns jobs sorted largest-first for better CPU utilisation.
    """
    jobs: List[ArtifactJob] = []
    root_path = Path(root)

    for artifact_type, pattern, is_directory in ARTIFACT_PATTERNS:
        full_pattern = str(root_path / pattern.replace("/", os.sep))

        if "*" in full_pattern:
            matches = _glob_ci(full_pattern)
        else:
            matches = _glob_ci(full_pattern)

        for match in matches:
            p = Path(match)
            if not p.exists():
                continue
            try:
                size = (
                    sum(f.stat().st_size for f in p.rglob("*") if f.is_file())
                    if is_directory else p.stat().st_size
                )
            except OSError:
                size = 0

            jobs.append(ArtifactJob(
                artifact_type=artifact_type,
                path=str(p),
                size_bytes=size,
                is_directory=is_directory,
            ))

    # Deduplicate (same path can match multiple patterns)
    seen: set[str] = set()
    unique: List[ArtifactJob] = []
    for j in jobs:
        if j.path not in seen:
            seen.add(j.path)
            unique.append(j)

    unique.sort(key=lambda j: j.size_bytes, reverse=True)
    return unique


# ── Parser dispatch ───────────────────────────────────────────────────────────

def _dispatch_job(job: ArtifactJob) -> ParseResult:
    """
    Run the appropriate parser for one artifact.
    Any exception is caught and stored in ParseResult.error.
    The run ALWAYS continues regardless of outcome.
    """
    t0 = time.perf_counter()
    events: List[Dict[str, Any]] = []
    error = ""

    try:
        if RUST_AVAILABLE:
            events = _dispatch_rust(job)
        else:
            events = _dispatch_python(job)
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
        log.warning("Parser error [%s] %s — %s", job.artifact_type, job.path, error)

    # Remap temp extraction paths to evidence-relative logical paths
    if job.logical_path and events:
        lpath = job.logical_path
        if job.is_directory:
            for ev in events:
                fname = Path(ev.get("artifact_path", "")).name
                ev["artifact_path"] = f"{lpath}\\{fname}" if fname else lpath
        else:
            for ev in events:
                ev["artifact_path"] = lpath

    return ParseResult(
        artifact_type=job.artifact_type,
        path=job.path,
        event_count=len(events),
        elapsed_secs=time.perf_counter() - t0,
        events=events,
        error=error,
    )


def _dispatch_rust(job: ArtifactJob) -> List[Dict[str, Any]]:
    if job.artifact_type == "MFT":
        return list(_core.parse_mft_file(job.path))

    if job.artifact_type == "USNJRNL":
        return list(_core.parse_usnjrnl_file(job.path))

    if job.artifact_type == "EVTX":
        return list(_core.parse_evtx_file(job.path))

    if job.artifact_type == "PREFETCH":
        # Python wrapper handles MAM decompression before calling Rust
        from supertimeline.parsers.prefetch import parse_dir
        return parse_dir(job.path)

    if job.artifact_type == "LNK":
        from supertimeline.parsers.lnk import parse_dir as parse_lnk_dir
        return parse_lnk_dir(job.path)

    # Fall through to Python parsers for remaining types
    return _dispatch_python(job)


def _dispatch_python(job: ArtifactJob) -> List[Dict[str, Any]]:
    if job.artifact_type == "REGISTRY":
        from supertimeline.parsers.registry import parse
        return parse(job.path)

    if job.artifact_type == "SRUM":
        from supertimeline.parsers.srum import parse
        return parse(job.path)

    if job.artifact_type == "PREFETCH":
        from supertimeline.parsers.prefetch import parse_dir
        return parse_dir(job.path)

    if job.artifact_type == "LOGFILE":
        from supertimeline.parsers.logfile import parse_logfile
        return parse_logfile(job.path)

    if job.artifact_type == "AMCACHE":
        from supertimeline.parsers.amcache import parse_amcache
        return parse_amcache(job.path)

    log.debug("No parser for artifact type %s — skipping", job.artifact_type)
    return []


# Maps flat extracted name → evidence-relative logical path
_LOGICAL_PATH_MAP: Dict[str, str] = {
    "MFT":         "$MFT",
    "LogFile":     "$LogFile",
    "UsnJrnl_J":   "$Extend\\$UsnJrnl:$J",
    "UsnJrnl_Max": "$Extend\\$UsnJrnl:$Max",
    "SYSTEM":      "Windows\\System32\\config\\SYSTEM",
    "SOFTWARE":    "Windows\\System32\\config\\SOFTWARE",
    "SAM":         "Windows\\System32\\config\\SAM",
    "SECURITY":    "Windows\\System32\\config\\SECURITY",
    "SRUDB.dat":   "Windows\\System32\\sru\\SRUDB.dat",
    "Amcache.hve": "Windows\\AppCompat\\Programs\\Amcache.hve",
    "Recent":      "Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Recent",
}


# ── Extracted-dir discovery ───────────────────────────────────────────────────

def _discover_from_extracted(root: str) -> List[ArtifactJob]:
    """
    Build artifact jobs from a flat extracted temp directory.

    The temp dir contains files/dirs with sanitized names (MFT, evtx/, Prefetch/, etc.)
    as defined by EXTRACTED_ARTIFACT_MAP in image.py.  For EVTX directories the
    individual *.evtx files are expanded so each gets its own job.
    """
    from supertimeline.image import EXTRACTED_ARTIFACT_MAP

    jobs: List[ArtifactJob] = []
    root_path = Path(root)

    for flat_name, (artifact_type, is_directory) in EXTRACTED_ARTIFACT_MAP.items():
        candidate = root_path / flat_name
        if not candidate.exists():
            continue

        if is_directory and candidate.is_dir():
            if artifact_type == "EVTX":
                # Expand to individual .evtx files; each gets its own logical path
                for evtx_file in candidate.glob("*.evtx"):
                    try:
                        size = evtx_file.stat().st_size
                    except OSError:
                        size = 0
                    jobs.append(ArtifactJob(
                        artifact_type="EVTX",
                        path=str(evtx_file),
                        size_bytes=size,
                        is_directory=False,
                        logical_path=f"Windows\\System32\\winevt\\Logs\\{evtx_file.name}",
                    ))
            else:
                try:
                    size = sum(f.stat().st_size for f in candidate.rglob("*") if f.is_file())
                except OSError:
                    size = 0
                jobs.append(ArtifactJob(
                    artifact_type=artifact_type,
                    path=str(candidate),
                    size_bytes=size,
                    is_directory=True,
                    logical_path=(
                        "Windows\\Prefetch" if artifact_type == "PREFETCH"
                        else "Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Recent" if artifact_type == "LNK"
                        else flat_name
                    ),
                ))
        elif not is_directory and candidate.is_file():
            try:
                size = candidate.stat().st_size
            except OSError:
                size = 0
            jobs.append(ArtifactJob(
                artifact_type=artifact_type,
                path=str(candidate),
                size_bytes=size,
                is_directory=False,
                logical_path=_LOGICAL_PATH_MAP.get(flat_name, flat_name),
            ))

    jobs.sort(key=lambda j: j.size_bytes, reverse=True)
    log.info("Extracted temp dir: found %d artifact jobs in %s", len(jobs), root)
    return jobs


# ── Orchestrator ──────────────────────────────────────────────────────────────

class Orchestrator:
    """
    Discovers artifacts, dispatches all parsers in parallel, streams events.

    Image format handling:
      - If path is a directory or drive letter → use directly
      - If path is a forensic image (E01/raw/VMDK/VHD) → extract via pytsk3
        then treat extracted dir as root (temp dir cleaned up on close)
    """

    def __init__(self, root: str, max_workers: int = 0, output_format: str = "parquet",
                 progress_cb=None):
        self.original_path = root
        self.max_workers = max_workers or os.cpu_count() or 4
        self.output_format = output_format
        self._jobs: List[ArtifactJob] = []
        self._results: List[ParseResult] = []
        self._tmp_dir: Optional[str] = None
        self.root, self.image_format = self._resolve_root(root, progress_cb)

    def _resolve_root(self, path: str, progress_cb=None):
        from supertimeline.image import open_image, ImageFormat
        try:
            root, fmt, tmp = open_image(path, progress_cb=progress_cb)
            self._tmp_dir = tmp
            return root, fmt
        except RuntimeError as exc:
            raise

    def discover(self) -> List[ArtifactJob]:
        if self._tmp_dir is not None:
            self._jobs = _discover_from_extracted(self.root)
        else:
            self._jobs = discover_artifacts(self.root)
        return self._jobs

    def run(self, progress_callback: Callable = None) -> Iterator[ParseResult]:
        """
        Dispatch all jobs in parallel. Yields ParseResult as each finishes.
        Never raises — all errors are stored in ParseResult.error.
        """
        if not self._jobs:
            self.discover()

        # Rust parsers release the GIL — ThreadPoolExecutor gives true parallelism
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {pool.submit(_dispatch_job, job): job for job in self._jobs}

            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                except Exception as exc:
                    job = futures[future]
                    result = ParseResult(
                        artifact_type=job.artifact_type,
                        path=job.path,
                        event_count=0,
                        elapsed_secs=0.0,
                        error=f"Unhandled: {exc}",
                    )

                self._results.append(result)
                if progress_callback:
                    try:
                        progress_callback(result)
                    except Exception:
                        pass
                yield result

    def close(self):
        """Remove any temp directory created during image extraction."""
        if self._tmp_dir and os.path.exists(self._tmp_dir):
            shutil.rmtree(self._tmp_dir, ignore_errors=True)
            self._tmp_dir = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    @property
    def total_events(self) -> int:
        return sum(r.event_count for r in self._results)

    def summary(self) -> Dict[str, Any]:
        return {
            "image_format":        self.image_format.name,
            "artifacts_processed": len(self._results),
            "total_events":        self.total_events,
            "errors": [
                {"artifact": r.artifact_type, "path": r.path, "error": r.error}
                for r in self._results if r.error
            ],
            "per_artifact": [
                {
                    "type":         r.artifact_type,
                    "path":         r.path,
                    "events":       r.event_count,
                    "elapsed_secs": round(r.elapsed_secs, 3),
                    "events_per_sec": (
                        int(r.event_count / r.elapsed_secs)
                        if r.elapsed_secs > 0 else 0
                    ),
                    "error":        r.error,
                }
                for r in self._results
            ],
        }
