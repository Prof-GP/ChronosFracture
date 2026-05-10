"""
Volume Shadow Copy (VSS) delta analysis.

Enumerates VSS shadow copies accessible via \\\\.\\HarddiskVolumeShadowCopy{N}
on Windows, parses their $MFT and registry hives, and emits events for
artifacts present in a shadow copy but absent from the current filesystem
(deleted/wiped evidence).

Requires: pytsk3, Windows OS, elevated privileges for full VSS access.
"""
from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

log = logging.getLogger(__name__)

# ── WMI helpers ───────────────────────────────────────────────────────────────

def _parse_wmi_datetime(wmi_dt: str) -> int:
    """Convert WMI datetime (yyyymmddHHMMSS.ffffff±UUU) to Unix nanoseconds."""
    if not wmi_dt or len(wmi_dt) < 14:
        return 0
    try:
        from datetime import datetime, timezone, timedelta
        m = re.match(r'(\d{14})\.(\d{6})([+-])(\d{3})', wmi_dt)
        if not m:
            return 0
        dt_str, frac_str, sign, tz_min_str = m.groups()
        dt = datetime.strptime(dt_str, '%Y%m%d%H%M%S')
        offset = timedelta(minutes=int(tz_min_str) * (1 if sign == '+' else -1))
        dt = dt.replace(tzinfo=timezone(offset))
        frac_ns = int(frac_str) * 1000  # microseconds → nanoseconds
        return int(dt.timestamp()) * 1_000_000_000 + frac_ns
    except Exception:
        return 0


def _get_vss_creation_times() -> Dict[int, int]:
    """Query WMI for VSS creation timestamps. Returns {shadow_copy_index: unix_ns}."""
    try:
        result = subprocess.run(
            ['powershell', '-NonInteractive', '-Command',
             'Get-WmiObject Win32_ShadowCopy | '
             'Select-Object DeviceObject,InstallDate | '
             'ConvertTo-Json -Depth 1 -Compress'],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return {}

        import json
        data = json.loads(result.stdout)
        if isinstance(data, dict):
            data = [data]

        times: Dict[int, int] = {}
        for item in data:
            dev          = (item.get('DeviceObject') or '')
            install_date = (item.get('InstallDate')  or '')
            m = re.search(r'HarddiskVolumeShadowCopy(\d+)', dev, re.IGNORECASE)
            if not m:
                continue
            times[int(m.group(1))] = _parse_wmi_datetime(install_date)
        return times
    except Exception as exc:
        log.debug("VSS WMI query failed: %s", exc)
        return {}


# ── Enumeration ───────────────────────────────────────────────────────────────

def enumerate_shadow_copies() -> List[Tuple[int, str, int]]:
    """
    Enumerate accessible VSS shadow copies on Windows.

    Returns list of (index, device_path, creation_time_ns).
    Probes \\\\.\\HarddiskVolumeShadowCopy{1..63} via pytsk3.
    Stops after 5 consecutive misses to avoid scanning the full range.
    """
    import sys
    if sys.platform != 'win32':
        return []
    try:
        import pytsk3
    except ImportError:
        log.warning("VSS enumeration requires pytsk3 — skipping")
        return []

    creation_times = _get_vss_creation_times()
    results: List[Tuple[int, str, int]] = []
    misses = 0

    for i in range(1, 64):
        vss_path = f"\\\\.\\HarddiskVolumeShadowCopy{i}"
        try:
            img = pytsk3.Img_Info(vss_path)
            pytsk3.FS_Info(img)
            results.append((i, vss_path, creation_times.get(i, 0)))
            misses = 0
            log.debug("VSS: found shadow copy #%d", i)
        except Exception:
            misses += 1
            if misses >= 5:
                break

    log.info("VSS: found %d shadow copies", len(results))
    return results


# ── Artifact extraction from a shadow copy ────────────────────────────────────

def _extract_vss_artifacts(vss_path: str) -> Tuple[str, bool]:
    """
    Extract $MFT and registry hives from a VSS shadow copy into a temp dir.

    Output structure:
        <tmp_dir>/MFT
        <tmp_dir>/SYSTEM
        <tmp_dir>/SOFTWARE
        <tmp_dir>/SAM
        <tmp_dir>/userhives/<username>/NTUSER.DAT

    Returns (tmp_dir, success). Caller must delete tmp_dir when done.
    """
    from supertimeline.image import _tsk_extract_file, _tsk_extract_user_hives
    try:
        import pytsk3
    except ImportError:
        return '', False

    tmp_dir = tempfile.mkdtemp(prefix='st_vss_')
    try:
        img = pytsk3.Img_Info(vss_path)
        fs  = pytsk3.FS_Info(img)

        _tsk_extract_file(fs, '$MFT', os.path.join(tmp_dir, 'MFT'))

        for src, dest in [
            ('Windows/System32/config/SYSTEM',   'SYSTEM'),
            ('Windows/System32/config/SOFTWARE', 'SOFTWARE'),
            ('Windows/System32/config/SAM',      'SAM'),
        ]:
            _tsk_extract_file(fs, src, os.path.join(tmp_dir, dest))

        _tsk_extract_user_hives(fs, tmp_dir)
        return tmp_dir, True

    except Exception as exc:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        log.debug("VSS extract failed (%s): %s", vss_path, exc)
        return '', False


# ── Delta helpers ─────────────────────────────────────────────────────────────

def _reg_key_identity(ev: Dict[str, Any]) -> str:
    """
    Extract a canonical registry key path from a registry event for comparison.

    Plugin events:  'Persistence: AutoRun | val=data | HKLM\\...\\Run'  → last HK* segment
    Generic events: 'HKLM\\SYSTEM\\ControlSet001\\...'                  → full message
    """
    msg = ev.get('message', '')
    for part in reversed(msg.split(' | ')):
        part = part.strip()
        if part.startswith(('HKLM', 'HKCU', 'HKU', 'HKCR', 'HKCC')):
            return part
    return msg


def build_current_sets(
    current_mft_paths: Set[str],
    current_reg_keys: Set[str],
    events: List[Dict[str, Any]],
) -> None:
    """
    Populate mft/registry lookup sets from a batch of already-parsed events.
    Called incrementally during the streaming parse so we avoid re-reading parquet.
    """
    for ev in events:
        src = ev.get('source', '')
        if src == 'MFT':
            fp = ev.get('file_path', '')
            if fp:
                current_mft_paths.add(fp)
        elif src == 'REGISTRY':
            key_id = _reg_key_identity(ev)
            if key_id:
                current_reg_keys.add(key_id)


# ── Per-snapshot delta computation ────────────────────────────────────────────

_SKIP_PATH_PREFIXES = (
    '\\system volume information',
    '\\$',
)


def _compute_snapshot_delta(
    vss_idx: int,
    vss_path: str,
    current_mft_paths: Set[str],
    current_reg_keys: Set[str],
) -> List[Dict[str, Any]]:
    """
    Parse one VSS snapshot, diff against current, return only delta events.
    Events are tagged source=SHADOWCOPY with the VSS index in the message.
    """
    try:
        import supertimeline_core as _core
    except ImportError:
        log.warning("VSS delta requires supertimeline_core — skipping snapshot #%d", vss_idx)
        return []

    from supertimeline.parsers.registry import parse as parse_registry

    delta: List[Dict[str, Any]] = []
    tmp_dir, ok = _extract_vss_artifacts(vss_path)
    if not ok:
        log.warning("VSS#%d: artifact extraction failed, skipping", vss_idx)
        return delta

    try:
        # ── $MFT delta: files in this snapshot absent from current ────────────
        mft_path = os.path.join(tmp_dir, 'MFT')
        if os.path.isfile(mft_path):
            for ev in _core.parse_mft_file(mft_path):
                fp = ev.get('file_path', '')
                if not fp or fp in current_mft_paths:
                    continue
                fp_lower = fp.lower()
                if any(fp_lower.startswith(p) for p in _SKIP_PATH_PREFIXES):
                    continue
                ev['source']        = 'SHADOWCOPY'
                ev['artifact']      = 'Deleted File (VSS)'
                ev['message']       = f"[VSS#{vss_idx}] Deleted: {fp}"
                ev['message_short'] = f"Deleted: {Path(fp).name}"
                delta.append(ev)

        # ── Registry delta: keys in this snapshot absent from current ─────────
        hives: List[Tuple[str, str]] = [
            (os.path.join(tmp_dir, 'SYSTEM'),   'SYSTEM'),
            (os.path.join(tmp_dir, 'SOFTWARE'), 'SOFTWARE'),
            (os.path.join(tmp_dir, 'SAM'),      'SAM'),
        ]
        userhives_root = Path(tmp_dir) / 'userhives'
        if userhives_root.is_dir():
            for user_dir in userhives_root.iterdir():
                if not user_dir.is_dir():
                    continue
                nt = user_dir / 'NTUSER.DAT'
                if nt.is_file():
                    hives.append((str(nt), f'NTUSER.DAT ({user_dir.name})'))

        for hive_path, hive_label in hives:
            if not os.path.isfile(hive_path):
                continue
            try:
                for ev in parse_registry(hive_path):
                    key_id = _reg_key_identity(ev)
                    if not key_id or key_id in current_reg_keys:
                        continue
                    orig_msg = ev.get('message', key_id)
                    ev['source']        = 'SHADOWCOPY'
                    ev['artifact']      = 'Deleted Registry Key (VSS)'
                    ev['message']       = f"[VSS#{vss_idx}] Deleted key: {orig_msg}"
                    ev['message_short'] = f"Deleted key: {key_id.split(chr(92))[-1]}"
                    delta.append(ev)
            except Exception as exc:
                log.debug("VSS registry parse error (%s / %s): %s",
                          vss_path, hive_label, exc)

    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    log.info("VSS#%d: %d delta events", vss_idx, len(delta))
    return delta


# ── Public entry point ────────────────────────────────────────────────────────

def compute_vss_delta(
    shadow_copies: List[Tuple[int, str, int]],
    current_mft_paths: Set[str],
    current_reg_keys: Set[str],
    progress_cb=None,
) -> List[Dict[str, Any]]:
    """
    Compute VSS delta for a pre-enumerated list of shadow copies.

    shadow_copies: output of enumerate_shadow_copies()
    current_mft_paths / current_reg_keys: built incrementally during main parse
    progress_cb: optional callable(idx, total, vss_path) for UI updates

    Returns list of delta events (present in VSS, absent in current filesystem).
    """
    delta: List[Dict[str, Any]] = []
    for i, (idx, vss_path, _creation_ns) in enumerate(shadow_copies, 1):
        if progress_cb:
            progress_cb(i, len(shadow_copies), vss_path)
        delta.extend(
            _compute_snapshot_delta(idx, vss_path, current_mft_paths, current_reg_keys)
        )
    return delta
