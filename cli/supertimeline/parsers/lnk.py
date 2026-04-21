"""
LNK / Jump List parser — glue layer over Rust core.

Walks a Recent/ directory tree and dispatches to the appropriate Rust parser:
  • *.lnk                      → parse_lnk_bytes()
  • *.automaticDestinations-ms → parse_jumplist_bytes()  (OLE/CFB compound doc)
  • *.customDestinations-ms    → parse_jumplist_bytes()  (flat LNK concatenation)

Handles per-user subdirectory structure produced by the image extractor:
  recent_root/<username>/*.lnk
  recent_root/<username>/AutomaticDestinations/*.automaticDestinations-ms
  recent_root/<username>/CustomDestinations/*.customDestinations-ms
"""
import logging
from pathlib import Path
from typing import List, Dict, Any

log = logging.getLogger(__name__)

try:
    import supertimeline_core as _core
    _RUST = True
except ImportError:
    _RUST = False
    _core = None

_JUMP_SUFFIXES = (".automaticDestinations-ms", ".customDestinations-ms")


def parse_dir(recent_root: str) -> List[Dict[str, Any]]:
    """
    Walk recent_root recursively and parse all LNK and Jump List files.
    Returns a flat list of timeline event dicts.
    """
    if not _RUST:
        log.debug("Rust core unavailable — LNK/JumpList parser disabled")
        return []

    root = Path(recent_root)
    if not root.exists():
        log.debug("LNK root not found: %s", recent_root)
        return []

    events: List[Dict[str, Any]] = []

    for path in root.rglob("*"):
        if not path.is_file():
            continue
        name = path.name.lower()
        try:
            data = path.read_bytes()
            if name.endswith(".lnk"):
                events.extend(_core.parse_lnk_bytes(data, str(path)))
            elif any(name.endswith(s.lower()) for s in _JUMP_SUFFIXES):
                events.extend(_core.parse_jumplist_bytes(data, str(path)))
        except Exception as exc:
            log.debug("Skipping %s: %s", path.name, exc)

    log.debug("LNK/JumpList: %d events from %s", len(events), recent_root)
    return events
