"""
SRUM (System Resource Usage Monitor) parser.
Reads SRUDB.dat via ESE database format for execution/network timeline events.
Pure Python — requires pyesedb or wraps esentutl output.
"""
from typing import List, Dict, Any

def parse(srum_path: str) -> List[Dict[str, Any]]:
    """
    Parse SRUDB.dat. Currently returns empty list if pyesedb is unavailable.
    Full implementation requires: pip install libyal-python or pyesedb.
    """
    events = []
    try:
        import pyesedb
        db = pyesedb.open(srum_path)
        # Tables: {D10CA2FE-6FCF-4F6D-848E-B2E99266FA89} = Application Timeline
        #         {973F5D5C-1D90-4944-BE8E-24B94231A174} = Network Usage
        for table in db.tables:
            if "D10CA2FE" in table.name or "973F5D5C" in table.name:
                for record in table.records:
                    events.extend(_parse_srum_record(record, srum_path, table.name))
    except ImportError:
        pass
    except Exception:
        pass
    return events


def _parse_srum_record(record, path: str, table_name: str) -> List[Dict[str, Any]]:
    from supertimeline.utils.timestamps import unix_ns_to_iso
    events = []
    try:
        ts_col = record.get_value_data_as_integer(1)  # TimeStamp column
        app_id = record.get_value_data_as_string(2)
        ns = ts_col * 1_000_000_000
        events.append({
            "timestamp_ns":    ns,
            "timestamp_iso":   unix_ns_to_iso(ns),
            "macb":            "M",
            "source":          "SRUM",
            "artifact":        "SRUM",
            "artifact_path":   path,
            "message":         f"SRUM execution: {app_id}",
            "is_fn_timestamp": False,
            "tz_offset_secs":  0,
        })
    except Exception:
        pass
    return events
