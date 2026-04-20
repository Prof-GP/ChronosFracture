"""
SRUM parser — unit tests using mock pyesedb objects.

Tests the parser logic end-to-end without requiring a real SRUDB.dat or
a live ESE database handle.  Mock objects implement the minimal pyesedb
column/record API that the parser relies on.
"""

from __future__ import annotations
import sys
import types
import struct
import pytest

FILETIME_EPOCH_DIFF = 116_444_736_000_000_000
# 2024-06-15 12:00:00 UTC expressed as OLE Automation Date (days since 1899-12-30)
# unix_secs = 1_718_445_600  →  ole_days = (unix_secs / 86400) + 25569
_OLE_2024 = (1_718_445_600 / 86400.0) + 25569.0


# ── Minimal pyesedb mock ──────────────────────────────────────────────────────

class MockColumn:
    def __init__(self, name: str, col_type: int = 4):
        self.name = name
        self.type = col_type


class MockRecord:
    def __init__(self, int_values: dict, str_values: dict, blob_values: dict):
        self._int = int_values    # {col_index: int}
        self._str = str_values    # {col_index: str}
        self._blob = blob_values  # {col_index: bytes}

    def get_value_data_as_integer(self, idx):
        if idx in self._int:
            return self._int[idx]
        raise Exception(f"no int at {idx}")

    def get_value_data(self, idx):
        if idx in self._blob:
            return self._blob[idx]
        if idx in self._str:
            return self._str[idx].encode("utf-16-le") + b"\x00\x00"
        return None


class MockTable:
    def __init__(self, name: str, columns: list[str], records: list[MockRecord],
                 col_types: dict[int, int] | None = None):
        self.name = name
        col_types = col_types or {}
        self._columns = [MockColumn(c, col_types.get(i, 4)) for i, c in enumerate(columns)]
        self._records = records

    def get_number_of_columns(self):
        return len(self._columns)

    def get_column(self, i):
        return self._columns[i]

    def get_number_of_records(self):
        return len(self._records)

    def get_record(self, i):
        return self._records[i]


class MockDb:
    def __init__(self, tables: list[MockTable]):
        self._tables = tables

    def get_number_of_tables(self):
        return len(self._tables)

    def get_table(self, i):
        return self._tables[i]

    def get_table_by_name(self, name):
        for t in self._tables:
            if t.name == name:
                return t
        raise Exception("not found")


def _make_pyesedb_mock(db: MockDb):
    """Inject a fake pyesedb module that returns db on open()."""
    mod = types.ModuleType("pyesedb")
    mod.open = lambda path: db
    sys.modules["pyesedb"] = mod
    return mod


# ── Helpers ───────────────────────────────────────────────────────────────────

def _id_map_table(entries: dict[int, str]) -> MockTable:
    """Build a SruDbIdMapTable mock from {id: name} dict."""
    # Columns: IdIndex=0, IdType=1, IdBlob=2
    columns = ["IdIndex", "IdType", "IdBlob"]
    records = []
    for id_val, name in entries.items():
        records.append(MockRecord(
            int_values={0: id_val, 1: 0},
            str_values={},
            blob_values={2: name.encode("utf-16-le") + b"\x00\x00"},
        ))
    return MockTable("SruDbIdMapTable", columns, records)


def _ole_bytes(ole_days: float) -> bytes:
    """Encode an OLE Automation Date as 8-byte little-endian double."""
    return struct.pack("<d", ole_days)


def _app_timeline_table(rows: list[dict]) -> MockTable:
    """
    rows: list of {ts (OLE float), app_id, user_id, fg_cycles, bg_cycles}
    Columns match the lowercase names the parser looks for.
    TimeStamp is col[1], type 8 (OLE Automation Date).
    """
    cols = ["AutoIncId", "TimeStamp", "AppId", "UserId",
            "ForegroundCycleTime", "BackgroundCycleTime",
            "ForegroundContextSwitches", "BackgroundContextSwitches",
            "ForegroundBytesRead", "BackgroundBytesRead",
            "ForegroundBytesWritten", "BackgroundBytesWritten"]
    records = []
    for row in rows:
        ts_val = row["ts"]
        ts_bytes = _ole_bytes(ts_val) if isinstance(ts_val, float) else None
        records.append(MockRecord(
            int_values={
                2: row.get("app_id", 1),
                3: row.get("user_id", 2),
                4: row.get("fg_cycles", 0),
                5: row.get("bg_cycles", 0),
                6: 0, 7: 0, 8: 0, 9: 0, 10: 0, 11: 0,
            },
            str_values={},
            blob_values={1: ts_bytes} if ts_bytes is not None else {},
        ))
    return MockTable(
        "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}",
        cols, records,
        col_types={1: 8},  # TimeStamp = OLE Automation Date
    )


def _network_table(rows: list[dict]) -> MockTable:
    cols = ["AutoIncId", "TimeStamp", "AppId", "UserId",
            "InterfaceLuid", "BytesSent", "BytesRecvd"]
    records = []
    for row in rows:
        ts_val = row["ts"]
        ts_bytes = _ole_bytes(ts_val) if isinstance(ts_val, float) else None
        records.append(MockRecord(
            int_values={
                2: row.get("app_id", 1),
                3: row.get("user_id", 2),
                4: 0,
                5: row.get("sent", 0),
                6: row.get("recv", 0),
            },
            str_values={},
            blob_values={1: ts_bytes} if ts_bytes is not None else {},
        ))
    return MockTable(
        "{973F5D5C-1D90-4944-BE8E-24B94231A174}",
        cols, records,
        col_types={1: 8},
    )


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestIdMap:
    def test_builds_id_map(self):
        from supertimeline.parsers.srum import _build_id_map
        db = MockDb([_id_map_table({1: r"C:\Windows\System32\svchost.exe", 2: "S-1-5-21-1234"})])
        _make_pyesedb_mock(db)
        id_map = _build_id_map(db)
        assert id_map[1] == r"C:\Windows\System32\svchost.exe"
        assert id_map[2] == "S-1-5-21-1234"

    def test_empty_table(self):
        from supertimeline.parsers.srum import _build_id_map
        db = MockDb([_id_map_table({})])
        id_map = _build_id_map(db)
        assert id_map == {}


class TestAppTimeline:
    def setup_method(self):
        db = MockDb([
            _id_map_table({1: r"C:\Windows\explorer.exe", 2: "S-1-5-21-9999"}),
            _app_timeline_table([
                {"ts": _OLE_2024, "app_id": 1, "user_id": 2, "fg_cycles": 1_000_000, "bg_cycles": 500_000},
            ]),
        ])
        _make_pyesedb_mock(db)
        from supertimeline.parsers.srum import parse
        self.events = parse("fake/SRUDB.dat")

    def test_event_count(self):
        assert len(self.events) == 1

    def test_source_and_artifact(self):
        ev = self.events[0]
        assert ev["source"] == "SRUM"
        assert ev["artifact"] == "SRUM AppTimeline"

    def test_app_name_resolved(self):
        assert "explorer.exe" in self.events[0]["message"]

    def test_user_resolved(self):
        assert "S-1-5-21-9999" in self.events[0]["message"]

    def test_cpu_cycles_in_message(self):
        msg = self.events[0]["message"]
        assert "fg_cycles" in msg
        assert "bg_cycles" in msg

    def test_timestamp_is_valid_iso(self):
        iso = self.events[0]["timestamp_iso"]
        assert iso.startswith("2024-06-1")
        assert iso.endswith("Z")

    def test_timestamp_ns_positive(self):
        assert self.events[0]["timestamp_ns"] > 0

    def test_zero_timestamp_skipped(self):
        db = MockDb([
            _id_map_table({}),
            _app_timeline_table([{"ts": 0.0, "app_id": 1}]),
        ])
        _make_pyesedb_mock(db)
        from supertimeline.parsers import srum as srum_mod
        # Re-import to pick up mock
        events = srum_mod.parse("fake/SRUDB.dat")
        assert events == []


class TestNetworkUsage:
    def setup_method(self):
        db = MockDb([
            _id_map_table({1: r"C:\Program Files\Chrome\chrome.exe", 2: "S-1-5-21-8888"}),
            _network_table([
                {"ts": _OLE_2024, "app_id": 1, "user_id": 2, "sent": 4096, "recv": 131072},
            ]),
        ])
        _make_pyesedb_mock(db)
        from supertimeline.parsers.srum import parse
        self.events = parse("fake/SRUDB.dat")

    def test_event_count(self):
        assert len(self.events) == 1

    def test_artifact_label(self):
        assert self.events[0]["artifact"] == "SRUM Network"

    def test_app_name_in_message(self):
        assert "chrome.exe" in self.events[0]["message"]

    def test_bytes_in_message(self):
        msg = self.events[0]["message"]
        assert "sent=" in msg
        assert "recv=" in msg

    def test_byte_values(self):
        msg = self.events[0]["message"]
        assert "4,096B" in msg
        assert "131,072B" in msg


class TestBothTables:
    def test_events_from_both_tables(self):
        db = MockDb([
            _id_map_table({1: "app.exe", 2: "SID"}),
            _app_timeline_table([{"ts": _OLE_2024, "app_id": 1, "user_id": 2}]),
            _network_table([{"ts": _OLE_2024, "app_id": 1, "user_id": 2}]),
        ])
        _make_pyesedb_mock(db)
        from supertimeline.parsers.srum import parse
        events = parse("fake/SRUDB.dat")
        assert len(events) == 2
        artifacts = {e["artifact"] for e in events}
        assert artifacts == {"SRUM AppTimeline", "SRUM Network"}


class TestMissingPyesedb:
    def test_returns_empty_without_pyesedb(self):
        # Remove the mock so import fails
        sys.modules.pop("pyesedb", None)
        # Also make import raise
        sys.modules["pyesedb"] = None  # causes ImportError on `import pyesedb`
        try:
            from supertimeline.parsers import srum as srum_mod
            import importlib
            importlib.reload(srum_mod)
            result = srum_mod.parse("nonexistent.dat")
            assert result == []
        finally:
            sys.modules.pop("pyesedb", None)
