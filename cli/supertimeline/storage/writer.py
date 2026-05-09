"""
Streaming event writer — supports Parquet, JSONL, CSV, SQLite, and Timesketch output.
Events are written as they arrive; no full in-memory accumulation required.
Post-processing (sort, hostname fill, message_short) is done via separate functions
that operate on the Parquet intermediate file.
"""
import json
import csv
import os
from pathlib import Path
from typing import Dict, Any, List

try:
    import pyarrow as pa
    import pyarrow.parquet as pq
    ARROW_AVAILABLE = True
except ImportError:
    ARROW_AVAILABLE = False


SCHEMA_FIELDS = [
    "timestamp_ns",
    "timestamp_iso",
    "macb",
    "source",
    "artifact",
    "hostname",
    "file_path",
    "message",
    "message_short",
    "is_fn_timestamp",
    "tz_offset_secs",
]

_INT64_MAX = 9_223_372_036_854_775_807


def _enrich(ev: Dict[str, Any]) -> None:
    """Fill derived fields that parsers may not set."""
    ev.setdefault("hostname", "")
    if "message_short" not in ev:
        msg = ev.get("message") or ""
        ev["message_short"] = msg[:80]


class StreamingWriter:
    """
    Writes timeline events to disk as they arrive from parsers.
    Supports Parquet (columnar, fast sort), JSONL, and CSV.
    For sorted output of non-Parquet formats, write Parquet first
    then call the convert_* / write_*_from_parquet functions below.
    """

    def __init__(self, output_path: str, format: str = "parquet", batch_size: int = 100_000):
        self.output_path = output_path
        self.format = format.lower()
        self.batch_size = batch_size
        self._buffer: List[Dict[str, Any]] = []
        self._total_written = 0
        self._writer = None
        self._file = None
        self._csv_writer = None
        self._open()

    def _open(self):
        if self.format == "parquet":
            if not ARROW_AVAILABLE:
                raise RuntimeError("pyarrow is required for Parquet output. Run: pip install pyarrow")
            self._schema = pa.schema([
                pa.field("timestamp_ns",    pa.int64()),
                pa.field("timestamp_iso",   pa.string()),
                pa.field("macb",            pa.string()),
                pa.field("source",          pa.string()),
                pa.field("artifact",        pa.string()),
                pa.field("hostname",        pa.string()),
                pa.field("file_path",       pa.string()),
                pa.field("message",         pa.string()),
                pa.field("message_short",   pa.string()),
                pa.field("is_fn_timestamp", pa.bool_()),
                pa.field("tz_offset_secs",  pa.int32()),
            ])
            self._file = open(self.output_path, "wb")
            self._writer = pq.ParquetWriter(
                self._file,
                self._schema,
                compression="snappy",
            )

        elif self.format == "jsonl":
            self._file = open(self.output_path, "w", encoding="utf-8", buffering=1)

        elif self.format == "csv":
            self._file = open(self.output_path, "w", newline="", encoding="utf-8")
            self._csv_writer = csv.DictWriter(
                self._file,
                fieldnames=SCHEMA_FIELDS,
                extrasaction="ignore",
            )
            self._csv_writer.writeheader()

        else:
            raise ValueError(f"Unsupported output format: {self.format}")

    def write_event(self, event: Dict[str, Any]):
        self._buffer.append(event)
        if len(self._buffer) >= self.batch_size:
            self._flush()

    def write_events(self, events: List[Dict[str, Any]]):
        for ev in events:
            self.write_event(ev)

    def _flush(self):
        if not self._buffer:
            return

        for ev in self._buffer:
            _enrich(ev)

        if self.format == "parquet":
            self._flush_parquet()
        elif self.format == "jsonl":
            self._flush_jsonl()
        elif self.format == "csv":
            self._flush_csv()

        self._total_written += len(self._buffer)
        self._buffer = []

    def _flush_parquet(self):
        cols = {f: [] for f in SCHEMA_FIELDS}
        for ev in self._buffer:
            for f in SCHEMA_FIELDS:
                cols[f].append(ev.get(f))

        ts_clamped = [
            t if (t is not None and 0 <= t <= _INT64_MAX) else 0
            for t in cols["timestamp_ns"]
        ]

        arrays = [
            pa.array(ts_clamped,                    type=pa.int64()),
            pa.array(cols["timestamp_iso"],          type=pa.string()),
            pa.array(cols["macb"],                   type=pa.string()),
            pa.array(cols["source"],                 type=pa.string()),
            pa.array(cols["artifact"],               type=pa.string()),
            pa.array(cols["hostname"],               type=pa.string()),
            pa.array(cols["file_path"],              type=pa.string()),
            pa.array(cols["message"],                type=pa.string()),
            pa.array(cols["message_short"],          type=pa.string()),
            pa.array(cols["is_fn_timestamp"],        type=pa.bool_()),
            pa.array(cols["tz_offset_secs"],         type=pa.int32()),
        ]
        batch = pa.record_batch(arrays, schema=self._schema)
        self._writer.write_batch(batch)

    def _flush_jsonl(self):
        for ev in self._buffer:
            self._file.write(
                json.dumps({f: ev.get(f) for f in SCHEMA_FIELDS}, default=str) + "\n"
            )

    def _flush_csv(self):
        self._csv_writer.writerows(self._buffer)

    def close(self) -> int:
        self._flush()
        if self.format == "parquet" and self._writer:
            self._writer.close()
        if self._file:
            self._file.close()
        return self._total_written

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


# ── Post-processing ───────────────────────────────────────────────────────────

def post_process_parquet(
    input_path: str,
    output_path: str,
    hostname: str = "",
    sort: bool = True,
) -> int:
    """
    Sort by timestamp_ns and fill empty hostname fields.
    Returns final event count.
    """
    if not ARROW_AVAILABLE:
        raise RuntimeError("pyarrow required for post-processing")

    table = pq.read_table(input_path)

    if hostname and "hostname" in table.schema.names:
        hn = table.column("hostname").to_pylist()
        filled = [h if (h and h.strip()) else hostname for h in hn]
        idx = table.schema.get_field_index("hostname")
        table = table.set_column(idx, "hostname", pa.array(filled, type=pa.string()))

    if sort:
        table = table.sort_by([("timestamp_ns", "ascending")])

    pq.write_table(table, output_path, compression="snappy")
    return len(table)


# ── Conversion functions ──────────────────────────────────────────────────────

def convert_parquet_to_csv(parquet_path: str, csv_path: str) -> int:
    """Convert a (sorted) Parquet file to CSV."""
    if not ARROW_AVAILABLE:
        raise RuntimeError("pyarrow required")
    table = pq.read_table(parquet_path)
    present = [f for f in SCHEMA_FIELDS if f in table.schema.names]
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=SCHEMA_FIELDS, extrasaction="ignore")
        w.writeheader()
        for batch in table.to_batches(max_chunksize=200_000):
            cols = {c: batch.column(c).to_pylist() for c in present}
            for i in range(len(batch)):
                w.writerow({c: cols[c][i] for c in present})
    return len(table)


def convert_parquet_to_jsonl(parquet_path: str, jsonl_path: str) -> int:
    """Convert a (sorted) Parquet file to JSONL."""
    if not ARROW_AVAILABLE:
        raise RuntimeError("pyarrow required")
    table = pq.read_table(parquet_path)
    present = [f for f in SCHEMA_FIELDS if f in table.schema.names]
    with open(jsonl_path, "w", encoding="utf-8") as f:
        for batch in table.to_batches(max_chunksize=200_000):
            cols = {c: batch.column(c).to_pylist() for c in present}
            for i in range(len(batch)):
                f.write(json.dumps({c: cols[c][i] for c in present}, default=str) + "\n")
    return len(table)


def write_sqlite_from_parquet(parquet_path: str, sqlite_path: str) -> int:
    """Write sorted Parquet to a SQLite timeline database."""
    import sqlite3
    if not ARROW_AVAILABLE:
        raise RuntimeError("pyarrow required for SQLite output")

    table = pq.read_table(parquet_path)
    present = [f for f in SCHEMA_FIELDS if f in table.schema.names]

    if os.path.exists(sqlite_path):
        os.remove(sqlite_path)

    conn = sqlite3.connect(sqlite_path)
    conn.execute("""
        CREATE TABLE timeline (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp_ns    INTEGER,
            timestamp_iso   TEXT,
            macb            TEXT,
            source          TEXT,
            artifact        TEXT,
            hostname        TEXT,
            file_path       TEXT,
            message         TEXT,
            message_short   TEXT,
            is_fn_timestamp INTEGER,
            tz_offset_secs  INTEGER
        )
    """)

    total = 0
    for batch in table.to_batches(max_chunksize=50_000):
        cols = {c: batch.column(c).to_pylist() for c in present}
        rows = [tuple(cols[f][i] for f in present) for i in range(len(batch))]
        ph = ", ".join("?" * len(present))
        cn = ", ".join(present)
        conn.executemany(f"INSERT INTO timeline ({cn}) VALUES ({ph})", rows)
        total += len(batch)

    conn.execute("CREATE INDEX idx_ts       ON timeline(timestamp_ns)")
    conn.execute("CREATE INDEX idx_artifact ON timeline(artifact)")
    conn.commit()
    conn.close()
    return total


def write_timesketch_from_parquet(parquet_path: str, output_path: str) -> int:
    """
    Write a Timesketch-compatible CSV.
    Timesketch expects: datetime, timestamp_desc, source_short, source_long, message.
    """
    if not ARROW_AVAILABLE:
        raise RuntimeError("pyarrow required for Timesketch output")

    TS_COLS = [
        "datetime", "timestamp_desc", "source_short", "source_long",
        "message", "message_short", "hostname", "filename",
    ]

    table = pq.read_table(parquet_path)
    src_names = table.schema.names

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=TS_COLS, extrasaction="ignore")
        w.writeheader()
        for batch in table.to_batches(max_chunksize=200_000):
            n = len(batch)
            cols = {c: batch.column(c).to_pylist() for c in src_names}

            def _get(col_name, idx):
                col = cols.get(col_name)
                return (col[idx] or "") if col else ""

            for i in range(n):
                artifact = _get("artifact", i)
                macb     = _get("macb", i)
                w.writerow({
                    "datetime":       _get("timestamp_iso", i),
                    "timestamp_desc": _macb_desc(macb, artifact),
                    "source_short":   artifact[:6],
                    "source_long":    artifact,
                    "message":        _get("message", i),
                    "message_short":  _get("message_short", i),
                    "hostname":       _get("hostname", i),
                    "filename":       _get("file_path", i),
                })

    return len(table)


def _macb_desc(macb: str, artifact: str) -> str:
    mapping = {"M": "Last Written", "A": "Last Accessed", "C": "Last Changed (MFT)", "B": "Created"}
    desc = mapping.get(macb, "Timestamp")
    return f"{artifact} {desc}" if artifact else desc


# ── Legacy helpers (kept for USN recovery merge path) ────────────────────────

def merge_and_sort_parquet(input_paths: list, output_path: str) -> int:
    """Merge multiple Parquet files and sort by timestamp_ns."""
    if not ARROW_AVAILABLE:
        raise RuntimeError("pyarrow required")
    tables = [pq.read_table(p) for p in input_paths if Path(p).exists()]
    merged = pa.concat_tables(tables)
    sorted_table = merged.sort_by([("timestamp_ns", "ascending")])
    pq.write_table(sorted_table, output_path, compression="snappy")
    return len(sorted_table)


def sort_parquet_by_timestamp(input_path: str, output_path: str):
    """Sort an existing Parquet file by timestamp_ns using Arrow."""
    if not ARROW_AVAILABLE:
        raise RuntimeError("pyarrow required")
    table = pq.read_table(input_path)
    sorted_table = table.sort_by([("timestamp_ns", "ascending")])
    pq.write_table(sorted_table, output_path, compression="snappy")
    return len(sorted_table)
