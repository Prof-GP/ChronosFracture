"""
Streaming event writer — supports Parquet, JSONL, and CSV output.
Events are written as they arrive; no full in-memory accumulation required.
"""
import json
import csv
import sys
import io
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
    "artifact_path",
    "file_path",
    "message",
    "is_fn_timestamp",
    "tz_offset_secs",
]


class StreamingWriter:
    """
    Writes timeline events to disk as they arrive from parsers.
    Supports Parquet (columnar, fast sort), JSONL, and CSV.
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
                pa.field("artifact_path",   pa.string()),
                pa.field("file_path",       pa.string()),
                pa.field("message",         pa.string()),
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

        if self.format == "parquet":
            self._flush_parquet()
        elif self.format == "jsonl":
            self._flush_jsonl()
        elif self.format == "csv":
            self._flush_csv()

        self._total_written += len(self._buffer)
        self._buffer = []

    def _flush_parquet(self):
        cols = {field: [] for field in SCHEMA_FIELDS}
        for ev in self._buffer:
            for f in SCHEMA_FIELDS:
                cols[f].append(ev.get(f))

        # Clamp timestamps to int64 range to guard against parser bugs producing garbage FILETIMEs
        _INT64_MAX = 9_223_372_036_854_775_807
        ts_clamped = [
            t if (t is not None and 0 <= t <= _INT64_MAX) else 0
            for t in cols["timestamp_ns"]
        ]

        arrays = [
            pa.array(ts_clamped,              type=pa.int64()),
            pa.array(cols["timestamp_iso"],   type=pa.string()),
            pa.array(cols["macb"],            type=pa.string()),
            pa.array(cols["source"],          type=pa.string()),
            pa.array(cols["artifact"],        type=pa.string()),
            pa.array(cols["artifact_path"],   type=pa.string()),
            pa.array(cols["file_path"],       type=pa.string()),
            pa.array(cols["message"],         type=pa.string()),
            pa.array(cols["is_fn_timestamp"], type=pa.bool_()),
            pa.array(cols["tz_offset_secs"],  type=pa.int32()),
        ]
        batch = pa.record_batch(arrays, schema=self._schema)
        self._writer.write_batch(batch)

    def _flush_jsonl(self):
        for ev in self._buffer:
            self._file.write(json.dumps(ev, default=str) + "\n")

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


def merge_and_sort_parquet(input_paths: list, output_path: str) -> int:
    """Merge multiple Parquet files and sort by timestamp_ns."""
    if not ARROW_AVAILABLE:
        raise RuntimeError("pyarrow required")
    import pyarrow as pa
    tables = [pq.read_table(p) for p in input_paths if Path(p).exists()]
    merged = pa.concat_tables(tables)
    sorted_table = merged.sort_by([("timestamp_ns", "ascending")])
    pq.write_table(sorted_table, output_path, compression="snappy")
    return len(sorted_table)


def sort_parquet_by_timestamp(input_path: str, output_path: str):
    """
    Sort an existing Parquet file by timestamp_ns using Arrow.
    Arrow columnar sort is extremely fast — 100M rows sorts in ~30 seconds.
    """
    if not ARROW_AVAILABLE:
        raise RuntimeError("pyarrow required")

    table = pq.read_table(input_path)
    sorted_table = table.sort_by([("timestamp_ns", "ascending")])
    pq.write_table(sorted_table, output_path, compression="snappy")
    return len(sorted_table)
