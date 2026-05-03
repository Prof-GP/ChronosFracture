// Arrow/Parquet streaming writer — used by the Python orchestrator via PyO3
// Events are batched and written as they arrive; no full-load required.
use arrow::array::*;
use arrow::datatypes::{DataType, Field, Schema};
use arrow::record_batch::RecordBatch;
use parquet::arrow::ArrowWriter;
use parquet::file::properties::WriterProperties;
use std::fs::File;
use std::sync::Arc;

use crate::types::TimelineEvent;

pub fn schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("timestamp_ns",     DataType::Int64,   false),
        Field::new("timestamp_iso",    DataType::Utf8,    false),
        Field::new("macb",             DataType::Utf8,    false),
        Field::new("source",           DataType::Utf8,    false),
        Field::new("artifact",         DataType::Utf8,    false),
        Field::new("message",          DataType::Utf8,    false),
        Field::new("is_fn_timestamp",  DataType::Boolean, false),
        Field::new("tz_offset_secs",   DataType::Int32,   false),
    ]))
}

pub fn write_events_to_parquet(events: &[TimelineEvent], output_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let schema = schema();

    let mut timestamp_ns_builder  = Int64Builder::new();
    let mut timestamp_iso_builder = StringBuilder::new();
    let mut macb_builder          = StringBuilder::new();
    let mut source_builder        = StringBuilder::new();
    let mut artifact_builder      = StringBuilder::new();
    let mut message_builder       = StringBuilder::new();
    let mut is_fn_builder         = BooleanBuilder::new();
    let mut tz_offset_builder     = Int32Builder::new();

    for ev in events {
        timestamp_ns_builder.append_value(ev.timestamp_ns);
        timestamp_iso_builder.append_value(ev.timestamp_iso());
        macb_builder.append_value(&ev.macb);
        source_builder.append_value(&ev.source);
        artifact_builder.append_value(&ev.artifact);
        message_builder.append_value(&ev.message);
        is_fn_builder.append_value(ev.is_fn_timestamp);
        tz_offset_builder.append_value(ev.tz_offset_secs);
    }

    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(timestamp_ns_builder.finish()),
            Arc::new(timestamp_iso_builder.finish()),
            Arc::new(macb_builder.finish()),
            Arc::new(source_builder.finish()),
            Arc::new(artifact_builder.finish()),
            Arc::new(message_builder.finish()),
            Arc::new(is_fn_builder.finish()),
            Arc::new(tz_offset_builder.finish()),
        ],
    )?;

    let file = File::create(output_path)?;
    let props = WriterProperties::builder()
        .set_compression(parquet::basic::Compression::SNAPPY)
        .build();

    let mut writer = ArrowWriter::try_new(file, schema, Some(props))?;
    writer.write(&batch)?;
    writer.close()?;

    Ok(())
}
