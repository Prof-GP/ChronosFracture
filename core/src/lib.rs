// Treat unused imports/variables as errors — prevents stale code silently entering production.
// dead_code is a warning only; constants for future parsers are intentionally retained.
#![deny(unused_imports, unused_variables)]
#![warn(dead_code, clippy::unwrap_used, clippy::panic)]

use pyo3::prelude::*;

pub mod parsers;
pub mod storage;
pub mod types;
pub mod utils;

use parsers::mft::MftParser;
use pyo3::types::PyBytes;
use parsers::usnjrnl::UsnJrnlParser;
use parsers::evtx::EvtxParser;
use parsers::prefetch::PrefetchParser;
use parsers::lnk::{parse_lnk_bytes, parse_lnk_dir};
use parsers::jumplists::parse_jumplist_bytes;

/// Expose the Rust LZXPRESS Huffman decompressor to Python.
/// Cross-platform — no Windows API, no external libraries.
#[pyfunction]
fn decompress_mam_py(py: Python<'_>, data: &[u8]) -> PyResult<Py<PyBytes>> {
    utils::lzxpress::decompress_mam(data)
        .map(|v| PyBytes::new_bound(py, &v).into())
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e))
}

#[pymodule]
fn supertimeline_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<MftParser>()?;
    m.add_class::<UsnJrnlParser>()?;
    m.add_class::<EvtxParser>()?;
    m.add_class::<PrefetchParser>()?;
    m.add_function(wrap_pyfunction!(parsers::mft::parse_mft_file, m)?)?;
    m.add_function(wrap_pyfunction!(parsers::usnjrnl::parse_usnjrnl_file, m)?)?;
    m.add_function(wrap_pyfunction!(parsers::evtx::parse_evtx_file, m)?)?;
    m.add_function(wrap_pyfunction!(parsers::prefetch::parse_prefetch_dir, m)?)?;
    m.add_function(wrap_pyfunction!(parsers::prefetch::parse_prefetch_bytes_decompressed, m)?)?;
    m.add_function(wrap_pyfunction!(parse_lnk_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(parse_lnk_dir, m)?)?;
    m.add_function(wrap_pyfunction!(parse_jumplist_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(decompress_mam_py, m)?)?;
    Ok(())
}
