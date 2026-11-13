// SPDX-License-Identifier: MIT
// Rust guideline compliant 2026-02-21

//! PyO3 bindings for the `UnsignedQuadStream` contract and Jelly codec.
//!
//! Exposes five functions to Python as `quad_fast._native` (same layout as
//! `office-parsers-rs/owl-fast-py`): [`build_quad_ipc`] builds one
//! `UnsignedQuadStream` v1 batch from plain quad tuples and returns Arrow
//! IPC stream bytes, [`read_quad_ipc`] decodes such bytes back into quad
//! tuples, [`jelly_encode`] / [`jelly_decode`] translate between IPC
//! bytes and non-delimited protobuf-encoded Jelly `RdfStreamFrame` messages,
//! and [`jsonld_to_quad_ipc`] decodes one inline-context JSON-LD document
//! into IPC bytes via `jsonld-fast-core`.
//!
//! The wire shapes are:
//!
//! - quad in: `(subject, predicate, object[, graph[, provenance]])`
//! - quad out: `(subject, predicate, object, graph, provenance)`
//! - `subject` / `graph`: `(kind, value)` with kind `"iri"` or `"bnode"`;
//!   `graph` is `None` for the default graph
//! - `object`: `(kind, value, datatype, language)` with kind `"iri"`,
//!   `"bnode"`, or `"literal"`
//! - `provenance`: dict with keys `source_artifact_iri`,
//!   `source_content_sha256`, `source_offset_start`, `source_offset_end`,
//!   `observed_at_micros`, or `None`
//!
//! Everything is fail-closed: resource-limit keyword arguments mirror the
//! Rust `QuadLimits` / Jelly table limits, exceeded budgets raise
//! `QuadResourceError`, and every other malformed input raises `ValueError`
//! with a stable machine-readable code as the first message token. Output
//! is unsigned by construction; this module never attaches or promotes
//! assurance.
//!
//! RDF 1.2 triple terms (RDF-star) have no place in this term shape — its
//! object kinds are `"iri"`, `"bnode"`, and `"literal"` only — so a batch
//! carrying one is refused by name (`unsupported: rdf12_triple_term`)
//! rather than flattened into a node reference, and this binding never
//! announces RDF-star on the Jelly wire.
//!
//! The conversion logic lives in [`convert`], which is pure Rust and unit
//! tested without a Python interpreter (see `src/tests.rs`).
//!
//! Every call runs its encoding and decoding with the GIL released
//! (`Python::detach`), so other Python threads keep running during a long
//! call; only the conversion to and from Python objects holds it. A Rust
//! panic inside a call is caught by PyO3 at the function boundary and raised
//! as `pyo3_runtime.PanicException`; the workspace never builds with
//! `panic = "abort"`, which would turn it into a process abort.

use jelly_fast_core::{JellyDecoderOptions, JellyEncoderOptions};
use jsonld_fast_core::JsonLdLimits;
use pyo3::exceptions::PyValueError;
use pyo3::intern;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};
use quad_fast_core::QuadLimits;

use crate::convert::{BindingError, ProvenanceSpec, QuadSpec, TermSpec};

mod convert;
#[cfg(test)]
mod tests;

pyo3::create_exception!(
    quad_fast,
    QuadResourceError,
    PyValueError,
    "Raised when a configured fail-closed resource limit is exceeded."
);

/// Subject or graph tuple on the Python side: `(kind, value)`.
type PyTermPair = (String, String);
/// Object tuple on the Python side: `(kind, value, datatype, language)`.
type PyObjectTerm = (String, String, Option<String>, Option<String>);
/// Decoded quad tuple: subject, predicate, object, graph, provenance.
type PyQuadOut = (
    PyTermPair,
    String,
    PyObjectTerm,
    Option<PyTermPair>,
    Option<Py<PyDict>>,
);

fn binding_err(error: BindingError) -> PyErr {
    if error.is_resource_limit() {
        QuadResourceError::new_err(error.to_string())
    } else {
        PyValueError::new_err(error.to_string())
    }
}

fn pair_term(pair: PyTermPair) -> TermSpec {
    TermSpec {
        kind: pair.0,
        value: pair.1,
        datatype: None,
        language: None,
    }
}

fn object_term(object: PyObjectTerm) -> TermSpec {
    TermSpec {
        kind: object.0,
        value: object.1,
        datatype: object.2,
        language: object.3,
    }
}

fn provenance_from_dict(dict: &Bound<'_, PyDict>) -> PyResult<ProvenanceSpec> {
    let mut spec = ProvenanceSpec::default();
    for (key, value) in dict.iter() {
        let key: String = key.extract().map_err(|_type_error| {
            PyValueError::new_err("provenance_key: provenance keys must be strings")
        })?;
        match key.as_str() {
            "source_artifact_iri" => spec.source_artifact_iri = value.extract()?,
            "source_content_sha256" => spec.source_content_sha256 = value.extract()?,
            "source_offset_start" => spec.source_offset_start = value.extract()?,
            "source_offset_end" => spec.source_offset_end = value.extract()?,
            "observed_at_micros" => spec.observed_at_micros = value.extract()?,
            other => {
                return Err(PyValueError::new_err(format!(
                    "provenance_key: unknown provenance key {other:?}"
                )));
            }
        }
    }
    Ok(spec)
}

fn quad_from_py(index: usize, item: &Bound<'_, PyAny>) -> PyResult<QuadSpec> {
    type Quad5<'py> = (
        PyTermPair,
        String,
        PyObjectTerm,
        Option<PyTermPair>,
        Option<Bound<'py, PyDict>>,
    );
    type Quad4 = (PyTermPair, String, PyObjectTerm, Option<PyTermPair>);
    type Quad3 = (PyTermPair, String, PyObjectTerm);

    let (subject, predicate, object, graph, provenance) =
        if let Ok((s, p, o, g, prov)) = item.extract::<Quad5<'_>>() {
            (s, p, o, g, prov)
        } else if let Ok((s, p, o, g)) = item.extract::<Quad4>() {
            (s, p, o, g, None)
        } else if let Ok((s, p, o)) = item.extract::<Quad3>() {
            (s, p, o, None, None)
        } else {
            return Err(PyValueError::new_err(format!(
                "quad_shape: quad {index} must be (subject, predicate, object[, graph[, \
                 provenance]]) with subject/graph = (kind, value) and object = (kind, value, \
                 datatype, language)"
            )));
        };

    let provenance = provenance
        .as_ref()
        .map(provenance_from_dict)
        .transpose()?
        .filter(|spec| !spec.is_empty());

    Ok(QuadSpec {
        subject: pair_term(subject),
        predicate,
        object: object_term(object),
        graph: graph.map(pair_term),
        provenance,
    })
}

fn provenance_to_dict(py: Python<'_>, spec: &ProvenanceSpec) -> PyResult<Py<PyDict>> {
    let dict = PyDict::new(py);
    dict.set_item(
        intern!(py, "source_artifact_iri"),
        spec.source_artifact_iri.as_deref(),
    )?;
    dict.set_item(
        intern!(py, "source_content_sha256"),
        spec.source_content_sha256
            .as_deref()
            .map(|bytes| PyBytes::new(py, bytes)),
    )?;
    dict.set_item(intern!(py, "source_offset_start"), spec.source_offset_start)?;
    dict.set_item(intern!(py, "source_offset_end"), spec.source_offset_end)?;
    dict.set_item(intern!(py, "observed_at_micros"), spec.observed_at_micros)?;
    Ok(dict.unbind())
}

fn quad_to_py(py: Python<'_>, spec: QuadSpec) -> PyResult<PyQuadOut> {
    let provenance = spec
        .provenance
        .as_ref()
        .map(|prov| provenance_to_dict(py, prov))
        .transpose()?;
    Ok((
        (spec.subject.kind, spec.subject.value),
        spec.predicate,
        (
            spec.object.kind,
            spec.object.value,
            spec.object.datatype,
            spec.object.language,
        ),
        spec.graph.map(|graph| (graph.kind, graph.value)),
        provenance,
    ))
}

fn quad_limits(max_quads: Option<usize>, max_retained_term_bytes: Option<usize>) -> QuadLimits {
    let mut limits = QuadLimits::default();
    if let Some(value) = max_quads {
        limits.max_quads = value;
    }
    if let Some(value) = max_retained_term_bytes {
        limits.max_retained_term_bytes = value;
    }
    limits
}

/// Builds one `UnsignedQuadStream` v1 batch as Arrow IPC stream bytes.
#[pyfunction]
#[pyo3(signature = (quads, *, max_quads=None, max_retained_term_bytes=None, max_ipc_bytes=None))]
fn build_quad_ipc(
    py: Python<'_>,
    quads: Vec<Bound<'_, PyAny>>,
    max_quads: Option<usize>,
    max_retained_term_bytes: Option<usize>,
    max_ipc_bytes: Option<usize>,
) -> PyResult<Py<PyBytes>> {
    let specs = quads
        .iter()
        .enumerate()
        .map(|(index, item)| quad_from_py(index, item))
        .collect::<PyResult<Vec<_>>>()?;
    let limits = quad_limits(max_quads, max_retained_term_bytes);
    let max_ipc_bytes = max_ipc_bytes.unwrap_or(quad_fast_core::DEFAULT_MAX_IPC_BYTES);
    let payload = py
        .detach(|| convert::quads_to_ipc(&specs, limits, max_ipc_bytes))
        .map_err(binding_err)?;
    Ok(PyBytes::new(py, &payload).unbind())
}

/// Decodes `UnsignedQuadStream` Arrow IPC bytes into quad tuples.
#[pyfunction]
fn read_quad_ipc(py: Python<'_>, data: &[u8]) -> PyResult<Vec<PyQuadOut>> {
    py.detach(|| convert::ipc_to_quads(data))
        .map_err(binding_err)?
        .into_iter()
        .map(|spec| quad_to_py(py, spec))
        .collect()
}

/// Decodes one JSON-LD document (inline context) into `UnsignedQuadStream`
/// Arrow IPC bytes.
///
/// The document is expanded and deserialized to quads by `jsonld-fast-core`
/// under fail-closed budgets; remote contexts and `@import` are refused by
/// name, never fetched. Each call is one JSON-LD document: blank node
/// labels are freshly issued per call, so a JSONL log must be projected one
/// batch per line, not merged. Caller-supplied provenance rides every row.
#[pyfunction]
#[pyo3(signature = (
    text,
    *,
    provenance=None,
    max_input_bytes=None,
    max_nodes=None,
    max_depth=None,
    max_quads=None,
    max_retained_term_bytes=None,
    max_ipc_bytes=None,
))]
#[expect(
    clippy::too_many_arguments,
    reason = "keyword-only Python surface mirroring JsonLdLimits and QuadLimits"
)]
fn jsonld_to_quad_ipc(
    py: Python<'_>,
    text: &str,
    provenance: Option<Bound<'_, PyDict>>,
    max_input_bytes: Option<usize>,
    max_nodes: Option<usize>,
    max_depth: Option<usize>,
    max_quads: Option<usize>,
    max_retained_term_bytes: Option<usize>,
    max_ipc_bytes: Option<usize>,
) -> PyResult<Py<PyBytes>> {
    let provenance = provenance
        .as_ref()
        .map(provenance_from_dict)
        .transpose()?
        .filter(|spec| !spec.is_empty());
    let mut limits = JsonLdLimits::default();
    if let Some(value) = max_input_bytes {
        limits.max_input_bytes = value;
    }
    if let Some(value) = max_nodes {
        limits.max_nodes = value;
    }
    if let Some(value) = max_depth {
        limits.max_depth = value;
    }
    let quad_limits = quad_limits(max_quads, max_retained_term_bytes);
    let max_ipc_bytes = max_ipc_bytes.unwrap_or(quad_fast_core::DEFAULT_MAX_IPC_BYTES);
    let payload = py
        .detach(|| {
            convert::jsonld_to_ipc(
                text,
                provenance.as_ref(),
                &limits,
                quad_limits,
                max_ipc_bytes,
            )
        })
        .map_err(binding_err)?;
    Ok(PyBytes::new(py, &payload).unbind())
}

/// Encodes an IPC quad stream as protobuf-encoded Jelly frames.
#[pyfunction]
#[pyo3(signature = (
    data,
    *,
    stream_name=None,
    max_prefix_table_size=None,
    max_name_table_size=None,
    max_datatype_table_size=None,
    quads_per_frame=None,
    allow_provenance_loss=false,
))]
#[expect(
    clippy::too_many_arguments,
    reason = "keyword-only Python surface mirroring JellyEncoderOptions"
)]
fn jelly_encode(
    py: Python<'_>,
    data: &[u8],
    stream_name: Option<String>,
    max_prefix_table_size: Option<u32>,
    max_name_table_size: Option<u32>,
    max_datatype_table_size: Option<u32>,
    quads_per_frame: Option<usize>,
    allow_provenance_loss: bool,
) -> PyResult<Vec<Py<PyBytes>>> {
    let mut options = JellyEncoderOptions {
        stream_name,
        allow_provenance_loss,
        ..JellyEncoderOptions::default()
    };
    if let Some(value) = max_prefix_table_size {
        options.max_prefix_table_size = value;
    }
    if let Some(value) = max_name_table_size {
        options.max_name_table_size = value;
    }
    if let Some(value) = max_datatype_table_size {
        options.max_datatype_table_size = value;
    }
    if let Some(value) = quads_per_frame {
        options.quads_per_frame = value;
    }
    let frames = py
        .detach(|| convert::ipc_to_jelly_frames(data, options))
        .map_err(binding_err)?;
    Ok(frames
        .into_iter()
        .map(|frame| PyBytes::new(py, &frame).unbind())
        .collect())
}

/// Decodes protobuf-encoded Jelly frames back into IPC bytes.
#[pyfunction]
#[pyo3(signature = (
    frames,
    *,
    max_prefix_table_size=None,
    max_name_table_size=None,
    max_datatype_table_size=None,
    max_quads=None,
    max_retained_term_bytes=None,
    max_ipc_bytes=None,
))]
#[expect(
    clippy::too_many_arguments,
    reason = "keyword-only Python surface mirroring JellyDecoderOptions"
)]
fn jelly_decode(
    py: Python<'_>,
    frames: Vec<Vec<u8>>,
    max_prefix_table_size: Option<u32>,
    max_name_table_size: Option<u32>,
    max_datatype_table_size: Option<u32>,
    max_quads: Option<usize>,
    max_retained_term_bytes: Option<usize>,
    max_ipc_bytes: Option<usize>,
) -> PyResult<Py<PyBytes>> {
    let mut options = JellyDecoderOptions {
        quad_limits: quad_limits(max_quads, max_retained_term_bytes),
        ..JellyDecoderOptions::default()
    };
    if let Some(value) = max_prefix_table_size {
        options.max_prefix_table_size = value;
    }
    if let Some(value) = max_name_table_size {
        options.max_name_table_size = value;
    }
    if let Some(value) = max_datatype_table_size {
        options.max_datatype_table_size = value;
    }
    let max_ipc_bytes = max_ipc_bytes.unwrap_or(quad_fast_core::DEFAULT_MAX_IPC_BYTES);
    let payload = py
        .detach(|| convert::jelly_frames_to_ipc(&frames, options, max_ipc_bytes))
        .map_err(binding_err)?;
    Ok(PyBytes::new(py, &payload).unbind())
}

/// Panics on purpose, so a test can prove a panic surfaces as an exception.
///
/// Compiled only with the `panic-probe` feature, which no release enables.
/// The panic happens with the GIL released, as the real calls do their work,
/// so the test covers the path from `py.detach` back to the function boundary.
/// `tests/test_panic.py` calls it in a child interpreter and requires
/// `pyo3_runtime.PanicException` while the process exits normally.
///
/// # Panics
///
/// Always, with the message `panic-probe: deliberate panic`.
#[cfg(feature = "panic-probe")]
#[pyfunction]
#[pyo3(name = "_panic_probe")]
fn panic_probe(py: Python<'_>) {
    py.detach(|| panic!("panic-probe: deliberate panic"))
}

/// Registers the `quad_fast._native` extension module.
#[pymodule]
fn _native(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add(
        "QuadResourceError",
        module.py().get_type::<QuadResourceError>(),
    )?;
    module.add_function(wrap_pyfunction!(build_quad_ipc, module)?)?;
    module.add_function(wrap_pyfunction!(read_quad_ipc, module)?)?;
    module.add_function(wrap_pyfunction!(jelly_encode, module)?)?;
    module.add_function(wrap_pyfunction!(jelly_decode, module)?)?;
    module.add_function(wrap_pyfunction!(jsonld_to_quad_ipc, module)?)?;
    #[cfg(feature = "panic-probe")]
    module.add_function(wrap_pyfunction!(panic_probe, module)?)?;
    Ok(())
}
