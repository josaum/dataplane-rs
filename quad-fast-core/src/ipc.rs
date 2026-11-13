// Rust guideline compliant 2026-02-21
//! Arrow IPC stream transport for `UnsignedQuadStream` batches.
//!
//! # Reading foreign bytes is fail-closed
//!
//! [`read_ipc_stream`] is the crate's only entry point that accepts bytes an
//! attacker chose (a Flight `DoPut` body, a gRPC frame, a file on disk).
//! Arrow's IPC decoder is not written to that threat model: a corrupted
//! encapsulated message can make it panic inside a buffer slice, and a
//! message that *declares* a body far larger than the payload can make it
//! attempt an allocation large enough to abort the process — which no
//! `catch_unwind` can intercept. Both were observed against
//! `arrow-ipc = 58.3.0` by this crate's fuzz harness.
//!
//! So the reader is layered:
//!
//! 1. [`preflight_stream`] walks the encapsulated-message framing *without
//!    decoding array data*, verifying each message's flatbuffer with the
//!    generated verifier and bounding every declared length by the bytes
//!    actually present. This is what removes the unbounded-allocation class:
//!    after it passes, no declared length exceeds the input.
//! 2. The arrow decode then runs inside [`std::panic::catch_unwind`], so a
//!    residual panic inside a size-valid body becomes [`QuadError::Ipc`]
//!    rather than unwinding into a caller's request handler.
//! 3. [`crate::validate_contract`] rejects anything that is a readable Arrow
//!    stream but not `UnsignedQuadStream` v1.
//!
//! ## Deliberate narrowings
//!
//! * **Modern framing only.** Every message must be introduced by the
//!   `0xFFFF_FFFF` continuation marker followed by a `u32` metadata length.
//!   The pre-1.0 legacy framing (bare length prefix, `write_legacy_ipc_format`)
//!   is refused; nothing in this workspace emits it.
//! * **Compression refused.** A `RecordBatch` or `DictionaryBatch` message
//!   that declares a body compression is refused. Arrow's decompressor
//!   allocates the *declared* uncompressed size, which is attacker-chosen and
//!   unbounded, and no writer in this cartridge compresses (verified: no
//!   `try_with_compression` call exists, and `quad-fast-flight` uses
//!   `IpcWriteOptions::default()`). Lifting this needs a bound on the
//!   decompressed size, which arrow does not expose.
//! * **Message kinds.** Only `Schema`, `DictionaryBatch`, and `RecordBatch`
//!   are accepted; `Tensor` and `SparseTensor` cannot occur in a contract
//!   stream.

use std::io::Cursor;

use arrow_array::RecordBatch;
use arrow_ipc::{MessageHeader, reader::StreamReader, root_as_message, writer::StreamWriter};

use crate::{
    error::{QuadError, QuadResource},
    schema::{quad_stream_schema, validate_contract},
};

/// Default maximum encoded IPC payload: 64 MiB.
///
/// Same default as `owl-fast-core::DEFAULT_MAX_IPC_BYTES` so both parser
/// planes fail closed at the same scale.
pub const DEFAULT_MAX_IPC_BYTES: usize = 64 * 1024 * 1024;

/// Marker introducing every encapsulated message in the modern IPC framing.
const CONTINUATION_MARKER: u32 = 0xFFFF_FFFF;

/// Bytes consumed by the continuation marker plus the metadata length.
const PREFIX_LEN: usize = 8;

fn ipc_err(error: arrow_schema::ArrowError) -> QuadError {
    QuadError::Ipc(error.to_string())
}

fn malformed(detail: impl Into<String>) -> QuadError {
    QuadError::Ipc(detail.into())
}

/// Encodes contract-valid batches as one Arrow IPC stream.
///
/// # Errors
///
/// Returns [`QuadError::Contract`] when any batch is not an
/// `UnsignedQuadStream` batch, [`QuadError::ResourceLimit`] when the encoded
/// payload exceeds `max_ipc_bytes`, and [`QuadError::Ipc`] on encoder
/// failure.
pub fn write_ipc_stream(
    batches: &[RecordBatch],
    max_ipc_bytes: usize,
) -> Result<Vec<u8>, QuadError> {
    for batch in batches {
        validate_contract(batch.schema().as_ref())?;
    }
    let schema = quad_stream_schema();
    let mut writer = StreamWriter::try_new(Vec::new(), schema.as_ref()).map_err(ipc_err)?;
    for batch in batches {
        writer.write(batch).map_err(ipc_err)?;
    }
    writer.finish().map_err(ipc_err)?;
    let bytes = writer.into_inner().map_err(ipc_err)?;
    if bytes.len() > max_ipc_bytes {
        return Err(QuadError::ResourceLimit {
            resource: QuadResource::IpcBytes,
            limit: max_ipc_bytes,
            observed: bytes.len(),
        });
    }
    Ok(bytes)
}

/// Decodes an Arrow IPC stream of contract-valid quad batches.
///
/// Fail-closed on arbitrary bytes: see the module documentation for the
/// pre-flight, the panic barrier, and the deliberate narrowings (modern
/// framing only, no body compression, no tensor messages).
///
/// # Errors
///
/// Returns [`QuadError::Ipc`] when the payload is not a well-framed, readable
/// IPC stream — including when arrow's decoder panics on it — and
/// [`QuadError::Contract`] when the stream schema is not `UnsignedQuadStream`
/// v1.
pub fn read_ipc_stream(bytes: &[u8]) -> Result<Vec<RecordBatch>, QuadError> {
    // The pre-flight runs inside the barrier too: it is written not to panic,
    // but a decoder barrier that trusts its own pre-flight is a barrier with
    // a hole in it.
    match std::panic::catch_unwind(|| {
        preflight_stream(bytes)?;
        decode_stream(bytes)
    }) {
        Ok(result) => result,
        Err(payload) => Err(malformed(format!(
            "arrow IPC decoder panicked on a malformed payload: {}",
            panic_detail(payload.as_ref())
        ))),
    }
}

/// Extracts a printable reason from a caught panic payload.
fn panic_detail(payload: &(dyn std::any::Any + Send)) -> &str {
    if let Some(message) = payload.downcast_ref::<&'static str>() {
        message
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.as_str()
    } else {
        "<non-string panic payload>"
    }
}

/// Decodes a pre-flighted stream into contract-valid batches.
fn decode_stream(bytes: &[u8]) -> Result<Vec<RecordBatch>, QuadError> {
    let reader = StreamReader::try_new(Cursor::new(bytes), None).map_err(ipc_err)?;
    validate_contract(reader.schema().as_ref())?;
    let mut batches = Vec::new();
    for batch in reader {
        batches.push(batch.map_err(ipc_err)?);
    }
    Ok(batches)
}

/// Validates the encapsulated-message framing without decoding array data.
///
/// Every declared length is bounded by the bytes actually present, so a
/// payload that survives this cannot drive an allocation larger than itself.
///
/// # Errors
///
/// Returns [`QuadError::Ipc`] describing the first structural violation.
fn preflight_stream(bytes: &[u8]) -> Result<(), QuadError> {
    let mut offset = 0usize;
    let mut saw_schema = false;
    while offset < bytes.len() {
        let remaining = bytes.len() - offset;
        if remaining < PREFIX_LEN {
            return Err(malformed(format!(
                "truncated message prefix at byte {offset}: {remaining} bytes remain, need \
                 {PREFIX_LEN}"
            )));
        }
        let marker = read_u32(bytes, offset);
        if marker != CONTINUATION_MARKER {
            return Err(malformed(format!(
                "message at byte {offset} is not introduced by the continuation marker \
                 (found {marker:#010x}); legacy IPC framing is refused"
            )));
        }
        let metadata_len = read_u32(bytes, offset + 4) as usize;
        if metadata_len == 0 {
            // End-of-stream marker. Nothing may follow it.
            if offset + PREFIX_LEN != bytes.len() {
                return Err(malformed(format!(
                    "{} trailing bytes after the end-of-stream marker",
                    bytes.len() - offset - PREFIX_LEN
                )));
            }
            return Ok(());
        }
        let metadata_end = offset
            .checked_add(PREFIX_LEN)
            .and_then(|start| start.checked_add(metadata_len))
            .ok_or_else(|| {
                malformed(format!(
                    "metadata length {metadata_len} overflows the stream offset"
                ))
            })?;
        if metadata_end > bytes.len() {
            return Err(malformed(format!(
                "message at byte {offset} declares {metadata_len} metadata bytes but only {} \
                 remain",
                bytes.len() - offset - PREFIX_LEN
            )));
        }
        let body_len =
            preflight_message(&bytes[offset + PREFIX_LEN..metadata_end], &mut saw_schema)?;
        let next = metadata_end.checked_add(body_len).ok_or_else(|| {
            malformed(format!(
                "body length {body_len} overflows the stream offset"
            ))
        })?;
        if next > bytes.len() {
            return Err(malformed(format!(
                "message at byte {offset} declares a {body_len}-byte body but only {} bytes remain",
                bytes.len() - metadata_end
            )));
        }
        offset = next;
    }
    if !saw_schema {
        return Err(malformed("stream carries no schema message"));
    }
    Ok(())
}

/// Verifies one message's flatbuffer and returns its declared body length.
fn preflight_message(metadata: &[u8], saw_schema: &mut bool) -> Result<usize, QuadError> {
    let message = root_as_message(metadata).map_err(|error| {
        malformed(format!(
            "message metadata is not a valid flatbuffer: {error}"
        ))
    })?;
    let body_len = usize::try_from(message.bodyLength())
        .map_err(|_ignored| malformed("message declares a negative body length"))?;
    match message.header_type() {
        MessageHeader::Schema => {
            if *saw_schema {
                return Err(malformed("stream carries more than one schema message"));
            }
            *saw_schema = true;
        }
        MessageHeader::RecordBatch | MessageHeader::DictionaryBatch => {
            require_schema_first(*saw_schema, "record or dictionary batch")?;
            preflight_batch_header(&message, body_len)?;
        }
        other => return Err(unsupported_header(other)),
    }
    Ok(body_len)
}

fn unsupported_header(header: MessageHeader) -> QuadError {
    malformed(format!(
        "unsupported IPC message header {:?}; an UnsignedQuadStream stream carries only \
         schema, dictionary batch, and record batch messages",
        header.0
    ))
}

/// Checks a record or dictionary batch header against the body it describes.
///
/// Arrow slices every buffer out of the body with a slicing call that panics
/// when the range falls outside it, and decompresses into an allocation of
/// the size the buffer itself declares. So, before any decode:
///
/// * body compression is refused (the declared size is attacker-chosen);
/// * delta dictionaries are refused (each delta re-concatenates the whole
///   dictionary, so `n` small deltas cost `O(n^2)` copying, and no writer in
///   this workspace emits them: `quad-fast-flight` and `write_ipc_stream`
///   both use `DictionaryHandling::Resend`);
/// * every length, count and offset must be non-negative, and every buffer
///   must lie inside `body_len`.
fn preflight_batch_header(
    message: &arrow_ipc::Message<'_>,
    body_len: usize,
) -> Result<(), QuadError> {
    let (batch, kind) = match message.header_type() {
        MessageHeader::RecordBatch => (
            message
                .header_as_record_batch()
                .ok_or_else(|| malformed("record batch message has no record batch header"))?,
            "record batch",
        ),
        MessageHeader::DictionaryBatch => {
            let dictionary = message.header_as_dictionary_batch().ok_or_else(|| {
                malformed("dictionary batch message has no dictionary batch header")
            })?;
            if dictionary.isDelta() {
                return Err(malformed(
                    "dictionary batch is a delta; delta dictionaries are refused (each one \
                     re-copies the whole dictionary)",
                ));
            }
            (
                dictionary
                    .data()
                    .ok_or_else(|| malformed("dictionary batch message carries no record batch"))?,
                "dictionary batch",
            )
        }
        other => return Err(unsupported_header(other)),
    };
    reject_compression(batch.compression().is_some(), kind)?;
    if batch.length() < 0 {
        return Err(malformed(format!("{kind} declares a negative row count")));
    }
    for node in batch.nodes().into_iter().flatten() {
        if node.length() < 0 || node.null_count() < 0 {
            return Err(malformed(format!(
                "{kind} declares a negative field length or null count"
            )));
        }
    }
    for buffer in batch.buffers().into_iter().flatten() {
        let end = usize::try_from(buffer.offset())
            .ok()
            .zip(usize::try_from(buffer.length()).ok())
            .and_then(|(offset, length)| offset.checked_add(length));
        match end {
            Some(end) if end <= body_len => {}
            _ => {
                return Err(malformed(format!(
                    "{kind} declares a buffer outside its {body_len}-byte body"
                )));
            }
        }
    }
    Ok(())
}

/// Verifies one encapsulated IPC message that arrives on its own.
///
/// This is the per-message form of the stream pre-flight that
/// [`read_ipc_stream`] runs, for transports that deliver header and body
/// separately (an Arrow Flight `FlightData` carries `data_header` and
/// `data_body`). Run it on every message *before* handing it to an Arrow
/// decoder. A message with no header (`MessageHeader::NONE`, used by Flight
/// for metadata-only frames) passes with an empty body.
///
/// # Errors
///
/// Returns [`QuadError::Ipc`] when the header is not a verifiable flatbuffer,
/// is a message kind a contract stream never carries, declares a body
/// compression or a delta dictionary, declares a negative length or count,
/// or describes a buffer that lies outside `body`.
pub fn preflight_ipc_message(metadata: &[u8], body: &[u8]) -> Result<(), QuadError> {
    let message = root_as_message(metadata).map_err(|error| {
        malformed(format!(
            "message metadata is not a valid flatbuffer: {error}"
        ))
    })?;
    match message.header_type() {
        MessageHeader::NONE | MessageHeader::Schema => Ok(()),
        MessageHeader::RecordBatch | MessageHeader::DictionaryBatch => {
            preflight_batch_header(&message, body.len())
        }
        other => Err(unsupported_header(other)),
    }
}

fn require_schema_first(saw_schema: bool, kind: &str) -> Result<(), QuadError> {
    if saw_schema {
        return Ok(());
    }
    Err(malformed(format!(
        "{kind} message precedes the schema message"
    )))
}

fn reject_compression(compressed: bool, kind: &str) -> Result<(), QuadError> {
    if !compressed {
        return Ok(());
    }
    Err(malformed(format!(
        "{kind} message declares a body compression; the decompressed size is attacker-chosen \
         and unbounded, so compressed contract streams are refused"
    )))
}

/// Reads a little-endian `u32` at `offset`.
///
/// The caller has already checked that four bytes are available.
fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    let mut word = [0u8; 4];
    word.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_le_bytes(word)
}
