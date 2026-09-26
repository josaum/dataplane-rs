// SPDX-License-Identifier: MIT
// Rust guideline compliant 2026-02-21
//! Fail-closed decoding of Jelly-Patch stream frames into patch ops.

use oxrdf::Term;
use quad_fast_core::{QuadBatchBuilder, QuadLimits};

use crate::{
    decoder::check_declared_table_sizes,
    encoder::SPEC_MIN_NAME_TABLE_SIZE,
    error::{JellyError, JellyResource},
    patch::{PatchOp, encoder::PATCH_PROTOCOL_VERSION},
    proto::patch::{
        PatchStatementType, PatchStreamType, RdfPatchFrame, RdfPatchHeader, RdfPatchOptions,
        rdf_patch_header, rdf_patch_row,
    },
    terms::{TermDecoder, blank_node},
};

/// Fail-closed configuration for [`JellyPatchDecoder`].
///
/// All limits are explicit: the decoder rejects streams that declare
/// lookup tables larger than the configured maxima before allocating
/// anything, and every batch built from statement rows is governed by
/// `quad_limits`.
#[derive(Clone, Debug)]
pub struct JellyPatchDecoderOptions {
    /// Largest prefix lookup table this decoder accepts.
    pub max_prefix_table_size: u32,
    /// Largest name lookup table this decoder accepts.
    pub max_name_table_size: u32,
    /// Largest datatype lookup table this decoder accepts.
    pub max_datatype_table_size: u32,
    /// Limits applied to every batch built from consecutive statements.
    pub quad_limits: QuadLimits,
}

impl Default for JellyPatchDecoderOptions {
    fn default() -> Self {
        Self {
            max_prefix_table_size: crate::encoder::DEFAULT_MAX_PREFIX_TABLE_SIZE,
            max_name_table_size: crate::encoder::DEFAULT_MAX_NAME_TABLE_SIZE,
            max_datatype_table_size: crate::encoder::DEFAULT_MAX_DATATYPE_TABLE_SIZE,
            quad_limits: QuadLimits::default(),
        }
    }
}

/// Per-stream state created once the options row has been validated.
#[derive(Debug)]
struct PatchState {
    terms: TermDecoder,
    in_transaction: bool,
}

/// Statement rows being grouped into one pending quad batch.
struct PendingBatch {
    is_add: bool,
    builder: QuadBatchBuilder,
}

/// Decodes Jelly-Patch `FLAT` stream frames into [`PatchOp`] sequences.
///
/// One decoder instance consumes exactly one patch stream: the options
/// row must arrive before any other row, and lookup table, repeated-term,
/// and transaction state persist across frames (`FLAT` semantics). Every
/// produced batch is unsigned by construction with null provenance
/// columns; decoding never attaches or promotes assurance.
///
/// The decoder fails closed with typed errors — never silently skipping
/// rows — for the full refused surface listed in the [module
/// docs](crate::patch). Maximal runs of consecutive add (or delete) rows
/// within a frame collapse into one [`PatchOp::Add`] (or
/// [`PatchOp::Delete`]) batch each.
///
/// Call [`JellyPatchDecoder::finish`] when the transport signals
/// end-of-stream so a patch that ends with an open transaction surfaces
/// as a typed error instead of silence.
///
/// # Examples
///
/// ```
/// use jelly_fast_core::{
///     JellyPatchDecoder, JellyPatchDecoderOptions, JellyPatchEncoder,
///     JellyPatchEncoderOptions,
/// };
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let mut encoder = JellyPatchEncoder::new(JellyPatchEncoderOptions::default())?;
/// let frames = encoder.encode_ops(&[])?;
///
/// let mut decoder = JellyPatchDecoder::new(JellyPatchDecoderOptions::default());
/// let ops = decoder.decode_frame(&frames[0])?;
/// decoder.finish()?;
/// assert!(ops.is_empty());
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct JellyPatchDecoder {
    options: JellyPatchDecoderOptions,
    state: Option<PatchState>,
}

impl JellyPatchDecoder {
    /// Creates a decoder for one patch stream governed by `options`.
    #[must_use]
    pub fn new(options: JellyPatchDecoderOptions) -> Self {
        Self {
            options,
            state: None,
        }
    }

    /// Decodes one frame into a sequence of patch operations.
    ///
    /// The first frame must start with the stream options row. Frames
    /// that carry only non-operation rows produce an empty sequence.
    ///
    /// # Errors
    ///
    /// Returns [`JellyError::Options`] for missing, duplicated, or
    /// invalid options; [`JellyError::Unsupported`] for refused protocol
    /// features (TRIPLES statement type, FRAME/PUNCTUATED stream types,
    /// triple terms outside the object position or without the `rdf_star`
    /// options flag, generalized statements, namespace rows, versions other
    /// than 1); [`JellyError::ResourceLimit`] when a declared table
    /// exceeds a configured maximum; [`JellyError::Lookup`],
    /// [`JellyError::Frame`], and [`JellyError::Term`] for malformed row
    /// content or ordering (including transaction and header-placement
    /// violations); and [`JellyError::Quad`] when batch construction hits
    /// a quad limit.
    pub fn decode_frame(&mut self, frame: &RdfPatchFrame) -> Result<Vec<PatchOp>, JellyError> {
        let mut ops = Vec::new();
        let mut pending: Option<PendingBatch> = None;
        // The vendored schema requires header rows at the start of the
        // patch frame; options and lookup entry rows do not displace them.
        let mut non_header_row_seen = false;
        for row in &frame.rows {
            let row = row
                .row
                .as_ref()
                .ok_or_else(|| JellyError::Frame("patch row without a payload".into()))?;
            match row {
                rdf_patch_row::Row::Options(options) => self.accept_options(options)?,
                rdf_patch_row::Row::StatementAdd(quad)
                | rdf_patch_row::Row::StatementDelete(quad) => {
                    non_header_row_seen = true;
                    let is_add = matches!(row, rdf_patch_row::Row::StatementAdd(_));
                    let quad = self.state_mut()?.terms.decode_quad(quad)?;
                    let same_run = matches!(&pending, Some(batch) if batch.is_add == is_add);
                    if !same_run {
                        flush_pending(&mut pending, &mut ops)?;
                        pending = Some(PendingBatch {
                            is_add,
                            builder: QuadBatchBuilder::new(self.options.quad_limits),
                        });
                    }
                    let batch = pending.as_mut().expect("pending batch ensured above");
                    batch.builder.push(quad.as_ref(), None)?;
                }
                rdf_patch_row::Row::TransactionStart(_) => {
                    non_header_row_seen = true;
                    flush_pending(&mut pending, &mut ops)?;
                    let state = self.state_mut()?;
                    if state.in_transaction {
                        return Err(JellyError::Frame(
                            "transaction start inside an open transaction (transactions cannot \
                             nest)"
                                .into(),
                        ));
                    }
                    state.in_transaction = true;
                    ops.push(PatchOp::TransactionStart);
                }
                rdf_patch_row::Row::TransactionCommit(_)
                | rdf_patch_row::Row::TransactionAbort(_) => {
                    non_header_row_seen = true;
                    flush_pending(&mut pending, &mut ops)?;
                    let is_commit = matches!(row, rdf_patch_row::Row::TransactionCommit(_));
                    let state = self.state_mut()?;
                    if !state.in_transaction {
                        let kind = if is_commit { "commit" } else { "abort" };
                        return Err(JellyError::Frame(format!(
                            "transaction {kind} without an open transaction"
                        )));
                    }
                    state.in_transaction = false;
                    ops.push(if is_commit {
                        PatchOp::TransactionCommit
                    } else {
                        PatchOp::TransactionAbort
                    });
                }
                rdf_patch_row::Row::Header(header) => {
                    if non_header_row_seen {
                        return Err(JellyError::Frame(
                            "header rows must occur at the start of the patch frame".into(),
                        ));
                    }
                    let state = self.state_mut()?;
                    ops.push(decode_header(&mut state.terms, header)?);
                }
                rdf_patch_row::Row::Name(entry) => {
                    self.state_mut()?
                        .terms
                        .assign_name(entry.id, entry.value.clone())?;
                }
                rdf_patch_row::Row::Prefix(entry) => {
                    self.state_mut()?
                        .terms
                        .assign_prefix(entry.id, entry.value.clone())?;
                }
                rdf_patch_row::Row::Datatype(entry) => {
                    self.state_mut()?
                        .terms
                        .assign_datatype(entry.id, entry.value.clone())?;
                }
                rdf_patch_row::Row::NamespaceAdd(declaration)
                | rdf_patch_row::Row::NamespaceDelete(declaration) => {
                    // Ensure the ordering error wins when options are absent.
                    let _ = self.state_mut()?;
                    return Err(JellyError::Unsupported {
                        feature: "namespace_declaration",
                        detail: format!(
                            "namespace declaration `{}` cannot be represented in the quad \
                             contract and will not be dropped silently",
                            declaration.name
                        ),
                    });
                }
                rdf_patch_row::Row::Punctuation(_) => {
                    let _ = self.state_mut()?;
                    // Options validation admits FLAT streams only, and the
                    // vendored schema restricts punctuation to PUNCTUATED
                    // streams, so this row is a structural violation here.
                    return Err(JellyError::Frame(
                        "punctuation row is not valid in a FLAT patch stream".into(),
                    ));
                }
            }
        }
        flush_pending(&mut pending, &mut ops)?;
        Ok(ops)
    }

    /// Validates that the decoded patch stream can end here.
    ///
    /// Call when the transport signals end-of-stream.
    ///
    /// # Errors
    ///
    /// Returns [`JellyError::Frame`] when a transaction is still open; a
    /// truncated patch must never pass for a complete one.
    pub fn finish(&self) -> Result<(), JellyError> {
        if self
            .state
            .as_ref()
            .is_some_and(|state| state.in_transaction)
        {
            return Err(JellyError::Frame(
                "patch stream ended with an open transaction".into(),
            ));
        }
        Ok(())
    }

    /// Returns the stream state, failing when options have not arrived.
    fn state_mut(&mut self) -> Result<&mut PatchState, JellyError> {
        self.state.as_mut().ok_or_else(|| {
            JellyError::Options("patch options row must precede all other rows".into())
        })
    }

    /// Validates the options row and initializes stream state.
    fn accept_options(&mut self, options: &RdfPatchOptions) -> Result<(), JellyError> {
        if self.state.is_some() {
            return Err(JellyError::Options("duplicate patch options row".into()));
        }
        match options.version {
            PATCH_PROTOCOL_VERSION => {}
            0 => {
                return Err(JellyError::Options(
                    "patch options version is 0 (the field is required)".into(),
                ));
            }
            other => {
                return Err(JellyError::Unsupported {
                    feature: "patch_version",
                    detail: format!(
                        "patch protocol version {other} is not supported (expected \
                         {PATCH_PROTOCOL_VERSION}; 10000+ marks custom extensions)"
                    ),
                });
            }
        }
        match PatchStatementType::try_from(options.statement_type) {
            Ok(PatchStatementType::Quads) => {}
            Ok(PatchStatementType::Triples) => {
                return Err(JellyError::Unsupported {
                    feature: "patch_statement_type_triples",
                    detail: "this decoder consumes QUADS patch streams only; TRIPLES streams are \
                             not mapped to the default graph implicitly"
                        .into(),
                });
            }
            Ok(PatchStatementType::Unspecified) | Err(_) => {
                return Err(JellyError::Options(format!(
                    "patch statement type {} is unspecified or unknown",
                    options.statement_type
                )));
            }
        }
        match PatchStreamType::try_from(options.stream_type) {
            Ok(PatchStreamType::Flat) => {}
            Ok(PatchStreamType::Frame) => {
                return Err(JellyError::Unsupported {
                    feature: "patch_stream_type_frame",
                    detail: "FRAME patch streams are not supported: the vendored schema \
                             underdetermines lookup table resets at patch boundaries"
                        .into(),
                });
            }
            Ok(PatchStreamType::Punctuated) => {
                return Err(JellyError::Unsupported {
                    feature: "patch_stream_type_punctuated",
                    detail: "PUNCTUATED patch streams are not supported: the vendored schema \
                             underdetermines lookup table resets at patch boundaries"
                        .into(),
                });
            }
            Ok(PatchStreamType::Unspecified) | Err(_) => {
                return Err(JellyError::Options(format!(
                    "patch stream type {} is unspecified or unknown",
                    options.stream_type
                )));
            }
        }
        if options.generalized_statements {
            return Err(JellyError::Unsupported {
                feature: "generalized_statements",
                detail: "generalized RDF statements are not supported".into(),
            });
        }
        if options.max_name_table_size < SPEC_MIN_NAME_TABLE_SIZE {
            return Err(JellyError::Options(format!(
                "max_name_table_size {} is below the spec minimum {SPEC_MIN_NAME_TABLE_SIZE}",
                options.max_name_table_size
            )));
        }
        check_declared_table_sizes(
            [
                (JellyResource::PrefixTable, options.max_prefix_table_size),
                (JellyResource::NameTable, options.max_name_table_size),
                (
                    JellyResource::DatatypeTable,
                    options.max_datatype_table_size,
                ),
            ],
            [
                self.options.max_prefix_table_size,
                self.options.max_name_table_size,
                self.options.max_datatype_table_size,
            ],
        )?;
        self.state = Some(PatchState {
            terms: TermDecoder::new(
                options.max_prefix_table_size,
                options.max_name_table_size,
                options.max_datatype_table_size,
                options.rdf_star,
                self.options.quad_limits.max_quoted_depth,
            ),
            in_transaction: false,
        });
        Ok(())
    }
}

/// Finishes a pending statement run into an add or delete operation.
fn flush_pending(
    pending: &mut Option<PendingBatch>,
    ops: &mut Vec<PatchOp>,
) -> Result<(), JellyError> {
    if let Some(batch) = pending.take() {
        let record_batch = batch.builder.finish()?;
        ops.push(if batch.is_add {
            PatchOp::Add(record_batch)
        } else {
            PatchOp::Delete(record_batch)
        });
    }
    Ok(())
}

/// Decodes one header row into a [`PatchOp::Header`].
fn decode_header(terms: &mut TermDecoder, header: &RdfPatchHeader) -> Result<PatchOp, JellyError> {
    if header.key.is_empty() {
        return Err(JellyError::Frame(
            "patch header key must not be empty (the field is required)".into(),
        ));
    }
    let value = header
        .value
        .as_ref()
        .ok_or_else(|| JellyError::Frame("patch header value must be set".into()))?;
    let value = match value {
        rdf_patch_header::Value::HIri(iri) => Term::NamedNode(terms.resolve_iri(iri, "header")?),
        rdf_patch_header::Value::HBnode(label) => Term::BlankNode(blank_node(label, "header")?),
        rdf_patch_header::Value::HLiteral(literal) => Term::Literal(terms.decode_literal(literal)?),
        // The vendored `patch.proto` models header triple terms explicitly
        // and gates them with the same `rdf_star` option as statement rows,
        // so they are decoded rather than refused; `decode_header_triple_term`
        // enforces the option flag and the depth bound.
        rdf_patch_header::Value::HTripleTerm(triple) => {
            Term::Triple(Box::new(terms.decode_header_triple_term(triple)?))
        }
    };
    Ok(PatchOp::Header {
        key: header.key.clone(),
        value,
    })
}
