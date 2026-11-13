// SPDX-License-Identifier: MIT
// Rust guideline compliant 2026-02-21
//! Encoding of [`PatchOp`] sequences into Jelly-Patch stream frames.

use oxrdf::Term;
use quad_fast_core::{DEFAULT_MAX_QUOTED_DEPTH, QuadStreamReader, quoted::check_depth};

use crate::{
    encoder::{
        DEFAULT_MAX_DATATYPE_TABLE_SIZE, DEFAULT_MAX_NAME_TABLE_SIZE,
        DEFAULT_MAX_PREFIX_TABLE_SIZE, check_provenance_loss, read_owned_quad,
        validate_encoder_table_sizes,
    },
    error::JellyError,
    patch::PatchOp,
    proto::patch::{
        PatchStatementType, PatchStreamType, RdfPatchFrame, RdfPatchHeader, RdfPatchOptions,
        RdfPatchRow, RdfPatchTransactionAbort, RdfPatchTransactionCommit, RdfPatchTransactionStart,
        rdf_patch_header, rdf_patch_row,
    },
    terms::{LookupEntry, TermEncoder},
};

/// Protocol version emitted in patch stream options.
///
/// The vendored `patch.proto` requires 1 for Jelly-Patch 1.0.x (based on
/// Jelly-RDF 1.1.x); values of 10000 or higher mark custom extensions.
pub const PATCH_PROTOCOL_VERSION: u32 = 1;

/// Default operation rows per emitted patch frame: 8192.
///
/// Same sizing rationale as the RDF stream codec's
/// [`crate::DEFAULT_QUADS_PER_FRAME`]: frames of typical rows stay well
/// under common gRPC message-size ceilings while amortizing per-frame
/// overhead.
pub const DEFAULT_PATCH_ROWS_PER_FRAME: usize = 8192;

/// Fail-closed configuration for [`JellyPatchEncoder`].
#[derive(Clone, Debug)]
pub struct JellyPatchEncoderOptions {
    /// Maximum prefix lookup table size (must be at least 1).
    pub max_prefix_table_size: u32,
    /// Maximum name lookup table size (must be at least 8 per the schema).
    pub max_name_table_size: u32,
    /// Maximum datatype lookup table size (must be at least 1).
    pub max_datatype_table_size: u32,
    /// Maximum operation rows per emitted frame (must be at least 1).
    ///
    /// Statement, transaction, and header rows all count; lookup entry
    /// rows ride along with the row that needs them.
    pub rows_per_frame: usize,
    /// Permit encoding batches that carry per-quad source provenance.
    ///
    /// The vendored Jelly-Patch schema has no per-quad provenance fields,
    /// so provenance cannot survive this codec. With the default `false`,
    /// the encoder fails closed on any non-null provenance column instead
    /// of dropping data silently; set `true` only when the caller
    /// knowingly accepts the loss.
    pub allow_provenance_loss: bool,
    /// Announce and emit RDF 1.2 triple terms (`RdfPatchOptions.rdf_star`).
    ///
    /// The vendored `patch.proto` carries statement rows as the very same
    /// `RdfQuad` message as the RDF stream and gates them with the same
    /// `rdf_star` option, and models header triple terms explicitly
    /// (`h_triple_term`), so patch RDF-star semantics are determined by the
    /// vendored schema rather than underdetermined — both are implemented.
    /// Default `false`, which keeps emitted patches byte-identical to the
    /// pre-RDF-star encoder and refuses triple terms rather than writing
    /// them into a stream that denies them.
    pub rdf_star: bool,
    /// Maximum triple-term nesting depth read out of a batch or header.
    pub max_quoted_depth: usize,
}

impl Default for JellyPatchEncoderOptions {
    fn default() -> Self {
        Self {
            max_prefix_table_size: DEFAULT_MAX_PREFIX_TABLE_SIZE,
            max_name_table_size: DEFAULT_MAX_NAME_TABLE_SIZE,
            max_datatype_table_size: DEFAULT_MAX_DATATYPE_TABLE_SIZE,
            rows_per_frame: DEFAULT_PATCH_ROWS_PER_FRAME,
            allow_provenance_loss: false,
            rdf_star: false,
            max_quoted_depth: DEFAULT_MAX_QUOTED_DEPTH,
        }
    }
}

/// Encodes [`PatchOp`] sequences into Jelly-Patch `FLAT` stream frames.
///
/// One encoder instance produces exactly one patch stream: the first
/// frame starts with the options row, and lookup table, repeated-term,
/// and transaction state span calls and frames (`FLAT` semantics). Output
/// is unsigned by construction.
///
/// Call [`JellyPatchEncoder::finish`] before transmitting the final frame
/// to fail closed on a patch that ends with an open transaction.
///
/// # Examples
///
/// ```
/// use jelly_fast_core::{JellyPatchEncoder, JellyPatchEncoderOptions, PatchOp};
/// use oxrdf::{NamedNode, Quad};
/// use quad_fast_core::{QuadBatchBuilder, QuadLimits};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let quad = Quad::new(
///     NamedNode::new("http://example.com/s")?,
///     NamedNode::new("http://example.com/p")?,
///     NamedNode::new("http://example.com/o")?,
///     oxrdf::GraphName::DefaultGraph,
/// );
/// let mut builder = QuadBatchBuilder::new(QuadLimits::default());
/// builder.push(quad.as_ref(), None)?;
/// let batch = builder.finish()?;
///
/// let mut encoder = JellyPatchEncoder::new(JellyPatchEncoderOptions::default())?;
/// let frames = encoder.encode_ops(&[PatchOp::Add(batch)])?;
/// encoder.finish()?;
/// assert_eq!(frames.len(), 1);
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct JellyPatchEncoder {
    options: JellyPatchEncoderOptions,
    terms: TermEncoder,
    options_emitted: bool,
    in_transaction: bool,
    statements_encoded: bool,
}

/// Wraps a lookup entry into a patch stream row.
fn entry_row(entry: LookupEntry) -> RdfPatchRow {
    let row = match entry {
        LookupEntry::Prefix(entry) => rdf_patch_row::Row::Prefix(entry),
        LookupEntry::Name(entry) => rdf_patch_row::Row::Name(entry),
        LookupEntry::Datatype(entry) => rdf_patch_row::Row::Datatype(entry),
    };
    RdfPatchRow { row: Some(row) }
}

/// Counts one operation row, cutting a frame at the configured size.
fn count_row(
    rows_per_frame: usize,
    rows_in_frame: &mut usize,
    rows: &mut Vec<RdfPatchRow>,
    frames: &mut Vec<RdfPatchFrame>,
) {
    *rows_in_frame += 1;
    if *rows_in_frame == rows_per_frame {
        frames.push(RdfPatchFrame {
            rows: std::mem::take(rows),
        });
        *rows_in_frame = 0;
    }
}

impl JellyPatchEncoder {
    /// Creates an encoder for one patch stream governed by `options`.
    ///
    /// # Errors
    ///
    /// Returns [`JellyError::Options`] when a table size is below its
    /// minimum (name below 8 per the schema, prefix or datatype below 1)
    /// or `rows_per_frame` is zero.
    pub fn new(options: JellyPatchEncoderOptions) -> Result<Self, JellyError> {
        validate_encoder_table_sizes(
            options.max_prefix_table_size,
            options.max_name_table_size,
            options.max_datatype_table_size,
        )?;
        if options.rows_per_frame == 0 {
            return Err(JellyError::Options(
                "rows_per_frame must be at least 1".into(),
            ));
        }
        Ok(Self {
            terms: TermEncoder::new(
                options.max_prefix_table_size,
                options.max_name_table_size,
                options.max_datatype_table_size,
            ),
            options_emitted: false,
            in_transaction: false,
            statements_encoded: false,
            options,
        })
    }

    /// Encodes operations into zero or more Jelly-Patch stream frames.
    ///
    /// The first call emits the options row at the start of the first
    /// frame; an empty first call therefore still yields one options-only
    /// frame (a valid empty patch). Frames hold at most `rows_per_frame`
    /// operation rows plus the lookup entry rows they need.
    ///
    /// # Errors
    ///
    /// Returns [`JellyError::Frame`] for operation-order violations
    /// (nested transactions, commit or abort without an open transaction,
    /// a header after a statement or transaction operation, an empty
    /// header key); [`JellyError::Quad`] when a batch is not a valid
    /// `UnsignedQuadStream` batch; and [`JellyError::Unsupported`] when a
    /// batch carries source provenance while `allow_provenance_loss` is
    /// `false`. Returns [`JellyError::ResourceLimit`] when a lookup table is
    /// too small to hold every distinct value a single statement or header
    /// row needs, for the same reason as the RDF stream encoder: the entry
    /// rows precede the row that references them, so reassigning an
    /// identifier within one row would silently rewrite a term.
    ///
    /// An encoder that has returned an error must not be reused; the patch
    /// it was producing is incomplete.
    pub fn encode_ops(&mut self, ops: &[PatchOp]) -> Result<Vec<RdfPatchFrame>, JellyError> {
        let mut frames = Vec::new();
        let mut rows: Vec<RdfPatchRow> = Vec::new();
        if !self.options_emitted {
            rows.push(RdfPatchRow {
                row: Some(rdf_patch_row::Row::Options(self.patch_options())),
            });
            self.options_emitted = true;
        }
        let mut entries: Vec<LookupEntry> = Vec::new();
        let mut rows_in_frame = 0usize;
        for op in ops {
            match op {
                PatchOp::Header { key, value } => {
                    if self.statements_encoded {
                        return Err(JellyError::Frame(
                            "header rows must occur at the start of the patch, before any \
                             statement or transaction row"
                                .into(),
                        ));
                    }
                    if key.is_empty() {
                        return Err(JellyError::Frame(
                            "patch header key must not be empty (the field is required)".into(),
                        ));
                    }
                    // Header values never use the id-0 IRI delta on encode;
                    // see the module docs for the interop rationale. A header
                    // is its own lookup-identifier generation: it is one wire
                    // row, so an identifier it uses must not be reassigned
                    // within it.
                    self.terms.begin_row();
                    let value = match value {
                        Term::NamedNode(node) => rdf_patch_header::Value::HIri(
                            self.terms.encode_iri(node.as_str(), false, &mut entries)?,
                        ),
                        Term::BlankNode(node) => {
                            rdf_patch_header::Value::HBnode(node.as_str().to_owned())
                        }
                        Term::Literal(literal) => rdf_patch_header::Value::HLiteral(
                            self.terms.encode_literal(literal.as_ref(), &mut entries)?,
                        ),
                        Term::Triple(triple) => {
                            if !self.options.rdf_star {
                                return Err(JellyError::Unsupported {
                                    feature: "rdf_star",
                                    detail: format!(
                                        "patch header `{key}` carries an RDF 1.2 triple term; set \
                                         rdf_star on the encoder options to announce and emit \
                                         RDF-star content"
                                    ),
                                });
                            }
                            check_depth(value.as_ref(), self.options.max_quoted_depth)?;
                            rdf_patch_header::Value::HTripleTerm(self.terms.encode_triple_term(
                                triple.as_ref().as_ref(),
                                false,
                                &mut entries,
                            )?)
                        }
                    };
                    rows.extend(entries.drain(..).map(entry_row));
                    rows.push(RdfPatchRow {
                        row: Some(rdf_patch_row::Row::Header(RdfPatchHeader {
                            key: key.clone(),
                            value: Some(value),
                        })),
                    });
                    count_row(
                        self.options.rows_per_frame,
                        &mut rows_in_frame,
                        &mut rows,
                        &mut frames,
                    );
                }
                PatchOp::TransactionStart => {
                    if self.in_transaction {
                        return Err(JellyError::Frame(
                            "transaction start inside an open transaction (transactions cannot \
                             nest)"
                                .into(),
                        ));
                    }
                    self.in_transaction = true;
                    self.statements_encoded = true;
                    rows.push(RdfPatchRow {
                        row: Some(rdf_patch_row::Row::TransactionStart(
                            RdfPatchTransactionStart {},
                        )),
                    });
                    count_row(
                        self.options.rows_per_frame,
                        &mut rows_in_frame,
                        &mut rows,
                        &mut frames,
                    );
                }
                PatchOp::TransactionCommit | PatchOp::TransactionAbort => {
                    if !self.in_transaction {
                        let kind = if matches!(op, PatchOp::TransactionCommit) {
                            "commit"
                        } else {
                            "abort"
                        };
                        return Err(JellyError::Frame(format!(
                            "transaction {kind} without an open transaction"
                        )));
                    }
                    self.in_transaction = false;
                    self.statements_encoded = true;
                    let row = if matches!(op, PatchOp::TransactionCommit) {
                        rdf_patch_row::Row::TransactionCommit(RdfPatchTransactionCommit {})
                    } else {
                        rdf_patch_row::Row::TransactionAbort(RdfPatchTransactionAbort {})
                    };
                    rows.push(RdfPatchRow { row: Some(row) });
                    count_row(
                        self.options.rows_per_frame,
                        &mut rows_in_frame,
                        &mut rows,
                        &mut frames,
                    );
                }
                PatchOp::Add(batch) | PatchOp::Delete(batch) => {
                    self.statements_encoded = true;
                    let is_add = matches!(op, PatchOp::Add(_));
                    let reader = QuadStreamReader::new(batch)?;
                    // Zero-copy unless the batch actually carries a triple
                    // term; see the RDF stream encoder for the same split.
                    let has_triple_terms = reader.contains_triple_terms();
                    for row_index in 0..reader.len() {
                        check_provenance_loss(
                            &reader,
                            row_index,
                            self.options.allow_provenance_loss,
                        )?;
                        let quad_row = if has_triple_terms {
                            let quad = read_owned_quad(
                                &reader,
                                row_index,
                                self.options.rdf_star,
                                self.options.max_quoted_depth,
                            )?;
                            self.terms.encode_quad(quad.as_ref(), &mut entries)?
                        } else {
                            self.terms
                                .encode_quad(reader.quad(row_index)?, &mut entries)?
                        };
                        rows.extend(entries.drain(..).map(entry_row));
                        let row = if is_add {
                            rdf_patch_row::Row::StatementAdd(quad_row)
                        } else {
                            rdf_patch_row::Row::StatementDelete(quad_row)
                        };
                        rows.push(RdfPatchRow { row: Some(row) });
                        count_row(
                            self.options.rows_per_frame,
                            &mut rows_in_frame,
                            &mut rows,
                            &mut frames,
                        );
                    }
                }
            }
        }
        if !rows.is_empty() {
            frames.push(RdfPatchFrame { rows });
        }
        Ok(frames)
    }

    /// Validates that the encoded patch stream can end here.
    ///
    /// # Errors
    ///
    /// Returns [`JellyError::Frame`] when a transaction is still open; a
    /// patch must not end mid-transaction, and failing closed here beats
    /// shipping a torn patch.
    pub fn finish(&self) -> Result<(), JellyError> {
        if self.in_transaction {
            return Err(JellyError::Frame(
                "patch stream ended with an open transaction".into(),
            ));
        }
        Ok(())
    }

    /// Returns the options row content this encoder announces.
    fn patch_options(&self) -> RdfPatchOptions {
        RdfPatchOptions {
            statement_type: PatchStatementType::Quads.into(),
            stream_type: PatchStreamType::Flat.into(),
            generalized_statements: false,
            rdf_star: self.options.rdf_star,
            max_name_table_size: self.options.max_name_table_size,
            max_prefix_table_size: self.options.max_prefix_table_size,
            max_datatype_table_size: self.options.max_datatype_table_size,
            version: PATCH_PROTOCOL_VERSION,
        }
    }
}
