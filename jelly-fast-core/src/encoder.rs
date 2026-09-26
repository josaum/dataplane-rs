// Rust guideline compliant 2026-02-21
//! Encoding of `UnsignedQuadStream` batches into Jelly stream frames.

use arrow_array::RecordBatch;
use quad_fast_core::{DEFAULT_MAX_QUOTED_DEPTH, QuadLimits, QuadStreamReader};

use crate::{
    error::JellyError,
    proto::{
        LogicalStreamType, PhysicalStreamType, RdfStreamFrame, RdfStreamOptions, RdfStreamRow,
        rdf_stream_row,
    },
    terms::{LookupEntry, TermEncoder},
};

/// Protocol version emitted in stream options.
///
/// This codec implements the Jelly 1.1.x feature set (serialization spec
/// 1.1.1), for which the options `version` field must be 2. All emitted
/// rows are also valid Jelly 1.0.x rows, so 1.0.x consumers reject the
/// stream only on the version check, never on row content.
pub const PROTOCOL_VERSION: u32 = 2;

/// Smallest name table size the Jelly specification allows.
///
/// `RdfStreamOptions.max_name_table_size` is required to be at least 8.
pub const SPEC_MIN_NAME_TABLE_SIZE: u32 = 8;

/// Default maximum prefix lookup table size: 128 entries.
///
/// Matches the "small" preset conventions of upstream Jelly
/// implementations; prefixes are low-cardinality in typical corpora.
pub const DEFAULT_MAX_PREFIX_TABLE_SIZE: u32 = 128;

/// Default maximum name lookup table size: 4000 entries.
///
/// Matches the default of upstream Jelly implementations; names dominate
/// table traffic, so this table is the largest.
pub const DEFAULT_MAX_NAME_TABLE_SIZE: u32 = 4000;

/// Default maximum datatype lookup table size: 32 entries.
///
/// Real-world corpora use few distinct datatypes; 32 covers the XSD set
/// with room for custom datatypes.
pub const DEFAULT_MAX_DATATYPE_TABLE_SIZE: u32 = 32;

/// Default quad statement rows per emitted frame: 8192.
///
/// Keeps a frame of typical quads well under common gRPC message-size
/// ceilings while amortizing per-frame overhead.
pub const DEFAULT_QUADS_PER_FRAME: usize = 8192;

/// Fail-closed configuration for [`JellyEncoder`].
#[derive(Clone, Debug)]
pub struct JellyEncoderOptions {
    /// Optional stream name emitted in the options row.
    ///
    /// Pub/sub transports use this as the topic name.
    pub stream_name: Option<String>,
    /// Maximum prefix lookup table size (must be at least 1).
    pub max_prefix_table_size: u32,
    /// Maximum name lookup table size (must be at least 8 per the spec).
    pub max_name_table_size: u32,
    /// Maximum datatype lookup table size (must be at least 1).
    pub max_datatype_table_size: u32,
    /// Maximum quad statement rows per emitted frame (must be at least 1).
    pub quads_per_frame: usize,
    /// Permit encoding batches that carry per-quad source provenance.
    ///
    /// Jelly 1.1.1 has no per-quad provenance fields, so provenance cannot
    /// survive this codec. With the default `false`, the encoder fails
    /// closed on any non-null provenance column instead of dropping data
    /// silently; set `true` only when the caller knowingly accepts the
    /// loss.
    pub allow_provenance_loss: bool,
    /// Announce and emit RDF 1.2 triple terms (`RdfStreamOptions.rdf_star`).
    ///
    /// Default `false`, which keeps the emitted options row and every
    /// statement row byte-identical to the pre-RDF-star encoder. With it
    /// unset, a batch carrying a triple term is refused
    /// ([`JellyError::Unsupported`], feature `rdf_star`) instead of being
    /// written into a stream whose own options row denies RDF-star content.
    pub rdf_star: bool,
    /// Maximum triple-term nesting depth read out of a batch.
    ///
    /// Bounds the recursive encoder; a batch nesting deeper fails closed
    /// with a `quoted_depth` resource limit from [`quad_fast_core`].
    pub max_quoted_depth: usize,
}

impl Default for JellyEncoderOptions {
    fn default() -> Self {
        Self {
            stream_name: None,
            max_prefix_table_size: DEFAULT_MAX_PREFIX_TABLE_SIZE,
            max_name_table_size: DEFAULT_MAX_NAME_TABLE_SIZE,
            max_datatype_table_size: DEFAULT_MAX_DATATYPE_TABLE_SIZE,
            quads_per_frame: DEFAULT_QUADS_PER_FRAME,
            allow_provenance_loss: false,
            rdf_star: false,
            max_quoted_depth: DEFAULT_MAX_QUOTED_DEPTH,
        }
    }
}

/// Reads one row as an owned quad under the encoder's triple-term policy.
///
/// Shared by both Jelly encoders. Rows without a triple term decode exactly
/// as the borrowed path does; a triple-term row is refused unless the caller
/// opted into RDF-star, so a stream never contradicts its own options row.
pub(crate) fn read_owned_quad(
    reader: &QuadStreamReader<'_>,
    row_index: usize,
    rdf_star: bool,
    max_quoted_depth: usize,
) -> Result<oxrdf::Quad, JellyError> {
    let limits = QuadLimits {
        max_quoted_depth,
        ..QuadLimits::default()
    };
    let quad = reader.quad_owned(row_index, limits)?;
    if !rdf_star && matches!(quad.object, oxrdf::Term::Triple(_)) {
        return Err(JellyError::Unsupported {
            feature: "rdf_star",
            detail: format!(
                "batch row {row_index} carries an RDF 1.2 triple term; set rdf_star on the \
                 encoder options to announce and emit RDF-star content"
            ),
        });
    }
    Ok(quad)
}

/// Validates common lookup table sizing rules shared by both encoders.
///
/// The name table minimum comes from the vendored schemas (both
/// `RdfStreamOptions` and `RdfPatchOptions` require at least 8); prefix
/// and datatype tables must hold at least one entry because these encoders
/// always use them.
pub(crate) fn validate_encoder_table_sizes(
    max_prefix_table_size: u32,
    max_name_table_size: u32,
    max_datatype_table_size: u32,
) -> Result<(), JellyError> {
    if max_name_table_size < SPEC_MIN_NAME_TABLE_SIZE {
        return Err(JellyError::Options(format!(
            "max_name_table_size {max_name_table_size} is below the spec minimum \
             {SPEC_MIN_NAME_TABLE_SIZE}"
        )));
    }
    if max_prefix_table_size == 0 {
        return Err(JellyError::Options(
            "max_prefix_table_size must be at least 1 (this encoder always uses the prefix lookup)"
                .into(),
        ));
    }
    if max_datatype_table_size == 0 {
        return Err(JellyError::Options(
            "max_datatype_table_size must be at least 1".into(),
        ));
    }
    Ok(())
}

/// Checks a reader row for provenance the wire format cannot carry.
///
/// Neither Jelly 1.1.1 nor the vendored Jelly-Patch schema has per-quad
/// provenance fields, so both encoders refuse batches that carry
/// provenance unless the caller explicitly accepts the loss.
pub(crate) fn check_provenance_loss(
    reader: &QuadStreamReader<'_>,
    row_index: usize,
    allow_provenance_loss: bool,
) -> Result<(), JellyError> {
    if allow_provenance_loss {
        return Ok(());
    }
    let provenance = reader.provenance(row_index);
    let has_provenance = provenance.source_artifact_iri.is_some()
        || provenance.source_content_sha256.is_some()
        || provenance.source_offset_start.is_some()
        || provenance.source_offset_end.is_some()
        || provenance.observed_at_micros.is_some();
    if has_provenance {
        return Err(JellyError::Unsupported {
            feature: "provenance",
            detail: format!(
                "batch row {row_index} carries source provenance, which the Jelly wire formats \
                 cannot represent; set allow_provenance_loss to encode anyway"
            ),
        });
    }
    Ok(())
}

/// Encodes `UnsignedQuadStream` batches into Jelly QUADS stream frames.
///
/// One encoder instance produces exactly one logical Jelly stream: the
/// first frame starts with the options row, lookup table state persists
/// across batches, and repeated-term elision spans batch boundaries.
/// Output is unsigned by construction (Atlas product invariant 7): frames
/// carry RDF data and lookup state, never assurance.
///
/// # Examples
///
/// ```
/// use jelly_fast_core::{JellyEncoder, JellyEncoderOptions};
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
/// let mut encoder = JellyEncoder::new(JellyEncoderOptions::default())?;
/// let frames = encoder.encode_batch(&batch)?;
/// assert_eq!(frames.len(), 1);
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct JellyEncoder {
    options: JellyEncoderOptions,
    terms: TermEncoder,
    options_emitted: bool,
}

/// Wraps a lookup entry into an RDF stream row.
fn entry_row(entry: LookupEntry) -> RdfStreamRow {
    let row = match entry {
        LookupEntry::Prefix(entry) => rdf_stream_row::Row::Prefix(entry),
        LookupEntry::Name(entry) => rdf_stream_row::Row::Name(entry),
        LookupEntry::Datatype(entry) => rdf_stream_row::Row::Datatype(entry),
    };
    RdfStreamRow { row: Some(row) }
}

impl JellyEncoder {
    /// Creates an encoder for one Jelly stream governed by `options`.
    ///
    /// # Errors
    ///
    /// Returns [`JellyError::Options`] when a table size is below its
    /// minimum (name below 8 per the spec, prefix or datatype below 1) or
    /// `quads_per_frame` is zero.
    pub fn new(options: JellyEncoderOptions) -> Result<Self, JellyError> {
        validate_encoder_table_sizes(
            options.max_prefix_table_size,
            options.max_name_table_size,
            options.max_datatype_table_size,
        )?;
        if options.quads_per_frame == 0 {
            return Err(JellyError::Options(
                "quads_per_frame must be at least 1".into(),
            ));
        }
        Ok(Self {
            terms: TermEncoder::new(
                options.max_prefix_table_size,
                options.max_name_table_size,
                options.max_datatype_table_size,
            ),
            options_emitted: false,
            options,
        })
    }

    /// Encodes one batch into zero or more Jelly stream frames.
    ///
    /// The first call emits the options row at the start of the first
    /// frame; an empty first batch therefore still yields one options-only
    /// frame so the stream stays valid. Frames hold at most
    /// `quads_per_frame` quad rows plus the lookup entry rows they need.
    ///
    /// # Errors
    ///
    /// Returns [`JellyError::Quad`] when `batch` is not a valid
    /// `UnsignedQuadStream` batch and [`JellyError::Unsupported`] when the
    /// batch carries source provenance while `allow_provenance_loss` is
    /// `false` (Jelly cannot represent per-quad provenance; refusing beats
    /// dropping it silently) or carries an RDF 1.2 triple term while
    /// `rdf_star` is `false`. Returns [`JellyError::ResourceLimit`] when a
    /// lookup table is too small to hold every distinct value a single quad
    /// needs — every entry row for a quad precedes that quad on the wire, so
    /// reassigning an identifier the quad already used would silently
    /// rewrite one of its terms.
    ///
    /// An encoder that has returned an error must not be reused: the stream
    /// it was producing is incomplete and its lookup state is mid-quad.
    pub fn encode_batch(&mut self, batch: &RecordBatch) -> Result<Vec<RdfStreamFrame>, JellyError> {
        let reader = QuadStreamReader::new(batch)?;
        let mut frames = Vec::new();
        let mut rows: Vec<RdfStreamRow> = Vec::new();
        if !self.options_emitted {
            rows.push(RdfStreamRow {
                row: Some(rdf_stream_row::Row::Options(self.stream_options())),
            });
            self.options_emitted = true;
        }
        let mut entries = Vec::new();
        let mut quads_in_frame = 0usize;
        // Batches without triple terms keep the zero-copy read path; only a
        // batch that actually carries one pays for materializing quads.
        let has_triple_terms = reader.contains_triple_terms();
        for row_index in 0..reader.len() {
            check_provenance_loss(&reader, row_index, self.options.allow_provenance_loss)?;
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
            rows.push(RdfStreamRow {
                row: Some(rdf_stream_row::Row::Quad(quad_row)),
            });
            quads_in_frame += 1;
            if quads_in_frame == self.options.quads_per_frame {
                frames.push(RdfStreamFrame {
                    rows: std::mem::take(&mut rows),
                    metadata: std::collections::HashMap::new(),
                });
                quads_in_frame = 0;
            }
        }
        if !rows.is_empty() {
            frames.push(RdfStreamFrame {
                rows,
                metadata: std::collections::HashMap::new(),
            });
        }
        Ok(frames)
    }

    /// Returns the options row content this encoder announces.
    fn stream_options(&self) -> RdfStreamOptions {
        RdfStreamOptions {
            stream_name: self.options.stream_name.clone().unwrap_or_default(),
            physical_type: PhysicalStreamType::Quads.into(),
            generalized_statements: false,
            rdf_star: self.options.rdf_star,
            max_name_table_size: self.options.max_name_table_size,
            max_prefix_table_size: self.options.max_prefix_table_size,
            max_datatype_table_size: self.options.max_datatype_table_size,
            logical_type: LogicalStreamType::FlatQuads.into(),
            version: PROTOCOL_VERSION,
        }
    }
}
