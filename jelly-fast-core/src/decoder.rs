// Rust guideline compliant 2026-02-21
//! Fail-closed decoding of Jelly stream frames into quad batches.

use arrow_array::RecordBatch;
use quad_fast_core::{QuadBatchBuilder, QuadLimits};

use crate::{
    encoder::SPEC_MIN_NAME_TABLE_SIZE,
    error::{JellyError, JellyResource},
    proto::{PhysicalStreamType, RdfStreamFrame, RdfStreamOptions, rdf_stream_row},
    terms::TermDecoder,
};

/// Fail-closed configuration for [`JellyDecoder`].
///
/// All limits are explicit: the decoder rejects streams that declare
/// lookup tables larger than the configured maxima before allocating
/// anything, and every produced batch is governed by `quad_limits`.
#[derive(Clone, Debug)]
pub struct JellyDecoderOptions {
    /// Largest prefix lookup table this decoder accepts.
    pub max_prefix_table_size: u32,
    /// Largest name lookup table this decoder accepts.
    pub max_name_table_size: u32,
    /// Largest datatype lookup table this decoder accepts.
    pub max_datatype_table_size: u32,
    /// Limits applied to every batch built from a frame.
    pub quad_limits: QuadLimits,
}

impl Default for JellyDecoderOptions {
    fn default() -> Self {
        Self {
            max_prefix_table_size: crate::encoder::DEFAULT_MAX_PREFIX_TABLE_SIZE,
            max_name_table_size: crate::encoder::DEFAULT_MAX_NAME_TABLE_SIZE,
            max_datatype_table_size: crate::encoder::DEFAULT_MAX_DATATYPE_TABLE_SIZE,
            quad_limits: QuadLimits::default(),
        }
    }
}

/// Validates declared lookup table sizes against configured maxima.
///
/// Shared by the RDF stream decoder and the patch decoder: both fail
/// closed with [`JellyError::ResourceLimit`] before allocating any table
/// storage when a stream declares more than the decoder accepts.
pub(crate) fn check_declared_table_sizes(
    declared: [(JellyResource, u32); 3],
    limits: [u32; 3],
) -> Result<(), JellyError> {
    for ((resource, declared), limit) in declared.into_iter().zip(limits) {
        if declared > limit {
            return Err(JellyError::ResourceLimit {
                resource,
                limit,
                observed: declared,
            });
        }
    }
    Ok(())
}

/// Decodes Jelly QUADS stream frames into `UnsignedQuadStream` batches.
///
/// One decoder instance consumes exactly one logical Jelly stream: the
/// options row must arrive before any other row, and lookup table plus
/// repeated-term state persists across frames. Every produced batch is
/// unsigned by construction; decoding never attaches or promotes
/// assurance.
///
/// The decoder fails closed. It returns typed errors — never silently
/// skipping rows — for: rows before the options row, duplicated options,
/// unknown protocol versions, generalized-statement content, triple terms
/// in a subject or predicate position (RDF 1.2 admits them only as
/// objects) or on a stream that did not announce `rdf_star`, triple terms
/// nested deeper than `quad_limits.max_quoted_depth`, TRIPLES/GRAPHS
/// physical stream types, namespace declaration rows, lookup identifier
/// misses, and declared table sizes above the configured maxima.
///
/// RDF 1.2 triple terms in the object position **are** decoded, into
/// `object_kind = "triple"` rows of the quad contract.
///
/// # Examples
///
/// ```
/// use jelly_fast_core::{
///     JellyDecoder, JellyDecoderOptions, JellyEncoder, JellyEncoderOptions,
/// };
/// use quad_fast_core::{QuadBatchBuilder, QuadLimits};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let batch = QuadBatchBuilder::new(QuadLimits::default()).finish()?;
/// let mut encoder = JellyEncoder::new(JellyEncoderOptions::default())?;
/// let frames = encoder.encode_batch(&batch)?;
///
/// let mut decoder = JellyDecoder::new(JellyDecoderOptions::default());
/// let decoded = decoder.decode_frame(&frames[0])?;
/// assert_eq!(decoded.num_rows(), 0);
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct JellyDecoder {
    options: JellyDecoderOptions,
    stream: Option<TermDecoder>,
    /// Set by the first error; every later frame fails closed.
    failed: bool,
}

/// Message of the error every frame gets after the decoder has failed.
const POISONED: &str = "stream decoder failed on an earlier frame; its lookup table and \
                        repeated-term state are undefined, so it refuses every later frame";

impl JellyDecoder {
    /// Creates a decoder for one Jelly stream governed by `options`.
    #[must_use]
    pub fn new(options: JellyDecoderOptions) -> Self {
        Self {
            options,
            stream: None,
            failed: false,
        }
    }

    /// Decodes one frame into one `UnsignedQuadStream` batch.
    ///
    /// The first frame must start with the stream options row. Frames that
    /// carry only non-statement rows produce an empty (zero-row) batch.
    ///
    /// # Errors
    ///
    /// Returns [`JellyError::Options`] for missing, duplicated, or invalid
    /// options; [`JellyError::Unsupported`] for protocol features this
    /// codec refuses (triple terms outside the object position,
    /// generalized statements, TRIPLES/GRAPHS physical types, namespace
    /// declarations, unknown versions);
    /// [`JellyError::ResourceLimit`] when a declared table exceeds a
    /// configured maximum; [`JellyError::Lookup`], [`JellyError::Frame`],
    /// and [`JellyError::Term`] for malformed row content; and
    /// [`JellyError::Quad`] when batch construction hits a quad limit.
    ///
    /// After any error the decoder is poisoned: frame state is mutated in
    /// place without rollback, so every later call returns
    /// [`JellyError::Frame`] instead of decoding against half-applied
    /// lookup tables.
    pub fn decode_frame(&mut self, frame: &RdfStreamFrame) -> Result<RecordBatch, JellyError> {
        if self.failed {
            return Err(JellyError::Frame(POISONED.into()));
        }
        let result = self.decode_frame_unchecked(frame);
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    /// Decodes one frame, mutating stream state in place (no rollback).
    fn decode_frame_unchecked(
        &mut self,
        frame: &RdfStreamFrame,
    ) -> Result<RecordBatch, JellyError> {
        let mut builder = QuadBatchBuilder::new(self.options.quad_limits);
        for row in &frame.rows {
            let row = row
                .row
                .as_ref()
                .ok_or_else(|| JellyError::Frame("stream row without a payload".into()))?;
            match row {
                rdf_stream_row::Row::Options(options) => self.accept_options(options)?,
                rdf_stream_row::Row::Quad(quad) => {
                    let quad = self.stream_mut()?.decode_quad(quad)?;
                    builder.push(quad.as_ref(), None)?;
                }
                rdf_stream_row::Row::Name(entry) => {
                    self.stream_mut()?
                        .assign_name(entry.id, entry.value.clone())?;
                }
                rdf_stream_row::Row::Prefix(entry) => {
                    self.stream_mut()?
                        .assign_prefix(entry.id, entry.value.clone())?;
                }
                rdf_stream_row::Row::Datatype(entry) => {
                    self.stream_mut()?
                        .assign_datatype(entry.id, entry.value.clone())?;
                }
                rdf_stream_row::Row::Triple(_) => {
                    // Ensure the ordering error wins when options are absent.
                    let _ = self.stream_mut()?;
                    return Err(JellyError::Frame(
                        "triple row is not valid in a QUADS stream".into(),
                    ));
                }
                rdf_stream_row::Row::GraphStart(_) | rdf_stream_row::Row::GraphEnd(_) => {
                    let _ = self.stream_mut()?;
                    return Err(JellyError::Frame(
                        "graph boundary rows are only valid in a GRAPHS stream".into(),
                    ));
                }
                rdf_stream_row::Row::Namespace(declaration) => {
                    return Err(JellyError::Unsupported {
                        feature: "namespace_declaration",
                        detail: format!(
                            "namespace declaration `{}` cannot be represented in the quad \
                             contract and will not be dropped silently",
                            declaration.name
                        ),
                    });
                }
            }
        }
        Ok(builder.finish()?)
    }

    /// Returns the stream state, failing when options have not arrived.
    fn stream_mut(&mut self) -> Result<&mut TermDecoder, JellyError> {
        self.stream.as_mut().ok_or_else(|| {
            JellyError::Options("stream options row must precede all other rows".into())
        })
    }

    /// Validates the options row and initializes stream state.
    fn accept_options(&mut self, options: &RdfStreamOptions) -> Result<(), JellyError> {
        if self.stream.is_some() {
            return Err(JellyError::Options("duplicate stream options row".into()));
        }
        match options.version {
            1 | 2 => {}
            0 => {
                return Err(JellyError::Options(
                    "stream options version is 0 (the field is required)".into(),
                ));
            }
            other => {
                return Err(JellyError::Unsupported {
                    feature: "version",
                    detail: format!("protocol version {other} is not supported (expected 1 or 2)"),
                });
            }
        }
        match PhysicalStreamType::try_from(options.physical_type) {
            Ok(PhysicalStreamType::Quads) => {}
            Ok(PhysicalStreamType::Triples) => {
                return Err(JellyError::Unsupported {
                    feature: "physical_type_triples",
                    detail: "this decoder consumes QUADS streams only; TRIPLES streams are not \
                             mapped to the default graph implicitly"
                        .into(),
                });
            }
            Ok(PhysicalStreamType::Graphs) => {
                return Err(JellyError::Unsupported {
                    feature: "physical_type_graphs",
                    detail: "GRAPHS physical stream type is not supported by this QUADS \
                             decoder"
                        .into(),
                });
            }
            Ok(PhysicalStreamType::Unspecified) | Err(_) => {
                return Err(JellyError::Options(format!(
                    "physical stream type {} is unspecified or unknown",
                    options.physical_type
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
        // `rdf_star` is carried into the term decoder rather than refused:
        // triple terms in the object position are supported (RDF 1.2), and a
        // triple term arriving on a stream that did not announce RDF-star is
        // refused there.
        self.stream = Some(TermDecoder::new(
            options.max_prefix_table_size,
            options.max_name_table_size,
            options.max_datatype_table_size,
            options.rdf_star,
            self.options.quad_limits.max_quoted_depth,
        ));
        Ok(())
    }
}
