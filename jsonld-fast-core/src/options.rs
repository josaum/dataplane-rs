// Rust guideline compliant 2026-02-21
//! Fail-closed processing limits and processor options.

use quad_fast_core::QuadLimits;

/// Default maximum raw input bytes: 64 MiB.
///
/// Matches `quad_fast_core::DEFAULT_MAX_RETAINED_TERM_BYTES` so the JSON-LD
/// plane fails closed at the same scale as the quad plane. Raising it also
/// raises peak memory roughly proportionally (the document tree is held in
/// memory during expansion).
pub const DEFAULT_MAX_INPUT_BYTES: usize = 64 * 1024 * 1024;

/// Default maximum JSON values visited during expansion.
///
/// Matches `quad_fast_core::DEFAULT_MAX_QUADS` so a maximally dense document
/// cannot out-produce a single quad batch by orders of magnitude.
pub const DEFAULT_MAX_NODES: usize = 1_048_576;

/// Default maximum expansion nesting depth.
///
/// Matches `serde_json`'s own default recursion limit of 128, so documents
/// that parse are also expandable; deeper nesting would risk stack overflow
/// in recursive expansion.
pub const DEFAULT_MAX_DEPTH: usize = 128;

/// Maximum native recursion depth of context processing: 32.
///
/// Two chains of the Context Processing and Create Term Definition
/// algorithms recurse on the *contents* of a context rather than on
/// document nesting, so [`JsonLdLimits::max_depth`] cannot see them:
///
/// - a scoped context validated while a term is defined (JSON-LD 1.1 API
///   section 4.2.2 step 21.2), and
/// - a term definition created to resolve another term's prefix (section
///   4.2.2 step 14, via IRI expansion) — `{"a": "b:x", "b": "c:x", ...}`
///   is **flat** JSON of arbitrary chain length. Terms of one local context
///   are now defined dependencies-first with an explicit stack, so such a
///   chain no longer recurses; the bound still covers dependencies the
///   ordering does not see.
///
/// Both are refused past this depth with
/// [`crate::JsonLdError::ResourceLimit`] and
/// [`crate::JsonLdResource::ContextRecursion`]. The bound is a constant,
/// not a caller-tunable limit, because it governs the native stack rather
/// than payload size: raising it cannot be made safe by the caller. Real
/// contexts nest a prefix one or two levels deep, so 32 is far above any
/// legitimate document and far below the depth at which an unoptimized
/// build runs out of stack.
pub const MAX_CONTEXT_RECURSION: usize = 32;

/// Maximum nesting of embedded nodes in one framing run: 2,048.
///
/// Framing embeds a referenced node inside the node that references it, so
/// a flat `@graph` of chained nodes frames as deep as the chain is long; no
/// document-nesting budget sees that. Deeper embedding is refused with
/// [`crate::JsonLdError::ResourceLimit`] and
/// [`crate::JsonLdResource::EmbedDepth`]. 2,048 keeps a ring of a thousand
/// `@once`-embedded nodes (the framing benchmark) working while bounding
/// the worker stack below. Like [`MAX_CONTEXT_RECURSION`] it is a constant,
/// not a caller-tunable limit, because it sizes native stack.
pub const MAX_FRAME_EMBED_DEPTH: usize = 2_048;

/// Native stack reserved per embed level on the framing worker: 128 KiB.
///
/// Framing plus the compaction of its output measured about 25 KiB per
/// embed level in an unoptimized build; 128 KiB leaves a five-fold margin.
/// The worker reserves [`MAX_FRAME_EMBED_DEPTH`] times this plus
/// [`FRAME_WORKER_BASE_STACK`] (about 257 MiB of address space, committed
/// only as the recursion actually touches it).
pub(crate) const FRAME_STACK_PER_EMBED_LEVEL: usize = 128 * 1024;

/// Fixed native stack of the framing worker, for the non-recursive frames.
pub(crate) const FRAME_WORKER_BASE_STACK: usize = 1024 * 1024;

/// Output bytes allowed per byte of input when no explicit
/// [`JsonLdLimits::max_output_bytes`] is set: 16.
///
/// Only produced strings are charged (keys, IRIs, values), not
/// punctuation, so legitimate output is about the size of the input or a
/// small multiple of it when short terms become long IRIs. Measured: the
/// 26 W3C fixtures that expand need at most 0.8 charged bytes per byte of
/// input text, and the benchmark documents (up to 1,024 nodes) fit inside
/// [`OUTPUT_BYTES_FLOOR`] alone. 16 leaves a wide margin for documents
/// built from very short terms. A term mapped to a 1 MiB IRI and used 128
/// times is 128 times its input and is refused.
pub const OUTPUT_BYTES_PER_INPUT_BYTE: usize = 16;

/// Output bytes always allowed regardless of input size: 16 MiB.
///
/// Small documents legitimately expand by more than
/// [`OUTPUT_BYTES_PER_INPUT_BYTE`] (a one-letter term becomes a 30-byte
/// IRI); the floor keeps every such document well inside the budget.
pub const OUTPUT_BYTES_FLOOR: usize = 16 * 1024 * 1024;

/// Fail-closed limits for one JSON-LD processing run.
#[derive(Clone, Copy, Debug)]
pub struct JsonLdLimits {
    /// Maximum raw UTF-8 input bytes accepted by [`crate::parse_document`].
    pub max_input_bytes: usize,
    /// Maximum JSON values (objects, arrays, scalars) visited in expansion.
    pub max_nodes: usize,
    /// Maximum nesting depth reached during expansion.
    pub max_depth: usize,
    /// Maximum bytes of strings expansion may produce (expanded keys and
    /// IRIs, `@vocab`/`@base` resolutions, and copied values).
    ///
    /// `None` (the default) derives the budget from the input:
    /// [`OUTPUT_BYTES_PER_INPUT_BYTE`] times its estimated serialized size,
    /// plus [`OUTPUT_BYTES_FLOOR`]. `Some(bytes)` sets it outright.
    pub max_output_bytes: Option<usize>,
}

impl JsonLdLimits {
    /// The output budget for an input of about `input_bytes` bytes.
    #[must_use]
    pub fn output_budget(&self, input_bytes: usize) -> usize {
        self.max_output_bytes.unwrap_or_else(|| {
            input_bytes
                .saturating_mul(OUTPUT_BYTES_PER_INPUT_BYTE)
                .saturating_add(OUTPUT_BYTES_FLOOR)
        })
    }
}

impl Default for JsonLdLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: DEFAULT_MAX_INPUT_BYTES,
            max_nodes: DEFAULT_MAX_NODES,
            max_depth: DEFAULT_MAX_DEPTH,
            max_output_bytes: None,
        }
    }
}

/// Options for expansion, compaction, framing, and RDF deserialization.
#[derive(Clone, Debug)]
pub struct JsonLdOptions {
    /// Base IRI used to resolve relative IRI references (`@base` overrides).
    pub base: Option<String>,
    /// Fail-closed JSON-LD processing limits.
    pub limits: JsonLdLimits,
    /// Fail-closed limits for the produced quad batch.
    pub quad_limits: QuadLimits,
    /// The `compactArrays` API option (JSON-LD 1.1 API section 6.1):
    /// when `true` (the default), single-element arrays whose term has no
    /// `@set`/`@list` container compact to their only element.
    pub compact_arrays: bool,
}

impl Default for JsonLdOptions {
    fn default() -> Self {
        Self {
            base: None,
            limits: JsonLdLimits::default(),
            quad_limits: QuadLimits::default(),
            compact_arrays: true,
        }
    }
}
