/**
 * quad-fast-node: Node bindings for the UnsignedQuadStream v1 Arrow contract
 * and the Jelly RDF frame codec.
 *
 * All output is unsigned by construction; the Arrow schema carries
 * `dataplane.assurance = "unsigned"` and nothing in this binding attaches or
 * upgrades assurance. Every function is fail-closed: malformed input and
 * unknown option keys throw typed errors whose message starts with a stable
 * machine-readable code (`input:`, `resource_limit:`, `precision:`,
 * `frame_decode:`, `unsupported:`, ...).
 */

/** An IRI or blank-node term. */
export interface SubjectTerm {
  kind: 'iri' | 'bnode';
  value: string;
}

/**
 * An object-position term. `datatype` and `language` are only legal when
 * `kind` is `'literal'` and are mutually exclusive. Simple literals are
 * stored with an explicit `xsd:string` datatype by the contract, so decoded
 * quads always name the datatype.
 */
export interface ObjectTerm {
  kind: 'iri' | 'bnode' | 'literal';
  value: string;
  datatype?: string;
  language?: string;
}

/** A graph name; omit the whole object (or use `'default'`) for the default graph. */
export interface GraphTerm {
  kind: 'default' | 'iri' | 'bnode';
  value?: string;
}

/**
 * Source provenance carried, never certified: attaching it does not sign
 * the quad. Offsets and timestamps are confined to Number.MAX_SAFE_INTEGER;
 * decoding a stored value beyond it throws a `precision:` error instead of
 * rounding silently.
 */
export interface QuadProvenance {
  sourceArtifactIri?: string;
  /** SHA-256 of the exact source bytes as 64 hex characters. */
  sourceContentSha256?: string;
  sourceOffsetStart?: number;
  sourceOffsetEnd?: number;
  observedAtMicros?: number;
}

/** One RDF quad in the JS shape shared by every function in this binding. */
export interface QuadObject {
  subject: SubjectTerm;
  /** Predicate IRI. */
  predicate: string;
  object: ObjectTerm;
  graph?: GraphTerm;
  provenance?: QuadProvenance;
}

/** Fail-closed budgets for building or reading Arrow IPC quad streams. */
export interface IpcOptions {
  /** Maximum quads per batch on build; cumulative decoded-quad budget on read. */
  maxQuads?: number;
  /** Maximum aggregate bytes retained by term lexical forms. */
  maxRetainedTermBytes?: number;
  /** Maximum encoded (build) or accepted (read) IPC payload bytes. */
  maxIpcBytes?: number;
}

/** Fail-closed options for encoding Jelly stream frames. */
export interface JellyEncodeOptions {
  maxQuads?: number;
  maxRetainedTermBytes?: number;
  /** Optional stream name emitted in the options row (pub/sub topic). */
  streamName?: string;
  maxPrefixTableSize?: number;
  /** Must be at least 8 per the Jelly spec. */
  maxNameTableSize?: number;
  maxDatatypeTableSize?: number;
  quadsPerFrame?: number;
  /**
   * Jelly 1.1.1 has no per-quad provenance fields. Without this flag, quads
   * carrying provenance are refused (`unsupported:`) rather than silently
   * stripped; set it only when the loss is knowingly accepted.
   */
  allowProvenanceLoss?: boolean;
}

/** Fail-closed options for decoding Jelly stream frames. */
export interface JellyDecodeOptions {
  /** Per-frame and cumulative decoded-quad budget. */
  maxQuads?: number;
  maxRetainedTermBytes?: number;
  maxPrefixTableSize?: number;
  maxNameTableSize?: number;
  maxDatatypeTableSize?: number;
  /** Maximum accepted payload bytes. */
  maxInputBytes?: number;
  /** Maximum length-delimited frames per payload. */
  maxFrames?: number;
}

/** Crate / binding version string. */
export declare function version(): string;

/**
 * Builds one UnsignedQuadStream batch from quad objects and returns it as
 * Arrow IPC stream bytes (schema metadata: `dataplane.assurance = "unsigned"`).
 */
export declare function quadsToIpc(quads: QuadObject[], options?: IpcOptions): Buffer;

/** Decodes Arrow IPC stream bytes of contract batches into quad objects. */
export declare function ipcToQuads(ipc: Buffer, options?: IpcOptions): QuadObject[];

/**
 * Builds one contract batch from quad objects and encodes it as
 * length-delimited Jelly stream frames (QUADS physical type, version 2).
 */
export declare function quadsToJellyFrames(
  quads: QuadObject[],
  options?: JellyEncodeOptions
): Buffer;

/**
 * Decodes length-delimited Jelly stream frames into quad objects. The whole
 * payload is one logical Jelly stream: the first frame must open with the
 * options row. Decoded quads never carry provenance (the wire format has
 * none).
 */
export declare function jellyFramesToQuads(
  frames: Buffer,
  options?: JellyDecodeOptions
): QuadObject[];
