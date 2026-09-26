"""UnsignedQuadStream v1 quad batches and Jelly frames from Python.

Thin, typed veneer over the ``quad_fast._native`` extension module (built
with maturin from the ``quad-fast-py`` Rust crate). All payloads are bytes:
Arrow IPC streams carrying ``UnsignedQuadStream`` v1 batches, and
non-delimited protobuf-encoded Jelly ``RdfStreamFrame`` messages.

Quads are plain tuples:

- quad in: ``(subject, predicate, object)``, optionally with a fourth
  ``graph`` element and a fifth ``provenance`` element
- quad out: always ``(subject, predicate, object, graph, provenance)``
- ``subject`` / ``graph``: ``(kind, value)`` with kind ``"iri"`` or
  ``"bnode"``; ``graph`` is ``None`` for the default graph
- ``object``: ``(kind, value, datatype, language)`` with kind ``"iri"``,
  ``"bnode"``, or ``"literal"``; simple literals come back normalized with
  an explicit ``http://www.w3.org/2001/XMLSchema#string`` datatype, and
  language-tagged literals come back with ``datatype=None`` and a
  lowercase language tag (RDF 1.1 tags are case-insensitive)
- ``provenance``: dict with keys ``source_artifact_iri``,
  ``source_content_sha256`` (32 bytes), ``source_offset_start``,
  ``source_offset_end``, ``observed_at_micros``, or ``None``

Everything is fail-closed: exceeded resource budgets raise
:class:`QuadResourceError`, every other malformed input raises
``ValueError`` whose message starts with a stable machine-readable code.
Output is unsigned by construction and never carries or promotes assurance.
"""

from __future__ import annotations

from typing import Any, Optional, Sequence, Tuple

from quad_fast import _native

QuadResourceError = _native.QuadResourceError

Subject = Tuple[str, str]
ObjectTerm = Tuple[str, str, Optional[str], Optional[str]]
Graph = Optional[Tuple[str, str]]
Provenance = Optional[dict]
QuadOut = Tuple[Subject, str, ObjectTerm, Graph, Provenance]


def build_quad_ipc(
    quads: Sequence[Any],
    *,
    max_quads: int | None = None,
    max_retained_term_bytes: int | None = None,
    max_ipc_bytes: int | None = None,
) -> bytes:
    """Build one ``UnsignedQuadStream`` v1 batch as Arrow IPC stream bytes."""
    return _native.build_quad_ipc(
        quads,
        max_quads=max_quads,
        max_retained_term_bytes=max_retained_term_bytes,
        max_ipc_bytes=max_ipc_bytes,
    )


def read_quad_ipc(data: bytes) -> list[QuadOut]:
    """Decode ``UnsignedQuadStream`` Arrow IPC bytes into quad tuples."""
    return _native.read_quad_ipc(data)


def jsonld_to_quad_ipc(
    text: str,
    *,
    provenance: Provenance = None,
    max_input_bytes: int | None = None,
    max_nodes: int | None = None,
    max_depth: int | None = None,
    max_quads: int | None = None,
    max_retained_term_bytes: int | None = None,
    max_ipc_bytes: int | None = None,
) -> bytes:
    """Decode one inline-context JSON-LD document into IPC quad bytes.

    Remote contexts and ``@import`` are refused by name, never fetched;
    IRIs that stay relative after expansion are refused rather than
    dropped. Each call is one JSON-LD document — blank node labels restart
    per call, so a JSONL log must be projected one batch per line, never
    merged. Provenance, when given, rides every row of the batch.
    """
    return _native.jsonld_to_quad_ipc(
        text,
        provenance=provenance,
        max_input_bytes=max_input_bytes,
        max_nodes=max_nodes,
        max_depth=max_depth,
        max_quads=max_quads,
        max_retained_term_bytes=max_retained_term_bytes,
        max_ipc_bytes=max_ipc_bytes,
    )


def jelly_encode(
    data: bytes,
    *,
    stream_name: str | None = None,
    max_prefix_table_size: int | None = None,
    max_name_table_size: int | None = None,
    max_datatype_table_size: int | None = None,
    quads_per_frame: int | None = None,
    allow_provenance_loss: bool = False,
) -> list[bytes]:
    """Encode an IPC quad stream as protobuf-encoded Jelly frames.

    Jelly 1.1.1 has no per-quad provenance fields; encoding a payload that
    carries provenance fails closed unless ``allow_provenance_loss`` is set.
    """
    return _native.jelly_encode(
        data,
        stream_name=stream_name,
        max_prefix_table_size=max_prefix_table_size,
        max_name_table_size=max_name_table_size,
        max_datatype_table_size=max_datatype_table_size,
        quads_per_frame=quads_per_frame,
        allow_provenance_loss=allow_provenance_loss,
    )


def jelly_decode(
    frames: Sequence[bytes],
    *,
    max_prefix_table_size: int | None = None,
    max_name_table_size: int | None = None,
    max_datatype_table_size: int | None = None,
    max_quads: int | None = None,
    max_retained_term_bytes: int | None = None,
    max_ipc_bytes: int | None = None,
) -> bytes:
    """Decode one logical Jelly stream (frames in order) into IPC bytes.

    ``max_quads`` and ``max_retained_term_bytes`` govern each frame's batch
    individually, not the stream total. Decoded batches always carry null
    provenance.
    """
    return _native.jelly_decode(
        frames,
        max_prefix_table_size=max_prefix_table_size,
        max_name_table_size=max_name_table_size,
        max_datatype_table_size=max_datatype_table_size,
        max_quads=max_quads,
        max_retained_term_bytes=max_retained_term_bytes,
        max_ipc_bytes=max_ipc_bytes,
    )


__all__ = [
    "Graph",
    "ObjectTerm",
    "Provenance",
    "QuadOut",
    "QuadResourceError",
    "Subject",
    "build_quad_ipc",
    "jelly_decode",
    "jelly_encode",
    "jsonld_to_quad_ipc",
    "read_quad_ipc",
]
