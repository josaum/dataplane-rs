# SPDX-License-Identifier: MIT
"""Python smoke test for the quad_fast extension module.

This file is NOT part of the cargo gate (cargo ignores .py files in
``tests/``). Run it against a built extension module:

    cd quad-fast-py
    uv sync && uv run maturin develop   # or: pip install maturin && maturin develop
    uv run pytest tests/                # or: pytest tests/

It only smoke-tests the Python object adapter; the conversion logic itself
is covered interpreter-free by the Rust unit tests in ``src/tests.rs``.
"""

from __future__ import annotations

import pytest

quad_fast = pytest.importorskip("quad_fast")

XSD_STRING = "http://www.w3.org/2001/XMLSchema#string"

QUADS = [
    (("iri", "http://example.com/s"), "http://example.com/p", ("iri", "http://example.com/o", None, None)),
    (
        ("bnode", "b0"),
        "http://example.com/p",
        ("literal", "hallo", None, "de-DE"),
        ("iri", "http://example.com/g"),
    ),
    (
        ("iri", "http://example.com/s"),
        "http://example.com/p",
        ("literal", "plain", None, None),
        None,
        {
            "source_artifact_iri": "http://example.com/artifact",
            "source_content_sha256": bytes(32),
            "source_offset_start": 0,
            "source_offset_end": 7,
            "observed_at_micros": 1_756_684_800_000_000,
        },
    ),
]


def test_ipc_round_trip() -> None:
    payload = quad_fast.build_quad_ipc(QUADS)
    quads = quad_fast.read_quad_ipc(payload)
    assert len(quads) == 3
    subject, predicate, obj, graph, provenance = quads[0]
    assert subject == ("iri", "http://example.com/s")
    assert predicate == "http://example.com/p"
    assert obj == ("iri", "http://example.com/o", None, None)
    assert graph is None
    assert provenance is None
    # Language-tagged literal: datatype slot stays None, tag lowercases.
    assert quads[1][2] == ("literal", "hallo", None, "de-de")
    assert quads[1][3] == ("iri", "http://example.com/g")
    # Simple literal normalizes to an explicit xsd:string datatype.
    assert quads[2][2] == ("literal", "plain", XSD_STRING, None)
    assert quads[2][4]["source_artifact_iri"] == "http://example.com/artifact"
    assert quads[2][4]["source_content_sha256"] == bytes(32)


def test_jelly_round_trip() -> None:
    payload = quad_fast.build_quad_ipc(QUADS[:2])
    frames = quad_fast.jelly_encode(payload)
    assert frames and all(isinstance(frame, bytes) for frame in frames)
    decoded = quad_fast.read_quad_ipc(quad_fast.jelly_decode(frames))
    assert [quad[:4] for quad in decoded] == [
        (("iri", "http://example.com/s"), "http://example.com/p", ("iri", "http://example.com/o", None, None), None),
        (
            ("bnode", "b0"),
            "http://example.com/p",
            ("literal", "hallo", None, "de-de"),
            ("iri", "http://example.com/g"),
        ),
    ]


def test_jelly_encode_fails_closed_on_provenance() -> None:
    payload = quad_fast.build_quad_ipc(QUADS)
    with pytest.raises(ValueError):
        quad_fast.jelly_encode(payload)
    frames = quad_fast.jelly_encode(payload, allow_provenance_loss=True)
    decoded = quad_fast.read_quad_ipc(quad_fast.jelly_decode(frames))
    assert all(quad[4] is None for quad in decoded)


def test_resource_limits_raise_typed_error() -> None:
    with pytest.raises(quad_fast.QuadResourceError):
        quad_fast.build_quad_ipc(QUADS, max_quads=1)


def test_unknown_provenance_key_raises_value_error() -> None:
    quad = (
        ("iri", "http://example.com/s"),
        "http://example.com/p",
        ("iri", "http://example.com/o", None, None),
        None,
        {"bogus": 1},
    )
    with pytest.raises(ValueError, match="provenance_key"):
        quad_fast.build_quad_ipc([quad])
    with pytest.raises(ValueError, match="provenance_key"):
        quad_fast.build_quad_ipc([quad[:4] + ({1: "non-string key"},)])
    with pytest.raises(ValueError, match="provenance_sha256_length"):
        quad_fast.build_quad_ipc([quad[:4] + ({"source_content_sha256": b"short"},)])


def test_malformed_input_raises_value_error() -> None:
    with pytest.raises(ValueError):
        quad_fast.build_quad_ipc([(("iri", "not an iri"), "http://example.com/p", ("iri", "http://example.com/o", None, None))])
    with pytest.raises(ValueError):
        quad_fast.build_quad_ipc(["not a quad"])
    with pytest.raises(ValueError):
        quad_fast.read_quad_ipc(b"not arrow ipc")
    with pytest.raises(ValueError):
        quad_fast.jelly_decode([b"not a frame"])


def test_jsonld_to_quad_ipc_decodes_with_provenance() -> None:
    document = (
        '{"@context": {"id": "@id",'
        ' "named_graph": {"@id": "urn:dataplane:namedGraph", "@type": "@id"}},'
        ' "id": "urn:uuid:00000000-0000-4000-8000-000000000000",'
        ' "named_graph": "urn:dataplane:graph:events:v1"}'
    )
    payload = quad_fast.jsonld_to_quad_ipc(
        document, provenance={"source_artifact_iri": "urn:dataplane:test:artifact"}
    )
    quads = quad_fast.read_quad_ipc(payload)
    subject, predicate, obj, graph, provenance = quads[0]
    assert subject == ("iri", "urn:uuid:00000000-0000-4000-8000-000000000000")
    assert predicate == "urn:dataplane:namedGraph"
    assert obj == ("iri", "urn:dataplane:graph:events:v1", None, None)
    assert graph is None
    assert provenance is not None
    assert provenance["source_artifact_iri"] == "urn:dataplane:test:artifact"


def test_jsonld_to_quad_ipc_refuses_remote_context() -> None:
    with pytest.raises(ValueError, match="remote_context_refused"):
        quad_fast.jsonld_to_quad_ipc(
            '{"@context": "https://schema.org/", "@id": "http://example.com/it"}'
        )
