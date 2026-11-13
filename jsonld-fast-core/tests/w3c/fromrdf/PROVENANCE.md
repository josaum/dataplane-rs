# W3C JSON-LD 1.1 API `fromRdf` list fixtures

The 18 list-related tests of the W3C JSON-LD 1.1 API `fromRdf` suite
(`fromRdf/manifest.jsonld`: 0001, 0004, 0005, 0009–0016, 0020–0023, 0026,
li01, li02). Upstream inputs are N-Quads; each `NNNN-in.json` here is that
input transcribed as a flat expanded JSON-LD `@graph` (one node per quad
group), so `to_quads` reproduces the upstream quads exactly. Each
`NNNN-out.json` is the upstream expected output, unchanged.

- Upstream: <https://github.com/w3c/json-ld-api/tree/main/tests/fromRdf>
- License: [W3C Test Suite License](https://www.w3.org/Consortium/Legal/2008/04-testsuite-license),
  dual-licensed under the W3C 3-clause BSD License, as for the parent
  `tests/w3c` fixtures.
- Transcribed: 2026-11-13.

`tests/w3c_fromrdf_tests.rs` pins the tests this processor currently
passes so none can regress; the others are reported, not asserted.
