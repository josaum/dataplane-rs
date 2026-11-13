# W3C JSON-LD 1.1 API `fromRdf` list fixtures

The 18 list-related tests of the W3C JSON-LD 1.1 API `fromRdf` suite
(`fromRdf/manifest.jsonld`: 0001, 0004, 0005, 0009–0016, 0020–0023, 0026,
li01, li02). Upstream inputs are N-Quads; each `NNNN-in.json` here is that
input as converted (during review) to a flat expanded JSON-LD `@graph`, so
that `to_quads` can feed it to `from_quads`. Each `NNNN-out.json` is the
upstream expected output as provided by that conversion. Neither set has
been re-diffed against upstream since.

- Upstream: <https://github.com/w3c/json-ld-api/tree/main/tests/fromRdf>
- License: upstream `LICENSE.md` states that all documents in the
  repository are licensed under the
  [W3C Software and Document License](https://www.w3.org/copyright/software-license-2023/),
  which permits copying, modification, and redistribution provided this
  notice and a link to the license are kept.
- Copyright © World Wide Web Consortium (W3C®) and the JSON-LD
  contributors.
- Converted: 2026-11-13.

`tests/w3c_fromrdf_tests.rs` pins the tests this processor currently
passes so none can regress; the others are reported, not asserted.
