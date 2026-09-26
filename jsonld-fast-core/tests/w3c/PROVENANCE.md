# W3C JSON-LD 1.1 API fixtures

Curated, inline-context subset of the W3C JSON-LD 1.1 API test suite,
transcribed for this codec. The processor performs **no network I/O**, so
remote-context and `@import` tests from the upstream suite are represented
here by a single refusal fixture rather than fetched inputs.

- Upstream: <https://github.com/w3c/json-ld-api/tree/main/tests>
- Framing suite (not vendored in this slice): <https://github.com/w3c/json-ld-framing/tree/main/tests>
- License: [W3C Test Suite License](https://www.w3.org/Consortium/Legal/2008/04-testsuite-license)
- Processing mode: JSON-LD 1.1 only (`json-ld-1.0` tests are omitted)
- Last transcribed: 2026-09-01

Each `manifest.json` entry names the upstream test class it corresponds to.
Inputs were chosen because they exercise algorithms this processor
implements (prefix/`@vocab` expansion, `@type: @id` coercion, language
tags, `@graph`, `@list`, compaction, flattening) without remote IRIs.
