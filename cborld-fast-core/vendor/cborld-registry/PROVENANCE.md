# Vendored CBOR-LD registry entries

Source: https://github.com/json-ld/cborld-registry
Commit: c7ece75bae6ef40c23e19ce111b5c51f3cf38950 (main, committed
2026-07-30T17:23:45Z, "Add entry 31000001: California DMV Disabled Person
Parking Placards.")
Retrieved: 2026-09-01 via raw.githubusercontent.com, pinned to the commit
above. The `tables/` listing at that commit was cross-checked through the
GitHub contents API: it holds exactly the nine files below, and their upstream
byte sizes match the vendored copies.

License: the registry repository states that all documents in it are licensed
by contributors under the [W3C Document
License](https://www.w3.org/Consortium/Legal/copyright-documents). The upstream
`LICENSE.md` is vendored verbatim beside the tables. The crate's own MIT
license covers the Rust code, not these documents.

Do not edit these files by hand. Re-vendor from a pinned upstream commit,
re-run `generate_tables.py`, and update this record.

## Files

Each `tables/<id>.yml` is one CBOR-LD Registry Entry: a use case (`domain`),
registration contacts (`contact`), a processing model (`mode`), a
`provisional` flag, and — for every entry except 0 and 1 — a
`compressionTable` holding **typed sub-tables**. A registry entry identifier
therefore does *not* name a single context IRI: it selects an entire set of
sub-tables, each keyed by a table type (`context`, `url`, or a JSON-LD type
IRI) and each mapping small integers to values of that type.

| File | sha256 | Entry | Provisional | Sub-tables |
| --- | --- | --- | --- | --- |
| `LICENSE.md` | `7a3ad7d36b8855bc301276279769da4aff648ea5d7b92f3f023c0823ee948764` | — | — | upstream license text |
| `tables/0.yml` | `206a1f8defad12a7a94cad570880335eae4f7793ae290472efbe8d9df8683459` | Uncompressed CBOR-LD | no | none |
| `tables/1.yml` | `366a0d1d23b758da6a220c5731a3243c30ee37aa611c6b6d70fa8f8a93d62048` | Compressed CBOR-LD | no | none |
| `tables/100.yml` | `d2f00684e16e2dc903c025ece1c1817520c0972b8a92647738c06587c08c0013` | Verifiable Credential Barcodes Examples | yes | `context` (3), `…#cryptosuiteString` (4) |
| `tables/10001.yml` | `dca0eaa274e6a81f754d1ee9fc472c1d4c3d56ad8a22de51e6a4904c8f97a041` | Provisional California DMV Test Credentials | yes | `context` (4), `…#cryptosuiteString` (1), `url` (3) |
| `tables/10002.yml` | `5085bf6c00486e303ca21a069157f5d6b7994d68e81e7ea33e8421b909c43142` | Provisional First Responder Credentials | yes | `context` (5), `…#cryptosuiteString` (1), `url` (3) |
| `tables/10003.yml` | `637580981b4f568c65ece79c9daf13044588256902715cb8dace75cfdbe2d562` | California Instant Identity credentials | yes | `context` (3), `…#cryptosuiteString` (1) |
| `tables/31000000.yml` | `fd85ee08ec2c8b7866d9cc1791cb9faef4475adabc5f438f6f10bdc98590af1b` | California DMV Physical Identification Documents | yes | `context` (2), `…#cryptosuiteString` (1), `url` (28) |
| `tables/31000001.yml` | `bc5b674a6faec8719e1c791c1c94893f795a9f7d0ab570f4498b49988897f9d5` | California DMV Disabled Person Parking Placards | yes | `context` (3), `…#cryptosuiteString` (1), `url` (28) |
| `tables/32000000.yml` | `ada09c7416ca50e4dd7c7e0876cdffa2b351ffec1b67d1e12c468f5b326d320e` | Utopia Demo Verifiable Credentials | yes | `context` (4), `…#cryptosuiteString` (2), `url` (3) |

Entries 0 and 1 are the reserved, non-provisional default modes owned by the
W3C JSON-LD Working Group and carry no compression table. **Every other entry
is marked `provisional: true`**, meaning upstream may change or remove it; see
the crate docs for the opt-in posture that follows from this.

## How the data reaches the codec

The `.yml` files above are the authoritative vendored artifact. They are
transcribed at vendor time into `src/registry_tables.rs` by
`generate_tables.py` (Python standard library only), followed by
`cargo fmt -p cborld-fast-core`; that pair is idempotent, so a re-vendor
diffs only where upstream actually changed. Two reasons for transcribing
rather than parsing at runtime:

1. The house rule forbids new external dependencies, and the shipped codec is
   fail-closed — a generated `const` cannot fail to parse at startup, whereas
   an in-crate YAML parser is a runtime failure mode with no upside.
2. `tests/registry_tables.rs` re-parses these same `.yml` files with an
   independent, test-only parser and asserts the generated constants match,
   entry for entry and row for row, so the transcription cannot drift
   silently from the vendored bytes.

`contact` is deliberately not transcribed: it is registration metadata, not
wire format. Nothing else in the files is dropped.

## Field naming note

The registry YAML spells the processing model `mode`, while CBOR-LD 1.0
§"Expressing a Processing Model" calls the registry-entry member
`processingModel` (absent meaning the default model). All nine vendored
entries carry `mode: default`. The Rust transcription keeps the registry's
`mode` spelling verbatim, and the codec refuses any entry whose `mode` is not
`default`, since its algorithms implement only that model.

## Not vendored from here

The generic codec constants (CBOR tag, keyword table, URL prefix table,
`typesEncodedAsBytes`, multibase headers) come from the CBOR-LD 1.0
specification, `w3c/cbor-ld` at commit
`9e1bea64a3b81c6b98a19c6374ea527e6e28a955`; they are recorded in
`src/registry.rs`, not here.

The legacy `digitalbazaar/cborld` flat `STRING_TABLE` is a **different,
incompatible** compression model (per-value codec identifiers in one flat
table). It is deliberately not vendored and must not be blended with these
entries.
