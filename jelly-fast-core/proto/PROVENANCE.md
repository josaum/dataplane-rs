# Vendored Jelly protobuf schemas

Source: https://github.com/Jelly-RDF/jelly-protobuf
Commit: d1d3088274be36d761617a1228a83d5b697831d6 (main, committed 2026-08-18T09:50:22Z)
Retrieved: 2026-08-31 via raw.githubusercontent.com

Files:
- `rdf.proto` — Jelly RDF serialization, protocol version 1.1.1
- `grpc.proto` — Jelly gRPC streaming protocol, version 1.0.0
- `patch.proto` — Jelly RDF patch protocol, version 1.0.x (consumed by the
  `patch` codec module; task graph N7)

License: upstream Jelly protobuf is Apache-2.0. Do not edit these files by
hand; re-vendor from a pinned upstream commit and update this record.

## Dataplane-authored files (NOT vendored)

- `dataplane_patch_grpc.proto` — the dataplane's own patch pub/sub service
  surface (`dataplane.jelly.patch.v1`), written in this repository.
  The vendored `patch.proto` defines no gRPC service and its options carry
  no topic name, so this file declares one, modeled on the vendored
  `grpc.proto` `RdfStreamService` shape. It claims no wire
  interoperability with any upstream Jelly-Patch gRPC protocol and is MIT
  licensed with the rest of the crate.
