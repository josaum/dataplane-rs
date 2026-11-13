#!/usr/bin/env python3
"""Prove that a consumer ships exactly one release of dataplane-rs.

A consumer vendors this repository in two forms that must agree:

* the wheels and ``release-manifest.json`` (what Python installs), and
* the source at the manifest's ``source.commit`` (what its Rust crates link),
  normally a git submodule.

This check fails when any of the following is true:

1. a vendored wheel is not named by the manifest, or the manifest names a
   wheel that is not vendored;
2. a vendored wheel's SHA-256 differs from the manifest's;
3. the pinned source commit differs from the manifest's ``source.commit``;
4. the manifest records a dirty source tree.

It is standard library only: a provenance check that needs a dependency is a
provenance check with an unverified dependency.

Usage (from the consumer's checkout)::

    python3 vendor/dataplane-rs/src/scripts/verify_consumer_pin.py \
        --vendor vendor/dataplane-rs [--source vendor/dataplane-rs/src]

``--source`` defaults to ``<vendor>/src``. Pass ``--no-source`` for a consumer
that installs wheels only and links no Rust crate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

MANIFEST_NAME = "release-manifest.json"
SCHEMA = "dataplane-rs.release.v1"


@dataclass
class Report:
    failures: list[str] = field(default_factory=list)
    checked_wheels: int = 0
    source_commit: str | None = None
    pinned_commit: str | None = None

    def fail(self, message: str) -> None:
        self.failures.append(message)

    @property
    def ok(self) -> bool:
        return not self.failures


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def pinned_commit(source: Path) -> str:
    """The commit the consumer's source pin resolves to.

    For a submodule this is the checked-out HEAD of the submodule; for a plain
    checkout it is that checkout's HEAD. Either way it is what the consumer's
    Rust crates actually compile.
    """
    out = subprocess.run(
        ["git", "-C", str(source), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    )
    return out.stdout.strip()


def verify(vendor: Path, source: Path | None) -> Report:
    report = Report()
    manifest_path = vendor / MANIFEST_NAME
    if not manifest_path.is_file():
        report.fail(f"missing {manifest_path}")
        return report

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema_version") != SCHEMA:
        report.fail(
            f"manifest schema is {manifest.get('schema_version')!r}, expected {SCHEMA!r}"
        )

    source_info = manifest.get("source", {})
    report.source_commit = source_info.get("commit")
    if not report.source_commit:
        report.fail("manifest names no source commit")
    if source_info.get("dirty"):
        report.fail("manifest records a dirty source tree; that is not a release")

    declared = {a["file"]: a for a in manifest.get("artifacts", [])}
    declared_wheels = {k: v for k, v in declared.items() if k.endswith(".whl")}
    declared_tarballs = {k: v for k, v in declared.items() if k.endswith(".tgz")}

    present_wheels = {p.name: p for p in vendor.glob("*.whl")}
    present_tarballs = {p.name: p for p in vendor.glob("*.tgz")}
    present = {**present_wheels, **present_tarballs}

    for name in sorted(present.keys() - declared.keys()):
        report.fail(f"vendored artifact not named by the manifest: {name}")

    if present_wheels or (not present_tarballs):
        for name in sorted(declared_wheels.keys() - present_wheels.keys()):
            report.fail(f"manifest names a wheel that is not vendored: {name}")

    if present_tarballs:
        for name in sorted(declared_tarballs.keys() - present_tarballs.keys()):
            report.fail(f"manifest names a tarball that is not vendored: {name}")

    for name in sorted(declared.keys() & present.keys()):
        expected = declared[name]["sha256"]
        actual = sha256_of(present[name])
        report.checked_wheels += 1
        if actual != expected:
            report.fail(
                f"{name}: sha256 {actual[:16]}… does not match manifest {expected[:16]}…"
            )
        expected_bytes = declared[name].get("bytes")
        if expected_bytes is not None and present[name].stat().st_size != expected_bytes:
            report.fail(f"{name}: size differs from manifest")

    if source is not None:
        if not (source / "Cargo.toml").is_file():
            report.fail(
                f"source pin {source} is not a checkout (no Cargo.toml); "
                "run `git submodule update --init` or pass --no-source"
            )
        else:
            try:
                report.pinned_commit = pinned_commit(source)
            except (subprocess.CalledProcessError, FileNotFoundError) as exc:
                report.fail(f"cannot resolve the source pin at {source}: {exc}")
            if (
                report.pinned_commit
                and report.source_commit
                and report.pinned_commit != report.source_commit
            ):
                report.fail(
                    "source pin and wheels disagree: source is at "
                    f"{report.pinned_commit[:12]}, wheels were built from "
                    f"{report.source_commit[:12]}"
                )
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--vendor", required=True, type=Path, help="directory holding the wheels and release-manifest.json")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--source", type=Path, help="pinned source checkout (default: <vendor>/src)")
    group.add_argument("--no-source", action="store_true", help="consumer links no Rust crate; check wheels only")
    args = parser.parse_args(argv)

    source: Path | None
    if args.no_source:
        source = None
    else:
        source = args.source if args.source is not None else args.vendor / "src"

    report = verify(args.vendor, source)
    if report.ok:
        pin = f", source pinned at {report.pinned_commit[:12]}" if report.pinned_commit else ""
        print(
            f"ok: {report.checked_wheels} wheel(s) match release "
            f"{(report.source_commit or '?')[:12]}{pin}"
        )
        return 0
    for failure in report.failures:
        print(f"FAIL: {failure}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
