#!/usr/bin/env python3
"""Embed each crate's CycloneDX SBOM inside its wheel.

A wheel that ships without its SBOM makes a consumer guess what went into the
artifact. The bill of materials travels with the bytes it describes.

Placement follows the convention:
``<distribution>.dist-info/sboms/<crate>.cyclonedx.json``.

Wheels are rebuilt in place, so run this before generating the release manifest
— injecting changes the archive and therefore its SHA-256.

Usage:
    python3 scripts/inject_sbom.py [--dist dist]
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import json
import shutil
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

#: Wheel distribution name -> the crate whose SBOM belongs in it.
SBOM_SOURCES: dict[str, str] = {
    "quad_fast": "quad-fast-core",
}


def crate_sbom(crate: str) -> Path:
    """Locate the crate's SBOM."""

    candidate = ROOT / crate / f"{crate}.cdx.json"
    return candidate


def distribution_name(archive: zipfile.ZipFile) -> str:
    metadata = next(
        name for name in archive.namelist() if name.endswith(".dist-info/METADATA")
    )
    for line in archive.read(metadata).decode("utf-8").splitlines():
        if line.startswith("Name: "):
            return line[6:].strip()
    raise SystemExit("wheel carries no Name in METADATA")


def inject(wheel: Path, sbom: Path) -> bool:
    """Rewrite the wheel with the SBOM added. Returns False if already present."""

    with zipfile.ZipFile(wheel) as archive:
        distribution = distribution_name(archive)
        crate = SBOM_SOURCES.get(distribution.replace("-", "_"))
        if crate is None:
            raise SystemExit(f"{wheel.name}: no crate maps to {distribution!r}")

        # dist-info keeps the dashed distribution name as published.
        info = next(
            name.split("/")[0]
            for name in archive.namelist()
            if name.endswith(".dist-info/METADATA")
        )
        member = f"{info}/sboms/{crate}.cyclonedx.json"
        payload = sbom.read_bytes()
        # A malformed SBOM must not be shipped as if it were valid.
        json.loads(payload)

        original_entries = {name: archive.read(name) for name in archive.namelist()}
        entries = {
            name: blob
            for name, blob in original_entries.items()
            if "/sboms/" not in name
        }

    entries[member] = payload
    record = f"{info}/RECORD"
    rows = [
        (
            name,
            "sha256="
            + base64.urlsafe_b64encode(hashlib.sha256(blob).digest())
            .rstrip(b"=")
            .decode("ascii"),
            str(len(blob)),
        )
        for name, blob in sorted(entries.items())
        if name != record
    ]
    rows.append((record, "", ""))
    output = io.StringIO(newline="")
    csv.writer(output, lineterminator="\n").writerows(rows)
    entries[record] = output.getvalue().encode("utf-8")
    if entries == original_entries:
        return False

    with tempfile.NamedTemporaryFile(
        dir=wheel.parent, suffix=".whl", delete=False
    ) as handle:
        temporary = Path(handle.name)

    with zipfile.ZipFile(temporary, "w", zipfile.ZIP_DEFLATED) as out:
        for name, blob in sorted(entries.items()):
            # Deterministic timestamps, matching the bundle packer's convention.
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            out.writestr(info, blob)

    shutil.move(str(temporary), wheel)
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist", default="dist")
    arguments = parser.parse_args(argv)

    dist = (ROOT / arguments.dist).resolve()
    wheels = sorted(dist.glob("*.whl"))
    if not wheels:
        raise SystemExit(f"no wheels in {dist}; build them first")

    failures: list[str] = []
    for wheel in wheels:
        with zipfile.ZipFile(wheel) as archive:
            distribution = distribution_name(archive)
        crate = SBOM_SOURCES.get(distribution.replace("-", "_"))
        if crate is None:
            failures.append(f"{wheel.name}: unmapped distribution {distribution!r}")
            continue
        sbom = crate_sbom(crate)
        if not sbom.is_file():
            failures.append(
                f"{wheel.name}: no SBOM at {sbom.relative_to(ROOT)}; run "
                f"`cargo cyclonedx --manifest-path {crate}/Cargo.toml -f json`"
            )
            continue
        changed = inject(wheel, sbom)
        print(
            f"  {'injected' if changed else 'already present'}: {wheel.name} <- {sbom.name}"
        )

    if failures:
        for failure in failures:
            print(f"  {failure}")
        raise SystemExit("SBOM injection incomplete")

    # The archive changed, so any hash recorded earlier is now stale.
    for name in ("release-manifest.json", "SHA256SUMS"):
        stamp = dist / name
        if stamp.is_file():
            stamp.unlink()
            print(f"  removed {name}; regenerate it after this step")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
