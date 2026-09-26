#!/usr/bin/env python3
"""Publish a versioned, provenance-stamped release manifest of dataplane artifacts.

Binds for every artifact (.whl and .tgz):
* the artifact file name, its SHA-256, and its size,
* the crate and distribution version it reports,
* the exact source commit and whether the tree was dirty at build time,
* the Rust toolchain and target triple, and
* author identity verification ("Dionisio Chiuratto Agourakis").

Usage:
    python3 scripts/release_manifest.py --out dist [--allow-dirty]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import zipfile
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_NAME = "release-manifest.json"
SCHEMA_VERSION = "dataplane-rs.release.v1"

NODE_CRATES: set[str] = {
    "quad-fast-node",
}

CRATES: dict[str, str] = {
    "quad_fast": "quad-fast-py",
}


def run(argv: list[str], *, cwd: Path = ROOT) -> str:
    completed = subprocess.run(
        argv, cwd=cwd, text=True, capture_output=True, check=False
    )
    if completed.returncode != 0:
        raise SystemExit(f"command failed: {' '.join(argv)}\n{completed.stderr}")
    return completed.stdout.strip()


def source_commit() -> str:
    try:
        return run(["git", "rev-parse", "HEAD"])
    except SystemExit:
        return "unknown"


def source_is_dirty() -> bool:
    try:
        return bool(run(["git", "status", "--porcelain"]))
    except SystemExit:
        return True


def crate_version(crate: str) -> str:
    manifest = (ROOT / crate / "Cargo.toml").read_text(encoding="utf-8")
    match = re.search(r'^version = "([^"]+)"', manifest, flags=re.M)
    if match is None:
        raise SystemExit(f"{crate}/Cargo.toml declares no version")
    return match.group(1)


def wheel_distribution(path: Path) -> tuple[str, str, str | None]:
    with zipfile.ZipFile(path) as archive:
        metadata_name = next(
            name for name in archive.namelist() if name.endswith(".dist-info/METADATA")
        )
        metadata = archive.read(metadata_name).decode("utf-8")
    name = re.search(r"^Name: (.+)$", metadata, flags=re.M)
    version = re.search(r"^Version: (.+)$", metadata, flags=re.M)
    author = re.search(r"^Author(?:-email)?: (.+)$", metadata, flags=re.M)
    if name is None or version is None:
        raise SystemExit(f"{path.name} carries no Name/Version metadata")
    return name.group(1).strip(), version.group(1).strip(), (author.group(1).strip() if author else None)


def tarball_distribution(path: Path) -> tuple[str, str, str | None]:
    with tarfile.open(path, "r:gz") as archive:
        try:
            member = archive.getmember("package/package.json")
            f = archive.extractfile(member)
            if f is None:
                raise KeyError
            metadata = json.loads(f.read().decode("utf-8"))
        except KeyError:
            raise SystemExit(f"{path.name} carries no package/package.json")
        name = metadata.get("name")
        version = metadata.get("version")
        author = metadata.get("author")
        if not name or not version:
            raise SystemExit(f"{path.name} package.json is missing name/version")
        return name, version, author


def digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def cyclonedx_available() -> bool:
    return shutil.which("cargo-cyclonedx") is not None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default="dist", help="directory holding built wheels and tarballs")
    parser.add_argument(
        "--allow-dirty",
        action="store_true",
        help="record a dirty tree instead of refusing to publish it",
    )
    arguments = parser.parse_args()

    out = (ROOT / arguments.out).resolve()
    wheels = sorted(out.glob("*.whl"))
    tarballs = sorted(out.glob("*.tgz"))
    if not wheels and not tarballs:
        raise SystemExit(f"no artifacts in {out}; build them first")

    dirty = source_is_dirty()
    if dirty and not arguments.allow_dirty:
        raise SystemExit(
            "the working tree has uncommitted changes, so these artifacts cannot "
            "be reproduced from a commit. Commit first, or pass --allow-dirty to "
            "record the dirty state explicitly."
        )

    artifacts = []
    for artifact_path in wheels + tarballs:
        is_wheel = artifact_path.name.endswith(".whl")
        if is_wheel:
            distribution, version, author = wheel_distribution(artifact_path)
            key = distribution.replace("-", "_")
            crate = CRATES.get(key)
        else:
            distribution, version, author = tarball_distribution(artifact_path)
            crate = distribution
            if crate not in NODE_CRATES:
                crate = None

        if crate is None:
            raise SystemExit(f"{artifact_path.name}: no crate maps to distribution {distribution!r}")

        declared = crate_version(crate)
        if version != declared:
            raise SystemExit(
                f"{artifact_path.name} reports version {version} but {crate} declares "
                f"{declared}; a consumer pinning {version} would get other bytes"
            )
        if author and author.strip() != "Dionisio Chiuratto Agourakis":
            raise SystemExit(
                f"{artifact_path.name} is attributed to {author!r}. A shared artifact must "
                "name this repository, so a consumer can trace it back."
            )
        artifacts.append(
            {
                "distribution": distribution,
                "crate": crate,
                "version": version,
                "author": author,
                "file": artifact_path.name,
                "sha256": digest(artifact_path),
                "bytes": artifact_path.stat().st_size,
            }
        )

    manifest = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "source": {
            "commit": source_commit(),
            "dirty": dirty,
        },
        "build": {
            "rustc": run(["rustc", "--version"]),
            "cargo": run(["cargo", "--version"]),
            "target": run(["rustc", "-vV"]).split("host: ")[-1].splitlines()[0],
            "python_abi": "abi3-py38",
        },
        "artifacts": artifacts,
    }

    destination = out / MANIFEST_NAME
    destination.write_text(json.dumps(manifest, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    print(f"wrote {destination}")
    for artifact in artifacts:
        print(f"  {artifact['file']}  sha256={artifact['sha256'][:16]}…  {artifact['bytes']} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
