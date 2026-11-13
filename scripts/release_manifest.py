#!/usr/bin/env python3
"""Publish a versioned, provenance-stamped release manifest of dataplane artifacts.

Binds for every artifact (.whl and .tgz):
* the artifact file name, its SHA-256, and its size,
* the crate and distribution version it reports,
* the exact source commit and whether the tree was dirty at build time,
* the Rust toolchain and target triple,
* a CycloneDX SBOM when ``cargo-cyclonedx`` is installed, and
* author identity verification ("Dionisio Chiuratto Agourakis").

Usage:
    python3 scripts/release_manifest.py --out dist [--require-complete] [--allow-dirty]
"""

from __future__ import annotations

import argparse
import hashlib
import json
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
REPOSITORY = "https://github.com/fast-parser-inc/dataplane-rs"

NODE_CRATES: set[str] = {
    "quad-fast-node",
}

CRATES: dict[str, str] = {
    "quad_fast": "quad-fast-py",
}

TARGET_PLATFORMS = {
    "darwin-arm64": "aarch64-apple-darwin",
    "linux-x64-gnu": "x86_64-unknown-linux-gnu",
    "linux-arm64-gnu": "aarch64-unknown-linux-gnu",
    "win32-x64-msvc": "x86_64-pc-windows-msvc",
}

WHEEL_ONLY_TARGETS: dict[str, str] = {}


def validate_native_architecture(header: bytes, target: str, path: Path) -> None:
    actual = None
    if (
        len(header) >= 64
        and header[:7] == b"\x7fELF\x02\x01\x01"
        and int.from_bytes(header[16:18], "little") == 3
    ):
        actual = {
            62: "x86_64-unknown-linux-gnu",
            183: "aarch64-unknown-linux-gnu",
        }.get(int.from_bytes(header[18:20], "little"))
    elif (
        len(header) >= 32
        and header[:4] == b"\xcf\xfa\xed\xfe"
        and int.from_bytes(header[4:8], "little") == 0x0100000C
        and int.from_bytes(header[12:16], "little") in {6, 8}
    ):
        actual = "aarch64-apple-darwin"
    elif len(header) >= 64 and header[:2] == b"MZ":
        pe_offset = int.from_bytes(header[0x3C:0x40], "little")
        if 0 < pe_offset <= len(header) - 6 and header[pe_offset:pe_offset + 4] == b"PE\0\0":
            actual = {0x8664: "x86_64-pc-windows-msvc", 0xAA64: "aarch64-pc-windows-msvc"}.get(
                int.from_bytes(header[pe_offset + 4:pe_offset + 6], "little")
            )
    if actual != target:
        raise SystemExit(
            f"{path.name}: native architecture disagrees with declared target {target}"
        )


def artifact_target(path: Path) -> str:
    if path.suffix == ".tgz":
        for platform, target in TARGET_PLATFORMS.items():
            if path.name.endswith(f"-{platform}.tgz"):
                with tarfile.open(path, "r:gz") as archive:
                    binaries = [
                        member
                        for member in archive.getmembers()
                        if member.name.endswith(".node")
                    ]
                    if (
                        len(binaries) != 1
                        or not binaries[0].isfile()
                        or binaries[0].size == 0
                    ):
                        raise SystemExit(
                            f"{path.name}: expected exactly one nonempty regular Node binary"
                        )
                    with archive.extractfile(binaries[0]) as native:
                        validate_native_architecture(native.read(4096), target, path)
                return target
    else:
        with zipfile.ZipFile(path) as archive:
            members = [
                name for name in archive.namelist() if name.endswith(".dist-info/WHEEL")
            ]
            if len(members) != 1:
                raise SystemExit(
                    f"{path.name}: expected exactly one WHEEL metadata file"
                )
            tags = re.findall(
                r"^Tag: (.+)$",
                archive.read(members[0]).decode("utf-8"),
                flags=re.MULTILINE,
            )
        platforms = {
            platform for tag in tags for platform in tag.rsplit("-", 1)[-1].split(".")
        }
        filename_platform = path.stem.rsplit("-", 1)[-1]
        if platforms != set(filename_platform.split(".")):
            raise SystemExit(
                f"{path.name}: filename platform disagrees with WHEEL tags"
            )
        if all(
            re.fullmatch(r"macosx_\d+_\d+_arm64", platform) for platform in platforms
        ):
            target = TARGET_PLATFORMS["darwin-arm64"]
        elif all(
            re.fullmatch(r"manylinux(?:_\d+_\d+|\d+)_x86_64", platform)
            for platform in platforms
        ):
            target = TARGET_PLATFORMS["linux-x64-gnu"]
        elif all(
            re.fullmatch(r"manylinux(?:_\d+_\d+|\d+)_aarch64", platform)
            for platform in platforms
        ):
            target = TARGET_PLATFORMS["linux-arm64-gnu"]
        elif platforms == {"win_amd64"}:
            target = TARGET_PLATFORMS["win32-x64-msvc"]
        else:
            raise SystemExit(f"{path.name}: unsupported release platform")
        distribution = path.name.split("-", 1)[0]
        native_suffix = ".pyd" if target.endswith("windows-msvc") else ".so"
        with zipfile.ZipFile(path) as archive:
            binaries = [
                name
                for name in archive.namelist()
                if name.startswith(f"{distribution}/") and name.endswith(native_suffix)
            ]
            if len(binaries) != 1:
                raise SystemExit(
                    f"{path.name}: expected exactly one distribution native extension"
                )
            with archive.open(binaries[0]) as native:
                validate_native_architecture(native.read(4096), target, path)
        return target
    raise SystemExit(f"{path.name}: unsupported release platform")


def validate_release_matrix(artifacts: list[dict], *, complete: bool) -> None:
    actual = [(artifact["crate"], artifact["target"]) for artifact in artifacts]
    if len(actual) != len(set(actual)):
        raise SystemExit("duplicate crate/target artifacts in release")
    if complete:
        expected = {
            (crate, target)
            for crate in set(CRATES.values()) | NODE_CRATES
            for target in TARGET_PLATFORMS.values()
        } | {
            (crate, target)
            for crate in set(CRATES.values())
            for target in WHEEL_ONLY_TARGETS.values()
        }
        missing = sorted(expected - set(actual))
        if missing:
            raise SystemExit(f"incomplete release matrix: {missing}")
        if set(actual) - expected:
            raise SystemExit(
                "release matrix contains undeclared crate/target artifacts"
            )
        for artifact in artifacts:
            if artifact["file"].endswith(".whl"):
                sbom = artifact["sbom"]
                core = artifact["crate"].replace("-py", "-core")
                if (
                    not sbom
                    or sbom["format"] != "CycloneDX"
                    or sbom["component"] != core
                    or sbom["component_version"] != crate_version(core)
                ):
                    raise SystemExit(
                        f"{artifact['file']}: missing or incorrect core CycloneDX SBOM"
                    )


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
    match = re.search(r'^version = "([^"]+)"', manifest, flags=re.MULTILINE)
    if match is None:
        manifest = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
        match = re.search(r'^version = "([^"]+)"', manifest, flags=re.MULTILINE)
    if match is None:
        raise SystemExit(f"{crate}/Cargo.toml declares no version")
    return match.group(1)


def wheel_distribution(path: Path) -> tuple[str, str, str | None]:
    """Return (distribution, version, author) as the wheel itself reports them."""

    with zipfile.ZipFile(path) as archive:
        metadata_name = next(
            name for name in archive.namelist() if name.endswith(".dist-info/METADATA")
        )
        metadata = archive.read(metadata_name).decode("utf-8")
    name = re.search(r"^Name: (.+)$", metadata, flags=re.MULTILINE)
    version = re.search(r"^Version: (.+)$", metadata, flags=re.MULTILINE)
    author = re.search(r"^Author(?:-email)?: (.+)$", metadata, flags=re.MULTILINE)
    if name is None or version is None:
        raise SystemExit(f"{path.name} carries no Name/Version metadata")
    return (
        name.group(1).strip(),
        version.group(1).strip(),
        (author.group(1).strip() if author else None),
    )


def wheel_sbom(path: Path) -> dict[str, str] | None:
    """Return the embedded SBOM's identity, or None when the wheel carries none."""

    with zipfile.ZipFile(path) as archive:
        members = [
            n for n in archive.namelist() if "/sboms/" in n and n.endswith(".json")
        ]
        if not members:
            return None
        if len(members) != 1:
            raise SystemExit(f"{path.name}: expected exactly one embedded SBOM")
        document = json.loads(archive.read(members[0]))
    component = (document.get("metadata") or {}).get("component") or {}
    return {
        "member": members[0],
        "spec_version": str(document.get("specVersion") or ""),
        "component": str(component.get("name") or ""),
        "component_version": str(component.get("version") or ""),
        "format": str(document.get("bomFormat") or ""),
    }


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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default="dist", help="directory holding built wheels and tarballs")
    parser.add_argument(
        "--require-complete",
        action="store_true",
        help="require every declared wheel and Node binding on all release targets",
    )
    parser.add_argument(
        "--allow-dirty",
        action="store_true",
        help="record a dirty tree instead of refusing to publish it",
    )
    arguments = parser.parse_args(argv)

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
            raise SystemExit(
                f"{artifact_path.name}: no crate maps to distribution {distribution!r}"
            )

        filename_distribution = (
            distribution.replace("-", "_") if is_wheel else distribution
        )
        if not artifact_path.name.startswith(f"{filename_distribution}-{version}-"):
            raise SystemExit(
                f"{artifact_path.name}: filename disagrees with distribution/version metadata"
            )
        declared = crate_version(crate)
        if version != declared:
            raise SystemExit(
                f"{artifact_path.name} reports version {version} but {crate} declares "
                f"{declared}; a consumer pinning {version} would get other bytes"
            )
        if not author or author.strip() != "Dionisio Chiuratto Agourakis":
            raise SystemExit(
                f"{artifact_path.name} is attributed to {author!r}. A shared artifact must "
                "name this repository, so a consumer can trace it back."
            )
        artifacts.append(
            {
                "sbom": wheel_sbom(artifact_path) if is_wheel else None,
                "distribution": distribution,
                "crate": crate,
                "version": version,
                "author": author,
                "file": artifact_path.name,
                "sha256": digest(artifact_path),
                "bytes": artifact_path.stat().st_size,
                "target": artifact_target(artifact_path),
            }
        )

    validate_release_matrix(artifacts, complete=arguments.require_complete)
    commit = source_commit()
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise SystemExit("cannot stamp a release without an exact source commit")
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "repository": REPOSITORY,
        "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "source": {
            "commit": commit,
            "dirty": dirty,
        },
        "build": {
            "rustc": run(["rustc", "--version"]),
            "cargo": run(["cargo", "--version"]),
            "target": run(["rustc", "-vV"]).split("host: ")[-1].splitlines()[0],
            "python_abi": "abi3-py38",
        },
        "sbom": {
            "tool": "cargo-cyclonedx" if cyclonedx_available() else None,
            "embedded": all(
                artifact["sbom"]
                for artifact in artifacts
                if artifact["file"].endswith(".whl")
            ),
            "note": (
                None
                if all(
                    artifact["sbom"]
                    for artifact in artifacts
                    if artifact["file"].endswith(".whl")
                )
                else "One or more wheels carry no embedded SBOM. Run "
                "scripts/inject_sbom.py before generating this manifest."
            ),
        },
        "artifacts": artifacts,
    }

    destination = out / MANIFEST_NAME
    destination.write_text(
        json.dumps(manifest, indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    checksums = [(artifact["file"], artifact["sha256"]) for artifact in artifacts]
    checksums.append((MANIFEST_NAME, digest(destination)))
    (out / "SHA256SUMS").write_text(
        "".join(f"{checksum}  {name}\n" for name, checksum in sorted(checksums)),
        encoding="utf-8",
        newline="\n",
    )
    print(f"wrote {destination}")
    for artifact in artifacts:
        print(
            f"  {artifact['file']}  sha256={artifact['sha256'][:16]}…  {artifact['bytes']} bytes"
        )
    if not cyclonedx_available():
        print("  note: no SBOM written (cargo-cyclonedx missing)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
