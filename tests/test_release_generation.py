from __future__ import annotations

import base64
import csv
import hashlib
import importlib.util
import io
import json
import tarfile
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def load_script(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


release = load_script("release_manifest")
injection = load_script("inject_sbom")
PLATFORMS = {
    "aarch64-apple-darwin": "macosx_11_0_arm64",
    "x86_64-unknown-linux-gnu": "manylinux_2_17_x86_64.manylinux2014_x86_64",
    "aarch64-unknown-linux-gnu": "manylinux_2_17_aarch64.manylinux2014_aarch64",
    "x86_64-pc-windows-msvc": "win_amd64",
}


def targets_for(crate: str) -> list[str]:
    """Every target a crate ships on: Node bindings skip the wheel-only targets."""
    targets = list(release.TARGET_PLATFORMS.values())
    if not crate.endswith("-node"):
        targets += list(release.WHEEL_ONLY_TARGETS.values())
    return targets


def native_header(target: str) -> bytes:
    header = bytearray(64)
    if target == "x86_64-pc-windows-msvc":
        # Minimal PE: "MZ", e_lfanew -> "PE\0\0", COFF machine = AMD64.
        header[:2] = b"MZ"
        header[0x3C:0x40] = (0x40).to_bytes(4, "little")
        header += b"PE\0\0" + (0x8664).to_bytes(2, "little") + bytes(18)
        return bytes(header)
    if target == "aarch64-apple-darwin":
        header[:4] = b"\xcf\xfa\xed\xfe"
        header[4:8] = (0x0100000C).to_bytes(4, "little")
        header[12:16] = (6).to_bytes(4, "little")
    else:
        header[:7] = b"\x7fELF\x02\x01\x01"
        header[16:18] = (3).to_bytes(2, "little")
        machine = 62 if target == "x86_64-unknown-linux-gnu" else 183
        header[18:20] = machine.to_bytes(2, "little")
    return bytes(header)


def wheel(
    directory: Path,
    distribution: str = "quad_fast",
    platform: str = "macosx_11_0_arm64",
) -> Path:
    crate = release.CRATES[distribution]
    version = release.crate_version(crate)
    info = f"{distribution}-{version}.dist-info"
    path = directory / f"{distribution}-{version}-cp38-abi3-{platform}.whl"
    core_name = crate.replace("-py", "-core")
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "metadata": {
            "component": {"name": core_name, "version": version}
        },
    }
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(
            f"{info}/METADATA",
            f"Name: {distribution.replace('_', '-')}\nVersion: {version}\nAuthor: Dionisio Chiuratto Agourakis\n",
        )
        archive.writestr(
            f"{info}/WHEEL", f"Wheel-Version: 1.0\nTag: cp38-abi3-{platform}\n"
        )
        archive.writestr(f"{info}/sboms/core.json", json.dumps(sbom))
        archive.writestr(f"{info}/RECORD", "")
        target = (
            "aarch64-apple-darwin"
            if platform.startswith("macosx_")
            else next(target for target, tag in PLATFORMS.items() if tag == platform)
        )
        suffix = ".pyd" if target.endswith("windows-msvc") else ".so"
        archive.writestr(f"{distribution}/_native.abi3{suffix}", native_header(target))
    return path


def node_package(
    directory: Path,
    crate: str = "quad-fast-node",
    platform: str = "darwin-arm64",
    binary: bool = True,
) -> Path:
    version = release.crate_version(crate)
    path = directory / f"{crate}-{version}-{platform}.tgz"
    entries = {
        "package/package.json": json.dumps(
            {
                "name": crate,
                "version": version,
                "author": "Dionisio Chiuratto Agourakis",
            }
        ).encode()
    }
    if binary:
        entries[f"package/{crate.replace('-', '_')}.node"] = native_header(
            release.TARGET_PLATFORMS[platform]
        )
    with tarfile.open(path, "w:gz") as archive:
        for name, data in entries.items():
            member = tarfile.TarInfo(name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    return path


@pytest.fixture
def generator(monkeypatch):
    monkeypatch.setattr(release, "source_is_dirty", lambda: False)
    monkeypatch.setattr(release, "source_commit", lambda: "a" * 40)
    monkeypatch.setattr(
        release,
        "run",
        lambda args: (
            "host: aarch64-apple-darwin" if "-vV" in args else "fixture-toolchain"
        ),
    )
    monkeypatch.setattr(release, "cyclonedx_available", lambda: True)
    return release


def test_complete_matrix_stamps_wheels_and_node_provenance(tmp_path: Path, generator):
    for distribution in release.CRATES:
        for platform in PLATFORMS.values():
            wheel(tmp_path, distribution, platform)
    for crate in release.NODE_CRATES:
        for platform in release.TARGET_PLATFORMS:
            node_package(tmp_path, crate, platform)
    assert generator.main(["--out", str(tmp_path), "--require-complete"]) == 0
    manifest_bytes = (tmp_path / release.MANIFEST_NAME).read_bytes()
    assert b"\r\n" not in manifest_bytes
    manifest = json.loads(manifest_bytes.decode("utf-8"))
    assert len(manifest["artifacts"]) == 8  # 1 Python binding x 4 targets + 1 Node binding x 4
    assert manifest["source"] == {"commit": "a" * 40, "dirty": False}
    for artifact in manifest["artifacts"]:
        path = tmp_path / artifact["file"]
        assert artifact["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
        assert artifact["bytes"] == path.stat().st_size
        assert artifact["target"] in PLATFORMS
    sums_bytes = (tmp_path / "SHA256SUMS").read_bytes()
    assert b"\r\n" not in sums_bytes
    sums = dict(
        line.split("  ", 1)[::-1]
        for line in sums_bytes.decode("utf-8").splitlines()
    )
    assert set(sums) == {artifact["file"] for artifact in manifest["artifacts"]} | {
        release.MANIFEST_NAME
    }
    assert sum(name.endswith(".tgz") for name in sums) == 4
    for name, digest in sums.items():
        assert digest == hashlib.sha256((tmp_path / name).read_bytes()).hexdigest()


def test_missing_cyclonedx_prints_note_to_stderr_without_name_error(
    tmp_path: Path, generator, monkeypatch, capsys
):
    wheel(tmp_path)
    monkeypatch.setattr(generator, "cyclonedx_available", lambda: False)
    assert generator.main(["--out", str(tmp_path)]) == 0
    captured = capsys.readouterr()
    assert "cargo-cyclonedx missing" in captured.err


def test_missing_node_or_wheel_target_prevents_release(tmp_path: Path, generator):
    wheel(tmp_path)
    with pytest.raises(SystemExit, match="incomplete release matrix"):
        generator.main(["--out", str(tmp_path), "--require-complete"])
    assert not (tmp_path / release.MANIFEST_NAME).exists()


def test_duplicate_crate_target_prevents_release(tmp_path: Path, generator):
    wheel(tmp_path, platform="macosx_11_0_arm64")
    wheel(tmp_path, platform="macosx_12_0_arm64")
    with pytest.raises(SystemExit, match="duplicate crate/target"):
        generator.main(["--out", str(tmp_path)])


def test_node_tarball_without_native_binary_is_rejected(tmp_path: Path):
    with pytest.raises(SystemExit, match="Node binary"):
        release.artifact_target(node_package(tmp_path, binary=False))


def test_node_tarball_accepts_windows_pe_binary(tmp_path: Path):
    path = node_package(tmp_path, platform="win32-x64-msvc")
    assert release.artifact_target(path) == "x86_64-pc-windows-msvc"


def test_node_tarball_rejects_native_binary_for_a_different_target(tmp_path: Path):
    path = node_package(tmp_path, platform="linux-x64-gnu")
    renamed = path.with_name(path.name.replace("linux-x64-gnu", "linux-arm64-gnu"))
    path.rename(renamed)
    with pytest.raises(SystemExit, match="native architecture"):
        release.artifact_target(renamed)


def test_wheel_rejects_non_native_extension_payload(tmp_path: Path):
    path = wheel(tmp_path)
    with zipfile.ZipFile(path) as archive:
        entries = {name: archive.read(name) for name in archive.namelist()}
    entries["quad_fast/_native.abi3.so"] = b"not a native extension"
    with zipfile.ZipFile(path, "w") as archive:
        for name, payload in entries.items():
            archive.writestr(name, payload)
    with pytest.raises(SystemExit, match="native architecture"):
        release.artifact_target(path)


def test_wheel_accepts_windows_pyd_extension_payload(tmp_path: Path):
    path = wheel(tmp_path, platform="win_amd64")
    assert release.artifact_target(path) == "x86_64-pc-windows-msvc"


def test_wheel_platform_must_match_metadata(tmp_path: Path):
    path = wheel(tmp_path)
    renamed = path.with_name(
        path.name.replace("macosx_11_0_arm64", "manylinux_2_17_aarch64")
    )
    path.rename(renamed)
    with pytest.raises(SystemExit, match="disagrees"):
        release.artifact_target(renamed)


def test_artifact_filename_must_match_distribution_metadata(tmp_path: Path, generator):
    path = node_package(tmp_path)
    path.rename(path.with_name(path.name.replace("quad-fast-node", "other-fast-node")))
    with pytest.raises(SystemExit, match="filename disagrees"):
        generator.main(["--out", str(tmp_path)])


def test_unknown_source_commit_prevents_stamp(tmp_path: Path, generator, monkeypatch):
    wheel(tmp_path)
    monkeypatch.setattr(generator, "source_commit", lambda: "unknown")
    with pytest.raises(SystemExit, match="exact source commit"):
        generator.main(["--out", str(tmp_path)])


@pytest.mark.parametrize("missing_crate", ["quad-fast-py", "quad-fast-node"])
@pytest.mark.parametrize(
    "missing_target",
    [
        "aarch64-apple-darwin",
        "x86_64-unknown-linux-gnu",
        "aarch64-unknown-linux-gnu",
        "x86_64-pc-windows-msvc",
    ],
)
def test_each_binding_is_required_on_every_target(missing_crate: str, missing_target: str):
    artifacts = [
        {"crate": crate, "target": target, "file": f"{crate}-{target}.tgz"}
        for crate in set(release.CRATES.values()) | release.NODE_CRATES
        for target in targets_for(crate)
        if (crate, target) != (missing_crate, missing_target)
    ]
    with pytest.raises(SystemExit, match=missing_crate):
        release.validate_release_matrix(artifacts, complete=True)


def test_complete_release_requires_core_sbom_identity():
    artifacts = [
        {
            "crate": crate,
            "target": target,
            "file": f"{crate}-{target}.whl",
            "sbom": {"format": "CycloneDX", "component": "incorrect"},
        }
        for crate in set(release.CRATES.values()) | release.NODE_CRATES
        for target in targets_for(crate)
    ]
    with pytest.raises(SystemExit, match="incorrect core CycloneDX SBOM"):
        release.validate_release_matrix(artifacts, complete=True)


def test_duplicate_embedded_sboms_are_rejected(tmp_path: Path):
    path = wheel(tmp_path)
    with zipfile.ZipFile(path, "a") as archive:
        archive.writestr("extra.dist-info/sboms/extra.json", "{}")
    with pytest.raises(SystemExit, match="exactly one embedded SBOM"):
        release.wheel_sbom(path)


def test_stale_core_sbom_version_prevents_complete_release():
    artifacts = []
    for crate in set(release.CRATES.values()) | release.NODE_CRATES:
        for target in targets_for(crate):
            is_wheel = crate.endswith("-py")
            artifacts.append(
                {
                    "crate": crate,
                    "target": target,
                    "file": f"{crate}-{target}.{'whl' if is_wheel else 'tgz'}",
                    "sbom": {
                        "format": "CycloneDX",
                        "component": crate.replace("-py", "-core"),
                        "component_version": "999.0.0",
                    }
                    if is_wheel
                    else None,
                }
            )
    with pytest.raises(SystemExit, match="incorrect core CycloneDX SBOM"):
        release.validate_release_matrix(artifacts, complete=True)


def test_dirty_tree_cannot_stamp_release(tmp_path: Path, generator, monkeypatch):
    wheel(tmp_path)
    monkeypatch.setattr(generator, "source_is_dirty", lambda: True)
    with pytest.raises(SystemExit, match="uncommitted changes"):
        generator.main(["--out", str(tmp_path)])


def test_dirty_local_build_is_explicitly_attributed(
    tmp_path: Path, generator, monkeypatch
):
    wheel(tmp_path)
    monkeypatch.setattr(generator, "source_is_dirty", lambda: True)
    assert generator.main(["--out", str(tmp_path), "--allow-dirty"]) == 0
    assert (
        json.loads((tmp_path / release.MANIFEST_NAME).read_text(encoding="utf-8"))[
            "source"
        ]["dirty"]
        is True
    )


def test_quad_sbom_injection_rebuilds_record_and_removes_duplicates(tmp_path: Path):
    path = wheel(tmp_path)
    version = release.crate_version("quad-fast-py")
    sbom = tmp_path / "quad-fast-core.cdx.json"
    sbom.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "metadata": {
                    "component": {"name": "quad-fast-core", "version": version}
                },
            }
        ),
        encoding="utf-8",
    )
    assert injection.inject(path, sbom)
    first_hash = release.digest(path)
    assert not injection.inject(path, sbom)
    assert release.digest(path) == first_hash
    with zipfile.ZipFile(path) as archive:
        assert archive.testzip() is None
        sboms = [name for name in archive.namelist() if "/sboms/" in name]
        assert len(sboms) == 1
        record = next(
            name for name in archive.namelist() if name.endswith(".dist-info/RECORD")
        )
        rows = list(csv.reader(io.StringIO(archive.read(record).decode("utf-8"))))
        assert {row[0] for row in rows} == set(archive.namelist())
        for name, digest, size in rows:
            if name == record:
                assert digest == size == ""
            else:
                payload = archive.read(name)
                assert (
                    digest
                    == "sha256="
                    + base64.urlsafe_b64encode(hashlib.sha256(payload).digest())
                    .rstrip(b"=")
                    .decode("ascii")
                )
                assert size == str(len(payload))


def test_release_workflow_requires_ci_and_complete_joint_publication():
    workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
    assert "uses: ./.github/workflows/ci.yml" in workflow
    assert workflow.count("needs: verify") == 2
    assert "needs: [wheels, node]" in workflow
    assert "--require-complete" in workflow
    assert "dist/*.tgz" in workflow
    assert "quad-fast-py" in workflow
    assert "quad-fast-node" in workflow
    assert "win32-x64-msvc" in workflow
    assert "maturin==1.15.0" in workflow
    assert "ziglang==0.15.2" in workflow
    assert "CARGO_ZIGBUILD_ZIG_PATH" in workflow
    assert "CARGO_ZIGBUILD_PYTHON_PATH" in workflow
    assert "maturin build --release --locked" in workflow


def test_sbom_rewrite_invalidates_manifest_and_checksums(tmp_path: Path, monkeypatch):
    wheel(tmp_path)
    sbom = tmp_path / "quad-fast-core.cdx.json"
    sbom.write_text(json.dumps({"bomFormat": "CycloneDX"}), encoding="utf-8")
    monkeypatch.setattr(injection, "crate_sbom", lambda crate: sbom)
    (tmp_path / "release-manifest.json").write_text("{}", encoding="utf-8")
    (tmp_path / "SHA256SUMS").write_text("stale", encoding="utf-8")
    assert injection.main(["--dist", str(tmp_path)]) == 0
    assert not (tmp_path / "release-manifest.json").exists()
    assert not (tmp_path / "SHA256SUMS").exists()
