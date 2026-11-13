"""The consumer pin check must fail on every way a consumer can drift.

Each test builds a small vendor directory from scratch rather than reading the
real `dist/`, so the suite runs on a clean clone with no wheels built.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import verify_consumer_pin as vcp  # noqa: E402

COMMIT = "0" * 40
OTHER = "1" * 40


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)


def _source_at(tmp_path: Path, commit_marker: str) -> Path:
    """A minimal git checkout whose HEAD the check can resolve."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "Cargo.toml").write_text("[workspace]\n", encoding="utf-8")
    _git(src, "init", "-q")
    _git(
        src,
        "-c",
        "user.email=t@t",
        "-c",
        "user.name=t",
        "commit",
        "-q",
        "--allow-empty",
        "-m",
        commit_marker,
    )
    return src


def _head(src: Path) -> str:
    return subprocess.run(
        ["git", "-C", str(src), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _vendor(
    tmp_path: Path,
    *,
    commit: str,
    wheels: dict[str, bytes],
    dirty: bool = False,
    extra_declared: dict[str, bytes] | None = None,
) -> Path:
    vendor = tmp_path / "vendor"
    vendor.mkdir()
    artifacts = []
    for name, payload in wheels.items():
        (vendor / name).write_bytes(payload)
    for name, payload in {**wheels, **(extra_declared or {})}.items():
        artifacts.append(
            {
                "file": name,
                "sha256": hashlib.sha256(payload).hexdigest(),
                "bytes": len(payload),
            }
        )
    (vendor / vcp.MANIFEST_NAME).write_text(
        json.dumps(
            {
                "schema_version": vcp.SCHEMA,
                "source": {"commit": commit, "dirty": dirty},
                "artifacts": artifacts,
            }
        ),
        encoding="utf-8",
    )
    return vendor


def test_matching_wheels_and_pin_pass(tmp_path: Path) -> None:
    src = _source_at(tmp_path, "release")
    vendor = _vendor(
        tmp_path,
        commit=_head(src),
        wheels={"quad_fast-0.1.0-py3-none-any.whl": b"a"},
    )
    report = vcp.verify(vendor, src)
    assert report.ok, report.failures
    assert report.checked_wheels == 1


def test_wheels_only_consumer_skips_the_source_pin(tmp_path: Path) -> None:
    vendor = _vendor(
        tmp_path,
        commit=COMMIT,
        wheels={"quad_fast-0.1.0-py3-none-any.whl": b"a"},
    )
    assert vcp.verify(vendor, None).ok


def test_a_substituted_wheel_fails(tmp_path: Path) -> None:
    vendor = _vendor(
        tmp_path,
        commit=COMMIT,
        wheels={"quad_fast-0.1.0-py3-none-any.whl": b"a"},
    )
    (vendor / "quad_fast-0.1.0-py3-none-any.whl").write_bytes(b"tampered")
    report = vcp.verify(vendor, None)
    assert any("sha256" in f for f in report.failures), report.failures


def test_an_undeclared_wheel_fails(tmp_path: Path) -> None:
    vendor = _vendor(
        tmp_path,
        commit=COMMIT,
        wheels={"quad_fast-0.1.0-py3-none-any.whl": b"a"},
    )
    (vendor / "stray_fast-9.9.9-py3-none-any.whl").write_bytes(b"?")
    report = vcp.verify(vendor, None)
    assert any("not named by the manifest" in f for f in report.failures), report.failures


def test_a_missing_declared_wheel_fails(tmp_path: Path) -> None:
    vendor = _vendor(
        tmp_path,
        commit=COMMIT,
        wheels={"quad_fast-0.1.0-py3-none-any.whl": b"a"},
        extra_declared={"other_fast-0.1.0-py3-none-any.whl": b"b"},
    )
    report = vcp.verify(vendor, None)
    assert any("not vendored" in f for f in report.failures), report.failures


def test_a_source_pin_at_another_commit_fails(tmp_path: Path) -> None:
    src = _source_at(tmp_path, "newer")
    vendor = _vendor(
        tmp_path,
        commit=OTHER,
        wheels={"quad_fast-0.1.0-py3-none-any.whl": b"a"},
    )
    report = vcp.verify(vendor, src)
    assert any("disagree" in f for f in report.failures), report.failures


def test_a_dirty_release_is_refused(tmp_path: Path) -> None:
    vendor = _vendor(tmp_path, commit=COMMIT, wheels={}, dirty=True)
    report = vcp.verify(vendor, None)
    assert any("dirty" in f for f in report.failures), report.failures


def test_an_uninitialised_submodule_is_named_not_guessed(tmp_path: Path) -> None:
    vendor = _vendor(tmp_path, commit=COMMIT, wheels={})
    empty = tmp_path / "src"
    empty.mkdir()
    report = vcp.verify(vendor, empty)
    assert any("submodule update --init" in f for f in report.failures), report.failures


def test_tarballs_and_wheels_together_pass(tmp_path: Path) -> None:
    vendor = _vendor(
        tmp_path,
        commit=COMMIT,
        wheels={
            "quad_fast-0.1.0-win_amd64.whl": b"a",
            "quad-fast-node-0.1.0-win32-x64-msvc.tgz": b"pkg",
        },
    )
    report = vcp.verify(vendor, None)
    assert report.ok, report.failures
    assert report.checked_wheels == 2


def test_missing_declared_tarball_fails_when_tarballs_present(tmp_path: Path) -> None:
    vendor = _vendor(
        tmp_path,
        commit=COMMIT,
        wheels={"quad-fast-node-0.1.0-darwin-arm64.tgz": b"pkg1"},
        extra_declared={"quad-fast-node-0.1.0-win32-x64-msvc.tgz": b"pkg2"},
    )
    report = vcp.verify(vendor, None)
    assert any(
        "manifest names a tarball that is not vendored" in f for f in report.failures
    ), report.failures


@pytest.mark.skipif(
    not (Path(__file__).resolve().parents[1] / "dist" / vcp.MANIFEST_NAME).is_file(),
    reason="no local release in dist/",
)
def test_the_local_release_directory_is_self_consistent() -> None:
    repo = Path(__file__).resolve().parents[1]
    report = vcp.verify(repo / "dist", None)
    assert report.ok, report.failures
