from __future__ import annotations

import re
import shlex
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/release.yml"
BINDING_TEST_PATHS = ("quad-fast-py/tests",)


def workflow_step(workflow: str, name: str) -> str:
    step = re.search(
        rf"^      - name: {re.escape(name)}\n"
        r"(?P<body>.*?)(?=^      - |\Z)",
        workflow,
        re.MULTILINE | re.DOTALL,
    )
    assert step is not None, f"workflow step is missing: {name}"
    return step["body"]


def assert_native_arm_release_contract(workflow: str) -> None:
    row = re.search(
        r"^ +\- \{ os: (?P<runner>[^,]+), target: aarch64-unknown-linux-gnu, "
        r'compat: "(?P<compat>[^"]*)" \}',
        workflow,
        re.MULTILINE,
    )
    assert row is not None, "ARM wheel matrix row is missing"
    assert row["runner"].strip() == "ubuntu-24.04-arm"
    assert shlex.split(row["compat"]) == ["--compatibility", "manylinux_2_17"]
    assert re.search(
        r"^  ARM_MANYLINUX_IMAGE: quay\.io/pypa/manylinux2014_aarch64@sha256:[0-9a-f]{64}$",
        workflow,
        re.MULTILINE,
    )
    step = workflow_step(workflow, "Build native ARM manylinux wheels")
    assert "if: matrix.target == 'aarch64-unknown-linux-gnu'" in step
    assert "--zig" not in step
    assert "ubuntu-latest" not in step
    assert "--platform linux/arm64" in step
    assert "${{ env.ARM_MANYLINUX_IMAGE }}" in step
    assert 'test "$(uname -m)" = aarch64' in step
    assert "rustup which --toolchain 1.98.1 rustc" in step
    assert '"${task_rust_toolchain}:/opt/rust:ro"' in step
    assert "test \"$(rustc --version | cut -d ' ' -f 2)\" = 1.98.1" in step
    assert "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=gcc" in step
    assert "RUSTFLAGS='-C link-arg=-Wl,--fix-cortex-a53-843419'" in step
    assert '"maturin==1.15.0"' in step
    assert "maturin build --release --locked --target aarch64-unknown-linux-gnu" in step
    assert "--compatibility manylinux_2_17" in step
    assert "for crate in $BINDINGS" in step
    assert '--manifest-path "$crate/Cargo.toml"' in step
    assert "--interpreter /opt/python/cp312-cp312/bin/python" in step
    assert "pyarrow" not in step
    smoke = workflow_step(workflow, "Smoke native ARM wheel artifacts")
    assert "if: matrix.target == 'aarch64-unknown-linux-gnu'" in smoke
    assert 'test "$(uname -m)" = aarch64' in smoke
    assert "artifact_target(wheel) == 'aarch64-unknown-linux-gnu'" in smoke
    assert "assert len(wheels) == len(sys.argv) - 1" in smoke
    assert '"pyarrow==25.0.1"' in smoke
    assert "python3 -m pip install --no-index --no-deps dist/*.whl" in smoke
    assert "python3 -I -c" in smoke and "importlib.import_module" in smoke
    assert "os.environ['BINDINGS'].split()" in smoke
    assert "python3 -I -m pytest --import-mode=importlib -q" in smoke
    for path in BINDING_TEST_PATHS:
        assert path in smoke
        assert (ROOT / path).is_dir(), f"artifact smoke references absent tests: {path}"
    shared = re.search(
        r"^      - name: Build every binding for .*?\n(?P<body>.*?)(?=^      - |\Z)",
        workflow,
        re.MULTILINE | re.DOTALL,
    )
    assert shared is not None
    assert "if: matrix.target != 'aarch64-unknown-linux-gnu'" in shared["body"]
    assert "zig.exe" in shared["body"]
    assert (
        "{ os: windows-latest,   target: x86_64-pc-windows-msvc,    platform: win32-x64-msvc }"
        in workflow
    )


def test_arm_and_windows_release_contract():
    assert_native_arm_release_contract(WORKFLOW.read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    ("original", "replacement"),
    [
        (
            "os: ubuntu-24.04-arm, target: aarch64-unknown-linux-gnu, compat:",
            "os: ubuntu-latest, target: aarch64-unknown-linux-gnu, compat:",
        ),
        (
            'compat: "--compatibility manylinux_2_17"',
            'compat: "--zig --compatibility manylinux_2_17"',
        ),
        (
            "quay.io/pypa/manylinux2014_aarch64@sha256:",
            "quay.io/pypa/manylinux2014_aarch64:latest@sha256:",
        ),
        (
            "rustup which --toolchain 1.98.1 rustc",
            "rustup which --toolchain stable rustc",
        ),
        ("LINKER=gcc", "LINKER=zig"),
        ("--fix-cortex-a53-843419", "--unrelated-linker-option"),
        ("maturin build --release --locked", "maturin build --release"),
        ("python3 -I -m pytest --import-mode=importlib -q", "python3 --version"),
        ("quad-fast-py/tests", "absent-quad-tests"),
        ('"pyarrow==25.0.1"', '"unrelated-dependency"'),
        ("artifact_target(wheel)", "unrelated_check(wheel)"),
        ("--platform linux/arm64", "--platform linux/amd64"),
        ('"${task_rust_toolchain}:/opt/rust:ro"', '"${task_rust_toolchain}:/opt/rust"'),
        ("python3 -m pip install --no-index --no-deps dist/*.whl", "python3 --version"),
        ("importlib.import_module", "importlib.find_spec"),
        (
            "if: matrix.target != 'aarch64-unknown-linux-gnu'",
            "if: always()",
        ),
        ("platform: win32-x64-msvc", "platform: removed-win32-node"),
    ],
)
def test_arm_release_contract_rejects_regressions(original: str, replacement: str):
    workflow = WORKFLOW.read_text(encoding="utf-8")
    assert original in workflow
    with pytest.raises(AssertionError):
        assert_native_arm_release_contract(workflow.replace(original, replacement))
