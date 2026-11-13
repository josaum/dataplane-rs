"""A Rust panic in a binding call must reach the caller as an exception.

Two source contracts back the runtime probes (quad-fast-node/panic.test.mjs and
quad-fast-py/tests/test_panic.py), which only exercise one probe function:

- every `#[napi]` item in a Node binding is built with `catch_unwind`, so a
  panic in any exported function is a thrown JS Error rather than an abort;
- no Cargo profile, and no RUSTFLAGS in a workflow, sets `panic = "abort"`,
  which would turn PyO3's PanicException and napi's thrown Error into a
  process abort.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
NODE_SOURCES = sorted(ROOT.glob("*-node/src/**/*.rs"))
MANIFESTS = sorted([ROOT / "Cargo.toml", *ROOT.glob("*/Cargo.toml")])
WORKFLOWS = sorted((ROOT / ".github/workflows").glob("*.y*ml"))

NAPI_ATTRIBUTE = re.compile(r"^\s*#\[napi(?P<args>\([^\]]*\))?\]\s*$")
EXPORTED_ITEM = re.compile(r"^\s*pub (?:async )?(?:fn|struct|enum|impl)\b|^\s*impl\b")


def assert_napi_items_catch_unwind(source: str, name: str) -> None:
    lines = source.splitlines()
    for index, line in enumerate(lines):
        match = NAPI_ATTRIBUTE.match(line)
        if not match:
            continue
        following = next(
            (later for later in lines[index + 1 :] if not later.strip().startswith("#[")), ""
        )
        if not re.match(r"^\s*pub (?:async )?fn\b", following):
            # Objects and enums are not calls; their methods carry their own
            # attribute and are checked on their own line.
            continue
        assert "catch_unwind" in (match["args"] or ""), (
            f"{name}:{index + 1}: `{following.strip()}` is exported without catch_unwind; "
            "a panic in it aborts the Node process"
        )


def assert_unwinding(manifest: str, name: str) -> None:
    document = tomllib.loads(manifest)
    for profile, settings in (document.get("profile") or {}).items():
        assert settings.get("panic", "unwind") == "unwind", (
            f"{name} [profile.{profile}] sets panic = {settings['panic']!r}; "
            "a binding panic would abort the host process"
        )


def assert_no_abort_flag(workflow: str, name: str) -> None:
    assert not re.search(r"panic\s*=\s*abort|CARGO_PROFILE_\w+_PANIC", workflow), (
        f"{name} builds with panic=abort"
    )


def test_there_are_node_sources():
    assert NODE_SOURCES


@pytest.mark.parametrize("path", NODE_SOURCES, ids=lambda path: path.relative_to(ROOT).as_posix())
def test_every_exported_node_function_catches_unwind(path: Path):
    assert_napi_items_catch_unwind(path.read_text(encoding="utf-8"), path.name)


@pytest.mark.parametrize("path", MANIFESTS, ids=lambda path: path.relative_to(ROOT).as_posix())
def test_no_profile_aborts_on_panic(path: Path):
    assert_unwinding(path.read_text(encoding="utf-8"), path.name)


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda path: path.name)
def test_no_workflow_builds_with_panic_abort(path: Path):
    assert_no_abort_flag(path.read_text(encoding="utf-8"), path.name)


NODE_LIB = ROOT / "quad-fast-node/src/lib.rs"
ROOT_MANIFEST = ROOT / "Cargo.toml"
CI = ROOT / ".github/workflows/ci.yml"

MUTATIONS = [
    (
        lambda text: assert_napi_items_catch_unwind(text, NODE_LIB.name),
        NODE_LIB,
        "#[napi(catch_unwind)]\npub fn quads_to_ipc",
        "#[napi]\npub fn quads_to_ipc",
    ),
    (
        lambda text: assert_napi_items_catch_unwind(text, NODE_LIB.name),
        NODE_LIB,
        "#[napi(catch_unwind)]\npub fn version",
        "#[napi(js_name = \"version\")]\npub fn version",
    ),
    (
        lambda text: assert_unwinding(text, ROOT_MANIFEST.name),
        ROOT_MANIFEST,
        "[profile.release]\n",
        "[profile.release]\npanic = \"abort\"\n",
    ),
    (
        lambda text: assert_no_abort_flag(text, CI.name),
        CI,
        "  RUSTFLAGS: -D warnings\n",
        "  RUSTFLAGS: -D warnings -C panic=abort\n",
    ),
]


@pytest.mark.parametrize("case", MUTATIONS, ids=[f"{index:02d}-{case[1].name}" for index, case in enumerate(MUTATIONS)])
def test_contracts_reject_regressions(case):
    contract, path, original, replacement = case
    text = path.read_text(encoding="utf-8")
    assert original in text, f"the mutation no longer applies to {path.name}: {original!r}"
    contract(text)
    with pytest.raises(AssertionError):
        contract(text.replace(original, replacement, 1))
