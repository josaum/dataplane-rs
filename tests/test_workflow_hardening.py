"""Supply-chain and least-privilege contracts of the GitHub Actions workflows.

Four contracts, each checked against the files in the repository and against
a mutated copy that must fail it:

- every `uses:` names a full commit SHA, with the version in a trailing
  comment (a local `./` reusable workflow is exempt);
- no workflow grants a write permission to all of its jobs, and only the
  job that publishes the release holds `contents: write`;
- cargo-deny and cargo-audit run, at pinned versions, in a workflow that runs
  on every push to main and every pull request, and that release.yml does not
  call;
- Dependabot updates every ecosystem that has a manifest in the repository,
  and holds the upgrades the consumers cannot take yet (pyo3 0.30, napi 3).

Structure is read with PyYAML. A `uses:` line is also read as text, because
the version comment after a pinned SHA is invisible to a YAML parser.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github/workflows"
CI = WORKFLOWS / "ci.yml"
RELEASE = WORKFLOWS / "release.yml"
AUDIT = WORKFLOWS / "audit.yml"
DEPENDABOT = ROOT / ".github/dependabot.yml"
DENY_CONFIG = ROOT / "deny.toml"
ALL_WORKFLOWS = sorted([*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")])

# The one job in each workflow that may hold a token able to write.
WRITERS = {"release.yml": {"manifest": {"contents": "write"}}}
# Actions that publish no version tags: the comment names the branch whose
# history holds the pinned commit.
BRANCH_PINNED = {"dtolnay/rust-toolchain": "master"}
# Values that grant nothing beyond reading.
READ_ONLY = {"read", "none"}

USES = re.compile(r"^\s*(?:- )?uses:\s*(?P<ref>\S+)(?P<rest>.*)$")
PINNED = re.compile(
    r"^(?P<action>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)(?:/[A-Za-z0-9_./-]+)?@(?P<sha>[0-9a-f]{40})$"
)
VERSION_COMMENT = re.compile(r"^\s+#\s+(?P<version>v\d+(?:\.\d+){0,2}|[A-Za-z0-9_.-]+)\s*$")


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def load(text: str) -> dict:
    document = yaml.safe_load(text)
    assert isinstance(document, dict), "a workflow is a mapping"
    return document


def triggers(document: dict) -> dict:
    # YAML 1.1 reads a bare `on` key as the boolean True.
    on = document.get("on", document.get(True))
    if isinstance(on, str):
        return {on: None}
    if isinstance(on, list):
        return {name: None for name in on}
    assert isinstance(on, dict), "a workflow names its triggers"
    return on


def steps(document: dict):
    for name, job in (document.get("jobs") or {}).items():
        for step in job.get("steps") or []:
            yield name, step


# --- contract 1: every action is pinned to a commit SHA ---------------------


def assert_actions_pinned(text: str) -> None:
    found = 0
    for number, line in enumerate(text.splitlines(), start=1):
        if line.lstrip().startswith("#"):
            continue
        match = USES.match(line)
        if not match:
            continue
        found += 1
        ref = match["ref"].strip("'\"")
        if ref.startswith("./"):
            continue
        pinned = PINNED.match(ref)
        assert pinned, f"line {number}: {ref} is not pinned to a full commit SHA"
        comment = VERSION_COMMENT.match(match["rest"])
        assert comment, f"line {number}: {ref} has no trailing version comment"
        branch = BRANCH_PINNED.get(pinned["action"])
        if branch is None:
            assert comment["version"].startswith("v"), (
                f"line {number}: {pinned['action']} names no version tag in its comment"
            )
        else:
            assert comment["version"] == branch, (
                f"line {number}: {pinned['action']} must name the branch {branch!r}"
            )
    # The YAML view must agree with the text view: a `uses:` spelled in a way
    # the line pattern cannot read (flow style, for one) would escape it.
    in_yaml = sum(1 for _, step in steps(load(text)) if "uses" in step)
    in_yaml += sum(1 for job in (load(text).get("jobs") or {}).values() if "uses" in job)
    assert found == in_yaml, f"read {found} `uses:` lines, but the workflow has {in_yaml}"


def assert_toolchain_named(text: str) -> None:
    """A branch-pinned rust-toolchain must say which compiler it installs."""
    channel = tomllib.loads(read(ROOT / "rust-toolchain.toml"))["toolchain"]["channel"]
    for job, step in steps(load(text)):
        if str(step.get("uses", "")).startswith("dtolnay/rust-toolchain@"):
            toolchain = (step.get("with") or {}).get("toolchain")
            assert str(toolchain) == channel, (
                f"job {job}: dtolnay/rust-toolchain installs {toolchain!r}, "
                f"rust-toolchain.toml pins {channel!r}"
            )


# --- contract 2: least privilege --------------------------------------------


def assert_read_only(permissions, where: str) -> None:
    assert permissions is not None, f"{where} declares no permissions; the default may write"
    if isinstance(permissions, str):
        assert permissions in {"read-all", "{}"}, f"{where} grants {permissions!r}"
        return
    assert isinstance(permissions, dict), f"{where}: permissions must be a mapping"
    for scope, value in permissions.items():
        assert value in READ_ONLY, f"{where} grants {scope}: {value}"


def assert_least_privilege(text: str, name: str) -> None:
    document = load(text)
    assert_read_only(document.get("permissions"), f"{name} (workflow-wide)")
    allowed = WRITERS.get(name, {})
    for job_name, job in (document.get("jobs") or {}).items():
        permissions = job.get("permissions")
        if permissions is None:
            continue
        if job_name in allowed:
            assert permissions == allowed[job_name], (
                f"{name} job {job_name} must hold exactly {allowed[job_name]}, "
                f"not {permissions}"
            )
        else:
            assert_read_only(permissions, f"{name} job {job_name}")


def assert_publisher_writes(text: str) -> None:
    """The release job that publishes is the one that holds the write token."""
    jobs = load(text).get("jobs") or {}
    publishers = [
        name
        for name, step in steps(load(text))
        if str(step.get("uses", "")).startswith("softprops/action-gh-release@")
    ]
    assert publishers == ["manifest"], f"the release is published by {publishers}"
    assert jobs["manifest"].get("permissions") == {"contents": "write"}


# --- contract 3: cargo-deny and cargo-audit run ------------------------------


INSTALL = re.compile(
    r"cargo install (?P<tool>cargo-deny|cargo-audit) --locked --version \d+\.\d+\.\d+\b"
)


def assert_audit_contract(audit: str, ci: str, release: str, policy_text: str | None = None) -> None:
    document = load(audit)
    on = triggers(document)
    assert "pull_request" in on, "the audit must run on every pull request"
    assert on["pull_request"] is None or not (on["pull_request"] or {}).get("paths"), (
        "the audit must run on every pull request, not only some paths"
    )
    push = on.get("push") or {}
    assert "main" in (push.get("branches") or []), "the audit must run on every push to main"
    assert "schedule" in on, "advisories arrive on their own schedule; the audit must too"
    commands = {
        name: "\n".join(str(step.get("run", "")) for step in job.get("steps") or [])
        for name, job in (document.get("jobs") or {}).items()
    }
    installs = {m["tool"] for run in commands.values() for m in INSTALL.finditer(run)}
    assert installs == {"cargo-deny", "cargo-audit"}, (
        f"cargo-deny and cargo-audit must be installed at pinned versions, found {installs}"
    )
    deny_jobs = [n for n, run in commands.items() if re.search(r"\bcargo deny --locked check\b", run)]
    audit_jobs = [n for n, run in commands.items() if re.search(r"\bcargo audit\b", run)]
    assert deny_jobs, "no job runs `cargo deny --locked check`"
    assert audit_jobs, "no job runs `cargo audit`"
    assert not set(deny_jobs) & set(audit_jobs), (
        "deny and audit share a job, so one failure would hide the other"
    )
    assert DENY_CONFIG.is_file(), "cargo-deny needs deny.toml"
    policy = tomllib.loads(read(DENY_CONFIG) if policy_text is None else policy_text)
    advisories = policy["advisories"]
    assert advisories.get("ignore", []) == [], "no advisory may be waved through"
    # Without `unsound = "all"`, cargo-deny 0.20.2 lets a transitive unsound
    # crate through that `cargo audit --deny unsound` fails on.
    for key in ("unsound", "unmaintained"):
        assert advisories.get(key) == "all", f"deny.toml must fail any {key} crate, not {advisories.get(key)!r}"
    assert advisories.get("yanked") == "deny", "a yanked version must fail"
    for workflow in (ci, release):
        parsed = load(workflow)
        called = [str(step.get("uses", "")) for _, step in steps(parsed)]
        called += [str(job.get("uses", "")) for job in (parsed.get("jobs") or {}).values()]
        assert not any("audit.yml" in uses for uses in called), (
            "ci.yml and release.yml must not call audit.yml: an advisory must not block a release"
        )
        for _, step in steps(parsed):
            run = str(step.get("run", ""))
            assert not re.search(r"\bcargo (deny|audit)\b", run), (
                "ci.yml and release.yml must not scan advisories: release.yml calls ci.yml"
            )


# --- contract 4: Dependabot covers each ecosystem ---------------------------


def present_ecosystems(root: Path) -> set[tuple[str, str]]:
    def directory(path: Path) -> str:
        relative = path.parent.relative_to(root).as_posix()
        return "/" if relative == "." else f"/{relative}"

    def tracked(path: Path) -> bool:
        parts = path.relative_to(root).parts
        return not any(part in {"node_modules", "target", ".venv"} or part.startswith(".") for part in parts[:-1])

    found = {("cargo", "/")} if (root / "Cargo.toml").is_file() else set()
    if any((root / ".github/workflows").glob("*.y*ml")):
        found.add(("github-actions", "/"))
    # A uv.lock is what pins a Python project's dependencies; without one,
    # pip reads the pyproject.toml or requirements file.
    for path in root.rglob("uv.lock"):
        if tracked(path):
            found.add(("uv", directory(path)))
    for path in [*root.rglob("pyproject.toml"), *root.rglob("requirements*.txt")]:
        if tracked(path) and not (path.parent / "uv.lock").is_file():
            found.add(("pip", directory(path)))
    for path in root.rglob("package.json"):
        if tracked(path):
            found.add(("npm", directory(path)))
    return found


def assert_dependabot_contract(dependabot: str, ecosystems: set[tuple[str, str]]) -> None:
    document = yaml.safe_load(dependabot)
    assert document.get("version") == 2
    covered = set()
    for update in document.get("updates") or []:
        interval = (update.get("schedule") or {}).get("interval")
        assert interval in {"daily", "weekly"}, (
            f"{update.get('package-ecosystem')} updates {interval!r}, at least weekly is required"
        )
        directories = update.get("directories") or [update.get("directory")]
        for entry in directories:
            covered.add((update.get("package-ecosystem"), entry))
    missing = ecosystems - covered
    assert not missing, f"Dependabot does not update {sorted(missing)}"
    assert_dependabot_holds(document)


# Upgrades Dependabot must not propose, each held for as long as its reason
# holds in the manifests: (dependency-name, version range, reason).
HOLDS = [
    ("pyo3*", ">=0.30", "pyo3 0.30 drops abi3-py38, which quad-fast-py builds"),
    ("napi", ">=3", "the consumer shells load napi 2 builds"),
    ("napi-derive", ">=3", "napi-derive 3 needs the napi 3 runtime"),
    ("arrow*", ">=59", "batches are stamped with Arrow 58, which downstream readers check"),
]


def held_reasons() -> set[str]:
    """The holds whose reason is still true of the manifests."""
    python = tomllib.loads(read(ROOT / "quad-fast-py/Cargo.toml"))
    node = tomllib.loads(read(ROOT / "quad-fast-node/Cargo.toml"))
    reasons = set()
    pyo3 = python["dependencies"].get("pyo3", {})
    if "abi3-py38" in pyo3.get("features", []):
        reasons.add("pyo3*")
    napi = node["dependencies"].get("napi", {})
    napi = napi.get("version", "") if isinstance(napi, dict) else napi
    if napi.split(".")[0] == "2":
        reasons.update({"napi", "napi-derive"})
    workspace = tomllib.loads(read(ROOT / "Cargo.toml"))["workspace"]["dependencies"]
    arrow = [
        spec.get("version", "") if isinstance(spec, dict) else spec
        for name, spec in workspace.items()
        if name == "arrow" or name.startswith("arrow-")
    ]
    if arrow and all(version.startswith("=58.") for version in arrow):
        reasons.add("arrow*")
    return reasons


def assert_arrow_moves_together(update: dict) -> None:
    """Every Arrow crate moves in the same pull request as the others."""
    groups = update.get("groups") or {}
    # A dependency joins the first group that matches, so a group listed
    # before this one, or an exclusion from it, would split the Arrow crates.
    assert list(groups)[:1] == ["cargo-minor-and-patch"], (
        f"cargo-minor-and-patch must be the first cargo group, not {list(groups)[:1]}"
    )
    minor = groups["cargo-minor-and-patch"]
    assert minor.get("patterns") == ["*"] and "exclude-patterns" not in minor, (
        "minor and patch updates must arrive together, with nothing carved out"
    )
    assert minor.get("update-types") == ["minor", "patch"]
    arrow = groups.get("arrow-major")
    assert arrow is not None, "Arrow majors must arrive as one pull request"
    assert arrow.get("patterns") == ["arrow", "arrow-*"], arrow.get("patterns")
    assert arrow.get("update-types") == ["major"]


def assert_dependabot_holds(document: dict) -> None:
    cargo = [u for u in document.get("updates") or [] if u.get("package-ecosystem") == "cargo"]
    assert cargo, "Dependabot has no cargo entry"
    assert_arrow_moves_together(cargo[0])
    ignored = {
        entry.get("dependency-name"): entry.get("versions") or []
        for update in cargo
        for entry in update.get("ignore") or []
    }
    for name, versions, reason in HOLDS:
        if name in held_reasons():
            assert ignored.get(name) == [versions], (
                f"Dependabot must hold {name} {versions} ({reason}); it ignores {ignored.get(name)}"
            )


# --- the repository passes every contract ------------------------------------


def workflow_id(path: Path) -> str:
    return path.name


def test_the_workflows_exist():
    assert {CI, RELEASE, AUDIT} <= set(ALL_WORKFLOWS)


@pytest.mark.parametrize("path", ALL_WORKFLOWS, ids=workflow_id)
def test_every_action_is_pinned_by_commit_sha(path: Path):
    assert_actions_pinned(read(path))
    assert_toolchain_named(read(path))


@pytest.mark.parametrize("path", ALL_WORKFLOWS, ids=workflow_id)
def test_no_workflow_wide_write_permission(path: Path):
    assert_least_privilege(read(path), path.name)


def test_only_the_publishing_job_holds_a_write_token():
    assert_publisher_writes(read(RELEASE))


def test_deny_and_audit_run_and_cannot_block_a_release():
    assert_audit_contract(read(AUDIT), read(CI), read(RELEASE))


def test_dependabot_covers_every_ecosystem_present():
    ecosystems = present_ecosystems(ROOT)
    assert {"cargo", "github-actions", "uv", "npm"} <= {name for name, _ in ecosystems}
    assert_dependabot_contract(read(DEPENDABOT), ecosystems)


def test_the_ecosystem_scan_finds_a_new_manifest(tmp_path: Path):
    (tmp_path / "Cargo.toml").write_text("[workspace]\n")
    (tmp_path / ".github/workflows").mkdir(parents=True)
    (tmp_path / ".github/workflows/ci.yml").write_text("name: ci\n")
    (tmp_path / "web").mkdir()
    (tmp_path / "web/package.json").write_text("{}")
    (tmp_path / "web/node_modules/dep").mkdir(parents=True)
    (tmp_path / "web/node_modules/dep/package.json").write_text("{}")
    (tmp_path / "locked").mkdir()
    (tmp_path / "locked/pyproject.toml").write_text("[project]\n")
    (tmp_path / "locked/uv.lock").write_text("version = 1\n")
    (tmp_path / "plain").mkdir()
    (tmp_path / "plain/requirements.txt").write_text("pytest\n")
    assert present_ecosystems(tmp_path) == {
        ("cargo", "/"),
        ("github-actions", "/"),
        ("npm", "/web"),
        ("uv", "/locked"),
        ("pip", "/plain"),
    }


# --- each contract rejects the regression it exists for ---------------------

CHECKOUT = "actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0"
CACHE = "Swatinem/rust-cache@d1527c8f67ef9af357290475d4af4b0fab8f12e0 # v2.9.3"
TOOLCHAIN = "dtolnay/rust-toolchain@683b588c487a69d01f6c6ddf40f036ff682cc2c8 # master"


def pinned(path: Path, original: str, replacement: str) -> None:
    assert_actions_pinned(read(path).replace(original, replacement, 1))


def toolchain(path: Path, original: str, replacement: str) -> None:
    assert_toolchain_named(read(path).replace(original, replacement, 1))


def privilege(path: Path, original: str, replacement: str) -> None:
    assert_least_privilege(read(path).replace(original, replacement, 1), path.name)


def publisher(path: Path, original: str, replacement: str) -> None:
    assert_publisher_writes(read(path).replace(original, replacement, 1))


def audit(path: Path, original: str, replacement: str) -> None:
    texts = {AUDIT: read(AUDIT), CI: read(CI), RELEASE: read(RELEASE), DENY_CONFIG: read(DENY_CONFIG)}
    texts[path] = texts[path].replace(original, replacement, 1)
    assert_audit_contract(texts[AUDIT], texts[CI], texts[RELEASE], texts[DENY_CONFIG])


def dependabot(path: Path, original: str, replacement: str) -> None:
    assert_dependabot_contract(
        read(path).replace(original, replacement, 1), present_ecosystems(ROOT)
    )


MUTATIONS = [
    # 1. pinning
    (pinned, CI, CHECKOUT, "actions/checkout@v4"),
    (pinned, CI, CHECKOUT, "actions/checkout@11d5960a326750d5838078e36cf38b85af677262"),
    (pinned, CI, CHECKOUT, "actions/checkout@11d5960a"),
    (pinned, RELEASE, TOOLCHAIN, "dtolnay/rust-toolchain@1.98.1"),
    (pinned, RELEASE, TOOLCHAIN, "dtolnay/rust-toolchain@683b588c487a69d01f6c6ddf40f036ff682cc2c8 # v1"),
    (pinned, AUDIT, CHECKOUT, "actions/checkout@main # v4.4.0"),
    (pinned, CI, f"- uses: {CACHE}", f"- {{uses: {CACHE.split(' #')[0]}}}"),
    (toolchain, CI, "toolchain: 1.98.1", "toolchain: stable"),
    # 2. least privilege
    (privilege, RELEASE, "permissions:\n  contents: read\n", "permissions:\n  contents: write\n"),
    (privilege, RELEASE, "permissions:\n  contents: read\n", "permissions: write-all\n"),
    (privilege, CI, "permissions:\n  contents: read\n", ""),
    (privilege, AUDIT, "permissions:\n  contents: read\n", "permissions:\n  contents: read\n  packages: write\n"),
    (
        privilege,
        RELEASE,
        "  wheels:\n    needs: verify\n",
        "  wheels:\n    needs: verify\n    permissions:\n      contents: write\n",
    ),
    (audit, CI, "      - run: cargo test --workspace --locked\n", "      - run: cargo test --workspace --locked\n      - run: cargo deny --locked check\n"),
    (
        privilege,
        RELEASE,
        "    permissions:\n      contents: write\n",
        "    permissions:\n      contents: write\n      id-token: write\n",
    ),
    (publisher, RELEASE, "    permissions:\n      contents: write\n", ""),
    # 3. deny and audit
    (audit, AUDIT, "run: cargo deny --locked check", "run: echo skipped"),
    (audit, AUDIT, "run: cargo audit --deny unsound", "run: echo skipped"),
    (audit, AUDIT, "cargo install cargo-deny --locked --version 0.20.2", "cargo install cargo-deny --locked"),
    (audit, AUDIT, "cargo install cargo-audit --locked --version 0.23.0", "cargo install cargo-audit"),
    (audit, AUDIT, "  pull_request:\n", ""),
    (audit, AUDIT, "  push:\n    branches: [main]\n", ""),
    (audit, AUDIT, "  pull_request:\n", "  pull_request:\n    paths: [Cargo.lock]\n"),
    (
        audit,
        RELEASE,
        "    uses: ./.github/workflows/ci.yml\n",
        "    uses: ./.github/workflows/ci.yml\n  advisories:\n    uses: ./.github/workflows/audit.yml\n",
    ),
    (audit, DENY_CONFIG, 'unsound = "all"\n', ""),
    (audit, DENY_CONFIG, 'unmaintained = "all"\n', 'unmaintained = "workspace"\n'),
    (audit, DENY_CONFIG, "ignore = []", 'ignore = ["RUSTSEC-2026-0442"]'),
    # 4. Dependabot
    (dependabot, DEPENDABOT, "package-ecosystem: npm", "package-ecosystem: bundler"),
    (dependabot, DEPENDABOT, "package-ecosystem: uv", "package-ecosystem: pip"),
    (dependabot, DEPENDABOT, '- dependency-name: "pyo3*"', '- dependency-name: "pyo3-ffi"'),
    (dependabot, DEPENDABOT, '- ">=0.30"', '- ">=0.31"'),
    (dependabot, DEPENDABOT, '- dependency-name: "napi"\n', '- dependency-name: "napi-sys"\n'),
    (dependabot, DEPENDABOT, '- dependency-name: "napi-derive"', '- dependency-name: "napi-build"'),
    (dependabot, DEPENDABOT, '      - dependency-name: "arrow*"\n', '      - dependency-name: "arrow"\n'),
    (dependabot, DEPENDABOT, '          - ">=59"\n', '          - ">=60"\n'),
    (dependabot, DEPENDABOT, "      arrow-major:", "      arrow-anything:"),
    (dependabot, DEPENDABOT, '          - "arrow-*"\n', ""),
    (
        dependabot,
        DEPENDABOT,
        "        update-types:\n          - minor\n",
        "        exclude-patterns:\n          - arrow-*\n        update-types:\n          - minor\n",
    ),
    (
        dependabot,
        DEPENDABOT,
        "      cargo-minor-and-patch:\n",
        "      arrow:\n        patterns:\n          - arrow-*\n      cargo-minor-and-patch:\n",
    ),
    (dependabot, DEPENDABOT, "package-ecosystem: github-actions", "package-ecosystem: docker"),
    (dependabot, DEPENDABOT, "directory: /quad-fast-py", "directory: /elsewhere"),
    (dependabot, DEPENDABOT, "interval: weekly", "interval: monthly"),
]


@pytest.mark.parametrize(
    "case",
    MUTATIONS,
    ids=[f"{index:02d}-{case[0].__name__}-{case[1].name}" for index, case in enumerate(MUTATIONS)],
)
def test_contracts_reject_regressions(case):
    contract, path, original, replacement = case
    assert original in read(path), f"the mutation no longer applies to {path.name}: {original!r}"
    contract(path, original, original)  # the unmutated file passes
    with pytest.raises(AssertionError):
        contract(path, original, replacement)
