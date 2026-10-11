"""scripts/verify_action_pins.py: offline tests with a fake tag resolver.

The live check (real GitHub API) runs in the CI `verify-action-pins` job; here
the resolver is faked so the parsing and policy are tested without network.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

_ROOT = Path(__file__).resolve().parent.parent
_SCRIPT = _ROOT / "scripts" / "verify_action_pins.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("verify_action_pins", _SCRIPT)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


vap = _load()
REAL = "a" * 40
FAKE = "b" * 40


def _fake(repo: str, tag: str) -> str | None:
    return {("actions/checkout", "v6.0.3"): REAL}.get((repo, tag))


def _wf(tmp_path: Path, *lines: str) -> Path:
    (tmp_path / "ci.yml").write_text("jobs:\n  x:\n    steps:\n" + "\n".join(lines) + "\n")
    return tmp_path


def test_correct_pin_passes(tmp_path: Path) -> None:
    wf = _wf(tmp_path, f"      - uses: actions/checkout@{REAL} # v6.0.3")
    assert vap.problems(wf, _fake) == []


@pytest.mark.parametrize(
    ("line", "message"),
    [
        (f"      - uses: actions/checkout@{FAKE} # v6.0.3", "is not v6.0.3"),
        (f"      - uses: actions/checkout@{REAL} # v6", "exact version comment"),
        (f"      - uses: actions/checkout@{REAL} # v6.0", "exact version comment"),
        (f"      - uses: actions/checkout@{REAL}", "exact version comment"),
        ("      - uses: actions/checkout@v6.0.3", "not pinned to a full commit SHA"),
        ("      - uses: actions/checkout@main # v6.0.3", "not pinned to a full commit SHA"),
        (f"      - uses: actions/checkout@{REAL} # v9.9.9", "has no tag v9.9.9"),
    ],
)
def test_bad_pins_fail(tmp_path: Path, line: str, message: str) -> None:
    found = vap.problems(_wf(tmp_path, line), _fake)
    assert len(found) == 1 and message in found[0], found


def test_local_reusable_workflow_is_allowed(tmp_path: Path) -> None:
    assert vap.problems(_wf(tmp_path, "    uses: ./.github/workflows/ci.yml"), _fake) == []


def test_repo_workflows_use_only_exact_sha_pins() -> None:
    """Offline policy check over the real workflows (resolution is CI's job)."""
    found = vap.problems(_ROOT / ".github" / "workflows", lambda repo, tag: None)
    # With a resolver that knows no tags, every pin must fail ONLY on resolution:
    # none may fail the format/comment policy.
    assert found and all("has no tag" in p for p in found), found


# --- review round 2 (Sol): the workflow is parsed, not regexed ------------------


def _raw(tmp_path: Path, text: str) -> Path:
    (tmp_path / "wf.yml").write_text(text, encoding="utf-8")
    return tmp_path


def test_flow_style_unpinned_action_is_caught(tmp_path: Path) -> None:
    wf = _raw(
        tmp_path,
        "jobs:\n  x:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - { uses: actions/checkout@main }\n",
    )
    found = vap.problems(wf, _fake)
    assert found and "not pinned to a full commit SHA" in found[0]


def test_flow_style_pinned_action_passes(tmp_path: Path) -> None:
    wf = _raw(tmp_path, f"jobs:\n  x:\n    steps: [{{uses: actions/checkout@{REAL}}}] # v6.0.3\n")
    assert vap.problems(wf, _fake) == []


def test_non_string_uses_is_rejected(tmp_path: Path) -> None:
    wf = _raw(tmp_path, "jobs:\n  x:\n    steps:\n      - uses: [actions/checkout@main]\n")
    assert any("must be a plain string" in p for p in vap.problems(wf, _fake))


def test_uses_behind_an_alias_is_still_checked(tmp_path: Path) -> None:
    wf = _raw(tmp_path, "x: &step {uses: actions/checkout@main}\njobs:\n  y:\n    steps: [*step]\n")
    assert any("not pinned" in p for p in vap.problems(wf, _fake))


def test_resolve_tag_dereferences_an_annotated_tag(monkeypatch: pytest.MonkeyPatch) -> None:
    """resolve_tag follows an annotated tag object to the commit it points at,
    calling the ref endpoint then the tag-object endpoint (round-4 coverage)."""
    calls: list[str] = []

    def fake_api(path: str) -> dict[str, object]:
        calls.append(path)
        if path.endswith("/git/ref/tags/v1.2.3"):
            return {"object": {"sha": "t" * 40, "type": "tag"}}
        if path.endswith("/git/tags/" + "t" * 40):
            return {"object": {"sha": "c" * 40, "type": "commit"}}
        raise AssertionError(path)

    monkeypatch.setattr(vap, "_api", fake_api)
    assert vap.resolve_tag("owner/repo", "v1.2.3") == "c" * 40
    assert calls == [
        "repos/owner/repo/git/ref/tags/v1.2.3",
        "repos/owner/repo/git/tags/" + "t" * 40,
    ]


def test_resolve_tag_returns_a_lightweight_tag_commit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vap, "_api", lambda path: {"object": {"sha": "c" * 40, "type": "commit"}})
    assert vap.resolve_tag("owner/repo", "v1.0.0") == "c" * 40


def test_multidocument_workflow_is_parsed_not_raised(tmp_path: Path) -> None:
    """A multi-document workflow yields policy diagnostics, not a traceback."""
    wf = tmp_path / "wf"
    wf.mkdir()
    (wf / "a.yml").write_text(
        "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@main\n"
        "---\n"
        "jobs:\n  b:\n    steps:\n      - uses: actions/setup-python@main\n",
        encoding="utf-8",
    )
    found = vap.problems(wf, _fake)
    assert sum("not pinned" in p for p in found) == 2
