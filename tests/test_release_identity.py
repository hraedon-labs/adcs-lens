"""The release identity gate (scripts/check_release_identity.py)."""

from __future__ import annotations

import importlib.util
import tarfile
import zipfile
from pathlib import Path
from types import ModuleType

import pytest

_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "check_release_identity.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_release_identity", _SCRIPT)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


cri = _load()

_CHANGELOG = """# Changelog

## [Unreleased]
{unreleased}
## [{top}] — 2026-10-10

### Fixed
- something

## [1.1.2] — 2026-07-01
"""


def _repo(tmp_path: Path, *, version: str = "1.2.0", top: str = "1.2.0",
          unreleased: str = "") -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "pyproject.toml").write_text(
        f'[project]\nname = "adcs-lens"\nversion = "{version}"\n', encoding="utf-8"
    )
    (tmp_path / "CHANGELOG.md").write_text(
        _CHANGELOG.format(top=top, unreleased=unreleased), encoding="utf-8"
    )
    return tmp_path


def test_consistent_release_passes(tmp_path: Path) -> None:
    assert cri.problems_for("v1.2.0", root=_repo(tmp_path)) == []


@pytest.mark.parametrize("tag", ["1.2.0", "v1.2", "v1.2.1", "v1.2.0-rc1", "refs/tags/v1.2.0"])
def test_tag_must_equal_v_plus_version(tmp_path: Path, tag: str) -> None:
    problems = cri.problems_for(tag, root=_repo(tmp_path))
    assert any("does not match pyproject" in p for p in problems)


def test_changelog_top_entry_must_match(tmp_path: Path) -> None:
    problems = cri.problems_for("v1.2.0", root=_repo(tmp_path, top="1.1.3"))
    assert any("top entry is [1.1.3]" in p for p in problems)


def test_unreleased_must_be_empty(tmp_path: Path) -> None:
    problems = cri.problems_for(
        "v1.2.0", root=_repo(tmp_path, unreleased="\n### Fixed\n- pending\n")
    )
    assert any("[Unreleased] is not empty" in p for p in problems)


def test_no_versioned_entry(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    (root / "CHANGELOG.md").write_text("# Changelog\n\n## [Unreleased]\n", encoding="utf-8")
    assert cri.problems_for("v1.2.0", root=root) == [
        "CHANGELOG.md has no versioned '## [X.Y.Z]' entry"
    ]


def _wheel(path: Path, version: str) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr(
            f"adcs_lens-{version}.dist-info/METADATA",
            f"Metadata-Version: 2.4\nName: adcs-lens\nVersion: {version}\n",
        )
    return path


def _sdist(path: Path, version: str) -> Path:
    info = path.parent / "PKG-INFO"
    info.write_text(f"Metadata-Version: 2.4\nName: adcs-lens\nVersion: {version}\n")
    with tarfile.open(path, "w:gz") as tf:
        tf.add(info, arcname=f"adcs_lens-{version}/PKG-INFO")
    return path


def test_built_distributions_must_carry_the_version(tmp_path: Path) -> None:
    root = _repo(tmp_path / "repo")
    good_w = _wheel(tmp_path / "good.whl", "1.2.0")
    good_s = _sdist(tmp_path / "good.tar.gz", "1.2.0")
    assert cri.problems_for("v1.2.0", root=root, wheel=good_w, sdist=good_s) == []
    bad_w = _wheel(tmp_path / "bad.whl", "1.2.0.dev0")
    (tmp_path / "s").mkdir()
    bad_s = _sdist(tmp_path / "s" / "bad.tar.gz", "1.1.2")
    problems = cri.problems_for("v1.2.0", root=root, wheel=bad_w, sdist=bad_s)
    assert len(problems) == 2


def test_this_repo_reports_pending_unreleased_entries() -> None:
    # The real repository today: pyproject says 1.2.0 and [1.2.0] is the top
    # entry, but [Unreleased] carries changes -- so a v1.2.0 tag is refused
    # until the owner cuts the release notes.
    problems = cri.problems_for(f"v{cri.pyproject_version()}")
    assert all("Unreleased" in p for p in problems)


def test_release_workflow_has_least_privilege_and_no_token() -> None:
    wf = (Path(__file__).resolve().parent.parent / ".github" / "workflows" / "release.yml")
    text = wf.read_text(encoding="utf-8")
    assert "permissions: {}" in text
    assert "password:" not in text and "PYPI_API_TOKEN" not in text
    assert "if: vars.PYPI_PUBLISH == 'true'" in text
    assert "SOURCE_DATE_EPOCH" in text and "cmp " in text
    assert not (wf.parent / "publish.yml").exists()
