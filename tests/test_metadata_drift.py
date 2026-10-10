"""Project metadata must name the repository's real owner (publication.toml)."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

from adcs_lens.display import PROJECT_URL

ROOT = Path(__file__).resolve().parent.parent


def _remote_owner() -> str:
    data = tomllib.loads((ROOT / "publication.toml").read_text(encoding="utf-8"))
    return str(data["publication"]["remote_owner"])


def _owner(url: str) -> str:
    m = re.match(r"https://github\.com/([^/]+)/adcs-lens(?:[/.]|$)", url)
    assert m, f"not a github.com/<owner>/adcs-lens URL: {url}"
    return m.group(1)


def test_pyproject_urls_owner_matches_publication_remote_owner() -> None:
    urls = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["urls"]
    assert urls, "pyproject [project.urls] is empty"
    for name, url in urls.items():
        assert _owner(url) == _remote_owner(), f"{name}: {url}"


def test_sarif_information_uri_owner_matches() -> None:
    assert _owner(PROJECT_URL) == _remote_owner()


def test_docs_never_link_a_different_github_owner() -> None:
    owner = _remote_owner()
    pattern = re.compile(r"github\.com/([A-Za-z0-9-]+)/adcs-lens")
    for path in [ROOT / "README.md", ROOT / "SECURITY.md", ROOT / "AGENTS.md",
                 *sorted((ROOT / "docs").glob("*.md"))]:
        for m in pattern.finditer(path.read_text(encoding="utf-8")):
            assert m.group(1) == owner, f"{path.name}: github.com/{m.group(1)}/adcs-lens"
