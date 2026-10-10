#!/usr/bin/env python3
"""Release identity gate: the tag, pyproject version, and CHANGELOG must agree.

Run by .github/workflows/release.yml before anything is built, and again on
the built distributions. Stdlib only.

    python scripts/check_release_identity.py --tag v1.2.0
    python scripts/check_release_identity.py --tag v1.2.0 --wheel dist/x.whl --sdist dist/x.tar.gz

Checks (all must hold; each failure is reported):
  * the tag is exactly ``v`` + ``[project].version`` from pyproject.toml;
  * the CHANGELOG's top versioned entry (``## [X] ...``) is that version;
  * the ``[Unreleased]`` section is empty — a tagged release must not ship
    changes its own changelog entry does not describe;
  * with --wheel / --sdist: the version recorded in the built METADATA /
    PKG-INFO is that version too (what is published is what was checked).
"""

from __future__ import annotations

import argparse
import re
import sys
import tarfile
import tomllib
import zipfile
from email.parser import HeaderParser
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_HEADING = re.compile(r"^## \[(?P<version>[^\]]+)\]")


def pyproject_version(root: Path = ROOT) -> str:
    data = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    return str(data["project"]["version"])


def changelog_problems(text: str, version: str) -> list[str]:
    """Problems with CHANGELOG.md for releasing *version* (empty = ok)."""
    problems: list[str] = []
    headings = [
        (i, m.group("version"))
        for i, line in enumerate(text.splitlines())
        if (m := _HEADING.match(line))
    ]
    lines = text.splitlines()
    versioned = [(i, v) for i, v in headings if v.lower() != "unreleased"]
    if not versioned:
        return ["CHANGELOG.md has no versioned '## [X.Y.Z]' entry"]
    top_index, top_version = versioned[0]
    if top_version != version:
        problems.append(
            f"CHANGELOG.md top entry is [{top_version}], expected [{version}]"
        )
    for i, v in headings:
        if v.lower() != "unreleased":
            continue
        following = [j for j, _ in headings if j > i]
        end = following[0] if following else len(lines)
        body = [ln for ln in lines[i + 1 : end] if ln.strip()]
        if body:
            problems.append(
                "CHANGELOG.md [Unreleased] is not empty: move its entries under "
                f"[{version}] before tagging ({len(body)} line(s) pending)"
            )
        if i > top_index:
            problems.append("CHANGELOG.md [Unreleased] must sit above the versioned entries")
    return problems


def _metadata_version(raw: str) -> str:
    return str(HeaderParser().parsestr(raw).get("Version", ""))


def wheel_version(path: Path) -> str:
    with zipfile.ZipFile(path) as zf:
        name = next(n for n in zf.namelist() if n.endswith(".dist-info/METADATA"))
        return _metadata_version(zf.read(name).decode("utf-8"))


def sdist_version(path: Path) -> str:
    with tarfile.open(path, "r:gz") as tf:
        member = next(
            m for m in tf.getmembers() if m.name.count("/") == 1 and m.name.endswith("/PKG-INFO")
        )
        fh = tf.extractfile(member)
        if fh is None:
            raise ValueError(f"{path}: PKG-INFO is not a regular file")
        return _metadata_version(fh.read().decode("utf-8"))


def problems_for(
    tag: str,
    *,
    root: Path = ROOT,
    wheel: Path | None = None,
    sdist: Path | None = None,
) -> list[str]:
    version = pyproject_version(root)
    problems: list[str] = []
    if tag != f"v{version}":
        problems.append(f"tag {tag!r} does not match pyproject version 'v{version}'")
    problems += changelog_problems((root / "CHANGELOG.md").read_text(encoding="utf-8"), version)
    if wheel is not None and (got := wheel_version(wheel)) != version:
        problems.append(f"wheel {wheel.name} carries version {got!r}, expected {version!r}")
    if sdist is not None and (got := sdist_version(sdist)) != version:
        problems.append(f"sdist {sdist.name} carries version {got!r}, expected {version!r}")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--tag", required=True, help="the pushed tag, e.g. v1.2.0")
    parser.add_argument("--wheel", type=Path)
    parser.add_argument("--sdist", type=Path)
    args = parser.parse_args(argv)
    problems = problems_for(args.tag, wheel=args.wheel, sdist=args.sdist)
    for p in problems:
        print(f"release identity: {p}", file=sys.stderr)
    if problems:
        return 1
    print(f"release identity ok: {args.tag}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
