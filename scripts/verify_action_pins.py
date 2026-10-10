#!/usr/bin/env python3
"""Verify every GitHub Actions pin names the commit its version comment claims.

    GITHUB_TOKEN=... python scripts/verify_action_pins.py [.github/workflows]

Every ``uses:`` line in the workflows must be either a local reusable workflow
(``./...``) or exactly ``owner/repo[/path]@<40-hex sha> # vX.Y.Z``: a full
commit SHA with an exact semantic-version comment (``# v4``, ``# v4.6`` or a
missing comment are rejected, since a moving major tag cannot be checked). For
each pin, the tag is resolved through the GitHub API
(``repos/<o>/<r>/git/ref/tags/<tag>``, dereferencing annotated tags through
``git/tags``) and must equal the pinned SHA. A fabricated or stale SHA fails.

Stdlib only. Uses GITHUB_TOKEN when set (CI), else unauthenticated requests.
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path

USES = re.compile(r"^\s*-?\s*uses:\s*(?P<ref>\S+)(?:\s*#\s*(?P<comment>.*?))?\s*$")
PIN = re.compile(r"^(?P<repo>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)(?:/[^@\s]+)?@(?P<sha>[0-9a-f]{40})$")
EXACT_VERSION = re.compile(r"^v\d+\.\d+\.\d+$")

Resolver = Callable[[str, str], str | None]


def _api(path: str) -> dict[str, object]:
    req = urllib.request.Request(
        f"https://api.github.com/{path}",
        headers={"Accept": "application/vnd.github+json", "User-Agent": "adcs-lens-pin-check"},
    )
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 (fixed host)
        data: dict[str, object] = json.load(resp)
        return data


def resolve_tag(repo: str, tag: str) -> str | None:
    """The commit SHA *tag* names in *repo*, or None if the tag does not exist."""
    try:
        ref = _api(f"repos/{repo}/git/ref/tags/{tag}")
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise
    obj = ref["object"]
    assert isinstance(obj, dict)
    sha, kind = str(obj["sha"]), str(obj["type"])
    while kind == "tag":  # annotated tag: dereference to what it points at
        tag_obj = _api(f"repos/{repo}/git/tags/{sha}")["object"]
        assert isinstance(tag_obj, dict)
        sha, kind = str(tag_obj["sha"]), str(tag_obj["type"])
    return sha


def problems(workflows: Path, resolve: Resolver = resolve_tag) -> list[str]:
    out: list[str] = []
    cache: dict[tuple[str, str], str | None] = {}
    files = sorted([*workflows.glob("*.yml"), *workflows.glob("*.yaml")])
    if not files:
        return [f"no workflow files under {workflows}"]
    for wf in files:
        for lineno, line in enumerate(wf.read_text(encoding="utf-8").splitlines(), 1):
            m = USES.match(line)
            if not m:
                continue
            where = f"{wf.name}:{lineno}"
            ref, comment = m.group("ref"), (m.group("comment") or "").strip()
            if ref.startswith("./"):
                continue  # local reusable workflow
            pin = PIN.match(ref)
            if pin is None:
                out.append(f"{where}: {ref!r} is not pinned to a full commit SHA")
                continue
            if not EXACT_VERSION.match(comment):
                out.append(
                    f"{where}: {ref!r} needs an exact version comment like '# v1.2.3', "
                    f"got {comment!r}"
                )
                continue
            key = (pin.group("repo"), comment)
            if key not in cache:
                cache[key] = resolve(*key)
            real = cache[key]
            if real is None:
                out.append(f"{where}: {key[0]} has no tag {comment}")
            elif real != pin.group("sha"):
                out.append(
                    f"{where}: {key[0]}@{pin.group('sha')} is not {comment} "
                    f"(which is {real})"
                )
    return out


def main(argv: list[str]) -> int:
    workflows = Path(argv[1]) if len(argv) > 1 else Path(".github/workflows")
    found = problems(workflows)
    for p in found:
        print(f"action pin: {p}", file=sys.stderr)
    if found:
        return 1
    print(f"action pins ok ({workflows})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
