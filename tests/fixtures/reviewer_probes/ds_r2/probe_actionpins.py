#!/usr/bin/env python3
"""Probe scripts/verify_action_pins.py policy edges with a faked API."""
from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path("/home/itadmin/wt/scratch/sibling-review/adcs-chore-sibling-review-2026-10-09-ds")
spec = importlib.util.spec_from_file_location("vap", ROOT / "scripts" / "verify_action_pins.py")
vap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vap)

REAL = "a" * 40


def wf(tmp: Path, *lines: str) -> Path:
    (tmp / "ci.yml").write_text("jobs:\n  x:\n    steps:\n" + "\n".join(lines) + "\n")
    return tmp


tmp = ROOT / ".review" / "tmp" / "wfprobe"
tmp.mkdir(parents=True, exist_ok=True)

cases = {
    "normal-pin": f"      - uses: actions/checkout@{REAL} # v6.0.3",
    "space-before-colon": f"      - uses: actions/checkout@{REAL} # v6.0.3".replace(
        "uses:", "uses :"
    ),
    "tab-indent": f"\t- uses: actions/checkout@{REAL} # v6.0.3",
    "quoted-uses-key": f'      - "uses": actions/checkout@{REAL} # v6.0.3',
    "quoted-value": f'      - uses: "actions/checkout@{REAL}" # v6.0.3',
    "comment-nospace": f"      - uses: actions/checkout@{REAL}# v6.0.3",
    "major-only": f"      - uses: actions/checkout@{REAL} # v6",
    "extra-comment": f"      - uses: actions/checkout@{REAL} # v6.0.3 (pin)",
    "not-a-pin": "      - uses: actions/checkout@v6.0.3",
}
for name, line in cases.items():
    found = vap.problems(wf(tmp, line), lambda repo, tag: REAL)
    print(f"{name:20s} -> {found!r}")

# Annotated tag dereference: tag object -> commit.
calls: list[str] = []


def fake_api(path: str) -> dict:
    calls.append(path)
    if path == "repos/actions/checkout/git/ref/tags/v6.0.3":
        return {"object": {"sha": "tagobj", "type": "tag"}}
    if path == "repos/actions/checkout/git/tags/tagobj":
        return {"object": {"sha": REAL, "type": "commit"}}
    raise RuntimeError(f"unexpected {path}")


vap._api_orig = vap._api
vap._api = fake_api  # type: ignore[assignment]
print("annotated deref ->", vap.resolve_tag("actions/checkout", "v6.0.3"), "calls:", calls)
vap._api = vap._api_orig  # type: ignore[assignment]

# Lightweight tag: type commit directly.
calls.clear()


def fake_api_light(path: str) -> dict:
    calls.append(path)
    return {"object": {"sha": REAL, "type": "commit"}}


vap._api = fake_api_light  # type: ignore[assignment]
print("lightweight deref ->", vap.resolve_tag("actions/checkout", "v6.0.3"), "calls:", calls)
vap._api = vap._api_orig  # type: ignore[assignment]
