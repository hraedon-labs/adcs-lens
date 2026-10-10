"""DeepSeek round-2 reviewer probes, replayed against the read-only gate.

The probe scripts under ``tests/fixtures/reviewer_probes/ds_r2/`` are the
reviewer's own files, copied verbatim. This module never executes them: it
reads their case tables with ``ast.literal_eval`` (a module whose cases are not
literal data is listed in ``_NOT_LOADABLE`` instead of being rewritten), appends
each case to the real collector, and asserts that the gate reports exactly the
checks recorded in ``expected.json``.

A case recorded with an empty list is a control the gate must accept. A case
with checks must be flagged by those checks, not merely by something, and must
also change the golden inventory (the closed world catches it regardless).

Regenerate the expectations after a deliberate gate change with
``ADCS_LENS_WRITE_PROBE_EXPECTATIONS=1 pytest tests/test_reviewer_probes_ds_r2.py``
and review the diff: a case moving from a check to ``[]`` is a regression.
"""

from __future__ import annotations

import ast
import json
import os
import re
from pathlib import Path

import pytest

from tests.test_collector_readonly import (
    INVENTORY,
    _collector_text,
    _dump,
    render_inventory,
    violations,
)

PROBES = Path(__file__).parent / "fixtures" / "reviewer_probes" / "ds_r2"
EXPECTED = PROBES / "expected.json"
_WRITE = os.environ.get("ADCS_LENS_WRITE_PROBE_EXPECTATIONS") == "1"
_TAG = re.compile(r"^\[[a-z-]+\]")

# Probe modules whose cases are built at runtime (f-strings) and so cannot be
# read as literal data. Their candidates are covered by the action-pin tests.
_NOT_LOADABLE = frozenset({"probe_actionpins.py"})


def _literal_cases(path: Path) -> dict[str, str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target, value = node.targets[0], node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            target, value = node.target, node.value
        else:
            continue
        if not (isinstance(target, ast.Name) and target.id.lower() in {"cases", "candidates"}):
            continue
        cases = ast.literal_eval(value)
        assert isinstance(cases, dict), path.name
        assert all(isinstance(k, str) and isinstance(v, str) for k, v in cases.items())
        return cases
    raise AssertionError(f"{path.name}: no literal `cases`/`candidates` table")


def _all_cases() -> dict[str, str]:
    out: dict[str, str] = {}
    for path in sorted(PROBES.glob("*.py")):
        if path.name in _NOT_LOADABLE:
            continue
        for name, snippet in _literal_cases(path).items():
            out[f"{path.stem}::{name}"] = snippet
    return out


CASES = _all_cases()


def _checks(found: list[str]) -> list[str]:
    tags = set()
    for v in found:
        m = _TAG.match(v)
        tags.add(m.group(0) if m else "[untagged]")
    return sorted(tags)


def test_every_probe_module_is_loaded_or_declared() -> None:
    present = {p.name for p in PROBES.glob("*.py")}
    assert _NOT_LOADABLE <= present, sorted(_NOT_LOADABLE - present)
    loaded = {key.split("::", 1)[0] + ".py" for key in CASES}
    assert loaded | _NOT_LOADABLE == present


@pytest.mark.skipif(not _WRITE, reason="set ADCS_LENS_WRITE_PROBE_EXPECTATIONS=1 to regenerate")
def test_write_expectations(tmp_path: Path) -> None:
    result: dict[str, list[str]] = {}
    for key, snippet in CASES.items():
        script = tmp_path / "collector-plus-probe.ps1"
        script.write_text(_collector_text() + "\n" + snippet + "\n", encoding="utf-8")
        result[key] = _checks(violations(_dump(script)))
    EXPECTED.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def test_expectations_cover_exactly_the_loaded_cases() -> None:
    expected = json.loads(EXPECTED.read_text(encoding="utf-8"))
    assert sorted(expected) == sorted(CASES)


@pytest.mark.parametrize("key", sorted(CASES))
def test_probe_is_flagged_by_the_recorded_checks(tmp_path: Path, key: str) -> None:
    expected = json.loads(EXPECTED.read_text(encoding="utf-8"))[key]
    script = tmp_path / "collector-plus-probe.ps1"
    script.write_text(_collector_text() + "\n" + CASES[key] + "\n", encoding="utf-8")
    dump = _dump(script)
    assert _checks(violations(dump)) == expected, key
    if expected:
        assert "[untagged]" not in expected, key
        assert render_inventory(dump) != INVENTORY.read_text(encoding="utf-8"), key
