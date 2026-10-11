"""Tests for the plain-language consequences catalogue (WI-015)."""

from __future__ import annotations

import ast
import json
from pathlib import Path

from adcs_lens.consequences import (
    CONSEQUENCES,
    ConsequenceEntry,
    consequence_for,
)
from adcs_lens.detection import Finding, run_all
from adcs_lens.display import render_json, render_text
from adcs_lens.ingest import ingest
from adcs_lens.model import Severity
from tests.conftest import NOW

_DETECTION_SRC = Path(__file__).resolve().parent.parent / "src" / "adcs_lens" / "detection.py"


def test_esc6_entry_has_all_fields() -> None:
    entry = consequence_for("ESC6")
    assert isinstance(entry, ConsequenceEntry)
    assert entry.check == "ESC6"
    assert entry.summary
    assert entry.consequence
    assert entry.remediation


def test_unknown_check_returns_none() -> None:
    assert consequence_for("NONEXISTENT") is None


def test_no_entry_has_empty_fields() -> None:
    for entry in CONSEQUENCES.values():
        assert entry.summary.strip(), f"{entry.check} summary is empty"
        assert entry.consequence.strip(), f"{entry.check} consequence is empty"
        assert entry.remediation.strip(), f"{entry.check} remediation is empty"
        assert entry.summary.endswith((".", "!", "?")), (
            f"{entry.check} summary lacks terminal punctuation"
        )


def test_run_all_findings_have_consequences(json_export: Path) -> None:
    estate = ingest(json_export)
    findings = run_all(estate, now=NOW)
    emitted_checks = {f.check for f in findings}
    for check in sorted(emitted_checks):
        assert check in CONSEQUENCES, f"emitted check {check} has no consequence entry"


def test_catalogue_matches_every_check_literal_in_detection() -> None:
    """The catalogue must cover exactly the check identifiers detectors emit.

    This is the mechanical traceability guard: if a detector adds a new
    check="..." literal, this test fails until the catalogue gains the entry.
    No hand-maintained expected-set is involved — the catalogue is derived
    from the detectors' own source.
    """
    tree = ast.parse(_DETECTION_SRC.read_text(encoding="utf-8"))
    emitted: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        # Posture checks are emitted through the single verdict construction
        # site, _verdicts(estate, "<check>", "<variant>", fn); notes are built
        # as Finding(check="<NOTE>", ...).
        if isinstance(func, ast.Name) and func.id == "_verdicts":
            check_arg = node.args[1]
            if isinstance(check_arg, ast.Constant):
                emitted.add(check_arg.value)
            continue
        if not (isinstance(func, ast.Name) and func.id == "Finding"):
            continue
        for kw in node.keywords:
            if kw.arg == "check" and isinstance(kw.value, ast.Constant):
                emitted.add(kw.value.value)
    catalogue = set(CONSEQUENCES.keys())
    assert emitted == catalogue, (
        "check / catalogue mismatch:\n"
        f"  emitted by detectors but not in catalogue: {sorted(emitted - catalogue)}\n"
        f"  in catalogue but not emitted by detectors: {sorted(catalogue - emitted)}"
    )


def test_unknown_check_renders_null_consequence_in_json() -> None:
    finding = Finding(
        check="NO_SUCH_CHECK",
        severity=Severity.INFO,
        title="t",
        subject="s",
        detail="d",
        source="src",
    )
    data = json.loads(render_json([finding]))
    assert data["findings"][0]["consequence"] is None


def test_unknown_check_omits_plain_terms_in_text() -> None:
    finding = Finding(
        check="NO_SUCH_CHECK",
        severity=Severity.INFO,
        title="t",
        subject="s",
        detail="d",
        source="src",
    )
    text = render_text([finding])
    assert "in plain terms:" not in text
    assert "how to fix:" not in text
