"""Threat-model <-> detector traceability (WI-023).

Locks ``docs/threat-model.md`` as the design spine: every ESC class it lists
must have a detector, every detector must be wired into ``run_all``, and every
hygiene row must be either implemented or explicitly deferred. If any of these
drift, a test here fails — that is the guard.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
_THREAT_MODEL = _REPO / "docs" / "threat-model.md"
_DETECTION_SRC = _REPO / "src" / "adcs_lens" / "detection.py"

# Maps each hygiene-table row name to the check identifier that implements it,
# or None when the check is deferred. When a detector is added for a deferred
# row, move its value from None to the check string — the test will fail until
# you do, which is the point.
HYGIENE_STATUS: dict[str, str | None] = {
    "CA cert expiry": "CA_CERT_EXPIRY",
    "CRL signing expiry": "CA_CERT_EXPIRY",
    "CRL freshness": "CRL_EXPIRY",
    "CDP / AIA reachability": "CDP_AIA_ABSENT",
    "OCSP URL presence": "OCSP_URL_ABSENT",
    "Weak signing algorithm": "WEAK_SIG_ALG",
    "Weak key length": "WEAK_KEY_SIZE",
    "Audit configuration": "CA_AUDIT_DISABLED",
    "Orphaned / unused templates": "ORPHANED_TEMPLATE",
}


def _esc_rows_in_threat_model() -> list[tuple[str, str]]:
    """Return ``(esc_id, detectability)`` pairs from the catalogue table.

    The detectability cell is the third column. ``Static`` and
    ``Static (enabling config)`` verdicts must have a detector; ``Out`` and
    ``Out (unresolved)`` verdicts must not. This is what closes the gap that let
    ESC12 sit silently absent: every ESC number in the range must appear with a
    verdict, and only static verdicts require a detector.
    """
    text = _THREAT_MODEL.read_text(encoding="utf-8")
    # Stop at the hygiene section so we only parse the ESC catalogue table.
    section = text.split("## Non-ESC hygiene & lifecycle")[0]
    rows: list[tuple[str, str]] = []
    for line in section.splitlines():
        m = re.match(r"^\|\s*(ESC\d+)\s*\|(.*)$", line)
        if not m:
            continue
        cells = m.group(2).split("|")
        # cells[0] is "What it is", cells[1] is "Detectability".
        detectability = cells[1].strip() if len(cells) > 1 else ""
        rows.append((m.group(1), detectability))
    return rows


def _esc_detectors() -> set[str]:
    """Extract ESC IDs that have a ``detect_escN`` function in detection.py."""
    tree = ast.parse(_DETECTION_SRC.read_text(encoding="utf-8"))
    ids: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name.startswith("detect_esc"):
            ids.add(node.name.removeprefix("detect_").upper())
    return ids


def _all_detect_functions() -> set[str]:
    """Every public ``detect_*`` function defined in detection.py."""
    tree = ast.parse(_DETECTION_SRC.read_text(encoding="utf-8"))
    return {
        node.name
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name.startswith("detect_")
        and not node.name.startswith("_")
    }


def _run_all_called_detectors() -> set[str]:
    """Every ``detect_*`` function called inside ``run_all``'s body."""
    tree = ast.parse(_DETECTION_SRC.read_text(encoding="utf-8"))
    called: set[str] = set()
    for node in tree.body:
        if not (isinstance(node, ast.FunctionDef) and node.name == "run_all"):
            continue
        for inner in ast.walk(node):
            if isinstance(inner, ast.Call) and isinstance(inner.func, ast.Name):
                if inner.func.id.startswith("detect_"):
                    called.add(inner.func.id)
    return called


def _hygiene_rows_in_threat_model() -> set[str]:
    """Extract the first-column check name from the hygiene table."""
    text = _THREAT_MODEL.read_text(encoding="utf-8")
    section = text.split("## Non-ESC hygiene & lifecycle")[1]
    rows: set[str] = set()
    for line in section.splitlines():
        m = re.match(r"^\|\s*(.+?)\s*\|", line)
        if not m:
            continue
        name = m.group(1)
        if name.lower() == "check":
            continue
        if set(name) <= {"-"}:
            continue
        rows.add(name)
    return rows


def _check_literals_in_detection() -> set[str]:
    """Every ``check="..."`` literal passed to ``Finding`` in detection.py."""
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
    return emitted


def _info_check_literals_in_detection() -> set[str]:
    """Every check id passed to a ``Finding`` whose severity is ``Severity.INFO``.

    Used to lock the ``_DEGRADATION_NOTES`` set (WI-030): an INFO-severity
    finding is, by project convention, a coverage-gap note excluded from the
    ``--exit-code`` gate. If a new INFO degrade note ships without being added
    to that set, the gate silently re-trips on clean estates.
    """
    tree = ast.parse(_DETECTION_SRC.read_text(encoding="utf-8"))
    emitted: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not (isinstance(func, ast.Name) and func.id == "Finding"):
            continue
        check = None
        is_info = False
        for kw in node.keywords:
            if kw.arg == "check" and isinstance(kw.value, ast.Constant):
                check = kw.value.value
            if kw.arg == "severity" and isinstance(kw.value, ast.Attribute):
                is_info = kw.value.attr == "INFO"
        if check is not None and is_info:
            emitted.add(check)
    return emitted


def _verdict_of(detectability: str) -> str:
    """Extract the bolded verdict token from a detectability cell.

    e.g. '**Static (enabling config)** -- ...' -> 'Static (enabling config)'.
    """
    m = re.match(r"^\*\*(.+?)\*\*", detectability)
    return m.group(1) if m else detectability


# Verdicts that require a detector (the condition is statically readable AND
# the detector is built). Everything else (Out, Out (unresolved),
# Static (not yet implemented)) is exempt.
_IMPLEMENTED_VERDICTS: frozenset[str] = frozenset({"Static", "Static (enabling config)"})


def test_esc_threat_model_matches_detectors() -> None:
    """Every implemented ESC class has a detector, and vice versa.

    Only ``Static`` / ``Static (enabling config)`` verdicts require a detector;
    ``Out``, ``Out (unresolved)``, and ``Static (not yet implemented)`` are
    exempt. This is what lets ESC12 be documented as unresolved without forcing a
    stub detector, while still keeping the catalogue honest: every row must carry
    a recognized verdict.
    """
    rows = _esc_rows_in_threat_model()
    row_ids = {esc for esc, _ in rows}
    implemented_ids = {esc for esc, det in rows if _verdict_of(det) in _IMPLEMENTED_VERDICTS}
    deferred_ids = {esc for esc, det in rows if _verdict_of(det) not in _IMPLEMENTED_VERDICTS}
    assert implemented_ids | deferred_ids == row_ids, (
        "ESC rows with an unrecognized verdict: "
        f"{sorted(row_ids - (implemented_ids | deferred_ids))}"
    )
    det = _esc_detectors()
    missing_detectors = implemented_ids - det
    stray_detectors = det - implemented_ids
    assert not missing_detectors, (
        "ESC threat-model rows marked Static (implemented) but no detector:\n"
        f"  {sorted(missing_detectors)}"
    )
    assert not stray_detectors, (
        "detectors exist for ESC classes not marked Static (implemented):\n"
        f"  {sorted(stray_detectors)}"
    )


def test_esc_catalogue_has_no_silent_gaps() -> None:
    """The ESC catalogue accounts for a contiguous range with no missing numbers.

    This is the guard that would have caught ESC12's silent absence: a number
    can be skipped only if it appears with an explicit ``Out``/``Out
    (unresolved)`` verdict, never by simple omission. ESC numbering is
    1-based and contiguous from 1 to the highest declared number.
    """
    rows = _esc_rows_in_threat_model()
    numbers = sorted(int(esc[3:]) for esc, _ in rows)
    assert numbers, "no ESC rows found in the threat model"
    expected = list(range(1, numbers[-1] + 1))
    assert numbers == expected, (
        "ESC catalogue is not contiguous; missing numbers must be added with an "
        f"explicit Out verdict (or implemented): missing {sorted(set(expected) - set(numbers))}"
    )


def test_run_all_calls_every_detector() -> None:
    """No detector function is accidentally left out of run_all."""
    defined = _all_detect_functions()
    called = _run_all_called_detectors()
    assert defined == called, (
        "run_all wiring mismatch:\n"
        f"  defined but not called by run_all: {sorted(defined - called)}\n"
        f"  called by run_all but not defined: {sorted(called - defined)}"
    )


def test_hygiene_rows_all_accounted_for() -> None:
    """Every hygiene row in the threat model is implemented or explicitly deferred."""
    rows = _hygiene_rows_in_threat_model()
    known = set(HYGIENE_STATUS)
    assert rows == known, (
        "hygiene row drift:\n"
        f"  in threat model but not in HYGIENE_STATUS: {sorted(rows - known)}\n"
        f"  in HYGIENE_STATUS but not in threat model: {sorted(known - rows)}"
    )


def test_hygiene_status_matches_detector_emissions() -> None:
    """Every implemented hygiene row maps to a check a detector actually emits.

    This closes the gap where a row is marked implemented in ``HYGIENE_STATUS``
    but the check id is stale, or vice versa. (A deferred row mapped to ``None``
    cannot be checked for silent implementation because its future check id is
    unknown — adding the row to ``HYGIENE_STATUS`` at implementation time is the
    intended workflow, enforced by ``test_hygiene_rows_all_accounted_for``.)
    """
    emitted = _check_literals_in_detection()
    for row, check in HYGIENE_STATUS.items():
        if check is not None:
            assert check in emitted, (
                f"hygiene row {row!r} maps to {check!r} but no detector emits it"
            )


def test_degradation_notes_set_stays_in_sync() -> None:
    """Every INFO-severity check literal is a registered degradation note.

    WI-030 excludes ``_DEGRADATION_NOTES`` from the ``--exit-code`` gate. By
    project convention INFO severity marks only coverage-gap notes (a skipped
    collector pass), never a real posture finding. If a future detector adds
    an INFO degrade note without registering it in the set, the note would
    silently re-trip the CI gate on a clean estate — the exact bug WI-030 fixed.
    Mirrors the consequences-catalogue AST guard.
    """
    from adcs_lens.detection import _DEGRADATION_NOTES

    info_checks = _info_check_literals_in_detection()
    assert info_checks == _DEGRADATION_NOTES, (
        "INFO-severity check literals and _DEGRADATION_NOTES drifted:\n"
        f"  emitted INFO checks not in the set (would re-trip --exit-code): "
        f"{sorted(info_checks - _DEGRADATION_NOTES)}\n"
        f"  in the set but not emitted (stale entry): "
        f"{sorted(_DEGRADATION_NOTES - info_checks)}"
    )
