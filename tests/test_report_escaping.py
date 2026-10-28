"""Export text quoted in findings cannot forge report lines or emit control characters.

The text, HTML and narrative renderers (and CLI error/warning lines) escape
control characters in export-derived strings at render time. JSON and SARIF are
unchanged: their encoders already escape.
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import pytest

from adcs_lens.cli import EXIT_DATA_ERROR, _error, main
from adcs_lens.detection import Finding
from adcs_lens.diff import (
    CoverageChange,
    DriftReport,
    FindingDelta,
    FirstObservation,
    IndeterminateFinding,
    UnevaluatedCheck,
)
from adcs_lens.display import render_diff_html, render_diff_text, render_html, render_text
from adcs_lens.limits import escape_control
from adcs_lens.model import Severity
from adcs_lens.narration import generate_executive_summary

MARK = "FORGED-LINE"
# A line break, a bare CR, an ESC sequence, a line separator and a lone surrogate.
HOSTILE = f"x\n{MARK} [CRITICAL] ESC1 fake\r\x1b[2J\u2028\udc80"
FIELDS = ("check", "title", "subject", "detail", "source")


def _finding(**overrides: str) -> Finding:
    base = Finding(
        check="ESC1",
        severity=Severity.HIGH,
        title="Synthetic title",
        subject="LabTemplate",
        detail="Synthetic detail",
        source="templates.json",
    )
    return dataclasses.replace(base, **overrides)


def _assert_safe(output: str) -> None:
    """No export-supplied control character reaches the output; no forged line starts."""
    assert {ch for ch in output if not ch.isprintable()} <= {"\n"}
    for line in output.splitlines():
        assert not line.lstrip().startswith(MARK)


def _report(f: Finding) -> DriftReport:
    return DriftReport(
        new=(f,),
        resolved=(f,),
        changed=(FindingDelta(old=f, new=dataclasses.replace(f, severity=Severity.LOW)),),
        unchanged=0,
        indeterminate=(IndeterminateFinding(finding=f, reason=HOSTILE, current=None),),
        coverage_changes=(CoverageChange(finding=f, direction="appeared"),),
        unevaluated=(UnevaluatedCheck(check=HOSTILE, objects=1, reason=HOSTILE),),
        first_observed=(FirstObservation(finding=f, reason=HOSTILE),),
    )


@pytest.mark.parametrize("field", FIELDS)
def test_newline_in_any_finding_field_cannot_start_a_report_line(field: str) -> None:
    hostile = _finding(**{field: HOSTILE})
    # Same shape with a harmless value (a check name decides which catalogue lines follow).
    benign = _finding(**{field: "UNKNOWN_CHECK" if field == "check" else "plain"})

    text = render_text([hostile])
    _assert_safe(text)
    # The same line count as a benign finding: nothing was split.
    assert len(text.splitlines()) == len(render_text([benign]).splitlines())
    assert escape_control(HOSTILE) in text

    _assert_safe(render_html([hostile]))
    _assert_safe(generate_executive_summary([hostile]))
    assert len(generate_executive_summary([hostile]).splitlines()) == len(
        generate_executive_summary([benign]).splitlines()
    )

    # Every diff section carries the finding; the reasons are hostile in both cases.
    report = _report(hostile)
    diff_text = render_diff_text(report)
    _assert_safe(diff_text)
    assert len(diff_text.splitlines()) == len(render_diff_text(_report(benign)).splitlines())
    _assert_safe(render_diff_html(report))


def test_coverage_gap_note_fields_are_escaped_in_the_narrative() -> None:
    gap = _finding(check="CA_REGISTRY_NOT_EVALUATED", title=HOSTILE)
    _assert_safe(generate_executive_summary([gap]))


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("plain", "plain"),
        ("a\nb", "a\\nb"),
        ("a\r\nb", "a\\r\\nb"),
        ("\x1b[2J", "\\x1b[2J"),
        ("t\tab", "t\\tab"),
        ("sep\u2028", "sep\\u2028"),
        ("nb\u00a0sp", "nb\\xa0sp"),
        ("lone\udc80", "lone\\udc80"),
        # Spaces, backslashes, quotes and non-ASCII printable text read as collected.
        ("C:\\Windows  'x' \u00e9", "C:\\Windows  'x' \u00e9"),
    ],
)
def test_escape_control(text: str, expected: str) -> None:
    assert escape_control(text) == expected


def test_error_escapes_control_characters_itself(capsys: pytest.CaptureFixture[str]) -> None:
    assert _error(f"bad value {HOSTILE}") == EXIT_DATA_ERROR
    err = capsys.readouterr().err
    assert err.startswith("error: bad value x\\n")
    assert len(err.splitlines()) == 1
    assert err.endswith("\n")
    assert {ch for ch in err if not ch.isprintable()} == {"\n"}


def test_error_bounds_the_escaped_length(capsys: pytest.CaptureFixture[str]) -> None:
    # Escaping expands "\n" to two characters; the cap applies to the escaped text.
    _error("\n" * 5000)
    err = capsys.readouterr().err
    assert len(err) < 1_100
    assert "more chars]" in err


def _export_with_hostile_name(export: Path, name: str, hostile: str) -> None:
    for path in export.glob("*.json"):
        text = path.read_text(encoding="utf-8")
        if name in text:
            path.write_text(text.replace(name, json.dumps(hostile)[1:-1]), encoding="utf-8")


@pytest.mark.parametrize("extra", [[], ["--html"], ["--narrate"]])
def test_doctor_end_to_end_with_newline_in_export_text(
    json_export: Path, capsys: pytest.CaptureFixture[str], extra: list[str]
) -> None:
    _export_with_hostile_name(json_export, "LabWebServer", f"LabWebServer\n{MARK} [CRITICAL] fake")
    assert main(["doctor", str(json_export), *extra]) == 0
    captured = capsys.readouterr()
    for stream in (captured.out, captured.err):
        _assert_safe(stream)
    if "--narrate" not in extra:
        assert "LabWebServer\\n" + MARK in captured.out
    assert main(["doctor", str(json_export), "--json"]) == 0
    assert "LabWebServer\\n" + MARK in capsys.readouterr().out  # JSON encoding is unchanged
