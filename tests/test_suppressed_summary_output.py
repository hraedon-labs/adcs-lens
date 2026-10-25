"""Suppression diagnostics stay readable without changing matching or JSON."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from adcs_lens.cli import main
from adcs_lens.detection import Finding
from adcs_lens.model import Severity
from adcs_lens.suppression import (
    SuppressionResult,
    SuppressionRule,
    apply_suppressions,
    format_suppression_summary,
    suppression_summary,
)

HEADER = "suppressed 1 finding(s) by risk-acceptance rules:"


def _finding(check: str = "ESC8", subject: str = "LAB Issuing CA") -> Finding:
    return Finding(check, Severity.HIGH, "Synthetic finding", subject, "Synthetic", "Synthetic")


def _format(check: str, subject: str) -> str:
    return format_suppression_summary(SuppressionResult((_finding(check, subject),), (), (), ()))


@pytest.mark.parametrize("field", ["check", "subject"])
@pytest.mark.parametrize(
    ("control", "escaped"),
    [
        ("\n", r"\n"),
        ("\r", r"\r"),
        ("\t", r"\t"),
        ("\x1b", r"\x1b"),
        ("\0", r"\x00"),
        ("\ud800", r"\ud800"),
    ],
    ids=["newline", "carriage-return", "tab", "escape", "nul", "surrogate"],
)
def test_each_summary_field_escapes_controls(field: str, control: str, escaped: str) -> None:
    raw = {"check": "ESC8", "subject": "LAB Issuing CA"}
    raw[field] = "A" + control + "B"
    expected = {**raw, field: "A" + escaped + "B"}

    assert _format(**raw).splitlines() == [HEADER, f"  [{expected['check']}] {expected['subject']}"]


@pytest.mark.parametrize("field", ["check", "subject"])
@pytest.mark.parametrize("length", [81, 32_768, 100_000])
def test_each_summary_field_bounds_long_values(field: str, length: int) -> None:
    raw = {"check": "ESC8", "subject": "LAB Issuing CA"}
    raw[field] = "S" * length
    expected = {**raw, field: "S" * 80 + f"...[{length - 80} more chars]"}

    assert _format(**raw) == f"{HEADER}\n  [{expected['check']}] {expected['subject']}"


@pytest.mark.parametrize("length", [79, 80])
def test_short_plain_fields_keep_their_existing_output(length: int) -> None:
    subject = "S" * length
    assert _format("ESC8", subject) == f"{HEADER}\n  [ESC8] {subject}"


def test_display_does_not_change_matching_or_structured_metadata() -> None:
    subject = "S" * 100 + "\nSynthetic subject\x1b"
    finding = _finding(subject=subject)
    rule = SuppressionRule("ESC8", subject, "Full\noperator reason", None)
    result = apply_suppressions([finding], (rule,), now=datetime(2026, 10, 25, tzinfo=UTC))

    format_suppression_summary(result)

    assert result.suppressed == (finding,)
    assert result.remaining == ()
    assert suppression_summary(result, (rule,))["suppressed"] == [
        {"check": "ESC8", "subject": subject, "reason": "Full\noperator reason"}
    ]


@pytest.mark.parametrize(
    "subject",
    ["LAB\nSYNTHETIC EXTRA LINE", "LAB\x1b[31mCA", "S" * 32_768],
    ids=["newline", "escape", "long"],
)
def test_doctor_keeps_full_suppression_json_with_readable_stderr(
    json_export: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str], subject: str
) -> None:
    config_path = json_export / "ca-config.json"
    config = json.loads(config_path.read_text(encoding="utf-8-sig"))
    for ca in config:
        if ca["name"] == "LAB Issuing CA":
            ca["name"] = subject
    config_path.write_text(json.dumps(config), encoding="utf-8")
    # The export's CA references must follow the renamed synthetic CA.
    for filename in ("ca-security.json", "enrollment-services.json"):
        path = json_export / filename
        mapping = json.loads(path.read_text(encoding="utf-8-sig"))
        mapping[subject] = mapping.pop("LAB Issuing CA")
        path.write_text(json.dumps(mapping), encoding="utf-8")
    suppressions = tmp_path / "suppressions.json"
    suppressions.write_text(
        json.dumps(
            {
                "suppressions": [
                    {"check": check, "subject": subject, "reason": "Synthetic risk acceptance"}
                    for check in ("ESC6", "CA_AUDIT_DISABLED")
                ]
            }
        ),
        encoding="utf-8",
    )

    rc = main(
        [
            "doctor",
            str(json_export),
            "--json",
            "--exit-code",
            "--severity",
            "critical",
            "--suppressions",
            str(suppressions),
        ]
    )

    captured = capsys.readouterr()
    assert rc == 0, captured.err[:400]
    metadata = json.loads(captured.out)["suppressions"]
    assert metadata["suppressed_count"] == 2
    assert {row["subject"] for row in metadata["suppressed"]} == {subject}
    assert {row["check"] for row in metadata["suppressed"]} == {"ESC6", "CA_AUDIT_DISABLED"}
    assert subject not in captured.err
    assert "\x1b" not in captured.err
    assert "SYNTHETIC EXTRA LINE" not in captured.err.splitlines()
    assert all(len(line) < 600 for line in captured.err.splitlines())
