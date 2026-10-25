"""Ambiguous risk acceptance is refused before findings are rendered."""

from __future__ import annotations

from pathlib import Path

import pytest

from adcs_lens.cli import EXIT_DATA_ERROR, main
from adcs_lens.suppression import load_suppressions


@pytest.mark.parametrize(
    "document",
    [
        '{"suppressions": [], "suppressions": []}',
        '{"suppressions": [{"check": "ESC8", "check": "ESC6", "reason": "reviewed"}]}',
        '{"suppressions": [{"check": "ESC8", "reason": "reviewed", '
        '"subject": "/synthetic-a", "subject": null}]}',
        '{"suppressions": [{"check": "ESC8", "reason": "first", "reason": "second"}]}',
        '{"suppressions": [{"check": "ESC8", "reason": "reviewed", '
        '"expires": "2020-01-01", "expires": null}]}',
        '{"suppressions": [{"check": "ESC8", "reason": "reviewed", '
        '"subject": "/synthetic-a", "subj\\u0065ct": null}]}',
        '{"suppressions": [], "metadata": {"note": "first", "note": "second"}}',
    ],
    ids=["list", "check", "subject", "reason", "expiry", "escaped-key", "metadata"],
)
def test_repeated_suppression_keys_are_refused_before_interpretation(
    tmp_path: Path, document: str
) -> None:
    path = tmp_path / "suppressions.json"
    path.write_text(document, encoding="utf-8-sig")
    before = path.read_bytes()
    with pytest.raises(ValueError, match="duplicate JSON key"):
        load_suppressions(path)
    assert path.read_bytes() == before


@pytest.mark.parametrize("format_args", [[], ["--json"], ["--sarif"], ["--html"]])
def test_doctor_does_not_render_with_ambiguous_risk_acceptance(
    json_export: Path,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    format_args: list[str],
) -> None:
    path = tmp_path / "suppressions.json"
    path.write_text(
        '{"suppressions": [{"check": "ESC6", "reason": "one synthetic CA", '
        '"subject": "Synthetic CA", "subject": null}]}',
        encoding="utf-8",
    )
    assert main(["doctor", str(json_export), "--suppressions", str(path), *format_args]) == (
        EXIT_DATA_ERROR
    )
    captured = capsys.readouterr()
    assert captured.out == ""
    errors = [line for line in captured.err.splitlines() if line.startswith("error:")]
    assert len(errors) == 1
    assert "duplicate JSON key" in errors[0]
    assert "Traceback" not in captured.err
