"""Strict input loaders refuse Python's non-JSON numeric extension tokens."""

from __future__ import annotations

import json
import math
from pathlib import Path

import pytest

from adcs_lens.cli import EXIT_DATA_ERROR, main
from adcs_lens.ingest import IngestError, _load
from adcs_lens.suppression import load_suppressions

_CONSTANTS = ["NaN", "Infinity", "-Infinity"]


def _risk_text(token: str, location: str = "rule") -> str:
    metadata = '"metadata":{"nested":[{"value":' + token + "}]}"
    rule = '{"check":"ESC8","reason":"Synthetic reviewed exception"'
    if location == "rule":
        rule += "," + metadata
    document = '{"suppressions":[' + rule + "}]"
    if location == "document":
        document += "," + metadata
    return document + "}"


@pytest.mark.parametrize("token", _CONSTANTS)
@pytest.mark.parametrize("location", ["rule", "document"])
def test_suppression_numeric_extensions_are_refused(
    tmp_path: Path, token: str, location: str
) -> None:
    path = tmp_path / "risks.json"
    path.write_text(_risk_text(token, location), encoding="utf-8-sig")
    original = path.read_bytes()
    with pytest.raises(ValueError, match="non-standard JSON constant"):
        load_suppressions(path)
    assert path.read_bytes() == original


@pytest.mark.parametrize("token", _CONSTANTS)
def test_export_numeric_extensions_are_ingest_errors(tmp_path: Path, token: str) -> None:
    path = tmp_path / "ca-config.json"
    path.write_text('{"nested":[{"value":' + token + "}]}", encoding="utf-8-sig")
    original = path.read_bytes()
    with pytest.raises(IngestError, match="non-standard JSON constant"):
        _load(tmp_path, path.name)
    assert path.read_bytes() == original


@pytest.mark.parametrize("token", _CONSTANTS)
@pytest.mark.parametrize("format_args", [[], ["--json"], ["--sarif"], ["--html"]])
def test_doctor_never_renders_with_non_json_risk_metadata(
    json_export: Path,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    token: str,
    format_args: list[str],
) -> None:
    path = tmp_path / "risks.json"
    path.write_text(_risk_text(token), encoding="utf-8")
    assert main(["doctor", str(json_export), "--suppressions", str(path), *format_args]) == (
        EXIT_DATA_ERROR
    )
    captured = capsys.readouterr()
    assert captured.out == ""
    errors = [line for line in captured.err.splitlines() if line.startswith("error:")]
    assert len(errors) == 1
    assert "non-standard JSON constant" in errors[0]
    assert "Traceback" not in captured.err


@pytest.mark.parametrize("token", _CONSTANTS)
def test_cli_rejects_extension_even_in_unused_export_metadata(
    json_export: Path, capsys: pytest.CaptureFixture[str], token: str
) -> None:
    path = json_export / "collector-manifest.json"
    text = path.read_text(encoding="utf-8-sig")
    assert text.lstrip().startswith("{")
    text = text.lstrip()
    path.write_text('{"synthetic_numeric_extension":' + token + "," + text[1:])
    original = path.read_bytes()
    assert main(["ingest", str(json_export)]) == EXIT_DATA_ERROR
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "non-standard JSON constant" in captured.err
    assert "Traceback" not in captured.err
    assert path.read_bytes() == original


@pytest.mark.parametrize("value", _CONSTANTS)
def test_constant_words_inside_strings_remain_valid(tmp_path: Path, value: str) -> None:
    encoded = json.dumps(value)
    path = tmp_path / "risks.json"
    path.write_text(_risk_text(encoded), encoding="utf-8")
    rules = load_suppressions(path)
    assert len(rules) == 1 and rules[0].check == "ESC8"
    export = tmp_path / "ca-config.json"
    export.write_text('{"nested":[{"value":' + encoded + "}]}", encoding="utf-8")
    assert _load(tmp_path, export.name) == {"nested": [{"value": value}]}


@pytest.mark.parametrize("token", ["0", "-23", "1.25", "1e308", "-1.5e-400"])
def test_standard_number_grammar_retains_existing_handling(tmp_path: Path, token: str) -> None:
    path = tmp_path / "ca-config.json"
    path.write_text('{"value":' + token + "}", encoding="utf-8")
    loaded = _load(tmp_path, path.name)
    assert isinstance(loaded, dict)
    assert loaded["value"] == json.loads(token)
    assert math.isfinite(loaded["value"])


_OVERFLOWS = ["1e400", "-1e400", "1E+999", "2.5e400", "1" + "0" * 400 + ".0"]


@pytest.mark.parametrize("token", _OVERFLOWS)
def test_export_overflowing_number_is_an_ingest_error(tmp_path: Path, token: str) -> None:
    path = tmp_path / "ca-config.json"
    path.write_text('{"nested":[{"value":' + token + "}]}", encoding="utf-8")
    with pytest.raises(IngestError, match="non-finite JSON number"):
        _load(tmp_path, path.name)


@pytest.mark.parametrize("token", _OVERFLOWS)
@pytest.mark.parametrize("location", ["rule", "document"])
def test_suppression_overflowing_number_is_refused(
    tmp_path: Path, token: str, location: str
) -> None:
    path = tmp_path / "risks.json"
    path.write_text(_risk_text(token, location), encoding="utf-8")
    with pytest.raises(ValueError, match="non-finite JSON number"):
        load_suppressions(path)


@pytest.mark.parametrize("token", _OVERFLOWS)
def test_cli_rejects_overflowing_number_in_unused_export_metadata(
    json_export: Path, capsys: pytest.CaptureFixture[str], token: str
) -> None:
    path = json_export / "collector-manifest.json"
    text = path.read_text(encoding="utf-8-sig").lstrip()
    path.write_text('{"synthetic_number":' + token + "," + text[1:])
    assert main(["ingest", str(json_export)]) == EXIT_DATA_ERROR
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "non-finite JSON number" in captured.err
    assert "Traceback" not in captured.err
    assert max(len(line) for line in captured.err.splitlines()) < 1200
