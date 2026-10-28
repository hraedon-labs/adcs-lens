"""Rejected export fields cannot turn one CLI diagnostic into a large log."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from adcs_lens.cli import EXIT_DATA_ERROR, main


def _exports(tmp_path: Path, value: object) -> tuple[Path, Path, bytes]:
    good = tmp_path / "good"
    bad = tmp_path / "bad"
    for directory in (good, bad):
        directory.mkdir()
        (directory / "collector-manifest.json").write_text("{}", encoding="utf-8")
    path = bad / "ca-config.json"
    path.write_text(json.dumps([{"name": "LAB CA", "audit_filter": value}]), encoding="utf-8")
    return good, bad, path.read_bytes()


def _command(mode: str, good: Path, bad: Path) -> list[str]:
    command, _, output_format = mode.partition(":")
    if command == "diff-old":
        args = ["diff", str(bad), str(good)]
    elif command == "diff-new":
        args = ["diff", str(good), str(bad)]
    else:
        args = [command, str(bad)]
    return args + ([f"--{output_format}"] if output_format else [])


@pytest.mark.parametrize(
    "mode",
    [
        "ingest",
        "doctor",
        "doctor:json",
        "doctor:sarif",
        "doctor:html",
        "diff-old",
        "diff-old:json",
        "diff-old:sarif",
        "diff-old:html",
        "diff-new",
    ],
)
@pytest.mark.parametrize("structured", [False, True], ids=["string", "object"])
def test_large_invalid_fields_have_bounded_cli_errors(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], mode: str, structured: bool
) -> None:
    value: object = {"bad": "X" * 32_768} if structured else "X" * 32_768
    good, bad, before = _exports(tmp_path, value)

    assert main(_command(mode, good, bad)) == EXIT_DATA_ERROR

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith("error: invalid CA AuditFilter:")
    assert len(captured.err.splitlines()) == 1
    assert len(captured.err) < 1_100
    assert re.search(r"\.\.\.\[\d+ more chars\]\n$", captured.err)
    assert (bad / "ca-config.json").read_bytes() == before


@pytest.mark.parametrize("mode", ["ingest", "doctor", "diff-old", "diff-new"])
def test_short_cli_validation_errors_keep_their_context(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], mode: str
) -> None:
    good, bad, before = _exports(tmp_path, "not-a-number")

    assert main(_command(mode, good, bad)) == EXIT_DATA_ERROR

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "error: invalid CA AuditFilter: 'not-a-number'\n"
    assert (bad / "ca-config.json").read_bytes() == before
