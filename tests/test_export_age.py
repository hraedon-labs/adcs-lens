"""Export staleness: stale / future-dated / unparseable collected_at is surfaced."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from adcs_lens.cli import main
from adcs_lens.detection import (
    STALE_EXPORT_DAYS_DEFAULT,
    detect_export_age,
    is_degradation_note,
    parse_collected_at,
    run_all,
)
from adcs_lens.ingest import ingest
from tests.fixtures.build_fixture import build_export

NOW = datetime(2026, 10, 9, 12, 0, 0, tzinfo=UTC)


def _export(tmp_path: Path, collected_at: str | None) -> Path:
    base = build_export(tmp_path / "e", now=NOW)
    path = base / "collector-manifest.json"
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    if collected_at is None:
        del data["collected_at"]
    else:
        data["collected_at"] = collected_at
    path.write_text(json.dumps(data), encoding="utf-8")
    return base


def _age_checks(tmp_path: Path, collected_at: str | None, **kw: int) -> list[str]:
    estate = ingest(_export(tmp_path, collected_at))
    return [f.check for f in detect_export_age(estate, now=NOW, **kw)]


def test_default_threshold_is_eight_days() -> None:
    assert STALE_EXPORT_DAYS_DEFAULT == 8


def test_collector_timestamp_format_parses() -> None:
    # The collector writes ToString('o') of a UTC time: 7 fractional digits + Z.
    parsed = parse_collected_at("2026-10-09T12:34:56.1234567Z")
    assert parsed == datetime(2026, 10, 9, 12, 34, 56, 123456, tzinfo=UTC)


@pytest.mark.parametrize(
    ("age", "expected"),
    [
        (timedelta(0), []),
        (timedelta(days=8), []),  # at the threshold: not stale
        (timedelta(days=8, seconds=1), ["EXPORT_STALE"]),
        (timedelta(days=400), ["EXPORT_STALE"]),
    ],
)
def test_stale_boundary(tmp_path: Path, age: timedelta, expected: list[str]) -> None:
    assert _age_checks(tmp_path, (NOW - age).isoformat()) == expected


def test_custom_threshold(tmp_path: Path) -> None:
    ts = (NOW - timedelta(days=3)).isoformat()
    assert _age_checks(tmp_path, ts, stale_days=2) == ["EXPORT_STALE"]
    assert _age_checks(tmp_path, ts, stale_days=3) == []


@pytest.mark.parametrize(
    ("collected_at", "title_part"),
    [
        (None, "unknown"),
        ("", "unknown"),
        ("yesterday", "unknown"),
        ("2026-10-09T12:00:00", "unknown"),  # no UTC offset: ambiguous
        ((NOW + timedelta(minutes=6)).isoformat(), "future"),
        ((NOW + timedelta(days=30)).isoformat(), "future"),
    ],
)
def test_invalid_or_future_timestamp(
    tmp_path: Path, collected_at: str | None, title_part: str
) -> None:
    estate = ingest(_export(tmp_path, collected_at))
    notes = detect_export_age(estate, now=NOW)
    assert [n.check for n in notes] == ["EXPORT_TIMESTAMP_INVALID"]
    assert title_part in notes[0].title


def test_small_future_skew_tolerated(tmp_path: Path) -> None:
    assert _age_checks(tmp_path, (NOW + timedelta(minutes=4)).isoformat()) == []


def test_notes_carry_clock_caveat_and_are_not_gated(tmp_path: Path) -> None:
    estate = ingest(_export(tmp_path, (NOW - timedelta(days=30)).isoformat()))
    (note,) = [f for f in run_all(estate, now=NOW) if f.check == "EXPORT_STALE"]
    assert "only if the collector host's clock was right" in note.detail
    assert is_degradation_note(note)


@pytest.mark.parametrize("fmt", [[], ["--json"], ["--html"], ["--sarif"]])
def test_stale_note_in_every_doctor_format(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], fmt: list[str]
) -> None:
    export = _export(tmp_path, "2020-01-01T00:00:00Z")
    assert main(["doctor", str(export), *fmt]) == 0
    captured = capsys.readouterr()
    assert "EXPORT_STALE" in captured.out
    assert "Export is older than the staleness threshold" in captured.err


def test_stale_warning_survives_severity_filter(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    export = _export(tmp_path, "2020-01-01T00:00:00Z")
    main(["doctor", str(export), "--severity", "critical"])
    captured = capsys.readouterr()
    assert "EXPORT_STALE" not in captured.out  # INFO filtered from the body...
    assert "staleness threshold" in captured.err  # ...but still on stderr


def test_env_threshold_applies(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    export = _export(tmp_path, (datetime.now(UTC) - timedelta(days=3)).isoformat())
    monkeypatch.setenv("ADCS_LENS_STALE_EXPORT_DAYS", "2")
    main(["doctor", str(export), "--json"])
    assert "EXPORT_STALE" in capsys.readouterr().out
    monkeypatch.setenv("ADCS_LENS_STALE_EXPORT_DAYS", "30")
    main(["doctor", str(export), "--json"])
    assert "EXPORT_STALE" not in capsys.readouterr().out


@pytest.mark.parametrize(
    "bad",
    ["", "0", "-1", "+8", "8.0", " 8", "8 ", "eight", "1e3", "36501", "08", "0008",
     "99999", "9" * 4301, "٣"],
)
@pytest.mark.parametrize("cmd", ["doctor", "ingest", "diff"])
def test_env_threshold_rejects_non_positive_integers(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    bad: str,
    cmd: str,
) -> None:
    export = build_export(tmp_path / "e")
    monkeypatch.setenv("ADCS_LENS_STALE_EXPORT_DAYS", bad)
    argv = [cmd, str(export)] + ([str(export)] if cmd == "diff" else [])
    assert main(argv) == 2
    assert "ADCS_LENS_STALE_EXPORT_DAYS must be a positive integer" in capsys.readouterr().err


def test_detector_rejects_non_positive_threshold(tmp_path: Path) -> None:
    estate = ingest(build_export(tmp_path / "e"))
    with pytest.raises(ValueError):
        detect_export_age(estate, now=NOW, stale_days=0)


def test_diff_warns_about_both_exports(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    old = _export(tmp_path / "o", "2020-01-01T00:00:00Z")
    new = _export(tmp_path / "n", "2021-01-01T00:00:00Z")
    main(["diff", str(old), str(new)])
    err = capsys.readouterr().err
    assert f"older export {old}: Export is older" in err
    assert f"newer export {new}: Export is older" in err
