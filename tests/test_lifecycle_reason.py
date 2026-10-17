"""Why lifecycle was not evaluated: ingest names the cause, not just the fact.

The ingest line and the ``LIFECYCLE_NOT_EVALUATED`` note used to say only that
no cert/CRL data was parsed. A missing optional ``[certs]`` extra and an export
with no cert data look the same there, and the first cost a live re-check a
false defect lead (2026-10-14). The cause is recorded at ingest, where both
facts are known, and the CLI and the note repeat it.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from adcs_lens import ingest as ingest_mod
from adcs_lens.cli import main
from adcs_lens.detection import detect_infra_cert_expiry
from adcs_lens.ingest import ingest
from adcs_lens.model import (
    LIFECYCLE_EMPTY_INDEX,
    LIFECYCLE_EXTRA_MISSING,
    LIFECYCLE_NO_INDEX,
    LIFECYCLE_PASS_SKIPPED,
)
from tests.conftest import NOW
from tests.fixtures.build_fixture import inject_enumeration


def _unskip_certs(export: Path) -> None:
    path = export / "collector-manifest.json"
    manifest = json.loads(path.read_text(encoding="utf-8-sig"))
    manifest["skipped_passes"] = [p for p in manifest["skipped_passes"] if p != "certs"]
    path.write_text(json.dumps(manifest), encoding="utf-8")


def _write_index(export: Path, index: dict[str, object]) -> None:
    (export / "certs").mkdir(exist_ok=True)
    (export / "certs" / "index.json").write_text(json.dumps(index), encoding="utf-8")
    _unskip_certs(export)
    inject_enumeration(export)


def _note(estate: object) -> str:
    (finding,) = detect_infra_cert_expiry(estate, now=NOW)  # type: ignore[arg-type]
    assert finding.check == "LIFECYCLE_NOT_EVALUATED"
    return finding.detail


def test_extra_missing_names_the_extra_and_the_rows_it_could_not_parse(
    full_export: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # The export lists certs and CRLs; the [certs] extra is simulated absent.
    monkeypatch.setattr(ingest_mod, "_try_load_certs", lambda: None)
    estate = ingest(full_export)
    m = estate.manifest
    assert m.certs_parsed is False
    assert m.certs_not_parsed_reason == LIFECYCLE_EXTRA_MISSING
    assert (m.certs_index_certs, m.certs_index_crls) == (2, 2)
    assert estate.crls == ()
    assert main(["ingest", str(full_export)]) == 0
    out = capsys.readouterr().out
    assert "CRLs: 0" in out
    assert "lifecycle evaluated: False (the optional [certs] extra is not installed" in out
    assert "the 2 certificates and 2 CRLs the export lists were not parsed" in out
    detail = _note(estate)
    assert "Cause: the optional [certs] extra is not installed" in detail
    assert "pip install adcs-lens[certs]" in detail


def test_certs_pass_skipped_is_not_blamed_on_the_extra(
    json_export: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    estate = ingest(json_export)
    assert "certs" in estate.manifest.skipped_passes
    assert estate.manifest.certs_not_parsed_reason == LIFECYCLE_PASS_SKIPPED
    assert main(["ingest", str(json_export)]) == 0
    out = capsys.readouterr().out
    assert "lifecycle evaluated: False (the export's certs pass was skipped" in out
    assert "[certs]" not in out
    detail = _note(estate)
    assert "Cause: the export's certs pass was skipped" in detail
    assert "[certs] extra" not in detail


def test_missing_index_is_reported_as_missing_data(
    json_export: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Not listed as skipped, yet no certs/index.json: the export has no cert data.
    # A current collector always writes it (ingest refuses the gap), so use an
    # older one, whose absent files degrade to a missing pass.
    _unskip_certs(json_export)
    path = json_export / "collector-manifest.json"
    manifest = json.loads(path.read_text(encoding="utf-8-sig"))
    manifest["collector_version"] = "0.7.0"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    estate = ingest(json_export)
    assert estate.manifest.certs_not_parsed_reason == LIFECYCLE_NO_INDEX
    assert main(["ingest", str(json_export)]) == 0
    assert "(the export has no certs/index.json" in capsys.readouterr().out
    assert "Cause: the export has no certs/index.json" in _note(estate)


def test_empty_index_is_reported_as_no_cert_data(
    json_export: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _write_index(json_export, {"certs": [], "crls": []})
    estate = ingest(json_export)
    assert estate.manifest.certs_parsed is False
    assert estate.manifest.certs_not_parsed_reason == LIFECYCLE_EMPTY_INDEX
    assert (estate.manifest.certs_index_certs, estate.manifest.certs_index_crls) == (0, 0)
    assert main(["ingest", str(json_export)]) == 0
    assert "certs/index.json lists no certificates and no CRLs" in capsys.readouterr().out
    assert "Cause: certs/index.json lists no certificates and no CRLs" in _note(estate)


def test_empty_index_wins_over_a_missing_extra(
    json_export: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # With nothing listed, installing the extra would change nothing: do not send
    # the reader after it.
    monkeypatch.setattr(ingest_mod, "_try_load_certs", lambda: None)
    _write_index(json_export, {"certs": [], "crls": []})
    estate = ingest(json_export)
    assert estate.manifest.certs_not_parsed_reason == LIFECYCLE_EMPTY_INDEX


@pytest.mark.certs
def test_parsed_export_has_no_reason(full_export: Path, capsys: pytest.CaptureFixture[str]) -> None:
    estate = ingest(full_export)
    assert estate.manifest.certs_parsed is True
    assert estate.manifest.certs_not_parsed_reason == ""
    assert main(["ingest", str(full_export)]) == 0
    out = capsys.readouterr().out
    assert "lifecycle evaluated: True" in out
    assert "lifecycle evaluated: True (" not in out


def test_a_hand_built_manifest_keeps_the_two_cause_note() -> None:
    # No reason recorded (a Manifest not built by ingest): the note keeps naming
    # both possible causes rather than claiming one.
    from tests.test_detection import _estate

    (finding,) = detect_infra_cert_expiry(_estate(certs_parsed=False), now=NOW)
    assert "Two possible causes" in finding.detail
