"""Round-5 reviewer probes of ``adcs-lens diff``, replayed as regression tests.

DeepSeek round 5 (eb3c426) NEW BLOCKING 1: an incomplete declared container was
enforced on the resolution path only. A partial enrollment-services enumeration
(an honest collector marks it ``complete: false``) still let
ORPHANED_TEMPLATE report every template whose publisher row was lost as a NEW
finding — exit 1 (regressions) with ``coverage_lost`` false. The related ESC15
case: a partial CA list with no visible issuing CA made the worst patch state
UNKNOWN, a new MEDIUM finding drawn from missing rows.

Sol round 5 NEW BLOCKING 1 (a DC returned without dNSHostName, dropped by the
collector under a complete marker) needs the collector itself and is replayed in
tests/test_collector_simulated.py.

This module uses only the export files and the CLI, so it runs unchanged at
eb3c426, where both cases fail.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

import pytest

from adcs_lens.cli import main
from tests.fixtures.build_fixture import ISSUING_CA, ROOT_CA
from tests.test_diff_coverage import build_full_export

pytest.importorskip("cryptography")
pytestmark = pytest.mark.certs


def _rw(path: Path, fn: Any) -> None:
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    out = fn(data)
    path.write_text(json.dumps(data if out is None else out), encoding="utf-8")


def _incomplete(base: Path, container: str, rows: int) -> None:
    def m(d: dict[str, Any]) -> None:
        d["enumeration"][container] = {"complete": False, "count": rows}

    _rw(base / "collector-manifest.json", m)


def _diff(old: Path, new: Path, capsys: pytest.CaptureFixture[str]) -> tuple[int, Any]:
    rc = main(["diff", str(old), str(new), "--exit-code", "--json"])
    return rc, json.loads(capsys.readouterr().out)


def test_ds_r5_partial_enrollment_services_invents_no_orphaned_template(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """DS's probe_es.py: every CA's template list lost, the container incomplete.

    eb3c426: NEW ORPHANED_TEMPLATE (a published template), exit 1, coverage_lost
    false.
    """
    old = build_full_export(tmp_path / "old")
    new = tmp_path / "new"
    shutil.copytree(old, new)
    _rw(new / "enrollment-services.json", lambda d: {k: [] for k in d})
    services = json.loads((new / "enrollment-services.json").read_text(encoding="utf-8"))
    _incomplete(new, "enrollment-services", len(services))
    rc, env = _diff(old, new, capsys)
    assert "ORPHANED_TEMPLATE" not in {f["check"] for f in env["new"]}
    assert env["summary"]["regressions"] is False
    assert env["summary"]["coverage_lost"] is True
    assert rc == 3


def test_ds_r5_partial_ca_list_invents_no_esc15(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """DS's related case: every CA patched (no ESC15); the newer CA search lost
    both issuing CAs and is marked incomplete.

    eb3c426: the worst patch state of no visible issuing CA was UNKNOWN, a NEW
    MEDIUM ESC15 finding, exit 1.
    """
    old = build_full_export(tmp_path / "old")
    _rw(
        old / "ca-config.json",
        lambda cas: [c.__setitem__("ca_patch_state", "patched") for c in cas] and None,
    )
    new = tmp_path / "new"
    shutil.copytree(old, new)
    _rw(new / "ca-config.json", lambda cas: [c for c in cas if c["kind"] == "root"])
    _incomplete(new, "ca-config", 1)
    # A failed enrollment-services object writes neither its CA row nor its
    # publication entry, and ca-security.json is keyed by the rows written.
    _rw(new / "enrollment-services.json", lambda es: {})
    _incomplete(new, "enrollment-services", 0)
    _rw(new / "ca-security.json", lambda sec: {k: v for k, v in sec.items() if k == ROOT_CA})
    rc, env = _diff(old, new, capsys)
    assert "ESC15" not in {f["check"] for f in env["new"]}
    assert env["summary"]["regressions"] is False
    assert env["summary"]["coverage_lost"] is True
    assert rc == 3
    assert ISSUING_CA not in {f["subject"] for f in env["new"]}
