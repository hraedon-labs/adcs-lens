"""Round-6 reviewer probe, replayed with the real collector body.

Kept free of round-7 test helpers so it runs unchanged against older commits
(it fails at 4b4903b and passes from the round-7 commit on).
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from adcs_lens.cli import main

_SIMULATE = Path(__file__).resolve().parent / "collector" / "simulate.ps1"
_PWSH = shutil.which("pwsh")
pytestmark = pytest.mark.skipif(_PWSH is None, reason="pwsh is not installed")


def _simulate(out: Path, *args: str) -> Path:
    assert _PWSH is not None
    proc = subprocess.run(
        [_PWSH, "-NoProfile", "-NonInteractive", "-File", str(_SIMULATE), "-OutDir", str(out)]
        + list(args),
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return out


def test_sol_r6_enrollment_service_without_cn_is_not_a_regression(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Sol round 6 NEW BLOCKING 1 (.review/probe-missing-es-cn.ps1), replayed.

    The collector runs on a host that is not a CA and the enrollment-services
    search returns 'LAB Issuing CA' without cn. At 4b4903b it wrote the row
    under the key '', both markers stayed complete, ingest skipped the blank
    publisher, and diff reported ORPHANED_TEMPLATE 'Lab Web Server' as new
    (exit 1). Now the object is a failure and the run is coverage lost (exit 3).
    """
    old = _simulate(tmp_path / "old", "-NotACa")
    new = _simulate(tmp_path / "new", "-NotACa", "-Omit", "enrollment-services:cn:missing")
    manifest = json.loads((new / "collector-manifest.json").read_text(encoding="utf-8"))
    assert manifest["enumeration"]["enrollment-services"]["complete"] is False
    assert manifest["enumeration"]["ca-config"]["complete"] is False
    assert "" not in json.loads((new / "enrollment-services.json").read_text(encoding="utf-8"))
    capsys.readouterr()
    rc = main(["diff", str(old), str(new), "--exit-code", "--json"])
    env = json.loads(capsys.readouterr().out)
    assert not [f for f in env["new"] if f["check"] == "ORPHANED_TEMPLATE"]
    assert env["new"] == [] and env["resolved"] == []
    assert "ORPHANED_TEMPLATE" in {u["check"] for u in env["unevaluated"]}
    assert env["summary"]["coverage_lost"] is True
    assert rc == 3
