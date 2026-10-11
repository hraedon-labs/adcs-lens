"""Round-9 reviewer probe, replayed with the real collector body.

Kept free of round-10 test helpers so it runs unchanged against older commits
(it fails at cca7c03 and passes from the round-10 commit on). The simulator is
patched in a temporary copy, as the reviewer did, so only the LDAP value of
the enrollment service's certificateTemplates differs between the exports.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from adcs_lens.cli import main

_ROOT = Path(__file__).resolve().parent.parent
_SIMULATE = _ROOT / "tests" / "collector" / "simulate.ps1"
_COLLECTOR = _ROOT / "scripts" / "Export-AdcsEstate.ps1"
_PWSH = shutil.which("pwsh")
pytestmark = pytest.mark.skipif(_PWSH is None, reason="pwsh is not installed")

_PUBLISHED = "certificatetemplates = @('LabWebServer', 'LabUser')"


def _simulate(tmp: Path, name: str, published: str) -> Path:
    source = _SIMULATE.read_text(encoding="utf-8")
    assert _PUBLISHED in source, "simulator layout changed"
    source = source.replace(_PUBLISHED, f"certificatetemplates = @({published})")
    source = source.replace(
        "Join-Path $PSScriptRoot '../../scripts/Export-AdcsEstate.ps1'", f"'{_COLLECTOR}'"
    )
    script = tmp / f"simulate-{name}.ps1"
    script.write_text(source, encoding="utf-8")
    out = tmp / name
    assert _PWSH is not None
    proc = subprocess.run(
        [_PWSH, "-NoProfile", "-NonInteractive", "-File", str(script), "-OutDir", str(out)],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return out


@pytest.mark.parametrize(
    "reference",
    [" LabWebServer ", "labwebserver", "ＬabWebServer"],
    ids=["whitespace", "case", "unicode"],
)
def test_sol_r9_a_reference_that_only_folds_to_a_cn_never_publishes_it(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], reference: str
) -> None:
    """Sol round 9 NEW BLOCKING 1 (.review/tmp/ws-r9-copy), replayed.

    The older export's CA does not publish LabWebServer (an orphan finding);
    the newer one's certificateTemplates holds " LabWebServer ". At cca7c03
    ingest trimmed the value, attached it to the template, and diff resolved
    the orphan on that false clean verdict (exit 0). MS-WCCE requires the value
    to be identical to the template's cn, so it is ambiguous: the template's
    publication is not obtained and the older finding is withheld (exit 3).
    """
    old = _simulate(tmp_path, "old", "'LabUser'")
    new = _simulate(tmp_path, "new", f"'{reference}', 'LabUser'")
    published = json.loads((new / "enrollment-services.json").read_text(encoding="utf-8"))
    assert reference in published["LAB Issuing CA"]  # copied verbatim by the collector
    capsys.readouterr()
    rc = main(["diff", str(old), str(new), "--exit-code", "--json"])
    env = json.loads(capsys.readouterr().out)
    assert "ORPHANED_TEMPLATE" not in {f["check"] for f in env["resolved"]}
    assert env["resolved"] == [] and env["new"] == []
    assert "ORPHANED_TEMPLATE" in {i["check"] for i in env["indeterminate"]}
    assert env["summary"]["coverage_lost"] is True
    assert rc == 3
