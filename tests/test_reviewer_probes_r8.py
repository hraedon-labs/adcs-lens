"""Round-8 reviewer probe, replayed.

Kept free of round-9 test helpers so it runs unchanged against older commits
(it fails at 2c5f181 and passes from the round-9 commit on).
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from adcs_lens.cli import main
from adcs_lens.ingest import ingest
from tests.test_diff_coverage import build_full_export

pytest.importorskip("cryptography")

_COLLISION = "1.2.3.4.500"


def _collide(seed: Path, out: Path, *, victim_takes_the_oid: bool) -> tuple[Path, str]:
    shutil.copytree(seed, out)
    rows = json.loads((out / "templates.json").read_text(encoding="utf-8"))
    rows[0]["name"] = _COLLISION  # a published template whose cn is a valid dotted OID
    if victim_takes_the_oid:
        rows[1]["oid"] = _COLLISION
    (out / "templates.json").write_text(json.dumps(rows), encoding="utf-8")
    services = json.loads((out / "enrollment-services.json").read_text(encoding="utf-8"))
    services["LAB Issuing CA"] = [_COLLISION]
    (out / "enrollment-services.json").write_text(json.dumps(services), encoding="utf-8")
    return out, rows[1]["object_guid"]


def test_sol_r8_publication_reference_attaches_to_one_template_only(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Sol round 8 NEW BLOCKING 1 (.review/tmp/probe_publication_collision_r8.py).

    The one publication reference is template A's cn; in the newer export
    template B's OID becomes the same dotted value. At 2c5f181 ingest matched
    "oid or cn" per template, attached the publisher to B too, and diff
    resolved B's ORPHANED_TEMPLATE on that false clean verdict (exit 0).
    certificateTemplates names templates by cn, so B stays unpublished: its
    finding is unchanged, nothing resolves, and there is nothing to withhold.
    """
    seed = build_full_export(tmp_path / "seed")
    old, _ = _collide(seed, tmp_path / "old", victim_takes_the_oid=False)
    new, victim = _collide(seed, tmp_path / "new", victim_takes_the_oid=True)
    template = next(t for t in ingest(new).templates if t.object_guid == victim)
    assert template.published_by == ()
    capsys.readouterr()
    rc = main(["diff", str(old), str(new), "--exit-code", "--json"])
    env = json.loads(capsys.readouterr().out)
    assert "ORPHANED_TEMPLATE" not in {f["check"] for f in env["resolved"]}
    assert env["resolved"] == [] and env["new"] == []
    assert "ORPHANED_TEMPLATE" not in {i["check"] for i in env["indeterminate"]}
    assert rc == 0  # the victim's finding is simply still there
