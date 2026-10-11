"""Round-4 reviewer probes of ``adcs-lens diff``, replayed as regression tests.

Both round-4 executing reviewers (Sol = GPT-5.6 via codex, DS = DeepSeek via
opencode) reviewed 9fb13d3 and demonstrated false resolutions. The replays here
are the reviewers' exact exports, committed under
``tests/fixtures/reviewer_probes/r4/`` and generated from the committed round-3
bases (``r3/old`` = collector 0.9.0, ``r3/old_legacy`` = 0.8.0) by applying each
probe's mutation (see ``_REPLAYS``). Every replay but one (DS P1, a witness)
resolved findings at 9fb13d3. This module imports nothing but the CLI, so it runs unchanged against
older commits.

tests/test_round5_analogues.py holds the 0.10.0 analogues: what an honest
collector >= 0.10.0 writes in the same situation, exercising the mechanism that
closes each probe on a current export (so the replays here are not withheld
merely because 0.9.0 is legacy), each next to a control that still resolves.
The round-4 mutation probes (check rename, indirection through nested helpers /
lambdas / method aliases / getattr / dict dispatch with Assert sinks, the
blindly regenerated pin) are mutants in the mutation gate
(tests/mutation_gate.py HAND_WRITTEN "r4:*"), and the rename contract is pinned
by tests/test_verdicts.py.

Threat model: a hand-forged export that *lies* — a 0.10.0 marker claiming a
complete enumeration the collector never ran — is out of scope for diff; the
honest-collector side of that boundary is the collector's paging proof
(tests/collector/Collector.Tests.ps1, ``_pagedSearchCore``) and the simulated
collection (tests/test_collector_simulated.py).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import pytest

from adcs_lens.cli import main

R3 = Path(__file__).parent / "fixtures" / "reviewer_probes" / "r3"
R4 = Path(__file__).parent / "fixtures" / "reviewer_probes" / "r4"
_LABESC1 = frozenset({"ESC1", "ESC13", "WEAK_TEMPLATE_KEY_SIZE", "ORPHANED_TEMPLATE"})


@dataclass(frozen=True)
class _Replay:
    rc: int
    withheld: frozenset[str] = frozenset()  # exact set of indeterminate checks
    error: str | None = None  # ingest error substring (rc 1)
    base: Path = R3 / "old"


_REPLAYS: dict[str, _Replay] = {
    # --- Sol NEW BLOCKING 1/2 (round-3 B1 not closed): a self-asserted marker --
    # LegacyV1WebServer removed and the templates marker re-counted to match
    # (9 -> 8). 9fb13d3: ESC15 + ORPHANED_TEMPLATE resolved, exit 0. Now a 0.9.0
    # marker (written unconditionally after the loop) proves nothing.
    "sol_r4_forged_complete_marker": _Replay(3, frozenset({"ESC15", "ORPHANED_TEMPLATE"})),
    # The same on a 0.8.0 export that carries an (impossible) marker. 9fb13d3:
    # resolved, exit 0 (the version was never consulted).
    "sol_r4_legacy_impossible_marker": _Replay(
        3, frozenset({"ESC15", "ORPHANED_TEMPLATE"}), base=R3 / "old_legacy"
    ),
    # --- Sol round-3 B2 not closed: present but wrong-typed / missing inputs ---
    # edit_flags = "" (a string). 9fb13d3: ESC6 resolved, exit 0.
    "sol_r4_wrong_type_ca_input": _Replay(1, error="edit_flags must be an array of strings"),
    # auth_providers = "negotiate" (iterated as characters). 9fb13d3: ESC8 resolved.
    "sol_r4_wrong_type_endpoint_input": _Replay(
        1, error="auth_providers must be an array of strings"
    ),
    # acl_obtained=true but no security key. 9fb13d3: ESC1 + ESC13 resolved.
    "sol_r4_missing_template_security": _Replay(1, error="'LabEsc1' is missing security"),
    # A principal row without mappings. 9fb13d3: ESC14 resolved.
    "sol_r4_missing_principal_mappings": _Replay(1, error="is missing mappings"),
    # LAB-DC02 had the Schannel UPN bit (ESC10); the newer row omits the methods.
    # 9fb13d3: ESC10 resolved.
    "sol_r4_missing_dc_methods": _Replay(
        1,
        error="'LAB-DC02' is missing schannel_mapping_methods",
        base=R4 / "sol_r4_missing_dc_methods_old",
    ),
    # --- Sol NEW BLOCKING 1: decisions certified from another partial container --
    # LAB-DC01 (the only non-strict DC) removed; the dc-config marker still says
    # 2. 9fb13d3: ESC14 resolved (its verdict reads every DC), exit 0 at 3 only
    # because ESC10 on the removed DC was withheld.
    "sol_r4_esc14_incomplete_dc_dependency": _Replay(3, frozenset({"ESC10", "ESC14"})),
    # The only unpatched issuing CA removed; the ca-config marker still says 3.
    # 9fb13d3: ESC15 resolved, exit 0.
    "sol_r4_esc15_incomplete_ca_dependency": _Replay(
        3, frozenset({"ESC15"}), base=R4 / "sol_r4_esc15_incomplete_ca_dependency_old"
    ),
    # --- DeepSeek -------------------------------------------------------------------
    # P1: a genuine template deletion on a 0.8.0 export. Resolved at 8729b14,
    # already withheld at 9fb13d3 (DS's N3 was that the docs still promised a
    # legacy fallback): a WITNESS of the intended behaviour, not a regression.
    # Legacy exports fail closed by design.
    "ds_r4_p1_legacy_genuine_deletion": _Replay(3, _LABESC1, base=R3 / "old_legacy"),
    # P2: the CA's certutil EditFlags read failed and the 0.9.0 collector wrote
    # an empty list. 9fb13d3: ESC6 resolved, exit 0.
    "ds_r4_p2_ca_registry_read_failed": _Replay(3, frozenset({"ESC6"})),
    # The same for DisableExtensionList. 9fb13d3: ESC16 resolved, exit 0.
    "ds_r4_p2_esc16_read_failed": _Replay(3, frozenset({"ESC16"})),
    # P3b: a partial template list whose marker count matches the rows written.
    # 9fb13d3: four findings resolved, exit 0.
    "ds_r4_p3b_matching_count_partial": _Replay(3, _LABESC1),
    # A whole CA row lost with a matching count. 9fb13d3: five CA findings resolved.
    # (Losing the only unpatched issuing CA also lowers ESC15 HIGH -> MEDIUM: an
    # improvement from an unproven estate, withheld too.)
    "ds_r4_ca_row_dropped_matching_count": _Replay(
        3, frozenset({"CA_AUDIT_DISABLED", "ESC6", "ESC7", "ESC16", "ESC15"})
    ),
}
_BASES_ONLY = {"sol_r4_missing_dc_methods_old", "sol_r4_esc15_incomplete_ca_dependency_old"}


def test_every_r4_fixture_has_a_replay() -> None:
    present = {p.name for p in R4.iterdir() if p.is_dir()}
    assert present == set(_REPLAYS) | _BASES_ONLY


@pytest.mark.parametrize("name", sorted(_REPLAYS))
def test_r4_replay(name: str, capsys: pytest.CaptureFixture[str]) -> None:
    """Replays the named reviewer's round-4 probe export through ``diff --exit-code``."""
    case = _REPLAYS[name]
    rc = main(["diff", str(case.base), str(R4 / name), "--exit-code", "--json"])
    out = capsys.readouterr()
    assert rc == case.rc, out.err or out.out
    if case.error is not None:
        assert case.error in out.err
        assert out.out == ""
        return
    env = json.loads(out.out)
    assert [f["check"] for f in env["resolved"] if f["severity"] != "info"] == []
    assert {i["check"] for i in env["indeterminate"]} == case.withheld
    assert env["summary"]["coverage_lost"] is True
