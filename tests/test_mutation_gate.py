"""Mutation gate: every detector mutant must make a functional diff test fail.

Review round 4 showed that a static shape guard cannot decide whether a
detector computes a correct CLEAN verdict (nested helpers, lambdas, method
aliases, getattr, dict dispatch and Assert sinks all slipped past
tests/detection_records.py, and its pin table could be regenerated blindly).
Whether a verdict is *correct* is detection correctness, so it is tested the way
correctness is: functionally, against mutants.

tests/mutation_gate.py enumerates ~1,250 deterministic mutants of
``src/adcs_lens/detection.py`` and the ``normalize.py`` helpers — generic AST
operators over every function and constant in scope, plus the explicit
HAND_WRITTEN list replaying every reviewer probe and variant from rounds 2-4 —
and runs each against tests/mutation_corpus.py. A mutant is killed when, on some
corpus pair, ``diff`` (or ``evaluate``'s verdicts) differs from what the pristine
code produces, or when a framework contract probe changes outcome. A finding
that disappears shows up as resolved / indeterminate; a resolution granted where
the pristine code withholds shows up as resolved.

Every mutant must be killed, except the ones in EQUIVALENT: each provably
cannot change any detector result, and says why. The list is checked both ways —
a new survivor fails, and so does an "equivalent" that starts being killed.

Runtime: 60-115 s single-process on a 12-vCPU lab VM (~1,250 mutants, ~130
corpus pairs; most mutants die on the first pair tried), longer on a loaded or
slower runner. It runs in CI with the rest of the suite.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

import pytest

from adcs_lens import detection
from tests import mutation_corpus, mutation_gate
from tests.mutation_gate import HAND_WRITTEN, Baseline, Run

pytest.importorskip("cryptography")
pytestmark = pytest.mark.certs

# A Deny ACE always blocks the rights it names: every right a detector requests
# (enroll, the six control rights, the two CA roles) has a _COVERS entry, and
# _blocked_rights adds exactly that entry to the trustee's blocked set.
_DENY_SELF_BLOCKS = (
    "a Deny ACE's rights are all in its own trustee's blocked set (every requested "
    "right has a _COVERS entry), so without the Allow-only guard it still never counts"
)

EQUIVALENT: dict[str, str] = {
    "drop-guard:detection._low_priv_allow_aces_in:if ace.ace_type is not AceType.ALLOW#1": (
        _DENY_SELF_BLOCKS
    ),
    "drop-guard:detection._esc7_trustees:if ace.ace_type is not AceType.ALLOW#1": (
        _DENY_SELF_BLOCKS + " (both CA roles have _COVERS entries)"
    ),
    "drop-guard:detection._low_priv_dangerous_writeproperty_aces:"
    "if ace.ace_type is not AceType.ALLOW#1": (
        "a Deny scoped WriteProperty blocks the same property GUIDs it names "
        "(_blocked_scoped_writeproperty), so its surviving set is always empty"
    ),
    "drop-guard:detection._low_priv_dangerous_writeproperty_aces:if not dangerous#1": (
        "with no dangerous GUID the surviving set (dangerous - blocked) is empty and "
        "the ACE is skipped anyway; the guard only saves the blocked-set computation"
    ),
    "drop-guard:detection._scoped_writeproperty_guids:"
    "if not token.startswith('writeproperty:')#1": (
        "without the guard any token loses its first 14 characters; only a token "
        "whose remainder is a dangerous property GUID could then match, and the "
        "collector emits that shape only as 'writeproperty:<guid>'"
    ),
    "drop-guard:detection.Evaluation.evaluated:if self.trusted#1": (
        "diff tests `trusted` before it calls evaluated() (_withhold_absent returns "
        "early, _withhold_improvement short-circuits), so the shortcut is never reached"
    ),
    "drop-guard:detection.Evaluation.clears:if self.trusted#1": (
        "diff tests `trusted` before it calls clears() (_withhold_absent returns "
        "early), so the shortcut is never reached"
    ),
    "drop-element:detection.<_ALL_RIGHTS>:'genericall'#1": (
        "_ALL_RIGHTS is only GenericAll/FullControl coverage; genericall and "
        "fullcontrol are each covered and blocked by exactly the same ACEs (only a "
        "GenericAll/FullControl Deny blocks either, and it blocks the whole set), so "
        "dropping one leaves the other deciding every verdict and the same text"
    ),
    "drop-element:detection.<_ALL_RIGHTS>:'fullcontrol'#1": (
        "the mirror of the genericall entry: genericall still decides every verdict"
    ),
    "drop-element:detection.<_COVERS>:'autoenroll': ...#1": (
        "no detector requests or text-filters AutoEnroll (deliberately not an "
        "enrollment capability, see _ENROLL_RIGHTS), so what a Deny AutoEnroll blocks "
        "cannot change a result; the entry documents the Windows semantics"
    ),
    "drop-element:detection.<_COVERS>:'autoenroll'#1": (
        "AllExtendedRights covering AutoEnroll cannot change a result for the same "
        "reason (no detector requests AutoEnroll); kept to document the semantics"
    ),
}


@pytest.fixture(scope="module")
def gate(tmp_path_factory: pytest.TempPathFactory) -> tuple[Run, Baseline]:
    corpus = mutation_corpus.build(Path(tmp_path_factory.mktemp("mutation-corpus")))
    base = mutation_gate.baseline(corpus)
    mutants, trees = mutation_gate.all_mutants()
    return mutation_gate.run(mutants, trees, base), base


def test_every_mutant_is_killed_or_a_listed_equivalent(gate: tuple[Run, Baseline]) -> None:
    run, _ = gate
    survivors = set(run.survivors)
    unexpected = sorted(survivors - set(EQUIVALENT))
    assert not unexpected, (
        f"{len(unexpected)} mutant(s) survived every functional test — add a corpus "
        "case (tests/mutation_corpus.py) that tells them apart, or, if a mutant "
        "provably cannot change any result, list it in EQUIVALENT with the reason:\n"
        + "\n".join(unexpected)
    )
    stale = sorted(set(EQUIVALENT) - survivors)
    assert not stale, "listed as equivalent but now killed (remove them):\n" + "\n".join(stale)


def test_the_mutant_set_is_explicit_and_complete() -> None:
    """Every operator produces mutants; ids are unique; the lists name real mutants."""
    mutants, _ = mutation_gate.all_mutants()
    ids = [m.id for m in mutants]
    assert len(ids) == len(set(ids)), [i for i, n in Counter(ids).items() if n > 1]
    families = Counter(m.family for m in mutants)
    floors = {
        "return-empty": 100,
        "negate-condition": 150,
        "drop-guard": 100,
        "swap-compare": 100,
        "swap-boolean": 40,
        "swap-arithmetic": 20,
        "int-boundary": 15,
        "drop-element": 200,
        "rename-identity": 50,
        "drop-undecided": 2,
        "empty-argument": 2,
    }
    for family, floor in floors.items():
        assert families[family] >= floor, (family, families[family])
    assert set(EQUIVALENT) <= set(ids)
    # Both modules in scope are mutated.
    assert {m.target for m in mutants} == {"detection", "normalize"}
    assert len(ids) > 1000


def test_every_reviewer_probe_is_in_the_hand_written_list() -> None:
    names = set(HAND_WRITTEN)
    round3 = {n for n in names if n.startswith(("r3:", "r3v:"))}
    assert len(round3) == 2 + 27  # the two reviewer mutants + the 27 variants
    assert {
        "r4:nested_helper",
        "r4:module_lambda",
        "r4:method_alias",
        "r4:getattr",
        "r4:dict_dispatch",
        "r4:assert_sink",
        "r4:ds_dict_dispatch_mutant",
        "r4:pin_blind_regeneration_slice",
        "r4:rename_esc1",
        "r4:mislabel_esc1_as_esc2",
        "r4:rename_esc4_owner_variant",
        "r4:rename_esc7_family",
    } <= names


def test_the_pristine_detectors_survive_their_own_corpus(gate: tuple[Run, Baseline]) -> None:
    """Control: the harness does not kill everything (the pristine module survives)."""
    _, base = gate
    assert mutation_gate.kill(detection, base) is None


def test_the_gate_reports_its_runtime(gate: tuple[Run, Baseline]) -> None:
    run, _ = gate
    print(f"\nmutation gate: {len(run.results)} mutants in {run.seconds:.1f}s")
    assert run.seconds < 900, "the gate is meant to stay CI-sized"
