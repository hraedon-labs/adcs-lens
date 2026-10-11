"""Round-3 reviewer probes of ``adcs-lens diff``, replayed as regression tests.

Both round-3 executing reviewers (Sol = GPT-5.6 via codex, DS = DeepSeek via
opencode) reviewed 8729b14 and demonstrated false resolutions with probe
scripts. Their probes generated exports at run time; the exports here are
committed instead, so the tests do not depend on the fixture builder (or on the
reviewers' scratch directories) staying the same.

Layout, under ``tests/fixtures/reviewer_probes/r3/``:

* ``old/`` -- the full-coverage export (``build_full_export`` with the certs
  pass declared skipped to keep the fixtures small; enumeration markers match
  the rows). It is the OLDER side of every current-collector case.
* ``old_legacy/`` -- the same export as collector 0.8.0 wrote it: no
  objectGUIDs, no ``enrollment_service``, no enumeration markers (Sol's
  ``strip_guid_identity``).
* ``<case>/`` -- the NEWER export: the older one with exactly the reviewer's
  mutation applied (see ``_CASES``). ``ds_r3_nn3_duplicate_crl_guid`` is a
  single export with the certs pass, since CRL GUIDs need ``certs/index.json``.

Every case except the control resolved findings, exit 0, at 8729b14. A case
that becomes clean again at a later commit is a regression.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from adcs_lens import detection
from adcs_lens.cli import main
from adcs_lens.detection import Evaluation, Finding, ObjectRef, is_degradation_note
from adcs_lens.diff import diff_findings
from adcs_lens.ingest import IngestError, ingest
from adcs_lens.model import Severity
from tests.conftest import NOW
from tests.detection_records import problems
from tests.test_detection_records import POST_RECORD

R3 = Path(__file__).parent / "fixtures" / "reviewer_probes" / "r3"
_BASES = frozenset({"old", "old_legacy"})
_CRL_CASE = "ds_r3_nn3_duplicate_crl_guid"

_CA_CHECKS = frozenset({"CA_AUDIT_DISABLED", "ESC16", "ESC6", "ESC7"})


@dataclass(frozen=True)
class _Case:
    rc: int
    withheld: frozenset[str] = frozenset()  # exact set of indeterminate checks
    resolved: frozenset[str] = frozenset()  # exact set of resolved posture checks
    error: str | None = None  # ingest error substring (rc 1, no report)
    base: str = "old"


_CASES: dict[str, _Case] = {
    # --- Sol r3 NEW BLOCKING 1: pass presence taken as complete enumeration -------
    # templates.json lost the LegacyV1WebServer row (the marker still counts it).
    # 8729b14: ESC15 + ORPHANED_TEMPLATE resolved, exit 0.
    "sol_r3_b1_partial_template_container": _Case(
        3, withheld=frozenset({"ESC15", "ORPHANED_TEMPLATE"})
    ),
    # oid-objects.json emptied: ESC13 lost its OID join input. 8729b14: resolved.
    "sol_r3_b1_partial_oid_container": _Case(3, withheld=frozenset({"ESC13"})),
    # The same truncated template list from a 0.8.0 collector (no GUIDs, no
    # markers, nothing unmatched left). 8729b14: resolved, exit 0.
    "sol_r3_b1_legacy_partial_template": _Case(
        3, withheld=frozenset({"ESC15", "ORPHANED_TEMPLATE"}), base="old_legacy"
    ),
    # CONTROL (passes at both commits): the same row removed, but the collector's
    # marker counts the rows it really enumerated, so this is a genuine deletion
    # and must still resolve. Shows the cases above are not withheld vacuously.
    "sol_r3_b1_control_genuine_deletion": _Case(
        0, resolved=frozenset({"ESC15", "ORPHANED_TEMPLATE"})
    ),
    # --- Sol r3 NEW BLOCKING 2: missing detector inputs defaulted to clean ------
    # 8729b14: ESC8 / ESC8 / ESC6 resolved, exit 0. Now each is an ingest error.
    "sol_r3_b2_missing_endpoint_input": _Case(1, error="'/CertSrv' is missing auth_providers"),
    "sol_r3_b2_malformed_endpoint_row": _Case(
        1, error="web-endpoints.json entries must be objects"
    ),
    "sol_r3_b2_missing_ca_input": _Case(1, error="is missing edit_flags"),
    # --- Sol r3 NEW BLOCKING 3 / DS r3 NB3: GUID exemptions manufacture a deletion
    # An enterprise (kind=issuing) CA renamed, declared standalone, GUID dropped,
    # registry read lost. 8729b14: four CA checks resolved, exit 0. Now the
    # exemption is rejected (an issuing CA is not standalone).
    "sol_r3_b3_standalone_guid_exemption": _Case(1, error="object_guid is missing"),
    "ds_r3_nb3_standalone_exempt": _Case(1, error="object_guid is missing"),
    # DS's probe with kind=standalone as well, so the ingest exemption is VALID:
    # isolates the per-type guid_types layer (one GUID-less CA makes the ca type
    # not GUID-complete -> the unmatched CA could be the old one renamed).
    # 8729b14: four CA checks resolved, exit 0.
    "ds_r3_nb3_standalone_exempt_valid_kind": _Case(3, withheld=_CA_CHECKS),
    # The Public Key Services container moved, unreadable, GUID dropped (a valid
    # exemption for a fixed container). 8729b14: ESC5 resolved, exit 0.
    "sol_r3_b3_unreadable_pki_guid_exemption": _Case(3, withheld=frozenset({"ESC5"})),
    "ds_r3_nb3_pki_unreadable_exempt": _Case(3, withheld=frozenset({"ESC5"})),
}


def test_every_r3_fixture_has_a_case() -> None:
    present = {p.name for p in R3.iterdir() if p.is_dir()}
    assert present == set(_CASES) | _BASES | {_CRL_CASE}


@pytest.mark.parametrize("name", sorted(_CASES))
def test_r3_probe(name: str, capsys: pytest.CaptureFixture[str]) -> None:
    """Replays the named reviewer's round-3 probe export through ``diff --exit-code``."""
    case = _CASES[name]
    rc = main(["diff", str(R3 / case.base), str(R3 / name), "--exit-code", "--json"])
    out = capsys.readouterr()
    assert rc == case.rc, out.err or out.out
    if case.error is not None:
        assert case.error in out.err
        assert out.out == ""
        return
    env = json.loads(out.out)
    resolved = {f["check"] for f in env["resolved"] if f["severity"] != "info"}
    assert resolved == case.resolved
    assert {i["check"] for i in env["indeterminate"]} == case.withheld
    assert env["summary"]["coverage_lost"] is bool(case.withheld)


@pytest.mark.certs
def test_ds_r3_nn3_duplicate_crl_guid_is_rejected() -> None:
    """DS r3 NN3: two CRLs sharing an objectGUID. 8729b14 ingested it silently."""
    pytest.importorskip("cryptography")
    with pytest.raises(IngestError, match=r"CRLs\): duplicate object_guid"):
        ingest(R3 / _CRL_CASE)


# --- Sol r3 NEW BLOCKING 4 / DS r3 NN1: a helper called after the record point --
# ``_low_priv_enrollers`` runs after ESC1/2/3/9/13/15 record a template. Each
# reviewer made it return nothing; the 8729b14 residual guard reported no problem.

_ENROLLERS_BODY = "    return _low_priv_allow_aces(template, _ENROLL_RIGHTS)\n"
_HELPER_MUTANTS: dict[str, tuple[str, str]] = {
    # Sol r3_adversarial.py: replace the return line (unique in detection.py).
    "sol_r3_b4_enrollers_return_empty": (
        _ENROLLERS_BODY,
        "    return []  # R3 MUTANT: helper silently skips all enrollers\n",
    ),
    # DS probe_helper_gap.py: replace the docstring and the return line.
    "ds_r3_nn1_enrollers_return_empty": (
        '    """Allow-ACEs that grant (or imply) enroll to a low-privilege trustee."""\n'
        + _ENROLLERS_BODY,
        '    """MUTANT: silently skip every template."""\n    return []\n',
    ),
}
_ENROLLER_CHECKS = frozenset({"ESC1", "ESC2", "ESC3", "ESC9", "ESC13", "ESC15"})


def _helper_mutant(name: str) -> str:
    source = Path(detection.__file__).read_text(encoding="utf-8")
    old, new = _HELPER_MUTANTS[name]
    assert source.count(old) == 1, f"{name}: mutation anchor not found"
    return source.replace(old, new)


def _load(source: str, name: str) -> ModuleType:
    mod_name = f"adcs_lens._r3_{name}"
    spec = importlib.util.spec_from_loader(mod_name, loader=None)
    assert spec is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod  # dataclasses need the module registered
    try:
        exec(compile(source, f"<{mod_name}>", "exec"), mod.__dict__)
    finally:
        sys.modules.pop(mod_name, None)
    return mod


@pytest.mark.parametrize("name", sorted(_HELPER_MUTANTS))
def test_r3_post_record_helper_mutant_is_caught_by_the_guard(name: str) -> None:
    """The residual guard must flag the reviewer's helper mutant."""
    assert problems(_helper_mutant(name), POST_RECORD), f"{name} survived the residual guard"


@pytest.mark.parametrize("name", sorted(_HELPER_MUTANTS))
def test_r3_post_record_helper_mutant_needs_the_guard(name: str) -> None:
    """Executed (passes at both commits): unguarded, the mutant WOULD clear six checks.

    This is what makes the guard test above load-bearing: the records design
    alone cannot see a skip that happens after the record.
    """
    old_ev = detection.evaluate(ingest(R3 / "old"), now=NOW)
    raw: Any = _load(_helper_mutant(name), name).evaluate(ingest(R3 / "old"), now=NOW)
    new_ev = Evaluation(
        findings=tuple(raw.findings),
        objects=tuple(raw.objects),
        records=raw.records,
        containers=raw.containers,
        guid_types=raw.guid_types,
    )
    report = diff_findings(old_ev, new_ev)
    resolved = {f.check for f in report.resolved if not is_degradation_note(f)}
    assert resolved == _ENROLLER_CHECKS


# Variants of the same helper mutant (NOT reviewer probes; found while replaying
# them). Each keeps the pinned call to ``_low_priv_allow_aces`` but still makes
# the helper return nothing, and executed each clears the same six checks.
_HELPER_VARIANTS: dict[str, str] = {
    "call_then_discard": ("    _low_priv_allow_aces(template, _ENROLL_RIGHTS)\n    return []\n"),
    "wrong_rights": "    return _low_priv_allow_aces(template, frozenset())\n",
}


@pytest.mark.xfail(
    strict=True,
    reason=(
        "OPEN (variant of Sol r3 B4 / DS r3 NN1): the round-4 guard pins which "
        "helpers a post-record helper calls, not whether their result is used, so a "
        "helper that keeps the call but returns nothing still survives"
    ),
)
@pytest.mark.parametrize("variant", sorted(_HELPER_VARIANTS))
def test_r3_helper_mutant_variant_that_keeps_the_call_is_caught(variant: str) -> None:
    source = Path(detection.__file__).read_text(encoding="utf-8")
    assert source.count(_ENROLLERS_BODY) == 1
    assert problems(source.replace(_ENROLLERS_BODY, _HELPER_VARIANTS[variant]), POST_RECORD)


# --- DS r3 NB3, in-process form ----------------------------------------------------


# Fixed after round 4: diff no longer takes the producer's ``guid_types`` on trust;
# the newer objects themselves must agree (every one of that type carries a GUID,
# none carries the older object's) and the older object must be in the older
# inventory. Each case below resolved at 91e1b06.

_OLD_REF = ObjectRef("template", "a" * 32, ("cn:old",))


def _esc9_old(*, inventory: tuple[ObjectRef, ...] = (_OLD_REF,)) -> Evaluation:
    return Evaluation(
        findings=(
            Finding(
                check="ESC9",
                severity=Severity.HIGH,
                title="t",
                subject="Old",
                detail="d",
                source="s",
                object_ref=_OLD_REF,
            ),
        ),
        objects=inventory,
    )


def _esc9_new(*objects: ObjectRef) -> Evaluation:
    return Evaluation(
        findings=(),
        objects=objects,
        containers=frozenset({("ESC9", "template")}),
        guid_types=frozenset({"template"}),
    )


def test_ds_r3_nb3_diff_does_not_trust_guid_types_over_a_guidless_object() -> None:
    """DS r3 NB3 verbatim: GUID-typed container, unmatched GUID-less renamed object."""
    report = diff_findings(_esc9_old(), _esc9_new(ObjectRef("template", "", ("cn:renamed",))))
    assert report.resolved == ()
    assert [i.finding.check for i in report.indeterminate] == ["ESC9"]


def test_diff_does_not_trust_guid_types_over_a_paired_guidless_object() -> None:
    """Strict form: ANY GUID-less newer object of the type voids the GUID claim.

    Here the GUID-less newer object is paired (by alias) to a different older
    object, so the legacy rule (no unpaired newer object) is what resolves; the
    GUID shortcut alone must not.
    """
    other_old = ObjectRef("template", "", ("cn:other",))
    report = diff_findings(
        _esc9_old(inventory=(_OLD_REF, other_old)),
        _esc9_new(ObjectRef("template", "", ("cn:other",)), ObjectRef("template", "", ("cn:new",))),
    )
    assert report.resolved == ()
    assert [i.finding.check for i in report.indeterminate] == ["ESC9"]


def test_diff_does_not_resolve_a_guid_still_present_but_unpairable() -> None:
    """The older object's GUID is in the newer export twice (ambiguous, so unpaired)."""
    dup = ObjectRef("template", "a" * 32, ("cn:old",))
    dup2 = ObjectRef("template", "a" * 32, ("cn:copy",))
    report = diff_findings(_esc9_old(), _esc9_new(dup, dup2))
    assert report.resolved == ()
    assert "still in the newer export" in report.indeterminate[0].reason


def test_diff_does_not_resolve_an_object_missing_from_the_older_inventory() -> None:
    """A finding whose object the older inventory lacks was never looked for."""
    still_there = ObjectRef("template", "a" * 32, ("cn:old",))
    report = diff_findings(_esc9_old(inventory=()), _esc9_new(still_there))
    assert report.resolved == ()
    assert [i.finding.check for i in report.indeterminate] == ["ESC9"]


def test_diff_guid_absence_still_resolves_when_the_objects_agree() -> None:
    """Control: every newer template carries a GUID and none is the old one."""
    report = diff_findings(_esc9_old(), _esc9_new(ObjectRef("template", "b" * 32, ("cn:other",))))
    assert [f.check for f in report.resolved] == ["ESC9"]
    assert report.indeterminate == ()
