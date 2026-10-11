"""Verdicts: one per object per check, one construction site, declared inputs.

Review round 4 rulings A and B (see detection.py, "Verdicts"):

* every posture check decides every object of its subject type exactly once,
  and findings and evaluation records both derive from that single verdict, so
  their identity cannot diverge;
* every check declares its inputs (subject fields, dependency containers and
  dependency fields), and diff may rely on a verdict only when all of them were
  obtained / complete. The declaration is machine-checked both ways: reading an
  undeclared input raises, and withholding any declared input makes the check's
  verdicts unusable.

The small structural test at the bottom replaces the residual static records
guard (tests/detection_records.py, removed in round 5). It no longer tries to
decide whether a verdict is *correct* — the mutation gate does that
functionally (tests/test_mutation_gate.py) — it only pins the construction
invariants the drift contract relies on: posture findings are built in one
place, a verdict is the return value of a top-level verdict function (nothing
runs after it), and only the identity helpers may look past a reader.
"""

from __future__ import annotations

import ast
import dataclasses
from collections import Counter
from pathlib import Path
from typing import Any

import pytest

from adcs_lens import detection
from adcs_lens.detection import (
    _SUBJECTS,
    CHECKS,
    Evaluation,
    UndeclaredInput,
    _Reader,
    _subject_ref,
    is_degradation_note,
)
from adcs_lens.diff import diff_findings
from adcs_lens.ingest import ingest
from adcs_lens.model import Estate
from tests.conftest import NOW
from tests.mutation_corpus import kitchen_sink
from tests.test_diff_coverage import build_full_export, enrich

pytest.importorskip("cryptography")
pytestmark = pytest.mark.certs

_SOURCE = Path(detection.__file__).read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def full(tmp_path_factory: pytest.TempPathFactory) -> Estate:
    return enrich(ingest(build_full_export(tmp_path_factory.mktemp("verdicts") / "export")))


@pytest.fixture(scope="module")
def sink(full: Estate) -> Estate:
    return kitchen_sink(full)


def _verdicts(ev: Evaluation, check: str, variant: str) -> list[Any]:
    return [v for v in ev.verdicts if (v.check, v.variant) == (check, variant)]


# --- A: exactly one verdict per evaluated object, findings derived from it ------------


@pytest.mark.parametrize("which", ["full", "sink"])
def test_every_object_gets_exactly_one_verdict_per_check(
    which: str, request: pytest.FixtureRequest
) -> None:
    estate: Estate = request.getfixturevalue(which)
    ev = detection.evaluate(estate, now=NOW)
    for (check, variant), decl in CHECKS.items():
        subjects = Counter(
            _subject_ref(decl.subject, o).key for o in _SUBJECTS[decl.subject](estate)
        )
        got = Counter(v.key for v in _verdicts(ev, check, variant))
        assert got == subjects, (check, variant)


def test_findings_and_records_are_derived_from_the_same_verdict(sink: Estate) -> None:
    ev = detection.evaluate(sink, now=NOW)
    findings = [f for f in ev.findings if not is_degradation_note(f)]
    by_verdict: dict[tuple[str, str, str], list[Any]] = {}
    for f in findings:
        assert f.object_ref is not None
        pattern = f.variant
        if (f.check, f.variant) not in CHECKS:
            pattern = f.variant.split(":", 1)[0] + ":*"
        by_verdict.setdefault((f.check, pattern, f.object_ref.key), []).append(f)
    states = {(v.check, v.variant, v.key): v.state for v in ev.verdicts}
    for key in by_verdict:
        assert states.get(key) == "finding", key
    for key, state in states.items():
        assert (state == "finding") == (key in by_verdict), (key, state)


def test_a_check_rename_leaves_the_old_identity_withheld(full: Estate) -> None:
    """Round-4 blocking 4: renaming a check cannot resolve the old identity.

    The verdict construction site sets the identity once, so a consistent rename
    yields findings AND records under the new name only: the old finding finds no
    verdict and is withheld (it was resolved at 9fb13d3, Sol's identity probe).
    """
    from tests.mutation_gate import DETECTION_SRC, HAND_WRITTEN, _load

    source = HAND_WRITTEN["r4:rename_esc1"](DETECTION_SRC)
    mutant: Any = _load(compile(source, "<rename>", "exec"), "rename")
    old = detection.evaluate(full, now=NOW)
    raw = mutant.evaluate(full, now=NOW)
    new = Evaluation(**{f.name: getattr(raw, f.name) for f in dataclasses.fields(raw)})
    report = diff_findings(old, new)
    assert "ESC1" not in {f.check for f in report.resolved}
    assert "ESC1" in {i.finding.check for i in report.indeterminate}
    assert "ESC1_RENAMED" in {f.check for f in report.new}


# --- B: declared inputs, machine-checked -------------------------------------------------


def test_reading_an_undeclared_input_raises(full: Estate) -> None:
    reader: Any = _Reader(full.templates[0], frozenset({"name"}), "TEST")
    assert reader.name == full.templates[0].name
    with pytest.raises(UndeclaredInput, match="TEST reads CertTemplate.ekus"):
        _ = reader.ekus


def _lose_field(estate: Estate, object_type: str, field: str) -> Estate:
    from tests.mutation_corpus import _unobtain

    return _unobtain(estate, object_type, field)


def _usable(ev: Evaluation, check: str, variant: str) -> list[Any]:
    return [v for v in _verdicts(ev, check, variant) if v.usable]


@pytest.mark.parametrize("key", sorted(CHECKS), ids=lambda k: f"{k[0]}[{k[1]}]")
def test_withholding_any_declared_input_makes_the_verdicts_unusable(
    full: Estate, key: tuple[str, str]
) -> None:
    check, variant = key
    decl = CHECKS[key]
    baseline = detection.evaluate(full, now=NOW)
    assert _usable(baseline, check, variant), f"{key}: no usable verdict to withhold"
    assert (check, decl.subject) in baseline.containers
    # Each declared container (its own and every dependency's).
    for container in decl.containers:
        degraded = dataclasses.replace(
            full,
            manifest=dataclasses.replace(
                full.manifest,
                enumeration_complete=full.manifest.enumeration_complete - {container},
            ),
        )
        ev = detection.evaluate(degraded, now=NOW)
        assert not _usable(ev, check, variant), (key, container)
        assert (check, decl.subject) not in ev.containers, (key, container)
    # Each declared subject field that a collector can fail to obtain.
    for field in decl.fields:
        degraded = _lose_field(full, decl.subject, field)
        if degraded is full:
            continue  # parsed from the DER / the enumeration itself: always obtained
        ev = detection.evaluate(degraded, now=NOW)
        assert not _usable(ev, check, variant), (key, field)
    # Each declared dependency field, lost on every dependency object.
    for object_type, fields in decl.deps.items():
        for field in fields:
            degraded = _lose_dependency(full, object_type, field)
            if degraded is full:
                continue
            ev = detection.evaluate(degraded, now=NOW)
            assert not _usable(ev, check, variant), (key, object_type, field)


def _lose_dependency(estate: Estate, object_type: str, field: str) -> Estate:
    if object_type in ("ca", "dc"):
        return _lose_field(estate, object_type, field)
    return estate  # OID fields come from the enumeration itself


def test_a_check_cannot_read_a_dependency_it_does_not_declare(full: Estate) -> None:
    ctx = detection._Context(full, CHECKS[("ESC1", "")], "ESC1", NOW, 90)
    with pytest.raises(UndeclaredInput, match="ESC1 reads the ca container"):
        ctx.dep("ca")


@pytest.mark.parametrize(
    "key", sorted(k for k, d in CHECKS.items() if d.text), ids=lambda k: f"{k[0]}[{k[1]}]"
)
def test_presentation_fields_never_decide_a_verdict(sink: Estate, key: tuple[str, str]) -> None:
    """A field declared as finding text only may change words, never a verdict."""
    check, variant = key
    decl = CHECKS[key]
    base = detection.evaluate(sink, now=NOW)
    for field in decl.text:
        for value in ((), ("Some CA",), ("A", "B")):
            changed = dataclasses.replace(
                sink,
                templates=tuple(dataclasses.replace(t, **{field: value}) for t in sink.templates),
            )
            ev = detection.evaluate(changed, now=NOW)
            assert {(v.key, v.state, v.usable) for v in _verdicts(ev, check, variant)} == {
                (v.key, v.state, v.usable) for v in _verdicts(base, check, variant)
            }, (
                key,
                field,
                value,
            )


# --- structure: the construction invariants ----------------------------------------------

_TREE = ast.parse(_SOURCE)
_TOP = {n.name: n for n in _TREE.body if isinstance(n, ast.FunctionDef)}
_REF_HELPERS = {
    "_template_ref",
    "_pki_ref",
    "_ca_ref",
    "_dc_ref",
    "_principal_ref",
    "_endpoint_ref",
    "_crl_ref",
}


def _calls(name: str) -> list[tuple[ast.Call, str]]:
    out = []
    for fn_name, fn in _TOP.items():
        for node in ast.walk(fn):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id == name:
                    out.append((node, fn_name))
    return out


def test_posture_findings_are_built_only_at_the_verdict_construction_site() -> None:
    notes = detection._DEGRADATION_NOTES
    for node, where in _calls("Finding"):
        if where == "_make_findings":
            continue
        check = next((k.value for k in node.keywords if k.arg == "check"), None)
        assert isinstance(check, ast.Constant) and check.value in notes, (
            f"{where} builds a Finding outside _make_findings: only degradation notes may"
        )


def test_every_verdict_is_the_return_value_of_a_top_level_verdict_function() -> None:
    sites = _calls("_verdicts")
    declared = set()
    for node, where in sites:
        estate, check, variant, decide = node.args[:4]
        assert isinstance(estate, ast.Name) and estate.id == "estate", where
        assert isinstance(check, ast.Constant) and isinstance(check.value, str), where
        assert isinstance(variant, ast.Constant) and isinstance(variant.value, str), where
        assert isinstance(decide, ast.Name) and decide.id in _TOP, (
            f"{where}: the verdict function must be a top-level def (no closure over the estate)"
        )
        fn = _TOP[decide.id]
        assert [a.arg for a in fn.args.args] == [fn.args.args[0].arg, "ctx"], decide.id
        assert "estate" not in {n.id for n in ast.walk(fn) if isinstance(n, ast.Name)}, decide.id
        declared.add((check.value, variant.value))
    assert declared == set(CHECKS), "every declared check has exactly one verdict site"
    assert len(sites) == len(CHECKS)


def test_only_identity_helpers_look_past_a_reader() -> None:
    users = {where for _node, where in _calls("_raw")}
    assert users == _REF_HELPERS
