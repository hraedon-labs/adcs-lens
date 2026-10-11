"""An incomplete container never yields a finding or a resolution derived from it.

Round-5 review (DS NEW BLOCKING 1): completeness was enforced on the resolution
path only, so a partial enumeration could manufacture a regression (a template
whose publisher row was lost read as ORPHANED; a CA list with no visible issuing
CA made ESC15 "unknown"). The rule now: a verdict whose conclusion rests on an
absence in a declared container (no publisher, no unpatched CA, no linked OID,
no non-strict DC) is undecided when that container is not proven complete, and
a comparison the newer export cannot make is coverage loss.

This guard is differential and spans every check: for each container any check
declares, mark it incomplete — and, separately, drop each of its objects under
an incomplete marker — then diff against the intact export. Nothing may come
out new, worsened, improved or resolved, and coverage loss must be reported.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Iterator

import pytest

from adcs_lens import detection
from adcs_lens.detection import CHECKS, Evaluation, is_degradation_note
from adcs_lens.diff import DriftReport, diff_findings
from adcs_lens.ingest import ingest
from adcs_lens.model import Estate
from tests.conftest import NOW
from tests.mutation_corpus import kitchen_sink
from tests.test_diff_coverage import build_full_export, enrich

pytest.importorskip("cryptography")
pytestmark = pytest.mark.certs

_CONTAINERS = sorted({c for d in CHECKS.values() for c in d.containers})


@pytest.fixture(scope="module")
def full(tmp_path_factory: pytest.TempPathFactory) -> Estate:
    return enrich(ingest(build_full_export(tmp_path_factory.mktemp("scope") / "export")))


def _incomplete(e: Estate, container: str) -> Estate:
    complete = e.manifest.enumeration_complete - {container}
    return dataclasses.replace(
        e, manifest=dataclasses.replace(e.manifest, enumeration_complete=complete)
    )


def _drops(e: Estate, container: str) -> Iterator[tuple[str, Estate]]:
    """*e* without each object of *container*, one at a time."""
    collections = {
        "templates": "templates",
        "ca-config": "cas",
        "pki-acls": "acls",
        "dc-config": "dcs",
        "principal-mappings": "principal_mappings",
        "web-endpoints": "endpoints",
        "oid-objects": "oids",
        "crls": "crls",
    }
    if container in collections:
        field = collections[container]
        rows = getattr(e, field)
        for i in range(len(rows)):
            yield f"{container}[{i}]", dataclasses.replace(e, **{field: rows[:i] + rows[i + 1 :]})
    elif container == "enrollment-services":
        for ca in sorted({ca for t in e.templates for ca in t.published_by}):
            templates = tuple(
                dataclasses.replace(t, published_by=tuple(p for p in t.published_by if p != ca))
                for t in e.templates
            )
            yield f"publications of {ca}", dataclasses.replace(e, templates=templates)
    elif container == "certs":
        for i, ca in enumerate(e.cas):
            for j in range(len(ca.certs)):
                cas = list(e.cas)
                cas[i] = dataclasses.replace(ca, certs=ca.certs[:j] + ca.certs[j + 1 :])
                yield f"certs of {ca.name}[{j}]", dataclasses.replace(e, cas=tuple(cas))
    else:
        raise AssertionError(f"no row model for container {container!r}")


def _assert_nothing_derived(
    old: Evaluation, new_estate: Estate, container: str, label: str
) -> DriftReport:
    report = diff_findings(old, detection.evaluate(new_estate, now=NOW))
    new = [f.check for f in report.new if not is_degradation_note(f)]
    assert new == [], f"{label}: a finding derived from an incomplete container: {new}"
    resolved = [f.check for f in report.resolved if not is_degradation_note(f)]
    assert resolved == [], f"{label}: a resolution from an incomplete container: {resolved}"
    moved = [
        (d.new.check, d.old.severity.value, d.new.severity.value)
        for d in report.changed
        if d.old.severity != d.new.severity and not is_degradation_note(d.new)
    ]
    assert moved == [], f"{label}: a severity derived from an incomplete container: {moved}"
    # Every check the older export decided from this container is now blocked.
    relying = {check for (check, _), d in CHECKS.items() if container in d.containers}
    decided = {check for check, _ in old.containers} & relying
    blocked = {u.check for u in report.unevaluated}
    assert decided <= blocked, f"{label}: blocked comparison not reported: {decided - blocked}"
    assert report.coverage_lost is bool(decided or report.indeterminate), label
    return report


@pytest.mark.parametrize("container", _CONTAINERS)
def test_marking_a_container_incomplete_derives_nothing(full: Estate, container: str) -> None:
    old = detection.evaluate(full, now=NOW)
    # The full export decides every check, so every check relying on the
    # container must be reported blocked.
    relying = {check for (check, _), d in CHECKS.items() if container in d.containers}
    assert relying <= {check for check, _ in old.containers}
    _assert_nothing_derived(old, _incomplete(full, container), container, container)


@pytest.mark.parametrize("container", _CONTAINERS)
def test_dropping_an_object_of_an_incomplete_container_derives_nothing(
    full: Estate, container: str
) -> None:
    old = detection.evaluate(full, now=NOW)
    cases = list(_drops(_incomplete(full, container), container))
    assert cases, f"{container}: the full export has no object to drop"
    for label, degraded in cases:
        _assert_nothing_derived(old, degraded, container, label)


@pytest.mark.parametrize("container", _CONTAINERS)
def test_the_kitchen_sink_derives_nothing_from_an_incomplete_container(
    full: Estate, container: str
) -> None:
    sink = kitchen_sink(full)
    _assert_nothing_derived(
        detection.evaluate(sink, now=NOW),
        _incomplete(sink, container),
        container,
        f"sink:{container}",
    )


def test_a_complete_container_still_yields_absence_findings(full: Estate) -> None:
    """Control: with the containers complete, an unpublished template is ORPHANED
    and a CA list without an issuing CA leaves ESC15 'unknown' (MEDIUM)."""
    templates = tuple(dataclasses.replace(t, published_by=()) for t in full.templates)
    ev = detection.evaluate(dataclasses.replace(full, templates=templates), now=NOW)
    assert "ORPHANED_TEMPLATE" in {f.check for f in ev.findings}
    roots = tuple(c for c in full.cas if c.kind.value == "root")
    ev = detection.evaluate(dataclasses.replace(full, cas=roots), now=NOW)
    assert any(f.check == "ESC15" and f.severity.value == "medium" for f in ev.findings)


def test_an_incomplete_container_keeps_findings_backed_by_visible_evidence(
    full: Estate,
) -> None:
    """A present unpatched issuing CA still makes ESC15 HIGH, and a present
    non-strict DC still makes ESC14, when their containers are incomplete."""
    ev = detection.evaluate(_incomplete(_incomplete(full, "ca-config"), "dc-config"), now=NOW)
    checks = {(f.check, f.severity.value) for f in ev.findings}
    assert ("ESC15", "high") in checks
    assert ("ESC14", "high") in checks


def test_this_guard_covers_every_declared_container() -> None:
    assert set(_CONTAINERS) == {
        "templates",
        "ca-config",
        "pki-acls",
        "dc-config",
        "principal-mappings",
        "web-endpoints",
        "oid-objects",
        "enrollment-services",
        "certs",
        "crls",
    }
