"""Drift coverage honesty: an absence caused by lost coverage is never a "fix".

The guard here is differential and does not trust any hand-written list of
which checks a degradation affects:

1. Build a *full-coverage* export in which every posture check in the
   consequences catalogue fires at least once (asserted).
2. Degrade a copy along exactly one coverage path — a skipped pass, a missing
   file, an unreadable DACL, an uncollected CA registry, an unknown collector
   version, ... — changing nothing about the estate's real posture.
3. Diff full -> degraded. Since nothing was fixed, NO posture finding may be
   reported resolved (or severity-improved); every old posture finding that is
   absent must sit in ``indeterminate``; and ``diff --exit-code`` must not
   return the clean code.

The tripwires at the bottom fail when a new pass name or a new coverage-shaped
model field appears without a degradation case here, so a detector cannot grow
a new skip path that the coverage map silently ignores.
"""

from __future__ import annotations

import ast
import dataclasses
import json
import shutil
import types
import typing
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from adcs_lens import detection
from adcs_lens.cli import EXIT_DIFF_COVERAGE_LOST, EXIT_DIFF_REGRESSIONS, main
from adcs_lens.consequences import CONSEQUENCES
from adcs_lens.detection import (
    Evaluation,
    Finding,
    coverage_gaps,
    is_degradation_note,
)
from adcs_lens.diff import DriftReport, diff_findings
from adcs_lens.display import (
    render_diff_html,
    render_diff_json,
    render_diff_sarif,
    render_diff_text,
)
from adcs_lens.ingest import ingest
from adcs_lens.model import (
    KNOWN_PASSES,
    PASS_FILES,
    SEVERITY_RANK,
    CertAuthority,
    CertKind,
    CertLifecycle,
    CertTemplate,
    Crl,
    CrlTier,
    DcConfiguration,
    Estate,
    Manifest,
    PkiObjectAcl,
)
from tests.conftest import NOW
from tests.fixtures.build_fixture import (
    HIGH_PRIV_SID,
    ISSUING_CA,
    LOW_PRIV_SID,
    POLICY_OID,
    ROOT_CA,
    build_export,
    collector_defaults,
)

pytest.importorskip("cryptography")
pytestmark = pytest.mark.certs

CA2 = "LAB Issuing CA 2"
_ENROLL = [
    {
        "trustee_sid": LOW_PRIV_SID,
        "trustee_name": "Domain Users",
        "rights": ["Enroll"],
        "ace_type": "Allow",
    }
]

POSTURE_CHECKS = frozenset(c for c in CONSEQUENCES if c not in detection._DEGRADATION_NOTES)


# --- full-coverage export --------------------------------------------------------


def _rw(path: Path, mutate: Callable[[Any], Any]) -> None:
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    out = mutate(data)
    path.write_text(json.dumps(data if out is None else out), encoding="utf-8")


def _rw_full(path: Path, mutate: Callable[[Any], Any]) -> None:
    """_rw for building the full export: also add the collector's defaults."""
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    out = mutate(data)
    data = data if out is None else out
    collector_defaults(path.name, data)
    path.write_text(json.dumps(data), encoding="utf-8")


def build_full_export(out: Path) -> Path:
    """The synthetic export, extended so every posture check fires."""
    base = build_export(out, with_certs=True, now=NOW)

    def cas(data: list[dict[str, Any]]) -> None:
        for ca in data:
            if ca["name"] == ISSUING_CA:
                ca["owner_sid"] = LOW_PRIV_SID  # ESC7 owner-based control
        data.append(
            {
                "name": CA2,
                "dns": "labca02.lab.example.com",
                "config_string": f"labca02.lab.example.com\\{CA2}",
                "kind": "issuing",
                "edit_flags": [],
                "interface_flags": [],  # ESC11: encrypted requests not enforced
                "audit_filter": 0x3F,  # CA_AUDIT_UNDERSCOPED
                "disabled_extensions": [],
                "ca_patch_state": "unknown",
                "owner_sid": HIGH_PRIV_SID,
                "registry_config_collected": True,
            }
        )

    _rw_full(base / "ca-config.json", cas)
    _rw_full(base / "ca-security.json", lambda d: d.__setitem__(CA2, []))

    def templates(data: list[dict[str, Any]]) -> None:
        for t in data:
            t.setdefault("owner_sid", HIGH_PRIV_SID)
        data.extend(
            [
                {
                    "name": "LabEsc1",
                    "display_name": "Lab ESC1",
                    "schema_version": 2,
                    "oid": "1.3.6.1.4.1.311.21.8.1.2.3.4.130",
                    "ekus": ["1.3.6.1.5.5.7.3.2"],  # client auth
                    "name_flags": ["ENROLLEE_SUPPLIES_SUBJECT"],
                    "enrollment_flags": [],
                    "min_key_size": 1024,  # WEAK_TEMPLATE_KEY_SIZE
                    "issuance_policy_oids": [POLICY_OID],  # ESC13 (group-linked)
                    "security": _ENROLL,
                    "owner_sid": HIGH_PRIV_SID,
                    "acl_obtained": True,
                },
                {
                    "name": "LabAnyPurpose",
                    "display_name": "Lab Any Purpose",
                    "schema_version": 2,
                    "oid": "1.3.6.1.4.1.311.21.8.1.2.3.4.131",
                    "ekus": [],  # ESC2
                    "name_flags": [],
                    "enrollment_flags": [],
                    "min_key_size": 2048,
                    "issuance_policy_oids": [],
                    "security": _ENROLL,
                    "owner_sid": HIGH_PRIV_SID,
                    "acl_obtained": True,
                },
                {
                    "name": "LabAgent",
                    "display_name": "Lab Agent",
                    "schema_version": 2,
                    "oid": "1.3.6.1.4.1.311.21.8.1.2.3.4.132",
                    "ekus": ["1.3.6.1.4.1.311.20.2.1"],  # ESC3
                    "name_flags": [],
                    "enrollment_flags": [],
                    "min_key_size": 2048,
                    "issuance_policy_oids": [],
                    "security": [
                        *_ENROLL,
                        {
                            "trustee_sid": LOW_PRIV_SID,
                            "trustee_name": "Domain Users",
                            "rights": ["GenericWrite"],  # ESC4 (DACL control)
                            "ace_type": "Allow",
                        },
                    ],
                    "owner_sid": HIGH_PRIV_SID,
                    "acl_obtained": True,
                },
            ]
        )

    _rw_full(base / "templates.json", templates)
    _rw(
        base / "oid-objects.json",
        lambda d: d[0].__setitem__(
            "group_link", "CN=Lab Admins,OU=Groups,DC=lab,DC=example,DC=com"
        ),
    )
    _rw(
        base / "pki-acls.json",
        lambda d: [o.setdefault("owner_sid", HIGH_PRIV_SID) for o in d] and None,
    )
    return base


def enrich(estate: Estate) -> Estate:
    """Attach a SHA-1 / 1024-bit / no-AIA / no-CDP cert to CA2 when lifecycle ran.

    This cryptography build refuses SHA-1 signatures, so the weak cert is
    injected post-ingest (applied identically to both sides of every diff).
    """
    if not estate.manifest.certs_parsed:
        return estate
    weak = CertLifecycle(
        subject="CN=LAB Issuing CA 2",
        kind=CertKind.ISSUING_CA,
        not_before=NOW - timedelta(days=10),
        not_after=NOW + timedelta(days=900),
        sig_alg="sha1WithRSAEncryption",
        key_bits=1024,
        key_alg="rsa",
    )
    cas = tuple(
        dataclasses.replace(ca, certs=(*ca.certs, weak)) if ca.name == CA2 else ca
        for ca in estate.cas
    )
    # A CRL inside its early-warning window (the DER fixture has none).
    soon = Crl(
        issuer="CN=LAB Issuing CA 2",
        this_update=NOW - timedelta(days=6),
        next_update=NOW + timedelta(hours=12),
        tier=CrlTier.ISSUING,
        source="enriched: early-warning CRL",
    )
    return dataclasses.replace(estate, cas=cas, crls=(*estate.crls, soon))


def evaluate(export: Path) -> tuple[Evaluation, Estate]:
    estate = enrich(ingest(export))
    return detection.evaluate(estate, now=NOW), estate


@pytest.fixture(scope="module")
def full_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return build_full_export(tmp_path_factory.mktemp("full") / "export")


@pytest.fixture(scope="module")
def full_findings(full_dir: Path) -> Evaluation:
    return evaluate(full_dir)[0]


def test_full_export_fires_every_posture_check(full_findings: Evaluation) -> None:
    """The differential guard is only as wide as this export: pin it to the catalogue."""
    fired = {f.check for f in full_findings.findings if not is_degradation_note(f)}
    assert fired == POSTURE_CHECKS, (
        f"not fired: {sorted(POSTURE_CHECKS - fired)}; unexpected: {sorted(fired - POSTURE_CHECKS)}"
    )


def test_full_export_has_no_coverage_gaps_that_hide_findings(full_dir: Path) -> None:
    ev, estate = evaluate(full_dir)
    hidden = [f for f in ev.findings for g in coverage_gaps(estate) if g.covers(f)]
    # A gap may exist in the full export (e.g. the deliberately unreadable
    # template), but it must not cover any finding the export still reports.
    assert hidden == []


# --- degradation paths ---------------------------------------------------------


def _manifest(base: Path, mutate: Callable[[dict[str, Any]], None]) -> None:
    _rw(base / "collector-manifest.json", mutate)


def _skip_pass(pass_name: str) -> Callable[[Path], None]:
    def apply(base: Path) -> None:
        _manifest(base, lambda m: m["skipped_passes"].append(pass_name))
        if pass_name in PASS_FILES:
            (base / PASS_FILES[pass_name]).unlink(missing_ok=True)
            if pass_name == "certs":
                shutil.rmtree(base / "certs", ignore_errors=True)

    return apply


def _missing_file(pass_name: str) -> Callable[[Path], None]:
    def apply(base: Path) -> None:
        _manifest(base, lambda m: m.__setitem__("collector_version", "0.7.0"))
        (base / PASS_FILES[pass_name]).unlink()

    return apply


def _set_version(version: str | None) -> Callable[[Path], None]:
    def apply(base: Path) -> None:
        def m(d: dict[str, Any]) -> None:
            if version is None:
                d.pop("collector_version", None)
            else:
                d["collector_version"] = version

        _manifest(base, m)

    return apply


def _each(
    base: Path, file: str, key: str, value: str, mutate: Callable[[dict[str, Any]], None]
) -> None:
    def go(data: list[dict[str, Any]]) -> None:
        hits = [o for o in data if o.get(key) == value]
        assert hits, f"{value!r} not in {file}"
        for o in hits:
            mutate(o)

    _rw(base / file, go)


def _template(name: str, mutate: Callable[[dict[str, Any]], None]) -> Callable[[Path], None]:
    return lambda base: _each(base, "templates.json", "name", name, mutate)


def _pki(dn: str, mutate: Callable[[dict[str, Any]], None]) -> Callable[[Path], None]:
    return lambda base: _each(base, "pki-acls.json", "object_dn", dn, mutate)


def _ca(name: str, mutate: Callable[[dict[str, Any]], None]) -> Callable[[Path], None]:
    return lambda base: _each(base, "ca-config.json", "name", name, mutate)


def _ca_remote(name: str) -> Callable[[Path], None]:
    """What the collector emits for a CA whose registry it could not read."""

    def apply(base: Path) -> None:
        def m(ca: dict[str, Any]) -> None:
            ca.update(
                edit_flags=[],
                interface_flags=[],
                audit_filter=None,
                disabled_extensions=[],
                owner_sid="",
                registry_config_collected=False,
            )

        _each(base, "ca-config.json", "name", name, m)
        _rw(base / "ca-security.json", lambda d: d.__setitem__(name, []))

    return apply


def _ca_security_entry_absent(name: str) -> Callable[[Path], None]:
    return lambda base: _rw(base / "ca-security.json", lambda d: d.pop(name) and None)


def _dc_wmi_failed(name: str) -> Callable[[Path], None]:
    def m(dc: dict[str, Any]) -> None:
        dc["strong_certificate_binding_enforcement"] = "unknown"
        dc["schannel_mapping_methods"] = []

    return lambda base: _each(base, "dc-config.json", "name", name, m)


def _cn_oid_change(name: str) -> Callable[[Path], None]:
    """Rename a template's cn AND OID (publication follows the OID) + lose its DACL."""

    def apply(base: Path) -> None:
        data = json.loads((base / "templates.json").read_text(encoding="utf-8-sig"))
        tmpl = next(t for t in data if t["name"] == name)
        old_oid, new_oid = tmpl["oid"], tmpl["oid"] + ".9"
        tmpl.update(name=name + "X", oid=new_oid, acl_obtained=False, security=[])
        (base / "templates.json").write_text(json.dumps(data), encoding="utf-8")
        def republish(services: dict[str, list[str]]) -> None:
            for refs in services.values():
                refs[:] = [new_oid if r == old_oid else r for r in refs]

        _rw(base / "enrollment-services.json", republish)

    return apply


def _drop_index_entry(kind: str, index: int) -> Callable[[Path], None]:
    """Remove one cert or CRL from certs/index.json (a partially populated index)."""

    def apply(base: Path) -> None:
        def m(d: dict[str, Any]) -> None:
            del d[kind][index]

        _rw(base / "certs" / "index.json", m)

    return apply


def _set(key: str, value: Any) -> Callable[[dict[str, Any]], None]:
    return lambda o: o.__setitem__(key, value)


def _pop(key: str) -> Callable[[dict[str, Any]], None]:
    return lambda o: o.pop(key, None) and None


_TEMPLATES = [
    "LabWebServer",
    "LegacyV1WebServer",
    "LabEcdsaClient",
    "LabOwnedTemplate",
    "LabScopedWriteTemplate",
    "LabEsc1",
    "LabAnyPurpose",
    "LabAgent",
]
_PKI = [
    "CN=NTAuthCertificates,...,DC=lab,DC=example,DC=com",
    "CN=Public Key Services,...,DC=lab,DC=example,DC=com",
    "CN=AIA,CN=Public Key Services,...,DC=lab,DC=example,DC=com",
]
_CAS = [ROOT_CA, ISSUING_CA, CA2]


def _degradations() -> Iterator[Any]:
    for p in sorted(KNOWN_PASSES):
        yield pytest.param(_skip_pass(p), id=f"skip:{p}")
    for p in sorted(PASS_FILES):
        yield pytest.param(_missing_file(p), id=f"missing-file:{p}")
    for v in ("unknown", "", "garbage", "0.7.0", None):
        yield pytest.param(_set_version(v), id=f"version:{v!r}")
    for t in _TEMPLATES:
        yield pytest.param(_template(t, _set("acl_obtained", False)), id=f"template-acl:{t}")
        # What the collector actually emits for an unreadable SD: no ACEs too.
        yield pytest.param(
            _template(t, lambda o: o.update(security=[], acl_obtained=False)),
            id=f"template-acl-and-aces:{t}",
        )
        yield pytest.param(_template(t, _pop("owner_sid")), id=f"template-owner:{t}")
        yield pytest.param(_template(t, _set("min_key_size", None)), id=f"template-keysize:{t}")
    for dn in _PKI:
        yield pytest.param(
            _pki(dn, lambda o: o.update(acl_obtained=False)), id=f"pki-acl:{dn[:12]}"
        )
        yield pytest.param(_pki(dn, _set("owner_sid", "")), id=f"pki-owner:{dn[:12]}")
    for ca in _CAS:
        yield pytest.param(_ca_remote(ca), id=f"ca-registry:{ca}")
        yield pytest.param(_ca_security_entry_absent(ca), id=f"ca-security-entry:{ca}")
        yield pytest.param(_ca(ca, _set("owner_sid", "")), id=f"ca-owner:{ca}")
        yield pytest.param(_ca(ca, _set("audit_filter", None)), id=f"ca-audit:{ca}")
    for dc in ("LAB-DC01", "LAB-DC02"):
        yield pytest.param(_dc_wmi_failed(dc), id=f"dc-binding-unknown:{dc}")
    yield pytest.param(
        lambda base: _rw(base / "dc-config.json", lambda d: []), id="dc-config-empty"
    )
    # --- identity drift combined with coverage loss (review round 1) ---------
    # Presentation text changes in the newer export while coverage drops. The
    # gap and the match must use stable identity (OID / cn / CA name / DN), so
    # none of these may read as a resolution.
    for t in _TEMPLATES:
        yield pytest.param(
            _template(t, lambda o: o.update(
                display_name=o["display_name"] + " RENAMED", acl_obtained=False, security=[]
            )),
            id=f"rename-display+acl:{t}",
        )
        yield pytest.param(
            _template(t, lambda o: o.update(display_name="", acl_obtained=False)),
            id=f"clear-display+acl:{t}",
        )
        yield pytest.param(
            _template(t, lambda o: (o.update(name=o["name"] + "Renamed"), o.pop("owner_sid"))
                      and None),
            id=f"rename-cn+owner:{t}",
        )
    for ca in _CAS:
        yield pytest.param(
            _ca(ca, lambda o: o.update(config_string="NEW\\" + o["name"], owner_sid="")),
            id=f"config-string+owner:{ca}",
        )
        yield pytest.param(
            _ca(ca, lambda o: o.update(config_string="NEW\\" + o["name"], audit_filter=None)),
            id=f"config-string+audit:{ca}",
        )
    for dn in _PKI:
        yield pytest.param(
            _pki(dn, lambda o: o.update(object_dn=o["object_dn"].upper(), acl_obtained=False)),
            id=f"dn-case+pki-acl:{dn[:12]}",
        )
    # REAL renames (not case changes) together with coverage loss. With
    # objectGUID identity (collector >= 0.9.0, as here) the object pairs on its
    # GUID, so the gap is per-object and nothing resolves or turns NEW.
    yield pytest.param(
        lambda base: _each(base, "dc-config.json", "name", "LAB-DC01", lambda d: d.update(
            name="LAB-DC01-RENAMED", strong_certificate_binding_enforcement="unknown",
            schannel_mapping_methods=[],
        )),
        id="dc-rename+binding-unknown",
    )
    yield pytest.param(
        lambda base: (
            _each(base, "ca-config.json", "name", ISSUING_CA, lambda c: c.update(
                name=ISSUING_CA + " RENAMED", edit_flags=[], interface_flags=[],
                audit_filter=None, disabled_extensions=[], owner_sid="",
                registry_config_collected=False,
            )),
            _rw(base / "ca-security.json", lambda d: d.__setitem__(ISSUING_CA + " RENAMED", [])),
        ) and None,
        id="ca-cn-rename+registry-lost",
    )
    for t in _TEMPLATES:
        yield pytest.param(_cn_oid_change(t), id=f"template-cn+oid-change+acl:{t}")
    # --- weaker evidence is never an improvement (ESC15 patch state) ---------
    yield pytest.param(_ca(ISSUING_CA, _set("ca_patch_state", "unknown")), id="patch-unknown")
    # --- partial certs/index.json (reachable from the real collector) --------
    for kind in ("certs", "crls"):
        for i in range(2):
            yield pytest.param(_drop_index_entry(kind, i), id=f"index-drop-{kind}:{i}")


def _assert_no_false_resolution(report: DriftReport, old_ev: Evaluation) -> None:
    old = list(old_ev.findings)
    resolved = [f.check for f in report.resolved if not is_degradation_note(f)]
    assert resolved == [], f"coverage loss reported as resolution: {resolved}"
    improved = [
        d.new.check
        for d in report.changed
        if SEVERITY_RANK[d.new.severity] > SEVERITY_RANK[d.old.severity]
        and not is_degradation_note(d.new)
    ]
    assert improved == [], f"coverage loss reported as improvement: {improved}"
    withheld = {
        (i.finding.check, i.finding.subject, i.finding.source) for i in report.indeterminate
    }
    old_posture = {(f.check, f.subject, f.source) for f in old if not is_degradation_note(f)}
    assert old_posture  # sanity: the full export has posture findings
    assert all(i.reason for i in report.indeterminate)
    # Everything withheld is a posture finding from the older export.
    assert withheld <= old_posture


@pytest.mark.parametrize("degrade", list(_degradations()))
def test_coverage_loss_is_never_a_resolution(
    full_dir: Path, full_findings: Evaluation, tmp_path: Path, degrade: Callable[[Path], None]
) -> None:
    newer = tmp_path / "newer"
    shutil.copytree(full_dir, newer)
    degrade(newer)
    new_findings, new_estate = evaluate(newer)
    report = diff_findings(full_findings, new_findings, coverage=coverage_gaps(new_estate))
    _assert_no_false_resolution(report, full_findings)
    # (Every older posture finding is matched, resolved or withheld by
    # construction; resolved is asserted empty above.) Pure coverage loss must
    # not invent regressions either.
    assert report.regressions is False, [x.check for x in report.new]


def test_certs_extra_absent_is_never_a_resolution(
    full_dir: Path, full_findings: Evaluation, monkeypatch: pytest.MonkeyPatch
) -> None:
    import adcs_lens.ingest as ingest_mod

    monkeypatch.setattr(ingest_mod, "_try_load_certs", lambda: None)
    new_findings, new_estate = evaluate(full_dir)
    assert not new_estate.manifest.certs_parsed
    report = diff_findings(full_findings, new_findings, coverage=coverage_gaps(new_estate))
    _assert_no_false_resolution(report, full_findings)
    assert {i.finding.check for i in report.indeterminate} >= {"CA_CERT_EXPIRY", "CRL_EXPIRY"}


def _map_certs(e: Estate, fn: Callable[[CertLifecycle], CertLifecycle]) -> Estate:
    return dataclasses.replace(
        e,
        cas=tuple(dataclasses.replace(ca, certs=tuple(fn(c) for c in ca.certs)) for ca in e.cas),
        unattached_certs=tuple((n, fn(c)) for n, c in e.unattached_certs),
    )


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(
            lambda e: dataclasses.replace(
                e,
                crls=tuple(dataclasses.replace(c, next_update=None) for c in e.crls),
            ),
            id="crl-next-update-unreadable",
        ),
        pytest.param(
            lambda e: dataclasses.replace(
                e,
                crls=tuple(dataclasses.replace(c, this_update=None) for c in e.crls),
            ),
            id="crl-this-update-unreadable",
        ),
        pytest.param(
            lambda e: dataclasses.replace(
                e,
                cas=tuple(
                    dataclasses.replace(
                        ca,
                        certs=tuple(
                            dataclasses.replace(c, not_after=None, key_bits=None)
                            for c in ca.certs
                        ),
                    )
                    for ca in e.cas
                ),
            ),
            id="cert-fields-unreadable",
        ),
        pytest.param(
            lambda e: _map_certs(e, lambda c: dataclasses.replace(c, sig_alg="unknown")),
            id="cert-sig-alg-unknown",
        ),
        pytest.param(
            lambda e: _map_certs(e, lambda c: dataclasses.replace(c, key_alg="")),
            id="cert-key-alg-unknown",
        ),
    ],
)
def test_estate_level_lifecycle_gaps_are_never_a_resolution(
    full_dir: Path, full_findings: Evaluation, mutate: Callable[[Estate], Estate]
) -> None:
    # Not producible from DER via this fixture, but the detectors branch on them.
    new_estate = mutate(evaluate(full_dir)[1])
    new_findings = detection.evaluate(new_estate, now=NOW)
    report = diff_findings(full_findings, new_findings, coverage=coverage_gaps(new_estate))
    _assert_no_false_resolution(report, full_findings)
    assert report.indeterminate


# --- precision: real fixes still resolve; gaps stay narrow -----------------------


def test_real_fix_still_resolves(
    full_dir: Path, full_findings: Evaluation, tmp_path: Path
) -> None:
    newer = tmp_path / "newer"
    shutil.copytree(full_dir, newer)
    _ca(ISSUING_CA, _set("edit_flags", []))(newer)  # remove EDITF_ATTRIBUTESUBJECTALTNAME2
    new_findings, new_estate = evaluate(newer)
    report = diff_findings(full_findings, new_findings, coverage=coverage_gaps(new_estate))
    assert [f.check for f in report.resolved] == ["ESC6"]
    assert report.indeterminate == ()
    assert not report.coverage_lost


def test_per_object_gap_is_scoped_to_that_object(
    full_dir: Path, full_findings: Evaluation, tmp_path: Path
) -> None:
    newer = tmp_path / "newer"
    shutil.copytree(full_dir, newer)
    _template("LegacyV1WebServer", _set("acl_obtained", False))(newer)
    new_findings, new_estate = evaluate(newer)
    report = diff_findings(full_findings, new_findings, coverage=coverage_gaps(new_estate))
    assert {(i.finding.check, i.finding.subject) for i in report.indeterminate} == {
        ("ESC15", "Legacy V1 Web Server")
    }
    # ESC9 / ESC15 on other templates are untouched.
    assert ("ESC9", "Lab Web Server") not in {(i.finding.check, i.finding.subject)
                                              for i in report.indeterminate}


def test_owner_gap_withholds_only_the_owner_variant(
    full_dir: Path, full_findings: Evaluation, tmp_path: Path
) -> None:
    newer = tmp_path / "newer"
    shutil.copytree(full_dir, newer)
    # Drop the owner on the low-priv-owned template AND fix its DACL-free state:
    # the owner-based ESC4 is withheld, nothing else on that template is.
    _template("LabOwnedTemplate", _pop("owner_sid"))(newer)
    new_findings, new_estate = evaluate(newer)
    report = diff_findings(full_findings, new_findings, coverage=coverage_gaps(new_estate))
    assert [(i.finding.check, i.finding.source) for i in report.indeterminate] == [
        ("ESC4", "template 'LabOwnedTemplate': nTSecurityDescriptor owner")
    ]


# --- the coordinator's repro, end to end ----------------------------------------


def test_repro_skipped_template_and_ca_security_withholds_high_findings(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Newer export skips template-security + ca-security (repro of the review bug).

    Before the fix ESC4/ESC7/ESC9/ESC15 (HIGH) were listed as resolved,
    ``regressions`` was False and ``diff --exit-code`` returned 0.
    """
    old = build_export(tmp_path / "old")
    new = build_export(tmp_path / "new")
    _manifest(new, lambda m: m.__setitem__(
        "skipped_passes", ["certs", "template-security", "ca-security"]))
    eo, en = ingest(old), ingest(new)
    report = diff_findings(
        detection.evaluate(eo), detection.evaluate(en), coverage=coverage_gaps(en)
    )
    assert [f for f in report.resolved if not is_degradation_note(f)] == []
    withheld = {i.finding.check for i in report.indeterminate}
    assert {"ESC4", "ESC7", "ESC9", "ESC15"} <= withheld
    assert report.regressions is False
    assert report.coverage_lost is True

    rc = main(["diff", str(old), str(new), "--exit-code"])
    assert rc == EXIT_DIFF_COVERAGE_LOST == 3
    out = capsys.readouterr().out
    assert "COVERAGE LOST" in out
    assert "[? NOT RE-EVALUATED] [HIGH] ESC9" in out
    assert "[- RESOLVED] [HIGH]" not in out


def test_regressions_dominate_coverage_loss(tmp_path: Path) -> None:
    old = build_export(tmp_path / "old")
    new = build_export(tmp_path / "new")
    _manifest(new, lambda m: m.__setitem__("skipped_passes", ["certs", "ca-security"]))
    _ca(ISSUING_CA, _set("interface_flags", []))(new)  # ESC11 appears
    assert main(["diff", str(old), str(new), "--exit-code"]) == EXIT_DIFF_REGRESSIONS == 1


def test_no_exit_code_flag_stays_zero_on_coverage_loss(tmp_path: Path) -> None:
    old = build_export(tmp_path / "old")
    new = build_export(tmp_path / "new")
    _manifest(new, lambda m: m.__setitem__("skipped_passes", ["certs", "pki-acls"]))
    assert main(["diff", str(old), str(new)]) == 0


# --- every renderer shows the withheld bucket -----------------------------------


@pytest.fixture
def lossy_report(tmp_path: Path) -> DriftReport:
    old = build_export(tmp_path / "old")
    new = build_export(tmp_path / "new")
    _manifest(new, lambda m: m.__setitem__("skipped_passes", ["certs", "pki-acls"]))
    en = ingest(new)
    return diff_findings(
        detection.evaluate(ingest(old)), detection.evaluate(en), coverage=coverage_gaps(en)
    )


def test_json_envelope_carries_indeterminate(lossy_report: DriftReport) -> None:
    env = json.loads(render_diff_json(lossy_report))
    assert env["schema_version"] == 4
    assert env["summary"]["indeterminate"] == len(env["indeterminate"]) > 0
    assert env["summary"]["coverage_lost"] is True
    item = env["indeterminate"][0]
    assert item["check"] == "ESC5"
    assert "pki-acls" in item["reason"]
    assert item["current_severity"] is None
    assert "consequence" in item
    assert not any(f["check"] == "ESC5" for f in env["resolved"])


def test_sarif_keeps_withheld_alerts_open(lossy_report: DriftReport) -> None:
    sarif = json.loads(render_diff_sarif(lossy_report))
    results = sarif["runs"][0]["results"]
    esc5 = [r for r in results if r["ruleId"] == "ESC5"]
    assert esc5
    for r in esc5:
        assert r["baselineState"] == "unchanged"  # never "absent" (which closes it)
        assert r["properties"]["adcsLensDrift"] == "indeterminate"
        assert "pki-acls" in r["properties"]["coverageLostReason"]


def test_sarif_with_indeterminate_validates(lossy_report: DriftReport) -> None:
    jsonschema = pytest.importorskip("jsonschema")
    schema_path = Path(__file__).parent / "fixtures" / "sarif-2.1.0.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    jsonschema.validate(json.loads(render_diff_sarif(lossy_report)), schema)


def test_html_has_coverage_lost_section(lossy_report: DriftReport) -> None:
    out = render_diff_html(lossy_report)
    assert 'id="indeterminate-findings"' in out
    assert "Coverage lost." in out
    assert "No drift" not in out


def test_text_has_coverage_lost_banner(lossy_report: DriftReport) -> None:
    out = render_diff_text(lossy_report)
    assert "COVERAGE LOST" in out
    assert "?2 not re-evaluated" in out or "not re-evaluated" in out
    assert "(no drift)" not in out


def test_withheld_only_report_is_not_no_drift() -> None:
    f = Finding(check="ESC8", severity=detection.Severity.HIGH, title="t", subject="s",
                detail="d", source="x")
    report = diff_findings(
        [f], [], coverage=(detection.CoverageGap(reason="r", checks=frozenset({"ESC8"})),)
    )
    assert "(no drift)" not in render_diff_text(report)
    assert "No drift" not in render_diff_html(report)


def test_degradation_notes_are_coverage_transitions_not_resolutions() -> None:
    note = Finding(check="PKI_ACL_UNREADABLE", severity=detection.Severity.INFO, title="t",
                   subject="s", detail="d", source="x")
    report = diff_findings([note], [], coverage=(detection.CoverageGap(reason="r"),))
    assert report.resolved == ()
    assert report.indeterminate == ()
    assert [(c.finding, c.direction) for c in report.coverage_changes] == [(note, "cleared")]
    appeared = diff_findings([], [note])
    assert appeared.new == () and appeared.regressions is False
    assert [c.direction for c in appeared.coverage_changes] == ["appeared"]
    assert "COVERAGE CLEARED" in render_diff_text(report)
    assert "[- RESOLVED]" not in render_diff_text(report)
    env = json.loads(render_diff_json(report))
    assert env["resolved"] == [] and env["coverage_changes"][0]["direction"] == "cleared"


# --- reviewer probes (round 1), copied verbatim as regression fixtures ---------
# tests/fixtures/review_probes/<name>/{old,new} are the exports the two
# adversarial reviewers used to reproduce false resolutions (Sol: sol_*, DeepSeek:
# ds_*). They were upgraded only by adding the coverage markers the current
# collector always writes, where absent; each probe's own mutation is intact.
_PROBES = Path(__file__).parent / "fixtures" / "review_probes"
@dataclass(frozen=True)
class _Expect:
    rc: int
    withheld: dict[str, str | None] = dataclasses.field(default_factory=dict)
    resolved: frozenset[str] = frozenset()  # exact set of resolved posture checks
    new: frozenset[str] = frozenset()  # posture checks that must surface as NEW
    error: str | None = None  # ingest error substring (rc 1)


_PROBE_EXPECT: dict[str, _Expect] = {
    # --- round 1 --------------------------------------------------------------
    "ds_caowner_cli": _Expect(3, {"ESC7": None}),
    "ds_rekey_webserver": _Expect(3, {"ESC9": None}),
    "sol_esc15_patch_unknown": _Expect(3, {"ESC15": "medium"}),
    "sol_owner_source_rename": _Expect(3, {"ESC4": None}),
    "sol_partial_certs_index": _Expect(3, {"CA_CERT_EXPIRY": None}),
    # The reviewer regenerated keys for old and new, so the certificates are
    # genuinely different objects (new fingerprint): the newer cert is a new
    # finding (exit 1) and the older ones are withheld, never resolved.
    "sol_partial_crls_index": _Expect(
        1, {"CRL_EXPIRY": None, "CA_CERT_EXPIRY": None}, new=frozenset({"CA_CERT_EXPIRY"})
    ),
    "sol_renamed_unreadable_template": _Expect(3, {"ESC15": None}),
    "sol_template_security_skipped": _Expect(3, {"ESC15": None, "ESC4": None, "ESC9": None}),
    "sol_invalid_pki_acl_flag": _Expect(1, error="acl_obtained must be a JSON boolean"),
    "sol_invalid_registry_flag": _Expect(
        1, error="registry_config_collected must be a JSON boolean"
    ),
    "sol_string_false_template_acl": _Expect(1, error="acl_obtained must be a JSON boolean"),
    "sol_unknown_skip_typo": _Expect(1, error="unknown pass name"),
    "sol_numeric_version_missing_field": _Expect(1, error="collector_version must be a string"),
    # --- round 2 (Sol) ----------------------------------------------------------
    # CA CN renamed while its registry read is lost (legacy identity, no GUID).
    "sol2_ca_rename_coverage_loss": _Expect(
        3, {"ESC6": None, "ESC7": None, "ESC16": None, "CA_AUDIT_DISABLED": None}
    ),
    # Template cn AND OID both change while its DACL becomes unreadable.
    "sol2_template_all_aliases_change_coverage_loss": _Expect(3, {"ESC15": None}),
    # Two CAs share a name / two templates share an OID / one cert indexed
    # twice: ambiguous identity is withheld (old) and NEW (new), never CHANGED.
    "sol2_ca_name_collision": _Expect(
        1, {"ESC6": None, "ESC7": None}, new=frozenset({"ESC6", "ESC7"})
    ),
    "sol2_template_oid_collision": _Expect(1, {"ESC15": None}, new=frozenset({"ESC15"})),
    "sol2_duplicate_cert_fingerprint": _Expect(
        1, {"CA_CERT_EXPIRY": None}, new=frozenset({"CA_CERT_EXPIRY"})
    ),
    # Under the pristine detector nothing changes; the mutant runs are in
    # tests/test_detection_records.py.
    "sol2_mutant_dns_skip": _Expect(0),
    # --- round 2 (DeepSeek) -----------------------------------------------------
    # NB1: a REAL DC rename (LAB-DC01 -> LAB-DC01-RENAMED) with binding unset.
    "ds2_s6b_dc_rename": _Expect(3, {"ESC10": None}),
    "ds2_s6b_norename": _Expect(3, {"ESC10": None}),
    "ds2_s6_dc_rename_unknown": _Expect(3, {"ESC10": None, "ESC14": None}),
    # NB2: a distinct template reuses a removed one's OID: NEW, not CHANGED.
    "ds2_s1_oid_collision": _Expect(1, {"ESC9": None}, new=frozenset({"ESC9"})),
    "ds2_ca_dup": _Expect(1, {"ESC6": None, "ESC7": None}),
    "ds2_life": _Expect(3, {"CA_CERT_EXPIRY": None}),
    "ds2_s7b": _Expect(3, {"ESC9": None}),
    "ds2_s7_both_ids_move": _Expect(1, {"ESC9": None}),
    "ds2_s8_oid_empty": _Expect(1, {"ESC9": None}),
    "ds2_s9_dup_fingerprint": _Expect(1, new=frozenset({"CDP_AIA_ABSENT", "OCSP_URL_ABSENT"})),
    "ds2_s10_esc15_id_move": _Expect(1, {"ESC15": None}, new=frozenset({"ESC15"})),
    # Same cert (same fingerprint) re-homed to another CA: same object, content
    # change only.
    "ds2_s4_fingerprint_dual_ca": _Expect(0),
    # Objects genuinely removed while their container was fully collected and
    # no unmatched object of that type remains: positive evidence -> resolved.
    "ds2_s2_template_removed": _Expect(0, resolved=frozenset({"ESC9"})),
    "ds2_s3_pki_removed": _Expect(0, resolved=frozenset({"ESC5"})),
    "ds2_s5_dc_removed": _Expect(0, resolved=frozenset({"ESC10", "ESC14"})),
}


def test_every_probe_has_an_expectation() -> None:
    assert sorted(p.name for p in _PROBES.iterdir()) == sorted(_PROBE_EXPECT)


@pytest.mark.parametrize("name", sorted(_PROBE_EXPECT))
def test_reviewer_probe(name: str, capsys: pytest.CaptureFixture[str]) -> None:
    exp = _PROBE_EXPECT[name]
    base = _PROBES / name
    rc = main(["diff", str(base / "old"), str(base / "new"), "--exit-code", "--json"])
    out = capsys.readouterr()
    assert rc == exp.rc, out.err
    if exp.error is not None:
        assert exp.error in out.err
        return
    env = json.loads(out.out)
    resolved = {f["check"] for f in env["resolved"] if f["severity"] != "info"}
    assert resolved == exp.resolved
    withheld: dict[str, str | None] = {}
    for i in env["indeterminate"]:
        withheld.setdefault(i["check"], i["current_severity"])
    for check, current in exp.withheld.items():
        assert check in withheld, (check, withheld)
        assert withheld[check] == current
    assert exp.new <= {f["check"] for f in env["new"]}
    # Ambiguity is never relabelled as a change of the same finding.
    if exp.new:
        assert not ({c["check"] for c in env["changed"]} & exp.new)
    assert env["summary"]["coverage_lost"] is bool(exp.withheld)


def test_esc15_unknown_patch_state_withholds_the_improvement(
    full_dir: Path, full_findings: Evaluation, tmp_path: Path
) -> None:
    newer = tmp_path / "newer"
    shutil.copytree(full_dir, newer)
    _ca(ISSUING_CA, _set("ca_patch_state", "unknown"))(newer)
    new_findings, new_estate = evaluate(newer)
    report = diff_findings(full_findings, new_findings, coverage=coverage_gaps(new_estate))
    esc15 = [i for i in report.indeterminate if i.finding.check == "ESC15"]
    assert esc15 and all(
        i.current is not None and i.current.severity.value == "medium" for i in esc15
    )
    assert not [d for d in report.changed if d.new.check == "ESC15"]


def test_presentation_only_changes_are_neither_resolved_nor_new(
    full_dir: Path, full_findings: Evaluation, tmp_path: Path
) -> None:
    newer = tmp_path / "newer"
    shutil.copytree(full_dir, newer)
    for t in _TEMPLATES:
        _template(t, lambda o: o.update(display_name=o["display_name"] + " v2"))(newer)
    for ca in _CAS:
        _ca(ca, lambda o: o.update(config_string="NEW\\" + o["name"]))(newer)
    new_findings, new_estate = evaluate(newer)
    report = diff_findings(full_findings, new_findings, coverage=coverage_gaps(new_estate))
    assert report.resolved == () and report.new == () and report.indeterminate == ()
    assert report.changed and all(d.content_changed for d in report.changed)


def test_every_posture_finding_carries_stable_identity(full_findings: Evaluation) -> None:
    missing = [
        f.check for f in full_findings.findings
        if not is_degradation_note(f) and f.object_ref is None
    ]
    assert missing == []


# --- tripwires: a new skip path must be classified here -------------------------


def test_every_detector_pass_constant_is_a_known_pass() -> None:
    src = Path(detection.__file__).read_text(encoding="utf-8")
    consts = {
        node.targets[0].id: node.value.value
        for node in ast.parse(src).body
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id.endswith("_PASS")
        and isinstance(node.value, ast.Constant)
    }
    assert consts, "expected *_PASS constants in detection.py"
    assert set(consts.values()) <= KNOWN_PASSES, consts


def test_detectors_never_read_skipped_passes_directly() -> None:
    # Detectors must use _pass_collected() (skipped OR missing); reading
    # manifest.skipped_passes would ignore missing files.
    src = Path(detection.__file__).read_text(encoding="utf-8")
    code_lines = [ln for ln in src.splitlines() if ".manifest.skipped_passes" in ln]
    assert code_lines == [
        "    if pass_name in estate.manifest.skipped_passes:"
    ], code_lines


# Every coverage-shaped model field (bool, Optional, or an "unknown"-capable
# enum) must be classified: either a degradation case above exercises it, or
# it is explicitly not a coverage marker. A new such field fails this test
# until someone decides which — and, if it gates a detector, adds a predicate
# + coverage_gaps entry + degradation case.
_COVERAGE_FIELDS: dict[tuple[type, str], str] = {
    (CertTemplate, "acl_obtained"): "template-acl:*",
    (CertTemplate, "min_key_size"): "template-keysize:*",
    (PkiObjectAcl, "acl_obtained"): "pki-acl:*",
    (CertAuthority, "registry_config_collected"): "ca-registry:*",
    (CertAuthority, "enrollment_service"): (
        "identity, not coverage: False only for a standalone CA (no AD object, so "
        "no objectGUID; legacy identity applies to it)"
    ),
    (CertAuthority, "security_collected"): "ca-security-entry:*",
    (CertAuthority, "audit_filter"): "ca-audit:*",
    (CertAuthority, "ca_patch_state"): (
        "evidence, not coverage: UNKNOWN keeps ESC15 firing (MEDIUM) with "
        "evidence_complete=False, so an improvement is withheld (patch-unknown)"
    ),
    (CertLifecycle, "not_before"): "not read by any detector",
    (CertLifecycle, "not_after"): "cert-fields-unreadable",
    (CertLifecycle, "key_bits"): "cert-fields-unreadable",
    (Crl, "this_update"): "crl-this-update-unreadable",
    (Crl, "next_update"): "crl-next-update-unreadable",
    (DcConfiguration, "strong_certificate_binding_enforcement"): "dc-binding-unknown:*",
    (Manifest, "certs_parsed"): "skip:certs / certs-extra-absent",
    (Manifest, "enrollment_services_available"): "skip:enrollment-services",
}
# Owner SIDs are str fields where "" means not captured.
_OWNER_FIELDS = {
    (CertTemplate, "owner_sid"): "template-owner:*",
    (PkiObjectAcl, "owner_sid"): "pki-owner:*",
    (CertAuthority, "owner_sid"): "ca-owner:*",
}


def _coverage_shaped(cls: type) -> set[str]:
    hints = typing.get_type_hints(cls)
    out: set[str] = set()
    for f in dataclasses.fields(cls):
        hint = hints[f.name]
        args = typing.get_args(hint)
        optional = isinstance(hint, types.UnionType) and type(None) in args
        unknown_enum = isinstance(hint, type) and hasattr(hint, "UNKNOWN")
        if hint is bool or optional or unknown_enum:
            out.add(f.name)
    return out


@pytest.mark.parametrize(
    "cls",
    [CertTemplate, PkiObjectAcl, CertAuthority, CertLifecycle, Crl, DcConfiguration, Manifest],
)
def test_every_coverage_shaped_field_is_classified(cls: type) -> None:
    shaped = _coverage_shaped(cls)
    known = {name for (c, name) in _COVERAGE_FIELDS if c is cls}
    assert shaped == known, (
        f"{cls.__name__}: unclassified coverage-shaped fields {sorted(shaped - known)}; "
        f"stale entries {sorted(known - shaped)}"
    )


def test_owner_fields_exist() -> None:
    for cls, name in _OWNER_FIELDS:
        assert name in {f.name for f in dataclasses.fields(cls)}


# --- legacy (pre-GUID) identity: conservative absence rule ----------------------


def _strip(*keys: str) -> Callable[[list[dict[str, Any]]], None]:
    def apply(items: list[dict[str, Any]]) -> None:
        for item in items:
            for k in keys:
                item.pop(k, None)

    return apply


def _legacy(base: Path) -> None:
    """Turn an export into what collector 0.8.0 wrote: no objectGUIDs."""
    _rw(base / "collector-manifest.json", lambda m: m.__setitem__("collector_version", "0.8.0"))
    for name in ("templates.json", "pki-acls.json", "oid-objects.json",
                 "dc-config.json", "principal-mappings.json"):
        _rw(base / name, _strip("object_guid"))
    _rw(base / "ca-config.json", _strip("object_guid", "enrollment_service"))
    _rw(base / "certs" / "index.json", lambda d: _strip("object_guid")(d["crls"]))


_LEGACY_RENAMES = {
    "dc-rename+binding-unknown": lambda base: _each(
        base, "dc-config.json", "name", "LAB-DC01",
        lambda d: d.update(name="LAB-DC01-RENAMED",
                           strong_certificate_binding_enforcement="unknown",
                           schannel_mapping_methods=[]),
    ),
    "template-cn+oid-change+acl": _template(
        "LegacyV1WebServer",
        lambda o: o.update(
            name="LegacyRenamed", oid=o["oid"] + ".9", acl_obtained=False, security=[]
        ),
    ),
}


@pytest.fixture(scope="module")
def legacy_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    base = build_full_export(tmp_path_factory.mktemp("legacy") / "export")
    _legacy(base)
    return base


@pytest.mark.parametrize("name", sorted(_LEGACY_RENAMES))
def test_legacy_rename_with_coverage_loss_is_withheld(
    legacy_dir: Path, tmp_path: Path, name: str
) -> None:
    """No GUID: a renamed object cannot be paired, so its older findings may
    resolve only if the newer export has no unpaired object of that type."""
    old_ev, _ = evaluate(legacy_dir)
    newer = tmp_path / "newer"
    shutil.copytree(legacy_dir, newer)
    _LEGACY_RENAMES[name](newer)
    new_ev, new_estate = evaluate(newer)
    report = diff_findings(old_ev, new_ev, coverage=coverage_gaps(new_estate))
    assert [f.check for f in report.resolved if not is_degradation_note(f)] == []
    assert report.indeterminate


def test_guid_identity_survives_rename(full_dir: Path, full_findings: Evaluation,
                                       tmp_path: Path) -> None:
    """With GUIDs a pure rename (all names change, coverage intact) is CHANGED, not NEW."""
    newer = tmp_path / "newer"
    shutil.copytree(full_dir, newer)
    _template("LegacyV1WebServer", lambda o: o.update(name="Renamed", oid=o["oid"] + ".9",
                                                      display_name="Renamed"))(newer)
    new_ev, new_estate = evaluate(newer)
    report = diff_findings(full_findings, new_ev, coverage=coverage_gaps(new_estate))
    assert report.new == () and report.resolved == () and report.indeterminate == ()
    assert any(d.new.check == "ESC15" and d.content_changed for d in report.changed)


def test_guid_absent_object_resolves_when_container_enumerated(
    full_dir: Path, full_findings: Evaluation, tmp_path: Path
) -> None:
    """A deleted template (GUID gone, templates fully enumerated) is a real fix."""
    newer = tmp_path / "newer"
    shutil.copytree(full_dir, newer)
    _rw(base := newer / "templates.json", lambda ts: [t for t in ts if t["name"] != "LabAgent"])
    assert base.exists()
    new_ev, new_estate = evaluate(newer)
    report = diff_findings(full_findings, new_ev, coverage=coverage_gaps(new_estate))
    resolved = {(f.check, f.subject) for f in report.resolved}
    assert ("ESC3", "Lab Agent") in resolved
    assert report.indeterminate == ()
