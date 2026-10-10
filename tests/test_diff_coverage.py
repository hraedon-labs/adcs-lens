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
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from adcs_lens import detection
from adcs_lens.cli import EXIT_DIFF_COVERAGE_LOST, EXIT_DIFF_REGRESSIONS, main
from adcs_lens.consequences import CONSEQUENCES
from adcs_lens.detection import (
    Finding,
    coverage_gaps,
    is_degradation_note,
    run_all,
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

    _rw(base / "ca-config.json", cas)
    _rw(base / "ca-security.json", lambda d: d.__setitem__(CA2, []))

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
                },
            ]
        )

    _rw(base / "templates.json", templates)
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


def evaluate(export: Path) -> tuple[list[Finding], Estate]:
    estate = enrich(ingest(export))
    return run_all(estate, now=NOW), estate


@pytest.fixture(scope="module")
def full_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return build_full_export(tmp_path_factory.mktemp("full") / "export")


@pytest.fixture(scope="module")
def full_findings(full_dir: Path) -> list[Finding]:
    return evaluate(full_dir)[0]


def test_full_export_fires_every_posture_check(full_findings: list[Finding]) -> None:
    """The differential guard is only as wide as this export: pin it to the catalogue."""
    fired = {f.check for f in full_findings if not is_degradation_note(f)}
    assert fired == POSTURE_CHECKS, (
        f"not fired: {sorted(POSTURE_CHECKS - fired)}; unexpected: {sorted(fired - POSTURE_CHECKS)}"
    )


def test_full_export_has_no_coverage_gaps_that_hide_findings(full_dir: Path) -> None:
    findings, estate = evaluate(full_dir)
    hidden = [f for f in findings for g in coverage_gaps(estate) if g.covers(f)]
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


def _assert_no_false_resolution(report: DriftReport, old: list[Finding]) -> None:
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
    full_dir: Path, full_findings: list[Finding], tmp_path: Path, degrade: Callable[[Path], None]
) -> None:
    newer = tmp_path / "newer"
    shutil.copytree(full_dir, newer)
    degrade(newer)
    new_findings, new_estate = evaluate(newer)
    report = diff_findings(full_findings, new_findings, coverage=coverage_gaps(new_estate))
    _assert_no_false_resolution(report, full_findings)
    # Every older posture finding is accounted for: still present (unchanged /
    # changed) or withheld — never silently gone.
    present = {(f.check, f.subject, f.source) for f in new_findings}
    withheld = {
        (i.finding.check, i.finding.subject, i.finding.source) for i in report.indeterminate
    }
    for f in full_findings:
        if is_degradation_note(f):
            continue
        key = (f.check, f.subject, f.source)
        assert key in present or key in withheld, f"{key} vanished"


def test_certs_extra_absent_is_never_a_resolution(
    full_dir: Path, full_findings: list[Finding], monkeypatch: pytest.MonkeyPatch
) -> None:
    import adcs_lens.ingest as ingest_mod

    monkeypatch.setattr(ingest_mod, "_try_load_certs", lambda: None)
    new_findings, new_estate = evaluate(full_dir)
    assert not new_estate.manifest.certs_parsed
    report = diff_findings(full_findings, new_findings, coverage=coverage_gaps(new_estate))
    _assert_no_false_resolution(report, full_findings)
    assert {i.finding.check for i in report.indeterminate} >= {"CA_CERT_EXPIRY", "CRL_EXPIRY"}


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
    ],
)
def test_estate_level_lifecycle_gaps_are_never_a_resolution(
    full_dir: Path, full_findings: list[Finding], mutate: Callable[[Estate], Estate]
) -> None:
    # Not producible from DER via this fixture, but the detectors branch on them.
    new_estate = mutate(evaluate(full_dir)[1])
    new_findings = run_all(new_estate, now=NOW)
    report = diff_findings(full_findings, new_findings, coverage=coverage_gaps(new_estate))
    _assert_no_false_resolution(report, full_findings)
    assert report.indeterminate


# --- precision: real fixes still resolve; gaps stay narrow -----------------------


def test_real_fix_still_resolves(
    full_dir: Path, full_findings: list[Finding], tmp_path: Path
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
    full_dir: Path, full_findings: list[Finding], tmp_path: Path
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
    full_dir: Path, full_findings: list[Finding], tmp_path: Path
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
    report = diff_findings(run_all(eo), run_all(en), coverage=coverage_gaps(en))
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
    return diff_findings(run_all(ingest(old)), run_all(en), coverage=coverage_gaps(en))


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


def test_degradation_notes_are_never_withheld() -> None:
    note = Finding(check="PKI_ACL_UNREADABLE", severity=detection.Severity.INFO, title="t",
                   subject="s", detail="d", source="x")
    report = diff_findings([note], [], coverage=(detection.CoverageGap(reason="r"),))
    assert report.resolved == (note,)
    assert report.indeterminate == ()


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
    (CertAuthority, "security_collected"): "ca-security-entry:*",
    (CertAuthority, "audit_filter"): "ca-audit:*",
    (CertAuthority, "ca_patch_state"): (
        "not a coverage marker: UNKNOWN keeps ESC15 firing at MEDIUM (fails toward flagging); "
        "ca-config loss is covered by skip:ca-config"
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
