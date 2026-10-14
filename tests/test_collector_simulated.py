"""The real collector body, run under pwsh with mocked native transports.

tests/collector/simulate.ps1 executes scripts/Export-AdcsEstate.ps1's own code
(only LDAP, certutil, the CA\\Security hive, security-descriptor parsing, IIS and
WMI are faked) and writes an export; this test ingests it with adcs-lens. It is
the end-to-end check of round 5 ruling C: a failed read reaches the core as
"not obtained" (JSON null), never as an empty list, and an enumeration marker is
complete only when its paged search was proven complete. It is not a substitute
for a live run against an AD CS estate (tracked as WI-044 for the collector).
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from adcs_lens.cli import main
from adcs_lens.detection import evaluate
from adcs_lens.ingest import IngestError, ingest
from adcs_lens.model import CaKind, Estate, StrongCertBinding
from tests.conftest import NOW

_SIMULATE = Path(__file__).parent / "collector" / "simulate.ps1"
_PWSH = shutil.which("pwsh")
pytestmark = pytest.mark.skipif(_PWSH is None, reason="pwsh is not installed")


def _collect(tmp_path: Path, scenario: str, *args: str, name: str = "") -> Path:
    out = tmp_path / (name or scenario)
    assert _PWSH is not None
    proc = subprocess.run(
        [
            _PWSH,
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(_SIMULATE),
            "-OutDir",
            str(out),
            "-Scenario",
            scenario,
            *args,
        ],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return out


@pytest.fixture(scope="module")
def clean(tmp_path_factory: pytest.TempPathFactory) -> Estate:
    return ingest(_collect(tmp_path_factory.mktemp("sim"), "clean"))


@pytest.fixture(scope="module")
def failures(tmp_path_factory: pytest.TempPathFactory) -> Estate:
    return ingest(_collect(tmp_path_factory.mktemp("sim"), "failures"))


def _ca(estate: Estate, name: str):  # type: ignore[no-untyped-def]
    return next(c for c in estate.cas if c.name == name)


def test_clean_collection_is_a_proven_export(clean: Estate) -> None:
    m = clean.manifest
    assert m.collector_version == "0.12.0" and m.reads_proven
    assert m.enumeration_complete >= {
        "ca-config",
        "enrollment-services",
        "templates",
        "oid-objects",
        "pki-acls",
        "dc-config",
        "principal-mappings",
    }
    # WI-044: IIS is read on labca01 only and LAB Issuing CA 2 runs on labca02,
    # so the endpoint list is attributed to labca01 and is not complete.
    assert "web-endpoints" not in m.enumeration_complete
    assert {e.host for e in clean.endpoints} == {"labca01.lab.example.com"}
    local = _ca(clean, "LAB Issuing CA")
    assert local.edit_flags == {"EDITF_ATTRIBUTESUBJECTALTNAME2"}
    assert local.audit_filter == 0  # "= 0" is read (auditing disabled), not "not captured"
    # WI-044: certutil's indexed REG_MULTI_SZ lines yield the values (the OID,
    # without certutil's friendly name), never the "0:" index tokens.
    assert local.disabled_extensions == {"1.3.6.1.4.1.311.25.2", "2.5.29.15"}
    assert local.kind is CaKind.ISSUING and local.unobtained == frozenset()
    remote = _ca(clean, "LAB Issuing CA 2")
    assert not remote.registry_config_collected
    assert {"edit_flags", "interface_flags", "disabled_extensions", "security"} <= remote.unobtained


def test_clean_collection_decides_with_usable_verdicts(clean: Estate) -> None:
    ev = evaluate(clean, now=NOW)
    checks = {(f.check, f.subject) for f in ev.findings}
    assert {
        ("ESC6", "LAB Issuing CA"),
        ("CA_AUDIT_DISABLED", "LAB Issuing CA"),
        ("ESC16", "LAB Issuing CA"),
        ("ESC8", "/CertSrv"),
    } <= checks
    usable = {(v.check, v.state) for v in ev.verdicts if v.usable}
    assert ("ESC6", "finding") in usable and ("ESC1", "finding") in usable
    cdp = next(a for a in clean.acls if a.kind.value == "cdp")
    assert not cdp.acl_obtained and "security" in cdp.unobtained  # unreadable fixed container
    # WI-044: each CA host's own computer account controls its own enrollment
    # service (as AD CS setup grants): allowlisted there, so no ESC5.
    es = [a for a in clean.acls if a.object_dn.startswith("CN=LAB Issuing CA")]
    assert {a.ca_host_sid[-4:] for a in es} == {"1105", "1106"}
    assert not [f for f in ev.findings if f.check == "ESC5" and "Enrollment Services" in f.subject]
    assert ("ESC5", "dacl", "finding") not in {
        (v.check, v.variant, v.state) for v in ev.verdicts if v.usable
    }
    note = next(f for f in ev.findings if f.check == "ENROLLMENT_ENDPOINTS_NOT_EVALUATED")
    assert "labca02.lab.example.com" in note.detail
    assert not [v for v in ev.verdicts if v.check == "ESC8" and v.usable]


def test_failed_reads_reach_the_core_as_not_obtained(failures: Estate) -> None:
    local = _ca(failures, "LAB Issuing CA")
    # certutil EditFlags failed (access denied): not obtained, not "no flags".
    assert "edit_flags" in local.unobtained
    # CAType not configured: the kind is not known (no silent "issuing").
    assert "kind" in local.unobtained
    # DisableExtensionList not configured: a read, empty.
    assert (
        local.disabled_extensions == frozenset() and "disabled_extensions" not in local.unobtained
    )
    # WI-044: AuditFilter not configured is the CA default, 0 (auditing off),
    # not "not obtained".
    assert local.audit_filter == 0 and "audit_filter" not in local.unobtained
    user = next(t for t in failures.templates if t.name == "LabUser")
    assert not user.acl_obtained and "security" in user.unobtained
    ep = next(e for e in failures.endpoints if e.name == "/CertSrv")
    assert "epa" in ep.unobtained
    dc2 = next(d for d in failures.dcs if d.name.startswith("LAB-DC02"))
    assert "strong_certificate_binding_enforcement" in dc2.unobtained
    dc1 = next(d for d in failures.dcs if d.name.startswith("LAB-DC01"))
    assert dc1.strong_certificate_binding_enforcement is StrongCertBinding.STRICT
    # The template search lost a page: the container is not complete.
    assert "templates" not in failures.manifest.enumeration_complete
    # No CA\Security descriptor could be read: the pass is declared skipped.
    assert "ca-security" in failures.manifest.skipped_passes


def test_failed_reads_never_yield_a_usable_clean_verdict(failures: Estate) -> None:
    ev = evaluate(failures, now=NOW)
    by = {(v.check, v.key): v for v in ev.verdicts}
    esc6 = [v for (check, _), v in by.items() if check == "ESC6" and v.state != "undecided"]
    assert all(not v.usable for v in esc6)
    assert not [v for v in ev.verdicts if v.check == "ESC6" and v.usable]
    assert not [v for v in ev.verdicts if v.check in ("ESC1", "ESC9") and v.usable]
    assert ("ESC1", "template") not in ev.containers
    # ESC8 still reports the relay path (the site binds HTTP and sslFlags
    # reads None, so it is open whatever the unread EPA setting) but its
    # verdict cannot clear anything.
    assert "ESC8" in {f.check for f in ev.findings}
    assert not [v for v in ev.verdicts if v.check == "ESC8" and v.usable]
    assert ("CA_AUDIT_DISABLED", "LAB Issuing CA") in {(f.check, f.subject) for f in ev.findings}


# --- round 5 review: every enumerated object is serialized or the container is
# --- marked incomplete ------------------------------------------------------------

_CONTAINERS = (
    "ca-config",
    "enrollment-services",
    "templates",
    "oid-objects",
    "pki-acls",
    "certs",
    "crls",
    "web-endpoints",
    "principal-mappings",
    "dc-config",
)


def test_every_enumeration_loop_marks_a_failed_object_incomplete(tmp_path: Path) -> None:
    """Each loop meets one object it cannot serialize (bad-entries scenario).

    The marker must say complete=false with the reason - the old collector kept
    complete=true and a self-count of the rows it retained.
    """
    out = _collect(tmp_path, "bad-entries")
    manifest = json.loads((out / "collector-manifest.json").read_text(encoding="utf-8"))
    for container in _CONTAINERS:
        marker = manifest["enumeration"][container]
        assert marker["complete"] is False, container
        assert marker["reason"], container
    assert "of 3 enumerated object(s) serialized" in manifest["enumeration"]["templates"]["reason"]
    estate = ingest(out)  # still a well-formed export: counts match the rows written
    assert not estate.manifest.enumeration_complete & set(_CONTAINERS)
    assert not evaluate(estate, now=NOW).containers


def test_a_dc_returned_without_a_dns_name_is_kept_as_a_placeholder(tmp_path: Path) -> None:
    estate = ingest(_collect(tmp_path, "missing-dc-dns"))
    placeholder = next(d for d in estate.dcs if d.object_guid == "09" * 16)
    assert placeholder.unobtained >= {
        "strong_certificate_binding_enforcement",
        "schannel_mapping_methods",
    }
    assert "dc-config" in estate.manifest.enumeration_complete  # every DC serialized


def test_sol_r5_dc_without_dns_does_not_resolve_esc10_or_esc14(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Sol round 5 NEW BLOCKING 1, replayed with the real collector body.

    The DC search returns LAB-DC02 (the only non-strict DC) without dNSHostName.
    At eb3c426 the collector dropped it yet marked dc-config complete, and diff
    resolved ESC10 on LAB-DC02 and ESC14 on the weakly mapped principal (exit 0).
    """
    old, new = _collect(tmp_path, "clean"), _collect(tmp_path, "missing-dc-dns")
    rc = main(["diff", str(old), str(new), "--exit-code", "--json"])
    env = json.loads(capsys.readouterr().out)
    resolved = {f["check"] for f in env["resolved"]}
    assert not resolved & {"ESC10", "ESC14"}
    assert {"ESC10", "ESC14"} <= {i["check"] for i in env["indeterminate"]}
    assert env["summary"]["coverage_lost"] is True
    assert rc == 3


# --- WI-044 live-validation defects, replayed with the real collector body ------


def _env(old: Path, new: Path, capsys: pytest.CaptureFixture[str]) -> tuple[int, dict[str, Any]]:
    capsys.readouterr()
    rc = main(["diff", str(old), str(new), "--exit-code", "--json"])
    return rc, json.loads(capsys.readouterr().out)


def test_wi044_one_ca_on_the_collector_host_completes_the_endpoint_list(tmp_path: Path) -> None:
    estate = ingest(_collect(tmp_path, "clean", "-OneCa", name="one-ca"))
    assert "web-endpoints" in estate.manifest.enumeration_complete
    ev = evaluate(estate, now=NOW)
    assert "ENROLLMENT_ENDPOINTS_NOT_EVALUATED" not in {f.check for f in ev.findings}
    assert [v.state for v in ev.verdicts if v.check == "ESC8" and v.usable] == ["finding"]


def test_wi044_a_non_ca_iis_host_attributes_its_endpoints_and_is_partial(tmp_path: Path) -> None:
    out = _collect(tmp_path, "clean", "-OneCa", "-HostName", "labweb01", name="web-host")
    marker = json.loads((out / "collector-manifest.json").read_text(encoding="utf-8"))[
        "enumeration"
    ]["web-endpoints"]
    assert marker["complete"] is False
    assert "labweb01.lab.example.com, which is not a CA host" in marker["reason"]
    assert "labca01.lab.example.com" in marker["reason"]  # the CA host not inspected
    estate = ingest(out)
    assert {e.host for e in estate.endpoints} == {"labweb01.lab.example.com"}
    ev = evaluate(estate, now=NOW)
    assert "ESC8" in {f.check for f in ev.findings}  # what it did read still reports
    assert "ENROLLMENT_ENDPOINTS_NOT_EVALUATED" in {f.check for f in ev.findings}
    assert not [v for v in ev.verdicts if v.check == "ESC8" and v.usable]


def test_wi044_baseline_esc8_then_unevaluated_host_never_resolves(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """WI-044 live defect 2, replayed. The baseline (collected on the CA host)
    has ESC8 HIGH on /CertSrv. The newer export comes from a domain member that
    is not a CA host and runs IIS with no enrollment application. Collector
    0.10.0 wrote web-endpoints complete with count 0 there, and diff listed ESC8
    as resolved (exit 0). It must stay not re-evaluated (exit 3), both for this
    collector's partial marker and for the 0.10.0 export shape."""
    old = _collect(tmp_path, "clean", "-OneCa", name="ca-host")
    new = _collect(
        tmp_path,
        "clean",
        "-OneCa",
        "-HostName",
        "labweb01",
        "-NoEnrollmentApps",
        name="web-host-empty",
    )
    assert ingest(new).endpoints == ()
    rc, env = _env(old, new, capsys)
    assert "ESC8" not in {f["check"] for f in env["resolved"]}
    assert "ESC8" in {i["check"] for i in env["indeterminate"]}
    assert rc == 3

    # The same pair in the 0.10.0 shape: the newer marker claims a complete,
    # empty list and nothing names a host. Ingest still refuses to vouch for it,
    # because the manifest's collector host is not the CA host.
    old_legacy = _as_collector_0_10_0(old, tmp_path / "ca-host-0.10.0")
    legacy = _as_collector_0_10_0(new, tmp_path / "web-host-empty-0.10.0")
    assert json.loads((legacy / "collector-manifest.json").read_text(encoding="utf-8"))[
        "enumeration"
    ]["web-endpoints"] == {"complete": True, "count": 0}
    assert "web-endpoints" in ingest(old_legacy).manifest.enumeration_complete
    assert "web-endpoints" not in ingest(legacy).manifest.enumeration_complete
    rc, env = _env(old_legacy, legacy, capsys)
    assert "ESC8" not in {f["check"] for f in env["resolved"]}
    assert "ESC8" in {i["check"] for i in env["indeterminate"]}
    assert rc == 3


def _as_collector_0_10_0(src: Path, dst: Path) -> Path:
    """A copy of *src* as collector 0.10.0 wrote it: no host attribution, and a
    web-endpoints marker that is complete whenever IIS enumerated cleanly."""
    shutil.copytree(src, dst)
    manifest_path = dst / "collector-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["collector_version"] = "0.10.0"
    manifest.pop("host_fqdn")
    marker = manifest["enumeration"]["web-endpoints"]
    manifest["enumeration"]["web-endpoints"] = {"complete": True, "count": marker["count"]}
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    for name, keys in (
        ("pki-acls.json", ("ca_host_sid", "enrollment_service")),
        ("web-endpoints.json", ("host",)),
    ):
        rows = json.loads((dst / name).read_text(encoding="utf-8"))
        for row in rows:
            for key in keys:
                row.pop(key)
        (dst / name).write_text(json.dumps(rows), encoding="utf-8")
    return dst


def test_wi044_an_unresolved_ca_host_account_is_undecided_and_noted(tmp_path: Path) -> None:
    estate = ingest(_collect(tmp_path, "clean", "-HostLookupFails", name="lookup-fails"))
    es = [a for a in estate.acls if a.object_dn.startswith("CN=LAB Issuing CA")]
    assert es and all("ca_host_sid" in a.unobtained for a in es)
    ev = evaluate(estate, now=NOW)
    notes = [f for f in ev.findings if f.check == "CA_HOST_ACCOUNT_UNRESOLVED"]
    assert len(notes) == len(es)
    # Neither a silent allowlist nor a manufactured CRITICAL: undecided.
    assert not [f for f in ev.findings if f.check == "ESC5" and "Enrollment Services" in f.subject]
    keys = {
        v.key
        for v in ev.verdicts
        if v.check == "ESC5" and v.variant == "dacl" and v.state == "undecided"
    }
    assert {f"g:pki:{a.object_guid}" for a in es} <= keys


def test_wi044_two_enrollment_services_on_the_collector_host_are_one_ca_host(
    tmp_path: Path,
) -> None:
    """DS round 2 N4: every matching enrollment service added its host, so two
    on one host counted as "more than one CA host matches this host" and the
    endpoint list could never be complete. Hosts are now counted distinctly,
    as the core recomputes them."""
    out = _collect(tmp_path, "clean", "-SecondCaOnThisHost", name="two-cas-one-host")
    marker = json.loads((out / "collector-manifest.json").read_text(encoding="utf-8"))[
        "enumeration"
    ]["web-endpoints"]
    assert marker["complete"] is True, marker
    estate = ingest(out)
    assert {c.dns for c in estate.cas} == {"labca01.lab.example.com"}
    assert "web-endpoints" in estate.manifest.enumeration_complete
    assert estate.manifest.host_fqdn == "labca01.lab.example.com"


def test_wi044_a_trailing_root_dot_does_not_make_another_ca_host(tmp_path: Path) -> None:
    """DS round 3 N4: the collector's distinct-host count now drops one
    trailing root dot, as the core does, so the two agree."""
    out = _collect(
        tmp_path, "clean", "-SecondCaOnThisHost", "-TrailingDot", name="two-cas-trailing-dot"
    )
    marker = json.loads((out / "collector-manifest.json").read_text(encoding="utf-8"))[
        "enumeration"
    ]["web-endpoints"]
    assert marker["complete"] is True, marker
    estate = ingest(out)
    assert "labca01.lab.example.com." in {c.dns for c in estate.cas}
    assert "web-endpoints" in estate.manifest.enumeration_complete


# --- 2026-10-13 live run: IIS Extended Protection / sslFlags in location tags ---


def test_liveval_location_tag_layout_is_read_and_resolves_esc8(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Live case D3, replayed with the real collector body. The baseline
    endpoint has Extended Protection None and sslFlags None (ESC8 HIGH). The
    fix (Require, 'Ssl, Ssl128') lives in the applicationHost.config location
    tag, as AD CS setup leaves it, and IIS returns those enum / flags values as
    text. Collector 0.11.0 read .Value of that text, exported none / false and
    kept ESC8 forever; the location-scoped value is now read and ESC8 resolves."""
    old = _collect(tmp_path, "clean", "-OneCa", name="d3-base")
    new = _collect(tmp_path, "clean", "-OneCa", "-IisLayout", "mitigated", name="d3-restored")
    rows = json.loads((new / "web-endpoints.json").read_text(encoding="utf-8"))
    assert [(r["epa"], r["ssl_required"], r["windows_auth"]) for r in rows] == [
        ("require", True, True)
    ]
    estate = ingest(new)
    assert "web-endpoints" in estate.manifest.enumeration_complete
    ev = evaluate(estate, now=NOW)
    assert [(v.state, v.usable) for v in ev.verdicts if v.check == "ESC8"] == [("clean", True)]
    rc, env = _env(old, new, capsys)
    assert "ESC8" in {f["check"] for f in env["resolved"]}
    assert rc == 0


def test_liveval_epa_off_https_only_still_fires(tmp_path: Path) -> None:
    out = _collect(tmp_path, "clean", "-OneCa", "-IisLayout", "epa-off", name="epa-off")
    ev = evaluate(ingest(out), now=NOW)
    esc8 = [f for f in ev.findings if f.check == "ESC8"]
    assert len(esc8) == 1 and "Extended Protection is 'none'" in esc8[0].detail
    assert "cleartext HTTP" not in esc8[0].detail
    assert [(v.state, v.usable) for v in ev.verdicts if v.check == "ESC8"] == [("finding", True)]


def test_liveval_scopes_that_disagree_are_not_evaluated(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The location tag says Require / Ssl,Ssl128 while the application-path
    read returns the parent default None / None (the scope reading of the live
    report): neither value is believed. Both are null, the endpoint list is
    incomplete with the two readings in its reason, ESC8 is undecided with a
    note, and diff from the HIGH baseline neither resolves nor keeps it."""
    old = _collect(tmp_path, "clean", "-OneCa", name="split-base")
    new = _collect(tmp_path, "clean", "-OneCa", "-IisLayout", "split", name="split")
    manifest = json.loads((new / "collector-manifest.json").read_text(encoding="utf-8"))
    marker = manifest["enumeration"]["web-endpoints"]
    assert marker["complete"] is False
    split = "tokenChecking not obtained (application: 'None', applicationHost location: 'Require')"
    assert split in marker["reason"]
    assert "sslFlags not obtained" in marker["reason"]
    estate = ingest(new)
    (ep,) = estate.endpoints
    assert {"epa", "ssl_required"} <= ep.unobtained
    ev = evaluate(estate, now=NOW)
    assert "ESC8" not in {f.check for f in ev.findings}
    assert "/CertSrv" in {
        f.subject for f in ev.findings if f.check == "ENROLLMENT_ENDPOINTS_NOT_EVALUATED"
    }
    assert [v.state for v in ev.verdicts if v.check == "ESC8"] == ["undecided"]
    rc, env = _env(old, new, capsys)
    assert "ESC8" not in {f["check"] for f in env["resolved"]}
    assert "ESC8" in {i["check"] for i in env["indeterminate"]}
    assert rc == 3


# --- 2026-10-13 live run, case B3: the CA server's AD computer object (ESC5) ---


def test_liveval_ca_host_computer_objects_are_read_without_exemption(clean: Estate) -> None:
    computers = [a for a in clean.acls if a.kind.value == "ca_computer"]
    assert sorted(a.object_dn for a in computers) == [
        "CN=labca01,CN=Computers,DC=lab,DC=example,DC=com",
        "CN=labca02,CN=Computers,DC=lab,DC=example,DC=com",
    ]
    assert all(a.acl_obtained and a.object_guid for a in computers)
    # Never an enrollment-service row, never tied to a CA host.
    assert all(not a.enrollment_service and a.ca_host_sid == "" for a in computers)
    assert "pki-acls" in clean.manifest.enumeration_complete


def test_liveval_b3_generic_all_on_the_ca_computer_object_is_esc5(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    base = _collect(tmp_path, "clean", "-OneCa", name="b3-base")
    seeded = _collect(tmp_path, "clean", "-OneCa", "-CaComputerGenericAll", name="b3-seeded")
    ev = evaluate(ingest(seeded), now=NOW)
    (esc5,) = [f for f in ev.findings if f.check == "ESC5"]
    assert esc5.subject == "CN=labca01,CN=Computers,DC=lab,DC=example,DC=com"
    assert esc5.severity.value == "critical" and "GenericAll" in esc5.detail
    rc, env = _env(base, seeded, capsys)
    assert [f["check"] for f in env["new"]] == ["ESC5"] and rc == 1
    rc, env = _env(seeded, base, capsys)
    assert [f["check"] for f in env["resolved"]] == ["ESC5"] and rc == 0


def test_liveval_an_unresolved_ca_host_leaves_pki_acls_incomplete(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A CA host whose computer object is not resolved (here: the lookup
    fails) is an ESC5 object the export never saw: pki-acls is incomplete, so a
    computer-object finding from the baseline is never resolved by it."""
    seeded = _collect(tmp_path, "clean", "-OneCa", "-CaComputerGenericAll", name="b3-seeded2")
    lost = _collect(tmp_path, "clean", "-OneCa", "-HostLookupFails", name="b3-lost")
    marker = json.loads((lost / "collector-manifest.json").read_text(encoding="utf-8"))[
        "enumeration"
    ]["pki-acls"]
    assert marker["complete"] is False
    assert "CA host computer object" in marker["reason"]
    rc, env = _env(seeded, lost, capsys)
    assert "ESC5" not in {f["check"] for f in env["resolved"]}
    assert "ESC5" in {i["check"] for i in env["indeterminate"]}
    assert rc == 3


@pytest.mark.parametrize(
    "tamper", [{"enrollment_service": True}, {"ca_host_sid": "S-1-5-21-1-2-3-1105"}]
)
def test_liveval_a_ca_computer_row_cannot_carry_the_exemption(
    tmp_path: Path, tamper: dict[str, Any]
) -> None:
    out = _collect(tmp_path, "clean", "-OneCa", name="b3-tamper")
    path = out / "pki-acls.json"
    rows = json.loads(path.read_text(encoding="utf-8"))
    next(r for r in rows if r["kind"] == "ca_computer").update(tamper)
    path.write_text(json.dumps(rows), encoding="utf-8")
    with pytest.raises(IngestError):
        ingest(out)


# --- 2026-10-13 live run, case A1d: msPKI-RA-Signature (ESC1) ------------------


def test_liveval_a1d_one_authorized_signature_caps_esc1(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    base = _collect(tmp_path, "clean", "-OneCa", name="a1d-base")
    seeded = _collect(tmp_path, "clean", "-OneCa", "-RaSignature", "1", name="a1d-seeded")
    rows = json.loads((seeded / "templates.json").read_text(encoding="utf-8"))
    assert {r["name"]: r["ra_signatures"] for r in rows} == {"LabWebServer": 1, "LabUser": 0}
    old = next(f for f in evaluate(ingest(base), now=NOW).findings if f.check == "ESC1")
    new = next(f for f in evaluate(ingest(seeded), now=NOW).findings if f.check == "ESC1")
    assert (old.severity.value, new.severity.value) == ("critical", "medium")
    assert "requires 1 authorized signature(s)" in new.detail
    _rc, env = _env(base, seeded, capsys)
    (changed,) = [c for c in env["changed"] if c["check"] == "ESC1"]
    assert (changed["old_severity"], changed["new_severity"]) == ("critical", "medium")
    assert not changed["worsened"]


def test_liveval_a1d_an_absent_attribute_is_not_zero(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """msPKI-RA-Signature not returned: null (not obtained), never "0
    required". ESC1 keeps its full severity, says the requirement was not
    read, and its verdict is not usable; templates stays complete (the
    attribute is a placeholder, like a DC's dNSHostName)."""
    out = _collect(tmp_path, "clean", "-OneCa", "-RaSignature", "absent", name="a1d-absent")
    rows = json.loads((out / "templates.json").read_text(encoding="utf-8"))
    assert {r["name"]: r["ra_signatures"] for r in rows} == {"LabWebServer": None, "LabUser": 0}
    estate = ingest(out)
    assert "templates" in estate.manifest.enumeration_complete
    web = next(t for t in estate.templates if t.name == "LabWebServer")
    assert web.ra_signatures is None and "ra_signatures" in web.unobtained
    ev = evaluate(estate, now=NOW)
    esc1 = next(f for f in ev.findings if f.check == "ESC1")
    assert esc1.severity.value == "critical" and "was not read" in esc1.detail
    assert [v.usable for v in ev.verdicts if v.check == "ESC1" and v.state == "finding"] == [False]


@pytest.mark.parametrize("tamper", ["drop", -1, "1"])
def test_liveval_ra_signatures_is_required_and_typed_from_0_12_0(
    tmp_path: Path, tamper: object
) -> None:
    out = _collect(tmp_path, "clean", "-OneCa", name="a1d-tamper")
    path = out / "templates.json"
    rows = json.loads(path.read_text(encoding="utf-8"))
    if tamper == "drop":
        rows[0].pop("ra_signatures")
    else:
        rows[0]["ra_signatures"] = tamper
    path.write_text(json.dumps(rows), encoding="utf-8")
    with pytest.raises(IngestError):
        ingest(out)
