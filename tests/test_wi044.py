"""WI-044 live-validation defects, at the core (ingest / detection / diff).

The collector side of each defect is replayed through the real collector body
in tests/test_collector_simulated.py and pinned in the Pester suite
(tests/collector/Collector.Tests.ps1). Here:

* defect 2 - IIS is read on the collector host only, so the endpoint list
  vouches for absent endpoints only when that host is the only CA host
  (``endpoint_scope_gaps``); otherwise ingest drops ``web-endpoints`` from the
  complete containers, ESC8 adds an ENROLLMENT_ENDPOINTS_NOT_EVALUATED note, and
  diff cannot resolve ESC8;
* defect 4 - the CA host's own computer account is not low-privilege on its own
  enrollment-service object (``ca_host_sid``), and only there;
* ESC15 annotates publication like ESC1-3 and never gates on it.
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from adcs_lens.detection import (
    detect_esc5,
    detect_esc8,
    detect_esc15,
    evaluate,
    is_degradation_note,
)
from adcs_lens.diff import diff_findings
from adcs_lens.ingest import IngestError, ingest
from adcs_lens.model import (
    AceEntry,
    AceType,
    AclKind,
    CaKind,
    CaPatchState,
    CertAuthority,
    CertTemplate,
    EndpointKind,
    EnrollmentEndpoint,
    EpaPolicy,
    Estate,
    Manifest,
    PkiObjectAcl,
    endpoint_scope_gaps,
)
from adcs_lens.normalize import is_low_priv_trustee
from tests.conftest import NOW

DOMAIN_SID = "S-1-5-21-1111111111-2222222222-3333333333"
CA1_HOST = f"{DOMAIN_SID}-1105"  # labca01's computer account
CA2_HOST = f"{DOMAIN_SID}-1106"  # labca02's computer account
DELEGATE = f"{DOMAIN_SID}-1201"  # a custom group with delegated control
DOMAIN_ADMINS = f"{DOMAIN_SID}-512"
DOMAIN_USERS = f"{DOMAIN_SID}-513"
ES_DN = "CN=LAB Issuing CA,CN=Enrollment Services,CN=Public Key Services,CN=Services,DC=x"


def _ace(sid: str, *rights: str) -> AceEntry:
    return AceEntry(trustee_sid=sid, trustee_name="", rights=rights, ace_type=AceType.ALLOW)


def _setup_grant(sid: str) -> AceEntry:
    """What AD CS setup grants the CA computer account on its enrollment service."""
    return _ace(sid, "WriteDacl", "WriteOwner", "WritePropertyAll")


def _manifest(
    *, version: str = "t", host: str = "", complete: frozenset[str] = frozenset()
) -> Manifest:
    return Manifest(
        collector_version=version,
        collected_at="",
        host=host,
        domain="",
        skipped_passes=(),
        certs_parsed=True,
        enumeration_complete=complete,
    )


def _estate(
    *,
    cas: tuple[CertAuthority, ...] = (),
    acls: tuple[PkiObjectAcl, ...] = (),
    endpoints: tuple[EnrollmentEndpoint, ...] = (),
    templates: tuple[CertTemplate, ...] = (),
    manifest: Manifest | None = None,
) -> Estate:
    return Estate(
        cas=cas,
        templates=templates,
        acls=acls,
        oids=(),
        crls=(),
        endpoints=endpoints,
        dcs=(),
        principal_mappings=(),
        manifest=manifest or _manifest(),
    )


def _es_object(
    *aces: AceEntry, ca_host_sid: str = CA1_HOST, owner: str = DOMAIN_ADMINS
) -> PkiObjectAcl:
    return PkiObjectAcl(
        object_dn=ES_DN,
        kind=AclKind.CA_OBJECT,
        security=aces,
        owner_sid=owner,
        object_guid="01" * 16,
        ca_host_sid=ca_host_sid,
    )


def _ca(name: str, dns: str, *, enrollment_service: bool = True) -> CertAuthority:
    return CertAuthority(
        name=name,
        dns=dns,
        config_string=f"{dns}\\{name}",
        kind=CaKind.ISSUING,
        edit_flags=frozenset(),
        interface_flags=frozenset(),
        audit_filter=127,
        security=(),
        certs=(),
        enrollment_service=enrollment_service,
    )


# --- defect 4: the CA host's own computer account (ESC5) ----------------------


def test_the_ca_host_account_on_its_own_enrollment_service_is_not_esc5() -> None:
    """The live false positive: every enterprise CA install fired ESC5 CRITICAL."""
    estate = _estate(acls=(_es_object(_setup_grant(CA1_HOST)),))
    assert [f for f in detect_esc5(estate) if f.check == "ESC5"] == []


def test_the_ca_host_account_is_exempt_only_from_its_own_trustee_entry() -> None:
    """A delegated controller beside the setup grant is still CRITICAL, and the
    finding names only the delegate."""
    estate = _estate(acls=(_es_object(_setup_grant(CA1_HOST), _ace(DELEGATE, "GenericAll")),))
    [finding] = [f for f in detect_esc5(estate) if f.check == "ESC5"]
    assert finding.severity.value == "critical"
    assert DELEGATE in finding.detail and CA1_HOST not in finding.detail


def test_another_cas_host_account_on_this_cas_object_is_still_esc5() -> None:
    """Allowlisted on THAT CA's object only: labca02's account controlling
    labca01's enrollment service is a finding."""
    estate = _estate(acls=(_es_object(_setup_grant(CA2_HOST), ca_host_sid=CA1_HOST),))
    [finding] = [f for f in detect_esc5(estate) if f.check == "ESC5"]
    assert CA2_HOST in finding.detail


@pytest.mark.parametrize("kind", [AclKind.NTAUTH, AclKind.PKS_CONTAINER, AclKind.CA_OBJECT])
def test_a_ca_host_account_without_its_own_object_stays_low_privilege(kind: AclKind) -> None:
    """Not computer accounts in general: on an object that names no CA host
    (ca_host_sid empty: a fixed container, a Certification Authorities object)
    the CA's computer account is low-privilege like any other account."""
    obj = PkiObjectAcl(
        object_dn="CN=Obj,DC=x",
        kind=kind,
        security=(_setup_grant(CA1_HOST),),
        owner_sid=DOMAIN_ADMINS,
    )
    assert [f.check for f in detect_esc5(_estate(acls=(obj,))) if f.check == "ESC5"] == ["ESC5"]
    assert is_low_priv_trustee(CA1_HOST)  # the global allowlist is unchanged


def test_the_ca_host_account_owning_its_own_enrollment_service_is_not_esc5() -> None:
    own = _estate(acls=(_es_object(owner=CA1_HOST),))
    assert [f for f in detect_esc5(own) if f.check == "ESC5"] == []
    other = _estate(acls=(_es_object(owner=CA2_HOST),))
    [finding] = [f for f in detect_esc5(other) if f.check == "ESC5"]
    assert finding.variant == "owner"


def test_an_unresolved_ca_host_account_is_undecided_never_flagged_or_allowlisted() -> None:
    obj = replace(
        _es_object(_setup_grant(CA1_HOST), ca_host_sid=""), unobtained=frozenset({"ca_host_sid"})
    )
    estate = _estate(acls=(obj,))
    findings = detect_esc5(estate)
    assert [f.check for f in findings] == ["CA_HOST_ACCOUNT_UNRESOLVED"]
    assert is_degradation_note(findings[0])
    states = {
        (v.variant, v.state, v.usable)
        for v in evaluate(estate, now=NOW).verdicts
        if v.check == "ESC5"
    }
    assert ("dacl", "undecided", False) in states
    # Nothing low-privilege controls it: clean, but not usable for drift.
    clean = replace(obj, security=(_ace(DOMAIN_ADMINS, "GenericAll"),))
    states = {
        (v.variant, v.state, v.usable)
        for v in evaluate(_estate(acls=(clean,)), now=NOW).verdicts
        if v.check == "ESC5"
    }
    assert ("dacl", "clean", False) in states


def test_enterprise_read_only_domain_controllers_stay_low_privilege() -> None:
    """Judgment call (WI-044): RID 498 is NOT added to the high-privilege
    allowlist. The allowlist holds principals whose compromise is already
    domain-compromise-class; an RODC is designed not to be (no writable
    directory, its own krbtgt, only the secrets its replication policy allows),
    so a certificate escalation open to RODCs (e.g. ESC15 on the v1 Domain
    Controller template) is a real path from an RODC to the domain."""
    assert is_low_priv_trustee(f"{DOMAIN_SID}-498")
    assert is_low_priv_trustee(f"{DOMAIN_SID}-521")  # Read-only Domain Controllers


# --- defect 2: endpoint attribution (ESC8) ------------------------------------


def test_endpoint_scope_is_complete_only_when_the_collector_host_is_the_only_ca_host() -> None:
    one = (_ca("CA1", "labca01.lab.example.com"),)
    assert endpoint_scope_gaps("labca01", one) == ()
    assert endpoint_scope_gaps("LABCA01", one) == ()  # DNS names compare case-insensitively
    # A domain member that is not a CA host (the WI-044 live run).
    assert endpoint_scope_gaps("labweb01", one) == (
        "the collector host 'labweb01' is not a CA host",
        "CA host(s) not inspected: labca01.lab.example.com",
    )
    two = (*one, _ca("CA2", "labca02.lab.example.com"))
    assert endpoint_scope_gaps("labca01", two) == (
        "CA host(s) not inspected: labca02.lab.example.com",
    )
    no_dns = (_ca("CA1", ""),)
    assert (
        endpoint_scope_gaps("labca01", no_dns)[-1]
        == "CA host(s) not inspected: CA1 (no dNSHostName)"
    )
    # An offline root is no enrollment host; a standalone local CA is this host.
    root = (_ca("Root", "", enrollment_service=False),)
    assert endpoint_scope_gaps("labca01", root) == (
        "the collector host 'labca01' is not a CA host",
    )
    local = (_ca("Standalone", "labca01.lab.example.com", enrollment_service=False),)
    assert endpoint_scope_gaps("labca01", local) == ()
    assert endpoint_scope_gaps("", one)[0] == "the collector host '(unnamed)' is not a CA host"


def _endpoint(host: str = "labca01.lab.example.com") -> EnrollmentEndpoint:
    return EnrollmentEndpoint(
        kind=EndpointKind.WEB_ENROLLMENT,
        name="/CertSrv",
        transports=frozenset({"http"}),
        ssl_required=False,
        windows_auth=True,
        auth_providers=frozenset({"ntlm"}),
        epa=EpaPolicy.NONE,
        host=host,
    )


def test_esc8_names_the_host_and_notes_an_uninspected_ca_host() -> None:
    cas = (_ca("CA1", "labca01.lab.example.com"), _ca("CA2", "labca02.lab.example.com"))
    estate = _estate(
        cas=cas,
        endpoints=(_endpoint(),),
        manifest=_manifest(version="0.11.0", host="labca01", complete=frozenset({"ca-config"})),
    )
    findings = {f.check: f for f in detect_esc8(estate)}
    assert "on labca01.lab.example.com" in findings["ESC8"].source
    note = findings["ENROLLMENT_ENDPOINTS_NOT_EVALUATED"]
    assert "labca02.lab.example.com" in note.detail
    assert not [v for v in evaluate(estate, now=NOW).verdicts if v.check == "ESC8" and v.usable]


def test_esc8_has_no_note_when_every_ca_host_was_inspected() -> None:
    estate = _estate(
        cas=(_ca("CA1", "labca01.lab.example.com"),),
        endpoints=(_endpoint(),),
        manifest=_manifest(
            version="0.11.0", host="labca01", complete=frozenset({"ca-config", "web-endpoints"})
        ),
    )
    assert [f.check for f in detect_esc8(estate)] == ["ESC8"]


def test_two_hosts_certsrv_never_pair_across_exports() -> None:
    """Attribution is identity: labca02's /CertSrv is not labca01's, so a
    finding on one is never matched to (or resolved by) the other."""
    a = evaluate(
        _estate(cas=(_ca("CA1", "x"),), endpoints=(_endpoint("labca01.lab.example.com"),)), now=NOW
    )
    b = evaluate(
        _estate(cas=(_ca("CA1", "x"),), endpoints=(_endpoint("labca02.lab.example.com"),)), now=NOW
    )
    drift = diff_findings(a, b)
    assert "ESC8" in {f.check for f in drift.new}
    assert "ESC8" not in {f.check for f in drift.resolved}


# --- ingest: host attribution (collector >= 0.11.0) ---------------------------


def _rw(path: Path, mutate: Any) -> None:
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    mutate(data)
    path.write_text(json.dumps(data), encoding="utf-8")


def _as_0_11_0(export: Path) -> Path:
    _rw(export / "collector-manifest.json", lambda m: m.__setitem__("collector_version", "0.11.0"))

    def endpoints(rows: list[dict[str, Any]]) -> None:
        for row in rows:
            row["host"] = "labca01.lab.example.com"

    def acls(rows: list[dict[str, Any]]) -> None:
        for row in rows:
            row["ca_host_sid"] = ""

    _rw(export / "web-endpoints.json", endpoints)
    _rw(export / "pki-acls.json", acls)
    return export


def test_ingest_reads_host_attribution(json_export: Path) -> None:
    export = _as_0_11_0(json_export)

    def es_row(rows: list[dict[str, Any]]) -> None:
        rows.append(
            {
                "object_dn": ES_DN,
                "kind": "ca_object",
                "owner_sid": DOMAIN_ADMINS,
                "object_guid": "ab" * 16,
                "security": [],
                "acl_obtained": True,
                "ca_host_sid": CA1_HOST.lower().replace("s-1", "S-1"),
            }
        )

    _rw(export / "pki-acls.json", es_row)
    _rw(
        export / "collector-manifest.json",
        lambda m: m["enumeration"]["pki-acls"].__setitem__(
            "count", m["enumeration"]["pki-acls"]["count"] + 1
        ),
    )
    estate = ingest(export)
    assert {e.host for e in estate.endpoints} == {"labca01.lab.example.com"}
    es = next(a for a in estate.acls if a.object_dn == ES_DN)
    assert es.ca_host_sid == CA1_HOST


@pytest.mark.parametrize(
    ("sid", "kind"),
    [
        ("S-1-1-0", "ca_object"),  # Everyone: would allowlist the world
        (f"{DOMAIN_SID}-512", "ntauth"),  # only an enrollment service's row names a CA host
        ("not a sid", "ca_object"),
    ],
)
def test_ingest_rejects_a_ca_host_sid_that_could_allowlist_anything_else(
    json_export: Path, sid: str, kind: str
) -> None:
    export = _as_0_11_0(json_export)

    def bad(rows: list[dict[str, Any]]) -> None:
        rows[0]["ca_host_sid"] = sid
        rows[0]["kind"] = kind

    _rw(export / "pki-acls.json", bad)
    with pytest.raises(IngestError, match="ca_host_sid"):
        ingest(export)


@pytest.mark.parametrize(
    ("file", "key"), [("pki-acls.json", "ca_host_sid"), ("web-endpoints.json", "host")]
)
def test_a_0_11_0_export_must_carry_host_attribution(
    json_export: Path, file: str, key: str
) -> None:
    export = _as_0_11_0(json_export)
    _rw(export / file, lambda rows: rows[0].pop(key))
    with pytest.raises(IngestError, match=key):
        ingest(export)


def test_a_null_ca_host_sid_is_not_obtained(json_export: Path) -> None:
    export = _as_0_11_0(json_export)

    def null(rows: list[dict[str, Any]]) -> None:
        rows[0]["ca_host_sid"] = None
        rows[0]["kind"] = "ca_object"

    _rw(export / "pki-acls.json", null)
    assert "ca_host_sid" in ingest(export).acls[0].unobtained


def test_a_0_10_0_marker_from_a_non_ca_host_is_not_complete(json_export: Path) -> None:
    """The live export's shape: collector 0.10.0 on a domain member with IIS
    marked web-endpoints complete with count 0."""
    _rw(json_export / "web-endpoints.json", lambda rows: rows.clear())

    def from_member(m: dict[str, Any]) -> None:
        m["host"] = "LABWEB01"
        m["enumeration"]["web-endpoints"] = {"complete": True, "count": 0}

    _rw(json_export / "collector-manifest.json", from_member)
    assert "web-endpoints" not in ingest(json_export).manifest.enumeration_complete


# --- ESC15: publication is annotated, never a gate ----------------------------


def _v1(published_by: tuple[str, ...]) -> CertTemplate:
    return CertTemplate(
        name="LabV1",
        display_name="Lab V1",
        schema_version=1,
        oid="1.3.6.1.4.1.311.21.8.9.9",
        ekus=(),
        name_flags=frozenset(),
        enrollment_flags=frozenset(),
        min_key_size=2048,
        issuance_policy_oids=(),
        security=(_ace(DOMAIN_USERS, "Enroll"),),
        published_by=published_by,
    )


def test_esc15_annotates_publication_at_the_same_severity() -> None:
    ca = replace(_ca("CA1", "labca01.lab.example.com"), ca_patch_state=CaPatchState.UNPATCHED)
    manifest = replace(_manifest(), enrollment_services_available=True)
    published = detect_esc15(_estate(cas=(ca,), templates=(_v1(("CA1",)),), manifest=manifest))
    unpublished = detect_esc15(_estate(cas=(ca,), templates=(_v1(()),), manifest=manifest))
    assert [f.severity for f in published] == [f.severity for f in unpublished]
    assert "Publication state: published by CA1." in published[0].detail
    assert "Publication state: confirmed unpublished" in unpublished[0].detail
