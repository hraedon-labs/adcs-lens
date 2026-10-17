"""Detector logic, exercised on directly-constructed model objects (no I/O)."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from adcs_lens.detection import (
    _AUDIT_CATEGORIES,
    CHECKS,
    Finding,
    detect_acl_coverage_caveats,
    detect_audit_config,
    detect_ca_registry_gaps,
    detect_cdp_aia_absence,
    detect_esc1,
    detect_esc2,
    detect_esc3,
    detect_esc4,
    detect_esc5,
    detect_esc6,
    detect_esc7,
    detect_esc8,
    detect_esc9,
    detect_esc11,
    detect_esc13,
    detect_esc16,
    detect_infra_cert_expiry,
    detect_ocsp_absence,
    detect_orphaned_templates,
    detect_pki_acl_gaps,
    detect_template_acl_gaps,
    detect_weak_key_size,
    detect_weak_signing,
    evaluate,
    is_degradation_note,
    run_all,
)
from adcs_lens.model import (
    AceEntry,
    AceType,
    AclKind,
    CaKind,
    CaPatchState,
    CertAuthority,
    CertKind,
    CertLifecycle,
    CertTemplate,
    Crl,
    CrlTier,
    DcConfiguration,
    EndpointKind,
    EnrollmentEndpoint,
    EpaPolicy,
    Estate,
    IssuanceOid,
    Manifest,
    PkiObjectAcl,
    PrincipalMapping,
    SchannelMappingMethod,
    Severity,
    StrongCertBinding,
    decoders_superseded,
    superseded_name_flag_reading,
)

NOW = datetime(2026, 6, 15, 12, 0, 0, tzinfo=UTC)

CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
SERVER_AUTH = "1.3.6.1.5.5.7.3.1"
ANY_PURPOSE = "2.5.29.37.0"
ENROLLMENT_AGENT = "1.3.6.1.4.1.311.20.2.1"
LOW_PRIV_SID = "S-1-5-21-1111111111-2222222222-3333333333-513"  # Domain Users
HIGH_PRIV_SID = "S-1-5-21-1111111111-2222222222-3333333333-512"  # Domain Admins
POLICY_OID = "1.3.6.1.4.1.311.21.8.1.2.3.4.999"
DOMAIN_ADMINS_SID = "S-1-5-21-1111111111-2222222222-3333333333-512"


def _enroll_ace(sid: str = LOW_PRIV_SID, *, right: str = "Enroll") -> AceEntry:
    return AceEntry(
        trustee_sid=sid, trustee_name="trustee", rights=(right,), ace_type=AceType.ALLOW
    )


def _template(
    name: str = "T",
    *,
    ekus: tuple[str, ...] = (CLIENT_AUTH,),
    name_flags: tuple[str, ...] = ("ENROLLEE_SUPPLIES_SUBJECT",),
    enrollment_flags: tuple[str, ...] = (),
    issuance_policy_oids: tuple[str, ...] = (),
    security: tuple[AceEntry, ...] = (),
    acl_obtained: bool = True,
    schema_version: int = 2,
    min_key_size: int = 2048,
    csp: str = "",
    owner_sid: str = "",
    published_by: tuple[str, ...] = (),
) -> CertTemplate:
    return CertTemplate(
        name=name,
        display_name=name,
        schema_version=schema_version,
        oid=f"1.3.6.1.4.1.311.21.8.{name}",
        ekus=ekus,
        name_flags=frozenset(name_flags),
        enrollment_flags=frozenset(enrollment_flags),
        min_key_size=min_key_size,
        issuance_policy_oids=issuance_policy_oids,
        security=security,
        published_by=published_by,
        acl_obtained=acl_obtained,
        csp=csp,
        owner_sid=owner_sid,
    )


def _ca(
    name: str,
    *,
    kind: CaKind = CaKind.ISSUING,
    edit_flags: tuple[str, ...] = (),
    interface_flags: tuple[str, ...] = (),
    audit_filter: int | None = None,
    certs: tuple[CertLifecycle, ...] = (),
    security: tuple[AceEntry, ...] = (),
    disabled_extensions: tuple[str, ...] = (),
    ca_patch_state: CaPatchState = CaPatchState.UNKNOWN,
    owner_sid: str = "",
    registry_config_collected: bool = True,
) -> CertAuthority:
    return CertAuthority(
        name=name,
        dns="",
        config_string=f"host\\{name}",
        kind=kind,
        edit_flags=frozenset(edit_flags),
        interface_flags=frozenset(interface_flags),
        audit_filter=audit_filter,
        security=security,
        certs=certs,
        disabled_extensions=frozenset(disabled_extensions),
        ca_patch_state=ca_patch_state,
        owner_sid=owner_sid,
        registry_config_collected=registry_config_collected,
    )


def _cert(
    subject: str = "CN=CA",
    *,
    kind: CertKind = CertKind.ISSUING_CA,
    not_before: datetime = NOW,
    not_after: datetime = NOW + timedelta(days=365),
    sig_alg: str = "sha256",
    key_bits: int | None = 2048,
    key_alg: str = "rsa",
    ocsp_urls: tuple[str, ...] = ("http://ocsp/ocsp",),
    cdp_urls: tuple[str, ...] = ("http://crl/crl.crl",),
    aia_urls: tuple[str, ...] = ("http://aia/ca.cer",),
) -> CertLifecycle:
    return CertLifecycle(
        subject=subject,
        kind=kind,
        not_before=not_before,
        not_after=not_after,
        sig_alg=sig_alg,
        key_bits=key_bits,
        key_alg=key_alg,
        ocsp_urls=ocsp_urls,
        cdp_urls=cdp_urls,
        aia_urls=aia_urls,
    )


def _ctrl_ace(
    sid: str = LOW_PRIV_SID, *, right: str = "WriteDacl", ace_type: AceType = AceType.ALLOW
) -> AceEntry:
    return AceEntry(trustee_sid=sid, trustee_name="trustee", rights=(right,), ace_type=ace_type)


def _deny_enroll(sid: str = LOW_PRIV_SID) -> AceEntry:
    """A Deny-Enroll ACE on a low-priv trustee (for Deny-precedence tests)."""
    return _ctrl_ace(sid=sid, right="Enroll", ace_type=AceType.DENY)


def _pki_acl(
    kind: AclKind,
    *,
    dn: str = "CN=Obj,CN=Public Key Services,CN=Services,CN=Configuration,DC=x",
    security: tuple[AceEntry, ...] = (),
    owner_sid: str = "",
    acl_obtained: bool = True,
) -> PkiObjectAcl:
    return PkiObjectAcl(
        object_dn=dn, kind=kind, security=security, owner_sid=owner_sid,
        acl_obtained=acl_obtained,
    )


def _endpoint(
    kind: EndpointKind = EndpointKind.WEB_ENROLLMENT,
    *,
    name: str = "/CertSrv",
    transports: tuple[str, ...] = ("http", "https"),
    ssl_required: bool = False,
    windows_auth: bool = True,
    auth_providers: tuple[str, ...] = ("negotiate", "ntlm"),
    epa: EpaPolicy = EpaPolicy.NONE,
) -> EnrollmentEndpoint:
    return EnrollmentEndpoint(
        kind=kind,
        name=name,
        transports=frozenset(transports),
        ssl_required=ssl_required,
        windows_auth=windows_auth,
        auth_providers=frozenset(auth_providers),
        epa=epa,
    )


def _estate(
    *,
    cas: tuple[CertAuthority, ...] = (),
    templates: tuple[CertTemplate, ...] = (),
    acls: tuple[PkiObjectAcl, ...] = (),
    crls: tuple[Crl, ...] = (),
    oids: tuple[IssuanceOid, ...] = (),
    endpoints: tuple[EnrollmentEndpoint, ...] = (),
    dcs: tuple[DcConfiguration, ...] = (),
    principal_mappings: tuple[PrincipalMapping, ...] = (),
    certs_parsed: bool = True,
    skipped_passes: tuple[str, ...] = (),
    enrollment_services_available: bool = False,
) -> Estate:
    manifest = Manifest(
        collector_version="t",
        collected_at="",
        host="",
        domain="",
        skipped_passes=skipped_passes,
        certs_parsed=certs_parsed,
        enrollment_services_available=enrollment_services_available,
    )
    return Estate(
        cas=cas,
        templates=templates,
        acls=acls,
        oids=oids,
        crls=crls,
        endpoints=endpoints,
        dcs=dcs,
        principal_mappings=principal_mappings,
        manifest=manifest,
    )


def _dc(
    name: str = "DC01",
    *,
    strong_binding: StrongCertBinding = StrongCertBinding.DISABLED,
    schannel_methods: tuple[SchannelMappingMethod, ...] = (),
) -> DcConfiguration:
    return DcConfiguration(
        name=name,
        strong_certificate_binding_enforcement=strong_binding,
        schannel_mapping_methods=frozenset(schannel_methods),
    )


# --- ESC6 -----------------------------------------------------------------


def test_esc6_flagged() -> None:
    estate = _estate(cas=(_ca("BadCA", edit_flags=("EDITF_ATTRIBUTESUBJECTALTNAME2",)),))
    findings = detect_esc6(estate)
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].subject == "BadCA"
    assert "policy\\EditFlags" in findings[0].source


def test_esc6_clean_ca_no_finding() -> None:
    assert detect_esc6(_estate(cas=(_ca("GoodCA"),))) == []


# --- ESC1 -----------------------------------------------------------------


def test_esc1_flagged_when_all_conditions_hold() -> None:
    tmpl = _template("VulnUserAuth", security=(_enroll_ace(),))
    findings = detect_esc1(_estate(templates=(tmpl,)))
    assert len(findings) == 1
    assert findings[0].check == "ESC1"
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].subject == "VulnUserAuth"


def test_esc1_no_eku_is_dangerous() -> None:
    # A template with no EKU at all is valid for any purpose -> still ESC1.
    tmpl = _template("NoEku", ekus=(), security=(_enroll_ace(),))
    assert len(detect_esc1(_estate(templates=(tmpl,)))) == 1


def test_esc1_not_flagged_without_auth_eku() -> None:
    # Server-auth-only template cannot authenticate as a user.
    tmpl = _template("WebOnly", ekus=(SERVER_AUTH,), security=(_enroll_ace(),))
    assert detect_esc1(_estate(templates=(tmpl,))) == []


def test_esc1_not_flagged_without_supplies_subject() -> None:
    tmpl = _template("Fixed", name_flags=(), security=(_enroll_ace(),))
    assert detect_esc1(_estate(templates=(tmpl,))) == []


def test_esc1_mitigated_by_manager_approval() -> None:
    tmpl = _template(
        "Approved", enrollment_flags=("PEND_ALL_REQUESTS",), security=(_enroll_ace(),)
    )
    assert detect_esc1(_estate(templates=(tmpl,))) == []


def test_esc1_not_flagged_when_only_high_priv_can_enroll() -> None:
    tmpl = _template("AdminOnly", security=(_enroll_ace(HIGH_PRIV_SID),))
    assert detect_esc1(_estate(templates=(tmpl,))) == []


def test_esc1_deny_ace_does_not_count_as_enroll() -> None:
    deny = AceEntry(
        trustee_sid=LOW_PRIV_SID,
        trustee_name="Domain Users",
        rights=("Enroll",),
        ace_type=AceType.DENY,
    )
    assert detect_esc1(_estate(templates=(_template("D", security=(deny,)),))) == []


def test_esc1_broad_right_implies_enroll() -> None:
    # GenericAll on the template implies the ability to enroll.
    tmpl = _template("Owned", security=(_enroll_ace(right="GenericAll"),))
    assert len(detect_esc1(_estate(templates=(tmpl,)))) == 1


def test_esc1_degrades_when_template_security_not_collected() -> None:
    tmpl = _template("Vuln", security=(_enroll_ace(),))
    findings = detect_esc1(
        _estate(templates=(tmpl,), skipped_passes=("template-security",))
    )
    assert len(findings) == 1
    assert findings[0].check == "TEMPLATE_ACL_NOT_EVALUATED"
    assert findings[0].severity == Severity.INFO


# --- ESC2 -----------------------------------------------------------------


def test_esc2_any_purpose_eku_flagged() -> None:
    tmpl = _template("AnyPurpose", ekus=(ANY_PURPOSE,), security=(_enroll_ace(),))
    findings = detect_esc2(_estate(templates=(tmpl,)))
    assert len(findings) == 1
    assert findings[0].check == "ESC2"
    assert findings[0].severity == Severity.HIGH


def test_esc2_no_eku_flagged() -> None:
    tmpl = _template("NoEku", ekus=(), security=(_enroll_ace(),))
    assert len(detect_esc2(_estate(templates=(tmpl,)))) == 1


def test_esc2_constrained_eku_not_flagged() -> None:
    tmpl = _template("Web", ekus=(SERVER_AUTH,), security=(_enroll_ace(),))
    assert detect_esc2(_estate(templates=(tmpl,))) == []


def test_esc2_requires_low_priv_enroll() -> None:
    tmpl = _template("AnyPurpose", ekus=(ANY_PURPOSE,), security=(_enroll_ace(HIGH_PRIV_SID),))
    assert detect_esc2(_estate(templates=(tmpl,))) == []


def test_esc2_mitigated_by_manager_approval() -> None:
    tmpl = _template(
        "AnyPurpose",
        ekus=(ANY_PURPOSE,),
        enrollment_flags=("PEND_ALL_REQUESTS",),
        security=(_enroll_ace(),),
    )
    assert detect_esc2(_estate(templates=(tmpl,))) == []


# --- ESC3 -----------------------------------------------------------------


def test_esc3_enrollment_agent_eku_flagged() -> None:
    tmpl = _template("Agent", ekus=(ENROLLMENT_AGENT,), security=(_enroll_ace(),))
    findings = detect_esc3(_estate(templates=(tmpl,)))
    assert len(findings) == 1
    assert findings[0].check == "ESC3"
    assert findings[0].severity == Severity.HIGH


def test_esc3_not_flagged_without_agent_eku() -> None:
    tmpl = _template("Plain", ekus=(CLIENT_AUTH,), security=(_enroll_ace(),))
    assert detect_esc3(_estate(templates=(tmpl,))) == []


def test_esc3_requires_low_priv_enroll() -> None:
    tmpl = _template("Agent", ekus=(ENROLLMENT_AGENT,), security=(_enroll_ace(HIGH_PRIV_SID),))
    assert detect_esc3(_estate(templates=(tmpl,))) == []


def test_esc2_esc3_silent_when_template_security_not_collected() -> None:
    tmpl = _template("Agent", ekus=(ENROLLMENT_AGENT, ANY_PURPOSE), security=(_enroll_ace(),))
    skipped = _estate(templates=(tmpl,), skipped_passes=("template-security",))
    assert detect_esc2(skipped) == []
    assert detect_esc3(skipped) == []


@pytest.mark.parametrize(
    ("detector", "ekus", "check", "severity"),
    [
        (detect_esc1, (CLIENT_AUTH,), "ESC1", Severity.CRITICAL),
        (detect_esc2, (ANY_PURPOSE,), "ESC2", Severity.HIGH),
        (detect_esc3, (ENROLLMENT_AGENT,), "ESC3", Severity.HIGH),
    ],
)
@pytest.mark.parametrize(
    ("published_by", "enrollment_services_available", "expected_detail"),
    [
        (
            ("LAB Issuing CA",),
            True,
            "Publication state: published by LAB Issuing CA.",
        ),
        (
            (),
            True,
            "Publication state: confirmed unpublished (not offered by any CA).",
        ),
        (
            (),
            False,
            "Publication state: unknown (enrollment-services export absent or unevaluated).",
        ),
    ],
)
def test_esc1_esc2_esc3_details_include_publication_state(
    detector: Callable[[Estate], list[Finding]],
    ekus: tuple[str, ...],
    check: str,
    severity: Severity,
    published_by: tuple[str, ...],
    enrollment_services_available: bool,
    expected_detail: str,
) -> None:
    tmpl = _template(
        f"{check}PublicationState",
        ekus=ekus,
        security=(_enroll_ace(),),
        published_by=published_by,
    )
    findings = detector(
        _estate(
            templates=(tmpl,),
            enrollment_services_available=enrollment_services_available,
        )
    )
    assert len(findings) == 1
    assert findings[0].check == check
    assert findings[0].severity == severity
    assert expected_detail in findings[0].detail


def test_esc1_publication_detail_normalizes_multiple_blank_duplicate_publishers() -> None:
    tmpl = _template(
        "PublisherNormalization",
        security=(_enroll_ace(),),
        published_by=(" Zebra CA ", "", "Alpha CA", "Alpha CA", "   "),
    )
    findings = detect_esc1(
        _estate(templates=(tmpl,), enrollment_services_available=True)
    )
    assert len(findings) == 1
    assert "Publication state: published by Alpha CA, Zebra CA." in findings[0].detail


def test_publication_availability_is_not_inferred_from_nonempty_publishers() -> None:
    vulnerable = _template("Vulnerable", security=(_enroll_ace(),))
    published = _template(
        "PublishedEvidence",
        name_flags=(),
        security=(),
        published_by=("LAB Issuing CA",),
    )
    estate = _estate(templates=(vulnerable, published))

    finding = next(f for f in detect_esc1(estate) if f.subject == "Vulnerable")
    assert finding.severity == Severity.CRITICAL
    assert (
        "Publication state: unknown (enrollment-services export absent or unevaluated)."
        in finding.detail
    )
    assert detect_orphaned_templates(estate) == []


# --- ESC4 -----------------------------------------------------------------


def test_esc4_flagged_when_low_priv_can_write_template() -> None:
    tmpl = _template("Delegated", security=(_enroll_ace(right="WriteDacl"),))
    findings = detect_esc4(_estate(templates=(tmpl,)))
    assert len(findings) == 1
    assert findings[0].check == "ESC4"
    assert findings[0].severity == Severity.HIGH
    assert "WriteDacl" in findings[0].detail


def test_esc4_genericall_flagged() -> None:
    tmpl = _template("Owned", security=(_enroll_ace(right="GenericAll"),))
    assert len(detect_esc4(_estate(templates=(tmpl,)))) == 1


def test_esc4_blanket_writeproperty_flagged() -> None:
    # Blanket WriteProperty (collector token 'WritePropertyAll', from an all-zero
    # ObjectType) can rewrite msPKI-Certificate-Name-Flag → ESC1, so it is control.
    tmpl = _template("BlanketWrite", security=(_enroll_ace(right="WritePropertyAll"),))
    findings = detect_esc4(_estate(templates=(tmpl,)))
    assert len(findings) == 1
    assert findings[0].check == "ESC4"
    assert "WritePropertyAll" in findings[0].detail


def test_esc4_scoped_writeproperty_not_flagged() -> None:
    # A bare 'WriteProperty' (no GUID, from an older collector v0.6.1) is still
    # not flagged — the scope is unknown. The collector v0.6.2+ emits
    # 'WriteProperty:<guid>' for scoped writes, which ARE flagged when the GUID
    # is in the dangerous-property set (see test_esc4_scoped_writeproperty_*).
    tmpl = _template("ScopedWrite", security=(_enroll_ace(right="WriteProperty"),))
    assert detect_esc4(_estate(templates=(tmpl,))) == []


def test_esc4_enroll_only_is_not_esc4() -> None:
    # Plain Enroll is not a control right — that is ESC1 territory, not ESC4.
    tmpl = _template("EnrollOnly", security=(_enroll_ace(right="Enroll"),))
    assert detect_esc4(_estate(templates=(tmpl,))) == []


def test_esc4_high_priv_writer_not_flagged() -> None:
    tmpl = _template("AdminWrite", security=(_enroll_ace(HIGH_PRIV_SID, right="WriteOwner"),))
    assert detect_esc4(_estate(templates=(tmpl,))) == []


def test_esc4_silent_when_template_security_not_collected() -> None:
    # ESC1 emits the degradation note; ESC4 stays silent to avoid duplicating it.
    tmpl = _template("Delegated", security=(_enroll_ace(right="WriteDacl"),))
    assert detect_esc4(
        _estate(templates=(tmpl,), skipped_passes=("template-security",))
    ) == []


def test_esc4_owner_based_control_flagged() -> None:
    # A low-priv OWNER can rewrite the DACL to grant itself control even with no
    # control ACE — an ESC4 path the DACL-only check misses (WI-019).
    tmpl = _template("OwnerControlled", security=(), owner_sid=LOW_PRIV_SID)
    findings = detect_esc4(_estate(templates=(tmpl,)))
    assert len(findings) == 1
    assert findings[0].check == "ESC4"
    assert findings[0].severity == Severity.HIGH
    assert "owner" in findings[0].detail.lower()


def test_esc4_owner_high_priv_not_flagged() -> None:
    tmpl = _template("AdminOwned", security=(), owner_sid=HIGH_PRIV_SID)
    assert detect_esc4(_estate(templates=(tmpl,))) == []


def test_esc4_owner_empty_not_flagged() -> None:
    # No owner captured -> owner-based control is skipped (a known gap, not a
    # false positive).
    tmpl = _template("NoOwner", security=(), owner_sid="")
    assert detect_esc4(_estate(templates=(tmpl,))) == []


# --- ESC7 -----------------------------------------------------------------


def test_esc7_manage_ca_by_low_priv_is_critical() -> None:
    ca = _ca("IssuingCA", security=(_enroll_ace(right="ManageCA"),))
    findings = detect_esc7(_estate(cas=(ca,)))
    assert len(findings) == 1
    assert findings[0].check == "ESC7"
    assert findings[0].severity == Severity.CRITICAL


def test_esc7_manage_certs_by_low_priv_is_high() -> None:
    ca = _ca("IssuingCA", security=(_enroll_ace(right="ManageCertificates"),))
    findings = detect_esc7(_estate(cas=(ca,)))
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


def test_esc7_low_priv_enroll_only_no_finding() -> None:
    # Authenticated Users with Enroll on the CA is normal, not ESC7.
    ca = _ca("IssuingCA", security=(_enroll_ace(right="Enroll"),))
    assert detect_esc7(_estate(cas=(ca,))) == []


def test_esc7_high_priv_manage_not_flagged() -> None:
    ca = _ca("IssuingCA", security=(_enroll_ace(HIGH_PRIV_SID, right="ManageCA"),))
    assert detect_esc7(_estate(cas=(ca,))) == []


def test_esc7_aggregates_both_roles_per_trustee_to_one_critical() -> None:
    # Same low-priv trustee with two ACEs (ManageCA + ManageCertificates) -> one
    # finding, escalated to critical by the Manage CA right.
    ca = _ca(
        "IssuingCA",
        security=(
            _enroll_ace(right="ManageCA"),
            _enroll_ace(right="ManageCertificates"),
        ),
    )
    findings = detect_esc7(_estate(cas=(ca,)))
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


def test_esc7_genericall_implies_manage_ca() -> None:
    # GenericAll covers ManageCA via _COVERS — a low-priv trustee granted blanket
    # CA control must be flagged CRITICAL, not silently missed (the raw rights
    # intersection would skip GenericAll entirely).
    ca = _ca("IssuingCA", security=(_enroll_ace(right="GenericAll"),))
    findings = detect_esc7(_estate(cas=(ca,)))
    assert len(findings) == 1
    assert findings[0].check == "ESC7"
    assert findings[0].severity == Severity.CRITICAL


def test_esc7_fullcontrol_implies_manage_ca() -> None:
    ca = _ca("IssuingCA", security=(_enroll_ace(right="FullControl"),))
    findings = detect_esc7(_estate(cas=(ca,)))
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


def test_esc7_all_extended_rights_does_not_imply_manage_ca() -> None:
    # AllExtendedRights covers only Enroll/AutoEnroll (extended rights), NOT the
    # CA role access-mask bits ManageCA/ManageCertificates (per Windows access-
    # mask semantics) — so it must not fire ESC7.
    ca = _ca("IssuingCA", security=(_enroll_ace(right="AllExtendedRights"),))
    assert detect_esc7(_estate(cas=(ca,))) == []


def test_esc7_degrades_when_ca_security_not_collected() -> None:
    ca = _ca("IssuingCA", security=(_enroll_ace(right="ManageCA"),))
    findings = detect_esc7(_estate(cas=(ca,), skipped_passes=("ca-security",)))
    assert len(findings) == 1
    assert findings[0].check == "CA_SECURITY_NOT_EVALUATED"
    assert findings[0].severity == Severity.INFO


def test_esc7_owner_based_control_is_critical() -> None:
    # A low-priv owner of CA\Security can rewrite the DACL -> grant ManageCA
    # (WI-037). Distinct vector from an ACE; distinct remediation (reset owner).
    ca = _ca("IssuingCA", security=(), owner_sid=LOW_PRIV_SID)
    findings = detect_esc7(_estate(cas=(ca,)))
    assert len(findings) == 1
    assert findings[0].check == "ESC7"
    assert findings[0].severity == Severity.CRITICAL
    assert "owned by" in findings[0].title.lower()
    assert "owner" in findings[0].source.lower()


def test_esc7_high_priv_owner_not_flagged() -> None:
    ca = _ca("IssuingCA", security=(), owner_sid=HIGH_PRIV_SID)
    assert detect_esc7(_estate(cas=(ca,))) == []


def test_esc7_owner_absent_not_flagged() -> None:
    # owner_sid empty (not captured) -> owner control skipped, not a false positive.
    ca = _ca("IssuingCA", security=(), owner_sid="")
    assert detect_esc7(_estate(cas=(ca,))) == []


def test_esc7_owner_and_ace_emit_distinct_findings() -> None:
    # Both an ACE granting ManageCerts and a low-priv owner -> two findings
    # (distinct vectors, distinct diff keys via source).
    ca = _ca(
        "IssuingCA",
        security=(_enroll_ace(right="ManageCertificates"),),
        owner_sid=LOW_PRIV_SID,
    )
    findings = [f for f in detect_esc7(_estate(cas=(ca,))) if f.check == "ESC7"]
    assert len(findings) == 2
    sources = {f.source for f in findings}
    assert any("owner" in s.lower() for s in sources)
    assert any("owner" not in s.lower() for s in sources)


# --- ESC9 -----------------------------------------------------------------


def test_esc9_flagged_when_enrollable_and_no_approval() -> None:
    tmpl = _template(
        "WeakMap",
        enrollment_flags=("NO_SECURITY_EXTENSION",),
        security=(_enroll_ace(),),
    )
    findings = detect_esc9(_estate(templates=(tmpl,)))
    assert len(findings) == 1
    assert findings[0].check == "ESC9"
    assert findings[0].severity == Severity.HIGH
    assert "Enrollable by" in findings[0].detail


def test_esc9_clean_template_no_finding() -> None:
    assert detect_esc9(_estate(templates=(_template("Clean"),))) == []


def test_esc9_not_flagged_without_low_priv_enroll() -> None:
    # The flag is present but no low-priv principal can enroll -> not an
    # attacker-reachable primitive -> no false positive (WI-038).
    tmpl = _template(
        "WeakMap",
        enrollment_flags=("NO_SECURITY_EXTENSION",),
        security=(_enroll_ace(HIGH_PRIV_SID),),
    )
    assert detect_esc9(_estate(templates=(tmpl,))) == []


def test_esc9_not_flagged_with_manager_approval() -> None:
    tmpl = _template(
        "WeakMap",
        enrollment_flags=("NO_SECURITY_EXTENSION", "PEND_ALL_REQUESTS"),
        security=(_enroll_ace(),),
    )
    assert detect_esc9(_estate(templates=(tmpl,))) == []


def test_esc9_degrades_when_template_security_skipped() -> None:
    # Without template security the enroll ACL cannot be evaluated -> ESC9
    # returns nothing (ESC1 emits the estate-level degrade note). No silent pass.
    tmpl = _template("WeakMap", enrollment_flags=("NO_SECURITY_EXTENSION",))
    assert detect_esc9(_estate(templates=(tmpl,), skipped_passes=("template-security",))) == []


# --- ESC16 -----------------------------------------------------------------


def test_esc16_flagged_when_security_extension_disabled_ca_wide() -> None:
    ca = _ca("WeakCA", disabled_extensions=("1.3.6.1.4.1.311.25.2",))
    findings = detect_esc16(_estate(cas=(ca,)))
    assert len(findings) == 1
    assert findings[0].check == "ESC16"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].subject == "WeakCA"
    assert "DisableExtensionList" in findings[0].source


def test_esc16_clean_ca_no_finding() -> None:
    assert detect_esc16(_estate(cas=(_ca("GoodCA"),))) == []


def test_esc16_not_flagged_for_unrelated_disabled_oid() -> None:
    # Only szOID_NTDS_CA_SECURITY_EXT triggers ESC16; another disabled OID does not.
    ca = _ca("OtherCA", disabled_extensions=("2.5.29.14",))
    assert detect_esc16(_estate(cas=(ca,))) == []


def test_esc16_evaluates_without_template_security() -> None:
    # ESC16 is CA-level (no ACL dependency), so it works on an ACL-skipped export.
    ca = _ca("WeakCA", disabled_extensions=("1.3.6.1.4.1.311.25.2",))
    findings = detect_esc16(
        _estate(cas=(ca,), skipped_passes=("template-security",))
    )
    assert len(findings) == 1


def test_esc16_flags_each_vulnerable_ca() -> None:
    two = (
        _ca("CA1", disabled_extensions=("1.3.6.1.4.1.311.25.2",)),
        _ca("CA2", disabled_extensions=("1.3.6.1.4.1.311.25.2",)),
    )
    assert len(detect_esc16(_estate(cas=two))) == 2


def test_esc16_skips_root_ca() -> None:
    # An offline root does not issue AD-auth end-entity certs, so the SID
    # extension is irrelevant there — mirroring ESC11's root exclusion.
    root = _ca(
        "RootCA",
        kind=CaKind.ROOT,
        disabled_extensions=("1.3.6.1.4.1.311.25.2",),
    )
    assert detect_esc16(_estate(cas=(root,))) == []


# --- ESC10 -----------------------------------------------------------------


def test_esc10_flagged_when_binding_disabled() -> None:
    """Case 2: StrongCertificateBindingEnforcement Disabled -> HIGH."""
    from adcs_lens.detection import detect_esc10

    estate = _estate(dcs=(_dc("WeakDC", strong_binding=StrongCertBinding.DISABLED),))
    findings = detect_esc10(estate)
    assert len(findings) == 1
    assert findings[0].check == "ESC10"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].subject == "WeakDC"
    assert "disabled" in findings[0].detail.lower()


def test_esc10_flagged_when_schannel_upn_bit_set() -> None:
    """Case 1: Schannel UPN mapping bit -> HIGH even under strict binding."""
    from adcs_lens.detection import detect_esc10

    estate = _estate(
        dcs=(
            _dc(
                "UpnDC",
                strong_binding=StrongCertBinding.STRICT,
                schannel_methods=(SchannelMappingMethod.UPN,),
            ),
        )
    )
    findings = detect_esc10(estate)
    assert len(findings) == 1
    assert findings[0].check == "ESC10"
    assert findings[0].severity == Severity.HIGH
    assert "upn" in findings[0].detail.lower()


def test_esc10_not_flagged_when_strict_and_no_upn() -> None:
    from adcs_lens.detection import detect_esc10

    estate = _estate(
        dcs=(
            _dc(
                "StrongDC",
                strong_binding=StrongCertBinding.STRICT,
                schannel_methods=(SchannelMappingMethod.S4U2SELF,),
            ),
        )
    )
    assert detect_esc10(estate) == []


def test_esc10_permissive_is_medium() -> None:
    """Compatibility mode without the UPN bit is a transitional MEDIUM."""
    from adcs_lens.detection import detect_esc10

    estate = _estate(dcs=(_dc("CompatDC", strong_binding=StrongCertBinding.PERMISSIVE),))
    findings = detect_esc10(estate)
    assert len(findings) == 1
    assert findings[0].check == "ESC10"
    assert findings[0].severity == Severity.MEDIUM
    assert "compatibility" in findings[0].detail.lower()


def test_esc10_unknown_enforcement_emits_note_not_high() -> None:
    from adcs_lens.detection import detect_esc10

    estate = _estate(dcs=(_dc("DC-UNKNOWN", strong_binding=StrongCertBinding.UNKNOWN),))
    findings = detect_esc10(estate)
    assert len(findings) == 1
    assert findings[0].check == "ESC10_ENFORCEMENT_UNKNOWN"
    assert findings[0].severity == Severity.INFO


def test_esc10_degrades_when_pass_skipped() -> None:
    from adcs_lens.detection import detect_esc10

    estate = _estate(dcs=(_dc("DC01"),), skipped_passes=("esc10-dc-registry",))
    findings = detect_esc10(estate)
    assert len(findings) == 1
    assert findings[0].check == "DC_REGISTRY_NOT_EVALUATED"
    assert findings[0].severity == Severity.INFO


def test_esc10_degrades_when_pass_ran_but_listed_no_dcs() -> None:
    # A domain always has a DC, so an empty list means discovery failed: name
    # the gap instead of reading it as a clean estate.
    from adcs_lens.detection import detect_esc10

    findings = detect_esc10(_estate(dcs=()))
    assert [(f.check, f.source) for f in findings] == [
        ("DC_REGISTRY_NOT_EVALUATED", "dc-config.json: no domain controllers listed")
    ]


def test_run_all_includes_esc10() -> None:
    estate = _estate(dcs=(_dc("DC01", strong_binding=StrongCertBinding.DISABLED),))
    assert "ESC10" in {f.check for f in run_all(estate)}


# --- ESC14 -----------------------------------------------------------------


def _weak_dc() -> DcConfiguration:
    return _dc("DC01", strong_binding=StrongCertBinding.DISABLED)


def test_esc14_flagged_when_weak_form_and_non_strict_dc() -> None:
    from adcs_lens.detection import detect_esc14

    estate = _estate(
        dcs=(_weak_dc(),),
        principal_mappings=(
            PrincipalMapping(
                dn="CN=Service Account,OU=SA,DC=test",
                mappings=(
                    "X509:<I>CN=CA<S>CN=Service Account",  # issuer+subject = weak
                    "CN=Service Account,OU=SA,DC=test",  # non-X.509, ignored
                ),
            ),
        ),
    )
    findings = detect_esc14(estate)
    assert len(findings) == 1
    assert findings[0].check == "ESC14"
    assert findings[0].severity == Severity.HIGH
    assert "Service Account" in findings[0].subject


def test_esc14_not_flagged_for_strong_forms_only() -> None:
    """The KB5014754 correction: issuer+serial and SKI are STRONG, never flagged."""
    from adcs_lens.detection import detect_esc14

    estate = _estate(
        dcs=(_weak_dc(),),
        principal_mappings=(
            PrincipalMapping(
                dn="CN=Strong,DC=test",
                mappings=(
                    "X509:<I>CN=CA<SR>1200AABBCC",  # issuer+serial = strong
                    "X509:<SKI>aB1cD2eF3",  # SKI = strong
                    "X509:<SHA1-PUKEY>cD2eF3",  # SHA1 public key = strong
                ),
            ),
        ),
    )
    assert detect_esc14(estate) == []


def test_esc14_not_flagged_when_no_x509_mappings() -> None:
    from adcs_lens.detection import detect_esc14

    estate = _estate(
        dcs=(_weak_dc(),),
        principal_mappings=(
            PrincipalMapping(
                dn="CN=Regular User,OU=Users,DC=test",
                mappings=("kerberos:user@TEST.LOCAL",),
            ),
        ),
    )
    assert detect_esc14(estate) == []


def test_esc14_not_flagged_when_all_dcs_strict() -> None:
    from adcs_lens.detection import detect_esc14

    estate = _estate(
        dcs=(_dc("DC01", strong_binding=StrongCertBinding.STRICT),),
        principal_mappings=(
            PrincipalMapping(
                dn="CN=Service Account,OU=SA,DC=test",
                mappings=("X509:<I>CN=CA<S>CN=Service Account",),
            ),
        ),
    )
    assert detect_esc14(estate) == []


def test_esc14_not_flagged_when_no_principal_mappings() -> None:
    from adcs_lens.detection import detect_esc14

    assert detect_esc14(_estate(dcs=(_weak_dc(),), principal_mappings=())) == []


def test_esc14_degrades_when_pass_skipped() -> None:
    from adcs_lens.detection import detect_esc14

    estate = _estate(
        dcs=(_weak_dc(),),
        principal_mappings=(
            PrincipalMapping(
                dn="CN=Service Account,OU=SA,DC=test",
                mappings=("X509:<I>CN=CA<S>CN=Service Account",),
            ),
        ),
        skipped_passes=("esc14-altsecid",),
    )
    findings = detect_esc14(estate)
    assert len(findings) == 1
    assert findings[0].check == "ALTSECID_NOT_EVALUATED"
    assert findings[0].severity == Severity.INFO


def test_esc14_clean_when_pass_ran_and_no_mappings() -> None:
    from adcs_lens.detection import detect_esc14

    assert detect_esc14(_estate(dcs=(_weak_dc(),), principal_mappings=())) == []


def test_esc14_enforcement_unknown_when_dc_registry_skipped() -> None:
    from adcs_lens.detection import detect_esc14

    estate = _estate(
        dcs=(),
        principal_mappings=(
            PrincipalMapping(dn="CN=X,DC=test", mappings=("X509:<S>CN=X",)),
        ),
        skipped_passes=("esc10-dc-registry",),
    )
    findings = detect_esc14(estate)
    assert len(findings) == 1
    assert findings[0].check == "ESC14_ENFORCEMENT_UNKNOWN"
    assert findings[0].severity == Severity.INFO


def test_esc14_enforcement_unknown_when_binding_unreadable() -> None:
    from adcs_lens.detection import detect_esc14

    estate = _estate(
        dcs=(_dc("DC-UNKNOWN", strong_binding=StrongCertBinding.UNKNOWN),),
        principal_mappings=(
            PrincipalMapping(dn="CN=X,DC=test", mappings=("X509:<S>CN=X",)),
        ),
    )
    findings = detect_esc14(estate)
    assert len(findings) == 1
    assert findings[0].check == "ESC14_ENFORCEMENT_UNKNOWN"
    assert findings[0].severity == Severity.INFO


def test_x509_mapping_form_classification() -> None:
    from adcs_lens.detection import _x509_mapping_form
    from adcs_lens.model import X509MappingForm

    assert _x509_mapping_form("X509:<I>CN=CA<S>CN=Svc") is X509MappingForm.ISSUER_SUBJECT
    assert _x509_mapping_form("X509:<S>CN=Svc") is X509MappingForm.SUBJECT_ONLY
    assert _x509_mapping_form("X509:<RFC822>u@test") is X509MappingForm.RFC822
    assert _x509_mapping_form("X509:<PN>u@test") is X509MappingForm.PRINCIPAL_NAME
    assert _x509_mapping_form("X509:<I>CN=CA<SR>12AB") is X509MappingForm.ISSUER_SERIAL
    assert _x509_mapping_form("X509:<SKI>aabb") is X509MappingForm.SKI
    assert _x509_mapping_form("X509:<SHA1-PUKEY>aabb") is X509MappingForm.SHA1_PUBLIC_KEY
    # case-insensitive prefix; whitespace tolerant
    assert _x509_mapping_form("  x509:<s>CN=Svc  ") is X509MappingForm.SUBJECT_ONLY
    # non-X.509 / unrecognized
    assert _x509_mapping_form("kerberos:u@TEST") is X509MappingForm.UNKNOWN
    assert _x509_mapping_form("") is X509MappingForm.UNKNOWN
    assert _x509_mapping_form("X509:<I>CN=CA") is X509MappingForm.UNKNOWN  # issuer-only


def test_esc14_empty_mappings_not_flagged() -> None:
    from adcs_lens.detection import detect_esc14

    estate = _estate(
        dcs=(_weak_dc(),),
        principal_mappings=(PrincipalMapping(dn="CN=X,DC=test", mappings=()),),
    )
    assert detect_esc14(estate) == []


def test_esc14_lists_only_non_strict_dcs() -> None:
    from adcs_lens.detection import detect_esc14

    estate = _estate(
        dcs=(
            _dc("VULN-DC", strong_binding=StrongCertBinding.DISABLED),
            _dc("SAFE-DC", strong_binding=StrongCertBinding.STRICT),
        ),
        principal_mappings=(
            PrincipalMapping(dn="CN=X,DC=test", mappings=("X509:<S>CN=X",)),
        ),
    )
    findings = detect_esc14(estate)
    assert len(findings) == 1
    assert findings[0].check == "ESC14"
    assert "VULN-DC" in findings[0].detail
    assert "SAFE-DC" not in findings[0].detail


def test_run_all_includes_esc14() -> None:
    estate = _estate(
        dcs=(_weak_dc(),),
        principal_mappings=(
            PrincipalMapping(
                dn="CN=Service Account,OU=SA,DC=test",
                mappings=("X509:<I>CN=CA<S>CN=Service Account",),
            ),
        ),
    )
    assert "ESC14" in {f.check for f in run_all(estate)}


# --- template ACL gap -----------------------------------------------------


def test_acl_gap_emits_one_info_per_unreadable_template() -> None:
    # One unreadable template (otherwise ESC1-positive) + one readable clean one.
    unreadable = _template("Unreadable", security=(_enroll_ace(),), acl_obtained=False)
    readable = _template("Readable", security=(_enroll_ace(),), acl_obtained=True)
    findings = detect_template_acl_gaps(_estate(templates=(unreadable, readable)))
    assert len(findings) == 1
    assert findings[0].check == "TEMPLATE_ACL_UNREADABLE"
    assert findings[0].severity == Severity.INFO
    assert findings[0].subject == "Unreadable"
    # Detail enumerates exactly the ACL-dependent detectors that were skipped.
    assert "ESC1/2/3/4/13" in findings[0].detail


def test_acl_gap_silent_when_template_security_not_collected() -> None:
    # Estate-level degrade owns the note when the whole pass was skipped.
    tmpl = _template("Unreadable", security=(_enroll_ace(),), acl_obtained=False)
    estate = _estate(templates=(tmpl,), skipped_passes=("template-security",))
    assert detect_template_acl_gaps(estate) == []


def test_esc1_skips_unreadable_template() -> None:
    # ESC1-positive but acl_obtained=False -> gap detector owns the note, ESC1 silent.
    tmpl = _template("Unreadable", security=(_enroll_ace(),), acl_obtained=False)
    assert detect_esc1(_estate(templates=(tmpl,))) == []


def test_esc4_skips_unreadable_template() -> None:
    # ESC4-positive (WriteDacl to low-priv) but acl_obtained=False -> ESC4 silent.
    tmpl = _template(
        "Writable", security=(_enroll_ace(right="WriteDacl"),), acl_obtained=False
    )
    assert detect_esc4(_estate(templates=(tmpl,))) == []


def test_esc2_skips_unreadable_template() -> None:
    # No-EKU (any-purpose) + low-priv enroll is ESC2-positive, but unreadable DACL
    # means the enroll ACL cannot be evaluated -> ESC2 silent, gap detector owns it.
    tmpl = _template("Any", ekus=(), security=(_enroll_ace(),), acl_obtained=False)
    assert detect_esc2(_estate(templates=(tmpl,))) == []


def test_esc3_skips_unreadable_template() -> None:
    tmpl = _template(
        "Agent", ekus=(ENROLLMENT_AGENT,), security=(_enroll_ace(),), acl_obtained=False
    )
    assert detect_esc3(_estate(templates=(tmpl,))) == []


def test_esc9_skips_unreadable_template() -> None:
    # The enroll ACL could not be read (acl_obtained=False) -> ESC9 cannot
    # confirm enrollability -> skips the template (TEMPLATE_ACL_UNREADABLE
    # covers the gap). Not a false positive, not a silent pass.
    tmpl = _template(
        "WeakMap", enrollment_flags=("NO_SECURITY_EXTENSION",), acl_obtained=False
    )
    assert detect_esc9(_estate(templates=(tmpl,))) == []


def test_acl_gap_wired_into_run_all() -> None:
    # Unreadable-template estate: TEMPLATE_ACL_UNREADABLE present, matching ESC1
    # and ESC9 absent (both need the enroll ACL, which is unreadable).
    tmpl = _template(
        "Unreadable",
        security=(_enroll_ace(),),
        enrollment_flags=("NO_SECURITY_EXTENSION",),
        acl_obtained=False,
    )
    checks = {f.check for f in run_all(_estate(templates=(tmpl,)))}
    assert "TEMPLATE_ACL_UNREADABLE" in checks
    assert "ESC1" not in checks
    assert "ESC9" not in checks


# --- lifecycle: degrade path ----------------------------------------------


def test_lifecycle_degrades_without_certs() -> None:
    findings = detect_infra_cert_expiry(_estate(certs_parsed=False), now=NOW)
    assert len(findings) == 1
    assert findings[0].check == "LIFECYCLE_NOT_EVALUATED"
    assert findings[0].severity == Severity.INFO


def test_lifecycle_rejects_naive_now() -> None:
    estate = _estate(
        cas=(
            _ca(
                "CA",
                certs=(
                    CertLifecycle(
                        "CN=Soon",
                        CertKind.ISSUING_CA,
                        NOW,
                        NOW + timedelta(days=30),
                        "sha256",
                        2048,
                        "rsa",
                    ),
                ),
            ),
        )
    )
    try:
        detect_infra_cert_expiry(estate, now=datetime(2026, 6, 15, 12, 0, 0))
    except ValueError:
        pass
    else:
        raise AssertionError("naive datetime should be rejected")


# --- lifecycle: cert expiry -----------------------------------------------


def test_expired_ca_cert_critical() -> None:
    cert = CertLifecycle(
        "CN=Old",
        CertKind.ISSUING_CA,
        NOW - timedelta(days=800),
        NOW - timedelta(days=1),
        "sha256",
        2048,
        "rsa",
    )
    findings = detect_infra_cert_expiry(_estate(cas=(_ca("CA", certs=(cert,)),)), now=NOW)
    assert findings[0].check == "CA_CERT_EXPIRY"
    assert findings[0].severity == Severity.CRITICAL


def test_issuing_cert_near_expiry_high() -> None:
    cert = CertLifecycle(
        "CN=Soon", CertKind.ISSUING_CA, NOW, NOW + timedelta(days=30), "sha256", 2048, "rsa"
    )
    findings = detect_infra_cert_expiry(
        _estate(cas=(_ca("CA", certs=(cert,)),)), now=NOW, warn_days=90
    )
    assert findings[0].severity == Severity.HIGH


def test_root_cert_near_expiry_escalated_to_critical() -> None:
    cert = CertLifecycle(
        "CN=Root", CertKind.ROOT_CA, NOW, NOW + timedelta(days=30), "sha256", 4096, "rsa"
    )
    findings = detect_infra_cert_expiry(
        _estate(cas=(_ca("Root", kind=CaKind.ROOT, certs=(cert,)),)), now=NOW
    )
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].tier == CrlTier.ROOT


def test_healthy_cert_no_finding() -> None:
    cert = CertLifecycle(
        "CN=Fine", CertKind.ISSUING_CA, NOW, NOW + timedelta(days=1000), "sha256", 2048, "rsa"
    )
    assert detect_infra_cert_expiry(_estate(cas=(_ca("CA", certs=(cert,)),)), now=NOW) == []


# --- lifecycle: CRL freshness ---------------------------------------------


def test_expired_root_crl_critical_and_root_tier() -> None:
    crl = Crl(
        "CN=Root",
        NOW - timedelta(days=400),
        NOW - timedelta(days=35),
        CrlTier.ROOT,
        "published",
    )
    findings = detect_infra_cert_expiry(_estate(crls=(crl,)), now=NOW)
    assert findings[0].check == "CRL_EXPIRY"
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].tier == CrlTier.ROOT
    assert "offline" in findings[0].detail


def test_fresh_crl_no_finding() -> None:
    crl = Crl(
        "CN=Iss",
        NOW - timedelta(days=2),
        NOW + timedelta(days=5),
        CrlTier.ISSUING,
        "host",
    )
    assert detect_infra_cert_expiry(_estate(crls=(crl,)), now=NOW) == []


# --- lifecycle: CRL early-warning window (WI-022) -------------------------


def test_crl_early_warning_within_window_is_high() -> None:
    # Validity period 8 days; 25% window = 2 days (floored at 1). 1 day remains
    # -> within the window -> HIGH (issuing tier), not CRITICAL.
    crl = Crl("CN=Iss", NOW - timedelta(days=7), NOW + timedelta(days=1), CrlTier.ISSUING, "dp")
    findings = detect_infra_cert_expiry(_estate(crls=(crl,)), now=NOW)
    assert len(findings) == 1
    assert findings[0].check == "CRL_EXPIRY"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].tier == CrlTier.ISSUING
    assert "early-warning" in findings[0].title
    assert "1 day" in findings[0].title


def test_crl_early_warning_root_tier_escalates_to_critical() -> None:
    crl = Crl("CN=Root", NOW - timedelta(days=7), NOW + timedelta(days=1), CrlTier.ROOT, "dp")
    findings = detect_infra_cert_expiry(_estate(crls=(crl,)), now=NOW)
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].tier == CrlTier.ROOT


def test_crl_outside_warning_window_no_finding() -> None:
    # Validity 10 days; window 2.5 days; 3 days remain -> outside window -> clean.
    crl = Crl("CN=Iss", NOW - timedelta(days=7), NOW + timedelta(days=3), CrlTier.ISSUING, "dp")
    assert detect_infra_cert_expiry(_estate(crls=(crl,)), now=NOW) == []


def test_crl_window_floored_to_one_day_for_multi_day_validity() -> None:
    # Validity 3 days; 25% would be 0.75 day, floored up to 1 day (1d < 3d so the
    # floor is strictly inside the validity period). 1 day remains -> flagged.
    crl = Crl("CN=Iss", NOW - timedelta(days=2), NOW + timedelta(days=1), CrlTier.ISSUING, "dp")
    findings = detect_infra_cert_expiry(_estate(crls=(crl,)), now=NOW)
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert "1 day" in findings[0].title


def test_crl_short_validity_not_flagged_from_publication() -> None:
    # A 24-hour CRL the moment it is published: fractional window is 6h, and the
    # 1-day floor does NOT apply (1d is not strictly inside a 1d validity), so a
    # fresh short CRL is not flagged (WI-022 review fix — no false positive from
    # publication on short-lived CRLs).
    crl = Crl("CN=Iss", NOW, NOW + timedelta(hours=24), CrlTier.ISSUING, "dp")
    assert detect_infra_cert_expiry(_estate(crls=(crl,)), now=NOW) == []


def test_crl_sub_day_remaining_rendered_in_hours() -> None:
    # Within the window with under a day remaining -> title reads hours, not the
    # misleading "0 day(s)" that timedelta.days truncation would produce.
    validity = timedelta(days=8)
    next_update = NOW + timedelta(hours=5)
    crl = Crl("CN=Iss", next_update - validity, next_update, CrlTier.ISSUING, "dp")
    findings = detect_infra_cert_expiry(_estate(crls=(crl,)), now=NOW)
    assert len(findings) == 1
    assert "hour" in findings[0].title


def test_crl_without_this_update_only_flags_when_expired() -> None:
    fresh = Crl("CN=Iss", None, NOW + timedelta(days=1), CrlTier.ISSUING, "dp")
    assert detect_infra_cert_expiry(_estate(crls=(fresh,)), now=NOW) == []
    expired = Crl("CN=Iss", None, NOW - timedelta(days=1), CrlTier.ISSUING, "dp")
    findings = detect_infra_cert_expiry(_estate(crls=(expired,)), now=NOW)
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


# --- ACL coverage caveat (WI-033) -----------------------------------------


def test_acl_caveat_fires_when_templates_have_security() -> None:
    tmpl = _template("T", security=(_enroll_ace(),))
    findings = detect_acl_coverage_caveats(_estate(templates=(tmpl,)))
    assert len(findings) == 1
    assert findings[0].check == "ACL_GROUP_TOKEN_CAVEAT"
    assert findings[0].severity == Severity.INFO
    assert is_degradation_note(findings[0])
    assert "group" in findings[0].detail.lower()


def test_acl_caveat_fires_for_pki_acl_or_ca_security() -> None:
    acl = PkiObjectAcl(object_dn="cn=x", kind=AclKind.NTAUTH, security=(_ctrl_ace(),))
    assert detect_acl_coverage_caveats(_estate(acls=(acl,)))
    ca = _ca("CA", security=(_ctrl_ace(),))
    assert detect_acl_coverage_caveats(_estate(cas=(ca,)))


def test_acl_caveat_absent_without_any_acl_inputs() -> None:
    # Templates with no security, no PKI ACLs, no CA security -> nothing to caveat.
    assert detect_acl_coverage_caveats(_estate(templates=(_template("T"),))) == []
    assert detect_acl_coverage_caveats(_estate()) == []


# --- ESC11 ----------------------------------------------------------------


def test_esc11_flagged_when_flag_absent() -> None:
    estate = _estate(cas=(_ca("IssuingCA", interface_flags=()),))
    findings = detect_esc11(estate)
    assert len(findings) == 1
    assert findings[0].check == "ESC11"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].subject == "IssuingCA"
    assert "InterfaceFlags" in findings[0].source


def test_esc11_clean_when_flag_present() -> None:
    estate = _estate(
        cas=(_ca("IssuingCA", interface_flags=("IF_ENFORCEENCRYPTICERTREQUEST",)),)
    )
    assert detect_esc11(estate) == []


def test_esc11_root_ca_not_flagged_even_if_flag_absent() -> None:
    estate = _estate(cas=(_ca("RootCA", kind=CaKind.ROOT, interface_flags=()),))
    assert detect_esc11(estate) == []


def test_esc11_flagged_when_only_unrelated_flags_present() -> None:
    # An unrelated interface flag does not mask the absence of the encryption
    # requirement — this is exactly the CA that should be flagged.
    estate = _estate(cas=(_ca("IssuingCA", interface_flags=("IF_LOCKICERTREQUEST",)),))
    findings = detect_esc11(estate)
    assert len(findings) == 1
    assert findings[0].check == "ESC11"


# --- ESC13 ----------------------------------------------------------------


def test_esc13_flagged_when_policy_linked_and_low_priv_enroll() -> None:
    tmpl = _template(
        "LinkedPolicy",
        ekus=(CLIENT_AUTH,),
        issuance_policy_oids=(POLICY_OID,),
        security=(_enroll_ace(),),
    )
    estate = _estate(
        templates=(tmpl,),
        oids=(IssuanceOid(POLICY_OID, "Linked", DOMAIN_ADMINS_SID),),
    )
    findings = detect_esc13(estate)
    assert len(findings) == 1
    assert findings[0].check == "ESC13"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].subject == "LinkedPolicy"
    assert DOMAIN_ADMINS_SID in findings[0].detail


def test_esc13_not_flagged_when_policy_not_group_linked() -> None:
    tmpl = _template(
        "UnlinkedPolicy",
        ekus=(CLIENT_AUTH,),
        issuance_policy_oids=(POLICY_OID,),
        security=(_enroll_ace(),),
    )
    estate = _estate(
        templates=(tmpl,),
        oids=(IssuanceOid(POLICY_OID, "Linked", None),),
    )
    assert detect_esc13(estate) == []


def test_esc13_not_flagged_without_auth_eku() -> None:
    tmpl = _template(
        "ServerPolicy",
        ekus=(SERVER_AUTH,),
        issuance_policy_oids=(POLICY_OID,),
        security=(_enroll_ace(),),
    )
    estate = _estate(
        templates=(tmpl,),
        oids=(IssuanceOid(POLICY_OID, "Linked", DOMAIN_ADMINS_SID),),
    )
    assert detect_esc13(estate) == []


def test_esc13_mitigated_by_manager_approval() -> None:
    tmpl = _template(
        "ApprovedPolicy",
        ekus=(CLIENT_AUTH,),
        issuance_policy_oids=(POLICY_OID,),
        enrollment_flags=("PEND_ALL_REQUESTS",),
        security=(_enroll_ace(),),
    )
    estate = _estate(
        templates=(tmpl,),
        oids=(IssuanceOid(POLICY_OID, "Linked", DOMAIN_ADMINS_SID),),
    )
    assert detect_esc13(estate) == []


def test_esc13_requires_low_priv_enroll() -> None:
    tmpl = _template(
        "AdminPolicy",
        ekus=(CLIENT_AUTH,),
        issuance_policy_oids=(POLICY_OID,),
        security=(_enroll_ace(HIGH_PRIV_SID),),
    )
    estate = _estate(
        templates=(tmpl,),
        oids=(IssuanceOid(POLICY_OID, "Linked", DOMAIN_ADMINS_SID),),
    )
    assert detect_esc13(estate) == []


def test_esc13_silent_when_template_security_not_collected() -> None:
    tmpl = _template(
        "LinkedPolicy",
        ekus=(CLIENT_AUTH,),
        issuance_policy_oids=(POLICY_OID,),
        security=(_enroll_ace(),),
    )
    estate = _estate(
        templates=(tmpl,),
        oids=(IssuanceOid(POLICY_OID, "Linked", DOMAIN_ADMINS_SID),),
        skipped_passes=("template-security",),
    )
    assert detect_esc13(estate) == []


def test_esc13_skips_unreadable_template() -> None:
    # ESC13 also depends on the enroll ACL; an unreadable-DACL template with a
    # group-linked policy is skipped (the gap detector owns the note).
    tmpl = _template(
        "UnreadablePolicy",
        ekus=(CLIENT_AUTH,),
        issuance_policy_oids=(POLICY_OID,),
        security=(_enroll_ace(),),
        acl_obtained=False,
    )
    estate = _estate(
        templates=(tmpl,), oids=(IssuanceOid(POLICY_OID, "L", DOMAIN_ADMINS_SID),)
    )
    assert detect_esc13(estate) == []
    # And the gap detector surfaces it instead.
    assert any(
        f.check == "TEMPLATE_ACL_UNREADABLE" for f in detect_template_acl_gaps(estate)
    )


def test_esc13_flagged_when_no_eku() -> None:
    # No EKU = valid for any purpose (incl. client auth) -> the dangerous
    # SubCA-equivalent case; still auth-capable, so still ESC13.
    tmpl = _template(
        "NoEkuPolicy", ekus=(), issuance_policy_oids=(POLICY_OID,), security=(_enroll_ace(),)
    )
    estate = _estate(templates=(tmpl,), oids=(IssuanceOid(POLICY_OID, "L", DOMAIN_ADMINS_SID),))
    assert len(detect_esc13(estate)) == 1


def test_esc13_flagged_with_any_purpose_eku() -> None:
    tmpl = _template(
        "AnyPurposePolicy",
        ekus=(ANY_PURPOSE,),
        issuance_policy_oids=(POLICY_OID,),
        security=(_enroll_ace(),),
    )
    estate = _estate(templates=(tmpl,), oids=(IssuanceOid(POLICY_OID, "L", DOMAIN_ADMINS_SID),))
    assert len(detect_esc13(estate)) == 1


def test_esc13_not_flagged_when_template_has_no_policy() -> None:
    tmpl = _template("Plain", ekus=(CLIENT_AUTH,), security=(_enroll_ace(),))
    estate = _estate(
        templates=(tmpl,), oids=(IssuanceOid(POLICY_OID, "L", DOMAIN_ADMINS_SID),)
    )
    assert detect_esc13(estate) == []


def test_esc13_not_flagged_when_oid_absent_from_estate() -> None:
    # Template references a policy OID that is not present (or not group-linked)
    # in estate.oids -> no join -> no finding.
    tmpl = _template(
        "OrphanPolicy",
        ekus=(CLIENT_AUTH,),
        issuance_policy_oids=(POLICY_OID,),
        security=(_enroll_ace(),),
    )
    assert detect_esc13(_estate(templates=(tmpl,), oids=())) == []


# --- ESC15 ----------------------------------------------------------------


def test_esc15_high_when_ca_unpatched() -> None:
    from adcs_lens.detection import detect_esc15

    # A v1 template with no auth EKU and no supplies-subject is still ESC15: the
    # requester injects the application policy under EKUwu. On a known-unpatched
    # CA the finding is HIGH.
    tmpl = _template(
        "WebServerV1",
        schema_version=1,
        ekus=("1.3.6.1.5.5.7.3.1",),  # serverAuth — not a client-auth EKU
        name_flags=(),
        security=(_enroll_ace(),),
    )
    findings = detect_esc15(
        _estate(cas=(_ca("CA", ca_patch_state=CaPatchState.UNPATCHED),), templates=(tmpl,))
    )
    assert len(findings) == 1
    assert findings[0].check == "ESC15"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].subject == "WebServerV1"
    assert "CVE-2024-49019" in findings[0].detail


def test_esc15_medium_when_patch_state_unknown() -> None:
    from adcs_lens.detection import detect_esc15

    # When CA patch state is unknown (the common case — the collector cannot yet
    # read it), ESC15 is MEDIUM with an explicit "confirm patch state" caveat,
    # not a false HIGH on a patched estate (WI-027).
    tmpl = _template("V1Unknown", schema_version=1, security=(_enroll_ace(),))
    findings = detect_esc15(_estate(cas=(_ca("CA"),), templates=(tmpl,)))
    assert len(findings) == 1
    assert findings[0].check == "ESC15"
    assert findings[0].severity == Severity.MEDIUM
    assert "patch state is unknown" in findings[0].detail.lower()


def test_esc15_suppressed_when_ca_patched() -> None:
    from adcs_lens.detection import detect_esc15

    # On a known-patched CA the EKUwu path is closed — no finding (WI-027).
    tmpl = _template("V1Patched", schema_version=1, security=(_enroll_ace(),))
    assert (
        detect_esc15(
            _estate(cas=(_ca("CA", ca_patch_state=CaPatchState.PATCHED),), templates=(tmpl,))
        )
        == []
    )


def test_esc15_ignores_offline_root_patch_state() -> None:
    from adcs_lens.detection import detect_esc15

    # An unpatched offline ROOT must not escalate ESC15 when the issuing CA is
    # patched — the root never issues end-entity certs (mirrors ESC11/ESC16).
    tmpl = _template("V1", schema_version=1, security=(_enroll_ace(),))
    estate = _estate(
        cas=(
            _ca("Root", kind=CaKind.ROOT, ca_patch_state=CaPatchState.UNPATCHED),
            _ca("Issuing", ca_patch_state=CaPatchState.PATCHED),
        ),
        templates=(tmpl,),
    )
    assert detect_esc15(estate) == []


def test_esc15_not_flagged_for_v2_template() -> None:
    from adcs_lens.detection import detect_esc15

    tmpl = _template("ModernTemplate", schema_version=2, security=(_enroll_ace(),))
    assert detect_esc15(_estate(templates=(tmpl,))) == []


def test_esc15_mitigated_by_manager_approval() -> None:
    from adcs_lens.detection import detect_esc15

    tmpl = _template(
        "V1Approved",
        schema_version=1,
        enrollment_flags=("PEND_ALL_REQUESTS",),
        security=(_enroll_ace(),),
    )
    assert detect_esc15(_estate(templates=(tmpl,))) == []


def test_esc15_requires_low_priv_enroll() -> None:
    from adcs_lens.detection import detect_esc15

    # v1 template but only a high-priv trustee can enroll -> not ESC15.
    tmpl = _template(
        "V1Restricted",
        schema_version=1,
        security=(_enroll_ace(sid="S-1-5-21-1-2-3-512"),),  # Domain Admins
    )
    assert detect_esc15(_estate(templates=(tmpl,))) == []


def test_esc15_silent_when_template_security_not_collected() -> None:
    from adcs_lens.detection import detect_esc15

    tmpl = _template("V1", schema_version=1, security=(_enroll_ace(),))
    estate = _estate(templates=(tmpl,), skipped_passes=("template-security",))
    assert detect_esc15(estate) == []


def test_esc15_skips_unreadable_template() -> None:
    from adcs_lens.detection import detect_esc15

    tmpl = _template("V1", schema_version=1, acl_obtained=False, security=())
    assert detect_esc15(_estate(templates=(tmpl,))) == []


def test_run_all_includes_esc15() -> None:
    tmpl = _template("V1", schema_version=1, security=(_enroll_ace(),))
    assert "ESC15" in {f.check for f in run_all(_estate(templates=(tmpl,)))}


# --- composition ----------------------------------------------------------


def test_run_all_sorted_worst_first() -> None:
    from adcs_lens.model import SEVERITY_RANK

    cert = _cert("CN=Soon", not_after=NOW + timedelta(days=30))
    estate = _estate(
        cas=(_ca("BadCA", edit_flags=("EDITF_ATTRIBUTESUBJECTALTNAME2",), certs=(cert,)),),
    )
    findings = run_all(estate, now=NOW)
    severities = [f.severity for f in findings]
    assert severities == sorted(severities, key=SEVERITY_RANK.__getitem__)
    assert findings[0].severity == Severity.CRITICAL


# --- ESC1 / ESC2 / ESC3 and authorized signatures (live run 2026-10-13, A1d) ---

_ENROLL = (AceEntry(LOW_PRIV_SID, "Domain Users", ("Enroll",), AceType.ALLOW),)


def _esc123_templates(ra: int | None, *, unread: bool = False) -> dict[str, CertTemplate]:
    base = {
        "ESC1": _template("E1", security=_ENROLL),
        "ESC2": _template("E2", ekus=(), name_flags=(), security=_ENROLL),
        "ESC3": _template("E3", ekus=(ENROLLMENT_AGENT,), name_flags=(), security=_ENROLL),
    }
    lost = frozenset({"ra_signatures"}) if unread else frozenset()
    return {k: replace(t, ra_signatures=ra, unobtained=lost) for k, t in base.items()}


_ESC123 = {"ESC1": detect_esc1, "ESC2": detect_esc2, "ESC3": detect_esc3}
_FULL = {"ESC1": Severity.CRITICAL, "ESC2": Severity.HIGH, "ESC3": Severity.HIGH}


def test_esc123_no_authorized_signature_keeps_full_severity() -> None:
    for check, tmpl in _esc123_templates(0).items():
        (f,) = _ESC123[check](_estate(templates=(tmpl,)))
        assert (f.check, f.severity) == (check, _FULL[check])
        assert "msPKI-RA-Signature" not in f.detail


def test_esc123_a_required_authorized_signature_caps_at_medium() -> None:
    # The documented rule: >= 1 required signature is not a suppression (an
    # enrollment agent can supply it) but caps the severity at MEDIUM.
    for ra in (1, 2):
        for check, tmpl in _esc123_templates(ra).items():
            (f,) = _ESC123[check](_estate(templates=(tmpl,)))
            assert (f.check, f.severity) == (check, Severity.MEDIUM)
            assert f"requires {ra} authorized signature(s)" in f.detail
            assert "ESC3" in f.detail


def test_esc123_an_unread_requirement_is_never_zero_and_never_a_mitigation() -> None:
    for unread in (False, True):  # an older export / a null from the collector
        for check, tmpl in _esc123_templates(None, unread=unread).items():
            (f,) = _ESC123[check](_estate(templates=(tmpl,)))
            assert f.severity == _FULL[check]
            assert "was not read, so it is treated as none" in f.detail


def test_esc123_a_failed_read_still_flags_but_the_verdict_is_unusable() -> None:
    # (A usable verdict needs complete containers: see the simulated A1d tests.)
    estate = _estate(templates=tuple(_esc123_templates(None, unread=True).values()))
    got = {
        (v.check, v.state, v.usable)
        for v in evaluate(estate, now=NOW).verdicts
        if v.check in _ESC123 and v.state != "clean"
    }
    assert got == {(c, "finding", False) for c in _ESC123}


# --- ESC5 on the CA server's computer object (live run 2026-10-13, case B3) ---

_CA_HOST_SID = "S-1-5-21-1111111111-2222222222-3333333333-1105"
_COMPUTER_DN = "CN=LABCA01,CN=Computers,DC=lab,DC=example,DC=com"


def _computer(*aces: AceEntry, owner: str = DOMAIN_ADMINS_SID) -> PkiObjectAcl:
    return PkiObjectAcl(
        object_dn=_COMPUTER_DN, kind=AclKind.CA_COMPUTER, security=aces, owner_sid=owner
    )


def test_esc5_low_priv_control_of_the_ca_computer_object_is_critical() -> None:
    for right in ("GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "WritePropertyAll"):
        ace = AceEntry(LOW_PRIV_SID, "Helpdesk", (right,), AceType.ALLOW)
        (f,) = detect_esc5(_estate(acls=(_computer(ace),)))
        assert f.check == "ESC5" and f.severity == Severity.CRITICAL, right
        assert "computer object" in f.detail


def test_esc5_low_priv_owner_of_the_ca_computer_object_is_critical() -> None:
    (f,) = detect_esc5(_estate(acls=(_computer(owner=LOW_PRIV_SID),)))
    assert f.severity == Severity.CRITICAL and f.variant == "owner"


def test_esc5_the_ca_host_account_is_not_exempt_on_its_computer_object() -> None:
    # The round-4 exemption is for the enrollment-service object only: a
    # ca_host_sid (which ingest refuses on such a row anyway) exempts nothing.
    ace = AceEntry(_CA_HOST_SID, "LABCA01$", ("GenericAll",), AceType.ALLOW)
    obj = replace(_computer(ace), ca_host_sid=_CA_HOST_SID, enrollment_service=True)
    assert [f.check for f in detect_esc5(_estate(acls=(obj,)))] == ["ESC5"]


# Review round 1 (Sol B2 / DeepSeek N1): property-scoped takeover writes on the
# CA computer object. GUIDs from [MS-ADA2] 2.218 / 2.358 and [MS-ADTS]
# 3.1.1.2.3.3 / 6.1.1.2.7.59 / 6.1.1.2.7.82 (see _CA_COMPUTER_TAKEOVER_PROPERTIES).
_RBCD = "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79"
_ACCOUNT_RESTRICTIONS = "4c164200-20c0-11d0-a768-00aa006e0529"
_KEY_CREDENTIAL_LINK = "5b47d60f-6090-40b2-9f37-2a4de88f3063"
_VALIDATED_WRITE_COMPUTER = "9b026da6-0d3c-465c-8bee-5199d7165cba"
# Any GUID outside the takeover set (the scoped write must name one of them).
_UNRELATED = "f3a64788-5306-11d1-a9c5-0000f80367c1"


def _scoped(guid: str, *before: AceEntry, sid: str = LOW_PRIV_SID) -> PkiObjectAcl:
    """A computer object whose DACL holds *before* (canonical order: Denies
    first), then a scoped WriteProperty Allow for *sid*."""
    allow = AceEntry(sid, "Helpdesk", (f"WriteProperty:{guid}",), AceType.ALLOW)
    return _computer(*before, allow)


@pytest.mark.parametrize(
    "guid", [_RBCD, _ACCOUNT_RESTRICTIONS, _KEY_CREDENTIAL_LINK, _VALIDATED_WRITE_COMPUTER]
)
def test_esc5_a_scoped_takeover_write_on_the_ca_computer_object_is_critical(guid: str) -> None:
    for token in (guid, guid.upper()):
        (f,) = detect_esc5(_estate(acls=(_scoped(token),)))
        assert (f.check, f.variant, f.severity) == (
            "ESC5",
            "scoped-writeproperty",
            Severity.CRITICAL,
        )
        assert "Helpdesk" in f.detail


def test_esc5_a_scoped_write_to_an_unrelated_attribute_does_not_fire() -> None:
    assert detect_esc5(_estate(acls=(_scoped(_UNRELATED),))) == []


def test_esc5_scoped_takeover_writes_honour_deny_precedence() -> None:
    exact = AceEntry(LOW_PRIV_SID, "", (f"WriteProperty:{_RBCD}",), AceType.DENY)
    assert detect_esc5(_estate(acls=(_scoped(_RBCD, exact),))) == []
    for blanket in ("WritePropertyAll", "GenericWrite", "GenericAll"):
        deny = AceEntry(LOW_PRIV_SID, "", (blanket,), AceType.DENY)
        assert detect_esc5(_estate(acls=(_scoped(_KEY_CREDENTIAL_LINK, deny),))) == [], blanket
    # A Deny on one attribute leaves the other scoped write standing.
    other = AceEntry(LOW_PRIV_SID, "", (f"WriteProperty:{_KEY_CREDENTIAL_LINK}",), AceType.DENY)
    assert [f.variant for f in detect_esc5(_estate(acls=(_scoped(_RBCD, other),)))] == [
        "scoped-writeproperty"
    ]


# Review round 2 (Sol B2): [MS-ADTS] Checking Object-Specific Access - ACEs in
# DACL order, the object -> property set -> attribute tree, inherit-only ACEs
# skipped. Sol's five probes, then inherit-only and explicit-before-inherited.
def _wp(kind: AceType, guid: str, **flags: bool) -> AceEntry:
    return AceEntry(LOW_PRIV_SID, "Helpdesk", (f"WriteProperty:{guid}",), kind, **flags)


@pytest.mark.parametrize(
    ("label", "aces", "fires"),
    [
        (
            "deny Account Restrictions then allow RBCD",
            (_wp(AceType.DENY, _ACCOUNT_RESTRICTIONS), _wp(AceType.ALLOW, _RBCD)),
            False,
        ),
        (
            "deny RBCD then allow Account Restrictions",
            (_wp(AceType.DENY, _RBCD), _wp(AceType.ALLOW, _ACCOUNT_RESTRICTIONS)),
            False,
        ),
        (
            "deny DS-Validated-Write-Computer then allow KCL",
            (
                _wp(AceType.DENY, _VALIDATED_WRITE_COMPUTER),
                _wp(AceType.ALLOW, _KEY_CREDENTIAL_LINK),
            ),
            False,
        ),
        (
            "deny KCL then allow DS-Validated-Write-Computer",
            (
                _wp(AceType.DENY, _KEY_CREDENTIAL_LINK),
                _wp(AceType.ALLOW, _VALIDATED_WRITE_COMPUTER),
            ),
            False,
        ),
        (
            "allow RBCD before deny RBCD",
            (_wp(AceType.ALLOW, _RBCD), _wp(AceType.DENY, _RBCD)),
            True,
        ),
        (
            "an inherit-only Allow never counts for the object itself",
            (_wp(AceType.ALLOW, _RBCD, inherited=True, inherit_only=True),),
            False,
        ),
        (
            "an explicit Allow before an inherited Deny stays granted",
            (_wp(AceType.ALLOW, _RBCD), _wp(AceType.DENY, _ACCOUNT_RESTRICTIONS, inherited=True)),
            True,
        ),
        (
            "an explicit Deny before an inherited Allow stays denied",
            (_wp(AceType.DENY, _RBCD), _wp(AceType.ALLOW, _ACCOUNT_RESTRICTIONS, inherited=True)),
            False,
        ),
        (
            "an inherit-only Deny does not block the object's own Allow",
            (_wp(AceType.DENY, _RBCD, inherit_only=True), _wp(AceType.ALLOW, _RBCD)),
            True,
        ),
        (
            "a Deny on the other attribute's set does not block this one",
            (
                _wp(AceType.DENY, _VALIDATED_WRITE_COMPUTER),
                _wp(AceType.ALLOW, _ACCOUNT_RESTRICTIONS),
            ),
            True,
        ),
    ],
)
def test_esc5_scoped_takeover_writes_follow_the_ordered_access_check(
    label: str, aces: tuple[AceEntry, ...], fires: bool
) -> None:
    found = [f.variant for f in detect_esc5(_estate(acls=(_computer(*aces),)))]
    assert found == (["scoped-writeproperty"] if fires else []), label


@pytest.mark.parametrize(
    ("aces", "fires"),
    [
        # An Allow reached before a Deny of the same right stays granted.
        ((_ctrl_ace(right="WriteDacl"), _ctrl_ace(right="WriteDacl", ace_type=AceType.DENY)), True),
        (
            (_ctrl_ace(right="WriteDacl", ace_type=AceType.DENY), _ctrl_ace(right="WriteDacl")),
            False,
        ),
    ],
)
def test_esc4_esc5_object_rights_follow_dacl_order(aces: tuple[AceEntry, ...], fires: bool) -> None:
    tmpl = _template("T", security=aces)
    assert bool(detect_esc4(_estate(templates=(tmpl,)))) is fires
    obj = _pki_acl(AclKind.NTAUTH, security=aces)
    assert bool(detect_esc5(_estate(acls=(obj,)))) is fires


def _deny(right: str) -> AceEntry:
    return _ctrl_ace(right=right, ace_type=AceType.DENY)


_NAME_FLAG_ATTRIBUTE = "ea1dddc4-60ff-416e-8cc0-17cee534bce7"  # msPKI-Certificate-Name-Flag


# Review round 3 (Sol B2): a broad right counts only through the components it
# maps to ([MS-DTYP] ACCESS_MASK generic mapping; GenericWrite = a write of
# every property, GenericAll = every component) that an earlier Deny left in
# effect. A later broad Allow never re-grants a component already denied.
@pytest.mark.parametrize(
    ("label", "aces", "held"),
    [
        (
            "blanket WriteProperty Deny before GenericWrite",
            (_deny("WritePropertyAll"), _ctrl_ace(right="GenericWrite")),
            None,
        ),
        (
            "GenericWrite before a blanket WriteProperty Deny",
            (_ctrl_ace(right="GenericWrite"), _deny("WritePropertyAll")),
            "GenericWrite",
        ),
        (
            "GenericWrite Deny before blanket WriteProperty",
            (_deny("GenericWrite"), _ctrl_ace(right="WritePropertyAll")),
            None,
        ),
        (
            "blanket WriteProperty before a GenericWrite Deny",
            (_ctrl_ace(right="WritePropertyAll"), _deny("GenericWrite")),
            "WritePropertyAll",
        ),
        (
            "GenericWrite Deny before GenericWrite",
            (_deny("GenericWrite"), _ctrl_ace(right="GenericWrite")),
            None,
        ),
        (
            "GenericAll Deny before GenericWrite",
            (_deny("GenericAll"), _ctrl_ace(right="GenericWrite")),
            None,
        ),
        (
            "blanket WriteProperty Deny before GenericAll: control rights remain",
            (_deny("WritePropertyAll"), _ctrl_ace(right="GenericAll")),
            "GenericAll (in effect only: WriteDacl, WriteOwner)",
        ),
        (
            "every control component denied before GenericAll",
            (
                _deny("WriteDacl"),
                _deny("WriteOwner"),
                _deny("GenericWrite"),
                _ctrl_ace(right="GenericAll"),
            ),
            None,
        ),
        (
            "GenericAll before the Denies",
            (
                _ctrl_ace(right="GenericAll"),
                _deny("WriteDacl"),
                _deny("WriteOwner"),
                _deny("GenericWrite"),
            ),
            "GenericAll",
        ),
        (
            "a scoped Deny does not narrow a blanket write (the danger lists are not exhaustive)",
            (
                _deny(f"WriteProperty:{_NAME_FLAG_ATTRIBUTE}"),
                _ctrl_ace(right="GenericWrite"),
            ),
            "GenericWrite",
        ),
    ],
)
def test_broad_rights_count_through_the_components_left_in_effect(
    label: str, aces: tuple[AceEntry, ...], held: str | None
) -> None:
    tmpl = _template("T", security=aces)
    esc4 = [f for f in detect_esc4(_estate(templates=(tmpl,))) if f.variant == "dacl"]
    esc5 = detect_esc5(_estate(acls=(_pki_acl(AclKind.NTAUTH, security=aces),)))
    if held is None:
        assert esc4 == [], label
        assert esc5 == [], label
        return
    (f4,) = esc4
    (f5,) = esc5
    assert f4.detail.startswith(f"trustee hold {held} on the template"), (label, f4.detail)
    assert f5.detail.startswith(f"trustee hold {held} on "), (label, f5.detail)


def test_a_blanket_deny_before_genericwrite_blocks_the_scoped_writes_too() -> None:
    """The scoped variants read the same tree: GenericWrite reaches every
    attribute, and a blanket WriteProperty Deny before it decides them all."""
    aces = (_deny("WritePropertyAll"), _ctrl_ace(right="GenericWrite"))
    assert detect_esc4(_estate(templates=(_template("T", security=aces),))) == []
    computer = replace(_pki_acl(AclKind.CA_COMPUTER, security=aces), owner_sid=DOMAIN_ADMINS_SID)
    assert detect_esc5(_estate(acls=(computer,))) == []


def test_inherit_only_aces_never_grant_on_the_object_itself() -> None:
    io_allow = AceEntry(LOW_PRIV_SID, "Helpdesk", ("GenericAll",), AceType.ALLOW, True, True)
    assert detect_esc5(_estate(acls=(_pki_acl(AclKind.PKS_CONTAINER, security=(io_allow,)),))) == []
    assert detect_esc4(_estate(templates=(_template("T", security=(io_allow,)),))) == []
    io_enroll = AceEntry(LOW_PRIV_SID, "Domain Users", ("Enroll",), AceType.ALLOW, True, True)
    assert detect_esc1(_estate(templates=(_template("T", security=(io_enroll,)),))) == []


def test_esc5_scoped_takeover_writes_by_a_privileged_trustee_are_clean() -> None:
    assert detect_esc5(_estate(acls=(_scoped(_RBCD, sid=DOMAIN_ADMINS_SID),))) == []


def test_esc5_scoped_takeover_writes_count_only_on_the_ca_computer_object() -> None:
    ace = AceEntry(LOW_PRIV_SID, "Helpdesk", (f"WriteProperty:{_RBCD}",), AceType.ALLOW)
    for kind in (AclKind.CA_OBJECT, AclKind.PKS_CONTAINER, AclKind.NTAUTH):
        obj = PkiObjectAcl("CN=X", kind, (ace,), owner_sid=DOMAIN_ADMINS_SID)
        assert detect_esc5(_estate(acls=(obj,))) == [], kind


# --- review round 3 (Sol B1, DeepSeek N1): name-flag readings -----------------


@pytest.mark.parametrize(
    ("version", "superseded"),
    [
        ("0.11.0", True),
        ("0.10.0-fixture", True),
        ("0.12.0", False),
        ("1.0.0", False),
        ("unknown", True),
        ("", True),
        ("garbage", True),
    ],
)
def test_an_unparseable_collector_version_may_have_used_the_superseded_table(
    version: str, superseded: bool
) -> None:
    assert ("template.name_flags" in decoders_superseded(version)) is superseded


def test_superseded_names_are_re_read_through_the_old_table() -> None:
    old = "0.11.0"
    reread = superseded_name_flag_reading
    # 0x1 means the same in both tables.
    assert reread(frozenset({"ENROLLEE_SUPPLIES_SUBJECT"}), None, old) == {
        "ENROLLEE_SUPPLIES_SUBJECT"
    }
    # The old table's SAN name stood for 0x8 (a renewal flag); its DOMAIN_DNS for 0x10000.
    assert reread(frozenset({"ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME"}), None, old) == {
        "OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME"
    }
    assert reread(frozenset({"SUBJECT_ALT_REQUIRE_DOMAIN_DNS"}), None, old) == {
        "ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME"
    }
    assert reread(frozenset({"SUBJECT_REQUIRE_COMMON_NAME", "NOT_A_FLAG"}), None, old) == {
        "SUBJECT_REQUIRE_COMMON_NAME",
        "NOT_A_FLAG",
    }
    # A raw value or the corrected table: there is no other reading.
    assert reread(frozenset({"ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME"}), 0x8, old) is None
    assert reread(frozenset({"ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME"}), None, "0.12.0") is None


def test_every_name_flag_reader_declares_the_flags_it_turns_on() -> None:
    """Without them its verdict could never be uncertain across the decoder
    correction (_name_flags_uncertain compares only the declared flags)."""
    readers = {
        k: d for k, d in CHECKS.items() if d.subject == "template" and "name_flags" in d.fields
    }
    assert readers
    for key, decl in readers.items():
        assert decl.name_flags, key
    assert readers[("ESC1", "")].name_flags == {
        "ENROLLEE_SUPPLIES_SUBJECT",
        "ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME",
    }


@pytest.mark.parametrize(
    ("names", "uncertain"),
    [
        ((), False),
        (("ENROLLEE_SUPPLIES_SUBJECT",), False),
        (("ENROLLEE_SUPPLIES_SUBJECT", "ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME"), False),
        (("ENROLLEE_SUPPLIES_SUBJECT", "SUBJECT_ALT_REQUIRE_DOMAIN_DNS"), False),
        (("SUBJECT_REQUIRE_COMMON_NAME", "SUBJECT_ALT_REQUIRE_UPN"), False),
        (("ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME",), True),
        (("SUBJECT_ALT_REQUIRE_DOMAIN_DNS",), True),
    ],
)
def test_esc1_is_uncertain_only_where_the_readings_disagree_on_its_flags(
    names: tuple[str, ...], uncertain: bool
) -> None:
    tmpl = replace(_template("T", name_flags=names, security=(_enroll_ace(),)), ra_signatures=0)
    base = _estate(templates=(tmpl,))
    estate = replace(base, manifest=replace(base.manifest, collector_version="0.11.0"))
    ev = evaluate(estate, now=NOW)
    (verdict,) = [v for v in ev.verdicts if v.check == "ESC1"]
    assert ev.decoder_uncertain == ({("ESC1", verdict.key)} if uncertain else set())
    findings = [f for f in ev.findings if f.check == "ESC1"]
    for f in findings:
        assert f.evidence_complete is (not uncertain)
        assert ("may be a decoder artifact" in f.detail) is uncertain
        assert "would not let" not in f.detail
    # From 0.12.0 (or with the raw value) nothing is uncertain.
    current = replace(estate, manifest=replace(estate.manifest, collector_version="0.12.0"))
    assert not evaluate(current, now=NOW).decoder_uncertain


# --- review round 2 (Sol B3): the owner's implicit rights ----------------------


def _with_heuristics(estate: Estate, ds_heuristics: str | None) -> Estate:
    return replace(estate, manifest=replace(estate.manifest, ds_heuristics=ds_heuristics))


def _heuristic(char29: str) -> str:
    # dSHeuristics with character 29 set (characters 10 / 20 must be "1" / "2").
    return "000000000100000000020000000" + "0" + char29


@pytest.mark.parametrize(
    ("ds_heuristics", "fires", "complete"),
    [
        (None, True, False),  # not read: the finding stands, evidence incomplete
        ("", True, True),  # attribute not set: every heuristic at its default (0)
        (_heuristic("0"), True, True),
        (_heuristic("2"), True, True),
        (_heuristic("1"), False, True),  # BlockOwnerImplicitRights in force
        (_heuristic("x"), False, True),  # any other character is 1
        ("0000002", True, True),  # shorter than 29 characters: 0
    ],
)
def test_esc5_computer_owner_follows_block_owner_implicit_rights(
    ds_heuristics: str | None, fires: bool, complete: bool
) -> None:
    estate = _with_heuristics(_estate(acls=(_computer(owner=LOW_PRIV_SID),)), ds_heuristics)
    found = [f for f in detect_esc5(estate) if f.variant == "owner"]
    assert bool(found) is fires
    if found:
        assert found[0].evidence_complete is complete
        assert ("dSHeuristics was not read" in found[0].detail) is (not complete)


def test_block_owner_implicit_rights_applies_to_the_computer_object_only() -> None:
    obj = _pki_acl(AclKind.NTAUTH, owner_sid=LOW_PRIV_SID)
    estate = _with_heuristics(_estate(acls=(obj,)), _heuristic("1"))
    assert [f.variant for f in detect_esc5(estate)] == ["owner"]


_OWNER_RIGHTS = "S-1-3-4"


def test_owner_rights_replace_the_owners_implicit_rights() -> None:
    read_only = AceEntry(_OWNER_RIGHTS, "OWNER RIGHTS", ("ReadControl",), AceType.ALLOW)
    for estate in (
        _with_heuristics(_estate(acls=(_computer(read_only, owner=LOW_PRIV_SID),)), ""),
        _estate(acls=(_pki_acl(AclKind.NTAUTH, owner_sid=LOW_PRIV_SID, security=(read_only,)),)),
    ):
        assert detect_esc5(estate) == []
    tmpl = _template("T", owner_sid=LOW_PRIV_SID, security=(read_only,))
    assert detect_esc4(_estate(templates=(tmpl,))) == []


def test_owner_rights_that_grant_control_are_the_owners_finding() -> None:
    control = AceEntry(_OWNER_RIGHTS, "OWNER RIGHTS", ("WriteDacl",), AceType.ALLOW)
    obj = _computer(control, owner=LOW_PRIV_SID)
    # Even with BlockOwnerImplicitRights: the explicit OWNER RIGHTS grant stands.
    (f,) = detect_esc5(_with_heuristics(_estate(acls=(obj,)), _heuristic("1")))
    assert f.variant == "owner" and "OWNER RIGHTS" in f.detail and "WriteDacl" in f.detail
    rbcd = AceEntry(_OWNER_RIGHTS, "", (f"WriteProperty:{_ACCOUNT_RESTRICTIONS}",), AceType.ALLOW)
    (f,) = detect_esc5(_with_heuristics(_estate(acls=(_computer(rbcd, owner=LOW_PRIV_SID),)), ""))
    assert f.variant == "owner" and _RBCD in f.detail
    # With a privileged owner, an OWNER RIGHTS ACE is not a low-privilege grant.
    assert detect_esc5(_estate(acls=(_computer(control, rbcd),))) == []


# A RECONSTRUCTION, not a capture (review round 3, DeepSeek N4): the computer
# class's defaultSecurityDescriptor from [MS-ADSC] 2.21 "Class computer"
# (learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adsc/
# 142185a8-2e23-4628-b002-cf31d57bb37a, page dated 2019-02-14, read 2026-10-14),
# written as the collector would tokenize it. CREATOR OWNER becomes the creator
# (a Domain Admins member's objects are owned by Domain Admins). Exact: the
# full-control ACEs of DA / AO / SY (RPWPCRCCDCLCLORCWOWDSDDTSW = 0xF01FF, which
# .NET names GenericAll), CREATOR OWNER's base rights and its
# (OA;;WP;4c164200-20c0-11d0-a768-00aa006e0529;;CO) Account Restrictions write -
# the ACE that decides ESC5 - and the property writes of Cert Publishers and
# SELF. Simplified where no ESC5 verdict can change: the validated writes (SW)
# and the Everyone / S-1-5-32-560 rights lose their object GUIDs, and Print
# Operators' CCDC its printQueue class. DeepSeek N5 (round 2): this older
# default must not fire.
#
# The live re-check of 2026-10-14 (docs/live-validation-plan.md, B3b) recorded
# the real descriptor of a Server 2025-generation domain: the same, plus an
# INHERITED ``SELF: ReadProperty, WriteProperty:3f78c3e5...`` (the RBCD
# attribute) on every computer object. It is not in the class's
# defaultSecurityDescriptor; it arrives from the domain head. Owner decision
# 2026-10-16: that ACE fires ESC5 scoped-writeproperty at CRITICAL with its own
# wording (the coerce-and-relay path; LDAP signing / channel binding is the
# mitigation and is not read), so a CA host of that generation reports it.
_ACCOUNT_OPERATORS = "S-1-5-32-548"
_CERT_PUBLISHERS = "S-1-5-21-1111111111-2222222222-3333333333-517"
_SELF = "S-1-5-10"


def _default_computer_dacl(creator: str) -> tuple[AceEntry, ...]:
    def ace(sid: str, *rights: str) -> AceEntry:
        # Named, as the collector's Translate() names every resolvable trustee: an
        # unnamed domain SID on the CA computer object is treated as unresolved.
        return AceEntry(sid, "trustee", rights, AceType.ALLOW)

    return (
        ace(DOMAIN_ADMINS_SID, "GenericAll"),
        ace(_ACCOUNT_OPERATORS, "GenericAll"),
        ace("S-1-5-18", "GenericAll"),
        ace(
            creator,
            "ReadProperty",
            "AllExtendedRights",
            "ListChildren",
            "ListObject",
            "ReadControl",
            "Delete",
            "DeleteTree",
        ),
        ace(creator, f"WriteProperty:{_ACCOUNT_RESTRICTIONS}"),
        ace("S-1-5-11", "ReadProperty", "ListChildren", "ListObject", "ReadControl"),
        ace("S-1-1-0", "ExtendedRight"),
        ace(_SELF, "CreateChild", "DeleteChild"),
        ace("S-1-5-32-550", "CreateChild", "DeleteChild"),
        ace(_CERT_PUBLISHERS, "ReadProperty", "WriteProperty:bf967a7f-0de6-11d0-a285-00aa003049e2"),
        ace(_SELF, "Self"),
        ace(_SELF, "ReadProperty", "WriteProperty:77b5b886-944a-11d1-aebd-0000f80367c1"),
        ace(creator, "Self"),
        ace(creator, "WriteProperty:3e0abfd0-126a-11d0-a060-00aa006c33ed"),
        ace(creator, "WriteProperty:5f202010-79a5-11d0-9020-00c04fc2d4cf"),
        ace(creator, "WriteProperty:bf967950-0de6-11d0-a285-00aa003049e2"),
        ace(creator, "WriteProperty:bf967953-0de6-11d0-a285-00aa003049e2"),
        ace("S-1-5-32-560", "ReadProperty"),
    )


def _inherited_self_rbcd() -> AceEntry:
    return AceEntry(
        _SELF,
        "NT AUTHORITY\\SELF",
        ("ReadProperty", f"WriteProperty:{_RBCD}"),
        AceType.ALLOW,
        inherited=True,
    )


def test_the_ms_adsc_default_computer_dacl_of_an_admin_joined_ca_host_is_clean() -> None:
    # The older default, without the SELF RBCD ACE: no finding.
    obj = _computer(*_default_computer_dacl(DOMAIN_ADMINS_SID))
    assert detect_esc5(_with_heuristics(_estate(acls=(obj,)), "")) == []


def test_the_2025_generation_default_computer_dacl_fires_the_self_rbcd_path() -> None:
    obj = _computer(*_default_computer_dacl(DOMAIN_ADMINS_SID), _inherited_self_rbcd())
    (f,) = detect_esc5(_with_heuristics(_estate(acls=(obj,)), ""))
    assert (f.check, f.variant, f.severity) == ("ESC5", "scoped-writeproperty", Severity.CRITICAL)
    _assert_self_rbcd_wording(f.detail)
    assert "inherited" in f.detail  # the fix is at the parent container, not on this object


def _assert_self_rbcd_wording(detail: str, *, alone: bool = True) -> None:
    assert "NT AUTHORITY\\SELF" in detail
    assert "msDS-AllowedToActOnBehalfOfOtherIdentity" in detail
    assert "coerced and relayed to LDAP" in detail
    assert "take it over" in detail
    assert "LDAP signing and LDAP channel binding" in detail
    assert "cannot be cleared from the export" in detail
    if alone:
        assert "Remove the delegated write" not in detail


def test_self_alone_on_the_rbcd_attribute_is_critical_with_its_own_wording() -> None:
    ace = AceEntry(_SELF, "NT AUTHORITY\\SELF", (f"WriteProperty:{_RBCD}",), AceType.ALLOW)
    (f,) = detect_esc5(_estate(acls=(_computer(ace),)))
    assert (f.variant, f.severity) == ("scoped-writeproperty", Severity.CRITICAL)
    _assert_self_rbcd_wording(f.detail)
    assert "inherited" not in f.detail  # an explicit ACE: nothing to say about a parent


def test_self_through_the_account_restrictions_set_gets_the_self_wording() -> None:
    ace = AceEntry(_SELF, "", (f"WriteProperty:{_ACCOUNT_RESTRICTIONS}",), AceType.ALLOW)
    (f,) = detect_esc5(_estate(acls=(_computer(ace),)))
    assert f.severity == Severity.CRITICAL
    _assert_self_rbcd_wording(f.detail)


def test_self_and_a_low_priv_group_are_both_reported() -> None:
    self_ace = _inherited_self_rbcd()
    group = AceEntry(LOW_PRIV_SID, "Helpdesk", (f"WriteProperty:{_RBCD}",), AceType.ALLOW)
    (f,) = detect_esc5(_estate(acls=(_computer(self_ace, group),)))
    assert f.severity == Severity.CRITICAL
    assert "Helpdesk hold a property-scoped WriteProperty" in f.detail
    assert "Remove the delegated write" in f.detail  # the group's general wording
    _assert_self_rbcd_wording(f.detail, alone=False)  # and SELF's own, same finding


def test_self_on_key_credential_link_keeps_the_general_wording() -> None:
    # SELF's own wording is the RBCD relay path; another takeover attribute is not it.
    ace = AceEntry(
        _SELF, "NT AUTHORITY\\SELF", (f"WriteProperty:{_KEY_CREDENTIAL_LINK}",), AceType.ALLOW
    )
    (f,) = detect_esc5(_estate(acls=(_computer(ace),)))
    assert "coerced and relayed" not in f.detail
    assert "msDS-KeyCredentialLink" in f.detail and "Remove the delegated write" in f.detail


def test_an_inherit_only_self_rbcd_ace_does_not_apply_to_the_object() -> None:
    ace = AceEntry(
        _SELF,
        "NT AUTHORITY\\SELF",
        (f"WriteProperty:{_RBCD}",),
        AceType.ALLOW,
        inherited=True,
        inherit_only=True,
    )
    assert detect_esc5(_estate(acls=(_computer(ace),))) == []


def test_the_self_wording_changes_no_finding_identity() -> None:
    # Same check and variant as before the wording change: diff pairs on
    # (check, variant, object), so a SELF finding from an earlier export is the
    # same finding (a content change at most), never resolved plus new.
    ace = AceEntry(_SELF, "", (f"WriteProperty:{_RBCD}",), AceType.ALLOW)
    (f,) = detect_esc5(_estate(acls=(_computer(ace),)))
    assert (f.check, f.variant) == ("ESC5", "scoped-writeproperty")


_DANGLING_SID = "S-1-5-21-1111111111-2222222222-3333333333-4683"


def _assert_unresolved_wording(detail: str) -> None:
    assert "did not resolve a friendly name for the trustee SID" in detail
    assert "deleted principal" in detail and "foreign or trusted domain" in detail
    assert "lookup that failed at collection time" in detail
    assert "takeover path" in detail and "hygiene debt" in detail
    assert "Verify the SID's domain and retry name resolution" in detail
    assert "collection artefact" in detail
    assert "remove the ACE" in detail


def test_an_unresolved_trustee_sid_with_generic_all_is_critical_and_says_so() -> None:
    ace = AceEntry(_DANGLING_SID, "", ("GenericAll",), AceType.ALLOW)
    (f,) = detect_esc5(_estate(acls=(_computer(ace),)))
    assert (f.variant, f.severity) == ("dacl", Severity.CRITICAL)
    assert _DANGLING_SID in f.detail
    assert "GenericAll" in f.detail
    _assert_unresolved_wording(f.detail)


def test_a_resolved_trustee_keeps_the_general_dacl_wording() -> None:
    ace = AceEntry(LOW_PRIV_SID, "Helpdesk", ("GenericAll",), AceType.ALLOW)
    (f,) = detect_esc5(_estate(acls=(_computer(ace),)))
    assert "did not resolve a friendly name" not in f.detail
    assert f.detail.endswith("Remove the delegated control.")


def test_resolved_and_unresolved_trustees_are_both_named() -> None:
    named = AceEntry(LOW_PRIV_SID, "Helpdesk", ("GenericAll",), AceType.ALLOW)
    dangling = AceEntry(_DANGLING_SID, "", ("GenericAll",), AceType.ALLOW)
    (f,) = detect_esc5(_estate(acls=(_computer(named, dangling),)))
    assert "Helpdesk hold" in f.detail and "Remove the delegated control." in f.detail
    assert _DANGLING_SID in f.detail
    _assert_unresolved_wording(f.detail)


def test_the_unresolved_wording_is_for_the_ca_computer_object_only() -> None:
    # Owner decision 2026-10-16 was on the CA computer object: other PKI objects
    # keep the general wording (identical text, severity unchanged).
    ace = AceEntry(_DANGLING_SID, "", ("GenericAll",), AceType.ALLOW)
    (f,) = detect_esc5(_estate(acls=(_pki_acl(AclKind.NTAUTH, security=(ace,)),)))
    assert "did not resolve a friendly name" not in f.detail


def test_the_default_computer_dacl_of_a_user_joined_ca_host_is_an_rbcd_path() -> None:
    """Joined by an ordinary user (MachineAccountQuota): the default SD's
    CREATOR OWNER write of Account Restrictions goes to that user, who can then
    set msDS-AllowedToActOnBehalfOfOtherIdentity - a real takeover path."""
    obj = _computer(*_default_computer_dacl(LOW_PRIV_SID))
    found = detect_esc5(_with_heuristics(_estate(acls=(obj,)), ""))
    assert [(f.variant, f.severity) for f in found] == [("scoped-writeproperty", Severity.CRITICAL)]
    assert "msDS-AllowedToActOnBehalfOfOtherIdentity" in found[0].detail


def test_esc5_default_privileged_aces_on_the_ca_computer_object_are_clean() -> None:
    aces = tuple(
        AceEntry(sid, "trustee", ("GenericAll",), AceType.ALLOW)
        for sid in (DOMAIN_ADMINS_SID, "S-1-5-18", "S-1-5-32-548")
    )
    assert detect_esc5(_estate(acls=(_computer(*aces),))) == []


# --- ESC8 -----------------------------------------------------------------


def test_esc8_web_enrollment_http_ntlm_is_high() -> None:
    # /certsrv over HTTP with NTLM and no EPA — the textbook relay case.
    estate = _estate(endpoints=(_endpoint(),))
    findings = detect_esc8(estate)
    assert len(findings) == 1
    assert findings[0].check == "ESC8"
    assert findings[0].severity == Severity.HIGH
    assert "cleartext HTTP" in findings[0].detail


def test_esc8_https_only_no_epa_negotiate_is_medium() -> None:
    # HTTPS-only, Negotiate (no explicit NTLM), EPA off -> weaker (MEDIUM).
    estate = _estate(
        endpoints=(
            _endpoint(
                transports=("https",),
                ssl_required=True,
                auth_providers=("negotiate",),
                epa=EpaPolicy.NONE,
            ),
        )
    )
    findings = detect_esc8(estate)
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


def test_esc8_epa_allow_distinct_from_none_in_detail() -> None:
    # WI-035: EPA 'allow' (honored only if the client offers it) and 'none' (not
    # honored) are both flagged, but the detail distinguishes the risk level so
    # an operator can prioritize. ('unknown' is not evaluated: see below.)
    for epa, needle in (
        (EpaPolicy.ALLOW, "allow"),
        (EpaPolicy.NONE, "none"),
    ):
        estate = _estate(
            endpoints=(
                _endpoint(
                    transports=("https",),
                    ssl_required=True,
                    auth_providers=("negotiate",),
                    epa=epa,
                ),
            )
        )
        findings = detect_esc8(estate)
        assert len(findings) == 1
        assert needle in findings[0].detail.lower()


def test_esc8_https_only_explicit_ntlm_no_epa_is_high() -> None:
    estate = _estate(
        endpoints=(
            _endpoint(
                transports=("https",),
                ssl_required=True,
                auth_providers=("negotiate", "ntlm"),
                epa=EpaPolicy.NONE,
            ),
        )
    )
    assert detect_esc8(estate)[0].severity == Severity.HIGH


def test_esc8_mitigated_when_epa_required_and_https_only() -> None:
    estate = _estate(
        endpoints=(
            _endpoint(transports=("https",), ssl_required=True, epa=EpaPolicy.REQUIRE),
        )
    )
    assert detect_esc8(estate) == []


def test_esc8_http_open_flagged_even_with_epa_required() -> None:
    # EPA Require does not help if the endpoint is still reachable over HTTP.
    estate = _estate(endpoints=(_endpoint(epa=EpaPolicy.REQUIRE),))
    assert detect_esc8(estate)[0].severity == Severity.HIGH


# --- ESC8 with unread IIS settings (live run 2026-10-13) --------------------
# Collector 0.11.0 exported a Require / Ssl,Ssl128 endpoint as epa none and
# ssl_required false. An unread value is now never "off": the endpoint is
# flagged only when what was read opens the relay path, clean when both
# settings close it, and otherwise undecided (not evaluated, with a note).


def _esc8_states(estate: Estate) -> list[str]:
    return [v.state for v in evaluate(estate, now=NOW).verdicts if v.check == "ESC8"]


def test_esc8_live_d3_epa_require_and_ssl_required_is_clean() -> None:
    # The live estate's true configuration: HTTP still bound on the site, but
    # sslFlags Ssl (HTTPS required for the app) and tokenChecking Require.
    ep = _endpoint(ssl_required=True, epa=EpaPolicy.REQUIRE)
    estate = _estate(endpoints=(ep,))
    assert detect_esc8(estate) == []
    assert _esc8_states(estate) == ["clean"]


def test_esc8_fires_when_epa_is_off_even_https_only() -> None:
    for epa in (EpaPolicy.NONE, EpaPolicy.ALLOW):
        ep = _endpoint(ssl_required=True, epa=epa)
        findings = detect_esc8(_estate(endpoints=(ep,)))
        assert [f.check for f in findings] == ["ESC8"]
        assert findings[0].severity == Severity.HIGH  # explicit NTLM provider


@pytest.mark.parametrize(
    "unread",
    [{"epa"}, {"ssl_required"}, {"epa", "ssl_required"}],
)
def test_esc8_is_not_evaluated_when_the_deciding_setting_was_not_read(unread: set[str]) -> None:
    # EPA Require + SSL required is clean; with either unread nothing decides it.
    ep = replace(
        _endpoint(ssl_required=True, epa=EpaPolicy.REQUIRE),
        unobtained=frozenset(unread),
    )
    estate = _estate(endpoints=(ep,))
    findings = detect_esc8(estate)
    assert "ESC8" not in {f.check for f in findings}
    notes = [f for f in findings if f.check == "ENROLLMENT_ENDPOINTS_NOT_EVALUATED"]
    assert len(notes) == 1 and notes[0].subject == "/CertSrv"
    if "epa" in unread:
        assert "Extended Protection" in notes[0].detail
    if "ssl_required" in unread:
        assert "sslFlags" in notes[0].detail
    assert _esc8_states(estate) == ["undecided"]


def test_esc8_epa_unknown_token_is_not_evaluated() -> None:
    ep = _endpoint(ssl_required=True, epa=EpaPolicy.UNKNOWN)
    estate = _estate(endpoints=(ep,))
    assert [f.check for f in detect_esc8(estate)] == ["ENROLLMENT_ENDPOINTS_NOT_EVALUATED"]
    assert _esc8_states(estate) == ["undecided"]


def test_esc8_unread_epa_still_fires_when_http_is_open() -> None:
    # What was read already opens the relay path: cleartext HTTP.
    ep = replace(_endpoint(ssl_required=False), unobtained=frozenset({"epa"}))
    findings = detect_esc8(_estate(endpoints=(ep,)))
    assert [f.check for f in findings] == ["ESC8"]
    assert "Extended Protection setting was not read" in findings[0].detail


def test_esc8_unread_ssl_flags_fires_when_epa_is_off() -> None:
    ep = replace(
        _endpoint(auth_providers=("negotiate",), epa=EpaPolicy.NONE),
        unobtained=frozenset({"ssl_required"}),
    )
    findings = detect_esc8(_estate(endpoints=(ep,)))
    assert [f.check for f in findings] == ["ESC8"]
    # HTTP that may be open counts as open: HIGH, not the HTTPS-only MEDIUM.
    assert findings[0].severity == Severity.HIGH
    assert "sslFlags was not read" in findings[0].detail


def test_esc8_unread_ssl_flags_does_not_matter_without_an_http_binding() -> None:
    ep = replace(
        _endpoint(transports=("https",), epa=EpaPolicy.REQUIRE),
        unobtained=frozenset({"ssl_required"}),
    )
    estate = _estate(endpoints=(ep,))
    assert detect_esc8(estate) == []
    assert _esc8_states(estate) == ["clean"]


def test_esc8_unread_settings_on_a_kerberos_only_or_no_auth_endpoint_need_no_note() -> None:
    for ep in (
        _endpoint(auth_providers=("kerberos",), epa=EpaPolicy.UNKNOWN),
        _endpoint(windows_auth=False, epa=EpaPolicy.UNKNOWN),
        _endpoint(kind=EndpointKind.NDES, epa=EpaPolicy.UNKNOWN),
    ):
        assert detect_esc8(_estate(endpoints=(ep,))) == []


def test_esc8_kerberos_only_not_flagged() -> None:
    estate = _estate(endpoints=(_endpoint(auth_providers=("kerberos",)),))
    assert detect_esc8(estate) == []


def test_esc8_no_windows_auth_not_flagged() -> None:
    estate = _estate(endpoints=(_endpoint(windows_auth=False),))
    assert detect_esc8(estate) == []


def test_esc8_ndes_not_flagged() -> None:
    estate = _estate(endpoints=(_endpoint(kind=EndpointKind.NDES),))
    assert detect_esc8(estate) == []


def test_esc8_ces_endpoint_flagged() -> None:
    estate = _estate(endpoints=(_endpoint(kind=EndpointKind.CES, name="/CES"),))
    findings = detect_esc8(estate)
    assert len(findings) == 1
    assert findings[0].subject == "/CES"


def test_esc8_degrades_when_pass_skipped() -> None:
    estate = _estate(endpoints=(), skipped_passes=("enrollment-endpoints",))
    findings = detect_esc8(estate)
    assert len(findings) == 1
    assert findings[0].check == "ENROLLMENT_ENDPOINTS_NOT_EVALUATED"
    assert findings[0].severity == Severity.INFO


def test_esc8_clean_when_pass_ran_and_no_endpoints() -> None:
    assert detect_esc8(_estate(endpoints=())) == []


def test_run_all_includes_esc8() -> None:
    estate = _estate(endpoints=(_endpoint(),))
    assert "ESC8" in {f.check for f in run_all(estate)}


# --- ESC5 -----------------------------------------------------------------


def test_esc5_ntauth_writable_is_critical() -> None:
    estate = _estate(
        acls=(_pki_acl(AclKind.NTAUTH, security=(_ctrl_ace(right="WriteDacl"),)),),
    )
    findings = detect_esc5(estate)
    assert len(findings) == 1
    assert findings[0].check == "ESC5"
    assert findings[0].severity == Severity.CRITICAL
    assert "NTAuthCertificates" in findings[0].detail
    assert "WriteDacl" in findings[0].detail


def test_esc5_ca_object_writable_is_critical() -> None:
    estate = _estate(acls=(_pki_acl(AclKind.CA_OBJECT, security=(_ctrl_ace(right="GenericAll"),)),))
    findings = detect_esc5(estate)
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


def test_esc5_container_writable_is_high() -> None:
    for kind in (AclKind.PKS_CONTAINER, AclKind.AIA, AclKind.CDP):
        estate = _estate(acls=(_pki_acl(kind, security=(_ctrl_ace(right="GenericWrite"),)),))
        findings = detect_esc5(estate)
        assert len(findings) == 1, kind
        assert findings[0].severity == Severity.HIGH, kind


def test_esc5_not_flagged_for_high_priv_trustee() -> None:
    estate = _estate(
        acls=(_pki_acl(AclKind.NTAUTH, security=(_ctrl_ace(HIGH_PRIV_SID, right="WriteDacl"),)),),
    )
    assert detect_esc5(estate) == []


def test_esc5_not_flagged_for_read_or_enroll_rights() -> None:
    estate = _estate(
        acls=(
            _pki_acl(
                AclKind.NTAUTH,
                security=(_ctrl_ace(right="ReadProperty"), _ctrl_ace(right="Enroll")),
            ),
        ),
    )
    assert detect_esc5(estate) == []


def test_esc5_not_flagged_for_scoped_writeproperty() -> None:
    # A property-scoped WriteProperty (non-blanket) is not treated as control,
    # mirroring ESC4; only WritePropertyAll / Generic* / WriteDacl / WriteOwner.
    estate = _estate(
        acls=(_pki_acl(AclKind.NTAUTH, security=(_ctrl_ace(right="WriteProperty"),)),),
    )
    assert detect_esc5(estate) == []


def test_esc5_writepropertyall_is_flagged() -> None:
    estate = _estate(
        acls=(_pki_acl(AclKind.CA_OBJECT, security=(_ctrl_ace(right="WritePropertyAll"),)),),
    )
    assert len(detect_esc5(estate)) == 1


def test_esc5_deny_ace_ignored() -> None:
    estate = _estate(
        acls=(
            _pki_acl(
                AclKind.NTAUTH,
                security=(_ctrl_ace(right="WriteDacl", ace_type=AceType.DENY),),
            ),
        ),
    )
    assert detect_esc5(estate) == []


def test_esc5_clean_when_pass_ran_and_no_dangerous_aces() -> None:
    estate = _estate(acls=(_pki_acl(AclKind.NTAUTH, security=(_ctrl_ace(right="ReadProperty"),)),))
    assert detect_esc5(estate) == []


def test_esc5_degrades_when_pass_skipped() -> None:
    estate = _estate(acls=(), skipped_passes=("pki-acls",))
    findings = detect_esc5(estate)
    assert len(findings) == 1
    assert findings[0].check == "PKI_ACL_NOT_EVALUATED"
    assert findings[0].severity == Severity.INFO


def test_esc5_subject_falls_back_to_kind_when_dn_empty() -> None:
    estate = _estate(
        acls=(_pki_acl(AclKind.NTAUTH, dn="", security=(_ctrl_ace(right="WriteOwner"),)),),
    )
    findings = detect_esc5(estate)
    assert len(findings) == 1
    assert findings[0].subject == AclKind.NTAUTH.value


def test_esc5_owner_based_control_flagged() -> None:
    # A low-priv OWNER of an NTAuth object can rewrite the DACL to grant itself
    # control — an ESC5 path the DACL-only check misses (WI-019). NTAuth is
    # CRITICAL (full-trust primitive).
    acl = _pki_acl(AclKind.NTAUTH, security=(), owner_sid=LOW_PRIV_SID)
    findings = detect_esc5(_estate(acls=(acl,)))
    assert len(findings) == 1
    assert findings[0].check == "ESC5"
    assert findings[0].severity == Severity.CRITICAL
    assert "owner" in findings[0].detail.lower()


def test_esc5_owner_high_priv_not_flagged() -> None:
    acl = _pki_acl(AclKind.AIA, security=(), owner_sid=HIGH_PRIV_SID)
    assert detect_esc5(_estate(acls=(acl,))) == []


def test_esc5_owner_empty_not_flagged() -> None:
    # No owner captured -> owner-based control is skipped (a known gap, not a
    # false positive).
    acl = _pki_acl(AclKind.AIA, security=(), owner_sid="")
    assert detect_esc5(_estate(acls=(acl,))) == []


def test_run_all_includes_esc5() -> None:
    estate = _estate(acls=(_pki_acl(AclKind.NTAUTH, security=(_ctrl_ace(right="WriteDacl"),)),))
    checks = {f.check for f in run_all(estate)}
    assert "ESC5" in checks


def test_run_all_includes_esc11_and_esc13() -> None:
    # Lock the wiring: both new detectors are reachable through run_all.
    tmpl = _template(
        "LinkedPolicy",
        ekus=(CLIENT_AUTH,),
        name_flags=(),
        issuance_policy_oids=(POLICY_OID,),
        security=(_enroll_ace(),),
    )
    estate = _estate(
        cas=(_ca("RelayCA", interface_flags=()),),
        templates=(tmpl,),
        oids=(IssuanceOid(POLICY_OID, "L", DOMAIN_ADMINS_SID),),
    )
    checks = {f.check for f in run_all(estate)}
    assert "ESC11" in checks
    assert "ESC13" in checks


def test_severity_rank_is_worst_first_not_alphabetical() -> None:
    # run_all sorts by SEVERITY_RANK; a StrEnum would otherwise sort
    # alphabetically as critical,high,info,low,medium (INFO before MEDIUM/LOW).
    # This locks the explicit rank against such a regression.
    from adcs_lens.model import SEVERITY_RANK

    worst_first = [
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
    ]
    assert list(SEVERITY_RANK.keys()) == worst_first
    # Ordering the enum members by the rank must NOT match naive sorted() order.
    by_rank = sorted(worst_first, key=SEVERITY_RANK.__getitem__)
    assert by_rank == worst_first
    # If this ever fails, Severity gained a natural order — revisit the rank.
    assert by_rank != sorted(worst_first)


def test_run_all_puts_info_degradation_last() -> None:
    # Real-output smoke: an INFO degradation note must sort after every actionable
    # finding, not between HIGH and (future) MEDIUM.
    cert = CertLifecycle(
        "CN=Soon", CertKind.ISSUING_CA, NOW, NOW + timedelta(days=30), "sha256", 2048, "rsa"
    )
    estate = _estate(
        templates=(_template("Vuln", security=(_enroll_ace(),)),),  # ESC1 CRITICAL
        cas=(_ca("CA", certs=(cert,)),),  # cert-expiry HIGH
        skipped_passes=("ca-security",),  # ESC7 INFO degradation note
    )
    findings = run_all(estate, now=NOW)
    assert findings[-1].severity == Severity.INFO
    assert findings[0].severity == Severity.CRITICAL


# --- Deny-ACE precedence --------------------------------------------------


def test_esc1_suppressed_when_same_right_denied() -> None:
    allow = _enroll_ace(right="Enroll")
    deny = _ctrl_ace(right="Enroll", ace_type=AceType.DENY)
    assert detect_esc1(_estate(templates=(_template("T", security=(deny, allow)),))) == []


def test_esc1_suppressed_by_broad_deny() -> None:
    allow = _enroll_ace(right="Enroll")
    deny = _ctrl_ace(right="GenericAll", ace_type=AceType.DENY)
    assert detect_esc1(_estate(templates=(_template("T", security=(deny, allow)),))) == []


def test_esc1_not_suppressed_when_unrelated_right_denied() -> None:
    allow = _enroll_ace(right="Enroll")
    deny = _ctrl_ace(right="WriteDacl", ace_type=AceType.DENY)
    findings = detect_esc1(_estate(templates=(_template("T", security=(allow, deny)),)))
    assert len(findings) == 1
    assert findings[0].check == "ESC1"


def test_esc1_not_suppressed_when_autoenroll_denied() -> None:
    # AutoEnroll is a distinct extended right; denying it must not block Enroll.
    allow = _enroll_ace(right="Enroll")
    deny = _ctrl_ace(right="AutoEnroll", ace_type=AceType.DENY)
    findings = detect_esc1(_estate(templates=(_template("T", security=(allow, deny)),)))
    assert len(findings) == 1
    assert findings[0].check == "ESC1"


def test_esc1_specific_deny_beats_broad_allow() -> None:
    allow = _enroll_ace(right="GenericAll")
    deny = _ctrl_ace(right="Enroll", ace_type=AceType.DENY)
    assert detect_esc1(_estate(templates=(_template("T", security=(deny, allow)),))) == []


def test_esc1_broad_allow_survives_unrelated_deny() -> None:
    allow = _enroll_ace(right="GenericAll")
    deny = _ctrl_ace(right="WriteDacl", ace_type=AceType.DENY)
    findings = detect_esc1(_estate(templates=(_template("T", security=(allow, deny)),)))
    assert len(findings) == 1
    assert findings[0].check == "ESC1"


def test_esc4_suppressed_when_control_right_denied() -> None:
    allow = _enroll_ace(right="WriteDacl")
    deny = _ctrl_ace(right="WriteDacl", ace_type=AceType.DENY)
    assert detect_esc4(_estate(templates=(_template("T", security=(deny, allow)),))) == []


def test_esc4_not_suppressed_when_only_one_control_right_denied() -> None:
    allow = _enroll_ace(right="GenericAll")
    deny = _ctrl_ace(right="WriteDacl", ace_type=AceType.DENY)
    findings = detect_esc4(_estate(templates=(_template("T", security=(allow, deny)),)))
    assert len(findings) == 1
    assert findings[0].check == "ESC4"
    assert "WriteDacl" not in findings[0].detail
    assert "GenericAll" in findings[0].detail


def test_esc7_suppressed_when_manageca_denied() -> None:
    allow = _enroll_ace(right="ManageCA")
    deny = _ctrl_ace(right="ManageCA", ace_type=AceType.DENY)
    assert detect_esc7(_estate(cas=(_ca("CA", security=(allow, deny)),))) == []


def test_esc7_suppressed_by_broad_deny() -> None:
    allow = _enroll_ace(right="ManageCA")
    deny = _ctrl_ace(right="GenericAll", ace_type=AceType.DENY)
    assert detect_esc7(_estate(cas=(_ca("CA", security=(allow, deny)),))) == []


def test_esc7_not_suppressed_when_managecertificates_denied() -> None:
    allow = _enroll_ace(right="ManageCA")
    deny = _ctrl_ace(right="ManageCertificates", ace_type=AceType.DENY)
    findings = detect_esc7(_estate(cas=(_ca("CA", security=(allow, deny)),)))
    assert len(findings) == 1
    assert findings[0].check == "ESC7"
    assert findings[0].severity == Severity.CRITICAL


# --- hygiene: weak signing algorithm ---------------------------------------


def test_weak_signing_sha1_is_high() -> None:
    estate = _estate(cas=(_ca("OldCA", certs=(_cert("CN=Old", sig_alg="sha1"),)),))
    findings = detect_weak_signing(estate)
    assert len(findings) == 1
    assert findings[0].check == "WEAK_SIG_ALG"
    assert findings[0].severity == Severity.HIGH
    assert "sha1" in findings[0].detail.lower()


def test_weak_signing_md5_is_critical() -> None:
    estate = _estate(cas=(_ca("AncientCA", certs=(_cert("CN=Ancient", sig_alg="md5"),)),))
    findings = detect_weak_signing(estate)
    assert len(findings) == 1
    assert findings[0].check == "WEAK_SIG_ALG"
    assert findings[0].severity == Severity.CRITICAL
    assert "md5" in findings[0].detail.lower()


def test_weak_signing_case_insensitive() -> None:
    estate = _estate(cas=(_ca("OldCA", certs=(_cert("CN=Old", sig_alg="SHA1"),)),))
    assert len(detect_weak_signing(estate)) == 1


def test_weak_signing_ignores_sha256() -> None:
    estate = _estate(cas=(_ca("GoodCA", certs=(_cert("CN=Good", sig_alg="sha256"),)),))
    assert detect_weak_signing(estate) == []


def test_weak_signing_does_not_false_positive_on_sha256withrsa() -> None:
    # "sha256WithRSAEncryption" must not match the sha1 branch via substring.
    estate = _estate(
        cas=(_ca("ModCA", certs=(_cert("CN=Mod", sig_alg="sha256WithRSAEncryption"),)),)
    )
    assert detect_weak_signing(estate) == []


def test_weak_signing_flags_sha1withrsa() -> None:
    estate = _estate(
        cas=(_ca("OldCA", certs=(_cert("CN=Old", sig_alg="sha1WithRSAEncryption"),)),)
    )
    findings = detect_weak_signing(estate)
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


def test_weak_signing_degrades_without_certs() -> None:
    estate = _estate(
        cas=(_ca("OldCA", certs=(_cert("CN=Old", sig_alg="sha1"),)),),
        certs_parsed=False,
    )
    assert detect_weak_signing(estate) == []


# --- hygiene: weak key length ----------------------------------------------


def test_weak_key_size_1024_bit_ca_is_high() -> None:
    estate = _estate(cas=(_ca("CA", certs=(_cert("CN=C", key_bits=1024),)),))
    findings = detect_weak_key_size(estate)
    ca_findings = [f for f in findings if f.check == "WEAK_KEY_SIZE"]
    assert len(ca_findings) == 1
    assert ca_findings[0].severity == Severity.HIGH


def test_weak_key_size_under_1024_is_critical() -> None:
    estate = _estate(cas=(_ca("CA", certs=(_cert("CN=C", key_bits=512),)),))
    findings = detect_weak_key_size(estate)
    ca_findings = [f for f in findings if f.check == "WEAK_KEY_SIZE"]
    assert len(ca_findings) == 1
    assert ca_findings[0].severity == Severity.CRITICAL


def test_weak_key_size_between_1024_and_2048_is_medium() -> None:
    estate = _estate(cas=(_ca("CA", certs=(_cert("CN=C", key_bits=1536),)),))
    findings = detect_weak_key_size(estate)
    ca_findings = [f for f in findings if f.check == "WEAK_KEY_SIZE"]
    assert len(ca_findings) == 1
    assert ca_findings[0].severity == Severity.MEDIUM


def test_weak_key_size_skips_ecdsa_keys() -> None:
    estate = _estate(
        cas=(_ca("CA", certs=(_cert("CN=EC", key_bits=256, key_alg="ecdsa"),)),)
    )
    findings = detect_weak_key_size(estate)
    assert all(f.check != "WEAK_KEY_SIZE" for f in findings)


def test_weak_key_size_skips_dsa_keys() -> None:
    estate = _estate(
        cas=(_ca("CA", certs=(_cert("CN=DSA", key_bits=1024, key_alg="dsa"),)),)
    )
    findings = detect_weak_key_size(estate)
    assert all(f.check != "WEAK_KEY_SIZE" for f in findings)


def test_weak_key_size_2048_or_strong_is_clean() -> None:
    estate = _estate(
        cas=(_ca("CA", certs=(_cert("CN=C", key_bits=2048), _cert("CN=D", key_bits=4096))),)
    )
    assert detect_weak_key_size(estate) == []


def test_weak_key_size_degrades_ca_part_without_certs() -> None:
    estate = _estate(
        cas=(_ca("CA", certs=(_cert("CN=C", key_bits=512),)),),
        templates=(_template("T", min_key_size=512),),
        certs_parsed=False,
    )
    findings = detect_weak_key_size(estate)
    assert all(f.check == "WEAK_TEMPLATE_KEY_SIZE" for f in findings)


def test_weak_template_key_size_high_below_1024() -> None:
    estate = _estate(templates=(_template("Weak", min_key_size=512),))
    findings = detect_weak_key_size(estate)
    assert len(findings) == 1
    assert findings[0].check == "WEAK_TEMPLATE_KEY_SIZE"
    assert findings[0].severity == Severity.HIGH


def test_weak_template_key_size_medium_1024() -> None:
    estate = _estate(templates=(_template("Weak", min_key_size=1024),))
    findings = detect_weak_key_size(estate)
    assert len(findings) == 1
    assert findings[0].check == "WEAK_TEMPLATE_KEY_SIZE"
    assert findings[0].severity == Severity.MEDIUM


def test_weak_template_key_size_clean_at_2048() -> None:
    assert detect_weak_key_size(_estate(templates=(_template("OK", min_key_size=2048),))) == []


def test_weak_template_key_size_skips_ecdsa_by_csp() -> None:
    # An ECDSA template (CSP indicates EC) with a P-256 curve size (256) must NOT
    # fire WEAK_TEMPLATE_KEY_SIZE — 256 is a curve size, not an RSA bit length
    # (WI-025).
    tmpl = _template("Ecdsa", min_key_size=256, csp="ECDSA Key Storage Provider")
    assert detect_weak_key_size(_estate(templates=(tmpl,))) == []


def test_weak_template_key_size_skips_ecdsa_by_curve_size() -> None:
    # Even without a captured CSP, a min_key_size of 256/384/521 is unambiguously
    # an EC curve size (never a valid RSA minimum), so the RSA baseline is skipped.
    for bits in (256, 384, 521):
        tmpl = _template(f"EC{bits}", min_key_size=bits)
        assert detect_weak_key_size(_estate(templates=(tmpl,))) == [], f"{bits}-bit flagged"


def test_weak_template_key_size_rsa_1024_still_flagged() -> None:
    # A genuine RSA-1024 template is still flagged (the algorithm-aware skip must
    # not weaken the RSA check).
    tmpl = _template("Rsa1024", min_key_size=1024)
    findings = detect_weak_key_size(_estate(templates=(tmpl,)))
    assert len(findings) == 1
    assert findings[0].check == "WEAK_TEMPLATE_KEY_SIZE"


# --- hygiene: audit configuration ------------------------------------------


def test_audit_disabled_is_critical() -> None:
    estate = _estate(cas=(_ca("CA", audit_filter=0),))
    findings = detect_audit_config(estate)
    assert len(findings) == 1
    assert findings[0].check == "CA_AUDIT_DISABLED"
    assert findings[0].severity == Severity.CRITICAL


def test_audit_underscoped_flags_missing_categories() -> None:
    # 0x7F (127) is the full Microsoft baseline; 0x1 + 0x4 = 5 -> missing Revoke,
    # Change CA config, and Change CA security.
    estate = _estate(cas=(_ca("CA", audit_filter=5),))
    findings = detect_audit_config(estate)
    assert len(findings) == 1
    assert findings[0].check == "CA_AUDIT_UNDERSCOPED"
    assert findings[0].severity == Severity.MEDIUM
    assert "Revoke" in findings[0].detail
    assert "Change CA config" in findings[0].detail
    assert "Change CA security" in findings[0].detail


def test_audit_full_baseline_clean() -> None:
    estate = _estate(cas=(_ca("CA", audit_filter=127),))
    assert detect_audit_config(estate) == []


def test_audit_none_on_all_cas_degrades_to_note() -> None:
    estate = _estate(cas=(_ca("CA", audit_filter=None),))
    findings = detect_audit_config(estate)
    assert len(findings) == 1
    assert findings[0].check == "CA_AUDIT_NOT_EVALUATED"
    assert findings[0].severity == Severity.INFO


def test_audit_clean_ca_not_flagged_alongside_disabled() -> None:
    estate = _estate(cas=(_ca("Good", audit_filter=127), _ca("Disabled", audit_filter=0)))
    findings = detect_audit_config(estate)
    assert len(findings) == 1
    assert findings[0].subject == "Disabled"


def test_audit_skips_none_ca_and_evaluates_valued_ca() -> None:
    estate = _estate(cas=(_ca("Unknown", audit_filter=None), _ca("Disabled", audit_filter=0)))
    findings = detect_audit_config(estate)
    by_subj = {f.subject: f for f in findings}
    # The valued CA is still evaluated and flagged.
    assert by_subj["Disabled"].check == "CA_AUDIT_DISABLED"
    # The unevaluated CA degrades to its own note rather than being dropped silently.
    assert by_subj["Unknown"].check == "CA_AUDIT_NOT_EVALUATED"
    assert by_subj["Unknown"].severity == Severity.INFO
    assert len(findings) == 2


def test_audit_only_noncritical_bits_flagged_as_underscoped() -> None:
    # 0x80 is a non-baseline bit; with none of the 0x7F baseline set, the CA is
    # under-scoped (not disabled) and every baseline category is named.
    estate = _estate(cas=(_ca("Odd", audit_filter=0x80),))
    findings = detect_audit_config(estate)
    assert len(findings) == 1
    assert findings[0].check == "CA_AUDIT_UNDERSCOPED"
    assert findings[0].severity == Severity.MEDIUM
    for name in _AUDIT_CATEGORIES.values():
        assert name in findings[0].detail


def test_audit_extra_bits_beyond_baseline_still_clean() -> None:
    # Baseline (0x7F) fully present plus a non-baseline bit is still complete.
    estate = _estate(cas=(_ca("Full", audit_filter=0x7F | 0x80),))
    assert detect_audit_config(estate) == []


# --- run_all wiring --------------------------------------------------------


def test_run_all_includes_new_hygiene_detectors() -> None:
    estate = _estate(
        cas=(
            _ca(
                "AuditCA",
                audit_filter=0,
                certs=(_cert("CN=C", sig_alg="sha1", key_bits=1024),),
            ),
        ),
        templates=(_template("WeakKey", min_key_size=1024),),
    )
    checks = {f.check for f in run_all(estate)}
    assert "WEAK_SIG_ALG" in checks
    assert "WEAK_KEY_SIZE" in checks
    assert "WEAK_TEMPLATE_KEY_SIZE" in checks
    assert "CA_AUDIT_DISABLED" in checks


def test_esc5_suppressed_when_control_right_denied() -> None:
    allow = _ctrl_ace(right="WriteDacl")
    deny = _ctrl_ace(right="WriteDacl", ace_type=AceType.DENY)
    assert (
        detect_esc5(
            _estate(acls=(_pki_acl(AclKind.NTAUTH, security=(deny, allow)),))
        )
        == []
    )


# Broad enroll rights must still fire when unblocked (guards the coverage
# expansion that the _ENROLL_RIGHTS narrowing introduced).
def test_esc1_all_extended_rights_still_fires() -> None:
    tmpl = _template("AER", security=(_enroll_ace(right="AllExtendedRights"),))
    assert len(detect_esc1(_estate(templates=(tmpl,)))) == 1


def test_esc1_full_control_still_fires() -> None:
    tmpl = _template("FC", security=(_enroll_ace(right="FullControl"),))
    assert len(detect_esc1(_estate(templates=(tmpl,)))) == 1


# Each enroll-dependent detector is wired through the shared Deny-aware path —
# one test each so a future refactor that inlines the check can't silently drop
# Deny precedence without a test catching it.
def test_esc2_suppressed_when_enroll_denied() -> None:
    tmpl = _template("Any", ekus=(ANY_PURPOSE,), security=(_deny_enroll(), _enroll_ace()))
    assert detect_esc2(_estate(templates=(tmpl,))) == []


def test_esc3_suppressed_when_enroll_denied() -> None:
    tmpl = _template("Agent", ekus=(ENROLLMENT_AGENT,), security=(_deny_enroll(), _enroll_ace()))
    assert detect_esc3(_estate(templates=(tmpl,))) == []


def test_esc13_suppressed_when_enroll_denied() -> None:
    tmpl = _template(
        "Linked",
        ekus=(CLIENT_AUTH,),
        issuance_policy_oids=(POLICY_OID,),
        security=(_deny_enroll(), _enroll_ace()),
    )
    estate = _estate(
        templates=(tmpl,), oids=(IssuanceOid(POLICY_OID, "L", DOMAIN_ADMINS_SID),)
    )
    assert detect_esc13(estate) == []


def test_esc15_suppressed_when_enroll_denied() -> None:
    from adcs_lens.detection import detect_esc15

    tmpl = _template("V1", schema_version=1, security=(_deny_enroll(), _enroll_ace()))
    assert detect_esc15(_estate(templates=(tmpl,))) == []


# A single multi-right Allow ACE with one right denied: the finding still fires
# (WriteOwner survives) but only the surviving right is rendered.
def test_esc4_rendering_hides_only_blocked_right() -> None:
    allow = AceEntry(
        trustee_sid=LOW_PRIV_SID,
        trustee_name="trustee",
        rights=("WriteDacl", "WriteOwner"),
        ace_type=AceType.ALLOW,
    )
    deny = _ctrl_ace(right="WriteDacl", ace_type=AceType.DENY)
    tmpl = _template("Multi", security=(deny, allow))
    findings = detect_esc4(_estate(templates=(tmpl,)))
    assert len(findings) == 1
    assert "WriteOwner" in findings[0].detail
    assert "WriteDacl" not in findings[0].detail


# --- ESC4: property-scoped WriteProperty on dangerous GUIDs (WI-019) ---------

# Verified schemaIDGUID values from MS-ADSC / MS-ADA3 specifications.
_NAME_FLAG_GUID = "ea1dddc4-60ff-416e-8cc0-17cee534bce7"
_ENROLL_FLAG_GUID = "d15ef7d8-f226-46db-ae79-b34e560bd12c"
_EKU_GUID = "18976af6-3b9e-11d2-90cc-00c04fd91ab1"


def test_esc4_scoped_writeproperty_on_dangerous_guid_flagged() -> None:
    # A scoped WriteProperty on msPKI-Certificate-Name-Flag lets a low-priv
    # principal flip ENROLLEE_SUPPLIES_SUBJECT on -> an ESC4 path (WI-019).
    ace = AceEntry(
        trustee_sid=LOW_PRIV_SID,
        trustee_name="Domain Users",
        rights=(f"WriteProperty:{_NAME_FLAG_GUID}",),
        ace_type=AceType.ALLOW,
    )
    tmpl = _template("ScopedWrite", security=(ace,))
    findings = detect_esc4(_estate(templates=(tmpl,)))
    esc4 = [f for f in findings if f.check == "ESC4"]
    assert len(esc4) == 1
    assert "scoped" in esc4[0].title.lower()
    assert "dangerous" in esc4[0].detail.lower()


def test_esc4_scoped_writeproperty_on_eku_guid_flagged() -> None:
    # A scoped WriteProperty on pKIExtendedKeyUsage lets a low-priv principal
    # add a client-auth EKU -> an ESC4 path.
    ace = AceEntry(
        trustee_sid=LOW_PRIV_SID,
        trustee_name="Domain Users",
        rights=(f"WriteProperty:{_EKU_GUID}",),
        ace_type=AceType.ALLOW,
    )
    tmpl = _template("ScopedEku", security=(ace,))
    findings = detect_esc4(_estate(templates=(tmpl,)))
    assert any(f.check == "ESC4" and "scoped" in f.title.lower() for f in findings)


def test_esc4_scoped_writeproperty_on_benign_guid_not_flagged() -> None:
    # A scoped WriteProperty on a non-dangerous property (e.g. displayName) is
    # not an ESC4 path — the GUID is not in the dangerous set.
    ace = AceEntry(
        trustee_sid=LOW_PRIV_SID,
        trustee_name="Domain Users",
        rights=("WriteProperty:00000000-0000-0000-0000-deadbeef0001",),
        ace_type=AceType.ALLOW,
    )
    tmpl = _template("BenignScoped", security=(ace,))
    assert detect_esc4(_estate(templates=(tmpl,))) == []


def test_esc4_bare_writeproperty_still_not_flagged() -> None:
    # A bare 'WriteProperty' (no GUID, from an older collector) is still
    # excluded — the scope is unknown (backward compat with v0.6.1).
    tmpl = _template("BareWrite", security=(_enroll_ace(right="WriteProperty"),))
    assert detect_esc4(_estate(templates=(tmpl,))) == []


def test_esc4_scoped_writeproperty_high_priv_not_flagged() -> None:
    ace = AceEntry(
        trustee_sid=HIGH_PRIV_SID,
        trustee_name="Domain Admins",
        rights=(f"WriteProperty:{_NAME_FLAG_GUID}",),
        ace_type=AceType.ALLOW,
    )
    tmpl = _template("AdminScoped", security=(ace,))
    assert detect_esc4(_estate(templates=(tmpl,))) == []


def test_esc4_scoped_writeproperty_suppressed_by_deny() -> None:
    # A Deny of the same scoped WriteProperty blocks the Allow (Deny precedence).
    allow = AceEntry(
        trustee_sid=LOW_PRIV_SID,
        trustee_name="Domain Users",
        rights=(f"WriteProperty:{_NAME_FLAG_GUID}",),
        ace_type=AceType.ALLOW,
    )
    deny = AceEntry(
        trustee_sid=LOW_PRIV_SID,
        trustee_name="Domain Users",
        rights=(f"WriteProperty:{_NAME_FLAG_GUID}",),
        ace_type=AceType.DENY,
    )
    tmpl = _template("DeniedScoped", security=(deny, allow))
    esc4 = [f for f in detect_esc4(_estate(templates=(tmpl,))) if f.check == "ESC4"]
    assert esc4 == []


def test_esc4_scoped_writeproperty_suppressed_by_writepropertyall_deny() -> None:
    # A blanket WritePropertyAll Deny blocks every scoped write (it covers all
    # properties), including dangerous ones.
    allow = AceEntry(
        trustee_sid=LOW_PRIV_SID,
        trustee_name="Domain Users",
        rights=(f"WriteProperty:{_NAME_FLAG_GUID}",),
        ace_type=AceType.ALLOW,
    )
    deny = _ctrl_ace(right="WritePropertyAll", ace_type=AceType.DENY)
    tmpl = _template("BlanketDenied", security=(deny, allow))
    esc4 = [f for f in detect_esc4(_estate(templates=(tmpl,))) if f.check == "ESC4"]
    assert esc4 == []


@pytest.mark.parametrize("broad_right", ["GenericAll", "FullControl", "GenericWrite"])
def test_esc4_scoped_writeproperty_suppressed_by_broad_deny(
    broad_right: str,
) -> None:
    # A broad Deny (GenericAll / FullControl / GenericWrite) covers
    # WritePropertyAll per the _COVERS map, so it must suppress a scoped
    # WriteProperty Allow on a dangerous property — otherwise the scoped Allow
    # would fire as a false positive (the trustee is denied all writes).
    allow = AceEntry(
        trustee_sid=LOW_PRIV_SID,
        trustee_name="Domain Users",
        rights=(f"WriteProperty:{_NAME_FLAG_GUID}",),
        ace_type=AceType.ALLOW,
    )
    deny = _ctrl_ace(right=broad_right, ace_type=AceType.DENY)
    tmpl = _template("BroadDenied", security=(deny, allow))
    esc4 = [f for f in detect_esc4(_estate(templates=(tmpl,))) if f.check == "ESC4"]
    assert esc4 == []


def test_esc4_scoped_writeproperty_and_object_control_emit_two_findings() -> None:
    # Both an object-wide WriteDacl and a scoped WriteProperty on a dangerous
    # property -> two distinct ESC4 findings (distinct vectors/remediations).
    allow_ctrl = _enroll_ace(right="WriteDacl")
    allow_scoped = AceEntry(
        trustee_sid=LOW_PRIV_SID,
        trustee_name="Domain Users",
        rights=(f"WriteProperty:{_ENROLL_FLAG_GUID}",),
        ace_type=AceType.ALLOW,
    )
    tmpl = _template("Both", security=(allow_ctrl, allow_scoped))
    esc4 = [f for f in detect_esc4(_estate(templates=(tmpl,))) if f.check == "ESC4"]
    assert len(esc4) == 2
    titles = {f.title for f in esc4}
    assert any("writable" in t.lower() for t in titles)
    assert any("scoped" in t.lower() for t in titles)


def test_esc4_scoped_writeproperty_skips_unreadable_template() -> None:
    # An unreadable-DACL template is skipped (the gap detector owns the note).
    ace = AceEntry(
        trustee_sid=LOW_PRIV_SID,
        trustee_name="Domain Users",
        rights=(f"WriteProperty:{_NAME_FLAG_GUID}",),
        ace_type=AceType.ALLOW,
    )
    tmpl = _template("UnreadableScoped", security=(ace,), acl_obtained=False)
    assert detect_esc4(_estate(templates=(tmpl,))) == []


def test_esc4_scoped_writeproperty_wired_into_run_all() -> None:
    ace = AceEntry(
        trustee_sid=LOW_PRIV_SID,
        trustee_name="Domain Users",
        rights=(f"WriteProperty:{_NAME_FLAG_GUID}",),
        ace_type=AceType.ALLOW,
    )
    tmpl = _template("ScopedRunAll", security=(ace,))
    checks = {f.check for f in run_all(_estate(templates=(tmpl,)))}
    assert "ESC4" in checks


# --- Orphaned templates (WI-032) ---------------------------------------------


def test_orphaned_template_flagged_when_not_published() -> None:
    # Explicit enrollment-services availability confirms the empty publication
    # state and flags the orphan alongside a published template.
    published = _template("Published", published_by=("LAB Issuing CA",))
    orphan = _template("Orphaned", security=())
    findings = detect_orphaned_templates(
        _estate(
            templates=(published, orphan),
            enrollment_services_available=True,
        )
    )
    assert len(findings) == 1
    assert findings[0].check == "ORPHANED_TEMPLATE"
    assert findings[0].severity == Severity.LOW
    assert findings[0].subject == "Orphaned"


def test_orphaned_template_not_flagged_when_published() -> None:
    tmpl = CertTemplate(
        name="Published",
        display_name="Published",
        schema_version=2,
        oid="1.3.6.1.4.1.311.21.8.pub",
        ekus=(CLIENT_AUTH,),
        name_flags=frozenset(),
        enrollment_flags=frozenset(),
        min_key_size=2048,
        issuance_policy_oids=(),
        security=(),
        published_by=("LAB Issuing CA",),
    )
    assert detect_orphaned_templates(
        _estate(templates=(tmpl,), enrollment_services_available=True)
    ) == []


def test_orphaned_template_skipped_when_enrollment_services_export_absent() -> None:
    # Degradation: without an enrollment-services export, every template would
    # look orphaned — meaningless noise. The check is skipped (WI-032 review fix).
    orphan = _template("Orphaned", security=())
    assert detect_orphaned_templates(_estate(templates=(orphan,))) == []


def test_orphaned_template_flagged_when_enrollment_services_export_is_empty() -> None:
    orphan = _template("Orphaned", security=())
    findings = detect_orphaned_templates(
        _estate(templates=(orphan,), enrollment_services_available=True)
    )
    assert len(findings) == 1
    assert findings[0].check == "ORPHANED_TEMPLATE"
    assert findings[0].severity == Severity.LOW


def test_orphaned_template_wired_into_run_all() -> None:
    published = _template("Published", published_by=("LAB Issuing CA",))
    orphan = _template("Orphan", security=())
    checks = {
        f.check
        for f in run_all(
            _estate(
                templates=(published, orphan),
                enrollment_services_available=True,
            )
        )
    }
    assert "ORPHANED_TEMPLATE" in checks


# --- OCSP URL absence (WI-022) -----------------------------------------------


def test_ocsp_absent_flagged_when_no_ocsp_url() -> None:
    cert = _cert("CN=NoOCSP", ocsp_urls=())
    ca = _ca("IssuingCA", certs=(cert,))
    findings = detect_ocsp_absence(_estate(cas=(ca,)))
    assert len(findings) == 1
    assert findings[0].check == "OCSP_URL_ABSENT"
    assert findings[0].severity == Severity.LOW
    assert findings[0].subject == "IssuingCA"
    assert findings[0].tier == CrlTier.ISSUING


def test_ocsp_absent_not_flagged_when_ocsp_url_present() -> None:
    cert = _cert("CN=WithOCSP", ocsp_urls=("http://ocsp/ocsp",))
    ca = _ca("IssuingCA", certs=(cert,))
    assert detect_ocsp_absence(_estate(cas=(ca,))) == []


def test_ocsp_absent_skips_root_ca() -> None:
    cert = _cert("CN=Root", kind=CertKind.ROOT_CA, ocsp_urls=())
    ca = _ca("RootCA", kind=CaKind.ROOT, certs=(cert,))
    assert detect_ocsp_absence(_estate(cas=(ca,))) == []


def test_ocsp_absent_degrades_without_certs() -> None:
    cert = _cert("CN=NoOCSP", ocsp_urls=())
    ca = _ca("IssuingCA", certs=(cert,))
    assert detect_ocsp_absence(_estate(cas=(ca,), certs_parsed=False)) == []


def test_ocsp_absent_wired_into_run_all() -> None:
    cert = _cert("CN=NoOCSP", ocsp_urls=())
    ca = _ca("IssuingCA", certs=(cert,))
    checks = {f.check for f in run_all(_estate(cas=(ca,)))}
    assert "OCSP_URL_ABSENT" in checks


# --- CDP / AIA URL absence (WI-032) ------------------------------------------


def test_cdp_aia_absent_flagged_when_both_missing() -> None:
    cert = _cert("CN=NoURLs", cdp_urls=(), aia_urls=())
    ca = _ca("IssuingCA", certs=(cert,))
    findings = detect_cdp_aia_absence(_estate(cas=(ca,)))
    assert len(findings) == 1
    assert findings[0].check == "CDP_AIA_ABSENT"
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].subject == "IssuingCA"
    assert findings[0].tier == CrlTier.ISSUING
    assert "cannot fetch revocation data or build the certificate chain" in findings[0].detail


def test_cdp_aia_absent_not_flagged_when_both_present() -> None:
    cert = _cert("CN=WithURLs", cdp_urls=("http://crl/crl.crl",), aia_urls=("http://aia/ca.cer",))
    ca = _ca("IssuingCA", certs=(cert,))
    assert detect_cdp_aia_absence(_estate(cas=(ca,))) == []


def test_cdp_aia_absent_flagged_when_only_cdp_missing() -> None:
    cert = _cert("CN=NoCDP", cdp_urls=(), aia_urls=("http://aia/ca.cer",))
    ca = _ca("IssuingCA", certs=(cert,))
    findings = detect_cdp_aia_absence(_estate(cas=(ca,)))
    assert len(findings) == 1
    assert "CRL Distribution Points" in findings[0].detail
    assert "Authority Information Access" not in findings[0].detail
    assert "cannot fetch revocation data (CRL)" in findings[0].detail
    assert "build the certificate chain" not in findings[0].detail


def test_cdp_aia_absent_flagged_when_only_aia_missing() -> None:
    cert = _cert("CN=NoAIA", cdp_urls=("http://crl/crl.crl",), aia_urls=())
    ca = _ca("IssuingCA", certs=(cert,))
    findings = detect_cdp_aia_absence(_estate(cas=(ca,)))
    assert len(findings) == 1
    assert "Authority Information Access" in findings[0].detail
    assert "CRL Distribution Points" not in findings[0].detail
    assert "cannot build the certificate chain (CA issuer info)" in findings[0].detail
    assert "revocation data" not in findings[0].detail


def test_cdp_aia_absent_skips_root_ca() -> None:
    cert = _cert("CN=Root", kind=CertKind.ROOT_CA, cdp_urls=(), aia_urls=())
    ca = _ca("RootCA", kind=CaKind.ROOT, certs=(cert,))
    assert detect_cdp_aia_absence(_estate(cas=(ca,))) == []


def test_cdp_aia_absent_degrades_without_certs() -> None:
    cert = _cert("CN=NoURLs", cdp_urls=(), aia_urls=())
    ca = _ca("IssuingCA", certs=(cert,))
    assert detect_cdp_aia_absence(_estate(cas=(ca,), certs_parsed=False)) == []


def test_cdp_aia_absent_wired_into_run_all() -> None:
    cert = _cert("CN=NoURLs", cdp_urls=(), aia_urls=())
    ca = _ca("IssuingCA", certs=(cert,))
    checks = {f.check for f in run_all(_estate(cas=(ca,)))}
    assert "CDP_AIA_ABSENT" in checks


# --- CA registry-config gap (multi-CA honesty) ----------------------------


def test_esc11_skips_uncollected_ca() -> None:
    """A remote CA ships empty interface flags; ESC11 must not fire on the absence."""
    ca = _ca("RemoteCA", interface_flags=(), registry_config_collected=False)
    assert detect_esc11(_estate(cas=(ca,))) == []


def test_esc6_skips_uncollected_ca() -> None:
    ca = _ca("RemoteCA", edit_flags=(), registry_config_collected=False)
    assert detect_esc6(_estate(cas=(ca,))) == []


def test_esc16_skips_uncollected_ca() -> None:
    ca = _ca("RemoteCA", disabled_extensions=(), registry_config_collected=False)
    assert detect_esc16(_estate(cas=(ca,))) == []


def test_esc7_skips_uncollected_ca() -> None:
    ca = _ca(
        "RemoteCA",
        security=(),
        owner_sid=LOW_PRIV_SID,
        registry_config_collected=False,
    )
    assert detect_esc7(_estate(cas=(ca,))) == []


def test_ca_registry_gap_note_per_uncollected_ca() -> None:
    local = _ca("LocalCA", edit_flags=("EDITF_ATTRIBUTESUBJECTALTNAME2",))
    remote = _ca("RemoteCA", registry_config_collected=False)
    findings = detect_ca_registry_gaps(_estate(cas=(local, remote)))
    assert len(findings) == 1
    f = findings[0]
    assert f.check == "CA_REGISTRY_NOT_EVALUATED"
    assert f.severity is Severity.INFO
    assert f.subject == "RemoteCA"
    assert is_degradation_note(f)


def test_ca_registry_gap_note_wired_into_run_all() -> None:
    remote = _ca("RemoteCA", registry_config_collected=False)
    checks = {f.check for f in run_all(_estate(cas=(remote,)))}
    assert "CA_REGISTRY_NOT_EVALUATED" in checks
    assert "ESC11" not in checks


# --- PKI object ACL gap (ESC5 honesty) --------------------------------------


def test_esc5_skips_unreadable_object() -> None:
    obj = _pki_acl(
        AclKind.NTAUTH,
        security=(_ctrl_ace(right="WriteDacl"),),
        acl_obtained=False,
    )
    assert detect_esc5(_estate(acls=(obj,))) == []


def test_pki_acl_gap_note_flagged() -> None:
    obj = _pki_acl(AclKind.NTAUTH, acl_obtained=False)
    findings = detect_pki_acl_gaps(_estate(acls=(obj,)))
    assert len(findings) == 1
    f = findings[0]
    assert f.check == "PKI_ACL_UNREADABLE"
    assert f.severity is Severity.INFO
    assert is_degradation_note(f)


def test_pki_acl_gap_silent_when_pass_skipped() -> None:
    obj = _pki_acl(AclKind.NTAUTH, acl_obtained=False)
    assert detect_pki_acl_gaps(_estate(acls=(obj,), skipped_passes=("pki-acls",))) == []


def test_pki_acl_gap_note_wired_into_run_all() -> None:
    obj = _pki_acl(AclKind.NTAUTH, acl_obtained=False)
    checks = {f.check for f in run_all(_estate(acls=(obj,)))}
    assert "PKI_ACL_UNREADABLE" in checks
    assert "ESC5" not in checks


# --- ESC7 structured SID (WI-042) --------------------------------------------


def test_esc7_role_finding_carries_trustee_sid() -> None:
    ca = _ca(
        "CA",
        security=(_ctrl_ace(sid=LOW_PRIV_SID, right="ManageCA"),),
    )
    findings = detect_esc7(_estate(cas=(ca,)))
    assert len(findings) == 1
    assert findings[0].sid == LOW_PRIV_SID


def test_esc7_owner_finding_carries_owner_sid() -> None:
    ca = _ca("CA", owner_sid=LOW_PRIV_SID)
    findings = detect_esc7(_estate(cas=(ca,)))
    assert len(findings) == 1
    assert findings[0].sid == LOW_PRIV_SID


# --- Allowlist trustee classification through the detectors -------------------


def test_esc1_fires_for_custom_group_enroll() -> None:
    """The false-negative fix: a custom (non-well-known) group holding Enroll
    on an ESC1-positive template now flags (pre-inversion it was invisible)."""
    custom_group_sid = "S-1-5-21-1111111111-2222222222-3333333333-1601"
    tmpl = _template(security=(_enroll_ace(sid=custom_group_sid),))
    findings = detect_esc1(_estate(templates=(tmpl,)))
    assert len(findings) == 1
    assert findings[0].check == "ESC1"


def test_esc1_still_quiet_for_domain_admins_enroll() -> None:
    tmpl = _template(security=(_enroll_ace(sid=HIGH_PRIV_SID),))
    assert detect_esc1(_estate(templates=(tmpl,))) == []


# --- review round 1 (Sol B1, DeepSeek N1/N4/N6) --------------------------------
_FOREIGN_DA = "S-1-5-21-4444444444-5555555555-6666666666-512"
_FOREIGN_EA = "S-1-5-21-4444444444-5555555555-6666666666-519"


def test_foreign_unresolved_domain_admin_genericall() -> None:
    # Sol's probe case: an unnamed -512 may be another domain's Domain Admins; the
    # privileged-RID allowlist cannot know, so on the CA computer object it fires.
    ace = AceEntry(_FOREIGN_DA, "", ("GenericAll",), AceType.ALLOW)
    (f,) = detect_esc5(_estate(acls=(_computer(ace),)))
    assert (f.variant, f.severity) == ("dacl", Severity.CRITICAL)
    assert _FOREIGN_DA in f.detail
    _assert_unresolved_wording(f.detail)


@pytest.mark.parametrize(
    "sid",
    [
        _FOREIGN_DA,
        _FOREIGN_EA,
        *(f"S-1-5-21-4444444444-5555555555-6666666666-{rid}" for rid in (518, 498, 516, 521)),
    ],
)
def test_unresolved_privileged_rid_with_control_is_critical(sid: str) -> None:
    ace = AceEntry(sid, "", ("GenericAll",), AceType.ALLOW)
    (f,) = detect_esc5(_estate(acls=(_computer(ace),)))
    assert f.severity == Severity.CRITICAL
    _assert_unresolved_wording(f.detail)


def test_unresolved_privileged_rid_rbcd_scoped_write_is_critical() -> None:
    ace = AceEntry(_FOREIGN_DA, "", (f"WriteProperty:{_RBCD}",), AceType.ALLOW)
    (f,) = detect_esc5(_estate(acls=(_computer(ace),)))
    assert (f.variant, f.severity) == ("scoped-writeproperty", Severity.CRITICAL)
    assert _FOREIGN_DA in f.detail and "msDS-AllowedToActOnBehalfOfOtherIdentity" in f.detail
    _assert_unresolved_wording(f.detail)
    assert "Remove the delegated write" not in f.detail


def test_unresolved_trustee_scoped_write_has_the_unresolved_wording() -> None:
    ace = AceEntry(_DANGLING_SID, "", (f"WriteProperty:{_KEY_CREDENTIAL_LINK}",), AceType.ALLOW)
    (f,) = detect_esc5(_estate(acls=(_computer(ace),)))
    assert f.variant == "scoped-writeproperty" and "msDS-KeyCredentialLink" in f.detail
    _assert_unresolved_wording(f.detail)


def test_named_and_unresolved_scoped_trustees_are_both_named() -> None:
    named = AceEntry(LOW_PRIV_SID, "Helpdesk", (f"WriteProperty:{_RBCD}",), AceType.ALLOW)
    dangling = AceEntry(_DANGLING_SID, "", (f"WriteProperty:{_RBCD}",), AceType.ALLOW)
    (f,) = detect_esc5(_estate(acls=(_computer(named, dangling),)))
    assert "Helpdesk hold a property-scoped" in f.detail
    assert "Remove the delegated write" in f.detail
    assert _DANGLING_SID in f.detail
    _assert_unresolved_wording(f.detail)


def test_a_named_local_domain_admin_stays_clean() -> None:
    for right in ("GenericAll", f"WriteProperty:{_RBCD}"):
        ace = AceEntry(DOMAIN_ADMINS_SID, "Domain Admins", (right,), AceType.ALLOW)
        assert detect_esc5(_estate(acls=(_computer(ace),))) == []


def test_unresolved_privileged_rid_is_unchanged_on_other_pki_objects() -> None:
    # is_low_priv_trustee is not changed globally: only the CA computer object.
    ace = AceEntry(_FOREIGN_DA, "", ("GenericAll",), AceType.ALLOW)
    assert detect_esc5(_estate(acls=(_pki_acl(AclKind.NTAUTH, security=(ace,)),))) == []


def test_mixed_explicit_and_inherited_self_acls_say_where_each_is_fixed() -> None:
    explicit = AceEntry(_SELF, "", (f"WriteProperty:{_RBCD}",), AceType.ALLOW)
    (f,) = detect_esc5(_estate(acls=(_computer(_inherited_self_rbcd(), explicit),)))
    assert "Some of these ACEs are inherited and must be fixed at the parent" in f.detail
    assert "the explicit ones must be fixed on this object" in f.detail


def test_self_is_named_in_the_general_part_without_a_friendly_name() -> None:
    kcl = AceEntry(_SELF, "", (f"WriteProperty:{_KEY_CREDENTIAL_LINK}",), AceType.ALLOW)
    (f,) = detect_esc5(_estate(acls=(_computer(kcl),)))
    assert f.detail.startswith("NT AUTHORITY\\SELF hold a property-scoped")
    assert "S-1-5-10" not in f.detail
