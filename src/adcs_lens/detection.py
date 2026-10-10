"""Deterministic detectors. No AI, no I/O, no probing — pure functions over an
:class:`~adcs_lens.model.Estate`.

The checks here span both data paths: ESC1 / ESC6 / ESC9 on the config/template
path and infrastructure cert/CRL expiry on the lifecycle path. Each finding is
traceable to the exact source fact, per the charter's "evidence-producing"
principle, and ACL-dependent checks degrade to a note rather than a false
"all clear" when the collector did not capture the relevant security descriptors.
"""

from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from adcs_lens.model import (
    KNOWN_PASSES,
    PASS_FILES,
    SEVERITY_RANK,
    WEAK_X509_MAPPING_FORMS,
    AceEntry,
    AceType,
    AclKind,
    CaKind,
    CaPatchState,
    CertAuthority,
    CertKind,
    CertLifecycle,
    CertTemplate,
    CollectorVersionStatus,
    Crl,
    CrlTier,
    DcConfiguration,
    EndpointKind,
    EnrollmentEndpoint,
    EpaPolicy,
    Estate,
    PkiObjectAcl,
    PrincipalMapping,
    SchannelMappingMethod,
    Severity,
    StrongCertBinding,
    X509MappingForm,
)
from adcs_lens.normalize import is_low_priv_trustee, normalize_sid

# ESC6: requester-supplied SAN honored CA-wide regardless of template.
_EDITF_SAN2 = "EDITF_ATTRIBUTESUBJECTALTNAME2"

# --- ESC1 / ESC9: template-driven enrollment escalation ----------------------
# Name flags that let the *requester* choose the subject/SAN, so they can name a
# privileged principal. Either form qualifies (collector emits the MS names).
_ENROLLEE_SUPPLIES_SUBJECT = frozenset(
    {"ENROLLEE_SUPPLIES_SUBJECT", "ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME"}
)
# Enrollment flag that gates issuance behind a CA manager — mitigates ESC1.
_MANAGER_APPROVAL = "PEND_ALL_REQUESTS"
# Enrollment flag behind ESC9 (issued cert omits szOID_NTDS_CA_SECURITY_EXT).
_NO_SECURITY_EXTENSION = "NO_SECURITY_EXTENSION"
# ESC16: the same extension disabled CA-wide via policy\DisableExtensionList.
_NTDS_CA_SECURITY_EXT = "1.3.6.1.4.1.311.25.2"

# EKUs whose presence lets the issued cert authenticate as its subject. A
# template with *no* EKU is equally dangerous (valid for any purpose).
_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
_SMARTCARD_LOGON = "1.3.6.1.4.1.311.20.2.2"
_PKINIT_CLIENT_AUTH = "1.3.6.1.5.2.3.4"
_ANY_PURPOSE = "2.5.29.37.0"
_AUTH_EKUS = frozenset({_CLIENT_AUTH, _SMARTCARD_LOGON, _PKINIT_CLIENT_AUTH, _ANY_PURPOSE})

# Certificate Request Agent EKU (ESC3): the holder can enroll on behalf of others.
_ENROLLMENT_AGENT_EKU = "1.3.6.1.4.1.311.20.2.1"

# The single enrollment-capability right. ``AutoEnroll`` is intentionally
# excluded: AD CS issuance is gated on the Enroll extended right, so a principal
# with only AutoEnroll cannot obtain a certificate at all (the old behavior of
# flagging AutoEnroll-alone as ESC1 was a latent false positive). Broad rights
# (GenericAll/FullControl/AllExtendedRights) still satisfy this via ``_COVERS``.
# Narrowing is also required for sound Deny logic: keeping ``autoenroll`` here
# would make ``Allow AutoEnroll + Deny Enroll`` fire (AutoEnroll survives a Deny
# that does not cover it) — a false positive, since the principal lacks Enroll.
_ENROLL_RIGHTS = frozenset({"enroll"})

# Every right token the detectors treat as a capability (lower-cased). Used so
# that a GenericAll/FullControl Deny can be represented as "blocks everything"
# without a sentinel. Not exhaustive over collector tokens — only over rights a
# detector keys a capability on.
_ALL_RIGHTS: frozenset[str] = frozenset(
    {
        "enroll", "autoenroll", "allextendedrights",
        "genericall", "fullcontrol", "genericread",
        "genericwrite", "writedacl", "writeowner",
        "writepropertyall", "writeproperty", "readproperty",
        "manageca", "managecertificates",
    }
)

# A denied right D blocks every right in _COVERS[D]. Implications follow
# Windows access-mask semantics:
#   - GenericAll / FullControl cover every right.
#   - AllExtendedRights covers the extended rights Enroll + AutoEnroll only.
#   - GenericWrite covers write-all-properties (WritePropertyAll) but NOT
#     WriteDacl / WriteOwner (those are control rights, not property writes).
# IMPORTANT: AutoEnroll does NOT cover Enroll (distinct extended rights), and
# Enroll does NOT cover AutoEnroll. Getting this backwards causes false negatives.
_COVERS: dict[str, frozenset[str]] = {
    "genericall": _ALL_RIGHTS,
    "fullcontrol": _ALL_RIGHTS,
    "allextendedrights": frozenset({"enroll", "autoenroll"}),
    "enroll": frozenset({"enroll"}),
    "autoenroll": frozenset({"autoenroll"}),
    "genericwrite": frozenset({"genericwrite", "writepropertyall"}),
    "writedacl": frozenset({"writedacl"}),
    "writeowner": frozenset({"writeowner"}),
    "writepropertyall": frozenset({"writepropertyall"}),
    "writeproperty": frozenset({"writeproperty"}),
    "manageca": frozenset({"manageca"}),
    "managecertificates": frozenset({"managecertificates"}),
}

# ACE rights (lower-cased) that let a principal rewrite a template object, and so
# turn it into ESC1 (enable enrollee-supplied subjects + a client-auth EKU). These
# are object-wide control rights. ``writepropertyall`` is a blanket WriteProperty
# (collector tokenises an all-zero ObjectType this way): it can rewrite any
# property, including msPKI-Certificate-Name-Flag → ENROLLEE_SUPPLIES_SUBJECT.
# Property-scoped WriteProperty (token ``writeproperty``) is excluded — flagging
# it would need a property-set GUID map to know whether it reaches the name flags.
_DANGEROUS_TEMPLATE_CONTROL = frozenset(
    {
        "genericall",
        "genericwrite",
        "writedacl",
        "writeowner",
        "fullcontrol",
        "writepropertyall",
    }
)

# Property schemaIDGUIDs (verified from the MS-ADSC / MS-ADA3 specifications)
# whose write lets a low-priv principal convert a template into an ESC1 path:
# enable ENROLLEE_SUPPLIES_SUBJECT, change the EKU set, alter enrollment flags,
# or link issuance policies. The collector (v0.6.2+) emits these as
# ``writeproperty:<guid>`` tokens for scoped WriteProperty ACEs (WI-019).
_DANGEROUS_PROPERTY_GUIDS: frozenset[str] = frozenset(
    {
        # msPKI-Certificate-Name-Flag — flip ENROLLEE_SUPPLIES_SUBJECT on.
        "ea1dddc4-60ff-416e-8cc0-17cee534bce7",
        # msPKI-Enrollment-Flag — clear manager approval / NO_SECURITY_EXTENSION.
        "d15ef7d8-f226-46db-ae79-b34e560bd12c",
        # pKIExtendedKeyUsage — add a client-authentication EKU.
        "18976af6-3b9e-11d2-90cc-00c04fd91ab1",
        # msPKI-Certificate-Policy — link to a group-linked issuance policy.
        "38942346-cc5b-424b-a7d8-6ffd12029c5f",
        # msPKI-Certificate-Application-Policy — the v2+ equivalent of EKU write.
        "dbd90548-aa37-4202-9966-8c537ba5ce32",
    }
)

# Manifest pass whose absence means template ACLs were not collected (collector
# Phase 1b). ESC checks needing the enroll ACL degrade to a note when it is
# listed in skipped_passes.
_TEMPLATE_SECURITY_PASS = "template-security"

# --- ESC5: writable ACL on PKI container / CA objects ------------------------
# Same object-wide control rights as ESC4 (they let a principal rewrite the
# object's DACL or contents), here applied to the Public Key Services containers
# and CA objects rather than to a template.
_DANGEROUS_OBJECT_CONTROL = _DANGEROUS_TEMPLATE_CONTROL
# Manifest pass whose absence means PKI-object ACLs were not collected.
_PKI_ACLS_PASS = "pki-acls"
# Per-object-kind severity + the escalation a write on it enables. NTAuth and CA
# objects are full-trust primitives (CRITICAL); the distribution containers let
# an attacker tamper with chain/revocation (HIGH).
_ESC5_IMPACT: dict[AclKind, tuple[Severity, str]] = {
    AclKind.NTAUTH: (
        Severity.CRITICAL,
        "the NTAuthCertificates object — adding a CA certificate here makes every "
        "certificate that CA issues trusted for AD authentication, forging any "
        "principal estate-wide",
    ),
    AclKind.CA_OBJECT: (
        Severity.CRITICAL,
        "a CA object — control lets an attacker alter the CA's published templates "
        "and enrollment configuration",
    ),
    AclKind.PKS_CONTAINER: (
        Severity.HIGH,
        "a Public Key Services container — control lets an attacker create child "
        "objects such as a rogue template or enrollment service",
    ),
    AclKind.AIA: (
        Severity.HIGH,
        "the AIA container — control lets an attacker tamper with the published CA "
        "chain (authority information access)",
    ),
    AclKind.CDP: (
        Severity.HIGH,
        "the CDP container — control lets an attacker tamper with CRL distribution, "
        "undermining revocation",
    ),
}

# --- ESC7: CA role permissions held by low-priv principals -------------------
_CA_MANAGE_CA = "manageca"  # CA_ACCESS_ADMIN — full CA control
_CA_MANAGE_CERTS = "managecertificates"  # CA_ACCESS_OFFICER — issue/approve/revoke
_CA_SECURITY_PASS = "ca-security"

# ESC11: RPC (ICertPassage) encrypted certificate request enforcement flag.
_ESC11_FLAG = "IF_ENFORCEENCRYPTICERTREQUEST"

# --- ESC8: NTLM relay to HTTP enrollment (Web Enrollment / CES) ---------------
_ESC8_ENDPOINTS_PASS = "enrollment-endpoints"

# --- ESC10: Weak DC certificate mapping ----------------------------------------
# Two registry-backed cases, per SpecterOps "Certified Pre-Owned" + KB5014754:
#   case 1: Schannel CertificateMappingMethods has the UPN bit (0x4) — a cert's
#           UPN SAN alone maps to an account, so writing a victim's UPN impersonates it.
#   case 2: KDC StrongCertificateBindingEnforcement is Disabled — weak/implicit
#           mappings are allowed (the ESC9 "no SID extension" path opens up).
# The pass for this is 'esc10-dc-registry'.
_ESC10_DC_REGISTRY_PASS = "esc10-dc-registry"
# StrongCertificateBindingEnforcement states that leave weak mappings exploitable.
# UNKNOWN is excluded — we don't know the state, so we don't assert vulnerability.
_BINDING_NON_STRICT = frozenset({StrongCertBinding.DISABLED, StrongCertBinding.PERMISSIVE})

# --- ESC14: Weak explicit cert mapping via altSecurityIdentities ----------------
# A principal whose altSecurityIdentities holds a *weak* (reusable) X.509 mapping
# form — subject-only, issuer+subject, RFC822/email, or UPN — can be impersonated
# by anyone who obtains a certificate matching those reusable fields, unless the
# DC enforces strong binding (StrongCertificateBindingEnforcement = strict). Strong
# (nonreusable) forms — issuer+serial, SKI, SHA1 public key — are not flagged.
# The pass for this is 'esc14-altsecid'.
_ESC14_ALTSECID_PASS = "esc14-altsecid"
# Auth providers that permit NTLM: explicit NTLM, or Negotiate (which falls back
# to NTLM unless it is explicitly disabled — so a Negotiate endpoint is treated
# as NTLM-relayable).
_NTLM_PROVIDERS = frozenset({"ntlm", "negotiate"})
# Endpoint kinds whose Windows-auth relay path ESC8 models. NDES/SCEP uses a
# different (challenge-based) flow, so it is collected but not flagged here.
_ESC8_KINDS = frozenset({EndpointKind.WEB_ENROLLMENT, EndpointKind.CES})

# Coverage-gap note identifiers. These INFO findings signal a detector was skipped
# because the export lacks a required pass, not a posture weakness, so they are
# excluded from the --exit-code gate while still being shown in the output.
_DEGRADATION_NOTES: frozenset[str] = frozenset(
    {
        "ACL_GROUP_TOKEN_CAVEAT",
        "ALTSECID_NOT_EVALUATED",
        "CA_AUDIT_NOT_EVALUATED",
        "CA_REGISTRY_NOT_EVALUATED",
        "CA_SECURITY_NOT_EVALUATED",
        "COLLECTOR_VERSION_UNVERIFIED",
        "DC_REGISTRY_NOT_EVALUATED",
        "ENROLLMENT_ENDPOINTS_NOT_EVALUATED",
        "ESC10_ENFORCEMENT_UNKNOWN",
        "ESC14_ENFORCEMENT_UNKNOWN",
        "LIFECYCLE_NOT_EVALUATED",
        "PASS_NOT_COLLECTED",
        "PKI_ACL_NOT_EVALUATED",
        "PKI_ACL_UNREADABLE",
        "TEMPLATE_ACL_NOT_EVALUATED",
        "TEMPLATE_ACL_UNREADABLE",
    }
)


@dataclass(frozen=True)
class Finding:
    """One posture finding, traceable to a source fact."""

    check: str  # "ESC6", "CA_CERT_EXPIRY", "CRL_EXPIRY", ...
    severity: Severity
    title: str
    subject: str  # the CA / template / object the finding is about
    detail: str
    source: str  # the exact source fact (registry path, cert file, CRL, ...)
    tier: CrlTier | None = None  # root | issuing for lifecycle findings
    # Structured principal SID for findings about a specific trustee (currently
    # ESC7, which reports the low-privilege role holder / owner). Carried as a
    # first-class field so renderers (e.g. the SARIF properties bag) never parse
    # it out of free-text detail with a regex (WI-042). Empty when not applicable.
    sid: str = ""
    # The object the finding is about: its type, objectGUID (collector >=
    # 0.9.0) and legacy aliases. Drift pairs objects across exports on the
    # GUID, or — for older exports — conservatively on unambiguous aliases.
    # None for estate-level notes and hand-built findings.
    object_ref: ObjectRef | None = None
    # Distinguishes several findings of one check on one object (e.g. ESC4's
    # "dacl" / "scoped-writeproperty" / "owner" paths, ESC7's per-trustee rows).
    variant: str = ""
    # True only when the detector states the severity rests on complete
    # evidence. Defaults to False, so a detector that forgets to say so has its
    # severity improvements withheld, never shown as fixes (e.g. ESC15 with an
    # UNKNOWN CA patch state passes False).
    evidence_complete: bool = False


def is_degradation_note(finding: Finding) -> bool:
    """True when a finding is a coverage-gap note rather than a posture finding."""
    return finding.check in _DEGRADATION_NOTES


# --- Coverage predicates -------------------------------------------------------
# Each predicate below is the ONE place the core decides "this input was not
# collected / not readable, so it cannot be evaluated". Detectors call them to
# skip (and emit a degradation note); :func:`coverage_gaps` calls the very same
# functions to tell ``diff`` which absences in a newer export are coverage loss
# rather than resolution (explanations). Resolution itself needs a positive
# evaluation record (see _evaluated below), so a skip a detector grows without
# routing it through here still only withholds — it can never resolve.


def _pass_collected(estate: Estate, pass_name: str) -> bool:
    """True unless the pass was declared skipped or its export file is missing."""
    return pass_name not in estate.manifest.uncollected_passes


def _uncollected_source(estate: Estate, pass_name: str) -> str:
    """The source fact for a pass-level degradation note."""
    if pass_name in estate.manifest.skipped_passes:
        return f"collector-manifest.json: skipped_passes contains '{pass_name}'"
    file_name = PASS_FILES.get(pass_name, pass_name)
    return f"export: {file_name} missing (pass '{pass_name}' not collected)"


def _collector_verified(estate: Estate) -> bool:
    """True when the collector version is known to be at/above the core's minimum.

    An older or unknown collector may omit fields whose ingest defaults read as
    "collected" (``acl_obtained``, ``registry_config_collected``, owners), so
    none of its per-object coverage markers can be trusted.
    """
    return estate.manifest.collector_version_status is CollectorVersionStatus.CURRENT


def _template_acl_readable(tmpl: CertTemplate) -> bool:
    return tmpl.acl_obtained


def _pki_acl_readable(obj: PkiObjectAcl) -> bool:
    return obj.acl_obtained


def _owner_captured(owner_sid: str) -> bool:
    """Every AD object / CA descriptor has an owner; empty means it was not captured."""
    return bool(owner_sid)


def _ca_registry_collected(ca: CertAuthority) -> bool:
    return ca.registry_config_collected


def _ca_security_readable(ca: CertAuthority) -> bool:
    return ca.security_collected


def _audit_filter_captured(ca: CertAuthority) -> bool:
    return ca.audit_filter is not None


def _template_key_size_captured(tmpl: CertTemplate) -> bool:
    return tmpl.min_key_size is not None


def _lifecycle_parsed(estate: Estate) -> bool:
    return estate.manifest.certs_parsed


def _cert_expiry_readable(cert: CertLifecycle) -> bool:
    return cert.not_after is not None


def _cert_key_size_readable(cert: CertLifecycle) -> bool:
    return cert.key_bits is not None


def _crl_next_update_readable(crl: Crl) -> bool:
    return crl.next_update is not None


def _cert_sig_alg_readable(cert: CertLifecycle) -> bool:
    return cert.sig_alg.strip().lower() not in ("", "unknown")


def _cert_key_alg_known(cert: CertLifecycle) -> bool:
    return cert.key_alg.strip().lower() not in ("", "unknown")


def _crl_window_readable(crl: Crl) -> bool:
    """thisUpdate known, so the early-warning window can be computed."""
    return crl.this_update is not None


def _dc_binding_known(dc: DcConfiguration) -> bool:
    return dc.strong_certificate_binding_enforcement is not StrongCertBinding.UNKNOWN


def _non_strict_dcs(estate: Estate) -> list[DcConfiguration]:
    """DCs whose StrongCertificateBindingEnforcement leaves weak mappings usable."""
    return [
        dc for dc in estate.dcs
        if dc.strong_certificate_binding_enforcement in _BINDING_NON_STRICT
    ]


def _esc14_enforcement_resolved(estate: Estate) -> bool:
    """True when DC enforcement is known well enough to decide ESC14.

    Resolved when some DC is known non-strict (ESC14 is exploitable there), or
    when the DC registry pass ran, found DCs, and every one reported a known
    value (all strict → weak mappings are mitigated). Otherwise ESC14 degrades
    to the ``ESC14_ENFORCEMENT_UNKNOWN`` note.
    """
    if _non_strict_dcs(estate):
        return True
    return (
        _pass_collected(estate, _ESC10_DC_REGISTRY_PASS)
        and _dcs_discovered(estate)
        and all(_dc_binding_known(dc) for dc in estate.dcs)
    )


# Finding subject / source helpers shared by detectors and coverage_gaps(), so a
# per-object coverage gap names exactly the subject a finding would carry.
def _template_subject(tmpl: CertTemplate) -> str:
    return tmpl.display_name or tmpl.name


def _template_owner_source(tmpl: CertTemplate) -> str:
    return f"template '{tmpl.name}': nTSecurityDescriptor owner"


def _pki_subject(obj: PkiObjectAcl) -> str:
    return obj.object_dn or obj.kind.value


def _pki_owner_source(obj: PkiObjectAcl) -> str:
    return f"{_pki_subject(obj)}: nTSecurityDescriptor owner"


def _ca_owner_source(ca: CertAuthority) -> str:
    return f"{ca.config_string or ca.name}: CA\\Security owner"


def _cert_subject(cert_subject: str, ca_name: str) -> str:
    return cert_subject or ca_name


# --- Stable object identity ---------------------------------------------------
LIFECYCLE_TYPES: frozenset[str] = frozenset({"cert", "crl"})


@dataclass(frozen=True)
class ObjectRef:
    """Identity of an exported object.

    ``guid`` is the AD objectGUID (collector >= 0.9.0) — immutable across
    renames and moves. ``aliases`` are the legacy identifiers (OID, cn, DN,
    DNS name, certificate fingerprint), lower-cased where AD compares them
    case-insensitively; they are used only when a GUID is missing on either
    side, and only when unambiguous (see diff.py).
    """

    type: str
    guid: str = ""
    aliases: tuple[str, ...] = ()

    @property
    def key(self) -> str:
        """Unique within one export when identity is unambiguous."""
        if self.guid:
            return f"g:{self.type}:{self.guid}"
        return f"a:{self.type}:" + "|".join(sorted(self.aliases))


def _template_ref(tmpl: CertTemplate) -> ObjectRef:
    aliases = []
    if tmpl.oid:
        aliases.append(f"oid:{tmpl.oid.lower()}")
    if tmpl.name:
        aliases.append(f"cn:{tmpl.name.lower()}")
    return ObjectRef("template", tmpl.object_guid, tuple(aliases))


def _pki_ref(obj: PkiObjectAcl) -> ObjectRef:
    return ObjectRef("pki", obj.object_guid, (f"dn:{(obj.object_dn or obj.kind.value).lower()}",))


def _ca_ref(ca: CertAuthority) -> ObjectRef:
    return ObjectRef("ca", ca.object_guid, (f"cn:{ca.name.lower()}",))


def _dc_ref(dc: DcConfiguration) -> ObjectRef:
    return ObjectRef("dc", dc.object_guid, (f"dns:{dc.name.lower()}",))


def _principal_ref(principal: PrincipalMapping) -> ObjectRef:
    return ObjectRef("principal", principal.object_guid, (f"dn:{principal.dn.lower()}",))


def _endpoint_ref(ep: EnrollmentEndpoint) -> ObjectRef:
    return ObjectRef("endpoint", "", (f"app:{ep.kind.value}:{(ep.name or ep.kind.value).lower()}",))


def _cert_ref(cert: CertLifecycle, ca_name: str) -> ObjectRef:
    if cert.fingerprint:
        return ObjectRef("cert", "", (f"sha256:{cert.fingerprint}",))
    stamp = cert.not_after.isoformat() if cert.not_after else ""
    return ObjectRef("cert", "", (f"cert:{ca_name.lower()}|{cert.subject}|{stamp}",))


def _crl_ref(crl: Crl) -> ObjectRef:
    return ObjectRef("crl", crl.object_guid, (f"crl:{crl.issuer.lower()}|{crl.source}",))


def estate_objects(estate: Estate) -> tuple[ObjectRef, ...]:
    """Every identity-bearing object in *estate* (the drift inventory)."""
    refs: list[ObjectRef] = [_template_ref(t) for t in estate.templates]
    refs += [_pki_ref(o) for o in estate.acls]
    refs += [_ca_ref(c) for c in estate.cas]
    refs += [_dc_ref(d) for d in estate.dcs]
    refs += [_principal_ref(p) for p in estate.principal_mappings]
    refs += [_endpoint_ref(e) for e in estate.endpoints]
    refs += [_cert_ref(cert, name) for name, _kind, cert in _all_certs(estate)]
    refs += [_crl_ref(c) for c in estate.crls]
    return tuple(refs)


# --- Evaluation records ------------------------------------------------------
# A detector calls _evaluated(check, ref[, variant]) at the point where every
# input it needs for that object is present, and _container_evaluated(check,
# type) when it enumerated every object of that type. diff resolves an older
# finding ONLY on such a record in the newer estate, so a skipped input, an
# early return, a filter or a forgotten gate means "not recorded" and therefore
# "withheld" — safe by construction. What remains is a check placed AFTER the
# record point; tests/test_detection_records.py classifies those structurally.


@dataclass
class _Recorder:
    objects: set[tuple[str, str, str]] = field(default_factory=set)
    containers: set[tuple[str, str]] = field(default_factory=set)


_RECORDER: ContextVar[_Recorder | None] = ContextVar("adcs_lens_recorder", default=None)


def _evaluated(check: str, ref: ObjectRef, variant: str = "") -> None:
    """Record that *check* was fully evaluated for the object *ref*.

    *variant* "" covers the finding's base variant; a trailing "*" (e.g.
    "trustee:*") covers every variant with that prefix.
    """
    rec = _RECORDER.get()
    if rec is not None:
        rec.objects.add((check, variant, ref.key))


def _container_evaluated(check: str, object_type: str) -> None:
    """Record that *check* enumerated every *object_type* object in the estate."""
    rec = _RECORDER.get()
    if rec is not None:
        rec.containers.add((check, object_type))


def _all_certs(estate: Estate) -> list[tuple[str, CaKind | None, CertLifecycle]]:
    """Every parsed CA certificate as (ca name, CA kind or None, cert).

    Includes certificates whose ca_name matched no CA in ca-config.json (the
    offline root is the usual case) with kind None, so they are evaluated
    rather than silently dropped.
    """
    out: list[tuple[str, CaKind | None, CertLifecycle]] = [
        (ca.name, ca.kind, cert) for ca in estate.cas for cert in ca.certs
    ]
    out.extend((name, None, cert) for name, cert in estate.unattached_certs)
    return out


# Passes that already have a dedicated degradation note naming them.
_PASSES_WITH_DEDICATED_NOTE: frozenset[str] = frozenset(
    {
        "template-security",
        "pki-acls",
        "ca-security",
        "enrollment-endpoints",
        "esc10-dc-registry",
        "esc14-altsecid",
        "certs",
    }
)


def detect_collection_gaps(estate: Estate) -> list[Finding]:
    """Name collector-level coverage gaps that no other detector reports.

    * ``COLLECTOR_VERSION_UNVERIFIED`` — the collector version is missing,
      unknown, unparseable, or older than the core's minimum, so the export's
      per-object coverage markers cannot be trusted (an absent field defaults
      to "collected"). The export is still evaluated; this keeps it from reading
      as current.
    * ``PASS_NOT_COLLECTED`` — one per pass whose export file is missing (only
      possible for an unverified collector; ingest rejects it otherwise), and one
      per declared-skipped pass that has no dedicated note of its own (the core
      files ca-config / templates / oid-objects / enrollment-services).
    """
    findings: list[Finding] = []
    m = estate.manifest
    if not _collector_verified(estate):
        shown = m.collector_version or "(missing)"
        findings.append(
            Finding(
                check="COLLECTOR_VERSION_UNVERIFIED",
                severity=Severity.INFO,
                title="Collector version not verified as current",
                subject="(estate)",
                detail=(
                    f"The export's collector version is {shown!r} "
                    f"({m.collector_version_status.value}), so it cannot be confirmed to "
                    "emit every field the detectors rely on. Absent per-object coverage "
                    "markers (DACL obtained, CA registry collected, owners) default to "
                    "'collected', so a finding missing here is not proof of a fix, and "
                    "diff withholds every resolution against this export. Re-run a "
                    "current collector."
                ),
                source=f"collector-manifest.json: collector_version={shown!r}",
            )
        )
    for pass_name in sorted(m.uncollected_passes & KNOWN_PASSES):
        missing = pass_name in m.missing_passes
        if not missing and pass_name in _PASSES_WITH_DEDICATED_NOTE:
            continue
        file_name = PASS_FILES.get(pass_name, pass_name)
        cause = (
            f"{file_name} is missing from the export (the collector version is not "
            "verified, so this is recorded as a gap rather than rejected)"
            if missing
            else "the manifest lists it in skipped_passes"
        )
        findings.append(
            Finding(
                check="PASS_NOT_COLLECTED",
                severity=Severity.INFO,
                title=f"Collector pass '{pass_name}' not collected",
                subject=pass_name,
                detail=(
                    f"Pass '{pass_name}' was not collected: {cause}. Every check that "
                    "depends on it is unevaluated for this export, and diff withholds "
                    "their resolutions. Re-run the collector and copy the complete export."
                ),
                source=_uncollected_source(estate, pass_name),
            )
        )
    return findings


def detect_esc6(estate: Estate) -> list[Finding]:
    """Flag any CA with ``EDITF_ATTRIBUTESUBJECTALTNAME2`` set.

    With this flag a requester can put an arbitrary SAN (e.g. a domain admin
    UPN) into *any* issued certificate, regardless of template — a CA-wide
    privilege-escalation primitive. Statically readable from the CA policy
    registry; we flag the enabling flag, we do not request a certificate.

    Unlike ESC11/ESC16 (which skip ``CaKind.ROOT``), ESC6 is reported for every
    CA kind, including an offline root. The reasoning differs: ESC11/ESC16
    gate a *relay/mapping* path that needs the CA to serve AD-auth end-entity
    enrollment, which an offline root never does. ESC6 is a per-CA policy flag
    (it does not propagate via the CA hierarchy): a root with it set would
    honor requester-supplied SANs on the certificates *it* issues — i.e.
    subordinate CA certs — which is a configuration smell regardless of whether
    the root is currently online. It is surfaced, not silently passed.
    Remediation is the same regardless of tier.

    CAs whose registry configuration was not collected
    (``registry_config_collected`` False — e.g. a multi-CA estate where the
    collector ran on a different host) are skipped: an empty ``edit_flags``
    would read as a silent clean. The ``CA_REGISTRY_NOT_EVALUATED`` note names
    them.
    """
    findings: list[Finding] = []
    if _pass_collected(estate, "ca-config"):
        _container_evaluated("ESC6", "ca")
    for ca in estate.cas:
        if not _ca_registry_collected(ca):
            continue
        _evaluated("ESC6", _ca_ref(ca))
        if _EDITF_SAN2 in ca.edit_flags:
            findings.append(
                Finding(
                    check="ESC6",
                    object_ref=_ca_ref(ca),
                    evidence_complete=True,
                    severity=Severity.CRITICAL,
                    title="CA honors requester-supplied SAN (EDITF_ATTRIBUTESUBJECTALTNAME2)",
                    subject=ca.name,
                    detail=(
                        "Requesters can specify an arbitrary subjectAltName on any "
                        "template this CA issues, enabling authentication as any "
                        "principal. Remove the flag: certutil -setreg "
                        "policy\\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2, then "
                        "restart certsvc."
                    ),
                    source=f"{ca.config_string} policy\\EditFlags",
                )
            )
    return findings


def _can_authenticate(template: CertTemplate) -> bool:
    """True if the template's EKUs permit client authentication.

    A template with no EKU at all is valid for any purpose, so it qualifies too.
    """
    if not template.ekus:
        return True
    return any(eku in _AUTH_EKUS for eku in template.ekus)


def _blocked_rights(security: tuple[AceEntry, ...], trustee_sid: str) -> frozenset[str]:
    """Rights blocked for *trustee_sid* by explicit Deny ACEs, expanded by implication.

    A Deny of a right blocks that right and every right it covers (per
    ``_COVERS``). Only same-trustee Deny ACEs are considered — group-token
    expansion (a Deny on a group the requester belongs to) is out of scope: the
    collector exposes only the ACE trustee SID, not the requester's full group
    token, so we match on the ACE's own trustee SID.
    """
    sid = normalize_sid(trustee_sid)
    blocked: set[str] = set()
    for ace in security:
        if ace.ace_type is not AceType.DENY:
            continue
        if normalize_sid(ace.trustee_sid) != sid:
            continue
        for r in ace.rights:
            blocked |= _COVERS.get(r.strip().lower(), frozenset())
    return frozenset(blocked)


def _low_priv_allow_aces_in(
    security: tuple[AceEntry, ...], rights: frozenset[str]
) -> list[AceEntry]:
    """Allow-ACEs in *security* granting any of *rights* (lower-cased) to low-priv,
    after Deny precedence: a right that is blocked by an explicit Deny on the same
    trustee does not count. Broad rights (e.g. GenericAll) satisfy only if they cover
    at least one requested right that is not blocked. An ACE is kept only if at least
    one of its granting rights survives, so a trustee fully blocked by Deny yields no
    ACE here (the capability is suppressed)."""
    out: list[AceEntry] = []
    for ace in security:
        if ace.ace_type is not AceType.ALLOW:
            continue
        if not is_low_priv_trustee(ace.trustee_sid):
            continue
        blocked = _blocked_rights(security, ace.trustee_sid)
        for r in ace.rights:
            token = r.strip().lower()
            covers = _COVERS.get(token, frozenset({token}))
            if (covers & rights) - blocked:
                out.append(ace)
                break
    return out


def _low_priv_allow_aces(
    template: CertTemplate, rights: frozenset[str]
) -> list[AceEntry]:
    """Allow-ACEs granting any of *rights* (lower-cased match) to a low-priv trustee."""
    return _low_priv_allow_aces_in(template.security, rights)


def _low_priv_enrollers(template: CertTemplate) -> list[AceEntry]:
    """Allow-ACEs that grant (or imply) enroll to a low-privilege trustee."""
    return _low_priv_allow_aces(template, _ENROLL_RIGHTS)


def _normalized_publishers(template: CertTemplate) -> tuple[str, ...]:
    """Return non-blank publisher names, de-duplicated and deterministically sorted."""
    return tuple(sorted({name.strip() for name in template.published_by if name.strip()}))


def _publication_data_available(estate: Estate) -> bool:
    """Return whether the enrollment-services export was present and valid."""
    return estate.manifest.enrollment_services_available


def _template_publication_detail(
    template: CertTemplate, *, publication_data_available: bool
) -> str:
    """Render publication state without treating it as a detector gate."""
    publishers = _normalized_publishers(template)
    if publishers:
        publisher_list = ", ".join(publishers)
        return f"Publication state: published by {publisher_list}."
    if publication_data_available:
        return "Publication state: confirmed unpublished (not offered by any CA)."
    return "Publication state: unknown (enrollment-services export absent or unevaluated)."


def _scoped_writeproperty_guids(rights: tuple[str, ...]) -> set[str]:
    """Extract dangerous property GUIDs from scoped WriteProperty tokens.

    The collector (v0.6.2+) emits ``writeproperty:<guid>`` for a WriteProperty
    ACE whose ObjectType is a non-zero GUID. A bare ``writeproperty`` (no GUID,
    from an older collector) yields nothing — backward-compatible exclusion of
    unknown-scope writes (WI-019).
    """
    guids: set[str] = set()
    for r in rights:
        token = r.strip().lower()
        if not token.startswith("writeproperty:"):
            continue
        guid = token[len("writeproperty:"):]
        if guid in _DANGEROUS_PROPERTY_GUIDS:
            guids.add(guid)
    return guids


def _low_priv_dangerous_writeproperty_aces(
    security: tuple[AceEntry, ...],
) -> list[tuple[AceEntry, set[str]]]:
    """Allow-ACEs granting a low-priv trustee a scoped WriteProperty on a
    dangerous template property, after Deny precedence.

    Returns ``(ace, guids)`` pairs where *guids* is the set of dangerous
    property GUIDs the ACE reaches that are not blocked by an explicit Deny
    on the same trustee.
    """
    out: list[tuple[AceEntry, set[str]]] = []
    for ace in security:
        if ace.ace_type is not AceType.ALLOW:
            continue
        if not is_low_priv_trustee(ace.trustee_sid):
            continue
        dangerous = _scoped_writeproperty_guids(ace.rights)
        if not dangerous:
            continue
        blocked = _blocked_scoped_writeproperty(security, ace.trustee_sid)
        surviving = dangerous - blocked
        if surviving:
            out.append((ace, surviving))
    return out


def _blocked_scoped_writeproperty(
    security: tuple[AceEntry, ...], trustee_sid: str
) -> set[str]:
    """Dangerous property GUIDs blocked for *trustee_sid* by explicit Deny ACEs.

    A Deny of ``writeproperty:<guid>`` blocks that specific scoped write. A
    blanket ``writepropertyall`` Deny blocks every scoped write (it covers all
    properties). Broad rights that cover WritePropertyAll — ``genericall``,
    ``fullcontrol``, and ``genericwrite`` — also block every scoped write, since
    a Deny of any right covering ``writepropertyall`` suppresses scoped writes
    under Windows access-mask semantics. That implication is delegated to
    ``_blocked_rights`` (which expands the ``_COVERS`` map), so a GenericAll /
    FullControl / GenericWrite Deny does not leave a stray scoped-WriteProperty
    Allow finding (a false positive). Same-trustee Deny ACEs only — group-token
    expansion is out of scope (mirrors ``_blocked_rights``).
    """
    sid = normalize_sid(trustee_sid)
    blocked: set[str] = set()
    # A broad Deny (GenericAll / FullControl / GenericWrite / WritePropertyAll)
    # covers WritePropertyAll and so blocks every scoped write. ``_blocked_rights``
    # already expands the ``_COVERS`` implications, so membership of
    # "writepropertyall" in the blocked set catches all of them in one shot.
    if "writepropertyall" in _blocked_rights(security, trustee_sid):
        blocked |= _DANGEROUS_PROPERTY_GUIDS
    for ace in security:
        if ace.ace_type is not AceType.DENY:
            continue
        if normalize_sid(ace.trustee_sid) != sid:
            continue
        for r in ace.rights:
            token = r.strip().lower()
            if token == "writepropertyall":
                blocked |= _DANGEROUS_PROPERTY_GUIDS
            elif token.startswith("writeproperty:"):
                guid = token[len("writeproperty:"):]
                if guid in _DANGEROUS_PROPERTY_GUIDS:
                    blocked.add(guid)
    return blocked


def _template_container(estate: Estate, check: str, *extra_passes: str) -> None:
    """Record that *check* enumerated every template (templates + ACL passes ran)."""
    if all(_pass_collected(estate, p) for p in ("templates", *extra_passes)):
        _container_evaluated(check, "template")


def _template_security_collected(estate: Estate) -> bool:
    return _pass_collected(estate, _TEMPLATE_SECURITY_PASS)


def detect_esc1(estate: Estate) -> list[Finding]:
    """Flag templates that let a low-priv user enroll a cert naming any subject.

    ESC1 holds when a template (a) lets the requester supply the subject/SAN,
    (b) carries a client-authentication EKU (or no EKU), (c) does not require CA
    manager approval, and (d) is enrollable by a low-privilege principal. A
    domain user can then request a certificate *as* a domain admin and
    authenticate as them. Every condition is statically readable; we never
    enroll.

    Degrades honestly: when template security descriptors were not collected
    (collector Phase 1b — ``template-security`` in ``skipped_passes``) the enroll
    ACL cannot be evaluated, so this emits one INFO note instead of silently
    passing.
    """
    if not _template_security_collected(estate):
        return [
            Finding(
                check="TEMPLATE_ACL_NOT_EVALUATED",
                severity=Severity.INFO,
                title="Template enroll permissions not evaluated",
                subject="(estate)",
                detail=(
                    "The export did not include template security descriptors, so "
                    "ESC1 and ESC9 enroll-permission checks were skipped. Re-run a "
                    "collector that captures template nTSecurityDescriptor ACEs "
                    "(Phase 1b)."
                ),
                source=_uncollected_source(estate, "template-security"),
            )
        ]
    findings: list[Finding] = []
    _template_container(estate, "ESC1", _TEMPLATE_SECURITY_PASS)
    publication_data_available = _publication_data_available(estate)
    for tmpl in estate.templates:
        if not _template_acl_readable(tmpl):
            continue
        _evaluated("ESC1", _template_ref(tmpl))
        if not (tmpl.name_flags & _ENROLLEE_SUPPLIES_SUBJECT):
            continue
        if not _can_authenticate(tmpl):
            continue
        if _MANAGER_APPROVAL in tmpl.enrollment_flags:
            continue
        enrollers = _low_priv_enrollers(tmpl)
        if not enrollers:
            continue
        who = ", ".join(sorted({a.trustee_name or a.trustee_sid for a in enrollers}))
        publication = _template_publication_detail(
            tmpl, publication_data_available=publication_data_available
        )
        findings.append(
            Finding(
                check="ESC1",
                object_ref=_template_ref(tmpl),
                evidence_complete=True,
                severity=Severity.CRITICAL,
                title="Template lets a low-priv enrollee supply subject + authenticate",
                subject=_template_subject(tmpl),
                detail=(
                    f"Enrollable by {who}; the requester supplies the subject/SAN and "
                    "the template carries a client-authentication EKU (or none) with no "
                    "manager approval — a domain user can enroll as any principal. "
                    f"{publication} "
                    "Restrict enroll rights, require manager approval, or clear the "
                    "enrollee-supplies-subject flag. (Confirm no issuance/RA-signature "
                    "requirement also gates it — not yet modeled.)"
                ),
                source=f"template '{tmpl.name}' (oid {tmpl.oid}): name flags + enroll ACL",
            )
        )
    return findings


def detect_esc2(estate: Estate) -> list[Finding]:
    """Flag any-purpose / no-EKU templates enrollable by low-priv principals.

    ESC2: a template defines the Any-Purpose EKU (or no EKU at all) and a
    low-privilege principal can enroll without manager approval. The issued
    certificate is valid for *any* use — including client authentication — so a
    domain user obtains a broadly-usable credential. Statically readable from the
    EKU list + enroll ACL.

    Returns nothing when template security wasn't collected (ESC1 emits the
    single degradation note).
    """
    if not _template_security_collected(estate):
        return []
    findings: list[Finding] = []
    _template_container(estate, "ESC2", _TEMPLATE_SECURITY_PASS)
    publication_data_available = _publication_data_available(estate)
    for tmpl in estate.templates:
        if not _template_acl_readable(tmpl):
            continue
        _evaluated("ESC2", _template_ref(tmpl))
        any_purpose = (not tmpl.ekus) or (_ANY_PURPOSE in tmpl.ekus)
        if not any_purpose:
            continue
        if _MANAGER_APPROVAL in tmpl.enrollment_flags:
            continue
        enrollers = _low_priv_enrollers(tmpl)
        if not enrollers:
            continue
        who = ", ".join(sorted({a.trustee_name or a.trustee_sid for a in enrollers}))
        kind = "no EKU" if not tmpl.ekus else "the Any-Purpose EKU"
        publication = _template_publication_detail(
            tmpl, publication_data_available=publication_data_available
        )
        findings.append(
            Finding(
                check="ESC2",
                object_ref=_template_ref(tmpl),
                evidence_complete=True,
                severity=Severity.HIGH,
                title="Any-purpose / no-EKU template enrollable by low-priv",
                subject=_template_subject(tmpl),
                detail=(
                    f"Enrollable by {who}; the template defines {kind}, so the issued "
                    "cert is valid for any purpose (including client authentication). "
                    f"{publication} "
                    "Constrain the EKU set, require manager approval, or restrict "
                    "enroll rights."
                ),
                source=f"template '{tmpl.name}' (oid {tmpl.oid}): EKU list + enroll ACL",
            )
        )
    return findings


def detect_esc3(estate: Estate) -> list[Finding]:
    """Flag enrollment-agent templates enrollable by low-priv principals.

    ESC3: a template carries the Certificate Request Agent EKU and a
    low-privilege principal can enroll without manager approval. The resulting
    enrollment-agent certificate lets the holder request certificates *on behalf
    of other principals* — a path to impersonation. We flag the enabling
    template; the on-behalf-of request itself is out of scope.

    Returns nothing when template security wasn't collected (ESC1 emits the
    single degradation note).
    """
    if not _template_security_collected(estate):
        return []
    findings: list[Finding] = []
    _template_container(estate, "ESC3", _TEMPLATE_SECURITY_PASS)
    publication_data_available = _publication_data_available(estate)
    for tmpl in estate.templates:
        if not _template_acl_readable(tmpl):
            continue
        _evaluated("ESC3", _template_ref(tmpl))
        if _ENROLLMENT_AGENT_EKU not in tmpl.ekus:
            continue
        if _MANAGER_APPROVAL in tmpl.enrollment_flags:
            continue
        enrollers = _low_priv_enrollers(tmpl)
        if not enrollers:
            continue
        who = ", ".join(sorted({a.trustee_name or a.trustee_sid for a in enrollers}))
        publication = _template_publication_detail(
            tmpl, publication_data_available=publication_data_available
        )
        findings.append(
            Finding(
                check="ESC3",
                object_ref=_template_ref(tmpl),
                evidence_complete=True,
                severity=Severity.HIGH,
                title="Enrollment-agent template enrollable by low-priv",
                subject=_template_subject(tmpl),
                detail=(
                    f"Enrollable by {who}; the template grants the Certificate Request "
                    "Agent EKU, so the holder can request certificates on behalf of "
                    f"other principals. {publication} "
                    "Restrict enroll rights or require manager "
                    "approval."
                ),
                source=f"template '{tmpl.name}' (oid {tmpl.oid}): EKU list + enroll ACL",
            )
        )
    return findings


def detect_esc4(estate: Estate) -> list[Finding]:
    """Flag templates a low-privilege principal can rewrite (a path to ESC1).

    ESC4: a low-privilege trustee holds an object-wide control right (GenericAll,
    GenericWrite, WriteDacl, WriteOwner, or a *blanket* WriteProperty) on the
    template, **or** a low-privilege principal *owns* the template (an owner can
    rewrite the DACL to grant itself control). Either lets them edit the template
    — e.g. turn on enrollee-supplied subjects and add a client-auth EKU —
    converting it into ESC1. We flag the standing control right / ownership; we
    never modify the template.

    Shares the ESC1 degradation: when template security was not collected the
    ESC1 detector emits the single ``TEMPLATE_ACL_NOT_EVALUATED`` note, so this
    returns nothing rather than duplicating it.

    Scope: evaluates DACL control rights, owner-based control (WI-019), and
    property-*scoped* WriteProperty on dangerous template properties (WI-019).
    A scoped WriteProperty whose ObjectType is one of the well-known dangerous
    property GUIDs (msPKI-Certificate-Name-Flag, msPKI-Enrollment-Flag,
    pKIExtendedKeyUsage, msPKI-Certificate-Policy,
    msPKI-Certificate-Application-Policy) lets a low-priv principal flip the
    template into ESC1 just as object-wide control does. Bare ``writeproperty``
    (no GUID, from an older collector) is still excluded — the scope is unknown.
    Owner-based control is skipped when the owner was not captured
    (``owner_sid`` empty) — a known gap, never a false positive.
    """
    if not _template_security_collected(estate):
        return []
    findings: list[Finding] = []
    _template_container(estate, "ESC4", _TEMPLATE_SECURITY_PASS)
    for tmpl in estate.templates:
        if not _template_acl_readable(tmpl):
            continue
        ref = _template_ref(tmpl)
        _evaluated("ESC4", ref, "dacl")
        _evaluated("ESC4", ref, "scoped-writeproperty")
        controllers = _low_priv_allow_aces(tmpl, _DANGEROUS_TEMPLATE_CONTROL)
        if controllers:
            who = ", ".join(sorted({a.trustee_name or a.trustee_sid for a in controllers}))
            template_security = tmpl.security
            rights = ", ".join(
                sorted(
                    {
                        r
                        for a in controllers
                        for r in a.rights
                        if r.strip().lower() in _DANGEROUS_TEMPLATE_CONTROL
                        and r.strip().lower()
                        not in _blocked_rights(template_security, a.trustee_sid)
                    }
                )
            )
            findings.append(
                Finding(
                    check="ESC4",
                    object_ref=_template_ref(tmpl),
                    variant="dacl",
                    evidence_complete=True,
                    severity=Severity.HIGH,
                    title="Template object is writable by a low-privilege principal",
                    subject=_template_subject(tmpl),
                    detail=(
                        f"{who} hold {rights} on the template and can rewrite it (e.g. "
                        "enable enrollee-supplied subjects + a client-auth EKU) to create "
                        "an ESC1 path. Remove the delegated control."
                    ),
                    source=f"template '{tmpl.name}': nTSecurityDescriptor DACL",
                )
            )
        # Property-scoped WriteProperty on a dangerous property (WI-019): a
        # scoped write that reaches msPKI-Certificate-Name-Flag etc. is an ESC1
        # conversion path just like object-wide control, surfaced separately so
        # the remediation (narrow the scoped write) is distinct.
        scoped = _low_priv_dangerous_writeproperty_aces(tmpl.security)
        if scoped:
            who = ", ".join(
                sorted({a.trustee_name or a.trustee_sid for a, _ in scoped})
            )
            findings.append(
                Finding(
                    check="ESC4",
                    object_ref=_template_ref(tmpl),
                    variant="scoped-writeproperty",
                    evidence_complete=True,
                    severity=Severity.HIGH,
                    title=(
                        "Template has a dangerous property-scoped write "
                        "by a low-privilege principal"
                    ),
                    subject=_template_subject(tmpl),
                    detail=(
                        f"{who} hold a scoped WriteProperty on one or more dangerous "
                        "template properties (msPKI-Certificate-Name-Flag, "
                        "msPKI-Enrollment-Flag, pKIExtendedKeyUsage, "
                        "msPKI-Certificate-Policy, or msPKI-Certificate-Application-Policy) "
                        "and can rewrite it to create an ESC1 path. Narrow the scoped "
                        "write to non-dangerous properties or remove it."
                    ),
                    source=f"template '{tmpl.name}': nTSecurityDescriptor scoped WriteProperty",
                )
            )
        # Owner-based control (WI-019): a low-privilege owner can rewrite the
        # DACL to grant itself control even with no control ACE, so it is an
        # independent ESC4 path. Surfaced separately from the DACL finding.
        if _owner_captured(tmpl.owner_sid):
            _evaluated("ESC4", ref, "owner")
        if _owner_captured(tmpl.owner_sid) and is_low_priv_trustee(tmpl.owner_sid):
            findings.append(
                Finding(
                    check="ESC4",
                    object_ref=_template_ref(tmpl),
                    variant="owner",
                    evidence_complete=True,
                    severity=Severity.HIGH,
                    title="Template is owned by a low-privilege principal",
                    subject=_template_subject(tmpl),
                    detail=(
                        f"The template owner is a low-privilege principal "
                        f"({tmpl.owner_sid}). As the owner it can rewrite the template's "
                        "DACL to grant itself control and then convert the template into an "
                        "ESC1 path. Reset ownership to a privileged account (e.g. Domain Admins)."
                    ),
                    source=_template_owner_source(tmpl),
                )
            )
    return findings


def detect_esc5(estate: Estate) -> list[Finding]:
    """Flag PKI container / CA objects writable by a low-privilege principal.

    ESC5: a low-priv trustee holds an object-wide control right (GenericAll,
    GenericWrite, WriteDacl, WriteOwner, or a *blanket* WriteProperty) on a
    Public Key Services object — NTAuthCertificates, a CA object, the AIA/CDP
    containers, or a PKS container — **or** a low-priv principal owns the object
    (an owner can rewrite the DACL to grant itself control). Each grants a
    distinct escalation: writing NTAuth publishes a rogue trusted CA; writing a
    CA object reconfigures issuance; writing AIA/CDP tampers with chain/revocation.
    We flag the standing control right / ownership; we never modify the object.

    Degrades to a note when the PKI-ACL pass was not collected (``pki-acls`` in
    ``skipped_passes``) so the absence of findings is not mistaken for a clean
    result. Property-*scoped* WriteProperty is not flagged (mirrors ESC4): only
    blanket object-control rights are treated as control. Owner-based control is
    skipped when the owner was not captured (``owner_sid`` empty) — a known gap,
    never a false positive.
    """
    if not _pass_collected(estate, _PKI_ACLS_PASS):
        return [
            Finding(
                check="PKI_ACL_NOT_EVALUATED",
                severity=Severity.INFO,
                title="PKI object permissions not evaluated",
                subject="(estate)",
                detail=(
                    "The export did not include PKI-object security descriptors, so "
                    "ESC5 (writable NTAuth / CA object / PKS container) was skipped. "
                    "Re-run a collector that captures the pki-acls pass."
                ),
                source=_uncollected_source(estate, "pki-acls"),
            )
        ]
    findings: list[Finding] = []
    _container_evaluated("ESC5", "pki")
    for obj in estate.acls:
        if not _pki_acl_readable(obj):
            continue  # unreadable DACL — the PKI_ACL_UNREADABLE note surfaces it
        ref = _pki_ref(obj)
        _evaluated("ESC5", ref, "dacl")
        if _owner_captured(obj.owner_sid):
            _evaluated("ESC5", ref, "owner")
        severity, impact = _ESC5_IMPACT.get(
            obj.kind,
            (Severity.HIGH, "a Public Key Services object"),
        )
        controllers = _low_priv_allow_aces_in(obj.security, _DANGEROUS_OBJECT_CONTROL)
        if controllers:
            who = ", ".join(sorted({a.trustee_name or a.trustee_sid for a in controllers}))
            rights = ", ".join(
                sorted(
                    {
                        r
                        for a in controllers
                        for r in a.rights
                        if r.strip().lower() in _DANGEROUS_OBJECT_CONTROL
                        and r.strip().lower() not in _blocked_rights(obj.security, a.trustee_sid)
                    }
                )
            )
            findings.append(
                Finding(
                    check="ESC5",
                    object_ref=_pki_ref(obj),
                    variant="dacl",
                    evidence_complete=True,
                    severity=severity,
                    title="PKI object is writable by a low-privilege principal",
                    subject=_pki_subject(obj),
                    detail=(
                        f"{who} hold {rights} on {impact}. Remove the delegated control."
                    ),
                    source=f"{obj.object_dn or obj.kind.value}: nTSecurityDescriptor DACL",
                )
            )
        # Owner-based control (WI-019): a low-privilege owner can rewrite the
        # DACL to grant itself control even with no control ACE.
        if _owner_captured(obj.owner_sid) and is_low_priv_trustee(obj.owner_sid):
            findings.append(
                Finding(
                    check="ESC5",
                    object_ref=_pki_ref(obj),
                    variant="owner",
                    evidence_complete=True,
                    severity=severity,
                    title="PKI object is owned by a low-privilege principal",
                    subject=_pki_subject(obj),
                    detail=(
                        f"The owner of {impact} is a low-privilege principal "
                        f"({obj.owner_sid}). As the owner it can rewrite the object's "
                        "DACL to grant itself control. Reset ownership to a privileged "
                        "account (e.g. Domain Admins)."
                    ),
                    source=_pki_owner_source(obj),
                )
            )
    return findings


def detect_esc7(estate: Estate) -> list[Finding]:
    """Flag CA role rights (Manage CA / Manage Certificates) held by low-priv.

    ESC7: a low-privilege principal holds **Manage CA** (can flip CA policy — e.g.
    turn on EDITF_ATTRIBUTESUBJECTALTNAME2 → ESC6, or publish a vulnerable
    template) or **Manage Certificates** (can approve pending requests / revoke).
    Read from the CA's ``CA\\Security`` registry descriptor; we flag the standing
    right, we never exercise it. Broad rights (GenericAll / FullControl) that
    imply a CA role are recognized via the ``_COVERS`` implication map, so a
    low-privilege trustee granted blanket CA control is not silently missed.

    Owner-based control (WI-037): a low-privilege *owner* of ``CA\\Security`` can
    rewrite the DACL to grant itself Manage CA — the CA-level analogue of ESC4/
    ESC5 owner control — and is flagged separately (distinct vector and
    remediation: reset ownership). Skipped when the owner was not captured.

    Degrades to a note when the CA security descriptor was not collected.
    """
    if not _pass_collected(estate, _CA_SECURITY_PASS):
        return [
            Finding(
                check="CA_SECURITY_NOT_EVALUATED",
                severity=Severity.INFO,
                title="CA role permissions not evaluated",
                subject="(estate)",
                detail=(
                    "The export did not include the CA security descriptor, so ESC7 "
                    "(Manage CA / Manage Certificates held by low-priv) was skipped. "
                    "Re-run a collector that captures CA\\Security."
                ),
                source=_uncollected_source(estate, "ca-security"),
            )
        ]
    findings: list[Finding] = []
    if _pass_collected(estate, "ca-config"):
        _container_evaluated("ESC7", "ca")
    for ca in estate.cas:
        # The CA security descriptor is read from the CA host's local registry;
        # when it was not collected for this CA (registry_config_collected False)
        # an empty security tuple would read as a silent clean. The
        # CA_REGISTRY_NOT_EVALUATED note names such CAs.
        if not _ca_registry_collected(ca):
            continue
        ref = _ca_ref(ca)
        if _ca_security_readable(ca):
            _evaluated("ESC7", ref, "trustee:*")
        if _owner_captured(ca.owner_sid):
            _evaluated("ESC7", ref, "owner")
        if not _ca_security_readable(ca):
            # ca-security.json carried no entry for this CA, so its DACL never
            # reached the export: name the gap instead of reading "no ACEs" as a
            # clean CA. (Owner-based control below is still evaluated — the
            # owner comes from ca-config.json.)
            findings.append(
                Finding(
                    check="CA_SECURITY_NOT_EVALUATED",
                    severity=Severity.INFO,
                    title=f"CA role permissions not evaluated for {ca.name}",
                    subject=ca.name,
                    detail=(
                        f"ca-security.json has no entry for {ca.name}, so its CA\\Security "
                        "DACL was not evaluated for ESC7 (Manage CA / Manage Certificates "
                        "held by low-priv). Re-run the collector on this CA."
                    ),
                    source=f"{ca.config_string or ca.name}: no ca-security.json entry",
                )
            )
        by_trustee: dict[str, tuple[str, set[str]]] = {}
        for ace in ca.security:
            if ace.ace_type is not AceType.ALLOW:
                continue
            if not is_low_priv_trustee(ace.trustee_sid):
                continue
            blocked = _blocked_rights(ca.security, ace.trustee_sid)
            # Expand broad rights via _COVERS so GenericAll / FullControl (which
            # cover ManageCA / ManageCertificates) are not silently missed — a
            # raw intersection of ace.rights with the two role tokens would skip
            # them entirely, a domain-compromise-class false negative.
            manage: set[str] = set()
            for r in ace.rights:
                token = r.strip().lower()
                manage |= _COVERS.get(token, frozenset({token})) & {
                    _CA_MANAGE_CA,
                    _CA_MANAGE_CERTS,
                }
            manage -= blocked
            if not manage:
                continue
            _, rights = by_trustee.setdefault(ace.trustee_sid, (ace.trustee_name, set()))
            rights |= manage
        for sid, (name, rights) in by_trustee.items():
            who = name or sid
            if _CA_MANAGE_CA in rights:
                severity = Severity.CRITICAL
                role = "Manage CA (full CA control)"
            else:
                severity = Severity.HIGH
                role = "Manage Certificates (approve/issue/revoke)"
            findings.append(
                Finding(
                    check="ESC7",
                    object_ref=_ca_ref(ca),
                    variant=f"trustee:{sid}",
                    evidence_complete=True,
                    severity=severity,
                    title="CA role right held by a low-privilege principal",
                    subject=ca.name,
                    detail=(
                        f"{who} holds {role} on this CA. Manage CA can flip CA policy "
                        "(e.g. enable requester-supplied SANs → ESC6) or publish a "
                        "vulnerable template; Manage Certificates can approve pending "
                        "requests. Remove the role from low-privilege principals."
                    ),
                    source=f"{ca.config_string or ca.name}: CA\\Security",
                    sid=sid,
                )
            )
        # Owner-based control (WI-037): a low-privilege owner of CA\\Security can
        # rewrite the DACL to grant itself Manage CA — the CA-level analogue of
        # ESC4/ESC5 owner control. Emitted as a distinct finding (distinct vector
        # and remediation: reset ownership, not just remove an ACE). Skipped when
        # the owner was not captured (a known gap, never a false positive).
        if _owner_captured(ca.owner_sid) and is_low_priv_trustee(ca.owner_sid):
            findings.append(
                Finding(
                    check="ESC7",
                    object_ref=_ca_ref(ca),
                    variant="owner",
                    evidence_complete=True,
                    severity=Severity.CRITICAL,
                    title="CA security descriptor owned by a low-privilege principal",
                    subject=ca.name,
                    detail=(
                        f"The owner of this CA's security descriptor ({ca.owner_sid}) "
                        "is a low-privilege principal. As the owner it can rewrite the "
                        "DACL to grant itself Manage CA (full CA control) or Manage "
                        "Certificates. Reset ownership to a privileged account."
                    ),
                    source=_ca_owner_source(ca),
                    sid=ca.owner_sid,
                )
            )
    return findings


def detect_esc8(estate: Estate) -> list[Finding]:
    """Flag HTTP enrollment endpoints that enable an NTLM relay to certificates.

    ESC8: a Windows-authenticated enrollment endpoint (Web Enrollment ``/certsrv``
    or CES) that accepts NTLM without Extended Protection (channel binding), and/
    or is reachable over cleartext HTTP. An attacker who coerces a privileged
    account (e.g. a DC via PetitPotam) can relay its NTLM authentication to the
    endpoint and obtain a certificate *as that account*. We flag the enabling
    configuration; the relay itself is out of scope and never confirmed here.

    Mitigated (not flagged) when Extended Protection is *required* and the
    endpoint is HTTPS-only. Kerberos-only endpoints (no NTLM/Negotiate) are not
    relayable and are skipped. Degrades to a note when the endpoint pass was not
    collected.
    """
    if not _pass_collected(estate, _ESC8_ENDPOINTS_PASS):
        return [
            Finding(
                check="ENROLLMENT_ENDPOINTS_NOT_EVALUATED",
                severity=Severity.INFO,
                title="HTTP enrollment endpoints not evaluated",
                subject="(estate)",
                detail=(
                    "The export did not include the enrollment-endpoint pass, so ESC8 "
                    "(NTLM relay to Web Enrollment / CES) was skipped. Re-run a "
                    "collector that captures IIS enrollment endpoints on the CA host."
                ),
                source=_uncollected_source(estate, "enrollment-endpoints"),
            )
        ]
    findings: list[Finding] = []
    _container_evaluated("ESC8", "endpoint")
    for ep in estate.endpoints:
        _evaluated("ESC8", _endpoint_ref(ep))
        if ep.kind not in _ESC8_KINDS:
            continue
        if not ep.windows_auth:
            continue
        if not (ep.auth_providers & _NTLM_PROVIDERS):
            continue  # Kerberos-only — not NTLM-relayable
        http_open = "http" in ep.transports and not ep.ssl_required
        epa_required = ep.epa is EpaPolicy.REQUIRE
        if epa_required and not http_open:
            continue  # channel binding enforced + HTTPS-only -> mitigated
        conditions: list[str] = []
        if http_open:
            conditions.append("it is reachable over cleartext HTTP")
        if not epa_required:
            if ep.epa is EpaPolicy.ALLOW:
                conditions.append(
                    "Extended Protection is 'allow' (honored only if the client offers "
                    "a channel binding, so a relay via a client that does not send one "
                    "is not mitigated)"
                )
            elif ep.epa is EpaPolicy.NONE:
                conditions.append("Extended Protection is 'none' (channel binding not honored)")
            else:  # UNKNOWN
                conditions.append(
                    "Extended Protection state is unknown (treated as not required)"
                )
        explicit_ntlm = "ntlm" in ep.auth_providers
        # Cleartext HTTP or an explicit NTLM provider is the textbook relay case;
        # an HTTPS-only Negotiate endpoint missing EPA is weaker (MEDIUM).
        severity = Severity.HIGH if (http_open or explicit_ntlm) else Severity.MEDIUM
        findings.append(
            Finding(
                check="ESC8",
                object_ref=_endpoint_ref(ep),
                evidence_complete=True,
                severity=severity,
                title="HTTP enrollment endpoint enables NTLM relay to certificates",
                subject=ep.name or ep.kind.value,
                detail=(
                    f"The {ep.kind.value} endpoint accepts NTLM authentication and "
                    f"{' and '.join(conditions)}. An attacker who coerces a privileged "
                    "account can relay its NTLM authentication here and enroll a "
                    "certificate as that account. The relay itself is NOT confirmed by "
                    "this read-only check. Require Extended Protection (channel "
                    "binding), enforce HTTPS-only, and prefer Kerberos / disable NTLM."
                ),
                source=(
                    f"IIS enrollment endpoint '{ep.name or ep.kind.value}': "
                    "bindings + windowsAuthentication + extendedProtection"
                ),
            )
        )
    return findings


def detect_esc9(estate: Estate) -> list[Finding]:
    """Flag enrollable templates with CT_FLAG_NO_SECURITY_EXTENSION set.

    ESC9: certificates issued from such a template omit the SID security
    extension (szOID_NTDS_CA_SECURITY_EXT), so on a DC where
    ``StrongCertificateBindingEnforcement`` is not enforcing the cert can be
    mapped to a different (higher-privilege) account. We flag the enabling
    template flag only where it is *attacker-reachable*: a low-privilege
    principal can enroll without CA manager approval. A template nobody
    low-priv can enroll, or that requires manager approval, is not an unattended
    primitive and is not flagged (WI-038 — this closes the clear false-positive
    vector where ESC9 previously fired on every template carrying the flag).

    This mirrors the false-negative-safe subset of ESC1's gating (enroll ACL +
    no manager approval) — these gates can only suppress templates that are not
    attacker-reachable, so they cannot hide a real ESC9 primitive. It does NOT
    gate on client-auth EKU or on DC binding enforcement: the EKU gate has
    mapping-relevance edge cases (the remaining open question in WI-038), and
    enforcement gating would need opt-in DC data whose absence would suppress
    ESC9 on most exports (ESC16, the CA-level analogue, likewise hedges on
    enforcement in its detail text rather than gating).

    Degrades honestly: when template security descriptors were not collected the
    enroll ACL cannot be evaluated, so this returns nothing and ESC1 emits the
    estate-level ``TEMPLATE_ACL_NOT_EVALUATED`` note.
    """
    if not _template_security_collected(estate):
        return []
    findings: list[Finding] = []
    _template_container(estate, "ESC9", _TEMPLATE_SECURITY_PASS)
    for tmpl in estate.templates:
        if not _template_acl_readable(tmpl):
            continue
        _evaluated("ESC9", _template_ref(tmpl))
        if _NO_SECURITY_EXTENSION not in tmpl.enrollment_flags:
            continue
        if _MANAGER_APPROVAL in tmpl.enrollment_flags:
            continue
        enrollers = _low_priv_enrollers(tmpl)
        if not enrollers:
            continue
        who = ", ".join(sorted({a.trustee_name or a.trustee_sid for a in enrollers}))
        findings.append(
            Finding(
                check="ESC9",
                object_ref=_template_ref(tmpl),
                evidence_complete=True,
                severity=Severity.HIGH,
                title=(
                    "Enrollable template omits the SID security extension "
                    "(NO_SECURITY_EXTENSION)"
                ),
                subject=_template_subject(tmpl),
                detail=(
                    f"Enrollable by {who}; certificates from this template lack "
                    "szOID_NTDS_CA_SECURITY_EXT. Where DC "
                    "StrongCertificateBindingEnforcement is not enforcing, the cert "
                    "can be mapped to another account. Clear the flag unless a "
                    "specific mapping scenario requires it."
                ),
                source=f"template '{tmpl.name}': msPKI-Enrollment-Flag + enroll ACL",
            )
        )
    return findings


def detect_esc16(estate: Estate) -> list[Finding]:
    """Flag CAs that disable the SID security extension CA-wide.

    ESC16: the CA's ``DisableExtensionList`` policy setting contains
    ``szOID_NTDS_CA_SECURITY_EXT``, so every certificate the CA issues omits the
    SID security extension — the CA-level analogue of ESC9's per-template
    ``NO_SECURITY_EXTENSION`` flag. Where DC ``StrongCertificateBindingEnforcement``
    is not enforcing, the cert can be mapped to a different (higher-privilege)
    account. We flag the enabling CA configuration; the mapping/relay itself is
    out of scope. Readable from the CA policy registry with no ACL dependency, so
    it evaluates on every export (unlike ESC1).

    Root CAs are excluded (mirroring ESC11): an offline root does not issue
    AD-authentication end-entity certificates, so the SID extension is irrelevant
    there and flagging it would be a false positive. Severity is HIGH (not
    CRITICAL) because, like ESC9/ESC11, exploitation requires an external
    precondition (weak DC binding enforcement) — it is an enabling
    configuration, not a direct primitive like ESC6.

    CAs whose registry configuration was not collected are skipped (an empty
    ``disabled_extensions`` would read as clean); the
    ``CA_REGISTRY_NOT_EVALUATED`` note names them.
    """
    findings: list[Finding] = []
    if _pass_collected(estate, "ca-config"):
        _container_evaluated("ESC16", "ca")
    for ca in estate.cas:
        if not _ca_registry_collected(ca):
            continue
        _evaluated("ESC16", _ca_ref(ca))
        if ca.kind is CaKind.ROOT:
            continue
        if _NTDS_CA_SECURITY_EXT in ca.disabled_extensions:
            findings.append(
                Finding(
                    check="ESC16",
                    object_ref=_ca_ref(ca),
                    evidence_complete=True,
                    severity=Severity.HIGH,
                    title="CA-wide disable of the SID security extension",
                    subject=ca.name,
                    detail=(
                        "The CA's DisableExtensionList contains szOID_NTDS_CA_SECURITY_EXT, "
                        "so every issued certificate omits the SID security extension. Where "
                        "DC StrongCertificateBindingEnforcement is not enforcing, a certificate "
                        "can be mapped to another account. Remove the OID from "
                        "policy\\DisableExtensionList (re-set the multi-string without it via "
                        "certutil -setreg or the registry editor), then restart certsvc — unless "
                        "the CA intentionally issues certificates for a non-AD mapping scenario."
                    ),
                    source=f"{ca.config_string or ca.name}: policy\\DisableExtensionList",
                )
            )
    return findings


def _schannel_method_list(methods: frozenset[SchannelMappingMethod]) -> str:
    """Render the enabled Schannel mapping methods for a finding's source line."""
    return ", ".join(sorted(m.value for m in methods)) if methods else "none"


def _dc_registry_not_evaluated(estate: Estate, label: str) -> Finding:
    """The shared degrade-to-note finding when the esc10-dc-registry pass is absent
    or listed no domain controllers at all (a domain always has one, so an empty
    list means DC discovery failed, not that the estate is clean)."""
    if _pass_collected(estate, _ESC10_DC_REGISTRY_PASS):
        why = "the DC registry pass listed no domain controllers"
        source = "dc-config.json: no domain controllers listed"
    else:
        why = "the export did not include DC registry values"
        source = _uncollected_source(estate, _ESC10_DC_REGISTRY_PASS)
    return Finding(
        check="DC_REGISTRY_NOT_EVALUATED",
        severity=Severity.INFO,
        title="DC certificate mapping configuration not evaluated",
        subject="(estate)",
        detail=(
            f"{why[0].upper()}{why[1:]}, so {label} was skipped. "
            "Re-run a collector that captures the DC registry: "
            "StrongCertificateBindingEnforcement (KDC) and CertificateMappingMethods (Schannel)."
        ),
        source=source,
    )


def _dcs_discovered(estate: Estate) -> bool:
    return bool(estate.dcs)


def detect_esc10(estate: Estate) -> list[Finding]:
    """Flag DCs whose certificate-mapping configuration enables ESC10.

    Two registry-backed cases (SpecterOps "Certified Pre-Owned" + KB5014754):
      case 1 (HIGH): Schannel ``CertificateMappingMethods`` has the UPN bit (0x4)
        — a certificate's UPN SAN alone maps to an account.
      case 2 (HIGH): KDC ``StrongCertificateBindingEnforcement`` is Disabled —
        weak/implicit mappings are accepted (the ESC9 path opens up).
    Compatibility mode (permissive) without the UPN bit is a transitional weakness
    (MEDIUM); strict enforcement with no UPN bit is clear. We flag the enabling
    configuration; the mapping attack itself is out of scope.

    Degrades to a note when the DC registry pass was not collected.
    """
    if not _pass_collected(estate, _ESC10_DC_REGISTRY_PASS):
        return [_dc_registry_not_evaluated(estate, "ESC10 (weak certificate mapping)")]
    if not _dcs_discovered(estate):
        return [_dc_registry_not_evaluated(estate, "ESC10 (weak certificate mapping)")]
    findings: list[Finding] = []
    _container_evaluated("ESC10", "dc")
    for dc in estate.dcs:
        if _dc_binding_known(dc):
            _evaluated("ESC10", _dc_ref(dc))
        binding = dc.strong_certificate_binding_enforcement
        upn_mapping = SchannelMappingMethod.UPN in dc.schannel_mapping_methods
        reasons: list[str] = []
        if upn_mapping:
            reasons.append(
                "Schannel CertificateMappingMethods enables UPN mapping (0x4), so a "
                "certificate carrying a victim's UPN in its SAN maps to that account"
            )
        if binding == StrongCertBinding.DISABLED:
            reasons.append(
                "StrongCertificateBindingEnforcement is Disabled (0), so weak/implicit "
                "certificate mappings are accepted"
            )
        if reasons:
            findings.append(
                Finding(
                    check="ESC10",
                    object_ref=_dc_ref(dc),
                    evidence_complete=True,
                    severity=Severity.HIGH,
                    title="DC accepts weak certificate mappings",
                    subject=dc.name,
                    detail=(
                        f"{'; '.join(reasons)}. An attacker who can influence the mapped "
                        "field can authenticate as another account. Set "
                        "StrongCertificateBindingEnforcement to 2 (Full) and clear the UPN "
                        "bit from Schannel CertificateMappingMethods."
                    ),
                    source=(
                        f"DC '{dc.name}': StrongCertificateBindingEnforcement="
                        f"{binding.value}, Schannel CertificateMappingMethods="
                        f"{_schannel_method_list(dc.schannel_mapping_methods)}"
                    ),
                )
            )
            continue
        if binding == StrongCertBinding.PERMISSIVE:
            findings.append(
                Finding(
                    check="ESC10",
                    object_ref=_dc_ref(dc),
                    evidence_complete=True,
                    severity=Severity.MEDIUM,
                    title="DC certificate binding is in compatibility mode",
                    subject=dc.name,
                    detail=(
                        "StrongCertificateBindingEnforcement is Compatibility (1): the DC "
                        "attempts strong mapping but still accepts weak mappings for accounts "
                        "that predate the certificate. Move to 2 (Full) once all certificates "
                        "carry the SID extension."
                    ),
                    source=(
                        f"DC '{dc.name}': StrongCertificateBindingEnforcement={binding.value}"
                    ),
                )
            )
            continue
        if not _dc_binding_known(dc):
            findings.append(
                Finding(
                    check="ESC10_ENFORCEMENT_UNKNOWN",
                    severity=Severity.INFO,
                    title="DC StrongCertificateBindingEnforcement not confirmed",
                    subject=dc.name,
                    detail=(
                        "StrongCertificateBindingEnforcement is not explicitly configured or "
                        "could not be read, so its value is the OS default — which is Full only "
                        "on DCs patched past the Feb 2025 enforcement date, and Compatibility "
                        "(weak) otherwise. ESC10 case 2 cannot be ruled out without confirming "
                        "it; set the value to 2 (Full) explicitly to be certain."
                    ),
                    source=f"DC '{dc.name}': StrongCertificateBindingEnforcement not set",
                )
            )
    return findings


def _x509_mapping_form(mapping: str) -> X509MappingForm:
    """Classify one altSecurityIdentities value into its X.509 mapping form.

    Returns :attr:`X509MappingForm.UNKNOWN` for non-X.509 values (e.g. ``Kerberos:``)
    or unrecognized shapes. The bracketed tokens (``<SKI>``, ``<I>``/``<S>``/``<SR>``,
    etc.) are the documented certificateUserIds syntax.
    """
    text = mapping.strip()
    if not text.upper().startswith("X509:"):
        return X509MappingForm.UNKNOWN
    body = text.upper()
    if "<SKI>" in body:
        return X509MappingForm.SKI
    if "<SHA1-PUKEY>" in body:
        return X509MappingForm.SHA1_PUBLIC_KEY
    if "<RFC822>" in body:
        return X509MappingForm.RFC822
    if "<PN>" in body:
        return X509MappingForm.PRINCIPAL_NAME
    if "<I>" in body:
        # Issuer present: pair with serial (strong) or subject (weak). Issuer-only
        # is not a supported mapping.
        if "<SR>" in body:
            return X509MappingForm.ISSUER_SERIAL
        if "<S>" in body:
            return X509MappingForm.ISSUER_SUBJECT
        return X509MappingForm.UNKNOWN
    if "<S>" in body:
        return X509MappingForm.SUBJECT_ONLY
    return X509MappingForm.UNKNOWN


def detect_esc14(estate: Estate) -> list[Finding]:
    """Flag principals with *weak* explicit X.509 mappings in altSecurityIdentities.

    ESC14: a principal whose altSecurityIdentities holds a weak (reusable) X.509
    mapping form — subject-only, issuer+subject, RFC822/email, or UPN — can be
    impersonated by anyone who obtains a certificate matching those reusable fields,
    unless the DC enforces strong binding. Strong (nonreusable) forms — issuer+serial,
    SKI, SHA1 public key — are not flagged. Exploitability also requires a DC whose
    StrongCertificateBindingEnforcement is not strict.

    Degrades to a note when the altSecurityIdentities pass was not collected, and to
    an INFO note when DC enforcement could not be determined.
    """
    if not _pass_collected(estate, _ESC14_ALTSECID_PASS):
        return [
            Finding(
                check="ALTSECID_NOT_EVALUATED",
                severity=Severity.INFO,
                title="Principal altSecurityIdentities not evaluated",
                subject="(estate)",
                detail=(
                    "The export did not include principal altSecurityIdentities, so ESC14 "
                    "(weak explicit cert mapping) was skipped. Re-run a collector that "
                    "captures AD principal altSecurityIdentities."
                ),
                source=_uncollected_source(estate, "esc14-altsecid"),
            )
        ]
    # Every principal is fully evaluated once DC enforcement is known.
    if _esc14_enforcement_resolved(estate):
        _container_evaluated("ESC14", "principal")
        for principal in estate.principal_mappings:
            _evaluated("ESC14", _principal_ref(principal))
    # Find principals carrying at least one weak (reusable) X.509 mapping form.
    weak_principals: list[tuple[str, list[str], PrincipalMapping]] = []
    for principal in estate.principal_mappings:
        weak = [m for m in principal.mappings if _x509_mapping_form(m) in WEAK_X509_MAPPING_FORMS]
        if weak:
            weak_principals.append((principal.dn, weak, principal))
    if not weak_principals:
        return []  # only strong / non-X.509 mappings — nothing exploitable

    # Exploitability depends on a DC with non-strict enforcement.
    non_strict_dcs = _non_strict_dcs(estate)
    if not non_strict_dcs:
        if not _esc14_enforcement_resolved(estate):
            names = ", ".join(sorted(dn for dn, _, _ in weak_principals))
            return [
                Finding(
                    check="ESC14_ENFORCEMENT_UNKNOWN",
                    severity=Severity.INFO,
                    title="Weak altSecurityIdentities mappings present; DC enforcement unknown",
                    subject="(estate)",
                    detail=(
                        f"Principal(s) {names} carry weak (reusable) altSecurityIdentities "
                        "mappings, but StrongCertificateBindingEnforcement could not be "
                        "confirmed non-strict (DC registry pass missing, no DCs collected, or "
                        "the value was unreadable). ESC14 exploitability is uncertain — "
                        "re-collect DC registry to resolve."
                    ),
                    source="principal-mappings.json + dc-config.json (enforcement unresolved)",
                )
            ]
        return []  # every DC enforces strong binding — weak mappings are mitigated

    dc_names = ", ".join(sorted(dc.name for dc in non_strict_dcs))
    findings: list[Finding] = []
    for dn, weak, principal in sorted(weak_principals, key=lambda w: w[0]):
        shown = weak[:3]
        preview = ", ".join(f"'{m}'" for m in shown)
        suffix = f" (and {len(weak) - 3} more)" if len(weak) > 3 else ""
        findings.append(
            Finding(
                check="ESC14",
                object_ref=_principal_ref(principal),
                evidence_complete=True,
                severity=Severity.HIGH,
                title="Principal has a weak explicit certificate mapping (altSecurityIdentities)",
                subject=dn,
                detail=(
                    f"Principal has {len(weak)} weak (reusable) altSecurityIdentities mapping(s) "
                    f"[{preview}{suffix}] and DC(s) {dc_names} do not enforce strong certificate "
                    "binding. An attacker who obtains a certificate matching those reusable "
                    "fields can authenticate as this principal. Replace with a strong "
                    "(nonreusable) mapping — issuer+serial, SKI, or SHA1-PUKEY — and set "
                    "StrongCertificateBindingEnforcement to 2 (Full)."
                ),
                source=f"Principal '{dn}': altSecurityIdentities",
            )
        )
    return findings


def detect_ca_registry_gaps(estate: Estate) -> list[Finding]:
    """Flag CAs whose registry-derived configuration was not collected.

    The CA registry hives (policy EditFlags, InterfaceFlags, AuditFilter,
    DisableExtensionList, CA\\Security) are read locally on the CA host. In a
    multi-CA estate the collector captures them only for the CA it runs on;
    every other CA ships with empty registry fields, which would otherwise read
    as silently clean for ESC6/ESC16 (absent flags match nothing), silently
    skipped for ESC7 (no ACEs to evaluate), or — worst — a false ESC11 finding
    (that detector fires on the *absence* of a flag). Those detectors skip
    CAs with ``registry_config_collected`` False; this emits one INFO note per
    such CA so the gap is named rather than hidden.
    """
    findings: list[Finding] = []
    for ca in estate.cas:
        if _ca_registry_collected(ca):
            continue
        findings.append(
            Finding(
                check="CA_REGISTRY_NOT_EVALUATED",
                severity=Severity.INFO,
                title=f"CA registry configuration not collected for {ca.name}",
                subject=ca.name,
                detail=(
                    f"{ca.name} is not the CA the collector ran on, so its "
                    "registry-derived configuration (EditFlags, InterfaceFlags, "
                    "AuditFilter, DisableExtensionList, CA\\Security) was not "
                    "captured and ESC6/ESC7/ESC11/ESC16 were skipped for it. Re-run "
                    f"the collector on {ca.dns or ca.name} (or on each CA) for "
                    "full coverage."
                ),
                source=f"{ca.config_string or ca.name}: registry_config_collected=false",
            )
        )
    return findings


def detect_pki_acl_gaps(estate: Estate) -> list[Finding]:
    """Flag PKI objects whose DACL was requested but not obtained.

    The PKI-object analogue of :func:`detect_template_acl_gaps`: when the
    ``pki-acls`` pass ran but an individual object's ``nTSecurityDescriptor``
    came back unreadable (LDAP denial, corrupt SD), ESC5 cannot evaluate it and
    it would otherwise silently pass — indistinguishable from a genuinely safe
    object. One INFO note per such object; ESC5 skips them.
    """
    if not _pass_collected(estate, _PKI_ACLS_PASS):
        return []  # the pass-level PKI_ACL_NOT_EVALUATED note covers it
    findings: list[Finding] = []
    for obj in estate.acls:
        if _pki_acl_readable(obj):
            continue
        findings.append(
            Finding(
                check="PKI_ACL_UNREADABLE",
                severity=Severity.INFO,
                title="PKI object DACL was requested but not obtained",
                subject=_pki_subject(obj),
                detail=(
                    "The collector ran the pki-acls pass but this object's "
                    "nTSecurityDescriptor came back empty (LDAP denial or corrupt "
                    "SD), so its ESC5 control rights could not be evaluated. "
                    "Re-collect with adequate read rights on the object."
                ),
                source=f"{obj.object_dn or obj.kind.value}: nTSecurityDescriptor not obtained",
            )
        )
    return findings


def detect_template_acl_gaps(estate: Estate) -> list[Finding]:
    """Flag templates whose DACL was requested but not obtained.

    When the ``template-security`` pass ran but an individual template's
    ``nTSecurityDescriptor`` came back empty (LDAP denial, corrupt SD), its
    enroll/control rights could not be evaluated and it would otherwise silently
    pass every ESC1/2/3/4/13 check — indistinguishable from a genuinely safe
    template. This emits one INFO note per such template so the gap is visible
    rather than hidden; ESC1/2/3/4/13 themselves skip these templates.

    Silent when the pass was skipped wholesale: in that case ESC1 already emits
    the single estate-level ``TEMPLATE_ACL_NOT_EVALUATED`` note, so duplicating
    it here would be noise.
    """
    if not _template_security_collected(estate):
        return []
    findings: list[Finding] = []
    for tmpl in estate.templates:
        if _template_acl_readable(tmpl):
            continue
        findings.append(
            Finding(
                check="TEMPLATE_ACL_UNREADABLE",
                severity=Severity.INFO,
                title="Template DACL was requested but not obtained",
                subject=_template_subject(tmpl),
                detail=(
                    "The collector ran the template-security pass but this "
                    "template's nTSecurityDescriptor came back empty (LDAP denial "
                    "or corrupt SD), so its ESC1/2/3/4/13 enroll and control rights "
                    "could not be evaluated. Re-collect with adequate read rights "
                    "on the template object."
                ),
                source=f"template '{tmpl.name}': nTSecurityDescriptor not obtained",
            )
        )
    return findings


def _group_linked_policies(estate: Estate) -> dict[str, str]:
    """Return a map of issuance-policy OID -> linked group SID (ESC13)."""
    return {o.oid: o.group_link for o in estate.oids if o.group_link}


def detect_esc11(estate: Estate) -> list[Finding]:
    """Flag non-root CAs missing ``IF_ENFORCEENCRYPTICERTREQUEST``.

    ESC11: when the ICertPassage RPC interface does not require an encrypted
    certificate request, an attacker can relay NTLM authentication to the CA
    and request a certificate as the relayed principal. We flag the enabling
    ``CA\\InterfaceFlags`` configuration; the relay itself is out of scope and is
    never confirmed by this read-only check.

    Root CAs are excluded by design: a two-tier offline root does not serve RPC
    client enrollment, so flagging it would be a false positive.

    CAs whose registry configuration was not collected are skipped — the flag
    lives in the registry, so an absent read would otherwise produce a false
    "flag not set" finding on every remote CA (the one detector whose trigger
    is the *absence* of a value). The ``CA_REGISTRY_NOT_EVALUATED`` note names
    them.
    """
    findings: list[Finding] = []
    if _pass_collected(estate, "ca-config"):
        _container_evaluated("ESC11", "ca")
    for ca in estate.cas:
        if not _ca_registry_collected(ca):
            continue
        _evaluated("ESC11", _ca_ref(ca))
        if ca.kind is CaKind.ROOT:
            continue
        if _ESC11_FLAG in ca.interface_flags:
            continue
        findings.append(
            Finding(
                check="ESC11",
                object_ref=_ca_ref(ca),
                evidence_complete=True,
                severity=Severity.HIGH,
                title="CA RPC enrollment does not require encrypted requests",
                subject=ca.name,
                detail=(
                    "ICertPassage is not required to use an encrypted certificate "
                    "request, enabling NTLM-relay-to-enrollment (ESC11). The relay "
                    "itself is NOT confirmed by this read-only check. Enable the flag: "
                    "certutil -setreg CA\\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST, "
                    "then restart certsvc."
                ),
                source=f"{ca.config_string or ca.name}: CA\\InterfaceFlags",
            )
        )
    return findings


def detect_esc13(estate: Estate) -> list[Finding]:
    """Flag group-linked issuance policies on low-priv-enrollable auth templates.

    ESC13: an issuance-policy OID maps to a group via ``msDS-OIDToGroupLink``; a
    client-auth-capable template advertises that OID; and a low-privilege
    principal can enroll. Authenticating with the issued certificate then grants
    the enrollee the privileges of the linked group. We only flag when the
    template can authenticate its subject (no EKU, Any-Purpose, or a client-auth
    EKU) because a non-auth certificate cannot deliver the group escalation in
    practice. The CPO ESC13 condition that the requester is not already in the
    linked group is automatically satisfied here: the threat is a low-priv
    enrollee being mapped to a typically more privileged group.

    Degrades like ESC1/2/3/4: when template security descriptors were not
    collected, ESC1 emits the single estate-level note, so this returns nothing.
    """
    if not _template_security_collected(estate):
        return []
    if not _pass_collected(estate, "oid-objects"):
        return []  # group links unknown: nothing evaluated, nothing recorded
    policy_map = _group_linked_policies(estate)
    oid_names = {o.oid: o.name for o in estate.oids if o.group_link}
    findings: list[Finding] = []
    _template_container(estate, "ESC13", _TEMPLATE_SECURITY_PASS, "oid-objects")
    for tmpl in estate.templates:
        if not _template_acl_readable(tmpl):
            continue
        _evaluated("ESC13", _template_ref(tmpl))
        if _MANAGER_APPROVAL in tmpl.enrollment_flags:
            continue
        linked = [o for o in tmpl.issuance_policy_oids if o in policy_map]
        if not linked:
            continue
        if not _can_authenticate(tmpl):
            continue
        enrollers = _low_priv_enrollers(tmpl)
        if not enrollers:
            continue
        who = ", ".join(sorted({a.trustee_name or a.trustee_sid for a in enrollers}))
        policy_lines = ", ".join(
            f"{oid} ({oid_names.get(oid, '')}) -> {policy_map[oid]}" for oid in linked
        )
        findings.append(
            Finding(
                check="ESC13",
                object_ref=_template_ref(tmpl),
                evidence_complete=True,
                severity=Severity.HIGH,
                title="Group-linked issuance policy enrollable by low-priv",
                subject=_template_subject(tmpl),
                detail=(
                    f"Enrollable by {who}; issuance polic"
                    f"{'y' if len(linked) == 1 else 'ies'} {policy_lines} map to "
                    "privileged group(s). Authenticating with the resulting certificate "
                    "grants the enrollee the privileges of the linked group (impact "
                    "depends on the group; could be Domain Admins). Remove "
                    "msDS-OIDToGroupLink or restrict enroll rights / require manager "
                    "approval."
                ),
                source=(
                    f"template '{tmpl.name}' (oid {tmpl.oid}): "
                    "msPKI-Certificate-Policy + msDS-OIDToGroupLink"
                ),
            )
        )
    return findings


def _worst_ca_patch_state(estate: Estate) -> CaPatchState:
    """The worst (most-vulnerable) patch state among issuing CAs.

    A v1 template is exploitable via any unpatched issuing CA, so ESC15 keys on
    the worst case: if any issuing CA is UNPATCHED the finding is HIGH; if all are
    PATCHED the EKUwu path is closed; otherwise (some UNKNOWN, none unpatched) it
    is MEDIUM with an explicit "confirm patch state" caveat.

    Offline root CAs are excluded (mirrors ESC11/ESC16): a root never issues
    end-entity certificates, so its patch state is irrelevant to whether a v1
    template is exploitable — counting an unpatched root would falsely escalate
    ESC15 on a patched issuing CA.
    """
    issuing = [ca for ca in estate.cas if ca.kind is not CaKind.ROOT]
    if not issuing:
        return CaPatchState.UNKNOWN
    states = {ca.ca_patch_state for ca in issuing}
    if CaPatchState.UNPATCHED in states:
        return CaPatchState.UNPATCHED
    if CaPatchState.UNKNOWN in states:
        return CaPatchState.UNKNOWN
    return CaPatchState.PATCHED


def detect_esc15(estate: Estate) -> list[Finding]:
    """Flag schema v1 templates enrollable by low-priv principals (EKUwu).

    ESC15 / CVE-2024-49019 ("EKUwu"): on a CA without the November 2024 fix, a
    schema **version 1** template does not constrain the issued certificate's
    application policies, so an enrollee can inject arbitrary EKUs into the
    request — e.g. Client Authentication (→ domain auth, ESC1-like) or Certificate
    Request Agent (→ enroll-on-behalf-of, ESC3-like). Any v1 template a low-priv
    principal can enroll in is therefore an escalation primitive, regardless of
    the template's own EKUs.

    Patch-state aware (WI-027): the collector cannot yet read CA build/patch
    level, so it defaults to UNKNOWN. On an UNKNOWN-patch estate the finding is
    MEDIUM with an explicit "confirm the CA is patched" caveat (not a false HIGH
    on a patched estate); on a known-UNPATCHED CA it is HIGH; on a known-PATCHED
    CA the EKUwu path is closed and no finding is emitted.

    Degrades like ESC1/2/3/4: when template security descriptors were not
    collected, ESC1 emits the single estate-level note, so this returns nothing.
    """
    if not _template_security_collected(estate):
        return []
    if not _pass_collected(estate, "ca-config"):
        return []  # CA patch state unknown: nothing evaluated, nothing recorded
    patch_state = _worst_ca_patch_state(estate)
    findings: list[Finding] = []
    _template_container(estate, "ESC15", _TEMPLATE_SECURITY_PASS, "ca-config")
    for tmpl in estate.templates:
        if not _template_acl_readable(tmpl):
            continue
        _evaluated("ESC15", _template_ref(tmpl))
        if patch_state is CaPatchState.PATCHED:
            continue  # the EKUwu path is closed on every issuing CA
        if tmpl.schema_version != 1:
            continue
        if _MANAGER_APPROVAL in tmpl.enrollment_flags:
            continue
        enrollers = _low_priv_enrollers(tmpl)
        if not enrollers:
            continue
        who = ", ".join(sorted({a.trustee_name or a.trustee_sid for a in enrollers}))
        if patch_state is CaPatchState.UNPATCHED:
            severity = Severity.HIGH
            patch_note = (
                "The CA is not patched for CVE-2024-49019, so the requester can inject "
                "application policies (EKUs) such as Client Authentication or Certificate "
                "Request Agent into the request, turning this into an ESC1/ESC3-style "
                "escalation regardless of the template's own EKUs."
            )
        else:  # UNKNOWN — the common case until the collector captures patch state
            severity = Severity.MEDIUM
            patch_note = (
                "CA patch state is unknown. If the CA is not patched for CVE-2024-49019 "
                "(November 2024), the requester can inject application policies (EKUs) "
                "such as Client Authentication or Certificate Request Agent into the "
                "request, turning this into an ESC1/ESC3-style escalation regardless of "
                "the template's own EKUs. Confirm the CA is patched."
            )
        findings.append(
            Finding(
                check="ESC15",
                object_ref=_template_ref(tmpl),
                evidence_complete=patch_state is not CaPatchState.UNKNOWN,
                severity=severity,
                title="Schema v1 template enrollable by low-priv (EKUwu / CVE-2024-49019)",
                subject=_template_subject(tmpl),
                detail=(
                    f"Enrollable by {who}; this is a schema version 1 template with no "
                    f"manager approval. {patch_note} Upgrade the template to schema v2+, "
                    "require manager approval, or restrict enroll rights."
                ),
                source=f"template '{tmpl.name}' (oid {tmpl.oid}): schema_version=1 + enroll ACL",
            )
        )
    return findings


def detect_infra_cert_expiry(
    estate: Estate,
    *,
    now: datetime | None = None,
    warn_days: int = 90,
) -> list[Finding]:
    """Flag CA/sub-CA certs and CRLs at/near expiry.

    Root-tier items get explicit top-severity treatment: the box that signs the
    root CRL is offline by design, so an expired root CRL is a silent,
    estate-wide authentication failure nobody is watching for.

    Degrades cleanly: when the export was ingested without the ``[certs]`` extra
    there is no lifecycle data, so this emits a single ``info`` note rather than
    a false "all clear".
    """
    if now is None:
        now = datetime.now(UTC)
    elif now.tzinfo is None:
        raise ValueError("'now' must be timezone-aware (prefer UTC)")

    if not _lifecycle_parsed(estate):
        return [
            Finding(
                check="LIFECYCLE_NOT_EVALUATED",
                severity=Severity.INFO,
                title="Certificate lifecycle not evaluated",
                subject="(estate)",
                detail=(
                    "No cert/CRL data was parsed from this export, so CA/CRL expiry, "
                    "weak signing algorithm, and CA-cert key-size checks were skipped. "
                    "Two possible causes, most likely first: the collector did not "
                    "capture the certs pass (re-run a collector >= 0.8.0, which reads "
                    "the published CA certs and CRLs from AD), or adcs-lens was "
                    "installed without the [certs] extra (pip install "
                    "adcs-lens[certs]) needed to parse them."
                ),
                source="collector-manifest.json: certs_parsed=false",
            )
        ]

    findings: list[Finding] = []

    for ca_name, _kind, cert in _all_certs(estate):
        if not _cert_expiry_readable(cert) or cert.not_after is None:
            continue
        _evaluated("CA_CERT_EXPIRY", _cert_ref(cert, ca_name))
        findings.extend(_expiry_finding(ca_name, cert, cert.not_after, now, warn_days))

    for crl in estate.crls:
        if not _crl_next_update_readable(crl):
            continue
        if _crl_window_readable(crl):
            # thisUpdate known: the early-warning window evaluates too.
            _evaluated("CRL_EXPIRY", _crl_ref(crl))
        findings.extend(
            _crl_finding(crl, now)
        )
    return findings


def _expiry_finding(
    ca_name: str,
    cert: CertLifecycle,
    not_after: datetime,
    now: datetime,
    warn_days: int,
) -> list[Finding]:
    subject, kind = cert.subject, cert.kind
    days = (not_after - now).days
    root = kind == CertKind.ROOT_CA
    if not_after < now:
        severity = Severity.CRITICAL
        title = "CA certificate has expired"
    elif days <= warn_days:
        # A failing root invalidates the whole estate, so escalate it.
        severity = Severity.CRITICAL if root else Severity.HIGH
        title = f"CA certificate expires in {days} day(s)"
    else:
        return []
    return [
        Finding(
            check="CA_CERT_EXPIRY",
            object_ref=_cert_ref(cert, ca_name),
            evidence_complete=True,
            severity=severity,
            title=title,
            subject=subject or ca_name,
            detail=(
                f"{kind.value} certificate not_after={not_after.isoformat()}"
                + (" — root tier: failure cascades to the entire chain." if root else ".")
            ),
            source=f"CA cert for {ca_name}",
            tier=CrlTier.ROOT if root else CrlTier.ISSUING,
        )
    ]


# CRL early-warning window as a fraction of the CRL's own validity period
# (next_update - this_update), floored at one day. See _crl_finding for why an
# absolute day count (tuned for year-long CA certs) is wrong for short CRLs.
_CRL_EARLY_WARN_FRACTION = 0.25


def _crl_horizon(remaining: timedelta) -> str:
    """Human-readable remaining time for a CRL early-warning title.

    Whole days when >= 1 day remains; otherwise whole hours, so a CRL with two
    hours left reads "2 hour(s)" rather than the misleading "0 day(s)" that
    ``timedelta.days`` truncation would produce.
    """
    if remaining.days >= 1:
        return f"{remaining.days} day(s)"
    hours = int(remaining.total_seconds() // 3600)
    return f"{hours} hour(s)"


def _crl_finding(crl: Crl, now: datetime) -> list[Finding]:
    """Return CRL freshness findings.

    Two states produce a finding:

    * **Past nextUpdate** — CRITICAL. Clients that fetch the CRL treat the chain
      as invalid; an expired *root*-tier CRL is a silent estate-wide auth failure
      because its signer is offline.
    * **Within the early-warning window** — the CRL will expire soon. CRLs are
      short-lived (days or weeks), so the cert-style absolute ``warn_days``
      window (tuned for year-long CA certs) would fire on essentially every CRL
      and is not used here. Instead the window is a fraction of the CRL's *own*
      validity period (``next_update - this_update``). The fraction is raised to
      a one-day floor only when that floor stays *strictly inside* the validity
      period, so a short (<= 1 day) CRL is never flagged from the moment it is
      published — it gets the pure fractional lead time (e.g. 6 hours for a
      24-hour CRL). A CRL whose ``this_update`` was not captured cannot be
      windowed and only the past-nextUpdate check applies.

    The check id stays ``CRL_EXPIRY`` for both states so the threat-model
    "CRL freshness" row and the consequences entry remain single-valued; the
    title and severity carry the distinction.
    """
    next_update = crl.next_update
    if next_update is None:
        return []
    root = crl.tier == CrlTier.ROOT
    if next_update < now:
        return [
            Finding(
                check="CRL_EXPIRY",
                object_ref=_crl_ref(crl),
                evidence_complete=True,
                severity=Severity.CRITICAL,
                title="Published CRL is past nextUpdate (chain validation fails)",
                subject=crl.issuer,
                detail=(
                    "Clients that fetch this CRL will treat the chain as invalid"
                    + (
                        " — and because the root CRL signer is offline, nobody is "
                        "watching it expire (silent estate-wide auth failure)."
                        if root
                        else "."
                    )
                ),
                source=f"CRL nextUpdate {next_update.isoformat()} ({crl.source})",
                tier=crl.tier,
            )
        ]
    window: timedelta | None = None
    if _crl_window_readable(crl) and crl.this_update is not None:
        validity = next_update - crl.this_update
        if validity.total_seconds() > 0:
            # Fractional lead time of the CRL's own validity. The one-day floor
            # applies only when it stays strictly inside the validity period, so
            # a short CRL (validity <= 1 day) is never flagged at publication —
            # it gets the pure fractional window instead (WI-022 review fix).
            window = validity * _CRL_EARLY_WARN_FRACTION
            if window < timedelta(days=1) < validity:
                window = timedelta(days=1)
    if window is not None and next_update - now <= window:
        remaining = next_update - now
        horizon = _crl_horizon(remaining)
        severity = Severity.CRITICAL if root else Severity.HIGH
        return [
            Finding(
                check="CRL_EXPIRY",
                object_ref=_crl_ref(crl),
                evidence_complete=True,
                severity=severity,
                title=f"Published CRL expires in {horizon} (early-warning window)",
                subject=crl.issuer,
                detail=(
                    "The CRL's nextUpdate is approaching; clients depend on a "
                    "current CRL for revocation checking, and once it passes "
                    "nextUpdate chain validation fails. Refresh publication "
                    "before nextUpdate."
                    + (
                        " — root-tier CRL expiry cascades estate-wide because the "
                        "offline signer is not watched."
                        if root
                        else ""
                    )
                ),
                source=f"CRL nextUpdate {next_update.isoformat()} ({crl.source})",
                tier=crl.tier,
            )
        ]
    return []


# The seven certsvc audit bits that make up the Microsoft-recommended full
# baseline of AuditFilter=127 (0x7F). ``detect_audit_config`` flags a CA as
# under-scoped if any of these are clear, so the detector stays aligned with the
# baseline it recommends in its remediation text.
_AUDIT_CATEGORIES: dict[int, str] = {
    0x1: "Start/Stop CA",
    0x2: "Backup/Restore",
    0x4: "Issue/Cert",
    0x8: "Revoke",
    0x10: "Change CA config",
    0x20: "Change CA security",
    0x40: "Store/Retrieve cert",
}
# The full-baseline value the remediation text recommends. Asserted against the
# bit set so the two cannot drift apart.
_AUDIT_FULL_BASELINE = 0x7F
assert sum(_AUDIT_CATEGORIES) == _AUDIT_FULL_BASELINE


def detect_weak_signing(estate: Estate) -> list[Finding]:
    """Flag CA certificates signed with weak hashing algorithms (SHA-1 / MD5).

    The threat model classifies weak CA signing algorithms as a static hygiene
    finding. MD5 is treated as CRITICAL and SHA-1 as HIGH; both use the same
    ``WEAK_SIG_ALG`` identifier so the distinction is carried by severity.

    Matching is by substring on the lower-cased algorithm name. SHA-1 names
    (``sha1``, ``sha1WithRSAEncryption``, ``ecdsa-with-SHA1``) all carry the
    ``sha1`` token; no standard hash name (e.g. ``sha256``, ``sha512``) contains
    it, so the simple check avoids both false positives and false negatives.

    Degrades cleanly: when the export was ingested without DER cert parsing this
    returns nothing; the ``LIFECYCLE_NOT_EVALUATED`` note from
    :func:`detect_infra_cert_expiry` already covers the gap.
    """
    if not _lifecycle_parsed(estate):
        return []
    findings: list[Finding] = []
    for ca_name, _kind, cert in _all_certs(estate):
        if not _cert_sig_alg_readable(cert):
            continue
        _evaluated("WEAK_SIG_ALG", _cert_ref(cert, ca_name))
        alg = cert.sig_alg.lower()
        if "md5" in alg:
            severity = Severity.CRITICAL
            title = "CA certificate signed with MD5"
        elif "sha1" in alg:
            severity = Severity.HIGH
            title = "CA certificate signed with SHA-1"
        else:
            continue
        findings.append(
            Finding(
                check="WEAK_SIG_ALG",
                object_ref=_cert_ref(cert, ca_name),
                evidence_complete=True,
                severity=severity,
                title=title,
                subject=ca_name,
                detail=(
                    f"{ca_name}'s certificate ({cert.subject}) uses the signature "
                    f"algorithm '{cert.sig_alg}'. Collision-capable hashing weakens the "
                    "entire chain's integrity. Reissue the certificate using SHA-256 or "
                    "stronger."
                ),
                source=f"CA cert for {ca_name}: {cert.subject} sig_alg={cert.sig_alg}",
            )
        )
    return findings


def _template_uses_ecdsa(tmpl: CertTemplate) -> bool:
    """True when the template's CSP or key size indicates an EC (non-RSA) algorithm.

    ``msPKI-Minimal-Key-Size`` is RSA-oriented (bits). An ECDSA template
    legitimately carries a smaller minimum — the curve size (256/384/521 for
    P-256/P-384/P-521) — so the RSA 2048-bit baseline must not be applied to it.
    We detect ECDSA from the captured CSP when available, and from the key size
    alone otherwise: 256/384/521 are never valid RSA minimums, so a template with
    one of those sizes is unambiguously an EC template (WI-025).
    """
    if "ecdsa" in tmpl.csp or "ecdh" in tmpl.csp:
        return True
    return tmpl.min_key_size in (256, 384, 521)


def detect_weak_key_size(estate: Estate) -> list[Finding]:
    """Flag weak RSA key lengths in CA certificates and certificate templates.

    CA certificates and templates both express a minimum key size. CA certs with
    fewer than 2048 bits are flagged with ``WEAK_KEY_SIZE``; templates that allow
    below 2048 bits are flagged with ``WEAK_TEMPLATE_KEY_SIZE``. The template
    check always runs regardless of whether DER certs were parsed.

    Only RSA keys are subject to the 2048-bit baseline — ECDSA keys legitimately
    use 256/384/521-bit sizes, so non-RSA CA certs are skipped and ECDSA templates
    (detected via the captured CSP or an unambiguous EC curve size) are skipped
    (WI-025). A template whose algorithm is genuinely unknown and whose key size
    is not an EC curve size is checked against the RSA baseline — the common case,
    since RSA dominates AD CS templates.

    Degrades cleanly: the CA certificate half returns nothing when
    ``certs_parsed`` is False, mirroring other lifecycle detectors.
    """
    findings: list[Finding] = []

    if _lifecycle_parsed(estate):
        for ca_name, _kind, cert in _all_certs(estate):
            if not _cert_key_size_readable(cert) or not _cert_key_alg_known(cert):
                continue
            _evaluated("WEAK_KEY_SIZE", _cert_ref(cert, ca_name))
            bits = cert.key_bits
            if bits is None or bits >= 2048:
                continue
            if cert.key_alg != "rsa":
                continue
            if bits < 1024:
                severity = Severity.CRITICAL
                title = f"CA certificate uses a {bits}-bit key"
            elif bits == 1024:
                severity = Severity.HIGH
                title = "CA certificate uses a 1024-bit key"
            else:
                severity = Severity.MEDIUM
                title = f"CA certificate uses a {bits}-bit key"
            findings.append(
                Finding(
                    check="WEAK_KEY_SIZE",
                    object_ref=_cert_ref(cert, ca_name),
                    evidence_complete=True,
                    severity=severity,
                    title=title,
                    subject=ca_name,
                    detail=(
                        f"{ca_name}'s certificate ({cert.subject}) uses a {bits}-bit "
                        "key, below the 2048-bit baseline. RSA keys below 2048 bits are "
                        "increasingly factorable. Reissue the certificate with a 2048-bit "
                        "or larger key."
                    ),
                    source=f"CA cert for {ca_name}: {cert.subject} key_bits={bits}",
                )
            )

    _template_container(estate, "WEAK_TEMPLATE_KEY_SIZE")
    for tmpl in estate.templates:
        if not _template_key_size_captured(tmpl):
            continue
        _evaluated("WEAK_TEMPLATE_KEY_SIZE", _template_ref(tmpl))
        bits = tmpl.min_key_size
        if bits is None or bits >= 2048:
            continue
        if _template_uses_ecdsa(tmpl):
            continue
        if bits < 1024:
            severity = Severity.HIGH
            title = f"Template allows a {bits}-bit key"
        elif bits == 1024:
            severity = Severity.MEDIUM
            title = "Template allows a 1024-bit key"
        else:
            severity = Severity.MEDIUM
            title = f"Template allows a {bits}-bit key"
        findings.append(
            Finding(
                check="WEAK_TEMPLATE_KEY_SIZE",
                object_ref=_template_ref(tmpl),
                evidence_complete=True,
                severity=severity,
                title=title,
                subject=_template_subject(tmpl),
                detail=(
                    f"Template '{tmpl.name}' permits a minimum key size of {bits} bits, "
                    "below the 2048-bit policy baseline. Certificates issued with weak keys "
                    "can be broken. Set msPKI-Minimal-Key-Size to 2048 or higher."
                ),
                source=f"template '{tmpl.name}': msPKI-Minimal-Key-Size={bits}",
            )
        )

    return findings


def detect_audit_config(estate: Estate) -> list[Finding]:
    """Flag CAs whose audit configuration is disabled or missing event categories.

    A fully configured CA logs every certsvc audit category — the Microsoft
    recommended full baseline is AuditFilter=127 (0x7F). An AuditFilter of 0
    means auditing is fully disabled; any value that does not include all seven
    baseline bits (0x1-0x40) is flagged as under-scoped, naming the missing
    categories.

    Degrades cleanly: when no CA in the export carries an AuditFilter value this
    emits a single estate-level INFO note; when *some* CAs lack a value while
    others have one, each unevaluated CA gets its own INFO note so the gap is
    never silently dropped alongside real findings.
    """
    if not estate.cas or not any(_audit_filter_captured(ca) for ca in estate.cas):
        return [
            Finding(
                check="CA_AUDIT_NOT_EVALUATED",
                severity=Severity.INFO,
                title="CA audit configuration not evaluated",
                subject="(estate)",
                detail=(
                    "The export did not include CA AuditFilter values, so CA audit "
                    "configuration could not be evaluated. Re-run a collector that captures "
                    "certutil -getreg CA\\AuditFilter."
                ),
                source="collector-manifest.json: CA AuditFilter not captured",
            )
        ]

    findings: list[Finding] = []
    if _pass_collected(estate, "ca-config"):
        _container_evaluated("CA_AUDIT_DISABLED", "ca")
        _container_evaluated("CA_AUDIT_UNDERSCOPED", "ca")
    for ca in estate.cas:
        if not _audit_filter_captured(ca) or ca.audit_filter is None:
            findings.append(
                Finding(
                    check="CA_AUDIT_NOT_EVALUATED",
                    severity=Severity.INFO,
                    title=f"CA audit configuration not evaluated for {ca.name}",
                    subject=ca.name,
                    detail=(
                        f"{ca.name} has no AuditFilter value in the export, so its audit "
                        "configuration could not be evaluated. Re-run a collector that captures "
                        f"certutil -getreg CA\\AuditFilter for {ca.name}."
                    ),
                    source=f"{ca.config_string or ca.name}: CA\\AuditFilter not captured",
                )
            )
            continue
        _evaluated("CA_AUDIT_DISABLED", _ca_ref(ca))
        _evaluated("CA_AUDIT_UNDERSCOPED", _ca_ref(ca))
        if ca.audit_filter == 0:
            findings.append(
                Finding(
                    check="CA_AUDIT_DISABLED",
                    object_ref=_ca_ref(ca),
                    evidence_complete=True,
                    severity=Severity.CRITICAL,
                    title="CA auditing is fully disabled",
                    subject=ca.name,
                    detail=(
                        f"{ca.name} has AuditFilter=0, so no CA events are written to the "
                        "security log. This removes the audit trail needed to detect or "
                        "investigate misuse. Enable the full audit baseline: certutil -setreg "
                        "CA\\AuditFilter 127, then restart certsvc."
                    ),
                    source=f"{ca.config_string or ca.name}: CA\\AuditFilter=0",
                )
            )
            continue

        missing = [name for bit, name in _AUDIT_CATEGORIES.items() if not (ca.audit_filter & bit)]
        if missing:
            missing_text = ", ".join(missing)
            findings.append(
                Finding(
                    check="CA_AUDIT_UNDERSCOPED",
                    object_ref=_ca_ref(ca),
                    evidence_complete=True,
                    severity=Severity.MEDIUM,
                    title="CA audit filter is missing event categories",
                    subject=ca.name,
                    detail=(
                        f"{ca.name} has AuditFilter={ca.audit_filter} (0x{ca.audit_filter:X}), "
                        f"which does not include the full 127 (0x7F) baseline: missing "
                        f"{missing_text}. Missing event categories hide CA administration and "
                        "certificate lifecycle activity. Enable the full audit baseline: "
                        "certutil -setreg CA\\AuditFilter 127, then restart certsvc."
                    ),
                    source=f"{ca.config_string or ca.name}: CA\\AuditFilter={ca.audit_filter}",
                )
            )

    return findings


def detect_acl_coverage_caveats(estate: Estate) -> list[Finding]:
    """Emit an estate-level note on the ACL-modeling boundary (WI-033).

    The ACL-gated detectors (ESC1–ESC5, ESC7, ESC9, ESC13, ESC15) reason about the ACE
    trustee SID directly, with two honesty boundaries:

    * **No group-token expansion.** Nested-group membership is not modeled: a Deny
      on a group containing the requester, or Enroll/control rights held only
      transitively via group membership, are invisible. The *absence* of an ACL
      finding is therefore not by itself proof that no ACL path exists.
    * **Allowlist trustee classification.** A trustee is treated as privileged
      only when its SID is in the curated high-privilege set (built-in admin and
      operator groups, SYSTEM/service identities, domain trust accounts, and the
      well-known admin RIDs); everything else — including custom groups and
      named accounts — is treated as low-privilege. This fails toward flagging:
      a custom *privileged* group may produce a finding that is really noise.

    This note surfaces both boundaries in the output (not only in source
    comments) whenever ACL reasoning actually ran, so a reader never over-trusts
    an ACL result in either direction.

    Fires once per estate when any ACL input is present (a template, PKI object,
    or CA carrying a security descriptor). A minimal export with no ACLs has no
    ACL reasoning to caveat and gets no note. Excluded from the ``--exit-code``
    gate via ``_DEGRADATION_NOTES`` — it is a coverage note, not a posture
    finding.
    """
    acl_inputs = (
        any(tmpl.security for tmpl in estate.templates)
        or any(acl.security for acl in estate.acls)
        or any(ca.security for ca in estate.cas)
    )
    if not acl_inputs:
        return []
    return [
        Finding(
            check="ACL_GROUP_TOKEN_CAVEAT",
            severity=Severity.INFO,
            title="ACL findings: no group expansion; allowlist trustee classification",
            subject="(estate)",
            detail=(
                "ESC1–ESC5, ESC7, ESC9, ESC13, and ESC15 match ACEs on the trustee SID "
                "directly; nested-group tokens are not expanded, so a Deny on a group "
                "containing the requester, or rights held only via group membership, "
                "are not modeled. Trustees are classified by a high-privilege SID "
                "allowlist: any trustee outside it (custom groups, named accounts) is "
                "treated as low-privilege, which fails toward flagging — a custom "
                "privileged group may read as a finding. Confirm ACL-derived "
                "conclusions directly in AD when one is load-bearing."
            ),
            source=(
                "detection.py: ACL trustee-SID matching (no group-token expansion; "
                "high-priv allowlist classification)"
            ),
        )
    ]


def detect_orphaned_templates(estate: Estate) -> list[Finding]:
    """Flag templates not published by any enrollment service (WI-032).

    A template that exists in AD but no CA offers for enrollment is either a
    leftover from a deprecated use case or a misconfiguration. It is not directly
    exploitable, but it expands the attack surface (a CA operator can publish it
    at any time) and signals hygiene drift. Statically readable from the
    enrollment-services join already performed at ingest.

    Degrades honestly: if the enrollment-services export was absent, every
    template would look orphaned — meaningless noise. The check is skipped in
    that case rather than flagging the whole estate. A present valid empty export
    confirms that no templates are published and therefore does produce findings.
    """
    if not _publication_data_available(estate):
        return []
    findings: list[Finding] = []
    _template_container(estate, "ORPHANED_TEMPLATE")
    for tmpl in estate.templates:
        _evaluated("ORPHANED_TEMPLATE", _template_ref(tmpl))
        if _normalized_publishers(tmpl):
            continue
        findings.append(
            Finding(
                check="ORPHANED_TEMPLATE",
                object_ref=_template_ref(tmpl),
                evidence_complete=True,
                severity=Severity.LOW,
                title="Template is not published by any enrollment service",
                subject=_template_subject(tmpl),
                detail=(
                    f"Template '{tmpl.name}' exists in AD but no CA offers it for "
                    "enrollment. It is not directly exploitable, but it expands the "
                    "attack surface and signals hygiene drift. Remove the template if "
                    "it is no longer needed, or publish it under the intended CA."
                ),
                source=f"template '{tmpl.name}': published_by is empty",
            )
        )
    return findings


def detect_ocsp_absence(estate: Estate) -> list[Finding]:
    """Flag issuing CAs whose certificate lacks an OCSP URL in its AIA (WI-022).

    OCSP-based revocation checking is not available for certificates issued by a
    CA whose own certificate carries no OCSP responder URL in its Authority
    Information Access extension. This is a posture note (many CAs use only CRL),
    not a vulnerability — clients fall back to CRL fetching. Only issuing CAs are
    checked: an offline root never serves end-entity certs, so its OCSP presence
    is irrelevant. Only fires when certs were parsed (same gate as other
    lifecycle checks).
    """
    if not _lifecycle_parsed(estate):
        return []
    findings: list[Finding] = []
    for ca in estate.cas:
        for cert in ca.certs:
            _evaluated("OCSP_URL_ABSENT", _cert_ref(cert, ca.name))
        if ca.kind is CaKind.ROOT:
            continue
        for cert in ca.certs:
            if cert.ocsp_urls:
                continue
            findings.append(
                Finding(
                    check="OCSP_URL_ABSENT",
                    object_ref=_cert_ref(cert, ca.name),
                    evidence_complete=True,
                    severity=Severity.LOW,
                    title="Issuing CA certificate has no OCSP responder URL",
                    subject=ca.name,
                    detail=(
                        f"The certificate for {ca.name} ({cert.subject}) carries no OCSP "
                        "responder URL in its Authority Information Access extension, so "
                        "OCSP-based revocation checking is not available for certificates "
                        "issued by this CA. Clients fall back to CRL fetching. This is a "
                        "posture note, not a vulnerability — add an OCSP URL if the CA "
                        "should support OCSP-based revocation."
                    ),
                    source=f"CA cert for {ca.name}: {cert.subject} AIA extension (no OCSP)",
                    tier=CrlTier.ISSUING,
                )
            )
    return findings


def detect_cdp_aia_absence(estate: Estate) -> list[Finding]:
    """Flag issuing CAs whose certificate has no CDP or AIA URL (WI-032).

    A CA certificate without a CRL Distribution Point extension gives clients no
    revocation path at all, and without an AIA extension clients cannot build the
    chain to the issuer. Both are real posture problems (not just hygiene):
    clients that cannot fetch a CRL will reject the chain or silently skip
    revocation checking. Only issuing CAs are checked (an offline root's
    self-signed cert is its own chain root). Only fires when certs were parsed.
    """
    if not _lifecycle_parsed(estate):
        return []
    findings: list[Finding] = []
    for ca in estate.cas:
        for cert in ca.certs:
            _evaluated("CDP_AIA_ABSENT", _cert_ref(cert, ca.name))
        if ca.kind is CaKind.ROOT:
            continue
        for cert in ca.certs:
            missing: list[str] = []
            cdp_missing = not cert.cdp_urls
            aia_missing = not cert.aia_urls
            if cdp_missing:
                missing.append("CRL Distribution Points")
            if aia_missing:
                missing.append("Authority Information Access (CA Issuers)")
            if not missing:
                continue
            missing_text = " and ".join(missing)
            if cdp_missing and aia_missing:
                consequence = (
                    "so clients cannot fetch revocation data or build the "
                    "certificate chain"
                )
            elif cdp_missing:
                consequence = "so clients cannot fetch revocation data (CRL)"
            else:  # aia_missing
                consequence = (
                    "so clients cannot build the certificate chain (CA issuer info)"
                )
            findings.append(
                Finding(
                    check="CDP_AIA_ABSENT",
                    object_ref=_cert_ref(cert, ca.name),
                    evidence_complete=True,
                    severity=Severity.MEDIUM,
                    title=f"Issuing CA certificate lacks {missing_text}",
                    subject=ca.name,
                    detail=(
                        f"The certificate for {ca.name} ({cert.subject}) has no "
                        f"{missing_text} extension URL(s), {consequence}. Publish CDP and "
                        "AIA URLs on the CA certificate and reissue if necessary."
                    ),
                    source=f"CA cert for {ca.name}: {cert.subject} missing {missing_text}",
                    tier=CrlTier.ISSUING,
                )
            )
    return findings


def run_all(
    estate: Estate,
    *,
    now: datetime | None = None,
    warn_days: int = 90,
) -> list[Finding]:
    """Run every detector and return findings sorted worst-first, then by check."""
    findings = [
        *detect_esc1(estate),
        *detect_esc2(estate),
        *detect_esc3(estate),
        *detect_esc4(estate),
        *detect_esc5(estate),
        *detect_esc6(estate),
        *detect_esc7(estate),
        *detect_esc8(estate),
        *detect_esc9(estate),
        *detect_esc10(estate),
        *detect_esc14(estate),
        *detect_template_acl_gaps(estate),
        *detect_pki_acl_gaps(estate),
        *detect_ca_registry_gaps(estate),
        *detect_esc11(estate),
        *detect_esc13(estate),
        *detect_esc15(estate),
        *detect_esc16(estate),
        *detect_infra_cert_expiry(estate, now=now, warn_days=warn_days),
        *detect_weak_signing(estate),
        *detect_weak_key_size(estate),
        *detect_audit_config(estate),
        *detect_orphaned_templates(estate),
        *detect_ocsp_absence(estate),
        *detect_cdp_aia_absence(estate),
        *detect_acl_coverage_caveats(estate),
        *detect_collection_gaps(estate),
    ]
    findings.sort(key=lambda f: (SEVERITY_RANK[f.severity], f.check, f.subject))
    return findings


@dataclass(frozen=True)
class Evaluation:
    """Everything drift needs from one export: findings plus positive records.

    ``records`` holds (check, variant pattern, object key) for each object a
    detector fully evaluated; ``containers`` holds (check, object type) for each
    type it fully enumerated. ``objects`` is the identity inventory and
    ``guid_types`` the object types whose identity is an objectGUID (collector
    >= 0.9.0). ``trusted`` is only for hand-built findings (tests, callers
    that have no estate): every finding counts as fully evaluated.
    """

    findings: tuple[Finding, ...]
    objects: tuple[ObjectRef, ...] = ()
    records: frozenset[tuple[str, str, str]] = frozenset()
    containers: frozenset[tuple[str, str]] = frozenset()
    guid_types: frozenset[str] = frozenset()
    trusted: bool = False

    @classmethod
    def from_findings(cls, findings: list[Finding] | tuple[Finding, ...]) -> Evaluation:
        """A trusted evaluation of hand-built findings (no estate to check).

        The identity inventory is the findings' own object references.
        """
        refs = {f.object_ref.key: f.object_ref for f in findings if f.object_ref is not None}
        return cls(findings=tuple(findings), objects=tuple(refs.values()), trusted=True)

    def evaluated(self, check: str, variant: str, key: str) -> bool:
        if self.trusted:
            return True
        for rec_check, pattern, rec_key in self.records:
            if rec_check != check or rec_key != key:
                continue
            if pattern == variant or (pattern.endswith("*") and variant.startswith(pattern[:-1])):
                return True
        return False

    def container_evaluated(self, check: str, object_type: str) -> bool:
        return self.trusted or (check, object_type) in self.containers


# Object types whose identity is the objectGUID when the collector exports it.
# Object types whose identity is objectGUID when the collector exports it. A
# type counts as GUID-complete (absence => deletion) only when EVERY object of
# that type in the export actually carries a GUID; one GUID-less object of that
# type (a standalone CA, an unreadable container) drops the whole type back to
# the conservative legacy rule, so an exemption can never manufacture a deletion.
_GUID_TYPES: frozenset[str] = frozenset({"template", "pki", "ca", "dc", "principal", "crl"})


def _guid_complete_types(objects: tuple[ObjectRef, ...]) -> frozenset[str]:
    by_type: dict[str, list[ObjectRef]] = {}
    for ref in objects:
        by_type.setdefault(ref.type, []).append(ref)
    return frozenset(
        t for t in _GUID_TYPES
        if by_type.get(t) and all(ref.guid for ref in by_type[t])
    )


def evaluate(
    estate: Estate,
    *,
    now: datetime | None = None,
    warn_days: int = 90,
) -> Evaluation:
    """Run every detector and capture what each one positively evaluated.

    An unverified collector (stale or unknown version) yields no records at all:
    its per-object coverage markers default to "collected", so nothing it
    reports absent can count as fixed.
    """
    rec = _Recorder()
    token = _RECORDER.set(rec)
    try:
        findings = run_all(estate, now=now, warn_days=warn_days)
    finally:
        _RECORDER.reset(token)
    verified = _collector_verified(estate)
    objects = estate_objects(estate)
    guid_types = (
        _guid_complete_types(objects) if estate.manifest.guid_identity else frozenset()
    )
    return Evaluation(
        findings=tuple(findings),
        objects=objects,
        records=frozenset(rec.objects) if verified else frozenset(),
        containers=frozenset(rec.containers) if verified else frozenset(),
        guid_types=guid_types,
    )


# --- Coverage map for drift -----------------------------------------------------
# Check families: which posture checks consume which input. Used only by
# coverage_gaps(); the guard tests (tests/test_diff_coverage.py) degrade a full
# export along every path and assert no posture finding is reported resolved,
# so a check missing from its family fails the build.
_TEMPLATE_ACL_CHECKS: frozenset[str] = frozenset(
    {"ESC1", "ESC2", "ESC3", "ESC4", "ESC9", "ESC13", "ESC15"}
)
_TEMPLATE_CHECKS: frozenset[str] = _TEMPLATE_ACL_CHECKS | {
    "WEAK_TEMPLATE_KEY_SIZE",
    "ORPHANED_TEMPLATE",
}
_CA_AUDIT_CHECKS: frozenset[str] = frozenset({"CA_AUDIT_DISABLED", "CA_AUDIT_UNDERSCOPED"})
_CA_REGISTRY_CHECKS: frozenset[str] = frozenset(
    {"ESC6", "ESC7", "ESC11", "ESC16"}
) | _CA_AUDIT_CHECKS
_LIFECYCLE_CHECKS: frozenset[str] = frozenset(
    {
        "CA_CERT_EXPIRY",
        "CRL_EXPIRY",
        "WEAK_SIG_ALG",
        "WEAK_KEY_SIZE",
        "OCSP_URL_ABSENT",
        "CDP_AIA_ABSENT",
    }
)
# Everything keyed on a CA from ca-config.json: the registry checks, ESC15's
# patch state, and the CA-cert lifecycle checks (certs attach to CAs by name).
_CA_CHECKS: frozenset[str] = (
    _CA_REGISTRY_CHECKS
    | {"ESC15"}
    | (_LIFECYCLE_CHECKS - {"CRL_EXPIRY"})
)
# Pass → the posture checks that cannot be evaluated without it.
_PASS_COVERAGE: dict[str, frozenset[str]] = {
    "template-security": _TEMPLATE_ACL_CHECKS,
    "templates": _TEMPLATE_CHECKS,
    "ca-config": _CA_CHECKS,
    "oid-objects": frozenset({"ESC13"}),
    "enrollment-services": frozenset({"ORPHANED_TEMPLATE"}),
    "pki-acls": frozenset({"ESC5"}),
    "ca-security": frozenset({"ESC7"}),
    "enrollment-endpoints": frozenset({"ESC8"}),
    "esc10-dc-registry": frozenset({"ESC10", "ESC14"}),
    "esc14-altsecid": frozenset({"ESC14"}),
    "certs": _LIFECYCLE_CHECKS,
}
assert set(_PASS_COVERAGE) == KNOWN_PASSES, "every known pass needs a coverage entry"


@dataclass(frozen=True)
class CoverageGap:
    """A slice of posture the export could not evaluate — the *explanation*.

    Since review round 3, safety does not depend on these gaps: diff resolves
    only on positive evaluation records (see :func:`evaluate`). Gaps supply
    the human-readable reason a finding was withheld. ``checks`` None means
    every check; ``obj`` None means estate-wide; ``variant`` narrows to one
    finding variant.
    """

    reason: str
    checks: frozenset[str] | None = None
    obj: ObjectRef | None = None
    variant: str | None = None

    def covers(self, finding: Finding) -> bool:
        """True when this gap explains *finding*'s absence/improvement."""
        if is_degradation_note(finding):
            return False
        if self.checks is not None and finding.check not in self.checks:
            return False
        if self.obj is not None and (
            finding.object_ref is None or not same_object(self.obj, finding.object_ref)
        ):
            return False
        return self.variant is None or finding.variant == self.variant


def same_object(a: ObjectRef, b: ObjectRef) -> bool:
    """Best-effort identity for explanations: GUID when both have one, else aliases."""
    if a.type != b.type:
        return False
    if a.guid and b.guid:
        return a.guid == b.guid
    return bool(set(a.aliases) & set(b.aliases))


def _object_gap(
    reason: str, checks: frozenset[str], ref: ObjectRef, variant: str | None = None
) -> CoverageGap:
    return CoverageGap(reason=reason, checks=checks, obj=ref, variant=variant)


def coverage_gaps(estate: Estate) -> tuple[CoverageGap, ...]:
    """Everything *estate* could not evaluate, from the detectors' own predicates.

    ``diff`` uses this on the newer export: a finding that disappeared (or whose
    severity improved) may be reported resolved only if no gap covers it.
    Per-object gaps carry the object's stable aliases, never presentation text.
    """
    gaps: list[CoverageGap] = []
    m = estate.manifest

    if not _collector_verified(estate):
        gaps.append(
            CoverageGap(
                reason=(
                    f"collector version {m.collector_version or '(missing)'!r} is "
                    f"{m.collector_version_status.value}: coverage markers untrusted"
                )
            )
        )

    for pass_name, checks in _PASS_COVERAGE.items():
        if not _pass_collected(estate, pass_name):
            gaps.append(
                CoverageGap(
                    reason=f"pass '{pass_name}' not collected in the newer export",
                    checks=checks,
                )
            )
    if not _template_security_collected(estate):
        gaps.append(
            CoverageGap(reason="template security not collected", checks=_TEMPLATE_ACL_CHECKS)
        )
    if not _publication_data_available(estate):
        gaps.append(
            CoverageGap(
                reason="enrollment-services publication data not available",
                checks=frozenset({"ORPHANED_TEMPLATE"}),
            )
        )
    if not _lifecycle_parsed(estate):
        gaps.append(
            CoverageGap(
                reason="no cert/CRL data parsed (certs pass absent or [certs] extra missing)",
                checks=_LIFECYCLE_CHECKS,
            )
        )
    if not _esc14_enforcement_resolved(estate):
        gaps.append(
            CoverageGap(
                reason="DC StrongCertificateBindingEnforcement unresolved",
                checks=frozenset({"ESC14"}),
            )
        )
    if _pass_collected(estate, _ESC10_DC_REGISTRY_PASS) and not _dcs_discovered(estate):
        gaps.append(
            CoverageGap(
                reason="DC registry pass listed no domain controllers",
                checks=frozenset({"ESC10"}),
            )
        )

    for tmpl in estate.templates:
        ids = _template_ref(tmpl)
        if not _template_acl_readable(tmpl):
            gaps.append(
                _object_gap(
                    f"template DACL not obtained for {tmpl.name!r}", _TEMPLATE_ACL_CHECKS, ids
                )
            )
        elif not _owner_captured(tmpl.owner_sid):
            gaps.append(
                _object_gap(
                    f"template owner not captured for {tmpl.name!r}",
                    frozenset({"ESC4"}),
                    ids,
                    variant="owner",
                )
            )
        if not _template_key_size_captured(tmpl):
            gaps.append(
                _object_gap(
                    f"template minimum key size not captured for {tmpl.name!r}",
                    frozenset({"WEAK_TEMPLATE_KEY_SIZE"}),
                    ids,
                )
            )

    for obj in estate.acls:
        ids = _pki_ref(obj)
        label = _pki_subject(obj)
        if not _pki_acl_readable(obj):
            gaps.append(
                _object_gap(f"PKI object DACL not obtained for {label!r}", frozenset({"ESC5"}), ids)
            )
        elif not _owner_captured(obj.owner_sid):
            gaps.append(
                _object_gap(
                    f"PKI object owner not captured for {label!r}",
                    frozenset({"ESC5"}),
                    ids,
                    variant="owner",
                )
            )

    for ca in estate.cas:
        ids = _ca_ref(ca)
        if not _ca_registry_collected(ca):
            gaps.append(
                _object_gap(
                    f"CA registry configuration not collected for {ca.name!r}",
                    _CA_REGISTRY_CHECKS,
                    ids,
                )
            )
        else:
            if not _ca_security_readable(ca):
                gaps.append(
                    _object_gap(
                        f"no ca-security.json entry for {ca.name!r}", frozenset({"ESC7"}), ids
                    )
                )
            if not _owner_captured(ca.owner_sid):
                gaps.append(
                    _object_gap(
                        f"CA\\Security owner not captured for {ca.name!r}",
                        frozenset({"ESC7"}),
                        ids,
                        variant="owner",
                    )
                )
        if not _audit_filter_captured(ca):
            gaps.append(
                _object_gap(
                    f"CA AuditFilter not captured for {ca.name!r}", _CA_AUDIT_CHECKS, ids
                )
            )

    for ca_name, _kind, cert in _all_certs(estate):
        ids = _cert_ref(cert, ca_name)
        if not _cert_expiry_readable(cert):
            gaps.append(
                _object_gap(
                    f"CA certificate expiry not readable for {ca_name!r}",
                    frozenset({"CA_CERT_EXPIRY"}),
                    ids,
                )
            )
        if not _cert_key_size_readable(cert) or not _cert_key_alg_known(cert):
            gaps.append(
                _object_gap(
                    f"CA certificate key algorithm/size not readable for {ca_name!r}",
                    frozenset({"WEAK_KEY_SIZE"}),
                    ids,
                )
            )
        if not _cert_sig_alg_readable(cert):
            gaps.append(
                _object_gap(
                    f"CA certificate signature algorithm not readable for {ca_name!r}",
                    frozenset({"WEAK_SIG_ALG"}),
                    ids,
                )
            )

    for crl in estate.crls:
        ids = _crl_ref(crl)
        if not _crl_next_update_readable(crl):
            gaps.append(
                _object_gap(
                    f"CRL nextUpdate not readable for {crl.issuer!r}",
                    frozenset({"CRL_EXPIRY"}),
                    ids,
                )
            )
        elif not _crl_window_readable(crl):
            # Past-nextUpdate still evaluates, but the early-warning window
            # cannot, so an early-warning CRL_EXPIRY may vanish without a fix.
            gaps.append(
                _object_gap(
                    f"CRL thisUpdate not readable for {crl.issuer!r}",
                    frozenset({"CRL_EXPIRY"}),
                    ids,
                )
            )

    if _pass_collected(estate, _ESC10_DC_REGISTRY_PASS):
        for dc in estate.dcs:
            if not _dc_binding_known(dc):
                gaps.append(
                    _object_gap(
                        f"StrongCertificateBindingEnforcement unknown on {dc.name!r}",
                        frozenset({"ESC10"}),
                        _dc_ref(dc),
                    )
                )

    return tuple(gaps)
