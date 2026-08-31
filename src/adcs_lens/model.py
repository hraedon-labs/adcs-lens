"""Normalized data model — the contract every detector depends on.

These dataclasses are the boundary between the collector's on-disk JSON/DER
export and the deterministic detectors. They are frozen and use immutable
collection types (``tuple``/``frozenset``) so a parsed :class:`Estate` cannot be
mutated out from under a detector. Every field maps to a named collector output
(see ``plans/001`` Phase 1 and the threat model's data-source columns).

Cert/CRL lifecycle fields are populated only when the optional ``[certs]`` extra
is installed; otherwise they are ``None`` and lifecycle checks degrade to a note
(:attr:`Manifest.certs_parsed` records which happened).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum


class Severity(StrEnum):
    """Finding severity, ordered from worst to least."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# Worst-to-least rank, derived from the enum's declared order so it cannot drift.
SEVERITY_RANK: dict[Severity, int] = {sev: i for i, sev in enumerate(Severity)}


class AceType(StrEnum):
    """Access-control entry type."""

    ALLOW = "Allow"
    DENY = "Deny"


class CaKind(StrEnum):
    """Classification of a certification authority."""

    ROOT = "root"
    ISSUING = "issuing"
    STANDALONE = "standalone"


class CaPatchState(StrEnum):
    """Whether the CA is patched for CVE-2024-49019 (EKUwu / ESC15).

    The collector cannot yet read CA build/patch level statically, so it defaults
    to UNKNOWN: ESC15 then reports MEDIUM with an explicit "confirm patch state"
    caveat rather than a false HIGH on a patched estate. A future collector that
    captures the CA's OS build / KB level can populate PATCHED or UNPATCHED.
    """

    UNKNOWN = "unknown"
    PATCHED = "patched"
    UNPATCHED = "unpatched"


class CertKind(StrEnum):
    """Classification of a parsed certificate's role."""

    ROOT_CA = "root_ca"
    ISSUING_CA = "issuing_ca"
    CROSS_CA = "cross_ca"
    OTHER = "other"


class CrlTier(StrEnum):
    """Classification of a CRL by which CA tier it serves."""

    ROOT = "root"
    ISSUING = "issuing"


class AclKind(StrEnum):
    """Classification of a PKI object that carries a security descriptor."""

    NTAUTH = "ntauth"
    AIA = "aia"
    CDP = "cdp"
    PKS_CONTAINER = "pks_container"
    CA_OBJECT = "ca_object"


class EndpointKind(StrEnum):
    """An HTTP/RPC enrollment endpoint that AD CS can expose (ESC8 surface)."""

    WEB_ENROLLMENT = "web_enrollment"  # /certsrv — the classic NTLM-relay target
    CES = "ces"  # Certificate Enrollment Web Service
    NDES = "ndes"  # Network Device Enrollment (SCEP)


class EpaPolicy(StrEnum):
    """IIS Extended Protection for Authentication (channel-binding) policy."""

    NONE = "none"  # tokenChecking Off — relay not mitigated
    ALLOW = "allow"  # honored if the client offers it, but not required
    REQUIRE = "require"  # enforced — the ESC8 mitigation
    UNKNOWN = "unknown"  # endpoint present but EPA state not read


class StrongCertBinding(StrEnum):
    """DC ``StrongCertificateBindingEnforcement`` registry value (KDC key).

    Per KB5014754: 0 = Disabled (no strong-mapping check), 1 = Compatibility
    ("permissive" — strong mapping attempted, weak allowed with a warning),
    2 = Full ("strict" — strong mapping required).
    """

    DISABLED = "disabled"
    PERMISSIVE = "permissive"
    STRICT = "strict"
    UNKNOWN = "unknown"


class SchannelMappingMethod(StrEnum):
    """A bit of the Schannel ``CertificateMappingMethods`` registry DWORD.

    Bits per the TLS registry-settings doc: Subject/Issuer 0x1, Issuer 0x2,
    UPN 0x4, S4U2Self 0x8, S4U2Self-Explicit 0x10. ESC10 "case 1" is the UPN
    bit: a certificate's UPN SAN alone maps to an account, so an attacker who
    can write a victim's UPN can impersonate it.
    """

    SUBJECT_ISSUER = "subject_issuer"
    ISSUER = "issuer"
    UPN = "upn"
    S4U2SELF = "s4u2self"
    S4U2SELF_EXPLICIT = "s4u2self_explicit"
    UNKNOWN = "unknown"


class X509MappingForm(StrEnum):
    """The form of an ``altSecurityIdentities`` X.509 mapping value (ESC14).

    Strong (nonreusable) vs weak (reusable) per KB5014754. Strong forms bind to
    a specific certificate (serial, key id, or public-key hash); weak forms bind
    to reusable fields (subject/issuer DN, email, UPN) that an attacker can
    obtain a matching certificate for.
    """

    # Strong (nonreusable)
    ISSUER_SERIAL = "issuer_serial"  # X509:<I>...<SR>...
    SKI = "ski"  # X509:<SKI>...
    SHA1_PUBLIC_KEY = "sha1_public_key"  # X509:<SHA1-PUKEY>...
    # Weak (reusable)
    ISSUER_SUBJECT = "issuer_subject"  # X509:<I>...<S>...
    SUBJECT_ONLY = "subject_only"  # X509:<S>...
    RFC822 = "rfc822"  # X509:<RFC822>...
    PRINCIPAL_NAME = "principal_name"  # X509:<PN>...
    # Not an X.509 mapping (e.g. Kerberos:...) or unrecognized
    UNKNOWN = "unknown"


# X.509 mapping forms that are weak (reusable) and so exploitable when the DC's
# StrongCertificateBindingEnforcement is not strict.
WEAK_X509_MAPPING_FORMS: frozenset[X509MappingForm] = frozenset(
    {
        X509MappingForm.ISSUER_SUBJECT,
        X509MappingForm.SUBJECT_ONLY,
        X509MappingForm.RFC822,
        X509MappingForm.PRINCIPAL_NAME,
    }
)


@dataclass(frozen=True)
class PrincipalMapping:
    """A principal's altSecurityIdentities mappings (ESC14 surface)."""

    dn: str
    mappings: tuple[str, ...]


@dataclass(frozen=True)
class AceEntry:
    """One access-control entry on a PKI object."""

    trustee_sid: str
    trustee_name: str
    rights: tuple[str, ...]
    ace_type: AceType


@dataclass(frozen=True)
class CertLifecycle:
    """Lifecycle facts parsed from a CA/sub-CA certificate (``[certs]`` path)."""

    subject: str
    kind: CertKind
    not_before: datetime | None
    not_after: datetime | None
    sig_alg: str
    key_bits: int | None
    key_alg: str
    # Revocation/chain URLs parsed from the AIA and CRL Distribution Points
    # extensions. Empty tuples when the extension is absent or the cert was
    # parsed by an older certs.py that did not extract them (WI-022 / WI-032).
    ocsp_urls: tuple[str, ...] = ()
    cdp_urls: tuple[str, ...] = ()
    aia_urls: tuple[str, ...] = ()


@dataclass(frozen=True)
class Crl:
    """A certificate revocation list's freshness facts."""

    issuer: str
    this_update: datetime | None
    next_update: datetime | None
    tier: CrlTier
    source: str  # where it was captured (published CDP, AD container, host)


@dataclass(frozen=True)
class CertAuthority:
    """A certification authority's configuration, security, and certs."""

    name: str
    dns: str
    config_string: str
    kind: CaKind
    edit_flags: frozenset[str]
    interface_flags: frozenset[str]
    audit_filter: int | None
    security: tuple[AceEntry, ...]
    certs: tuple[CertLifecycle, ...]
    # OIDs the CA strips from every issued cert (policy\DisableExtensionList).
    # Empty by default so pre-field exports read as "no gap" (no false ESC16).
    disabled_extensions: frozenset[str] = frozenset()
    # Whether the CA is patched for CVE-2024-49019 (EKUwu / ESC15). Defaults to
    # UNKNOWN so the ESC15 detector degrades honestly (see CaPatchState).
    ca_patch_state: CaPatchState = CaPatchState.UNKNOWN
    # Security descriptor owner (normalized SID) of CA\\Security. Empty when not
    # captured; the ESC7 detector then skips owner-based control (a known gap,
    # not a false positive). A low-priv owner can rewrite the CA DACL to grant
    # itself Manage CA — the CA-level analogue of ESC4/ESC5 owner control.
    owner_sid: str = ""
    # False when this CA's registry-derived configuration (edit flags, interface
    # flags, audit filter, disabled extensions, CA\Security) was not collected —
    # e.g. the collector ran on a different host than this CA, since those hives
    # are read locally. Registry-gated detectors (ESC6/ESC7/ESC11/ESC16) skip
    # such CAs and an estate-level note names them, so a remote CA never reads
    # as silently clean. Default True so pre-field exports read as "collected".
    registry_config_collected: bool = True


@dataclass(frozen=True)
class CertTemplate:
    """A certificate template (``pKICertificateTemplate``)."""

    name: str
    display_name: str
    schema_version: int
    oid: str
    ekus: tuple[str, ...]
    name_flags: frozenset[str]
    enrollment_flags: frozenset[str]
    min_key_size: int | None
    issuance_policy_oids: tuple[str, ...]
    security: tuple[AceEntry, ...]
    published_by: tuple[str, ...]
    # True when the collector obtained this template's nTSecurityDescriptor.
    # Default True so pre-field exports read as "no gap" (no false signal).
    acl_obtained: bool = True
    # The template's configured CSP / key algorithm (lower-cased provider name).
    # Empty when the collector did not capture it; the weak-key detector then
    # applies the RSA baseline (the common case) and notes the caveat. A template
    # whose CSP indicates ECDSA is skipped (its min key size is a curve size).
    csp: str = ""
    # Security descriptor owner (normalized SID). Empty when not captured; the
    # ESC4 detector then skips owner-based control (a known gap, not a false
    # positive). A low-priv owner can rewrite the DACL, creating an ESC1 path.
    owner_sid: str = ""


@dataclass(frozen=True)
class PkiObjectAcl:
    """A security descriptor on a Public Key Services object/container."""

    object_dn: str
    kind: AclKind
    security: tuple[AceEntry, ...]
    # Security descriptor owner (normalized SID). Empty when not captured; the
    # ESC5 detector then skips owner-based control (a known gap, not a false
    # positive). A low-priv owner can rewrite the object's DACL.
    owner_sid: str = ""
    # True when the collector obtained this object's nTSecurityDescriptor.
    # False means the object exists but its descriptor could not be read (LDAP
    # denial, corrupt SD) — ESC5 must skip it rather than silently clearing it,
    # and a PKI_ACL_UNREADABLE note surfaces the gap (the PKI-object analogue of
    # the template acl_obtained marker). Default True for pre-field exports.
    acl_obtained: bool = True


@dataclass(frozen=True)
class EnrollmentEndpoint:
    """An HTTP/RPC enrollment endpoint and its relay-relevant configuration.

    ESC8 is the *enabling condition* for an NTLM relay to certificate enrollment:
    a Windows-authenticated HTTP enrollment endpoint that accepts NTLM, without
    Extended Protection (channel binding) and/or reachable over cleartext HTTP.
    The relay itself is out of scope; these fields are the statically-readable
    prerequisites the detector reasons over.
    """

    kind: EndpointKind
    name: str  # the IIS application / endpoint name (e.g. "/CertSrv")
    transports: frozenset[str]  # {"http", "https"} the hosting site binds
    ssl_required: bool  # the app requires HTTPS (so HTTP is blocked for it)
    windows_auth: bool  # Windows Authentication is enabled on the endpoint
    auth_providers: frozenset[str]  # lower-cased: {"negotiate", "ntlm", ...}
    epa: EpaPolicy


@dataclass(frozen=True)
class IssuanceOid:
    """An enterprise issuance-policy OID and any group it is linked to (ESC13).

    ``group_link`` is the DN of the group the OID maps to via msDS-OIDToGroupLink
    (the AMA link), or None. It is a distinguished name, not a SID.
    """

    oid: str
    name: str
    group_link: str | None


@dataclass(frozen=True)
class Manifest:
    """Provenance of one collection — what was (and was not) read."""

    collector_version: str
    collected_at: str
    host: str
    domain: str
    skipped_passes: tuple[str, ...]
    # True when the lifecycle (cert/CRL) data was actually parsed; False when the
    # [certs] extra was absent at ingest time, so lifecycle checks must degrade.
    certs_parsed: bool
    # True when enrollment-services.json was present and valid, including a valid
    # empty object. False when the export was absent, so an empty published_by
    # tuple means publication state is unknown rather than confirmed unpublished.
    enrollment_services_available: bool = False


@dataclass(frozen=True)
class DcConfiguration:
    """A domain controller's certificate mapping configuration (ESC10 surface).

    ``schannel_mapping_methods`` is the decoded Schannel ``CertificateMappingMethods``
    DWORD; ``strong_certificate_binding_enforcement`` is the KDC value. ESC10 keys
    on the UPN Schannel bit (case 1) and a disabled binding enforcement (case 2).
    """

    name: str
    strong_certificate_binding_enforcement: StrongCertBinding
    schannel_mapping_methods: frozenset[SchannelMappingMethod]


@dataclass(frozen=True)
class Estate:
    """The whole normalized export — the detectors' single input."""

    cas: tuple[CertAuthority, ...]
    templates: tuple[CertTemplate, ...]
    acls: tuple[PkiObjectAcl, ...]
    oids: tuple[IssuanceOid, ...]
    crls: tuple[Crl, ...]
    endpoints: tuple[EnrollmentEndpoint, ...]
    dcs: tuple[DcConfiguration, ...]
    principal_mappings: tuple[PrincipalMapping, ...]
    manifest: Manifest
