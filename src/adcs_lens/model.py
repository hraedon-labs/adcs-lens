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

import re
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


class CollectorVersionStatus(StrEnum):
    """Whether the export's collector version can be trusted to emit every field.

    CURRENT: parseable and at/above the core's minimum. STALE: parseable but
    older than the minimum, so fields the detectors branch on may be absent and
    their defaults read as "collected". UNKNOWN: missing, ``unknown``, or
    unparseable — it cannot be ranked, so it is never treated as current.
    """

    CURRENT = "current"
    STALE = "stale"
    UNKNOWN = "unknown"


# The oldest collector version whose export the core reads at full precision.
# A collector older than this may omit fields the detectors branch on; the
# core still degrades honestly, but a stale export should not read as silently
# clean. Warn, do not fail (WI-031). MIN is 0.8.0 because that release added
# the certs/ lifecycle pass (the whole CA cert/CRL expiry family), per-CA
# registry_config_collected (multi-CA honesty), the CA kind from CAType, and
# the PKI-object acl_obtained gap marker — a pre-0.8.0 export silently lacks
# all of them, so the warning is what keeps the gap visible.
MIN_COLLECTOR_VERSION = "0.8.0"
# From this collector version on, every AD-backed object carries its objectGUID
# (ingest requires it), and drift matches objects on it. Older exports fall
# back to name/OID/DN aliases, which drift treats conservatively.
GUID_IDENTITY_VERSION = "0.9.0"
# From this collector version on, every native read (LDAP paged searches,
# security descriptors, certutil -getreg, the CA\\Security hive, IIS and DC
# registry reads) is checked for success before a field is reported obtained or a
# container complete: a failed read is written as JSON null (the field is then
# listed in the object's ``unobtained``), never as an empty list, and each
# enumeration marker says whether its paged search provably returned every
# object. ``diff`` trusts evaluation records only from such an export; an older
# export is evaluated for ``scan`` but never resolves anything (it fails closed).
PROVEN_READS_VERSION = "0.10.0"
# From this collector version on (WI-044), every IIS enrollment endpoint names
# the host it was read on (``host``), the manifest names the collector host's
# FQDN (``host_fqdn``), and every pki-acls row says whether it is an enrollment
# service (``enrollment_service``); only such a row carries the CA host's
# computer-account SID (``ca_host_sid``, null when it could not be resolved,
# empty on every other object). Ingest requires these keys from such an export.
HOST_ATTRIBUTION_VERSION = "0.11.0"
# From this collector version on (live run 2026-10-13), every template carries
# ``ra_signatures`` (msPKI-RA-Signature, null when not obtained). Ingest requires
# the key from such an export; an older export has none (not collected).
RA_SIGNATURE_VERSION = "0.12.0"


def parse_collector_version(s: str) -> tuple[int, int, int] | None:
    """Parse a leading numeric ``major.minor.patch`` from *s*.

    Tolerates pre-release / build suffixes (``0.5.0-fixture`` → ``(0, 5, 0)``),
    short forms (``0.5`` → ``(0, 5, 0)``), and a leading ``v`` (``v0.5.0`` →
    ``(0, 5, 0)``). Returns ``None`` when no leading numeric version is found
    (``unknown`` / empty / garbage).
    """
    m = re.match(r"\s*v?(\d+)(?:\.(\d+))?(?:\.(\d+))?", s)
    if not m:
        return None
    major = int(m.group(1))
    minor = int(m.group(2)) if m.group(2) else 0
    patch = int(m.group(3)) if m.group(3) else 0
    return (major, minor, patch)


def collector_version_status(collector_version: str) -> CollectorVersionStatus:
    """Classify a collector version against :data:`MIN_COLLECTOR_VERSION`.

    Missing, ``unknown``, or unparseable versions are UNKNOWN — they cannot be
    ranked, so they are never treated as current (a version-less export may come
    from any collector, including one that predates fields the detectors assume
    were collected).
    """
    got = parse_collector_version(collector_version)
    minimum = parse_collector_version(MIN_COLLECTOR_VERSION)
    if got is None or minimum is None:
        return CollectorVersionStatus.UNKNOWN
    if got < minimum:
        return CollectorVersionStatus.STALE
    return CollectorVersionStatus.CURRENT


def version_has_guid_identity(collector_version: str) -> bool:
    """True for a collector version that exports objectGUID on AD objects."""
    got = parse_collector_version(collector_version)
    minimum = parse_collector_version(GUID_IDENTITY_VERSION)
    return got is not None and minimum is not None and got >= minimum


def version_attributes_hosts(collector_version: str) -> bool:
    """True for a collector version that writes host attribution (see HOST_ATTRIBUTION_VERSION)."""
    got = parse_collector_version(collector_version)
    minimum = parse_collector_version(HOST_ATTRIBUTION_VERSION)
    return got is not None and minimum is not None and got >= minimum


def version_reads_ra_signatures(collector_version: str) -> bool:
    """True for a collector version that reads msPKI-RA-Signature (see RA_SIGNATURE_VERSION)."""
    got = parse_collector_version(collector_version)
    minimum = parse_collector_version(RA_SIGNATURE_VERSION)
    return got is not None and minimum is not None and got >= minimum


def version_proves_reads(collector_version: str) -> bool:
    """True for a collector version that proves every read (see PROVEN_READS_VERSION)."""
    got = parse_collector_version(collector_version)
    minimum = parse_collector_version(PROVEN_READS_VERSION)
    return got is not None and minimum is not None and got >= minimum


# Collector passes that write their own export file, mapped to that file. A
# pass the manifest does not list in ``skipped_passes`` must have its file
# present (ingest enforces this for a CURRENT collector and records a
# degradation for an older/unknown one). The first four are core files the
# collector always writes; they have pass names so a hand-built or partial
# export can declare them absent honestly instead of reading as empty.
PASS_FILES: dict[str, str] = {
    "ca-config": "ca-config.json",
    "templates": "templates.json",
    "oid-objects": "oid-objects.json",
    "enrollment-services": "enrollment-services.json",
    "pki-acls": "pki-acls.json",
    "ca-security": "ca-security.json",
    "enrollment-endpoints": "web-endpoints.json",
    "esc10-dc-registry": "dc-config.json",
    "esc14-altsecid": "principal-mappings.json",
    "certs": "certs/index.json",
}
# Every pass name the core understands: the file-backed passes plus
# ``template-security`` (template DACLs, carried inside templates.json).
KNOWN_PASSES: frozenset[str] = frozenset({*PASS_FILES, "template-security"})


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
    # The CA host's AD computer object (collector >= 0.12.0): read from the
    # domain NC for each enrollment service whose dNSHostName resolved to one
    # computer object. Never an enrollment-service row, never exempts anyone.
    CA_COMPUTER = "ca_computer"


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
    # objectGUID (32 hex chars) — the immutable identity drift matches on.
    # Required for collector >= GUID_IDENTITY_VERSION; empty for older exports.
    object_guid: str = ""


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
    # SHA-256 of the DER encoding (lower-case hex): the certificate's stable
    # identity across exports. Empty when built without DER (tests).
    fingerprint: str = ""
    # Fields the library could not derive from this (loaded) certificate: an
    # unknown signature OID, an unsupported key type, a malformed extension.
    unobtained: frozenset[str] = frozenset()


@dataclass(frozen=True)
class Crl:
    """A certificate revocation list's freshness facts."""

    issuer: str
    this_update: datetime | None
    next_update: datetime | None
    tier: CrlTier | None  # None: not obtained (derived from the AIA certs)
    source: str  # where it was captured (published CDP, AD container, host)
    # objectGUID of the CDP object the CRL was read from (collector >= 0.9.0).
    object_guid: str = ""


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
    # False when ca-security.json was present but carried no entry for this CA
    # (the collector writes one per CA, possibly empty). ESC7 then skips the
    # CA's DACL and names the gap rather than reading "no ACEs" as clean.
    security_collected: bool = True
    # objectGUID (32 hex chars) — the immutable identity drift matches on.
    # Required for collector >= GUID_IDENTITY_VERSION; empty for older exports.
    object_guid: str = ""
    # False for a standalone CA added from the local registry: it has no
    # Enrollment Services object, so it has no objectGUID either.
    enrollment_service: bool = True
    # Detector inputs the collector tried to read and could not (a failed
    # certutil / LDAP / registry / IIS read, written as JSON null). The field then
    # holds a placeholder that must never be read as a value: a detector that
    # needs it cannot decide this object, and no record vouches for it.
    unobtained: frozenset[str] = frozenset()


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
    # objectGUID (32 hex chars) — the immutable identity drift matches on.
    # Required for collector >= GUID_IDENTITY_VERSION; empty for older exports.
    object_guid: str = ""
    # The template's configured CSP / key algorithm (lower-cased provider name).
    # Empty when the collector did not capture it; the weak-key detector then
    # applies the RSA baseline (the common case) and notes the caveat. A template
    # whose CSP indicates ECDSA is skipped (its min key size is a curve size).
    csp: str = ""
    # Security descriptor owner (normalized SID). Empty when not captured; the
    # ESC4 detector then skips owner-based control (a known gap, not a false
    # positive). A low-priv owner can rewrite the DACL, creating an ESC1 path.
    owner_sid: str = ""
    # msPKI-RA-Signature ([MS-CRTD] 2.18): the number of authorized ("recovery
    # agent", in the specification's words) signatures a request for this
    # template must carry (collector >= RA_SIGNATURE_VERSION). None when it was
    # not obtained (listed in ``unobtained``) or not collected (an older
    # export): unknown, never "0 required". ESC1/ESC2/ESC3 read it.
    ra_signatures: int | None = None
    # Detector inputs the collector tried to read and could not (a failed
    # certutil / LDAP / registry / IIS read, written as JSON null). The field then
    # holds a placeholder that must never be read as a value: a detector that
    # needs it cannot decide this object, and no record vouches for it.
    unobtained: frozenset[str] = frozenset()


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
    # objectGUID (32 hex chars) — the immutable identity drift matches on.
    # Required for collector >= GUID_IDENTITY_VERSION; empty for older exports.
    object_guid: str = ""
    # The computer-account SID of the CA host this enrollment-service object
    # names in its dNSHostName (collector >= HOST_ATTRIBUTION_VERSION). AD CS
    # setup grants that account control of its own enrollment-service object,
    # so ESC5 does not treat it as low-privilege on THIS object only. Empty on
    # every other object and in older exports; listed in ``unobtained`` when the
    # collector could not resolve it.
    ca_host_sid: str = ""
    # True for the row of an Enrollment Services object (collector >=
    # HOST_ATTRIBUTION_VERSION: the row came from the Enrollment Services
    # search). The only rows that may carry ``ca_host_sid``.
    enrollment_service: bool = False
    # Detector inputs the collector tried to read and could not (a failed
    # certutil / LDAP / registry / IIS read, written as JSON null). The field then
    # holds a placeholder that must never be read as a value: a detector that
    # needs it cannot decide this object, and no record vouches for it.
    unobtained: frozenset[str] = frozenset()


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
    # The host whose IIS configuration this endpoint was read from: the row's
    # ``host`` (collector >= HOST_ATTRIBUTION_VERSION, which must equal the
    # manifest's ``host_fqdn``; ingest attributes it to that FQDN, or to the
    # short ``host`` when that FQDN is not believed) or, for an older
    # export, the manifest's ``host``
    # (the collector reads IIS on its own host only, and 0.10.0 wrote its short
    # name). Empty only for a hand-built estate.
    host: str = ""
    # Detector inputs the collector tried to read and could not (a failed
    # IIS configuration read, written as JSON null). The field then
    # holds a placeholder that must never be read as a value: a detector that
    # needs it cannot decide this object, and no record vouches for it.
    unobtained: frozenset[str] = frozenset()


@dataclass(frozen=True)
class IssuanceOid:
    """An enterprise issuance-policy OID and any group it is linked to (ESC13).

    ``group_link`` is the DN of the group the OID maps to via msDS-OIDToGroupLink
    (the AMA link), or None. It is a distinguished name, not a SID.
    """

    oid: str
    name: str
    group_link: str | None
    # objectGUID (32 hex chars) — the immutable identity drift matches on.
    # Required for collector >= GUID_IDENTITY_VERSION; empty for older exports.
    object_guid: str = ""


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
    # Present is not complete: "confirmed unpublished" also needs the
    # enrollment-services container in ``enumeration_complete`` (proven exports).
    enrollment_services_available: bool = False
    # Passes whose export file was absent although the manifest did not list
    # them as skipped. Only an older/unknown collector can produce this (ingest
    # rejects it for a current one); detectors treat these exactly like skipped
    # passes and a note names each one.
    missing_passes: tuple[str, ...] = ()
    # Containers whose enumeration the collector marked complete AND whose marked
    # count matched the rows ingested. A collector >= PROVEN_READS_VERSION marks a
    # container complete only when its paged search provably returned every
    # object. Every evaluation record needs the containers its check declares.
    enumeration_complete: frozenset[str] = frozenset()
    # The collector host's FQDN as the collector resolved it (collector >=
    # HOST_ATTRIBUTION_VERSION; its short name when DNS gave nothing better).
    # The IIS pass reads this host only. Empty when the export wrote none, or
    # wrote one whose first label is not ``host`` (not believed: the export is
    # then attributed to ``host``).
    host_fqdn: str = ""

    @property
    def collector_version_status(self) -> CollectorVersionStatus:
        """Derived from ``collector_version`` — never stored, so never inconsistent."""
        return collector_version_status(self.collector_version)

    @property
    def guid_identity(self) -> bool:
        """True when the collector exports objectGUID identity (>= 0.9.0)."""
        return version_has_guid_identity(self.collector_version)

    @property
    def reads_proven(self) -> bool:
        """True when the collector proves its reads (>= PROVEN_READS_VERSION)."""
        return version_proves_reads(self.collector_version)

    @property
    def uncollected_passes(self) -> frozenset[str]:
        """Passes not collected: declared skipped, or missing from the export."""
        return frozenset(self.skipped_passes) | frozenset(self.missing_passes)


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
    # objectGUID (32 hex chars) — the immutable identity drift matches on.
    # Required for collector >= GUID_IDENTITY_VERSION; empty for older exports.
    object_guid: str = ""
    # Detector inputs the collector tried to read and could not (a failed
    # remote registry (WMI) read, written as JSON null). The field then
    # holds a placeholder that must never be read as a value: a detector that
    # needs it cannot decide this object, and no record vouches for it.
    unobtained: frozenset[str] = frozenset()


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
    # Certificates from certs/index.json whose ca_name matches no CA in
    # ca-config.json, as (ca_name, cert). The offline root is the usual case: it
    # is published in AIA but is not an enrollment service. They are evaluated
    # by the lifecycle detectors (expiry, signature, key size), never dropped.
    unattached_certs: tuple[tuple[str, CertLifecycle], ...] = ()


# The model attribute each join compares on the joined-to object, by the join's
# name in the collector's $JOINS table (tests/test_object_schema.py ties the two:
# $JOINS "cn" -> name, "oid" -> oid). Every implementation reads its key from
# here (a declaration, like KNOWN_PASSES), so the table cannot drift from what
# is compared.
JOIN_KEYS: dict[str, tuple[str, ...]] = {
    "publication": ("name",),  # template cn (MS-WCCE: identical)
    "publication-legacy": ("name", "oid"),  # exports older than 0.10.0
    "cert-ca": ("name",),  # CA cn
    "ca-security": ("name",),  # CA cn
    "publisher-ca": ("name",),  # CA cn
    "oid-link": ("oid",),  # OID object's msPKI-Cert-Template-OID
    "crl-tier": ("ca_name",),  # the AIA object's cn, per certs/index.json row
}
