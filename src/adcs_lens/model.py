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
# From this collector version on, every certs/index.json row records the length
# in bytes of the value it copied from AD (``bytes``), so ingest can tell a value
# AD holds that does not parse (reported: CRL_UNPARSEABLE / CA_CERT_UNPARSEABLE)
# from a file damaged after collection (an IngestError), and an AIA value that
# the collector's own parser could not load is written as it is with ``kind``
# null instead of failing the AIA object. Ingest requires ``bytes`` from such an
# export.
BYTE_LENGTH_VERSION = "0.13.0"
# Object populations a collector first exports at a given version, as
# "<object type>/<population>". An export from an older (or unknown) collector
# did not look for them: its silence about them is "not collected", never
# "absent". Diff never resolves an object of such a population against that
# export (not re-evaluated, exit 3), and a finding on one first seen after an
# upgrade is reported as FIRST OBSERVED (coverage gained) - still a regression
# for --exit-code (exit 1), but labelled as not proof that the estate changed
# (review rounds 1 and 2 of the 2026-10-13 fixes, Sol B1).
POPULATION_VERSIONS: dict[str, str] = {
    # The CA hosts' AD computer objects, pki-acls rows of kind ca_computer.
    "pki/ca_computer": "0.12.0",
}
# Decoded fields whose decoding table a collector version corrected, as
# "<object type>.<field>": an export from an older collector carries names from
# the superseded table and no raw value to re-decode (review round 2, DeepSeek
# B1).
#   template.name_flags: collector < 0.12.0 decoded msPKI-Certificate-Name-Flag
#   with several bits shifted (0x8 and 0x10000 among them, an ESC1 input).
# The uncertainty is per object and per check, not per export (review round 3,
# Sol B1): the superseded table is known (TEMPLATE_NAME_FLAGS_BEFORE_0_12), so
# a template's names can be re-read through it (superseded_name_flag_reading),
# and a check is uncertain on that template only when the two readings disagree
# on the flags it turns on. Elsewhere (0x1, ENROLLEE_SUPPLIES_SUBJECT, decodes
# alike in both tables) the comparison is between equals and diff compares as
# usual.
DECODER_VERSIONS: dict[str, str] = {
    "template.name_flags": "0.12.0",
}
# msPKI-Certificate-Name-Flag bits ([MS-CRTD] 2.28), the core's own table: from
# collector 0.12.0 the export carries the raw value and the core decodes it, so
# a future correction here needs no collector change.
TEMPLATE_NAME_FLAGS: dict[int, str] = {
    0x00000001: "ENROLLEE_SUPPLIES_SUBJECT",
    0x00000008: "OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME",
    0x00010000: "ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME",
    0x00400000: "SUBJECT_ALT_REQUIRE_DOMAIN_DNS",
    0x00800000: "SUBJECT_ALT_REQUIRE_SPN",
    0x01000000: "SUBJECT_ALT_REQUIRE_DIRECTORY_GUID",
    0x02000000: "SUBJECT_ALT_REQUIRE_UPN",
    0x04000000: "SUBJECT_ALT_REQUIRE_EMAIL",
    0x08000000: "SUBJECT_ALT_REQUIRE_DNS",
    0x10000000: "SUBJECT_REQUIRE_DNS_AS_CN",
    0x20000000: "SUBJECT_REQUIRE_EMAIL",
    0x40000000: "SUBJECT_REQUIRE_COMMON_NAME",
    0x80000000: "SUBJECT_REQUIRE_DIRECTORY_PATH",
}
# The msPKI-Certificate-Name-Flag table every collector before 0.12.0 used
# (unchanged from the first collector until 0.12.0 corrected it): the names an
# older export carries, by the raw bit they stood for. Bits 0x01000000,
# 0x02000000 and 0x80000000 had no entry (never named). Only for re-reading an
# older export's names; never to decode.
TEMPLATE_NAME_FLAGS_BEFORE_0_12: dict[int, str] = {
    0x00000001: "ENROLLEE_SUPPLIES_SUBJECT",
    0x00000008: "ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME",
    0x00010000: "SUBJECT_ALT_REQUIRE_DOMAIN_DNS",
    0x00400000: "SUBJECT_ALT_REQUIRE_UPN",
    0x00800000: "SUBJECT_ALT_REQUIRE_EMAIL",
    0x04000000: "SUBJECT_ALT_REQUIRE_DNS",
    0x08000000: "SUBJECT_REQUIRE_DNS_AS_CN",
    0x10000000: "SUBJECT_REQUIRE_DIRECTORY_PATH",
    0x20000000: "SUBJECT_REQUIRE_EMAIL",
    0x40000000: "SUBJECT_REQUIRE_COMMON_NAME",
}
# msPKI-Enrollment-Flag bits the detectors read ([MS-CRTD] 2.26), named as the
# collector names them.
TEMPLATE_ENROLLMENT_FLAGS: dict[int, str] = {
    0x00000002: "PEND_ALL_REQUESTS",
    0x00000008: "PUBLISH_TO_DS",
    0x00000020: "AUTO_ENROLLMENT",
    0x00000100: "USER_INTERACTION_REQUIRED",
    0x00080000: "NO_SECURITY_EXTENSION",
}


def decode_flags(raw: int, table: dict[int, str]) -> frozenset[str]:
    """The names of the bits of a (signed or unsigned) 32-bit flag value."""
    value = raw & 0xFFFFFFFF
    return frozenset(name for bit, name in table.items() if value & bit)


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


def version_records_lengths(collector_version: str) -> bool:
    """True for a collector version that records each cert/CRL value's length
    (see BYTE_LENGTH_VERSION)."""
    got = parse_collector_version(collector_version)
    minimum = parse_collector_version(BYTE_LENGTH_VERSION)
    return got is not None and minimum is not None and got >= minimum


def populations_not_collected(collector_version: str) -> frozenset[str]:
    """The POPULATION_VERSIONS populations a collector version does not export
    (all of them for a missing or unparseable version)."""
    got = parse_collector_version(collector_version)
    out = set()
    for population, first in POPULATION_VERSIONS.items():
        minimum = parse_collector_version(first)
        if got is None or minimum is None or got < minimum:
            out.add(population)
    return frozenset(out)


def decoders_superseded(collector_version: str) -> frozenset[str]:
    """The DECODER_VERSIONS fields a collector version may have decoded with a
    superseded table: all of them for a missing or unparseable version, which
    names no table (review round 3, DeepSeek N1: unknown fails toward the gap,
    as populations_not_collected does). Intended and conservative: when both
    exports of a diff name no table, a template whose readings disagree is
    withheld even if both in fact used the same table (review round 4,
    DeepSeek N4) - never a false resolution."""
    got = parse_collector_version(collector_version)
    out = set()
    for field, first in DECODER_VERSIONS.items():
        minimum = parse_collector_version(first)
        if got is None or minimum is None or got < minimum:
            out.add(field)
    return frozenset(out)


_NAME_FLAG_BITS_BEFORE_0_12 = {name: bit for bit, name in TEMPLATE_NAME_FLAGS_BEFORE_0_12.items()}


def superseded_name_flag_reading(
    names: frozenset[str], raw: int | None, collector_version: str
) -> frozenset[str] | None:
    """The other reading of a template's name flags, or None when there is none:
    the core decoded them from the raw value, or the collector version used the
    corrected table. Otherwise the names may have come from the superseded table
    (TEMPLATE_NAME_FLAGS_BEFORE_0_12): each name is re-read as the bit it stood
    for there, decoded with the corrected table. A name that table never wrote
    is kept as it is."""
    if raw is not None or "template.name_flags" not in decoders_superseded(collector_version):
        return None
    out: set[str] = set()
    for name in names:
        bit = _NAME_FLAG_BITS_BEFORE_0_12.get(name)
        out.add(TEMPLATE_NAME_FLAGS[bit] if bit is not None else name)
    return frozenset(out)


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


# Schannel CertificateMappingMethods bits (the collector's $SCHANNEL_BITS), for
# the core's own decode of the raw DWORD (collector >= 0.12.0).
SCHANNEL_MAPPING_BITS: dict[int, str] = {
    0x1: "subject_issuer",
    0x2: "issuer",
    0x4: "upn",
    0x8: "s4u2self",
    0x10: "s4u2self_explicit",
}


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
    # Collector >= 0.12.0 (review round 2, Sol B2): the ACE was inherited, and
    # it is inherit-only (it applies to child objects, never to this one: the
    # access check skips it, [MS-ADTS] Checking Object-Specific Access 3.1).
    # ACEs are kept in DACL order, which the access check evaluates in.
    inherited: bool = False
    inherit_only: bool = False


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
    # Set when the value AD holds for this certificate does not load in the
    # [certs] library: one of the UNPARSEABLE_* classes. Such a placeholder
    # carries no certificate fact (every lifecycle field is listed in
    # ``unobtained``), so every check on it is undecided. "" for a certificate
    # that loaded.
    unparseable: str = ""
    # True when that value is not a certificate at all: the collector's own
    # loader (.NET) rejected it too (collector >= 0.13.0 writes kind null), or no
    # loader can read it (empty, one byte, truncated). CA_CERT_UNPARSEABLE
    # reports it, and it decides no CRL tier. False for an unparseable value the
    # collector loaded (CA_CERT_NOT_EVALUATED: a certificate adcs-lens cannot read).
    not_a_certificate: bool = False
    # The certs/ file the value was read from and its length in bytes (never
    # the bytes themselves). Set for unparseable placeholders.
    file: str = ""
    byte_length: int | None = None
    # Whether the export recorded the value's length (certs/index.json
    # ``bytes``, collector >= 0.13.0), so the file is known to be the whole
    # value the collector read.
    length_recorded: bool = False
    # objectGUID of the AIA object holding a value that is not a certificate
    # (collector >= 0.13.0): that value's identity across exports.
    aia_object_guid: str = ""


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
    # Set when the value the CDP object holds does not load as a CRL at all: one
    # of the UNPARSEABLE_* classes. Such a placeholder carries no CRL fact
    # (issuer, thisUpdate, nextUpdate are not obtained), so CRL_EXPIRY is
    # undecided on it, and CRL_UNPARSEABLE reports it. "" for a CRL that loaded.
    unparseable: str = ""
    # The CDP object's cn (certs/index.json ca_name), the certs/ file the value
    # was read from and its length in bytes (never the bytes themselves).
    ca_name: str = ""
    file: str = ""
    byte_length: int | None = None
    # As CertLifecycle.length_recorded.
    length_recorded: bool = False


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
    # The raw msPKI-Certificate-Name-Flag / msPKI-Enrollment-Flag values
    # (collector >= 0.12.0; None for an older export). When present, ingest
    # decodes name_flags / enrollment_flags from them with the core's tables
    # (TEMPLATE_NAME_FLAGS / TEMPLATE_ENROLLMENT_FLAGS), not the collector's.
    name_flags_raw: int | None = None
    enrollment_flags_raw: int | None = None
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


# How a cert/CRL value that does not load is classified (CertLifecycle /
# Crl ``unparseable``). Computed from the length and the outer DER header only;
# the bytes themselves are never reported.
UNPARSEABLE_EMPTY = "empty"  # zero bytes
UNPARSEABLE_ZERO_BYTE = "single-zero-byte"  # exactly one byte, 0x00
UNPARSEABLE_SINGLE_BYTE = "single-byte"  # exactly one byte, any other value
UNPARSEABLE_TRUNCATED = "truncated-der"  # a DER SEQUENCE header longer than the value
UNPARSEABLE_NOT_DER = "not-der"  # no DER SEQUENCE: another tag, BER, trailing bytes
UNPARSEABLE_MALFORMED = "malformed-der"  # a complete SEQUENCE the parser rejects
# Classes no certificate or CRL parser can load: the value certainly holds no
# CRL / certificate. The others may be an encoding another parser accepts.
UNPARSEABLE_CERTAIN: frozenset[str] = frozenset(
    {UNPARSEABLE_EMPTY, UNPARSEABLE_ZERO_BYTE, UNPARSEABLE_SINGLE_BYTE, UNPARSEABLE_TRUNCATED}
)


def classify_unparseable(data: bytes) -> str:
    """Classify a cert/CRL value that did not load (see UNPARSEABLE_*).

    Reads only the length and the outer tag / length octets (X.690 8.1.2-8.1.3).
    A certificate and a CRL are both a DER SEQUENCE (tag 0x30) with a definite
    length; a header that promises more bytes than the value holds is a
    truncated value, and anything that is not one complete SEQUENCE is not DER
    (an indefinite BER length, another tag, trailing bytes).
    """
    n = len(data)
    if n == 0:
        return UNPARSEABLE_EMPTY
    if n == 1:
        return UNPARSEABLE_ZERO_BYTE if data[0] == 0 else UNPARSEABLE_SINGLE_BYTE
    if data[0] != 0x30:
        return UNPARSEABLE_NOT_DER
    first = data[1]
    if first < 0x80:
        header, length = 2, first
    else:
        count = first & 0x7F
        if count == 0 or count > 4:
            # 0x80 is BER's indefinite length (not DER); more than four length
            # octets is beyond any value the export accepts.
            return UNPARSEABLE_NOT_DER
        if n < 2 + count:
            return UNPARSEABLE_TRUNCATED
        header, length = 2 + count, int.from_bytes(data[2 : 2 + count], "big")
    if header + length > n:
        return UNPARSEABLE_TRUNCATED
    if header + length < n:
        return UNPARSEABLE_NOT_DER
    return UNPARSEABLE_MALFORMED


# A BER (X.690 8.1) element reader for could_be_certificate. Lenient on
# purpose (any definite length form, indefinite lengths, high tag numbers):
# it bounds what SOME certificate loader might accept, not what DER allows.
_BER_MAX_DEPTH = 64
_BerElement = tuple[int, int, int, int]  # first tag octet, content start/end, element end


def _ber(data: bytes, pos: int, end: int, depth: int = 0) -> _BerElement | None:
    """The BER element starting at data[pos], within data[:end]; None when no
    complete element starts there."""
    if depth > _BER_MAX_DEPTH or pos >= end:
        return None
    tag, i = data[pos], pos + 1
    if tag & 0x1F == 0x1F:  # high tag number form: base-128 octets
        while i < end and data[i] & 0x80:
            i += 1
        i += 1
    if i >= end:
        return None
    first, i = data[i], i + 1
    if first == 0x80:  # indefinite: constructed only, ends at end-of-contents 00 00
        if not tag & 0x20:
            return None
        start = i
        while not (i + 1 < end and data[i] == 0 and data[i + 1] == 0):
            child = _ber(data, i, end, depth + 1)
            if child is None:
                return None
            i = child[3]
        return tag, start, i, i + 2
    if first == 0xFF:  # reserved (X.690 8.1.3.5)
        return None
    length = first
    if first & 0x80:
        count = first & 0x7F
        if i + count > end:
            return None
        length, i = int.from_bytes(data[i : i + count], "big"), i + count
    if i + length > end:
        return None
    return tag, i, i + length, i + length


def _ber_children(data: bytes, element: _BerElement) -> list[_BerElement] | None:
    """The elements a constructed element holds; None when they do not decode."""
    tag, i, content_end, _ = element
    if not tag & 0x20:
        return None
    out: list[_BerElement] = []
    while i < content_end:
        child = _ber(data, i, content_end)
        if child is None:
            return None
        out.append(child)
        i = child[3]
    return out


_SEQUENCE_TAG = 0x30
_INTEGER_TAG = 0x02
_VERSION_TAG = 0xA0  # tbsCertificate version [0] EXPLICIT


def _ber_nonempty(element: _BerElement, tag: int) -> bool:
    return element[0] == tag and element[1] < element[2]


def _ber_algorithm(data: bytes, element: _BerElement) -> bool:
    if element[0] != _SEQUENCE_TAG:
        return False
    fields = _ber_children(data, element)
    # AlgorithmIdentifier has an OID and, optionally, one parameters value.
    return bool(
        fields
        and len(fields) <= 2
        and _ber_nonempty(fields[0], 0x06)
        and not data[fields[0][2] - 1] & 0x80
    )


def _ber_bit_string(data: bytes, element: _BerElement, depth: int = 0) -> bool:
    if depth > _BER_MAX_DEPTH:
        return False
    if element[0] == 0x03:
        start, end = element[1:3]
        # Even an empty BIT STRING must carry its unused-bits octet.
        return start < end and data[start] <= 7 and (end > start + 1 or data[start] == 0)
    if element[0] != 0x23:
        return False
    fields = _ber_children(data, element)
    return fields is not None and all(_ber_bit_string(data, f, depth + 1) for f in fields)


def could_be_certificate(data: bytes) -> bool:
    """Whether *data* has the mandatory structure of an X.509 Certificate (RFC 5280
    4.1) under a lenient BER reading, so that some certificate loader might
    read it.

    Certificate ::= SEQUENCE { tbsCertificate SEQUENCE, signatureAlgorithm
    SEQUENCE, signatureValue BIT STRING }, and tbsCertificate starts with an
    optional [0] version, then serialNumber INTEGER, signature, issuer,
    validity, subject and subjectPublicKeyInfo (each a SEQUENCE). Their required
    inner fields must also be present. This is a necessary structural check,
    not certificate validation or a prediction of any particular loader. False means
    no loader can read it as a certificate (an empty SEQUENCE, a SEQUENCE of
    one INTEGER, an OCTET STRING); True still leaves encodings a loader may or
    may not accept (BER lengths, bytes after the certificate, a field the
    [certs] library rejects).
    """
    outer = _ber(data, 0, len(data))
    if outer is None or outer[0] != _SEQUENCE_TAG:
        return False
    parts = _ber_children(data, outer)
    if parts is None or [p[0] for p in parts[:2]] != [_SEQUENCE_TAG] * 2 or len(parts) != 3:
        return False
    if not _ber_algorithm(data, parts[1]) or not _ber_bit_string(data, parts[2]):
        return False
    tbs = _ber_children(data, parts[0])
    if tbs is None:
        return False
    if tbs and tbs[0][0] == _VERSION_TAG:
        version = _ber_children(data, tbs[0])
        if not version or len(version) != 1 or not _ber_nonempty(version[0], _INTEGER_TAG):
            return False
        tbs = tbs[1:]
    if len(tbs) < 6 or [t[0] for t in tbs[:6]] != [_INTEGER_TAG] + [_SEQUENCE_TAG] * 5:
        return False
    serial, signature, _issuer, validity, _subject, spki = tbs[:6]
    times = _ber_children(data, validity)
    key = _ber_children(data, spki)
    return bool(
        _ber_nonempty(serial, _INTEGER_TAG)
        and _ber_algorithm(data, signature)
        and times is not None
        and len(times) == 2
        and all(t[0] in (0x17, 0x18) and t[1] < t[2] for t in times)
        and key is not None
        and len(key) == 2
        and _ber_algorithm(data, key[0])
        and _ber_bit_string(data, key[1])
    )


# Why a lifecycle (cert/CRL) pass produced no data (Manifest.certs_not_parsed_reason).
LIFECYCLE_EXTRA_MISSING = "certs-extra-missing"  # export lists certs/CRLs; [certs] absent
LIFECYCLE_PASS_SKIPPED = "certs-pass-skipped"  # the manifest lists the certs pass as skipped
LIFECYCLE_NO_INDEX = "no-certs-index"  # the export has no certs/index.json
LIFECYCLE_EMPTY_INDEX = "empty-certs-index"  # certs/index.json lists no entries


def _plural(n: int, noun: str) -> str:
    return f"{n} {noun}" if n == 1 else f"{n} {noun}s"


def _lifecycle_reason_text(m: Manifest) -> str:
    reason = m.certs_not_parsed_reason
    if reason == LIFECYCLE_EXTRA_MISSING:
        return (
            "the optional [certs] extra is not installed or could not be imported "
            "(pip install adcs-lens[certs]), "
            f"so the {_plural(m.certs_index_certs, 'certificate')} and "
            f"{_plural(m.certs_index_crls, 'CRL')} the export lists were not parsed"
        )
    if reason == LIFECYCLE_PASS_SKIPPED:
        return "the export's certs pass was skipped by the collector (no cert/CRL data was read)"
    if reason == LIFECYCLE_NO_INDEX:
        return "the export has no certs/index.json (the collector did not write the certs pass)"
    if reason == LIFECYCLE_EMPTY_INDEX:
        return "certs/index.json lists no certificates and no CRLs (the export has no cert data)"
    return ""


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
    # The forest's dSHeuristics (CN=Directory Service,CN=Windows NT,CN=Services
    # in the Configuration NC; collector >= 0.12.0): "" when the attribute is
    # not set (every heuristic at its default), None when it was not read or
    # not collected. Character 29 is BlockOwnerImplicitRights ([MS-ADTS]
    # 6.1.1.2.4.1.2), which ESC5 reads for a computer object's owner.
    ds_heuristics: str | None = None
    # Why lifecycle (cert/CRL) data was not parsed: one of the LIFECYCLE_* reason
    # codes below, or "" when it was parsed (or the reason is unknown, as for a
    # Manifest built by hand). ``certs_index_*`` are the rows certs/index.json
    # lists, counted whether or not the [certs] extra could parse them.
    certs_not_parsed_reason: str = ""
    certs_index_certs: int = 0
    certs_index_crls: int = 0

    @property
    def lifecycle_not_evaluated_reason(self) -> str:
        """The reason lifecycle was not evaluated, in words ("" when unknown)."""
        return _lifecycle_reason_text(self)

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
