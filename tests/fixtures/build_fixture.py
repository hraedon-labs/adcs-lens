"""Generate a synthetic AD CS export directory for tests.

Declarative Python, not hand-maintained JSON/DER blobs (the gpo-lens lesson:
hand-written fixtures are a time bomb). All identifiers are synthetic
placeholders — no work-domain CA/template/OID/SID/domain names ever (AGENTS.md
hard rule).

The export models the two-tier SMB case the charter targets: an offline root CA
plus an online issuing CA, with one ESC6-positive CA and a root CRL that is past
its nextUpdate (the catastrophic-but-invisible case).
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

# Synthetic placeholders only.
DOMAIN = "lab.example.com"
ROOT_CA = "LAB Root CA"
ISSUING_CA = "LAB Issuing CA"
LOW_PRIV_SID = "S-1-5-21-1111111111-2222222222-3333333333-513"  # "Domain Users"
HIGH_PRIV_SID = "S-1-5-21-1111111111-2222222222-3333333333-512"  # "Domain Admins"
TEMPLATE_OID = "1.3.6.1.4.1.311.21.8.1.2.3.4.100"
POLICY_OID = "1.3.6.1.4.1.311.21.8.1.2.3.4.200"


# Coverage markers the current collector writes on every object (ingest
# requires them as JSON booleans for collector >= 0.8.0).
_REQUIRED_MARKERS: dict[str, tuple[str, bool]] = {
    "templates.json": ("acl_obtained", True),
    "pki-acls.json": ("acl_obtained", True),
    "ca-config.json": ("registry_config_collected", True),
}
# Collector >= 0.9.0 exports objectGUID on every AD object; the fixture derives
# a deterministic synthetic GUID from each object's natural key, so the same
# object keeps its GUID across two builds (as in AD) whatever else changes.
# Collector >= 0.10.0 proves its reads: every declared field is written (null
# for a failed read) and enumeration markers are required.
FIXTURE_COLLECTOR_VERSION = "0.10.0-fixture"
# Registry-derived CA fields: null for a CA the collector did not run on.
_CA_REGISTRY_KEYS = (
    "edit_flags",
    "interface_flags",
    "audit_filter",
    "disabled_extensions",
    "owner_sid",
)
_GUID_KEYS: dict[str, str] = {
    "templates.json": "name",
    "pki-acls.json": "object_dn",
    "ca-config.json": "name",
    "oid-objects.json": "oid",
    "dc-config.json": "name",
    "principal-mappings.json": "dn",
}
_GUID_NS = uuid.UUID("6f9c1d3e-2b4a-4c8e-9f10-0a1b2c3d4e5f")


def fixture_guid(file_name: str, key: str) -> str:
    """The synthetic objectGUID the fixture gives the object *key* in *file_name*."""
    return uuid.uuid5(_GUID_NS, f"{file_name}:{key}").hex


def collector_defaults(file_name: str, obj: Any) -> Any:
    """Add the fields the current collector always writes, where absent.

    Mirrors collector 0.10.0: an object whose security descriptor was not
    obtained carries ``security``/``owner_sid`` null (never an empty list), and a
    CA whose registry was not collected carries null registry fields.
    """
    marker = _REQUIRED_MARKERS.get(file_name)
    guid_key = _GUID_KEYS.get(file_name)
    if isinstance(obj, list):
        for item in obj:
            if marker is not None:
                item.setdefault(*marker)
            if guid_key is not None:
                item.setdefault("object_guid", fixture_guid(file_name, str(item[guid_key])))
            if file_name == "ca-config.json":
                item.setdefault("enrollment_service", True)
                item.setdefault("dns", "")
                item.setdefault("config_string", "")
                item.setdefault("kind", "issuing")
                item.setdefault("ca_patch_state", "unknown")
                item.setdefault("owner_sid", None)
                for key in ("edit_flags", "interface_flags", "disabled_extensions"):
                    item.setdefault(key, [])
                item.setdefault("audit_filter", None)
                if item.get("registry_config_collected") is False:
                    for key in _CA_REGISTRY_KEYS:
                        item[key] = None
            if file_name in ("templates.json", "pki-acls.json"):
                item.setdefault("owner_sid", None)
                item.setdefault("security", [])
                if item.get("acl_obtained") is False:
                    item["security"] = None
                    item["owner_sid"] = None
            if file_name == "templates.json":
                item.setdefault("display_name", item.get("name", ""))
                item.setdefault("csp", "")
                item.setdefault("min_key_size", None)
                item.setdefault("schema_version", 1)
                for key in ("ekus", "name_flags", "enrollment_flags", "issuance_policy_oids"):
                    item.setdefault(key, [])
            if file_name == "oid-objects.json":
                item.setdefault("name", "")
                item.setdefault("group_link", None)
    return obj


# container -> (file name, how to count its rows). Mirrors ingest's row counts.
_ENUM_CONTAINERS: dict[str, str] = {
    "ca-config": "ca-config.json",
    "enrollment-services": "enrollment-services.json",
    "templates": "templates.json",
    "oid-objects": "oid-objects.json",
    "pki-acls": "pki-acls.json",
    "web-endpoints": "web-endpoints.json",
    "dc-config": "dc-config.json",
    "principal-mappings": "principal-mappings.json",
    "certs": "certs/index.json",
    "crls": "certs/index.json",
}


def inject_enumeration(base: Path) -> None:
    """Rewrite the manifest with completion markers matching the files on disk.

    What the current collector writes: one ``{complete: true, count: N}`` per
    container whose pass was collected, N matching the rows.
    """
    mpath = base / "collector-manifest.json"
    manifest = json.loads(mpath.read_text(encoding="utf-8-sig"))
    skipped = set(manifest.get("skipped_passes", []))
    pass_of = {
        "web-endpoints": "enrollment-endpoints",
        "dc-config": "esc10-dc-registry",
        "principal-mappings": "esc14-altsecid",
        "certs": "certs",
        "crls": "certs",
    }
    enumeration: dict[str, Any] = {}
    for container, file_name in _ENUM_CONTAINERS.items():
        if pass_of.get(container, container) in skipped:
            continue
        fpath = base / file_name
        if not fpath.is_file():
            continue
        data = json.loads(fpath.read_text(encoding="utf-8-sig"))
        if container == "enrollment-services":
            count = len(data)
        elif container in ("certs", "crls"):
            count = len(data.get(container, []))
        else:
            count = len(data)
        enumeration[container] = {"complete": True, "count": count}
    manifest["enumeration"] = enumeration
    # Preserve the collector's UTF-8 BOM so the BOM-tolerance path stays exercised.
    had_bom = mpath.read_bytes()[:3] == b"\xef\xbb\xbf"
    mpath.write_text(json.dumps(manifest, indent=2), encoding="utf-8-sig" if had_bom else "utf-8")


def _write_json(path: Path, obj: Any, *, bom: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    collector_defaults(path.name, obj)
    encoding = "utf-8-sig" if bom else "utf-8"
    path.write_text(json.dumps(obj, indent=2), encoding=encoding)


def build_export(
    out_dir: str | Path,
    *,
    with_certs: bool = False,
    now: datetime | None = None,
) -> Path:
    """Write a synthetic export into *out_dir*; return its path."""
    base = Path(out_dir)
    now = now or datetime.now(UTC)

    # collector-manifest.json — emitted with a UTF-8 BOM (PowerShell 5.1 writes
    # one) to keep the ingest BOM-tolerance honest.
    _write_json(
        base / "collector-manifest.json",
        {
            "collector_version": FIXTURE_COLLECTOR_VERSION,
            "collected_at": now.isoformat(),
            "host": "LABCA01",
            "domain": DOMAIN,
            # Mirrors the collector: the certs pass writes certs/index.json only
            # when it ran, and lists itself as skipped otherwise.
            "skipped_passes": [] if with_certs else ["certs"],
        },
        bom=True,
    )

    _write_json(
        base / "ca-config.json",
        [
            {
                "name": ROOT_CA,
                "dns": "",
                "config_string": f"OFFLINE\\{ROOT_CA}",
                "kind": "root",
                "edit_flags": [],
                "interface_flags": [],
                "audit_filter": 127,
                "disabled_extensions": [],
                # Offline root; patch state unknown is the honest default.
                "ca_patch_state": "unknown",
                # Owned by a high-priv principal (Domain Admins) so the ESC7
                # owner-based path does not fire — exercises the 0.6.0 field
                # round-trip without adding a finding.
                "owner_sid": HIGH_PRIV_SID,
            },
            {
                "name": ISSUING_CA,
                "dns": f"labca01.{DOMAIN}",
                "config_string": f"labca01.{DOMAIN}\\{ISSUING_CA}",
                "kind": "issuing",
                # ESC6 enabling flag.
                "edit_flags": ["EDITF_ATTRIBUTESUBJECTALTNAME2"],
                "interface_flags": ["IF_ENFORCEENCRYPTICERTREQUEST"],
                "audit_filter": 0,
                # ESC16 enabling config: the CA-wide DisableExtensionList contains
                # szOID_NTDS_CA_SECURITY_EXT, so every issued cert omits the SID
                # extension (the CA-level analogue of the ESC9 template flag).
                "disabled_extensions": ["1.3.6.1.4.1.311.25.2"],
                # The issuing CA is modelled as unpatched for CVE-2024-49019 so the
                # ESC15 (EKUwu) finding stays HIGH end-to-end (the common vulnerable
                # case the fixture exercises).
                "ca_patch_state": "unpatched",
                "owner_sid": HIGH_PRIV_SID,
            },
        ],
    )

    _write_json(
        base / "ca-security.json",
        {
            # The collector writes an entry for every CA (empty when it has no
            # ACEs); an absent entry is a coverage gap (CA_SECURITY_NOT_EVALUATED).
            ROOT_CA: [],
            ISSUING_CA: [
                {
                    "trustee_sid": LOW_PRIV_SID,
                    "trustee_name": "Domain Users",
                    "rights": ["ManageCertificates"],
                    "ace_type": "Allow",
                }
            ],
        },
    )

    _write_json(
        base / "templates.json",
        [
            {
                "name": "LabWebServer",
                "display_name": "Lab Web Server",
                "schema_version": 2,
                "oid": TEMPLATE_OID,
                "ekus": ["1.3.6.1.5.5.7.3.1"],  # Server Auth (not client auth -> not ESC1)
                "name_flags": ["ENROLLEE_SUPPLIES_SUBJECT"],
                # ESC9 enabling flag: issued certs omit the SID security extension.
                "enrollment_flags": ["NO_SECURITY_EXTENSION"],
                "min_key_size": 2048,
                "issuance_policy_oids": [POLICY_OID],
                # Low-priv enroll is present, but the EKU is Server Auth (not a
                # client-auth EKU), so this is *not* ESC1 — exercises the template
                # security round-trip without a false positive.
                "security": [
                    {
                        "trustee_sid": LOW_PRIV_SID,
                        "trustee_name": "Domain Users",
                        "rights": ["Enroll"],
                        "ace_type": "Allow",
                    }
                ],
            },
            {
                # ESC15 (EKUwu): a schema v1 template, low-priv enrollable, no
                # manager approval. Server-Auth EKU and no supplies-subject keep it
                # clear of ESC1/ESC2 — the EKUwu risk is the v1 schema itself.
                "name": "LegacyV1WebServer",
                "display_name": "Legacy V1 Web Server",
                "schema_version": 1,
                "oid": "1.3.6.1.4.1.311.21.8.legacyv1",
                "ekus": ["1.3.6.1.5.5.7.3.1"],  # Server Auth
                "name_flags": [],
                "enrollment_flags": [],
                "min_key_size": 2048,
                "issuance_policy_oids": [],
                "security": [
                    {
                        "trustee_sid": LOW_PRIV_SID,
                        "trustee_name": "Domain Users",
                        "rights": ["Enroll"],
                        "ace_type": "Allow",
                    }
                ],
            },
            {
                # Unreadable-DACL template: the collector ran the template-security
                # pass but this template's nTSecurityDescriptor came back empty
                # (LDAP denial), so acl_obtained is False. It is configured
                # ESC1-positive (enrollee-supplied subject + a client-auth EKU) to
                # prove the detectors SKIP it rather than falsely clear it — the
                # TEMPLATE_ACL_UNREADABLE gap detector surfaces the gap instead.
                "name": "LabKrbClientUnreadable",
                "display_name": "Lab Krb Client (unreadable)",
                "schema_version": 2,
                "oid": "1.3.6.1.4.1.311.21.8.1.2.3.4.101",
                "ekus": ["1.3.6.1.5.5.7.3.2"],  # Client Auth -> would be ESC1 if readable
                "name_flags": ["ENROLLEE_SUPPLIES_SUBJECT"],
                "enrollment_flags": [],
                "min_key_size": 2048,
                "issuance_policy_oids": [],
                "security": [],  # SD not obtained
                "acl_obtained": False,
            },
            {
                # ECDSA template (WI-025): a P-256 template whose min_key_size is
                # 256 — a curve size, not an RSA bit length. It must NOT fire
                # WEAK_TEMPLATE_KEY_SIZE (the RSA 2048-bit baseline does not apply
                # to ECDSA). Server-Auth EKU + no supplies-subject keep it clear
                # of ESC1/2/3.
                "name": "LabEcdsaClient",
                "display_name": "Lab ECDSA Client",
                "schema_version": 2,
                "oid": "1.3.6.1.4.1.311.21.8.1.2.3.4.110",
                "ekus": ["1.3.6.1.5.5.7.3.1"],  # Server Auth
                "name_flags": [],
                "enrollment_flags": [],
                "min_key_size": 256,  # P-256 curve size
                "issuance_policy_oids": [],
                "csp": "Microsoft Software Key Storage Provider (ECDSA)",
                "security": [
                    {
                        "trustee_sid": LOW_PRIV_SID,
                        "trustee_name": "Domain Users",
                        "rights": ["Enroll"],
                        "ace_type": "Allow",
                    }
                ],
            },
            {
                # Owner-based control (WI-019): a template whose security descriptor
                # OWNER is a low-priv principal, with no DACL control ACE. The
                # owner can rewrite the DACL to grant itself control -> an ESC4
                # path the DACL-only check would miss. No enroll ACE so it stays
                # clear of ESC1/2/3/15.
                "name": "LabOwnedTemplate",
                "display_name": "Lab Owned Template",
                "schema_version": 2,
                "oid": "1.3.6.1.4.1.311.21.8.1.2.3.4.120",
                "ekus": ["1.3.6.1.5.5.7.3.1"],  # Server Auth
                "name_flags": [],
                "enrollment_flags": [],
                "min_key_size": 2048,
                "issuance_policy_oids": [],
                "security": [],
                "acl_obtained": True,
                "owner_sid": LOW_PRIV_SID,
            },
            {
                # Property-scoped WriteProperty on a dangerous property (WI-019):
                # a low-priv trustee holds a scoped WriteProperty whose ObjectType
                # is the msPKI-Certificate-Name-Flag schemaIDGUID. This lets them
                # flip ENROLLEE_SUPPLIES_SUBJECT on -> an ESC4 path. The collector
                # (v0.6.2+) emits this as 'WriteProperty:<guid>'; the core matches
                # it against the dangerous-property GUID map.
                "name": "LabScopedWriteTemplate",
                "display_name": "Lab Scoped Write Template",
                "schema_version": 2,
                "oid": "1.3.6.1.4.1.311.21.8.1.2.3.4.121",
                "ekus": ["1.3.6.1.5.5.7.3.1"],  # Server Auth
                "name_flags": [],
                "enrollment_flags": [],
                "min_key_size": 2048,
                "issuance_policy_oids": [],
                "security": [
                    {
                        "trustee_sid": LOW_PRIV_SID,
                        "trustee_name": "Domain Users",
                        # msPKI-Certificate-Name-Flag schemaIDGUID (verified from
                        # MS-ADSC) — a scoped write here can enable
                        # ENROLLEE_SUPPLIES_SUBJECT -> ESC1 conversion (ESC4).
                        "rights": ["WriteProperty:ea1dddc4-60ff-416e-8cc0-17cee534bce7"],
                        "ace_type": "Allow",
                    }
                ],
                "acl_obtained": True,
            },
        ],
    )

    _write_json(base / "enrollment-services.json", {ISSUING_CA: [TEMPLATE_OID]})

    _write_json(
        base / "pki-acls.json",
        [
            {
                # Benign: a *scoped* WriteProperty is not object control, so this
                # exercises the ingest round-trip WITHOUT a false ESC5 positive.
                "object_dn": "CN=NTAuthCertificates,...,DC=lab,DC=example,DC=com",
                "kind": "ntauth",
                "security": [
                    {
                        "trustee_sid": LOW_PRIV_SID,
                        "trustee_name": "Domain Users",
                        "rights": ["WriteProperty"],
                        "ace_type": "Allow",
                    }
                ],
            },
            {
                # ESC5-positive: low-priv WriteDacl on the PKS container is
                # object control (a path to a rogue template / enrollment service).
                "object_dn": "CN=Public Key Services,...,DC=lab,DC=example,DC=com",
                "kind": "pks_container",
                "security": [
                    {
                        "trustee_sid": LOW_PRIV_SID,
                        "trustee_name": "Domain Users",
                        "rights": ["WriteDacl"],
                        "ace_type": "Allow",
                    }
                ],
            },
            {
                # Owner-based control (WI-019): the AIA container's owner is a
                # low-priv principal with no DACL control ACE. The owner can
                # rewrite the DACL to grant itself control -> an ESC5 path the
                # DACL-only check would miss.
                "object_dn": "CN=AIA,CN=Public Key Services,...,DC=lab,DC=example,DC=com",
                "kind": "aia",
                "security": [],
                "owner_sid": LOW_PRIV_SID,
            },
            {
                # Unreadable-DACL PKI object: the collector ran the pki-acls
                # pass but this object's nTSecurityDescriptor came back empty
                # (LDAP denial). It is configured ESC5-positive (low-priv
                # WriteDacl) to prove ESC5 SKIPS it rather than falsely clearing
                # it — the PKI_ACL_UNREADABLE gap detector surfaces the gap.
                "object_dn": "CN=CDP,CN=Public Key Services,...,DC=lab,DC=example,DC=com",
                "kind": "cdp",
                "security": [
                    {
                        "trustee_sid": LOW_PRIV_SID,
                        "trustee_name": "Domain Users",
                        "rights": ["WriteDacl"],
                        "ace_type": "Allow",
                    }
                ],
                "acl_obtained": False,
            },
        ],
    )

    _write_json(
        base / "oid-objects.json",
        [{"oid": POLICY_OID, "name": "Lab High Assurance", "group_link": None}],
    )

    # ESC8: Web Enrollment reachable over HTTP with NTLM and no Extended
    # Protection (the textbook relay case); a Kerberos-only CES that must NOT
    # flag (exercises the negative branch through the full pipeline).
    _write_json(
        base / "web-endpoints.json",
        [
            {
                "kind": "web_enrollment",
                "name": "/CertSrv",
                "transports": ["http", "https"],
                "ssl_required": False,
                "windows_auth": True,
                "auth_providers": ["Negotiate", "NTLM"],
                "epa": "none",
            },
            {
                "kind": "ces",
                "name": "/LAB_CES_Kerberos",
                "transports": ["https"],
                "ssl_required": True,
                "windows_auth": True,
                "auth_providers": ["Kerberos"],
                "epa": "require",
            },
        ],
    )

    # ESC10: DC registry config. The fixture models a weak configuration
    # (permissive enforcement + weak mapping methods enabled) to exercise the
    # detector. A second DC with strict enforcement exercises the negative branch.
    # LAB-DC01: ESC10 both cases — binding Disabled (case 2) + Schannel UPN bit
    # (case 1). LAB-DC02: Full enforcement, no UPN bit — the negative branch.
    _write_json(
        base / "dc-config.json",
        [
            {
                "name": "LAB-DC01",
                "strong_certificate_binding_enforcement": "disabled",
                "schannel_mapping_methods": ["upn", "s4u2self", "s4u2self_explicit"],
            },
            {
                "name": "LAB-DC02",
                "strong_certificate_binding_enforcement": "strict",
                "schannel_mapping_methods": ["s4u2self", "s4u2self_explicit"],
            },
        ],
    )

    # ESC14: a principal with a weak (reusable) issuer+subject mapping should flag
    # (LAB-DC01 is non-strict); a principal with only strong (nonreusable) forms —
    # issuer+serial and SKI — must NOT flag; a Kerberos-only principal must NOT flag.
    _write_json(
        base / "principal-mappings.json",
        [
            {
                "dn": "CN=Service Account,OU=Service Accounts,DC=lab,DC=example,DC=com",
                "mappings": [
                    "X509:<I>DC=com,DC=example,CN=LAB-CA<S>DC=com,DC=example,CN=Service Account",
                    "1.3.6.1.4.1.311.20.2.3=Service Account@lab.example.com",
                ],
            },
            {
                "dn": "CN=Strong Mapped,OU=Service Accounts,DC=lab,DC=example,DC=com",
                "mappings": [
                    "X509:<I>DC=com,DC=example,CN=LAB-CA<SR>1200000000AABBCCDD",
                    "X509:<SKI>aB1cD2eF3gH4iJ5kL6mN7oP8qR",
                ],
            },
            {
                "dn": "CN=Regular User,OU=Users,DC=lab,DC=example,DC=com",
                "mappings": [
                    "kerberos:user@LAB.EXAMPLE.COM",
                ],
            },
        ],
    )

    if with_certs:
        _write_certs(base, now=now)

    inject_enumeration(base)
    return base


# pass -> (export file, its empty value). Mirrors adcs_lens.model.PASS_FILES
# (the fixture may import only stdlib + cryptography; a test pins the two equal).
MINIMAL_PASS_FILES: dict[str, tuple[str, Any]] = {
    "ca-config": ("ca-config.json", []),
    "templates": ("templates.json", []),
    "oid-objects": ("oid-objects.json", []),
    "enrollment-services": ("enrollment-services.json", {}),
    "pki-acls": ("pki-acls.json", []),
    "ca-security": ("ca-security.json", {}),
    "enrollment-endpoints": ("web-endpoints.json", []),
    "esc10-dc-registry": ("dc-config.json", []),
    "esc14-altsecid": ("principal-mappings.json", []),
    "certs": ("certs/index.json", {"certs": [], "crls": []}),
}


def build_minimal_export(
    out_dir: str | Path,
    *,
    skipped_passes: tuple[str, ...] = ("certs",),
    collector_version: str = FIXTURE_COLLECTOR_VERSION,
) -> Path:
    """Write a structurally complete but empty export: a manifest plus an empty
    file for every pass not listed in *skipped_passes*.

    This is what the collector produces against an estate with nothing in it —
    the honest stand-in for "an empty export" now that ingest refuses a
    directory without a manifest or with a non-skipped pass's file missing.
    """
    base = Path(out_dir)
    _write_json(
        base / "collector-manifest.json",
        {
            "collector_version": collector_version,
            "collected_at": datetime.now(UTC).isoformat(),
            "host": "LABCA01",
            "domain": DOMAIN,
            "skipped_passes": list(skipped_passes),
        },
    )
    for pass_name, (file_name, empty) in MINIMAL_PASS_FILES.items():
        if pass_name not in skipped_passes:
            _write_json(base / file_name, empty)
    inject_enumeration(base)
    return base


def _write_certs(base: Path, *, now: datetime) -> None:
    """Write synthetic DER certs/CRLs and their index (needs cryptography)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.x509.oid import AuthorityInformationAccessOID, NameOID

    _DER = Encoding.DER
    certs_dir = base / "certs"
    certs_dir.mkdir(parents=True, exist_ok=True)

    def _self_signed(
        cn: str,
        not_before: datetime,
        not_after: datetime,
    ) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .sign(key, hashes.SHA256())
        )
        return cert, key

    # Root cert: healthy. Issuing cert: expiring within 30 days (should flag).
    # The issuing cert carries AIA (OCSP + CA Issuers) and CRL Distribution
    # Points extensions so the OCSP_URL_ABSENT and CDP_AIA_ABSENT checks stay
    # clean on the fixture (the issuing CA is well-configured for revocation).
    root_cert, root_key = _self_signed(
        ROOT_CA, now - timedelta(days=3650), now + timedelta(days=3650)
    )
    iss_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    iss_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, ISSUING_CA)])
    iss_cert = (
        x509.CertificateBuilder()
        .subject_name(iss_name)
        .issuer_name(root_cert.subject)
        .public_key(iss_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1700))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(
            x509.AuthorityInformationAccess(
                [
                    x509.AccessDescription(
                        AuthorityInformationAccessOID.OCSP,
                        x509.UniformResourceIdentifier(f"http://ocsp.{DOMAIN}/ocsp"),
                    ),
                    x509.AccessDescription(
                        AuthorityInformationAccessOID.CA_ISSUERS,
                        x509.UniformResourceIdentifier(f"http://aia.{DOMAIN}/{ROOT_CA}.cer"),
                    ),
                ]
            ),
            critical=False,
        )
        .add_extension(
            x509.CRLDistributionPoints(
                [
                    x509.DistributionPoint(
                        full_name=[
                            x509.UniformResourceIdentifier(f"http://crl.{DOMAIN}/{ISSUING_CA}.crl")
                        ],
                        relative_name=None,
                        reasons=None,
                        crl_issuer=None,
                    )
                ]
            ),
            critical=False,
        )
        .sign(root_key, hashes.SHA256())
    )
    (certs_dir / "root.cer").write_bytes(root_cert.public_bytes(_DER))
    (certs_dir / "issuing.cer").write_bytes(iss_cert.public_bytes(_DER))

    # Root CRL: past nextUpdate (the silent estate-wide failure). Issuing CRL: fresh.
    root_crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(root_cert.subject)
        .last_update(now - timedelta(days=400))
        .next_update(now - timedelta(days=35))  # expired
        .sign(root_key, hashes.SHA256())
    )
    iss_crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(iss_cert.subject)
        .last_update(now - timedelta(days=2))
        .next_update(now + timedelta(days=5))
        .sign(iss_key, hashes.SHA256())  # signed by the issuing CA, not the root
    )
    (certs_dir / "root.crl").write_bytes(root_crl.public_bytes(_DER))
    (certs_dir / "issuing.crl").write_bytes(iss_crl.public_bytes(_DER))

    _write_json(
        certs_dir / "index.json",
        {
            "certs": [
                {"file": "root.cer", "ca_name": ROOT_CA, "kind": "root_ca"},
                {"file": "issuing.cer", "ca_name": ISSUING_CA, "kind": "issuing_ca"},
            ],
            "crls": [
                {
                    "file": "root.crl",
                    "object_guid": fixture_guid("crl", ROOT_CA),
                    "issuer": ROOT_CA,
                    "tier": "root",
                    "source": "published: AD AIA container (root is offline)",
                },
                {
                    "file": "issuing.crl",
                    "object_guid": fixture_guid("crl", ISSUING_CA),
                    "issuer": ISSUING_CA,
                    "tier": "issuing",
                    "source": "host: LABCA01",
                },
            ],
        },
    )


if __name__ == "__main__":  # manual generation for inspection
    import sys

    out = build_export(sys.argv[1] if len(sys.argv) > 1 else "./synthetic-export", with_certs=True)
    print(f"wrote synthetic export to {out}")
