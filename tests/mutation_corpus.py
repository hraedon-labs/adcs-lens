"""The functional corpus the mutation gate (tests/test_mutation_gate.py) runs.

Every estate here is built in-process from the synthetic full export
(tests/test_diff_coverage.py ``build_full_export`` + ``enrich``) plus a
"kitchen sink" of extra objects, each placed to exercise one detector branch:
a Deny that blocks an Allow, a broad right that covers Enroll, each dangerous
property GUID, each high-privilege SID of the allowlist, each X.509 mapping
form and token precedence, each audit / key-size / expiry boundary, and so on.
Nothing here states expected findings: the gate compares a mutant's diff output
against the pristine detectors' on the same inputs, so the corpus only has to
*reach* behaviour.

Kinds of diff pairs (the older side is always evaluated by the pristine code):

* ``self:`` ``(F, F)`` — a lost, added, re-worded or relabelled finding shows up
  as resolved / indeterminate / new / changed, and the newer findings are
  compared attribute by attribute;
* ``transition:`` ``(sink, degraded sink)`` — a pass skipped, certs unparsed, a
  stale collector, no DCs: coverage-state transitions and withheld findings;
* ``fix:`` / ``delete:`` — every posture finding genuinely fixed (or its object
  deleted), so a mutant that makes a clearing verdict unusable turns "resolved"
  into "indeterminate";
* ``withheld:`` ``(sink, degrade(fixed(sink)))`` — the same fixes with one
  declared input lost (a container not proven complete, a field not obtained,
  a collector that does not prove its reads), so a mutant that trusts a verdict
  it should not turns "indeterminate" into "resolved";
* a few targeted pairs (legacy renames, mitigated / unresolved DC enforcement,
  unknown patch state, remote CAs, a single complete container).
"""

from __future__ import annotations

import shutil
import zlib
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import timedelta
from pathlib import Path
from typing import Any

from adcs_lens.ingest import ingest
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
    PkiObjectAcl,
    PrincipalMapping,
    SchannelMappingMethod,
    StrongCertBinding,
)
from tests.conftest import NOW
from tests.test_diff_coverage import build_full_export, enrich

LOW = "S-1-5-21-1111111111-2222222222-3333333333-1105"  # a named (custom) account
DU = "S-1-5-21-1111111111-2222222222-3333333333-513"  # Domain Users
DA = "S-1-5-21-1111111111-2222222222-3333333333-512"  # Domain Admins
CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
SERVER_AUTH = "1.3.6.1.5.5.7.3.1"
SMARTCARD = "1.3.6.1.4.1.311.20.2.2"
PKINIT = "1.3.6.1.5.2.3.4"
ANY_PURPOSE = "2.5.29.37.0"
AGENT = "1.3.6.1.4.1.311.20.2.1"
LINKED_POLICY = "1.3.6.1.4.1.311.21.8.7.7.7.1"
UNLINKED_POLICY = "1.3.6.1.4.1.311.21.8.7.7.7.2"
OTHER_LINKED_POLICY = "1.3.6.1.4.1.311.21.8.7.7.7.3"
# Two OID objects share this OID (one linked): the ESC13 join is ambiguous.
DUPLICATE_POLICY = "1.3.6.1.4.1.311.21.8.7.7.7.4"
# An OID object whose OID only folds to this one (surrounding spaces): ambiguous.
NEAR_POLICY = "1.3.6.1.4.1.311.21.8.7.7.7.5"
# No OID object carries this one: no link.
ABSENT_POLICY = "1.3.6.1.4.1.311.21.8.7.7.7.6"
DANGEROUS_GUIDS = (
    "ea1dddc4-60ff-416e-8cc0-17cee534bce7",
    "d15ef7d8-f226-46db-ae79-b34e560bd12c",
    "18976af6-3b9e-11d2-90cc-00c04fd91ab1",
    "38942346-cc5b-424b-a7d8-6ffd12029c5f",
    "dbd90548-aa37-4202-9966-8c537ba5ce32",
)
# Every SID of the high-privilege allowlist (normalize.py): a right granted to
# one of them is not a finding, so dropping any one from the allowlist must
# surface a new finding.
HIGH_PRIV_SIDS = (
    "S-1-5-18",
    "S-1-5-19",
    "S-1-5-20",
    "S-1-5-9",
    "S-1-5-32-544",
    "S-1-5-32-548",
    "S-1-5-32-549",
    "S-1-5-32-550",
    "S-1-5-32-551",
    *(
        f"S-1-5-21-1111111111-2222222222-3333333333-{rid}"
        for rid in ("500", "502", "512", "516", "517", "518", "519", "526", "527")
    ),
)
SUPPLY = ("ENROLLEE_SUPPLIES_SUBJECT",)

_GUIDS = [0]


def _guid() -> str:
    _GUIDS[0] += 1
    return f"{_GUIDS[0]:032x}"


def _stable(text: str) -> int:
    return zlib.crc32(text.encode("utf-8"))


def ace(sid: str, *rights: str, deny: bool = False, name: str = "") -> AceEntry:
    return AceEntry(
        trustee_sid=sid,
        trustee_name=name,
        rights=rights,
        ace_type=AceType.DENY if deny else AceType.ALLOW,
    )


def tmpl(name: str, **kw: Any) -> CertTemplate:
    base: dict[str, Any] = {
        "name": name,
        "display_name": name,
        "schema_version": 2,
        "oid": f"1.3.6.1.4.1.311.21.8.9.{_stable(name)}",
        "ekus": (CLIENT_AUTH,),
        "name_flags": frozenset(),
        "enrollment_flags": frozenset(),
        "min_key_size": 2048,
        "issuance_policy_oids": (),
        "security": (),
        "published_by": ("LAB Issuing CA",),
        "owner_sid": DA,
        "object_guid": _guid(),
    }
    base.update(kw)
    for key in ("name_flags", "enrollment_flags"):
        base[key] = frozenset(base[key])
    return CertTemplate(**base)


def ca(name: str, **kw: Any) -> CertAuthority:
    base: dict[str, Any] = {
        "name": name,
        "dns": f"{name.lower().replace(' ', '')}.lab.example.com",
        "config_string": f"host\\{name}",
        "kind": CaKind.ISSUING,
        "edit_flags": frozenset(),
        "interface_flags": frozenset({"IF_ENFORCEENCRYPTICERTREQUEST"}),
        "audit_filter": 127,
        "security": (),
        "certs": (),
        "disabled_extensions": frozenset(),
        "ca_patch_state": CaPatchState.PATCHED,
        "owner_sid": DA,
        "object_guid": _guid(),
    }
    base.update(kw)
    for key in ("edit_flags", "interface_flags", "disabled_extensions"):
        base[key] = frozenset(base[key])
    return CertAuthority(**base)


def cert(subject: str, **kw: Any) -> CertLifecycle:
    base: dict[str, Any] = {
        "subject": subject,
        "kind": CertKind.ISSUING_CA,
        "not_before": NOW - timedelta(days=100),
        "not_after": NOW + timedelta(days=2000),
        "sig_alg": "sha256WithRSAEncryption",
        "key_bits": 4096,
        "key_alg": "rsa",
        "ocsp_urls": ("http://ocsp/o",),
        "cdp_urls": ("http://crl/c.crl",),
        "aia_urls": ("http://aia/a.cer",),
        "fingerprint": f"{_stable(subject):064x}",
    }
    base.update(kw)
    return CertLifecycle(**base)


def _enroll_template(name: str, **kw: Any) -> CertTemplate:
    return tmpl(name, security=(ace(LOW, "Enroll"),), **kw)


def _templates() -> list[CertTemplate]:
    e1 = SUPPLY
    out = [
        # --- ESC1 gates ---------------------------------------------------------
        tmpl("KsEsc1Plain", name_flags=e1, security=(ace(LOW, "Enroll", name="u1"),)),
        _enroll_template("KsEsc1San", name_flags=("ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME",)),
        _enroll_template("KsEsc1Smartcard", name_flags=e1, ekus=(SMARTCARD,)),
        _enroll_template("KsEsc1Pkinit", name_flags=e1, ekus=(PKINIT,)),
        _enroll_template("KsEsc1AnyPurpose", name_flags=e1, ekus=(ANY_PURPOSE,)),
        _enroll_template("KsEsc1NoEku", name_flags=e1, ekus=()),
        _enroll_template("KsEsc1ServerOnly", name_flags=e1, ekus=(SERVER_AUTH,)),
        _enroll_template("KsEsc1Approval", name_flags=e1, enrollment_flags=("PEND_ALL_REQUESTS",)),
        _enroll_template("KsEsc1NoDisplay", name_flags=e1, display_name=""),
        # A publication reference matched two templates: published_by unknown.
        _enroll_template(
            "KsEsc1AmbiguousPublication", name_flags=e1, unobtained=frozenset({"published_by"})
        ),
        tmpl(
            "KsEsc1Deny",
            name_flags=e1,
            security=(ace(LOW, "Enroll"), ace(LOW, "Enroll", deny=True)),
        ),
        tmpl(
            "KsEsc1DenyOther",
            name_flags=e1,
            security=(ace(LOW, "Enroll"), ace(DU, "Enroll", deny=True)),
        ),
        tmpl(
            "KsEsc1DenyGenericAll",
            name_flags=e1,
            security=(ace(LOW, "Enroll"), ace(LOW, "GenericAll", deny=True)),
        ),
        tmpl(
            "KsEsc1DenyAllExt",
            name_flags=e1,
            security=(ace(LOW, "Enroll"), ace(LOW, "AllExtendedRights", deny=True)),
        ),
        tmpl(
            "KsEsc1DenyAutoEnroll",
            name_flags=e1,
            security=(ace(LOW, "Enroll"), ace(LOW, "AutoEnroll", deny=True)),
        ),
        tmpl("KsEsc1GenericAll", name_flags=e1, security=(ace(LOW, "GenericAll"),)),
        tmpl("KsEsc1FullControl", name_flags=e1, security=(ace(LOW, "FullControl"),)),
        tmpl("KsEsc1AllExt", name_flags=e1, security=(ace(LOW, "AllExtendedRights"),)),
        tmpl("KsEsc1AutoOnly", name_flags=e1, security=(ace(LOW, "AutoEnroll"),)),
        tmpl("KsEsc1Spaced", name_flags=e1, security=(ace(LOW, " ENROLL "),)),
        tmpl(
            "KsEsc1HighPriv",
            name_flags=e1,
            security=tuple(ace(s, "Enroll") for s in HIGH_PRIV_SIDS),
        ),
        tmpl(
            "KsEsc1LowerSid",
            name_flags=e1,
            security=(ace("s-1-5-21-1111111111-2222222222-3333333333-512", "Enroll"),),
        ),
        tmpl("KsEsc1NotDomainRid", name_flags=e1, security=(ace("S-1-5-32-512", "Enroll"),)),
        tmpl(
            "KsEsc1TwoTrustees",
            name_flags=e1,
            security=(ace(LOW, "Enroll", name="bob"), ace(DU, "Enroll")),
        ),
        # --- ESC2 / ESC3 / ESC9 -----------------------------------------------------
        _enroll_template(
            "KsEsc2Approval", ekus=(ANY_PURPOSE,), enrollment_flags=("PEND_ALL_REQUESTS",)
        ),
        tmpl("KsEsc2NoEnroll", ekus=(), security=(ace(DA, "Enroll"),)),
        _enroll_template("KsEsc3", ekus=(AGENT,)),
        _enroll_template("KsEsc3Approval", ekus=(AGENT,), enrollment_flags=("PEND_ALL_REQUESTS",)),
        _enroll_template(
            "KsEsc9", ekus=(SERVER_AUTH,), enrollment_flags=("NO_SECURITY_EXTENSION",)
        ),
        _enroll_template(
            "KsEsc9Approval",
            ekus=(SERVER_AUTH,),
            enrollment_flags=("NO_SECURITY_EXTENSION", "PEND_ALL_REQUESTS"),
        ),
        tmpl("KsEsc9NoEnroll", ekus=(SERVER_AUTH,), enrollment_flags=("NO_SECURITY_EXTENSION",)),
        _enroll_template(
            "KsNoOid", oid="", ekus=(SERVER_AUTH,), enrollment_flags=("NO_SECURITY_EXTENSION",)
        ),
        # --- ESC13 ------------------------------------------------------------------
        _enroll_template("KsEsc13", issuance_policy_oids=(LINKED_POLICY,)),
        _enroll_template(
            "KsEsc13Two",
            issuance_policy_oids=(LINKED_POLICY, UNLINKED_POLICY, OTHER_LINKED_POLICY),
        ),
        _enroll_template("KsEsc13Unlinked", issuance_policy_oids=(UNLINKED_POLICY,)),
        _enroll_template("KsEsc13Duplicate", issuance_policy_oids=(DUPLICATE_POLICY,)),
        _enroll_template("KsEsc13Near", issuance_policy_oids=(NEAR_POLICY,)),
        _enroll_template("KsEsc13Absent", issuance_policy_oids=(ABSENT_POLICY,)),
        _enroll_template(
            "KsEsc13Server", ekus=(SERVER_AUTH,), issuance_policy_oids=(LINKED_POLICY,)
        ),
        _enroll_template(
            "KsEsc13Approval",
            issuance_policy_oids=(LINKED_POLICY,),
            enrollment_flags=("PEND_ALL_REQUESTS",),
        ),
        # --- ESC15 ------------------------------------------------------------------
        _enroll_template("KsEsc15", schema_version=1, ekus=(SERVER_AUTH,)),
        _enroll_template(
            "KsEsc15Approval",
            schema_version=1,
            ekus=(SERVER_AUTH,),
            enrollment_flags=("PEND_ALL_REQUESTS",),
        ),
        tmpl("KsEsc15NoEnroll", schema_version=1, ekus=(SERVER_AUTH,)),
        _enroll_template("KsEsc15V3", schema_version=3, ekus=(SERVER_AUTH,)),
        # --- template key size --------------------------------------------------------
        *(
            tmpl(f"KsKey{bits}", ekus=(SERVER_AUTH,), min_key_size=bits)
            for bits in (255, 384, 512, 521, 1023, 1024, 1025, 2047, 2048)
        ),
        tmpl(
            "KsKeyEcdsaCsp",
            ekus=(SERVER_AUTH,),
            min_key_size=1024,
            csp="microsoft software key storage provider (ecdsa)",
        ),
        tmpl("KsKeyEcdhCsp", ekus=(SERVER_AUTH,), min_key_size=1024, csp="ecdh_p256"),
        tmpl("KsKeyNone", ekus=(SERVER_AUTH,), min_key_size=None),
        # --- orphaned / owners / unreadable -------------------------------------------
        tmpl("KsOrphan", ekus=(SERVER_AUTH,), published_by=()),
        tmpl("KsOrphanBlank", ekus=(SERVER_AUTH,), published_by=("  ",)),
        tmpl("KsOwnedLow", ekus=(SERVER_AUTH,), owner_sid=LOW),
        tmpl("KsOwnedSystem", ekus=(SERVER_AUTH,), owner_sid="S-1-5-18"),
        tmpl("KsOwnerLost", ekus=(SERVER_AUTH,), owner_sid=""),
        tmpl(
            "KsAclLost",
            ekus=(SERVER_AUTH,),
            name_flags=e1,
            acl_obtained=False,
            security=(ace(LOW, "Enroll"),),
        ),
    ]
    # --- ESC4: each control right, Deny precedence, scoped writes ---------------------
    for right in (
        "GenericAll",
        "GenericWrite",
        "WriteDacl",
        "WriteOwner",
        "FullControl",
        "WritePropertyAll",
    ):
        out.append(tmpl(f"KsEsc4{right}", ekus=(SERVER_AUTH,), security=(ace(LOW, right),)))
    g = DANGEROUS_GUIDS
    out += [
        tmpl(
            "KsEsc4Two",
            ekus=(SERVER_AUTH,),
            security=(ace(LOW, "WriteDacl", "WriteOwner"), ace(DU, "GenericWrite")),
        ),
        tmpl(
            "KsEsc4DenyBroad",
            ekus=(SERVER_AUTH,),
            security=(ace(LOW, "WriteDacl"), ace(LOW, "GenericAll", deny=True)),
        ),
        tmpl(
            "KsEsc4DenyPartial",
            ekus=(SERVER_AUTH,),
            security=(ace(LOW, "WriteDacl", "WriteOwner"), ace(LOW, "WriteDacl", deny=True)),
        ),
        tmpl(
            "KsEsc4GwDeny",
            ekus=(SERVER_AUTH,),
            security=(ace(LOW, "GenericWrite", "WriteDacl"), ace(LOW, "GenericWrite", deny=True)),
        ),
        tmpl(
            "KsEsc4OwnerDeny",
            ekus=(SERVER_AUTH,),
            security=(ace(LOW, "WriteOwner"), ace(LOW, "WriteOwner", deny=True)),
        ),
        tmpl(
            "KsEsc4OwnerUnderBroadDeny",
            ekus=(SERVER_AUTH,),
            security=(ace(LOW, "GenericAll", "WriteOwner"), ace(LOW, "GenericAll", deny=True)),
        ),
        tmpl(
            "KsEsc4WpaDeny",
            ekus=(SERVER_AUTH,),
            security=(ace(LOW, "WritePropertyAll"), ace(LOW, "WritePropertyAll", deny=True)),
        ),
        tmpl("KsEsc4ScopedBare", ekus=(SERVER_AUTH,), security=(ace(LOW, "WriteProperty"),)),
        tmpl(
            "KsEsc4ScopedBenign",
            ekus=(SERVER_AUTH,),
            security=(ace(LOW, "WriteProperty:00000000-1111-2222-3333-444444444444"),),
        ),
        tmpl(
            "KsEsc4ScopedDenyAll",
            ekus=(SERVER_AUTH,),
            security=(
                ace(LOW, f"WriteProperty:{g[0]}"),
                ace(LOW, "WritePropertyAll", deny=True),
            ),
        ),
        tmpl(
            "KsEsc4ScopedDenyGeneric",
            ekus=(SERVER_AUTH,),
            security=(ace(LOW, f"WriteProperty:{g[1]}"), ace(LOW, "GenericWrite", deny=True)),
        ),
        tmpl(
            "KsEsc4ScopedDenyOne",
            ekus=(SERVER_AUTH,),
            security=(
                ace(LOW, f"WriteProperty:{g[2]}", f"WriteProperty:{g[3]}"),
                ace(LOW, f"WriteProperty:{g[2]}", deny=True),
            ),
        ),
        tmpl(
            "KsEsc4ScopedDenyBoth",
            ekus=(SERVER_AUTH,),
            security=(
                ace(LOW, f"WriteProperty:{g[4]}"),
                ace(LOW, f"WriteProperty:{g[4].upper()}", deny=True),
            ),
        ),
        tmpl(
            "KsEsc4ScopedDenyOther",
            ekus=(SERVER_AUTH,),
            security=(
                ace(LOW, f"WriteProperty:{g[0]}"),
                ace(DU, f"WriteProperty:{g[0]}", deny=True),
            ),
        ),
        tmpl(
            "KsEsc4ScopedHighPriv",
            ekus=(SERVER_AUTH,),
            security=(ace(DA, f"WriteProperty:{g[0]}"),),
        ),
    ]
    for i, guid in enumerate(g):
        out.append(
            tmpl(
                f"KsEsc4Scoped{i}",
                ekus=(SERVER_AUTH,),
                security=(ace(LOW, f"WriteProperty:{guid.upper()}"),),
            )
        )
    return out


def _lifecycle_certs() -> tuple[CertLifecycle, ...]:
    return (
        cert("CN=KS expired", not_after=NOW - timedelta(days=1)),
        cert("CN=KS expires now", not_after=NOW),
        cert("CN=KS soon", not_after=NOW + timedelta(days=30)),
        cert("CN=KS 90", not_after=NOW + timedelta(days=90, hours=1)),
        cert("CN=KS 91", not_after=NOW + timedelta(days=91, hours=1)),
        cert("CN=KS root soon", kind=CertKind.ROOT_CA, not_after=NOW + timedelta(days=10)),
        cert("CN=KS md5", sig_alg="md5WithRSAEncryption"),
        cert("CN=KS sha1", sig_alg="ecdsa-with-SHA1"),
        cert("CN=KS SHA1 upper", sig_alg="SHA1RSA"),
        cert("CN=KS unknown alg", sig_alg="unknown"),
        *(cert(f"CN=KS {bits}", key_bits=bits) for bits in (512, 1023, 1024, 1025, 2047, 2048)),
        cert("CN=KS ec", key_bits=256, key_alg="ec"),
        cert("CN=KS no ocsp", ocsp_urls=()),
        cert("CN=KS no cdp", cdp_urls=()),
        cert("CN=KS no aia", aia_urls=()),
        cert("CN=KS none", cdp_urls=(), aia_urls=(), ocsp_urls=()),
    )


def _cas() -> list[CertAuthority]:
    return [
        ca(
            "KS Root ESC6",
            kind=CaKind.ROOT,
            dns="",
            edit_flags={"EDITF_ATTRIBUTESUBJECTALTNAME2"},
            interface_flags=(),
            disabled_extensions={"1.3.6.1.4.1.311.25.2"},
            ca_patch_state=CaPatchState.UNPATCHED,
            certs=(
                cert(
                    "CN=KS Root ESC6",
                    kind=CertKind.ROOT_CA,
                    ocsp_urls=(),
                    cdp_urls=(),
                    aia_urls=(),
                ),
            ),
        ),
        # A loaded certificate whose signature hash and extensions the library
        # could not derive: the placeholders must not decide anything.
        ca(
            "KS Odd Cert",
            certs=(
                cert(
                    "CN=KS Odd Cert",
                    sig_alg="sha1WithRSAEncryption",
                    ocsp_urls=(),
                    cdp_urls=(),
                    aia_urls=(),
                    unobtained=frozenset({"sig_alg", "ocsp_urls", "cdp_urls", "aia_urls"}),
                ),
            ),
        ),
        ca(
            "KS Standalone",
            kind=CaKind.STANDALONE,
            interface_flags=(),
            disabled_extensions={"1.3.6.1.4.1.311.25.2", "1.2.3"},
        ),
        ca("KS Esc7 GenericAll", security=(ace(LOW, "GenericAll"),)),
        ca(
            "KS Esc7 Officer",
            security=(ace(LOW, "ManageCertificates", name="officer"), ace(DA, "ManageCA")),
        ),
        ca(
            "KS Esc7 Deny",
            security=(ace(LOW, "ManageCA", "ManageCertificates"), ace(LOW, "ManageCA", deny=True)),
        ),
        ca(
            "KS Esc7 DenyAll",
            security=(ace(LOW, "ManageCA"), ace(LOW, "FullControl", deny=True)),
        ),
        ca(
            "KS Esc7 FullMinusCA",
            security=(ace(LOW, "FullControl"), ace(LOW, "ManageCA", deny=True)),
        ),
        ca(
            "KS Esc7 OfficerDeny",
            security=(ace(LOW, "ManageCertificates"), ace(LOW, "ManageCertificates", deny=True)),
        ),
        ca(
            "KS Esc7 Two",
            security=(ace(LOW, "ManageCA"), ace(DU, "ManageCertificates"), ace(DU, "Read")),
        ),
        ca("KS Esc7 OwnerLow", owner_sid=LOW),
        ca("KS Esc7 OwnerLost", owner_sid=""),
        ca("KS Esc7 SecurityLost", security_collected=False),
        ca(
            "KS Remote",
            registry_config_collected=False,
            edit_flags={"EDITF_ATTRIBUTESUBJECTALTNAME2"},
            interface_flags=(),
            audit_filter=None,
        ),
        ca("KS Audit Zero", audit_filter=0),
        ca("KS Audit 3F", audit_filter=0x3F),
        ca("KS Audit 40", audit_filter=0x40),
        ca("KS Audit 7E", audit_filter=0x7E),
        ca("KS Audit FF", audit_filter=0xFF),
        ca("KS Audit None", audit_filter=None),
        ca("KS Unknown Patch", ca_patch_state=CaPatchState.UNKNOWN, certs=_lifecycle_certs()),
    ]


def _pkis() -> list[PkiObjectAcl]:
    def pki(dn: str, kind: AclKind, *aces: AceEntry, owner: str = DA) -> PkiObjectAcl:
        return PkiObjectAcl(
            object_dn=dn, kind=kind, security=aces, owner_sid=owner, object_guid=_guid()
        )

    out = []
    for kind in AclKind:
        out.append(pki(f"CN=KS {kind.value}", kind, ace(LOW, "WriteOwner")))
        out.append(pki(f"CN=KS owned {kind.value}", kind, owner=DU))
    out += [
        pki("", AclKind.AIA, ace(LOW, "GenericAll")),
        # Same alias as the DN-less AIA object above: only the GUID tells them apart.
        pki("", AclKind.AIA, ace(DU, "WriteDacl")),
        pki(
            "CN=KS deny",
            AclKind.NTAUTH,
            ace(LOW, "GenericWrite"),
            ace(LOW, "FullControl", deny=True),
        ),
        pki("CN=KS scoped", AclKind.NTAUTH, ace(LOW, f"WriteProperty:{DANGEROUS_GUIDS[0]}")),
        pki(
            "CN=KS highpriv",
            AclKind.CA_OBJECT,
            ace("S-1-5-32-544", "GenericAll"),
            owner="S-1-5-18",
        ),
        pki("CN=KS owner lost", AclKind.CDP, owner=""),
        pki("CN=KS mixed", AclKind.CDP, ace(LOW, "WriteDacl", "ReadProperty")),
        pki(
            "CN=KS gwdeny",
            AclKind.PKS_CONTAINER,
            ace(LOW, "GenericWrite", "WriteDacl"),
            ace(LOW, "GenericWrite", deny=True),
        ),
    ]
    return out


def _endpoints() -> list[EnrollmentEndpoint]:
    def ep(name: str, **kw: Any) -> EnrollmentEndpoint:
        base: dict[str, Any] = {
            "kind": EndpointKind.WEB_ENROLLMENT,
            "name": name,
            "transports": frozenset({"https"}),
            "ssl_required": True,
            "windows_auth": True,
            "auth_providers": frozenset({"negotiate"}),
            "epa": EpaPolicy.REQUIRE,
        }
        base.update(kw)
        return EnrollmentEndpoint(**base)

    http = frozenset({"http", "https"})
    return [
        ep("/ks-negotiate-none", epa=EpaPolicy.NONE),
        ep("/ks-negotiate-allow", epa=EpaPolicy.ALLOW),
        ep("/ks-negotiate-unknown", epa=EpaPolicy.UNKNOWN),
        ep("/ks-ntlm-https", auth_providers=frozenset({"ntlm"}), epa=EpaPolicy.ALLOW),
        ep("/ks-http-require", transports=http, ssl_required=False),
        ep("/ks-http-sslreq", transports=http, ssl_required=True, epa=EpaPolicy.NONE),
        ep("/ks-require", auth_providers=frozenset({"ntlm", "negotiate"})),
        ep(
            "/ks-kerberos",
            auth_providers=frozenset({"kerberos"}),
            epa=EpaPolicy.NONE,
            transports=frozenset({"http"}),
            ssl_required=False,
        ),
        ep("/ks-noauth", windows_auth=False, epa=EpaPolicy.NONE),
        ep("/ks_CES_Kerberos", kind=EndpointKind.CES, epa=EpaPolicy.NONE),
        ep(
            "/ks-mscep",
            kind=EndpointKind.NDES,
            epa=EpaPolicy.NONE,
            transports=frozenset({"http"}),
            ssl_required=False,
            auth_providers=frozenset({"ntlm"}),
        ),
        ep("", kind=EndpointKind.CES, epa=EpaPolicy.NONE),
    ]


def _dcs() -> list[DcConfiguration]:
    def dc(
        name: str, binding: StrongCertBinding, *methods: SchannelMappingMethod, **kw: Any
    ) -> DcConfiguration:
        return DcConfiguration(
            name=name,
            strong_certificate_binding_enforcement=binding,
            schannel_mapping_methods=frozenset(methods),
            object_guid=_guid(),
            **kw,
        )

    up = SchannelMappingMethod.UPN
    s4u = SchannelMappingMethod.S4U2SELF
    return [
        dc("KS-DC-DIS", StrongCertBinding.DISABLED),
        dc("KS-DC-PERM", StrongCertBinding.PERMISSIVE, s4u),
        dc("KS-DC-PERM-UPN", StrongCertBinding.PERMISSIVE, up),
        dc("KS-DC-STRICT-UPN", StrongCertBinding.STRICT, up),
        dc("KS-DC-STRICT", StrongCertBinding.STRICT, s4u),
        dc("KS-DC-UNK", StrongCertBinding.UNKNOWN, s4u),
        dc("KS-DC-UNK-UPN", StrongCertBinding.UNKNOWN, up),
        dc(
            "KS-DC-LOST",
            StrongCertBinding.UNKNOWN,
            unobtained=frozenset({"strong_certificate_binding_enforcement"}),
        ),
        dc(
            "KS-DC-SCH-LOST",
            StrongCertBinding.DISABLED,
            unobtained=frozenset({"schannel_mapping_methods"}),
        ),
    ]


def _principals() -> list[PrincipalMapping]:
    forms = {
        "subject": "X509:<S>CN=victim",
        "issuer-subject": "X509:<I>CN=CA<S>CN=victim",
        "rfc822": "X509:<RFC822>victim@lab.example.com",
        "pn": "X509:<PN>victim@lab.example.com",
        "issuer-serial": "X509:<I>CN=CA<SR>0102",
        "ski": "X509:<SKI>abcdef",
        "sha1": "X509:<SHA1-PUKEY>abcdef",
        "issuer-only": "X509:<I>CN=CA",
        "kerberos": "Kerberos:victim@LAB",
        "lower": "x509:<s>cn=victim",
        "spaced": "  X509:<S>CN=victim  ",
        # Precedence: a strong token wins over a weak one in the same value, and
        # a non-X.509 value is never classified by its tokens.
        "serial-wins": "X509:<I>CN=CA<SR>01<S>CN=victim",
        "ski-wins": "X509:<SKI>ab<S>CN=victim",
        "sha1-wins": "X509:<SHA1-PUKEY>ab<S>CN=victim",
        "rfc822-before-pn": "X509:<RFC822>a@b<PN>a@b",
        "kerberos-token": "Kerberos:<S>CN=victim",
    }
    out = [
        PrincipalMapping(dn=f"CN=KS {k},DC=lab", mappings=(v,), object_guid=_guid())
        for k, v in forms.items()
    ]
    for count in (3, 4, 5):
        out.append(
            PrincipalMapping(
                dn=f"CN=KS weak x{count},DC=lab",
                mappings=tuple(f"X509:<S>CN=v{count}-{i}" for i in range(count)),
                object_guid=_guid(),
            )
        )
    return out


def _crls() -> list[Crl]:
    def crl(
        issuer: str,
        this: timedelta | None,
        nxt: timedelta | None,
        tier: CrlTier | None = CrlTier.ISSUING,
    ) -> Crl:
        return Crl(
            issuer=issuer,
            this_update=None if this is None else NOW + this,
            next_update=None if nxt is None else NOW + nxt,
            tier=tier,
            source=f"ks:{issuer}",
            object_guid=_guid(),
        )

    d, h, s = timedelta(days=1), timedelta(hours=1), timedelta(seconds=1)
    return [
        crl("CN=KS expired root", -10 * d, -1 * d, CrlTier.ROOT),
        crl("CN=KS expired", -10 * d, -1 * h),
        crl("CN=KS window", -6 * d, 1 * d),
        crl("CN=KS window root", -6 * d, 1 * d, CrlTier.ROOT),
        # The tier was not derived (the AIA source was incomplete): usable never.
        crl("CN=KS window unknown tier", -6 * d, 1 * d, None),
        crl("CN=KS expired unknown tier", -10 * d, -1 * d, None),
        crl("CN=KS edge", -3 * d, 1 * d),
        crl("CN=KS fresh", -1 * d, 7 * d),
        crl("CN=KS short", -18 * h, 6 * h),
        crl("CN=KS short fresh", -1 * h, 23 * h),
        crl("CN=KS hours", -40 * d, 5 * h),
        crl("CN=KS backwards", 2 * d, 1 * d),
        crl("CN=KS no this", None, 1 * h),
        crl("CN=KS no next", -1 * d, None),
        crl("CN=KS next now", -1 * d, timedelta(0)),
        crl("CN=KS tiny", -0.9 * s, 0.1 * s),
        crl("CN=KS zero validity", 1 * h, 1 * h),
        crl("CN=KS zero now", timedelta(0), timedelta(0)),
    ]


def kitchen_sink(base: Estate) -> Estate:
    """*base* plus every branch-exercising object above."""
    oids = (
        *base.oids,
        IssuanceOid(
            oid=LINKED_POLICY,
            name="KS Linked",
            group_link="CN=KS Admins,DC=lab",
            object_guid=_guid(),
        ),
        IssuanceOid(oid=UNLINKED_POLICY, name="KS Unlinked", group_link=None, object_guid=_guid()),
        IssuanceOid(
            oid=OTHER_LINKED_POLICY, name="", group_link="CN=KS Ops,DC=lab", object_guid=_guid()
        ),
        IssuanceOid(
            oid=DUPLICATE_POLICY,
            name="KS Dup A",
            group_link="CN=KS Dup,DC=lab",
            object_guid=_guid(),
        ),
        IssuanceOid(oid=DUPLICATE_POLICY, name="KS Dup B", group_link=None, object_guid=_guid()),
        IssuanceOid(
            oid=f" {NEAR_POLICY} ",
            name="KS Near",
            group_link="CN=KS Near,DC=lab",
            object_guid=_guid(),
        ),
    )
    offline_root = cert(
        "CN=KS Offline Root",
        kind=CertKind.ROOT_CA,
        not_after=NOW + timedelta(days=5),
        ocsp_urls=(),
        cdp_urls=(),
        aia_urls=(),
    )
    return replace(
        base,
        templates=(*base.templates, *_templates()),
        cas=(*base.cas, *_cas()),
        acls=(*base.acls, *_pkis()),
        endpoints=(*base.endpoints, *_endpoints()),
        dcs=(*base.dcs, *_dcs()),
        principal_mappings=(*base.principal_mappings, *_principals()),
        crls=(*base.crls, *_crls()),
        oids=oids,
        unattached_certs=(
            *base.unattached_certs,
            ("KS Offline Root", offline_root),
            (
                "KS Odd Root",
                cert(
                    "CN=KS Odd Root",
                    kind=CertKind.ROOT_CA,
                    sig_alg="md5WithRSAEncryption",
                    unobtained=frozenset({"sig_alg"}),
                ),
            ),
        ),
    )


# --- fixes and degradations -------------------------------------------------------------


def _fix_cert(c: CertLifecycle) -> CertLifecycle:
    fixed_cert = replace(
        c,
        sig_alg="sha256WithRSAEncryption",
        key_bits=4096,
        key_alg="rsa",
        ocsp_urls=("http://o",),
        cdp_urls=("http://c",),
        aia_urls=("http://a",),
        not_after=(c.not_after or NOW) + timedelta(days=4000),
    )
    # A cert without a fingerprint is identified by its expiry: keep it.
    return fixed_cert if c.fingerprint else replace(fixed_cert, not_after=c.not_after)


def fixed(e: Estate) -> Estate:
    """Every posture finding genuinely fixed, every object kept (same identity)."""
    binding = "strong_certificate_binding_enforcement"
    return replace(
        e,
        templates=tuple(
            replace(
                t,
                security=tuple(a for a in t.security if a.ace_type is AceType.DENY),
                owner_sid=DA if t.owner_sid else "",
                min_key_size=4096 if t.min_key_size is not None else None,
                published_by=("LAB Issuing CA",),
                enrollment_flags=frozenset(
                    f for f in t.enrollment_flags if f != "NO_SECURITY_EXTENSION"
                ),
            )
            for t in e.templates
        ),
        cas=tuple(
            replace(
                c,
                edit_flags=frozenset(),
                interface_flags=frozenset({"IF_ENFORCEENCRYPTICERTREQUEST"}),
                disabled_extensions=frozenset(),
                audit_filter=127 if c.audit_filter is not None else None,
                security=(),
                owner_sid=DA if c.owner_sid else "",
                ca_patch_state=CaPatchState.PATCHED,
                certs=tuple(_fix_cert(x) for x in c.certs),
            )
            for c in e.cas
        ),
        unattached_certs=tuple((n, _fix_cert(c)) for n, c in e.unattached_certs),
        acls=tuple(replace(a, security=(), owner_sid=DA if a.owner_sid else "") for a in e.acls),
        endpoints=tuple(
            replace(p, transports=frozenset({"https"}), ssl_required=True, epa=EpaPolicy.REQUIRE)
            for p in e.endpoints
        ),
        dcs=tuple(
            replace(
                d,
                strong_certificate_binding_enforcement=StrongCertBinding.STRICT
                if binding not in d.unobtained
                else d.strong_certificate_binding_enforcement,
                schannel_mapping_methods=frozenset({SchannelMappingMethod.S4U2SELF}),
            )
            for d in e.dcs
        ),
        principal_mappings=tuple(
            replace(p, mappings=("X509:<I>CN=CA<SR>01",)) for p in e.principal_mappings
        ),
        crls=tuple(
            replace(
                c,
                next_update=None if c.next_update is None else NOW + timedelta(days=30),
                this_update=None if c.this_update is None else NOW - timedelta(days=1),
            )
            for c in e.crls
        ),
    )


def _lose(o: Any, field: str) -> Any:
    return replace(o, unobtained=o.unobtained | {field})


def _unobtain(e: Estate, object_type: str, field: str) -> Estate:
    """*field* not obtained on every object of *object_type*."""
    if object_type == "template":
        return replace(e, templates=tuple(_lose(t, field) for t in e.templates))
    if object_type == "ca":
        return replace(e, cas=tuple(_lose(c, field) for c in e.cas))
    if object_type == "pki":
        return replace(e, acls=tuple(_lose(a, field) for a in e.acls))
    if object_type == "dc":
        return replace(e, dcs=tuple(_lose(d, field) for d in e.dcs))
    if object_type == "endpoint":
        return replace(e, endpoints=tuple(_lose(p, field) for p in e.endpoints))
    if object_type == "crl":
        if field not in ("next_update", "this_update"):
            return e  # the tier comes from the index itself: always obtained
        return replace(e, crls=tuple(replace(c, **{field: None}) for c in e.crls))
    if object_type == "cert":
        if field == "ca_kind":
            return replace(e, cas=tuple(_lose(c, "kind") for c in e.cas))
        value: Any = "unknown" if field in ("sig_alg", "key_alg") else None
        if field not in ("not_after", "key_bits", "sig_alg", "key_alg"):
            return e  # always obtained (parsed from the DER itself)
        return replace(
            e,
            cas=tuple(
                replace(c, certs=tuple(replace(x, **{field: value}) for x in c.certs))
                for c in e.cas
            ),
            unattached_certs=tuple(
                (n, replace(x, **{field: value})) for n, x in e.unattached_certs
            ),
        )
    return e  # principal mappings and OID fields are always obtained


@dataclass(frozen=True)
class Pair:
    name: str
    old: Estate
    new: Estate


def _degradations() -> dict[str, Callable[[Estate], Estate]]:
    from adcs_lens.detection import CHECKS

    out: dict[str, Callable[[Estate], Estate]] = {}
    containers = sorted({c for d in CHECKS.values() for c in d.containers})
    for container in containers:

        def incomplete(e: Estate, c: str = container) -> Estate:
            return replace(
                e,
                manifest=replace(
                    e.manifest, enumeration_complete=e.manifest.enumeration_complete - {c}
                ),
            )

        out[f"incomplete:{container}"] = incomplete
    fields = sorted(
        {(d.subject, f) for d in CHECKS.values() for f in d.fields}
        | {(t, f) for d in CHECKS.values() for t, fs in d.deps.items() for f in fs}
    )
    for object_type, field in fields:

        def unobtained(e: Estate, t: str = object_type, f: str = field) -> Estate:
            return _unobtain(e, t, f)

        out[f"unobtained:{object_type}.{field}"] = unobtained
    out["reads-not-proven"] = lambda e: replace(
        e, manifest=replace(e.manifest, collector_version="0.9.0")
    )
    return out


def _strip_guids(e: Estate) -> Estate:
    def strip(objs: tuple[Any, ...]) -> tuple[Any, ...]:
        return tuple(replace(o, object_guid="") for o in objs)

    return replace(
        e,
        templates=strip(e.templates),
        cas=strip(e.cas),
        acls=strip(e.acls),
        dcs=strip(e.dcs),
        principal_mappings=strip(e.principal_mappings),
        crls=strip(e.crls),
        oids=strip(e.oids),
        # A 0.8.0 export carries no enumeration markers either.
        manifest=replace(e.manifest, collector_version="0.8.0", enumeration_complete=frozenset()),
    )


@dataclass(frozen=True)
class Corpus:
    pairs: tuple[Pair, ...]
    # An estate on which the pristine detectors raise (a value of the wrong type
    # that ingest would have rejected): a mutant that swallows errors does not.
    raising: Estate


def _skip(e: Estate, *passes: str) -> Estate:
    return replace(
        e, manifest=replace(e.manifest, skipped_passes=(*e.manifest.skipped_passes, *passes))
    )


def _variants(base: Estate) -> dict[str, Estate]:
    """*base* degraded or reshaped along each estate-level coverage path."""

    def patch(rule: Callable[[int, CertAuthority], CaPatchState]) -> Estate:
        cas = tuple(replace(c, ca_patch_state=rule(i, c)) for i, c in enumerate(base.cas))
        return replace(base, cas=cas)

    def dcs(binding: StrongCertBinding, **kw: Any) -> Estate:
        return replace(
            base,
            dcs=tuple(
                replace(
                    d,
                    strong_certificate_binding_enforcement=binding,
                    unobtained=frozenset(),
                    **kw,
                )
                for d in base.dcs
            ),
        )

    def manifest(**kw: Any) -> Estate:
        return replace(base, manifest=replace(base.manifest, **kw))

    return {
        "patched-only": patch(lambda i, c: CaPatchState.PATCHED),
        "unpatched-root-only": patch(
            lambda i, c: CaPatchState.UNPATCHED if c.kind is CaKind.ROOT else CaPatchState.PATCHED
        ),
        "unknown-patch-only": patch(
            lambda i, c: CaPatchState.UNKNOWN if i % 2 else CaPatchState.PATCHED
        ),
        "no-issuing-ca": replace(base, cas=tuple(c for c in base.cas if c.kind is CaKind.ROOT)),
        "strict-dcs": dcs(StrongCertBinding.STRICT),
        "unknown-dcs": dcs(StrongCertBinding.UNKNOWN, schannel_mapping_methods=frozenset()),
        "no-dcs": replace(base, dcs=()),
        "dc-pass-skipped": _skip(replace(base, dcs=()), "esc10-dc-registry"),
        "dc-pass-skipped-with-dcs": _skip(base, "esc10-dc-registry"),
        "publication-unknown": manifest(enrollment_services_available=False),
        "no-audit": replace(base, cas=tuple(replace(c, audit_filter=None) for c in base.cas)),
        "no-acl-inputs": replace(
            base,
            templates=tuple(replace(t, security=()) for t in base.templates),
            acls=tuple(replace(a, security=()) for a in base.acls),
            cas=tuple(replace(c, security=()) for c in base.cas),
        ),
        "certs-not-parsed": manifest(certs_parsed=False),
        "stale-collector": manifest(collector_version="0.7.0"),
        **{
            f"skipped:{p}": _skip(base, p)
            for p in (
                "template-security",
                "pki-acls",
                "ca-security",
                "enrollment-endpoints",
                "esc14-altsecid",
                "oid-objects",
                "ca-config",
                "certs",
                "templates",
                "enrollment-services",
            )
        },
    }


def build(tmp: Path) -> Corpus:
    from adcs_lens.detection import CHECKS

    _GUIDS[0] = 0
    shutil.rmtree(tmp, ignore_errors=True)
    full = enrich(ingest(build_full_export(tmp / "full")))
    sink = kitchen_sink(full)
    sink_variants = _variants(sink)
    legacy = _strip_guids(sink)
    pairs = [Pair("self:full", full, full), Pair("self:sink", sink, sink)]
    pairs += [Pair(f"self:{n}", e, e) for n, e in {**sink_variants, "legacy": legacy}.items()]
    # Coverage-state transitions on the smaller full export (it fires every
    # posture check): the newer side degraded, the older intact.
    pairs += [Pair(f"transition:{n}", full, e) for n, e in _variants(full).items()]
    fix = fixed(sink)
    pairs.append(Pair("fix:sink", sink, fix))
    legacy_fix = _strip_guids(fix)
    pairs.append(Pair("fix:legacy", legacy, legacy_fix))
    # A genuinely deleted object of each type resolves by absence (GUID, container
    # complete) even though an unrelated object of the type was added (unpaired);
    # a deleted CRL never does (an index can be partial).
    newcomers = kitchen_sink(
        replace(
            sink,
            templates=(),
            cas=(),
            acls=(),
            dcs=(),
            principal_mappings=(),
            endpoints=(),
            crls=(),
        )
    )
    pairs.append(
        Pair(
            "delete:sink",
            sink,
            replace(
                fix,
                templates=(*fix.templates[:3], newcomers.templates[0]),
                cas=(*fix.cas[:2], newcomers.cas[1]),
                acls=(*fix.acls[:2], newcomers.acls[0]),
                dcs=(*fix.dcs[:1], newcomers.dcs[4]),
                principal_mappings=(*fix.principal_mappings[:1], newcomers.principal_mappings[4]),
                endpoints=fix.endpoints[:1],
                crls=fix.crls[:1],
            ),
        )
    )
    # Legacy identity: a template whose OID changed (same cn) and one whose cn
    # changed (same OID) are not the same objects without a GUID.
    renamed = []
    for t in legacy_fix.templates:
        if t.name == "KsEsc1Plain":
            t = replace(t, oid=t.oid + ".9")
        elif t.name == "KsEsc3":
            t = replace(t, name="KsEsc3Renamed")
        renamed.append(t)
    pairs.append(Pair("legacy-rename", legacy, replace(legacy_fix, templates=tuple(renamed))))
    # DC enforcement: all strict (weak mappings mitigated: resolved), all unset
    # (undecided: withheld), and unset on fixed DCs.
    pairs.append(Pair("mitigated:dcs", sink, sink_variants["strict-dcs"]))
    pairs.append(Pair("enforcement-unknown", sink, sink_variants["unknown-dcs"]))
    pairs.append(
        Pair(
            "unset:dcs",
            sink,
            replace(
                fix,
                dcs=tuple(
                    replace(d, strong_certificate_binding_enforcement=StrongCertBinding.UNKNOWN)
                    for d in fix.dcs
                ),
            ),
        )
    )
    pairs.append(Pair("patch-unknown", sink, sink_variants["unknown-patch-only"]))
    pairs.append(
        Pair(
            "ca-remote",
            sink,
            replace(fix, cas=tuple(replace(c, registry_config_collected=False) for c in fix.cas)),
        )
    )
    pairs.append(
        Pair(
            "only-templates-complete",
            sink,
            replace(
                fix, manifest=replace(fix.manifest, enumeration_complete=frozenset({"templates"}))
            ),
        )
    )
    # Each declared container marked incomplete on the kitchen sink: a verdict
    # resting on an absence there must turn undecided (round-5 review).
    for container in sorted({c for d in CHECKS.values() for c in d.containers}):
        degraded = replace(
            sink,
            manifest=replace(
                sink.manifest,
                enumeration_complete=sink.manifest.enumeration_complete - {container},
            ),
        )
        pairs.append(Pair(f"incomplete:{container}", sink, degraded))
    # ESC15 with an incomplete CA list: every visible issuing CA patched (or only
    # an unpatched root visible) proves nothing about the missing ones.
    for name in ("patched-only", "unpatched-root-only"):
        variant = sink_variants[name]
        pairs.append(
            Pair(
                f"incomplete-ca:{name}",
                sink,
                replace(
                    variant,
                    manifest=replace(
                        variant.manifest,
                        enumeration_complete=variant.manifest.enumeration_complete - {"ca-config"},
                    ),
                ),
            )
        )
    # Withheld pairs on the full export: every posture check fixed, one input lost.
    full_fix = fixed(full)
    for name, degrade in _degradations().items():
        pairs.append(Pair(f"withheld:{name}", full, degrade(full_fix)))
    raising = replace(
        sink,
        cas=(replace(sink.cas[0], edit_flags=None), *sink.cas[1:]),  # type: ignore[arg-type]
    )
    return Corpus(pairs=tuple(pairs), raising=raising)
