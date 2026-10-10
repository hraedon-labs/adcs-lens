# ruff: noqa: E501  (the mutant table holds literal source fragments)
"""Evaluation records: forgotten skips withhold by construction (review round 3).

Two kinds of proof, both executed:

1. **Records design.** Each mutant below inserts a plausible skip (from the
   round-2 reviews: Sol's guard-* copies and DeepSeek's guard_probe.py) BEFORE
   a detector's record point — a mixed gate, a filtered estate, an early
   return, a lambda/helper filter, a misused predicate, a dropped
   evidence_complete — and is loaded as a real module. The older export is
   evaluated by the pristine detectors, the newer by the mutant: nothing the
   mutant suppresses may come out resolved, and (where the mutant fires) the
   lost findings must be withheld. No guard has to recognise the syntax.
2. **Residual guard.** A skip placed AFTER the record point would vouch for an
   object it skipped, so tests/detection_records.py classifies every construct
   there; the post-record mutants must be flagged by it (and, executed, they
   show the false resolution the guard prevents).
"""

from __future__ import annotations

import dataclasses
import importlib.util
import json
import shutil
import sys
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from adcs_lens import detection
from adcs_lens.detection import Evaluation, is_degradation_note
from adcs_lens.diff import diff_findings
from adcs_lens.ingest import ingest
from tests.conftest import NOW
from tests.detection_records import problems
from tests.fixtures.build_fixture import ISSUING_CA
from tests.test_diff_coverage import build_full_export, enrich

pytest.importorskip("cryptography")
pytestmark = pytest.mark.certs

_DETECTION = Path(detection.__file__)

# Every construct after a record point, reviewed as posture logic: vulnerability
# conditions, finding-text branches, notes, and gates that only precede a LATER
# record (e.g. ESC4's owner gate guards the owner-variant record).
POST_RECORD: Counter[tuple[str, str]] = Counter(
    {
    ('_pass_collected', 'calls: '): 1,
    ('_owner_captured', 'calls: '): 1,
    ('_ca_security_readable', 'calls: '): 1,
    ('_template_key_size_captured', 'calls: '): 1,
    ('_crl_next_update_readable', 'calls: '): 1,
    ('_crl_window_readable', 'calls: '): 1,
    ('_dc_binding_known', 'calls: '): 1,
    ('_non_strict_dcs', 'calls: '): 1,
    ('_non_strict_dcs', 'dc.strong_certificate_binding_enforcement in _BINDING_NON_STRICT'): 1,
    ('_esc14_enforcement_resolved', 'calls: _dc_binding_known,_dcs_discovered,_non_strict_dcs,_pass_collected'): 1,
    ('_esc14_enforcement_resolved', '_non_strict_dcs(estate)'): 1,
    ('_template_subject', 'calls: '): 1,
    ('_template_owner_source', 'calls: '): 1,
    ('_pki_subject', 'calls: '): 1,
    ('_pki_owner_source', 'calls: _pki_subject'): 1,
    ('_ca_owner_source', 'calls: '): 1,
    ('_template_ref', 'calls: '): 1,
    ('_template_ref', 'tmpl.oid'): 1,
    ('_template_ref', 'tmpl.name'): 1,
    ('_pki_ref', 'calls: '): 1,
    ('_ca_ref', 'calls: '): 1,
    ('_dc_ref', 'calls: '): 1,
    ('_principal_ref', 'calls: '): 1,
    ('_endpoint_ref', 'calls: '): 1,
    ('_cert_ref', 'calls: '): 1,
    ('_cert_ref', 'cert.fingerprint'): 1,
    ('_cert_ref', 'cert.not_after'): 1,
    ('_crl_ref', 'calls: '): 1,
    ('detect_esc6', 'calls: _ca_ref'): 1,
    ('detect_esc6', '_EDITF_SAN2 in ca.edit_flags'): 1,
    ('_can_authenticate', 'calls: '): 1,
    ('_can_authenticate', 'not template.ekus'): 1,
    ('_blocked_rights', 'calls: '): 1,
    ('_blocked_rights', 'ace.ace_type is not AceType.DENY'): 1,
    ('_blocked_rights', 'normalize_sid(ace.trustee_sid) != sid'): 1,
    ('_low_priv_allow_aces_in', 'calls: _blocked_rights'): 1,
    ('_low_priv_allow_aces_in', 'ace.ace_type is not AceType.ALLOW'): 1,
    ('_low_priv_allow_aces_in', 'not is_low_priv_trustee(ace.trustee_sid)'): 1,
    ('_low_priv_allow_aces_in', '(covers & rights) - blocked'): 1,
    ('_low_priv_allow_aces', 'calls: _low_priv_allow_aces_in'): 1,
    ('_low_priv_enrollers', 'calls: _low_priv_allow_aces'): 1,
    ('_normalized_publishers', 'calls: '): 1,
    ('_normalized_publishers', 'name.strip()'): 1,
    ('_template_publication_detail', 'calls: _normalized_publishers'): 1,
    ('_template_publication_detail', 'publishers'): 1,
    ('_template_publication_detail', 'publication_data_available'): 1,
    ('_scoped_writeproperty_guids', 'calls: '): 1,
    ('_scoped_writeproperty_guids', "not token.startswith('writeproperty:')"): 1,
    ('_scoped_writeproperty_guids', 'guid in _DANGEROUS_PROPERTY_GUIDS'): 1,
    ('_low_priv_dangerous_writeproperty_aces', 'calls: _blocked_scoped_writeproperty,_scoped_writeproperty_guids'): 1,
    ('_low_priv_dangerous_writeproperty_aces', 'ace.ace_type is not AceType.ALLOW'): 1,
    ('_low_priv_dangerous_writeproperty_aces', 'not is_low_priv_trustee(ace.trustee_sid)'): 1,
    ('_low_priv_dangerous_writeproperty_aces', 'not dangerous'): 1,
    ('_low_priv_dangerous_writeproperty_aces', 'surviving'): 1,
    ('_blocked_scoped_writeproperty', 'calls: _blocked_rights'): 1,
    ('_blocked_scoped_writeproperty', "'writepropertyall' in _blocked_rights(security, trustee_sid)"): 1,
    ('_blocked_scoped_writeproperty', 'ace.ace_type is not AceType.DENY'): 1,
    ('_blocked_scoped_writeproperty', 'normalize_sid(ace.trustee_sid) != sid'): 1,
    ('_blocked_scoped_writeproperty', "token == 'writepropertyall'"): 1,
    ('_blocked_scoped_writeproperty', "token.startswith('writeproperty:')"): 1,
    ('_blocked_scoped_writeproperty', 'guid in _DANGEROUS_PROPERTY_GUIDS'): 1,
    ('_template_container', 'calls: _pass_collected'): 1,
    ('_template_container', "all((_pass_collected(estate, p) for p in ('templates', *extra_passes)))"): 1,
    ('detect_esc1', 'calls: _can_authenticate,_low_priv_enrollers,_template_publication_detail,_template_ref,_template_subject'): 1,
    ('detect_esc1', 'not tmpl.name_flags & _ENROLLEE_SUPPLIES_SUBJECT'): 1,
    ('detect_esc1', 'not _can_authenticate(tmpl)'): 1,
    ('detect_esc1', '_MANAGER_APPROVAL in tmpl.enrollment_flags'): 1,
    ('detect_esc1', 'not enrollers'): 1,
    ('detect_esc2', 'calls: _low_priv_enrollers,_template_publication_detail,_template_ref,_template_subject'): 1,
    ('detect_esc2', 'not any_purpose'): 1,
    ('detect_esc2', '_MANAGER_APPROVAL in tmpl.enrollment_flags'): 1,
    ('detect_esc2', 'not enrollers'): 1,
    ('detect_esc2', 'not tmpl.ekus'): 1,
    ('detect_esc3', 'calls: _low_priv_enrollers,_template_publication_detail,_template_ref,_template_subject'): 1,
    ('detect_esc3', '_ENROLLMENT_AGENT_EKU not in tmpl.ekus'): 1,
    ('detect_esc3', '_MANAGER_APPROVAL in tmpl.enrollment_flags'): 1,
    ('detect_esc3', 'not enrollers'): 1,
    ('detect_esc4', 'calls: _blocked_rights,_low_priv_allow_aces,_low_priv_dangerous_writeproperty_aces,_owner_captured,_template_owner_source,_template_ref,_template_subject'): 1,
    ('detect_esc4', 'controllers'): 1,
    ('detect_esc4', 'scoped'): 1,
    ('detect_esc4', '_owner_captured(tmpl.owner_sid)'): 1,
    ('detect_esc4', '_owner_captured(tmpl.owner_sid) and is_low_priv_trustee(tmpl.owner_sid)'): 1,
    ('detect_esc5', 'calls: _blocked_rights,_low_priv_allow_aces_in,_owner_captured,_pki_owner_source,_pki_ref,_pki_subject'): 1,
    ('detect_esc5', '_owner_captured(obj.owner_sid)'): 1,
    ('detect_esc5', 'controllers'): 1,
    ('detect_esc5', '_owner_captured(obj.owner_sid) and is_low_priv_trustee(obj.owner_sid)'): 1,
    ('detect_esc7', 'calls: _blocked_rights,_ca_owner_source,_ca_ref,_ca_security_readable,_owner_captured'): 1,
    ('detect_esc7', '_owner_captured(ca.owner_sid)'): 1,
    ('detect_esc7', 'not _ca_security_readable(ca)'): 1,
    ('detect_esc7', '_owner_captured(ca.owner_sid) and is_low_priv_trustee(ca.owner_sid)'): 1,
    ('detect_esc7', 'ace.ace_type is not AceType.ALLOW'): 1,
    ('detect_esc7', 'not is_low_priv_trustee(ace.trustee_sid)'): 1,
    ('detect_esc7', 'not manage'): 1,
    ('detect_esc7', '_CA_MANAGE_CA in rights'): 1,
    ('detect_esc8', 'calls: _endpoint_ref'): 1,
    ('detect_esc8', 'ep.kind not in _ESC8_KINDS'): 1,
    ('detect_esc8', 'not ep.windows_auth'): 1,
    ('detect_esc8', 'not ep.auth_providers & _NTLM_PROVIDERS'): 1,
    ('detect_esc8', 'epa_required and (not http_open)'): 1,
    ('detect_esc8', 'http_open'): 1,
    ('detect_esc8', 'not epa_required'): 1,
    ('detect_esc8', 'ep.epa is EpaPolicy.ALLOW'): 1,
    ('detect_esc8', 'http_open or explicit_ntlm'): 1,
    ('detect_esc8', 'ep.epa is EpaPolicy.NONE'): 1,
    ('detect_esc9', 'calls: _low_priv_enrollers,_template_ref,_template_subject'): 1,
    ('detect_esc9', '_NO_SECURITY_EXTENSION not in tmpl.enrollment_flags'): 1,
    ('detect_esc9', '_MANAGER_APPROVAL in tmpl.enrollment_flags'): 1,
    ('detect_esc9', 'not enrollers'): 1,
    ('detect_esc16', 'calls: _ca_ref'): 1,
    ('detect_esc16', 'ca.kind is CaKind.ROOT'): 1,
    ('detect_esc16', '_NTDS_CA_SECURITY_EXT in ca.disabled_extensions'): 1,
    ('_schannel_method_list', 'calls: '): 1,
    ('_schannel_method_list', 'methods'): 1,
    ('_dcs_discovered', 'calls: '): 1,
    ('detect_esc10', 'calls: _dc_binding_known,_dc_ref,_schannel_method_list'): 1,
    ('detect_esc10', 'upn_mapping'): 1,
    ('detect_esc10', 'binding == StrongCertBinding.DISABLED'): 1,
    ('detect_esc10', 'reasons'): 1,
    ('detect_esc10', 'binding == StrongCertBinding.PERMISSIVE'): 1,
    ('detect_esc10', 'not _dc_binding_known(dc)'): 1,
    ('_x509_mapping_form', 'calls: '): 1,
    ('_x509_mapping_form', "not text.upper().startswith('X509:')"): 1,
    ('_x509_mapping_form', "'<SKI>' in body"): 1,
    ('_x509_mapping_form', "'<SHA1-PUKEY>' in body"): 1,
    ('_x509_mapping_form', "'<RFC822>' in body"): 1,
    ('_x509_mapping_form', "'<PN>' in body"): 1,
    ('_x509_mapping_form', "'<I>' in body"): 1,
    ('_x509_mapping_form', "'<S>' in body"): 2,
    ('_x509_mapping_form', "'<SR>' in body"): 1,
    ('detect_esc14', 'calls: _esc14_enforcement_resolved,_non_strict_dcs,_principal_ref,_x509_mapping_form'): 1,
    ('detect_esc14', 'not weak_principals'): 1,
    ('detect_esc14', 'not non_strict_dcs'): 1,
    ('detect_esc14', 'weak'): 1,
    ('detect_esc14', 'not _esc14_enforcement_resolved(estate)'): 1,
    ('detect_esc14', 'len(weak) > 3'): 1,
    ('detect_esc14', 'lambda lambda w: w[0]'): 1,
    ('detect_esc11', 'calls: _ca_ref'): 1,
    ('detect_esc11', 'ca.kind is CaKind.ROOT'): 1,
    ('detect_esc11', '_ESC11_FLAG in ca.interface_flags'): 1,
    ('detect_esc13', 'calls: _can_authenticate,_low_priv_enrollers,_template_ref,_template_subject'): 1,
    ('detect_esc13', '_MANAGER_APPROVAL in tmpl.enrollment_flags'): 1,
    ('detect_esc13', 'not linked'): 1,
    ('detect_esc13', 'not _can_authenticate(tmpl)'): 1,
    ('detect_esc13', 'not enrollers'): 1,
    ('detect_esc13', 'len(linked) == 1'): 1,
    ('detect_esc15', 'calls: _low_priv_enrollers,_template_ref,_template_subject'): 1,
    ('detect_esc15', 'patch_state is CaPatchState.PATCHED'): 1,
    ('detect_esc15', 'tmpl.schema_version != 1'): 1,
    ('detect_esc15', '_MANAGER_APPROVAL in tmpl.enrollment_flags'): 1,
    ('detect_esc15', 'not enrollers'): 1,
    ('detect_esc15', 'patch_state is CaPatchState.UNPATCHED'): 1,
    ('detect_infra_cert_expiry', 'calls: _crl_finding,_crl_next_update_readable,_crl_ref,_crl_window_readable,_expiry_finding'): 1,
    ('detect_infra_cert_expiry', 'not _crl_next_update_readable(crl)'): 1,
    ('detect_infra_cert_expiry', '_crl_window_readable(crl)'): 1,
    ('_expiry_finding', 'calls: _cert_ref'): 1,
    ('_expiry_finding', 'not_after < now'): 1,
    ('_expiry_finding', 'days <= warn_days'): 1,
    ('_expiry_finding', 'root'): 3,
    ('_crl_horizon', 'calls: '): 1,
    ('_crl_horizon', 'remaining.days >= 1'): 1,
    ('_crl_finding', 'calls: _crl_horizon,_crl_ref,_crl_window_readable'): 1,
    ('_crl_finding', 'next_update is None'): 1,
    ('_crl_finding', 'next_update < now'): 1,
    ('_crl_finding', '_crl_window_readable(crl) and crl.this_update is not None'): 1,
    ('_crl_finding', 'window is not None and next_update - now <= window'): 1,
    ('_crl_finding', 'validity.total_seconds() > 0'): 1,
    ('_crl_finding', 'window < timedelta(days=1) < validity'): 1,
    ('_crl_finding', 'root'): 3,
    ('detect_weak_signing', 'calls: _cert_ref'): 1,
    ('detect_weak_signing', "'md5' in alg"): 1,
    ('detect_weak_signing', "'sha1' in alg"): 1,
    ('_template_uses_ecdsa', 'calls: '): 1,
    ('_template_uses_ecdsa', "'ecdsa' in tmpl.csp or 'ecdh' in tmpl.csp"): 1,
    ('detect_weak_key_size', 'calls: _cert_ref,_template_container,_template_key_size_captured,_template_ref,_template_subject,_template_uses_ecdsa'): 1,
    ('detect_weak_key_size', 'not _template_key_size_captured(tmpl)'): 1,
    ('detect_weak_key_size', 'bits is None or bits >= 2048'): 2,
    ('detect_weak_key_size', '_template_uses_ecdsa(tmpl)'): 1,
    ('detect_weak_key_size', 'bits < 1024'): 2,
    ('detect_weak_key_size', "cert.key_alg != 'rsa'"): 1,
    ('detect_weak_key_size', 'bits == 1024'): 2,
    ('detect_audit_config', 'calls: _ca_ref'): 1,
    ('detect_audit_config', 'ca.audit_filter == 0'): 1,
    ('detect_audit_config', 'missing'): 1,
    ('detect_orphaned_templates', 'calls: _normalized_publishers,_template_ref,_template_subject'): 1,
    ('detect_orphaned_templates', '_normalized_publishers(tmpl)'): 1,
    ('detect_ocsp_absence', 'calls: _cert_ref'): 1,
    ('detect_ocsp_absence', 'ca.kind is CaKind.ROOT'): 1,
    ('detect_ocsp_absence', 'cert.ocsp_urls'): 1,
    ('detect_cdp_aia_absence', 'calls: _cert_ref'): 1,
    ('detect_cdp_aia_absence', 'ca.kind is CaKind.ROOT'): 1,
    ('detect_cdp_aia_absence', 'cdp_missing'): 2,
    ('detect_cdp_aia_absence', 'aia_missing'): 1,
    ('detect_cdp_aia_absence', 'not missing'): 1,
    ('detect_cdp_aia_absence', 'cdp_missing and aia_missing'): 1,
    }
)


def _src() -> str:
    return _DETECTION.read_text(encoding="utf-8")


def test_post_record_constructs_are_classified() -> None:
    found = problems(_src(), POST_RECORD)
    assert found == [], "\n".join(found)


# --- mutants -----------------------------------------------------------------


def _sub(old: str, new: str) -> Callable[[str], str]:
    def apply(src: str) -> str:
        assert old in src, old
        return src.replace(old, new, 1)

    return apply


def _in_func(header: str, anchor: str, insert: str, *, after: bool = True) -> Callable[[str], str]:
    def apply(src: str) -> str:
        start = src.index(header)
        at = src.index(anchor, start)
        if after:
            at += len(anchor)
        return src[:at] + insert + src[at:]

    return apply


def _replace_in_func(header: str, old: str, new: str) -> Callable[[str], str]:
    def apply(src: str) -> str:
        start = src.index(header)
        at = src.index(old, start)
        return src[:at] + new + src[at + len(old):]

    return apply


def _chain(*fns: Callable[[str], str]) -> Callable[[str], str]:
    def apply(src: str) -> str:
        for f in fns:
            src = f(src)
        return src

    return apply


ESC6 = "def detect_esc6(estate: Estate) -> list[Finding]:"
ESC1 = "def detect_esc1(estate: Estate) -> list[Finding]:"
ESC1_LOOP = "    for tmpl in estate.templates:\n"
ESC6_LOOP = "    for ca in estate.cas:\n"
ESC6_BODY = '    findings: list[Finding] = []\n    if _pass_collected(estate, "ca-config"):\n        _container_evaluated("ESC6", "ca")\n'


@dataclasses.dataclass(frozen=True)
class Mutant:
    mutate: Callable[[str], str]
    trigger: Callable[[Path], None] | None  # newer-export change that makes it fire
    checks: frozenset[str]  # checks the mutant suppresses (must be withheld)
    killed_by: str  # "records" or "guard"


def _ca_dns_cleared(base: Path) -> None:
    _rw(base / "ca-config.json", lambda cas: [c.__setitem__("dns", "") for c in cas if c["name"] == ISSUING_CA])


def _esc1_display_cleared(base: Path) -> None:
    _rw(base / "templates.json", lambda ts: [t.__setitem__("display_name", "") for t in ts if t["name"] == "LabEsc1"])


def _certs_skipped(base: Path) -> None:
    _rw(base / "collector-manifest.json", lambda m: m["skipped_passes"].append("certs"))
    shutil.rmtree(base / "certs")


def _patch_unknown(base: Path) -> None:
    _rw(base / "ca-config.json", lambda cas: [c.__setitem__("ca_patch_state", "unknown") for c in cas if c["name"] == ISSUING_CA])


def _rw(path: Path, fn: Callable[[Any], Any]) -> None:
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    fn(data)
    path.write_text(json.dumps(data), encoding="utf-8")


ESC6_SET = frozenset({"ESC6"})
ESC1_SET = frozenset({"ESC1"})

MUTANTS: dict[str, Mutant] = {
    # ---- Sol, round 2 (.review/tmp/guard-*) -----------------------------------
    "sol-guard-mixed": Mutant(
        _sub("        if not _ca_registry_collected(ca):\n            continue\n        _evaluated(\"ESC6\"",
             "        if not _ca_registry_collected(ca) or not ca.dns:\n            continue\n        _evaluated(\"ESC6\""),
        _ca_dns_cleared, ESC6_SET, "records"),
    "sol-guard-filter": Mutant(
        _chain(
            _sub(ESC6, "def _only_dns_cas(estate: Estate) -> Estate:\n    import dataclasses as _dc\n"
                 "    return _dc.replace(estate, cas=tuple(filter(lambda ca: bool(ca.dns), estate.cas)))\n\n\n" + ESC6),
            _in_func(ESC6, ESC6_BODY, "    estate = _only_dns_cas(estate)\n"),
        ),
        _ca_dns_cleared, ESC6_SET, "records"),
    "sol-guard-early": Mutant(
        _in_func(ESC6, ESC6_BODY, "    return []  # MUTANT\n", after=False),
        None, ESC6_SET, "records"),
    "sol-guard-evidence": Mutant(
        _sub("                evidence_complete=patch_state is not CaPatchState.UNKNOWN,\n", ""),
        _patch_unknown, frozenset({"ESC15"}), "records"),
    # ---- DeepSeek, round 2 (.review/tmp/guard_probe.py) ------------------------
    "ds-filter-lambda": Mutant(
        _replace_in_func(ESC1, ESC1_LOOP, "    for tmpl in filter(lambda t: t.display_name, estate.templates):\n"),
        _esc1_display_cleared, ESC1_SET, "records"),
    "ds-early-return": Mutant(
        _sub(ESC1 + "\n", ESC1 + "\n    return []  # MUTANT\n"), None, ESC1_SET, "records"),
    "ds-helper-skip": Mutant(
        _chain(
            _sub(ESC1, "def _skip_esc1_helper(t: CertTemplate) -> bool:\n    return not t.display_name\n\n\n" + ESC1),
            _in_func(ESC1, ESC1_LOOP, "        if _skip_esc1_helper(tmpl):\n            continue  # MUTANT\n"),
        ),
        _esc1_display_cleared, ESC1_SET, "records"),
    "ds-walrus": Mutant(
        _in_func(ESC1, ESC1_LOOP, "        if (dn := tmpl.display_name) and not dn:\n            continue  # MUTANT\n"),
        _esc1_display_cleared, frozenset(), "records"),  # never true: a no-op mutant
    "ds-any-element": Mutant(
        _in_func(ESC1, ESC1_LOOP, "        if any(not t.display_name for t in estate.templates):\n            continue  # MUTANT\n"),
        _esc1_display_cleared, ESC1_SET, "records"),
    "ds-comprehension": Mutant(
        _in_func(ESC1, ESC1_LOOP, "        if [t for t in estate.templates if not t.display_name]:\n            continue  # MUTANT\n"),
        _esc1_display_cleared, ESC1_SET, "records"),
    "ds-wrong-pass-predicate": Mutant(
        _in_func(ESC1, ESC1_LOOP, "        if not _pass_collected(estate, 'certs'):\n            continue  # MUTANT\n"),
        _certs_skipped, ESC1_SET, "records"),
    "ds-wrong-purpose-predicate": Mutant(
        _in_func(ESC1, ESC1_LOOP, "        if _owner_captured(tmpl.owner_sid):\n            continue  # MUTANT\n"),
        None, ESC1_SET, "records"),
    "ds-filter-method": Mutant(
        _chain(
            _sub(ESC1, "def _keep(t: CertTemplate) -> bool:\n    return bool(t.display_name)\n\n\n" + ESC1),
            _replace_in_func(ESC1, ESC1_LOOP, "    for tmpl in filter(_keep, estate.templates):\n"),
        ),
        _esc1_display_cleared, ESC1_SET, "records"),
    "ds-class-method-skip": Mutant(
        _chain(
            _sub(ESC1, "class _Skip:\n    def __init__(self, t: CertTemplate) -> None:\n        self.ok = bool(t.display_name)\n\n\n" + ESC1),
            _in_func(ESC1, ESC1_LOOP, "        if not _Skip(tmpl).ok:\n            continue  # MUTANT\n"),
        ),
        _esc1_display_cleared, ESC1_SET, "records"),
    # ---- after the record point: the residual guard's job ----------------------
    "post-record-continue": Mutant(
        _sub('        _evaluated("ESC6", _ca_ref(ca))\n', '        _evaluated("ESC6", _ca_ref(ca))\n        if not ca.dns:\n            continue  # MUTANT\n'),
        _ca_dns_cleared, ESC6_SET, "guard"),
    "post-record-unconditional-continue": Mutant(
        _sub('        _evaluated("ESC1", _template_ref(tmpl))\n', '        _evaluated("ESC1", _template_ref(tmpl))\n        continue  # MUTANT\n'),
        None, ESC1_SET, "guard"),
    "post-record-findings-filter": Mutant(
        _in_func(ESC6, "    return findings\n", "    findings = [f for f in findings if f.subject != 'x']\n", after=False),
        None, frozenset(), "guard"),
    "record-before-gate": Mutant(
        _sub("        if not _ca_registry_collected(ca):\n            continue\n        _evaluated(\"ESC6\", _ca_ref(ca))\n",
             "        _evaluated(\"ESC6\", _ca_ref(ca))\n        if not _ca_registry_collected(ca):\n            continue\n"),
        None, frozenset(), "guard"),
    "records-after-findings": Mutant(
        _chain(
            _sub('        _evaluated("ESC6", _ca_ref(ca))\n', ""),
            _in_func(ESC6, "    return findings\n", '    for ca in estate.cas:\n        _evaluated("ESC6", _ca_ref(ca))\n', after=False),
        ),
        None, frozenset(), "guard"),
    # ---- Sol round 3: a gating helper called AFTER the record stops working -----
    # _low_priv_enrollers runs after ESC1/2/3/9/13/15 record their templates; if
    # it returns nothing, every such finding is suppressed. The guard follows the
    # helper and pins its call graph, so dropping its worker call is caught.
    "sol-r3-enrollers-return-empty": Mutant(
        _replace_in_func(
            "def _low_priv_enrollers(template: CertTemplate) -> list[AceEntry]:",
            "    return _low_priv_allow_aces(template, _ENROLL_RIGHTS)\n",
            "    return []  # MUTANT\n",
        ),
        _esc1_display_cleared,
        frozenset({"ESC1", "ESC2", "ESC3", "ESC9", "ESC13", "ESC15"}),
        "guard"),
}


def _load_mutant(src: str, name: str) -> ModuleType:
    mod_name = f"adcs_lens._mutant_{name.replace('-', '_')}"
    spec = importlib.util.spec_from_loader(mod_name, loader=None)
    assert spec is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod  # dataclasses need the module registered
    try:
        exec(compile(src, f"<{mod_name}>", "exec"), mod.__dict__)
    finally:
        sys.modules.pop(mod_name, None)
    return mod


def _as_pristine(ev: Any) -> Evaluation:
    return Evaluation(
        findings=tuple(ev.findings), objects=tuple(ev.objects), records=ev.records,
        containers=ev.containers, guid_types=ev.guid_types,
    )


@pytest.fixture(scope="module")
def full_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return build_full_export(tmp_path_factory.mktemp("rec") / "export")


def _run(name: str, full_dir: Path, tmp_path: Path) -> tuple[Any, Evaluation]:
    m = MUTANTS[name]
    mutated = m.mutate(_src())
    assert mutated != _src(), f"mutant {name} did not apply"
    newer = tmp_path / "newer"
    shutil.copytree(full_dir, newer)
    if m.trigger is not None:
        m.trigger(newer)
    old_ev = detection.evaluate(enrich(ingest(full_dir)), now=NOW)
    mod = _load_mutant(mutated, name)
    new_ev = _as_pristine(mod.evaluate(enrich(ingest(newer)), now=NOW))
    return diff_findings(old_ev, new_ev), old_ev


@pytest.mark.parametrize("name", sorted(n for n, m in MUTANTS.items() if m.killed_by == "records"))
def test_records_design_withholds_what_a_mutant_skips(name: str, full_dir: Path, tmp_path: Path) -> None:
    report, _old = _run(name, full_dir, tmp_path)
    resolved = [f.check for f in report.resolved if not is_degradation_note(f)]
    assert resolved == [], f"{name}: false resolution {resolved}"
    improved = [d.new.check for d in report.changed
                if detection.SEVERITY_RANK[d.new.severity] > detection.SEVERITY_RANK[d.old.severity]]
    assert improved == [], f"{name}: false improvement {improved}"
    withheld = {i.finding.check for i in report.indeterminate}
    assert MUTANTS[name].checks <= withheld, (name, withheld)


@pytest.mark.parametrize("name", sorted(MUTANTS))
def test_guard_verdict(name: str) -> None:
    """Post-record mutants are flagged; pre-record ones need no guard (records)."""
    found = problems(MUTANTS[name].mutate(_src()), POST_RECORD)
    if MUTANTS[name].killed_by == "guard":
        assert found, f"{name} survived the residual guard"


@pytest.mark.parametrize(
    "name", sorted(n for n, m in MUTANTS.items() if m.killed_by == "guard" and m.checks)
)
def test_post_record_mutant_really_needs_the_guard(name: str, full_dir: Path, tmp_path: Path) -> None:
    """Executed: without the guard, a post-record skip WOULD resolve falsely."""
    report, _old = _run(name, full_dir, tmp_path)
    assert {f.check for f in report.resolved} & MUTANTS[name].checks
