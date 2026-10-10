"""Predicate parity is structural: every detector condition is classified.

See tests/detection_conditions.py for the rule. This module holds the reviewed
classification of every POSTURE condition in detection.py, keyed by
(function, condition source) with its occurrence count, and proves the guard
kills the review's mutants: a new skip such as ``if not ca.dns: continue`` in
detect_esc6 or ``if not tmpl.display_name: continue`` in detect_esc1 fails
the build unless it is either a registered coverage predicate consulted by
coverage_gaps, or deliberately added here in review.

Posture conditions are vulnerability logic (flags, EKUs, rights, kinds),
finding-text branches, and type narrowing of values a registered predicate
already gated. Nothing here may decide "this input was not collected": such a
condition belongs in detection.COVERAGE_PREDICATES.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

import pytest

from tests.detection_conditions import analyse, problems

_DETECTION = Path(__file__).resolve().parent.parent / "src" / "adcs_lens" / "detection.py"

POSTURE_CONDITIONS: Counter[tuple[str, str]] = Counter(
    {
    ('_uncollected_source', 'pass_name in estate.manifest.skipped_passes'): 1,
    ('_non_strict_dcs', 'dc.strong_certificate_binding_enforcement in _BINDING_NON_STRICT'): 1,
    ('_template_ids', 'tmpl.oid'): 1,
    ('_template_ids', 'tmpl.name'): 1,
    ('_cert_ids', 'cert.fingerprint'): 1,
    ('_cert_ids', 'cert.not_after'): 1,
    ('detect_collection_gaps', 'not missing and pass_name in _PASSES_WITH_DEDICATED_NOTE'): 1,
    ('detect_collection_gaps', 'missing'): 1,
    ('detect_esc6', '_EDITF_SAN2 in ca.edit_flags'): 1,
    ('_can_authenticate', 'not template.ekus'): 1,
    ('_blocked_rights', 'ace.ace_type is not AceType.DENY'): 1,
    ('_blocked_rights', 'normalize_sid(ace.trustee_sid) != sid'): 1,
    ('_low_priv_allow_aces_in', 'ace.ace_type is not AceType.ALLOW'): 1,
    ('_low_priv_allow_aces_in', 'not is_low_priv_trustee(ace.trustee_sid)'): 1,
    ('_low_priv_allow_aces_in', '(covers & rights) - blocked'): 1,
    ('_normalized_publishers', 'name.strip()'): 1,
    ('_template_publication_detail', 'publishers'): 1,
    ('_template_publication_detail', 'publication_data_available'): 1,
    ('_scoped_writeproperty_guids', "not token.startswith('writeproperty:')"): 1,
    ('_scoped_writeproperty_guids', 'guid in _DANGEROUS_PROPERTY_GUIDS'): 1,
    ('_low_priv_dangerous_writeproperty_aces', 'ace.ace_type is not AceType.ALLOW'): 1,
    ('_low_priv_dangerous_writeproperty_aces', 'not is_low_priv_trustee(ace.trustee_sid)'): 1,
    ('_low_priv_dangerous_writeproperty_aces', 'not dangerous'): 1,
    ('_low_priv_dangerous_writeproperty_aces', 'surviving'): 1,
    ('_blocked_scoped_writeproperty', "'writepropertyall' in _blocked_rights(security, trustee_sid)"): 1,  # noqa: E501
    ('_blocked_scoped_writeproperty', 'ace.ace_type is not AceType.DENY'): 1,
    ('_blocked_scoped_writeproperty', 'normalize_sid(ace.trustee_sid) != sid'): 1,
    ('_blocked_scoped_writeproperty', "token == 'writepropertyall'"): 1,
    ('_blocked_scoped_writeproperty', "token.startswith('writeproperty:')"): 1,
    ('_blocked_scoped_writeproperty', 'guid in _DANGEROUS_PROPERTY_GUIDS'): 1,
    ('detect_esc1', 'not tmpl.name_flags & _ENROLLEE_SUPPLIES_SUBJECT'): 1,
    ('detect_esc1', 'not _can_authenticate(tmpl)'): 1,
    ('detect_esc1', '_MANAGER_APPROVAL in tmpl.enrollment_flags'): 1,
    ('detect_esc1', 'not enrollers'): 1,
    ('detect_esc2', 'not any_purpose'): 1,
    ('detect_esc2', '_MANAGER_APPROVAL in tmpl.enrollment_flags'): 1,
    ('detect_esc2', 'not enrollers'): 1,
    ('detect_esc2', 'not tmpl.ekus'): 1,
    ('detect_esc3', '_ENROLLMENT_AGENT_EKU not in tmpl.ekus'): 1,
    ('detect_esc3', '_MANAGER_APPROVAL in tmpl.enrollment_flags'): 1,
    ('detect_esc3', 'not enrollers'): 1,
    ('detect_esc4', 'controllers'): 1,
    ('detect_esc4', 'scoped'): 1,
    ('detect_esc4', 'r.strip().lower() in _DANGEROUS_TEMPLATE_CONTROL and r.strip().lower() not in _blocked_rights(template_security, a.trustee_sid)'): 1,  # noqa: E501
    ('detect_esc5', 'controllers'): 1,
    ('detect_esc5', 'r.strip().lower() in _DANGEROUS_OBJECT_CONTROL and r.strip().lower() not in _blocked_rights(obj.security, a.trustee_sid)'): 1,  # noqa: E501
    ('detect_esc7', 'ace.ace_type is not AceType.ALLOW'): 1,
    ('detect_esc7', 'not is_low_priv_trustee(ace.trustee_sid)'): 1,
    ('detect_esc7', 'not manage'): 1,
    ('detect_esc7', '_CA_MANAGE_CA in rights'): 1,
    ('detect_esc8', 'ep.kind not in _ESC8_KINDS'): 1,
    ('detect_esc8', 'not ep.windows_auth'): 1,
    ('detect_esc8', 'not ep.auth_providers & _NTLM_PROVIDERS'): 1,
    ('detect_esc8', 'epa_required and (not http_open)'): 1,
    ('detect_esc8', 'http_open'): 1,
    ('detect_esc8', 'not epa_required'): 1,
    ('detect_esc8', 'ep.epa is EpaPolicy.ALLOW'): 1,
    ('detect_esc8', 'http_open or explicit_ntlm'): 1,
    ('detect_esc8', 'ep.epa is EpaPolicy.NONE'): 1,
    ('detect_esc9', '_NO_SECURITY_EXTENSION not in tmpl.enrollment_flags'): 1,
    ('detect_esc9', '_MANAGER_APPROVAL in tmpl.enrollment_flags'): 1,
    ('detect_esc9', 'not enrollers'): 1,
    ('detect_esc16', 'ca.kind is CaKind.ROOT'): 1,
    ('detect_esc16', '_NTDS_CA_SECURITY_EXT in ca.disabled_extensions'): 1,
    ('_schannel_method_list', 'methods'): 1,
    ('detect_esc10', 'upn_mapping'): 1,
    ('detect_esc10', 'binding == StrongCertBinding.DISABLED'): 1,
    ('detect_esc10', 'reasons'): 1,
    ('detect_esc10', 'binding == StrongCertBinding.PERMISSIVE'): 1,
    ('_x509_mapping_form', "not text.upper().startswith('X509:')"): 1,
    ('_x509_mapping_form', "'<SKI>' in body"): 1,
    ('_x509_mapping_form', "'<SHA1-PUKEY>' in body"): 1,
    ('_x509_mapping_form', "'<RFC822>' in body"): 1,
    ('_x509_mapping_form', "'<PN>' in body"): 1,
    ('_x509_mapping_form', "'<I>' in body"): 1,
    ('_x509_mapping_form', "'<S>' in body"): 2,
    ('_x509_mapping_form', "'<SR>' in body"): 1,
    ('detect_esc14', 'not weak_principals'): 1,
    ('detect_esc14', 'not non_strict_dcs'): 1,
    ('detect_esc14', 'weak'): 1,
    ('detect_esc14', 'len(weak) > 3'): 1,
    ('detect_esc14', '_x509_mapping_form(m) in WEAK_X509_MAPPING_FORMS'): 1,
    ('_group_linked_policies', 'o.group_link'): 1,
    ('detect_esc11', 'ca.kind is CaKind.ROOT'): 1,
    ('detect_esc11', '_ESC11_FLAG in ca.interface_flags'): 1,
    ('detect_esc13', '_MANAGER_APPROVAL in tmpl.enrollment_flags'): 1,
    ('detect_esc13', 'not linked'): 1,
    ('detect_esc13', 'not _can_authenticate(tmpl)'): 1,
    ('detect_esc13', 'not enrollers'): 1,
    ('detect_esc13', 'o.group_link'): 1,
    ('detect_esc13', 'o in policy_map'): 1,
    ('detect_esc13', 'len(linked) == 1'): 1,
    ('_worst_ca_patch_state', 'not issuing'): 1,
    ('_worst_ca_patch_state', 'CaPatchState.UNPATCHED in states'): 1,
    ('_worst_ca_patch_state', 'CaPatchState.UNKNOWN in states'): 1,
    ('_worst_ca_patch_state', 'ca.kind is not CaKind.ROOT'): 1,
    ('detect_esc15', 'patch_state is CaPatchState.PATCHED'): 1,
    ('detect_esc15', 'tmpl.schema_version != 1'): 1,
    ('detect_esc15', '_MANAGER_APPROVAL in tmpl.enrollment_flags'): 1,
    ('detect_esc15', 'not enrollers'): 1,
    ('detect_esc15', 'patch_state is CaPatchState.UNPATCHED'): 1,
    ('detect_infra_cert_expiry', 'now is None'): 1,
    ('detect_infra_cert_expiry', 'now.tzinfo is None'): 1,
    ('_expiry_finding', 'not_after < now'): 1,
    ('_expiry_finding', 'days <= warn_days'): 1,
    ('_expiry_finding', 'root'): 3,
    ('_crl_horizon', 'remaining.days >= 1'): 1,
    ('_crl_finding', 'next_update is None'): 1,
    ('_crl_finding', 'next_update < now'): 1,
    ('_crl_finding', 'window is not None and next_update - now <= window'): 1,
    ('_crl_finding', 'validity.total_seconds() > 0'): 1,
    ('_crl_finding', 'window < timedelta(days=1) < validity'): 1,
    ('_crl_finding', 'root'): 3,
    ('detect_weak_signing', "'md5' in alg"): 1,
    ('detect_weak_signing', "'sha1' in alg"): 1,
    ('_template_uses_ecdsa', "'ecdsa' in tmpl.csp or 'ecdh' in tmpl.csp"): 1,
    ('detect_weak_key_size', 'bits is None or bits >= 2048'): 2,
    ('detect_weak_key_size', '_template_uses_ecdsa(tmpl)'): 1,
    ('detect_weak_key_size', 'bits < 1024'): 2,
    ('detect_weak_key_size', "cert.key_alg != 'rsa'"): 1,
    ('detect_weak_key_size', 'bits == 1024'): 2,
    ('detect_audit_config', 'ca.audit_filter == 0'): 1,
    ('detect_audit_config', 'missing'): 1,
    ('detect_audit_config', 'not ca.audit_filter & bit'): 1,
    ('detect_acl_coverage_caveats', 'not acl_inputs'): 1,
    ('detect_orphaned_templates', '_normalized_publishers(tmpl)'): 1,
    ('detect_ocsp_absence', 'ca.kind is CaKind.ROOT'): 1,
    ('detect_ocsp_absence', 'cert.ocsp_urls'): 1,
    ('detect_cdp_aia_absence', 'ca.kind is CaKind.ROOT'): 1,
    ('detect_cdp_aia_absence', 'cdp_missing'): 2,
    ('detect_cdp_aia_absence', 'aia_missing'): 1,
    ('detect_cdp_aia_absence', 'not missing'): 1,
    ('detect_cdp_aia_absence', 'cdp_missing and aia_missing'): 1,
    }
)


def _src() -> str:
    return _DETECTION.read_text(encoding="utf-8")


def test_every_detection_condition_is_classified() -> None:
    found = problems(_src(), POSTURE_CONDITIONS)
    assert found == [], "\n".join(found)


def test_every_registered_predicate_gates_a_detector() -> None:
    a = analyse(_src())
    assert a.registered - a.predicates_in_conditions == set()


def _mutate(src: str, anchor: str, insert: str) -> str:
    assert src.count(anchor) >= 1, anchor
    return src.replace(anchor, anchor + insert, 1)


_ESC6_LOOP = "def detect_esc6(estate: Estate) -> list[Finding]:"
_ESC1_LOOP = "def detect_esc1(estate: Estate) -> list[Finding]:"


def _in_first_loop(src: str, func_header: str, loop: str, body: str) -> str:
    """Insert *body* right after the first *loop* line inside *func_header*."""
    start = src.index(func_header)
    at = src.index(loop, start) + len(loop)
    return src[:at] + body + src[at:]


MUTANTS = {
    # Sol's mutant: a newly missing DNS name silently suppresses ESC6.
    "esc6-dns-skip": lambda s: _in_first_loop(
        s, _ESC6_LOOP, "    for ca in estate.cas:\n",
        "        if not ca.dns:\n            continue  # MUTANT\n",
    ),
    # DeepSeek's mutant: a cleared display name silently suppresses ESC1.
    "esc1-display-name-skip": lambda s: _in_first_loop(
        s, _ESC1_LOOP, "    for tmpl in estate.templates:\n",
        "        if not tmpl.display_name:\n            continue  # MUTANT\n",
    ),
    # Tightening a positive condition is just as much a new skip.
    "esc6-positive-condition-tightened": lambda s: s.replace(
        "if _EDITF_SAN2 in ca.edit_flags:", "if _EDITF_SAN2 in ca.edit_flags and ca.dns:", 1
    ),
    # A skip hidden in an exception handler.
    "esc6-try-except-skip": lambda s: _in_first_loop(
        s, _ESC6_LOOP, "    for ca in estate.cas:\n",
        "        try:\n            ca.dns.encode()\n        except ValueError:\n"
        "            continue  # MUTANT\n",
    ),
    # A registered predicate that coverage_gaps forgets to consult.
    "predicate-missing-from-coverage-gaps": lambda s: s.replace(
        "    if _pass_collected(estate, _ESC10_DC_REGISTRY_PASS) and not _dcs_discovered(estate):",
        "    if False:",
        1,
    ),
}


@pytest.mark.parametrize("name", sorted(MUTANTS))
def test_guard_kills_mutant(name: str) -> None:
    mutated = MUTANTS[name](_src())
    assert mutated != _src(), f"mutant {name} did not apply"
    assert problems(mutated, POSTURE_CONDITIONS), f"mutant {name} survived the guard"


def test_mutant_esc6_dns_skip_is_reported_precisely() -> None:
    found = problems(MUTANTS["esc6-dns-skip"](_src()), POSTURE_CONDITIONS)
    assert found == ["unclassified condition in detect_esc6: 'not ca.dns' (x1)"]


def test_mutant_esc1_display_name_skip_is_reported_precisely() -> None:
    found = problems(MUTANTS["esc1-display-name-skip"](_src()), POSTURE_CONDITIONS)
    assert found == ["unclassified condition in detect_esc1: 'not tmpl.display_name' (x1)"]
