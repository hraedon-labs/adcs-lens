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
# record (e.g. ESC4's owner gate guards the owner-variant record). Besides the
# bare conditions / lambdas, keys are prefixed:
#   "flow: ..."  an evidence call with its consumer and exact arguments;
#   "bind: ..."  a binding the verdict reads (conditions, loop iterables, evidence
#                arguments, helper return values), traced back through the region;
#   "return ..." a return of a whole-body helper (Finding bodies elided).
# Regenerate with tests.detection_records.analyse(source)[0] ONLY after reviewing
# each changed key as posture logic.
POST_RECORD: Counter[tuple[str, str]] = Counter(
    {
    ('_pass_collected', 'return pass_name not in estate.manifest.uncollected_passes'): 1,
    ('_owner_captured', 'return bool(owner_sid)'): 1,
    ('_ca_security_readable', 'return ca.security_collected'): 1,
    ('_template_key_size_captured', 'return tmpl.min_key_size is not None'): 1,
    ('_crl_next_update_readable', 'return crl.next_update is not None'): 1,
    ('_crl_window_readable', 'return crl.this_update is not None'): 1,
    ('_dc_binding_known', 'return dc.strong_certificate_binding_enforcement is not StrongCertBinding.UNKNOWN'): 1,
    ('_non_strict_dcs', 'return [dc for dc in estate.dcs if dc.strong_certificate_binding_enforcement in _BINDING_NON_STRICT]'): 1,
    ('_non_strict_dcs', 'dc.strong_certificate_binding_enforcement in _BINDING_NON_STRICT'): 1,
    ('_esc14_enforcement_resolved', 'return _pass_collected(estate, _ESC10_DC_REGISTRY_PASS) and _dcs_discovered(estate) and all((_dc_binding_known(dc) for dc in estate.dcs))'): 1,
    ('_esc14_enforcement_resolved', 'flow: if _non_strict_dcs(estate)'): 1,
    ('_esc14_enforcement_resolved', 'return True'): 1,
    ('_esc14_enforcement_resolved', 'flow: return _pass_collected(estate, _ESC10_DC_REGISTRY_PASS) and _dcs_discovered(estate) and all((_dc_binding_known(dc) for dc in estate.dcs))'): 3,
    ('_esc14_enforcement_resolved', '_non_strict_dcs(estate)'): 1,
    ('_template_subject', 'return tmpl.display_name or tmpl.name'): 1,
    ('_template_owner_source', 'return f"template \'{tmpl.name}\': nTSecurityDescriptor owner"'): 1,
    ('_pki_subject', 'return obj.object_dn or obj.kind.value'): 1,
    ('_pki_owner_source', "return f'{_pki_subject(obj)}: nTSecurityDescriptor owner'"): 1,
    ('_pki_owner_source', 'flow: {_pki_subject(obj)}'): 1,
    ('_ca_owner_source', "return f'{ca.config_string or ca.name}: CA\\\\Security owner'"): 1,
    ('_template_ref', "return ObjectRef('template', tmpl.object_guid, tuple(aliases))"): 1,
    ('_template_ref', 'bind: aliases = []'): 1,
    ('_template_ref', "bind: aliases.append(f'oid:{tmpl.oid.lower()}')"): 1,
    ('_template_ref', "bind: aliases.append(f'cn:{tmpl.name.lower()}')"): 1,
    ('_template_ref', 'tmpl.oid'): 1,
    ('_template_ref', 'tmpl.name'): 1,
    ('_pki_ref', "return ObjectRef('pki', obj.object_guid, (f'dn:{(obj.object_dn or obj.kind.value).lower()}',))"): 1,
    ('_ca_ref', "return ObjectRef('ca', ca.object_guid, (f'cn:{ca.name.lower()}',))"): 1,
    ('_dc_ref', "return ObjectRef('dc', dc.object_guid, (f'dns:{dc.name.lower()}',))"): 1,
    ('_principal_ref', "return ObjectRef('principal', principal.object_guid, (f'dn:{principal.dn.lower()}',))"): 1,
    ('_endpoint_ref', "return ObjectRef('endpoint', '', (f'app:{ep.kind.value}:{(ep.name or ep.kind.value).lower()}',))"): 1,
    ('_cert_ref', "return ObjectRef('cert', '', (f'cert:{ca_name.lower()}|{cert.subject}|{stamp}',))"): 1,
    ('_cert_ref', "return ObjectRef('cert', '', (f'sha256:{cert.fingerprint}',))"): 1,
    ('_cert_ref', "bind: stamp = cert.not_after.isoformat() if cert.not_after else ''"): 1,
    ('_cert_ref', 'cert.fingerprint'): 1,
    ('_cert_ref', 'cert.not_after'): 1,
    ('_crl_ref', "return ObjectRef('crl', crl.object_guid, (f'crl:{crl.issuer.lower()}|{crl.source}',))"): 1,
    ('detect_esc6', 'flow: object_ref=_ca_ref(ca)'): 1,
    ('detect_esc6', '_EDITF_SAN2 in ca.edit_flags'): 1,
    ('_can_authenticate', 'return any((eku in _AUTH_EKUS for eku in template.ekus))'): 1,
    ('_can_authenticate', 'return True'): 1,
    ('_can_authenticate', 'not template.ekus'): 1,
    ('_blocked_rights', 'return frozenset(blocked)'): 1,
    ('_blocked_rights', 'bind: sid = normalize_sid(trustee_sid)'): 1,
    ('_blocked_rights', 'bind: blocked: set[str] = set()'): 1,
    ('_blocked_rights', 'bind: for ace in security'): 1,
    ('_blocked_rights', 'bind: blocked |= _COVERS.get(r.strip().lower(), frozenset())'): 1,
    ('_blocked_rights', 'bind: for r in ace.rights'): 1,
    ('_blocked_rights', 'ace.ace_type is not AceType.DENY'): 1,
    ('_blocked_rights', 'normalize_sid(ace.trustee_sid) != sid'): 1,
    ('_low_priv_allow_aces_in', 'return out'): 1,
    ('_low_priv_allow_aces_in', 'flow: blocked = _blocked_rights(security, ace.trustee_sid)'): 1,
    ('_low_priv_allow_aces_in', 'bind: out: list[AceEntry] = []'): 1,
    ('_low_priv_allow_aces_in', 'bind: for ace in security'): 1,
    ('_low_priv_allow_aces_in', 'bind: covers = _COVERS.get(token, frozenset({token}))'): 1,
    ('_low_priv_allow_aces_in', 'bind: out.append(ace)'): 1,
    ('_low_priv_allow_aces_in', 'bind: token = r.strip().lower()'): 1,
    ('_low_priv_allow_aces_in', 'bind: for r in ace.rights'): 1,
    ('_low_priv_allow_aces_in', 'ace.ace_type is not AceType.ALLOW'): 1,
    ('_low_priv_allow_aces_in', 'not is_low_priv_trustee(ace.trustee_sid)'): 1,
    ('_low_priv_allow_aces_in', '(covers & rights) - blocked'): 1,
    ('_low_priv_allow_aces', 'return _low_priv_allow_aces_in(template.security, rights)'): 1,
    ('_low_priv_allow_aces', 'flow: return _low_priv_allow_aces_in(template.security, rights)'): 1,
    ('_low_priv_enrollers', 'return _low_priv_allow_aces(template, _ENROLL_RIGHTS)'): 1,
    ('_low_priv_enrollers', 'flow: return _low_priv_allow_aces(template, _ENROLL_RIGHTS)'): 1,
    ('_normalized_publishers', 'return tuple(sorted({name.strip() for name in template.published_by if name.strip()}))'): 1,
    ('_normalized_publishers', 'name.strip()'): 1,
    ('_template_publication_detail', "return 'Publication state: unknown (enrollment-services export absent or unevaluated).'"): 1,
    ('_template_publication_detail', 'flow: publishers = _normalized_publishers(template)'): 1,
    ('_template_publication_detail', "return f'Publication state: published by {publisher_list}.'"): 1,
    ('_template_publication_detail', "return 'Publication state: confirmed unpublished (not offered by any CA).'"): 1,
    ('_template_publication_detail', "bind: publisher_list = ', '.join(publishers)"): 1,
    ('_template_publication_detail', 'publishers'): 1,
    ('_template_publication_detail', 'publication_data_available'): 1,
    ('_scoped_writeproperty_guids', 'return guids'): 1,
    ('_scoped_writeproperty_guids', 'bind: guids: set[str] = set()'): 1,
    ('_scoped_writeproperty_guids', 'bind: token = r.strip().lower()'): 1,
    ('_scoped_writeproperty_guids', "bind: guid = token[len('writeproperty:'):]"): 1,
    ('_scoped_writeproperty_guids', 'bind: guids.add(guid)'): 1,
    ('_scoped_writeproperty_guids', 'bind: for r in rights'): 1,
    ('_scoped_writeproperty_guids', "not token.startswith('writeproperty:')"): 1,
    ('_scoped_writeproperty_guids', 'guid in _DANGEROUS_PROPERTY_GUIDS'): 1,
    ('_low_priv_dangerous_writeproperty_aces', 'return out'): 1,
    ('_low_priv_dangerous_writeproperty_aces', 'flow: dangerous = _scoped_writeproperty_guids(ace.rights)'): 1,
    ('_low_priv_dangerous_writeproperty_aces', 'flow: blocked = _blocked_scoped_writeproperty(security, ace.trustee_sid)'): 1,
    ('_low_priv_dangerous_writeproperty_aces', 'bind: out: list[tuple[AceEntry, set[str]]] = []'): 1,
    ('_low_priv_dangerous_writeproperty_aces', 'bind: for ace in security'): 1,
    ('_low_priv_dangerous_writeproperty_aces', 'bind: surviving = dangerous - blocked'): 1,
    ('_low_priv_dangerous_writeproperty_aces', 'bind: out.append((ace, surviving))'): 1,
    ('_low_priv_dangerous_writeproperty_aces', 'ace.ace_type is not AceType.ALLOW'): 1,
    ('_low_priv_dangerous_writeproperty_aces', 'not is_low_priv_trustee(ace.trustee_sid)'): 1,
    ('_low_priv_dangerous_writeproperty_aces', 'not dangerous'): 1,
    ('_low_priv_dangerous_writeproperty_aces', 'surviving'): 1,
    ('_blocked_scoped_writeproperty', 'return blocked'): 1,
    ('_blocked_scoped_writeproperty', "flow: if 'writepropertyall' in _blocked_rights(security, trustee_sid)"): 1,
    ('_blocked_scoped_writeproperty', 'bind: sid = normalize_sid(trustee_sid)'): 1,
    ('_blocked_scoped_writeproperty', 'bind: blocked: set[str] = set()'): 1,
    ('_blocked_scoped_writeproperty', 'bind: for ace in security'): 1,
    ('_blocked_scoped_writeproperty', 'bind: blocked |= _DANGEROUS_PROPERTY_GUIDS'): 2,
    ('_blocked_scoped_writeproperty', 'bind: token = r.strip().lower()'): 1,
    ('_blocked_scoped_writeproperty', "bind: guid = token[len('writeproperty:'):]"): 1,
    ('_blocked_scoped_writeproperty', 'bind: blocked.add(guid)'): 1,
    ('_blocked_scoped_writeproperty', 'bind: for r in ace.rights'): 1,
    ('_blocked_scoped_writeproperty', "'writepropertyall' in _blocked_rights(security, trustee_sid)"): 1,
    ('_blocked_scoped_writeproperty', 'ace.ace_type is not AceType.DENY'): 1,
    ('_blocked_scoped_writeproperty', 'normalize_sid(ace.trustee_sid) != sid'): 1,
    ('_blocked_scoped_writeproperty', "token == 'writepropertyall'"): 1,
    ('_blocked_scoped_writeproperty', "token.startswith('writeproperty:')"): 1,
    ('_blocked_scoped_writeproperty', 'guid in _DANGEROUS_PROPERTY_GUIDS'): 1,
    ('_template_container', "flow: if all((_pass_collected(estate, p) for p in ('templates', *extra_passes)))"): 1,
    ('_template_container', "all((_pass_collected(estate, p) for p in ('templates', *extra_passes)))"): 1,
    ('detect_esc1', 'flow: enrollers = _low_priv_enrollers(tmpl)'): 1,
    ('detect_esc1', 'flow: publication = _template_publication_detail(tmpl, publication_data_available=publication_data_available)'): 1,
    ('detect_esc1', 'flow: if not _can_authenticate(tmpl)'): 1,
    ('detect_esc1', 'flow: object_ref=_template_ref(tmpl)'): 1,
    ('detect_esc1', 'flow: subject=_template_subject(tmpl)'): 1,
    ('detect_esc1', 'not tmpl.name_flags & _ENROLLEE_SUPPLIES_SUBJECT'): 1,
    ('detect_esc1', 'not _can_authenticate(tmpl)'): 1,
    ('detect_esc1', '_MANAGER_APPROVAL in tmpl.enrollment_flags'): 1,
    ('detect_esc1', 'not enrollers'): 1,
    ('detect_esc2', 'flow: enrollers = _low_priv_enrollers(tmpl)'): 1,
    ('detect_esc2', 'flow: publication = _template_publication_detail(tmpl, publication_data_available=publication_data_available)'): 1,
    ('detect_esc2', 'flow: object_ref=_template_ref(tmpl)'): 1,
    ('detect_esc2', 'flow: subject=_template_subject(tmpl)'): 1,
    ('detect_esc2', 'bind: any_purpose = not tmpl.ekus or _ANY_PURPOSE in tmpl.ekus'): 1,
    ('detect_esc2', 'not any_purpose'): 1,
    ('detect_esc2', '_MANAGER_APPROVAL in tmpl.enrollment_flags'): 1,
    ('detect_esc2', 'not enrollers'): 1,
    ('detect_esc2', 'not tmpl.ekus'): 1,
    ('detect_esc3', 'flow: enrollers = _low_priv_enrollers(tmpl)'): 1,
    ('detect_esc3', 'flow: publication = _template_publication_detail(tmpl, publication_data_available=publication_data_available)'): 1,
    ('detect_esc3', 'flow: object_ref=_template_ref(tmpl)'): 1,
    ('detect_esc3', 'flow: subject=_template_subject(tmpl)'): 1,
    ('detect_esc3', '_ENROLLMENT_AGENT_EKU not in tmpl.ekus'): 1,
    ('detect_esc3', '_MANAGER_APPROVAL in tmpl.enrollment_flags'): 1,
    ('detect_esc3', 'not enrollers'): 1,
    ('detect_esc4', 'flow: controllers = _low_priv_allow_aces(tmpl, _DANGEROUS_TEMPLATE_CONTROL)'): 1,
    ('detect_esc4', 'flow: scoped = _low_priv_dangerous_writeproperty_aces(tmpl.security)'): 1,
    ('detect_esc4', 'flow: if _owner_captured(tmpl.owner_sid)'): 1,
    ('detect_esc4', 'flow: if _owner_captured(tmpl.owner_sid) and is_low_priv_trustee(tmpl.owner_sid)'): 1,
    ('detect_esc4', 'flow: object_ref=_template_ref(tmpl)'): 3,
    ('detect_esc4', 'flow: subject=_template_subject(tmpl)'): 3,
    ('detect_esc4', 'flow: source=_template_owner_source(tmpl)'): 1,
    ('detect_esc4', "flow: rights = ', '.join(sorted({r for a in controllers for r in a.rights if r.strip().lower() in _DANGEROUS_TEMPLATE_CONTROL and r.strip().lower() not in _blocked_rights(template_security, a.trustee_sid)}))"): 1,
    ('detect_esc4', 'bind: template_security = tmpl.security'): 1,
    ('detect_esc4', 'controllers'): 1,
    ('detect_esc4', 'scoped'): 1,
    ('detect_esc4', '_owner_captured(tmpl.owner_sid)'): 1,
    ('detect_esc4', '_owner_captured(tmpl.owner_sid) and is_low_priv_trustee(tmpl.owner_sid)'): 1,
    ('detect_esc4', 'r.strip().lower() in _DANGEROUS_TEMPLATE_CONTROL and r.strip().lower() not in _blocked_rights(template_security, a.trustee_sid)'): 1,
    ('detect_esc5', 'flow: if _owner_captured(obj.owner_sid)'): 1,
    ('detect_esc5', 'flow: controllers = _low_priv_allow_aces_in(obj.security, _DANGEROUS_OBJECT_CONTROL)'): 1,
    ('detect_esc5', 'flow: if _owner_captured(obj.owner_sid) and is_low_priv_trustee(obj.owner_sid)'): 1,
    ('detect_esc5', 'flow: object_ref=_pki_ref(obj)'): 2,
    ('detect_esc5', 'flow: subject=_pki_subject(obj)'): 2,
    ('detect_esc5', 'flow: source=_pki_owner_source(obj)'): 1,
    ('detect_esc5', "flow: rights = ', '.join(sorted({r for a in controllers for r in a.rights if r.strip().lower() in _DANGEROUS_OBJECT_CONTROL and r.strip().lower() not in _blocked_rights(obj.security, a.trustee_sid)}))"): 1,
    ('detect_esc5', '_owner_captured(obj.owner_sid)'): 1,
    ('detect_esc5', 'controllers'): 1,
    ('detect_esc5', '_owner_captured(obj.owner_sid) and is_low_priv_trustee(obj.owner_sid)'): 1,
    ('detect_esc5', 'r.strip().lower() in _DANGEROUS_OBJECT_CONTROL and r.strip().lower() not in _blocked_rights(obj.security, a.trustee_sid)'): 1,
    ('detect_esc7', 'flow: if _owner_captured(ca.owner_sid)'): 1,
    ('detect_esc7', 'flow: if not _ca_security_readable(ca)'): 1,
    ('detect_esc7', 'flow: blocked = _blocked_rights(ca.security, ace.trustee_sid)'): 1,
    ('detect_esc7', 'flow: if _owner_captured(ca.owner_sid) and is_low_priv_trustee(ca.owner_sid)'): 1,
    ('detect_esc7', 'flow: object_ref=_ca_ref(ca)'): 2,
    ('detect_esc7', 'flow: source=_ca_owner_source(ca)'): 1,
    ('detect_esc7', 'bind: by_trustee: dict[str, tuple[str, set[str]]] = {}'): 1,
    ('detect_esc7', 'bind: for ace in ca.security'): 1,
    ('detect_esc7', 'bind: for (sid, (name, rights)) in by_trustee.items()'): 1,
    ('detect_esc7', 'bind: manage: set[str] = set()'): 1,
    ('detect_esc7', 'bind: manage -= blocked'): 1,
    ('detect_esc7', 'bind: _, rights = by_trustee.setdefault(ace.trustee_sid, (ace.trustee_name, set()))'): 1,
    ('detect_esc7', 'bind: rights |= manage'): 1,
    ('detect_esc7', 'bind: manage |= _COVERS.get(token, frozenset({token})) & {_CA_MANAGE_CA, _CA_MANAGE_CERTS}'): 1,
    ('detect_esc7', 'bind: by_trustee.setdefault(ace.trustee_sid, (ace.trustee_name, set()))'): 1,
    ('detect_esc7', 'bind: token = r.strip().lower()'): 1,
    ('detect_esc7', 'bind: for r in ace.rights'): 1,
    ('detect_esc7', '_owner_captured(ca.owner_sid)'): 1,
    ('detect_esc7', 'not _ca_security_readable(ca)'): 1,
    ('detect_esc7', '_owner_captured(ca.owner_sid) and is_low_priv_trustee(ca.owner_sid)'): 1,
    ('detect_esc7', 'ace.ace_type is not AceType.ALLOW'): 1,
    ('detect_esc7', 'not is_low_priv_trustee(ace.trustee_sid)'): 1,
    ('detect_esc7', 'not manage'): 1,
    ('detect_esc7', '_CA_MANAGE_CA in rights'): 1,
    ('detect_esc8', 'flow: object_ref=_endpoint_ref(ep)'): 1,
    ('detect_esc8', "bind: http_open = 'http' in ep.transports and (not ep.ssl_required)"): 1,
    ('detect_esc8', 'bind: epa_required = ep.epa is EpaPolicy.REQUIRE'): 1,
    ('detect_esc8', "bind: explicit_ntlm = 'ntlm' in ep.auth_providers"): 1,
    ('detect_esc8', 'ep.kind not in _ESC8_KINDS'): 1,
    ('detect_esc8', 'not ep.windows_auth'): 1,
    ('detect_esc8', 'not ep.auth_providers & _NTLM_PROVIDERS'): 1,
    ('detect_esc8', 'epa_required and (not http_open)'): 1,
    ('detect_esc8', 'http_open'): 1,
    ('detect_esc8', 'not epa_required'): 1,
    ('detect_esc8', 'ep.epa is EpaPolicy.ALLOW'): 1,
    ('detect_esc8', 'http_open or explicit_ntlm'): 1,
    ('detect_esc8', 'ep.epa is EpaPolicy.NONE'): 1,
    ('detect_esc9', 'flow: enrollers = _low_priv_enrollers(tmpl)'): 1,
    ('detect_esc9', 'flow: object_ref=_template_ref(tmpl)'): 1,
    ('detect_esc9', 'flow: subject=_template_subject(tmpl)'): 1,
    ('detect_esc9', '_NO_SECURITY_EXTENSION not in tmpl.enrollment_flags'): 1,
    ('detect_esc9', '_MANAGER_APPROVAL in tmpl.enrollment_flags'): 1,
    ('detect_esc9', 'not enrollers'): 1,
    ('detect_esc16', 'flow: object_ref=_ca_ref(ca)'): 1,
    ('detect_esc16', 'ca.kind is CaKind.ROOT'): 1,
    ('detect_esc16', '_NTDS_CA_SECURITY_EXT in ca.disabled_extensions'): 1,
    ('_schannel_method_list', "return ', '.join(sorted((m.value for m in methods))) if methods else 'none'"): 1,
    ('_schannel_method_list', 'methods'): 1,
    ('_dcs_discovered', 'return bool(estate.dcs)'): 1,
    ('detect_esc10', 'flow: if not _dc_binding_known(dc)'): 1,
    ('detect_esc10', 'flow: object_ref=_dc_ref(dc)'): 2,
    ('detect_esc10', 'flow: {_schannel_method_list(dc.schannel_mapping_methods)}'): 1,
    ('detect_esc10', 'bind: binding = dc.strong_certificate_binding_enforcement'): 1,
    ('detect_esc10', 'bind: upn_mapping = SchannelMappingMethod.UPN in dc.schannel_mapping_methods'): 1,
    ('detect_esc10', 'bind: reasons: list[str] = []'): 1,
    ('detect_esc10', 'bind: reasons.append("Schannel CertificateMappingMethods enables UPN mapping (0x4), so a certificate carrying a victim\'s UPN in its SAN maps to that account")'): 1,
    ('detect_esc10', "bind: reasons.append('StrongCertificateBindingEnforcement is Disabled (0), so weak/implicit certificate mappings are accepted')"): 1,
    ('detect_esc10', 'upn_mapping'): 1,
    ('detect_esc10', 'binding == StrongCertBinding.DISABLED'): 1,
    ('detect_esc10', 'reasons'): 1,
    ('detect_esc10', 'binding == StrongCertBinding.PERMISSIVE'): 1,
    ('detect_esc10', 'not _dc_binding_known(dc)'): 1,
    ('_x509_mapping_form', 'return X509MappingForm.UNKNOWN'): 3,
    ('_x509_mapping_form', 'return X509MappingForm.SKI'): 1,
    ('_x509_mapping_form', 'return X509MappingForm.SHA1_PUBLIC_KEY'): 1,
    ('_x509_mapping_form', 'return X509MappingForm.RFC822'): 1,
    ('_x509_mapping_form', 'return X509MappingForm.PRINCIPAL_NAME'): 1,
    ('_x509_mapping_form', 'return X509MappingForm.SUBJECT_ONLY'): 1,
    ('_x509_mapping_form', 'return X509MappingForm.ISSUER_SERIAL'): 1,
    ('_x509_mapping_form', 'return X509MappingForm.ISSUER_SUBJECT'): 1,
    ('_x509_mapping_form', 'bind: text = mapping.strip()'): 1,
    ('_x509_mapping_form', 'bind: body = text.upper()'): 1,
    ('_x509_mapping_form', "not text.upper().startswith('X509:')"): 1,
    ('_x509_mapping_form', "'<SKI>' in body"): 1,
    ('_x509_mapping_form', "'<SHA1-PUKEY>' in body"): 1,
    ('_x509_mapping_form', "'<RFC822>' in body"): 1,
    ('_x509_mapping_form', "'<PN>' in body"): 1,
    ('_x509_mapping_form', "'<I>' in body"): 1,
    ('_x509_mapping_form', "'<S>' in body"): 2,
    ('_x509_mapping_form', "'<SR>' in body"): 1,
    ('detect_esc14', 'flow: non_strict_dcs = _non_strict_dcs(estate)'): 1,
    ('detect_esc14', 'flow: if not _esc14_enforcement_resolved(estate)'): 1,
    ('detect_esc14', 'flow: weak = [m for m in principal.mappings if _x509_mapping_form(m) in WEAK_X509_MAPPING_FORMS]'): 1,
    ('detect_esc14', 'flow: object_ref=_principal_ref(principal)'): 1,
    ('detect_esc14', 'bind: weak_principals: list[tuple[str, list[str], PrincipalMapping]] = []'): 1,
    ('detect_esc14', 'bind: for principal in estate.principal_mappings'): 1,
    ('detect_esc14', 'bind: for (dn, weak, principal) in sorted(weak_principals, key=lambda w: w[0])'): 1,
    ('detect_esc14', 'bind: weak_principals.append((principal.dn, weak, principal))'): 1,
    ('detect_esc14', 'bind: shown = weak[:3]'): 1,
    ('detect_esc14', 'not weak_principals'): 1,
    ('detect_esc14', 'not non_strict_dcs'): 1,
    ('detect_esc14', 'weak'): 1,
    ('detect_esc14', 'not _esc14_enforcement_resolved(estate)'): 1,
    ('detect_esc14', 'len(weak) > 3'): 1,
    ('detect_esc14', '_x509_mapping_form(m) in WEAK_X509_MAPPING_FORMS'): 1,
    ('detect_esc14', 'lambda lambda w: w[0]'): 1,
    ('detect_esc11', 'flow: object_ref=_ca_ref(ca)'): 1,
    ('detect_esc11', 'ca.kind is CaKind.ROOT'): 1,
    ('detect_esc11', '_ESC11_FLAG in ca.interface_flags'): 1,
    ('detect_esc13', 'flow: enrollers = _low_priv_enrollers(tmpl)'): 1,
    ('detect_esc13', 'flow: if not _can_authenticate(tmpl)'): 1,
    ('detect_esc13', 'flow: object_ref=_template_ref(tmpl)'): 1,
    ('detect_esc13', 'flow: subject=_template_subject(tmpl)'): 1,
    ('detect_esc13', 'bind: linked = [o for o in tmpl.issuance_policy_oids if o in policy_map]'): 1,
    ('detect_esc13', '_MANAGER_APPROVAL in tmpl.enrollment_flags'): 1,
    ('detect_esc13', 'not linked'): 1,
    ('detect_esc13', 'not _can_authenticate(tmpl)'): 1,
    ('detect_esc13', 'not enrollers'): 1,
    ('detect_esc13', 'o in policy_map'): 1,
    ('detect_esc13', 'len(linked) == 1'): 1,
    ('detect_esc15', 'flow: enrollers = _low_priv_enrollers(tmpl)'): 1,
    ('detect_esc15', 'flow: object_ref=_template_ref(tmpl)'): 1,
    ('detect_esc15', 'flow: subject=_template_subject(tmpl)'): 1,
    ('detect_esc15', 'patch_state is CaPatchState.PATCHED'): 1,
    ('detect_esc15', 'tmpl.schema_version != 1'): 1,
    ('detect_esc15', '_MANAGER_APPROVAL in tmpl.enrollment_flags'): 1,
    ('detect_esc15', 'not enrollers'): 1,
    ('detect_esc15', 'patch_state is CaPatchState.UNPATCHED'): 1,
    ('detect_infra_cert_expiry', 'flow: if _crl_window_readable(crl)'): 1,
    ('detect_infra_cert_expiry', 'flow: findings.extend(_expiry_finding(ca_name, cert, cert.not_after, now, warn_days))'): 1,
    ('detect_infra_cert_expiry', 'flow: if not _crl_next_update_readable(crl)'): 1,
    ('detect_infra_cert_expiry', 'flow: findings.extend(_crl_finding(crl, now))'): 1,
    ('detect_infra_cert_expiry', "flow: _evaluated('CRL_EXPIRY', _crl_ref(crl))"): 1,
    ('detect_infra_cert_expiry', 'bind: for crl in estate.crls'): 1,
    ('detect_infra_cert_expiry', 'not _crl_next_update_readable(crl)'): 1,
    ('detect_infra_cert_expiry', '_crl_window_readable(crl)'): 1,
    ('_expiry_finding', 'return [Finding(...)]'): 1,
    ('_expiry_finding', 'return []'): 1,
    ('_expiry_finding', 'flow: object_ref=_cert_ref(cert, ca_name)'): 1,
    ('_expiry_finding', 'bind: subject, kind = (cert.subject, cert.kind)'): 1,
    ('_expiry_finding', 'bind: days = (not_after - now).days'): 1,
    ('_expiry_finding', 'bind: root = kind == CertKind.ROOT_CA'): 1,
    ('_expiry_finding', 'bind: severity = Severity.CRITICAL'): 1,
    ('_expiry_finding', "bind: title = 'CA certificate has expired'"): 1,
    ('_expiry_finding', 'bind: severity = Severity.CRITICAL if root else Severity.HIGH'): 1,
    ('_expiry_finding', "bind: title = f'CA certificate expires in {days} day(s)'"): 1,
    ('_expiry_finding', 'not_after < now'): 1,
    ('_expiry_finding', 'days <= warn_days'): 1,
    ('_expiry_finding', 'root'): 3,
    ('_crl_horizon', "return f'{hours} hour(s)'"): 1,
    ('_crl_horizon', "return f'{remaining.days} day(s)'"): 1,
    ('_crl_horizon', 'bind: hours = int(remaining.total_seconds() // 3600)'): 1,
    ('_crl_horizon', 'remaining.days >= 1'): 1,
    ('_crl_finding', 'return []'): 2,
    ('_crl_finding', 'return [Finding(...)]'): 2,
    ('_crl_finding', 'flow: if _crl_window_readable(crl) and crl.this_update is not None'): 1,
    ('_crl_finding', 'flow: horizon = _crl_horizon(remaining)'): 1,
    ('_crl_finding', 'flow: object_ref=_crl_ref(crl)'): 2,
    ('_crl_finding', 'bind: next_update = crl.next_update'): 1,
    ('_crl_finding', 'bind: root = crl.tier == CrlTier.ROOT'): 1,
    ('_crl_finding', 'bind: window: timedelta | None = None'): 1,
    ('_crl_finding', 'bind: validity = next_update - crl.this_update'): 1,
    ('_crl_finding', 'bind: remaining = next_update - now'): 1,
    ('_crl_finding', 'bind: severity = Severity.CRITICAL if root else Severity.HIGH'): 1,
    ('_crl_finding', 'bind: window = validity * _CRL_EARLY_WARN_FRACTION'): 1,
    ('_crl_finding', 'bind: window = timedelta(days=1)'): 1,
    ('_crl_finding', 'next_update is None'): 1,
    ('_crl_finding', 'next_update < now'): 1,
    ('_crl_finding', '_crl_window_readable(crl) and crl.this_update is not None'): 1,
    ('_crl_finding', 'window is not None and next_update - now <= window'): 1,
    ('_crl_finding', 'validity.total_seconds() > 0'): 1,
    ('_crl_finding', 'window < timedelta(days=1) < validity'): 1,
    ('_crl_finding', 'root'): 3,
    ('detect_weak_signing', 'flow: object_ref=_cert_ref(cert, ca_name)'): 1,
    ('detect_weak_signing', 'bind: alg = cert.sig_alg.lower()'): 1,
    ('detect_weak_signing', "'md5' in alg"): 1,
    ('detect_weak_signing', "'sha1' in alg"): 1,
    ('_template_uses_ecdsa', 'return tmpl.min_key_size in (256, 384, 521)'): 1,
    ('_template_uses_ecdsa', 'return True'): 1,
    ('_template_uses_ecdsa', "'ecdsa' in tmpl.csp or 'ecdh' in tmpl.csp"): 1,
    ('detect_weak_key_size', 'flow: if _template_uses_ecdsa(tmpl)'): 1,
    ('detect_weak_key_size', 'flow: if not _template_key_size_captured(tmpl)'): 1,
    ('detect_weak_key_size', "flow: _evaluated('WEAK_TEMPLATE_KEY_SIZE', _template_ref(tmpl))"): 1,
    ('detect_weak_key_size', 'flow: object_ref=_template_ref(tmpl)'): 1,
    ('detect_weak_key_size', 'flow: subject=_template_subject(tmpl)'): 1,
    ('detect_weak_key_size', 'flow: object_ref=_cert_ref(cert, ca_name)'): 1,
    ('detect_weak_key_size', 'bind: for tmpl in estate.templates'): 1,
    ('detect_weak_key_size', 'bind: bits = tmpl.min_key_size'): 1,
    ('detect_weak_key_size', 'bind: bits = cert.key_bits'): 1,
    ('detect_weak_key_size', 'not _template_key_size_captured(tmpl)'): 1,
    ('detect_weak_key_size', 'bits is None or bits >= 2048'): 2,
    ('detect_weak_key_size', '_template_uses_ecdsa(tmpl)'): 1,
    ('detect_weak_key_size', 'bits < 1024'): 2,
    ('detect_weak_key_size', "cert.key_alg != 'rsa'"): 1,
    ('detect_weak_key_size', 'bits == 1024'): 2,
    ('detect_audit_config', "flow: _evaluated('CA_AUDIT_UNDERSCOPED', _ca_ref(ca))"): 1,
    ('detect_audit_config', 'flow: object_ref=_ca_ref(ca)'): 2,
    ('detect_audit_config', 'bind: missing = [name for bit, name in _AUDIT_CATEGORIES.items() if not ca.audit_filter & bit]'): 1,
    ('detect_audit_config', 'ca.audit_filter == 0'): 1,
    ('detect_audit_config', 'missing'): 1,
    ('detect_audit_config', 'not ca.audit_filter & bit'): 1,
    ('detect_orphaned_templates', 'flow: if _normalized_publishers(tmpl)'): 1,
    ('detect_orphaned_templates', 'flow: object_ref=_template_ref(tmpl)'): 1,
    ('detect_orphaned_templates', 'flow: subject=_template_subject(tmpl)'): 1,
    ('detect_orphaned_templates', '_normalized_publishers(tmpl)'): 1,
    ('detect_ocsp_absence', 'flow: object_ref=_cert_ref(cert, ca.name)'): 1,
    ('detect_ocsp_absence', 'bind: for cert in ca.certs'): 1,
    ('detect_ocsp_absence', 'ca.kind is CaKind.ROOT'): 1,
    ('detect_ocsp_absence', 'cert.ocsp_urls'): 1,
    ('detect_cdp_aia_absence', 'flow: object_ref=_cert_ref(cert, ca.name)'): 1,
    ('detect_cdp_aia_absence', 'bind: for cert in ca.certs'): 1,
    ('detect_cdp_aia_absence', 'bind: missing: list[str] = []'): 1,
    ('detect_cdp_aia_absence', 'bind: cdp_missing = not cert.cdp_urls'): 1,
    ('detect_cdp_aia_absence', 'bind: aia_missing = not cert.aia_urls'): 1,
    ('detect_cdp_aia_absence', "bind: missing.append('CRL Distribution Points')"): 1,
    ('detect_cdp_aia_absence', "bind: missing.append('Authority Information Access (CA Issuers)')"): 1,
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
ESC6_BODY = '    findings: list[Finding] = []\n    if _pass_collected(estate, "ca-config"):\n        _container_evaluated(estate, "ESC6", "ca")\n'


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
    # helper and pins its evidence flows, so dropping its worker call is caught
    # (variants that keep the call: tests/test_reviewer_probes_r3.py).
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
