"""Plain-language consequences catalogue.

Pure data mapping each detector check identifier to a non-technical summary,
business risk, and remediation. Used by the display and report layers; no AI.

Also hosts :func:`finding_with_consequence`, the single serialization of a
finding + its catalogue entry shared by the JSON/diff renderers (display.py)
and the narration layer (narration.py) so the two can never drift (WI-043).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from adcs_lens.detection import Finding


@dataclass(frozen=True)
class ConsequenceEntry:
    """Plain-language explanation of one finding type."""

    check: str
    summary: str
    consequence: str
    remediation: str


CONSEQUENCES: dict[str, ConsequenceEntry] = {
    "ESC1": ConsequenceEntry(
        check="ESC1",
        summary=(
            "A certificate template lets ordinary users choose the name on the certificate "
            "and enroll without manager approval."
        ),
        consequence=(
            "An attacker can request a certificate that names a privileged account such as a "
            "domain administrator, then use it to authenticate as that account and take control "
            "of the domain."
        ),
        remediation=(
            "Disable the 'enrollee supplies subject' setting on the template, require CA manager "
            "approval for enrollments, and restrict Enroll rights to only approved groups."
        ),
    ),
    "ESC2": ConsequenceEntry(
        check="ESC2",
        summary=(
            "A certificate template has no usage restrictions (no EKU or an any-purpose EKU) "
            "and is enrollable by ordinary users."
        ),
        consequence=(
            "An attacker obtains a certificate in their own name that is valid for any purpose, "
            "including client authentication — a credential usable far beyond what the template "
            "should have authorized."
        ),
        remediation=(
            "Limit the template to the specific certificate usages it actually needs, and "
            "restrict Enroll rights to approved groups."
        ),
    ),
    "ESC3": ConsequenceEntry(
        check="ESC3",
        summary=(
            "A certificate template grants the Enrollment Agent right and is enrollable by "
            "ordinary users."
        ),
        consequence=(
            "An attacker can request certificates on behalf of other principals, including "
            "higher-privilege accounts, without needing their credentials."
        ),
        remediation=(
            "Restrict Enrollment Agent templates to tightly controlled groups and require CA "
            "manager approval for enrollments."
        ),
    ),
    "ESC4": ConsequenceEntry(
        check="ESC4",
        summary="An ordinary user has edit control over a certificate template object.",
        consequence=(
            "An attacker can change the template settings to create an ESC1 path, for example by "
            "allowing enrollee-supplied names and adding a client-authentication EKU, then "
            "request a domain-admin certificate."
        ),
        remediation=(
            "Remove delegated write, modify, or change-permissions rights from low-privilege "
            "users on certificate templates, and reset ownership to a privileged account when a "
            "low-privilege principal owns the template."
        ),
    ),
    "ESC5": ConsequenceEntry(
        check="ESC5",
        summary=(
            "An ordinary user can modify a critical Public Key Services object, or the CA "
            "server's computer object, in Active Directory."
        ),
        consequence=(
            "Depending on which object is writable, an attacker can make a rogue certificate "
            "authority trusted estate-wide (NTAuth), alter a CA's published templates and "
            "enrollment configuration (CA object), create rogue child objects such as a malicious "
            "template (Public Key Services container), tamper with certificate chain and "
            "revocation data (AIA / CDP), or take over the CA server itself and its signing "
            "key (the CA server's computer object)."
        ),
        remediation=(
            "Remove delegated control over NTAuthCertificates, CA objects, the Public Key "
            "Services, AIA, and CDP containers, and the CA server's computer object, and reset "
            "ownership to a privileged account when a low-privilege principal owns the object."
        ),
    ),
    "ESC6": ConsequenceEntry(
        check="ESC6",
        summary=(
            "A certificate authority is configured to honor subject names supplied by "
            "the requester."
        ),
        consequence=(
            "An attacker can put any identity, such as a domain administrator, into a certificate "
            "request on any template the CA issues, and then authenticate as that identity."
        ),
        remediation=(
            "Remove the EDITF_ATTRIBUTESUBJECTALTNAME2 flag from the CA policy registry and "
            "restart the certificate service."
        ),
    ),
    "ESC7": ConsequenceEntry(
        check="ESC7",
        summary=(
            "A low-privilege principal holds CA manager or certificate-officer rights on a CA, "
            "or owns the CA security descriptor."
        ),
        consequence=(
            "With Manage Certificates, the holder can approve pending requests and issue "
            "attacker-chosen certificates. With Manage CA, they can additionally change CA policy "
            "to enable other escalation paths, such as requester-supplied SANs. A low-privilege "
            "owner of the CA security descriptor can rewrite it to grant itself either role."
        ),
        remediation=(
            "Remove non-administrative principals from the Manage CA and Manage Certificates "
            "roles on certificate authorities, and reset CA security descriptor ownership to a "
            "privileged account when a low-privilege principal is the owner."
        ),
    ),
    "ESC8": ConsequenceEntry(
        check="ESC8",
        summary=(
            "A web-based enrollment endpoint accepts NTLM authentication without channel "
            "binding."
        ),
        consequence=(
            "This is the configuration an NTLM-relay attack requires: if an attacker can coerce a "
            "privileged account to authenticate here, they could relay that authentication and "
            "obtain a certificate as that account. The relay itself is not confirmed by this "
            "read-only check."
        ),
        remediation=(
            "Require HTTPS-only access, enforce Extended Protection for Authentication, and "
            "disable or restrict NTLM on enrollment endpoints."
        ),
    ),
    "ESC9": ConsequenceEntry(
        check="ESC9",
        summary="A certificate template issues certificates that omit the SID security extension.",
        consequence=(
            "Without the SID binding, a certificate can be mapped to a different account on a "
            "domain controller that does not enforce strong certificate binding, enabling "
            "impersonation of privileged accounts."
        ),
        remediation=(
            "Clear the NO_SECURITY_EXTENSION flag on the template unless a specific, approved "
            "mapping scenario explicitly requires it."
        ),
    ),
    "ESC10": ConsequenceEntry(
        check="ESC10",
        summary="A domain controller is configured to accept weak certificate-to-account mappings.",
        consequence=(
            "An attacker who can obtain or influence the matching field, such as a user principal "
            "name, can authenticate as another account using a certificate."
        ),
        remediation=(
            "Set StrongCertificateBindingEnforcement to 2 (Full) on every domain controller and "
            "clear the UPN mapping bit from Schannel CertificateMappingMethods."
        ),
    ),
    "ESC11": ConsequenceEntry(
        check="ESC11",
        summary=(
            "A certificate authority's RPC enrollment interface does not require encrypted "
            "requests."
        ),
        consequence=(
            "This is the configuration an NTLM-relay attack against the RPC enrollment interface "
            "requires: if an attacker can coerce a privileged account to authenticate, they could "
            "relay that authentication and request a certificate as that account. The relay itself "
            "is not confirmed by this read-only check."
        ),
        remediation=(
            "Enable the IF_ENFORCEENCRYPTICERTREQUEST flag on every non-root CA and restart the "
            "certificate service."
        ),
    ),
    "ESC13": ConsequenceEntry(
        check="ESC13",
        summary=(
            "A certificate template links an issuance policy to a privileged group and is "
            "enrollable by ordinary users."
        ),
        consequence=(
            "Authenticating with the issued certificate grants the holder the membership and "
            "privileges of the linked group, which may be domain-wide administrators."
        ),
        remediation=(
            "Remove the OID-to-group link on the issuance policy, restrict Enroll rights, or "
            "require CA manager approval on the template."
        ),
    ),
    "ESC14": ConsequenceEntry(
        check="ESC14",
        summary=(
            "An account has an explicit weak certificate mapping that can be reproduced by an "
            "attacker."
        ),
        consequence=(
            "An attacker who obtains a certificate matching the reusable mapping fields can "
            "authenticate as the mapped account, including privileged service accounts."
        ),
        remediation=(
            "Replace weak altSecurityIdentities mappings with strong, non-reusable forms such as "
            "issuer plus serial number, SKI, or SHA1 public-key hash, and enforce strong binding."
        ),
    ),
    "ESC15": ConsequenceEntry(
        check="ESC15",
        summary="An old schema version 1 certificate template is enrollable by ordinary users.",
        consequence=(
            "On a certificate authority that is not patched for CVE-2024-49019, the requester can "
            "inject arbitrary certificate usages such as Client Authentication into the request, "
            "turning the template into an ESC1 or ESC3 escalation path. When CA patch state is "
            "unknown the finding is reported at a reduced severity with a caveat to confirm the "
            "patch; on a known-patched CA the EKUwu path is closed."
        ),
        remediation=(
            "Confirm the CA is patched for CVE-2024-49019, upgrade the template to schema "
            "version 2 or later, and restrict Enroll rights."
        ),
    ),
    "ESC16": ConsequenceEntry(
        check="ESC16",
        summary=(
            "The certificate authority is configured to omit the SID security extension from "
            "every certificate it issues."
        ),
        consequence=(
            "Without the SID binding, certificates from this CA can be mapped to different "
            "accounts on a domain controller that does not enforce strong certificate binding, "
            "enabling impersonation of privileged accounts across the whole CA."
        ),
        remediation=(
            "Remove szOID_NTDS_CA_SECURITY_EXT from the CA's DisableExtensionList policy "
            "setting and restart the certificate service, unless the CA intentionally "
            "issues certificates for a non-AD mapping scenario."
        ),
    ),
    "CA_CERT_EXPIRY": ConsequenceEntry(
        check="CA_CERT_EXPIRY",
        summary="A certificate authority certificate has expired or is about to expire.",
        consequence=(
            "Expired or soon-to-expire CA certificates cause certificate validation failures, "
            "breaking authentication, signing, and applications that rely on the PKI."
        ),
        remediation=(
            "Renew the CA certificate before expiry and update distribution points; treat root-CA "
            "renewal as an estate-wide change-control event."
        ),
    ),
    "CRL_EXPIRY": ConsequenceEntry(
        check="CRL_EXPIRY",
        summary=(
            "A published certificate revocation list has passed, or is approaching, "
            "its next update time."
        ),
        consequence=(
            "Once a CRL passes nextUpdate, clients that fetch it reject certificates "
            "issued by the CA, causing widespread authentication and service outages "
            "until a fresh CRL is published. A CRL approaching nextUpdate should be "
            "refreshed proactively, because the window closes silently — a root-tier "
            "CRL expiry is a silent estate-wide failure because its offline signer is "
            "not watched."
        ),
        remediation=(
            "Publish a fresh CRL before nextUpdate, then verify CRL distribution points "
            "are reachable and that publication is scheduled and monitored."
        ),
    ),
    "TEMPLATE_ACL_UNREADABLE": ConsequenceEntry(
        check="TEMPLATE_ACL_UNREADABLE",
        summary="The export could not read the access-control list for one certificate template.",
        consequence=(
            "The tool cannot determine whether this template has dangerous enroll or control "
            "rights, so associated ESC risks remain unverified and could be hidden."
        ),
        remediation=(
            "Re-run the collector with permissions sufficient to read each certificate template's "
            "nTSecurityDescriptor."
        ),
    ),
    "TEMPLATE_ACL_NOT_EVALUATED": ConsequenceEntry(
        check="TEMPLATE_ACL_NOT_EVALUATED",
        summary="Template security descriptors were not collected in this export.",
        consequence=(
            "The tool cannot rule out ESC1, ESC2, ESC3, ESC4, ESC9, ESC13, or ESC15 on any "
            "template, so the posture for template-based escalation is unverified."
        ),
        remediation=(
            "Re-run the collector with the template-security pass enabled to capture template "
            "access-control entries."
        ),
    ),
    "PKI_ACL_NOT_EVALUATED": ConsequenceEntry(
        check="PKI_ACL_NOT_EVALUATED",
        summary="Public Key Services object permissions were not collected in this export.",
        consequence=(
            "The tool cannot rule out ESC5, including writable NTAuth certificates, CA objects, or "
            "PKS containers, so the posture for trust-tampering is unverified."
        ),
        remediation=(
            "Re-run the collector with the pki-acls pass enabled to capture PKI object "
            "access-control entries."
        ),
    ),
    "CA_SECURITY_NOT_EVALUATED": ConsequenceEntry(
        check="CA_SECURITY_NOT_EVALUATED",
        summary="The CA security descriptor and role rights were not collected in this export.",
        consequence=(
            "The tool cannot rule out ESC7, so it is unverified whether low-privilege principals "
            "hold Manage CA or Manage Certificates rights."
        ),
        remediation=(
            "Re-run the collector with the ca-security pass enabled to capture CA\\Security "
            "access-control entries."
        ),
    ),
    "ENROLLMENT_ENDPOINTS_NOT_EVALUATED": ConsequenceEntry(
        check="ENROLLMENT_ENDPOINTS_NOT_EVALUATED",
        summary=(
            "IIS enrollment endpoint configuration was not collected, or not collected on "
            "every CA host, in this export."
        ),
        consequence=(
            "The tool cannot rule out ESC8, so it is unverified whether web or CES enrollment "
            "endpoints are exposed to NTLM relay on the hosts it did not inspect."
        ),
        remediation=(
            "Re-run the collector on each CA host with the enrollment-endpoints pass enabled "
            "to capture IIS bindings, authentication providers, and Extended Protection "
            "settings."
        ),
    ),
    "DC_REGISTRY_NOT_EVALUATED": ConsequenceEntry(
        check="DC_REGISTRY_NOT_EVALUATED",
        summary=(
            "Domain-controller certificate-mapping registry values were not collected in this "
            "export."
        ),
        consequence=(
            "The tool cannot rule out ESC10, so it is unverified whether domain controllers accept "
            "weak certificate mappings."
        ),
        remediation=(
            "Re-run the collector with the esc10-dc-registry pass enabled to capture "
            "StrongCertificateBindingEnforcement and Schannel CertificateMappingMethods."
        ),
    ),
    "ALTSECID_NOT_EVALUATED": ConsequenceEntry(
        check="ALTSECID_NOT_EVALUATED",
        summary="Principal altSecurityIdentities mappings were not collected in this export.",
        consequence=(
            "The tool cannot rule out ESC14, so it is unverified whether any accounts have weak "
            "explicit certificate mappings."
        ),
        remediation=(
            "Re-run the collector with the esc14-altsecid pass enabled to capture principal "
            "altSecurityIdentities values."
        ),
    ),
    "ESC10_ENFORCEMENT_UNKNOWN": ConsequenceEntry(
        check="ESC10_ENFORCEMENT_UNKNOWN",
        summary=(
            "The domain controller's strong certificate binding enforcement could not be "
            "confirmed."
        ),
        consequence=(
            "Without confirming the registry value, the tool cannot rule out the ESC10 case 2 "
            "weak-mapping path; the actual posture may be stricter or weaker than expected."
        ),
        remediation=(
            "Set StrongCertificateBindingEnforcement to 2 (Full) explicitly and re-collect the DC "
            "registry values."
        ),
    ),
    "ESC14_ENFORCEMENT_UNKNOWN": ConsequenceEntry(
        check="ESC14_ENFORCEMENT_UNKNOWN",
        summary=(
            "Weak explicit certificate mappings exist, but domain-controller enforcement is "
            "unknown."
        ),
        consequence=(
            "The weak mappings are present, yet the tool cannot determine whether domain "
            "controllers enforce strong binding, so ESC14 exploitability is uncertain."
        ),
        remediation=(
            "Confirm DC registry collection succeeds, set StrongCertificateBindingEnforcement to "
            "2 (Full), and replace weak mappings with strong forms."
        ),
    ),
    "WEAK_SIG_ALG": ConsequenceEntry(
        check="WEAK_SIG_ALG",
        summary="A certificate authority certificate is signed with SHA-1 or MD5.",
        consequence=(
            "Cryptographic collision attacks against SHA-1 and MD5 are practical, so an attacker "
            "who can craft a collision could forge a certificate that chains to the CA."
        ),
        remediation=(
            "Reissue the CA certificate and all chain certificates using SHA-256 or stronger, and "
            "configure the CA to issue only with modern signature algorithms."
        ),
    ),
    "WEAK_KEY_SIZE": ConsequenceEntry(
        check="WEAK_KEY_SIZE",
        summary="A certificate authority certificate uses an RSA key shorter than 2048 bits.",
        consequence=(
            "Smaller RSA keys are increasingly factorable, so an attacker who recovers the CA or "
            "sub-CA private key can issue fraudulent certificates that clients trust."
        ),
        remediation=(
            "Reissue the CA certificate with a 2048-bit or larger RSA key (4096-bit preferred for "
            "root and long-lived certificates)."
        ),
    ),
    "WEAK_TEMPLATE_KEY_SIZE": ConsequenceEntry(
        check="WEAK_TEMPLATE_KEY_SIZE",
        summary="A certificate template allows requests with RSA keys shorter than 2048 bits.",
        consequence=(
            "Certificates issued from this template may carry short, weak keys that are easier "
            "to factor, undermining the confidentiality or integrity the certificate protects."
        ),
        remediation=(
            "Set the template's msPKI-Minimal-Key-Size to 2048 or higher so only acceptably "
            "strong keys can be requested."
        ),
    ),
    "CA_AUDIT_DISABLED": ConsequenceEntry(
        check="CA_AUDIT_DISABLED",
        summary="Certificate authority auditing is fully disabled (AuditFilter is 0).",
        consequence=(
            "No CA security events are written to the log, so malicious issuance, policy changes, "
            "or CA stop/start activity cannot be detected or investigated."
        ),
        remediation=(
            "Enable the full audit baseline: certutil -setreg CA\\AuditFilter 127, then restart "
            "the certificate service."
        ),
    ),
    "CA_AUDIT_UNDERSCOPED": ConsequenceEntry(
        check="CA_AUDIT_UNDERSCOPED",
        summary="Certificate authority auditing is enabled but missing event categories.",
        consequence=(
            "Gaps in the audit filter mean important CA events such as certificate issuance, "
            "revocation, backup, or configuration changes are not recorded, delaying incident "
            "detection."
        ),
        remediation=(
            "Enable the full audit baseline: certutil -setreg CA\\AuditFilter 127, then restart "
            "the certificate service."
        ),
    ),
    "CA_AUDIT_NOT_EVALUATED": ConsequenceEntry(
        check="CA_AUDIT_NOT_EVALUATED",
        summary="The export did not include certificate authority audit filter settings.",
        consequence=(
            "The tool cannot determine whether CA auditing is disabled or under-scoped, so audit "
            "configuration weaknesses may be hidden."
        ),
        remediation=(
            "Re-run the collector with the CA registry pass enabled to capture CA\\AuditFilter, "
            "then review and enforce the recommended baseline of 127."
        ),
    ),
    "LIFECYCLE_NOT_EVALUATED": ConsequenceEntry(
        check="LIFECYCLE_NOT_EVALUATED",
        summary="No certificate or CRL data was parsed from this export.",
        consequence=(
            "The tool cannot detect expired or soon-to-expire CA certificates and CRLs, so "
            "lifecycle failures are hidden for this run."
        ),
        remediation=(
            "Re-run collector 0.8.0 or newer (it captures the published CA certificates and "
            "CRLs from AD), and install the optional certificates extra "
            "(pip install adcs-lens[certs]) so adcs-lens can parse them."
        ),
    ),
    "CA_REGISTRY_NOT_EVALUATED": ConsequenceEntry(
        check="CA_REGISTRY_NOT_EVALUATED",
        summary=(
            "A certificate authority's registry configuration was not collected because the "
            "collector ran on a different host."
        ),
        consequence=(
            "The CA registry checks (requester-supplied SANs, RPC encryption enforcement, "
            "disabled extensions, CA role permissions) were skipped for this CA, so "
            "weaknesses there are hidden."
        ),
        remediation=(
            "Re-run the collector on each certificate authority (or on the named CA) so its "
            "local registry hives are captured."
        ),
    ),
    "EXPORT_STALE": ConsequenceEntry(
        check="EXPORT_STALE",
        summary="The export is older than the configured staleness threshold.",
        consequence=(
            "Findings describe the estate as it was when the export was collected; changes "
            "since then (new templates, altered permissions, renewed or expired certificates) "
            "are not reflected. Export age is collection age only if the collector host's "
            "clock was right."
        ),
        remediation=(
            "Re-run the collector and analyse the fresh export, or raise "
            "ADCS_LENS_STALE_EXPORT_DAYS if a longer collection cadence is intended."
        ),
    ),
    "EXPORT_TIMESTAMP_INVALID": ConsequenceEntry(
        check="EXPORT_TIMESTAMP_INVALID",
        summary="The export's collection time is missing, unparseable, or in the future.",
        consequence=(
            "The export's age cannot be determined, so it may describe an estate that has "
            "since changed, and a future timestamp means a clock on the collector or "
            "analysis host is wrong."
        ),
        remediation=(
            "Check the collector host's clock and re-run the collector; do not edit "
            "collected_at by hand."
        ),
    ),
    "COLLECTOR_VERSION_UNVERIFIED": ConsequenceEntry(
        check="COLLECTOR_VERSION_UNVERIFIED",
        summary=(
            "The export's collector version is missing, unknown, or older than the minimum "
            "adcs-lens expects."
        ),
        consequence=(
            "An older or unidentified collector may omit fields whose absence reads as "
            "'collected' (template and PKI-object DACL markers, per-CA registry markers, "
            "owners), so a clean result on this export is not proof of a clean estate, and "
            "drift against it cannot confirm any fix."
        ),
        remediation=(
            "Re-run the current collector (scripts/Export-AdcsEstate.ps1) and analyse that "
            "export instead."
        ),
    ),
    "PASS_NOT_COLLECTED": ConsequenceEntry(
        check="PASS_NOT_COLLECTED",
        summary="A collector pass's data is absent from this export.",
        consequence=(
            "Every check that depends on the named pass was not evaluated, so weaknesses it "
            "would reveal are hidden for this run, and drift cannot confirm their resolution."
        ),
        remediation=(
            "Re-run the collector and copy the complete export directory, including every "
            "JSON file the manifest does not list as skipped."
        ),
    ),
    "PKI_ACL_UNREADABLE": ConsequenceEntry(
        check="PKI_ACL_UNREADABLE",
        summary="A Public Key Services object's security descriptor could not be read.",
        consequence=(
            "The tool cannot tell whether a low-privilege principal controls this object, so "
            "a writable-ACL escalation path (ESC5) may be hidden."
        ),
        remediation=(
            "Re-collect with an account that has read access to the named object's "
            "nTSecurityDescriptor."
        ),
    ),
    "CA_HOST_ACCOUNT_UNRESOLVED": ConsequenceEntry(
        check="CA_HOST_ACCOUNT_UNRESOLVED",
        summary=(
            "The computer account of the CA host an enrollment service names could not "
            "be resolved."
        ),
        consequence=(
            "AD CS setup grants that account control of its own enrollment-service object, so "
            "without its SID the tool cannot tell that grant from a delegated one: ESC5 on the "
            "object is undecided when a low-privilege trustee controls or owns it."
        ),
        remediation=(
            "Re-run the collector from the CA host's domain, and check that the enrollment "
            "service's dNSHostName matches the CA computer object's dNSHostName exactly."
        ),
    ),
    "ACL_GROUP_TOKEN_CAVEAT": ConsequenceEntry(
        check="ACL_GROUP_TOKEN_CAVEAT",
        summary=(
            "Access-control findings match ACEs by trustee SID, do not expand group "
            "membership, and classify trustees by a high-privilege allowlist."
        ),
        consequence=(
            "A Deny on a group that contains the requester, or Enroll and control rights held only "
            "through nested group membership, are not modeled — so a 'no finding' result is not "
            "by itself proof that no access-control escalation path exists. In the other "
            "direction, any trustee outside the known high-privilege set (custom groups, named "
            "accounts) is treated as low-privilege, so a custom privileged group may produce a "
            "finding that is really noise."
        ),
        remediation=(
            "When an ACL conclusion is load-bearing, confirm it directly in Active Directory with "
            "the requester's full group token expanded, and review findings whose trustee is a "
            "custom group to confirm whether it is genuinely low-privilege."
        ),
    ),
    "ORPHANED_TEMPLATE": ConsequenceEntry(
        check="ORPHANED_TEMPLATE",
        summary="A certificate template exists in AD but no CA offers it for enrollment.",
        consequence=(
            "The template is not directly exploitable, but it expands the attack surface and "
            "signals hygiene drift. A CA operator can publish it at any time, potentially "
            "exposing a vulnerable configuration that was thought to be retired."
        ),
        remediation=(
            "Remove the template if it is no longer needed, or publish it under the intended CA "
            "and review its configuration."
        ),
    ),
    "OCSP_URL_ABSENT": ConsequenceEntry(
        check="OCSP_URL_ABSENT",
        summary="An issuing CA certificate carries no OCSP responder URL in its AIA extension.",
        consequence=(
            "OCSP-based revocation checking is not available for certificates issued by this CA. "
            "Clients fall back to CRL fetching, which may not be feasible if CRL distribution is "
            "also misconfigured. This is a posture note, not a vulnerability — many CAs use "
            "only CRL."
        ),
        remediation=(
            "Add an OCSP responder URL to the CA certificate's AIA extension if the CA should "
            "support OCSP-based revocation, or confirm that CRL-based revocation is sufficient."
        ),
    ),
    "CDP_AIA_ABSENT": ConsequenceEntry(
        check="CDP_AIA_ABSENT",
        summary=(
            "An issuing CA certificate lacks CRL Distribution Point or AIA extension URLs."
        ),
        consequence=(
            "Clients that cannot fetch a CRL have no revocation path and will reject the chain "
            "or silently skip revocation checking. Without an AIA URL, clients cannot build the "
            "certificate chain to the issuer. Both undermine the PKI's reliability."
        ),
        remediation=(
            "Publish CDP and AIA URLs on the CA certificate and reissue if necessary, then verify "
            "the URLs are reachable from client systems."
        ),
    ),
}


def consequence_for(check: str) -> ConsequenceEntry | None:
    """Return the plain-language entry for *check*, or None if unknown."""
    return CONSEQUENCES.get(check)


def finding_with_consequence(f: Finding) -> dict[str, object]:
    """Serialize a finding with its plain-language consequence attached.

    The one implementation of the finding+consequence JSON shape, shared by
    display.py (the doctor/diff JSON envelopes) and narration.py (the LLM
    context payload). ``consequence`` is ``None`` for a check with no catalogue
    entry. (WI-043: previously duplicated between display and narration.)
    """
    data: dict[str, object] = dict(asdict(f))
    entry = consequence_for(f.check)
    if entry is None:
        data["consequence"] = None
    else:
        data["consequence"] = {
            "summary": entry.summary,
            "consequence": entry.consequence,
            "remediation": entry.remediation,
        }
    return data
