# Live validation plan (collector 0.11.0 and the core)

> **Run 2026-10-13 (collector 0.11.0, fbdd447): done.** The results are in
> CHANGELOG `[Unreleased]` -> Validated. Where the run showed this plan was
> wrong, the plan is corrected in place below (marked **Corrected after the
> 2026-10-13 run**). The defects it found are fixed in collector 0.12.0; the
> cases that must be re-checked live on that collector are listed in
> [Re-checks for collector 0.12.0](#re-checks-for-collector-0120).
>
> **Re-check 2026-10-14/15 (collector 0.12.0, a20fe36): done.** Every re-check
> row passed, and **the endpoint fix is proven live** (the Phase 1 endpoints row
> and D3). Two rows are corrected in place (marked **Corrected after the
> 2026-10-14 re-check**): the version-gap exit code, and the B3 baseline. The
> results are in CHANGELOG `[Unreleased]` -> Validated.

**Purpose.** WI-044 validated the 0.10.0 LDAP layer from a domain member that
is not a CA. Its first contact with real data found four defects that fixtures
had hidden (CHANGELOG, Unreleased → Validated). This plan covers what that run
could not reach. It also tests the thing reviews cannot: whether each detector
fires on a real misconfiguration, and stops firing when the misconfiguration is
removed.

**Who runs it.** An operator or an agent with lab access. Run the phases in
order; each phase stands alone, so stop after any of them and report. Phase 3 changes
the estate on purpose. Phases 0–2 and 4 are read-only.

**Placeholders.** Write results with placeholders only. Real names, SIDs and raw
exports stay outside the repository, as AGENTS.md requires. Use these:

| Placeholder | Meaning |
|---|---|
| `<CA-HOST>` | The enterprise issuing CA server |
| `<MEMBER>` | A domain-joined non-CA server |
| `<DC1>` | A domain controller |
| `WORK-DOMAIN.local` | The domain |
| `LABCA` | The CA name |

## Rules for every phase

- **Version.** Run the collector at the commit under test. That is collector
  0.11.0: branch `fix/wi-044-defects`, or main once it merges. Record
  `git rev-parse HEAD` and the export's `collector_version` in every result.
- **Evidence location.** Store each export under an evidence directory outside
  the repository, readable only by the operator: on the controller,
  `/home/itadmin/adcs-lens-evidence/<date>/<phase>-<case>/`. Never commit an
  export.
- **Analysis.** Run `adcs-lens ingest`, `doctor --json` and, where stated,
  `diff --exit-code` against every export. Keep the JSON.
- **Comparing results.** "Expected" below is stated as a security condition.
  Where the detector's documented definition differs from that condition, a
  mismatch is still a finding. Note the detector's rule, not just pass or fail,
  so the difference can be triaged. A detector that is right for the wrong
  reason, or a note that reads "clean" where it should read "not evaluated", is
  a defect.
- **No delegation workarounds.** Never configure Kerberos delegation to get
  around the SSH double-hop. Use a console or RDP logon, a scheduled task under
  the intended principal, or the collector's explicit-credential parameters.

## Phase 0: baseline and read-only proof (read-only)

Prove the collector changes nothing, on the host where it has the most reach.

1. **Snapshot before the run.**
   - Export the CA registry: `reg export HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration`.
   - Record `certutil -getreg CA\*` output.
   - Record the CA database row count. **Corrected after the 2026-10-13
     run:** the earlier shape, `certutil -view -restrict "RequestID>0" -out
     RequestID csv | measure`, did not give a usable count (the operator
     recorded 0 before the run and re-counted with a parser): certutil's CSV
     output is a header line followed by one quoted value per request, not a
     number. Count the data rows explicitly, for example
     `(certutil -view -restrict "RequestID>0" -out RequestID csv | Select-Object -Skip 1 | Where-Object { $_.Trim() }).Count`,
     and check the number against the CA console once.
   - In LDAP, record `uSNChanged` and `whenChanged` for every object under
     `CN=Public Key Services,CN=Services,CN=Configuration,...` and for the CA's
     computer object.
   - Record the highest committed USN on `<DC1>`.
2. **Enable auditing for the run.** This step changes configuration on purpose,
   before the collector runs, so that a write by the collector would leave a
   record.
   - On the DCs, turn on the Directory Service Changes subcategory (event 5136).
   - On `<CA-HOST>`, turn on the Certification Services subcategory and set CA
     auditing (AuditFilter 127), then restart CertSvc.
   - Note the original values; Phase 3 and cleanup need them.
3. **Run the collector on `<CA-HOST>`** as a domain administrator, from a console
   or RDP session, using `-OutDir`. Run it again with `-CollectDcMapping`, and
   with DC registry credentials if `<CA-HOST>` cannot read the DC registry with
   its own token.
4. **Check after the run.**
   - Repeat step 1 and diff the snapshots.
   - Check the Security log on the DCs for 5136 events in the run window.
   - Check the Security log on `<CA-HOST>` for Certification Services events
     in the run window, for example 4885 (audit filter changed) or 4892
     (property changed). The audit setup in step 2 produces its own events
     before the run; attribute them.

**Expected:**
- Every snapshot is identical.
- There is no 5136 event from the collector's principal and no CA
  configuration-change event.
- The highest committed USN may advance for unrelated reasons, so attribute
  any change.

**Report:** the diff of the snapshots (empty is the pass), and any audit event
in the window.

This phase's two exports are the reference exports ("CA-host reference") for
later phases.

## Phase 1: the local-CA path (read-only)

Everything WI-044 left "not live-validated", on the CA-host reference export.
Compare each field with an independent read on `<CA-HOST>`.

| Area | Collector output to check | Independent read |
|---|---|---|
| CA registry row | `registry_config_collected: true`; EditFlags, InterfaceFlags, CAType kind, CommonName, AuditFilter, CRL/CA cert URL lists, DisableExtensionList | `certutil -getreg CA\EditFlags` (and the same for every other value); `certutil -getreg policy\DisableExtensionList`; `certutil -getreg CA\CRLPublicationURLs` |
| Multi-string values (WI-044 defect 1) | Each REG_MULTI_SZ list equals certutil's values, without the `N:` indices. An empty list reads as empty, never as null or a list of index tokens | Same certutil reads |
| AuditFilter (defect 3) | With AuditFilter 127, CA_AUDIT_* findings do not fire. Delete the value (Phase 3 case H1) for absent = 0 | `certutil -getreg CA\AuditFilter` |
| CA\Security (ESC7 input) | Owner and every ACE (trustee, ManageCA / ManageCertificates / Enroll / Read, Allow / Deny) equal the CA's security settings | `certutil -getreg CA\Security`, plus the CA console's Security tab |
| Endpoints (defect 2) | Web Enrollment / CES rows carry `<CA-HOST>` as their host; the auth providers (NTLM / Negotiate / Kerberos), the HTTPS binding, `ssl_required` and Extended Protection match IIS; the pass is `complete` only if this is the only CA host | **Corrected after the 2026-10-13 run:** read the ground truth from the `<location path="<site>/<app>">` tags in `%windir%\System32\inetsrv\config\applicationHost.config` (AD CS setup keeps `/certsrv`'s and CES's `windowsAuthentication` / `extendedProtection` and `access sslFlags` there, because those sections are locked below applicationHost.config), and cross-check with `Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Location '<site>/<app>' -Filter ... -Name ...`. Do not dereference `.Value` on an enum or flags result: it reads nothing, which is how the run's own independent read and collector 0.11.0 both missed `Require` / `Ssl, Ssl128`. `Get-WebBinding` for the bindings |
| ESC5 own-account exemption (defect 4) | `ca_host_sid` on the CA's enrollment-service rows equals the computer object's objectSid. ESC5 does **not** fire for that account on that object, and there is no CA_HOST_ACCOUNT_UNRESOLVED | `Get-ADComputer <CA-HOST> -Properties objectSid,dNSHostName`, and `dNSHostName` on the enrollment-service object (they must be identical, including case) |
| Existing estate observations | CRL_EXPIRY fires for the root whose AD-published CRL went past nextUpdate in February 2026. Whether doctor says anything about the issuing CA's root not being published in AD (record what it says; silence is an observation, not necessarily a defect) | `certutil -dump` of the CRL, and `openssl crl -nextupdate` |

Then run the same commit from `<MEMBER>`, as in WI-044. Expect:
- the endpoint pass is partial, naming `<CA-HOST>` as not inspected;
- ENROLLMENT_ENDPOINTS_NOT_EVALUATED is emitted;
- `diff --exit-code` from the CA-host reference to this export exits 3 (lost
  coverage), never 0, and ESC8 is not resolved.

## Phase 2: privilege contexts (read-only)

A collector run with less privilege must say what it could not read. It must
never call the missing parts clean. Run on `<CA-HOST>` unless stated, one
export per row.

| Case | Principal | Expected |
|---|---|---|
| P1 | Domain administrator (the Phase 0 reference) | Every pass complete |
| P2 | An account with local admin on `<CA-HOST>` only, no domain rights | LDAP passes complete (Authenticated Users can read the PKI containers); CA registry and CA\Security read; DC registry not evaluated |
| P3 | An ordinary domain user with no admin rights | Whatever the CA registry and CA\Security reads deny is marked not obtained, with a `*_NOT_EVALUATED` note. No ESC6/7/11/16 "clean" verdicts appear without data. **Corrected after the 2026-10-13 run:** a plain user may be able to read the CertSvc registry (on the lab CA it could, so the registry row was obtained); what such a user cannot do there is load the IIS configuration, so `enrollment-endpoints` is skipped and ESC8 is not re-evaluated. Record which reads succeeded rather than expecting every registry read to be denied |
| P4 | From an SSH session on `<MEMBER>` with `-LdapUserB64` / `-LdapPassB64` (the documented double-hop route) | LDAP passes complete. Then search the whole export directory, and any transcript or log, for the password, its base64 form and its UTF-16LE base64 form: **none may appear** |
| P5 | `-CollectDcMapping` with `-DcRegistryUserB64` / `-DcRegistryPassB64` for an account allowed remote registry reads on the DCs | `esc10-dc-registry` complete. StrongCertificateBindingEnforcement and CertificateMappingMethods equal `reg query` on each DC. The same credential-leak search as P4 |

For every case, `diff --exit-code` from P1 to that case must exit 3 wherever
coverage dropped, and must never mark a finding resolved because its input
went missing. **Corrected after the 2026-10-14 re-check:** exit 3 holds only if
the older export carries no regressions. Regressions take precedence over exit 3
(README, exit-code table: "this wins over 3"; `diff --help` for `--exit-code`),
so a diff that also shows any regression (a new or worsened finding, or one
first observed after coverage was gained) exits 1, with the coverage rows still
shown as `NOT RE-EVALUATED`. An older export with real problems of its own
(a stale CRL, a misread value) produces such regressions in the newer one.

## Phase 3: seeded misconfigurations (CHANGES THE ESTATE)

For each case: make **one** change, collect, check, revert, collect again, and
confirm the revert. Run from `<CA-HOST>` as a domain administrator. Each case
needs four things:

| Step | Check |
|---|---|
| **seeded** export | `doctor` shows the expected finding, at the documented severity, on the right object |
| `diff --exit-code baseline seeded` | Exits 1 and lists the finding as new |
| **reverted** export | The finding is gone |
| `diff --exit-code seeded reverted` | Lists the finding as resolved and exits 0 |

Any other finding that appears or disappears between baseline and seeded is
also a result. The detector should change only what the case changed.

**Safety and cleanup.**
- **Test objects.**
  - Make every test template a *duplicate* of a built-in template, named with
    the prefix `zzAdcsLensTest-`.
  - Create a dedicated, non-privileged group `zzAdcsLensTest-Enrollees` with
    one test user, and grant enrollment rights to that group. The detector
    treats any custom group as low-privileged, so Domain Users does not need
    to be exposed. Case A1b alone uses Authenticated Users, to test well-known
    SID handling; revert it straight away.
  - Publish a test template on the CA only for its case, and unpublish it
    during the revert.
- **CA-wide changes** (C1–C4, H1) affect real issuance.
  - Record the original value first, change one value at a time, restart
    CertSvc, and restore and verify the original before moving on.
  - Do not enroll any certificate unless the case says so. Detection is
    static; nothing here needs an issued certificate.
- **Before Phase 3, record the starting state** to roll back to:
  - an `ldifde` export of `CN=Public Key Services` and of every object the
    phase touches;
  - a `reg export` of the CertSvc configuration.

### Templates (A)

| Case | Seed (on a test duplicate, enrollable by the test group, published) | Expected |
|---|---|---|
| A1 | Supply in request (`msPKI-Certificate-Name-Flag` ENROLLEE_SUPPLIES_SUBJECT); Client Authentication EKU; no manager approval; 0 authorized signatures | ESC1, plus ENROLLEE_SUPPLIES_SUBJECT |
| A1b | A1, but enrollment granted to Authenticated Users instead of the group | ESC1 with the well-known trustee reported correctly |
| A1c | A1, but with CA manager approval on (`PEND_ALL_REQUESTS`) | ESC1 suppressed or downgraded, per the documented rule; PEND_ALL_REQUESTS reported |
| A1d | A1, but with 1 authorized signature required (`msPKI-RA-Signature` = 1; [MS-CRTD] 2.18) | **Corrected after the 2026-10-13 run:** the attribute is `msPKI-RA-Signature` (an integer count); `msPKI-RA-Signature-Policies` does not exist, which is why the run could not seed this case. From collector 0.12.0: ESC1 still fires, capped at MEDIUM, naming the required signature (the documented rule above `_ra_signature_effect` in `detection.py`); with 0 it is CRITICAL; an unread value is never read as 0 |
| A2 | Any Purpose EKU, then (a separate run) no EKU, without supply-in-request | ESC2 |
| A3 | Certificate Request Agent EKU, enrollable by the group, plus a second template that allows enroll-on-behalf | ESC3, on the right template(s) |
| A4 | Grant the test group Write / WriteDacl / WriteOwner / GenericAll, one at a time, on a test template; also a property-scoped `WriteProperty` on `msPKI-Certificate-Name-Flag` | ESC4 for each. The scoped write is reported as scoped (WI-019) |
| A5 | A schema version 1 duplicate with supply-in-request, enrollable by the group, published; then the same template unpublished | ESC15. Publication state is annotated in both runs, at the same severity (the repo convention) |
| A6 | A test template with `CT_FLAG_NO_SECURITY_EXTENSION` (`msPKI-Enrollment-Flag` 0x80000) and Client Authentication | ESC9, plus NO_SECURITY_EXTENSION |
| A7 | An issuance policy OID linked to a group via `msDS-OIDToGroupLink`, on a template enrollable by the test group | ESC13 |
| A8 | `msPKI-Minimal-Key-Size` 1024 on a test template | WEAK_TEMPLATE_KEY_SIZE |
| A9 | A test template whose display name has leading or trailing spaces and non-ASCII characters (an earlier defect involved `" LabWebServer "`) | Joins and publication are resolved exactly. No false ORPHANED_TEMPLATE |
| A10 | A template listed in the CA's `certificateTemplates` that does not exist in AD | **Corrected after the 2026-10-13 run:** ORPHANED_TEMPLATE means the opposite direction - a template in AD that no CA serves - so this case cannot fire it. A CA listing a name that is missing from AD is an **undetected case** today (no detector models it); record what doctor says |

### PKI objects (B)

| Case | Seed | Expected |
|---|---|---|
| B1 | Grant the test group GenericWrite on the CA's enrollment-service object | ESC5, at the documented severity. The CA's own account on that object is still exempt (defect 4) |
| B2 | Grant the test group WriteDacl on the `NTAuthCertificates` object | ESC5 |
| B3 | Grant the test group GenericAll on the CA computer object | ESC5 CRITICAL on the computer object (kind `ca_computer`). **Corrected after the 2026-10-13 run:** collector 0.11.0 never read that object's descriptor, so the case could not fire; collector 0.12.0 reads it |
| B4 | Make the test user the owner of a PKI container | ESC5, through ownership |

### CA configuration (C), one value at a time, restoring between cases

| Case | Seed | Expected |
|---|---|---|
| C1 | `certutil -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2` | ESC6 |
| C2 | Grant the test group ManageCA, then (a separate run) ManageCertificates, on the CA | ESC7 for each |
| C3 | `certutil -setreg CA\InterfaceFlags -IF_ENFORCEENCRYPTICERTREQUEST` | ESC11, plus IF_ENFORCEENCRYPTICERTREQUEST |
| C4 | Add `1.3.6.1.4.1.311.25.2` to `policy\DisableExtensionList` | ESC16 (the case WI-044 defect 1 made impossible on 0.10.0). Also add a second, unrelated OID, to prove the list parses as a list |

### Endpoints (D)

| Case | Seed | Expected |
|---|---|---|
| D1 | Turn Extended Protection off on `/certsrv`, with NTLM or Negotiate on | ESC8 |
| D2 | Add an HTTP (non-TLS) binding for Web Enrollment | ESC8, with the HTTP transport reported |
| D3 | Restore HTTPS and Extended Protection = Require | ESC8 resolved by `diff` (the positive resolution that defect 2 must not block). **Corrected after the 2026-10-13 run:** first check what the estate already has: on the lab CA the true configuration was already Require / `Ssl, Ssl128` in the location tags, so D1/D2's "already dirty" premise was an artifact of the 0.11.0 read defect. Seed D1/D2 into the location tag (`-PSPath 'MACHINE/WEBROOT/APPHOST' -Location ...`, or appcmd `/commit:apphost`): an application-level write to a locked section fails |

### DC and principal mapping (E), with `-CollectDcMapping` plus DC registry credentials

DCs with Microsoft's certificate-binding enforcement updates may ignore some of
these values at runtime. The detector reads the registry statically, so it is
still the right input to test. Record each DC's patch level beside the result.

| Case | Seed | Expected |
|---|---|---|
| E1 | On `<DC1>`, `StrongCertificateBindingEnforcement` = 0 under `HKLM\SYSTEM\CurrentControlSet\Services\Kdc`; then (a separate run) 1 | 0: ESC10 case 2 (HIGH) for that DC only. **Corrected after the 2026-10-13 run:** 1 (compatibility mode) is a separate ESC10 finding at MEDIUM, not case 2 |
| E2 | On `<DC1>`, `CertificateMappingMethods` with the UPN bit (0x4) under `...\SecurityProviders\Schannel` | ESC10 case 1 |
| E3 | Set a weak `altSecurityIdentities` mapping (subject-only, `X509:<S>...`) on the test user; then a strong one (`X509:<I>...<SR>...`) | **Corrected after the 2026-10-13 run:** ESC14 needs a DC that is known not to enforce strong binding. With every DC's enforcement unknown (value not set), a weak mapping gives the estate note ESC14_ENFORCEMENT_UNKNOWN, not ESC14. Run E3b for the finding |
| E3b | E3 combined with `StrongCertificateBindingEnforcement` = 0 on `<DC1>` | ESC14 (HIGH) on the test user for the weak mapping; the strong form resolves it; removing the KDC value restores the baseline |

### Hygiene (H)

| Case | Seed | Expected |
|---|---|---|
| H1 | Delete `CA\AuditFilter` (restart CertSvc), then set it to 0, then to a partial mask such as 1 | Absent or 0 gives CA_AUDIT_DISABLED (defect 3). The partial mask gives CA_AUDIT_UNDERSCOPED |
| H2 | Remove the AIA or OCSP URL from the CA's extension settings (on a CA whose certificates you can reissue, or observe only) | CDP_AIA_ABSENT or OCSP_URL_ABSENT, as appropriate |

## Phase 4: scale and shape (read-only after setup)

| Case | Setup | Expected |
|---|---|---|
| S1 | Create 600 `msPKI-Enterprise-Oid` objects named `zzAdcsLensTest-*` under `CN=OID` (the LDAP page size is 500) | `oid-objects` complete, with a count of exactly 600 plus the original. The multi-page cookie path is exercised. Delete the objects afterwards |
| S2 | An **inherit-only** ACE on `CN=Certificate Templates` granting the test group Enroll on child `pKICertificateTemplate` objects | Each template's ACE list shows the inherited ACE. The container's own ACL does not treat the inherit-only ACE as applying to the container. Remove it afterwards |
| S3 | An explicit **Deny** Enroll for the test group on an A1 template | ESC1 suppressed or annotated per the documented rule, and never silently ignored |

## Harness notes (from the 2026-10-13 run)

- **Force replication between a change and a collect.** With several DCs, AD
  replication raced the collects; run `repadmin /syncall /AdeP` (or wait and
  confirm the change on the DC the collector binds to) after each seed and
  each revert.
- **Seed interactively.** Scripts that edit security descriptors, run as
  scheduled tasks, wedged unpredictably (the task ran but its wrapper never saw
  completion). A console or RDP session was reliable, and is what "console
  logon" in the rules above means.
- **Windows PowerShell 5.1 and `ActiveDirectoryAccessRule`.** On the lab host
  the constructor bound rights-first; a type-first argument order silently
  built the wrong ACE. Read the ACE back after every seed.
- **Plain-user scheduled tasks** (P3) need "Log on as a batch job", which a
  server grants to Administrators only by default; grant it for the run and
  restore the original list afterwards.

## Re-checks for collector 0.12.0

Collector 0.12.0 fixes the 2026-10-13 defects against simulated and recorded
inputs only. Re-run these on `<CA-HOST>`, each with the full seed / diff /
revert / diff cycle of Phase 3:

| Case | Expected on 0.12.0 |
|---|---|
| Phase 1 endpoints (**proven live 2026-10-14**) | `web-endpoints.json` shows the true location-tag values (`epa: require`, `ssl_required: true` on the lab CA), and the baseline has no ESC8. The two-scope read was first run only against simulated IIS (proven live 2026-10-14, as marked): **this row and D3 are the release condition for calling the endpoint fix proven** (review round 1, Sol N2). If a value reads null, the `web-endpoints` reason says which read failed, could not be decoded, or disagreed. `the scopes disagree: application-path 'None', applicationHost location 'Require'` would confirm the report's scope reading (the application-path read returns the parent default); the follow-up is then to decide the value from the location tag when the section is locked below applicationHost.config, which needs a lock-state read this collector does not make yet |
| D3 | **Proven live 2026-10-14: PASS (with the Phase 1 endpoints row, the release condition for the endpoint fix is met).** With Require / `Ssl, Ssl128` restored after a D1 seed, `diff` resolves ESC8 (exit 0) |
| D1 | **Passed 2026-10-14.** tokenChecking None in the location tag gives ESC8 (EPA none) |
| B3 | **Passed 2026-10-14, with an estate caveat. Corrected after the 2026-10-14 re-check:** on a Server 2025-generation domain the computer object already carries two ESC5 CRITICAL findings at baseline (an inherited `NT AUTHORITY\SELF` write of the RBCD attribute, which every computer object of that domain has, and a GenericAll held by an unresolvable SID), so the seed shows in `diff` as a changed finding (exit 0), not a new one; read the finding's trustee list. The baseline is clean only in a domain without them. GenericAll for the test group on `<CA-HOST>`'s computer object gives ESC5 CRITICAL on that object; the revert resolves it. **Before seeding, record the computer object's default DACL** (`dsacls`, or the `pki-acls.json` row) **and the forest's dSHeuristics** (the manifest's `ds_heuristics`). Expected baseline: no ESC5 on the computer object when an administrator joined `<CA-HOST>`, in a domain without the inherited `SELF` RBCD ACE (a Server 2025-generation domain has it on every computer object, and then ESC5 `scoped-writeproperty` fires at baseline). If an ordinary user joined it (MachineAccountQuota), the default SD's CREATOR OWNER write of Account Restrictions gives that user an RBCD path, and ESC5 `scoped-writeproperty` CRITICAL is a true positive: record who created the object. If dSHeuristics character 29 is 1, a low-privilege owner gives no owner finding |
| B3b | **Passed 2026-10-14, all four sub-cases.** A property-scoped write for the test group on `msDS-AllowedToActOnBehalfOfOtherIdentity` of `<CA-HOST>`'s computer object gives ESC5 `scoped-writeproperty` CRITICAL; a scoped write to an unrelated attribute gives nothing; a Deny for the test group on Account Restrictions placed before the Allow suppresses it, and an inherit-only Allow (applying to child objects) gives nothing |
| Version gap | `diff` from a 0.11.0 export to a 0.12.0 one lists any computer-object finding under **first observed: coverage gained** (exit 1) with `CA_COMPUTER_NOT_COLLECTED` clearing; from 0.12.0 back to 0.11.0 it resolves nothing on the computer object, nor ESC1 on a template whose name flags the 0.11.0 table read differently (bits 0x8 / 0x10000; a template with only 0x1 compares as usual). **Corrected after the 2026-10-14 re-check:** that direction exits 3 only if the diff shows no regression. Regressions take precedence over exit 3 (README, exit-code table: "this wins over 3"), so when the lab's older export carried any (a stale CRL, the 0.11.0 ESC8 read defect, a leftover template) it exited 1, with the coverage rows still shown as `NOT RE-EVALUATED` / `FIRST OBSERVED: COVERAGE GAINED`. Passed 2026-10-14 in substance, both directions exit 1 |
| A1d | **Passed 2026-10-14.** `msPKI-RA-Signature` = 1 on the A1 template: ESC1 at MEDIUM naming the requirement (CRITICAL -> MEDIUM in `diff`); 0 restores CRITICAL |

## What to report

Report each case's row from the tables above, filled in:
- the commit and collector version;
- **expected** and **observed** results, with the finding id, severity and
  object (placeholders);
- the two diff exit codes;
- pass, fail or "detector rule differs" (quoting the rule);
- the evidence path.

Report separately any finding that appeared without being seeded, and any
note that reads "clean" where it should read "not evaluated".

Clean up, and confirm with a final export plus `diff --exit-code` against the
Phase 0 reference:
- every `zzAdcsLensTest-` object and group;
- CA settings restored to their recorded originals;
- auditing returned to its original setting.

The diff should report nothing new, apart from findings that were already
present before the test.
