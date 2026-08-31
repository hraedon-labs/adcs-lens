# Changelog

All notable changes to adcs-lens are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- **Template publication state is explicit and normalized**: ingest now records
  whether `enrollment-services.json` was present and valid, distinguishing a
  missing export (publication unknown) from a present empty export (all
  templates confirmed unpublished). Enrollment-service mappings must be arrays
  of strings; blank CA/template names are ignored, and publisher names are
  de-duplicated and sorted for deterministic findings.
- **ESC1/ESC2/ESC3 publication context**: affected-template findings now name
  the CAs that publish the template, state when it is confirmed unpublished, or
  state when publication is unknown. Publication remains context rather than a
  detector gate, so an unpublished vulnerable template is still reported.

### Fixed
- **Orphaned-template availability handling**: `ORPHANED_TEMPLATE` now skips
  only when `enrollment-services.json` is absent. A present valid empty export
  confirms that no templates are offered and correctly produces findings. Diffs
  withhold prior orphan findings from the resolved set when the newer export
  lacks enrollment-services coverage.

## [1.2.0] — 2026-07-28

### Added
- **Collector v0.8.0 — certs/ lifecycle pass**: the collector now captures the
  published CA certificates (AIA-container `cACertificate`) and base CRLs
  (CDP-container `certificateRevocationList`) from AD via plain LDAP, writing
  DER files + `certs/index.json`. This runs from any domain member (no
  certutil) and — crucially — captures the **offline root's** cert and CRL
  from their published locations: the root box is powered off by design, so
  its expired CRL is the catastrophic-but-invisible case this pass exists to
  make detectable. Delta CRLs are skipped (only the base CRL gates chain
  validation). New Pester-tested helpers: `_caKindFromType`, `_safeFileName`,
  `_certKindFromDer`.
- **Multi-CA registry honesty**: CA registry hives (`EditFlags`,
  `InterfaceFlags`, `AuditFilter`, `DisableExtensionList`, `CA\Security`) are
  local to the collector host, so they are now attributed only to the local CA
  (matched on certutil common name + DNS host). Every other enrollment service
  exports with `registry_config_collected = false`; the registry-gated
  detectors (ESC6/ESC7/ESC11/ESC16) skip those CAs and a new
  `CA_REGISTRY_NOT_EVALUATED` INFO note names them — a remote CA never reads
  as silently clean. This also fixes a false ESC11 on every remote CA (that
  detector fires on the *absence* of a flag). A standalone CA — never present
  in Enrollment Services — is now added when it is the local host, with `kind`
  derived from `CAType` (standalone root → `root`, standalone subordinate →
  `standalone`).
- **`PKI_ACL_UNREADABLE` note**: the PKI-object analogue of the template
  `acl_obtained` marker. When the pki-acls pass ran but an object's
  `nTSecurityDescriptor` came back unreadable (LDAP denial, corrupt SD), ESC5
  skips the object and this INFO note surfaces the gap instead of silently
  clearing it. The collector emits the marker for the well-known fixed
  containers it could not read at all.
- **Architecture guards**: executable tests that no core module imports the
  narration layer and that the CLI reaches it only lazily (inside a function) —
  the layering rule was previously documented but only half-enforced (narration
  is itself stdlib-only, so a reverse import passed the stdlib guard silently).

### Changed
- **Low-privilege trustee classification inverted to an allowlist**
  (`is_low_priv_trustee`): only the curated high-privilege set (built-in admin
  and operator groups, SYSTEM/service identities, Enterprise Domain
  Controllers, and the well-known domain RIDs — Administrator, krbtgt, Domain
  Admins, Domain Controllers, Cert Publishers, Schema/Enterprise Admins,
  Key/Enterprise Key Admins) is treated as privileged. Everything else —
  Everyone, Authenticated Users, Domain Users/Computers, **custom groups, and
  named accounts** — is treated as low-privilege. The previous blocklist
  missed custom groups entirely: Enroll granted to a purpose-built group
  silently produced no ESC1 finding, a domain-compromise-class false negative.
  The new direction fails toward flagging (a custom *privileged* group may
  read as noise); the `ACL_GROUP_TOKEN_CAVEAT` estate note now documents both
  honesty boundaries (no group-token expansion + allowlist classification).
- **`MIN_COLLECTOR_VERSION` 0.6.0 → 0.8.0**: pre-0.8.0 exports lack the certs
  pass, per-CA `registry_config_collected`, CAType-derived `kind`, and the
  PKI-object `acl_obtained` marker, so the stale-collector warning now names
  them.
- **JSON envelope `schema_version` 2 → 3**: every finding carries a structured
  `sid` field (the principal SID for trustee-specific findings, currently
  ESC7). SARIF renderers read it directly instead of extracting a SID from the
  free-text detail with a regex (WI-042).
- **`_finding_with_consequence` deduplicated** into
  `consequences.finding_with_consequence`, shared by the display and narration
  layers so the two serializations can never drift (WI-043).
- Collector: CES/CEP endpoint classification now requires the `_CES_`/`_CEP_`
  infix or an exact `cep` path segment — a bare substring match false-matched
  unrelated apps (`/concept`, `/reception`). The `ca-security` pass is marked
  skipped when no local CA security descriptor was read (e.g. the collector
  ran on a tier-0 box that is not a CA), so the core's
  `CA_SECURITY_NOT_EVALUATED` note fires instead of a silent "no ESC7".
  `LIFECYCLE_NOT_EVALUATED` now names both possible causes (collector predates
  the certs pass; missing `[certs]` extra). All scripts/comments are pure
  ASCII with a Pester guard (PS 5.1 BOM-less parse safety, the bug class
  behind 5a98907).

## [1.1.2] — 2026-07-16

### Changed
- **Collector v0.7.0**: LDAP credentials are now optional. By default the
  collector uses the current user's integrated Windows credentials (mirroring
  the gpo-lens collector), so you can run it interactively as a Domain Admin
  without base64-encoding anything:
  `scripts/Export-AdcsEstate.ps1 -OutDir C:\AdcsExport`
  For key-based SSH sessions (the double-hop problem), pass explicit creds
  via `-LdapUserB64` / `-LdapPassB64` as before. The DC registry pass
  (`-CollectDcMapping`) likewise defaults to integrated creds when
  `-DcRegistryUserB64` / `-DcRegistryPassB64` are omitted. Providing only one
  of a credential pair is now an error (was a silent misbind).

## [1.1.1] — 2026-07-16

### Added
- **Windows installer** (`scripts/install-windows.ps1`): creates a venv under
  `C:\ProgramData\adcs-lens`, installs adcs-lens with the `[certs]` extra, and
  verifies the CLI entry point. Handles Python 3.12+ discovery (including the
  Python Install Manager and Windows Store stubs), copies a user-scoped Python
  to a shared location for scheduled tasks / SSH sessions, and is safe to re-run
  (upgrades in place). A `-NoCerts` switch skips the `[certs]` extra for
  air-gapped hosts without a C compiler. Pester-tested helper functions
  (version parsing, shared-Python detection) run in CI on Linux pwsh.
- **Windows uninstaller** (`scripts/uninstall-windows.ps1`): removes the venv
  and optionally the shared Python install (`-RemoveData`). Safe to re-run.
- **CI job** (`installer-helpers`): Pester tests for the installer's pure helper
  functions, running on Linux pwsh alongside the collector helper tests.

## [1.1.0] — 2026-07-14

### Added
- **Property-scoped WriteProperty (WI-019)**: ESC4 now flags a low-priv
  trustee holding a scoped `WriteProperty` on a dangerous template property
  (msPKI-Certificate-Name-Flag, msPKI-Enrollment-Flag, pKIExtendedKeyUsage,
  msPKI-Certificate-Policy, msPKI-Certificate-Application-Policy). The
  collector (v0.6.2) emits `WriteProperty:<guid>` for scoped writes; the core
  maps the GUID to the property name and flags it. Broad Deny rights
  (GenericAll, FullControl, GenericWrite) correctly suppress scoped writes via
  the existing `_COVERS` implication map.
- **OCSP URL-presence check (WI-022)**: flags issuing CAs whose certificate
  lacks an OCSP responder URL in its AIA extension (`OCSP_URL_ABSENT`, LOW).
  The `[certs]` extra now parses AIA and CRL Distribution Points extensions.
- **Orphaned-template detector (WI-032)**: flags templates that exist in AD
  but are not published by any enrollment service (`ORPHANED_TEMPLATE`, LOW).
  Degrades to no-op when no enrollment services are present.
- **CDP/AIA URL-presence check (WI-032)**: flags issuing CAs whose certificate
  lacks CDP or AIA URLs (`CDP_AIA_ABSENT`, MEDIUM).
- **Narration layer (WI-016)**: optional executive-summary module
  (`adcs_lens.narration`) with deterministic (template-based) and optional
  AI-enhanced modes. Accessible via `doctor --narrate` (prints to stderr).
  Imports the core, never the reverse (architecture-guarded).
- **Findings suppression / risk-acceptance (WI-021)**: `doctor
  --suppressions <file.json>` loads a JSON risk-acceptance file and filters
  suppressed findings from the `--exit-code` gate. Each rule carries a reason
  and optional expiry. Suppressed findings are excluded from output; the
  suppression summary is printed to stderr for the audit trail.
- **SARIF `locations` structure (WI-035)**: each SARIF result now carries a
  `locations` array with `physicalLocation.artifactLocation` (using a `file:` URI)
  and `logicalLocations` for the source fact and subject, per the SARIF 2.1.0 spec.
- **HTML table of contents (WI-035)**: the HTML report now includes a TOC
  linking to each severity band with counts.
- **Diff SARIF/HTML output (WI-035)**: `diff --sarif` and `diff --html` flags
  for CI/GRC integration of drift reports.
- **ESC7 SID in SARIF (WI-035)**: ESC7 findings include a `properties.sid`
  field in SARIF output.
- **PyPI publishing workflow (WI-039)**: GitHub Action workflow
  (`.github/workflows/publish.yml`) that builds and publishes to PyPI.
  Currently manual-dispatch only — no PyPI release exists yet and the
  `PYPI_API_TOKEN` secret / `pypi` environment are not configured; install
  from git (see README) until then.

### Fixed
- **Suppression date-only expiry (WI-041)**: a date-only `expires` value
  (`"2026-12-31"`) now keeps the rule active through the end of that day
  (UTC) instead of expiring at the midnight that starts it. An explicit ISO
  datetime is honored literally (assumed UTC when naive).
- **Collector v0.6.1**: LDAP `SecurityMasks` now requests `Dacl,Owner` (was
  `Dacl` only), so template and PKI-object `owner_sid` fields are actually
  populated. In v0.6.0 these were always empty — the owner-based ESC4/ESC5
  control paths (WI-019) could never fire on real data. The CA `owner_sid`
  (ESC7, read from the registry) was unaffected. The core degrades honestly
  either way (empty `owner_sid` → owner control skipped), so this was a
  coverage gap, not a false positive.
- **Collector v0.6.2**: scoped `WriteProperty` ACEs now emit the property GUID
  (`WriteProperty:<guid>`) instead of bare `WriteProperty`, enabling the
  property-scoped ESC4 detector (WI-019).

### Validated
- **WI-040**: Collector v0.6.0–v0.6.2 CA `owner_sid` capture live-validated
  on `LABCA` (`WORK-DOMAIN.local`). The CA security descriptor owner resolves to
  `S-1-5-32-544` (BUILTIN\Administrators — high-priv), so the ESC7
  owner-based finding correctly does *not* fire. Template and PKI-object
  owner_sids now also resolve (all high-priv: Enterprise Admins / Domain
  Admins) with the v0.6.1 fix. The full `doctor` run produces 35 findings
  (2 HIGH ESC8, 6 MEDIUM ESC15, 27 LOW orphaned templates, 6 INFO coverage
  notes) — all validated against the live estate.

## [1.0.0] — 2026-07-14

First public release. Local-first, read-only AD CS / PKI posture analysis with a
deterministic, stdlib-only core (no AI in the truth path).

### Added
- **ESC detectors** for the statically-detectable family: ESC1, ESC2, ESC3, ESC4,
  ESC5, ESC6, ESC7, ESC8, ESC9, ESC10, ESC11, ESC13, ESC14, ESC15, ESC16
  (ESC12 has no established static-detectability boundary — see
  `docs/threat-model.md`).
- **Infrastructure lifecycle**: CA cert / CRL-signing cert expiry, CRL freshness
  with a proportional early-warning window, weak signing algorithm (SHA-1/MD5),
  weak CA/template RSA key size (ECDSA templates skipped).
- **Operational hygiene**: CA audit disabled / under-scoped (vs. the 127 baseline).
- **Plain-language consequences catalogue**: every finding carries a summary,
  risk, and remediation block in the text, JSON, SARIF, and HTML output.
- **Output formats**: stable JSON envelope, SARIF v2.1.0 (CI/GRC), self-contained
  deterministic HTML evidence report.
- **Drift detection** (`diff`): regressions / fixes / severity changes between two
  read-only exports, with `--exit-code` for scheduled-scan gating — no live access.
- **Collector** (`scripts/Export-AdcsEstate.ps1`, v0.6.0): read-only PowerShell
  export of CA config, templates (with DACLs + owner), PKI-object ACLs, IIS
  enrollment endpoints, issuance OIDs, and opt-in ESC10/ESC14 DC mapping passes.
- **Collector/core version-compat check**: warns at ingest when a collector
  predates the minimum (`0.6.0`) so a stale export cannot read as silently clean.
- **Threat-model ↔ detector traceability test**: AST-locks the design spine so no
  ESC class or hygiene row can drift undetected.

### Stability contracts (from 1.0.0)
- **Diff identity** is `(check, subject, source)`. `source` is load-bearing and
  **stable public API**: a cosmetic edit to a detector's `source` string is a
  breaking change that produces a false regression+resolved pair on the next
  `diff`. The `test_diff_identity_contract_is_check_subject_source` test pins it.
- **JSON envelope** `schema_version` is `2`. The catalogue of `check` identifiers
  is locked by `test_catalogue_matches_every_check_literal_in_detection`.

### Known limitations
- **No nested-group expansion.** ACL-gated detectors (ESC1–ESC5, ESC7, ESC9,
  ESC13, ESC15) match the ACE trustee SID directly; a Deny on a group containing
  the requester, or rights held via group membership, are not modeled. Surfaced
  as an estate-level coverage note (`ACL_GROUP_TOKEN_CAVEAT`) — a "no finding" is
  not proof of no path.
- **`ca_patch_state` is always `unknown`.** The collector cannot yet read the CA
  build/patch level for CVE-2024-49019, so ESC15 caps at **MEDIUM** (with a
  "confirm patch state" caveat) on every real estate rather than asserting HIGH.
- **ESC12 is out of scope.** No statically-detectable enabling configuration has
  been identified in canonical tooling or research; the number is preserved for
  catalogue continuity and tracked as `Out (unresolved)`.
- **Collector v0.6.0 CA `owner_sid` capture is not live-validated.** ~~It is
  Pester-unit-tested and correct by inspection; the ESC7 owner-based finding
  should be treated as unconfirmed until the next live collector run.~~
  **Live-validated on LABCA (2026-07-14).** The CA owner_sid resolves to
  BUILTIN\Administrators (high-priv); ESC7 owner-based control correctly does
  not fire. Template/PKI-object owner_sids required a collector fix (v0.6.1:
  LDAP SecurityMasks must include `Owner`).
- **ESC9 EKU / DC-enforcement gates deliberately omitted.** ESC9 gates on
  low-priv enrollability + no manager approval (the false-negative-safe subset);
  the client-auth-EKU and binding-enforcement questions are tracked, not silent.

### Read-only / defensive boundary
adcs-lens never authenticates to, enrolls against, writes to, or relays through
live AD CS. It detects the *enabling configuration* of a weakness statically and
never performs the attack to confirm it. ESC8/ESC11/ESC15 report the prerequisite
and state that exploitability is not confirmed.
