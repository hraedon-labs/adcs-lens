# Changelog

All notable changes to adcs-lens are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- **Review round 5 follow-up: incomplete containers derive nothing.**
  - **Collector:** every enumeration loop serializes every object its verified
    search returned or says why not. Each loop catches a per-object failure,
    and the marker is computed by `_searchMarker` from the search's proof, the
    number of objects it returned, the rows written and the failures:
    `complete: true` needs all three to agree. A DC returned without
    `dNSHostName` (Sol round 5) was skipped under a complete marker, so ESC10
    and ESC14 resolved; it is now kept as a GUID + DN placeholder with null
    deciding fields. An IIS application whose path cannot be read (PowerShell
    swallows a failing getter) marks `web-endpoints` incomplete instead of being
    filtered as "not an enrollment endpoint". `LdapDirectoryIdentifier` gets a
    real `$null` server.
  - **Detectors:** a conclusion resting on an absence in a declared container is
    undecided when a reads-proven export marks that container incomplete: no
    visible publisher (ORPHANED_TEMPLATE, DS round 5), every visible issuing CA
    patched or none visible (ESC15), no visible group link (ESC13), every DC
    strict (ESC14). Findings backed by visible evidence (a present unpatched or
    unknown CA, a present non-strict DC) are kept. "Publication state: confirmed
    unpublished" in finding text also needs a complete enrollment-services
    container.
  - **diff:** a check the older export decided (a usable verdict, or a complete
    enumeration) that the newer export cannot decide is listed in the new
    `unevaluated` report section (JSON `unevaluated` / `summary.unevaluated`,
    text, HTML, SARIF run property) and makes `coverage_lost` true, so
    `--exit-code` returns 3 even when no older finding existed to withhold.
  - **Tests:** `tests/test_incomplete_scope.py` marks each declared container
    incomplete, and separately drops each of its objects, and requires no new,
    worsened, improved or resolved finding and the blocked comparison reported.
    It covers every check. `tests/test_reviewer_probes_r5.py` and the simulated
    collector (`missing-dc-dns`, `bad-entries` scenarios: one unserializable
    object in every loop) replay both round-5 probes; all fail at eb3c426.
- **Review round 5: verdicts, declared inputs, proven reads, mutation gate.**
  - **One verdict per (check, object[, variant]).** Each posture check decides
    every object of its subject type exactly once, in a top-level verdict
    function whose return value (None, a `FindingBody`, or a sub-variant map)
    *is* the verdict. `_verdicts()` is the single construction site: it sets
    the finding identity (check, variant, object) once and records the verdict,
    so findings and evaluation records cannot diverge. (ESC7's per-trustee
    rights are one family verdict per CA, `trustee:*`, which clears every
    trustee it does not flag; the findings carry `trustee:<sid>`.) Renaming a check leaves
    the old identity with no verdict: withheld, never resolved (round-4
    blocking 4). `Evaluation.verdicts` exposes every verdict (finding / clean /
    undecided, usable or not).
  - **Declared inputs, machine-checked.** `detection.CHECKS` declares, per
    check, the subject fields that decide the verdict, every container it
    enumerates (ESC15 the CAs, ESC14 the DCs, ESC13 the OIDs, ORPHANED_TEMPLATE
    the enrollment services, the CA-cert checks the CA list) and the fields it
    reads from them. A verdict function sees objects only through a reader that
    raises on an undeclared read and makes the object undecided on a field the
    collector did not obtain. `diff` relies on a verdict only when every
    declared container is complete and every declared field of the object and
    of every dependency object was obtained (round-4 blocking 1).
    `tests/test_verdicts.py` withholds each declared input in turn and requires
    the verdicts to become unusable.
  - **Collector 0.10.0 proves its reads (read-only throughout).** LDAP goes
    through `System.DirectoryServices.Protocols`: a container is marked
    complete only when every page returned Success and the final paging cookie
    was empty (a thrown page, a size or time limit, or a missing paging control
    leaves `complete: false` with the reason). `certutil -getreg` results are
    used only on exit code 0; a value that is not configured is empty, any other
    failure is `null`. Security descriptors (templates, PKI objects), the
    CA\Security hive, each IIS property, and each DC registry value (StdRegProv
    return codes) are checked the same way. A failed read is written as JSON
    `null`, never as an empty list (round-4 blocking 2). The old
    `inputs_obtained` endpoint flag is replaced by per-field nulls, and the
    tokenChecking (Extended Protection) read now counts too. Also fixed: a small
    certutil DWORD printed without a parenthesised decimal (`AuditFilter
    REG_DWORD = 0`, auditing disabled) used to parse as "not captured".
  - **Ingest.** Arrays must be arrays of strings in every export (a string is
    never iterated character by character). For a collector >= 0.10.0
    (`PROVEN_READS_VERSION`) every declared key is required, `null` marks a
    failed read (recorded in the object's `unobtained`), contradictory nulls
    are rejected (`acl_obtained` vs `security`, a remote CA carrying registry
    values), `ca-security.json` needs an entry per CA, and every collected
    container needs a marker whose count matches the rows when it claims
    completeness. Exports from older collectors are still scanned, but never
    resolve anything (they fail closed); the docs no longer claim a legacy
    fallback. Ingest also requires, for a collector >= 0.8.0, the template,
    PKI-object, DC and principal inputs the detectors read.
  - **Mutation gate replaces the residual static guard.** `tests/detection_records.py`
    and its 372-entry pin table are removed. `tests/test_mutation_gate.py` runs
    ~1,200 deterministic mutants of `detection.py` and the `normalize.py`
    helpers (generic AST operators plus every reviewer probe and variant from
    rounds 2-4) against a functional corpus; every mutant must change `diff`'s
    output or `evaluate()`'s verdicts on some corpus pair, except eleven listed
    equivalents, each with its reason (round-4 blocking 3). Runtime 60-115 s on
    the lab VM.
  - **Round-4 probes replayed.** `tests/test_reviewer_probes_r4.py` replays each
    reviewer export (all but one resolved findings at 9fb13d3; the other was
    already withheld and is kept as a witness);
    `tests/test_round5_analogues.py` exercises each closing mechanism on a
    0.10.0 export next to a control that still resolves;
    `tests/test_collector_simulated.py` runs the real collector body under pwsh
    with mocked transports and ingests the result.
  - Behaviour-neutral cleanups the mutation analysis exposed: dead
    `version_has_enumeration` / `enumeration_markers_expected` removed, rights
    tokens no detector keys on dropped from `_ALL_RIGHTS` / `_COVERS`, and a few
    redundant branches removed. `build_full_export` re-counts its markers after
    extending the export.
- **`diff` no longer reports coverage loss as resolution.** Before this fix,
  only `ORPHANED_TEMPLATE` was withheld when the newer export lacked coverage.
  A newer export that skipped `template-security` and `ca-security` listed
  ESC4/ESC7/ESC9/ESC15 (HIGH) as *resolved*, and `diff --exit-code` passed.
  Resolution is now withheld for every degradation path the detectors have:
  any skipped or missing pass (template-security, pki-acls, ca-security,
  enrollment-endpoints, esc10-dc-registry, esc14-altsecid, certs, and the core
  files), per-template and per-PKI-object unreadable DACLs, uncaptured owners
  (only the owner-based ESC4/ESC5/ESC7 variant), CAs whose registry was not
  collected, CAs missing from `ca-security.json`, uncaptured AuditFilter or
  template minimum key size, unparsed lifecycle data or unreadable cert/CRL
  fields, DCs with unknown binding enforcement, an empty DC list, unresolved
  ESC14 enforcement, and an unknown or stale collector version (which withholds
  everything). The coverage map is `detection.coverage_gaps()`. It is built
  from the same predicate functions the detectors use to skip.
  `tests/test_diff_coverage.py` degrades a full-coverage export (one where every
  posture check fires) along each path and asserts nothing is reported
  resolved. Its tripwires fail when a new pass name or a new coverage-shaped
  model field appears without being classified.
- **Enumeration completeness and proven inputs (review round 4, items 1-2).**
  - The collector writes a per-container completion marker
    (manifest `enumeration`: `{complete: true, count: N}`), only after each
    paged search / list build finishes without error. Ingest treats a container
    as fully enumerated only when its marker is complete and its count matches
    the rows; a missing or mismatched marker makes the container not complete,
    so absence-based drift resolution and type-enumeration records for it
    withhold. ESC13 records a template only when the OID container it depends on
    is complete.
  - Detector inputs may no longer default to clean for a current collector:
    a collected CA hive must carry `edit_flags` / `interface_flags` /
    `disabled_extensions` (an omitted key is an IngestError), endpoints must
    carry `transports` / `auth_providers` / `epa`, and a malformed endpoint row
    is an IngestError, not a silent filter. The collector gives each IIS
    endpoint an `inputs_obtained` flag (true only when every `-ErrorAction
    SilentlyContinue` read succeeded); ESC8 records an endpoint only when it is
    true, so a failed read never reads as a benign default.
  - Correction (round 5): this did **not** close honest truncation. The 0.9.0
    marker was written unconditionally after each loop with a self-count, so it
    proved only that the loop finished, not that the search returned every
    object; a partial search with a matching count still resolved everything
    it lost, and ESC14 / ESC15 ignored their dependency containers. Collector
    0.10.0 replaces it with a proven marker (below), and a 0.9.0 export no
    longer resolves anything.
- **Residual round-3 defects closed (after round 4).**
  - `diff` no longer takes an Evaluation's `guid_types` on trust. Resolving a
    GUID-identified object by absence now also requires that every newer object
    of that type carries a GUID, that none carries the older object's GUID, and
    that the object is in the older inventory. Otherwise the legacy rule
    decides (no unmatched newer object of that type).
  - (Superseded in round 5: the guard was bypassable through nested helpers,
    lambdas, method aliases, `getattr` and dict dispatch, and its pin table could
    be regenerated blindly. It is replaced by the mutation gate, below.)
    The residual records guard now checks dataflow as well as which helpers are
    called. A post-record helper that still calls its worker but discards,
    overwrites, slices or empties the result, or passes it a constant argument,
    is caught. So is a swallowed exception or a helper replaced by
    redefinition, rebinding or a decorator. Evidence flows and the bindings a
    verdict reads are pinned. The blatant forms (discarded, overwritten or
    never-read evidence, non-input arguments, an unconditional constant return,
    `except` / `suppress`, rebound helpers) are violations that no table edit
    can classify away. Post-record comprehension filters, which the guard used
    to skip because comprehension nodes carry no line number, are now
    classified.
- **Drift resolves only on positive evaluation records (review round 3).**
  - Detectors record each (check, object[, variant]) they fully evaluated, and
    each object type they fully enumerated (`detection.evaluate()` returns an
    `Evaluation`). `diff` resolves an older finding only on such a record, or,
    for an object that is genuinely gone, on a container record together with
    GUID identity (legacy exports additionally need no unmatched object of
    that type). A skipped input, an early return, a filter, a misused
    predicate, or a forgotten gate now means "not recorded", which withholds
    the finding by construction.
  - `evidence_complete` defaults to False, so omitting it withholds
    improvements.
  - The large condition table is replaced by a residual guard
    (`tests/detection_records.py`) that covers only code after a record point.
  - `tests/test_detection_records.py` loads each round-2 reviewer mutant (four
    from Sol, ten from DeepSeek) as a real module and proves it withholds. Five
    post-record mutants are proven flagged by the guard, and two of them are
    shown, executed, to resolve falsely without it.
- **objectGUID identity.** Collector 0.9.0 exports `object_guid` (the raw
  objectGUID as hex) for templates, enrollment-service CAs, PKI objects, OIDs,
  DCs, principals and CDP objects. Ingest requires it for that version and
  rejects malformed or duplicate GUIDs. Exempt are a standalone CA
  (`enrollment_service: false`) and a fixed container the collector could not
  read. Matching is one-to-one: ambiguous identity is withheld (older side) or
  NEW (newer side), never CHANGED. Legacy pairing requires that every alias
  kind both objects carry agrees, so a different template reusing a removed
  one's OID is NEW.
- The round-2 probe exports from both reviewers are committed as regression
  fixtures under `tests/fixtures/review_probes`.
- **Drift resolution requires positive evidence (review round 1).**
  - Findings carry stable `object_ids` (template OID/cn, CA name, PKI DN, DC
    name, principal DN, endpoint, cert SHA-256 fingerprint, CRL issuer+source)
    and a `variant`. Drift matching and coverage gaps use any shared alias, so
    a renamed display name, internal name, or config string no longer makes a
    gap miss.
  - Certificates and CRLs absent from the newer index are withheld, never
    resolved.
  - Certificates whose `ca_name` matches no CA (the offline root) are kept in
    `Estate.unattached_certs` and evaluated for expiry, signature, and key size;
    before this, they were silently dropped.
  - `Finding.evidence_complete` (False for ESC15 when the CA patch state is
    unknown) withholds an "improvement" that rests on weaker evidence.
  - Degradation notes become `coverage_changes` (appeared / cleared) and are
    no longer listed as new or resolved.
  - Signature and key-algorithm coverage predicates were added.
  - (Round 1 added a condition-classifying guard; round 3 replaced it with
    evaluation records, see above.)
  - The reviewers' probe exports are kept as regression fixtures.
- **Coverage markers are strict.** `acl_obtained` (templates, PKI objects),
  `registry_config_collected`, `ssl_required`, and `windows_auth` must be JSON
  booleans. They are required for a current collector, and any malformed value
  is an `IngestError`; they never fail toward "collected" (a string `"false"`
  used to read as True). Unknown names in `skipped_passes` and a non-string
  `collector_version` (e.g. `99`, which used to rank as current) are also
  `IngestError`s.
- **Partial exports fail loudly.** A missing `collector-manifest.json`, or a
  missing or nonexistent export directory, is now an `IngestError`. Before, an
  empty directory or a mistyped path ingested as an empty, "clean" estate. For a
  current collector, a missing file for a pass the manifest does not list as
  skipped is an `IngestError`. For an unknown or stale collector it becomes a
  `PASS_NOT_COLLECTED` gap. `skipped_passes` must be an array of strings.
- **Unknown collector versions are never treated as current.** A missing,
  `unknown`, or unparseable `collector_version` now emits a
  `COLLECTOR_VERSION_UNVERIFIED` note (a version below the minimum does too),
  and the stderr compatibility warning fires for it. Before, it was silently
  accepted.
- A CA with no entry in `ca-security.json` now gets a per-CA
  `CA_SECURITY_NOT_EVALUATED` note, where it used to read as having no ACEs. A
  DC registry pass that lists no domain controllers now emits
  `DC_REGISTRY_NOT_EVALUATED`; before, ESC10 passed silently.

### Added
- **"Not re-evaluated — coverage lost" drift bucket**: `DriftReport.indeterminate`
  (each item carries the older finding, the gap reason, and the current
  severity when an improvement was withheld). It appears in all four
  renderers: a text banner and section, a JSON `indeterminate` list with
  `summary.indeterminate` and `summary.coverage_lost`, a SARIF
  `baselineState: "unchanged"` result with `properties.adcsLensDrift` and
  `coverageLostReason`, and an HTML section.
- **`diff --exit-code` exits 3** when there are no regressions but coverage was
  lost. Regressions still exit 1 and take precedence; a clean run exits 0.
- Notes: `COLLECTOR_VERSION_UNVERIFIED`, `PASS_NOT_COLLECTED`.

### Changed
- **JSON envelope `schema_version` 3 → 4** (shared by both envelopes; 4 is
  unreleased and also covers the new finding fields `object_ids`, `variant`,
  `evidence_complete` and the diff `coverage_changes` list).
- `diff_findings(..., incomplete_checks=)` is replaced by
  `diff_findings(..., coverage=detection.coverage_gaps(newer_estate))`, and
  `diff.incomplete_coverage_checks` is removed. `MIN_COLLECTOR_VERSION` now
  lives in `adcs_lens.model` (`adcs_lens.ingest` still exposes it), and
  `Manifest.collector_version_status` is derived from `collector_version`.
- A declared skip now takes precedence over a leftover file for
  `enrollment-services` and `certs`.
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
