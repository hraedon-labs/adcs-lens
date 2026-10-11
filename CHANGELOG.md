# Changelog

All notable changes to adcs-lens are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Export staleness notes**: `EXPORT_STALE` when the manifest's `collected_at`
  is more than 8 days old (override with `ADCS_LENS_STALE_EXPORT_DAYS`, which
  accepts only a plain positive integer number of days from 1 to 36500, with
  no leading zero; anything else, including an arbitrarily long digit string,
  exits 2 with an error), and `EXPORT_TIMESTAMP_INVALID` when
  `collected_at` is missing, unparseable, has no UTC offset, or is more than 5
  minutes in the future. Both are INFO coverage notes in text, JSON, SARIF, and
  HTML output (excluded from `--exit-code`). `ingest`, `doctor`, and `diff`
  (for both exports) also print them on stderr, so `--severity` cannot hide them. Export age equals
  collection age only if the collector host's clock was right. The 8-day default
  and the 5-minute skew tolerance are policy choices, not measurements.
- **Per-file input size limits** (`adcs_lens/limits.py`): the manifest
  (1 MiB), `certs/index.json` (16 MiB), every other export JSON file (64 MiB),
  each DER certificate (1 MiB) and CRL (256 MiB), and the suppressions file
  (4 MiB). An oversized file is rejected with `IngestError` and never
  truncated. The size is checked before the read and again after a bounded
  read. The limits are policy choices, not measurements (table in the README).
  Malformed DER and invalid UTF-8 are now an `IngestError` instead of a
  traceback.

### Security
- **Collector read-only gate hardened (review round 1).** Every bypass the
  reviewers reproduced is now flagged:
  - Member dispatch through `ForEach-Object -MemberName` / `-ArgumentList`:
    `ForEach-Object` and `Where-Object` take exactly one script block.
  - `Get-WmiObject` with extra parameters: only its three exact StdRegProv
    `-List` vectors are allowed.
  - Redirections: everything except `2>$null` is rejected.
  - Reassigned, comment-pinned, script-scoped, `+=`, foreach-rebound,
    `[ref]`, `Set-Variable` or `-OutVariable` write targets: confinement is
    checked on the AST, and each write-target variable must have exactly its
    expected `Join-Path $OutDir` assignment.
  - `New-Item -Name`, and `certutil` with anything other than `-getreg <key>`.

  Every allowed cmdlet now has an exact argument vector. The collector's write
  variables were renamed to unique names (`$outPath`, `$outParent`, `$outName`,
  `$certFile`, `$crlFile`) so the one-assignment rule can hold; behaviour is
  unchanged.
- **Collector gate is closed-world (review round 3).**
  `tests/collector/collector-inventory.json` pins the collector's entire
  call-site surface: every command with its full normalised argument AST
  (common parameters included), every member call with its receiver, every
  variable binding (assignments in any scope, foreach variables, function,
  script-block and script parameters, and common-parameter variable writes),
  every redirection, type reference and function. Any difference fails CI.
  `tests/collector/regen_inventory.py` refuses to write unless every semantic
  check passes. The semantic layer itself is stricter:
  - variable names are compared case-insensitively;
  - each pinned variable (the write paths, `$OutDir`, `$outName`, `$dcDns`,
    `$dcCred`, `$reg`) must have exactly its expected bindings across all
    scopes, so `$OUTPATH = ...`, a same-name function or script-block
    parameter, or a reassigned `$dcDns` all fail;
  - `-*Variable` common parameters (including abbreviations) are rejected;
  - every member-call receiver must be a variable bound in the script.

  Every Sol round-2 candidate is a regression case that asserts which check
  flags it.
- **Collector gate: golden whole-syntax-tree inventory and an exact semantic
  floor (ported from gpo-lens).** The round-3 golden file was sorted and
  dropped command text, so a reordered statement, a weakened `if`, a
  `#Requires` line or a `--` on a counter left it unchanged. Now:
  - `tests/collector/collector-inventory.json` is an order-preserving
    serialization of the collector's whole AST (every node and its
    semantically relevant properties, in source order) plus a SHA-256 of the
    source with only CRLF->LF normalized. Any edit, a comment included, fails
    until regenerated. The serializer is table-driven and copied from
    gpo-lens; an unknown node type is emitted as UNSUPPORTED and refused.
    Meta-tests check that the table covers every Ast type and property of the
    running pwsh, that every exotic node type serializes, and that 77 sampled
    mutations (single tokens, statement swaps, negated conditions, inserted
    statements, `#Requires`) each change the tree.
  - The semantic floor, which the regeneration script must pass, now pins
    exactly: every binding (assignments of any operator and scope, `++`/`--`,
    `foreach`, parameter declarations including defaults and attributes,
    local-function call-site arguments, property/index writes) of every write
    root, receiver and exec input, and of every variable those bindings read
    (93 variables). The receiver of every instance method, and the exact text
    plus control-flow context of every write, exec, module-load and remote
    operation (31 operations), are pinned too, so a duplicate, a reordered or
    weakened guard, or a changed later argument fails. The floor refuses
    provider-drive and `$global:`/`$variable:` writes, automatic and preference
    variable writes, any `$PSDefaultParameterValues` /
    `$PSModuleAutoLoadingPreference` / `$ExecutionContext` reference,
    splatting and extra positional arguments into local functions,
    dot-sourced calls, `#Requires`, background jobs, `foreach -parallel`,
    non-ASCII source, AST node types the collector does not use, and any
    change to the ordered list of local functions.
  - 22 regression probes adapt every gpo-lens round-3 class to this
    collector, plus 3 edits only the golden tree catches. Each of the 22 is
    rejected by its intended check and changes the tree. Against the a789b5d
    gate, 17 were admitted by the semantic floor and 5 of those also left the
    golden file unchanged (a moved guard, a weakened opt-in guard, `-or` to
    `-and`, `#Requires`, an added `$i--`).
  - The DeepSeek round-2 expectations were regenerated: 84 of 169 cases gained
    checks, none lost one, and five former controls are now flagged (each an
    extra copy of an allowed write, load or exec, now outside the pinned
    operation set).
  - Gate dumps are batched in one pwsh process, so the collector tests run
    faster than before despite the larger inventory.
  - The threat model's new "Collector read-only gate" section lists what the
    gate does not prove.
  - **Round-4 hardening (interprocedural + lifetime + per-scope).** Each local
    function's whole body is pinned by an exact normalized-AST digest
    (`LOCAL_FUNCTION_BODIES`), hand-maintained and never written by the
    regeneration script (proven by `test_regen_does_not_touch_pin_tables`), so a
    helper's return value or body cannot be changed without a deliberate edit of
    that table even when every call-site binding is unchanged. Lifetime-changing
    instance calls (`Dispose`/`Close`/`Flush`/...) and LDAP query executions
    (`FindAll`/`FindOne`) are now guarded operations, pinned with context, so a
    duplicate or reordered call fails. Binding pins are keyed per scope, so the
    same name in two scopes is two separate pins. Three probes adapt the
    gpo-lens round-4 classes (a helper return rebinding a write path, a helper
    constant return feeding a remote credential, a duplicate state-changing
    call); all three were admitted by the 1b7caea floor and are now rejected.
    The DeepSeek round-2 expectations were regenerated again: no case gained a
    `[]`, one (`outname-reassign`, a write to `_writeJson`'s always-shadowed
    parameter) is now correctly inert under per-scope modeling.
  - **Round-3 hardening (caller-scope blocks + case-insensitivity).** A script
    block passed to `ForEach-Object` / `Where-Object` / `%` / `.ForEach()` /
    `.Where()` or dot-sourced runs in the caller's scope, so the dumper now
    collapses its bindings onto the enclosing scope (only `& { }` is isolated);
    an unqualified assignment inside such a block to a confined variable
    (`$OutDir`, `$certDir`, `$dcDns`, a transitive input) is rejected instead of
    hiding in a child scope. Command, function, method, parameter and variable
    names are compared case-insensitively at a single point (`_cf` / `_canon`
    and lower-cased scope keys), closing a case-variant `_WRITEJSON` call that
    wrote outside the output root and regenerated with the pin tables untouched.
    A meta-test (`test_verdict_is_case_insensitive`) re-runs every append-style
    regression snippet with the casing of its command/function/parameter/
    variable names flipped (via the dumper's `-SwapNames` mode) and requires an
    identical verdict. Seven probes (four caller-scope rebinds, three case
    variants) were admitted by the bac9359 floor and are now rejected. The
    input-read guard also refuses the indirect openers `argparse.FileType` and
    `importlib.import_module` (Sol E5 / DeepSeek N3-2), with regression cases.
- **Fabricated action pins replaced.** The SHAs inherited from the old
  `publish.yml` for `actions/upload-artifact` v4.6.2,
  `actions/download-artifact` v5.0.0 and `pypa/gh-action-pypi-publish`
  v1.13.0 did not exist upstream. They are replaced with the real tag commits,
  and `attest-build-provenance` is annotated with its exact tag v3.0.0. A new CI
  job, `verify-action-pins` (`scripts/verify_action_pins.py`), fails when any
  `uses: o/r@<sha> # vX.Y.Z` pin is not exactly that tag's commit, or lacks an
  exact version comment.

### Changed
- `verify_action_pins.py` parses workflows with PyYAML (now locked in the dev
  extra), so flow-style `{ uses: ... }` mappings, aliases and non-string
  values are checked. The input-read guard also rejects reflection
  (`sys.modules`, dunder attributes other than `__name__`). The sdist ships
  everything its own test suite reads, and `tests/test_sdist.py` builds it and
  runs that suite from the extracted tree.
- The input-read guard now covers subpackages and an import allowlist (io,
  builtins, codecs, sqlite3, subprocess, ... are refused). It also forbids
  `os.*` other than `os.environ`, and `open` / `getattr` / `__import__` /
  `eval` / `exec`. Its remaining limits are stated in the test.
- The sdist has an explicit include list, so untracked files in a working tree
  cannot change it (local double-builds match CI).
- **Metadata / doc drift**: the pyproject URLs, the README install URL, the
  SECURITY.md advisory link and the SARIF `informationUri` now name the real
  owner, `hraedon-labs` (they said `hraedon`). A test pins every pyproject URL
  and doc link to `publication.toml` `remote_owner`. The README and AGENTS.md
  status no longer claim v1.0 or "released" v1.2.0 (the latest tag is v1.1.2).
  AGENTS.md no longer says the collector is "to be built", says the model "will
  exist", or says tests use real-export numbers. `docs/publication-review.md`
  gains a dated note instead of a rewrite.
- **Release workflow**: the parked, token-based `publish.yml` is replaced by a
  tag-triggered `release.yml`. It requires the tag, the pyproject version, and
  the CHANGELOG top entry to agree (with `[Unreleased]` empty) and the tagged
  commit to be on `main`. It re-runs `ci.yml` (now callable through
  `workflow_call`), builds the sdist and wheel twice with `SOURCE_DATE_EPOCH`
  and compares them byte for byte, install-smokes the wheel, and writes
  `SHA256SUMS`. It attests build provenance and creates the GitHub Release. The
  PyPI upload uses Trusted Publishing (OIDC) and runs only when repo variable
  `PYPI_PUBLISH == 'true'`. Each job declares its own least-privilege
  `permissions:`. The build backend is locked in a new `release` dependency
  group. Owner steps are in `docs/releasing.md`.
- **Locked dependencies + supply-chain audit**: `uv.lock` is committed. CI
  installs with `uv sync --locked`, checks `uv lock --check`, and a new
  `supply-chain` job runs `pip-audit --strict` (pinned to 2.10.1) over the
  locked export of every extra. To clear the audit, the `[certs]` extra now
  requires `cryptography>=50,<51` (was `>=43,<45`; 44.0.3 had advisories fixed
  in 46.0.5–50.0.0) and dev requires `pytest>=9.0.3,<10`.
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
