# Changelog

All notable changes to adcs-lens are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- Bound CLI error messages for malformed export fields while keeping their
  diagnostic context and the existing exit-4 rejection.

- Suppressed-finding summaries on stderr now escape control characters and
  shorten long checks and subjects, as expired-rule summaries already do.
  Suppression matching and JSON metadata retain the complete original values.

## [1.2.1] — 2026-10-24

A fix release.

### Upgrading from 1.2.0

- **Suppression files are read strictly.** A `--suppressions` file that 1.2.0
  accepted can now stop the run with exit 4: one with a repeated key, a key
  outside the documented set (including a case variant such as `Subject`), a
  blank or `null` `subject`, a `null` `expires`, a `metadata` value that is not a
  JSON object, or extra notes in a key adcs-lens does not define. Move free-form notes into `metadata` (top level or per
  rule), write a check-wide rule by omitting `subject`, and omit `expires` for a
  rule that does not expire. See `docs/operations.md`, "Accepting a risk".
- **An oversized or garbled collector version is analysed, not rejected.**
  1.2.0 exited 4 on a `collector_version` component too long for Python's
  integer parser. It is now UNKNOWN, like `unknown`: analysed with the
  untrusted-coverage caveats and a `warning:` line, never as current. The
  `COLLECTOR_VERSION_UNVERIFIED` note is a coverage note, so on its own it does
  not make `doctor --exit-code` exit non-zero.

### Fixed

- **Suppression keys are a closed set.** The top-level object may hold only
  `suppressions` and `metadata`; a rule only `check`, `subject`, `reason`,
  `expires` and `metadata`. Any other key exits 4 with a message naming it (and
  the intended key, for a case variant). An ignored `"Subject"` used to make a
  rule match every finding of its check, and an ignored `"Expires"` made an
  expired acceptance permanent.
- **`metadata` is the one free-form key.** It must be a JSON object; its
  contents are never interpreted, so a `subject` or `expires` inside it cannot
  change a rule.
- **A blank or `null` `subject` is refused instead of matching everything.**
  Omitting `subject` remains the only way to write a check-wide rule. `expires`
  is likewise either omitted or an ISO date string.
- **Suppression documents refuse repeated JSON keys** instead of silently
  applying the last value, which could broaden a risk acceptance.
- **Suppression JSON nested beyond the loader's guard** produces a normal data
  error (exit 4) instead of a traceback.
- **Suppression files accept the UTF-8 byte-order mark** written by Windows
  PowerShell, as collector JSON already does. Any other BOM is refused.
- **A number the JSON decoder refuses** (for example an integer of thousands of
  digits) is reported as `suppression file contains malformed JSON (...)`,
  not as a bare interpreter message.
- **Collector version components are capped at 9 ASCII digits** before they are
  converted, so a version with a longer component, or with no leading ASCII
  digit, is UNKNOWN whatever the interpreter's `int_max_str_digits` setting
  (previously `-X int_max_str_digits=0` could make a nonsensical version
  current). Only ASCII digits are read: a non-ASCII digit later in the version
  ends what is parsed (`0.13.٠` reads as `0.13`), which never makes a version
  more trusted.
- **A lone surrogate or other unencodable character in export text no longer
  crashes a report.** The text, HTML and `--narrate` outputs died with a
  `UnicodeEncodeError` traceback; the CLI now escapes such characters on output.
- **Warnings and version echoes escape control characters.** The expired-rule
  warning and summary, the stale-collector warning, the collector-version
  findings and the `ingest` summary (host, domain, collection time, version) now
  escape newlines and other control characters, so a value in a suppression file
  or an export manifest cannot start a forged `error:` or `warning:` line there.
  Other export text quoted inside report findings (names, hosts, paths) is still
  printed as collected.
- **Echoed input is bounded.** Duplicate and unknown key names, a bad `expires`
  value and the collector version are quoted to at most 80 characters in
  `error:` / `warning:` lines and coverage notes, with a marker naming how many
  were cut; a 100,000-character key used to produce a 100 KB stderr line.
- **A CDP/AIA object whose value does not parse no longer stops the run.** An
  unmodified export of a production CA exited 4 on `<file>.crl: not a DER CRL
  (... ShortData { needed: 1 })`: a CDP object whose `certificateRevocationList`
  value is a single byte. AD can hold such a value (some PKI management tools,
  PSPKI for one, write a single 0x00 byte into a CDP or AIA object that holds no
  CRL or certificate), so it is a fact about the estate, not a damaged export.
  It is now reported as one of the three findings below. Each names the object,
  the `certs/` file, the value's length and a class (single 0x00 byte, single
  byte, truncated DER, not DER, malformed DER), never the bytes. Every lifecycle
  check that needed the value is undecided, a value that is not a certificate
  decides no CRL tier, and `diff` treats the object as coverage lost (an older
  finding on it is not re-evaluated, never resolved) or, the other way, resolves
  `CRL_UNPARSEABLE` and labels a newly visible `CRL_EXPIRY` "first observed:
  coverage gained". `CA_CERT_UNPARSEABLE` is identified by its AIA object's
  objectGUID and the value's SHA-256 (one AIA object can hold several values,
  each its own finding), and resolves once a complete 0.13.0 or later export
  whose AIA values were parsed no longer holds that value on that object; a
  value still there is never resolved. The findings:
  - `CRL_UNPARSEABLE` (LOW): a CDP object's value does not load as a CRL. Its
    client impact is stated as fact only for a value no parser can load (one
    byte, cut short); for another encoding it is conditional on Windows
    rejecting the value too;
  - `CA_CERT_UNPARSEABLE` (LOW): an AIA `cACertificate` value is not a
    certificate (the collector's own loader rejected it, or no loader can read
    it). Collector 0.12.0 failed the whole AIA object instead, which left the
    `certs` container incomplete;
  - `CA_CERT_NOT_EVALUATED` (INFO coverage note, outside the `--exit-code`
    gate): the collector's loader read exactly these bytes as a certificate
    (its recorded `loader_sha256` matches), but adcs-lens cannot load them (a
    BER length, bytes after the certificate, a field it rejects).

### Documentation

- Added `docs/install.md`, `docs/operations.md`, `docs/handover.md` and
  `CONTRIBUTING.md`; rewrote the README's opening and status sections in plain
  language; added the trust and permission summary to `SECURITY.md`. Corrected
  stale statements: the README no longer lists `sqlite3`/XML parsing among the
  core's modules or calls the CA `owner_sid` capture unvalidated, and
  `AGENTS.md` no longer gives the JSON envelope as `schema_version` 3 (it is 4).

### Changed

- **Collector 0.13.0.** Each `certs/index.json` row records the length of the
  value it copied (`bytes`); an AIA row also records its AIA object's
  `object_guid` and, for a value its .NET loader read, `loader_sha256` (the
  SHA-256 of exactly those bytes: evidence of what the loader read, not
  integrity); and an AIA value the collector's loader cannot read is written
  as it is with `kind: null` instead of failing the AIA object. Ingest requires
  these from a 0.13.0 export and refuses (exit 4) what the collector cannot have
  written: a file whose length differs from `bytes`, an empty value, a
  `kind: null` value that loads as a certificate, a named kind on bytes other
  than the ones its loader read (a missing, malformed or different
  `loader_sha256` - so any value no loader reads, whatever its shape), a
  `loader_sha256` on a kind-null row, a kind it never writes
  (`other`), a file name other than its own (`{n:d2}-{file-safe cn}`), and an
  AIA objectGUID that is missing, malformed, under two cns, or split by another
  object's rows. No per-file integrity digest is recorded: see README "Exit
  codes".
- **The `certs/` structure is checked without the `[certs]` extra.** Every
  `certs/index.json` row must name a plain `certs/*.cer` (AIA) or
  `certs/*.crl` (CDP) file - never a path, a link or `index.json` - in a
  `certs/` that is not a link, that exists, is within its size limit and, from
  0.13.0, has its recorded length, the collector's name and well-formed AIA
  rows (objectGUID, kind). 1.2.0 checked files only when the extra was
  installed.
- **Older exports.** An export from a collector before 0.13.0 records no length,
  so a value AD holds cannot be told from a damaged file. Such an export keeps
  failing closed (exit 4, now with a message to re-copy the export or re-run
  collector 0.13.0), except for a single-byte value other than 0x30 - the
  placeholder's shape, which no truncated certificate or CRL can have - on a CDP
  object (or, from a collector before 0.10.0, an AIA object). That value is
  reported as above, with a caveat that damage after collection cannot be ruled
  out. The fail-closed behaviour for every other damaged export is unchanged.

## [1.2.0] — 2026-10-20

First release since 1.1.2 (2026-07-16). The version number 1.2.0 was prepared on
2026-07-28 but never tagged or published; everything below ships together as one
release. It is a GitHub Release only (not uploaded to PyPI).

### Upgrading from 1.1.2

This release changes behaviour that scripts and gates can see. Read this before
upgrading a scheduled job.

- **Re-run the collector.** `scripts/Export-AdcsEstate.ps1` is now **0.12.0**
  (1.1.2 shipped 0.7.0). The minimum collector the core accepts without a
  warning is now **0.8.0** (was 0.6.0). An older export is still analysed by
  `doctor`, with a warning and its gaps named as notes, but `diff` resolves or
  improves nothing on evidence from an export older than **0.10.0**: only
  collector 0.10.0 and later prove their reads. Exports from 0.8.0 to 0.11.0
  stay readable; some 0.12.0 checks name what an older export lacked (see
  `CA_COMPUTER_NOT_COLLECTED` and the template-name-flag note below).
- **Exit codes.** Any unreadable, partial or rejected export now exits **4** for
  every command (1.1.2 exited 1, the same code as a regression; a gate keyed on
  1 will no longer see a bad export as a failure of that kind, but it still
  never passes as 0). `diff --exit-code` now also exits **3** when there are no
  regressions but the newer export lost coverage (older findings or checks
  could not be re-evaluated); regressions still exit 1 and win. A finding that
  is newly visible only because the newer export gained coverage still exits 1.
  An invalid `ADCS_LENS_STALE_EXPORT_DAYS` exits 2. `doctor --exit-code` is
  unchanged (1 when a posture finding meets `--severity`; coverage notes are
  excluded).
- **JSON envelope `schema_version` 2 → 4**, shared by the `doctor` and `diff`
  envelopes. Every finding gains `sid`, `object_ref`, `variant` and
  `evidence_complete` (`object_ref` is `null` on estate-level notes). The `diff` envelope gains `first_observed`,
  `indeterminate`, `unevaluated` and `coverage_changes`, and `summary` gains
  `first_observed`, `indeterminate`, `unevaluated`, `coverage_changes` and
  `coverage_lost`. Degradation notes that appear or clear are listed under
  `coverage_changes`, no longer under `new` or `resolved`.
- **Drift buckets.** `diff` now reports four things besides new / resolved /
  worsened / improved: findings **first observed: coverage gained**, older
  findings **not re-evaluated**, checks **not re-evaluated**, and coverage
  changes (see Added). A finding is resolved only on a positive evaluation
  record; one that merely disappeared from the newer export because a pass was
  skipped, unreadable or incomplete is withheld, not resolved.
- **Stricter ingest.** An empty or mistyped export directory, or one with no
  `collector-manifest.json`, is an error (it used to ingest as an empty, clean
  estate). For a current collector, a missing file for a pass the manifest does
  not list as skipped, a missing or mistyped field, or a container whose
  completeness marker disagrees with its rows is an error. Join keys compare
  exactly; nothing is trimmed, case-folded or normalized to make a reference
  match.
- **More findings, and fewer false clean verdicts.** Trustee classification is
  now a high-privilege allowlist, so custom groups and named accounts count as
  low-privilege (new ESC1/ESC4/ESC5/ESC7 findings are expected on estates that
  grant Enroll or write rights to a purpose-built group). ESC5 now also covers
  the CA server's AD computer object. ESC1/ESC2/ESC3 findings on templates that
  require authorized signatures are capped at MEDIUM. A CRL or certificate the
  `[certs]` extra cannot fully read no longer aborts the run.
- **`[certs]` extra.** `cryptography` is now `>=50,<51` (was `>=43,<45`), to
  clear published advisories. Python 3.12 or later is still required.
- **Staleness notes on stderr.** `ingest`, `doctor` and `diff` print
  `EXPORT_STALE` / `EXPORT_TIMESTAMP_INVALID` notes on stderr (see Added).

### Security
- **Collector read-only gate (closed world).** `tests/test_collector_readonly.py`
  parses (never runs) `scripts/Export-AdcsEstate.ps1` with pwsh and fails CI on
  any change that is not reviewed. It pins an order-preserving serialization of
  the script's whole syntax tree plus a source digest
  (`tests/collector/collector-inventory.json`, regenerated only by
  `regen_inventory.py` after the semantic floor passes) and an exact semantic
  floor of hand-maintained pin tables: every command invocation and its
  argument vector, every .NET call and constructor, every variable binding of
  the write paths and credentials, every guarded write/exec/load/remote
  operation, each local function, and a per-statement digest that covers the
  statement's ancestor chain. Reviewers' bypasses (member dispatch through
  `ForEach-Object -MemberName`, `Get-WmiObject` extra parameters, redirections
  other than `2>$null`, reassigned or script-scoped write targets,
  `New-Item -Name`, `certutil` other than `-getreg <key>`, `New-Object`
  overloads that persist keys, caller-scope script blocks, case variants of
  names, UNC / URL literals) are each a regression case. The collector's
  `Assert-AdcsOutputPath` now runs before every file or directory it creates and
  throws unless the full path is inside `$OutDir` (no UNC or device path, no
  reparse point on the way). The input-read guard on the Python side also
  covers subpackages, an import allowlist, `os.*` other than `os.environ`,
  reflection, and indirect openers. The threat model's "Collector read-only
  gate" section lists what the gate does not prove.
- **Release and supply chain.** The token-based `publish.yml` is replaced by a
  tag-triggered `release.yml` (see Changed). `uv.lock` is committed; CI installs
  with `uv sync --locked`, checks `uv lock --check`, and a `supply-chain` job
  runs `pip-audit --strict` (pinned 2.10.1) over the locked export of every
  extra and group.
- **Fabricated action pins replaced.** The SHAs inherited from `publish.yml` for
  `actions/upload-artifact` v4.6.2, `actions/download-artifact` v5.0.0 and
  `pypa/gh-action-pypi-publish` v1.13.0 did not exist upstream. They are
  replaced with the real tag commits, and a new CI job, `verify-action-pins`
  (`scripts/verify_action_pins.py`, which parses workflows with PyYAML), fails
  when any `uses: o/r@<sha> # vX.Y.Z` pin is not exactly that tag's commit or
  lacks an exact version comment.
- **Input size limits and a data-error boundary.** See Added. A damaged export
  is a one-line `error:` and exit 4, never a traceback and never truncated.

### Added
- **Collector 0.8.0 to 0.12.0** (the collector went from 0.7.0 to 0.12.0):
  - **certs/ lifecycle pass.** Published CA certificates (AIA container
    `cACertificate`) and base CRLs (CDP container `certificateRevocationList`)
    are read from AD over plain LDAP, from any domain member (no `certutil`),
    and written as DER files plus `certs/index.json`. This captures the powered-
    off offline root's certificate and CRL, the catastrophic-but-invisible
    expiry case. Delta CRLs are skipped. Certificates whose CA matches no CA row
    (the offline root) are kept and still evaluated for expiry, signature and
    key size.
  - **Proven reads (0.10.0).** LDAP goes through
    `System.DirectoryServices.Protocols`; a container is marked `complete` only
    when every page returned Success and the final paging cookie was empty.
    `certutil -getreg` results are used only on exit code 0, and a failed read
    is JSON `null`, never an empty list. Each container has a completion marker
    in the manifest (`enumeration`) that must agree with the rows.
  - **objectGUID identity (0.9.0)**, template / endpoint / CA / DC / PKI-object
    identity keys, and the raw `msPKI-Certificate-Name-Flag` /
    `msPKI-Enrollment-Flag` values and the DCs' raw
    `StrongCertificateBindingEnforcement` / `CertificateMappingMethods` DWORDs,
    so the core decodes them with its own tables.
  - **Host attribution (0.11.0).** Every IIS endpoint row names its host, the
    manifest names the collector host's FQDN (`host_fqdn`), and each
    enrollment-service row carries `enrollment_service` and `ca_host_sid`.
  - **0.12.0.** The CA server's AD computer object is read as a `pki-acls` row
    of kind `ca_computer`; `msPKI-RA-Signature` is read as `ra_signatures`; IIS
    Extended Protection, `sslFlags` and authentication providers are read at the
    application and at its applicationHost.config location tag; each ACE
    carries `inherited` and `inherit_only` in DACL order; and the forest's
    dSHeuristics is read for BlockOwnerImplicitRights.
  - Every derived field (CRL tier, endpoint transports, template publication,
    certificate CA kind) declares its source containers; a missing or ambiguous
    source gives null (not obtained), never a default.
- **Multi-CA registry honesty.** CA registry hives (`EditFlags`,
  `InterfaceFlags`, `AuditFilter`, `DisableExtensionList`, `CA\Security`) are
  local to the collector host, so they are attributed only to the local CA
  (exact match on the `certutil` common name and DNS host). Every other
  enrollment service exports `registry_config_collected = false`; ESC6, ESC7,
  ESC11 and ESC16 skip those CAs and `CA_REGISTRY_NOT_EVALUATED` names them.
  This also removes a false ESC11 on every remote CA. A standalone CA, never
  present in Enrollment Services, is added when it is the local host, with
  `kind` derived from `CAType` (standalone root `root`, standalone subordinate
  `standalone`). An unread or unknown `CAType`, and any remote enterprise CA,
  has a null kind.
- **Detectors and notes.**
  - ESC5 on the CA server's computer object (CRITICAL, no exemption), including
    property-scoped takeover writes: `msDS-AllowedToActOnBehalfOfOtherIdentity`
    (RBCD) or its property set Account Restrictions, and `msDS-KeyCredentialLink`
    or DS-Validated-Write-Computer (variant `scoped-writeproperty`).
  - `CA_COMPUTER_NOT_COLLECTED` for an export older than collector 0.12.0.
  - `PKI_ACL_UNREADABLE`, the PKI-object analogue of the template
    `acl_obtained` marker: ESC5 skips the object and the INFO note names it.
  - `CA_HOST_ACCOUNT_UNRESOLVED`, `ENROLLMENT_ENDPOINTS_NOT_EVALUATED`,
    `COLLECTOR_VERSION_UNVERIFIED`, `PASS_NOT_COLLECTED`, a per-CA
    `CA_SECURITY_NOT_EVALUATED` for a CA with no `ca-security.json` entry, and
    `DC_REGISTRY_NOT_EVALUATED` for a DC registry pass that lists no DCs.
  - ESC8 is three-valued: flagged when what was read opens the relay path,
    clean when Extended Protection Require and HTTPS-only are both known, and
    undecided (with a per-endpoint note) otherwise.
  - ESC1, ESC2, ESC3 and ESC15 findings name which CAs publish the template,
    state when it is confirmed unpublished, or state that publication is
    unknown. Publication is context, not a gate, so an unpublished vulnerable
    template is still reported.
  - ESC1/ESC2/ESC3 findings on a template that requires one or more authorized
    signatures are flagged but capped at MEDIUM, naming the requirement.
- **Export staleness notes.** `EXPORT_STALE` when the manifest's `collected_at`
  is more than 8 days old (override with `ADCS_LENS_STALE_EXPORT_DAYS`, a plain
  positive integer from 1 to 36500 with no leading zero; anything else exits
  2), and `EXPORT_TIMESTAMP_INVALID` when `collected_at` is missing, unparseable,
  has no UTC offset, or is more than 5 minutes in the future. Both are INFO
  coverage notes in text, JSON, SARIF and HTML output (excluded from
  `--exit-code`) and are also printed on stderr by `ingest`, `doctor` and `diff`
  (both exports), so `--severity` cannot hide them. Export age equals
  collection age only if the collector host's clock was right; the 8-day
  default and the 5-minute tolerance are policy choices, not measurements.
- **Per-file input size limits** (`adcs_lens/limits.py`): the manifest 1 MiB,
  `certs/index.json` 16 MiB, every other export JSON file 64 MiB, each DER
  certificate 1 MiB and CRL 256 MiB, and the suppressions file 4 MiB. An
  oversized file is rejected (exit 4), never truncated. The limits are policy
  choices (table in the README).
- **`diff` evidence model.**
  - **Positive evaluation records.** Each detector decides every object of its
    subject type once per `(check, object[, variant])`; `diff` resolves an
    older finding only on such a record (or on a complete container together
    with GUID identity for an object that is gone). A skipped input, an
    incomplete container, an unobtained field, an unreadable descriptor or an
    unknown or stale collector version withholds the finding instead of
    resolving it. `Finding.evidence_complete` withholds an "improvement" that
    rests on weaker evidence (for example ESC15 with an unknown CA patch state).
  - **"Not re-evaluated" buckets.** `DriftReport.indeterminate` (an older
    finding the newer export could not re-evaluate, with the reason and the
    current severity when an improvement was withheld) and `unevaluated` (a
    check the older export decided that the newer one cannot, with object count
    and reason). Both set `coverage_lost`. They appear in text (a COVERAGE LOST
    banner and sections), JSON, SARIF (`adcsLensDrift: indeterminate`,
    `coverageLostReason`, run property `adcsLensCoverageLost`) and HTML.
  - **First observed: coverage gained.** A finding the older export could not
    have reported (a population its collector did not collect, or a check
    reading a field the two exports decoded with different tables) is reported
    apart from new findings, in all four renderers. It still fails
    `--exit-code` (exit 1).
  - **Stable identity.** Findings carry an `object_ref` (the objectGUID, plus `aliases`
    holding the legacy identifiers: template OID/cn, CA name, PKI DN, DC name,
    principal DN, endpoint, certificate SHA-256, CRL issuer+source; `null` on
    estate-level notes) and a `variant`; `diff` pairs findings on check, variant and
    object, never on text, so a reworded finding is a changed finding, not
    resolved plus new. Matching is one-to-one on objectGUID; an ambiguous
    identity is withheld (older side) or new (newer side). Certificates and
    CRLs absent from the newer index are withheld, not resolved. Per-host
    endpoint identity means a dedicated Web Enrollment server's endpoint is
    never resolved by an export from the CA host.
  - **Version gaps.** `model.POPULATION_VERSIONS` records which collector first
    exported each population, so diff across a gap withholds findings on
    populations the older export could not carry. Template name flags changed
    meaning in 0.12.0 (see Fixed): for an export older than 0.12.0, or of
    unknown version, the superseded table is re-applied, and ESC1 on a template
    whose two readings disagree on the enrollee-supplies-subject bits is
    undecided (not re-evaluated, with the reason, and its text says it may be a
    decoder artifact).
- **Ordered access check.** ESC1 to ESC5 evaluate a trustee's rights ACE by ACE
  in DACL order per [MS-ADTS] "Checking Object-Specific Access": an Allow
  reached before a Deny stays granted, a Deny reached first stays denied,
  inherit-only ACEs never count for the object itself, and scoped writes follow
  the object / property set / attribute tree. Broad rights (GenericAll,
  GenericWrite) count only through the components an earlier Deny left in
  effect. An OWNER RIGHTS (S-1-3-4) ACE replaces the owner's implicit rights,
  and on the CA computer object BlockOwnerImplicitRights is honoured (when
  dSHeuristics could not be read the finding says its evidence is incomplete).
  ESC7's `CA\Security` Deny handling and group-token expansion are not modelled
  (stated limits in `docs/threat-model.md`).
- **Architecture guards**: executable tests that no core module imports the
  narration layer and that the CLI reaches it only lazily.
- **Mutation gate.** `tests/test_mutation_gate.py` runs deterministic mutants of
  `detection.py` and the `normalize.py` helpers against a functional corpus;
  every mutant must change `diff`'s output or `evaluate()`'s verdicts, except
  listed equivalents. (Replaces the residual static guard.)

### Changed
- **Low-privilege trustee classification inverted to an allowlist**
  (`is_low_priv_trustee`): only the curated high-privilege set (built-in admin
  and operator groups, SYSTEM and service identities, Enterprise Domain
  Controllers, and the well-known domain RIDs: Administrator, krbtgt, Domain
  Admins, Domain Controllers, Cert Publishers, Schema/Enterprise Admins,
  Key/Enterprise Key Admins) is privileged. Everything else, including
  Everyone, Authenticated Users, Domain Users/Computers, **custom groups and
  named accounts**, is low-privilege. The old blocklist missed custom groups
  (Enroll granted to a purpose-built group produced no ESC1 finding, a
  domain-compromise-class false negative). The new direction fails toward
  flagging; the `ACL_GROUP_TOKEN_CAVEAT` estate note documents both honesty
  boundaries (no group-token expansion, allowlist classification). Enterprise
  Read-only Domain Controllers (-498) is deliberately not on the allowlist.
- **ESC5 on the CA computer object.** Both findings below are CRITICAL.
  - `NT AUTHORITY\SELF` writing `msDS-AllowedToActOnBehalfOfOtherIdentity`
    (`scoped-writeproperty`) has its own text: the CA host's own
    authentication, coerced and relayed to LDAP, can write resource-based
    constrained delegation and take the host over; domain controllers that
    enforce LDAP signing and channel binding block the relay, which this
    collector does not read, so the finding cannot be cleared from the export.
    An inherited ACE adds that the fix is at the parent container (a Server
    2025-generation domain carries it on every computer object). An
    inherit-only SELF ACE does not apply to the object and is ignored.
  - An unresolved trustee SID holding control (`dacl`) says the collector did
    not resolve a friendly name (a deleted principal, a foreign or trusted
    domain, or a failed lookup), that the ACE is a takeover path if the SID is
    reachable, and to verify the SID's domain and retry.
  - **Behaviour change:** an unnamed `S-1-5-21-` trustee SID is low-privilege on
    the CA computer object whatever its RID (a foreign domain's Domain Admins
    was a false negative), so whether a privileged-RID trustee produces a
    finding there depends on the collector's best-effort name lookup, and a
    transient lookup failure can show in `diff` as a new or worsened ESC5. A
    named privileged trustee stays clean; every other object is unchanged.
- **ESC5 no longer flags the CA's own computer account** on its own
  enrollment-service object. The collector resolves each service's CA host
  account (the one computer object whose `dNSHostName` is identical) into
  `ca_host_sid`, set only on rows the Enrollment Services search returned
  (`enrollment_service: true`); ESC5 exempts it on that object only. When it
  cannot be resolved, the object is undecided whenever anything low-privilege
  controls or owns it, and `CA_HOST_ACCOUNT_UNRESOLVED` names it.
- **`MIN_COLLECTOR_VERSION` 0.6.0 to 0.8.0** (now defined in `adcs_lens.model`;
  `adcs_lens.ingest` still exposes it). `Manifest.collector_version_status` is
  derived from `collector_version`. An unknown, missing or unparseable collector
  version is never treated as current: it emits `COLLECTOR_VERSION_UNVERIFIED`
  and the stderr warning, and withholds everything in `diff`.
- **Template publication state is explicit.** Ingest records whether
  `enrollment-services.json` was present and valid, separating a missing export
  (publication unknown) from a present empty one (all templates confirmed
  unpublished). `ORPHANED_TEMPLATE` skips only when the file is absent.
  Mappings must be arrays of strings; blank names are ignored; publisher names
  are de-duplicated and sorted. A declared skip takes precedence over a leftover
  file for `enrollment-services` and `certs`.
- **`ingest` and `LIFECYCLE_NOT_EVALUATED` name why lifecycle was not
  evaluated:** the `[certs]` extra is not installed or could not be imported
  while the export lists certificates; the certs pass was skipped; there is no
  `certs/index.json`; or the index is empty (an empty index wins over a missing
  extra). Finding identity does not change.
- **Collector.** An unset `CA\AuditFilter` is 0 (auditing off, per [MS-CSRA]),
  so `CA_AUDIT_DISABLED` fires instead of `CA_AUDIT_NOT_EVALUATED` (a failed read
  stays null). CES/CEP endpoint classification requires the `_CES_` / `_CEP_`
  infix or an exact `cep` path segment (a substring match false-matched
  `/concept`, `/reception`). The `ca-security` pass is marked skipped when no
  local CA security descriptor was read. A collector run that returns an object
  without a required attribute counts it as an object failure (the container is
  incomplete) instead of writing a coerced `''` or default. All scripts are pure
  ASCII (PS 5.1 BOM-less parse safety), pinned by a Pester test.
- **Joins compare exactly.** No join (publication, certificate to CA, CRL tier,
  CA\Security and publisher to CA, template to OID object, local-CA match)
  trims, case-folds or Unicode-normalizes a key to make it match. A reference
  matches only when exactly one key is identical and no other key folds to it
  (NFKC, trim, case-fold); otherwise the joined field is not obtained, the
  dependent check is undecided, and `diff` reports it not re-evaluated. Two CA
  names that fold together are an ingest error. The joins and their zero- and
  multi-match behaviour are declared in the collector (`$JOINS`) and tied to
  `model.JOIN_KEYS` by test.
- **Metadata and docs.** The pyproject URLs, the README install URL, the
  SECURITY.md advisory link and the SARIF `informationUri` now name the real
  owner, `hraedon-labs` (they said `hraedon`); a test pins every URL to
  `publication.toml`. AGENTS.md no longer says the collector is "to be built"
  or that tests use real-export numbers.
- **Release workflow.** `release.yml` requires the tag, the pyproject version
  and the CHANGELOG top entry to agree (with `[Unreleased]` empty) and the tagged
  commit to be on `main`; re-runs `ci.yml` through `workflow_call`; builds the
  sdist and wheel twice with `SOURCE_DATE_EPOCH` and compares them byte for byte;
  install-smokes the wheel from hash-checked locked requirements; writes
  `SHA256SUMS`; attests build provenance; and creates the GitHub Release. The
  PyPI upload uses Trusted Publishing and runs only when repository variable
  `PYPI_PUBLISH == 'true'`. Owner steps are in `docs/releasing.md`. The build
  backend is locked in a new `release` dependency group, and the sdist has an
  explicit include list (and ships everything its own test suite reads;
  `tests/test_sdist.py` builds it and runs that suite).
- **Shared code.** `_finding_with_consequence` is deduplicated into
  `consequences.finding_with_consequence` so the display and narration layers
  cannot drift (WI-043). SARIF renderers read the structured `sid` instead of
  extracting a SID from the detail text (WI-042).

### Fixed
- **ESC16 false negative on real data.** `_parseCertutilMultiSzLines` returned
  certutil's `N:` index tokens instead of the values, so the SID-extension OID
  never reached `disabled_extensions`. It now reads the real layout, skips the
  `CSURL_*` flag lines, reads an empty value as an empty list, returns null for
  any layout it does not know, and keeps only the OID when certutil appends a
  friendly name.
- **IIS endpoints were not attributed to a host.** A non-CA IIS host reported a
  complete, empty endpoint list, so `diff` could resolve an ESC8 finding. Endpoints
  now name their host (part of their identity) and the list is complete only when
  the collector host is the only CA host and the CA list is complete; hosts compare
  as whole ASCII DNS names, and a name the parser does not support matches nothing
  yet still counts as a rival for a short name. `diff` resolves an endpoint
  finding only when the newer export read that endpoint's host. This applies to
  0.10.0 exports too.
- **IIS Extended Protection and `sslFlags` read as `none` / `false`.** On a CA
  host these live in applicationHost.config `<location>` tags; collector 0.11.0
  exported `Require` / `Ssl, Ssl128` as `epa: none`, `ssl_required: false`
  (two false ESC8 HIGH findings that a real fix could never resolve). Each of
  `enabled`, `tokenChecking` and `sslFlags` is now read at the application path and
  at its location tag, decoded strictly, and kept only when both scopes agree;
  anything else is null and the `web-endpoints` marker is incomplete. EPA
  `unknown` no longer fires ESC8, and `SslNegotiateCert` alone no longer reads as
  SSL required.
- **The CA server's AD computer object was never collected**, so GenericAll on it
  produced no ESC5 finding. It is now collected and rated (see Added).
- **ESC1/ESC2/ESC3 ignored `msPKI-RA-Signature`** (see Added; null when not
  returned or invalid, never 0; an unread value is treated as none and says so).
- **Template name flags decoded per [MS-CRTD] 2.28.** Several
  `msPKI-Certificate-Name-Flag` bits were shifted: 0x00010000, the real
  `ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME` (an ESC1 input), decoded as
  `SUBJECT_ALT_REQUIRE_DOMAIN_DNS` (an ESC1 false negative on a SAN-only
  template), and 0x00000008, a renewal flag, decoded as the SAN flag (an ESC1
  false positive). The table lists all 13 flags exactly as the specification
  does; 0x1 was always right.
- **Unset `CA\AuditFilter` was exported as null** (see Changed).
- **`diff` reported coverage loss as resolution.** A newer export that skipped
  `template-security` and `ca-security` listed ESC4/ESC7/ESC9/ESC15 as resolved
  and `diff --exit-code` passed. Resolution is now withheld for every degradation
  path (skipped or missing passes, unreadable DACLs, uncaptured owners, CAs whose
  registry was not collected, unparsed lifecycle data, DCs with unknown binding
  enforcement, an unknown or stale collector version, and others); the map is
  `detection.coverage_gaps()`.
- **Absence in an incomplete container no longer produces a verdict.** No visible
  publisher in an incomplete enrollment-services list is not ORPHANED_TEMPLATE;
  an incomplete CA list cannot make ESC15 "unknown" or clean; an incomplete OID
  or DC container leaves ESC13 and ESC14 undecided. A DC returned without
  `dNSHostName` is kept as a placeholder with null deciding fields instead of
  being skipped. Findings backed by visible evidence are kept.
- **Coverage markers are strict.** `acl_obtained`, `registry_config_collected`,
  `ssl_required` and `windows_auth` must be JSON booleans (a string `"false"`
  used to read as True); unknown names in `skipped_passes` and a non-string
  `collector_version` are errors. Arrays must be arrays of strings in every
  export. Duplicate JSON keys, a blank identity or join key, a duplicate CA name,
  an enrollment-services entry with no enterprise CA row (or the reverse) and a
  CA\Security entry naming no CA are errors.
- **A certificate the library cannot fully read** (an unknown signature
  algorithm, Ed25519/Ed448 without a separate hash, an unsupported key type, a
  malformed or duplicated extension, an unreadable date) raised
  `UnsupportedAlgorithm` and exited with a traceback. Each field of a
  certificate or CRL is now derived separately; one the library cannot read is
  recorded in `CertLifecycle.unobtained`, only the checks reading it are
  undecided (never a guessed weak or strong), and the rest is still evaluated.
  Only bytes the library cannot load at all reject the export.
- **Damaged exports** (not UTF-8 or UTF-16, a lone BOM, NUL, truncation, wrong JSON
  type or shape, nesting too deep, larger than the limit, a garbage DER file)
  are a one-line `error:` and exit 4 for every command; an invalid-UTF-8 manifest
  used to exit 1 with a traceback. Malformed DER and invalid UTF-8 are an
  `IngestError`.
- **Joins could attach to the wrong object.** A published template whose cn is a
  dotted value equal to another template's OID attached the publisher to both,
  and an enrollment service whose `certificateTemplates` held `" Name "`
  published template `Name`; either let `diff` report a false clean verdict.
  Closed by the exact-join rule (see Changed). A small certutil DWORD printed
  without a parenthesised decimal (`AuditFilter REG_DWORD = 0`) no longer parses
  as "not captured".

### Removed
- `publish.yml` (the token-based PyPI workflow), replaced by `release.yml`.
- `diff`'s resolve-on-absence rule: in 1.1.2 a finding missing from the newer
  export was reported resolved. It is replaced by the evaluation records above.
- Python API: `diff.diff_findings(..., incomplete_checks=)` is replaced by
  `diff_findings(..., coverage=detection.coverage_gaps(newer_estate))`, and
  `diff.incomplete_coverage_checks` is removed. (The CLI is the supported
  interface; this only affects code that imported `adcs_lens.diff`.)

### Validated
Live validation was run against a lab Windows Server 2025 domain (placeholders
`<CA-HOST>`, `<MEMBER>`, `<DC1>`); evidence is kept by the operator outside the
repository, and the plan is `docs/live-validation-plan.md`.
- **Collector 0.10.0 LDAP layer (2026-10-12, from a non-CA domain member).**
  Enumeration markers, objectGUIDs, template attributes, template and PKI-object
  ACEs and owners, AIA and CDP certificate and CRL bytes (SHA-256), and the
  multi-CA registry honesty path matched independent ADSI and `openssl` reads. Four
  defects were found and fixed in 0.11.0 (the multi-string registry parser, IIS
  host attribution, the unset AuditFilter, and ESC5 on the CA's own account).
- **Collector 0.11.0 on the CA host (2026-10-13).** The read-only proof (LDAP
  snapshot and CA database unchanged; the one CertSvc registry difference was
  the plan's own audit step), the local-CA path, the ESC5 own-account exemption,
  the privilege contexts (0 credential-leak hits across all export and transcript
  files), ESC10 DC registry values, multi-page paging (620 OID objects), and most
  seeded ESC1-ESC11, ESC14-ESC16 and hygiene cases passed. Three defects were
  found and fixed in 0.12.0 (the IIS location-tag read, the CA computer object, and
  authorized signatures).
- **Collector 0.12.0 on the CA host (2026-10-14/15).** The IIS endpoint fix, the
  resolution of ESC8 after restoring the configuration (D3), the CA computer
  object ESC5 findings and their scoped-write sub-cases, and authorized
  signatures passed, as did the version-gap rows. Both diff directions exited 1,
  not 3: the older export carried real regressions, which take precedence.
- **Not proven live:** ESC13 in the 2026-10-13 run (the OID object could not be
  created; earlier lab validation covers it), inherit-only ACEs (partial), and
  the absent-AuditFilter read path (covered by unit and simulated tests).
  Everything in 0.12.0 beyond the cases above is tested against simulated and
  recorded input only.
- Observations, not defects: `doctor` says nothing about an issuing CA's root not
  being published in AD (no detector models issuer publication), and ESC8 treats
  Negotiate as NTLM-capable by rule, also on a Kerberos CES instance.

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
