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
- **Review round 11 follow-up: a certificate the library cannot fully read.**
  - **The class (both reviewers, round 11):** a structurally valid DER
    certificate whose signature algorithm the library does not know raised
    `UnsupportedAlgorithm` out of `certs.py` - a traceback and exit 1 for
    every command - because the boundary caught `ValueError` only.
  - **Fix:** `certs.py` derives every field of a loaded certificate or CRL
    separately (`_derive`); any library exception for one field (an unknown
    signature OID, Ed25519/Ed448 with no separate hash, an unsupported or
    unknown key type, a malformed or duplicated extension, an unreadable
    date) records that field in the new `CertLifecycle.unobtained`, so only
    the checks reading it are undecided - never a guessed weak or strong -
    and the rest of the certificate is still evaluated. Only bytes the
    library cannot load at all (`UnparseableDer`) reject the export (exit 4).
  - **Collector:** an unread CAType maps to a null kind like an unknown one
    (the comment still claimed `issuing`).
  - **Tests:** `tests/test_cert_algorithms.py` generates certificates for every
    key type and signature algorithm the library signs with (RSA incl. PSS,
    EC P-256/384/521, DSA, Ed25519, Ed448, SHA-1 by OID swap) plus hand-edited
    DER (unknown signature OID, unknown key OID, duplicated extension) and
    CRLs of each algorithm, through ingest, doctor and diff: no traceback, the
    expected fields not obtained, exactly their checks undecided, weak values
    still flagged. `tests/test_reviewer_probes_r11.py` replays both probes
    (fail at 2977888).
- **Review round 10 follow-up: one key comparison; every bad export is exit 4.**
  - **One fold, one language (Sol round 10):** the collector folded keys with
    `ToLowerInvariant`, which is not the core's Unicode case fold (`Straße`
    and `STRASSE` are one name under `str.casefold`), so it resolved a CRL
    tier the core would call ambiguous and diff resolved the older CRL
    finding (exit 0). The collector now folds nothing: it writes each CDP
    object's cn verbatim (`ca_name` in certs/index.json) and ingest derives
    the tier with `normalize.resolve_join` against the AIA rows, only when
    the certs marker is complete. The local-CA match is an exact `-ceq`; a
    near match leaves both rows for ingest, which rejects two CA names that
    fold together. A test fails if the collector regains a folding helper.
  - **Data-error boundary:** every way an export file can be damaged - not
    UTF-8 (or UTF-16), a lone BOM, NUL, truncation, the wrong JSON type or
    shape, nesting too deep, larger than 256 MB, an unreadable or garbage
    DER file - is a one-line `error:` and exit 4 for every command, never a
    traceback (an invalid-UTF-8 manifest exited 1 with a traceback). A parser
    fault on untrusted input that escapes a specific check is reported as a
    rejected export.
  - **Collector:** an unknown CAType value is a null kind (not obtained),
    no longer a guessed `issuing`; `_schemaCheck` throws for a container with
    no schema instead of requiring nothing. `certs.parse_crl` is typed for a
    null tier.
  - **Tests:** `tests/test_export_corruption.py` corrupts every file of a full
    export in 7 to 13 ways and runs ingest, doctor and diff (both sides) on each
    (173 cases; 73 fail at c66f4d2). `tests/test_reviewer_probes_r10.py`
    replays both of Sol's probes (all fail at c66f4d2). Ingest tests cover
    the Unicode case-fold twin (ß / SS), case, whitespace and fullwidth.
- **Review round 9 follow-up: join keys compare exactly.**
  - **The class (Sol round 9):** ingest trimmed every key before joining, so
    an enrollment service whose certificateTemplates held `" LabWebServer "`
    published template `LabWebServer`, and diff resolved its ORPHANED_TEMPLATE
    on that false clean verdict (exit 0). MS-WCCE defines each value as
    identical to the template's cn and the CA issues only for an identical
    match.
  - **Rule:** no join trims, case-folds or Unicode-normalizes a key to make it
    match. `normalize.resolve_join` (and `_uniqueMatch` in the collector)
    matches a reference only when exactly one key is identical to it and no
    other key folds to it (NFKC, trim, case-fold); a reference that only folds
    to a key is ambiguous, so the joined field is not obtained. A reads-proven
    export's strings are kept exactly as read; a string list holding a value
    with surrounding whitespace is not obtained. Applied to publication, cert
    -> CA (a near-match leaves the certificate unattached), the CRL tier
    lookup (an ordinal dictionary instead of a case-insensitive hashtable),
    CA\Security and publisher -> CA (exact), template -> OID object (ESC13
    undecided) and the local-CA match (`-ceq`; a near match is a remote CA,
    and the standalone fallback no longer adds a second row beside it).
  - **`$JOINS` is tied to the code:** the core reads every join key from
    `model.JOIN_KEYS`, and a test checks the table's keys and comparison
    against that and against the `# join: <name>` markers in the collector.
    The derived-field table no longer describes the old "oid or cn" join.
  - **CA names folding together** (case, spaces, NFKC) are an ingest error for
    every collector version, not only current ones.
  - **Exit code 4** for an export that cannot be read or is rejected, for
    every command (it was 1, the regression code). Still never 0, so a gate
    fails closed; argparse usage errors keep 2.
  - **Tests:** every join has case / whitespace / Unicode reference variants
    beside the twin, run through the real collector (no verdict moves, relying
    checks not re-evaluated, exit 3; CA-row twins are rejected).
    `tests/test_reviewer_probes_r9.py` replays Sol's probe (fails at cca7c03).
  - **Mutation gate:** a `normalize` mutant now reaches every name the
    detector imports from `normalize` (it rebound only `is_low_priv_trustee`
    and `normalize_sid`, so mutants of any other helper survived unseen); the
    corpus gains exact, near-only and absent issuance-policy OID joins.
- **Review round 8 follow-up: a join proves one object answers.**
  - **The class (Sol round 8):** ingest attached a publication reference to
    a template by "OID or cn" without proving one template answered. A
    published template whose cn is a valid dotted value equal to another
    template's OID attached the publisher to both, and diff resolved the
    second template's ORPHANED_TEMPLATE on that false clean verdict (exit 0).
  - **`$JOINS`** in the collector lists every join between objects (in the
    collector, ingest or a detector) with the keys it compares and what a
    reference matching no object, or several, yields: publication, cert ->
    CA, CRL tier lookup, CA\Security -> CA, publisher -> CA, template ->
    OID object (ESC13) and application -> site. Several matches never attach
    to an arbitrary one: the joined field is not obtained for every match, or
    the export is rejected.
  - **Publication:** `certificateTemplates` lists template common names, so a
    0.10.0 export joins on cn only (trimmed, case-insensitive). Older exports
    still try the OID too, and a reference must then match one template
    across both. A reference matching several templates leaves
    `published_by` not obtained for each: ORPHANED_TEMPLATE is undecided and
    the finding text says the publication state is unknown.
  - **CA names:** two CA rows whose names differ only in case are an ingest
    error; certificates join their CA ignoring case (as AD compares cn).
  - **ESC13:** an issuance-policy OID matching more than one OID object is
    undecided (ingest already marks `oid-objects` incomplete).
  - **Tests:** `tests/test_object_schema.py` requires every join to declare its
    keys and its zero- and multi-match behaviour, and runs the real collector
    with one ambiguity per join (a case-variant twin): no verdict moves, each
    relying check the baseline decided is not re-evaluated, exit 3 (or an
    ingest error for CA-name joins). The simulated LabUser now carries the
    linked issuance policy, so ESC13 is decided in the baseline.
    `tests/test_reviewer_probes_r8.py` replays Sol's probe (fails at 2c5f181);
    test fixtures publish templates by cn, as the collector does.
- **Review round 7 follow-up: a derived field names its sources.**
  - **The class (Sol round 7):** the collector set each CRL's `tier` from a map
    of the AIA certificates an earlier loop serialized, defaulting to
    `issuing` on a miss. A partial AIA read turned a root CRL into an issuing
    one under a complete `crls` marker, CRL_EXPIRY declared only `crls`, and
    diff reported a verified critical -> high improvement.
  - **Provenance table:** `$DERIVED_FIELDS` in the collector records every
    field derived from another object or container: `crl.tier` (AIA certs),
    `endpoint.transports` (the IIS site's bindings), `template.published_by`
    (enrollment services, joined in ingest) and `cert.ca_kind` (the CA row,
    joined in ingest), each with its source containers, join and what a miss
    yields. A source that is incomplete, or a lookup that misses, yields null
    (not obtained), never a default; every check reading the field declares
    the source containers (CRL_EXPIRY now depends on `certs`).
  - **Collector:** a CRL's tier is null unless the AIA enumeration was complete
    with every object serialized and one unambiguous certificate kind matched;
    a site whose bindings read nothing gives endpoints null `transports`; a
    remote enterprise CA's `kind` is null (it may be a root: CAType is read on
    the CA host) instead of `issuing`; a certificate that does not parse is an
    object failure instead of kind `other`. The certs / crls markers compare
    objects returned with objects serialized and count rows separately, so a
    failed AIA object reads "0 of 1", not "0 of 0".
  - **Ingest / detection:** a null CRL tier is not obtained (the key is still
    required); a CA whose registry was not collected must carry a null kind.
    CRL_EXPIRY reports an unknown tier at the issuing severity with an
    unusable verdict (never raised to root on a guess, never an improvement
    over an older root reading); ESC15 counts a CA of unknown kind as one that
    may issue. Publication text names an incomplete enrollment-services list.
  - **Tests:** `tests/test_object_schema.py` fails when a declared detection
    input has no single source (schema attribute, own-object read, or
    `$DERIVED_FIELDS`), when a check reading a derived field omits a source
    container, and when the collector body looks objects up in a map not
    declared; it runs a source-loss case per derived field (no verdict moves;
    every relying check the baseline decided is not re-evaluated; exit 3). The
    corruption matrix's DER now holds a root CRL inside its warning window and
    an issuing certificate. `tests/test_reviewer_probes_r7.py` replays Sol's
    probe (fails at 2ba72dd).
- **Review round 6 follow-up: one table of what an object must carry.**
  - **Collector:** `$OBJECT_SCHEMA` declares, per container, each requested
    attribute's type, the export field it feeds and its need (required,
    optional, placeholder, security descriptor). `_requireSchema` runs on every
    returned object: a missing required attribute, an empty value or a wrong
    type (a multi-valued cn, a GUID that is not 16 bytes, a non-integer flag)
    is an object failure counted by the container's marker, never a coerced
    `''` or default. An enrollment service returned without `cn` (Sol round 6)
    was written under the key `''` with both markers complete, ingest skipped
    the blank publisher, and diff reported a false ORPHANED_TEMPLATE
    regression (exit 1); it now marks `enrollment-services` and `ca-config`
    incomplete (exit 3). The standalone-CA fallback no longer runs when an
    enrollment-service object failed.
  - **Ingest:** never skips or coerces an identity or join key of a
    reads-proven export. `REQUIRED_KEYS` (mirrored from the schema) must be
    non-blank strings, including a certificate's `kind` and a CRL's `tier`;
    duplicate JSON keys, a blank publisher or template reference, two
    publishers trimming to one name, an enrollment-services entry with no
    enterprise CA row (or the reverse), a duplicate CA name and a CA\Security
    entry naming no CA are errors; an empty element in a string list is an
    error; two OID objects sharing an OID make `oid-objects` incomplete.
  - **diff:** `UnevaluatedCheck.objects` counts objects, not verdict variants
    (ESC4's three variants on one template are one object). The text and HTML
    summaries count the unevaluated checks, the COVERAGE LOST line names them,
    the HTML report never says "No drift" when a check was not re-evaluated,
    and SARIF carries `adcsLensCoverageLost`.
  - **Tests:** `tests/test_object_schema.py` checks the schema against
    `REQUIRED_KEYS` and the inputs `detection.CHECKS` declares, then runs the
    real collector body (simulated transports, real DER for AIA/CDP) once per
    container x attribute x {missing, empty, wrong type}: 97 runs, each with
    the container incomplete (or the DC placeholder), ingest accepting the
    export, no new, resolved or worsened finding, only checks reading that
    container not re-evaluated, and exit 3. `tests/test_reviewer_probes_r6.py`
    replays Sol's probe (fails at 4b4903b). Test fixtures that wrote an
    enterprise CA with no publication entry (impossible from the collector)
    were corrected.
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
