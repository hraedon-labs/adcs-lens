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
    identical verdict (replacement / multi-edit probes are not name-swapped).
    Seven probes (five caller-scope rebinds, two case variants) were admitted
    by the bac9359 floor and are now rejected. The input-read guard also refuses the indirect openers `argparse.FileType` and
    `importlib.import_module` (Sol E5 / DeepSeek N3-2), with regression cases.
  - **Round-4 hardening (constructor and call overloads).** Every admitted
    `New-Object` constructor is pinned by its exact argument vector
    (`NEW_OBJECT_VECTORS`), so an allowlisted type reached through another
    overload — e.g. an `X509Certificate2` PFX constructor with persist-key flags,
    which writes to a key store outside the output directory — is refused; and
    every constructor call is a guarded operation pinned with its context. Every
    .NET method call (static and instance) is pinned as an exact multiset of
    receiver, method and full argument vector (`PINNED_MEMBER_CALLS`), so an
    allowlisted method with a different argument count, flag or path, or an
    extra call, fails. `[Type]::new(...)` and cast construction remain refused
    by the static-member and type allowlists. The input-read guard now checks
    the imported symbol of every `from X import name as alias`. The PFX
    constructor, an extra allowlisted call and the aliased `FileType` import
    were admitted at ec14759 and are now rejected. The DeepSeek round-2
    expectations gained checks on 59 cases; none lost one.
    `tests/collector/print_pin_candidates.py` prints candidate pin tables for a
    reviewed rebuild (it never writes a file).
  - **Integration with collector 0.10.0.** The gate's pins were rebuilt for the
    System.DirectoryServices.Protocols collector (reviewed entry by entry; the
    admitted types and members are listed in the integration commit), and the
    gpo-lens round 5-7 lessons were ported: every command invocation is pinned
    (text, count, context); every variable in a command or .NET-call argument or
    a branch/loop condition is binding-pinned; a secret-taint table restricts
    credential-bearing variables to their established sites; UNC / `//host` /
    URL forms are refused in arguments and binding values; variable-writing
    common parameters are also resolved through cmdlet metadata; and the script
    header / param block is digest-pinned. The dumper takes one AST traversal per
    file and the gate dumps in parallel batches.
  - **Integration review r1 (Sol B1) + structural closure.** `switch -File` /
    `-Regex` and `foreach -Parallel` flags are refused (the semantic projection
    now carries every statement flag, not only foreach's). REMOTE_LITERALS
    refuses any UNC / `//host` / `\\?\` / `scheme://` string literal anywhere
    in the script (not only in command/.NET arguments), with a committed
    exemption list. A semantic-projection completeness meta-test requires every
    (AST node type, serialized property) to be inspected or declared inert. And
    STATEMENT_DIGESTS pins the normalized-AST-subtree digest of every statement
    (subsuming the per-function body pins), so any edit anywhere fails the floor
    until a human updates the hand-maintained table. verify_action_pins also
    handles multi-document workflows, with committed annotated-tag unit tests.
  - **Integration review r2 (Sol B1): ancestor-chain digests + a product write
    guard.** STATEMENT_DIGESTS keyed only a statement's own subtree by numeric
    path, so wrapping the whole script body in `begin`/`process`/`end`/`clean`
    left every digest unchanged. Each digest now also covers its full ancestor
    chain (node types, roles, `NamedBlockAst.BlockKind` / `Unnamed` and other
    non-child properties, conditions, param blocks, attributes), with a
    meta-test that mutates each ancestor property kind. The collector now calls
    `Assert-AdcsOutputPath` before every file or directory it creates: it
    resolves the full path and throws unless it is inside `$OutDir`
    (case-insensitive, separator-normalized, no UNC / device path, no reparse
    point on the way), with Pester tests. The gate's new `[write-guard]` rule
    requires that guard on each sink's exact target, so a traversal returned by
    a helper such as `_safeFileName` is refused at runtime, not only by the
    digest. The input-read guard also refuses `from sys import modules` and
    aliased `os` / `sys` / `importlib` imports.
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
- **2026-10-13 live-validation defects (collector 0.12.0; 3d9e13a, 165cf79,
  62272ae).** The three defects the live run of collector 0.11.0 found (see
  Validated below). The fixes are tested against simulated and recorded input
  only; the live re-checks are listed in `docs/live-validation-plan.md`.
  - **IIS Extended Protection and sslFlags (ESC8, case D3).** On the CA host
    the Web Enrollment and CES apps keep `extendedProtection tokenChecking` and
    `access sslFlags` in applicationHost.config `<location>` tags; collector
    0.11.0 exported a `Require` / `Ssl, Ssl128` endpoint as `epa: none`,
    `ssl_required: false` - two false ESC8 HIGH findings that a real fix could
    never resolve. It dereferenced `.Value` on every
    `Get-WebConfigurationProperty` result; the Boolean and the providers
    collection read correctly from the same path, the enum and flags values did
    not, and the empty result was mapped to `none` / `false`. Each of
    `enabled`, `tokenChecking` and `sslFlags` is now read at the application
    path and at `-PSPath 'MACHINE/WEBROOT/APPHOST' -Location '<site>/<app>'`,
    decoded strictly (a bare value or a wrapper's `Value`; documented names and
    numbers only), and kept only when both scopes agree. Anything else is null
    and names both readings in the `web-endpoints` marker (incomplete). ESC8 is
    three-valued: flagged when what was read opens the relay path, clean when
    Require + HTTPS-only are both known, otherwise undecided with a
    per-endpoint `ENROLLMENT_ENDPOINTS_NOT_EVALUATED` note. EPA `unknown` no
    longer fires ESC8, and `SslNegotiateCert` alone no longer reads as SSL
    required. The gate pins the three IIS reads as exact vectors; the
    location read's `-PSPath` must be the literal local config path.
  - **The CA server's AD computer object (ESC5, case B3).** GenericAll on it
    produced no finding: its descriptor was never read. SpecterOps' "Certified
    Pre-Owned" lists the CA server's AD computer object among the ESC5 objects
    (the whitepaper, p. 70: "The CA server's AD computer object (i.e.,
    compromise through S4U2Self or S4U2Proxy)"; the 2021-06-17 blog post words
    the parenthetical "i.e., compromise through RBCD"). The collector now reads the
    descriptor (DACL + owner) of each CA host computer object it resolves for
    `ca_host_sid`, as a `pki-acls` row of kind `ca_computer`; ESC5 rates it
    CRITICAL and exempts no account on it (the WI-044 exemption stays on the
    enrollment-service object only). An unresolved or unreadable CA host
    computer object leaves `pki-acls` incomplete.
  - **Authorized signatures (ESC1 / ESC2 / ESC3, case A1d).** The collector
    reads `msPKI-RA-Signature` ([MS-CRTD] 2.18; not "msPKI-RA-Signature-
    Policies", which does not exist) into `ra_signatures`, null when not
    returned or invalid, never 0. A template requiring one or more
    authorized signatures is still flagged but capped at MEDIUM, naming the
    requirement and the enrollment-agent (ESC3) dependency; an unread value is
    treated as none (full severity) and said so. Ingest requires the field from
    collector 0.12.0.
  - **Template name flags decoded per [MS-CRTD] 2.28** (found while
    verifying the RA attribute, not by the live run). Several
    `msPKI-Certificate-Name-Flag` bits were shifted: 0x00010000, the real
    `ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME` (an ESC1 input), was decoded as
    `SUBJECT_ALT_REQUIRE_DOMAIN_DNS` (an ESC1 false negative on a SAN-only
    template), and 0x00000008, `OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME` (a
    renewal flag), as `ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME` (an ESC1 false
    positive). The table now lists all 13 flags exactly as the specification
    does. The 0x1 flag (`ENROLLEE_SUPPLIES_SUBJECT`), the one every live ESC1
    case used, was always right.
  - **Review round 1 of these fixes (Sol, DeepSeek).**
    - *Exports older than collector 0.12.0 did not collect the CA computer
      objects* (`model.POPULATION_VERSIONS`), yet diff treated their complete
      `pki-acls` marker as proof the objects were absent: a 0.12.0 -> 0.11.0
      diff resolved a CRITICAL ESC5 (exit 0), and 0.11.0 -> 0.12.0 reported it
      new with no coverage change. Such an export now carries a
      `CA_COMPUTER_NOT_COLLECTED` note; diff withholds any finding on a CA
      computer object against it (not re-evaluated, exit 3), counts an older
      decided verdict on one as coverage lost, and a first finding after an
      upgrade is accompanied by the note clearing.
    - *Property-scoped takeover writes on the CA computer object*: ESC5
      (variant `scoped-writeproperty`, CRITICAL) now flags a low-privilege
      scoped WriteProperty on `msDS-AllowedToActOnBehalfOfOtherIdentity`
      (schemaIdGuid 3f78c3e5-f79a-46bd-a0b8-9d18116ddc79, [MS-ADA2] 2.218) or
      its property set Account Restrictions (4c164200-20c0-11d0-a768-
      00aa006e0529, [MS-ADTS] 3.1.1.2.3.3), and on `msDS-KeyCredentialLink`
      (5b47d60f-6090-40b2-9f37-2a4de88f3063, [MS-ADA2] 2.358) or its
      attributeSecurityGUID, DS-Validated-Write-Computer (9b026da6-0d3c-465c-
      8bee-5199d7165cba, [MS-ADTS] 6.1.1.2.7.82), with the ESC4 Deny
      precedence. The validated write ("Self") is not modelled.
    - An ESC1-ESC3 finding whose `msPKI-RA-Signature` was not read (an older
      export, or a null) states incomplete evidence, and diff no longer reads a
      drop from that stricter severity (e.g. CRITICAL under 0.11.0 to MEDIUM
      under 0.12.0) as an improvement.
    - Collector: IIS integer values of other widths are decoded (Int64 / UInt32
      values used to read as null); `SslMapCert` stays name-only (no documented number); the
      `web-endpoints` reason now says which read failed, could not be decoded,
      or disagreed; and the authentication providers are read at both scopes
      too and must agree. The citation of "Certified Pre-Owned" now quotes the
      whitepaper and the blog post exactly.
  - **Review round 2 of these fixes (Sol, DeepSeek).**
    - *First observations are labelled, and still fail the gate.* A finding
      the older export could not have reported (a population its collector
      did not collect, or a check reading a field the two exports decoded with
      different tables) is reported under **first observed: coverage gained**
      in text, JSON (`first_observed`, `summary.first_observed`), SARIF
      (`adcsLensDrift: first-observed`) and HTML, not under new. `diff
      --exit-code` still exits 1 for it: a newly visible finding fails the
      gate (the CLI help and the README say so).
    - *Template name flags across the decoder change.* A pre-0.12.0 export
      decoded `msPKI-Certificate-Name-Flag` with the shifted table, so diff
      between such an export and a current one could resolve a CRITICAL ESC1
      (exit 0) or invent one. The superseded table is known
      (`model.TEMPLATE_NAME_FLAGS_BEFORE_0_12`, unchanged from the first
      collector to 0.11.0), so a template whose names came without a raw value,
      from a collector older than 0.12.0 or of unknown version, is re-read
      through it; ESC1 on that template is uncertain only when the two readings
      disagree on the enrollee-supplies-subject flags (bits 0x8 and 0x10000;
      0x1 decodes alike in both). On such a template diff resolves and improves
      nothing (not re-evaluated, exit 3, with the reason) and labels a newly
      decoded ESC1 first observed, and its ESC1 finding states incomplete
      evidence and says why. Everywhere else ESC1 compares as usual: a change
      of manager approval on a template with only 0x1 is new or resolved (review
      round 3, Sol B1 - the gap had been check-wide), and an unparseable or
      missing collector version counts as possibly superseded (DeepSeek N1).
      Going forward the collector also exports the raw
      `msPKI-Certificate-Name-Flag` / `msPKI-Enrollment-Flag` values and the
      DCs' raw `StrongCertificateBindingEnforcement` / `CertificateMappingMethods`
      DWORDs, and the core decodes them with its own tables, so a future
      decoding correction needs no collector change. A raw DC DWORD is accepted
      signed or unsigned and read as its unsigned value (the collector's `[int]`
      cast of a DWORD with bit 31 set fails today, leaving the value not
      obtained - fail-closed, and outside every documented value).
    - *The ordered access check* ([MS-ADTS] "Checking Object-Specific
      Access"). ESC1-ESC5 now evaluate a trustee's rights ACE by ACE in DACL
      order: an Allow reached before a Deny stays granted, a Deny reached first
      stays denied, and an inherit-only ACE never counts for the object itself.
      Scoped writes follow the object / property set / attribute tree, so a Deny
      on Account Restrictions blocks the RBCD attribute and a Deny on
      DS-Validated-Write-Computer blocks `msDS-KeyCredentialLink`, and the
      reverse. Before this, a same-trustee Deny anywhere in the DACL blocked an
      earlier Allow (a false negative), property-set and attribute Denies did
      not block each other (false positives), and inherit-only ACEs counted. The
      collector now exports each ACE's `inherited` and `inherit_only` flags in
      DACL order. A broad right counts only through the components it maps to
      (GenericAll / FullControl: WriteDacl, WriteOwner, a write of every
      property; GenericWrite: a write of every property) that an earlier Deny
      left in effect: a blanket WriteProperty Deny before a GenericWrite Allow
      leaves nothing (review round 3, Sol B2), and a GenericAll narrowed by
      earlier Denies is reported with the components left. (ESC7's CA\Security
      Deny handling is unchanged: a registry descriptor, out of this change's
      scope; group-token expansion is not modelled. Both are stated limits in
      docs/threat-model.md.)
    - *The owner's implicit rights.* An OWNER RIGHTS (S-1-3-4) ACE replaces the
      owner's implicit READ_CONTROL / WRITE_DAC, so ESC4 / ESC5 owner findings
      then count only what it grants. On the CA server's computer object the
      forest's BlockOwnerImplicitRights (dSHeuristics character 29; collected,
      read-only) blocks the implicit rights: when it is 1 the owner variant does
      not fire on that basis, and when dSHeuristics could not be read the
      finding states incomplete evidence.
    - A default computer-object DACL reconstructed from [MS-ADSC] 2.21 (the
      ACE that decides ESC5 exact; the reconstruction and its source are noted
      in the tests) is modelled in tests: joined by an administrator it is clean; joined by an ordinary user
      (MachineAccountQuota) the creator's write of Account Restrictions is a
      real RBCD path and is flagged. `_sameNames` compares multisets; a
      providers disagreement between the two IIS scopes is tested.
- **WI-044 live-validation defects (collector 0.11.0, deae6e3; review round 1
  fixes 8b2a192, round 2 fixes 73913ac, round 3 fixes ba27efe).** The four defects the live run of collector 0.10.0 found
  (see Validated below):
  - **REG_MULTI_SZ values.** `_parseCertutilMultiSzLines` reads certutil's
    real layout, `    <index>: <value>`, and returns the values (whole, with
    spaces) instead of the index tokens. It skips the `CSURL_*` flag lines
    certutil prints under a value, reads the empty-value hex dump as an empty
    list, and returns null (not obtained) for any layout it does not know
    (including a blank value or an index with a leading zero).
    DisableExtensionList values keep only the OID when certutil appends the
    OID's friendly name. ESC16 is no longer a false negative on real data.
    The Pester and simulator fixtures now use the real layout (placeholder
    values).
  - **IIS endpoints are attributed to a host.** Every `web-endpoints` row names
    the host IIS was read on (`host`), and the manifest names the collector
    host's FQDN (`host_fqdn`); a 0.10.0 export's endpoints are attributed to its
    manifest `host`. The container is complete only when the collector host is
    a CA host and no other CA host exists; otherwise the marker names the CA
    hosts not inspected. The core applies the same rule to every collector
    version, and only from a complete CA list (ESC8 now declares `ca-config`),
    so a 0.10.0 export from a non-CA IIS host (complete, count 0) no longer lets
    `diff` resolve ESC8. Host names compare as ASCII DNS names: A-Z
    case-insensitively, one trailing root dot ignored, two FQDNs only when they
    are the same name, and a short name (0.10.0) with an FQDN of that first
    label - or with an equal short name - only when no host name either export
    knows is a rival. A name this parser does not support (non-ASCII, an empty
    label, a repeated trailing dot, over 253 characters) matches nothing, so
    nothing resolves on it, but as a known name it still counts as a rival:
    a known name whose first label is the short name, or is not ASCII, makes a
    short name ambiguous. The manifest's `host_fqdn` is believed only when it
    is supported and its first label is the manifest's `host` (otherwise -
    e.g. a reverse-DNS answer for another machine, or an IDN name - the export
    is attributed to the short `host`), and a 0.11.0 endpoint row naming any
    other host (compared as a DNS name) is refused as altered. Endpoint evidence is
    per host: `diff` resolves an endpoint finding only when the newer export
    read that endpoint's host, so a dedicated Web Enrollment / CES server's
    endpoint is never resolved by an export from the CA host. The host is part
    of the endpoint's identity (two hosts' `/CertSrv` never pair; a 0.10.0
    endpoint pairs with the 0.11.0 one on the same host). `doctor` adds
    `ENROLLMENT_ENDPOINTS_NOT_EVALUATED` naming the gap.
  - **An unset `CA\AuditFilter` is 0** (auditing off; [MS-CSRA] 3.1.4.2.10
    says the audit filter is initialized to 0), so `CA_AUDIT_DISABLED` fires
    instead of `CA_AUDIT_NOT_EVALUATED`. A failed read stays null.
  - **ESC5 no longer flags the CA's own computer account** on its own
    enrollment-service object. The collector resolves each enrollment
    service's CA host account (the computer object whose `dNSHostName` is
    identical to the service's, one read-only domain-NC search) into the
    `pki-acls` field `ca_host_sid`. ESC5 treats that SID as high-privilege on
    that object only, never on other CAs' objects or other PKI objects. When
    the SID cannot be resolved (the CA host is in another domain, two or no
    computer objects answer), the object is undecided whenever anything
    low-privilege controls or owns it, and a `CA_HOST_ACCOUNT_UNRESOLVED`
    note names it. Only a row the Enrollment Services search returned carries
    the SID: the collector marks it (`enrollment_service: true`), ESC5 exempts
    nothing on any other row, and ingest refuses `ca_host_sid` anywhere else
    and accepts it there only as a domain account SID or null; ESC5 also checks
    that such a row is a `ca_object` (necessary, not sufficient: Certification
    Authorities objects share that kind, so the collector-written flag remains
    the discriminator). Ingest cannot
    tell a computer account's SID from a group's; that it is the CA host's
    account rests on the collector, which takes it from the single computer
    object whose `dNSHostName` is identical (a lookup that returns any other
    object, even a case variant, leaves it unresolved).
  - **ESC15 publication.** ESC15 now states each template's publication state,
    like ESC1-3, at the same severity: an unpublished v1 template stays a
    latent risk (the convention recorded in `docs/review-findings.md`).
    Enterprise Read-only Domain Controllers (-498) is deliberately not added
    to the high-privilege allowlist: an RODC is not a domain-compromise-class
    principal, so an escalation open to RODCs is a real path.
  - Collector 0.11.0 (`HOST_ATTRIBUTION_VERSION`): ingest requires `host` on
    every endpoint row, `host_fqdn` in the manifest, and `enrollment_service`
    and `ca_host_sid` on every `pki-acls` row of a 0.11.0 export. The read-only
    gate's pins and golden inventory were rebuilt; no allowlist was extended.
  - **Review round 1** (both lineages requested changes; 8b2a192): the
    independent `host:` alias made every endpoint of one host ambiguous to
    `diff` (identical exports reported a NEW ESC8, a real fix never resolved);
    hosts were compared by first DNS label; ESC8 absence was judged estate-wide
    and from an incomplete CA list; `ca_host_sid` was accepted on any
    `ca_object` row; the CA-host lookup accepted an exact match beside a case
    variant. Each reviewer probe is a regression test
    (`tests/test_wi044_review_r1.py`, `tests/test_wi044.py`, the Pester suite).
  - **Review round 2** (DeepSeek passed, Sol requested changes; 73913ac): the
    endpoint absence rule compared a short host name only with the newer
    export's host names, forgetting a rival only the older export knew (it now
    uses both exports'); host names were Unicode case-folded, merging distinct
    names such as `straße` and `strasse`; `host_fqdn` was not cross-checked;
    the ESC5 exemption trusted the flag without the kind at the detector; and
    the collector counted two enrollment services on one host as two CA hosts,
    so that host's endpoint list could never be complete. Each probe is a
    regression test (`tests/test_wi044_review_r2.py`, the simulated collector
    tests).
  - **Review round 3** (DeepSeek passed, Sol requested changes; ba27efe): a
    known host name the parser does not support (a non-ASCII AD dNSHostName or
    a 254/255-byte extended host name, both legal per MS-HNDS) vanished from
    the short-name rival set, so an old 0.10.0 short-host endpoint resolved
    from another host with the same first label; it now poisons short-name
    matching. Also: equal short names are ambiguous when two candidates are
    known; an unsupported own-host `host_fqdn` degrades (not believed) instead
    of refusing the export; the endpoint row check and the collector's
    distinct-host count compare as DNS names (one trailing root dot dropped);
    explanation-only host matching uses whole names. Each probe is a regression
    test (`tests/test_wi044_review_r3.py`).
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

### Validated
- **Live validation run (2026-10-13): collector 0.11.0 and the core at fbdd447,
  on the CA host, following `docs/live-validation-plan.md`.** The enterprise
  issuing CA `LABCA` on `<CA-HOST>` (an enterprise subordinate CA on Windows
  Server 2025), `<MEMBER>`, three DCs, and two further root CAs published in
  AD, all in `WORK-DOMAIN.local`. The collector ran unmodified, mostly as
  scheduled tasks under a domain administrator (the plan's no-delegation
  route), and as SYSTEM on `<MEMBER>`. Evidence is kept by the operator outside
  the repository.
  - **Phase 0, read-only proof: passed.** The LDAP snapshot (uSNChanged and
    whenChanged of all 78 objects under Public Key Services and of the CA
    computer object) was identical before and after. The CertSvc registry
    differed by exactly one value, the AuditFilter set by the plan's own audit
    step; the policy hive was identical. The CA database row count was equal.
    The DCs' highest committed USNs advanced with no 5136/5137/5138/5139/5141/
    4719 events in the window, so the advance is attributed to non-object
    writes. No Certification Services or directory-change events came from
    the collector's principal. Both runs (default and `-CollectDcMapping`)
    completed every pass.
  - **Phase 1, local-CA path: passed except the endpoints.** Two CA-host runs
    diffed with no drift (exit 0). The `<MEMBER>` run met all four
    expectations: partial endpoint pass naming `<CA-HOST>`,
    ENROLLMENT_ENDPOINTS_NOT_EVALUATED, CA registry and CA\Security not
    collected, and `diff` exit 3 with ESC8 withheld, never resolved.
    EditFlags, InterfaceFlags, CAType, CommonName, AuditFilter and
    DisableExtensionList matched certutil token for token, the empty
    REG_MULTI_SZ as `[]` (the WI-044 fix, confirmed live). All five
    CA\Security ACEs matched; ESC7's baseline finding named exactly the one
    group-managed service account holding ManageCertificates. The ESC5
    own-account exemption held on real data: `ca_host_sid` equalled the
    computer object's objectSid from an independent read, with no
    CA_HOST_ACCOUNT_UNRESOLVED and no ESC5 for the CA's own account. All four
    CRL / CA-certificate expiry findings matched `openssl` to the second.
    **Endpoints failed:** the true configuration (`Require`, `Ssl, Ssl128`)
    was exported as `none` / `false` (defect 1 below).
  - **Phase 2, privilege contexts: passed.** P1 (domain admin) every pass
    complete. P2 (local admin on `<CA-HOST>` only) identical coverage, `diff`
    exit 0. P3 (a plain domain user) could read the CertSvc registry, so the
    plan's row was inverted: the IIS pass was skipped and `diff` exited 3 with
    ESC8 and the CDP/OCSP checks not re-evaluated; no clean verdict appeared
    without data. P4 (`<MEMBER>` over SSH with `-LdapUserB64` /
    `-LdapPassB64`) LDAP complete, `diff` exit 3. P5 (`-DcRegistryUserB64` /
    `-DcRegistryPassB64`) `esc10-dc-registry` complete, both values equal to
    `reg query` on each DC. The credential-leak search found **0** hits for the
    plain, base64-UTF-8 and base64-UTF-16LE forms of both credentials across
    all 36 export and transcript files.
  - **Phase 3 and 4, seeded cases** (each seeded, diffed, reverted and diffed
    back unless noted):
    - passed: C1 ESC6 CRITICAL; C2a ESC7 CRITICAL (ManageCA); C2b ESC7 HIGH
      (ManageCertificates; per trustee); C3 ESC11 HIGH; C4 ESC16 HIGH with
      both OIDs parsed as a list; E2 ESC10 HIGH (case 1, `<DC1>` only); E3b
      ESC14 HIGH (weak mapping with KDC binding 0; the strong form resolves
      it); H1 CA_AUDIT_DISABLED CRITICAL (0) and CA_AUDIT_UNDERSCOPED MEDIUM
      (1); A1 and A1b ESC1 CRITICAL (the well-known trustee reported
      correctly); A1c no ESC1 under manager approval; A2 / A2b ESC2 HIGH; A3
      ESC3 HIGH on the agent template; A4a-A4e ESC4 HIGH for each of
      WritePropertyAll, scoped WriteProperty on msPKI-Certificate-Name-Flag,
      WriteDacl, WriteOwner and GenericAll; A5 ESC1 CRITICAL + ESC15 MEDIUM,
      ORPHANED_TEMPLATE LOW when unpublished; A6 ESC9 HIGH; A8
      WEAK_TEMPLATE_KEY_SIZE MEDIUM; A9 exact joins with padded display
      names and no false joins; B1 and B2 ESC5 CRITICAL; B4 ESC5 HIGH
      (owner); S1 `oid-objects` complete with exactly 620 (the multi-page
      cookie path, live); S3 ESC1 suppressed by an explicit Deny and back
      when it is removed;
    - observed, not seeded: H2 CDP_AIA_ABSENT MEDIUM and OCSP_URL_ABSENT LOW,
      already present on the issuing CA;
    - detector rule differs from the plan (the plan is corrected): E1 binding
      1 is a separate ESC10 MEDIUM, not case 2; E3 with every DC's
      enforcement unknown gives ESC14_ENFORCEMENT_UNKNOWN; A10
      ORPHANED_TEMPLATE is the AD-side direction (a CA listing a name missing
      from AD is undetected);
    - **failed:** D3 (defect 1) and B3 (defect 2); D1 / D2 were not seeded
      because the estate's true configuration was already mitigated.
    - The closing export diffed against the Phase 0 reference exited 1 with
      exactly one new finding, CA_AUDIT_DISABLED, from restoring AuditFilter
      to its original absent state.

  **Not proven live (environment-limited):**
  - A1d: the seed referenced a non-existent attribute, so the case was not
    seeded (defect 3);
  - A7 / ESC13: the `msPKI-Enterprise-Oid` object could not be created, so
    ESC13 is still live-proven only by the earlier lab validation;
  - S2: no false container-level finding, but the inherited ACE on each
    template was not checked before the revert (partial);
  - H1 absent: shown only indirectly (exports from before the run carry the
    absent state; the read path is covered by unit and simulated tests).

  **Observations:** doctor says nothing about the issuing CA's root not being
  published in AD (no detector models issuer publication); ESC8 treats
  Negotiate as NTLM-capable by rule, also on a Kerberos CES instance.

  **Defects found (fixed in collector 0.12.0; see Fixed above):**
  1. IIS Extended Protection and sslFlags exported as `none` / `false` from
     location-tagged configuration: two false ESC8 HIGH findings, and D3's
     resolution unreachable.
  2. The CA server's AD computer object was never collected: no ESC5 for B3.
  3. ESC1 / ESC2 / ESC3 did not model required authorized signatures, and
     the collector did not read `msPKI-RA-Signature`.

- **WI-044 (partial, 2026-10-12): collector 0.10.0 LDAP layer live-validated
  from a domain member that is not a CA.** The collector at 4676a31 ran
  unmodified, read-only, on a domain-joined member of the lab domain
  (`WORK-DOMAIN.local`). It ran under a temporary local scheduled task as
  SYSTEM, so it authenticated to AD as the member's computer account (an
  Authenticated User). An SSH session's S4U token cannot authenticate to AD
  (the double-hop), and no delegation, trust or ACL change was made. It made
  two runs, one default and one with `-CollectDcMapping`. The estate has one
  enterprise issuing CA (`LABCA`, an enrollment service) and two further
  self-signed CAs published in AD (Certification Authorities, AIA, CDP).
  Each field below was compared with a separate ADSI `DirectorySearcher` read
  (`ObjectSecurity` for the security descriptors) from the same SYSTEM context:
  - **Enumeration markers.** Every container was `complete: true`, and each
    count matched the rows and the independent count: templates 35,
    enrollment services 1, OIDs 20 (the `CN=OID` container is itself an
    `msPKI-Enterprise-Oid` and is one of the rows), PKI ACLs 9 (6 fixed + 2
    CA objects + 1 enrollment service), AIA 3, CRLs 3, DCs 3, principals with
    altSecurityIdentities 0. Every search fit in one page, so the multi-page
    cookie path was **not** exercised live.
  - **objectGUID.** Every template, enrollment service, OID, PKI object, CDP
    object and DC matched, in raw byte order.
  - **Template attributes.** All 35 templates matched on display name, OID,
    schema version, minimum key size, EKUs, issuance policies, CSP, and the
    name and enrollment flags decoded from the raw integers.
  - **ACEs.** On all 35 templates, the 6 fixed PKI containers and the 3 CA
    objects, the owner SID and every ACE matched in order: trustee SID,
    rights tokens and Allow/Deny. The tokens include `Enroll`, `AutoEnroll`,
    `WritePropertyAll` and scoped `WriteProperty:<guid>`, re-derived
    independently from `ActiveDirectoryRights` + `ObjectType`.
    `acl_obtained` was true throughout. The estate has no inherit-only ACEs,
    so how those are handled was not exercised.
  - **Certificates and CRLs.** The DER bytes of every AIA certificate and
    every base CRL matched the AD values by SHA-256. The `root_ca` /
    `issuing_ca` kinds, the CRL `ca_name` / `source` and the derived CRL tier
    are correct. `openssl` agrees with the `doctor` expiry dates and
    nextUpdate values.
  - **Multi-CA registry honesty.** The CA is remote to the collector host. It
    exported `registry_config_collected=false` with null registry fields and
    `ca-security.json` `{CA: null}`, `ca-security` was skipped, and `doctor`
    emitted `CA_REGISTRY_NOT_EVALUATED` / `CA_SECURITY_NOT_EVALUATED`.
    `certutil -getreg CA\CommonName` on the non-CA host exits with
    ERROR_FILE_NOT_FOUND and is correctly read as "absent" (not a CA host), so
    `ca-config` stays complete.
  - **DC mapping.** The per-DC WMI registry read was denied for the computer
    account. The DCs became identity-bearing rows with null deciding fields,
    `esc10-dc-registry` was skipped, and `DC_REGISTRY_NOT_EVALUATED` was
    emitted. `esc14-altsecid` ran and correctly found zero principals.
  - **certutil parsers and the ESC7 parser.** These were checked against real
    output from the CA, read remotely and read-only with
    `certutil -config ... -getreg`. `EditFlags` / `InterfaceFlags` flag names
    and DWORDs, `CAType` (1, kind `issuing`), `CommonName`, and the
    ERROR_FILE_NOT_FOUND "absent" status are parsed correctly. The real
    `CA\Security` bytes, passed through `_caSecurityFromBytes`, give the same
    ACEs and owner (BUILTIN\Administrators) as certutil's decoded view.
  - `ingest`, `doctor` (text, JSON, SARIF, HTML) and `diff` all ran cleanly on
    both exports.

  **Not live-validated:**
  - the local-CA path: the registry row from the collector host, the CA\Security
    hive read, CAType kind attribution, and IIS endpoints on the CA host. Running
    on the CA host needs an access route that this run did not have;
  - ESC10 DC registry values, which need a credential with remote-registry read
    on the DCs;
  - multi-page LDAP paging;
  - inherit-only ACEs.

  **Defects found (all fixed in collector 0.11.0, deae6e3; see Fixed above):**
  - **`_parseCertutilMultiSzLines` returns the index tokens, not the values.**
    Real certutil prints each REG_MULTI_SZ value as `    0: <value> [name]`.
    The parser takes the first token on each line, so it returns
    `["0:", "1:", ...]`. This was reproduced on the lab CA's
    `EnableRequestExtensionList` and `CRLPublicationURLs`. For
    `policy\DisableExtensionList` the SID-extension OID would never appear in
    `disabled_extensions`, so ESC16 is a false negative on real data. The
    Pester and simulator fixtures use an index-less format that certutil does
    not print. **Fixed** (deae6e3).
  - **The IIS endpoint pass is not attributed to a host.** On any non-CA host
    with IIS (WebAdministration present), `enrollment-endpoints` runs, finds
    no Web Enrollment / CES / NDES application, and writes `web-endpoints`
    `complete: true, count: 0`. The CA's `/certsrv` (live here, on HTTPS with
    Negotiate/NTLM) is therefore invisible, and no
    `ENROLLMENT_ENDPOINTS_NOT_EVALUATED` note is emitted. A synthetic probe
    confirmed the effect: a baseline with an ESC8 HIGH, diffed against this
    export, lists ESC8 as **resolved** and `diff --exit-code` exits 0.
    **Fixed** (deae6e3): re-run against the fixed core, the same probe (the
    synthetic baseline against this real 0.10.0 export) lists ESC8 as not
    re-evaluated and exits 3; tests/test_collector_simulated.py replays it for
    a 0.11.0 export and the 0.10.0 shape.
  - **An unset `CA\AuditFilter` is exported as null ("not obtained").**
    `_certutilDwordFrom` maps the absent status to null. The lab CA has no
    AuditFilter value, which is believed to mean auditing is off (the default,
    0; confirm). On a local run this gives `CA_AUDIT_NOT_EVALUATED` ("re-run a
    collector...") instead of `CA_AUDIT_DISABLED`. This fails safe, but the
    finding is lost and the note's advice cannot help. **Fixed** (deae6e3):
    absent is read as 0; [MS-CSRA] 3.1.4.2.10 says the audit filter is
    initialized to 0. Not yet confirmed on a live CA.
  - **Core: ESC5 flags the CA's own computer account at CRITICAL.** The CA
    host's computer account holds full control of its own enrollment-service
    object, as AD CS setup grants. Under the high-privilege allowlist that is
    a named computer account, so ESC5 fires CRITICAL on every enterprise CA
    install. The allowlist covers Cert Publishers (-517) but not the CA
    computer account itself. Related precision notes: ESC15 is not gated on
    publication (5 of 7 lab ESC15 findings are on unpublished templates), and
    Enterprise Read-only Domain Controllers (-498) is not in the allowlist.
    **Fixed** (deae6e3): the CA host account is exempt on its own
    enrollment-service object only; ESC15 annotates publication without
    gating (the ESC1-3 convention); -498 deliberately stays low-privilege.
    A 0.10.0 export carries no `ca_host_sid`, so this export still shows the
    ESC5 finding until it is re-collected with collector 0.11.0.

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
