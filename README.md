# adcs-lens

adcs-lens is a read-only checker for Active Directory Certificate Services
(AD CS), the Windows PKI. It reads *copies* of a CA and PKI configuration
export, and reports misconfigurations, weak settings and certificate/CRL
expiry. It never touches or authenticates to live AD CS. The checks are plain,
deterministic code: **no AI sits in the truth path**. The only optional
language-model use is narration, which restates facts the core already
computed (see "Narration" below).

> **Project status:** v1.2.0 (2026-10-20), feature-complete for its charter
> (the full statically-detectable ESC family plus lifecycle/hygiene checks).
> The next release is a 1.2.1 fix release; its notes are the `[Unreleased]`
> section of [`CHANGELOG.md`](CHANGELOG.md). Not under active development;
> maintained passively. Security reports (see [`SECURITY.md`](SECURITY.md)) and
> bug reports are welcome, but there is no feature roadmap or response-time
> commitment.

## Who it is for, and what it does not do

For the people who run or audit a Windows CA: a sysadmin or security reviewer
at an organisation with an on-premises AD CS, who wants an evidence report and
cannot send the CA configuration to a vendor cloud. No PKI specialist is
needed to read the output: each finding carries a plain-language summary, risk
and remediation.

It does **not**: connect to AD CS from the analysis side, enroll or request
certificates, relay, exploit or "prove" a weakness, change any CA setting,
watch anything continuously, or send alerts. See "Scope" below.

## How it works, in four steps

1. **Collect.** On the CA (or a tier-0 admin box), run the read-only PowerShell
   collector `scripts/Export-AdcsEstate.ps1`. It writes an export folder of
   JSON and DER files.
2. **Copy** that folder to the analysis machine. The export contains your PKI
   structure and permissions: treat it as sensitive, and never commit it
   (the repository ignores `samples/` for this reason).
3. **Analyse.** `adcs-lens doctor <export>` prints prioritized findings (text,
   JSON, SARIF or HTML). `adcs-lens diff <old> <new>` compares two exports.
4. **Act.** Fix the findings; collect again on a schedule and `diff`.

Quickstart:

```powershell
# On the CA host, as an account that can read the PKI containers in AD:
scripts/Export-AdcsEstate.ps1 -OutDir C:\AdcsExport
```

```bash
adcs-lens doctor C:\AdcsExport
```

Install, permissions and day-to-day use are in
[`docs/install.md`](docs/install.md) and [`docs/operations.md`](docs/operations.md).
If you inherited this tool, start with [`docs/handover.md`](docs/handover.md).

## Documentation

| Document | Read it for |
|---|---|
| [`docs/install.md`](docs/install.md) | Prerequisites, installing the analyser and running the collector, permissions and why |
| [`docs/operations.md`](docs/operations.md) | Day-to-day use, options, exit codes, scheduled scans, suppressions, upgrading, troubleshooting |
| [`docs/handover.md`](docs/handover.md) | Start here if you inherit the tool: architecture, where things live, build/test/release, known gaps |
| [`docs/threat-model.md`](docs/threat-model.md) | The ESC + hygiene catalogue and the static-detectability boundary |
| [`SECURITY.md`](SECURITY.md) | What the tool can and cannot touch; how to report a vulnerability |
| [`CONTRIBUTING.md`](CONTRIBUTING.md), [`AGENTS.md`](AGENTS.md) | Maintainer conventions and hard rules |
| [`CHANGELOG.md`](CHANGELOG.md) | What changed, including the pending 1.2.1 notes |
| [`docs/releasing.md`](docs/releasing.md) | How a release is cut |

## Why this exists

Microsoft effectively froze AD CS over a decade ago. The misconfigurations are
correspondingly decade-deep, and nobody puts energy into a CA until an audit or
an incident forces it. The tooling that *does* exist for this surface —
Certipy, Certify — is built to **exploit** it: it authenticates, requests
certificates, and relays, and it produces output for an attacker, not an
auditor.

There is a real, open gap on the **defensive, read-only, evidence-producing**
side, and it is sharpest for the organizations least able to fill it: small,
regulated shops with a legacy on-prem CA, no PKI specialist, and a hard
constraint against shipping their CA configuration to a vendor cloud. That is
the org adcs-lens is for.

## The line vs. cert-watch

cert-watch and adcs-lens both touch certificates but answer different
questions. The dividing principle is **access, not subject**:

- **adcs-lens** — anything answerable from a **read-only export**, point-in-time
  or diffed over time: PKI posture (CA config, templates, enrollment
  permissions, ACLs) and the *point-in-time* state of infrastructure cert/CRL
  lifecycle. Air-gappable; holds no standing access; never alerts.
- **cert-watch** — anything needing **standing live access or push alerting**:
  continuous freshness/reachability of certs and CRLs, alerting before a
  deadline. For certs chaining to a **private trust**, reading the CRL and
  flagging misconfigurations is part of cert-watch's *default* scan workflow —
  the live half of this split.

So a CA / CRL-signing cert's *expiry as of an export* is an adcs-lens finding;
the *continuous watch that alerts you 7 days before* it expires is cert-watch's.
The two compose: adcs-lens discovers PKI structure (including CAs with no serving
leaf cert); cert-watch watches the live deadlines. adcs-lens does **not** acquire
live-touch to do drift: drift comes from diffing scheduled read-only exports
(the `diff` command), never from a standing connection.

## Scope

**In scope (v1.0 core):**
- **CA configuration** — `EDITF_*` policy flags, `IF_*` interface flags, CA role
  permissions, audit configuration (ESC6 / ESC7 / ESC11 surface).
- **Certificate templates** — `msPKI-*` enrollment/name flags, EKUs,
  requester-supplied-SAN, security-extension settings, issuance-policy links
  (ESC1 / ESC2 / ESC3 / ESC9 / ESC13 / ESC15 surface).
- **PKI object ACLs** — `nTSecurityDescriptor` on templates and the Public Key
  Services containers, NTAuth, enrollment services (ESC4 / ESC5 surface).
- **Infrastructure cert lifecycle** — root/sub-CA cert expiry, CRL signing cert
  expiry, CRL freshness and CDP/AIA reachability *as declared in config*.

**Later module:**
- Per-host certificate-store inventory across the estate (a much larger
  read-only acquisition problem; deferred deliberately).

**Out of scope (non-goals):**
- **Any active probing or exploitation.** adcs-lens never authenticates,
  enrolls, requests a certificate, or relays. It reads exported configuration
  and flags the *condition that enables* a weakness — it never demonstrates the
  weakness. (See `docs/threat-model.md` for which ESC classes are statically
  detectable and which inherently require active testing we will not do.)
- **Endpoint TLS lifecycle** — cert-watch's job.
- **Live-touch / standing access / alerting.** adcs-lens never holds a live
  connection to AD CS and never alerts. Change detection comes from diffing
  *scheduled read-only exports* (Stance 2, the `diff` command), not from monitoring.
  Anything that genuinely needs standing access or push alerting — e.g.
  continuous private-trust CRL freshness — belongs to cert-watch.
- **Remediation execution.** adcs-lens describes and prioritizes; it does not
  change CA configuration.

## Design principles

- **Deterministic core.** No AI in the truth path. Parse, normalize, query — all
  pure and verifiable.
- **Read-only, never live.** Input is file copies of an export. No code
  authenticates to or writes to AD CS.
- **Flag, don't probe.** Detect enabling configuration statically; never perform
  the attack to confirm it. This is the defensive boundary that separates
  adcs-lens from offensive PKI tooling.
- **Zero runtime dependencies in the core.** Stdlib-only (`json`, `argparse`,
  `hashlib` and similar) so the core is portable and air-gappable. The only
  optional dependency is the `[certs]` extra (`cryptography`), for certificate
  and CRL parsing. The `narration` and `web` extras exist but are empty
  placeholders: installing them adds nothing.
- **Evidence-producing.** The output is an artifact an auditor or manager can
  read — findings prioritized by severity, each traceable to a source fact.

## Install

adcs-lens needs **Python ≥ 3.12**. The deterministic core is stdlib-only and
air-gappable (zero runtime dependencies). Install the optional `[certs]` extra to
enable CA/CRL (DER) lifecycle parsing — cert/CRL expiry, CRL early-warning, weak
signing algorithm, and CA-cert key-size checks. Without `[certs]`, lifecycle
fields are `None` and those checks degrade to an explicit coverage note rather
than producing wrong answers.

### Windows (installer script)

For a dedicated analysis host or a tier-0 admin box, use the Windows installer
script. It creates a venv under `C:\ProgramData\adcs-lens`, installs adcs-lens
with the `[certs]` extra, and verifies the CLI entry point:

```powershell
# From an elevated PowerShell, in the repo root:
powershell -ExecutionPolicy Bypass -File .\scripts\install-windows.ps1

# Custom install directory:
powershell -ExecutionPolicy Bypass -File .\scripts\install-windows.ps1 -InstallDir D:\adcs-lens

# Air-gapped host without a C compiler (skip [certs]; lifecycle checks degrade to notes):
powershell -ExecutionPolicy Bypass -File .\scripts\install-windows.ps1 -NoCerts
```

The installer handles Python 3.12+ discovery (including the Python Install
Manager and Windows Store stubs), copies a user-scoped Python to a shared
location if needed (so scheduled tasks and SSH sessions can reach it), and is
safe to re-run (upgrades the package in place). To refresh the shared Python
after upgrading your system Python, run `uninstall-windows.ps1 -RemoveData`
first. After install, the CLI is at
`C:\ProgramData\adcs-lens\venv\Scripts\adcs-lens.exe`.

To uninstall:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\uninstall-windows.ps1
# Also remove the shared Python:
powershell -ExecutionPolicy Bypass -File .\scripts\uninstall-windows.ps1 -RemoveData
```

### pip install

```bash
# From the latest main branch (recommended):
pip install "adcs-lens[certs] @ git+https://github.com/hraedon-labs/adcs-lens.git"

# Or, from a checkout (use this for a private mirror or a fork):
pip install -e ".[certs]"

# From PyPI (not yet published; publishing is gated on the owner enabling
# PyPI Trusted Publishing — see docs/releasing.md):
# pip install "adcs-lens[certs]"
```

This installs the `adcs-lens` command. The dependency-free core is well suited
to an air-gapped / tier-0 analysis host — vendor the single `src/adcs_lens/`
package when network access is unavailable.

## Workflow

```powershell
# On the CA / a tier-0 admin box, export the PKI config (read-only):
# Run as a Domain Admin (or an account with read access to the PKI container) —
# the collector uses your current Windows credentials by default:
scripts/Export-AdcsEstate.ps1 -OutDir C:\AdcsExport

# For key-based SSH sessions (double-hop), pass explicit LDAP creds (base64):
$u = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("user@domain.local"))
$p = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("password"))
scripts/Export-AdcsEstate.ps1 -OutDir C:\AdcsExport -LdapUserB64 $u -LdapPassB64 $p

# (Base64 is for quoting only, not secrecy: the credential is still visible to
# local process inspection and script-block logging, like any argument.)

# Opt-in ESC10/ESC14 DC certificate-mapping passes:
scripts/Export-AdcsEstate.ps1 -OutDir C:\AdcsExport -CollectDcMapping
```

```bash
# Copy the export to your analysis machine, then:
adcs-lens ingest C:\AdcsExport
adcs-lens doctor C:\AdcsExport            # prioritized posture + lifecycle findings
adcs-lens doctor C:\AdcsExport --json     # stable JSON envelope (with consequences)
adcs-lens doctor C:\AdcsExport --sarif    # SARIF v2.1.0 for CI / GRC integration
adcs-lens doctor C:\AdcsExport --html     # self-contained HTML evidence report
adcs-lens diff  OLD\Export NEW\Export     # Stance 2: what got worse / better since the baseline
adcs-lens diff  OLD NEW --exit-code       # 1 on regressions, 3 on lost coverage, 4 on a bad export
```

#### Input limits

Every file adcs-lens reads has a size limit. A file over its limit is
**rejected** (an ingest error, exit 4), never truncated: a truncated array or
CRL would parse as a smaller, cleaner estate. These limits are **policy
choices**, set generously above any export we expect. They are not
measurements of real exports.

| File | Limit |
|---|---|
| `collector-manifest.json` | 1 MiB |
| `certs/index.json` | 16 MiB |
| every other export JSON file (`templates.json`, `pki-acls.json`, `principal-mappings.json`, ...) | 64 MiB |
| one DER CA certificate (`certs/*.cer`) | 1 MiB |
| one DER CRL (`certs/*.crl`) | 256 MiB |
| `--suppressions` file | 4 MiB |

The values live in `src/adcs_lens/limits.py`.

Suppression JSON must use unique object keys at every level, including inside
`metadata`, and only the documented keys (the key sets are closed and
case-sensitive). A repeated or unknown key is ambiguous risk acceptance and
stops analysis with exit 4, as does JSON nested beyond the loader's nesting
guard. See `docs/operations.md`, "Accepting a risk".

Exports describe the estate *as collected*. An export more than 8 days old gets
an `EXPORT_STALE` note, and a missing, unparseable or future `collected_at` gets
`EXPORT_TIMESTAMP_INVALID`. Both are also printed on stderr. Set
`ADCS_LENS_STALE_EXPORT_DAYS=<days>` (a positive integer) for a different
collection cadence. Export age equals collection age only if the collector
host's clock was right.

#### Drift and coverage

`diff` reports a finding as **resolved** only when the newer export fully
re-evaluated that check for that object. If the newer export lost coverage
(a skipped or missing collector pass, an unreadable template/PKI-object DACL, a
CA whose registry was not collected, an unknown or older collector version,
lifecycle data that was not parsed, and so on), the finding goes into a
separate **not re-evaluated — coverage lost** bucket (`indeterminate` in JSON,
`baselineState: "unchanged"` plus `properties.adcsLensDrift: "indeterminate"`
in SARIF, so the alert stays open). It is never counted as fixed. A severity
*improvement* on an object the newer export could not fully evaluate, or one
whose newer severity rests on weaker evidence (for example an ESC15 drop from
HIGH to MEDIUM because the CA patch state became unknown), is withheld the
same way.

**Resolution needs positive evidence.** Every posture check reaches exactly one
verdict per object (finding, clean, or undecided) and declares the inputs it
reads: the object's fields and every collector container it depends on (ESC15
reads every CA's patch state, ESC14 every DC's binding enforcement, ESC13 the
issuance-policy OIDs). `diff` reports a finding as resolved only on a *usable*
clean verdict in the newer export: every declared field was obtained and every
declared container was proven completely enumerated. An object that is
genuinely gone resolves only when the check enumerated every object of that
type with all its declared containers complete and the object's `objectGUID`
is absent; types without GUID identity (HTTP endpoints, a standalone CA, an
unreadable fixed container) also need that no unmatched object of that type
could be the same one renamed. A skipped pass, an unreadable descriptor, a
failed read, or a detector that cannot decide an object is therefore "not
usable", so the finding is withheld rather than resolved. Certificates and CRLs
missing from the newer index are never treated as resolved.

Only an export from collector **0.10.0 or later** can resolve anything. Earlier
collectors did not prove their reads: a failed `certutil -getreg` was written as
an empty list, and a container's completion marker was written after each loop
whatever the search returned. An older export is still analysed by `doctor`,
but in `diff` every older finding it does not match is withheld (there is no
legacy fallback). Re-run a current collector.

An incomplete container never produces a finding from what it is missing: a
template with no visible publisher in an incomplete enrollment-services list
is not reported orphaned, and an incomplete CA list cannot turn ESC15
"unknown". When the newer export cannot decide a check the older export decided,
`diff` lists it as **not re-evaluated** (`unevaluated` in JSON) and reports
coverage lost (exit 3), even if there was no older finding to withhold.

An object the collector cannot fully identify is never written with a made-up
key. `$OBJECT_SCHEMA` in the collector lists, per container, every attribute it
requests with its type and whether it is required (identity, join or deciding),
optional (AD omits an attribute that has no value), a placeholder (a DC's
`dNSHostName`) or the security descriptor. A returned object missing a required
attribute, or carrying an empty or wrong-typed value, is an object failure: no
row, and the container is marked incomplete. Ingest mirrors the key columns
(`ingest.REQUIRED_KEYS`) and rejects a reads-proven export whose identity or
join keys are blank, duplicated, or do not join (an enrollment-services entry
per enterprise CA row, a CA\Security entry per CA, no duplicate JSON keys).

A field derived from another object or container (a CRL's tier from the AIA
certificates, an endpoint's transports from its site's bindings, a template's
publishers from the enrollment services, a certificate's CA kind from its CA
row) is listed with its sources in `$DERIVED_FIELDS`. When a source is
incomplete or the lookup misses, the field is null (not obtained), never a
default, and every check that reads it depends on the source containers, so
`diff` withholds the comparison instead of reporting a change.

Every join between objects is listed in `$JOINS` with the keys it compares. A
reference that matches more than one object (two templates answering one cn,
two CA rows sharing a name) is never attached to one of them: the joined
field is not obtained for each, or ingest rejects the export. Enrollment
services name their templates by cn, so a current export joins publication on
cn only. Keys are compared exactly as stored (MS-WCCE: a certificateTemplates
value is identical to the template's cn): a reference that matches a key only
after trimming, case-folding or Unicode normalization is ambiguous, never a
match. That comparison exists once, in the core (`normalize.resolve_join`): the
collector writes keys verbatim and never folds one.

**Scope.** `diff` trusts that both exports come from the adcs-lens collector.
They may be partial (a read fails, a search pages or hits a size or time
limit, a pass throws), and the collector records each such failure as a JSON
`null` field or a `complete: false` enumeration marker instead of writing an
empty value. A hand-forged export that lies about what was read is out of
scope for `diff`.

**Identity.** Collector 0.9.0 and later exports each AD object's `objectGUID`,
and objects are matched on it, so renames and moves don't break matching.
Without GUIDs, objects are matched on their OID / cn / DN / DNS name, and only
when every identifier both exports carry agrees and the match is one-to-one. If
two objects share an identifier, every finding on them is withheld (older side)
or reported as NEW (newer side), never as a change of the same finding. A
certificate's identity is its SHA-256 fingerprint. A certificate whose CA is
not in `ca-config.json` (typically the offline root) is still evaluated.
Coverage notes that appear or clear are reported as **coverage state changed**,
never as new or resolved. A newer finding the older export could not have
reported - its object belongs to a population the older collector did not
collect (the CA servers' computer objects before collector 0.12.0), or its
verdict on that object depends on which table decoded an input (a template's
name flags from a collector older than 0.12.0, or of unknown version, where the
superseded table and the corrected one disagree on the flags the check turns
on) - is reported as **first observed: coverage gained**, apart from new
findings. Across such a gap nothing is resolved or improved (those findings are
not re-evaluated); a template whose flags read alike in both tables compares as
usual.

`--exit-code` results:

| Command | 0 | 1 | 3 |
|---|---|---|---|
| `doctor --exit-code` | nothing at or above `--severity` (coverage notes excluded) | a posture finding meets `--severity` | — |
| `diff --exit-code` | no regressions and no coverage loss | regressions (new or worsened posture findings), and posture findings first observed after coverage was gained (a newly visible finding fails the gate, labelled apart from new ones); this wins over 3 | no regressions, but the newer export lost coverage and older findings were withheld |

Errors exit 4 and print one `error:` line on stderr, for every command: an
unreadable, partial or rejected export, a file that is not UTF-8 JSON (a BOM is
fine), truncated, of the wrong shape or types, nested too deeply or larger than
its per-file limit (see Input limits above), or a `certs/` file that cannot be
what the collector wrote (see below). A gate therefore fails closed without
mistaking a bad export for a regression. argparse usage errors
exit 2. A certificate that loads but names something the library cannot
interpret (an unknown signature or key algorithm, a malformed extension) is
not an error: that one field is not obtained and only the checks reading it
are undecided.

**A published value that is not a certificate or CRL is a finding, not an
error.** AD can hold a CDP object's `certificateRevocationList`, or an AIA
object's `cACertificate`, that is not a certificate or CRL at all: some PKI
management tools (PSPKI, for one) write a single 0x00 byte into an object that
holds none. The collector copies the value as it is and, from **collector
0.13.0**, records its length (`bytes`) in `certs/index.json` and, for an AIA
value, the AIA object's `object_guid` and, for one its own loader (.NET) read
as a certificate, `loader_sha256` (the SHA-256 of exactly those bytes); an AIA
value that loader cannot read is written with `kind: null`. The core then reports:

| Check | Kind | When |
|---|---|---|
| `CRL_UNPARSEABLE` | LOW posture finding | a CDP object's value does not load as a CRL (one byte, a truncated DER header, not DER, or DER that is not a CRL) |
| `CA_CERT_UNPARSEABLE` | LOW posture finding | an AIA value is not a certificate: the collector's loader rejected it, or no loader can read it |
| `CA_CERT_NOT_EVALUATED` | INFO coverage note | the collector's loader read exactly these bytes as a certificate (the row's `loader_sha256` matches the file), but the `[certs]` library cannot load it (a BER length, bytes after the certificate, a field it rejects) |

Each names the object, the file, the value's length and its class, never its
bytes. For a value no parser can load (one byte, cut short) `CRL_UNPARSEABLE`
says a client gets no CRL there; for an encoding another parser may accept it
says so only conditionally (if Windows rejects it too). Microsoft documents
that Windows clients try a certificate's CDP URLs in order until one yields a
valid CRL ([PKI design considerations](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/pki-design-considerations)),
and that a CRL that cannot be found or is invalid is a revocation failure on
which a domain controller denies smart card logon
([Enabling smart card logon](https://learn.microsoft.com/en-us/troubleshoot/windows-server/certificates-and-public-key-infrastructure-pki/enabling-smart-card-logon-third-party-certification-authorities#revocation-checking-problems)).
Whether any certificate names the location is not in the export, hence LOW.

Every lifecycle check that needed the value (CRL_EXPIRY on the CDP object, the
certificate checks on the AIA value) is undecided, and a value that is not a
certificate decides no CRL's tier. `doctor --exit-code` exits 1 on the two LOW
findings, like any posture finding that meets `--severity` (suppress a reviewed
one with `--suppressions`); the note never trips it. In `diff`, an older
finding on a CDP object that now holds such a value is **not re-evaluated**
(coverage lost), never resolved; the newer `CRL_UNPARSEABLE` is new (exit 1);
and the reverse resolves `CRL_UNPARSEABLE` and labels a newly visible
`CRL_EXPIRY` **first observed: coverage gained**. `CA_CERT_UNPARSEABLE` is
identified by its AIA object's `objectGUID` and the value's SHA-256 (an AIA
object can hold several values): it resolves once a newer export from
collector 0.13.0 or later, with a complete `certs` enumeration and its AIA
values parsed (`certs/index.json` rows read with the `[certs]` extra), no
longer holds that value on that object - a value still there is never
resolved, and another value on the object is new. Against an older export, or
one that parsed no AIA values (no rows, the extra missing, the pass skipped),
it is not re-evaluated, and the reason says which.

Exit 4 still applies when a `certs/` file cannot be the value the collector
read. These checks need only the standard library, so they run whether or not
the `[certs]` extra is installed: a row whose `file` is not a plain
`certs/*.cer` (AIA) or `certs/*.crl` (CDP) file (a path, a link, `index.json`),
a `certs/` that is a link, a missing or oversized file, and, from collector
0.13.0: a file name other than the collector's own (`{n:d2}-{cn}.cer|.crl`, the
cn with every UTF-16 unit outside `[A-Za-z0-9._-]` made `_` - except the
three letters .NET's case-insensitive match keeps, U+0130, U+0131 and U+212A,
accepted either way - n rising row by row), a file whose length differs from the recorded `bytes`, a row without
`bytes`, an empty value (the collector fails such an object instead of writing
it), and, for an AIA value, a missing or malformed `object_guid`, one GUID
under two cns or split by another object's rows, a `kind` other than
`root_ca`, `issuing_ca` or null (it writes a value its loader rejects as null,
never `other`), or a `loader_sha256` that is missing, malformed, set on a
kind-null row, or not the SHA-256 of the file on a named-kind row. The
collector records `loader_sha256` for each AIA value its .NET loader read, so
a named kind on bytes that loader did not read - anything no loader reads,
whatever its shape - is exit 4. With the extra, from collector 0.13.0, also: a
row with `kind: null` whose value loads as a certificate, and a named kind on
a one-byte or cut-short value even with a matching `loader_sha256` (defence
in depth; an empty value is refused on every install, above). `loader_sha256` is
evidence of what the collector's loader read, not integrity: anyone who can
edit the index can recompute it (forged exports are outside the trust model,
see docs/threat-model.md). The length cannot catch an alteration that keeps
the size on a kind-null row or a CRL; the export carries no integrity digest
of its files, and a digest of the DER files alone would not make the rest of
the export trustworthy, so that is left to an export-wide integrity record
(not yet built).

An export from an older collector records no length, so a value AD holds
cannot be told from a file damaged after collection: ingest accepts only a
single byte other than 0x30 (the placeholder's shape, which no truncated
certificate or CRL has) and reports it with that caveat; any other value that
does not load is still exit 4 with a message to re-copy the export or re-run
collector 0.13.0 or later. Collectors 0.10.0 to 0.12.0 never wrote an AIA value
their loader rejected (the AIA object failed and the `certs` container was
marked incomplete), so an unloadable certificate file in their export is
always exit 4.

Ingest refuses a partial export: the directory must contain
`collector-manifest.json`, and every file for a pass the manifest does not list
in `skipped_passes` must be present. The current collector always writes them.
For a collector >= 0.10.0 every field a detector reads must be present with the
right type (`null` only where a read can fail), and every collected container
needs an `enumeration` marker whose count matches the rows when it claims
`complete: true`; anything else is an `IngestError` (the export was altered after
collection).
For an export from a collector with an unknown version, or one older than the
minimum, an absent file is recorded as a `PASS_NOT_COLLECTED` gap instead of
failing ingest, and the export gets a `COLLECTOR_VERSION_UNVERIFIED` note.
Diffs against such an export withhold every resolution.

## Narration

`doctor --narrate` prints a deterministic executive summary to stderr after the
findings. It calls no model. `adcs_lens.narration` can also refine that summary
with an LLM, but only when a library caller passes it a client object; the CLI
never does, and the detection core never imports the narration module (an
architecture test enforces this).

## Status

**v1.2.0** (2026-10-20). The deterministic core is complete and tested
(ingest, `doctor`, `diff`). It has:

- ESC1-ESC11 and ESC13-ESC16 detectors (ESC12 has no established
  static-detectability boundary; see `docs/threat-model.md`);
- infrastructure cert/CRL-expiry checks;
- crypto/operational hygiene detectors: `WEAK_SIG_ALG`, `WEAK_KEY_SIZE` /
  `WEAK_TEMPLATE_KEY_SIZE`, `CA_AUDIT_DISABLED` / `CA_AUDIT_UNDERSCOPED`;
- per-template ACL-gap detection (`TEMPLATE_ACL_UNREADABLE`).

Every finding carries a plain-language **consequences** entry (summary, risk,
remediation) in the text and JSON output. `doctor --sarif` emits SARIF v2.1.0
for CI / GRC integration, and `doctor --html` emits a self-contained,
deterministic HTML evidence report.

The read-only PowerShell **collector** (`scripts/Export-AdcsEstate.ps1`, now
0.13.0 on `main`) is built, and its core passes are **validated end-to-end
against a live enterprise CA**: including the PKI-object ACL pass (NTAuth /
AIA / CDP / PKS containers + CA objects) that backs ESC5 and the IIS
enrollment-endpoint pass (Web Enrollment / CES bindings, Windows-auth,
Extended Protection) that backs ESC8. The CA `owner_sid` capture (ESC7
owner-based control) is also live-validated; see the CHANGELOG. The synthetic
fixture generator (`tests/fixtures/build_fixture.py`) exercises the full
pipeline end-to-end. The collector's ESC10 / ESC14 opt-in passes
(`-CollectDcMapping`: `esc10-dc-registry` via WMI StdRegProv against each DC,
`esc14-altsecid` via LDAP) are built and **validated live** against the
author's lab: DC discovery, remote registry read, and altSecurityIdentities
read were all confirmed end-to-end.

- The **ESC10 / ESC14** detectors (DC certificate-mapping) use a
  KB5014754-aligned taxonomy. ESC10 keys on the Schannel UPN mapping bit and a
  disabled KDC binding. ESC14 flags only *weak (reusable)*
  altSecurityIdentities forms (subject-only, issuer+subject, RFC822, UPN),
  never the strong (nonreusable) issuer+serial / SKI / SHA1-PUKEY forms.
- **ESC15** (EKUwu / CVE-2024-49019) flags schema v1 templates a low-priv
  principal can enroll in, since the requester can inject application
  policies on an unpatched CA.

Phase-1 honesty/precision work closes the false-positive and false-negative
edges so the "full ESC family" claim never overclaims:

- ESC7 expands broad rights (GenericAll/FullControl) via an implication map so
  blanket CA control is not missed.
- ESC15 severity tracks CA patch state (HIGH unpatched / MEDIUM unknown /
  suppressed patched). The collector emits `unknown` today, pending a future
  OS-build signal, so a real estate reports MEDIUM with a "confirm patch
  state" caveat rather than a false HIGH.
- The template weak-key detector is algorithm-aware (ECDSA templates skipped).
- ESC4/ESC5 model owner-based control (a low-priv owner can rewrite the DACL).
- ESC8 distinguishes EPA allow/none in the finding detail, and leaves an
  endpoint whose Extended Protection or sslFlags could not be read undecided
  (with a note) unless what was read already opens the relay path (collector
  0.12.0 reads both at the application and at its applicationHost.config
  location tag).
- ESC1-ESC5, ESC7, ESC13, and ESC15 match ACLs on the trustee SID directly:
  nested-group membership is not expanded. This is surfaced as a coverage note
  in `doctor` output.

Stance-2 drift detection (`diff`) diffs the findings of two read-only exports
and reports regressions / fixes / severity changes, with `--exit-code` for
scheduled-scan gating, with no live access. A threat-model to detector
traceability test locks the design spine against drift.

Foundational docs: [`docs/threat-model.md`](docs/threat-model.md) (the ESC +
hygiene catalogue with the static-detectability boundary; **start here** for the
design), [`AGENTS.md`](AGENTS.md) (conventions and hard rules) and
[`plans/001-data-model-and-collector.md`](plans/001-data-model-and-collector.md)
(the plan this core implements).
