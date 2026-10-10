# adcs-lens

Local-first, **read-only** Active Directory Certificate Services (AD CS) posture
analysis. Ingests *copies* of a CA + PKI configuration export (it never touches
or authenticates to live AD CS) and answers questions about its hygiene,
misconfiguration, and certificate lifecycle. The deterministic core has **no AI
in the truth path** — the LLM layer only narrates facts the core already
computed.

> **Project status:** stable at v1.2.0 and feature-complete for its charter
> (the full statically-detectable ESC family plus lifecycle/hygiene checks).
> Not under active development; maintained passively — security reports (see
> `SECURITY.md`) and bug reports are welcome, but there is no feature roadmap
> or response-time commitment.

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
live-touch to do drift — drift comes from diffing scheduled read-only exports (a
later plan), never from a standing connection.

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
- **Zero runtime dependencies in the core.** Stdlib-only (`json`, `sqlite3`,
  `xml`/registry-export parsing, `argparse`) so the core is portable and
  air-gappable. Narration and any web UI are optional extras.
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
pip install "adcs-lens[certs] @ git+https://github.com/hraedon/adcs-lens.git"

# Or, from a checkout:
pip install -e ".[certs]"

# From PyPI (not yet published — this will work if/when a PyPI release is cut):
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
adcs-lens diff  OLD NEW --exit-code       # 1 on regressions, 3 on lost coverage (for scheduled scans)
```

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

**Resolution needs positive evidence.** Each detector records which objects it
*fully* evaluated (every input it needs was present). `diff` reports a finding
as resolved only if the newer export recorded that check on that object, or
the object is genuinely gone. "Genuinely gone" means the detector enumerated
every object of that type and the object's `objectGUID` is absent. For exports
from collectors older than 0.9.0, which have no GUIDs, it also requires that no
unmatched object of that type remains that could be the same one renamed. A
skipped pass, an unreadable descriptor, or a detector that skips work is
therefore "not recorded", so the finding is withheld rather than resolved.
Certificates and CRLs missing from the newer index are never treated as
resolved.

**Identity.** Collector 0.9.0 and later exports each AD object's `objectGUID`,
and objects are matched on it, so renames and moves don't break matching.
Without GUIDs, objects are matched on their OID / cn / DN / DNS name, and only
when every identifier both exports carry agrees and the match is one-to-one. If
two objects share an identifier, every finding on them is withheld (older side)
or reported as NEW (newer side), never as a change of the same finding. A
certificate's identity is its SHA-256 fingerprint. A certificate whose CA is
not in `ca-config.json` (typically the offline root) is still evaluated.
Coverage notes that appear or clear are reported as **coverage state changed**,
never as new or resolved.

`--exit-code` results:

| Command | 0 | 1 | 3 |
|---|---|---|---|
| `doctor --exit-code` | nothing at or above `--severity` (coverage notes excluded) | a posture finding meets `--severity` | — |
| `diff --exit-code` | no regressions and no coverage loss | regressions (new or worsened posture findings); this wins over 3 | no regressions, but the newer export lost coverage and older findings were withheld |

Errors (an unreadable or partial export, malformed JSON) also exit 1 and print
`error:` on stderr. argparse usage errors exit 2.

Ingest refuses a partial export: the directory must contain
`collector-manifest.json`, and every file for a pass the manifest does not list
in `skipped_passes` must be present. The current collector always writes them.
For an export from a collector with an unknown version, or one older than the
minimum, an absent file is recorded as a `PASS_NOT_COLLECTED` gap instead of
failing ingest, and the export gets a `COLLECTOR_VERSION_UNVERIFIED` note.
Diffs against such an export withhold every resolution.

> Status: the deterministic core is built and tested (ingest → `doctor`) with
> **ESC1**, **ESC2**, **ESC3**, **ESC4**, **ESC5**, **ESC6**, **ESC7**, **ESC8**,
> **ESC9**, **ESC10**, **ESC11**, **ESC13**, **ESC14**, **ESC15**, **ESC16** and
> infrastructure cert/CRL-expiry detectors, plus crypto/operational hygiene
> detectors (`WEAK_SIG_ALG`, `WEAK_KEY_SIZE` / `WEAK_TEMPLATE_KEY_SIZE`,
> `CA_AUDIT_DISABLED` / `CA_AUDIT_UNDERSCOPED`). Per-template ACL-gap detection
> (`TEMPLATE_ACL_UNREADABLE`) is also built. Every finding carries a
> plain-language **consequences** entry (summary, risk, remediation) in the text
> and JSON output, `doctor --sarif` emits SARIF v2.1.0 for CI / GRC integration,
> and `doctor --html` emits a self-contained, deterministic HTML evidence report.
> The read-only PowerShell **collector** (`scripts/Export-AdcsEstate.ps1`) is
> built and its core passes are **validated end-to-end against a live enterprise
> CA** — including the PKI-object ACL pass (NTAuth / AIA / CDP / PKS containers
> + CA objects) that backs ESC5 and the IIS enrollment-endpoint pass (Web
> Enrollment / CES bindings, Windows-auth, Extended Protection) that backs ESC8.
> The synthetic fixture generator (`tests/fixtures/build_fixture.py`) exercises
> the full pipeline end-to-end. The v0.6.0 CA `owner_sid` capture (ESC7
> owner-based control) is additive and **not yet live-validated** — it is
> Pester-unit-tested and correct by inspection, but the ESC7 owner finding should
> be treated as unconfirmed until the next live collector run. The **ESC10 / ESC14** detectors (DC certificate-mapping) use a
> KB5014754-aligned taxonomy — ESC10 keys on the Schannel UPN mapping bit and a
> disabled KDC binding; ESC14 flags only *weak (reusable)* altSecurityIdentities
> forms (subject-only, issuer+subject, RFC822, UPN), never the strong (nonreusable)
> issuer+serial / SKI / SHA1-PUKEY forms. Their opt-in collector passes
> (`-CollectDcMapping`: `esc10-dc-registry` via WMI StdRegProv against each DC,
> `esc14-altsecid` via LDAP) are built and **validated live** against the lab —
> DC discovery, remote registry read, and altSecurityIdentities read all confirmed
> end-to-end. **ESC15** (EKUwu / CVE-2024-49019) flags schema v1 templates a
> low-priv principal can enroll in, since the requester can inject application
> policies on an unpatched CA.

## Status

**v1.0** — the deterministic core is complete and tested. ESC1–ESC11, ESC13–ESC16
detectors (ESC12 has no established static-detectability boundary — see
`docs/threat-model.md`), infrastructure cert/CRL-expiry checks, and
crypto/operational hygiene detectors (weak signing algorithm, weak CA/template
key size, CA audit configuration) — the statically-detectable ESC family and
hygiene rows the threat model marks. The collector — including the opt-in
ESC10/ESC14 DC certificate-mapping passes — is validated against the live lab.

Phase-1 honesty/precision work closes the false-positive and false-negative
edges so the "full ESC family" claim never overclaims: ESC7 expands broad rights
(GenericAll/FullControl) via an implication map so blanket CA control is not
missed; ESC15 severity tracks CA patch state (HIGH unpatched / MEDIUM unknown /
suppressed patched — the collector emits `unknown` today, pending a future
OS-build signal, so a real estate reports MEDIUM with a "confirm patch state"
caveat rather than a false HIGH); the template weak-key detector is
algorithm-aware (ECDSA templates skipped); ESC4/ESC5 model owner-based control
(a low-priv owner can rewrite the DACL); and ESC8 distinguishes EPA
allow/none/unknown in the finding detail. ESC1–ESC5, ESC7, ESC13, and ESC15
match ACLs on the trustee SID directly — nested-group membership is not
expanded, surfaced as a coverage note in `doctor` output. Stance-2 drift detection (`diff`) diffs the findings of two read-only
exports and reports regressions / fixes / severity changes, with `--exit-code`
for scheduled-scan gating — no live access. A threat-model ↔ detector
traceability test locks the design spine against drift.

Foundational docs:
- [`docs/threat-model.md`](docs/threat-model.md) — the ESC + hygiene catalogue
  with the static-detectability boundary. **Start here.**
- [`AGENTS.md`](AGENTS.md) — conventions and hard rules.
- [`plans/001-data-model-and-collector.md`](plans/001-data-model-and-collector.md)
  — the plan this core implements.
