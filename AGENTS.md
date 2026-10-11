# AGENTS.md

Conventions and quick reference for agents (and humans) working on adcs-lens.

## What this is

Local-first, **read-only** AD CS / PKI posture analysis. The tool ingests
*copies* of a CA + PKI configuration export and answers questions about its
hygiene, misconfiguration (the ESC classes), and infrastructure certificate
lifecycle. It never authenticates to, enrolls against, or writes to live AD CS.
The deterministic core has **no AI in the truth path** — the LLM layer only
narrates facts the core computed. See `README.md` for the full charter.

## Orient

1. **Read the threat model.** `docs/threat-model.md` — the ESC + hygiene
   catalogue with the static-detectability boundary. This is the design spine:
   it dictates what the collector captures and what the tool is allowed to claim.
2. **Read the model.** `src/adcs_lens/model.py` — the frozen dataclasses are
   the contract between the collector's export and the detectors.
3. **Validate against reality.** The test suite runs only on synthetic
   fixtures (`tests/fixtures/build_fixture.py`); no test reads a real export.
   Real-export validation is done by hand against the live lab (see Status for
   what has and has not been live-validated). Real exports stay in the
   gitignored `samples/` and are never committed.

## Hard rules

- **Read-only, never live.** No code authenticates to, enrolls against, or
  writes to AD CS. Input is exported files only. **No standing connection and no
  alerting** — change detection comes from diffing scheduled read-only exports
  (Stance 2, the `diff` command), not monitoring. Live/continuous concerns are
  cert-watch's (see Boundary).
- **Flag, don't probe.** Detect the *enabling configuration* of a weakness
  statically; never perform the attack (enroll, relay, request) to confirm it.
  An ESC8/ESC11/ESC15 finding reports the prerequisite and says exploitability
  is not confirmed. This is the line between adcs-lens and offensive tooling.
- **No AI in the deterministic core.** Detection and lifecycle checks run with
  zero model calls. Narration is an optional layer that imports the core, never
  the reverse (enforce with an architecture test).
- **Defensive output only.** Findings are framed for remediation and evidence,
  not exploitation. No payloads, no relay tooling, no request crafting.
- **No work-domain identifiers in committed files.** Docs, reflections, and
  fixtures use placeholders (e.g. `WORK-DOMAIN.local`, `LABCA`). Real exports
  live in a gitignored `samples/` and must never be committed.
- **Fixture data is synthetic.** No real CA names, template names, OIDs, SIDs,
  or domain names in committed test files.
- **Stdlib-only core.** Keep the truth path dependency-free
  (`json`, `sqlite3`, `argparse`, stdlib parsing) so it stays portable and
  air-gappable. Narration / web are optional extras.

## Build / test / lint

```bash
uv sync --locked --extra dev --extra certs   # installs exactly what uv.lock pins
.venv/bin/pytest -q            # unit + fixture tests
.venv/bin/ruff check .
.venv/bin/mypy src
```

## Collector

`scripts/Export-AdcsEstate.ps1` produces the inputs. It is read-only
PowerShell, run on the CA or a tier-0 admin box, and it uses `certutil -getreg`,
the local CertSvc registry (`CA\Security`), LDAP reads against the
Configuration / domain NC (System.DirectoryServices), IIS WebAdministration
queries, and (opt-in) WMI StdRegProv registry reads on DCs. See the
"Implications for the data model & collector" section of `docs/threat-model.md`
for exactly what it must capture — and what it must not (no enrollment, no
request).

The read-only contract is checked in CI by `tests/test_collector_readonly.py`,
which parses (never runs) the script in two layers. The **golden syntax tree**
(`tests/collector/collector-inventory.json`) is an order-preserving
serialization of the whole AST plus a source digest, so *any* edit to the
collector fails `test_collector_matches_golden_inventory` until it is
regenerated with `.venv/bin/python tests/collector/regen_inventory.py` and the
diff is reviewed. The regeneration refuses unless the **semantic floor**
(`violations()`) passes: exact command vectors and .NET allowlists,
`INSTANCE_RECEIVERS`, `PINNED_BINDINGS` (every binding of every write root,
receiver and exec input and of what they read), `GUARDED_OPS` (exact text and
control-flow context of every write/exec/load/remote operation),
`LOCAL_FUNCTIONS`, `LOCAL_FUNCTION_BODIES` (an exact normalized-AST digest of
each helper's body, so a changed return value or body is caught even when the
call site is unchanged), `ALLOWED_NODE_TYPES`, and refusal of provider/global/
automatic-variable writes. Binding pins are keyed per scope, with
`ForEach-Object`/`Where-Object`/dot-sourced blocks collapsed to the caller
scope; command/function/parameter/variable names are compared case
insensitively. `regen_inventory.py` writes only the golden JSON and never the
pin tables. A collector change that touches a write, a guard, a
receiver or a pinned variable therefore also needs a hand edit to those tables,
with a reason; never copy them from a generated dump without reading them.
Every reviewer probe is a regression case asserted to fail at its intended
check and to change the golden tree. The declared gaps are in the threat
model's "Collector read-only gate" section. Locally the test skips without
`pwsh`; in CI it fails.

## Boundary with cert-watch

The dividing principle is **access, not subject**: anything answerable from a
**read-only export** (point-in-time or diffed over time) is adcs-lens; anything
needing **standing live access or push alerting** is cert-watch. So
infrastructure cert/CRL *expiry as of an export* is an adcs-lens finding, but
*continuous* CRL freshness for private-trust certs is cert-watch's default scan
workflow (cert-watch WI-042). The two compose — adcs-lens discovers PKI
structure (incl. CAs with no serving leaf), cert-watch watches the live
deadlines. Drift detection in adcs-lens comes from diffing scheduled read-only
exports (WI-001), never from a standing connection.

## Status

**v1.2.0 (2026-07-28) — resumed from the v1.1.2 park to land collector v0.8.0
and a core honesty/precision bundle.** v1.2.0 is prepared in `pyproject.toml`
and `CHANGELOG.md` but **not yet tagged**: the latest release tag is v1.1.2
(checked 2026-10-10), and tagging is the owner's step (`docs/releasing.md`).
The repo is public and CI-gated (including a monthly scheduled run as a rot canary). The parked
backlog (WI-042 structured `Finding.sid`, WI-043 `_finding_with_consequence`
dedup) is resolved in this release; `docs/review-findings.md` holds older
deferred findings. If the scheduled CI run has gone red, fix CI first — it is
dependency/runner rot, not a regression in the code.

The v1.2.0 bundle: collector v0.8.0 gains the **certs/ lifecycle pass**
(published CA certs from the AIA container + base CRLs from CDP, read from AD
via plain LDAP — including the powered-off offline root's cert and CRL, the
catastrophic-but-invisible expiry case), **multi-CA registry honesty**
(registry hives are local to the collector host: attributed only to that CA;
remote CAs export `registry_config_collected=false`, ESC6/ESC7/ESC11/ESC16
skip them, and `CA_REGISTRY_NOT_EVALUATED` names them — also fixing a false
ESC11 on every remote CA), CAType-derived CA `kind` (incl. a
standalone-local-CA fallback), and the PKI-object `acl_obtained` marker
(`PKI_ACL_UNREADABLE`, the ESC5 analogue of the template gap signal). The core
inverts `is_low_priv_trustee` to a **high-privilege allowlist** (the blocklist
missed custom groups entirely — a domain-compromise-class ESC1 false
negative), failing toward flagging with both honesty boundaries documented in
the `ACL_GROUP_TOKEN_CAVEAT` estate note. `MIN_COLLECTOR_VERSION` is 0.8.0;
the JSON envelope is `schema_version` 3 (structured `sid`). Collector v0.8.0's
new passes are Pester/fixture-tested but **not yet live-validated** (tracked
as WI-044).

The deterministic core is built and tested (ingest → `doctor` → `diff`, ESC1–ESC11,
ESC13–ESC16 detectors — ESC12 has no static-detectability boundary — plus
crypto/operational hygiene detectors `WEAK_SIG_ALG` / `WEAK_KEY_SIZE` /
`WEAK_TEMPLATE_KEY_SIZE` / `CA_AUDIT_DISABLED` / `CA_AUDIT_UNDERSCOPED`, infra
cert/CRL lifecycle, and an architecture guard), plus a per-template unreadable-DACL
signal (`TEMPLATE_ACL_UNREADABLE`). The read-only PowerShell collector
(`scripts/Export-AdcsEstate.ps1`) captures CA config, templates (with their
DACLs → ACEs, and an `acl_obtained` marker), CA role security
(`CA\Security` → ESC7, incl. `owner_sid` for owner-based control), PKI-object ACLs
(NTAuth / AIA / CDP / PKS containers + CA objects → ESC5), IIS enrollment
endpoints (Web Enrollment / CES bindings + Windows-auth + Extended Protection
→ ESC8), issuance OIDs, and the opt-in ESC10/ESC14 DC certificate-mapping passes
(`-CollectDcMapping`: `esc14-altsecid` LDAP read of principal
altSecurityIdentities + `esc10-dc-registry` per-DC KDC
StrongCertificateBindingEnforcement and Schannel CertificateMappingMethods via
WMI StdRegProv with explicit creds); its **core passes are validated
end-to-end against a live enterprise CA** (LABCA, `WORK-DOMAIN.local`), and the
v0.6.1 collector's `owner_sid` capture (CA + template + PKI-object) is
**live-validated** — the CA owner is BUILTIN\Administrators (high-priv), so
ESC7 owner-based control correctly does not fire. The v0.6.1 fix corrects an
LDAP `SecurityMasks` bug that left template/PKI-object owner_sids empty in
v0.6.0; the core degrades honestly either way.
ESC15 (EKUwu / CVE-2024-49019) flags schema v1 templates a low-priv
principal can enroll in, with severity tracking CA patch state (HIGH unpatched /
MEDIUM unknown / suppressed patched) — the collector emits `ca_patch_state`
(unknown by default; a future enhancement can populate it from the OS build).
The statically-detectable ESC family is now built (ESC1–ESC11, ESC13–ESC16;
ESC12 has no established static-detectability boundary — see
`docs/threat-model.md`, tracked as WI-026).
Phase-1 honesty/precision work closes the false-positive and false-negative
edges: ESC7 expands broad rights (GenericAll/FullControl) via the `_COVERS`
implication map so blanket CA control is not missed, and models **owner-based
control** of `CA\Security` (a low-priv owner can rewrite the DACL → ManageCA);
ESC9 is gated on low-priv enrollability + no manager approval (mirroring ESC1's
FN-safe subset) so it no longer fires on non-enrollable / approval-required
templates; the template weak-key detector is algorithm-aware (ECDSA templates
skipped via CSP or unambiguous EC curve sizes 256/384/521); ESC4/ESC5 model
owner-based control (a low-priv owner can rewrite the DACL); and ESC8
distinguishes EPA allow/none/unknown in the finding detail. The collector
(v0.6.0) now emits template `csp` + `owner_sid`, PKI-object `owner_sid`, CA
`owner_sid` + `ca_patch_state`, and decodes GENERIC_ALL on CA security. The core
warns (stderr, not fail) when a collector predates the minimum it expects
(`MIN_COLLECTOR_VERSION`), and surfaces the ACL group-token-expansion caveat as
an estate-level coverage note.
ESC5 is
negative-validated on the real CA with positive validation via the synthetic
fixture; ESC8/ESC10/ESC11/ESC13/ESC14 are **positive-validated on the real lab**
(ESC8 live `/certsrv` HTTP+NTLM+no-EPA → HIGH; ESC10 via a temporary Schannel UPN
bit + disabled binding on a DC; ESC11 via a temporarily-cleared
IF_ENFORCEENCRYPTICERTREQUEST; ESC13 via a temporary AMA OID→universal-security-group
link on a v1 template; ESC14 via a temporary weak altSecurityIdentities — all
reverted with cleanup discipline). The ESC13 validation caught a collector bug: it
read the OID→group link from the non-existent `msPKI-OIDToGroupLink` instead of
`msDS-OIDToGroupLink` (a group DN), so ESC13 was a permanent false negative.

The **value-delivery layer** is now built on top of the detection core:
crypto/operational hygiene detectors (`WEAK_SIG_ALG`, `WEAK_KEY_SIZE` /
`WEAK_TEMPLATE_KEY_SIZE`, `CA_AUDIT_DISABLED` / `CA_AUDIT_UNDERSCOPED`) consume
already-captured fields; a plain-language **consequences catalogue**
(`consequences.py`, pure data — no AI) attaches a summary / risk / remediation
block to every finding in the text and JSON output (envelope `schema_version`
bumped to 2); `doctor --sarif` emits SARIF v2.1.0 for CI / GRC integration,
`doctor --html` emits a self-contained deterministic HTML evidence report; and
a threat-model ↔ detector **traceability test** (`test_threat_model_traceability`)
locks the design spine so no ESC class or hygiene row can drift undetected.

The collector's OS-independent helpers (bit decoders, certutil parsers, IIS
classifiers) are unit-tested with Pester via `-FunctionsOnly` (CI `collector-helpers`
job on pwsh); the Windows-only collection paths stay out of scope (WI-009).
