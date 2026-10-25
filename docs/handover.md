# Taking over adcs-lens

Start here if you have inherited adcs-lens and the person who built it is not
around to ask. This page is a map and a short list of rules; it links to the
detail instead of repeating it. It describes **v1.2.1** (2026-10-24), which ships collector 0.13.0; changes
after it are in the CHANGELOG `[Unreleased]` section.

adcs-lens is a **read-only** checker for AD CS. A PowerShell collector, run on a
CA or tier-0 box, exports the PKI configuration to a folder. A Python program
reads that folder and reports findings. It never connects to AD CS from the
analysis side, and the collector only reads. Nothing runs continuously: there is
no server, database or service account.

## 1. Fill in the site sheet first

Keep these facts in your own records, **not in this repository** (see rule 1
below). Copy the table, and fill it in with the previous owner.

| Fact | Where to find it | Value |
|---|---|---|
| Analyser version in use | `adcs-lens --version` | |
| Where the analyser is installed | `install-windows.ps1` default is `C:\ProgramData\adcs-lens` | |
| Collector version in use | `collector_version` in any export's `collector-manifest.json` | |
| Which CA host(s) the collector runs on, and under which account | Task Scheduler or your runbook | |
| How often it runs, and where exports are kept | Your scheduler / file share | |
| Who reads the reports, and where they go | | |
| Suppressions file(s) in use, and who approved each | Your `--suppressions` file | |
| Where the private mirror lives, and who can push to it | | |
| Who gets told when a run fails or an export goes stale | | |

## 2. Rules that are easy to break

1. **Never commit real data.** Exports hold real CA names, templates, SIDs and
   domain names. Real exports live in the gitignored `samples/` folder, or
   elsewhere outside the repository. Committed docs, fixtures and tests use
   placeholders (`lab.example.com`, `LAB Issuing CA`, `LABCA01`, synthetic SIDs).
   A CI gate enforces this (see "Publication guards and a mirror").
2. **The collector must stay read-only.** It runs with directory privileges.
   Any edit to `scripts/Export-AdcsEstate.ps1` fails
   `tests/test_collector_readonly.py` until a human has reviewed the change and
   regenerated the golden inventory and, for a change touching a write, guard,
   receiver or pinned variable, hand-edited the pin tables with a reason. Read
   the "Collector" section of [`AGENTS.md`](../AGENTS.md) before touching it.
3. **Flag, don't probe.** The tool detects the *enabling configuration* of a
   weakness. It must never enroll, request, relay or "prove" anything.
4. **No AI in the truth path.** Detection and lifecycle checks make no model
   calls. Narration is optional and one-way (it imports the core, never the
   reverse; an architecture test enforces it).
5. **A missing read is never a clean result.** The collector writes a failed read
   as `null` or an incomplete-enumeration marker, and `diff` resolves a finding
   only on positive evidence. Do not "fix" a noisy `not re-evaluated` list by
   treating missing data as empty. See the README's "Drift and coverage".
6. **`diff` trusts the collector.** A hand-forged export is out of scope for the
   tool: forged indexes and forged `loader_sha256` values are outside the trust
   model. Keep exports under your own access control. See
   [`threat-model.md`](threat-model.md).
7. **Run the collector on every CA.** Registry and IIS reads are local to the
   collector host. One run covers one CA.

## 3. Architecture on one page

```
 CA host / tier-0 box                          analysis machine
 ────────────────────                          ──────────────────────────────────
 scripts/Export-AdcsEstate.ps1  ──export──►   ingest  ─►  Estate (model.py)
   (read-only: certutil, LDAP,     folder          │
    local registry, IIS,                            ├─► detection.py  ─► findings
    optional DC WMI)                                │      (ESC1-11/13-16, hygiene, lifecycle)
                                                    ├─► consequences.py (summary / risk / fix)
                                                    ├─► diff.py (two exports → drift)
                                                    └─► display.py (text / JSON / SARIF / HTML)
```

| Module (`src/adcs_lens/`) | Role |
|---|---|
| `model.py` | Frozen dataclasses: the contract between export and detectors. `MIN_COLLECTOR_VERSION` lives here. |
| `ingest.py` | Reads and validates an export folder; rejects partial, altered or malformed input (exit 4). |
| `normalize.py` | SID, join-key and host-name helpers (one place for key comparison). |
| `detection.py` | All detectors and the lifecycle checks. Pure functions, no I/O. |
| `consequences.py` | Plain-language summary / risk / remediation per check id. Pure data. |
| `diff.py` | Drift between two exports; resolves only on positive evidence. |
| `display.py` | Renders text, JSON envelope (`SCHEMA_VERSION`), SARIF, HTML. |
| `suppression.py` | Risk-acceptance file for the `--exit-code` gate. |
| `limits.py` | Per-file input size limits; bounds on input echoed in messages. |
| `strict_json.py` | Duplicate-key-refusing JSON decoder hook shared by `ingest.py` and `suppression.py`. |
| `certs.py` | The only module that imports a third-party package (`cryptography`, the `[certs]` extra). |
| `narration.py` | Optional executive summary. |
| `cli.py` | `ingest`, `doctor`, `diff`; exit codes. |

Other places: `scripts/` (collector, Windows installer/uninstaller, release and
publication gates), `tests/` (including `tests/fixtures/build_fixture.py`, the
synthetic export generator), `docs/threat-model.md` (the design spine: what each
check can and cannot detect), `plans/` (the original plans), `reflections/`
(dated working notes from the original development; history, not instructions),
`.github/workflows/` (CI and release).

## 4. Build, test, release

```bash
uv sync --locked --extra dev --extra certs --group release   # exactly what uv.lock pins
.venv/bin/ruff check .
.venv/bin/mypy src
.venv/bin/pytest -q
```

- The full test suite is slow (about 16 minutes on the owner's host). CI runs it
  on Python 3.12 and 3.13, plus Pester jobs for the collector helpers and the
  installer, a Windows collector job, a lock/audit job and an action-pin check.
  A monthly scheduled CI run is a rot canary: if it goes red, fix CI first. It
  is usually dependency or runner drift, not a code regression.
- The collector's read-only gate needs `pwsh`; locally it skips without it, in CI
  it fails.
- No test reads a real export. Real-estate validation has been done by hand, on
  the author's lab (see `docs/live-validation-plan.md` and the CHANGELOG
  "Validated" entries). A change to a detector or the collector that is only
  tested on synthetic data is not live-validated.
- A release is a `v*` tag pushed by the owner; `release.yml` verifies identity
  (tag, `pyproject.toml` version, CHANGELOG), re-runs CI, builds reproducibly,
  attests provenance and optionally publishes to PyPI. See
  [`releasing.md`](releasing.md). Version 1.2.1 is already released; follow
  that checklist for the next version.

## 5. Publication guards and a mirror

This repository came from a public upstream (`hraedon-labs/adcs-lens`) and
three mechanisms assume that identity. If you maintain a private mirror, expect
each of these:

- **`publication.toml`** declares `remote_owner = "hraedon-labs"`, the allowed
  author emails and `visibility = "public"`. The local pre-push hook
  (`githooks/pre-push`, installed by `scripts/install-git-hooks.sh`) refuses a
  push to any other owner. `tests/test_metadata_drift.py` requires the
  `pyproject.toml` project URLs and the SARIF URI to name that same owner. To
  host a fork elsewhere, change them together, in one commit, and keep that test
  passing.
- **The identifier gate** (`scripts/check_committed_identifiers.py`, CI job
  `identifier-gate`) fails closed when `visibility = "public"` and no denylist
  is supplied: it needs the repository secret `FORBIDDEN_IDENTIFIERS`, or a local
  gitignored `.identifiers-denylist.local`. The denylist is a list of your real
  domain, host and account names; it is not in the repository. Without it the
  gate fails in CI (this is deliberate). Not yet documented: the exact
  procedure the mirror's owner follows to supply it.
- **Release workflow.** PyPI Trusted Publishing is registered on PyPI for the
  upstream owner and repository, and needs a `pypi` environment. A mirror has
  neither; until configured, a release is a GitHub Release only
  ([`releasing.md`](releasing.md)).

## 6. Known gaps and debts

Collected from the README, AGENTS.md, CHANGELOG and threat model. Nothing here is
a surprise to the code; each is a stated limit.

- **No export integrity record.** The export carries no per-file digest;
  `loader_sha256` records what the collector's loader read, not integrity. An
  export-wide integrity record is "not yet built".
- **ESC12** has no established static-detectability boundary; the tool does not
  claim to detect it.
- **Group membership is not expanded.** ACL checks match the trustee SID
  directly (an estate-level `ACL_GROUP_TOKEN_CAVEAT` note says so).
- **CA patch state is always `unknown`** (collector emits it; ESC15 reports
  MEDIUM with a "confirm patch state" caveat). A future collector could derive it
  from the OS build.
- **One collector run covers one CA**; dedicated enrollment web servers that are
  not CA hosts are never reported as completely enumerated.
- **Live validation gaps**: some seeded cases could not be run (the plan lists
  them), inherit-only ACEs were validated only partially, and the collector 0.13.0
  changes are tested against simulated input.
- **No scheduled-task wrapper, no least-privilege account definition and no tested
  gMSA for the collector** ship with the repository. See [`install.md`](install.md).
- **PyPI**: not published unless the owner has enabled it.
- The `narration` and `web` extras are empty placeholders.
- `docs/review-findings.md` lists older review findings (all marked resolved).

## 7. Dependencies

- Runtime: Python 3.12+; nothing else. Optional: `cryptography` (the `[certs]`
  extra), pinned in `pyproject.toml` and `uv.lock`.
- Collector: Windows PowerShell, `certutil`, the IIS `WebAdministration`
  module (for ESC8), AD read access, and for `-CollectDcMapping` remote registry
  (WMI) read on the DCs.
- Dev: pytest, ruff, mypy, jsonschema, pyyaml; `pwsh` + Pester for the
  PowerShell tests; `uv`.
- `.claude/settings.json` holds a Claude Code session hook that calls an
  `agent-notes` tool from the original author's setup. It ends with `|| true` and
  is harmless if the tool is absent; ignore or delete it.

## 8. Where updates and support come from

adcs-lens is MIT-licensed, passively maintained by its author: security reports
and bug reports are welcome, with no response-time commitment. Report a
vulnerability as described in [`SECURITY.md`](../SECURITY.md). If upstream stops
publishing, the license lets your organisation fork it; the tests and CI
configuration come with it. Track upstream changes by reading the CHANGELOG
before merging.

## 9. Where everything else is

| Question | Document |
|---|---|
| What is it, and what does it not do? | [README](../README.md) |
| How do I install it, and what does the collector need? | [install](install.md) |
| How do I run it, gate on it, upgrade it, fix it? | [operations](operations.md) |
| What can each check detect, and what can it not? | [threat model](threat-model.md) |
| Conventions and hard rules | [AGENTS.md](../AGENTS.md), [CONTRIBUTING.md](../CONTRIBUTING.md) |
| How is a release cut? | [releasing](releasing.md) |
| What changed? | [CHANGELOG](../CHANGELOG.md) |
