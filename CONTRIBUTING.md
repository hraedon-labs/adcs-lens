# Contributing to adcs-lens

Thanks for helping. adcs-lens is passively maintained, so a small, focused,
well-tested change has the best chance. Read [`AGENTS.md`](AGENTS.md) (hard
rules and the collector's read-only gate) and
[`docs/handover.md`](docs/handover.md) (architecture and where things live)
first.

## Rules that decide whether a change is accepted

- **Read-only, never live.** No code may authenticate to, enroll against, write
  to or relay through AD CS. Input is exported files only.
- **Flag, don't probe.** Detect the enabling configuration; never run the
  attack.
- **No AI in the deterministic core**, and a stdlib-only core. The only
  third-party import is in `certs.py`, behind the `[certs]` extra.
- **No real identifiers in committed files.** Use synthetic placeholders
  (`lab.example.com`, `LAB Issuing CA`, synthetic SIDs and OIDs). Real exports
  stay in the gitignored `samples/`.
- **A missing or unreadable input is "not obtained", never "clean".** A new
  check declares the fields and containers it needs, and gives exactly one
  verdict per object (finding, clean or undecided).
- **A change to a detector needs a test**, and a change to the collector needs
  the gate reviewed (see AGENTS.md, "Collector").
- Docs are part of the change: update the README, `docs/threat-model.md` (a
  traceability test locks it to the detectors) and the CHANGELOG
  `[Unreleased]` section.

## Set up

```bash
uv sync --locked --extra dev --extra certs --group release
scripts/install-git-hooks.sh   # optional: identifier and publication hooks
```

The hooks need a denylist (`.identifiers-denylist.local`, gitignored, or
`$FORBIDDEN_IDENTIFIERS`); see [`docs/handover.md`](docs/handover.md#5-publication-guards-and-a-mirror).

## Before you open a pull request

```bash
.venv/bin/ruff check .
.venv/bin/mypy src
.venv/bin/pytest -q
```

The full suite takes about 16 minutes. While iterating, run the tests for the
module you changed (for example `.venv/bin/pytest -q tests/test_detection.py`).
Install `pwsh` to run the collector gate locally; without it that test skips,
while CI fails it. CI also runs Pester for the collector helpers and installer.

## Commits and releases

Write a clear message that says what changed and why. Releases are cut by the
maintainer pushing a tag; see [`docs/releasing.md`](docs/releasing.md). Add your
change to the `[Unreleased]` section of [`CHANGELOG.md`](CHANGELOG.md): the
release check requires that section to be empty at release time, so the
maintainer moves entries under the new version.

## Reporting a problem

Bugs: open an issue. Security problems: follow [`SECURITY.md`](SECURITY.md); do
not open a public issue.
