# Releasing adcs-lens

Releases are cut by pushing a `v*` tag. `.github/workflows/release.yml` does
the rest, and refuses to publish anything that fails its checks.

## What the workflow enforces

| Job | Checks | Permissions |
|---|---|---|
| `identity` | the tag is exactly `v` + `pyproject.toml` `[project].version`; the CHANGELOG's top versioned entry is that version; `[Unreleased]` is empty; the tagged commit is reachable from `main` (`scripts/check_release_identity.py`) | `contents: read` |
| `ci` | the whole `ci.yml` workflow, re-run on the tagged commit through `workflow_call` | `contents: read` |
| `build` | `uv lock --check`; sdist + wheel built twice with `SOURCE_DATE_EPOCH` set to the commit time, using the locked `release` dependency group (`--no-isolation`), and required to be byte-identical (`cmp`); both carry the checked version; the wheel is installed into a fresh venv from hash-checked locked `[certs]` requirements, and `adcs-lens --version` and a synthetic `doctor --json` run are smoke-tested; `SHA256SUMS` | `contents: read` |
| `github-release` | checksums re-verified; build provenance attested (`actions/attest-build-provenance`); the remote tag must still name the built commit; GitHub Release created | `contents: write`, `id-token: write`, `attestations: write` |
| `pypi` | runs **only** when the repository variable `PYPI_PUBLISH` is `true`; checksums re-verified; uploaded through PyPI **Trusted Publishing** (OIDC). No password or API token exists anywhere. | `id-token: write` |

Every third-party action is pinned to a full commit SHA with an exact version
comment (`# vX.Y.Z`). The CI job `verify-action-pins` resolves each tag through
the GitHub API and fails if the SHA is not that tag's commit.

## Owner steps

1. **Cut the release notes.** Move the `[Unreleased]` entries under a new
   `## [X.Y.Z] — YYYY-MM-DD` heading, leave `[Unreleased]` empty, and set
   `pyproject.toml` `version = "X.Y.Z"`. Merge to `main`.
2. **Tag the merged commit:** `git tag -a vX.Y.Z -m "adcs-lens X.Y.Z"` and push
   the tag.
3. **One-time PyPI setup (before the first PyPI upload).** On PyPI, add a
   *Trusted Publisher* (pending publisher if the project does not exist yet)
   for the `adcs-lens` project with: owner `hraedon-labs`, repository
   `adcs-lens`, workflow `release.yml`, environment `pypi`. In the GitHub
   repository settings, create the `pypi` environment (adding required
   reviewers is recommended) and set the repository variable
   `PYPI_PUBLISH=true`. Until both are done the `pypi` job is skipped, and a
   release is a GitHub Release only.
4. Recommended: add a tag-protection ruleset for `v*`, so a tag cannot be moved
   after it is pushed. The workflow re-checks the tag before publishing, but a
   narrow race remains between that check and the publish step.
