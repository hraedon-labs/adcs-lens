# Publication review

> **Note (2026-10-10):** this is a dated historical record of the pre-publication
> review and is intentionally not rewritten. The repository has since been
> published: `publication.toml` declares `visibility = "public"` and the
> remote owner is `hraedon-labs`. The status line below describes the state
> at review time.

**Status:** private repository; public flip gated on this review.

## Sanitization rule

No work-domain identifiers may appear in any committed file. All committed
examples, fixtures, tests, plans, and documentation must use synthetic
placeholders:

- Domain names: use `lab.example.com` or another reserved/example domain.
- CA names: use `LAB Root CA`, `LAB Issuing CA`, etc.
- Computer names: use `LABCA01` or similar.
- SIDs: use synthetically constructed values (e.g.
  `S-1-5-21-1111111111-2222222222-3333333333-513`).
- OIDs: use arcs under the Microsoft enterprise OID space or otherwise clearly
  synthetic sub-arcs.
- Real exports, if produced, live in the gitignored `samples/` directory and
  are never committed.

## Pre-publication checklist

- [x] No real CA names, domain names, SIDs, OIDs, or template names in committed
      source, tests, fixtures, plans, or docs — verified in HEAD and all history.
      Sanitized 2026-06-20 (HEAD) and 2026-06-24 (full history): the real
      issuing-CA common name, CA hostname, AD domain, service-account name, and a
      real domain SID all leaked into committed reflections, test fixtures, and
      commit messages. All replaced with synthetic placeholders (`ad-LABCA01`,
      `LABCA01`, `lab.example.com`, `svc-labadmin`,
      `S-1-5-21-1111111111-2222222222-3333333333-*`). Re-verify
      before any flip by grepping all tracked files for the internal CA hostname
      / common-name / AD-domain tokens (do not hardcode them here) — only the
      intentional `hraedon` GitHub identity should remain.
- [x] **Git history clean.** A 2026-06-24 `git filter-repo` scrub (`--replace-text`
      for blob contents, `--replace-message` for commit bodies) removed every
      real identifier from all 44 commits across all refs. Because the repo had
      already been pushed, the immutable `refs/pull/*` snapshots still held
      pre-scrub commits, so the GitHub repository was deleted and recreated from
      the sanitized history (the documented delete+recreate remedy). The
      `hraedon` public identity (author email, GitHub URLs) was intentionally
      preserved. Closes WI-010.
- [x] `.gitignore` rejects `samples/` and local environment artifacts.
- [x] CI is green on Python 3.12 and 3.13.
- [x] Architecture guard (`tests/test_architecture.py`) passes.

> Note: the `hraedon` GitHub handle/author name in `pyproject.toml` and project
> URLs is the public repo identity and is intentionally retained — only internal
> infrastructure identifiers (CA hostnames, AD domain, topology) are scrubbed.
