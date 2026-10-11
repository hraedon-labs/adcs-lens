# Security policy

## About this tool

adcs-lens is a **defensive, read-only** AD CS / PKI posture analyzer. It ingests
*copies* of an exported CA + PKI configuration and reports misconfiguration and
hygiene findings. It never authenticates to, enrolls against, writes to, or
relays through live AD CS, and it never performs an attack to confirm a weakness
("flag, don't probe"). Its findings are framed for remediation and evidence, not
exploitation.

## Reporting a vulnerability

Found a security issue in adcs-lens itself (e.g. a path-traversal in ingest, an
injection in rendered output, or a finding that silently under-reports a
critical misconfiguration)?

Please report it **privately** rather than as a public issue:

- Email: **plm@hraedon.com**
- Or open a private vulnerability report via GitHub's
  [Security Advisories](https://github.com/hraedon-labs/adcs-lens/security/advisories/new).

Please include the affected version, a reproduction, and the expected vs. actual
behavior. Acknowledgement within 72 hours is the target.

## Scope

In-scope: vulnerabilities in adcs-lens code that cause a false all-clear on a real
misconfiguration, a crash/injection on a malformed export, or leakage of the
exported estate data.

Out of scope (but welcome as regular issues): the AD CS misconfigurations the tool
*detects* (those are findings, not adcs-lens bugs), and the read-only PowerShell
collector's behavior against a live CA (it is read-only by design; if it ever
mutates state, that is a critical bug — report it the same way).
