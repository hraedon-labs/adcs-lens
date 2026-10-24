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

This is the upstream project's channel. If your organisation runs a private
mirror, also tell your own security contact; fixes arrive by syncing upstream.

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

## What it can and cannot touch

- **Collector** (`scripts/Export-AdcsEstate.ps1`, on the CA or a tier-0 box): reads
  only. It runs `certutil -getreg`, reads the local CertSvc registry, makes LDAP
  reads against AD, reads IIS configuration, and (only with `-CollectDcMapping`)
  reads DC registry values over WMI. It writes only files, only inside its
  `-OutDir`. CI parses (never runs) the script and fails if it gains any write,
  enroll, request or remote-change operation outside its allowlist
  ([`AGENTS.md`](AGENTS.md), "Collector").
- **Analyser** (`adcs-lens`): reads export folders and writes to stdout/stderr.
  It makes no network connection and keeps no state.
- **What is in an export** is sensitive (CA, template and account names,
  permissions, certificates). Protect export folders like any PKI inventory.
  An explicit-credential run (`-LdapUserB64` / `-LdapPassB64`) exposes the
  credential to local process inspection and script-block logging; base64 is not
  secrecy.
- **Trust model:** an export is trusted to come from the adcs-lens collector. A
  hand-forged export is out of scope; see [`docs/threat-model.md`](docs/threat-model.md).
