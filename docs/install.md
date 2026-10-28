# Installing adcs-lens

adcs-lens has two parts, and they are installed in different places:

| Part | What it is | Runs on | Needs |
|---|---|---|---|
| **Collector** | `scripts/Export-AdcsEstate.ps1`, a read-only PowerShell script | The CA host (or a tier-0 admin box) | Windows PowerShell (written for 5.1), AD read access |
| **Analyser** | The `adcs-lens` command (Python package) | Any machine that can read the export folder, Windows or Linux | Python 3.12 or later |

adcs-lens is a command-line tool. It is not a service: there is no web
server, no IIS site, no application pool, no TLS binding, no database and no
service account to manage. It stores no state: it reads export folders on
demand. Because of that, there is also nothing to back up beyond the export
folders you choose to keep.

## 1. Analyser

### Prerequisites

- Python 3.12 or later (CI tests 3.12 and 3.13).
- Recommended: the `[certs]` extra (the `cryptography` package). Without it,
  certificate and CRL expiry, CRL early-warning, weak signing algorithm and
  CA-certificate key-size checks cannot run: those fields are `None` and the
  checks degrade to an explicit coverage note, not a wrong answer. Use
  `-NoCerts` (below) only on a host that cannot install `cryptography`
  (air-gapped, no C compiler).

### Windows (installer script)

Run from an elevated PowerShell, in a checkout of the repository:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install-windows.ps1
# Custom install directory:
powershell -ExecutionPolicy Bypass -File .\scripts\install-windows.ps1 -InstallDir D:\adcs-lens
# Without [certs]:
powershell -ExecutionPolicy Bypass -File .\scripts\install-windows.ps1 -NoCerts
```

The script creates a virtual environment under `C:\ProgramData\adcs-lens`
(or `-InstallDir`), installs adcs-lens with the `[certs]` extra, and checks
that the CLI starts. The command is then
`C:\ProgramData\adcs-lens\venv\Scripts\adcs-lens.exe`. Details:

- It finds Python 3.12+ (including the Python Install Manager; it recognises the
  Windows Store stubs and skips them, as they are unusable non-interactively). If the Python it finds is user-scoped, it copies it to a shared
  location under the install directory so scheduled tasks and SSH sessions can
  reach it. To refresh that shared copy after upgrading your system Python, run
  `uninstall-windows.ps1 -RemoveData` first, then install again.
- Dependencies are hash-locked. The `[certs]` dependencies (`cryptography` and
  its own dependencies) and the build backend (`hatchling`) install with
  `pip install --require-hashes` from `scripts\locks\*.lock.txt`, exported from
  `uv.lock`; adcs-lens itself is then installed with `--no-build-isolation
  --no-deps`, so pip resolves nothing from the index at install time. With
  `-NoCerts` only the build backend is installed (the core has no other
  dependencies). After changing dependencies and running `uv lock`, regenerate
  both files; `tests/test_install_locks.py` fails when they drift:
  `uv export --locked --extra certs --no-dev --no-emit-project --no-header --format requirements-txt -o scripts/locks/requirements-certs.lock.txt`
  and
  `uv export --locked --only-group build --no-emit-project --no-header --format requirements-txt -o scripts/locks/requirements-build.lock.txt`.
  For an offline host, download the wheels for both files in advance and set
  `PIP_NO_INDEX=1` and `PIP_FIND_LINKS` to that folder. The `pip` self-upgrade
  at the start of the install is the one step not covered by the lock.
- Re-running is safe: it recreates the venv and upgrades in place.
- The script is not signed. `-ExecutionPolicy Bypass` applies per invocation;
  or sign the script with your organisation's code-signing certificate.
- It runs on Windows PowerShell 5.1.

To uninstall (add `-RemoveData` to also remove the shared Python):

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\uninstall-windows.ps1
```

### pip (Windows or Linux)

```bash
pip install -e ".[certs]"        # from a checkout (use this for a private mirror)
```

On a PEP 668 "externally managed" Python (many current Linux distributions),
create a virtual environment first (`python -m venv .venv`). A pip install
straight from the upstream GitHub URL is described in the README. PyPI
publication is gated on the owner enabling Trusted Publishing; check the
project's releases before assuming a PyPI package exists
([`releasing.md`](releasing.md)).

### Air-gapped host

The core has no runtime dependencies. Where there is no network, copy the
single `src/adcs_lens/` package to the host (the `[certs]` extra, if wanted,
must be installed from an offline wheel of `cryptography`).

### Check it works

```bash
adcs-lens --version
```

## 2. Collector

### Where to run it

Run it **on the CA host** (or a tier-0 admin box) in a Windows PowerShell 5.1
session. Several passes read the *local* machine, so what you get depends on
where you run it:

- The CA registry and `CA\Security` are read on the collector host only. They
  are attributed to the CA running there. Any other CA in the forest is
  exported with `registry_config_collected = false`; the registry-based checks
  (ESC6, ESC7, ESC11, ESC16) skip it and a note names it. **Run the collector
  on each CA** for full coverage.
- IIS enrollment endpoints (Web Enrollment / CES) are read on the collector
  host only, and the endpoint list counts as complete only when the collector
  host is the only CA host. A dedicated enrollment web server that is not a CA
  host is never reported as completely enumerated.
- Everything else (templates, Enrollment Services, OIDs, PKI-object ACLs, the
  published CA certificates and CRLs) is read from AD over LDAP, so it is the
  same wherever you run it.

### What it needs, and why

The collector never writes to AD or to the CA. It uses these read paths:

| Read | How | Why |
|---|---|---|
| CA settings (policy flags, interface flags, audit filter, CA type, disabled extensions) | `certutil -getreg`, local, on the CA host | ESC6 / ESC11 / ESC16 / audit checks |
| CA role permissions (`CA\Security`) | Local CertSvc registry | ESC7 |
| Templates, Enrollment Services, enterprise OIDs, their security descriptors and the PKI containers (NTAuth, AIA, CDP, Public Key Services) | LDAP against the Configuration naming context | ESC1-ESC5, ESC9, ESC13, ESC15 |
| Published CA certificates (AIA) and CRLs (CDP) | LDAP, copied as DER | Certificate/CRL expiry and algorithm checks, including a powered-off offline root |
| The CA server's own AD computer object, and the forest `dSHeuristics` | LDAP | ESC5 |
| IIS bindings, Windows authentication, Extended Protection, `sslFlags` | IIS `WebAdministration` module, local | ESC8 |
| `-CollectDcMapping` only: each DC's KDC and Schannel registry values | WMI `StdRegProv` against every DC | ESC10 |
| `-CollectDcMapping` only: principals' `altSecurityIdentities` | LDAP | ESC14 |

Run it as an account that can read the PKI containers and their security
descriptors in AD. By default the script binds with your current integrated
Windows credentials; the simplest tested route is a Domain Admin on the CA host
(the README's own example). Lesser accounts work but see less, and the
collector says what it could not read instead of calling it clean. What has
been observed live (from the live validation plan, `docs/live-validation-plan.md`):

- An account with local admin on the CA host only: the LDAP passes complete
  (Authenticated Users can read the PKI containers); the CA registry and
  `CA\Security` are read; the DC registry pass is not evaluated.
- An ordinary domain user: whichever reads Windows denies are marked "not
  obtained" with a `*_NOT_EVALUATED` note. A plain user may still read the
  CertSvc registry, but cannot load the IIS configuration, so the
  `enrollment-endpoints` pass is skipped and ESC8 is not evaluated.

The minimum rights, as an exact list, are not yet documented: the collector
has been run live as the accounts above, not derived as a least-privilege set.
A gMSA or dedicated service account for the collector has not been tested:
not yet documented.

### Explicit credentials (SSH sessions)

In a key-based SSH session the network credential is not delegated (the
double-hop problem), so integrated authentication cannot reach AD. Pass explicit
LDAP credentials with `-LdapUserB64` and `-LdapPassB64` (both or neither; base64
of the UTF-8 user name and password). Base64 only survives quoting through the
layers; it is **not** secrecy. The credential remains visible to local process
inspection and script-block logging, like any command-line argument. Prefer a
console or RDP session, or a scheduled task under the intended account, where
you can. Do not configure Kerberos delegation to get around the double hop.

For the opt-in DC mapping passes, `-DcRegistryUserB64` / `-DcRegistryPassB64`
supply an account allowed to read the registry remotely on the DCs. When
omitted, the pass uses your integrated credentials.

### Run it

```powershell
scripts/Export-AdcsEstate.ps1 -OutDir C:\AdcsExport
scripts/Export-AdcsEstate.ps1 -OutDir C:\AdcsExport -CollectDcMapping   # adds ESC10 / ESC14
```

`-OutDir` is created if absent. The script writes only inside it, and refuses
UNC or device paths, any path outside `-OutDir`, and any path that passes
through a junction or symlink. The export contains `collector-manifest.json`,
`ca-config.json`, `templates.json`, `oid-objects.json`, `pki-acls.json`,
`web-endpoints.json`, `dc-config.json`, `principal-mappings.json`,
`enrollment-services.json`, `ca-security.json` and a `certs/` folder (DER files
plus `index.json`). The manifest records the collector version, the collection
time, the host, and any `skipped_passes` (`certs`, `ca-security`,
`enrollment-endpoints`, `esc10-dc-registry`, `esc14-altsecid`).

Every read is proven before it is reported (collector 0.10.0 and later): a read
that fails is written as JSON `null` or an incomplete-enumeration marker,
never as an empty list that would look like a clean configuration.

Treat the export folder as sensitive (names, permissions, certificates). Keep it
off shared drives and out of the repository.

### Verify the export

Copy the folder to the analysis machine and run:

```bash
adcs-lens ingest <export-folder>
```

It prints what was read (CAs, templates, ACLs, CRLs) and any skipped passes. A
rejected export exits 4 with one `error:` line; see
[`operations.md`](operations.md#troubleshooting).

## Mirrored or forked copies

If you keep a private mirror, three repository guards assume the upstream
identity. See [`handover.md`](handover.md#5-publication-guards-and-a-mirror)
before you push from a mirror or turn on CI there.
