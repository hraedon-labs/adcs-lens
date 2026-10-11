# AD CS threat model & detectability boundary

This is the design spine of adcs-lens. It catalogues the AD CS weakness classes
the tool reasons about and — critically — classifies each by **what a read-only
configuration export can actually detect statically**, versus what would require
active probing the tool will never do.

The detectability column *is* the "flag, don't probe" principle made concrete:

- **Static** — the enabling condition is fully readable from exported
  configuration. adcs-lens detects it deterministically.
- **Static (enabling config)** — the *prerequisite* is readable, but confirming
  exploitability requires runtime conditions (e.g. an NTLM relay, an RPC call).
  adcs-lens flags the prerequisite and says so; it never confirms by probing.
- **Out** — detection inherently requires authenticating, enrolling, relaying,
  or otherwise acting against live AD CS. Explicitly out of scope.
- **Out (unresolved)** — no statically-detectable enabling configuration has
  been identified in canonical tooling (e.g. Certipy's enumeration engine) or
  published research. The ESC number is preserved for catalogue continuity but
  the class is not classified. Not silently omitted — every ESC number in the
  catalogue is accounted for, enforced by the traceability test.
- **Static (not yet implemented)** — the enabling condition is statically
  readable, but no detector is built yet (and the collector may not capture the
  field). Listed so the catalogue stays honest rather than silently omitting a
  detectable class; tracked as a work item.

## ESC catalogue

| ID | What it is | Detectability | Primary data source |
|----|-----------|---------------|---------------------|
| ESC1 | Template allows requester-supplied SAN + client-auth EKU, enrollable by low-priv | **Static** | template `msPKI-Certificate-Name-Flag` (ENROLLEE_SUPPLIES_SUBJECT), EKU list, enroll ACL |
| ESC2 | Template with Any-Purpose EKU or no EKU (SubCA-equivalent) | **Static** | template `pKIExtendedKeyUsage` / EKU absence |
| ESC3 | Enrollment-Agent (Certificate Request Agent) EKU usable by low-priv | **Static** | template EKU + enroll ACL |
| ESC4 | Template object ACL grants write to low-priv, or low-priv owner (can be edited into ESC1) | **Static** | template `nTSecurityDescriptor` (DACL + owner) |
| ESC5 | Writable ACL / low-priv owner on PKI objects (CA objects, NTAuth, PKS containers) | **Static** | container/object `nTSecurityDescriptor` (DACL + owner) |
| ESC6 | `EDITF_ATTRIBUTESUBJECTALTNAME2` set on the CA | **Static** | CA registry `policy\EditFlags` (`certutil -getreg`) |
| ESC7 | CA permissions (ManageCA / ManageCertificates) held by low-priv, or low-priv owner of the CA security descriptor | **Static** | CA security descriptor DACL + owner (`certutil -getreg CA\Security`) |
| ESC8 | NTLM relay to HTTP/RPC enrollment (Web Enrollment / CES) | **Static (enabling config)** — detect role installed + EPA off; relay itself is **Out** | role/endpoint inventory; IIS EPA setting |
| ESC9 | `CT_FLAG_NO_SECURITY_EXTENSION` on a template enrollable by low-priv without manager approval (weak mapping) | **Static** | template `msPKI-Enrollment-Flag` + enroll ACL |
| ESC10 | Weak certificate mappings on DCs (`StrongCertificateBindingEnforcement` / `CertificateMappingMethods`) | **Static** (needs DC registry in export) | DC registry export |
| ESC11 | `IF_ENFORCEENCRYPTICERTREQUEST` off → RPC (ICertPassage) relay | **Static (enabling config)** — flag the flag; relay is **Out** | CA registry `InterfaceFlags` (`certutil -getreg`) |
| ESC12 | *Unresolved* — no statically-detectable enabling configuration has been identified in canonical tooling or published research; the ESC number is preserved for continuity. Tracked as WI-026. | **Out (unresolved)** | n/a |
| ESC13 | Issuance-policy OID linked to a privileged group | **Static** | template `msPKI-Certificate-Policy` + `msDS-OIDToGroupLink` on the OID object |
| ESC14 | Weak explicit cert mapping via `altSecurityIdentities` | **Static** (needs AD object read in export) | AD principal `altSecurityIdentities` |
| ESC15 | EKUwu (CVE-2024-49019): v1 template + application policies in request | **Static (enabling config)** — flag vulnerable v1 templates; severity tracks CA patch state (HIGH unpatched / MEDIUM unknown / suppressed patched); request-side is **Out** | template schema version + name flags; CA patch state |
| ESC16 | CA-wide disable of the security extension (`disabled_extensions` contains `1.3.6.1.4.1.311.25.2`) — the CA-level analogue of ESC9 | **Static** | CA `disabled_extensions` (policy `DisableExtensionList`) |

## Non-ESC hygiene & lifecycle

These are the checks that matter most to a legacy shop on an audit clock and are
under-served by the offensive tooling entirely:

| Check | What it catches | Detectability | Source |
|-------|----------------|---------------|--------|
| CA cert expiry | Root/sub-CA certificate approaching/past expiry | **Static** | CA cert in export |
| CRL signing expiry | The CRL signing cert expiring — silent estate-wide auth failure | **Static** | CA config / CRL |
| CRL freshness | Published CRL stale or overdue vs. its validity period | **Static** | exported CRL + config |
| CDP / AIA reachability | Distribution points declared but unreachable/misconfigured | **Static (declared)** — config only; no live fetch | CA config |
| OCSP URL presence | CA certificate lacks an OCSP responder URL in AIA | **Static** | CA cert AIA extension |
| Weak signing algorithm | CA signing with SHA-1 / MD5 | **Static** | CA cert / config |
| Weak key length | CA or template minimum key size below policy (RSA baseline; ECDSA templates skipped) | **Static** | CA cert; template `msPKI-Minimal-Key-Size` + CSP |
| Audit configuration | CA auditing disabled or under-scoped | **Static** | CA registry `AuditFilter` |
| Orphaned / unused templates | Published templates nobody should still enroll | **Static** | published-templates list vs. template inventory |

## Implications for the data model & collector

The detectability table dictates what the read-only collector must capture, and
nothing more:

1. **CA registry configuration** — `certutil -getreg` (CA, policy, and security
   hives): `EditFlags`, `InterfaceFlags`, `AuditFilter`, role security.
2. **AD Public Key Services container** (Configuration NC): `pKICertificateTemplate`
   objects with all `msPKI-*` attributes and EKUs; Certification Authorities;
   Enrollment Services; NTAuthCertificates; OID objects (for ESC13). Each with
   its `nTSecurityDescriptor`.
3. **Certificates & CRLs**: CA/sub-CA certs and the current CRL(s) for lifecycle
   and algorithm/key checks.
4. **Role/endpoint inventory**: which AD CS roles are installed (Web Enrollment,
   CES/CEP) for the ESC8 *enabling-config* flag.
5. **(Optional, for ESC10/ESC14)** targeted DC registry values and principal
   `altSecurityIdentities` — gated, because they widen the export footprint.

Everything above is obtainable read-only with `certutil`, the AD CS PowerShell
module, and LDAP reads against the Configuration NC. No item requires
authenticating *as* an enrollee or issuing a request — which is exactly why the
tool can stay defensive.

## Collector read-only gate: what it proves and what it does not

The collector runs with directory privileges, so its read-only property is a
CI check (`tests/test_collector_readonly.py`, parsing the script with
`tests/collector/Get-ScriptInvocations.ps1`; it never executes it). The check
has two layers.

1. **Golden syntax tree.** `tests/collector/collector-inventory.json` holds an
   order-preserving serialization of the whole AST (every node with its
   operators, names, string values, flags, `#Requires`, attributes and
   arguments, in source order) and a SHA-256 of the source text. Any edit,
   including a reorder, a changed later argument, a `#Requires` line or a
   comment, fails the comparison until the file is regenerated. Meta-tests
   prove the serializer covers every AST node type and property of the
   running PowerShell, and that sampled systematic mutations (single tokens,
   statement swaps, negated conditions, inserted statements) all change the
   tree.
2. **Semantic floor.** `tests/collector/regen_inventory.py` refuses to
   regenerate unless the semantic checks pass, so what a regeneration can admit
   is bounded by them: allowlisted commands with exact argument vectors,
   allowlisted .NET calls with pinned receivers, exact binding pins for every
   write root, receiver and exec input and their dependencies, the exact text
   and control-flow context of every write, exec, module-load, remote and
   lifetime-changing (`Dispose`/`Close`/`Flush`/...) operation, a closed set of
   AST node types, the exact ordered list of local functions and an exact
   normalized-AST digest of each function's body, and refusal of provider-drive
   / `$global:` writes,
   automatic-variable writes, `$PSDefaultParameterValues` /
   `$PSModuleAutoLoadingPreference` / `$ExecutionContext`, `-*Variable` common
   parameters, splatting, `#Requires`, background jobs and non-ASCII source.
   Command, function, method, parameter and variable names are matched case
   insensitively (PowerShell resolves them so), and a script block passed to
   `ForEach-Object` / `Where-Object` / `%` / `.ForEach()` / `.Where()` or dot-
   sourced is treated as the caller's scope for bindings (only `& { }` is an
   isolated scope), so an unqualified assignment inside such a block rebinds the
   enclosing pinned variable.

The golden comparison is the completeness guarantee; the semantic floor is
what a regeneration cannot get past; a person still reviews the golden diff.
Declared gaps:

- The floor is allowlists and pins, not a proof of read-only behaviour. An
  edit it admits (a new `return`, a changed message, a new pure read) is
  caught only as a golden diff that a reviewer must read.
- The only normalization is CRLF->LF, so a line-ending change inside a
  multi-line string literal is not detected.
- Guard pinning is intraprocedural and syntactic: an operation's context lists
  the conditions, loops, try blocks and directly-exiting `if`s / `Assert-*`
  calls around it in its own function. A guard in a caller, or one that exits
  from a nested block (the credential-pair check), is protected only by the
  golden tree.
- Binding pins follow variables through assignments, per scope, and into a
  called local function's parameters. A helper's body and return value are not
  modeled by dataflow, but every local function's whole body is pinned by an
  exact normalized-AST digest (`LOCAL_FUNCTION_BODIES`), so any change to a
  helper — its return expression, a constant, a reordered statement — fails the
  body pin and cannot be regenerated without a deliberate edit of that table.
  Variables are pinned per scope, so the same name in two scopes is two
  separate pins; a block that runs in the caller scope is collapsed onto the
  enclosing scope so its assignments hit the pinned key. A script block whose
  execution scope cannot be proven isolated is treated as the caller scope
  (strict default).
- Instance methods are bound to a pinned receiver variable, not a resolved
  runtime type; the type allowlist is the backstop.
- That the allowlisted cmdlets, `certutil -getreg` and the WMI `GetDWORDValue`
  method do not write rests on Microsoft's documentation.
- Script parameters (`-OutDir`, the credential parameters) are operator input;
  only their in-file declarations are pinned.
- The check runs with pwsh 7 on Linux. Windows PowerShell 5.1 parses the
  script in the `collector-windows` job but does not run this gate.
