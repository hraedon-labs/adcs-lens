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
| ESC1 | Template allows requester-supplied SAN + client-auth EKU, enrollable by low-priv | **Static** | template `msPKI-Certificate-Name-Flag` (ENROLLEE_SUPPLIES_SUBJECT), EKU list, enroll ACL; `msPKI-RA-Signature` ([MS-CRTD] 2.18; collector >= 0.12.0): one or more required authorized signatures caps ESC1-ESC3 at MEDIUM, unread is treated as none |
| ESC2 | Template with Any-Purpose EKU or no EKU (SubCA-equivalent) | **Static** | template `pKIExtendedKeyUsage` / EKU absence |
| ESC3 | Enrollment-Agent (Certificate Request Agent) EKU usable by low-priv | **Static** | template EKU + enroll ACL |
| ESC4 | Template object ACL grants write to low-priv, or low-priv owner (can be edited into ESC1) | **Static** | template `nTSecurityDescriptor` (DACL + owner) |
| ESC5 | Writable ACL / low-priv owner on PKI objects (CA objects, NTAuth, PKS containers) and on the CA server's AD computer object (collector >= 0.12.0) | **Static** | container/object `nTSecurityDescriptor` (DACL + owner); the CA host computer object resolved from each enrollment service's `dNSHostName` |
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
   its `nTSecurityDescriptor`. For each enrollment service, the objectSid of
   the computer object whose `dNSHostName` is identical to the service's
   (collector >= 0.11.0): AD CS setup grants that account control of its own
   enrollment-service object, so ESC5 does not treat it as low-privilege on
   that object only (WI-044). Only the rows of the Enrollment Services search
   carry it (`enrollment_service`). Ingest checks that consistency and the
   SID's shape; it cannot check that the SID is a computer account rather
   than a group, which rests on the collector's lookup. The same computer
   object's own `nTSecurityDescriptor` (DACL + owner) is read as a pki-acls row
   of kind `ca_computer` (collector >= 0.12.0): control of the CA server's AD
   computer object is an ESC5 path. SpecterOps' "Certified Pre-Owned" lists it
   among the ESC5 objects (whitepaper p. 70: "The CA server's AD computer object
   (i.e., compromise through S4U2Self or S4U2Proxy)"; the 2021-06-17 blog post
   words the parenthetical "i.e., compromise through RBCD"). ESC5 flags the
   object-wide control rights and ownership, and property-scoped writes to
   `msDS-AllowedToActOnBehalfOfOtherIdentity` (RBCD) and
   `msDS-KeyCredentialLink` (shadow credentials) or to the property sets that
   contain them ([MS-ADA2] 2.218 / 2.358; [MS-ADTS] 3.1.1.2.3.3). No account
   is exempted on it, and a CA host whose computer object is not resolved or
   not read leaves pki-acls incomplete. An export from a collector older than
   0.12.0 did not collect these objects: `CA_COMPUTER_NOT_COLLECTED` says so,
   and diff neither resolves nor silently newly asserts across that gap.
3. **Certificates & CRLs**: CA/sub-CA certs and the current CRL(s) for lifecycle
   and algorithm/key checks.
4. **Role/endpoint inventory**: which AD CS roles are installed (Web Enrollment,
   CES/CEP) for the ESC8 *enabling-config* flag. IIS is read on the collector
   host only, so each endpoint names that host, and the endpoint list counts as
   complete only when the collector host is the only CA host and the CA list
   is complete (WI-044); otherwise ESC8 is reported for what was read, with
   `ENROLLMENT_ENDPOINTS_NOT_EVALUATED`, and nothing absent resolves. An
   endpoint finding resolves only from an export that read that endpoint's
   host. Windows auth, Extended Protection and sslFlags are read at the
   application and at its applicationHost.config `<location>` tag (collector
   >= 0.12.0; AD CS setup keeps them there because those sections are locked
   below applicationHost.config) and kept only when both agree; an unread value
   is never "off", and an endpoint it would decide is undecided. Host names compare as ASCII DNS names; a name the parser does not
   support (a non-ASCII IDN name, a malformed or over-253-character name -
   legal AD dNSHostNames among them) matches nothing, so nothing resolves on
   it, and as a known name it makes any short name with its first label, or
   every short name if its first label is not ASCII, ambiguous. A short name
   is judged against the host names of both exports, so a rival known only to
   the newer export also withholds an older short-host finding (conservative).
   The manifest's `host_fqdn` counts only when it is supported and its first
   label is the manifest's `host`; otherwise the export is attributed to the
   short `host`.
   Known limitations, all conservative (withheld, never a false resolution):
   a dedicated Web Enrollment / CES server that is not a CA host never has a
   complete endpoint list, so a fix there is never reported resolved; a CA
   host renamed between exports is another host (its old endpoint finding is
   withheld, a still-vulnerable endpoint under the new name is new); a host
   that changes between an IDN U-label and its A-label is not matched. One
   case is accepted rather than withheld: when the collector could resolve
   only its short name and that name is the first label of exactly one known
   CA host, it is taken to be that host (a member with the same short name in
   another domain would be indistinguishable; collector 0.10.0 exports always
   carry only the short name). The ESC5 provenance flag and the CA host SID
   are collector attestations: ingest checks their consistency and shape, not
   their truth (a forged export is out of scope).
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
   lifetime-changing (`Dispose`/`Close`/`Flush`/...) and constructor
   (`New-Object`) operation, the exact argument vector of every admitted
   constructor (so another overload of an allowlisted type is refused) and of
   every .NET method call, static or instance (`PINNED_MEMBER_CALLS`), a closed set of
   AST node types, the exact ordered list of local functions, a hand-maintained
   digest of EVERY statement (STATEMENT_DIGESTS: each top-level statement and
   each statement inside every function / scriptblock body, keyed by structural
   path; a function definition is itself a statement, subsuming the former
   per-function body pins). Each digest covers the statement's own normalized
   subtree AND its full ancestor chain up to the script root: every ancestor's
   node type, the role it is reached through, its non-child properties
   (`NamedBlockAst.BlockKind` / `Unnamed`, loop labels, operators, flags) and
   its context children (conditions, param blocks, attributes, catch types,
   loop initializers/iterators, redirections), so moving a statement into a
   `begin`/`process`/`clean` block, under another condition or into another
   function changes its digest (a meta-test mutates each ancestor property kind
   and requires a change). Every write sink must be preceded, on its exact
   target, by the product's `Assert-AdcsOutputPath` guard (`[write-guard]`,
   below). And refusal of
   provider-drive
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
   Since the integration with collector 0.10.0: EVERY command invocation (not
   only the side-effecting ones) is pinned with its exact text, count and
   control-flow context; every variable in any command or .NET-call argument
   and in any branch / loop condition is binding-pinned (computed closure,
   asserted by a test); credential-bearing variables (the four credential
   parameters and everything their values flow into: the decoded user/password,
   the `NetworkCredential`, the LDAP connection, the WMI credential and handle)
   may be referenced only at their pinned sites (`SECRET_USES`); a UNC path,
   `//host` or URL is refused in any command argument, .NET-call argument or
   binding value; variable-writing common parameters are also resolved through
   the real cmdlet metadata (unique prefixes such as `-Pi`, aliases such as
   `-pv`/`-ov`/`-ev`) where pwsh has the cmdlet; and the script header (help,
   `[CmdletBinding]`, param block) is digest-pinned (`HEADER_SHA256`). The LDAP
   client (System.DirectoryServices.Protocols) is admitted read-side only:
   `SearchRequest` is the only request type, the one `SendRequest` argument is
   binding-pinned to it, and Modify/Add/Delete/ModifyDN/Extended requests are
   never allowlisted. A switch / foreach statement flag other than None
   (switch -File / -Regex, foreach -Parallel) is refused; every string literal
   or expandable string anywhere in the script that looks like a UNC path,
   `//host`, a `\\?\` / `\\.\` device path or a `scheme://` URL is refused
   (REMOTE_LITERALS) with a committed exemption list; and a semantic-projection
   completeness meta-test requires every (AST node type, serialized property) to
   be inspected by a check or declared inert with a reason, so a new I/O-capable
   property cannot be serialized into the golden while the floor ignores it.

3. **Product write guard (defence in depth, runtime).** Before every file or
   directory it creates (the output root, each JSON file and its parent, the
   `certs` directory, each certificate / CRL file) the collector calls
   `Assert-AdcsOutputPath <target>`. It refuses a UNC, `//host` or `\\?\` /
   `\\.\` device path, resolves the target and `$OutDir` with
   `[IO.Path]::GetFullPath`, throws unless the target equals `$OutDir` or lies
   under it (case-insensitive, either separator), and throws if any existing
   component between the target and `$OutDir` is a reparse point (junction or
   symlink). The gate's `[write-guard]` rule requires that call, on the sink's
   exact target text, in the control-flow context of every `New-Item -Path` and
   `[IO.File]::WriteAll*` sink, and GUARDED_OPS pins the same contexts. Pester
   tests (`tests/collector/Collector.Tests.ps1`) cover inside paths, `..`
   traversal, absolute paths elsewhere, a sibling with the same prefix, UNC,
   `\\?\`, `\\?\UNC\`, `\\.\` and `//host` forms, and a symlinked
   subdirectory. Limits: `$OutDir` itself (operator input) may be anywhere,
   including a link; a dangling link, or a link created after the check and
   before the write (a race needing write access to the output directory), is
   not detected.

The golden comparison is the completeness guarantee; the semantic floor is
what a regeneration cannot get past; a person still reviews the golden diff.
Declared gaps:

- The floor is allowlists and pins, not a proof of read-only behaviour.
  Because STATEMENT_DIGESTS fails on any AST change, the floor admits nothing
  until a person pastes new digests; what it then admits is bounded by the
  OTHER checks (allowlists, exact vectors, binding / guarded-op / secret pins,
  `[write-guard]`). Some harmful edits are caught by the digest alone -- e.g.
  `_safeFileName` returning `..\..\..\Windows\evil` changes no call site,
  binding or vector -- so an approved digest update is only as safe as the
  reviewer's reading of that statement. The product guard below is the
  runtime backstop for exactly that class of write-path edit.
- The only normalization is CRLF->LF. A line-ending change inside a
  multi-line string literal is therefore not visible to the gate, but it also
  cannot be committed: `.gitattributes` sets `*.ps1 text eol=crlf`, so git
  stores LF and checks out CRLF (the same normalization), and a bare CR still
  changes the source digest. `test_line_ending_normalization_matches_git`
  pins the attribute.
- Guard pinning is intraprocedural and syntactic: an operation's context lists
  the conditions, loops, try blocks and directly-exiting `if`s / `Assert-*`
  calls around it in its own function. A guard in a caller, or one that exits
  from a nested block (the credential-pair check), is protected only by the
  golden tree.
- Binding pins follow variables through assignments, per scope, and into a
  called local function's parameters. A helper's body and return value are not
  modeled by dataflow, but every statement (a function definition among them)
  is pinned by an exact normalized-AST subtree digest (`STATEMENT_DIGESTS`), so
  any change anywhere — a helper's return expression, a constant, a reordered or
  inserted statement — fails the semantic floor and cannot be regenerated
  without a deliberate edit of that hand-maintained table.
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
- Credential taint follows binding values per scope; a value read through a
  credentialed handle (`$reg.GetDWORDValue(...)`) is data, not a credential, and
  taint does not follow a local function's return value (`$conn = _ldapConnection`
  in `_search`): that function's body is pinned instead.
- Cmdlet metadata is available only for cmdlets this pwsh has; for
  `Get-WmiObject` and the IIS cmdlets the gate's own strict prefix/alias rule
  applies (any prefix of a `-*Variable` parameter is refused).
- The check runs with pwsh 7 on Linux. Windows PowerShell 5.1 parses the
  script in the `collector-windows` job but does not run this gate.
