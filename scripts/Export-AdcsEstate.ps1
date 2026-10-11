<#
.SYNOPSIS
  Read-only AD CS estate collector for adcs-lens (Plan 001 Phase 1).

.DESCRIPTION
  Captures the inputs the adcs-lens deterministic core ingests, READ-ONLY:
    * CA registry config via `certutil -getreg` (policy EditFlags, CA
      InterfaceFlags, AuditFilter, CAType, policy DisableExtensionList) - read
      locally on the CA host.
    * AD Public Key Services objects via LDAP (enrollment services, certificate
      templates, enterprise OIDs, PKI-object security descriptors).
    * Published CA certificates and CRLs via LDAP (the AIA and CDP containers
      in the Configuration NC), written as DER + certs/index.json so the
      lifecycle detectors (CA cert/CRL expiry, weak algorithms) can run.

  It NEVER enrolls, requests, writes, or relays. It only reads. Output is a
  directory of JSON files matching adcs_lens.ingest's contract.

  Every read is PROVEN before it is reported (collector >= 0.10.0): an LDAP
  enumeration is marked complete in the manifest only when every page came
  back with result Success and the final paging cookie was empty (no size or
  time limit, no failed page); a certutil -getreg value is used only when
  certutil exited 0 (a value that is not set is "absent", any other failure is
  "not obtained"); security descriptors, the CA\Security hive, IIS properties
  and DC registry values are read inside try/catch with their return codes
  checked. A read that fails is written as JSON null - never as an empty list
  that would read as a clean configuration - and adcs-lens then treats that
  input as not obtained.

  Registry-derived configuration is read locally, so it is attributed only to
  the CA running on the collector host. Other CAs found in Enrollment Services
  are exported with registry_config_collected = false; the core's registry-
  gated detectors (ESC6/ESC7/ESC11/ESC16) skip them and an estate-level note
  names them. Re-run on each CA for full coverage.

  Auth: by default the script uses the current user's integrated Windows
  credentials (run as a Domain Admin or an account with read access to the
  PKI container). This mirrors the gpo-lens collector's approach and is the
  simplest path when running interactively on the CA or a tier-0 admin box.

  For key-based SSH sessions (where the network credential is not delegated -
  the double-hop problem), pass explicit LDAP credentials via -LdapUserB64 /
  -LdapPassB64. Base64 is used to survive quoting/escaping through SSH and
  PowerShell invocation layers; note it is NOT secrecy - the credential is
  still visible to local process inspection and script-block logging, like
  any command-line argument. When both are provided, the script binds with
  them; when neither is provided, it binds with integrated auth.

.PARAMETER OutDir
  Directory to write the export into (created if absent).

.PARAMETER LdapUserB64 / .PARAMETER LdapPassB64
  Optional. Base64 (UTF-8) of the LDAP bind username (UPN or DOMAIN\user)
  and password. When BOTH are provided, the script uses explicit LDAP
  binds (needed for key-based SSH / double-hop). When BOTH are omitted
  (the default), the script uses the current user's integrated credentials.
  Providing only one is an error.

.PARAMETER CollectDcMapping
  Opt in to the ESC10/ESC14 DC certificate-mapping passes (they widen the export
  footprint beyond the AD CS config). Enables esc14-altsecid (an LDAP read of
  principal altSecurityIdentities). Without it both passes are skipped + noted.

.PARAMETER DcRegistryUserB64 / .PARAMETER DcRegistryPassB64
  Optional. Base64 (UTF-8) creds with remote-registry read on the domain
  controllers, used by the esc10-dc-registry pass (KDC
  StrongCertificateBindingEnforcement + Schannel CertificateMappingMethods via
  WMI). Only used when -CollectDcMapping is set. When omitted, the pass uses
  the current user's integrated credentials (WMI without -Credential). When
  provided, the pass binds with them.
#>
[CmdletBinding(DefaultParameterSetName = 'Collect')]
param(
  [Parameter(Mandatory, ParameterSetName = 'Collect')] [string] $OutDir,
  # Optional: explicit LDAP creds for SSH / double-hop. When both are omitted,
  # the script uses the current user's integrated credentials (default).
  [Parameter(ParameterSetName = 'Collect')] [string] $LdapUserB64,
  [Parameter(ParameterSetName = 'Collect')] [string] $LdapPassB64,
  # ESC10/ESC14 DC certificate-mapping passes widen the export footprint, so they
  # are opt-in. When set, esc14-altsecid (LDAP altSecurityIdentities) runs; the
  # esc10-dc-registry pass additionally needs DC-admin creds for remote registry.
  [Parameter(ParameterSetName = 'Collect')] [switch] $CollectDcMapping,
  [Parameter(ParameterSetName = 'Collect')] [string] $DcRegistryUserB64,
  [Parameter(ParameterSetName = 'Collect')] [string] $DcRegistryPassB64,
  # Self-test: define the pure helper functions and return before any collection.
  # Lets the Pester suite dot-source this script and exercise the parsers/decoders
  # on Linux pwsh (the LDAP/WMI/certutil paths need Windows + a live estate).
  [Parameter(Mandatory, ParameterSetName = 'SelfTest')] [switch] $FunctionsOnly
)

$ErrorActionPreference = 'Stop'
$COLLECTOR_VERSION = '0.10.0'

function _b64([string]$s) { [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($s)) }

# objectGUID (a 16-byte LDAP attribute) as 32 lower-case hex characters, in the
# attribute's raw byte order. This is the object's immutable identity: it
# survives renames and moves, so the core matches findings across exports on
# it (collector >= 0.9.0). Empty when the attribute was not returned.
function _guidHex($values) {
  if (-not $values -or $values.Count -lt 1) { return '' }
  $b = [byte[]]$values[0]
  if ($b.Count -ne 16) { return '' }
  (($b | ForEach-Object { $_.ToString('x2') }) -join '')
}

# Use JavaScriptSerializer, not ConvertTo-Json: PS 5.1's ConvertTo-Json collapses
# single-element arrays to scalars (top-level AND nested), which would corrupt the
# list fields adcs_lens.ingest requires. JavaScriptSerializer honours the real
# .NET type, so a 1-element array stays a JSON array.
function _writeJson($obj, [string]$name) {
  $p = Join-Path $OutDir $name
  $dir = Split-Path $p -Parent
  if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
  [IO.File]::WriteAllText($p, $script:JS.Serialize($obj), (New-Object Text.UTF8Encoding($false)))
}

# --- LDAP plumbing -----------------------------------------------------------
# Searches use System.DirectoryServices.Protocols, not DirectorySearcher: only a
# raw paged search exposes the result code of every page and the server's
# paging cookie, which is what proves an enumeration returned every object.
#
# _pagedSearchCore is pure (the transport is the $send scriptblock: cookie in,
# response out), so the Pester suite can drive it with fake responses on Linux.
# A search is complete only when every page returned ResultCode Success, each
# carried a paging response control, and the last one's cookie was empty. A
# thrown page (DirectoryOperationException for sizeLimitExceeded /
# timeLimitExceeded / busy, a dropped connection) or a page cap reached leaves
# complete = false; the rows gathered so far are still returned.
function _pagedSearchCore([scriptblock]$send, [int]$maxPages = 100000) {
  $entries = New-Object System.Collections.ArrayList
  [byte[]]$cookie = @()
  $complete = $false
  $reason = "page limit ($maxPages) reached"
  for ($page = 0; $page -lt $maxPages; $page++) {
    try { $resp = & $send $cookie } catch { $reason = "page $page failed: $($_.Exception.Message)"; break }
    if ($null -eq $resp) { $reason = "page $page returned no response"; break }
    if ([string]$resp.ResultCode -ne 'Success') { $reason = "page $page result $($resp.ResultCode)"; break }
    foreach ($e in @($resp.Entries)) { [void]$entries.Add($e) }
    $ctl = @($resp.Controls | Where-Object { $null -ne $_ -and $_.PSObject.Properties['Cookie'] }) | Select-Object -First 1
    if ($null -eq $ctl) { $reason = "page $page carried no paging control"; break }
    $cookie = [byte[]]@($ctl.Cookie)
    if ($cookie.Length -eq 0) { $complete = $true; $reason = ''; break }
  }
  @{ entries = $entries; complete = $complete; reason = $reason }
}

# A single-object read (Base scope: RootDSE, one fixed container): complete only
# when the request returned ResultCode Success; no paging is involved.
function _baseSearchCore([scriptblock]$send) {
  try { $resp = & $send $null } catch { return @{ entries = @(); complete = $false; reason = "read failed: $($_.Exception.Message)" } }
  if ($null -eq $resp -or [string]$resp.ResultCode -ne 'Success') {
    return @{ entries = @(); complete = $false; reason = "result $($resp.ResultCode)" }
  }
  @{ entries = @($resp.Entries); complete = $true; reason = '' }
}

# Binary attributes; every other attribute is read as strings.
$BINARY_ATTRS = @('objectguid', 'ntsecuritydescriptor', 'cacertificate', 'certificaterevocationlist')

# A SearchResultEntry as a hashtable: lower-cased attribute name -> array of
# values (byte[] for binary attributes), plus 'distinguishedname'.
function _entryProps($entry) {
  $p = @{}
  foreach ($n in @($entry.Attributes.AttributeNames)) {
    $key = ([string]$n).ToLower()
    $attr = $entry.Attributes[[string]$n]
    if ($BINARY_ATTRS -contains $key) { $p[$key] = @($attr.GetValues([byte[]])) }
    else { $p[$key] = @($attr.GetValues([string])) }
  }
  $p['distinguishedname'] = @([string]$entry.DistinguishedName)
  $p
}
# The values of one attribute, emitted one by one (nothing when it was not
# returned). Always collect with @(_v ...): @@(_v $p 'cn')[0] is the first value.
function _v($p, [string]$name) { if ($p.ContainsKey($name)) { $p[$name] } }

# One LDAP connection for the run. Explicit credentials (-LdapUserB64 /
# -LdapPassB64) when given, otherwise the current user's integrated credentials;
# the domain controller is located by the OS (no server named). Bind only - the
# collector sends nothing but SearchRequests.
function _ldapConnection() {
  if ($script:LdapConn) { return $script:LdapConn }
  Add-Type -AssemblyName System.DirectoryServices.Protocols
  $id = [System.DirectoryServices.Protocols.LdapDirectoryIdentifier]::new($null)
  if ($LdapUser) {
    $cred = New-Object System.Net.NetworkCredential($LdapUser, $LdapPass)
    $conn = [System.DirectoryServices.Protocols.LdapConnection]::new($id, $cred)
  } else {
    $conn = [System.DirectoryServices.Protocols.LdapConnection]::new($id)
  }
  $conn.AuthType = [System.DirectoryServices.Protocols.AuthType]::Negotiate
  $conn.SessionOptions.ProtocolVersion = 3
  $conn.Bind()
  $script:LdapConn = $conn
  $conn
}
# A paged, read-only search: @{ entries; complete; reason } (see _pagedSearchCore).
# -Sd requests the DACL and Owner of nTSecurityDescriptor (no SACL: readable
# without SeSecurityPrivilege); -Scope Base reads one object.
function _search([string]$baseDn, [string]$filter, [string[]]$attrs,
                 [string]$Scope = 'Subtree', [switch]$Sd) {
  $conn = _ldapConnection
  $send = {
    param([byte[]]$cookie)
    $req = [System.DirectoryServices.Protocols.SearchRequest]::new(
      $baseDn, $filter, [System.DirectoryServices.Protocols.SearchScope]$Scope, $attrs)
    if ($Scope -ne 'Base') {
      $page = [System.DirectoryServices.Protocols.PageResultRequestControl]::new(500)
      if ($cookie -and $cookie.Length) { $page.Cookie = $cookie }
      [void]$req.Controls.Add($page)
    }
    if ($Sd) {
      [void]$req.Controls.Add([System.DirectoryServices.Protocols.SecurityDescriptorFlagControl]::new(
        [System.DirectoryServices.Protocols.SecurityMasks]'Dacl,Owner'))
    }
    $conn.SendRequest($req)
  }.GetNewClosure()
  if ($Scope -eq 'Base') { return _baseSearchCore $send }
  _pagedSearchCore $send
}
# RootDSE naming contexts (read once): @{ config; domain }.
function _rootDse() {
  if ($script:RootDse) { return $script:RootDse }
  $r = _search '' '(objectClass=*)' @('configurationNamingContext', 'defaultNamingContext') -Scope Base
  if (-not $r.complete -or $r.entries.Count -ne 1) { throw "RootDSE could not be read: $($r.reason)" }
  $p = _entryProps $r.entries[0]
  $script:RootDse = @{
    config = [string]@(_v $p 'configurationnamingcontext')[0]
    domain = [string]@(_v $p 'defaultnamingcontext')[0]
  }
  $script:RootDse
}
# A value that may be $null (not obtained) as JSON: $null stays null, anything
# else becomes an array (so a single item never collapses to a scalar).
function _list($value) { if ($null -eq $value) { return $null }; ,@($value) }

# What every LDAP-enumerated object must carry, per container: the one table.
# tests/test_object_schema.py checks it against ingest's required keys and the
# inputs detection.CHECKS declares. For each requested attribute: its type, the
# export field it feeds, and its need:
#   required     - identity / join / deciding: missing, empty or wrong-typed
#                  makes the object a failure (no row; container incomplete)
#   optional     - AD omits an attribute that has no value, so absence is the
#                  value (no flags, no EKU, not linked); present but empty or
#                  wrong-typed is still a failure
#   placeholder  - needed to read the object's deciding fields elsewhere (a DC's
#                  dNSHostName for its registry): missing / invalid keeps the
#                  object as an identity-bearing row with those fields null
#   sd           - the security descriptor, proven separately (_sdRead)
$OBJECT_SCHEMA = ConvertFrom-Json @'
{
  "enrollment-services": {
    "distinguishedname": {"type": "string", "need": "required", "field": "(identity)"},
    "cn": {"type": "string", "need": "required", "field": "name"},
    "objectguid": {"type": "guid", "need": "required", "field": "object_guid"},
    "dnshostname": {"type": "string", "need": "optional", "field": "dns"},
    "certificatetemplates": {"type": "strings", "need": "optional", "field": "(source of template.published_by)"}
  },
  "templates": {
    "distinguishedname": {"type": "string", "need": "required", "field": "(identity)"},
    "cn": {"type": "string", "need": "required", "field": "name"},
    "objectguid": {"type": "guid", "need": "required", "field": "object_guid"},
    "mspki-cert-template-oid": {"type": "string", "need": "required", "field": "oid"},
    "displayname": {"type": "string", "need": "optional", "field": "display_name"},
    "mspki-certificate-name-flag": {"type": "int", "need": "optional", "field": "name_flags"},
    "mspki-enrollment-flag": {"type": "int", "need": "optional", "field": "enrollment_flags"},
    "pkiextendedkeyusage": {"type": "strings", "need": "optional", "field": "ekus"},
    "mspki-certificate-policy": {"type": "strings", "need": "optional", "field": "issuance_policy_oids"},
    "pkicsp": {"type": "strings", "need": "optional", "field": "csp"},
    "mspki-template-schema-version": {"type": "int", "need": "optional", "field": "schema_version"},
    "mspki-minimal-key-size": {"type": "int", "need": "optional", "field": "min_key_size"},
    "ntsecuritydescriptor": {"type": "bytes", "need": "sd", "field": "security"}
  },
  "oid-objects": {
    "distinguishedname": {"type": "string", "need": "required", "field": "(identity)"},
    "mspki-cert-template-oid": {"type": "string", "need": "required", "field": "oid"},
    "objectguid": {"type": "guid", "need": "required", "field": "object_guid"},
    "displayname": {"type": "string", "need": "optional", "field": "name"},
    "msds-oidtogrouplink": {"type": "string", "need": "optional", "field": "group_link"}
  },
  "pki-acls": {
    "distinguishedname": {"type": "string", "need": "required", "field": "object_dn"},
    "objectguid": {"type": "guid", "need": "required", "field": "object_guid"},
    "ntsecuritydescriptor": {"type": "bytes", "need": "sd", "field": "security"}
  },
  "certs": {
    "distinguishedname": {"type": "string", "need": "required", "field": "(identity)"},
    "cn": {"type": "string", "need": "required", "field": "ca_name"},
    "cacertificate": {"type": "bytes", "need": "optional", "field": "(certificate)"}
  },
  "crls": {
    "distinguishedname": {"type": "string", "need": "required", "field": "source"},
    "cn": {"type": "string", "need": "required", "field": "ca_name"},
    "objectguid": {"type": "guid", "need": "required", "field": "object_guid"},
    "certificaterevocationlist": {"type": "bytes", "need": "optional", "field": "(crl)"}
  },
  "principal-mappings": {
    "distinguishedname": {"type": "string", "need": "required", "field": "dn"},
    "objectguid": {"type": "guid", "need": "required", "field": "object_guid"},
    "altsecurityidentities": {"type": "strings", "need": "required", "field": "mappings"}
  },
  "dc-config": {
    "distinguishedname": {"type": "string", "need": "required", "field": "(identity)"},
    "objectguid": {"type": "guid", "need": "required", "field": "object_guid"},
    "dnshostname": {"type": "string", "need": "placeholder", "field": "name"}
  }
}
'@

# Fields DERIVED from another object or container (a join, a lookup in a map an
# earlier loop built, a parent object's read), keyed subject.field as
# detection.CHECKS names them. For each: who derives it, the source fields and
# containers, the join, and what a miss yields. A source container that is
# incomplete, or a lookup that misses, yields null (not obtained) - never a
# default - and every check reading the field declares the source containers.
# tests/test_object_schema.py checks both, and every detection input must have
# exactly one source: a schema attribute, this table, or a named own-object
# read (registry, WMI, IIS, DER, security descriptor).
$DERIVED_FIELDS = ConvertFrom-Json @'
{
  "crl.tier": {
    "by": "ingest", "from": ["certs.kind"], "containers": ["certs"],
    "join": "the CRL's CDP cn = the AIA object's cn", "miss": "null"
  },
  "endpoint.transports": {
    "by": "collector", "from": ["IIS site bindings"], "containers": ["web-endpoints"],
    "join": "the application's site", "miss": "null"
  },
  "template.published_by": {
    "by": "ingest", "from": ["enrollment-services.certificatetemplates"],
    "containers": ["enrollment-services"], "join": "template cn, exactly ($JOINS publication)",
    "miss": "unpublished only when enrollment-services is complete",
    "text": "ESC1-3 publication detail says the list is incomplete when it is"
  },
  "cert.ca_kind": {
    "by": "ingest", "from": ["ca.kind"], "containers": ["ca-config"],
    "join": "certs/index.json ca_name = CA name", "miss": "null (unattached certificate)"
  }
}
'@

# Every join between objects - in the collector, ingest or a detector - with the
# keys it compares and what it does when a reference matches NO candidate or
# MORE THAN ONE. Keys are compared EXACTLY as stored: no join trims, folds case
# or Unicode-normalizes a key to make it match. A reference identical to no
# candidate but equal to one under that folding (" X ", "x", a compatibility
# character) is AMBIGUOUS. An ambiguous join never attaches to an arbitrary
# match: the joined field is not obtained (or ingest rejects the export), so no
# verdict relying on it is usable. "impl" names where the comparison lives:
# normalize.resolve_join in the core - the ONE implementation of key folding;
# this script never folds a key - or an exact -ceq here (marked
# "# join: <name>"); the core reads its keys from model.JOIN_KEYS.
# tests/test_object_schema.py ties this table to both and runs ambiguity cases.
#   MS-WCCE: each certificateTemplates value is identical to a template's cn
#   and the CA issues only for an identical match, so publication joins on cn,
#   exactly. Exports from older collectors also tried the OID.
$JOINS = ConvertFrom-Json @'
{
  "publication": {
    "field": "template.published_by", "by": "ingest", "impl": "resolve_join",
    "from": "enrollment-services.certificatetemplates", "to": "templates",
    "keys": ["cn"], "legacy_keys": ["cn", "oid"], "compare": "identical (MS-WCCE)",
    "none": "attaches nowhere (a published template that is not in AD)",
    "ambiguous": "published_by not obtained for every template it is identical or folds to"
  },
  "cert-ca": {
    "field": "cert.ca_kind", "by": "ingest", "impl": "resolve_join",
    "from": "certs.ca_name", "to": "ca-config",
    "keys": ["cn"], "compare": "identical (both are cn values the collector copied)",
    "none": "unattached: ca_kind not obtained",
    "ambiguous": "unattached: ca_kind not obtained (two CA rows folding together is an ingest error)"
  },
  "crl-tier": {
    "field": "crl.tier", "by": "ingest", "impl": "resolve_join",
    "from": "crls.ca_name (the CDP object's cn)", "to": "certs (certs/index.json ca_name)",
    "keys": ["ca_name"], "compare": "identical",
    "none": "tier null",
    "ambiguous": "tier null (also when one cn's certificates disagree on kind)"
  },
  "ca-security": {
    "field": "ca.security", "by": "ingest", "impl": "exact set",
    "from": "ca-security.json keys", "to": "ca-config",
    "keys": ["cn"], "compare": "identical (the collector writes the row's name)",
    "none": "ingest error: an entry naming no CA, or a CA without an entry",
    "ambiguous": "ingest error: two CA rows whose names fold together"
  },
  "publisher-ca": {
    "field": "ca.enrollment_service", "by": "ingest", "impl": "exact set",
    "from": "enrollment-services.json keys", "to": "ca-config",
    "keys": ["cn"], "compare": "identical (the collector writes the row's name)",
    "none": "ingest error: a publisher without a CA row, or the reverse",
    "ambiguous": "ingest error: two CA rows whose names fold together"
  },
  "oid-link": {
    "field": "oid.group_link", "by": "detection (ESC13)", "impl": "resolve_join",
    "from": "templates.issuance_policy_oids", "to": "oid-objects",
    "keys": ["oid"], "compare": "identical",
    "none": "no link: decided only when oid-objects is complete",
    "ambiguous": "ESC13 undecided (duplicate OIDs also mark oid-objects incomplete)"
  },
  "local-ca": {
    "field": "ca.edit_flags", "by": "collector", "impl": "-ceq",
    "from": "enrollment-services.cn", "to": "certutil CA\\CommonName",
    "keys": ["cn"], "compare": "identical (-ceq)",
    "none": "a remote CA: every registry field null (also for a CA whose AD name is sanitized)",
    "ambiguous": "ingest error: the local CA's standalone row and the enrollment service fold together"
  },
  "app-site": {
    "field": "endpoint.transports", "by": "collector", "impl": "parent object",
    "from": "IIS application", "to": "its IIS site", "keys": ["(parent object)"],
    "compare": "enumerated under the site",
    "none": "transports null when the site's bindings read nothing",
    "ambiguous": "impossible: each application is enumerated under one site"
  }
}
'@

# Check one object (a hashtable from _entryProps) against its container's
# schema: @{ fatal = <reason or $null>; soft = @(placeholder attributes that are
# missing or invalid) }. Never coerces: a missing required attribute is a
# failure, not ''.
function _schemaCheck($p, $spec) {
  # A container name with no schema is a collector bug, never "nothing required".
  if ($null -eq $spec) { throw 'no object schema for this container' }
  $soft = @()
  foreach ($prop in $spec.PSObject.Properties) {
    $attr = $prop.Name; $rule = $prop.Value
    # The descriptor is proven by _sdRead: unreadable is a null read, not a failure.
    if ($rule.need -eq 'sd') { continue }
    $values = @(_v $p $attr)
    $why = $null
    if ($values.Count -eq 0) {
      if ($rule.need -eq 'required') { $why = "$attr missing" }
      elseif ($rule.need -eq 'placeholder') { $why = "$attr missing" }
    } else {
      switch ($rule.type) {
        'guid' { if (-not ($values[0] -is [byte[]]) -or $values[0].Length -ne 16) { $why = "$attr is not a 16-byte objectGUID" } }
        'bytes' { foreach ($v in $values) { if (-not ($v -is [byte[]]) -or $v.Length -eq 0) { $why = "$attr is not a binary value" } } }
        'int' { $n = 0; if ($values.Count -ne 1 -or -not ($values[0] -is [string]) -or -not [int]::TryParse($values[0], [ref]$n)) { $why = "$attr is not an integer" } }
        'string' { if ($values.Count -ne 1 -or -not ($values[0] -is [string]) -or -not $values[0].Trim()) { $why = "$attr is empty or not a single string" } }
        'strings' { foreach ($v in $values) { if (-not ($v -is [string]) -or -not $v.Trim()) { $why = "$attr has an empty or non-string value" } } }
      }
    }
    if ($why) {
      if ($rule.need -eq 'placeholder') { $soft += $attr }
      else { return @{ fatal = $why; soft = $soft } }
    }
  }
  @{ fatal = $null; soft = $soft }
}
# Throw an object failure (caught by the loop, counted by its marker) when a
# required attribute is missing, empty or wrong-typed.
function _requireSchema($p, [string]$container) {
  $check = _schemaCheck $p $OBJECT_SCHEMA.$container
  if ($check.fatal) { throw "$container object $([string]@(_v $p 'distinguishedname')[0]): $($check.fatal)" }
  $check
}

# The enumeration marker of a container filled from verified searches. The
# collector-side invariant behind complete=$true: the searches were proven
# complete AND the rows serialized equal the objects they returned AND no object
# failed to serialize. Anything else is complete=$false with the reason - a row
# the collector dropped is never hidden behind a self-count of the rows it kept.
# count is always the rows written, so ingest can check it against the file.
# $rows is the number of rows written when it differs from the objects (an AIA
# object may carry several certificates); by default one row per object.
function _searchMarker([bool]$searched, [string]$searchReason, [int]$returned, [int]$written, [string[]]$failures, [int]$rows = -1) {
  $failures = @($failures | Where-Object { $_ })
  $complete = $searched -and $written -eq $returned -and $failures.Count -eq 0
  $m = [ordered]@{ complete = $complete; count = $(if ($rows -ge 0) { $rows } else { $written }) }
  if (-not $complete) {
    $why = @()
    if (-not $searched) { $why += $searchReason }
    if ($written -ne $returned -or $failures.Count) {
      $detail = "$written of $returned enumerated object(s) serialized"
      if ($failures.Count) { $detail += ': ' + ($failures -join '; ') }
      $why += $detail
    }
    $m['reason'] = ($why -join '; ')
  }
  $m
}

# --- bit-flag decoders (emit the documented MS names) -----------------------
$NAME_FLAGS = [ordered]@{
  0x00000001 = 'ENROLLEE_SUPPLIES_SUBJECT'
  0x00010000 = 'SUBJECT_ALT_REQUIRE_DOMAIN_DNS'
  0x00400000 = 'SUBJECT_ALT_REQUIRE_UPN'
  0x00800000 = 'SUBJECT_ALT_REQUIRE_EMAIL'
  0x04000000 = 'SUBJECT_ALT_REQUIRE_DNS'
  0x08000000 = 'SUBJECT_REQUIRE_DNS_AS_CN'
  0x10000000 = 'SUBJECT_REQUIRE_DIRECTORY_PATH'
  0x20000000 = 'SUBJECT_REQUIRE_EMAIL'
  0x40000000 = 'SUBJECT_REQUIRE_COMMON_NAME'
  0x00000008 = 'ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME'
}
$ENROLL_FLAGS = [ordered]@{
  0x00000002 = 'PEND_ALL_REQUESTS'                 # manager approval
  0x00000008 = 'PUBLISH_TO_DS'
  0x00000020 = 'AUTO_ENROLLMENT'
  0x00000100 = 'USER_INTERACTION_REQUIRED'
  0x00080000 = 'NO_SECURITY_EXTENSION'             # ESC9 (CT_FLAG_NO_SECURITY_EXTENSION)
}
function _decode([int]$value, $map) {
  $out = @()
  # Iterate entries (not $map[$k]): indexing an [ordered] dict with an int key
  # selects BY POSITION, not by key, which silently mis-decodes / yields $null.
  foreach ($e in $map.GetEnumerator()) { if ($value -band $e.Key) { $out += $e.Value } }
  ,$out
}

# Schannel CertificateMappingMethods bits (TLS registry-settings doc). The UPN bit
# (0x4) is ESC10 case 1. Kept here (not in the DC-mapping block) so the self-test
# can exercise the decode.
$SCHANNEL_BITS = [ordered]@{ 1 = 'subject_issuer'; 2 = 'issuer'; 4 = 'upn'; 8 = 's4u2self'; 16 = 's4u2self_explicit' }

# KDC StrongCertificateBindingEnforcement (0/1/2 -> disabled/permissive/strict).
function _decodeBinding([int]$v) {
  switch ($v) { 0 { 'disabled' } 1 { 'permissive' } 2 { 'strict' } default { 'unknown' } }
}

# Pure parsers for certutil -getreg output (split from the certutil invocation so
# the line-matching can be unit-tested without certutil/Windows).
function _parseCertutilFlagLines($lines) {
  $out = @()
  foreach ($line in $lines) { if ($line -match '^\s+([A-Z][A-Z0-9_]+)\s+--\s') { $out += $Matches[1] } }
  ,$out
}
function _parseCertutilDwordLines($lines) {
  # certutil prints the value in hex, with the decimal in parentheses only when
  # they differ ("= 7f (127)", but "= 0"): match the REG_DWORD line itself.
  foreach ($line in $lines) {
    if ($line -match 'REG_DWORD\s*=\s*(?:0x)?([0-9a-fA-F]+)\b') { return [Convert]::ToInt64($Matches[1], 16) }
  }
  return $null
}
# Parse certutil -getreg REG_MULTI_SZ output (e.g. policy\DisableExtensionList -> ESC16).
# certutil prints the value name + 'REG_MULTI_SZ' then each string on its own indented
# line; a first value may also follow '=' on the marker line. Captures OID-style tokens
# (no internal spaces); sufficient for DisableExtensionList, whose values are bare OIDs.
function _parseCertutilMultiSzLines($lines) {
  $out = @()
  $inMulti = $false
  foreach ($line in $lines) {
    if ($line -match 'REG_MULTI_SZ') {
      $inMulti = $true
      if ($line -match '=\s*(.+)$') {
        foreach ($tok in ($Matches[1] -split '\s+')) { if ($tok) { $out += $tok } }
      }
      continue
    }
    if ($inMulti) {
      if ($line -match '^\s+(\S+)') { $out += $Matches[1] }
      elseif ($line.Trim().Length) { break }
    }
  }
  ,$out
}

# certutil -getreg outcome. Exit code 0 is a successful read. A value or key
# that does not exist (0x80070002 ERROR_FILE_NOT_FOUND, exit code 2 or the
# HRESULT) is "absent": the setting is not configured. Anything else (service
# not running, access denied, certutil missing) is "failed": not obtained.
function _certutilStatus($lines, $exitCode) {
  if ($exitCode -eq 0) { return 'ok' }
  $text = ($lines | ForEach-Object { [string]$_ }) -join "`n"
  if ($exitCode -eq 2 -or $exitCode -eq -2147024894 -or $text -match '0x80070002|ERROR_FILE_NOT_FOUND') { return 'absent' }
  'failed'
}
# Flag names from a REG_DWORD flag value (EditFlags / InterfaceFlags): the list
# (possibly empty) when the value line was read, empty when the value is not
# set, $null when the read failed or the output carries no value line.
function _certutilFlagsFrom($lines, $exitCode) {
  switch (_certutilStatus $lines $exitCode) {
    'absent' { return ,@() }
    'failed' { return $null }
  }
  if ($null -eq (_parseCertutilDwordLines $lines)) { return $null }
  $flags = _parseCertutilFlagLines $lines   # returns the list as one object
  ,$flags
}
# A REG_DWORD value, or $null when it is not set or was not read.
function _certutilDwordFrom($lines, $exitCode) {
  if ((_certutilStatus $lines $exitCode) -ne 'ok') { return $null }
  _parseCertutilDwordLines $lines
}
# A REG_MULTI_SZ value: the list when read, empty when not set, $null on failure
# or when the output carries no REG_MULTI_SZ line.
function _certutilMultiSzFrom($lines, $exitCode) {
  switch (_certutilStatus $lines $exitCode) {
    'absent' { return ,@() }
    'failed' { return $null }
  }
  if (-not ($lines | Where-Object { [string]$_ -match 'REG_MULTI_SZ' })) { return $null }
  $values = _parseCertutilMultiSzLines $lines
  ,$values
}
# A REG_SZ value (e.g. CA\CommonName): @{ status = ok|absent|failed; value }.
function _certutilStringFrom($lines, $exitCode, [string]$name) {
  $status = _certutilStatus $lines $exitCode
  $value = $null
  if ($status -eq 'ok') {
    $value = ($lines | Where-Object { [string]$_ -match "$name REG_SZ = (.+)" } | ForEach-Object { $Matches[1].Trim() } | Select-Object -First 1)
    if (-not $value) { $status = 'failed' }
  }
  @{ status = $status; value = $value }
}

# StdRegProv GetDWORDValue outcome: ReturnValue 0 with a value is a read; 1 / 2
# (value / key not found) means not configured; anything else, or no result
# object at all, is a failed read.
function _wmiDwordStatus($result) {
  if ($null -eq $result) { return 'failed' }
  if ($result.ReturnValue -eq 0 -and $null -ne $result.uValue) { return 'ok' }
  if ($result.ReturnValue -eq 1 -or $result.ReturnValue -eq 2) { return 'absent' }
  'failed'
}

# Run one read; @{ ok = $true; value } on success, @{ ok = $false } when it threw.
# Lets a caller tell an empty result (ok, nothing there) from a failed read.
function _tryRead([scriptblock]$read) {
  try { @{ ok = $true; value = (& $read) } } catch { @{ ok = $false; value = $null } }
}

# IIS enrollment-endpoint classifiers (ESC8). Top-level so the self-test reaches
# them; the live IIS pass below calls these.
function _epaToken($v) {
  switch ([string]$v) {
    '2' { 'require' } 'Require' { 'require' }
    '1' { 'allow' }   'Allow'   { 'allow' }
    '0' { 'none' }    'Off' { 'none' } 'None' { 'none' } '' { 'none' }
    default { 'unknown' }
  }
}
function _classifyApp([string]$p) {
  $l = $p.ToLower()
  if ($l -match 'mscep') { return 'ndes' }            # NDES/SCEP
  if ($l -match 'certsrv') { return 'web_enrollment' } # /certsrv
  # CES/CEP: the _CES_ / _CEP_ infix (the default CEP endpoint names, e.g.
  # /ADPolicyProvider_CEP_Kerberos, /contoso_CES_Kerberos) or a path *segment*
  # that is exactly "cep". A bare substring match on 'cep' would false-match
  # unrelated apps (e.g. "/concept", "/reception"); require boundaries instead.
  if ($l -match '_ces_' -or $l -match '_cep_' -or $l -match '(^|/)cep($|/)') { return 'ces' }
  return $null
}

# --- CA kind from certutil CAType (CaKind in the core model) -----------------
# CA\CAType REG_DWORD: 0 = Enterprise Root, 1 = Enterprise Subordinate,
# 3 = Standalone Root, 4 = Standalone Subordinate. Enterprise CAs (0/1) map to
# 'issuing': they are online and serve AD-integrated enrollment, so the RPC/
# SID-extension checks (ESC11/ESC16) legitimately apply to them. A standalone
# root (3) maps to 'root' (the detectors' offline-root exclusions apply); a
# standalone subordinate (4) maps to 'standalone'. An unread or unknown CAType
# is $null (not obtained): never a guessed 'issuing'.
function _caKindFromType($t) {
  if ($null -eq $t) { return $null }
  switch ([int]$t) {
    0 { 'issuing'; return }
    1 { 'issuing'; return }
    3 { 'root'; return }
    4 { 'standalone'; return }
    # A CAType this collector does not know is not a kind it can name: null
    # (not obtained), never a guessed 'issuing'.
    default { $null; return }
  }
}

# --- cert/CRL helpers (the certs/ lifecycle pass) ----------------------------
# Filesystem-safe name for a DER file derived from a CA / object name.
function _safeFileName([string]$name) {
  ($name -replace '[^A-Za-z0-9._-]', '_')
}
# Classify a DER certificate as root_ca (self-signed: subject == issuer) or
# issuing_ca. Returns 'other' when the bytes cannot be parsed. Pure: works on
# any pwsh with .NET X509Certificate2, so the Pester suite can exercise it.
function _certKindFromDer([byte[]]$der) {
  if (-not $der -or $der.Length -eq 0) { return 'other' }
  try {
    $c = New-Object Security.Cryptography.X509Certificates.X509Certificate2(,$der)
    if ($c.Subject -eq $c.Issuer) { return 'root_ca' }
    return 'issuing_ca'
  } catch { return 'other' }
}

# --- nTSecurityDescriptor -> ACEs (ESC1/ESC4/ESC5/ESC7 inputs) --------------
# Extended-right GUIDs we care about; an all-zero ObjectType on an ExtendedRight
# ACE means "all extended rights" (which includes Enroll). The same all-zero
# ObjectType on a WriteProperty ACE means "write *all* properties" (blanket) -
# emitted as 'WritePropertyAll' so ESC4 can flag it (a blanket WriteProperty can
# rewrite msPKI-Certificate-Name-Flag -> ESC1). A non-zero ObjectType scopes the
# write to one property/property-set and is emitted as 'WriteProperty:<guid>'
# (lower-cased) so the core can match it against the dangerous-property GUID map
# (WI-019). A bare 'WriteProperty' (no GUID) from an older collector stays
# excluded - the scope is unknown.
$ENROLL_GUID     = '0e10c968-78fb-11d2-90d4-00c04f79dc55'
$AUTOENROLL_GUID = 'a05b8cc2-17b1-4cc8-8b00-94f99c9c2cca'
$ZERO_GUID       = '00000000-0000-0000-0000-000000000000'
function _parseAces([byte[]]$sdBytes) {
  $out = @()
  if (-not $sdBytes -or $sdBytes.Length -eq 0) { return ,$out }
  $sd = New-Object DirectoryServices.ActiveDirectorySecurity
  $sd.SetSecurityDescriptorBinaryForm($sdBytes)
  # Resolve trustees to SIDs (offline-safe); the friendly name is best-effort.
  foreach ($a in $sd.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
    $sid  = [string]$a.IdentityReference.Value
    $name = ''
    try { $name = [string]$a.IdentityReference.Translate([Security.Principal.NTAccount]).Value } catch { }
    $ot = $a.ObjectType.ToString()
    $rights = @()
    foreach ($flag in ($a.ActiveDirectoryRights.ToString() -split ',\s*')) {
      if ($flag -eq 'ExtendedRight') {
        if     ($ot -eq $ENROLL_GUID)     { $rights += 'Enroll' }
        elseif ($ot -eq $AUTOENROLL_GUID) { $rights += 'AutoEnroll' }
        elseif ($ot -eq $ZERO_GUID)       { $rights += 'AllExtendedRights' }
        else                              { $rights += 'ExtendedRight' }
      } elseif ($flag -eq 'WriteProperty') {
        if ($ot -eq $ZERO_GUID) { $rights += 'WritePropertyAll' }  # blanket: all properties
        else                    { $rights += "WriteProperty:$($ot.ToLower())" }  # scoped to one property/set
      } else {
        $rights += $flag
      }
    }
    $out += [ordered]@{
      trustee_sid  = $sid
      trustee_name = $name
      rights       = (@($rights))
      ace_type     = [string]$a.AccessControlType   # 'Allow' | 'Deny'
    }
  }
  ,$out
}

# --- PKI object DACLs (ESC5) ------------------------------------------------
# A security descriptor's ACEs and owner: @{ aces; owner }. aces is $null when
# the descriptor was not returned or could not be parsed (never an empty list);
# owner is $null when it could not be read.
function _sdRead($sdBytes) {
  if (-not $sdBytes -or $sdBytes.Length -eq 0) { return @{ aces = $null; owner = $null } }
  $aces = $null
  try { $aces = _parseAces ([byte[]]$sdBytes) } catch { $aces = $null }
  $owner = _readOwner ([byte[]]$sdBytes)
  if (-not $owner -or $null -eq $aces) { $owner = $null }
  @{ aces = $aces; owner = $owner }
}
# One PKI-object row from a search entry (hashtable from _entryProps).
function _aclRow($p, [string]$kind) {
  $sec = _sdRead (@(_v $p 'ntsecuritydescriptor')[0])
  [ordered]@{
    object_dn = [string]@(_v $p 'distinguishedname')[0]; kind = $kind; owner_sid = $sec.owner
    object_guid = (_guidHex @(_v $p 'objectguid'))
    security = $sec.aces; acl_obtained = ($null -ne $sec.aces)
  }
}
# Read the nTSecurityDescriptor of a single object (Base scope). $null when the
# object could not be read at all (absent, or no read access).
function _objAcl([string]$dn, [string]$kind) {
  $r = _search $dn '(objectClass=*)' @('ntsecuritydescriptor', 'objectguid') -Scope Base -Sd
  if (-not $r.complete -or $r.entries.Count -ne 1) { return $null }
  $p = _entryProps $r.entries[0]
  # A fixed container without a valid identity is reported as unreadable (the
  # caller's gap row), never as a row with a coerced GUID.
  if ((_schemaCheck $p $OBJECT_SCHEMA.'pki-acls').fatal) { return $null }
  _aclRow $p $kind
}
# Enumerate the child objects under a container and tokenise each one's DACL:
# @{ rows; complete; reason } - complete only when the paged search proved it.
function _childAcls([string]$containerDn, [string]$filter, [string]$kind) {
  $r = _search $containerDn $filter @('ntsecuritydescriptor', 'objectguid') -Sd
  $rows = @(); $failures = @()
  foreach ($e in $r.entries) {
    try {
      $p = _entryProps $e
      $null = _requireSchema $p 'pki-acls'
      $rows += _aclRow $p $kind
    } catch { $failures += "$kind`: $($_.Exception.Message)" }
  }
  @{ rows = $rows; complete = $r.complete; reason = $r.reason; returned = @($r.entries).Count; failures = $failures }
}

function _readOwner([byte[]]$sdBytes) {
  # The security descriptor Owner (a SID) - a low-priv owner can rewrite the
  # DACL to grant itself control (ESC4/ESC5 owner-based path, WI-019). Returns
  # the owner SID string, or '' when the SD is absent/malformed/has no owner.
  if (-not $sdBytes -or $sdBytes.Length -eq 0) { return '' }
  try {
    $sd = New-Object DirectoryServices.ActiveDirectorySecurity
    $sd.SetSecurityDescriptorBinaryForm($sdBytes)
    return [string]$sd.GetOwner([Security.Principal.SecurityIdentifier]).Value
  } catch { return '' }
}

# The CA's own role permissions (ESC7) live in the registry "Security" REG_BINARY,
# not AD. Parse the raw SD so we get SIDs + CA access-mask bits directly (offline),
# rather than certutil's name-resolved text (domain name lookups hit the double-hop).
# Returns @{ aces; owner }, each $null when not obtained (absent or unparseable
# value) - an unread descriptor is never an empty ACL.
function _caSecurityFromBytes($bytes) {
  if (-not $bytes -or $bytes.Length -eq 0) { return @{ aces = $null; owner = $null } }
  try { $rsd = New-Object Security.AccessControl.RawSecurityDescriptor(@([byte[]]$bytes), 0) }
  catch { return @{ aces = $null; owner = $null } }
  $out = @()
  foreach ($a in $rsd.DiscretionaryAcl) {
    $m = [int]$a.AccessMask
    $rights = @()
    if ($m -band 0x1)   { $rights += 'ManageCA' }            # CA_ACCESS_ADMIN
    if ($m -band 0x2)   { $rights += 'ManageCertificates' }  # CA_ACCESS_OFFICER
    if ($m -band 0x4)   { $rights += 'Auditor' }
    if ($m -band 0x8)   { $rights += 'Operator' }
    if ($m -band 0x100)     { $rights += 'Read' }
    if ($m -band 0x200)     { $rights += 'Enroll' }
    if ($m -band 0x10000000){ $rights += 'GenericAll' }
    $type = if ($a.AceQualifier -eq 'AccessDenied') { 'Deny' } else { 'Allow' }
    $out += [ordered]@{
      trustee_sid  = [string]$a.SecurityIdentifier.Value
      trustee_name = ''
      rights       = (@($rights))
      ace_type     = $type
    }
  }
  $owner = if ($rsd.Owner) { [string]$rsd.Owner.Value } else { $null }
  @{ aces = $out; owner = $owner }
}

# Pure bytes -> owner SID (CA\Security owner, ESC7 owner-based control, WI-037).
# Returns '' for absent/empty/unparseable input.
function _rawSdOwner([byte[]]$bytes) {
  $sec = _caSecurityFromBytes $bytes
  if ($sec.owner) { $sec.owner } else { '' }
}

# Read the local CA\Security hive for one CA: @{ aces; owner } (see above).
function _caSecurityRead([string]$caName) {
  $r = _tryRead {
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
      "SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$caName")
    if ($key) { $key.GetValue('Security') } else { $null }
  }
  if (-not $r.ok) { return @{ aces = $null; owner = $null } }
  _caSecurityFromBytes $r.value
}

# --- CA registry via certutil (local, no network cred needed) ---------------
# Run certutil -getreg (read-only) and keep its exit code: @{ lines; code }.
# Native stderr is captured, never turned into a terminating error.
function _certutilRead([string]$regpath) {
  $prev = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  try {
    $lines = @(& certutil -getreg $regpath 2>&1 | ForEach-Object { [string]$_ })
    $code = $LASTEXITCODE
  } catch {
    $lines = @([string]$_.Exception.Message); $code = -1
  } finally { $ErrorActionPreference = $prev }
  @{ lines = $lines; code = $code }
}
function _certutilFlags([string]$regpath) { $r = _certutilRead $regpath; _certutilFlagsFrom $r.lines $r.code }
function _certutilDword([string]$regpath) { $r = _certutilRead $regpath; _certutilDwordFrom $r.lines $r.code }
function _certutilMultiSz([string]$regpath) { $r = _certutilRead $regpath; _certutilMultiSzFrom $r.lines $r.code }

# --- self-test boundary -----------------------------------------------------
# Everything above is a pure function/data definition. The Pester suite dot-sources
# this script with -FunctionsOnly and stops here; nothing below runs in that mode.
if ($PSCmdlet.ParameterSetName -eq 'SelfTest') { return }

# --- Credential resolution ---------------------------------------------------
# When both -LdapUserB64 and -LdapPassB64 are provided, decode them and use
# explicit LDAP binds (needed for key-based SSH / double-hop). When both are
# omitted (the default), leave $LdapUser/$LdapPass empty so _ldapConnection binds
# with the current user's integrated credentials. Providing only one is an
# error - a half-specified credential pair would silently bind as the wrong
# identity.
$LdapUser = ''
$LdapPass = ''
if ($LdapUserB64 -or $LdapPassB64) {
  if (-not ($LdapUserB64 -and $LdapPassB64)) {
    throw "Provide BOTH -LdapUserB64 and -LdapPassB64 for explicit LDAP creds, or NEITHER for integrated auth (current user)."
  }
  $LdapUser = _b64 $LdapUserB64
  $LdapPass = _b64 $LdapPassB64
}
if ($LdapUser) {
  Write-Host "Using explicit LDAP credentials ($LdapUser)"
} else {
  Write-Host "Using integrated auth (current user) for LDAP"
}

# DC registry creds: same pattern. When both provided, use them; when both
# omitted, the esc10-dc-registry pass uses the current user's integrated creds.
# Only validated when -CollectDcMapping is set (otherwise the creds are never
# used).
$DcRegistryUser = ''
$DcRegistryPass = ''
if ($CollectDcMapping -and ($DcRegistryUserB64 -or $DcRegistryPassB64)) {
  if (-not ($DcRegistryUserB64 -and $DcRegistryPassB64)) {
    throw "Provide BOTH -DcRegistryUserB64 and -DcRegistryPassB64 for explicit DC creds, or NEITHER for integrated auth."
  }
  $DcRegistryUser = _b64 $DcRegistryUserB64
  $DcRegistryPass = _b64 $DcRegistryPassB64
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
Add-Type -AssemblyName System.Web.Extensions
$script:JS = New-Object System.Web.Script.Serialization.JavaScriptSerializer
$script:JS.MaxJsonLength = [int]::MaxValue

# Enumeration completion markers (collector >= 0.10.0). One per collected
# container: complete = $true only when its paged searches provably returned
# every object (see _pagedSearchCore) and every read it depends on succeeded;
# otherwise complete = $false with the reason. count is the number of rows
# written either way, so ingest can check the marker against the file.
$enumeration = [ordered]@{}
function _mark([string]$container, [bool]$complete, [int]$count, [string]$reason) {
  $m = [ordered]@{ complete = $complete; count = $count }
  if (-not $complete) { $m['reason'] = $reason }
  $enumeration[$container] = $m
}
# Every LDAP-backed container is marked through _searchMarker: each loop below
# serializes every object its search returned (a failed object is caught and
# recorded, never silently skipped), and the marker compares the two counts.
function _markSearch([string]$container, $search, [int]$returned, [int]$written, [string[]]$failures, [int]$rows = -1) {
  $enumeration[$container] = _searchMarker ([bool]$search.complete) ([string]$search.reason) $returned $written $failures $rows
}

# The local CA's registry, read once (certutil -getreg, read-only). A value that
# could not be read is $null; a value that is not set is an empty list.
$cnRead         = _certutilRead 'CA\CommonName'
$cnResult       = _certutilStringFrom $cnRead.lines $cnRead.code 'CommonName'
$caCommonName   = $cnResult.value
$editFlags      = _certutilFlags 'policy\EditFlags'
$interfaceFlags = _certutilFlags 'CA\InterfaceFlags'
$auditFilter    = _certutilDword 'CA\AuditFilter'
$disabledExt    = _certutilMultiSz 'policy\DisableExtensionList'
$caType         = _certutilDword 'CA\CAType'
$localKind      = if ($null -ne $caType) { _caKindFromType $caType } else { $null }

# Registry hives are LOCAL to the collector host: the CA they describe is the
# local one. Resolve the local identity once (short + FQDN) so enrollment
# services for OTHER CAs are not mis-attributed this host's registry config.
$localHost = ([string](hostname)).ToLower()
try { $localFqdn = ([System.Net.Dns]::GetHostEntry($localHost).HostName).ToLower() } catch { $localFqdn = $localHost }

$rootDse = _rootDse
$pksDn = "CN=Public Key Services,CN=Services,$($rootDse.config)"

# The registry row of the local CA (enterprise or standalone).
function _localCaRow([string]$name, [string]$dns, [string]$guid, [bool]$enrollmentService) {
  $sec = _caSecurityRead $name
  $script:localSecurity[$name] = $sec.aces
  [ordered]@{
    name           = $name
    dns            = $dns
    config_string  = "$dns\$name"
    object_guid    = $guid
    enrollment_service = $enrollmentService
    kind           = $localKind
    edit_flags     = (_list $editFlags)
    interface_flags= (_list $interfaceFlags)
    audit_filter   = $auditFilter
    # Collector cannot yet read CA build/patch level statically (ESC15 /
    # CVE-2024-49019): 'unknown' lets the detector degrade ESC15 to MEDIUM.
    ca_patch_state = 'unknown'
    disabled_extensions = (_list $disabledExt)
    # CA\Security owner (ESC7 owner-based control, WI-037): null when the local
    # registry SD could not be read.
    owner_sid      = $sec.owner
    registry_config_collected = $true
  }
}
$script:localSecurity = @{}

# --- enrollment services (CAs) ----------------------------------------------
$caConfig = @()
$enrollmentServices = [ordered]@{}
$es = _search "CN=Enrollment Services,$pksDn" '(objectClass=pKIEnrollmentService)' @('cn', 'dnshostname', 'certificatetemplates', 'objectguid')
$esFailures = @()
foreach ($e in $es.entries) {
  try {
    $p = _entryProps $e
    $null = _requireSchema $p 'enrollment-services'
    $cn = [string]@(_v $p 'cn')[0]; $dns = [string]@(_v $p 'dnshostname')[0]
    $published = @(_v $p 'certificatetemplates' | ForEach-Object { [string]$_ })
    $caHost = ([string]$dns -split '\.')[0].ToLower()
    # The local CA: its common name matches certutil's AND its dns host is this
    # machine. Everything else is remote: its registry-derived fields are null and
    # registry_config_collected=false tells the core those detectors were NOT
    # evaluated for this CA (a named gap, never a silent clean).
    # join: local-ca - the enrollment service's cn is compared with certutil's
    # CA\CommonName exactly (-ceq): a near match is not this CA.
    $isLocal = ($caCommonName -and $cn -ceq $caCommonName -and
                $caHost -and ($caHost -eq $localHost -or $dns.ToLower() -eq $localFqdn))
    if ($isLocal) {
      $row = _localCaRow $cn $dns (_guidHex @(_v $p 'objectguid')) $true
    } else {
      $row = [ordered]@{
        name           = $cn
        dns            = $dns
        config_string  = "$dns\$cn"
        object_guid    = (_guidHex @(_v $p 'objectguid'))
        enrollment_service = $true
        # An enterprise CA may be a root or a subordinate: CAType is read from
        # the CA's own registry, so for a remote CA the kind is not obtained.
        kind           = $null
        edit_flags     = $null
        interface_flags= $null
        audit_filter   = $null
        ca_patch_state = 'unknown'
        disabled_extensions = $null
        owner_sid      = $null
        registry_config_collected = $false
      }
    }
    # Both outputs of this object are written together, last, so a failure
    # above leaves neither (and the markers below count the gap).
    $caConfig += $row
    $enrollmentServices[$cn] = $published
  } catch { $esFailures += "enrollment service: $($_.Exception.Message)" }
}

# A CA not published as an enrollment service (a standalone CA is never in
# Enrollment Services) is invisible to the LDAP pass above. If the LOCAL host
# is such a CA, add it so its registry config is still evaluated.
$standalone = 0
# Only when every enrollment service was serialized: a failed object may be the
# local CA itself, which must not come back as a GUID-less "standalone" row.
# join: local-ca - and only when no enrollment service's cn is identical to the
# local CA's (-ceq). A near match is not resolved here: both rows are written
# and ingest, which makes every ambiguity decision, rejects two CA names that
# fold together.
if ($caCommonName -and -not $esFailures -and -not ($caConfig | Where-Object { $_.name -ceq $caCommonName })) {
  # A standalone CA has no Enrollment Services object, so no objectGUID.
  $caConfig += (_localCaRow $caCommonName $localFqdn '' $false)
  $standalone = 1
}
# ca-config is complete when the enrollment-services search was, every
# enrollment service became a row, AND the local CA question was answered:
# CA\CommonName read (a CA) or absent (not a CA host).
$caSearch = @{ complete = ($es.complete -and $cnResult.status -ne 'failed')
               reason = $(if (-not $es.complete) { $es.reason } else { 'CA\CommonName could not be read' }) }
_markSearch 'ca-config' $caSearch (@($es.entries).Count + $standalone) $caConfig.Count $esFailures
# One mapping entry per enrollment service: two services sharing a cn would
# collapse to one key, and the count mismatch marks the container incomplete.
_markSearch 'enrollment-services' $es @($es.entries).Count $enrollmentServices.Count $esFailures

# --- certificate templates --------------------------------------------------
$templates = @()
$ts = _search "CN=Certificate Templates,$pksDn" '(objectClass=pKICertificateTemplate)' @(
  'cn', 'displayname', 'objectguid', 'mspki-certificate-name-flag', 'mspki-enrollment-flag',
  'pkiextendedkeyusage', 'mspki-certificate-policy', 'pkicsp', 'mspki-template-schema-version',
  'mspki-cert-template-oid', 'mspki-minimal-key-size', 'ntsecuritydescriptor') -Sd
$tsFailures = @()
foreach ($e in $ts.entries) {
  try {
    $p = _entryProps $e
    $null = _requireSchema $p 'templates'
    $nf = if (@(_v $p 'mspki-certificate-name-flag').Count) { [int]@(_v $p 'mspki-certificate-name-flag')[0] } else { 0 }
    $ef = if (@(_v $p 'mspki-enrollment-flag').Count) { [int]@(_v $p 'mspki-enrollment-flag')[0] } else { 0 }
    $csps = @(_v $p 'pkicsp' | ForEach-Object { [string]$_ })
    $sec = _sdRead (@(_v $p 'ntsecuritydescriptor')[0])
    $templates += [ordered]@{
      name              = [string]@(_v $p 'cn')[0]
      object_guid       = (_guidHex @(_v $p 'objectguid'))
      display_name      = [string]@(_v $p 'displayname')[0]
      schema_version    = if (@(_v $p 'mspki-template-schema-version').Count) { [int]@(_v $p 'mspki-template-schema-version')[0] } else { 1 }
      oid               = [string]@(_v $p 'mspki-cert-template-oid')[0]
      ekus              = (@(_v $p 'pkiextendedkeyusage' | ForEach-Object { [string]$_ }))
      name_flags        = (_decode $nf $NAME_FLAGS)
      enrollment_flags  = (_decode $ef $ENROLL_FLAGS)
      min_key_size      = if (@(_v $p 'mspki-minimal-key-size').Count) { [int]@(_v $p 'mspki-minimal-key-size')[0] } else { $null }
      issuance_policy_oids = (@(_v $p 'mspki-certificate-policy' | ForEach-Object { [string]$_ }))
      csp               = (($csps -join ', ').ToLower())
      security          = $sec.aces                  # template DACL -> ACEs (ESC1/ESC4); null if not obtained
      acl_obtained      = ($null -ne $sec.aces)      # SD requested, returned and parsed
      owner_sid         = $sec.owner
    }
  } catch { $tsFailures += "template: $($_.Exception.Message)" }
}
_markSearch 'templates' $ts @($ts.entries).Count $templates.Count $tsFailures

# --- enterprise OID objects (issuance policies) -----------------------------
$oids = @()
$os = _search "CN=OID,$pksDn" '(objectClass=msPKI-Enterprise-Oid)' @('mspki-cert-template-oid', 'objectguid', 'displayname', 'msds-oidtogrouplink')
$osFailures = @()
foreach ($e in $os.entries) {
  try {
    $p = _entryProps $e
    $null = _requireSchema $p 'oid-objects'
    # The OID->group link (ESC13) is msDS-OIDToGroupLink (a group DN), NOT
    # msPKI-OIDToGroupLink - the latter does not exist, so the old name always
    # read $null and ESC13 could never fire on real data.
    $gl = if (@(_v $p 'msds-oidtogrouplink').Count) { [string]@(_v $p 'msds-oidtogrouplink')[0] } else { $null }
    $oids += [ordered]@{
      oid        = [string]@(_v $p 'mspki-cert-template-oid')[0]
      object_guid = (_guidHex @(_v $p 'objectguid'))
      name       = [string]@(_v $p 'displayname')[0]
      group_link = $gl
    }
  } catch { $osFailures += "OID: $($_.Exception.Message)" }
}
_markSearch 'oid-objects' $os @($os.entries).Count $oids.Count $osFailures

# --- PKI object ACLs (ESC5) --------------------------------------------------
# Capture DACLs on the Public Key Services containers + CA objects. A low-priv
# trustee with object-control rights (WriteDacl/WriteOwner/GenericWrite/
# GenericAll) on any of these is the ESC5 escalation primitive.
$pkiAcls = @()
foreach ($pair in @(
    @($pksDn,                                        'pks_container'),
    @("CN=NTAuthCertificates,$pksDn",                'ntauth'),
    @("CN=AIA,$pksDn",                               'aia'),
    @("CN=CDP,$pksDn",                               'cdp'),
    @("CN=Certification Authorities,$pksDn",         'pks_container'),
    @("CN=Enrollment Services,$pksDn",               'pks_container'))) {
  $a = _objAcl $pair[0] $pair[1]
  if ($a) { $pkiAcls += $a }
  else {
    # One of the well-known fixed containers could not be read at all (LDAP
    # denial). Emit a gap marker (acl_obtained=$false, security null) so ESC5
    # does not silently clear it.
    $pkiAcls += [ordered]@{
      object_dn = $pair[0]; kind = $pair[1]; owner_sid = $null
      object_guid = ''   # the object could not be read at all
      security = $null; acl_obtained = $false
    }
  }
}
# Individual CA objects: trusted roots + issuing enrollment services.
$caObjects = _childAcls "CN=Certification Authorities,$pksDn" '(objectClass=certificationAuthority)' 'ca_object'
$esObjects = _childAcls "CN=Enrollment Services,$pksDn"       '(objectClass=pKIEnrollmentService)'   'ca_object'
$pkiAcls += $caObjects.rows
$pkiAcls += $esObjects.rows
# The six fixed containers always yield a row (a gap row when unreadable); the
# child searches must serialize every object they returned.
$pkiSearch = @{ complete = ($caObjects.complete -and $esObjects.complete)
                reason = $(if (-not $caObjects.complete) { $caObjects.reason } else { $esObjects.reason }) }
_markSearch 'pki-acls' $pkiSearch (6 + $caObjects.returned + $esObjects.returned) $pkiAcls.Count (@($caObjects.failures) + @($esObjects.failures))

# --- CA role security (ESC7) -------------------------------------------------
# Keyed by the CA name used in ca-config.json so ingest joins them to the CA:
# the ACEs read from the CA host's LOCAL registry, or null when they were not
# (a remote CA, or a failed read). When NO CA yields a descriptor (e.g. the
# collector ran on a tier-0 box that is not a CA), the pass effectively did not
# run: mark it skipped so the core emits its CA_SECURITY_NOT_EVALUATED note.
$caSecurity = [ordered]@{}
$anyCaSecurity = $false
foreach ($ca in $caConfig) {
  # Assigned directly (not through an if-expression, which would unroll a
  # one-ACE list into a bare object).
  $aces = $null
  if ($ca.registry_config_collected -and $script:localSecurity.ContainsKey($ca.name)) { $aces = $script:localSecurity[$ca.name] }
  $caSecurity[$ca.name] = $aces
  if ($null -ne $aces) { $anyCaSecurity = $true }
}

# --- CA certificates + CRLs (lifecycle path, plan 001 certs/) ----------------
# Published CA certs (AIA container children, cACertificate) and base CRLs (CDP
# container children, certificateRevocationList), read from AD via plain LDAP -
# no certutil, so this runs from any domain member. Crucially it captures the
# OFFLINE ROOT's cert and CRL from their published locations: the root box is
# powered off by design, so its expired CRL is the catastrophic-but-invisible
# case this pass exists to make detectable. Delta CRLs (deltaRevocationList)
# are skipped; only the base CRL gates chain validation.
$certsSkipped = $true
$certIndex = @()
$crlIndex = @()
try {
  $certDir = Join-Path $OutDir 'certs'
  $i = 0
  $aia = _search "CN=AIA,$pksDn" '(objectClass=certificationAuthority)' @('cn', 'cacertificate')
  $aiaFailures = @(); $aiaObjects = 0
  foreach ($e in $aia.entries) {
    try {
      $p = _entryProps $e
      $null = _requireSchema $p 'certs'
      $cn = [string]@(_v $p 'cn')[0]
      $rows = @()
      foreach ($blob in @(_v $p 'cacertificate')) {
        $der = [byte[]]$blob
        # The certificate's own DER decides its kind; one that does not parse
        # is an object failure, never kind 'other'.
        $kind = _certKindFromDer $der
        if ($kind -eq 'other') { throw "AIA object $cn carries a certificate that does not parse" }
        $rows += ,@($der, $kind)
      }
      # Rows are recorded only once the whole object serialized (a failure
      # above leaves none).
      foreach ($r in $rows) {
        $der = $r[0]; $kind = $r[1]
        New-Item -ItemType Directory -Force -Path $certDir | Out-Null
        $file = '{0:d2}-{1}.cer' -f $i, (_safeFileName $cn); $i++
        [IO.File]::WriteAllBytes((Join-Path $certDir $file), $der)
        # ca_name joins to ca-config.json by CA common name at ingest. For an
        # enterprise CA the AIA child's CN IS the CA common name; a mismatch
        # would leave the cert unattached (a coverage gap, not a false finding).
        $certIndex += [ordered]@{ file = $file; ca_name = $cn; kind = $kind }
      }
      $aiaObjects++
    } catch { $aiaFailures += "AIA object: $($_.Exception.Message)" }
  }
  $j = 0
  $cdp = _search "CN=CDP,$pksDn" '(objectClass=cRLDistributionPoint)' @('cn', 'certificaterevocationlist', 'objectguid')
  $cdpFailures = @(); $cdpObjects = 0
  # A CRL's tier is DERIVED from another container (the AIA certificates of the
  # CA with the same cn: self-signed = root). The collector does not decide it:
  # it writes the CDP object's cn verbatim as ca_name, and ingest makes the join
  # (normalize.resolve_join, the one implementation of every key comparison)
  # against certs/index.json, only when the certs marker is complete.
  foreach ($e in $cdp.entries) {
    try {
      $p = _entryProps $e
      $null = _requireSchema $p 'crls'
      $cn = [string]@(_v $p 'cn')[0]
      # A CDP object with no base CRL publishes no CRL: there is no CRL row to
      # write (not a dropped object - CRLs are never resolved by absence anyway).
      if (-not @(_v $p 'certificaterevocationlist').Count) { $cdpObjects++; continue }
      $der = [byte[]]@(_v $p 'certificaterevocationlist')[0]
      New-Item -ItemType Directory -Force -Path $certDir | Out-Null
      $file = '{0:d2}-{1}.crl' -f $j, (_safeFileName $cn); $j++
      [IO.File]::WriteAllBytes((Join-Path $certDir $file), $der)
      $crlIndex += [ordered]@{
        object_guid = (_guidHex @(_v $p 'objectguid'))   # the CDP object
        file   = $file
        ca_name = $cn   # the CDP object's cn, verbatim: ingest derives the tier
        source = "AD CDP container: $([string]@(_v $p 'distinguishedname')[0])"
      }
      $cdpObjects++
    } catch { $cdpFailures += "CDP object: $($_.Exception.Message)" }
  }
  if ($certIndex.Count -gt 0 -or $crlIndex.Count -gt 0) { $certsSkipped = $false }
  # One AIA object may carry several certificates and a CDP object none, so the
  # marker compares OBJECTS returned with objects serialized, and counts rows.
  _markSearch 'certs' $aia @($aia.entries).Count $aiaObjects $aiaFailures $certIndex.Count
  _markSearch 'crls' $cdp @($cdp.entries).Count $cdpObjects $cdpFailures $crlIndex.Count
} catch {
  Write-Warning "certs pass failed: $($_.Exception.Message)"
}

# --- HTTP enrollment endpoints (ESC8) ---------------------------------------
# IIS bindings + Windows-auth + Extended Protection on the Web Enrollment
# (/certsrv) and CES apps. Needs WebAdministration on the host; absent off the
# enrollment host, so the pass is skipped + noted (the detector degrades).
$webEndpoints = @()
$endpointsSkipped = $true
try { Import-Module WebAdministration -ErrorAction Stop; $endpointsSkipped = $false } catch { }
if (-not $endpointsSkipped) {
  $endpointsComplete = $true; $endpointsReason = ''; $iisFailures = @()
  try {
    foreach ($site in (Get-Website -ErrorAction Stop)) {
      $protos = @(); foreach ($b in $site.bindings.Collection) { if ($protos -notcontains [string]$b.protocol) { $protos += [string]$b.protocol } }
      foreach ($app in (Get-WebApplication -Site $site.Name -ErrorAction Stop)) {
        # A property getter that fails reads as empty (PowerShell swallows it):
        # an application whose path cannot be read cannot be classified, so it
        # is a failure that marks the container incomplete, not a filtered app.
        $appPath = [string]$app.path
        if (-not $appPath) { $iisFailures += "IIS application under '$($site.Name)' has no readable path"; continue }
        $kind = _classifyApp $appPath
        # transports are DERIVED from the site's bindings, not the application:
        # a site always has a binding, so none read is not obtained (null).
        $transports = $null
        if ($protos.Count) { $transports = @($protos) }
        # Not Web Enrollment / CES / NDES: outside this container by definition.
        if (-not $kind) { continue }
        $ps = "IIS:\Sites\$($site.Name)\" + $appPath.TrimStart('/')
        $auth = 'system.webServer/security/authentication/windowsAuthentication'
        # Every property read is checked: a read that throws is null (not
        # obtained), never a benign default.
        $wa  = _tryRead { Get-WebConfigurationProperty -PSPath $ps -Filter $auth -Name enabled -ErrorAction Stop }
        $tc  = _tryRead { Get-WebConfigurationProperty -PSPath $ps -Filter $auth -Name 'extendedProtection.tokenChecking' -ErrorAction Stop }
        $ssl = _tryRead { Get-WebConfigurationProperty -PSPath $ps -Filter 'system.webServer/security/access' -Name sslFlags -ErrorAction Stop }
        $pr  = _tryRead { Get-WebConfigurationProperty -PSPath $ps -Filter "$auth/providers" -Name Collection -ErrorAction Stop }
        $provs = $null
        if ($pr.ok) { $provs = @(); foreach ($p in @($pr.value)) { if ($p.value) { $provs += ([string]$p.value).ToLower() } } }
        $webEndpoints += [ordered]@{
          kind           = $kind
          name           = $appPath
          transports     = $transports
          ssl_required   = if ($ssl.ok) { ([string]$ssl.value.Value) -match 'Ssl' } else { $null }
          windows_auth   = if ($wa.ok) { [bool]$wa.value.Value } else { $null }
          auth_providers = (_list $provs)
          epa            = if ($tc.ok) { _epaToken $tc.value.Value } else { $null }
        }
      }
    }
  } catch {
    $endpointsComplete = $false; $endpointsReason = "IIS enumeration failed: $($_.Exception.Message)"
    Write-Warning $endpointsReason
  }
  # Endpoints are a filter of the IIS applications (no 1:1 count to compare); an
  # application that could not be read or classified is what marks this.
  $enumeration['web-endpoints'] = _searchMarker $endpointsComplete $endpointsReason $webEndpoints.Count $webEndpoints.Count $iisFailures
}

# --- DC certificate mapping (ESC10 / ESC14) ---------------------------------
# Opt-in (-CollectDcMapping). esc14-altsecid is an LDAP read of principal
# altSecurityIdentities (raw values; the detector classifies the X.509 form).
# esc10-dc-registry reads each DC's KDC StrongCertificateBindingEnforcement and
# Schannel CertificateMappingMethods DWORD via WMI StdRegProv with explicit creds.
$dcConfigs = @()
$principalMappings = @()
$esc10Skipped = $true
$esc14Skipped = $true
if ($CollectDcMapping) {
  $domNc = $rootDse.domain

  # esc14-altsecid: every principal carrying an altSecurityIdentities value.
  try {
    $ps14 = _search $domNc '(altSecurityIdentities=*)' @('altsecurityidentities', 'objectguid')
    $psFailures = @()
    foreach ($e in $ps14.entries) {
      try {
        $p = _entryProps $e
        $null = _requireSchema $p 'principal-mappings'
        $principalMappings += [ordered]@{
          dn       = [string]@(_v $p 'distinguishedname')[0]
          object_guid = (_guidHex @(_v $p 'objectguid'))
          mappings = (@(_v $p 'altsecurityidentities' | ForEach-Object { [string]$_ }))
        }
      } catch { $psFailures += "principal: $($_.Exception.Message)" }
    }
    $esc14Skipped = $false
    _markSearch 'principal-mappings' $ps14 @($ps14.entries).Count $principalMappings.Count $psFailures
  } catch { Write-Warning "esc14-altsecid failed: $($_.Exception.Message)" }

  # esc10-dc-registry: per-DC KDC + Schannel registry. Uses explicit DC creds
  # when both -DcRegistryUserB64/-DcRegistryPassB64 are provided; otherwise
  # uses the current user's integrated credentials.
  $HKLM = [uint32]2147483650
  $dcCred = $null
  if ($DcRegistryUser) {
    $dcCred = New-Object Management.Automation.PSCredential(
      $DcRegistryUser,
      (ConvertTo-SecureString $DcRegistryPass -AsPlainText -Force))
  }
  # Discover DCs from the domain NC (server-trust accounts: UAC bit 0x2000).
  $dcs = _search $domNc '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))' @('dnshostname', 'objectguid')
  $dcFailures = @()
  foreach ($e in $dcs.entries) {
    try {
      $p = _entryProps $e
      $check = _requireSchema $p 'dc-config'
      $dcDns = [string]@(_v $p 'dnshostname')[0]
      $dcGuid = _guidHex @(_v $p 'objectguid')
      # null = the read failed (not obtained); 'unknown' / no methods = the value
      # is not configured on that DC (the OS default applies).
      $binding = $null; $schannelMethods = $null
      if ($check.soft -contains 'dnshostname') {
        # The search returned this DC but not a valid dNSHostName, so its registry
        # cannot be read. Keep the DC as an identity-bearing placeholder (GUID +
        # DN, deciding fields null) - never drop it: ESC10 cannot decide it and
        # ESC14, which depends on every DC, cannot decide anything.
        $dcDns = [string]@(_v $p 'distinguishedname')[0]
        Write-Warning "esc10-dc-registry: $dcDns has no dNSHostName; its registry was not read"
      } else {
        try {
          if ($dcDns.ToLower() -eq $localHost -or $dcDns.ToLower().StartsWith($localHost + '.')) {
            $reg = Get-WmiObject -Namespace 'root\default' -Class StdRegProv -List
          } elseif ($dcCred) {
            $reg = Get-WmiObject -ComputerName $dcDns -Credential $dcCred -Namespace 'root\default' -Class StdRegProv -List
          } else {
            $reg = Get-WmiObject -ComputerName $dcDns -Namespace 'root\default' -Class StdRegProv -List
          }
          $kdc = $reg.GetDWORDValue($HKLM, 'SYSTEM\CurrentControlSet\Services\Kdc', 'StrongCertificateBindingEnforcement')
          switch (_wmiDwordStatus $kdc) {
            'ok'     { $binding = _decodeBinding ([int]$kdc.uValue) }
            'absent' { $binding = 'unknown' }
          }
          $sch = $reg.GetDWORDValue($HKLM, 'SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL', 'CertificateMappingMethods')
          switch (_wmiDwordStatus $sch) {
            # _decode iterates entries by key/value - indexing an [ordered] dict with
            # an int key selects BY POSITION, which silently mis-decodes the bits.
            'ok'     { $schannelMethods = _decode ([int]$sch.uValue) $SCHANNEL_BITS }
            'absent' { $schannelMethods = @() }
          }
        } catch { Write-Warning "esc10-dc-registry $dcDns failed: $($_.Exception.Message)" }
      }
      $dcConfigs += [ordered]@{
        name                                   = $dcDns
        object_guid                            = $dcGuid
        strong_certificate_binding_enforcement = $binding
        schannel_mapping_methods               = (_list $schannelMethods)
      }
    } catch { $dcFailures += "DC: $($_.Exception.Message)" }
  }
  # The pass ran. If every DC's WMI read failed (e.g. double-hop SSH with LDAP
  # creds but no DC registry creds), treat it as effectively skipped so the
  # manifest surfaces the gap rather than reporting all-unread as "ran".
  $wmiFailures = @($dcConfigs | Where-Object { $null -eq $_.strong_certificate_binding_enforcement }).Count
  if ($dcConfigs.Count -gt 0 -and $wmiFailures -eq $dcConfigs.Count) {
    Write-Warning "esc10-dc-registry: all $($dcConfigs.Count) DC(s) failed the registry read -- pass effectively skipped (WMI access denied? provide -DcRegistryUserB64/-DcRegistryPassB64 for SSH/double-hop)."
    $esc10Skipped = $true
  } else {
    $esc10Skipped = $false
    _markSearch 'dc-config' $dcs @($dcs.entries).Count $dcConfigs.Count $dcFailures
  }
}

# --- manifest ----------------------------------------------------------------
$skippedPasses = @()
if ($certsSkipped) { $skippedPasses += 'certs' }              # cert/CRL DER ([certs] extra)
if (-not $anyCaSecurity) { $skippedPasses += 'ca-security' }  # CA\Security registry SD (ESC7)
if ($endpointsSkipped) { $skippedPasses += 'enrollment-endpoints' }
if ($esc10Skipped) { $skippedPasses += 'esc10-dc-registry' }
if ($esc14Skipped) { $skippedPasses += 'esc14-altsecid' }
$manifest = [ordered]@{
  collector_version = $COLLECTOR_VERSION
  collected_at      = (Get-Date).ToUniversalTime().ToString('o')
  host              = [string](hostname)
  domain            = $rootDse.domain
  skipped_passes    = (@($skippedPasses))
  enumeration       = $enumeration
}

# --- write the export (force arrays so single items don't collapse) ---------
_writeJson @($caConfig)  'ca-config.json'
_writeJson @($templates) 'templates.json'
_writeJson @($oids)      'oid-objects.json'
_writeJson @($pkiAcls)   'pki-acls.json'
_writeJson @($webEndpoints) 'web-endpoints.json'
_writeJson @($dcConfigs) 'dc-config.json'
_writeJson @($principalMappings) 'principal-mappings.json'
_writeJson $enrollmentServices 'enrollment-services.json'
_writeJson $caSecurity   'ca-security.json'
if (-not $certsSkipped) {
  _writeJson ([ordered]@{ certs = @($certIndex); crls = @($crlIndex) }) 'certs/index.json'
}
_writeJson $manifest     'collector-manifest.json'

Write-Output ("OK cas={0} templates={1} oids={2} pkiacls={3} endpoints={4} dcs={5} altsecid={6} certs={7} crls={8} editflags=[{9}] ca={10}" -f `
  $caConfig.Count, $templates.Count, $oids.Count, $pkiAcls.Count, $webEndpoints.Count, $dcConfigs.Count, $principalMappings.Count, $certIndex.Count, $crlIndex.Count, ((@($editFlags) | Where-Object { $_ }) -join ','), $caCommonName)
