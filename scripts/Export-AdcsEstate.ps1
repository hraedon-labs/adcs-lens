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
$COLLECTOR_VERSION = '0.9.0'

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
# _ldapEntry builds a DirectoryEntry with or without explicit credentials.
# When $LdapUser is set (explicit creds via -LdapUserB64), it binds with them
# (needed for key-based SSH / double-hop). When $LdapUser is empty (the
# default), it binds with the current user's integrated credentials - mirroring
# the gpo-lens collector's approach of assuming DA when running interactively.
function _ldapEntry([string]$path) {
  if ($LdapUser) {
    New-Object DirectoryServices.DirectoryEntry($path, $LdapUser, $LdapPass)
  } else {
    New-Object DirectoryServices.DirectoryEntry($path)
  }
}
function _ldapRootDse() { _ldapEntry 'LDAP://RootDSE' }

function _ldapRoot([string]$container) {
  $cfg = (_ldapRootDse).configurationNamingContext
  $path = if ($container) { "LDAP://$container,CN=Public Key Services,CN=Services,$cfg" }
          else { "LDAP://CN=Public Key Services,CN=Services,$cfg" }
  _ldapEntry $path
}
function _search([DirectoryServices.DirectoryEntry]$root, [string]$filter) {
  $s = New-Object DirectoryServices.DirectorySearcher($root)
  $s.Filter = $filter; $s.PageSize = 200; $s.SearchScope = 'Subtree'
  # Request the DACL *and* Owner so nTSecurityDescriptor comes back with ACEs
  # and the owner SID (read-only). Owner is needed for ESC4/ESC5 owner-based
  # control - without it the owner_sid is always empty (v0.6.0 bug fix).
  $s.SecurityMasks = [DirectoryServices.SecurityMasks]'Dacl,Owner'
  $s.FindAll()
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
  foreach ($line in $lines) {
    if ($line -match '=\s*([0-9a-fA-Fx]+)\s*\(') { return [Convert]::ToInt64($Matches[1].Replace('0x', ''), 16) }
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
# standalone subordinate (4) maps to 'standalone'. Unknown/unread -> 'issuing'
# (the pre-0.8.0 default, so behavior does not change when CAType is absent).
function _caKindFromType($t) {
  if ($null -eq $t) { return 'issuing' }
  switch ([int]$t) {
    0 { 'issuing'; return }
    1 { 'issuing'; return }
    3 { 'root'; return }
    4 { 'standalone'; return }
    default { 'issuing'; return }
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
# Read the nTSecurityDescriptor on a single object (Base scope) and tokenise its
# ACEs via _parseAces. Pure LDAP against the Configuration NC - no certutil, so
# this pass runs from any domain member with the explicit bind creds.
function _objAcl([string]$dn, [string]$kind) {
  $de = _ldapEntry "LDAP://$dn"
  $s = New-Object DirectoryServices.DirectorySearcher($de)
  $s.SearchScope = 'Base'; $s.Filter = '(objectClass=*)'
  $s.SecurityMasks = [DirectoryServices.SecurityMasks]'Dacl,Owner'
  $r = $null
  try { $r = $s.FindOne() } catch { return $null }   # object absent / no read
  if (-not $r) { return $null }
  $sdb = if ($r.Properties['ntsecuritydescriptor'].Count) { [byte[]]$r.Properties['ntsecuritydescriptor'][0] } else { $null }
  [ordered]@{
    object_dn = $dn; kind = $kind; owner_sid = (_readOwner $sdb)
    object_guid = (_guidHex $r.Properties['objectguid'])
    security = (_parseAces $sdb); acl_obtained = ($null -ne $sdb)
  }
}
# Enumerate child objects under a container and tokenise each one's DACL.
function _childAcls([string]$containerDn, [string]$filter, [string]$kind) {
  $out = @()
  $root = _ldapEntry "LDAP://$containerDn"
  foreach ($r in (_search $root $filter)) {
    $dn  = [string]$r.Properties['distinguishedname'][0]
    $sdb = if ($r.Properties['ntsecuritydescriptor'].Count) { [byte[]]$r.Properties['ntsecuritydescriptor'][0] } else { $null }
    $out += [ordered]@{
      object_dn = $dn; kind = $kind; owner_sid = (_readOwner $sdb)
      object_guid = (_guidHex $r.Properties['objectguid'])
      security = (_parseAces $sdb); acl_obtained = ($null -ne $sdb)
    }
  }
  ,$out
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
function _caSecurityAces([string]$caName) {
  $out = @()
  $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
    "SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$caName")
  if (-not $key) { return ,$out }
  $bytes = $key.GetValue('Security')
  if (-not $bytes) { return ,$out }
  $rsd = New-Object Security.AccessControl.RawSecurityDescriptor(@([byte[]]$bytes), 0)
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
  ,$out
}

# Pure bytes -> owner SID via the same RawSecurityDescriptor parser
# _caSecurityAces uses. Factored out so it is unit-testable without mocking the
# registry (ESC7 owner-based control, WI-037). Returns '' for absent/empty input.
function _rawSdOwner([byte[]]$bytes) {
  if (-not $bytes -or $bytes.Length -eq 0) { return '' }
  try {
    $rsd = New-Object Security.AccessControl.RawSecurityDescriptor(@([byte[]]$bytes), 0)
    if ($rsd.Owner) { return [string]$rsd.Owner.Value }
  } catch {}
  ''
}

# The CA\Security owner (ESC7 owner-based control, WI-037). A low-priv owner of
# the CA security descriptor can rewrite the DACL to grant itself Manage CA - the
# CA-level analogue of ESC4/ESC5 owner control. Returns the owner SID string, or
# '' when the SD is absent/malformed/has no owner. Reads the same registry value
# as _caSecurityAces via the same RawSecurityDescriptor parser.
function _caSecurityOwner([string]$caName) {
  $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
    "SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$caName")
  if (-not $key) { return '' }
  _rawSdOwner $key.GetValue('Security')
}

# --- CA registry via certutil (local, no network cred needed) ---------------
# Parse certutil's own decoded "FLAG_NAME -- value" lines for EditFlags/InterfaceFlags.
function _certutilFlags([string]$regpath) { _parseCertutilFlagLines (& certutil -getreg $regpath 2>$null) }
function _certutilDword([string]$regpath) { _parseCertutilDwordLines (& certutil -getreg $regpath 2>$null) }
function _certutilMultiSz([string]$regpath) { _parseCertutilMultiSzLines (& certutil -getreg $regpath 2>$null) }

# --- self-test boundary -----------------------------------------------------
# Everything above is a pure function/data definition. The Pester suite dot-sources
# this script with -FunctionsOnly and stops here; nothing below runs in that mode.
if ($PSCmdlet.ParameterSetName -eq 'SelfTest') { return }

# --- Credential resolution ---------------------------------------------------
# When both -LdapUserB64 and -LdapPassB64 are provided, decode them and use
# explicit LDAP binds (needed for key-based SSH / double-hop). When both are
# omitted (the default), leave $LdapUser/$LdapPass empty so _ldapEntry binds
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

# Enumeration completion markers (collector >= 0.9.0). Each entry is written only
# AFTER its paged LDAP search / list build finished without throwing, so a
# truncated or aborted enumeration leaves no marker. Ingest requires the markers
# and checks each count against the rows; absence-based drift resolution and
# type-enumeration records depend on them. ErrorActionPreference is Stop, so
# reaching the line after a foreach means that search completed.
$enumeration = [ordered]@{}

$caCommonName = ((& certutil -getreg CA\CommonName 2>$null) | Where-Object { $_ -match 'CommonName REG_SZ = (.+)' } | ForEach-Object { $Matches[1].Trim() } | Select-Object -First 1)
$editFlags      = _certutilFlags 'policy\EditFlags'
$interfaceFlags = _certutilFlags 'CA\InterfaceFlags'
$auditFilter    = _certutilDword 'CA\AuditFilter'
$disabledExt    = _certutilMultiSz 'policy\DisableExtensionList'
$caType         = _certutilDword 'CA\CAType'

# Registry hives are LOCAL to the collector host: the CA they describe is the
# local one. Resolve the local identity once (short + FQDN) so enrollment
# services for OTHER CAs are not mis-attributed this host's registry config.
$localHost = ([string](hostname)).ToLower()
try { $localFqdn = ([System.Net.Dns]::GetHostEntry($localHost).HostName).ToLower() } catch { $localFqdn = $localHost }

# --- enrollment services (CAs) ----------------------------------------------
$enrollRoot = _ldapRoot 'CN=Enrollment Services'
$caConfig = @()
$enrollmentServices = [ordered]@{}
foreach ($r in (_search $enrollRoot '(objectClass=pKIEnrollmentService)')) {
  $p = $r.Properties
  $cn = [string]$p['cn'][0]; $dns = [string]$p['dnshostname'][0]
  $templates = @(); foreach ($t in $p['certificatetemplates']) { $templates += [string]$t }
  $enrollmentServices[$cn] = $templates
  $caHost = ([string]$dns -split '\.')[0].ToLower()
  # The local CA: its common name matches certutil's AND its dns host is this
  # machine. Everything else is remote: its registry-derived fields stay empty
  # and registry_config_collected=false tells the core those detectors were
  # NOT evaluated for this CA (a named gap, never a silent clean).
  $isLocal = ($caCommonName -and $cn -eq $caCommonName -and
              $caHost -and ($caHost -eq $localHost -or $dns.ToLower() -eq $localFqdn))
  if ($isLocal) {
    $caConfig += [ordered]@{
      name           = $cn
      dns            = $dns
      config_string  = "$dns\$cn"
      object_guid    = (_guidHex $p['objectguid'])
      enrollment_service = $true
      kind           = (_caKindFromType $caType)
      edit_flags     = (@($editFlags))
      interface_flags= (@($interfaceFlags))
      audit_filter   = $auditFilter
      # Collector cannot yet read CA build/patch level statically (ESC15 / CVE-2024-49019).
      # Emitting 'unknown' lets the detector degrade the ESC15 finding to MEDIUM; a
      # future enhancement may populate this from the OS build.
      ca_patch_state = 'unknown'
      disabled_extensions = (@($disabledExt))
      # CA\Security owner (ESC7 owner-based control, WI-037). Empty when the local
      # registry SD could not be read; the ESC7 detector then skips owner control.
      owner_sid      = (_caSecurityOwner $cn)
      registry_config_collected = $true
    }
  } else {
    $caConfig += [ordered]@{
      name           = $cn
      dns            = $dns
      config_string  = "$dns\$cn"
      object_guid    = (_guidHex $p['objectguid'])
      enrollment_service = $true
      kind           = 'issuing'   # enterprise by definition (it is in Enrollment Services)
      edit_flags     = (@())
      interface_flags= (@())
      audit_filter   = $null
      ca_patch_state = 'unknown'
      disabled_extensions = (@())
      owner_sid      = ''
      registry_config_collected = $false
    }
  }
}

# A CA not published as an enrollment service (a standalone CA is never in
# Enrollment Services) is invisible to the LDAP pass above. If the LOCAL host
# is such a CA, add it so its registry config is still evaluated.
if ($caCommonName -and -not ($caConfig | Where-Object { $_.name -eq $caCommonName })) {
  $caConfig += [ordered]@{
    name           = $caCommonName
    dns            = $localFqdn
    config_string  = "$localFqdn\$caCommonName"
    # A standalone CA has no Enrollment Services object, so no objectGUID.
    object_guid    = ''
    enrollment_service = $false
    kind           = (_caKindFromType $caType)
    edit_flags     = (@($editFlags))
    interface_flags= (@($interfaceFlags))
    audit_filter   = $auditFilter
    ca_patch_state = 'unknown'
    disabled_extensions = (@($disabledExt))
    owner_sid      = (_caSecurityOwner $caCommonName)
    registry_config_collected = $true
  }
}
$enumeration['ca-config'] = [ordered]@{ complete = $true; count = $caConfig.Count }
$enumeration['enrollment-services'] = [ordered]@{ complete = $true; count = $enrollmentServices.Count }

# --- certificate templates --------------------------------------------------
$tmplRoot = _ldapRoot 'CN=Certificate Templates'
$templates = @()
foreach ($r in (_search $tmplRoot '(objectClass=pKICertificateTemplate)')) {
  $p = $r.Properties
  $nf = if ($p['mspki-certificate-name-flag'].Count) { [int]$p['mspki-certificate-name-flag'][0] } else { 0 }
  $ef = if ($p['mspki-enrollment-flag'].Count) { [int]$p['mspki-enrollment-flag'][0] } else { 0 }
  $ekus = @(); foreach ($e in $p['pkiextendedkeyusage']) { $ekus += [string]$e }
  $pol  = @(); foreach ($o in $p['mspki-certificate-policy']) { $pol += [string]$o }
  $csps = @(); foreach ($c in $p['pKICSP']) { $csps += [string]$c }
  $sdb  = if ($p['ntsecuritydescriptor'].Count) { [byte[]]$p['ntsecuritydescriptor'][0] } else { $null }
  $templates += [ordered]@{
    name              = [string]$p['cn'][0]
    object_guid       = (_guidHex $p['objectguid'])
    display_name      = [string]$p['displayname'][0]
    schema_version    = if ($p['mspki-template-schema-version'].Count) { [int]$p['mspki-template-schema-version'][0] } else { 1 }
    oid               = [string]$p['mspki-cert-template-oid'][0]
    ekus              = (@($ekus))
    name_flags        = (_decode $nf $NAME_FLAGS)
    enrollment_flags  = (_decode $ef $ENROLL_FLAGS)
    min_key_size      = if ($p['mspki-minimal-key-size'].Count) { [int]$p['mspki-minimal-key-size'][0] } else { $null }
    issuance_policy_oids = (@($pol))
    csp               = (($csps -join ', ').ToLower())
    security          = (_parseAces $sdb)   # template DACL -> ACEs (ESC1/ESC4)
    acl_obtained      = ($null -ne $sdb)    # SD requested & obtained (per-template gap signal)
    owner_sid         = (_readOwner $sdb)
  }
}
$enumeration['templates'] = [ordered]@{ complete = $true; count = $templates.Count }

# --- enterprise OID objects (issuance policies) -----------------------------
$oidRoot = _ldapRoot 'CN=OID'
$oids = @()
foreach ($r in (_search $oidRoot '(objectClass=msPKI-Enterprise-Oid)')) {
  $p = $r.Properties
  # The OID->group link (ESC13) is msDS-OIDToGroupLink (a group DN), NOT
  # msPKI-OIDToGroupLink - the latter does not exist, so the old name always
  # read $null and ESC13 could never fire on real data.
  $gl = if ($p['msds-oidtogrouplink'].Count) { [string]$p['msds-oidtogrouplink'][0] } else { $null }
  $oids += [ordered]@{
    oid        = [string]$p['mspki-cert-template-oid'][0]
    object_guid = (_guidHex $p['objectguid'])
    name       = [string]$p['displayname'][0]
    group_link = $gl
  }
}
$enumeration['oid-objects'] = [ordered]@{ complete = $true; count = $oids.Count }

# --- PKI object ACLs (ESC5) --------------------------------------------------
# Capture DACLs on the Public Key Services containers + CA objects. A low-priv
# trustee with object-control rights (WriteDacl/WriteOwner/GenericWrite/
# GenericAll) on any of these is the ESC5 escalation primitive.
$cfgNc = (_ldapRootDse).configurationNamingContext
$pksDn = "CN=Public Key Services,CN=Services,$cfgNc"
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
    # The object is one of the well-known fixed containers but could not be
    # read at all (LDAP denial). Emit a gap marker (acl_obtained=$false) so
    # ESC5 does not silently clear it - the PKI-object analogue of the
    # template-level gap signal.
    $pkiAcls += [ordered]@{
      object_dn = $pair[0]; kind = $pair[1]; owner_sid = ''
      object_guid = ''   # the object could not be read at all
      security = @(); acl_obtained = $false
    }
  }
}
# Individual CA objects: trusted roots + issuing enrollment services.
$pkiAcls += _childAcls "CN=Certification Authorities,$pksDn" '(objectClass=certificationAuthority)' 'ca_object'
$pkiAcls += _childAcls "CN=Enrollment Services,$pksDn"       '(objectClass=pKIEnrollmentService)'   'ca_object'
$enumeration['pki-acls'] = [ordered]@{ complete = $true; count = $pkiAcls.Count }

# --- CA role security (ESC7) -------------------------------------------------
# Keyed by the CA name used in ca-config.json so ingest joins them to the CA.
# The descriptor lives in the CA host's LOCAL registry, so only CAs whose
# registry config was collected can yield ACEs. When NO CA yields any (e.g.
# the collector ran on a tier-0 box that is not a CA), the pass effectively
# did not run: mark it skipped so the core emits its CA_SECURITY_NOT_EVALUATED
# note instead of a silent "no ESC7 findings".
$caSecurity = [ordered]@{}
$anyCaSecurity = $false
foreach ($ca in $caConfig) {
  $aces = if ($ca.registry_config_collected) { ,(_caSecurityAces $ca.name) } else { ,@() }
  # _caSecurityAces returns a wrapped array; normalise before counting/storing.
  $flat = @($aces | ForEach-Object { $_ })
  $caSecurity[$ca.name] = $flat
  if ($flat.Count -gt 0) { $anyCaSecurity = $true }
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
$caKindByName = @{}
try {
  $certDir = Join-Path $OutDir 'certs'
  $i = 0
  foreach ($r in (_search (_ldapRoot 'CN=AIA') '(objectClass=certificationAuthority)')) {
    $p = $r.Properties
    $cn = [string]$p['cn'][0]
    foreach ($blob in $p['cacertificate']) {
      $der = [byte[]]$blob
      $kind = _certKindFromDer $der
      if (-not $caKindByName.ContainsKey($cn)) { $caKindByName[$cn] = $kind }
      New-Item -ItemType Directory -Force -Path $certDir | Out-Null
      $file = '{0:d2}-{1}.cer' -f $i, (_safeFileName $cn); $i++
      [IO.File]::WriteAllBytes((Join-Path $certDir $file), $der)
      # ca_name joins to ca-config.json by CA common name at ingest. For an
      # enterprise CA the AIA child's CN IS the CA common name; a mismatch
      # would leave the cert unattached (a coverage gap, not a false finding).
      $certIndex += [ordered]@{ file = $file; ca_name = $cn; kind = $kind }
    }
  }
  $j = 0
  foreach ($r in (_search (_ldapRoot 'CN=CDP') '(objectClass=cRLDistributionPoint)')) {
    $p = $r.Properties
    $cn = [string]$p['cn'][0]
    if (-not $p['certificaterevocationlist'].Count) { continue }
    $der = [byte[]]$p['certificaterevocationlist'][0]
    New-Item -ItemType Directory -Force -Path $certDir | Out-Null
    $file = '{0:d2}-{1}.crl' -f $j, (_safeFileName $cn); $j++
    [IO.File]::WriteAllBytes((Join-Path $certDir $file), $der)
    # Tier by the issuing CA's self-signedness when known; default issuing.
    $tier = if ($caKindByName.ContainsKey($cn) -and $caKindByName[$cn] -eq 'root_ca') { 'root' } else { 'issuing' }
    $crlIndex += [ordered]@{
      object_guid = (_guidHex $p['objectguid'])   # the CDP object
      file   = $file
      tier   = $tier
      source = "AD CDP container: $([string]$p['distinguishedname'][0])"
    }
  }
  if ($certIndex.Count -gt 0 -or $crlIndex.Count -gt 0) { $certsSkipped = $false }
  # Both the AIA cert loop and the CDP CRL loop completed without throwing.
  $enumeration['certs'] = [ordered]@{ complete = $true; count = $certIndex.Count }
  $enumeration['crls'] = [ordered]@{ complete = $true; count = $crlIndex.Count }
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
  foreach ($site in (Get-Website)) {
    $protos = @(); foreach ($b in $site.bindings.Collection) { if ($protos -notcontains [string]$b.protocol) { $protos += [string]$b.protocol } }
    foreach ($app in (Get-WebApplication -Site $site.Name)) {
      $kind = _classifyApp ([string]$app.path)
      if (-not $kind) { continue }
      $ps = "IIS:\Sites\$($site.Name)\" + ([string]$app.path).TrimStart('/')
      # Each read is checked for success: a SilentlyContinue failure returns
      # $null, so inputs_obtained is false and ESC8 will not record this
      # endpoint as evaluated (a failed read must not read as a benign default).
      $waRaw = (Get-WebConfigurationProperty -PSPath $ps -Filter 'system.webServer/security/authentication/windowsAuthentication' -Name enabled -ErrorAction SilentlyContinue)
      $tcRaw = (Get-WebConfigurationProperty -PSPath $ps -Filter 'system.webServer/security/authentication/windowsAuthentication' -Name 'extendedProtection.tokenChecking' -ErrorAction SilentlyContinue)
      $sslRaw = (Get-WebConfigurationProperty -PSPath $ps -Filter 'system.webServer/security/access' -Name sslFlags -ErrorAction SilentlyContinue)
      $provsRaw = (Get-WebConfigurationProperty -PSPath $ps -Filter 'system.webServer/security/authentication/windowsAuthentication/providers' -Name Collection -ErrorAction SilentlyContinue)
      $wa = $waRaw.Value
      $tc = $tcRaw.Value
      $ssl = [string]$sslRaw.Value
      $provs = @()
      foreach ($p in $provsRaw) { if ($p.value) { $provs += ([string]$p.value).ToLower() } }
      $obtained = ($null -ne $waRaw -and $null -ne $sslRaw -and $null -ne $provsRaw)
      $webEndpoints += [ordered]@{
        kind           = $kind
        name           = [string]$app.path
        transports     = (@($protos))
        ssl_required   = ($ssl -match 'Ssl')
        windows_auth   = [bool]$wa
        auth_providers = (@($provs))
        epa            = (_epaToken $tc)
        inputs_obtained = $obtained
      }
    }
  }
  $enumeration['web-endpoints'] = [ordered]@{ complete = $true; count = $webEndpoints.Count }
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
  $domNc = (_ldapRootDse).defaultNamingContext

  # esc14-altsecid: every principal carrying an altSecurityIdentities value.
  try {
    $domRoot = _ldapEntry "LDAP://$domNc"
    $s = New-Object DirectoryServices.DirectorySearcher($domRoot)
    $s.Filter = '(altSecurityIdentities=*)'; $s.PageSize = 200; $s.SearchScope = 'Subtree'
    [void]$s.PropertiesToLoad.Add('distinguishedName')
    [void]$s.PropertiesToLoad.Add('altSecurityIdentities')
    [void]$s.PropertiesToLoad.Add('objectGUID')
    foreach ($r in $s.FindAll()) {
      $maps = @(); foreach ($m in $r.Properties['altsecurityidentities']) { $maps += [string]$m }
      $principalMappings += [ordered]@{
        dn       = [string]$r.Properties['distinguishedname'][0]
        object_guid = (_guidHex $r.Properties['objectguid'])
        mappings = (@($maps))
      }
    }
    $esc14Skipped = $false
    $enumeration['principal-mappings'] = [ordered]@{ complete = $true; count = $principalMappings.Count }
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
  $localHost = ([string](hostname)).ToLower()
  # Discover DCs from the domain NC (server-trust accounts: UAC bit 0x2000).
  $dcRoot = _ldapEntry "LDAP://$domNc"
  $ds = New-Object DirectoryServices.DirectorySearcher($dcRoot)
  $ds.Filter = '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))'
  $ds.PageSize = 200; $ds.SearchScope = 'Subtree'; [void]$ds.PropertiesToLoad.Add('dnshostname')
  [void]$ds.PropertiesToLoad.Add('objectGUID')
  foreach ($r in $ds.FindAll()) {
    $dcDns = [string]$r.Properties['dnshostname'][0]
    $dcGuid = _guidHex $r.Properties['objectguid']
    if (-not $dcDns) { continue }
    $binding = 'unknown'; $schannelMethods = @()
    try {
      if ($dcDns.ToLower() -eq $localHost -or $dcDns.ToLower().StartsWith($localHost + '.')) {
        $reg = Get-WmiObject -Namespace 'root\default' -Class StdRegProv -List
      } elseif ($dcCred) {
        $reg = Get-WmiObject -ComputerName $dcDns -Credential $dcCred -Namespace 'root\default' -Class StdRegProv -List
      } else {
        $reg = Get-WmiObject -ComputerName $dcDns -Namespace 'root\default' -Class StdRegProv -List
      }
      $kdc = $reg.GetDWORDValue($HKLM, 'SYSTEM\CurrentControlSet\Services\Kdc', 'StrongCertificateBindingEnforcement')
      if ($kdc.ReturnValue -eq 0 -and $null -ne $kdc.uValue) {
        $binding = _decodeBinding ([int]$kdc.uValue)
      }
      $sch = $reg.GetDWORDValue($HKLM, 'SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL', 'CertificateMappingMethods')
      if ($sch.ReturnValue -eq 0 -and $null -ne $sch.uValue) {
        # _decode iterates entries by key/value - indexing an [ordered] dict with
        # an int key selects BY POSITION, which silently mis-decodes the bits.
        $schannelMethods = _decode ([int]$sch.uValue) $SCHANNEL_BITS
      }
    } catch { Write-Warning "esc10-dc-registry $dcDns failed: $($_.Exception.Message)" }
    $dcConfigs += [ordered]@{
      name                                   = $dcDns
      object_guid                            = $dcGuid
      strong_certificate_binding_enforcement = $binding
      schannel_mapping_methods               = (@($schannelMethods))
    }
  }
  # The pass ran. If every DC's WMI lookup failed (e.g. double-hop SSH with
  # LDAP creds but no DC registry creds), treat it as effectively skipped so
  # the manifest surfaces the gap rather than reporting all-unknown as "ran".
  $wmiFailures = ($dcConfigs | Where-Object { $_.strong_certificate_binding_enforcement -eq 'unknown' }).Count
  if ($dcConfigs.Count -gt 0 -and $wmiFailures -eq $dcConfigs.Count) {
    Write-Warning "esc10-dc-registry: all $($dcConfigs.Count) DC(s) returned unknown -- pass effectively skipped (WMI access denied? provide -DcRegistryUserB64/-DcRegistryPassB64 for SSH/double-hop)."
    $esc10Skipped = $true
  } else {
    $esc10Skipped = $false
    $enumeration['dc-config'] = [ordered]@{ complete = $true; count = $dcConfigs.Count }
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
  domain            = (_ldapRootDse).defaultNamingContext
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
  $caConfig.Count, $templates.Count, $oids.Count, $pkiAcls.Count, $webEndpoints.Count, $dcConfigs.Count, $principalMappings.Count, $certIndex.Count, $crlIndex.Count, ($editFlags -join ','), $caCommonName)
