<#
  Run the REAL collector body (scripts/Export-AdcsEstate.ps1) against mocked
  native transports, on any pwsh, and write a real export directory.

  Only the transports are replaced: _search (LDAP), _certutilRead (certutil
  -getreg), _caSecurityRead (the CA\Security hive), _sdRead (security
  descriptors, Windows-only parser), hostname, the IIS cmdlets and WMI, and
  the JSON serializer (System.Web.Extensions is Windows-only). Every decision
  the collector makes - what is a proven read, what is null, which enumeration
  marker is complete - runs unmodified, so tests/test_collector_simulated.py can
  ingest the result with adcs-lens and check the 0.10.0 contract end to end.

  -Scenario clean     every read succeeds
  -Scenario failures  certutil EditFlags fails, CAType, AuditFilter and
                      DisableExtensionList are not configured, the template
                      search loses a page,
                      one template's descriptor is unreadable, the CA\Security
                      read fails, one IIS property read throws, and one DC's
                      WMI read is denied
  -Scenario missing-dc-dns
                      Sol round 5: the DC search returns LAB-DC02 (the only
                      non-strict DC) without dNSHostName
  -Scenario bad-entries
                      every enumeration loop meets one object it cannot
                      serialize (an unparseable objectGUID / certificate blob /
                      IIS application); each container must then be marked
                      incomplete, never silently short

  -Omit container:attribute:mode
                      round 7: on the FIRST object the container's search
                      returns, make one attribute of $OBJECT_SCHEMA missing,
                      empty, or of the wrong type (mode = missing | empty |
                      wrongtype); tests/test_object_schema.py runs it for every
                      container x attribute
  -DerDir dir         AIA and CDP each return one object carrying root.cer /
                      root.crl from dir (real DER, so certs/crls have objects);
                      AIA also returns 'LAB Issuing CA' with issuing.cer when
                      the file exists
  -BrokenBindings     the IIS site's bindings read returns nothing (the
                      endpoints' transports are then not obtained)
  -Ambiguous join[:variant]
                      make one join of $JOINS ambiguous.
                      variant twin (round 8, the default): a second object
                      answering the same key - publication (a template
                      'labwebserver'), crl-tier (an AIA object 'lab root ca'
                      carrying a cross-certificate), oid-link (a second OID
                      object with the same OID), cert-ca (an enrollment
                      service 'lab issuing ca 2').
                      variant case | space | unicode (round 9): the REFERENCE
                      is not identical to its key but folds to it (lower case,
                      surrounding spaces, a fullwidth character) -
                      publication (CA 1 publishes 'LabWebServer' so), crl-tier
                      (the root's AIA cn), cert-ca (the issuing CA's AIA cn),
                      oid-link (a second OID object with the linked OID so),
                      local-ca (the local enrollment service's cn)
  -NotACa             CA\CommonName is not configured: this host is not a CA
                      (Sol round 6: the local CA is then never the fallback row)
  -HostName name      the collector host (default labca01, the first CA's host;
                      labweb01 is an IIS host that is no CA host: WI-044)
  -OneCa              Enrollment Services hold only LAB Issuing CA (on labca01),
                      so the collector host can be the only CA host
  -NoEnrollmentApps   IIS runs but serves no Web Enrollment / CES / NDES
                      application (only /owa): with -HostName labweb01, the
                      WI-044 live case (a non-CA IIS host, nothing found)
  -HostLookupFails    the search for each CA host's computer account fails
                      (WI-044: ca_host_sid is then not obtained)
  -Ambiguous ca-host:twin|case
                      the CA host's computer account search returns two objects
                      with that dNSHostName (twin), or only one whose
                      dNSHostName differs in case (case)

  certutil output follows the format of real certutil -getreg output (the
  registry path line, a blank line, the value, the 'CertUtil:' trailer); the
  REG_MULTI_SZ value is printed as indexed lines, '    0: <value>'.

  Every returned entry carries distinguishedname, as the real _entryProps
  always adds it.
#>
param(
  [Parameter(Mandatory)] [string] $OutDir,
  [ValidateSet('clean', 'failures', 'missing-dc-dns', 'bad-entries')] [string] $Scenario = 'clean',
  [string] $Omit = '',
  [string] $DerDir = '',
  [switch] $NotACa,
  [switch] $BrokenBindings,
  [string] $Ambiguous = '',
  [string] $HostName = 'labca01',
  [switch] $OneCa,
  [switch] $HostLookupFails,
  [switch] $NoEnrollmentApps
)
$ErrorActionPreference = 'Stop'
$collector = Join-Path $PSScriptRoot '../../scripts/Export-AdcsEstate.ps1'
$source = [IO.File]::ReadAllText($collector)
$boundary = "if (`$PSCmdlet.ParameterSetName -eq 'SelfTest') { return }"
$start = $source.IndexOf("`$ErrorActionPreference = 'Stop'")
$cut = $source.IndexOf($boundary)
if ($start -lt 0 -or $cut -lt 0) { throw 'collector layout changed: cannot find the self-test boundary' }
$definitions = $source.Substring($start, $cut - $start)
$body = $source.Substring($cut + $boundary.Length)

$mocks = @'
function hostname { $HostName }
$script:OneCa = [bool]$OneCa
$script:HostLookupFails = [bool]$HostLookupFails
$script:NoEnrollmentApps = [bool]$NoEnrollmentApps
$script:Fail = ($Scenario -eq 'failures')
$script:MissingDcDns = ($Scenario -eq 'missing-dc-dns')
$script:Bad = ($Scenario -eq 'bad-entries')
$script:NotACa = [bool]$NotACa
$script:BrokenBindings = [bool]$BrokenBindings
$script:Ambiguous, $script:Variant = ($Ambiguous + ':twin') -split ':' | Select-Object -First 2
if ($script:Ambiguous -notin @('', 'publication', 'crl-tier', 'oid-link', 'cert-ca', 'local-ca', 'ca-host') -or
    $script:Variant -notin @('twin', 'case', 'space', 'unicode')) { throw "bad -Ambiguous $Ambiguous" }
# The reference variant: equal to $v under trimming / case / NFKC, not identical.
function _variant([string]$v) {
  switch ($script:Variant) {
    'case' { return $v.ToLowerInvariant() }
    'space' { return " $v " }
    'unicode' {
      # The first letter (or digit) as its fullwidth form (NFKC folds it back).
      $i = 0; while ($i -lt $v.Length -and -not [char]::IsLetterOrDigit($v[$i])) { $i++ }
      $wide = [char]([int][char]$v[$i] + 0xFEE0)
      return $v.Substring(0, $i) + $wide + $v.Substring($i + 1)
    }
  }
  throw "no variant for $($script:Variant)"
}
$script:OmitSpec = $null
if ($Omit) {
  $c, $a, $m = $Omit -split ':'
  if (-not $OBJECT_SCHEMA.$c -or -not $OBJECT_SCHEMA.$c.$a -or $m -notin @('missing', 'empty', 'wrongtype')) { throw "bad -Omit $Omit" }
  $script:OmitSpec = @{ container = $c; attr = $a; mode = $m }
}
$script:Der = $null
if ($DerDir) {
  $script:Der = @{ cer = [IO.File]::ReadAllBytes((Join-Path $DerDir 'root.cer')); crl = [IO.File]::ReadAllBytes((Join-Path $DerDir 'root.crl')); issuing = $null }
  # Optional: the issuing CA's certificate, published in AIA under its cn.
  if (Test-Path (Join-Path $DerDir 'issuing.cer')) { $script:Der.issuing = [IO.File]::ReadAllBytes((Join-Path $DerDir 'issuing.cer')) }
  $script:Der.cross = $null
  if (Test-Path (Join-Path $DerDir 'cross.cer')) { $script:Der.cross = [IO.File]::ReadAllBytes((Join-Path $DerDir 'cross.cer')) }
}
# The real _guidHex, except that the marker GUID 0xEE.. cannot be rendered:
# the seam that makes one object per loop fail to serialize.
function _guidHex($values) {
  if (-not $values -or $values.Count -lt 1) { return '' }
  $b = [byte[]]$values[0]
  if ($b.Count -ne 16) { return '' }
  if ($b[0] -eq 0xEE) { throw 'unrenderable objectGUID' }
  (($b | ForEach-Object { $_.ToString('x2') }) -join '')
}
function _bad([hashtable]$p) { if ($script:Bad) { $p['objectguid'] = @(_g 0xEE); $p } }
# certutil -getreg output in its real layout (WI-044): the registry path line,
# a blank line, the value, the trailer.
function _ok($name, $lines) {
  @{ lines = @("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\LAB Issuing CA\$($name):", '') + @($lines) + @('CertUtil: -getreg command completed successfully.'); code = 0 }
}
function _absent($name) {
  @{ lines = @("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\LAB Issuing CA\$($name):", 'CertUtil: -getreg command FAILED: 0x80070002 (WIN32: 2 ERROR_FILE_NOT_FOUND)', 'CertUtil: The system cannot find the file specified.'); code = -2147024894 }
}
function _certutilRead([string]$regpath) {
  switch ($regpath) {
    'CA\CommonName' {
      if ($script:NotACa) { return @{ lines = @('CertUtil: -getreg command FAILED: 0x80070002 (WIN32: 2 ERROR_FILE_NOT_FOUND)'); code = 2 } }
      return _ok 'CommonName' '  CommonName REG_SZ = LAB Issuing CA'
    }
    'policy\EditFlags' {
      if ($script:Fail) { return @{ lines = @('CertUtil: -getreg command FAILED: 0x80070005 (WIN32: 5 ERROR_ACCESS_DENIED)'); code = 5 } }
      return _ok 'EditFlags' @('  EditFlags REG_DWORD = 15014e (1376590)', '    EDITF_ATTRIBUTESUBJECTALTNAME2 -- 40000 (262144)')
    }
    'CA\InterfaceFlags' { return _ok 'InterfaceFlags' @('  InterfaceFlags REG_DWORD = 641 (1601)', '    IF_ENFORCEENCRYPTICERTREQUEST -- 200 (512)') }
    'CA\AuditFilter' {
      # Not configured (the CA default): auditing off, read as 0 (WI-044).
      if ($script:Fail) { return _absent 'AuditFilter' }
      return _ok 'AuditFilter' '  AuditFilter REG_DWORD = 0'
    }
    'policy\DisableExtensionList' {
      if ($script:Fail) { return _absent 'DisableExtensionList' }
      # Indexed values; certutil prints a known OID's friendly name after it.
      return _ok 'DisableExtensionList' @('  DisableExtensionList REG_MULTI_SZ =', '    0: 1.3.6.1.4.1.311.25.2', '    1: 2.5.29.15 Key Usage')
    }
    'CA\CAType' {
      if ($script:Fail) { return @{ lines = @('FAILED: 0x80070002'); code = 2 } }
      return _ok 'CAType' @('  CAType REG_DWORD = 1', '    ENUM_ENTERPRISE_SUBCA -- 1')
    }
  }
  throw "unexpected certutil read $regpath"
}
function _caSecurityRead([string]$caName) {
  if ($script:Fail) { return @{ aces = $null; owner = $null } }
  @{ aces = @([ordered]@{ trustee_sid = 'S-1-5-21-1111111111-2222222222-3333333333-513'; trustee_name = ''; rights = @('ManageCertificates'); ace_type = 'Allow' }); owner = 'S-1-5-32-544' }
}
# Fake security descriptor bytes carry the trustee in the first bytes; the
# Windows-only parser is replaced, the null handling is the collector's.
# An enrollment-service object's descriptor (first byte 0xC0 + n) also grants
# control to its CA host's computer account (RID 1104 + n), as AD CS setup does.
function _sdRead($sdBytes) {
  if (-not $sdBytes) { return @{ aces = $null; owner = $null } }
  $aces = @([ordered]@{ trustee_sid = 'S-1-5-21-1111111111-2222222222-3333333333-513'; trustee_name = 'Domain Users'; rights = @('Enroll'); ace_type = 'Allow' })
  $b = [byte[]]$sdBytes
  if ($b[0] -gt 0xC0) {
    $aces += [ordered]@{ trustee_sid = "S-1-5-21-1111111111-2222222222-3333333333-$(1104 + $b[0] - 0xC0)"; trustee_name = ''; rights = @('WriteDacl', 'WriteOwner', 'WritePropertyAll'); ace_type = 'Allow' }
  }
  @{ aces = $aces; owner = 'S-1-5-21-1111111111-2222222222-3333333333-512' }
}
# A binary objectSid S-1-5-21-1111111111-2222222222-3333333333-<rid>.
function _sidBytes([int]$rid) {
  $b = [byte[]](1, 5, 0, 0, 0, 0, 0, 5)
  foreach ($n in @(21, 1111111111, 2222222222, 3333333333, $rid)) { $b += [BitConverter]::GetBytes([uint32]$n) }
  ,[byte[]]$b
}
function _entryProps($entry) { $entry }
function _g([int]$n) { ,([byte[]](@($n) * 16)) }
function _ent([hashtable]$p) { $p }
function _done($entries) { @{ entries = @($entries); complete = $true; reason = '' } }
function _plus($entries, [hashtable]$bad) { _done (@($entries) + @(_bad $bad)) }
function _searchRaw([string]$baseDn, [string]$filter, [string[]]$attrs, [string]$Scope = 'Subtree', [switch]$Sd) {
  $pks = 'CN=Public Key Services,CN=Services,CN=Configuration,DC=lab,DC=example,DC=com'
  if ($baseDn -eq '' -and $Scope -eq 'Base') {
    return _done (_ent @{ configurationnamingcontext = @('CN=Configuration,DC=lab,DC=example,DC=com'); defaultnamingcontext = @('DC=lab,DC=example,DC=com') })
  }
  if ($Scope -eq 'Base') {
    if ($baseDn -like 'CN=CDP,*') { return @{ entries = @(); complete = $false; reason = 'read failed: insufficient access' } }
    return _done (_ent @{ distinguishedname = @($baseDn); objectguid = @(_g ($baseDn.Length)); ntsecuritydescriptor = @(,[byte[]](1, 2, 3)) })
  }
  if ($filter -eq '(objectClass=pKIEnrollmentService)' -and $baseDn -eq "CN=Enrollment Services,$pks") {
    $esRows = @(
      (_ent @{ cn = @('LAB Issuing CA'); dnshostname = @('labca01.lab.example.com'); certificatetemplates = @('LabWebServer', 'LabUser'); objectguid = @(_g 1); distinguishedname = @("CN=LAB Issuing CA,$baseDn"); ntsecuritydescriptor = @(,[byte[]](0xC1)) }),
      (_ent @{ cn = @('LAB Issuing CA 2'); dnshostname = @('labca02.lab.example.com'); certificatetemplates = @('LabUser'); objectguid = @(_g 2); distinguishedname = @("CN=LAB Issuing CA 2,$baseDn"); ntsecuritydescriptor = @(,[byte[]](0xC2)) })
    )
    if ($script:OneCa) { $esRows = @($esRows[0]) }
    return _plus $esRows @{ cn = @('LAB Bad CA'); dnshostname = @('labbad.lab.example.com'); distinguishedname = @("CN=LAB Bad CA,$baseDn") }
  }
  if ($filter -eq '(objectClass=pKICertificateTemplate)') {
    $rows = @(
      (_ent @{ cn = @('LabWebServer'); displayname = @('Lab Web Server'); objectguid = @(_g 3); 'mspki-certificate-name-flag' = @('1'); 'mspki-enrollment-flag' = @('0'); pkiextendedkeyusage = @('1.3.6.1.5.5.7.3.2'); 'mspki-template-schema-version' = @('2'); 'mspki-cert-template-oid' = @('1.3.6.1.4.1.311.21.8.1.1'); 'mspki-minimal-key-size' = @('2048'); ntsecuritydescriptor = @(,[byte[]](1)) }),
      (_ent @{ cn = @('LabUser'); displayname = @('Lab User'); objectguid = @(_g 4); pkiextendedkeyusage = @('1.3.6.1.5.5.7.3.2', '1.3.6.1.4.1.311.10.3.4'); 'mspki-cert-template-oid' = @('1.3.6.1.4.1.311.21.8.1.2'); 'mspki-certificate-policy' = @('1.3.6.1.4.1.311.21.8.1.9'); ntsecuritydescriptor = @(if ($script:Fail) { } else { ,[byte[]](1) }) })
    )
    if ($script:Fail) { return @{ entries = $rows; complete = $false; reason = 'page 1 failed: The size limit for this request was exceeded' } }
    return _plus $rows @{ cn = @('LabBad'); 'mspki-cert-template-oid' = @('1.3.6.1.4.1.311.21.8.1.66') }
  }
  if ($filter -eq '(objectClass=msPKI-Enterprise-Oid)') {
    return _plus (_ent @{ 'mspki-cert-template-oid' = @('1.3.6.1.4.1.311.21.8.1.9'); objectguid = @(_g 5); displayname = @('Lab Policy'); 'msds-oidtogrouplink' = @('CN=Lab Admins,DC=lab,DC=example,DC=com') }) @{ 'mspki-cert-template-oid' = @('1.3.6.1.4.1.311.21.8.1.66') }
  }
  if ($filter -eq '(objectClass=certificationAuthority)' -and $baseDn -like 'CN=Certification Authorities,*') {
    return _plus (_ent @{ distinguishedname = @("CN=LAB Root CA,$baseDn"); objectguid = @(_g 6); ntsecuritydescriptor = @(,[byte[]](1)) }) @{ distinguishedname = @("CN=LAB Bad Root,$baseDn") }
  }
  if ($filter -eq '(objectClass=certificationAuthority)' -and $baseDn -like 'CN=AIA,*') {
    if ($script:Der) {
      $objs = @(_ent @{ cn = @('LAB Root CA'); cacertificate = @(,$script:Der.cer) })
      if ($script:Der.issuing) { $objs += ,(_ent @{ cn = @('LAB Issuing CA'); cacertificate = @(,$script:Der.issuing) }) }
      return _done $objs
    }
    if ($script:Bad) { return _done (_ent @{ cn = @('LAB Bad Root'); cacertificate = @('not a certificate') }) }
    return _done @()
  }
  if ($filter -eq '(objectClass=cRLDistributionPoint)') {
    if ($script:Der) { return _done (_ent @{ cn = @('LAB Root CA'); objectguid = @(_g 10); certificaterevocationlist = @(,$script:Der.crl) }) }
    return _plus @() @{ cn = @('LAB Bad CRL'); certificaterevocationlist = @(,[byte[]](1, 2)) }
  }
  if ($filter -eq '(altSecurityIdentities=*)') {
    return _plus (_ent @{ distinguishedname = @('CN=Svc,DC=lab,DC=example,DC=com'); objectguid = @(_g 7); altsecurityidentities = @('X509:<I>CN=CA<S>CN=Svc') }) @{ distinguishedname = @('CN=Bad,DC=lab,DC=example,DC=com'); altsecurityidentities = @('X509:<S>CN=Bad') }
  }
  if ($filter -like '(&(objectCategory=computer)(dNSHostName=*') {
    # The CA host's computer account (WI-044): labcaNN is RID 1104 + NN.
    if ($script:HostLookupFails) { return @{ entries = @(); complete = $false; reason = 'page 0 failed: The server is not operational' } }
    $dns = $filter -replace '^.*\(dNSHostName=(.*)\)\)$', '$1'
    if ($dns -notmatch '^labca0(\d)\.') { return _done @() }
    $found = @(_ent @{ dnshostname = @($dns); objectsid = @(,(_sidBytes (1104 + [int]$Matches[1]))); distinguishedname = @("CN=$(($dns -split '\.')[0]),CN=Computers,DC=lab,DC=example,DC=com") })
    if ($script:Ambiguous -eq 'ca-host' -and $script:Variant -eq 'twin') {
      $found += ,(_ent @{ dnshostname = @($dns); objectsid = @(,(_sidBytes 1199)); distinguishedname = @('CN=twin,CN=Computers,DC=lab,DC=example,DC=com') })
    }
    if ($script:Ambiguous -eq 'ca-host' -and $script:Variant -eq 'case') { $found[0].dnshostname = @($dns.ToUpperInvariant()) }
    return _done $found
  }
  if ($filter -like '(&(objectCategory=computer)*') {
    if ($script:MissingDcDns) {
      return _done @(
        (_ent @{ dnshostname = @('LAB-DC01.lab.example.com'); objectguid = @(_g 8) }),
        (_ent @{ objectguid = @(_g 9) })
      )
    }
    return _plus @(
      (_ent @{ dnshostname = @('LAB-DC01.lab.example.com'); objectguid = @(_g 8) }),
      (_ent @{ dnshostname = @('LAB-DC02.lab.example.com'); objectguid = @(_g 9) })
    ) @{ dnshostname = @('LAB-DCBAD.lab.example.com') }
  }
  throw "unexpected search $baseDn $filter"
}
# The container a search fills (the targets of -Omit); '' for the fixed-object
# Base reads and the rootDSE.
function _containerOf([string]$baseDn, [string]$filter, [string[]]$attrs, [string]$Scope) {
  if ($Scope -eq 'Base') { return '' }
  if ($filter -eq '(objectClass=pKIEnrollmentService)') { if ($attrs -contains 'cn') { return 'enrollment-services' }; return '' }
  if ($filter -eq '(objectClass=pKICertificateTemplate)') { return 'templates' }
  if ($filter -eq '(objectClass=msPKI-Enterprise-Oid)') { return 'oid-objects' }
  if ($filter -eq '(objectClass=certificationAuthority)') { if ($baseDn -like 'CN=AIA,*') { return 'certs' }; return 'pki-acls' }
  if ($filter -eq '(objectClass=cRLDistributionPoint)') { return 'crls' }
  if ($filter -eq '(altSecurityIdentities=*)') { return 'principal-mappings' }
  if ($filter -like '(&(objectCategory=computer)(dNSHostName=*') { return '' }
  if ($filter -like '(&(objectCategory=computer)*') { return 'dc-config' }
  ''
}
function _corrupt([string]$type, [string]$mode) {
  if ($mode -eq 'empty') {
    if ($type -in @('guid', 'bytes')) { return ,@(,[byte[]]@()) }
    return ,@('')
  }
  switch ($type) {
    'string' { return ,@('first', 'second') }          # multi-valued
    'int' { return ,@('not-a-number') }
    'strings' { return ,@(,[byte[]](1, 2)) }           # binary, not text
    'guid' { return ,@(,[byte[]](1, 2, 3)) }           # not 16 bytes
    'bytes' { return ,@('text, not binary') }
  }
  throw "unknown type $type"
}
function _rdn([hashtable]$p) {
  if ($p.ContainsKey('cn')) { return [string]$p['cn'][0] }
  if ($p.ContainsKey('dnshostname')) { return ([string]$p['dnshostname'][0] -split '\.')[0] }
  if ($p.ContainsKey('mspki-cert-template-oid')) { return [string]$p['mspki-cert-template-oid'][0] }
  'object'
}
function _search([string]$baseDn, [string]$filter, [string[]]$attrs, [string]$Scope = 'Subtree', [switch]$Sd) {
  $r = _searchRaw $baseDn $filter $attrs -Scope $Scope -Sd:$Sd
  $container = _containerOf $baseDn $filter $attrs $Scope
  $target = $script:OmitSpec -and $script:OmitSpec.container -eq $container
  $entries = @()
  foreach ($e in @($r.entries)) {
    if ($null -eq $e) { continue }
    $p = @{} + $e
    if ($baseDn -and -not $p.ContainsKey('distinguishedname')) { $p['distinguishedname'] = @("CN=$(_rdn $p),$baseDn") }
    if ($target) {
      $attr = $script:OmitSpec.attr
      if ($script:OmitSpec.mode -eq 'missing') { $p.Remove($attr) }
      else { $p[$attr] = _corrupt $OBJECT_SCHEMA.$container.$attr.type $script:OmitSpec.mode }
      $target = $false
    }
    $entries += , $p
  }
  $twin = $null
  if ($script:Variant -ne 'twin') {
    switch ($script:Ambiguous) {
      'publication' { if ($container -eq 'enrollment-services' -and $entries) {
        $entries[0].certificatetemplates = @($entries[0].certificatetemplates | ForEach-Object {
          if ($_ -ceq 'LabWebServer') { _variant $_ } else { $_ } }) } }
      'crl-tier' { foreach ($e in $entries) { if ($container -eq 'certs' -and $e.cn[0] -ceq 'LAB Root CA') { $e.cn = @(_variant 'LAB Root CA') } } }
      'cert-ca' { foreach ($e in $entries) { if ($container -eq 'certs' -and $e.cn[0] -ceq 'LAB Issuing CA') { $e.cn = @(_variant 'LAB Issuing CA') } } }
      'local-ca' { if ($container -eq 'enrollment-services' -and $entries) { $entries[0].cn = @(_variant 'LAB Issuing CA') } }
      'oid-link' { if ($container -eq 'oid-objects' -and $entries) {
        $twin = @{} + $entries[0]; $twin.objectguid = @(_g 31)
        $twin['mspki-cert-template-oid'] = @(_variant ([string]$entries[0]['mspki-cert-template-oid'][0])) } }
    }
  }
  if ($script:Variant -eq 'twin') { switch ($script:Ambiguous) {
    'publication' { if ($container -eq 'templates' -and $entries) {
      # No descriptor: the twin itself decides nothing (no finding of its own).
      $twin = @{} + $entries[0]; $twin.cn = @('labwebserver'); $twin.objectguid = @(_g 30)
      $twin['mspki-cert-template-oid'] = @('1.3.6.1.4.1.311.21.8.1.77'); $twin.Remove('ntsecuritydescriptor') } }
    'crl-tier' { if ($container -eq 'certs' -and $script:Der -and $script:Der.cross) {
      # A cross-certificate of the root (same subject, another issuer): not
      # self-signed, so 'LAB Root CA' now has two kinds.
      $twin = @{ cn = @('lab root ca'); cacertificate = @(,$script:Der.cross) } } }
    'oid-link' { if ($container -eq 'oid-objects' -and $entries) {
      $twin = @{} + $entries[0]; $twin.objectguid = @(_g 31); $twin.Remove('msds-oidtogrouplink') } }
    'cert-ca' { if ($container -eq 'enrollment-services' -and $entries.Count -gt 1) {
      $twin = @{} + $entries[1]; $twin.cn = @('lab issuing ca 2'); $twin.objectguid = @(_g 32)
      $twin.dnshostname = @('labca03.lab.example.com') } }
  } }
  if ($twin) {
    $twin['distinguishedname'] = @("CN=$(_rdn $twin) (twin),$baseDn")
    $entries += , $twin
  }
  @{ entries = $entries; complete = $r.complete; reason = $r.reason }
}
function Import-Module { param([string]$Name) if ($Name -ne 'WebAdministration') { throw "unexpected module $Name" } }
function Get-Website {
  param($ErrorAction)
  $bindings = @([pscustomobject]@{ protocol = 'http' }, [pscustomobject]@{ protocol = 'https' })
  if ($script:BrokenBindings) { $bindings = @() }
  ,@([pscustomobject]@{ Name = 'Default Web Site'; bindings = [pscustomobject]@{ Collection = $bindings } })
}
function Get-WebApplication {
  param($Site, $ErrorAction)
  $apps = @([pscustomobject]@{ path = '/CertSrv' }, [pscustomobject]@{ path = '/owa' })
  if ($script:NoEnrollmentApps) { $apps = @([pscustomobject]@{ path = '/owa' }) }
  if ($script:Bad) {
    $broken = [pscustomobject]@{}
    $broken | Add-Member -MemberType ScriptProperty -Name path -Value { throw 'application path unreadable' }
    $apps += $broken
  }
  $apps
}
function Get-WebConfigurationProperty {
  param($PSPath, $Filter, $Name, $ErrorAction)
  switch ($Name) {
    'enabled' { return [pscustomobject]@{ Value = $true } }
    'extendedProtection.tokenChecking' { if ($script:Fail) { throw 'configuration read denied' }; return [pscustomobject]@{ Value = 'None' } }
    'sslFlags' { return [pscustomobject]@{ Value = '' } }
    'Collection' { return @([pscustomobject]@{ value = 'Negotiate' }, [pscustomobject]@{ value = 'NTLM' }) }
  }
}
function Get-WmiObject {
  param($ComputerName, $Credential, $Namespace, $Class, [switch]$List)
  $denied = $script:Fail -and $ComputerName -like 'LAB-DC02*'
  $o = [pscustomobject]@{ Denied = $denied; Computer = $ComputerName }
  $o | Add-Member -MemberType ScriptMethod -Name GetDWORDValue -Value {
    param($hive, $key, $value)
    if ($this.Denied) { return [pscustomobject]@{ ReturnValue = 5; uValue = $null } }
    if ($value -eq 'StrongCertificateBindingEnforcement') {
      # LAB-DC01 strict (2), every other DC disabled (0): the non-strict DC is
      # what makes ESC14 exploitable.
      $binding = if ($this.Computer -like 'LAB-DC01*') { 2 } else { 0 }
      return [pscustomobject]@{ ReturnValue = 0; uValue = $binding }
    }
    return [pscustomobject]@{ ReturnValue = 2; uValue = $null }
  }
  $o
}
function _writeJson($obj, [string]$name) {
  $p = Join-Path $OutDir $name
  $dir = Split-Path $p -Parent
  if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
  [IO.File]::WriteAllText($p, (ConvertTo-Json -InputObject $obj -Depth 20), (New-Object Text.UTF8Encoding($false)))
}
'@

# The collector body loads System.Web.Extensions for its serializer; _writeJson
# is mocked, so drop that line (Windows-only assembly).
$body = $body -replace 'Add-Type -AssemblyName System\.Web\.Extensions', '# (System.Web.Extensions: mocked)'
$body = $body -replace '\$script:JS = New-Object System\.Web\.Script\.Serialization\.JavaScriptSerializer', '$script:JS = $null'
$body = $body -replace '\$script:JS\.MaxJsonLength = \[int\]::MaxValue', ''
# The host's FQDN: DNS cannot resolve the simulated host name.
$fqdnLine = 'try { $localFqdn = ([System.Net.Dns]::GetHostEntry($localHost).HostName).ToLower() } catch { $localFqdn = $localHost }'
if (-not $body.Contains($fqdnLine)) { throw 'collector layout changed: cannot find the FQDN lookup' }
$body = $body.Replace($fqdnLine, '$localFqdn = "$localHost.lab.example.com"')
$script = [scriptblock]::Create(
  "param(`$OutDir, `$Scenario, `$Omit, `$DerDir, `$NotACa, `$BrokenBindings, `$Ambiguous, `$HostName, `$OneCa, `$HostLookupFails, `$NoEnrollmentApps, [switch]`$CollectDcMapping)`n" + $definitions + "`n" + $mocks + "`n" + $body)
& $script -OutDir $OutDir -Scenario $Scenario -Omit $Omit -DerDir $DerDir -NotACa $NotACa -BrokenBindings $BrokenBindings -Ambiguous $Ambiguous -HostName $HostName -OneCa $OneCa -HostLookupFails $HostLookupFails -NoEnrollmentApps $NoEnrollmentApps -CollectDcMapping
