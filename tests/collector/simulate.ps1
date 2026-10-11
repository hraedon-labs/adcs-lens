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
  -Scenario failures  certutil EditFlags fails, CAType and DisableExtensionList
                      are not configured, the template search loses a page,
                      one template's descriptor is unreadable, the CA\Security
                      read fails, one IIS property read throws, and one DC's
                      WMI read is denied
#>
param(
  [Parameter(Mandatory)] [string] $OutDir,
  [ValidateSet('clean', 'failures')] [string] $Scenario = 'clean'
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
function hostname { 'labca01' }
$script:Fail = ($Scenario -eq 'failures')
function _ok($lines) { @{ lines = @($lines); code = 0 } }
function _certutilRead([string]$regpath) {
  switch ($regpath) {
    'CA\CommonName' { return _ok '  CommonName REG_SZ = LAB Issuing CA' }
    'policy\EditFlags' {
      if ($script:Fail) { return @{ lines = @('CertUtil: -getreg command FAILED: 0x80070005 (WIN32: 5 ERROR_ACCESS_DENIED)'); code = 5 } }
      return _ok @('  EditFlags REG_DWORD = 15014e (1376590)', '    EDITF_ATTRIBUTESUBJECTALTNAME2 -- 40000 (262144)')
    }
    'CA\InterfaceFlags' { return _ok @('  InterfaceFlags REG_DWORD = 641 (1601)', '    IF_ENFORCEENCRYPTICERTREQUEST -- 200 (512)') }
    'CA\AuditFilter' { return _ok '  AuditFilter REG_DWORD = 0' }
    'policy\DisableExtensionList' {
      if ($script:Fail) { return @{ lines = @('CertUtil: -getreg command FAILED: 0x80070002 (WIN32: 2 ERROR_FILE_NOT_FOUND)'); code = -2147024894 } }
      return _ok @('  DisableExtensionList REG_MULTI_SZ =', '    1.3.6.1.4.1.311.25.2')
    }
    'CA\CAType' {
      if ($script:Fail) { return @{ lines = @('FAILED: 0x80070002'); code = 2 } }
      return _ok '  CAType REG_DWORD = 1'
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
function _sdRead($sdBytes) {
  if (-not $sdBytes) { return @{ aces = $null; owner = $null } }
  @{ aces = @([ordered]@{ trustee_sid = 'S-1-5-21-1111111111-2222222222-3333333333-513'; trustee_name = 'Domain Users'; rights = @('Enroll'); ace_type = 'Allow' }); owner = 'S-1-5-21-1111111111-2222222222-3333333333-512' }
}
function _entryProps($entry) { $entry }
function _g([int]$n) { ,([byte[]](@($n) * 16)) }
function _ent([hashtable]$p) { $p }
function _done($entries) { @{ entries = @($entries); complete = $true; reason = '' } }
function _search([string]$baseDn, [string]$filter, [string[]]$attrs, [string]$Scope = 'Subtree', [switch]$Sd) {
  $pks = 'CN=Public Key Services,CN=Services,CN=Configuration,DC=lab,DC=example,DC=com'
  if ($baseDn -eq '' -and $Scope -eq 'Base') {
    return _done (_ent @{ configurationnamingcontext = @('CN=Configuration,DC=lab,DC=example,DC=com'); defaultnamingcontext = @('DC=lab,DC=example,DC=com') })
  }
  if ($Scope -eq 'Base') {
    if ($baseDn -like 'CN=CDP,*') { return @{ entries = @(); complete = $false; reason = 'read failed: insufficient access' } }
    return _done (_ent @{ distinguishedname = @($baseDn); objectguid = @(_g ($baseDn.Length)); ntsecuritydescriptor = @(,[byte[]](1, 2, 3)) })
  }
  if ($filter -eq '(objectClass=pKIEnrollmentService)' -and $baseDn -eq "CN=Enrollment Services,$pks") {
    return _done @(
      (_ent @{ cn = @('LAB Issuing CA'); dnshostname = @('labca01.lab.example.com'); certificatetemplates = @('LabWebServer', 'LabUser'); objectguid = @(_g 1); distinguishedname = @("CN=LAB Issuing CA,$baseDn"); ntsecuritydescriptor = @(,[byte[]](1)) }),
      (_ent @{ cn = @('LAB Issuing CA 2'); dnshostname = @('labca02.lab.example.com'); certificatetemplates = @('LabUser'); objectguid = @(_g 2); distinguishedname = @("CN=LAB Issuing CA 2,$baseDn"); ntsecuritydescriptor = @(,[byte[]](1)) })
    )
  }
  if ($filter -eq '(objectClass=pKICertificateTemplate)') {
    $rows = @(
      (_ent @{ cn = @('LabWebServer'); displayname = @('Lab Web Server'); objectguid = @(_g 3); 'mspki-certificate-name-flag' = @('1'); 'mspki-enrollment-flag' = @('0'); pkiextendedkeyusage = @('1.3.6.1.5.5.7.3.2'); 'mspki-template-schema-version' = @('2'); 'mspki-cert-template-oid' = @('1.3.6.1.4.1.311.21.8.1.1'); 'mspki-minimal-key-size' = @('2048'); ntsecuritydescriptor = @(,[byte[]](1)) }),
      (_ent @{ cn = @('LabUser'); displayname = @('Lab User'); objectguid = @(_g 4); pkiextendedkeyusage = @('1.3.6.1.5.5.7.3.2', '1.3.6.1.4.1.311.10.3.4'); 'mspki-cert-template-oid' = @('1.3.6.1.4.1.311.21.8.1.2'); ntsecuritydescriptor = @(if ($script:Fail) { } else { ,[byte[]](1) }) })
    )
    if ($script:Fail) { return @{ entries = $rows; complete = $false; reason = 'page 1 failed: The size limit for this request was exceeded' } }
    return _done $rows
  }
  if ($filter -eq '(objectClass=msPKI-Enterprise-Oid)') {
    return _done (_ent @{ 'mspki-cert-template-oid' = @('1.3.6.1.4.1.311.21.8.1.9'); objectguid = @(_g 5); displayname = @('Lab Policy'); 'msds-oidtogrouplink' = @('CN=Lab Admins,DC=lab,DC=example,DC=com') })
  }
  if ($filter -eq '(objectClass=certificationAuthority)' -and $baseDn -like 'CN=Certification Authorities,*') {
    return _done (_ent @{ distinguishedname = @("CN=LAB Root CA,$baseDn"); objectguid = @(_g 6); ntsecuritydescriptor = @(,[byte[]](1)) })
  }
  if ($filter -eq '(objectClass=certificationAuthority)' -and $baseDn -like 'CN=AIA,*') { return _done @() }
  if ($filter -eq '(objectClass=cRLDistributionPoint)') { return _done @() }
  if ($filter -eq '(altSecurityIdentities=*)') {
    return _done (_ent @{ distinguishedname = @('CN=Svc,DC=lab,DC=example,DC=com'); objectguid = @(_g 7); altsecurityidentities = @('X509:<I>CN=CA<S>CN=Svc') })
  }
  if ($filter -like '(&(objectCategory=computer)*') {
    return _done @(
      (_ent @{ dnshostname = @('LAB-DC01.lab.example.com'); objectguid = @(_g 8) }),
      (_ent @{ dnshostname = @('LAB-DC02.lab.example.com'); objectguid = @(_g 9) })
    )
  }
  throw "unexpected search $baseDn $filter"
}
function Import-Module { param([string]$Name) if ($Name -ne 'WebAdministration') { throw "unexpected module $Name" } }
function Get-Website { param($ErrorAction) ,@([pscustomobject]@{ Name = 'Default Web Site'; bindings = [pscustomobject]@{ Collection = @([pscustomobject]@{ protocol = 'http' }, [pscustomobject]@{ protocol = 'https' }) } }) }
function Get-WebApplication { param($Site, $ErrorAction) @([pscustomobject]@{ path = '/CertSrv' }, [pscustomobject]@{ path = '/owa' }) }
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
  $o = [pscustomobject]@{ Denied = $denied }
  $o | Add-Member -MemberType ScriptMethod -Name GetDWORDValue -Value {
    param($hive, $key, $value)
    if ($this.Denied) { return [pscustomobject]@{ ReturnValue = 5; uValue = $null } }
    if ($value -eq 'StrongCertificateBindingEnforcement') { return [pscustomobject]@{ ReturnValue = 0; uValue = 0 } }
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
$script = [scriptblock]::Create(
  "param(`$OutDir, `$Scenario, [switch]`$CollectDcMapping)`n" + $definitions + "`n" + $mocks + "`n" + $body)
& $script -OutDir $OutDir -Scenario $Scenario -CollectDcMapping
