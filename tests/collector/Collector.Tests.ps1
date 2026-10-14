<#
  Pester tests for the OS-independent helpers in Export-AdcsEstate.ps1.

  These run on Linux pwsh (CI) by dot-sourcing the collector with -FunctionsOnly,
  which defines the pure functions and returns before any LDAP/WMI/certutil work.
  The Windows-only paths (_parseAces over System.DirectoryServices, the live
  collection passes) are out of scope here — see WI-009.
#>
BeforeAll {
    . "$PSScriptRoot/../../scripts/Export-AdcsEstate.ps1" -FunctionsOnly
}

Describe '_decode (bit-map decode)' {
    It 'decodes the Schannel UPN bit (0x4) to upn, by key not position' {
        # Regression guard for the [ordered]-int-index bug: 0x4 is the 3rd entry by
        # key (upn) but the 3rd by position would be the same here; the real trap is
        # that $map[4] returns the 5th element. _decode must use the key.
        (_decode 4 $SCHANNEL_BITS) | Should -Be @('upn')
    }
    It 'decodes a combined Schannel value (UPN + S4U2Self-Explicit = 0x14)' {
        (_decode 0x14 $SCHANNEL_BITS) | Should -Be @('upn', 's4u2self_explicit')
    }
    It 'returns no methods for zero' {
        # ,$out wraps an empty result as a 1-element array of @() (which serializes to
        # []); assert emptiness via -join so the wrapper does not skew the check.
        ((_decode 0 $SCHANNEL_BITS) -join ',') | Should -Be ''
    }
    It 'decodes template name flags by key (ENROLLEE_SUPPLIES_SUBJECT = 0x1)' {
        (_decode 0x1 $NAME_FLAGS) | Should -Be @('ENROLLEE_SUPPLIES_SUBJECT')
    }
    It 'decodes the NO_SECURITY_EXTENSION enrollment flag (ESC9, 0x00080000)' {
        (_decode 0x00080000 $ENROLL_FLAGS) | Should -Be @('NO_SECURITY_EXTENSION')
    }
}

Describe '_decodeBinding (StrongCertificateBindingEnforcement)' {
    It 'maps 0 -> disabled' { _decodeBinding 0 | Should -Be 'disabled' }
    It 'maps 1 -> permissive' { _decodeBinding 1 | Should -Be 'permissive' }
    It 'maps 2 -> strict' { _decodeBinding 2 | Should -Be 'strict' }
    It 'maps an unexpected value -> unknown' { _decodeBinding 99 | Should -Be 'unknown' }
}

Describe '_parseCertutilFlagLines' {
    It 'extracts the decoded flag names from certutil -getreg output' {
        $lines = @(
            '  InterfaceFlags REG_DWORD = 641 (1601)',
            '    IF_LOCKICERTREQUEST -- 1',
            '    IF_ENFORCEENCRYPTICERTREQUEST -- 200 (512)'
        )
        (_parseCertutilFlagLines $lines) | Should -Be @('IF_LOCKICERTREQUEST', 'IF_ENFORCEENCRYPTICERTREQUEST')
    }
    It 'returns no flags when no flag lines are present' {
        ((_parseCertutilFlagLines @('some header', 'CertUtil: -getreg command completed.')) -join ',') | Should -Be ''
    }
}

Describe '_parseCertutilDwordLines' {
    It 'reads the first hex DWORD from certutil output' {
        $lines = @('  AuditFilter REG_DWORD = 7f (127)')
        _parseCertutilDwordLines $lines | Should -Be 127
    }
    It 'reads a small value printed without a decimal (AuditFilter = 0 is auditing disabled)' {
        _parseCertutilDwordLines @('  AuditFilter REG_DWORD = 0') | Should -Be 0
        _parseCertutilDwordLines @('  CAType REG_DWORD = 1') | Should -Be 1
    }
    It 'returns $null when no DWORD line is present' {
        _parseCertutilDwordLines @('CommonName REG_SZ = lab-ca') | Should -Be $null
    }
}

Describe '_parseCertutilMultiSzLines (WI-044: real certutil -getreg layout)' {
    # Layout taken from real certutil -getreg output (WI-044 live run), with
    # placeholder names: the registry path line, a blank line, the marker line,
    # one '    <index>: <value>' line per string, the 'CertUtil:' trailer.
    BeforeAll {
        $script:Head = @('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\LABCA\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\DisableExtensionList:', '')
        $script:Tail = @('CertUtil: -getreg command completed successfully.')
    }
    It 'returns the value after the index, never the index token (the WI-044 ESC16 false negative)' {
        $lines = $Head + @('  DisableExtensionList REG_MULTI_SZ =', '    0: 1.3.6.1.4.1.311.25.2') + $Tail
        $r = _parseCertutilMultiSzLines $lines
        @($r).Count | Should -Be 1
        @($r)[0] | Should -Be '1.3.6.1.4.1.311.25.2'
        @($r) | Where-Object { $_ -match '^\d+:$' } | Should -BeNullOrEmpty
    }
    It 'keeps a whole value with spaces: an OID with its friendly name' {
        $lines = $Head + @(
            '  EnableRequestExtensionList REG_MULTI_SZ =',
            '    0: 1.2.840.113549.1.9.15 SMIME Capabilities',
            '    1: 1.3.6.1.4.1.311.21.1 CA Version',
            '    2: 2.5.29.15 Key Usage'
        ) + $Tail
        $r = _parseCertutilMultiSzLines $lines
        @($r).Count | Should -Be 3
        @($r)[0] | Should -Be '1.2.840.113549.1.9.15 SMIME Capabilities'
        @($r)[2] | Should -Be '2.5.29.15 Key Usage'
    }
    It 'keeps flag-prefixed URL values and skips the flag lines certutil prints under them' {
        $lines = $Head + @(
            '  CRLPublicationURLs REG_MULTI_SZ =',
            '    0: 1:C:\Windows\system32\CertSrv\CertEnroll\%3%8%9.crl',
            '    CSURL_SERVERPUBLISH -- 1',
            '',
            '    1: 15:ldap:///CN=%7%8,CN=%2,CN=CDP,CN=Public Key Services,CN=Services,%6%10',
            '    CSURL_SERVERPUBLISH -- 1',
            '    CSURL_ADDTOCERTCDP -- 2',
            '    CSURL_ADDTOFRESHESTCRL -- 4',
            '    CSURL_ADDTOCRLCDP -- 8',
            '',
            '    2: 6:http://pki.example.com/CertEnroll/%3%8%9.crl',
            '    CSURL_ADDTOCERTCDP -- 2',
            '    CSURL_ADDTOFRESHESTCRL -- 4',
            ''
        ) + $Tail
        $r = _parseCertutilMultiSzLines $lines
        @($r).Count | Should -Be 3
        @($r)[1] | Should -Be '15:ldap:///CN=%7%8,CN=%2,CN=CDP,CN=Public Key Services,CN=Services,%6%10'
        @($r)[2] | Should -Be '6:http://pki.example.com/CertEnroll/%3%8%9.crl'
    }
    It 'reads an empty value (hex dump before the marker, no index line) as an empty list' {
        $lines = @($Head[0], "0000`t00 00                                              ..", "0000`t00 00 00 00                                        ....", '', '  DisableExtensionList REG_MULTI_SZ =') + $Tail
        $r = _parseCertutilMultiSzLines $lines
        $null -eq $r | Should -BeFalse
        @($r).Count | Should -Be 0
    }
    It 'returns $null (not obtained) for output it does not know' {
        $cases = @(
            @('  X REG_MULTI_SZ =', '    1: 1.2.3'),                       # index out of order
            @('  X REG_MULTI_SZ =', '    0: 1.2.3', '    0: 1.2.4'),      # repeated index
            @('  X REG_MULTI_SZ = 1.2.3'),                                 # inline value
            @('  X REG_MULTI_SZ =', '    1.2.3'),                          # the old index-less fixture
            @('  X REG_MULTI_SZ =', '    0:'),                             # empty value
            @('  X REG_MULTI_SZ =', '    0:   '),                          # blank value (DS round 1)
            @('  X REG_MULTI_SZ =', '    00: a'),                          # leading-zero index (DS round 1)
            @('  X REG_MULTI_SZ =', '    CSURL_SERVERPUBLISH -- 1'),       # flag line before a value
            @('  X REG_MULTI_SZ =', '  X REG_MULTI_SZ ='),                 # second marker
            @('CertUtil: -getreg command completed successfully.')          # no marker
        )
        foreach ($c in $cases) { _parseCertutilMultiSzLines $c | Should -Be $null -Because ($c -join ' / ') }
    }
}

Describe '_caHost (WI-044: the CA host account lookup; Sol round 1; 0.12.0: its DN)' {
    # The LDAP transport is replaced; the entries are what _entryProps returns.
    BeforeEach {
        function _rootDse { @{ domain = 'DC=lab,DC=example,DC=com' } }
        function _entryProps($entry) { $entry }
        function _sidString($values) { if (@($values).Count -eq 1) { [string]@($values)[0] } else { $null } }
        function _search($baseDn, $filter, $attrs) { @{ complete = $script:complete; entries = $script:entries; reason = '' } }
        $script:complete = $true
        $script:dns = 'labca01.lab.example.com'
    }
    It 'returns the SID of the one computer object whose dNSHostName is identical' {
        $script:entries = @(@{ dnshostname = @($dns); objectsid = @('S-1-5-21-1-2-3-1105'); distinguishedname = @('CN=labca01,CN=Computers,DC=lab,DC=example,DC=com') })
        $h = _caHost @($dns)
        $h.sid | Should -Be 'S-1-5-21-1-2-3-1105'
        $h.dn | Should -Be 'CN=labca01,CN=Computers,DC=lab,DC=example,DC=com'
    }
    It 'is unresolved when an exact match comes with a case-variant duplicate (the mixed-case probe)' {
        $script:entries = @(
            @{ dnshostname = @($dns); objectsid = @('S-1-5-21-1-2-3-1105') },
            @{ dnshostname = @('LABCA01.LAB.EXAMPLE.COM'); objectsid = @('S-1-5-21-1-2-3-9999') }
        )
        _caHost @($dns) | Should -Be $null
    }
    It 'is unresolved for two exact answers, one case-variant answer, none, or a failed search' {
        $script:entries = @(
            @{ dnshostname = @($dns); objectsid = @('S-1-5-21-1-2-3-1105') },
            @{ dnshostname = @($dns); objectsid = @('S-1-5-21-1-2-3-9999') }
        )
        _caHost @($dns) | Should -Be $null
        $script:entries = @(@{ dnshostname = @('LABCA01.lab.example.com'); objectsid = @('S-1-5-21-1-2-3-1105') })
        _caHost @($dns) | Should -Be $null
        $script:entries = @()
        _caHost @($dns) | Should -Be $null
        $script:entries = @(@{ dnshostname = @($dns); objectsid = @('S-1-5-21-1-2-3-1105') })
        $script:complete = $false
        _caHost @($dns) | Should -Be $null
    }
    It 'is unresolved when the enrollment service has no single dNSHostName' {
        $script:entries = @(@{ dnshostname = @($dns); objectsid = @('S-1-5-21-1-2-3-1105') })
        _caHost @() | Should -Be $null
        _caHost @($dns, 'other.lab.example.com') | Should -Be $null
    }
}

Describe '_caHost: the computer object is still named when its SID does not decode (0.12.0)' {
    BeforeEach {
        function _rootDse { @{ domain = 'DC=lab,DC=example,DC=com' } }
        function _entryProps($entry) { $entry }
        function _search($baseDn, $filter, $attrs) { @{ complete = $true; entries = $script:entries; reason = '' } }
    }
    It 'keeps the DN (its descriptor is read) with sid $null (ca_host_sid not obtained)' {
        $script:entries = @(@{ dnshostname = @('labca01.lab.example.com'); objectsid = @([byte[]](1, 2)); distinguishedname = @('CN=labca01,CN=Computers,DC=lab,DC=example,DC=com') })
        $h = _caHost @('labca01.lab.example.com')
        $h.sid | Should -Be $null
        $h.dn | Should -Be 'CN=labca01,CN=Computers,DC=lab,DC=example,DC=com'
    }
}

Describe '_aclRow provenance (WI-044: only an enrollment service row is tied to a CA host)' {
    It 'marks the row with the search it came from' {
        $p = @{ distinguishedname = @('CN=LABCA,CN=Enrollment Services,CN=Public Key Services'); objectguid = @(,[byte[]](0..15)) }
        $es = _aclRow $p 'ca_object' $null $true
        $es.enrollment_service | Should -BeTrue
        $es.ca_host_sid | Should -Be $null
        $other = _aclRow $p 'ca_object' '' $false
        $other.enrollment_service | Should -BeFalse
        $other.ca_host_sid | Should -Be ''
    }
}

Describe '_oidValues (OIDs of an OID-list REG_MULTI_SZ)' {
    It 'takes the OID from an OID followed by its friendly name' {
        (_oidValues @('1.3.6.1.4.1.311.25.2', '2.5.29.15 Key Usage')) | Should -Be @('1.3.6.1.4.1.311.25.2', '2.5.29.15')
    }
    It 'keeps a value that is not an OID verbatim, an empty list empty, and $null null' {
        (_oidValues @('not an oid')) | Should -Be @('not an oid')
        $e = _oidValues @()
        $null -eq $e | Should -BeFalse
        @($e).Count | Should -Be 0
        _oidValues $null | Should -Be $null
    }
}

Describe '_auditFilterFrom (WI-044: an unset AuditFilter is auditing off)' {
    It 'reads a set value' {
        _auditFilterFrom @('  AuditFilter REG_DWORD = 7f (127)', 'CertUtil: -getreg command completed successfully.') 0 | Should -Be 127
    }
    It 'reads a value that is not set (ERROR_FILE_NOT_FOUND) as 0, not $null' {
        $lines = @('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\LABCA\AuditFilter:', 'CertUtil: -getreg command FAILED: 0x80070002 (WIN32: 2 ERROR_FILE_NOT_FOUND)', 'CertUtil: The system cannot find the file specified.')
        $r = _auditFilterFrom $lines -2147024894
        $null -eq $r | Should -BeFalse
        $r | Should -Be 0
    }
    It 'keeps a failed read $null (not obtained)' {
        _auditFilterFrom @('CertUtil: -getreg command FAILED: 0x80070005 (WIN32: 5 ERROR_ACCESS_DENIED)') -2147024891 | Should -Be $null
        _auditFilterFrom @('CertUtil: -getreg command completed successfully.') 0 | Should -Be $null
    }
}

Describe '_sidString / _ldapEscape (WI-044 CA host account lookup)' {
    It 'decodes a binary objectSid' {
        $b = [byte[]](1, 5, 0, 0, 0, 0, 0, 5) + [BitConverter]::GetBytes([uint32]21) + [BitConverter]::GetBytes([uint32]1111111111) + [BitConverter]::GetBytes([uint32]2222222222) + [BitConverter]::GetBytes([uint32]3333333333) + [BitConverter]::GetBytes([uint32]1105)
        _sidString @(,[byte[]]$b) | Should -Be 'S-1-5-21-1111111111-2222222222-3333333333-1105'
        _sidString @(,[byte[]](1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0)) | Should -Be 'S-1-5-18'
    }
    It 'returns $null for anything that is not exactly one well-formed SID' {
        _sidString @() | Should -Be $null
        _sidString @(,[byte[]](1, 2, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0)) | Should -Be $null   # count says 2, one present
        _sidString @(,[byte[]](2, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0)) | Should -Be $null   # revision 2
        _sidString @('S-1-5-18') | Should -Be $null                                       # not binary
        _sidString @([byte[]](1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0), [byte[]](1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0)) | Should -Be $null
    }
    It 'escapes every RFC 4515 special character, backslash first' {
        _ldapEscape 'ca01.lab.example.com' | Should -Be 'ca01.lab.example.com'
        _ldapEscape 'a*)(b\c' | Should -Be 'a\2a\29\28b\5cc'
        _ldapEscape ('x' + [char]0) | Should -Be 'x\00'
    }
}

Describe '_epaToken (Extended Protection token)' {
    It 'maps require values' { _epaToken 2 | Should -Be 'require'; _epaToken 'Require' | Should -Be 'require' }
    It 'maps allow values' { _epaToken 1 | Should -Be 'allow'; _epaToken 'Allow' | Should -Be 'allow' }
    It 'maps none values' { _epaToken 0 | Should -Be 'none'; _epaToken 'None' | Should -Be 'none' }
    It 'never reads an empty, missing or unknown value as none (the 0.11.0 defect)' {
        foreach ($v in @('', $null, 'Off', 'weird', $true, 3)) { _epaToken $v | Should -Be $null }
    }
}

Describe '_sslRequiredFrom (sslFlags -> ssl_required)' {
    It 'is true when the Ssl flag is set, by name or by number' {
        foreach ($v in @('Ssl', 'Ssl, Ssl128', 'Ssl,Ssl128', 'Ssl,SslNegotiateCert', 'ssl', 8, 264, 72)) { _sslRequiredFrom $v | Should -BeTrue }
    }
    It 'is false for None or client-certificate flags alone' {
        foreach ($v in @('None', 'SslNegotiateCert', 'SslRequireCert', 'SslMapCert', 0, 32, 96)) { _sslRequiredFrom $v | Should -BeFalse }
    }
    It 'is $null (not obtained) for anything it cannot vouch for' {
        foreach ($v in @('', $null, 'Ssl128', 256, 'None, Ssl', 'Ssl, Bogus', 'Ssl;Ssl128', 128, 9, -1, $true)) {
            _sslRequiredFrom $v | Should -Be $null
        }
    }
}

Describe '_iisScalar / _iisBool / _bothScopes (one IIS value, both scopes)' {
    It 'takes a bare value or a wrapper Value, and nothing else' {
        _iisScalar @{ ok = $true; value = 'Require' } | Should -Be 'Require'
        _iisScalar @{ ok = $true; value = [pscustomobject]@{ Value = $true } } | Should -BeTrue
        _iisScalar @{ ok = $true; value = [pscustomobject]@{ Value = 2 } } | Should -Be 2
        _iisScalar @{ ok = $false; value = $null } | Should -Be $null
        _iisScalar @{ ok = $true; value = @('a', 'b') } | Should -Be $null
        _iisScalar @{ ok = $true; value = @() } | Should -Be $null
        _iisScalar @{ ok = $true; value = [pscustomobject]@{ Other = 1 } } | Should -Be $null
        _iisScalar @{ ok = $true; value = [pscustomobject]@{ Value = [pscustomobject]@{ Value = 1 } } } | Should -Be $null
    }
    It 'reads a Boolean or its text only' {
        _iisBool $true | Should -BeTrue
        _iisBool 'False' | Should -BeFalse
        foreach ($v in @($null, '', 'yes', 1)) { _iisBool $v | Should -Be $null }
    }
    It 'keeps a value only when both scopes decode to the same one' {
        _bothScopes 'require' 'require' | Should -Be 'require'
        _bothScopes $false $false | Should -BeFalse
        _bothScopes 'none' 'require' | Should -Be $null
        _bothScopes $null 'require' | Should -Be $null
        _bothScopes 'require' $null | Should -Be $null
    }
}

Describe 'IIS location-tag layout (2026-10-13 live: Extended Protection and sslFlags in applicationHost.config location tags)' {
    # A fake Get-WebConfigurationProperty modelling an IIS server where AD CS setup
    # wrote the Web Enrollment app's settings into
    # <location path="Default Web Site/CertSrv"> in applicationHost.config. A
    # Boolean comes back as a ConfigurationAttribute (an object with Value); the
    # enum and flags attributes come back as their value text.
    BeforeAll {
        function script:_layout([string]$appEpa, [string]$appSsl) {
            $script:IisLayout = @{
                app = @{ 'enabled' = [pscustomobject]@{ Value = $true }; 'extendedProtection.tokenChecking' = $appEpa; 'sslFlags' = $appSsl }
                apphost = @{ 'enabled' = [pscustomobject]@{ Value = $true }; 'extendedProtection.tokenChecking' = 'Require'; 'sslFlags' = 'Ssl, Ssl128' }
            }
        }
        function script:Get-WebConfigurationProperty {
            param($PSPath, $Location, $Filter, $Name, $ErrorAction)
            if ($PSPath -eq 'MACHINE/WEBROOT/APPHOST') {
                if ($Location -cne 'Default Web Site/CertSrv') { throw "no location $Location" }
                return $script:IisLayout.apphost[$Name]
            }
            if ($PSPath -cne 'IIS:\Sites\Default Web Site\CertSrv') { throw "unexpected path $PSPath" }
            $script:IisLayout.app[$Name]
        }
    }
    It 'the 0.11.0 read dereferenced .Value of the enum / flags text and got nothing: epa none, ssl_required false' {
        _layout 'Require' 'Ssl, Ssl128'
        $tc = _tryRead { Get-WebConfigurationProperty -PSPath 'IIS:\Sites\Default Web Site\CertSrv' -Filter 'f' -Name 'extendedProtection.tokenChecking' -ErrorAction Stop }
        $ssl = _tryRead { Get-WebConfigurationProperty -PSPath 'IIS:\Sites\Default Web Site\CertSrv' -Filter 'f' -Name sslFlags -ErrorAction Stop }
        $tc.ok | Should -BeTrue
        $tc.value.Value | Should -Be $null
        # The 0.11.0 expressions: _epaToken '' was 'none'; '' -match 'Ssl' is false.
        ([string]$tc.value.Value) | Should -Be ''
        (([string]$ssl.value.Value) -match 'Ssl') | Should -BeFalse
    }
    It 'reads Require and SSL required from both scopes' {
        _layout 'Require' 'Ssl, Ssl128'
        $tc = _iisRead 'IIS:\Sites\Default Web Site\CertSrv' 'Default Web Site/CertSrv' 'f' 'extendedProtection.tokenChecking'
        $ssl = _iisRead 'IIS:\Sites\Default Web Site\CertSrv' 'Default Web Site/CertSrv' 'f' 'sslFlags'
        $wa = _iisRead 'IIS:\Sites\Default Web Site\CertSrv' 'Default Web Site/CertSrv' 'f' 'enabled'
        _bothScopes (_epaToken $tc.app) (_epaToken $tc.apphost) | Should -Be 'require'
        _bothScopes (_sslRequiredFrom $ssl.app) (_sslRequiredFrom $ssl.apphost) | Should -BeTrue
        _bothScopes (_iisBool $wa.app) (_iisBool $wa.apphost) | Should -BeTrue
    }
    It 'is not obtained when the application read returns the parent default (None) while the location tag says Require' {
        _layout 'None' 'None'
        $tc = _iisRead 'IIS:\Sites\Default Web Site\CertSrv' 'Default Web Site/CertSrv' 'f' 'extendedProtection.tokenChecking'
        $ssl = _iisRead 'IIS:\Sites\Default Web Site\CertSrv' 'Default Web Site/CertSrv' 'f' 'sslFlags'
        $tc.app | Should -Be 'None'
        $tc.apphost | Should -Be 'Require'
        _bothScopes (_epaToken $tc.app) (_epaToken $tc.apphost) | Should -Be $null
        _bothScopes (_sslRequiredFrom $ssl.app) (_sslRequiredFrom $ssl.apphost) | Should -Be $null
    }
    It 'is not obtained when either scope fails to read' {
        _layout 'Require' 'Ssl, Ssl128'
        $tc = _iisRead 'IIS:\Sites\Default Web Site\CertSrv' 'Default Web Site/Elsewhere' 'f' 'extendedProtection.tokenChecking'
        $tc.app | Should -Be 'Require'
        $tc.apphost | Should -Be $null
        _bothScopes (_epaToken $tc.app) (_epaToken $tc.apphost) | Should -Be $null
    }
}

Describe '_classifyApp (IIS app path -> endpoint kind)' {
    It 'classifies /certsrv as web_enrollment' { _classifyApp '/certsrv' | Should -Be 'web_enrollment' }
    It 'classifies an mscep path as ndes' { _classifyApp '/CertSrv/mscep' | Should -Be 'ndes' }
    It 'classifies a CES/CEP path as ces' { _classifyApp '/ADPolicyProvider_CEP_Kerberos' | Should -Be 'ces' }
    It 'returns $null for an unrelated app' { _classifyApp '/owa' | Should -Be $null }
}

Describe '_caKindFromType (CAType -> CaKind)' {
    It 'maps Enterprise Root (0) to issuing' { _caKindFromType 0 | Should -Be 'issuing' }
    It 'maps Enterprise Subordinate (1) to issuing' { _caKindFromType 1 | Should -Be 'issuing' }
    It 'maps Standalone Root (3) to root' { _caKindFromType 3 | Should -Be 'root' }
    It 'maps Standalone Subordinate (4) to standalone' { _caKindFromType 4 | Should -Be 'standalone' }
    It 'maps an unexpected value to null (not obtained), never a guessed issuing' { _caKindFromType 99 | Should -BeNullOrEmpty }
    It 'maps $null (CAType unreadable) to null (not obtained)' { _caKindFromType $null | Should -BeNullOrEmpty }
}

Describe '_guidHex (objectGUID identity, collector 0.9.0)' {
    It 'renders the 16 raw bytes as 32 lower-case hex characters, in order' {
        _guidHex @(,[byte[]](0..15)) | Should -Be '000102030405060708090a0b0c0d0e0f'
    }
    It 'returns empty when the attribute was not returned' {
        _guidHex @() | Should -Be ''
        _guidHex $null | Should -Be ''
    }
    It 'returns empty for a value that is not 16 bytes' {
        _guidHex @(,[byte[]](1, 2, 3)) | Should -Be ''
    }
}

Describe '_safeFileName (DER file names)' {
    It 'keeps alphanumerics, dots, underscores and hyphens' {
        _safeFileName 'LAB-CA_01.example.com' | Should -Be 'LAB-CA_01.example.com'
    }
    It 'replaces spaces and path-hostile characters with underscores' {
        _safeFileName 'LAB Issuing CA (old)/2' | Should -Be 'LAB_Issuing_CA__old__2'
    }
    It 'produces a name with no directory separator left' {
        (_safeFileName 'a/b\c:d') | Should -Not -Match '[/\\:]'
    }
}

Describe '_certKindFromDer (root vs issuing classification)' {
    BeforeAll {
        function _newCert([string]$subject, $issuerCert, [int]$days) {
            $key = [System.Security.Cryptography.RSA]::Create(2048)
            $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
                "CN=$subject", $key,
                [System.Security.Cryptography.HashAlgorithmName]::SHA256,
                [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
            $now = [System.DateTimeOffset]::UtcNow
            if ($null -eq $issuerCert) {
                # A CA needs Basic Constraints for CertificateRequest.Create to
                # accept it as an issuer for the leaf below.
                $req.CertificateExtensions.Add(
                    [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($true, $false, 0, $true))
                $cert = $req.CreateSelfSigned($now.AddDays(-1), $now.AddDays($days))
            } else {
                $cert = $req.Create($issuerCert, $now.AddDays(-1), $now.AddDays($days), [byte[]](1,2,3,4))
            }
            @{ Cert = $cert; Key = $key }
        }
        $script:_root = _newCert 'Pester Root' $null 365
        $script:_leaf = _newCert 'Pester Leaf' $script:_root.Cert 90
    }
    AfterAll {
        foreach ($x in @($script:_root, $script:_leaf)) { if ($x) { $x.Cert.Dispose(); $x.Key.Dispose() } }
    }
    It 'classifies a self-signed cert as root_ca' {
        _certKindFromDer $script:_root.Cert.RawData | Should -Be 'root_ca'
    }
    It 'classifies a CA-signed cert as issuing_ca' {
        _certKindFromDer $script:_leaf.Cert.RawData | Should -Be 'issuing_ca'
    }
    It 'returns other for empty input' { _certKindFromDer @() | Should -Be 'other' }
    It 'returns other for garbage bytes' { _certKindFromDer ([byte[]](1,2,3)) | Should -Be 'other' }
}

Describe '_classifyApp tightened CEP matching' {
    It 'still classifies a _CES_ path as ces' { _classifyApp '/contoso_CES_Kerberos' | Should -Be 'ces' }
    It 'classifies a bare /cep segment as ces' { _classifyApp '/cep' | Should -Be 'ces' }
    It 'does not false-match a path merely containing cep' { _classifyApp '/concept' | Should -Be $null }
    It 'does not false-match cep inside a longer segment' { _classifyApp '/reception' | Should -Be $null }
}

Describe '_pagedSearchCore (proof that a paged LDAP search returned everything)' {
    BeforeAll {
        function Resp($entries, $cookie, $code = 'Success', [switch]$NoControl) {
            $controls = @()
            if (-not $NoControl) { $controls = @([pscustomobject]@{ Cookie = [byte[]]$cookie }) }
            [pscustomobject]@{ ResultCode = $code; Entries = @($entries); Controls = $controls }
        }
    }
    It 'is complete when every page succeeds and the last cookie is empty' {
        $script:pages = @((Resp @('a', 'b') @(1)), (Resp @('c') @()))
        $script:n = 0
        $r = _pagedSearchCore { param($c) $script:pages[$script:n++] }
        $r.complete | Should -BeTrue
        @($r.entries) | Should -Be @('a', 'b', 'c')
        $r.reason | Should -Be ''
    }
    It 'is incomplete when a page throws (size/time limit, dropped connection) but keeps the rows' {
        $script:n = 0
        $r = _pagedSearchCore { param($c) if ($script:n++ -eq 0) { Resp @('a') @(1) } else { throw 'The size limit was exceeded' } }
        $r.complete | Should -BeFalse
        @($r.entries) | Should -Be @('a')
        $r.reason | Should -Match 'size limit'
    }
    It 'is incomplete when a page returns a non-Success result code' {
        $r = _pagedSearchCore { param($c) Resp @('a') @() 'SizeLimitExceeded' }
        $r.complete | Should -BeFalse
        $r.reason | Should -Match 'SizeLimitExceeded'
    }
    It 'is incomplete when the server returns no paging control' {
        $r = _pagedSearchCore { param($c) Resp @('a') @() -NoControl }
        $r.complete | Should -BeFalse
        $r.reason | Should -Match 'no paging control'
    }
    It 'is incomplete when the cookie never empties within the page cap' {
        $r = _pagedSearchCore { param($c) Resp @('a') @(9) } 3
        $r.complete | Should -BeFalse
        @($r.entries).Count | Should -Be 3
    }
    It 'is incomplete (never falsely complete) when the paging control carries a null cookie' {
        $r = _pagedSearchCore { param($c) [pscustomobject]@{ ResultCode = 'Success'; Entries = @('a'); Controls = @([pscustomobject]@{ Cookie = $null }) } } 3
        $r.complete | Should -BeFalse
    }
    It 'passes the previous page cookie to the next request' {
        $script:seen = @()
        $script:n = 0
        $null = _pagedSearchCore { param($c) $script:seen += ,@($c); if ($script:n++ -eq 0) { Resp @() @(7) } else { Resp @() @() } }
        $script:seen[0].Length | Should -Be 0
        $script:seen[1] | Should -Be @(7)
    }
}

Describe '_searchMarker (rows serialized == objects the verified search returned)' {
    It 'is complete only for a complete search with every object serialized' {
        $m = _searchMarker $true '' 3 3 @()
        $m.complete | Should -BeTrue
        $m.count | Should -Be 3
        $m.Contains('reason') | Should -BeFalse
    }
    It 'is incomplete when an object was not serialized, even after a complete search' {
        $m = _searchMarker $true '' 3 2 @()
        $m.complete | Should -BeFalse
        $m.count | Should -Be 2
        $m.reason | Should -Match '2 of 3 enumerated object'
    }
    It 'is incomplete when an object failed, with the failure in the reason' {
        $m = _searchMarker $true '' 1 1 @('template: unparseable')
        $m.complete | Should -BeFalse
        $m.reason | Should -Match 'template: unparseable'
    }
    It 'is incomplete when the search was not proven complete' {
        $m = _searchMarker $false 'page 1 failed' 2 2 @()
        $m.complete | Should -BeFalse
        $m.reason | Should -Be 'page 1 failed'
    }
}

Describe '_schemaCheck (round 7: a returned object never yields a coerced key)' {
    BeforeAll {
        function Es([hashtable]$extra) {
            $p = @{ distinguishedname = @('CN=LAB CA,CN=Enrollment Services'); cn = @('LAB CA')
                    objectguid = @(,[byte[]](@(1) * 16)) }
            foreach ($k in $extra.Keys) { if ($null -eq $extra[$k]) { $p.Remove($k) } else { $p[$k] = $extra[$k] } }
            $p
        }
    }
    It 'accepts a well-formed enrollment service, optional attributes absent' {
        $c = _schemaCheck (Es @{}) $OBJECT_SCHEMA.'enrollment-services'
        $c.fatal | Should -BeNullOrEmpty
    }
    It 'fails an enrollment service without cn (Sol round 6), never keys it as an empty string' {
        (_schemaCheck (Es @{ cn = $null }) $OBJECT_SCHEMA.'enrollment-services').fatal | Should -Be 'cn missing'
        { _requireSchema (Es @{ cn = $null }) 'enrollment-services' } | Should -Throw '*cn missing*'
    }
    It 'fails an empty or multi-valued required string' {
        (_schemaCheck (Es @{ cn = @('') }) $OBJECT_SCHEMA.'enrollment-services').fatal | Should -Match 'cn is empty'
        (_schemaCheck (Es @{ cn = @('a', 'b') }) $OBJECT_SCHEMA.'enrollment-services').fatal | Should -Match 'cn is empty or not a single string'
    }
    It 'fails an objectGUID that is not 16 bytes' {
        (_schemaCheck (Es @{ objectguid = @(,[byte[]](1, 2)) }) $OBJECT_SCHEMA.'enrollment-services').fatal | Should -Match 'objectguid'
    }
    It 'fails a present-but-empty optional attribute (absence is a value, emptiness is not)' {
        (_schemaCheck (Es @{ certificatetemplates = @('LabUser', '') }) $OBJECT_SCHEMA.'enrollment-services').fatal | Should -Match 'certificatetemplates'
    }
    It 'fails a non-integer flag on a template' {
        $t = @{ distinguishedname = @('CN=T'); cn = @('T'); objectguid = @(,[byte[]](@(2) * 16))
                'mspki-cert-template-oid' = @('1.2.3'); 'mspki-enrollment-flag' = @('x') }
        (_schemaCheck $t $OBJECT_SCHEMA.templates).fatal | Should -Match 'not an integer'
    }
    It 'leaves an unreadable security descriptor to _sdRead (a null read, not an object failure)' {
        $t = @{ distinguishedname = @('CN=T'); cn = @('T'); objectguid = @(,[byte[]](@(2) * 16))
                'mspki-cert-template-oid' = @('1.2.3'); ntsecuritydescriptor = @(,[byte[]]@()) }
        (_schemaCheck $t $OBJECT_SCHEMA.templates).fatal | Should -BeNullOrEmpty
    }
    It 'keeps a DC without dNSHostName as a soft (placeholder) failure' {
        $dc = @{ distinguishedname = @('CN=DC2'); objectguid = @(,[byte[]](@(9) * 16)) }
        $c = _schemaCheck $dc $OBJECT_SCHEMA.'dc-config'
        $c.fatal | Should -BeNullOrEmpty
        $c.soft | Should -Be @('dnshostname')
    }
}

Describe '_searchMarker with rows that are not 1:1 with objects (certs / crls)' {
    It 'compares objects returned with objects serialized and counts rows' {
        # One AIA object carrying two certificates: 1 of 1 objects, 2 rows.
        $m = _searchMarker $true '' 1 1 @() 2
        $m.complete | Should -BeTrue
        $m.count | Should -Be 2
    }
    It 'names the object that failed, not "0 of 0" (Sol round 7 minor)' {
        $m = _searchMarker $true '' 1 0 @('AIA object: cn missing') 0
        $m.complete | Should -BeFalse
        $m.count | Should -Be 0
        $m.reason | Should -Match '0 of 1 enumerated object'
    }
}

Describe '_schemaCheck guards' {
    It 'throws for a container with no schema instead of requiring nothing' {
        { _requireSchema @{ distinguishedname = @('CN=x') } 'no-such-container' } | Should -Throw '*no object schema*'
    }
}

Describe '_baseSearchCore (single-object reads)' {
    It 'is complete for a Success result' {
        $r = _baseSearchCore { param($c) [pscustomobject]@{ ResultCode = 'Success'; Entries = @('root') } }
        $r.complete | Should -BeTrue
        @($r.entries) | Should -Be @('root')
    }
    It 'is not complete when the read throws (absent object, no read access)' {
        $r = _baseSearchCore { param($c) throw 'noSuchObject' }
        $r.complete | Should -BeFalse
        @($r.entries).Count | Should -Be 0
    }
    It 'is not complete for any other result code' {
        (_baseSearchCore { param($c) [pscustomobject]@{ ResultCode = 'InsufficientAccessRights'; Entries = @() } }).complete | Should -BeFalse
    }
}

Describe 'certutil -getreg outcomes (a failed read is never an empty list)' {
    It 'classifies exit code 0 as ok, not-found as absent, anything else as failed' {
        _certutilStatus @('x') 0 | Should -Be 'ok'
        _certutilStatus @('CertUtil: -getreg command FAILED: 0x80070002 (WIN32: 2 ERROR_FILE_NOT_FOUND)') -2147024894 | Should -Be 'absent'
        _certutilStatus @() 2 | Should -Be 'absent'
        _certutilStatus @('CertUtil: -getreg command FAILED: 0x80070005 (WIN32: 5 ERROR_ACCESS_DENIED)') -2147024891 | Should -Be 'failed'
        _certutilStatus @() -1 | Should -Be 'failed'
    }
    It 'returns the flags of a successful read' {
        $lines = @('  EditFlags REG_DWORD = 15014e (1376590)', '    EDITF_ATTRIBUTESUBJECTALTNAME2 -- 40000 (262144)')
        (_certutilFlagsFrom $lines 0) | Should -Be @('EDITF_ATTRIBUTESUBJECTALTNAME2')
    }
    It 'returns an empty list for a read value with no flags set, or a value not configured' {
        $r = _certutilFlagsFrom @('  InterfaceFlags REG_DWORD = 0') 0
        $null -eq $r | Should -BeFalse
        @($r).Count | Should -Be 0
        $a = _certutilFlagsFrom @('FAILED: 0x80070002') 2
        $null -eq $a | Should -BeFalse
        @($a).Count | Should -Be 0
    }
    It 'returns $null for a failed read or output without the value line' {
        _certutilFlagsFrom @('FAILED: 0x80070005') 5 | Should -Be $null
        _certutilFlagsFrom @('CertUtil: -getreg command completed successfully.') 0 | Should -Be $null
    }
    It 'reads a DWORD only from a successful read' {
        _certutilDwordFrom @('  AuditFilter REG_DWORD = 7f (127)') 0 | Should -Be 127
        _certutilDwordFrom @('FAILED: 0x80070002') 2 | Should -Be $null
        _certutilDwordFrom @('FAILED') 5 | Should -Be $null
    }
    It 'reads a multi-string: list, empty when not configured, $null on failure' {
        $read = @('  DisableExtensionList REG_MULTI_SZ =', '    0: 1.3.6.1.4.1.311.25.2', 'CertUtil: -getreg command completed successfully.')
        (_certutilMultiSzFrom $read 0) | Should -Be @('1.3.6.1.4.1.311.25.2')
        _certutilMultiSzFrom @('  DisableExtensionList REG_MULTI_SZ =', '    1.3.6.1.4.1.311.25.2') 0 | Should -Be $null
        $absent = _certutilMultiSzFrom @('FAILED: 0x80070002') 2
        $null -eq $absent | Should -BeFalse
        @($absent).Count | Should -Be 0
        _certutilMultiSzFrom @('FAILED') 5 | Should -Be $null
        _certutilMultiSzFrom @('completed successfully') 0 | Should -Be $null
    }
    It 'reads a string value with its status' {
        $ok = _certutilStringFrom @('  CommonName REG_SZ = LAB-CA') 0 'CommonName'
        $ok.status | Should -Be 'ok'; $ok.value | Should -Be 'LAB-CA'
        (_certutilStringFrom @('FAILED: 0x80070002') 2 'CommonName').status | Should -Be 'absent'
        (_certutilStringFrom @('FAILED') 1062 'CommonName').status | Should -Be 'failed'
        (_certutilStringFrom @('garbage') 0 'CommonName').status | Should -Be 'failed'
    }
}

Describe '_wmiDwordStatus (StdRegProv GetDWORDValue)' {
    It 'is ok for ReturnValue 0 with a value' { _wmiDwordStatus ([pscustomobject]@{ ReturnValue = 0; uValue = 2 }) | Should -Be 'ok' }
    It 'is absent for value / key not found' {
        _wmiDwordStatus ([pscustomobject]@{ ReturnValue = 1; uValue = $null }) | Should -Be 'absent'
        _wmiDwordStatus ([pscustomobject]@{ ReturnValue = 2; uValue = $null }) | Should -Be 'absent'
    }
    It 'is failed for access denied, a missing value on success, or no result' {
        _wmiDwordStatus ([pscustomobject]@{ ReturnValue = 5; uValue = $null }) | Should -Be 'failed'
        _wmiDwordStatus ([pscustomobject]@{ ReturnValue = 0; uValue = $null }) | Should -Be 'failed'
        _wmiDwordStatus $null | Should -Be 'failed'
    }
}

Describe 'not-obtained reads stay null' {
    It '_tryRead tells an empty result from a failed read' {
        $empty = _tryRead { @() }
        $empty.ok | Should -BeTrue
        $failed = _tryRead { throw 'access denied' }
        $failed.ok | Should -BeFalse
        $failed.value | Should -Be $null
    }
    It '_list keeps null as null and makes a list of anything else' {
        _list $null | Should -Be $null
        $e = _list @()
        $null -eq $e | Should -BeFalse
        @($e).Count | Should -Be 0
        (_list 'a') | Should -Be @('a')
    }
    It '_sdRead reports an absent descriptor as not obtained' {
        $r = _sdRead $null
        $r.aces | Should -Be $null
        $r.owner | Should -Be $null
    }
    It '_caSecurityFromBytes reports an absent or unparseable hive value as not obtained' {
        foreach ($bytes in @($null, [byte[]]@(), [byte[]](1, 2, 3))) {
            $r = _caSecurityFromBytes $bytes
            $r.aces | Should -Be $null
            $r.owner | Should -Be $null
        }
    }
    It '_v yields the values of an attribute, nothing for one not returned' {
        $p = @{ cn = @('x'); ekus = @('a', 'b'); objectguid = @(,[byte[]](0..15)) }
        @(_v $p 'cn')[0] | Should -Be 'x'
        @(_v $p 'ekus' | ForEach-Object { [string]$_ }) | Should -Be @('a', 'b')
        @(_v $p 'missing').Count | Should -Be 0
        _guidHex @(_v $p 'objectguid') | Should -Be '000102030405060708090a0b0c0d0e0f'
    }
}

Describe 'the collector stays read-only' {
    BeforeAll { $script:src = Get-Content "$PSScriptRoot/../../scripts/Export-AdcsEstate.ps1" -Raw }
    It 'invokes certutil only with -getreg' {
        $calls = [regex]::Matches($script:src, 'certutil\s+-(\w+)') | ForEach-Object { $_.Groups[1].Value }
        @($calls | Sort-Object -Unique) | Should -Be @('getreg')
    }
    It 'sends only LDAP search requests' {
        $script:src | Should -Not -Match '(Modify|Add|Delete|ModifyDN|Extended)Request'
        $script:src | Should -Match 'SearchRequest'
    }
    It 'writes no registry, AD or IIS configuration' {
        $script:src | Should -Not -Match '\.SetValue\(|Set-ItemProperty|New-ItemProperty|Set-WebConfiguration|Set-ADObject|CommitChanges|SetDWORDValue|CreateKey'
    }
}

Describe 'scripts are pure ASCII (PS 5.1 BOM-less parse safety)' {
    # PS 5.1 reads a BOM-less .ps1 as ANSI: a UTF-8 em dash in a *string literal*
    # once mis-decoded to a quote char and broke parsing (fixed in 5a98907).
    # Keeping the scripts ASCII-only removes the whole bug class.
    It 'no .ps1 under scripts/ contains non-ASCII characters' {
        $bad = @()
        foreach ($f in (Get-ChildItem "$PSScriptRoot/../../scripts" -Filter *.ps1)) {
            $bytes = [IO.File]::ReadAllBytes($f.FullName)
            if ($bytes | Where-Object { $_ -gt 127 }) { $bad += $f.Name }
        }
        $bad | Should -Be @()
    }
}

Describe 'Assert-AdcsOutputPath (every write stays inside -OutDir)' {
    BeforeAll {
        # The guard reads $OutDir dynamically, as the collector's own param.
        $script:base = Join-Path $TestDrive 'guard'
        $OutDir = Join-Path $script:base 'out'
        New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
        New-Item -ItemType Directory -Force -Path (Join-Path $script:base 'outside') | Out-Null
        $sep = [IO.Path]::DirectorySeparatorChar
    }
    It 'accepts the output directory itself and paths inside it' {
        { Assert-AdcsOutputPath $OutDir } | Should -Not -Throw
        { Assert-AdcsOutputPath (Join-Path $OutDir 'ca-config.json') } | Should -Not -Throw
        { Assert-AdcsOutputPath (Join-Path (Join-Path $OutDir 'certs') '00-ca.cer') } | Should -Not -Throw
    }
    It 'refuses a .. traversal out of the output directory' {
        { Assert-AdcsOutputPath ($OutDir + $sep + '..' + $sep + 'outside' + $sep + 'x.json') } |
            Should -Throw '*outside the output directory*'
        { Assert-AdcsOutputPath (Join-Path $OutDir ('..' + $sep + '..' + $sep + 'evil')) } |
            Should -Throw '*outside the output directory*'
    }
    It 'refuses an absolute path elsewhere' {
        { Assert-AdcsOutputPath (Join-Path $script:base 'outside') } | Should -Throw '*outside the output directory*'
        { Assert-AdcsOutputPath ([IO.Path]::GetTempPath()) } | Should -Throw '*outside the output directory*'
    }
    It 'refuses a sibling directory that only shares the prefix' {
        { Assert-AdcsOutputPath ($OutDir + 'side' + $sep + 'x.json') } | Should -Throw '*outside the output directory*'
    }
    It 'refuses UNC and device paths outright' {
        { Assert-AdcsOutputPath '\\host.example.test\share\x.json' } | Should -Throw '*UNC or device path*'
        { Assert-AdcsOutputPath '\\?\C:\Windows\x.json' } | Should -Throw '*UNC or device path*'
        { Assert-AdcsOutputPath '\\?\UNC\host\share\x' } | Should -Throw '*UNC or device path*'
        { Assert-AdcsOutputPath '\\.\PhysicalDrive0' } | Should -Throw '*UNC or device path*'
        { Assert-AdcsOutputPath '//host.example.test/share/x.json' } | Should -Throw '*UNC or device path*'
    }
    It 'refuses to write through a junction / symlink inside the output directory' -Skip:($IsWindows) {
        $link = Join-Path $OutDir 'link'
        New-Item -ItemType SymbolicLink -Path $link -Target (Join-Path $script:base 'outside') -Force | Out-Null
        { Assert-AdcsOutputPath (Join-Path $link 'x.json') } | Should -Throw '*reparse point*'
    }
}

