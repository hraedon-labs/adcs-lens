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
    It 'returns $null when no DWORD line is present' {
        _parseCertutilDwordLines @('CommonName REG_SZ = lab-ca') | Should -Be $null
    }
}

Describe '_parseCertutilMultiSzLines' {
    It 'collects indented continuation values (multi-value)' {
        $lines = @(
            '  DisableExtensionList REG_MULTI_SZ =',
            '    1.3.6.1.4.1.311.25.2',
            '    2.5.29.14',
            'CertUtil: -getreg command completed successfully.'
        )
        (_parseCertutilMultiSzLines $lines) | Should -Be @('1.3.6.1.4.1.311.25.2', '2.5.29.14')
    }
    It 'captures a same-line value after =' {
        $lines = @(
            '  DisableExtensionList REG_MULTI_SZ = 1.3.6.1.4.1.311.25.2',
            'CertUtil: -getreg command completed successfully.'
        )
        (_parseCertutilMultiSzLines $lines) | Should -Be @('1.3.6.1.4.1.311.25.2')
    }
    It 'captures multiple same-line values after =' {
        $lines = @(
            '  DisableExtensionList REG_MULTI_SZ = 1.3.6.1.4.1.311.25.2 2.5.29.14',
            'CertUtil: -getreg command completed successfully.'
        )
        (_parseCertutilMultiSzLines $lines) | Should -Be @('1.3.6.1.4.1.311.25.2', '2.5.29.14')
    }
    It 'collects continuation values when the marker line is empty' {
        $lines = @(
            '  DisableExtensionList REG_MULTI_SZ =',
            '    1.3.6.1.4.1.311.25.2',
            'CertUtil: -getreg command completed successfully.'
        )
        (_parseCertutilMultiSzLines $lines) | Should -Be @('1.3.6.1.4.1.311.25.2')
    }
    It 'returns empty when the value is absent' {
        $lines = @('CertUtil: -getreg command completed successfully.')
        ((_parseCertutilMultiSzLines $lines) -join ',') | Should -Be ''
    }
}

Describe '_epaToken (Extended Protection token)' {
    It 'maps require values' { _epaToken 2 | Should -Be 'require'; _epaToken 'Require' | Should -Be 'require' }
    It 'maps allow values' { _epaToken 1 | Should -Be 'allow' }
    It 'maps none/off/empty values' { _epaToken 0 | Should -Be 'none'; _epaToken '' | Should -Be 'none'; _epaToken 'Off' | Should -Be 'none' }
    It 'maps an unrecognized value to unknown' { _epaToken 'weird' | Should -Be 'unknown' }
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
    It 'maps an unexpected value to issuing (pre-0.8.0 default)' { _caKindFromType 99 | Should -Be 'issuing' }
    It 'maps $null (CAType unreadable) to issuing' { _caKindFromType $null | Should -Be 'issuing' }
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
