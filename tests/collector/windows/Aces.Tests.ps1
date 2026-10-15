<#
  Windows-only Pester tests for _parseAces, which uses System.DirectoryServices
  (.NET) to decode an nTSecurityDescriptor and is the input to ESC1/ESC4/ESC5/ESC7.
  These can't run on Linux pwsh, so they live in their own dir and run only on the
  windows-latest CI job. We build a security descriptor with known ACEs in-test
  (no captured blob needed) and assert the round-trip through _parseAces.
#>
BeforeAll {
    . "$PSScriptRoot/../../../scripts/Export-AdcsEstate.ps1" -FunctionsOnly

    $script:ENROLL_GUID = [Guid]'0e10c968-78fb-11d2-90d4-00c04f79dc55'
    $script:ZERO_GUID = [Guid]'00000000-0000-0000-0000-000000000000'
    $script:TEST_SID = 'S-1-5-21-1111111111-2222222222-3333333333-1000'

    function New-Sd([System.DirectoryServices.ActiveDirectoryAccessRule[]]$rules) {
        $sd = New-Object System.DirectoryServices.ActiveDirectorySecurity
        foreach ($r in $rules) { $sd.AddAccessRule($r) }
        $sd.GetSecurityDescriptorBinaryForm()
    }
    function New-SdWithOwner([string]$sidStr) {
        $sd = New-Object System.DirectoryServices.ActiveDirectorySecurity
        $sd.SetOwner((New-Object System.Security.Principal.SecurityIdentifier($sidStr)))
        $sd.GetSecurityDescriptorBinaryForm()
    }
    function Rule(
        [string]$sidStr,
        [System.DirectoryServices.ActiveDirectoryRights]$rights,
        [System.Security.AccessControl.AccessControlType]$type,
        [Guid]$guid
    ) {
        # Type the args so PowerShell picks the (IdentityReference, ActiveDirectoryRights,
        # AccessControlType, Guid) overload unambiguously.
        $sid = New-Object System.Security.Principal.SecurityIdentifier($sidStr)
        New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, $rights, $type, $guid)
    }
}

Describe '_parseAces (Windows / System.DirectoryServices)' {
    It 'maps an ExtendedRight ACE with the Enroll GUID to the Enroll right' {
        $bytes = New-Sd @((Rule $TEST_SID 'ExtendedRight' 'Allow' $ENROLL_GUID))
        $aces = _parseAces $bytes
        $mine = @($aces | Where-Object { $_.trustee_sid -eq $TEST_SID })
        $mine.Count | Should -Be 1
        $mine[0].rights | Should -Contain 'Enroll'
        $mine[0].ace_type | Should -Be 'Allow'
    }

    It 'maps an all-zero-ObjectType ExtendedRight ACE to AllExtendedRights' {
        $bytes = New-Sd @((Rule $TEST_SID 'ExtendedRight' 'Allow' $ZERO_GUID))
        $mine = @((_parseAces $bytes) | Where-Object { $_.trustee_sid -eq $TEST_SID })
        $mine[0].rights | Should -Contain 'AllExtendedRights'
    }

    It 'maps an all-zero-ObjectType WriteProperty ACE to WritePropertyAll (ESC4)' {
        $bytes = New-Sd @((Rule $TEST_SID 'WriteProperty' 'Allow' $ZERO_GUID))
        $mine = @((_parseAces $bytes) | Where-Object { $_.trustee_sid -eq $TEST_SID })
        $mine[0].rights | Should -Contain 'WritePropertyAll'
    }

    It 'maps a scoped WriteProperty ACE to WriteProperty:<guid> (WI-019)' {
        # A non-zero ObjectType scopes the write to one property; the collector
        # emits 'WriteProperty:<guid>' (lower-cased) so the core can match it
        # against the dangerous-property GUID map (ESC4 scoped-write path).
        $nameFlagGuid = [Guid]'ea1dddc4-60ff-416e-8cc0-17cee534bce7'
        $bytes = New-Sd @((Rule $TEST_SID 'WriteProperty' 'Allow' $nameFlagGuid))
        $mine = @((_parseAces $bytes) | Where-Object { $_.trustee_sid -eq $TEST_SID })
        $mine[0].rights | Should -Contain 'WriteProperty:ea1dddc4-60ff-416e-8cc0-17cee534bce7'
    }

    It 'preserves GenericAll and the Deny ACE type' {
        $bytes = New-Sd @((Rule $TEST_SID 'GenericAll' 'Deny' $ZERO_GUID))
        $mine = @((_parseAces $bytes) | Where-Object { $_.trustee_sid -eq $TEST_SID })
        $mine[0].rights | Should -Contain 'GenericAll'
        $mine[0].ace_type | Should -Be 'Deny'
    }

    It 'marks an inherit-only ACE and an explicit one (review round 2, Sol B2)' {
        $sid = New-Object System.Security.Principal.SecurityIdentifier($TEST_SID)
        $children = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $sid, [System.DirectoryServices.ActiveDirectoryRights]'GenericAll',
            [System.Security.AccessControl.AccessControlType]'Allow',
            [System.DirectoryServices.ActiveDirectorySecurityInheritance]'Children')
        $bytes = New-Sd @($children, (Rule $TEST_SID 'ReadProperty' 'Allow' $ZERO_GUID))
        $mine = @((_parseAces $bytes) | Where-Object { $_.trustee_sid -eq $TEST_SID })
        $io = @($mine | Where-Object { $_.rights -contains 'GenericAll' })
        $io.Count | Should -Be 1
        $io[0].inherit_only | Should -BeTrue
        $io[0].inherited | Should -BeFalse
        $own = @($mine | Where-Object { $_.rights -contains 'ReadProperty' })
        $own[0].inherit_only | Should -BeFalse
    }

    It 'returns an empty result for an empty descriptor' {
        ((_parseAces ([byte[]]@())) -join ',') | Should -Be ''
    }
}

Describe '_readOwner (Windows / System.DirectoryServices)' {
    It 'returns the owner SID from a synthetic security descriptor' {
        $bytes = New-SdWithOwner $TEST_SID
        _readOwner $bytes | Should -Be $TEST_SID
    }

    It 'returns empty for null or empty input' {
        _readOwner $null | Should -Be ''
        _readOwner ([byte[]]@()) | Should -Be ''
    }
}

Describe '_rawSdOwner (Windows / RawSecurityDescriptor — CA\Security owner, WI-037)' {
    It 'returns the owner SID from a synthetic CA-style security descriptor' {
        # _caSecurityOwner parses the CA registry SD via RawSecurityDescriptor
        # (not the AD ActiveDirectorySecurity parser _readOwner uses). A binary SD
        # built either way is a valid self-relative SD, so New-SdWithOwner feeds
        # both parsers and confirms the CA-registry parser path reads the owner.
        $bytes = New-SdWithOwner $TEST_SID
        _rawSdOwner $bytes | Should -Be $TEST_SID
    }

    It 'returns empty for null or empty input' {
        _rawSdOwner $null | Should -Be ''
        _rawSdOwner ([byte[]]@()) | Should -Be ''
    }
}
