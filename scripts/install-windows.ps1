<#
STYLE: Never embed single quotes inside double-quoted strings. PowerShell 5.1
reads this file via the system ANSI codepage when the UTF-8 BOM is missing
(e.g. GitHub zip download), and multi-byte UTF-8 sequences corrupt the
parser's quote-tracking state -- every subsequent ' inside "..." becomes a
fatal parse error. Use `" `"` (escaped double quotes) or restructure instead.

Also: this script must run on PowerShell 5.1 (the default on Windows Server
2016+). Avoid PS 7+ syntax: no ?? (null-coalescing), no ternary operator, no
pipeline chain operators (&& / ||). Use if/else and -or/-and instead.

.SYNOPSIS
    Bootstrap adcs-lens on Windows.

.DESCRIPTION
    Creates a virtualenv and installs adcs-lens (with the [certs] extra for
    DER cert/CRL lifecycle parsing) into it. adcs-lens is a CLI tool, not a
    web service: no IIS, no TLS bindings, no secrets, no app pool. The
    installer just creates a venv, installs the package, and makes the
    adcs-lens command available.

    Re-running is safe: the venv is recreated and the package upgraded in
    place. No data is lost (adcs-lens stores no persistent state; it reads
    exported directories on demand).

    When the detected Python is user-scoped (the default with the Python
    Install Manager), the script copies it to a shared location under
    InstallDir so it is reachable outside a user profile (important for
    scheduled tasks or SSH sessions).

.PARAMETER InstallDir
    Base directory for the venv and the shared Python install.
    Default: C:\ProgramData\adcs-lens

.PARAMETER NoCerts
    Skip the [certs] extra. Without it, DER cert/CRL lifecycle fields are
    None and lifecycle checks degrade to a coverage note instead of
    producing wrong answers. Only use this if you cannot install the
    cryptography package on the target host (air-gapped, no compiler).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\scripts\install-windows.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\scripts\install-windows.ps1 -InstallDir D:\adcs-lens

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\scripts\install-windows.ps1 -NoCerts

.NOTES
    This script is not signed. If your execution policy blocks unsigned
    scripts, either bypass it per-invocation (see example above) or sign
    the script with your organisation's code-signing certificate.
#>
[CmdletBinding()]
param(
    [string]$InstallDir = "C:\ProgramData\adcs-lens",
    [switch]$NoCerts
)

# --- Helper functions (extracted for Pester testing) ---
# Placed before the main execution body so the script can be dot-sourced to
# load the functions without running the install logic.

function Test-PythonVersion {
    <#
    .SYNOPSIS
        Parse a Python --version output string and check whether it meets the
        minimum (3.12). Returns a hashtable with Major, Minor, MeetsMinimum,
        and Raw fields, or $null when the string does not look like a Python
        version.
    #>
    param([string]$VersionOutput)
    # Pre-filter to the first line starting with "Python <digit>" so a stray
    # line containing "Python 3.11" ahead of the real "Python 3.14" does not
    # match the wrong version. Mirrors the sibling installers.
    $verLine = ($VersionOutput -split "`n" | Where-Object { $_ -match "^Python\s+\d" } | Select-Object -First 1)
    if (-not $verLine) { $verLine = $VersionOutput }
    if ($verLine -match "Python\s+(\d+)\.(\d+)") {
        $major = [int]$Matches[1]
        $minor = [int]$Matches[2]
        $meets = ($major -ge 3 -and $minor -ge 12) -or ($major -gt 3)
        return @{ Major = $major; Minor = $minor; MeetsMinimum = [bool]$meets; Raw = $verLine.Trim() }
    }
    return $null
}

function Test-NeedsSharedPython {
    <#
    .SYNOPSIS
        Return $true when a python.exe path lives under a user profile or the
        Windows Store WindowsApps directory, meaning it is unreachable by
        scheduled tasks or SSH sessions and should be copied to a shared
        location.
    #>
    param([string]$PythonExePath)
    if (-not $PythonExePath) { return $false }
    return ($PythonExePath -like "*\AppData\*" -or $PythonExePath -like "*\WindowsApps\*")
}

# Guard: only run the main installation body when executed directly. Dot-sourcing
# loads the helper functions above so they can be unit-tested without touching
# the filesystem or creating venvs.
if ($MyInvocation.InvocationName -ne ".") {

    $ErrorActionPreference = "Stop"

    # --- Must be elevated (we write under ProgramData) ---
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run from an elevated (Administrator) PowerShell."
    }

    $repoRoot = (Resolve-Path "$PSScriptRoot\..").Path
    $venv     = Join-Path $InstallDir "venv"

    # --- Create the install directory and harden its ACL early ---
    # This must happen BEFORE the shared-Python copy so the python subtree and
    # the venv inherit the hardened ACL (admins + SYSTEM only). On a fresh
    # install the default ProgramData ACL grants BUILTIN\Users create-files
    # inheritance, which allows a non-admin to plant a malicious exe/dll in the
    # venv or shared-Python tree. On a re-run the directory already exists with
    # whatever ACL the operator set; do not clobber it.
    $freshInstall = -not (Test-Path $InstallDir)
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    if ($freshInstall) {
        Write-Host "Restricting ACL on $InstallDir (admins + SYSTEM only) ..."
        icacls $InstallDir /inheritance:r /grant:r "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-Host "  [warn] ACL hardening failed (icacls exit $LASTEXITCODE); directory retains default ACL."
        }
    }

    # --- Locate a Python 3.12+ launcher ---
    # The Windows 'py' launcher works interactively but can fail through
    # PowerShell's & operator (Windows Store stubs, argument mangling).
    # Use cmd /c for probing, then resolve the real python.exe path so all
    # subsequent calls go directly to the executable.
    function Invoke-PyProbe {
        param([string]$Exe, [string[]]$Arguments)
        $argStr = ($Arguments | ForEach-Object { if ($_ -match '\s') { "`"$_`"" } else { $_ } }) -join ' '
        $tmp = Join-Path $env:TEMP "adcs-py-probe.txt"
        & cmd /c "`"$Exe`" $argStr > `"$tmp`" 2>&1"
        $exit = $LASTEXITCODE
        $out = ""
        if (Test-Path $tmp) {
            $out = (Get-Content $tmp -Raw)
            Remove-Item $tmp -Force
        }
        @{ ExitCode = $exit; Output = if ($out) { $out.Trim() } else { "" } }
    }

    # Candidate interpreters, in priority order. Fully-qualified python.exe
    # paths come first because they work in non-interactive sessions (SSH /
    # scheduled task / service); the bare `py` / `python` / `python3` PATH
    # launchers come last and are skipped below when they resolve to a
    # Windows Store execution-alias stub under WindowsApps -- those 0-byte
    # reparse points fail with "cannot be accessed by the system" outside an
    # interactive logon.
    $launchers = @()
    # 1. The shared interpreter a prior install copied under InstallDir.
    $sharedCandidate = Join-Path $InstallDir "python\python.exe"
    if (Test-Path $sharedCandidate) { $launchers += @{ Exe = $sharedCandidate; Args = @() } }
    # 2. Python Install Manager per-user runtimes (full prefixes, real exes).
    if ($env:LOCALAPPDATA) {
        $imRoot = Join-Path $env:LOCALAPPDATA "Python"
        foreach ($pc in (Get-ChildItem $imRoot -Filter "pythoncore-*" -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending)) {
            $p = Join-Path $pc.FullName "python.exe"
            if (Test-Path $p) { $launchers += @{ Exe = $p; Args = @() } }
        }
    }
    # 3. Per-machine Python installs.
    foreach ($base in @($env:ProgramFiles, ${env:ProgramFiles(x86)})) {
        if (-not $base) { continue }
        foreach ($d in (Get-ChildItem $base -Filter "Python3*" -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending)) {
            $p = Join-Path $d.FullName "python.exe"
            if (Test-Path $p) { $launchers += @{ Exe = $p; Args = @() } }
        }
    }
    # 4. Install Manager bin shims, then the bare PATH launchers, as a last resort.
    if ($env:LOCALAPPDATA) {
        foreach ($n in @("python3.exe", "python.exe")) {
            $p = Join-Path (Join-Path $env:LOCALAPPDATA "Python\bin") $n
            if (Test-Path $p) { $launchers += @{ Exe = $p; Args = @() } }
        }
    }
    $launchers += @(
        @{ Exe = "py";      Args = @("-3.14") },
        @{ Exe = "py";      Args = @("-3.12") },
        @{ Exe = "py";      Args = @("-3") },
        @{ Exe = "python";  Args = @() },
        @{ Exe = "python3"; Args = @() }
    )
    $python = $null
    $resolvedMajor = 0
    $resolvedMinor = 0
    foreach ($l in $launchers) {
        $label = "$($l.Exe) $($l.Args -join `" `")"
        $cmd = Get-Command $l.Exe -ErrorAction SilentlyContinue
        if (-not $cmd) {
            Write-Host "  [skip] $label -- exe not found on PATH"
            continue
        }
        # Skip Windows Store execution-alias stubs: they resolve on PATH but
        # cannot be executed in a non-interactive session.
        if ($cmd.Source -and $cmd.Source -match "\\WindowsApps\\") {
            Write-Host "  [skip] $label -- Windows Store alias ($($cmd.Source)), unusable non-interactively"
            continue
        }
        $probeArgs = $l.Args + @("--version")
        $r = Invoke-PyProbe -Exe $l.Exe -Arguments $probeArgs
        if ($r.ExitCode -ne 0) {
            Write-Host "  [fail] $label -- exit code $($r.ExitCode)"
            continue
        }
        $verInfo = Test-PythonVersion -VersionOutput $r.Output
        if ($verInfo) {
            if ($verInfo.MeetsMinimum) {
                # Resolve the real python.exe path so we bypass the launcher
                # for all subsequent calls (venv, pip). Ask Python itself.
                $resolved = ""
                try {
                    $selfProbe = Invoke-PyProbe -Exe $l.Exe -Arguments ($l.Args + @("-c", "import sys; print(sys.executable)"))
                    if ($selfProbe.ExitCode -eq 0) {
                        $candidate = ($selfProbe.Output -split "`n" | Select-Object -First 1).Trim()
                        if ($candidate -and (Test-Path $candidate -ErrorAction SilentlyContinue)) {
                            $resolved = $candidate
                        }
                    }
                } catch { }
                if ($resolved) {
                    Write-Host "  [ok]   $label -- $($verInfo.Raw) (resolved: $resolved)"
                    $python = @{ Exe = $resolved; Args = @() }
                } else {
                    Write-Host "  [ok]   $label -- $($verInfo.Raw) (using launcher directly)"
                    $python = $l
                }
                $resolvedMajor = $verInfo.Major
                $resolvedMinor = $verInfo.Minor
                break
            }
            Write-Host "  [fail] $label -- version $($verInfo.Major).$($verInfo.Minor) < 3.12"
        } else {
            Write-Host "  [fail] $label -- output not recognised: $($r.Output)"
        }
    }
    if (-not $python) {
        throw "Python 3.12+ not found. Install it (winget install Python.Python.3.14) and re-run."
    }

    # --- Ensure Python is in a shared (non-user-profile) location ---
    # The Python Install Manager installs runtimes per-user only (under
    # %LocalAppData%\Python). A scheduled task or SSH session cannot access
    # user profiles, so we copy the runtime to a shared directory under
    # InstallDir.
    $sharedPyDir = Join-Path $InstallDir "python"
    $sharedPyExe = Join-Path $sharedPyDir "python.exe"
    $needsShared = Test-NeedsSharedPython -PythonExePath $python.Exe
    if ($needsShared) {
        if (Test-Path $sharedPyExe) {
            Write-Host "Using existing shared Python at $sharedPyDir"
        } else {
            Write-Host "Python is user-scoped ($($python.Exe)); copying to shared location ..."
            Write-Host "  Installing to $sharedPyDir via py install --target ..."
            $tag = "$resolvedMajor.$resolvedMinor"
            $r = Invoke-PyProbe -Exe "py" -Arguments @("install", "--target=$sharedPyDir", $tag)
            if ($r.ExitCode -ne 0) {
                # Fallback: manually copy the installation
                Write-Host "  py install --target failed (exit $($r.ExitCode)); copying manually ..."
                $pySrc = Split-Path $python.Exe
                # Copy the entire Python prefix (not just the exe -- we need stdlib)
                if (Test-Path $pySrc) {
                    Copy-Item -Path $pySrc -Destination $sharedPyDir -Recurse -Force
                }
            }
            if (-not (Test-Path $sharedPyExe)) {
                # py install --target may extract to a subdirectory
                $nested = Get-ChildItem -Path $sharedPyDir -Filter "python.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($nested) {
                    $sharedPyDir = Split-Path $nested.FullName
                    $sharedPyExe = $nested.FullName
                }
            }
            if (-not (Test-Path $sharedPyExe)) {
                throw "Failed to create shared Python at $sharedPyDir. Copy $($python.Exe) manually."
            }
            # Python 3.14+ marks venvlauncher.exe as hidden/system. When we
            # copy the installation to a shared location, those attributes
            # survive. The venv module then cannot copy the launcher into the
            # new venv, producing a degraded wrapper instead of a proper
            # launcher.
            $launcher = Join-Path $sharedPyDir "Lib\venv\scripts\nt\venvlauncher.exe"
            $wlauncher = Join-Path $sharedPyDir "Lib\venv\scripts\nt\venvwlauncher.exe"
            if (Test-Path $launcher) {
                attrib -H -S $launcher 2>$null | Out-Null
            }
            if (Test-Path $wlauncher) {
                attrib -H -S $wlauncher 2>$null | Out-Null
            }
            Write-Host "  Shared Python ready at $sharedPyExe"
        }
        $python = @{ Exe = $sharedPyExe; Args = @() }
    }

    # Clear hidden/system attributes on the chosen interpreter's venv launchers
    # before creating the venv. Python 3.14 marks venvlauncher.exe hidden+system;
    # venv creation then fails with "Unable to copy ... venvlauncher.exe". The
    # fresh-copy path above clears these, but when we reuse an existing shared
    # Python (the common re-install case) the attributes survive, so clear them
    # here unconditionally against whichever interpreter we resolved.
    $pyPrefix = Split-Path $python.Exe
    foreach ($vl in @("Lib\venv\scripts\nt\venvlauncher.exe", "Lib\venv\scripts\nt\venvwlauncher.exe")) {
        $vlPath = Join-Path $pyPrefix $vl
        if (Test-Path $vlPath) { attrib -H -S $vlPath 2>$null | Out-Null }
    }

    Write-Host "Creating virtualenv at $venv ..."
    # Capture venv output rather than letting it stream. Python 3.14 can emit a
    # scary-looking "Unable to copy ... venvlauncher.exe" line while still
    # producing a working venv via its fallback; we only want to show that noise
    # if the venv actually fails to verify below.
    $venvOut = & $python.Exe @($python.Args + @("-m", "venv", $venv)) 2>&1
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path (Join-Path $venv "Scripts\python.exe"))) {
        if ($venvOut) { Write-Host ($venvOut | Out-String) }
        throw "Failed to create virtualenv at $venv using $($python.Exe)."
    }

    $venvPy = Join-Path $venv "Scripts\python.exe"
    # Verify the venv is functional (not just that the file exists). In Python
    # 3.14 the venvlauncher copy may silently produce a broken wrapper when the
    # source launcher has hidden/system attributes.
    $venvProbe = & $venvPy -c "import sys; print(sys.executable)" 2>&1
    if ($LASTEXITCODE -ne 0) {
        if ($venvOut) { Write-Host ($venvOut | Out-String) }
        throw "venv created but python.exe is not functional (exit $LASTEXITCODE): $venvProbe"
    }
    Write-Host "  venv verified: $venvProbe"
    if ("$venvOut" -match "Unable to copy") {
        # The venv verified functional, so the launcher-copy message is cosmetic
        # (Python used its fallback wrapper). Say so, so it does not read as a
        # failure.
        Write-Host "  Note: Python logged a benign `"Unable to copy venvlauncher.exe`" message during"
        Write-Host "        venv creation; the venv was created and verified working, so it is not an error."
    }

    Write-Host "Installing adcs-lens ..."
    & $venvPy -m pip install --upgrade pip 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  [warn] pip self-upgrade failed (exit $LASTEXITCODE); continuing with the bundled pip."
    }
    # Every third-party wheel is installed from a hash-locked requirements file
    # exported from uv.lock (scripts/locks/), so the install never re-resolves a
    # dependency from the index. adcs-lens itself is then installed --no-deps.
    $locks = Join-Path $repoRoot "scripts\locks"
    $buildLock = Join-Path $locks "requirements-build.lock.txt"
    $certsLock = Join-Path $locks "requirements-certs.lock.txt"
    $requiredLocks = @($buildLock)
    if (-not $NoCerts) { $requiredLocks += $certsLock }
    foreach ($lock in $requiredLocks) {
        if (-not (Test-Path $lock)) {
            throw "Missing lock file $lock; run the installer from a complete adcs-lens checkout."
        }
    }
    # The build backend (hatchling), locked separately so the package is built with
    # --no-build-isolation and pip cannot resolve another backend at install time.
    & $venvPy -m pip install --require-hashes -r $buildLock
    if ($LASTEXITCODE -ne 0) {
        throw "Hash-pinned build dependency install failed (exit $LASTEXITCODE)."
    }
    # The [certs] extra pulls cryptography for DER cert/CRL lifecycle parsing.
    # Without it lifecycle fields are None and lifecycle checks degrade to a
    # coverage note. Use -NoCerts to skip (air-gapped hosts without a compiler);
    # the core has no other runtime dependencies, so -NoCerts installs none.
    if (-not $NoCerts) {
        & $venvPy -m pip install --require-hashes -r $certsLock
        if ($LASTEXITCODE -ne 0) {
            throw "Hash-pinned [certs] dependency install failed (exit $LASTEXITCODE)."
        }
    }
    # --upgrade so an in-place re-install actually refreshes the package
    # metadata. Without it pip could leave a prior version's dist-info in
    # place, which is what the app reports as its version.
    & $venvPy -m pip install --upgrade --no-build-isolation --no-deps $repoRoot
    if ($LASTEXITCODE -ne 0) {
        throw "pip install of adcs-lens failed (exit $LASTEXITCODE)."
    }

    # Surface the version that actually landed in the venv, and flag drift from
    # the source tree being installed.
    $installedVer = ((& $venvPy -m pip show adcs-lens 2>$null | Select-String "^Version:") -replace "^Version:\s*", "").Trim()
    $sourceVer = ""
    $pyprojectPath = Join-Path $repoRoot "pyproject.toml"
    if (Test-Path $pyprojectPath) {
        $verLine = Get-Content $pyprojectPath | Select-String '^\s*version\s*=' | Select-Object -First 1
        if ($verLine) { $sourceVer = ($verLine.ToString() -replace '.*=\s*"?([^"]*)"?.*', '$1').Trim() }
    }
    Write-Host "  Installed adcs-lens version: $installedVer"
    if ($sourceVer -and $installedVer -and ($installedVer -ne $sourceVer)) {
        Write-Host "  [warn] Installed version ($installedVer) does not match the source tree ($sourceVer)."
    }

    # Verify the CLI entry point is available.
    $adcsLensExe = Join-Path $venv "Scripts\adcs-lens.exe"
    if (Test-Path $adcsLensExe) {
        $cliVer = & $adcsLensExe --version 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  CLI verified: $cliVer"
        } else {
            Write-Host "  [warn] adcs-lens.exe exists but --version exited with code ${LASTEXITCODE}:"
            Write-Host "         $cliVer"
            Write-Host "         The venv python.exe is at $venvPy; use it directly if the entry point is broken."
        }
    } else {
        Write-Host "  [warn] adcs-lens.exe not found at $adcsLensExe"
        Write-Host "         The venv python.exe is at $venvPy; use it directly if the entry point is missing."
    }

    Write-Host ""
    Write-Host "Done. adcs-lens installed to $venv"
    Write-Host ""
    Write-Host "Usage:"
    Write-Host "  $venvPy -m adcs_lens --help"
    Write-Host "  # or, if the entry point resolved:"
    Write-Host "  & `"$adcsLensExe`" --help"
    Write-Host ""
    Write-Host "Typical workflow:"
    Write-Host "  1. Export the PKI config on the CA (read-only):"
    Write-Host "     scripts\Export-AdcsEstate.ps1 -OutDir C:\AdcsExport"
    Write-Host "  2. Analyze the export:"
    Write-Host "     & `"$adcsLensExe`" doctor C:\AdcsExport"
    Write-Host "     & `"$adcsLensExe`" doctor C:\AdcsExport --json"
    Write-Host "     & `"$adcsLensExe`" doctor C:\AdcsExport --html"
    Write-Host "     & `"$adcsLensExe`" diff OLD\Export NEW\Export"
    Write-Host ""
    if ($NoCerts) {
        Write-Host "NOTE: -NoCerts was used; DER cert/CRL lifecycle parsing is disabled."
        Write-Host "      Lifecycle fields are None and lifecycle checks degrade to a coverage note."
    }

} # end dot-source guard
