#!/usr/bin/env python3
"""Round-2 adversarial probe of the collector read-only gate.

Appends each candidate statement to a COPY of the real collector, runs the real
pwsh dumper + the real violations() from tests/test_collector_readonly.py, and
reports FLAGGED / BYPASS. A BYPASS is a snippet the gate accepted.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path("/home/itadmin/wt/scratch/sibling-review/adcs-chore-sibling-review-2026-10-09-ds")
OUT = ROOT / ".review" / "tmp" / "probe_out"
OUT.mkdir(parents=True, exist_ok=True)

spec = importlib.util.spec_from_file_location(
    "tcr", ROOT / "tests" / "test_collector_readonly.py"
)
tcr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tcr)

COLLECTOR_TEXT = tcr._collector_text()


def check(snippet: str) -> tuple[bool, list[str]]:
    p = OUT / "collector-plus.ps1"
    p.write_text(COLLECTOR_TEXT + "\n" + snippet + "\n", encoding="utf-8")
    dump = tcr._dump(p)
    v = tcr.violations(dump, p.read_text(encoding="utf-8"))
    return (len(v) > 0), v


CANDIDATES: dict[str, str] = {
    # --- redirection variants -------------------------------------------------
    "redir-out-file": "Write-Output 'x' > C:\\Windows\\evil.txt",
    "redir-append-file": "Write-Output 'x' >> C:\\Windows\\evil.txt",
    "redir-noclobber": "Write-Output 'x' >| C:\\Windows\\evil.txt",
    "redir-in-var": "$s = 'x' > C:\\Windows\\evil.txt",
    "redir-stderr-file": "certutil -getreg x 2> C:\\Windows\\evil.txt",
    "redir-to-unc": "Write-Output 'x' > \\\\remote\\share\\evil.txt",
    "redir-2gt-in-allowlisted-cmd": "certutil -getreg CA\\\\CommonName 2>$null",
    "redir-all-star": "Write-Output 'x' *> C:\\evil.txt",
    "redir-merge-2to1": "Write-Output 'x' 2>&1",
    "redir-3-to-null": "Write-Output 'x' 3>$null",
    "redir-1-to-null": "Write-Output 'x' 1>$null",
    # --- New-Item ------------------------------------------------------------
    "new-item-name-escape": "New-Item -ItemType Directory -Force -Path $OutDir -Name ..\\\\..\\\\Windows\\\\evil",
    "new-item-extra-value": "New-Item -ItemType Directory -Force -Path $OutDir -Value x",
    "new-item-path-file": "New-Item -ItemType File -Force -Path $OutDir",
    "new-item-path-file-outpath": "New-Item -ItemType Directory -Force -Path $outPath",
    # --- write-target indirection -------------------------------------------
    "indirect-write-var": "$x = $outPath\n[IO.File]::WriteAllText($x, 'evil')",
    "second-assign-outpath": "$outPath = 'C:\\\\Windows\\\\Temp\\\\evil.json'\n[IO.File]::WriteAllText($outPath, 'x')",
    "script-scope-outpath": "$script:outPath = 'C:\\\\evil.json'",
    "global-scope-certdir": "$global:certDir = 'C:\\\\evil'",
    "compound-certfile": "$certFile += '\\\\..\\\\..\\\\evil'",
    "foreach-rebind-certdir": "foreach ($certDir in @('C:\\\\evil')) { }",
    "ref-rebind-outpath": "$r = [ref]$outPath\n$r.Value = 'C:\\\\evil.json'",
    "writeallbytes-join-extra": "$certDir = Join-Path 'C:\\\\Windows' 'certs'",
    "writeallbytes-different-var": "[IO.File]::WriteAllBytes((Join-Path $certDir $certFile), $der)",
    "writeallbytes-filename-var": "$evil = '..\\\\..\\\\evil.cer'\n[IO.File]::WriteAllBytes((Join-Path $certDir $evil), $der)",
    "writeallbytes-name-only": "$certFile = '..\\\\..\\\\evil.cer'",
    "writealltext-via-file-accelerator": "[File]::WriteAllText($outPath, 'x')",
    "writealltext-dotnet-fullname": "[System.IO.File]::WriteAllText($outPath, 'x')",
    "writealltext-create": "[IO.File]::Create($outPath)",
    "writealltext-delete": "[IO.File]::Delete($outPath)",
    "writealltext-copy": "[IO.File]::Copy($outPath, 'C:\\\\evil.txt')",
    "writealltext-move": "[IO.File]::Move($outPath, 'C:\\\\evil.txt')",
    "writealltext-openwrite": "[IO.File]::OpenWrite('C:\\\\evil.txt')",
    "writealltext-appendalltext": "[IO.File]::AppendAllText('C:\\\\evil.txt', 'x')",
    # --- commands / pipelines -------------------------------------------------
    "splat-new-item": "$h = @{ ItemType='Directory'; Path='C:\\\\evil'; Force=$true }\nNew-Item @h",
    "splat-wmi": "$h = @{ Namespace='root\\\\default'; Class='StdRegProv'; List=$true; ComputerName='dc01' }\nGet-WmiObject @h",
    "set-content": "Set-Content -Path C:\\\\evil.txt -Value x",
    "add-content": "Add-Content -Path C:\\\\evil.txt -Value x",
    "out-file": "Write-Output x | Out-File C:\\\\evil.txt",
    "export-csv": "1 | Export-Csv C:\\\\evil.csv",
    "tee-object": "1 | Tee-Object -FilePath C:\\\\evil.txt",
    "copy-item": "Copy-Item $OutDir C:\\\\evil -Recurse",
    "remove-item": "Remove-Item C:\\\\Windows -Recurse",
    "start-transcript": "Start-Transcript C:\\\\evil.txt",
    "set-itemproperty": "Set-ItemProperty -Path HKLM:\\\\x -Name y -Value 1",
    "new-itemproperty": "New-ItemProperty -Path HKLM:\\\\x -Name y -Value 1",
    "remove-itemproperty": "Remove-ItemProperty -Path HKLM:\\\\x -Name y",
    "reg-add": "reg add HKLM\\\\Software\\\\x /v y /t REG_DWORD /d 1",
    "certutil-setreg-direct": "certutil -setreg policy\\\\EditFlags +X",
    "certutil-getreg-then-setreg": "certutil -getreg policy\\\\EditFlags -setreg policy\\\\EditFlags +X",
    "certutil-extra-key": "certutil -getreg $regpath CA\\\\Other",
    "certutil-two-keys": "certutil -getreg $regpath $other",
    "certutil-computer": "certutil -getreg -config dc01 policy\\\\EditFlags",
    "mkdir-alias": "mkdir C:\\\\evil",
    "ni-alias": "ni -ItemType Directory -Path C:\\\\evil",
    # --- dynamic invocation ---------------------------------------------------
    "amp-var": "$c = 'Set-Item'; & $c x",
    "amp-quoted-certutil": "& 'certutil' -getreg x",
    "dot-source": ". C:\\\\evil.ps1",
    "iex": "Invoke-Expression 'whoami'",
    "iex-alias": "iex 'whoami'",
    "scriptblock-create-invoke": "[scriptblock]::Create('x').Invoke()",
    "powershell-create-addscript": "[PowerShell]::Create().AddScript('x').Invoke()",
    "invoke-command": "Invoke-Command -ComputerName ca01 -ScriptBlock { 1 }",
    "invoke-command-splat": "$h=@{ComputerName='ca01';ScriptBlock={1}}\nInvoke-Command @h",
    "start-process": "Start-Process cmd.exe",
    "start-job": "Start-Job { 1 }",
    "register-scheduledtask": "Register-ScheduledTask -TaskName x -Action (1)",
    "import-module-arbitrary": "Import-Module Evil",
    "import-module-webadmin-cmdname-var": "Import-Module WebAdministration -ErrorAction Stop",
    # --- dynamic member -------------------------------------------------------
    "dynamic-member": "$m = 'CommitChanges'; $de.$m()",
    "dynamic-member-decompose": "$m = 'Set' + 'Info'; $de.$m()",
    "quoted-member": "$de.'CommitChanges'()",
    "member-put": "$de.Put('description','x')",
    "member-setinfo": "$de.SetInfo()",
    "member-commit": "$de.CommitChanges()",
    "properties-add": "$de.Properties['x'].Add('y')",
    "wmi-setdword": "$reg.SetDWORDValue(2147483650, 'k', 'v', 1)",
    "wmi-createkey": "$reg.CreateKey(2147483650, 'SOFTWARE\\\\x')",
    "registry-open-writable": "[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('x', $true)",
    "registry-createsubkey": "[Microsoft.Win32.Registry]::LocalMachine.CreateSubKey('x')",
    # --- ForEach-Object / Where-Object member dispatch ------------------------
    "foreach-member-setinfo": "$de | ForEach-Object -MemberName SetInfo",
    "foreach-member-arglist": "$de | ForEach-Object -MemberName Put -ArgumentList @('a','b')",
    "where-member": "$de | Where-Object -MemberName DeleteTree",
    "foreach-begin-process": "1 | ForEach-Object -Begin { } -Process { $_ }",
    "foreach-scriptblock-write": "1..2 | ForEach-Object { [IO.File]::WriteAllText('C:\\\\evil.txt','x') }",
    "foreach-scriptblock-newitem": "1..2 | ForEach-Object { New-Item -ItemType Directory -Path 'C:\\\\evil' }",
    # --- functions / scriptblocks defined then invoked ------------------------
    "function-write-elsewhere": "function evil { [IO.File]::WriteAllText('C:\\\\evil.txt','x') }\nevil",
    "function-destructive-cmd": "function evil { Remove-Item C:\\\\Windows -Recurse }\nevil",
    "function-ad-write": "function evil { $de = New-Object DirectoryServices.DirectoryEntry('LDAP://x'); $de.CommitChanges() }\nevil",
    "function-target-param": "function evil($p) { [IO.File]::WriteAllText($p,'x') }\nevil 'C:\\\\evil.txt'",
    "function-shadow-joinpath": "function Join-Path { 'C:\\\\evil' }\n[IO.File]::WriteAllText((Join-Path $OutDir $outName),'x')",
    "new-module": "New-Module -ScriptBlock { function f {} }",
    "using-namespace": "using namespace System.IO\n[File]::WriteAllText('C:\\\\evil.txt','x')",
    "add-type-typedef": "Add-Type -TypeDefinition 'public class X {}'",
    "add-type-language": "Add-Type -Language CSharp 'public class X {}'",
    "add-type-assembly": "Add-Type -AssemblyName System.Web.Extensions",
    # --- provider paths / registry -------------------------------------------
    "set-item-hklm": "Set-Item -Path HKLM:\\\\Software\\\\x -Value 1",
    "new-item-hklm": "New-Item -Path HKLM:\\\\Software\\\\x -Force",
    "get-item-hklm": "Get-Item -Path HKLM:\\\\Software\\\\x",
    "set-item-env": "Set-Item -Path Env:EVIL -Value 1",
    "set-location": "Set-Location C:\\\\Windows",
    "new-psdrive": "New-PSDrive -Name X -PSProvider FileSystem -Root C:\\\\evil",
    # --- remote host / ComputerName variants ---------------------------------
    "wmi-computername-literal": "$x = Get-WmiObject -Namespace 'root\\\\default' -Class StdRegProv -List -ComputerName 'dc01'",
    "wmi-computername-othervar": "$dcDns2 = $dcDns\nGet-WmiObject -Namespace 'root\\\\default' -Class StdRegProv -List -ComputerName $dcDns2",
    "wmi-computername-abbrev": "Get-WmiObject -Namespace 'root\\\\default' -Class StdRegProv -List -Comp $dcDns",
    "wmi-computername-colon": "Get-WmiObject -Namespace 'root\\\\default' -Class StdRegProv -List -ComputerName:$dcDns",
    "wmi-computername-cred-othervar": "Get-WmiObject -Namespace 'root\\\\default' -Class StdRegProv -List -ComputerName $dcDns -Credential $other",
    "wmi-computername-dup": "Get-WmiObject -Namespace 'root\\\\default' -Class StdRegProv -List -ComputerName $dcDns -ComputerName $evil",
    # --- scope / variable ------------------------------------------------
    "set-variable": "Set-Variable -Name outPath -Value 'C:\\\\evil'",
    "new-variable": "New-Variable -Name outPath -Value 'C:\\\\evil'",
    "outvariable": "_decode 1 $NAME_FLAGS -OutVariable outPath",
    "outvariable-write": "_writeJson @{} 'a.json' -OutVariable outPath",
    "null-reassign": "$null = 'C:\\\\evil.txt'",
    "outdir-reassign": "$OutDir = 'C:\\\\evil'",
    "outname-reassign": "$outName = 'evil.json'",
    # --- _writeJson escapes ---------------------------------------------------
    "writejson-traversal": "_writeJson @{} '..\\\\..\\\\evil.json'",
    "writejson-absolute": "_writeJson @{} 'C:\\\\evil.json'",
    "writejson-var": "$n = 'evil.json'\n_writeJson @{} $n",
    "writejson-subdir-safe": "_writeJson @{} 'certs/index.json'",
    "writejson-param": "_writeJson @{} 'a.json' -Verbose",
    # --- misc AD / CA --------------------------------------------------------
    "adobject-set": "Set-ADObject -Identity 'x' -Replace @{a=1}",
    "adsi-put": "[ADSI]'LDAP://x'.Put('description','x')",
    "adsi-setinfo": "[ADSI]'LDAP://x'.SetInfo()",
    "directoryentry-setvalue": "(New-Object DirectoryServices.DirectoryEntry('LDAP://x')).Properties['x'].Value = 'y'",
    "ca-setreg-wmi": "$reg.SetStringValue(2147483650, 'k', 'v', 'x')",
    "invoke-wmimethod": "Invoke-WmiMethod -Class StdRegProv -Name SetDWORDValue",
    "invoke-cimmethod": "Invoke-CimMethod -ClassName StdRegProv -MethodName SetDWORDValue",
    "get-wmi-then-setmember": "$reg = Get-WmiObject -Namespace 'root\\\\default' -Class StdRegProv -List\n$reg | ForEach-Object -MemberName SetDWORDValue -ArgumentList @(1,'k','v',1)",
}


def main() -> int:
    bypasses = []
    flagged = []
    for name, snip in CANDIDATES.items():
        try:
            ok, v = check(snip)
        except Exception as exc:  # noqa: BLE001
            print(f"DUP-check-error {name}: {exc}")
            continue
        if ok:
            flagged.append(name)
            print(f"FLAGGED {name}")
        else:
            bypasses.append(name)
            print(f"BYPASS  {name}   :: {snip!r}")
    print(f"\n=== {len(flagged)} flagged, {len(bypasses)} BYPASS of {len(CANDIDATES)} ===")
    for b in bypasses:
        print("BYPASS:", b)
    return 0


if __name__ == "__main__":
    sys.exit(main())
