"""The collector is read-only: enforced by an ALLOWLIST over its parsed AST.

``scripts/Export-AdcsEstate.ps1`` runs on a CA / tier-0 box with privileged
credentials, so "read-only" must be a checked property, not a comment. This
test asks pwsh to *parse* the script (``[Parser]::ParseFile`` — nothing in it
executes; see ``tests/collector/Get-ScriptInvocations.ps1``) and fails on any
command invocation, .NET member invocation, ``New-Object`` type, or static type
that is not explicitly allowed below. It is an allowlist, not a denylist: a
new call of any kind fails until someone reviews it and adds it here with a
reason.

Write-capable surfaces and how they are handled:

* AD writes (``Set-AD*``, ``New-AD*``, ``Remove-AD*``, ``DirectoryEntry
  .CommitChanges``, ``.Properties[...].Add``): not allowlisted. ``Add`` is
  allowed only on ``DirectorySearcher.PropertiesToLoad`` (a query projection).
* CA config writes (``certutil -setreg`` / any non ``-getreg`` verb): every
  ``certutil`` invocation must be ``certutil -getreg ...``.
* Registry writes: ``Microsoft.Win32.Registry...OpenSubKey`` is allowed only
  with the 1-argument (read-only) overload; ``Set-ItemProperty`` /
  ``New-ItemProperty`` / WMI ``Set*Value`` are not allowlisted. WMI is allowed
  only as ``Get-WmiObject -Class StdRegProv -List`` + ``GetDWORDValue``.
* Remote execution (``Invoke-Command``, ``Enter-PSSession``,
  ``Invoke-Expression``, ``Start-Process``, ``& $computed``): not allowlisted;
  any invocation whose command name is computed at runtime is a violation.
* **Local file writes are allowed only into the output directory**: the
  ``[IO.File]::WriteAll*`` calls must take ``$p`` (``_writeJson``, where
  ``$p = Join-Path $OutDir $name``) or ``(Join-Path $certDir $file)`` (where
  ``$certDir = Join-Path $OutDir 'certs'``), and ``New-Item`` may only create a
  directory at ``$OutDir`` / ``$dir`` / ``$certDir``. Those defining
  assignments are pinned below.

PowerShell 5.1: the collector must run on Windows PowerShell 5.1, so this test
never executes it — it only parses it (here with pwsh 7). Parsing with 7 does
not prove 5.1 compatibility; the ``collector-windows`` CI job additionally
parses the script with Windows PowerShell 5.1 and fails on any parse error.

Out of scope: ``scripts/install-windows.ps1`` and ``scripts/uninstall-windows.ps1``
run on the *analysis* host (they create/remove a local venv and are expected to
write there); they never run on a CA and never touch AD CS, so they are not
held to the collector's read-only contract.

``pwsh`` is required. Locally the test skips without it; under CI (``CI`` set)
a missing pwsh is a failure, not a skip.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parent.parent
COLLECTOR = ROOT / "scripts" / "Export-AdcsEstate.ps1"
DUMPER = ROOT / "tests" / "collector" / "Get-ScriptInvocations.ps1"


def _pwsh() -> str:
    exe = shutil.which("pwsh")
    if exe is None:
        if os.environ.get("CI"):
            pytest.fail("pwsh is required in CI for the collector read-only check")
        pytest.skip("pwsh not installed")
    return exe


def _dump(script: Path) -> dict[str, Any]:
    out = subprocess.run(
        [_pwsh(), "-NoProfile", "-NonInteractive", "-File", str(DUMPER), "-Path", str(script)],
        capture_output=True,
        text=True,
        timeout=120,
        check=True,
    )
    data: dict[str, Any] = json.loads(out.stdout)
    return data


def _arg_after(args: list[str], flag: str) -> str | None:
    lowered = [a.lower() for a in args]
    if flag.lower() in lowered:
        i = lowered.index(flag.lower())
        return args[i + 1] if i + 1 < len(args) else None
    return None


# --- the allowlist ---------------------------------------------------------------

Check = Callable[[dict[str, Any]], str | None]  # returns a violation reason or None


def _certutil(c: dict[str, Any]) -> str | None:
    if not c["args"] or c["args"][0].lower() != "-getreg":
        return "certutil may only be invoked as 'certutil -getreg'"
    return None


def _new_item(c: dict[str, Any]) -> str | None:
    if (_arg_after(c["args"], "-ItemType") or "").lower() != "directory":
        return "New-Item may only create directories"
    if _arg_after(c["args"], "-Path") not in {"$OutDir", "$dir", "$certDir"}:
        return "New-Item may only target the output directory ($OutDir / $dir / $certDir)"
    return None


_NEW_OBJECT_TYPES = {
    # LDAP read plumbing (no CommitChanges anywhere — see member allowlist).
    "DirectoryServices.DirectoryEntry",
    "DirectoryServices.DirectorySearcher",
    # In-memory security-descriptor decoders.
    "DirectoryServices.ActiveDirectorySecurity",
    "Security.AccessControl.RawSecurityDescriptor",
    "Security.Cryptography.X509Certificates.X509Certificate2",
    # Credential object for the opt-in WMI registry read.
    "Management.Automation.PSCredential",
    # JSON + encoding for writing the export.
    "System.Web.Script.Serialization.JavaScriptSerializer",
    "Text.UTF8Encoding",
}


def _new_object(c: dict[str, Any]) -> str | None:
    type_name = re.split(r"[\s(]", c["args"][0], maxsplit=1)[0] if c["args"] else ""
    if type_name not in _NEW_OBJECT_TYPES:
        return f"New-Object type {type_name!r} is not allowlisted"
    return None


def _wmi(c: dict[str, Any]) -> str | None:
    args = c["args"]
    if _arg_after(args, "-Class") != "StdRegProv" or "-List" not in args:
        return "Get-WmiObject is allowed only as '-Class StdRegProv -List' (registry read)"
    if _arg_after(args, "-Namespace") != "'root\\default'":
        return "Get-WmiObject is allowed only in root\\default"
    return None


def _fixed(expected: list[str]) -> Check:
    return lambda c: None if c["args"] == expected else f"only {expected} is allowed"


def _ok(c: dict[str, Any]) -> str | None:
    return None


ALLOWED_COMMANDS: dict[str, Check] = {
    "certutil": _certutil,
    "New-Item": _new_item,
    "New-Object": _new_object,
    "Get-WmiObject": _wmi,
    "Import-Module": _fixed(["WebAdministration", "-ErrorAction", "Stop"]),
    "Add-Type": _fixed(["-AssemblyName", "System.Web.Extensions"]),
    # Read-only IIS configuration queries (ESC8 pass).
    "Get-Website": _ok,
    "Get-WebApplication": _ok,
    "Get-WebConfigurationProperty": _ok,
    # Pure pipeline / path / output helpers.
    "ForEach-Object": _ok,
    "Where-Object": _ok,
    "Select-Object": _ok,
    "Join-Path": _ok,
    "Split-Path": _ok,
    "Test-Path": _ok,
    "Get-Date": _ok,
    "Out-Null": _ok,
    "Write-Host": _ok,
    "Write-Output": _ok,
    "Write-Warning": _ok,
    "ConvertTo-SecureString": _ok,  # builds the opt-in WMI credential in memory
    "hostname": _ok,
}

# (static type expression, member)
ALLOWED_STATIC: set[tuple[str, str]] = {
    ("[Convert]", "FromBase64String"),
    ("[Convert]", "ToInt64"),
    ("[System.Net.Dns]", "GetHostEntry"),
    ("[IO.File]", "WriteAllText"),
    ("[IO.File]", "WriteAllBytes"),
}
# Every allowed WriteAll* call writes into the output directory.
ALLOWED_WRITE_TARGETS = {"$p", "(Join-Path $certDir $file)"}
PINNED_OUTPUT_PATHS = (
    "$p = Join-Path $OutDir $name",
    "$certDir = Join-Path $OutDir 'certs'",
)


def _open_sub_key(m: dict[str, Any]) -> str | None:
    return None if m["argc"] == 1 else "OpenSubKey must use the read-only (1-argument) overload"


def _properties_to_load(m: dict[str, Any]) -> str | None:
    if m["target"].endswith(".PropertiesToLoad"):
        return None
    return "Add is allowed only on DirectorySearcher.PropertiesToLoad"


ALLOWED_INSTANCE: dict[str, Check] = {
    # string / collection helpers
    "ToLower": _ok,
    "Trim": _ok,
    "TrimStart": _ok,
    "Replace": _ok,
    "StartsWith": _ok,
    "ToString": _ok,
    "ToUniversalTime": _ok,
    "GetString": _ok,
    "GetEnumerator": _ok,
    "ContainsKey": _ok,
    "Serialize": _ok,  # JavaScriptSerializer -> JSON text
    # LDAP reads
    "FindAll": _ok,
    "FindOne": _ok,
    "Add": _properties_to_load,
    # In-memory security-descriptor decoding (ActiveDirectorySecurity object
    # built by New-Object; nothing is written back to AD).
    "SetSecurityDescriptorBinaryForm": _ok,
    "GetAccessRules": _ok,
    "GetOwner": _ok,
    "Translate": _ok,  # SID <-> NTAccount name lookup
    # Local registry read (CA\Security) and WMI StdRegProv read (DC values).
    "OpenSubKey": _open_sub_key,
    "GetValue": _ok,
    "GetDWORDValue": _ok,
}

ALLOWED_STATIC_TYPES = {
    "bool", "byte[]", "int", "string", "switch", "uint32", "void", "ordered",
    "Convert", "IO.File", "System.Net.Dns", "Text.Encoding", "Microsoft.Win32.Registry",
    "DirectoryServices.DirectoryEntry", "DirectoryServices.SecurityMasks",
    "Security.Principal.NTAccount", "Security.Principal.SecurityIdentifier",
}


def violations(dump: dict[str, Any], source: str) -> list[str]:
    out = [f"parse error {e}" for e in dump["parse_errors"]]
    defined = set(dump["functions"])
    for c in dump["commands"]:
        where = f"line {c['line']}: {c['text']}"
        name = c["name"]
        if name is None or not c["bareword"]:
            out.append(f"{where}: dynamic invocation (command name computed at runtime)")
            continue
        if name in defined:
            continue
        check = ALLOWED_COMMANDS.get(name)
        if check is None:
            out.append(f"{where}: command {name!r} is not allowlisted")
            continue
        reason = check(c)
        if reason:
            out.append(f"{where}: {reason}")
    for m in dump["members"]:
        where = f"line {m['line']}: {m['text']}"
        if not m["constant_member"]:
            out.append(f"{where}: dynamic member invocation")
            continue
        if m["static"]:
            if (m["target"], m["member"]) not in ALLOWED_STATIC:
                out.append(f"{where}: static call {m['target']}::{m['member']} not allowlisted")
            elif m["member"].startswith("WriteAll") and (
                not m["args"] or m["args"][0] not in ALLOWED_WRITE_TARGETS
            ):
                out.append(f"{where}: file write outside the output directory")
            continue
        check = ALLOWED_INSTANCE.get(m["member"])
        if check is None:
            out.append(f"{where}: method {m['member']!r} is not allowlisted")
            continue
        reason = check(m)
        if reason:
            out.append(f"{where}: {reason}")
    for t in dump["static_types"]:
        if t not in ALLOWED_STATIC_TYPES:
            out.append(f"type literal [{t}] is not allowlisted")
    if any(m["static"] and m["member"].startswith("WriteAll") for m in dump["members"]):
        for pinned in PINNED_OUTPUT_PATHS:
            if pinned not in source:
                out.append(f"output path definition changed: expected {pinned!r}")
    return out


# --- tests -------------------------------------------------------------------------


def test_collector_is_read_only() -> None:
    dump = _dump(COLLECTOR)
    found = violations(dump, COLLECTOR.read_text(encoding="utf-8"))
    assert found == [], "collector read-only allowlist violations:\n" + "\n".join(found)
    # Sanity: the dump actually saw the collector's surface.
    names = {c["name"] for c in dump["commands"]}
    assert {"certutil", "Get-WmiObject", "New-Object"} <= names


def test_allowlist_has_no_stale_entries() -> None:
    """Every allowlisted command / method is still used — keep the list honest."""
    dump = _dump(COLLECTOR)
    used_cmds = {c["name"] for c in dump["commands"]}
    used_members = {m["member"] for m in dump["members"] if not m["static"]}
    used_static = {(m["target"], m["member"]) for m in dump["members"] if m["static"]}
    assert set(ALLOWED_COMMANDS) - used_cmds == set()
    assert set(ALLOWED_INSTANCE) - used_members == set()
    assert ALLOWED_STATIC - used_static == set()


_BAD_SNIPPETS = {
    "set-adobject": "Set-ADObject -Identity 'x' -Replace @{a=1}",
    "new-aduser": "New-ADUser -Name x",
    "remove-adobject": "Remove-ADObject -Identity x",
    "certutil-setreg": "certutil -setreg policy\\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2",
    "commit-changes": (
        "$de = New-Object DirectoryServices.DirectoryEntry('LDAP://x'); $de.CommitChanges()"
    ),
    "properties-add": "$de.Properties['x'].Add('y')",
    "invoke-command": "Invoke-Command -ComputerName ca01 -ScriptBlock { 1 }",
    "invoke-expression": "Invoke-Expression 'whoami'",
    "dynamic-call": "$c = 'Set-Item'; & $c x",
    "dynamic-member": "$m = 'CommitChanges'; $de.$m()",
    "wmi-set": "$reg.SetDWORDValue(2147483650, 'k', 'v', 1)",
    "registry-writable": "[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('x', $true)",
    "set-itemproperty": "Set-ItemProperty -Path HKLM:\\x -Name y -Value 1",
    "file-write-elsewhere": "[IO.File]::WriteAllText('C:\\Windows\\x.txt', 'y')",
    "new-item-elsewhere": "New-Item -ItemType Directory -Path C:\\Windows\\x",
    "start-process": "Start-Process cmd.exe",
    "new-object-com": "New-Object -ComObject WScript.Shell",
}


@pytest.mark.parametrize("snippet", list(_BAD_SNIPPETS.values()), ids=list(_BAD_SNIPPETS))
def test_checker_flags_write_capable_surface(tmp_path: Path, snippet: str) -> None:
    """Prove the checker is not vacuous: each write-capable form is reported."""
    script = tmp_path / "bad.ps1"
    script.write_text(snippet + "\n", encoding="utf-8")
    assert violations(_dump(script), snippet), f"not flagged: {snippet}"
