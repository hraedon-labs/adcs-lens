# ruff: noqa: E501  (the regression tables hold literal PowerShell)
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
* **Local file writes are allowed only into the output directory**, checked
  on the AST (comments cannot satisfy it): ``[IO.File]::WriteAllText`` must
  take ``$outPath`` and ``WriteAllBytes`` ``(Join-Path $certDir $certFile|
  $crlFile)``; ``New-Item`` only ``-ItemType Directory -Force -Path`` one of
  ``$OutDir`` / ``$outParent`` / ``$certDir``. Each of those variables must have
  exactly the expected assignments in the whole script (any scope, compound
  operators and foreach loop variables included) — ``$outPath = Join-Path
  $OutDir $outName``, ``$outParent = Split-Path $outPath -Parent``,
  ``$certDir = Join-Path $OutDir 'certs'``, and one sanitised file-name format
  each for ``$certFile`` / ``$crlFile``. ``$OutDir`` and ``$outName`` are
  parameters that are never assigned, and every ``_writeJson`` call passes a
  plain relative literal name. ``[ref]``, ``Set-Variable`` / ``New-Variable``
  and ``-OutVariable``-style common parameters are not allowlisted.
* **Redirections**: the only one allowed is ``2>$null`` (discarding certutil's
  stderr). Any other ``>`` / ``>>`` / ``>|`` / ``n>`` / ``n>&1`` is a violation.
* **Member dispatch through cmdlets**: ``ForEach-Object`` / ``Where-Object``
  must take exactly one script block (no ``-MemberName``, ``-ArgumentList`` or
  positional member names), and every allowed cmdlet has an exact argument
  vector (e.g. ``Get-WmiObject`` only in its three StdRegProv ``-List`` forms,
  ``certutil`` only as ``-getreg <one key>``, ``New-Item`` without ``-Name``).

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
import sys
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


# --- the allowlist ---------------------------------------------------------------

Check = Callable[[dict[str, Any]], str | None]  # returns a violation reason or None


def _ok(c: dict[str, Any]) -> str | None:
    return None


def _exact(*vectors: list[str]) -> Check:
    """Allow only these exact argument vectors (parameters and values, in order)."""
    allowed = [list(v) for v in vectors]

    def check(c: dict[str, Any]) -> str | None:
        if c["args"] in allowed:
            return None
        return f"arguments {c['args']} are not one of the allowed vectors {allowed}"

    return check


def _one_scriptblock(c: dict[str, Any]) -> str | None:
    els = c["elements"]
    if len(els) == 1 and els[0]["kind"] == "ScriptBlockExpressionAst":
        return None
    # -MemberName / -ArgumentList / a positional member name turn ForEach-Object
    # into a generic method dispatcher ($de | ForEach-Object -MemberName SetInfo).
    return "only a single script-block argument is allowed (no member dispatch)"


def _positional(count: int) -> Check:
    def check(c: dict[str, Any]) -> str | None:
        els = c["elements"]
        if len(els) == count and not any(e["parameter"] is not None for e in els):
            return None
        return f"exactly {count} positional argument(s) and no parameters are allowed"

    return check


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
    els = c["elements"]
    if any(e["parameter"] is not None for e in els):
        return "New-Object may not take parameters (-ComObject, -TypeName, -Property, ...)"
    type_name = re.split(r"[\s(]", c["args"][0], maxsplit=1)[0] if c["args"] else ""
    if type_name not in _NEW_OBJECT_TYPES:
        return f"New-Object type {type_name!r} is not allowlisted"
    return None


_WMI_READ = ["-Namespace", "'root\\default'", "-Class", "StdRegProv", "-List"]
_WEBCFG_PARAMS = {"pspath", "filter", "name", "erroraction"}  # lower-cased by the dumper


def _web_config(c: dict[str, Any]) -> str | None:
    params = [e["parameter"] for e in c["elements"] if e["parameter"] is not None]
    if sorted(params) == sorted(_WEBCFG_PARAMS) and len(c["elements"]) == 2 * len(params):
        return None
    return f"Get-WebConfigurationProperty may only take {sorted(_WEBCFG_PARAMS)}"


ALLOWED_COMMANDS: dict[str, Check] = {
    # certutil only reads: `certutil -getreg <one key>`.
    "certutil": _exact(["-getreg", "$regpath"], ["-getreg", "CA\\CommonName"]),
    "New-Item": _exact(
        *(["-ItemType", "Directory", "-Force", "-Path", p]
          for p in ("$OutDir", "$outParent", "$certDir"))
    ),
    "New-Object": _new_object,
    # WMI only to obtain the StdRegProv class (local, or on a DC for the opt-in
    # esc10 pass); the only methods then allowed on it are reads (GetDWORDValue).
    "Get-WmiObject": _exact(
        _WMI_READ,
        ["-ComputerName", "$dcDns", *_WMI_READ],
        ["-ComputerName", "$dcDns", "-Credential", "$dcCred", *_WMI_READ],
    ),
    "Import-Module": _exact(["WebAdministration", "-ErrorAction", "Stop"]),
    "Add-Type": _exact(["-AssemblyName", "System.Web.Extensions"]),
    # Read-only IIS configuration queries (ESC8 pass).
    "Get-Website": _exact([]),
    "Get-WebApplication": _exact(["-Site", "$site.Name"]),
    "Get-WebConfigurationProperty": _web_config,
    # Pipeline helpers: script blocks only (their bodies are analysed too).
    "ForEach-Object": _one_scriptblock,
    "Where-Object": _one_scriptblock,
    "Select-Object": _exact(["-First", "1"]),
    # Path / output helpers.
    "Join-Path": _positional(2),
    "Split-Path": _exact(["$outPath", "-Parent"]),
    "Test-Path": _exact(["$outParent"]),
    "Get-Date": _exact([]),
    "Out-Null": _exact([]),
    "hostname": _exact([]),
    "Write-Host": _positional(1),
    "Write-Output": _positional(1),
    "Write-Warning": _positional(1),
    # Builds the opt-in WMI credential in memory.
    "ConvertTo-SecureString": _exact(["$DcRegistryPass", "-AsPlainText", "-Force"]),
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
ALLOWED_WRITE_TARGETS = {
    "WriteAllText": {"$outPath"},
    "WriteAllBytes": {"(Join-Path $certDir $certFile)", "(Join-Path $certDir $crlFile)"},
}
# PINNED variables: the complete set of bindings each may have anywhere in the
# script — assignments (any operator, any scope), foreach loop variables,
# function / script-block / script parameters, and common-parameter writes —
# compared on the lower-cased name, because PowerShell resolves names
# case-insensitively. Any extra binding (a same-name parameter shadowing it, a
# `$OUTPATH = ...`, a `$global:outPath = ...`) is a violation. These are the
# write-path variables and the remote-host / credential provenance for WMI.
_SCRIPT = "<script>"
PINNED_BINDINGS: dict[str, list[tuple[str, str, str]]] = {
    "outdir": [("parameter", _SCRIPT, "")],
    "outname": [("parameter", "_writeJson", "")],
    "outpath": [("assign Equals", "_writeJson", "Join-Path $OutDir $outName")],
    "outparent": [("assign Equals", "_writeJson", "Split-Path $outPath -Parent")],
    "certdir": [("assign Equals", _SCRIPT, "Join-Path $OutDir 'certs'")],
    "certfile": [("assign Equals", _SCRIPT, "'{0:d2}-{1}.cer' -f $i, (_safeFileName $cn)")],
    "crlfile": [("assign Equals", _SCRIPT, "'{0:d2}-{1}.crl' -f $j, (_safeFileName $cn)")],
    # The only remote host WMI may reach: a DC's dNSHostName from the DC search.
    "dcdns": [("assign Equals", _SCRIPT, "[string]$r.Properties['dnshostname'][0]")],
    "dccred": [
        ("assign Equals", _SCRIPT, "$null"),
        ("assign Equals", _SCRIPT,
         "New-Object Management.Automation.PSCredential( $DcRegistryUser, "
         "(ConvertTo-SecureString $DcRegistryPass -AsPlainText -Force))"),
    ],
    # The StdRegProv handle whose only allowed method is GetDWORDValue.
    "reg": [
        ("assign Equals", _SCRIPT,
         "Get-WmiObject -Namespace 'root\\default' -Class StdRegProv -List"),
        ("assign Equals", _SCRIPT,
         "Get-WmiObject -ComputerName $dcDns -Credential $dcCred -Namespace "
         "'root\\default' -Class StdRegProv -List"),
        ("assign Equals", _SCRIPT,
         "Get-WmiObject -ComputerName $dcDns -Namespace 'root\\default' -Class StdRegProv -List"),
    ],
}
# Automatic variables a member call may use as its receiver without a binding.
_AUTOMATIC_RECEIVERS = {"_", "matches"}
_SAFE_OUTPUT_NAME = re.compile(r"'(?:[A-Za-z0-9_-]+/)?[A-Za-z0-9_-]+\.json'")
# The only redirection: certutil's stderr discarded.
ALLOWED_REDIRECTIONS = {("FileRedirectionAst", "Error", "$null", False)}


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


def violations(dump: dict[str, Any], source: str = "") -> list[str]:
    """Every semantic violation in a parsed script (empty = read-only).

    Each message starts with the [check] that raised it.
    """
    out = [f"[parse] {e}" for e in dump["parse_errors"]]
    defined = {f["name"].lower() for f in dump["functions"]}
    bound = {b["variable"] for b in dump["bindings"] if b["variable"]}
    for c in dump["commands"]:
        where = f"{c['scope']}: {c['text']}"
        name = c["name"]
        if name is None or not c["bareword"]:
            out.append(f"[dynamic] {where}: command name computed at runtime")
            continue
        if name.lower() in defined:
            if name == "_writeJson":
                vals = [e["text"] for e in c["elements"] if e["parameter"] is None]
                if len(vals) != 2 or not _SAFE_OUTPUT_NAME.fullmatch(vals[1]):
                    out.append(f"[write-path] {where}: _writeJson must take a plain relative name")
            if any(e["parameter"] is not None for e in c["elements"]):
                out.append(f"[command] {where}: parameters on a script function are not allowed")
            continue
        check = ALLOWED_COMMANDS.get(name)
        if check is None:
            out.append(f"[command] {where}: command {name!r} is not allowlisted")
            continue
        reason = check(c)
        if reason:
            tag = "[write-path]" if name == "New-Item" else "[command]"
            out.append(f"{tag} {where}: {reason}")
    for b in dump["bindings"]:
        if b["kind"] == "common-parameter":
            out.append(
                f"[common-parameter] {b['scope']}: {b['value']} writes ${b['variable']}"
            )
    for m in dump["members"]:
        where = f"{m['scope']}: {m['text']}"
        if not m["constant_member"]:
            out.append(f"[dynamic] {where}: dynamic member invocation")
            continue
        if m["static"]:
            if (m["target"], m["member"]) not in ALLOWED_STATIC:
                out.append(f"[member] {where}: static {m['target']}::{m['member']} not allowlisted")
            elif m["member"] in ALLOWED_WRITE_TARGETS and (
                not m["args"] or m["args"][0] not in ALLOWED_WRITE_TARGETS[m["member"]]
            ):
                out.append(f"[write-path] {where}: file write outside the output directory")
            continue
        root = m["receiver_root"]
        if root is not None and root not in bound and root not in _AUTOMATIC_RECEIVERS:
            out.append(f"[receiver] {where}: receiver ${root} has no binding in the script")
        check = ALLOWED_INSTANCE.get(m["member"])
        if check is None:
            out.append(f"[member] {where}: method {m['member']!r} is not allowlisted")
            continue
        reason = check(m)
        if reason:
            out.append(f"[member] {where}: {reason}")
    for r in dump["redirections"]:
        if (r["kind"], r["stream"], r["location"], r["append"]) not in ALLOWED_REDIRECTIONS:
            out.append(f"[redirection] {r['scope']}: {r['text']!r} is not allowed")
    for var, expected in PINNED_BINDINGS.items():
        got = sorted(
            (b["kind"], b["scope"], b["value"]) for b in dump["bindings"] if b["variable"] == var
        )
        if got != sorted(expected):
            out.append(f"[pinned-binding] ${var} must be bound exactly as {sorted(expected)}, got {got}")
    for t in dump["static_types"]:
        if t not in ALLOWED_STATIC_TYPES:
            out.append(f"[type] [{t}] is not allowlisted")
    return out


# --- golden call-site inventory (closed world) ------------------------------------
# Everything the gate reasons about, normalised (no line numbers, sorted), is
# committed in tests/collector/collector-inventory.json. ANY difference fails:
# a new or changed call, argument, receiver, binding, redirection, type or
# function cannot land without the inventory diff appearing in review.
# Regenerate (only possible when every semantic check passes):
#   .venv/bin/python tests/collector/regen_inventory.py
INVENTORY = ROOT / "tests" / "collector" / "collector-inventory.json"


def inventory(dump: dict[str, Any]) -> dict[str, list[Any]]:
    def strip(entries: list[dict[str, Any]], drop: tuple[str, ...] = ("text",)) -> list[Any]:
        cleaned = [{k: v for k, v in e.items() if k not in drop} for e in entries]
        return sorted(cleaned, key=lambda e: json.dumps(e, sort_keys=True))

    return {
        "commands": strip(dump["commands"], ("text", "args")),
        "members": strip(dump["members"], ("text",)),
        "redirections": strip(dump["redirections"], ("text",)),
        "bindings": strip(dump["bindings"], ()),
        "functions": strip(dump["functions"], ()),
        "types": sorted(dump["static_types"]),
    }


def render_inventory(dump: dict[str, Any]) -> str:
    return json.dumps(inventory(dump), indent=1, sort_keys=True) + "\n"


# --- tests -------------------------------------------------------------------------


def test_collector_is_read_only() -> None:
    dump = _dump(COLLECTOR)
    found = violations(dump, COLLECTOR.read_text(encoding="utf-8"))
    assert found == [], "collector read-only allowlist violations:\n" + "\n".join(found)
    # Sanity: the dump actually saw the collector's surface.
    names = {c["name"] for c in dump["commands"]}
    assert {"certutil", "Get-WmiObject", "New-Object"} <= names


def test_collector_matches_golden_inventory() -> None:
    """Closed world: the collector's whole call-site surface is pinned."""
    current = render_inventory(_dump(COLLECTOR))
    golden = INVENTORY.read_text(encoding="utf-8")
    assert current == golden, (
        "the collector's call-site inventory changed; review the change and, if it "
        "is read-only, regenerate with: .venv/bin/python tests/collector/regen_inventory.py"
    )


def test_regeneration_refuses_a_failing_collector(tmp_path: Path) -> None:
    bad = tmp_path / "bad.ps1"
    bad.write_text(_collector_text() + "\n$OUTPATH = 'C:\\evil'\n", encoding="utf-8")
    out = tmp_path / "inv.json"
    script = ROOT / "tests" / "collector" / "regen_inventory.py"
    proc = subprocess.run(
        [sys.executable, str(script), "--collector", str(bad), "--out", str(out)],
        capture_output=True, text=True, timeout=180,
    )
    assert proc.returncode == 1, proc.stderr
    assert "refusing to write" in proc.stderr and "[pinned-binding]" in proc.stderr
    assert not out.exists()


def test_pinned_variables_are_really_used() -> None:
    """Every pinned variable exists in the collector (no stale pins)."""
    bound = {b["variable"] for b in _dump(COLLECTOR)["bindings"]}
    assert set(PINNED_BINDINGS) <= bound


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
    # --- review round 1: Sol's six reproduced bypasses -----------------------
    "sol-remote-wmi-foreach-member": (
        "$reg = Get-WmiObject -List -Namespace 'root\\default' -Class StdRegProv "
        "-ComputerName 'dc01'\n"
        "$reg | ForEach-Object -MemberName SetDWORDValue -ArgumentList "
        "@(2147483650, 'SOFTWARE\\AdcsLensProbe', 'Pwned', 1)"
    ),
    "sol-ad-foreach-member": (
        "$de = New-Object DirectoryServices.DirectoryEntry('LDAP://CN=x,DC=example,DC=test')\n"
        "$de | ForEach-Object -MemberName Put -ArgumentList @('description', 'owned')\n"
        "$de | ForEach-Object -MemberName SetInfo"
    ),
    "sol-registry-foreach-member": (
        "$rk = [Microsoft.Win32.Registry]::LocalMachine | ForEach-Object -MemberName "
        "CreateSubKey -ArgumentList 'SOFTWARE\\AdcsLensProbe'\n"
        "$rk | ForEach-Object -MemberName SetValue -ArgumentList @('Pwned', 1)"
    ),
    "sol-mutated-file-target": (
        "$p = 'C:\\Windows\\Temp\\adcs-lens-probe.txt'\n[IO.File]::WriteAllText($p, 'owned')"
    ),
    "sol-mutated-directory-target": (
        "$dir = 'C:\\Windows\\Temp\\adcs-lens-probe-dir'\n"
        "New-Item -ItemType Directory -Path $dir"
    ),
    "sol-redirection": "$payload = 'owned'\n$payload > 'C:\\Windows\\Temp\\adcs-lens-probe.txt'",
    # --- review round 1: DeepSeek B1 (redirections) ----------------------------
    "ds-redirect-out-file": "Write-Output 'x' > C:\\Windows\\evil.txt",
    "ds-redirect-append-file": "Write-Output 'x' >> C:\\Windows\\evil.txt",
    "ds-redirect-noclobber": "Write-Output 'x' >| C:\\Windows\\evil.txt",
    "ds-redirect-in-var": "$s = 'x' > C:\\Windows\\evil.txt",
    "ds-redirect-stderr": "certutil -getreg x 2> C:\\Windows\\evil.txt",
    "ds-redirect-to-unc": "Write-Output 'x' > \\\\remote\\share\\evil.txt",
    "ds-redirect-only-in-pipeline": "1..3 | ForEach-Object { $_ } > C:\\evil.txt",
    "ds-redirect-merge": "Write-Output 'x' 2>&1",
    # --- DeepSeek B2: a second assignment repoints a write target ---------------
    "ds-second-assignment-outpath": (
        "$outPath = 'C:\\Windows\\Temp\\evil.json'\n"
        "[IO.File]::WriteAllText($outPath, 'x')"
    ),
    "ds-second-assignment-certdir": "$certDir = 'C:\\Windows\\Temp'",
    "ds-script-scope-assignment": "$script:outParent = 'C:\\Windows\\Temp'",
    "ds-compound-assignment": "$certFile += '\\..\\..\\evil'",
    "ds-foreach-rebinds-target": "foreach ($crlFile in @('..\\..\\evil')) { }",
    "ds-ref-rebinds-target": "$r = [ref]$outPath",
    "ds-set-variable": "Set-Variable -Name outPath -Value 'C:\\evil'",
    "ds-outvariable": "_decode 1 $NAME_FLAGS -OutVariable outPath",
    "ds-writejson-escape": "_writeJson @{} '..\\..\\evil.json'",
    # --- DeepSeek B3: New-Item -Name escapes the output directory ---------------
    "ds-new-item-name-escape": (
        "New-Item -ItemType Directory -Force -Path $OutDir -Name ..\\..\\Windows\\evil"
    ),
    # --- DeepSeek N1: certutil with a trailing -setreg ---------------------------
    "ds-certutil-getreg-then-setreg": (
        "certutil -getreg policy\\EditFlags -setreg policy\\EditFlags +X"
    ),
    "certutil-extra-key": "certutil -getreg $regpath CA\\Other",
}

# Replacement mutations of the real collector (the pin must be the AST, not text).
_REPLACEMENTS = {
    # DeepSeek B2: keep the old pin text as a comment, repoint the real assignment.
    "ds-pin-as-comment-then-repoint": (
        "  $outPath = Join-Path $OutDir $outName",
        "  # $outPath = Join-Path $OutDir $outName\n  $outPath = 'C:\\Windows\\Temp\\evil.json'",
    ),
    "repoint-certdir": (
        "$certDir = Join-Path $OutDir 'certs'",
        "$certDir = Join-Path 'C:\\Windows' 'certs'",
    ),
    "assign-outdir": (
        "New-Item -ItemType Directory -Force -Path $OutDir | Out-Null",
        "$OutDir = 'C:\\Windows'\nNew-Item -ItemType Directory -Force -Path $OutDir | Out-Null",
    ),
}


def _collector_text() -> str:
    return COLLECTOR.read_bytes().decode("utf-8").replace("\r\n", "\n")


@pytest.mark.parametrize("snippet", list(_BAD_SNIPPETS.values()), ids=list(_BAD_SNIPPETS))
def test_checker_flags_write_capable_surface(tmp_path: Path, snippet: str) -> None:
    """Each write-capable form, appended to the REAL collector, is reported.

    Appending (rather than checking the snippet alone) is what makes these
    meaningful: the snippet reuses the collector's own allowlisted names and
    variables, which is exactly how the round-1 bypasses worked.
    """
    script = tmp_path / "collector-plus-snippet.ps1"
    script.write_text(_collector_text() + "\n" + snippet + "\n", encoding="utf-8")
    assert violations(_dump(script)), f"not flagged: {snippet}"


@pytest.mark.parametrize("name", sorted(_REPLACEMENTS))
def test_checker_flags_repointed_write_targets(tmp_path: Path, name: str) -> None:
    old, new = _REPLACEMENTS[name]
    text = _collector_text()
    assert old in text, old
    script = tmp_path / "collector-mutated.ps1"
    script.write_text(text.replace(old, new, 1), encoding="utf-8")
    assert violations(_dump(script)), f"not flagged: {name}"


def test_appending_a_harmless_line_stays_clean(tmp_path: Path) -> None:
    """Control: the append harness itself does not cause violations."""
    script = tmp_path / "collector-plus-noop.ps1"
    script.write_text(_collector_text() + "\nWrite-Output 'done'\n", encoding="utf-8")
    assert violations(_dump(script)) == []


# --- review round 2 (Sol): each candidate, and WHICH check must flag it -------------
# Appended to the real collector. Every one also changes the golden inventory
# (the closed world catches it regardless); the tag proves the semantic layer
# catches it too, for the right reason.
_SOL_R2: dict[str, tuple[str, str]] = {
    "directory_set_adobject": (
        "Set-ADObject -Identity 'CN=x,DC=example,DC=test' -Replace @{description='owned'}",
        "[command]"),
    "directory_adsi_put": (
        "$de = [ADSI]'LDAP://CN=x,DC=example,DC=test'\n$de.Put('description', 'owned')\n$de.SetInfo()",
        "[member]"),
    "ca_certutil_setreg": (
        "certutil -setreg policy\\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2", "[command]"),
    "registry_set_item_property": (
        "Set-ItemProperty -Path HKLM:\\SOFTWARE -Name Probe -Value 1", "[command]"),
    "remote_invoke_command": (
        "Invoke-Command -ComputerName dc01 -ScriptBlock { Set-ItemProperty -Path HKLM:\\SOFTWARE "
        "-Name Probe -Value 1 }", "[command]"),
    "outside_direct_file": (
        "[IO.File]::WriteAllText('C:\\Windows\\Temp\\probe.txt', 'owned')", "[write-path]"),
    "outside_indirect_file": (
        "$target = 'C:\\Windows\\Temp\\probe.txt'\n[IO.File]::WriteAllText($target, 'owned')",
        "[write-path]"),
    "splatting": (
        "$args = @('-setreg', 'policy\\EditFlags', '+EDITF_ATTRIBUTESUBJECTALTNAME2')\ncertutil @args",
        "[command]"),
    "pipeline_member_dispatch": (
        "$reg | ForEach-Object -MemberName SetDWORDValue -ArgumentList "
        "@(2147483650, 'SOFTWARE\\Probe', 'Pwned', 1)", "[command]"),
    "dynamic_member": ("$method = 'SetInfo'\n$de.$method()", "[dynamic]"),
    "type_accelerator_adsi": ("$de = [ADSI]'LDAP://CN=x,DC=example,DC=test'", "[type]"),
    "type_alias_system_io_file": (
        "[System.IO.File]::WriteAllText('C:\\Windows\\Temp\\probe.txt', 'owned')", "[member]"),
    "provider_path_direct": (
        "New-Item -ItemType Directory -Force -Path HKLM:\\SOFTWARE\\AdcsLensProbe", "[write-path]"),
    "redirect_file": (
        "certutil -getreg CA\\CommonName 2> 'C:\\Windows\\Temp\\err.txt'", "[redirection]"),
    "scope_modifier": (
        "$global:outPath = 'C:\\Windows\\Temp\\probe.txt'\n[IO.File]::WriteAllText($outPath, 'owned')",
        "[pinned-binding]"),
    "function_unsafe_body": (
        "function Invoke-Later { Set-ItemProperty -Path HKLM:\\SOFTWARE -Name Probe -Value 1 }\n"
        "Invoke-Later", "[command]"),
    "scriptblock_invoke_later": (
        "$later = { Set-ItemProperty -Path HKLM:\\SOFTWARE -Name Probe -Value 1 }\n$later.Invoke()",
        "[command]"),
    "computer_different_variable": (
        "$otherDc = 'dc02.example.test'\n"
        "Get-WmiObject -ComputerName $otherDc -Namespace 'root\\default' -Class StdRegProv -List",
        "[command]"),
    # The round-2 bypasses: case-insensitive names and same-name parameters.
    "BYPASS_case_insensitive_outpath": (
        "$OUTPATH = 'C:\\Windows\\Temp\\probe.txt'\n"
        "[IO.File]::WriteAllText($outPath, 'owned', (New-Object Text.UTF8Encoding($false)))",
        "[pinned-binding]"),
    "BYPASS_function_parameter_outpath": (
        "function Invoke-Outside([string]$outPath) {\n"
        "  [IO.File]::WriteAllText($outPath, 'owned', (New-Object Text.UTF8Encoding($false)))\n"
        "}\nInvoke-Outside 'C:\\Windows\\Temp\\probe.txt'", "[pinned-binding]"),
    "BYPASS_function_parameter_provider": (
        "function New-Outside([string]$OutDir) {\n"
        "  New-Item -ItemType Directory -Force -Path $OutDir | Out-Null\n"
        "}\nNew-Outside 'HKLM:\\SOFTWARE\\AdcsLensProbe'", "[pinned-binding]"),
    "BYPASS_function_scriptblock_provider": (
        "function New-Later([string]$OutDir) {\n"
        "  1 | ForEach-Object { New-Item -ItemType Directory -Force -Path $OutDir | Out-Null }\n"
        "}\nNew-Later 'C:\\Windows\\Temp\\AdcsLensProbe'", "[pinned-binding]"),
    "BYPASS_scriptblock_param_block": (
        "1 | ForEach-Object { param($outDir) New-Item -ItemType Directory -Force -Path $outDir }",
        "[pinned-binding]"),
    "BYPASS_computer_same_name_parameter": (
        "function Read-OtherHost([string]$dcDns) {\n"
        "  Get-WmiObject -ComputerName $dcDns -Namespace 'root\\default' -Class StdRegProv -List\n"
        "}\nRead-OtherHost 'attacker.example.test'", "[pinned-binding]"),
    "BYPASS_computer_same_name_reassignment": (
        "$dcDns = 'attacker.example.test'\n"
        "Get-WmiObject -ComputerName $dcDns -Namespace 'root\\default' -Class StdRegProv -List",
        "[pinned-binding]"),
    "common_parameter_variable_write": (
        "Get-Date -OutVariable outPath | Out-Null", "[common-parameter]"),
    "common_parameter_abbreviated": ("Get-Date -ov dcDns | Out-Null", "[common-parameter]"),
    "unbound_receiver": (
        "$ExecutionContext.SessionState.PSVariable.Set('outPath', 'C:\\evil')", "[receiver]"),
}


@pytest.mark.parametrize("name", sorted(_SOL_R2))
def test_round2_candidate_is_flagged_by_the_right_check(tmp_path: Path, name: str) -> None:
    snippet, tag = _SOL_R2[name]
    script = tmp_path / "collector-plus-candidate.ps1"
    script.write_text(_collector_text() + "\n" + snippet + "\n", encoding="utf-8")
    dump = _dump(script)
    found = violations(dump)
    assert any(v.startswith(tag) for v in found), (name, tag, found)
    assert render_inventory(dump) != INVENTORY.read_text(encoding="utf-8")


def test_null_discard_is_allowed_by_semantics_but_not_by_the_inventory(tmp_path: Path) -> None:
    """Sol's control: `$NULL = ...` cannot rebind $null; the semantic layer allows
    the 2>$null discard, and the closed-world inventory still flags the change."""
    script = tmp_path / "collector-plus-null.ps1"
    script.write_text(
        _collector_text() + "\n$NULL = 'C:\\Windows\\Temp\\err.txt'\n"
        "certutil -getreg CA\\CommonName 2>$null\n", encoding="utf-8")
    dump = _dump(script)
    assert violations(dump) == []
    assert render_inventory(dump) != INVENTORY.read_text(encoding="utf-8")
