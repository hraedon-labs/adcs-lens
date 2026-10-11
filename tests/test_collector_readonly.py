# ruff: noqa: E501  (the regression tables hold literal PowerShell)
"""The collector is read-only: enforced by a PowerShell AST gate in two layers.

``scripts/Export-AdcsEstate.ps1`` runs on a CA / tier-0 box with privileged
credentials, so "read-only" must be a checked property, not a comment. This
test asks pwsh to *parse* the script (``[Parser]::ParseFile`` — nothing in it
executes; see ``tests/collector/Get-ScriptInvocations.ps1``).

1. **Golden syntax tree** (completeness). ``tests/collector/collector-inventory.json``
   holds an order-preserving serialization of the WHOLE syntax tree (one line
   per node: its role in the parent, its type and every semantically relevant
   property — operators, names, string values, flags, ``#Requires``,
   attributes, every argument) plus a SHA-256 of the source text (CRLF
   normalized). ANY edit — a reorder, a changed later argument, a ``#Requires``
   line, even a comment — fails ``test_collector_matches_golden_inventory``
   until it is regenerated with ``tests/collector/regen_inventory.py`` and the
   diff is reviewed. Meta-tests prove the serializer covers every Ast type and
   property of the running PowerShell and that sampled systematic mutations
   change the tree.

2. **Semantic floor** (``violations()``). The regeneration script refuses to
   write unless this returns nothing, so a regeneration can only admit what
   these allowlists and pins admit. It is a floor, not a proof: an admitted
   edit still shows up as a golden diff a reviewer must read.

Write-capable surfaces and how the floor handles them:

* AD writes (``Set-AD*``, ``New-AD*``, ``Remove-AD*``, ``DirectoryEntry
  .CommitChanges``, ``.Properties[...].Add``, LDAP Add/Modify/Delete
  requests): not allowlisted. ``Add`` is allowed only on the collector's own
  in-memory collections (``_ADD_TARGETS``: the paged search's ``ArrayList`` of
  results and a ``SearchRequest``'s control list), and every ``.Add`` call is
  pinned with its arguments in ``PINNED_MEMBER_CALLS``.
* CA config writes: every ``certutil`` invocation must be ``certutil -getreg ...``.
* Registry writes: ``OpenSubKey`` only with the 1-argument (read-only)
  overload; WMI only as ``Get-WmiObject -Class StdRegProv -List`` + ``GetDWORDValue``.
* Remote execution (``Invoke-Command``, ``Invoke-Expression``,
  ``Start-Process``, ``& $computed``, dot-sourcing): not allowlisted; a command
  whose name is computed at runtime, or invoked with ``.``, is a violation.
* **Local file writes only into the output directory**: each write target is
  one of a fixed set of path expressions, and every variable those
  expressions read is PINNED (below). In the product, every write sink is
  preceded by ``Assert-AdcsOutputPath <target>``, which resolves the full path
  and throws unless it is inside ``$OutDir``; the ``[write-guard]`` rule
  requires that guard, on the sink's exact target, in each sink's context.
* **Every write, exec and remote operation is pinned with its control-flow
  context** (``GUARDED_OPS``): its exact text plus the enclosing functions,
  conditions, loops, try blocks and preceding early-exit guards. A duplicate,
  a guard moved after the operation, or a weakened condition changes the
  multiset and fails.
* **Exact binding pins** (``PINNED_BINDINGS``): every write root, every
  receiver of an instance-method call / property write / index write, every
  exec input, and transitively every variable their bindings read, has its
  complete binding set pinned: assignments of any operator and scope,
  ``++``/``--``, ``foreach`` variables, parameter declarations (attributes,
  type and default), call-site arguments of local functions, and property /
  index writes on the object. Any rebind is not in the set and fails.
* Refused outright: provider-drive (``${alias:x}``, ``$env:x``, ``${C:\\x}``)
  and ``$global:``/``$variable:`` assignment targets, any provider-drive
  variable reference, writes to automatic/preference variables (beyond
  ``$ErrorActionPreference = 'Stop'``), any reference to
  ``$PSDefaultParameterValues`` / ``$PSModuleAutoLoadingPreference`` /
  ``$ExecutionContext``, ``-*Variable`` common parameters (any spelling or
  computed name), splatting, destructuring, ``#Requires``, background jobs,
  ``foreach -parallel``, non-ASCII source, AST node types the collector does
  not use, and any change to the exact list of local functions.
* **Redirections**: the only ones allowed are stream merges into the
  pipeline (``ALLOWED_REDIRECTIONS``: the collector's one ``certutil -getreg
  ... 2>&1``, which is also pinned as a guarded operation); every file
  redirection, ``2>$null`` included, is refused.
* **Member dispatch through cmdlets**: ``ForEach-Object`` / ``Where-Object``
  take exactly one script block, and every allowed cmdlet has an exact
  argument vector.

PowerShell 5.1: the collector must run on Windows PowerShell 5.1, so this test
never executes it — it only parses it (here with pwsh 7). The
``collector-windows`` CI job additionally parses it with Windows PowerShell 5.1.

Out of scope: ``scripts/install-windows.ps1`` and ``scripts/uninstall-windows.ps1``
run on the *analysis* host; they never run on a CA and never touch AD CS.

Declared limits are in ``docs/threat-model.md`` ("Collector read-only gate").

``pwsh`` is required. Locally the test skips without it; under CI (``CI`` set)
a missing pwsh is a failure, not a skip.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from collections.abc import Callable, Iterable
from functools import cache
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


def _run_dumper(paths: list[Path], *flags: str, timeout: int = 900) -> Any:
    out = subprocess.run(
        [
            _pwsh(),
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(DUMPER),
            *flags,
            *(str(p) for p in paths),
        ],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


# Dumps are cached by source content: one pwsh process dumps many files several
# times faster than one process per file, so the parametrized regression tests
# register their sources up front (register_sources) and the first cache miss
# dumps every registered source in batches.
_DUMP_CACHE: dict[str, dict[str, Any]] = {}
_PENDING: dict[str, bytes] = {}
_BATCH = 40


def _key(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def register_sources(texts: Iterable[str]) -> None:
    for text in texts:
        data = text.encode("utf-8")
        _PENDING.setdefault(_key(data), data)


# Parallel pwsh processes for a batch prefetch (each process dumps a chunk).
_WORKERS = max(1, min(4, (os.cpu_count() or 1)))


def _prefetch(extra: dict[str, bytes]) -> None:
    todo = {k: v for k, v in {**_PENDING, **extra}.items() if k not in _DUMP_CACHE}
    _PENDING.clear()
    if not todo:
        return
    from concurrent.futures import ThreadPoolExecutor

    with tempfile.TemporaryDirectory(prefix="adcs-gate-") as tmp:
        items = sorted(todo.items())
        size = max(1, min(_BATCH, -(-len(items) // _WORKERS)))
        chunks = [items[i : i + size] for i in range(0, len(items), size)]

        def dump_chunk(chunk: list[tuple[str, bytes]]) -> list[tuple[str, dict[str, Any]]]:
            paths = []
            for key, data in chunk:
                path = Path(tmp) / f"{key}.ps1"
                path.write_bytes(data)
                paths.append(path)
            entries = _run_dumper(paths, "-Many")
            return [(key, entry) for (key, _), entry in zip(chunk, entries, strict=True)]

        with ThreadPoolExecutor(max_workers=_WORKERS) as pool:
            for results in pool.map(dump_chunk, chunks):
                _DUMP_CACHE.update(results)


def _dump(script: Path) -> dict[str, Any]:
    data = script.read_bytes()
    key = _key(data)
    if key not in _DUMP_CACHE:
        _pwsh()
        _prefetch({key: data})
    return _DUMP_CACHE[key]


# --- the allowlist ---------------------------------------------------------------

Check = Callable[[dict[str, Any]], str | None]  # returns a violation reason or None

# A $variable name or a -parameter flag: both are case-insensitive in PowerShell.
_NAME_TOKEN = re.compile(
    r"\$\{[^}]+\}|\$[A-Za-z_][A-Za-z0-9_:]*|(?<![\w'\"-])-[A-Za-z][A-Za-z0-9]*"
)
_STRING_SPAN = re.compile(r"'[^']*'|\"[^\"]*\"")


def _canon(text: str) -> str:
    """Lower-case every $variable name and -parameter flag in *text*, leaving
    quoted strings and bareword values untouched, so an argument vector / write
    target compares case-insensitively on NAMES but exactly on VALUES."""
    out: list[str] = []
    i = 0
    for m in _STRING_SPAN.finditer(text):
        out.append(_NAME_TOKEN.sub(lambda t: t.group().lower(), text[i : m.start()]))
        out.append(m.group())
        i = m.end()
    out.append(_NAME_TOKEN.sub(lambda t: t.group().lower(), text[i:]))
    return "".join(out)


def _ok(c: dict[str, Any]) -> str | None:
    return None


def _exact(*vectors: list[str]) -> Check:
    """Allow only these exact argument vectors (parameters and values, in order)."""
    allowed = [[_canon(a) for a in v] for v in vectors]

    def check(c: dict[str, Any]) -> str | None:
        if [_canon(a) for a in c["args"]] in allowed:
            return None
        return f"arguments {c['args']} are not one of the allowed vectors {vectors}"

    return check


def _literal_here_string(c: dict[str, Any]) -> str | None:
    els = c["elements"]
    if (
        len(els) == 1
        and els[0]["parameter"] is None
        and els[0]["kind"] == "StringConstantExpressionAst"
        and els[0]["text"].startswith("@'")
    ):
        return None
    return "only one literal single-quoted here-string argument is allowed"


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


# Every admitted constructor, as its EXACT argument vector (type, then the
# parenthesised constructor arguments). A type's other overloads are not
# admitted: e.g. X509Certificate2(path, password, flags) can persist a private
# key in a machine key store, but only the in-memory (,$der) form is listed.
# Each New-Object call is also a guarded operation, so its count and
# control-flow context are pinned in GUARDED_OPS.
NEW_OBJECT_VECTORS: frozenset[tuple[str, ...]] = frozenset(
    {
        # The LDAP bind credential, in memory, handed only to LdapConnection::new
        # (see SECRET_USES).
        ("System.Net.NetworkCredential", "($LdapUser, $LdapPass)"),
        # The paged search's in-memory result list.
        ("System.Collections.ArrayList",),
        # In-memory security-descriptor / certificate decoders.
        ("DirectoryServices.ActiveDirectorySecurity",),
        ("Security.AccessControl.RawSecurityDescriptor", "(@([byte[]]$bytes), 0)"),
        ("Security.Cryptography.X509Certificates.X509Certificate2", "(,$der)"),
        # Credential object for the opt-in WMI registry read.
        (
            "Management.Automation.PSCredential",
            "( $DcRegistryUser, (ConvertTo-SecureString $DcRegistryPass -AsPlainText -Force))",
        ),
        # JSON + encoding for writing the export.
        ("System.Web.Script.Serialization.JavaScriptSerializer",),
        ("Text.UTF8Encoding", "($false)"),
    }
)
_NEW_OBJECT_VECTORS_CANON = frozenset(tuple(_canon(a) for a in v) for v in NEW_OBJECT_VECTORS)


def _new_object(c: dict[str, Any]) -> str | None:
    els = c["elements"]
    if any(e["parameter"] is not None for e in els):
        return "New-Object may not take parameters (-ComObject, -TypeName, -Property, ...)"
    if tuple(_canon(a) for a in c["args"]) not in _NEW_OBJECT_VECTORS_CANON:
        return f"New-Object constructor {c['args']} is not an allowlisted exact argument vector"
    return None


_WMI_READ = ["-Namespace", "'root\\default'", "-Class", "StdRegProv", "-List"]
_WEBCFG_PARAMS = {"pspath", "filter", "name", "erroraction"}  # lower-cased by the dumper


def _web_config(c: dict[str, Any]) -> str | None:
    params = [e["parameter"] for e in c["elements"] if e["parameter"] is not None]
    if sorted(params) == sorted(_WEBCFG_PARAMS) and len(c["elements"]) == 2 * len(params):
        return None
    return f"Get-WebConfigurationProperty may only take {sorted(_WEBCFG_PARAMS)}"


ALLOWED_COMMANDS: dict[str, Check] = {
    # certutil only reads: `certutil -getreg <one key>` (the key is _certutilRead's
    # pinned parameter; every call site passes a literal key).
    "certutil": _exact(["-getreg", "$regpath"]),
    "New-Item": _exact(
        *(
            ["-ItemType", "Directory", "-Force", "-Path", p]
            for p in ("$OutDir", "$outParent", "$certDir")
        )
    ),
    "New-Object": _new_object,
    # WMI only to obtain the StdRegProv class (local, or on a DC for the opt-in
    # esc10 pass); the only methods then allowed on it are reads (GetDWORDValue).
    "Get-WmiObject": _exact(
        _WMI_READ,
        ["-ComputerName", "$dcDns", *_WMI_READ],
        ["-ComputerName", "$dcDns", "-Credential", "$dcCred", *_WMI_READ],
    ),
    # A module load is code execution: one exact form, and pinned in GUARDED_OPS.
    "Import-Module": _exact(["WebAdministration", "-ErrorAction", "Stop"]),
    # Framework assembly loads only: the JSON serializer, and the LDAP client
    # (System.DirectoryServices.Protocols; the collector builds only SearchRequests).
    "Add-Type": _exact(
        ["-AssemblyName", "System.Web.Extensions"],
        ["-AssemblyName", "System.DirectoryServices.Protocols"],
    ),
    # Read-only IIS configuration queries (ESC8 pass).
    "Get-Website": _exact(["-ErrorAction", "Stop"]),
    "Get-WebApplication": _exact(["-Site", "$site.Name", "-ErrorAction", "Stop"]),
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
    # Parses the collector's own literal schema tables (a single-quoted here-
    # string: no expansion, no input): in memory only.
    "ConvertFrom-Json": _literal_here_string,
    # Builds the opt-in WMI credential in memory.
    "ConvertTo-SecureString": _exact(["$DcRegistryPass", "-AsPlainText", "-Force"]),
}

# Commands that can never be allowlisted, whatever ALLOWED_COMMANDS says: they
# rebind command resolution (aliases, functions, drives, location), write
# variables by name, run code or register engine callbacks. (Import-Module is
# the one code-load the collector needs; it has an exact vector and a pinned
# guarded operation instead.)
FORBIDDEN_COMMANDS = frozenset(
    {
        "Add-PSSnapin",
        "Clear-Item",
        "Clear-Variable",
        "Export-Alias",
        "Import-Alias",
        "Invoke-Command",
        "Invoke-Expression",
        "Invoke-Item",
        "New-Alias",
        "New-Module",
        "New-PSDrive",
        "New-Variable",
        "Pop-Location",
        "Push-Location",
        "Register-EngineEvent",
        "Register-ObjectEvent",
        "Remove-Variable",
        "Set-Alias",
        "Set-Item",
        "Set-ItemProperty",
        "Set-Location",
        "Set-PSBreakpoint",
        "Set-Variable",
        "Start-Job",
        "Start-Process",
        "Start-ThreadJob",
        "Update-FormatData",
        "Update-TypeData",
    }
)

# (static type expression, member)
ALLOWED_STATIC: set[tuple[str, str]] = {
    ("[Convert]", "FromBase64String"),
    ("[Convert]", "ToInt64"),
    ("[System.Net.Dns]", "GetHostEntry"),
    ("[IO.File]", "WriteAllText"),
    ("[IO.File]", "WriteAllBytes"),
    ("[int]", "TryParse"),  # schema type check (the [ref] target is pinned)
    # Assert-AdcsOutputPath (the write-path guard): path arithmetic and
    # existence / attribute reads only.
    ("[IO.Path]", "GetFullPath"),
    ("[IO.Path]", "GetDirectoryName"),
    ("[IO.Directory]", "Exists"),
    ("[IO.File]", "Exists"),
    ("[IO.File]", "GetAttributes"),
    # System.DirectoryServices.Protocols, read side only. The identifier
    # locates a DC; the connection binds; SearchRequest is the ONLY request type
    # (ModifyRequest / AddRequest / DeleteRequest / ModifyDNRequest /
    # ExtendedRequest are never allowlisted, see _NEVER_TYPES); the two controls
    # page a search and ask for the DACL+Owner of nTSecurityDescriptor.
    ("[System.DirectoryServices.Protocols.LdapDirectoryIdentifier]", "new"),
    ("[System.DirectoryServices.Protocols.LdapConnection]", "new"),
    ("[System.DirectoryServices.Protocols.SearchRequest]", "new"),
    ("[System.DirectoryServices.Protocols.PageResultRequestControl]", "new"),
    ("[System.DirectoryServices.Protocols.SecurityDescriptorFlagControl]", "new"),
}
# Every allowed WriteAll* call writes into the output directory.
ALLOWED_WRITE_TARGETS = {
    "WriteAllText": {"$outPath"},
    "WriteAllBytes": {"(Join-Path $certDir $certFile)", "(Join-Path $certDir $crlFile)"},
}
# Property / indexer ASSIGNMENTS are object writes. The only ones allowed are
# the collector's existing configuration of query/serialiser objects and its
# own local hashtables, each tied to the receiver's binding (provenance) in the
# same scope. Anything else — in particular any assignment on a
# directory-services entry, or to a `.Value` — is rejected. (The receivers are
# also PINNED below, so their bindings are exact.)
_SERIALISER = re.compile(r"New-Object System\.Web\.Script\.Serialization\.JavaScriptSerializer")
_LDAP_CONNECTION = re.compile(
    r"\[System\.DirectoryServices\.Protocols\.LdapConnection\]::new\(\$id(, \$cred)?\)"
)
_PAGE_CONTROL = re.compile(
    r"\[System\.DirectoryServices\.Protocols\.PageResultRequestControl\]::new\(500\)"
)
# A hashtable literal: an in-memory table the collector builds itself.
_LOCAL_TABLE = re.compile(r"(\[ordered\])?@\{.*\}")
MEMBER_ASSIGNMENTS_ALLOWED: dict[tuple[str, str], re.Pattern[str]] = {
    ("js", "maxjsonlength"): _SERIALISER,
    # Client-side settings of the local LDAP connection object (no LDAP traffic).
    ("conn", "authtype"): _LDAP_CONNECTION,
    # The paging cookie of the local request control (the server's own cookie).
    ("page", "cookie"): _PAGE_CONTROL,
}
# The only nested property write: the connection's LDAP protocol version.
NESTED_MEMBER_ASSIGNMENTS_ALLOWED: dict[tuple[str, str], re.Pattern[str]] = {
    ("conn", "sessionoptions.protocolversion"): _LDAP_CONNECTION,
}
INDEX_ASSIGNMENTS_ALLOWED: dict[str, re.Pattern[str]] = {
    "casecurity": _LOCAL_TABLE,
    "enrollmentservices": _LOCAL_TABLE,
    # Local [ordered]@{} of per-container enumeration completion markers.
    "enumeration": _LOCAL_TABLE,
    # _entryProps' attribute table and a marker's reason field (local tables).
    "p": _LOCAL_TABLE,
    "m": _LOCAL_TABLE,
    # The local CA's registry ACEs, keyed by CA name.
    "localsecurity": _LOCAL_TABLE,
}
_DIRECTORY_SOURCES = re.compile(
    r"DirectoryServices\.DirectoryEntry|_ldapEntry|_ldapRoot|_ldapRootDse|\[ADSI\]",
    re.IGNORECASE,
)
_SCRIPT = "<script>"


def _receiver_bindings(dump: dict[str, Any], root: str, scope: str) -> list[str]:
    """Values bound to *root* in *scope* (or the script scope if none there)."""
    local = [b["value"] for b in dump["bindings"] if b["variable"] == root and b["scope"] == scope]
    if local:
        return local
    return [b["value"] for b in dump["bindings"] if b["variable"] == root and b["scope"] == _SCRIPT]


def _member_assignment_violations(dump: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for m in dump.get("member_assignments", []):
        where = f"[member-assign] {m['scope']}: {m['target']} {m['operator']} ..."
        root = m["receiver_root"]
        target = m["target"].lower()
        if target.endswith(".value"):
            out.append(f"{where}: assignment to .Value is rejected")
            continue
        values = _receiver_bindings(dump, root, m["scope"]) if root else []
        if any(_DIRECTORY_SOURCES.search(v) for v in values):
            out.append(f"{where}: assignment on a directory-services object is rejected")
            continue
        if m["kind"] == "member":
            member = target.rsplit(".", 1)[-1]
            pattern = MEMBER_ASSIGNMENTS_ALLOWED.get((root or "", member))
            path = target.split(".", 1)[-1]
            if "." in path or "[" in target:
                # nested targets ($x.A.B = ...) only where explicitly listed
                pattern = NESTED_MEMBER_ASSIGNMENTS_ALLOWED.get((root or "", path))
        else:
            pattern = INDEX_ASSIGNMENTS_ALLOWED.get(root or "")
            if target.count("[") != 1:
                pattern = None
        if pattern is None:
            out.append(f"{where}: property/indexer assignment is not allowlisted")
        elif not values or not all(pattern.fullmatch(v) for v in values):
            out.append(f"{where}: receiver ${root} is not bound to an allowed object ({values})")
    return out


# Automatic variables a member call may use as its receiver without a binding.
_AUTOMATIC_RECEIVERS = {"_", "matches"}
_SAFE_OUTPUT_NAME = re.compile(r"'(?:[A-Za-z0-9_-]+/)?[A-Za-z0-9_-]+\.json'")
# The only redirection: certutil's stderr discarded.
# certutil's stderr merged into its output (2>&1) so the exit code and message
# are captured; it writes no file. No file redirection is allowed.
ALLOWED_REDIRECTIONS = {("MergingRedirectionAst", "Error", None, None)}


def _open_sub_key(m: dict[str, Any]) -> str | None:
    return None if m["argc"] == 1 else "OpenSubKey must use the read-only (1-argument) overload"


# Add only on the collector's own in-memory collections: the paged search's
# result list and a SearchRequest's control list.
_ADD_TARGETS = {"$entries", "$req.Controls"}


def _add_target(m: dict[str, Any]) -> str | None:
    if _canon(m["target"]) in {_canon(t) for t in _ADD_TARGETS}:
        return None
    return f"Add is allowed only on {sorted(_ADD_TARGETS)}"


ALLOWED_INSTANCE: dict[str, Check] = {
    # string / collection helpers
    "ToLower": _ok,
    "Trim": _ok,
    "TrimStart": _ok,
    "StartsWith": _ok,
    "ToString": _ok,
    "ToUniversalTime": _ok,
    "GetString": _ok,
    "GetEnumerator": _ok,
    "ContainsKey": _ok,
    "Serialize": _ok,  # JavaScriptSerializer -> JSON text
    "TrimEnd": _ok,  # string helpers of the write-path guard
    "Equals": _ok,
    # LDAP (System.DirectoryServices.Protocols): Bind authenticates the local
    # connection; SendRequest transmits the request it is given, and its one
    # argument is binding-pinned to a SearchRequest; GetValues reads a returned
    # attribute's values. GetNewClosure captures the search scriptblock.
    "Bind": _ok,
    "SendRequest": _ok,
    "GetValues": _ok,
    "GetNewClosure": _ok,
    "Add": _add_target,
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
    "bool",
    "byte[]",
    "int",
    "string",
    "switch",
    "uint32",
    "void",
    "ordered",
    "Convert",
    "IO.File",
    "System.Net.Dns",
    "Text.Encoding",
    "Microsoft.Win32.Registry",
    "Security.Principal.NTAccount",
    "Security.Principal.SecurityIdentifier",
    # The write-path guard: path / comparison / attribute types.
    "char",
    "IO.Path",
    "IO.Directory",
    "IO.FileAttributes",
    "StringComparison",
    # Parameter type constraints of local helpers.
    "string[]",
    "scriptblock",  # [scriptblock]$send / $read parameters (::Create is not allowlisted)
    "ref",  # only in the pinned [int]::TryParse($values[0], [ref]$n)
    # System.DirectoryServices.Protocols, read side (see ALLOWED_STATIC).
    "System.DirectoryServices.Protocols.AuthType",
    "System.DirectoryServices.Protocols.LdapConnection",
    "System.DirectoryServices.Protocols.LdapDirectoryIdentifier",
    "System.DirectoryServices.Protocols.PageResultRequestControl",
    "System.DirectoryServices.Protocols.SearchRequest",
    "System.DirectoryServices.Protocols.SearchScope",
    "System.DirectoryServices.Protocols.SecurityDescriptorFlagControl",
    "System.DirectoryServices.Protocols.SecurityMasks",
}
# LDAP write / server-side operations and other non-read transports: never
# admitted, whatever the allowlists say (test_never_types_are_never_allowlisted).
_NEVER_TYPES = re.compile(
    r"(ModifyRequest|AddRequest|DeleteRequest|ModifyDNRequest|ExtendedRequest|"
    r"DsmlSoapHttpConnection|DsmlRequestDocument|CompareRequest|DirectoryEntry)$",
    re.IGNORECASE,
)

# --- closed sets (strict default: what cannot be positively pinned is refused) -----

# AST node types the collector may contain: exactly the ones it uses today.
# Classes/enums, DSC configurations, dynamic keywords, data sections, traps,
# `$using:`, pipeline chains (&&/||), ternaries, do/while/for loops and
# parse-error nodes are all refused rather than reasoned about.
ALLOWED_NODE_TYPES = frozenset(
    {
        "ArrayExpressionAst",
        "ArrayLiteralAst",
        "AssignmentStatementAst",
        "AttributeAst",
        "BinaryExpressionAst",
        "BreakStatementAst",
        "CatchClauseAst",
        "CommandAst",
        "CommandExpressionAst",
        "CommandParameterAst",
        "ConstantExpressionAst",
        "ContinueStatementAst",
        "ConvertExpressionAst",
        "ExpandableStringExpressionAst",
        "ForEachStatementAst",
        "ForStatementAst",
        "FunctionDefinitionAst",
        "HashtableAst",
        "IfStatementAst",
        "IndexExpressionAst",
        "InvokeMemberExpressionAst",
        "MemberExpressionAst",
        "MergingRedirectionAst",
        "NamedAttributeArgumentAst",
        "NamedBlockAst",
        "ParamBlockAst",
        "ParameterAst",
        "ParenExpressionAst",
        "PipelineAst",
        "ReturnStatementAst",
        "ScriptBlockAst",
        "ScriptBlockExpressionAst",
        "StatementBlockAst",
        "StringConstantExpressionAst",
        "SubExpressionAst",
        "SwitchStatementAst",
        "ThrowStatementAst",
        "TryStatementAst",
        "TypeConstraintAst",
        "TypeExpressionAst",
        "UnaryExpressionAst",
        "VariableExpressionAst",
    }
)

# The exact functions the collector defines, in source order. A redefinition
# (a second `function _safeFileName`), a new helper, or a function shadowing an
# allowlisted cmdlet is not this tuple.
LOCAL_FUNCTIONS: tuple[str, ...] = (
    "_b64",
    "_guidHex",
    "Assert-AdcsOutputPath",
    "_writeJson",
    "_pagedSearchCore",
    "_baseSearchCore",
    "_entryProps",
    "_v",
    "_ldapConnection",
    "_search",
    "_rootDse",
    "_list",
    "_schemaCheck",
    "_requireSchema",
    "_searchMarker",
    "_decode",
    "_decodeBinding",
    "_parseCertutilFlagLines",
    "_parseCertutilDwordLines",
    "_parseCertutilMultiSzLines",
    "_certutilStatus",
    "_certutilFlagsFrom",
    "_certutilDwordFrom",
    "_certutilMultiSzFrom",
    "_certutilStringFrom",
    "_wmiDwordStatus",
    "_tryRead",
    "_epaToken",
    "_classifyApp",
    "_caKindFromType",
    "_safeFileName",
    "_certKindFromDer",
    "_parseAces",
    "_sdRead",
    "_aclRow",
    "_objAcl",
    "_childAcls",
    "_readOwner",
    "_caSecurityFromBytes",
    "_rawSdOwner",
    "_caSecurityRead",
    "_certutilRead",
    "_certutilFlags",
    "_certutilDword",
    "_certutilMultiSz",
    "_mark",
    "_markSearch",
    "_localCaRow",
)

# Structural-closure pins: the digest of the normalized AST subtree of EVERY
# statement of the collector (each top-level statement and each statement inside
# every function / scriptblock body), keyed by its structural index path (see
# _statement_digests). HAND-MAINTAINED and never written by regen_inventory.py
# (test_regen_does_not_touch_pin_tables), so ANY edit anywhere -- a changed
# string, a new statement, a reorder -- fails the semantic floor until a human
# updates this table; print_pin_candidates.py prints the candidates. A function
# definition is itself a statement, so this subsumes the former
# LOCAL_FUNCTION_BODIES. The semantic checks above remain the floor for a harmful
# edit made by someone who does update the digests.
STATEMENT_DIGESTS: dict[str, str] = {
    "0.1.0": "4fbc2be395306a6ec8b4282e2d60450b6a7d3b24f40585523b206be47d1ab1a6",  # AssignmentStatementAst
    "0.1.1": "eebcad12f29f7916f1c4b0e0b7680e5424db23486d424163bbd9fdc780f14365",  # AssignmentStatementAst
    "0.1.2": "49b00bcb38f3c824c5d8688ac77386c4965f47bb0aedcd8dc2bca944ecda5536",  # FunctionDefinitionAst
    "0.1.2.1.0.0": "b0bfbd94546c89400b1af0293ef422a27650d212a82ba56351a60bfd2814382e",  # PipelineAst
    "0.1.3": "b3b801bf40104c7fb858531280ce6b2b0c9b34369d2684feb75a48a59d0dd35e",  # FunctionDefinitionAst
    "0.1.3.1.0.0": "d79e48398ed0962ead1ef868305f06b587289c598b43d2817aecdfff46c334da",  # IfStatementAst
    "0.1.3.1.0.0.1.0": "0f1c5e2054b9780de87535dd47d4e921576f9b3ba57e9f0c47c66374e148f982",  # ReturnStatementAst
    "0.1.3.1.0.1": "7689cd73d6a9e57fcac7dba259748a79f55f8fdff46fd71d363addb329bfcf93",  # AssignmentStatementAst
    "0.1.3.1.0.2": "2e8799c3b0206f61d379144819f4f7642d798d46d0ecc95ed8645e5a1a958697",  # IfStatementAst
    "0.1.3.1.0.2.1.0": "57e6daf90a2713135839508c8dd45d42a6d27a63f0960af06102bf9e41413758",  # ReturnStatementAst
    "0.1.3.1.0.3": "875280a27059f597f8f409a7541751fd892ef7b9c7352c19c158242f1eddc128",  # PipelineAst
    "0.1.3.1.0.3.0.0.0.0.0.0.0.1.1.0.0.0": "1c4c0b4c2db3270bdf0167f5edd566d9cdabc5487494124078f8e5f9ce5a0546",  # PipelineAst
    "0.1.4": "06da9195ceddbcb300198a04453953657a1e4f9e38295e9186f4d0789982e4fd",  # FunctionDefinitionAst
    "0.1.4.1.0.0": "5745206c02a3234174c694f7fcdc190be4661cb691ddfc58661f781881681e0e",  # IfStatementAst
    "0.1.4.1.0.0.1.0": "d56fa7a4db41b29f0ffaa7098ede1c404cbd816b351ce2b512327a00231e1e1f",  # ThrowStatementAst
    "0.1.4.1.0.1": "52c0f1f03c2dd6dc012297d264c2ac69b024dc0fca41fb2b92c2d567d7ed7525",  # AssignmentStatementAst
    "0.1.4.1.0.2": "fb979f98ddd7ce5456493d273f80a3b719923a951042c4990619d9cec1e05408",  # AssignmentStatementAst
    "0.1.4.1.0.3": "9bde3f11a81bc2280d99d63b3e5168bc3c52bd12638f70881795ff1928c65c37",  # AssignmentStatementAst
    "0.1.4.1.0.4": "e6895f55572c05a93b0f02e6cf4ca6d4a64d79073225245bc3cf21565dd8afc8",  # IfStatementAst
    "0.1.4.1.0.4.1.0": "1c17477dbe35a21f27493269680441397268cab59ab4fda67c0a6b044d799653",  # ThrowStatementAst
    "0.1.4.1.0.5": "74eb0f4121ef306c77aa1c40809427a80551291ce3bc3bd1beda9c151f1c65e4",  # ForStatementAst
    "0.1.4.1.0.5.3.0": "350d8d1cdd4c1f30c133b813de31924ecf5c34a443cd604939605e2b535b6ece",  # IfStatementAst
    "0.1.4.1.0.5.3.0.1.0": "940f60a11a160155a5e09137f9093fa4176a0a44b591bf1621d1e4d9b24ba7d1",  # IfStatementAst
    "0.1.4.1.0.5.3.0.1.0.1.0": "16b5738d3971e50496a4947c9793eaa8c7ee1d623695018abe91f0c4dbd02b7c",  # ThrowStatementAst
    "0.1.5": "5b927d5bc0688445dfa72cdc144c0f914350eb29a977da21a6178c1bbd2e5b1f",  # FunctionDefinitionAst
    "0.1.5.2.0.0": "d5e7394ab6d3bc27f0c0a614f6b9e0a1b47b875e8e9805745294e63b60b25038",  # AssignmentStatementAst
    "0.1.5.2.0.1": "522f1bb114dcfbe9704a72dc1d50e06ed017c51ed705912b4f4811d40d8d6280",  # AssignmentStatementAst
    "0.1.5.2.0.2": "12f6018ca8d5a849504bd7911a862d7f1594348c48c3203133dabb31ce9379f9",  # PipelineAst
    "0.1.5.2.0.3": "13c7ffdd8f5606e097691aff449e679e11d8f4579bee1c59bbda401e7af54ee4",  # PipelineAst
    "0.1.5.2.0.4": "750921de9135bb95874f059dd9249756cec32ec66b8e62912921f68e33cd2163",  # IfStatementAst
    "0.1.5.2.0.4.1.0": "857d0dda6210d3beddd980388b85f833ad7ccd7b59df623db18c3a36aed51911",  # PipelineAst
    "0.1.5.2.0.5": "9420ac4159fdd841a8cf887ff9f6dfa1f1497c28b0bbc955fd6c12759440ad69",  # PipelineAst
    "0.1.6": "c7d1e7f48c0481e4e024bd81a6cc79638fff8b986f02c9ca729286eb4beb841f",  # FunctionDefinitionAst
    "0.1.6.2.0.0": "a1c043784d742ebe308652df11433deb68982dd9ce5b3bd28f58e61d74f70a76",  # AssignmentStatementAst
    "0.1.6.2.0.1": "a72a3f565a6e0dbdb8af341e0572585703961d9449e7975538d9003c673064a5",  # AssignmentStatementAst
    "0.1.6.2.0.2": "1681ecbee8d1352314e06ed99c0f768574395558d617a1173b9927762d66ff6b",  # AssignmentStatementAst
    "0.1.6.2.0.3": "61db35a4f03659c6341b8bf2d71131d97f97970df6be1cccc2cbfbd4fda1e10d",  # AssignmentStatementAst
    "0.1.6.2.0.4": "f8d7f4fae864e1944e0658268ae0909a66d392223d9bfdfc77d71390bb6053ec",  # ForStatementAst
    "0.1.6.2.0.4.3.0": "7e7a71721d49741b41761e8e3a77e08e94ccd9f6718f128cea9b37c687f14cdb",  # TryStatementAst
    "0.1.6.2.0.4.3.0.0.0": "4343d8ef61e58b1aae0138a7ba1fe9ca9ed26d8b76ff80e163281af3f6a33dcd",  # AssignmentStatementAst
    "0.1.6.2.0.4.3.0.1.0.0": "933d9cb1a207a755717bc2d6743e231166d942db0a62c85cafa3409a0e034bea",  # AssignmentStatementAst
    "0.1.6.2.0.4.3.0.1.0.0.1.0.1.0.0": "26b57a2b64b239a1f73f4a09751c84698f3b6424910b07b9c6cf83851fff32cf",  # PipelineAst
    "0.1.6.2.0.4.3.0.1.0.1": "f3969ec4e82b3524ac54248a4e60abca72b4bde7f441c32784247f05f6650f1f",  # BreakStatementAst
    "0.1.6.2.0.4.3.1": "227452ad9eb9e1dbe4908912f9ea83ada3f84c856712a171f3f09b25c5c00295",  # IfStatementAst
    "0.1.6.2.0.4.3.1.1.0": "902ab15e95bf6444b3b89d08a2f42105236542a53b3887bdb1879c6d6a3c0ab2",  # AssignmentStatementAst
    "0.1.6.2.0.4.3.1.1.1": "acb816caa190fb42a3f528ba1b40b1687ce5928dab725e326a7c247b62fd5545",  # BreakStatementAst
    "0.1.6.2.0.4.3.2": "e2b1667047d854e243d6a6c03b900a8b3c3b919ef14d9934fdcaa5257a3e600a",  # IfStatementAst
    "0.1.6.2.0.4.3.2.1.0": "ffa40a82fec550ef937bd32e80d06075ee1475adbf138bbbaf5a4e7d71f23a19",  # AssignmentStatementAst
    "0.1.6.2.0.4.3.2.1.0.1.0.1.0.0": "3b64b557473df8104da9c66d5b255137a57810cc067ac27a4fb2dd0257cf91f1",  # PipelineAst
    "0.1.6.2.0.4.3.2.1.1": "8ca86a6c3df5a98763905625227f573ddab4b26d97203ab11d3d718888efda17",  # BreakStatementAst
    "0.1.6.2.0.4.3.3": "82d382b886077de1287c78cfc5b5d6deb0bdb51fba3da80b591d7874372ee26b",  # ForEachStatementAst
    "0.1.6.2.0.4.3.3.1.0.0.0.0": "14442495f41add26bb7c74c5c8d04b6fdc880dc8a634300274b4a1eb3da3f1b5",  # PipelineAst
    "0.1.6.2.0.4.3.3.2.0": "6eed316eda4ec196011b393b0efac0ac0f6a709a14a2210cf7e631c4893d7ad1",  # PipelineAst
    "0.1.6.2.0.4.3.4": "0cb056e4f565b9fa0614924c2f696fec8fd74ba13ff86c837dd4cbe33f71137f",  # AssignmentStatementAst
    "0.1.6.2.0.4.3.4.1.0.0.0.0": "1a882270571dc20d427197933b49848d98ab93971cd14ca91779fedec234c16a",  # PipelineAst
    "0.1.6.2.0.4.3.4.1.0.0.0.0.1.1.0.0.0": "acb0785965348321bd296ae995d4bcd9857cdb658195213c45e0aef2dc623d8f",  # PipelineAst
    "0.1.6.2.0.4.3.5": "b2aef9a3df12145daeb1859711a15c0f2f8c8fcf3734447cd33e001ed0153b04",  # IfStatementAst
    "0.1.6.2.0.4.3.5.1.0": "f3cbb7ce6d8909b6e66153662bef550a59ecab62b4ffa080af999db3f59b06ff",  # AssignmentStatementAst
    "0.1.6.2.0.4.3.5.1.1": "4d0655bd1d3ea5fe5e9e9ad5bfdca40a29d8f8cc1281824522fcdc4245964fc7",  # BreakStatementAst
    "0.1.6.2.0.4.3.6": "a70be465e47d9a53be566aabab01197135dcb49bb2dc461b294b74a8a987f215",  # AssignmentStatementAst
    "0.1.6.2.0.4.3.6.1.0.1.0.0": "14b9c33f50fe719750b485953ff40065c896c6c08a70a1855fab7b0a173011e3",  # PipelineAst
    "0.1.6.2.0.4.3.7": "a60250bd68dfd275323cd727e4de64f27de270ac7586eef24be0b6def6fbd064",  # IfStatementAst
    "0.1.6.2.0.4.3.7.1.0": "58db1e81ce470b820e51e528462e3a46c50b445ccdf19f4734b60dac45f19973",  # AssignmentStatementAst
    "0.1.6.2.0.4.3.7.1.1": "85e3bc82e7716d7719cba01c0f88bda31bd17e5586902a0497a83c13e57c2cd9",  # AssignmentStatementAst
    "0.1.6.2.0.4.3.7.1.2": "203ad101f17d7e8bc08d161d56aa545f8134be3d777ed2d3bdc41259dc53a2d7",  # BreakStatementAst
    "0.1.6.2.0.5": "a3b4a0cccd66d411db48a0c951bed10c52f203350aa5419dae63ffcf0cb1602b",  # PipelineAst
    "0.1.7": "7a7bc874c65305fd64a566d19abcd54bc683e79a4914c669b1c4720718216d89",  # FunctionDefinitionAst
    "0.1.7.1.0.0": "8fa2ece4133ae77cd660c4ad4819d7b3b717b92c92cc79229703c4649b8caef5",  # TryStatementAst
    "0.1.7.1.0.0.0.0": "f30690072d22bcd80f9f425a22695ca585e54afa58424ce35b704254e195b0ff",  # AssignmentStatementAst
    "0.1.7.1.0.0.1.0.0": "408177d672b1c1c58c2c05ece47fb690928b89aaa757eba5b692fc70885c32e6",  # ReturnStatementAst
    "0.1.7.1.0.0.1.0.0.0.0.0.5.0.0.0.0.0": "8d135d05cb3e04156e87439e0bc556da807c9c3700e1ecbf1d6f609e858e6725",  # PipelineAst
    "0.1.7.1.0.1": "5cbde857bbfba1fd253e669c55de3da58f01a22137d57e3ecf7c95e46686cac2",  # IfStatementAst
    "0.1.7.1.0.1.1.0": "a314ec23447b282a9c2da8f7eab089e7c665d557182e7320954a3f02ec47c4ee",  # ReturnStatementAst
    "0.1.7.1.0.1.1.0.0.0.0.5.0.0.0.0.0": "0b0ce2a11786286003f59c90fb95de070db67d2801484ef7db7efd7f3b8b45a2",  # PipelineAst
    "0.1.7.1.0.2": "c54817513beb6318841449a4acaf916fbde7847db2156498f6713fe8128f20ca",  # PipelineAst
    "0.1.7.1.0.2.0.0.1.0.0.0.0": "c337682e856332e76ed09d2537887b45497efec74910ccaf73ab7e64bc3f5c41",  # PipelineAst
    "0.1.8": "90c23efa0950833d3be4ef50ba45c5dd04f17bd92190aa38e87e1bd50fa1f199",  # AssignmentStatementAst
    "0.1.8.1.0.0.0": "384736f2d648b42e4b5baa4890365c5055040e91917883bdadec0d09fda32573",  # PipelineAst
    "0.1.9": "bdbdf2b8353e1dc3e559b4851c0aae9bcb2d541b723203aa82bc4c575d264843",  # FunctionDefinitionAst
    "0.1.9.1.0.0": "c3c3829d8ba24cae6650f4fbe001eda6c820ef99e95da86c6a195432a9c80d3a",  # AssignmentStatementAst
    "0.1.9.1.0.1": "e8c32274688d50d148ba3b5c06ff20a07d9c6554c8fd205c79a64fbea318bdb4",  # ForEachStatementAst
    "0.1.9.1.0.1.1.0.0.0.0": "e848f3bc65219f0b1eb7a62d32f753ebf0774f556ccf2ae09350d965a31cd57d",  # PipelineAst
    "0.1.9.1.0.1.2.0": "7103457d4c45d3ec9982620a0d7e3c2eb4891e89f2aa93b4572319d1340d1884",  # AssignmentStatementAst
    "0.1.9.1.0.1.2.1": "b7457d43863e5106d8e1c24d9d036eca03564ac2b0a018506acb7e44ea5c142d",  # AssignmentStatementAst
    "0.1.9.1.0.1.2.2": "609afd062727a0af5c34de48d7b53bc63330bce85fa567e3778795c75d4dd7fb",  # IfStatementAst
    "0.1.9.1.0.1.2.2.1.0": "84357104c43af064ea4bc448213d791549720b892ebde9dd6d0e373ab85e547a",  # AssignmentStatementAst
    "0.1.9.1.0.1.2.2.1.0.1.0.0.0": "92e18646ae5201bd7561c04537bcb23b33b2471661c8b3fdede1b483623586a4",  # PipelineAst
    "0.1.9.1.0.1.2.2.2.0": "106e2eeca1fbb457a9dd9c0a8a66a17d0e39eba4183197d3fafdfb36013369c2",  # AssignmentStatementAst
    "0.1.9.1.0.1.2.2.2.0.1.0.0.0": "3fac83de6279669021a46df8f1bd5ce56fb1f75bfb4db50bbf09605375efde7d",  # PipelineAst
    "0.1.9.1.0.2": "8c9e04da447abe99314ce519d1fa36dafb4a705b0f56557f3370fe7aa954d150",  # AssignmentStatementAst
    "0.1.9.1.0.2.1.0.0.0": "b30561337247fbf734884af0f9b26d4f1029047f31d87f8fff56d15562dba36b",  # PipelineAst
    "0.1.9.1.0.3": "c444d247971de4acc78e1c035e8c6495d819a03b159ae45229dde74776268f91",  # PipelineAst
    "0.1.10": "ca7b70bf600c5eaa34a34293b36c83115ff512dbb2497275f24acdc6f3001d7c",  # FunctionDefinitionAst
    "0.1.10.2.0.0": "ce25ed7e66f4b04de934fb51cc812dc0909b333ec06da42aa6a61b0889db4f85",  # IfStatementAst
    "0.1.10.2.0.0.1.0": "00b329e88db7229be31acc6d8938ab00dccb6a2881f3f73a72eed28ed8af02a6",  # PipelineAst
    "0.1.11": "0af291c66846e474446ba80765e013d01001c4f63537d5cbd69801994b1689d5",  # FunctionDefinitionAst
    "0.1.11.0.0.0": "9d110f7c120d6ca8607deab4e7f6e6a34dc3abd984f76b838da58159aab0d308",  # IfStatementAst
    "0.1.11.0.0.0.1.0": "ec5093be6346080a11dd44dc7c99be626f58004902a243c765847c0b8206f675",  # ReturnStatementAst
    "0.1.11.0.0.1": "6bbfe97f77fc1a013ad29f18eec5faab1a2ed4e671c6f1c5e26eed04ee757e1a",  # PipelineAst
    "0.1.11.0.0.2": "6ea0fdec36515088ffd41555d8874879b839e2fd49b7f39e89095b220532485f",  # AssignmentStatementAst
    "0.1.11.0.0.3": "9d668eb2674ce2a35c2eb03ebf0eb4b841ab743f55bd86c238dad2f53bb3353c",  # IfStatementAst
    "0.1.11.0.0.3.1.0": "c9e61f9fda529f211fed1fb9f40b075ef472df9ffc2a76f120e4a40931970208",  # AssignmentStatementAst
    "0.1.11.0.0.3.1.1": "980ec92005a50844f962b4fad145c5befe47dbb8624287f050378f94e7b5823a",  # AssignmentStatementAst
    "0.1.11.0.0.3.2.0": "9da45d4a69c866f91e67f8131a30466a07f07de25324a2a70bd4f8e151542560",  # AssignmentStatementAst
    "0.1.11.0.0.4": "0d82dd04cc65a2ac3fe92af2cf9dbaa0afea3e27adb0cd5b4da0f654bab538eb",  # AssignmentStatementAst
    "0.1.11.0.0.5": "00850ed41603a6a31f8bc77eae50d70cfcb5dac247004fcb19475f5987fd8f4f",  # AssignmentStatementAst
    "0.1.11.0.0.6": "455cb03f5900dc4adbeb92d57c4486c8c2da8fd909a19eec302e6be3ff431e3b",  # PipelineAst
    "0.1.11.0.0.7": "998e47b24925d9a552e30dd9e7bb4796fbbb038110055fdc8f70932cb5fc06ad",  # AssignmentStatementAst
    "0.1.11.0.0.8": "1c197860aec950bc748c08a6621ef56b0857d09b56d2ba46a80c97908dd3b758",  # PipelineAst
    "0.1.12": "26e74f513ed8d540331a0b623b7fdb42dcb8f8a73d5c4cca683450cddb9c933a",  # FunctionDefinitionAst
    "0.1.12.5.0.0": "e612c8af8e4b7448aeab60662aab5ae98b328eab25072d80de6538184cf24909",  # AssignmentStatementAst
    "0.1.12.5.0.1": "51b655351a442274c185d9df1337511989fdf55b5c92a55bd82fdf256514aff0",  # AssignmentStatementAst
    "0.1.12.5.0.1.1.0.0.0.1.0": "1bea3a15e31d1489811c875793db1750a696cd3117879ac3ae68f86f26ebe734",  # AssignmentStatementAst
    "0.1.12.5.0.1.1.0.0.0.1.1": "f0e2f98da352ddf898ecfc3f353714c470061342ac0772d302f9c3cd4042f81d",  # IfStatementAst
    "0.1.12.5.0.1.1.0.0.0.1.1.1.0": "8e660ea1f7520cbf643e1c39e441627c00adeb883e9967e9c9d5701aa3121812",  # AssignmentStatementAst
    "0.1.12.5.0.1.1.0.0.0.1.1.1.1": "a682e010417416ad840652c2fe5d1daa4712c36a0e66f081a46b4224a2e25b6b",  # IfStatementAst
    "0.1.12.5.0.1.1.0.0.0.1.1.1.1.1.0": "829c3a645734206e1928aaad2e13118d926e2826e2e49f51e38f51c38288e8c6",  # AssignmentStatementAst
    "0.1.12.5.0.1.1.0.0.0.1.1.1.2": "7eca7d4b34afd71b8e01721d51133ecb6cb23b7c1c40d3ea371bc3ab8574e2ff",  # PipelineAst
    "0.1.12.5.0.1.1.0.0.0.1.2": "fca27b0a8b48a7873bc6f1e5930ff8871932508b12550f710fbdb26ecf5ab635",  # IfStatementAst
    "0.1.12.5.0.1.1.0.0.0.1.2.1.0": "2d60e913bba1cfd37812dabb00b8ad8cd222f4e12deaadc6e86c36dfd11fdea2",  # PipelineAst
    "0.1.12.5.0.1.1.0.0.0.1.3": "812f685d210e77154428218e3b2e13ff2cbb54f01b74439df3c5942f47ea398f",  # PipelineAst
    "0.1.12.5.0.2": "ce590f13a266c557384b926f28725431ec6b032b85bade556b5b5efae64e314a",  # IfStatementAst
    "0.1.12.5.0.2.1.0": "d220a30d83f55a9c01706effb800aee8a741534c4392d9f5348eea09b4b45316",  # ReturnStatementAst
    "0.1.12.5.0.3": "eb22f7a26b0c87c42373bfb5b937f04cb0680d699e8c80588278e1a837f76873",  # PipelineAst
    "0.1.13": "73a6465e93ea74b65e8bfbab761ee98f82ca8deb88428f81fa65ed851b1030f6",  # FunctionDefinitionAst
    "0.1.13.0.0.0": "8ffe6a2deb191bea0f6127f4040a2a363bc39a546da3f51caffe77cc13046e2a",  # IfStatementAst
    "0.1.13.0.0.0.1.0": "bb461f4c6deabf98ce8b565b88e323d6b98b5652e953773f2451e1ad03f5738a",  # ReturnStatementAst
    "0.1.13.0.0.1": "68ed3828b55124900291fd30b9474edc97ca5b278a33a731a0ab974413c0ea42",  # AssignmentStatementAst
    "0.1.13.0.0.1.1.0.3.0.0": "32eba412de40b1b54a4c4f5b08ff2aff2f6fc2e606f16ee8b596363eb3e77996",  # PipelineAst
    "0.1.13.0.0.2": "bbfd26e29f683f59636c1d7530b5fd5f14cb4af730d068850ad885c53f9763e4",  # IfStatementAst
    "0.1.13.0.0.2.1.0": "5fe3a82ea648c95ea4b7ed3614e20978b9bb324a98c9fe192350b8fca5dd657e",  # ThrowStatementAst
    "0.1.13.0.0.2.1.0.0.0.0.0.0.0": "e63b37c849715ae21eb75436faf277b994d90683266031111b15c5c81a3d2ac4",  # PipelineAst
    "0.1.13.0.0.3": "c84930c77a9a3eeb94bae74ef1835c90a8ef1283b0cccebcb5ae4f8e1abe4bab",  # AssignmentStatementAst
    "0.1.13.0.0.4": "8ef06c67b61d93eb19cf209bb5ffe301418be1db62c6b698dfa9c5b919eec0d9",  # AssignmentStatementAst
    "0.1.13.0.0.4.1.0.1.0.0.1.0.0.0": "5fa2634001b5f0bf41ec56327cff9cdbcf2e72097c81c2b7f464f08b4186c323",  # PipelineAst
    "0.1.13.0.0.4.1.0.3.0.0.1.0.0.0": "3a0da9fbf46d715e38bd786c6c594dfb794e21b490e95944d7feb61495a51e42",  # PipelineAst
    "0.1.13.0.0.5": "097b00d0d8f90cba34e107796a82602d235ac685d5a6f01be91ff6a6572abb28",  # PipelineAst
    "0.1.14": "3e9bad796687f25c1a373457bf91355ad00f09c7b9cded26e0efa809ab3b7edb",  # FunctionDefinitionAst
    "0.1.14.1.0.0": "50d11f8d59f8dc15d7d1d4a67b410019d709bf4b57a69c95139f49ee841d5249",  # IfStatementAst
    "0.1.14.1.0.0.1.0": "034f04e0d072ccea539ef6f0fc5c42e44be94958f3cee229b133d8b291683ff6",  # ReturnStatementAst
    "0.1.14.1.0.1": "014cb1f36b292f88eb8bd0ff0fceff6cf247b7a150589c0972b84a4febec44fb",  # PipelineAst
    "0.1.14.1.0.1.0.0.0.0.0": "9e31b3ca3eca9ecf8c189b1d9b62d7396563f123a4721b1e752fdef3655ef77f",  # PipelineAst
    "0.1.15": "1f92108609216e0c3f2e59c95ffa5cf47b039c24a1277d28e4890b16c8d17315",  # AssignmentStatementAst
    "0.1.16": "73da63b7688b7e736acb5f35b24e64708d35c1f2b16afa5ecb93aede2f5e29a2",  # AssignmentStatementAst
    "0.1.17": "7d8e25e702262a3e707469d456f082cb7c8f8e604be515659f42ce30126dde5b",  # AssignmentStatementAst
    "0.1.18": "486891f732fffff7f16d8547fa265a9fe4b92230d561206d3243f4865f8e8e06",  # FunctionDefinitionAst
    "0.1.18.2.0.0": "0b269a93c39d80d64588115a1fcf6a6cfc68e81d74f35491dba17d37e92c4620",  # IfStatementAst
    "0.1.18.2.0.0.1.0": "7052ab248ea66c5c5562cc74357b25fc941ce266220df845c6adcc0bf8e68b5e",  # ThrowStatementAst
    "0.1.18.2.0.1": "2e577763bc8f6981cd75aaeec3b47d01e05e4e77ce15adf58f606038e91e55a7",  # AssignmentStatementAst
    "0.1.18.2.0.2": "6b447743cb23335e3e34b18b8ee2fdeaf10f0dd81347217852be3d73e014d701",  # ForEachStatementAst
    "0.1.18.2.0.2.2.0": "9a489bb3d47c0c4fbf129e7a156c5fa10a8248d551a38b41db9dedd2a505244b",  # AssignmentStatementAst
    "0.1.18.2.0.2.2.1": "3c64fa9d476ab0d52fc3f33d4d817a7baa115da72ff9cb2fc81fe0cc9fc87292",  # AssignmentStatementAst
    "0.1.18.2.0.2.2.2": "2d2c2a11eb9111aaf523a2665efd85b907846ed4d62502b95cad85a7eb6dd793",  # IfStatementAst
    "0.1.18.2.0.2.2.2.1.0": "5c840c17b3ccefa112992e8c708f4e5114f6b79871c8a5b7b3c877c0c593a12c",  # ContinueStatementAst
    "0.1.18.2.0.2.2.3": "4e042208786b82ba7d49c7e5dc38f38e419aee61a31e4ffc37f5a6f3581aae3a",  # AssignmentStatementAst
    "0.1.18.2.0.2.2.3.1.0.0.0": "9684f9abff96187de4b9956517241f5f85008061df355640280d88f699cced8f",  # PipelineAst
    "0.1.18.2.0.2.2.4": "b12f617e4eddbec1b437d8a7653b64bb2a9d2e5210fc045243f83478c7dc9b96",  # AssignmentStatementAst
    "0.1.18.2.0.2.2.5": "834fbeac6b307d33d949bd12e746ee026dd0b38d50d24b15242ff1e62ed95a5f",  # IfStatementAst
    "0.1.18.2.0.2.2.5.1.0": "7482c8cfe586de6e54917a119db96d9f6ad253c0984570dbbf13d57a943f5e7f",  # IfStatementAst
    "0.1.18.2.0.2.2.5.1.0.1.0": "26faf7149ed055acac6e2835f65a13d9ea5aa4d18837f8a2166182fe043b1a04",  # AssignmentStatementAst
    "0.1.18.2.0.2.2.5.1.0.3.0": "ac02a2b9b909282fc3e9760fdf1ac8b33c0a8eb46b2474930f43249f58244962",  # AssignmentStatementAst
    "0.1.18.2.0.2.2.5.2.0": "d5705e74927a3f5c6e572efeb826dfa2fae117687ba05241cbdecacecfffde20",  # SwitchStatementAst
    "0.1.18.2.0.2.2.5.2.0.2.0": "d135f35d4ac65690daf0d4e73f8c829a8e577a38685cc6e40f6aa39b4d97d5bd",  # IfStatementAst
    "0.1.18.2.0.2.2.5.2.0.2.0.1.0": "7e6801a063737023a0739d35ddb4fdceb5ab12306f6be5e135e167531b3f8529",  # AssignmentStatementAst
    "0.1.18.2.0.2.2.5.2.0.4.0": "5020ec0063c7d5a08cba9961216bed96a5fdd919acc286a58def2adf42bcc55e",  # ForEachStatementAst
    "0.1.18.2.0.2.2.5.2.0.4.0.2.0": "983fced63a1a74609efb7913f80fd537c5635fab1b26048087f9e55ec9b1e63c",  # IfStatementAst
    "0.1.18.2.0.2.2.5.2.0.4.0.2.0.1.0": "d3da010a940663ea4413671fe02ff74542d1e20be0bcc1673889df7897e3d2a5",  # AssignmentStatementAst
    "0.1.18.2.0.2.2.5.2.0.6.0": "6baca9f24798831d8377c3e1e9a2c1c0a2cf4ff1ba6fe35d4f0c17661baba388",  # AssignmentStatementAst
    "0.1.18.2.0.2.2.5.2.0.6.1": "0b90b5b8a677f43b7b51a9bc10688307d047a24c6afccfe25aa750672926ba43",  # IfStatementAst
    "0.1.18.2.0.2.2.5.2.0.6.1.1.0": "fbf4a2ee1d94da7490e8375ad789a192670433c97c1df2725d4d01dbc421355e",  # AssignmentStatementAst
    "0.1.18.2.0.2.2.5.2.0.8.0": "3abafc3d7c5ff0c189420201c816b4402740e71004bef59a022a20ff73bad4dc",  # IfStatementAst
    "0.1.18.2.0.2.2.5.2.0.8.0.1.0": "15d15cc24ea0c8be2f4a864cf6a8381b298cf4a5b82a5dcb8f6cff40a0974277",  # AssignmentStatementAst
    "0.1.18.2.0.2.2.5.2.0.10.0": "eb09d24cd9ef249d032f7cf5b50dc46f8b5dae37066a602123548eef738567c3",  # ForEachStatementAst
    "0.1.18.2.0.2.2.5.2.0.10.0.2.0": "1fb9052553ccfa6d8fa2e2a0e453b673cf0978e6c6c39d8263e6f1c2032da5ea",  # IfStatementAst
    "0.1.18.2.0.2.2.5.2.0.10.0.2.0.1.0": "ce36c4fa8b6868db3dc59d01f55bf5b9ebb70ee5e019ed0a40defdc72efd1657",  # AssignmentStatementAst
    "0.1.18.2.0.2.2.6": "c2e7e5bc5b4d51af1eef83b4780ab8aa56cb36e91609a83c335419f5e2bd92aa",  # IfStatementAst
    "0.1.18.2.0.2.2.6.1.0": "29c379dab2492354c5f79b84761c866b54241cb5c4ed473696cc3a2f0f6f2691",  # IfStatementAst
    "0.1.18.2.0.2.2.6.1.0.1.0": "1a90d3213d4a9fcd4426085b82cdf4d6f3e910735878738936846b0aebc71897",  # AssignmentStatementAst
    "0.1.18.2.0.2.2.6.1.0.2.0": "322b8be6303cb46de1b2377bc231bed04fb23a14cbae57e76546426e1968a699",  # ReturnStatementAst
    "0.1.18.2.0.3": "e8d235a7fc829fb8f0d10becfa48c8810992fb14eddc0eb567cedf0f4f47bc7e",  # PipelineAst
    "0.1.19": "90de02726d6d00ee8fb191b79543b0c64ac41250ebdb67f93f617c2fd0c49f32",  # FunctionDefinitionAst
    "0.1.19.2.0.0": "f8126f071a78d2a84998e07902d9a93625e581b6bdad7726715cd67cd4ea19a8",  # AssignmentStatementAst
    "0.1.19.2.0.1": "519e8913bd4a5a42e2290ef326329460dd769057cd7fff1f7e9a2e2d37c90353",  # IfStatementAst
    "0.1.19.2.0.1.1.0": "b1c0ceb4c4e9e4a4be33f28e0be4c51b81f5a390b6890737aca8284cf71ab623",  # ThrowStatementAst
    "0.1.19.2.0.1.1.0.0.0.0.1.0.0": "873f1c03ff35ee63cc90b50665a652e822a718dc83581a479945713b19a43dca",  # PipelineAst
    "0.1.19.2.0.1.1.0.0.0.0.1.0.0.0.0.1.0.0.0": "a251ae577c1ac0d28115f9dc190af75cc835ecce0e52307b1425e0439226f435",  # PipelineAst
    "0.1.19.2.0.1.1.0.0.0.0.2.0.0": "d78d79814488ad3ef7927bfee833de7fcce8f28a53eaa073415f184b9b6b2def",  # PipelineAst
    "0.1.19.2.0.2": "42c1a271743fdf8b5b7aad42a98754e91bf908f7351752a33e772df102ac2151",  # PipelineAst
    "0.1.20": "c0ab94523ace228482be418cb3d7507cf855f40f6197ee254efbf0a49dd131d1",  # FunctionDefinitionAst
    "0.1.20.6.0.0": "5a68016271c9202746e46af270e52cc6b408bb10b2a7bbb4195cb9d41ae16389",  # AssignmentStatementAst
    "0.1.20.6.0.0.1.0.0.0": "e5d713e8cf8e7e953dcfbf5b3812940c6705345662597fba2eee99f591e2f63a",  # PipelineAst
    "0.1.20.6.0.0.1.0.0.0.1.1.0.0.0": "16b3e45ef8fef7fbacbee5cb934a411ca934d9d5af93ee6cccaf21969b58e3dd",  # PipelineAst
    "0.1.20.6.0.1": "0941dd987bb4ebe89ba3b08fc91e9ed67883c6554be21cb24686377475464428",  # AssignmentStatementAst
    "0.1.20.6.0.2": "f953f9db5cb2c267fac3a4a70d6805b464bc7433c2bec8a64a394b6f16f250cb",  # AssignmentStatementAst
    "0.1.20.6.0.2.1.0.1.3.0.0.0.0": "f6b9a872ab1e884adb4a3df825eae941b003eea30c0666d70d4995f2abca7204",  # IfStatementAst
    "0.1.20.6.0.2.1.0.1.3.0.0.0.0.1.0": "d4a23a4adf5921d3f90cdf81e51caa7bd7e9b620459da69b7bde121ef84d8b4c",  # PipelineAst
    "0.1.20.6.0.2.1.0.1.3.0.0.0.0.2.0": "471bdbd21d0c93e9c80b12e44cf45856bf44d1e6ff88d537542a9b7cf1a56b4d",  # PipelineAst
    "0.1.20.6.0.3": "5edc334f880104ad113fa29f37ca729cae61a9ed82634d154a866468b53d3306",  # IfStatementAst
    "0.1.20.6.0.3.1.0": "e11a24c8834cf7b4d4775d0800afc9b76669de5956499565421add3fe2ffff19",  # AssignmentStatementAst
    "0.1.20.6.0.3.1.1": "c27f1f9f24c11a2500131e2c98e9595f4e69d0ecedb99a862a9a6d83cb005008",  # IfStatementAst
    "0.1.20.6.0.3.1.1.1.0": "1496d5adf87213b5825ce2db6fe51fcba5ea13e5369fb5f1f0cf830fe9af4572",  # AssignmentStatementAst
    "0.1.20.6.0.3.1.2": "8dd51c163df87dd47f7fa96edf74db863cbae3c68be52b6b8222849fff48fcf4",  # IfStatementAst
    "0.1.20.6.0.3.1.2.1.0": "fe08d42f49ef99640734b0b75be6a9fe4c2b90d4d3a418e6f38611e76314641a",  # AssignmentStatementAst
    "0.1.20.6.0.3.1.2.1.1": "e35109d1ea4bcae08ae0694fcbfb617df1940d1721610bd638c0688c6908ff7b",  # IfStatementAst
    "0.1.20.6.0.3.1.2.1.1.1.0": "ed2e74b3d0ce028c2d4a7e7087e78068bcbba3d0917d60a77bfcd3a0b7d25325",  # AssignmentStatementAst
    "0.1.20.6.0.3.1.2.1.2": "6472ce3bcd23f1a6921d2d8a0b0f31561404ae3216fc9e9f82360547b94c43d3",  # AssignmentStatementAst
    "0.1.20.6.0.3.1.3": "e1273de977c366d44600037b71f5ebf0390ca5347e79d253f2c446cc8fe1c96c",  # AssignmentStatementAst
    "0.1.20.6.0.4": "1baa6ad9eac240915796269df0a16cce2ff2df301c9f997005e6e5ee27f6257c",  # PipelineAst
    "0.1.21": "249c6e29929f242af2eb64d84f08c08cd80b900fa78869ac1c27b26cfa72ac9e",  # AssignmentStatementAst
    "0.1.22": "f07ad785eb4cf320e9739f52f77118407a1a9f5acdfe7a39d97de8e8baa403ee",  # AssignmentStatementAst
    "0.1.23": "049409208c4057379efb7fe3fc546bd183ffabd78e2d575b195b0321864ba0ed",  # FunctionDefinitionAst
    "0.1.23.2.0.0": "deccaa4f24b96c9af3eed92dba3c8065ae7c4b2f1cee912484ec642bcbd41be1",  # AssignmentStatementAst
    "0.1.23.2.0.1": "0a32cc51e4e08c7515a8252837a5dfc5fa49844a664cea2a14e3d89c741bae65",  # ForEachStatementAst
    "0.1.23.2.0.1.2.0": "bd4535c2bdff8540cdd3df03f94958b56707d7fd24f1032130557440ed9a5b41",  # IfStatementAst
    "0.1.23.2.0.1.2.0.1.0": "c844fb61f8fc965f639eb3ad916fee141f6972cbbc282da5cf61ee1626eb0282",  # AssignmentStatementAst
    "0.1.23.2.0.2": "c21b086831265cb2689d2823c44f433bcaf32b4e6ae695871ebaf01ab3d6ea27",  # PipelineAst
    "0.1.24": "a6a0fedd333bc04ccf6f74adaab5ba483df88778bbf9c54dbeebb07561c263ca",  # AssignmentStatementAst
    "0.1.25": "92ad838f99d656c59c9193527043b9f603a59adaf5e6cd30084b501d02f9da83",  # FunctionDefinitionAst
    "0.1.25.1.0.0": "ae24bda32d789a56ffbd3f91ffe29dbb523ab6bfabe8624c5d3120ac69cf214f",  # SwitchStatementAst
    "0.1.25.1.0.0.2.0": "ee6101c7a8d62c5eed38b9d52c1718526514b6674548119e7aa86930da935baa",  # PipelineAst
    "0.1.25.1.0.0.4.0": "c2225c8340b0db3038abaa15e619430f0874c2fcfb3088385ced88732aa38021",  # PipelineAst
    "0.1.25.1.0.0.6.0": "c1b0a66f781914678c89008df12821f0fab589d6a08c3439a95c11024081180f",  # PipelineAst
    "0.1.25.1.0.0.7.0": "99732066dacce1f19ea69646620b1a2806afc0d496cd7e8b107f2987a5f2cc9e",  # PipelineAst
    "0.1.26": "dec3c3fd305d4e8fe90d3fe28676141709998f939a7f7c01d81cfaa5ae0ae188",  # FunctionDefinitionAst
    "0.1.26.1.0.0": "719e263b45a2a5c961c4b0febdacfc64c4b8ab54226455e7dd3de1d0ac905fff",  # AssignmentStatementAst
    "0.1.26.1.0.1": "fa85ef5279789a0d9a15aced187451cd482ae7933c9452355746190eb88ee613",  # ForEachStatementAst
    "0.1.26.1.0.1.2.0": "bd2b8f3150205d9787cc10cef14e3775d36f9e5267315a09335c7165400f5f92",  # IfStatementAst
    "0.1.26.1.0.1.2.0.1.0": "cf310c190cfebf3931f5d7c71ccd13f15b0a3e0a6ea71d8c5c0740e7e3e5b952",  # AssignmentStatementAst
    "0.1.26.1.0.2": "77aa8530d87c72b15c22554fb006a6708ec344516c5bcc945a68babd6f531fd2",  # PipelineAst
    "0.1.27": "4d95c42901337d6897900c3358f1708f46cff8050315630881509e46099e9df7",  # FunctionDefinitionAst
    "0.1.27.1.0.0": "c8d88a4e13e361c36a6cbd9716d1f06654f9d9d20e1a8a6eb00cbff90ef092fd",  # ForEachStatementAst
    "0.1.27.1.0.0.2.0": "be33b26e3d627bce4621a3507dfc0a911e8fa06d101c9ccb63d81f15496fb9ea",  # IfStatementAst
    "0.1.27.1.0.0.2.0.1.0": "aef8e9700e76e6205435f9fcf4a2a96d152b9c69931e88ef0752dc87bec5e20e",  # ReturnStatementAst
    "0.1.27.1.0.1": "e95d630806cea42f223aba34415d55003d48d32242bf8e32d6bcb61fb0e1b842",  # ReturnStatementAst
    "0.1.28": "2f804e834c36df84d0a19ce7b94b98b02d8dc6c612cdf8434cff4d6c6e195b32",  # FunctionDefinitionAst
    "0.1.28.1.0.0": "dfd2ab0a1d0594420340ed271bc40aa11273fe59f6b081f6f8594cccb01aa5a7",  # AssignmentStatementAst
    "0.1.28.1.0.1": "48fd8277361417f2cd3ffead658e086fa92063fc81c8fc31031ac13924b0a965",  # AssignmentStatementAst
    "0.1.28.1.0.2": "5f4eab61ce7aad5ae371bdb368d699b209479211c9cbc620365ca900ddc384b7",  # ForEachStatementAst
    "0.1.28.1.0.2.2.0": "dfa935fdd64dec53d6836b97291b7ada8e3eb164fd8d1f5af2938ccbd86e3da9",  # IfStatementAst
    "0.1.28.1.0.2.2.0.1.0": "893ca7386f5624b13b623558b846390bcc97208b91a72e4b1eb2f0128ea7a062",  # AssignmentStatementAst
    "0.1.28.1.0.2.2.0.1.1": "3047d8ce296b34f2c26efbeb4729a0f0bb5cf4fca39f5800c29bf8ba0e3ec9a3",  # IfStatementAst
    "0.1.28.1.0.2.2.0.1.1.1.0": "ac78582c67d5fb41dca93e143af1fb1fae73ced24b1f3a2221907ada6d70c09a",  # ForEachStatementAst
    "0.1.28.1.0.2.2.0.1.1.1.0.2.0": "b37bd39e3820a8f9d567e3150ccb9d8ea20a3e84ca9e948cec7cc9c22442f43c",  # IfStatementAst
    "0.1.28.1.0.2.2.0.1.1.1.0.2.0.1.0": "25f641e2e6c9a9628ab8ba3d5dc0c39a02119070fd67af4183ceb3cc30fb9b89",  # AssignmentStatementAst
    "0.1.28.1.0.2.2.0.1.2": "f2d5c3251c35d6e2474d18328545b7ebdf16025bcd2446fe4d5c3296b1a2d1f4",  # ContinueStatementAst
    "0.1.28.1.0.2.2.1": "9854eca5622b575d0236b9a00f5f5a0a1d04ed8df43003a1a6bbbbbc97686cdc",  # IfStatementAst
    "0.1.28.1.0.2.2.1.1.0": "2aeb01ff60a00d311d1537d2c0bd515913866af42ee82828512629568179a620",  # IfStatementAst
    "0.1.28.1.0.2.2.1.1.0.1.0": "6dd446e265eaa900666692e1780d2b2321d257ee18c8b65aa5fda36df6bd908d",  # AssignmentStatementAst
    "0.1.28.1.0.2.2.1.1.0.3.0": "a0c5192ad729bad4cc218db445bf6f19e7982262fa56f24760025a4ed47f0194",  # BreakStatementAst
    "0.1.28.1.0.3": "02f2f6f13b8ce7dedd4aa71cdfc76a0aea9fdb371a6877bda1145d163082599d",  # PipelineAst
    "0.1.29": "80bbb2e2a2cec3c90f328f052438050dd6efd7161930e98722f9b104e7fc52e1",  # FunctionDefinitionAst
    "0.1.29.2.0.0": "92caffa42c3673d0a2b2c52b33f69d018be01d066d8b00c886455f17b5ab618f",  # IfStatementAst
    "0.1.29.2.0.0.1.0": "2f5806c00cc2ff78eae3ef5ee7023f22052f121461f619d9d5d4e68627a06796",  # ReturnStatementAst
    "0.1.29.2.0.1": "48b1c3796fc4a2cae4c02d666dc86f1edf091ef02bda87b2eb18e333052bb341",  # AssignmentStatementAst
    "0.1.29.2.0.1.1.0.0.0.1.1.0.0.0": "9b30f385694ee527fca4253fd214335a3f1509cb0c4ff64b8f47b031febcaf35",  # PipelineAst
    "0.1.29.2.0.2": "42b7e584361a98ab53b5c236c24898c8a14f5e93368af7e662f72b5f7ec1d280",  # IfStatementAst
    "0.1.29.2.0.2.1.0": "50e189ee4eb7bd53921b2cf64362a9b129c96ffed2cadb43bc7a8462b13ce41a",  # ReturnStatementAst
    "0.1.29.2.0.3": "4a4c472423a530c3e66445e75d4dc2a4eb48e40956b3bbea90ab88219fca5026",  # PipelineAst
    "0.1.30": "ae8da6445840c88ba7a662f5b681b19e5ce126e710ca4f62bc1d8c1989f23658",  # FunctionDefinitionAst
    "0.1.30.2.0.0": "e5169631aa2868a977d46e7958c4c82cf0031cd866f99afcdb6bc366734c634c",  # SwitchStatementAst
    "0.1.30.2.0.0.2.0": "792cd8c4ad0a73052bcf04416e363bbefcdd478abff5d5a24290d2b850b361cc",  # ReturnStatementAst
    "0.1.30.2.0.0.4.0": "d78b1c4cd1242d1e56656aa71295188ce8c3e7cab64be1ee69b3a819a4f761ae",  # ReturnStatementAst
    "0.1.30.2.0.1": "524c8aa6659e021e6d6b708198df51aa25f4360cdfbc3d6658f25be9a938561c",  # IfStatementAst
    "0.1.30.2.0.1.1.0": "3ac528753ae0d4e9076723e5f9adaea1f16a76c6b583f3342b40a22080693c49",  # ReturnStatementAst
    "0.1.30.2.0.2": "6659c04daa779ac5d058dc3070487d1460229882ee1b4d307101c38db6cd7468",  # AssignmentStatementAst
    "0.1.30.2.0.3": "c750f58adb81c9f935c2f8d7d1895ae6008c0cab91034c022e355ad266bd50d3",  # PipelineAst
    "0.1.31": "cd7488e735c9a7120752aa29f532762eb7c69ba0676c16d56b0d3fd12faa6e12",  # FunctionDefinitionAst
    "0.1.31.2.0.0": "dadcb472b6db72685c56fe379998c85461d8a1cde08382e40c19d4090cb00fe2",  # IfStatementAst
    "0.1.31.2.0.0.1.0": "886b831083cd98e28907a77bb025ed8b5c6c024d3f9c06636801b6a9978bc405",  # ReturnStatementAst
    "0.1.31.2.0.1": "7c90c8bdba55f22190b2896ce28d737b19d9d5929432331d1591a20853fc7d75",  # PipelineAst
    "0.1.32": "1a49d4b68028ac661b9f56cff11a6a02e19fe1ec775df3d80c3d1ada022d4935",  # FunctionDefinitionAst
    "0.1.32.2.0.0": "d4c43dd7c5d477430d7ab089aeca44ae972f3bc0a2f6175cda209a91961b16ac",  # SwitchStatementAst
    "0.1.32.2.0.0.2.0": "5ff61d7b0c3ea5fca277d32217005551ab6100d2b18223e806566ede0cd507df",  # ReturnStatementAst
    "0.1.32.2.0.0.4.0": "e006a7f56463a10c74b482fcc920b2d50a28df00148288ebfed2f7dec800a169",  # ReturnStatementAst
    "0.1.32.2.0.1": "0f2e8a0963819141506f77fa27feec01369796ba16901e1b2fd1531601e7c957",  # IfStatementAst
    "0.1.32.2.0.1.0.0.0.0.0.1.1.0.0.0": "9fad9a387e014e1b7fe18920c64eab0f92d63f7b58986b6337c28e6e43f6b1de",  # PipelineAst
    "0.1.32.2.0.1.1.0": "6aa278f9cc2bbe87a3aea3ac977573c96dd415c7babc4bb2764c6f8f4a506bb6",  # ReturnStatementAst
    "0.1.32.2.0.2": "dcf53e8e13b80a2fd07297dfb85dc13acc6aa4853b0ac2575a0ba086e2e8b672",  # AssignmentStatementAst
    "0.1.32.2.0.3": "ebfae2b63f87dd27986f9691444d8fbb19e93f0ac83925088103b7f66376e52a",  # PipelineAst
    "0.1.33": "53ec9ec557aaf8955f297b157648f864930e03d4885377f86cf058ade149e2b4",  # FunctionDefinitionAst
    "0.1.33.3.0.0": "3d14553042d265bd478f1f2a1e36255b45c41156f76946ccf7ba1b16161b2e64",  # AssignmentStatementAst
    "0.1.33.3.0.1": "a96e65e62b1762016a63a0ea204207790d50a6b9a01304a41af8b3936a899885",  # AssignmentStatementAst
    "0.1.33.3.0.2": "c9dd15decd64fb8637ad19b29ddca06af41e085dd4dd990197e63f9242629fd6",  # IfStatementAst
    "0.1.33.3.0.2.1.0": "f059f9f9395f70be25574ad9e79bc680679b2a1f598887d65e61b08b013346d9",  # AssignmentStatementAst
    "0.1.33.3.0.2.1.0.1.0.0.1.1.0.0.0": "027c04bfbc2c139591a6b7dc758477fe5a9dc7e5c8cadc1ee3b589776d5c24df",  # PipelineAst
    "0.1.33.3.0.2.1.0.1.0.0.2.1.0.0.0": "0ced929b51659f923d4806e507c54a27b934d3790976806e0437c0fd1349dcf5",  # PipelineAst
    "0.1.33.3.0.2.1.1": "87bf3790f8ff1a8aedec1e39a68d4f7c90d113a570a887188e93e388270fd614",  # IfStatementAst
    "0.1.33.3.0.2.1.1.1.0": "5fcc449f19ac5f2c8cba8884bbc22859f7eccb7d840381cf7e05ca3da1f08bd2",  # AssignmentStatementAst
    "0.1.33.3.0.3": "d2b45f11a990cc19333c2aa49172fa350bc33ae0bde375e5679655ab879474d6",  # PipelineAst
    "0.1.34": "2abe3107db949bfd694f83483330a52e745f4cf3ab742a8e5aa1072b71705216",  # FunctionDefinitionAst
    "0.1.34.1.0.0": "3df781289f65507001ba1d6212cc461836f5d6fe3147f4326353d443f3628e98",  # IfStatementAst
    "0.1.34.1.0.0.1.0": "b1fbea2b35f311af2ccec43f170e1ca1d053f6a95898603b8dfe83799d520da0",  # ReturnStatementAst
    "0.1.34.1.0.1": "7a8fd408e85b93d4433e1f8a260914abdec2364961dce820b4fa84f612e3afc0",  # IfStatementAst
    "0.1.34.1.0.1.1.0": "392311973f097d00e52231a969d168374d92f0fee5fe0bdc7807305fbada108e",  # ReturnStatementAst
    "0.1.34.1.0.2": "bcb23f15ddc5a4610cef2c07ce779013236c12dae42062c4e8fddbd4dceeaa7d",  # IfStatementAst
    "0.1.34.1.0.2.1.0": "052fedd592329b00631689d772a4b0273b179eab00d2b165cc7a9436cd03289c",  # ReturnStatementAst
    "0.1.34.1.0.3": "34d55870b2cafd32529160336312c9b3d90e703736644d7cded54d3f3c3e2bc6",  # PipelineAst
    "0.1.35": "a6d28fdbe78c0bb2982ed0d76bfaf79f2957d4bc9873847da3fd06e52453764f",  # FunctionDefinitionAst
    "0.1.35.1.0.0": "96f5a144544ea992b892f01b8333f66f26fcce01f3320dc66bbc3773d21f5660",  # TryStatementAst
    "0.1.35.1.0.0.0.0": "1ec592653f528e91f79b9afa5575989a58cc597278600430b7cd05d21d2ad7a8",  # PipelineAst
    "0.1.35.1.0.0.1.0.0": "a8c91595790763a13a78a94960a315d9b80c9dd00a047accba75bdbaf91cb310",  # PipelineAst
    "0.1.36": "60ffc8b5eb825a7b9afe4d58523612a7104707792adf0ed074dcb7108211d05a",  # FunctionDefinitionAst
    "0.1.36.1.0.0": "92fa1d2e58e73e28f532f2e3e00221f152df6b8c485a8ad23bdf1352f97e069c",  # SwitchStatementAst
    "0.1.36.1.0.0.2.0": "c7f8bb47ed63580a1ae76a169281b54f13a4f532466c3a7fd2fe4266106ec8a2",  # PipelineAst
    "0.1.36.1.0.0.4.0": "932f1322e71fc094056b826988db96f0cb6f10b01f1e83e380cf638e419739e2",  # PipelineAst
    "0.1.36.1.0.0.6.0": "a9956f3bab0416db1b2565411a4690a6bfdea8ac5272b3dfacd379016aa337eb",  # PipelineAst
    "0.1.36.1.0.0.8.0": "c0729f972c8451d9a498ccafa9f4b240b3031ffa747f43f5d0536973833492c5",  # PipelineAst
    "0.1.36.1.0.0.10.0": "0a428b7e645eb9c9a5e84530d86080c5215515ce3b9de5ee050023d59154cb05",  # PipelineAst
    "0.1.36.1.0.0.12.0": "4dfc45a143d2ad0e18e51af9de7102e5d81d7e0534ee2b9bab01048ac3d67ccc",  # PipelineAst
    "0.1.36.1.0.0.14.0": "702b43dd697715ede7101a755370c045e6615719041da22736f70d8c7e7883d2",  # PipelineAst
    "0.1.36.1.0.0.16.0": "7ff613fa128289b9fdb1ce878a07ce1b1f6d5743702ee5f60b604e616ab921b5",  # PipelineAst
    "0.1.36.1.0.0.17.0": "97099736b75405886ef27f86a97be5a97c0059616f9a16dbb6322e7dc97aaeec",  # PipelineAst
    "0.1.37": "bc209dc55f7927ff8fd03a7af388d85cd8bfc351c066f37f622c38f8a1b6de62",  # FunctionDefinitionAst
    "0.1.37.1.0.0": "b87e0d13be51a869efc77fb7da58901e080264d3960b208bc71a1844750cb404",  # AssignmentStatementAst
    "0.1.37.1.0.1": "1f98c3b36f48f0c4283cc119513ffa999899c0475fcb1dc4b88ce449b6def53e",  # IfStatementAst
    "0.1.37.1.0.1.1.0": "ac38087f6911a0d8f86bcd1317dab1e6a59b1fcb4a6a5f96b5f9b765a63e8230",  # ReturnStatementAst
    "0.1.37.1.0.2": "22b4fc01c1b4914f9c32c614ae8832db2520c9a8b63dbd5b6411f878bfe31d4f",  # IfStatementAst
    "0.1.37.1.0.2.1.0": "508d2b08c36c8974f8cd953856cc4aa92f206c1bb0e530bb2edc2838dccd5733",  # ReturnStatementAst
    "0.1.37.1.0.3": "5ec163597b6ac26645705f278cc1aef76aa9f0071b65309c08ab64a6303bf4cb",  # IfStatementAst
    "0.1.37.1.0.3.1.0": "d175a9a58973218c1f9e710ac5b537be869e05422fc6da51ba3716b4754f7fc3",  # ReturnStatementAst
    "0.1.37.1.0.4": "b1192f4f0c2503d03d71ed92dc71992f6d913a35490ba31ead5a486683eddaaa",  # ReturnStatementAst
    "0.1.38": "1e8cf141fca2ff8bdaa76dbc02ffab443f8295356a5548fd34cabeb6b446285d",  # FunctionDefinitionAst
    "0.1.38.1.0.0": "5ef254f649b6e1a45518f956543854c9e579bc924c57d11771576a4250395954",  # IfStatementAst
    "0.1.38.1.0.0.1.0": "8014ac7de07c932d42ae6bb968e388f07a891387e15d75ef2ef17e4a70c4fecd",  # ReturnStatementAst
    "0.1.38.1.0.1": "36c3cc234680ebff18a7584a0a2c289088a32a7cf6e4df5b08aad81e12eea28a",  # SwitchStatementAst
    "0.1.38.1.0.1.2.0": "51a8b70df0f4a942326714d83da252a8b16524cbf8ced8cbe46c3e8f8559148d",  # PipelineAst
    "0.1.38.1.0.1.2.1": "c525e340aa7b11a5ef19d0ff841d90cf930e9f574619822677a936713117cbf0",  # ReturnStatementAst
    "0.1.38.1.0.1.4.0": "3f32c73498f3a38e24e4f4c52fcec9e0a14508092fd46ffe7dd2ad510a25b406",  # PipelineAst
    "0.1.38.1.0.1.4.1": "5d54c6253231b6876366be605f3b06975958bb5f652f069a4b8ec35354025ea0",  # ReturnStatementAst
    "0.1.38.1.0.1.6.0": "c242569f84d88b92318b1e41da5e8255bb38ad658d2373e2b2c68b5d2df0ea17",  # PipelineAst
    "0.1.38.1.0.1.6.1": "133308619d297e9e7a0141034fb931f2d85ca62f9ca4b890b1c11c850d0db8ac",  # ReturnStatementAst
    "0.1.38.1.0.1.8.0": "f7d5fe2982cb6f259d2ebc79bea444bf8ad2b34efb918ca82da7c264833f7593",  # PipelineAst
    "0.1.38.1.0.1.8.1": "7193461020c990b03c3ad2301be6d19d5c048278a680486b6f0e18c921b53900",  # ReturnStatementAst
    "0.1.38.1.0.1.9.0": "5a1da3c37ba39d173f98bf882239682856bcf33c9ab66b07648b5768b256784e",  # PipelineAst
    "0.1.38.1.0.1.9.1": "3a95c1af5ccd6e2daf2fe52859ab92cc39bda291f45995ad14acf183bbf36afd",  # ReturnStatementAst
    "0.1.39": "9767b71368a55ab00f5c39ab93f0b1135501d3f0045ebffcececc1a24029eb69",  # FunctionDefinitionAst
    "0.1.39.1.0.0": "5d18f600162455b9f58361201a431f7d94b2d6611c040554ba6aead8e1a4b651",  # PipelineAst
    "0.1.40": "ef2e76794817e33f4ecce6d3f1061ab606122d0b7724d40510ee2ef8e06797d0",  # FunctionDefinitionAst
    "0.1.40.1.0.0": "4831a9e44b1ba82a67f5c3db1a9a3b0edc209a536ec9a60ac7a64739a06c6e80",  # IfStatementAst
    "0.1.40.1.0.0.1.0": "6c498f59f3c6ba8063100e907b5d5449f1b5783d4d2b4ed21d64782448caae6b",  # ReturnStatementAst
    "0.1.40.1.0.1": "a7fc82775401ddf6537dc6ad6fa0d41d723b70c75783d63dabf15c9587b523de",  # TryStatementAst
    "0.1.40.1.0.1.0.0": "8016f12d80b71881ed71eaef2b2fb2e5fb9c2d808391eb65f80e2cff1a017701",  # AssignmentStatementAst
    "0.1.40.1.0.1.0.1": "69600a078234fc427d9e0dfbf63274960bfba2e775606ee69bb758e32192d109",  # IfStatementAst
    "0.1.40.1.0.1.0.1.1.0": "600964e397bc3116a70ab986dac6f9f0911a7635df5605888f479b976c072588",  # ReturnStatementAst
    "0.1.40.1.0.1.0.2": "dd46c6dcce1dbb7a99554918d5ee8ff929f97cb9d3c79ff5dca2ef51dfbd7336",  # ReturnStatementAst
    "0.1.40.1.0.1.1.0.0": "2b1b5cd597451f44bc2aec31a5fc9e430c21cbe699978285bcb1d7268b1d1802",  # ReturnStatementAst
    "0.1.41": "59827f80e531c7ac09189c606037f1d8d69a91f7ba7a9f82d76779681c547f90",  # AssignmentStatementAst
    "0.1.42": "bdfdd0813810c9f078f46eca089f504a3cb76445511fd49ab53a8b3f68f1e98f",  # AssignmentStatementAst
    "0.1.43": "c15c3072fcca6eb5a2781c29ae1715fa305dde03375d911b2b5ef425581a77bf",  # AssignmentStatementAst
    "0.1.44": "b0a67b029182a45bc4926a31012ea816341d7748eaecef69dd8e76bcd7905ec5",  # FunctionDefinitionAst
    "0.1.44.1.0.0": "72bbb228495d5c901365e4072761f806b8776735fa4f20996705d1af1ea58e74",  # AssignmentStatementAst
    "0.1.44.1.0.1": "3e0cab9046d20bbdd5ebb8cda5c18795288620d1703a0de7e55347eb5428200e",  # IfStatementAst
    "0.1.44.1.0.1.1.0": "4c462cc72fd9a9a30eb62ac67ce1318e68a4b6915f6719a118d8d5378a2d5e95",  # ReturnStatementAst
    "0.1.44.1.0.2": "db6aea8a2db00a2b3de7ebb6ab41f65d451ac4b1f83dc76105a9f45cc5872bf0",  # AssignmentStatementAst
    "0.1.44.1.0.3": "1fc04f19cd1a5bab0918ec46dad34e09dee0713917f393e0848924f2c73da74e",  # PipelineAst
    "0.1.44.1.0.4": "e1fe5fbb7de68d911705039130778ef3de1953badd4d884acc1801db8fca4e62",  # ForEachStatementAst
    "0.1.44.1.0.4.2.0": "a63d46c867ef7fd5706637d5a495fd2e776de6743db89a0a578ae13be0908038",  # AssignmentStatementAst
    "0.1.44.1.0.4.2.1": "a84909d9ced2e6cb65ec24052857df9dd7b7e1e0dcca7dddacc3956308930e0f",  # AssignmentStatementAst
    "0.1.44.1.0.4.2.2": "165b613593cc3f288e96f99f1dbd363a170a0f440b3b8f4090aedd3dd366eed5",  # TryStatementAst
    "0.1.44.1.0.4.2.2.0.0": "62e93d0efe2a7bc170cdd06b5bc56db76e14df7e837041affb01608add55ee42",  # AssignmentStatementAst
    "0.1.44.1.0.4.2.3": "fe7591e83de6cae2c2649b8ed35c6d219b630a5dfe68f67db57314107b555d0c",  # AssignmentStatementAst
    "0.1.44.1.0.4.2.4": "813436693f23f4462c55e4125c30b71f1706eda9b158c4890924cd7e6303c3ab",  # AssignmentStatementAst
    "0.1.44.1.0.4.2.5": "27c0170900fbf8043c5e8305ff43f0815d865510ca51235bf1a051e42733bb94",  # ForEachStatementAst
    "0.1.44.1.0.4.2.5.2.0": "1a46f8d0de8a0817e443dbeae7a5bbdf832c19bd0cbae096da5579c40d81b883",  # IfStatementAst
    "0.1.44.1.0.4.2.5.2.0.1.0": "0f7b916c55455105db604e0a5e16c3f2206af629b0cd110d79703f80255308b9",  # IfStatementAst
    "0.1.44.1.0.4.2.5.2.0.1.0.1.0": "52c616ab60575093d4d95abb6b007bfb7b3cbce9da72e4f6417a31565a4f6628",  # AssignmentStatementAst
    "0.1.44.1.0.4.2.5.2.0.1.0.3.0": "1e171a819e26166d5673e65ba7a9faf41b79aa9755ea5ddcb306e5085f8cc11c",  # AssignmentStatementAst
    "0.1.44.1.0.4.2.5.2.0.1.0.5.0": "c8adc6914899fa56533a256f38ea23bdc14fa9ec3840750ed6f0c901a06b4d7f",  # AssignmentStatementAst
    "0.1.44.1.0.4.2.5.2.0.1.0.6.0": "76a46b5a41f7b2de3d400c7fa87d76405f85fce97ccae586868f58bfd559b5c6",  # AssignmentStatementAst
    "0.1.44.1.0.4.2.5.2.0.3.0": "f4d882fe8e0ddd21eaed34bc169baef2312ea6a79a0a1fa4f918fc6cec3aef06",  # IfStatementAst
    "0.1.44.1.0.4.2.5.2.0.3.0.1.0": "1add2cb3f7a3b6c63331d8beec6b9de45adcdc258f067a46c5921ee9bab82c40",  # AssignmentStatementAst
    "0.1.44.1.0.4.2.5.2.0.3.0.2.0": "28e8ee25663620722536246ebde4eca2a83c80206deb7cea351f8fb605957a73",  # AssignmentStatementAst
    "0.1.44.1.0.4.2.5.2.0.3.0.2.0.1.0.0.0.0": "e08528756236bc03d43ede1cd61803c38d0912d5ace5c1428793d1adf5529352",  # PipelineAst
    "0.1.44.1.0.4.2.5.2.0.4.0": "d7e62b3bdbd94410446e8f71e30d3662cdc77074c569c57f431885b56c33b487",  # AssignmentStatementAst
    "0.1.44.1.0.4.2.6": "0dbd1e8af87dfb15f6ffcd8805104ce92ec56a3f4f79c80dca96d950b7ea8e2b",  # AssignmentStatementAst
    "0.1.44.1.0.4.2.6.1.0.1.5.0.0.0.0.0.0.0": "1b05f6a21fb4dfd2275d19936c0eb078373291f1166e98b8dba88c821036cf61",  # PipelineAst
    "0.1.44.1.0.5": "77d4650216e7b74913a15c62b639e6226dc5bcd345c4560cec3b25336b81c2af",  # PipelineAst
    "0.1.45": "df418ec9dd45c90372f5710de090d5438ee9646da09387d3fcae494c4645a1a3",  # FunctionDefinitionAst
    "0.1.45.1.0.0": "bac54ed78e9de4896d089c6e1d96e28265a7d86bbbc9d2c9fdf1ab16334d8ea3",  # IfStatementAst
    "0.1.45.1.0.0.1.0": "af5a3d53fa65f2e46dc44c7431d071e010c05ab1f790b97a9b0b16a6d85f6025",  # ReturnStatementAst
    "0.1.45.1.0.1": "af44d1e1d210988ae9323cf55f3efd62661a131a5c2d65600f5e19be3da93315",  # AssignmentStatementAst
    "0.1.45.1.0.2": "1730e88783bcba1ddf07f765fc1dcbd970acfaa619e8c46eba391f62dfe02264",  # TryStatementAst
    "0.1.45.1.0.2.0.0": "0a467db7040ff1bd3bc418ee9573f7143d1981ca2ef03bcc8e0e09b41479e65f",  # AssignmentStatementAst
    "0.1.45.1.0.2.1.0.0": "50e269e76e6bfa6731978a84e3968b3176ad31b03aa00a7471f4ada5cff923ba",  # AssignmentStatementAst
    "0.1.45.1.0.3": "356a8294a5c98dc2f4ea9a043f11064582437e7c18dd98113d1349ae6b8a53d2",  # AssignmentStatementAst
    "0.1.45.1.0.4": "f5d01b21e0396177a651dc3d93dca848df33a8d89ef01590e084ca717009d4df",  # IfStatementAst
    "0.1.45.1.0.4.1.0": "0cf75299e791ca405d6bc16efd580f356383660eba41108debbcdcaa11e32594",  # AssignmentStatementAst
    "0.1.45.1.0.5": "059476758a4937705917442eea05d617cf75bf73982fe069aea7dcad3a999001",  # PipelineAst
    "0.1.46": "8f356a5121369059d9379af4d6b045b0ea9d6f2499d5436feafe468a1b0c2ad5",  # FunctionDefinitionAst
    "0.1.46.2.0.0": "c2488d5cbb6dca86cfc278d7a822deebff39299866e3de7a2a9d581b86588fcd",  # AssignmentStatementAst
    "0.1.46.2.0.0.1.0.1.0.0.0.0.0.0": "811fb2669555bd88b10555012180651e6d81e062594f016b8c7c2c2aed8a72d6",  # PipelineAst
    "0.1.46.2.0.1": "7681ddfeabe03d80fb18b7a7979c275d1d0e09668a33aeda45ce2e222105d3e2",  # PipelineAst
    "0.1.46.2.0.1.0.0.1.1.0.0.1.0.0.0": "0d222eadab0aaa02c25b58298e1b33b26a10374357b03936d8ac387624a846f4",  # PipelineAst
    "0.1.46.2.0.1.0.0.1.7.0.0.0.0.1.0.0": "46bc7af51fdaafd04a9442be8f11a43987021c9f7aa18aa875c7f53afbabcb51",  # PipelineAst
    "0.1.47": "98ca9333d43c78bee3943bd6c14615be75d0a24444da938ed60ca6ef21aac8d2",  # FunctionDefinitionAst
    "0.1.47.2.0.0": "87b445f57650384f69598aa04bc73357590ef133270476c2befc5081de4c06d6",  # AssignmentStatementAst
    "0.1.47.2.0.0.1.0.3.0.0": "0ce39eeb23feed3326d184d4b98b5daceeaa11adb357f73e1d8471d925dd5ff5",  # PipelineAst
    "0.1.47.2.0.1": "576f917b582650f945b429ff3a715c8b8b88e389cf6b5de8256f8b793429ef88",  # IfStatementAst
    "0.1.47.2.0.1.1.0": "3676a9026eab4cac7498875f77d8876e9fcacc93bd6c6dbd4cda0f112b877c4e",  # ReturnStatementAst
    "0.1.47.2.0.2": "3ddb98208b0d94ac89f1d9c6feeff1efc2d4e8a2cf1a0a40cf37673742273480",  # AssignmentStatementAst
    "0.1.47.2.0.3": "602b72749f215d9b73da910c7fedb1ec4dd74338a2a0b81e7fdad496fbe7e54c",  # IfStatementAst
    "0.1.47.2.0.3.1.0": "5f2002d5ec6b5412fcb4bf2b20dd7cf309e777c64d98b122437acaab62ff9353",  # ReturnStatementAst
    "0.1.47.2.0.4": "fd97a22db1fa50ff41192d9e1b47ed1e6b2869d4fee5bdfdb6211eeb5495fa97",  # PipelineAst
    "0.1.48": "a155c07d7fc6a00deae2875ca9d686ba4e4549aa09b9023704b7e068449e3d0a",  # FunctionDefinitionAst
    "0.1.48.3.0.0": "279dcf6e8f4b2ab0ea1332ae381d38d39a70904a89b0a9d5c233b5d1825177df",  # AssignmentStatementAst
    "0.1.48.3.0.0.1.0.3.0.0": "9eed2d9c10ce6171a8d8822b7460b9f5f8d2db79daf1648a4bc3b6c3d22002cd",  # PipelineAst
    "0.1.48.3.0.1": "e71000004e316762552696903b53c69e1f23d40a3cba4d406988bc15058a5cc9",  # AssignmentStatementAst
    "0.1.48.3.0.2": "af2efce3a274dfb3cad95f58234fc9eacd42ee56b024f6d3750abab6e326fb96",  # AssignmentStatementAst
    "0.1.48.3.0.3": "532efcd48b41cfbf3682a22e0a83037728443115b4d51b67cb2a6f563ef5ded9",  # ForEachStatementAst
    "0.1.48.3.0.3.2.0": "15cc25ec8fce3a16a23d7285695879ed85533559dff3df37c3bd46888eb74618",  # TryStatementAst
    "0.1.48.3.0.3.2.0.0.0": "4905c149d8d7efa2862c31a2efdec4542ce35ef4589e6b6662e9765bfe078201",  # AssignmentStatementAst
    "0.1.48.3.0.3.2.0.0.1": "98adb61016a0ce238d9a71e9485c682be4aaddf1c3101b64abc498db4f6a5400",  # AssignmentStatementAst
    "0.1.48.3.0.3.2.0.0.2": "90c7da03d3883d670ab0a4886a277b0f405e41840eb83fa809060a6be543d8ff",  # AssignmentStatementAst
    "0.1.48.3.0.3.2.0.1.0.0": "3b487d2aad7ffe8a1da089ffd85cf9d5b10db9700aefe053a7b949bee8266b38",  # AssignmentStatementAst
    "0.1.48.3.0.3.2.0.1.0.0.1.0.1.0.0": "a6e161039bea297ef5a0458085c08292965cd1c16f83272c2fe0c548f749523c",  # PipelineAst
    "0.1.48.3.0.4": "7220dd5165c5abda559434155ea6f8c5b464b21a3b108d0a5df6bf4daee7db19",  # PipelineAst
    "0.1.48.3.0.4.0.0.7.0.0.0.0.0": "8acbf04ab2e26de0026cd2a7d269c989e4e381d00dcab24f481dad72caae9597",  # PipelineAst
    "0.1.49": "069ba816c515ab365c66a57184461980d6a51c6e7e6440a6f1b906fbb7f06844",  # FunctionDefinitionAst
    "0.1.49.1.0.0": "8441b9db35d785812adca406684c0e5505aef00036a8705b1674709ee08d139b",  # IfStatementAst
    "0.1.49.1.0.0.1.0": "43d0268a16e6b74b8408ea1953ae98d21dd72d0804861d3e8e4f63d6f6bc2e14",  # ReturnStatementAst
    "0.1.49.1.0.1": "977b1abc4f54c3d1206ed4dd770ef7cb3967d9c126d12ebb54fe0dcb40210584",  # TryStatementAst
    "0.1.49.1.0.1.0.0": "b36bd12f98695ad28852ced1b5a47573830ba9b83e33ceec626d43976515005a",  # AssignmentStatementAst
    "0.1.49.1.0.1.0.1": "3043bb9bd599c85b0d55a12a5ec4b755c80bbf7149640b7b578068f5ed046cbb",  # PipelineAst
    "0.1.49.1.0.1.0.2": "d8b8377de2a4e50759e479bddc3fa726161425cae2406d23c46bb1fc76b08eba",  # ReturnStatementAst
    "0.1.49.1.0.1.1.0.0": "f0c19095918307c89c191aefec6389201a1ff585df4763519509a9cd3cf8255c",  # ReturnStatementAst
    "0.1.50": "b71d91a9af73ac0260f9f067acd592067499573f08093da7fe06fb556d20b228",  # FunctionDefinitionAst
    "0.1.50.1.0.0": "b5e6b5dd8910bd1dc4d2010777c6b0f7519595beea4aacfc1d78c2b688cff331",  # IfStatementAst
    "0.1.50.1.0.0.1.0": "bd776fbe6156ac3354fb84a645c4504205835521db0b10ef31be313a1f338110",  # ReturnStatementAst
    "0.1.50.1.0.1": "aa6b70917e76b8fce2cd162ac00dee9a260fec55482ad71961fc9752eda0de5d",  # TryStatementAst
    "0.1.50.1.0.1.0.0": "08667d082305866f533264188f5da786dc53c1271f376f81e81ffbd471db6fe7",  # AssignmentStatementAst
    "0.1.50.1.0.1.0.0.1.0.2.0.0.0.0.0.0": "5391d128c2bad45d6fd712827af40a40554adbc31ea1df81579b1c6d92b6745b",  # PipelineAst
    "0.1.50.1.0.1.1.0.0": "86564bf0bac6fd3258e1b2a2465ac92057c719325d942727396c6c38088f8c7b",  # ReturnStatementAst
    "0.1.50.1.0.2": "e14fc28c560ea7f2ec6408680b77446be99ea1aa4ee8f67d3e6f0f0fb2fa245c",  # AssignmentStatementAst
    "0.1.50.1.0.3": "06d6accb821cee8576e6d1e7b90ec245ee312f88988361c015f546e56be99098",  # ForEachStatementAst
    "0.1.50.1.0.3.2.0": "52b7abd59d278f3d0d29302dbc3f84d6044c082a8498763c5088d6fb8fd62d91",  # AssignmentStatementAst
    "0.1.50.1.0.3.2.1": "32b4d1676edafaf6c184179c4d6ff8818c70d25ae72bceacc53b0d93bb5b5c7b",  # AssignmentStatementAst
    "0.1.50.1.0.3.2.2": "5e72636ffea8955561a50533e502ef36f8ac7dcd06581eb609a72c947984912d",  # IfStatementAst
    "0.1.50.1.0.3.2.2.1.0": "207d1093ecb6351392626873f3318e3f75c4aa999a0948b5e827a486286e2edf",  # AssignmentStatementAst
    "0.1.50.1.0.3.2.3": "dd480aadc9c5c7f0cec56778e18e86ee10563430d387b22551c4daa6222447ad",  # IfStatementAst
    "0.1.50.1.0.3.2.3.1.0": "415c2527abb3227ceb2717b7478fa3e3a10fe43a1a0a3b196b296cf3f901d5d6",  # AssignmentStatementAst
    "0.1.50.1.0.3.2.4": "19f20b9ff9e10e30e2ec7e2b46a207cd8ee8417408d68755d4e3c15875172315",  # IfStatementAst
    "0.1.50.1.0.3.2.4.1.0": "c6e7aa548ce252b861578c2058cb7a2c3b15bd79e56b80e28d603dbe759052b4",  # AssignmentStatementAst
    "0.1.50.1.0.3.2.5": "d5e11a73a4d59cde5b6dfd90aa614ce5b5e6851f3ac387f6fcb907129063c67f",  # IfStatementAst
    "0.1.50.1.0.3.2.5.1.0": "97fb00e6c0775d6ff10fadff830572f223305239d5b37f0b8b71f544fbf085c2",  # AssignmentStatementAst
    "0.1.50.1.0.3.2.6": "21a0b573e3c9bfc9af90b3fb694525c47cb18690823ee50d45b8fef001376bee",  # IfStatementAst
    "0.1.50.1.0.3.2.6.1.0": "b68b9acf01ca6e5869a8a0578492d2de2ae07c48e2f82dc7eacdd3e717929630",  # AssignmentStatementAst
    "0.1.50.1.0.3.2.7": "dca811c1985f77654c6e8108e45e664d0aa56bafe24e3c4fc7499d0b6b67f687",  # IfStatementAst
    "0.1.50.1.0.3.2.7.1.0": "8f404c92d27621af0465c884c66ccd8f35542c1be97036833b99313c1429b446",  # AssignmentStatementAst
    "0.1.50.1.0.3.2.8": "0c35e781092979c821890d8a9b1660bc26936176cd2c7b1ea74ecabc42b4141f",  # IfStatementAst
    "0.1.50.1.0.3.2.8.1.0": "2538748a795a45e3f3a7e326e1ac50332210e70e2cfb9f67a8c48c801a9061ce",  # AssignmentStatementAst
    "0.1.50.1.0.3.2.9": "321bf48ae422e6da66700d499aeaabc4b5ba1adc6c61e91d5b0deeaa1fb9cdf1",  # AssignmentStatementAst
    "0.1.50.1.0.3.2.9.1.1.0": "8a296c45d11fcdec01466e57ae5cdc40c06c6b8b244d37efe83177ab2b9a5ad1",  # PipelineAst
    "0.1.50.1.0.3.2.9.1.2.0": "357eae7234543e1879a9ca73ba0e0cd0ac5c3333d04b47900206c0a0f7585e50",  # PipelineAst
    "0.1.50.1.0.3.2.10": "69a714c976850bd9dc13868a1cdcda37ebec7648cedab0d0ae9dfadb777538d4",  # AssignmentStatementAst
    "0.1.50.1.0.3.2.10.1.0.1.5.0.0.0.0.0.0.0": "1d6f678b1307da13d10a45345b58ee48fdf0f204a30797fc4ea953f8a0313685",  # PipelineAst
    "0.1.50.1.0.4": "d7fcb385e08f85afe24d8566d1a94c54e900503546dad2c217069c0df7182bd2",  # AssignmentStatementAst
    "0.1.50.1.0.4.1.1.0": "85a0bbafc39bfedecc09d95394ade4d511743f13a9617ee2949c751cf6250a43",  # PipelineAst
    "0.1.50.1.0.4.1.2.0": "30b97840f83c325a77fc99768339311e6e41558f3b931539131e09cb9ec33387",  # PipelineAst
    "0.1.50.1.0.5": "16dc71648199d421c27330373caee5144e3cbed3a14ba45f32fb92919542a8d8",  # PipelineAst
    "0.1.51": "e51c4a0c9268ddd90f5aec0cf7fa1a74d76418a242b052804fa186a070f1d9f3",  # FunctionDefinitionAst
    "0.1.51.1.0.0": "15ce64b3231f8a166c2ecc2e1d0a421fbc9b18e2040a3f81eccafa52a3793007",  # AssignmentStatementAst
    "0.1.51.1.0.1": "d93b5431a9987a3a0e0d33024a7bfbee918b4d8fd20324b2658d186e2d393eff",  # IfStatementAst
    "0.1.51.1.0.1.1.0": "3b9ee9bee52af96810b46dae99428177699d7054a22ac9651aff70a1f2c30d99",  # PipelineAst
    "0.1.51.1.0.1.2.0": "a7fb01dbfcd126c03b34199abb95c09933559bb97ccfeb90dd0ca1fa14026cea",  # PipelineAst
    "0.1.52": "08c8ae54919aa7f06b85cd43c61d9960a37f17a7e11f20615f52b704c46b1dda",  # FunctionDefinitionAst
    "0.1.52.1.0.0": "9a6ac3764275cb962a986595f0b7c343b7c14b1930b8ab76f20b2ac00a30bda9",  # AssignmentStatementAst
    "0.1.52.1.0.0.1.0.1.0.0.0": "f1f4a4b4bfcdaa80c394bb9bc61651a64295844e80600b931dfa39846c54f2ff",  # AssignmentStatementAst
    "0.1.52.1.0.0.1.0.1.0.0.1": "9ce4b7c6fd70661513483641640abf8816b12c90ffa7a3f25ae103ad67b29dc3",  # IfStatementAst
    "0.1.52.1.0.0.1.0.1.0.0.1.1.0": "d546ab890320ea7497087c56cf4dcd4c053347c4aeb575f4556f10aa5d382383",  # PipelineAst
    "0.1.52.1.0.0.1.0.1.0.0.1.2.0": "0e428d21bea90ae60c018c2a74092f3d2197f253d852e954e8f422cb05d859b0",  # PipelineAst
    "0.1.52.1.0.1": "0967dc35b0acc28da509144363969a9ac978b914cd9a6487245b1b14837f9b13",  # IfStatementAst
    "0.1.52.1.0.1.1.0": "ac802e80a4eb5b50b8eb58ef709cf419cb6b5b44892e006bce7fe8116093c3cb",  # ReturnStatementAst
    "0.1.52.1.0.2": "5609601803133f8961caee1ef181ee7444c0e6ef265479c9d583c121b1da490d",  # PipelineAst
    "0.1.53": "b94ef0feb775568bdffd894e61f2e57c4915bba5867399eeb539eedecb340226",  # FunctionDefinitionAst
    "0.1.53.1.0.0": "e5391fa02e494d80a3c8efa199e3b956ed0eb0fef9f209cba1ab7486ee2fd4a4",  # AssignmentStatementAst
    "0.1.53.1.0.1": "36a2e159282f4619eb1564e7420c841f7e0df6563f88457734b19c75d4b7c064",  # AssignmentStatementAst
    "0.1.53.1.0.2": "9bf3600b308ec492cb0b9c06b9efcd94b1c1c628668ee055643efd7aa78012d8",  # TryStatementAst
    "0.1.53.1.0.2.0.0": "cb6cfdb0e385643daae581795517a77a6df0fe6bb36ee3fb2a1a6bb8a36ba130",  # AssignmentStatementAst
    "0.1.53.1.0.2.0.0.1.0.0.0": "ea59093495bfb5e8bcaf4f3777a25ef269066c84bdc6bd0635f40b0b26621f0b",  # PipelineAst
    "0.1.53.1.0.2.0.0.1.0.0.0.1.1.0.0.0": "942c31185aafb8de6ac13e42eff696d294a66fe5fca4a2d192c4c76727a5f022",  # PipelineAst
    "0.1.53.1.0.2.0.1": "0d5a4472b04d45b4d785be78f98a61295cf0aaba7e61e664845a7bb615168b3b",  # AssignmentStatementAst
    "0.1.53.1.0.2.1.0.0": "a2541eafb660effcfe967a402e6952b8a077bf436a0275242853064a26eba2bd",  # AssignmentStatementAst
    "0.1.53.1.0.2.1.0.0.1.0.0.0": "bfae62203c216f0b6272b0ec24528853dde13edd01f0b743d7478d1550888d50",  # PipelineAst
    "0.1.53.1.0.2.1.0.1": "187fcedc3148056e3f901632a59296ca29ea174a09f2c7613d960f5650963faa",  # AssignmentStatementAst
    "0.1.53.1.0.2.2.0": "d270348e8047c5c56da65343d6c252706aefa61fd61856cb19986da6619d78d1",  # AssignmentStatementAst
    "0.1.53.1.0.3": "09c704538226d5a26c0e8756955e448ec1fb72b0b9ee2b87e76465b03a822756",  # PipelineAst
    "0.1.54": "59853e1f9f4ae55c4c1eb4bc14f3b0e9a35e75bb3d09449e3eae711ad690069d",  # FunctionDefinitionAst
    "0.1.54.1.0.0": "1e7e15969049da32e410609507a09563e2794f7b50682fcacc6fff9a32a8b677",  # AssignmentStatementAst
    "0.1.54.1.0.1": "c4af10d3e67a468d89dbc32648f78ef65084a2202a478293fe7128a9e17cb8b7",  # PipelineAst
    "0.1.55": "f52a4eb7398e49f850c9f723b0c50fc25350fccce870b2090bc40c92f445d31f",  # FunctionDefinitionAst
    "0.1.55.1.0.0": "a3bcd08b70e1884b89955dbfe40d3d44f80a7f6804eaef8a1de5a13bdcc13b75",  # AssignmentStatementAst
    "0.1.55.1.0.1": "bbe63ff7be7ef34fc1a6f6af16fe9353c3837e3cea330c6e72d36d1e99c7147a",  # PipelineAst
    "0.1.56": "227e6f6c2af6220af4ddbb846bd7f9113ef1e75f947aa4cc9ca908e2b365f7a2",  # FunctionDefinitionAst
    "0.1.56.1.0.0": "a2a01ff52fc2b047b6f500d8b7e24a3c7f6d445a4c4541f2181d624931d69de7",  # AssignmentStatementAst
    "0.1.56.1.0.1": "806d305edcff93480d6223ca096e40a325e16d0b60f2801dd0cc38432bc90d7c",  # PipelineAst
    "0.1.57": "be0b9457239f6aabbe2f156c6aab6fda79dfb3cfa39f1fc691b34c70d531cac1",  # IfStatementAst
    "0.1.57.1.0": "b45e2b0aeda9cd1677f00259c5f4b4311b3ac7126402cfaa420951b004a5aca2",  # ReturnStatementAst
    "0.1.58": "4b2e64f734b00228eb82e375b60100dc3f202aa72466c5c3dfccf77340427187",  # AssignmentStatementAst
    "0.1.59": "5eda4f432ab56449bdb5aea87d209c16a31f45c5ac0e06226b017a1934487089",  # AssignmentStatementAst
    "0.1.60": "b1e03f0683c5bc14d611fc821be20b491ad8f5a9cc89d250d7da4dfce3f3bb1e",  # IfStatementAst
    "0.1.60.1.0": "2d7bdac3250484ebd6a52cc2563e38d8e3fa7cf6faffd1992c5e4b023f925c43",  # IfStatementAst
    "0.1.60.1.0.1.0": "c6b231b112d02a5d3edf7c1ff92ff322af2edd79362ce6d27c0e1d688eaf0125",  # ThrowStatementAst
    "0.1.60.1.1": "603f120c83dabcdbd555f5c50107e29dc4121af8421245f819553b80c8ce9143",  # AssignmentStatementAst
    "0.1.60.1.2": "84db74593806b4f2bd6bf9db78a162b284a138d78493ef441bdfcbb78dc660c0",  # AssignmentStatementAst
    "0.1.61": "94d744c26912a812e913d410ec88657b8d82354db337b8254807ffb7cc395963",  # IfStatementAst
    "0.1.61.1.0": "1495158c14edf82a41149d7957b6712062da0e7bb2a8170e9b5357939fe3da53",  # PipelineAst
    "0.1.61.2.0": "c3301cbbc0386f5519bf0be177915296a0ef97f6f263e1b55472b4681b91b9b7",  # PipelineAst
    "0.1.62": "ff3e80e6e7cc7955dd34dc5d43e62a5b96f7071465c78407df8e01875b19c69a",  # AssignmentStatementAst
    "0.1.63": "a08036a17e9d049f1df69cb9832dccb3bdc7b6fde1d026a56dcfd3a02210c9ad",  # AssignmentStatementAst
    "0.1.64": "d267e481a94925cca47e58a8f8d3c75516b8bf48df9505f484e5652fe683d882",  # IfStatementAst
    "0.1.64.1.0": "b2e27128dfcc1b43bbe060452b75839ee7cde8e9ba5b8187946692d038293e90",  # IfStatementAst
    "0.1.64.1.0.1.0": "214e452f625ffe1547080b08b4e8a90158c7c02d47af57d74a7e5ace06c5ae2c",  # ThrowStatementAst
    "0.1.64.1.1": "3cb59566ab13401519c35edf58e3baac9e07574fe234bf04fac3c844da2235c2",  # AssignmentStatementAst
    "0.1.64.1.2": "e9829c64b813e95b3ba508cac901d02ff0b6b8e8f3923484ba1021a7e5e30d91",  # AssignmentStatementAst
    "0.1.65": "84239a8285331f5d686a012e9e9ddd89686723af2a5b342185a57ea55b71d3a3",  # PipelineAst
    "0.1.66": "f5c792980365be3cc3a4a34c80818edbc0624367932f987592f861f289325b69",  # PipelineAst
    "0.1.67": "adda0c0e9673789b4d2603672b538326f2e373143f946ead62537a09d67c8011",  # PipelineAst
    "0.1.68": "ebec863cad53ee0536b80b47431bf450f04e4372538a25b2e38ce95bbec9bf56",  # AssignmentStatementAst
    "0.1.69": "ee2a5740b27da12bf0bb8f1fab307f01ff3642c61b1dfb498f3802a2b864297d",  # AssignmentStatementAst
    "0.1.70": "593def1cc03702bff42c0b624c162b4d7a18a546810bed60f5f3079b23655879",  # AssignmentStatementAst
    "0.1.71": "54fe71c2dfbe193bb8a575a4d5ccaa4856acf8dbd6a32f53504d36dec696cfff",  # FunctionDefinitionAst
    "0.1.71.4.0.0": "b61656bb02f0b64e2d1f23ec1fbe8ac2a1a92ae336fbb7e054f4d1af008ab8cc",  # AssignmentStatementAst
    "0.1.71.4.0.1": "e02c21a4bbf0583a68bc5929a53e85a1934756b5a23845d3ff40d34bc0193296",  # IfStatementAst
    "0.1.71.4.0.1.1.0": "5d53bbf877d818d40f17eb8bcecde45498ffb357dbb16e9ad3f2398ec1ddf488",  # AssignmentStatementAst
    "0.1.71.4.0.2": "c72d9162ecb3b114f832438e3c098dd8e3ac0a487675080e8bdc230a7e449f0f",  # AssignmentStatementAst
    "0.1.72": "725adeb8503bba2b268f07362e9719abb792dfb33218843fe9f5b5484390ec9b",  # FunctionDefinitionAst
    "0.1.72.6.0.0": "ad02889cd2648b2e5d9a4046525c67d5bf4c1499f1e4e64582d7e3ea08068bc7",  # AssignmentStatementAst
    "0.1.73": "c429754ad9f3f52cd0ce9c69c3c839ce1306c1acde72f45d5c8cdb13c042e97d",  # AssignmentStatementAst
    "0.1.74": "3b6ed4d1a896db78f7440ab1097f18bc35fa871c0a682c7bf6de577f4799f7a5",  # AssignmentStatementAst
    "0.1.75": "3df41030c2414916f43f69c2149f6ddaf16a45c36ca44928381c39656d0f17f7",  # AssignmentStatementAst
    "0.1.76": "42fb16267915f904b043755f95028dc5223106c7719999e89ab7e5dde7032f5f",  # AssignmentStatementAst
    "0.1.77": "c44172168641957e8d30338c49c651d5de49fe197e04185ceead4dddd4f3499b",  # AssignmentStatementAst
    "0.1.78": "b04e94334b28288a20c86bbba01f65f7d2c877e295df93d1419416ed21eebb90",  # AssignmentStatementAst
    "0.1.79": "6633d4e8365cf82fc00edb30bab180abe47ab1ec4c1c52e88763841ff48f01ab",  # AssignmentStatementAst
    "0.1.80": "71f69a1192417170d2cbba39b9da3957d891d0dcf74e552883011f0256a8504b",  # AssignmentStatementAst
    "0.1.81": "48d5f438de985290ed55bd8655e27e583ac6e411956b14e8cb25b4ccf639c1e2",  # AssignmentStatementAst
    "0.1.81.1.1.0": "d7b1b5f981f0442ce128d46a1e5c8f7045bc1c9ae4af445f68b1d93adffc61a4",  # PipelineAst
    "0.1.81.1.2.0": "b45d9e56a51093fc6adbdf8ba490895259cfeae5d89cfb5a69887b25fc45e32b",  # PipelineAst
    "0.1.82": "d181331cc0cc68093548b55f3f98c45b3719353fd5e6a588c2025c6513cfac6a",  # AssignmentStatementAst
    "0.1.83": "20c02762ba209b7ad2bfc75b67102ddcc1aa30fcb4658246331d8c4ff5b64465",  # TryStatementAst
    "0.1.83.0.0": "9091abb122b1c821351107c6cee9e74a702332313fed78e0ff7e33866b0a91c3",  # AssignmentStatementAst
    "0.1.83.1.0.0": "3ae9ed7beb47c620dd884f7541c6a09d4d91f97f6d01d959b5263877635e30a4",  # AssignmentStatementAst
    "0.1.84": "6024af29467e2e323b07ea692626e043b41b2614f0fab8c106ec892509ac84c7",  # AssignmentStatementAst
    "0.1.85": "85faaacfcad71acffb2ef5d6752d41234ef9747169176e3670edf17cda5052ef",  # AssignmentStatementAst
    "0.1.85.1.0.0.0.0": "3c02fdffcf55d932695c88bbd4ff553c30caf40ab4b63f2747f5301d5c58f095",  # PipelineAst
    "0.1.86": "be6166c65bac9f47a0531604b83a09e84a3933915055b395b90abe5ba20e2f1e",  # FunctionDefinitionAst
    "0.1.86.4.0.0": "52474eae7bd180f912f33605615844341ad5ec2d60476166d57be8e7beeb6745",  # AssignmentStatementAst
    "0.1.86.4.0.1": "7821eee11daadb04e249a89194cb1b0eddd0301219db7dac1a2f8a2151292623",  # AssignmentStatementAst
    "0.1.86.4.0.2": "7412170e876015181eeee3f209d8d191a55e104ec30630a4e52f6970fdbad51b",  # PipelineAst
    "0.1.87": "e4e8d50a9a2c8873b1bd729bfbdae53bd4a323973da91b2966a0a0d9dd67162a",  # AssignmentStatementAst
    "0.1.88": "67738d55e39daa6ec1c05f0d550bdf6ae594229da8191abb1010b80b5a316df4",  # AssignmentStatementAst
    "0.1.89": "92ae98e4573abc0877711c5229608fc541eb00406062bf6858e3612ded4e887a",  # AssignmentStatementAst
    "0.1.90": "7c874bfc5b760baab4603ef5ba257cb448a073a5a204483c19faa3c95a9760fb",  # AssignmentStatementAst
    "0.1.90.1.0.3.0.0": "99c0e91c70849537fbc94cf713bc59dd652a2bddcbdfc9d31a248580811c4d02",  # PipelineAst
    "0.1.91": "237eff6936145d70b4a902b404548277c1234bc433cab23532f136050ff179cc",  # AssignmentStatementAst
    "0.1.92": "bbd4d07a01ae063367894a88a7badb5a64073c788fed64e72586a2ccadd8fc1a",  # ForEachStatementAst
    "0.1.92.2.0": "08bd68f02d083c0a68689caac55623ee7b2888487f4694dba75536d5a8c3213e",  # TryStatementAst
    "0.1.92.2.0.0.0": "f97b9efb02a19dca2c2a0be57a16dfa6e688937bf9f176e45358fe033f01d8fd",  # AssignmentStatementAst
    "0.1.92.2.0.0.1": "9a8948517efb5663a204b0091a15bc6885c9e63c834315479b8c20c3f0f5c455",  # AssignmentStatementAst
    "0.1.92.2.0.0.2": "f05f8f4ae6af6a74dbf169c931b3c68f45814c3f9e474e882139e0253f6d7082",  # AssignmentStatementAst
    "0.1.92.2.0.0.2.1.0.1.0.0.0": "eb18e8d967d75393f660183a8fb419b3266b5fe66c612e596eac5162845faa53",  # PipelineAst
    "0.1.92.2.0.0.3": "e5766faab99fb20b2714f36b22ac4ba51ab1de9e37c8e1bf3472f088a2c795eb",  # AssignmentStatementAst
    "0.1.92.2.0.0.3.1.0.1.0.0.0": "ccbc85d150f5d87ca2499bc6ef712d8d8ebf7c6d68af2149855c9e2990d0b5e8",  # PipelineAst
    "0.1.92.2.0.0.4": "c8a768572bfa30e3325e3bf18ea6eec07534b97ff262d7e410c39ff4896c06b5",  # AssignmentStatementAst
    "0.1.92.2.0.0.4.1.0.0.0": "da669770fa8c07d26b9b723e9fb11d059c873aad817b9237820f845f1bc0cbc9",  # PipelineAst
    "0.1.92.2.0.0.4.1.0.0.0.1.1.0.0.0": "b5e2fad504aecba141510c026127c26a04c7e0bdc0da39dc2c217a6eabdaf4d3",  # PipelineAst
    "0.1.92.2.0.0.5": "eb900c288cc2521ac8c434f7e6f686972709d7a29fe9628f9a8ad56595ca674c",  # AssignmentStatementAst
    "0.1.92.2.0.0.6": "845b61c6178e7349ecd1ec50de5c7596d5c686d6692bafa3431c455677956233",  # AssignmentStatementAst
    "0.1.92.2.0.0.7": "8ddc419619e0dff66c46a7b1b419a31564b3773217480691f9ea87d3aad67f2a",  # IfStatementAst
    "0.1.92.2.0.0.7.1.0": "c92490b12de2711b77eefb211f5254a41cf243d4da451a147cd630b69c126f39",  # AssignmentStatementAst
    "0.1.92.2.0.0.7.1.0.1.0.3.0.0.1.0.0": "1ae36c75ca0b984caa561c76fa6371717d9ad583b89b3e7933a5879f027740e3",  # PipelineAst
    "0.1.92.2.0.0.7.2.0": "78ebddf3296d9f8323339542b5a8902b7dc534fcbc221e5e13280fa5c9c01f16",  # AssignmentStatementAst
    "0.1.92.2.0.0.7.2.0.1.0.1.7.0.0.0.0.1.0.0": "0cd857fba5c3ede4d9116bff080e8f727eb9a10bb0630f8eebba55d4960fcd85",  # PipelineAst
    "0.1.92.2.0.0.8": "8e3358cf1fad1ffa7075d7aa913fc0dcc104f0aa68e5da1e678f4889af4a3536",  # AssignmentStatementAst
    "0.1.92.2.0.0.9": "95df6d6a81773cd7ceedb98a278904699160fede90ad640dd655ee91722057d3",  # AssignmentStatementAst
    "0.1.92.2.0.1.0.0": "861091db5bc95b4452c9b72bafb99fe8210ca11c60fadc4ab972257e27cf3de3",  # AssignmentStatementAst
    "0.1.92.2.0.1.0.0.1.0.0.0.0": "821e65289a20e09e3ea1ef9c492a6b6e68ec5574b61c8d08388614a84da6a8c6",  # PipelineAst
    "0.1.93": "a0fea04f905146e11aad8d7617b2e00337cdb4a712d606a26a9ed1bfe362b35d",  # AssignmentStatementAst
    "0.1.94": "20d892a11be067467c1b37b0a74205f2e6a6766d1041378ddb097090cfc2a11a",  # IfStatementAst
    "0.1.94.0.0.0.1.0.0.1.1.0.0.0": "91829dd6d0a277426cb6abe25fcf437767d807249004df8a0ba5196ba46f07f6",  # PipelineAst
    "0.1.94.1.0": "304e1e0458c2572b7829d143e4175f31e0503f5f64acb8c689c40cbdda61aec2",  # AssignmentStatementAst
    "0.1.94.1.1": "8920d3de162582a9b54f5966a4cfd349dae59d32e5e8761f8ca422341683bfbd",  # AssignmentStatementAst
    "0.1.95": "7169887c1189103f9bb79456906a853b711fe6501c536d0873234728aad32a1f",  # AssignmentStatementAst
    "0.1.95.1.0.3.0.0.0.0": "de7978c4770d50389a8e4003888d9bad6a0204355a6a6021ec76bc6275c2d14c",  # IfStatementAst
    "0.1.95.1.0.3.0.0.0.0.1.0": "91239f6e762493f3fe117b5948901a798768e3e39a81217eaa2f2ec1316eb502",  # PipelineAst
    "0.1.95.1.0.3.0.0.0.0.2.0": "2b30acda84913c0ef593c4039767d9f6b8e524d42e302778b27766397a137ebd",  # PipelineAst
    "0.1.96": "ed4cc4eceb5edd9e4e5c430e9966e35a82b20fd4217e6d6cf2e56b3854ba15b1",  # PipelineAst
    "0.1.96.0.3.0.0.0.0.0.0.0": "7b188c3b53f535a9f9d07e1294e7245efa6cbff94956cbb05bb08dabe26e0c97",  # PipelineAst
    "0.1.97": "66273b6d69d7a2f1b71887f455afcc0f6f57a181d57ea6df7a6e30b2604dae79",  # PipelineAst
    "0.1.97.0.3.0.0.0": "b312403a46d3dd39f859f3605a5c258c2e24ec7db77830e7557780de5cc635a8",  # PipelineAst
    "0.1.98": "9f6fcec641f46f8a9747f17f80a8ff22ced1e139d3e421709f2b0436c201e1c3",  # AssignmentStatementAst
    "0.1.99": "ff11e302912fe81dff45b03e5509ea1aa146a30b38ec58ef4fc7d63ae1958555",  # AssignmentStatementAst
    "0.1.99.1.0.3.0.0": "987c47d56f07253959845b0ec42d5f2eee2e63dfbb40aca9b079071aa500ad8d",  # PipelineAst
    "0.1.100": "1ece00575c897253d0b85bdb1e0326bcb2b9277f0b6cbdd3c7b05b816923a2c6",  # AssignmentStatementAst
    "0.1.101": "2f2c77222ec403811bf1490b62c2b62ca483fc85001d7d86ee410262df00ca87",  # ForEachStatementAst
    "0.1.101.2.0": "4a8ebebeaba90239c3322b10488d2223b506220eaad57cf467854c94a4968e34",  # TryStatementAst
    "0.1.101.2.0.0.0": "5eaedd4e223512792ef13df934223d49c78ba54685632070a01b5321859fa22e",  # AssignmentStatementAst
    "0.1.101.2.0.0.1": "cb5cce58ebc205efb1ee071eb73e680461f24ed4626bca034bc147aabb2fd361",  # AssignmentStatementAst
    "0.1.101.2.0.0.2": "763b1a24fd18eba47e09fe3d986f27b96ec7038b7ac5d93c1f488938338aa99a",  # AssignmentStatementAst
    "0.1.101.2.0.0.2.1.0.0.0.0.0.0": "f349ef28cb54c2e7258387b4b8835a9eb2ca436263222670bfdd4c6c866af855",  # PipelineAst
    "0.1.101.2.0.0.2.1.1.0": "86d88a334e62564e8d4816fd4a6bb3d557b7bc237b45d9f5facc31c6a9adf3ee",  # PipelineAst
    "0.1.101.2.0.0.2.1.1.0.0.0.1.0.0.0": "4f4ab1b2bd41c09c1dc0f6044c182e2752ab81d75a234a26e25ce94c1d9a66b4",  # PipelineAst
    "0.1.101.2.0.0.2.1.2.0": "9edfb3278d1ea5ae8fa6cdaed162695b8deff4e7a1c0883dcdefe48bae66798f",  # PipelineAst
    "0.1.101.2.0.0.3": "61a3ecb9a32b510e71049f3a0ef446638f7ffe8c33b01d7cc978d84c9a3a86b1",  # AssignmentStatementAst
    "0.1.101.2.0.0.3.1.0.0.0.0.0.0": "db81951d50d547c52d7606ee962ba859cb9e1717cef25d257e96ab4280e86065",  # PipelineAst
    "0.1.101.2.0.0.3.1.1.0": "dbd9f5122fd11bcc9bb8511906cf2996d5e8f314a71b99cb764c64a349cbbbd5",  # PipelineAst
    "0.1.101.2.0.0.3.1.1.0.0.0.1.0.0.0": "4d9d08fecd84f228876fba445e864a34edb23a3c35840fe8ad2fff710feb2988",  # PipelineAst
    "0.1.101.2.0.0.3.1.2.0": "3d90d5b8b8c4ff6d5e319474304db2810f0adc5a7fab8b12e88d85240e92cfa7",  # PipelineAst
    "0.1.101.2.0.0.4": "a46d1f91be2bd0209d3916f5c3fefe722eeb7389ae08e9906f745717356e0305",  # AssignmentStatementAst
    "0.1.101.2.0.0.4.1.0.0.0": "662a6562db8378182d2d2c12da9bb7e92b390297c44a3f745d6fb400cf1c0dab",  # PipelineAst
    "0.1.101.2.0.0.4.1.0.0.0.1.1.0.0.0": "777b01a0c475a00f1bca6d6a8f5adbf54fe90e865ec02416b6a7cb58b177f21e",  # PipelineAst
    "0.1.101.2.0.0.5": "a9add02697d54f13d8ded3e7378e8639e52ecdd7ae9e4065a56788a4a314543f",  # AssignmentStatementAst
    "0.1.101.2.0.0.5.1.0.1.0.0.0.0.0.0": "9d9c7b3e45f6f8cadf24eff610a41de6aafa589bbfe2e88113f939c4d11de747",  # PipelineAst
    "0.1.101.2.0.0.6": "d6e0753367bdebd69fcafad35862e359ed139c0823e6d69e931b6f6712656f20",  # AssignmentStatementAst
    "0.1.101.2.0.0.6.1.0.1.1.0.0.1.0.0.0": "f554870fe11c67d9e3e6a59641276e6ae21025848c12d2501f6239ad6ba7e599",  # PipelineAst
    "0.1.101.2.0.0.6.1.0.1.3.0.0.0.0.1.0.0": "a26aef058438b237f8d9d8de0bab1fa298d59402cf9d13099ea1e410c549dc86",  # PipelineAst
    "0.1.101.2.0.0.6.1.0.1.5.0.0.1.0.0.0": "2b44fafb46922676ea4ff8b6a9f8781ad0758b976262c86d24d749b1c0b92192",  # PipelineAst
    "0.1.101.2.0.0.6.1.0.1.7.0.0.0.0.0.0": "9857e3bdda771a9125b99daae674465ef0c44548ba703e99be105f871a35e336",  # PipelineAst
    "0.1.101.2.0.0.6.1.0.1.7.1.0": "e43c66852230f21e9c5982a4b147533e21388132c8cbc7aaea7592f4fc3bec23",  # PipelineAst
    "0.1.101.2.0.0.6.1.0.1.7.1.0.0.0.1.0.0.0": "c8d91778b1d2a508854bb4ff90e0ecda38710c265b6072e2d1fe1a2d25a9a84f",  # PipelineAst
    "0.1.101.2.0.0.6.1.0.1.7.2.0": "366fc13f8d4a7c070df36e77221be38f5d18cf2a3b80f6d913785d642f6649ec",  # PipelineAst
    "0.1.101.2.0.0.6.1.0.1.9.0.0.1.0.0.0": "118c775af7dfb6c736710867fb52d110dee7b093e9124f19aefe91f35109201d",  # PipelineAst
    "0.1.101.2.0.0.6.1.0.1.11.0.0.0.0.0.0.0": "7260c2113560bc8e7c1560e426182d17ead5ec78bbc6557fbeefee9059416bb9",  # PipelineAst
    "0.1.101.2.0.0.6.1.0.1.11.0.0.0.0.0.0.0.1.1.0.0.0": "b9b65cbf672c2797bbd885481eb4d66ad1ef33677d2b341f59d5fa775475b803",  # PipelineAst
    "0.1.101.2.0.0.6.1.0.1.17.0.0.0.0.0.0": "4f92ff89c5f11a624611ea3bb8a2eb14cf8bd15e822c9428474b5b43bc293ef6",  # PipelineAst
    "0.1.101.2.0.0.6.1.0.1.17.1.0": "9f1d080c284fbeb42472311516b7e280ede83652ee9411ce4abc1d8a34299d08",  # PipelineAst
    "0.1.101.2.0.0.6.1.0.1.17.1.0.0.0.1.0.0.0": "eea9c8059d495ce00d68144cb191f656efb1bd4a3ae83da3eb5c8e45a9a3ac42",  # PipelineAst
    "0.1.101.2.0.0.6.1.0.1.17.2.0": "560a967b16c315677927985fa5259d8a357b7e72430b8f3b81fba072906e417f",  # PipelineAst
    "0.1.101.2.0.0.6.1.0.1.19.0.0.0.0.0.0.0": "bda49e6c6412f9fac5826589cb220cd9ca5f1e45eb21bf7ef4965264f578b03e",  # PipelineAst
    "0.1.101.2.0.0.6.1.0.1.19.0.0.0.0.0.0.0.1.1.0.0.0": "02e03ce1ee1954e3063ed444c3bcb53c644381674a711522f6ae3a989322ff1d",  # PipelineAst
    "0.1.101.2.0.1.0.0": "ef2340e5f9df4d95d87516aaeba129ef8835772dd293bb9cb3753b3982305440",  # AssignmentStatementAst
    "0.1.101.2.0.1.0.0.1.0.0.0.0": "5b4de35b3878876ca21b546a57432976b6c476092564d7edabfe0e7de37f39bb",  # PipelineAst
    "0.1.102": "efead023873dc7680519c18767911b71dbd58be8068078a46d7c03733373e67c",  # PipelineAst
    "0.1.102.0.3.0.0.0": "46fb2729614090f4525b12be0b1d01fb4ab5a760060adb4e3f2cfa15f49844ad",  # PipelineAst
    "0.1.103": "accc5862488152f9ece2855db0b4514c7c7b9e2b3a224e0a4f4ee93dd978c99f",  # AssignmentStatementAst
    "0.1.104": "b808d6a379c94694f51511cd2e20ff1d15657c158bbe1601033a89cbcdf714ff",  # AssignmentStatementAst
    "0.1.104.1.0.3.0.0": "e50431daac0a8e36d54515cf75d79a84ec133cbb60e1bc01f4c7cdf55094b65e",  # PipelineAst
    "0.1.105": "2ecf262635102a3c29f18f70759363b0b155e99624c02940168e84ded37f4394",  # AssignmentStatementAst
    "0.1.106": "0000117ea5e6d4dea75973cddbade432cb8b6baf567797f80f34f4507314d287",  # ForEachStatementAst
    "0.1.106.2.0": "3e0e303fb30c0b3e28c52a1d7b0ddedd38ed4b893b38a7e55a2a50c1dafc2b36",  # TryStatementAst
    "0.1.106.2.0.0.0": "01904d13f2b0f0edfb6a65a4b97ee6652e91fa192bb472d9251d6e1e0a7cb02b",  # AssignmentStatementAst
    "0.1.106.2.0.0.1": "48b11aab2ebd1e1e3dbe60eeda23b6ef6b945ec25f1331acf3c67e66ce8b9eb6",  # AssignmentStatementAst
    "0.1.106.2.0.0.2": "149a9c4653605a09106a7d4d606ee0952403f1e45128dbd6f8deb4ee28722b1e",  # AssignmentStatementAst
    "0.1.106.2.0.0.2.1.0.0.0.0.0.0": "224fe1ea75836733907ef3351c7bc20784414772fe1f1853b90087634c476bd6",  # PipelineAst
    "0.1.106.2.0.0.2.1.1.0": "ccd58ec58f1125059512fedfb29e0056c52bd6f073c7be931e39781ea2fdcb63",  # PipelineAst
    "0.1.106.2.0.0.2.1.1.0.0.0.1.0.0.0": "662e3381e0d8678d11a09e96341bdef8e89b2f4fefd52636bb6be67a2bb3c3e8",  # PipelineAst
    "0.1.106.2.0.0.2.1.2.0": "b1a43678eb209f101821318ba9b1d59212ec582bb36a79215aa7fc6f9dc9a41d",  # PipelineAst
    "0.1.106.2.0.0.3": "a40c1a7ba7e3f8727b23fe1325f12463f2742224133690d28cf7abee8701af5d",  # AssignmentStatementAst
    "0.1.106.2.0.0.3.1.0.1.1.0.0.1.0.0.0": "1d01b4703df61fb633dd3312a372277bb3ae7a694c18c6f943b6eaa7db93c0f0",  # PipelineAst
    "0.1.106.2.0.0.3.1.0.1.3.0.0.0.0.1.0.0": "45b201eea6dc8518e01cbdb54a1f0afbb1e42f4b0305200f28793cb06fb0d559",  # PipelineAst
    "0.1.106.2.0.0.3.1.0.1.5.0.0.1.0.0.0": "e2312a04066665a4e7e0b6c522a45343b51b8018f1767279ad272720c3d72562",  # PipelineAst
    "0.1.106.2.0.1.0.0": "b697143c9575697e6a5037582dbf6a5c06ece807591447dc4c1cbcf03e84d194",  # AssignmentStatementAst
    "0.1.106.2.0.1.0.0.1.0.0.0.0": "fb2de81ba941e32f0d9f50553d53438d5d1f7377d3d2676616d06d5149eb4f7b",  # PipelineAst
    "0.1.107": "86b2c1427840c0102845550f6c8c0f92fe9a16f03cd2c182a97c464f247c983a",  # PipelineAst
    "0.1.107.0.3.0.0.0": "48865857869fe5545084c7a67987defce8909aaa702971ae719795935de7efdb",  # PipelineAst
    "0.1.108": "634ac6a309c3416f4367830f3f53af724e7dd71262e1a45f01884f8b33592b0e",  # AssignmentStatementAst
    "0.1.109": "3b034ec2f9a062f242ffb9463eb894a32f916c31078a871e22af2ad34d67c270",  # ForEachStatementAst
    "0.1.109.1.0.0.0.0": "50024b1ee37f877f9c8ed207ff17c7a33361ad396079decaeeb33b03f6ae0abe",  # PipelineAst
    "0.1.109.1.0.0.0.0.0.0.0.0.0": "f7c6d14d13df4c8d6d6cbd702b610163fb5049335a465de9d3de2ac46774980f",  # PipelineAst
    "0.1.109.1.0.0.0.0.0.0.1.0.0": "58ae6d88dc3359fd89bba5a1a9a4f7deb7587b08a928494f3362430e23b0accb",  # PipelineAst
    "0.1.109.1.0.0.0.0.0.0.2.0.0": "4e49b64fe106049673c9d6331fe12975e5c0e946edc6626081f6fa6feed55661",  # PipelineAst
    "0.1.109.1.0.0.0.0.0.0.3.0.0": "e85a6c1c55707252534d4354c03a898f4132007268c93c36da230362aa8e03fc",  # PipelineAst
    "0.1.109.1.0.0.0.0.0.0.4.0.0": "eb4fd8f4abc96d31ba4e1c9fb4ed1d3226ac1ca574cec12d2354de20be329c41",  # PipelineAst
    "0.1.109.1.0.0.0.0.0.0.5.0.0": "640febaf2eaa6ed65d1c378749014c37538592d7e860bcdeeb60ff3f0c6d1038",  # PipelineAst
    "0.1.109.2.0": "75376e830ff7bdbc4b65f2f920e2c8d47c07652235d8750c8caaba168c2b2237",  # AssignmentStatementAst
    "0.1.109.2.1": "1a250ff623e9f6aae3162b2db272b25e86b8049dcfba78c5c1fd79f6dd71f52d",  # IfStatementAst
    "0.1.109.2.1.1.0": "7d1743b9d64797e6e95d7a0eb1e5291cfad8a0b5878baeec7ae43311e1a3c7e4",  # AssignmentStatementAst
    "0.1.109.2.1.2.0": "16f3021a5e5c5b6ec813e59c0dcc117d6c883686cfb05b4f81cfcf5ee1cbdb49",  # AssignmentStatementAst
    "0.1.110": "36627dca5652c2a27093adc5d4e6d90ffa53bb5927b044560489b9a4eb528bcd",  # AssignmentStatementAst
    "0.1.111": "677f33ef2ddcff2f965d63fdbc93303f5344bc4790bee615573a70da11219dd9",  # AssignmentStatementAst
    "0.1.112": "a16ac16a4cef0e083896559c0596ed9c54a9654b1d62d28dbc50a8bbfb0ab41e",  # AssignmentStatementAst
    "0.1.113": "022d87e8b16d45addcc0a210dc06ce042c4b2897300812d40eb2c0b78e39b33e",  # AssignmentStatementAst
    "0.1.114": "b49f49abb6410c5e880b31f86e19d3f38d8d662bc62d2c1a167882777fcba028",  # AssignmentStatementAst
    "0.1.114.1.0.3.0.0.0.0": "aba79b29b99e52c5ac625969a9101e182f6ee00a6d3ad03368099f9b62789e64",  # IfStatementAst
    "0.1.114.1.0.3.0.0.0.0.1.0": "1e2dcd5a5bde85dce9ab441d0b48565c599b2a7b994f217a13740a3235c1d0b7",  # PipelineAst
    "0.1.114.1.0.3.0.0.0.0.2.0": "f1375c546862619ec2599e3a8acb25f2e02655942e9c55ce8989c16dabde0b5e",  # PipelineAst
    "0.1.115": "1f4d2e3bc94faf0a5b200a9a429c6fcfc9bcce93c3b9eac7a4720d92192b4e22",  # PipelineAst
    "0.1.115.0.5.0.0.0.0.0.0": "75ceb98f892e605d51b9575250a74a4d617cd3edfc2171e4c0a4eae130ce7d9e",  # PipelineAst
    "0.1.115.0.5.0.0.0.1.0.0": "39bffced8521a8110e45045e418a2d40af3d0f54982c14820a7545068c1dbd19",  # PipelineAst
    "0.1.116": "a3434ac208fdd67e8943ee174c1f099304ce7416042acb29cfdbbb20900ef18a",  # AssignmentStatementAst
    "0.1.117": "434df4234c8f0f1ab45ad95dec70f9232d5e216338eab88efc0e8d9109a85f3b",  # AssignmentStatementAst
    "0.1.118": "c9dacbb99e463e664be8e77f473c9b3d3a8a57fea9d91e0b5ab1dc6e85f47146",  # ForEachStatementAst
    "0.1.118.2.0": "3910d65eb1ffbacc0d173b3d56d1124668857250b8ff63131c95ddb15b97365e",  # AssignmentStatementAst
    "0.1.118.2.1": "13e3a222e4a4efc778dcb4d3e8ffff9138dde0544a245a0c1aa6777fed015c98",  # IfStatementAst
    "0.1.118.2.1.1.0": "0e99c3b436969b6aabb2ab170ce5cfbfea7dfe1e63718c17819631be00cab82f",  # AssignmentStatementAst
    "0.1.118.2.2": "d2287bd4e7e8e11a3d3317a6d96f71f4e2ccff36b8687394cbc3594c9bbb5845",  # AssignmentStatementAst
    "0.1.118.2.3": "77869f562bc4a1788c6d50ab53133cfda49c853c9449a101e817baf0982a1054",  # IfStatementAst
    "0.1.118.2.3.1.0": "e8f224a1b66525cc4e256c6b3d17b838b170139726d82cfbd2e142c458e35f5f",  # AssignmentStatementAst
    "0.1.119": "3fe7305fa95f2c5baf6bde43d009e43b058d194f96573346b57676503c61ec4b",  # AssignmentStatementAst
    "0.1.120": "a8cf3d2a19e1d9ba479f5ac7797e683a430d9c05051e971a480055d22554cf86",  # AssignmentStatementAst
    "0.1.121": "ffbe730129fd297dbdd0bd1917686a57b521791d071b7a7208c1409be9e15bfc",  # AssignmentStatementAst
    "0.1.122": "2f3404c10cf0b3778d2cd958adb4f3b90852cf0c0661028f72d5c5799046b537",  # TryStatementAst
    "0.1.122.0.0": "e8f7e372ab22a71f8956da6d9bf56584cdf6f8a8757a60033ed5e2e7a015b658",  # AssignmentStatementAst
    "0.1.122.0.1": "4a8f1dd49530213e6917b802c66cef85b2831fc57e510f480efd5a8e259aa08c",  # PipelineAst
    "0.1.122.0.2": "62f8018e65cc716f4cdad94190a73cbf2cfee681b25df520c8009eece89eb08e",  # AssignmentStatementAst
    "0.1.122.0.3": "3d6dd782a4459850c5e832c852ca681c201281af07c54879db89973cee9253e4",  # AssignmentStatementAst
    "0.1.122.0.3.1.0.3.0.0": "872143cf6a991a34ae9fe1b841f8442242a93a71490f96e43267cb4900c53cd3",  # PipelineAst
    "0.1.122.0.4": "82712860a782c4ef9470a486c44384a2e94eb45331105379e2c24e7ad9617254",  # AssignmentStatementAst
    "0.1.122.0.5": "a2501fe260648b8f0c12d822f4e98ccd43946ad64805c65ea8487873f1103077",  # AssignmentStatementAst
    "0.1.122.0.6": "e2bd182bb00e205ac49603543a695f6bddf9351de35382d9fa306fa4b33e5795",  # ForEachStatementAst
    "0.1.122.0.6.2.0": "678abf0564470c897803284ae2e1ab1693e81780d08d3d01933b95518be0b684",  # TryStatementAst
    "0.1.122.0.6.2.0.0.0": "654e9ea394a5230f22d3edeb8b339ada49174bfa6df0fd16f9237c52e44d70fb",  # AssignmentStatementAst
    "0.1.122.0.6.2.0.0.1": "01b5242fdc069493eb9ec045764b27af58f9cd429fb6117a9a41b66c11c757f0",  # AssignmentStatementAst
    "0.1.122.0.6.2.0.0.2": "eaf523fdde7ffa7b08a1024c4abd95190cb14b6c5dd28f4c3193321387efd837",  # AssignmentStatementAst
    "0.1.122.0.6.2.0.0.2.1.0.1.0.0.0": "97201ecfe738a1048658ada59639b9f596f147f1b6d21788f51e5bc5d13e52ff",  # PipelineAst
    "0.1.122.0.6.2.0.0.3": "368abd9681592c2bd9719facab7ae3d17bce84916b04b71f395789d5e230903d",  # AssignmentStatementAst
    "0.1.122.0.6.2.0.0.4": "087c2946e8a3f0b2930eee3fbb69a8b4329076ba9fea1b8a0d280d46fdf3b691",  # ForEachStatementAst
    "0.1.122.0.6.2.0.0.4.1.0.0.0.0": "8de05c7eee044307e753b1cc2d89a3d52e6afa5edda79aa58c7a9fd22b504d10",  # PipelineAst
    "0.1.122.0.6.2.0.0.4.2.0": "c4b3ad1e4661fa3f791a24b0a331b2de89e0c869aab06b81b65ca5b01a5b83b9",  # AssignmentStatementAst
    "0.1.122.0.6.2.0.0.4.2.1": "d9cfbd1c1be558d513c47c44f47a26272cac683b38316d05764d87821a89ff67",  # AssignmentStatementAst
    "0.1.122.0.6.2.0.0.4.2.2": "5dfd147c4d9a9d63954341ff39566b67f441a16e295ce211ada82f8b9c3beb0b",  # IfStatementAst
    "0.1.122.0.6.2.0.0.4.2.2.1.0": "57cb0a2dd38f5336a292b5575cc6939dd37d8964e3d0d8b20682b277f8f29077",  # ThrowStatementAst
    "0.1.122.0.6.2.0.0.4.2.3": "6b5ae931f0c2e5e4ffd06c3c547e4112da5217d57534acbc17978ce4ae9873b5",  # AssignmentStatementAst
    "0.1.122.0.6.2.0.0.4.2.3.1.0.0.0.0": "ffd34c30662a45e69c258ab18deb49c60d234bdefb5574d7da0c52ea7c0e8cff",  # PipelineAst
    "0.1.122.0.6.2.0.0.5": "e8b5904c453e400ce5650cc0f021dbf2851860e0fc5f4abecc7fb510cd08bae9",  # ForEachStatementAst
    "0.1.122.0.6.2.0.0.5.2.0": "27bcd8129f48bfcf666d461bb65d0e2992aad8a2981f6562666476303196451c",  # AssignmentStatementAst
    "0.1.122.0.6.2.0.0.5.2.1": "dcfa38021d558f23882bc1c1c8bb54a4e8a132e6984a051436402afb917eba83",  # AssignmentStatementAst
    "0.1.122.0.6.2.0.0.5.2.2": "4dd22bcd2a7825b82aa96530e3696b09fb06ae8505687c45212634b5deb6dd9b",  # PipelineAst
    "0.1.122.0.6.2.0.0.5.2.3": "937a81e09d74693db33aa3fcd656eae92a9e078cfbda2141b47bd125f35d5d46",  # AssignmentStatementAst
    "0.1.122.0.6.2.0.0.5.2.4": "39d1e8e018cb972f31d02d0526f78cd7633d7de4ba1fb93281bdf3db940fa369",  # PipelineAst
    "0.1.122.0.6.2.0.0.5.2.5": "c6c66f1b94ce53a01d603e07fb1468d273540cd5944aeac12464bbe6347396f3",  # PipelineAst
    "0.1.122.0.6.2.0.0.5.2.6": "1b46fc96ed279e3f1769fd81aaef14682e530c06ce1e7019f78031dbfb880ce3",  # PipelineAst
    "0.1.122.0.6.2.0.0.5.2.7": "d903f1f3974131b14825cf90408a4d78272113a51c0bcbee4f111457cc250dca",  # AssignmentStatementAst
    "0.1.122.0.6.2.0.0.6": "b6c539a059e8e9fc084901891c8d1a84f93e7e8888645211325ba53518c6d8f5",  # PipelineAst
    "0.1.122.0.6.2.0.1.0.0": "59c621f71183725469a126f9b08b7f9ba2f3c66e832cac94854800557ccd475b",  # AssignmentStatementAst
    "0.1.122.0.6.2.0.1.0.0.1.0.0.0.0": "135d86f9207f8942ae8f588c04978cbebfbcea3043fead5106d22a824a310e4a",  # PipelineAst
    "0.1.122.0.7": "9a734eaf7b3dbb5a982093d133f84cdff0709d6bc846d33037d3e4fce8da4c2c",  # AssignmentStatementAst
    "0.1.122.0.8": "bc188cf6b632264ea19715e88edb82b5bc0b06d9443c4e98bb481454eca6dc9f",  # AssignmentStatementAst
    "0.1.122.0.8.1.0.3.0.0": "a3e75d9157aa998ab1c88f6dc51c9838d2adb60d91cf16d3ce38aac272aa36dd",  # PipelineAst
    "0.1.122.0.9": "4e02bba5e4c43f15dac42092211f673e185c574de3f0b37ead7c60648f277d82",  # AssignmentStatementAst
    "0.1.122.0.10": "63706fb5ec0059e7d6884fd29f26d84b84b6b00c274c036ed7db714c3f490bd4",  # AssignmentStatementAst
    "0.1.122.0.11": "ccb260438b8d4a800abd6a45dd7e19c78ac5cb87ed2889a22b3e3ef5e42716c9",  # ForEachStatementAst
    "0.1.122.0.11.2.0": "34bdb05399bc364ba1af1d514cdce30e70d3417c52b5b36eedf3e5d9ddb5ece3",  # TryStatementAst
    "0.1.122.0.11.2.0.0.0": "ba6edcf932e258969043cde43c605ddfd92d24f2242a59614ff65e7c9e09ea4a",  # AssignmentStatementAst
    "0.1.122.0.11.2.0.0.1": "e0f10ec28610e029cb600bed4d414cc54cd41e5fa703a02b21d9af6735c19b94",  # AssignmentStatementAst
    "0.1.122.0.11.2.0.0.2": "3717a087116143d56cccbf25e0d01fbe9c0687423e6a0cf50266fc607a39eb0d",  # AssignmentStatementAst
    "0.1.122.0.11.2.0.0.2.1.0.1.0.0.0": "f3a0d71af5d69aa3ceeeb9acc968b6fb006df156cf31882bab98b73508e3769f",  # PipelineAst
    "0.1.122.0.11.2.0.0.3": "d8c0241efd815f084c87155dc2ed1a7026cfb036f2c76c71e8451ac9a82fefd8",  # IfStatementAst
    "0.1.122.0.11.2.0.0.3.0.0.0.0.0.0.0": "782d05944f79b863c80ca7e5ef23b5a02ea5742666627a6386dce1b109bbd2e7",  # PipelineAst
    "0.1.122.0.11.2.0.0.3.1.0": "404ddade7093cc4b4837ffedab81d41cd66d34c4e1830c1059ccd1e55da060b1",  # PipelineAst
    "0.1.122.0.11.2.0.0.3.1.1": "aa1c45d94ffcbc1462de7416b2c6de2cdf014de47e52d992a8a5cd6f87bba252",  # ContinueStatementAst
    "0.1.122.0.11.2.0.0.4": "bc0d510b551230cdd312d3068105b5502472b24b99b2498efe981a68ca42129b",  # AssignmentStatementAst
    "0.1.122.0.11.2.0.0.4.1.0.1.0.0.0": "b20de56e47ffdfb6be64e6c4c12f43b914e8ac172fb61c28fdd9833c8f057050",  # PipelineAst
    "0.1.122.0.11.2.0.0.5": "9d7fb21f5dcddbdaf231820c7da160681b434871eee3984258cd593287e039f0",  # PipelineAst
    "0.1.122.0.11.2.0.0.6": "602d8986ea0344634ddb18a85bd575643a3a04a849c8be45dd5e32f8cc2ebb6c",  # AssignmentStatementAst
    "0.1.122.0.11.2.0.0.7": "5c65dc62ba8d589518b2e4e829fdbd523d2a944a6f8fea5abf39138351fff71c",  # PipelineAst
    "0.1.122.0.11.2.0.0.8": "4061f83572f68d918142c8e57705bf4f86440e7e588d1f7c923f99cc1948ea06",  # PipelineAst
    "0.1.122.0.11.2.0.0.9": "e7beb1ac11e87c92f6311c0508d1b8ba389ba48e5319f7c60c86071503f9be7f",  # PipelineAst
    "0.1.122.0.11.2.0.0.10": "12438a4f1fa6aeeb4188a73a0b11b21479b335870c2fb4afc0cd28f113deb83d",  # AssignmentStatementAst
    "0.1.122.0.11.2.0.0.10.1.0.1.1.0.0.0.0.1.0.0": "7ba3da9e7e733d5a640e4f2ad3b61f13ac3f3459eb73cbd33246f8b41fe0b10d",  # PipelineAst
    "0.1.122.0.11.2.0.0.10.1.0.1.7.0.0.0.0.0": "2eed38ac7c10031cfa2ca33ffdb08277e3f7ad6c554d8bb3c997559db1340418",  # PipelineAst
    "0.1.122.0.11.2.0.0.10.1.0.1.7.0.0.0.0.0.0.0.1.0.0.0": "5e5f29fc8208eec6a762c4e446ff3138905d39e5feab8be4f6037ad468ebb887",  # PipelineAst
    "0.1.122.0.11.2.0.0.11": "65dd63756f3e0e7382c192ca17a8a88901e711c8a0095b45295ddd7a04139ec0",  # PipelineAst
    "0.1.122.0.11.2.0.1.0.0": "86310f8ae0f4dec33fc0cda1a63ec6ae3e7555e02f1914bea11fe29494873068",  # AssignmentStatementAst
    "0.1.122.0.11.2.0.1.0.0.1.0.0.0.0": "8b9240066e6fc86278751281f244abb3560dc19a9aa98ce927def22c2a51e533",  # PipelineAst
    "0.1.122.0.12": "69928e15effc08e1609356a439f2bdb1380bb12e6c35dd61363aa7da7616e9d0",  # IfStatementAst
    "0.1.122.0.12.1.0": "0759713837a2af1cf7f75af4382af1022d3e036788ea4c85d3fc15e5e9921c29",  # AssignmentStatementAst
    "0.1.122.0.13": "9d002af46857bb6fbbafae4ef7f6023ba9f3845cd1c798d1f57bc875aa0653bd",  # PipelineAst
    "0.1.122.0.13.0.3.0.0.0": "54f12456de8e795626d65ab45c94cc720ec5fce841f1b1f788fcfbfd8bc168ba",  # PipelineAst
    "0.1.122.0.14": "6eb719585d9a2bd66794a5b084fca9d0772982262793098f69e38f1531768b4c",  # PipelineAst
    "0.1.122.0.14.0.3.0.0.0": "220a33439578423991e94a3466a0f42cb0ab2e5511673c6ac23c75670e3dfeee",  # PipelineAst
    "0.1.122.1.0.0": "5d9c46a9ceecb8e352c0f909863cd0b2e7df40359cbe8a7155ada008a9b96490",  # PipelineAst
    "0.1.122.1.0.0.0.1.0.0.0": "ede8d9cc0cab62b66a16ba5ccf841cf7283cf86f897c898d9151d2b61c884b7d",  # PipelineAst
    "0.1.123": "e68cf067f0c9c0180078d284c480730fd8b5ce8198778b8c4003ee40364c254e",  # AssignmentStatementAst
    "0.1.124": "0deed7b83be228b9f99b6e5aa0bb3e50f668b2d9716594f9eff42134ae2d9928",  # AssignmentStatementAst
    "0.1.125": "38c1b2167749fa488aa11bbccbf9bf4f972804d607495ccbae8ef0db61c21569",  # TryStatementAst
    "0.1.125.0.0": "702629d5621618bed4f1c14318ba2d85417b1eb1542d0dc6ebbf82649a975dad",  # PipelineAst
    "0.1.125.0.1": "aab6271ff63faaabdbb529943ebaabb139ff6d2526cfa62404410e60c4d6aa9a",  # AssignmentStatementAst
    "0.1.126": "f25999046f4caff1948e6b7a9844c1990f07c8b5951be630244598fd7f2e95d5",  # IfStatementAst
    "0.1.126.1.0": "9da2c36ec375608e8623573b26bfce5213d49df2504b94c21e755fb18d16811c",  # AssignmentStatementAst
    "0.1.126.1.1": "6865a39a78992cf8b7ea2b8a64edc219e144ffd8ed0994a65134f04065268bf2",  # AssignmentStatementAst
    "0.1.126.1.2": "1488c78cbe952c2530473e882bd23862ce2180ee194b3919f062fa6b81720295",  # AssignmentStatementAst
    "0.1.126.1.3": "4df55ee2ec82b09dacdeb06166cb5597576becf1c5e4c4c90eb5524c40b844be",  # TryStatementAst
    "0.1.126.1.3.0.0": "bc83a42b5b61c8c8864a199e22e488f2fd2d2d0f23e5ded1e4cb60ca16737bc9",  # ForEachStatementAst
    "0.1.126.1.3.0.0.2.0": "c39b4962a7af288ac3c07613bb8ed1a1e02fce787197fccfda2c3982b2655f8e",  # AssignmentStatementAst
    "0.1.126.1.3.0.0.2.1": "e014427136be9cea9193f99a2e0a22020901f2ad98dae2bca085b6c5cc2bfd90",  # ForEachStatementAst
    "0.1.126.1.3.0.0.2.1.2.0": "7f29d6b883f2b16ddd0125f0cd0271623a9a87eeb81f5bcd2f144511231a3127",  # IfStatementAst
    "0.1.126.1.3.0.0.2.1.2.0.1.0": "b488e2f8cd5e9acdb0a3d1cfef39149dd1d4d77647101e07fbe977dec94139d5",  # AssignmentStatementAst
    "0.1.126.1.3.0.0.2.2": "0623f59bf0b2c53d893e8d723fcfc1b1ec89367a4f57af6201d7cf3183b8ac9a",  # ForEachStatementAst
    "0.1.126.1.3.0.0.2.2.2.0": "42395598b0fa78a2f1bb7518973c4c0cd24b923102a8c82e9b5c1e6a0b75c9b2",  # AssignmentStatementAst
    "0.1.126.1.3.0.0.2.2.2.1": "e4ab9f89321c8f1fdfa2e1528f3cd04741a7f7f1caa9d4eb640f591e77b874c1",  # IfStatementAst
    "0.1.126.1.3.0.0.2.2.2.1.1.0": "e46d137aa88f444fce8b23e11da29d43508b7e7313310e897642733fff1e125f",  # AssignmentStatementAst
    "0.1.126.1.3.0.0.2.2.2.1.1.0.1.0.0.0.0": "0fbda189c280845b3e001b757951207226b56e57eb841c37d4b9439c94230107",  # PipelineAst
    "0.1.126.1.3.0.0.2.2.2.1.1.1": "92f6c0ecc06e6263507c421b53e220efb84c40b7910c75a7f9a57441bca72914",  # ContinueStatementAst
    "0.1.126.1.3.0.0.2.2.2.2": "859eb514e3dcd053d033f97143144412f288cfc32cc46560b433089208856707",  # AssignmentStatementAst
    "0.1.126.1.3.0.0.2.2.2.3": "6a0447b578e8e3c3386995abc271891ca78ce2e5a79089e60897d55a3dadcc0b",  # AssignmentStatementAst
    "0.1.126.1.3.0.0.2.2.2.4": "a503a336a5ec4677b343a9bd42187f1e25f3dd6bf4d85a1398138b5e1a067ff0",  # IfStatementAst
    "0.1.126.1.3.0.0.2.2.2.4.1.0": "47da20b7a69d7df7257abcf742cca7626fd206535e6be49aeb584a8dbda44061",  # AssignmentStatementAst
    "0.1.126.1.3.0.0.2.2.2.4.1.0.1.0.0.0": "d8277c8a43638333f8d69ddf608ebc501408212dc07b148739f5deae2194c19a",  # PipelineAst
    "0.1.126.1.3.0.0.2.2.2.5": "f62a4fa1c585e3af3c47c2a70ff6aa144c3214374e525900c24518472141e052",  # IfStatementAst
    "0.1.126.1.3.0.0.2.2.2.5.1.0": "40ddd2e43974248bfced76c767733437a48fe575de9761e369894960d2d3f2bd",  # ContinueStatementAst
    "0.1.126.1.3.0.0.2.2.2.6": "453c92c421b1f6f1fd1f2065f201971ee22630f540dff8044adcc3f823faaeeb",  # AssignmentStatementAst
    "0.1.126.1.3.0.0.2.2.2.6.1.0.0.0.0.0": "7e626d96dcc5c9cec9f0ab9e118fff1da57cfdae46510249155f46d89e453b77",  # PipelineAst
    "0.1.126.1.3.0.0.2.2.2.7": "8f74b1616200be77b557e0e23af43a83d4fd7fff2239346d92974eadc69bb0bb",  # AssignmentStatementAst
    "0.1.126.1.3.0.0.2.2.2.8": "789a09cda6b6d15b6147905f83a723e26712ea9d45b0d05ab4427046a522b166",  # AssignmentStatementAst
    "0.1.126.1.3.0.0.2.2.2.8.1.0.1.0.0.0": "96b7914018c38cfa9c6867cce54819bb210677eecb5617ca440244e82b4ba0bc",  # PipelineAst
    "0.1.126.1.3.0.0.2.2.2.9": "bef42240ab5d7e21e1f9605947b56c6eb1e0b1e139b8601db0ff2da6e6024b70",  # AssignmentStatementAst
    "0.1.126.1.3.0.0.2.2.2.9.1.0.1.0.0.0": "73eef000fc65f71995f6b4057f610f7152d56fba6a7d02846d7ebfd1ab7ab42d",  # PipelineAst
    "0.1.126.1.3.0.0.2.2.2.10": "e92c607c2f1737a7fa4df0a0ed283245226272da42fa1295feeac2d743e4f8e1",  # AssignmentStatementAst
    "0.1.126.1.3.0.0.2.2.2.10.1.0.1.0.0.0": "1025dc0f733c76bd41f2f3e6ddf2babfde2327b689d089f16c9246f0236f9df8",  # PipelineAst
    "0.1.126.1.3.0.0.2.2.2.11": "6d986067cce5d7b07050e2870ba51ffdde5065883b12d5491b48510d42329973",  # AssignmentStatementAst
    "0.1.126.1.3.0.0.2.2.2.11.1.0.1.0.0.0": "5375a47b601f4e7d7a4200b97d4e44060c5cec83a6191ec02bb4e425b891ba1d",  # PipelineAst
    "0.1.126.1.3.0.0.2.2.2.12": "eb5444ae4aae312f3852400872aaa85eaf0b4b47b960e5a3c493cf1b9ec745ec",  # AssignmentStatementAst
    "0.1.126.1.3.0.0.2.2.2.13": "6bd9fdbfdf3cd34ff379998efcefee1d0c6b8365e2afffb3afb24c851ea7dbe1",  # IfStatementAst
    "0.1.126.1.3.0.0.2.2.2.13.1.0": "1b90ce3945db1855fb92f983622a4377aed572c7c1b95c0d61068d7cad040898",  # AssignmentStatementAst
    "0.1.126.1.3.0.0.2.2.2.13.1.1": "314e4b5f2edf1c001398085e1d92b6afb45e44dd6706ba8fb657fec5b89f4669",  # ForEachStatementAst
    "0.1.126.1.3.0.0.2.2.2.13.1.1.1.0.0.0.0": "266b03c86558f3614242f4ff0accb7e98f57c13cb3bda6463b1f3d2932606df5",  # PipelineAst
    "0.1.126.1.3.0.0.2.2.2.13.1.1.2.0": "d4be5e9e65ab6339279955a01767e9d953dcfc6375bbd217fa4a295286b085ba",  # IfStatementAst
    "0.1.126.1.3.0.0.2.2.2.13.1.1.2.0.1.0": "8f43744a5265f3b19835eb834aa9e16777409caa5c5ef0458071a34ef17168e4",  # AssignmentStatementAst
    "0.1.126.1.3.0.0.2.2.2.14": "00ece61d23d89a464cb1d088feb09d5c9cb3735245509699da85ac40f3a3c0e1",  # AssignmentStatementAst
    "0.1.126.1.3.0.0.2.2.2.14.1.0.1.7.1.0": "73c265bf07ff48276ef83b88edde637824250a211b2fe27fa8cac4a7d9b9dd7d",  # PipelineAst
    "0.1.126.1.3.0.0.2.2.2.14.1.0.1.7.2.0": "7cc2c6e38e51fa0e5e4da380cbd1c79af5734cd210d929c21023243ba5245632",  # PipelineAst
    "0.1.126.1.3.0.0.2.2.2.14.1.0.1.9.1.0": "d65f4b0deb48a95cbac7f2f73cd36498ee2c616b40944d42745c7ad64d606ba0",  # PipelineAst
    "0.1.126.1.3.0.0.2.2.2.14.1.0.1.9.2.0": "7d7c2abfc171f9813de8ccee26f252a83a5340e7f0cb6569f33621cc94787e8e",  # PipelineAst
    "0.1.126.1.3.0.0.2.2.2.14.1.0.1.13.1.0": "392f13f7141c6e489b0b1f6cc7bdf12b23f1e940e5fbaffbdc4aa562eb4ad426",  # PipelineAst
    "0.1.126.1.3.0.0.2.2.2.14.1.0.1.13.2.0": "20d1fdd1dc358b95a0ecde7c4501ac9f495a42c116239fc3576b8e4400832823",  # PipelineAst
    "0.1.126.1.3.1.0.0": "33683524ce28f68383be33b20060125e535633d0193b8e6490a2e24ff18a8a7d",  # AssignmentStatementAst
    "0.1.126.1.3.1.0.1": "3e6ec3c8fa2fcc5129f97cc9694f17ab2015adcebcbf10b48e6c2ba5c3a21727",  # AssignmentStatementAst
    "0.1.126.1.3.1.0.1.1.0.0.0.0": "9cc64a73bccb00262f240b6c261c9d1be1b12b061381d8f27d2534a83b5dd79a",  # PipelineAst
    "0.1.126.1.3.1.0.2": "95de1d5e1b007a3bc9b12c9c809c905e097d3642d4bf475e0f2d84bb016a89d1",  # PipelineAst
    "0.1.126.1.4": "539e53a8ee841db0857f5eee305267a80c777f30b9314fd422b47c20fb7be4aa",  # AssignmentStatementAst
    "0.1.127": "96ec5978107eb846fe06e1021d5b3960f06e975f045c0eeb40ae675ad2c009a7",  # AssignmentStatementAst
    "0.1.128": "ec7af7af6b518bcf318d2cad90a5bdad00cd1f98b0a0112ae1dcfc1580c45183",  # AssignmentStatementAst
    "0.1.129": "7044aabc0f49eced0bdf95644298ec8f7d3c23d812568929b6b3c35ee9495449",  # AssignmentStatementAst
    "0.1.130": "d187515e6e0a092c398274fd1213a3732ab964f50f1d102679824c247ce084a6",  # AssignmentStatementAst
    "0.1.131": "2364f2070f6aba524f835b069fb37aba4bb02847d9d42783a5ba67cf8abe374d",  # IfStatementAst
    "0.1.131.1.0": "73f7180d6743d7149b28ed345413ba0b8668ed8f79f4269180022bc12f51f140",  # AssignmentStatementAst
    "0.1.131.1.1": "c6beea59a813c3ee3b31b2145257ed292301f11c15565a749959ebe525b50e43",  # TryStatementAst
    "0.1.131.1.1.0.0": "10841f88fc02618d69270d4bf1509f9f4953727103b11fd3f47292964c4ad34d",  # AssignmentStatementAst
    "0.1.131.1.1.0.0.1.0.3.0.0": "b0095e0133c02a9fc052fa1fcc6e992f2f8f4c99f2eb5ebb270117ef73d91ad4",  # PipelineAst
    "0.1.131.1.1.0.1": "437650d99c040cb527352fcf1e7a732608424d2e1fa046df5dc9a003453ad80d",  # AssignmentStatementAst
    "0.1.131.1.1.0.2": "5f73680a5af3e59072183048deeecac0307abb67486ce953aa2931ca2c331594",  # ForEachStatementAst
    "0.1.131.1.1.0.2.2.0": "d37d2de5e496f6fc649d882727a58412d2922833a52aa21804472ffd6037ebcf",  # TryStatementAst
    "0.1.131.1.1.0.2.2.0.0.0": "6473102037e2b444140a1aa4fd94d01aeb3a12ad298b2b280a2de33545d969ca",  # AssignmentStatementAst
    "0.1.131.1.1.0.2.2.0.0.1": "c7ffc8edb21bb350099d37c26cf7e69ae02e57842f84cff8eb7084af6eeda219",  # AssignmentStatementAst
    "0.1.131.1.1.0.2.2.0.0.2": "4bed9ee9c69f85a92319132b24c409d709ed548e1abb09ad4f2b5f0818344f20",  # AssignmentStatementAst
    "0.1.131.1.1.0.2.2.0.0.2.1.0.1.1.0.0.1.0.0.0": "75692764e001bdfb86eaabe89566910c5a45977fde9c02356edbf524c7a177c3",  # PipelineAst
    "0.1.131.1.1.0.2.2.0.0.2.1.0.1.3.0.0.0.0.1.0.0": "54ab09bdbd6ce679edd5ce541c12b5824ea888a686b893e90fe75cae0b7ef020",  # PipelineAst
    "0.1.131.1.1.0.2.2.0.0.2.1.0.1.5.0.0.0.0.0.0.0": "8c85573a8bdf3629da3d9e6706f033be2f3408237c5484efd689285b29c4e6b9",  # PipelineAst
    "0.1.131.1.1.0.2.2.0.0.2.1.0.1.5.0.0.0.0.0.0.0.1.1.0.0.0": "24b15ce1e7a709474da4ea883e4edbbaca032ccdf02cda187b076deff5692f99",  # PipelineAst
    "0.1.131.1.1.0.2.2.0.1.0.0": "6a6643dc43a84859e7d2df8056e69c888fb7e96bdd6adf30842b0a8957a76a8d",  # AssignmentStatementAst
    "0.1.131.1.1.0.2.2.0.1.0.0.1.0.0.0.0": "e8920fe1a17d36afe70f18e2fd2b338d2484e4523b2a24322b7b87ba58efc624",  # PipelineAst
    "0.1.131.1.1.0.3": "b155b98b237c4cf00f0e73155f3bcbf85e320cdedd29571b5559ad3fed207ca6",  # AssignmentStatementAst
    "0.1.131.1.1.0.4": "51d85096ce21cc83a5d8572aec881f7dbd5e8642592c28c764cd3a1d10404422",  # PipelineAst
    "0.1.131.1.1.0.4.0.3.0.0.0": "dcae3e8c8ae56962052f6fb84e0d23a054407bb191b8987472cf70858f0bec09",  # PipelineAst
    "0.1.131.1.1.1.0.0": "1d7f5022ce7eaa8e1611ca93430f479b48418c3f3de8d4e53eb5526fde1f4a93",  # PipelineAst
    "0.1.131.1.1.1.0.0.0.1.0.0.0": "ff213b448ce901d973f3add7780f8153fd88eafdda286c22d7b5b152228f6aba",  # PipelineAst
    "0.1.131.1.2": "46f7beb27a926aaf5218213ecc05c8217f594d6f4be6a0697f584f97387db059",  # AssignmentStatementAst
    "0.1.131.1.3": "7c73802e15d550fb4ffa9b1f84a0b9665420ad1c567492b29272a0285adfc936",  # AssignmentStatementAst
    "0.1.131.1.4": "3ba0043f43cecb414a6428580715a55270f3bc0b2ccfc5288872c728288270a5",  # IfStatementAst
    "0.1.131.1.4.1.0": "3220b93e739aa7966eb454384afb37ff2a92f7f9bc7d86e2e2d2e2424d6c3b21",  # AssignmentStatementAst
    "0.1.131.1.5": "220b6c53b32d095434febdd8c09fa126536377eef42fe8eaa0e4376e05c080c2",  # AssignmentStatementAst
    "0.1.131.1.5.1.0.3.0.0": "df2cf0d2ccfa3ba18926f8aae21445ce99473a22dd8245868575bb00ef35dc09",  # PipelineAst
    "0.1.131.1.6": "c110dbaec70203b64007dd5831d1dbd668177a000a1e2ee91633d27b4aabb5a8",  # AssignmentStatementAst
    "0.1.131.1.7": "61dba74fd644eeb69e78398f2a0d4b8401efb94897e096b44faffb1ba07044db",  # ForEachStatementAst
    "0.1.131.1.7.2.0": "9ba117fe235831c9dd9fa4184ae57426d440faa6c5b40e79637f09c9e9c7624d",  # TryStatementAst
    "0.1.131.1.7.2.0.0.0": "27577d9acbc5d69d78915876d7316143f9ff599a0ecadc2fe614060574d4ce50",  # AssignmentStatementAst
    "0.1.131.1.7.2.0.0.1": "ca7ef4b894e260d9a341705fa87e10876f9a81448397ae2f86b91099114cab28",  # AssignmentStatementAst
    "0.1.131.1.7.2.0.0.2": "43379b19af2466eafbd633ee67288e8fe50dff864164af48a6b6ea3e28e0a907",  # AssignmentStatementAst
    "0.1.131.1.7.2.0.0.2.1.0.1.0.0.0": "6391b079daae7ddd1ccc0b3f62de9421591f7b996520e398d78ffffceb7539e2",  # PipelineAst
    "0.1.131.1.7.2.0.0.3": "eeba80c93cc5ad815ef329215633d8f92747ff3dadac99d7e2b1cca78a145c41",  # AssignmentStatementAst
    "0.1.131.1.7.2.0.0.3.1.0.1.0.0": "158207480faf34cf5e53aee0cef2de5dca7a746812320af92bf10c230d452012",  # PipelineAst
    "0.1.131.1.7.2.0.0.4": "594947e88527b403606a2ac90d0a667a7968bd8215229af4f56ad886b3e37372",  # AssignmentStatementAst
    "0.1.131.1.7.2.0.0.5": "d00b7927b03f0149087ee07a73701574f210b8e8a548ea1f4e8529640c89df33",  # AssignmentStatementAst
    "0.1.131.1.7.2.0.0.6": "9cf34bc75b368c433626d48a54949c35fa669d1a0098cf6df1d04c6a0dff2a15",  # IfStatementAst
    "0.1.131.1.7.2.0.0.6.1.0": "b1f11dc854dbf2d25d1600aff34e7186ea4835c1f5da7142be770612b3120582",  # AssignmentStatementAst
    "0.1.131.1.7.2.0.0.6.1.0.1.0.1.0.0.0": "583fb8d360e551b16f60a1d8e6a78c683bf81b9b83d721acb3e1b6233be24aa6",  # PipelineAst
    "0.1.131.1.7.2.0.0.6.1.1": "d59b20570c0299ede84ab75b653f2955e8d1b6d933284be728c4c6b7c7b59eca",  # PipelineAst
    "0.1.131.1.7.2.0.0.6.2.0": "52345125d40b9c2dcc0d60ff78a075f8d8ea85a335eecfb5e2b9fa3ef152a45b",  # TryStatementAst
    "0.1.131.1.7.2.0.0.6.2.0.0.0": "91dfb239c20fb5ab2425e183ebd5f0f3df86d1b9983e50a2d0b882f0b4918d42",  # IfStatementAst
    "0.1.131.1.7.2.0.0.6.2.0.0.0.1.0": "06026980c35fb1f02dccd3b2bf05392aaf626805226ba453a0181162681a2bc9",  # AssignmentStatementAst
    "0.1.131.1.7.2.0.0.6.2.0.0.0.3.0": "7a5a462bb56775dffecbf261d46d17e79b9fd47769e1c54af257f0d72b597441",  # AssignmentStatementAst
    "0.1.131.1.7.2.0.0.6.2.0.0.0.4.0": "6963eba82a5da369209a954196c9256038c2750a83d33308435b24f92e09e040",  # AssignmentStatementAst
    "0.1.131.1.7.2.0.0.6.2.0.0.1": "09b4820f0de20bc97bf149a7ff97067cb7b910f553c7bd37978b352fd5ca4b33",  # AssignmentStatementAst
    "0.1.131.1.7.2.0.0.6.2.0.0.2": "1ee76fa078ca77dd7924443f15707596e885a92485ca556042f27c380247a534",  # SwitchStatementAst
    "0.1.131.1.7.2.0.0.6.2.0.0.2.2.0": "d444ae1b0d9b068557a21984aada974106c2093db3827cd9bae43a763f85ca6b",  # AssignmentStatementAst
    "0.1.131.1.7.2.0.0.6.2.0.0.2.4.0": "59cede225500b8d84430a822686ba6f4f754af47b57d9d48f466c402115cb36b",  # AssignmentStatementAst
    "0.1.131.1.7.2.0.0.6.2.0.0.3": "d2ba003b963b100f16c6b202926b340f4007de9dd2a0e079328e54234f04a6cb",  # AssignmentStatementAst
    "0.1.131.1.7.2.0.0.6.2.0.0.4": "d757d9dcaf6ee2e33e49a9ed774131ab6acd96cade625039481c1d458d829fac",  # SwitchStatementAst
    "0.1.131.1.7.2.0.0.6.2.0.0.4.2.0": "833885054f9f034baf609b8323b0752c0035395ff33921341a829aa7430c2693",  # AssignmentStatementAst
    "0.1.131.1.7.2.0.0.6.2.0.0.4.4.0": "d07f76cdd5a361b1af3364e3aa835ac98c8b6567dff94ff5acba2a86321347a8",  # AssignmentStatementAst
    "0.1.131.1.7.2.0.0.6.2.0.1.0.0": "9d29a02b4e7ceda7688df9f27e1b2b0a5f60694400d38c4c4f89011ee48ac1ea",  # PipelineAst
    "0.1.131.1.7.2.0.0.6.2.0.1.0.0.0.1.1.0.0": "13ae20044113a0b33146f1664ab5fbf2cf068463d24713e9723e4a00482deb26",  # PipelineAst
    "0.1.131.1.7.2.0.0.7": "80ea15fecfe2e5918a51e1bac14c145319e72a29a44cf1e79b51791a7eb8dc8e",  # AssignmentStatementAst
    "0.1.131.1.7.2.0.1.0.0": "c29f087e1aa0f301965e6cabfcee9de4b937b068660fe9188be6f861d4bb6f53",  # AssignmentStatementAst
    "0.1.131.1.7.2.0.1.0.0.1.0.0.0.0": "751500df771e0ebacea16a2ee43955c524fd3485a7c440c021e06c7c88fa2ad3",  # PipelineAst
    "0.1.131.1.8": "90404b1cabc9262363777a5064be8bd496823ab272c8ddbf1223bf256c65d6ce",  # AssignmentStatementAst
    "0.1.131.1.8.1.0.0.0.0": "8e87caa1255ff15657308f638702668b479bd68ed7ec5605812b8aac24cd6bbf",  # PipelineAst
    "0.1.131.1.8.1.0.0.0.0.1.1.0.0.0": "6e5d5b3755ab10c4e31300fd133bf1f63fb15efa4391047ce657748bb20162a9",  # PipelineAst
    "0.1.131.1.9": "885b9f2a848599f9ac709d4a35be9c0855e824a31892e3fdbf524a839cf34ef0",  # IfStatementAst
    "0.1.131.1.9.1.0": "a75a5c8d5e2edec345e9e10e29c1c480f62ab6c4eef09e8e4824554489b2a0e6",  # PipelineAst
    "0.1.131.1.9.1.0.0.1.0.0.0": "0eb3bbedc2033c286c45a573b10bc70af57ddb6ab7c4b839ee5fb0c54c6729f2",  # PipelineAst
    "0.1.131.1.9.1.1": "b8dcf5bba3f5a778d5284035c8f1fceebc57f3bac5c1a6de595ad476b824030d",  # AssignmentStatementAst
    "0.1.131.1.9.2.0": "a5cf09c6cbabed25e0b4c92a1ce82716c14104e2f9726ff810c84e314d6fe462",  # AssignmentStatementAst
    "0.1.131.1.9.2.1": "1a2b83d0b3784cb6e3db1f0c7dc481dfd42eeda43024ca1a1769f3a0e7e2eaf1",  # PipelineAst
    "0.1.131.1.9.2.1.0.3.0.0.0": "c880d260e66466c0481dda1ac3e61ba1375b894d4252e1c0e9f05a5df88dfa26",  # PipelineAst
    "0.1.132": "2f4ce5e5b97d0e1617ed9186887a2c32dfeb6eafaf15ffa230107ccf128af075",  # AssignmentStatementAst
    "0.1.133": "2cd64ca07a83e2eb35ab7a026a24efac97f4f06d99afbe737adcd8ec542d8680",  # IfStatementAst
    "0.1.133.1.0": "8ef8d7edfcd4fc266e12427581274c87119fc3db7014264edaf49a7f725701db",  # AssignmentStatementAst
    "0.1.134": "5224c1bd0a2627cbe15a0ba3cb606e88914a042a3c9608f6ca7ae54e20eb2df4",  # IfStatementAst
    "0.1.134.1.0": "1bb3188c00f88744247ca47e190327a328836b79706083196e4cc82b564eefa5",  # AssignmentStatementAst
    "0.1.135": "bd1aa633a7e346c464b1bff828094450073cc99f2ee9e8078842595f283804a9",  # IfStatementAst
    "0.1.135.1.0": "8bfe23221a8b602a3085ed28d8d1cd6a4bfa2c36b80a0d58e7971cd21c3af3dd",  # AssignmentStatementAst
    "0.1.136": "5d5fa118ac0f4c7fc4db9240662429e03233a454773abcdcbbdcb4acac617aac",  # IfStatementAst
    "0.1.136.1.0": "4b1c2f9d01e1e0ec2acdb363e7a2c347c3d8bd93969cf8a2eb1a9ce71dd0fcf0",  # AssignmentStatementAst
    "0.1.137": "2d913b564edce69d0b690157ba9e036caa12c6d51cc736ca1494085ee09de893",  # IfStatementAst
    "0.1.137.1.0": "1e791ba153d7c52b7a7dd1b7433ebd2e834320d7d859bde0e6419bd3d7a73cdc",  # AssignmentStatementAst
    "0.1.138": "2606357e04c31815173cd9cc783629fda0f5c615b194d8be8718ce39e1b3096b",  # AssignmentStatementAst
    "0.1.138.1.0.1.9.0.0.0.0.0.0.0": "a01de5b5ee87190f2cc2ab55da121bcdeee753146f410677b306402ec850dd5d",  # PipelineAst
    "0.1.139": "0b768ecd16b7e45e5785aaa86283f904a3e01a22eb59c1643a22c25584755725",  # PipelineAst
    "0.1.139.0.1.0.0": "97774bbc2592252f0146610f6330ecb76df43189dad5f47bb89987176562c55b",  # PipelineAst
    "0.1.140": "4af3f0757880cbd091ae962e4ee4c66ce91e7a02baa056530e4b74fa90b64a04",  # PipelineAst
    "0.1.140.0.1.0.0": "4d25ea7e6fcdc2d511fc8d22ce4a79f2278fc212da43284d26d7e3cfdda3c4aa",  # PipelineAst
    "0.1.141": "5e1ce15360a2cef37db2073b79c6aebb2a5dd17db6c431bf6f32105d264326d4",  # PipelineAst
    "0.1.141.0.1.0.0": "b913154989f478144477d4680ae5758445447614d886e590f2c14e1954f80f47",  # PipelineAst
    "0.1.142": "b71bde9a5487df37752de8e48c73fdd5bd0d28b2f7a220d4fa87dda74aebb987",  # PipelineAst
    "0.1.142.0.1.0.0": "40c26b235e8bc16a3d38c549619fa74d80351a14d5309c07deb2e600952a52cd",  # PipelineAst
    "0.1.143": "9a7f37ff56705b8c1192bcf2ab554b297405274ac72d90e2692b826147844bf5",  # PipelineAst
    "0.1.143.0.1.0.0": "402765a3e43d55e8ec49f446f0465cde8ade080089833e6ce1bf2ca6db6f48c9",  # PipelineAst
    "0.1.144": "e97bd7e9c6e1f9bc31a5ce4fa5a85af8a06309edeec4cadb8405a0dccfd9afcc",  # PipelineAst
    "0.1.144.0.1.0.0": "f37080139dd7acc6eb107beff00bcea8ae00609c6bfd1dcc9f8db0234ef8a4f5",  # PipelineAst
    "0.1.145": "06824522c6913ab8594bbfa3a3f3d9fe302679a8770f9e35956e3388026d036f",  # PipelineAst
    "0.1.145.0.1.0.0": "d7ff3e6d80ddbf0eb40def8043367445f85285862205f3be5c9b34299a5633d1",  # PipelineAst
    "0.1.146": "2b33d6be68a30fdb93e129fab8682eaba36a5a08836276231a168e06092984d6",  # PipelineAst
    "0.1.147": "f6c8eefe685b199fabdb7fc936b519f3ca72b14147b68719636b6e09c27a476c",  # PipelineAst
    "0.1.148": "1d6368296e4884491b99c5a156e9b49a89b59ab3f8aa9907c74dd49aecc6024a",  # IfStatementAst
    "0.1.148.1.0": "59211bfa12e979ae615a84da7b4ad68919c1a1ba32faabe20e8f9a06490f5cd6",  # PipelineAst
    "0.1.148.1.0.0.1.0.0.0.1.1.0.0.0.0": "7b4ac614cf4cd0c0d7969b45f412f66a05d1883664772f1a8e9ed98e32619569",  # PipelineAst
    "0.1.148.1.0.0.1.0.0.0.1.3.0.0.0.0": "dc881e018143332078e258742072acb70e3eaa4b308e207f53285903d66bfaec",  # PipelineAst
    "0.1.149": "3bb958e5aaecfa85022c8248aac92594ec2b145d21810f01497227301877cdd6",  # PipelineAst
    "0.1.150": "5ebbc468272d1f35618c2abb3dcd50e862a1df4010e9f3510cd94c22b3b03125",  # PipelineAst
    "0.1.150.0.1.0.0.0.1.9.0.0.0.0.0.0.0.0.0": "6e306d5498dbcd6e1fd1025d19889f0f6fb412caa6eeac92839a27c7532e95b5",  # PipelineAst
    "0.1.150.0.1.0.0.0.1.9.0.0.0.0.0.1.1.0.0.0": "e874aa99466ab3ea3cbccaa327ff6487924a60518437ab9f3371a74254758827",  # PipelineAst
}

# Automatic and preference variables. The engine reads them, so binding one
# changes how *other* statements behave; a write is refused unless it is in
# SPECIAL_BINDINGS. Any variable named *preference is treated the same way.
_SPECIAL_VARIABLES = frozenset(
    {
        "$",
        "?",
        "^",
        "_",
        "args",
        "consolefilename",
        "enabledexperimentalfeatures",
        "error",
        "errorview",
        "event",
        "eventargs",
        "eventsubscriber",
        "executioncontext",
        "false",
        "foreach",
        "formatenumerationlimit",
        "home",
        "host",
        "input",
        "iscoreclr",
        "islinux",
        "ismacos",
        "iswindows",
        "lastexitcode",
        "logcommandhealthevent",
        "logcommandlifecycleevent",
        "logenginehealthevent",
        "logenginelifecycleevent",
        "logproviderhealthevent",
        "logproviderlifecycleevent",
        "matches",
        "maximumaliascount",
        "maximumdrivecount",
        "maximumerrorcount",
        "maximumfunctioncount",
        "maximumhistorycount",
        "maximumvariablecount",
        "myinvocation",
        "nestedpromptlevel",
        "null",
        "ofs",
        "outputencoding",
        "pid",
        "profile",
        "psboundparameters",
        "pscmdlet",
        "pscommandpath",
        "psculture",
        "psdebugcontext",
        "psdefaultparametervalues",
        "psedition",
        "psemailserver",
        "pshome",
        "psitem",
        "psnativecommandargumentpassing",
        "psnativecommanduseerroractionpreference",
        "psscriptroot",
        "pssenderinfo",
        "pssessionapplicationname",
        "pssessionconfigurationname",
        "pssessionoption",
        "psstyle",
        "psuiculture",
        "psversiontable",
        "pwd",
        "sender",
        "shellid",
        "stacktrace",
        "switch",
        "this",
        "transcript",
        "true",
    }
)
# Never referenced at all (read or write): engine-wide parameter injection,
# module auto-loading, and the engine object itself.
FORBIDDEN_VARIABLE_REFS = frozenset(
    {"psdefaultparametervalues", "psmoduleautoloadingpreference", "executioncontext"}
)
# The only automatic/preference variable bindings the collector makes.
SPECIAL_BINDINGS: frozenset[tuple[str, tuple[str, str, str]]] = frozenset(
    {
        ("erroractionpreference", ("assign Equals", _SCRIPT, "'Stop'")),
        # _certutilRead lets certutil's native stderr through (2>&1) and restores
        # the caller's preference in a finally block.
        ("erroractionpreference", ("assign Equals", "_certutilread", "'Continue'")),
        ("erroractionpreference", ("assign Equals", "_certutilread", "$prev")),
    }
)
# Qualifiers a binding may carry. `$global:` leaks into the caller's session,
# `$variable:` is the variable provider, and a drive (`${alias:x}`, `$env:x`,
# `${function:x}`, `${C:\\file}`) is a provider write.
_ALLOWED_QUALIFIERS = frozenset({"", "script", "local", "private"})
# Variables the engine sets that a pinned binding may read without a pin of
# their own (none of them may be bound: see the special-variable check).
_AUTO_READ_OK = frozenset({"_", "psitem", "true", "false", "null", "matches", "pscmdlet"})

# Operations that write, execute, load code or reach another host. Each is
# pinned in GUARDED_OPS with its exact text and control-flow context.
_GUARDED_COMMANDS = frozenset(
    {
        "New-Item",
        "certutil",
        "Get-WmiObject",
        "Import-Module",
        "Add-Type",
        "_writeJson",
        "New-Object",
    }
)
_GUARDED_STATIC = frozenset({("[IO.File]", "WriteAllText"), ("[IO.File]", "WriteAllBytes")})
# Lifetime-changing calls on a handle/stream/searcher/registry-key receiver
# (release a lock, flush a buffer, clear a store). Their call count and location
# matter, so they are guarded (not collapsed into a set) even though the
# collector currently makes none. A method here that is not also in
# ALLOWED_INSTANCE is still refused by the member allowlist.
_LIFETIME_METHODS = frozenset(
    {"Dispose", "Close", "Flush", "Clear", "Delete", "Remove", "Reset", "Stop", "Kill"}
)
# Instance methods whose invocation has an external effect (a registry/WMI read,
# an LDAP query execution, a lifetime change). Pinned in GUARDED_OPS with
# context, so a duplicate or reordered call fails.
_GUARDED_INSTANCE = (
    frozenset({"GetDWORDValue", "OpenSubKey", "SendRequest", "Bind"}) | _LIFETIME_METHODS
)
# The only dynamic invocations: a local helper running the scriptblock it was
# handed (the paged / base LDAP search transport, and _tryRead's read). Each is
# pinned by scope and exact text; the invoked variable is binding-pinned, and the
# scriptblock bodies are ordinary collector code checked like everything else.
DYNAMIC_INVOCATIONS: frozenset[tuple[str, str]] = frozenset(
    {
        ("_pagedsearchcore", "& $send $cookie"),
        ("_basesearchcore", "& $send $null"),
        ("_tryread", "& $read"),
    }
)
# Common parameters that write a variable named by their argument (canonical
# names as cmdlet metadata reports them).
_VARIABLE_WRITING_PARAMS = frozenset(
    {"OutVariable", "ErrorVariable", "WarningVariable", "InformationVariable", "PipelineVariable"}
)
# A UNC path, a `//host` authority, or a URL with a scheme: never in a command
# argument, a .NET call argument or a binding value (the collector reads its
# own host, the directory through the located DC, and named DCs by dNSHostName).
# Exact string literals exempted from the UNC/URL screen. Reviewed and committed;
# the collector currently needs none (its literal JSON schema tables contain only
# single-backslash registry paths and dotted identifiers, not UNC or URLs).
REMOTE_LITERAL_EXEMPTIONS: frozenset[str] = frozenset()
_UNC_OR_URL = re.compile(
    r"(?:^|(?<=['\"\s(,=@{]))\\\\[^\\\s'\"]|(?<![:\w])//[A-Za-z0-9]|\b[A-Za-z][A-Za-z0-9+.-]*://"
)
# Credential-bearing variables: the four credential parameters and everything
# derived from them (closed under binding flow: test_secret_taint_is_closed).
# Each reference is pinned to its exact (scope, statement) in SECRET_USES, so a
# credential cannot be logged, written, sent to another host or passed anywhere
# new without a deliberate edit here.
SECRET_SEEDS = frozenset({"ldapuserb64", "ldappassb64", "dcregistryuserb64", "dcregistrypassb64"})
SECRET_VARIABLES: frozenset[str] = frozenset(
    {
        "<script>::dccred",
        "<script>::dcregistrypass",
        "<script>::dcregistrypassb64",
        "<script>::dcregistryuser",
        "<script>::dcregistryuserb64",
        "<script>::ldappass",
        "<script>::ldappassb64",
        "<script>::ldapuser",
        "<script>::ldapuserb64",
        "<script>::reg",
        "_b64::s",
        "_ldapconnection::conn",
        "_ldapconnection::cred",
        "_ldapconnection::ldapconn",
    }
)
SECRET_USES: dict[str, list[tuple[str, str]]] = {
    "<script>::dccred": [
        ("<script>", "$dcCred"),
        ("<script>", "$dcCred = $null"),
        (
            "<script>",
            "$dcCred = New-Object Management.Automation.PSCredential( $DcRegistryUser, (ConvertTo-SecureString $DcRegistryPass -AsPlainText -Force))",
        ),
        (
            "<script>",
            "Get-WmiObject -ComputerName $dcDns -Credential $dcCred -Namespace 'root\\default' -Class StdRegProv -List",
        ),
    ],
    "<script>::dcregistrypass": [
        ("<script>", "$DcRegistryPass = ''"),
        ("<script>", "$DcRegistryPass = _b64 $DcRegistryPassB64"),
        ("<script>", "ConvertTo-SecureString $DcRegistryPass -AsPlainText -Force"),
    ],
    "<script>::dcregistrypassb64": [
        ("<script>", ""),
        ("<script>", "$DcRegistryUserB64 -and $DcRegistryPassB64"),
        ("<script>", "$DcRegistryUserB64 -or $DcRegistryPassB64"),
        ("<script>", "_b64 $DcRegistryPassB64"),
    ],
    "<script>::dcregistryuser": [
        ("<script>", "$DcRegistryUser"),
        ("<script>", "$DcRegistryUser = ''"),
        ("<script>", "$DcRegistryUser = _b64 $DcRegistryUserB64"),
        (
            "<script>",
            "$DcRegistryUser, (ConvertTo-SecureString $DcRegistryPass -AsPlainText -Force)",
        ),
    ],
    "<script>::dcregistryuserb64": [
        ("<script>", ""),
        ("<script>", "$DcRegistryUserB64 -and $DcRegistryPassB64"),
        ("<script>", "$DcRegistryUserB64 -or $DcRegistryPassB64"),
        ("<script>", "_b64 $DcRegistryUserB64"),
    ],
    "<script>::ldappass": [
        ("<script>", "$LdapPass = ''"),
        ("<script>", "$LdapPass = _b64 $LdapPassB64"),
        ("_ldapconnection", "$LdapUser, $LdapPass"),
    ],
    "<script>::ldappassb64": [
        ("<script>", ""),
        ("<script>", "$LdapUserB64 -and $LdapPassB64"),
        ("<script>", "$LdapUserB64 -or $LdapPassB64"),
        ("<script>", "_b64 $LdapPassB64"),
    ],
    "<script>::ldapuser": [
        ("<script>", "$LdapUser"),
        ("<script>", "$LdapUser = ''"),
        ("<script>", "$LdapUser = _b64 $LdapUserB64"),
        ("<script>", 'Write-Host "Using explicit LDAP credentials ($LdapUser)"'),
        ("_ldapconnection", "$LdapUser"),
        ("_ldapconnection", "$LdapUser, $LdapPass"),
    ],
    "<script>::ldapuserb64": [
        ("<script>", ""),
        ("<script>", "$LdapUserB64 -and $LdapPassB64"),
        ("<script>", "$LdapUserB64 -or $LdapPassB64"),
        ("<script>", "_b64 $LdapUserB64"),
    ],
    "<script>::reg": [
        (
            "<script>",
            "$kdc = $reg.GetDWORDValue($HKLM, 'SYSTEM\\CurrentControlSet\\Services\\Kdc', 'StrongCertificateBindingEnforcement')",
        ),
        (
            "<script>",
            "$reg = Get-WmiObject -ComputerName $dcDns -Credential $dcCred -Namespace 'root\\default' -Class StdRegProv -List",
        ),
        (
            "<script>",
            "$reg = Get-WmiObject -ComputerName $dcDns -Namespace 'root\\default' -Class StdRegProv -List",
        ),
        ("<script>", "$reg = Get-WmiObject -Namespace 'root\\default' -Class StdRegProv -List"),
        (
            "<script>",
            "$sch = $reg.GetDWORDValue($HKLM, 'SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL', 'CertificateMappingMethods')",
        ),
    ],
    "_b64::s": [
        ("_b64", "[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($s))"),
        (
            "_b64",
            "function _b64([string]$s) { [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($s)) }",
        ),
    ],
    "_ldapconnection::conn": [
        ("_ldapconnection", "$conn"),
        (
            "_ldapconnection",
            "$conn = [System.DirectoryServices.Protocols.LdapConnection]::new($id)",
        ),
        (
            "_ldapconnection",
            "$conn = [System.DirectoryServices.Protocols.LdapConnection]::new($id, $cred)",
        ),
        (
            "_ldapconnection",
            "$conn.AuthType = [System.DirectoryServices.Protocols.AuthType]::Negotiate",
        ),
        ("_ldapconnection", "$conn.Bind()"),
        ("_ldapconnection", "$conn.SessionOptions.ProtocolVersion = 3"),
        ("_ldapconnection", "$script:LdapConn = $conn"),
    ],
    "_ldapconnection::cred": [
        (
            "_ldapconnection",
            "$conn = [System.DirectoryServices.Protocols.LdapConnection]::new($id, $cred)",
        ),
        (
            "_ldapconnection",
            "$cred = New-Object System.Net.NetworkCredential($LdapUser, $LdapPass)",
        ),
    ],
    "_ldapconnection::ldapconn": [
        ("_ldapconnection", "$script:LdapConn"),
        ("_ldapconnection", "$script:LdapConn"),
        ("_ldapconnection", "$script:LdapConn = $conn"),
    ],
}
# SHA-256 of the script header (comment help, [CmdletBinding], param block).
HEADER_SHA256 = "2840733cd4a19d1fb54debc57b01d33f070383375d3419ac0445e277724c33c8"

# Allowlisted instance method -> the receiver roots it may be called on
# (lower-cased; "" = a non-variable receiver such as `(Get-Date)` or a
# parenthesised expression). A call on any other receiver fails.
INSTANCE_RECEIVERS: dict[str, frozenset[str]] = {
    "Add": frozenset(["entries", "req"]),
    "Bind": frozenset(["conn"]),
    "ContainsKey": frozenset(["localsecurity", "p"]),
    "Equals": frozenset(["full"]),
    "GetAccessRules": frozenset(["sd"]),
    "GetDWORDValue": frozenset(["reg"]),
    "GetEnumerator": frozenset(["map"]),
    "GetNewClosure": frozenset([""]),
    "GetOwner": frozenset(["sd"]),
    "GetString": frozenset([""]),
    "GetValue": frozenset(["key"]),
    "GetValues": frozenset(["attr"]),
    "OpenSubKey": frozenset([""]),
    "SendRequest": frozenset(["conn"]),
    "Serialize": frozenset(["js"]),
    "SetSecurityDescriptorBinaryForm": frozenset(["sd"]),
    "StartsWith": frozenset(["dcdns", "full"]),
    "ToLower": frozenset(["", "dcdns", "dns", "ot", "p"]),
    "ToString": frozenset(["", "_", "a"]),
    "ToUniversalTime": frozenset([""]),
    "Translate": frozenset(["a"]),
    "Trim": frozenset(["line", "matches", "v", "values"]),
    "TrimEnd": frozenset([""]),
    "TrimStart": frozenset(["apppath"]),
}

# Every .NET member invocation (static and instance), pinned as an exact
# multiset of (receiver/type, method, every argument) — names case-folded,
# values exact. An allowlisted method reached with a different overload
# (another argument count, a writable flag, a different path) or an extra call
# is not in the multiset and fails, independent of GUARDED_OPS. HAND-MAINTAINED;
# tests/collector/print_pin_candidates.py prints candidates for review.
PINNED_MEMBER_CALLS: tuple[tuple[str, ...], ...] = (
    ("$_", "tostring", "'x2'"),
    ("$a.ActiveDirectoryRights", "tostring", ""),
    ("$a.IdentityReference", "translate", "[Security.Principal.NTAccount]"),
    ("$a.ObjectType", "tostring", ""),
    ("$apppath", "trimstart", "'/'"),
    ("$attr", "getvalues", "[byte[]]"),
    ("$attr", "getvalues", "[string]"),
    ("$conn", "bind", ""),
    ("$conn", "sendrequest", "$req"),
    ("$dcdns", "tolower", ""),
    ("$dcdns", "tolower", ""),
    ("$dcdns.ToLower()", "startswith", "$localhost + '.'"),
    ("$dns", "tolower", ""),
    ("$entries", "add", "$e"),
    ("$full", "equals", "$root", "[StringComparison]::OrdinalIgnoreCase"),
    (
        "$full",
        "startswith",
        "$root + [IO.Path]::AltDirectorySeparatorChar",
        "[StringComparison]::OrdinalIgnoreCase",
    ),
    (
        "$full",
        "startswith",
        "$root + [IO.Path]::DirectorySeparatorChar",
        "[StringComparison]::OrdinalIgnoreCase",
    ),
    ("$key", "getvalue", "'Security'"),
    ("$line", "trim", ""),
    ("$map", "getenumerator", ""),
    ("$matches[1]", "trim", ""),
    ("$ot", "tolower", ""),
    ("$p", "containskey", "$name"),
    ("$p", "tolower", ""),
    (
        "$reg",
        "getdwordvalue",
        "$hklm",
        "'SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL'",
        "'CertificateMappingMethods'",
    ),
    (
        "$reg",
        "getdwordvalue",
        "$hklm",
        "'SYSTEM\\CurrentControlSet\\Services\\Kdc'",
        "'StrongCertificateBindingEnforcement'",
    ),
    ("$req.Controls", "add", "$page"),
    (
        "$req.Controls",
        "add",
        "[System.DirectoryServices.Protocols.SecurityDescriptorFlagControl]::new( [System.DirectoryServices.Protocols.SecurityMasks]'Dacl,Owner')",
    ),
    ("$script:js", "serialize", "$obj"),
    ("$script:localsecurity", "containskey", "$ca.name"),
    ("$sd", "getaccessrules", "$true", "$true", "[Security.Principal.SecurityIdentifier]"),
    ("$sd", "getowner", "[Security.Principal.SecurityIdentifier]"),
    ("$sd", "setsecuritydescriptorbinaryform", "$sdbytes"),
    ("$sd", "setsecuritydescriptorbinaryform", "$sdbytes"),
    ("$v", "trim", ""),
    ("$values[0]", "trim", ""),
    ("($csps -join ', ')", "tolower", ""),
    ("(Get-Date)", "touniversaltime", ""),
    ("(Get-Date).ToUniversalTime()", "tostring", "'o'"),
    ("([System.Net.Dns]::GetHostEntry($localhost).HostName)", "tolower", ""),
    ("([string]$dns -split '\\.')[0]", "tolower", ""),
    ("([string]$n)", "tolower", ""),
    ("([string]$p.value)", "tolower", ""),
    ("([string](hostname))", "tolower", ""),
    ("[Convert]", "frombase64string", "$s"),
    ("[Convert]", "toint64", "$matches[1]", "16"),
    ("[IO.Directory]", "exists", "$cur"),
    ("[IO.File]", "exists", "$cur"),
    ("[IO.File]", "getattributes", "$cur"),
    ("[IO.File]", "writeallbytes", "(Join-Path $certdir $certfile)", "$der"),
    ("[IO.File]", "writeallbytes", "(Join-Path $certdir $crlfile)", "$der"),
    (
        "[IO.File]",
        "writealltext",
        "$outpath",
        "$script:js.Serialize($obj)",
        "(New-Object Text.UTF8Encoding($false))",
    ),
    ("[IO.Path]", "getdirectoryname", "$cur"),
    ("[IO.Path]", "getfullpath", "$outdir"),
    ("[IO.Path]", "getfullpath", "$path"),
    ("[IO.Path]::GetFullPath($outdir)", "trimend", "[char]'\\'", "[char]'/'"),
    ("[IO.Path]::GetFullPath($path)", "trimend", "[char]'\\'", "[char]'/'"),
    (
        "[Microsoft.Win32.Registry]::LocalMachine",
        "opensubkey",
        '"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\$caName"',
    ),
    ("[System.DirectoryServices.Protocols.LdapConnection]", "new", "$id"),
    ("[System.DirectoryServices.Protocols.LdapConnection]", "new", "$id", "$cred"),
    ("[System.DirectoryServices.Protocols.LdapDirectoryIdentifier]", "new", "$null"),
    ("[System.DirectoryServices.Protocols.PageResultRequestControl]", "new", "500"),
    (
        "[System.DirectoryServices.Protocols.SearchRequest]",
        "new",
        "$basedn",
        "$filter",
        "[System.DirectoryServices.Protocols.SearchScope]$scope",
        "$attrs",
    ),
    (
        "[System.DirectoryServices.Protocols.SecurityDescriptorFlagControl]",
        "new",
        "[System.DirectoryServices.Protocols.SecurityMasks]'Dacl,Owner'",
    ),
    ("[System.Net.Dns]", "gethostentry", "$localhost"),
    ("[Text.Encoding]::UTF8", "getstring", "[Convert]::FromBase64String($s)"),
    ("[int]", "tryparse", "$values[0]", "[ref]$n"),
    (
        "{ param([byte[]]$cookie) $req = [System.DirectoryServices.Protocols.SearchRequest]::new( $basedn, $filter, [System.DirectoryServices.Protocols.SearchScope]$scope, $attrs) if ($scope -ne 'Base') { $page = [System.DirectoryServices.Protocols.PageResultRequestControl]::new(500) if ($cookie -and $cookie.Length) { $page.Cookie = $cookie } [void]$req.Controls.Add($page) } if ($sd) { [void]$req.Controls.Add([System.DirectoryServices.Protocols.SecurityDescriptorFlagControl]::new( [System.DirectoryServices.Protocols.SecurityMasks]'Dacl,Owner')) } $conn.SendRequest($req) }",
        "getnewclosure",
        "",
    ),
)

# Every variable whose binding matters, pinned to the EXACT multiset of its
# bindings (kind, scope, value) — see _bindings_by_var for the kinds. Required:
# write roots, variables in write/exec inputs, receivers of every instance call
# and property/index write, and transitively every variable their bindings
# read (_required_vars). An empty list means "must stay unbound". Both
# directions are strict: an extra binding (a rebind) and a stale entry fail.
# Keyed "<scope>::<name>" so the same name in two scopes is two pins (e.g.
# _b64's parameter $s is separate from the searcher $s). Each comment is the
# first reason the key is required. Edit by hand, with a reason.
PINNED_BINDINGS: dict[str, list[tuple[str, str]]] = {
    # condition $a
    "<script>::a": [
        ("assign Equals", "_objAcl $pair[0] $pair[1]"),
    ],
    # condition $null -ne $aces
    "<script>::aces": [
        ("assign Equals", "$null"),
        ("assign Equals", "$script:localSecurity[$ca.name]"),
    ],
    # input of _markSearch: _markSearch 'certs' $aia @($aia.entries).Count $aiaObjects $aiaFailures $certIndex.Count
    "<script>::aia": [
        (
            "assign Equals",
            "_search \"CN=AIA,$pksDn\" '(objectClass=certificationAuthority)' @('cn', 'cacertificate')",
        ),
    ],
    # input of _markSearch: _markSearch 'certs' $aia @($aia.entries).Count $aiaObjects $aiaFailures $certIndex.Count
    "<script>::aiafailures": [
        ("assign Equals", "@()"),
        ("assign PlusEquals", '"AIA object: $($_.Exception.Message)"'),
    ],
    # input of _markSearch: _markSearch 'certs' $aia @($aia.entries).Count $aiaObjects $aiaFailures $certIndex.Count
    "<script>::aiaobjects": [
        ("assign Equals", "0"),
        ("incdec PostfixPlusPlus", ""),
    ],
    # condition -not $anyCaSecurity
    "<script>::anycasecurity": [
        ("assign Equals", "$false"),
        ("assign Equals", "$true"),
    ],
    # read by a binding of $<script>::apppath
    "<script>::app": [
        ("foreach", "(Get-WebApplication -Site $site.Name -ErrorAction Stop)"),
    ],
    # input of _classifyApp: _classifyApp $appPath
    "<script>::apppath": [
        ("assign Equals", "[string]$app.path"),
    ],
    # input of _tryRead: _tryRead { Get-WebConfigurationProperty -PSPath $ps -Filter $auth -Name enabled -ErrorAction Stop }
    "<script>::auth": [
        ("assign Equals", "'system.webServer/security/authentication/windowsAuthentication'"),
    ],
    # condition $ot -eq $AUTOENROLL_GUID
    "<script>::autoenroll_guid": [
        ("assign Equals", "'a05b8cc2-17b1-4cc8-8b00-94f99c9c2cca'"),
    ],
    # condition $protos -notcontains [string]$b.protocol
    "<script>::b": [
        ("foreach", "$site.bindings.Collection"),
    ],
    # condition $BINARY_ATTRS -contains $key
    "<script>::binary_attrs": [
        (
            "assign Equals",
            "@('objectguid', 'ntsecuritydescriptor', 'cacertificate', 'certificaterevocationlist')",
        ),
    ],
    # read by a binding of $<script>::dcconfigs
    "<script>::binding": [
        ("assign Equals", "$null"),
        ("assign Equals", "'unknown'"),
        ("assign Equals", "_decodeBinding ([int]$kdc.uValue)"),
    ],
    # read by a binding of $<script>::der
    "<script>::blob": [
        ("foreach", "@(_v $p 'cacertificate')"),
    ],
    # argument of .ContainsKey(): $script:localSecurity.ContainsKey($ca.name)
    "<script>::ca": [
        ("foreach", "$caConfig"),
    ],
    # input of Where-Object: Where-Object { $_.name -ceq $caCommonName }
    "<script>::cacommonname": [
        ("assign Equals", "$cnResult.value"),
    ],
    # input of _markSearch: _markSearch 'ca-config' $caSearch (@($es.entries).Count + $standalone) $caConfig.Count $esFailures
    "<script>::caconfig": [
        ("assign Equals", "@()"),
        ("assign PlusEquals", "$row"),
        ("assign PlusEquals", "(_localCaRow $caCommonName $localFqdn '' $false)"),
    ],
    # read by a binding of $<script>::islocal
    "<script>::cahost": [
        ("assign Equals", "([string]$dns -split '\\.')[0].ToLower()"),
    ],
    # input of _markSearch: _markSearch 'pki-acls' $pkiSearch (6 + $caObjects.returned + $esObjects.returned) $pkiAcls.Count (@($caObjects.failures) + @($esObjects.failures))
    "<script>::caobjects": [
        (
            "assign Equals",
            "_childAcls \"CN=Certification Authorities,$pksDn\" '(objectClass=certificationAuthority)' 'ca_object'",
        ),
    ],
    # input of _markSearch: _markSearch 'ca-config' $caSearch (@($es.entries).Count + $standalone) $caConfig.Count $esFailures
    "<script>::casearch": [
        (
            "assign Equals",
            "@{ complete = ($es.complete -and $cnResult.status -ne 'failed') reason = $(if (-not $es.complete) { $es.reason } else { 'CA\\CommonName could not be read' }) }",
        ),
    ],
    # input of _writeJson: _writeJson $caSecurity 'ca-security.json'
    "<script>::casecurity": [
        ("assign Equals", "[ordered]@{}"),
        ("index Equals", "$caSecurity[$ca.name] = $aces"),
    ],
    # input of _caKindFromType: _caKindFromType $caType
    "<script>::catype": [
        ("assign Equals", "_certutilDword 'CA\\CAType'"),
    ],
    # input of _markSearch: _markSearch 'crls' $cdp @($cdp.entries).Count $cdpObjects $cdpFailures $crlIndex.Count
    "<script>::cdp": [
        (
            "assign Equals",
            "_search \"CN=CDP,$pksDn\" '(objectClass=cRLDistributionPoint)' @('cn', 'certificaterevocationlist', 'objectguid')",
        ),
    ],
    # input of _markSearch: _markSearch 'crls' $cdp @($cdp.entries).Count $cdpObjects $cdpFailures $crlIndex.Count
    "<script>::cdpfailures": [
        ("assign Equals", "@()"),
        ("assign PlusEquals", '"CDP object: $($_.Exception.Message)"'),
    ],
    # input of _markSearch: _markSearch 'crls' $cdp @($cdp.entries).Count $cdpObjects $cdpFailures $crlIndex.Count
    "<script>::cdpobjects": [
        ("assign Equals", "0"),
        ("incdec PostfixPlusPlus", ""),
        ("incdec PostfixPlusPlus", ""),
    ],
    # input of Assert-AdcsOutputPath: Assert-AdcsOutputPath $certDir
    "<script>::certdir": [
        ("assign Equals", "Join-Path $OutDir 'certs'"),
    ],
    # input of Assert-AdcsOutputPath: Assert-AdcsOutputPath (Join-Path $certDir $certFile)
    "<script>::certfile": [
        ("assign Equals", "'{0:d2}-{1}.cer' -f $i, (_safeFileName $cn)"),
    ],
    # input of _markSearch: _markSearch 'certs' $aia @($aia.entries).Count $aiaObjects $aiaFailures $certIndex.Count
    "<script>::certindex": [
        ("assign Equals", "@()"),
        ("assign PlusEquals", "[ordered]@{ file = $certFile; ca_name = $cn; kind = $kind }"),
    ],
    # condition $certsSkipped
    "<script>::certsskipped": [
        ("assign Equals", "$false"),
        ("assign Equals", "$true"),
    ],
    # condition $check.soft -contains 'dnshostname'
    "<script>::check": [
        ("assign Equals", "_requireSchema $p 'dc-config'"),
    ],
    # input of _localCaRow: _localCaRow $cn $dns (_guidHex @(_v $p 'objectguid')) $true
    "<script>::cn": [
        ("assign Equals", "[string]@(_v $p 'cn')[0]"),
        ("assign Equals", "[string]@(_v $p 'cn')[0]"),
        ("assign Equals", "[string]@(_v $p 'cn')[0]"),
    ],
    # input of _certutilStringFrom: _certutilStringFrom $cnRead.lines $cnRead.code 'CommonName'
    "<script>::cnread": [
        ("assign Equals", "_certutilRead 'CA\\CommonName'"),
    ],
    # read by a binding of $<script>::casearch
    "<script>::cnresult": [
        ("assign Equals", "_certutilStringFrom $cnRead.lines $cnRead.code 'CommonName'"),
    ],
    # condition $CollectDcMapping -and ($DcRegistryUserB64 -or $DcRegistryPassB64)
    "<script>::collectdcmapping": [
        ("parameter", "[Parameter(ParameterSetName = 'Collect')] [switch] $CollectDcMapping"),
    ],
    # read by a binding of $<script>::manifest
    "<script>::collector_version": [
        ("assign Equals", "'0.10.0'"),
    ],
    # input of Assert-AdcsOutputPath: Assert-AdcsOutputPath (Join-Path $certDir $crlFile)
    "<script>::crlfile": [
        ("assign Equals", "'{0:d2}-{1}.crl' -f $j, (_safeFileName $cn)"),
    ],
    # input of _markSearch: _markSearch 'crls' $cdp @($cdp.entries).Count $cdpObjects $cdpFailures $crlIndex.Count
    "<script>::crlindex": [
        ("assign Equals", "@()"),
        (
            "assign PlusEquals",
            "[ordered]@{ object_guid = (_guidHex @(_v $p 'objectguid')) # the CDP object file = $crlFile ca_name = $cn # the CDP object's cn, verbatim: ingest derives the tier source = \"AD CDP container: $([string]@(_v $p 'distinguishedname')[0])\" }",
        ),
    ],
    # read by a binding of $<script>::templates
    "<script>::csps": [
        ("assign Equals", "@(_v $p 'pkicsp' | ForEach-Object { [string]$_ })"),
    ],
    # input of Write-Warning: Write-Warning "esc10-dc-registry: all $($dcConfigs.Count) DC(s) failed the registry read -- pass effectively skipped (WMI access denied? provide -DcRegistryUserB64/-DcRegistryPassB64 for SSH/double-hop)."
    "<script>::dcconfigs": [
        ("assign Equals", "@()"),
        (
            "assign PlusEquals",
            "[ordered]@{ name = $dcDns object_guid = $dcGuid strong_certificate_binding_enforcement = $binding schannel_mapping_methods = (_list $schannelMethods) }",
        ),
    ],
    # input of Get-WmiObject: Get-WmiObject -ComputerName $dcDns -Credential $dcCred -Namespace 'root\default' -Class StdRegProv -List
    "<script>::dccred": [
        ("assign Equals", "$null"),
        (
            "assign Equals",
            "New-Object Management.Automation.PSCredential( $DcRegistryUser, (ConvertTo-SecureString $DcRegistryPass -AsPlainText -Force))",
        ),
    ],
    # input of Write-Warning: Write-Warning "esc10-dc-registry: $dcDns has no dNSHostName; its registry was not read"
    "<script>::dcdns": [
        ("assign Equals", "[string]@(_v $p 'distinguishedname')[0]"),
        ("assign Equals", "[string]@(_v $p 'dnshostname')[0]"),
    ],
    # input of _markSearch: _markSearch 'dc-config' $dcs @($dcs.entries).Count $dcConfigs.Count $dcFailures
    "<script>::dcfailures": [
        ("assign Equals", "@()"),
        ("assign PlusEquals", '"DC: $($_.Exception.Message)"'),
    ],
    # read by a binding of $<script>::dcconfigs
    "<script>::dcguid": [
        ("assign Equals", "_guidHex @(_v $p 'objectguid')"),
    ],
    # input of New-Object: New-Object Management.Automation.PSCredential( $DcRegistryUser, (ConvertTo-SecureString $DcRegistryPass -AsPlainText -Force))
    "<script>::dcregistrypass": [
        ("assign Equals", "''"),
        ("assign Equals", "_b64 $DcRegistryPassB64"),
    ],
    # input of _b64: _b64 $DcRegistryPassB64
    "<script>::dcregistrypassb64": [
        ("parameter", "[Parameter(ParameterSetName = 'Collect')] [string] $DcRegistryPassB64"),
    ],
    # input of New-Object: New-Object Management.Automation.PSCredential( $DcRegistryUser, (ConvertTo-SecureString $DcRegistryPass -AsPlainText -Force))
    "<script>::dcregistryuser": [
        ("assign Equals", "''"),
        ("assign Equals", "_b64 $DcRegistryUserB64"),
    ],
    # input of _b64: _b64 $DcRegistryUserB64
    "<script>::dcregistryuserb64": [
        ("parameter", "[Parameter(ParameterSetName = 'Collect')] [string] $DcRegistryUserB64"),
    ],
    # input of _markSearch: _markSearch 'dc-config' $dcs @($dcs.entries).Count $dcConfigs.Count $dcFailures
    "<script>::dcs": [
        (
            "assign Equals",
            "_search $domNc '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))' @('dnshostname', 'objectguid')",
        ),
    ],
    # input of _certKindFromDer: _certKindFromDer $der
    "<script>::der": [
        ("assign Equals", "$r[0]"),
        ("assign Equals", "[byte[]]$blob"),
        ("assign Equals", "[byte[]]@(_v $p 'certificaterevocationlist')[0]"),
    ],
    # input of _list: _list $disabledExt
    "<script>::disabledext": [
        ("assign Equals", "_certutilMultiSz 'policy\\DisableExtensionList'"),
    ],
    # input of _localCaRow: _localCaRow $cn $dns (_guidHex @(_v $p 'objectguid')) $true
    "<script>::dns": [
        ("assign Equals", "[string]@(_v $p 'dnshostname')[0]"),
    ],
    # input of _search: _search $domNc '(altSecurityIdentities=*)' @('altsecurityidentities', 'objectguid')
    "<script>::domnc": [
        ("assign Equals", "$rootDse.domain"),
    ],
    # input of _entryProps: _entryProps $e
    "<script>::e": [
        ("foreach", "$aia.entries"),
        ("foreach", "$cdp.entries"),
        ("foreach", "$dcs.entries"),
        ("foreach", "$es.entries"),
        ("foreach", "$os.entries"),
        ("foreach", "$ps14.entries"),
        ("foreach", "$ts.entries"),
    ],
    # input of _list: _list $editFlags
    "<script>::editflags": [
        ("assign Equals", "_certutilFlags 'policy\\EditFlags'"),
    ],
    # input of _decode: _decode $ef $ENROLL_FLAGS
    "<script>::ef": [
        (
            "assign Equals",
            "if (@(_v $p 'mspki-enrollment-flag').Count) { [int]@(_v $p 'mspki-enrollment-flag')[0] } else { 0 }",
        ),
    ],
    # input of _searchMarker: _searchMarker $endpointsComplete $endpointsReason $webEndpoints.Count $webEndpoints.Count $iisFailures
    "<script>::endpointscomplete": [
        ("assign Equals", "$false"),
        ("assign Equals", "$true"),
    ],
    # input of Write-Warning: Write-Warning $endpointsReason
    "<script>::endpointsreason": [
        ("assign Equals", '"IIS enumeration failed: $($_.Exception.Message)"'),
        ("assign Equals", "''"),
    ],
    # condition -not $endpointsSkipped
    "<script>::endpointsskipped": [
        ("assign Equals", "$false"),
        ("assign Equals", "$true"),
    ],
    # input of _decode: _decode $ef $ENROLL_FLAGS
    "<script>::enroll_flags": [
        (
            "assign Equals",
            "[ordered]@{ 0x00000002 = 'PEND_ALL_REQUESTS' # manager approval 0x00000008 = 'PUBLISH_TO_DS' 0x00000020 = 'AUTO_ENROLLMENT' 0x00000100 = 'USER_INTERACTION_REQUIRED' 0x00080000 = 'NO_SECURITY_EXTENSION' # ESC9 (CT_FLAG_NO_SECURITY_EXTENSION) }",
        ),
    ],
    # condition $ot -eq $ENROLL_GUID
    "<script>::enroll_guid": [
        ("assign Equals", "'0e10c968-78fb-11d2-90d4-00c04f79dc55'"),
    ],
    # input of _markSearch: _markSearch 'enrollment-services' $es @($es.entries).Count $enrollmentServices.Count $esFailures
    "<script>::enrollmentservices": [
        ("assign Equals", "[ordered]@{}"),
        ("index Equals", "$enrollmentServices[$cn] = $published"),
    ],
    # index write $enumeration['web-endpoints']
    "<script>::enumeration": [
        ("assign Equals", "[ordered]@{}"),
        (
            "index Equals",
            "$enumeration['web-endpoints'] = _searchMarker $endpointsComplete $endpointsReason $webEndpoints.Count $webEndpoints.Count $iisFailures",
        ),
    ],
    # input of _markSearch: _markSearch 'ca-config' $caSearch (@($es.entries).Count + $standalone) $caConfig.Count $esFailures
    "<script>::es": [
        (
            "assign Equals",
            "_search \"CN=Enrollment Services,$pksDn\" '(objectClass=pKIEnrollmentService)' @('cn', 'dnshostname', 'certificatetemplates', 'objectguid')",
        ),
    ],
    # condition $esc10Skipped
    "<script>::esc10skipped": [
        ("assign Equals", "$false"),
        ("assign Equals", "$true"),
        ("assign Equals", "$true"),
    ],
    # condition $esc14Skipped
    "<script>::esc14skipped": [
        ("assign Equals", "$false"),
        ("assign Equals", "$true"),
    ],
    # input of _markSearch: _markSearch 'ca-config' $caSearch (@($es.entries).Count + $standalone) $caConfig.Count $esFailures
    "<script>::esfailures": [
        ("assign Equals", "@()"),
        ("assign PlusEquals", '"enrollment service: $($_.Exception.Message)"'),
    ],
    # input of _markSearch: _markSearch 'pki-acls' $pkiSearch (6 + $caObjects.returned + $esObjects.returned) $pkiAcls.Count (@($caObjects.failures) + @($esObjects.failures))
    "<script>::esobjects": [
        (
            "assign Equals",
            "_childAcls \"CN=Enrollment Services,$pksDn\" '(objectClass=pKIEnrollmentService)' 'ca_object'",
        ),
    ],
    # read by a binding of $<script>::oids
    "<script>::gl": [
        (
            "assign Equals",
            "if (@(_v $p 'msds-oidtogrouplink').Count) { [string]@(_v $p 'msds-oidtogrouplink')[0] } else { $null }",
        ),
    ],
    # input of GetDWORDValue: $reg.GetDWORDValue($HKLM, 'SYSTEM\CurrentControlSet\Services\Kdc', 'StrongCertificateBindingEnforcement')
    "<script>::hklm": [
        ("assign Equals", "[uint32]2147483650"),
    ],
    # read by a binding of $<script>::certfile
    "<script>::i": [
        ("assign Equals", "0"),
        ("incdec PostfixPlusPlus", ""),
    ],
    # input of _searchMarker: _searchMarker $endpointsComplete $endpointsReason $webEndpoints.Count $webEndpoints.Count $iisFailures
    "<script>::iisfailures": [
        ("assign Equals", "@()"),
        ("assign PlusEquals", "\"IIS application under '$($site.Name)' has no readable path\""),
    ],
    # input of _list: _list $interfaceFlags
    "<script>::interfaceflags": [
        ("assign Equals", "_certutilFlags 'CA\\InterfaceFlags'"),
    ],
    # condition $isLocal
    "<script>::islocal": [
        (
            "assign Equals",
            "($caCommonName -and $cn -ceq $caCommonName -and $caHost -and ($caHost -eq $localHost -or $dns.ToLower() -eq $localFqdn))",
        ),
    ],
    # read by a binding of $<script>::crlfile
    "<script>::j": [
        ("assign Equals", "0"),
        ("incdec PostfixPlusPlus", ""),
    ],
    # input of ConvertFrom-Json: ConvertFrom-Json @' { "crl.tier": { "by": "ingest", "from": ["certs.kind"], "containers": ["certs"], "join": "the CRL's CDP cn = the AIA object's cn", "miss": "null" }, "endpoint.transports": { "by": "collector", "from": ["IIS site bindings"], "containers": ["web-endpoints"], "join": "the application's site", "miss": "null" }, "template.published_by": { "by": "ingest", "from": ["enrollment-services.certificatetemplates"], "containers": ["enrollment-services"], "join": "template cn, exactly ($JOINS publication)", "miss": "unpublished only when enrollment-services is complete", "text": "ESC1-3 publication detail says the list is incomplete when it is" }, "cert.ca_kind": { "by": "ingest", "from": ["ca.kind"], "containers": ["ca-config"], "join": "certs/index.json ca_name = CA name", "miss": "null (unattached certificate)" } } '@
    "<script>::joins": [
        (
            "assign Equals",
            'ConvertFrom-Json @\' { "publication": { "field": "template.published_by", "by": "ingest", "impl": "resolve_join", "from": "enrollment-services.certificatetemplates", "to": "templates", "keys": ["cn"], "legacy_keys": ["cn", "oid"], "compare": "identical (MS-WCCE)", "none": "attaches nowhere (a published template that is not in AD)", "ambiguous": "published_by not obtained for every template it is identical or folds to" }, "cert-ca": { "field": "cert.ca_kind", "by": "ingest", "impl": "resolve_join", "from": "certs.ca_name", "to": "ca-config", "keys": ["cn"], "compare": "identical (both are cn values the collector copied)", "none": "unattached: ca_kind not obtained", "ambiguous": "unattached: ca_kind not obtained (two CA rows folding together is an ingest error)" }, "crl-tier": { "field": "crl.tier", "by": "ingest", "impl": "resolve_join", "from": "crls.ca_name (the CDP object\'s cn)", "to": "certs (certs/index.json ca_name)", "keys": ["ca_name"], "compare": "identical", "none": "tier null", "ambiguous": "tier null (also when one cn\'s certificates disagree on kind)" }, "ca-security": { "field": "ca.security", "by": "ingest", "impl": "exact set", "from": "ca-security.json keys", "to": "ca-config", "keys": ["cn"], "compare": "identical (the collector writes the row\'s name)", "none": "ingest error: an entry naming no CA, or a CA without an entry", "ambiguous": "ingest error: two CA rows whose names fold together" }, "publisher-ca": { "field": "ca.enrollment_service", "by": "ingest", "impl": "exact set", "from": "enrollment-services.json keys", "to": "ca-config", "keys": ["cn"], "compare": "identical (the collector writes the row\'s name)", "none": "ingest error: a publisher without a CA row, or the reverse", "ambiguous": "ingest error: two CA rows whose names fold together" }, "oid-link": { "field": "oid.group_link", "by": "detection (ESC13)", "impl": "resolve_join", "from": "templates.issuance_policy_oids", "to": "oid-objects", "keys": ["oid"], "compare": "identical", "none": "no link: decided only when oid-objects is complete", "ambiguous": "ESC13 undecided (duplicate OIDs also mark oid-objects incomplete)" }, "local-ca": { "field": "ca.edit_flags", "by": "collector", "impl": "-ceq", "from": "enrollment-services.cn", "to": "certutil CA\\\\CommonName", "keys": ["cn"], "compare": "identical (-ceq)", "none": "a remote CA: every registry field null (also for a CA whose AD name is sanitized)", "ambiguous": "ingest error: the local CA\'s standalone row and the enrollment service fold together" }, "app-site": { "field": "endpoint.transports", "by": "collector", "impl": "parent object", "from": "IIS application", "to": "its IIS site", "keys": ["(parent object)"], "compare": "enumerated under the site", "none": "transports null when the site\'s bindings read nothing", "ambiguous": "impossible: each application is enumerated under one site" } } \'@',
        ),
    ],
    # input of WriteAllText: [IO.File]::WriteAllText($outPath, $script:JS.Serialize($obj), (New-Object Text.UTF8Encoding($false)))
    "<script>::js": [
        ("assign Equals", "New-Object System.Web.Script.Serialization.JavaScriptSerializer"),
        ("member Equals", "$script:JS.MaxJsonLength = [int]::MaxValue"),
    ],
    # input of _wmiDwordStatus: _wmiDwordStatus $kdc
    "<script>::kdc": [
        (
            "assign Equals",
            "$reg.GetDWORDValue($HKLM, 'SYSTEM\\CurrentControlSet\\Services\\Kdc', 'StrongCertificateBindingEnforcement')",
        ),
    ],
    # condition $kind -eq 'other'
    "<script>::kind": [
        ("assign Equals", "$r[1]"),
        ("assign Equals", "_certKindFromDer $der"),
        ("assign Equals", "_classifyApp $appPath"),
    ],
    # input of New-Object: New-Object System.Net.NetworkCredential($LdapUser, $LdapPass)
    "<script>::ldappass": [
        ("assign Equals", "''"),
        ("assign Equals", "_b64 $LdapPassB64"),
    ],
    # input of _b64: _b64 $LdapPassB64
    "<script>::ldappassb64": [
        ("parameter", "[Parameter(ParameterSetName = 'Collect')] [string] $LdapPassB64"),
    ],
    # input of New-Object: New-Object System.Net.NetworkCredential($LdapUser, $LdapPass)
    "<script>::ldapuser": [
        ("assign Equals", "''"),
        ("assign Equals", "_b64 $LdapUserB64"),
    ],
    # input of _b64: _b64 $LdapUserB64
    "<script>::ldapuserb64": [
        ("parameter", "[Parameter(ParameterSetName = 'Collect')] [string] $LdapUserB64"),
    ],
    # input of _localCaRow: _localCaRow $caCommonName $localFqdn '' $false
    "<script>::localfqdn": [
        ("assign Equals", "$localHost"),
        ("assign Equals", "([System.Net.Dns]::GetHostEntry($localHost).HostName).ToLower()"),
    ],
    # argument of .GetHostEntry(): [System.Net.Dns]::GetHostEntry($localHost)
    "<script>::localhost": [
        ("assign Equals", "([string](hostname)).ToLower()"),
    ],
    # receiver of .ContainsKey()
    "<script>::localsecurity": [
        ("assign Equals", "@{}"),
    ],
    # input of _writeJson: _writeJson $manifest 'collector-manifest.json'
    "<script>::manifest": [
        (
            "assign Equals",
            "[ordered]@{ collector_version = $COLLECTOR_VERSION collected_at = (Get-Date).ToUniversalTime().ToString('o') host = [string](hostname) domain = $rootDse.domain skipped_passes = (@($skippedPasses)) enumeration = $enumeration }",
        ),
    ],
    # input of _decode: _decode $nf $NAME_FLAGS
    "<script>::name_flags": [
        (
            "assign Equals",
            "[ordered]@{ 0x00000001 = 'ENROLLEE_SUPPLIES_SUBJECT' 0x00010000 = 'SUBJECT_ALT_REQUIRE_DOMAIN_DNS' 0x00400000 = 'SUBJECT_ALT_REQUIRE_UPN' 0x00800000 = 'SUBJECT_ALT_REQUIRE_EMAIL' 0x04000000 = 'SUBJECT_ALT_REQUIRE_DNS' 0x08000000 = 'SUBJECT_REQUIRE_DNS_AS_CN' 0x10000000 = 'SUBJECT_REQUIRE_DIRECTORY_PATH' 0x20000000 = 'SUBJECT_REQUIRE_EMAIL' 0x40000000 = 'SUBJECT_REQUIRE_COMMON_NAME' 0x00000008 = 'ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME' }",
        ),
    ],
    # input of _decode: _decode $nf $NAME_FLAGS
    "<script>::nf": [
        (
            "assign Equals",
            "if (@(_v $p 'mspki-certificate-name-flag').Count) { [int]@(_v $p 'mspki-certificate-name-flag')[0] } else { 0 }",
        ),
    ],
    # input of _schemaCheck: _schemaCheck $p $OBJECT_SCHEMA.$container
    "<script>::object_schema": [
        (
            "assign Equals",
            'ConvertFrom-Json @\' { "enrollment-services": { "distinguishedname": {"type": "string", "need": "required", "field": "(identity)"}, "cn": {"type": "string", "need": "required", "field": "name"}, "objectguid": {"type": "guid", "need": "required", "field": "object_guid"}, "dnshostname": {"type": "string", "need": "optional", "field": "dns"}, "certificatetemplates": {"type": "strings", "need": "optional", "field": "(source of template.published_by)"} }, "templates": { "distinguishedname": {"type": "string", "need": "required", "field": "(identity)"}, "cn": {"type": "string", "need": "required", "field": "name"}, "objectguid": {"type": "guid", "need": "required", "field": "object_guid"}, "mspki-cert-template-oid": {"type": "string", "need": "required", "field": "oid"}, "displayname": {"type": "string", "need": "optional", "field": "display_name"}, "mspki-certificate-name-flag": {"type": "int", "need": "optional", "field": "name_flags"}, "mspki-enrollment-flag": {"type": "int", "need": "optional", "field": "enrollment_flags"}, "pkiextendedkeyusage": {"type": "strings", "need": "optional", "field": "ekus"}, "mspki-certificate-policy": {"type": "strings", "need": "optional", "field": "issuance_policy_oids"}, "pkicsp": {"type": "strings", "need": "optional", "field": "csp"}, "mspki-template-schema-version": {"type": "int", "need": "optional", "field": "schema_version"}, "mspki-minimal-key-size": {"type": "int", "need": "optional", "field": "min_key_size"}, "ntsecuritydescriptor": {"type": "bytes", "need": "sd", "field": "security"} }, "oid-objects": { "distinguishedname": {"type": "string", "need": "required", "field": "(identity)"}, "mspki-cert-template-oid": {"type": "string", "need": "required", "field": "oid"}, "objectguid": {"type": "guid", "need": "required", "field": "object_guid"}, "displayname": {"type": "string", "need": "optional", "field": "name"}, "msds-oidtogrouplink": {"type": "string", "need": "optional", "field": "group_link"} }, "pki-acls": { "distinguishedname": {"type": "string", "need": "required", "field": "object_dn"}, "objectguid": {"type": "guid", "need": "required", "field": "object_guid"}, "ntsecuritydescriptor": {"type": "bytes", "need": "sd", "field": "security"} }, "certs": { "distinguishedname": {"type": "string", "need": "required", "field": "(identity)"}, "cn": {"type": "string", "need": "required", "field": "ca_name"}, "cacertificate": {"type": "bytes", "need": "optional", "field": "(certificate)"} }, "crls": { "distinguishedname": {"type": "string", "need": "required", "field": "source"}, "cn": {"type": "string", "need": "required", "field": "ca_name"}, "objectguid": {"type": "guid", "need": "required", "field": "object_guid"}, "certificaterevocationlist": {"type": "bytes", "need": "optional", "field": "(crl)"} }, "principal-mappings": { "distinguishedname": {"type": "string", "need": "required", "field": "dn"}, "objectguid": {"type": "guid", "need": "required", "field": "object_guid"}, "altsecurityidentities": {"type": "strings", "need": "required", "field": "mappings"} }, "dc-config": { "distinguishedname": {"type": "string", "need": "required", "field": "(identity)"}, "objectguid": {"type": "guid", "need": "required", "field": "object_guid"}, "dnshostname": {"type": "string", "need": "placeholder", "field": "name"} } } \'@',
        ),
    ],
    # input of _markSearch: _markSearch 'oid-objects' $os @($os.entries).Count $oids.Count $osFailures
    "<script>::oids": [
        ("assign Equals", "@()"),
        (
            "assign PlusEquals",
            "[ordered]@{ oid = [string]@(_v $p 'mspki-cert-template-oid')[0] object_guid = (_guidHex @(_v $p 'objectguid')) name = [string]@(_v $p 'displayname')[0] group_link = $gl }",
        ),
    ],
    # input of _markSearch: _markSearch 'oid-objects' $os @($os.entries).Count $oids.Count $osFailures
    "<script>::os": [
        (
            "assign Equals",
            "_search \"CN=OID,$pksDn\" '(objectClass=msPKI-Enterprise-Oid)' @('mspki-cert-template-oid', 'objectguid', 'displayname', 'msds-oidtogrouplink')",
        ),
    ],
    # input of _markSearch: _markSearch 'oid-objects' $os @($os.entries).Count $oids.Count $osFailures
    "<script>::osfailures": [
        ("assign Equals", "@()"),
        ("assign PlusEquals", '"OID: $($_.Exception.Message)"'),
    ],
    # input of Join-Path: Join-Path $OutDir $outName
    "<script>::outdir": [
        ("parameter", "[Parameter(Mandatory, ParameterSetName = 'Collect')] [string] $OutDir"),
    ],
    # input of _requireSchema: _requireSchema $p 'enrollment-services'
    "<script>::p": [
        ("assign Equals", "_entryProps $e"),
        ("assign Equals", "_entryProps $e"),
        ("assign Equals", "_entryProps $e"),
        ("assign Equals", "_entryProps $e"),
        ("assign Equals", "_entryProps $e"),
        ("assign Equals", "_entryProps $e"),
        ("assign Equals", "_entryProps $e"),
        ("foreach", "@($pr.value)"),
    ],
    # input of _objAcl: _objAcl $pair[0] $pair[1]
    "<script>::pair": [
        (
            "foreach",
            "@( @($pksDn, 'pks_container'), @(\"CN=NTAuthCertificates,$pksDn\", 'ntauth'), @(\"CN=AIA,$pksDn\", 'aia'), @(\"CN=CDP,$pksDn\", 'cdp'), @(\"CN=Certification Authorities,$pksDn\", 'pks_container'), @(\"CN=Enrollment Services,$pksDn\", 'pks_container'))",
        ),
    ],
    # input of _markSearch: _markSearch 'pki-acls' $pkiSearch (6 + $caObjects.returned + $esObjects.returned) $pkiAcls.Count (@($caObjects.failures) + @($esObjects.failures))
    "<script>::pkiacls": [
        ("assign Equals", "@()"),
        ("assign PlusEquals", "$a"),
        ("assign PlusEquals", "$caObjects.rows"),
        ("assign PlusEquals", "$esObjects.rows"),
        (
            "assign PlusEquals",
            "[ordered]@{ object_dn = $pair[0]; kind = $pair[1]; owner_sid = $null object_guid = '' # the object could not be read at all security = $null; acl_obtained = $false }",
        ),
    ],
    # input of _markSearch: _markSearch 'pki-acls' $pkiSearch (6 + $caObjects.returned + $esObjects.returned) $pkiAcls.Count (@($caObjects.failures) + @($esObjects.failures))
    "<script>::pkisearch": [
        (
            "assign Equals",
            "@{ complete = ($caObjects.complete -and $esObjects.complete) reason = $(if (-not $caObjects.complete) { $caObjects.reason } else { $esObjects.reason }) }",
        ),
    ],
    # input of _search: _search "CN=Enrollment Services,$pksDn" '(objectClass=pKIEnrollmentService)' @('cn', 'dnshostname', 'certificatetemplates', 'objectguid')
    "<script>::pksdn": [
        ("assign Equals", '"CN=Public Key Services,CN=Services,$($rootDse.config)"'),
    ],
    # condition $pr.ok
    "<script>::pr": [
        (
            "assign Equals",
            '_tryRead { Get-WebConfigurationProperty -PSPath $ps -Filter "$auth/providers" -Name Collection -ErrorAction Stop }',
        ),
    ],
    # input of _markSearch: _markSearch 'principal-mappings' $ps14 @($ps14.entries).Count $principalMappings.Count $psFailures
    "<script>::principalmappings": [
        ("assign Equals", "@()"),
        (
            "assign PlusEquals",
            "[ordered]@{ dn = [string]@(_v $p 'distinguishedname')[0] object_guid = (_guidHex @(_v $p 'objectguid')) mappings = (@(_v $p 'altsecurityidentities' | ForEach-Object { [string]$_ })) }",
        ),
    ],
    # condition $protos -notcontains [string]$b.protocol
    "<script>::protos": [
        ("assign Equals", "@()"),
        ("assign PlusEquals", "[string]$b.protocol"),
    ],
    # input of _list: _list $provs
    "<script>::provs": [
        ("assign Equals", "$null"),
        ("assign Equals", "@()"),
        ("assign PlusEquals", "([string]$p.value).ToLower()"),
    ],
    # input of _tryRead: _tryRead { Get-WebConfigurationProperty -PSPath $ps -Filter $auth -Name enabled -ErrorAction Stop }
    "<script>::ps": [
        ("assign Equals", "\"IIS:\\Sites\\$($site.Name)\\\" + $appPath.TrimStart('/')"),
    ],
    # input of _markSearch: _markSearch 'principal-mappings' $ps14 @($ps14.entries).Count $principalMappings.Count $psFailures
    "<script>::ps14": [
        (
            "assign Equals",
            "_search $domNc '(altSecurityIdentities=*)' @('altsecurityidentities', 'objectguid')",
        ),
    ],
    # input of _markSearch: _markSearch 'principal-mappings' $ps14 @($ps14.entries).Count $principalMappings.Count $psFailures
    "<script>::psfailures": [
        ("assign Equals", "@()"),
        ("assign PlusEquals", '"principal: $($_.Exception.Message)"'),
    ],
    # read by a binding of $<script>::enrollmentservices
    "<script>::published": [
        ("assign Equals", "@(_v $p 'certificatetemplates' | ForEach-Object { [string]$_ })"),
    ],
    # read by a binding of $_entryprops::entry
    "<script>::r": [
        ("foreach", "$rows"),
    ],
    # receiver of .GetDWORDValue()
    "<script>::reg": [
        (
            "assign Equals",
            "Get-WmiObject -ComputerName $dcDns -Credential $dcCred -Namespace 'root\\default' -Class StdRegProv -List",
        ),
        (
            "assign Equals",
            "Get-WmiObject -ComputerName $dcDns -Namespace 'root\\default' -Class StdRegProv -List",
        ),
        ("assign Equals", "Get-WmiObject -Namespace 'root\\default' -Class StdRegProv -List"),
    ],
    # read by a binding of $<script>::manifest
    "<script>::rootdse": [
        ("assign Equals", "_rootDse"),
    ],
    # read by a binding of $<script>::caconfig
    "<script>::row": [
        (
            "assign Equals",
            "[ordered]@{ name = $cn dns = $dns config_string = \"$dns\\$cn\" object_guid = (_guidHex @(_v $p 'objectguid')) enrollment_service = $true # An enterprise CA may be a root or a subordinate: CAType is read from # the CA's own registry, so for a remote CA the kind is not obtained. kind = $null edit_flags = $null interface_flags= $null audit_filter = $null ca_patch_state = 'unknown' disabled_extensions = $null owner_sid = $null registry_config_collected = $false }",
        ),
        ("assign Equals", "_localCaRow $cn $dns (_guidHex @(_v $p 'objectguid')) $true"),
    ],
    # condition $rows
    "<script>::rows": [
        ("assign Equals", "@()"),
        ("assign PlusEquals", ",@($der, $kind)"),
    ],
    # input of _wmiDwordStatus: _wmiDwordStatus $sch
    "<script>::sch": [
        (
            "assign Equals",
            "$reg.GetDWORDValue($HKLM, 'SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL', 'CertificateMappingMethods')",
        ),
    ],
    # input of _decode: _decode ([int]$sch.uValue) $SCHANNEL_BITS
    "<script>::schannel_bits": [
        (
            "assign Equals",
            "[ordered]@{ 1 = 'subject_issuer'; 2 = 'issuer'; 4 = 'upn'; 8 = 's4u2self'; 16 = 's4u2self_explicit' }",
        ),
    ],
    # input of _list: _list $schannelMethods
    "<script>::schannelmethods": [
        ("assign Equals", "$null"),
        ("assign Equals", "@()"),
        ("assign Equals", "_decode ([int]$sch.uValue) $SCHANNEL_BITS"),
    ],
    # read by a binding of $<script>::templates
    "<script>::sec": [
        ("assign Equals", "_sdRead (@(_v $p 'ntsecuritydescriptor')[0])"),
    ],
    # input of Get-WebApplication: Get-WebApplication -Site $site.Name -ErrorAction Stop
    "<script>::site": [
        ("foreach", "(Get-Website -ErrorAction Stop)"),
    ],
    # read by a binding of $<script>::manifest
    "<script>::skippedpasses": [
        ("assign Equals", "@()"),
        ("assign PlusEquals", "'ca-security'"),
        ("assign PlusEquals", "'certs'"),
        ("assign PlusEquals", "'enrollment-endpoints'"),
        ("assign PlusEquals", "'esc10-dc-registry'"),
        ("assign PlusEquals", "'esc14-altsecid'"),
    ],
    # condition $ssl.ok
    "<script>::ssl": [
        (
            "assign Equals",
            "_tryRead { Get-WebConfigurationProperty -PSPath $ps -Filter 'system.webServer/security/access' -Name sslFlags -ErrorAction Stop }",
        ),
    ],
    # input of _markSearch: _markSearch 'ca-config' $caSearch (@($es.entries).Count + $standalone) $caConfig.Count $esFailures
    "<script>::standalone": [
        ("assign Equals", "0"),
        ("assign Equals", "1"),
    ],
    # input of _epaToken: _epaToken $tc.value.Value
    "<script>::tc": [
        (
            "assign Equals",
            "_tryRead { Get-WebConfigurationProperty -PSPath $ps -Filter $auth -Name 'extendedProtection.tokenChecking' -ErrorAction Stop }",
        ),
    ],
    # input of _markSearch: _markSearch 'templates' $ts @($ts.entries).Count $templates.Count $tsFailures
    "<script>::templates": [
        ("assign Equals", "@()"),
        (
            "assign PlusEquals",
            "[ordered]@{ name = [string]@(_v $p 'cn')[0] object_guid = (_guidHex @(_v $p 'objectguid')) display_name = [string]@(_v $p 'displayname')[0] schema_version = if (@(_v $p 'mspki-template-schema-version').Count) { [int]@(_v $p 'mspki-template-schema-version')[0] } else { 1 } oid = [string]@(_v $p 'mspki-cert-template-oid')[0] ekus = (@(_v $p 'pkiextendedkeyusage' | ForEach-Object { [string]$_ })) name_flags = (_decode $nf $NAME_FLAGS) enrollment_flags = (_decode $ef $ENROLL_FLAGS) min_key_size = if (@(_v $p 'mspki-minimal-key-size').Count) { [int]@(_v $p 'mspki-minimal-key-size')[0] } else { $null } issuance_policy_oids = (@(_v $p 'mspki-certificate-policy' | ForEach-Object { [string]$_ })) csp = (($csps -join ', ').ToLower()) security = $sec.aces # template DACL -> ACEs (ESC1/ESC4); null if not obtained acl_obtained = ($null -ne $sec.aces) # SD requested, returned and parsed owner_sid = $sec.owner }",
        ),
    ],
    # read by a binding of $<script>::webendpoints
    "<script>::transports": [
        ("assign Equals", "$null"),
        ("assign Equals", "@($protos)"),
    ],
    # input of _markSearch: _markSearch 'templates' $ts @($ts.entries).Count $templates.Count $tsFailures
    "<script>::ts": [
        (
            "assign Equals",
            "_search \"CN=Certificate Templates,$pksDn\" '(objectClass=pKICertificateTemplate)' @( 'cn', 'displayname', 'objectguid', 'mspki-certificate-name-flag', 'mspki-enrollment-flag', 'pkiextendedkeyusage', 'mspki-certificate-policy', 'pkicsp', 'mspki-template-schema-version', 'mspki-cert-template-oid', 'mspki-minimal-key-size', 'ntsecuritydescriptor') -Sd",
        ),
    ],
    # input of _markSearch: _markSearch 'templates' $ts @($ts.entries).Count $templates.Count $tsFailures
    "<script>::tsfailures": [
        ("assign Equals", "@()"),
        ("assign PlusEquals", '"template: $($_.Exception.Message)"'),
    ],
    # condition $wa.ok
    "<script>::wa": [
        (
            "assign Equals",
            "_tryRead { Get-WebConfigurationProperty -PSPath $ps -Filter $auth -Name enabled -ErrorAction Stop }",
        ),
    ],
    # input of _searchMarker: _searchMarker $endpointsComplete $endpointsReason $webEndpoints.Count $webEndpoints.Count $iisFailures
    "<script>::webendpoints": [
        ("assign Equals", "@()"),
        (
            "assign PlusEquals",
            "[ordered]@{ kind = $kind name = $appPath transports = $transports ssl_required = if ($ssl.ok) { ([string]$ssl.value.Value) -match 'Ssl' } else { $null } windows_auth = if ($wa.ok) { [bool]$wa.value.Value } else { $null } auth_providers = (_list $provs) epa = if ($tc.ok) { _epaToken $tc.value.Value } else { $null } }",
        ),
    ],
    # condition $dcConfigs.Count -gt 0 -and $wmiFailures -eq $dcConfigs.Count
    "<script>::wmifailures": [
        (
            "assign Equals",
            "@($dcConfigs | Where-Object { $null -eq $_.strong_certificate_binding_enforcement }).Count",
        ),
    ],
    # condition $ot -eq $ZERO_GUID
    "<script>::zero_guid": [
        ("assign Equals", "'00000000-0000-0000-0000-000000000000'"),
    ],
    # input of _sdRead: _sdRead (@(_v $p 'ntsecuritydescriptor')[0])
    "_aclrow::p": [
        ("arg", "$p"),
        ("arg", "$p"),
        ("parameter", "$p"),
    ],
    # argument of .GetString(): [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($s))
    "_b64::s": [
        ("arg", "$DcRegistryPassB64"),
        ("arg", "$DcRegistryUserB64"),
        ("arg", "$LdapPassB64"),
        ("arg", "$LdapUserB64"),
        ("parameter", "[string]$s"),
    ],
    # condition $null -eq $resp -or [string]$resp.ResultCode -ne 'Success'
    "_basesearchcore::resp": [
        ("assign Equals", "& $send $null"),
    ],
    # input of $send: & $send $null
    "_basesearchcore::send": [
        ("arg", "$send"),
        ("parameter", "[scriptblock]$send"),
    ],
    # condition $null -eq $t
    "_cakindfromtype::t": [
        ("arg", "$caType"),
        ("parameter", "$t"),
    ],
    # condition $a.AceQualifier -eq 'AccessDenied'
    "_casecurityfrombytes::a": [
        ("foreach", "$rsd.DiscretionaryAcl"),
    ],
    # input of New-Object: New-Object Security.AccessControl.RawSecurityDescriptor(@([byte[]]$bytes), 0)
    "_casecurityfrombytes::bytes": [
        ("arg", "$bytes"),
        ("arg", "$r.value"),
        ("parameter", "$bytes"),
    ],
    # condition $m -band 0x1
    "_casecurityfrombytes::m": [
        ("assign Equals", "[int]$a.AccessMask"),
    ],
    # condition $rsd.Owner
    "_casecurityfrombytes::rsd": [
        (
            "assign Equals",
            "New-Object Security.AccessControl.RawSecurityDescriptor(@([byte[]]$bytes), 0)",
        ),
    ],
    # input of _tryRead: _tryRead { $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey( "SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$caName") if ($key) { $key.GetValue('Security') } else { $null } }
    "_casecurityread::caname": [
        ("arg", "$name"),
        ("parameter", "[string]$caName"),
    ],
    # input of _tryRead: _tryRead { $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey( "SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$caName") if ($key) { $key.GetValue('Security') } else { $null } }
    "_casecurityread::key": [
        (
            "assign Equals",
            '[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey( "SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\$caName")',
        ),
    ],
    # input of _caSecurityFromBytes: _caSecurityFromBytes $r.value
    "_casecurityread::r": [
        (
            "assign Equals",
            "_tryRead { $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey( \"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\$caName\") if ($key) { $key.GetValue('Security') } else { $null } }",
        ),
    ],
    # condition $c.Subject -eq $c.Issuer
    "_certkindfromder::c": [
        (
            "assign Equals",
            "New-Object Security.Cryptography.X509Certificates.X509Certificate2(,$der)",
        ),
    ],
    # input of New-Object: New-Object Security.Cryptography.X509Certificates.X509Certificate2(,$der)
    "_certkindfromder::der": [
        ("arg", "$der"),
        ("parameter", "[byte[]]$der"),
    ],
    # input of _certutilDwordFrom: _certutilDwordFrom $r.lines $r.code
    "_certutildword::r": [
        ("assign Equals", "_certutilRead $regpath"),
    ],
    # input of _certutilRead: _certutilRead $regpath
    "_certutildword::regpath": [
        ("arg", "'CA\\AuditFilter'"),
        ("arg", "'CA\\CAType'"),
        ("parameter", "[string]$regpath"),
    ],
    # input of _certutilStatus: _certutilStatus $lines $exitCode
    "_certutildwordfrom::exitcode": [
        ("arg", "$r.code"),
        ("parameter", "$exitCode"),
    ],
    # input of _certutilStatus: _certutilStatus $lines $exitCode
    "_certutildwordfrom::lines": [
        ("arg", "$r.lines"),
        ("parameter", "$lines"),
    ],
    # input of _certutilFlagsFrom: _certutilFlagsFrom $r.lines $r.code
    "_certutilflags::r": [
        ("assign Equals", "_certutilRead $regpath"),
    ],
    # input of _certutilRead: _certutilRead $regpath
    "_certutilflags::regpath": [
        ("arg", "'CA\\InterfaceFlags'"),
        ("arg", "'policy\\EditFlags'"),
        ("parameter", "[string]$regpath"),
    ],
    # input of _certutilStatus: _certutilStatus $lines $exitCode
    "_certutilflagsfrom::exitcode": [
        ("arg", "$r.code"),
        ("parameter", "$exitCode"),
    ],
    # input of _certutilStatus: _certutilStatus $lines $exitCode
    "_certutilflagsfrom::lines": [
        ("arg", "$r.lines"),
        ("parameter", "$lines"),
    ],
    # input of _certutilMultiSzFrom: _certutilMultiSzFrom $r.lines $r.code
    "_certutilmultisz::r": [
        ("assign Equals", "_certutilRead $regpath"),
    ],
    # input of _certutilRead: _certutilRead $regpath
    "_certutilmultisz::regpath": [
        ("arg", "'policy\\DisableExtensionList'"),
        ("parameter", "[string]$regpath"),
    ],
    # input of _certutilStatus: _certutilStatus $lines $exitCode
    "_certutilmultiszfrom::exitcode": [
        ("arg", "$r.code"),
        ("parameter", "$exitCode"),
    ],
    # input of _certutilStatus: _certutilStatus $lines $exitCode
    "_certutilmultiszfrom::lines": [
        ("arg", "$r.lines"),
        ("parameter", "$lines"),
    ],
    # parameter of _guidHex, called by a binding of $<script>::dcguid
    "_certutilmultiszfrom::values": [
        ("assign Equals", "_parseCertutilMultiSzLines $lines"),
    ],
    # parameter of _certutilStatus, called by a binding of $_certutilstringfrom::status
    "_certutilread::lines": [
        ("assign Equals", "@(& certutil -getreg $regpath 2>&1 | ForEach-Object { [string]$_ })"),
        ("assign Equals", "@([string]$_.Exception.Message)"),
    ],
    # input of certutil: & certutil -getreg $regpath 2>&1
    "_certutilread::regpath": [
        ("arg", "$regpath"),
        ("arg", "$regpath"),
        ("arg", "$regpath"),
        ("arg", "'CA\\CommonName'"),
        ("parameter", "[string]$regpath"),
    ],
    # condition $exitCode -eq 0
    "_certutilstatus::exitcode": [
        ("arg", "$exitCode"),
        ("arg", "$exitCode"),
        ("arg", "$exitCode"),
        ("arg", "$exitCode"),
        ("parameter", "$exitCode"),
    ],
    # parameter of _certutilStatus, called by a binding of $_certutilstringfrom::status
    "_certutilstatus::lines": [
        ("arg", "$lines"),
        ("arg", "$lines"),
        ("arg", "$lines"),
        ("arg", "$lines"),
        ("parameter", "$lines"),
    ],
    # condition $exitCode -eq 2 -or $exitCode -eq -2147024894 -or $text -match '0x80070002|ERROR_FILE_NOT_FOUND'
    "_certutilstatus::text": [
        ("assign Equals", '($lines | ForEach-Object { [string]$_ }) -join "`n"'),
    ],
    # input of _certutilStatus: _certutilStatus $lines $exitCode
    "_certutilstringfrom::exitcode": [
        ("arg", "$cnRead.code"),
        ("parameter", "$exitCode"),
    ],
    # input of _certutilStatus: _certutilStatus $lines $exitCode
    "_certutilstringfrom::lines": [
        ("arg", "$cnRead.lines"),
        ("parameter", "$lines"),
    ],
    # input of Where-Object: Where-Object { [string]$_ -match "$name REG_SZ = (.+)" }
    "_certutilstringfrom::name": [
        ("arg", "'CommonName'"),
        ("parameter", "[string]$name"),
    ],
    # condition $status -eq 'ok'
    "_certutilstringfrom::status": [
        ("assign Equals", "'failed'"),
        ("assign Equals", "_certutilStatus $lines $exitCode"),
    ],
    # condition -not $value
    "_certutilstringfrom::value": [
        ("assign Equals", "$null"),
        (
            "assign Equals",
            '($lines | Where-Object { [string]$_ -match "$name REG_SZ = (.+)" } | ForEach-Object { $Matches[1].Trim() } | Select-Object -First 1)',
        ),
    ],
    # input of _search: _search $containerDn $filter @('ntsecuritydescriptor', 'objectguid') -Sd
    "_childacls::containerdn": [
        ("arg", '"CN=Certification Authorities,$pksDn"'),
        ("arg", '"CN=Enrollment Services,$pksDn"'),
        ("parameter", "[string]$containerDn"),
    ],
    # input of _entryProps: _entryProps $e
    "_childacls::e": [
        ("foreach", "$r.entries"),
    ],
    # parameter of _searchMarker, called by a binding of $<script>::enumeration
    "_childacls::failures": [
        ("assign Equals", "@()"),
        ("assign PlusEquals", '"$kind`: $($_.Exception.Message)"'),
    ],
    # input of _search: _search $containerDn $filter @('ntsecuritydescriptor', 'objectguid') -Sd
    "_childacls::filter": [
        ("arg", "'(objectClass=certificationAuthority)'"),
        ("arg", "'(objectClass=pKIEnrollmentService)'"),
        ("parameter", "[string]$filter"),
    ],
    # input of _aclRow: _aclRow $p $kind
    "_childacls::kind": [
        ("arg", "'ca_object'"),
        ("arg", "'ca_object'"),
        ("parameter", "[string]$kind"),
    ],
    # input of _requireSchema: _requireSchema $p 'pki-acls'
    "_childacls::p": [
        ("assign Equals", "_entryProps $e"),
    ],
    # condition $r.entries
    "_childacls::r": [
        (
            "assign Equals",
            "_search $containerDn $filter @('ntsecuritydescriptor', 'objectguid') -Sd",
        ),
    ],
    # condition $l -match 'mscep'
    "_classifyapp::l": [
        ("assign Equals", "$p.ToLower()"),
    ],
    # receiver of .ToLower()
    "_classifyapp::p": [
        ("arg", "$appPath"),
        ("parameter", "[string]$p"),
    ],
    # condition $value -band $e.Key
    "_decode::e": [
        ("foreach", "$map.GetEnumerator()"),
    ],
    # receiver of .GetEnumerator()
    "_decode::map": [
        ("arg", "$ENROLL_FLAGS"),
        ("arg", "$NAME_FLAGS"),
        ("arg", "$SCHANNEL_BITS"),
        ("parameter", "$map"),
    ],
    # condition $value -band $e.Key
    "_decode::value": [
        ("arg", "$ef"),
        ("arg", "$nf"),
        ("arg", "([int]$sch.uValue)"),
        ("parameter", "[int]$value"),
    ],
    # condition $v
    "_decodebinding::v": [
        ("arg", "([int]$kdc.uValue)"),
        ("parameter", "[int]$v"),
    ],
    # receiver of .GetValues()
    "_entryprops::attr": [
        ("assign Equals", "$entry.Attributes[[string]$n]"),
    ],
    # condition @($entry.Attributes.AttributeNames)
    "_entryprops::entry": [
        ("arg", "$e"),
        ("arg", "$e"),
        ("arg", "$e"),
        ("arg", "$e"),
        ("arg", "$e"),
        ("arg", "$e"),
        ("arg", "$e"),
        ("arg", "$e"),
        ("arg", "$r.entries[0]"),
        ("arg", "$r.entries[0]"),
        ("parameter", "$entry"),
    ],
    # condition $BINARY_ATTRS -contains $key
    "_entryprops::key": [
        ("assign Equals", "([string]$n).ToLower()"),
    ],
    # read by a binding of $_entryprops::key
    "_entryprops::n": [
        ("foreach", "@($entry.Attributes.AttributeNames)"),
    ],
    # index write $p[$key]
    "_entryprops::p": [
        ("assign Equals", "@{}"),
        ("index Equals", "$p[$key] = @($attr.GetValues([byte[]]))"),
        ("index Equals", "$p[$key] = @($attr.GetValues([string]))"),
        ("index Equals", "$p['distinguishedname'] = @([string]$entry.DistinguishedName)"),
    ],
    # condition [string]$v
    "_epatoken::v": [
        ("arg", "$tc.value.Value"),
        ("parameter", "$v"),
    ],
    # condition $b.Count -ne 16
    "_guidhex::b": [
        ("assign Equals", "[byte[]]$values[0]"),
    ],
    # condition -not $values -or $values.Count -lt 1
    "_guidhex::values": [
        ("arg", "@(_v $p 'objectguid')"),
        ("arg", "@(_v $p 'objectguid')"),
        ("arg", "@(_v $p 'objectguid')"),
        ("arg", "@(_v $p 'objectguid')"),
        ("arg", "@(_v $p 'objectguid')"),
        ("arg", "@(_v $p 'objectguid')"),
        ("arg", "@(_v $p 'objectguid')"),
        ("arg", "@(_v $p 'objectguid')"),
        ("parameter", "$values"),
    ],
    # receiver of .Bind()
    "_ldapconnection::conn": [
        ("assign Equals", "[System.DirectoryServices.Protocols.LdapConnection]::new($id)"),
        ("assign Equals", "[System.DirectoryServices.Protocols.LdapConnection]::new($id, $cred)"),
        (
            "member Equals",
            "$conn.AuthType = [System.DirectoryServices.Protocols.AuthType]::Negotiate",
        ),
        ("member Equals", "$conn.SessionOptions.ProtocolVersion = 3"),
    ],
    # argument of .new(): [System.DirectoryServices.Protocols.LdapConnection]::new($id, $cred)
    "_ldapconnection::cred": [
        ("assign Equals", "New-Object System.Net.NetworkCredential($LdapUser, $LdapPass)"),
    ],
    # argument of .new(): [System.DirectoryServices.Protocols.LdapConnection]::new($id, $cred)
    "_ldapconnection::id": [
        (
            "assign Equals",
            "[System.DirectoryServices.Protocols.LdapDirectoryIdentifier]::new($null)",
        ),
    ],
    # condition $script:LdapConn
    "_ldapconnection::ldapconn": [
        ("assign Equals", "$conn"),
    ],
    # condition $null -eq $value
    "_list::value": [
        ("arg", "$disabledExt"),
        ("arg", "$editFlags"),
        ("arg", "$interfaceFlags"),
        ("arg", "$provs"),
        ("arg", "$schannelMethods"),
        ("parameter", "$value"),
    ],
    # parameter of _localCaRow, called by a binding of $<script>::caconfig
    "_localcarow::enrollmentservice": [
        ("arg", "$false"),
        ("arg", "$true"),
        ("parameter", "[bool]$enrollmentService"),
    ],
    # parameter of _localCaRow, called by a binding of $<script>::caconfig
    "_localcarow::guid": [
        ("arg", "''"),
        ("arg", "(_guidHex @(_v $p 'objectguid'))"),
        ("parameter", "[string]$guid"),
    ],
    # index write $script:localSecurity[$name]
    "_localcarow::localsecurity": [
        ("index Equals", "$script:localSecurity[$name] = $sec.aces"),
    ],
    # input of _caSecurityRead: _caSecurityRead $name
    "_localcarow::name": [
        ("arg", "$caCommonName"),
        ("arg", "$cn"),
        ("parameter", "[string]$name"),
    ],
    # read by a binding of $_localcarow::localsecurity
    "_localcarow::sec": [
        ("assign Equals", "_caSecurityRead $name"),
    ],
    # condition -not $complete
    "_mark::complete": [
        ("parameter", "[bool]$complete"),
    ],
    # read by a binding of $_mark::enumeration
    "_mark::container": [
        ("parameter", "[string]$container"),
    ],
    # read by a binding of $_mark::m
    "_mark::count": [
        ("parameter", "[int]$count"),
    ],
    # index write $enumeration[$container]
    "_mark::enumeration": [
        ("index Equals", "$enumeration[$container] = $m"),
    ],
    # index write $m['reason']
    "_mark::m": [
        ("assign Equals", "[ordered]@{ complete = $complete; count = $count }"),
        ("index Equals", "$m['reason'] = $reason"),
    ],
    # read by a binding of $_mark::m
    "_mark::reason": [
        ("parameter", "[string]$reason"),
    ],
    # read by a binding of $_marksearch::enumeration
    "_marksearch::container": [
        ("arg", "'ca-config'"),
        ("arg", "'certs'"),
        ("arg", "'crls'"),
        ("arg", "'dc-config'"),
        ("arg", "'enrollment-services'"),
        ("arg", "'oid-objects'"),
        ("arg", "'pki-acls'"),
        ("arg", "'principal-mappings'"),
        ("arg", "'templates'"),
        ("parameter", "[string]$container"),
    ],
    # index write $enumeration[$container]
    "_marksearch::enumeration": [
        (
            "index Equals",
            "$enumeration[$container] = _searchMarker ([bool]$search.complete) ([string]$search.reason) $returned $written $failures $rows",
        ),
    ],
    # input of _searchMarker: _searchMarker ([bool]$search.complete) ([string]$search.reason) $returned $written $failures $rows
    "_marksearch::failures": [
        ("arg", "$aiaFailures"),
        ("arg", "$cdpFailures"),
        ("arg", "$dcFailures"),
        ("arg", "$esFailures"),
        ("arg", "$esFailures"),
        ("arg", "$osFailures"),
        ("arg", "$psFailures"),
        ("arg", "$tsFailures"),
        ("arg", "(@($caObjects.failures) + @($esObjects.failures))"),
        ("parameter", "[string[]]$failures"),
    ],
    # input of _searchMarker: _searchMarker ([bool]$search.complete) ([string]$search.reason) $returned $written $failures $rows
    "_marksearch::returned": [
        ("arg", "(6 + $caObjects.returned + $esObjects.returned)"),
        ("arg", "(@($es.entries).Count + $standalone)"),
        ("arg", "@($aia.entries).Count"),
        ("arg", "@($cdp.entries).Count"),
        ("arg", "@($dcs.entries).Count"),
        ("arg", "@($es.entries).Count"),
        ("arg", "@($os.entries).Count"),
        ("arg", "@($ps14.entries).Count"),
        ("arg", "@($ts.entries).Count"),
        ("parameter", "[int]$returned"),
    ],
    # input of _searchMarker: _searchMarker ([bool]$search.complete) ([string]$search.reason) $returned $written $failures $rows
    "_marksearch::rows": [
        ("arg", "$certIndex.Count"),
        ("arg", "$crlIndex.Count"),
        ("parameter", "[int]$rows = -1"),
    ],
    # input of _searchMarker: _searchMarker ([bool]$search.complete) ([string]$search.reason) $returned $written $failures $rows
    "_marksearch::search": [
        ("arg", "$aia"),
        ("arg", "$caSearch"),
        ("arg", "$cdp"),
        ("arg", "$dcs"),
        ("arg", "$es"),
        ("arg", "$os"),
        ("arg", "$pkiSearch"),
        ("arg", "$ps14"),
        ("arg", "$ts"),
        ("parameter", "$search"),
    ],
    # input of _searchMarker: _searchMarker ([bool]$search.complete) ([string]$search.reason) $returned $written $failures $rows
    "_marksearch::written": [
        ("arg", "$aiaObjects"),
        ("arg", "$caConfig.Count"),
        ("arg", "$cdpObjects"),
        ("arg", "$dcConfigs.Count"),
        ("arg", "$enrollmentServices.Count"),
        ("arg", "$oids.Count"),
        ("arg", "$pkiAcls.Count"),
        ("arg", "$principalMappings.Count"),
        ("arg", "$templates.Count"),
        ("parameter", "[int]$written"),
    ],
    # input of _search: _search $dn '(objectClass=*)' @('ntsecuritydescriptor', 'objectguid') -Scope Base -Sd
    "_objacl::dn": [
        ("arg", "$pair[0]"),
        ("parameter", "[string]$dn"),
    ],
    # input of _aclRow: _aclRow $p $kind
    "_objacl::kind": [
        ("arg", "$pair[1]"),
        ("parameter", "[string]$kind"),
    ],
    # input of _schemaCheck: _schemaCheck $p $OBJECT_SCHEMA.'pki-acls'
    "_objacl::p": [
        ("assign Equals", "_entryProps $r.entries[0]"),
    ],
    # input of _entryProps: _entryProps $r.entries[0]
    "_objacl::r": [
        (
            "assign Equals",
            "_search $dn '(objectClass=*)' @('ntsecuritydescriptor', 'objectguid') -Scope Base -Sd",
        ),
    ],
    # input of $send: & $send $cookie
    "_pagedsearchcore::cookie": [
        ("assign Equals", "@()"),
        ("assign Equals", "[byte[]]@($ctl.Cookie)"),
    ],
    # condition $null -eq $ctl
    "_pagedsearchcore::ctl": [
        (
            "assign Equals",
            "@($resp.Controls | Where-Object { $null -ne $_ -and $_.PSObject.Properties['Cookie'] }) | Select-Object -First 1",
        ),
    ],
    # argument of .Add(): $entries.Add($e)
    "_pagedsearchcore::e": [
        ("foreach", "@($resp.Entries)"),
    ],
    # receiver of .Add()
    "_pagedsearchcore::entries": [
        ("assign Equals", "New-Object System.Collections.ArrayList"),
    ],
    # condition $page -lt $maxPages
    "_pagedsearchcore::maxpages": [
        ("parameter", "[int]$maxPages = 100000"),
    ],
    # condition $page -lt $maxPages
    "_pagedsearchcore::page": [
        ("assign Equals", "0"),
        ("incdec PostfixPlusPlus", ""),
    ],
    # condition $null -eq $resp
    "_pagedsearchcore::resp": [
        ("assign Equals", "& $send $cookie"),
    ],
    # input of $send: & $send $cookie
    "_pagedsearchcore::send": [
        ("arg", "$send"),
        ("parameter", "[scriptblock]$send"),
    ],
    # receiver of .Translate()
    "_parseaces::a": [
        ("foreach", "$sd.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])"),
    ],
    # condition $flag -eq 'ExtendedRight'
    "_parseaces::flag": [
        ("foreach", "($a.ActiveDirectoryRights.ToString() -split ',\\s*')"),
    ],
    # parameter of _safeFileName, called by a binding of $<script>::crlfile
    "_parseaces::name": [
        ("assign Equals", "''"),
        (
            "assign Equals",
            "[string]$a.IdentityReference.Translate([Security.Principal.NTAccount]).Value",
        ),
    ],
    # receiver of .ToLower()
    "_parseaces::ot": [
        ("assign Equals", "$a.ObjectType.ToString()"),
    ],
    # receiver of .SetSecurityDescriptorBinaryForm()
    "_parseaces::sd": [
        ("assign Equals", "New-Object DirectoryServices.ActiveDirectorySecurity"),
    ],
    # argument of .SetSecurityDescriptorBinaryForm(): $sd.SetSecurityDescriptorBinaryForm($sdBytes)
    "_parseaces::sdbytes": [
        ("arg", "([byte[]]$sdBytes)"),
        ("parameter", "[byte[]]$sdBytes"),
    ],
    # condition $line -match 'REG_DWORD\s*=\s*(?:0x)?([0-9a-fA-F]+)\b'
    "_parsecertutildwordlines::line": [
        ("foreach", "$lines"),
    ],
    # condition $lines
    "_parsecertutildwordlines::lines": [
        ("arg", "$lines"),
        ("arg", "$lines"),
        ("parameter", "$lines"),
    ],
    # condition $line -match '^\s+([A-Z][A-Z0-9_]+)\s+--\s'
    "_parsecertutilflaglines::line": [
        ("foreach", "$lines"),
    ],
    # condition $lines
    "_parsecertutilflaglines::lines": [
        ("arg", "$lines"),
        ("parameter", "$lines"),
    ],
    # condition $inMulti
    "_parsecertutilmultiszlines::inmulti": [
        ("assign Equals", "$false"),
        ("assign Equals", "$true"),
    ],
    # receiver of .Trim()
    "_parsecertutilmultiszlines::line": [
        ("foreach", "$lines"),
    ],
    # condition $lines
    "_parsecertutilmultiszlines::lines": [
        ("arg", "$lines"),
        ("parameter", "$lines"),
    ],
    # condition $tok
    "_parsecertutilmultiszlines::tok": [
        ("foreach", "($Matches[1] -split '\\s+')"),
    ],
    # input of _caSecurityFromBytes: _caSecurityFromBytes $bytes
    "_rawsdowner::bytes": [
        ("parameter", "[byte[]]$bytes"),
    ],
    # condition $sec.owner
    "_rawsdowner::sec": [
        ("assign Equals", "_caSecurityFromBytes $bytes"),
    ],
    # receiver of .SetSecurityDescriptorBinaryForm()
    "_readowner::sd": [
        ("assign Equals", "New-Object DirectoryServices.ActiveDirectorySecurity"),
    ],
    # argument of .SetSecurityDescriptorBinaryForm(): $sd.SetSecurityDescriptorBinaryForm($sdBytes)
    "_readowner::sdbytes": [
        ("arg", "([byte[]]$sdBytes)"),
        ("parameter", "[byte[]]$sdBytes"),
    ],
    # condition $check.fatal
    "_requireschema::check": [
        ("assign Equals", "_schemaCheck $p $OBJECT_SCHEMA.$container"),
    ],
    # input of _schemaCheck: _schemaCheck $p $OBJECT_SCHEMA.$container
    "_requireschema::container": [
        ("arg", "'certs'"),
        ("arg", "'crls'"),
        ("arg", "'dc-config'"),
        ("arg", "'enrollment-services'"),
        ("arg", "'oid-objects'"),
        ("arg", "'pki-acls'"),
        ("arg", "'principal-mappings'"),
        ("arg", "'templates'"),
        ("parameter", "[string]$container"),
    ],
    # input of _schemaCheck: _schemaCheck $p $OBJECT_SCHEMA.$container
    "_requireschema::p": [
        ("arg", "$p"),
        ("arg", "$p"),
        ("arg", "$p"),
        ("arg", "$p"),
        ("arg", "$p"),
        ("arg", "$p"),
        ("arg", "$p"),
        ("arg", "$p"),
        ("parameter", "$p"),
    ],
    # input of _v: _v $p 'configurationnamingcontext'
    "_rootdse::p": [
        ("assign Equals", "_entryProps $r.entries[0]"),
    ],
    # input of _entryProps: _entryProps $r.entries[0]
    "_rootdse::r": [
        (
            "assign Equals",
            "_search '' '(objectClass=*)' @('configurationNamingContext', 'defaultNamingContext') -Scope Base",
        ),
    ],
    # condition $script:RootDse
    "_rootdse::rootdse": [
        (
            "assign Equals",
            "@{ config = [string]@(_v $p 'configurationnamingcontext')[0] domain = [string]@(_v $p 'defaultnamingcontext')[0] }",
        ),
    ],
    # parameter of _safeFileName, called by a binding of $<script>::crlfile
    "_safefilename::name": [
        ("arg", "$cn"),
        ("arg", "$cn"),
        ("parameter", "[string]$name"),
    ],
    # input of _v: _v $p $attr
    "_schemacheck::attr": [
        ("assign Equals", "$prop.Name"),
    ],
    # argument of .TryParse(): [int]::TryParse($values[0], [ref]$n)
    "_schemacheck::n": [
        ("assign Equals", "0"),
        ("ref", "[int]::TryParse($values[0], [ref]$n)"),
    ],
    # input of _v: _v $p $attr
    "_schemacheck::p": [
        ("arg", "$p"),
        ("arg", "$p"),
        ("parameter", "$p"),
    ],
    # read by a binding of $_schemacheck::rule
    "_schemacheck::prop": [
        ("foreach", "$spec.PSObject.Properties"),
    ],
    # condition $rule.need -eq 'sd'
    "_schemacheck::rule": [
        ("assign Equals", "$prop.Value"),
    ],
    # condition $null -eq $spec
    "_schemacheck::spec": [
        ("arg", "$OBJECT_SCHEMA.$container"),
        ("arg", "$OBJECT_SCHEMA.'pki-acls'"),
        ("parameter", "$spec"),
    ],
    # receiver of .Trim()
    "_schemacheck::v": [
        ("foreach", "$values"),
        ("foreach", "$values"),
    ],
    # argument of .TryParse(): [int]::TryParse($values[0], [ref]$n)
    "_schemacheck::values": [
        ("assign Equals", "@(_v $p $attr)"),
    ],
    # condition $why
    "_schemacheck::why": [
        ("assign Equals", '"$attr has an empty or non-string value"'),
        ("assign Equals", '"$attr is empty or not a single string"'),
        ("assign Equals", '"$attr is not a 16-byte objectGUID"'),
        ("assign Equals", '"$attr is not a binary value"'),
        ("assign Equals", '"$attr is not an integer"'),
        ("assign Equals", '"$attr missing"'),
        ("assign Equals", '"$attr missing"'),
        ("assign Equals", "$null"),
    ],
    # condition -not $owner -or $null -eq $aces
    "_sdread::aces": [
        ("assign Equals", "$null"),
        ("assign Equals", "$null"),
        ("assign Equals", "_parseAces ([byte[]]$sdBytes)"),
    ],
    # condition -not $owner -or $null -eq $aces
    "_sdread::owner": [
        ("assign Equals", "$null"),
        ("assign Equals", "_readOwner ([byte[]]$sdBytes)"),
    ],
    # input of _parseAces: _parseAces ([byte[]]$sdBytes)
    "_sdread::sdbytes": [
        ("arg", "(@(_v $p 'ntsecuritydescriptor')[0])"),
        ("arg", "(@(_v $p 'ntsecuritydescriptor')[0])"),
        ("parameter", "$sdBytes"),
    ],
    # argument of .new(): [System.DirectoryServices.Protocols.SearchRequest]::new( $baseDn, $filter, [System.DirectoryServices.Protocols.SearchScope]$Scope, $attrs)
    "_search::attrs": [
        (
            "arg",
            "@( 'cn', 'displayname', 'objectguid', 'mspki-certificate-name-flag', 'mspki-enrollment-flag', 'pkiextendedkeyusage', 'mspki-certificate-policy', 'pkicsp', 'mspki-template-schema-version', 'mspki-cert-template-oid', 'mspki-minimal-key-size', 'ntsecuritydescriptor')",
        ),
        ("arg", "@('altsecurityidentities', 'objectguid')"),
        ("arg", "@('cn', 'cacertificate')"),
        ("arg", "@('cn', 'certificaterevocationlist', 'objectguid')"),
        ("arg", "@('cn', 'dnshostname', 'certificatetemplates', 'objectguid')"),
        ("arg", "@('configurationNamingContext', 'defaultNamingContext')"),
        ("arg", "@('dnshostname', 'objectguid')"),
        ("arg", "@('mspki-cert-template-oid', 'objectguid', 'displayname', 'msds-oidtogrouplink')"),
        ("arg", "@('ntsecuritydescriptor', 'objectguid')"),
        ("arg", "@('ntsecuritydescriptor', 'objectguid')"),
        ("parameter", "[string[]]$attrs"),
    ],
    # argument of .new(): [System.DirectoryServices.Protocols.SearchRequest]::new( $baseDn, $filter, [System.DirectoryServices.Protocols.SearchScope]$Scope, $attrs)
    "_search::basedn": [
        ("arg", '"CN=AIA,$pksDn"'),
        ("arg", '"CN=CDP,$pksDn"'),
        ("arg", '"CN=Certificate Templates,$pksDn"'),
        ("arg", '"CN=Enrollment Services,$pksDn"'),
        ("arg", '"CN=OID,$pksDn"'),
        ("arg", "$containerDn"),
        ("arg", "$dn"),
        ("arg", "$domNc"),
        ("arg", "$domNc"),
        ("arg", "''"),
        ("parameter", "[string]$baseDn"),
    ],
    # receiver of .SendRequest()
    "_search::conn": [
        ("assign Equals", "_ldapConnection"),
    ],
    # condition $cookie -and $cookie.Length
    "_search::cookie": [
        ("parameter", "[byte[]]$cookie"),
    ],
    # argument of .new(): [System.DirectoryServices.Protocols.SearchRequest]::new( $baseDn, $filter, [System.DirectoryServices.Protocols.SearchScope]$Scope, $attrs)
    "_search::filter": [
        ("arg", "$filter"),
        ("arg", "'(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))'"),
        ("arg", "'(altSecurityIdentities=*)'"),
        ("arg", "'(objectClass=*)'"),
        ("arg", "'(objectClass=*)'"),
        ("arg", "'(objectClass=cRLDistributionPoint)'"),
        ("arg", "'(objectClass=certificationAuthority)'"),
        ("arg", "'(objectClass=msPKI-Enterprise-Oid)'"),
        ("arg", "'(objectClass=pKICertificateTemplate)'"),
        ("arg", "'(objectClass=pKIEnrollmentService)'"),
        ("parameter", "[string]$filter"),
    ],
    # argument of .Add(): $req.Controls.Add($page)
    "_search::page": [
        (
            "assign Equals",
            "[System.DirectoryServices.Protocols.PageResultRequestControl]::new(500)",
        ),
        ("member Equals", "$page.Cookie = $cookie"),
    ],
    # input of SendRequest: $conn.SendRequest($req)
    "_search::req": [
        (
            "assign Equals",
            "[System.DirectoryServices.Protocols.SearchRequest]::new( $baseDn, $filter, [System.DirectoryServices.Protocols.SearchScope]$Scope, $attrs)",
        ),
    ],
    # argument of .new(): [System.DirectoryServices.Protocols.SearchRequest]::new( $baseDn, $filter, [System.DirectoryServices.Protocols.SearchScope]$Scope, $attrs)
    "_search::scope": [
        ("arg", "Base"),
        ("arg", "Base"),
        ("parameter", "[string]$Scope = 'Subtree'"),
    ],
    # condition $Sd
    "_search::sd": [
        ("arg", "switch"),
        ("arg", "switch"),
        ("arg", "switch"),
        ("parameter", "[switch]$Sd"),
    ],
    # input of _baseSearchCore: _baseSearchCore $send
    "_search::send": [
        (
            "assign Equals",
            "{ param([byte[]]$cookie) $req = [System.DirectoryServices.Protocols.SearchRequest]::new( $baseDn, $filter, [System.DirectoryServices.Protocols.SearchScope]$Scope, $attrs) if ($Scope -ne 'Base') { $page = [System.DirectoryServices.Protocols.PageResultRequestControl]::new(500) if ($cookie -and $cookie.Length) { $page.Cookie = $cookie } [void]$req.Controls.Add($page) } if ($Sd) { [void]$req.Controls.Add([System.DirectoryServices.Protocols.SecurityDescriptorFlagControl]::new( [System.DirectoryServices.Protocols.SecurityMasks]'Dacl,Owner')) } $conn.SendRequest($req) }.GetNewClosure()",
        ),
    ],
    # condition -not $complete
    "_searchmarker::complete": [
        ("assign Equals", "$searched -and $written -eq $returned -and $failures.Count -eq 0"),
    ],
    # read by a binding of $_searchmarker::why
    "_searchmarker::detail": [
        ("assign Equals", '"$written of $returned enumerated object(s) serialized"'),
        ("assign PlusEquals", "': ' + ($failures -join '; ')"),
    ],
    # condition $written -ne $returned -or $failures.Count
    "_searchmarker::failures": [
        ("arg", "$failures"),
        ("arg", "$iisFailures"),
        ("assign Equals", "@($failures | Where-Object { $_ })"),
        ("parameter", "[string[]]$failures"),
    ],
    # index write $m['reason']
    "_searchmarker::m": [
        (
            "assign Equals",
            "[ordered]@{ complete = $complete; count = $(if ($rows -ge 0) { $rows } else { $written }) }",
        ),
        ("index Equals", "$m['reason'] = ($why -join '; ')"),
    ],
    # condition $written -ne $returned -or $failures.Count
    "_searchmarker::returned": [
        ("arg", "$returned"),
        ("arg", "$webEndpoints.Count"),
        ("parameter", "[int]$returned"),
    ],
    # condition $rows -ge 0
    "_searchmarker::rows": [
        ("arg", "$rows"),
        ("parameter", "[int]$rows = -1"),
    ],
    # condition -not $searched
    "_searchmarker::searched": [
        ("arg", "$endpointsComplete"),
        ("arg", "([bool]$search.complete)"),
        ("parameter", "[bool]$searched"),
    ],
    # parameter of _searchMarker, called by a binding of $<script>::enumeration
    "_searchmarker::searchreason": [
        ("arg", "$endpointsReason"),
        ("arg", "([string]$search.reason)"),
        ("parameter", "[string]$searchReason"),
    ],
    # read by a binding of $_searchmarker::m
    "_searchmarker::why": [
        ("assign Equals", "@()"),
        ("assign PlusEquals", "$detail"),
        ("assign PlusEquals", "$searchReason"),
    ],
    # condition $written -ne $returned -or $failures.Count
    "_searchmarker::written": [
        ("arg", "$webEndpoints.Count"),
        ("arg", "$written"),
        ("parameter", "[int]$written"),
    ],
    # input of $read: & $read
    "_tryread::read": [
        (
            "arg",
            "{ $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey( \"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\$caName\") if ($key) { $key.GetValue('Security') } else { $null } }",
        ),
        (
            "arg",
            '{ Get-WebConfigurationProperty -PSPath $ps -Filter "$auth/providers" -Name Collection -ErrorAction Stop }',
        ),
        (
            "arg",
            "{ Get-WebConfigurationProperty -PSPath $ps -Filter $auth -Name 'extendedProtection.tokenChecking' -ErrorAction Stop }",
        ),
        (
            "arg",
            "{ Get-WebConfigurationProperty -PSPath $ps -Filter $auth -Name enabled -ErrorAction Stop }",
        ),
        (
            "arg",
            "{ Get-WebConfigurationProperty -PSPath $ps -Filter 'system.webServer/security/access' -Name sslFlags -ErrorAction Stop }",
        ),
        ("parameter", "[scriptblock]$read"),
    ],
    # argument of .ContainsKey(): $p.ContainsKey($name)
    "_v::name": [
        ("arg", "$attr"),
        ("arg", "'altsecurityidentities'"),
        ("arg", "'cacertificate'"),
        ("arg", "'certificaterevocationlist'"),
        ("arg", "'certificaterevocationlist'"),
        ("arg", "'certificatetemplates'"),
        ("arg", "'cn'"),
        ("arg", "'cn'"),
        ("arg", "'cn'"),
        ("arg", "'cn'"),
        ("arg", "'configurationnamingcontext'"),
        ("arg", "'defaultnamingcontext'"),
        ("arg", "'displayname'"),
        ("arg", "'displayname'"),
        ("arg", "'distinguishedname'"),
        ("arg", "'distinguishedname'"),
        ("arg", "'distinguishedname'"),
        ("arg", "'distinguishedname'"),
        ("arg", "'distinguishedname'"),
        ("arg", "'dnshostname'"),
        ("arg", "'dnshostname'"),
        ("arg", "'msds-oidtogrouplink'"),
        ("arg", "'msds-oidtogrouplink'"),
        ("arg", "'mspki-cert-template-oid'"),
        ("arg", "'mspki-cert-template-oid'"),
        ("arg", "'mspki-certificate-name-flag'"),
        ("arg", "'mspki-certificate-name-flag'"),
        ("arg", "'mspki-certificate-policy'"),
        ("arg", "'mspki-enrollment-flag'"),
        ("arg", "'mspki-enrollment-flag'"),
        ("arg", "'mspki-minimal-key-size'"),
        ("arg", "'mspki-minimal-key-size'"),
        ("arg", "'mspki-template-schema-version'"),
        ("arg", "'mspki-template-schema-version'"),
        ("arg", "'ntsecuritydescriptor'"),
        ("arg", "'ntsecuritydescriptor'"),
        ("arg", "'objectguid'"),
        ("arg", "'objectguid'"),
        ("arg", "'objectguid'"),
        ("arg", "'objectguid'"),
        ("arg", "'objectguid'"),
        ("arg", "'objectguid'"),
        ("arg", "'objectguid'"),
        ("arg", "'objectguid'"),
        ("arg", "'pkicsp'"),
        ("arg", "'pkiextendedkeyusage'"),
        ("parameter", "[string]$name"),
    ],
    # receiver of .ContainsKey()
    "_v::p": [
        ("arg", "$p"),
        ("arg", "$p"),
        ("arg", "$p"),
        ("arg", "$p"),
        ("arg", "$p"),
        ("arg", "$p"),
        ("arg", "$p"),
        ("arg", "$p"),
        ("arg", "$p"),
        ("arg", "$p"),
        ("arg", "$p"),
        ("arg", "$p"),
        ("arg", "$p"),
        ("arg", "$p"),
        ("arg", "$p"),
        ("arg", "$p"),
        ("arg", "$p"),
        ("arg", "$p"),
        ("arg", "$p"),
        ("arg", "$p"),
        ("arg", "$p"),
        ("arg", "$p"),
        ("arg", "$p"),
        ("arg", "$p"),
        ("arg", "$p"),
        ("arg", "$p"),
        ("arg", "$p"),
        ("arg", "$p"),
        ("arg", "$p"),
        ("arg", "$p"),
        ("arg", "$p"),
        ("arg", "$p"),
        ("arg", "$p"),
        ("arg", "$p"),
        ("arg", "$p"),
        ("arg", "$p"),
        ("arg", "$p"),
        ("arg", "$p"),
        ("arg", "$p"),
        ("arg", "$p"),
        ("arg", "$p"),
        ("arg", "$p"),
        ("arg", "$p"),
        ("arg", "$p"),
        ("arg", "$p"),
        ("arg", "$p"),
        ("parameter", "$p"),
    ],
    # condition $null -eq $result
    "_wmidwordstatus::result": [
        ("arg", "$kdc"),
        ("arg", "$sch"),
        ("parameter", "$result"),
    ],
    # input of WriteAllText: [IO.File]::WriteAllText($outPath, $script:JS.Serialize($obj), (New-Object Text.UTF8Encoding($false)))
    "_writejson::obj": [
        ("arg", "$caSecurity"),
        ("arg", "$enrollmentServices"),
        ("arg", "$manifest"),
        ("arg", "([ordered]@{ certs = @($certIndex); crls = @($crlIndex) })"),
        ("arg", "@($caConfig)"),
        ("arg", "@($dcConfigs)"),
        ("arg", "@($oids)"),
        ("arg", "@($pkiAcls)"),
        ("arg", "@($principalMappings)"),
        ("arg", "@($templates)"),
        ("arg", "@($webEndpoints)"),
        ("parameter", "$obj"),
    ],
    # input of Join-Path: Join-Path $OutDir $outName
    "_writejson::outname": [
        ("arg", "'ca-config.json'"),
        ("arg", "'ca-security.json'"),
        ("arg", "'certs/index.json'"),
        ("arg", "'collector-manifest.json'"),
        ("arg", "'dc-config.json'"),
        ("arg", "'enrollment-services.json'"),
        ("arg", "'oid-objects.json'"),
        ("arg", "'pki-acls.json'"),
        ("arg", "'principal-mappings.json'"),
        ("arg", "'templates.json'"),
        ("arg", "'web-endpoints.json'"),
        ("parameter", "[string]$outName"),
    ],
    # input of Assert-AdcsOutputPath: Assert-AdcsOutputPath $outParent
    "_writejson::outparent": [
        ("assign Equals", "Split-Path $outPath -Parent"),
    ],
    # input of Split-Path: Split-Path $outPath -Parent
    "_writejson::outpath": [
        ("assign Equals", "Join-Path $OutDir $outName"),
    ],
    # argument of .GetDirectoryName(): [IO.Path]::GetDirectoryName($cur)
    "assert-adcsoutputpath::cur": [
        ("assign Equals", "$full"),
        ("assign Equals", "[IO.Path]::GetDirectoryName($cur)"),
    ],
    # receiver of .Equals()
    "assert-adcsoutputpath::full": [
        ("assign Equals", "[IO.Path]::GetFullPath($path).TrimEnd([char]'\\', [char]'/')"),
    ],
    # condition -not $inside
    "assert-adcsoutputpath::inside": [
        (
            "assign Equals",
            "$full.Equals($root, [StringComparison]::OrdinalIgnoreCase) -or $full.StartsWith($root + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase) -or $full.StartsWith($root + [IO.Path]::AltDirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)",
        ),
    ],
    # argument of .GetFullPath(): [IO.Path]::GetFullPath($path)
    "assert-adcsoutputpath::path": [
        ("arg", "$OutDir"),
        ("arg", "$certDir"),
        ("arg", "$outParent"),
        ("arg", "$outPath"),
        ("arg", "(Join-Path $certDir $certFile)"),
        ("arg", "(Join-Path $certDir $crlFile)"),
        ("parameter", "[string]$path"),
    ],
    # argument of .Equals(): $full.Equals($root, [StringComparison]::OrdinalIgnoreCase)
    "assert-adcsoutputpath::root": [
        ("assign Equals", "[IO.Path]::GetFullPath($OutDir).TrimEnd([char]'\\', [char]'/')"),
    ],
}

# The pinned write/exec/remote operations with their control-flow context, as a
# multiset of (normalized text, context outermost-first).
GUARDED_OPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "ForEach-Object { $_.ToString('x2') }",
        (
            "function _guidHex",
            "guard if (-not $values -or $values.Count -lt 1) -> return",
            "guard if ($b.Count -ne 16) -> return",
        ),
    ),
    ("Join-Path $OutDir $outName", ("function _writeJson",)),
    ("Split-Path $outPath -Parent", ("function _writeJson",)),
    ("Assert-AdcsOutputPath $outParent", ("function _writeJson",)),
    (
        "Assert-AdcsOutputPath $outPath",
        ("function _writeJson", "guard Assert-AdcsOutputPath $outParent"),
    ),
    (
        "Test-Path $outParent",
        (
            "function _writeJson",
            "guard Assert-AdcsOutputPath $outParent",
            "guard Assert-AdcsOutputPath $outPath",
            "if-condition after []",
        ),
    ),
    (
        "New-Item -ItemType Directory -Force -Path $outParent",
        (
            "function _writeJson",
            "guard Assert-AdcsOutputPath $outParent",
            "guard Assert-AdcsOutputPath $outPath",
            "if (-not (Test-Path $outParent)) after []",
        ),
    ),
    (
        "Out-Null",
        (
            "function _writeJson",
            "guard Assert-AdcsOutputPath $outParent",
            "guard Assert-AdcsOutputPath $outPath",
            "if (-not (Test-Path $outParent)) after []",
        ),
    ),
    (
        "New-Object Text.UTF8Encoding($false)",
        (
            "function _writeJson",
            "guard Assert-AdcsOutputPath $outParent",
            "guard Assert-AdcsOutputPath $outPath",
        ),
    ),
    ("New-Object System.Collections.ArrayList", ("function _pagedSearchCore",)),
    (
        "& $send $cookie",
        ("function _pagedSearchCore", "for ($page = 0; $page -lt $maxPages; $page++)", "try"),
    ),
    (
        "Where-Object { $null -ne $_ -and $_.PSObject.Properties['Cookie'] }",
        (
            "function _pagedSearchCore",
            "for ($page = 0; $page -lt $maxPages; $page++)",
            "guard if ($null -eq $resp) -> break",
            "guard if ([string]$resp.ResultCode -ne 'Success') -> break",
        ),
    ),
    (
        "Select-Object -First 1",
        (
            "function _pagedSearchCore",
            "for ($page = 0; $page -lt $maxPages; $page++)",
            "guard if ($null -eq $resp) -> break",
            "guard if ([string]$resp.ResultCode -ne 'Success') -> break",
        ),
    ),
    ("& $send $null", ("function _baseSearchCore", "try")),
    (
        "Add-Type -AssemblyName System.DirectoryServices.Protocols",
        ("function _ldapConnection", "guard if ($script:LdapConn) -> return"),
    ),
    (
        "New-Object System.Net.NetworkCredential($LdapUser, $LdapPass)",
        (
            "function _ldapConnection",
            "guard if ($script:LdapConn) -> return",
            "if ($LdapUser) after []",
        ),
    ),
    ("_ldapConnection", ("function _search",)),
    ("_baseSearchCore $send", ("function _search", "if ($Scope -eq 'Base') after []")),
    ("_pagedSearchCore $send", ("function _search", "guard if ($Scope -eq 'Base') -> return")),
    (
        "_search '' '(objectClass=*)' @('configurationNamingContext', 'defaultNamingContext') -Scope Base",
        ("function _rootDse", "guard if ($script:RootDse) -> return"),
    ),
    (
        "_entryProps $r.entries[0]",
        (
            "function _rootDse",
            "guard if ($script:RootDse) -> return",
            "guard if (-not $r.complete -or $r.entries.Count -ne 1) -> throw",
        ),
    ),
    (
        "_v $p 'configurationnamingcontext'",
        (
            "function _rootDse",
            "guard if ($script:RootDse) -> return",
            "guard if (-not $r.complete -or $r.entries.Count -ne 1) -> throw",
        ),
    ),
    (
        "_v $p 'defaultnamingcontext'",
        (
            "function _rootDse",
            "guard if ($script:RootDse) -> return",
            "guard if (-not $r.complete -or $r.entries.Count -ne 1) -> throw",
        ),
    ),
    (
        'ConvertFrom-Json @\' { "enrollment-services": { "distinguishedname": {"type": "string", "need": "required", "field": "(identity)"}, "cn": {"type": "string", "need": "required", "field": "name"}, "objectguid": {"type": "guid", "need": "required", "field": "object_guid"}, "dnshostname": {"type": "string", "need": "optional", "field": "dns"}, "certificatetemplates": {"type": "strings", "need": "optional", "field": "(source of template.published_by)"} }, "templates": { "distinguishedname": {"type": "string", "need": "required", "field": "(identity)"}, "cn": {"type": "string", "need": "required", "field": "name"}, "objectguid": {"type": "guid", "need": "required", "field": "object_guid"}, "mspki-cert-template-oid": {"type": "string", "need": "required", "field": "oid"}, "displayname": {"type": "string", "need": "optional", "field": "display_name"}, "mspki-certificate-name-flag": {"type": "int", "need": "optional", "field": "name_flags"}, "mspki-enrollment-flag": {"type": "int", "need": "optional", "field": "enrollment_flags"}, "pkiextendedkeyusage": {"type": "strings", "need": "optional", "field": "ekus"}, "mspki-certificate-policy": {"type": "strings", "need": "optional", "field": "issuance_policy_oids"}, "pkicsp": {"type": "strings", "need": "optional", "field": "csp"}, "mspki-template-schema-version": {"type": "int", "need": "optional", "field": "schema_version"}, "mspki-minimal-key-size": {"type": "int", "need": "optional", "field": "min_key_size"}, "ntsecuritydescriptor": {"type": "bytes", "need": "sd", "field": "security"} }, "oid-objects": { "distinguishedname": {"type": "string", "need": "required", "field": "(identity)"}, "mspki-cert-template-oid": {"type": "string", "need": "required", "field": "oid"}, "objectguid": {"type": "guid", "need": "required", "field": "object_guid"}, "displayname": {"type": "string", "need": "optional", "field": "name"}, "msds-oidtogrouplink": {"type": "string", "need": "optional", "field": "group_link"} }, "pki-acls": { "distinguishedname": {"type": "string", "need": "required", "field": "object_dn"}, "objectguid": {"type": "guid", "need": "required", "field": "object_guid"}, "ntsecuritydescriptor": {"type": "bytes", "need": "sd", "field": "security"} }, "certs": { "distinguishedname": {"type": "string", "need": "required", "field": "(identity)"}, "cn": {"type": "string", "need": "required", "field": "ca_name"}, "cacertificate": {"type": "bytes", "need": "optional", "field": "(certificate)"} }, "crls": { "distinguishedname": {"type": "string", "need": "required", "field": "source"}, "cn": {"type": "string", "need": "required", "field": "ca_name"}, "objectguid": {"type": "guid", "need": "required", "field": "object_guid"}, "certificaterevocationlist": {"type": "bytes", "need": "optional", "field": "(crl)"} }, "principal-mappings": { "distinguishedname": {"type": "string", "need": "required", "field": "dn"}, "objectguid": {"type": "guid", "need": "required", "field": "object_guid"}, "altsecurityidentities": {"type": "strings", "need": "required", "field": "mappings"} }, "dc-config": { "distinguishedname": {"type": "string", "need": "required", "field": "(identity)"}, "objectguid": {"type": "guid", "need": "required", "field": "object_guid"}, "dnshostname": {"type": "string", "need": "placeholder", "field": "name"} } } \'@',
        (),
    ),
    (
        'ConvertFrom-Json @\' { "crl.tier": { "by": "ingest", "from": ["certs.kind"], "containers": ["certs"], "join": "the CRL\'s CDP cn = the AIA object\'s cn", "miss": "null" }, "endpoint.transports": { "by": "collector", "from": ["IIS site bindings"], "containers": ["web-endpoints"], "join": "the application\'s site", "miss": "null" }, "template.published_by": { "by": "ingest", "from": ["enrollment-services.certificatetemplates"], "containers": ["enrollment-services"], "join": "template cn, exactly ($JOINS publication)", "miss": "unpublished only when enrollment-services is complete", "text": "ESC1-3 publication detail says the list is incomplete when it is" }, "cert.ca_kind": { "by": "ingest", "from": ["ca.kind"], "containers": ["ca-config"], "join": "certs/index.json ca_name = CA name", "miss": "null (unattached certificate)" } } \'@',
        (),
    ),
    (
        'ConvertFrom-Json @\' { "publication": { "field": "template.published_by", "by": "ingest", "impl": "resolve_join", "from": "enrollment-services.certificatetemplates", "to": "templates", "keys": ["cn"], "legacy_keys": ["cn", "oid"], "compare": "identical (MS-WCCE)", "none": "attaches nowhere (a published template that is not in AD)", "ambiguous": "published_by not obtained for every template it is identical or folds to" }, "cert-ca": { "field": "cert.ca_kind", "by": "ingest", "impl": "resolve_join", "from": "certs.ca_name", "to": "ca-config", "keys": ["cn"], "compare": "identical (both are cn values the collector copied)", "none": "unattached: ca_kind not obtained", "ambiguous": "unattached: ca_kind not obtained (two CA rows folding together is an ingest error)" }, "crl-tier": { "field": "crl.tier", "by": "ingest", "impl": "resolve_join", "from": "crls.ca_name (the CDP object\'s cn)", "to": "certs (certs/index.json ca_name)", "keys": ["ca_name"], "compare": "identical", "none": "tier null", "ambiguous": "tier null (also when one cn\'s certificates disagree on kind)" }, "ca-security": { "field": "ca.security", "by": "ingest", "impl": "exact set", "from": "ca-security.json keys", "to": "ca-config", "keys": ["cn"], "compare": "identical (the collector writes the row\'s name)", "none": "ingest error: an entry naming no CA, or a CA without an entry", "ambiguous": "ingest error: two CA rows whose names fold together" }, "publisher-ca": { "field": "ca.enrollment_service", "by": "ingest", "impl": "exact set", "from": "enrollment-services.json keys", "to": "ca-config", "keys": ["cn"], "compare": "identical (the collector writes the row\'s name)", "none": "ingest error: a publisher without a CA row, or the reverse", "ambiguous": "ingest error: two CA rows whose names fold together" }, "oid-link": { "field": "oid.group_link", "by": "detection (ESC13)", "impl": "resolve_join", "from": "templates.issuance_policy_oids", "to": "oid-objects", "keys": ["oid"], "compare": "identical", "none": "no link: decided only when oid-objects is complete", "ambiguous": "ESC13 undecided (duplicate OIDs also mark oid-objects incomplete)" }, "local-ca": { "field": "ca.edit_flags", "by": "collector", "impl": "-ceq", "from": "enrollment-services.cn", "to": "certutil CA\\\\CommonName", "keys": ["cn"], "compare": "identical (-ceq)", "none": "a remote CA: every registry field null (also for a CA whose AD name is sanitized)", "ambiguous": "ingest error: the local CA\'s standalone row and the enrollment service fold together" }, "app-site": { "field": "endpoint.transports", "by": "collector", "impl": "parent object", "from": "IIS application", "to": "its IIS site", "keys": ["(parent object)"], "compare": "enumerated under the site", "none": "transports null when the site\'s bindings read nothing", "ambiguous": "impossible: each application is enumerated under one site" } } \'@',
        (),
    ),
    (
        "_v $p $attr",
        (
            "function _schemaCheck",
            "guard if ($null -eq $spec) -> throw",
            "foreach ($prop in $spec.PSObject.Properties)",
            "guard if ($rule.need -eq 'sd') -> continue",
        ),
    ),
    ("_schemaCheck $p $OBJECT_SCHEMA.$container", ("function _requireSchema",)),
    ("_v $p 'distinguishedname'", ("function _requireSchema", "if ($check.fatal) after []")),
    ("Where-Object { $_ }", ("function _searchMarker",)),
    (
        "ForEach-Object { [string]$_ }",
        ("function _certutilStatus", "guard if ($exitCode -eq 0) -> return"),
    ),
    (
        "_certutilStatus $lines $exitCode",
        ("function _certutilFlagsFrom", "switch (_certutilStatus $lines $exitCode)"),
    ),
    ("_parseCertutilDwordLines $lines", ("function _certutilFlagsFrom", "if-condition after []")),
    (
        "_parseCertutilFlagLines $lines",
        (
            "function _certutilFlagsFrom",
            "guard if ($null -eq (_parseCertutilDwordLines $lines)) -> return",
        ),
    ),
    ("_certutilStatus $lines $exitCode", ("function _certutilDwordFrom", "if-condition after []")),
    (
        "_parseCertutilDwordLines $lines",
        (
            "function _certutilDwordFrom",
            "guard if ((_certutilStatus $lines $exitCode) -ne 'ok') -> return",
        ),
    ),
    (
        "_certutilStatus $lines $exitCode",
        ("function _certutilMultiSzFrom", "switch (_certutilStatus $lines $exitCode)"),
    ),
    (
        "Where-Object { [string]$_ -match 'REG_MULTI_SZ' }",
        ("function _certutilMultiSzFrom", "if-condition after []"),
    ),
    (
        "_parseCertutilMultiSzLines $lines",
        (
            "function _certutilMultiSzFrom",
            "guard if (-not ($lines | Where-Object { [string]$_ -match 'REG_MULTI_SZ' })) -> return",
        ),
    ),
    ("_certutilStatus $lines $exitCode", ("function _certutilStringFrom",)),
    (
        'Where-Object { [string]$_ -match "$name REG_SZ = (.+)" }',
        ("function _certutilStringFrom", "if ($status -eq 'ok') after []"),
    ),
    (
        "ForEach-Object { $Matches[1].Trim() }",
        ("function _certutilStringFrom", "if ($status -eq 'ok') after []"),
    ),
    ("Select-Object -First 1", ("function _certutilStringFrom", "if ($status -eq 'ok') after []")),
    ("& $read", ("function _tryRead", "try")),
    (
        "New-Object Security.Cryptography.X509Certificates.X509Certificate2(,$der)",
        (
            "function _certKindFromDer",
            "guard if (-not $der -or $der.Length -eq 0) -> return",
            "try",
        ),
    ),
    (
        "New-Object DirectoryServices.ActiveDirectorySecurity",
        ("function _parseAces", "guard if (-not $sdBytes -or $sdBytes.Length -eq 0) -> return"),
    ),
    (
        "_parseAces ([byte[]]$sdBytes)",
        ("function _sdRead", "guard if (-not $sdBytes -or $sdBytes.Length -eq 0) -> return", "try"),
    ),
    (
        "_readOwner ([byte[]]$sdBytes)",
        ("function _sdRead", "guard if (-not $sdBytes -or $sdBytes.Length -eq 0) -> return"),
    ),
    ("_sdRead (@(_v $p 'ntsecuritydescriptor')[0])", ("function _aclRow",)),
    ("_v $p 'ntsecuritydescriptor'", ("function _aclRow",)),
    ("_v $p 'distinguishedname'", ("function _aclRow",)),
    ("_guidHex @(_v $p 'objectguid')", ("function _aclRow",)),
    ("_v $p 'objectguid'", ("function _aclRow",)),
    (
        "_search $dn '(objectClass=*)' @('ntsecuritydescriptor', 'objectguid') -Scope Base -Sd",
        ("function _objAcl",),
    ),
    (
        "_entryProps $r.entries[0]",
        ("function _objAcl", "guard if (-not $r.complete -or $r.entries.Count -ne 1) -> return"),
    ),
    (
        "_schemaCheck $p $OBJECT_SCHEMA.'pki-acls'",
        (
            "function _objAcl",
            "guard if (-not $r.complete -or $r.entries.Count -ne 1) -> return",
            "if-condition after []",
        ),
    ),
    (
        "_aclRow $p $kind",
        (
            "function _objAcl",
            "guard if (-not $r.complete -or $r.entries.Count -ne 1) -> return",
            "guard if ((_schemaCheck $p $OBJECT_SCHEMA.'pki-acls').fatal) -> return",
        ),
    ),
    (
        "_search $containerDn $filter @('ntsecuritydescriptor', 'objectguid') -Sd",
        ("function _childAcls",),
    ),
    ("_entryProps $e", ("function _childAcls", "foreach ($e in $r.entries)", "try")),
    ("_requireSchema $p 'pki-acls'", ("function _childAcls", "foreach ($e in $r.entries)", "try")),
    ("_aclRow $p $kind", ("function _childAcls", "foreach ($e in $r.entries)", "try")),
    (
        "New-Object DirectoryServices.ActiveDirectorySecurity",
        (
            "function _readOwner",
            "guard if (-not $sdBytes -or $sdBytes.Length -eq 0) -> return",
            "try",
        ),
    ),
    (
        "New-Object Security.AccessControl.RawSecurityDescriptor(@([byte[]]$bytes), 0)",
        (
            "function _caSecurityFromBytes",
            "guard if (-not $bytes -or $bytes.Length -eq 0) -> return",
            "try",
        ),
    ),
    ("_caSecurityFromBytes $bytes", ("function _rawSdOwner",)),
    (
        "_tryRead { $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey( \"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\$caName\") if ($key) { $key.GetValue('Security') } else { $null } }",
        ("function _caSecurityRead",),
    ),
    (
        "_caSecurityFromBytes $r.value",
        ("function _caSecurityRead", "guard if (-not $r.ok) -> return"),
    ),
    ("& certutil -getreg $regpath 2>&1", ("function _certutilRead", "try")),
    ("ForEach-Object { [string]$_ }", ("function _certutilRead", "try")),
    ("_certutilRead $regpath", ("function _certutilFlags",)),
    ("_certutilFlagsFrom $r.lines $r.code", ("function _certutilFlags",)),
    ("_certutilRead $regpath", ("function _certutilDword",)),
    ("_certutilDwordFrom $r.lines $r.code", ("function _certutilDword",)),
    ("_certutilRead $regpath", ("function _certutilMultiSz",)),
    ("_certutilMultiSzFrom $r.lines $r.code", ("function _certutilMultiSz",)),
    (
        "_b64 $LdapUserB64",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "if ($LdapUserB64 -or $LdapPassB64) after []",
            "guard if (-not ($LdapUserB64 -and $LdapPassB64)) -> throw",
        ),
    ),
    (
        "_b64 $LdapPassB64",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "if ($LdapUserB64 -or $LdapPassB64) after []",
            "guard if (-not ($LdapUserB64 -and $LdapPassB64)) -> throw",
        ),
    ),
    (
        'Write-Host "Using explicit LDAP credentials ($LdapUser)"',
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "if ($LdapUser) after []",
        ),
    ),
    (
        'Write-Host "Using integrated auth (current user) for LDAP"',
        ("guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return", "else of [($LdapUser)]"),
    ),
    (
        "_b64 $DcRegistryUserB64",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "if ($CollectDcMapping -and ($DcRegistryUserB64 -or $DcRegistryPassB64)) after []",
            "guard if (-not ($DcRegistryUserB64 -and $DcRegistryPassB64)) -> throw",
        ),
    ),
    (
        "_b64 $DcRegistryPassB64",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "if ($CollectDcMapping -and ($DcRegistryUserB64 -or $DcRegistryPassB64)) after []",
            "guard if (-not ($DcRegistryUserB64 -and $DcRegistryPassB64)) -> throw",
        ),
    ),
    (
        "Assert-AdcsOutputPath $OutDir",
        ("guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",),
    ),
    (
        "New-Item -ItemType Directory -Force -Path $OutDir",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
        ),
    ),
    (
        "Out-Null",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
        ),
    ),
    (
        "Add-Type -AssemblyName System.Web.Extensions",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
        ),
    ),
    (
        "New-Object System.Web.Script.Serialization.JavaScriptSerializer",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
        ),
    ),
    (
        "_searchMarker ([bool]$search.complete) ([string]$search.reason) $returned $written $failures $rows",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "function _markSearch",
        ),
    ),
    (
        "_certutilRead 'CA\\CommonName'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
        ),
    ),
    (
        "_certutilStringFrom $cnRead.lines $cnRead.code 'CommonName'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
        ),
    ),
    (
        "_certutilFlags 'policy\\EditFlags'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
        ),
    ),
    (
        "_certutilFlags 'CA\\InterfaceFlags'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
        ),
    ),
    (
        "_certutilDword 'CA\\AuditFilter'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
        ),
    ),
    (
        "_certutilMultiSz 'policy\\DisableExtensionList'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
        ),
    ),
    (
        "_certutilDword 'CA\\CAType'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
        ),
    ),
    (
        "_caKindFromType $caType",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "if ($null -ne $caType) after []",
        ),
    ),
    (
        "hostname",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
        ),
    ),
    (
        "_rootDse",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
        ),
    ),
    (
        "_caSecurityRead $name",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "function _localCaRow",
        ),
    ),
    (
        "_list $editFlags",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "function _localCaRow",
        ),
    ),
    (
        "_list $interfaceFlags",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "function _localCaRow",
        ),
    ),
    (
        "_list $disabledExt",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "function _localCaRow",
        ),
    ),
    (
        "_search \"CN=Enrollment Services,$pksDn\" '(objectClass=pKIEnrollmentService)' @('cn', 'dnshostname', 'certificatetemplates', 'objectguid')",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
        ),
    ),
    (
        "_entryProps $e",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "foreach ($e in $es.entries)",
            "try",
        ),
    ),
    (
        "_requireSchema $p 'enrollment-services'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "foreach ($e in $es.entries)",
            "try",
        ),
    ),
    (
        "_v $p 'cn'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "foreach ($e in $es.entries)",
            "try",
        ),
    ),
    (
        "_v $p 'dnshostname'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "foreach ($e in $es.entries)",
            "try",
        ),
    ),
    (
        "_v $p 'certificatetemplates'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "foreach ($e in $es.entries)",
            "try",
        ),
    ),
    (
        "ForEach-Object { [string]$_ }",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "foreach ($e in $es.entries)",
            "try",
        ),
    ),
    (
        "_localCaRow $cn $dns (_guidHex @(_v $p 'objectguid')) $true",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "foreach ($e in $es.entries)",
            "try",
            "if ($isLocal) after []",
        ),
    ),
    (
        "_guidHex @(_v $p 'objectguid')",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "foreach ($e in $es.entries)",
            "try",
            "if ($isLocal) after []",
        ),
    ),
    (
        "_v $p 'objectguid'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "foreach ($e in $es.entries)",
            "try",
            "if ($isLocal) after []",
        ),
    ),
    (
        "_guidHex @(_v $p 'objectguid')",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "foreach ($e in $es.entries)",
            "try",
            "else of [($isLocal)]",
        ),
    ),
    (
        "_v $p 'objectguid'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "foreach ($e in $es.entries)",
            "try",
            "else of [($isLocal)]",
        ),
    ),
    (
        "Where-Object { $_.name -ceq $caCommonName }",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "if-condition after []",
        ),
    ),
    (
        "_localCaRow $caCommonName $localFqdn '' $false",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "if ($caCommonName -and -not $esFailures -and -not ($caConfig | Where-Object { $_.name -ceq $caCommonName })) after []",
        ),
    ),
    (
        "_markSearch 'ca-config' $caSearch (@($es.entries).Count + $standalone) $caConfig.Count $esFailures",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
        ),
    ),
    (
        "_markSearch 'enrollment-services' $es @($es.entries).Count $enrollmentServices.Count $esFailures",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
        ),
    ),
    (
        "_search \"CN=Certificate Templates,$pksDn\" '(objectClass=pKICertificateTemplate)' @( 'cn', 'displayname', 'objectguid', 'mspki-certificate-name-flag', 'mspki-enrollment-flag', 'pkiextendedkeyusage', 'mspki-certificate-policy', 'pkicsp', 'mspki-template-schema-version', 'mspki-cert-template-oid', 'mspki-minimal-key-size', 'ntsecuritydescriptor') -Sd",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
        ),
    ),
    (
        "_entryProps $e",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "foreach ($e in $ts.entries)",
            "try",
        ),
    ),
    (
        "_requireSchema $p 'templates'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "foreach ($e in $ts.entries)",
            "try",
        ),
    ),
    (
        "_v $p 'mspki-certificate-name-flag'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "foreach ($e in $ts.entries)",
            "try",
            "if-condition after []",
        ),
    ),
    (
        "_v $p 'mspki-certificate-name-flag'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "foreach ($e in $ts.entries)",
            "try",
            "if (@(_v $p 'mspki-certificate-name-flag').Count) after []",
        ),
    ),
    (
        "_v $p 'mspki-enrollment-flag'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "foreach ($e in $ts.entries)",
            "try",
            "if-condition after []",
        ),
    ),
    (
        "_v $p 'mspki-enrollment-flag'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "foreach ($e in $ts.entries)",
            "try",
            "if (@(_v $p 'mspki-enrollment-flag').Count) after []",
        ),
    ),
    (
        "_v $p 'pkicsp'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "foreach ($e in $ts.entries)",
            "try",
        ),
    ),
    (
        "ForEach-Object { [string]$_ }",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "foreach ($e in $ts.entries)",
            "try",
        ),
    ),
    (
        "_sdRead (@(_v $p 'ntsecuritydescriptor')[0])",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "foreach ($e in $ts.entries)",
            "try",
        ),
    ),
    (
        "_v $p 'ntsecuritydescriptor'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "foreach ($e in $ts.entries)",
            "try",
        ),
    ),
    (
        "_v $p 'cn'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "foreach ($e in $ts.entries)",
            "try",
        ),
    ),
    (
        "_guidHex @(_v $p 'objectguid')",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "foreach ($e in $ts.entries)",
            "try",
        ),
    ),
    (
        "_v $p 'objectguid'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "foreach ($e in $ts.entries)",
            "try",
        ),
    ),
    (
        "_v $p 'displayname'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "foreach ($e in $ts.entries)",
            "try",
        ),
    ),
    (
        "_v $p 'mspki-template-schema-version'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "foreach ($e in $ts.entries)",
            "try",
            "if-condition after []",
        ),
    ),
    (
        "_v $p 'mspki-template-schema-version'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "foreach ($e in $ts.entries)",
            "try",
            "if (@(_v $p 'mspki-template-schema-version').Count) after []",
        ),
    ),
    (
        "_v $p 'mspki-cert-template-oid'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "foreach ($e in $ts.entries)",
            "try",
        ),
    ),
    (
        "_v $p 'pkiextendedkeyusage'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "foreach ($e in $ts.entries)",
            "try",
        ),
    ),
    (
        "ForEach-Object { [string]$_ }",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "foreach ($e in $ts.entries)",
            "try",
        ),
    ),
    (
        "_decode $nf $NAME_FLAGS",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "foreach ($e in $ts.entries)",
            "try",
        ),
    ),
    (
        "_decode $ef $ENROLL_FLAGS",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "foreach ($e in $ts.entries)",
            "try",
        ),
    ),
    (
        "_v $p 'mspki-minimal-key-size'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "foreach ($e in $ts.entries)",
            "try",
            "if-condition after []",
        ),
    ),
    (
        "_v $p 'mspki-minimal-key-size'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "foreach ($e in $ts.entries)",
            "try",
            "if (@(_v $p 'mspki-minimal-key-size').Count) after []",
        ),
    ),
    (
        "_v $p 'mspki-certificate-policy'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "foreach ($e in $ts.entries)",
            "try",
        ),
    ),
    (
        "ForEach-Object { [string]$_ }",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "foreach ($e in $ts.entries)",
            "try",
        ),
    ),
    (
        "_markSearch 'templates' $ts @($ts.entries).Count $templates.Count $tsFailures",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
        ),
    ),
    (
        "_search \"CN=OID,$pksDn\" '(objectClass=msPKI-Enterprise-Oid)' @('mspki-cert-template-oid', 'objectguid', 'displayname', 'msds-oidtogrouplink')",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
        ),
    ),
    (
        "_entryProps $e",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "foreach ($e in $os.entries)",
            "try",
        ),
    ),
    (
        "_requireSchema $p 'oid-objects'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "foreach ($e in $os.entries)",
            "try",
        ),
    ),
    (
        "_v $p 'msds-oidtogrouplink'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "foreach ($e in $os.entries)",
            "try",
            "if-condition after []",
        ),
    ),
    (
        "_v $p 'msds-oidtogrouplink'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "foreach ($e in $os.entries)",
            "try",
            "if (@(_v $p 'msds-oidtogrouplink').Count) after []",
        ),
    ),
    (
        "_v $p 'mspki-cert-template-oid'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "foreach ($e in $os.entries)",
            "try",
        ),
    ),
    (
        "_guidHex @(_v $p 'objectguid')",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "foreach ($e in $os.entries)",
            "try",
        ),
    ),
    (
        "_v $p 'objectguid'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "foreach ($e in $os.entries)",
            "try",
        ),
    ),
    (
        "_v $p 'displayname'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "foreach ($e in $os.entries)",
            "try",
        ),
    ),
    (
        "_markSearch 'oid-objects' $os @($os.entries).Count $oids.Count $osFailures",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
        ),
    ),
    (
        "_objAcl $pair[0] $pair[1]",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "foreach ($pair in @( @($pksDn, 'pks_container'), @(\"CN=NTAuthCertificates,$pksDn\", 'ntauth'), @(\"CN=AIA,$pksDn\", 'aia'), @(\"CN=CDP,$pksDn\", 'cdp'), @(\"CN=Certification Authorities,$pksDn\", 'pks_container'), @(\"CN=Enrollment Services,$pksDn\", 'pks_container')))",
        ),
    ),
    (
        "_childAcls \"CN=Certification Authorities,$pksDn\" '(objectClass=certificationAuthority)' 'ca_object'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
        ),
    ),
    (
        "_childAcls \"CN=Enrollment Services,$pksDn\" '(objectClass=pKIEnrollmentService)' 'ca_object'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
        ),
    ),
    (
        "_markSearch 'pki-acls' $pkiSearch (6 + $caObjects.returned + $esObjects.returned) $pkiAcls.Count (@($caObjects.failures) + @($esObjects.failures))",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
        ),
    ),
    (
        "Join-Path $OutDir 'certs'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "try",
        ),
    ),
    (
        "Assert-AdcsOutputPath $certDir",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "try",
        ),
    ),
    (
        "_search \"CN=AIA,$pksDn\" '(objectClass=certificationAuthority)' @('cn', 'cacertificate')",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "try",
            "guard Assert-AdcsOutputPath $certDir",
        ),
    ),
    (
        "_entryProps $e",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "try",
            "guard Assert-AdcsOutputPath $certDir",
            "foreach ($e in $aia.entries)",
            "try",
        ),
    ),
    (
        "_requireSchema $p 'certs'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "try",
            "guard Assert-AdcsOutputPath $certDir",
            "foreach ($e in $aia.entries)",
            "try",
        ),
    ),
    (
        "_v $p 'cn'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "try",
            "guard Assert-AdcsOutputPath $certDir",
            "foreach ($e in $aia.entries)",
            "try",
        ),
    ),
    (
        "_v $p 'cacertificate'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "try",
            "guard Assert-AdcsOutputPath $certDir",
            "foreach ($e in $aia.entries)",
            "try",
            "foreach ($blob in @(_v $p 'cacertificate'))",
        ),
    ),
    (
        "_certKindFromDer $der",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "try",
            "guard Assert-AdcsOutputPath $certDir",
            "foreach ($e in $aia.entries)",
            "try",
            "foreach ($blob in @(_v $p 'cacertificate'))",
        ),
    ),
    (
        "New-Item -ItemType Directory -Force -Path $certDir",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "try",
            "guard Assert-AdcsOutputPath $certDir",
            "foreach ($e in $aia.entries)",
            "try",
            "foreach ($r in $rows)",
        ),
    ),
    (
        "Out-Null",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "try",
            "guard Assert-AdcsOutputPath $certDir",
            "foreach ($e in $aia.entries)",
            "try",
            "foreach ($r in $rows)",
        ),
    ),
    (
        "_safeFileName $cn",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "try",
            "guard Assert-AdcsOutputPath $certDir",
            "foreach ($e in $aia.entries)",
            "try",
            "foreach ($r in $rows)",
        ),
    ),
    (
        "Assert-AdcsOutputPath (Join-Path $certDir $certFile)",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "try",
            "guard Assert-AdcsOutputPath $certDir",
            "foreach ($e in $aia.entries)",
            "try",
            "foreach ($r in $rows)",
        ),
    ),
    (
        "Join-Path $certDir $certFile",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "try",
            "guard Assert-AdcsOutputPath $certDir",
            "foreach ($e in $aia.entries)",
            "try",
            "foreach ($r in $rows)",
        ),
    ),
    (
        "Join-Path $certDir $certFile",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "try",
            "guard Assert-AdcsOutputPath $certDir",
            "foreach ($e in $aia.entries)",
            "try",
            "foreach ($r in $rows)",
            "guard Assert-AdcsOutputPath (Join-Path $certDir $certFile)",
        ),
    ),
    (
        "_search \"CN=CDP,$pksDn\" '(objectClass=cRLDistributionPoint)' @('cn', 'certificaterevocationlist', 'objectguid')",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "try",
            "guard Assert-AdcsOutputPath $certDir",
        ),
    ),
    (
        "_entryProps $e",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "try",
            "guard Assert-AdcsOutputPath $certDir",
            "foreach ($e in $cdp.entries)",
            "try",
        ),
    ),
    (
        "_requireSchema $p 'crls'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "try",
            "guard Assert-AdcsOutputPath $certDir",
            "foreach ($e in $cdp.entries)",
            "try",
        ),
    ),
    (
        "_v $p 'cn'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "try",
            "guard Assert-AdcsOutputPath $certDir",
            "foreach ($e in $cdp.entries)",
            "try",
        ),
    ),
    (
        "_v $p 'certificaterevocationlist'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "try",
            "guard Assert-AdcsOutputPath $certDir",
            "foreach ($e in $cdp.entries)",
            "try",
            "if-condition after []",
        ),
    ),
    (
        "_v $p 'certificaterevocationlist'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "try",
            "guard Assert-AdcsOutputPath $certDir",
            "foreach ($e in $cdp.entries)",
            "try",
            "guard if (-not @(_v $p 'certificaterevocationlist').Count) -> continue",
        ),
    ),
    (
        "New-Item -ItemType Directory -Force -Path $certDir",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "try",
            "guard Assert-AdcsOutputPath $certDir",
            "foreach ($e in $cdp.entries)",
            "try",
            "guard if (-not @(_v $p 'certificaterevocationlist').Count) -> continue",
        ),
    ),
    (
        "Out-Null",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "try",
            "guard Assert-AdcsOutputPath $certDir",
            "foreach ($e in $cdp.entries)",
            "try",
            "guard if (-not @(_v $p 'certificaterevocationlist').Count) -> continue",
        ),
    ),
    (
        "_safeFileName $cn",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "try",
            "guard Assert-AdcsOutputPath $certDir",
            "foreach ($e in $cdp.entries)",
            "try",
            "guard if (-not @(_v $p 'certificaterevocationlist').Count) -> continue",
        ),
    ),
    (
        "Assert-AdcsOutputPath (Join-Path $certDir $crlFile)",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "try",
            "guard Assert-AdcsOutputPath $certDir",
            "foreach ($e in $cdp.entries)",
            "try",
            "guard if (-not @(_v $p 'certificaterevocationlist').Count) -> continue",
        ),
    ),
    (
        "Join-Path $certDir $crlFile",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "try",
            "guard Assert-AdcsOutputPath $certDir",
            "foreach ($e in $cdp.entries)",
            "try",
            "guard if (-not @(_v $p 'certificaterevocationlist').Count) -> continue",
        ),
    ),
    (
        "Join-Path $certDir $crlFile",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "try",
            "guard Assert-AdcsOutputPath $certDir",
            "foreach ($e in $cdp.entries)",
            "try",
            "guard if (-not @(_v $p 'certificaterevocationlist').Count) -> continue",
            "guard Assert-AdcsOutputPath (Join-Path $certDir $crlFile)",
        ),
    ),
    (
        "_guidHex @(_v $p 'objectguid')",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "try",
            "guard Assert-AdcsOutputPath $certDir",
            "foreach ($e in $cdp.entries)",
            "try",
            "guard if (-not @(_v $p 'certificaterevocationlist').Count) -> continue",
            "guard Assert-AdcsOutputPath (Join-Path $certDir $crlFile)",
        ),
    ),
    (
        "_v $p 'objectguid'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "try",
            "guard Assert-AdcsOutputPath $certDir",
            "foreach ($e in $cdp.entries)",
            "try",
            "guard if (-not @(_v $p 'certificaterevocationlist').Count) -> continue",
            "guard Assert-AdcsOutputPath (Join-Path $certDir $crlFile)",
        ),
    ),
    (
        "_v $p 'distinguishedname'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "try",
            "guard Assert-AdcsOutputPath $certDir",
            "foreach ($e in $cdp.entries)",
            "try",
            "guard if (-not @(_v $p 'certificaterevocationlist').Count) -> continue",
            "guard Assert-AdcsOutputPath (Join-Path $certDir $crlFile)",
        ),
    ),
    (
        "_markSearch 'certs' $aia @($aia.entries).Count $aiaObjects $aiaFailures $certIndex.Count",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "try",
            "guard Assert-AdcsOutputPath $certDir",
        ),
    ),
    (
        "_markSearch 'crls' $cdp @($cdp.entries).Count $cdpObjects $cdpFailures $crlIndex.Count",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "try",
            "guard Assert-AdcsOutputPath $certDir",
        ),
    ),
    (
        'Write-Warning "certs pass failed: $($_.Exception.Message)"',
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "catch []",
        ),
    ),
    (
        "Import-Module WebAdministration -ErrorAction Stop",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "try",
        ),
    ),
    (
        "Get-Website -ErrorAction Stop",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "if (-not $endpointsSkipped) after []",
            "try",
            "foreach ($site in (Get-Website -ErrorAction Stop))",
        ),
    ),
    (
        "Get-WebApplication -Site $site.Name -ErrorAction Stop",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "if (-not $endpointsSkipped) after []",
            "try",
            "foreach ($site in (Get-Website -ErrorAction Stop))",
            "foreach ($app in (Get-WebApplication -Site $site.Name -ErrorAction Stop))",
        ),
    ),
    (
        "_classifyApp $appPath",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "if (-not $endpointsSkipped) after []",
            "try",
            "foreach ($site in (Get-Website -ErrorAction Stop))",
            "foreach ($app in (Get-WebApplication -Site $site.Name -ErrorAction Stop))",
            "guard if (-not $appPath) -> continue",
        ),
    ),
    (
        "_tryRead { Get-WebConfigurationProperty -PSPath $ps -Filter $auth -Name enabled -ErrorAction Stop }",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "if (-not $endpointsSkipped) after []",
            "try",
            "foreach ($site in (Get-Website -ErrorAction Stop))",
            "foreach ($app in (Get-WebApplication -Site $site.Name -ErrorAction Stop))",
            "guard if (-not $appPath) -> continue",
            "guard if (-not $kind) -> continue",
        ),
    ),
    (
        "Get-WebConfigurationProperty -PSPath $ps -Filter $auth -Name enabled -ErrorAction Stop",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "if (-not $endpointsSkipped) after []",
            "try",
            "foreach ($site in (Get-Website -ErrorAction Stop))",
            "foreach ($app in (Get-WebApplication -Site $site.Name -ErrorAction Stop))",
            "guard if (-not $appPath) -> continue",
            "guard if (-not $kind) -> continue",
            "scriptblock of _tryRead",
        ),
    ),
    (
        "_tryRead { Get-WebConfigurationProperty -PSPath $ps -Filter $auth -Name 'extendedProtection.tokenChecking' -ErrorAction Stop }",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "if (-not $endpointsSkipped) after []",
            "try",
            "foreach ($site in (Get-Website -ErrorAction Stop))",
            "foreach ($app in (Get-WebApplication -Site $site.Name -ErrorAction Stop))",
            "guard if (-not $appPath) -> continue",
            "guard if (-not $kind) -> continue",
        ),
    ),
    (
        "Get-WebConfigurationProperty -PSPath $ps -Filter $auth -Name 'extendedProtection.tokenChecking' -ErrorAction Stop",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "if (-not $endpointsSkipped) after []",
            "try",
            "foreach ($site in (Get-Website -ErrorAction Stop))",
            "foreach ($app in (Get-WebApplication -Site $site.Name -ErrorAction Stop))",
            "guard if (-not $appPath) -> continue",
            "guard if (-not $kind) -> continue",
            "scriptblock of _tryRead",
        ),
    ),
    (
        "_tryRead { Get-WebConfigurationProperty -PSPath $ps -Filter 'system.webServer/security/access' -Name sslFlags -ErrorAction Stop }",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "if (-not $endpointsSkipped) after []",
            "try",
            "foreach ($site in (Get-Website -ErrorAction Stop))",
            "foreach ($app in (Get-WebApplication -Site $site.Name -ErrorAction Stop))",
            "guard if (-not $appPath) -> continue",
            "guard if (-not $kind) -> continue",
        ),
    ),
    (
        "Get-WebConfigurationProperty -PSPath $ps -Filter 'system.webServer/security/access' -Name sslFlags -ErrorAction Stop",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "if (-not $endpointsSkipped) after []",
            "try",
            "foreach ($site in (Get-Website -ErrorAction Stop))",
            "foreach ($app in (Get-WebApplication -Site $site.Name -ErrorAction Stop))",
            "guard if (-not $appPath) -> continue",
            "guard if (-not $kind) -> continue",
            "scriptblock of _tryRead",
        ),
    ),
    (
        '_tryRead { Get-WebConfigurationProperty -PSPath $ps -Filter "$auth/providers" -Name Collection -ErrorAction Stop }',
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "if (-not $endpointsSkipped) after []",
            "try",
            "foreach ($site in (Get-Website -ErrorAction Stop))",
            "foreach ($app in (Get-WebApplication -Site $site.Name -ErrorAction Stop))",
            "guard if (-not $appPath) -> continue",
            "guard if (-not $kind) -> continue",
        ),
    ),
    (
        'Get-WebConfigurationProperty -PSPath $ps -Filter "$auth/providers" -Name Collection -ErrorAction Stop',
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "if (-not $endpointsSkipped) after []",
            "try",
            "foreach ($site in (Get-Website -ErrorAction Stop))",
            "foreach ($app in (Get-WebApplication -Site $site.Name -ErrorAction Stop))",
            "guard if (-not $appPath) -> continue",
            "guard if (-not $kind) -> continue",
            "scriptblock of _tryRead",
        ),
    ),
    (
        "_list $provs",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "if (-not $endpointsSkipped) after []",
            "try",
            "foreach ($site in (Get-Website -ErrorAction Stop))",
            "foreach ($app in (Get-WebApplication -Site $site.Name -ErrorAction Stop))",
            "guard if (-not $appPath) -> continue",
            "guard if (-not $kind) -> continue",
        ),
    ),
    (
        "_epaToken $tc.value.Value",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "if (-not $endpointsSkipped) after []",
            "try",
            "foreach ($site in (Get-Website -ErrorAction Stop))",
            "foreach ($app in (Get-WebApplication -Site $site.Name -ErrorAction Stop))",
            "guard if (-not $appPath) -> continue",
            "guard if (-not $kind) -> continue",
            "if ($tc.ok) after []",
        ),
    ),
    (
        "Write-Warning $endpointsReason",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "if (-not $endpointsSkipped) after []",
            "catch []",
        ),
    ),
    (
        "_searchMarker $endpointsComplete $endpointsReason $webEndpoints.Count $webEndpoints.Count $iisFailures",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "if (-not $endpointsSkipped) after []",
        ),
    ),
    (
        "_search $domNc '(altSecurityIdentities=*)' @('altsecurityidentities', 'objectguid')",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "if ($CollectDcMapping) after []",
            "try",
        ),
    ),
    (
        "_entryProps $e",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "if ($CollectDcMapping) after []",
            "try",
            "foreach ($e in $ps14.entries)",
            "try",
        ),
    ),
    (
        "_requireSchema $p 'principal-mappings'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "if ($CollectDcMapping) after []",
            "try",
            "foreach ($e in $ps14.entries)",
            "try",
        ),
    ),
    (
        "_v $p 'distinguishedname'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "if ($CollectDcMapping) after []",
            "try",
            "foreach ($e in $ps14.entries)",
            "try",
        ),
    ),
    (
        "_guidHex @(_v $p 'objectguid')",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "if ($CollectDcMapping) after []",
            "try",
            "foreach ($e in $ps14.entries)",
            "try",
        ),
    ),
    (
        "_v $p 'objectguid'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "if ($CollectDcMapping) after []",
            "try",
            "foreach ($e in $ps14.entries)",
            "try",
        ),
    ),
    (
        "_v $p 'altsecurityidentities'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "if ($CollectDcMapping) after []",
            "try",
            "foreach ($e in $ps14.entries)",
            "try",
        ),
    ),
    (
        "ForEach-Object { [string]$_ }",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "if ($CollectDcMapping) after []",
            "try",
            "foreach ($e in $ps14.entries)",
            "try",
        ),
    ),
    (
        "_markSearch 'principal-mappings' $ps14 @($ps14.entries).Count $principalMappings.Count $psFailures",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "if ($CollectDcMapping) after []",
            "try",
        ),
    ),
    (
        'Write-Warning "esc14-altsecid failed: $($_.Exception.Message)"',
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "if ($CollectDcMapping) after []",
            "catch []",
        ),
    ),
    (
        "New-Object Management.Automation.PSCredential( $DcRegistryUser, (ConvertTo-SecureString $DcRegistryPass -AsPlainText -Force))",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "if ($CollectDcMapping) after []",
            "if ($DcRegistryUser) after []",
        ),
    ),
    (
        "ConvertTo-SecureString $DcRegistryPass -AsPlainText -Force",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "if ($CollectDcMapping) after []",
            "if ($DcRegistryUser) after []",
        ),
    ),
    (
        "_search $domNc '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))' @('dnshostname', 'objectguid')",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "if ($CollectDcMapping) after []",
        ),
    ),
    (
        "_entryProps $e",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "if ($CollectDcMapping) after []",
            "foreach ($e in $dcs.entries)",
            "try",
        ),
    ),
    (
        "_requireSchema $p 'dc-config'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "if ($CollectDcMapping) after []",
            "foreach ($e in $dcs.entries)",
            "try",
        ),
    ),
    (
        "_v $p 'dnshostname'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "if ($CollectDcMapping) after []",
            "foreach ($e in $dcs.entries)",
            "try",
        ),
    ),
    (
        "_guidHex @(_v $p 'objectguid')",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "if ($CollectDcMapping) after []",
            "foreach ($e in $dcs.entries)",
            "try",
        ),
    ),
    (
        "_v $p 'objectguid'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "if ($CollectDcMapping) after []",
            "foreach ($e in $dcs.entries)",
            "try",
        ),
    ),
    (
        "_v $p 'distinguishedname'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "if ($CollectDcMapping) after []",
            "foreach ($e in $dcs.entries)",
            "try",
            "if ($check.soft -contains 'dnshostname') after []",
        ),
    ),
    (
        'Write-Warning "esc10-dc-registry: $dcDns has no dNSHostName; its registry was not read"',
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "if ($CollectDcMapping) after []",
            "foreach ($e in $dcs.entries)",
            "try",
            "if ($check.soft -contains 'dnshostname') after []",
        ),
    ),
    (
        "Get-WmiObject -Namespace 'root\\default' -Class StdRegProv -List",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "if ($CollectDcMapping) after []",
            "foreach ($e in $dcs.entries)",
            "try",
            "else of [($check.soft -contains 'dnshostname')]",
            "try",
            "if ($dcDns.ToLower() -eq $localHost -or $dcDns.ToLower().StartsWith($localHost + '.')) after []",
        ),
    ),
    (
        "Get-WmiObject -ComputerName $dcDns -Credential $dcCred -Namespace 'root\\default' -Class StdRegProv -List",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "if ($CollectDcMapping) after []",
            "foreach ($e in $dcs.entries)",
            "try",
            "else of [($check.soft -contains 'dnshostname')]",
            "try",
            "if ($dcCred) after [($dcDns.ToLower() -eq $localHost -or $dcDns.ToLower().StartsWith($localHost + '.'))]",
        ),
    ),
    (
        "Get-WmiObject -ComputerName $dcDns -Namespace 'root\\default' -Class StdRegProv -List",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "if ($CollectDcMapping) after []",
            "foreach ($e in $dcs.entries)",
            "try",
            "else of [($check.soft -contains 'dnshostname')]",
            "try",
            "else of [($dcDns.ToLower() -eq $localHost -or $dcDns.ToLower().StartsWith($localHost + '.')) ; ($dcCred)]",
        ),
    ),
    (
        "_wmiDwordStatus $kdc",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "if ($CollectDcMapping) after []",
            "foreach ($e in $dcs.entries)",
            "try",
            "else of [($check.soft -contains 'dnshostname')]",
            "try",
            "switch (_wmiDwordStatus $kdc)",
        ),
    ),
    (
        "_decodeBinding ([int]$kdc.uValue)",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "if ($CollectDcMapping) after []",
            "foreach ($e in $dcs.entries)",
            "try",
            "else of [($check.soft -contains 'dnshostname')]",
            "try",
            "switch (_wmiDwordStatus $kdc)",
        ),
    ),
    (
        "_wmiDwordStatus $sch",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "if ($CollectDcMapping) after []",
            "foreach ($e in $dcs.entries)",
            "try",
            "else of [($check.soft -contains 'dnshostname')]",
            "try",
            "switch (_wmiDwordStatus $sch)",
        ),
    ),
    (
        "_decode ([int]$sch.uValue) $SCHANNEL_BITS",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "if ($CollectDcMapping) after []",
            "foreach ($e in $dcs.entries)",
            "try",
            "else of [($check.soft -contains 'dnshostname')]",
            "try",
            "switch (_wmiDwordStatus $sch)",
        ),
    ),
    (
        'Write-Warning "esc10-dc-registry $dcDns failed: $($_.Exception.Message)"',
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "if ($CollectDcMapping) after []",
            "foreach ($e in $dcs.entries)",
            "try",
            "else of [($check.soft -contains 'dnshostname')]",
            "catch []",
        ),
    ),
    (
        "_list $schannelMethods",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "if ($CollectDcMapping) after []",
            "foreach ($e in $dcs.entries)",
            "try",
        ),
    ),
    (
        "Where-Object { $null -eq $_.strong_certificate_binding_enforcement }",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "if ($CollectDcMapping) after []",
        ),
    ),
    (
        'Write-Warning "esc10-dc-registry: all $($dcConfigs.Count) DC(s) failed the registry read -- pass effectively skipped (WMI access denied? provide -DcRegistryUserB64/-DcRegistryPassB64 for SSH/double-hop)."',
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "if ($CollectDcMapping) after []",
            "if ($dcConfigs.Count -gt 0 -and $wmiFailures -eq $dcConfigs.Count) after []",
        ),
    ),
    (
        "_markSearch 'dc-config' $dcs @($dcs.entries).Count $dcConfigs.Count $dcFailures",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "if ($CollectDcMapping) after []",
            "else of [($dcConfigs.Count -gt 0 -and $wmiFailures -eq $dcConfigs.Count)]",
        ),
    ),
    (
        "Get-Date",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
        ),
    ),
    (
        "hostname",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
        ),
    ),
    (
        "_writeJson @($caConfig) 'ca-config.json'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
        ),
    ),
    (
        "_writeJson @($templates) 'templates.json'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
        ),
    ),
    (
        "_writeJson @($oids) 'oid-objects.json'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
        ),
    ),
    (
        "_writeJson @($pkiAcls) 'pki-acls.json'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
        ),
    ),
    (
        "_writeJson @($webEndpoints) 'web-endpoints.json'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
        ),
    ),
    (
        "_writeJson @($dcConfigs) 'dc-config.json'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
        ),
    ),
    (
        "_writeJson @($principalMappings) 'principal-mappings.json'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
        ),
    ),
    (
        "_writeJson $enrollmentServices 'enrollment-services.json'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
        ),
    ),
    (
        "_writeJson $caSecurity 'ca-security.json'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
        ),
    ),
    (
        "_writeJson ([ordered]@{ certs = @($certIndex); crls = @($crlIndex) }) 'certs/index.json'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "if (-not $certsSkipped) after []",
        ),
    ),
    (
        "_writeJson $manifest 'collector-manifest.json'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
        ),
    ),
    (
        "Write-Output (\"OK cas={0} templates={1} oids={2} pkiacls={3} endpoints={4} dcs={5} altsecid={6} certs={7} crls={8} editflags=[{9}] ca={10}\" -f ` $caConfig.Count, $templates.Count, $oids.Count, $pkiAcls.Count, $webEndpoints.Count, $dcConfigs.Count, $principalMappings.Count, $certIndex.Count, $crlIndex.Count, ((@($editFlags) | Where-Object { $_ }) -join ','), $caCommonName)",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
        ),
    ),
    (
        "Where-Object { $_ }",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
        ),
    ),
    (
        "[IO.File]::WriteAllText($outPath, $script:JS.Serialize($obj), (New-Object Text.UTF8Encoding($false)))",
        (
            "function _writeJson",
            "guard Assert-AdcsOutputPath $outParent",
            "guard Assert-AdcsOutputPath $outPath",
        ),
    ),
    ("$conn.Bind()", ("function _ldapConnection", "guard if ($script:LdapConn) -> return")),
    ("$conn.SendRequest($req)", ("function _search", "scriptblock in InvokeMemberExpressionAst")),
    (
        '[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey( "SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\$caName")',
        ("function _caSecurityRead", "scriptblock of _tryRead"),
    ),
    (
        "[IO.File]::WriteAllBytes((Join-Path $certDir $certFile), $der)",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "try",
            "guard Assert-AdcsOutputPath $certDir",
            "foreach ($e in $aia.entries)",
            "try",
            "foreach ($r in $rows)",
            "guard Assert-AdcsOutputPath (Join-Path $certDir $certFile)",
        ),
    ),
    (
        "[IO.File]::WriteAllBytes((Join-Path $certDir $crlFile), $der)",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "try",
            "guard Assert-AdcsOutputPath $certDir",
            "foreach ($e in $cdp.entries)",
            "try",
            "guard if (-not @(_v $p 'certificaterevocationlist').Count) -> continue",
            "guard Assert-AdcsOutputPath (Join-Path $certDir $crlFile)",
        ),
    ),
    (
        "$reg.GetDWORDValue($HKLM, 'SYSTEM\\CurrentControlSet\\Services\\Kdc', 'StrongCertificateBindingEnforcement')",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "if ($CollectDcMapping) after []",
            "foreach ($e in $dcs.entries)",
            "try",
            "else of [($check.soft -contains 'dnshostname')]",
            "try",
        ),
    ),
    (
        "$reg.GetDWORDValue($HKLM, 'SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL', 'CertificateMappingMethods')",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "if ($CollectDcMapping) after []",
            "foreach ($e in $dcs.entries)",
            "try",
            "else of [($check.soft -contains 'dnshostname')]",
            "try",
        ),
    ),
)


# --- dataflow helpers ---------------------------------------------------------------

_VARIABLE = re.compile(r"\$(?:\{([^}]+)\}|((?:[A-Za-z_][A-Za-z0-9_]*:)?[A-Za-z_][A-Za-z0-9_]*))")
_SCOPE_PREFIXES = ("script:", "local:", "private:", "global:", "variable:", "using:")


def _bare_var(name: str) -> str:
    low = name.lower()
    for prefix in _SCOPE_PREFIXES:
        if low.startswith(prefix):
            return low[len(prefix) :]
    return low


def _vars_in(text: str | None) -> set[str]:
    return {_bare_var(a or b) for a, b in _VARIABLE.findall(text or "")}


# A variable's bindings are keyed per SCOPE ("<scope>::<name>"), so the same
# name in two scopes is two separate pins (e.g. $s declared as _b64's parameter
# is distinct from the DirectorySearcher $s assigned in the script). A binding
# is (kind, value); the kinds are listed in _bindings_by_var.
Binding = tuple[str, str]


def _skey(scope: str, name: str) -> str:
    return f"{scope}::{name}"


def _bindings_by_var(dump: dict[str, Any]) -> dict[str, list[Binding]]:
    """Every way each (scope, variable) acquires a value, as (kind, value):

    ``assign <Op>`` (any operator; value = right-hand side), ``incdec <Token>``,
    ``foreach`` (value = source), ``parameter`` (value = the whole declaration:
    attributes, type, default), ``arg`` / ``splat`` (a call-site argument of a
    local function; the scope is the callee, where the parameter lives), and
    ``member <Op>`` / ``index <Op>`` (a property / index write on the variable's
    object; value = ``target = rhs``). Names are lower-cased with any scope
    qualifier stripped. ``$null = ...`` discards output and binds nothing.
    """
    out: dict[str, list[Binding]] = {}
    for b in dump["bindings"]:
        name = b["variable"]
        if name is None or b["kind"] == "common-parameter":
            continue
        if name == "null" and b["kind"] == "assign Equals":
            continue
        out.setdefault(_skey(b["scope"], name), []).append((b["kind"], b["value"]))
    for m in dump["member_assignments"]:
        if m["receiver_root"]:
            out.setdefault(_skey(m["scope"], m["receiver_root"]), []).append(
                (f"{m['kind']} {m['operator']}", f"{m['target']} = {m['value']}")
            )
    return out


# PowerShell resolves command, function, method and parameter names case
# insensitively, so every comparison against a fixed name goes through a
# lower-cased mirror. `_cf` is the one canonicalization point; the case
# meta-test (test_verdict_is_case_insensitive) re-runs every APPEND-style
# regression snippet with its names' casing flipped and requires identical
# verdicts. Replacement / multi-edit probes are not name-swapped; they rely on
# the same single canonicalization point.
def _cf(name: str | None) -> str:
    return (name or "").lower()


_ALLOWED_COMMANDS_CF = {k.lower(): v for k, v in ALLOWED_COMMANDS.items()}
_ALLOWED_INSTANCE_CF = {k.lower(): v for k, v in ALLOWED_INSTANCE.items()}
_ALLOWED_STATIC_CF = {(t.lower(), m.lower()) for t, m in ALLOWED_STATIC}
_ALLOWED_WRITE_TARGETS_CF = {k.lower(): v for k, v in ALLOWED_WRITE_TARGETS.items()}
_FORBIDDEN_COMMANDS_CF = {c.lower() for c in FORBIDDEN_COMMANDS}
_GUARDED_COMMANDS_CF = {c.lower() for c in _GUARDED_COMMANDS}
_GUARDED_STATIC_CF = {(t.lower(), m.lower()) for t, m in _GUARDED_STATIC}
_GUARDED_INSTANCE_CF = {m.lower() for m in _GUARDED_INSTANCE}
_INSTANCE_RECEIVERS_CF = {k.lower(): v for k, v in INSTANCE_RECEIVERS.items()}


def _member_call_key(m: dict[str, Any]) -> tuple[str, ...]:
    return (_canon(m["target"]), _cf(m["member"]), *(_canon(a) for a in m["args"]))


def _guarded(dump: dict[str, Any]) -> list[tuple[str, dict[str, Any], list[str]]]:
    """(name, entry, input texts) for every pinned operation: EVERY command
    invocation (its exact text, count and control-flow context are pinned in
    GUARDED_OPS, whatever the command), plus the write/exec/remote/lifetime .NET
    calls. Inputs are every argument (and the invoked variable of a dynamic
    call): each variable in them is binding-pinned."""
    found: list[tuple[str, dict[str, Any], list[str]]] = []
    for c in dump["commands"]:
        inputs = [e["text"] for e in c["elements"]]
        if not c["name"] or not c["bareword"]:
            inputs = [c.get("head", ""), *inputs]
        found.append((c["name"] or c.get("head", ""), c, inputs))
    for m in dump["members"]:
        if m["static"]:
            if (_cf(m["target"]), _cf(m["member"])) not in _GUARDED_STATIC_CF:
                continue
        elif _cf(m["member"]) not in _GUARDED_INSTANCE_CF:
            continue
        found.append((m["member"], m, list(m["args"])))
    return found


def _guarded_ops(dump: dict[str, Any]) -> list[tuple[str, tuple[str, ...]]]:
    return [(entry["text"], tuple(entry["context"])) for _, entry, _ in _guarded(dump)]


def _resolve(bindings: dict[str, list[Binding]], name: str, scope: str) -> set[str]:
    """The binding key(s) a reference to $name in *scope* resolves to.

    PowerShell resolves dynamically: a name bound in the current scope wins,
    else the script (enclosing) scope. When neither is bound we do not know
    which scope applies, so every scope that binds the name is required (the
    safe over-approximation). A nested scope (``<scope>/{}``) falls back to its
    function/script parent before the script.
    """
    if _skey(scope, name) in bindings:
        return {_skey(scope, name)}
    parent = scope.rsplit("/", 1)[0] if scope.endswith("/{}") else scope
    if parent != scope and _skey(parent, name) in bindings:
        return {_skey(parent, name)}
    if _skey("<script>", name) in bindings:
        return {_skey("<script>", name)}
    hits = {k for k in bindings if k.split("::", 1)[1] == name}
    return hits


_LOCAL_CALL = re.compile(r"(?<![\w$.-])(_[A-Za-z][A-Za-z0-9]*)")


def _required_vars(dump: dict[str, Any]) -> dict[str, str]:
    """(scope, variable) keys whose every binding must be pinned, with the first
    reason. Roots: write/exec/load/remote-operation inputs, receivers of every
    instance call and property / index write, each resolved in the operation's
    own scope; then the closure: every variable read by any binding of a
    required key, and the parameters of any local function such a binding calls.
    """
    bindings = _bindings_by_var(dump)
    params = {f["name"].lower(): (f["name"], f["params"]) for f in dump["function_params"]}
    reasons: dict[str, str] = {}
    pending: list[str] = []

    def need(name: str | None, scope: str, why: str) -> None:
        if not name:
            return
        for key in _resolve(bindings, name, scope):
            if key not in reasons:
                reasons[key] = why
                pending.append(key)

    for name, entry, inputs in _guarded(dump):
        for text in inputs:
            for var in sorted(_vars_in(text)):
                need(var, entry["scope"], f"input of {name}: {entry['text']}")
    for m in dump["members"]:
        if not m["static"]:
            need(m["receiver_root"], m["scope"], f"receiver of .{m['member']}()")
        # Every .NET call is pinned (PINNED_MEMBER_CALLS): its arguments' variables too.
        for text in m["args"]:
            for var in sorted(_vars_in(text)):
                need(var, m["scope"], f"argument of .{m['member']}(): {m['text']}")
    for cond in dump.get("conditions", []):
        for var in sorted(_vars_in(cond["text"])):
            need(var, cond["scope"], f"condition {cond['text']}")
    for m in dump["member_assignments"]:
        need(m["receiver_root"], m["scope"], f"{m['kind']} write {m['target']}")
    while pending:
        key = pending.pop()
        scope = key.split("::", 1)[0]
        for _kind, value in sorted(bindings.get(key, [])):
            for ref in sorted(_vars_in(value)):
                need(ref, scope, f"read by a binding of ${key}")
            # A binding that calls a local function also depends on that
            # function's parameters (its body is pinned separately, below).
            for fn in _LOCAL_CALL.findall(value):
                real_name, fn_params = params.get(fn.lower(), (fn, []))
                for param in fn_params:
                    need(param, real_name, f"parameter of {fn}, called by a binding of ${key}")
    return {k: why for k, why in reasons.items() if k.split("::", 1)[1] not in _AUTO_READ_OK}


# Exact per-function body pins: the normalized-AST digest of each local
# function's whole subtree (its name and every node with every property, in
# source order). A change to any helper body — its emitted/return value, a
# constant, a reordered statement — changes its digest and fails
# test_collector_body_pins, so it needs a deliberate edit of this table on TOP
# of regenerating the golden. The regeneration script never writes this table
# (test_regen_does_not_touch_pin_tables), so a helper-body change cannot be
# laundered by a regenerate. Comments/whitespace are covered by the golden
# source digest, not here.
def _row_index_paths(rows: list[list[Any]]) -> list[tuple[int, ...]]:
    """Pre-order child-index path of every AST row (a stable structural id)."""
    paths: list[tuple[int, ...]] = []
    path: list[int] = []
    for row in rows:
        d = int(row[0])
        if d == len(path):
            path.append(0)
        else:
            path = path[: d + 1]
            path[d] += 1
        paths.append(tuple(path))
    return paths


def _subtree_digest(rows: list[list[Any]], i: int) -> str:
    depth = rows[i][0]
    sub = [rows[i]]
    j = i + 1
    while j < len(rows) and rows[j][0] > depth:
        sub.append(rows[j])
        j += 1
    return hashlib.sha256("\n".join(_ast_line(r) for r in sub).encode("utf-8")).hexdigest()


# Children of an ancestor that give a statement its control / declaration
# context (an enclosing if / loop / switch condition, a foreach variable, a
# catch type list, a function's or scriptblock's param block, parameters and
# attributes). Their whole subtrees enter the digest of every statement below.
_CONTEXT_ROLES = frozenset(
    {
        "Clauses.Condition",
        "Condition",
        "Variable",
        "Initializer",
        "Iterator",
        "CatchTypes",
        "ParamBlock",
        "Parameters",
        "Attributes",
        "DynamicParamBlock",
        "Clauses.Pattern",
        "Redirections",
        "CatchClauses",
        "Finally",
    }
)


def _statement_digests(dump: dict[str, Any]) -> dict[str, str]:
    """Digest of EVERY statement (each top-level statement and each statement in
    every function / scriptblock body), keyed by its structural index path.

    Each digest covers the statement's CONTEXT as well as its own subtree: for
    every ancestor from the root down to the statement, the ancestor's own row
    (node type, the role it fills in its parent and every non-child property --
    e.g. NamedBlockAst.BlockKind / Unnamed, FunctionDefinitionAst.Name,
    ForEach / Switch flags), the child index taken, and the full subtrees of the
    ancestor's context children (_CONTEXT_ROLES). So moving a statement,
    re-wrapping it in a begin/process/end/clean block, renaming its function or
    changing an enclosing condition changes its digest, not only an edit to the
    statement itself. A function definition is itself a statement (subsuming
    the former LOCAL_FUNCTION_BODIES)."""
    rows = dump["ast_rows"]
    paths = _row_index_paths(rows)
    n = len(rows)
    lines = [_ast_line(r) for r in rows]
    ends = [0] * n
    for i in range(n - 1, -1, -1):
        j = i + 1
        while j < n and rows[j][0] > rows[i][0]:
            j = ends[j]
        ends[i] = j
    sub_hash: dict[int, str] = {}

    def subtree(i: int) -> str:
        if i not in sub_hash:
            sub_hash[i] = hashlib.sha256("\n".join(lines[i : ends[i]]).encode("utf-8")).hexdigest()
        return sub_hash[i]

    out: dict[str, str] = {}
    stack: list[int] = []  # indices of the ancestors of row i
    for i, row in enumerate(rows):
        depth = row[0]
        while stack and rows[stack[-1]][0] >= depth:
            stack.pop()
        if row[1] == "Statements":
            parts: list[str] = []
            for a in stack:
                parts.append(f"A{paths[a][-1]}|{lines[a].strip()}")
                child_depth = rows[a][0] + 1
                j = a + 1
                while j < ends[a]:
                    if rows[j][0] == child_depth and rows[j][1] in _CONTEXT_ROLES:
                        parts.append(f"C|{rows[j][1]}|{subtree(j)}")
                    j = ends[j] if rows[j][0] >= child_depth else j + 1
            parts.append(f"S{paths[i][-1]}|{subtree(i)}")
            key = ".".join(str(x) for x in paths[i])
            out[key] = hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()
        stack.append(i)
    return out


def _statement_digest_labels(dump: dict[str, Any]) -> dict[str, str]:
    """key -> a human hint (the statement's AST type), for the candidate printer."""
    rows = dump["ast_rows"]
    paths = _row_index_paths(rows)
    return {
        ".".join(str(n) for n in paths[i]): row[2]
        for i, row in enumerate(rows)
        if row[1] == "Statements"
    }


def _structure_violations(dump: dict[str, Any]) -> list[str]:
    """Whole-tree screens, local functions, and unpinnable / engine bindings."""
    out: list[str] = []
    if dump["unsupported_nodes"]:
        out.append(f"[ast] nodes the serializer does not cover: {dump['unsupported_nodes']}")
    extra = sorted(set(dump["node_types"]) - ALLOWED_NODE_TYPES)
    if extra:
        out.append(f"[ast] AST node types outside the closed set: {extra}")
    if dump["script_requirements"]:
        out.append("[ast] #Requires is not allowed (it loads modules / changes the engine)")
    if dump["background_pipelines"]:
        out.append(f"[ast] background jobs are not allowed: {dump['background_pipelines']}")
    for sf in dump.get("statement_flags", []):
        if sf["flags"] != "None":
            out.append(
                f"[ast] {sf['scope']}: {sf['kind']} -{sf['flags']} flag is not allowed "
                f"(switch -File / -Regex / foreach -Parallel): {sf['condition']!r}"
            )
    if dump["source_non_ascii_bytes"]:
        out.append(f"[ast] source has {dump['source_non_ascii_bytes']} non-ASCII bytes")

    names = [f["name"] for f in dump["functions"]]
    if len({n.lower() for n in names}) != len(names):
        out.append(f"[local-function] a function is defined twice: {names}")
    if tuple(names) != LOCAL_FUNCTIONS:
        out.append(
            "[local-function] defined functions differ from LOCAL_FUNCTIONS: "
            f"extra {sorted(set(names) - set(LOCAL_FUNCTIONS))}, "
            f"missing {sorted(set(LOCAL_FUNCTIONS) - set(names))}, or reordered"
        )
    for f in dump["function_params"]:
        if f["pipeline_params"]:
            out.append(f"[local-function] {f['name']}: pipeline-bound parameters are not allowed")

    specials: list[tuple[str, Binding]] = []
    for b in dump["bindings"]:
        name, kind = b["variable"], b["kind"]
        if name is None or kind == "common-parameter":
            continue
        where = f"[binding] {b['scope']}: {b.get('target') or name}"
        if b["qualifier"] not in _ALLOWED_QUALIFIERS:
            out.append(
                f"{where}: provider-drive / {b['qualifier']}-scope write ({kind}) is not allowed"
            )
            continue
        if kind == "splat":
            out.append(f"{where}: splatting into a local function is not allowed")
            continue
        if kind == "arg" and (name == "args" or name.startswith("-")):
            out.append(f"{where}: call-site argument {b['value']!r} binds no declared parameter")
            continue
        if name == "null" and kind == "assign Equals":
            continue  # `$null = expr` discards output
        if name in _SPECIAL_VARIABLES or name.endswith("preference"):
            specials.append((name, (kind, b["scope"], b["value"])))
    for name, binding in specials:
        if (name, binding) not in SPECIAL_BINDINGS:
            out.append(
                f"[binding] write to automatic/preference variable ${name} {binding} is not allowed"
            )
    for ref in dump["variable_refs"]:
        if ref["name"] in FORBIDDEN_VARIABLE_REFS:
            out.append(f"[binding] {ref['text']} may not be referenced")
        if ref["qualifier"] == "drive":
            out.append(f"[binding] provider-drive variable {ref['text']} is not allowed")
        if ref["splatted"]:
            out.append(f"[binding] splatted variable {ref['text']} is not allowed")
    return out


def _pinning_violations(dump: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for m in dump["members"]:
        if m["static"] or _cf(m["member"]) not in _ALLOWED_INSTANCE_CF:
            continue
        permitted = _INSTANCE_RECEIVERS_CF.get(_cf(m["member"]), frozenset())
        if (m["receiver_root"] or "") not in permitted:
            out.append(
                f"[receiver] {m['scope']}: {m['text']}: .{m['member']}() on receiver "
                f"{m['receiver_root']!r} (allowed: {sorted(permitted)})"
            )
    required = _required_vars(dump)
    bindings = _bindings_by_var(dump)
    # An explicitly scope-qualified write ($script:/$global:/...) to a confined
    # name, whose resulting key is not the pinned one, deliberately reaches an
    # outer scope to rebind it. (An unqualified same-named local in another
    # function is a genuinely separate variable — _b64's $s vs the searcher $s —
    # and, being per-scope, is pinned/required on its own if it reaches a sink.)
    confined = {k.split("::", 1)[1] for k in PINNED_BINDINGS}
    for b in dump["bindings"]:
        name = b["variable"]
        if (
            name in confined
            and b["qualifier"] in {"script", "global", "local", "private", "variable"}
            and _skey(b["scope"], name) not in PINNED_BINDINGS
        ):
            out.append(
                f"[pinned-binding] {b['scope']}: ${b['qualifier']}:{name} "
                "rebinds a confined variable in an unexpected scope"
            )
    for var in sorted(set(required) - set(PINNED_BINDINGS)):
        out.append(f"[pinned-binding] ${var} must be pinned ({required[var]})")
    for var in sorted(set(PINNED_BINDINGS) - set(required)):
        out.append(
            f"[pinned-binding] stale pin ${var}: no longer a write/exec input, receiver or dependency"
        )
    for var, expected in PINNED_BINDINGS.items():
        got = sorted(bindings.get(var, []))
        if got != sorted(expected):
            extra = sorted((Counter(got) - Counter(expected)).elements())
            missing = sorted((Counter(expected) - Counter(got)).elements())
            out.append(
                f"[pinned-binding] ${var} must be bound exactly as pinned: "
                f"unexpected {extra}, missing {missing}"
            )
    calls = Counter(_member_call_key(m) for m in dump["members"])
    pinned_calls = Counter(PINNED_MEMBER_CALLS)
    for key in sorted((calls - pinned_calls).elements()):
        out.append(f"[member-call] unexpected .NET call {key}")
    for key in sorted((pinned_calls - calls).elements()):
        out.append(f"[member-call] missing .NET call {key}")
    actual = Counter(_guarded_ops(dump))
    allowed = Counter(GUARDED_OPS)
    for op, ctx in sorted((actual - allowed).elements()):
        out.append(f"[guarded-op] unexpected: {op} @ {' > '.join(ctx)}")
    for op, ctx in sorted((allowed - actual).elements()):
        out.append(f"[guarded-op] missing: {op} @ {' > '.join(ctx)}")
    return out


def _secret_closure(dump: dict[str, Any]) -> set[str]:
    """Scoped keys ("<scope>::<name>") of every credential-bearing variable:
    the credential parameters, and every key with a binding (assignment,
    call-site argument, foreach, property write, ...) that reads a secret key
    (resolved per scope, as the binding pins resolve)."""
    bindings = _bindings_by_var(dump)
    secret = {_skey(_SCRIPT, n) for n in SECRET_SEEDS}
    changed = True
    while changed:
        changed = False
        for key, values in bindings.items():
            if key in secret:
                continue
            scope = key.split("::", 1)[0]
            for _kind, value in values:
                if any(
                    _resolve(bindings, ref, scope) & secret and not _only_call_receiver(value, ref)
                    for ref in _vars_in(value)
                ):
                    secret.add(key)
                    changed = True
                    break
    return secret


def _only_call_receiver(value: str, name: str) -> bool:
    """True when every occurrence of $name in *value* is the receiver of a
    method call ($reg.GetDWORDValue(...)): the call's result is data read
    through the credentialed handle, not the credential itself."""
    occurrences = list(
        re.finditer(r"\$(?:[A-Za-z]+:)?\{?" + re.escape(name) + r"\}?(?![A-Za-z0-9_])", value, re.I)
    )
    return bool(occurrences) and all(
        re.match(r"(?:\.[A-Za-z_]\w*)*\.[A-Za-z_]\w*\s*\(", value[m.end() :]) for m in occurrences
    )


def _secret_uses(dump: dict[str, Any], keys: set[str]) -> dict[str, list[tuple[str, str]]]:
    """Every reference to a secret key, as (scope, enclosing statement)."""
    bindings = _bindings_by_var(dump)
    out: dict[str, list[tuple[str, str]]] = {}
    for u in dump.get("variable_uses", []):
        for key in _resolve(bindings, u["name"], u["scope"]) & keys:
            out.setdefault(key, []).append((u["scope"], u["statement"]))
    return out


def _extra_violations(dump: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for t in dump["static_types"]:
        if _NEVER_TYPES.search(t):
            out.append(f"[type] [{t}] is never admitted (LDAP write / non-read transport)")
    # REMOTE_LITERALS: every string literal / expandable string ANYWHERE in the
    # script (a switch -File / foreach input, a here-string, a command or .NET
    # argument, a binding value) that looks like a UNC path, a `//host`
    # authority, a `\\?\` / `\\.\` device path or a `scheme://` URL is
    # refused. The only exemptions are REMOTE_LITERAL_EXEMPTIONS (exact texts),
    # reviewed and committed.
    remote_texts = [(lit["scope"], lit["text"]) for lit in dump.get("string_literals", [])]
    remote_texts += [("<ref>", r["text"]) for r in dump["variable_refs"]]
    remote_texts += [(b["scope"], b.get("target") or "") for b in dump["bindings"]]
    for scope, text in remote_texts:
        if not text or text in REMOTE_LITERAL_EXEMPTIONS:
            continue
        if _UNC_OR_URL.search(text):
            out.append(f"[unc-url] {scope}: {text!r} looks like a UNC path, //host or URL")
    secret = _secret_closure(dump)
    if secret != set(SECRET_VARIABLES):
        out.append(
            f"[secret] credential-bearing variables changed: new {sorted(secret - set(SECRET_VARIABLES))}, "
            f"gone {sorted(set(SECRET_VARIABLES) - secret)}"
        )
    uses = _secret_uses(dump, secret | set(SECRET_VARIABLES))
    for name in sorted(set(uses) | set(SECRET_USES)):
        got = Counter(uses.get(name, []))
        want = Counter(SECRET_USES.get(name, []))
        for scope, stmt in sorted((got - want).elements()):
            out.append(f"[secret] {scope}: ${name} used at an unpinned site: {stmt}")
        for scope, stmt in sorted((want - got).elements()):
            out.append(f"[secret] ${name}: pinned use missing: {scope}: {stmt}")
    if dump.get("header_sha256") != HEADER_SHA256:
        out.append(
            f"[header] the script header / param block changed ({dump.get('header_sha256')}); "
            "edit HEADER_SHA256 deliberately"
        )
    return out


# WRITE GUARD (product defence in depth). The collector resolves every file /
# directory it is about to create with Assert-AdcsOutputPath, which throws
# unless the full path is inside $OutDir (case-insensitive, separator-
# normalized, no UNC / device form, no junction or symlink on the way). Every
# write sink -- each New-Item -Path X and each [IO.File]::WriteAll*(X, ...) --
# must have `guard Assert-AdcsOutputPath X` (the same target text) in its
# control-flow context, i.e. an earlier statement on every path to the sink.
# GUARDED_OPS pins the same contexts exactly; this rule states the intent so a
# re-pin cannot drop a guard silently. The guard's own body is pinned by
# STATEMENT_DIGESTS; rebinding X between guard and sink changes PINNED_BINDINGS.
WRITE_GUARD = "Assert-AdcsOutputPath"


def _write_sinks(dump: dict[str, Any]) -> list[tuple[str, str, str | None, list[str]]]:
    """(scope, text, target or None if unresolvable, context) for every write sink."""
    sinks: list[tuple[str, str, str | None, list[str]]] = []
    for c in dump["commands"]:
        if not c["name"] or _cf(c["name"]) != "new-item":
            continue
        target = None
        elements = c["elements"]
        for i, e in enumerate(elements):
            if e["parameter"] and _cf(e["parameter"]) == "path" and i + 1 < len(elements):
                if elements[i + 1]["parameter"] is None and ":" not in e["text"]:
                    target = elements[i + 1]["text"]
        sinks.append((c["scope"], c["text"], target, list(c["context"])))
    for m in dump["members"]:
        if m["static"] and _cf(m["member"]) in _ALLOWED_WRITE_TARGETS_CF:
            target = m["args"][0] if m["args"] else None
            sinks.append((m["scope"], m["text"], target, list(m.get("context") or [])))
    return sinks


def _write_guard_violations(dump: dict[str, Any]) -> list[str]:
    out = []
    for scope, text, target, context in _write_sinks(dump):
        if target is None:
            out.append(f"[write-guard] {scope}: {text}: write target not resolvable")
            continue
        # Command names are case-insensitive, and so are Windows paths.
        want = _canon(f"guard {WRITE_GUARD} {target}").casefold()
        if not any(_canon(x).casefold() == want for x in context):
            out.append(f"[write-guard] {scope}: {text}: not preceded by {WRITE_GUARD} {target}")
    return out


def violations(dump: dict[str, Any], source: str = "") -> list[str]:
    """Every semantic violation in a parsed script (empty = admitted by the floor).

    Each message starts with the [check] that raised it.
    """
    out = [f"[parse] {e}" for e in dump["parse_errors"]]
    defined = {f["name"].lower() for f in dump["functions"]}
    bound = {b["variable"] for b in dump["bindings"] if b["variable"]}
    for c in dump["commands"]:
        where = f"{c['scope']}: {c['text']}"
        name = c["name"]
        if name is None or not c["bareword"]:
            if not (
                c["operator"] == "Ampersand"
                and (c["scope"], _canon(c["text"]))
                in {(sc, _canon(t)) for sc, t in DYNAMIC_INVOCATIONS}
            ):
                out.append(f"[dynamic] {where}: command name computed at runtime")
            continue
        if c["operator"] == "Dot":
            # Still checked against the allowlists below.
            out.append(f"[dynamic] {where}: dot-sourced invocation runs in the caller's scope")
        if name.lower() in defined:
            if name.lower() == "_writejson":
                vals = [e["text"] for e in c["elements"] if e["parameter"] is None]
                if len(vals) != 2 or not _SAFE_OUTPUT_NAME.fullmatch(vals[1]):
                    out.append(f"[write-path] {where}: _writeJson must take a plain relative name")
            # Named arguments must resolve to a declared parameter (an unresolved
            # one is a [binding] violation); every call-site binding is pinned.
            continue
        check = _ALLOWED_COMMANDS_CF.get(_cf(name))
        if check is None or _cf(name) in _FORBIDDEN_COMMANDS_CF:
            out.append(f"[command] {where}: command {name!r} is not allowlisted")
            continue
        reason = check(c)
        if reason:
            tag = "[write-path]" if _cf(name) == "new-item" else "[command]"
            out.append(f"{tag} {where}: {reason}")
        # Cmdlet metadata resolves prefixes (-Pi) and aliases (-pv/-ov/-ev).
        written = set(c.get("bound_params") or ()) & _VARIABLE_WRITING_PARAMS
        if written:
            out.append(f"[common-parameter] {where}: writes a variable via {sorted(written)}")
    for b in dump["bindings"]:
        if b["kind"] == "common-parameter":
            out.append(f"[common-parameter] {b['scope']}: {b['value']} writes {b['target']!r}")
    for m in dump["members"]:
        where = f"{m['scope']}: {m['text']}"
        if not m["constant_member"]:
            out.append(f"[dynamic] {where}: dynamic member invocation")
            continue
        if m["static"]:
            if (_cf(m["target"]), _cf(m["member"])) not in _ALLOWED_STATIC_CF:
                out.append(f"[member] {where}: static {m['target']}::{m['member']} not allowlisted")
            elif _cf(m["member"]) in _ALLOWED_WRITE_TARGETS_CF and (
                not m["args"]
                or _canon(m["args"][0])
                not in {_canon(t) for t in _ALLOWED_WRITE_TARGETS_CF[_cf(m["member"])]}
            ):
                out.append(f"[write-path] {where}: file write outside the output directory")
            continue
        root = m["receiver_root"]
        if root is not None and root not in bound and root not in _AUTOMATIC_RECEIVERS:
            out.append(f"[receiver] {where}: receiver ${root} has no binding in the script")
        check = _ALLOWED_INSTANCE_CF.get(_cf(m["member"]))
        if check is None:
            out.append(f"[member] {where}: method {m['member']!r} is not allowlisted")
            continue
        reason = check(m)
        if reason:
            out.append(f"[member] {where}: {reason}")
    for r in dump["redirections"]:
        if (r["kind"], r["stream"], r["location"], r["append"]) not in ALLOWED_REDIRECTIONS:
            out.append(f"[redirection] {r['scope']}: {r['text']!r} is not allowed")
    for b in dump["bindings"]:
        if b["kind"].startswith("destructure"):
            out.append(
                f"[binding] {b['scope']}: destructuring assignment {b['target']!r} binds "
                f"${b['variable']}"
            )
        elif b["kind"] == "assign-unrecognised-target":
            out.append(f"[binding] {b['scope']}: unrecognised assignment target {b['target']!r}")
    out.extend(_member_assignment_violations(dump))
    for t in dump["static_types"]:
        if t not in ALLOWED_STATIC_TYPES:
            out.append(f"[type] [{t}] is not allowlisted")
    out.extend(_structure_violations(dump))
    out.extend(_pinning_violations(dump))
    out.extend(_extra_violations(dump))
    out.extend(_write_guard_violations(dump))
    actual = _statement_digests(dump)
    for key in sorted(set(actual) | set(STATEMENT_DIGESTS)):
        if actual.get(key) != STATEMENT_DIGESTS.get(key):
            out.append(
                f"[statement-digest] statement {key} changed (digest "
                f"{actual.get(key)} != pinned {STATEMENT_DIGESTS.get(key)}); "
                "edit STATEMENT_DIGESTS deliberately (print_pin_candidates.py prints it)"
            )
    return out


# --- golden syntax-tree inventory (closed world) -----------------------------------
# tests/collector/collector-inventory.json records (1) ``ast``: an
# order-preserving serialization of the WHOLE syntax tree, one line per node,
# pre-order, indented by depth, naming the property the node fills in its
# parent and every semantically relevant scalar; and (2) ``source_sha256``: a
# digest of the source with only CRLF->LF normalized, so comments and
# whitespace (which the AST omits but a script can observe) are covered too.
# Regenerate (only possible when violations() is empty):
#   .venv/bin/python tests/collector/regen_inventory.py
INVENTORY = ROOT / "tests" / "collector" / "collector-inventory.json"


def _ast_line(row: list[Any]) -> str:
    depth, role, kind, attrs = row[0], row[1], row[2], row[3]
    text = "  " * int(depth) + f"{role}: {kind}"
    for key, value in attrs:
        text += f" {key}={json.dumps(value, ensure_ascii=True)}"
    if len(row) > 4:  # an UNSUPPORTED node also carries its source text
        text += f" text={json.dumps(row[4], ensure_ascii=True)}"
    return text


def inventory(dump: dict[str, Any]) -> dict[str, Any]:
    return {
        "source_sha256": dump["source_sha256"],
        "parse_errors": dump["parse_errors"],
        "ast": [_ast_line(row) for row in dump["ast_rows"]],
    }


def render_inventory(dump: dict[str, Any]) -> str:
    return json.dumps(inventory(dump), indent=1, sort_keys=True, ensure_ascii=True) + "\n"


def golden_ast() -> list[str]:
    ast: list[str] = json.loads(INVENTORY.read_text(encoding="utf-8"))["ast"]
    return ast


def tree_changed(dump: dict[str, Any]) -> bool:
    """True when the edit changed the syntax tree itself (not only the digest)."""
    return inventory(dump)["ast"] != golden_ast()


# --- tests -------------------------------------------------------------------------


def _collector_text() -> str:
    return COLLECTOR.read_bytes().decode("utf-8").replace("\r\n", "\n")


def test_collector_is_read_only() -> None:
    dump = _dump(COLLECTOR)
    found = violations(dump, COLLECTOR.read_text(encoding="utf-8"))
    assert found == [], "collector read-only allowlist violations:\n" + "\n".join(found)
    # Sanity: the dump actually saw the collector's surface.
    names = {c["name"] for c in dump["commands"]}
    assert {"certutil", "Get-WmiObject", "New-Object"} <= names


def test_collector_matches_golden_inventory() -> None:
    """Closed world: the collector's whole syntax tree and source are pinned."""
    current = render_inventory(_dump(COLLECTOR))
    golden = INVENTORY.read_text(encoding="utf-8")
    if current != golden:
        import difflib

        diff = "\n".join(
            list(
                difflib.unified_diff(
                    golden.splitlines(), current.splitlines(), "committed", "current", lineterm=""
                )
            )[:120]
        )
        raise AssertionError(
            "the collector's syntax-tree inventory changed; review the change and, if it is "
            "read-only, regenerate with: .venv/bin/python tests/collector/regen_inventory.py\n"
            + diff
        )


def test_regeneration_refuses_a_failing_collector(tmp_path: Path) -> None:
    bad = tmp_path / "bad.ps1"
    # A second script-scope binding of a pinned write root ($certDir).
    bad.write_text(_collector_text() + "\n$certDir = 'C:\\evil'\n", encoding="utf-8")
    out = tmp_path / "inv.json"
    script = ROOT / "tests" / "collector" / "regen_inventory.py"
    proc = subprocess.run(
        [sys.executable, str(script), "--collector", str(bad), "--out", str(out)],
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert proc.returncode == 1, proc.stderr
    assert "refusing to write" in proc.stderr and "[pinned-binding]" in proc.stderr
    assert not out.exists()


def test_regen_does_not_touch_pin_tables(tmp_path: Path) -> None:
    """The regeneration script writes only the golden JSON; it never edits the
    hand-maintained pin tables, so a helper-body or binding change cannot be
    laundered by a regenerate (it still needs a deliberate edit of this file)."""
    before = Path(__file__).read_bytes()
    out = tmp_path / "inv.json"
    script = ROOT / "tests" / "collector" / "regen_inventory.py"
    proc = subprocess.run(
        [sys.executable, str(script), "--out", str(out)],
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert proc.returncode == 0, proc.stderr
    assert out.exists()
    assert Path(__file__).read_bytes() == before, "regen must not modify the gate/pin file"
    src = script.read_text(encoding="utf-8")
    for table in (
        "PINNED_BINDINGS",
        "GUARDED_OPS",
        "STATEMENT_DIGESTS",
        "INSTANCE_RECEIVERS",
        "PINNED_MEMBER_CALLS",
        "NEW_OBJECT_VECTORS",
        "SECRET_VARIABLES",
        "SECRET_USES",
        "HEADER_SHA256",
        "DYNAMIC_INVOCATIONS",
        "print_pin_candidates",
    ):
        assert table not in src, f"regen_inventory.py must not reference {table}"


def test_pin_candidate_printer_writes_nothing(tmp_path: Path) -> None:
    """The rebuild helper only prints; the gate file is untouched."""
    before = Path(__file__).read_bytes()
    script = ROOT / "tests" / "collector" / "print_pin_candidates.py"
    proc = subprocess.run(
        [sys.executable, str(script)], capture_output=True, text=True, timeout=300, cwd=tmp_path
    )
    assert proc.returncode == 0, proc.stderr
    assert "PINNED_BINDINGS" in proc.stdout and "PINNED_MEMBER_CALLS" in proc.stdout
    assert Path(__file__).read_bytes() == before
    assert list(tmp_path.iterdir()) == []


# One statement nested under every kind of ancestor context; each mutation
# changes ONE ancestor property and must change that statement's digest.
_ANCESTOR_BASE = """function Get-Probe {
  [CmdletBinding()]
  param([string]$p)
  if ($p -eq 'x') {
    foreach ($i in @(1)) {
      try {
        switch ($i) { 1 { Write-Output 'probe-inner' } }
      } catch [System.Exception] { }
    }
  }
}
"""
_ANCESTOR_MUTATIONS = {
    "block-kind": ("  if ($p -eq 'x') {", "  process {\n  if ($p -eq 'x') {", "BLOCK"),
    "function-name": ("function Get-Probe {", "function Get-Other {", ""),
    "parameter": ("param([string]$p)", "param([int]$p)", ""),
    "attribute": ("  [CmdletBinding()]\n", "", ""),
    "if-condition": ("if ($p -eq 'x')", "if ($p -ne 'x')", ""),
    "foreach-variable": ("foreach ($i in @(1))", "foreach ($j in @(1))", ""),
    "foreach-source": ("foreach ($i in @(1))", "foreach ($i in @(2))", ""),
    "catch-type": ("catch [System.Exception]", "catch [System.IO.IOException]", ""),
    "switch-condition": ("switch ($i)", "switch ($i + 1)", ""),
    "switch-flag": ("switch ($i)", "switch -Regex ($i)", ""),
    "switch-pattern": ("{ 1 { Write", "{ 2 { Write", ""),
    "scriptblock-nesting": (
        "{ 1 { Write-Output 'probe-inner' } }",
        "{ 1 { & { Write-Output 'probe-inner' } } }",
        "",
    ),
}


def _probe_statement_digest(dump: dict[str, Any]) -> str:
    """The digest of the innermost `Write-Output 'probe-inner'` statement."""
    rows = dump["ast_rows"]
    paths = _row_index_paths(rows)
    digests = _statement_digests(dump)
    best: tuple[int, str] | None = None
    for i, row in enumerate(rows):
        if row[1] != "Statements":
            continue
        j = i + 1
        while j < len(rows) and rows[j][0] > row[0]:
            j += 1
        sub = rows[i:j]
        if any(
            r[2] == "StringConstantExpressionAst"
            and ["Value", "probe-inner"] in [list(a) for a in r[3]]
            for r in sub
        ):
            if best is None or len(sub) < best[0]:
                best = (len(sub), ".".join(str(x) for x in paths[i]))
    assert best is not None
    return digests[best[1]]


def test_statement_digest_covers_every_ancestor_property(tmp_path: Path) -> None:
    """Each ancestor-context property (block kind / unnamed, function name,
    parameters, attributes, if condition, foreach variable and source, catch
    types, switch condition / flag / pattern, scriptblock nesting) changes the
    digest of a statement nested beneath it."""
    files = [tmp_path / "base.ps1"]
    files[0].write_text(_ANCESTOR_BASE, encoding="utf-8")
    for name, (old, new, tail) in _ANCESTOR_MUTATIONS.items():
        assert _ANCESTOR_BASE.count(old) == 1, name
        f = tmp_path / f"{name}.ps1"
        text = _ANCESTOR_BASE.replace(old, new, 1)
        if tail == "BLOCK":  # close the new process block before the function's brace
            text = text[: text.rindex("}")] + "}\n}\n"
        f.write_text(text, encoding="utf-8")
        files.append(f)
    dumps = _run_dumper(files, "-Many")
    assert all(not d["parse_errors"] for d in dumps), [d["parse_errors"] for d in dumps]
    base = _probe_statement_digest(dumps[0])
    unchanged = [
        name
        for name, d in zip(_ANCESTOR_MUTATIONS, dumps[1:], strict=True)
        if _probe_statement_digest(d) == base
    ]
    assert not unchanged, (
        f"ancestor mutations that left the statement digest unchanged: {unchanged}"
    )


def test_statement_digests_cover_every_statement() -> None:
    """Every statement has a pinned digest and vice versa, and all match; every
    top-level function definition is among them (subsuming the old body pins)."""
    dump = _dump(COLLECTOR)
    digests = _statement_digests(dump)
    assert digests == STATEMENT_DIGESTS
    labels = _statement_digest_labels(dump)
    # Every local function appears as a (top-level) function-definition statement,
    # so STATEMENT_DIGESTS subsumes the former per-function body pins.
    assert sum(t == "FunctionDefinitionAst" for t in labels.values()) == len(LOCAL_FUNCTIONS)


def test_pins_cover_exactly_the_required_variables() -> None:
    """Every required variable is pinned, and every pin is still required."""
    dump = _dump(COLLECTOR)
    assert set(PINNED_BINDINGS) == set(_required_vars(dump))
    # The write paths and the remote-host / credential provenance are among them
    # (keyed by scope; the counters $i/$j live in the <script> scope).
    names = {k.split("::", 1)[1] for k in PINNED_BINDINGS}
    assert {
        "outdir",
        "outname",
        "outpath",
        "outparent",
        "certdir",
        "certfile",
        "crlfile",
        "i",
        "j",
        "dcdns",
        "dccred",
        "reg",
        "regpath",
    } <= names


def test_allowlist_has_no_stale_entries() -> None:
    """Every allowlist / closed-set entry is still used — keep the lists honest."""
    dump = _dump(COLLECTOR)
    used_cmds = {c["name"] for c in dump["commands"]}
    used_members = {m["member"] for m in dump["members"] if not m["static"]}
    used_static = {(m["target"], m["member"]) for m in dump["members"] if m["static"]}
    assert set(ALLOWED_COMMANDS) - used_cmds == set()
    assert set(ALLOWED_INSTANCE) - used_members == set()
    assert ALLOWED_STATIC - used_static == set()
    assert set(dump["node_types"]) == ALLOWED_NODE_TYPES
    receivers: dict[str, set[str]] = {}
    for m in dump["members"]:
        if not m["static"]:
            receivers.setdefault(m["member"], set()).add(m["receiver_root"] or "")
    assert receivers == {k: set(v) for k, v in INSTANCE_RECEIVERS.items()}
    assert set(INSTANCE_RECEIVERS) == set(ALLOWED_INSTANCE)
    assert Counter(_guarded_ops(dump)) == Counter(GUARDED_OPS)
    # Every command invocation is pinned (not just the side-effecting ones).
    commands = Counter((c["text"], tuple(c["context"])) for c in dump["commands"])
    assert not commands - Counter(GUARDED_OPS)
    assert set(dump["static_types"]) == ALLOWED_STATIC_TYPES
    used_vectors = {
        tuple(_canon(a) for a in c["args"])
        for c in dump["commands"]
        if _cf(c["name"]) == "new-object"
    }
    assert used_vectors == set(_NEW_OBJECT_VECTORS_CANON)
    dynamic = {
        (c["scope"], c["text"]) for c in dump["commands"] if not c["name"] or not c["bareword"]
    }
    assert dynamic == set(DYNAMIC_INVOCATIONS)
    redirections = {
        (r["kind"], r["stream"], r["location"], r["append"]) for r in dump["redirections"]
    }
    assert redirections == ALLOWED_REDIRECTIONS
    specials = {
        (b["variable"], (b["kind"], b["scope"], b["value"]))
        for b in dump["bindings"]
        if b["variable"]
        and (b["variable"] in _SPECIAL_VARIABLES or b["variable"].endswith("preference"))
        and not (b["variable"] == "null" and b["kind"] == "assign Equals")  # discards
    }
    assert specials == set(SPECIAL_BINDINGS)


def test_never_types_are_never_allowlisted() -> None:
    """LDAP write requests (Modify/Add/Delete/ModifyDN/Extended) and other
    non-read transports are in no allowlist, so no collector change can admit
    them by regenerating."""
    names = set(ALLOWED_STATIC_TYPES) | {t.strip("[]") for t, _m in ALLOWED_STATIC}
    names |= {v[0] for v in NEW_OBJECT_VECTORS}
    assert not {n for n in names if _NEVER_TYPES.search(n)}
    for t in ("ModifyRequest", "AddRequest", "DeleteRequest", "ModifyDNRequest", "ExtendedRequest"):
        assert _NEVER_TYPES.search(f"System.DirectoryServices.Protocols.{t}")


def test_every_argument_and_condition_variable_is_pinned() -> None:
    """Closure coverage: every variable in every command argument, every .NET
    call's receiver and arguments, and every branch/loop condition resolves to a
    pinned binding key (or is an engine variable that may be read unpinned)."""
    dump = _dump(COLLECTOR)
    bindings = _bindings_by_var(dump)
    uses: list[tuple[str, str]] = []
    for c in dump["commands"]:
        for text in [c.get("head", ""), *(e["text"] for e in c["elements"])]:
            uses += [(v, c["scope"]) for v in _vars_in(text)]
    for m in dump["members"]:
        for text in [m["target"], *m["args"]]:
            uses += [(v, m["scope"]) for v in _vars_in(text)]
    for cond in dump["conditions"]:
        uses += [(v, cond["scope"]) for v in _vars_in(cond["text"])]
    missing = sorted(
        {
            (v, scope)
            for v, scope in uses
            if v not in _AUTO_READ_OK
            and v not in {"lastexitcode", "pscmdlet", "this"}
            and not (_resolve(bindings, v, scope) & set(PINNED_BINDINGS))
            and _resolve(bindings, v, scope)
        }
    )
    assert not missing, missing


def test_secret_taint_is_closed_and_pinned() -> None:
    dump = _dump(COLLECTOR)
    assert _secret_closure(dump) == set(SECRET_VARIABLES)
    assert {_skey(_SCRIPT, n) for n in SECRET_SEEDS} <= set(SECRET_VARIABLES)
    uses = _secret_uses(dump, set(SECRET_VARIABLES))
    assert {k: sorted(v) for k, v in uses.items()} == {k: sorted(v) for k, v in SECRET_USES.items()}


def test_header_is_pinned() -> None:
    assert _dump(COLLECTOR)["header_sha256"] == HEADER_SHA256


# Spellings of the variable-writing common parameters: full names, unique
# prefixes and aliases. Each, on an allowlisted cmdlet, must be flagged; where
# the cmdlet is available to this pwsh, cmdlet metadata must resolve it to the
# canonical parameter (the metadata path, not only the gate's prefix rule).
_VARIABLE_PARAM_SPELLINGS = {
    "-OutVariable": "OutVariable",
    "-OutVar": "OutVariable",
    "-ov": "OutVariable",
    "-PipelineVariable": "PipelineVariable",
    "-Pi": "PipelineVariable",
    "-pv": "PipelineVariable",
    "-ErrorVariable": "ErrorVariable",
    "-ErrorV": "ErrorVariable",
    "-ev": "ErrorVariable",
    "-WarningVariable": "WarningVariable",
    "-wv": "WarningVariable",
    "-InformationVariable": "InformationVariable",
    "-iv": "InformationVariable",
}


@pytest.mark.parametrize("spelling", sorted(_VARIABLE_PARAM_SPELLINGS))
def test_variable_writing_parameter_spellings_are_flagged(tmp_path: Path, spelling: str) -> None:
    dump = _check_text(tmp_path, _appended(f"Get-Date {spelling} probeVar | Out-Null"))
    assert "[common-parameter]" in _tags(violations(dump)), spelling
    cmd = next(c for c in dump["commands"] if c["text"].startswith(f"Get-Date {spelling}"))
    assert (
        cmd["bound_params"] is not None
        and _VARIABLE_PARAM_SPELLINGS[spelling] in cmd["bound_params"]
    )


def test_forbidden_commands_are_never_allowlisted() -> None:
    forbidden = {c.lower() for c in FORBIDDEN_COMMANDS}
    assert not {c for c in ALLOWED_COMMANDS if c.lower() in forbidden}


# Files PowerShell can load as code or configuration. Every one under scripts/
# is either the gated collector or an analysis-host script declared out of scope.
_POWERSHELL_SUFFIXES = (".ps1", ".psm1", ".psd1", ".ps1xml", ".cdxml", ".pssc", ".psrc")
OUT_OF_SCOPE = {
    "install-windows.ps1": "runs on the analysis host to create a local venv, never on a CA",
    "uninstall-windows.ps1": "runs on the analysis host to remove the local venv, never on a CA",
}


def test_every_powershell_file_under_scripts_is_classified() -> None:
    scripts = ROOT / "scripts"
    on_disk = {
        p.relative_to(scripts).as_posix()
        for p in scripts.rglob("*")
        if p.is_file() and p.suffix.lower() in _POWERSHELL_SUFFIXES
    }
    assert on_disk == {COLLECTOR.name, *OUT_OF_SCOPE}


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
        "$dir = 'C:\\Windows\\Temp\\adcs-lens-probe-dir'\nNew-Item -ItemType Directory -Path $dir"
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
        "$outPath = 'C:\\Windows\\Temp\\evil.json'\n[IO.File]::WriteAllText($outPath, 'x')"
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


def _appended(snippet: str) -> str:
    return _collector_text() + "\n" + snippet + "\n"


def _replaced(name: str) -> str:
    old, new = _REPLACEMENTS[name]
    text = _collector_text()
    assert old in text, old
    return text.replace(old, new, 1)


def _check_text(tmp_path: Path, text: str) -> dict[str, Any]:
    script = tmp_path / "collector-variant.ps1"
    script.write_text(text, encoding="utf-8")
    return _dump(script)


@pytest.mark.parametrize("snippet", list(_BAD_SNIPPETS.values()), ids=list(_BAD_SNIPPETS))
def test_checker_flags_write_capable_surface(tmp_path: Path, snippet: str) -> None:
    """Each write-capable form, appended to the REAL collector, is reported.

    Appending (rather than checking the snippet alone) is what makes these
    meaningful: the snippet reuses the collector's own allowlisted names and
    variables, which is exactly how the round-1 bypasses worked.
    """
    assert violations(_check_text(tmp_path, _appended(snippet))), f"not flagged: {snippet}"


@pytest.mark.parametrize("name", sorted(_REPLACEMENTS))
def test_checker_flags_repointed_write_targets(tmp_path: Path, name: str) -> None:
    assert violations(_check_text(tmp_path, _replaced(name))), f"not flagged: {name}"


def test_appending_a_harmless_line_is_only_a_new_command(tmp_path: Path) -> None:
    """Control: the append harness itself causes no violation beyond the
    every-command pin (a harmless allowlisted command is still a new operation)."""
    found = violations(_check_text(tmp_path, _appended("Write-Output 'done'")))
    assert {v.split("]", 1)[0] + "]" for v in found} == {"[guarded-op]", "[statement-digest]"}


# --- review round 2 (Sol): each candidate, and WHICH check must flag it -------------
# Appended to the real collector. Every one also changes the golden syntax tree;
# the tag proves the semantic layer catches it too, for the right reason.
_SOL_R2: dict[str, tuple[str, str]] = {
    "directory_set_adobject": (
        "Set-ADObject -Identity 'CN=x,DC=example,DC=test' -Replace @{description='owned'}",
        "[command]",
    ),
    "directory_adsi_put": (
        "$de = [ADSI]'LDAP://CN=x,DC=example,DC=test'\n$de.Put('description', 'owned')\n$de.SetInfo()",
        "[member]",
    ),
    "ca_certutil_setreg": (
        "certutil -setreg policy\\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2",
        "[command]",
    ),
    "registry_set_item_property": (
        "Set-ItemProperty -Path HKLM:\\SOFTWARE -Name Probe -Value 1",
        "[command]",
    ),
    "remote_invoke_command": (
        "Invoke-Command -ComputerName dc01 -ScriptBlock { Set-ItemProperty -Path HKLM:\\SOFTWARE "
        "-Name Probe -Value 1 }",
        "[command]",
    ),
    "outside_direct_file": (
        "[IO.File]::WriteAllText('C:\\Windows\\Temp\\probe.txt', 'owned')",
        "[write-path]",
    ),
    "outside_indirect_file": (
        "$target = 'C:\\Windows\\Temp\\probe.txt'\n[IO.File]::WriteAllText($target, 'owned')",
        "[write-path]",
    ),
    "splatting": (
        "$args = @('-setreg', 'policy\\EditFlags', '+EDITF_ATTRIBUTESUBJECTALTNAME2')\ncertutil @args",
        "[command]",
    ),
    "pipeline_member_dispatch": (
        "$reg | ForEach-Object -MemberName SetDWORDValue -ArgumentList "
        "@(2147483650, 'SOFTWARE\\Probe', 'Pwned', 1)",
        "[command]",
    ),
    "dynamic_member": ("$method = 'SetInfo'\n$de.$method()", "[dynamic]"),
    "type_accelerator_adsi": ("$de = [ADSI]'LDAP://CN=x,DC=example,DC=test'", "[type]"),
    "type_alias_system_io_file": (
        "[System.IO.File]::WriteAllText('C:\\Windows\\Temp\\probe.txt', 'owned')",
        "[member]",
    ),
    "provider_path_direct": (
        "New-Item -ItemType Directory -Force -Path HKLM:\\SOFTWARE\\AdcsLensProbe",
        "[write-path]",
    ),
    "redirect_file": (
        "certutil -getreg CA\\CommonName 2> 'C:\\Windows\\Temp\\err.txt'",
        "[redirection]",
    ),
    "scope_modifier": (
        "$global:outPath = 'C:\\Windows\\Temp\\probe.txt'\n[IO.File]::WriteAllText($outPath, 'owned')",
        "[pinned-binding]",
    ),
    "function_unsafe_body": (
        "function Invoke-Later { Set-ItemProperty -Path HKLM:\\SOFTWARE -Name Probe -Value 1 }\n"
        "Invoke-Later",
        "[command]",
    ),
    "scriptblock_invoke_later": (
        "$later = { Set-ItemProperty -Path HKLM:\\SOFTWARE -Name Probe -Value 1 }\n$later.Invoke()",
        "[command]",
    ),
    "computer_different_variable": (
        "$otherDc = 'dc02.example.test'\n"
        "Get-WmiObject -ComputerName $otherDc -Namespace 'root\\default' -Class StdRegProv -List",
        "[command]",
    ),
    # The round-2 bypasses: case-insensitive names and same-name parameters.
    "BYPASS_case_insensitive_outpath": (
        "$OUTPATH = 'C:\\Windows\\Temp\\probe.txt'\n"
        "[IO.File]::WriteAllText($outPath, 'owned', (New-Object Text.UTF8Encoding($false)))",
        "[pinned-binding]",
    ),
    "BYPASS_function_parameter_outpath": (
        "function Invoke-Outside([string]$outPath) {\n"
        "  [IO.File]::WriteAllText($outPath, 'owned', (New-Object Text.UTF8Encoding($false)))\n"
        "}\nInvoke-Outside 'C:\\Windows\\Temp\\probe.txt'",
        "[pinned-binding]",
    ),
    "BYPASS_function_parameter_provider": (
        "function New-Outside([string]$OutDir) {\n"
        "  New-Item -ItemType Directory -Force -Path $OutDir | Out-Null\n"
        "}\nNew-Outside 'HKLM:\\SOFTWARE\\AdcsLensProbe'",
        "[pinned-binding]",
    ),
    "BYPASS_function_scriptblock_provider": (
        "function New-Later([string]$OutDir) {\n"
        "  1 | ForEach-Object { New-Item -ItemType Directory -Force -Path $OutDir | Out-Null }\n"
        "}\nNew-Later 'C:\\Windows\\Temp\\AdcsLensProbe'",
        "[pinned-binding]",
    ),
    "BYPASS_scriptblock_param_block": (
        "1 | ForEach-Object { param($outDir) New-Item -ItemType Directory -Force -Path $outDir }",
        "[pinned-binding]",
    ),
    "BYPASS_computer_same_name_parameter": (
        "function Read-OtherHost([string]$dcDns) {\n"
        "  Get-WmiObject -ComputerName $dcDns -Namespace 'root\\default' -Class StdRegProv -List\n"
        "}\nRead-OtherHost 'attacker.example.test'",
        "[pinned-binding]",
    ),
    "BYPASS_computer_same_name_reassignment": (
        "$dcDns = 'attacker.example.test'\n"
        "Get-WmiObject -ComputerName $dcDns -Namespace 'root\\default' -Class StdRegProv -List",
        "[pinned-binding]",
    ),
    "common_parameter_variable_write": (
        "Get-Date -OutVariable outPath | Out-Null",
        "[common-parameter]",
    ),
    "common_parameter_abbreviated": ("Get-Date -ov dcDns | Out-Null", "[common-parameter]"),
    "unbound_receiver": (
        "$ExecutionContext.SessionState.PSVariable.Set('outPath', 'C:\\evil')",
        "[receiver]",
    ),
}


@pytest.mark.parametrize("name", sorted(_SOL_R2))
def test_round2_candidate_is_flagged_by_the_right_check(tmp_path: Path, name: str) -> None:
    snippet, tag = _SOL_R2[name]
    dump = _check_text(tmp_path, _appended(snippet))
    found = violations(dump)
    assert any(v.startswith(tag) for v in found), (name, tag, found)
    assert tree_changed(dump)


def test_null_discard_is_allowed_by_semantics_but_not_by_the_inventory(tmp_path: Path) -> None:
    """Sol's control: `$NULL = ...` cannot rebind $null, so the semantic layer
    admits it, and the golden syntax tree still flags the change."""
    dump = _check_text(tmp_path, _appended("$NULL = 'C:\\Windows\\Temp\\err.txt'"))
    # $null = ... binds nothing and is not a write/exec; the only violation is the
    # structural-closure digest of the new statement.
    assert {v.split("]", 1)[0] + "]" for v in violations(dump)} == {"[statement-digest]"}
    assert tree_changed(dump)


def test_an_extra_certutil_call_is_a_new_exec_operation(tmp_path: Path) -> None:
    """The second half of Sol's control. Under collector 0.10.0 certutil runs
    only through _certutilRead (`-getreg $regpath 2>&1`): a direct call is a new
    operation outside GUARDED_OPS, its literal key is not the pinned vector, and
    a file-style `2>$null` redirection is no longer allowed."""
    dump = _check_text(tmp_path, _appended("certutil -getreg CA\\CommonName 2>$null"))
    tags = {v.split("]", 1)[0] + "]" for v in violations(dump)}
    assert tags == {"[guarded-op]", "[command]", "[redirection]", "[ast]", "[statement-digest]"}
    assert tree_changed(dump)


# --- property / indexer assignments (review round 2, DS N-R2-3) ------------------


def test_member_assignment_allowlist_matches_the_collector_exactly() -> None:
    """Every allowlisted object write is one the collector really makes, and vice versa."""
    dump = _dump(COLLECTOR)
    seen_members = {
        (m["receiver_root"], m["target"].lower().split(".", 1)[-1])
        for m in dump["member_assignments"]
        if m["kind"] == "member"
    }
    allowed_members = set(MEMBER_ASSIGNMENTS_ALLOWED) | set(NESTED_MEMBER_ASSIGNMENTS_ALLOWED)
    seen_index = {m["receiver_root"] for m in dump["member_assignments"] if m["kind"] == "index"}
    assert seen_members == allowed_members
    assert seen_index == set(INDEX_ASSIGNMENTS_ALLOWED)
    assert _member_assignment_violations(dump) == []


def test_collector_has_no_destructuring_or_unrecognised_targets() -> None:
    kinds = {b["kind"] for b in _dump(COLLECTOR)["bindings"]}
    assert not {k for k in kinds if k.startswith("destructure")}
    assert "assign-unrecognised-target" not in kinds


# --- round-3 classes (gpo-lens reviewers), adapted to this collector -----------------
# (id, edits, expected check). Each edit is (anchor, replacement) applied in
# order to the real collector; the anchor must occur exactly once. An anchor of
# "" means "append". Every probe was accepted by the a789b5d gate (semantic
# layer and/or golden inventory unchanged) — see CHANGELOG — and must now be
# flagged by its expected check, not by a parse error, AND change the tree.
_SELFTEST_GUARD = "if ($PSCmdlet.ParameterSetName -eq 'SelfTest') { return }\n"
_OUTDIR_MKDIR = "New-Item -ItemType Directory -Force -Path $OutDir | Out-Null\n"
_CERTFILE = "$certFile = '{0:d2}-{1}.cer'"
Edit = tuple[str, str]
_R3_PROBES: list[tuple[str, tuple[Edit, ...], str]] = [
    (
        "guard_moved_after_write",
        ((_SELFTEST_GUARD, ""), (_OUTDIR_MKDIR, _OUTDIR_MKDIR + _SELFTEST_GUARD)),
        "[guarded-op]",
    ),
    (
        "guard_weakened_opt_in",
        (("if ($CollectDcMapping) {", "if ($CollectDcMapping -or $true) {"),),
        "[guarded-op]",
    ),
    (
        "guard_or_to_and",
        (
            (
                "$dcDns.ToLower() -eq $localHost -or $dcDns",
                "$dcDns.ToLower() -eq $localHost -and $dcDns",
            ),
        ),
        "[guarded-op]",
    ),
    ("requires_module", (("<prepend>", "#Requires -Modules AdcsLensProbe\n"),), "[ast]"),
    (
        "psdefaultparametervalues",
        (("", "$PSDefaultParameterValues['Get-WmiObject:ComputerName'] = 'host.example.test'"),),
        "[binding]",
    ),
    (
        "receiver_rebind",
        (
            (
                "    if ($key) { $key.GetValue('Security') } else { $null }\n",
                "    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SOFTWARE\\AdcsLensProbe')\n"
                "    if ($key) { $key.GetValue('Security') } else { $null }\n",
            ),
        ),
        "[pinned-binding]",
    ),
    (
        "alias_provider_write",
        (("# --- manifest ---", "${Alias:Get-Date} = 'Get-Random'\n# --- manifest ---"),),
        "[binding]",
    ),
    ("duplicate_write_op", (("", "_writeJson @($caConfig) 'ca-config.json'"),), "[guarded-op]"),
    (
        "computed_outvariable",
        (("", "Get-Date -OutVariable ('out' + 'Path') | Out-Null"),),
        "[common-parameter]",
    ),
    (
        "later_member_argument",
        (("(New-Object Text.UTF8Encoding($false))", "(New-Object Text.UTF8Encoding($true))"),),
        "[guarded-op]",
    ),
    (
        "unpinned_counter_reassigned",
        ((_CERTFILE, "$i = 'probe'\n      " + _CERTFILE),),
        "[pinned-binding]",
    ),
    ("counter_decrement_added", ((_CERTFILE, "$i--\n      " + _CERTFILE),), "[pinned-binding]"),
    ("provider_drive_write", (("", "${C:\\Windows\\Temp\\probe.txt} = 'x'"),), "[binding]"),
    ("env_variable_write", (("", "$env:PSModulePath = 'x'"),), "[binding]"),
    ("global_variable_write", (("", "$global:AdcsLensProbe = 1"),), "[binding]"),
    ("preference_variable_write", (("", "$ErrorActionPreference = 'Continue'"),), "[binding]"),
    (
        "parameter_default_added",
        (
            (
                "[Parameter(Mandatory, ParameterSetName = 'Collect')] [string] $OutDir,",
                "[Parameter(ParameterSetName = 'Collect')] [string] $OutDir = 'probe',",
            ),
        ),
        "[pinned-binding]",
    ),
    (
        "helper_redefined",
        (
            (
                "# --- self-test boundary",
                "function _safeFileName([string]$name) { $name }\n# --- self-test boundary",
            ),
        ),
        "[local-function]",
    ),
    (
        "callsite_argument_added",
        (("", "_certutilFlags 'policy\\Other' | Out-Null"),),
        "[pinned-binding]",
    ),
    ("dot_sourced_helper_call", (("", ". _writeJson @{} 'probe.json'"),), "[dynamic]"),
    (
        "splat_into_helper",
        (("", "$probeArgs = @(1, 2)\n_decode @probeArgs | Out-Null"),),
        "[binding]",
    ),
    ("extra_positional_argument", (("", "_decode 1 $NAME_FLAGS 'extra' | Out-Null"),), "[binding]"),
    # --- Round-4 classes (gpo-lens Sol), adapted to this collector ---
    # BL-1: a helper's return value is changed to feed a write path; its body is
    # not reachable through the call-site binding, so only the body pin catches it.
    (
        "helper_return_rebinds_write_path",
        (("  ($name -replace '[^A-Za-z0-9._-]', '_')", "  '..\\..\\..\\Windows\\evil'"),),
        "[statement-digest]",
    ),
    # BL-2: a helper feeding an exec/remote input (the WMI credential) returns a
    # constant; every binding and call vector is unchanged.
    (
        "helper_constant_return",
        (
            (
                "function _b64([string]$s) { [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($s)) }",
                "function _b64([string]$s) { 'ATTACKER' }",
            ),
        ),
        "[statement-digest]",
    ),
    # --- Integration r2 (Sol B1) ---
    # Wrapping the whole script body in a named block changes no statement's
    # own subtree, only its ancestor (NamedBlockAst.BlockKind / Unnamed).
    *(
        (
            f"root_body_wrapped_in_{kind}",
            (
                (
                    "\n$ErrorActionPreference = 'Stop'\n",
                    f"\n{kind} {{\n$ErrorActionPreference = 'Stop'\n",
                ),
                ("", "}"),
            ),
            "[statement-digest]",
        )
        for kind in ("begin", "process", "end", "clean")
    ),
    # Every write sink must be preceded by Assert-AdcsOutputPath on its exact target.
    (
        "write_guard_removed",
        (("        Assert-AdcsOutputPath (Join-Path $certDir $certFile)\n", ""),),
        "[write-guard]",
    ),
    (
        "write_guard_wrong_target",
        (("  Assert-AdcsOutputPath $outPath\n", "  Assert-AdcsOutputPath $outParent\n"),),
        "[write-guard]",
    ),
    (
        "write_guard_only_on_one_branch",
        (
            (
                "\nAssert-AdcsOutputPath $OutDir\n",
                "\nif ($CollectDcMapping) { Assert-AdcsOutputPath $OutDir }\n",
            ),
        ),
        "[write-guard]",
    ),
    (
        "write_guard_body_neutered",
        (
            (
                '  if (-not $inside) { throw "refusing to write outside the output directory: $full" }\n',
                "",
            ),
        ),
        "[statement-digest]",
    ),
    # BL-3: a duplicate state-changing instance call (an extra LDAP FindOne, like
    # an early Dispose/Close on a handle) before the real one; a set of method
    # names and receivers would miss it, the guarded-op multiset does not.
    (
        "duplicate_lifetime_call",
        (("  $conn.Bind()\n", "  $conn.Bind()\n  $conn.Bind()\n"),),
        "[guarded-op]",
    ),
    # --- Round-3 classes (Sol B1 / DeepSeek B-R3-1), adapted to this collector ---
    # Sol B1: ForEach-Object / Where-Object / % process blocks run in the
    # caller's scope, so an unqualified assignment inside one rebinds the real
    # pinned variable. Each targets a different confined root.
    (
        "caller_scope_foreach_outroot",
        (("", "1 | ForEach-Object { $OutDir = 'C:\\Windows\\Temp\\AdcsProbe' }"),),
        "[pinned-binding]",
    ),
    (
        "caller_scope_where_certdir",
        (("", "1 | Where-Object { $certDir = 'C:\\Windows\\Temp\\AdcsProbe'; $true } | Out-Null"),),
        "[pinned-binding]",
    ),
    (
        "caller_scope_foreach_dcdns",
        (("", "1 | ForEach-Object { $dcDns = 'attacker.example.test' }"),),
        "[pinned-binding]",
    ),
    (
        "caller_scope_psscriptroot_root",
        (("", "1 | ForEach-Object { $OutDir = $PSScriptRoot }"),),
        "[pinned-binding]",
    ),
    (
        "caller_scope_transitive_dcuser",
        (("", "1 | ForEach-Object { $DcRegistryUser = 'attacker\\admin' }"),),
        "[pinned-binding]",
    ),
    # DeepSeek B-R3-1: a case-variant spelling of a local function is the same
    # function to PowerShell; it must hit the same pins and checks.
    (
        "case_variant_writejson_escape",
        (("", "_WRITEJSON @{} '..\\..\\evil.json'"),),
        "[write-path]",
    ),
    (
        "case_variant_writejson_remote",
        (("", "_writeJSON @{} '\\\\remote\\share\\evil.json'"),),
        "[write-path]",
    ),
    # --- Round-4 classes (Sol B1): constructor overloads and .NET call overloads ---
    # An allowlisted type reached through another constructor overload (a PFX
    # path + persist-key flags): only the exact (,$der) vector is admitted.
    (
        "x509_persist_key_constructor",
        (
            (
                "",
                "New-Object Security.Cryptography.X509Certificates.X509Certificate2("
                "'C:\\Windows\\Temp\\attacker.pfx', 'password', 18) | Out-Null",
            ),
        ),
        "[command]",
    ),
    # The same constructor through [Type]::new(...).
    (
        "type_new_constructor",
        (
            (
                "",
                "[Security.Cryptography.X509Certificates.X509Certificate2]::new("
                "'C:\\Windows\\Temp\\attacker.pfx', 'password', 18) | Out-Null",
            ),
        ),
        "[member]",
    ),
    # An extra call of an allowlisted method on an allowlisted receiver.
    (
        "member_call_added",
        (
            (
                "  $p['distinguishedname'] = @([string]$entry.DistinguishedName)\n",
                "  $null = $p.ContainsKey('cn')\n"
                "  $p['distinguishedname'] = @([string]$entry.DistinguishedName)\n",
            ),
        ),
        "[member-call]",
    ),
    # --- Integration (collector 0.10.0) + gpo-lens rounds 5-7 classes ---
    # An LDAP write request type is never admitted (SearchRequest only).
    (
        "ldap_modify_request",
        (
            (
                "",
                "$mr = [System.DirectoryServices.Protocols.ModifyRequest]::new("
                "'CN=x,DC=example,DC=test', 'Replace', 'description', 'y')",
            ),
        ),
        "[type]",
    ),
    # A credential used at a new site (logged; written into the export).
    ("secret_logged", (("", "Write-Host $LdapPass"),), "[secret]"),
    ("secret_written", (("", "_writeJson @{ p = $DcRegistryPass } 'probe.json'"),), "[secret]"),
    # UNC / URL forms in a command argument and in a binding value.
    (
        "unc_command_argument",
        (
            (
                "",
                "Get-WmiObject -ComputerName '\\\\host.example.test' -Namespace "
                "'root\\default' -Class StdRegProv -List | Out-Null",
            ),
        ),
        "[unc-url]",
    ),
    ("url_binding_value", (("", "$probeUrl = 'https://host.example.test/x'"),), "[unc-url]"),
    # Every command invocation is pinned, even a harmless allowlisted one.
    ("allowlisted_command_added", (("", "Get-Date | Out-Null"),), "[guarded-op]"),
    # A new dynamic invocation outside the pinned three.
    ("dynamic_invocation_added", (("", "$read = { 1 }\n& $read"),), "[dynamic]"),
    # A changed message is a changed (pinned) command.
    (
        "message_text_changed",
        (
            (
                'Write-Host "Using integrated auth (current user) for LDAP"',
                'Write-Host "Using integrated auth for LDAP"',
            ),
        ),
        "[guarded-op]",
    ),
    # --- Integration r1 (Sol B1): switch -File / remote literals anywhere ---
    # A switch -File reading a UNC path: rejected by the statement-flag screen
    # AND as a remote string literal.
    (
        "switch_file_unc",
        (("", "switch -File '\\\\attacker.example.test\\share\\probe.txt' { default { } }"),),
        "[ast]",
    ),
    # switch -File with a variable path (still a -File switch).
    (
        "switch_file_variable",
        (("", "$probePath = 'C:\\probe.txt'\nswitch -File $probePath { default { } }"),),
        "[ast]",
    ),
    # switch -Regex is also a non-None flag.
    ("switch_regex_flag", (("", "switch -Regex ('a') { 'a' { 1 } }"),), "[ast]"),
    # A provider-drive variable path read ${\\host\share\x} is a remote literal
    # in a binding target and a provider-drive reference.
    (
        "provider_unc_variable",
        (("", "${\\\\host\\share\\x} = 'y'"),),
        "[unc-url]",
    ),
    # A remote literal in a here-string / deep expression, not a command element.
    (
        "remote_literal_in_expression",
        (("", "$probe = @{ path = '\\\\attacker.example.test\\share' }"),),
        "[unc-url]",
    ),
    # A device-path literal (\\?\ / \\.\).
    # A bare appended statement with no write/exec/binding effect: caught only by
    # the structural-closure digest (every statement is pinned).
    ("trailing_return", (("", "return"),), "[statement-digest]"),
    ("device_path_literal", (("", "$probe = '\\\\?\\C:\\probe.txt'"),), "[unc-url]"),
]


def test_header_help_edit_is_caught_by_the_header_pin(tmp_path: Path) -> None:
    """The script header (help, [CmdletBinding], param block) is digest-pinned: a
    help-text edit leaves the AST unchanged but fails [header] (and the golden
    source digest)."""
    text = _collector_text().replace(
        "  Directory to write the export into (created if absent).",
        "  Directory to write the export into.",
    )
    assert text != _collector_text()
    dump = _check_text(tmp_path, text)
    assert _tags(violations(dump)) == {"[header]"}
    assert not tree_changed(dump)
    assert render_inventory(dump) != INVENTORY.read_text(encoding="utf-8")


def _apply(edits: tuple[Edit, ...]) -> str:
    text = _collector_text()
    for anchor, change in edits:
        if anchor == "":
            text = text + "\n" + change + "\n"
        elif anchor == "<prepend>":
            text = change + text
        else:
            assert text.count(anchor) == 1, f"edit anchor must occur exactly once: {anchor!r}"
            text = text.replace(anchor, change, 1)
    return text


def _tags(found: list[str]) -> set[str]:
    return {v.split("]", 1)[0] + "]" for v in found}


@pytest.mark.parametrize("probe", _R3_PROBES, ids=[p[0] for p in _R3_PROBES])
def test_round3_class_is_flagged_by_the_right_check(
    tmp_path: Path, probe: tuple[str, tuple[Edit, ...], str]
) -> None:
    probe_id, edits, expected = probe
    dump = _check_text(tmp_path, _apply(edits))
    tags = _tags(violations(dump))
    assert "[parse]" not in tags, (probe_id, tags)
    assert expected in tags, (probe_id, expected, tags)
    assert tree_changed(dump), probe_id


def test_line_ending_normalization_matches_git() -> None:
    """The golden's only normalization is CRLF->LF. That is exactly git's own
    normalization for `*.ps1 text eol=crlf`: the repository stores LF and every
    checkout writes CRLF, so a CRLF<->LF change inside a here-string cannot be
    committed at all, and a bare CR (which neither normalizes) changes the
    source digest. Pin the attribute so the two cannot drift apart."""
    if shutil.which("git") is None or not (ROOT / ".git").exists():
        pytest.skip("not a git checkout")
    out = subprocess.run(
        ["git", "-C", str(ROOT), "check-attr", "text", "eol", "--", str(COLLECTOR)],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert ": text: set" in out and ": eol: crlf" in out, out


def test_every_write_sink_is_guarded_on_its_exact_target() -> None:
    """The product guard precedes all seven write sinks (four New-Item, three
    WriteAll*), each on the sink's own target, and nothing else writes."""
    dump = _dump(COLLECTOR)
    sinks = _write_sinks(dump)
    assert sorted(target or "" for _, _, target, _ in sinks) == sorted(
        [
            "$OutDir",
            "$outParent",
            "$certDir",
            "$certDir",
            "$outPath",
            "(Join-Path $certDir $certFile)",
            "(Join-Path $certDir $crlFile)",
        ]
    )
    assert _write_guard_violations(dump) == []
    # The guard function is defined exactly once and is a local function.
    assert [f["name"] for f in dump["functions"]].count(WRITE_GUARD) == 1


# --- case-insensitivity meta-test (DeepSeek B-R3-1) --------------------------------
# PowerShell command/function/parameter/variable names are case-insensitive, so
# every APPEND-style regression snippet (the bad snippets, the Sol round-2 set and
# the append-only R3 probes -- not the replacement / multi-edit probes) must get
# the SAME verdict when the casing of its
# NAMES is flipped. The dumper's -SwapNames mode flips the case of command /
# function-call names, parameter flags and variable names only (bareword values,
# quoted strings, type literals and member names are left intact), so this tests
# names without disturbing the values the gate pins exactly.


def _append_snippets() -> dict[str, str]:
    out = {f"bad::{k}": v for k, v in _BAD_SNIPPETS.items()}
    out.update({f"sol::{k}": v for k, (v, _tag) in _SOL_R2.items()})
    for probe_id, edits, _expected in _R3_PROBES:
        if len(edits) == 1 and edits[0][0] == "":
            out[f"r3::{probe_id}"] = edits[0][1]
    return out


@cache
def _name_swapped_scripts() -> dict[str, str]:
    """key -> `_appended(<snippet with NAME casing flipped>)` (the snippet alone
    is name-swapped via pwsh, then appended to the unchanged collector, so only
    the probe's casing varies)."""
    items = sorted(_append_snippets().items())
    with tempfile.TemporaryDirectory(prefix="adcs-swap-") as tmp:
        paths = []
        for key, snippet in items:
            path = Path(tmp) / f"{_key(key.encode())[:16]}.ps1"
            path.write_text(snippet + "\n", encoding="utf-8")
            paths.append(path)
        swapped = {Path(e["path"]).name: e["swapped"] for e in _run_dumper(paths, "-SwapNames")}
    out = {}
    for (key, _), path in zip(items, paths, strict=True):
        out[key] = _appended(swapped[path.name].rstrip("\n"))
    register_sources(out.values())
    return out


@pytest.mark.parametrize("key", sorted(_append_snippets()))
def test_verdict_is_case_insensitive(tmp_path: Path, key: str) -> None:
    snippet = _append_snippets()[key]
    canonical = _tags(violations(_check_text(tmp_path, _appended(snippet))))
    swapped_src = _name_swapped_scripts()[key]
    swapped = _tags(violations(_check_text(tmp_path, swapped_src)))
    assert canonical == swapped, (key, sorted(canonical), sorted(swapped))


# Edits the semantic floor deliberately admits (no write/exec/binding effect)
# but the golden inventory must still catch, so a reviewer sees them.
# A comment-only edit changes the source digest but not the AST or any statement,
# so the semantic floor admits it and only the golden source digest catches it.
_GOLDEN_ONLY: list[tuple[str, tuple[Edit, ...]]] = [
    ("comment_only", (("", "# reviewer note"),)),
]


@pytest.mark.parametrize("probe", _GOLDEN_ONLY, ids=[p[0] for p in _GOLDEN_ONLY])
def test_golden_catches_semantically_neutral_edits(
    tmp_path: Path, probe: tuple[str, tuple[Edit, ...]]
) -> None:
    probe_id, edits = probe
    dump = _check_text(tmp_path, _apply(edits))
    assert violations(dump) == [], probe_id
    assert render_inventory(dump) != INVENTORY.read_text(encoding="utf-8"), probe_id
    assert tree_changed(dump) == (probe_id != "comment_only"), probe_id


# Register every variant above so they are dumped in a few batched pwsh runs
# (a fixture, so importing this module — e.g. from regen_inventory.py — dumps
# nothing extra).
@pytest.fixture(autouse=True, scope="module")
def _batch_variants() -> None:
    register_sources(_all_variants())


def _all_variants() -> list[str]:
    return [
        *(_appended(s) for s in _BAD_SNIPPETS.values()),
        *(_replaced(n) for n in _REPLACEMENTS),
        _appended("Write-Output 'done'"),
        *(_appended(s) for s, _ in _SOL_R2.values()),
        _appended("$NULL = 'C:\\Windows\\Temp\\err.txt'"),
        _appended("certutil -getreg CA\\CommonName 2>$null"),
        *(_apply(e) for _, e, _ in _R3_PROBES),
        *(_apply(e) for _, e in _GOLDEN_ONLY),
    ]


# --- completeness of the syntax-tree serialization (meta-tests) --------------------

# Properties the serializer deliberately skips on every node type, and why.
_EXCLUDED_AST_PROPERTIES = {
    "*.Parent": "back-reference; structure is the row nesting",
    "*.Extent": "source position/text; the text is represented by the child nodes",
    "*.ErrorPosition": "source position of an operator token",
    "*.StaticType": "derived by the parser from the node type, constant or cast",
    "ConvertExpressionAst.Attribute": "the same object as ConvertExpressionAst.Type",
}
_KNOWN_REQUIREMENT_PROPERTIES = {
    "IsElevationRequired",
    "RequiredApplicationId",
    "RequiredAssemblies",
    "RequiredModules",
    "RequiredPSEditions",
    "RequiredPSVersion",
    "RequiresPSSnapIns",  # Windows PowerShell 5.1 only
}


_SEMANTIC_PROPERTY_DISPOSITION: dict[str, str] = {
    "ArrayExpressionAst.SubExpression": "structural: its child nodes are each serialized and checked",
    "ArrayLiteralAst.Elements": "structural: its child nodes are each serialized and checked",
    "AssignmentStatementAst.Left": "check: assignment target (bindings / member_assignments)",
    "AssignmentStatementAst.Operator": "check: binding kind (_bindings_by_var / check_bindings)",
    "AssignmentStatementAst.Right": "check: binding value (dataflow pins, secret taint, UNC literals)",
    "AttributeAst.NamedArguments": "structural: its child nodes are each serialized and checked",
    "AttributeAst.PositionalArguments": "structural: its child nodes are each serialized and checked",
    "AttributeAst.TypeName": "check: type denylist (static_types / _NEVER_TYPES)",
    "BinaryExpressionAst.Left": "structural: its child nodes are each serialized and checked",
    "BinaryExpressionAst.Operator": "inert: arithmetic/logical/comparison operator, no I/O",
    "BinaryExpressionAst.Right": "structural: its child nodes are each serialized and checked",
    "BreakStatementAst.Label": "inert: loop label, control flow only",
    "CatchClauseAst.Body": "structural: its child nodes are each serialized and checked",
    "CatchClauseAst.CatchTypes": "check: type denylist (static_types)",
    "CatchClauseAst.IsCatchAll": "inert: catch-all flag, control flow only",
    "CommandAst.CommandElements": "check: commands projection (name, every argument, metadata)",
    "CommandAst.DefiningKeyword": "inert: null for ordinary commands; a defining keyword yields a refused node type",
    "CommandAst.InvocationOperator": "check: violations() (Dot dot-sourcing refused, Ampersand dynamic pinned)",
    "CommandAst.Redirections": "check: redirections projection",
    "CommandExpressionAst.Expression": "structural: its child nodes are each serialized and checked",
    "CommandExpressionAst.Redirections": "check: redirections projection",
    "CommandParameterAst.Argument": "structural: its child nodes are each serialized and checked",
    "CommandParameterAst.ParameterName": "check: commands elements (parameter names, common-parameter / metadata)",
    "ConstantExpressionAst.Value": "inert: a numeric / non-string constant, no I/O (strings are StringConstantExpressionAst)",
    "ContinueStatementAst.Label": "inert: loop label, control flow only",
    "ConvertExpressionAst.Child": "structural: its child nodes are each serialized and checked",
    "ConvertExpressionAst.Type": "check: type denylist (static_types) and [ref] binding",
    "ExpandableStringExpressionAst.NestedExpressions": "structural: its child nodes are each serialized and checked",
    "ExpandableStringExpressionAst.StringConstantType": "inert: quoting kind",
    "ExpandableStringExpressionAst.Value": "check: string_literals (REMOTE_LITERALS)",
    "ForEachStatementAst.Body": "structural: its child nodes are each serialized and checked",
    "ForEachStatementAst.Condition": "check: conditions projection + string_literals",
    "ForEachStatementAst.Flags": "check: statement_flags (foreach -Parallel refused)",
    "ForEachStatementAst.Label": "inert: loop label, control flow only",
    "ForEachStatementAst.ThrottleLimit": "inert: only meaningful with -Parallel, which statement_flags refuses",
    "ForEachStatementAst.Variable": "check: bindings (foreach loop variable)",
    "ForStatementAst.Body": "structural: its child nodes are each serialized and checked",
    "ForStatementAst.Condition": "check: conditions projection + string_literals",
    "ForStatementAst.Initializer": "structural: its child nodes are each serialized and checked",
    "ForStatementAst.Iterator": "structural: its child nodes are each serialized and checked",
    "ForStatementAst.Label": "inert: loop label, control flow only",
    "FunctionDefinitionAst.Body": "structural: its child nodes are each serialized and checked",
    "FunctionDefinitionAst.IsFilter": "check: STATEMENT_DIGESTS (the function statement digest covers the whole body)",
    "FunctionDefinitionAst.IsWorkflow": "check: STATEMENT_DIGESTS (a workflow changes the function statement subtree)",
    "FunctionDefinitionAst.Name": "check: LOCAL_FUNCTIONS (exact ordered set)",
    "FunctionDefinitionAst.Parameters": "check: bindings (parameter declarations)",
    "HashtableAst.KeyValuePairs": "structural: its child nodes are each serialized and checked",
    "IfStatementAst.Clauses": "check: conditions projection (+ bodies structural)",
    "IfStatementAst.ElseClause": "structural: its child nodes are each serialized and checked",
    "IndexExpressionAst.Index": "structural: its child nodes are each serialized and checked",
    "IndexExpressionAst.NullConditional": "inert: ?[] null-conditional flag, no I/O",
    "IndexExpressionAst.Target": "check: member_assignments root (index writes) + structural",
    "InvokeMemberExpressionAst.Arguments": "check: PINNED_MEMBER_CALLS + argument variables, UNC, secret",
    "InvokeMemberExpressionAst.Expression": "check: receiver (INSTANCE_RECEIVERS / receiver pins)",
    "InvokeMemberExpressionAst.GenericTypeArguments": "check: type denylist (static_types)",
    "InvokeMemberExpressionAst.Member": "check: member allowlist (ALLOWED_INSTANCE / ALLOWED_STATIC)",
    "InvokeMemberExpressionAst.NullConditional": "inert: ?. null-conditional flag, no I/O",
    "InvokeMemberExpressionAst.Static": "check: members projection (static vs instance)",
    "MemberExpressionAst.Expression": "check: receiver (member_assignments root)",
    "MemberExpressionAst.Member": "check: member name (member_assignments allowlist)",
    "MemberExpressionAst.NullConditional": "inert: ?. null-conditional flag, no I/O",
    "MemberExpressionAst.Static": "check: members / member_assignments projection",
    "MergingRedirectionAst.FromStream": "check: redirections (ALLOWED_REDIRECTIONS)",
    "MergingRedirectionAst.ToStream": "check: redirections (ALLOWED_REDIRECTIONS)",
    "NamedAttributeArgumentAst.Argument": "structural: its child nodes are each serialized and checked",
    "NamedAttributeArgumentAst.ArgumentName": "check: function_params pipeline check (ValueFromPipeline*)",
    "NamedAttributeArgumentAst.ExpressionOmitted": "inert: switch-style attribute arg, no I/O",
    "NamedBlockAst.BlockKind": "check: STATEMENT_DIGESTS ancestor chain (begin/process/end/clean lifecycle)",
    "NamedBlockAst.Statements": "structural: its child nodes are each serialized and checked",
    "NamedBlockAst.Traps": "check: node_types (a trap yields a refused TrapStatementAst)",
    "NamedBlockAst.Unnamed": "check: STATEMENT_DIGESTS ancestor chain (implicit vs explicit block)",
    "ParamBlockAst.Attributes": "check: type denylist (static_types) + structural",
    "ParamBlockAst.Parameters": "structural: its child nodes are each serialized and checked",
    "ParameterAst.Attributes": "check: type denylist (static_types)",
    "ParameterAst.DefaultValue": "structural: its child nodes are each serialized and checked",
    "ParameterAst.Name": "check: bindings (parameter declaration)",
    "ParenExpressionAst.Pipeline": "structural: its child nodes are each serialized and checked",
    "PipelineAst.Background": "check: background_pipelines (background jobs refused)",
    "PipelineAst.PipelineElements": "structural: its child nodes are each serialized and checked",
    "ReturnStatementAst.Pipeline": "structural: its child nodes are each serialized and checked",
    "ScriptBlockAst.Attributes": "check: type denylist (static_types)",
    "ScriptBlockAst.BeginBlock": "structural: its child nodes are each serialized and checked",
    "ScriptBlockAst.CleanBlock": "structural: its child nodes are each serialized and checked",
    "ScriptBlockAst.DynamicParamBlock": "inert: dynamicparam block; the collector defines none (would change the body digest + golden)",
    "ScriptBlockAst.EndBlock": "structural: its child nodes are each serialized and checked",
    "ScriptBlockAst.ParamBlock": "structural: its child nodes are each serialized and checked",
    "ScriptBlockAst.ProcessBlock": "structural: its child nodes are each serialized and checked",
    "ScriptBlockAst.ScriptRequirements": "check: script_requirements (#Requires refused)",
    "ScriptBlockAst.UsingStatements": "check: node_types (using statements yield refused UsingStatementAst)",
    "ScriptBlockExpressionAst.ScriptBlock": "check: _scope (caller-scope collapse) + structural",
    "StatementBlockAst.Statements": "structural: its child nodes are each serialized and checked",
    "StatementBlockAst.Traps": "check: node_types (a trap yields a refused TrapStatementAst)",
    "StringConstantExpressionAst.StringConstantType": "inert: bareword vs quoted kind (a bareword command name is checked via commands)",
    "StringConstantExpressionAst.Value": "check: string_literals (REMOTE_LITERALS) + command/argument checks",
    "SubExpressionAst.SubExpression": "structural: its child nodes are each serialized and checked",
    "SwitchStatementAst.Clauses": "structural: its child nodes are each serialized and checked",
    "SwitchStatementAst.Condition": "check: conditions projection + string_literals (switch input)",
    "SwitchStatementAst.Default": "structural: its child nodes are each serialized and checked",
    "SwitchStatementAst.Flags": "check: statement_flags (switch -File / -Regex refused)",
    "SwitchStatementAst.Label": "inert: loop label, control flow only",
    "ThrowStatementAst.IsRethrow": "inert: rethrow flag, control flow only",
    "ThrowStatementAst.Pipeline": "structural: its child nodes are each serialized and checked",
    "TryStatementAst.Body": "structural: its child nodes are each serialized and checked",
    "TryStatementAst.CatchClauses": "structural: its child nodes are each serialized and checked",
    "TryStatementAst.Finally": "structural: its child nodes are each serialized and checked",
    "TypeConstraintAst.TypeName": "check: type denylist (static_types / _NEVER_TYPES)",
    "TypeExpressionAst.TypeName": "check: type denylist (static_types / ALLOWED_STATIC / _NEVER_TYPES)",
    "UnaryExpressionAst.Child": "structural: its child nodes are each serialized and checked",
    "UnaryExpressionAst.TokenKind": "check: bindings (++/-- rebind their operand)",
    "VariableExpressionAst.Splatted": "check: splatting refused (check_bindings / variable_refs)",
    "VariableExpressionAst.VariablePath": "check: variable_refs (provider-drive refused) + bindings + secret taint",
}


def test_every_serialized_property_is_inspected_or_declared_inert() -> None:
    """Semantic-projection completeness: for every (AST node type, property) the
    golden serializer emits, the semantic layer must either INSPECT it or declare
    it SEMANTICALLY INERT with a reason. A serialized property of an ALLOWED node
    type that is in neither place fails here, so a new I/O- or behaviour-capable
    property cannot be serialized (and pass the golden) while the floor ignores
    it. Properties of a refused node type are inert because the node type itself
    is rejected by ALLOWED_NODE_TYPES."""
    table = _run_dumper([], "-Describe", timeout=120)["table"]
    missing: list[str] = []
    for node_type, props in table.items():
        if node_type not in ALLOWED_NODE_TYPES:
            continue  # the whole node type is refused (test_whole_tree_screens)
        for prop in props:
            key = f"{node_type}.{prop}"
            if key not in _SEMANTIC_PROPERTY_DISPOSITION:
                missing.append(key)
    assert not missing, (
        "serialized properties with no semantic disposition (inspect them or add a "
        "SEMANTICALLY_INERT reason to _SEMANTIC_PROPERTY_DISPOSITION):\n"
        + "\n".join(sorted(missing))
    )
    serialized = {
        f"{t}.{p}" for t, props in table.items() if t in ALLOWED_NODE_TYPES for p in props
    }
    stale = sorted(set(_SEMANTIC_PROPERTY_DISPOSITION) - serialized)
    assert not stale, "dispositions for properties the serializer no longer emits:\n" + "\n".join(
        stale
    )


def test_switch_and_loop_flags_are_refused() -> None:
    """Every switch / foreach statement in the collector has Flags=None, and a
    switch -File is rejected (its input is also screened as a remote literal)."""
    dump = _dump(COLLECTOR)
    assert all(sf["flags"] == "None" for sf in dump["statement_flags"])


def test_serializer_covers_every_ast_node_type() -> None:
    """Every concrete Ast type of the running PowerShell is in the serializer
    table, and every public property is serialized or excluded with a stated
    reason. A new PowerShell node type or property fails here."""
    described = _run_dumper([], "-Describe", timeout=120)
    table = described["table"]
    assert set(described["excluded"]) == set(_EXCLUDED_AST_PROPERTIES)
    problems: list[str] = []
    for node in described["ast_types"]:
        name = node["name"]
        if name not in table:
            problems.append(f"{name}: not in the serializer table")
            continue
        listed = set(table[name])
        for prop in node["properties"]:
            if prop in listed or f"*.{prop}" in _EXCLUDED_AST_PROPERTIES:
                continue
            if f"{name}.{prop}" in _EXCLUDED_AST_PROPERTIES:
                continue
            problems.append(f"{name}.{prop}: neither serialized nor excluded")
    assert not problems, "serializer table is incomplete:\n" + "\n".join(problems)
    unknown = set(described["script_requirements_properties"]) - _KNOWN_REQUIREMENT_PROPERTIES
    assert not unknown, f"new #Requires properties: {sorted(unknown)}"


# One construct per node type the collector does not use, so the serializer is
# exercised on all of them and the closed node set refuses them. Parsed only.
_EXOTIC_SOURCE = """#Requires -Version 5.1
using namespace System.Text
class GateBox : System.Object {
    [string] $Name = 'x'
    hidden static [int] $Count
    GateBox() { $this.Name = 'y' }
    [string] Show([int] $n) { return $this.Name * $n }
}
enum GateColor { Red = 1; Blue }
function Get-Gate { [CmdletBinding()] param([Parameter(Mandatory)][ValidateNotNull()] $a)
    dynamicparam { }
    begin { trap { continue } }
    process { do { $a-- } until ($a -lt 0); do { break } while ($false); for ($k = 0; $k -lt 1; $k++) { } }
    end { data GateData { 'x' }; $b = $a ? 1 : 2; Get-Item . && Get-Item .. || Get-Item / }
}
filter Test-Gate { $_ }
$x = [GateBox]::new(); $x.Show(2) | Out-Null
$s = { param($q) $using:q }
Start-Sleep 1 &
foreach -parallel ($i in 1..2) { $i }
while ($false) { }
switch -regex ('a') { 'a' { 1 } default { 2 } }
$h = @{ k = 1 }; $h['k'] += 2; [int]$h.k
"text $($h.k)" | Out-Null; @'
here
'@ | Out-Null
"""


def test_serializer_handles_every_node_type(tmp_path: Path) -> None:
    source = tmp_path / "exotic.ps1"
    source.write_bytes(_EXOTIC_SOURCE.encode("ascii"))
    entry = _run_dumper([source], "-Many", timeout=120)[0]
    assert entry["unsupported_nodes"] == [], entry["unsupported_nodes"]
    lines = inventory(entry)["ast"]
    assert lines[0].startswith("Script: ScriptBlockAst ScriptRequirements=")
    used = set(entry["node_types"])
    for kind in (
        "TypeDefinitionAst",
        "PropertyMemberAst",
        "FunctionMemberAst",
        "TrapStatementAst",
        "DataStatementAst",
        "TernaryExpressionAst",
        "PipelineChainAst",
        "UsingExpressionAst",
        "DoUntilStatementAst",
        "DoWhileStatementAst",
        "ForStatementAst",
        "WhileStatementAst",
        "UsingStatementAst",
    ):
        assert kind in used, f"exotic source did not produce {kind}"
    # All of them are refused by the semantic floor.
    tags = _tags(_structure_violations(entry))
    assert "[ast]" in tags
    assert {
        "TypeDefinitionAst",
        "PipelineChainAst",
        "TrapStatementAst",
    } <= used - ALLOWED_NODE_TYPES


# Single-token mutations by token kind / operator text.
_OPERATOR_SWAPS = {
    "-eq": "-ne",
    "-ne": "-eq",
    "-or": "-and",
    "-and": "-or",
    "-band": "-bor",
    "-bor": "-band",
    "-gt": "-ge",
    "-ge": "-gt",
    "-lt": "-le",
    "-le": "-lt",
    "-match": "-notmatch",
    "-notmatch": "-match",
    "-like": "-notlike",
    "-notlike": "-like",
    "-contains": "-notcontains",
    "-notcontains": "-contains",
    "-in": "-notin",
    "-notin": "-in",
    "-is": "-isnot",
    "-isnot": "-is",
    "-not": "-bnot",
    "-replace": "-creplace",
    "-split": "-csplit",
    "-join": "-split",
    "-f": "-join",
    "+": "-",
    "-": "+",
    "*": "/",
    "/": "*",
    "=": "+=",
    "+=": "=",
    "++": "--",
    "--": "++",
    "2>": "3>",
    "break": "continue",
    "continue": "break",
}


def _token_mutation(token: dict[str, Any]) -> str | None:
    kind, text = token["kind"], token["text"]
    if kind in ("Variable", "SplattedVariable"):
        return text[:-1] + "Q}" if text.endswith("}") else text + "Q"
    if kind == "Parameter":
        return text[:-1] + "Q:" if text.endswith(":") else text + "Q"
    if kind == "Number":
        return "8" if text == "7" else "7"
    if kind in ("StringLiteral", "StringExpandable"):
        return text[0] + "Q" + text[1:]
    if kind in ("HereStringLiteral", "HereStringExpandable"):
        cut = text.index("\n") + 1
        return text[:cut] + "Q" + text[cut:]
    if kind in ("Identifier", "Generic"):
        return text + "Q"
    return _OPERATOR_SWAPS.get(text.lower())


def _evenly(items: list[Any], count: int) -> list[Any]:
    if len(items) <= count:
        return list(items)
    step = (len(items) - 1) / (count - 1)
    return [items[round(i * step)] for i in range(count)]


def _mutants(source: str, sites: dict[str, Any]) -> list[tuple[str, str]]:
    """(label, mutated source) pairs that must each change the syntax tree."""
    out: list[tuple[str, str]] = []
    tokens = [t for t in sites["tokens"] if _token_mutation(t) is not None]
    for t in _evenly(tokens, 40):
        new = _token_mutation(t)
        assert new is not None
        out.append(
            (
                f"token {t['kind']} {t['text']!r}@{t['start']}",
                source[: t["start"]] + new + source[t["end"] :],
            )
        )
    swaps = [
        (s1, e1, s2, e2)
        for s1, e1, s2, e2 in sites["siblings"]
        if " ".join(source[s1:e1].split()) != " ".join(source[s2:e2].split())
    ]
    for s1, e1, s2, e2 in _evenly(swaps, 15):
        swapped = source[:s1] + source[s2:e2] + source[e1:s2] + source[s1:e1] + source[e2:]
        out.append((f"swap statements @{s1}/{s2}", swapped))
    for start, end in _evenly(list(sites["conditions"]), 12):
        out.append(
            (
                f"negate condition @{start}",
                source[:start] + "-not (" + source[start:end] + ")" + source[end:],
            )
        )
    for pos in [*_evenly(list(sites["block_starts"]), 3), len(source)]:
        for label, stmt in (
            ("index assignment", "$PSDefaultParameterValues['Get-Item:Force'] = $true\n"),
            ("return", "return\n"),
        ):
            sep = "" if pos == 0 or source[pos - 1] in "\n " else "\n"
            out.append((f"insert {label} @{pos}", source[:pos] + sep + stmt + source[pos:]))
    out.append(("#Requires module", "#Requires -Modules AdcsLensProbe\n" + source))
    out.append(("#Requires elevation", "#Requires -RunAsAdministrator\n" + source))
    return out


def test_inventory_detects_systematic_mutations(tmp_path: Path) -> None:
    """Generic completeness evidence: mutate the collector systematically —
    single tokens (evenly sampled over every mutable token), adjacent statement
    swaps, negated conditions, an inserted index assignment / `return`, an
    added `#Requires` — and require the serialized tree to differ for every
    mutant that still parses. Comment/whitespace-only edits must leave the tree
    unchanged but change the source digest; CRLF must change nothing."""
    # The committed file has CRLF line endings; mutate an LF copy (the
    # serializer normalizes CRLF, which the "crlf" neutral case checks).
    source = COLLECTOR.read_bytes().decode("ascii").replace("\r\n", "\n")
    base = tmp_path / "base.ps1"
    base.write_bytes(source.encode("ascii"))
    sites = _run_dumper([base], "-Many", "-Sites", timeout=120)[0]
    mutants = _mutants(source, sites)
    files: list[Path] = [base, COLLECTOR]
    for i, (_label, text) in enumerate(mutants):
        target = tmp_path / f"m{i:04d}.ps1"
        target.write_bytes(text.encode("ascii"))
        files.append(target)
    neutral = {
        "comment": "# reviewer comment\n" + source,
        "whitespace": "\n\n" + source.replace("\n", "  \n", 1),
        "crlf": source.replace("\n", "\r\n"),
    }
    for name, text in neutral.items():
        target = tmp_path / f"neutral-{name}.ps1"
        target.write_bytes(text.encode("ascii"))
        files.append(target)
    results = _run_dumper(files, "-Many", "-AstOnly")
    original = inventory(results[0])
    assert inventory(results[1]) == original, "the committed CRLF file and its LF copy differ"
    by_path = {Path(r["path"]).name: inventory(r) for r in results[2:]}
    undetected: list[str] = []
    clean = 0
    for i, (label, _text) in enumerate(mutants):
        mutant = by_path[f"m{i:04d}.ps1"]
        if mutant["parse_errors"]:
            continue
        clean += 1
        if mutant["ast"] == original["ast"]:
            undetected.append(label)
    assert not undetected, f"mutations not reflected in the syntax tree: {undetected}"
    assert clean >= len(mutants) * 0.6, f"only {clean}/{len(mutants)} mutants parsed"
    for name in ("comment", "whitespace"):
        changed = by_path[f"neutral-{name}.ps1"]
        assert changed["ast"] == original["ast"], f"{name}-only edit changed the tree"
        assert changed["source_sha256"] != original["source_sha256"], name
    assert by_path["neutral-crlf.ps1"] == original, "CRLF changed the inventory"
