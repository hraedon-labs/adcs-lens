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
# Read-only IIS configuration queries (ESC8 pass), as exact argument vectors
# (collector >= 0.12.0; the earlier check admitted any value for these four
# parameters). One property at the application's effective path ($ps, built
# from 'IIS:\Sites\'), the same property at its applicationHost.config location
# tag (the -PSPath is the literal local config path MACHINE/WEBROOT/APPHOST,
# never a variable, so the read cannot be pointed at another file or machine),
# and the authentication providers collection.
_WEBCFG_VECTORS = (
    ["-PSPath", "$ps", "-Filter", "$filter", "-Name", "$name", "-ErrorAction", "Stop"],
    [
        "-PSPath",
        "'MACHINE/WEBROOT/APPHOST'",
        "-Location",
        "$loc",
        "-Filter",
        "$filter",
        "-Name",
        "$name",
        "-ErrorAction",
        "Stop",
    ],
    ["-PSPath", "$ps", "-Filter", '"$auth/providers"', "-Name", "Collection", "-ErrorAction", "Stop"],
)
_web_config = _exact(*_WEBCFG_VECTORS)


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
    "_iisScalar",
    "_epaToken",
    "_sslRequiredFrom",
    "_iisBool",
    "_iisRead",
    "_bothScopes",
    "_classifyApp",
    "_caKindFromType",
    "_safeFileName",
    "_certKindFromDer",
    "_parseAces",
    "_sdRead",
    "_aclRow",
    "_caHost",
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
    "0.1.1": "5feb8b2cd4e5d98cc4b5f89ad0667f500e833096c5e12ecb0c1ee0db0b868507",  # AssignmentStatementAst
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
    "0.1.17": "9ed06a2c1acf7b942d6cc52e2a2109a09c8ea7114fa88fda53cf7232ac22afce",  # AssignmentStatementAst
    "0.1.18": "eb9e0a2da61d84c9ef377c2576ad04aad2359ce74beee05124ba5bba5697b2db",  # AssignmentStatementAst
    "0.1.19": "be552331e25cd469d73bf8e7fe1e3288e13c69979bec60e449ee05040801013d",  # AssignmentStatementAst
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
    "0.1.23": "9d0d2a0493c0d0871b56fb194c33161af2a6c8bebb1eeeb81ba44ae844c4a693",  # AssignmentStatementAst
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
    "0.1.40": "1729c4457143830d003529d7f1aa6c56f4eb43bf4cfbc96f0927bdfe74842227",  # FunctionDefinitionAst
    "0.1.40.1.0.0": "aa9819395495d0d4918e433708bcba4b9125d9e225d66d1220dad4f4e64a224a",  # IfStatementAst
    "0.1.40.1.0.0.1.0": "3c45b8443a148973ff1ccef62783e4f5d9402a6e9beaedd2a0cfddc9fdc98350",  # ReturnStatementAst
    "0.1.40.1.0.1": "8a690db67490bd9c5d2790504370c5eb8cf5efbd7d0372669ba86ae0c65a8a02",  # AssignmentStatementAst
    "0.1.40.1.0.1.1.0.0.0": "acb3f86f855dfec187927969fc5b31ba3a85246f6b289714bdcab4f97d8192ed",  # PipelineAst
    "0.1.40.1.0.2": "05bea5e9075e985cee381a5ad7cb6e315dd5c5cd475381c34b9f731db57720a8",  # IfStatementAst
    "0.1.40.1.0.2.1.0": "b28a609463117a1bc2ea2b4cc43f2e8ad3d3cadd976629838edb28d5fe65f484",  # ReturnStatementAst
    "0.1.40.1.0.3": "193703f4aa9885e38e56612a58352b9ba525f32e751b5ac23bdeda2cf6b27207",  # AssignmentStatementAst
    "0.1.40.1.0.4": "01e6ea5fff6a22053881860fb975886b633e17a21afba49108b035df13c67a23",  # IfStatementAst
    "0.1.40.1.0.4.1.0": "d5c0f3bcf0b36a6de4a1c1aec66bedd2e5302a34bb41bdbbecb420c3600f1d0a",  # ReturnStatementAst
    "0.1.40.1.0.5": "5a020005694de40b44d7fa0ccecdcd6a09595633fcc0a120e2c94845c21fe2d7",  # IfStatementAst
    "0.1.40.1.0.5.1.0": "ea3685add3fae9cfd8a3c0e5b189c13160f8e69b46c1528c72d891966c922fcc",  # AssignmentStatementAst
    "0.1.40.1.0.5.1.1": "89121172ed4751e6448063f3bde177d6355cd771c90180bd084a5a8f73de9487",  # IfStatementAst
    "0.1.40.1.0.5.1.1.1.0": "d274731748f66147a6efcf14d76ed7e4e6ba5a75e07323b855f0c1727c06d7b4",  # ReturnStatementAst
    "0.1.40.1.0.6": "1e367aa2e294b4851d7837f8512738f5e38945735e4436ecf8cf386e2652dfcc",  # ReturnStatementAst
    "0.1.41": "7a956073c73dffdd19e44425809a94c174d4a1380ce742d3c18a026824849fab",  # FunctionDefinitionAst
    "0.1.41.1.0.0": "e4c8bd5ad213ef6ab8cbd1712872b966375fa14d372db27184d3217192c9bb14",  # IfStatementAst
    "0.1.41.1.0.0.1.0": "ef085b93549b196ca1fc37aa52b523f129e970c1e8929b9ea8ae5b1b8563bc3b",  # ReturnStatementAst
    "0.1.41.1.0.1": "5c01d295bb24b0e8a22cca62331dee4e97b2bd1bad73ae0bd757e1853b198309",  # SwitchStatementAst
    "0.1.41.1.0.1.2.0": "77602f7b487f256395a852c69a131c69a3789e5df1df2b6d843119fa3d968f1e",  # ReturnStatementAst
    "0.1.41.1.0.1.4.0": "c0860c0fdf08005126aafbf281c74c8d8394d22f3413cf9ce70f2eda0ab196a6",  # ReturnStatementAst
    "0.1.41.1.0.1.6.0": "ea0e7c6cf10d8ecd186a8880608aa1d140d57a9e55607504b2d4b32ff2029404",  # ReturnStatementAst
    "0.1.41.1.0.1.8.0": "02b10b86c964e224f9e5d7934d13cc593074a2b995ebf6f4522a63bea6e2ca32",  # ReturnStatementAst
    "0.1.41.1.0.1.10.0": "12d4c082cc7a826f367f73b457fa16ff526f1d9c7eb00a6e6e7302045be2ce9c",  # ReturnStatementAst
    "0.1.41.1.0.1.12.0": "abde62fbb362e64ebfc6adfdfa90edf2a61c6d48c75dc06e7005c955f0c628a2",  # ReturnStatementAst
    "0.1.41.1.0.2": "f5e863fc1a7ae98a4cc38af8258267e32f22fcdf5b0ae30037f3c260e3a6a690",  # ReturnStatementAst
    "0.1.42": "5a86ebd553ffd16a378365a5d00b1434a8e7fe256014457d933cb7732973b777",  # FunctionDefinitionAst
    "0.1.42.1.0.0": "42fe8e43e900f69490bf0d78897a2df7cf70cdc22781b63f850f7c6d0d08d04e",  # IfStatementAst
    "0.1.42.1.0.0.1.0": "dd6cfe3000c3f72c6dceb2410f0ee97506a559b64377310ecbd98bfb16aa23ab",  # ReturnStatementAst
    "0.1.42.1.0.1": "61c679bee50bac9e5a5935c21ae6603784aec7011f412368a2c6758bbc0b9806",  # IfStatementAst
    "0.1.42.1.0.1.1.0": "5fb59a0d8543089fcfabd064d343f50bc99271b74cd5adab2603ae54d3c204e2",  # IfStatementAst
    "0.1.42.1.0.1.1.0.1.0": "05feda75c3e8c3ae46fffd1defc019672d71bddd44ef91bc14c982b422191145",  # ReturnStatementAst
    "0.1.42.1.0.1.1.1": "be9be350e73f56513347a958514d843a3fa4570435d86a0bff34bd004f17f1e9",  # AssignmentStatementAst
    "0.1.42.1.0.1.1.2": "5b3ffb4a4235bf6bcc8f9f61f27eac591764adb83d29917d1c32e79507045ffe",  # AssignmentStatementAst
    "0.1.42.1.0.1.2.0": "f3849a8af0a6441f2bdca587927707be9ed6c1d44e90612859e4109e5aceb27b",  # AssignmentStatementAst
    "0.1.42.1.0.1.2.0.1.0.0.0": "2107d22a57e4f921ce2e03c66a53dab597916cae9d66c239bab74199f31cbd2b",  # PipelineAst
    "0.1.42.1.0.1.2.1": "96dcda8216abf744a39350cdd0ea25a59a80076e7192479fd426038387084de6",  # ForEachStatementAst
    "0.1.42.1.0.1.2.1.2.0": "0edf834437382fa21c578b068b9285595c63ea27689dc9e9196910fab85be838",  # IfStatementAst
    "0.1.42.1.0.1.2.1.2.0.0.0.0.0.0.0": "02c365c3458015cfd9a82d6a83686c0fc401a328d96148ff2275b729f6f2745a",  # PipelineAst
    "0.1.42.1.0.1.2.1.2.0.1.0": "a375b88048aa9b63f3c53c5c9f780ce4e4939ce27c33225842bbff74fcdf6f04",  # ReturnStatementAst
    "0.1.42.1.0.1.2.2": "386946688c69d70d1da8a83496d620b8cf7f8bbbad8b0ceb5f22971a25b00246",  # IfStatementAst
    "0.1.42.1.0.1.2.2.1.0": "d50d4e9f03fd0ca95797312013185586ecda39e599405f044e425c0106782fdf",  # ReturnStatementAst
    "0.1.42.1.0.1.2.3": "7ad6cd4feb686e8ee84e006175cfba3646f9a480a79ff97272fb01f39eaa7e6e",  # AssignmentStatementAst
    "0.1.42.1.0.1.2.4": "d9171381671689543089d586861048194406c72e1dd661341b47480bf06f476b",  # AssignmentStatementAst
    "0.1.42.1.0.2": "6602b588580a758b11998a289021bf158aaf1a03cf658a42e9eeb52a18e8ac28",  # IfStatementAst
    "0.1.42.1.0.2.1.0": "87ca8005ad7398878d8bc2fc3b3902091bd0858dbc616ae3adad1cfbb7278108",  # ReturnStatementAst
    "0.1.42.1.0.3": "67ac84edb1ca2d0ef8d413b4611c894ab972305f9feb3bb7d5c59c8c1867890c",  # ReturnStatementAst
    "0.1.43": "300402f7de082bcc4ab72dcaf15ccf8f5a03eb3b1bb8b5fbeb9f3401c1198c6d",  # FunctionDefinitionAst
    "0.1.43.1.0.0": "c8c7fa0b709bb28ac851b4d21ad52622aa7aa3662750364e40bf9550ddce57cc",  # IfStatementAst
    "0.1.43.1.0.0.1.0": "3fd2094622649e42caab425b1cec13357578df3dd5c27556c561dcd647350fa8",  # ReturnStatementAst
    "0.1.43.1.0.1": "b824479641bec9ab377b4fbb149ac6ce95050715e1bf3b17479d606caeec0f07",  # IfStatementAst
    "0.1.43.1.0.1.1.0": "6a0572f666d1ee5c2dc25ac410ad7948e4377ef5ea1410e192cc9dc5e84fa7ba",  # SwitchStatementAst
    "0.1.43.1.0.1.1.0.2.0": "88cc45b35c2c32e2857b69db28f53f7d6bb7f13fb92cc4ba8fdda78abe8c24bc",  # ReturnStatementAst
    "0.1.43.1.0.1.1.0.4.0": "df88e18c745306fe7c0d3f3c505597fd000de12534b76ef9a45a84226fd14dc1",  # ReturnStatementAst
    "0.1.43.1.0.2": "7435008bff061e9a21ade2ee2ef776ef665beeff201ab4436bda320c54d13376",  # ReturnStatementAst
    "0.1.44": "33bedbdd7faad02334d526523d4577599df878304cf0c3690d4d7a5492ec1234",  # FunctionDefinitionAst
    "0.1.44.4.0.0": "2cb20c8334b408345e91bb91f8fad8ec421ff2ba9835ce1a51b207bcef4ae7d1",  # AssignmentStatementAst
    "0.1.44.4.0.0.1.0.1.0.0.0": "7efcd292ed3412dcdf96050bfa57cd360f1ac27719f43c14b5fd6f56380a48a2",  # PipelineAst
    "0.1.44.4.0.1": "86d64f6ec1f4da18dfa165f15a3468e0907bb137443373c0db23be282f4044b2",  # AssignmentStatementAst
    "0.1.44.4.0.1.1.0.1.0.0.0": "8c9dc5375a8c2aec244222f65c0d5b8f07b9aac4f9c6d7c51c6d4a10c728307c",  # PipelineAst
    "0.1.44.4.0.2": "f87782b613ce2d2737f521c381705a9cd0e2d75c9ea54796722a6fc655fccd42",  # PipelineAst
    "0.1.45": "16c7767f38eecfaadf5f460961585749e0c1f3d5295e339b64083303099b5849",  # FunctionDefinitionAst
    "0.1.45.2.0.0": "605d436f9d9cbafcf7ef09258ae0ba64e7674a62b04d665539e27cabcedbcf55",  # IfStatementAst
    "0.1.45.2.0.0.1.0": "110b0fbc027a0d17adb4634e04ab91ce890261f0ef8fae380b4c96279ca768f4",  # ReturnStatementAst
    "0.1.45.2.0.1": "cb2519cae9a3f16e8c8b9395cac7305149628e35babf257f8317c81043aa4888",  # IfStatementAst
    "0.1.45.2.0.1.1.0": "5d6134d0765676c7dc1c422d2622a91e755317e3d0398f25f4a05afa000f94ee",  # ReturnStatementAst
    "0.1.45.2.0.2": "3f88ac0a481c4924673b024722044e08999b27b99e76283b1020ef7d94d24564",  # ReturnStatementAst
    "0.1.46": "bdab1e3c8e6fda8b1a03ac39662bfdf45719483321dcbcd8cad56d1282084776",  # FunctionDefinitionAst
    "0.1.46.1.0.0": "0bc47194cacd3554513c7e0fb48fec0729c17285c88c5ecd82c58772ed3886f3",  # AssignmentStatementAst
    "0.1.46.1.0.1": "2d96c3806ed531661b8ef76434e62030a7fe5eb0774c00fd881d68017e199cf6",  # IfStatementAst
    "0.1.46.1.0.1.1.0": "9ff012d045aff2d26328ea7e85c430330587bce6a57d1c6330175ddf1e1106ec",  # ReturnStatementAst
    "0.1.46.1.0.2": "720f63e2cc4487f12f4601845f0217e8addd06fd4c71117312ec330c294024c9",  # IfStatementAst
    "0.1.46.1.0.2.1.0": "1fc50cbe9de2651bf513e83d3ad21994149113ca2bc7b65afafe2ecd0e0885c2",  # ReturnStatementAst
    "0.1.46.1.0.3": "92c62294936251efc80c3587492c108f9482ad79e17b81cce25f35f97a31935c",  # IfStatementAst
    "0.1.46.1.0.3.1.0": "e49ae8e3beffa14c946a276b866a73a4f1b7074f78b7644e589141a51ef505ee",  # ReturnStatementAst
    "0.1.46.1.0.4": "a907bc144542e1cb33946bf0766a26d4a89f679b2dd3414df33196ddeddf5a90",  # ReturnStatementAst
    "0.1.47": "7d1d899123de20e7d9a4a9ccd3115b631d4d420caa9f87e675ee5a008780cf86",  # FunctionDefinitionAst
    "0.1.47.1.0.0": "0fb7cbdf5392f0d2b5dfc522aa3b91ff40edd27e427ce888c211641d1155562b",  # IfStatementAst
    "0.1.47.1.0.0.1.0": "9cbc7ff95b00bc9e1e39ec7ecc355ac52803c02af8e1df682a90a5c6d503a7bb",  # ReturnStatementAst
    "0.1.47.1.0.1": "e6aad33571df840f880a9ae4ac9f58336c50fd501300192e9aace4a928f5ae12",  # SwitchStatementAst
    "0.1.47.1.0.1.2.0": "aef26733dc761bffe82ed77d2baa0ffabd80b6a1066b85294698d14da97a9310",  # PipelineAst
    "0.1.47.1.0.1.2.1": "b383476f05d2fdd9bf2e0b00e5f38579a939b54d2303b3c643a8814b515c96ea",  # ReturnStatementAst
    "0.1.47.1.0.1.4.0": "35cb503230a8127d4f47e7700779cb5545fa938b2f1b85e9da9007cad760fd1c",  # PipelineAst
    "0.1.47.1.0.1.4.1": "2567150bb39d3caaac49daaf8aa97e70096d7811ec5daeff37b2298fdeef2794",  # ReturnStatementAst
    "0.1.47.1.0.1.6.0": "7110fdba0c237f802b640a40a183840e0025f34abb7a387170741adb6ac55c5e",  # PipelineAst
    "0.1.47.1.0.1.6.1": "96cd187f03ca8b09340ea84f56076a4d876a5e086dca0e1716335865b42f3be8",  # ReturnStatementAst
    "0.1.47.1.0.1.8.0": "97b375a83ee0ee3071fd1e7147f298ba30a1287f1a93af09980ae13931662a05",  # PipelineAst
    "0.1.47.1.0.1.8.1": "a877969c5a47faa73191bfd8384bc0e178f023d73a12f72c6bea866462e72d4f",  # ReturnStatementAst
    "0.1.47.1.0.1.9.0": "e6bd61c6f6eab960a4321f086d9f146eaf5e752423afc4bcadf2f34198c5199c",  # PipelineAst
    "0.1.47.1.0.1.9.1": "4bf0975a4196d426a1d0cc1900cf0f4c165f58031d4ff6fcad8efe6c191ed307",  # ReturnStatementAst
    "0.1.48": "78aa6b01201d1c2bb534cbb2112881fa0a455f3b295e3348985c29008a651441",  # FunctionDefinitionAst
    "0.1.48.1.0.0": "31357cda36e329da1821938ca39bdaea96d56603cd96a5bcaf97a7404bb03aea",  # PipelineAst
    "0.1.49": "a26b60bfb38521c1a29ed5ff55f7f7bd3133e83f1700a037eb5e427966bd3ae8",  # FunctionDefinitionAst
    "0.1.49.1.0.0": "1ce909924498f9c4c123c25ef3081292e37daa7560481061e2513d24ab877760",  # IfStatementAst
    "0.1.49.1.0.0.1.0": "030f31969c307b48ad906853982276d548bd8ddf0ea888792287e252fb82afc2",  # ReturnStatementAst
    "0.1.49.1.0.1": "b217614c60ab388a7993723cac00c9493ab768b7a275d2ec7419ad7efa8f8806",  # TryStatementAst
    "0.1.49.1.0.1.0.0": "23c2201ffc21d6183c8886a1ecc23982e07bb1330b8c56406f26fdd13d60c81e",  # AssignmentStatementAst
    "0.1.49.1.0.1.0.1": "5bac9438e1f869b6fd9853de4ad46c7d58f4d1f41d0ee82b0ce4b268ab0329df",  # IfStatementAst
    "0.1.49.1.0.1.0.1.1.0": "057f1113ba3d1c3e0a3da8b0addcf75354b0c41e3ffc04b9fce615e774c462b3",  # ReturnStatementAst
    "0.1.49.1.0.1.0.2": "300ee744c9179b45b69b857b35bb75f1ebb66831db2b87b54ee545ed7ae97890",  # ReturnStatementAst
    "0.1.49.1.0.1.1.0.0": "6c5dfec7e75528af9063e02ab3c5923352b3927271aeb30f9f89976043d62326",  # ReturnStatementAst
    "0.1.50": "9f97192508563917735e8f42ec551630e32368c3ba0aafdceab9498177b79aa3",  # AssignmentStatementAst
    "0.1.51": "4751287c6ffcb3c3699e3704f0ab4b16a1988d11e322f8adfe29c6bc932d1fb1",  # AssignmentStatementAst
    "0.1.52": "ec3c45007cd9c558bcc2c08d2a69b0fe15ab2029ed14ba2f8ed388d227774cde",  # AssignmentStatementAst
    "0.1.53": "2c1b8548b5d6019a426856c6fa02a0673fad522171d6b2acaee51a162093bbb6",  # FunctionDefinitionAst
    "0.1.53.1.0.0": "87aeb95326e5fd862d44ff06716a8774c592b23ac27e858a0a4bcdc6c268e687",  # AssignmentStatementAst
    "0.1.53.1.0.1": "2b8d89a27f3ef66c5817f90e85fe2b9956402c0657424062275030fd81a79bd4",  # IfStatementAst
    "0.1.53.1.0.1.1.0": "f43d91a59ce8c8499bb5a70db0d043ab88f7c1a3f1e9dc6269266a99a879a64c",  # ReturnStatementAst
    "0.1.53.1.0.2": "d9ecb2a9560f5bbbf574a0f6e97234623531fe7017d5d9c822bb61e026aad0f2",  # AssignmentStatementAst
    "0.1.53.1.0.3": "dcfd0677d829a4224f787ff3423e74746d37f4a07b807f0042c5e101c260d0e2",  # PipelineAst
    "0.1.53.1.0.4": "4fe6f8edd4ff7e3957142d5a84a435c397bb37e5c16c4de38d153cc31671ce13",  # ForEachStatementAst
    "0.1.53.1.0.4.2.0": "461949241d3f9e86487cb417c0c7db1d74cd601c0fd12b61e27750760b4ee29a",  # AssignmentStatementAst
    "0.1.53.1.0.4.2.1": "915ce070c15441deeacdd1a61811bbafa3794abeac58a2645c59c4d62054c331",  # AssignmentStatementAst
    "0.1.53.1.0.4.2.2": "9f78e96860e1afd2238db61ffd48b9e1319eb2fd116df9a339357d2e8aab098e",  # TryStatementAst
    "0.1.53.1.0.4.2.2.0.0": "8ef94d1ab0bd11005ee5ca35cc6ed24305b575cb845e12f874216f5226ed7f46",  # AssignmentStatementAst
    "0.1.53.1.0.4.2.3": "d10e785d799928727c255f91b57d0dbed1652230bed2a2ea0bf5df5dae4c0645",  # AssignmentStatementAst
    "0.1.53.1.0.4.2.4": "ff2313aeef277e9121d9b413d87bf9fcfb57e2b664d40c9ec0b2bdf5a9f55e46",  # AssignmentStatementAst
    "0.1.53.1.0.4.2.5": "7322e94f03dd5550b1f80de5d803851825649c84fa296141b32d392b6cd74e19",  # ForEachStatementAst
    "0.1.53.1.0.4.2.5.2.0": "6882b0a9e2d68cd94aac6ff136d2ec8511f64bc2e7e05de6148d257b2f3735d7",  # IfStatementAst
    "0.1.53.1.0.4.2.5.2.0.1.0": "cae8d179be55576f38cd250a287f6e50e5999ee071d0844d742382b814146f4f",  # IfStatementAst
    "0.1.53.1.0.4.2.5.2.0.1.0.1.0": "ac4c1429be70670f702196e6d9cbea640666503580cdb7ed3e9c6a6490111605",  # AssignmentStatementAst
    "0.1.53.1.0.4.2.5.2.0.1.0.3.0": "a5adcfed6debdc8a003d69a59db1a4060019d9f98fc29c59ed2630e581a70362",  # AssignmentStatementAst
    "0.1.53.1.0.4.2.5.2.0.1.0.5.0": "24d61d5aa4dee4812ff946924cd17f18e5b92054b39d4b4c7ab5a097059a32c9",  # AssignmentStatementAst
    "0.1.53.1.0.4.2.5.2.0.1.0.6.0": "d7abd4b7db39d6bfa78f30f1aeee3f38e1b0b3d77838d0b84ca203125abf3bc4",  # AssignmentStatementAst
    "0.1.53.1.0.4.2.5.2.0.3.0": "bdb01ca13f5b654119abf2e4ab6f2528b3ea16aada0f74b84668d6554ba254b6",  # IfStatementAst
    "0.1.53.1.0.4.2.5.2.0.3.0.1.0": "9a121d2efc9103c3c846120822ee0f83974e0f489c0617a08b4a5b73d6afac96",  # AssignmentStatementAst
    "0.1.53.1.0.4.2.5.2.0.3.0.2.0": "c98f29f47fadfed36d7423722aab4cc51ebeb99b7280b9939c28094a1e9a27c2",  # AssignmentStatementAst
    "0.1.53.1.0.4.2.5.2.0.3.0.2.0.1.0.0.0.0": "e32a336d84e11f5984a2b39f3d5124c02557aedc7619e5212df348759721455c",  # PipelineAst
    "0.1.53.1.0.4.2.5.2.0.4.0": "4d52086b85232a46e47aeb7a95b629bc34cd78c1023fa340b1ed54ee5cc63732",  # AssignmentStatementAst
    "0.1.53.1.0.4.2.6": "cbeb0d365a8ee5ec6574054869cf964f9dc39e48723f27b4dc07548f36d384ae",  # AssignmentStatementAst
    "0.1.53.1.0.4.2.6.1.0.1.5.0.0.0.0.0.0.0": "c666bda076e47a68f89474827861f6a4701d810637abcec877708039637ca332",  # PipelineAst
    "0.1.53.1.0.5": "a5d4cc271e34ac6b953cf9026ad4a9d29a7566e53a5fd5b1cf238eac1cda4596",  # PipelineAst
    "0.1.54": "ea4929866f0283833567e81d319d6b8fdb3dcddb3f8b0f5626895bb1064ff0b5",  # FunctionDefinitionAst
    "0.1.54.1.0.0": "8a0aebdfacd963e9760b919845650b82f5192a802a9639138d0ba199f7373a30",  # IfStatementAst
    "0.1.54.1.0.0.1.0": "f1967c5ef49628856f377007d647819a2dba0c04dbf06311704743f0207b45eb",  # ReturnStatementAst
    "0.1.54.1.0.1": "52deced7ce51b50ba196beef7eb329e5381a373c57cfcc42f249cd8735167296",  # AssignmentStatementAst
    "0.1.54.1.0.2": "09f8658d0e176a6d28594256fa331becafe5c8bc59af8db9930ee96077a45a83",  # TryStatementAst
    "0.1.54.1.0.2.0.0": "7f78283cd96b2fe9f84939c375783cec031e17e5ec76957fa4a35ed89000d42f",  # AssignmentStatementAst
    "0.1.54.1.0.2.1.0.0": "59cc4e8fb69e46d4f55aa38dc2d2da74b08210f7383d87652cb3d43198147c54",  # AssignmentStatementAst
    "0.1.54.1.0.3": "31df18bd2af5eff439efc4f2d67e3f618ed72038aa1633aa98ee3521c2350eb6",  # AssignmentStatementAst
    "0.1.54.1.0.4": "559b915627f86a42f05bcc6de24d2a3e842e5e39f041ffc62de09d74f58f9d54",  # IfStatementAst
    "0.1.54.1.0.4.1.0": "a3b166dfeca40ed84686d138e2094b51b0cb7db7815f2edd308ca1c8439c6593",  # AssignmentStatementAst
    "0.1.54.1.0.5": "ebe51125786b7b3f95059c32af509ec11ffff7147fa635c1cdd94b80a53da83c",  # PipelineAst
    "0.1.55": "a8ad0a36124d9a8b05a14cba394d1ec6df754c289c1a17ad4e1c2ce1656a9188",  # FunctionDefinitionAst
    "0.1.55.4.0.0": "d5191b91d9d9ec88dd61679050b4726df7743a8025f0066b31310de9df6cb403",  # AssignmentStatementAst
    "0.1.55.4.0.0.1.0.1.0.0.0.0.0.0": "d3610b49aae5182f355465eb7ca6d830604f2af1a1a806a4629685fa930da274",  # PipelineAst
    "0.1.55.4.0.1": "6df288a2e66aacaa2defc6b882b388335df0954f8cae4d548c156c0f624f2987",  # PipelineAst
    "0.1.55.4.0.1.0.0.1.1.0.0.1.0.0.0": "8b8e418cdf5895981abf9ebc08d0dcb4a8669b8b7775a63c42b967c6dc1ceffe",  # PipelineAst
    "0.1.55.4.0.1.0.0.1.7.0.0.0.0.1.0.0": "8b19b230ffb40504641d7cf81ad0f2aea20b5f2be9cf96f07c21562d10055900",  # PipelineAst
    "0.1.56": "001dfd010699e1dcbcbc71af6178e7f914a0f4b01d5cf94fc1e91272fd78c288",  # FunctionDefinitionAst
    "0.1.56.1.0.0": "7e946b647042a5a6e22143ce3777a1c02b5edcfc9a200e9cec58330f99dac0ef",  # IfStatementAst
    "0.1.56.1.0.0.0.0.0.0.0.0.0": "93a95dd9c8dd0ea76034780a7f0710347d1d25ad8696bc8cd3eb30569807babe",  # PipelineAst
    "0.1.56.1.0.0.1.0": "e46b2eda8f377d8fd962d74052b8ede5242c1283a05e4c708fb752b1247ec2e0",  # ReturnStatementAst
    "0.1.56.1.0.1": "76224f3d49d7d6d739a2f899374a44061174206b924b95d30b038c2fe2d2eed5",  # AssignmentStatementAst
    "0.1.56.1.0.1.1.0.1.0.0.0": "b4f26d07b6f1c8340fa5c777ec6cd68c2aeeed50fc2d0ae2e839ac2ba5b5d5b1",  # PipelineAst
    "0.1.56.1.0.2": "199f5b5a250c93940dbccbabdfa2ba2a81d31a1aaf5dd7cfc6a083939b79a59f",  # AssignmentStatementAst
    "0.1.56.1.0.2.1.0.2.0.0.0": "234c036507019fc4d2681c4b470f5d3a450a402ab2775a2a7c77538751ea2a28",  # PipelineAst
    "0.1.56.1.0.2.1.0.3.0.0": "d8fefc5d727370d37d62fb1d17040ac019cb1795f6701dd5c8ff0a0eda71e233",  # PipelineAst
    "0.1.56.1.0.3": "3b6b72d308af7471d05df2afa2189b4a97f6836088271b7a3dd1d5ceeb2474b7",  # IfStatementAst
    "0.1.56.1.0.3.0.0.0.1.0.0.0.0": "e28b1cdef40c31e6be1cfe2ff50cb33a8d3964b46770d74a949d49e2018904b5",  # PipelineAst
    "0.1.56.1.0.3.1.0": "ebe3bd9fba484665f2074698a11e887fa60b44b722af0a542f66b9cfd5b06ccd",  # ReturnStatementAst
    "0.1.56.1.0.4": "e5f9f2861ac62243f065b150cffb42b654342bf42568ce0444fddc36aac03e18",  # AssignmentStatementAst
    "0.1.56.1.0.5": "8507030155e57b2d38c405ddaeeb6ca8f52a40d0fc418966a0afcce9174fa60e",  # ForEachStatementAst
    "0.1.56.1.0.5.2.0": "b6d4b95fa19e9144bfed026a4b18433335656ce78c8a39fe94b5a959ce3ce80a",  # AssignmentStatementAst
    "0.1.56.1.0.5.2.1": "491fa5f8d446b86c89eab60134583e29c0da35d5cdfa1eca4bb56f5c931cea64",  # IfStatementAst
    "0.1.56.1.0.5.2.1.0.0.0.0.0.0.0.0": "e1be5ed62310458ec447983ef8275d7196e20d888f4f63f9c2bfe690be5201be",  # PipelineAst
    "0.1.56.1.0.5.2.1.0.0.0.1.0.1.0.0.0": "e6104e64b2773d4b397fbe898f8f74c7b7fd543f2bc503defa64678b26073864",  # PipelineAst
    "0.1.56.1.0.5.2.1.1.0": "b90f9f8f8876ac5695c0f9e246afd1d285ac3479e606311ed4b912db33bcc7e8",  # AssignmentStatementAst
    "0.1.56.1.0.6": "455284d28fd9c993cce7270953ebfed6f4bd442cb52ed8324af65906955ada58",  # IfStatementAst
    "0.1.56.1.0.6.1.0": "ef5234169c49477f486508df5efd325c056d17e22f62f6b4e4e57bcf38036b81",  # ReturnStatementAst
    "0.1.56.1.0.7": "fc4cac0d036f12c7cffd1e4caf7f04077fac1f046429974a0f4e4d70e56b7320",  # PipelineAst
    "0.1.56.1.0.7.0.0.1.0.0.0.0.1.0.0": "a306e8da8e197fef76da41a21bb6a14b632cf02be9831cc6545c95d05105a99e",  # PipelineAst
    "0.1.56.1.0.7.0.0.3.0.0.1.0.0.0": "d1725748b3704b56f0950c1c185c491aacdd05d1dff8b3e8f6e8e5618163d77b",  # PipelineAst
    "0.1.57": "5802723cd8f157ce1433e10dd42dff05ca38bea61519f14bafe0c15f2f45c800",  # FunctionDefinitionAst
    "0.1.57.2.0.0": "5890513bb29c43534cca1e45988bba6117b318f7c8c1ab46d5f85facc10c11a6",  # AssignmentStatementAst
    "0.1.57.2.0.0.1.0.3.0.0": "03ab30583f8720752cdee4fbee94a97bb8495a05ef65b21562fc91543201a174",  # PipelineAst
    "0.1.57.2.0.1": "ae8986e66116b6ec7dbfa8512de1eb12dc5a2ad5c6a039d14a0b533923ff0e98",  # IfStatementAst
    "0.1.57.2.0.1.1.0": "4983f7d63edd617178e9b2d90dbef1f2ca7381ccb7155b2db12ff09d777948cc",  # ReturnStatementAst
    "0.1.57.2.0.2": "7b0429fe116c6dbded4fe0d865602b826ac04cf20292d3d731705fc78f631cc5",  # AssignmentStatementAst
    "0.1.57.2.0.3": "bebd8e6d29a4afe28f58763c7a5549266bc5971d606843cc9b58b57f5261c6c0",  # IfStatementAst
    "0.1.57.2.0.3.1.0": "8455e084a579ca1b12038b4297ca06cf908b75841689a4664952657313e60a72",  # ReturnStatementAst
    "0.1.57.2.0.4": "d3b50addfa0d152b78a70ac933a6b99d4bae4b859b0655a6a9735d03123b2d20",  # PipelineAst
    "0.1.58": "41ce201e30782163330ba40830a2daa1f07b308a1954be8ce94015b0146325e4",  # FunctionDefinitionAst
    "0.1.58.4.0.0": "f1de1e149bb26f3d2d8f9f54a0b0cf299e7573849184c31a2a0d3397b2abac48",  # AssignmentStatementAst
    "0.1.58.4.0.0.1.0.0.0": "399168b6adba148c90000cfd49cf4bd31a03c4509fbcf001a026c861f91c9a42",  # PipelineAst
    "0.1.58.4.0.1": "55dbb6276ff7dc8ab7f34de1023511931c3f687f4be0bda356dec9906b61007f",  # IfStatementAst
    "0.1.58.4.0.1.1.0": "417065b026daef530be3b429090b874a2dfebe5e5e0c3e84498cc1d319565a6f",  # AssignmentStatementAst
    "0.1.58.4.0.2": "0a51272ec0a0a56f86c86c33f6345b2f86720ecc000c9ebc753b94ce0dec3329",  # AssignmentStatementAst
    "0.1.58.4.0.3": "f19b27a021682e62585fe8ba88264e9006fd942005d9279b700226af4a1d9440",  # AssignmentStatementAst
    "0.1.58.4.0.4": "c839270cfe298322a9a4db5b69607248ade9a3b0346059470ad72ecdae9769a8",  # AssignmentStatementAst
    "0.1.58.4.0.5": "cd0512ba1fae3132657da20d9fbcf73f47beb4385fd441e86dd2b5a6e55de3ad",  # AssignmentStatementAst
    "0.1.58.4.0.6": "cbbe1fbddd312855a77d29c0c219e7484186daf9cd279223f8647b2b9e8d486e",  # AssignmentStatementAst
    "0.1.58.4.0.7": "bcf2983ed77f900fe80943b859687ef68dae3d3e9cdd68e1f1b5f9a5f42e8c6d",  # ForEachStatementAst
    "0.1.58.4.0.7.2.0": "c9bd6826c18ebb954f0dd3d84d49b74675e582a0326277a6edf579230c291031",  # TryStatementAst
    "0.1.58.4.0.7.2.0.0.0": "b491fcdc4afbefa995fbbd843973a6664a0e548c5960417befb469c5efe4cc75",  # AssignmentStatementAst
    "0.1.58.4.0.7.2.0.0.1": "6093bed51df6fbd6e0fc1c4a14ae75bec433bc4ba6796590a44fd5a42afc953a",  # AssignmentStatementAst
    "0.1.58.4.0.7.2.0.0.2": "5eb0761e08cc570c1d08a655d9eccac374ca65c133e8804d99964df1bb15ec0e",  # AssignmentStatementAst
    "0.1.58.4.0.7.2.0.0.3": "a016f62cb6e353946c117b584037a2ade87bbfd8d121618bb454ff1fc3305957",  # IfStatementAst
    "0.1.58.4.0.7.2.0.0.3.1.0": "3612aaa38194e5e814a77d1d5083b230a459aaf6a58811784fa4ccffb70cee69",  # AssignmentStatementAst
    "0.1.58.4.0.7.2.0.0.3.1.0.1.0.1.0.0": "471c5a1497a9d8a00eca607925e4a814248cca01ed53828e53179db8cc83bc55",  # PipelineAst
    "0.1.58.4.0.7.2.0.0.3.1.1": "d34c7b2001dfa304213d15e2f04d9f440031445763d1ef1032339e593206c827",  # AssignmentStatementAst
    "0.1.58.4.0.7.2.0.0.3.1.2": "9436b4d7e975637096538d520d9b9e8526df879317a990e3bd39b145a9b483cd",  # IfStatementAst
    "0.1.58.4.0.7.2.0.0.3.1.2.1.0": "a5772ba15178b20fffed4f4f40acf7b3622a7bfda70fca100a1934849763ebd1",  # AssignmentStatementAst
    "0.1.58.4.0.7.2.0.0.3.1.2.1.1": "fab5b0d5733b7ca0e5a18935d49a38a4536ad56f9a41b24b40cb51c7244ef918",  # AssignmentStatementAst
    "0.1.58.4.0.7.2.0.0.3.1.2.2.0": "789057ee633abacb3cd13b2287f36c2c578ec90c965a70f0552fafccb8c4edfe",  # AssignmentStatementAst
    "0.1.58.4.0.7.2.0.0.3.1.2.2.0.1.0.0.0.0": "d47305bc498eb78a74252520ab22b93e48a200462212bcd0857bfefda072cdaf",  # PipelineAst
    "0.1.58.4.0.7.2.0.0.3.1.2.2.0.1.0.0.0.0.0.0.1.0.0.0": "b86bba589ae408e1cf6971a88de2f1a2ea6364b11ddd92b43fe3a7122c0749ad",  # PipelineAst
    "0.1.58.4.0.7.2.0.0.4": "54fea1285d84ec807f376ffe97afc01ab6707e34c1528fdfbb9bbad74dffde61",  # AssignmentStatementAst
    "0.1.58.4.0.7.2.0.1.0.0": "c779d65862c2679a3d0e776d48b289f30d3ae0d9c94252c56206a960c30121fa",  # AssignmentStatementAst
    "0.1.58.4.0.7.2.0.1.0.0.1.0.1.0.0": "e3edd03797ec0e3b6bbcf19e73c98fd8c867169f734923280c0b71598a69dfbc",  # PipelineAst
    "0.1.58.4.0.8": "a2bb27e9f0bb0f9835627400ff054fff34a506ee8efa207d7176804c0335f8dc",  # PipelineAst
    "0.1.58.4.0.8.0.0.7.0.0.0.0.0": "fd178a671856353026921b0c0d937226c4c8cf4638f5b87d482c3726cc1474c1",  # PipelineAst
    "0.1.59": "c47423dca175bcbff0ff17debf155c1ac39391dc478ffe62b7666faf9499ac26",  # FunctionDefinitionAst
    "0.1.59.1.0.0": "69ff16fe9f11cda89f5930e08cca0fce91c44f35696af825e0934f8a4282bd85",  # IfStatementAst
    "0.1.59.1.0.0.1.0": "3faf82030dfa17c81e985426213f4ed549b58837665a16112c2f979aefb5843d",  # ReturnStatementAst
    "0.1.59.1.0.1": "86b9c04da7cd2ea9bf23396974e357fdd76d56ec2e2631fa1814e88db835bf9b",  # TryStatementAst
    "0.1.59.1.0.1.0.0": "cbcffb909bbc7da9998b17af9633356aaa34624eddfcf3a937a97388f2c58d65",  # AssignmentStatementAst
    "0.1.59.1.0.1.0.1": "d6024db7e538e59e312b8d644081fb1708d2d673dcaea7446158c9fd08354ebf",  # PipelineAst
    "0.1.59.1.0.1.0.2": "59aae9ef4de2ddea191fdc8051e95203308993272961f919e59277af98b9558b",  # ReturnStatementAst
    "0.1.59.1.0.1.1.0.0": "f11285307a896985ad166b62cb620f3db691262a8a6abdc32c8f8ceecbdbcac4",  # ReturnStatementAst
    "0.1.60": "5f5f4d44e6a4ccdf23e99192a9860606b4610964504016018bed75dff11aceeb",  # FunctionDefinitionAst
    "0.1.60.1.0.0": "bcdffdd619986e6b212d55ae688d1e19d59678f111f5eb7dab1b0f5f4dbaf418",  # IfStatementAst
    "0.1.60.1.0.0.1.0": "d912dfeae59b6f3e1714fcce54ff444dab0b02c0ebedf466ae12435e7048f225",  # ReturnStatementAst
    "0.1.60.1.0.1": "6bfcd9df368fb8afc15d86b2a50c91237b751ea8dfbf1a735b60f8057a1f2304",  # TryStatementAst
    "0.1.60.1.0.1.0.0": "0a093d8cbdc6a4c67207638d6b38ac76fce139b0f4dafe94d7e14e1b8cb8ad70",  # AssignmentStatementAst
    "0.1.60.1.0.1.0.0.1.0.2.0.0.0.0.0.0": "6b394126a87adf5916b82eec8ca90a706a73b5d0ed949b155a4f74beb514d16f",  # PipelineAst
    "0.1.60.1.0.1.1.0.0": "7bddf3266cb5a87cea03430f57ecd62fd6842b883a6057cec5018018ad853249",  # ReturnStatementAst
    "0.1.60.1.0.2": "8f008fbd013f21b1120eb582cfd92c76e4653f5f503dc89b8dd8e95ef9727a47",  # AssignmentStatementAst
    "0.1.60.1.0.3": "6a466fac0deb315881248b4b93b48ed46b0425be4379f4d855e8f3f6df02e492",  # ForEachStatementAst
    "0.1.60.1.0.3.2.0": "93a1cf6c9f0792822f411650ca5d50c650ca01684fae5c64f2299a6a44d79ef3",  # AssignmentStatementAst
    "0.1.60.1.0.3.2.1": "0f09c04ed7601d841938cc4d308ffc0b7d5b6048d27a17c3d84c75445f64618b",  # AssignmentStatementAst
    "0.1.60.1.0.3.2.2": "606e679aa6efca3134e45048ad7b0c6b81329bfa67e8381d3d3db01e2a5ce4cc",  # IfStatementAst
    "0.1.60.1.0.3.2.2.1.0": "211b97e74232f40b5a1ec645074a2e4c10de09bbff9e9a2bb68838d0a1c940e4",  # AssignmentStatementAst
    "0.1.60.1.0.3.2.3": "06e956863a9f77238ecb303c114b1792e95985463ce3b1c88622aeaf16806ac6",  # IfStatementAst
    "0.1.60.1.0.3.2.3.1.0": "01ac92f5e61bbeb251dabcb411d88a09b3ff25a7d8b661e1bca6698b53be9124",  # AssignmentStatementAst
    "0.1.60.1.0.3.2.4": "6e662c436c0193cb7ff500e486fe96af2889c95a0cfc87d82c4e668860797272",  # IfStatementAst
    "0.1.60.1.0.3.2.4.1.0": "66534b5b14a97f8c977db71246e4ea1a15092fd6c4bbff3c08f79e36c7edd19d",  # AssignmentStatementAst
    "0.1.60.1.0.3.2.5": "f375e699d49dc38bfc9b85cd4427a5d213728ad86326a380dbfaa52669666797",  # IfStatementAst
    "0.1.60.1.0.3.2.5.1.0": "51d5ddaef30db7fa89e55f19c8ac4f1e410454c450740b31614eae55df3c0579",  # AssignmentStatementAst
    "0.1.60.1.0.3.2.6": "bcfa738d6738d9e83a692c791a719a072cdc71bef1d70e6e567d653de9be3d70",  # IfStatementAst
    "0.1.60.1.0.3.2.6.1.0": "65454d2fee5f817b046c87d11385903c1e7002c5fd4aa620bb0b4dcc04b9c0a8",  # AssignmentStatementAst
    "0.1.60.1.0.3.2.7": "6286632f31dc56b45b9f606c8ca6f61574879f9db4f599757cee36b8bcfccde2",  # IfStatementAst
    "0.1.60.1.0.3.2.7.1.0": "a5507ee9434884dea8c367a84d686d7522e51029889b3817d6c19a18b02b7656",  # AssignmentStatementAst
    "0.1.60.1.0.3.2.8": "bd063384278e4cdbecda3ffd5d040e798f2b828f99dd83145d35cd02e7d985f2",  # IfStatementAst
    "0.1.60.1.0.3.2.8.1.0": "dfb78e4aff94c43f48f44f4de6ea4c6b4f0054446cd48746c6de897b9756d9ed",  # AssignmentStatementAst
    "0.1.60.1.0.3.2.9": "291a5ffdab79ff867166b3224152fb296fd2a9d3e277f4ddd80c3722ac7e125b",  # AssignmentStatementAst
    "0.1.60.1.0.3.2.9.1.1.0": "c3c748b61b11d4060c46636144a99ec9bc5d80a231d5305d1ac7d4efa165b0d6",  # PipelineAst
    "0.1.60.1.0.3.2.9.1.2.0": "148cb51047e863bd1e642d97ac67a357a41b83f1a32e58317fd479a750952b69",  # PipelineAst
    "0.1.60.1.0.3.2.10": "91c2f19b0481d260daa0c4d043164b833fb0a1aebd45967c4ef2568cf10696c1",  # AssignmentStatementAst
    "0.1.60.1.0.3.2.10.1.0.1.5.0.0.0.0.0.0.0": "69ba913250fd12a1899fc392d7ee1a10363311d0a053089691714a75b2f41a06",  # PipelineAst
    "0.1.60.1.0.4": "77baa062cf32a12f06c59f6c1a32085d35b9b506fc3c3bc09b857006c4f56167",  # AssignmentStatementAst
    "0.1.60.1.0.4.1.1.0": "e7a5e4095a5e033e67e0ee94dc1856e31213d5861a11d8c07e5d0baca98703bb",  # PipelineAst
    "0.1.60.1.0.4.1.2.0": "7252f0c9d5b754d18802d6098623fc0ab9be311a40745b3c9e8cda2f6f613918",  # PipelineAst
    "0.1.60.1.0.5": "1399993293ed35bf0711465a5fde77ec56a746b120c6b907fad7bb032362a7dc",  # PipelineAst
    "0.1.61": "5bd7ae3fe477d787b999e666cdc18c322ff434ad605adafdf7443e1bc81bf810",  # FunctionDefinitionAst
    "0.1.61.1.0.0": "15aa7cd37118c54af9257fb3ceaa0223dbd52bfc24a8e287b58376adc9f0454a",  # AssignmentStatementAst
    "0.1.61.1.0.1": "82c7cabb3f0da5deb96d234cb851db95c1ca49844cde95a209e7db5974f27a95",  # IfStatementAst
    "0.1.61.1.0.1.1.0": "b52c06fcdd50b023324d279650993822d3b62a3f0dc2c89a16408f373635bd70",  # PipelineAst
    "0.1.61.1.0.1.2.0": "50aaf9d77e2f918108bd3969271f1c10935876324227f71979b52c47ccb77fd4",  # PipelineAst
    "0.1.62": "f2c5692f024a1db442d48a68fdfdeebdddc9492bd240dcabb37270b8aae5d80d",  # FunctionDefinitionAst
    "0.1.62.1.0.0": "96b5b5d4388baf010d11d64540c3c8afba2ec5e5c3e9d8e8f9f17d5a24ff7d3c",  # AssignmentStatementAst
    "0.1.62.1.0.0.1.0.1.0.0.0": "82b5fbd0ca49f8b129f3e75405e975ffa731482f4185493e7356e590dc328fec",  # AssignmentStatementAst
    "0.1.62.1.0.0.1.0.1.0.0.1": "588a123fba9bdd728cc3157e2e19f048b5e4012f774bd42764866f0891a829aa",  # IfStatementAst
    "0.1.62.1.0.0.1.0.1.0.0.1.1.0": "0ee8dd0d45d60f1e7984fcaa8f115a279bb43e23977cd72653a9b8f365919afe",  # PipelineAst
    "0.1.62.1.0.0.1.0.1.0.0.1.2.0": "e16fb96efafd4e8ab7a64f52d6e391254816cfb69aff84b7d2aa751ea81cf774",  # PipelineAst
    "0.1.62.1.0.1": "a7302a18a57b408f51028e39e1e23d05e28d3d1c767cd58c592db91c8835cd9c",  # IfStatementAst
    "0.1.62.1.0.1.1.0": "b4eec8a35ecb30ac3f85953ecf331c7dce2eac5c10219c0a63b9db05c5200aa5",  # ReturnStatementAst
    "0.1.62.1.0.2": "a7cd85496bf660def512af6e3b636a5e75ff881e24f8ff0512253f9ff5e526cf",  # PipelineAst
    "0.1.63": "67c6f0a6c60ffe9519878eb611a725a33f8185f6c57580b0fdd1f2a6106a98d1",  # FunctionDefinitionAst
    "0.1.63.1.0.0": "7e96d72edd69b766ca91691c601d165e0631b760f68f7ff78c07ab1193200c00",  # AssignmentStatementAst
    "0.1.63.1.0.1": "3546d1ffbd108f7d174f1c056d591bb301fd4153cab20eb182fc220a641f708c",  # AssignmentStatementAst
    "0.1.63.1.0.2": "8c9826c434b7af861ebe1347c0a7b0d490652e99036535ea64b030c70f3bb93c",  # TryStatementAst
    "0.1.63.1.0.2.0.0": "5eb64936181ed781f5aeaf115fa653b0da26744d413a818eefe55312b1c2b1b2",  # AssignmentStatementAst
    "0.1.63.1.0.2.0.0.1.0.0.0": "bee1a6f17b4798f552ca256af5fcc2975c6d1b6e7dfa5d4875f72140d46dd58f",  # PipelineAst
    "0.1.63.1.0.2.0.0.1.0.0.0.1.1.0.0.0": "707637a3c965be86d7d7b7c2472c8968d32fa6b1e816214229867b1d4f95b6b9",  # PipelineAst
    "0.1.63.1.0.2.0.1": "adb0903383e745788002cf9dcb940f25364d855cf656e782b5fc31cf51a2c7b5",  # AssignmentStatementAst
    "0.1.63.1.0.2.1.0.0": "c10d415f28a81f4d55d7cc73dcd94a11e44125dbeef5df8d9e13a41bdeb8c424",  # AssignmentStatementAst
    "0.1.63.1.0.2.1.0.0.1.0.0.0": "76e7e4f4f0b40001cf2b03e8fe0997abc1e0b760ea094f4e361ac72d26bbe2a6",  # PipelineAst
    "0.1.63.1.0.2.1.0.1": "12adc032afdee36a647d1accf1831bb6a524eebba129d162c2fca393f802d633",  # AssignmentStatementAst
    "0.1.63.1.0.2.2.0": "4b95435ef44e82809312b9795c7dbdcb24bc4ac0da6e2abe4b97f55eb67301ab",  # AssignmentStatementAst
    "0.1.63.1.0.3": "0eac18e1096ee18192c620734ca363dd64fa06b4a7697087d9840a878f41c8f8",  # PipelineAst
    "0.1.64": "4515014e5dbbb898cbe2b47bf9ade6b3d437da8084bac3e93d6f5d088225ed6a",  # FunctionDefinitionAst
    "0.1.64.1.0.0": "8269998be8aaf81c6a5286d571272260024aa1b167e24c91b57b38f5bd0bde55",  # AssignmentStatementAst
    "0.1.64.1.0.1": "a7d605d5797cf7154efe3172313f5e00ef0824635ba18ae10b9c6c7795cd3769",  # PipelineAst
    "0.1.65": "97322f263e70fc6701eeea620dbc9ed2fa99190d1cbf36acd3e2e645ba75aa32",  # FunctionDefinitionAst
    "0.1.65.1.0.0": "16ed62a09d53b95e330f929e30c1a9c5e4f80afb88fa384ce0c50e786008e382",  # AssignmentStatementAst
    "0.1.65.1.0.1": "cc9092ed39732eb1cc76754376be83a188d8022210f45f77f53b6242c9a4488e",  # PipelineAst
    "0.1.66": "220c06ae7d95c2f4214e41ad4d41d11f9b66d8b8e4c54d42af0045fa664e5e2d",  # FunctionDefinitionAst
    "0.1.66.1.0.0": "797f758c5d7538ad5edb9b04a87b4ab069f8a90fc9d130a216fd28957e885c53",  # AssignmentStatementAst
    "0.1.66.1.0.1": "34c2e9ce428bf5af21241be86b6766b3a58c0599002fdbfeeb945114ba50db5d",  # PipelineAst
    "0.1.67": "35e09d87f99af98c35bbf220a41a737cad95e56789a0ea3d317132fc4c33cee4",  # IfStatementAst
    "0.1.67.1.0": "83fc2617cda8da888b1f41d4f0b4a96a8e93724ea6b928670c2cac713fcb3919",  # ReturnStatementAst
    "0.1.68": "906f881553be995b47fb897b5c0411caaff22acde8c172bce642e9d604336128",  # AssignmentStatementAst
    "0.1.69": "1ac8860ada0ec13c359c8d0af543eadce422acf6819783c372469b4522f58881",  # AssignmentStatementAst
    "0.1.70": "beb7236ebc1ab601cee30e995fe366f9e6717a60ad749994a4f71bef50dc4013",  # IfStatementAst
    "0.1.70.1.0": "83c378784ab0bfd5b2512a6becf50b47c9940883ab6e91c3d15c6933eb23695c",  # IfStatementAst
    "0.1.70.1.0.1.0": "bca3f34d7e62e8bf6b8b12fe64a49e9a3dac139239b28a2108eb815761076f6c",  # ThrowStatementAst
    "0.1.70.1.1": "3c7c91f135d1b27a702264063c45a1f5121115525888afb12cfbf93ee3646c54",  # AssignmentStatementAst
    "0.1.70.1.2": "2fbcfcfbd13f3ec0614dda99e7f543e373fa0f6bccc3429a7a4098e04f71623e",  # AssignmentStatementAst
    "0.1.71": "d7a7ef8665b2aa49a604e30e36dd02731253ecc51d9f92145126f57bcd76d94e",  # IfStatementAst
    "0.1.71.1.0": "51421127ed6555c3f7b65e209f4ba66df778b1a55e6b46025f27299ffbd9d8df",  # PipelineAst
    "0.1.71.2.0": "cec764cdacf0de0977a597c442c8cb37e2a69e37182db2a1785bcaa491114d77",  # PipelineAst
    "0.1.72": "b66081c1547eebc1390a309f6745cf1ab915126a68885506cf530f982d9633c5",  # AssignmentStatementAst
    "0.1.73": "72429cce736dc936408f9bd7d69dea0f38fb78988d7da966b5b1e007b0ca3889",  # AssignmentStatementAst
    "0.1.74": "ec4fe02c0c2bb149f01ea851643b51a56934368d98af10e19c40ca913ea18b0e",  # IfStatementAst
    "0.1.74.1.0": "cd2a13757befbc1713f99520c4fa9af16ae3f605ff71700da94767e3677e8c35",  # IfStatementAst
    "0.1.74.1.0.1.0": "70edd451712dd4d7775a189bb0f0194eeb9c9599a3199b8d973c3508f5a3b4b6",  # ThrowStatementAst
    "0.1.74.1.1": "d7f479a1f466771cd2b7bacc741d163b04bee1a0a18254693361d8db4c02605d",  # AssignmentStatementAst
    "0.1.74.1.2": "86b8162f1fbf93bca23556a63a359f98bb3df4e3e2fa01c7512cc3797a7e640c",  # AssignmentStatementAst
    "0.1.75": "68bead04feaaf4cd39f68714bd1a14731e3af808c687860bcc4c428f23594e9d",  # PipelineAst
    "0.1.76": "147a2b65c2646569da690c3374de81353ac752e42a29eb7549bd3bd2f1506483",  # PipelineAst
    "0.1.77": "ddf9156f2f4130e489b70eec60cba772939fc78c2e0fcc9d77902ce1765f7c2d",  # PipelineAst
    "0.1.78": "b0da30f0c2b2843557db4cfe53b6bf8fa20e52cc633dca538c11ce2e21798d8f",  # AssignmentStatementAst
    "0.1.79": "161a0ac3da709d66472c469f4375d2b0e142f21578c071937be3523e726ba9d0",  # AssignmentStatementAst
    "0.1.80": "65722d76c6c96a3474ae055de3959f7e1bbc21518dd02fbe7a06b207c72ce530",  # AssignmentStatementAst
    "0.1.81": "09be3f13b9025ecc8d6f1375f2763f57862d054d8c76881329768ea1a2e99e06",  # FunctionDefinitionAst
    "0.1.81.4.0.0": "a4a1094c5bcd154af55bf0f01327893c480162643c9d4036fa9d178b4805c999",  # AssignmentStatementAst
    "0.1.81.4.0.1": "0d8014c2bdfd4cc2fa339991ff347ff4c1b56ef42b77b18738864dc58c092a1f",  # IfStatementAst
    "0.1.81.4.0.1.1.0": "9bab9c1564782d030f7ad2cfd756d08c5e86b0b50503ac5d1f900c7b94522222",  # AssignmentStatementAst
    "0.1.81.4.0.2": "08c10d89b351c5d9c255bb05bf25c200743d74c398c597e9098f556d6cca103f",  # AssignmentStatementAst
    "0.1.82": "68e57e0d16f8e198fa0a23dd2898166b2f507b81e19023c289f04e22aba36f24",  # FunctionDefinitionAst
    "0.1.82.6.0.0": "d91ce3e84d7f36552a9b231980661e9e57de84fdbfdbf30a1311a46a8a522935",  # AssignmentStatementAst
    "0.1.83": "554e6a8a4fae29a915fede96813554cf76b2bf472125160966872ffd9776a9f6",  # AssignmentStatementAst
    "0.1.84": "620f18755b00a18e84e3b78b103bfc67af5d4ea5a76dd624ff25695ad1fc5874",  # AssignmentStatementAst
    "0.1.85": "227c1bf6dc2668cbe0b71422cb445d9c76a61b8223592f00b3f1701ba966745b",  # AssignmentStatementAst
    "0.1.86": "b66e958169b4e08c78135253cb441d1738f71507357b4dcb4fa2e1f6e37ef6ea",  # AssignmentStatementAst
    "0.1.87": "25317f355412090641850e448f6729098f96bbf3051fd5b537fd7119c7c0d196",  # AssignmentStatementAst
    "0.1.88": "a3e9e23283fab791574e02a6ca7bce39a7e633b9e95e4a446b9c0c96a6ace2dc",  # AssignmentStatementAst
    "0.1.89": "e93db4e6732bc9d693b8577941033ba01ddca3daf7325605e5d6bed06be7c792",  # AssignmentStatementAst
    "0.1.90": "f66e858b3e9dd57fb30e3d9f4e5fb1d3ac3246a80fa63e34bb307fd93a3cf499",  # AssignmentStatementAst
    "0.1.91": "9898e6471b9a4edd6a96bff70aea06a6671d19984f2b246d6f53e352bb41ec95",  # AssignmentStatementAst
    "0.1.92": "23e3c27f1edd457f3d4d6c16873375a492c37b9ef332b18ce9efc46ebaf12237",  # AssignmentStatementAst
    "0.1.92.1.1.0": "6ae3d31946575b611b63cd627ec8f12e7fb61937c9ca4ca5f802d2351015551e",  # PipelineAst
    "0.1.92.1.2.0": "b5c4be6be3234046464c0f5270eb856878afdcd370d54ba8ce02b572c4bee7d4",  # PipelineAst
    "0.1.93": "5ceeeaa8c1fc7ba69f8f204b8403078fabe55bb3adbb3a2f3cd50b9a4dd4ef54",  # AssignmentStatementAst
    "0.1.94": "95c52859d5bb88fd93d21b48dbc74463d988f4680c4db3db72496284c1f5f802",  # TryStatementAst
    "0.1.94.0.0": "87366ea1a0ff7e251944e74502b6b1b44f53a5b9d8b35c3e6a6acdd145af9e9b",  # AssignmentStatementAst
    "0.1.94.1.0.0": "791aff15abf2feb8d15127eab99cf0c298de7ac186a17a489a3f8f891d2850f6",  # AssignmentStatementAst
    "0.1.95": "761f28fe8ab6a54debdb36f18baf30360db9abb96cd0cf40ed9ad8f69db7ffd6",  # AssignmentStatementAst
    "0.1.96": "6d7543d7bdb92097718a8ab02952c8bce6bae0164b08819ef7739b58995862d7",  # AssignmentStatementAst
    "0.1.96.1.0.0.0.0": "afd2b0bb5844321eb4c48053cd154baa936b467ae0c74da9962d7e6fcd88fce2",  # PipelineAst
    "0.1.97": "e045543b8c480ef4388dee1d3dc6a3c0df2b2b9570b58424eb57973abde4121a",  # FunctionDefinitionAst
    "0.1.97.4.0.0": "d5a995085c6a8abf916d108aaaca1f579c64098ed3715efdb81dcafbec123f41",  # AssignmentStatementAst
    "0.1.97.4.0.1": "f8267832d291b7bd6e9f4d64cddbd0070c8de9ce4e8e38d25c9dcbad6c5bb197",  # AssignmentStatementAst
    "0.1.97.4.0.2": "39899585907420ba31a99283d64d5dfadaaa2efe4b6e0465bc71ae2278972cba",  # PipelineAst
    "0.1.98": "1e5a6b06cbfdc96c7e4c9ccfd85a0c0ef6b725c4adef85240d7891bbb73ca893",  # AssignmentStatementAst
    "0.1.99": "589032503970e7aaacd94e98089a924b02a108dce55d5a3ac4468e4a5834e9c3",  # AssignmentStatementAst
    "0.1.100": "165021ab6cca818491aa89e3be37f083440725a04bef97ec321040a3726681d4",  # AssignmentStatementAst
    "0.1.101": "7578c5d579663dce42d5b4e8ee098800997df86b554f850d315cf744dd8890b6",  # AssignmentStatementAst
    "0.1.102": "f1f7a8637c7a429a7ae6e98b809c695297a7c5c5e3d969366f562c2fecf4ea43",  # AssignmentStatementAst
    "0.1.103": "a20ef8e9f12c2d8a4797c50de252544a1d0f7e1de6f84746f63514ad603a0874",  # AssignmentStatementAst
    "0.1.104": "bc0cd6fcbc1350ea44ab59316f06a300a19e23a1673b3d9c8935460190e0d11c",  # AssignmentStatementAst
    "0.1.104.1.0.3.0.0": "f8369c52345ae5652f221eebe4fedb70284f15803529824f9534df436e2bb89b",  # PipelineAst
    "0.1.105": "7cf966b19e89aa2dcbe62b48bd84b618d7a130e56272737c05a8791269fa9797",  # AssignmentStatementAst
    "0.1.106": "6191e467c0816a96f94393c3bed9aa609846340dde84c567d233c61536833185",  # ForEachStatementAst
    "0.1.106.2.0": "175a51daad9c02d1e5466de47422c12ce596f821b5f8a5a470f808f830c8d551",  # TryStatementAst
    "0.1.106.2.0.0.0": "fb23c9636aa9e65d58a12181a9a641fe1bb9390cc49f95ab9929178ab4b01e7e",  # AssignmentStatementAst
    "0.1.106.2.0.0.1": "0a3fa59f8a020f234afa7f20a1546d37b3d0ed266490acd11105c2acb9955ed0",  # AssignmentStatementAst
    "0.1.106.2.0.0.2": "78982bda5a5328024aecb0b41e7099fdb10eaeab6d64eceeb9a619c724c7d832",  # AssignmentStatementAst
    "0.1.106.2.0.0.2.1.0.1.0.0.0": "901b40fd76d90b936963f53096d7546166ae0177c85201e6c9a80e22baf59b0e",  # PipelineAst
    "0.1.106.2.0.0.3": "782686aefdb84e8948798b53e950c0f7395025a13e7e91aac4ec2f0eb3f39e78",  # AssignmentStatementAst
    "0.1.106.2.0.0.3.1.0.1.0.0.0": "a2f009718d64a9d4428a4824925b8d9dc60c8569f31540ea563eb83175e5e3ca",  # PipelineAst
    "0.1.106.2.0.0.4": "0d6a03660de58a71e0bacae71dc2ce99335e300eeb5679afd508b2f5b0645287",  # AssignmentStatementAst
    "0.1.106.2.0.0.4.1.0.0.0": "5e2158a5e264e1e26af031828245702a1f5149c308e0512a4ef9310dc34e8fca",  # PipelineAst
    "0.1.106.2.0.0.4.1.0.0.0.1.1.0.0.0": "057c07b2c9553589b27caff1efa1d719a691b321c80959d95a63addb19611c19",  # PipelineAst
    "0.1.106.2.0.0.5": "faf6216b7dccf84c875b085e218178541654fbfe51eb6cce9a908e1ea09c149d",  # AssignmentStatementAst
    "0.1.106.2.0.0.6": "b009ddc043cf0b72a97c40617d5611478616627a0b328c8a4ffdb8fa62c54c61",  # AssignmentStatementAst
    "0.1.106.2.0.0.7": "ac5012cdf30f8deb7f35a9cc86ccd0eb001ea596c7568e615013dea682dd6aa5",  # IfStatementAst
    "0.1.106.2.0.0.7.1.0": "4c583145737c507ed1ad18d9eb607ff5c3a221ee326d60d0d1b123b076cbd459",  # AssignmentStatementAst
    "0.1.106.2.0.0.7.1.0.1.0.3.0.0.1.0.0": "89f826acf54efb4f9f20640b8b82f30c2eb88f4f9594487ee7a9bb696ac7ccbe",  # PipelineAst
    "0.1.106.2.0.0.7.2.0": "7a7293b271793bece4029211c26e47dc908d64e3f98adf32b788484ef2f4b5fb",  # AssignmentStatementAst
    "0.1.106.2.0.0.7.2.0.1.0.1.7.0.0.0.0.1.0.0": "fca22a94e3d898190d7757292f12daa23218cda1bb1035a7507adcdc7087046a",  # PipelineAst
    "0.1.106.2.0.0.8": "e0a372d3be6479a9a09ab3a6c4f4b95cab2a1d93d8d34026ec461d6722af3c75",  # AssignmentStatementAst
    "0.1.106.2.0.0.9": "b89de4262f45c6836b86b9c87167bb115dd78361cb4d2c52537b4f2d90465574",  # AssignmentStatementAst
    "0.1.106.2.0.0.10": "b250566d2ddfaba8ea6c5796b2880dab3c107a8bb6a0bdbe562433d66a180245",  # AssignmentStatementAst
    "0.1.106.2.0.0.11": "8e04f66c65970d0d12452515152bbf0b44fd5e83519c9c4c0c22714f5d362965",  # AssignmentStatementAst
    "0.1.106.2.0.0.12": "01cab739b46c72ecc59db4cdb170cb58f21081f522b8092b1dd7e6ca141375f9",  # IfStatementAst
    "0.1.106.2.0.0.12.1.0": "483b23b96d9f27d62409883b12fbf6f80bd9adb8b463b297d2adc425db77c2d5",  # AssignmentStatementAst
    "0.1.106.2.0.0.12.2.0": "86f1d9e48d2e81434a9b5f7da8c383d2fde26ca0643c2282f91357b3ef304a37",  # AssignmentStatementAst
    "0.1.106.2.0.0.13": "1488ed2812ae2805b55365c391a544fd55072aa34876c0f8fec55f7be685f684",  # IfStatementAst
    "0.1.106.2.0.0.13.1.0": "96031869dd631a205500c4fe89f48db02bc1dd95a22d2bbdedd66a2a5657e1f5",  # AssignmentStatementAst
    "0.1.106.2.0.0.13.1.1": "f4e53a0ceca1f67c02431348670ab8cc1ac1329d4b90a527c4e992b91d37f394",  # IfStatementAst
    "0.1.106.2.0.0.13.1.1.1.0": "6562239a59229611729a61f26fbd4e1d7d91564f22cf1a1d02e977be8099876d",  # AssignmentStatementAst
    "0.1.106.2.0.0.13.3.0": "1bb555439a702a8f6f3b315a9b18f32121e1c5ae533e02c1947d4bdb96b7c1ea",  # AssignmentStatementAst
    "0.1.106.2.0.0.13.4.0": "9f032edf3e296241dd6d7919944d5fc9801e76e5995c7986cbf0d7573587820e",  # AssignmentStatementAst
    "0.1.106.2.0.1.0.0": "057adef8e38738cc8332f5978e4745a9cfcb7bfc337b03e8d9c0780cfc979b0b",  # AssignmentStatementAst
    "0.1.106.2.0.1.0.0.1.0.0.0.0": "6aad848e211b64c77b5b7913d83e5ae474abdb1e3fce629eb7de0bca3618d25d",  # PipelineAst
    "0.1.107": "99b02e822ced9aa3ded8ae75404e302da4182086a2a1575e88adba21fdfa2e52",  # AssignmentStatementAst
    "0.1.108": "78a3f9648e38cdc76e211b710e7bba7780f445baee419ed9324a57a5a3e15070",  # IfStatementAst
    "0.1.108.0.0.0.1.0.0.1.1.0.0.0": "8deb4587e361b1e6597a93369724f4109759bad9b85de70dc2d1672186036dad",  # PipelineAst
    "0.1.108.1.0": "39810281a36540f8d8544dcfd9133a206ec9c1219b8e2b637527e05616a5c905",  # AssignmentStatementAst
    "0.1.108.1.1": "4e9a1605933fff6cd7a7b404285637a299aee74b6d6c79f293025c8848b84e9d",  # AssignmentStatementAst
    "0.1.108.1.2": "7802a6a51050c9b56f0e1e72d55943919b2202ed0c381b17d31bf1763bf15bea",  # AssignmentStatementAst
    "0.1.109": "7fc50fc44b63c76638d3d9c70915cace56de1d4684f474862868de1b4eb5ee17",  # AssignmentStatementAst
    "0.1.109.1.0.3.0.0.0.0": "4c5e51f40f8d187361e1d5e37c7b84b155e70edfa5fb925aaa3e14c3e9391ee9",  # IfStatementAst
    "0.1.109.1.0.3.0.0.0.0.1.0": "a8a381a4af9974795399e5216e7799ba765ffc05f26a7738031322dd1c8d2b45",  # PipelineAst
    "0.1.109.1.0.3.0.0.0.0.2.0": "a05572d288f191636e44f7e42ece8d5dda23c55aee363e88b934bd325968bbf3",  # PipelineAst
    "0.1.110": "b2e18a2b0ac88bc83d9f343c7b7747ff9969d8e9144d90ec423b29041483076d",  # PipelineAst
    "0.1.110.0.3.0.0.0.0.0.0.0": "340ee053b0dc266c18db76e61d2f9f7811347c6bb9c33499a01c8c2d6b7a5e12",  # PipelineAst
    "0.1.111": "3a5cadbe65ff2dee1a144be7dd25bdd27510b27e72288da4fabdca2608e24b99",  # PipelineAst
    "0.1.111.0.3.0.0.0": "e780cb200543459c6bd57f5df8ccd33c64957fa24a5a32eeec3b38c7cc737aa2",  # PipelineAst
    "0.1.112": "d254a0a5c0b83704c18777d7e2fb3fff264c15cb8b1ab3a0c245ac0864eaf9b4",  # AssignmentStatementAst
    "0.1.113": "f14445417901a0179ba5992510f8499803f2aa64faa34c1323909e1796d6d9c9",  # AssignmentStatementAst
    "0.1.113.1.0.3.0.0": "776480901bdbc929b32eeca88fa795e1829a92d26431683dd6bc83e0645033b8",  # PipelineAst
    "0.1.114": "f06fd066d45b2211fcece489e3cef3e001a01427baf3a78733e277d3482a3ffa",  # AssignmentStatementAst
    "0.1.115": "75eecdffc4316c454deae2e2d7a5b8f652020ea5a0bafdf81aa801d1550e994c",  # ForEachStatementAst
    "0.1.115.2.0": "ea35ad11666cccacef6402eda9005ffb5f67d509f1e5b78d649830a192d888c6",  # TryStatementAst
    "0.1.115.2.0.0.0": "331e16667b006ab9688b9877859a1f21f0e7109c5c2d913308d02fea1a53a8e2",  # AssignmentStatementAst
    "0.1.115.2.0.0.1": "7bee610c9a3ea4765bb86c400c6b6c2d618b84433e9245ab61e87849eb02b446",  # AssignmentStatementAst
    "0.1.115.2.0.0.2": "ef9553730e4d45150971590d9ac1ecf8f7c18eb8438de3a7503b522022a22773",  # AssignmentStatementAst
    "0.1.115.2.0.0.3": "c1d429801ff4930dd5758b94193b259f61701f260045b34f256b7f2939fd9d1e",  # IfStatementAst
    "0.1.115.2.0.0.3.1.0": "fe9e16584766838a6de114ae4d30fa454b70f669cff42853460ae8234f8d884b",  # AssignmentStatementAst
    "0.1.115.2.0.0.3.1.0.1.0.1.0.0.0": "5abb1a24674f55d790be87bb20a42558f037205d97d147524bd54e3a7d4e57b9",  # PipelineAst
    "0.1.115.2.0.0.4": "08a660a32838a70b7aab338e9abce9f6d7c23138ec7b276326426d714a970f2e",  # IfStatementAst
    "0.1.115.2.0.0.4.1.0": "a4ae6c2ab33b8a7ac2f61619d3e1b616411ff893dfbd1686c532a3261a7ee1b5",  # AssignmentStatementAst
    "0.1.115.2.0.0.5": "6cfeaef62c76679f0e29c3fd7ae229dad5b05194df2387b31a3bd68191dedd9d",  # AssignmentStatementAst
    "0.1.115.2.0.0.5.1.0.0.0.0.0.0": "598176b6a00f307889321d470811ca71d44b5845894285376da952c7776fe9a3",  # PipelineAst
    "0.1.115.2.0.0.5.1.1.0": "5a3ee1716e2cc65804a726be79dbce33eb19304afed66101f8094d034b633182",  # PipelineAst
    "0.1.115.2.0.0.5.1.1.0.0.0.1.0.0.0": "8951ba2167d068ff31ceaa644efc11f3f8162e5b06a372bcee22d09de22bada8",  # PipelineAst
    "0.1.115.2.0.0.5.1.2.0": "a7f4247f3aae8ebfd0eac9081a1115b0b0565874581db14aaa53da99aa325254",  # PipelineAst
    "0.1.115.2.0.0.6": "0d72013e82ab3d6c55c82251d084a88a843973a2bf012d79cfd720c4f69033d4",  # AssignmentStatementAst
    "0.1.115.2.0.0.6.1.0.0.0.0.0.0": "1b4853b4bbbfddbd3d71c098a34404005b9365e13a4e392acc400916bcd9807b",  # PipelineAst
    "0.1.115.2.0.0.6.1.1.0": "595e1ac92eeef96d2e935067a9a94029be712f8048d231ff87498095c7f534b3",  # PipelineAst
    "0.1.115.2.0.0.6.1.1.0.0.0.1.0.0.0": "6013b655000b4641cdd8e815bfb98117a169342d488cecee22aed31db9645615",  # PipelineAst
    "0.1.115.2.0.0.6.1.2.0": "fa715128ca004a3c13417aece266d8e30937691351a298edf44f5bc82b5959c4",  # PipelineAst
    "0.1.115.2.0.0.7": "e6a9c538e4d6fd68f54f8745d1be265e07a3c34c79c6899abe118fd7226d152d",  # AssignmentStatementAst
    "0.1.115.2.0.0.7.1.0.0.0": "67e9f133c13d4d80c391f3126fa085375c3b0b7ce83ef9d0345045909d03dbec",  # PipelineAst
    "0.1.115.2.0.0.7.1.0.0.0.1.1.0.0.0": "5381a39ea79e3c0d2b539195d19d2163fc3b1ae0444411086cf98fc41e2c9fc7",  # PipelineAst
    "0.1.115.2.0.0.8": "26e532cf373b7aabbac254fda745ad54b002f21f514053cfed58834e829960c5",  # AssignmentStatementAst
    "0.1.115.2.0.0.8.1.0.1.0.0.0.0.0.0": "3b812cb99001526e2dc571fb4c82fbd48cdfd17b42e5b02d113ba092b7e23acc",  # PipelineAst
    "0.1.115.2.0.0.9": "c6d20e56792ea959c77a30b296500ea1edaf5516857aa19c473f7181f1a3c400",  # AssignmentStatementAst
    "0.1.115.2.0.0.9.1.0.1.1.0.0.1.0.0.0": "772dc20e904fec5e26f9e9d7dd3ccef74ad28ccd6a4c8dbbbccc091d83670b59",  # PipelineAst
    "0.1.115.2.0.0.9.1.0.1.3.0.0.0.0.1.0.0": "87cce876d423d6daf957fbc365c640c5ac53e660ca08af50d1e3ae2242e7f03d",  # PipelineAst
    "0.1.115.2.0.0.9.1.0.1.5.0.0.1.0.0.0": "56be898c0e80d094b289c0f0612f71103860dcfd24c407a65fc5ab55e0d39dd9",  # PipelineAst
    "0.1.115.2.0.0.9.1.0.1.7.0.0.0.0.0.0": "85ef3a8f9b866ded3d783eb688f057b547274cb446966a6f3e50df6a3d819db0",  # PipelineAst
    "0.1.115.2.0.0.9.1.0.1.7.1.0": "5300d77041d9b759e29f7f08568b4d3dd63fa16d35cb65f7e3869e6bd83dcc55",  # PipelineAst
    "0.1.115.2.0.0.9.1.0.1.7.1.0.0.0.1.0.0.0": "28d721bffe1131c0ac3a13b641899e25d6f0eee025c089dbbe8e7b231608941a",  # PipelineAst
    "0.1.115.2.0.0.9.1.0.1.7.2.0": "fe21edfcbf22ed38d2c3b52afd7dfb19a77c3edd89569404786939a850bd8a1a",  # PipelineAst
    "0.1.115.2.0.0.9.1.0.1.9.0.0.1.0.0.0": "da37fe09ae3d9ff9af88e64be2eba08d11643b17443bb3a45d8a089617e4ca2d",  # PipelineAst
    "0.1.115.2.0.0.9.1.0.1.11.0.0.0.0.0.0.0": "2b529c2abc252f8e2ba0aa5907b104e86f430cd99f2e90e3cb470f8f630a6d7d",  # PipelineAst
    "0.1.115.2.0.0.9.1.0.1.11.0.0.0.0.0.0.0.1.1.0.0.0": "c5a69e2dd2950e9bebc792b09e22c4447ada48d9d279bf6641c7f230d3c26614",  # PipelineAst
    "0.1.115.2.0.0.9.1.0.1.17.0.0.0.0.0.0": "20105da60b91d8ba094374330decf110a2bddbf4e6163cd7e673ccd0e990efcb",  # PipelineAst
    "0.1.115.2.0.0.9.1.0.1.17.1.0": "8773e7647469439a3fdf2240f7ee3e0cb0964b21898e191b625d1683061d0278",  # PipelineAst
    "0.1.115.2.0.0.9.1.0.1.17.1.0.0.0.1.0.0.0": "de9dbcd9d35659370e7c33d24dd37a9f2ee5503b40b6a2206ad4997846626329",  # PipelineAst
    "0.1.115.2.0.0.9.1.0.1.17.2.0": "d408be8f60f97c0fe42ce4cb4c1669fa0e6b9ed87f7eb9f43c3b3b3a5a42502f",  # PipelineAst
    "0.1.115.2.0.0.9.1.0.1.21.0.0.0.0.0.0.0": "349630fe1da52834e6dfc7832ae4f74d6853c8a72d44cfe689fd654c0bcb65d2",  # PipelineAst
    "0.1.115.2.0.0.9.1.0.1.21.0.0.0.0.0.0.0.1.1.0.0.0": "e336ff81fb05ccbe5a60b306897fbbface2052709e820ba9af867972ec6c494f",  # PipelineAst
    "0.1.115.2.0.1.0.0": "5e08874495a0f5419265be6016286819c37ef51d5575f31c87bd96f406665052",  # AssignmentStatementAst
    "0.1.115.2.0.1.0.0.1.0.0.0.0": "5083aa9fdda77b9ce57dbafed6da4403230ba644b4ad43510aa716a030ccc2a5",  # PipelineAst
    "0.1.116": "11552b8309f2760c0448002e990c41ef0ebe662f912a0db4575c8a365fdb96b1",  # PipelineAst
    "0.1.116.0.3.0.0.0": "56cd8fd80aa3827e383b6dbd511a4d237f19f7ef0e2d93a74cd0bd60c7655fc7",  # PipelineAst
    "0.1.117": "1e1441790e405a756c2d5cda6c344d42c6857fb9fb3c3904e58ef7212fdf413f",  # AssignmentStatementAst
    "0.1.118": "a51aec29ddf84aa879eec5fe810c33f5cb3f5b38ce533cd6924a0375efd23b1a",  # AssignmentStatementAst
    "0.1.118.1.0.3.0.0": "a616e25139050d2236641f123ec8feaa53ed0552a1419dd13da95ef4ab10adaa",  # PipelineAst
    "0.1.119": "922632e99a4d89cbd7f8b5139c7399f6543038aa9d4220ef5d2f3a5cec6cd299",  # AssignmentStatementAst
    "0.1.120": "72556509b84d22b119d5b842b2ab6c2f828129c43d5724e4de8b65dac9f260e7",  # ForEachStatementAst
    "0.1.120.2.0": "cea0c6e0f86108cb772482fa06ffa5e9bad4cb43255e5fb42b369517357ae460",  # TryStatementAst
    "0.1.120.2.0.0.0": "93d862cbf27300e00ddc3f07657573bce3fa1587a3c18aaffbede0eabed4cfee",  # AssignmentStatementAst
    "0.1.120.2.0.0.1": "4e97be6166403b386c272283ad706c48262fc2601010a8e9537569c89196e49b",  # AssignmentStatementAst
    "0.1.120.2.0.0.2": "64d42bcd196c8a667fb1147a856b78540fff414d9acca67e2f7287d4dbe895f0",  # AssignmentStatementAst
    "0.1.120.2.0.0.2.1.0.0.0.0.0.0": "8170594e4af3371500f8e898a5b56d78f406504edcabe825dc6eb59d55b26ac8",  # PipelineAst
    "0.1.120.2.0.0.2.1.1.0": "d9cbddd21bb23ece3e518738969be8b85e138bdafd240dc34b73c3feeb916d6d",  # PipelineAst
    "0.1.120.2.0.0.2.1.1.0.0.0.1.0.0.0": "62e03e72fc958f9bfe4d33335995e1023b559e40dd5db18a3f4e2eda744b96c0",  # PipelineAst
    "0.1.120.2.0.0.2.1.2.0": "84ae010ddf6e59073e9a5ef4cb59bce55e0d64c8dde0068fd337aee0af393d47",  # PipelineAst
    "0.1.120.2.0.0.3": "c2d0d8feaf8111e55afc68ad7d4b79e0e32501987f41e1b9e63f9681f9b9201e",  # AssignmentStatementAst
    "0.1.120.2.0.0.3.1.0.1.1.0.0.1.0.0.0": "3062d7dac577d2fbbc004e3dccf981176052c34822d156bb3eb9ee9a96acd588",  # PipelineAst
    "0.1.120.2.0.0.3.1.0.1.3.0.0.0.0.1.0.0": "d578faa6046bec813ae9f666de67c55a43bda0f384cf6cf19e102f30fb022e4f",  # PipelineAst
    "0.1.120.2.0.0.3.1.0.1.5.0.0.1.0.0.0": "215d4c0faf15b3cd37ae480292dfc5234e8760e9c8b185ce9c0b2c753d81bf42",  # PipelineAst
    "0.1.120.2.0.1.0.0": "579dc65db15b756d82104b6c663e3ca4ff61eb0bcdb326985a3c085bfec1d093",  # AssignmentStatementAst
    "0.1.120.2.0.1.0.0.1.0.0.0.0": "93337361f8643cc821933f9976c87c83d3f12673556233c78dcf4e3c384778f2",  # PipelineAst
    "0.1.121": "c0cab1799bdcea6a1bda5b0e38d9c3aaefd85614b9a87abe9740b2fd76d510b5",  # PipelineAst
    "0.1.121.0.3.0.0.0": "7e75da5fb57e99e67a63558b431b3407bc6bb92f15df224623bb11b021850a87",  # PipelineAst
    "0.1.122": "b401ae317432f766201f3c86e3620957b8a64df962f821ed6ea5d3e47005cb84",  # AssignmentStatementAst
    "0.1.123": "693276445254d8ec242fa461ebe897e0d85133969bde197b2f7ecf147594e312",  # ForEachStatementAst
    "0.1.123.1.0.0.0.0": "c65d65a54f664c8b6afb68e0ebf21cf2a32cfeef8d76d821dfd8edea23280180",  # PipelineAst
    "0.1.123.1.0.0.0.0.0.0.0.0.0": "48bd0ab69b8e859abc5f0d916f5c1cb1fb86c803031345a1bdbbc1b357a23193",  # PipelineAst
    "0.1.123.1.0.0.0.0.0.0.1.0.0": "1268ee39d4ac14c3027ffa34f0980ec4c5920aba0f0bd797a328f13befdf5600",  # PipelineAst
    "0.1.123.1.0.0.0.0.0.0.2.0.0": "4451e2a78b894f8c2e958d6a8f419438be8de0515cda559ef1725e20b4b5b6a0",  # PipelineAst
    "0.1.123.1.0.0.0.0.0.0.3.0.0": "da38db144d806cd6ebbfc1565883f96a46c0f90410b1de1d5b8bf494004b5771",  # PipelineAst
    "0.1.123.1.0.0.0.0.0.0.4.0.0": "250f915dc1a7fc1d0eb789a385f0dc93e89cfa21ba0ae1e52b3ceb00ce53a9f2",  # PipelineAst
    "0.1.123.1.0.0.0.0.0.0.5.0.0": "dd929f5ea83f123993ab3d3592e2792b36d98acba65918631f5f678adc784f65",  # PipelineAst
    "0.1.123.2.0": "eedf81ccaa2922b333e1e574768eebf9ad08bfa6dbb44618f2521b54d12ad4c8",  # AssignmentStatementAst
    "0.1.123.2.1": "8f916278f895411414bf2405b806fc93374fee42302d53370d923d6d2d87d058",  # IfStatementAst
    "0.1.123.2.1.1.0": "d7326dfbe132b0dbef5905b14182852887da997eaa76a4eca5e52cafc77882a8",  # AssignmentStatementAst
    "0.1.123.2.1.2.0": "c7e649775fde960c0b6de6660083798961216866d6d7d76dbfbf3f05c4294956",  # AssignmentStatementAst
    "0.1.124": "bd25ce6818d219fa9111a69246695d7fbba2b62fcec114e35ae3765148cf8acc",  # AssignmentStatementAst
    "0.1.125": "c76d4162b6b0854dde9549e0936a44a8c9c9c54aed2cef1473f2c6daee111f44",  # AssignmentStatementAst
    "0.1.126": "2f9e5c07c1d2296feb7b2760bf4aa7deaac3d145de58d59ee2cd9f16dfa823b4",  # AssignmentStatementAst
    "0.1.127": "fe1af4a27fe36581538be8fe8b6df33eb705decd959d2e6d3e0d5d524c931ef0",  # AssignmentStatementAst
    "0.1.128": "fc75245e2e61ac9f60aeebcf65b2c3c8fb68547884a0d3ef0b6aa6253a9f47a1",  # AssignmentStatementAst
    "0.1.129": "889f792618fcc23e4a84bade5eeaf1c7a7f62c9c1b72e36fcbb959898ea589b9",  # ForEachStatementAst
    "0.1.129.1.0.0.0.0": "10163edf6f78d5b53519723e9759951d26a0da3dc699348da65419fdc8cdcf2d",  # PipelineAst
    "0.1.129.2.0": "7ca233df7150094a170b7282cfd45c1482144f1db6cd3b829fcea886bd5f038d",  # IfStatementAst
    "0.1.129.2.0.1.0": "cd051ac18446a8dfa9b6d992262f06db3720a87e816a5672432e742bc5cad981",  # AssignmentStatementAst
    "0.1.130": "123dafce872fc83328058251e243b28979ffd90675a41e49a67225047cb497bb",  # AssignmentStatementAst
    "0.1.130.1.0.0.0": "4f4cad66b7617f9450f078dde67fbcbef8ff10018d76a5256c7f60491db24e98",  # PipelineAst
    "0.1.131": "329b3438b0e0fb616fe7f0dcd9b175a6065855cfdaa190fefce5b7570d8ab419",  # ForEachStatementAst
    "0.1.131.2.0": "49666d0fd975bd5b8d16c2aa9a3d8213d949e73df6fbc50f50bf2d43a0a9884d",  # AssignmentStatementAst
    "0.1.131.2.1": "ef3bf6d3ed77f413fb2fa7cb09d2b2d2d8b01cdea78720233502d725ee2b1a24",  # IfStatementAst
    "0.1.131.2.1.1.0": "e04f27dbd453c41766856c136d64b8cec06e15ab7a3c411f4caf93e16c0ecc05",  # AssignmentStatementAst
    "0.1.131.2.1.2.0": "495ec2cd5df2634de4c1161efbf1721db9340b2e722b6308d6c586ef5550d283",  # AssignmentStatementAst
    "0.1.132": "61c2d0663a799438fa7fc0f17fd55809109fbdb7cc1048ca4b59ac0f1a20879e",  # AssignmentStatementAst
    "0.1.132.1.0.3.0.0.0.0": "87ee3cdd86b10d731783d5f17cd91b376daf1219c789b4517a789e32c71af4ba",  # IfStatementAst
    "0.1.132.1.0.3.0.0.0.0.1.0": "00b9ec11cd0047f1aaadced7bf8905a519872eb410deb7d1d387140b3cec8465",  # PipelineAst
    "0.1.132.1.0.3.0.0.0.0.2.0": "0af8b810c354f23c77dc8a73e7c5cf47edaf0e4a8bbd8104e9ee709f94376c39",  # PipelineAst
    "0.1.133": "09afb3a7a059c30bcd95b57b66ea0cf2a24ab2b5f15eb072170731f73e4714f0",  # PipelineAst
    "0.1.133.0.5.0.0.0.0.0.0.0": "abff3bc67bc421371565b509f77a446687d47d9f1418bc9480018bf35693ce70",  # PipelineAst
    "0.1.133.0.5.0.0.0.0.1.0.0": "e583de4c4ab05c63d5b576f7fc688757e7a81f4f232376ff5ee696d23c78ca79",  # PipelineAst
    "0.1.134": "f01202629c7893a99a7cbe601b671e71bba0081a74b9471e8a0b53f48de97692",  # AssignmentStatementAst
    "0.1.135": "cd5b41901c22ca743f998c96402f1c961458675166ddd4b4bc0345d2df47fc1a",  # AssignmentStatementAst
    "0.1.136": "aa61ed1b73885ce8759e9e850551afc736879785aaa183a65daf022640f48ef3",  # ForEachStatementAst
    "0.1.136.2.0": "ada6324622d0b0f61ac9e5364bf4cc1b8f12a53b0c16429d7c58003cc1112e46",  # AssignmentStatementAst
    "0.1.136.2.1": "c28fc0d469eca033523093f0b67db5da35a74c74ddd6e7d50743122a835cd42b",  # IfStatementAst
    "0.1.136.2.1.1.0": "23bb9ab17991951d05ab3eb9f15cf9c60bf881d92ff723b7795b16324d458c9e",  # AssignmentStatementAst
    "0.1.136.2.2": "af29ae28df8201e45734bec27a9a65e1222809810f7bd7a124d11569fdc5ec51",  # AssignmentStatementAst
    "0.1.136.2.3": "c2d0cd7e66a3bc35b7ecc1d03b0a13346fdc13dca201d2ae4551a18ea24fdd85",  # IfStatementAst
    "0.1.136.2.3.1.0": "5925c5e7bd7207c08e9ec6f4d15fd79c6dce4e799636e47493a1c35997439b9c",  # AssignmentStatementAst
    "0.1.137": "466e601b34965eff2c3357796f2fefd89340cca38ec8db1bb1de0df13935b528",  # AssignmentStatementAst
    "0.1.138": "d4185636f1ec352303fc4b4739008536ac40a32ec0275ffea3d42fff203077c1",  # AssignmentStatementAst
    "0.1.139": "356284466d122764923a7f34c85917d277a999ad91ae06670324f6dd987832f1",  # AssignmentStatementAst
    "0.1.140": "a16853014113946f26f2df528792942c46ed7704ca2e83397407bed46299a21b",  # TryStatementAst
    "0.1.140.0.0": "958f8c1cd00b76aa597fb2e51d56b059e04f1ddaa6eacd72c65fbc7399d91c57",  # AssignmentStatementAst
    "0.1.140.0.1": "0c4fd3ffb9c0f28f971599aadabf03cd6b13d7dc5a6278464f3a967bd5e6daf1",  # PipelineAst
    "0.1.140.0.2": "18d44fc62d032808d2961925417a75e79898e6ade5562fda37345054b949061e",  # AssignmentStatementAst
    "0.1.140.0.3": "e4701c05af5dce924164379bcb8bd33780e8c9e73fb2f694d37a9ad0840e6739",  # AssignmentStatementAst
    "0.1.140.0.3.1.0.3.0.0": "fce77f4ed4cac8704c338d85f5483000440d9944c3dc26347186aee0e1a9f8b4",  # PipelineAst
    "0.1.140.0.4": "44fe580deef86e49f222d5ef9b5462445f3c047677245964cc5d2ee49e0badd4",  # AssignmentStatementAst
    "0.1.140.0.5": "9998dae913413ba60bfaf6a7cf90d4fc69e456e3cec587f65ad7148d61c07736",  # AssignmentStatementAst
    "0.1.140.0.6": "5320d40ee45a4a35b9c4120cbdb36cd83d0b67d54c92b2bb9969941f585e32fe",  # ForEachStatementAst
    "0.1.140.0.6.2.0": "a92b804fc378fc4e525ae783ef3973b70c60fd0b66dcf439375b3294561a29c3",  # TryStatementAst
    "0.1.140.0.6.2.0.0.0": "3fe99cb60720f687b2ab99f1fc5235d2a427105a835d3395386946f2bff462e3",  # AssignmentStatementAst
    "0.1.140.0.6.2.0.0.1": "48ad7d92e1b06418ecd952ad9c559290977f1a3904fbef8bcfe6b4edcae85e62",  # AssignmentStatementAst
    "0.1.140.0.6.2.0.0.2": "45d3a376aec475ca1b40bf0390da5064cac524db9608d69e306c18f701706e57",  # AssignmentStatementAst
    "0.1.140.0.6.2.0.0.2.1.0.1.0.0.0": "338fc2f486affa6874dcb17c3961f8d5786905c06540df96015f74e3baf33b14",  # PipelineAst
    "0.1.140.0.6.2.0.0.3": "27d8370bd4533e00eae140bd22ff20bb04f5f657a7dcec11fcbdbf0a5b1bb7bf",  # AssignmentStatementAst
    "0.1.140.0.6.2.0.0.4": "62396113177b05cc9305682e01cde14dffb5efcd0c8d3a12a489c7d099f495ad",  # ForEachStatementAst
    "0.1.140.0.6.2.0.0.4.1.0.0.0.0": "17c11e2ab8d6c3895363130d183cbc71c917b248d5ebde561742223b556a7b6a",  # PipelineAst
    "0.1.140.0.6.2.0.0.4.2.0": "d5b92e7105f3d505640803de591603dc9d7f764f6be56e0b2563678a432dc562",  # AssignmentStatementAst
    "0.1.140.0.6.2.0.0.4.2.1": "1ffc3f29ac7ace50823581ab6a281eb86c35c5d1ca7192dbd5c78130b198f2fa",  # AssignmentStatementAst
    "0.1.140.0.6.2.0.0.4.2.2": "6b4d8ed3346e0b7aaf9eef017fcddf476cdcd558778fd6a2d83c7da65d42fb56",  # IfStatementAst
    "0.1.140.0.6.2.0.0.4.2.2.1.0": "6bd2ad16cf8c39fe4ed1757aa5d31491578d08182ff0de34fdd536035a8fa9c0",  # ThrowStatementAst
    "0.1.140.0.6.2.0.0.4.2.3": "18560c278bba5e72bbabbf0223c260c4490a68d46d7ba897c9f4b06531d16962",  # AssignmentStatementAst
    "0.1.140.0.6.2.0.0.4.2.3.1.0.0.0.0": "e6525d4a27a55c56e2294fedf5f5adfb6aa7317c852d4ede3c1d09e676c77572",  # PipelineAst
    "0.1.140.0.6.2.0.0.5": "9963d56cf827c4e0e7e0eeda0a811f6dabc0c05c6ad886fa6ab0ca965a5405b5",  # ForEachStatementAst
    "0.1.140.0.6.2.0.0.5.2.0": "b4d2ab732d3837960270ada089b14f5a1b8d9a28556c594c3d102a39966437c3",  # AssignmentStatementAst
    "0.1.140.0.6.2.0.0.5.2.1": "e414f9f674de36c0e454ac0c303dd4bbcbc0c614cc6ddca9d62d172bbd5f25a7",  # AssignmentStatementAst
    "0.1.140.0.6.2.0.0.5.2.2": "057c7e3f3c45633097b88972dcc753f6e63a9d9f0e8ab9f74b170971a0cae90a",  # PipelineAst
    "0.1.140.0.6.2.0.0.5.2.3": "023e21fe334ce47373ea0e6ad480da2f98e5d35e9d15e9b5505845774c8aeb4e",  # AssignmentStatementAst
    "0.1.140.0.6.2.0.0.5.2.4": "7d99036efb199b7ad76b1613adf0d8cd43bc766a40c94916520a158e35a5a69b",  # PipelineAst
    "0.1.140.0.6.2.0.0.5.2.5": "5b3231d7bf71431582ac575f4bddaa7c14b276edbf98297624b37629ae465a13",  # PipelineAst
    "0.1.140.0.6.2.0.0.5.2.6": "f2c1aec2ad20b5367d5a76c0530c6b69a11a606f60cfdac67be9ff11a6824758",  # PipelineAst
    "0.1.140.0.6.2.0.0.5.2.7": "1c20a26fbde59c0d117dc6f5a4bdd3fb577c3d1186c41ca0f25df068047ceaa9",  # AssignmentStatementAst
    "0.1.140.0.6.2.0.0.6": "fba9982863b985ff9138f4a983e11a436ae5cf635d8eb93fbaae35944626ba21",  # PipelineAst
    "0.1.140.0.6.2.0.1.0.0": "657653f0320509ed711406f327eb89ffc7329ff618fcfbf8d7c1dc9683dcee1b",  # AssignmentStatementAst
    "0.1.140.0.6.2.0.1.0.0.1.0.0.0.0": "0c4306da5e2b1fd90487283835b45928a1ab759d867423a5eb1f83f5677026df",  # PipelineAst
    "0.1.140.0.7": "05a1c981322a13f3460b0c4750c8eb28dedbd641b12cf058360ebe3a3ea2cdf1",  # AssignmentStatementAst
    "0.1.140.0.8": "150f20482409c15f10270db250190ae3fb5b76f55839348b3c20dba923a86c97",  # AssignmentStatementAst
    "0.1.140.0.8.1.0.3.0.0": "f974f0f345ef3b4e690cdfe06bb0cf67842bf46ef4befdead5f313aa7da55bbc",  # PipelineAst
    "0.1.140.0.9": "e61ad41cde7c5261727d6b893abd58b00d673ae80a7b4c23db8c1f43015e5bc0",  # AssignmentStatementAst
    "0.1.140.0.10": "89dda1abddc353fafb630771429c80eb9dc55da5adb495e06826fc8a6037bffe",  # AssignmentStatementAst
    "0.1.140.0.11": "f4712e557941c262f0ed01b60bc7956e484d557b434e71c1c5518fd55c09a89b",  # ForEachStatementAst
    "0.1.140.0.11.2.0": "7fad189742e9a7be5307184a49d4dbd7b57327e3c020a15fb7349d9372e8e257",  # TryStatementAst
    "0.1.140.0.11.2.0.0.0": "f5d7349359996001e8b87816e7bef7ecc2255a63926848614f1ce296b9e1e3bd",  # AssignmentStatementAst
    "0.1.140.0.11.2.0.0.1": "f3bcf6ba4c4a116a2b2aa3942b44c21c00e0506a35c6f94960dac3aa049deb3c",  # AssignmentStatementAst
    "0.1.140.0.11.2.0.0.2": "ce95b636a282ef6df02c0464d2dfb543370c827c545a3edc5a5d7240861b96bc",  # AssignmentStatementAst
    "0.1.140.0.11.2.0.0.2.1.0.1.0.0.0": "abb16f8be6b7ddaf10628535b2ebe13428981388eab493e4b1c1f25609392f50",  # PipelineAst
    "0.1.140.0.11.2.0.0.3": "708a125db58e12e3dc6d12eef5b8fbf8f4c6a8ec4c79b86186c1f29b40768398",  # IfStatementAst
    "0.1.140.0.11.2.0.0.3.0.0.0.0.0.0.0": "bf8567be681c4cd2011c15485def2e760ff1ad4f281f112cd1d2e4d370d6fa7d",  # PipelineAst
    "0.1.140.0.11.2.0.0.3.1.0": "0e94209583215542255434fdddbcc8153a8bcfddaa9705c5c4dccd4755f37daa",  # PipelineAst
    "0.1.140.0.11.2.0.0.3.1.1": "4cca73385eed5cdb07ecee5da47d091c23075eb1ae30b027664cac0e5bca736e",  # ContinueStatementAst
    "0.1.140.0.11.2.0.0.4": "97e8c105bd456df0943ec652faba437e7a5336867624cb612adb20bb831c4aa3",  # AssignmentStatementAst
    "0.1.140.0.11.2.0.0.4.1.0.1.0.0.0": "eb62c543432e85dc2860db6d3d4aefb485547e949400c14ef6ac287383b3a5e8",  # PipelineAst
    "0.1.140.0.11.2.0.0.5": "9590dbb368ac3e5d1a2a048ca04d94f10fa5f3df5bc49c7ea7af7120abe823b6",  # PipelineAst
    "0.1.140.0.11.2.0.0.6": "05639b93c70da790c65189b24ae9fc996d31e56955c41e7eaa12e70e52a28717",  # AssignmentStatementAst
    "0.1.140.0.11.2.0.0.7": "8eef090a780a09c1134d21f68994633e74b559e256d21fe676e4a76e66c0b269",  # PipelineAst
    "0.1.140.0.11.2.0.0.8": "1f7e79cb34d9e78469ea878d623eaa1b254638ab2006a1132b9fd64c8de165fa",  # PipelineAst
    "0.1.140.0.11.2.0.0.9": "72fb675a632b23b4258962b6b2b3337c7e2675ac74e956811258f6e0f002e3b8",  # PipelineAst
    "0.1.140.0.11.2.0.0.10": "4978909d619d92481ebcbd8eaa9d27ff4b0e8d343e6f7bd191a3b4f1942e21ed",  # AssignmentStatementAst
    "0.1.140.0.11.2.0.0.10.1.0.1.1.0.0.0.0.1.0.0": "ed107bbc1888aa2c3dd8dc55ec07598964d0ec49222ba8c1fb682faec937bcbb",  # PipelineAst
    "0.1.140.0.11.2.0.0.10.1.0.1.7.0.0.0.0.0": "2afaf0e41479e64a7ffe28235ed196887ca3aa88cbf20cc26f96bfa112b7d4ca",  # PipelineAst
    "0.1.140.0.11.2.0.0.10.1.0.1.7.0.0.0.0.0.0.0.1.0.0.0": "40f11625e1b1d57f43eb9bf3f20e9b5eff8c99a904ae127bd9088d4b4fc4b0c2",  # PipelineAst
    "0.1.140.0.11.2.0.0.11": "51a07b03564d3a49cceb5fa467b8a8c02bb4bcd31202d2a23962e90042a16d3e",  # PipelineAst
    "0.1.140.0.11.2.0.1.0.0": "febc1cfe75e7bd0ae7840d87612e4d2d693049ca1d1c97cfac9fa4cf30368e37",  # AssignmentStatementAst
    "0.1.140.0.11.2.0.1.0.0.1.0.0.0.0": "40d7dced5f0003eb1041d380a485c4dc849babde1cfa2b54b353f717d0595f9d",  # PipelineAst
    "0.1.140.0.12": "6e62230b06d9c80becc3ac0a530d932e9cff30de39ba2eaaf916a73b33e4deef",  # IfStatementAst
    "0.1.140.0.12.1.0": "ee8fbfbd7683a77511f6f24069d4c52c2b2b8048e5a9999268eb0031cf0f043e",  # AssignmentStatementAst
    "0.1.140.0.13": "91d1afd9377929e9cc61bb1c639366236bee73798781a33c83d7602077601260",  # PipelineAst
    "0.1.140.0.13.0.3.0.0.0": "58d35dcee249bc1378aaf2242f1ecc1ae6225ba5a88eba6f77964bfe01f6df63",  # PipelineAst
    "0.1.140.0.14": "f5ab7320fd991bf17622696b525559dc30b116b2f5fc9317a421010658810d64",  # PipelineAst
    "0.1.140.0.14.0.3.0.0.0": "3bf0d95df19e93e0fbd55dd42ddd8f1f3178f4b58e681fd027ba6eae76c9e454",  # PipelineAst
    "0.1.140.1.0.0": "890020be26600c5937db5cfe5d07b3631f52407c8f8d29a951aeff69b7969d5a",  # PipelineAst
    "0.1.140.1.0.0.0.1.0.0.0": "cfce3c3fcc504468a3809e86b9097e5d7142cb11fe2588c1fa1896510566dd7c",  # PipelineAst
    "0.1.141": "a9cdcc94887e0f06eb1ab9928b5d16390687a8f5444f1becb089589e8f6b4bcd",  # AssignmentStatementAst
    "0.1.142": "814b7e0a8f38b2e53cff14263377eb5678f538c8bab6ab289598daa07493394f",  # IfStatementAst
    "0.1.142.1.0": "ef6d10158961ee266dd9c19b1f403b01aecb8c399c823b12137d26a47203ccb9",  # AssignmentStatementAst
    "0.1.143": "26a11766d5e2f1e285257611dad2b770b387f24f032516e203703b550dad460e",  # IfStatementAst
    "0.1.143.1.0": "3a3f89e49acb4f6cff803639d6b1b89537f0cf762249b209eb637ca4b27cefc1",  # AssignmentStatementAst
    "0.1.144": "3782eaedac4e1d05866920298425c39626d3d6a93031dc21ee11c793411beacf",  # IfStatementAst
    "0.1.144.1.0": "48bd2060f48244fc4048b031fe6fe2d74565fb6e901962a4d836f80f1db2e1b9",  # AssignmentStatementAst
    "0.1.144.1.0.1.0.0.0.0": "58e4a3db1e59f8a1de510599b7fdbb1d9c98ed9a683486d93642f20b4fdbe139",  # PipelineAst
    "0.1.145": "7a5a3279d3db37bd0a160ce375c12621ce06e7cab0d6327f261417037222bf95",  # IfStatementAst
    "0.1.145.1.0": "c676fb39fe162db583ca836d1b55bc997f05f4c23eb376562ba9aeeccbb68399",  # AssignmentStatementAst
    "0.1.145.1.0.1.0.0.0.0": "ad72121dd26e87c4a8981e46ace2a1260b8f5dd6e7822ae400a5bd028333ea11",  # PipelineAst
    "0.1.146": "2ec63b631b636a2a31a6295d39d7a1c0895c2e7f39f12605a9cef6611eeb019d",  # AssignmentStatementAst
    "0.1.147": "dcaf198a7052838198831a0849dc45b4c857c2054a6f8f95f37eeefe7e1bb6f5",  # AssignmentStatementAst
    "0.1.148": "cd302d0760822a32e9f42e8d30639a9fdac3681eb2b3ca17ba6c3800f42555f1",  # TryStatementAst
    "0.1.148.0.0": "c2e8daca05d11cc09f9fa4da5cadfcbbe986015213820290d1fef5bd1f443738",  # PipelineAst
    "0.1.148.0.1": "2ef2e031cde0aad450fa2746df4ae9c6463ad5e32576af7c588f7afe75009405",  # AssignmentStatementAst
    "0.1.149": "986a5a66524c21c0a835086db919fd6f4e032f62a5136ea95314e8d6e241b851",  # IfStatementAst
    "0.1.149.1.0": "1ca3e1911e588df47a7397b3f010de7614667cf28f7848001ebfddbce96ceb4d",  # AssignmentStatementAst
    "0.1.149.1.1": "e3bc2061f02f6631c5db41258fbab5d617f1715798b194d3890b17782660cad9",  # AssignmentStatementAst
    "0.1.149.1.2": "513589308107f30cebe416dd71c569ce563e4d2a368274c93daee012210a0d22",  # AssignmentStatementAst
    "0.1.149.1.3": "4e466cfa9ba6f9e81d9a88f0fdf34fcc3a580c938b202bfa652a9db034bbdd9e",  # TryStatementAst
    "0.1.149.1.3.0.0": "8c416e8b4014f49b41f053ecfe4aa7a9e7a7318fe1525749ea81b475800bad8e",  # ForEachStatementAst
    "0.1.149.1.3.0.0.2.0": "23ec59f3409d921ed0f7fe9d0fb6da28deabc17d5ad4f5f71ce956fa8bcc9e13",  # AssignmentStatementAst
    "0.1.149.1.3.0.0.2.1": "ab8b3a4f97a9b55ebea26bc64909bfc29e76e28a8cd2fdbfe7d95443fbf5620c",  # ForEachStatementAst
    "0.1.149.1.3.0.0.2.1.2.0": "d5896d2fdca37fa8e60c601c49dea73c3a76c03cccd455cdbd4c273dfb3842e7",  # IfStatementAst
    "0.1.149.1.3.0.0.2.1.2.0.1.0": "52e7ed0bc231f8db423b85b8790aa9b2615172d94756b370c7a0feefa5e6ed61",  # AssignmentStatementAst
    "0.1.149.1.3.0.0.2.2": "0b9859974935d7a8a0a322d3403305297e0dfe83405438287ec468d9021a2bc6",  # ForEachStatementAst
    "0.1.149.1.3.0.0.2.2.2.0": "a156b3259ded9408bae3188f2e67103686f1707963b2c393ae96a1269d4ba008",  # AssignmentStatementAst
    "0.1.149.1.3.0.0.2.2.2.1": "d6d3f60d3a3ef15e9a0c0da983a5a955eb20055966f5f40af9197422a49685ed",  # IfStatementAst
    "0.1.149.1.3.0.0.2.2.2.1.1.0": "4ca40bd78eaa14a4415b7c6bb3a93ac0d54c986e50586c06d068ceb28a15ae38",  # AssignmentStatementAst
    "0.1.149.1.3.0.0.2.2.2.1.1.0.1.0.0.0.0": "a0bf72ec2002f1b5a9101639ca75c025db5e7e76119285cd78345d4a6a708e60",  # PipelineAst
    "0.1.149.1.3.0.0.2.2.2.1.1.1": "da01c2e0894d42796de338e01d8cc43b16f663d4ec7dbef483e5db462675c7d3",  # ContinueStatementAst
    "0.1.149.1.3.0.0.2.2.2.2": "37c9bf99ca1f9d3355f66882f0458c012537dcee8ca297675f25e0468d5d1117",  # AssignmentStatementAst
    "0.1.149.1.3.0.0.2.2.2.3": "b1dff95ace207ea100d7c5786b9fc043518ba9d9ead2888d8eb81d91d9664445",  # AssignmentStatementAst
    "0.1.149.1.3.0.0.2.2.2.4": "3ff063cbd04adbac738f6bd782df199c5f83967036c712796469059eba3651b7",  # IfStatementAst
    "0.1.149.1.3.0.0.2.2.2.4.1.0": "4237e086d9fa72d387347a9ef6266d0c7354db529fc6106b519d361d7af630cd",  # AssignmentStatementAst
    "0.1.149.1.3.0.0.2.2.2.4.1.0.1.0.0.0": "56e4f606c221564065d578a687e709c5e1d9ad1ea68134c39787432f1dd16802",  # PipelineAst
    "0.1.149.1.3.0.0.2.2.2.5": "c5fb6e232d3ba7a175961222b05d85c8210fd3c820b76afbb9ebeee0048e0603",  # IfStatementAst
    "0.1.149.1.3.0.0.2.2.2.5.1.0": "f4a4ffc8688688f9641bd57423ad3a88839ed4b3f8acc27becfa4a75d625dd3f",  # ContinueStatementAst
    "0.1.149.1.3.0.0.2.2.2.6": "40561f026415340676c0cb310edea18b11d549d3e66d84af410ade82e89f4e72",  # AssignmentStatementAst
    "0.1.149.1.3.0.0.2.2.2.6.1.0.0.0.0.0": "38c67282fcc5ce61d4c223989cf718f445c738b50ba243a82455cb74cfa820f4",  # PipelineAst
    "0.1.149.1.3.0.0.2.2.2.7": "db7268db93a0110ae9a9ff3791d1477ad23d404dd0f330052ad8190655c193bb",  # AssignmentStatementAst
    "0.1.149.1.3.0.0.2.2.2.7.1.0.0.0.0": "1d0b2aa3b1e11bfa9835e332df94e3c76da686f93591e1c302dfeddf5cb23fa0",  # PipelineAst
    "0.1.149.1.3.0.0.2.2.2.8": "7b2cbd80307a8de5ae547bfaf29d5cbb6683cec4dacd6b2c0751985bc2f14e5f",  # AssignmentStatementAst
    "0.1.149.1.3.0.0.2.2.2.9": "5afb0ccc54ba9668542a10ae5fc7e72bb476c8279f3a36f56f1977d29e2d77cb",  # AssignmentStatementAst
    "0.1.149.1.3.0.0.2.2.2.10": "cdc8440757f5c93b1102f5fdd7f9498ff8c191248bb162e5f438f79fd9b4a20b",  # AssignmentStatementAst
    "0.1.149.1.3.0.0.2.2.2.11": "f6f7957cf2e0808cdbb64b2df27029e7f690a6c9c7536d7490a5cc16726e569c",  # AssignmentStatementAst
    "0.1.149.1.3.0.0.2.2.2.12": "be7d293806fb6772e9fcc0647057ab5f01895dbc00d3c9c4ef538f067868e056",  # AssignmentStatementAst
    "0.1.149.1.3.0.0.2.2.2.13": "7b7fd0a865e316f9379e2f63ccc95a589f5204925c1ea3c0ba7899244e4059e5",  # AssignmentStatementAst
    "0.1.149.1.3.0.0.2.2.2.14": "cb5a3d695205d3337d66b26c5bbd5d6fe6505f011967f8f4e21002b1c49016df",  # AssignmentStatementAst
    "0.1.149.1.3.0.0.2.2.2.15": "218987593f66dc79ff4e01a0364cb78d398919e1a0d497e27c2fbe1c39e62bb9",  # IfStatementAst
    "0.1.149.1.3.0.0.2.2.2.15.1.0": "21903c10bccec5b778e2ae68d4d45241e3044599933949fc13aa25f94d964da4",  # AssignmentStatementAst
    "0.1.149.1.3.0.0.2.2.2.15.1.0.1.0.1.0.0": "a76a51b48385a6c12ca6240aea230c62df9921f7f03e8dc9c46d560d36ac3ced",  # PipelineAst
    "0.1.149.1.3.0.0.2.2.2.15.1.0.1.0.2.0.0": "f1956b980d9ef4bd78ab096dd448f233366b3d5689d7219ba7874f6e682ef30c",  # PipelineAst
    "0.1.149.1.3.0.0.2.2.2.16": "c1777a7602f76b2fbf25196a5a44f65a084d46cbe0e02391f8b9f2873aca8171",  # IfStatementAst
    "0.1.149.1.3.0.0.2.2.2.16.1.0": "8b68e29d51e04243805cf72bc7ac506cf320af8a64759294ed7a97e27dcb606e",  # AssignmentStatementAst
    "0.1.149.1.3.0.0.2.2.2.16.1.0.1.0.1.0.0": "190184ff523691ed10e72b1643bc735358d9d80c122674eb76d10a21f9deab61",  # PipelineAst
    "0.1.149.1.3.0.0.2.2.2.16.1.0.1.0.2.0.0": "f836dd5dcc447616792295442cefe2d41f97cdf88cb21f0dc4c1281816197a48",  # PipelineAst
    "0.1.149.1.3.0.0.2.2.2.17": "dc8d9cd84a19f51a77042da397e87fcd6e475d94b80734f494298ac2a753d125",  # IfStatementAst
    "0.1.149.1.3.0.0.2.2.2.17.1.0": "924ca970e94e81ac5ad9d195d4a3fc12b8a2066ba1cf502550206a94669bda90",  # AssignmentStatementAst
    "0.1.149.1.3.0.0.2.2.2.17.1.0.1.0.1.0.0": "8c7b4bdaeda51912e551d175769315c6abe1774dba55bcaaed18e38f1ea85419",  # PipelineAst
    "0.1.149.1.3.0.0.2.2.2.17.1.0.1.0.2.0.0": "c306a79d2677d9afb0f2ef615249305bbbdefb263bb65da63a9fd2a66b5961e5",  # PipelineAst
    "0.1.149.1.3.0.0.2.2.2.18": "1af00e3d77c8d7ffb53ba6325ae0b09ac3c12b964767e213ae76a672e7fef3db",  # AssignmentStatementAst
    "0.1.149.1.3.0.0.2.2.2.18.1.0.1.0.0.0": "8dde27cf12d3540c3c72ed5448cedb1d944978ceedae812700760246d970a5b4",  # PipelineAst
    "0.1.149.1.3.0.0.2.2.2.19": "62c0f4bbb94dbe3a85d244ba8dcb379eac7609eef2957649f3b0a2fda235871e",  # AssignmentStatementAst
    "0.1.149.1.3.0.0.2.2.2.20": "ceca68359aef6cce256af3dfaa27e3225e1d34c761e42f080a5940f73de0879d",  # IfStatementAst
    "0.1.149.1.3.0.0.2.2.2.20.1.0": "97d1ee060a879efc1b1155b6b1ac8c6667cd03047828b7c3f7979941b2f860f4",  # AssignmentStatementAst
    "0.1.149.1.3.0.0.2.2.2.20.1.1": "d1088e61692a9313dd777df84dde5f290dba903f18d49ead05d0db8c1d3f7a0c",  # ForEachStatementAst
    "0.1.149.1.3.0.0.2.2.2.20.1.1.1.0.0.0.0": "a15fa4d8fb6a7928e01c5a4876d7dfbeee2bcd1d52c0d9934a23fa2f384e0ac5",  # PipelineAst
    "0.1.149.1.3.0.0.2.2.2.20.1.1.2.0": "941766043455fefc46d4a6408893b1cae633940d504b82b530e5c98feb0007d3",  # IfStatementAst
    "0.1.149.1.3.0.0.2.2.2.20.1.1.2.0.1.0": "21d8d359a29512d88447cb75dccd0cc67fe05b97feaa9c3e6944806390ec91ab",  # AssignmentStatementAst
    "0.1.149.1.3.0.0.2.2.2.21": "42cd9fb5bd8e8bbee6b7c5dca0d491dd19b0d3b13caac350a48a13fb5bc2fd6c",  # AssignmentStatementAst
    "0.1.149.1.3.1.0.0": "17019cb5d65fcce78b26af90371cef949a23543a2f978671f41175c430f59d1a",  # AssignmentStatementAst
    "0.1.149.1.3.1.0.1": "abbc47a3e6047ec10a8232eaf796e63d0366aae5c084569bd2ca119a713b8688",  # AssignmentStatementAst
    "0.1.149.1.3.1.0.1.1.0.0.0.0": "c0e76b92829c9a8d69690c8af2847db52eeddc71544274bb9ecf09a89fdcb45f",  # PipelineAst
    "0.1.149.1.3.1.0.2": "060fc81aec9ab0e0f4dae937a50dff7b1fa927c48bf692907d1feae4ab5bef09",  # PipelineAst
    "0.1.149.1.4": "80ec4300cc685c282aa27b7fb7f4b3907b505bdb5db8da9ec6b7500a98199f1c",  # AssignmentStatementAst
    "0.1.149.1.4.1.0.0.0.0.0.0.0.0": "6b1376c7abeefcfc5bcf161463e7f62ce5a3f480133b580e4096e04f5ebb8647",  # PipelineAst
    "0.1.149.1.4.1.0.0.0.1.1.0.0.0": "e191f07c7196e63d91441774af73fdf48844a7182fcc7f2bb23a04a9a5be60e6",  # PipelineAst
    "0.1.149.1.5": "3658d287b01ce252b15210f930395fa5126395e09d2b6fbf06c76f7b9961f4e0",  # AssignmentStatementAst
    "0.1.150": "46f8c1793db7ea87de634b4672f6d97bae542ac909c9eb9000270edb00285b6a",  # AssignmentStatementAst
    "0.1.151": "62e7cd378529d0bc380141899c545bca5241e341f2516baa21a7dbdad877433e",  # AssignmentStatementAst
    "0.1.152": "e1b7b50b14a72817fa8c6b1f9e25067d98ef5e6d6596e2c68869111dce1cbd35",  # AssignmentStatementAst
    "0.1.153": "f2a13e49d6adc2e339c3ec71181bfd34d556d96bb1eed2b0a9ddc64dc07a1e50",  # AssignmentStatementAst
    "0.1.154": "34417389acf6412d1563deca8e804496d959d4fbb742c68de69dbdc08a131b5a",  # IfStatementAst
    "0.1.154.1.0": "49340698b2b841c9182d48c9b6141a6c3dad2bcd46e0da863bf5f606b03c040c",  # AssignmentStatementAst
    "0.1.154.1.1": "05d525e82cbe07617c89f1c9fc2ab719716ed8ef9ac33122f76f2bacab181bea",  # TryStatementAst
    "0.1.154.1.1.0.0": "35332e7604f0335aa52414c6c9d1c7cdbc729c8571ef6281af3b54759dda78d6",  # AssignmentStatementAst
    "0.1.154.1.1.0.0.1.0.3.0.0": "dd191d4786004f4494ffb8d2a895206f9c9b4fdb4c892a63c406af6cab6cd36f",  # PipelineAst
    "0.1.154.1.1.0.1": "26c23b8a281fadb346a586a4823618c75d65b89eb2a61fd0ff0746027b39aa48",  # AssignmentStatementAst
    "0.1.154.1.1.0.2": "554ae1394566b8361255ac51a0e1c4a5a6642f1f3e2304a45c3ebd7129f9482b",  # ForEachStatementAst
    "0.1.154.1.1.0.2.2.0": "310e7a0f3274abe23113204f07df3994f77ef9ae1ca4df8df7339c618427668c",  # TryStatementAst
    "0.1.154.1.1.0.2.2.0.0.0": "52cb0d8a8b740423e9ffbe31589e2b268bba6907c743d36e5c99b62737f8f2f6",  # AssignmentStatementAst
    "0.1.154.1.1.0.2.2.0.0.1": "4e755dc7ea8f45cfc48fc235bc4eaaf854158066ccc10995eb156afc90495539",  # AssignmentStatementAst
    "0.1.154.1.1.0.2.2.0.0.2": "14609b429faf1aff0465b872da8c3231a610f790107cdb8d886b55fe862ce1c9",  # AssignmentStatementAst
    "0.1.154.1.1.0.2.2.0.0.2.1.0.1.1.0.0.1.0.0.0": "8d62b5ee4733813cec930c88a27e98c9d3339dddecad76a5928fafd200ac5075",  # PipelineAst
    "0.1.154.1.1.0.2.2.0.0.2.1.0.1.3.0.0.0.0.1.0.0": "cc082121bc3e4a4c6b8fd5246a243bb715763040b095367d83162c7200bdf140",  # PipelineAst
    "0.1.154.1.1.0.2.2.0.0.2.1.0.1.5.0.0.0.0.0.0.0": "981ce1639697bf01a6c7ac292fd2e6efe2f3ba3288b22917c7310d822648af86",  # PipelineAst
    "0.1.154.1.1.0.2.2.0.0.2.1.0.1.5.0.0.0.0.0.0.0.1.1.0.0.0": "81cce39b931098850d64dc032ac22179fe5f5df30c2277eea7de8750d1ff2842",  # PipelineAst
    "0.1.154.1.1.0.2.2.0.1.0.0": "866bcf7ba7acbc65c7a5dd0d49a54fb70a60722c2e6f7618e5596e1f2721a5f5",  # AssignmentStatementAst
    "0.1.154.1.1.0.2.2.0.1.0.0.1.0.0.0.0": "4ad0b14088f20c958e8c2ec37c7eedc1a9585ce1fc696cd370f205b1b8f936e4",  # PipelineAst
    "0.1.154.1.1.0.3": "bbd7690ece31a3fb9f00378f9f450d57710e809460a7c9ee4115c5f3ac20437a",  # AssignmentStatementAst
    "0.1.154.1.1.0.4": "22efb1142588dce3ea3d9c3d093a86b9262856df949101812db8454b11d9f5b1",  # PipelineAst
    "0.1.154.1.1.0.4.0.3.0.0.0": "b4da6c895695c4301e45c77fcc2afd57aff2785ae517dac3f8d077d79f7c4d8e",  # PipelineAst
    "0.1.154.1.1.1.0.0": "d404474cff30cdb6f737568a8a68acb4b83db7304140d7f9ce9c3e529695cea2",  # PipelineAst
    "0.1.154.1.1.1.0.0.0.1.0.0.0": "0ef1cb21230163bbe8aedef78d51ccceaf4df700820aa0574d2f22b85428e597",  # PipelineAst
    "0.1.154.1.2": "1ac11544abacf66227753c178370c2d6e681b058165838ddc69a446527f54d9e",  # AssignmentStatementAst
    "0.1.154.1.3": "a0d34d7aa2c9e46db8876b69604a8d9ae06bdc2523b4dc446f74e37d8e216e89",  # AssignmentStatementAst
    "0.1.154.1.4": "b8486ea6c6be12db028490d44eb88ff4e8efa4207aa4519dc0387c3566b3b7cb",  # IfStatementAst
    "0.1.154.1.4.1.0": "88577c82dddbad1477806d5b84e4b690f20667ac36b7c3bdf0feb58ea98a0a44",  # AssignmentStatementAst
    "0.1.154.1.5": "ee108c8f1620662c752b3beb3ec597352fac33880ff9d29b4abe71c93a1dbb78",  # AssignmentStatementAst
    "0.1.154.1.5.1.0.3.0.0": "ca9fd4598ab2ad70d8e7d9432d21e424665518bacece8c706e14cad2014fb8c1",  # PipelineAst
    "0.1.154.1.6": "58467dec4d67889fa7d7db39cbedb98ad5a02bea815d1b48853fd3d6038dd49b",  # AssignmentStatementAst
    "0.1.154.1.7": "0efaabe9798d8cd5baa635c77be44fdcc5ce91ceca316ad12cc7e32bc32956d6",  # ForEachStatementAst
    "0.1.154.1.7.2.0": "aed7e9b7aaf5d796c2601e80e5202679b600a8f76f82dc0b7b164d916f543edb",  # TryStatementAst
    "0.1.154.1.7.2.0.0.0": "a5ffa06e4dd13247d43ca147161e3c653cea7c913e3dac742ac8483588756bf2",  # AssignmentStatementAst
    "0.1.154.1.7.2.0.0.1": "3c616368f42716139dc5daa942b2bc1c0c02ae2b272ef82c82311c3b89b86667",  # AssignmentStatementAst
    "0.1.154.1.7.2.0.0.2": "26211420d19c94539d3425b6200b8a40ecbc9d39f11a3218951a3ef4ece3dcfe",  # AssignmentStatementAst
    "0.1.154.1.7.2.0.0.2.1.0.1.0.0.0": "8838f85ac9a15d0934fa8db630eb688e3a41afb14be69e05b8192caa0a311dfe",  # PipelineAst
    "0.1.154.1.7.2.0.0.3": "47b9639336f970553d0595339c38742fd22c90904c61aa7e4751fa650e9b1341",  # AssignmentStatementAst
    "0.1.154.1.7.2.0.0.3.1.0.1.0.0": "63a8140dbfb5b4171bbe1a9a8795ac8bc6b20e752d9a67f6551e78208336f0d8",  # PipelineAst
    "0.1.154.1.7.2.0.0.4": "7b5b7e11b4d269934c9a39d0b19a19ec9de794985b87994ff1d1603733149955",  # AssignmentStatementAst
    "0.1.154.1.7.2.0.0.5": "e786db8e2c3b2f4ba4112d056305ea0df006388cbe0f0c35304dd83121ae8c9a",  # AssignmentStatementAst
    "0.1.154.1.7.2.0.0.6": "24b1b619b53edc0fc8a4ea19afbe96fbb977ac7e24dfbd05054fede0a5a8dc8d",  # IfStatementAst
    "0.1.154.1.7.2.0.0.6.1.0": "cebd97310210fc1767d646e988bf844707a5588f4e21978f6f2821a2db571167",  # AssignmentStatementAst
    "0.1.154.1.7.2.0.0.6.1.0.1.0.1.0.0.0": "12ef845c3f2887bb8c7a520bc74f085dbe0b8b7c81097f9d711bd462e3dc5341",  # PipelineAst
    "0.1.154.1.7.2.0.0.6.1.1": "9b503c71a0f457184f5b10ee0454dcf2275eca48d2b9f0cf2c994f02a8739d1d",  # PipelineAst
    "0.1.154.1.7.2.0.0.6.2.0": "56179bc2a0a32751db587c101a49ef0c14cec1d9469b9f0982288eed51f7af80",  # TryStatementAst
    "0.1.154.1.7.2.0.0.6.2.0.0.0": "fac1efc91523657ba1c93c0b21d0eaf77f688887a9dc9b8d4d2dab86dd46e2ea",  # IfStatementAst
    "0.1.154.1.7.2.0.0.6.2.0.0.0.1.0": "508cab9fdce9315f992fc2139480ea1a229c841ec1d3ce1d630463b1616cc587",  # AssignmentStatementAst
    "0.1.154.1.7.2.0.0.6.2.0.0.0.3.0": "e935b4c6ef34f8e848ea6540ac7a4fee4ad89d34530440f28c931311fbd6d70b",  # AssignmentStatementAst
    "0.1.154.1.7.2.0.0.6.2.0.0.0.4.0": "1c40f4aaf580adf8e0c142d5f7d29317e508df655e4bcf72dbaa9f5323ab1350",  # AssignmentStatementAst
    "0.1.154.1.7.2.0.0.6.2.0.0.1": "77bfacb3dc880af9cd1aa02776744b34f38341e168fccdbd9223551e6153995c",  # AssignmentStatementAst
    "0.1.154.1.7.2.0.0.6.2.0.0.2": "ebca6440c392fe7667e821625ec1c49dca214309039ab7ed351cbea1fcd9d9ac",  # SwitchStatementAst
    "0.1.154.1.7.2.0.0.6.2.0.0.2.2.0": "d858f72330a6000e75e01a86432250bd679f1ea62c6d719da1ad87cdf0bae86b",  # AssignmentStatementAst
    "0.1.154.1.7.2.0.0.6.2.0.0.2.4.0": "22f9ed5b1b2d7403d25493dc91c7b779bb6a75edff0936281d58671cb0c72cc2",  # AssignmentStatementAst
    "0.1.154.1.7.2.0.0.6.2.0.0.3": "1ea5f124b0cabf2c60054c88c91dc019eaedced51617a19712a90285ceb670f4",  # AssignmentStatementAst
    "0.1.154.1.7.2.0.0.6.2.0.0.4": "5ca1cd7c31547219f7848e45b66f7f473a3a11c6bc2c789e5fbf193bb24a9a99",  # SwitchStatementAst
    "0.1.154.1.7.2.0.0.6.2.0.0.4.2.0": "4e0e3f5ada260a0e7d4df1e9aae4357d213790febdd8518a912a28957d18b6ac",  # AssignmentStatementAst
    "0.1.154.1.7.2.0.0.6.2.0.0.4.4.0": "63544e5fb42eee9a8601a9aeed9569d4cb880834d507b8e93a3e4f623792eb5b",  # AssignmentStatementAst
    "0.1.154.1.7.2.0.0.6.2.0.1.0.0": "13180c80731550b8fa5c50bdf9ab0ba4d9c3baa3407a6b76076dee58f2f75978",  # PipelineAst
    "0.1.154.1.7.2.0.0.6.2.0.1.0.0.0.1.1.0.0": "8ab56bc8e56da1f2dcad546712bd9c7197c93cad20ec082a25c6323921435e39",  # PipelineAst
    "0.1.154.1.7.2.0.0.7": "898191f48a582013730182494b3e50752cad67a9b9161bbab203a0d06a812462",  # AssignmentStatementAst
    "0.1.154.1.7.2.0.1.0.0": "91b3580c5e3274ad1bab3e7b2e3b5e22b752e1584a9a1d12069c58ff3feb2905",  # AssignmentStatementAst
    "0.1.154.1.7.2.0.1.0.0.1.0.0.0.0": "220682c522145f341ac6230ce3544edf02eac1cc3260cd44854c7535273f605b",  # PipelineAst
    "0.1.154.1.8": "331d83aedd01254b7b7b3ee82486f9a3f54c5e9ad61a3a29e45f42e7e63c89d2",  # AssignmentStatementAst
    "0.1.154.1.8.1.0.0.0.0": "ac30796e815a9ea7edc7ae9fa580e27803d3aa4ff09d5151c69da888fef14fce",  # PipelineAst
    "0.1.154.1.8.1.0.0.0.0.1.1.0.0.0": "c40bc3d4688ecc380240e25555d63d82d193e9c9499dec18accbe58a4adcacca",  # PipelineAst
    "0.1.154.1.9": "030e905d7a662971cbb0163d81a0c7d8e79fefbea5e337a91621ca98a0b95730",  # IfStatementAst
    "0.1.154.1.9.1.0": "12d3968655953f32ca0a89812ac297bfc1410e77bb31ce221d5caad7e7d1a743",  # PipelineAst
    "0.1.154.1.9.1.0.0.1.0.0.0": "f841a508c4e545d63c1b8279e6b94ade66698d610ec9de258d3a3723cf6d721f",  # PipelineAst
    "0.1.154.1.9.1.1": "680d718327d5bb8fb3fad8bd12187db26d6c80588d5a82fb10c0d2cd32d8b458",  # AssignmentStatementAst
    "0.1.154.1.9.2.0": "21200a24b25fd9eef5724d8895aef6d042c6e2e18c76a376ad06de26d600a779",  # AssignmentStatementAst
    "0.1.154.1.9.2.1": "e3ffa0787ae9cba9bbd18519162e42c82a550c69bfa1419443d9ec2e5a4d1cf2",  # PipelineAst
    "0.1.154.1.9.2.1.0.3.0.0.0": "69c974c7f35c027b60a24b91c05b5f5b643611f56bb6ae6a6f00a68e0baa4289",  # PipelineAst
    "0.1.155": "24edccfd503ee2c539d6c4cd4c98f08686e091ede8466ac7e5f7f399e04c62c2",  # AssignmentStatementAst
    "0.1.156": "e7396775fa7310147870f1747204cb45d2978d302789e9c7f37f630ff401b072",  # IfStatementAst
    "0.1.156.1.0": "f6ea1a46649d14d12ee39a8ad1ef7f2c056c197cf965dd7f8be0e4fb3876a424",  # AssignmentStatementAst
    "0.1.157": "1e694192bb65d084e6a6779ec3f180d9dde627062189cce066724367f48828c6",  # IfStatementAst
    "0.1.157.1.0": "b3f0715f0f4a11ae4f54835f01f2352876e51bb7b4c5f1cee16d8c2e343864d9",  # AssignmentStatementAst
    "0.1.158": "8e4e855d3046291950768e5a201823b55ecf08600719e817fe49f310fd03576f",  # IfStatementAst
    "0.1.158.1.0": "4ef826b478e3dfc7ff4ac248fd9cf583fe83af81d68f18f9b6dd8849f9e484f1",  # AssignmentStatementAst
    "0.1.159": "2cc77e52a6ce36d0ac787ebd4a6dd754fbae4ad60743bd18f12b32d940f4caeb",  # IfStatementAst
    "0.1.159.1.0": "9de9bd940b1273abaa22c5a8f63f2b608200d8bfe9b1f6641113b16de54ece7b",  # AssignmentStatementAst
    "0.1.160": "dc698be60320a90fa36715daa8375143951f9b9c0bdfaa0e9320ac83e7499f82",  # IfStatementAst
    "0.1.160.1.0": "975ecd1f88c80c5dae1c03a8304137b6d4df1182d649c3ad0e3a602c48dbf25c",  # AssignmentStatementAst
    "0.1.161": "e10c825de698a205ff169e639b685c02cc360734404797aa2d6f60ac37a847b8",  # AssignmentStatementAst
    "0.1.161.1.0.1.11.0.0.0.0.0.0.0": "17ff385c664fb5917860d21a7b337e638839823fcc32335678be0766f4805cf1",  # PipelineAst
    "0.1.162": "5143a74c84dbad78b43c3f2859474dc5991a814a87461fb904b4148a2e089cb9",  # PipelineAst
    "0.1.162.0.1.0.0": "398e6bc3f9b577fc0dbdf6f01db3d525c0c0daa8738e90c88e7c8d62b27e9313",  # PipelineAst
    "0.1.163": "382bff8765bdcb5bd8c991dc4e9ca8c19b8bbb01dc844c1fd84567f41d85374b",  # PipelineAst
    "0.1.163.0.1.0.0": "7484ffaf730e9eee8438f6b07aee58f313b78ea3c75d19acf800817681b12449",  # PipelineAst
    "0.1.164": "e24585090032080cf1116319bb54b5fd98dd187451464df0b6deed26dadb4d82",  # PipelineAst
    "0.1.164.0.1.0.0": "9011bda6274f9463802fa939ac007f8ecf724a0f4a3d77187f7647ded934cc1e",  # PipelineAst
    "0.1.165": "bb76137ea7f91b1354a08676a68bb18fb64bbb35341c33a1f14b11aeed03d00b",  # PipelineAst
    "0.1.165.0.1.0.0": "a0c623905f9dbcab14a5c6e594dee6232d68a5dd9ba8d6ba4aad19da340df2bf",  # PipelineAst
    "0.1.166": "544d87efb32e562b1a1d08df5ad9e778f7016081802ea5b97ab09574e5dda965",  # PipelineAst
    "0.1.166.0.1.0.0": "ef17c70f3004868c472e5f749c0f4818e734857d668822256d281288f9104840",  # PipelineAst
    "0.1.167": "48913f309adebaba5c6472405715f8f0fe5b9124bae53c0fe6a43e78f7174989",  # PipelineAst
    "0.1.167.0.1.0.0": "b757984c3fd5dfa527a03c81eadb8b44000ce946e53b155a2e8ba7290fbbe66d",  # PipelineAst
    "0.1.168": "f1a00d7e9a47a44026d0b2861a0231f3f618a4f83eb6b8e721a844eed6e9552c",  # PipelineAst
    "0.1.168.0.1.0.0": "47213a7ceaa4b1e2db9ff3ed6af7373f9c97ce0d28cacc4dde3387fd9881780e",  # PipelineAst
    "0.1.169": "89fd65e928d99efb9753143cbcea684bb9b02f834061ae1aa174d2c3355538d1",  # PipelineAst
    "0.1.170": "faf2af4090f6352aa4edd16f13a12998aab8b864af29b0f6e65fd4de4f53099d",  # PipelineAst
    "0.1.171": "7cd99ddc1f5d6e47469e4dec2c7eaadcb405f694cdfe92176ba00a86d9ef3a5f",  # IfStatementAst
    "0.1.171.1.0": "e4bf77966cb1b0d93347ab6fca0e3af9a69b2e017dff406a5090c3d9cf55eddb",  # PipelineAst
    "0.1.171.1.0.0.1.0.0.0.1.1.0.0.0.0": "8dc3cf1fc60c51d5d605ba0b38dc2b27463ab1852c6709334ccf09abf96cea85",  # PipelineAst
    "0.1.171.1.0.0.1.0.0.0.1.3.0.0.0.0": "1d8a81e0f91678e6de9607375b5d4e61e4a4aee292af9b036f4003045f43fb9e",  # PipelineAst
    "0.1.172": "8dfc28fa0eed6291366b196286b86d0e0bcba241df430d30f8fc8f1647b0c341",  # PipelineAst
    "0.1.173": "cae6cea515683c149a8206259b08dbc9a567689bbba9918b5b2e2de04120fbb0",  # PipelineAst
    "0.1.173.0.1.0.0.0.1.9.0.0.0.0.0.0.0.0.0": "0a6bbc7d1041335c4178f3e74b8e85d5b8addce09aee05ab332a446110e7516a",  # PipelineAst
    "0.1.173.0.1.0.0.0.1.9.0.0.0.0.0.1.1.0.0.0": "b9754d0b676ee1739a5eaaf580c1bf0b14440c487c80e132cc5e032ae9a2efc9",  # PipelineAst
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
HEADER_SHA256 = "b436b5e02129b84dbbb1742979d1741882e5111aae9aad0c9d365be9de65ee9b"

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
    # parameter of _bothScopes, called by a binding of $<script>::sslrequired
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
    # input of _iisRead: _iisRead $ps $loc $auth 'enabled'
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
    # input of _markSearch: _markSearch 'pki-acls' $pkiSearch (6 + $caObjects.returned + $esObjects.returned + $caComputerDns.Count) $pkiAcls.Count (@($caObjects.failures) + @($esObjects.failures) + $caComputerFailures)
    "<script>::cacomputerdns": [
        ("assign Equals", "@()"),
        ("assign PlusEquals", "$computerDn"),
    ],
    # input of _markSearch: _markSearch 'pki-acls' $pkiSearch (6 + $caObjects.returned + $esObjects.returned + $caComputerDns.Count) $pkiAcls.Count (@($caObjects.failures) + @($esObjects.failures) + $caComputerFailures)
    "<script>::cacomputerfailures": [
        ("assign Equals", "@($esObjects.misses)"),
        ("assign PlusEquals", '"the CA host computer object $computerDn could not be read"'),
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
    # condition $caHostsHere -notcontains $dnsKey
    "<script>::cahostshere": [
        ("assign Equals", "@()"),
        ("assign PlusEquals", "$dnsKey"),
    ],
    # input of _markSearch: _markSearch 'pki-acls' $pkiSearch (6 + $caObjects.returned + $esObjects.returned + $caComputerDns.Count) $pkiAcls.Count (@($caObjects.failures) + @($esObjects.failures) + $caComputerFailures)
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
    # condition $check.soft -notcontains 'mspki-ra-signature'
    "<script>::check": [
        ("assign Equals", "_requireSchema $p 'dc-config'"),
        ("assign Equals", "_requireSchema $p 'templates'"),
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
        ("assign Equals", "'0.12.0'"),
    ],
    # condition $computerAcl
    "<script>::computeracl": [
        ("assign Equals", "_objAcl $computerDn 'ca_computer'"),
    ],
    # input of _objAcl: _objAcl $computerDn 'ca_computer'
    "<script>::computerdn": [
        ("foreach", "$caComputerDns"),
        ("foreach", "@($esObjects.hosts)"),
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
    # condition $caHostsHere -notcontains $dnsKey
    "<script>::dnskey": [
        ("assign Equals", "$dns -replace '\\.$', ''"),
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
    # condition $null -eq $epa
    "<script>::epa": [
        ("assign Equals", "_bothScopes (_epaToken $tc.app) (_epaToken $tc.apphost)"),
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
    # input of _markSearch: _markSearch 'pki-acls' $pkiSearch (6 + $caObjects.returned + $esObjects.returned + $caComputerDns.Count) $pkiAcls.Count (@($caObjects.failures) + @($esObjects.failures) + $caComputerFailures)
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
        (
            "assign PlusEquals",
            "\"$appPath extendedProtection tokenChecking not obtained (application: '$($tc.app)', applicationHost location: '$($tc.apphost)')\"",
        ),
        (
            "assign PlusEquals",
            "\"$appPath sslFlags not obtained (application: '$($ssl.app)', applicationHost location: '$($ssl.apphost)')\"",
        ),
        (
            "assign PlusEquals",
            "\"$appPath windowsAuthentication enabled not obtained (application: '$($wa.app)', applicationHost location: '$($wa.apphost)')\"",
        ),
        ("assign PlusEquals", "\"IIS application under '$($site.Name)' has no readable path\""),
    ],
    # condition $iisHere
    "<script>::iishere": [
        ("assign Equals", "$false"),
        ("assign Equals", "($caHost -and $caHost -eq $localHost)"),
        ("assign Equals", "($dnsKey -and $dnsKey -eq $localFqdn)"),
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
            'ConvertFrom-Json @\' { "publication": { "field": "template.published_by", "by": "ingest", "impl": "resolve_join", "from": "enrollment-services.certificatetemplates", "to": "templates", "keys": ["cn"], "legacy_keys": ["cn", "oid"], "compare": "identical (MS-WCCE)", "none": "attaches nowhere (a published template that is not in AD)", "ambiguous": "published_by not obtained for every template it is identical or folds to" }, "cert-ca": { "field": "cert.ca_kind", "by": "ingest", "impl": "resolve_join", "from": "certs.ca_name", "to": "ca-config", "keys": ["cn"], "compare": "identical (both are cn values the collector copied)", "none": "unattached: ca_kind not obtained", "ambiguous": "unattached: ca_kind not obtained (two CA rows folding together is an ingest error)" }, "crl-tier": { "field": "crl.tier", "by": "ingest", "impl": "resolve_join", "from": "crls.ca_name (the CDP object\'s cn)", "to": "certs (certs/index.json ca_name)", "keys": ["ca_name"], "compare": "identical", "none": "tier null", "ambiguous": "tier null (also when one cn\'s certificates disagree on kind)" }, "ca-security": { "field": "ca.security", "by": "ingest", "impl": "exact set", "from": "ca-security.json keys", "to": "ca-config", "keys": ["cn"], "compare": "identical (the collector writes the row\'s name)", "none": "ingest error: an entry naming no CA, or a CA without an entry", "ambiguous": "ingest error: two CA rows whose names fold together" }, "publisher-ca": { "field": "ca.enrollment_service", "by": "ingest", "impl": "exact set", "from": "enrollment-services.json keys", "to": "ca-config", "keys": ["cn"], "compare": "identical (the collector writes the row\'s name)", "none": "ingest error: a publisher without a CA row, or the reverse", "ambiguous": "ingest error: two CA rows whose names fold together" }, "oid-link": { "field": "oid.group_link", "by": "detection (ESC13)", "impl": "resolve_join", "from": "templates.issuance_policy_oids", "to": "oid-objects", "keys": ["oid"], "compare": "identical", "none": "no link: decided only when oid-objects is complete", "ambiguous": "ESC13 undecided (duplicate OIDs also mark oid-objects incomplete)" }, "local-ca": { "field": "ca.edit_flags", "by": "collector", "impl": "-ceq", "from": "enrollment-services.cn", "to": "certutil CA\\\\CommonName", "keys": ["cn"], "compare": "identical (-ceq)", "none": "a remote CA: every registry field null (also for a CA whose AD name is sanitized)", "ambiguous": "ingest error: the local CA\'s standalone row and the enrollment service fold together" }, "ca-host": { "field": "pki.ca_host_sid", "by": "collector", "impl": "-ceq", "from": "enrollment-services dnshostname (the pki-acls row of the enrollment service)", "to": "computer objects in the domain NC", "keys": ["dnshostname"], "compare": "identical (-ceq) on the returned dNSHostName (the LDAP filter only narrows the search)", "none": "ca_host_sid null (not obtained), e.g. the CA host is in another domain; its computer object is not read and pki-acls is incomplete", "ambiguous": "ca_host_sid null (not obtained): two computer objects answer, or only one that differs in case; no computer object is read and pki-acls is incomplete" }, "app-site": { "field": "endpoint.transports", "by": "collector", "impl": "parent object", "from": "IIS application", "to": "its IIS site", "keys": ["(parent object)"], "compare": "enumerated under the site", "none": "transports null when the site\'s bindings read nothing", "ambiguous": "impossible: each application is enumerated under one site" } } \'@',
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
    # input of _iisRead: _iisRead $ps $loc $auth 'enabled'
    "<script>::loc": [
        ("assign Equals", '"$($site.Name)$appPath"'),
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
            "[ordered]@{ 0x00000001 = 'ENROLLEE_SUPPLIES_SUBJECT' 0x00000008 = 'OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME' 0x00010000 = 'ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME' 0x00400000 = 'SUBJECT_ALT_REQUIRE_DOMAIN_DNS' 0x00800000 = 'SUBJECT_ALT_REQUIRE_SPN' 0x01000000 = 'SUBJECT_ALT_REQUIRE_DIRECTORY_GUID' 0x02000000 = 'SUBJECT_ALT_REQUIRE_UPN' 0x04000000 = 'SUBJECT_ALT_REQUIRE_EMAIL' 0x08000000 = 'SUBJECT_ALT_REQUIRE_DNS' 0x10000000 = 'SUBJECT_REQUIRE_DNS_AS_CN' 0x20000000 = 'SUBJECT_REQUIRE_EMAIL' 0x40000000 = 'SUBJECT_REQUIRE_COMMON_NAME' 0x80000000 = 'SUBJECT_REQUIRE_DIRECTORY_PATH' }",
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
            'ConvertFrom-Json @\' { "enrollment-services": { "distinguishedname": {"type": "string", "need": "required", "field": "(identity)"}, "cn": {"type": "string", "need": "required", "field": "name"}, "objectguid": {"type": "guid", "need": "required", "field": "object_guid"}, "dnshostname": {"type": "string", "need": "optional", "field": "dns"}, "certificatetemplates": {"type": "strings", "need": "optional", "field": "(source of template.published_by)"} }, "templates": { "distinguishedname": {"type": "string", "need": "required", "field": "(identity)"}, "cn": {"type": "string", "need": "required", "field": "name"}, "objectguid": {"type": "guid", "need": "required", "field": "object_guid"}, "mspki-cert-template-oid": {"type": "string", "need": "required", "field": "oid"}, "displayname": {"type": "string", "need": "optional", "field": "display_name"}, "mspki-certificate-name-flag": {"type": "int", "need": "optional", "field": "name_flags"}, "mspki-enrollment-flag": {"type": "int", "need": "optional", "field": "enrollment_flags"}, "pkiextendedkeyusage": {"type": "strings", "need": "optional", "field": "ekus"}, "mspki-certificate-policy": {"type": "strings", "need": "optional", "field": "issuance_policy_oids"}, "pkicsp": {"type": "strings", "need": "optional", "field": "csp"}, "mspki-template-schema-version": {"type": "int", "need": "optional", "field": "schema_version"}, "mspki-minimal-key-size": {"type": "int", "need": "optional", "field": "min_key_size"}, "mspki-ra-signature": {"type": "int", "need": "placeholder", "field": "ra_signatures"}, "ntsecuritydescriptor": {"type": "bytes", "need": "sd", "field": "security"} }, "oid-objects": { "distinguishedname": {"type": "string", "need": "required", "field": "(identity)"}, "mspki-cert-template-oid": {"type": "string", "need": "required", "field": "oid"}, "objectguid": {"type": "guid", "need": "required", "field": "object_guid"}, "displayname": {"type": "string", "need": "optional", "field": "name"}, "msds-oidtogrouplink": {"type": "string", "need": "optional", "field": "group_link"} }, "pki-acls": { "distinguishedname": {"type": "string", "need": "required", "field": "object_dn"}, "objectguid": {"type": "guid", "need": "required", "field": "object_guid"}, "dnshostname": {"type": "string", "need": "optional", "field": "(source of pki.ca_host_sid)"}, "ntsecuritydescriptor": {"type": "bytes", "need": "sd", "field": "security"} }, "certs": { "distinguishedname": {"type": "string", "need": "required", "field": "(identity)"}, "cn": {"type": "string", "need": "required", "field": "ca_name"}, "cacertificate": {"type": "bytes", "need": "optional", "field": "(certificate)"} }, "crls": { "distinguishedname": {"type": "string", "need": "required", "field": "source"}, "cn": {"type": "string", "need": "required", "field": "ca_name"}, "objectguid": {"type": "guid", "need": "required", "field": "object_guid"}, "certificaterevocationlist": {"type": "bytes", "need": "optional", "field": "(crl)"} }, "principal-mappings": { "distinguishedname": {"type": "string", "need": "required", "field": "dn"}, "objectguid": {"type": "guid", "need": "required", "field": "object_guid"}, "altsecurityidentities": {"type": "strings", "need": "required", "field": "mappings"} }, "dc-config": { "distinguishedname": {"type": "string", "need": "required", "field": "(identity)"}, "objectguid": {"type": "guid", "need": "required", "field": "object_guid"}, "dnshostname": {"type": "string", "need": "placeholder", "field": "name"} } } \'@',
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
    # input of _markSearch: _markSearch 'pki-acls' $pkiSearch (6 + $caObjects.returned + $esObjects.returned + $caComputerDns.Count) $pkiAcls.Count (@($caObjects.failures) + @($esObjects.failures) + $caComputerFailures)
    "<script>::pkiacls": [
        ("assign Equals", "@()"),
        ("assign PlusEquals", "$a"),
        ("assign PlusEquals", "$caObjects.rows"),
        ("assign PlusEquals", "$computerAcl"),
        ("assign PlusEquals", "$esObjects.rows"),
        (
            "assign PlusEquals",
            "[ordered]@{ object_dn = $pair[0]; kind = $pair[1]; owner_sid = $null object_guid = '' # the object could not be read at all security = $null; acl_obtained = $false enrollment_service = $false ca_host_sid = '' }",
        ),
    ],
    # input of _markSearch: _markSearch 'pki-acls' $pkiSearch (6 + $caObjects.returned + $esObjects.returned + $caComputerDns.Count) $pkiAcls.Count (@($caObjects.failures) + @($esObjects.failures) + $caComputerFailures)
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
    # input of _iisRead: _iisRead $ps $loc $auth 'enabled'
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
    # condition $null -ne $ra -and $ra -lt 0
    "<script>::ra": [
        ("assign Equals", "$null"),
        ("assign Equals", "$null"),
        ("assign Equals", "[int]@(_v $p 'mspki-ra-signature')[0]"),
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
    # input of _bothScopes: _bothScopes (_sslRequiredFrom $ssl.app) (_sslRequiredFrom $ssl.apphost)
    "<script>::ssl": [
        ("assign Equals", "_iisRead $ps $loc 'system.webServer/security/access' 'sslFlags'"),
    ],
    # condition $null -eq $sslRequired
    "<script>::sslrequired": [
        (
            "assign Equals",
            "_bothScopes (_sslRequiredFrom $ssl.app) (_sslRequiredFrom $ssl.apphost)",
        ),
    ],
    # input of _markSearch: _markSearch 'ca-config' $caSearch (@($es.entries).Count + $standalone) $caConfig.Count $esFailures
    "<script>::standalone": [
        ("assign Equals", "0"),
        ("assign Equals", "1"),
    ],
    # input of _bothScopes: _bothScopes (_epaToken $tc.app) (_epaToken $tc.apphost)
    "<script>::tc": [
        ("assign Equals", "_iisRead $ps $loc $auth 'extendedProtection.tokenChecking'"),
    ],
    # input of _markSearch: _markSearch 'templates' $ts @($ts.entries).Count $templates.Count $tsFailures
    "<script>::templates": [
        ("assign Equals", "@()"),
        (
            "assign PlusEquals",
            "[ordered]@{ name = [string]@(_v $p 'cn')[0] object_guid = (_guidHex @(_v $p 'objectguid')) display_name = [string]@(_v $p 'displayname')[0] schema_version = if (@(_v $p 'mspki-template-schema-version').Count) { [int]@(_v $p 'mspki-template-schema-version')[0] } else { 1 } oid = [string]@(_v $p 'mspki-cert-template-oid')[0] ekus = (@(_v $p 'pkiextendedkeyusage' | ForEach-Object { [string]$_ })) name_flags = (_decode $nf $NAME_FLAGS) enrollment_flags = (_decode $ef $ENROLL_FLAGS) min_key_size = if (@(_v $p 'mspki-minimal-key-size').Count) { [int]@(_v $p 'mspki-minimal-key-size')[0] } else { $null } ra_signatures = $ra # authorized signatures required; null if not obtained issuance_policy_oids = (@(_v $p 'mspki-certificate-policy' | ForEach-Object { [string]$_ })) csp = (($csps -join ', ').ToLower()) security = $sec.aces # template DACL -> ACEs (ESC1/ESC4); null if not obtained acl_obtained = ($null -ne $sec.aces) # SD requested, returned and parsed owner_sid = $sec.owner }",
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
            "_search \"CN=Certificate Templates,$pksDn\" '(objectClass=pKICertificateTemplate)' @( 'cn', 'displayname', 'objectguid', 'mspki-certificate-name-flag', 'mspki-enrollment-flag', 'pkiextendedkeyusage', 'mspki-certificate-policy', 'pkicsp', 'mspki-template-schema-version', 'mspki-cert-template-oid', 'mspki-minimal-key-size', 'mspki-ra-signature', 'ntsecuritydescriptor') -Sd",
        ),
    ],
    # input of _markSearch: _markSearch 'templates' $ts @($ts.entries).Count $templates.Count $tsFailures
    "<script>::tsfailures": [
        ("assign Equals", "@()"),
        ("assign PlusEquals", '"template: $($_.Exception.Message)"'),
    ],
    # input of _bothScopes: _bothScopes (_iisBool $wa.app) (_iisBool $wa.apphost)
    "<script>::wa": [
        ("assign Equals", "_iisRead $ps $loc $auth 'enabled'"),
    ],
    # input of _searchMarker: _searchMarker ($endpointsComplete -and -not $endpointScope) $endpointsWhy $webEndpoints.Count $webEndpoints.Count $iisFailures
    "<script>::webendpoints": [
        ("assign Equals", "@()"),
        (
            "assign PlusEquals",
            "[ordered]@{ kind = $kind name = $appPath host = $localFqdn transports = $transports ssl_required = $sslRequired windows_auth = $windowsAuth auth_providers = (_list $provs) epa = $epa }",
        ),
    ],
    # condition $null -eq $windowsAuth
    "<script>::windowsauth": [
        ("assign Equals", "_bothScopes (_iisBool $wa.app) (_iisBool $wa.apphost)"),
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
    # condition $null -eq $app -or $null -eq $apphost
    "_bothscopes::app": [
        ("arg", "(_epaToken $tc.app)"),
        ("arg", "(_iisBool $wa.app)"),
        ("arg", "(_sslRequiredFrom $ssl.app)"),
        ("parameter", "$app"),
    ],
    # condition $null -eq $app -or $null -eq $apphost
    "_bothscopes::apphost": [
        ("arg", "(_epaToken $tc.apphost)"),
        ("arg", "(_iisBool $wa.apphost)"),
        ("arg", "(_sslRequiredFrom $ssl.apphost)"),
        ("parameter", "$apphost"),
    ],
    # input of _search: _search (_rootDse).domain "(&(objectCategory=computer)(dNSHostName=$(_ldapEscape $dns)))" @('objectsid', 'dnshostname')
    "_cahost::dns": [
        ("assign Equals", "[string]@($dnsValues)[0]"),
    ],
    # condition @($dnsValues).Count -ne 1
    "_cahost::dnsvalues": [
        ("arg", "@(_v $p 'dnshostname')"),
        ("parameter", "$dnsValues"),
    ],
    # input of _entryProps: _entryProps $e
    "_cahost::e": [
        ("foreach", "$r.entries"),
    ],
    # input of _sidString: _sidString @(_v $hits[0] 'objectsid')
    "_cahost::hits": [
        ("assign Equals", "@()"),
        ("assign PlusEquals", ",$hp"),
    ],
    # input of _v: _v $hp 'dnshostname'
    "_cahost::hp": [
        ("assign Equals", "_entryProps $e"),
    ],
    # condition -not $r.complete -or @($r.entries).Count -ne 1
    "_cahost::r": [
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
    # condition $null -ne $caHostObject
    "_childacls::cahostobject": [
        ("assign Equals", "_caHost @(_v $p 'dnshostname')"),
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
        ("assign Equals", "$caHostObject.sid"),
        ("assign Equals", "$null"),
        ("assign Equals", "''"),
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
    # condition $null -eq $v -or $v -is [bool]
    "_epatoken::v": [
        ("arg", "$tc.app"),
        ("arg", "$tc.apphost"),
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
    # condition $v -is [bool]
    "_iisbool::v": [
        ("arg", "$wa.app"),
        ("arg", "$wa.apphost"),
        ("parameter", "$v"),
    ],
    # input of _iisScalar: _iisScalar $app
    "_iisread::app": [
        (
            "assign Equals",
            "_tryRead { Get-WebConfigurationProperty -PSPath $ps -Filter $filter -Name $name -ErrorAction Stop }",
        ),
    ],
    # input of _iisScalar: _iisScalar $apphost
    "_iisread::apphost": [
        (
            "assign Equals",
            "_tryRead { Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Location $loc -Filter $filter -Name $name -ErrorAction Stop }",
        ),
    ],
    # input of _tryRead: _tryRead { Get-WebConfigurationProperty -PSPath $ps -Filter $filter -Name $name -ErrorAction Stop }
    "_iisread::filter": [
        ("arg", "$auth"),
        ("arg", "$auth"),
        ("arg", "'system.webServer/security/access'"),
        ("parameter", "[string]$filter"),
    ],
    # input of _tryRead: _tryRead { Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Location $loc -Filter $filter -Name $name -ErrorAction Stop }
    "_iisread::loc": [
        ("arg", "$loc"),
        ("arg", "$loc"),
        ("arg", "$loc"),
        ("parameter", "[string]$loc"),
    ],
    # input of _tryRead: _tryRead { Get-WebConfigurationProperty -PSPath $ps -Filter $filter -Name $name -ErrorAction Stop }
    "_iisread::name": [
        ("arg", "'enabled'"),
        ("arg", "'extendedProtection.tokenChecking'"),
        ("arg", "'sslFlags'"),
        ("parameter", "[string]$name"),
    ],
    # input of _tryRead: _tryRead { Get-WebConfigurationProperty -PSPath $ps -Filter $filter -Name $name -ErrorAction Stop }
    "_iisread::ps": [
        ("arg", "$ps"),
        ("arg", "$ps"),
        ("arg", "$ps"),
        ("parameter", "[string]$ps"),
    ],
    # condition $inner -is [string] -or $inner -is [bool] -or $inner -is [int]
    "_iisscalar::inner": [
        ("assign Equals", "$v.Value"),
    ],
    # condition $items.Count -ne 1 -or $null -eq $items[0]
    "_iisscalar::items": [
        ("assign Equals", "@($read.value)"),
    ],
    # condition $null -eq $read -or -not $read.ok
    "_iisscalar::read": [
        ("arg", "$app"),
        ("arg", "$apphost"),
        ("parameter", "$read"),
    ],
    # condition $v -is [string] -or $v -is [bool] -or $v -is [int]
    "_iisscalar::v": [
        ("assign Equals", "$items[0]"),
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
    # parameter of _ldapEscape, called by a binding of $_cahost::r
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
        ("arg", "(@($caObjects.failures) + @($esObjects.failures) + $caComputerFailures)"),
        ("parameter", "[string[]]$failures"),
    ],
    # input of _searchMarker: _searchMarker ([bool]$search.complete) ([string]$search.reason) $returned $written $failures $rows
    "_marksearch::returned": [
        ("arg", "(6 + $caObjects.returned + $esObjects.returned + $caComputerDns.Count)"),
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
        ("arg", "$computerDn"),
        ("arg", "$pair[0]"),
        ("parameter", "[string]$dn"),
    ],
    # input of _aclRow: _aclRow $p $kind '' $false
    "_objacl::kind": [
        ("arg", "$pair[1]"),
        ("arg", "'ca_computer'"),
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
    # parameter of _sslRequiredFrom, called by a binding of $<script>::sslrequired
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
    # parameter of _iisRead, called by a binding of $<script>::ssl
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
    # parameter of _iisRead, called by a binding of $<script>::ssl
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
            "@( 'cn', 'displayname', 'objectguid', 'mspki-certificate-name-flag', 'mspki-enrollment-flag', 'pkiextendedkeyusage', 'mspki-certificate-policy', 'pkicsp', 'mspki-template-schema-version', 'mspki-cert-template-oid', 'mspki-minimal-key-size', 'mspki-ra-signature', 'ntsecuritydescriptor')",
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
    # condition @('None', 'Ssl', 'SslNegotiateCert', 'SslRequireCert', 'SslMapCert', 'Ssl128') -notcontains $n
    "_sslrequiredfrom::n": [
        ("foreach", "$names"),
    ],
    # condition $names -contains 'None' -and $names.Count -ne 1
    "_sslrequiredfrom::names": [
        ("assign Equals", "@(([string]$v) -split '\\s*,\\s*')"),
    ],
    # condition $ssl128 -and -not $ssl
    "_sslrequiredfrom::ssl": [
        ("assign Equals", "$names -contains 'Ssl'"),
        ("assign Equals", "($v -band 8) -ne 0"),
    ],
    # condition $ssl128 -and -not $ssl
    "_sslrequiredfrom::ssl128": [
        ("assign Equals", "$names -contains 'Ssl128'"),
        ("assign Equals", "($v -band 256) -ne 0"),
    ],
    # condition $null -eq $v -or $v -is [bool]
    "_sslrequiredfrom::v": [
        ("arg", "$ssl.app"),
        ("arg", "$ssl.apphost"),
        ("parameter", "$v"),
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
            "{ Get-WebConfigurationProperty -PSPath $ps -Filter $filter -Name $name -ErrorAction Stop }",
        ),
        (
            "arg",
            "{ Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Location $loc -Filter $filter -Name $name -ErrorAction Stop }",
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
        ("arg", "'mspki-ra-signature'"),
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
        'ConvertFrom-Json @\' { "enrollment-services": { "distinguishedname": {"type": "string", "need": "required", "field": "(identity)"}, "cn": {"type": "string", "need": "required", "field": "name"}, "objectguid": {"type": "guid", "need": "required", "field": "object_guid"}, "dnshostname": {"type": "string", "need": "optional", "field": "dns"}, "certificatetemplates": {"type": "strings", "need": "optional", "field": "(source of template.published_by)"} }, "templates": { "distinguishedname": {"type": "string", "need": "required", "field": "(identity)"}, "cn": {"type": "string", "need": "required", "field": "name"}, "objectguid": {"type": "guid", "need": "required", "field": "object_guid"}, "mspki-cert-template-oid": {"type": "string", "need": "required", "field": "oid"}, "displayname": {"type": "string", "need": "optional", "field": "display_name"}, "mspki-certificate-name-flag": {"type": "int", "need": "optional", "field": "name_flags"}, "mspki-enrollment-flag": {"type": "int", "need": "optional", "field": "enrollment_flags"}, "pkiextendedkeyusage": {"type": "strings", "need": "optional", "field": "ekus"}, "mspki-certificate-policy": {"type": "strings", "need": "optional", "field": "issuance_policy_oids"}, "pkicsp": {"type": "strings", "need": "optional", "field": "csp"}, "mspki-template-schema-version": {"type": "int", "need": "optional", "field": "schema_version"}, "mspki-minimal-key-size": {"type": "int", "need": "optional", "field": "min_key_size"}, "mspki-ra-signature": {"type": "int", "need": "placeholder", "field": "ra_signatures"}, "ntsecuritydescriptor": {"type": "bytes", "need": "sd", "field": "security"} }, "oid-objects": { "distinguishedname": {"type": "string", "need": "required", "field": "(identity)"}, "mspki-cert-template-oid": {"type": "string", "need": "required", "field": "oid"}, "objectguid": {"type": "guid", "need": "required", "field": "object_guid"}, "displayname": {"type": "string", "need": "optional", "field": "name"}, "msds-oidtogrouplink": {"type": "string", "need": "optional", "field": "group_link"} }, "pki-acls": { "distinguishedname": {"type": "string", "need": "required", "field": "object_dn"}, "objectguid": {"type": "guid", "need": "required", "field": "object_guid"}, "dnshostname": {"type": "string", "need": "optional", "field": "(source of pki.ca_host_sid)"}, "ntsecuritydescriptor": {"type": "bytes", "need": "sd", "field": "security"} }, "certs": { "distinguishedname": {"type": "string", "need": "required", "field": "(identity)"}, "cn": {"type": "string", "need": "required", "field": "ca_name"}, "cacertificate": {"type": "bytes", "need": "optional", "field": "(certificate)"} }, "crls": { "distinguishedname": {"type": "string", "need": "required", "field": "source"}, "cn": {"type": "string", "need": "required", "field": "ca_name"}, "objectguid": {"type": "guid", "need": "required", "field": "object_guid"}, "certificaterevocationlist": {"type": "bytes", "need": "optional", "field": "(crl)"} }, "principal-mappings": { "distinguishedname": {"type": "string", "need": "required", "field": "dn"}, "objectguid": {"type": "guid", "need": "required", "field": "object_guid"}, "altsecurityidentities": {"type": "strings", "need": "required", "field": "mappings"} }, "dc-config": { "distinguishedname": {"type": "string", "need": "required", "field": "(identity)"}, "objectguid": {"type": "guid", "need": "required", "field": "object_guid"}, "dnshostname": {"type": "string", "need": "placeholder", "field": "name"} } } \'@',
        (),
    ),
    (
        'ConvertFrom-Json @\' { "crl.tier": { "by": "ingest", "from": ["certs.kind"], "containers": ["certs"], "join": "the CRL\'s CDP cn = the AIA object\'s cn", "miss": "null" }, "endpoint.transports": { "by": "collector", "from": ["IIS site bindings"], "containers": ["web-endpoints"], "join": "the application\'s site", "miss": "null" }, "template.published_by": { "by": "ingest", "from": ["enrollment-services.certificatetemplates"], "containers": ["enrollment-services"], "join": "template cn, exactly ($JOINS publication)", "miss": "unpublished only when enrollment-services is complete", "text": "ESC1-3 and ESC15 publication detail says the list is incomplete when it is" }, "pki.ca_host_sid": { "by": "collector", "from": ["the CA host\'s computer object objectSid (domain NC)"], "containers": [], "join": "the enrollment service\'s dNSHostName = the computer object\'s dNSHostName ($JOINS ca-host)", "miss": "null (not obtained): ESC5 cannot tell the CA host\'s own grant apart and is undecided" }, "cert.ca_kind": { "by": "ingest", "from": ["ca.kind"], "containers": ["ca-config"], "join": "certs/index.json ca_name = CA name", "miss": "null (unattached certificate)" } } \'@',
        (),
    ),
    (
        'ConvertFrom-Json @\' { "publication": { "field": "template.published_by", "by": "ingest", "impl": "resolve_join", "from": "enrollment-services.certificatetemplates", "to": "templates", "keys": ["cn"], "legacy_keys": ["cn", "oid"], "compare": "identical (MS-WCCE)", "none": "attaches nowhere (a published template that is not in AD)", "ambiguous": "published_by not obtained for every template it is identical or folds to" }, "cert-ca": { "field": "cert.ca_kind", "by": "ingest", "impl": "resolve_join", "from": "certs.ca_name", "to": "ca-config", "keys": ["cn"], "compare": "identical (both are cn values the collector copied)", "none": "unattached: ca_kind not obtained", "ambiguous": "unattached: ca_kind not obtained (two CA rows folding together is an ingest error)" }, "crl-tier": { "field": "crl.tier", "by": "ingest", "impl": "resolve_join", "from": "crls.ca_name (the CDP object\'s cn)", "to": "certs (certs/index.json ca_name)", "keys": ["ca_name"], "compare": "identical", "none": "tier null", "ambiguous": "tier null (also when one cn\'s certificates disagree on kind)" }, "ca-security": { "field": "ca.security", "by": "ingest", "impl": "exact set", "from": "ca-security.json keys", "to": "ca-config", "keys": ["cn"], "compare": "identical (the collector writes the row\'s name)", "none": "ingest error: an entry naming no CA, or a CA without an entry", "ambiguous": "ingest error: two CA rows whose names fold together" }, "publisher-ca": { "field": "ca.enrollment_service", "by": "ingest", "impl": "exact set", "from": "enrollment-services.json keys", "to": "ca-config", "keys": ["cn"], "compare": "identical (the collector writes the row\'s name)", "none": "ingest error: a publisher without a CA row, or the reverse", "ambiguous": "ingest error: two CA rows whose names fold together" }, "oid-link": { "field": "oid.group_link", "by": "detection (ESC13)", "impl": "resolve_join", "from": "templates.issuance_policy_oids", "to": "oid-objects", "keys": ["oid"], "compare": "identical", "none": "no link: decided only when oid-objects is complete", "ambiguous": "ESC13 undecided (duplicate OIDs also mark oid-objects incomplete)" }, "local-ca": { "field": "ca.edit_flags", "by": "collector", "impl": "-ceq", "from": "enrollment-services.cn", "to": "certutil CA\\\\CommonName", "keys": ["cn"], "compare": "identical (-ceq)", "none": "a remote CA: every registry field null (also for a CA whose AD name is sanitized)", "ambiguous": "ingest error: the local CA\'s standalone row and the enrollment service fold together" }, "ca-host": { "field": "pki.ca_host_sid", "by": "collector", "impl": "-ceq", "from": "enrollment-services dnshostname (the pki-acls row of the enrollment service)", "to": "computer objects in the domain NC", "keys": ["dnshostname"], "compare": "identical (-ceq) on the returned dNSHostName (the LDAP filter only narrows the search)", "none": "ca_host_sid null (not obtained), e.g. the CA host is in another domain; its computer object is not read and pki-acls is incomplete", "ambiguous": "ca_host_sid null (not obtained): two computer objects answer, or only one that differs in case; no computer object is read and pki-acls is incomplete" }, "app-site": { "field": "endpoint.transports", "by": "collector", "impl": "parent object", "from": "IIS application", "to": "its IIS site", "keys": ["(parent object)"], "compare": "enumerated under the site", "none": "transports null when the site\'s bindings read nothing", "ambiguous": "impossible: each application is enumerated under one site" } } \'@',
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
        "_tryRead { Get-WebConfigurationProperty -PSPath $ps -Filter $filter -Name $name -ErrorAction Stop }",
        ("function _iisRead",),
    ),
    (
        "Get-WebConfigurationProperty -PSPath $ps -Filter $filter -Name $name -ErrorAction Stop",
        ("function _iisRead", "scriptblock of _tryRead"),
    ),
    (
        "_tryRead { Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Location $loc -Filter $filter -Name $name -ErrorAction Stop }",
        ("function _iisRead",),
    ),
    (
        "Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Location $loc -Filter $filter -Name $name -ErrorAction Stop",
        ("function _iisRead", "scriptblock of _tryRead"),
    ),
    ("_iisScalar $app", ("function _iisRead",)),
    ("_iisScalar $apphost", ("function _iisRead",)),
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
        ("function _caHost", "guard if (@($dnsValues).Count -ne 1) -> return"),
    ),
    ("_rootDse", ("function _caHost", "guard if (@($dnsValues).Count -ne 1) -> return")),
    ("_ldapEscape $dns", ("function _caHost", "guard if (@($dnsValues).Count -ne 1) -> return")),
    (
        "_entryProps $e",
        (
            "function _caHost",
            "guard if (@($dnsValues).Count -ne 1) -> return",
            "guard if (-not $r.complete -or @($r.entries).Count -ne 1) -> return",
            "foreach ($e in $r.entries)",
        ),
    ),
    (
        "_v $hp 'dnshostname'",
        (
            "function _caHost",
            "guard if (@($dnsValues).Count -ne 1) -> return",
            "guard if (-not $r.complete -or @($r.entries).Count -ne 1) -> return",
            "foreach ($e in $r.entries)",
            "if-condition after []",
        ),
    ),
    (
        "_v $hp 'dnshostname'",
        (
            "function _caHost",
            "guard if (@($dnsValues).Count -ne 1) -> return",
            "guard if (-not $r.complete -or @($r.entries).Count -ne 1) -> return",
            "foreach ($e in $r.entries)",
            "if-condition after []",
        ),
    ),
    (
        "_sidString @(_v $hits[0] 'objectsid')",
        (
            "function _caHost",
            "guard if (@($dnsValues).Count -ne 1) -> return",
            "guard if (-not $r.complete -or @($r.entries).Count -ne 1) -> return",
            "guard if ($hits.Count -ne 1) -> return",
        ),
    ),
    (
        "_v $hits[0] 'objectsid'",
        (
            "function _caHost",
            "guard if (@($dnsValues).Count -ne 1) -> return",
            "guard if (-not $r.complete -or @($r.entries).Count -ne 1) -> return",
            "guard if ($hits.Count -ne 1) -> return",
        ),
    ),
    (
        "_v $hits[0] 'distinguishedname'",
        (
            "function _caHost",
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
        "_caHost @(_v $p 'dnshostname')",
        ("function _childAcls", "foreach ($e in $r.entries)", "try", "if ($CaHost) after []"),
    ),
    (
        "_v $p 'dnshostname'",
        ("function _childAcls", "foreach ($e in $r.entries)", "try", "if ($CaHost) after []"),
    ),
    (
        "_v $p 'distinguishedname'",
        (
            "function _childAcls",
            "foreach ($e in $r.entries)",
            "try",
            "if ($CaHost) after []",
            "else of [($null -ne $caHostObject)]",
        ),
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
        "_search \"CN=Certificate Templates,$pksDn\" '(objectClass=pKICertificateTemplate)' @( 'cn', 'displayname', 'objectguid', 'mspki-certificate-name-flag', 'mspki-enrollment-flag', 'pkiextendedkeyusage', 'mspki-certificate-policy', 'pkicsp', 'mspki-template-schema-version', 'mspki-cert-template-oid', 'mspki-minimal-key-size', 'mspki-ra-signature', 'ntsecuritydescriptor') -Sd",
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
        "_v $p 'mspki-ra-signature'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "foreach ($e in $ts.entries)",
            "try",
            "if ($check.soft -notcontains 'mspki-ra-signature') after []",
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
        "_objAcl $computerDn 'ca_computer'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "foreach ($computerDn in $caComputerDns)",
        ),
    ),
    (
        "_markSearch 'pki-acls' $pkiSearch (6 + $caObjects.returned + $esObjects.returned + $caComputerDns.Count) $pkiAcls.Count (@($caObjects.failures) + @($esObjects.failures) + $caComputerFailures)",
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
        "_iisRead $ps $loc $auth 'enabled'",
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
        "_iisRead $ps $loc $auth 'extendedProtection.tokenChecking'",
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
        "_iisRead $ps $loc 'system.webServer/security/access' 'sslFlags'",
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
        "_bothScopes (_iisBool $wa.app) (_iisBool $wa.apphost)",
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
        "_iisBool $wa.app",
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
        "_iisBool $wa.apphost",
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
        "_bothScopes (_epaToken $tc.app) (_epaToken $tc.apphost)",
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
        "_epaToken $tc.app",
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
        "_epaToken $tc.apphost",
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
        "_bothScopes (_sslRequiredFrom $ssl.app) (_sslRequiredFrom $ssl.apphost)",
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
        "_sslRequiredFrom $ssl.app",
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
        "_sslRequiredFrom $ssl.apphost",
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
_IIS_APPHOST_READ = (
    "Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Location $loc "
    "-Filter $filter -Name $name -ErrorAction Stop"
)
_R3_PROBES: list[tuple[str, tuple[Edit, ...], str]] = [
    # Collector 0.12.0: the applicationHost.config location read admits only the
    # literal local config path. A variable -PSPath (which could name any config
    # file) or another literal path is refused by its exact vector.
    (
        "iis_location_read_variable_pspath",
        (
            (
                _IIS_APPHOST_READ,
                "Get-WebConfigurationProperty -PSPath $ps -Location $loc "
                "-Filter $filter -Name $name -ErrorAction Stop",
            ),
        ),
        "[command]",
    ),
    (
        "iis_location_read_other_config_path",
        (
            (
                _IIS_APPHOST_READ,
                "Get-WebConfigurationProperty -PSPath 'probe-host/WEBROOT/APPHOST' -Location $loc "
                "-Filter $filter -Name $name -ErrorAction Stop",
            ),
        ),
        "[command]",
    ),
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
