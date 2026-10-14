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
# never a variable, so the read cannot be pointed at another file or machine).
# (Review round 1: the providers collection is read through the same two
# vectors, so its own third vector was removed.)
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
    "_iisInteger",
    "_epaToken",
    "_sslRequiredFrom",
    "_iisBool",
    "_iisRead",
    "_iisWhy",
    "_iisProviders",
    "_sameNames",
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
    "0.1.40": "83a31ca0ba5f11e90d54deb8e30906e952fdd76e3fccbce2f2c9119658a267cd",  # FunctionDefinitionAst
    "0.1.40.1.0.0": "aa9819395495d0d4918e433708bcba4b9125d9e225d66d1220dad4f4e64a224a",  # IfStatementAst
    "0.1.40.1.0.0.1.0": "3c45b8443a148973ff1ccef62783e4f5d9402a6e9beaedd2a0cfddc9fdc98350",  # ReturnStatementAst
    "0.1.40.1.0.1": "8a690db67490bd9c5d2790504370c5eb8cf5efbd7d0372669ba86ae0c65a8a02",  # AssignmentStatementAst
    "0.1.40.1.0.1.1.0.0.0": "acb3f86f855dfec187927969fc5b31ba3a85246f6b289714bdcab4f97d8192ed",  # PipelineAst
    "0.1.40.1.0.2": "05bea5e9075e985cee381a5ad7cb6e315dd5c5cd475381c34b9f731db57720a8",  # IfStatementAst
    "0.1.40.1.0.2.1.0": "b28a609463117a1bc2ea2b4cc43f2e8ad3d3cadd976629838edb28d5fe65f484",  # ReturnStatementAst
    "0.1.40.1.0.3": "193703f4aa9885e38e56612a58352b9ba525f32e751b5ac23bdeda2cf6b27207",  # AssignmentStatementAst
    "0.1.40.1.0.4": "a73785c28f5e97e8bea5171728696e885dbcb8087ff80652ba9093891caa6d6e",  # IfStatementAst
    "0.1.40.1.0.4.1.0": "b99fa15774f2572d7af740de955a74d43ee4d9cf3ce537ee6ba8b8211cc4ee63",  # ReturnStatementAst
    "0.1.40.1.0.5": "2675bea2f709d71d480b0a870db87f1f2f011db3e2363ddfa16801ffbbebdd7d",  # AssignmentStatementAst
    "0.1.40.1.0.6": "ab99ec7be0b56954aedde25558d5074ea1b1c256e4a7ee5479a369a9a269c3b2",  # IfStatementAst
    "0.1.40.1.0.6.1.0": "ff1b4d866e83c0c147d028f94e6f8e6e5f603a14255f61203cd56f0acf36df62",  # ReturnStatementAst
    "0.1.40.1.0.7": "98c8131789610768bf56881678ddb8e333a83371d2db8d357ce4df7cca5e5757",  # IfStatementAst
    "0.1.40.1.0.7.1.0": "e0c0a857c1a9d478ad17df0a8c92cc60a4082eddef47edbc3c908337c76d9006",  # AssignmentStatementAst
    "0.1.40.1.0.7.1.1": "9569097f138ad93a89fb27930902e88bf9d830c2ce60b7509808dc84a49c10ec",  # IfStatementAst
    "0.1.40.1.0.7.1.1.1.0": "e03e3ef65fb04d1616a24299f14f1b3dd3a965c566bb569170ed96b7aa0f1f1d",  # ReturnStatementAst
    "0.1.40.1.0.7.1.2": "2cbc5e9c8cb4ba7141ca73107d5bf55db50dfe59bfc21c0957a8a7c46f708591",  # AssignmentStatementAst
    "0.1.40.1.0.7.1.3": "598168b623337e6e8329cf7c8eff61533c1923eb93bdb1122a9f5a64d127ba75",  # IfStatementAst
    "0.1.40.1.0.7.1.3.1.0": "53fec1029b7003caf49c99f016d09f920babc665716d72a9f6ace9ef48fb5c23",  # ReturnStatementAst
    "0.1.40.1.0.8": "8f1672fe683c03d66fafec81d03b9277d8a16fe29a61f770faafdb6d171566de",  # ReturnStatementAst
    "0.1.41": "35c4c20b411db5311034313e63a31d380ebed0e8f4d93f28f3c6947bbc8dfc9d",  # FunctionDefinitionAst
    "0.1.41.1.0.0": "5070b772fab59a976c3d388259bd4037a0ebe902498d5cd9ed155ee7309505d8",  # IfStatementAst
    "0.1.41.1.0.0.1.0": "7886ac03a9adaea5cbf6a4ff2acb3e5796bf189790827f38f2c4c35dc126f60d",  # ReturnStatementAst
    "0.1.41.1.0.1": "8aa88a8cfce47c316a646064010f508d2520db7bef1271cfcbe8df5098666d22",  # AssignmentStatementAst
    "0.1.41.1.0.2": "a585761b11e83823822a8757c132f258151ad86e9f8fef99d7ce0796cfbc4c85",  # IfStatementAst
    "0.1.41.1.0.2.1.0": "d31d27af4e904d12fda643a6846a0ee8c1266416d1a2890410a49a9afb49c25e",  # ReturnStatementAst
    "0.1.41.1.0.3": "a8a78a5111a142bd246b15257e0b3f2e6c948b0c6804f770168fe02b6a9030db",  # ReturnStatementAst
    "0.1.42": "0ec5f9a6ad630a344a32917c7f1db26970de7d9d6f27d85e76ac1ea5d154caaa",  # FunctionDefinitionAst
    "0.1.42.1.0.0": "82b1af579ebe642225c7e9aa3b69bb44f96ef56eb23ca4648601aff1346fe172",  # IfStatementAst
    "0.1.42.1.0.0.1.0": "9e5b32ba4a573b72ccbd94a3794c3de2c1fd24d686b3982035f0d9a62119965a",  # ReturnStatementAst
    "0.1.42.1.0.1": "8cbc4d8b097505ccc099e61482e1c022d77504eed4be77bc2525f0e43d840569",  # SwitchStatementAst
    "0.1.42.1.0.1.2.0": "1497592535799fc1ecb6df82ffbfc005934806c25674ca082b1f725240113940",  # ReturnStatementAst
    "0.1.42.1.0.1.4.0": "f0de483962f71f0a6c08f00528c817daa8c8413c6f79ca85bfecb4d9c526dfc4",  # ReturnStatementAst
    "0.1.42.1.0.1.6.0": "f86879989e2adc46b673d3093a66a6d0504ad9abdc806e5dd5ddd0a4be967295",  # ReturnStatementAst
    "0.1.42.1.0.1.8.0": "8ac41fb0bc82df0d0cbfac3ca2de1da25605f0e69644c01c2edb96fa86c2a0a1",  # ReturnStatementAst
    "0.1.42.1.0.1.10.0": "766da0936ea4e30dc13b24ade006505b799ee81bb28deb46be1c134741453b79",  # ReturnStatementAst
    "0.1.42.1.0.1.12.0": "02e0ed0857b59db06dbb92962473a0958ad196905b223178a84cb2ef65df2bda",  # ReturnStatementAst
    "0.1.42.1.0.2": "9e7fd2d01d415a551223dd9cb21fcb191a1f6296a95620fffc0d69b7650308b1",  # ReturnStatementAst
    "0.1.43": "cbacc742e9b81c3f95ba65a8ca672087d2484246559714390f0ee5e57a6e8791",  # FunctionDefinitionAst
    "0.1.43.1.0.0": "62e3876bcd1751de5a2220a013c31c6b913f39ea4b17b4ff3391776ee865a7fc",  # IfStatementAst
    "0.1.43.1.0.0.1.0": "ee0a4e92d76ef951f14b29d0d57bb5b5b0cb73ea43c877d81ec5bb826954a5e2",  # ReturnStatementAst
    "0.1.43.1.0.1": "9596cabdc8b9e1cef3b0a1e5e53c3d71b1e258b3aa0abb1c5214dc9a154aed02",  # AssignmentStatementAst
    "0.1.43.1.0.2": "3342163f624a4de7a827bb73160277a8959e6ec245f674779ef0cb172299ffe1",  # IfStatementAst
    "0.1.43.1.0.2.1.0": "96467539cfbcd3cee67573897a31f2266710aa4fa9b830be68036db19662d6a6",  # IfStatementAst
    "0.1.43.1.0.2.1.0.1.0": "9d20d7d89d25e7ceb9cf1a50aca9e0dc2b3ca54cbd62be33d6d1d711c5b1eddf",  # ReturnStatementAst
    "0.1.43.1.0.2.1.1": "bf089bd119e2af5dd247cdc6db2d69810bc02aec0dbcbb769afcc9e1f5f8cd80",  # AssignmentStatementAst
    "0.1.43.1.0.2.1.2": "5dec12ac34d6e05c6189c3370b74797769f0782292f06610051d077524ce6561",  # AssignmentStatementAst
    "0.1.43.1.0.2.2.0": "e46aae31fd93d425dad87d5a0534b4d1b2f4d15f25effafe4f23a8327c35571a",  # AssignmentStatementAst
    "0.1.43.1.0.2.2.0.1.0.0.0": "7143135e293c4ca417a99e4e06b67430b2655c149a68b48ceb275e371ee71b5f",  # PipelineAst
    "0.1.43.1.0.2.2.1": "3ebecb49fe757d9434581db43733bbbef6b29eb3ae995fcba92b20d11a289163",  # ForEachStatementAst
    "0.1.43.1.0.2.2.1.2.0": "2a642df6765137e66de643cc4a477ff759808367d8df1149da9f4f366678e171",  # IfStatementAst
    "0.1.43.1.0.2.2.1.2.0.0.0.0.0.0.0": "6a0eebaeb0247005178c0754fdddb16843f09e693fadb812baf13bc816740265",  # PipelineAst
    "0.1.43.1.0.2.2.1.2.0.1.0": "d33074aab00470550e3dcde2484b62288224544782a66fc316a4c17e56591de6",  # ReturnStatementAst
    "0.1.43.1.0.2.2.2": "21cc9e78974066ac5f4771aefe6a3c76d90dc4d89990c6f5179797be311ef22e",  # IfStatementAst
    "0.1.43.1.0.2.2.2.1.0": "18de7c002c9aa844a79edcacb7ba995be27d3d4601321abbf9afc265fa055490",  # ReturnStatementAst
    "0.1.43.1.0.2.2.3": "05ac6936872fd5d72fa54df8582d7bfe1d18ac72254d661faac88385a1a2b5c6",  # AssignmentStatementAst
    "0.1.43.1.0.2.2.4": "cbbe0a2ea061db1c629a3ad1d491d841b843f146b51086c1751aaf0194b4206b",  # AssignmentStatementAst
    "0.1.43.1.0.3": "8f9043f00a90775a301e9e87c0b99ca294e61b29f03ff23607f991f95933e930",  # IfStatementAst
    "0.1.43.1.0.3.1.0": "51a1905d01e00cfee9a3ebd48328e8a543b38965f8f91d8d33a92bce13a1d559",  # ReturnStatementAst
    "0.1.43.1.0.4": "076df1ef2072c7d8c218b7772290a954d0dd3bba2b109d2b2308e85b6a38a012",  # ReturnStatementAst
    "0.1.44": "566bc30c5a636cda203691ac312c57eae005be426a62f76aa2324d4798f34f18",  # FunctionDefinitionAst
    "0.1.44.1.0.0": "a546f56640e0bebf2ea5e4a47c2c58bf444542d0e8fc2edfc8a00a09bbbe5ebc",  # IfStatementAst
    "0.1.44.1.0.0.1.0": "ff8b82beb3bca1c5105c838e474c56c5966fe7c7ae1cb8bdb7419e38ae9ac12d",  # ReturnStatementAst
    "0.1.44.1.0.1": "932f16ef7f29e9d0a7c6a65bb498fb3b130cba1b466334a51b1794a5a020ef50",  # IfStatementAst
    "0.1.44.1.0.1.1.0": "a01586f84113eeb98db2fcb7db43fbecaead9656d660ba44781fa50eb53269a3",  # SwitchStatementAst
    "0.1.44.1.0.1.1.0.2.0": "2e081ccce70f1f71b196b590c31ac2eb6fe7859e0b1ad34f554b9171b51468d2",  # ReturnStatementAst
    "0.1.44.1.0.1.1.0.4.0": "d0d9077335acc762e22955d89061988cee97f25b56ebb3d8a0167ba9fb14acc5",  # ReturnStatementAst
    "0.1.44.1.0.2": "26be26e43452c95c6353c6265e7296221f0e5d883bb953048dc61840d69728fd",  # ReturnStatementAst
    "0.1.45": "9a086676cad1f54441380027d1ea4653f15907aff81ec53998263cbf656e4801",  # FunctionDefinitionAst
    "0.1.45.4.0.0": "993965061aded9459347a21a2a5c8a3cefa0dc4409ce8794f41cec8d9139a253",  # AssignmentStatementAst
    "0.1.45.4.0.0.1.0.1.0.0.0": "46b5cfdc2e8e7469f4528be78d16974e0c4f8226ff39f510bf8198cb9df444b9",  # PipelineAst
    "0.1.45.4.0.1": "f05f6d7a524b8f5e57b19754e85ba419a1d5faa33b245cf3e5c032e70358a5e1",  # AssignmentStatementAst
    "0.1.45.4.0.1.1.0.1.0.0.0": "7401493c5667093f0ab23e2dfa4cb8c4c35dc9485b6d37bd1f141afb8a180522",  # PipelineAst
    "0.1.45.4.0.2": "05d47cc93e624c0f1ccb4ede6d8b8a718c0cec4ef5f17f17e6f6e4be380d2f2c",  # PipelineAst
    "0.1.46": "ad16ebd4099fcd76b02c3c78627cf8dc419b797245c6ff8f480cab5474766cc2",  # FunctionDefinitionAst
    "0.1.46.4.0.0": "5eba574774cbca2bf013cc8135b086202f393088df6037ff4fdeeb6fff31084a",  # AssignmentStatementAst
    "0.1.46.4.0.1": "37864be28fbd139f98c2eb42be588b5ce2dd8b9ae7bd65e2a67e3d288b9ff7be",  # ForEachStatementAst
    "0.1.46.4.0.1.1.0.0.0.0": "e2df4420f52030015d719e1c0c21e3db9aaea2c2040ae89c9ad6c3fa713b0752",  # PipelineAst
    "0.1.46.4.0.1.1.0.0.0.0.0.0.0.0.0": "5e65c8b2751db476c05a1ed23919b1a7de33bf46ddab0213f810a4d223a20b2a",  # PipelineAst
    "0.1.46.4.0.1.1.0.0.0.0.0.0.1.0.0": "95b1376764ae3a09cae703520ebf6be5766e9a31d9ed09bd4bdd48db14d5d22b",  # PipelineAst
    "0.1.46.4.0.1.2.0": "544977ddb43f34c8488e585dcb664ce7324be16a18c3795ff074954cd559d8fd",  # IfStatementAst
    "0.1.46.4.0.1.2.0.1.0": "075eb3133f3500e61e48c7f06678487b6f9752e1152265df2f9153430fc738f2",  # AssignmentStatementAst
    "0.1.46.4.0.1.2.0.1.0.1.0.0.0.0": "f71e66b591014bacb39140d2265a3b8359158f3545fe7dd4e53eb82644aad24c",  # PipelineAst
    "0.1.46.4.0.1.2.0.3.0": "0a0b925ada437a97f9bdcb522859b55fc84b96dcb4eef784e485ebaa6634422e",  # AssignmentStatementAst
    "0.1.46.4.0.1.2.0.3.0.1.0.0.0.0": "15862fde9c475bcd05164f9faa0d6f3a100c4dc74ae930db9493a2bdb448bdec",  # PipelineAst
    "0.1.46.4.0.1.2.0.5.0": "d7aa920918a978f695e8cc4edcc1ad090f4c66e2217f10ed90efcc3bee664bd6",  # AssignmentStatementAst
    "0.1.46.4.0.1.2.0.5.0.1.0.0.0.0": "41ef2c8817f44f16b8af02c75dfafba84c3a2cc3fbf2ade14d1bbdc1e67df167",  # PipelineAst
    "0.1.46.4.0.1.2.0.5.0.1.0.1.0.0": "13256615b2fe41a15eed875601c802a4e0148bf58a1501e2727369315f2e5050",  # PipelineAst
    "0.1.46.4.0.2": "77e3e0f25024dce18e9a42166a99558374ca4359ab2dbfc6354d10a1878ec21f",  # IfStatementAst
    "0.1.46.4.0.2.1.0": "b5c23c7b3d53747d52c14b0a930e824f1572669788e5caa74da42a326586b302",  # AssignmentStatementAst
    "0.1.46.4.0.2.1.0.1.0.0.0.0": "ab803bf7b2d96db68838871f205738707aca6195a5025f7ca834c3b84cefe65e",  # PipelineAst
    "0.1.46.4.0.2.1.0.1.0.1.0.0": "3db3e7bde127a60d5f4f78b867eb1998ecf5981f55da9e8a92b47567ced9397c",  # PipelineAst
    "0.1.46.4.0.3": "daa26e8cfa8c0a77e96d5848040aea40fa4215aca8dc18a62575e61e98c2b959",  # PipelineAst
    "0.1.47": "d6fe05101435cdc1dfba9a312364ec0a246708bf68467fe4f3bf494d7d3f3d96",  # FunctionDefinitionAst
    "0.1.47.1.0.0": "de04fafc26c93775202e0493b26b3adef39c352e2c1c054422eb045bba3a3c03",  # IfStatementAst
    "0.1.47.1.0.0.1.0": "d767e546f8edcaf67e5b1c68fde999b740347487790eaea89ccc2cedfcf676f4",  # ReturnStatementAst
    "0.1.47.1.0.1": "a713412d73c30d1ad1b9c4311f0980243bd64ae1a7e4d4912159e0e5bc3f70ed",  # AssignmentStatementAst
    "0.1.47.1.0.2": "c07ee16faa053355052299513a6e395850e954bb06738d1202859af9069128a9",  # ForEachStatementAst
    "0.1.47.1.0.2.1.0.0.0.0": "a0a073b8cbd8e075a3217b169ba4161bf005038081c180cd95002ee5f212e996",  # PipelineAst
    "0.1.47.1.0.2.2.0": "e8587a37762a9bf43a65039f3142f2263e210a371345a6b6869196aef3a9bdfa",  # IfStatementAst
    "0.1.47.1.0.2.2.0.1.0": "040b9d02095a41c956ff55c19d1aaa3af0de5934fa46eb8420bef0881e3508f9",  # AssignmentStatementAst
    "0.1.47.1.0.3": "b88e37351dd08ce85adc840550584d9fab3fe32079d0572f257e015b0a8ced78",  # ReturnStatementAst
    "0.1.48": "1504b61bf404e37d86c782e097fdaff1a5ae5810657a70181a32f40a12a36e53",  # FunctionDefinitionAst
    "0.1.48.2.0.0": "c06d912bfa67918eb22b25320cebea87f72934860a04305eef86c95c174ea185",  # IfStatementAst
    "0.1.48.2.0.0.0.0.0.0.0.0.0": "88ecc1da155f43ea31f4a4e2c1d1c0f8c8a7fac3d70edf186aa106d08038684c",  # PipelineAst
    "0.1.48.2.0.0.0.0.0.1.0.0.0": "91195b434236ce6be5a1753924789ae453735a3d6a228a838f52cd0b6c0391bf",  # PipelineAst
    "0.1.48.2.0.0.1.0": "04f9301c56eae161928ed3f387d389dc046b150d056e833bdf448465bfbfe3b0",  # ReturnStatementAst
    "0.1.48.2.0.1": "718f5f1cf7d1897ab968eccb7bec47ff77bf57957eb3a6e1b452e845a22c0cc6",  # ForEachStatementAst
    "0.1.48.2.0.1.1.0.0.0.0.0": "fc0142d5ac779c6c6e71ed985f526a74d676132536e14e5c803deb3ec8bbb41f",  # PipelineAst
    "0.1.48.2.0.1.1.0.0.1.0.0": "b56874c3a6cb14a4645b7ec2ba3fb547f19800bad100ae377ff53e3de9fecd8e",  # PipelineAst
    "0.1.48.2.0.1.2.0": "729544df6df9575f12460a4017b1ca443928af53de8a880914772a4a7f48fe50",  # IfStatementAst
    "0.1.48.2.0.1.2.0.0.0.0.0.0.0.0": "2fb8ecd1b09dc0fa4748c95092192280639ea8544651cac3b0315d616e73baf2",  # PipelineAst
    "0.1.48.2.0.1.2.0.0.0.0.0.0.0.0.0.0.0.0": "97e5880b2f3e2639a10cebc8cce24d52ebcfb38b0e50183a52259a48ba390be1",  # PipelineAst
    "0.1.48.2.0.1.2.0.0.0.0.0.0.0.0.1.1.0.0.0": "9f5f515bc85acf6b0aa489c2bb775b9fc3db0c0bf4aa21eddedc1531b566bb12",  # PipelineAst
    "0.1.48.2.0.1.2.0.0.0.0.1.0.0.0": "e52d4d4f4601f5e83e7b323c371ddd2d817d39ae47615c652e00a42dcb2e2967",  # PipelineAst
    "0.1.48.2.0.1.2.0.0.0.0.1.0.0.0.0.0.0.0": "0dc4132c76d810acc1353dc0ba50ce446240379d68f06ea21a712f1116507f25",  # PipelineAst
    "0.1.48.2.0.1.2.0.0.0.0.1.0.0.0.1.1.0.0.0": "8e2580fd92d3031186ab76162734cb2a48845a92f0a30dc3bcdd30769ae16c1a",  # PipelineAst
    "0.1.48.2.0.1.2.0.1.0": "904533ff45c3abdc62bb18058fc787ff43b4ecaa44b0aa64acad9f9338a4b2f0",  # ReturnStatementAst
    "0.1.48.2.0.2": "b123432ab754cc8b7112448e5334049e5105de0427d3174d7a71f7e6cf6b899a",  # ReturnStatementAst
    "0.1.49": "ee0463bf979095e72f17a7782d06ce18171b06cff1c42546e5df71713d567919",  # FunctionDefinitionAst
    "0.1.49.2.0.0": "51e2b3f6e271f33bdc939082f7fb8223194ca2faaab9fd7d264f293dc762389b",  # IfStatementAst
    "0.1.49.2.0.0.1.0": "23feed69107466b2bec730462f454a095fd4457d6693e26626a53602e45962bb",  # ReturnStatementAst
    "0.1.49.2.0.1": "b73686fcb9d8da3eb06970a9b6235217d5e977c96e34edc8985e6f06961fc672",  # IfStatementAst
    "0.1.49.2.0.1.1.0": "eb3947a458956f583c7ca8a3b9beb96ffc60000fceb16c3aa61d764b32b29d40",  # ReturnStatementAst
    "0.1.49.2.0.2": "9625d9fecc5beb07226a1b335d18c3e8a9c3403b06849ac74daafcb1955b5d4e",  # ReturnStatementAst
    "0.1.50": "7ec2df73608c93936d3b779320db254a4feb3a3b4d466b55926252e74132cd2e",  # FunctionDefinitionAst
    "0.1.50.1.0.0": "c8192713aa954005f64493ca4633ee80c4dcbedd9a321cf4ae7a78657617f2bb",  # AssignmentStatementAst
    "0.1.50.1.0.1": "c9459953e6fb5ad07fa28cf4edf6b41c8c1878f2285cc71c76e91722875ae23f",  # IfStatementAst
    "0.1.50.1.0.1.1.0": "ddcbf747981ed1024176b454aa92d6c5241de1482540d1e66f4bda42a9f15eaa",  # ReturnStatementAst
    "0.1.50.1.0.2": "dfd6c2b8db37d5cc8a3dc773a13147435e7f8095e539a363ada9e592e1235392",  # IfStatementAst
    "0.1.50.1.0.2.1.0": "5155e7b823da12e1199c7b534edddadf13f6871e7d92d0fa92154d1aea839244",  # ReturnStatementAst
    "0.1.50.1.0.3": "62e95b3ea1c65bae61d30b8d21b560ce22635d8eda4a9fd6b568c5305057ee92",  # IfStatementAst
    "0.1.50.1.0.3.1.0": "7b80113023f319fe1139121e3225465c155a5ce82429b31bdca5a662cff34c22",  # ReturnStatementAst
    "0.1.50.1.0.4": "7964d3a07b3f7eb065d8eca6beabb5741c92f801b2fddc0f2e146fad7e773d57",  # ReturnStatementAst
    "0.1.51": "d2ad24cf51173b58ad3cae441e7654b84e91eb9175ee4e549aeddde950af4ce7",  # FunctionDefinitionAst
    "0.1.51.1.0.0": "c2be3406aa558c055cc14d978158f29ad9884e01a0de2c5a38b1e401cbfddf1a",  # IfStatementAst
    "0.1.51.1.0.0.1.0": "63acc8c34994926fe19897d825e23c28c829c63442be2f31056d2c5ae362bac0",  # ReturnStatementAst
    "0.1.51.1.0.1": "cc122250010297ebbc25b1c897506c528047275a9b6278dcc3bf3aa25848da39",  # SwitchStatementAst
    "0.1.51.1.0.1.2.0": "1922e2ec50b9ee27e4df1130a8ff48c1a064803329075b1dda2b5438d3cf0f25",  # PipelineAst
    "0.1.51.1.0.1.2.1": "b35bd31ec258b46d66548d6a51d71319dbdefeb4f7246531307c260682d86454",  # ReturnStatementAst
    "0.1.51.1.0.1.4.0": "8d48b161666c6a6d8528b843dcde70c86eea91827d29c05fb266f3f944698002",  # PipelineAst
    "0.1.51.1.0.1.4.1": "3d316aacd07fdf8aba703f906a275aa2ec64fbefeb53c05b9a7318e10af2626a",  # ReturnStatementAst
    "0.1.51.1.0.1.6.0": "0799dc6701c7a11ddefc95ae3661383e74d2312be78491067585462635c2add4",  # PipelineAst
    "0.1.51.1.0.1.6.1": "0aefa8c9252ab67db5642c6d3b62375b69f37787d72096b4440a1f3714a7c711",  # ReturnStatementAst
    "0.1.51.1.0.1.8.0": "cd6fd1ce22c71f2d780af4ce2455e8e59a90df63efe6a014cec2537ad5cbea79",  # PipelineAst
    "0.1.51.1.0.1.8.1": "b4f8744a09f4f5d4abf414d5836833f84148690c423eef7164377e00bd9addbd",  # ReturnStatementAst
    "0.1.51.1.0.1.9.0": "60c9e6f71af14850176cc52d71b0a6380b839c21c003a089d6e5f418f1eb79e2",  # PipelineAst
    "0.1.51.1.0.1.9.1": "d6cef3233aa58ba0e88688956f2cc99e7c9b7b2b875f6b5af3608b682dc2a675",  # ReturnStatementAst
    "0.1.52": "7788d21a0d7b2c4c43687a973cac4ec8c25ea4ff466054183d56406cc3ac8bbe",  # FunctionDefinitionAst
    "0.1.52.1.0.0": "a42447dcb67453463ed3de0aab4ac5ce61ad32a5f2e5761f48d1a639f0ffaf99",  # PipelineAst
    "0.1.53": "c0330c6439a3bfe86140a70d7c086c666a6b6fb8976563f9997b5fb446b94204",  # FunctionDefinitionAst
    "0.1.53.1.0.0": "57f9690323e8d18e4d3ad6849ee012f0be8d4bf8ffbe91259d10f1876cb06e4b",  # IfStatementAst
    "0.1.53.1.0.0.1.0": "7a551a63912ec6c8b0f1e847b12253e6ef08abbe74f7272fea3819a7a1ff4f11",  # ReturnStatementAst
    "0.1.53.1.0.1": "ed94a923ef0eee0505809b50519f33b6f35f26ec0dbdd8e890782989a51391ba",  # TryStatementAst
    "0.1.53.1.0.1.0.0": "a05439fc9e1cbc07bfa013d3c6969e5eb8617e2fe0cf97dbe6308cc73c886b2b",  # AssignmentStatementAst
    "0.1.53.1.0.1.0.1": "04093ac4e42f5f64edba27f1a201925a3c7fda2f33fba79cb07cb2eefdf9154d",  # IfStatementAst
    "0.1.53.1.0.1.0.1.1.0": "09faf05437b8941d75d910d711e60812d4714318df490650c48a4b169c5e01f3",  # ReturnStatementAst
    "0.1.53.1.0.1.0.2": "94c099bddca8e00290bb3323b748f05bd2f13e9e6d5f979c2ffebacaa4a22c08",  # ReturnStatementAst
    "0.1.53.1.0.1.1.0.0": "0072cda2a573b0d649c1092e01278805643de97e40dc4123390bac47d57bae2e",  # ReturnStatementAst
    "0.1.54": "c005d734add9e548d2691dcbe26bb56f13ddaa2c7ea3342782e5253473b017db",  # AssignmentStatementAst
    "0.1.55": "f8e0c44fa60281607d8caa91929bce7da9d87079e9ba910481589e1d6982a273",  # AssignmentStatementAst
    "0.1.56": "2a7d6cc9af9265657116ac4933ebd3d39e7c995a70df8ffc93b8399577cba7cf",  # AssignmentStatementAst
    "0.1.57": "337f25b5535e70cb3632b25b0af5f88dd1de556d626b68ccf934784abb4576ec",  # FunctionDefinitionAst
    "0.1.57.1.0.0": "d41cb409e2b32d75723a3f6eec163bc51eb0c13cdfcbee9bf61e6dbd37a706e7",  # AssignmentStatementAst
    "0.1.57.1.0.1": "f2878459a9679f09f9b44e215c9202f089df97c0282a9dbba4f12e0b83130830",  # IfStatementAst
    "0.1.57.1.0.1.1.0": "9a6babde93b3c51133c7e3f1f5efeb8c3efa33fda0bcabce32e172856eea1f47",  # ReturnStatementAst
    "0.1.57.1.0.2": "e38620b8a7ad8e8de5e4a904da2b6a392129f7e24ecc196b2827688b85eeff84",  # AssignmentStatementAst
    "0.1.57.1.0.3": "4061b90b83abfd383232e0a9d9dbd635459697dd422fef9852eee4fce3385beb",  # PipelineAst
    "0.1.57.1.0.4": "99ce1f41614576e4b0fa4094c85d49d4a1ab05310b72c92f5cd6945464de7734",  # ForEachStatementAst
    "0.1.57.1.0.4.2.0": "6250855df9f2b0b397adba34507f13033076089e56290de5205acf374a64dcb6",  # AssignmentStatementAst
    "0.1.57.1.0.4.2.1": "04aea364b8fbe8702d3cc2c5015e89391b68ba25f234202329705cbcedcf1472",  # AssignmentStatementAst
    "0.1.57.1.0.4.2.2": "cfd323f5c65cb88c8f77024f6ebb5b9b3d79a507a0520b14255b7bd26bd70f4a",  # TryStatementAst
    "0.1.57.1.0.4.2.2.0.0": "eb932ed13e9433768a90fe3c31d81ede80425989fd6db88459abc343e1bfbc6b",  # AssignmentStatementAst
    "0.1.57.1.0.4.2.3": "c7a84a85228911366f620fd5d47e81ef7bb44e913971ace1ed5aa4c509006b55",  # AssignmentStatementAst
    "0.1.57.1.0.4.2.4": "fa843f8024ebaecfadc764dfb0ce2bc82d25ae0a2ca4d1bca8bb8cbb8c689fa1",  # AssignmentStatementAst
    "0.1.57.1.0.4.2.5": "357c844b4629e59cf408f97016fd26f235fa91a60a48b65c7f72a6edf901db1b",  # ForEachStatementAst
    "0.1.57.1.0.4.2.5.2.0": "4dd5dce971e42ecf9f2703929906d7707e1112b57097e8ecc01a217873ed9871",  # IfStatementAst
    "0.1.57.1.0.4.2.5.2.0.1.0": "d538b33492aa642e10d085a92f0170ce353d21f54d69c9f1e824827c5b26b73d",  # IfStatementAst
    "0.1.57.1.0.4.2.5.2.0.1.0.1.0": "c923c12cf57b9f70b2ce02767aa5f46e71f5917cd977fdeadba964925c0163b4",  # AssignmentStatementAst
    "0.1.57.1.0.4.2.5.2.0.1.0.3.0": "aac2ca644c3053b9183d01fda2a54f985cbaf1532dcd8a600a9319774605bfbe",  # AssignmentStatementAst
    "0.1.57.1.0.4.2.5.2.0.1.0.5.0": "773143c3fb817ecb3944e655012896fa0e92c773ab8765e1b6b023e6f08242f6",  # AssignmentStatementAst
    "0.1.57.1.0.4.2.5.2.0.1.0.6.0": "46ed47bced8deab6000257654ee3a8d22c7e165782c1d74177ff2c300127a7c6",  # AssignmentStatementAst
    "0.1.57.1.0.4.2.5.2.0.3.0": "dc5f828ad230ff275bd4eba1106908877bf2d8f12352b79d16ed976f4259976c",  # IfStatementAst
    "0.1.57.1.0.4.2.5.2.0.3.0.1.0": "b624371021b4e55d1b914a8df1ab2d32e0a0b8ce8f6334d16f5f3e9b8b4900be",  # AssignmentStatementAst
    "0.1.57.1.0.4.2.5.2.0.3.0.2.0": "34a8c02500867133468de1bf000e2801b41b29b77e05195c8fbf5d587d59447d",  # AssignmentStatementAst
    "0.1.57.1.0.4.2.5.2.0.3.0.2.0.1.0.0.0.0": "6b8e7fa71fd78ea6617e2b5e5a21831c7d9454b93acae9afae152aa3cabd54ce",  # PipelineAst
    "0.1.57.1.0.4.2.5.2.0.4.0": "862f8de0c3e2da484c104eee968336388efb24f1597fa615c6d2f5915b66df61",  # AssignmentStatementAst
    "0.1.57.1.0.4.2.6": "22d11b97a164589fb631a3d23a33e2af47276ee4c244b10cb2238d74a270266e",  # AssignmentStatementAst
    "0.1.57.1.0.4.2.6.1.0.1.5.0.0.0.0.0.0.0": "3d9072775a76a6ddf2a46e6a8cc7cd777e1bb937686985ff98773116291d4511",  # PipelineAst
    "0.1.57.1.0.5": "89c029441e939fcc4bfc07eba3baddb9eb18d3adb13fe95f010a33cfb029fc4d",  # PipelineAst
    "0.1.58": "b42661d46e561e0ecdcf69a9807b70f595e834a36772f5a9c7420becca43eb75",  # FunctionDefinitionAst
    "0.1.58.1.0.0": "89ed79d22acd07e38e3fb593ee71323dc2e664417249b157121aa4adbb670b1b",  # IfStatementAst
    "0.1.58.1.0.0.1.0": "1007191a8bfa930f8ca47af2431627bd2c84fd9daf233cbc7b1d78ba3c7870f3",  # ReturnStatementAst
    "0.1.58.1.0.1": "b981326796ca6c4017a128fb78aa18ebecea4d079431863dbb676429e81ba4ad",  # AssignmentStatementAst
    "0.1.58.1.0.2": "be96cbc0c1ffb996cf05420c1dadb511418dc6b2c4d1b0427fc271fab1e3d3a8",  # TryStatementAst
    "0.1.58.1.0.2.0.0": "9ba9c9762d9b43ff4e754537ec2b0458f97345ecddab5298ff61f445b79fe8b4",  # AssignmentStatementAst
    "0.1.58.1.0.2.1.0.0": "8bb2c0beb718c44ceb69152879bc933db3c759cfd2efd565501582302dc31e2d",  # AssignmentStatementAst
    "0.1.58.1.0.3": "9f4a2547f1a9cca916e6371add35c46f9f87bdaa36b8280137e3d3c0e6e9c4df",  # AssignmentStatementAst
    "0.1.58.1.0.4": "8213cbf96bfe24e8f8f71b404bea01fd4c0e0f0c2c9249ff5e840c02fb0c6516",  # IfStatementAst
    "0.1.58.1.0.4.1.0": "73b83d4e488f796c9471c7aff0763b0548a4023fd492429d24b3326a43592746",  # AssignmentStatementAst
    "0.1.58.1.0.5": "426647e1dbe1f7966a1f26fc69ebfdfd529934cfdd368a143531307b19281f0c",  # PipelineAst
    "0.1.59": "db8e263d60f63bb36c8ecbc14c5fb75763cb2b15a1fccda7d3830a55c4dc0363",  # FunctionDefinitionAst
    "0.1.59.4.0.0": "7c14b9cfb6abccc6a4f5d6f7b22b6c4accadd58fc9aaa6a9184f13c270dd3cb4",  # AssignmentStatementAst
    "0.1.59.4.0.0.1.0.1.0.0.0.0.0.0": "cd3d4c8a4983320f9efd444ad950a8a30d2ef0511065b5d073bff5188007f9cc",  # PipelineAst
    "0.1.59.4.0.1": "ddf928e0bab64f35eb1d8cf9c4a9a9c77445591bcd8b843a673ece5b70a355d0",  # PipelineAst
    "0.1.59.4.0.1.0.0.1.1.0.0.1.0.0.0": "3978fd56b38db1e4ae832d98549671239b8850b2122b4bc3ebbf2e0fa0711c31",  # PipelineAst
    "0.1.59.4.0.1.0.0.1.7.0.0.0.0.1.0.0": "76db7403914beaa60d7a8d349f79d10d2f54b4d9479bfa4741570abdf489d601",  # PipelineAst
    "0.1.60": "6e950a18f4a884b552683aea488ff79e88c660176e2557de3cab339f961514cc",  # FunctionDefinitionAst
    "0.1.60.1.0.0": "1b9e16eb40d72611fccbfea366385384544f6ac5e2b298c1f570772c9eecfec3",  # IfStatementAst
    "0.1.60.1.0.0.0.0.0.0.0.0.0": "07f4d6f3deb599bcedd6cbbabd93635b14492b108c848d846229a4a27b6a573a",  # PipelineAst
    "0.1.60.1.0.0.1.0": "8ff702bd842c233c3da24d5702552bd37a2f76f198b9d6791476f13267e95fdd",  # ReturnStatementAst
    "0.1.60.1.0.1": "32c28ac393cbe9598dc51b33d6782f48438f0380514f84c59536e3e83dd27efe",  # AssignmentStatementAst
    "0.1.60.1.0.1.1.0.1.0.0.0": "df2acce52f011ba5cc06ac6b7d09119c7ae19b61049669e3f8ae2c43cdf5c203",  # PipelineAst
    "0.1.60.1.0.2": "c423acfee5e6b41e9f4c993c3c32a4a0f89740146d3780d52950f5292f45fa59",  # AssignmentStatementAst
    "0.1.60.1.0.2.1.0.2.0.0.0": "94bba33daa97a870c4cd79a843a314b34f5795860d47e00efeb7b1c59fb28b0d",  # PipelineAst
    "0.1.60.1.0.2.1.0.3.0.0": "a55428176b177bff26c9178e03f7918aaa56a9bd35b8237f2b774d6063203d1b",  # PipelineAst
    "0.1.60.1.0.3": "4065508540fc75d07df529619abfa8f68f550e1d6b478633302b2905da4b56cf",  # IfStatementAst
    "0.1.60.1.0.3.0.0.0.1.0.0.0.0": "1167df9046fd557da18e9d5c993ce60255cc5794e7e8b40ad9a93256c195b84c",  # PipelineAst
    "0.1.60.1.0.3.1.0": "3975ec9b28c7a9b3305e0b483c2c1de100dd4fb7712af958965e064af9121356",  # ReturnStatementAst
    "0.1.60.1.0.4": "4f5cf38d7ec589fcfeedac363bf2524c8b6550148eb3753cc8c28923012c35cc",  # AssignmentStatementAst
    "0.1.60.1.0.5": "9586ca666e79ceb2f107330dd021d9e91217881ced1e07f56d9fa4660214aaa4",  # ForEachStatementAst
    "0.1.60.1.0.5.2.0": "9a7ec551d4b3f31f9420782908504a53a5ff06bbe999f8da379a8a0968d4a292",  # AssignmentStatementAst
    "0.1.60.1.0.5.2.1": "ecb7a1c7299ce6a46cb283b44a077017fe754a524d239ce869349e1fb9134b02",  # IfStatementAst
    "0.1.60.1.0.5.2.1.0.0.0.0.0.0.0.0": "0ce25493037842e84a974a062dc8d87460797daefb75dd2b8ef3502dc5675aa2",  # PipelineAst
    "0.1.60.1.0.5.2.1.0.0.0.1.0.1.0.0.0": "1766421600108f8309bdbe81f90dfd458d57039b1eac7b72781dfe14c78a19e4",  # PipelineAst
    "0.1.60.1.0.5.2.1.1.0": "ec15915e9f2e26bdaa20fa070051a61f8cc2230c352e378f71b6e4ef452a7692",  # AssignmentStatementAst
    "0.1.60.1.0.6": "e9dacfd2dcbf26dd434ead20a2ba3e5cc23908b6e9012eb3d816301db63ffb51",  # IfStatementAst
    "0.1.60.1.0.6.1.0": "3ffe69255f5de480b4b85d23463fd41c5581b04530b8a84d77cc3096e8ae8bfe",  # ReturnStatementAst
    "0.1.60.1.0.7": "1b0a42ba3cd1dcf6c95872abbadcdc51d0b6a50b269dacdf8eeea0540875cffa",  # PipelineAst
    "0.1.60.1.0.7.0.0.1.0.0.0.0.1.0.0": "6f503ad2fb0f2cc9acd0cedee1ab18614b78b0921527d4e2a6d6654edfe8d904",  # PipelineAst
    "0.1.60.1.0.7.0.0.3.0.0.1.0.0.0": "c703cf6c72c8ca8a438a3f88cf12ba802fca3abb04051ff39b890f6e9168b42b",  # PipelineAst
    "0.1.61": "a9b578a4b997d9878e169bfb909a2331884e3d1e8cde758fe950dc7a9e4db2cc",  # FunctionDefinitionAst
    "0.1.61.2.0.0": "bc3322fead919c112bab28016b6e200e0ab85339d7ca7406b2549e775cae2d93",  # AssignmentStatementAst
    "0.1.61.2.0.0.1.0.3.0.0": "ed1ec88df5e8669cb3fbe1945f60ce3eeaa9ef63663f8ac2cd9374b0f01f5841",  # PipelineAst
    "0.1.61.2.0.1": "2d8bcec095881d1a90678ac7197d47b8661387a033f3c4a1fc8dee724f2e1510",  # IfStatementAst
    "0.1.61.2.0.1.1.0": "c7728d3dba252948df40ef642417ed88e8276413b238095cdbc2c85d915be554",  # ReturnStatementAst
    "0.1.61.2.0.2": "029357bdaf32380c6cd58928d35444334524d3db8f67e53f30a22cfe1d8a88d2",  # AssignmentStatementAst
    "0.1.61.2.0.3": "1e03e988eca32aa4bc2c2c9cd6e9aa1da4bd26200b613f5392c6e04da76e2b7a",  # IfStatementAst
    "0.1.61.2.0.3.1.0": "fb33313ac15a10533ea3318f513139fffcabbaae3956fbb5901fd8cc7ea6e4f0",  # ReturnStatementAst
    "0.1.61.2.0.4": "b017f880bf551544960b067253f0d1fef23ee5e4610844bfe33a967969e1d8a9",  # PipelineAst
    "0.1.62": "c48a729f8edeb506db141b5df88846603c7117aecb4aed02cc2e6045e93468ed",  # FunctionDefinitionAst
    "0.1.62.4.0.0": "809c41c224fcd55721f9b22349864f98532196dec48592f7ed9731383275d96a",  # AssignmentStatementAst
    "0.1.62.4.0.0.1.0.0.0": "994209db596556ca7c085d34b01456a8d48e8f592c87a42b675b04439a504d61",  # PipelineAst
    "0.1.62.4.0.1": "7a9912ad548178368c2855edf93676c737db9cbf598094edcf5524dacdcbf2b5",  # IfStatementAst
    "0.1.62.4.0.1.1.0": "b1d21d93c68ca1c0f1d8ff9a5b06581cde9218f00fd89f39566812fe4eb4248e",  # AssignmentStatementAst
    "0.1.62.4.0.2": "4692da71af2aa53747ef94a7197fe8c2a83a2ea2b814ad73944197210d9827c5",  # AssignmentStatementAst
    "0.1.62.4.0.3": "fe52dc529299d94503810232bb942ac9bb9ed0305fbf2602647e91095a137e4c",  # AssignmentStatementAst
    "0.1.62.4.0.4": "5dee7ce088113adb0bdf8b347b9152792194af647e4d38ac5bbd0bf6b25af789",  # AssignmentStatementAst
    "0.1.62.4.0.5": "ff9ba53b0f2928c1b1459630c64213a94cc7e60c414ac679ad141fa795ddc845",  # AssignmentStatementAst
    "0.1.62.4.0.6": "ea8631e8592373bc207d8de30a8244b6b3dae7df175b0e904210393c93eeea1f",  # AssignmentStatementAst
    "0.1.62.4.0.7": "3f83b71de060e8da2e5a806cf6e6578916518dd424704690644edb15e4c971fe",  # ForEachStatementAst
    "0.1.62.4.0.7.2.0": "0b4193ab5d603cd7126a2f02082f2210da87c01634ffb1df080caadf1c12fe87",  # TryStatementAst
    "0.1.62.4.0.7.2.0.0.0": "438d2f58691bc845721d575d47e6bbb06f901c450bbb73f2a2a6c023fee740ae",  # AssignmentStatementAst
    "0.1.62.4.0.7.2.0.0.1": "f437c8ebf153208d6fb365370a7f9b5dd5e1f9d33095d284701af41024a42d7d",  # AssignmentStatementAst
    "0.1.62.4.0.7.2.0.0.2": "fe75825719a7c1c97429d3823a947dc6d38baf3c31aac88119cca50c5f63b6ab",  # AssignmentStatementAst
    "0.1.62.4.0.7.2.0.0.3": "5ca3bc52bcfdb94d1bd8f764392d2719eec58eb749d5d187769fc586713c396e",  # IfStatementAst
    "0.1.62.4.0.7.2.0.0.3.1.0": "966579c4e5e8c6a06169eb231053184089eb9426c717adf7d0d1b3428bfbf3d8",  # AssignmentStatementAst
    "0.1.62.4.0.7.2.0.0.3.1.0.1.0.1.0.0": "a58197a00e6426e8963412093959e4dae5662c88b155752cabcc17029ce2cead",  # PipelineAst
    "0.1.62.4.0.7.2.0.0.3.1.1": "71aa783c1984095a11a0aaeb45a3c108df9451f839e50d92caa4c310b8088d4e",  # AssignmentStatementAst
    "0.1.62.4.0.7.2.0.0.3.1.2": "78aca73861a06669de1cf6308b43d0c295c0cd1a9eeeac53dba631aa2a0e620b",  # IfStatementAst
    "0.1.62.4.0.7.2.0.0.3.1.2.1.0": "297e762278a2e85f8439188557eaaff533fa8ac9f82d7c0e787b5c2b6f8894de",  # AssignmentStatementAst
    "0.1.62.4.0.7.2.0.0.3.1.2.1.1": "aa1328eab8a90ffd21bf35e7d69ddb67da2e0a6f117ae93fd8cfdedc477aee6a",  # AssignmentStatementAst
    "0.1.62.4.0.7.2.0.0.3.1.2.2.0": "bd87ac078dcec1e8ce102df00be5d3d8b117954e7c86bfb07ea3037ab7958d5f",  # AssignmentStatementAst
    "0.1.62.4.0.7.2.0.0.3.1.2.2.0.1.0.0.0.0": "cc3e4f4f3dbf6bc8ead281fc496f8d340def250cd2b240f5dd5dec427f2fcd54",  # PipelineAst
    "0.1.62.4.0.7.2.0.0.3.1.2.2.0.1.0.0.0.0.0.0.1.0.0.0": "04bcb779ec902eb646623a75259db9f5b8558f9ce5af6f29d3ce8ea89ba75645",  # PipelineAst
    "0.1.62.4.0.7.2.0.0.4": "a7ddb5b475aa0d173d2c0516faa46db156832614684ef23914cee4b03d5abe11",  # AssignmentStatementAst
    "0.1.62.4.0.7.2.0.1.0.0": "451ce51026dd3656a51065a44ddcd5ab79306e37cd803e61d462477e4ae85f5c",  # AssignmentStatementAst
    "0.1.62.4.0.7.2.0.1.0.0.1.0.1.0.0": "e076a09812b334a0d58cdf44affdeedb3b6287cde228a2e1e852a4596b11a43f",  # PipelineAst
    "0.1.62.4.0.8": "aef01f7f54cc9e0cfd0ef88f40f5660f269a1d87ac5621fa690fe24bb19ecf7f",  # PipelineAst
    "0.1.62.4.0.8.0.0.7.0.0.0.0.0": "752135f50e99bf8ee901b353f7c0fd5dfa4a38a5f2f6a379575b78b6e6310448",  # PipelineAst
    "0.1.63": "b431b610ce6426f34b1f79a92baa7e22acaad637483dabe0f050295c67825229",  # FunctionDefinitionAst
    "0.1.63.1.0.0": "dae700815dfd645d643ace5f2a0a96565da36e411e22407b61bb524f6740ea44",  # IfStatementAst
    "0.1.63.1.0.0.1.0": "33e31cf8ca39a4fb69b3f50255676625b486d1db817c79f3c9d11237265b2639",  # ReturnStatementAst
    "0.1.63.1.0.1": "f0dece683223b57614fac689a8811f19aa4ba1a1e14892d8d11449f740a3b224",  # TryStatementAst
    "0.1.63.1.0.1.0.0": "489d0b02098da47d1a8e9df146831941d73b896d9f8bb7deeb0fd1981e3171cc",  # AssignmentStatementAst
    "0.1.63.1.0.1.0.1": "127637c451991922bd43e5d01759e0e21db3f979f5b52cf427878d842c523a0a",  # PipelineAst
    "0.1.63.1.0.1.0.2": "688dbab5903a610bf0aef65b75d38b9d17f95ed22be0e86b346bbafde22d8261",  # ReturnStatementAst
    "0.1.63.1.0.1.1.0.0": "22d555392147a2977a0f8eb0e559df2b1f2d640b69b36d825aaeb9aea1e7b91e",  # ReturnStatementAst
    "0.1.64": "9a12472d69743fd42373ba883eb9517b2199f71d3e9fe02ad36ca14cbb9a2918",  # FunctionDefinitionAst
    "0.1.64.1.0.0": "6ec70b4bbc6198b9ab125596921c1e5d1b82c1e2e13eccdf01e908cca3d96aad",  # IfStatementAst
    "0.1.64.1.0.0.1.0": "dbcbf966f217f389bd4002b240392755c1a9e44537bf7f2edfcc4c65933519ea",  # ReturnStatementAst
    "0.1.64.1.0.1": "ca86e13678ea8655f42beaa91f502525f617b011810dac3735c8d2d9fdc11d79",  # TryStatementAst
    "0.1.64.1.0.1.0.0": "cc901fc59c1b2346659f2a6c81d4409824cc2828cd37b699f44812b160665564",  # AssignmentStatementAst
    "0.1.64.1.0.1.0.0.1.0.2.0.0.0.0.0.0": "f86712c36ef6c407f33afe5a811b8fb356238578c2d07ed2066fc1aafa168b44",  # PipelineAst
    "0.1.64.1.0.1.1.0.0": "ec2230bd03c44686d353ca93610e433f81fa37b3d45c27b83b86466f7944dd1f",  # ReturnStatementAst
    "0.1.64.1.0.2": "f11db3594b6f5c4b91c465d8f7185d06c55b622816bc393e8604cf081cd74c0a",  # AssignmentStatementAst
    "0.1.64.1.0.3": "5c2e912fdc1d771951590a67c68ed50b85f99a3e7f24134a8adf2835ad97331a",  # ForEachStatementAst
    "0.1.64.1.0.3.2.0": "68e4350f699f4e0436d9fcdd1213735ff94ede2c925c0ba66cfa8607a9fa8ada",  # AssignmentStatementAst
    "0.1.64.1.0.3.2.1": "adc1e9680b7561dc712273155a866488a9c7db6392cf7624adac51249545c0ed",  # AssignmentStatementAst
    "0.1.64.1.0.3.2.2": "3be767436b69cc6193431d01a241ddeca843b78f8ddb68ad8c0be67f2ae35d1a",  # IfStatementAst
    "0.1.64.1.0.3.2.2.1.0": "4a547121d28327706a2e6f70f9eb1e192e8dc8388f5b635ea4942cd6b5bb8f40",  # AssignmentStatementAst
    "0.1.64.1.0.3.2.3": "afcf4b2032132fbb34c6823efd1e09e3864b5b26b96dc09e01e364df8f59328b",  # IfStatementAst
    "0.1.64.1.0.3.2.3.1.0": "bf209bcf8b934ccaf46e7e29c6eb078d1319576247ea4d2a777ccacebcf4bf25",  # AssignmentStatementAst
    "0.1.64.1.0.3.2.4": "ca548d032f46b0d9024ce573cd9eebf503885d1a88a9d619b78f4c5122cc985c",  # IfStatementAst
    "0.1.64.1.0.3.2.4.1.0": "eda151f0a761565c88b06517c25857ab73e230c720f820ea1e41493a27d1f8f5",  # AssignmentStatementAst
    "0.1.64.1.0.3.2.5": "b1e8cacefd9c2135803ab5f5a9a02a458b88a5e851b5710210cad3172e6fbb83",  # IfStatementAst
    "0.1.64.1.0.3.2.5.1.0": "f4480fdec1d5c132635f1d4c53b39b69498b5c8c63cccde7292db72490064191",  # AssignmentStatementAst
    "0.1.64.1.0.3.2.6": "625602c74fd698e8bd4d18b2fb02a9db792a94d31dacc068ca91041777b3e56f",  # IfStatementAst
    "0.1.64.1.0.3.2.6.1.0": "feac432d93e2a2788343b7be173d552ca24573a05ac3e503c6ab4a82c80c1e80",  # AssignmentStatementAst
    "0.1.64.1.0.3.2.7": "33a105b1a2eefd8c00acc07ddf034bfa52a958b7de516eeed84e40b3124f00f3",  # IfStatementAst
    "0.1.64.1.0.3.2.7.1.0": "5a0146fc370b73f130f5d27db053eaf25af2482e8eb06a15d3947d9f06eb959a",  # AssignmentStatementAst
    "0.1.64.1.0.3.2.8": "38eaf3a9a3306f54471dcbc96f81dd043b8e15d7ccd4c6dc82df73b8cd61e0fb",  # IfStatementAst
    "0.1.64.1.0.3.2.8.1.0": "d2e13561864968d6103bbd0c75ca2039998631c53778602dc2fa60f97ee21aaf",  # AssignmentStatementAst
    "0.1.64.1.0.3.2.9": "38fc3e30fbe57db43cc2bf04c548bc20b60a58603098664316cf916db99de7f6",  # AssignmentStatementAst
    "0.1.64.1.0.3.2.9.1.1.0": "50cca44a43f1018e76a3fd35413972446ae975239f6a16e0c903b77734d92f4c",  # PipelineAst
    "0.1.64.1.0.3.2.9.1.2.0": "91cddaff6c1e8136b5d3e8a04020abed41c790dee713a08c998da383da72eb97",  # PipelineAst
    "0.1.64.1.0.3.2.10": "1be9701c219ab25729f0b4296dc093596decc31680a059a93914e490d1de56be",  # AssignmentStatementAst
    "0.1.64.1.0.3.2.10.1.0.1.5.0.0.0.0.0.0.0": "443658da52f95310167425f9c4d085e422aec681270bf47bfc603994fca80ed8",  # PipelineAst
    "0.1.64.1.0.4": "c6bfa657f3a0e0289f3966507b56f7c3a5fb80a294baf2aaeea5bf0f5af9bd98",  # AssignmentStatementAst
    "0.1.64.1.0.4.1.1.0": "f8f5e1e9e53877a256bad107b0916dfc6e4e6fa2a80771eaa392734c72469921",  # PipelineAst
    "0.1.64.1.0.4.1.2.0": "c17c5e75445823e32ead705b7afdc3cd2555f0ecb6491bef2639f393a1606a2e",  # PipelineAst
    "0.1.64.1.0.5": "f7a852f12952999f02b80ef188e177ccf1a52f5de5fa311ae01b03e8731a7588",  # PipelineAst
    "0.1.65": "f06c704383cc8fe42663f20cae90b8a3287d9cc30a160687c69e20e5e0ae1e6c",  # FunctionDefinitionAst
    "0.1.65.1.0.0": "cca469651c438ad758ef10ca00328d7501f2bc166a1be595220769af76ba64ad",  # AssignmentStatementAst
    "0.1.65.1.0.1": "3a7059e8896c2030103d1b614d6d1dd7041193563506a4c55ea0e166fd3ca403",  # IfStatementAst
    "0.1.65.1.0.1.1.0": "d29b4ca86e9619ef592a280fb5fba790a144369d85bac7d891b0af6c8a6472e8",  # PipelineAst
    "0.1.65.1.0.1.2.0": "7ce3767aa176925627cf9a6059ed037b6ff3027e0f688fe3fff99c680ad15468",  # PipelineAst
    "0.1.66": "e4bf734fe1b62be56c35107af1167930316a3c7d0d575c82c0d74e0eccea0f27",  # FunctionDefinitionAst
    "0.1.66.1.0.0": "d486c172845625d31101c3402a68276735ee813041d6403ad268ae5d48a2ca93",  # AssignmentStatementAst
    "0.1.66.1.0.0.1.0.1.0.0.0": "0e0bc5cff0940eccc6543c23aa6d6a44bae6ec2f63516eb9072541b3a995f4cb",  # AssignmentStatementAst
    "0.1.66.1.0.0.1.0.1.0.0.1": "7167937f856591a3517fc7c80b8f5e463c71db42d64f441522fed7f2b0a7d2df",  # IfStatementAst
    "0.1.66.1.0.0.1.0.1.0.0.1.1.0": "3528a302c89d94e7192eab98b144351c4628df2fa3ac7ce590e87e9541a55059",  # PipelineAst
    "0.1.66.1.0.0.1.0.1.0.0.1.2.0": "1deeacad03a72838608ba5bff7c580d7296b29b00115c052c6afa40fb06e0034",  # PipelineAst
    "0.1.66.1.0.1": "38e1195cc090f085768950bca5607e89aeac27d4e0868d0083ea63cd3504f873",  # IfStatementAst
    "0.1.66.1.0.1.1.0": "197d2a61b69ea0101d681325f22d4ea05d7702addccfac07cec4f69045b36ec7",  # ReturnStatementAst
    "0.1.66.1.0.2": "c8ebab31e387762a9df67c032bd4fda559b0b2025d0ae238d22a5a895624e434",  # PipelineAst
    "0.1.67": "c22f34ca8b8290277da92f3b5bf77f53445f65947e29d947367d2fe99e25cf44",  # FunctionDefinitionAst
    "0.1.67.1.0.0": "2074212aff56744498c83e060663385dbd2c30966fbb257e2d558436eedb8bba",  # AssignmentStatementAst
    "0.1.67.1.0.1": "e8398f8b75a35a0aaef116045fb3cc3730dd714dc48a19ebe91a2105fc6f5356",  # AssignmentStatementAst
    "0.1.67.1.0.2": "2cb8ca19ce5dbd3c2bed96cec3098e36ddba30be2a2ddbcf0b62fab2fe3eb339",  # TryStatementAst
    "0.1.67.1.0.2.0.0": "316cf33b58f404282f64cbbd2e501c532bf174ad0bf391d953f3b428f91270c8",  # AssignmentStatementAst
    "0.1.67.1.0.2.0.0.1.0.0.0": "e54cc29e7f177b79328109ec0aa26e711e03088fea80f49028ccc3870273f275",  # PipelineAst
    "0.1.67.1.0.2.0.0.1.0.0.0.1.1.0.0.0": "c619d5295c54a5d869baae215d2fe2f18ae154545cd57fe3cf9cc891c8a34806",  # PipelineAst
    "0.1.67.1.0.2.0.1": "360fd2bec6773ac1e63623bf1390b73fbc9bd2e3c2323dc68dd41e4f43279732",  # AssignmentStatementAst
    "0.1.67.1.0.2.1.0.0": "bfedbf5e17a6bc6e457d446fa1689969ba51b88a978bef1f337f4c20be3d2508",  # AssignmentStatementAst
    "0.1.67.1.0.2.1.0.0.1.0.0.0": "d7ae7d893aa430e9b17d7e6622f624bf8c92bc13c0b199ca84e0246deebf109b",  # PipelineAst
    "0.1.67.1.0.2.1.0.1": "2264aa8a479b1f66814030b01669e6a3c92479142ba82c2bdd0a68cfd9269e40",  # AssignmentStatementAst
    "0.1.67.1.0.2.2.0": "35f00f66844563c42d807c414f3c505dc8e56eb98c2b6bb5122f7729a6a3dc0b",  # AssignmentStatementAst
    "0.1.67.1.0.3": "76bb14ed09b23e018ab27e20eb8fa888b2ab9cbce67a46d7bb3baf3e58b2b3e8",  # PipelineAst
    "0.1.68": "4db72a935308df541c30a8a07720721be98fbfa64f7aa5bbf336e2f20b75e7ae",  # FunctionDefinitionAst
    "0.1.68.1.0.0": "b52e4e724ee09bfa3bc955cd36163825862292566cbcb71f2caf946856d6ff4c",  # AssignmentStatementAst
    "0.1.68.1.0.1": "46f2cdd54dd2da32970ab7c717024031b5afe1e4961eb2b6fb1d09a93c20aead",  # PipelineAst
    "0.1.69": "8eb333bf522d0c1b1cdb6614af64353a1a6c407b8705441a5190ef8348c2af7f",  # FunctionDefinitionAst
    "0.1.69.1.0.0": "6dfcf29eef821eaf31a5c43b738e08a7ec6fc93dbd6c86a511bb504b1c25400f",  # AssignmentStatementAst
    "0.1.69.1.0.1": "e1908fe14363880805fd0306fe3ca3e2b1d0ff897b6e6032634ba7ca3835d763",  # PipelineAst
    "0.1.70": "5e8896f5071dd19f48879305bf3ff003e7eda1bff8f4da51e0989a6fc3ba6926",  # FunctionDefinitionAst
    "0.1.70.1.0.0": "18afe88b5902636619aae8f16a348cc4965460a8f3f73c056462656430bf0c72",  # AssignmentStatementAst
    "0.1.70.1.0.1": "268f89e5cb0afcb19e1cd665038f53af9accf61a293ea0de51a15c0d249f044c",  # PipelineAst
    "0.1.71": "75e3bbc96c0a27bf86bb900bb60b01db6dc0db2f81c52ce51343259cae632399",  # IfStatementAst
    "0.1.71.1.0": "b4271eff66662a68eb44d045eca9d15834274377bc91279da65b379c3369dd89",  # ReturnStatementAst
    "0.1.72": "ca4a21b7c4b0b5145bd1f31132ee1cace012961d361116fd12bab214c6d8b93b",  # AssignmentStatementAst
    "0.1.73": "a48c954c8da5b1fb85f25fb4331deb8245ec2f76f40920d46e3375a8e21f9b00",  # AssignmentStatementAst
    "0.1.74": "63c967552b41067f84f09e9bc629910898991dfce1f263fc9813530dfcdcde70",  # IfStatementAst
    "0.1.74.1.0": "753f5daf02d158f563f32d29af433c50b1b2a744cedec8e47a450bcd3f24bfd0",  # IfStatementAst
    "0.1.74.1.0.1.0": "fb51a80d4e09db6d248101a6e12100f6071e18f3c4f37cc1addbcfcb4e21158b",  # ThrowStatementAst
    "0.1.74.1.1": "3dd3060aedc60dffd5341ca1d168488ce29f18d598638357f48ce10b1f43d4bb",  # AssignmentStatementAst
    "0.1.74.1.2": "f7cc6d66beb0370038390566a5ae58bb1e0883c834bddbb1f698d2871ef58c68",  # AssignmentStatementAst
    "0.1.75": "f378bc10af25d66bd9ac3b026f15fcd7f73eb0bad175ffa7e504bd70ffbf36c8",  # IfStatementAst
    "0.1.75.1.0": "011cb2829655ef4315cf774ba4d6e13f59c84afe6a39e82f88ba6e8e22528b8c",  # PipelineAst
    "0.1.75.2.0": "15cc1fb735e588557efae74e3eed28f7748b0dcb9494a663c6736727f462bef9",  # PipelineAst
    "0.1.76": "c5345d4bf2eaa0b7a0a05b194132d0a587c45310fc40a66a105d4150179e8b35",  # AssignmentStatementAst
    "0.1.77": "b84d964ee5883b9d993f632058275edf8a3776be19938dd27daafe55d93313b5",  # AssignmentStatementAst
    "0.1.78": "b8ae18f96f34db6eefa71735a6ad710f9df837436f36fcd87aaac2cbac54beaa",  # IfStatementAst
    "0.1.78.1.0": "8b542382f974a7280b72d383ca0a1c4ef94b55590a68a6bca7fcb1a20db04ab7",  # IfStatementAst
    "0.1.78.1.0.1.0": "06d1c5d21923c1a4fc8316166f9c9617ada45118fb31460edbe5e99d90edf2a0",  # ThrowStatementAst
    "0.1.78.1.1": "5bd92916cdc40bb8a2bb6a0e7bc6e07439014d34be26b1ec1d29ae845ceb9709",  # AssignmentStatementAst
    "0.1.78.1.2": "8c4a7aab7aad2cf703f16dccadc8a3c9b2ccb55d3e67496d11548bbca0025951",  # AssignmentStatementAst
    "0.1.79": "c039f18f06ea446a6104f2311e1d7426e2e531d8d6cad777120b643ce80428ae",  # PipelineAst
    "0.1.80": "c393e53ad8e0d98534adeddeb05807fe552f29e436fb78c76263411e3ef67ccc",  # PipelineAst
    "0.1.81": "776d8a6fecc0f3942e61ad446e218716cbf3fbae8dadd587d4977e5ac6494ddb",  # PipelineAst
    "0.1.82": "2b1bdda94cfbeae24f2c31eda17b1fa6298c822d93104b420acb6b410bfa9359",  # AssignmentStatementAst
    "0.1.83": "563a87108e8da04cc5e12f57199e10cd1bfd908269f712dba8fc5e3cad7e026f",  # AssignmentStatementAst
    "0.1.84": "94fdd712a806327072d83456840862cd7462f57c49f1a738d31c6fc47c0ad366",  # AssignmentStatementAst
    "0.1.85": "734eeaab4914fcec724197dc35f6cf41c0828a0048898d77d25070997c59af0d",  # FunctionDefinitionAst
    "0.1.85.4.0.0": "2907a5d28a08feec9be26a5dd4785e7c3807778e23e0804673d573d4be7a633a",  # AssignmentStatementAst
    "0.1.85.4.0.1": "22b31bf8366f166dd384082a50d86c7ff16ac5220487a74bc6d314c4c3523456",  # IfStatementAst
    "0.1.85.4.0.1.1.0": "5aa282bcdc927b415dfd508db45f09ca6c57a9fc914dee6477e1655d971756c6",  # AssignmentStatementAst
    "0.1.85.4.0.2": "48132264679e7836acb817ba02350a488eb3bfe7c1a079b68c0134ae7a3fb8f6",  # AssignmentStatementAst
    "0.1.86": "94140f61dbe17ea7ec380a60320c8395ef4fdabd53b84f62a74598f2c00678b3",  # FunctionDefinitionAst
    "0.1.86.6.0.0": "123430129686a10f513416468f60390f073ef41c59bebd32c1893ce032f7c7c5",  # AssignmentStatementAst
    "0.1.87": "018407d4f56fcc900472f7f670a5940f0b9b0bbd554c5504d7c36da3a7ba65d6",  # AssignmentStatementAst
    "0.1.88": "f5ea20d7e355bc64f8a10417af5b7118cdca4c419d5dfcb7f54c183d69385031",  # AssignmentStatementAst
    "0.1.89": "78531be6e8420c739d38ebc1b984b7f5754bfd8b28fe99fb81170917523e9261",  # AssignmentStatementAst
    "0.1.90": "7fcfe6a554ef8741a6cc6fc9fcf2a0a9d241599c58dacfddec985d468459d149",  # AssignmentStatementAst
    "0.1.91": "2f6e062eca4813b8e8a3783a75b6617cd0886b5b23a8c85c311f18808dfc6128",  # AssignmentStatementAst
    "0.1.92": "74974ad5c1caf11350fdf432db0ab1546db913bb8198a7a47743abaf7de7fafb",  # AssignmentStatementAst
    "0.1.93": "ea5e9ae55c3252ed869a0b3e3c31282c17904051a762f21d3b8a61986dd033eb",  # AssignmentStatementAst
    "0.1.94": "44d43620f63079ecb7ea18602b925a9367a1538f0ca6ce10226aa84c6d2aa294",  # AssignmentStatementAst
    "0.1.95": "375f918d7cdd65faf9a5e2735d445cd2fca4b43b86aaf97afeb831179caf287f",  # AssignmentStatementAst
    "0.1.96": "7d2fb0bc12150e42c7bab7e2e866575f28b4bec36c5136a8bd7bdbbbaf1fe1fa",  # AssignmentStatementAst
    "0.1.96.1.1.0": "7d0b343a2414f400d46a9361163e2cfc56016aac8698d200c1661d66b44ae54e",  # PipelineAst
    "0.1.96.1.2.0": "11a6049d00625db0e2140f591bb5ecbac6b28b761a7c2d1ca3d1515833c3ce38",  # PipelineAst
    "0.1.97": "b2ed066b4b7c05e783f4384d50e464a4d621bf129fd83308cb3e959db153d84d",  # AssignmentStatementAst
    "0.1.98": "4d1874f724ba9b56f8f0457849406873ad287ad965b2871a2b7bf95f41876fb2",  # TryStatementAst
    "0.1.98.0.0": "0bc177b248b6fb0847a88422d8b0f4bcdd627e9919b56c71e0dd606b2b6f9fe1",  # AssignmentStatementAst
    "0.1.98.1.0.0": "c15c4a0bd783184325aa4fe5e3b3878b537426fd17c0bda93895607fd5777d1a",  # AssignmentStatementAst
    "0.1.99": "e214e8fe39d07f00a5a4b74c2dcc9d5f982be50ada327cb0890474dc324c818d",  # AssignmentStatementAst
    "0.1.100": "abc004dbc678911fd5ff5f2e19f2b8d6ef0193f3e96116e4e3853079d5bbc0b6",  # AssignmentStatementAst
    "0.1.100.1.0.0.0.0": "ba3ef25ce25b75a63365318d0e0a16fd7733c9117bf7913c8b087e94c23b7cc2",  # PipelineAst
    "0.1.101": "f3eb0baebfc3100f33f97ad5ca80f29db84bc94ad63f2a259f78146b50db6d1f",  # FunctionDefinitionAst
    "0.1.101.4.0.0": "8ae0304fe834e8daf9fa56198122ddeb0ac871c218feffa4ce3e87bd6758ee94",  # AssignmentStatementAst
    "0.1.101.4.0.1": "9d3a115c497487a4979a735978b261c09bbd72372fb3f81361fa2a2004b39798",  # AssignmentStatementAst
    "0.1.101.4.0.2": "47b71a2fe74007c8eec0431f105fca6bb3e046b3392b27b2f43eade8253f2c9a",  # PipelineAst
    "0.1.102": "1ccfd281d4e67324e0a782b84c5d10a6a185e53d67641d6343459e6d8fac5ad6",  # AssignmentStatementAst
    "0.1.103": "9a9ee89e8316b690ac95369fd47b637ccb96eac43114c28beba2dddb32f8eaba",  # AssignmentStatementAst
    "0.1.104": "5c0d1c8555128610c70a7c75fd0ba0f660f6fd13b04d78d9edd66456797f94ae",  # AssignmentStatementAst
    "0.1.105": "9c346b54b6e9264d5923dfa7dac85c7ebf2aea4bd2d2715856891a1f2a3024c5",  # AssignmentStatementAst
    "0.1.106": "8570bc24faf09daefe26730cc88c5844ca85c5dcd9b129811eb970f021da88f5",  # AssignmentStatementAst
    "0.1.107": "a7046262602486b263bf69c760ecf06bcf7f60b73c9ffa41a12964913b39f67e",  # AssignmentStatementAst
    "0.1.108": "e27ce6e95032c2fddfd30aadfaa02491fc5ba6f181888a5d74599ab81315da48",  # AssignmentStatementAst
    "0.1.108.1.0.3.0.0": "af1b81ddd17e0cdaf638b90583380173b8a94ab34d9466f8d86d47bf2530e231",  # PipelineAst
    "0.1.109": "48478d2b7e67aa3d49f5c478013b96dffef1e241bc85ab30ede1804118e5cb6a",  # AssignmentStatementAst
    "0.1.110": "14471179b4f28f4c200756e74c2db7f383497a988cfd7d4142f2dc2a623a739f",  # ForEachStatementAst
    "0.1.110.2.0": "a39abc48a87b25e34c1286e389b9948fe79e9857feeea2c7ee2ac4ecf6d011a3",  # TryStatementAst
    "0.1.110.2.0.0.0": "81b50899c63bcdbf1d771fc2fefefac81432a24e3cf9e49692d0d8136a70a59e",  # AssignmentStatementAst
    "0.1.110.2.0.0.1": "447ddd53cc154fe316e44d4da10a05ed5ba69f567ff1bf297f8e4020de130e8d",  # AssignmentStatementAst
    "0.1.110.2.0.0.2": "fd10bd8d6def2b7fabae9d34de8bdced8217e53ab2312254135ec29c8a6959fb",  # AssignmentStatementAst
    "0.1.110.2.0.0.2.1.0.1.0.0.0": "5a3b77fe2b4564851081276657746f7ac2e6b751410a4e3b8f71846fa611a85a",  # PipelineAst
    "0.1.110.2.0.0.3": "dcac2ce8f5b4457c02f6451a15c7b9a9aafe1c5616eac017f3d8a4e880e9103d",  # AssignmentStatementAst
    "0.1.110.2.0.0.3.1.0.1.0.0.0": "cc0a0fd0d205964bb6703a0b7e2eba5f4f9052dd7ab9cde4216283b55ecf6fd1",  # PipelineAst
    "0.1.110.2.0.0.4": "92024bbcf3710c13a047b2bfe18f22634c1abf0aa3f587750c73eb3696d06c19",  # AssignmentStatementAst
    "0.1.110.2.0.0.4.1.0.0.0": "06dfdf019de75af02183f7b11968d83d078486d68029b47ae7ca5147349be2bc",  # PipelineAst
    "0.1.110.2.0.0.4.1.0.0.0.1.1.0.0.0": "0e913e93e712f61be534e3d6df2b15d3eff79abeb66d38e479a1d2dc664e8674",  # PipelineAst
    "0.1.110.2.0.0.5": "e0bed9aed01413703a914a5772111c9fdfc3a957f1959c994a483208dc3d2573",  # AssignmentStatementAst
    "0.1.110.2.0.0.6": "22808e162ae71eb7d3270cb8a04cc50c20ae0ab314348321b2cc1edacde55f30",  # AssignmentStatementAst
    "0.1.110.2.0.0.7": "ac33af5faf537bf1e2a3e41c1a2cb2db3a4a2810f071dd06715eae422dd95b2c",  # IfStatementAst
    "0.1.110.2.0.0.7.1.0": "ad90066988bbddfb5e00cb220d499e414e329c624a48c15da7b399dc2d297bbc",  # AssignmentStatementAst
    "0.1.110.2.0.0.7.1.0.1.0.3.0.0.1.0.0": "b884807f96b72c2e9b1891cb1f3af5630c78301f6f8ff26973c586c300263ae7",  # PipelineAst
    "0.1.110.2.0.0.7.2.0": "f36d78cb23e325e43bb516091ca0c0e57f7e02df5069e3b3d2cfc1cb93407482",  # AssignmentStatementAst
    "0.1.110.2.0.0.7.2.0.1.0.1.7.0.0.0.0.1.0.0": "b4a0947f41c30fcefaf2f229c1bde6f06a9948762ba84a80d99796b83b06db3c",  # PipelineAst
    "0.1.110.2.0.0.8": "41a5d20da75a587f2f4e29fd9323ab0fb510f235d7efa3897da3fad3b68fc90b",  # AssignmentStatementAst
    "0.1.110.2.0.0.9": "1a9e5b5a0f86b1315f3def100b328c1bf826fdfd85a55e9ff54d753b8b3fabd4",  # AssignmentStatementAst
    "0.1.110.2.0.0.10": "6837c5747d7bc37f048b9e5e2dff04311ac7d4ff49adb5e1250284da0afaf296",  # AssignmentStatementAst
    "0.1.110.2.0.0.11": "763e83b6f996a9088cf4f505eacf575f49837c0bdaa2e2257cf1ba0860684dd4",  # AssignmentStatementAst
    "0.1.110.2.0.0.12": "b35783859b9d57989abd0c3ef7623df3043b760555be897baa5ffffa62064a89",  # IfStatementAst
    "0.1.110.2.0.0.12.1.0": "672c4039f75f263a20d510c8dd0eca6bcdcbc8cbafa1c6fdaa196dffd1a20ff7",  # AssignmentStatementAst
    "0.1.110.2.0.0.12.2.0": "3142580b5cb1587d82bc19dfaab45e97302dd88caa5c1ee30660316c5bb3532a",  # AssignmentStatementAst
    "0.1.110.2.0.0.13": "fc1f4f4f90810b8abeb2c33b316fd0f711e75cd125c6b148220960571af2785a",  # IfStatementAst
    "0.1.110.2.0.0.13.1.0": "989689308cd82b3cc1689fbeccd82906ae5efa562c8b89e2ab9a05b813dddee6",  # AssignmentStatementAst
    "0.1.110.2.0.0.13.1.1": "60fb4c3e9793b87f0bfcd9093d3d59c557bec72ea529e06d68cd25921623abe0",  # IfStatementAst
    "0.1.110.2.0.0.13.1.1.1.0": "7b873199ed567da23e3aa4281f80069ecf63d89f3e1206957804d7d70b445aad",  # AssignmentStatementAst
    "0.1.110.2.0.0.13.3.0": "419a8430bb229399cb890e79d48bf6542970177a0d69d9ce80b0079c4211a22f",  # AssignmentStatementAst
    "0.1.110.2.0.0.13.4.0": "574a40b1bec34565685af96dce96358ae5f7093e836ce7443f4fd2a74cd0ef88",  # AssignmentStatementAst
    "0.1.110.2.0.1.0.0": "d3e6cc90a1f3d7e65215ddd1061c90a306876425ae6a7399d978026b9d0388d4",  # AssignmentStatementAst
    "0.1.110.2.0.1.0.0.1.0.0.0.0": "d6720dc3ea98f98c855637f7542f10c8541dcc83e26dbea51c8d5ef666c2444e",  # PipelineAst
    "0.1.111": "460818e12c7794619aa83cc408125895418a34827194315e44817f71a53a9451",  # AssignmentStatementAst
    "0.1.112": "1786eb77f5c1a414503c773df39b05156fc95223d2b5e62e67cecaeda6aefce6",  # IfStatementAst
    "0.1.112.0.0.0.1.0.0.1.1.0.0.0": "8237fdab5920ba8b70ad68a1444d70027dfa4529e9f52115412e4760e4b22c20",  # PipelineAst
    "0.1.112.1.0": "baf49746eb9b095c685eab691c3ec0f75c0a5b6a592924d4fe914771c2b618a7",  # AssignmentStatementAst
    "0.1.112.1.1": "92e531f27822e5e119201826c60e8e1902bb3ec6f75a3f6961ab67c241d255a4",  # AssignmentStatementAst
    "0.1.112.1.2": "15be7b58df27b897fe56d42b190a9ddbc61848904c9fe7b4a72f8ad067c1b76a",  # AssignmentStatementAst
    "0.1.113": "ce7a10c638e673c1261023c83284f47f67756d4685bda496aa4f935862c8c537",  # AssignmentStatementAst
    "0.1.113.1.0.3.0.0.0.0": "7b6e54756aaf33cd161bc84ca5e23696622f17b9e954c387cdffca63eb832bef",  # IfStatementAst
    "0.1.113.1.0.3.0.0.0.0.1.0": "85938cade3e2a2ef0a3a5d06b431eadd39b83dad465cee01c03580e2575c3ffe",  # PipelineAst
    "0.1.113.1.0.3.0.0.0.0.2.0": "201b21fd9d8b73a1424d24f66c7d720781fe0dbc7dc5b967476bef557f21b43f",  # PipelineAst
    "0.1.114": "555feef65c6caf2b2762549648e522168d011552e17e0867f0b913d6a61a5aa6",  # PipelineAst
    "0.1.114.0.3.0.0.0.0.0.0.0": "0565e0993e4cea4593111cab3ade2dc0a64b4f93b05140a0542607da12451f4e",  # PipelineAst
    "0.1.115": "95c9ee347cc67e4f88b36f0395d48a67f2df945a731d13473ba86ff1f820029c",  # PipelineAst
    "0.1.115.0.3.0.0.0": "68b70fbcb272943b5a2754820ff182f123c65ad964bfae722c269f8fe258134c",  # PipelineAst
    "0.1.116": "7d60d99441a09f2e11430462d179d5416a4a995389ac83d0b50cd85ef429f4eb",  # AssignmentStatementAst
    "0.1.117": "a37be63617cac133288a94619496475d7e08ed175033c763dc29cfbb7a242d0b",  # AssignmentStatementAst
    "0.1.117.1.0.3.0.0": "4d7a048a89ff0452292766a84756f48c26bb0e6fc485810a614c94fb82fc0a4c",  # PipelineAst
    "0.1.118": "4cabe0502d02f77cb16350560f6f2625c4f96bf7b090504f388d8e03d48d64e9",  # AssignmentStatementAst
    "0.1.119": "5ef2f6443e165a1bfd228b7cb306cdc7b466491ab3785b3b993cace698ce4b04",  # ForEachStatementAst
    "0.1.119.2.0": "ed9bd039c80f19059a533d711b103d412e18a74ec2057f2c8822ff82bf664a0e",  # TryStatementAst
    "0.1.119.2.0.0.0": "01221e0718578e4cf8be2186a425ba4a782e69d354f51c8a09ec8a1653d68b19",  # AssignmentStatementAst
    "0.1.119.2.0.0.1": "f06ea8782a03774c94b6686e0e232c2214b9e178289ceaed849aedeea612c4cd",  # AssignmentStatementAst
    "0.1.119.2.0.0.2": "9173f7da360f2644544a0b9791553c7f423e1306af7950bbaef055dab41fe899",  # AssignmentStatementAst
    "0.1.119.2.0.0.3": "17c64106ea8d3697597c2115c538e3baa8aaf55a85d43b5f44df384617568d22",  # IfStatementAst
    "0.1.119.2.0.0.3.1.0": "5ef51aed3a39f87f3bedf77c8b98bfca8be01d2314accd47c38b098adf4fe0bb",  # AssignmentStatementAst
    "0.1.119.2.0.0.3.1.0.1.0.1.0.0.0": "16646f48a8ecad65e96a9c56565d84bfa77d0b0e7e077cb406767c38ddf99bce",  # PipelineAst
    "0.1.119.2.0.0.4": "de476290e20055654918d9b57bba2f9012f3e0856bc8a96e80c2e02f41d2daeb",  # IfStatementAst
    "0.1.119.2.0.0.4.1.0": "be321ba809fda2b82c0d8c187ed4f1ec35ba7bcd571e86ddd0ef528fc4061f26",  # AssignmentStatementAst
    "0.1.119.2.0.0.5": "ee4a7b16833d7b984bf7998384ce2eefe2421bdebcd3603872c18fb2eb3bc876",  # AssignmentStatementAst
    "0.1.119.2.0.0.5.1.0.0.0.0.0.0": "933d50444cda30e4e48d812ac66b6f58e3070b6f539cd0a5ba2b85a9e3d28d0d",  # PipelineAst
    "0.1.119.2.0.0.5.1.1.0": "1aad46fab5517e94b5666ff36d69f83a37ea5fbbfafbe8f9db80c5e2e923347b",  # PipelineAst
    "0.1.119.2.0.0.5.1.1.0.0.0.1.0.0.0": "a26115977902abbc1e6c5fb33432f647c14dbb88162694092c8190853e3879b8",  # PipelineAst
    "0.1.119.2.0.0.5.1.2.0": "1e0860315abf48b1714e51adf7e481d906165d5b5b06377014802bb90aa5156d",  # PipelineAst
    "0.1.119.2.0.0.6": "55a0e8a23dac4cffc2221af2beeaff7b3893b56ba827083893fec64ffdb2807d",  # AssignmentStatementAst
    "0.1.119.2.0.0.6.1.0.0.0.0.0.0": "1a1195c51e312e8c5bcf47a690710cd808a8e1e44b28f380bae8c6585a9e9959",  # PipelineAst
    "0.1.119.2.0.0.6.1.1.0": "1d8ec8e19374ab166e55a6dd10e4a3b817b7adb55e085c7cec5a5264c6523dd6",  # PipelineAst
    "0.1.119.2.0.0.6.1.1.0.0.0.1.0.0.0": "e3f3577236e69e9cc127c271fef7ee791e9dd3d8cf4c86483d1192dfa9d8d44c",  # PipelineAst
    "0.1.119.2.0.0.6.1.2.0": "4c10c8bd752d3d79f29458bd3b93e508f42dd080ce62e53279c156e8ba9b6f92",  # PipelineAst
    "0.1.119.2.0.0.7": "402ea7decc2502253b595e28eeafb9b27a9fb5373a3c2d95d07e9b99872e661a",  # AssignmentStatementAst
    "0.1.119.2.0.0.7.1.0.0.0": "2645d54cbe45d3858868cdf80e452a10cef1c366fdee7a41c2b2d35f7df9b08d",  # PipelineAst
    "0.1.119.2.0.0.7.1.0.0.0.1.1.0.0.0": "d73facce9865ec111833e0b580f66332ec33905b607d58fc505694d3b88fbe3c",  # PipelineAst
    "0.1.119.2.0.0.8": "9e9cab9bab55af34af0055a84ca57eb2f4145d745c1130491906e00c357f7a75",  # AssignmentStatementAst
    "0.1.119.2.0.0.8.1.0.1.0.0.0.0.0.0": "cad031787186cbee5e6b3359d21c21757513c7a337a98320a260530ca477f8e1",  # PipelineAst
    "0.1.119.2.0.0.9": "193dcd00a2dbfaed4cd27b37444c65de9658cf430cc628b70964f33445774b82",  # AssignmentStatementAst
    "0.1.119.2.0.0.9.1.0.1.1.0.0.1.0.0.0": "0ef6b32c1bf77711e694b58ae6eb5bb6b4cb570de49084ded4d420aeec4c5a52",  # PipelineAst
    "0.1.119.2.0.0.9.1.0.1.3.0.0.0.0.1.0.0": "d8fd2935035f6de43522ea264f5e061d289df42c6f8c54ac53b028b808491c33",  # PipelineAst
    "0.1.119.2.0.0.9.1.0.1.5.0.0.1.0.0.0": "bbf7cb8d42d88af4a6a0371d51bad5f9b6e2fd9620ac9b3f46b479cb1b065457",  # PipelineAst
    "0.1.119.2.0.0.9.1.0.1.7.0.0.0.0.0.0": "08e03bffca2c549e2127c6e4291df35e09eea03c5ac874e75fa37ea7a3f575dd",  # PipelineAst
    "0.1.119.2.0.0.9.1.0.1.7.1.0": "a5f57c0df18bf55fcc32ede57ac3d6010fd5ad6e39246e2a11e2edb02583df40",  # PipelineAst
    "0.1.119.2.0.0.9.1.0.1.7.1.0.0.0.1.0.0.0": "c6a577c21f12d57e8f705cd9c74803fb61f96b655bc69a8be7dfb85a58edb49f",  # PipelineAst
    "0.1.119.2.0.0.9.1.0.1.7.2.0": "9308836075132f81954bb692564ef1db3a7aaedefe903417f340033b67b6425a",  # PipelineAst
    "0.1.119.2.0.0.9.1.0.1.9.0.0.1.0.0.0": "faf520b79678573442976a70a43c96d92d95ed545dec12b72e89714d5928c950",  # PipelineAst
    "0.1.119.2.0.0.9.1.0.1.11.0.0.0.0.0.0.0": "eb5768b59f80e653338f92c548b9b0ce6f7ef2ceec838c372b41e72d6afbee7f",  # PipelineAst
    "0.1.119.2.0.0.9.1.0.1.11.0.0.0.0.0.0.0.1.1.0.0.0": "4496310311d7698e0c0f40d5077dc41e53c37e5b817653e05c9b6d55d760ec6a",  # PipelineAst
    "0.1.119.2.0.0.9.1.0.1.21.0.0.0.0.0.0": "fa648cd870c686e19a7dd491e4be7cb6a7307ff3ae13b38d9ed729a1170eabbb",  # PipelineAst
    "0.1.119.2.0.0.9.1.0.1.21.1.0": "2f9e20511b100a3f985291a82313b5e015aba024aaa118cfee7d7fbbf5080d58",  # PipelineAst
    "0.1.119.2.0.0.9.1.0.1.21.1.0.0.0.1.0.0.0": "681ccba64a0bc2d7448ce9bc3c9de67aa66b405ca1cb336275479d33ff5b8860",  # PipelineAst
    "0.1.119.2.0.0.9.1.0.1.21.2.0": "d186fb38eb997a5473b0276f41ab715e5cfd4dcbf56981efad60f3091120c17b",  # PipelineAst
    "0.1.119.2.0.0.9.1.0.1.25.0.0.0.0.0.0.0": "71d63c4fa70a2b8cdc104dc624e40219f0492ac4fde82693340c9df52ceb3668",  # PipelineAst
    "0.1.119.2.0.0.9.1.0.1.25.0.0.0.0.0.0.0.1.1.0.0.0": "4a4cc701166d6ab2a75979574f9cd26d820066c58f3cfd0b18e7d05254195339",  # PipelineAst
    "0.1.119.2.0.1.0.0": "ec7ab4590f96dfbe4e74ba44efeb709ab414234d43790fad6453edcc15193b96",  # AssignmentStatementAst
    "0.1.119.2.0.1.0.0.1.0.0.0.0": "1e14366b7a0116eab0ef872255b43e494a69d6d6145fdcc5cb1eef2aad801e2f",  # PipelineAst
    "0.1.120": "aa911edab10b38a82791cc5f35c12d967200e0e5d6b30148571b2a12ff393586",  # PipelineAst
    "0.1.120.0.3.0.0.0": "600b0a608b1f2ba00a5ac217b6b001cc75eb93fd3efe3347944503afd189ffb9",  # PipelineAst
    "0.1.121": "4303dd099503daebb22b5f9bf7b899ad23a072cd2bdea56eb9b9ba2d074f208f",  # AssignmentStatementAst
    "0.1.122": "c47c2f702e9b04ce13d492ca034460754dcdc971a733549555320edf4edd5acf",  # AssignmentStatementAst
    "0.1.122.1.0.3.0.0": "7e5f8178d31f0083bca22b150f54a08642f27f3416efdda1df0692c1b06faa62",  # PipelineAst
    "0.1.123": "e508c754c6f4cf3591f6edc7889846d33edd76b770c2cf9d10fddb555780ae0e",  # AssignmentStatementAst
    "0.1.124": "bf0bfec7a32cd5e643a999ddb9386a33c8ed49105a943ab35ade3abe8f1316aa",  # ForEachStatementAst
    "0.1.124.2.0": "5ba6073059851cbce19d76115181737dec47ea590637196b4f765cc8a66d88da",  # TryStatementAst
    "0.1.124.2.0.0.0": "a67209eb1093732acd47e0755eeb78a90d65fca1e9288aa6f3f38fd468fc5e17",  # AssignmentStatementAst
    "0.1.124.2.0.0.1": "1793d9dbd9aac702bae533ea6ca6eee4d177b8984a5ba831b056ee2647118453",  # AssignmentStatementAst
    "0.1.124.2.0.0.2": "cab1a6cc8b66ccaa98b8abe8158d7af59776e0363a4b9f9be5703398ea11000a",  # AssignmentStatementAst
    "0.1.124.2.0.0.2.1.0.0.0.0.0.0": "448c522b77f911da32fe209cf508a9bb16782315d31ceda8f6357aa5e62a2a5d",  # PipelineAst
    "0.1.124.2.0.0.2.1.1.0": "f5bce68ef1a729b0b7d0f69aaee2890ac2b4ef20a5dfcbbdde02d78386d6f088",  # PipelineAst
    "0.1.124.2.0.0.2.1.1.0.0.0.1.0.0.0": "ccbad22a48aa088918b5c719e1c9ac33bdfe185ce2f2d1d8c161af270525e733",  # PipelineAst
    "0.1.124.2.0.0.2.1.2.0": "f65a063ac9ca42ed8931141ee0ab3d515309e25ecf02615e2317695bf2eeea0f",  # PipelineAst
    "0.1.124.2.0.0.3": "b4c2c0ffeb5c35999a883c6f5d505591bacf1c1905969d1fc9efbd099d53651b",  # AssignmentStatementAst
    "0.1.124.2.0.0.3.1.0.1.1.0.0.1.0.0.0": "76ed91dd00a830115171271d842d412e5ce3894419816fabb74711fd0b0e602b",  # PipelineAst
    "0.1.124.2.0.0.3.1.0.1.3.0.0.0.0.1.0.0": "4672fa903df6cc21dc3346b4da1dc5b12e042c454ac6db26bbec9b9b238c2af0",  # PipelineAst
    "0.1.124.2.0.0.3.1.0.1.5.0.0.1.0.0.0": "f88bd83d50cc12916ded86eb7d9d6b41cf9923ca76c26b22e96276e6a8272a16",  # PipelineAst
    "0.1.124.2.0.1.0.0": "97dee6db860ca54aa8190f59b1121efd4386ab971ccc00c95406c2c456231ade",  # AssignmentStatementAst
    "0.1.124.2.0.1.0.0.1.0.0.0.0": "fccd21123de402420b76e4933dc0edc8ed989081a9e3f5eff18a463e40368f5d",  # PipelineAst
    "0.1.125": "81cd9e937ffe421d4814178521454261b2fb90e6432b12137ec62729678b6490",  # PipelineAst
    "0.1.125.0.3.0.0.0": "7449e107e8da03bb8b60c9eea36631e57ecd12a348cb9d66c0fb554c8f81d609",  # PipelineAst
    "0.1.126": "52da2cdd3adc924af05fb474fda0f09a7de18385381b4ef3a708a1d57024315a",  # AssignmentStatementAst
    "0.1.127": "289a115e3415aa32711857f0b92993c481eeeca792eb086a26b30d8d06ef7cb9",  # ForEachStatementAst
    "0.1.127.1.0.0.0.0": "e13b109e7b68d5db9c455f35f2323c38103103283d08822dd166aa62baf0adde",  # PipelineAst
    "0.1.127.1.0.0.0.0.0.0.0.0.0": "d957d8758a0b3d43c6755c8da749df215718782daedbc5c9a42cd70c0d83224d",  # PipelineAst
    "0.1.127.1.0.0.0.0.0.0.1.0.0": "cb11e9f93980107319497f240b973f85f575e68a8c80ad3982d0c607e36e2c0b",  # PipelineAst
    "0.1.127.1.0.0.0.0.0.0.2.0.0": "4f5bbb3ffc678d243ce0ab9bd6911a9916abcbcbc5a71e0be231e6460a4b54d2",  # PipelineAst
    "0.1.127.1.0.0.0.0.0.0.3.0.0": "f56f660b89defac4e1560cac490698b5a61bb1a025088eb884e1bd3eb6c42269",  # PipelineAst
    "0.1.127.1.0.0.0.0.0.0.4.0.0": "9083e4ff6a03b344311d0577dd3c329c970e251d6fa5e039b84ceb69b01e7352",  # PipelineAst
    "0.1.127.1.0.0.0.0.0.0.5.0.0": "3a0d4538e78d4a158fd5e2a5b9ae1d6ae849c7168d409adc564e8467ccea9f5d",  # PipelineAst
    "0.1.127.2.0": "046f379f5f6ebba0b44a1f9c5678f2c1d8387b4ceb2fb62328d9c75458cff266",  # AssignmentStatementAst
    "0.1.127.2.1": "a9f11548610e1b824bfe3ae0aaf3664e049a56569b3e45cf2f295cc820484682",  # IfStatementAst
    "0.1.127.2.1.1.0": "5061ceb336732fa9ec49c6b9eb3b8212001860370fc1228d142fc86964ffadfa",  # AssignmentStatementAst
    "0.1.127.2.1.2.0": "e27e8311d582a96f37bec888d11020a20a46108be0593008d8517d1d28589843",  # AssignmentStatementAst
    "0.1.128": "bf59753684d4a33c230dc3b37cc93383912c9b8545afee75240b9c82817ff742",  # AssignmentStatementAst
    "0.1.129": "12cb1761174d2351cb8394207fd3c27aef3e2b725554928148e78921e8fe25f1",  # AssignmentStatementAst
    "0.1.130": "85d85ad04057b09ece5c189110114360f61a90f59f72902e30cb9c8e88cfe8e9",  # AssignmentStatementAst
    "0.1.131": "3864665d20a338b88be87ae1c0cf1da0b26dcad354e2ad26125aeaac171614bd",  # AssignmentStatementAst
    "0.1.132": "3da5edbbda65f7e4607098e8260ab98de1b5408eb82c9f8e716b609f22769f44",  # AssignmentStatementAst
    "0.1.133": "a4a5917f55bfe69340b432212aa1dbf36fcca4e4eb4466388faa8ddc3936cfb1",  # ForEachStatementAst
    "0.1.133.1.0.0.0.0": "9189a4292960a933fd5e27e317cf5e616e7beabac0b7c7336aa2e65d2709987d",  # PipelineAst
    "0.1.133.2.0": "6e19e2bb3da1baa537f9218d0c88beb60e9c24d6348c76c655dbbde48529b0b2",  # IfStatementAst
    "0.1.133.2.0.1.0": "60293712c384c6773ffaa2645931df1c112693eaf30e51548b0fce838ffcd018",  # AssignmentStatementAst
    "0.1.134": "567c781894ad0d4fa90f9814c91c67100e7c5759d006dc250edbb5714c3ada10",  # AssignmentStatementAst
    "0.1.134.1.0.0.0": "577d1e79b92720f5a03d5caa54fbf60d0ff5b8e81c1d9d5e9491cbda735c17a5",  # PipelineAst
    "0.1.135": "01ef4bff2599e9e0d29d7a40d6e9d7d3ee685ae125cca95dfbcab2f24d0fe337",  # ForEachStatementAst
    "0.1.135.2.0": "09c7a3e1c9ee12a51f3036e9cd075815a5ec892a71f8337fcf82d91b3f537e46",  # AssignmentStatementAst
    "0.1.135.2.1": "a5279761bbe67b0391cb587ebdd37d88e5efcc1b004118684d361ff415576170",  # IfStatementAst
    "0.1.135.2.1.1.0": "a5c0730e5e744f74f10870bf10863c2526a2d5711a9a0c76f0684a36a1fad9d5",  # AssignmentStatementAst
    "0.1.135.2.1.2.0": "c13f98e784353008c6599e38ee1bee7bf26d276cf5278dad9af67fd905cdf5fa",  # AssignmentStatementAst
    "0.1.136": "356ed8754a9f08fa4c959d5312872d54bc6264a0cbbc3b3170c2a13df85a4025",  # AssignmentStatementAst
    "0.1.136.1.0.3.0.0.0.0": "e27104046134c17d1d7fd1bed3fc5cbed269c7dda377b0e6ebb0ac88bcb7eef6",  # IfStatementAst
    "0.1.136.1.0.3.0.0.0.0.1.0": "88cdf728795379ab1ecf5a967096f8c50e15d6f8b013cec9d57cdc719bf2cd25",  # PipelineAst
    "0.1.136.1.0.3.0.0.0.0.2.0": "7125ca0f0282680b08cca4ae4fb548486575bce361bb77c3436798ddfd86c73b",  # PipelineAst
    "0.1.137": "bd68cf5bd8ecf33675a84e51ed8b162383568df4179807568a4b1fb0475bb3c1",  # PipelineAst
    "0.1.137.0.5.0.0.0.0.0.0.0": "194436adb0d5900b65ec166258e87ee995313576078c92882d36e8539a06d75d",  # PipelineAst
    "0.1.137.0.5.0.0.0.0.1.0.0": "62f9e1864ebecf1e83e483c4a1a3c9ada7dd9d602cc7d567cb72ffc26cc4893b",  # PipelineAst
    "0.1.138": "2dc5eb16888e96ad1940af638828920090a0f28ff751c576ffdbf2a5a22b5339",  # AssignmentStatementAst
    "0.1.139": "bfffd7569467fbd264462ed1386df1696fe921bc125f052eef034e248176bb55",  # AssignmentStatementAst
    "0.1.140": "6e3e7626424ccafbd9a4fb6eda8497d952b20029df08f76b3c2e594efa195762",  # ForEachStatementAst
    "0.1.140.2.0": "8e343c754d5cbdc865a6cf01831efe0af14f7acd56228d9d3e532b010429d148",  # AssignmentStatementAst
    "0.1.140.2.1": "90628626d58b7ab0decbada1271e20c4631dbdd500eef18b5328cd9a6cd6b64d",  # IfStatementAst
    "0.1.140.2.1.1.0": "34eda3043225d0e666415b8fb64d9c3a06807762f148f25ba2766f068309be08",  # AssignmentStatementAst
    "0.1.140.2.2": "06ba0f86aa6552a459d82dd107cf7776c653869fad93a06a0d0b3682536c6ecb",  # AssignmentStatementAst
    "0.1.140.2.3": "d30a1f7f32b76bdee21db1374f6536990790e37af6b0b32d1eefe197f143393c",  # IfStatementAst
    "0.1.140.2.3.1.0": "9726b51a753bbb08aff1f41f555ef8dfb7920e6c9d800b213bdad807621b8f64",  # AssignmentStatementAst
    "0.1.141": "25726af35758e3d0e0e561aaa99750f14fae3f0364910b1dbfe3fdb68d66f16e",  # AssignmentStatementAst
    "0.1.142": "785b75181d096167fcfa4d7a8e9d5ee37bdbfff91d29517eb589042c409f2b4c",  # AssignmentStatementAst
    "0.1.143": "fa772b4f28a9cbb5bf44c517a85ced3415b9ec799b2d189d5e968863a58f9ccd",  # AssignmentStatementAst
    "0.1.144": "dc9abd18f04e5536df918627017c88aee24e71e037fcd182a10b680ed924f8fb",  # TryStatementAst
    "0.1.144.0.0": "645ab9b0fe886c77b279cb53729f7298d6c09ed5478f6a4c4eb10795a1f8a6ce",  # AssignmentStatementAst
    "0.1.144.0.1": "e21290b9a9f5359c6adaadf40fa7b20fc37972c36074a1ccb451c19d697e1b25",  # PipelineAst
    "0.1.144.0.2": "fa1fcb124e7a79129ada3745a16ef58d11a8f4ac4fbd3b8233b79119d02b81bd",  # AssignmentStatementAst
    "0.1.144.0.3": "a964d54499214cc294fc9aa02fbaf590f0cf4a5f5acb109f61c71c27841f403b",  # AssignmentStatementAst
    "0.1.144.0.3.1.0.3.0.0": "ac7ab60c3b2794d465ebce3c97f50137c1b0cc9d7d55829ba9e101c2c6cc4d4c",  # PipelineAst
    "0.1.144.0.4": "a71e652784117f4cb545556c13cf3cba9b7397829cbda143cf9de12f62ccf65a",  # AssignmentStatementAst
    "0.1.144.0.5": "636e6d61c3d01b1d0ae4e0fafb8795553455e56afeea73c30839d13e5059ee3a",  # AssignmentStatementAst
    "0.1.144.0.6": "5a11dc32ee0508964e8857d66b9eb0fc4ad4eeb6bd5811fcef3bf766207c8ef9",  # ForEachStatementAst
    "0.1.144.0.6.2.0": "251e6f0e3e23fa602d65c5194634fe20208885ae496bf354eae023a3b06ff916",  # TryStatementAst
    "0.1.144.0.6.2.0.0.0": "e0683fb2e0d2d0adc9f680101f1b35f062838d31078691ff120a05256f92dc0f",  # AssignmentStatementAst
    "0.1.144.0.6.2.0.0.1": "3b5a210441a9e5c045f9dfab4ff8fdc06666d9e8d3c8c4d912694fbc627ee537",  # AssignmentStatementAst
    "0.1.144.0.6.2.0.0.2": "b3e2d1f53efce4092c965d64edccfef0bad6c0cdd8cd38742a974140f7948c77",  # AssignmentStatementAst
    "0.1.144.0.6.2.0.0.2.1.0.1.0.0.0": "3ec832534aff8f41ab4848d0c3e057aba9334b1547e0231972642d9f29683c61",  # PipelineAst
    "0.1.144.0.6.2.0.0.3": "4a5290f25065ace11d2be86ed5edab77a26a1744cf4c165b88fedad2550c9171",  # AssignmentStatementAst
    "0.1.144.0.6.2.0.0.4": "7d3474f0931f884083cdce30ad4910dc723b1f6284f814f0935700c1a2d7d3f3",  # ForEachStatementAst
    "0.1.144.0.6.2.0.0.4.1.0.0.0.0": "6683da40271aab45be09e8440342a7392ae4281b6dbc300f660023c8ff02d34d",  # PipelineAst
    "0.1.144.0.6.2.0.0.4.2.0": "1e353e970953db32c506ddc99ddd6d9831c7adf88e227658e062f3b3b857fff9",  # AssignmentStatementAst
    "0.1.144.0.6.2.0.0.4.2.1": "a0b6b1901a20059a556cd2005943664032358d8ff24533540eb438b64a94e7ad",  # AssignmentStatementAst
    "0.1.144.0.6.2.0.0.4.2.2": "d97e03cbfc53fc73bbbdac15dfc7656df66b35fc03ef05f4fa70c0e931e096d3",  # IfStatementAst
    "0.1.144.0.6.2.0.0.4.2.2.1.0": "c72ae8c4a2197333ef3f07073282df417d7596cc6142540eef488515de52f5b6",  # ThrowStatementAst
    "0.1.144.0.6.2.0.0.4.2.3": "2f68620075cf470c0e8eb68995b2071375cf530696b6310cf4dc427f2accb8cd",  # AssignmentStatementAst
    "0.1.144.0.6.2.0.0.4.2.3.1.0.0.0.0": "47e79d34335771980dc923ab826cfe87a21340836028979732ce825578d652bc",  # PipelineAst
    "0.1.144.0.6.2.0.0.5": "efc43e795f2d0411465b8d9ba8cdcc32e4839be8dab3854f5a81c0a608adae6a",  # ForEachStatementAst
    "0.1.144.0.6.2.0.0.5.2.0": "a08b34ebf16c19fbc8f99016d9eb9f763032d7a3862918cdc371c65d2d321c77",  # AssignmentStatementAst
    "0.1.144.0.6.2.0.0.5.2.1": "6a361d3f184f7f1687daecad914339ebb700638c5c7b73aa0c3f0517beb3b7ec",  # AssignmentStatementAst
    "0.1.144.0.6.2.0.0.5.2.2": "68168f2b267c26343e06f3ac041a63b1a8e9d7a47c4d2b1ff3302e5bfc311551",  # PipelineAst
    "0.1.144.0.6.2.0.0.5.2.3": "ac2d360ee5c3cc825d500e271921d98ed7f16262d566593cf1c15684420eb53d",  # AssignmentStatementAst
    "0.1.144.0.6.2.0.0.5.2.4": "2c5b2a06ccfff17166a3c4c5194d9273a051a8d469a36d0d3fa4a00a9740bfee",  # PipelineAst
    "0.1.144.0.6.2.0.0.5.2.5": "1cb318957bb6d8cbbc2e8a1e70f2a523eaaf7e5bfe02cfe7ca5e3ef60e0d5038",  # PipelineAst
    "0.1.144.0.6.2.0.0.5.2.6": "276f273ebad87cea98d5c2996e57fcd0552ab77f823442ff5323a6f22da76038",  # PipelineAst
    "0.1.144.0.6.2.0.0.5.2.7": "5bf290e9beed8f02b6ccc73723289baf32a17be781a590bdf8a8027568b3ad3e",  # AssignmentStatementAst
    "0.1.144.0.6.2.0.0.6": "95679163670132a0eae0f1da89ea96a40c8e9c5730adf2dcdc22b09583595ba6",  # PipelineAst
    "0.1.144.0.6.2.0.1.0.0": "7f0fc844de912e6bf991811fc0242b27f9c12bff5c6fbd0ad05b0e53ced4af0c",  # AssignmentStatementAst
    "0.1.144.0.6.2.0.1.0.0.1.0.0.0.0": "f492144ab76ee4ee2df678c45a3372a5f9143702fe864c312f84a807888c0716",  # PipelineAst
    "0.1.144.0.7": "db5d1c6921b27c463b80608a6a1ba616172bdf1acb899e50c27c49281e04b0c6",  # AssignmentStatementAst
    "0.1.144.0.8": "c88b09dd1943a516f59fe5577c125c23012ba8d310806581eb3197e760b0851f",  # AssignmentStatementAst
    "0.1.144.0.8.1.0.3.0.0": "52f5e484307096ada7bcbe18643c4364255f1d15658852c11c73030f88b615e0",  # PipelineAst
    "0.1.144.0.9": "2342c08bad535e2d4e31c8a60c6a3d8f7623527218644fb77333b8d76e23e7f7",  # AssignmentStatementAst
    "0.1.144.0.10": "e5816940e0554c19037ee84bb837a4ee8febb69e935a24cf303fb2613f213bed",  # AssignmentStatementAst
    "0.1.144.0.11": "b1003e5ef87d43214ff99180d1d0bc2cb842956ba32acb73f897d3870cefbadf",  # ForEachStatementAst
    "0.1.144.0.11.2.0": "0fbcbcae361cfec3609d98eeb73ee593b422f523d9352bcaf432a82f451cbc0d",  # TryStatementAst
    "0.1.144.0.11.2.0.0.0": "55715ae76b7805dc1cb34c51869996975de12e00fdd4e75e369dc6904d03168f",  # AssignmentStatementAst
    "0.1.144.0.11.2.0.0.1": "cc83f093d431d82353abbe3c9cc99a5aa2659f4e09383d2939cf48923625426c",  # AssignmentStatementAst
    "0.1.144.0.11.2.0.0.2": "092a94badd26d5e854c9b70c1447418fc0169ba6b6f6453a38d2fc5b1acce331",  # AssignmentStatementAst
    "0.1.144.0.11.2.0.0.2.1.0.1.0.0.0": "89ef39e7911b2eeb56acd0dd53ec5eea6771e9a88568ad23852d03c19cc23f03",  # PipelineAst
    "0.1.144.0.11.2.0.0.3": "9fc885ee2968850d69ca43de837cf5baa32219af75008c1f66deb17b9d8bb7b9",  # IfStatementAst
    "0.1.144.0.11.2.0.0.3.0.0.0.0.0.0.0": "3938d7d1099e1f3b3a614450156060b69156e27c30187ac002a8d83e045ffccb",  # PipelineAst
    "0.1.144.0.11.2.0.0.3.1.0": "53622ee061ab5a581a0f425355e95b83717faf9dd27a37e23c5b1521c5bbb0a3",  # PipelineAst
    "0.1.144.0.11.2.0.0.3.1.1": "bfe616e035b112cc1c4eb90b8ab23cfd9e5e06a2b6091306ca97c490d11c1ed8",  # ContinueStatementAst
    "0.1.144.0.11.2.0.0.4": "a48d9ede93a452dad113f9b39135e39101c4cca36ee6620abe1dc5735abe681e",  # AssignmentStatementAst
    "0.1.144.0.11.2.0.0.4.1.0.1.0.0.0": "90f36ce5f89a9530f2839aeaff6ef0390e16b488be2b0c749631e0cd3338008c",  # PipelineAst
    "0.1.144.0.11.2.0.0.5": "6424679693485cfe9372f1ccf1338d7531b145c7aed1a5a902cb1ec921d065fc",  # PipelineAst
    "0.1.144.0.11.2.0.0.6": "cf28f54c81dddfdcedc13a36554a4d2ff74ec88335bdbec5cae02034a66cfc63",  # AssignmentStatementAst
    "0.1.144.0.11.2.0.0.7": "5306d189851214b2c5ca0f76c054b8835f7dc87f8301875f5ac8663968e68245",  # PipelineAst
    "0.1.144.0.11.2.0.0.8": "0bc7388dc19a68db94600ef8ee637e3d027824824d079b18d1873e1daae6432e",  # PipelineAst
    "0.1.144.0.11.2.0.0.9": "4b39065f3abf62ebe4323e68a66f03e9d0e9dd00b53cc9c354a2dc1b613f87c2",  # PipelineAst
    "0.1.144.0.11.2.0.0.10": "7d52491db38dcc4f546786f100b48865dc559e8f9035cd8817866a2b053905be",  # AssignmentStatementAst
    "0.1.144.0.11.2.0.0.10.1.0.1.1.0.0.0.0.1.0.0": "3afb95e79d7f53f83e2fcc0fce5a16e99f50de632f5dc033904ae79626a19842",  # PipelineAst
    "0.1.144.0.11.2.0.0.10.1.0.1.7.0.0.0.0.0": "51d200cd1d6d7706864b0e8886e133ae382530d54504597acd1de78e078a9563",  # PipelineAst
    "0.1.144.0.11.2.0.0.10.1.0.1.7.0.0.0.0.0.0.0.1.0.0.0": "44db4b358fa0a8db15efba46fc35cd0c330598ec075fe1c7b970cf6aa3a017f8",  # PipelineAst
    "0.1.144.0.11.2.0.0.11": "96a799891a720270e2fefc0d97e85aae54d3c58f117e1418257a9102457f6a8c",  # PipelineAst
    "0.1.144.0.11.2.0.1.0.0": "6042740878a25c1bab2c4e959913a6266398187377e48f84c6986ff6cb481f54",  # AssignmentStatementAst
    "0.1.144.0.11.2.0.1.0.0.1.0.0.0.0": "de6bd05f3fe9fd461f8cbe93207d82402b2e4f38e37477a8210a7876f24fdc2a",  # PipelineAst
    "0.1.144.0.12": "c787357b354e3daaa476a778d5e4b53fab53adf433db11aba3f22b1349630c97",  # IfStatementAst
    "0.1.144.0.12.1.0": "7a1489f0898a1eca622078ec97db3efcaafd26e0c7cc87dcb71ba09361735157",  # AssignmentStatementAst
    "0.1.144.0.13": "6a8895a70942fe12cb75521df01c7eea97a35d82fefec91529517753f5670600",  # PipelineAst
    "0.1.144.0.13.0.3.0.0.0": "b0547f2a5e84260495d6f0c7c9d0e7f447a69169a37501ca5e45d4fa361ad868",  # PipelineAst
    "0.1.144.0.14": "a2aed24df543f8e22d4f91187af6d3ef7c1889e7103d0bc47bb52feac228c726",  # PipelineAst
    "0.1.144.0.14.0.3.0.0.0": "0691ffe74a3492367fea404f5e6bed19ee8545f480edbf709f32b8ac18f495c0",  # PipelineAst
    "0.1.144.1.0.0": "7fffbc6f50591d23bf89e2b871930182adf10bf31d15602915b3207e378ef5a2",  # PipelineAst
    "0.1.144.1.0.0.0.1.0.0.0": "28e036662483a30db5656032fdb64e98f7ca9817e873faf82879122ca78a78b2",  # PipelineAst
    "0.1.145": "ed12edacb3a75d7f105a7a016a6ac4245c2f04e9fd7b78a5afa267ebeadd9066",  # AssignmentStatementAst
    "0.1.146": "5ccc067f9e9db7f2a777630a2209f9f9a0de0f835612811a41f7a5f88cf3f798",  # IfStatementAst
    "0.1.146.1.0": "9ea271b0ea90e98743202a84fdf0b5b5aa9c97a5d8870d6d73bff30fef96bcdc",  # AssignmentStatementAst
    "0.1.147": "35b00f629fa15c42f3a5399df5cb79b8e526523d8786ffbdc2047c7957ab2869",  # IfStatementAst
    "0.1.147.1.0": "84dd669615c9003f4497fadca7df4ce3b047561fdfe66d665740a5c43f691bdc",  # AssignmentStatementAst
    "0.1.148": "18cdc3a744d08630e4cf4fa70741066ebb1c5b93ec7ef5071340f1364d4349ba",  # IfStatementAst
    "0.1.148.1.0": "d700d9c6d7084cd74ff13f68a9e33cab717b39e2c57b43028366fbcc16e6a18d",  # AssignmentStatementAst
    "0.1.148.1.0.1.0.0.0.0": "56966a5f8d56e8c26e1d5530247dc5ad706fc05fb03acc4ad6656444a433f20c",  # PipelineAst
    "0.1.149": "334459548400ed9257b270ed2a1c5a0ec70c829308be8f1f480c513b3135d585",  # IfStatementAst
    "0.1.149.1.0": "d9494fc94821e4fbacd2d3b1dd4b68a2c94b1ffa5efbff04186fa2e07dd993ba",  # AssignmentStatementAst
    "0.1.149.1.0.1.0.0.0.0": "c1d21cced19647b254422a9907cd5bf938cdd88a0a8fed117b0f72ce56a030de",  # PipelineAst
    "0.1.150": "604d703d9433d36d9b0a2ea5a321b5e9362c951ac89512e019596b3cc88035c0",  # AssignmentStatementAst
    "0.1.151": "6cb7c1a5e12ab6a24a788e7042cb899dd44cf1ccc9415252aafa6ac31d816543",  # AssignmentStatementAst
    "0.1.152": "84f8aa6fbb2bef5eef4389a925d84f80b85cd0b00158380983876221f1049f17",  # TryStatementAst
    "0.1.152.0.0": "daa0bd5b769f853e21a418f7d7709d1e69773b5bd7f798fb6812cf5d8f74da95",  # PipelineAst
    "0.1.152.0.1": "206bd06f866a81382d1908e9102bf2705505ffacf98f9da406849a48331d0369",  # AssignmentStatementAst
    "0.1.153": "3e2c5782e1a328320c31fadf581d9065388c28fec8ddc2a8fa698bf19b1b93fe",  # IfStatementAst
    "0.1.153.1.0": "e795f5ff1adf16daf09039fafe459d4820bbd7be92fbdc7634db73fbe9685f5a",  # AssignmentStatementAst
    "0.1.153.1.1": "29985cb489b4e935183e6517b6abdec9e622b21f779cdde2f239cdea1f28dc6c",  # AssignmentStatementAst
    "0.1.153.1.2": "c939d0187332feafdb1c1ef591c59d3f0af7a4d5d5cf623d5a8e0d036a7290b5",  # AssignmentStatementAst
    "0.1.153.1.3": "c2e6f4f9d2809ebad9e017255e3e5bc4cb421f5a1c36aa68e9f6073a4473cd7b",  # TryStatementAst
    "0.1.153.1.3.0.0": "f8085a250cb82e2cd2589d4abb78a18f8c3120521cee00a8c64a7258064ddc2c",  # ForEachStatementAst
    "0.1.153.1.3.0.0.2.0": "5f3dd40e16447194041458d57fbdc61190a81f76792a0e4009505a2c603fb585",  # AssignmentStatementAst
    "0.1.153.1.3.0.0.2.1": "3a5e23877476e537b853902ef4bf13e83d93c94be79e0cec754774496acc7d99",  # ForEachStatementAst
    "0.1.153.1.3.0.0.2.1.2.0": "180da060fcf09400fff1b22ceb3369ce90bef23cc390e6662c0c2508278ea88c",  # IfStatementAst
    "0.1.153.1.3.0.0.2.1.2.0.1.0": "b1f33b69bc64ebb826898fcfd4278369f21ecaa329faa0315fa7cd4c8487e6b1",  # AssignmentStatementAst
    "0.1.153.1.3.0.0.2.2": "c4b552af50683fb20ff4fd5b608ece8e70ea014a7ffa33dcd7dab392c527ee48",  # ForEachStatementAst
    "0.1.153.1.3.0.0.2.2.2.0": "b112ccf7e2e2b2bf970338bedb6fb29974866e24d063d7886750dc0098875bef",  # AssignmentStatementAst
    "0.1.153.1.3.0.0.2.2.2.1": "98640334a714e3d44573eff1a0cd9fdb0a79c356033754b8dc0deec3504f674c",  # IfStatementAst
    "0.1.153.1.3.0.0.2.2.2.1.1.0": "d62ff6c02383f50e6a355c6aef37d9856a9509af15883b8db9d565479a6dbc1e",  # AssignmentStatementAst
    "0.1.153.1.3.0.0.2.2.2.1.1.0.1.0.0.0.0": "54b1fc41f1bf8c1f31cbb53143cf9e5aca2b9c6091e8212b4236b07836b63e56",  # PipelineAst
    "0.1.153.1.3.0.0.2.2.2.1.1.1": "b5aeb3b492fc328ced719debfe894676a5bffb2062daacf625e9630fe49d7a72",  # ContinueStatementAst
    "0.1.153.1.3.0.0.2.2.2.2": "fde0a95d9a973694f04803fc2f1bfa2efcb08faed62e3e5e41a9b18a197eb292",  # AssignmentStatementAst
    "0.1.153.1.3.0.0.2.2.2.3": "b0477a24bd987e37ce99c534005dbacc8a5289a44a9ba3cffeba7961f2a30647",  # AssignmentStatementAst
    "0.1.153.1.3.0.0.2.2.2.4": "ac79ed3a3cc88ee2eb36d3754e2e9f22f77ddaa54a0b89436a8fc78b70250bde",  # IfStatementAst
    "0.1.153.1.3.0.0.2.2.2.4.1.0": "a2eb5b24b6f9f4a55ea3fa917e5c1df5ed5f0f5e522bf7a8e188942b183adaec",  # AssignmentStatementAst
    "0.1.153.1.3.0.0.2.2.2.4.1.0.1.0.0.0": "a9bb6d12d2100531997d187e04e9c2487306ea1cb3c8cbf4af7545bb8b64bf5a",  # PipelineAst
    "0.1.153.1.3.0.0.2.2.2.5": "042570f4a93b96b8b56cec1fbeb395b8a2a83ab1ded2f9b5f4210ea85c231be0",  # IfStatementAst
    "0.1.153.1.3.0.0.2.2.2.5.1.0": "b92cc7f2287e5fa533c1ca30e811600d3b97bd50779a17fa5b2d6a0177a47f98",  # ContinueStatementAst
    "0.1.153.1.3.0.0.2.2.2.6": "97cedcf8053907293bf6e97c6ef8789cf56fa8426d6c64f4c0d2e2d99da6afcf",  # AssignmentStatementAst
    "0.1.153.1.3.0.0.2.2.2.6.1.0.0.0.0.0": "654b7eb874b260850f4e9e63316e2ce714c16564e325fe9535fc3a2a8dfba9d0",  # PipelineAst
    "0.1.153.1.3.0.0.2.2.2.7": "46110ff7cec57b83e38b73d020811836842a94b3e3edd739e7093554d10f73cd",  # AssignmentStatementAst
    "0.1.153.1.3.0.0.2.2.2.7.1.0.0.0.0": "094aee5f35060344e2a2160c3a41f01eaadac8dfdb38a4242e3613bab3d202ff",  # PipelineAst
    "0.1.153.1.3.0.0.2.2.2.8": "72f9d13ad69f2d38e5e53867b410a2b5167cda73d918241fc351c3efb7ec3b48",  # AssignmentStatementAst
    "0.1.153.1.3.0.0.2.2.2.9": "dc92d048c3ad59a0df6a8d9b663d6fe3927197622b16971ea7d8dd68513a4b26",  # AssignmentStatementAst
    "0.1.153.1.3.0.0.2.2.2.10": "056c3b162f011bdb88ecffc95548502b94688bf03f1ff428557831c18d159ff6",  # AssignmentStatementAst
    "0.1.153.1.3.0.0.2.2.2.11": "80263490326aef06eeaf1d059733c7354353ca93611ea4dd735a105ccc2b39de",  # AssignmentStatementAst
    "0.1.153.1.3.0.0.2.2.2.12": "cd54466cfab675291562cb1e9936afe106938961a9af123bed8ff69ffbef816c",  # AssignmentStatementAst
    "0.1.153.1.3.0.0.2.2.2.13": "9b3e1cfe41217ccc9893c0dbbbf681eec24cdb9e2bda7a27d074ab22dd9bd11e",  # AssignmentStatementAst
    "0.1.153.1.3.0.0.2.2.2.14": "f9c82a692b8dc6ff6425999e13535ad56a000481eb1506ed8e51ca1a90fde848",  # AssignmentStatementAst
    "0.1.153.1.3.0.0.2.2.2.15": "0ac52b374565e916eca6a18d8ac0b0f1bd8e9188612c14ea674169d2de3e8082",  # IfStatementAst
    "0.1.153.1.3.0.0.2.2.2.15.1.0": "5258e9ede734a64801ad193b31e0e45aeac67f3f173a8eaab39cb03ecd2ddafc",  # AssignmentStatementAst
    "0.1.153.1.3.0.0.2.2.2.16": "4dd83d5bd0180c084570ef6fe6f7742a6fc22553df4ebe438de23febe941d795",  # IfStatementAst
    "0.1.153.1.3.0.0.2.2.2.16.1.0": "a68f2d6361fc987eff3ca1a45c955a293686367d626cdeeaf29ce84ade6e5367",  # AssignmentStatementAst
    "0.1.153.1.3.0.0.2.2.2.17": "d58efe3d676e99c6aebab9717d9ad83bf70c05daf7b91f51c88506bdb068787c",  # IfStatementAst
    "0.1.153.1.3.0.0.2.2.2.17.1.0": "876c3bd983ca2f7bbfd9ce3cf9cf39747654f35e78ae0d1370346bcfad4af6c1",  # AssignmentStatementAst
    "0.1.153.1.3.0.0.2.2.2.18": "f2d899a2b8f9e2ef79f5f280045a917007cc39ed16dd3dc513e82b3ad6c45331",  # AssignmentStatementAst
    "0.1.153.1.3.0.0.2.2.2.19": "7e5e98d1ddc4dd5f96733af647632289db896d600d71f693480e464e2f931f43",  # AssignmentStatementAst
    "0.1.153.1.3.0.0.2.2.2.20": "db2831ffdd348d6938755fe11ecd155f001879623b0d65ec633def3abe0a8d1b",  # AssignmentStatementAst
    "0.1.153.1.3.0.0.2.2.2.21": "b455365056afc7e59dd3b0879d2b417aee910509a926b1059f374edd80728aae",  # AssignmentStatementAst
    "0.1.153.1.3.0.0.2.2.2.22": "5d09bb05feaa62b546deb9e658c3662be13e4bc670ecfa04290235c0f7e4cbb6",  # IfStatementAst
    "0.1.153.1.3.0.0.2.2.2.22.1.0": "133f23eba7450bd7453fc298e232111787936c137a96bafb1fe61732f593b642",  # AssignmentStatementAst
    "0.1.153.1.3.0.0.2.2.2.22.2.0": "5ba1b3498bba98d8f2f3d311eb201f6f0a378d162bc880e9f7876f59fa9a9fd1",  # AssignmentStatementAst
    "0.1.153.1.3.0.0.2.2.2.22.2.0.1.0.1.0.0": "1dbee8dcca1638dc4e7bd6b9ba97e4243e4d0d0025c2b67993094a77f68cccb2",  # PipelineAst
    "0.1.153.1.3.0.0.2.2.2.22.2.0.1.0.1.0.0.0.0.0.0.0": "e473d77f22566c71627dd45dbf5ebba85882eb58cdc845327e21bbf8807b7023",  # PipelineAst
    "0.1.153.1.3.0.0.2.2.2.22.2.0.1.0.2.0.0": "49755f2caf3aa3b371c122748409325907817cfe1660c2cf55f2d896e7278625",  # PipelineAst
    "0.1.153.1.3.0.0.2.2.2.22.2.0.1.0.2.0.0.0.0.0.0.0": "ee15c719940f839e50903c4423d216dbf8730652ffb17ed18028b3fe056468c7",  # PipelineAst
    "0.1.153.1.3.0.0.2.2.2.23": "1309787c0ce8761df26df00dfa12a2e37685952441f6f46a98e1f3e10321a645",  # AssignmentStatementAst
    "0.1.153.1.3.1.0.0": "e4f1b6088bb6d63b3fb8048cf37fb08516392f1b3ce9aaed64799a971331fcaf",  # AssignmentStatementAst
    "0.1.153.1.3.1.0.1": "8e8a0aafbe51e501298da05b940c630fd4e294a805876ef554f0cb6aca11c92e",  # AssignmentStatementAst
    "0.1.153.1.3.1.0.1.1.0.0.0.0": "a632bb61ff0653a7f806c8718fefadaf0954a2242251ec330c7047d4c7cf324b",  # PipelineAst
    "0.1.153.1.3.1.0.2": "13065389ede7af5c99475e6146045206a6d1d02180425caa676472edbc6916f7",  # PipelineAst
    "0.1.153.1.4": "20ea34126ad1f2fd3eef729be7361fb9b6084a30a00e8ab4a1a29c04ceaffdcf",  # AssignmentStatementAst
    "0.1.153.1.4.1.0.0.0.0.0.0.0.0": "f9d20147bd7b4c547f28a753d6a812ee03ae59378e8b03818c5276f02ec8c9c6",  # PipelineAst
    "0.1.153.1.4.1.0.0.0.1.1.0.0.0": "95fc72cfeab9b355f03105c4c0a1287752e88e0a48883c805686e0e253139b49",  # PipelineAst
    "0.1.153.1.5": "1dd37d6dd22cb98cf0096b1e88e8ab6f077fb7f51c0fae9acfa30eb92b65bfbf",  # AssignmentStatementAst
    "0.1.154": "b99adea39b47ffc155706bba8da378bb56ce53bb014cfe2680184b7e0913e3b7",  # AssignmentStatementAst
    "0.1.155": "5048de2ccc5055b7cb80342f63fae72879ef21aa54f763f47f86ebf69361f290",  # AssignmentStatementAst
    "0.1.156": "5831574965ccc1b01967c8a3ae68750608c8295c508ff1cca6ea1600d1a32dfb",  # AssignmentStatementAst
    "0.1.157": "6e7c8aaba3881801b8ec6b85ce4a75b00afabaf0843c4973c4b8d1e7b9716bc8",  # AssignmentStatementAst
    "0.1.158": "b39f8896b67fbadf1d68b11d7929f82579b4973201004191b3b5964703934643",  # IfStatementAst
    "0.1.158.1.0": "fc7a2183efc426ea211d2996e083c0b63135309e7455962833aef4211c222316",  # AssignmentStatementAst
    "0.1.158.1.1": "637f88230cd440586989a0a9afb7c11eafa4cd5b2dee29bfcbb99b3e8affff4b",  # TryStatementAst
    "0.1.158.1.1.0.0": "0a08496247801fc9bc12bfcf9fc8ce2d4769dffc16ae618a4062dc4937f2b705",  # AssignmentStatementAst
    "0.1.158.1.1.0.0.1.0.3.0.0": "d669dadedc49440b839caa0b3cbf19c25aa317642ef1982ead36fe2feec2871b",  # PipelineAst
    "0.1.158.1.1.0.1": "817e0c32a007da97e92465e658554cfaaa07f5477f4a2d9207644158fe035348",  # AssignmentStatementAst
    "0.1.158.1.1.0.2": "107344cf8329250f9dc15dbb3bc110351fc6680e83e397af8fddd3f40a6372ed",  # ForEachStatementAst
    "0.1.158.1.1.0.2.2.0": "18a812bcbfa6f6009d04dc323db52dfa53bd66783ca500d23d6386581f66d759",  # TryStatementAst
    "0.1.158.1.1.0.2.2.0.0.0": "bcbf96f469f7698ea8ac5712c8fe43248b5c998ee0ab3f058ca30e67567cc8fd",  # AssignmentStatementAst
    "0.1.158.1.1.0.2.2.0.0.1": "d893b710cb99e4a1778cb8b3c9451b1be13e100082fad70561b34b82a0207cde",  # AssignmentStatementAst
    "0.1.158.1.1.0.2.2.0.0.2": "c2cdd1e427d344dd98b677129479cdc3508fbde1d9cb02e5ffd7368097f85de2",  # AssignmentStatementAst
    "0.1.158.1.1.0.2.2.0.0.2.1.0.1.1.0.0.1.0.0.0": "306c133f5c5ab635eca907383aad41441063904606af2bfe58193217f7c583f6",  # PipelineAst
    "0.1.158.1.1.0.2.2.0.0.2.1.0.1.3.0.0.0.0.1.0.0": "61a9b61fcc6020bc7442d199da2a1e9430284682979d039fc1558adcf0d140b2",  # PipelineAst
    "0.1.158.1.1.0.2.2.0.0.2.1.0.1.5.0.0.0.0.0.0.0": "6fa714d36812289436636f83e8abf3fe3df78f037f361b44cb17ecd6742ce8d5",  # PipelineAst
    "0.1.158.1.1.0.2.2.0.0.2.1.0.1.5.0.0.0.0.0.0.0.1.1.0.0.0": "403150dc56611d00b661d613eea21c65298d493f8364efec549a072f1e9911c3",  # PipelineAst
    "0.1.158.1.1.0.2.2.0.1.0.0": "070def326ca8e4cf0098cccdce02f71e6b4be0606c623aae5ae5a2967ba1b7ac",  # AssignmentStatementAst
    "0.1.158.1.1.0.2.2.0.1.0.0.1.0.0.0.0": "14ceca84960976b0fdbfe3bf28214c6b370b17c468195d515311bd4d7756bb6a",  # PipelineAst
    "0.1.158.1.1.0.3": "79e3aed264780bd367e62e090736c53ddc8f9e0aa4dace437826a279dd294b6b",  # AssignmentStatementAst
    "0.1.158.1.1.0.4": "366cb40e05c4713efc619e75eee47d1322fd9773e65083fe65d239bbc369019d",  # PipelineAst
    "0.1.158.1.1.0.4.0.3.0.0.0": "80c20f8358cfd1719aa8385c41b8798e48b9af874d7200fd6db1171c4f66c356",  # PipelineAst
    "0.1.158.1.1.1.0.0": "807b7b564f73b2b378d9817be3bf096fa3aa41d7b225443d6435ae3c5e6255be",  # PipelineAst
    "0.1.158.1.1.1.0.0.0.1.0.0.0": "63deeed8df9832c8a0c9cc8554cb3a29e558597e00339f9272bfb7b462fc4ce4",  # PipelineAst
    "0.1.158.1.2": "ff5147b6fcad2f0d094cb1c6ac27fa9aa2376fa425761c4a538fcb738978c4bd",  # AssignmentStatementAst
    "0.1.158.1.3": "c86fc0001efe35a1d9f3b29923c6a6fed09998a0349e0881783eb9c237b1d8b4",  # AssignmentStatementAst
    "0.1.158.1.4": "3fc58fd66bfb466d296da16c6f350631de8f07f87d233132e8e430a7c747dcf9",  # IfStatementAst
    "0.1.158.1.4.1.0": "32d0ad86b480a4f422e8863b0c9f30f2dd71219d0cd69be49b1422a18400dd38",  # AssignmentStatementAst
    "0.1.158.1.5": "9209ed41373164f7cc746e086cced6c0dd24343d661488a3ac7776d28fa51610",  # AssignmentStatementAst
    "0.1.158.1.5.1.0.3.0.0": "40a982b2acfcc9aef5269535e416fdb90302df65900c3cff7e59087d8091c63c",  # PipelineAst
    "0.1.158.1.6": "c338b428444c965d438d58ad53d82bf77610edea9ed786060c16076b39796690",  # AssignmentStatementAst
    "0.1.158.1.7": "d1e96231fadb6774705e8cc448bed2b879dfa170ed8f72cbc77ec79e97cb5968",  # ForEachStatementAst
    "0.1.158.1.7.2.0": "18e36f5a9a0d6a3707e7bd304031a4e926af369e27e0b2ac0f87aa7a9801ad0e",  # TryStatementAst
    "0.1.158.1.7.2.0.0.0": "e5d5f18675cd08b0e54c60b9705217a924a7ab5c8c1e410ac9cc8ede3d8dfcec",  # AssignmentStatementAst
    "0.1.158.1.7.2.0.0.1": "31a071de014b9d5d9de14fd28950a0cc9134d12cbd9048d55ed7bdaa9ee40ece",  # AssignmentStatementAst
    "0.1.158.1.7.2.0.0.2": "984f9bbeb783b54fbe884353f15722c521da60133c8b656f341efd5fe7607371",  # AssignmentStatementAst
    "0.1.158.1.7.2.0.0.2.1.0.1.0.0.0": "86d20b106663e71d2b7341f645427a0705ea39eb2fa45c24dec4ada166b7e2af",  # PipelineAst
    "0.1.158.1.7.2.0.0.3": "e591ed395774d25d0bdd4f535d383d1f943e2953105bc648304ba44e4f48a39a",  # AssignmentStatementAst
    "0.1.158.1.7.2.0.0.3.1.0.1.0.0": "96868221db4b3cb06e1e41d1a00a99825a8cb9a34a284693391b2a53890d1a81",  # PipelineAst
    "0.1.158.1.7.2.0.0.4": "db7d61e303b150e4a3b2fa91e484b7830a8300c76366707507b2d95affcb04d7",  # AssignmentStatementAst
    "0.1.158.1.7.2.0.0.5": "f343c9601d33a641d1d450f92f13cb0d53a0f0376794e440929975ec2af7c9f0",  # AssignmentStatementAst
    "0.1.158.1.7.2.0.0.6": "59ffda9601b8c7c22a28affb2033d3fc51beec886f7f1d0edc9ed9482f560644",  # AssignmentStatementAst
    "0.1.158.1.7.2.0.0.7": "96810023acd2c8a122a69989c573456c6f9fd2fced9cb9ed2e79c04665c60674",  # AssignmentStatementAst
    "0.1.158.1.7.2.0.0.8": "3329a4553d83a2d736cf86316279201388c363534c55f6ae7410fb5f8e08c4d9",  # IfStatementAst
    "0.1.158.1.7.2.0.0.8.1.0": "2509ca1fb484b64de4a69b63eda82fb9361f18e43b6178604c1aacfc6fa8d3f6",  # AssignmentStatementAst
    "0.1.158.1.7.2.0.0.8.1.0.1.0.1.0.0.0": "d51ebd81d51f7c1b33f22f0c258784338654253f7e44de3406131535b5e1778b",  # PipelineAst
    "0.1.158.1.7.2.0.0.8.1.1": "ccd3e5b11e8c02c3761d38b61f9f8c1e495488ad37bc4096a4e2182270d7d41d",  # PipelineAst
    "0.1.158.1.7.2.0.0.8.2.0": "fd663808165cc2d93257f4b17f9a84b761fcdb1f0243960ee8c6787de19f3bdc",  # TryStatementAst
    "0.1.158.1.7.2.0.0.8.2.0.0.0": "0cc08db31fe3a178b2b024bf8e3b3a87603362a39d8f5f8eb532194b7f4318e6",  # IfStatementAst
    "0.1.158.1.7.2.0.0.8.2.0.0.0.1.0": "cbcdb328ff732f5fc31d92d750ba8ccab825f3e16ad29d531281322015ada1bc",  # AssignmentStatementAst
    "0.1.158.1.7.2.0.0.8.2.0.0.0.3.0": "bb55acad774932b3d183cd5a5408dac1c798ab22f6e866b0e1fa4636e9b9d23c",  # AssignmentStatementAst
    "0.1.158.1.7.2.0.0.8.2.0.0.0.4.0": "b319f3151bf8b3ace46c502d429585b9c52beb81aa317f72c4d601f4a3640e62",  # AssignmentStatementAst
    "0.1.158.1.7.2.0.0.8.2.0.0.1": "657df8e55e79e2d9bddd033c550f7ec9124472254ef32c3d24528c1fff9c8488",  # AssignmentStatementAst
    "0.1.158.1.7.2.0.0.8.2.0.0.2": "9a83c6405792c1d1187e6a0cd7329923ba301ae97407a0d76cc097e6de19353b",  # SwitchStatementAst
    "0.1.158.1.7.2.0.0.8.2.0.0.2.2.0": "883fd8eb0098668ba82e4dcd0c4ef9e5cc5b94324a8917b941f5e993601ef665",  # AssignmentStatementAst
    "0.1.158.1.7.2.0.0.8.2.0.0.2.2.1": "cd1d8ce7b66935ea1fcaa4a6498eb739e4343175b33472babae1f4f7b3f115c8",  # AssignmentStatementAst
    "0.1.158.1.7.2.0.0.8.2.0.0.2.4.0": "e5ef97fc979eb73b896decf203ee5c45c58c5c5153065bdd7accc29f4baed5d2",  # AssignmentStatementAst
    "0.1.158.1.7.2.0.0.8.2.0.0.3": "1ee73bc5e8289dc7e84f89540824438b244759127b944575872d53738f422a88",  # AssignmentStatementAst
    "0.1.158.1.7.2.0.0.8.2.0.0.4": "417ac4faa0bffa5bbc52302ef470424ef5ea431de2fc2142f89b0c8e446ce5d1",  # SwitchStatementAst
    "0.1.158.1.7.2.0.0.8.2.0.0.4.2.0": "ce9e2f2c50ed036aa44aabaef772a6b08cc8797daf3240d8a4c5bd6fa36da00a",  # AssignmentStatementAst
    "0.1.158.1.7.2.0.0.8.2.0.0.4.2.1": "b77c3cf7a2ccf13bed10afda2d1ce43baa12668a2c3b4488c929fb4dc28a948a",  # AssignmentStatementAst
    "0.1.158.1.7.2.0.0.8.2.0.0.4.4.0": "b7b430d3ccb216784823622bfdfc954a478a1aff5fe87100a1aed6ee9391c2b7",  # AssignmentStatementAst
    "0.1.158.1.7.2.0.0.8.2.0.1.0.0": "b23a55c3680b8539d7f13fc5b57b16be391b3cd654a6e9ba9d43ad60cdc0eda0",  # PipelineAst
    "0.1.158.1.7.2.0.0.8.2.0.1.0.0.0.1.1.0.0": "6ba2ad2d33379378f3719095a4a77712f31fb158639a4d702a9b3a2e9cab1124",  # PipelineAst
    "0.1.158.1.7.2.0.0.9": "1097822ae7a4815a58f8d6438e0644331b8919716599ff7eeeb736292aa3b4cd",  # AssignmentStatementAst
    "0.1.158.1.7.2.0.1.0.0": "d551e189268ab5cae9894dafa40eb1b7aab6b5b0586a766108cea5822146182f",  # AssignmentStatementAst
    "0.1.158.1.7.2.0.1.0.0.1.0.0.0.0": "018e03a3f37e5ccac8fa8a104128888f98ae1f3189bd02d6ad9d7d1948f3444b",  # PipelineAst
    "0.1.158.1.8": "1fb6842b659f7bc2249879f4e64b2bcf014f90ab4a34bcb967a1d115447d45a7",  # AssignmentStatementAst
    "0.1.158.1.8.1.0.0.0.0": "bf1893e6b55ce1bf24f339a76d4d2aca74648aee4924d734b87ad2f2fed3ba68",  # PipelineAst
    "0.1.158.1.8.1.0.0.0.0.1.1.0.0.0": "1d67c178b4f91b571090f6546569933081e3f3839f3478d30840e8aed157dafe",  # PipelineAst
    "0.1.158.1.9": "ee819634fcb4c0c86cb4e209123ac76ce5b6a5a3e9292b84d51d9803f8478254",  # IfStatementAst
    "0.1.158.1.9.1.0": "cf921c563d3fbc89172bac5b3a75685c440250aad4b1a9e35f929d8b5e9157fc",  # PipelineAst
    "0.1.158.1.9.1.0.0.1.0.0.0": "09927d64263aee44bce5e675989acd8378935758e58560b2031886e45c5a278f",  # PipelineAst
    "0.1.158.1.9.1.1": "d221baacc6d25aba31944706c2228f4f5898142a7732994156201cd9a2f1b85a",  # AssignmentStatementAst
    "0.1.158.1.9.2.0": "2dba005fcd11efa0b805ef565acf9399aa3c7edca66bb9f89bcf4f8b228041a8",  # AssignmentStatementAst
    "0.1.158.1.9.2.1": "2d082b07320ea6ecf6de6188f2ce097983ba5ecbc9e40d8b2d296859536fc790",  # PipelineAst
    "0.1.158.1.9.2.1.0.3.0.0.0": "1d88424221d79c5ef040687f45c4bab61b2f539808bddb3e58d7baa22ae23939",  # PipelineAst
    "0.1.159": "d0488f84c3d162ffce028b66e12b5d5b6f6d6aec5159fca80be86d994d22b1b4",  # AssignmentStatementAst
    "0.1.160": "f5c4b3b39052d13df308bfd0388a461d7d9ca23b1beff4ca38fc4c584496aa98",  # AssignmentStatementAst
    "0.1.160.1.0.1.0.0.0": "bfcb61c1fdaa187b9239dd73add0a2fd0d7b4b687b0c45f5ffb08bfa9e8df739",  # PipelineAst
    "0.1.160.1.0.3.0.0": "c6234b1be2818ca2d281517ae18596d18f7136001fbcae02a90e8289df5de295",  # PipelineAst
    "0.1.161": "1fedc19adbb62c9dc8aed966c680233be0c08fdf03aeac387be6d86fd13f93b4",  # IfStatementAst
    "0.1.161.0.0.0.1.0.0.0.0": "2fa9e3cfff64a229c9684b1aa48a6613558bce76c15dab153a0f104ef3bd7672",  # PipelineAst
    "0.1.161.1.0": "6437d798ca5ae4067bf3119bcdfe127df1706029864fbbaf416102c2206c0a99",  # AssignmentStatementAst
    "0.1.161.1.0.1.0.0.0": "2f294620bf646dd744a971da7c01f113d0fe15f069d75a2c80aabd59acc376d3",  # PipelineAst
    "0.1.161.1.0.1.0.0.0.0.1.0.0.1.0.0.0": "6d211fb083c6d53772d723abcc8d07df924add6f7e46268257e5acce629209d8",  # PipelineAst
    "0.1.161.1.1": "07391525f925d6f4b68872134360e0b6527089685e8da2b7a8f30a19cbcdabf9",  # IfStatementAst
    "0.1.161.1.1.1.0": "aff07be1e89524f03b4840d65d7b9f06a7f3c614d3c48ef77e98c6d804b318d9",  # AssignmentStatementAst
    "0.1.161.1.1.3.0": "a913798fcb640b90176fa30b7c7289f15d8170841a2a04a84aab98a84068b5a1",  # AssignmentStatementAst
    "0.1.162": "b075b48ea67c12e978c731733627eb7d462f604d23216226799d1cebc8d8669a",  # AssignmentStatementAst
    "0.1.163": "17511eff98c22f10ba266a7ec0ae53fdfeed3a478ad4ac117468a06863b547bd",  # IfStatementAst
    "0.1.163.1.0": "db25312f770372edd1c0adcb37869600039282cf0ac4d5ba78ce535a52dd296b",  # AssignmentStatementAst
    "0.1.164": "25dd5cb0c005b461350af2a2c84f1d38c2d34f74ef64cf1ad72d5323d656faa1",  # IfStatementAst
    "0.1.164.1.0": "9fcf402ef51af8d496a3cd398945cf197056d966297974fa4e7a1a4af862f8f0",  # AssignmentStatementAst
    "0.1.165": "6c2a5ae877d6c96929bb0c52c7adac80b18ebefa35a2c0b678f43f0ed17279d6",  # IfStatementAst
    "0.1.165.1.0": "4b37b9395d24d076078058c4b31d6ed56aef390357ca6a3f47e6cabf37780565",  # AssignmentStatementAst
    "0.1.166": "344819d0d59674083dbf30c159b4eea0a8efc28661f21fc6e2745b2bc6b34741",  # IfStatementAst
    "0.1.166.1.0": "5bca0cb9ab42f4c8fcff785160ea8dbb00a7d2a434a83202139bc006b7c3fe30",  # AssignmentStatementAst
    "0.1.167": "5b24ce1d289c9ca6afff8bf79e7979490ddffacdcaccd972aeb8be713940cf3b",  # IfStatementAst
    "0.1.167.1.0": "4e68e99a39ddbd949f7384cab22dfa50e99ef54e69b97d73ed9819c57d0e0b6a",  # AssignmentStatementAst
    "0.1.168": "b0c173e471f8f5b81c21f4149755a90d46af65852a4837081a76264e0f54cd07",  # AssignmentStatementAst
    "0.1.168.1.0.1.13.0.0.0.0.0.0.0": "354e09b5d5d9f93bd6735a75a58ff56489bbf26a108e5c92450d0743fc79a535",  # PipelineAst
    "0.1.169": "0486ada50eac4f18812def5849da4589fce22146640b22983779e8aaa8bc28d1",  # PipelineAst
    "0.1.169.0.1.0.0": "de8ee4c1a04ba9c76c3292e8b951062f1bcb40aae0094daae40385c9d2ec1b4b",  # PipelineAst
    "0.1.170": "d5d34a1640f21fd7fdaf0d72989b0ba86fc4aea33d82a99e7784754f2fae132f",  # PipelineAst
    "0.1.170.0.1.0.0": "3ec8683512c8906ea4431bcc0889df1127c641b64e2cb5929dd2080de638efb0",  # PipelineAst
    "0.1.171": "c466370f068cf0265e294a7206c211f37aba1531b5bd46c013a833085497bb6a",  # PipelineAst
    "0.1.171.0.1.0.0": "01fd3963a892d74a8f7a82b22d87c3eb6442a2d428a7b22528bf021aae0cad70",  # PipelineAst
    "0.1.172": "bbe85221644143bd43378b67c309caf02d5ed62cded22e3cdb787148e15928d9",  # PipelineAst
    "0.1.172.0.1.0.0": "2185ddec0edc01999d188d4df59408cc141253bef635cc9968142be621590a3a",  # PipelineAst
    "0.1.173": "5d9c34ca06c0991733e4df6fe6048c571de81991b97a1fd71a25ca5bfe42a293",  # PipelineAst
    "0.1.173.0.1.0.0": "53e91011e8a6d53c679615095824ad6568566f3f3972ac51433210e295819855",  # PipelineAst
    "0.1.174": "569be69c2ced24cdf889ef6201795b4b68cd7f7c9c1e3884cd4d61c3cf16e1af",  # PipelineAst
    "0.1.174.0.1.0.0": "a9b83e28eb2b43bf49443ad56d25edbf18b5cc1e808b7c5b916de11cd6f18e2d",  # PipelineAst
    "0.1.175": "5358be4aee1719a064edf6ee30f984bbabefed089d290236ece296e657a27178",  # PipelineAst
    "0.1.175.0.1.0.0": "cfcf3bac6586064a94cfce68dbcfc024f9686f4f4a115131fc22585929a947d9",  # PipelineAst
    "0.1.176": "cc81a74c17d5b9563eb0a8ad20ff4d851b96795c8b336405bd1e381aac95751a",  # PipelineAst
    "0.1.177": "afd91315ed66ff8707bb81e8ae1fa15d7637de3105b531db5a4b5d5aa165bd40",  # PipelineAst
    "0.1.178": "34f4f537b6ef7ed308bda94d70494e9bdf9813448a94e20394737167a6b08674",  # IfStatementAst
    "0.1.178.1.0": "22afc8aa1ecd05fe67d01c25e066eae35443199759d46a2b73a7e49878323563",  # PipelineAst
    "0.1.178.1.0.0.1.0.0.0.1.1.0.0.0.0": "11b0a7e35746d4e17fdb8dd150fcd263ab2e5a7977df5c3a94e4602218b6e123",  # PipelineAst
    "0.1.178.1.0.0.1.0.0.0.1.3.0.0.0.0": "09cffbd9c002064e8d5a058770ea24184de61097084e8543788afacbd67c18c2",  # PipelineAst
    "0.1.179": "21e3fca17efea731dc54b8376a0fcc0d0ea103ab708a774c05ccdd06c53beb67",  # PipelineAst
    "0.1.180": "26830483714cdba93e3a9444cecdbf12b904975a2fec9e326cfbdce11cda211e",  # PipelineAst
    "0.1.180.0.1.0.0.0.1.9.0.0.0.0.0.0.0.0.0": "2594746dff5ce001de0e26f760acc9f758e9229002c400156e7a279ce54916cf",  # PipelineAst
    "0.1.180.0.1.0.0.0.1.9.0.0.0.0.0.1.1.0.0.0": "2021ab4772d34be72e5ea552cee373e7de554d3b912b3c560f90aa06f40b46cb",  # PipelineAst
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
    ("[Convert]", "toint64", "$text", "10"),
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
    # input of _sameNames: _sameNames $appProvs $hostProvs
    "<script>::appprovs": [
        ("assign Equals", "_iisProviders $pr.appRead"),
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
    # read by a binding of $<script>::dcconfigs
    "<script>::bindingraw": [
        ("assign Equals", "$null"),
        ("assign Equals", "[int]$kdc.uValue"),
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
            "[ordered]@{ name = $dcDns object_guid = $dcGuid strong_certificate_binding_enforcement = $binding schannel_mapping_methods = (_list $schannelMethods) # The raw DWORDs (collector >= 0.12.0): null when not set or not read. strong_certificate_binding_enforcement_raw = $bindingRaw schannel_mapping_methods_raw = $schannelRaw }",
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
    # read by a binding of $<script>::manifest
    "<script>::dsheuristics": [
        ("assign Equals", "$null"),
        ("assign Equals", "''"),
        ("assign Equals", "[string]$dsValues[0]"),
    ],
    # input of _v: _v (_entryProps @($dsRead.entries)[0]) 'dsheuristics'
    "<script>::dsread": [
        (
            "assign Equals",
            "_search \"CN=Directory Service,CN=Windows NT,CN=Services,$($rootDse.config)\" '(objectClass=*)' @('dsheuristics') -Scope Base",
        ),
    ],
    # condition $dsValues.Count -eq 0
    "<script>::dsvalues": [
        ("assign Equals", "@(_v (_entryProps @($dsRead.entries)[0]) 'dsheuristics')"),
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
    # input of _sameNames: _sameNames $appProvs $hostProvs
    "<script>::hostprovs": [
        ("assign Equals", "_iisProviders $pr.apphostRead"),
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
            "\"$appPath windowsAuthentication providers not obtained: application-path [$(@($appProvs) -join ', ')], applicationHost location [$(@($hostProvs) -join ', ')]\"",
        ),
        ("assign PlusEquals", "\"IIS application under '$($site.Name)' has no readable path\""),
        (
            "assign PlusEquals",
            '_iisWhy "$appPath extendedProtection tokenChecking" $tc (_epaToken $tc.app) (_epaToken $tc.apphost)',
        ),
        (
            "assign PlusEquals",
            '_iisWhy "$appPath sslFlags" $ssl (_sslRequiredFrom $ssl.app) (_sslRequiredFrom $ssl.apphost)',
        ),
        (
            "assign PlusEquals",
            '_iisWhy "$appPath windowsAuthentication enabled" $wa (_iisBool $wa.app) (_iisBool $wa.apphost)',
        ),
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
            "[ordered]@{ collector_version = $COLLECTOR_VERSION collected_at = (Get-Date).ToUniversalTime().ToString('o') host = [string](hostname) host_fqdn = $localFqdn domain = $rootDse.domain ds_heuristics = $dsHeuristics skipped_passes = (@($skippedPasses)) enumeration = $enumeration }",
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
    # input of _iisProviders: _iisProviders $pr.appRead
    "<script>::pr": [
        ("assign Equals", "_iisRead $ps $loc \"$auth/providers\" 'Collection'"),
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
        ("assign Equals", "$appProvs"),
        ("assign Equals", "$null"),
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
    # input of _search: _search "CN=Directory Service,CN=Windows NT,CN=Services,$($rootDse.config)" '(objectClass=*)' @('dsheuristics') -Scope Base
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
    # read by a binding of $<script>::dcconfigs
    "<script>::schannelraw": [
        ("assign Equals", "$null"),
        ("assign Equals", "[int]$sch.uValue"),
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
            "[ordered]@{ name = [string]@(_v $p 'cn')[0] object_guid = (_guidHex @(_v $p 'objectguid')) display_name = [string]@(_v $p 'displayname')[0] schema_version = if (@(_v $p 'mspki-template-schema-version').Count) { [int]@(_v $p 'mspki-template-schema-version')[0] } else { 1 } oid = [string]@(_v $p 'mspki-cert-template-oid')[0] ekus = (@(_v $p 'pkiextendedkeyusage' | ForEach-Object { [string]$_ })) name_flags = (_decode $nf $NAME_FLAGS) enrollment_flags = (_decode $ef $ENROLL_FLAGS) # The raw values too (collector >= 0.12.0, review round 2): the core # decodes them with its own tables. name_flags_raw = $nf enrollment_flags_raw = $ef min_key_size = if (@(_v $p 'mspki-minimal-key-size').Count) { [int]@(_v $p 'mspki-minimal-key-size')[0] } else { $null } ra_signatures = $ra # authorized signatures required; null if not obtained issuance_policy_oids = (@(_v $p 'mspki-certificate-policy' | ForEach-Object { [string]$_ })) csp = (($csps -join ', ').ToLower()) security = $sec.aces # template DACL -> ACEs (ESC1/ESC4); null if not obtained acl_obtained = ($null -ne $sec.aces) # SD requested, returned and parsed owner_sid = $sec.owner }",
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
        ("arg", "@($dsRead.entries)[0]"),
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
        ("arg", "$tc.app"),
        ("arg", "$tc.apphost"),
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
        ("arg", "$wa.app"),
        ("arg", "$wa.apphost"),
        ("arg", "$wa.apphost"),
        ("parameter", "$v"),
    ],
    # argument of .ToInt64(): [Convert]::ToInt64($text, 10)
    "_iisinteger::text": [
        ("assign Equals", "[string]$v"),
    ],
    # condition $null -eq $v -or $v -is [string] -or $v -is [bool]
    "_iisinteger::v": [
        ("arg", "$inner"),
        ("arg", "$v"),
        ("arg", "$v"),
        ("parameter", "$v"),
    ],
    # condition $p.value
    "_iisproviders::p": [
        ("foreach", "@($read.value)"),
    ],
    # condition $null -eq $read -or -not $read.ok
    "_iisproviders::read": [
        ("arg", "$pr.appRead"),
        ("arg", "$pr.apphostRead"),
        ("parameter", "$read"),
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
        ("arg", '"$auth/providers"'),
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
        ("arg", "$loc"),
        ("parameter", "[string]$loc"),
    ],
    # input of _tryRead: _tryRead { Get-WebConfigurationProperty -PSPath $ps -Filter $filter -Name $name -ErrorAction Stop }
    "_iisread::name": [
        ("arg", "'Collection'"),
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
        ("arg", "$ps"),
        ("parameter", "[string]$ps"),
    ],
    # input of _iisInteger: _iisInteger $inner
    "_iisscalar::inner": [
        ("assign Equals", "$v.Value"),
    ],
    # condition $items.Count -ne 1 -or $null -eq $items[0]
    "_iisscalar::items": [
        ("assign Equals", "@($read.value)"),
    ],
    # condition $null -ne $n
    "_iisscalar::n": [
        ("assign Equals", "_iisInteger $inner"),
        ("assign Equals", "_iisInteger $v"),
    ],
    # condition $null -eq $read -or -not $read.ok
    "_iisscalar::read": [
        ("arg", "$app"),
        ("arg", "$apphost"),
        ("parameter", "$read"),
    ],
    # input of _iisInteger: _iisInteger $v
    "_iisscalar::v": [
        ("assign Equals", "$items[0]"),
    ],
    # condition @(@('application-path', $read.appRead, $read.app, $app), @('applicationHost location', $read.apphostRead, $read.apphost, $apphost))
    "_iiswhy::app": [
        ("arg", "(_epaToken $tc.app)"),
        ("arg", "(_iisBool $wa.app)"),
        ("arg", "(_sslRequiredFrom $ssl.app)"),
        ("parameter", "$app"),
    ],
    # condition @(@('application-path', $read.appRead, $read.app, $app), @('applicationHost location', $read.apphostRead, $read.apphost, $apphost))
    "_iiswhy::apphost": [
        ("arg", "(_epaToken $tc.apphost)"),
        ("arg", "(_iisBool $wa.apphost)"),
        ("arg", "(_sslRequiredFrom $ssl.apphost)"),
        ("parameter", "$apphost"),
    ],
    # parameter of _iisWhy, called by a binding of $<script>::iisfailures
    "_iiswhy::label": [
        ("arg", '"$appPath extendedProtection tokenChecking"'),
        ("arg", '"$appPath sslFlags"'),
        ("arg", '"$appPath windowsAuthentication enabled"'),
        ("parameter", "[string]$label"),
    ],
    # condition @(@('application-path', $read.appRead, $read.app, $app), @('applicationHost location', $read.apphostRead, $read.apphost, $apphost))
    "_iiswhy::read": [
        ("arg", "$ssl"),
        ("arg", "$tc"),
        ("arg", "$wa"),
        ("parameter", "$read"),
    ],
    # condition $null -eq $scope[1] -or -not $scope[1].ok
    "_iiswhy::scope": [
        (
            "foreach",
            "@(@('application-path', $read.appRead, $read.app, $app), @('applicationHost location', $read.apphostRead, $read.apphost, $apphost))",
        ),
    ],
    # condition -not $why
    "_iiswhy::why": [
        ("assign Equals", "@()"),
        ("assign PlusEquals", '"the $($scope[0]) read failed"'),
        ("assign PlusEquals", '"the $($scope[0]) read returned no single value of a known shape"'),
        (
            "assign PlusEquals",
            "\"the $($scope[0]) value '$($scope[2])' is not one this collector decodes\"",
        ),
        (
            "assign PlusEquals",
            "\"the scopes disagree: application-path '$($read.app)', applicationHost location '$($read.apphost)'\"",
        ),
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
    # parameter of _epaToken, called by a binding of $_iiswhy::apphost
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
    # parameter of _iisRead, called by a binding of $<script>::pr
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
    # parameter of _iisRead, called by a binding of $<script>::pr
    "_safefilename::name": [
        ("arg", "$cn"),
        ("arg", "$cn"),
        ("parameter", "[string]$name"),
    ],
    # condition @($a).Count -ne @($b).Count
    "_samenames::a": [
        ("arg", "$appProvs"),
        ("parameter", "$a"),
    ],
    # condition @($a).Count -ne @($b).Count
    "_samenames::b": [
        ("arg", "$hostProvs"),
        ("parameter", "$b"),
    ],
    # input of Where-Object: Where-Object { $_ -eq $providerName }
    "_samenames::providername": [
        ("foreach", "@($a) + @($b)"),
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
        ("arg", "@('dsheuristics')"),
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
        ("arg", '"CN=Directory Service,CN=Windows NT,CN=Services,$($rootDse.config)"'),
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
    # condition $null -ne $n
    "_sslrequiredfrom::n": [
        ("assign Equals", "_iisInteger $v"),
        ("foreach", "$names"),
    ],
    # condition $names -contains 'None' -and $names.Count -ne 1
    "_sslrequiredfrom::names": [
        ("assign Equals", "@(([string]$v) -split '\\s*,\\s*')"),
    ],
    # condition $ssl128 -and -not $ssl
    "_sslrequiredfrom::ssl": [
        ("assign Equals", "$names -contains 'Ssl'"),
        ("assign Equals", "($n -band 8) -ne 0"),
    ],
    # condition $ssl128 -and -not $ssl
    "_sslrequiredfrom::ssl128": [
        ("assign Equals", "$names -contains 'Ssl128'"),
        ("assign Equals", "($n -band 256) -ne 0"),
    ],
    # input of _iisInteger: _iisInteger $v
    "_sslrequiredfrom::v": [
        ("arg", "$ssl.app"),
        ("arg", "$ssl.app"),
        ("arg", "$ssl.apphost"),
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
        ("arg", "'dsheuristics'"),
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
        ("arg", "(_entryProps @($dsRead.entries)[0])"),
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
        "_iisInteger $v",
        (
            "function _iisScalar",
            "guard if ($null -eq $read -or -not $read.ok) -> return",
            "guard if ($items.Count -ne 1 -or $null -eq $items[0]) -> return",
            "guard if ($v -is [string] -or $v -is [bool]) -> return",
        ),
    ),
    (
        "_iisInteger $inner",
        (
            "function _iisScalar",
            "guard if ($null -eq $read -or -not $read.ok) -> return",
            "guard if ($items.Count -ne 1 -or $null -eq $items[0]) -> return",
            "guard if ($v -is [string] -or $v -is [bool]) -> return",
            "guard if ($null -ne $n) -> return",
            "if ($v.PSObject.Properties['Value']) after []",
            "guard if ($inner -is [string] -or $inner -is [bool]) -> return",
        ),
    ),
    (
        "_iisInteger $v",
        ("function _sslRequiredFrom", "guard if ($null -eq $v -or $v -is [bool]) -> return"),
    ),
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
        "Where-Object { $_ -eq $providerName }",
        (
            "function _sameNames",
            "guard if (@($a).Count -ne @($b).Count) -> return",
            "foreach ($providerName in @($a) + @($b))",
            "if-condition after []",
        ),
    ),
    (
        "Where-Object { $_ -eq $providerName }",
        (
            "function _sameNames",
            "guard if (@($a).Count -ne @($b).Count) -> return",
            "foreach ($providerName in @($a) + @($b))",
            "if-condition after []",
        ),
    ),
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
        '_iisWhy "$appPath windowsAuthentication enabled" $wa (_iisBool $wa.app) (_iisBool $wa.apphost)',
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "if (-not $endpointsSkipped) after []",
            "try",
            "foreach ($site in (Get-Website -ErrorAction Stop))",
            "foreach ($app in (Get-WebApplication -Site $site.Name -ErrorAction Stop))",
            "guard if (-not $appPath) -> continue",
            "guard if (-not $kind) -> continue",
            "if ($null -eq $windowsAuth) after []",
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
            "if ($null -eq $windowsAuth) after []",
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
            "if ($null -eq $windowsAuth) after []",
        ),
    ),
    (
        '_iisWhy "$appPath extendedProtection tokenChecking" $tc (_epaToken $tc.app) (_epaToken $tc.apphost)',
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "if (-not $endpointsSkipped) after []",
            "try",
            "foreach ($site in (Get-Website -ErrorAction Stop))",
            "foreach ($app in (Get-WebApplication -Site $site.Name -ErrorAction Stop))",
            "guard if (-not $appPath) -> continue",
            "guard if (-not $kind) -> continue",
            "if ($null -eq $epa) after []",
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
            "if ($null -eq $epa) after []",
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
            "if ($null -eq $epa) after []",
        ),
    ),
    (
        '_iisWhy "$appPath sslFlags" $ssl (_sslRequiredFrom $ssl.app) (_sslRequiredFrom $ssl.apphost)',
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "if (-not $endpointsSkipped) after []",
            "try",
            "foreach ($site in (Get-Website -ErrorAction Stop))",
            "foreach ($app in (Get-WebApplication -Site $site.Name -ErrorAction Stop))",
            "guard if (-not $appPath) -> continue",
            "guard if (-not $kind) -> continue",
            "if ($null -eq $sslRequired) after []",
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
            "if ($null -eq $sslRequired) after []",
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
            "if ($null -eq $sslRequired) after []",
        ),
    ),
    (
        "_iisRead $ps $loc \"$auth/providers\" 'Collection'",
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
        "_iisProviders $pr.appRead",
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
        "_iisProviders $pr.apphostRead",
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
        "_sameNames $appProvs $hostProvs",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "if (-not $endpointsSkipped) after []",
            "try",
            "foreach ($site in (Get-Website -ErrorAction Stop))",
            "foreach ($app in (Get-WebApplication -Site $site.Name -ErrorAction Stop))",
            "guard if (-not $appPath) -> continue",
            "guard if (-not $kind) -> continue",
            "if-condition after []",
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
        "_search \"CN=Directory Service,CN=Windows NT,CN=Services,$($rootDse.config)\" '(objectClass=*)' @('dsheuristics') -Scope Base",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
        ),
    ),
    (
        "_v (_entryProps @($dsRead.entries)[0]) 'dsheuristics'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "if ($dsRead.complete -and @($dsRead.entries).Count -eq 1) after []",
        ),
    ),
    (
        "_entryProps @($dsRead.entries)[0]",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "guard Assert-AdcsOutputPath $OutDir",
            "if ($dsRead.complete -and @($dsRead.entries).Count -eq 1) after []",
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
