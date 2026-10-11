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
  .CommitChanges``, ``.Properties[...].Add``): not allowlisted. ``Add`` is
  allowed only on ``DirectorySearcher.PropertiesToLoad`` (a query projection).
* CA config writes: every ``certutil`` invocation must be ``certutil -getreg ...``.
* Registry writes: ``OpenSubKey`` only with the 1-argument (read-only)
  overload; WMI only as ``Get-WmiObject -Class StdRegProv -List`` + ``GetDWORDValue``.
* Remote execution (``Invoke-Command``, ``Invoke-Expression``,
  ``Start-Process``, ``& $computed``, dot-sourcing): not allowlisted; a command
  whose name is computed at runtime, or invoked with ``.``, is a violation.
* **Local file writes only into the output directory**: each write target is
  one of a fixed set of path expressions, and every variable those
  expressions read is PINNED (below).
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
* **Redirections**: the only one allowed is ``2>$null``.
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
    "0.1.0": "84fb118238fe0a771fe3cbedde88c065353aee2d2810acb981e04b4b0ac66917",  # AssignmentStatementAst
    "0.1.1": "5f667464b41116e7386a299d20ba6321f79e2228b8c9fb67012bbedadedd9648",  # AssignmentStatementAst
    "0.1.2": "1a49ce34adf7351da0f78da93e8477388acc4c231637732fd92ca64bea4fd5d9",  # FunctionDefinitionAst
    "0.1.2.1.0.0": "20a1d6bfd33669dd1597a40e940b378ec84dfa5d83e0751fda9ea164b84ca4ef",  # PipelineAst
    "0.1.3": "c619af9bc124ebc0e651caa4b33f3b6f11386e214c15f45c9ff01f8df506bcee",  # FunctionDefinitionAst
    "0.1.3.1.0.0": "fa857985d3a09ff1198f46b1d7d098ad18177e8deeb737faa7f5a1ee4763b4ea",  # IfStatementAst
    "0.1.3.1.0.0.1.0": "d8f1d542dcaa67c72f743349995f2a38d05b2bddbfb1cc82446184dd39b77473",  # ReturnStatementAst
    "0.1.3.1.0.1": "74a7b7fa8c4f820ae35c5cad9713fe0e5e5a416d1b13d57b8de570538c75a473",  # AssignmentStatementAst
    "0.1.3.1.0.2": "be5e545b5fb2c4936ea67e2cda5b1a0a18b40c533041597134d7336d9eec25e8",  # IfStatementAst
    "0.1.3.1.0.2.1.0": "d8f1d542dcaa67c72f743349995f2a38d05b2bddbfb1cc82446184dd39b77473",  # ReturnStatementAst
    "0.1.3.1.0.3": "3af2c38e2bc39c560e5b3549bd9b172a31f53829116beaccf368761374925972",  # PipelineAst
    "0.1.3.1.0.3.0.0.0.0.0.0.0.1.1.0.0.0": "2fe2cf7b005d4d1b1a4b7351c8bd5e90e894fa314e502ccec7736bfcbb79325f",  # PipelineAst
    "0.1.4": "3342470dfce0fa18c7b9c9947b6a77ac9dcc7394f79a9f762ccc41931b777258",  # FunctionDefinitionAst
    "0.1.4.2.0.0": "55ebf6e0bf5780e1d59589aff5f6ff1652c795f9c9c6a58b247312309ee91426",  # AssignmentStatementAst
    "0.1.4.2.0.1": "41db3dec17a8718aeec53e5a67087ad6accf6bd1d16688225ff8862f1ed209cb",  # AssignmentStatementAst
    "0.1.4.2.0.2": "13ed17f2f16dceb6fa82a26c762bf4d0e034581074c95580664fba5c77f0ec5c",  # IfStatementAst
    "0.1.4.2.0.2.1.0": "1d9e1b97f66d585aaef941170fa28ffa9377924b8ac846c146c3de4b5515d586",  # PipelineAst
    "0.1.4.2.0.3": "96914313b16b1e9012da2b70b57aaf84584acb423850e483daf9b25b385ea489",  # PipelineAst
    "0.1.5": "c2ad23e192daae7b098b045e41f96f4f32aaea115fb3b9e3829e6a9474e43daf",  # FunctionDefinitionAst
    "0.1.5.2.0.0": "6033201fe4a07ac4c9e5c243ef57c1e8c5c229cfcfcf7e835a6ec35622edf94e",  # AssignmentStatementAst
    "0.1.5.2.0.1": "2aa1340bdc4e383752d9ccf36e38f5750a77eb308c84d62b833a4d5db0ae64c5",  # AssignmentStatementAst
    "0.1.5.2.0.2": "971cb7c2312161e0b192186d38466dd276c30189327b8f74bd10bc0b64089beb",  # AssignmentStatementAst
    "0.1.5.2.0.3": "113ee00e1faae14036af2b5da630eb08b5cf2e1bc187a3fbc52b9fe8947b3fbb",  # AssignmentStatementAst
    "0.1.5.2.0.4": "eeac84576f461a4b57b118ba6ccff9ba154696350f34e265fe5a27f37060e592",  # ForStatementAst
    "0.1.5.2.0.4.3.0": "d4f81235ae7bd3a1e84285ce375c77faf28d96c4928903caedaecf2a3e7741e5",  # TryStatementAst
    "0.1.5.2.0.4.3.0.0.0": "e4c4c96f0e9e6ff9ecd8e19063e2c722449d00c0b5e945483487c102fd3f981d",  # AssignmentStatementAst
    "0.1.5.2.0.4.3.0.1.0.0": "4c3532bee9eab60b2986e22cd862a50a0a6ec22cdca02a3fcfe2a2dcde602d36",  # AssignmentStatementAst
    "0.1.5.2.0.4.3.0.1.0.0.1.0.1.0.0": "8f4e41e0accbebd5e3f2aaeee043b5d0dc36dcca88b271971bcb3388d85ccbcd",  # PipelineAst
    "0.1.5.2.0.4.3.0.1.0.1": "1b61765d07b695be96cfac75d8eb3f268c9486bbdf09b6ab385fda727abe023e",  # BreakStatementAst
    "0.1.5.2.0.4.3.1": "f0c1dad1d7477c6d0a4ec0f1aab8098539ac86d2d0e4a10d8098649bd662a85a",  # IfStatementAst
    "0.1.5.2.0.4.3.1.1.0": "68d5a55525d557fffa92083c467d34f0e1c16245defd5aeec82028eeb1acccff",  # AssignmentStatementAst
    "0.1.5.2.0.4.3.1.1.1": "3b525a768c0117f18b00b92a864060051eeabd1b32d5ab4b66ca885192d28e6c",  # BreakStatementAst
    "0.1.5.2.0.4.3.2": "272c0a67013031ba96cb8b2de223975859b98d6cbd24154134dd0fc43ded810f",  # IfStatementAst
    "0.1.5.2.0.4.3.2.1.0": "bf23af4e498886a5d366a38adfda24cf17af41e096b9dc069df2b4fbb2aeab28",  # AssignmentStatementAst
    "0.1.5.2.0.4.3.2.1.0.1.0.1.0.0": "26efe7ffff04b778c467abbe7e71f58d72552596a68c71461eeb5f4670b12872",  # PipelineAst
    "0.1.5.2.0.4.3.2.1.1": "3b525a768c0117f18b00b92a864060051eeabd1b32d5ab4b66ca885192d28e6c",  # BreakStatementAst
    "0.1.5.2.0.4.3.3": "ee51e29b47943e2605a1b716fb98a8da9cf0d242e35ae569eb41a1b2f93d787b",  # ForEachStatementAst
    "0.1.5.2.0.4.3.3.1.0.0.0.0": "5531957262b08474a3be63e14e4804ee74a05f2c32a6184f762ba82fd076a342",  # PipelineAst
    "0.1.5.2.0.4.3.3.2.0": "53152d87c5e79c52c2ba21a7ccb031bebb89971850e066dd5beca798c9ec2fc4",  # PipelineAst
    "0.1.5.2.0.4.3.4": "131e5587d3f8c1628e590f55fe6a3d727773518a322e3cd08b7c963bd769a3c2",  # AssignmentStatementAst
    "0.1.5.2.0.4.3.4.1.0.0.0.0": "f8b10d7636ad90060c90554f8cbc290e3954d2314b865682fadc3ac5e9ffb809",  # PipelineAst
    "0.1.5.2.0.4.3.4.1.0.0.0.0.1.1.0.0.0": "3240731ddd2d3bfb9bae9d7e9782a8b194457177351f74fdbdd5bdc0bb8cce67",  # PipelineAst
    "0.1.5.2.0.4.3.5": "43318e903dc0dd7605017d19bb43aaa7be9694101e98665ed597b457eff5fa35",  # IfStatementAst
    "0.1.5.2.0.4.3.5.1.0": "be3e5aa5aabcc5d6820239ab322d91fac0fd10b0d51aeec633935bb9b978b978",  # AssignmentStatementAst
    "0.1.5.2.0.4.3.5.1.1": "3b525a768c0117f18b00b92a864060051eeabd1b32d5ab4b66ca885192d28e6c",  # BreakStatementAst
    "0.1.5.2.0.4.3.6": "2aa07bf46ebbe01bf28c308102bba8e54bce74d1ed97e9601cf3e94f3c655dc1",  # AssignmentStatementAst
    "0.1.5.2.0.4.3.6.1.0.1.0.0": "c035abc694b1ae8b5f4b2c6b6857f12b0acd4f26a1c73be07e3c33d29434735a",  # PipelineAst
    "0.1.5.2.0.4.3.7": "b77ad080ab1c43f9cadeb804fa5b6e1c6e7dd5a01b60543a08a80083789d5fdc",  # IfStatementAst
    "0.1.5.2.0.4.3.7.1.0": "0ec6028f4814ed060bd61143a8c30aa59dc3034fbe7006e79300af86815341b2",  # AssignmentStatementAst
    "0.1.5.2.0.4.3.7.1.1": "6f77b85817c248e623be6e95aff515895db40880ad22830e92fb7864deed1fb5",  # AssignmentStatementAst
    "0.1.5.2.0.4.3.7.1.2": "3b525a768c0117f18b00b92a864060051eeabd1b32d5ab4b66ca885192d28e6c",  # BreakStatementAst
    "0.1.5.2.0.5": "cbab9124558dc0c9efe6783b58b3d99e12ad42417827ca98af9e4bb69cd59a84",  # PipelineAst
    "0.1.6": "a392484f5a1aac9a308925338c812edbada3876534d5863169d009b7be715383",  # FunctionDefinitionAst
    "0.1.6.1.0.0": "34cc2ca06077de1fddeda52d0c74e37c18032498de5fd974fc9d961aeabe051b",  # TryStatementAst
    "0.1.6.1.0.0.0.0": "2da2e5f4847cb4b85856299fc25508f6128a8378f3d924ae4ae050bb616b6af0",  # AssignmentStatementAst
    "0.1.6.1.0.0.1.0.0": "c0c844d895c50236d52f5863400b751cbd2432ff7b922af865ab48c6a5788bc3",  # ReturnStatementAst
    "0.1.6.1.0.0.1.0.0.0.0.0.5.0.0.0.0.0": "824e7131f3a71d150375aaa85a4a78d76c9543aa5590534ea4f4bed14a20e0a7",  # PipelineAst
    "0.1.6.1.0.1": "fb4afc467c7ee2b3f6104af0324f06b0baa3b6e345905bc8972c26108dbc8c0a",  # IfStatementAst
    "0.1.6.1.0.1.1.0": "1d814a0ea90719bf4c9f39e3cb909662723bd3c553bff411174bf2f88102a047",  # ReturnStatementAst
    "0.1.6.1.0.1.1.0.0.0.0.5.0.0.0.0.0": "57c44bee98c5f300faadb96eac394dc956a9bb8a9407da4fe4d076b79009e6ab",  # PipelineAst
    "0.1.6.1.0.2": "4c1d5a96cf218ece54a65d45856a28918794efebdf76bedfec1a7f717c278af4",  # PipelineAst
    "0.1.6.1.0.2.0.0.1.0.0.0.0": "5531957262b08474a3be63e14e4804ee74a05f2c32a6184f762ba82fd076a342",  # PipelineAst
    "0.1.7": "521446a7e7bce90e85a41890a3ee9e17a1a5fc1257a1f74b75fdbdbea13ad2f8",  # AssignmentStatementAst
    "0.1.7.1.0.0.0": "b3c39c25ee3ebbc36b2797011f8132c95bd8d31ba85ccc2f5fd9ec7318826809",  # PipelineAst
    "0.1.8": "dd8c6854bed15f4eee928a44e35a217b94aae860164bab69bfef00ef09956d04",  # FunctionDefinitionAst
    "0.1.8.1.0.0": "239e374b34382ce6c474978341181f8d4d9b66c2b4b9498c25d1a81a87580803",  # AssignmentStatementAst
    "0.1.8.1.0.1": "03ad8a2323038ff217c8546575014128547335b5428025a70ea564a5abb7aa17",  # ForEachStatementAst
    "0.1.8.1.0.1.1.0.0.0.0": "a72f26e9a45e081eaf9a651aaf82f4544fad9e8c7307cd8646bc39e57c4e077c",  # PipelineAst
    "0.1.8.1.0.1.2.0": "bbf2fd5e95d513af7cdcb9456a5c82f38840a986b78a739ab63ab259d888a7a9",  # AssignmentStatementAst
    "0.1.8.1.0.1.2.1": "b3f8bd202259c39f442337a211811df9668a707f7e4f74e131b482a491eb5210",  # AssignmentStatementAst
    "0.1.8.1.0.1.2.2": "4c3fb919abcb789cc546c32b6fd71f5c6d824fe7245d8ad6a3f137e74547c38b",  # IfStatementAst
    "0.1.8.1.0.1.2.2.1.0": "4cb9ff42761abbc07c54f2be9fb231ceaecd1d1424f8d95690b32b7b2bacd562",  # AssignmentStatementAst
    "0.1.8.1.0.1.2.2.1.0.1.0.0.0": "4229438352b0733c1c689302e21eb4b187cd2ef5338bb00c3f626a01754bfc69",  # PipelineAst
    "0.1.8.1.0.1.2.2.2.0": "bfb77e774a48cf193c811d73477a41b6edf95f59561d9a27db1ed0cac0cf2566",  # AssignmentStatementAst
    "0.1.8.1.0.1.2.2.2.0.1.0.0.0": "51296598a86bcb20f3383c5ea52be12825d5e91dd0f72ec9fe64f08c54bbd291",  # PipelineAst
    "0.1.8.1.0.2": "262db6be58c4b05d911648a30716851ba56c89301e7680f90f8e09b3e83f429e",  # AssignmentStatementAst
    "0.1.8.1.0.2.1.0.0.0": "374c458cd8bcd41505c7132477c8619467dcdb4006956338f452f42c824befc9",  # PipelineAst
    "0.1.8.1.0.3": "5d7160266401bf8f6823c5ae2dc3c49bfe7b9f9af4c8b5be5dc4cfc7405357c4",  # PipelineAst
    "0.1.9": "dea5657d4479df2d603b92ce1497ac5becfbce4d96fdaaf952d8866616b9c31e",  # FunctionDefinitionAst
    "0.1.9.2.0.0": "827a1e61dd0e1ac10d3adfbd183266eb870be0c0fcceb7f0a62a216901a6e198",  # IfStatementAst
    "0.1.9.2.0.0.1.0": "3d497d1b34f1dd8c9e2cd9e802e13301808c695b7f4e3c9b7736a74ff5287eb3",  # PipelineAst
    "0.1.10": "50325dbe3aab8ffe0df322a3d6400ce6be10cf8cb4c88b8af8a146c71f254596",  # FunctionDefinitionAst
    "0.1.10.0.0.0": "d3a9d189eb038621ae8a1507c0fcab02f512ebb77ec621f9a128193ed407e778",  # IfStatementAst
    "0.1.10.0.0.0.1.0": "f31b24664eaa6135a8d3bd06e2f903d6ce2c9e0358c1d4d8c7e17dda48f1c819",  # ReturnStatementAst
    "0.1.10.0.0.1": "22395deb155e9a7b29e65d69b8b13cbe939a90bf951b1a5643023a5b6ab599be",  # PipelineAst
    "0.1.10.0.0.2": "6e56fb95a45de79476dbd264a07e339aa6695554801d2b8b452b2072df6317df",  # AssignmentStatementAst
    "0.1.10.0.0.3": "d50aaeec55c842c61bd5b136726825c6a33ae96218b2a14d736fcc08d2498923",  # IfStatementAst
    "0.1.10.0.0.3.1.0": "0ef1c05767c00dce6fa23746e98ed99fd18ace7bfeb0babf5ceff2d86e11dca7",  # AssignmentStatementAst
    "0.1.10.0.0.3.1.1": "a9c3e70d6114311878692414bf2bd82a18b9f71d536265a09aacf15f5ed86e82",  # AssignmentStatementAst
    "0.1.10.0.0.3.2.0": "f8659de4ac618e75e4bca8c141b59d00d252a5495cf2289f11c2cda76e79cc69",  # AssignmentStatementAst
    "0.1.10.0.0.4": "57accd5747976bba88fd5b880c59f10f67fbe76fa2dd4b2ddd45663d7e137e38",  # AssignmentStatementAst
    "0.1.10.0.0.5": "2af232988f3644ec0243ae15e08ace5089ab853ff4f25cca68047ea823e407f9",  # AssignmentStatementAst
    "0.1.10.0.0.6": "ad0623b179f6642a2cb3714ef1de104e4cd4bbb8ce32a3eed43e5076abc2760a",  # PipelineAst
    "0.1.10.0.0.7": "3ae30b3b8583d9b61f90c5f62d57c1834d13583d20d298a4caaf00d2a3af90d2",  # AssignmentStatementAst
    "0.1.10.0.0.8": "93fcbf92df9e4c284239eebdab5a4e6cef6692f4be94d8b826d3c757625f5446",  # PipelineAst
    "0.1.11": "e48d571d7da92a37dc1992614bc590c15faf2cd8758134b2bb265ccc761dc3e3",  # FunctionDefinitionAst
    "0.1.11.5.0.0": "6c82430e7d27815825f445c0d3f975388009e80e11567248a2cd75e44ee1a068",  # AssignmentStatementAst
    "0.1.11.5.0.1": "dbc3cdbc34fc5d46f7d2be7d01e448b186cabd9d21b66ee1495e5876053527fe",  # AssignmentStatementAst
    "0.1.11.5.0.1.1.0.0.0.1.0": "2b1a678fc65f02019d881721d1df55e55f19121d559f3993408ff62f108bf16b",  # AssignmentStatementAst
    "0.1.11.5.0.1.1.0.0.0.1.1": "316ca0ebf99044d957cc9535b1718856663106fa6c8bd21fbb8265337581672c",  # IfStatementAst
    "0.1.11.5.0.1.1.0.0.0.1.1.1.0": "f399bd0930e78cd2fa08063ba2507002ef422cc70ea32e55285ed83b032cf1bd",  # AssignmentStatementAst
    "0.1.11.5.0.1.1.0.0.0.1.1.1.1": "da3d3a888eff64a4c0f2521e968543d68b31f6e9a51b3023228a7fd68b38b736",  # IfStatementAst
    "0.1.11.5.0.1.1.0.0.0.1.1.1.1.1.0": "4abfc9d106f1976b9f693d09812c1d4d025bb48190e623a212e176ebc600bc5f",  # AssignmentStatementAst
    "0.1.11.5.0.1.1.0.0.0.1.1.1.2": "63e5dca46dff1b0ad3f832d00ba9cb6e41c6fd0b26c191f4ec130e2981653d1f",  # PipelineAst
    "0.1.11.5.0.1.1.0.0.0.1.2": "27bfba5f8fd8c49fc5c606c87c5cf69fa4ed8914640d05185c102059ca05225b",  # IfStatementAst
    "0.1.11.5.0.1.1.0.0.0.1.2.1.0": "4499670af2609ba96d12797b8f3f9089e1cfaf709a6b492da1061aab89b0be7b",  # PipelineAst
    "0.1.11.5.0.1.1.0.0.0.1.3": "2488bacb8fd348963e8f77d873eaaf4d236c79d1ee8b0d8d50b4ba492a9ce785",  # PipelineAst
    "0.1.11.5.0.2": "3b88d77f456809d02863f9193d9147faf56b44efe930dec66214d7a819d05bcb",  # IfStatementAst
    "0.1.11.5.0.2.1.0": "42f7a14cd6d5836cb10a782f63b5f7b2e7806b6691610fa6d8fd2f3912d47bd0",  # ReturnStatementAst
    "0.1.11.5.0.3": "54cc7d3920fced8044f7ba2bd6e66e570ea6cdb58bd73c00b39ca4aeb6be9b7c",  # PipelineAst
    "0.1.12": "ac6e27e4c0c2585d3aa6068fa955c4677b9bb0c6bd1f2af05471595376697e28",  # FunctionDefinitionAst
    "0.1.12.0.0.0": "d494e9304714ff1134e0a885c330de348b8b8be76072f688c588581aa910df7e",  # IfStatementAst
    "0.1.12.0.0.0.1.0": "717f4ec2e25435576dc53792e9acb6642d1ac7a76db15296cae0f69bb8c3dc54",  # ReturnStatementAst
    "0.1.12.0.0.1": "16ca73e5b5bcb7ba56603ad79201f5b3e2db12d0e7ad6e9083b384ab9a1fbcff",  # AssignmentStatementAst
    "0.1.12.0.0.1.1.0.3.0.0": "d0fd47b250699825642fb53c25783eb0c63f450eec3243e497a6bc7cb7b0724d",  # PipelineAst
    "0.1.12.0.0.2": "9f35d842e32a3e71ebd392d6175886fc04690e8fdff9146120ee5860ad1cac66",  # IfStatementAst
    "0.1.12.0.0.2.1.0": "176fbaf7ca6b259c3566f8cc3583132a4fe118d5f788f6fba594d4c21272a8ca",  # ThrowStatementAst
    "0.1.12.0.0.2.1.0.0.0.0.0.0.0": "cfbb8cc5f73bbfc799ae759ae3b2d816eab0d4379948030d92b91033854bccc9",  # PipelineAst
    "0.1.12.0.0.3": "340a6278df637f45fefb591d72322092e37d402b0be93654265bd607716ec5e7",  # AssignmentStatementAst
    "0.1.12.0.0.4": "2643464cf6cba7c4958ba9faf8d8ab74c80d475a5ffe42874567e84c8ed23580",  # AssignmentStatementAst
    "0.1.12.0.0.4.1.0.1.0.0.1.0.0.0": "e7ea2bc8ac32e9544c43e4e502cddd16af30341aaa10f5aa68f348efb49c301a",  # PipelineAst
    "0.1.12.0.0.4.1.0.3.0.0.1.0.0.0": "eb8fc9657edcb3d57454eec9af2b95c4b3ddf5ec93cf17395549584f69a75900",  # PipelineAst
    "0.1.12.0.0.5": "a3a303231b50826c2c7a93abab4c3de2a05dc978537d37dd38fcf7d64b79b861",  # PipelineAst
    "0.1.13": "05e923672fc1186b63add96851c3fb82515076d7928a03f190f2d1ef7d79965b",  # FunctionDefinitionAst
    "0.1.13.1.0.0": "46ebbc1dbed14b503eeb7c8b10ce0c38029b070d32a638c8b627a3a0d3c8df9b",  # IfStatementAst
    "0.1.13.1.0.0.1.0": "0793c2c8f1f54afa67107b9d2f17385214e4cffe4f213498eacc6f1207cc2ea1",  # ReturnStatementAst
    "0.1.13.1.0.1": "9d4605e408224a282651c7d9071003bcc717d4dc50641e004e89578d55b84ede",  # PipelineAst
    "0.1.13.1.0.1.0.0.0.0.0": "ee8225fd5062d419f4bdab8967b28b734c96df21ec1c10c726307f00c7ac549f",  # PipelineAst
    "0.1.14": "c4c94223bb254f5ada5dc95786b94df46f1f7135b6618ca1b1cf0275ae94797d",  # AssignmentStatementAst
    "0.1.15": "ead0f2d2cecf66c9231a53665c0de65581208397fe0a20217e2bc26a02c0b780",  # AssignmentStatementAst
    "0.1.16": "94164df7dde6670e1a8dac16ea27003609d10549b7a15f96677aa64cf98fe0d1",  # AssignmentStatementAst
    "0.1.17": "41836834beb3058098ad3b1e3fbda667bfd3eba80ae53ccb2a636fc838de33d8",  # FunctionDefinitionAst
    "0.1.17.2.0.0": "b2ebc86b63a7a3ee1b467ec907d6c8f954364da4fb74a99c566fae1fddd06fff",  # IfStatementAst
    "0.1.17.2.0.0.1.0": "6cc9cb03ed18438a7f5c4fc412f20903dc1df3f3dbee47e2cf965d756cff3b85",  # ThrowStatementAst
    "0.1.17.2.0.1": "f747a40416d078f019a23b331135166e6c4a9a971c8b33b641a94b59bf5e792c",  # AssignmentStatementAst
    "0.1.17.2.0.2": "a2e379962c4cd39ba471d34e37fed16eace0b8de2722f0323c8156c0a4f1227a",  # ForEachStatementAst
    "0.1.17.2.0.2.2.0": "eeb0b923d0b91d2c5b891112910394eed91a6568c239141a8dc6834272677e04",  # AssignmentStatementAst
    "0.1.17.2.0.2.2.1": "844fc29ebad0969d3c0981b456db9cc4e02362f134d52b85db9b321f3dca4889",  # AssignmentStatementAst
    "0.1.17.2.0.2.2.2": "9808775a87f131a2a84488e128ef8846338ffbe8450d78589a7166bde72083d4",  # IfStatementAst
    "0.1.17.2.0.2.2.2.1.0": "d6ff8afd5668d0a26b59211fc5dba03818e14e1a465bb27a96b209b4936dd335",  # ContinueStatementAst
    "0.1.17.2.0.2.2.3": "6bba28f23863ea9079f23ca5cd314705e07dde7b5b35c08c0e26e81443cb08f2",  # AssignmentStatementAst
    "0.1.17.2.0.2.2.3.1.0.0.0": "2d93fa1ec34715e1bb74287bef08a835f858e4920cd28d20a584cad1b849503b",  # PipelineAst
    "0.1.17.2.0.2.2.4": "f3b42857971c83c8bcc69cb24567a16a4eb1387c3d9a63bf544d0a0d897a8d2c",  # AssignmentStatementAst
    "0.1.17.2.0.2.2.5": "9a6197faaea1f6df4f1f4e8665396ecf803b9e49a3e0f92bbdd4bf08d578dba9",  # IfStatementAst
    "0.1.17.2.0.2.2.5.1.0": "8f160ebe674b7f4e3483cd819d74fba9658a212ef4530836b5684bcf46ad1a50",  # IfStatementAst
    "0.1.17.2.0.2.2.5.1.0.1.0": "72f7fed69a62c7664f9b90ce6348170bad832a4a24454c4d9fa036fb65ae4f63",  # AssignmentStatementAst
    "0.1.17.2.0.2.2.5.1.0.3.0": "72f7fed69a62c7664f9b90ce6348170bad832a4a24454c4d9fa036fb65ae4f63",  # AssignmentStatementAst
    "0.1.17.2.0.2.2.5.2.0": "587e3c600eb24f665db931c6caad18460b228dedb88451d4d4065fe4b7fed296",  # SwitchStatementAst
    "0.1.17.2.0.2.2.5.2.0.2.0": "ad069069fcb335c8aadee0c94966903baec949f8acbf608021543e30e9219c99",  # IfStatementAst
    "0.1.17.2.0.2.2.5.2.0.2.0.1.0": "0002317a5ffe2ad6228d50ec6c7b104b1e7bddbc694419ea973383faa4c59f02",  # AssignmentStatementAst
    "0.1.17.2.0.2.2.5.2.0.4.0": "61450090e808a91f7bb62a3a43803b1b5e5ccfe8c20d90838ac4aacaf350d443",  # ForEachStatementAst
    "0.1.17.2.0.2.2.5.2.0.4.0.2.0": "f4b7e7f38bb7036d3fd7ebfaa8dcd40eb0ad9a25038f9b13c58c55e6938648d0",  # IfStatementAst
    "0.1.17.2.0.2.2.5.2.0.4.0.2.0.1.0": "e70083d01356d59addf50db87246c43207e3c9cc52582de549368b5211e7c93c",  # AssignmentStatementAst
    "0.1.17.2.0.2.2.5.2.0.6.0": "4f8ab3de873fb6ea06abb196124adb68104385c4001a9775dcb7d4ab4751e078",  # AssignmentStatementAst
    "0.1.17.2.0.2.2.5.2.0.6.1": "62e7089e6afdd7f7f96ffa6dde6d992ffe6400c6eb1374c0c6d44186411ab734",  # IfStatementAst
    "0.1.17.2.0.2.2.5.2.0.6.1.1.0": "90fa84b84e09aed8c619b35a84482094c28bd7b460d7ebb66e3ecf1beaa5a415",  # AssignmentStatementAst
    "0.1.17.2.0.2.2.5.2.0.8.0": "485be823fba0ee858e6170a21149f8417a10162af4bce023de9a7ceba4fedf2d",  # IfStatementAst
    "0.1.17.2.0.2.2.5.2.0.8.0.1.0": "750758b4f0e298a22f37fdf8921ebca35ae4da33a20ad39f851f593cd3fab774",  # AssignmentStatementAst
    "0.1.17.2.0.2.2.5.2.0.10.0": "135d96bf9d3b1c50ac80c2704a11db85287d9c5d16ff466fee22c09557242ccc",  # ForEachStatementAst
    "0.1.17.2.0.2.2.5.2.0.10.0.2.0": "401b4dd31b06c9c9ef3337a77d6df5c6fad86064c951781dbeb73d466dedb254",  # IfStatementAst
    "0.1.17.2.0.2.2.5.2.0.10.0.2.0.1.0": "1a43ffaec2e3f58ba0a36ba19e5596077268175560481a00ca5eeba0e4d91fbd",  # AssignmentStatementAst
    "0.1.17.2.0.2.2.6": "fd429484eb2abe821536eb0c99136476e7d3dc678d3e34425a71d8a80a3e5467",  # IfStatementAst
    "0.1.17.2.0.2.2.6.1.0": "e217fe1046126944970e678458ab8e6a525558f069ba0a03dd956167b7726e94",  # IfStatementAst
    "0.1.17.2.0.2.2.6.1.0.1.0": "65cbef029bdc88263322b71a23294ccbbe8fd8b35f2aad0bad334c354dac5d41",  # AssignmentStatementAst
    "0.1.17.2.0.2.2.6.1.0.2.0": "5f69480c3817535962b3c3218d71e9263c4777d73a60f5865c6442694c1d8662",  # ReturnStatementAst
    "0.1.17.2.0.3": "3dcb52317e03d07a2a3f4c6d291011f134500ff7af188c5761cab08af78ecf08",  # PipelineAst
    "0.1.18": "5b7139b129fc1efac09c580918f8964282884c649dd1635d3df941c84c485824",  # FunctionDefinitionAst
    "0.1.18.2.0.0": "671261cd23e197b74ba51901dd555199c86be43adbfaf204021c6dc01de17a8a",  # AssignmentStatementAst
    "0.1.18.2.0.1": "b8e98f2a30573eee01cf170f34620b49ba6075382a66305bd662e8d3142005b0",  # IfStatementAst
    "0.1.18.2.0.1.1.0": "7cc90177b6e8969f7641515c8f7243f97c5984b7f26a98c8adbad54b0bae62ea",  # ThrowStatementAst
    "0.1.18.2.0.1.1.0.0.0.0.1.0.0": "68fc18164daba32af86dfb4963311d709e35299c6d69578ba7dc9667b7dea7cc",  # PipelineAst
    "0.1.18.2.0.1.1.0.0.0.0.1.0.0.0.0.1.0.0.0": "0c67d035acb26bb240c7a4ed9f6d6fdc20134583fd168d1a936aaba7d001a8f2",  # PipelineAst
    "0.1.18.2.0.1.1.0.0.0.0.2.0.0": "c1c676423476b63458ab6cb7211d01965d573c650bbd06271779093097a2d8a4",  # PipelineAst
    "0.1.18.2.0.2": "dd335cf3cc4517ada786cb148f089becde1269f65d81331d8260af1f417dd9ad",  # PipelineAst
    "0.1.19": "0df426646b16ca41e200f135cc12a1e444604a7ce50526128bc1e7c114e9fa9e",  # FunctionDefinitionAst
    "0.1.19.6.0.0": "1b634b8c5319fc47a5949e64bb6fd98c9ffa2ec4e734b7be5e6cbf2161f744e9",  # AssignmentStatementAst
    "0.1.19.6.0.0.1.0.0.0": "aaa85e65f0fba1dd9039f6518dbae3f405375e3efd87a806ddb796e80e12136e",  # PipelineAst
    "0.1.19.6.0.0.1.0.0.0.1.1.0.0.0": "afb28bec54d259bb71ed8728decebab3d4deacc60b9da524cab30c2f26124568",  # PipelineAst
    "0.1.19.6.0.1": "4515aa16021434bf88806e3b2feda6ee49079656da470a702bb7d4a24281c9fd",  # AssignmentStatementAst
    "0.1.19.6.0.2": "57aebde56a1eecf21a183771159e8b5f82fa3f7e1368577f068b2cf6dcb6b8d3",  # AssignmentStatementAst
    "0.1.19.6.0.2.1.0.1.3.0.0.0.0": "4513c277be2b19ba292d1291064658b2398bac382736b06621ddc0b132febed5",  # IfStatementAst
    "0.1.19.6.0.2.1.0.1.3.0.0.0.0.1.0": "1d266a11312f0d6b0550af218267d0043d32cae3bee11b8dd731bbbe3a46f9f2",  # PipelineAst
    "0.1.19.6.0.2.1.0.1.3.0.0.0.0.2.0": "1d6a6f425657e7eb6dc359ace411d287a951dc8c2a4e2b038fec1c3a9a19fee1",  # PipelineAst
    "0.1.19.6.0.3": "ffeb5a103f7d780d15f5d19528b2315a432c2a3e426e3cc9f1ee0562e32f60d9",  # IfStatementAst
    "0.1.19.6.0.3.1.0": "0d9f24bc8525e4129ad130a8f846d24ce23b4f2c21ac20ba134248d442dc1992",  # AssignmentStatementAst
    "0.1.19.6.0.3.1.1": "dba9654295a88ccae0a8733b16325ade07c3fb2873652627ffa778746b028e67",  # IfStatementAst
    "0.1.19.6.0.3.1.1.1.0": "b40037d99e41c5f353801f9f41d4d84c6e34f12c4fce2ae97b570692cfba4327",  # AssignmentStatementAst
    "0.1.19.6.0.3.1.2": "73f5a6ecdd9370cf2bc539a08abe80725bc4594fce2a9b830072eb77cea4fe43",  # IfStatementAst
    "0.1.19.6.0.3.1.2.1.0": "0fda04e918b76e4d1d005323d1efd2044dcffda29863bc19f4c954a21257211c",  # AssignmentStatementAst
    "0.1.19.6.0.3.1.2.1.1": "77d189d0396d0fa23243883a298ac6c9a8f907668fbf5927b9b90926446eac76",  # IfStatementAst
    "0.1.19.6.0.3.1.2.1.1.1.0": "c8b1c110e0e4f05a3006003803cb8924946b6c49fb39ea1a027067efb78860a5",  # AssignmentStatementAst
    "0.1.19.6.0.3.1.2.1.2": "25d5261e42cbaf6f43f534c88d190a23b84f46e128aa3078becd6436b993d120",  # AssignmentStatementAst
    "0.1.19.6.0.3.1.3": "8873089a0a11735c01731b3229eda3f97807b2aeb9538ce6dd93f595c794952b",  # AssignmentStatementAst
    "0.1.19.6.0.4": "405f98e6de4397cd5f5a26797f5877b07a1c99feeebe2527843d930b195956ec",  # PipelineAst
    "0.1.20": "f5d1c256f22119e299de5cc6fbcc224419eea13d30815e87c4d79b00662e56dc",  # AssignmentStatementAst
    "0.1.21": "512b6874c8c16d6e349aaff3c1991b6d42be5b56087ba9dd3541f4725df3d121",  # AssignmentStatementAst
    "0.1.22": "cdc004c8007fce9c2b7b41677772fd529fe59e5a136c2edd66d6029dd9b6da89",  # FunctionDefinitionAst
    "0.1.22.2.0.0": "84a583474bc0d8eb2b3c7c22e550812bb23c0ae3827bfe63459b7c7273a859b1",  # AssignmentStatementAst
    "0.1.22.2.0.1": "887f78a4bfc99f077de2557f76d00ad0dea30438a91988fc349546b06679c955",  # ForEachStatementAst
    "0.1.22.2.0.1.2.0": "992a82228fc05eb0bfcaa34db95d195e96c104a6abf9444486fd1ac34280b961",  # IfStatementAst
    "0.1.22.2.0.1.2.0.1.0": "c6595944264e6110b1a75ce63badbcd2277971df986ce234ba6377530e398a8c",  # AssignmentStatementAst
    "0.1.22.2.0.2": "3df7e1a921121e7410f32ea0ce106536e772ae8a65c97625bc6c01b6395bdea5",  # PipelineAst
    "0.1.23": "3aead760a3b6f6831af41def81ff3e68a0d153241283bdc247dedf8a5f67449e",  # AssignmentStatementAst
    "0.1.24": "802915e4fcb60cb9e5fc60342dda54b9ab9d64c28f2ebcd33a16b237b617894f",  # FunctionDefinitionAst
    "0.1.24.1.0.0": "fe808dedff8c79b491b3cf36dfbce00e2526f6b9d7bbbcd686b5617871101fa8",  # SwitchStatementAst
    "0.1.24.1.0.0.2.0": "ba6463aecd638f531ae453f48387b34922a77a01a181ff91b050eaa5c13c9c5a",  # PipelineAst
    "0.1.24.1.0.0.4.0": "564dbdc4ce8d958042fdccb910de3911669925af84ab14b01efbbea1ff2bf546",  # PipelineAst
    "0.1.24.1.0.0.6.0": "3c049b6e001352fd8e6563839ea184010d473e962df0b186776aab9b1eacd7e7",  # PipelineAst
    "0.1.24.1.0.0.7.0": "1a34d5df1046426b56eab1de9950d17e4448872b971e71b631f02d0745084554",  # PipelineAst
    "0.1.25": "4665be42fb1a7d783d3733dd459d759214f9e59838d9a4382f70026221bb1d89",  # FunctionDefinitionAst
    "0.1.25.1.0.0": "84a583474bc0d8eb2b3c7c22e550812bb23c0ae3827bfe63459b7c7273a859b1",  # AssignmentStatementAst
    "0.1.25.1.0.1": "04ceee9a6035da7e7859308c431664509f89582d65494b61baaa3ca705ccd981",  # ForEachStatementAst
    "0.1.25.1.0.1.2.0": "e6d49d4b238b98202008f3791fe8282f219dfa97277ac5e075dadae7437600bf",  # IfStatementAst
    "0.1.25.1.0.1.2.0.1.0": "3628505f55b1e43b6be7875e6f6b177f0d885ecb30e29ee4d06d42e115e69666",  # AssignmentStatementAst
    "0.1.25.1.0.2": "3df7e1a921121e7410f32ea0ce106536e772ae8a65c97625bc6c01b6395bdea5",  # PipelineAst
    "0.1.26": "9b6ca12eb4bf4e0bb4331baae28b4bb975fbf7598951c8209bc4c9db0075c924",  # FunctionDefinitionAst
    "0.1.26.1.0.0": "91341d891ec7273b52abf71823d6eb716648a1edf0fd7e29d34aa1cb3e3e6093",  # ForEachStatementAst
    "0.1.26.1.0.0.2.0": "4081ee5ad7ca4c754964743027d0d5e4f6b9443dd7437c8c10a86d2556c2729c",  # IfStatementAst
    "0.1.26.1.0.0.2.0.1.0": "cf092e7548b2629d0110791f308d6830a40f78870aa7678c46fa78b2441b2b3c",  # ReturnStatementAst
    "0.1.26.1.0.1": "ef1e23650e206ad5b2e318a15c29b4ae45946f840c7191cdfdd6ce6950ac3d6f",  # ReturnStatementAst
    "0.1.27": "9075cb8b6ef80d2a380ed8dcb0e9c406f2f9ab7c44beb00fe30303eb4da0a853",  # FunctionDefinitionAst
    "0.1.27.1.0.0": "84a583474bc0d8eb2b3c7c22e550812bb23c0ae3827bfe63459b7c7273a859b1",  # AssignmentStatementAst
    "0.1.27.1.0.1": "77b3ce304d11a2fd74345fff0c9ac5068091314a3f87fab900bc2c2f29f3c711",  # AssignmentStatementAst
    "0.1.27.1.0.2": "ddd9002f280897ad2e990c0011f2872535ba0ef218e450db4e2a8ee8416077bf",  # ForEachStatementAst
    "0.1.27.1.0.2.2.0": "c1f9eb6044c055986b3b5385a9ab3081491810fe7d6d903e3a2983c4f4c2fc40",  # IfStatementAst
    "0.1.27.1.0.2.2.0.1.0": "f9fe3daff8878386989631562a4eb21c8c3bfef7de79e1f2a2e6f6e2ab823499",  # AssignmentStatementAst
    "0.1.27.1.0.2.2.0.1.1": "ebe16fab6470b9d9493b68e9af7c86513ebcdcbd52714e8e257f6fd072f85f04",  # IfStatementAst
    "0.1.27.1.0.2.2.0.1.1.1.0": "f793b454948bb77e159575fbf027fbbe6887d2aa5f41b060b1cb58d37f9a1f05",  # ForEachStatementAst
    "0.1.27.1.0.2.2.0.1.1.1.0.2.0": "9aa2303e9a5b474fdbacbd897b316ff11da07a5431383017f7a99d8f6381fe3d",  # IfStatementAst
    "0.1.27.1.0.2.2.0.1.1.1.0.2.0.1.0": "1752afadc3fe92bcf512ec366882d0d5e57580cb644c1eb4bf3075ac123f5d3a",  # AssignmentStatementAst
    "0.1.27.1.0.2.2.0.1.2": "d6ff8afd5668d0a26b59211fc5dba03818e14e1a465bb27a96b209b4936dd335",  # ContinueStatementAst
    "0.1.27.1.0.2.2.1": "6f49c3ad2f32ac05337560668d02acd8b2458bdb0599faa9e0d88b7acba83bea",  # IfStatementAst
    "0.1.27.1.0.2.2.1.1.0": "31bab9133f6a52de55abc14e3bf923aaca19ef355ccdc92fc5e55cbd256d6c19",  # IfStatementAst
    "0.1.27.1.0.2.2.1.1.0.1.0": "a1f4614ca45c5ba64f460b230f839505679f72c083abab14fd08d0869e7f2131",  # AssignmentStatementAst
    "0.1.27.1.0.2.2.1.1.0.3.0": "d6e2a5ee9ff3e532bda4048593fa4187aef887c3b5f5895cae7a2be55f74d5f5",  # BreakStatementAst
    "0.1.27.1.0.3": "3df7e1a921121e7410f32ea0ce106536e772ae8a65c97625bc6c01b6395bdea5",  # PipelineAst
    "0.1.28": "e6c1def9807e98cc33f77965e87dacf743a0fd358430f139594f8e0a4a520533",  # FunctionDefinitionAst
    "0.1.28.2.0.0": "7bd4571be8409783e389b78a8ce612b4bcf1b0ad903c419b15eaa880e5410bb4",  # IfStatementAst
    "0.1.28.2.0.0.1.0": "a005d779a12e76a06ddf11c8b8ced6214ebad0bf31bf04a0ee6c248127903941",  # ReturnStatementAst
    "0.1.28.2.0.1": "bef02b19ae865605d566db1288690f6187b539bfa0e65d81c46e9535ac64ac48",  # AssignmentStatementAst
    "0.1.28.2.0.1.1.0.0.0.1.1.0.0.0": "3d26cc5e3618b720fbe3a4b3a8f950991777dce498c0901977e1d13e6007985a",  # PipelineAst
    "0.1.28.2.0.2": "b5d74e7fbf6d2d0cf62eb822c5f12527e26ea3e42900a3a32835f2636985b941",  # IfStatementAst
    "0.1.28.2.0.2.1.0": "828981c3118a82d3fdffc6c85fcffc4147c9e4d8a1a61849f198a63428e696a6",  # ReturnStatementAst
    "0.1.28.2.0.3": "fe60fd0a4eefbc6e3325a2b892f88b037d75d717bb1a21e0fccc6305dfbd3116",  # PipelineAst
    "0.1.29": "8f924bbfa88aa9534b5093606c659f175a8c301e121a9987098bf83af749603a",  # FunctionDefinitionAst
    "0.1.29.2.0.0": "462e05ad86b0d8cf887fd95bd62568c9b839b476a0c6613b0a7413c26169743f",  # SwitchStatementAst
    "0.1.29.2.0.0.2.0": "e5a44079ebefb1163d14805dcd9d84da44d87fafcc646646994bda1ab73095f4",  # ReturnStatementAst
    "0.1.29.2.0.0.4.0": "0793c2c8f1f54afa67107b9d2f17385214e4cffe4f213498eacc6f1207cc2ea1",  # ReturnStatementAst
    "0.1.29.2.0.1": "03d5516f88f42882bcec36a41c6273ca7bb2c3eeb4691e4e6287bc49e5793cc4",  # IfStatementAst
    "0.1.29.2.0.1.1.0": "0793c2c8f1f54afa67107b9d2f17385214e4cffe4f213498eacc6f1207cc2ea1",  # ReturnStatementAst
    "0.1.29.2.0.2": "f36030184ced7b7dd37578ad4a725511aac122908bd2b02678a8a0384c422c00",  # AssignmentStatementAst
    "0.1.29.2.0.3": "b3c8ff1f50432dfc58959b32e081ad9cdcdd3ba72c77131fb25f2de8e20151f8",  # PipelineAst
    "0.1.30": "4ae6f956b98285f80f1a789cca525c5cd2d06d0e14c0c3bc4703b337db8d5cf8",  # FunctionDefinitionAst
    "0.1.30.2.0.0": "f34ab833e46c4062fb53dc69854eed2f7d0cf8339baaccf0700c33c6c8c74b2b",  # IfStatementAst
    "0.1.30.2.0.0.1.0": "0793c2c8f1f54afa67107b9d2f17385214e4cffe4f213498eacc6f1207cc2ea1",  # ReturnStatementAst
    "0.1.30.2.0.1": "c38ac77435d8c2c4cd142a43e68b4ce484925f3fb7d94d7b5ca5261441437fea",  # PipelineAst
    "0.1.31": "dc052547dbdbc6c98fc6fe8e652f4466369ced9913167e588bdb61fc0305dc01",  # FunctionDefinitionAst
    "0.1.31.2.0.0": "462e05ad86b0d8cf887fd95bd62568c9b839b476a0c6613b0a7413c26169743f",  # SwitchStatementAst
    "0.1.31.2.0.0.2.0": "e5a44079ebefb1163d14805dcd9d84da44d87fafcc646646994bda1ab73095f4",  # ReturnStatementAst
    "0.1.31.2.0.0.4.0": "0793c2c8f1f54afa67107b9d2f17385214e4cffe4f213498eacc6f1207cc2ea1",  # ReturnStatementAst
    "0.1.31.2.0.1": "ae348895b360de8e18e4057b5bb0c7b120798a3b4c6d191884508eef2b409605",  # IfStatementAst
    "0.1.31.2.0.1.0.0.0.0.0.1.1.0.0.0": "8bf76097004cfcdf7b5ce9f9bc715ed11d61b3243408b00ef59c5349550e83fc",  # PipelineAst
    "0.1.31.2.0.1.1.0": "0793c2c8f1f54afa67107b9d2f17385214e4cffe4f213498eacc6f1207cc2ea1",  # ReturnStatementAst
    "0.1.31.2.0.2": "9b54911c37bbb429f6505f56ac9d6e50b26464c25f480110be264010d031b4ca",  # AssignmentStatementAst
    "0.1.31.2.0.3": "94f638b4fc098db2f057e4ca20aa9dcc5fa8686a2a34c449d38397f503939c45",  # PipelineAst
    "0.1.32": "594c3dce689d902d090608c78dd55e49a9c1c2de3eab85f9eae24cafc99f3085",  # FunctionDefinitionAst
    "0.1.32.3.0.0": "870127df18b359aa10cb6230b70f2403b5477f12a2612ad575e892162dde0037",  # AssignmentStatementAst
    "0.1.32.3.0.1": "a7a29c9b9cb5985a0d48845b9f47eed1a1770dfe66d06c1683efb84a9c9e3912",  # AssignmentStatementAst
    "0.1.32.3.0.2": "3f0f5b4e65cb2385d9a432842fd893f584b10c9eadac23d563c6902a5af9f382",  # IfStatementAst
    "0.1.32.3.0.2.1.0": "0425c163ce9db76cd5533e28d39c55ef90dbfa2c871dde0c4a1b7214683c077b",  # AssignmentStatementAst
    "0.1.32.3.0.2.1.0.1.0.0.1.1.0.0.0": "94227cd1e445ba1bd0187056ffcc8021265be32ba14c4fc9169899fa13b7b2d5",  # PipelineAst
    "0.1.32.3.0.2.1.0.1.0.0.2.1.0.0.0": "ba6bbac9fbfd4e6b11cfbfe96dc17eb61c294c07b6b5ce7c18b61eba0189cb02",  # PipelineAst
    "0.1.32.3.0.2.1.1": "fefd3182bc84548b2b2806c3fb12f0a37e05646dc8eb3e322bc8de63e2f773e5",  # IfStatementAst
    "0.1.32.3.0.2.1.1.1.0": "8fc75c40a1caa64403c0a00a3ebaaae68015e18e1b52017bd6d5504db3d62f8e",  # AssignmentStatementAst
    "0.1.32.3.0.3": "fb88eddecd15a5c54786b63fb26f054ae4840b4ee2f4cccde378016d3bc4771a",  # PipelineAst
    "0.1.33": "daf7d5354586c803b5913a5126ccced16b6b3963ef0e9350d7328e059ff7e4cf",  # FunctionDefinitionAst
    "0.1.33.1.0.0": "58416e52306afaef594919209cf00cfb2904a2611bc28db9f9531f5602b80efb",  # IfStatementAst
    "0.1.33.1.0.0.1.0": "b9e9d5194d2a3ba29abd9ba214a1b3d69a1559e0e867621c0f324378ed9f6171",  # ReturnStatementAst
    "0.1.33.1.0.1": "5326ec7ebddb72e0b17b6193a56e798c0b8de217f8c8dea7f53db9da529ebc83",  # IfStatementAst
    "0.1.33.1.0.1.1.0": "a005d779a12e76a06ddf11c8b8ced6214ebad0bf31bf04a0ee6c248127903941",  # ReturnStatementAst
    "0.1.33.1.0.2": "cd9c88c9eaea4c12a54033db4209cd863a10f204e7019e0271e6b77d8d4092fe",  # IfStatementAst
    "0.1.33.1.0.2.1.0": "828981c3118a82d3fdffc6c85fcffc4147c9e4d8a1a61849f198a63428e696a6",  # ReturnStatementAst
    "0.1.33.1.0.3": "fe60fd0a4eefbc6e3325a2b892f88b037d75d717bb1a21e0fccc6305dfbd3116",  # PipelineAst
    "0.1.34": "18128926eb51e4b9488e4301c6a87685f5ac7471b3ea385d65aff5904ef6f717",  # FunctionDefinitionAst
    "0.1.34.1.0.0": "0f9d72496e42006a5cd8b73672337f9da3ba9a146b554716930337cb4cd01e26",  # TryStatementAst
    "0.1.34.1.0.0.0.0": "bf5a2fceb4ef4130977a17f70d173b730506b6da30e5350447747a179c116c0e",  # PipelineAst
    "0.1.34.1.0.0.1.0.0": "7dab99a7ed5116c93d11fc53f3acd9f38d5494c30f54ba36e292aeadda8ee66c",  # PipelineAst
    "0.1.35": "c1f89189dd2ebcf585fa829179d518ceb08d5dd9246dfc44352c86ddb40a28f6",  # FunctionDefinitionAst
    "0.1.35.1.0.0": "5c45cfedfb54daccc7e64ee528ff356d67be05750f01ff1407e0eed5b3a5ce18",  # SwitchStatementAst
    "0.1.35.1.0.0.2.0": "eb07e9427902705f1f9b1c4badf49078c1ab861de4f6fad11026b177095693cf",  # PipelineAst
    "0.1.35.1.0.0.4.0": "eb07e9427902705f1f9b1c4badf49078c1ab861de4f6fad11026b177095693cf",  # PipelineAst
    "0.1.35.1.0.0.6.0": "7a5cc521f2139e90f243ba7e57e1f19fa4d6c5f2aa61efdfce0bbf6401042b7c",  # PipelineAst
    "0.1.35.1.0.0.8.0": "7a5cc521f2139e90f243ba7e57e1f19fa4d6c5f2aa61efdfce0bbf6401042b7c",  # PipelineAst
    "0.1.35.1.0.0.10.0": "f3d15c75e1024c8ed568de5a4e06b495c64c145bc4a76d7599ae540a66060576",  # PipelineAst
    "0.1.35.1.0.0.12.0": "f3d15c75e1024c8ed568de5a4e06b495c64c145bc4a76d7599ae540a66060576",  # PipelineAst
    "0.1.35.1.0.0.14.0": "f3d15c75e1024c8ed568de5a4e06b495c64c145bc4a76d7599ae540a66060576",  # PipelineAst
    "0.1.35.1.0.0.16.0": "f3d15c75e1024c8ed568de5a4e06b495c64c145bc4a76d7599ae540a66060576",  # PipelineAst
    "0.1.35.1.0.0.17.0": "1a34d5df1046426b56eab1de9950d17e4448872b971e71b631f02d0745084554",  # PipelineAst
    "0.1.36": "d465fbbf37cd52c3d399ced051dbc9439706df8f2f315aba4c758ad36d763090",  # FunctionDefinitionAst
    "0.1.36.1.0.0": "f38e7b87263f7a8a9f82e39f377cf08cf4502d097c81a4f4601555ea12a68ce4",  # AssignmentStatementAst
    "0.1.36.1.0.1": "62242debfdb5c194de1ef8766c688e9197c0d86a4f53593623df64d82cee04dd",  # IfStatementAst
    "0.1.36.1.0.1.1.0": "0771c47aeff022cf4ac93a165d8967b368e6ad76aebcb4b057cce2b51965f9ce",  # ReturnStatementAst
    "0.1.36.1.0.2": "21098f0bc5589393095b4fd2007a4c6cd6b22e377bea55d39af81f3297238a53",  # IfStatementAst
    "0.1.36.1.0.2.1.0": "7418319ad9cf16a6f4bd8fc566876fc4435021c3d00ffc89179b416c28518033",  # ReturnStatementAst
    "0.1.36.1.0.3": "743a8da5af3082f33ac5ae7b915e28a1a44ca8bd98de3b57d98a3f3a70ee2368",  # IfStatementAst
    "0.1.36.1.0.3.1.0": "763c7c02148c39f3eedfe679844b46a0a2fbf0b843a065d3fd2054869b525bc2",  # ReturnStatementAst
    "0.1.36.1.0.4": "ef1e23650e206ad5b2e318a15c29b4ae45946f840c7191cdfdd6ce6950ac3d6f",  # ReturnStatementAst
    "0.1.37": "7e734f283f3c6349b6b290edae6b64b0034731f47e408c24c55188c823f51db3",  # FunctionDefinitionAst
    "0.1.37.1.0.0": "0a6501069d56269888ad4bd5cd761ca67556300a6d24a3a898e79cb03652006e",  # IfStatementAst
    "0.1.37.1.0.0.1.0": "0793c2c8f1f54afa67107b9d2f17385214e4cffe4f213498eacc6f1207cc2ea1",  # ReturnStatementAst
    "0.1.37.1.0.1": "40cd1f4f1d9ddbabab71b0c2973ee8c8fd3fd5c9d117966cd492eb93234ae767",  # SwitchStatementAst
    "0.1.37.1.0.1.2.0": "f30d08d1f33bbcc9d39c6dde20dc02bc63a6bd7871eb1b4a25500002bdb9db9a",  # PipelineAst
    "0.1.37.1.0.1.2.1": "2ded3b81bd771d1e736f8504965acf688bf879457960249083cc4779c09f8eb5",  # ReturnStatementAst
    "0.1.37.1.0.1.4.0": "f30d08d1f33bbcc9d39c6dde20dc02bc63a6bd7871eb1b4a25500002bdb9db9a",  # PipelineAst
    "0.1.37.1.0.1.4.1": "2ded3b81bd771d1e736f8504965acf688bf879457960249083cc4779c09f8eb5",  # ReturnStatementAst
    "0.1.37.1.0.1.6.0": "7cbb761aa8f395b7624be273b7d0cfbd32dd7b5ad65b0cfbcb1310e1d1773572",  # PipelineAst
    "0.1.37.1.0.1.6.1": "2ded3b81bd771d1e736f8504965acf688bf879457960249083cc4779c09f8eb5",  # ReturnStatementAst
    "0.1.37.1.0.1.8.0": "53a518f7079d5aeb02fd7ffc2e6fe26e8adca53e322d67daceba388a40bd0813",  # PipelineAst
    "0.1.37.1.0.1.8.1": "2ded3b81bd771d1e736f8504965acf688bf879457960249083cc4779c09f8eb5",  # ReturnStatementAst
    "0.1.37.1.0.1.9.0": "5d935e35c38b7c18dd809ced80e558700370dc8d83f902da8ff3d0c3ec3dc633",  # PipelineAst
    "0.1.37.1.0.1.9.1": "2ded3b81bd771d1e736f8504965acf688bf879457960249083cc4779c09f8eb5",  # ReturnStatementAst
    "0.1.38": "dfe80595f08b9a45e871993e702efcfa575102f0b070076362654162b22b14a4",  # FunctionDefinitionAst
    "0.1.38.1.0.0": "77f886fe75d2e2571262bdf3aa9a5a25a4bda61f93dea921bfc16b1ea8f5f4a7",  # PipelineAst
    "0.1.39": "6ef5da02439d74855a67f0eb37ae2cf8ea7b4f76bee083d9c44185295f396a84",  # FunctionDefinitionAst
    "0.1.39.1.0.0": "40b11af5ad2b50b870f1caa5788789aaa353b5a49dc3b5c2fe3419c97e84c34e",  # IfStatementAst
    "0.1.39.1.0.0.1.0": "063b9dc5736ff4d7ff61e200fcd0b218ee9835c7d7b5eae7fc40fe33b1f1b22f",  # ReturnStatementAst
    "0.1.39.1.0.1": "8d5d6ffd1679df100452453a302701bfec95869fb52d3083cc92f1d7db5ebff1",  # TryStatementAst
    "0.1.39.1.0.1.0.0": "c5fa13da544b6f19e0c7a0e79dca6e4af2cb92cc5f383684e5de2e86b501bfc9",  # AssignmentStatementAst
    "0.1.39.1.0.1.0.1": "b2e18f89d797bf035b40e67424411a3efebc244cd367c2fcf431f04792305842",  # IfStatementAst
    "0.1.39.1.0.1.0.1.1.0": "2a53e2ecdbe17cecc292217887c697974d4557dd5684c0aa04b5764ab5a6ea73",  # ReturnStatementAst
    "0.1.39.1.0.1.0.2": "a14cf8991e5d30eda71ee14679b4f23aa6fa0b8627d2214be53983c195136d6a",  # ReturnStatementAst
    "0.1.39.1.0.1.1.0.0": "035ec98905d39d836dc897c3156b2752626fb466f21eacca2c715b9b45e06e15",  # ReturnStatementAst
    "0.1.40": "79352b4362fd476bfdbd904828d5ecb135332f7c7e7d88bbe1b1db4d914ce41d",  # AssignmentStatementAst
    "0.1.41": "af0d2cb52c928cb7abb9ef35ec8a8d6aa9294cf6cc5a32a8ab8f14103ece3751",  # AssignmentStatementAst
    "0.1.42": "2461251cba7e0742e0d0521099e676fe722c18b228d56a39cc917be2dcfc62b1",  # AssignmentStatementAst
    "0.1.43": "9db0d9fbe31ce02821cd5357ccc9c11e09fd5ccea39e446d44d7cdaef9fd6156",  # FunctionDefinitionAst
    "0.1.43.1.0.0": "84a583474bc0d8eb2b3c7c22e550812bb23c0ae3827bfe63459b7c7273a859b1",  # AssignmentStatementAst
    "0.1.43.1.0.1": "17e69be1855d0fd39f8b480ddea8c31c8a8d34a5bf78dde9726acd30475465c1",  # IfStatementAst
    "0.1.43.1.0.1.1.0": "1b6b9b6e61d4e24362df41dc1abdf4dba965ea0523c828b69279def5c0ae06d1",  # ReturnStatementAst
    "0.1.43.1.0.2": "e63c376426f0e2e99769cae9eb1642e2caa62626db8690c74cfd56b01d6ac86c",  # AssignmentStatementAst
    "0.1.43.1.0.3": "cd400ac2f62a34357a0f94ecc18884a42fc10c06073e98036dc228f2397f3228",  # PipelineAst
    "0.1.43.1.0.4": "f7115acaea1983c3ab902790a3a2162f9f95c3390d08821d7387705314ba2dab",  # ForEachStatementAst
    "0.1.43.1.0.4.2.0": "b82f5a5bc1118d35d8a3dbb11fe421246df972073f23aeac3191380e71499dee",  # AssignmentStatementAst
    "0.1.43.1.0.4.2.1": "2988ecf4f29571b029fb2b04d0de7feadf450a3df62d354a0d141f80490f2baa",  # AssignmentStatementAst
    "0.1.43.1.0.4.2.2": "a18e77f854a46a289619d4e989d7254cdcf992cc77f739466665cdbbc19a03ae",  # TryStatementAst
    "0.1.43.1.0.4.2.2.0.0": "7cbabd68907ffea3d866840d0f2f0b35201e526878ccac2c46b4249315e34f03",  # AssignmentStatementAst
    "0.1.43.1.0.4.2.3": "1528acebd31e1441383ec6ffb2066a7e1ac1d66aab93657e3069e8f4134b20bc",  # AssignmentStatementAst
    "0.1.43.1.0.4.2.4": "ef23c9ad6bbc067a20cd0d2a959ac6170a5dd39781d15a3a6b4fbc3dc07f8af0",  # AssignmentStatementAst
    "0.1.43.1.0.4.2.5": "576b981a98b8748219289423f351c0f20b041d3511164e24c78c7a21a2d62d7a",  # ForEachStatementAst
    "0.1.43.1.0.4.2.5.2.0": "2b2c8c6c9a7078589b54d5094f91e4d9576a2695bee6eca98d19dde49093df2e",  # IfStatementAst
    "0.1.43.1.0.4.2.5.2.0.1.0": "0f2265e4b174f0bfb21f8ebb2c7c1e0fcfb0f1c8a261bac3343ce77b96a874d7",  # IfStatementAst
    "0.1.43.1.0.4.2.5.2.0.1.0.1.0": "f3aa10ff5502df72c52c2461d40e5ee52fcaa8034ecf4d56d85217b2c0401670",  # AssignmentStatementAst
    "0.1.43.1.0.4.2.5.2.0.1.0.3.0": "5682795495f82a5fd5c3b09ec8419f6a4574c909b27527d4939d8582b24adeb7",  # AssignmentStatementAst
    "0.1.43.1.0.4.2.5.2.0.1.0.5.0": "9e72f01325e7701ba1c5927d73ace88c72f91c3be7f8cc688885740917e88f93",  # AssignmentStatementAst
    "0.1.43.1.0.4.2.5.2.0.1.0.6.0": "5d6bf65096d9b101c03f325b243ba9daf0aa2cab93cf057b11df4a2560150206",  # AssignmentStatementAst
    "0.1.43.1.0.4.2.5.2.0.3.0": "ba95b31f6f0e0de0ce7e3cf8a26f9f1508e8045398ba385438cb4431f339fee5",  # IfStatementAst
    "0.1.43.1.0.4.2.5.2.0.3.0.1.0": "c12b817be4cc20cdd99f0fe12c57aa30f0d4af6ec79e8a8b2f82d6953c308852",  # AssignmentStatementAst
    "0.1.43.1.0.4.2.5.2.0.3.0.2.0": "306690fea6bf65b5014f5e14192a50939d7715f5d6785f09cefede571c05f618",  # AssignmentStatementAst
    "0.1.43.1.0.4.2.5.2.0.3.0.2.0.1.0.0.0.0": "2ae5953a59998b5d7b871cbe516133736f366c1dffb7224134a4c4343276e8a9",  # PipelineAst
    "0.1.43.1.0.4.2.5.2.0.4.0": "93e73ec4b22c24b8fb36ac51ab9d43e93593771795994792d69cbc55c88b4948",  # AssignmentStatementAst
    "0.1.43.1.0.4.2.6": "cadd6b9d4200791d451da538e2ff0fe337cb9652969f9c7af0991e5f2eea435d",  # AssignmentStatementAst
    "0.1.43.1.0.4.2.6.1.0.1.5.0.0.0.0.0.0.0": "2a657e190e3c915ed9756c4def53b988aab26da9c3df8aaa14b8870b946fe0cb",  # PipelineAst
    "0.1.43.1.0.5": "3df7e1a921121e7410f32ea0ce106536e772ae8a65c97625bc6c01b6395bdea5",  # PipelineAst
    "0.1.44": "15f5bd086ee8ae9e6e4ae5a0705d300614af2fc5553f73184897fd40e26d2a73",  # FunctionDefinitionAst
    "0.1.44.1.0.0": "1f9456ca2e2266102857f0ea54efb9e83158b11bf080adc38001631b52cee8ed",  # IfStatementAst
    "0.1.44.1.0.0.1.0": "acb7cbff93ec24662103a2b9308610adf53c75d7af334b428b51c202fbc32a2a",  # ReturnStatementAst
    "0.1.44.1.0.1": "d9c99ca0a370e3ea18a2d24334c2804fe0891f09113ab194c6166fde3d877ecf",  # AssignmentStatementAst
    "0.1.44.1.0.2": "fd2b9dcf9c2489ac8c684d2cf0e6bd286c97aa80ee60e19adde4af7995831e5e",  # TryStatementAst
    "0.1.44.1.0.2.0.0": "3ac35790d263c97cce667f775953ec318e65485c9026f83930667a3efb1e43b6",  # AssignmentStatementAst
    "0.1.44.1.0.2.1.0.0": "fda264266da79463cdd9fbf9da9d3e8dc51055c7ea51ae7f7648e1606b8cd0c1",  # AssignmentStatementAst
    "0.1.44.1.0.3": "dfee30be3979ff1ca12db28b50b609f4151e585859c24663dd4f24f17487798f",  # AssignmentStatementAst
    "0.1.44.1.0.4": "8f52948be290a5770b11b14976700adae0f5f9188caed12d08bc37887896947e",  # IfStatementAst
    "0.1.44.1.0.4.1.0": "b1e5a2569203b46b058e6e298f384bc717c13c118192928548b7258213d225d2",  # AssignmentStatementAst
    "0.1.44.1.0.5": "1a28ed187c2ba5ebba5d5668a48ed5cb3e9b3eb45b5661a0134c5923673c3d1d",  # PipelineAst
    "0.1.45": "ccbedb5609f78e6c81c0068e376bf1f5690bf684eb31b84efaac0591dd861185",  # FunctionDefinitionAst
    "0.1.45.2.0.0": "2ec135b4b499df3a164034184171c5247d4240f2e5b967af67c92c36a87e4b7f",  # AssignmentStatementAst
    "0.1.45.2.0.0.1.0.1.0.0.0.0.0.0": "f5c53d1ac4004e86eefd7001dcbba5e61b58cce7114cd5f6dde57f44ffabf179",  # PipelineAst
    "0.1.45.2.0.1": "5e49a58bbc0b0a97de6d910a0221304f649676baca6294aea1efd5d06719f89e",  # PipelineAst
    "0.1.45.2.0.1.0.0.1.1.0.0.1.0.0.0": "69129633829cf5ed43213053dc59645cc6e36ecb786c61c7b7d800d56a8ffba9",  # PipelineAst
    "0.1.45.2.0.1.0.0.1.7.0.0.0.0.1.0.0": "09218e0d816dddfcef782826cd227ad1526af42a1f172cafa8f9707814b35747",  # PipelineAst
    "0.1.46": "be2e612268241074812e9d891b68a790308ac00d48c20a97ece8c64aa79f8b3f",  # FunctionDefinitionAst
    "0.1.46.2.0.0": "4e63d08f476d211e205c2f9d2afe4478a0bfc68b97719be895dda48ed38d967a",  # AssignmentStatementAst
    "0.1.46.2.0.0.1.0.3.0.0": "51a573f00557c6699befb6e72a3552df87d1db6b6a2a15e2bfbed1b48e9a23ee",  # PipelineAst
    "0.1.46.2.0.1": "3131d6eb9d71ba5d506b7715b7cc534d54b6e071ef1374e6ea2fba9a7a9a2ba0",  # IfStatementAst
    "0.1.46.2.0.1.1.0": "0793c2c8f1f54afa67107b9d2f17385214e4cffe4f213498eacc6f1207cc2ea1",  # ReturnStatementAst
    "0.1.46.2.0.2": "340a6278df637f45fefb591d72322092e37d402b0be93654265bd607716ec5e7",  # AssignmentStatementAst
    "0.1.46.2.0.3": "9dc0bc48cdb5fd66742c0c3a5b43fb8a78197f765482517b65a2cebdbcb502a3",  # IfStatementAst
    "0.1.46.2.0.3.1.0": "0793c2c8f1f54afa67107b9d2f17385214e4cffe4f213498eacc6f1207cc2ea1",  # ReturnStatementAst
    "0.1.46.2.0.4": "648afdfab92df55f686fb55b655a54e66fc8f9997774f6074ffd4db53ba70cab",  # PipelineAst
    "0.1.47": "aeb5cb0b4d46924588124773bad7a752a9b2024d26a9ed00ef237df8f6ff6c67",  # FunctionDefinitionAst
    "0.1.47.3.0.0": "34be4343449eb0fb69c551f0cea904cd16173a2864202372b4b0d938444a6be0",  # AssignmentStatementAst
    "0.1.47.3.0.0.1.0.3.0.0": "51a573f00557c6699befb6e72a3552df87d1db6b6a2a15e2bfbed1b48e9a23ee",  # PipelineAst
    "0.1.47.3.0.1": "7339debbbd602d97592cb2cf44571e06538d41491ddfe7b2d90703e1da401faa",  # AssignmentStatementAst
    "0.1.47.3.0.2": "4ca66c670d1ce4bddcaee943296a87fd44ae694d94f42f683c312362b69ec64a",  # AssignmentStatementAst
    "0.1.47.3.0.3": "ea3fc2c5e2acaba67e69c15608c19541b05d4e643be73201773597780e416dfb",  # ForEachStatementAst
    "0.1.47.3.0.3.2.0": "2d6864ea7aabf7c5634f8e84e151fef1251ca619bdf39995e20d4dc7ffdb35a3",  # TryStatementAst
    "0.1.47.3.0.3.2.0.0.0": "38465f820afd2664804c30ce28dad455a553c00614e8dd8c895c6f4e289ad0e5",  # AssignmentStatementAst
    "0.1.47.3.0.3.2.0.0.1": "5604ebb23d11fbfd3570e11a458146eacc1e5f5c2fd89e1cd2edda2c7c2af659",  # AssignmentStatementAst
    "0.1.47.3.0.3.2.0.0.2": "8c196ca4d92b704ecdaf54b16d31f908c12e73409bb732bcda5954568e5f9e11",  # AssignmentStatementAst
    "0.1.47.3.0.3.2.0.1.0.0": "eabb0b69fd05ec10f1702098b6f7682f2024c0a28ea5a07a09ef616483a08a0b",  # AssignmentStatementAst
    "0.1.47.3.0.3.2.0.1.0.0.1.0.1.0.0": "8f4e41e0accbebd5e3f2aaeee043b5d0dc36dcca88b271971bcb3388d85ccbcd",  # PipelineAst
    "0.1.47.3.0.4": "ea661bdcf04176194c34d1259c4b6c464ce8ebe583ea8c9c438669c6bfe0383e",  # PipelineAst
    "0.1.47.3.0.4.0.0.7.0.0.0.0.0": "baeee068c015ba0e32b784c2fba6dd72e155e570c3d69a72b736b69d87aa2142",  # PipelineAst
    "0.1.48": "4528459dd005966f0b7c51bc5adf4b1dd73baf6b46ac38c7372813d6e715efb5",  # FunctionDefinitionAst
    "0.1.48.1.0.0": "3463dc9c3d8413d8e4b5d69c605352d566339d0f46e114378446e0538918f440",  # IfStatementAst
    "0.1.48.1.0.0.1.0": "d8f1d542dcaa67c72f743349995f2a38d05b2bddbfb1cc82446184dd39b77473",  # ReturnStatementAst
    "0.1.48.1.0.1": "e0e4d48c8019bf6b87a8a11826f9dc907298a982e36295f9cab6f589e4631f50",  # TryStatementAst
    "0.1.48.1.0.1.0.0": "9da74291b2d9ca696c2ecc84d044b72566c83ca599c9cccd7f6f26ace0f29de0",  # AssignmentStatementAst
    "0.1.48.1.0.1.0.1": "bd9f6a204db3bfbcc93287e8b3b550fc3b3dfff10863f484cb0166122be1bc51",  # PipelineAst
    "0.1.48.1.0.1.0.2": "92d9e3a2749638b66cf1d0cbd4eb4551bd5806fde00013f862d91ebb8c868530",  # ReturnStatementAst
    "0.1.48.1.0.1.1.0.0": "1d10e422938050b8eda8940d08b1df66788fe13f1869892fc6161b0d18702b6c",  # ReturnStatementAst
    "0.1.49": "fdd41915e6b87c6231605d3622b4f2aa3d44c9e1acc4f5fd5bb0e0438922db2f",  # FunctionDefinitionAst
    "0.1.49.1.0.0": "43410313ee711c9740095a1db8950962f9c786a53db2849da1e46b4edf843586",  # IfStatementAst
    "0.1.49.1.0.0.1.0": "acb7cbff93ec24662103a2b9308610adf53c75d7af334b428b51c202fbc32a2a",  # ReturnStatementAst
    "0.1.49.1.0.1": "2aa5301cce211f08c3e3128232960aa47828e16377f119f61395122378c8f01a",  # TryStatementAst
    "0.1.49.1.0.1.0.0": "725e64f566bcb5a856dd8157cff1a3b5648d7ac522e82cb0198c74b8ebcaad4f",  # AssignmentStatementAst
    "0.1.49.1.0.1.0.0.1.0.2.0.0.0.0.0.0": "bedb4480b7cf7c42b52db5eab3880eeb13e97e9ddd050590179ba950846a6d3e",  # PipelineAst
    "0.1.49.1.0.1.1.0.0": "b60174ff60f01121f29512728e6d1cf533c5df6cbebc844f317c8682ef88ace3",  # ReturnStatementAst
    "0.1.49.1.0.2": "84a583474bc0d8eb2b3c7c22e550812bb23c0ae3827bfe63459b7c7273a859b1",  # AssignmentStatementAst
    "0.1.49.1.0.3": "2b9b8218041e290f15140231a0afeed3656babe528c6e5357d09c2ef31d7504e",  # ForEachStatementAst
    "0.1.49.1.0.3.2.0": "5478eac96c01a97a7d6657c458b51d6d62251f6a48d99b8bee233e904fbf1117",  # AssignmentStatementAst
    "0.1.49.1.0.3.2.1": "ef23c9ad6bbc067a20cd0d2a959ac6170a5dd39781d15a3a6b4fbc3dc07f8af0",  # AssignmentStatementAst
    "0.1.49.1.0.3.2.2": "02f77956a289c1d54d42025dae99a85d18e0c39c528a602f3e23769f7552ea2c",  # IfStatementAst
    "0.1.49.1.0.3.2.2.1.0": "664e1abe4a31c4cf63d6e7eaf916220d5aaf56b5d8d9f7442d06a87ff7c94aef",  # AssignmentStatementAst
    "0.1.49.1.0.3.2.3": "eca8b08d13e0403abb1dfc9db191d0e65e65561cf947ee184ee26ef5e0242b17",  # IfStatementAst
    "0.1.49.1.0.3.2.3.1.0": "6c53bb6dfae0f8f264a01065e158e431bece67dd84f4c2a490af03e3982c4c2f",  # AssignmentStatementAst
    "0.1.49.1.0.3.2.4": "82228bcd382698c4e72bbf3019d5a51ab54eb6cb3183320b391a990a2f0f28fb",  # IfStatementAst
    "0.1.49.1.0.3.2.4.1.0": "9e10a14f0cd867ab63615b34c8d8783809dd99c2c0ee0cef8208c7b7328ca95e",  # AssignmentStatementAst
    "0.1.49.1.0.3.2.5": "d54b38f2c2b0b9a6d67231afbde4baab9af17a02c4d3971c2b8dff74a8e7dc56",  # IfStatementAst
    "0.1.49.1.0.3.2.5.1.0": "4de558f472b7654f437e48cdd904549eb7b536039a1179a9b99f38faaddfe384",  # AssignmentStatementAst
    "0.1.49.1.0.3.2.6": "35a5af044a102c15495c1d6043b8e34dc1f801c96db3c1c91e9ecd3914461704",  # IfStatementAst
    "0.1.49.1.0.3.2.6.1.0": "3f21935418a3e9e643f6c78d5c9e61921c30f3aaaeb7647d883067317816162b",  # AssignmentStatementAst
    "0.1.49.1.0.3.2.7": "10fb619add664b5183be0629ca1a163a31d80a9bc145dff6e6093146fbf8e9b2",  # IfStatementAst
    "0.1.49.1.0.3.2.7.1.0": "c3d1183f0017247ec2235384a0070d2f0dd6107884c559ee25650ebe1931a0f6",  # AssignmentStatementAst
    "0.1.49.1.0.3.2.8": "33d957ae897df2c0f166632e2df6bf93bc1e38001822d961f1c853081c3c0b78",  # IfStatementAst
    "0.1.49.1.0.3.2.8.1.0": "4b79adb74b8285585cbe97c1a474bc5ddf4262838d76e19ccf03e38ccddb3dfd",  # AssignmentStatementAst
    "0.1.49.1.0.3.2.9": "d46f99514e86d7a4bedb8960752b9a718e053def8f1d308a004d33d7aed1970e",  # AssignmentStatementAst
    "0.1.49.1.0.3.2.9.1.1.0": "9700ebc70691fa760d25a7afb5301937ada001b4516a6240de07dd1ea06954f4",  # PipelineAst
    "0.1.49.1.0.3.2.9.1.2.0": "81e6edf08585d3829a3cd82e81b3aa66390166de8f09113257a637d046a91a4c",  # PipelineAst
    "0.1.49.1.0.3.2.10": "fe7ff1447edf89296e6fb54b01de04fe74d3e9eb45e9e1de470c6511c7d98629",  # AssignmentStatementAst
    "0.1.49.1.0.3.2.10.1.0.1.5.0.0.0.0.0.0.0": "2a657e190e3c915ed9756c4def53b988aab26da9c3df8aaa14b8870b946fe0cb",  # PipelineAst
    "0.1.49.1.0.4": "aa04992f0ad835770fd4bcb1b29d41215af0286c45e01956545d3a8834bb8961",  # AssignmentStatementAst
    "0.1.49.1.0.4.1.1.0": "9be7567ce6ebc340e528fc5304c91b4d1469a4fca63972090ec7116d0d5241f0",  # PipelineAst
    "0.1.49.1.0.4.1.2.0": "c36980a9a454befe672ded34688afcc656a0e6538bda177841328431c1af3740",  # PipelineAst
    "0.1.49.1.0.5": "7d71f3e22492b49f964c01fdc39e116e4a61273af6de90de6fdaa2f06d44a617",  # PipelineAst
    "0.1.50": "a4a2219101fea55704acebc01b4bcf80b8ebf5aae1e15b4e2cbf096e7d647146",  # FunctionDefinitionAst
    "0.1.50.1.0.0": "a52b3d323a674f8b9245d9be8af8198058a702336d135870469e247409479b05",  # AssignmentStatementAst
    "0.1.50.1.0.1": "9f7882877e9bd9d172fed8992bb82740cf1e5a2ff4c48e6003900ce137d6a01f",  # IfStatementAst
    "0.1.50.1.0.1.1.0": "bd56b926e5e094fd8a487ae09efcabe8a1964b16260715daaf13241a10d2ce8f",  # PipelineAst
    "0.1.50.1.0.1.2.0": "0daf7c4362278864e4466a84bc9d4d483eacb94d7c66412063105183132ab43b",  # PipelineAst
    "0.1.51": "e251931e6cbf968ee0528e6bb3d397f7af4bb7b4d77a3c1b73776ced4f2bee39",  # FunctionDefinitionAst
    "0.1.51.1.0.0": "081fcd68504c66a235e9398216ae1020b53bffecfc7bfbf2a236e37fc27b61a5",  # AssignmentStatementAst
    "0.1.51.1.0.0.1.0.1.0.0.0": "1e118024ed8ce7efcfc1487856df95b16efcc10a5dab1a7fe805402207f43acc",  # AssignmentStatementAst
    "0.1.51.1.0.0.1.0.1.0.0.1": "6b9f1921bafe7af67a88f31fe2e21a02774f962e1e8ff901fedd92335b240a4c",  # IfStatementAst
    "0.1.51.1.0.0.1.0.1.0.0.1.1.0": "b32b5996c777ee35cdb98104a7ba7b050248703dd32dc96285351520fde05fea",  # PipelineAst
    "0.1.51.1.0.0.1.0.1.0.0.1.2.0": "6a1547d49262cbb7d1f8b5cc282d4d2ab9eb92d28431c21fc55479498abbe763",  # PipelineAst
    "0.1.51.1.0.1": "f8de09ff7ad98befaf4090000313cf199f476965d9091a1bbceb09c0b536e95a",  # IfStatementAst
    "0.1.51.1.0.1.1.0": "acb7cbff93ec24662103a2b9308610adf53c75d7af334b428b51c202fbc32a2a",  # ReturnStatementAst
    "0.1.51.1.0.2": "5de84fef855d5142bb7d0a863aef59f192f5082e52584dbcdb5aeae318c5b424",  # PipelineAst
    "0.1.52": "da226d1c1db0c7ced6eb24d65b2c3fa88cc68902c7130528664a2aaa7678532a",  # FunctionDefinitionAst
    "0.1.52.1.0.0": "7e8933cd5a72a12a812ba18de971ddc3a0c25185188a6e83238e4555bc136da2",  # AssignmentStatementAst
    "0.1.52.1.0.1": "0888c75272361925dd9ce34192fd30014bc43d646cf3bdd45923775448642df3",  # AssignmentStatementAst
    "0.1.52.1.0.2": "c986f28d76e44f329f6bef9b826cbccd8ea28d95c9738d9255874f126808880e",  # TryStatementAst
    "0.1.52.1.0.2.0.0": "60617cd56fcd2dce91a77c48499700038ff83d614917be205911d817c0770451",  # AssignmentStatementAst
    "0.1.52.1.0.2.0.0.1.0.0.0": "b7decdb14ee24c90d339a0da4b64dbf98a5029c12490c4da7309119ae89d4675",  # PipelineAst
    "0.1.52.1.0.2.0.0.1.0.0.0.1.1.0.0.0": "2bddd672fa7cc447a2e0c23c1b21a3a414225bd8bb29d26bb6e64a04a7f50b64",  # PipelineAst
    "0.1.52.1.0.2.0.1": "518e4dc8b1beea8725c89db5e80a95aac8e40f0c5c0a0db5cb1097aba166fac2",  # AssignmentStatementAst
    "0.1.52.1.0.2.1.0.0": "5bd888a844932b6635caf735402eb65da29948ac89da8b1ec34c4d6ffb4330da",  # AssignmentStatementAst
    "0.1.52.1.0.2.1.0.0.1.0.0.0": "a16a24b1cb751ba5e0dca4bf160aec1c9b8ddd02efc1512f556639ca75879b8f",  # PipelineAst
    "0.1.52.1.0.2.1.0.1": "e2ad8d7af40b459251da21e55112a5d7cca6b77199ff52dcd8dd4bcc89d6ab9c",  # AssignmentStatementAst
    "0.1.52.1.0.2.2.0": "39b94b8c4d014bcd7486e09be990d83ed6bb6ac37aba41b1a08acd05030ac0ea",  # AssignmentStatementAst
    "0.1.52.1.0.3": "bf5a4d0a9cfd7432e2629332bcd617ba7a63065abde920b6cc7ab0e480d5fbc0",  # PipelineAst
    "0.1.53": "bb646b1fd740bcb0ace327c2e0727838066bcf8166109bac45737671e32f74ba",  # FunctionDefinitionAst
    "0.1.53.1.0.0": "2f293a4679bb80cb230d8db11dc37c8eccaa5408f57a2df503e6bd4907426888",  # AssignmentStatementAst
    "0.1.53.1.0.1": "f4406d31ee1b11b98c265690f47a648df3a7d8e3659e7c0030687a1dd0218379",  # PipelineAst
    "0.1.54": "d1a093dca087d61a37eea6ded63b2069bb75844f9b3e5c922fb9c21e2db1c54c",  # FunctionDefinitionAst
    "0.1.54.1.0.0": "2f293a4679bb80cb230d8db11dc37c8eccaa5408f57a2df503e6bd4907426888",  # AssignmentStatementAst
    "0.1.54.1.0.1": "1043735968c31321b055f2d52c56a7c1e6fbc213cf75f92fdd197752e25d0514",  # PipelineAst
    "0.1.55": "977f8c53fb9f6246477ed956c6601ff67758ceb062f8803780108e0f17767a7e",  # FunctionDefinitionAst
    "0.1.55.1.0.0": "2f293a4679bb80cb230d8db11dc37c8eccaa5408f57a2df503e6bd4907426888",  # AssignmentStatementAst
    "0.1.55.1.0.1": "e7b2b47ac6d10a0bf66b511f6642fb559e22a436a751aab707eb5e995344836e",  # PipelineAst
    "0.1.56": "1df0d97a2c06ebea5aec5fb67f41a11a2a85ae9a3200c32aba1d237c671e1520",  # IfStatementAst
    "0.1.56.1.0": "2f78da9390acae21a0c5375207614adf9099956abc78c417a8ffccce66d84b27",  # ReturnStatementAst
    "0.1.57": "60a07942773e6aa2c843ba9750cf8962a8f2cee3c91ed2e9d791c45aa8e0a3e3",  # AssignmentStatementAst
    "0.1.58": "b0a42df639e06cb6d6c78144029ba21bf2ac58f0f16791aa196af0d30a5a3d21",  # AssignmentStatementAst
    "0.1.59": "80cc832733cfbf7bd49f627dd48d2e4e8c5835b4dd66c17fbacc5897d1538e98",  # IfStatementAst
    "0.1.59.1.0": "1dc4e5295c362aece92b90d17fa5a2c216135032b5a14c1a6deaca5c4c9bbdf0",  # IfStatementAst
    "0.1.59.1.0.1.0": "dd6bf9ff9ba2c270f3819efa50908e7980ed77aed1502f4dd426756aa32d0a00",  # ThrowStatementAst
    "0.1.59.1.1": "9149a41e671bc51a86518596555eb308a904c8f6c036802ef0b12f720c7df741",  # AssignmentStatementAst
    "0.1.59.1.2": "5ba15fb116fec6a2f6a89ac62b67b88ee6242092f6d9d9c39611865e4cb60c5d",  # AssignmentStatementAst
    "0.1.60": "92909fc0f157b0a768ad546aaea42f0a911dd7d95ddc08088c16534240e0e549",  # IfStatementAst
    "0.1.60.1.0": "5d50d83c729ac6c541586ea1afdeaa18c96efd42d6264a0e7f7b672a4c2a785b",  # PipelineAst
    "0.1.60.2.0": "29360d3e4b3208db104c44afd5f17e4c36cf9e35ef7c7cb2d8e5eaa2791f3fd9",  # PipelineAst
    "0.1.61": "5fc30d0230730e79bacc86fa266b0b28ea7fa8fb86614c7dac550225cb661fc2",  # AssignmentStatementAst
    "0.1.62": "2f7c374c2927e7f19e62457aefd0b971665b58f604fda53686197b0267e412e3",  # AssignmentStatementAst
    "0.1.63": "32985e22ba9b60d996577425ad5f9d4629eefe37f0e2bcca933d5f48f189c003",  # IfStatementAst
    "0.1.63.1.0": "625ddc65e50a221412e12b048042507450daf0ca7ce5c471e61a50072e6a1744",  # IfStatementAst
    "0.1.63.1.0.1.0": "ac2672599273331467d2ddab2d57708feb3f390f1798b48cfb5b40290730869c",  # ThrowStatementAst
    "0.1.63.1.1": "0a474b891683ff020001e00b3813ad658d337cf264caf4af1c0f5aa19bad5383",  # AssignmentStatementAst
    "0.1.63.1.2": "324c08ba0577090c24211a95e00ecafdebac972f58da8e6803c95c886cf7234a",  # AssignmentStatementAst
    "0.1.64": "4b5fad48c1046971fe72b612b97bca61917c6c3c2b8f5c6c53d222ad035e1780",  # PipelineAst
    "0.1.65": "d5ae0a327d278de702e2e2c06b25b1367d8fe636c06b93ab509427f17d50ed01",  # PipelineAst
    "0.1.66": "7cc60de97672be7c1eda274634ddbef64bd7f4a3f8e2eccfc7f87969128215c2",  # AssignmentStatementAst
    "0.1.67": "7e2402ef633996173d57a986a471318835e4c9cbdab669db4bac98c6a331a4c0",  # AssignmentStatementAst
    "0.1.68": "bb890807f4588a08a334da9de6aca1d42598a58e4cb2f65ace497670e5076506",  # AssignmentStatementAst
    "0.1.69": "f5e6e3e61ebf6bcd060afa5856cfa6a65a211e4e37f6090c1d529846f4a1b8d9",  # FunctionDefinitionAst
    "0.1.69.4.0.0": "05464a5811957899f0595b2d8c99d0ad373340346eaa8e10ebfdb8e28a28b95b",  # AssignmentStatementAst
    "0.1.69.4.0.1": "b9a92baf8f1dbd76b7ac954bab8f27f6edccb96983c4fa87fc44317f376f3ce5",  # IfStatementAst
    "0.1.69.4.0.1.1.0": "a84273a78b5f4e8ccbb3c814e2e4738c6021d1c8a58ad119277f3bcf6ae663eb",  # AssignmentStatementAst
    "0.1.69.4.0.2": "fa153a5a31c70eb150c0f1dbd5fdb556471dea28ae0813b258cbde91e5174c2c",  # AssignmentStatementAst
    "0.1.70": "3ff9c062994edf721f63132afebe3a7724945e028664e0098f7b5449000b33b7",  # FunctionDefinitionAst
    "0.1.70.6.0.0": "5cfa5d0c1e192a71235ccf69ef55a70facb40225f350a18a7481c8812b8fe079",  # AssignmentStatementAst
    "0.1.71": "ed6b1a60ace1b3e0263c6b088f084ba0fb83db6f0c593ae33099ec1b87574d7d",  # AssignmentStatementAst
    "0.1.72": "2290ed392f97c0b03b6c9631ec9451239784ddd53e7321063c34d4d85a709d20",  # AssignmentStatementAst
    "0.1.73": "9cd4b3db49451b6c048de09d92a5757ee48520da806191f66c69ab10f01af604",  # AssignmentStatementAst
    "0.1.74": "b34704f527a778b0034087f84aad86eff2b298540de640877a43b7f639b3d2d6",  # AssignmentStatementAst
    "0.1.75": "35eb9949ec9fe50bdb831e916e203ec9d0c1dc050936b63b9b28cb1dd2b90c04",  # AssignmentStatementAst
    "0.1.76": "93b68ed4ae34ab23141cc31d3851e9cb585d77cc35d701b541b97bee00bb3229",  # AssignmentStatementAst
    "0.1.77": "f5b9dfe14a65c72d5cc70fd1cf93da5f6997874f822fe8b5cf68db2998f0a30c",  # AssignmentStatementAst
    "0.1.78": "c0c73fe2a63b7b8e7326de530a5fb31f9073dc77c75901cdfa187c56f1933128",  # AssignmentStatementAst
    "0.1.79": "9b44a6a9400c1212693f479eccc214735d9d45e3075815bd7b149e7c30709585",  # AssignmentStatementAst
    "0.1.79.1.1.0": "80ac4efd0a3a329a3b4ef0d3645307c6098326f60904d8b28d6f19a9dc94c9b2",  # PipelineAst
    "0.1.79.1.2.0": "fa6bee860a6834497769417f59d9a0a5de75c115a1912e973576e9addabbce4e",  # PipelineAst
    "0.1.80": "205b110944362949e2523030bafdda9d9eb037ab8a5d6f4c9bcd843b8fa6e614",  # AssignmentStatementAst
    "0.1.81": "55387306ef34ab5e014fb3b7704a85cb0a8a3e6ff5b7a4d9991ddadf43ef7c51",  # TryStatementAst
    "0.1.81.0.0": "b788cef2f652eba0033afc4503e48f75f9aebe10ebff02cc4c2e3c13cdbb8d4a",  # AssignmentStatementAst
    "0.1.81.1.0.0": "7a83be1278b7f6547b646fd5c5db5beab281e70640d49c2ca664e7f477b0813c",  # AssignmentStatementAst
    "0.1.82": "9ef9a0d58d792d3e8df069971fc8cc0b5156d501197e8db419c3613a4cafd00c",  # AssignmentStatementAst
    "0.1.83": "1d38cc544543964cc3e0c85bd3e2b13c8894ed08cffeb2f01078d3c937cd3ff1",  # AssignmentStatementAst
    "0.1.83.1.0.0.0.0": "c9b4966b7222eab5352c111439c318fd1b4d41015e0def1a424a9f0a73494f17",  # PipelineAst
    "0.1.84": "a7115e9a929e12c41367c5fb309519cf2f3b2001d5487a0008f4635ac065bd8c",  # FunctionDefinitionAst
    "0.1.84.4.0.0": "979aecd4306e522a62548c7214753a09445e5bf7f09e2c7c95abd443f8b9f6c5",  # AssignmentStatementAst
    "0.1.84.4.0.1": "d606be6e72f788ddc1b1b37c22dd7de3bd6d4828ff3fd43b0a1ded744d507383",  # AssignmentStatementAst
    "0.1.84.4.0.2": "07efe3bcecdef3c28583cd197c007dd029f6db3c63cca65cead2db6c40ebd255",  # PipelineAst
    "0.1.85": "71905f5c218a859cb3530afac9db788c8a51af75a1ecfe7c560bcc914c3e77d1",  # AssignmentStatementAst
    "0.1.86": "7f21588bf6f220acbb3991b41994287a62906bd2ecaa418fc7da85e8cc981657",  # AssignmentStatementAst
    "0.1.87": "1f8d3dd8290f361e09dfb59b1e55c3f1f10a2e8ce9f15b9262c2da4bba80e112",  # AssignmentStatementAst
    "0.1.88": "b82d26f52674afce093c6ab0198c4886f83492601cc60e90ba1af190bbdf06cc",  # AssignmentStatementAst
    "0.1.88.1.0.3.0.0": "acc4b01c570fcce7d296585c445cf1899e6a0cf0e285207e956007a1c9c6ad60",  # PipelineAst
    "0.1.89": "064765db4e8cdf75928ef0d19769875e6b2abb420a63b5d8b860618b065f9053",  # AssignmentStatementAst
    "0.1.90": "29955e604bd6c67ea6a1e00e93e9abe1188e4a362d311fd32d70d0453d91b763",  # ForEachStatementAst
    "0.1.90.2.0": "89d9fe53a75e02aa5110190347fc65772ca34f8061d75db8f8d27615055c2a34",  # TryStatementAst
    "0.1.90.2.0.0.0": "a7e9729a7c289b0c19f9e5e6f88dcb024b0ef4943629da145a2b555233baa025",  # AssignmentStatementAst
    "0.1.90.2.0.0.1": "4ab9935f4eb3dd13e1c03fb62e0dbd972c665ed90fedd5beb9a5ded8d02219de",  # AssignmentStatementAst
    "0.1.90.2.0.0.2": "669126b1cd0e85b22b53f8c730ec33d2ba48fa0b8b2ac978718083318f7bfe05",  # AssignmentStatementAst
    "0.1.90.2.0.0.2.1.0.1.0.0.0": "ffba7b748f843198e29b12c0c1a12ba41f103fb700b59850d21ea3e62b7ad9bb",  # PipelineAst
    "0.1.90.2.0.0.3": "9eb334498566b158aa2a9b058bbef4e57007d769c3cd82873711966fa5d9828c",  # AssignmentStatementAst
    "0.1.90.2.0.0.3.1.0.1.0.0.0": "4baf46725a2ef47a1430efa57a7b9e45b03c499bde254d9098c6bdf71b747488",  # PipelineAst
    "0.1.90.2.0.0.4": "a83e828e008b5fa6bc7db48447c3b42235961be30bcd8d299708ee7295f6cc43",  # AssignmentStatementAst
    "0.1.90.2.0.0.4.1.0.0.0": "90de237d0f13f0aa76e9407854ee743b4a34f8fc03c2f18719b58358c295c58e",  # PipelineAst
    "0.1.90.2.0.0.4.1.0.0.0.1.1.0.0.0": "e3f0f197bcd21813886df6fabc7996c9a5536587c23fa875bd4cf4a7dfc255a7",  # PipelineAst
    "0.1.90.2.0.0.5": "3d5fbb1972d85230553d99f7191c6c8103f00ed79adcf6a5a1ce47bfcd1092f8",  # AssignmentStatementAst
    "0.1.90.2.0.0.6": "388bd86ba6025b9b3c0ce5b06e3fed5b3f486216924774a80e70ec1d7b2f2107",  # AssignmentStatementAst
    "0.1.90.2.0.0.7": "b013688d4fe04e89ba0ec670a14da53e8e865f01700401f4dc58cc3bb8196abf",  # IfStatementAst
    "0.1.90.2.0.0.7.1.0": "f734194f30f6639f6cf6baadb8e4568da7b09de302be5baac91a4c358bc0dadd",  # AssignmentStatementAst
    "0.1.90.2.0.0.7.1.0.1.0.3.0.0.1.0.0": "09218e0d816dddfcef782826cd227ad1526af42a1f172cafa8f9707814b35747",  # PipelineAst
    "0.1.90.2.0.0.7.2.0": "7b5bdf6d79fd9b19b435ad70e3f16284b91134e37b74e020af3196c83412832e",  # AssignmentStatementAst
    "0.1.90.2.0.0.7.2.0.1.0.1.7.0.0.0.0.1.0.0": "a4b51cf7e6856e1aa3ca5917b8e5df9257b9bce249c2f88cff2d6bce4adb843c",  # PipelineAst
    "0.1.90.2.0.0.8": "c4413cd9a9f4ee30e9b2bd84583c2d44c8bc0999ee9e277b4aad1823e56c6e64",  # AssignmentStatementAst
    "0.1.90.2.0.0.9": "fcb1b30fe4aa8b6d22a458bd18d3a24f2433701bacec6a4064db987961bec4bd",  # AssignmentStatementAst
    "0.1.90.2.0.1.0.0": "fd5b56ad877bd97a3d68413511d9c1e00fc47c05d16fdd3b0d7a7270be2be959",  # AssignmentStatementAst
    "0.1.90.2.0.1.0.0.1.0.0.0.0": "b36c511c08f8126275b0c76e1ae47fc2e1f5f5795c8ed8dba235fcaf7aa505a2",  # PipelineAst
    "0.1.91": "39bc1d9e0e0c87e562fd55d0d8ef03bf424a012a6a1898b73f60ac9ad1d9ce72",  # AssignmentStatementAst
    "0.1.92": "119d856001fff494a38a388118a383caad17b91a57438061932e9a570d0bbc7e",  # IfStatementAst
    "0.1.92.0.0.0.1.0.0.1.1.0.0.0": "00f2324baf0685cfb100836b5c656d9ea77196c5cdb6ec09b76f9dc911f9ad5f",  # PipelineAst
    "0.1.92.1.0": "b471ea61cd800f03edad37576b4d457da99ac24e2ff0a3d075eb9b2df6389912",  # AssignmentStatementAst
    "0.1.92.1.1": "2f9bd712e9196e7a250f7b8b1dd9cc489f6c9816fb325e880bfd591266da83c3",  # AssignmentStatementAst
    "0.1.93": "c371b39306169bca81a247a2b77ba1ffa000e7e0d2550a2f72f95e16de3c6248",  # AssignmentStatementAst
    "0.1.93.1.0.3.0.0.0.0": "311008469361c7f9be2fe3d48f2c17dc2ec1d12dcea01d46dedcc557ca473ffd",  # IfStatementAst
    "0.1.93.1.0.3.0.0.0.0.1.0": "5065689417598b1c8e64be4fb5004b19f394287d5d856e8590f14e5e2041e054",  # PipelineAst
    "0.1.93.1.0.3.0.0.0.0.2.0": "58c3f502e335dd097ad507564e55e7a2b2e75d7637b31ac189832f9c95081993",  # PipelineAst
    "0.1.94": "bdd5a0e483b1f194b9940298deac8d70838efc207f9a998a1a03fc362c3103ab",  # PipelineAst
    "0.1.94.0.3.0.0.0.0.0.0.0": "43f717af8ff316ad591b15d1e4bedffebb8bb5a2abe18ede8796060e33bcf388",  # PipelineAst
    "0.1.95": "a2fcaa45d622355002276a564a45195cbbd964150788ae618646bae61cfa61be",  # PipelineAst
    "0.1.95.0.3.0.0.0": "300972d2b10c430498f2dadbe5e3186f8f9ff45e41ad1724f8b07f078ec8f1c2",  # PipelineAst
    "0.1.96": "e54b1cf66a21bd532c7b1365765d66f5119b392e54b7f9cef6ec5fd27b1085f3",  # AssignmentStatementAst
    "0.1.97": "6979f3420d59e3b27d4e83a1b1dffb6c7fcfb9588541accf0adbd715e050be9a",  # AssignmentStatementAst
    "0.1.97.1.0.3.0.0": "21e6e34d90cf0e74575a45177da9da3e401da1c044775074266cb1be6f3df9ff",  # PipelineAst
    "0.1.98": "37fe96a372cb59bf4f71263a859e1573d21b796992e5117f783be438b12bc2d2",  # AssignmentStatementAst
    "0.1.99": "aebef4c7d8690e0b618505d902a1ab995b5ff269e1a770ef4fba5959b193d1ef",  # ForEachStatementAst
    "0.1.99.2.0": "e0c057d44adc3ea31b69d49d2730abc7009bc5cfd00a2054a8545bdf7326f8da",  # TryStatementAst
    "0.1.99.2.0.0.0": "a7e9729a7c289b0c19f9e5e6f88dcb024b0ef4943629da145a2b555233baa025",  # AssignmentStatementAst
    "0.1.99.2.0.0.1": "ae63d5288d7b74af31dc6d975485a067a38c188aaf8a17bd6518a90219407f52",  # AssignmentStatementAst
    "0.1.99.2.0.0.2": "affc7b3e886ab1abc7a28cc6e773365505ddc38fbfa2f0412d418d0a5fff981e",  # AssignmentStatementAst
    "0.1.99.2.0.0.2.1.0.0.0.0.0.0": "35a71f236330c046c98ef0d3d9f3c058b81425c39b96ee083a68a310d0cd848b",  # PipelineAst
    "0.1.99.2.0.0.2.1.1.0": "9391448349840e63cb9e1221fb83f9d1b05ddfb1185f52ef481f97595e635201",  # PipelineAst
    "0.1.99.2.0.0.2.1.1.0.0.0.1.0.0.0": "8596d0380a48069621ef048db34ab5530349d193971cea285cf8a2d93daa5ac8",  # PipelineAst
    "0.1.99.2.0.0.2.1.2.0": "96d32d929406ef3a3693083f0873837a4b6c5931c57dc8a60f69972040111305",  # PipelineAst
    "0.1.99.2.0.0.3": "976ad4fa567fac4f425036b9de1ab2900a7c5cf0233f7c46ea68c4aa7b39fdb9",  # AssignmentStatementAst
    "0.1.99.2.0.0.3.1.0.0.0.0.0.0": "80cee2b7c4b339390f365f63f0298ace9a5ffaed8b16f2847d42e8ca23a0e892",  # PipelineAst
    "0.1.99.2.0.0.3.1.1.0": "c1d32ada9557443dd302a045a05aaa514bc18c1b75ca01d6db02537c75904966",  # PipelineAst
    "0.1.99.2.0.0.3.1.1.0.0.0.1.0.0.0": "b167beeeb17c348984cb2c5d46702033e5776142a9849dafc4bff8eddd57dbc1",  # PipelineAst
    "0.1.99.2.0.0.3.1.2.0": "96d32d929406ef3a3693083f0873837a4b6c5931c57dc8a60f69972040111305",  # PipelineAst
    "0.1.99.2.0.0.4": "b0c56e7e6bd1d9528e654e625ae5d548adeac106d35c8cc80d959e6796967bb8",  # AssignmentStatementAst
    "0.1.99.2.0.0.4.1.0.0.0": "7973b1852f2ee120368d6ea9289ba3642712d59770a3bb0a6d3a8fbed369ae0a",  # PipelineAst
    "0.1.99.2.0.0.4.1.0.0.0.1.1.0.0.0": "e3f0f197bcd21813886df6fabc7996c9a5536587c23fa875bd4cf4a7dfc255a7",  # PipelineAst
    "0.1.99.2.0.0.5": "2cf9a4898e4c6f0ac934f3dd07e112746166d4c1ef4467052d5ff4d04c8201fe",  # AssignmentStatementAst
    "0.1.99.2.0.0.5.1.0.1.0.0.0.0.0.0": "9035372a3bb05e43702411aa6283616ba25230e9df7154d8f9a45c22e659a131",  # PipelineAst
    "0.1.99.2.0.0.6": "3b6ef51422a7e9050935fba74af92d8ab5bc6867fed3ab1f28f50794eacf7fc0",  # AssignmentStatementAst
    "0.1.99.2.0.0.6.1.0.1.1.0.0.1.0.0.0": "f1357c36fc31ec4822d47278e768e7a0f3b3632a5e511bb5251905b80e79047e",  # PipelineAst
    "0.1.99.2.0.0.6.1.0.1.3.0.0.0.0.1.0.0": "06027d16117e611ffc896dc953a4615e99175f7eef074f259ff0d69eff9ef0a1",  # PipelineAst
    "0.1.99.2.0.0.6.1.0.1.5.0.0.1.0.0.0": "81e82ccdd898c79809244b3218fa20243c6be3a765c1e578f7d8e1fbd3090092",  # PipelineAst
    "0.1.99.2.0.0.6.1.0.1.7.0.0.0.0.0.0": "54a08cccda7d46280543fd0fb036be81473fd7193473261e7925a72935d41d43",  # PipelineAst
    "0.1.99.2.0.0.6.1.0.1.7.1.0": "acd1fd2f4d4cc6a7c840d961ca572bf9e7a3eb01c348bc0ab2026f653c48bc12",  # PipelineAst
    "0.1.99.2.0.0.6.1.0.1.7.1.0.0.0.1.0.0.0": "b62140d07b55579a0c5bff5764367bba0c793ded893e627214286ec4d1a48bbc",  # PipelineAst
    "0.1.99.2.0.0.6.1.0.1.7.2.0": "8c3007262f4bc5434c4e0e5a536451247b53f775aa0d79ef3f13efa46c817eaf",  # PipelineAst
    "0.1.99.2.0.0.6.1.0.1.9.0.0.1.0.0.0": "759c0241912ba05768b35f62be990e7290afd2df1ee8543a5c0430c0834cd5ad",  # PipelineAst
    "0.1.99.2.0.0.6.1.0.1.11.0.0.0.0.0.0.0": "0d732434a808295def44dc437fc12059419a31cb8b3d4d92601e5686b0ec7473",  # PipelineAst
    "0.1.99.2.0.0.6.1.0.1.11.0.0.0.0.0.0.0.1.1.0.0.0": "326d5acf83512ac2a55473035b3e1de950f7fb9c381baab3a50f3d5be7db6082",  # PipelineAst
    "0.1.99.2.0.0.6.1.0.1.17.0.0.0.0.0.0": "615530e947d3363692996d3e0c86b6c26606479c418e39b44462237a43751de6",  # PipelineAst
    "0.1.99.2.0.0.6.1.0.1.17.1.0": "1997f3ab99da8cb242364308fe29d2457e45add1b8918356fbbbca883b8e3533",  # PipelineAst
    "0.1.99.2.0.0.6.1.0.1.17.1.0.0.0.1.0.0.0": "bff9c63a3bcc6c7cca9d63a69d8ffa9c9edccaace27aa7e67d19ca78a70568ba",  # PipelineAst
    "0.1.99.2.0.0.6.1.0.1.17.2.0": "f8b8583f347f62a296c7afae776457281d1f37c9af61a33d3759880c2b921d29",  # PipelineAst
    "0.1.99.2.0.0.6.1.0.1.19.0.0.0.0.0.0.0": "bdda362f6bfaa2974f84aaa667110d717a91c061ffe0066c191cbe101454bf3a",  # PipelineAst
    "0.1.99.2.0.0.6.1.0.1.19.0.0.0.0.0.0.0.1.1.0.0.0": "326d5acf83512ac2a55473035b3e1de950f7fb9c381baab3a50f3d5be7db6082",  # PipelineAst
    "0.1.99.2.0.1.0.0": "78baf1ab3fd85ef881e4c314820ba162a8f8a6509da98d3bdb63a6647b103ad7",  # AssignmentStatementAst
    "0.1.99.2.0.1.0.0.1.0.0.0.0": "b36c511c08f8126275b0c76e1ae47fc2e1f5f5795c8ed8dba235fcaf7aa505a2",  # PipelineAst
    "0.1.100": "621f1194d259b0de6cb0da827266d56c62d438a434ff598ac8f42119480535be",  # PipelineAst
    "0.1.100.0.3.0.0.0": "94ba7bd02630278a620b15716c1b99acdb0f857e47e373b33fa4655c6ced44b0",  # PipelineAst
    "0.1.101": "2d26b4b433755a45f1015c96567bdce455f90390865b7cbcaa449ac9d8b33fac",  # AssignmentStatementAst
    "0.1.102": "39c0d3b048c6541a68404441e947e6108db554a7ae1cbb09eb3eca98e9e530f2",  # AssignmentStatementAst
    "0.1.102.1.0.3.0.0": "7b68ca762488fc282608784aaf32ec8057a26b09a4f644b5967539277a10d177",  # PipelineAst
    "0.1.103": "41740fbeae498f14b7740bf9cafaed6202fbc0dfc19fa9892da6e20942512051",  # AssignmentStatementAst
    "0.1.104": "1e627b1e83513f9dac5dbcd12268e4670df2128a3324588a78335e0f20756907",  # ForEachStatementAst
    "0.1.104.2.0": "3d8f32f28b5aac31e882ae026bffd66c48c8108c584125d950a0e8e2ac72cc26",  # TryStatementAst
    "0.1.104.2.0.0.0": "a7e9729a7c289b0c19f9e5e6f88dcb024b0ef4943629da145a2b555233baa025",  # AssignmentStatementAst
    "0.1.104.2.0.0.1": "e8a51b38a5803d36022e44185c1eb9cf4c5790922b4dc838bdd5b442ce1e4889",  # AssignmentStatementAst
    "0.1.104.2.0.0.2": "81ef0a3fd274876d02e920012e9989dd122c1ed8eb9ad1bf4c500f8e3c95c0b0",  # AssignmentStatementAst
    "0.1.104.2.0.0.2.1.0.0.0.0.0.0": "03c1b69d9b8d776178e107577f7fd28a9056e68d727aa30c3e29913e3a75978c",  # PipelineAst
    "0.1.104.2.0.0.2.1.1.0": "a3afdbaaae6f796dcb302f2ca37cf42ab081e52c422c84702d78124f21c55889",  # PipelineAst
    "0.1.104.2.0.0.2.1.1.0.0.0.1.0.0.0": "933a543e07f2764001c5e38a385898702fd379acced91e84537d87e123ab95d5",  # PipelineAst
    "0.1.104.2.0.0.2.1.2.0": "41f22e4dc298c3a4db2c492a03522e1298ea63c9b774dc55ca577732661f9b79",  # PipelineAst
    "0.1.104.2.0.0.3": "78208bf5d3272d940f9341df275eb670c7a95f19a9a285d744301dc756d5c2f5",  # AssignmentStatementAst
    "0.1.104.2.0.0.3.1.0.1.1.0.0.1.0.0.0": "759c0241912ba05768b35f62be990e7290afd2df1ee8543a5c0430c0834cd5ad",  # PipelineAst
    "0.1.104.2.0.0.3.1.0.1.3.0.0.0.0.1.0.0": "06027d16117e611ffc896dc953a4615e99175f7eef074f259ff0d69eff9ef0a1",  # PipelineAst
    "0.1.104.2.0.0.3.1.0.1.5.0.0.1.0.0.0": "81e82ccdd898c79809244b3218fa20243c6be3a765c1e578f7d8e1fbd3090092",  # PipelineAst
    "0.1.104.2.0.1.0.0": "8c5c7c970f10dd725cc094a5f4c3b93519661ba5aa6b19b53398220577c72f11",  # AssignmentStatementAst
    "0.1.104.2.0.1.0.0.1.0.0.0.0": "b36c511c08f8126275b0c76e1ae47fc2e1f5f5795c8ed8dba235fcaf7aa505a2",  # PipelineAst
    "0.1.105": "9623be881ffc395004d9565036c7cef4c6bbe641c0abcd784ac6be6462bcdd5c",  # PipelineAst
    "0.1.105.0.3.0.0.0": "8e53b2f5a501a1005cae9d1fe05149ad0a1bed36ea6562eefa7148ae63546b62",  # PipelineAst
    "0.1.106": "156333e3abe8c32d458c76519fcfe97f7b902685153868aeecac47e2328f54cd",  # AssignmentStatementAst
    "0.1.107": "6d490b33f3eebf79ace80202f5e8c43c59d9dd4d022d9973797edfde7a12af19",  # ForEachStatementAst
    "0.1.107.1.0.0.0.0": "6fef017d47d324bb59c1ea4922cc5ef9996762d4a32df6d17cb1141e2c42c0b6",  # PipelineAst
    "0.1.107.1.0.0.0.0.0.0.0.0.0": "817308a67f6f268e87f3e58f84985c6e7d2b7522cbce166f88f8904d9b736608",  # PipelineAst
    "0.1.107.1.0.0.0.0.0.0.1.0.0": "779bd6b2d9dc1ec89155e5f21b209d6eea1febdabbf128e4179a93931f1c68fb",  # PipelineAst
    "0.1.107.1.0.0.0.0.0.0.2.0.0": "4a643d4d62033a781212ee698c368b0f42ea2b829acc754b606b7a3a55a62acd",  # PipelineAst
    "0.1.107.1.0.0.0.0.0.0.3.0.0": "530d042f20a51c93a4a4b20caa566ef542a50ed2c543200c9f8d727e86ed6890",  # PipelineAst
    "0.1.107.1.0.0.0.0.0.0.4.0.0": "21faf3246bad46c0a346653114bdae48204d96c3970c4f8001419ad423b27a67",  # PipelineAst
    "0.1.107.1.0.0.0.0.0.0.5.0.0": "2f9c93baaab5d63b83ed99328aa81f570efb35861e0ea06bc2910df72ec8c17c",  # PipelineAst
    "0.1.107.2.0": "cc8c7d2b78a0b6fedb3086f62ed3e1059e27bfd3c0e9a5fce03f37f6eadfbeab",  # AssignmentStatementAst
    "0.1.107.2.1": "2996fe3e1ba1e0e38e45a28ff673d5064cfbfff1f107591dbb6856f92e0e5f3f",  # IfStatementAst
    "0.1.107.2.1.1.0": "d4dbd66ab51a6de537e51348b23bb809d9f94c891787cb85294c60f681d43e48",  # AssignmentStatementAst
    "0.1.107.2.1.2.0": "0bf4384a2f00c758cab3c808669b74754a6ab70986cd13a08c3524e680fc8f82",  # AssignmentStatementAst
    "0.1.108": "ec075f08db12206a519e47edca109480b0c251cf4522d1f76cc93f37c69a95d3",  # AssignmentStatementAst
    "0.1.109": "c03ec4a4c5c9a24128b6b8725751fc056c46284ab9001d8b9d21dbf7d305655b",  # AssignmentStatementAst
    "0.1.110": "c9156c73de334e858e814107a237cf4ffd35776c1a1a9c5c86ad7f90cf8ed96a",  # AssignmentStatementAst
    "0.1.111": "2228650729dc1fe55347d5b636b634d75fe13d02c28e181f6197f3eb36699081",  # AssignmentStatementAst
    "0.1.112": "cca241e076abfdf61e3c56815600e53ef27f85888c81c64ef6eb59ebd4fcc02e",  # AssignmentStatementAst
    "0.1.112.1.0.3.0.0.0.0": "ea79916bc120ea71fd09d682088a3a53e9330e248d62dbc676a677babaa4dae6",  # IfStatementAst
    "0.1.112.1.0.3.0.0.0.0.1.0": "249a2d94512058880de99af99bd34464ae5d8d86a6d290c79c91a3d77a15bd64",  # PipelineAst
    "0.1.112.1.0.3.0.0.0.0.2.0": "bd9e8ebc4648dc68713d2ad8009f1d67fb7fbee3a087921d8e52b8b69c27e347",  # PipelineAst
    "0.1.113": "58f0aaabb140cde890a9818465ba85ae103aa4ca497c9b727c6de956f6d2a1d9",  # PipelineAst
    "0.1.113.0.5.0.0.0.0.0.0": "e21cf658134b2ccbc4216a24d64f9091c3f536347f878fca102217fce1ffc78e",  # PipelineAst
    "0.1.113.0.5.0.0.0.1.0.0": "8ee6d3c81394589d1747587604e85fac2c8f88f2d1db28443524168355fdb355",  # PipelineAst
    "0.1.114": "5dcfa62bfcfb5e80550473f934ef20d831bc5ec79ef63535375ed4bdc8a2f6f5",  # AssignmentStatementAst
    "0.1.115": "88243b9eaf6a0c36aaef6049a35f2943269f5f4d48bb56476b15c07c23b68bbe",  # AssignmentStatementAst
    "0.1.116": "b4239dbffc29d91178c0fc3bce102ca27c9876fbdb7f22cf5c1bdb2bd87ee36b",  # ForEachStatementAst
    "0.1.116.2.0": "31e223a34b3242fafa8abbb759d44f17eb75cc685f595c0022c694d02f1db017",  # AssignmentStatementAst
    "0.1.116.2.1": "b90223bca7e7abc4c0cbb51c99e52e64b903bc85570b12ce37ab6d99d0e8fee5",  # IfStatementAst
    "0.1.116.2.1.1.0": "0da80823498795c0d3be303a3f1b5525d9430d8ee87ddb2ada2385c1f4f18c39",  # AssignmentStatementAst
    "0.1.116.2.2": "7bf2346899582ba1c0fc38826bf14315cae03edf32bdd2272c74f6e07b4eb7c5",  # AssignmentStatementAst
    "0.1.116.2.3": "c9d1845d698e6d250c79d4341cb8f6adc33aec23fc50449f3b6ca1a2084fcf07",  # IfStatementAst
    "0.1.116.2.3.1.0": "c1657498c821bd98473d0ac6037d1bcce238e4246b55c296f90a7017788428a2",  # AssignmentStatementAst
    "0.1.117": "942873e6fddbe0ceb6c761478c2e902a4fcb9588eb761e116b8925fef0e2fc59",  # AssignmentStatementAst
    "0.1.118": "996ae2e4fa305ac19680b8dffea08d77fe6135cf138f11d3c9ce936db1686ea9",  # AssignmentStatementAst
    "0.1.119": "208b886b2d4579515d35f078372089b4334064a9a85c8f952b1d1c337e65ffcc",  # AssignmentStatementAst
    "0.1.120": "273d58b4047f2b35cec7ca4f330551b8abf5d443cef3c727da90c4b34e03111d",  # TryStatementAst
    "0.1.120.0.0": "51ce87b8c58431477a4856dff270750e8ee9f0dd493b2623d3b181dad30fdb2f",  # AssignmentStatementAst
    "0.1.120.0.1": "3a2a44874e40ec32c7626fed1425e9637905c0ff7136e163eaf604887f75b5f1",  # AssignmentStatementAst
    "0.1.120.0.2": "6a83b4df2624f4c76f9e2cfaecab5b9c4c581be40b958cdb7e2f43632c04b743",  # AssignmentStatementAst
    "0.1.120.0.2.1.0.3.0.0": "28e00deabe4da9e17778541ec7113e8fee99ac13e44c829c31d54f1638ff8d78",  # PipelineAst
    "0.1.120.0.3": "a38338ee8094ac6f63bf8d65ef3a3524dddd10edb27e68e9cb4377c60cbf6c78",  # AssignmentStatementAst
    "0.1.120.0.4": "aac14940c75fb235137be1e80ef7901e6448cf6f23e5ae80ab1319339fa2b07a",  # AssignmentStatementAst
    "0.1.120.0.5": "ff97b8abcc9839ffbb373f80fcc555a60b032ca5207341dcd5754a1f4a1c0eed",  # ForEachStatementAst
    "0.1.120.0.5.2.0": "81eaf4ff18a134761d6ea902094ca3e0a47f1a0ba4b267d10fefa6b5c9fabe0a",  # TryStatementAst
    "0.1.120.0.5.2.0.0.0": "382af053cae0feb148fe2a8ebe6d26f47be63f4f44091c1b5621e4ccb58ad767",  # AssignmentStatementAst
    "0.1.120.0.5.2.0.0.1": "d5f6a8f2f4a83f2bbf50ca1bf856fb4ec8bafce1d3e93b7c5174bd66a31125d3",  # AssignmentStatementAst
    "0.1.120.0.5.2.0.0.2": "1640fcafa7497cf5d6c6f6a34938737ecd0649cab7d3f3bcce77c114c1c6b052",  # AssignmentStatementAst
    "0.1.120.0.5.2.0.0.2.1.0.1.0.0.0": "cc35c18a17d1396d5bebf9d34a155e032f60a0ecfcf2e8b7f0facf35c93fb94d",  # PipelineAst
    "0.1.120.0.5.2.0.0.3": "252c2c88f67d26fa24302eff5ef95b2a8b31c562eb61101e650d0eece550b693",  # AssignmentStatementAst
    "0.1.120.0.5.2.0.0.4": "8dd1a470d62a4bd6a75678bd8907674001446164fe22ccdef8d9a3166f37179e",  # ForEachStatementAst
    "0.1.120.0.5.2.0.0.4.1.0.0.0.0": "901720766e4f38da141d94cb6b5040493df07a91a6386569b1662f8f54a3181a",  # PipelineAst
    "0.1.120.0.5.2.0.0.4.2.0": "22a4ecb1eeae41052cf60fb91ee108e5b3f5b9501a0c4e19528a82880e8a7dd2",  # AssignmentStatementAst
    "0.1.120.0.5.2.0.0.4.2.1": "dd9ed2c4b28a09250853b589f256c3aed8f84b5ddc5b5ff738fc722d7800a2df",  # AssignmentStatementAst
    "0.1.120.0.5.2.0.0.4.2.2": "f480fdbf494efc5221c0fded27dbabc7085f5fa095b50a2bc632f940c447f976",  # IfStatementAst
    "0.1.120.0.5.2.0.0.4.2.2.1.0": "4170368c5437cd4f7d26fe1a973f02d9231e21c380cd8fd27c57f98dc2d711d1",  # ThrowStatementAst
    "0.1.120.0.5.2.0.0.4.2.3": "be1adc177ab7b327426bb6f8ba7a5069c4d13c68be7f282dab45187532337ec9",  # AssignmentStatementAst
    "0.1.120.0.5.2.0.0.4.2.3.1.0.0.0.0": "c872af5cb35399cb36dead9895f89c0fe38cdbd9a1e19e2f58c0157d60c56ece",  # PipelineAst
    "0.1.120.0.5.2.0.0.5": "53318046a110c581afe7ea5de2f8ce73817b244f86c92768171a8158b8f314ab",  # ForEachStatementAst
    "0.1.120.0.5.2.0.0.5.2.0": "2c5306ff7d332da23058c1006e065bb6a9201e7ddbf1afc2d5b93d6c1cedbb31",  # AssignmentStatementAst
    "0.1.120.0.5.2.0.0.5.2.1": "f47b7b065dee093d8732d024a2fcd4e4f2786715d51eb5f694654b4e90819361",  # AssignmentStatementAst
    "0.1.120.0.5.2.0.0.5.2.2": "e88507330cd7c7ffabdc76dfa6cc8b090e870ccc729acce781038faddcc5c881",  # PipelineAst
    "0.1.120.0.5.2.0.0.5.2.3": "a4a9989ec0d696e5111db59505a6607a880a96c50d88196f59df2f6ba19a108a",  # AssignmentStatementAst
    "0.1.120.0.5.2.0.0.5.2.4": "af3c649152ebde2276f1f9dc95377f50ce1e66fbbfc8c53bd4addf3c4128489b",  # PipelineAst
    "0.1.120.0.5.2.0.0.5.2.5": "993da4c5046486bee72eb4648463608891bed44743f1f1f9e25bd05e0f468d01",  # PipelineAst
    "0.1.120.0.5.2.0.0.5.2.6": "bab54092644934bb7001e804d307c0a2b1266a991dd460fed7ab883787ed1704",  # AssignmentStatementAst
    "0.1.120.0.5.2.0.0.6": "3b3679b25397c43d54784310cb18254b7aeaa19b21df5fe540471ad1704d9843",  # PipelineAst
    "0.1.120.0.5.2.0.1.0.0": "15d2e525b3370abdb4306a481d3e70d7c03b228998c71e6a5def914cc851ecf4",  # AssignmentStatementAst
    "0.1.120.0.5.2.0.1.0.0.1.0.0.0.0": "72a4cb1ec2e4f86e38878105d2cb1cde1e0ff051b73b84e72851c74b5708671a",  # PipelineAst
    "0.1.120.0.6": "a0e2ba414b824f964d69d5d0ee1af1845e2661395aed4502408189788a4dd4a4",  # AssignmentStatementAst
    "0.1.120.0.7": "19db68207837328d1ea24d01d502872d97f017d93d9f0678bcdc6e13584e62c1",  # AssignmentStatementAst
    "0.1.120.0.7.1.0.3.0.0": "e9489fb603682bd6789cebc2cab6f45dcc993ab28adc10724b3b32b164f97f51",  # PipelineAst
    "0.1.120.0.8": "78c65ab105308ffbd0a5cb157918412ec096098d2464507923e38815544cfd9c",  # AssignmentStatementAst
    "0.1.120.0.9": "12688d18f58f61ec12736ba219d165852cc5660bc6b8de111bbb4e57fb055c3b",  # AssignmentStatementAst
    "0.1.120.0.10": "4ec2e0c099e2e17aca9758672367cd2dc7222b4867fd35461d52b98e59317941",  # ForEachStatementAst
    "0.1.120.0.10.2.0": "9fef4a4ba62c2eb4a8579a4c2c5bf1f71458411c6c9a59267db51543a74d64b9",  # TryStatementAst
    "0.1.120.0.10.2.0.0.0": "382af053cae0feb148fe2a8ebe6d26f47be63f4f44091c1b5621e4ccb58ad767",  # AssignmentStatementAst
    "0.1.120.0.10.2.0.0.1": "c7dce66be993ab3498d40c0ec1a1c7e246e85c69f9ed384ef5f0e86279676e82",  # AssignmentStatementAst
    "0.1.120.0.10.2.0.0.2": "1640fcafa7497cf5d6c6f6a34938737ecd0649cab7d3f3bcce77c114c1c6b052",  # AssignmentStatementAst
    "0.1.120.0.10.2.0.0.2.1.0.1.0.0.0": "cc35c18a17d1396d5bebf9d34a155e032f60a0ecfcf2e8b7f0facf35c93fb94d",  # PipelineAst
    "0.1.120.0.10.2.0.0.3": "b8ae78ba658e80a52cd29d87c35334d89a2821c05162a9bb9b52e645f9dd5ff4",  # IfStatementAst
    "0.1.120.0.10.2.0.0.3.0.0.0.0.0.0.0": "b74f27fa0f81cd27564292f310687da9ac0ad5f5ec9235f1a6bf730eb38729ee",  # PipelineAst
    "0.1.120.0.10.2.0.0.3.1.0": "0f5226125d96427f274f5124dc7fc399b9cfede2de95e2773a0064c101751005",  # PipelineAst
    "0.1.120.0.10.2.0.0.3.1.1": "3b015bbb2ea6d56928abe793599a44990cf7de09806614e40df9a0aa534581c7",  # ContinueStatementAst
    "0.1.120.0.10.2.0.0.4": "34b107bc449089c43e242605531d2c762401b9d9b494d59815bfd30f3771f66b",  # AssignmentStatementAst
    "0.1.120.0.10.2.0.0.4.1.0.1.0.0.0": "d5a65c0ca8f90f5c6112cac41b986601bbd062514358a3b9c362fb1faee9d048",  # PipelineAst
    "0.1.120.0.10.2.0.0.5": "7f48bfa76f26b60f584d4e6276d11e06af6138f620242bfafb7b4880628fcf97",  # PipelineAst
    "0.1.120.0.10.2.0.0.6": "d8c2884826aaad0b20bb0226e4297e37d9bc1045c5c55239a69dc1f16f3fb4f3",  # AssignmentStatementAst
    "0.1.120.0.10.2.0.0.7": "ae8824dbc3795bda5ac4a94bd8ac4afec9b9f041230e4ccc63e0a3a397c7ae87",  # PipelineAst
    "0.1.120.0.10.2.0.0.8": "c1836c49e1adbb5a3ac011effd7625c174b424af08ca7c21e15c7683403c894d",  # PipelineAst
    "0.1.120.0.10.2.0.0.9": "82ec3ea2456f4a2cf1c1abe068a3dab8126757fdf72911d2d6f8367c9ce6b3ac",  # AssignmentStatementAst
    "0.1.120.0.10.2.0.0.9.1.0.1.1.0.0.0.0.1.0.0": "a4b51cf7e6856e1aa3ca5917b8e5df9257b9bce249c2f88cff2d6bce4adb843c",  # PipelineAst
    "0.1.120.0.10.2.0.0.9.1.0.1.7.0.0.0.0.0": "35ce1c589b2920e3b637a44ca2fc4c075160fe38e76de374af4dab8c0eb057ff",  # PipelineAst
    "0.1.120.0.10.2.0.0.9.1.0.1.7.0.0.0.0.0.0.0.1.0.0.0": "7d4e0a78fe37c14a6bd93cd0d7ff99d0ea9160597f64acdaa6a6a2711e0388cd",  # PipelineAst
    "0.1.120.0.10.2.0.0.10": "37cf6f53708ca6b85eea91f93cd7c2b73c56eda3366ef04eb71eb0984a2ec7a3",  # PipelineAst
    "0.1.120.0.10.2.0.1.0.0": "37021de661c56ee56e0f467993683c2000871701237f38300e99fb733ec5d127",  # AssignmentStatementAst
    "0.1.120.0.10.2.0.1.0.0.1.0.0.0.0": "72a4cb1ec2e4f86e38878105d2cb1cde1e0ff051b73b84e72851c74b5708671a",  # PipelineAst
    "0.1.120.0.11": "2dfd99a0c9e250b1694471c465f27a6a917a3cc44a51fd757c52a52a035b5534",  # IfStatementAst
    "0.1.120.0.11.1.0": "8a9b6d4e2934433dd2aaee8aaef42b79917985174770ef0a16a4774d08ec02bb",  # AssignmentStatementAst
    "0.1.120.0.12": "d62edc1008ef01f4581bc45816b22d4ed726cad9709fb5619249c0d73f697942",  # PipelineAst
    "0.1.120.0.12.0.3.0.0.0": "460a5bf23d815236b82118bd88fe27df6b72065f4c62a1076d284dc9d86800dc",  # PipelineAst
    "0.1.120.0.13": "7ce2afcf4a9a153019dc354ff17917ca29500aca9cca35ccf4b2a3d56bc2a652",  # PipelineAst
    "0.1.120.0.13.0.3.0.0.0": "2d75252df8a805e567a4f131c483b2e59a689b481f8a4d032b32e08deb4d040f",  # PipelineAst
    "0.1.120.1.0.0": "3ed94e49bf3d3869bc319aa562802ce846c1886ac70a73880cf1672705fb42a3",  # PipelineAst
    "0.1.120.1.0.0.0.1.0.0.0": "4d3211bb3dfde08b2f1f73204be2afa24e1f17e353a90fb361221d037aa8762b",  # PipelineAst
    "0.1.121": "4c8e921ca4f04b86d5955d7ce736677eb894a2dd1999367b306cac97a35473f9",  # AssignmentStatementAst
    "0.1.122": "c7c61d42504d02a89fda8f21df0319d6344a9bd7f04b326296b05009563e2f88",  # AssignmentStatementAst
    "0.1.123": "0aa8a002b711313cd122197c60a677556740ec8601b432c550fd88ef43ad57a1",  # TryStatementAst
    "0.1.123.0.0": "a5349819755dfa150bccb36d90a609dbc0e486a57f84b7a359979abf709f86a0",  # PipelineAst
    "0.1.123.0.1": "f3938cbb9b80631479e19c1380a5483d8e4bfe17c8c1a1992ff8fc75bb4f21b0",  # AssignmentStatementAst
    "0.1.124": "5ac8e6c19f4a1d7b74f5a294c3e821ad3193c7e6a7b4e1162ef2ca936d8fcc5e",  # IfStatementAst
    "0.1.124.1.0": "2e1f0279fa642402f478dac45fca53f66bf92ebedf52f1c1b582176e1639f8ab",  # AssignmentStatementAst
    "0.1.124.1.1": "f84998e2268c369983ebb4cc1ae23b89ec1927d0b76722fbfc4311ba16e2eb0c",  # AssignmentStatementAst
    "0.1.124.1.2": "e5134f803a9caf0fef36ee704e3dd17bbefe245d21372783742ac47e88eb493d",  # AssignmentStatementAst
    "0.1.124.1.3": "b03c1c12644e6f96bf014cc2637c2cf564708f7b891a12b5bf8bafca13aeab30",  # TryStatementAst
    "0.1.124.1.3.0.0": "ee94460abf7cb3ca8dd3379cdc0c88b46fc3cc150b60e9710e9884f178d0abfe",  # ForEachStatementAst
    "0.1.124.1.3.0.0.2.0": "d856d3f9c207e939623e3f2dd2127644b9591543507819af96d5bbb1f557356b",  # AssignmentStatementAst
    "0.1.124.1.3.0.0.2.1": "11f94aeb06d64e997d937041f35cad418394a8507aa97e92e50a687e97543891",  # ForEachStatementAst
    "0.1.124.1.3.0.0.2.1.2.0": "193479291395c6389bcb9bc70452686d5f3ee690ef5fab8f8afb0da0337e4c5c",  # IfStatementAst
    "0.1.124.1.3.0.0.2.1.2.0.1.0": "2fdedcf22780ecab3732e4f3506af825db829f2e824141ac1c25772684ee4a99",  # AssignmentStatementAst
    "0.1.124.1.3.0.0.2.2": "eec30ecd53c4928a3043b44a1ba16212b5f54ab76e6ad3a4925838ce4dc657eb",  # ForEachStatementAst
    "0.1.124.1.3.0.0.2.2.2.0": "93691680f5af3bec23004155a8820fd615932455c4e01bb3848d26ddd752189c",  # AssignmentStatementAst
    "0.1.124.1.3.0.0.2.2.2.1": "329c2dff479e9300baa48b785f1a6eac3172edcc09e30361df65927d8bbd240d",  # IfStatementAst
    "0.1.124.1.3.0.0.2.2.2.1.1.0": "585cab8cd15e1333bf7158abaf7aa3f2f7ce9c84d82aa2a1399fe4f2cdf8520b",  # AssignmentStatementAst
    "0.1.124.1.3.0.0.2.2.2.1.1.0.1.0.0.0.0": "0f60a2641514faef393bcd4a4a845f7802ca85102f100f39c1913f226307d682",  # PipelineAst
    "0.1.124.1.3.0.0.2.2.2.1.1.1": "94da432834acc8c207dccd5981e972a173720a00e0cedf189ff36ac1c04550f2",  # ContinueStatementAst
    "0.1.124.1.3.0.0.2.2.2.2": "b18d1b987a0fa5bdb962a2c6337ceb18870ec1e1ec16eed2d0524c19f685149c",  # AssignmentStatementAst
    "0.1.124.1.3.0.0.2.2.2.3": "24d6bf74f8c30665d1c4180af3fe1cb8a501b7f55ddabb514d4b0e610a12e048",  # AssignmentStatementAst
    "0.1.124.1.3.0.0.2.2.2.4": "970676eb7269ba2d39525c12e9e41e30a726b21cedd6bf2fb0852f02c6aa94eb",  # IfStatementAst
    "0.1.124.1.3.0.0.2.2.2.4.1.0": "228ff1d039b975237d7fc07a29ef62e5509ba4d64ff91c321826dc9f9e7afa54",  # AssignmentStatementAst
    "0.1.124.1.3.0.0.2.2.2.4.1.0.1.0.0.0": "c6212a9b65424d3943cf6384ac62c8271e7896d98b573a87fb9ae875895cf021",  # PipelineAst
    "0.1.124.1.3.0.0.2.2.2.5": "77b4f36f91cb3f27b63c4a8c1f84779ee6d6292d22756b7bb265ab2f41a32a5a",  # IfStatementAst
    "0.1.124.1.3.0.0.2.2.2.5.1.0": "94da432834acc8c207dccd5981e972a173720a00e0cedf189ff36ac1c04550f2",  # ContinueStatementAst
    "0.1.124.1.3.0.0.2.2.2.6": "442ec95741c7bb1834aa8147868e31c7e8718df4fba3f800add9f9187f07d3b4",  # AssignmentStatementAst
    "0.1.124.1.3.0.0.2.2.2.6.1.0.0.0.0.0": "d156e0abb079d5b49242026dfa689db6b1266cf73d867ccb3c3ce1bc6d652bcf",  # PipelineAst
    "0.1.124.1.3.0.0.2.2.2.7": "c672b91379b252710f29a0f38f872e6b364bfefc25c767a85b38b722df4d72f6",  # AssignmentStatementAst
    "0.1.124.1.3.0.0.2.2.2.8": "5ca5821499660c8d3b61f93908b6c00d5bc31c274befb93b4a6355f182ac5114",  # AssignmentStatementAst
    "0.1.124.1.3.0.0.2.2.2.8.1.0.1.0.0.0": "71681a9092b57f46a1b13305ce87abae47ede561943e610f95039d0e0d5c9f16",  # PipelineAst
    "0.1.124.1.3.0.0.2.2.2.9": "84e5191856ebc36e68391449539132e3c7a987af4a3c5c02fd92778d18583d48",  # AssignmentStatementAst
    "0.1.124.1.3.0.0.2.2.2.9.1.0.1.0.0.0": "6ef0709af557f386dc85999f96a2b35dee77b4b0a6bb8eaf141b64cc89f6d287",  # PipelineAst
    "0.1.124.1.3.0.0.2.2.2.10": "f167bd03722de6010e4528c7f960eefe53940ef213722b2f45f4d0ad1314584b",  # AssignmentStatementAst
    "0.1.124.1.3.0.0.2.2.2.10.1.0.1.0.0.0": "be09adf61eaa6a2b9063c9d278dfdedc371385e14ff63b3ee18257255e46236b",  # PipelineAst
    "0.1.124.1.3.0.0.2.2.2.11": "cfe4d8724eb36ffb6aa2bca09d2931c9551c848fc02ef8667c946dabd80637d9",  # AssignmentStatementAst
    "0.1.124.1.3.0.0.2.2.2.11.1.0.1.0.0.0": "8ae17a31810530aea6949252d97bcb187c1eed35249f645335e0779ea0f08934",  # PipelineAst
    "0.1.124.1.3.0.0.2.2.2.12": "a558981083beac8e1f7d41e519eae97af4b11ad73b73aa9129b3d62af1bba8a4",  # AssignmentStatementAst
    "0.1.124.1.3.0.0.2.2.2.13": "5ba44128edd6c3316af0aefd3b6145992f225ca5a13284a9ab83af2a84e3d386",  # IfStatementAst
    "0.1.124.1.3.0.0.2.2.2.13.1.0": "6cbe7ec5a0fc84815205439d35a8f93ce1474da9bd3037b201d356184ab56f2f",  # AssignmentStatementAst
    "0.1.124.1.3.0.0.2.2.2.13.1.1": "793e9f8cd28a8b83c0eaad3271b66f95af1d2c894e9134e06388b65f93fc1458",  # ForEachStatementAst
    "0.1.124.1.3.0.0.2.2.2.13.1.1.1.0.0.0.0": "8dbeef1950f4f0248048f7de9133723909a32c80a2363ae7bf558531b51e3573",  # PipelineAst
    "0.1.124.1.3.0.0.2.2.2.13.1.1.2.0": "a4aad7aa00d3c2f45e78367d0c063929b85c090c47c0127264234a556380f239",  # IfStatementAst
    "0.1.124.1.3.0.0.2.2.2.13.1.1.2.0.1.0": "015b8a1b59d4174df97d645e76a544465dac6de5fa0975788303a3245ffbb4ef",  # AssignmentStatementAst
    "0.1.124.1.3.0.0.2.2.2.14": "e1f990f6979757d4b8944a3d7dbc7b68800d9e301632ff168d8862f87cc49ef5",  # AssignmentStatementAst
    "0.1.124.1.3.0.0.2.2.2.14.1.0.1.7.1.0": "ff5265090f1e617fbc47e3bf3741d933c53396bf8dfd4922a98227c17e5a14ae",  # PipelineAst
    "0.1.124.1.3.0.0.2.2.2.14.1.0.1.7.2.0": "9187b8db4114729ed37aae9da17f61962f5bc0586522bbb20ddcd1be9b8f0c4d",  # PipelineAst
    "0.1.124.1.3.0.0.2.2.2.14.1.0.1.9.1.0": "89008903c7dbce249f529c21a30fe2d2fff3b8e16f0f2ff81e3f2c52c46d7eba",  # PipelineAst
    "0.1.124.1.3.0.0.2.2.2.14.1.0.1.9.2.0": "9187b8db4114729ed37aae9da17f61962f5bc0586522bbb20ddcd1be9b8f0c4d",  # PipelineAst
    "0.1.124.1.3.0.0.2.2.2.14.1.0.1.13.1.0": "da02ec8d7083cd16ee36260c10634035945f0400b850d4dfcbb72055d8592525",  # PipelineAst
    "0.1.124.1.3.0.0.2.2.2.14.1.0.1.13.2.0": "9187b8db4114729ed37aae9da17f61962f5bc0586522bbb20ddcd1be9b8f0c4d",  # PipelineAst
    "0.1.124.1.3.1.0.0": "23822bbd95f055275fc5017288615aa019960799bdf6814fc8b7842765e3f1b7",  # AssignmentStatementAst
    "0.1.124.1.3.1.0.1": "00755139736b69651a2b4b3ba321a39865074651da2c3ac1839b38e2846f9d9c",  # AssignmentStatementAst
    "0.1.124.1.3.1.0.1.1.0.0.0.0": "b36c511c08f8126275b0c76e1ae47fc2e1f5f5795c8ed8dba235fcaf7aa505a2",  # PipelineAst
    "0.1.124.1.3.1.0.2": "6326663910038ca6a97f46a040791b0cb01a6ce3a9a74f0ef421741121da8211",  # PipelineAst
    "0.1.124.1.4": "e0eeb67b743e6b418fec38605492344981ed6ce4552c8b4907996facbf7dc7e6",  # AssignmentStatementAst
    "0.1.125": "6815a6bf01923e5597ef94f2847d29d7fc0a92516de483fdf40660bdd0a98be9",  # AssignmentStatementAst
    "0.1.126": "9461534afa9c7e52c85ac1eff9c56751958421df9bdc432a142e0e73e85fe645",  # AssignmentStatementAst
    "0.1.127": "b3ef6d97661a22b3964c9ecaf5c619b950bf032870e785ffdd00c3222c86e421",  # AssignmentStatementAst
    "0.1.128": "dae5aaa4b40d2be3abb20d3cd10595aeb9c5b4bc3864bacb8467332c9d432bef",  # AssignmentStatementAst
    "0.1.129": "e51a9af4268ea395d23c553adac260178f5d57bf46bc5c94b7d86d7f818618da",  # IfStatementAst
    "0.1.129.1.0": "d6b175c6d51cd8240d88ed192658823ee1aacacd3c8b5081e4b205559432c2ce",  # AssignmentStatementAst
    "0.1.129.1.1": "c477af5a2b3a6e1358f334a2cf2c82fa0f8770dbde187efd161e219d97edf00b",  # TryStatementAst
    "0.1.129.1.1.0.0": "a3e1fe8aeac1c2e0045c2348882f376a5f13864c75bbabc769a71fb7254f9337",  # AssignmentStatementAst
    "0.1.129.1.1.0.0.1.0.3.0.0": "331a80f38bb721452754e3d19d11016916bc46540c6e97ed72b2fb3d5c3cf123",  # PipelineAst
    "0.1.129.1.1.0.1": "c61f106b949f12a276d9c7082456b59e3c3f8f6c53b45f78317fdadeca6cfdc3",  # AssignmentStatementAst
    "0.1.129.1.1.0.2": "e6836488994388166ed610552985a04d81e6dd5fff64da6d3d62f0956fe107ed",  # ForEachStatementAst
    "0.1.129.1.1.0.2.2.0": "67aa8784bdb774eda973d8e19c199f4d604eb1eab9d0b8ef58bebbfe9c74e572",  # TryStatementAst
    "0.1.129.1.1.0.2.2.0.0.0": "63ad3090437a9b565fefe98d81747f78d70e09d5cd6a0bbd0091b17d80cd5499",  # AssignmentStatementAst
    "0.1.129.1.1.0.2.2.0.0.1": "8d4cff2d5ba3c25287bbab3d00bc8a6bf87895f462cd54836135a0a0c6b9209a",  # AssignmentStatementAst
    "0.1.129.1.1.0.2.2.0.0.2": "6bf9afcb4877715e8a65793ed2d386c4dd9ce7bc95112eaef001d4ac25cea877",  # AssignmentStatementAst
    "0.1.129.1.1.0.2.2.0.0.2.1.0.1.1.0.0.1.0.0.0": "53baa5e491e38a5cdbebc238c50cd591c84292d5720ec121b5819be7958fd5bb",  # PipelineAst
    "0.1.129.1.1.0.2.2.0.0.2.1.0.1.3.0.0.0.0.1.0.0": "c918becfbbd1019f0f2474689e8857050db2b099e9889d81b65f3d7e85f94e8f",  # PipelineAst
    "0.1.129.1.1.0.2.2.0.0.2.1.0.1.5.0.0.0.0.0.0.0": "68cf1651f8adf05a8228b8f01f4b07505e61ea0fdd06b204cfcc51f7af26b506",  # PipelineAst
    "0.1.129.1.1.0.2.2.0.0.2.1.0.1.5.0.0.0.0.0.0.0.1.1.0.0.0": "c990f7fa67f3f8df3692227a19ba39972fa6af45211dccae2ce014cd4f9bc631",  # PipelineAst
    "0.1.129.1.1.0.2.2.0.1.0.0": "c092f06230cc02ca08abc0ee7fe6f493ba750de48f0f5a08cc195eb8de09dd18",  # AssignmentStatementAst
    "0.1.129.1.1.0.2.2.0.1.0.0.1.0.0.0.0": "932cc1df79f110eccbe803f25fce8245ac3b432b18fe9b36f58832f380b062e4",  # PipelineAst
    "0.1.129.1.1.0.3": "0c2bde90caa5f12a4ff2a5932963fc2a453b1b8972883e4744fd67a92582627d",  # AssignmentStatementAst
    "0.1.129.1.1.0.4": "312c9b044962472a541e13f871835286915369b020e4deba9115ef47c81fde1f",  # PipelineAst
    "0.1.129.1.1.0.4.0.3.0.0.0": "4ce271e1f3c810dee0046676bccf8dcbf6355c66ff28a4c46304859e8352c5f6",  # PipelineAst
    "0.1.129.1.1.1.0.0": "3dca59425fea743323b7ef5b986caaaab6020ab45f4b83b27303d785546bd7bb",  # PipelineAst
    "0.1.129.1.1.1.0.0.0.1.0.0.0": "b36c511c08f8126275b0c76e1ae47fc2e1f5f5795c8ed8dba235fcaf7aa505a2",  # PipelineAst
    "0.1.129.1.2": "036ae00d914f9c34f699035910ca77177a3a23453ace8041e2db5ac5b9f82127",  # AssignmentStatementAst
    "0.1.129.1.3": "c15c94442f664f89ce17978c725a336915f516c81af66c91436ca353464c223f",  # AssignmentStatementAst
    "0.1.129.1.4": "01fb1e3c744ad324d841cdfe85bd05241d2a052626b24991b1a159286f4f57b0",  # IfStatementAst
    "0.1.129.1.4.1.0": "ab9bd0e327c4ab99ccafbe7007c1fdbee3bf7716271d90c7a57d18083c8100d0",  # AssignmentStatementAst
    "0.1.129.1.5": "147673608077cf77200f6c9d48d692625f44635417592d51117ca7c17c85d30f",  # AssignmentStatementAst
    "0.1.129.1.5.1.0.3.0.0": "d4d2bf23a4116eb52071c560f2652cafa1e4008eeb79a4702a118b8d37a56cbc",  # PipelineAst
    "0.1.129.1.6": "e1c1aa0538aac8b8dc74ba3162a0e16a675b7740cf27c0d5d447b3661242b31a",  # AssignmentStatementAst
    "0.1.129.1.7": "0ed190556fa0c9d4d6d686da520515bc197da8aff571c21573a8da20b90961ef",  # ForEachStatementAst
    "0.1.129.1.7.2.0": "6412f40cc1e37a64dc59cf7912cddc6702880e401f7bd2c3e3f93bde2d0107ec",  # TryStatementAst
    "0.1.129.1.7.2.0.0.0": "382af053cae0feb148fe2a8ebe6d26f47be63f4f44091c1b5621e4ccb58ad767",  # AssignmentStatementAst
    "0.1.129.1.7.2.0.0.1": "006e1c0df3446a9b61550f789de7a8c6eda0946972653d89d67df622214fd510",  # AssignmentStatementAst
    "0.1.129.1.7.2.0.0.2": "655968c611c906956e4516f801c2004a8cb802d979fc1d70d32789c86c30b4f4",  # AssignmentStatementAst
    "0.1.129.1.7.2.0.0.2.1.0.1.0.0.0": "2defc069f700054802808c4070135630c3f09b52ec80943acfd312bee7f09201",  # PipelineAst
    "0.1.129.1.7.2.0.0.3": "9ba9187e5a2f40cf806fee934b92d3d146c7f76a4bfef95594c58cf8691534bc",  # AssignmentStatementAst
    "0.1.129.1.7.2.0.0.3.1.0.1.0.0": "b9ec05f201e6ee02dd034e77f8805adf1369514869bf2f7b31bb5c322098cde8",  # PipelineAst
    "0.1.129.1.7.2.0.0.4": "7e99fcd416c8e3a0a77123db555abd632c59634649ffe2dd0dc364ff10d5946e",  # AssignmentStatementAst
    "0.1.129.1.7.2.0.0.5": "d16eba63561764dd886d15762ff8fc1a0e0a5b36d45bee1f19ce347c92cb619a",  # AssignmentStatementAst
    "0.1.129.1.7.2.0.0.6": "8509d9493352039c4948438cfa219e4563afc47369f87059332b878d275d4b32",  # IfStatementAst
    "0.1.129.1.7.2.0.0.6.1.0": "45c6b2f0765ddae9e432bd4e02ad280e6c89030c0c1b29d37a56101e3dc88d64",  # AssignmentStatementAst
    "0.1.129.1.7.2.0.0.6.1.0.1.0.1.0.0.0": "8612157a15dc0feaeb3147a1cf7d4e336bb4a21da856ada48301c5a488163ed9",  # PipelineAst
    "0.1.129.1.7.2.0.0.6.1.1": "e8c23760ea2f1b29e77c14d523af62b40efb7a9362f6707d11229067edf045f8",  # PipelineAst
    "0.1.129.1.7.2.0.0.6.2.0": "706e6e43b1e4e8ea3bf78cda410530a62f52a996b2c0ed93d26e7fc71c623c2e",  # TryStatementAst
    "0.1.129.1.7.2.0.0.6.2.0.0.0": "28c3674349fea0fb4c11236cbb16a52ee0acecb6f412ce614a7b2e9c2d24aff6",  # IfStatementAst
    "0.1.129.1.7.2.0.0.6.2.0.0.0.1.0": "6c17488d2719477f9793a6051eaca64a32901aa8a2fc2784118213b066c2cc3e",  # AssignmentStatementAst
    "0.1.129.1.7.2.0.0.6.2.0.0.0.3.0": "6e462a1390b420a9d35913f0b9c0a1be0cc4c37b4437cdaece2087a7081fb23e",  # AssignmentStatementAst
    "0.1.129.1.7.2.0.0.6.2.0.0.0.4.0": "c4681c4e4274242f5c5a3de45c2b30b297029d0221d378b37c9bf77a4ec6117f",  # AssignmentStatementAst
    "0.1.129.1.7.2.0.0.6.2.0.0.1": "abc73f6b396d88ecd38b6da266cd0ddd88186086249d0a409d1e67c833f13abf",  # AssignmentStatementAst
    "0.1.129.1.7.2.0.0.6.2.0.0.2": "f6311b73af447bac53d76c4b9449d4d032781ac1bff27ea4be8868ab1eb32c15",  # SwitchStatementAst
    "0.1.129.1.7.2.0.0.6.2.0.0.2.2.0": "eff20cb28a7ca7d8a7edc763c1d0759e79f2b0e8f1982bdd2ac1efa0e0677c2e",  # AssignmentStatementAst
    "0.1.129.1.7.2.0.0.6.2.0.0.2.4.0": "179fc93b0cfc6ecff440928db4cdac275abbb184baed5407a1af84442a14a18b",  # AssignmentStatementAst
    "0.1.129.1.7.2.0.0.6.2.0.0.3": "0fec0629e77a6f3e4b23d987ca1b530be48a1aeb9fd2b5cdd74b9cdbf3d89020",  # AssignmentStatementAst
    "0.1.129.1.7.2.0.0.6.2.0.0.4": "d1e24879a7fcb69e027b82b37e2280aabbdb8589dd7faf3f3a721c7fa555e5d8",  # SwitchStatementAst
    "0.1.129.1.7.2.0.0.6.2.0.0.4.2.0": "4ed6c999ebf4ab2287c5465615417d77a3873e0996a7c8712ea71ac5bcd2e16f",  # AssignmentStatementAst
    "0.1.129.1.7.2.0.0.6.2.0.0.4.4.0": "aa372a5901cf2d89091c3d3dd19763300c21f9d97920404c4632851dfb0b4aee",  # AssignmentStatementAst
    "0.1.129.1.7.2.0.0.6.2.0.1.0.0": "c129fdf654e28398f4ed9eeab44d6e2a52ed4fa93be82352f7763f1a47c9cdf6",  # PipelineAst
    "0.1.129.1.7.2.0.0.6.2.0.1.0.0.0.1.1.0.0": "22f6b5fe7d1033679c20be01849286800a99d692aba8fa198125db3b514775d6",  # PipelineAst
    "0.1.129.1.7.2.0.0.7": "d8dec202b49ef547c68b5000a7a80bc23da51181dfc28c31606bb4427035877b",  # AssignmentStatementAst
    "0.1.129.1.7.2.0.1.0.0": "48156896f659291586866e7ab544c27c7f7bd4d5e7026c71cf4fc7c4bb345f5d",  # AssignmentStatementAst
    "0.1.129.1.7.2.0.1.0.0.1.0.0.0.0": "72a4cb1ec2e4f86e38878105d2cb1cde1e0ff051b73b84e72851c74b5708671a",  # PipelineAst
    "0.1.129.1.8": "09fd39d9cbf9b4eeda36f75ec12ba5fe67ed258003868f48645dee9e49ad9a92",  # AssignmentStatementAst
    "0.1.129.1.8.1.0.0.0.0": "b41daa96f19f5dc3201afda090559ae7eeeedc339a13c02d843a4af493184413",  # PipelineAst
    "0.1.129.1.8.1.0.0.0.0.1.1.0.0.0": "8f68dd41b649816d70261e1c9a6ba38efe070080de92bd3ec9a20b668ab01252",  # PipelineAst
    "0.1.129.1.9": "e0b86cb196a000921c46c68367a95f4195bfbd160467d4e25c2cd0811bf39e24",  # IfStatementAst
    "0.1.129.1.9.1.0": "11e42f7b17267bd489d817b3971c3a347b49d88cf86291ecaf2185e8d42ea398",  # PipelineAst
    "0.1.129.1.9.1.0.0.1.0.0.0": "fcc68d150092083abd87b4e6a47d0f6a70a0b720ca50403cd781b58c04bb2bb0",  # PipelineAst
    "0.1.129.1.9.1.1": "3aeaf9bf1b90c3b886095339fd5de27e3c52828e3381d6b80cf479fe548917bc",  # AssignmentStatementAst
    "0.1.129.1.9.2.0": "89b8e1c8d408be97f5ccf12810e82748c82f01265670e464ad7f6d3a49567ff9",  # AssignmentStatementAst
    "0.1.129.1.9.2.1": "265a23184e022a92d4b3b5f46b63e55ec4c98368708f61e54a6a8e8698cca6ad",  # PipelineAst
    "0.1.129.1.9.2.1.0.3.0.0.0": "2357f457c2a5b0557151ef7d451187180c7dafab8510ca9a18f2da8caf2da7bf",  # PipelineAst
    "0.1.130": "63b1730a0b186abd9062f0d268cbaafbac547f9d1409833ada84f9411d1cadf7",  # AssignmentStatementAst
    "0.1.131": "7b932dde8cccb07619cb6d94909797194dd5038bf97ba5ed76d74cf97e3ff6c6",  # IfStatementAst
    "0.1.131.1.0": "6de7d5cd2de5cca734f453fa9d9cc6f9f32284514755b56de82cf2c864410e1e",  # AssignmentStatementAst
    "0.1.132": "af4d05788ebad8236c618d2647e4a856028d17ee62d5228aff56d79deaac6918",  # IfStatementAst
    "0.1.132.1.0": "82cacbc8ded44efb4068951a5c4c54118425ba9493362a125614cb7fc8828a00",  # AssignmentStatementAst
    "0.1.133": "8fc1908b820844b603f658d09c8f04b779c1bf13822bbeaedab0cb01c032b8ba",  # IfStatementAst
    "0.1.133.1.0": "b355cee7072c07c8b890a5be7225e37d8f8c1018d933a989a3c5eedefc85d77f",  # AssignmentStatementAst
    "0.1.134": "a95565b0e82d49a57d5d5136d65cb2baf8372884b2604d4adf16c07b9737c3db",  # IfStatementAst
    "0.1.134.1.0": "9573ff11d287d182f6853b9ae5b8f7510330ceb9b4301834172a758de7c0f8ec",  # AssignmentStatementAst
    "0.1.135": "39a611b04fcd9429a4ca78fa3a12228e452339cb1d67b0d9c33244f3e4479ddf",  # IfStatementAst
    "0.1.135.1.0": "39bc3498dfdb1d3b79f4d080aeaf58e8386a6fc7047cafbda02354a625a5b849",  # AssignmentStatementAst
    "0.1.136": "51bdc61f01d7ca4f18b3723dd990ddd2d23147bc83f166f4c60698179c0ecfb5",  # AssignmentStatementAst
    "0.1.136.1.0.1.9.0.0.0.0.0.0.0": "7a355744fe80489bfcffae18172575b93c01e1382c1709842a71849b559a21b0",  # PipelineAst
    "0.1.137": "3d0e6cdb4fb04b62d964b9910f08d3bd0cc7b482a835ca639f62bc304fa58e5d",  # PipelineAst
    "0.1.137.0.1.0.0": "ffb8cca15020b2dc9719a47a394d522ea0e74ce71ba7bd9877d4c5e2e1913470",  # PipelineAst
    "0.1.138": "44ad1fc1a72730b3efdfed21bbd11d918977add20115793ec15392371389d60c",  # PipelineAst
    "0.1.138.0.1.0.0": "01bca51d7b0ee472bedfa779074c9399ee449b393f60df68d412a10ca69e6f92",  # PipelineAst
    "0.1.139": "b2989eac1a006da5fffdf4fdf11150c6ec456ecb90f373a471a43f42e876f33a",  # PipelineAst
    "0.1.139.0.1.0.0": "ee791e1223bae27e6eb81ab57c3c0b642a7b8ac88ada06897fc67c2a54bc2bea",  # PipelineAst
    "0.1.140": "8a49fbf0c3510a01570c872629f66c17d793a3e257433728abae4102a964734b",  # PipelineAst
    "0.1.140.0.1.0.0": "30d344ecc1595340c700452c97fd9f8714232fe55d7883d111bec09f8a208603",  # PipelineAst
    "0.1.141": "7a45d8f1c2fe116be098ade40d879b60af419f045f3c4d543cb0dbe99db8837c",  # PipelineAst
    "0.1.141.0.1.0.0": "2187e9c814a84d6714d1533694c204084a3714d660bd774d0fd7c25bc8a5441a",  # PipelineAst
    "0.1.142": "c88daa77b4b46d00034218178cc7426af1f45233594b1be1bc35f8ca9d4dd280",  # PipelineAst
    "0.1.142.0.1.0.0": "b5a4985b7359f8c287d75d3ba7191a77958b8ce059c1d6ff3da13ebbf37c923f",  # PipelineAst
    "0.1.143": "5491180f8f977c8bf3d07c6e297e79689b36ad0e0febbc2cccdaa19c51b4c3ff",  # PipelineAst
    "0.1.143.0.1.0.0": "ac0c4760ea285a4e6e54ce6523d40d4d7845f40948cf3a04552140d4ec1b575c",  # PipelineAst
    "0.1.144": "4a204d7e349b9c2ffce32dc2f7242ffa80b705af117ca8879873c048fefce67f",  # PipelineAst
    "0.1.145": "34b6aaaaa1a6b28bf3f03dc68d5b53a4a416835285b19f7366613a21482b04b9",  # PipelineAst
    "0.1.146": "e327ee322a0f2c6cedf0b9b9b2acad4dffaf52e75588611a4431332693eb1c51",  # IfStatementAst
    "0.1.146.1.0": "d6e0f5c99973fa44ab0d45b1d4c3f31961270a8fdbe5419ac67c7a7acb7fd0b6",  # PipelineAst
    "0.1.146.1.0.0.1.0.0.0.1.1.0.0.0.0": "1c82f3a9a936cb15ca405f746ec97a13778535fdf80e44ea1da78e1f783a5bde",  # PipelineAst
    "0.1.146.1.0.0.1.0.0.0.1.3.0.0.0.0": "59a673634b806e722d528701f4e368191c5f08924dfa7e2c16332546239c19a7",  # PipelineAst
    "0.1.147": "a7c7ac51a4ec2ccee24f067d3a2f2a09ba089c603c3442c6f1c25da5ee47f9b5",  # PipelineAst
    "0.1.148": "797692dc0cf9f700e778885922c2096a3ee58e0e1c780008c04f72dafeaea0ba",  # PipelineAst
    "0.1.148.0.1.0.0.0.1.9.0.0.0.0.0.0.0.0.0": "8deb529be250c46d1d1031839b96a86faa97c350fcd8a44fb5c041402e94a7cd",  # PipelineAst
    "0.1.148.0.1.0.0.0.1.9.0.0.0.0.0.1.1.0.0.0": "fa21e0842934ea811bc40e4a871d295bc84653e192954ea1c49efd09b7ab7238",  # PipelineAst
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
    "StartsWith": frozenset(["dcdns"]),
    "ToLower": frozenset(["", "dcdns", "dns", "ot", "p"]),
    "ToString": frozenset(["", "_", "a"]),
    "ToUniversalTime": frozenset([""]),
    "Translate": frozenset(["a"]),
    "Trim": frozenset(["line", "matches", "v", "values"]),
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
    ("[IO.File]", "writeallbytes", "(Join-Path $certdir $certfile)", "$der"),
    ("[IO.File]", "writeallbytes", "(Join-Path $certdir $crlfile)", "$der"),
    (
        "[IO.File]",
        "writealltext",
        "$outpath",
        "$script:js.Serialize($obj)",
        "(New-Object Text.UTF8Encoding($false))",
    ),
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
    # input of New-Item: New-Item -ItemType Directory -Force -Path $certDir
    "<script>::certdir": [
        ("assign Equals", "Join-Path $OutDir 'certs'"),
    ],
    # input of Join-Path: Join-Path $certDir $certFile
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
    # input of Join-Path: Join-Path $certDir $crlFile
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
    # input of Test-Path: Test-Path $outParent
    "_writejson::outparent": [
        ("assign Equals", "Split-Path $outPath -Parent"),
    ],
    # input of Split-Path: Split-Path $outPath -Parent
    "_writejson::outpath": [
        ("assign Equals", "Join-Path $OutDir $outName"),
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
    ("Test-Path $outParent", ("function _writeJson", "if-condition after []")),
    (
        "New-Item -ItemType Directory -Force -Path $outParent",
        ("function _writeJson", "if (-not (Test-Path $outParent)) after []"),
    ),
    ("Out-Null", ("function _writeJson", "if (-not (Test-Path $outParent)) after []")),
    ("New-Object Text.UTF8Encoding($false)", ("function _writeJson",)),
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
        "New-Item -ItemType Directory -Force -Path $OutDir",
        ("guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",),
    ),
    ("Out-Null", ("guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",)),
    (
        "Add-Type -AssemblyName System.Web.Extensions",
        ("guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",),
    ),
    (
        "New-Object System.Web.Script.Serialization.JavaScriptSerializer",
        ("guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",),
    ),
    (
        "_searchMarker ([bool]$search.complete) ([string]$search.reason) $returned $written $failures $rows",
        ("guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return", "function _markSearch"),
    ),
    (
        "_certutilRead 'CA\\CommonName'",
        ("guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",),
    ),
    (
        "_certutilStringFrom $cnRead.lines $cnRead.code 'CommonName'",
        ("guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",),
    ),
    (
        "_certutilFlags 'policy\\EditFlags'",
        ("guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",),
    ),
    (
        "_certutilFlags 'CA\\InterfaceFlags'",
        ("guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",),
    ),
    (
        "_certutilDword 'CA\\AuditFilter'",
        ("guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",),
    ),
    (
        "_certutilMultiSz 'policy\\DisableExtensionList'",
        ("guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",),
    ),
    (
        "_certutilDword 'CA\\CAType'",
        ("guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",),
    ),
    (
        "_caKindFromType $caType",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "if ($null -ne $caType) after []",
        ),
    ),
    ("hostname", ("guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",)),
    ("_rootDse", ("guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",)),
    (
        "_caSecurityRead $name",
        ("guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return", "function _localCaRow"),
    ),
    (
        "_list $editFlags",
        ("guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return", "function _localCaRow"),
    ),
    (
        "_list $interfaceFlags",
        ("guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return", "function _localCaRow"),
    ),
    (
        "_list $disabledExt",
        ("guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return", "function _localCaRow"),
    ),
    (
        "_search \"CN=Enrollment Services,$pksDn\" '(objectClass=pKIEnrollmentService)' @('cn', 'dnshostname', 'certificatetemplates', 'objectguid')",
        ("guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",),
    ),
    (
        "_entryProps $e",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "foreach ($e in $es.entries)",
            "try",
        ),
    ),
    (
        "_requireSchema $p 'enrollment-services'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "foreach ($e in $es.entries)",
            "try",
        ),
    ),
    (
        "_v $p 'cn'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "foreach ($e in $es.entries)",
            "try",
        ),
    ),
    (
        "_v $p 'dnshostname'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "foreach ($e in $es.entries)",
            "try",
        ),
    ),
    (
        "_v $p 'certificatetemplates'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "foreach ($e in $es.entries)",
            "try",
        ),
    ),
    (
        "ForEach-Object { [string]$_ }",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "foreach ($e in $es.entries)",
            "try",
        ),
    ),
    (
        "_localCaRow $cn $dns (_guidHex @(_v $p 'objectguid')) $true",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "foreach ($e in $es.entries)",
            "try",
            "if ($isLocal) after []",
        ),
    ),
    (
        "_guidHex @(_v $p 'objectguid')",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "foreach ($e in $es.entries)",
            "try",
            "if ($isLocal) after []",
        ),
    ),
    (
        "_v $p 'objectguid'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "foreach ($e in $es.entries)",
            "try",
            "if ($isLocal) after []",
        ),
    ),
    (
        "_guidHex @(_v $p 'objectguid')",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "foreach ($e in $es.entries)",
            "try",
            "else of [($isLocal)]",
        ),
    ),
    (
        "_v $p 'objectguid'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "foreach ($e in $es.entries)",
            "try",
            "else of [($isLocal)]",
        ),
    ),
    (
        "Where-Object { $_.name -ceq $caCommonName }",
        ("guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return", "if-condition after []"),
    ),
    (
        "_localCaRow $caCommonName $localFqdn '' $false",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "if ($caCommonName -and -not $esFailures -and -not ($caConfig | Where-Object { $_.name -ceq $caCommonName })) after []",
        ),
    ),
    (
        "_markSearch 'ca-config' $caSearch (@($es.entries).Count + $standalone) $caConfig.Count $esFailures",
        ("guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",),
    ),
    (
        "_markSearch 'enrollment-services' $es @($es.entries).Count $enrollmentServices.Count $esFailures",
        ("guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",),
    ),
    (
        "_search \"CN=Certificate Templates,$pksDn\" '(objectClass=pKICertificateTemplate)' @( 'cn', 'displayname', 'objectguid', 'mspki-certificate-name-flag', 'mspki-enrollment-flag', 'pkiextendedkeyusage', 'mspki-certificate-policy', 'pkicsp', 'mspki-template-schema-version', 'mspki-cert-template-oid', 'mspki-minimal-key-size', 'ntsecuritydescriptor') -Sd",
        ("guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",),
    ),
    (
        "_entryProps $e",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "foreach ($e in $ts.entries)",
            "try",
        ),
    ),
    (
        "_requireSchema $p 'templates'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "foreach ($e in $ts.entries)",
            "try",
        ),
    ),
    (
        "_v $p 'mspki-certificate-name-flag'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "foreach ($e in $ts.entries)",
            "try",
            "if-condition after []",
        ),
    ),
    (
        "_v $p 'mspki-certificate-name-flag'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "foreach ($e in $ts.entries)",
            "try",
            "if (@(_v $p 'mspki-certificate-name-flag').Count) after []",
        ),
    ),
    (
        "_v $p 'mspki-enrollment-flag'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "foreach ($e in $ts.entries)",
            "try",
            "if-condition after []",
        ),
    ),
    (
        "_v $p 'mspki-enrollment-flag'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "foreach ($e in $ts.entries)",
            "try",
            "if (@(_v $p 'mspki-enrollment-flag').Count) after []",
        ),
    ),
    (
        "_v $p 'pkicsp'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "foreach ($e in $ts.entries)",
            "try",
        ),
    ),
    (
        "ForEach-Object { [string]$_ }",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "foreach ($e in $ts.entries)",
            "try",
        ),
    ),
    (
        "_sdRead (@(_v $p 'ntsecuritydescriptor')[0])",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "foreach ($e in $ts.entries)",
            "try",
        ),
    ),
    (
        "_v $p 'ntsecuritydescriptor'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "foreach ($e in $ts.entries)",
            "try",
        ),
    ),
    (
        "_v $p 'cn'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "foreach ($e in $ts.entries)",
            "try",
        ),
    ),
    (
        "_guidHex @(_v $p 'objectguid')",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "foreach ($e in $ts.entries)",
            "try",
        ),
    ),
    (
        "_v $p 'objectguid'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "foreach ($e in $ts.entries)",
            "try",
        ),
    ),
    (
        "_v $p 'displayname'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "foreach ($e in $ts.entries)",
            "try",
        ),
    ),
    (
        "_v $p 'mspki-template-schema-version'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "foreach ($e in $ts.entries)",
            "try",
            "if-condition after []",
        ),
    ),
    (
        "_v $p 'mspki-template-schema-version'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "foreach ($e in $ts.entries)",
            "try",
            "if (@(_v $p 'mspki-template-schema-version').Count) after []",
        ),
    ),
    (
        "_v $p 'mspki-cert-template-oid'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "foreach ($e in $ts.entries)",
            "try",
        ),
    ),
    (
        "_v $p 'pkiextendedkeyusage'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "foreach ($e in $ts.entries)",
            "try",
        ),
    ),
    (
        "ForEach-Object { [string]$_ }",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "foreach ($e in $ts.entries)",
            "try",
        ),
    ),
    (
        "_decode $nf $NAME_FLAGS",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "foreach ($e in $ts.entries)",
            "try",
        ),
    ),
    (
        "_decode $ef $ENROLL_FLAGS",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "foreach ($e in $ts.entries)",
            "try",
        ),
    ),
    (
        "_v $p 'mspki-minimal-key-size'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "foreach ($e in $ts.entries)",
            "try",
            "if-condition after []",
        ),
    ),
    (
        "_v $p 'mspki-minimal-key-size'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "foreach ($e in $ts.entries)",
            "try",
            "if (@(_v $p 'mspki-minimal-key-size').Count) after []",
        ),
    ),
    (
        "_v $p 'mspki-certificate-policy'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "foreach ($e in $ts.entries)",
            "try",
        ),
    ),
    (
        "ForEach-Object { [string]$_ }",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "foreach ($e in $ts.entries)",
            "try",
        ),
    ),
    (
        "_markSearch 'templates' $ts @($ts.entries).Count $templates.Count $tsFailures",
        ("guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",),
    ),
    (
        "_search \"CN=OID,$pksDn\" '(objectClass=msPKI-Enterprise-Oid)' @('mspki-cert-template-oid', 'objectguid', 'displayname', 'msds-oidtogrouplink')",
        ("guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",),
    ),
    (
        "_entryProps $e",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "foreach ($e in $os.entries)",
            "try",
        ),
    ),
    (
        "_requireSchema $p 'oid-objects'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "foreach ($e in $os.entries)",
            "try",
        ),
    ),
    (
        "_v $p 'msds-oidtogrouplink'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "foreach ($e in $os.entries)",
            "try",
            "if-condition after []",
        ),
    ),
    (
        "_v $p 'msds-oidtogrouplink'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "foreach ($e in $os.entries)",
            "try",
            "if (@(_v $p 'msds-oidtogrouplink').Count) after []",
        ),
    ),
    (
        "_v $p 'mspki-cert-template-oid'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "foreach ($e in $os.entries)",
            "try",
        ),
    ),
    (
        "_guidHex @(_v $p 'objectguid')",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "foreach ($e in $os.entries)",
            "try",
        ),
    ),
    (
        "_v $p 'objectguid'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "foreach ($e in $os.entries)",
            "try",
        ),
    ),
    (
        "_v $p 'displayname'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "foreach ($e in $os.entries)",
            "try",
        ),
    ),
    (
        "_markSearch 'oid-objects' $os @($os.entries).Count $oids.Count $osFailures",
        ("guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",),
    ),
    (
        "_objAcl $pair[0] $pair[1]",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "foreach ($pair in @( @($pksDn, 'pks_container'), @(\"CN=NTAuthCertificates,$pksDn\", 'ntauth'), @(\"CN=AIA,$pksDn\", 'aia'), @(\"CN=CDP,$pksDn\", 'cdp'), @(\"CN=Certification Authorities,$pksDn\", 'pks_container'), @(\"CN=Enrollment Services,$pksDn\", 'pks_container')))",
        ),
    ),
    (
        "_childAcls \"CN=Certification Authorities,$pksDn\" '(objectClass=certificationAuthority)' 'ca_object'",
        ("guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",),
    ),
    (
        "_childAcls \"CN=Enrollment Services,$pksDn\" '(objectClass=pKIEnrollmentService)' 'ca_object'",
        ("guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",),
    ),
    (
        "_markSearch 'pki-acls' $pkiSearch (6 + $caObjects.returned + $esObjects.returned) $pkiAcls.Count (@($caObjects.failures) + @($esObjects.failures))",
        ("guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",),
    ),
    (
        "Join-Path $OutDir 'certs'",
        ("guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return", "try"),
    ),
    (
        "_search \"CN=AIA,$pksDn\" '(objectClass=certificationAuthority)' @('cn', 'cacertificate')",
        ("guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return", "try"),
    ),
    (
        "_entryProps $e",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "try",
            "foreach ($e in $aia.entries)",
            "try",
        ),
    ),
    (
        "_requireSchema $p 'certs'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "try",
            "foreach ($e in $aia.entries)",
            "try",
        ),
    ),
    (
        "_v $p 'cn'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "try",
            "foreach ($e in $aia.entries)",
            "try",
        ),
    ),
    (
        "_v $p 'cacertificate'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "try",
            "foreach ($e in $aia.entries)",
            "try",
            "foreach ($blob in @(_v $p 'cacertificate'))",
        ),
    ),
    (
        "_certKindFromDer $der",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "try",
            "foreach ($e in $aia.entries)",
            "try",
            "foreach ($blob in @(_v $p 'cacertificate'))",
        ),
    ),
    (
        "New-Item -ItemType Directory -Force -Path $certDir",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "try",
            "foreach ($e in $aia.entries)",
            "try",
            "foreach ($r in $rows)",
        ),
    ),
    (
        "Out-Null",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "try",
            "foreach ($e in $aia.entries)",
            "try",
            "foreach ($r in $rows)",
        ),
    ),
    (
        "_safeFileName $cn",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "try",
            "foreach ($e in $aia.entries)",
            "try",
            "foreach ($r in $rows)",
        ),
    ),
    (
        "Join-Path $certDir $certFile",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "try",
            "foreach ($e in $aia.entries)",
            "try",
            "foreach ($r in $rows)",
        ),
    ),
    (
        "_search \"CN=CDP,$pksDn\" '(objectClass=cRLDistributionPoint)' @('cn', 'certificaterevocationlist', 'objectguid')",
        ("guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return", "try"),
    ),
    (
        "_entryProps $e",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "try",
            "foreach ($e in $cdp.entries)",
            "try",
        ),
    ),
    (
        "_requireSchema $p 'crls'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "try",
            "foreach ($e in $cdp.entries)",
            "try",
        ),
    ),
    (
        "_v $p 'cn'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "try",
            "foreach ($e in $cdp.entries)",
            "try",
        ),
    ),
    (
        "_v $p 'certificaterevocationlist'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "try",
            "foreach ($e in $cdp.entries)",
            "try",
            "if-condition after []",
        ),
    ),
    (
        "_v $p 'certificaterevocationlist'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "try",
            "foreach ($e in $cdp.entries)",
            "try",
            "guard if (-not @(_v $p 'certificaterevocationlist').Count) -> continue",
        ),
    ),
    (
        "New-Item -ItemType Directory -Force -Path $certDir",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "try",
            "foreach ($e in $cdp.entries)",
            "try",
            "guard if (-not @(_v $p 'certificaterevocationlist').Count) -> continue",
        ),
    ),
    (
        "Out-Null",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "try",
            "foreach ($e in $cdp.entries)",
            "try",
            "guard if (-not @(_v $p 'certificaterevocationlist').Count) -> continue",
        ),
    ),
    (
        "_safeFileName $cn",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "try",
            "foreach ($e in $cdp.entries)",
            "try",
            "guard if (-not @(_v $p 'certificaterevocationlist').Count) -> continue",
        ),
    ),
    (
        "Join-Path $certDir $crlFile",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "try",
            "foreach ($e in $cdp.entries)",
            "try",
            "guard if (-not @(_v $p 'certificaterevocationlist').Count) -> continue",
        ),
    ),
    (
        "_guidHex @(_v $p 'objectguid')",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "try",
            "foreach ($e in $cdp.entries)",
            "try",
            "guard if (-not @(_v $p 'certificaterevocationlist').Count) -> continue",
        ),
    ),
    (
        "_v $p 'objectguid'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "try",
            "foreach ($e in $cdp.entries)",
            "try",
            "guard if (-not @(_v $p 'certificaterevocationlist').Count) -> continue",
        ),
    ),
    (
        "_v $p 'distinguishedname'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "try",
            "foreach ($e in $cdp.entries)",
            "try",
            "guard if (-not @(_v $p 'certificaterevocationlist').Count) -> continue",
        ),
    ),
    (
        "_markSearch 'certs' $aia @($aia.entries).Count $aiaObjects $aiaFailures $certIndex.Count",
        ("guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return", "try"),
    ),
    (
        "_markSearch 'crls' $cdp @($cdp.entries).Count $cdpObjects $cdpFailures $crlIndex.Count",
        ("guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return", "try"),
    ),
    (
        'Write-Warning "certs pass failed: $($_.Exception.Message)"',
        ("guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return", "catch []"),
    ),
    (
        "Import-Module WebAdministration -ErrorAction Stop",
        ("guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return", "try"),
    ),
    (
        "Get-Website -ErrorAction Stop",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "if (-not $endpointsSkipped) after []",
            "try",
            "foreach ($site in (Get-Website -ErrorAction Stop))",
        ),
    ),
    (
        "Get-WebApplication -Site $site.Name -ErrorAction Stop",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
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
            "if (-not $endpointsSkipped) after []",
            "catch []",
        ),
    ),
    (
        "_searchMarker $endpointsComplete $endpointsReason $webEndpoints.Count $webEndpoints.Count $iisFailures",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "if (-not $endpointsSkipped) after []",
        ),
    ),
    (
        "_search $domNc '(altSecurityIdentities=*)' @('altsecurityidentities', 'objectguid')",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "if ($CollectDcMapping) after []",
            "try",
        ),
    ),
    (
        "_entryProps $e",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
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
            "if ($CollectDcMapping) after []",
            "try",
        ),
    ),
    (
        'Write-Warning "esc14-altsecid failed: $($_.Exception.Message)"',
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "if ($CollectDcMapping) after []",
            "catch []",
        ),
    ),
    (
        "New-Object Management.Automation.PSCredential( $DcRegistryUser, (ConvertTo-SecureString $DcRegistryPass -AsPlainText -Force))",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "if ($CollectDcMapping) after []",
            "if ($DcRegistryUser) after []",
        ),
    ),
    (
        "ConvertTo-SecureString $DcRegistryPass -AsPlainText -Force",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "if ($CollectDcMapping) after []",
            "if ($DcRegistryUser) after []",
        ),
    ),
    (
        "_search $domNc '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))' @('dnshostname', 'objectguid')",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "if ($CollectDcMapping) after []",
        ),
    ),
    (
        "_entryProps $e",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "if ($CollectDcMapping) after []",
            "foreach ($e in $dcs.entries)",
            "try",
        ),
    ),
    (
        "_requireSchema $p 'dc-config'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "if ($CollectDcMapping) after []",
            "foreach ($e in $dcs.entries)",
            "try",
        ),
    ),
    (
        "_v $p 'dnshostname'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "if ($CollectDcMapping) after []",
            "foreach ($e in $dcs.entries)",
            "try",
        ),
    ),
    (
        "_guidHex @(_v $p 'objectguid')",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "if ($CollectDcMapping) after []",
            "foreach ($e in $dcs.entries)",
            "try",
        ),
    ),
    (
        "_v $p 'objectguid'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "if ($CollectDcMapping) after []",
            "foreach ($e in $dcs.entries)",
            "try",
        ),
    ),
    (
        "_v $p 'distinguishedname'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
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
            "if ($CollectDcMapping) after []",
            "foreach ($e in $dcs.entries)",
            "try",
        ),
    ),
    (
        "Where-Object { $null -eq $_.strong_certificate_binding_enforcement }",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "if ($CollectDcMapping) after []",
        ),
    ),
    (
        'Write-Warning "esc10-dc-registry: all $($dcConfigs.Count) DC(s) failed the registry read -- pass effectively skipped (WMI access denied? provide -DcRegistryUserB64/-DcRegistryPassB64 for SSH/double-hop)."',
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "if ($CollectDcMapping) after []",
            "if ($dcConfigs.Count -gt 0 -and $wmiFailures -eq $dcConfigs.Count) after []",
        ),
    ),
    (
        "_markSearch 'dc-config' $dcs @($dcs.entries).Count $dcConfigs.Count $dcFailures",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "if ($CollectDcMapping) after []",
            "else of [($dcConfigs.Count -gt 0 -and $wmiFailures -eq $dcConfigs.Count)]",
        ),
    ),
    ("Get-Date", ("guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",)),
    ("hostname", ("guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",)),
    (
        "_writeJson @($caConfig) 'ca-config.json'",
        ("guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",),
    ),
    (
        "_writeJson @($templates) 'templates.json'",
        ("guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",),
    ),
    (
        "_writeJson @($oids) 'oid-objects.json'",
        ("guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",),
    ),
    (
        "_writeJson @($pkiAcls) 'pki-acls.json'",
        ("guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",),
    ),
    (
        "_writeJson @($webEndpoints) 'web-endpoints.json'",
        ("guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",),
    ),
    (
        "_writeJson @($dcConfigs) 'dc-config.json'",
        ("guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",),
    ),
    (
        "_writeJson @($principalMappings) 'principal-mappings.json'",
        ("guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",),
    ),
    (
        "_writeJson $enrollmentServices 'enrollment-services.json'",
        ("guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",),
    ),
    (
        "_writeJson $caSecurity 'ca-security.json'",
        ("guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",),
    ),
    (
        "_writeJson ([ordered]@{ certs = @($certIndex); crls = @($crlIndex) }) 'certs/index.json'",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "if (-not $certsSkipped) after []",
        ),
    ),
    (
        "_writeJson $manifest 'collector-manifest.json'",
        ("guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",),
    ),
    (
        "Write-Output (\"OK cas={0} templates={1} oids={2} pkiacls={3} endpoints={4} dcs={5} altsecid={6} certs={7} crls={8} editflags=[{9}] ca={10}\" -f ` $caConfig.Count, $templates.Count, $oids.Count, $pkiAcls.Count, $webEndpoints.Count, $dcConfigs.Count, $principalMappings.Count, $certIndex.Count, $crlIndex.Count, ((@($editFlags) | Where-Object { $_ }) -join ','), $caCommonName)",
        ("guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",),
    ),
    ("Where-Object { $_ }", ("guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",)),
    (
        "[IO.File]::WriteAllText($outPath, $script:JS.Serialize($obj), (New-Object Text.UTF8Encoding($false)))",
        ("function _writeJson",),
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
            "try",
            "foreach ($e in $aia.entries)",
            "try",
            "foreach ($r in $rows)",
        ),
    ),
    (
        "[IO.File]::WriteAllBytes((Join-Path $certDir $crlFile), $der)",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "try",
            "foreach ($e in $cdp.entries)",
            "try",
            "guard if (-not @(_v $p 'certificaterevocationlist').Count) -> continue",
        ),
    ),
    (
        "$reg.GetDWORDValue($HKLM, 'SYSTEM\\CurrentControlSet\\Services\\Kdc', 'StrongCertificateBindingEnforcement')",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
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
# lower-cased mirror. `_cf` is the one canonicalization point; the regression
# meta-test re-runs every probe with randomized casing and requires identical
# verdicts.
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


def _statement_digests(dump: dict[str, Any]) -> dict[str, str]:
    """Digest of the normalized AST subtree (node types, every property and every
    string value) of EVERY statement: each top-level statement and each statement
    inside every function / scriptblock body, keyed by its structural index path.
    A function definition is itself a statement, so its subtree digest covers the
    function's name, parameters and whole body (this subsumes the former
    LOCAL_FUNCTION_BODIES). Any edit anywhere changes some statement's digest (or
    its path), so STATEMENT_DIGESTS below must be hand-edited before a
    regeneration will match."""
    rows = dump["ast_rows"]
    paths = _row_index_paths(rows)
    out: dict[str, str] = {}
    for i, row in enumerate(rows):
        if row[1] == "Statements":  # an element of a (named / statement) block
            out[".".join(str(n) for n in paths[i])] = _subtree_digest(rows, i)
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


# --- case-insensitivity meta-test (DeepSeek B-R3-1) --------------------------------
# PowerShell command/function/parameter/variable names are case-insensitive, so
# every regression snippet must get the SAME verdict when the casing of its
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
    "NamedBlockAst.BlockKind": "inert: begin/process/end/clean block kind, control structure",
    "NamedBlockAst.Statements": "structural: its child nodes are each serialized and checked",
    "NamedBlockAst.Traps": "check: node_types (a trap yields a refused TrapStatementAst)",
    "NamedBlockAst.Unnamed": "inert: whether the block keyword was written, no I/O",
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
