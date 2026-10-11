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


def _prefetch(extra: dict[str, bytes]) -> None:
    todo = {k: v for k, v in {**_PENDING, **extra}.items() if k not in _DUMP_CACHE}
    _PENDING.clear()
    if not todo:
        return
    with tempfile.TemporaryDirectory(prefix="adcs-gate-") as tmp:
        items = sorted(todo.items())
        for start in range(0, len(items), _BATCH):
            chunk = items[start : start + _BATCH]
            paths = []
            for key, data in chunk:
                path = Path(tmp) / f"{key}.ps1"
                path.write_bytes(data)
                paths.append(path)
            for (key, _), entry in zip(chunk, _run_dumper(paths, "-Many"), strict=True):
                _DUMP_CACHE[key] = entry


def _dump(script: Path) -> dict[str, Any]:
    data = script.read_bytes()
    key = _key(data)
    if key not in _DUMP_CACHE:
        _pwsh()
        _prefetch({key: data})
    return _DUMP_CACHE[key]


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
_SEARCHER = re.compile(r"New-Object DirectoryServices\.DirectorySearcher\(\$\w+\)")
_SERIALISER = re.compile(r"New-Object System\.Web\.Script\.Serialization\.JavaScriptSerializer")
_LOCAL_TABLE = re.compile(r"(\[ordered\])?@\{\}")
MEMBER_ASSIGNMENTS_ALLOWED: dict[tuple[str, str], re.Pattern[str]] = {
    ("s", "filter"): _SEARCHER,
    ("s", "pagesize"): _SEARCHER,
    ("s", "searchscope"): _SEARCHER,
    ("s", "securitymasks"): _SEARCHER,
    ("ds", "filter"): _SEARCHER,
    ("ds", "pagesize"): _SEARCHER,
    ("ds", "searchscope"): _SEARCHER,
    ("js", "maxjsonlength"): _SERIALISER,
}
INDEX_ASSIGNMENTS_ALLOWED: dict[str, re.Pattern[str]] = {
    "cakindbyname": _LOCAL_TABLE,
    "casecurity": _LOCAL_TABLE,
    "enrollmentservices": _LOCAL_TABLE,
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
            if "." in target.split(".", 1)[-1] or "[" in target:
                pattern = None  # nested targets ($x.A.B = ..., $x.A[0] = ...) are never allowed
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
    "DirectoryServices.DirectoryEntry",
    "DirectoryServices.SecurityMasks",
    "Security.Principal.NTAccount",
    "Security.Principal.SecurityIdentifier",
}

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
        "FileRedirectionAst",
        "ForEachStatementAst",
        "FunctionDefinitionAst",
        "HashtableAst",
        "IfStatementAst",
        "IndexExpressionAst",
        "InvokeMemberExpressionAst",
        "MemberExpressionAst",
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
    "_writeJson",
    "_ldapEntry",
    "_ldapRootDse",
    "_ldapRoot",
    "_search",
    "_decode",
    "_decodeBinding",
    "_parseCertutilFlagLines",
    "_parseCertutilDwordLines",
    "_parseCertutilMultiSzLines",
    "_epaToken",
    "_classifyApp",
    "_caKindFromType",
    "_safeFileName",
    "_certKindFromDer",
    "_parseAces",
    "_objAcl",
    "_childAcls",
    "_readOwner",
    "_caSecurityAces",
    "_rawSdOwner",
    "_caSecurityOwner",
    "_certutilFlags",
    "_certutilDword",
    "_certutilMultiSz",
)

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
    {("erroractionpreference", ("assign Equals", _SCRIPT, "'Stop'"))}
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
    {"New-Item", "certutil", "Get-WmiObject", "Import-Module", "Add-Type", "_writeJson"}
)
_GUARDED_STATIC = frozenset({("[IO.File]", "WriteAllText"), ("[IO.File]", "WriteAllBytes")})
_GUARDED_INSTANCE = frozenset({"GetDWORDValue", "OpenSubKey"})
# Which arguments of a guarded operation are inputs whose variables must be
# pinned (None = all). The data written is not an input: only the path is.
_GUARDED_INPUT_ARGS: dict[str, tuple[int, ...] | None] = {
    "_writeJson": (1,),
    "WriteAllText": (0,),
    "WriteAllBytes": (0,),
}

# Allowlisted instance method -> the receiver roots it may be called on
# (lower-cased; "" = a non-variable receiver such as `(Get-Date)` or a
# parenthesised expression). A call on any other receiver fails.
INSTANCE_RECEIVERS: dict[str, frozenset[str]] = {
    "Add": frozenset(["ds", "s"]),
    "ContainsKey": frozenset(["cakindbyname"]),
    "FindAll": frozenset(["ds", "s"]),
    "FindOne": frozenset(["s"]),
    "GetAccessRules": frozenset(["sd"]),
    "GetDWORDValue": frozenset(["reg"]),
    "GetEnumerator": frozenset(["map"]),
    "GetOwner": frozenset(["sd"]),
    "GetString": frozenset([""]),
    "GetValue": frozenset(["key"]),
    "OpenSubKey": frozenset([""]),
    "Replace": frozenset(["matches"]),
    "Serialize": frozenset(["js"]),
    "SetSecurityDescriptorBinaryForm": frozenset(["sd"]),
    "StartsWith": frozenset(["dcdns"]),
    "ToLower": frozenset(["", "dcdns", "dns", "ot", "p"]),
    "ToString": frozenset(["", "a"]),
    "ToUniversalTime": frozenset([""]),
    "Translate": frozenset(["a"]),
    "Trim": frozenset(["line", "matches"]),
    "TrimStart": frozenset([""]),
}

# Every variable whose binding matters, pinned to the EXACT multiset of its
# bindings (kind, scope, value) — see _bindings_by_var for the kinds. Required:
# write roots, variables in write/exec inputs, receivers of every instance call
# and property/index write, and transitively every variable their bindings
# read (_required_vars). An empty list means "must stay unbound". Both
# directions are strict: an extra binding (a rebind) and a stale entry fail.
# Each comment is the first reason the variable is required. Names are merged
# across scopes, so e.g. _b64's parameter $s shares a pin with the searcher $s.
# Edit by hand, with a reason; never paste a fresh dump of the bindings.
PINNED_BINDINGS: dict[str, list[tuple[str, str, str]]] = {
    # receiver of .Translate()
    "a": [
        ("assign Equals", "<script>", "_objAcl $pair[0] $pair[1]"),
        ("foreach", "_caSecurityAces", "$rsd.DiscretionaryAcl"),
        (
            "foreach",
            "_parseAces",
            "$sd.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])",
        ),
    ],
    # read by a binding of $flat
    "aces": [
        (
            "assign Equals",
            "<script>",
            "if ($ca.registry_config_collected) { ,(_caSecurityAces $ca.name) } else { ,@() }",
        ),
    ],
    # read by a binding of $p
    "app": [
        ("foreach", "<script>", "(Get-WebApplication -Site $site.Name)"),
    ],
    # read by a binding of $caconfig
    "auditfilter": [
        ("assign Equals", "<script>", "_certutilDword 'CA\\AuditFilter'"),
    ],
    # read by a binding of $der
    "blob": [
        ("foreach", "<script>", "$p['cacertificate']"),
    ],
    # read by a binding of $rsd
    "bytes": [
        ("arg", "_rawSdOwner", "$key.GetValue('Security')"),
        ("assign Equals", "_caSecurityAces", "$key.GetValue('Security')"),
        ("parameter", "_rawSdOwner", "[byte[]]$bytes"),
    ],
    # read by a binding of $csps
    "c": [
        (
            "assign Equals",
            "_certKindFromDer",
            "New-Object Security.Cryptography.X509Certificates.X509Certificate2(,$der)",
        ),
        ("foreach", "<script>", "$p['pKICSP']"),
    ],
    # read by a binding of $casecurity
    "ca": [
        ("foreach", "<script>", "$caConfig"),
    ],
    # read by a binding of $caconfig
    "cacommonname": [
        (
            "assign Equals",
            "<script>",
            "((& certutil -getreg CA\\CommonName 2>$null) | Where-Object { $_ -match 'CommonName REG_SZ = (.+)' } | ForEach-Object { $Matches[1].Trim() } | Select-Object -First 1)",
        ),
    ],
    # read by a binding of $ca
    "caconfig": [
        ("assign Equals", "<script>", "@()"),
        (
            "assign PlusEquals",
            "<script>",
            "[ordered]@{ name = $caCommonName dns = $localFqdn config_string = \"$localFqdn\\$caCommonName\" kind = (_caKindFromType $caType) edit_flags = (@($editFlags)) interface_flags= (@($interfaceFlags)) audit_filter = $auditFilter ca_patch_state = 'unknown' disabled_extensions = (@($disabledExt)) owner_sid = (_caSecurityOwner $caCommonName) registry_config_collected = $true }",
        ),
        (
            "assign PlusEquals",
            "<script>",
            "[ordered]@{ name = $cn dns = $dns config_string = \"$dns\\$cn\" kind = 'issuing' # enterprise by definition (it is in Enrollment Services) edit_flags = (@()) interface_flags= (@()) audit_filter = $null ca_patch_state = 'unknown' disabled_extensions = (@()) owner_sid = '' registry_config_collected = $false }",
        ),
        (
            "assign PlusEquals",
            "<script>",
            "[ordered]@{ name = $cn dns = $dns config_string = \"$dns\\$cn\" kind = (_caKindFromType $caType) edit_flags = (@($editFlags)) interface_flags= (@($interfaceFlags)) audit_filter = $auditFilter # Collector cannot yet read CA build/patch level statically (ESC15 / CVE-2024-49019). # Emitting 'unknown' lets the detector degrade the ESC15 finding to MEDIUM; a # future enhancement may populate this from the OS build. ca_patch_state = 'unknown' disabled_extensions = (@($disabledExt)) # CA\\Security owner (ESC7 owner-based control, WI-037). Empty when the local # registry SD could not be read; the ESC7 detector then skips owner control. owner_sid = (_caSecurityOwner $cn) registry_config_collected = $true }",
        ),
    ],
    # receiver of .ContainsKey()
    "cakindbyname": [
        ("assign Equals", "<script>", "@{}"),
        ("index Equals", "<script>", "$caKindByName[$cn] = $kind"),
    ],
    # input of OpenSubKey: [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey( "SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$caName")
    "caname": [
        ("arg", "_caSecurityAces", "$ca.name"),
        ("arg", "_caSecurityOwner", "$caCommonName"),
        ("arg", "_caSecurityOwner", "$cn"),
        ("parameter", "_caSecurityAces", "[string]$caName"),
        ("parameter", "_caSecurityOwner", "[string]$caName"),
    ],
    # index write $caSecurity[$ca.name]
    "casecurity": [
        ("assign Equals", "<script>", "[ordered]@{}"),
        ("index Equals", "<script>", "$caSecurity[$ca.name] = $flat"),
    ],
    # read by a binding of $t
    "catype": [
        ("assign Equals", "<script>", "_certutilDword 'CA\\CAType'"),
    ],
    # input of New-Item: New-Item -ItemType Directory -Force -Path $certDir
    "certdir": [
        ("assign Equals", "<script>", "Join-Path $OutDir 'certs'"),
    ],
    # input of WriteAllBytes: [IO.File]::WriteAllBytes((Join-Path $certDir $certFile), $der)
    "certfile": [
        ("assign Equals", "<script>", "'{0:d2}-{1}.cer' -f $i, (_safeFileName $cn)"),
    ],
    # read by a binding of $path
    "cfg": [
        ("assign Equals", "_ldapRoot", "(_ldapRootDse).configurationNamingContext"),
    ],
    # read by a binding of $pksdn
    "cfgnc": [
        ("assign Equals", "<script>", "(_ldapRootDse).configurationNamingContext"),
    ],
    # read by a binding of $enrollmentservices
    "cn": [
        ("assign Equals", "<script>", "[string]$p['cn'][0]"),
        ("assign Equals", "<script>", "[string]$p['cn'][0]"),
        ("assign Equals", "<script>", "[string]$p['cn'][0]"),
    ],
    # parameter of _ldapRoot, called by a binding of $root
    "container": [
        ("arg", "_ldapRoot", "'CN=AIA'"),
        ("arg", "_ldapRoot", "'CN=CDP'"),
        ("arg", "_ldapRoot", "'CN=Certificate Templates'"),
        ("arg", "_ldapRoot", "'CN=Enrollment Services'"),
        ("arg", "_ldapRoot", "'CN=OID'"),
        ("parameter", "_ldapRoot", "[string]$container"),
    ],
    # read by a binding of $root
    "containerdn": [
        ("arg", "_childAcls", '"CN=Certification Authorities,$pksDn"'),
        ("arg", "_childAcls", '"CN=Enrollment Services,$pksDn"'),
        ("parameter", "_childAcls", "[string]$containerDn"),
    ],
    # input of WriteAllBytes: [IO.File]::WriteAllBytes((Join-Path $certDir $crlFile), $der)
    "crlfile": [
        ("assign Equals", "<script>", "'{0:d2}-{1}.crl' -f $j, (_safeFileName $cn)"),
    ],
    # read by a binding of $templates
    "csps": [
        ("assign Equals", "<script>", "@()"),
        ("assign PlusEquals", "<script>", "[string]$c"),
    ],
    # input of Get-WmiObject: Get-WmiObject -ComputerName $dcDns -Credential $dcCred -Namespace 'root\default' -Class StdRegProv -List
    "dccred": [
        ("assign Equals", "<script>", "$null"),
        (
            "assign Equals",
            "<script>",
            "New-Object Management.Automation.PSCredential( $DcRegistryUser, (ConvertTo-SecureString $DcRegistryPass -AsPlainText -Force))",
        ),
    ],
    # input of Get-WmiObject: Get-WmiObject -ComputerName $dcDns -Credential $dcCred -Namespace 'root\default' -Class StdRegProv -List
    "dcdns": [
        ("assign Equals", "<script>", "[string]$r.Properties['dnshostname'][0]"),
    ],
    # read by a binding of $dccred
    "dcregistrypass": [
        ("assign Equals", "<script>", "''"),
        ("assign Equals", "<script>", "_b64 $DcRegistryPassB64"),
    ],
    # read by a binding of $s
    "dcregistrypassb64": [
        (
            "parameter",
            "<script>",
            "[Parameter(ParameterSetName = 'Collect')] [string] $DcRegistryPassB64",
        ),
    ],
    # read by a binding of $dccred
    "dcregistryuser": [
        ("assign Equals", "<script>", "''"),
        ("assign Equals", "<script>", "_b64 $DcRegistryUserB64"),
    ],
    # read by a binding of $s
    "dcregistryuserb64": [
        (
            "parameter",
            "<script>",
            "[Parameter(ParameterSetName = 'Collect')] [string] $DcRegistryUserB64",
        ),
    ],
    # read by a binding of $ds
    "dcroot": [
        ("assign Equals", "<script>", '_ldapEntry "LDAP://$domNc"'),
    ],
    # read by a binding of $s
    "de": [
        ("assign Equals", "_objAcl", '_ldapEntry "LDAP://$dn"'),
    ],
    # read by a binding of $c
    "der": [
        ("arg", "_certKindFromDer", "$der"),
        ("assign Equals", "<script>", "[byte[]]$blob"),
        ("assign Equals", "<script>", "[byte[]]$p['certificaterevocationlist'][0]"),
        ("parameter", "_certKindFromDer", "[byte[]]$der"),
    ],
    # read by a binding of $caconfig
    "disabledext": [
        ("assign Equals", "<script>", "_certutilMultiSz 'policy\\DisableExtensionList'"),
    ],
    # read by a binding of $path
    "dn": [
        ("arg", "_objAcl", "$pair[0]"),
        ("assign Equals", "_childAcls", "[string]$r.Properties['distinguishedname'][0]"),
        ("parameter", "_objAcl", "[string]$dn"),
    ],
    # receiver of .ToLower()
    "dns": [
        ("assign Equals", "<script>", "[string]$p['dnshostname'][0]"),
    ],
    # read by a binding of $path
    "domnc": [
        ("assign Equals", "<script>", "(_ldapRootDse).defaultNamingContext"),
    ],
    # read by a binding of $s
    "domroot": [
        ("assign Equals", "<script>", '_ldapEntry "LDAP://$domNc"'),
    ],
    # receiver of .Add()
    "ds": [
        ("assign Equals", "<script>", "New-Object DirectoryServices.DirectorySearcher($dcRoot)"),
        (
            "member Equals",
            "<script>",
            "$ds.Filter = '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))'",
        ),
        ("member Equals", "<script>", "$ds.PageSize = 200"),
        ("member Equals", "<script>", "$ds.SearchScope = 'Subtree'"),
    ],
    # read by a binding of $ekus
    "e": [
        ("foreach", "<script>", "$p['pkiextendedkeyusage']"),
        ("foreach", "_decode", "$map.GetEnumerator()"),
    ],
    # read by a binding of $caconfig
    "editflags": [
        ("assign Equals", "<script>", "_certutilFlags 'policy\\EditFlags'"),
    ],
    # read by a binding of $templates
    "ef": [
        (
            "assign Equals",
            "<script>",
            "if ($p['mspki-enrollment-flag'].Count) { [int]$p['mspki-enrollment-flag'][0] } else { 0 }",
        ),
    ],
    # read by a binding of $templates
    "ekus": [
        ("assign Equals", "<script>", "@()"),
        ("assign PlusEquals", "<script>", "[string]$e"),
    ],
    # read by a binding of $map
    "enroll_flags": [
        (
            "assign Equals",
            "<script>",
            "[ordered]@{ 0x00000002 = 'PEND_ALL_REQUESTS' # manager approval 0x00000008 = 'PUBLISH_TO_DS' 0x00000020 = 'AUTO_ENROLLMENT' 0x00000100 = 'USER_INTERACTION_REQUIRED' 0x00080000 = 'NO_SECURITY_EXTENSION' # ESC9 (CT_FLAG_NO_SECURITY_EXTENSION) }",
        ),
    ],
    # index write $enrollmentServices[$cn]
    "enrollmentservices": [
        ("assign Equals", "<script>", "[ordered]@{}"),
        ("index Equals", "<script>", "$enrollmentServices[$cn] = $templates"),
    ],
    # read by a binding of $root
    "enrollroot": [
        ("assign Equals", "<script>", "_ldapRoot 'CN=Enrollment Services'"),
    ],
    # read by a binding of $s
    "filter": [
        ("arg", "_childAcls", "'(objectClass=certificationAuthority)'"),
        ("arg", "_childAcls", "'(objectClass=pKIEnrollmentService)'"),
        ("arg", "_search", "$filter"),
        ("arg", "_search", "'(objectClass=cRLDistributionPoint)'"),
        ("arg", "_search", "'(objectClass=certificationAuthority)'"),
        ("arg", "_search", "'(objectClass=msPKI-Enterprise-Oid)'"),
        ("arg", "_search", "'(objectClass=pKICertificateTemplate)'"),
        ("arg", "_search", "'(objectClass=pKIEnrollmentService)'"),
        ("parameter", "_childAcls", "[string]$filter"),
        ("parameter", "_search", "[string]$filter"),
    ],
    # read by a binding of $casecurity
    "flat": [
        ("assign Equals", "<script>", "@($aces | ForEach-Object { $_ })"),
    ],
    # input of GetDWORDValue: $reg.GetDWORDValue($HKLM, 'SYSTEM\CurrentControlSet\Services\Kdc', 'StrongCertificateBindingEnforcement')
    "hklm": [
        ("assign Equals", "<script>", "[uint32]2147483650"),
    ],
    # read by a binding of $certfile
    "i": [
        ("assign Equals", "<script>", "0"),
        ("incdec PostfixPlusPlus", "<script>", ""),
    ],
    # read by a binding of $caconfig
    "interfaceflags": [
        ("assign Equals", "<script>", "_certutilFlags 'CA\\InterfaceFlags'"),
    ],
    # read by a binding of $crlfile
    "j": [
        ("assign Equals", "<script>", "0"),
        ("incdec PostfixPlusPlus", "<script>", ""),
    ],
    # receiver of .Serialize()
    "js": [
        (
            "assign Equals",
            "<script>",
            "New-Object System.Web.Script.Serialization.JavaScriptSerializer",
        ),
        ("member Equals", "<script>", "$script:JS.MaxJsonLength = [int]::MaxValue"),
    ],
    # receiver of .GetValue()
    "key": [
        (
            "assign Equals",
            "_caSecurityAces",
            '[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey( "SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\$caName")',
        ),
        (
            "assign Equals",
            "_caSecurityOwner",
            '[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey( "SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\$caName")',
        ),
    ],
    # read by a binding of $cakindbyname
    "kind": [
        ("arg", "_childAcls", "'ca_object'"),
        ("arg", "_childAcls", "'ca_object'"),
        ("arg", "_objAcl", "$pair[1]"),
        ("assign Equals", "<script>", "_certKindFromDer $der"),
        ("assign Equals", "<script>", "_classifyApp ([string]$app.path)"),
        ("parameter", "_childAcls", "[string]$kind"),
        ("parameter", "_objAcl", "[string]$kind"),
    ],
    # read by a binding of $s
    "ldappassb64": [
        (
            "parameter",
            "<script>",
            "[Parameter(ParameterSetName = 'Collect')] [string] $LdapPassB64",
        ),
    ],
    # read by a binding of $s
    "ldapuserb64": [
        (
            "parameter",
            "<script>",
            "[Parameter(ParameterSetName = 'Collect')] [string] $LdapUserB64",
        ),
    ],
    # receiver of .Trim()
    "line": [
        ("foreach", "_parseCertutilDwordLines", "$lines"),
        ("foreach", "_parseCertutilFlagLines", "$lines"),
        ("foreach", "_parseCertutilMultiSzLines", "$lines"),
    ],
    # read by a binding of $line
    "lines": [
        ("arg", "_parseCertutilDwordLines", "(& certutil -getreg $regpath 2>$null)"),
        ("arg", "_parseCertutilFlagLines", "(& certutil -getreg $regpath 2>$null)"),
        ("arg", "_parseCertutilMultiSzLines", "(& certutil -getreg $regpath 2>$null)"),
        ("parameter", "_parseCertutilDwordLines", "$lines"),
        ("parameter", "_parseCertutilFlagLines", "$lines"),
        ("parameter", "_parseCertutilMultiSzLines", "$lines"),
    ],
    # read by a binding of $caconfig
    "localfqdn": [
        ("assign Equals", "<script>", "$localHost"),
        (
            "assign Equals",
            "<script>",
            "([System.Net.Dns]::GetHostEntry($localHost).HostName).ToLower()",
        ),
    ],
    # read by a binding of $localfqdn
    "localhost": [
        ("assign Equals", "<script>", "([string](hostname)).ToLower()"),
        ("assign Equals", "<script>", "([string](hostname)).ToLower()"),
    ],
    # receiver of .GetEnumerator()
    "map": [
        ("arg", "_decode", "$ENROLL_FLAGS"),
        ("arg", "_decode", "$NAME_FLAGS"),
        ("arg", "_decode", "$SCHANNEL_BITS"),
        ("parameter", "_decode", "$map"),
    ],
    # parameter of _safeFileName, called by a binding of $crlfile
    "name": [
        ("arg", "_safeFileName", "$cn"),
        ("arg", "_safeFileName", "$cn"),
        ("assign Equals", "_parseAces", "''"),
        (
            "assign Equals",
            "_parseAces",
            "[string]$a.IdentityReference.Translate([Security.Principal.NTAccount]).Value",
        ),
        ("parameter", "_safeFileName", "[string]$name"),
    ],
    # read by a binding of $map
    "name_flags": [
        (
            "assign Equals",
            "<script>",
            "[ordered]@{ 0x00000001 = 'ENROLLEE_SUPPLIES_SUBJECT' 0x00010000 = 'SUBJECT_ALT_REQUIRE_DOMAIN_DNS' 0x00400000 = 'SUBJECT_ALT_REQUIRE_UPN' 0x00800000 = 'SUBJECT_ALT_REQUIRE_EMAIL' 0x04000000 = 'SUBJECT_ALT_REQUIRE_DNS' 0x08000000 = 'SUBJECT_REQUIRE_DNS_AS_CN' 0x10000000 = 'SUBJECT_REQUIRE_DIRECTORY_PATH' 0x20000000 = 'SUBJECT_REQUIRE_EMAIL' 0x40000000 = 'SUBJECT_REQUIRE_COMMON_NAME' 0x00000008 = 'ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME' }",
        ),
    ],
    # read by a binding of $templates
    "nf": [
        (
            "assign Equals",
            "<script>",
            "if ($p['mspki-certificate-name-flag'].Count) { [int]$p['mspki-certificate-name-flag'][0] } else { 0 }",
        ),
    ],
    # read by a binding of $pol
    "o": [
        ("foreach", "<script>", "$p['mspki-certificate-policy']"),
    ],
    # read by a binding of $root
    "oidroot": [
        ("assign Equals", "<script>", "_ldapRoot 'CN=OID'"),
    ],
    # receiver of .ToLower()
    "ot": [
        ("assign Equals", "_parseAces", "$a.ObjectType.ToString()"),
    ],
    # input of New-Item: New-Item -ItemType Directory -Force -Path $OutDir
    "outdir": [
        (
            "parameter",
            "<script>",
            "[Parameter(Mandatory, ParameterSetName = 'Collect')] [string] $OutDir",
        ),
    ],
    # read by a binding of $outpath
    "outname": [
        ("arg", "_writeJson", "'ca-config.json'"),
        ("arg", "_writeJson", "'ca-security.json'"),
        ("arg", "_writeJson", "'certs/index.json'"),
        ("arg", "_writeJson", "'collector-manifest.json'"),
        ("arg", "_writeJson", "'dc-config.json'"),
        ("arg", "_writeJson", "'enrollment-services.json'"),
        ("arg", "_writeJson", "'oid-objects.json'"),
        ("arg", "_writeJson", "'pki-acls.json'"),
        ("arg", "_writeJson", "'principal-mappings.json'"),
        ("arg", "_writeJson", "'templates.json'"),
        ("arg", "_writeJson", "'web-endpoints.json'"),
        ("parameter", "_writeJson", "[string]$outName"),
    ],
    # input of New-Item: New-Item -ItemType Directory -Force -Path $outParent
    "outparent": [
        ("assign Equals", "_writeJson", "Split-Path $outPath -Parent"),
    ],
    # input of WriteAllText: [IO.File]::WriteAllText($outPath, $script:JS.Serialize($obj), (New-Object Text.UTF8Encoding($false)))
    "outpath": [
        ("assign Equals", "_writeJson", "Join-Path $OutDir $outName"),
    ],
    # receiver of .ToLower()
    "p": [
        ("arg", "_classifyApp", "([string]$app.path)"),
        ("assign Equals", "<script>", "$r.Properties"),
        ("assign Equals", "<script>", "$r.Properties"),
        ("assign Equals", "<script>", "$r.Properties"),
        ("assign Equals", "<script>", "$r.Properties"),
        ("assign Equals", "<script>", "$r.Properties"),
        (
            "foreach",
            "<script>",
            "(Get-WebConfigurationProperty -PSPath $ps -Filter 'system.webServer/security/authentication/windowsAuthentication/providers' -Name Collection -ErrorAction SilentlyContinue)",
        ),
        ("parameter", "_classifyApp", "[string]$p"),
    ],
    # read by a binding of $dn
    "pair": [
        (
            "foreach",
            "<script>",
            "@( @($pksDn, 'pks_container'), @(\"CN=NTAuthCertificates,$pksDn\", 'ntauth'), @(\"CN=AIA,$pksDn\", 'aia'), @(\"CN=CDP,$pksDn\", 'cdp'), @(\"CN=Certification Authorities,$pksDn\", 'pks_container'), @(\"CN=Enrollment Services,$pksDn\", 'pks_container'))",
        ),
    ],
    # parameter of _ldapEntry, called by a binding of $root
    "path": [
        ("arg", "_ldapEntry", '"LDAP://$containerDn"'),
        ("arg", "_ldapEntry", '"LDAP://$dn"'),
        ("arg", "_ldapEntry", '"LDAP://$domNc"'),
        ("arg", "_ldapEntry", '"LDAP://$domNc"'),
        ("arg", "_ldapEntry", "$path"),
        ("arg", "_ldapEntry", "'LDAP://RootDSE'"),
        (
            "assign Equals",
            "_ldapRoot",
            'if ($container) { "LDAP://$container,CN=Public Key Services,CN=Services,$cfg" } else { "LDAP://CN=Public Key Services,CN=Services,$cfg" }',
        ),
        ("parameter", "_ldapEntry", "[string]$path"),
    ],
    # read by a binding of $pair
    "pksdn": [
        ("assign Equals", "<script>", '"CN=Public Key Services,CN=Services,$cfgNc"'),
    ],
    # read by a binding of $templates
    "pol": [
        ("assign Equals", "<script>", "@()"),
        ("assign PlusEquals", "<script>", "[string]$o"),
    ],
    # read by a binding of $p
    "ps": [
        (
            "assign Equals",
            "<script>",
            "\"IIS:\\Sites\\$($site.Name)\\\" + ([string]$app.path).TrimStart('/')",
        ),
    ],
    # read by a binding of $dn
    "r": [
        ("assign Equals", "_objAcl", "$null"),
        ("assign Equals", "_objAcl", "$s.FindOne()"),
        ("foreach", "<script>", "$ds.FindAll()"),
        ("foreach", "<script>", "$s.FindAll()"),
        ("foreach", "<script>", "(_search $enrollRoot '(objectClass=pKIEnrollmentService)')"),
        ("foreach", "<script>", "(_search $oidRoot '(objectClass=msPKI-Enterprise-Oid)')"),
        ("foreach", "<script>", "(_search $tmplRoot '(objectClass=pKICertificateTemplate)')"),
        (
            "foreach",
            "<script>",
            "(_search (_ldapRoot 'CN=AIA') '(objectClass=certificationAuthority)')",
        ),
        (
            "foreach",
            "<script>",
            "(_search (_ldapRoot 'CN=CDP') '(objectClass=cRLDistributionPoint)')",
        ),
        ("foreach", "_childAcls", "(_search $root $filter)"),
    ],
    # receiver of .GetDWORDValue()
    "reg": [
        (
            "assign Equals",
            "<script>",
            "Get-WmiObject -ComputerName $dcDns -Credential $dcCred -Namespace 'root\\default' -Class StdRegProv -List",
        ),
        (
            "assign Equals",
            "<script>",
            "Get-WmiObject -ComputerName $dcDns -Namespace 'root\\default' -Class StdRegProv -List",
        ),
        (
            "assign Equals",
            "<script>",
            "Get-WmiObject -Namespace 'root\\default' -Class StdRegProv -List",
        ),
    ],
    # input of certutil: & certutil -getreg $regpath 2>$null
    "regpath": [
        ("arg", "_certutilDword", "'CA\\AuditFilter'"),
        ("arg", "_certutilDword", "'CA\\CAType'"),
        ("arg", "_certutilFlags", "'CA\\InterfaceFlags'"),
        ("arg", "_certutilFlags", "'policy\\EditFlags'"),
        ("arg", "_certutilMultiSz", "'policy\\DisableExtensionList'"),
        ("parameter", "_certutilDword", "[string]$regpath"),
        ("parameter", "_certutilFlags", "[string]$regpath"),
        ("parameter", "_certutilMultiSz", "[string]$regpath"),
    ],
    # read by a binding of $s
    "root": [
        ("arg", "_search", "$enrollRoot"),
        ("arg", "_search", "$oidRoot"),
        ("arg", "_search", "$root"),
        ("arg", "_search", "$tmplRoot"),
        ("arg", "_search", "(_ldapRoot 'CN=AIA')"),
        ("arg", "_search", "(_ldapRoot 'CN=CDP')"),
        ("assign Equals", "_childAcls", '_ldapEntry "LDAP://$containerDn"'),
        ("parameter", "_search", "[DirectoryServices.DirectoryEntry]$root"),
    ],
    # read by a binding of $a
    "rsd": [
        (
            "assign Equals",
            "_caSecurityAces",
            "New-Object Security.AccessControl.RawSecurityDescriptor(@([byte[]]$bytes), 0)",
        ),
        (
            "assign Equals",
            "_rawSdOwner",
            "New-Object Security.AccessControl.RawSecurityDescriptor(@([byte[]]$bytes), 0)",
        ),
    ],
    # receiver of .FindAll()
    "s": [
        ("arg", "_b64", "$DcRegistryPassB64"),
        ("arg", "_b64", "$DcRegistryUserB64"),
        ("arg", "_b64", "$LdapPassB64"),
        ("arg", "_b64", "$LdapUserB64"),
        ("assign Equals", "<script>", "New-Object DirectoryServices.DirectorySearcher($domRoot)"),
        ("assign Equals", "_objAcl", "New-Object DirectoryServices.DirectorySearcher($de)"),
        ("assign Equals", "_search", "New-Object DirectoryServices.DirectorySearcher($root)"),
        ("member Equals", "<script>", "$s.Filter = '(altSecurityIdentities=*)'"),
        ("member Equals", "<script>", "$s.PageSize = 200"),
        ("member Equals", "<script>", "$s.SearchScope = 'Subtree'"),
        ("member Equals", "_objAcl", "$s.Filter = '(objectClass=*)'"),
        ("member Equals", "_objAcl", "$s.SearchScope = 'Base'"),
        (
            "member Equals",
            "_objAcl",
            "$s.SecurityMasks = [DirectoryServices.SecurityMasks]'Dacl,Owner'",
        ),
        ("member Equals", "_search", "$s.Filter = $filter"),
        ("member Equals", "_search", "$s.PageSize = 200"),
        ("member Equals", "_search", "$s.SearchScope = 'Subtree'"),
        (
            "member Equals",
            "_search",
            "$s.SecurityMasks = [DirectoryServices.SecurityMasks]'Dacl,Owner'",
        ),
        ("parameter", "_b64", "[string]$s"),
    ],
    # read by a binding of $value
    "sch": [
        (
            "assign Equals",
            "<script>",
            "$reg.GetDWORDValue($HKLM, 'SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL', 'CertificateMappingMethods')",
        ),
    ],
    # read by a binding of $map
    "schannel_bits": [
        (
            "assign Equals",
            "<script>",
            "[ordered]@{ 1 = 'subject_issuer'; 2 = 'issuer'; 4 = 'upn'; 8 = 's4u2self'; 16 = 's4u2self_explicit' }",
        ),
    ],
    # receiver of .SetSecurityDescriptorBinaryForm()
    "sd": [
        ("assign Equals", "_parseAces", "New-Object DirectoryServices.ActiveDirectorySecurity"),
        ("assign Equals", "_readOwner", "New-Object DirectoryServices.ActiveDirectorySecurity"),
    ],
    # read by a binding of $templates
    "sdb": [
        (
            "assign Equals",
            "<script>",
            "if ($p['ntsecuritydescriptor'].Count) { [byte[]]$p['ntsecuritydescriptor'][0] } else { $null }",
        ),
        (
            "assign Equals",
            "_childAcls",
            "if ($r.Properties['ntsecuritydescriptor'].Count) { [byte[]]$r.Properties['ntsecuritydescriptor'][0] } else { $null }",
        ),
        (
            "assign Equals",
            "_objAcl",
            "if ($r.Properties['ntsecuritydescriptor'].Count) { [byte[]]$r.Properties['ntsecuritydescriptor'][0] } else { $null }",
        ),
    ],
    # parameter of _parseAces, called by a binding of $templates
    "sdbytes": [
        ("arg", "_parseAces", "$sdb"),
        ("arg", "_parseAces", "$sdb"),
        ("arg", "_parseAces", "$sdb"),
        ("arg", "_readOwner", "$sdb"),
        ("arg", "_readOwner", "$sdb"),
        ("arg", "_readOwner", "$sdb"),
        ("parameter", "_parseAces", "[byte[]]$sdBytes"),
        ("parameter", "_readOwner", "[byte[]]$sdBytes"),
    ],
    # read by a binding of $ps
    "site": [
        ("foreach", "<script>", "(Get-Website)"),
    ],
    # read by a binding of $templates
    "t": [
        ("arg", "_caKindFromType", "$caType"),
        ("arg", "_caKindFromType", "$caType"),
        ("foreach", "<script>", "$p['certificatetemplates']"),
        ("parameter", "_caKindFromType", "$t"),
    ],
    # read by a binding of $enrollmentservices
    "templates": [
        ("assign Equals", "<script>", "@()"),
        ("assign Equals", "<script>", "@()"),
        (
            "assign PlusEquals",
            "<script>",
            "[ordered]@{ name = [string]$p['cn'][0] display_name = [string]$p['displayname'][0] schema_version = if ($p['mspki-template-schema-version'].Count) { [int]$p['mspki-template-schema-version'][0] } else { 1 } oid = [string]$p['mspki-cert-template-oid'][0] ekus = (@($ekus)) name_flags = (_decode $nf $NAME_FLAGS) enrollment_flags = (_decode $ef $ENROLL_FLAGS) min_key_size = if ($p['mspki-minimal-key-size'].Count) { [int]$p['mspki-minimal-key-size'][0] } else { $null } issuance_policy_oids = (@($pol)) csp = (($csps -join ', ').ToLower()) security = (_parseAces $sdb) # template DACL -> ACEs (ESC1/ESC4) acl_obtained = ($null -ne $sdb) # SD requested & obtained (per-template gap signal) owner_sid = (_readOwner $sdb) }",
        ),
        ("assign PlusEquals", "<script>", "[string]$t"),
    ],
    # read by a binding of $root
    "tmplroot": [
        ("assign Equals", "<script>", "_ldapRoot 'CN=Certificate Templates'"),
    ],
    # parameter of _decode, called by a binding of $templates
    "value": [
        ("arg", "_decode", "$ef"),
        ("arg", "_decode", "$nf"),
        ("arg", "_decode", "([int]$sch.uValue)"),
        ("parameter", "_decode", "[int]$value"),
    ],
}

# The pinned write/exec/remote operations with their control-flow context, as a
# multiset of (normalized text, context outermost-first).
GUARDED_OPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "New-Item -ItemType Directory -Force -Path $outParent",
        ("function _writeJson", "if (-not (Test-Path $outParent)) after []"),
    ),
    ("& certutil -getreg $regpath 2>$null", ("function _certutilFlags",)),
    ("& certutil -getreg $regpath 2>$null", ("function _certutilDword",)),
    ("& certutil -getreg $regpath 2>$null", ("function _certutilMultiSz",)),
    (
        "New-Item -ItemType Directory -Force -Path $OutDir",
        ("guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",),
    ),
    (
        "Add-Type -AssemblyName System.Web.Extensions",
        ("guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",),
    ),
    (
        "& certutil -getreg CA\\CommonName 2>$null",
        ("guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",),
    ),
    (
        "New-Item -ItemType Directory -Force -Path $certDir",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "try",
            "foreach ($r in (_search (_ldapRoot 'CN=AIA') '(objectClass=certificationAuthority)'))",
            "foreach ($blob in $p['cacertificate'])",
        ),
    ),
    (
        "New-Item -ItemType Directory -Force -Path $certDir",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "try",
            "foreach ($r in (_search (_ldapRoot 'CN=CDP') '(objectClass=cRLDistributionPoint)'))",
            "guard if (-not $p['certificaterevocationlist'].Count) -> continue",
        ),
    ),
    (
        "Import-Module WebAdministration -ErrorAction Stop",
        ("guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return", "try"),
    ),
    (
        "Get-WmiObject -Namespace 'root\\default' -Class StdRegProv -List",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "if ($CollectDcMapping) after []",
            "foreach ($r in $ds.FindAll())",
            "guard if (-not $dcDns) -> continue",
            "try",
            "if ($dcDns.ToLower() -eq $localHost -or $dcDns.ToLower().StartsWith($localHost + '.')) after []",
        ),
    ),
    (
        "Get-WmiObject -ComputerName $dcDns -Credential $dcCred -Namespace 'root\\default' -Class StdRegProv -List",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "if ($CollectDcMapping) after []",
            "foreach ($r in $ds.FindAll())",
            "guard if (-not $dcDns) -> continue",
            "try",
            "if ($dcCred) after [($dcDns.ToLower() -eq $localHost -or $dcDns.ToLower().StartsWith($localHost + '.'))]",
        ),
    ),
    (
        "Get-WmiObject -ComputerName $dcDns -Namespace 'root\\default' -Class StdRegProv -List",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "if ($CollectDcMapping) after []",
            "foreach ($r in $ds.FindAll())",
            "guard if (-not $dcDns) -> continue",
            "try",
            "else of [($dcDns.ToLower() -eq $localHost -or $dcDns.ToLower().StartsWith($localHost + '.')) ; ($dcCred)]",
        ),
    ),
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
        "[IO.File]::WriteAllText($outPath, $script:JS.Serialize($obj), (New-Object Text.UTF8Encoding($false)))",
        ("function _writeJson",),
    ),
    (
        '[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey( "SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\$caName")',
        ("function _caSecurityAces",),
    ),
    (
        '[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey( "SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\$caName")',
        ("function _caSecurityOwner",),
    ),
    (
        "[IO.File]::WriteAllBytes((Join-Path $certDir $certFile), $der)",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "try",
            "foreach ($r in (_search (_ldapRoot 'CN=AIA') '(objectClass=certificationAuthority)'))",
            "foreach ($blob in $p['cacertificate'])",
        ),
    ),
    (
        "[IO.File]::WriteAllBytes((Join-Path $certDir $crlFile), $der)",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "try",
            "foreach ($r in (_search (_ldapRoot 'CN=CDP') '(objectClass=cRLDistributionPoint)'))",
            "guard if (-not $p['certificaterevocationlist'].Count) -> continue",
        ),
    ),
    (
        "$reg.GetDWORDValue($HKLM, 'SYSTEM\\CurrentControlSet\\Services\\Kdc', 'StrongCertificateBindingEnforcement')",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "if ($CollectDcMapping) after []",
            "foreach ($r in $ds.FindAll())",
            "guard if (-not $dcDns) -> continue",
            "try",
        ),
    ),
    (
        "$reg.GetDWORDValue($HKLM, 'SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL', 'CertificateMappingMethods')",
        (
            "guard if ($PSCmdlet.ParameterSetName -eq 'SelfTest') -> return",
            "if ($CollectDcMapping) after []",
            "foreach ($r in $ds.FindAll())",
            "guard if (-not $dcDns) -> continue",
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


Binding = tuple[str, str, str]


def _bindings_by_var(dump: dict[str, Any]) -> dict[str, list[Binding]]:
    """Every way each variable acquires a value, as (kind, scope, value):

    ``assign <Op>`` (any operator; value = right-hand side), ``incdec <Token>``,
    ``foreach`` (value = source), ``parameter`` (value = the whole declaration:
    attributes, type, default), ``arg`` / ``splat`` (a call-site argument of a
    local function; scope = the call site), and ``member <Op>`` / ``index <Op>``
    (a property / index write on the variable's object; value = ``target =
    rhs``). Names are lower-cased with any scope qualifier stripped, merged over
    the whole script (over-approximating dynamic scoping). ``$null = ...``
    discards output and binds nothing.
    """
    out: dict[str, list[Binding]] = {}
    for b in dump["bindings"]:
        name = b["variable"]
        if name is None or b["kind"] == "common-parameter":
            continue
        if name == "null" and b["kind"] == "assign Equals":
            continue
        out.setdefault(name, []).append((b["kind"], b["scope"], b["value"]))
    for m in dump["member_assignments"]:
        if m["receiver_root"]:
            out.setdefault(m["receiver_root"], []).append(
                (f"{m['kind']} {m['operator']}", m["scope"], f"{m['target']} = {m['value']}")
            )
    return out


def _guarded(dump: dict[str, Any]) -> list[tuple[str, dict[str, Any], list[str]]]:
    """(name, entry, input texts) for every write/exec/load/remote operation."""
    found: list[tuple[str, dict[str, Any], list[str]]] = []
    for c in dump["commands"]:
        name = c["name"] or ""
        dynamic = not c["name"] or not c["bareword"] or c["operator"] == "Dot"
        if dynamic or name in _GUARDED_COMMANDS:
            positions = _GUARDED_INPUT_ARGS.get(name)
            values = (
                [e["text"] for e in c["elements"]]
                if c["name"] != "_writeJson"
                else [e["text"] for e in c["elements"] if e["parameter"] is None]
            )
            inputs = (
                values if positions is None else [values[i] for i in positions if i < len(values)]
            )
            found.append((name, c, inputs))
    for m in dump["members"]:
        if m["static"]:
            if (m["target"], m["member"]) not in _GUARDED_STATIC:
                continue
        elif m["member"] not in _GUARDED_INSTANCE:
            continue
        positions = _GUARDED_INPUT_ARGS.get(m["member"])
        inputs = (
            m["args"]
            if positions is None
            else [m["args"][i] for i in positions if i < len(m["args"])]
        )
        found.append((m["member"], m, inputs))
    return found


def _guarded_ops(dump: dict[str, Any]) -> list[tuple[str, tuple[str, ...]]]:
    return [(entry["text"], tuple(entry["context"])) for _, entry, _ in _guarded(dump)]


_LOCAL_CALL = re.compile(r"(?<![\w$.-])(_[A-Za-z][A-Za-z0-9]*)")


def _required_vars(dump: dict[str, Any]) -> dict[str, str]:
    """Variables whose every binding must be pinned, with the first reason."""
    reasons: dict[str, str] = {}

    def need(name: str | None, why: str) -> None:
        if name and name not in reasons:
            reasons[name] = why

    for name, entry, inputs in _guarded(dump):
        for text in inputs:
            for var in sorted(_vars_in(text)):
                need(var, f"input of {name}: {entry['text']}")
    for targets in ALLOWED_WRITE_TARGETS.values():
        for text in sorted(targets):
            for var in sorted(_vars_in(text)):
                need(var, f"write target {text}")
    for m in dump["members"]:
        if not m["static"]:
            need(m["receiver_root"], f"receiver of .{m['member']}()")
    for m in dump["member_assignments"]:
        need(m["receiver_root"], f"{m['kind']} write {m['target']}")
    bindings = _bindings_by_var(dump)
    params = {f["name"].lower(): f["params"] for f in dump["function_params"]}
    pending = sorted(reasons)
    while pending:
        var = pending.pop()
        for _kind, _scope, value in sorted(bindings.get(var, [])):
            refs = {(ref, f"read by a binding of ${var}") for ref in _vars_in(value)}
            # A binding that calls a local function also depends on that
            # function's parameters (not on the rest of its body: declared gap).
            for fn in _LOCAL_CALL.findall(value):
                refs |= {
                    (p, f"parameter of {fn}, called by a binding of ${var}")
                    for p in params.get(fn.lower(), [])
                }
            for ref, why in sorted(refs):
                if ref not in reasons:
                    reasons[ref] = why
                    pending.append(ref)
    return {v: why for v, why in reasons.items() if v not in _AUTO_READ_OK}


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
    if set(dump["foreach_flags"]) - {"None"}:
        out.append(f"[ast] foreach flags are not allowed: {dump['foreach_flags']}")
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
        if m["static"] or m["member"] not in ALLOWED_INSTANCE:
            continue
        permitted = INSTANCE_RECEIVERS.get(m["member"], frozenset())
        if (m["receiver_root"] or "") not in permitted:
            out.append(
                f"[receiver] {m['scope']}: {m['text']}: .{m['member']}() on receiver "
                f"{m['receiver_root']!r} (allowed: {sorted(permitted)})"
            )
    required = _required_vars(dump)
    bindings = _bindings_by_var(dump)
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
    actual = Counter(_guarded_ops(dump))
    allowed = Counter(GUARDED_OPS)
    for op, ctx in sorted((actual - allowed).elements()):
        out.append(f"[guarded-op] unexpected: {op} @ {' > '.join(ctx)}")
    for op, ctx in sorted((allowed - actual).elements()):
        out.append(f"[guarded-op] missing: {op} @ {' > '.join(ctx)}")
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
            out.append(f"[dynamic] {where}: command name computed at runtime")
            continue
        if c["operator"] == "Dot":
            # Still checked against the allowlists below.
            out.append(f"[dynamic] {where}: dot-sourced invocation runs in the caller's scope")
        if name.lower() in defined:
            if name == "_writeJson":
                vals = [e["text"] for e in c["elements"] if e["parameter"] is None]
                if len(vals) != 2 or not _SAFE_OUTPUT_NAME.fullmatch(vals[1]):
                    out.append(f"[write-path] {where}: _writeJson must take a plain relative name")
            if any(e["parameter"] is not None for e in c["elements"]):
                out.append(f"[command] {where}: parameters on a script function are not allowed")
            continue
        check = ALLOWED_COMMANDS.get(name)
        if check is None or name.lower() in {f.lower() for f in FORBIDDEN_COMMANDS}:
            out.append(f"[command] {where}: command {name!r} is not allowlisted")
            continue
        reason = check(c)
        if reason:
            tag = "[write-path]" if name == "New-Item" else "[command]"
            out.append(f"{tag} {where}: {reason}")
    for b in dump["bindings"]:
        if b["kind"] == "common-parameter":
            out.append(f"[common-parameter] {b['scope']}: {b['value']} writes {b['target']!r}")
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
    bad.write_text(_collector_text() + "\n$OUTPATH = 'C:\\evil'\n", encoding="utf-8")
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


def test_pins_cover_exactly_the_required_variables() -> None:
    """Every required variable is pinned, and every pin is still required."""
    dump = _dump(COLLECTOR)
    assert set(PINNED_BINDINGS) == set(_required_vars(dump))
    # The write paths and the remote-host / credential provenance are among them.
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
    } <= set(PINNED_BINDINGS)


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


def test_appending_a_harmless_line_stays_clean(tmp_path: Path) -> None:
    """Control: the append harness itself does not cause violations."""
    assert violations(_check_text(tmp_path, _appended("Write-Output 'done'"))) == []


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
    assert violations(dump) == []
    assert tree_changed(dump)


def test_an_extra_certutil_call_is_a_new_exec_operation(tmp_path: Path) -> None:
    """The second half of Sol's control. Its `2>$null` discard is still allowed
    (no [redirection]), but under exact exec pinning an extra `certutil`
    invocation is a new operation outside GUARDED_OPS."""
    dump = _check_text(tmp_path, _appended("certutil -getreg CA\\CommonName 2>$null"))
    tags = {v.split("]", 1)[0] + "]" for v in violations(dump)}
    assert tags == {"[guarded-op]"}
    assert tree_changed(dump)


# --- property / indexer assignments (review round 2, DS N-R2-3) ------------------


def test_member_assignment_allowlist_matches_the_collector_exactly() -> None:
    """Every allowlisted object write is one the collector really makes, and vice versa."""
    dump = _dump(COLLECTOR)
    seen_members = {
        (m["receiver_root"], m["target"].lower().rsplit(".", 1)[-1])
        for m in dump["member_assignments"]
        if m["kind"] == "member"
    }
    seen_index = {m["receiver_root"] for m in dump["member_assignments"] if m["kind"] == "index"}
    assert seen_members == set(MEMBER_ASSIGNMENTS_ALLOWED)
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
                "  if (-not $key) { return ,$out }\n",
                "  if (-not $key) { return ,$out }\n"
                "  $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SOFTWARE\\AdcsLensProbe')\n",
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
]


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


# Edits the semantic floor deliberately admits (no write/exec/binding effect)
# but the golden inventory must still catch, so a reviewer sees them.
_GOLDEN_ONLY: list[tuple[str, tuple[Edit, ...]]] = [
    ("trailing_return", (("", "return"),)),
    (
        "message_text",
        (
            (
                'Write-Host "Using integrated auth (current user) for LDAP"',
                'Write-Host "Using integrated auth for LDAP"',
            ),
        ),
    ),
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
