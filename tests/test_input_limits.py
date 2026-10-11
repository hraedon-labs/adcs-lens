"""Per-file input size limits: oversized files are rejected, never truncated."""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from adcs_lens import limits
from adcs_lens.ingest import IngestError, ingest
from adcs_lens.suppression import load_suppressions
from tests.fixtures.build_fixture import build_export

_SRC = Path(__file__).resolve().parent.parent / "src" / "adcs_lens"


def _pad_json(path: Path, size: int) -> None:
    """Rewrite *path* as the same JSON value padded with trailing spaces to *size* bytes."""
    body = json.dumps(json.loads(path.read_text(encoding="utf-8-sig"))).encode("utf-8")
    assert len(body) <= size
    path.write_bytes(body + b" " * (size - len(body)))


def test_limits_are_the_documented_policy_values() -> None:
    mib = 1024 * 1024
    assert limits.MANIFEST_MAX_BYTES == 1 * mib
    assert limits.JSON_MAX_BYTES == 64 * mib
    assert limits.CERT_INDEX_MAX_BYTES == 16 * mib
    assert limits.CERT_MAX_BYTES == 1 * mib
    assert limits.CRL_MAX_BYTES == 256 * mib
    assert limits.SUPPRESSIONS_MAX_BYTES == 4 * mib


@pytest.mark.parametrize(
    ("name", "attr"),
    [
        ("collector-manifest.json", "MANIFEST_MAX_BYTES"),
        ("templates.json", "JSON_MAX_BYTES"),
        ("ca-config.json", "JSON_MAX_BYTES"),
        ("pki-acls.json", "JSON_MAX_BYTES"),
        ("principal-mappings.json", "JSON_MAX_BYTES"),
    ],
)
def test_json_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str, attr: str
) -> None:
    export = build_export(tmp_path / "e")
    limit = 4096
    monkeypatch.setattr(limits, attr, limit)
    _pad_json(export / name, limit)
    ingest(export)  # exactly at the limit: accepted
    _pad_json(export / name, limit + 1)
    with pytest.raises(IngestError, match=f"{limit}-byte limit"):
        ingest(export)


def test_real_manifest_limit_rejects_one_byte_over(tmp_path: Path) -> None:
    # Unpatched: the real 1 MiB manifest limit, at the boundary.
    export = build_export(tmp_path / "e")
    _pad_json(export / "collector-manifest.json", limits.MANIFEST_MAX_BYTES)
    ingest(export)
    _pad_json(export / "collector-manifest.json", limits.MANIFEST_MAX_BYTES + 1)
    with pytest.raises(IngestError, match="refusing to read it"):
        ingest(export)


@pytest.mark.certs
@pytest.mark.parametrize(
    ("suffix", "attr"), [(".cer", "CERT_MAX_BYTES"), (".crl", "CRL_MAX_BYTES")]
)
def test_der_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, suffix: str, attr: str
) -> None:
    pytest.importorskip("cryptography")
    export = build_export(tmp_path / "e", with_certs=True)
    largest = max(p.stat().st_size for p in (export / "certs").iterdir() if p.suffix == suffix)
    monkeypatch.setattr(limits, attr, largest)
    ingest(export)  # the largest file is exactly at the limit
    monkeypatch.setattr(limits, attr, largest - 1)
    with pytest.raises(IngestError, match="byte limit"):
        ingest(export)


@pytest.mark.certs
def test_real_cert_limit_rejects_oversized_der(tmp_path: Path) -> None:
    pytest.importorskip("cryptography")
    export = build_export(tmp_path / "e", with_certs=True)
    target = next(p for p in (export / "certs").iterdir() if p.suffix == ".cer")
    target.write_bytes(b"\0" * (limits.CERT_MAX_BYTES + 1))
    with pytest.raises(IngestError, match="over the 1048576-byte limit"):
        ingest(export)


@pytest.mark.certs
def test_malformed_der_is_an_ingest_error(tmp_path: Path) -> None:
    pytest.importorskip("cryptography")
    export = build_export(tmp_path / "e", with_certs=True)
    for p in (export / "certs").iterdir():
        if p.suffix in (".cer", ".crl"):
            p.write_bytes(b"not der")
    with pytest.raises(IngestError, match="not a DER"):
        ingest(export)


def test_invalid_utf8_is_an_ingest_error(tmp_path: Path) -> None:
    export = build_export(tmp_path / "e")
    (export / "templates.json").write_bytes(b'["\xff\xfe"]')
    with pytest.raises(IngestError, match="not valid UTF-8"):
        ingest(export)


def test_suppression_file_boundary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "s.json"
    path.write_text(json.dumps({"suppressions": []}), encoding="utf-8")
    monkeypatch.setattr(limits, "SUPPRESSIONS_MAX_BYTES", 256)
    _pad_json(path, 256)
    load_suppressions(path)
    _pad_json(path, 257)
    with pytest.raises(ValueError, match="256-byte limit"):
        load_suppressions(path)


def test_cli_reports_oversized_input_as_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from adcs_lens.cli import main

    export = build_export(tmp_path / "e")
    monkeypatch.setattr(limits, "JSON_MAX_BYTES", 10)
    assert main(["doctor", str(export)]) == 4  # a bad export is a data error (exit 4)
    assert "byte limit" in capsys.readouterr().err


# Modules src/adcs_lens may import (outside limits.py). An allowlist, not a
# denylist: io, builtins, codecs, sqlite3, subprocess, shutil, mmap, tarfile,
# zipfile, tempfile, glob, fileinput, pickle, ctypes, ... are all refused.
_ALLOWED_IMPORTS = {
    "__future__",
    "argparse",
    "collections",
    "collections.abc",
    "contextvars",
    "dataclasses",
    "datetime",
    "enum",
    "hashlib",
    "html",
    "importlib.metadata",
    "json",
    "os",
    "pathlib",
    "re",
    "sys",
    "typing",
    "unicodedata",  # pure string normalization, no I/O (normalize.py)
    "urllib.parse",
    "adcs_lens",
}
_CERTS_ONLY_IMPORTS = {"cryptography"}  # the [certs] extra, certs.py only
_READ_ATTRS = {"read_text", "read_bytes", "open", "read", "readline", "readlines", "readinto"}
_FORBIDDEN_NAMES = {
    "open",
    "__import__",
    "eval",
    "exec",
    "compile",
    "globals",
    "vars",
    "__builtins__",
    "__loader__",
    # Indirect openers: argparse.FileType opens its path; importlib.import_module
    # loads an arbitrary module (e.g. subprocess) past the import allowlist.
    "FileType",
    "import_module",
}
_OS_ALLOWED_ATTRS = {"environ"}
# Indirect openers reachable as attributes/symbols of allowlisted modules.
_FORBIDDEN_ATTRS = {"FileType", "import_module"}
# Reflection reaches builtins without naming them (sys.modules['builtins'],
# x.__dict__['open'], type(x).__subclasses__()): only these are allowed.
_SYS_ALLOWED_ATTRS = {"stderr", "stdout", "exit", "argv"}
_DUNDER_ALLOWED = {"__name__"}


# getattr reaches any attribute by name (getattr(builtins, "open")), so it is
# not allowed in general: each call site is pinned exactly (module -> the
# unparsed call), reviewed as a by-name field read on a model object. A new
# call, or one that names a read/opener attribute, is refused.
_GETATTR_SITES: dict[str, list[str]] = {
    "detection.py": [
        "getattr(obj, 'unobtained', ())",
        "getattr(self._obj, name)",
        "getattr(obj, name)",
        "getattr(obj, name)",
        "getattr(o, key)",
        "getattr(cert, name)",
    ],
    "ingest.py": [
        "getattr(c, key)",
        "getattr(c, key)",
        "getattr(t, kind)",
        "getattr(ca, key)",
        "getattr(templates[matches[0]], k)",
        "getattr(c, key)",
    ],
}


def _getattr_offenders(rel: str, tree: ast.AST) -> list[str]:
    out: list[str] = []
    calls = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id == "getattr":
            parent_calls = [c for c in ast.walk(tree) if isinstance(c, ast.Call) and c.func is node]
            if not parent_calls:
                out.append(f"{rel}:{node.lineno}: getattr (not called directly)")
                continue
            call = parent_calls[0]
            calls.append(ast.unparse(call))
            if len(call.args) > 1 and isinstance(call.args[1], ast.Constant):
                name = str(call.args[1].value)
                if name in _READ_ATTRS | _FORBIDDEN_NAMES | _FORBIDDEN_ATTRS or name.startswith(
                    "__"
                ):
                    out.append(f"{rel}:{node.lineno}: getattr(..., {name!r})")
    if sorted(calls) != sorted(_GETATTR_SITES.get(rel, [])):
        out.append(f"{rel}: getattr call sites {sorted(calls)} differ from _GETATTR_SITES")
    return out


def _read_guard_offenders(src_root: Path) -> list[str]:
    offenders: list[str] = []
    for mod in sorted(src_root.rglob("*.py")):  # subpackages included
        rel = mod.relative_to(src_root).as_posix()
        if rel == "limits.py":
            continue
        tree = ast.parse(mod.read_text(encoding="utf-8"))
        offenders.extend(_getattr_offenders(rel, tree))
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
                if node.module in ("os", "pathlib", "builtins", "io"):
                    # `from os import read`, `from builtins import open as o`, ...
                    names += [f"{node.module}.{a.name}" for a in node.names]
                for alias in node.names:
                    # From ANY module: the imported symbol itself (not its local
                    # alias) must not be a forbidden opener, so
                    # `from argparse import FileType as FT` is caught.
                    if alias.name in _FORBIDDEN_NAMES or alias.name in _FORBIDDEN_ATTRS:
                        offenders.append(
                            f"{rel}:{node.lineno}: from {node.module} import {alias.name}"
                        )
            for name in names:
                top = name.split(".")[0]
                ok = (
                    name in _ALLOWED_IMPORTS
                    or top == "adcs_lens"
                    or (rel == "certs.py" and top in _CERTS_ONLY_IMPORTS)
                    or name in ("os.environ", "pathlib.Path")
                )
                if not ok:
                    offenders.append(f"{rel}:{node.lineno}: import {name}")
            if isinstance(node, ast.Attribute):
                if node.attr in _READ_ATTRS:
                    offenders.append(f"{rel}:{node.lineno}: .{node.attr}")
                if (
                    isinstance(node.value, ast.Name)
                    and node.value.id == "os"
                    and node.attr not in _OS_ALLOWED_ATTRS
                ):
                    offenders.append(f"{rel}:{node.lineno}: os.{node.attr}")
                if (
                    isinstance(node.value, ast.Name)
                    and node.value.id == "sys"
                    and node.attr not in _SYS_ALLOWED_ATTRS
                ):
                    offenders.append(f"{rel}:{node.lineno}: sys.{node.attr}")
                if node.attr in _FORBIDDEN_ATTRS:
                    offenders.append(f"{rel}:{node.lineno}: .{node.attr} (indirect opener)")
                if (
                    isinstance(node.value, ast.Name)
                    and node.value.id == "importlib"
                    and node.attr != "metadata"
                ):
                    offenders.append(f"{rel}:{node.lineno}: importlib.{node.attr}")
                if (
                    node.attr.startswith("__")
                    and node.attr.endswith("__")
                    and node.attr not in _DUNDER_ALLOWED
                ):
                    offenders.append(f"{rel}:{node.lineno}: .{node.attr} (reflection)")
            if isinstance(node, ast.Name) and node.id in _FORBIDDEN_NAMES:
                offenders.append(f"{rel}:{node.lineno}: {node.id}")
    return offenders


def test_only_limits_module_reads_files() -> None:
    """Every file read in src/adcs_lens goes through limits.read_bounded.

    Enforced statically on every module, subpackages included: an import
    allowlist (io, builtins, codecs, sqlite3, subprocess, ... are refused), no
    read-like attribute (.read_text/.read_bytes/.open/.read/...), no os.* other
    than os.environ, and no open / getattr / __import__ / eval / exec /
    globals / vars, no sys.* beyond stderr/stdout/exit/argv, and no dunder
    attribute other than __name__ (so `from builtins import open as o`,
    `getattr(builtins, "open")` and `sys.modules['builtins'].__dict__['open']`
    are all caught).

    Remaining limits, stated plainly: this cannot see reads performed inside a
    third-party dependency (cryptography only parses bytes it is handed), and
    a C extension would have to be imported first (which the allowlist refuses),
    and the few indirect openers reachable from allowlisted modules
    (``argparse.FileType``, ``importlib.import_module``) are named and refused;
    so the guard is a reviewed boundary, not a proof about arbitrary code.
    """
    assert _read_guard_offenders(_SRC) == []


@pytest.mark.parametrize(
    "snippet",
    [
        "def f(p):\n    return open(p, 'rb').read()\n",
        "import io\ndef f(p):\n    return io.open(p).read()\n",
        "import os\ndef f(p):\n    return os.read(os.open(p, 0), 10)\n",
        "from builtins import open as o\ndef f(p):\n    return o(p)\n",
        "import builtins\ndef f(p):\n    return getattr(builtins, 'open')(p)\n",
        "import sqlite3\ndef f(p):\n    return sqlite3.connect(p)\n",
        "from pathlib import Path\ndef f(p):\n    return Path(p).read_bytes()\n",
        "import subprocess\ndef f(p):\n    return subprocess.run(['cat', p])\n",
        "def f(p):\n    return __import__('io').open(p)\n",
        "from os import read\n",
        # Sol, round 2: reflective lookup through the allowed sys module.
        "import sys\ndef f(p):\n    return sys.modules['builtins'].__dict__['open'](p, 'rb')\n",
        "def f(p):\n    return type(p).__mro__[-1].__subclasses__()\n",
        "import sys\ndef f():\n    return sys.modules\n",
        # Sol/DeepSeek round 3: indirect openers reachable from allowlisted modules.
        "from argparse import FileType\ndef f(p):\n    return list(FileType('r')(p))\n",
        "import argparse\ndef f(p):\n    return list(argparse.FileType('r')(p))\n",
        "import importlib\n"
        "def f(p):\n    return importlib.import_module('subprocess').run(['cat', p])\n",
        "from importlib import import_module\ndef f(p):\n    return import_module('subprocess')\n",
        # Sol round 4: the same openers under an import alias.
        "from argparse import FileType as FT\ndef f(p):\n    return list(FT('r')(p))\n",
        "from importlib import import_module as im\ndef f(p):\n    return im('subprocess')\n",
    ],
)
def test_read_guard_catches_unbounded_reads(tmp_path: Path, snippet: str) -> None:
    pkg = tmp_path / "adcs_lens"
    (pkg / "sub").mkdir(parents=True)
    (pkg / "sub" / "evil.py").write_text(snippet, encoding="utf-8")  # a subpackage
    assert _read_guard_offenders(pkg), snippet
