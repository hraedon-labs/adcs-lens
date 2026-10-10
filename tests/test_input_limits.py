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
    assert main(["doctor", str(export)]) == 1
    assert "byte limit" in capsys.readouterr().err


def test_only_limits_module_reads_files() -> None:
    """Every file read goes through limits.read_bounded (no unbounded reads)."""
    offenders = []
    for mod in sorted(_SRC.glob("*.py")):
        if mod.name == "limits.py":
            continue
        for node in ast.walk(ast.parse(mod.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Attribute) and node.attr in {
                "read_text", "read_bytes", "open"
            }:
                offenders.append(f"{mod.name}:{node.lineno}: .{node.attr}")
            if isinstance(node, ast.Name) and node.id == "open":
                offenders.append(f"{mod.name}:{node.lineno}: open()")
    assert offenders == []
