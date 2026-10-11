"""Every malformed export is a one-line error and exit 4, never a traceback.

Sol round 10: an export file that is not valid UTF-8 escaped the data-error
boundary - every command printed a traceback and exited 1 (the regression
code). This corrupts each file of a full export in every way a file can be
damaged (encoding, BOM, NUL, truncation, wrong JSON types, nesting, size) and
runs every command on it.
"""

from __future__ import annotations

import json
import shutil
import tempfile
from collections.abc import Callable
from pathlib import Path

import pytest

from adcs_lens import ingest as ingest_mod
from adcs_lens.cli import EXIT_DATA_ERROR, main
from tests.test_diff_coverage import build_full_export

pytest.importorskip("cryptography")


def _wrong_rows(data: bytes) -> bytes:
    value = json.loads(data.decode("utf-8-sig"))
    if isinstance(value, list) and value and isinstance(value[0], dict):
        value[0] = {k: {"wrong": [1]} for k in value[0]}
    elif isinstance(value, dict):
        value = {k: 7 for k in value}
    else:
        value = {"wrong": True}
    return json.dumps(value).encode()


def _swap_container(data: bytes) -> bytes:
    value = json.loads(data.decode("utf-8-sig"))
    return b"{}" if isinstance(value, list) else b"[]"


Corruption = Callable[[bytes], bytes]
_ANY: dict[str, Corruption] = {
    "invalid-utf8": lambda d: b"\xff\xfe\x00" + d,
    "utf8-mid-sequence": lambda d: d[: len(d) // 2] + b"\xc3" + d[len(d) // 2 :],
    "bom-only": lambda d: b"\xef\xbb\xbf",
    "empty": lambda d: b"",
    "nul": lambda d: d[: len(d) // 2] + b"\x00" + d[len(d) // 2 :],
    "truncated": lambda d: d[: max(1, len(d) // 2)],
}
_JSON: dict[str, Corruption] = {
    "number": lambda d: b"5",
    "string": lambda d: b'"x"',
    "null": lambda d: b"null",
    "swapped-container": _swap_container,
    "wrong-row-types": _wrong_rows,
    "deeply-nested": lambda d: b"[" * 100_000 + b"]" * 100_000,
    "utf16": lambda d: d.decode("utf-8-sig").encode("utf-16"),
}
# A DER file accepts no JSON corruption, only the byte-level ones.
_DER: dict[str, Corruption] = {"garbage": lambda d: b"\x30\x03\x02\x01"}


@pytest.fixture(scope="module")
def seed(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return build_full_export(tmp_path_factory.mktemp("corrupt") / "seed")


def _files(seed: Path) -> list[str]:
    return sorted(str(p.relative_to(seed)) for p in seed.rglob("*") if p.is_file())


def _cases() -> list[tuple[str, str]]:
    seed = build_full_export(Path(tempfile.mkdtemp()) / "seed")  # honours TMPDIR
    cases = []
    for name in _files(seed):
        kinds = {**_ANY, **(_JSON if name.endswith(".json") else _DER)}
        cases += [(name, kind) for kind in kinds]
    shutil.rmtree(seed.parent)
    return cases


CASES = _cases()
COMMANDS: dict[str, Callable[[Path, Path], list[str]]] = {
    "ingest": lambda bad, good: ["ingest", str(bad)],
    "doctor": lambda bad, good: ["doctor", str(bad), "--json", "--exit-code"],
    "diff-old": lambda bad, good: ["diff", str(bad), str(good), "--exit-code"],
    "diff-new": lambda bad, good: ["diff", str(good), str(bad), "--json"],
}


def _corrupt(seed: Path, out: Path, name: str, kind: str) -> Path:
    shutil.copytree(seed, out)
    path = out / name
    table = {**_ANY, **_JSON, **_DER}
    path.write_bytes(table[kind](path.read_bytes()))
    return out


def _assert_data_error(argv: list[str], capsys: pytest.CaptureFixture[str]) -> None:
    capsys.readouterr()
    rc = main(argv)
    err = capsys.readouterr().err
    assert rc == EXIT_DATA_ERROR, (argv, rc, err)
    lines = [line for line in err.splitlines() if line.startswith("error:")]
    assert len(lines) == 1 and "Traceback" not in err, err


@pytest.mark.parametrize(("name", "kind"), CASES, ids=[f"{n}:{k}" for n, k in CASES])
def test_a_corrupted_export_file_is_exit_4_for_every_command(
    seed: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str], name: str, kind: str
) -> None:
    bad = _corrupt(seed, tmp_path / "bad", name, kind)
    for command in COMMANDS.values():
        _assert_data_error(command(bad, seed), capsys)


def test_an_oversized_export_file_is_refused_before_it_is_read(
    seed: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ingest_mod, "MAX_EXPORT_FILE_BYTES", 16)
    bad = tmp_path / "bad"
    shutil.copytree(seed, bad)
    for command in COMMANDS.values():
        _assert_data_error(command(bad, seed), capsys)


def test_a_missing_or_unreadable_export_is_exit_4(
    seed: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    missing = tmp_path / "missing"
    for command in COMMANDS.values():
        _assert_data_error(command(missing, seed), capsys)
    not_a_dir = tmp_path / "file"
    not_a_dir.write_text("{}", encoding="utf-8")
    for command in COMMANDS.values():
        _assert_data_error(command(not_a_dir, seed), capsys)
