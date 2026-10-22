"""A published CA certificate or CRL whose value does not load is an estate fact.

Owner report against 1.2.0: an unmodified export of a production CA stopped
the run (exit 4) on ``<file>.crl: not a DER CRL (... ShortData { needed: 1 })``
- a CDP object whose certificateRevocationList value is a single byte. AD PKI
management tools write a single 0x00 byte into an object that holds no CRL or
certificate (PSPKI does), so such a value is something AD can hold, not a sign
that the export was damaged.

The behaviour these tests pin:

* A value AD holds that does not load is reported - CRL_UNPARSEABLE (a CDP
  object) / CA_CERT_UNPARSEABLE (an AIA value that is not a certificate), LOW
  posture findings - or, for an AIA value the collector's own loader read but
  adcs-lens cannot, the CA_CERT_NOT_EVALUATED coverage note. The run goes on.
* Every lifecycle check that needed the value is undecided, and diff treats
  it as coverage lost or gained, never as resolved or as plain new.
* Collector >= 0.13.0 records each value's length; a file of another length was
  damaged after collection and is still exit 4. An older export cannot tell the
  two apart, so it keeps failing closed on everything except a single byte that
  no truncated certificate or CRL can be (anything but 0x30).
* The value's bytes are never reported: only its length and a class.
"""

from __future__ import annotations

import base64
import json
import shutil
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from adcs_lens.cli import EXIT_DATA_ERROR, main
from adcs_lens.detection import evaluate, is_degradation_note
from adcs_lens.ingest import IngestError, ingest
from adcs_lens.model import (
    UNPARSEABLE_EMPTY,
    UNPARSEABLE_MALFORMED,
    UNPARSEABLE_NOT_DER,
    UNPARSEABLE_SINGLE_BYTE,
    UNPARSEABLE_TRUNCATED,
    UNPARSEABLE_ZERO_BYTE,
    Severity,
    classify_unparseable,
)
from tests._pwsh import run_pwsh
from tests.conftest import NOW
from tests.test_diff_coverage import build_full_export

# A value whose bytes would be recognisable in any output that leaked them.
_MARKER = b"RAWVALUEMARK"
_RANDOM = b"\x04\x0c" + _MARKER  # an OCTET STRING: one DER structure, not a CRL
_TRUNCATED = b"\x30\x82\x01\x60\x30\x82"  # a SEQUENCE header promising 352 bytes


# --- classification ------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "cls"),
    [
        (b"", UNPARSEABLE_EMPTY),
        (b"\x00", UNPARSEABLE_ZERO_BYTE),
        (b" ", UNPARSEABLE_SINGLE_BYTE),
        (b"\x30", UNPARSEABLE_SINGLE_BYTE),
        (_TRUNCATED, UNPARSEABLE_TRUNCATED),
        (b"\x30\x84\x00\x00", UNPARSEABLE_TRUNCATED),  # length octets cut short
        (_RANDOM, UNPARSEABLE_NOT_DER),
        (b"\x30\x80\x02\x01\x01\x00\x00", UNPARSEABLE_NOT_DER),  # BER indefinite length
        (b"\x30\x03\x02\x01\x01\xff", UNPARSEABLE_NOT_DER),  # trailing bytes
        (b"\x30\x03\x02\x01\x01", UNPARSEABLE_MALFORMED),  # one SEQUENCE, not a CRL
    ],
)
def test_a_value_is_classified_from_its_length_and_outer_header(value: bytes, cls: str) -> None:
    assert classify_unparseable(value) == cls


# --- helpers -------------------------------------------------------------------


def _outputs(export: Path, capsys: pytest.CaptureFixture[str]) -> dict[str, str]:
    """Every doctor rendering of *export* (stdout and stderr)."""
    out: dict[str, str] = {}
    renderings: dict[str, list[str]] = {
        "text": [],
        "json": ["--json"],
        "sarif": ["--sarif"],
        "html": ["--html"],
    }
    for name, flags in renderings.items():
        capsys.readouterr()
        main(["doctor", str(export), *flags])
        captured = capsys.readouterr()
        out[name] = captured.out + captured.err
    return out


def _assert_no_raw_bytes(texts: dict[str, str], value: bytes) -> None:
    forms = {
        value.decode("latin-1"),
        value.hex(),
        value.hex().upper(),
        base64.b64encode(value).decode(),
    }
    for name, text in texts.items():
        for form in forms:
            assert form not in text, (name, form)


def _rc(argv: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, str]:
    capsys.readouterr()
    rc = main(argv)
    return rc, capsys.readouterr().out


def _diff_json(old: Path, new: Path, capsys: pytest.CaptureFixture[str]) -> tuple[int, Any]:
    rc, out = _rc(["diff", str(old), str(new), "--exit-code", "--json"], capsys)
    return rc, json.loads(out)


def _checks(items: list[dict[str, Any]]) -> set[tuple[str, str]]:
    return {(i["check"], i["subject"]) for i in items}


# --- an export from collector < 0.13.0 (no recorded length) ---------------------

pytest.importorskip("cryptography")
pytestmark = pytest.mark.certs


@pytest.fixture(scope="module")
def seed(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A collector 0.10.0 export: root.crl (expired: CRL_EXPIRY), issuing.crl
    (in date), root.cer and issuing.cer."""
    return build_full_export(tmp_path_factory.mktemp("unparseable") / "seed")


def _with(seed: Path, out: Path, **files: bytes) -> Path:
    shutil.copytree(seed, out)
    for name, value in files.items():
        (out / "certs" / name.replace("_", ".")).write_bytes(value)
    return out


def _set_version(export: Path, version: str) -> None:
    path = export / "collector-manifest.json"
    manifest = json.loads(path.read_text(encoding="utf-8-sig"))
    manifest["collector_version"] = version
    path.write_text(json.dumps(manifest), encoding="utf-8")


@pytest.mark.parametrize(("value", "cls"), [(b"\x00", "single-zero-byte"), (b" ", "single-byte")])
def test_a_one_byte_crl_no_longer_stops_the_run(
    seed: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str], value: bytes, cls: str
) -> None:
    export = _with(seed, tmp_path / "e", root_crl=value)
    estate = ingest(export)  # 1.2.0: IngestError "not a DER CRL"
    crl = next(c for c in estate.crls if c.file == "root.crl")
    assert (crl.unparseable, crl.byte_length, crl.next_update) == (cls, 1, None)

    ev = evaluate(estate, now=NOW)
    found = [f for f in ev.findings if f.check == "CRL_UNPARSEABLE"]
    assert len(found) == 1 and found[0].severity is Severity.LOW
    assert not is_degradation_note(found[0])
    assert "1 byte" in found[0].detail or "single" in found[0].detail
    # The older collector recorded no length: the finding says so.
    assert "did not record the length" in found[0].detail
    # Nothing was decided about the CRL itself: CRL_EXPIRY is undecided on it.
    assert not [f for f in ev.findings if f.check == "CRL_EXPIRY" and f.subject.endswith("Root CA")]
    crl_expiry = [v for v in ev.verdicts if v.check == "CRL_EXPIRY" and v.key.startswith("g:crl:")]
    assert "undecided" in {v.state for v in crl_expiry}

    for name, text in _outputs(export, capsys).items():
        assert "CRL_UNPARSEABLE" in text, name
    # A posture finding: --exit-code fails (1), not a data error (4).
    rc, _ = _rc(["doctor", str(export), "--exit-code"], capsys)
    assert rc == 1


@pytest.mark.parametrize(
    "value",
    [b"", b"\x30", _TRUNCATED, _RANDOM, b"not der"],
    ids=["empty", "0x30", "truncated", "random", "text"],
)
@pytest.mark.parametrize("name", ["root_crl", "root_cer"])
def test_an_older_export_still_refuses_any_other_value_that_does_not_load(
    seed: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str], value: bytes, name: str
) -> None:
    """Without a recorded length, a truncated or overwritten file looks exactly
    like a value AD might hold: fail closed, and say how to get it reported."""
    export = _with(seed, tmp_path / "e", **{name: value})
    with pytest.raises(IngestError, match="not a DER") as err:
        ingest(export)
    assert "0.13.0" in str(err.value)
    rc, _ = _rc(["doctor", str(export), "--exit-code"], capsys)
    assert rc == EXIT_DATA_ERROR


def test_a_reads_proven_collector_never_wrote_an_unloadable_certificate(
    seed: Path, tmp_path: Path
) -> None:
    """Collector 0.10.0-0.12.0 failed an AIA object whose value did not load
    (no row), so a one-byte certificate file in such an export was damaged."""
    export = _with(seed, tmp_path / "e", root_cer=b"\x00")
    with pytest.raises(IngestError, match="not a DER certificate"):
        ingest(export)


def test_an_unproven_export_reports_a_one_byte_aia_value(seed: Path, tmp_path: Path) -> None:
    export = _with(seed, tmp_path / "e", root_cer=b"\x00")
    _set_version(export, "0.9.0")
    ev = evaluate(ingest(export), now=NOW)
    found = [f for f in ev.findings if f.check == "CA_CERT_UNPARSEABLE"]
    assert [(f.subject, f.severity) for f in found] == [("LAB Root CA", Severity.LOW)]
    assert not [f for f in ev.findings if f.check == "CA_CERT_EXPIRY" and "Root" in f.subject]


def test_diff_a_crl_replaced_by_a_placeholder_is_coverage_lost_not_resolved(
    seed: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Older: a real (expired) root CRL and an in-date issuing CRL. Newer: both
    CDP objects hold the 0x00 placeholder."""
    newer = _with(seed, tmp_path / "newer", root_crl=b"\x00", issuing_crl=b"\x00")
    rc, env = _diff_json(seed, newer, capsys)
    assert not [f for f in env["resolved"] if f["check"] == "CRL_EXPIRY"]
    assert "CRL_EXPIRY" in {f["check"] for f in env["indeterminate"]}  # the expired root CRL
    assert "CRL_EXPIRY" in {u["check"] for u in env["unevaluated"]}  # the in-date issuing CRL
    assert {f["check"] for f in env["new"]} >= {"CRL_UNPARSEABLE"}
    assert env["summary"]["coverage_lost"] is True
    assert rc == 1  # a CDP object that lost its CRL is a regression; it wins over 3


def test_diff_a_placeholder_replaced_by_a_crl_resolves_it_and_gains_coverage(
    seed: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    older = _with(seed, tmp_path / "older", root_crl=b"\x00")
    rc, env = _diff_json(older, seed, capsys)
    assert ("CRL_UNPARSEABLE", "LAB Root CA") in _checks(env["resolved"])
    first = [f for f in env["first_observed"] if f["check"] == "CRL_EXPIRY"]
    assert first and "could not load it" in first[0]["reason"]
    assert not [f for f in env["new"] if f["check"] == "CRL_EXPIRY"]
    assert rc == 1  # a newly visible finding still fails the gate


def test_diff_an_unchanged_placeholder_is_unchanged(
    seed: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    older = _with(seed, tmp_path / "older", root_crl=b"\x00")
    newer = _with(seed, tmp_path / "newer", root_crl=b"\x00")
    rc, env = _diff_json(older, newer, capsys)
    assert not [f for f in env["new"] + env["resolved"] if "UNPARSEABLE" in f["check"]]
    assert not [i for i in env["indeterminate"] if i["check"] == "CRL_EXPIRY"]
    assert rc == 0


# --- an export from collector >= 0.13.0 (the real collector body) ----------------

_SIMULATE = Path(__file__).parent / "collector" / "simulate.ps1"
_PWSH = shutil.which("pwsh")
needs_pwsh = pytest.mark.skipif(_PWSH is None, reason="pwsh is not installed")


def _simulate(out: Path, der: Path, *extra: str) -> Path:
    assert _PWSH is not None
    proc = run_pwsh(
        [_PWSH, "-NoProfile", "-NonInteractive", "-File", str(_SIMULATE), "-OutDir", str(out)]
        + ["-DerDir", str(der), *extra],
        capture_output=True,
        text=True,
        timeout=300,
        out_dir=out,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return out


@pytest.fixture(scope="module")
def current(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Collector 0.13.0 run against AIA and CDP objects 'LAB Root CA' (a real
    root certificate and a CRL near its nextUpdate) and 'LAB Old CA', each of
    whose value is the single 0x00 byte."""
    if _PWSH is None:
        pytest.skip("pwsh is not installed")
    from tests.test_reviewer_probes_r10 import _write_der

    base = tmp_path_factory.mktemp("current")
    _write_der(base / "der", fresh=False)
    return _simulate(base / "export", base / "der", "-Placeholder", "00")


def _index(export: Path) -> dict[str, list[dict[str, Any]]]:
    data: dict[str, list[dict[str, Any]]] = json.loads(
        (export / "certs" / "index.json").read_text(encoding="utf-8-sig")
    )
    return data


def _rewrite(
    current: Path,
    out: Path,
    kind_name: str,
    cn: str,
    value: bytes,
    edit: Callable[[dict[str, Any]], None] | None = None,
) -> Path:
    """A copy of *current* whose *cn* row of *kind_name* holds *value* (as the
    collector writes it: the bytes and their length)."""
    shutil.copytree(current, out)
    index = _index(out)
    row = next(r for r in index[kind_name] if r["ca_name"] == cn)
    (out / "certs" / row["file"]).write_bytes(value)
    row["bytes"] = len(value)
    if edit is not None:
        edit(row)
    (out / "certs" / "index.json").write_text(json.dumps(index), encoding="utf-8")
    return out


@needs_pwsh
def test_the_collector_writes_the_value_as_ad_holds_it(current: Path) -> None:
    index = _index(current)
    crl = next(r for r in index["crls"] if r["ca_name"] == "LAB Old CA")
    cert = next(r for r in index["certs"] if r["ca_name"] == "LAB Old CA")
    assert (current / "certs" / crl["file"]).read_bytes() == b"\x00" and crl["bytes"] == 1
    assert (current / "certs" / cert["file"]).read_bytes() == b"\x00" and cert["bytes"] == 1
    assert cert["kind"] is None  # its own loader (.NET) could not read it
    real = next(r for r in index["certs"] if r["ca_name"] == "LAB Root CA")
    assert real["kind"] == "root_ca" and real["bytes"] == len(
        (current / "certs" / real["file"]).read_bytes()
    )
    manifest = json.loads((current / "collector-manifest.json").read_text(encoding="utf-8-sig"))
    assert manifest["collector_version"] == "0.13.0"
    # The AIA object is no longer an object failure: both containers are complete.
    assert manifest["enumeration"]["certs"]["complete"] is True
    assert manifest["enumeration"]["crls"]["complete"] is True


@needs_pwsh
def test_placeholders_are_reported_and_decide_nothing(
    current: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    estate = ingest(current)
    assert "certs" in estate.manifest.enumeration_complete
    tiers = {c.source.split(",")[0].split("CN=")[-1]: c.tier for c in estate.crls}
    # The root's tier still derives from its own certificate; the placeholder
    # AIA value decides no tier, so 'LAB Old CA' has none.
    assert tiers["LAB Root CA"] is not None and tiers["LAB Old CA"] is None
    ev = evaluate(estate, now=datetime.now(UTC))
    by_check = {(f.check, f.subject): f for f in ev.findings}
    assert by_check[("CRL_UNPARSEABLE", "LAB Old CA")].severity is Severity.LOW
    assert by_check[("CA_CERT_UNPARSEABLE", "LAB Old CA")].severity is Severity.LOW
    assert "did not record" not in by_check[("CRL_UNPARSEABLE", "LAB Old CA")].detail
    assert ("CRL_EXPIRY", "LAB Old CA") not in by_check
    old_ca = {v.check: v.state for v in ev.verdicts if "unparseable:lab old ca" in v.key}
    assert old_ca["CA_CERT_EXPIRY"] == "undecided" and old_ca["WEAK_SIG_ALG"] == "undecided"

    outputs = _outputs(current, capsys)
    for name, text in outputs.items():
        assert "CRL_UNPARSEABLE" in text and "CA_CERT_UNPARSEABLE" in text, name
    _, sarif = _rc(["doctor", str(current), "--sarif"], capsys)
    results = {r["ruleId"] for r in json.loads(sarif)["runs"][0]["results"]}
    assert {"CRL_UNPARSEABLE", "CA_CERT_UNPARSEABLE"} <= results


@needs_pwsh
@pytest.mark.parametrize(
    ("value", "cls"),
    [
        (b"", "empty"),
        (b"\x00", "single-zero-byte"),
        (_TRUNCATED, "truncated-der"),
        (_RANDOM, "not-der"),
    ],
    ids=["empty", "zero-byte", "truncated", "random"],
)
@pytest.mark.parametrize(
    ("kind_name", "check"), [("crls", "CRL_UNPARSEABLE"), ("certs", "CA_CERT_UNPARSEABLE")]
)
def test_every_class_of_value_is_reported_without_its_bytes(
    current: Path,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    value: bytes,
    cls: str,
    kind_name: str,
    check: str,
) -> None:
    def rejected(row: dict[str, Any]) -> None:
        if kind_name == "certs":
            row["kind"] = None  # as the collector writes a value .NET cannot load

    export = _rewrite(current, tmp_path / "e", kind_name, "LAB Root CA", value, rejected)
    ev = evaluate(ingest(export), now=datetime.now(UTC))
    found = [f for f in ev.findings if f.check == check and f.subject == "LAB Root CA"]
    assert len(found) == 1 and f"class {cls}" in found[0].source
    assert f"{len(value)} byte" in found[0].source or len(value) <= 1
    outputs = _outputs(export, capsys)
    _assert_no_raw_bytes(outputs, value if len(value) > 4 else _MARKER)


@needs_pwsh
def test_a_certificate_only_adcs_lens_cannot_read_is_a_coverage_note(
    current: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The collector's loader read it (kind named); the [certs] library cannot."""
    export = _rewrite(current, tmp_path / "e", "certs", "LAB Root CA", _RANDOM)
    estate = ingest(export)
    ev = evaluate(estate, now=datetime.now(UTC))
    notes = [f for f in ev.findings if f.check == "CA_CERT_NOT_EVALUATED"]
    assert len(notes) == 1 and is_degradation_note(notes[0])
    assert notes[0].severity is Severity.INFO
    assert not [f for f in ev.findings if f.check == "CA_CERT_UNPARSEABLE" and "Root" in f.subject]
    # Its kind is the collector's, so the root CRL's tier still derives from it.
    assert next(c for c in estate.crls if "CN=LAB Root CA," in c.source).tier is not None
    _assert_no_raw_bytes(_outputs(export, capsys), _MARKER)


@needs_pwsh
@pytest.mark.parametrize(
    ("kind_name", "value", "edit", "match"),
    [
        # A kind named for bytes no loader reads: not what the collector wrote.
        ("certs", b"\x00", None, "damaged after collection"),
        # The file is shorter than the value the collector recorded.
        ("crls", b"\x30\x82", lambda r: r.__setitem__("bytes", 354), "recorded 354"),
        ("certs", b"\x30\x82", lambda r: r.__setitem__("bytes", 700), "recorded 700"),
        # Collector 0.13.0 always records the length.
        ("crls", b"\x00", lambda r: r.pop("bytes"), "has no 'bytes'"),
        ("crls", b"\x00", lambda r: r.__setitem__("bytes", "1"), "non-negative integer"),
    ],
    ids=["kind-for-zero-byte", "short-crl", "short-cert", "no-length", "length-not-int"],
)
def test_a_file_the_collector_did_not_write_is_still_exit_4(
    current: Path,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    kind_name: str,
    value: bytes,
    edit: Callable[[dict[str, Any]], None] | None,
    match: str,
) -> None:
    bad = _rewrite(current, tmp_path / "bad", kind_name, "LAB Root CA", value, edit)
    with pytest.raises(IngestError, match=match):
        ingest(bad)
    for argv in (
        ["doctor", str(bad), "--exit-code"],
        ["diff", str(current), str(bad), "--exit-code"],
        ["diff", str(bad), str(current), "--exit-code"],
    ):
        rc, _ = _rc(argv, capsys)
        assert rc == EXIT_DATA_ERROR, argv


@needs_pwsh
def test_diff_current_exports_both_ways(
    current: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The root CRL is near its nextUpdate (a CRL_EXPIRY finding); a newer
    export whose root CDP object holds the placeholder lost that coverage, and
    the reverse resolves CRL_UNPARSEABLE and gains it."""
    placeholder = _rewrite(current, tmp_path / "placeholder", "crls", "LAB Root CA", b"\x00")
    rc, env = _diff_json(current, placeholder, capsys)
    assert ("CRL_EXPIRY", "LAB Root CA") not in _checks(env["resolved"])
    assert "CRL_EXPIRY" in {i["check"] for i in env["indeterminate"]}
    assert ("CRL_UNPARSEABLE", "LAB Root CA") in _checks(env["new"])
    assert rc == 1

    rc, env = _diff_json(placeholder, current, capsys)
    assert ("CRL_UNPARSEABLE", "LAB Root CA") in _checks(env["resolved"])
    assert "CRL_EXPIRY" in {f["check"] for f in env["first_observed"]}
    assert rc == 1
