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

from adcs_lens import ingest as ingest_module
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
# One complete DER SEQUENCE that is not a certificate or CRL: an encoding a
# loader other than the [certs] library's might accept.
_SEQUENCE = b"\x30\x0e\x04\x0c" + _MARKER


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
    assert "does not record the length" in found[0].detail
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
# simulate.ps1's objectGUID of the AIA object 'LAB Old CA' (_g 20).
_OLD_AIA_GUID = "14" * 16
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
    value: bytes | None,
    edit: Callable[[dict[str, Any]], None] | None = None,
) -> Path:
    """A copy of *current* whose *cn* row of *kind_name* holds *value* (as the
    collector writes it: the bytes and their length)."""
    shutil.copytree(current, out)
    index = _index(out)
    row = next(r for r in index[kind_name] if r["ca_name"] == cn)
    if value is not None:
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
    assert "does not record" not in by_check[("CRL_UNPARSEABLE", "LAB Old CA")].detail
    assert ("CRL_EXPIRY", "LAB Old CA") not in by_check
    old_ca = {v.check: v.state for v in ev.verdicts if v.key == f"g:cert:{_OLD_AIA_GUID}"}
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
        (b"\x00", "single-zero-byte"),
        (b" ", "single-byte"),
        (_TRUNCATED, "truncated-der"),
        (_RANDOM, "not-der"),
        (_SEQUENCE, "malformed-der"),
    ],
    ids=["zero-byte", "space", "truncated", "random", "sequence"],
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
    export = _rewrite(current, tmp_path / "e", "certs", "LAB Root CA", _SEQUENCE)
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
        # ... nor for an outer tag no DER certificate has, at the same length.
        ("certs", b"X" * 700, None, "damaged after collection"),
        ("certs", _RANDOM, None, "damaged after collection"),
        # kind null (its loader rejected it) on a value that IS a certificate.
        ("certs", None, lambda r: r.__setitem__("kind", None), "loads as a certificate"),
        # The collector writes values only as certs/*.cer and certs/*.crl.
        ("certs", b"\x00", lambda r: r.update(kind=None, file="index.json"), "plain certs/"),
        ("crls", b"\x00", lambda r: r.__setitem__("file", "01-LAB_Old_CA.cer"), "certs/\\*.crl"),
        ("crls", b"\x00", lambda r: r.__setitem__("file", "sub/x.crl"), "certs/"),
        ("crls", b"\x00", lambda r: r.__setitem__("file", 7), "certs/"),
        # Its schema check fails an object whose value is empty: never a row.
        ("crls", b"", None, "never writes an empty value"),
        ("certs", b"", lambda r: r.__setitem__("kind", None), "never writes an empty value"),
        # The AIA object's objectGUID is required from collector 0.13.0.
        ("certs", None, lambda r: r.pop("object_guid"), "object_guid"),
        # The file is shorter than the value the collector recorded.
        ("crls", b"\x30\x82", lambda r: r.__setitem__("bytes", 354), "recorded 354"),
        ("certs", b"\x30\x82", lambda r: r.__setitem__("bytes", 700), "recorded 700"),
        # Collector 0.13.0 always records the length.
        ("crls", b"\x00", lambda r: r.pop("bytes"), "has no 'bytes'"),
        ("crls", b"\x00", lambda r: r.__setitem__("bytes", "1"), "non-negative integer"),
    ],
    ids=[
        "kind-for-zero-byte",
        "kind-for-letters",
        "kind-for-octet-string",
        "kind-null-on-a-certificate",
        "index-as-value",
        "cer-as-crl",
        "subdirectory",
        "file-not-a-string",
        "empty-crl",
        "empty-aia-value",
        "no-aia-guid",
        "short-crl",
        "short-cert",
        "no-length",
        "length-not-int",
    ],
)
def test_a_file_the_collector_did_not_write_is_still_exit_4(
    current: Path,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    kind_name: str,
    value: bytes | None,
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


# --- review round 1 (Sol / DeepSeek probes) --------------------------------------


@pytest.mark.parametrize(
    ("kind_name", "edit", "match"),
    [
        ("crls", lambda r: r.pop("bytes"), "has no 'bytes'"),
        ("crls", lambda r: r.update(file="../../does-not-exist.crl"), "escapes certs"),
        ("crls", lambda r: r.update(file="missing.crl"), "cannot be read"),
        ("crls", lambda r: r.update(bytes=2), "recorded 2"),
        ("certs", lambda r: r.update(file="index.json"), "plain certs/"),
        ("crls", lambda r: r.update(file="00-LAB_Root_CA.cer"), "certs/\\*.crl"),
    ],
    ids=["no-length", "escape", "missing", "length-mismatch", "index-as-value", "wrong-suffix"],
)
@needs_pwsh
def test_structure_is_checked_without_the_certs_extra(
    current: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    kind_name: str,
    edit: Callable[[dict[str, Any]], None],
    match: str,
) -> None:
    """Sol r1 B1: only ASN.1 parsing needs the [certs] extra; the index rows and
    their files are checked with the stdlib on every install."""
    bad = _rewrite(current, tmp_path / "bad", kind_name, "LAB Old CA", None, edit)
    monkeypatch.setattr(ingest_module, "_try_load_certs", lambda: None)
    with pytest.raises(IngestError, match=match):
        ingest(bad)
    rc, _ = _rc(["doctor", str(bad), "--exit-code"], capsys)
    assert rc == EXIT_DATA_ERROR


def test_structure_is_checked_without_the_certs_extra_on_an_older_export(
    seed: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ingest_module, "_try_load_certs", lambda: None)
    assert ingest(seed).manifest.certs_parsed is False  # the control: no error
    export = _with(seed, tmp_path / "e")
    (export / "certs" / "root.crl").unlink()
    with pytest.raises(IngestError, match="cannot be read"):
        ingest(export)


@needs_pwsh
@pytest.mark.parametrize(
    "value",
    [
        b"\x30\x80\x02\x01\x01\x00\x00",
        b"\x30\x03\x02\x01\x01",
        b"\x30\x03\x02\x01\x01\xff",
        _RANDOM,
    ],
    ids=["ber-indefinite", "sequence-not-a-crl", "trailing-bytes", "octet-string"],
)
def test_a_crl_another_parser_may_load_is_not_said_to_fail_on_windows(
    current: Path, tmp_path: Path, value: bytes
) -> None:
    """Sol r1 B3: the client impact is conditional unless no parser can load it."""
    export = _rewrite(current, tmp_path / "e", "crls", "LAB Old CA", value)
    finding = next(
        f for f in evaluate(ingest(export)).findings if f.check == "CRL_UNPARSEABLE"
    )
    assert "Another parser may" in finding.detail
    assert "If Windows cannot load it either" in finding.detail
    assert "a client that fetches it gets no CRL there. Microsoft" not in finding.detail
    assert finding.title == "CDP object's CRL could not be parsed"


@needs_pwsh
@pytest.mark.parametrize("value", [b"\x00", b" ", _TRUNCATED], ids=["zero", "space", "truncated"])
def test_a_crl_no_parser_can_load_keeps_the_definite_wording(
    current: Path, tmp_path: Path, value: bytes
) -> None:
    export = _rewrite(current, tmp_path / "e", "crls", "LAB Old CA", value)
    finding = next(
        f for f in evaluate(ingest(export)).findings if f.check == "CRL_UNPARSEABLE"
    )
    assert "a client that fetches it gets no CRL there. Microsoft documents" in finding.detail
    assert "If Windows cannot load it either" not in finding.detail


@needs_pwsh
def test_a_downgraded_row_that_records_its_length_has_no_caveat(
    current: Path, tmp_path: Path
) -> None:
    """DeepSeek r1 N3: the caveat follows the row's recorded length, not the
    manifest version."""
    export, _ = _as_0_12(current, tmp_path / "e", keep_lengths=True)
    finding = next(
        f for f in evaluate(ingest(export)).findings if f.check == "CRL_UNPARSEABLE"
    )
    assert "does not record the length" not in finding.detail
    export, _ = _as_0_12(current, tmp_path / "f")
    finding = next(
        f for f in evaluate(ingest(export)).findings if f.check == "CRL_UNPARSEABLE"
    )
    assert "does not record the length" in finding.detail


def _as_0_12(current: Path, out: Path, *, keep_lengths: bool = False) -> tuple[Path, int]:
    """A copy of *current* as collector 0.12.0 wrote it: no recorded lengths or
    AIA object GUIDs, and the AIA object whose value its loader rejected is an
    object failure (no row; the certs marker incomplete)."""
    shutil.copytree(current, out)
    index = _index(out)
    dropped = [r for r in index["certs"] if r["kind"] is None]
    index["certs"] = [r for r in index["certs"] if r["kind"] is not None]
    for row in dropped:
        (out / "certs" / row["file"]).unlink()
    for row in index["certs"]:
        row.pop("object_guid", None)
    for row in index["certs"] + index["crls"]:
        if not keep_lengths:
            row.pop("bytes", None)
    (out / "certs" / "index.json").write_text(json.dumps(index), encoding="utf-8")
    path = out / "collector-manifest.json"
    manifest = json.loads(path.read_text(encoding="utf-8-sig"))
    manifest["collector_version"] = "0.12.0"
    marker = manifest["enumeration"]["certs"]
    marker.update(complete=False, count=len(index["certs"]))
    marker["reason"] = f"1 of {len(index['certs']) + 1} enumerated object(s) failed"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return out, len(dropped)


@needs_pwsh
def test_diff_across_the_0_13_0_upgrade(
    current: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """DeepSeek r1 N5: a 0.12.0 export (the CDP placeholder accepted as one
    byte; the AIA object failed) against the same estate read by 0.13.0."""
    older, dropped = _as_0_12(current, tmp_path / "older")
    assert dropped == 1
    rc, env = _diff_json(older, current, capsys)
    # The CDP object is the same object (its GUID) with the same placeholder.
    every = env["new"] + env["resolved"] + env["indeterminate"] + env["first_observed"]
    assert not [f for f in every if f["check"] == "CRL_UNPARSEABLE"]
    # The AIA value the older collector could not report is newly visible.
    assert ("CA_CERT_UNPARSEABLE", "LAB Old CA") in _checks(env["new"] + env["first_observed"])
    assert rc == 1

    rc, env = _diff_json(current, older, capsys)
    # The older (0.13.0) finding cannot be resolved by an export that neither
    # identifies AIA values nor enumerated them completely.
    assert ("CA_CERT_UNPARSEABLE", "LAB Old CA") not in _checks(env["resolved"])
    assert ("CA_CERT_UNPARSEABLE", "LAB Old CA") in _checks(env["indeterminate"])
    assert not [f for f in env["new"] + env["resolved"] if f["check"] == "CRL_UNPARSEABLE"]
    assert rc in (1, 3)


def _republished(current: Path, out: Path) -> Path:
    """*current* after 'LAB Old CA' got a real certificate in place of 0x00."""
    from tests.test_reviewer_probes_r10 import _write_der

    _write_der(out.parent / f"{out.name}-der", fresh=True)
    cert = (out.parent / f"{out.name}-der" / "root.cer").read_bytes()
    return _rewrite(
        current, out, "certs", "LAB Old CA", cert, lambda r: r.__setitem__("kind", "root_ca")
    )


@needs_pwsh
def test_diff_resolves_an_aia_placeholder_once_its_object_holds_a_certificate(
    current: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """DeepSeek r1 N2: CA_CERT_UNPARSEABLE is paired by the AIA object's GUID."""
    newer = _republished(current, tmp_path / "newer")
    rc, env = _diff_json(current, newer, capsys)
    assert ("CA_CERT_UNPARSEABLE", "LAB Old CA") in _checks(env["resolved"])
    # Unchanged: no resolution, no withholding.
    rc, env = _diff_json(current, current, capsys)
    every = env["new"] + env["resolved"] + env["indeterminate"]
    assert not [f for f in every if f["check"] == "CA_CERT_UNPARSEABLE"]


@needs_pwsh
def test_an_aia_placeholder_is_not_resolved_by_an_incomplete_enumeration(
    current: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    newer = _republished(current, tmp_path / "newer")
    path = newer / "collector-manifest.json"
    manifest = json.loads(path.read_text(encoding="utf-8-sig"))
    marker = manifest["enumeration"]["certs"]
    marker.update(complete=False, count=marker["count"] - 1, reason="1 object failed")
    index = _index(newer)
    gone = index["certs"].pop()
    (newer / "certs" / gone["file"]).unlink()
    (newer / "certs" / "index.json").write_text(json.dumps(index), encoding="utf-8")
    path.write_text(json.dumps(manifest), encoding="utf-8")
    rc, env = _diff_json(current, newer, capsys)
    assert ("CA_CERT_UNPARSEABLE", "LAB Old CA") not in _checks(env["resolved"])
    assert ("CA_CERT_UNPARSEABLE", "LAB Old CA") in _checks(env["indeterminate"])
