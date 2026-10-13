"""WI-044 review round 3: every reviewer probe, replayed as a regression test.

Sources (archived with the review): Sol's r3_host_probes.py and
r3_cli_probes.py, and DeepSeek's probes_r3.py and cli_probe_r3.py.

* Sol r3 blocking 1 - a known host name the parser does not support (a
  non-ASCII AD dNSHostName, a 254/255-byte extended host name; MS-HNDS allows
  both) vanished from the short-name rival set, so an old 0.10.0 short-host
  endpoint resolved from another host with the same first label (exit 0). Such
  a name now poisons short-name matching instead.
* DS r3 N3 - two equal short names matched even when two FQDNs with that label
  were known; they are now ambiguous.
* DS r3 N2 - a non-ASCII own-host host_fqdn made a genuine export
  un-ingestable (exit 4); it is now not believed (fall back to the short host).
* DS r3 N6 - the endpoint row / host_fqdn agreement check is a DNS comparison.
* DS r3 N5 - explanation-only host matching uses whole-name equality.
* Sol r3 NB1 - a rival known only to the newer export withholds an older
  short-host finding (conservative; pinned here, documented).
"""

from __future__ import annotations

import contextlib
import io
import json
import shutil
from pathlib import Path
from typing import Any

import pytest

from adcs_lens.cli import main
from adcs_lens.detection import ObjectRef, coverage_gaps, evaluate, same_object
from adcs_lens.diff import DriftReport, diff_findings
from adcs_lens.ingest import IngestError, ingest
from adcs_lens.model import (
    CaKind,
    CertAuthority,
    EndpointKind,
    EnrollmentEndpoint,
    EpaPolicy,
    Estate,
    Manifest,
)
from adcs_lens.normalize import host_key, same_host
from tests.conftest import NOW
from tests.fixtures.build_fixture import build_export

CA01 = "labca01.lab.example.com"
TARGET = "ca1.pki.example"
# 254 and 255 characters: legal AD extended host names (MS-HNDS 2.1), longer
# than this parser supports.
LONG_254 = "labca01." + ".".join(("a" * 63, "b" * 63, "c" * 63, "d" * 54))
LONG_255 = "labca01." + ".".join(("a" * 63, "b" * 63, "c" * 63, "d" * 55))
UNICODE_RIVAL = "labca01.bücher.example"


def test_the_long_rivals_are_the_lengths_claimed() -> None:
    assert (len(LONG_254), len(LONG_255)) == (254, 255)
    assert host_key(LONG_254) == host_key(LONG_255) == host_key(UNICODE_RIVAL) == ""


# --- Sol r3 blocking 1: unsupported rivals poison short names ------------------


@pytest.mark.parametrize(
    "rival",
    ["labca01.admin.example", UNICODE_RIVAL, LONG_254, LONG_255, "LABCA01.BÜCHER.EXAMPLE"],
)
def test_an_unsupported_or_supported_rival_makes_a_short_name_ambiguous(rival: str) -> None:
    assert same_host("labca01", CA01, [CA01])
    assert not same_host("labca01", CA01, [CA01, rival])


def test_a_known_name_with_a_non_ascii_first_label_poisons_every_short_name() -> None:
    """It might be the same label under an IDNA mapping (e.g. fullwidth
    characters), so it cannot be ruled out."""
    assert not same_host("labca01", CA01, [CA01, "ｌａｂｃａ０１.example"])
    assert not same_host("labca01", CA01, [CA01, "bücher.example"])


def test_the_candidate_itself_in_another_spelling_is_not_a_rival() -> None:
    assert same_host("labca01", CA01, [CA01, "LABCA01.LAB.EXAMPLE.COM.", "other.example"])


def _rw(path: Path, mutate: Any) -> None:
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    mutate(data)
    path.write_text(json.dumps(data), encoding="utf-8")


def _add_rivals(export: Path, rivals: tuple[str, ...]) -> None:
    """Standalone CA rows (no enrollment service) whose DNS names are rivals."""

    def add(rows: list[dict[str, Any]]) -> None:
        for i, dns in enumerate(rivals):
            row = dict(rows[0])
            row.update(
                name=f"LAB Rival {i}",
                dns=dns,
                config_string=f"{dns}\\LAB Rival {i}",
                object_guid=f"{i + 10:02x}" * 16,
                enrollment_service=False,
            )
            rows.append(row)

    _rw(export / "ca-config.json", add)
    _rw(
        export / "ca-security.json",
        lambda d: d.update({f"LAB Rival {i}": None for i in range(len(rivals))}),
    )
    _rw(
        export / "collector-manifest.json",
        lambda m: m["enumeration"]["ca-config"].update(
            count=m["enumeration"]["ca-config"]["count"] + len(rivals)
        ),
    )


def _as_011_empty(export: Path, *, host: str = "LABCA01", host_fqdn: str = CA01) -> Path:
    _rw(
        export / "collector-manifest.json",
        lambda m: m.update(collector_version="0.11.0", host=host, host_fqdn=host_fqdn),
    )
    _rw(export / "web-endpoints.json", lambda rows: rows.clear())
    _rw(
        export / "collector-manifest.json",
        lambda m: m["enumeration"]["web-endpoints"].update(count=0),
    )
    _rw(
        export / "pki-acls.json",
        lambda rows: [r.update(ca_host_sid="", enrollment_service=False) for r in rows],
    )
    return export


def _cli(old: Path, new: Path) -> tuple[int, dict[str, Any]]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        rc = main(["diff", str(old), str(new), "--exit-code", "--json"])
    return rc, json.loads(out.getvalue())


@pytest.mark.parametrize(
    "rivals",
    [(UNICODE_RIVAL,), (LONG_254,), (LONG_255,), (UNICODE_RIVAL, LONG_255)],
    ids=["unicode", "254-byte", "255-byte", "both"],
)
def test_sol_r3_b1_real_cli_an_old_only_unsupported_rival_never_resolves(
    tmp_path: Path, rivals: tuple[str, ...]
) -> None:
    """r3_cli_probes.py unicode-rival-product-path / 254-byte-rival-product-path:
    an old 0.10.0 export (short host LABCA01, /CertSrv vulnerable) that also
    knows a rival with first label labca01; a new empty 0.11.0 export from
    labca01.lab.example.com that does not. It exited 0 with ESC8 resolved."""
    old = build_export(tmp_path / "old", with_certs=False, now=NOW)
    _add_rivals(old, rivals)
    new = _as_011_empty(build_export(tmp_path / "new", with_certs=False, now=NOW))
    rc, env = _cli(old, new)
    assert [f["subject"] for f in env["resolved"] if f["check"] == "ESC8"] == []
    withheld = [i.get("finding", i) for i in env["indeterminate"]]
    assert [f["subject"] for f in withheld if f["check"] == "ESC8"] == ["/CertSrv"]
    assert rc == 3


def test_sol_r3_without_the_rival_the_same_upgrade_resolves(tmp_path: Path) -> None:
    old = build_export(tmp_path / "old", with_certs=False, now=NOW)
    new = _as_011_empty(build_export(tmp_path / "new", with_certs=False, now=NOW))
    rc, env = _cli(old, new)
    assert [f["subject"] for f in env["resolved"] if f["check"] == "ESC8"] == ["/CertSrv"]
    assert rc == 0


# --- hand-built replays (r3_host_probes.py, probes_r3.py) ----------------------


def _ca(name: str, dns: str, *, es: bool = True) -> CertAuthority:
    return CertAuthority(
        name=name,
        dns=dns,
        config_string=f"{dns}\\{name}",
        kind=CaKind.ISSUING,
        edit_flags=frozenset(),
        interface_flags=frozenset(),
        audit_filter=127,
        security=(),
        certs=(),
        enrollment_service=es,
    )


def _ep(host: str) -> EnrollmentEndpoint:
    return EnrollmentEndpoint(
        kind=EndpointKind.WEB_ENROLLMENT,
        name="/CertSrv",
        transports=frozenset({"http"}),
        ssl_required=False,
        windows_auth=True,
        auth_providers=frozenset({"ntlm"}),
        epa=EpaPolicy.NONE,
        host=host,
    )


def _estate(
    cas: tuple[CertAuthority, ...],
    endpoints: tuple[EnrollmentEndpoint, ...] = (),
    *,
    version: str = "0.11.0",
    host: str = "ca1",
    host_fqdn: str = TARGET,
) -> Estate:
    return Estate(
        cas=cas,
        templates=(),
        acls=(),
        oids=(),
        crls=(),
        endpoints=endpoints,
        dcs=(),
        principal_mappings=(),
        manifest=Manifest(
            collector_version=version,
            collected_at="",
            host=host,
            domain="",
            skipped_passes=(),
            certs_parsed=True,
            enumeration_complete=frozenset({"ca-config", "web-endpoints"}),
            host_fqdn=host_fqdn,
        ),
    )


def _drift(old: Estate, new: Estate) -> DriftReport:
    return diff_findings(
        evaluate(old, now=NOW), evaluate(new, now=NOW), coverage=coverage_gaps(new)
    )


@pytest.mark.parametrize(
    "rival", ["ca1.admin.example", "ca1.bücher.example", "ca1." + LONG_254[8:]]
)
def test_sol_r3_absence_with_a_rival_on_both_sides_is_withheld(rival: str) -> None:
    """absence_with_rival: the rival is a standalone CA row in both exports."""
    cas = (_ca("TARGET", TARGET), _ca("LOCAL-STANDALONE", rival, es=False))
    old = _estate(cas, (_ep("ca1"),), version="0.10.0", host_fqdn="")
    drift = _drift(old, _estate(cas))
    assert [f.subject for f in drift.resolved if f.check == "ESC8"] == []


def test_sol_r3_nb1_a_rival_known_only_to_the_newer_export_also_withholds() -> None:
    """Conservative by design: either export's knowledge makes a short name
    ambiguous (a genuine new CA on another host would also make the newer
    endpoint list incomplete)."""
    old = _estate(
        (_ca("TARGET", TARGET), _ca("NEW-STANDALONE", "root.admin.example", es=False)),
        (_ep("ca1"),),
        version="0.10.0",
        host_fqdn="",
    )
    new = _estate((_ca("TARGET", TARGET), _ca("NEW-STANDALONE", "ca1.admin.example", es=False)))
    drift = _drift(old, new)
    assert [f.subject for f in drift.resolved if f.check == "ESC8"] == []
    assert [i.finding.subject for i in drift.indeterminate if i.finding.check == "ESC8"] == [
        "/CertSrv"
    ]


# --- DS r3 N3: equal short names with two candidates ----------------------------


def test_ds_r3_n3_equal_short_names_are_ambiguous_with_two_candidates() -> None:
    assert same_host("ca1", "ca1", ["ca1.pki.example"])
    assert same_host("ca1", "CA1", [])
    assert not same_host("ca1", "ca1", ["ca1.pki.example", "ca1.admin.example"])
    assert not same_host("ca1", "ca1", ["ca1.pki.example", "ca1.bücher.example"])
    assert same_host("ca1.pki.example", "ca1.pki.example", ["ca1.admin.example"])  # FQDNs


def test_ds_r3_n3_a_short_to_short_diff_with_two_candidates_never_resolves() -> None:
    cas = (_ca("CA-A", "ca1.pki.example"), _ca("CA-B", "ca1.admin.example", es=False))
    old = _estate(cas, (_ep("ca1"),), version="0.10.0", host_fqdn="")
    new = _estate(cas, version="0.10.0", host_fqdn="")
    assert [f.subject for f in _drift(old, new).resolved if f.check == "ESC8"] == []


# --- DS r3 N2 / N6: ingest degrades, compares as DNS names ----------------------


def _as_011(export: Path, *, host_fqdn: str, row_host: str | None = None) -> Path:
    _rw(
        export / "collector-manifest.json",
        lambda m: m.update(collector_version="0.11.0", host="LABCA01", host_fqdn=host_fqdn),
    )
    _rw(
        export / "web-endpoints.json",
        lambda rows: [r.update(host=row_host or host_fqdn) for r in rows],
    )
    _rw(
        export / "pki-acls.json",
        lambda rows: [r.update(ca_host_sid="", enrollment_service=False) for r in rows],
    )
    return export


@pytest.mark.parametrize("fqdn", [UNICODE_RIVAL, LONG_254, "labca01..lab.example.com"])
def test_ds_r3_n2_an_unsupported_own_fqdn_degrades_not_refuses(tmp_path: Path, fqdn: str) -> None:
    """cli_probe_r3.py nonascii-host_fqdn: exit 4 before; now the export is
    read, attributed to its short host, and nothing resolves from it."""
    export = _as_011(build_export(tmp_path / "x", with_certs=False, now=NOW), host_fqdn=fqdn)
    estate = ingest(export)
    assert estate.manifest.host_fqdn == ""
    assert {e.host for e in estate.endpoints} == {"LABCA01"}
    old = build_export(tmp_path / "old", with_certs=False, now=NOW)
    new = tmp_path / "new"
    shutil.copytree(export, new)
    _rw(new / "web-endpoints.json", lambda rows: rows.clear())
    _rw(
        new / "collector-manifest.json", lambda m: m["enumeration"]["web-endpoints"].update(count=0)
    )
    rc, _env = _cli(old, new)
    assert rc != 4


@pytest.mark.parametrize("row_host", ["LABCA01.LAB.EXAMPLE.COM", "labca01.lab.example.com."])
def test_ds_r3_n6_a_row_host_equal_as_a_dns_name_is_accepted(tmp_path: Path, row_host: str) -> None:
    export = _as_011(
        build_export(tmp_path / "x", with_certs=False, now=NOW), host_fqdn=CA01, row_host=row_host
    )
    assert {e.host for e in ingest(export).endpoints} == {CA01}


def test_ds_r3_n6_a_row_on_another_host_is_still_refused(tmp_path: Path) -> None:
    export = _as_011(
        build_export(tmp_path / "x", with_certs=False, now=NOW),
        host_fqdn=CA01,
        row_host="labca02.lab.example.com",
    )
    with pytest.raises(IngestError, match="altered after collection"):
        ingest(export)


# --- DS r3 N5: explanations compare whole host names ---------------------------


def test_ds_r3_n5_explanations_never_infer_a_short_name() -> None:
    a = ObjectRef("endpoint", "", ("app:web_enrollment:/certsrv",), host="ca1")
    b = ObjectRef("endpoint", "", ("app:web_enrollment:/certsrv",), host=TARGET)
    c = ObjectRef("endpoint", "", ("app:web_enrollment:/certsrv",), host="CA1.PKI.EXAMPLE.")
    assert not same_object(a, b)
    assert same_object(b, c)
