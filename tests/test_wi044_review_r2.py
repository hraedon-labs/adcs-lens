"""WI-044 review round 2: every reviewer probe, replayed as a regression test.

Sources (archived with the review): Sol's r2_host_probes.py and
r2_esc5_probes.py, and DeepSeek's probes_r2.py, probes2.py and cli_probe.py.

* Sol r2 blocking 1 (DS N2) - the endpoint absence rule compared a short host
  name only against the newer export's host names; a rival FQDN only the older
  export knew was forgotten and the finding resolved.
* Sol r2 blocking 2 (DS N5) - host names were Unicode case-folded, merging
  distinct names ("straße" / "strasse"). Host names are now ASCII DNS names;
  anything else matches nothing.
* DS N1 / Sol NB1 - the manifest's host_fqdn is believed only when it names
  the collector host, and every endpoint row must carry it.
* DS N3 - the ESC5 exemption checks the object kind at the detector too.
* DS N4 - two enrollment services on one host are one CA host (the simulated
  collector run is in tests/test_collector_simulated.py).
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
from adcs_lens.detection import coverage_gaps, detect_esc5, evaluate
from adcs_lens.diff import DriftReport, diff_findings
from adcs_lens.ingest import IngestError, ingest
from adcs_lens.model import (
    AceEntry,
    AceType,
    AclKind,
    CaKind,
    CertAuthority,
    EndpointKind,
    EnrollmentEndpoint,
    EpaPolicy,
    Estate,
    Manifest,
    PkiObjectAcl,
)
from adcs_lens.normalize import host_key, same_host
from tests.conftest import NOW
from tests.fixtures.build_fixture import build_export

FULL = frozenset({"ca-config", "web-endpoints"})
CA1 = "ca1.pki.example"
CA01 = "labca01.lab.example.com"
HOST_SID = "S-1-5-21-1111111111-2222222222-3333333333-1105"


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


def _ep(host: str, name: str = "/CertSrv", *, fixed: bool = False) -> EnrollmentEndpoint:
    return EnrollmentEndpoint(
        kind=EndpointKind.WEB_ENROLLMENT,
        name=name,
        transports=frozenset({"https"} if fixed else {"http"}),
        ssl_required=fixed,
        windows_auth=True,
        auth_providers=frozenset({"ntlm"}),
        epa=EpaPolicy.REQUIRE if fixed else EpaPolicy.NONE,
        host=host,
    )


def _estate(
    cas: tuple[CertAuthority, ...],
    endpoints: tuple[EnrollmentEndpoint, ...] = (),
    *,
    version: str = "0.11.0",
    host: str = "",
    host_fqdn: str = "",
    complete: frozenset[str] = FULL,
    acls: tuple[PkiObjectAcl, ...] = (),
) -> Estate:
    return Estate(
        cas=cas,
        templates=(),
        acls=acls,
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
            enumeration_complete=complete,
            host_fqdn=host_fqdn,
        ),
    )


def _drift(old: Estate, new: Estate) -> DriftReport:
    return diff_findings(
        evaluate(old, now=NOW), evaluate(new, now=NOW), coverage=coverage_gaps(new)
    )


def _esc8(findings: Any) -> list[str]:
    return [f.subject for f in findings if f.check == "ESC8"]


def _exit(drift: DriftReport) -> int:
    return 1 if drift.regressions else 3 if drift.coverage_lost else 0


ONE = (_ca("CA1", CA1),)
V11 = _estate(ONE, (_ep(CA1),), host="CA1", host_fqdn=CA1)


# --- Sol r2 blocking 1: cross-export short-name ambiguity ---------------------

_RIVALS = (_ca("CA-A", "ca1.pki.example"), _ca("CA-B", "ca1.admin.example"))
_AMBIGUOUS = {
    # The old endpoint is on short host ca1; only the old export knows both FQDNs.
    "short-ambiguous-only-old-knows-rival": (
        _estate(_RIVALS, (_ep("ca1"),), version="0.10.0", host="ca1"),
        _estate(ONE, host="ca1", host_fqdn=CA1),
    ),
    # The new export is short-named; only the old export knows both FQDNs.
    "short-ambiguous-only-old-knows-rival-reverse": (
        _estate(_RIVALS, (_ep(CA1),), host="ca1", host_fqdn=CA1),
        _estate(ONE, version="0.10.0", host="ca1"),
    ),
    "short-ambiguous-new-knows-rival": (
        _estate(ONE, (_ep("CA1"),), version="0.10.0", host="CA1"),
        _estate(_RIVALS, host="ca1", host_fqdn=CA1),
    ),
    # Only the rival's DNS name changes; every CA object stays (no other drift).
    "short-ambiguity-isolated-false-clean": (
        _estate(
            (_ca("CA1", CA1), _ca("ROOT", "ca1.admin.example", es=False)),
            (_ep("ca1"),),
            version="0.10.0",
            host="ca1",
        ),
        _estate(
            (_ca("CA1", CA1), _ca("ROOT", "root.admin.example", es=False)),
            host="ca1",
            host_fqdn=CA1,
        ),
    ),
    # DS probes_r2: old export names two FQDNs, the new one is short-named.
    "ds-old-two-fqdns-new-one-short": (
        _estate(_RIVALS, (_ep(CA1),), host="ca1", host_fqdn=CA1),
        _estate(ONE, version="0.10.0", host="ca1"),
    ),
}


@pytest.mark.parametrize("name", sorted(_AMBIGUOUS))
def test_sol_r2_b1_a_short_name_either_export_knows_to_be_ambiguous_never_resolves(
    name: str,
) -> None:
    old, new = _AMBIGUOUS[name]
    drift = _drift(old, new)
    assert _esc8(drift.resolved) == [], name
    assert _esc8(i.finding for i in drift.indeterminate) == ["/CertSrv"], name
    assert _exit(drift) != 0, name


# --- Sol r2 blocking 2: host names are ASCII DNS names ------------------------


def test_sol_r2_b2_host_names_compare_as_ascii_dns_names() -> None:
    assert same_host("CA1.PKI.EXAMPLE", "ca1.pki.example")  # A-Z only, case-insensitively
    assert same_host("ca1.pki.example.", "ca1.pki.example")  # one trailing root dot
    assert not same_host("ca1.pki.example..", "ca1.pki.example")  # repeated trailing dot
    assert not same_host("ca1..pki.example", "ca1..pki.example")  # empty label
    assert not same_host("", "")
    # Non-ASCII names match nothing - not a look-alike, not their own A-label,
    # not even themselves - so nothing resolves on them.
    assert not same_host("straße.example", "strasse.example")
    assert not same_host("straße.example", "xn--strae-oqa.example")
    assert not same_host("straße.example", "straße.example")
    assert not same_host("ca1.pki.example", "CA1.PKİ.EXAMPLE")  # dotted capital I
    assert host_key("straße.example") == "" and host_key("STRASSE.example") == "strasse.example"
    assert host_key("xn--strae-oqa.example") == "xn--strae-oqa.example"  # A-labels are ASCII
    assert host_key("a" * 63 + ".example") and not host_key("a" * 64 + ".example")
    assert host_key("ca_1.example") and not host_key("ca 1.example") and not host_key("ca!1.x")


@pytest.mark.parametrize(
    ("name", "old_host", "new_host"),
    [
        ("distinct-idn-casefold-collision", "straße.example", "strasse.example"),
        ("same-idn-u-label-to-punycode", "straße.example", "xn--strae-oqa.example"),
        ("ds-idn-to-punycode", "bücher.example", "xn--bcher-kva.example"),
    ],
)
def test_sol_r2_b2_nothing_resolves_on_a_non_ascii_host(
    name: str, old_host: str, new_host: str
) -> None:
    old = _estate(
        (_ca("CA1", old_host),), (_ep(old_host),), host=old_host.split(".")[0], host_fqdn=old_host
    )
    new = _estate((_ca("CA1", new_host),), host=new_host.split(".")[0], host_fqdn=new_host)
    assert _esc8(_drift(old, new).resolved) == [], name


def test_sol_r2_nb3_an_endpoint_without_a_host_never_resolves() -> None:
    """A legacy or hand-built endpoint with no host names no machine, so no
    export can have read it (it used to resolve from any complete host)."""
    old = _estate(ONE, (_ep(""),), version="0.10.0", host="")
    drift = _drift(old, _estate(ONE, host="ca1", host_fqdn=CA1))
    assert _esc8(drift.resolved) == []
    assert _esc8(i.finding for i in drift.indeterminate) == ["/CertSrv"]


def test_sol_r2_positive_cases_still_resolve() -> None:
    assert _esc8(_drift(V11, _estate(ONE, host="ca1", host_fqdn=CA1)).resolved) == ["/CertSrv"]
    fixed = _estate(ONE, (_ep(CA1, fixed=True),), host="ca1", host_fqdn=CA1)
    assert _esc8(_drift(V11, fixed).resolved) == ["/CertSrv"]
    legacy = _estate(ONE, (_ep("CA1"),), version="0.10.0", host="CA1")
    assert _esc8(_drift(legacy, _estate(ONE, host="ca1", host_fqdn=CA1)).resolved) == ["/CertSrv"]
    upper = _estate((_ca("CA1", "CA1.PKI.EXAMPLE."),), host="CA1", host_fqdn="CA1.PKI.EXAMPLE.")
    assert _esc8(_drift(V11, upper).resolved) == ["/CertSrv"]


def test_sol_r2_nb4_ca_host_renames_stay_conservative() -> None:
    """Endpoints have no immutable identity: a renamed CA host is another host,
    so an absent endpoint is withheld and a present one is NEW (noisy, never a
    false fix)."""
    renamed = "ca1-new.pki.example"
    absent = _drift(V11, _estate((_ca("CA1", renamed),), host="ca1-new", host_fqdn=renamed))
    assert _esc8(absent.resolved) == [] and _exit(absent) == 3
    present = _drift(
        V11, _estate((_ca("CA1", renamed),), (_ep(renamed),), host="ca1-new", host_fqdn=renamed)
    )
    assert _esc8(present.new) == ["/CertSrv"] and _esc8(present.resolved) == []


# --- DS N1 / Sol NB1: host attribution must be self-consistent ----------------


def test_ds_n1_an_fqdn_that_names_another_host_is_not_believed_hand_built() -> None:
    """DS probes_r2 forged-host_fqdn: the manifest says host labweb01 but
    host_fqdn labca01's FQDN; the export is attributed to labweb01."""
    old = _estate((_ca("CA", CA01),), (_ep(CA01),), host="labca01", host_fqdn=CA01)
    forged = _estate((_ca("CA", CA01),), host="labweb01", host_fqdn=CA01)
    assert _esc8(_drift(old, forged).resolved) == []


def _rw(path: Path, mutate: Any) -> None:
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    mutate(data)
    path.write_text(json.dumps(data), encoding="utf-8")


def _as_011(path: Path, *, host: str = "LABCA01", host_fqdn: str = CA01) -> Path:
    _rw(
        path / "collector-manifest.json",
        lambda m: m.update(collector_version="0.11.0", host=host, host_fqdn=host_fqdn),
    )
    _rw(path / "web-endpoints.json", lambda rows: [r.update(host=host_fqdn) for r in rows])
    _rw(
        path / "pki-acls.json",
        lambda rows: [r.update(ca_host_sid="", enrollment_service=False) for r in rows],
    )
    return path


def test_ds_n1_ingest_attributes_an_unbelieved_fqdn_to_the_short_host(tmp_path: Path) -> None:
    """Sol NB1 ingest-inconsistent-manifest: host TOTALLY-OTHER, host_fqdn
    labca01's FQDN. Also the honest case of a reverse-DNS lookup that answered
    for another machine. The FQDN is dropped, the endpoints are attributed to
    the short host, and the endpoint list is not complete (not a CA host)."""
    export = _as_011(build_export(tmp_path / "x", with_certs=False, now=NOW), host="TOTALLY-OTHER")
    estate = ingest(export)
    assert estate.manifest.host_fqdn == ""
    assert {e.host for e in estate.endpoints} == {"TOTALLY-OTHER"}
    assert "web-endpoints" not in estate.manifest.enumeration_complete


def test_ds_n1_ingest_refuses_an_endpoint_row_on_another_host(tmp_path: Path) -> None:
    """Sol NB1 ingest-inconsistent-endpoint: the collector writes the rows'
    host and host_fqdn from one value, so a row naming another host was
    altered after collection (exit 4)."""
    export = _as_011(build_export(tmp_path / "x", with_certs=False, now=NOW))
    _rw(export / "web-endpoints.json", lambda rows: rows[0].update(host="other.example"))
    with pytest.raises(IngestError, match="altered after collection"):
        ingest(export)


@pytest.mark.parametrize(
    "fqdn",
    ["   ", "straße.example", "labca01..lab.example.com", "labca01.lab.example.com..", "a b"],
)
def test_ingest_refuses_a_host_fqdn_that_is_not_an_ascii_host_name(
    tmp_path: Path, fqdn: str
) -> None:
    export = _as_011(build_export(tmp_path / "x", with_certs=False, now=NOW), host_fqdn=fqdn)
    with pytest.raises(IngestError, match="host_fqdn"):
        ingest(export)


def _cli_diff(old: Path, new: Path) -> tuple[int, dict[str, Any]]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        rc = main(["diff", str(old), str(new), "--exit-code", "--json"])
    return rc, json.loads(out.getvalue())


def test_ds_cli_probe_forged_host_fqdn_does_not_resolve(tmp_path: Path) -> None:
    """DS cli_probe.py: manifest host labweb01, host_fqdn labca01's FQDN, no
    endpoint rows, marker complete. It resolved labca01's ESC8 (exit 0)."""
    legacy = build_export(tmp_path / "legacy", with_certs=False, now=NOW)
    forged = tmp_path / "forged"
    shutil.copytree(legacy, forged)

    def manifest(m: dict[str, Any]) -> None:
        m.update(collector_version="0.11.0", host="labweb01", host_fqdn=CA01)
        m["enumeration"]["web-endpoints"].update(count=0, complete=True)

    _rw(forged / "collector-manifest.json", manifest)
    _rw(forged / "web-endpoints.json", lambda rows: rows.clear())
    _rw(
        forged / "pki-acls.json",
        lambda rows: [r.update(ca_host_sid="", enrollment_service=False) for r in rows],
    )
    rc, env = _cli_diff(legacy, forged)
    assert [f["subject"] for f in env["resolved"] if f["check"] == "ESC8"] == []
    assert rc == 3


# --- DS N3: the detector checks the kind too ----------------------------------


@pytest.mark.parametrize("kind", [AclKind.NTAUTH, AclKind.PKS_CONTAINER, AclKind.AIA, AclKind.CDP])
def test_ds_n3_a_flagged_row_that_is_not_a_ca_object_exempts_nothing(kind: AclKind) -> None:
    """DS probes_r2 ntauth-flag-true (hand-built; ingest refuses it)."""
    obj = PkiObjectAcl(
        object_dn="CN=NTAuthCertificates,DC=x",
        kind=kind,
        security=(AceEntry(HOST_SID, "", ("GenericAll",), AceType.ALLOW),),
        owner_sid=HOST_SID,
        object_guid="ab" * 16,
        ca_host_sid=HOST_SID,
        enrollment_service=True,
    )
    variants = sorted(f.variant for f in detect_esc5(_estate((), acls=(obj,))) if f.check == "ESC5")
    assert variants == ["dacl", "owner"]
