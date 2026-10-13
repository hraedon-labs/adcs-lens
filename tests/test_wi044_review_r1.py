"""WI-044 review round 1: every reviewer probe, replayed as a regression test.

Sources (archived with the review): Sol's core-probes.py and
ca-host-lookup-probes.ps1 (the lookup probe is in the Pester suite,
tests/collector/Collector.Tests.ps1), and DeepSeek's probe_endpoint_alias.py,
probe_esc8_real_fixture.py, probe_esc8.py, probe_esc8_ingest.py and
probe_esc5b.py. The ESC5 provenance probes are in tests/test_wi044.py.

* DS blocking 1 - an independent ``host:`` alias made every endpoint of one
  host ambiguous: identical exports reported a NEW ESC8 and a real fix never
  resolved. The host is now part of the endpoint's identity (ObjectRef.host).
* Sol blocking 1 - hosts were compared by first DNS label.
* Sol blocking 2 - ESC8 absence was judged estate-wide (a dedicated web
  server's endpoint resolved by an export from the CA host) and from an
  incomplete CA list.
"""

from __future__ import annotations

import contextlib
import io
import json
import shutil
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from adcs_lens.cli import main
from adcs_lens.detection import evaluate
from adcs_lens.diff import DriftReport, diff_findings
from adcs_lens.ingest import ingest
from adcs_lens.model import (
    CaKind,
    CertAuthority,
    EndpointKind,
    EnrollmentEndpoint,
    EpaPolicy,
    Estate,
    Manifest,
)
from tests.conftest import NOW
from tests.fixtures.build_fixture import build_export

FULL = frozenset({"ca-config", "web-endpoints"})


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


def _ep(
    host: str, name: str = "/CertSrv", kind: EndpointKind = EndpointKind.WEB_ENROLLMENT
) -> EnrollmentEndpoint:
    return EnrollmentEndpoint(
        kind=kind,
        name=name,
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
    host: str = "",
    host_fqdn: str = "",
    complete: frozenset[str] = FULL,
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
            enumeration_complete=complete,
            host_fqdn=host_fqdn,
        ),
    )


def _drift(old: Estate, new: Estate) -> DriftReport:
    return diff_findings(evaluate(old, now=NOW), evaluate(new, now=NOW))


def _checks(findings: Any) -> list[tuple[str, str]]:
    return sorted((f.check, f.subject) for f in findings if f.check == "ESC8")


CA01 = "labca01.lab.example.com"
ONE_CA = (_ca("CA1", CA01),)


# --- DS blocking 1: endpoints of one host -------------------------------------


def test_ds_b1_identical_same_host_exports_are_unchanged() -> None:
    """probe_endpoint_alias.py / probe_esc8_unchanged.py."""
    eps = (_ep(CA01), _ep(CA01, "/LAB_CES_Kerberos", EndpointKind.CES))
    old = _estate(ONE_CA, eps, host="labca01", host_fqdn=CA01)
    drift = _drift(old, old)
    assert drift.new == () and drift.resolved == () and drift.indeterminate == ()
    assert drift.changed == () and not drift.coverage_lost


def test_ds_b1_removing_one_same_host_endpoint_resolves_exactly_its_finding() -> None:
    eps = (_ep(CA01), _ep(CA01, "/LAB_CES_Kerberos", EndpointKind.CES))
    old = _estate(ONE_CA, eps, host="labca01", host_fqdn=CA01)
    only_ces = _estate(ONE_CA, eps[1:], host="labca01", host_fqdn=CA01)
    drift = _drift(old, only_ces)
    assert _checks(drift.resolved) == [("ESC8", "/CertSrv")]
    assert drift.new == () and drift.indeterminate == () and drift.changed == ()
    none_left = _drift(old, _estate(ONE_CA, (), host="labca01", host_fqdn=CA01))
    assert _checks(none_left.resolved) == [("ESC8", "/CertSrv"), ("ESC8", "/LAB_CES_Kerberos")]


def test_ds_b1_host_less_and_host_bearing_endpoints_pair() -> None:
    """A collector 0.10.0 endpoint names the short host (ingest takes it from
    the manifest); it is the same object as the 0.11.0 endpoint on that host's
    FQDN, so an upgrade is unchanged and a later fix resolves."""
    legacy = _estate(ONE_CA, (_ep("LABCA01"),), version="0.10.0", host="LABCA01")
    current = _estate(ONE_CA, (_ep(CA01),), host="labca01", host_fqdn=CA01)
    drift = _drift(legacy, current)
    assert drift.new == () and drift.indeterminate == () and drift.resolved == ()
    # Paired: at most the source text changed (it now names the host's FQDN).
    assert [(d.new.check, d.worsened, d.content_changed) for d in drift.changed] == [
        ("ESC8", False, True)
    ]
    fixed = _estate(ONE_CA, (), host="labca01", host_fqdn=CA01)
    assert _checks(_drift(legacy, fixed).resolved) == [("ESC8", "/CertSrv")]


def test_ds_b1_a_short_name_that_fits_two_fqdns_pairs_with_neither() -> None:
    cas = (_ca("CA1", "ca1.pki.example"), _ca("CA2", "ca1.admin.example"))
    legacy = _estate(cas, (_ep("ca1"),), version="0.10.0", host="ca1")
    current = _estate(cas, (_ep("ca1.pki.example"),), host="ca1", host_fqdn="ca1.pki.example")
    drift = _drift(legacy, current)
    assert _checks(drift.new) == [("ESC8", "/CertSrv")]
    assert drift.resolved == ()


def _rw(path: Path, mutate: Any) -> None:
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    mutate(data)
    path.write_text(json.dumps(data), encoding="utf-8")


def _fixture_0_11_0(base: Path) -> Path:
    """The synthetic fixture as collector 0.11.0 writes it: both endpoints on
    labca01, the CES one made NTLM-relayable so the host has two findings."""
    export = build_export(base, with_certs=False, now=NOW)

    def manifest(m: dict[str, Any]) -> None:
        m.update(collector_version="0.11.0", host_fqdn=CA01)

    def endpoints(rows: list[dict[str, Any]]) -> None:
        for row in rows:
            row["host"] = CA01
            if row["kind"] == "ces":
                row.update(auth_providers=["NTLM"], epa="none")

    def acls(rows: list[dict[str, Any]]) -> None:
        for row in rows:
            row.update(ca_host_sid="", enrollment_service=False)

    _rw(export / "collector-manifest.json", manifest)
    _rw(export / "web-endpoints.json", endpoints)
    _rw(export / "pki-acls.json", acls)
    return export


def _cli_diff(old: Path, new: Path) -> tuple[int, dict[str, Any]]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = main(["diff", str(old), str(new), "--exit-code", "--json"])
    return rc, json.loads(out.getvalue())


def _drop_endpoint(export: Path, name: str) -> None:
    _rw(
        export / "web-endpoints.json",
        lambda rows: rows.__setitem__(slice(None), [r for r in rows if r["name"] != name]),
    )
    _rw(
        export / "collector-manifest.json",
        lambda m: m["enumeration"]["web-endpoints"].__setitem__(
            "count", m["enumeration"]["web-endpoints"]["count"] - 1
        ),
    )


def test_ds_b1_real_fixture_identical_exports_exit_0(tmp_path: Path) -> None:
    """probe_esc8_real_fixture.py: two identical 0.11.0 exports with /CertSrv
    and a CES endpoint on one host gave a NEW ESC8 and exit 1."""
    a = _fixture_0_11_0(tmp_path / "a")
    b = tmp_path / "b"
    shutil.copytree(a, b)
    rc, env = _cli_diff(a, b)
    assert env["new"] == [] and env["indeterminate"] == [] and env["resolved"] == []
    assert rc == 0
    _drop_endpoint(b, "/LAB_CES_Kerberos")
    rc, env = _cli_diff(a, b)
    assert [(f["check"], f["subject"]) for f in env["resolved"]] == [("ESC8", "/LAB_CES_Kerberos")]
    assert env["new"] == [] and env["indeterminate"] == []


def test_ds_b1_real_fixture_upgrade_from_0_10_0_is_unchanged(tmp_path: Path) -> None:
    legacy = build_export(tmp_path / "legacy", with_certs=False, now=NOW)
    current = tmp_path / "current"
    shutil.copytree(legacy, current)
    _rw(
        current / "collector-manifest.json",
        lambda m: m.update(collector_version="0.11.0", host_fqdn=CA01),
    )
    _rw(current / "web-endpoints.json", lambda rows: [r.__setitem__("host", CA01) for r in rows])
    _rw(
        current / "pki-acls.json",
        lambda rows: [r.update(ca_host_sid="", enrollment_service=False) for r in rows],
    )
    rc, env = _cli_diff(legacy, current)
    assert env["new"] == [] and env["indeterminate"] == [] and env["resolved"] == []
    assert rc == 0
    _drop_endpoint(current, "/CertSrv")
    rc, env = _cli_diff(legacy, current)
    assert [(f["check"], f["subject"]) for f in env["resolved"]] == [("ESC8", "/CertSrv")]


# --- Sol blocking 1 and 2: host-scoped evidence (core-probes.py) ---------------


def test_sol_b1_cross_domain_first_label_never_resolves() -> None:
    """cross-domain-0.10 / cross-domain-0.11-forged-marker: an export from
    ca1.admin.example (complete, empty) resolved ca1.pki.example's ESC8."""
    cas = (_ca("CA", "ca1.pki.example"),)
    old = _estate(cas, (_ep("ca1.pki.example"),), version="0.10.0", host="ca1.pki.example")
    for version in ("0.10.0", "0.11.0"):
        new = _estate(
            cas, (), version=version, host="ca1.admin.example", host_fqdn="ca1.admin.example"
        )
        drift = _drift(old, new)
        assert drift.resolved == (), version
        assert _checks(i.finding for i in drift.indeterminate) == [("ESC8", "/CertSrv")]


def test_sol_b2_an_incomplete_ca_list_never_resolves() -> None:
    """incomplete-ca-list-0.10: the CA list that scopes the endpoint list must
    itself be complete (ESC8 declares ca-config)."""
    cas = (_ca("CA", "ca1.pki.example"),)
    old = _estate(cas, (_ep("ca1.pki.example"),), version="0.10.0", host="ca1.pki.example")
    new = _estate(
        cas, (), version="0.10.0", host="ca1.pki.example", complete=frozenset({"web-endpoints"})
    )
    drift = _drift(old, new)
    assert drift.resolved == ()
    assert "ESC8" in {i.finding.check for i in drift.indeterminate}


def test_sol_b2_a_dedicated_web_servers_endpoint_is_not_resolved_from_the_ca_host() -> None:
    """dedicated-web-server-absence: the CA host's export never read the
    dedicated server, so the server's endpoint is neither present nor absent."""
    cas = (_ca("CA", "ca1.pki.example"),)
    old = _estate(
        cas,
        (_ep("web1.pki.example"),),
        host="web1",
        host_fqdn="web1.pki.example",
        complete=frozenset({"ca-config"}),
    )
    new = _estate(cas, (), host="ca1", host_fqdn="ca1.pki.example")
    drift = _drift(old, new)
    assert drift.resolved == ()
    [withheld] = [i for i in drift.indeterminate if i.finding.check == "ESC8"]
    assert "did not read IIS on web1.pki.example" in withheld.reason


def test_sol_b2_a_re_collect_on_the_ca_host_after_a_fix_still_resolves() -> None:
    cas = (_ca("CA", "ca1.pki.example"),)
    old = _estate(cas, (_ep("ca1.pki.example"),), host="ca1", host_fqdn="ca1.pki.example")
    new = _estate(cas, (), host="ca1", host_fqdn="ca1.pki.example")
    assert _checks(_drift(old, new).resolved) == [("ESC8", "/CertSrv")]
    # ... and with the endpoint still present but fixed (a usable clean verdict).
    fixed = replace(
        _ep("ca1.pki.example"),
        transports=frozenset({"https"}),
        ssl_required=True,
        epa=EpaPolicy.REQUIRE,
    )
    new_fixed = _estate(cas, (fixed,), host="ca1", host_fqdn="ca1.pki.example")
    assert _checks(_drift(old, new_fixed).resolved) == [("ESC8", "/CertSrv")]


# --- DS probe_esc8.py: the scenario table (hand-built estates) ----------------

_VULN = _estate(ONE_CA, (_ep(CA01),), version="0.10.0", host=CA01)
_SCENARIOS: dict[str, tuple[Estate, bool]] = {
    "A: 0.10.0 member, empty": (_estate(ONE_CA, version="0.10.0", host="LABWEB01"), False),
    "B: 0.10.0 CA host, empty": (_estate(ONE_CA, version="0.10.0", host="LABCA01"), True),
    "C: 0.11.0 CA host, empty": (_estate(ONE_CA, host="labca01", host_fqdn=CA01), True),
    "D: 0.11.0 no host, empty": (_estate(ONE_CA), False),
    "E: dedicated CES host, empty": (
        _estate(ONE_CA, host="ces01", host_fqdn="ces01.lab.example.com"),
        False,
    ),
    # The estate claims a complete endpoint list; the detector does not believe
    # it with a second CA host (DS N4: enforced at the detector, not only ingest).
    "F: two CAs, empty": (
        _estate((*ONE_CA, _ca("CA2", "labca02.lab.example.com")), host="labca01", host_fqdn=CA01),
        False,
    ),
    "G: standalone + enterprise on one host, empty": (
        _estate((*ONE_CA, _ca("SA", CA01, es=False)), host="labca01", host_fqdn=CA01),
        True,
    ),
    "H: /CertSrv now on another host": (
        _estate(ONE_CA, (_ep("labca02.lab.example.com"),), host="labca01", host_fqdn=CA01),
        False,
    ),
}


@pytest.mark.parametrize("name", sorted(_SCENARIOS))
def test_ds_probe_esc8_scenarios(name: str) -> None:
    new, resolves = _SCENARIOS[name]
    resolved = [f.check for f in _drift(_VULN, new).resolved]
    assert resolved == (["ESC8"] if resolves else []), name


# --- DS probe_esc8_ingest.py: the same through ingest -------------------------


def _member_export(
    base: Path, *, version: str, host: str, host_fqdn: str = "", ca_dns: str = ""
) -> Path:
    export = build_export(base, with_certs=False, now=NOW)
    _rw(export / "web-endpoints.json", lambda rows: rows.clear())

    def manifest(m: dict[str, Any]) -> None:
        m.update(collector_version=version, host=host)
        m["enumeration"]["web-endpoints"]["count"] = 0
        if host_fqdn:
            m["host_fqdn"] = host_fqdn

    _rw(export / "collector-manifest.json", manifest)
    if ca_dns:
        _rw(
            export / "ca-config.json",
            lambda rows: [r.__setitem__("dns", ca_dns) for r in rows if r.get("dns")],
        )
    if version == "0.11.0":
        _rw(
            export / "pki-acls.json",
            lambda rows: [r.update(ca_host_sid="", enrollment_service=False) for r in rows],
        )
    return export


@pytest.mark.parametrize(
    ("version", "host", "host_fqdn", "ca_dns", "resolves"),
    [
        ("0.10.0", "LABWEB01", "", "", False),  # A: a member
        ("0.10.0", "LABCA01", "", "", True),  # B: the CA host (correct fix)
        ("0.10.0", "LABCA01.LAB.EXAMPLE.COM", "", "", True),  # C: FQDN, other case
        ("0.10.0", "LABCA01", "", "labca02.lab.example.com", False),  # D: the CA moved
        ("0.11.0", "LABWEB01", "labweb01.lab.example.com", "", False),  # E: a member
        ("0.11.0", "LABCA01", CA01, "", True),  # F: the CA host (correct fix)
        ("0.11.0", "LABCA01", "labca01.other.example.com", "", False),  # Sol B1
    ],
)
def test_ds_probe_esc8_through_ingest(
    tmp_path: Path, version: str, host: str, host_fqdn: str, ca_dns: str, resolves: bool
) -> None:
    older = build_export(tmp_path / "older", with_certs=False, now=NOW)
    newer = _member_export(
        tmp_path / "newer", version=version, host=host, host_fqdn=host_fqdn, ca_dns=ca_dns
    )
    drift = diff_findings(evaluate(ingest(older), now=NOW), evaluate(ingest(newer), now=NOW))
    assert ("ESC8" in {f.check for f in drift.resolved}) is resolves
