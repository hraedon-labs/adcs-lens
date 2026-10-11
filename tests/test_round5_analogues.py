"""Round-4 reviewer probes, on a current (collector 0.10.0) export.

The companion of tests/test_reviewer_probes_r4.py: each replay there is a
0.9.0 / 0.8.0 export, which no longer resolves anything because such a
collector does not prove its reads. Here the same situations are written the
way an honest collector >= 0.10.0 writes them, so the mechanism that closes each
probe is exercised directly, next to a control that still resolves:

* a partial container is marked ``complete: false`` (Sol B1, DS P3b);
* a failed certutil read is null, not an empty list (DS P2);
* inputs are strictly typed and contradictory nulls rejected (Sol round-3 B2);
* a dependency container (ESC14's DCs, ESC15's CAs) must be complete (Sol
  NEW BLOCKING 1);
* a failed DC registry read withholds ESC10;
* a legacy export fails closed (DS P1).

A hand-forged 0.10.0 export that claims a completeness the collector never
proved is out of scope for diff: it is indistinguishable from the genuine
deletion controls below by construction.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

import pytest

from adcs_lens.detection import evaluate
from adcs_lens.diff import diff_findings
from adcs_lens.ingest import IngestError, ingest
from tests.conftest import NOW
from tests.fixtures.build_fixture import ISSUING_CA, inject_enumeration
from tests.test_diff_coverage import build_full_export, enrich

pytest.importorskip("cryptography")
pytestmark = pytest.mark.certs

_LABESC1 = frozenset({"ESC1", "ESC13", "WEAK_TEMPLATE_KEY_SIZE", "ORPHANED_TEMPLATE"})


@pytest.fixture(scope="module")
def current(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return build_full_export(tmp_path_factory.mktemp("r4") / "export")


def _copy(current: Path, tmp_path: Path) -> Path:
    newer = tmp_path / "newer"
    shutil.copytree(current, newer)
    return newer


def _rw(path: Path, fn: Any) -> None:
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    out = fn(data)
    path.write_text(json.dumps(data if out is None else out), encoding="utf-8")


def _marker(base: Path, container: str, *, complete: bool) -> None:
    def m(d: dict[str, Any]) -> None:
        d["enumeration"][container]["complete"] = complete

    _rw(base / "collector-manifest.json", m)


def _diff(old: Path, new: Path) -> tuple[set[str], set[str]]:
    report = diff_findings(
        evaluate(enrich(ingest(old)), now=NOW), evaluate(enrich(ingest(new)), now=NOW)
    )
    resolved = {f.check for f in report.resolved if f.severity.value != "info"}
    return resolved, {i.finding.check for i in report.indeterminate}


def _drop(base: Path, file: str, key: str, value: str) -> None:
    _rw(base / file, lambda rows: [r for r in rows if r[key] != value])
    if file == "ca-config.json":
        # A CA that is gone has no publication entry and no CA\Security entry
        # either: the collector writes those per CA row.
        for joined in ("enrollment-services.json", "ca-security.json"):
            _rw(base / joined, lambda d: {k: v for k, v in d.items() if k != value})
    inject_enumeration(base)  # the collector counts the rows it wrote


def test_analogue_partial_container_is_withheld_and_a_genuine_deletion_resolves(
    current: Path, tmp_path: Path
) -> None:
    """Sol B1 / DS P3b on 0.10.0: the collector marks a search it could not prove
    complete as complete=false. The control (marker proven complete) resolves —
    and is, by design, indistinguishable from a forged marker (out of scope)."""
    newer = _copy(current, tmp_path)
    _drop(newer, "templates.json", "name", "LabEsc1")
    resolved, _ = _diff(current, newer)
    assert _LABESC1 <= resolved  # control: a proven-complete container
    _marker(newer, "templates", complete=False)
    resolved, withheld = _diff(current, newer)
    assert not resolved & _LABESC1
    assert _LABESC1 <= withheld


@pytest.mark.parametrize("field,check", [("edit_flags", "ESC6"), ("disabled_extensions", "ESC16")])
def test_analogue_a_failed_certutil_read_is_null_and_withheld(
    current: Path, tmp_path: Path, field: str, check: str
) -> None:
    """DS P2 on 0.10.0: a failed read is written as null, not as an empty list."""
    newer = _copy(current, tmp_path)

    def set_field(value: Any) -> Any:
        def m(cas: list[dict[str, Any]]) -> None:
            for c in cas:
                if c["name"] == ISSUING_CA:
                    c[field] = value

        return m

    _rw(newer / "ca-config.json", set_field([]))
    resolved, _ = _diff(current, newer)
    assert check in resolved  # control: a proven read that is empty is a fix
    _rw(newer / "ca-config.json", set_field(None))
    resolved, withheld = _diff(current, newer)
    assert check not in resolved and check in withheld


@pytest.mark.parametrize(
    "file,key,value,mutate,error",
    [
        ("ca-config.json", "name", ISSUING_CA, ("edit_flags", ""), "must be an array of strings"),
        (
            "web-endpoints.json",
            "name",
            "/CertSrv",
            ("auth_providers", "negotiate"),
            "must be an array of strings",
        ),
        (
            "templates.json",
            "name",
            "LabEsc1",
            ("security", None),
            "acl_obtained=True contradicts security null",
        ),
        (
            "principal-mappings.json",
            "dn",
            "CN=Service Account,OU=Service Accounts,DC=lab,DC=example,DC=com",
            ("mappings", None),
            "mappings must not be null",
        ),
        (
            "dc-config.json",
            "name",
            "LAB-DC02",
            ("schannel_mapping_methods", "upn"),
            "must be an array of strings",
        ),
    ],
)
def test_analogue_inputs_are_strictly_typed(
    current: Path,
    tmp_path: Path,
    file: str,
    key: str,
    value: str,
    mutate: tuple[str, Any],
    error: str,
) -> None:
    """Sol round-3 B2 on 0.10.0: wrong types and contradictory nulls are rejected."""
    newer = _copy(current, tmp_path)

    def m(rows: list[dict[str, Any]]) -> None:
        for r in rows:
            if r[key] == value:
                r[mutate[0]] = mutate[1]

    _rw(newer / file, m)
    with pytest.raises(IngestError, match=error):
        ingest(newer)


@pytest.mark.parametrize(
    "file,key,value,container,check",
    [
        ("dc-config.json", "name", "LAB-DC01", "dc-config", "ESC14"),
        ("ca-config.json", "name", ISSUING_CA, "ca-config", "ESC15"),
    ],
)
def test_analogue_a_dependency_container_must_be_complete(
    current: Path,
    tmp_path: Path,
    file: str,
    key: str,
    value: str,
    container: str,
    check: str,
) -> None:
    """Sol NEW BLOCKING 1 on 0.10.0: ESC14 reads every DC, ESC15 every CA.

    The only non-strict DC / unpatched issuing CA is genuinely gone and the
    findings vanish; with the dependency container proven complete that is a fix
    (control), with it incomplete the verdict cannot be trusted.
    """
    newer = _copy(current, tmp_path)
    _drop(newer, file, key, value)
    _marker(newer, container, complete=False)
    resolved, withheld = _diff(current, newer)
    assert check not in resolved and check in withheld
    _marker(newer, container, complete=True)
    resolved, _ = _diff(current, newer)
    if check == "ESC14":
        # every remaining DC is strict: the weak mapping is mitigated
        assert check in resolved
    else:
        # the remaining issuing CA's patch state is unknown: ESC15 stays (MEDIUM)
        assert check not in resolved


def test_analogue_dc_methods_null_withholds_esc10(current: Path, tmp_path: Path) -> None:
    newer = _copy(current, tmp_path)

    def m(dcs: list[dict[str, Any]]) -> None:
        for dc in dcs:
            if dc["name"] == "LAB-DC01":
                dc["strong_certificate_binding_enforcement"] = "strict"
                dc["schannel_mapping_methods"] = None  # the WMI read failed

    _rw(newer / "dc-config.json", m)
    resolved, withheld = _diff(current, newer)
    assert "ESC10" not in resolved and "ESC10" in withheld


def test_analogue_legacy_exports_fail_closed(current: Path, tmp_path: Path) -> None:
    """DS P1: a genuine deletion in an export that does not prove its reads."""
    newer = _copy(current, tmp_path)
    _drop(newer, "templates.json", "name", "LabEsc1")
    _rw(newer / "collector-manifest.json", lambda m: m.__setitem__("collector_version", "0.9.0"))
    resolved, withheld = _diff(current, newer)
    assert resolved == set()
    assert _LABESC1 <= withheld
