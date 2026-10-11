"""The real collector body, run under pwsh with mocked native transports.

tests/collector/simulate.ps1 executes scripts/Export-AdcsEstate.ps1's own code
(only LDAP, certutil, the CA\\Security hive, security-descriptor parsing, IIS and
WMI are faked) and writes an export; this test ingests it with adcs-lens. It is
the end-to-end check of round 5 ruling C: a failed read reaches the core as
"not obtained" (JSON null), never as an empty list, and an enumeration marker is
complete only when its paged search was proven complete. It is not a substitute
for a live run against an AD CS estate (tracked as WI-044 for the collector).
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from adcs_lens.detection import evaluate
from adcs_lens.ingest import ingest
from adcs_lens.model import CaKind, Estate, StrongCertBinding
from tests.conftest import NOW

_SIMULATE = Path(__file__).parent / "collector" / "simulate.ps1"
_PWSH = shutil.which("pwsh")
pytestmark = pytest.mark.skipif(_PWSH is None, reason="pwsh is not installed")


def _collect(tmp_path: Path, scenario: str) -> Path:
    out = tmp_path / scenario
    assert _PWSH is not None
    proc = subprocess.run(
        [
            _PWSH,
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(_SIMULATE),
            "-OutDir",
            str(out),
            "-Scenario",
            scenario,
        ],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return out


@pytest.fixture(scope="module")
def clean(tmp_path_factory: pytest.TempPathFactory) -> Estate:
    return ingest(_collect(tmp_path_factory.mktemp("sim"), "clean"))


@pytest.fixture(scope="module")
def failures(tmp_path_factory: pytest.TempPathFactory) -> Estate:
    return ingest(_collect(tmp_path_factory.mktemp("sim"), "failures"))


def _ca(estate: Estate, name: str):  # type: ignore[no-untyped-def]
    return next(c for c in estate.cas if c.name == name)


def test_clean_collection_is_a_proven_export(clean: Estate) -> None:
    m = clean.manifest
    assert m.collector_version == "0.10.0" and m.reads_proven
    assert m.enumeration_complete >= {
        "ca-config",
        "enrollment-services",
        "templates",
        "oid-objects",
        "pki-acls",
        "web-endpoints",
        "dc-config",
        "principal-mappings",
    }
    local = _ca(clean, "LAB Issuing CA")
    assert local.edit_flags == {"EDITF_ATTRIBUTESUBJECTALTNAME2"}
    assert local.audit_filter == 0  # "= 0" is read (auditing disabled), not "not captured"
    assert local.kind is CaKind.ISSUING and local.unobtained == frozenset()
    remote = _ca(clean, "LAB Issuing CA 2")
    assert not remote.registry_config_collected
    assert {"edit_flags", "interface_flags", "disabled_extensions", "security"} <= remote.unobtained


def test_clean_collection_decides_with_usable_verdicts(clean: Estate) -> None:
    ev = evaluate(clean, now=NOW)
    checks = {(f.check, f.subject) for f in ev.findings}
    assert {
        ("ESC6", "LAB Issuing CA"),
        ("CA_AUDIT_DISABLED", "LAB Issuing CA"),
        ("ESC16", "LAB Issuing CA"),
        ("ESC8", "/CertSrv"),
    } <= checks
    usable = {(v.check, v.state) for v in ev.verdicts if v.usable}
    assert ("ESC6", "finding") in usable and ("ESC1", "finding") in usable
    cdp = next(a for a in clean.acls if a.kind.value == "cdp")
    assert not cdp.acl_obtained and "security" in cdp.unobtained  # unreadable fixed container


def test_failed_reads_reach_the_core_as_not_obtained(failures: Estate) -> None:
    local = _ca(failures, "LAB Issuing CA")
    # certutil EditFlags failed (access denied): not obtained, not "no flags".
    assert "edit_flags" in local.unobtained
    # CAType not configured: the kind is not known (no silent "issuing").
    assert "kind" in local.unobtained
    # DisableExtensionList not configured: a read, empty.
    assert (
        local.disabled_extensions == frozenset() and "disabled_extensions" not in local.unobtained
    )
    user = next(t for t in failures.templates if t.name == "LabUser")
    assert not user.acl_obtained and "security" in user.unobtained
    ep = next(e for e in failures.endpoints if e.name == "/CertSrv")
    assert "epa" in ep.unobtained
    dc2 = next(d for d in failures.dcs if d.name.startswith("LAB-DC02"))
    assert "strong_certificate_binding_enforcement" in dc2.unobtained
    dc1 = next(d for d in failures.dcs if d.name.startswith("LAB-DC01"))
    assert dc1.strong_certificate_binding_enforcement is StrongCertBinding.DISABLED
    # The template search lost a page: the container is not complete.
    assert "templates" not in failures.manifest.enumeration_complete
    # No CA\Security descriptor could be read: the pass is declared skipped.
    assert "ca-security" in failures.manifest.skipped_passes


def test_failed_reads_never_yield_a_usable_clean_verdict(failures: Estate) -> None:
    ev = evaluate(failures, now=NOW)
    by = {(v.check, v.key): v for v in ev.verdicts}
    esc6 = [v for (check, _), v in by.items() if check == "ESC6" and v.state != "undecided"]
    assert all(not v.usable for v in esc6)
    assert not [v for v in ev.verdicts if v.check == "ESC6" and v.usable]
    assert not [v for v in ev.verdicts if v.check in ("ESC1", "ESC9") and v.usable]
    assert ("ESC1", "template") not in ev.containers
    # ESC8 still reports the relay path (an unread EPA setting fails toward
    # flagging) but its verdict cannot clear anything.
    assert "ESC8" in {f.check for f in ev.findings}
    assert not [v for v in ev.verdicts if v.check == "ESC8" and v.usable]
