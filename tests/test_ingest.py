"""Ingest contract: the synthetic export round-trips to a populated Estate."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from adcs_lens.ingest import IngestError, collector_compat_warning, ingest
from adcs_lens.model import (
    PASS_FILES,
    CaKind,
    CollectorVersionStatus,
    CrlTier,
    Manifest,
    Severity,
)
from adcs_lens.normalize import is_low_priv_trustee
from tests.fixtures.build_fixture import build_minimal_export


def test_manifest_and_counts(json_export: Path) -> None:
    estate = ingest(json_export)
    assert estate.manifest.host == "LABCA01"
    assert estate.manifest.domain == "lab.example.com"
    # DC registry is collected in the fixture, so its pass is not skipped. Use the
    # hyphenated pass name the detectors actually gate on (esc10-dc-registry).
    assert "esc10-dc-registry" not in estate.manifest.skipped_passes
    assert len(estate.cas) == 2
    assert len(estate.templates) == 6
    assert len(estate.dcs) == 2


def test_bom_tolerant(json_export: Path) -> None:
    # collector-manifest.json is written with a UTF-8 BOM; ingest must not choke.
    raw = (json_export / "collector-manifest.json").read_bytes()
    assert raw[:3] == b"\xef\xbb\xbf", "fixture should exercise the BOM path"
    assert ingest(json_export).manifest.collector_version == "0.9.0-fixture"


def test_ca_flags_and_kind(json_export: Path) -> None:
    estate = ingest(json_export)
    issuing = next(c for c in estate.cas if c.kind == CaKind.ISSUING)
    assert "EDITF_ATTRIBUTESUBJECTALTNAME2" in issuing.edit_flags
    root = next(c for c in estate.cas if c.kind == CaKind.ROOT)
    assert root.edit_flags == frozenset()


def test_published_by_join(json_export: Path) -> None:
    estate = ingest(json_export)
    tmpl = estate.templates[0]
    # enrollment-services.json publishes the template by OID under the issuing CA.
    assert estate.manifest.enrollment_services_available is True
    assert "LAB Issuing CA" in tmpl.published_by


def test_published_by_join_normalizes_multiple_blank_duplicate_names(
    json_export: Path,
) -> None:
    from adcs_lens.detection import detect_esc1

    services_path = json_export / "enrollment-services.json"
    services_path.write_text(
        json.dumps(
            {
                " Zebra CA ": ["LabWebServer", "LabWebServer"],
                "Alpha CA": ["LabWebServer"],
                "": ["LabWebServer"],
                "   ": ["LabWebServer"],
            }
        ),
        encoding="utf-8",
    )
    templates_path = json_export / "templates.json"
    templates = json.loads(templates_path.read_text(encoding="utf-8"))
    templates[0]["ekus"] = ["1.3.6.1.5.5.7.3.2"]  # Client Authentication -> ESC1
    templates_path.write_text(json.dumps(templates), encoding="utf-8")

    estate = ingest(json_export)
    tmpl = next(t for t in estate.templates if t.name == "LabWebServer")
    assert estate.manifest.enrollment_services_available is True
    assert tmpl.published_by == ("Alpha CA", "Zebra CA")
    finding = next(f for f in detect_esc1(estate) if f.subject == "Lab Web Server")
    assert finding.severity == Severity.CRITICAL
    assert "Publication state: published by Alpha CA, Zebra CA." in finding.detail


def test_esc1_publication_state_unknown_when_enrollment_services_export_missing(
    json_export: Path,
) -> None:
    from adcs_lens.detection import detect_esc1, detect_orphaned_templates

    (json_export / "enrollment-services.json").unlink()
    # The manifest must declare the absence; an undeclared missing file is a
    # partial export (see test_missing_pass_file_rejected_for_current_collector).
    _set_skipped(json_export, "certs", "enrollment-services")
    templates_path = json_export / "templates.json"
    templates = json.loads(templates_path.read_text(encoding="utf-8"))
    templates[0]["ekus"] = ["1.3.6.1.5.5.7.3.2"]  # Client Authentication -> ESC1
    templates_path.write_text(json.dumps(templates), encoding="utf-8")

    estate = ingest(json_export)
    assert estate.manifest.enrollment_services_available is False
    findings = detect_esc1(estate)
    finding = next(f for f in findings if f.subject == "Lab Web Server")
    assert finding.severity == Severity.CRITICAL
    assert (
        "Publication state: unknown (enrollment-services export absent or unevaluated)."
        in finding.detail
    )
    assert detect_orphaned_templates(estate) == []


@pytest.mark.parametrize(
    "enrollment_services",
    [{}, {"LAB Issuing CA": []}],
    ids=["empty-object", "ca-with-empty-template-list"],
)
def test_empty_enrollment_services_export_confirms_unpublished(
    json_export: Path,
    enrollment_services: dict[str, list[str]],
) -> None:
    from adcs_lens.detection import detect_esc1, detect_orphaned_templates

    (json_export / "enrollment-services.json").write_text(
        json.dumps(enrollment_services), encoding="utf-8"
    )
    templates_path = json_export / "templates.json"
    templates = json.loads(templates_path.read_text(encoding="utf-8"))
    templates[0]["ekus"] = ["1.3.6.1.5.5.7.3.2"]  # Client Authentication -> ESC1
    templates_path.write_text(json.dumps(templates), encoding="utf-8")

    estate = ingest(json_export)
    assert estate.manifest.enrollment_services_available is True
    finding = next(f for f in detect_esc1(estate) if f.subject == "Lab Web Server")
    assert finding.severity == Severity.CRITICAL
    assert (
        "Publication state: confirmed unpublished (not offered by any CA)."
        in finding.detail
    )
    orphan = next(
        f for f in detect_orphaned_templates(estate) if f.subject == "Lab Web Server"
    )
    assert orphan.severity == Severity.LOW


@pytest.mark.parametrize(
    "mapping_value",
    [
        None,
        "LabWebServer",
        1,
        True,
        {"template": "LabWebServer"},
        [None],
        [1],
        [{}],
    ],
    ids=[
        "null",
        "string-scalar",
        "integer-scalar",
        "boolean-scalar",
        "object",
        "null-entry",
        "integer-entry",
        "object-entry",
    ],
)
def test_enrollment_services_rejects_malformed_mapping_values(
    json_export: Path,
    mapping_value: object,
) -> None:
    (json_export / "enrollment-services.json").write_text(
        json.dumps({"LAB Issuing CA": mapping_value}), encoding="utf-8"
    )
    with pytest.raises(
        IngestError,
        match=r"enrollment-services\.json mapping values must be arrays of strings",
    ):
        ingest(json_export)


def test_esc3_publication_state_confirmed_unpublished_from_fixture(
    json_export: Path,
) -> None:
    from adcs_lens.detection import detect_esc3

    templates_path = json_export / "templates.json"
    templates = json.loads(templates_path.read_text(encoding="utf-8"))
    legacy = next(t for t in templates if t["name"] == "LegacyV1WebServer")
    legacy["ekus"] = ["1.3.6.1.4.1.311.20.2.1"]  # Certificate Request Agent -> ESC3
    templates_path.write_text(json.dumps(templates), encoding="utf-8")

    estate = ingest(json_export)
    assert estate.manifest.enrollment_services_available is True
    assert any(t.published_by for t in estate.templates)  # mixed published/unpublished fixture
    finding = next(f for f in detect_esc3(estate) if f.subject == "Legacy V1 Web Server")
    assert finding.severity == Severity.HIGH
    assert (
        "Publication state: confirmed unpublished (not offered by any CA)."
        in finding.detail
    )


def test_sid_normalized_and_low_priv(json_export: Path) -> None:
    estate = ingest(json_export)
    issuing = next(c for c in estate.cas if c.kind == CaKind.ISSUING)
    ace = issuing.security[0]
    assert ace.trustee_sid.startswith("S-1-5-21-")
    assert is_low_priv_trustee(ace.trustee_sid)


def test_template_security_round_trips(json_export: Path) -> None:
    # The collector's Phase 1b template DACL pass lands in template.security as
    # normalized ACEs; an Allow/Enroll to a low-priv trustee survives ingest.
    estate = ingest(json_export)
    tmpl = estate.templates[0]
    ace = next(a for a in tmpl.security if "Enroll" in a.rights)
    assert ace.ace_type.value == "Allow"
    assert is_low_priv_trustee(ace.trustee_sid)
    # The fixture does not emit acl_obtained -> default True (no false gap signal).
    assert tmpl.acl_obtained is True


def test_certs_parsed_bool_when_no_certs_dir(json_export: Path) -> None:
    # No certs/ dir in the json-only export; certs_parsed reflects whether
    # lifecycle (cert/CRL) data was actually parsed, not merely whether the
    # [certs] extra is installed. With no certs/index.json it is False even
    # when cryptography is importable, so the lifecycle detector degrades
    # honestly rather than silently passing as "clean".
    estate = ingest(json_export)
    assert estate.manifest.certs_parsed is False
    assert estate.crls == ()


def test_missing_files_degrade_to_empty(tmp_path: Path) -> None:
    # A near-empty export (only a manifest) ingests without raising.
    (tmp_path / "collector-manifest.json").write_text("{}", encoding="utf-8")
    estate = ingest(tmp_path)
    assert estate.cas == ()
    assert estate.templates == ()


def test_ca_config_must_be_array(tmp_path: Path) -> None:
    (tmp_path / "collector-manifest.json").write_text("{}", encoding="utf-8")
    (tmp_path / "ca-config.json").write_text('{"not": "an array"}', encoding="utf-8")
    with pytest.raises(IngestError, match="expected a JSON array"):
        ingest(tmp_path)


def test_rejects_directory_traversal(tmp_path: Path) -> None:
    (tmp_path / "collector-manifest.json").write_text("{}", encoding="utf-8")
    certs_dir = tmp_path / "certs"
    certs_dir.mkdir()
    (certs_dir / "index.json").write_text(
        '{"certs": [{"file": "../../secret.txt"}]}', encoding="utf-8"
    )
    (tmp_path / "secret.txt").write_text("sensitive", encoding="utf-8")
    with pytest.raises(IngestError, match="escapes certs/"):
        ingest(tmp_path)


def test_null_manifest_fields_coerce_to_empty(tmp_path: Path) -> None:
    (tmp_path / "collector-manifest.json").write_text(
        '{"host": null, "domain": null}', encoding="utf-8"
    )
    m = ingest(tmp_path).manifest
    assert m.host == ""
    assert m.domain == ""


def test_audit_filter_coerces_string_and_hex(tmp_path: Path) -> None:
    # certutil often renders AuditFilter as a string (sometimes hex). Ingest must
    # coerce to int so detect_audit_config does not TypeError on a real export.
    (tmp_path / "collector-manifest.json").write_text("{}", encoding="utf-8")
    (tmp_path / "ca-config.json").write_text(
        json.dumps([{"name": "CA1", "audit_filter": "0x7F"}]), encoding="utf-8"
    )
    assert ingest(tmp_path).cas[0].audit_filter == 127

    (tmp_path / "ca-config.json").write_text(
        json.dumps([{"name": "CA1", "audit_filter": "127"}]), encoding="utf-8"
    )
    assert ingest(tmp_path).cas[0].audit_filter == 127


def test_audit_filter_rejects_bool(tmp_path: Path) -> None:
    # JSON true must not become 1; reject it so a malformed export is loud.
    (tmp_path / "collector-manifest.json").write_text("{}", encoding="utf-8")
    (tmp_path / "ca-config.json").write_text(
        json.dumps([{"name": "CA1", "audit_filter": True}]), encoding="utf-8"
    )
    with pytest.raises(IngestError, match="AuditFilter"):
        ingest(tmp_path)


def test_min_key_size_coerces_string(tmp_path: Path) -> None:
    (tmp_path / "collector-manifest.json").write_text("{}", encoding="utf-8")
    (tmp_path / "templates.json").write_text(
        json.dumps([{"name": "T", "min_key_size": "1024"}]), encoding="utf-8"
    )
    assert ingest(tmp_path).templates[0].min_key_size == 1024


def test_min_key_size_rejects_bool(tmp_path: Path) -> None:
    (tmp_path / "collector-manifest.json").write_text("{}", encoding="utf-8")
    (tmp_path / "templates.json").write_text(
        json.dumps([{"name": "T", "min_key_size": True}]), encoding="utf-8"
    )
    with pytest.raises(IngestError, match="min_key_size"):
        ingest(tmp_path)


@pytest.mark.parametrize("bad", ["false", "true", 0, 1, None])
def test_endpoint_bool_must_be_a_json_boolean(tmp_path: Path, bad: object) -> None:
    # A string "false" used to be coerced; a coverage/config boolean is now a
    # JSON boolean or an IngestError, never a guess (windows_auth False skips ESC8).
    (tmp_path / "collector-manifest.json").write_text("{}", encoding="utf-8")
    (tmp_path / "web-endpoints.json").write_text(
        json.dumps([{"name": "/CertSrv", "ssl_required": bad, "windows_auth": True}]),
        encoding="utf-8",
    )
    with pytest.raises(IngestError, match="ssl_required must be a JSON boolean"):
        ingest(tmp_path)


def test_enum_kind_case_insensitive(tmp_path: Path) -> None:
    # PowerShell/certutil frequently emit TitleCase; the StrEnum values are
    # lower-case. A casing mismatch must not raise IngestError.
    (tmp_path / "collector-manifest.json").write_text("{}", encoding="utf-8")
    (tmp_path / "ca-config.json").write_text(
        json.dumps([{"name": "CA1", "kind": "Root"}]), encoding="utf-8"
    )
    (tmp_path / "pki-acls.json").write_text(
        json.dumps([{"object_dn": "CN=NTAuth", "kind": "NTAuth", "security": []}]),
        encoding="utf-8",
    )
    estate = ingest(tmp_path)
    from adcs_lens.model import AclKind, CaKind

    assert estate.cas[0].kind is CaKind.ROOT
    assert estate.acls[0].kind is AclKind.NTAUTH


def test_template_acl_obtained_round_trips(tmp_path: Path) -> None:
    # Explicit false round-trips through ingest.
    (tmp_path / "collector-manifest.json").write_text("{}", encoding="utf-8")
    (tmp_path / "templates.json").write_text(
        json.dumps([{"name": "T", "acl_obtained": False}]), encoding="utf-8"
    )
    assert ingest(tmp_path).templates[0].acl_obtained is False

    # Absent key: tolerated (default True) only for an unverified collector,
    # which also puts the whole export under a wildcard coverage gap.
    d2 = tmp_path / "no_key"
    d2.mkdir()
    (d2 / "collector-manifest.json").write_text("{}", encoding="utf-8")
    (d2 / "templates.json").write_text(json.dumps([{"name": "T"}]), encoding="utf-8")
    assert ingest(d2).templates[0].acl_obtained is True

    # Non-bool values (null, string, int) are malformed: never default to
    # "collected", which would turn an unreadable DACL into a clean template.
    for bad in (None, "false", "true", 0, 1):
        d3 = tmp_path / f"bad_{bad!r}"
        d3.mkdir()
        (d3 / "collector-manifest.json").write_text("{}", encoding="utf-8")
        (d3 / "templates.json").write_text(
            json.dumps([{"name": "T", "acl_obtained": bad}]), encoding="utf-8"
        )
        with pytest.raises(IngestError, match="acl_obtained must be a JSON boolean"):
            ingest(d3)


@pytest.mark.parametrize(
    ("file", "key"),
    [
        ("templates.json", "acl_obtained"),
        ("pki-acls.json", "acl_obtained"),
        ("ca-config.json", "registry_config_collected"),
        ("web-endpoints.json", "windows_auth"),
        ("web-endpoints.json", "ssl_required"),
    ],
)
def test_current_collector_requires_coverage_markers(
    json_export: Path, file: str, key: str
) -> None:
    path = json_export / file
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    del data[0][key]
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(IngestError, match=f"{key} is missing"):
        ingest(json_export)


@pytest.mark.parametrize("bad", ["garbage", "false", 1, None])
@pytest.mark.parametrize(
    ("file", "key"),
    [
        ("templates.json", "acl_obtained"),
        ("pki-acls.json", "acl_obtained"),
        ("ca-config.json", "registry_config_collected"),
    ],
)
def test_malformed_coverage_marker_is_an_error(
    json_export: Path, file: str, key: str, bad: object
) -> None:
    path = json_export / file
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    data[0][key] = bad
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(IngestError, match=f"{key} must be a JSON boolean"):
        ingest(json_export)


def test_unknown_skipped_pass_is_an_error(json_export: Path) -> None:
    _set_skipped(json_export, "certs", "template-securty")
    with pytest.raises(IngestError, match="unknown pass name"):
        ingest(json_export)


@pytest.mark.parametrize("version", [99, 0.8, True, ["0.8.0"], {"v": "0.8.0"}])
def test_non_string_collector_version_is_an_error(json_export: Path, version: object) -> None:
    path = json_export / "collector-manifest.json"
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    data["collector_version"] = version
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(IngestError, match="collector_version must be a string"):
        ingest(json_export)


@pytest.mark.certs
def test_cert_matching_no_ca_is_kept_and_evaluated(tmp_path: Path) -> None:
    # The offline root is published in AIA but is not an enrollment service, so
    # its cert's ca_name matches no CA in ca-config.json. It must be evaluated
    # (expiry/signature/key), never silently dropped.
    pytest.importorskip("cryptography")
    from datetime import UTC, datetime, timedelta

    from adcs_lens.detection import run_all
    from tests.fixtures.build_fixture import build_export

    now = datetime(2026, 6, 15, 12, 0, tzinfo=UTC)
    export = build_export(tmp_path / "e", with_certs=True, now=now)
    path = export / "ca-config.json"
    cas = json.loads(path.read_text(encoding="utf-8-sig"))
    path.write_text(json.dumps([c for c in cas if c["name"] != "LAB Root CA"]), encoding="utf-8")
    estate = ingest(export)
    assert [name for name, _ in estate.unattached_certs] == ["LAB Root CA"]
    # Make the root cert expire inside the window: rebuild with a near expiry
    # is not needed — evaluate against a "now" past its notAfter instead.
    later = now + timedelta(days=3651)
    checks = {(f.check, f.subject) for f in run_all(estate, now=later)}
    assert ("CA_CERT_EXPIRY", "CN=LAB Root CA") in checks


def test_full_export_lifecycle(full_export: Path) -> None:
    estate = ingest(full_export)
    assert estate.manifest.certs_parsed is True
    assert len(estate.crls) == 2
    assert any(c.tier == CrlTier.ROOT for c in estate.crls)
    assert any(c.tier == CrlTier.ISSUING for c in estate.crls)


def test_crl_only_export_flips_certs_parsed(full_export: Path) -> None:
    # An export whose certs/index.json carries CRLs but no certs must still
    # report certs_parsed=True — the lifecycle path ran and parsed CRLs, so
    # the detector must not degrade to a false "not evaluated" note.
    import json as _json

    index_path = full_export / "certs" / "index.json"
    index = _json.loads(index_path.read_text(encoding="utf-8"))
    index["certs"] = []  # strip certs, keep CRLs
    index_path.write_text(_json.dumps(index), encoding="utf-8")
    estate = ingest(full_export)
    assert estate.manifest.certs_parsed is True
    assert len(estate.crls) == 2
    assert estate.cas[0].certs == ()  # no certs populated


def test_severity_enum_round_trips(json_export: Path) -> None:
    from adcs_lens.detection import run_all
    findings = run_all(ingest(json_export))
    esc6 = next(f for f in findings if f.check == "ESC6")
    assert esc6.severity == Severity.CRITICAL
    # The two readable templates omit acl_obtained (default True) -> no false gap
    # for them; the one explicit unreadable template surfaces a real gap note.
    gaps = [f for f in findings if f.check == "TEMPLATE_ACL_UNREADABLE"]
    assert len(gaps) == 1
    assert gaps[0].subject == "Lab Krb Client (unreadable)"


def test_esc8_detected_end_to_end(json_export: Path) -> None:
    # The fixture exposes Web Enrollment over HTTP+NTLM+no-EPA (ESC8) and a
    # Kerberos-only EPA-required CES (clean). Exercise the full
    # ingest -> EnrollmentEndpoint -> detect_esc8 pipeline.
    from adcs_lens.detection import run_all
    estate = ingest(json_export)
    assert len(estate.endpoints) == 2
    esc8 = [f for f in run_all(estate) if f.check == "ESC8"]
    assert len(esc8) == 1
    assert esc8[0].severity == Severity.HIGH
    assert esc8[0].subject == "/CertSrv"
    assert all(f.check != "ENROLLMENT_ENDPOINTS_NOT_EVALUATED" for f in run_all(estate))


def test_esc5_detected_end_to_end(json_export: Path) -> None:
    # The fixture carries a benign scoped-WriteProperty NTAuth ACE (no finding), a
    # low-priv WriteDacl on the PKS container (ESC5 via DACL control), and an AIA
    # container owned by a low-priv principal (ESC5 via owner-based control,
    # WI-019). Exercise the full ingest -> PkiObjectAcl -> detect_esc5 pipeline.
    from adcs_lens.detection import run_all
    estate = ingest(json_export)
    # 3 readable objects + the CDP container whose DACL was not obtained
    # (acl_obtained=False -> ESC5 skips it; PKI_ACL_UNREADABLE surfaces it).
    assert len(estate.acls) == 4
    esc5 = [f for f in run_all(estate) if f.check == "ESC5"]
    assert len(esc5) == 2
    assert all(f.severity == Severity.HIGH for f in esc5)
    # The DACL-control finding on the PKS container.
    assert any("Public Key Services" in f.subject for f in esc5)
    # The owner-based finding on the AIA container (WI-019).
    assert any("AIA" in f.subject for f in esc5)
    # The pass ran, so there must be no degrade note.
    assert all(f.check != "PKI_ACL_NOT_EVALUATED" for f in run_all(estate))


def test_template_acl_unreadable_end_to_end(json_export: Path) -> None:
    # Full ingest -> run_all pipeline for the TEMPLATE_ACL_UNREADABLE path that
    # previously was only exercised via hand-built model objects. An unreadable-
    # DACL template that is ESC1-positive-by-config is SKIPPED by ESC1 (its enroll
    # ACL was not obtained, so it cannot be evaluated) and surfaced by the gap
    # detector instead of being silently passed as "clean".
    from adcs_lens.detection import run_all
    estate = ingest(json_export)
    unreadable = next(t for t in estate.templates if not t.acl_obtained)
    assert unreadable.name == "LabKrbClientUnreadable"
    # It is ESC1-positive by config, so the only thing holding ESC1 back is the
    # unreadable ACL — ESC1 must skip it, not falsely clear it.
    assert "ENROLLEE_SUPPLIES_SUBJECT" in unreadable.name_flags
    assert "1.3.6.1.5.5.7.3.2" in unreadable.ekus  # Client Authentication
    assert unreadable.security == ()

    findings = run_all(estate)
    gap = next(f for f in findings if f.check == "TEMPLATE_ACL_UNREADABLE")
    assert gap.subject == "Lab Krb Client (unreadable)"
    assert gap.severity == Severity.INFO
    # No ESC1 finding for the unreadable template (and no estate-level degrade
    # note — the template-security pass did run).
    assert not any(
        f.check == "ESC1" and f.subject == unreadable.display_name for f in findings
    )
    assert all(f.check != "TEMPLATE_ACL_NOT_EVALUATED" for f in findings)


# --- collector/core version compatibility (WI-031) ------------------------


def _manifest(version: str) -> Manifest:
    return Manifest(
        collector_version=version,
        collected_at="",
        host="",
        domain="",
        skipped_passes=(),
        certs_parsed=False,
    )


def test_parse_version_tolerates_suffix_and_short_forms() -> None:
    from adcs_lens.model import parse_collector_version as _parse_version

    assert _parse_version("0.5.0") == (0, 5, 0)
    assert _parse_version("0.5.0-fixture") == (0, 5, 0)
    assert _parse_version("v0.5.0") == (0, 5, 0)
    assert _parse_version("1.2") == (1, 2, 0)
    assert _parse_version("unknown") is None
    assert _parse_version("") is None


def test_compat_warning_for_old_collector() -> None:
    msg = collector_compat_warning(_manifest("0.4.9"))
    assert msg is not None
    assert "0.4.9" in msg
    assert "0.8.0" in msg
    assert "certs/index.json" in msg  # names the fields that may be absent
    # A v-prefixed stale version is still recognized as stale.
    assert collector_compat_warning(_manifest("v0.4.0")) is not None


def test_compat_warning_for_collector_lacking_certs_pass() -> None:
    # 0.7.0 predates the certs/ lifecycle pass (MIN is 0.8.0) — it is stale.
    assert collector_compat_warning(_manifest("0.7.0")) is not None


def test_compat_warning_silent_for_current_collector() -> None:
    assert collector_compat_warning(_manifest("0.8.0")) is None
    assert collector_compat_warning(_manifest("1.0.0")) is None


@pytest.mark.parametrize("version", ["unknown", "", "garbage", "vX"])
def test_compat_warning_for_unparseable_version(version: str) -> None:
    # An unknown version cannot be ranked, so it is never treated as current.
    m = _manifest(version)
    assert m.collector_version_status is CollectorVersionStatus.UNKNOWN
    msg = collector_compat_warning(m)
    assert msg is not None
    assert "unknown or unparseable" in msg


def test_collector_version_status_is_derived_not_stored() -> None:
    # A programmatically built Manifest cannot claim CURRENT for a stale version.
    assert _manifest("0.7.9").collector_version_status is CollectorVersionStatus.STALE
    assert _manifest("0.8.0").collector_version_status is CollectorVersionStatus.CURRENT
    assert _manifest("1.0.0-rc1").collector_version_status is CollectorVersionStatus.CURRENT


def test_registry_config_collected_defaults_true(json_export: Path) -> None:
    # The fixture does not emit registry_config_collected -> default True
    # (pre-field exports read as "collected", no false gap signal).
    estate = ingest(json_export)
    assert all(ca.registry_config_collected is True for ca in estate.cas)


def test_registry_config_collected_round_trips(json_export: Path) -> None:
    path = json_export / "ca-config.json"
    cas = json.loads(path.read_text(encoding="utf-8"))
    cas[0]["registry_config_collected"] = False
    path.write_text(json.dumps(cas), encoding="utf-8")
    estate = ingest(json_export)
    assert estate.cas[0].registry_config_collected is False
    assert estate.cas[1].registry_config_collected is True


def test_pki_acl_obtained_round_trips(json_export: Path) -> None:
    # The fixture's CDP container carries acl_obtained=False; the others
    # default to True.
    estate = ingest(json_export)
    by_kind = {a.kind.value: a for a in estate.acls}
    assert by_kind["cdp"].acl_obtained is False
    assert by_kind["ntauth"].acl_obtained is True
    assert by_kind["aia"].acl_obtained is True


def test_certs_index_must_be_an_object(tmp_path: Path) -> None:
    # A certs/index.json that is a JSON array (contract violation) raises
    # IngestError, not an AttributeError.
    pytest.importorskip("cryptography")
    build_minimal_export(tmp_path, skipped_passes=())
    (tmp_path / "certs" / "index.json").write_text(json.dumps([]), encoding="utf-8")
    with pytest.raises(IngestError, match="certs/index.json must be an object"):
        ingest(tmp_path)


# --- partial / truncated exports are explicit, never silently empty -------------


def _set_skipped(export: Path, *passes: str, version: str | None = None) -> None:
    path = export / "collector-manifest.json"
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    data["skipped_passes"] = list(passes)
    if version is not None:
        data["collector_version"] = version
    path.write_text(json.dumps(data), encoding="utf-8")


def test_missing_export_directory_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(IngestError, match="export directory not found"):
        ingest(tmp_path / "does-not-exist")


def test_missing_manifest_is_an_error(tmp_path: Path) -> None:
    # An empty directory used to ingest as an empty, "clean" estate.
    with pytest.raises(IngestError, match="collector-manifest.json is missing"):
        ingest(tmp_path)


def test_manifest_must_be_an_object(tmp_path: Path) -> None:
    build_minimal_export(tmp_path)
    (tmp_path / "collector-manifest.json").write_text("[]", encoding="utf-8")
    with pytest.raises(IngestError, match="must be a JSON object"):
        ingest(tmp_path)


@pytest.mark.parametrize("bad", ["template-security", ["ok", 3], {"a": 1}])
def test_skipped_passes_must_be_a_string_array(tmp_path: Path, bad: object) -> None:
    # A bare string would be iterated character by character and silently
    # claim every pass ran.
    build_minimal_export(tmp_path)
    path = tmp_path / "collector-manifest.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["skipped_passes"] = bad
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(IngestError, match="skipped_passes must be an array of strings"):
        ingest(tmp_path)


@pytest.mark.parametrize("pass_name", sorted(PASS_FILES))
def test_missing_pass_file_rejected_for_current_collector(
    tmp_path: Path, pass_name: str
) -> None:
    # The current collector writes every non-skipped pass's file, so an absent
    # one is a truncated copy — refused, never read as an empty list.
    build_minimal_export(tmp_path, skipped_passes=())
    (tmp_path / PASS_FILES[pass_name]).unlink()
    with pytest.raises(IngestError, match=f"pass '{pass_name}'"):
        ingest(tmp_path)


@pytest.mark.parametrize("pass_name", sorted(PASS_FILES))
def test_declared_skip_allows_missing_file(tmp_path: Path, pass_name: str) -> None:
    build_minimal_export(tmp_path, skipped_passes=(pass_name,))
    estate = ingest(tmp_path)
    assert pass_name in estate.manifest.uncollected_passes
    assert estate.manifest.missing_passes == ()


@pytest.mark.parametrize("version", ["0.7.0", "unknown", ""])
@pytest.mark.parametrize("pass_name", sorted(PASS_FILES))
def test_missing_pass_file_degrades_for_unverified_collector(
    tmp_path: Path, pass_name: str, version: str
) -> None:
    # An older/unknown collector may predate a pass: record the absence as an
    # explicit degradation (fed to detectors and the diff coverage map).
    build_minimal_export(tmp_path, skipped_passes=(), collector_version=version)
    (tmp_path / PASS_FILES[pass_name]).unlink()
    estate = ingest(tmp_path)
    assert estate.manifest.missing_passes == (pass_name,)
    assert pass_name in estate.manifest.uncollected_passes
    from adcs_lens.detection import run_all

    checks = {(f.check, f.subject) for f in run_all(estate)}
    assert ("PASS_NOT_COLLECTED", pass_name) in checks
    assert ("COLLECTOR_VERSION_UNVERIFIED", "(estate)") in checks


def test_missing_collector_version_is_unknown_not_current(tmp_path: Path) -> None:
    build_minimal_export(tmp_path)
    path = tmp_path / "collector-manifest.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    del data["collector_version"]
    path.write_text(json.dumps(data), encoding="utf-8")
    estate = ingest(tmp_path)
    assert estate.manifest.collector_version_status is CollectorVersionStatus.UNKNOWN
    from adcs_lens.detection import run_all

    assert any(f.check == "COLLECTOR_VERSION_UNVERIFIED" for f in run_all(estate))


def test_current_collector_has_no_version_note(json_export: Path) -> None:
    from adcs_lens.detection import run_all

    assert not any(f.check == "COLLECTOR_VERSION_UNVERIFIED" for f in run_all(ingest(json_export)))


def test_ca_security_entry_absent_is_a_named_gap(json_export: Path) -> None:
    path = json_export / "ca-security.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    del data["LAB Issuing CA"]
    path.write_text(json.dumps(data), encoding="utf-8")
    estate = ingest(json_export)
    issuing = next(ca for ca in estate.cas if ca.name == "LAB Issuing CA")
    assert issuing.security_collected is False
    from adcs_lens.detection import detect_esc7

    findings = detect_esc7(estate)
    assert ("CA_SECURITY_NOT_EVALUATED", "LAB Issuing CA") in {
        (f.check, f.subject) for f in findings
    }
    assert not any(f.check == "ESC7" and f.subject == "LAB Issuing CA" and "Security owner"
                   not in f.source for f in findings)


def test_fixture_pass_map_matches_model() -> None:
    from tests.fixtures.build_fixture import MINIMAL_PASS_FILES

    assert {k: v[0] for k, v in MINIMAL_PASS_FILES.items()} == PASS_FILES


# --- objectGUID identity (collector >= 0.9.0) ---------------------------------

_GUID_FILES = [
    ("templates.json", 0),
    ("pki-acls.json", 0),
    ("ca-config.json", 1),
    ("oid-objects.json", 0),
    ("dc-config.json", 0),
    ("principal-mappings.json", 0),
]


@pytest.mark.parametrize(("file", "index"), _GUID_FILES)
def test_guid_required_for_guid_collector(json_export: Path, file: str, index: int) -> None:
    path = json_export / file
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    del data[index]["object_guid"]
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(IngestError, match="object_guid is missing"):
        ingest(json_export)


@pytest.mark.parametrize("bad", ["XYZ", "A" * 32, "0" * 31, 123, ["x"]])
@pytest.mark.parametrize(("file", "index"), _GUID_FILES)
def test_malformed_guid_is_an_error(json_export: Path, file: str, index: int, bad: object) -> None:
    path = json_export / file
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    data[index]["object_guid"] = bad
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(IngestError, match="object_guid must be 32 lower-case hex"):
        ingest(json_export)


@pytest.mark.parametrize(("file", "index"), _GUID_FILES)
def test_duplicate_guid_within_one_export_is_an_error(
    json_export: Path, file: str, index: int
) -> None:
    path = json_export / file
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    other = 1 - index if len(data) > 1 else None
    if other is None:
        data.append(dict(data[index]))
        key = next(k for k in ("name", "object_dn", "oid", "dn") if k in data[-1])
        data[-1][key] = str(data[-1][key]) + "-twin"
    else:
        data[other]["object_guid"] = data[index]["object_guid"]
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(IngestError, match="duplicate object_guid"):
        ingest(json_export)


def test_standalone_ca_and_unreadable_container_may_lack_a_guid(json_export: Path) -> None:
    cas_path = json_export / "ca-config.json"
    cas = json.loads(cas_path.read_text(encoding="utf-8-sig"))
    cas[0].update(enrollment_service=False, object_guid="")
    cas_path.write_text(json.dumps(cas), encoding="utf-8")
    acl_path = json_export / "pki-acls.json"
    acls = json.loads(acl_path.read_text(encoding="utf-8-sig"))
    unreadable = next(a for a in acls if a.get("acl_obtained") is False)
    unreadable["object_guid"] = ""
    acl_path.write_text(json.dumps(acls), encoding="utf-8")
    estate = ingest(json_export)
    assert estate.cas[0].enrollment_service is False and estate.cas[0].object_guid == ""
    assert estate.manifest.guid_identity is True


def test_pre_guid_collector_needs_no_guids(tmp_path: Path) -> None:
    build_minimal_export(tmp_path, collector_version="0.8.0")
    estate = ingest(tmp_path)
    assert estate.manifest.guid_identity is False


@pytest.mark.certs
def test_duplicate_crl_guid_is_an_error(tmp_path: Path) -> None:
    pytest.importorskip("cryptography")
    from tests.fixtures.build_fixture import build_export

    export = build_export(tmp_path / "e", with_certs=True)
    path = export / "certs" / "index.json"
    index = json.loads(path.read_text(encoding="utf-8-sig"))
    index["crls"][1]["object_guid"] = index["crls"][0]["object_guid"]
    path.write_text(json.dumps(index), encoding="utf-8")
    with pytest.raises(IngestError, match="duplicate object_guid"):
        ingest(export)


# --- GUID exemptions validated against collector facts (round 4, item 3) ---------


def test_guidless_ca_exemption_requires_standalone_kind(json_export: Path) -> None:
    path = json_export / "ca-config.json"
    cas = json.loads(path.read_text(encoding="utf-8-sig"))
    # enrollment_service=false but kind 'issuing' must NOT excuse a missing GUID.
    cas[0].update(enrollment_service=False, kind="issuing")
    del cas[0]["object_guid"]
    path.write_text(json.dumps(cas), encoding="utf-8")
    with pytest.raises(IngestError, match="object_guid is missing"):
        ingest(json_export)
    cas[0]["kind"] = "standalone"
    path.write_text(json.dumps(cas), encoding="utf-8")
    assert ingest(json_export).cas[0].object_guid == ""


def test_guidless_pki_exemption_requires_unreadable_fixed_container(json_export: Path) -> None:
    path = json_export / "pki-acls.json"
    acls = json.loads(path.read_text(encoding="utf-8-sig"))
    # An enumerated ca_object (readable) may not drop its GUID even if marked
    # acl_obtained=false; only an unreadable fixed container may.
    acls[0].update(kind="ca_object", acl_obtained=False)
    del acls[0]["object_guid"]
    path.write_text(json.dumps(acls), encoding="utf-8")
    with pytest.raises(IngestError, match="object_guid is missing"):
        ingest(json_export)
    acls[0]["kind"] = "ntauth"
    path.write_text(json.dumps(acls), encoding="utf-8")
    assert ingest(json_export).acls[0].object_guid == ""
