"""Ingest contract: the synthetic export round-trips to a populated Estate."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from adcs_lens.ingest import IngestError, collector_compat_warning, ingest
from adcs_lens.model import CaKind, CrlTier, Manifest, Severity
from adcs_lens.normalize import is_low_priv_trustee


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
    assert ingest(json_export).manifest.collector_version == "0.8.0-fixture"


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


def test_endpoint_bool_coerces_string_false(tmp_path: Path) -> None:
    # A JSON string "false" is truthy under naive bool(); ingest must read it as
    # False so the cleartext-HTTP ESC8 signal is not suppressed.
    (tmp_path / "collector-manifest.json").write_text("{}", encoding="utf-8")
    (tmp_path / "web-endpoints.json").write_text(
        json.dumps([{"name": "/CertSrv", "ssl_required": "false", "windows_auth": "true"}]),
        encoding="utf-8",
    )
    ep = ingest(tmp_path).endpoints[0]
    assert ep.ssl_required is False
    assert ep.windows_auth is True


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

    # Absent key defaults to True (backward compat with pre-field exports).
    d2 = tmp_path / "no_key"
    d2.mkdir()
    (d2 / "collector-manifest.json").write_text("{}", encoding="utf-8")
    (d2 / "templates.json").write_text(json.dumps([{"name": "T"}]), encoding="utf-8")
    assert ingest(d2).templates[0].acl_obtained is True

    # Non-bool values (null, string, int) fall back to True — a corrupt/wrong-type
    # field must never raise a false gap signal on a real export.
    for bad in (None, "false", "true", 0, 1):
        d3 = tmp_path / f"bad_{bad!r}"
        d3.mkdir()
        (d3 / "collector-manifest.json").write_text("{}", encoding="utf-8")
        (d3 / "templates.json").write_text(
            json.dumps([{"name": "T", "acl_obtained": bad}]), encoding="utf-8"
        )
        assert ingest(d3).templates[0].acl_obtained is True


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
    from adcs_lens.ingest import _parse_version

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


def test_compat_warning_silent_for_unparseable_version() -> None:
    # An unknown version cannot be ranked, so it is not flagged stale.
    assert collector_compat_warning(_manifest("unknown")) is None


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
    certs_dir = tmp_path / "certs"
    certs_dir.mkdir()
    (certs_dir / "index.json").write_text(json.dumps([]), encoding="utf-8")
    with pytest.raises(IngestError, match="certs/index.json must be an object"):
        ingest(tmp_path)
