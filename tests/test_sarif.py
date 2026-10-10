"""SARIF v2.1.0 output for CI / GRC integration (WI-020)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from adcs_lens.cli import main
from adcs_lens.detection import Finding
from adcs_lens.diff import diff_findings
from adcs_lens.display import render_diff_sarif, render_sarif
from adcs_lens.model import CrlTier, Severity


def _f(
    check: str,
    severity: Severity,
    *,
    subject: str = "subj",
    title: str = "title",
    detail: str = "detail",
    source: str = "source",
    tier: CrlTier | None = None,
    sid: str = "",
) -> Finding:
    return Finding(
        check=check,
        severity=severity,
        title=title,
        subject=subject,
        detail=detail,
        source=source,
        tier=tier,
        sid=sid,
    )


# --- CLI structure tests -----------------------------------------------------


def test_sarif_structure(json_export: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["doctor", str(json_export), "--sarif"])
    assert rc == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    assert doc["version"] == "2.1.0"
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "adcs-lens"
    assert driver["version"]
    assert driver["informationUri"] == "https://github.com/hraedon-labs/adcs-lens"
    results = doc["runs"][0]["results"]
    assert len(results) > 0
    esc6 = next(r for r in results if r["ruleId"] == "ESC6")
    assert esc6["level"] == "error"
    esc6_rule = next(r for r in driver["rules"] if r["id"] == "ESC6")
    assert esc6_rule["shortDescription"]["text"]
    assert esc6_rule["fullDescription"]["text"]
    assert esc6_rule["help"]["text"]


def test_sarif_info_finding_maps_to_none(
    json_export: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    main(["doctor", str(json_export), "--sarif"])
    doc = json.loads(capsys.readouterr().out)
    results = doc["runs"][0]["results"]
    info_levels = {r["level"] for r in results if r["ruleId"] == "TEMPLATE_ACL_UNREADABLE"}
    assert info_levels == {"none"}


def test_sarif_rules_deduplicated_sorted_and_indexed(
    json_export: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    main(["doctor", str(json_export), "--sarif"])
    doc = json.loads(capsys.readouterr().out)
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    rule_ids = [r["id"] for r in rules]
    assert rule_ids == sorted(rule_ids)
    assert len(rule_ids) == len(set(rule_ids))
    index_map = {r["id"]: i for i, r in enumerate(rules)}
    for result in doc["runs"][0]["results"]:
        assert result["ruleIndex"] == index_map[result["ruleId"]]


def test_sarif_exit_code_trips_on_critical(json_export: Path) -> None:
    assert (
        main(["doctor", str(json_export), "--sarif", "--exit-code", "--severity", "critical"]) == 1
    )


def test_sarif_and_json_are_mutually_exclusive(
    json_export: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["doctor", str(json_export), "--sarif", "--json"])
    assert exc_info.value.code == 2
    assert "not allowed with" in capsys.readouterr().err


def test_sarif_severity_filter_reduces_results(
    json_export: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    main(["doctor", str(json_export), "--sarif", "--severity", "critical"])
    doc = json.loads(capsys.readouterr().out)
    results = doc["runs"][0]["results"]
    assert all(r["level"] == "error" for r in results)


# --- Direct unit tests -------------------------------------------------------


def test_render_sarif_severity_mapping() -> None:
    findings = [
        _f("ESC6", Severity.CRITICAL),
        _f("ESC8", Severity.HIGH),
        _f("ESC10", Severity.MEDIUM),
        _f("ESCx", Severity.LOW),
        _f("TEMPLATE_ACL_UNREADABLE", Severity.INFO),
    ]
    doc = json.loads(render_sarif(findings))
    results = {r["ruleId"]: r for r in doc["runs"][0]["results"]}
    assert results["ESC6"]["level"] == "error"
    assert results["ESC8"]["level"] == "error"
    assert results["ESC10"]["level"] == "warning"
    assert results["ESCx"]["level"] == "note"
    assert results["TEMPLATE_ACL_UNREADABLE"]["level"] == "none"


def test_render_sarif_unknown_check_omits_consequence_fields() -> None:
    findings = [_f("BOGUS_CHECK", Severity.HIGH)]
    doc = json.loads(render_sarif(findings))
    rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["id"] == "BOGUS_CHECK"
    assert rule["shortDescription"]["text"] == "BOGUS_CHECK"
    assert "fullDescription" not in rule
    assert "help" not in rule


def test_render_sarif_tier_in_message() -> None:
    findings = [_f("CRL_EXPIRY", Severity.CRITICAL, tier=CrlTier.ROOT)]
    doc = json.loads(render_sarif(findings))
    msg = doc["runs"][0]["results"][0]["message"]["text"]
    assert "(root-tier)" in msg


def test_render_sarif_no_tier_when_none() -> None:
    findings = [_f("ESC6", Severity.CRITICAL, tier=None)]
    doc = json.loads(render_sarif(findings))
    msg = doc["runs"][0]["results"][0]["message"]["text"]
    assert "-tier" not in msg


def test_render_sarif_source_in_logical_locations() -> None:
    findings = [_f("ESC6", Severity.CRITICAL, source="template 'T': enroll ACL")]
    doc = json.loads(render_sarif(findings))
    result = doc["runs"][0]["results"][0]
    loc = result["locations"][0]["logicalLocations"][0]
    assert loc["fullyQualifiedName"] == "template 'T': enroll ACL"
    assert loc["name"] == "subj"


def test_render_sarif_includes_artifact_location() -> None:
    findings = [_f("ESC6", Severity.CRITICAL, source="template 'T': enroll ACL")]
    doc = json.loads(render_sarif(findings))
    result = doc["runs"][0]["results"][0]
    assert result["locations"][0]["physicalLocation"]["artifactLocation"] == {
        "uri": "file:///adcs-lens/template%20%27T%27%3A%20enroll%20ACL"
    }


def test_render_sarif_sid_property_from_structured_field() -> None:
    """The SARIF properties bag carries the finding's structured ``sid`` (WI-042)."""
    findings = [_f("ESC7", Severity.CRITICAL, sid="S-1-5-21-1111111111-2222222222-3333333333-513")]
    doc = json.loads(render_sarif(findings))
    result = doc["runs"][0]["results"][0]
    assert result["properties"] == {"sid": "S-1-5-21-1111111111-2222222222-3333333333-513"}


def test_render_sarif_no_sid_property_when_field_empty() -> None:
    """No properties bag when the finding carries no SID — even if the detail
    text happens to contain a SID-shaped string (WI-042: the renderer never
    parses SIDs out of free text)."""
    findings = [
        _f(
            "ESC7",
            Severity.HIGH,
            detail="The owner of this CA's security descriptor (S-1-5-21-1-2-3-512).",
        )
    ]
    doc = json.loads(render_sarif(findings))
    result = doc["runs"][0]["results"][0]
    assert "properties" not in result


def test_render_sarif_empty_findings() -> None:
    doc = json.loads(render_sarif([]))
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["results"] == []
    assert doc["runs"][0]["tool"]["driver"]["rules"] == []


def test_render_sarif_rule_index_after_sort() -> None:
    findings = [
        _f("ESC9", Severity.HIGH),
        _f("ESC1", Severity.CRITICAL),
        _f("ESC6", Severity.CRITICAL),
    ]
    doc = json.loads(render_sarif(findings))
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    assert [r["id"] for r in rules] == ["ESC1", "ESC6", "ESC9"]
    esc9 = next(r for r in doc["runs"][0]["results"] if r["ruleId"] == "ESC9")
    assert esc9["ruleIndex"] == 2


def test_render_sarif_multiple_findings_same_rule_share_index() -> None:
    findings = [
        _f("ESC8", Severity.HIGH, subject="ca01"),
        _f("ESC8", Severity.MEDIUM, subject="ca02"),
    ]
    doc = json.loads(render_sarif(findings))
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) == 1
    for result in doc["runs"][0]["results"]:
        assert result["ruleIndex"] == 0


def test_render_sarif_is_deterministic() -> None:
    findings = [
        _f("ESC9", Severity.HIGH),
        _f("ESC1", Severity.CRITICAL),
    ]
    first = render_sarif(findings)
    second = render_sarif(findings)
    assert first == second


_SCHEMA = json.loads(
    (Path(__file__).resolve().parent / "fixtures" / "sarif-2.1.0.json").read_text()
)


def test_render_sarif_validates_against_schema() -> None:
    try:
        import jsonschema
    except ImportError:
        pytest.skip("jsonschema not installed")
    findings = [_f("ESC6", Severity.CRITICAL), _f("ESC8", Severity.HIGH)]
    doc = json.loads(render_sarif(findings))
    jsonschema.validate(doc, _SCHEMA)


def test_render_diff_sarif_validates_against_schema() -> None:
    try:
        import jsonschema
    except ImportError:
        pytest.skip("jsonschema not installed")
    report = diff_findings(
        [_f("ESC8", severity=Severity.HIGH, subject="ca01")],
        [_f("ESC1", severity=Severity.CRITICAL, subject="TemplA")],
    )
    doc = json.loads(render_diff_sarif(report))
    jsonschema.validate(doc, _SCHEMA)
