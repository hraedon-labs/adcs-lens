"""Drift detection (Stance 2) — the diff between two posture snapshots."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from adcs_lens.cli import main
from adcs_lens.detection import CoverageGap, Finding, run_all
from adcs_lens.diff import diff_findings
from adcs_lens.display import (
    render_diff_html,
    render_diff_json,
    render_diff_sarif,
    render_diff_text,
)
from adcs_lens.ingest import ingest
from adcs_lens.model import Severity
from tests.fixtures.build_fixture import build_export, build_minimal_export


def _skip(export: Path, *passes: str) -> None:
    """Declare *passes* skipped in an export's manifest (replacing the list)."""
    path = export / "collector-manifest.json"
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    data["skipped_passes"] = list(passes)
    path.write_text(json.dumps(data), encoding="utf-8")


def _f(check: str, subject: str, severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        check=check,
        severity=severity,
        title=f"{check} on {subject}",
        subject=subject,
        detail="d",
        source="s",
    )


def test_diff_detects_new_finding() -> None:
    old = [_f("ESC1", "TemplA")]
    new = [_f("ESC1", "TemplA"), _f("ESC8", "ca01")]
    report = diff_findings(old, new)
    assert [f.check for f in report.new] == ["ESC8"]
    assert report.resolved == ()
    assert report.unchanged == 1
    assert report.regressions is True


def test_diff_detects_resolved_finding() -> None:
    old = [_f("ESC1", "TemplA"), _f("ESC8", "ca01")]
    new = [_f("ESC1", "TemplA")]
    report = diff_findings(old, new)
    assert report.new == ()
    assert [f.check for f in report.resolved] == ["ESC8"]
    assert report.regressions is False


def test_diff_withholds_only_resolutions_for_incompletely_covered_checks() -> None:
    old = [_f("ORPHANED_TEMPLATE", "TemplateA", Severity.LOW), _f("ESC8", "ca01")]
    report = diff_findings(
        old,
        [],
        coverage=(CoverageGap(reason="r", checks=frozenset({"ORPHANED_TEMPLATE"})),),
    )
    assert [f.check for f in report.resolved] == ["ESC8"]
    assert [i.finding.check for i in report.indeterminate] == ["ORPHANED_TEMPLATE"]
    assert report.indeterminate[0].reason == "r"
    assert report.coverage_lost is True
    assert report.regressions is False


def test_diff_detects_severity_change_worse() -> None:
    old = [_f("ESC10", "dc01", Severity.MEDIUM)]
    new = [_f("ESC10", "dc01", Severity.HIGH)]
    report = diff_findings(old, new)
    assert report.new == ()
    assert report.resolved == ()
    assert len(report.changed) == 1
    delta = report.changed[0]
    assert delta.old.severity == Severity.MEDIUM
    assert delta.new.severity == Severity.HIGH
    assert delta.worsened is True
    assert report.regressions is True


def test_diff_severity_change_better_is_not_regression() -> None:
    old = [_f("ESC10", "dc01", Severity.HIGH)]
    new = [_f("ESC10", "dc01", Severity.MEDIUM)]
    report = diff_findings(old, new)
    assert len(report.changed) == 1
    assert report.changed[0].worsened is False
    assert report.regressions is False


def test_diff_identical_snapshots_is_no_drift() -> None:
    findings = [_f("ESC1", "TemplA"), _f("ESC8", "ca01")]
    report = diff_findings(findings, list(findings))
    assert report.new == ()
    assert report.resolved == ()
    assert report.changed == ()
    assert report.unchanged == 2
    assert report.regressions is False


def test_diff_keys_on_check_and_subject() -> None:
    # Same check, different subject -> independent findings (one resolved, one new).
    old = [_f("ESC5", "objA")]
    new = [_f("ESC5", "objB")]
    report = diff_findings(old, new)
    assert {f.subject for f in report.new} == {"objB"}
    assert {f.subject for f in report.resolved} == {"objA"}


def test_diff_source_disambiguates_same_subject() -> None:
    # Two CRL_EXPIRY findings on the same issuer but different sources (e.g. two
    # CDPs) must not collapse: a newly-expired second CRL is a real new finding,
    # not "unchanged" against the first.
    old = [Finding(check="CRL_EXPIRY", severity=Severity.CRITICAL, title="t",
                   subject="LAB CA", detail="d", source="CRL from CDP-A")]
    new = [
        Finding(check="CRL_EXPIRY", severity=Severity.CRITICAL, title="t",
                subject="LAB CA", detail="d", source="CRL from CDP-A"),
        Finding(check="CRL_EXPIRY", severity=Severity.CRITICAL, title="t",
                subject="LAB CA", detail="d", source="CRL from CDP-B"),
    ]
    report = diff_findings(old, new)
    assert len(report.new) == 1
    assert report.new[0].source == "CRL from CDP-B"
    assert report.unchanged == 1
    assert report.regressions is True


def test_diff_source_change_is_new_and_resolved_not_content() -> None:
    # A source change is a new+resolved pair (source is part of the identity),
    # not a content change on the same issue.
    old = [_f("ESC1", "TemplA")]
    new = [Finding(check="ESC1", severity=Severity.HIGH, title="ESC1 on TemplA",
                  subject="TemplA", detail="d", source="new source")]
    report = diff_findings(old, new)
    assert report.changed == ()
    assert len(report.new) == 1
    assert len(report.resolved) == 1


def test_diff_identity_contract() -> None:
    """Drift identity: (check, variant, any stable object alias); legacy fallback.

    Detector findings carry ``object_ids`` built from stable attributes (OID /
    cn / CA name / DN / cert fingerprint), so presentation edits (display name,
    config string, source wording) are content changes, never a false
    resolved+new pair. Findings without aliases fall back to (subject, source).
    """
    from adcs_lens.diff import _keys

    f = Finding(
        check="C", severity=Severity.HIGH, title="t", subject="S", detail="d", source="SRC"
    )
    assert _keys(f) == [("C", "", "legacy:S\x00SRC")]
    g = Finding(
        check="ESC4", severity=Severity.HIGH, title="t", subject="Display", detail="d",
        source="x", object_ids=("template-oid:1.2", "template:cn"), variant="owner",
    )
    assert _keys(g) == [("ESC4", "owner", "template-oid:1.2"), ("ESC4", "owner", "template:cn")]


def test_presentation_change_is_content_change_not_resolution() -> None:
    old = [Finding(check="ESC1", severity=Severity.CRITICAL, title="t", subject="Old Name",
                   detail="d", source="template 'A'", object_ids=("template-oid:1.2",))]
    new = [Finding(check="ESC1", severity=Severity.CRITICAL, title="t", subject="New Name",
                   detail="d", source="template 'B'", object_ids=("template-oid:1.2",))]
    report = diff_findings(old, new)
    assert report.resolved == () and report.new == ()
    assert [d.content_changed for d in report.changed] == [True]
    assert report.regressions is False


def test_diff_new_findings_sorted_worst_first() -> None:
    old: list[Finding] = []
    new = [_f("ESCx", "s1", Severity.LOW), _f("ESCy", "s2", Severity.CRITICAL)]
    report = diff_findings(old, new)
    assert [f.severity for f in report.new] == [Severity.CRITICAL, Severity.LOW]


# --- CLI ---------------------------------------------------------------------


def test_cli_diff_no_drift_identical_exports(
    json_export: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rc = main(["diff", str(json_export), str(json_export), "--json"])
    assert rc == 0
    env = json.loads(capsys.readouterr().out)
    assert env["kind"] == "diff"
    assert env["schema_version"] == 4
    assert env["summary"]["new"] == 0
    assert env["summary"]["resolved"] == 0
    assert env["summary"]["regressions"] is False


def test_cli_diff_regressions_against_empty_baseline(
    json_export: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # An (effectively empty) baseline vs the populated fixture -> the fixture's
    # findings all read as new regressions; --exit-code trips.
    baseline = build_minimal_export(tmp_path / "empty")
    rc = main(["diff", str(baseline), str(json_export), "--exit-code"])
    assert rc == 1
    out = capsys.readouterr().out
    assert "new" in out
    assert "ESC6" in out  # the fixture's CRITICAL surfaces as a new finding


def test_cli_diff_exit_code_ignores_degradation_notes(
    json_export: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # A degradation note (coverage-gap INFO) is a coverage signal, not a posture
    # regression. An empty baseline vs the populated fixture yields the fixture's
    # real findings as new regressions (trips --exit-code); but the reverse —
    # populated fixture vs an empty export that only emits degrade notes — must
    # NOT trip --exit-code on those notes alone. We assert the empty-export path
    # produces degrade notes that are visible but do not gate.
    # Empty export with passes skipped -> degrade notes only.
    empty = build_minimal_export(
        tmp_path / "empty",
        skipped_passes=("certs", "enrollment-endpoints", "pki-acls",
                        "ca-security", "template-security"),
    )
    rc = main(["diff", str(json_export), str(empty), "--json", "--exit-code"])
    env = json.loads(capsys.readouterr().out)
    # The JSON summary's `regressions` flag agrees with the gate (both exclude
    # degradation notes) — no display-vs-gate inconsistency.
    assert env["summary"]["regressions"] is False
    # The degrade notes are surfaced as coverage-state transitions (visible, not
    # dropped, and never listed as new posture or as resolved).
    assert any(
        c["check"].endswith("_NOT_EVALUATED") and c["direction"] == "appeared"
        for c in env["coverage_changes"]
    )
    assert not any(f["check"].endswith("_NOT_EVALUATED") for f in env["new"])
    # The skipped passes' findings are withheld, not resolved, so the gate
    # reports coverage loss (3) rather than a clean run (0).
    assert env["summary"]["coverage_lost"] is True
    assert {"ESC5", "ESC7", "ESC8", "ESC1"} & {f["check"] for f in env["indeterminate"]}
    assert rc == 3


def test_cli_diff_available_empty_to_missing_does_not_resolve_orphans(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    old_export = build_export(tmp_path / "old")
    new_export = build_export(tmp_path / "new")
    (old_export / "enrollment-services.json").write_text("{}", encoding="utf-8")
    (new_export / "enrollment-services.json").unlink()
    _skip(new_export, "certs", "enrollment-services")
    for export in (old_export, new_export):
        templates_path = export / "templates.json"
        templates = json.loads(templates_path.read_text(encoding="utf-8"))
        templates[0]["ekus"] = ["1.3.6.1.5.5.7.3.2"]  # Client Authentication -> ESC1
        templates_path.write_text(json.dumps(templates), encoding="utf-8")

    assert main(["diff", str(old_export), str(new_export), "--json"]) == 0
    envelope = json.loads(capsys.readouterr().out)
    assert not any(f["check"] == "ORPHANED_TEMPLATE" for f in envelope["resolved"])
    assert any(f["check"] == "ORPHANED_TEMPLATE" for f in envelope["indeterminate"])
    esc1_delta = next(f for f in envelope["changed"] if f["check"] == "ESC1")
    assert esc1_delta["old_severity"] == Severity.CRITICAL.value
    assert esc1_delta["new_severity"] == Severity.CRITICAL.value

    old_esc = {
        (f.check, f.subject, f.severity)
        for f in run_all(ingest(old_export))
        if f.check.startswith("ESC")
    }
    new_esc = {
        (f.check, f.subject, f.severity)
        for f in run_all(ingest(new_export))
        if f.check.startswith("ESC")
    }
    assert new_esc == old_esc


def test_cli_diff_missing_to_available_empty_reports_new_orphans(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    old_export = build_export(tmp_path / "old")
    new_export = build_export(tmp_path / "new")
    (old_export / "enrollment-services.json").unlink()
    _skip(old_export, "certs", "enrollment-services")
    (new_export / "enrollment-services.json").write_text("{}", encoding="utf-8")

    assert main(["diff", str(old_export), str(new_export), "--json"]) == 0
    envelope = json.loads(capsys.readouterr().out)
    new_orphans = [f for f in envelope["new"] if f["check"] == "ORPHANED_TEMPLATE"]
    assert len(new_orphans) == 6
    assert all(f["severity"] == Severity.LOW.value for f in new_orphans)
    assert not any(f["check"] == "ORPHANED_TEMPLATE" for f in envelope["resolved"])


def test_cli_diff_reports_real_orphan_resolution_when_coverage_remains_available(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    old_export = build_export(tmp_path / "old")
    new_export = build_export(tmp_path / "new")
    (old_export / "enrollment-services.json").write_text("{}", encoding="utf-8")

    assert main(["diff", str(old_export), str(new_export), "--json"]) == 0
    envelope = json.loads(capsys.readouterr().out)
    resolved_orphans = [
        f for f in envelope["resolved"] if f["check"] == "ORPHANED_TEMPLATE"
    ]
    assert len(resolved_orphans) == 1
    assert resolved_orphans[0]["subject"] == "Lab Web Server"
    assert resolved_orphans[0]["severity"] == Severity.LOW.value


def test_cli_diff_text_renders_no_drift(
    json_export: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["diff", str(json_export), str(json_export)]) == 0
    assert "no drift" in capsys.readouterr().out


def test_cli_diff_json_new_findings_embed_consequence(
    json_export: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    baseline = build_minimal_export(tmp_path / "empty")
    rc = main(["diff", str(baseline), str(json_export), "--json"])
    assert rc == 0
    env = json.loads(capsys.readouterr().out)
    assert env["summary"]["new"] > 0
    for f in env["new"]:
        assert "consequence" in f
        assert isinstance(f["consequence"], dict)
        assert "summary" in f["consequence"]
        assert "consequence" in f["consequence"]
        assert "remediation" in f["consequence"]


def test_cli_diff_text_new_finding_shows_plain_terms(
    json_export: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    baseline = build_minimal_export(tmp_path / "empty")
    assert main(["diff", str(baseline), str(json_export)]) == 0
    out = capsys.readouterr().out
    assert "in plain terms:" in out
    assert "how to fix:" in out


def test_diff_detects_content_change_same_severity() -> None:
    old = [_f("ESC1", "TemplA")]
    new = [
        Finding(
            check="ESC1",
            severity=Severity.HIGH,
            title="ESC1 on TemplA",
            subject="TemplA",
            detail="new detail",
            source="s",
        )
    ]
    report = diff_findings(old, new)
    assert len(report.changed) == 1
    delta = report.changed[0]
    assert delta.worsened is False
    assert delta.content_changed is True
    assert report.regressions is False
    assert report.unchanged == 0


def test_diff_identical_content_is_unchanged() -> None:
    old = [_f("ESC1", "TemplA")]
    new = [_f("ESC1", "TemplA")]
    report = diff_findings(old, new)
    assert report.changed == ()
    assert report.unchanged == 1
    assert report.regressions is False


def test_content_change_does_not_trip_diff_exit_code(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = diff_findings(
        old=[_f("ESC1", "TemplA", Severity.HIGH)],
        new=[Finding(
            check="ESC1",
            severity=Severity.HIGH,
            title="ESC1 on TemplA",
            subject="TemplA",
            detail="wider enroller set",
            source="s",
        )],
    )
    assert report.regressions is False
    out = render_diff_text(report)
    assert "[~ CHANGED]" in out


def test_diff_json_emits_content_changed_field() -> None:
    # The --json diff envelope must surface content-only changes with a
    # content_changed flag so a CI consumer can distinguish them from
    # severity changes (WI-028).
    report = diff_findings(
        old=[_f("ESC1", "TemplA", Severity.HIGH)],
        new=[
            Finding(
                check="ESC1",
                severity=Severity.HIGH,
                title="ESC1 on TemplA",
                subject="TemplA",
                detail="changed detail",
                source="s",
            )
        ],
    )
    env = json.loads(render_diff_json(report))
    assert len(env["changed"]) == 1
    entry = env["changed"][0]
    assert entry["worsened"] is False
    assert entry["content_changed"] is True


def test_render_diff_sarif_empty_report() -> None:
    report = diff_findings([], [])
    doc = json.loads(render_diff_sarif(report))
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["results"] == []
    assert doc["runs"][0]["tool"]["driver"]["rules"] == []


def test_render_diff_sarif_new_finding_is_error() -> None:
    report = diff_findings([], [_f("ESC8", "ca01", Severity.HIGH)])
    doc = json.loads(render_diff_sarif(report))
    results = doc["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["level"] == "error"
    assert results[0]["ruleId"] == "ESC8"
    assert results[0]["locations"][0]["physicalLocation"]["artifactLocation"][
        "uri"
    ].startswith("file:///adcs-lens/")


def test_render_diff_sarif_uses_severity_mapping_for_worsened_and_resolved() -> None:
    # MEDIUM -> HIGH is a worsened drift; the new finding's severity (HIGH)
    # maps to SARIF "error".
    old = [_f("ESC10", "dc01", Severity.MEDIUM)]
    new = [_f("ESC10", "dc01", Severity.HIGH)]
    report = diff_findings(old, new)
    doc = json.loads(render_diff_sarif(report))
    results = doc["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["level"] == "error"

    # A fully resolved LOW finding maps to SARIF "note" via _SARIF_LEVEL.
    report = diff_findings([_f("ESC10", "dc01", Severity.LOW)], [])
    doc = json.loads(render_diff_sarif(report))
    results = doc["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["level"] == "note"


def test_render_diff_sarif_baseline_state() -> None:
    # New finding -> baselineState "new"
    report = diff_findings([], [_f("ESC8", "ca01", Severity.HIGH)])
    doc = json.loads(render_diff_sarif(report))
    assert doc["runs"][0]["results"][0]["baselineState"] == "new"

    # Resolved finding -> baselineState "absent"
    report = diff_findings([_f("ESC8", "ca01", Severity.HIGH)], [])
    doc = json.loads(render_diff_sarif(report))
    assert doc["runs"][0]["results"][0]["baselineState"] == "absent"

    # Changed finding -> baselineState "updated"
    old = [_f("ESC10", "dc01", Severity.MEDIUM)]
    new = [_f("ESC10", "dc01", Severity.HIGH)]
    report = diff_findings(old, new)
    doc = json.loads(render_diff_sarif(report))
    assert doc["runs"][0]["results"][0]["baselineState"] == "updated"


def test_render_diff_sarif_content_change_uses_new_severity() -> None:
    report = diff_findings(
        old=[_f("ESC1", "TemplA", Severity.LOW)],
        new=[
            Finding(
                check="ESC1",
                severity=Severity.MEDIUM,
                title="ESC1 on TemplA",
                subject="TemplA",
                detail="changed detail",
                source="s",
            )
        ],
    )
    doc = json.loads(render_diff_sarif(report))
    results = doc["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["level"] == "warning"


def test_render_diff_sarif_rules_deduplicated_sorted() -> None:
    report = diff_findings(
        [],
        [
            _f("ESC8", "ca01", Severity.HIGH),
            _f("ESC1", "TemplA", Severity.CRITICAL),
            _f("ESC8", "ca02", Severity.HIGH),
        ],
    )
    doc = json.loads(render_diff_sarif(report))
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    assert [r["id"] for r in rules] == ["ESC1", "ESC8"]


def test_render_diff_sarif_is_deterministic() -> None:
    report = diff_findings([], [_f("ESC1", "TemplA", Severity.HIGH)])
    first = render_diff_sarif(report)
    second = render_diff_sarif(report)
    assert first == second


def test_render_diff_html_selfcontained_document() -> None:
    report = diff_findings([], [_f("ESC1", "TemplA", Severity.HIGH)])
    out = render_diff_html(report)
    assert out.startswith("<!DOCTYPE html>")
    assert out.rstrip().endswith("</html>")
    assert "<style>" in out
    assert '<link rel="stylesheet"' not in out


def test_render_diff_html_summary_counts() -> None:
    report = diff_findings(
        old=[_f("ESC8", "ca01", Severity.HIGH)],
        new=[_f("ESC1", "TemplA", Severity.CRITICAL)],
    )
    out = render_diff_html(report)
    assert "+1 new" in out
    assert "-1 resolved" in out
    assert "~0 changed" in out
    assert "=0 unchanged" in out


def test_render_diff_html_new_finding_has_badge_and_consequence() -> None:
    report = diff_findings([], [_f("ESC1", "TemplA", Severity.CRITICAL)])
    out = render_diff_html(report)
    assert 'class="diff-badge new"' in out
    assert "New" in out
    assert "In plain terms." in out
    assert "How to fix." in out


def test_render_diff_html_changed_finding_shows_worsened_badge() -> None:
    old = [_f("ESC10", "dc01", Severity.MEDIUM)]
    new = [_f("ESC10", "dc01", Severity.HIGH)]
    report = diff_findings(old, new)
    out = render_diff_html(report)
    assert 'class="diff-badge worsened"' in out
    assert "medium &rarr; high" in out


def test_cli_diff_sarif_and_json_mutually_exclusive(
    json_export: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["diff", str(json_export), str(json_export), "--sarif", "--json"])
    assert exc_info.value.code == 2
    assert "not allowed with" in capsys.readouterr().err


def test_cli_diff_html_and_sarif_mutually_exclusive(
    json_export: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["diff", str(json_export), str(json_export), "--html", "--sarif"])
    assert exc_info.value.code == 2
    assert "not allowed with" in capsys.readouterr().err


def test_cli_diff_sarif_renders_on_identical_exports(
    json_export: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rc = main(["diff", str(json_export), str(json_export), "--sarif"])
    assert rc == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["results"] == []


def test_cli_diff_html_renders_on_identical_exports(
    json_export: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rc = main(["diff", str(json_export), str(json_export), "--html"])
    assert rc == 0
    out = capsys.readouterr().out
    assert out.startswith("<!DOCTYPE html>")
    assert "No drift" in out
