"""The `doctor` / `ingest` CLI front door over the synthetic export."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from adcs_lens.cli import main
from adcs_lens.model import Severity
from tests.fixtures.build_fixture import build_minimal_export


def test_doctor_json_flags_esc6(json_export: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["doctor", str(json_export), "--json"])
    assert rc == 0
    envelope = json.loads(capsys.readouterr().out)
    assert envelope["kind"] == "doctor"
    assert envelope["schema_version"] == 4
    checks = {f["check"] for f in envelope["findings"]}
    assert "ESC6" in checks
    # The fixture template sets NO_SECURITY_EXTENSION -> ESC9 surfaces end-to-end.
    assert "ESC9" in checks
    # The fixture grants Domain Users Manage Certificates on the issuing CA -> ESC7.
    assert "ESC7" in checks
    # The fixture issuing CA has szOID_NTDS_CA_SECURITY_EXT in DisableExtensionList
    # -> ESC16 surfaces end-to-end (ingest -> field -> detector).
    assert "ESC16" in checks
    # The fixture CDP container's DACL is unreadable (acl_obtained=False)
    # -> the PKI_ACL_UNREADABLE gap note surfaces end-to-end, and ESC5 skips it.
    assert "PKI_ACL_UNREADABLE" in checks
    assert not any(
        f["check"] == "ESC5" and "CDP" in f["subject"] for f in envelope["findings"]
    )
    esc6 = next(f for f in envelope["findings"] if f["check"] == "ESC6")
    assert esc6["severity"] == Severity.CRITICAL.value
    assert isinstance(esc6["consequence"], dict)
    assert "summary" in esc6["consequence"]
    assert "consequence" in esc6["consequence"]
    assert "remediation" in esc6["consequence"]


def test_doctor_text_renders(json_export: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["doctor", str(json_export)]) == 0
    out = capsys.readouterr().out
    assert "adcs-lens doctor" in out
    assert "ESC6" in out


def test_ingest_summary(json_export: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["ingest", str(json_export)]) == 0
    out = capsys.readouterr().out
    assert "CAs: 2" in out
    assert "lab.example.com" in out


def test_cli_reports_malformed_export(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (tmp_path / "collector-manifest.json").write_text("not json", encoding="utf-8")
    rc = main(["doctor", str(tmp_path)])
    assert rc != 0
    assert "malformed JSON" in capsys.readouterr().err


def test_old_collector_warns_on_stderr(
    json_export: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # A pre-minimum collector may omit fields detectors branch on -> visible warning.
    manifest_path = json_export / "collector-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    manifest["collector_version"] = "0.4.0"
    manifest_path.write_text(json.dumps(manifest))
    assert main(["doctor", str(json_export)]) == 0
    err = capsys.readouterr().err
    assert "warning" in err
    assert "0.4.0" in err


def test_current_collector_is_silent_on_stderr(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # A fresh export (collected now) from a current collector warns about nothing.
    # (The shared json_export is pinned to a fixed past date, so it is stale.)
    from tests.fixtures.build_fixture import build_export

    assert main(["ingest", str(build_export(tmp_path / "fresh"))]) == 0
    assert capsys.readouterr().err == ""


def test_doctor_severity_floor_excludes_below_threshold(
    json_export: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # A 'high' floor keeps critical+high and drops everything below (the INFO
    # degradation notes in particular). The fixture's CRITICAL ESC6 survives.
    rc = main(["doctor", str(json_export), "--json", "--severity", "high"])
    assert rc == 0
    findings = json.loads(capsys.readouterr().out)["findings"]
    severities = {f["severity"] for f in findings}
    assert severities <= {Severity.CRITICAL.value, Severity.HIGH.value}
    assert any(f["check"] == "ESC6" for f in findings)


def test_doctor_exit_code_trips_when_finding_meets_threshold(json_export: Path) -> None:
    # The fixture has a CRITICAL ESC6, so a 'critical' floor with --exit-code
    # must signal non-zero for CI gating.
    assert main(["doctor", str(json_export), "--exit-code", "--severity", "critical"]) == 1


def test_doctor_exit_code_clean_when_nothing_meets_threshold(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # An (effectively empty) export yields only INFO notes; a 'high' floor leaves
    # zero findings, so --exit-code stays zero.
    rc = main(["doctor", str(build_minimal_export(tmp_path)), "--exit-code", "--severity", "high"])
    assert rc == 0
    # Sanity: without the floor the INFO notes are present (default floor = info).
    capsys.readouterr()


def test_doctor_exit_code_clean_with_only_degradation_note(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Default severity floor includes INFO. An empty export emits only
    # CA_AUDIT_NOT_EVALUATED, which must be shown but must not trip the
    # --exit-code gate.
    rc = main(["doctor", str(build_minimal_export(tmp_path)), "--exit-code"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "CA_AUDIT_NOT_EVALUATED" in out


def test_degradation_note_shown_in_json_but_not_gated(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # The "shown but not gated" contract (WI-030) must hold for --json too,
    # the format a CI pipeline most likely consumes: the coverage-gap note is
    # present in the findings array while --exit-code stays zero.
    rc = main(["doctor", str(build_minimal_export(tmp_path)), "--json", "--exit-code"])
    assert rc == 0
    envelope = json.loads(capsys.readouterr().out)
    checks = {f["check"] for f in envelope["findings"]}
    assert "CA_AUDIT_NOT_EVALUATED" in checks


def test_doctor_exit_code_without_flag_stays_zero(json_export: Path) -> None:
    # Findings exist, but absent --exit-code the command still reports success.
    assert main(["doctor", str(json_export)]) == 0


def test_doctor_suppressions_filter_and_exit_code(
    json_export: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # The fixture has two CRITICAL findings on the issuing CA (ESC6 and
    # CA_AUDIT_DISABLED). Suppressing both should remove them from the output
    # and keep --exit-code clean at 'critical'.
    supp = tmp_path / "suppressions.json"
    supp.write_text(
        json.dumps(
            {
                "suppressions": [
                    {
                        "check": "ESC6",
                        "subject": "LAB Issuing CA",
                        "reason": "legacy flag accepted by CAB",
                        "expires": "2026-12-31",
                    },
                    {
                        "check": "CA_AUDIT_DISABLED",
                        "subject": "LAB Issuing CA",
                        "reason": "audit handled by separate SOC pipeline",
                        "expires": "2026-12-31",
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    rc = main(
        [
            "doctor",
            str(json_export),
            "--json",
            "--exit-code",
            "--severity",
            "critical",
            "--suppressions",
            str(supp),
        ]
    )
    captured = capsys.readouterr()
    assert rc == 0
    out = json.loads(captured.out)
    checks = {f["check"] for f in out["findings"]}
    assert "ESC6" not in checks
    assert "CA_AUDIT_DISABLED" not in checks
    assert "suppressed" in captured.err
    assert "[ESC6]" in captured.err


def test_doctor_suppressions_invalid_file(
    json_export: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    supp = tmp_path / "bad.json"
    supp.write_text("not json", encoding="utf-8")
    rc = main(["doctor", str(json_export), "--suppressions", str(supp)])
    assert rc != 0
    assert "malformed JSON" in capsys.readouterr().err


def test_doctor_narrate_prints_executive_summary_to_stderr(
    json_export: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rc = main(["doctor", str(json_export), "--narrate"])
    captured = capsys.readouterr()
    assert rc == 0
    assert "EXECUTIVE SUMMARY" in captured.err
    assert "adcs-lens doctor" in captured.out


def test_doctor_suppressions_expired_rule_warns(
    json_export: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    supp = tmp_path / "supp.json"
    supp.write_text(
        json.dumps(
            {
                "suppressions": [
                    {
                        "check": "ESC6",
                        "subject": "LAB Issuing CA",
                        "reason": "expired acceptance",
                        "expires": "2025-01-01",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    rc = main(["doctor", str(json_export), "--json", "--suppressions", str(supp)])
    captured = capsys.readouterr()
    assert rc == 0
    out = json.loads(captured.out)
    # The expired rule did not suppress ESC6, so it remains in the output.
    assert any(f["check"] == "ESC6" for f in out["findings"])
    assert "expired" in captured.err
    assert "2025-01-01" in captured.err


def test_doctor_json_includes_suppression_summary(
    json_export: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    supp = tmp_path / "suppressions.json"
    supp.write_text(
        json.dumps(
            {
                "suppressions": [
                    {
                        "check": "ESC6",
                        "subject": "LAB Issuing CA",
                        "reason": "legacy flag accepted by CAB",
                        "expires": "2026-12-31",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    rc = main(["doctor", str(json_export), "--json", "--suppressions", str(supp)])
    captured = capsys.readouterr()
    assert rc == 0
    envelope = json.loads(captured.out)
    assert "suppressions" in envelope
    summary = envelope["suppressions"]
    assert summary["suppressed_count"] == 1
    assert summary["suppressed"][0] == {
        "check": "ESC6",
        "subject": "LAB Issuing CA",
        "reason": "legacy flag accepted by CAB",
    }
    assert summary["expired_count"] == 0
    assert summary["warnings"] == []
    # The suppressed finding is not in the findings array.
    assert not any(f["check"] == "ESC6" for f in envelope["findings"])


def test_doctor_narrate_uses_post_suppression_findings(
    json_export: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    supp = tmp_path / "suppressions.json"
    supp.write_text(
        json.dumps(
            {
                "suppressions": [
                    {
                        "check": "ESC6",
                        "subject": "LAB Issuing CA",
                        "reason": "legacy flag accepted by CAB",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    rc = main(["doctor", str(json_export), "--narrate", "--suppressions", str(supp)])
    captured = capsys.readouterr()
    assert rc == 0
    assert "EXECUTIVE SUMMARY" in captured.err
    # The suppression summary is on stderr too; isolate the executive summary.
    executive = captured.err.split("EXECUTIVE SUMMARY", 1)[1]
    # ESC6 on LAB Issuing CA was suppressed; the check id must not appear in narration.
    assert "ESC6" not in executive


def test_doctor_json_includes_suppressions_key_even_when_nothing_matched(
    json_export: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    supp = tmp_path / "suppressions.json"
    supp.write_text(
        json.dumps(
            {
                "suppressions": [
                    {
                        "check": "NONEXISTENT_CHECK",
                        "subject": "no-such-subject",
                        "reason": "won't match anything",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    rc = main(["doctor", str(json_export), "--json", "--suppressions", str(supp)])
    captured = capsys.readouterr()
    assert rc == 0
    envelope = json.loads(captured.out)
    assert "suppressions" in envelope
    summary = envelope["suppressions"]
    assert summary["suppressed_count"] == 0
    assert summary["suppressed"] == []
    assert summary["expired_count"] == 0
