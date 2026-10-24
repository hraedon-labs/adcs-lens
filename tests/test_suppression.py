"""Tests for the findings suppression / risk-acceptance module."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from adcs_lens.detection import Finding
from adcs_lens.model import Severity
from adcs_lens.suppression import (
    SuppressionResult,
    SuppressionRule,
    apply_suppressions,
    format_suppression_summary,
    load_suppressions,
    suppression_summary,
)

NOW = datetime(2026, 6, 15, 12, 0, 0, tzinfo=UTC)


def _finding(
    check: str = "ESC8",
    subject: str = "/CertSrv",
    severity: Severity = Severity.HIGH,
    title: str = "test",
    detail: str = "detail",
    source: str = "source",
) -> Finding:
    return Finding(
        check=check,
        severity=severity,
        title=title,
        subject=subject,
        detail=detail,
        source=source,
    )


def _write_suppressions(path: Path, obj: object) -> None:
    path.write_text(json.dumps(obj), encoding="utf-8")


def test_load_valid_suppressions(tmp_path: Path) -> None:
    path = tmp_path / "suppressions.json"
    _write_suppressions(
        path,
        {
            "suppressions": [
                {"check": "ESC8", "subject": "/CertSrv", "reason": "behind ACL"},
                {"check": "ESC15", "reason": "patched", "expires": "2026-12-31"},
            ]
        },
    )
    rules = load_suppressions(path)
    assert len(rules) == 2
    assert rules[0] == SuppressionRule(
        check="ESC8",
        subject="/CertSrv",
        reason="behind ACL",
        expires=None,
    )
    assert rules[1].check == "ESC15"
    assert rules[1].subject is None
    assert rules[1].reason == "patched"
    # Date-only expiry means "valid through that whole day": end-of-day UTC.
    assert rules[1].expires == datetime(2026, 12, 31, 23, 59, 59, 999999, tzinfo=UTC)


def test_load_suppressions_written_with_a_powershell_utf8_bom(tmp_path: Path) -> None:
    path = tmp_path / "suppressions.json"
    path.write_text(
        json.dumps({"suppressions": [{"check": "ESC8", "reason": "reviewed exception"}]}),
        encoding="utf-8-sig",
    )
    assert load_suppressions(path) == (
        SuppressionRule(check="ESC8", subject=None, reason="reviewed exception", expires=None),
    )


def test_load_date_only_expires_is_active_through_that_day(tmp_path: Path) -> None:
    path = tmp_path / "suppressions.json"
    _write_suppressions(
        path,
        {"suppressions": [{"check": "ESC8", "reason": "x", "expires": "2026-12-31"}]},
    )
    (rule,) = load_suppressions(path)
    finding = _finding(check="ESC8")
    # Midday on the expiry date: the rule must still suppress.
    result = apply_suppressions(
        [finding], (rule,), now=datetime(2026, 12, 31, 12, 0, 0, tzinfo=UTC)
    )
    assert result.suppressed == (finding,)
    assert result.expired == ()
    # The following day: expired.
    result = apply_suppressions([finding], (rule,), now=datetime(2027, 1, 1, 0, 0, 0, tzinfo=UTC))
    assert result.suppressed == ()
    assert result.expired == (rule,)


def test_load_datetime_expires_is_preserved(tmp_path: Path) -> None:
    path = tmp_path / "suppressions.json"
    _write_suppressions(
        path,
        {"suppressions": [{"check": "ESC8", "reason": "x", "expires": "2026-12-31T08:30:00"}]},
    )
    (rule,) = load_suppressions(path)
    # An explicit time component is taken literally (assumed UTC when naive).
    assert rule.expires == datetime(2026, 12, 31, 8, 30, 0, tzinfo=UTC)


def test_load_missing_suppressions_key(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    _write_suppressions(path, {"ignored": []})
    with pytest.raises(ValueError, match="suppressions"):
        load_suppressions(path)


def test_load_missing_check(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    _write_suppressions(path, {"suppressions": [{"reason": "x"}]})
    with pytest.raises(ValueError, match="missing non-empty 'check'"):
        load_suppressions(path)


def test_load_missing_reason(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    _write_suppressions(path, {"suppressions": [{"check": "ESC8"}]})
    with pytest.raises(ValueError, match="missing non-empty 'reason'"):
        load_suppressions(path)


def test_load_malformed_json(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("not json", encoding="utf-8")
    with pytest.raises(ValueError, match="malformed JSON"):
        load_suppressions(path)


def test_load_non_object_suppressions(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    _write_suppressions(path, [])
    with pytest.raises(ValueError, match="JSON object"):
        load_suppressions(path)


def test_load_invalid_subject_type(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    _write_suppressions(
        path,
        {"suppressions": [{"check": "ESC8", "subject": 123, "reason": "x"}]},
    )
    with pytest.raises(ValueError, match="subject' must be a string"):
        load_suppressions(path)


def test_load_invalid_expires_type(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    _write_suppressions(
        path,
        {"suppressions": [{"check": "ESC8", "reason": "x", "expires": 2026}]},
    )
    with pytest.raises(ValueError, match="expires' must be an ISO date string"):
        load_suppressions(path)


def test_load_invalid_expires_format(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    _write_suppressions(
        path,
        {"suppressions": [{"check": "ESC8", "reason": "x", "expires": "not-a-date"}]},
    )
    with pytest.raises(ValueError, match="not a valid ISO date"):
        load_suppressions(path)


def test_apply_exact_match() -> None:
    finding = _finding(check="ESC8", subject="/CertSrv")
    rule = SuppressionRule(check="ESC8", subject="/CertSrv", reason="x", expires=None)
    result = apply_suppressions([finding], (rule,), now=NOW)
    assert result.suppressed == (finding,)
    assert result.remaining == ()
    assert result.expired == ()
    assert result.warnings == ()


def test_apply_check_only_match() -> None:
    a = _finding(check="ESC8", subject="/CertSrv")
    b = _finding(check="ESC8", subject="/Other")
    c = _finding(check="ESC6", subject="CA")
    rule = SuppressionRule(check="ESC8", subject=None, reason="x", expires=None)
    result = apply_suppressions([a, b, c], (rule,), now=NOW)
    assert result.suppressed == (a, b)
    assert result.remaining == (c,)


def test_apply_subject_mismatch_passes_through() -> None:
    finding = _finding(check="ESC8", subject="/Other")
    rule = SuppressionRule(check="ESC8", subject="/CertSrv", reason="x", expires=None)
    result = apply_suppressions([finding], (rule,), now=NOW)
    assert result.suppressed == ()
    assert result.remaining == (finding,)


def test_apply_expired_rule_not_applied() -> None:
    finding = _finding(check="ESC8", subject="/CertSrv")
    expired = SuppressionRule(
        check="ESC8",
        subject="/CertSrv",
        reason="old",
        expires=datetime(2025, 1, 1, tzinfo=UTC),
    )
    active = SuppressionRule(
        check="ESC8",
        subject=None,
        reason="current",
        expires=None,
    )
    result = apply_suppressions([finding], (expired, active), now=NOW)
    assert result.suppressed == (finding,)
    assert result.remaining == ()
    assert result.expired == (expired,)
    assert len(result.warnings) == 1
    assert "expired on 2025-01-01" in result.warnings[0]


def test_apply_expired_date_only() -> None:
    finding = _finding(check="ESC8", subject="/CertSrv")
    rule = SuppressionRule(
        check="ESC8",
        subject="/CertSrv",
        reason="old",
        expires=datetime(2025, 1, 1, tzinfo=UTC),
    )
    result = apply_suppressions([finding], (rule,), now=NOW)
    assert result.suppressed == ()
    assert result.remaining == (finding,)
    assert result.expired == (rule,)


def test_apply_multiple_rules_first_match_wins() -> None:
    finding = _finding(check="ESC8", subject="/CertSrv")
    first = SuppressionRule(check="ESC8", subject="/CertSrv", reason="first", expires=None)
    second = SuppressionRule(check="ESC8", subject=None, reason="second", expires=None)
    result = apply_suppressions([finding], (first, second), now=NOW)
    assert result.suppressed == (finding,)
    assert result.remaining == ()


def test_apply_no_match_passes_through() -> None:
    finding = _finding(check="ESC6", subject="CA")
    rule = SuppressionRule(check="ESC8", subject=None, reason="x", expires=None)
    result = apply_suppressions([finding], (rule,), now=NOW)
    assert result.suppressed == ()
    assert result.remaining == (finding,)


def test_format_summary_with_suppressed() -> None:
    f = _finding(check="ESC8", subject="/CertSrv")
    result = SuppressionResult(
        suppressed=(f,),
        remaining=(),
        expired=(),
        warnings=(),
    )
    summary = format_suppression_summary(result)
    assert "suppressed 1 finding(s)" in summary
    assert "[ESC8] /CertSrv" in summary


def test_format_summary_with_expired() -> None:
    rule = SuppressionRule(
        check="ESC8",
        subject="/CertSrv",
        reason="old",
        expires=datetime(2025, 1, 1, tzinfo=UTC),
    )
    result = SuppressionResult(
        suppressed=(),
        remaining=(_finding(check="ESC8"),),
        expired=(rule,),
        warnings=("expired",),
    )
    summary = format_suppression_summary(result)
    assert "1 suppression rule(s) expired" in summary
    assert "[ESC8]" in summary


def test_format_summary_empty() -> None:
    result = SuppressionResult(
        suppressed=(),
        remaining=(),
        expired=(),
        warnings=(),
    )
    assert format_suppression_summary(result) == ""


def test_load_from_path_string(tmp_path: Path) -> None:
    path = tmp_path / "supp.json"
    _write_suppressions(
        path,
        {"suppressions": [{"check": "ESC6", "reason": "legacy"}]},
    )
    rules = load_suppressions(str(path))
    assert len(rules) == 1
    assert rules[0].check == "ESC6"


def test_suppression_summary_structure() -> None:
    f = _finding(check="ESC8", subject="/CertSrv")
    rule = SuppressionRule(
        check="ESC8", subject="/CertSrv", reason="behind ACL", expires=None
    )
    expired_rule = SuppressionRule(
        check="ESC15",
        subject=None,
        reason="patched",
        expires=datetime(2025, 1, 1, tzinfo=UTC),
    )
    result = SuppressionResult(
        suppressed=(f,),
        remaining=(),
        expired=(expired_rule,),
        warnings=("expired",),
    )
    summary = suppression_summary(result, (rule, expired_rule))
    assert summary["suppressed_count"] == 1
    assert summary["suppressed"][0] == {
        "check": "ESC8",
        "subject": "/CertSrv",
        "reason": "behind ACL",
    }
    assert summary["expired_count"] == 1
    assert summary["expired"][0]["check"] == "ESC15"
    assert summary["warnings"] == ["expired"]


def test_suppression_summary_skips_expired_rule_reason() -> None:
    f = _finding(check="ESC8", subject="/CertSrv")
    expired_rule = SuppressionRule(
        check="ESC8",
        subject="/CertSrv",
        reason="old expired",
        expires=datetime(2025, 1, 1, tzinfo=UTC),
    )
    active_rule = SuppressionRule(
        check="ESC8", subject="/CertSrv", reason="new active", expires=None
    )
    result = SuppressionResult(
        suppressed=(f,),
        remaining=(),
        expired=(expired_rule,),
        warnings=("expired",),
    )
    summary = suppression_summary(result, (expired_rule, active_rule))
    assert summary["suppressed"][0]["reason"] == "new active"
