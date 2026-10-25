"""Findings suppression / risk-acceptance for scheduled scans.

Loads a JSON suppression file and filters findings so accepted-risk items
are removed from the rendered output and do not trip the --exit-code gate.
A summary of what was suppressed (and any expired rules) is emitted on
stderr for auditability.

Pure, stdlib-only. The suppression file is the operator's documented
risk-acceptance record — each rule carries a reason and optional expiry.
A date-only ``expires`` value ("2026-12-31") keeps the rule active through
the end of that day (UTC); a full ISO datetime is honored literally
(assumed UTC when no offset is given).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, date, datetime, time
from pathlib import Path

from adcs_lens import limits
from adcs_lens.detection import Finding


@dataclass(frozen=True)
class SuppressionRule:
    """One documented risk-acceptance rule."""

    check: str
    subject: str | None
    reason: str
    expires: datetime | None


@dataclass(frozen=True)
class SuppressionResult:
    """Outcome of applying suppression rules to a set of findings."""

    suppressed: tuple[Finding, ...]
    remaining: tuple[Finding, ...]
    expired: tuple[SuppressionRule, ...]
    warnings: tuple[str, ...]


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"suppression file contains duplicate JSON key {key!r}")
        result[key] = value
    return result


def load_suppressions(path: str | Path) -> tuple[SuppressionRule, ...]:
    """Load and validate a suppression JSON file.

    Raises:
        ValueError: when the file cannot be read, contains malformed JSON, or
            lacks required fields.
    """
    p = Path(path)
    try:
        data = limits.read_bounded(p, limits.SUPPRESSIONS_MAX_BYTES, "suppression file")
        raw = json.loads(data.decode("utf-8-sig"), object_pairs_hook=_unique_object)
    except limits.InputTooLargeError:
        raise
    except UnicodeDecodeError as exc:
        raise ValueError(f"suppression file is not valid UTF-8: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"suppression file contains malformed JSON: {exc}") from exc
    except OSError as exc:
        raise ValueError(f"cannot read suppression file: {exc}") from exc

    if not isinstance(raw, dict):
        raise ValueError("suppression file must be a JSON object")

    items = raw.get("suppressions")
    if not isinstance(items, list):
        raise ValueError("suppression file must contain a 'suppressions' list")

    rules: list[SuppressionRule] = []
    for i, item in enumerate(items):
        if not isinstance(item, dict):
            raise ValueError(f"suppression entry {i} must be an object")

        check = item.get("check")
        reason = item.get("reason")
        if not isinstance(check, str) or not check.strip():
            raise ValueError(f"suppression entry {i} missing non-empty 'check'")
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError(f"suppression entry {i} missing non-empty 'reason'")
        check = check.strip()
        reason = reason.strip()

        subject = item.get("subject")
        if subject is not None:
            if not isinstance(subject, str):
                raise ValueError(f"suppression entry {i} 'subject' must be a string")
            subject = subject.strip() or None

        expires: datetime | None = None
        expires_raw = item.get("expires")
        if expires_raw is not None:
            if not isinstance(expires_raw, str):
                raise ValueError(f"suppression entry {i} 'expires' must be an ISO date string")
            try:
                # A date-only value ("2026-12-31") means the rule is valid
                # through that whole day: expire at end-of-day UTC, not at
                # the midnight that starts it.
                parsed = datetime.combine(date.fromisoformat(expires_raw), time.max, tzinfo=UTC)
            except ValueError:
                try:
                    parsed = datetime.fromisoformat(expires_raw)
                except ValueError as exc:
                    raise ValueError(
                        f"suppression entry {i} 'expires' is not a valid ISO date: {exc}"
                    ) from exc
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=UTC)
            expires = parsed

        rules.append(SuppressionRule(check=check, subject=subject, reason=reason, expires=expires))

    return tuple(rules)


def apply_suppressions(
    findings: list[Finding],
    rules: tuple[SuppressionRule, ...],
    *,
    now: datetime | None = None,
) -> SuppressionResult:
    """Apply *rules* to *findings*.

    A rule matches a finding when ``finding.check == rule.check`` and either
    ``rule.subject`` is ``None`` or it equals ``finding.subject``. The first
    matching active rule wins. Expired rules (``expires < now``) are not
    applied and are returned in ``expired`` with a warning.
    """
    if now is None:
        now = datetime.now(UTC)
    elif now.tzinfo is None:
        now = now.replace(tzinfo=UTC)

    active: list[SuppressionRule] = []
    expired: list[SuppressionRule] = []
    warnings: list[str] = []
    for rule in rules:
        if rule.expires is not None and rule.expires < now:
            expired.append(rule)
            warnings.append(
                f"suppression for {rule.check}"
                f"{' (' + rule.subject + ')' if rule.subject else ''}"
                f" expired on {rule.expires.date().isoformat()}"
            )
        else:
            active.append(rule)

    suppressed: list[Finding] = []
    remaining: list[Finding] = []
    for finding in findings:
        matched = False
        for rule in active:
            if finding.check == rule.check and (
                rule.subject is None or finding.subject == rule.subject
            ):
                suppressed.append(finding)
                matched = True
                break
        if not matched:
            remaining.append(finding)

    return SuppressionResult(
        suppressed=tuple(suppressed),
        remaining=tuple(remaining),
        expired=tuple(expired),
        warnings=tuple(warnings),
    )


def suppression_summary(
    result: SuppressionResult,
    rules: tuple[SuppressionRule, ...] = (),
) -> dict[str, object]:
    """Build a JSON-serializable suppression summary for the JSON envelope."""

    def _reason_for(finding: Finding) -> str:
        for rule in rules:
            if rule in result.expired:
                continue
            if finding.check == rule.check and (
                rule.subject is None or finding.subject == rule.subject
            ):
                return rule.reason
        return ""

    return {
        "suppressed_count": len(result.suppressed),
        "suppressed": [
            {"check": f.check, "subject": f.subject, "reason": _reason_for(f)}
            for f in result.suppressed
        ],
        "expired_count": len(result.expired),
        "expired": [
            {
                "check": r.check,
                "subject": r.subject,
                "reason": r.reason,
                "expires": r.expires.date().isoformat() if r.expires else None,
            }
            for r in result.expired
        ],
        "warnings": list(result.warnings),
    }


def format_suppression_summary(result: SuppressionResult) -> str:
    """Return a human-readable summary of suppressed findings and expired rules."""
    lines: list[str] = []
    if result.suppressed:
        lines.append(f"suppressed {len(result.suppressed)} finding(s) by risk-acceptance rules:")
        for finding in result.suppressed:
            lines.append(f"  [{finding.check}] {finding.subject}")
    if result.expired:
        lines.append(f"{len(result.expired)} suppression rule(s) expired and were ignored:")
        for rule in result.expired:
            lines.append(
                f"  [{rule.check}]"
                f"{' subject=' + rule.subject if rule.subject else ' (all subjects)'}"
                f" expired on {rule.expires.date().isoformat() if rule.expires else 'unknown'}"
            )
    if not lines:
        return ""
    return "\n".join(lines)
