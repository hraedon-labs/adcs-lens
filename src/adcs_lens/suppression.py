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

The key sets are closed. The document object may hold only ``suppressions``
and ``metadata``; a rule only ``check``, ``subject``, ``reason``, ``expires``
and ``metadata``. Any other key - including a case variant such as
``Subject`` - is refused, because an ignored typo would silently broaden a
rule (a lost ``subject``) or resurrect an expired one (a lost ``expires``).
``metadata`` is a JSON object whose contents are never interpreted (ticket
numbers, approvers, notes); only the decoder rules apply inside it. An optional
key is either omitted or a non-empty string: omitting ``subject`` is the one
way to write a check-wide rule, so a blank or ``null`` subject is refused
rather than read as that wildcard.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, date, datetime, time
from pathlib import Path

from adcs_lens import limits
from adcs_lens.detection import Finding
from adcs_lens.strict_json import (
    DuplicateKeyError,
    reject_non_json_constant,
    unique_keys_hook,
)

DOCUMENT_KEYS = ("suppressions", "metadata")
RULE_KEYS = ("check", "subject", "reason", "expires", "metadata")


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


def _check_keys(obj: dict[str, object], allowed: tuple[str, ...], where: str) -> None:
    """Refuse the first key of *obj* (in document order) that is not in *allowed*."""
    for key in obj:
        if key in allowed:
            continue
        hint = ""
        if key.casefold() in allowed:
            hint = f" (keys are case-sensitive; did you mean {key.casefold()!r}?)"
        raise ValueError(
            f"{where} has unknown key {limits.bounded_repr(key)}{hint}; "
            f"allowed keys: {', '.join(allowed)}"
        )


def _check_metadata(obj: dict[str, object], where: str) -> None:
    if "metadata" in obj and not isinstance(obj["metadata"], dict):
        raise ValueError(f"{where} 'metadata' must be a JSON object")


def load_suppressions(path: str | Path) -> tuple[SuppressionRule, ...]:
    """Load and validate a suppression JSON file.

    Raises:
        ValueError: when the file cannot be read, contains malformed or
            ambiguous JSON (duplicate keys, excessive nesting), has a key
            outside the closed key sets, or lacks or misuses a field.
    """
    p = Path(path)
    try:
        data = limits.read_bounded(p, limits.SUPPRESSIONS_MAX_BYTES, "suppression file")
        raw = json.loads(
            data.decode("utf-8-sig"),
            object_pairs_hook=unique_keys_hook,
            parse_constant=reject_non_json_constant,
        )
    except limits.InputTooLargeError:
        raise
    except UnicodeDecodeError as exc:
        raise ValueError(f"suppression file is not valid UTF-8: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"suppression file contains malformed JSON: {exc}") from exc
    except DuplicateKeyError as exc:
        raise ValueError(f"suppression file contains duplicate JSON key {exc.shown}") from exc
    except ValueError as exc:
        # The decoder's other refusals, e.g. an integer literal beyond the
        # interpreter's digit limit. Message text from CPython is bounded.
        raise ValueError(f"suppression file contains malformed JSON ({exc})") from exc
    except RecursionError as exc:
        raise ValueError("suppression file contains malformed JSON (nested too deeply)") from exc
    except OSError as exc:
        raise ValueError(f"cannot read suppression file: {exc}") from exc

    if not isinstance(raw, dict):
        raise ValueError("suppression file must be a JSON object")
    _check_keys(raw, DOCUMENT_KEYS, "suppression file")
    _check_metadata(raw, "suppression file")

    items = raw.get("suppressions")
    if not isinstance(items, list):
        raise ValueError("suppression file must contain a 'suppressions' list")

    rules: list[SuppressionRule] = []
    for i, item in enumerate(items):
        if not isinstance(item, dict):
            raise ValueError(f"suppression entry {i} must be an object")
        _check_keys(item, RULE_KEYS, f"suppression entry {i}")
        _check_metadata(item, f"suppression entry {i}")

        check = item.get("check")
        reason = item.get("reason")
        if not isinstance(check, str) or not check.strip():
            raise ValueError(f"suppression entry {i} missing non-empty 'check'")
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError(f"suppression entry {i} missing non-empty 'reason'")
        check = check.strip()
        reason = reason.strip()

        # Omitting "subject" is the documented check-wide wildcard; a present
        # subject must name something, so blank and null are refused.
        subject: str | None = None
        if "subject" in item:
            subject_raw = item["subject"]
            if not isinstance(subject_raw, str):
                raise ValueError(
                    f"suppression entry {i} 'subject' must be a string "
                    "(omit 'subject' to match every finding of the check)"
                )
            subject = subject_raw.strip()
            if not subject:
                raise ValueError(
                    f"suppression entry {i} 'subject' is blank "
                    "(omit 'subject' to match every finding of the check)"
                )

        expires: datetime | None = None
        if "expires" in item:
            expires_raw = item["expires"]
            if not isinstance(expires_raw, str):
                raise ValueError(
                    f"suppression entry {i} 'expires' must be an ISO date string "
                    "(omit 'expires' for a rule that does not expire)"
                )
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
                        f"suppression entry {i} 'expires' is not a valid ISO date: "
                        f"{limits.bounded_repr(expires_raw)}"
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
                f"suppression for {limits.bounded_text(rule.check)}"
                f"{' (' + limits.bounded_text(rule.subject) + ')' if rule.subject else ''}"
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
            if rule.subject:
                subject = " subject=" + limits.bounded_text(rule.subject)
            else:
                subject = " (all subjects)"
            lines.append(
                f"  [{limits.bounded_text(rule.check)}]{subject}"
                f" expired on {rule.expires.date().isoformat() if rule.expires else 'unknown'}"
            )
    if not lines:
        return ""
    return "\n".join(lines)
