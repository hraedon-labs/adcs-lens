"""Rendering of findings — text, JSON, HTML, and SARIF. Pure, stdlib-only.

The JSON envelope is the stable contract the later narration/report layers will
consume, so it is versioned and emitted even when there are zero findings.
"""

from __future__ import annotations

import html
import json
from collections import Counter
from urllib.parse import quote

from adcs_lens import __version__
from adcs_lens.consequences import consequence_for, finding_with_consequence
from adcs_lens.detection import Finding
from adcs_lens.diff import CoverageChange, DriftReport, IndeterminateFinding
from adcs_lens.model import Severity

# Envelope shape history:
#   2 — every finding gains a `consequence` block (the value-delivery layer).
#   3 — every finding gains a `sid` field (WI-042: the structured principal
#       SID replaces the detail-text regex extraction).
#   4 — the diff envelope gains an `indeterminate` list (older findings the
#       newer export could not re-evaluate, each with a `reason` and
#       `current_severity`), a `coverage_changes` list (degradation notes that
#       appeared / cleared — no longer listed under new/resolved), and
#       `summary.indeterminate` / `summary.coverage_changes` /
#       `summary.coverage_lost`. Every finding (doctor and diff) gains
#       `object_ids`, `variant` and `evidence_complete`. One shared version for
#       both envelopes (4 is unreleased, so it absorbs all of these).
SCHEMA_VERSION = 4

_SARIF_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "none",
}


def _artifact_uri(source: str) -> str:
    """Encode a source fact as a file: artifactLocation URI for SARIF consumers."""
    return f"file:///adcs-lens/{quote(source, safe='')}"


def summarize(findings: list[Finding]) -> dict[str, int]:
    """Count findings by severity (every severity key present, zero-filled)."""
    counts = Counter(f.severity.value for f in findings)
    return {sev.value: counts.get(sev.value, 0) for sev in Severity}


def render_json(
    findings: list[Finding],
    *,
    suppressions: dict[str, object] | None = None,
) -> str:
    """Serialize findings + summary as a stable JSON envelope."""
    envelope: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "kind": "doctor",
        "summary": summarize(findings),
        "findings": [finding_with_consequence(f) for f in findings],
    }
    if suppressions is not None:
        envelope["suppressions"] = suppressions
    return json.dumps(envelope, indent=2, sort_keys=True)


def render_text(findings: list[Finding]) -> str:
    """Render a human-readable, severity-ordered report."""
    lines: list[str] = []
    summary = summarize(findings)
    actionable = sum(v for k, v in summary.items() if k != Severity.INFO.value)
    header = "  ".join(f"{sev.value}={summary[sev.value]}" for sev in Severity)
    lines.append(f"adcs-lens doctor  ::  {actionable} finding(s)  [{header}]")
    if not findings:
        lines.append("  (no findings)")
        return "\n".join(lines)
    for f in findings:
        tier = f" ({f.tier.value}-tier)" if f.tier is not None else ""
        lines.append(f"\n[{f.severity.value.upper()}] {f.check}{tier}  {f.subject}")
        lines.append(f"  {f.title}")
        lines.append(f"  {f.detail}")
        lines.append(f"  source: {f.source}")
        entry = consequence_for(f.check)
        if entry is not None:
            lines.append(f"  in plain terms: {entry.summary} {entry.consequence}")
            lines.append(f"  how to fix: {entry.remediation}")
    return "\n".join(lines)


def _indeterminate_json(item: IndeterminateFinding) -> dict[str, object]:
    """One withheld finding: the older finding, why, and what the newer export shows."""
    data = finding_with_consequence(item.finding)
    data["reason"] = item.reason
    data["current_severity"] = (
        item.current.severity.value if item.current is not None else None
    )
    return data


def _coverage_change_json(change: CoverageChange) -> dict[str, object]:
    data = finding_with_consequence(change.finding)
    data["direction"] = change.direction
    return data


def render_diff_json(report: DriftReport) -> str:
    """Serialize a drift report as a stable JSON envelope (kind=diff)."""
    envelope = {
        "schema_version": SCHEMA_VERSION,
        "kind": "diff",
        "summary": {
            "new": len(report.new),
            "resolved": len(report.resolved),
            "changed": len(report.changed),
            "unchanged": report.unchanged,
            "indeterminate": len(report.indeterminate),
            "coverage_changes": len(report.coverage_changes),
            "regressions": report.regressions,
            "coverage_lost": report.coverage_lost,
        },
        "new": [finding_with_consequence(f) for f in report.new],
        "resolved": [finding_with_consequence(f) for f in report.resolved],
        "indeterminate": [_indeterminate_json(i) for i in report.indeterminate],
        "coverage_changes": [_coverage_change_json(c) for c in report.coverage_changes],
        "changed": [
            {
                "check": d.new.check,
                "subject": d.new.subject,
                "old_severity": d.old.severity.value,
                "new_severity": d.new.severity.value,
                "worsened": d.worsened,
                "content_changed": d.content_changed,
            }
            for d in report.changed
        ],
    }
    return json.dumps(envelope, indent=2, sort_keys=True)


def render_diff_text(report: DriftReport) -> str:
    """Render a human-readable drift report, regressions first."""
    lines = [
        "adcs-lens diff  ::  "
        f"+{len(report.new)} new  -{len(report.resolved)} resolved  "
        f"~{len(report.changed)} changed  ={report.unchanged} unchanged  "
        f"?{len(report.indeterminate)} not re-evaluated  "
        f"!{len(report.coverage_changes)} coverage change(s)"
    ]
    if report.coverage_lost:
        lines.append(
            f"  COVERAGE LOST: {len(report.indeterminate)} older finding(s) were not "
            "re-evaluated by the newer export and are NOT reported as resolved."
        )
    if not (
        report.new
        or report.resolved
        or report.changed
        or report.indeterminate
        or report.coverage_changes
    ):
        lines.append("  (no drift)")
        return "\n".join(lines)
    for f in report.new:
        lines.append(f"\n[+ NEW] [{f.severity.value.upper()}] {f.check}  {f.subject}")
        lines.append(f"  {f.title}")
        entry = consequence_for(f.check)
        if entry is not None:
            lines.append(f"  in plain terms: {entry.summary} {entry.consequence}")
            lines.append(f"  how to fix: {entry.remediation}")
    for d in report.changed:
        if d.worsened:
            arrow = "worse"
        elif d.old.severity != d.new.severity:
            arrow = "better"
        else:
            arrow = "changed"
        lines.append(
            f"\n[~ {arrow.upper()}] {d.new.check}  {d.new.subject}: "
            f"{d.old.severity.value} -> {d.new.severity.value}"
        )
    for f in report.resolved:
        lines.append(f"\n[- RESOLVED] [{f.severity.value.upper()}] {f.check}  {f.subject}")
        lines.append(f"  {f.title}")
    for item in report.indeterminate:
        f = item.finding
        lines.append(
            f"\n[? NOT RE-EVALUATED] [{f.severity.value.upper()}] {f.check}  {f.subject}"
        )
        lines.append(f"  {f.title}")
        now = (
            f"now {item.current.severity.value} (improvement unverified)"
            if item.current is not None
            else "absent from the newer export"
        )
        lines.append(f"  {now}; coverage lost: {item.reason}")
    for change in report.coverage_changes:
        f = change.finding
        lines.append(
            f"\n[! COVERAGE {change.direction.upper()}] {f.check}  {f.subject}"
        )
        lines.append(f"  {f.title}")
        if change.direction == "cleared":
            lines.append(
                "  (a cleared coverage note is not a fix: the area may now be better "
                "covered, or not evaluated at all)"
            )
    return "\n".join(lines)


def _diff_sarif_result(
    f: Finding,
    level: str,
    rule_index: dict[str, int],
    baseline_state: str,
    indeterminate_reason: str | None = None,
) -> dict[str, object]:
    """Build one SARIF result for a drift finding."""
    tier_suffix = f" ({f.tier.value}-tier)" if f.tier is not None else ""
    result: dict[str, object] = {
        "ruleId": f.check,
        "ruleIndex": rule_index[f.check],
        "level": level,
        "message": {"text": f"{f.title}: {f.detail}{tier_suffix}"},
        "baselineState": baseline_state,
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": _artifact_uri(f.source)}
                },
                "logicalLocations": [
                    {"fullyQualifiedName": f.source, "name": f.subject},
                ],
            }
        ],
    }
    properties: dict[str, object] = {}
    if f.sid:
        properties["sid"] = f.sid
    if indeterminate_reason is not None:
        properties["adcsLensDrift"] = "indeterminate"
        properties["coverageLostReason"] = indeterminate_reason
    if properties:
        result["properties"] = properties
    return result


def render_diff_sarif(report: DriftReport) -> str:
    """Render a drift report as a SARIF v2.1.0 log.

    Each result uses the SARIF level mapped from the finding's own severity.
    New, worsened, content-changed, and resolved findings all preserve their
    source severity rather than being hard-coded to a single level. The
    finding's check id is used as the SARIF ``ruleId``. A ``baselineState``
    distinguishes new, updated, and resolved drift items for CI consumers.

    A finding the newer export could not re-evaluate (coverage lost) is NOT
    emitted as ``absent`` — that would close the alert on a guess. It is emitted
    as ``unchanged`` at its older severity, so the alert stays open, with
    ``properties.adcsLensDrift = "indeterminate"`` and the coverage reason.
    """
    findings = (
        list(report.new)
        + [d.new for d in report.changed]
        + list(report.resolved)
        + [i.finding for i in report.indeterminate]
        + [c.finding for c in report.coverage_changes]
    )
    check_ids = sorted({f.check for f in findings})
    rule_index: dict[str, int] = {check: i for i, check in enumerate(check_ids)}

    rules: list[dict[str, object]] = []
    for check in check_ids:
        entry = consequence_for(check)
        if entry is not None:
            rules.append(
                {
                    "id": check,
                    "name": check,
                    "shortDescription": {"text": entry.summary},
                    "fullDescription": {"text": entry.consequence},
                    "help": {"text": entry.remediation},
                }
            )
        else:
            rules.append({"id": check, "name": check, "shortDescription": {"text": check}})

    results: list[dict[str, object]] = []
    for f in report.new:
        results.append(_diff_sarif_result(f, _SARIF_LEVEL[f.severity], rule_index, "new"))
    for d in report.changed:
        results.append(
            _diff_sarif_result(d.new, _SARIF_LEVEL[d.new.severity], rule_index, "updated")
        )
    for f in report.resolved:
        results.append(_diff_sarif_result(f, _SARIF_LEVEL[f.severity], rule_index, "absent"))
    for item in report.indeterminate:
        f = item.finding
        results.append(
            _diff_sarif_result(
                f,
                _SARIF_LEVEL[f.severity],
                rule_index,
                "unchanged",
                indeterminate_reason=item.reason,
            )
        )
    for change in report.coverage_changes:
        f = change.finding
        result = _diff_sarif_result(
            f,
            _SARIF_LEVEL[f.severity],
            rule_index,
            "new" if change.direction == "appeared" else "absent",
        )
        props = result.setdefault("properties", {})
        assert isinstance(props, dict)
        props["adcsLensDrift"] = f"coverage-{change.direction}"
        results.append(result)

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "adcs-lens",
                        "version": __version__,
                        "informationUri": "https://github.com/hraedon/adcs-lens",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2, sort_keys=True)


def _diff_html_finding(f: Finding, badge_class: str | None = None) -> list[str]:
    """Render one finding in a diff HTML report."""
    out = [
        '<article class="finding">',
        '<div class="finding-head">',
        f'<span class="sev {_html_severity_class(f.severity)}">'
        f"{html.escape(f.severity.value.upper())}</span>",
        f'<span class="check">{html.escape(f.check)}</span>',
        f'<span class="subject">{html.escape(f.subject)}</span>',
        "</div>",
        f'<p class="title">{html.escape(f.title)}</p>',
        f'<p class="detail">{html.escape(f.detail)}</p>',
        f'<p class="source">source: {html.escape(f.source)}</p>',
    ]
    if badge_class:
        label = badge_class.replace("-", " ").title()
        out.insert(3, f'<span class="diff-badge {badge_class}">{label}</span>')
    entry = consequence_for(f.check)
    if entry is not None:
        out.append('<div class="consequence">')
        out.append(f"<p><strong>In plain terms.</strong> {html.escape(entry.summary)}</p>")
        out.append(f"<p><strong>Risk.</strong> {html.escape(entry.consequence)}</p>")
        out.append(f"<p><strong>How to fix.</strong> {html.escape(entry.remediation)}</p>")
        out.append("</div>")
    out.append("</article>")
    return out


def render_diff_html(report: DriftReport) -> str:
    """Render a self-contained HTML drift report."""
    new = list(report.new)
    resolved = list(report.resolved)
    changed = list(report.changed)
    unchanged = report.unchanged
    indeterminate = list(report.indeterminate)
    coverage_changes = list(report.coverage_changes)

    parts: list[str] = [
        "<!DOCTYPE html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        "<title>AD CS Drift Report — adcs-lens</title>",
        "<style>",
        _HTML_STYLE,
        _DIFF_HTML_STYLE,
        "</style>",
        "</head>",
        "<body>",
        "<header>",
        "<h1>AD CS Drift Report</h1>",
        f'<p class="tool">Generated by adcs-lens {html.escape(__version__)} — '
        "read-only drift between two exported AD CS / PKI snapshots.</p>",
        '<div class="summary">',
        f'<span class="diff-summary">+{len(new)} new</span>',
        f'<span class="diff-summary">-{len(resolved)} resolved</span>',
        f'<span class="diff-summary">~{len(changed)} changed</span>',
        f'<span class="diff-summary">={unchanged} unchanged</span>',
        f'<span class="diff-summary">?{len(indeterminate)} not re-evaluated</span>',
        f'<span class="diff-summary">!{len(coverage_changes)} coverage change(s)</span>',
        "</div>",
    ]
    if indeterminate:
        parts.append(
            f'<p class="coverage-lost"><strong>Coverage lost.</strong> {len(indeterminate)} '
            "older finding(s) were not re-evaluated by the newer export and are NOT "
            "reported as resolved.</p>"
        )
    parts.append("</header>")

    if not (new or changed or resolved or indeterminate or coverage_changes):
        parts.append('<p class="empty">No drift — posture is unchanged.</p>')
    else:
        parts.append("<main>")
        if new:
            parts.append('<section class="diff-section" id="new-findings">')
            parts.append(f'<h2>New findings <span class="count">({len(new)})</span></h2>')
            for f in new:
                parts.extend(_diff_html_finding(f, badge_class="new"))
            parts.append("</section>")
        if changed:
            parts.append('<section class="diff-section" id="changed-findings">')
            parts.append(f'<h2>Changed findings <span class="count">({len(changed)})</span></h2>')
            for d in changed:
                if d.worsened:
                    badge = "worsened"
                elif d.old.severity != d.new.severity:
                    badge = "improved"
                else:
                    badge = "changed"
                parts.append('<article class="finding changed">')
                parts.append('<div class="finding-head">')
                parts.append(
                    f'<span class="sev {_html_severity_class(d.new.severity)}">'
                    f"{html.escape(d.new.severity.value.upper())}</span>"
                )
                parts.append(f'<span class="check">{html.escape(d.new.check)}</span>')
                parts.append(f'<span class="subject">{html.escape(d.new.subject)}</span>')
                parts.append(f'<span class="diff-badge {badge}">{badge.title()}</span>')
                parts.append("</div>")
                parts.append(f'<p class="title">{html.escape(d.new.title)}</p>')
                parts.append(f'<p class="source">source: {html.escape(d.new.source)}</p>')
                parts.append(
                    f'<p class="detail">{html.escape(d.old.severity.value)} &rarr; '
                    f"{html.escape(d.new.severity.value)}</p>"
                )
                parts.append("</article>")
            parts.append("</section>")
        if resolved:
            parts.append('<section class="diff-section" id="resolved-findings">')
            parts.append(f'<h2>Resolved findings <span class="count">({len(resolved)})</span></h2>')
            for f in resolved:
                parts.extend(_diff_html_finding(f, badge_class="resolved"))
            parts.append("</section>")
        if indeterminate:
            parts.append('<section class="diff-section" id="indeterminate-findings">')
            parts.append(
                "<h2>Not re-evaluated — coverage lost "
                f'<span class="count">({len(indeterminate)})</span></h2>'
            )
            for item in indeterminate:
                article = _diff_html_finding(item.finding, badge_class="indeterminate")
                now = (
                    f"now {item.current.severity.value} (improvement unverified)"
                    if item.current is not None
                    else "absent from the newer export"
                )
                article.insert(
                    -1,
                    f'<p class="coverage-reason">{html.escape(now)}; coverage lost: '
                    f"{html.escape(item.reason)}</p>",
                )
                parts.extend(article)
            parts.append("</section>")
        if coverage_changes:
            parts.append('<section class="diff-section" id="coverage-changes">')
            parts.append(
                "<h2>Coverage state changed "
                f'<span class="count">({len(coverage_changes)})</span></h2>'
            )
            parts.append(
                '<p class="coverage-reason">Coverage notes that appeared or cleared. A '
                "cleared note is not a fix: the area may be better covered, or not "
                "evaluated at all.</p>"
            )
            for change in coverage_changes:
                parts.extend(
                    _diff_html_finding(change.finding, badge_class=f"coverage-{change.direction}")
                )
            parts.append("</section>")
        parts.append("</main>")

    parts.append("</body>")
    parts.append("</html>")
    return "\n".join(parts)


def render_sarif(findings: list[Finding]) -> str:
    """Render findings as a SARIF v2.1.0 log for CI / GRC integration.

    SARIF is the OASIS JSON format that CI systems (GitHub Code Scanning, Azure
    DevOps) and GRC tools consume natively. Rules are de-duplicated by check id
    and sorted so ``ruleIndex`` references are deterministic; results preserve
    the input (worst-first) order. AD CS objects are not files, so the source
    fact is placed in ``logicalLocations`` and surfaced as a ``file:`` scheme
    ``artifactLocation`` for GRC consumers.
    """
    check_ids = sorted({f.check for f in findings})
    index_by_check: dict[str, int] = {check: i for i, check in enumerate(check_ids)}

    rules: list[dict[str, object]] = []
    for check in check_ids:
        entry = consequence_for(check)
        if entry is not None:
            rules.append(
                {
                    "id": check,
                    "name": check,
                    "shortDescription": {"text": entry.summary},
                    "fullDescription": {"text": entry.consequence},
                    "help": {"text": entry.remediation},
                }
            )
        else:
            rules.append(
                {
                    "id": check,
                    "name": check,
                    "shortDescription": {"text": check},
                }
            )

    results: list[dict[str, object]] = []
    for f in findings:
        tier_suffix = f" ({f.tier.value}-tier)" if f.tier is not None else ""
        result: dict[str, object] = {
            "ruleId": f.check,
            "ruleIndex": index_by_check[f.check],
            "level": _SARIF_LEVEL[f.severity],
            "message": {"text": f"{f.title}: {f.detail}{tier_suffix}"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": _artifact_uri(f.source)}
                    },
                    "logicalLocations": [
                        {
                            "fullyQualifiedName": f.source,
                            "name": f.subject,
                        },
                    ],
                }
            ],
        }
        if f.sid:
            result["properties"] = {"sid": f.sid}
        results.append(result)

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "adcs-lens",
                        "version": __version__,
                        "informationUri": "https://github.com/hraedon/adcs-lens",
                        "rules": rules,
                    },
                },
                "results": results,
            },
        ],
    }
    return json.dumps(sarif, indent=2, sort_keys=True)


_HTML_SEVERITY_ORDER: tuple[Severity, ...] = tuple(Severity)


def _html_severity_class(severity: Severity) -> str:
    return f"sev-{severity.value}"


def render_html(findings: list[Finding]) -> str:
    """Render a self-contained HTML evidence report (WI-018).

    A single, dependency-free HTML document with inline CSS — no external
    resources, no JavaScript — suitable for handing to an auditor or attaching
    to a change record. Output is deterministic (no wall-clock timestamp): the
    report is a pure function of the findings, so the same export always
    produces byte-identical HTML. All dynamic text is HTML-escaped.

    Findings are grouped into severity bands (worst first); each finding shows
    its technical detail plus the plain-language consequence block (summary,
    risk, remediation) from the consequences catalogue.
    """
    summary = summarize(findings)
    actionable = sum(summary[sev.value] for sev in Severity if sev != Severity.INFO)

    parts: list[str] = [
        "<!DOCTYPE html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        "<title>AD CS Posture Report — adcs-lens</title>",
        "<style>",
        _HTML_STYLE,
        "</style>",
        "</head>",
        "<body>",
        "<header>",
        "<h1>AD CS Posture Report</h1>",
        f'<p class="tool">Generated by adcs-lens {html.escape(__version__)} — '
        "read-only analysis of an exported AD CS / PKI configuration. "
        "No live access was performed.</p>",
        '<div class="summary">',
        f'<span class="meta">{actionable} actionable finding(s)</span>',
    ]
    for sev in _HTML_SEVERITY_ORDER:
        count = summary[sev.value]
        parts.append(
            f'<span class="badge {_html_severity_class(sev)}">'
            f"{html.escape(sev.value.title())} {count}</span>"
        )
    parts.append("</div>")  # summary
    parts.append("</header>")

    if findings:
        # Table of contents: jump to each severity band that has findings.
        parts.append('<nav class="toc" aria-label="Table of contents">')
        parts.append("<h2>Contents</h2>")
        parts.append("<ul>")
        by_severity: dict[Severity, list[Finding]] = {sev: [] for sev in Severity}
        for f in findings:
            by_severity[f.severity].append(f)
        for sev in _HTML_SEVERITY_ORDER:
            band = by_severity[sev]
            if not band:
                continue
            parts.append(
                f'<li><a href="#{sev.value}">'
                f"{html.escape(sev.value.title())} "
                f'<span class="count">({len(band)})</span></a></li>'
            )
        parts.append("</ul>")
        parts.append("</nav>")

        parts.append("<main>")
        for sev in _HTML_SEVERITY_ORDER:
            band = by_severity[sev]
            if not band:
                continue
            parts.append(
                f'<section class="band {_html_severity_class(sev)}" id="{sev.value}">'
            )
            parts.append(
                f"<h2>{html.escape(sev.value.title())} "
                f'<span class="count">({len(band)})</span></h2>'
            )
            for f in band:
                parts.extend(_html_finding(f))
            parts.append("</section>")
        parts.append("</main>")
    else:
        parts.append('<p class="empty">No findings — nothing to act on.</p>')

    parts.append("</body>")
    parts.append("</html>")
    return "\n".join(parts)


def _html_finding(f: Finding) -> list[str]:
    """Render one finding as an <article>, consequence block included."""
    tier = f" ({f.tier.value}-tier)" if f.tier is not None else ""
    out = [
        '<article class="finding">',
        '<div class="finding-head">',
        f'<span class="sev {_html_severity_class(f.severity)}">'
        f"{html.escape(f.severity.value.upper())}</span>",
        f'<span class="check">{html.escape(f.check)}</span>',
        f'<span class="subject">{html.escape(f.subject)}{html.escape(tier)}</span>',
        "</div>",
        f'<p class="title">{html.escape(f.title)}</p>',
        f'<p class="detail">{html.escape(f.detail)}</p>',
        f'<p class="source">source: {html.escape(f.source)}</p>',
    ]
    entry = consequence_for(f.check)
    if entry is not None:
        out.append('<div class="consequence">')
        out.append(f"<p><strong>In plain terms.</strong> {html.escape(entry.summary)}</p>")
        out.append(f"<p><strong>Risk.</strong> {html.escape(entry.consequence)}</p>")
        out.append(
            f"<p><strong>How to fix.</strong> {html.escape(entry.remediation)}</p>"
        )
        out.append("</div>")
    out.append("</article>")
    return out


_HTML_STYLE = """
:root { color-scheme: light; }
body {
  font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
    Helvetica, Arial, sans-serif;
  margin: 0; padding: 2rem; color: #1a1a1a; background: #fff; max-width: 60rem;
}
h1 { font-size: 1.6rem; margin: 0 0 .25rem; }
h2 {
  font-size: 1.15rem; margin: 1.75rem 0 .5rem; padding-bottom: .25rem;
  border-bottom: 2px solid #ddd;
}
.tool { color: #555; margin: 0 0 .75rem; }
.summary {
  display: flex; flex-wrap: wrap; gap: .4rem; align-items: center;
  margin-bottom: 1rem;
}
.meta { font-weight: 600; margin-right: .5rem; }
.badge, .sev {
  display: inline-block; padding: .1rem .45rem; border-radius: .25rem;
  font-size: .8rem; font-weight: 600; color: #fff;
}
.badge.sev-critical, .sev.sev-critical { background: #b3261e; }
.badge.sev-high, .sev.sev-high { background: #d9534f; }
.badge.sev-medium, .sev.sev-medium { background: #e0a800; color: #1a1a1a; }
.badge.sev-low, .sev.sev-low { background: #6c757d; }
.badge.sev-info, .sev.sev-info { background: #5b7e9e; }
.band { margin-bottom: 1rem; }
.finding {
  border: 1px solid #e3e3e3; border-left: 4px solid #ccc; border-radius: .35rem;
  padding: .6rem .8rem; margin: .5rem 0;
}
.band.sev-critical .finding { border-left-color: #b3261e; }
.band.sev-high .finding { border-left-color: #d9534f; }
.band.sev-medium .finding { border-left-color: #e0a800; }
.band.sev-low .finding { border-left-color: #6c757d; }
.band.sev-info .finding { border-left-color: #5b7e9e; }
.finding-head { display: flex; flex-wrap: wrap; gap: .5rem; align-items: baseline; }
.check {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-weight: 700;
}
.subject { color: #444; word-break: break-word; }
.title { font-weight: 600; margin: .3rem 0 .1rem; }
.detail { margin: .1rem 0; }
.source {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: .82rem; color: #666; word-break: break-word;
}
.consequence {
  margin-top: .5rem; padding: .5rem .7rem; background: #f6f8fa;
  border-radius: .3rem;
}
.consequence p { margin: .2rem 0; }
.empty { font-size: 1.1rem; color: #555; }
.count { font-weight: 400; color: #666; }
.toc {
  background: #f6f8fa; border: 1px solid #e3e3e3; border-radius: .35rem;
  padding: .75rem 1rem; margin-bottom: 1.25rem;
}
.toc h2 { font-size: 1rem; margin: 0 0 .4rem; padding: 0; border: none; }
.toc ul {
  list-style: none; margin: 0; padding: 0;
  display: flex; flex-wrap: wrap; gap: .4rem;
}
.toc li { margin: 0; }
.toc a {
  display: inline-block; text-decoration: none; padding: .15rem .5rem;
  border-radius: .25rem; background: #fff; border: 1px solid #d8d8d8;
  color: #1a1a1a;
}
.toc a:hover { background: #eef; }
"""

_DIFF_HTML_STYLE = """
.diff-summary {
  display: inline-block; padding: .15rem .5rem; border-radius: .25rem;
  font-size: .85rem; font-weight: 600; background: #e9ecef; color: #1a1a1a;
}
.diff-badge {
  display: inline-block; padding: .1rem .4rem; border-radius: .25rem;
  font-size: .75rem; font-weight: 600; color: #fff;
}
.diff-badge.new { background: #b3261e; }
.diff-badge.resolved { background: #198754; }
.diff-badge.worsened { background: #b3261e; }
.diff-badge.improved { background: #198754; }
.diff-badge.changed { background: #e0a800; color: #1a1a1a; }
.diff-badge.indeterminate { background: #5b7e9e; }
.diff-badge.coverage-appeared, .diff-badge.coverage-cleared { background: #5b7e9e; }
.coverage-lost {
  border-left: 4px solid #b3261e; background: #fdf3f2; padding: .5rem .7rem;
  border-radius: .3rem;
}
.coverage-reason { font-style: italic; color: #444; }
.diff-section { margin-bottom: 1.25rem; }
.changed { border-left: 4px solid #e0a800; }
"""
