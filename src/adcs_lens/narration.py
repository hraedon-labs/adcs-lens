"""Optional narration layer — executive summary from findings.

Imports the deterministic core (detection + consequences) and produces a
plain-language executive summary. The default mode is deterministic (no AI);
an optional AI-enhanced mode uses an LLM to refine the narrative, falling
back to the deterministic summary when the LLM client is unavailable.

This module is OPTIONAL — the detection core never imports it; it imports the
core, never the reverse (enforced by the architecture test: no core module may
import narration, and the CLI may reach it only lazily, inside a function).
"""

from __future__ import annotations

import json
from typing import Protocol

from adcs_lens.consequences import consequence_for, finding_with_consequence
from adcs_lens.detection import Finding, is_degradation_note
from adcs_lens.limits import escape_control
from adcs_lens.model import SEVERITY_RANK, Severity

# The prose summary lists at most this many risks so an executive reader is not
# buried by a long estate. The structured ``summarize_posture`` result carries
# every risk; only the prose is capped.
_MAX_TOP_RISKS = 5

_LLM_PROMPT = """\
You are a security narrator producing an executive summary of an Active Directory
Certificate Services (AD CS) posture assessment for a non-technical audience
(a CISO or compliance officer).

STRICT RULES:
- Use ONLY the facts in the DETERMINISTIC SUMMARY and FINDINGS below.
- Do NOT invent, infer, or omit any finding, severity, count, subject, or detail.
- Do NOT suggest remediations beyond those listed under each finding.
- Do NOT claim any attack was performed or confirmed; these are read-only
  configuration checks that flag enabling conditions, not confirmed exploits.
- Preserve every severity and count exactly as given.
- Keep the summary concise: a few short paragraphs.

DETERMINISTIC SUMMARY:
{summary}

FINDINGS (JSON):
{findings_json}
"""


def _sorted_risks(findings: list[Finding]) -> list[Finding]:
    """Posture findings (non-degradation), worst-first then by check/subject."""
    return sorted(
        (f for f in findings if not is_degradation_note(f)),
        key=lambda f: (SEVERITY_RANK[f.severity], f.check, f.subject),
    )


def _sorted_gaps(findings: list[Finding]) -> list[Finding]:
    """Coverage-gap notes, ordered by check then subject for stable output."""
    return sorted(
        (f for f in findings if is_degradation_note(f)),
        key=lambda f: (f.check, f.subject),
    )


def summarize_posture(findings: list[Finding]) -> dict[str, object]:
    """Return a structured posture summary derived purely from *findings*.

    The result is JSON-serializable and contains:

    - ``total``: count of all findings (risks + coverage gaps).
    - ``actionable``: count of posture findings (everything that is not a
      coverage-gap degradation note).
    - ``by_severity``: per-severity counts over all findings, every severity
      present and zero-filled.
    - ``top_risks``: posture findings worst-first, each with its check, subject,
      severity, and the plain-language ``summary`` from the consequences
      catalogue (``None`` when the check has no catalogue entry).
    - ``coverage_gaps``: the degradation notes, each with check / title / subject.

    Pure function, no I/O.
    """
    by_severity = {sev.value: 0 for sev in Severity}
    for f in findings:
        by_severity[f.severity.value] += 1

    risks = _sorted_risks(findings)
    gaps = _sorted_gaps(findings)

    top_risks: list[dict[str, object]] = []
    for f in risks:
        entry = consequence_for(f.check)
        top_risks.append(
            {
                "check": f.check,
                "subject": f.subject,
                "severity": f.severity.value,
                "summary": entry.summary if entry is not None else None,
            }
        )

    return {
        "total": len(findings),
        "actionable": len(risks),
        "by_severity": by_severity,
        "top_risks": top_risks,
        "coverage_gaps": [
            {"check": f.check, "title": f.title, "subject": f.subject} for f in gaps
        ],
    }


def generate_executive_summary(findings: list[Finding]) -> str:
    """Render a multi-line, plain-text executive summary of *findings*.

    Opens with an overall posture assessment (actionable count + per-severity
    breakdown + coverage-gap count), lists the top risks worst-first (capped at
    five) with plain-language descriptions from the consequences catalogue,
    notes any coverage gaps, and closes with a remediation-priority
    recommendation. Deterministic: the same findings always produce
    byte-identical output. Pure function, no I/O.
    """
    risks = _sorted_risks(findings)
    gaps = _sorted_gaps(findings)

    counts = {sev.value: 0 for sev in Severity}
    for f in risks:
        counts[f.severity.value] += 1

    lines: list[str] = ["EXECUTIVE SUMMARY — AD CS / PKI POSTURE", ""]

    breakdown = ", ".join(
        f"{counts[sev.value]} {sev.value}" for sev in Severity if counts[sev.value] > 0
    )
    if breakdown:
        lines.append(
            f"Posture: {len(risks)} actionable finding(s) ({breakdown}) "
            f"and {len(gaps)} coverage gap(s)."
        )
    else:
        lines.append(
            f"Posture: {len(risks)} actionable finding(s) "
            f"and {len(gaps)} coverage gap(s)."
        )
    lines.append("")

    if risks:
        lines.append("Top risks (worst first):")
        lines.append("")
        for i, f in enumerate(risks[:_MAX_TOP_RISKS], start=1):
            entry = consequence_for(f.check)
            lines.append(
                f"{i}. [{f.severity.value.upper()}] {escape_control(f.check)} — "
                f"{escape_control(f.subject)}"
            )
            lines.append(f"   {escape_control(f.title)}")
            if entry is not None:
                lines.append(f"   In plain terms: {entry.summary}")
                lines.append(f"   Risk: {entry.consequence}")
                lines.append(f"   How to fix: {entry.remediation}")
            lines.append("")
    else:
        lines.append("No posture findings were detected for the checks evaluated.")
        lines.append("")

    if gaps:
        lines.append("Coverage gaps (checks that could not be fully evaluated):")
        for f in gaps:
            lines.append(f"- {escape_control(f.check)}: {escape_control(f.title)}")
        lines.append("")

    if not risks and not gaps:
        lines.append(
            "Priority: No findings and no coverage gaps. The estate evaluates "
            "clean against every check the tool performs."
        )
    elif not risks:
        lines.append(
            "Priority: No posture findings were detected, but coverage gaps mean "
            "some risk classes could not be evaluated. Re-run the collector with "
            "the missing passes so no risk class goes unverified."
        )
    elif counts[Severity.CRITICAL] > 0:
        lines.append(
            "Priority: Remediate CRITICAL findings first — they represent "
            "domain-compromise-class paths. Then address HIGH findings, which are "
            "enabling configurations for privilege escalation. Resolve coverage "
            "gaps by re-running the collector with the missing passes so no risk "
            "class goes unverified."
        )
    else:
        lines.append(
            "Priority: Address the highest-severity findings first — they are "
            "enabling configurations for privilege escalation or service failure. "
            "Resolve coverage gaps by re-running the collector with the missing "
            "passes so no risk class goes unverified."
        )

    return "\n".join(lines).rstrip() + "\n"


def _build_llm_prompt(findings: list[Finding], deterministic_summary: str) -> str:
    """Assemble the LLM prompt: deterministic summary + findings JSON as context."""
    findings_json = json.dumps(
        [finding_with_consequence(f) for f in findings],
        indent=2,
        sort_keys=True,
    )
    return _LLM_PROMPT.format(
        summary=deterministic_summary,
        findings_json=findings_json,
    )


class _LlmClient(Protocol):
    """Minimal LLM client interface: a single ``chat`` call returning text."""

    def chat(self, prompt: str) -> str: ...


def generate_narrated_summary(
    findings: list[Finding], *, llm_client: _LlmClient | None = None
) -> str:
    """Return an executive summary, optionally refined by an LLM.

    With ``llm_client`` ``None`` (the default) this is exactly
    :func:`generate_executive_summary` — deterministic, no AI. When an
    ``llm_client`` is supplied it must expose a ``chat(prompt: str) -> str``
    method; the deterministic summary and a JSON serialization of the findings
    are passed as context, with a prompt that forbids inventing facts.

    Any error — a missing client library, a network failure, a malformed
    response — falls back to the deterministic summary, so narration never
    blocks the deterministic result. The findings are never modified.
    """
    deterministic = generate_executive_summary(findings)
    if llm_client is None:
        return deterministic
    try:
        prompt = _build_llm_prompt(findings, deterministic)
        narrated = llm_client.chat(prompt)
        if isinstance(narrated, str) and narrated.strip():
            return narrated
        return deterministic
    except Exception:
        return deterministic
