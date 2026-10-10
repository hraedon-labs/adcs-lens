"""Drift detection over two read-only snapshots (Stance 2).

Pure, stdlib-only. Diffs the *findings* run_all produces for an older and a newer
export and reports what changed: regressions (new findings), fixes (resolved
findings), severity changes on the same issue, findings that could not be
re-evaluated, and coverage-state transitions.

Identity. A detector finding is matched across exports on ``(check, variant,
any stable object alias)`` — e.g. a template's OID or cn, a CA's name, a PKI
object's DN, a certificate's SHA-256 fingerprint — never on presentation text
(display name, config string, source sentence). A renamed display name is
therefore the *same* finding with changed content, not a fix plus a new issue.
Findings without object aliases (estate-level notes, hand-built findings) fall
back to ``(check, subject, source)``.

Resolution needs positive evidence. An older posture finding with no match in
the newer export is ``resolved`` only when no coverage gap of the newer export
covers it — the object is present and fully evaluated, or its container was
fully collected and the object is genuinely gone — and it is not a lifecycle
object (a certificate or CRL), whose absence from the export is never evidence
of a fix. Everything else lands in ``indeterminate`` with the reason. The same
holds for a severity *improvement*: it is withheld when a gap covers the
finding or the newer severity was computed from incomplete evidence.

The gaps come from :func:`adcs_lens.detection.coverage_gaps` — built from the
same predicate functions the detectors skip on (structurally enforced by
tests/test_diff_coverage.py).

Degradation notes (INFO coverage signals) are never "new" or "resolved": their
appearance or disappearance is reported as a coverage-state transition.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from adcs_lens.detection import LIFECYCLE_ID_PREFIXES, CoverageGap, Finding, is_degradation_note
from adcs_lens.model import SEVERITY_RANK

_Key = tuple[str, str, str]


def _keys(f: Finding) -> list[_Key]:
    """Every identity key of *f*: one per stable alias, or the legacy fallback."""
    if f.object_ids:
        return [(f.check, f.variant, alias) for alias in f.object_ids]
    return [(f.check, f.variant, f"legacy:{f.subject}\x00{f.source}")]


def _worst_first(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (SEVERITY_RANK[f.severity], f.check, f.subject, f.source))


@dataclass(frozen=True)
class FindingDelta:
    """A finding present in both snapshots (same identity) that changed.

    The change can be a severity shift, a content shift (title / detail /
    subject / source), or both. ``content_changed`` is true only when severity
    stayed the same but the explanatory fields changed.
    """

    old: Finding
    new: Finding

    @property
    def worsened(self) -> bool:
        # Lower rank == worse, so a smaller rank in `new` means it got worse.
        return SEVERITY_RANK[self.new.severity] < SEVERITY_RANK[self.old.severity]

    @property
    def content_changed(self) -> bool:
        """True when severity is unchanged but title, detail, subject or source differ."""
        if self.old.severity != self.new.severity:
            return False
        fields = ("title", "detail", "subject", "source")
        return any(getattr(self.old, f) != getattr(self.new, f) for f in fields)


@dataclass(frozen=True)
class IndeterminateFinding:
    """An older finding the newer export could not re-evaluate.

    ``finding`` is the older finding. ``current`` is the newer export's finding
    on the same identity when it still exists with a better severity (an
    improvement that cannot be trusted), else ``None`` (it disappeared).
    ``reason`` names why it was withheld.
    """

    finding: Finding
    reason: str
    current: Finding | None = None


@dataclass(frozen=True)
class CoverageChange:
    """A degradation note that appeared or cleared between the snapshots.

    ``direction`` is ``"appeared"`` (coverage got worse, or a gap became
    visible) or ``"cleared"`` (the note is gone — which can mean coverage
    improved OR that the area was not evaluated at all; it is never a fix).
    """

    finding: Finding
    direction: str


@dataclass(frozen=True)
class DriftReport:
    """The diff between an older and a newer posture snapshot."""

    new: tuple[Finding, ...]  # regressions: posture present now, absent before
    resolved: tuple[Finding, ...]  # fixes: posture present before, positively gone now
    changed: tuple[FindingDelta, ...]  # same identity, different severity or content
    unchanged: int  # count of findings identical across both
    # absent (or improved) now, but without positive evidence: "not
    # re-evaluated — coverage lost"
    indeterminate: tuple[IndeterminateFinding, ...] = ()
    # degradation notes that appeared / cleared (coverage-state transitions)
    coverage_changes: tuple[CoverageChange, ...] = ()

    @property
    def regressions(self) -> bool:
        """True when posture got worse: a new posture finding or a worsened severity.

        Content-only changes and coverage-state transitions do not count; the
        ``diff --exit-code`` gate uses exactly this property.
        """
        real_new = any(not is_degradation_note(f) for f in self.new)
        real_worsened = any(
            d.worsened and not is_degradation_note(d.new) for d in self.changed
        )
        return real_new or real_worsened

    @property
    def coverage_lost(self) -> bool:
        """True when any older posture finding could not be re-evaluated."""
        return bool(self.indeterminate)


def _gap_for(f: Finding, coverage: Sequence[CoverageGap]) -> CoverageGap | None:
    return next((g for g in coverage if g.covers(f)), None)


def _is_lifecycle(f: Finding) -> bool:
    return any(alias.startswith(LIFECYCLE_ID_PREFIXES) for alias in f.object_ids)


def _withhold_absent(f: Finding, coverage: Sequence[CoverageGap]) -> str | None:
    """Why an absent older posture finding may NOT be called resolved (None = may)."""
    gap = _gap_for(f, coverage)
    if gap is not None:
        return gap.reason
    if _is_lifecycle(f):
        return (
            "the certificate/CRL is absent from the newer export; absence from a "
            "cert/CRL index is not evidence of a fix (the index can be partial)"
        )
    return None


def _withhold_improvement(
    old: Finding, new: Finding, coverage: Sequence[CoverageGap]
) -> str | None:
    gap = _gap_for(old, coverage)
    if gap is not None:
        return gap.reason
    if not new.evidence_complete:
        return "the newer severity was computed from weaker evidence (an unknown input)"
    return None


def diff_findings(
    old: list[Finding],
    new: list[Finding],
    *,
    coverage: Sequence[CoverageGap] = (),
) -> DriftReport:
    """Compute finding drift against the newer export's *coverage* gaps.

    *coverage* is :func:`adcs_lens.detection.coverage_gaps` of the newer
    estate. With no gaps (the default) every absence of a non-lifecycle finding
    is a resolution.
    """
    new_index: dict[_Key, Finding] = {}
    for finding in new:
        for k in _keys(finding):
            new_index.setdefault(k, finding)

    added: list[Finding] = []
    resolved: list[Finding] = []
    indeterminate: list[IndeterminateFinding] = []
    coverage_changes: list[CoverageChange] = []
    changed: list[FindingDelta] = []
    unchanged = 0
    matched_new: set[int] = set()

    for of in old:
        nf = next((new_index[k] for k in _keys(of) if k in new_index), None)
        if nf is None:
            if is_degradation_note(of):
                coverage_changes.append(CoverageChange(finding=of, direction="cleared"))
                continue
            reason = _withhold_absent(of, coverage)
            if reason is None:
                resolved.append(of)
            else:
                indeterminate.append(IndeterminateFinding(finding=of, reason=reason))
            continue
        matched_new.add(id(nf))
        delta = FindingDelta(old=of, new=nf)
        if of.severity == nf.severity and not delta.content_changed:
            unchanged += 1
            continue
        improved = SEVERITY_RANK[nf.severity] > SEVERITY_RANK[of.severity]
        reason = (
            _withhold_improvement(of, nf, coverage)
            if improved and not is_degradation_note(of)
            else None
        )
        if reason is not None:
            indeterminate.append(IndeterminateFinding(finding=of, reason=reason, current=nf))
        else:
            changed.append(delta)

    for candidate in new:
        if id(candidate) in matched_new:
            continue
        if is_degradation_note(candidate):
            coverage_changes.append(CoverageChange(finding=candidate, direction="appeared"))
        else:
            added.append(candidate)

    return DriftReport(
        new=tuple(_worst_first(added)),
        resolved=tuple(_worst_first(resolved)),
        changed=tuple(sorted(changed, key=lambda d: (SEVERITY_RANK[d.new.severity], d.new.check))),
        unchanged=unchanged,
        indeterminate=tuple(
            sorted(
                indeterminate,
                key=lambda i: (
                    SEVERITY_RANK[i.finding.severity],
                    i.finding.check,
                    i.finding.subject,
                    i.finding.source,
                ),
            )
        ),
        coverage_changes=tuple(
            sorted(
                coverage_changes,
                key=lambda c: (c.direction, c.finding.check, c.finding.subject),
            )
        ),
    )
