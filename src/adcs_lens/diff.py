"""Drift detection over two read-only snapshots (Stance 2).

Pure, stdlib-only. Diffs the *findings* run_all produces for an older and a newer
export and reports what changed: regressions (new findings), fixes (resolved
findings), and severity changes on the same issue. This is the air-gap-preserving
"what got worse since the last scan" signal — no live access, just two exports.

A finding's drift identity is ``(check, subject, source)`` — the same check on
the same object, disambiguated by the source fact so that multiple findings
sharing a subject (e.g. two CRLs from one issuer, two certs with the same
subject) are not silently collapsed. A severity change on that tuple is a
"changed" finding, not a new-and-resolved pair. Content changes (different
title, detail) with an unchanged severity are also reported as "changed" but
do not count as regressions.

Coverage honesty: a finding that is absent from the newer export (or whose
severity improved) is classified ``resolved`` / improved only when the newer
export fully evaluated that check for that subject. Otherwise it lands in
``indeterminate`` with the reason, because a skipped pass, an unreadable DACL,
a remote CA's uncollected registry, or an unverified collector looks exactly
like a fix in the findings alone. The coverage map comes from
:func:`adcs_lens.detection.coverage_gaps` — the same predicates the detectors
use to skip — so it cannot drift from the detectors.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from adcs_lens.detection import CoverageGap, Finding, is_degradation_note
from adcs_lens.model import SEVERITY_RANK


def _key(f: Finding) -> tuple[str, str, str]:
    return (f.check, f.subject, f.source)


def _worst_first(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (SEVERITY_RANK[f.severity], f.check, f.subject, f.source))


@dataclass(frozen=True)
class FindingDelta:
    """A finding that drifted between snapshots (same check + subject + source).

    The change can be a severity shift, a content shift (title/detail), or
    both. ``content_changed`` is true only when severity stayed the same but
    the explanatory fields changed. ``source`` is part of the drift identity,
    so a source change produces a new-and-resolved pair, not a delta here.
    """

    old: Finding
    new: Finding

    @property
    def worsened(self) -> bool:
        # Lower rank == worse, so a smaller rank in `new` means it got worse.
        return SEVERITY_RANK[self.new.severity] < SEVERITY_RANK[self.old.severity]

    @property
    def content_changed(self) -> bool:
        """True when severity is unchanged but title or detail differ.

        ``source`` is part of the drift identity, so a source change is reported
        as a new-and-resolved pair rather than a content change on the same
        issue.
        """
        if self.old.severity != self.new.severity:
            return False
        return (
            self.old.title,
            self.old.detail,
        ) != (
            self.new.title,
            self.new.detail,
        )


@dataclass(frozen=True)
class IndeterminateFinding:
    """An older finding the newer export could not re-evaluate.

    ``finding`` is the older finding. ``current`` is the newer export's finding
    on the same identity when it still exists with a better severity (an
    improvement that cannot be trusted), else ``None`` (it disappeared).
    ``reason`` names the coverage gap that explains it.
    """

    finding: Finding
    reason: str
    current: Finding | None = None


@dataclass(frozen=True)
class DriftReport:
    """The diff between an older and a newer posture snapshot."""

    new: tuple[Finding, ...]  # regressions: present now, absent before
    resolved: tuple[Finding, ...]  # fixes: present before, absent now, fully re-evaluated
    # same (check, subject, source), different severity or content
    changed: tuple[FindingDelta, ...]
    unchanged: int  # count of findings identical across both
    # absent (or improved) now, but the newer export lost coverage for it, so it
    # is neither resolved nor still-present: "not re-evaluated — coverage lost"
    indeterminate: tuple[IndeterminateFinding, ...] = ()

    @property
    def coverage_lost(self) -> bool:
        """True when any older posture finding could not be re-evaluated.

        Only posture findings are ever withheld (degradation notes may always
        resolve), so a non-empty ``indeterminate`` is exactly this condition.
        """
        return bool(self.indeterminate)

    @property
    def regressions(self) -> bool:
        """True when posture got worse: a new posture finding or a worsened severity.

        Content-only changes (same severity, changed detail/title) are reported
        in ``changed`` but do not make this True. Degradation notes (coverage-gap
        INFO signals, e.g. a newly-missing collector pass) are excluded so the
        report's ``regressions`` flag agrees with the ``diff --exit-code`` gate
        and the ``doctor --exit-code`` gate — a coverage gap is not a posture
        regression.
        """
        real_new = any(not is_degradation_note(f) for f in self.new)
        real_worsened = any(
            d.worsened and not is_degradation_note(d.new) for d in self.changed
        )
        return real_new or real_worsened


def _gap_for(f: Finding, coverage: Sequence[CoverageGap]) -> CoverageGap | None:
    return next((g for g in coverage if g.covers(f)), None)


def diff_findings(
    old: list[Finding],
    new: list[Finding],
    *,
    coverage: Sequence[CoverageGap] = (),
) -> DriftReport:
    """Compute finding drift against the newer export's *coverage* gaps.

    *coverage* is :func:`adcs_lens.detection.coverage_gaps` of the newer
    estate. An older posture finding that is absent now, or whose severity
    improved, is withheld into ``indeterminate`` when a gap covers it — the
    newer export never re-evaluated it, so claiming a fix would be a guess.
    With no gaps (the default) every absence is a resolution.
    """
    old_by = {_key(f): f for f in old}
    new_by = {_key(f): f for f in new}

    added = [f for k, f in new_by.items() if k not in old_by]
    resolved: list[Finding] = []
    indeterminate: list[IndeterminateFinding] = []
    for k, f in old_by.items():
        if k in new_by:
            continue
        gap = _gap_for(f, coverage)
        if gap is None:
            resolved.append(f)
        else:
            indeterminate.append(IndeterminateFinding(finding=f, reason=gap.reason))

    changed: list[FindingDelta] = []
    unchanged = 0
    for k, nf in new_by.items():
        of = old_by.get(k)
        if of is None:
            continue
        delta = FindingDelta(old=of, new=nf)
        # Any severity difference (worse or better) is a change; otherwise a
        # content change (same severity, different title/detail/source) is.
        # content_changed is False when severity differs, so the disjunction is
        # exact and the tuple comparison lives in one place.
        if of.severity != nf.severity or delta.content_changed:
            improved = SEVERITY_RANK[nf.severity] > SEVERITY_RANK[of.severity]
            gap = _gap_for(of, coverage) if improved else None
            if gap is not None:
                indeterminate.append(
                    IndeterminateFinding(finding=of, reason=gap.reason, current=nf)
                )
            else:
                changed.append(delta)
        else:
            unchanged += 1

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
    )
