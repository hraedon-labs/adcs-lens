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
"""

from __future__ import annotations

from dataclasses import dataclass

from adcs_lens.detection import Finding, is_degradation_note
from adcs_lens.model import SEVERITY_RANK, Estate


def incomplete_coverage_checks(estate: Estate) -> frozenset[str]:
    """Checks whose absence cannot prove resolution in this snapshot.

    Detectors already suppress findings when their required input was not
    collected. Drift must carry that coverage boundary forward: otherwise a
    skipped detector looks identical to a fixed finding. This returns check IDs
    whose old findings must not be classified as resolved against *estate*.
    """
    unavailable: set[str] = set()
    if not estate.manifest.enrollment_services_available:
        unavailable.add("ORPHANED_TEMPLATE")
    return frozenset(unavailable)


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
class DriftReport:
    """The diff between an older and a newer posture snapshot."""

    new: tuple[Finding, ...]  # regressions: present now, absent before
    resolved: tuple[Finding, ...]  # fixes: present before, absent now
    # same (check, subject, source), different severity or content
    changed: tuple[FindingDelta, ...]
    unchanged: int  # count of findings identical across both

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


def diff_findings(
    old: list[Finding],
    new: list[Finding],
    *,
    incomplete_checks: frozenset[str] = frozenset(),
) -> DriftReport:
    """Compute finding drift, withholding resolutions for incompletely evaluated checks."""
    old_by = {_key(f): f for f in old}
    new_by = {_key(f): f for f in new}

    added = [f for k, f in new_by.items() if k not in old_by]
    resolved = [
        f
        for k, f in old_by.items()
        if k not in new_by and f.check not in incomplete_checks
    ]
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
            changed.append(delta)
        else:
            unchanged += 1

    return DriftReport(
        new=tuple(_worst_first(added)),
        resolved=tuple(_worst_first(resolved)),
        changed=tuple(sorted(changed, key=lambda d: (SEVERITY_RANK[d.new.severity], d.new.check))),
        unchanged=unchanged,
    )
