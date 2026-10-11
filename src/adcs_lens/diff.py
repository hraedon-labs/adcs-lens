"""Drift detection over two read-only snapshots (Stance 2).

Pure, stdlib-only. Diffs the findings of an older and a newer export and
reports regressions (new findings), fixes (resolved findings), severity /
content changes, findings that could not be re-evaluated, and coverage-state
transitions.

**Resolution needs positive evidence.** An older posture finding is
``resolved`` only when the newer export positively shows it is gone:

* its object is present in the newer export (paired by identity, below) and the
  newer export holds an *evaluation record* for that check on that object — the
  detector reached the point where every input it needs was present; or
* its object is genuinely absent: the newer export holds a *container record*
  for the check (every object of that type was enumerated) and the object's
  identity is an objectGUID on both sides — or, for older exports without
  GUIDs, the newer export has no unpaired object of that type that could be
  the same one renamed. The GUID rule needs the newer objects themselves to
  agree with the export's ``guid_types`` claim: every newer object of that type
  carries a GUID and none carries this one. The object must also be in the
  older inventory, so the pairing actually looked for it.

Certificates and CRLs are never resolved by absence (an index can be partial).
Everything else lands in ``indeterminate``. A severity *improvement* is
withheld the same way unless the newer side is recorded and states complete
evidence. Because resolution is driven by records the detectors emit, a skip,
an early return or a filter that a detector grows is "not recorded" and so
"withheld" by construction; :func:`adcs_lens.detection.coverage_gaps` only
supplies the human-readable reason.

**Identity is one-to-one.** Objects pair on objectGUID when both exports carry
one; otherwise on aliases (OID / cn / DN / DNS name / fingerprint) that are
unique within each export and pair exactly one object to exactly one object.
Ambiguous identity is never guessed: an older finding on an ambiguous object is
indeterminate, and a newer finding that cannot be uniquely matched is NEW (a
regression), never CHANGED.

Degradation notes (INFO coverage signals) are never "new" or "resolved": their
appearance or disappearance is reported as a coverage-state transition.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Sequence
from dataclasses import dataclass

from adcs_lens.detection import (
    LIFECYCLE_TYPES,
    CoverageGap,
    Evaluation,
    Finding,
    ObjectRef,
    is_degradation_note,
)
from adcs_lens.model import SEVERITY_RANK

_FKey = tuple[str, str, str]


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
    """An older finding the newer export could not positively re-evaluate.

    ``current`` is the newer finding on the same identity when it still exists
    with a better severity (an improvement that cannot be trusted), else None.
    """

    finding: Finding
    reason: str
    current: Finding | None = None


@dataclass(frozen=True)
class CoverageChange:
    """A degradation note that appeared or cleared between the snapshots.

    ``direction`` is ``"appeared"`` or ``"cleared"``. A cleared note is never a
    fix: the area may be better covered, or not evaluated at all.
    """

    finding: Finding
    direction: str


@dataclass(frozen=True)
class DriftReport:
    """The diff between an older and a newer posture snapshot."""

    new: tuple[Finding, ...]  # regressions: posture present now, not matched before
    resolved: tuple[Finding, ...]  # fixes: positively gone now
    changed: tuple[FindingDelta, ...]  # same identity, different severity or content
    unchanged: int  # count of findings identical across both
    # absent (or improved) now, but without positive evidence
    indeterminate: tuple[IndeterminateFinding, ...] = ()
    # degradation notes that appeared / cleared (coverage-state transitions)
    coverage_changes: tuple[CoverageChange, ...] = ()

    @property
    def regressions(self) -> bool:
        """True when posture got worse: a new posture finding or a worsened severity."""
        real_new = any(not is_degradation_note(f) for f in self.new)
        real_worsened = any(
            d.worsened and not is_degradation_note(d.new) for d in self.changed
        )
        return real_new or real_worsened

    @property
    def coverage_lost(self) -> bool:
        """True when any older posture finding could not be re-evaluated."""
        return bool(self.indeterminate)


# --- object pairing ----------------------------------------------------------


def _ambiguous_keys(objects: Sequence[ObjectRef]) -> set[str]:
    """Keys of objects whose identity is not unique within one export.

    With a GUID, only a duplicated GUID is ambiguous (ingest rejects those for
    AD types). Without one, any alias shared with another object of the same
    type is — as is an object appearing twice (e.g. one cert indexed twice).
    """
    out: set[str] = set()
    keys = Counter(o.key for o in objects)
    alias_owners: dict[tuple[str, str], set[str]] = defaultdict(set)
    for o in objects:
        for a in o.aliases:
            alias_owners[(o.type, a)].add(o.key)
    for o in objects:
        if keys[o.key] > 1:
            out.add(o.key)
        elif not o.guid and any(len(alias_owners[(o.type, a)]) > 1 for a in o.aliases):
            out.add(o.key)
    return out


def _alias_kinds(ref: ObjectRef) -> dict[str, str]:
    """{"oid": "1.2.3", "cn": "name", ...} — each alias split at its kind prefix."""
    return dict(a.split(":", 1) for a in ref.aliases if ":" in a)


def _consistent(a: ObjectRef, b: ObjectRef) -> bool:
    """Legacy identity: share an alias AND disagree on none of the kinds both carry.

    A template with the same OID but a different cn (or vice versa) is not
    proven to be the same object, so it is not paired: its older findings are
    withheld and its newer ones count as NEW, rather than one being silently
    relabelled as a CHANGED version of the other.
    """
    ka, kb = _alias_kinds(a), _alias_kinds(b)
    shared = ka.keys() & kb.keys()
    return bool(shared) and all(ka[k] == kb[k] for k in shared)


@dataclass(frozen=True)
class _Pairing:
    old_to_new: dict[str, str]
    ambiguous_old: set[str]
    unpaired_new_by_type: Counter[str]
    old_keys: frozenset[str] = frozenset()  # every object key in the older inventory


def _pair_objects(old: Sequence[ObjectRef], new: Sequence[ObjectRef]) -> _Pairing:
    amb_old, amb_new = _ambiguous_keys(old), _ambiguous_keys(new)
    pairs: dict[str, str] = {}
    paired_new: set[str] = set()
    olds = {o.key: o for o in old if o.key not in amb_old}
    news = {n.key: n for n in new if n.key not in amb_new}

    # 1. objectGUID on both sides.
    new_by_guid = {(n.type, n.guid): n for n in news.values() if n.guid}
    for o in olds.values():
        if o.guid and (o.type, o.guid) in new_by_guid:
            n = new_by_guid[(o.type, o.guid)]
            pairs[o.key] = n.key
            paired_new.add(n.key)

    # 2. Aliases, only where a GUID is missing on at least one side, only on
    #    aliases unique within each export, and only one-to-one.
    rem_old = [o for k, o in olds.items() if k not in pairs]
    rem_new = [n for k, n in news.items() if k not in paired_new]
    cand_new: dict[str, list[ObjectRef]] = {}
    cand_old: dict[str, list[ObjectRef]] = defaultdict(list)
    for o in rem_old:
        matches = [
            n for n in rem_new
            if n.type == o.type and not (o.guid and n.guid) and _consistent(o, n)
        ]
        cand_new[o.key] = matches
        for n in matches:
            cand_old[n.key].append(o)
    cross_ambiguous: set[str] = set()
    for o in rem_old:
        matches = cand_new[o.key]
        if len(matches) == 1 and len(cand_old[matches[0].key]) == 1:
            pairs[o.key] = matches[0].key
            paired_new.add(matches[0].key)
        elif len(matches) > 1 or any(len(cand_old[n.key]) > 1 for n in matches):
            cross_ambiguous.add(o.key)

    unpaired: Counter[str] = Counter(n.type for n in new if n.key not in paired_new)
    return _Pairing(pairs, amb_old | cross_ambiguous, unpaired, frozenset(o.key for o in old))


# --- finding matching -------------------------------------------------------


def _fkey(f: Finding, object_key: str | None) -> _FKey:
    if f.object_ref is None:
        return (f.check, f.variant, f"legacy:{f.subject}\x00{f.source}")
    return (f.check, f.variant, object_key or f.object_ref.key)


def _gap_reason(f: Finding, coverage: Sequence[CoverageGap]) -> str | None:
    gap = next((g for g in coverage if g.covers(f)), None)
    return gap.reason if gap is not None else None


def _withhold_absent(
    f: Finding,
    old_key: str,
    pairing: _Pairing,
    new: Evaluation,
    coverage: Sequence[CoverageGap],
) -> str | None:
    """Why an older posture finding with no newer match may NOT resolve (None = may)."""
    if new.trusted:
        return None
    explain = _gap_reason(f, coverage)
    ref = f.object_ref
    if ref is None:
        return explain or "the finding has no stable object identity"
    if old_key in pairing.ambiguous_old:
        return (
            "the object's identity is ambiguous (shared OID/name/fingerprint), "
            "so it cannot be matched"
        )
    new_key = pairing.old_to_new.get(old_key)
    if new_key is not None:
        # Same object, still present: resolved only if positively re-evaluated.
        if new.evaluated(f.check, f.variant, new_key):
            return None
        return explain or f"{f.check} was not fully evaluated for this object in the newer export"
    if ref.type in LIFECYCLE_TYPES:
        return (
            "the certificate/CRL is absent from the newer export; absence from a "
            "cert/CRL index is not evidence of a fix (the index can be partial)"
        )
    if not new.container_evaluated(f.check, ref.type):
        return explain or f"{f.check} did not enumerate every {ref.type} in the newer export"
    if ref.key not in pairing.old_keys:
        # The finding names an object the older inventory does not hold, so the
        # pairing never looked for it: absence of a pair proves nothing.
        return explain or "the finding's object is not in the older export's inventory"
    same_type = [n for n in new.objects if n.type == ref.type]
    if ref.guid and any(n.guid == ref.guid for n in same_type):
        # Present but unpaired (e.g. its GUID is duplicated in the newer export).
        return "an object with this objectGUID is still in the newer export but cannot be matched"
    # Defence in depth: ``guid_types`` is the producer's claim; it is honoured
    # only when the newer objects themselves agree, i.e. every newer object of
    # this type carries a GUID. A GUID-less one could be this object renamed,
    # so the type falls back to the conservative legacy rule below.
    if ref.guid and ref.type in new.guid_types and all(n.guid for n in same_type):
        return None  # objectGUID absent from a fully enumerated container: really gone
    if pairing.unpaired_new_by_type[ref.type]:
        return (
            f"identity is not stable for this {ref.type} (no objectGUID): "
            f"{pairing.unpaired_new_by_type[ref.type]} unmatched {ref.type}(s) in the newer "
            "export could be this one renamed"
        )
    return None


def _withhold_improvement(
    old: Finding,
    nf: Finding,
    new_key: str,
    new: Evaluation,
    coverage: Sequence[CoverageGap],
) -> str | None:
    if not new.trusted and not new.evaluated(nf.check, nf.variant, new_key):
        return _gap_reason(old, coverage) or (
            f"{nf.check} was not fully evaluated for this object in the newer export"
        )
    if not nf.evidence_complete:
        return "the newer severity was computed from weaker evidence (an unknown input)"
    return None


def _as_eval(x: Evaluation | Sequence[Finding]) -> Evaluation:
    return x if isinstance(x, Evaluation) else Evaluation.from_findings(tuple(x))


def diff_findings(
    old: Evaluation | Sequence[Finding],
    new: Evaluation | Sequence[Finding],
    *,
    coverage: Sequence[CoverageGap] = (),
) -> DriftReport:
    """Compute drift from the older to the newer :class:`Evaluation`.

    Plain finding lists are wrapped as *trusted* evaluations (hand-built
    findings with no estate behind them). *coverage* is
    :func:`adcs_lens.detection.coverage_gaps` of the newer estate and is used
    only to explain withheld findings.
    """
    old_ev, new_ev = _as_eval(old), _as_eval(new)
    pairing = _pair_objects(old_ev.objects, new_ev.objects)
    amb_new_objects = _ambiguous_keys(new_ev.objects)

    # Newer findings indexed by identity; duplicates (or findings on ambiguous
    # objects) are never matched, so they surface as NEW.
    new_index: dict[_FKey, list[Finding]] = defaultdict(list)
    for nf in new_ev.findings:
        if nf.object_ref is not None and nf.object_ref.key in amb_new_objects:
            continue
        new_index[_fkey(nf, None)].append(nf)
    old_counts = Counter(
        _fkey(f, None) for f in old_ev.findings
    )

    added: list[Finding] = []
    resolved: list[Finding] = []
    indeterminate: list[IndeterminateFinding] = []
    coverage_changes: list[CoverageChange] = []
    changed: list[FindingDelta] = []
    unchanged = 0
    matched_new: set[int] = set()

    for of in old_ev.findings:
        old_key = of.object_ref.key if of.object_ref is not None else ""
        if of.object_ref is not None:
            new_obj = pairing.old_to_new.get(old_key)
            candidates = new_index.get(_fkey(of, new_obj), []) if new_obj else []
        else:
            candidates = new_index.get(_fkey(of, None), [])
        unique = (
            len(candidates) == 1
            and old_counts[_fkey(of, None)] == 1
            and id(candidates[0]) not in matched_new
        )
        if not unique:
            if is_degradation_note(of):
                coverage_changes.append(CoverageChange(finding=of, direction="cleared"))
                continue
            if candidates or old_counts[_fkey(of, None)] > 1:
                indeterminate.append(
                    IndeterminateFinding(
                        finding=of, reason="the finding cannot be matched one-to-one"
                    )
                )
                continue
            reason = _withhold_absent(of, old_key, pairing, new_ev, coverage)
            if reason is None:
                resolved.append(of)
            else:
                indeterminate.append(IndeterminateFinding(finding=of, reason=reason))
            continue
        nf = candidates[0]
        matched_new.add(id(nf))
        delta = FindingDelta(old=of, new=nf)
        if of.severity == nf.severity and not delta.content_changed:
            unchanged += 1
            continue
        improved = SEVERITY_RANK[nf.severity] > SEVERITY_RANK[of.severity]
        reason = None
        if improved and not is_degradation_note(of):
            new_key = nf.object_ref.key if nf.object_ref is not None else ""
            reason = _withhold_improvement(of, nf, new_key, new_ev, coverage)
        if reason is not None:
            indeterminate.append(IndeterminateFinding(finding=of, reason=reason, current=nf))
        else:
            changed.append(delta)

    for candidate in new_ev.findings:
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
