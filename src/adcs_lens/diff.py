"""Drift detection over two read-only snapshots (Stance 2).

Pure, stdlib-only. Diffs the findings of an older and a newer export and
reports regressions (new findings), fixes (resolved findings), severity /
content changes, findings that could not be re-evaluated, and coverage-state
transitions.

**Resolution needs positive evidence.** An older posture finding is
``resolved`` only when the newer export positively shows it is gone:

* its object is present in the newer export (paired by identity, below) and the
  newer export holds a *usable verdict* that clears that check on that object:
  the detector decided the object from inputs that were all obtained, every
  container the check declares (its own and dependencies such as ESC15's CAs
  or ESC14's DCs) was proven completely enumerated, and the verdict is not a
  finding; or
* its object is genuinely absent: the check enumerated every object of that
  type with all its declared containers complete, and the object's identity is
  an objectGUID on both sides — the newer objects themselves must agree with the
  export's ``guid_types`` claim (every newer object of that type carries a GUID
  and none carries this one), and the object must be in the older inventory, so
  the pairing actually looked for it. A type without GUID identity (HTTP
  endpoints, and the GUID-exempt standalone CA / unreadable fixed PKI
  container) resolves by absence only when no unpaired newer object of that type
  could be the same one renamed.

Verdicts are usable only from a collector that proves its reads (>=
PROVEN_READS_VERSION, 0.10.0): an older export never resolves anything — there
is no legacy fallback. Certificates and CRLs are never resolved by absence (an
index can be partial). Everything else lands in ``indeterminate``. A severity
*improvement* is withheld the same way unless the newer side has a usable
verdict and states complete evidence. Because a verdict function that skips,
returns early or reads an input that was not obtained yields no usable clearing
verdict, such a path is "withheld" by construction;
:func:`adcs_lens.detection.coverage_gaps` only supplies the human-readable
reason. Whether a usable CLEAN verdict is *correct* is detection correctness,
pinned by the functional tests and the mutation gate
(tests/test_mutation_gate.py).

Threat model: exports come from the adcs-lens collector and may be partial
(reads fail, pages or limits truncate a search, a pass throws); the collector
records each such failure (null field, ``complete: false`` marker) rather than
writing an empty value. A hand-forged export that lies about what was read is
out of scope for ``diff``.

**Identity is one-to-one.** Objects pair on objectGUID when both exports carry
one; otherwise on aliases (OID / cn / DN / DNS name / fingerprint) that are
unique within each export and pair exactly one object to exactly one object.
Ambiguous identity is never guessed: an older finding on an ambiguous object is
indeterminate, and a newer finding that cannot be uniquely matched is NEW (a
regression), never CHANGED.

Degradation notes (INFO coverage signals) are never "new" or "resolved": their
appearance or disappearance is reported as a coverage-state transition.

**Coverage gained is labelled.** A newer finding the older export could not
have reported - its object belongs to a population the older collector did not
collect (``Evaluation.uncollected``), or its check reads a field the two exports
decoded with different tables (``Evaluation.superseded_checks``) - is listed in
``first_observed``, not ``new``. It still counts as a regression for
``--exit-code`` (a newly visible finding fails the gate); it is not proof that
the estate changed. Across such a gap nothing is resolved or improved either.

**A blocked comparison is coverage loss.** When the older export decided a check
(a usable verdict on an object, or a complete enumeration) and the newer export
cannot (an incomplete container, an input not obtained), the check is listed in
``unevaluated`` and ``coverage_lost`` is true even if no older finding existed
to withhold. The detectors themselves never draw a finding from an absence in an
incomplete container (no publisher, no unpatched CA, no non-strict DC): such an
object is undecided, so a partial enumeration cannot manufacture a regression.
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
        o, n = self.old, self.new
        return (o.title, o.detail, o.subject, o.source) != (n.title, n.detail, n.subject, n.source)


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
class UnevaluatedCheck:
    """A check the older export decided but the newer export could not.

    Raised even when the older export had no finding to withhold: an incomplete
    container (or an input not obtained) in the newer export blocks the
    comparison, so a new problem there would be invisible. ``objects`` counts
    the paired objects whose older verdict was usable and newer one is not
    (0 when only whole-container enumeration was lost).
    """

    check: str
    objects: int
    reason: str


@dataclass(frozen=True)
class CoverageChange:
    """A degradation note that appeared or cleared between the snapshots.

    ``direction`` is ``"appeared"`` or ``"cleared"``. A cleared note is never a
    fix: the area may be better covered, or not evaluated at all.
    """

    finding: Finding
    direction: str


@dataclass(frozen=True)
class FirstObservation:
    """A newer finding the older export could not have reported: its object
    belongs to a population the older collector did not collect, or its check
    reads a field the two exports decoded with different tables. It counts as a
    regression for ``--exit-code`` (a newly visible finding must fail a gate) but
    is labelled "first observed: coverage gained", not as proof that the estate
    worsened (review round 2, Sol B1)."""

    finding: Finding
    reason: str


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
    # checks the older export decided that the newer export could not
    unevaluated: tuple[UnevaluatedCheck, ...] = ()
    # newer findings the older export could not have reported (coverage gained)
    first_observed: tuple[FirstObservation, ...] = ()

    @property
    def regressions(self) -> bool:
        """True when posture got worse - a new posture finding or a worsened
        severity - or a posture finding is first observed after coverage was
        gained (a newly visible finding fails the gate; it is labelled apart)."""
        real_new = any(not is_degradation_note(f) for f in self.new)
        real_worsened = any(d.worsened and not is_degradation_note(d.new) for d in self.changed)
        first = any(not is_degradation_note(o.finding) for o in self.first_observed)
        return real_new or real_worsened or first

    @property
    def coverage_lost(self) -> bool:
        """True when an older finding or a check the older export decided could
        not be re-evaluated by the newer export."""
        return bool(self.indeterminate) or bool(self.unevaluated)


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


def _consistent(a: ObjectRef, b: ObjectRef, known: frozenset[str] = frozenset()) -> bool:
    """Legacy identity: share an alias AND disagree on none of the kinds both carry.

    A template with the same OID but a different cn (or vice versa) is not
    proven to be the same object, so it is not paired: its older findings are
    withheld and its newer ones count as NEW, rather than one being silently
    relabelled as a CHANGED version of the other. An endpoint also needs a
    compatible host (WI-044): "/CertSrv" on two machines is two objects. A
    collector 0.10.0 endpoint's host is that export's short host name, which
    pairs with an FQDN of that first label only when no other known FQDN has it.
    """
    ka, kb = _alias_kinds(a), _alias_kinds(b)
    shared = ka.keys() & kb.keys()
    return bool(shared) and all(ka[k] == kb[k] for k in shared) and b.host_compatible(a, known)


@dataclass(frozen=True)
class _Pairing:
    old_to_new: dict[str, str]
    ambiguous_old: set[str]
    unpaired_new_by_type: Counter[str]
    old_keys: frozenset[str] = frozenset()  # every object key in the older inventory
    # Every host name either export mentions: host comparison (pairing and the
    # endpoint absence rule) uses both exports' knowledge (WI-044).
    known: frozenset[str] = frozenset()


def _pair_objects(
    old: Sequence[ObjectRef], new: Sequence[ObjectRef], known: frozenset[str] = frozenset()
) -> _Pairing:
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
            n
            for n in rem_new
            if n.type == o.type and not (o.guid and n.guid) and _consistent(o, n, known)
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
    return _Pairing(
        pairs, amb_old | cross_ambiguous, unpaired, frozenset(o.key for o in old), known
    )


# --- finding matching -------------------------------------------------------


def _fkey(f: Finding, object_key: str | None) -> _FKey:
    if f.object_ref is None:
        return (f.check, f.variant, f"legacy:{f.subject}\x00{f.source}")
    return (f.check, f.variant, object_key or f.object_ref.key)


def _gap_reason(f: Finding, coverage: Sequence[CoverageGap]) -> str | None:
    gap = next((g for g in coverage if g.covers(f)), None)
    return gap.reason if gap is not None else None


def _decoder_gap(check: str, old: Evaluation, new: Evaluation) -> str | None:
    """Why *check* cannot be compared between the exports: it reads a field one
    of them decoded with a superseded table (model.DECODER_VERSIONS)."""
    if check not in old.superseded_checks ^ new.superseded_checks:
        return None
    return (
        f"the exports decode {check}'s inputs with different tables (a collector older "
        "than 0.12.0 decoded template name flags with several bits shifted), so the "
        "difference may be the decoder's, not the estate's; compare exports from "
        "collector 0.12.0 or later"
    )


def _first_observed(f: Finding, old: Evaluation, new: Evaluation) -> str | None:
    """Why a newer finding could not have been reported by the older export."""
    ref = f.object_ref
    if ref is not None and ref.population and ref.population in old.uncollected:
        return (
            f"first observed: coverage gained - the older export's collector did not "
            f"collect {ref.population} objects"
        )
    if f.check in old.superseded_checks ^ new.superseded_checks:
        return (
            "first observed: coverage gained - the exports decode this check's inputs "
            "with different tables (template name flags, corrected in collector 0.12.0)"
        )
    return None


def _withhold_absent(
    f: Finding,
    old_key: str,
    pairing: _Pairing,
    new: Evaluation,
    coverage: Sequence[CoverageGap],
    old: Evaluation | None = None,
) -> str | None:
    """Why an older posture finding with no newer match may NOT resolve (None = may)."""
    if new.trusted:
        return None
    if old is not None and (gap := _decoder_gap(f.check, old, new)):
        return gap
    explain = _gap_reason(f, coverage)
    ref = f.object_ref
    if ref is None:
        return explain or "the finding has no stable object identity"
    if old_key in pairing.ambiguous_old:
        return (
            "the object's identity is ambiguous (shared OID/name/fingerprint), "
            "so it cannot be matched"
        )
    if ref.population and ref.population in new.uncollected:
        # The newer export's collector predates this population (e.g. the CA
        # hosts' computer objects, collector 0.12.0): it did not look.
        return (
            f"the newer export's collector does not collect {ref.population} objects, "
            "so it says nothing about this one"
        )
    if ref.type == "endpoint" and not new.inspected_host(ref.host, pairing.known):
        # WI-044: IIS is read on the collector host only. An endpoint on a host
        # the newer export did not read (a dedicated Web Enrollment / CES
        # server, another CA host), on a short name either export knows to be
        # ambiguous, or on no valid host at all, is neither present nor absent
        # there.
        return (
            f"the newer export did not read IIS on {ref.host or '(no host)'} (it read "
            f"{', '.join(sorted(new.inspected_hosts)) or 'no host'}), so it says nothing "
            "about this endpoint"
        )
    new_key = pairing.old_to_new.get(old_key)
    if new_key is not None:
        # Same object, still present: resolved only on a usable clearing verdict.
        if new.clears(f.check, f.variant, new_key):
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
    # so the type falls back to the alias rule below (the only rule for types
    # with no GUID identity, such as HTTP endpoints).
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
    old_ev: Evaluation | None = None,
) -> str | None:
    if not new.trusted and old_ev is not None and (gap := _decoder_gap(nf.check, old_ev, new)):
        return gap
    if not new.trusted and not new.evaluated(nf.check, nf.variant, new_key):
        return _gap_reason(old, coverage) or (
            f"{nf.check} was not fully evaluated for this object in the newer export"
        )
    if not nf.evidence_complete:
        return "the newer severity was computed from weaker evidence (an unknown input)"
    if not new.trusted and not old.evidence_complete:
        # The older severity was the stricter reading of an unknown input (e.g.
        # msPKI-RA-Signature before collector 0.12.0): a lower one now may only
        # mean the input became known, not that the estate changed.
        return (
            "the older severity was computed from weaker evidence (an unknown input), "
            "so a lower severity now is not proof of a change"
        )
    return None


def _unevaluated(
    old: Evaluation,
    new: Evaluation,
    pairing: _Pairing,
    coverage: Sequence[CoverageGap],
) -> tuple[UnevaluatedCheck, ...]:
    """Checks the older export decided and the newer one cannot (see UnevaluatedCheck)."""
    if old.trusted or new.trusted:
        return ()
    lost: defaultdict[str, set[str]] = defaultdict(set)
    # Objects of a population the newer export's collector does not collect:
    # the older verdict on them cannot be compared at all.
    not_looked = {o.key for o in old.objects if o.population and o.population in new.uncollected}
    for check, variant, key in old.records:
        if key in not_looked:
            lost[check].add(key)
            continue
        new_key = pairing.old_to_new.get(key)
        if new_key is not None and not new.evaluated(check, variant, new_key):
            lost[check].add(new_key)  # objects, not verdict variants
    checks = set(lost) | {c for c, t in old.containers if not new.container_evaluated(c, t)}
    out = []
    for check in sorted(checks):
        gap = next(
            (g for g in coverage if g.checks is None or check in g.checks),
            None,
        )
        reason = (
            gap.reason
            if gap is not None
            else (f"the newer export could not decide {check} where the older export did")
        )
        out.append(UnevaluatedCheck(check=check, objects=len(lost[check]), reason=reason))
    return tuple(out)


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
    pairing = _pair_objects(old_ev.objects, new_ev.objects, old_ev.known_hosts | new_ev.known_hosts)
    amb_new_objects = _ambiguous_keys(new_ev.objects)

    # Newer findings indexed by identity; duplicates (or findings on ambiguous
    # objects) are never matched, so they surface as NEW.
    new_index: dict[_FKey, list[Finding]] = defaultdict(list)
    for nf in new_ev.findings:
        if nf.object_ref is not None and nf.object_ref.key in amb_new_objects:
            continue
        new_index[_fkey(nf, None)].append(nf)
    old_counts = Counter(_fkey(f, None) for f in old_ev.findings)

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
            reason = _withhold_absent(of, old_key, pairing, new_ev, coverage, old_ev)
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
            reason = _withhold_improvement(of, nf, new_key, new_ev, coverage, old_ev)
        if reason is not None:
            indeterminate.append(IndeterminateFinding(finding=of, reason=reason, current=nf))
        else:
            changed.append(delta)

    first_observed: list[FirstObservation] = []
    for candidate in new_ev.findings:
        if id(candidate) in matched_new:
            continue
        if is_degradation_note(candidate):
            coverage_changes.append(CoverageChange(finding=candidate, direction="appeared"))
        elif not new_ev.trusted and (why := _first_observed(candidate, old_ev, new_ev)):
            first_observed.append(FirstObservation(finding=candidate, reason=why))
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
        unevaluated=_unevaluated(old_ev, new_ev, pairing, coverage),
        first_observed=tuple(
            sorted(
                first_observed,
                key=lambda o: (SEVERITY_RANK[o.finding.severity], o.finding.check),
            )
        ),
    )
