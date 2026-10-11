"""Normalization helpers — SIDs and join keys.

Pure, stdlib-only. Kept separate from ingest so detectors that reason about
*who* a right is granted to (ESC4/5/7, later) share one definition of
"low-privilege trustee" rather than re-deriving it.
"""

from __future__ import annotations

import unicodedata

# Well-known SIDs that name a principal whose compromise is already
# domain-compromise-class (or the machine/service accounts that hold the keys
# anyway). A privileged right (enroll, write, ManageCA) granted to one of these
# is NOT an escalation finding — the trustee already has equivalent or greater
# power. Anything *outside* this set is treated as low-privilege.
#
# The classification is deliberately an allowlist of high-privilege SIDs rather
# than a blocklist of broad/low-privilege ones: the earlier blocklist missed
# custom groups entirely (e.g. Enroll granted to a purpose-built "Help Desk"
# group silently produced no ESC1 finding — a domain-compromise-class false
# negative, confirmed against the pre-inversion code). Failing toward flagging
# is the right direction for a defensive tool: a custom *privileged* group may
# read as a finding (noise), but no low-privilege trustee is ever silently
# invisible. Surfaced as the ACL_GROUP_TOKEN_CAVEAT estate note.
#
# Domain-relative RIDs (Domain Admins -512, ...) must be matched only under the
# domain SID prefix S-1-5-21-* — a bare "-512" suffix can belong to an unrelated
# group (the exact false-match gpo-lens had to fix for MS16-072).
_ABSOLUTE_HIGH_PRIV: frozenset[str] = frozenset(
    {
        "S-1-5-18",  # Local System
        "S-1-5-19",  # Local Service
        "S-1-5-20",  # Network Service
        "S-1-5-9",  # Enterprise Domain Controllers
        "S-1-5-32-544",  # BUILTIN\Administrators
        "S-1-5-32-548",  # Account Operators
        "S-1-5-32-549",  # Server Operators
        "S-1-5-32-550",  # Print Operators
        "S-1-5-32-551",  # Backup Operators
    }
)
_DOMAIN_HIGH_PRIV_RIDS: frozenset[str] = frozenset(
    {
        "500",  # Administrator
        "502",  # krbtgt
        "512",  # Domain Admins
        "516",  # Domain Controllers
        "517",  # Cert Publishers (holds the CA machine accounts)
        "518",  # Schema Admins
        "519",  # Enterprise Admins
        "526",  # Key Admins
        "527",  # Enterprise Key Admins
    }
)


def normalize_sid(sid: str) -> str:
    """Canonicalize a SID string: trim and upper-case the ``S-`` form."""
    s = sid.strip()
    if s[:2].upper() == "S-":
        return "S-" + s[2:].upper()
    return s


def is_low_priv_trustee(sid: str) -> bool:
    """True unless *sid* names a known high-privilege principal.

    Allowlist semantics: only the curated high-privilege set (built-in admin
    and operator groups, SYSTEM and service identities, domain trust accounts,
    and the well-known domain RIDs such as Domain/Enterprise/Schema Admins) is
    treated as privileged. Every other trustee — Everyone, Authenticated Users,
    Domain Users/Computers, custom groups, and named user or computer accounts —
    is treated as low-privilege, so an enabling right granted to any of them is
    surfaced rather than silently missed.

    Domain-relative RIDs only match under the ``S-1-5-21-`` domain prefix, so a
    coincidental ``*-512`` on an unrelated well-known SID does not suppress a
    finding.
    """
    s = normalize_sid(sid)
    if s in _ABSOLUTE_HIGH_PRIV:
        return False
    if s.startswith("S-1-5-21-"):
        rid = s.rsplit("-", 1)[-1]
        return rid not in _DOMAIN_HIGH_PRIV_RIDS
    return True


# --- joins between objects -------------------------------------------------------
#
# An identity or join key is compared EXACTLY as the protocol stores it: a
# template's cn in certificateTemplates is "identical" to the template's cn
# (MS-WCCE), a CA's cn is written by the collector into every file that names
# it, and an OID is a dotted-decimal string. No join strips, case-folds or
# Unicode-normalizes a key to make it match. A reference that is not identical
# to any candidate but equal to one under that folding (" LabWebServer ",
# "labwebserver", a compatibility-equivalent character) is AMBIGUOUS, never a
# match: the joined field is not obtained for every candidate it folds to.

JOIN_ONE = "one"
JOIN_NONE = "none"
JOIN_AMBIGUOUS = "ambiguous"


def join_fold(value: str) -> str:
    """The folding under which two keys could be confused (never used to match)."""
    return unicodedata.normalize("NFKC", value).strip().casefold()


def resolve_join[T](ref: str, candidates: list[tuple[str, T]]) -> tuple[str, list[T]]:
    """Match *ref* against ``(key, object)`` candidates, exactly and uniquely.

    Returns ``(JOIN_ONE, [obj])`` when exactly one candidate's key is identical
    to *ref* and no other candidate folds to it; ``(JOIN_NONE, [])`` when no
    candidate is identical or folds to it; otherwise ``(JOIN_AMBIGUOUS, objs)``
    with every candidate that is identical or folds to *ref*.
    """
    folded = join_fold(ref)
    exact = [obj for key, obj in candidates if key == ref]
    near = [obj for key, obj in candidates if key != ref and join_fold(key) == folded]
    if len(exact) == 1 and not near:
        return JOIN_ONE, exact
    if not exact and not near:
        return JOIN_NONE, []
    return JOIN_AMBIGUOUS, exact + near
