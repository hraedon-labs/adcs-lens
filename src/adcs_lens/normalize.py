"""Normalization helpers — SIDs, join keys and host names.

Pure, stdlib-only. Kept separate from ingest so detectors that reason about
*who* a right is granted to (ESC4/5/7, later) share one definition of
"low-privilege trustee" rather than re-deriving it.
"""

from __future__ import annotations

import unicodedata
from collections.abc import Iterable

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


# --- host names (WI-044: which host an IIS endpoint was read on) ------------------
#
# The collector reads IIS on its own host only, so an endpoint, and the absence
# of one, is evidence about that host alone. Host names are compared as DNS
# names (RFC 4343): ASCII letters A-Z case-insensitively, nothing else folded,
# and one trailing root dot ignored. A name that is not an ASCII host name -
# a non-ASCII (IDN U-label) name, an empty label, a repeated trailing dot, a
# character outside letters, digits, "-" and "_" - is not compared at all: it
# matches nothing, so nothing resolves on it (Sol round 2: Unicode case folding
# merged distinct names such as "straße" and "strasse"). Two FQDNs match only
# when they are the same name - "ca1.admin.example" is not "ca1.pki.example"
# although their first labels agree. A short name (no dot: collector 0.10.0
# wrote only the short host name) matches an FQDN with that first label only
# when no other known FQDN has the same first label; otherwise it could be
# either machine and matches neither. Two different short names never match.

_ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")
_HOST_LABEL = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-_")


def host_key(name: str) -> str:
    """A host name as compared: trimmed, one trailing root dot dropped, A-Z
    lower-cased; '' when it is not an ASCII host name (see above), so it
    matches nothing."""
    key = name.strip()
    if key.endswith("."):
        key = key[:-1]
    key = key.translate(_ASCII_LOWER)
    labels = key.split(".")
    if not key or len(key) > 253:
        return ""
    for label in labels:
        if not label or len(label) > 63 or not set(label).issubset(_HOST_LABEL):
            return ""
    return key


def fqdn_names_host(fqdn: str, host: str) -> bool:
    """Whether *fqdn* is a host name whose first label is the short *host* name
    (the collector writes both for its own host; DS / Sol round 2)."""
    key = host_key(fqdn)
    return bool(key) and key.split(".", 1)[0] == host_key(host)


def same_host(a: str, b: str, known: Iterable[str] = ()) -> bool:
    """Whether host names *a* and *b* certainly name one machine (see above).

    *known* holds every host name the caller knows of (CA hosts, endpoint
    hosts); a short name that fits more than one known FQDN matches none.
    """
    a, b = host_key(a), host_key(b)
    if not a:
        return False  # (an empty b never matches below either)
    if a == b:
        return True
    # Otherwise exactly one of them must be a short name with the other's first
    # label: two different FQDNs, or two different short names, never match.
    short, fqdn = (a, b) if "." in b else (b, a)
    if "." in short or fqdn.split(".", 1)[0] != short:
        return False
    rivals = {
        k for k in (host_key(n) for n in known) if "." in k and k.split(".", 1)[0] == short
    } - {fqdn}
    return not rivals


def endpoint_scope_gaps(
    collector_host: str, cas: Iterable[tuple[str, str, bool]]
) -> tuple[str, ...]:
    """Why the IIS endpoint list cannot cover every CA host (empty when it can).

    *cas* holds ``(name, dns, enrollment_service)`` for every CA row. The list
    speaks for the CA estate only when the collector host is a CA host and every
    enrollment-service CA runs on it (WI-044: a non-CA IIS host used to export a
    complete, empty list, and diff resolved ESC8). A CA row without an
    enrollment service (a standalone local CA, an offline root) counts only as
    evidence that the collector host is a CA host, when its DNS name is that host.
    """
    rows = list(cas)
    known = [dns for _name, dns, _es in rows]  # same_host ignores an empty name
    elsewhere: list[str] = []
    ca_host_here = False
    for name, dns, enrollment_service in rows:
        here = same_host(collector_host, dns, known)
        if not enrollment_service:
            ca_host_here = ca_host_here or here
        elif not dns:
            elsewhere.append(f"{name} (no dNSHostName)")
        elif here:
            ca_host_here = True
        else:
            elsewhere.append(dns)
    gaps: list[str] = []
    if not ca_host_here:
        gaps.append(f"the collector host {collector_host or '(unnamed)'!r} is not a CA host")
    if elsewhere:
        gaps.append("CA host(s) not inspected: " + ", ".join(sorted(elsewhere)))
    return tuple(gaps)
