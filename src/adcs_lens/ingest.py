"""Ingest a read-only collector export directory into a normalized :class:`Estate`.

Stdlib-only. Cert/CRL (DER) parsing is delegated lazily to the optional
:mod:`adcs_lens.certs` module (the ``[certs]`` extra); when it is unavailable
the import fails softly, lifecycle fields stay ``None``, and
:attr:`Manifest.certs_parsed` is ``False`` so the lifecycle detector degrades to
a note instead of producing wrong answers.

The JSON shapes read here are the ingest contract: the future PowerShell
collector (``scripts/Export-AdcsEstate.ps1``, Plan 001 Phase 1) and the
synthetic test fixtures both target them. BOM-tolerant (``utf-8-sig``) because
PowerShell 5.1 writes UTF-8 with a BOM.
"""

from __future__ import annotations

import json
import re
from dataclasses import replace
from pathlib import Path
from typing import Any, NamedTuple

from adcs_lens import limits
from adcs_lens.model import (
    GUID_IDENTITY_VERSION,
    JOIN_KEYS,
    KNOWN_PASSES,
    MIN_COLLECTOR_VERSION,
    PASS_FILES,
    PROVEN_READS_VERSION,
    SCHANNEL_MAPPING_BITS,
    TEMPLATE_ENROLLMENT_FLAGS,
    TEMPLATE_NAME_FLAGS,
    AceEntry,
    AceType,
    AclKind,
    CaKind,
    CaPatchState,
    CertAuthority,
    CertKind,
    CertLifecycle,
    CertTemplate,
    CollectorVersionStatus,
    Crl,
    CrlTier,
    DcConfiguration,
    EndpointKind,
    EnrollmentEndpoint,
    EpaPolicy,
    Estate,
    IssuanceOid,
    Manifest,
    PkiObjectAcl,
    PrincipalMapping,
    SchannelMappingMethod,
    StrongCertBinding,
    collector_version_status,
    decode_flags,
    version_attributes_hosts,
    version_has_guid_identity,
    version_proves_reads,
    version_reads_ra_signatures,
)
from adcs_lens.normalize import (
    JOIN_AMBIGUOUS,
    JOIN_ONE,
    endpoint_scope_gaps,
    fqdn_names_host,
    host_key,
    join_fold,
    normalize_sid,
    resolve_join,
)


class IngestError(ValueError):
    """Raised when an export file is malformed or violates the ingest contract."""


# Fields a collector at/above MIN is expected to emit; named in the warning so
# an operator knows which detectors may degrade on a stale export.
_STALE_COLLECTOR_FIELDS = (
    "certs/index.json",
    "registry_config_collected",
    "kind",
    "acl_obtained (pki-acls)",
)


def collector_compat_warning(manifest: Manifest) -> str | None:
    """Return a warning when the collector is not known to be current.

    A pre-minimum collector may omit fields the detectors branch on (an older
    collector emits no ``ca_patch_state`` → ESC15 degrades to MEDIUM-unknown, no
    ``owner_sid`` → owner-based ESC4/ESC5 control is skipped, no ``csp`` → the
    weak-key detector falls back to the RSA baseline). The core degrades
    honestly either way; this warning keeps a stale export from reading as
    silently clean. An unknown/unparseable version is warned about too: it
    cannot be ranked, so it is never assumed current. Returns ``None`` only for
    a current collector.
    """
    status = manifest.collector_version_status
    if status is CollectorVersionStatus.CURRENT:
        return None
    fields = ", ".join(_STALE_COLLECTOR_FIELDS)
    if status is CollectorVersionStatus.UNKNOWN:
        return (
            f"collector version {manifest.collector_version or '(missing)'!r} is unknown "
            f"or unparseable, so the export cannot be confirmed to come from a collector "
            f">= {MIN_COLLECTOR_VERSION}; fields ({fields}) may be absent and some "
            "detectors will degrade. Re-run with a current collector for full coverage."
        )
    return (
        f"collector {manifest.collector_version} is older than the "
        f"minimum adcs-lens expects ({MIN_COLLECTOR_VERSION}); fields "
        f"({fields}) may be absent and some "
        "detectors will degrade. Re-run with a current collector for full coverage."
    )


Coerced = Any  # alias for the loosely-typed JSON surface


def _coerce_str(value: Coerced) -> str:
    """A display / legacy value, trimmed. Never used for a reads-proven key."""
    return "" if value is None else str(value).strip()


def _key(value: Any, *, proven: bool) -> str:
    """A join key: exactly as read for a reads-proven export (legacy: trimmed)."""
    if proven and isinstance(value, str):
        return value
    return _coerce_str(value)


_ABSENT: Any = object()
_GUID = re.compile(r"[0-9a-f]{32}")


def _guid(value: Any, context: str, *, required: bool) -> str:
    """Read an exported objectGUID (32 lower-case hex characters).

    Required for a collector that exports GUID identity (>= 0.9.0); drift uses
    it as the object's identity, so a malformed value is an IngestError rather
    than a silent fall back to mutable names.
    """
    if value is _ABSENT or value is None or value == "":
        if required:
            raise IngestError(
                f"{context} object_guid is missing: collector >= {GUID_IDENTITY_VERSION} "
                "exports objectGUID for every AD object"
            )
        return ""
    if not isinstance(value, str) or not _GUID.fullmatch(value):
        raise IngestError(
            f"{context} object_guid must be 32 lower-case hex characters, got {value!r}"
        )
    return value


# The well-known fixed PKI containers the collector enumerates by DN. Only these
# may lack a GUID (when unreadable); an enumerated CA object is always readable.
_FIXED_PKI_KINDS = frozenset({"pks_container", "ntauth", "aia", "cdp"})


def _ca_guid_exempt(enrollment_service: bool, kind: CaKind) -> bool:
    return not enrollment_service and kind in (CaKind.ROOT, CaKind.STANDALONE)


def _pki_guid_exempt(row: dict[str, Any]) -> bool:
    kind = _coerce_str(row.get("kind", "")).lower()
    return row.get("acl_obtained") is False and kind in _FIXED_PKI_KINDS


# Enumeration container -> the pass whose collection implies the container ran.
_ENUMERATION_PASSES: dict[str, str] = {
    "ca-config": "ca-config",
    "enrollment-services": "enrollment-services",
    "templates": "templates",
    "oid-objects": "oid-objects",
    "pki-acls": "pki-acls",
    "web-endpoints": "enrollment-endpoints",
    "dc-config": "esc10-dc-registry",
    "principal-mappings": "esc14-altsecid",
    "certs": "certs",
    "crls": "certs",
}


def _enumeration_complete(
    raw_manifest: dict[str, Any],
    *,
    uncollected: frozenset[str],
    counts: dict[str, int],
    proven: bool,
) -> frozenset[str]:
    """Return the containers the collector proved fully enumerated.

    A collector >= PROVEN_READS_VERSION writes one ``{complete, count}`` marker
    per collected container and sets ``complete`` only when its paged search
    provably returned every object (no failed page, no size/time limit, an empty
    final paging cookie). For such an export a missing or malformed marker, an
    unknown container, or a ``complete`` marker whose count does not match the
    rows written is an IngestError: the export was altered after collection or
    is not a collector export. ``complete: false`` is legitimate and simply
    leaves the container incomplete.

    Older exports wrote an unconditional post-loop marker, which proves only
    that the loop finished; their markers are read leniently (a missing or
    mismatched marker is just "not complete") and never make a verdict usable,
    because such an export does not prove its reads at all.
    """
    raw = raw_manifest.get("enumeration", {})
    if raw in (None, "") and not proven:
        raw = {}
    if not isinstance(raw, dict):
        raise IngestError("collector-manifest.json: enumeration must be an object")
    if proven:
        unknown = sorted(set(raw) - set(_ENUMERATION_PASSES))
        if unknown:
            raise IngestError(
                f"collector-manifest.json: unknown enumeration container(s) {unknown}"
            )
    complete: set[str] = set()
    for container, pass_name in _ENUMERATION_PASSES.items():
        if pass_name in uncollected:
            continue
        marker = raw.get(container)
        rows = counts.get(container, 0)
        if proven:
            where = f"collector-manifest.json: enumeration[{container!r}]"
            if not isinstance(marker, dict):
                raise IngestError(
                    f"{where} is missing: collector >= {PROVEN_READS_VERSION} writes a "
                    "completion marker for every collected container"
                )
            done, count = marker.get("complete"), marker.get("count")
            if not isinstance(done, bool) or isinstance(count, bool) or not isinstance(count, int):
                raise IngestError(f"{where} must be {{complete: bool, count: int}}, got {marker!r}")
            if done and count != rows:
                raise IngestError(
                    f"{where} claims {count} object(s) but the export holds {rows}: the "
                    "export was altered after collection"
                )
            if done:
                complete.add(container)
        elif (
            isinstance(marker, dict)
            and marker.get("complete") is True
            and marker.get("count") == rows
        ):
            complete.add(container)
    return frozenset(complete)


def _reject_duplicate_guids(file: str, guids: list[str]) -> None:
    """Two objects of one type sharing an objectGUID make identity ambiguous."""
    seen: set[str] = set()
    for g in guids:
        if not g:
            continue
        if g in seen:
            raise IngestError(f"{file}: duplicate object_guid {g!r} (objectGUID is unique in AD)")
        seen.add(g)


def _coerce_int(value: Coerced, context: str) -> int | None:
    """Coerce a JSON value to ``int | None``, raising IngestError on a bad type.

    ``None`` → ``None`` (field absent). Ints pass through. Strings are parsed,
    tolerating a ``0x`` hex prefix (AuditFilter is often rendered hex by
    certutil). Bools are rejected so JSON ``true`` never becomes ``1``.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        raise IngestError(f"invalid {context}: {value!r} (expected an integer)")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return None
        try:
            return int(s, 16) if s.lower().startswith("0x") else int(s)
        except ValueError as exc:
            raise IngestError(f"invalid {context}: {value!r}") from exc
    raise IngestError(f"invalid {context}: {value!r} (expected an integer)")


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise IngestError(f"duplicate JSON key {key!r} (one entry would be silently lost)")
        out[key] = value
    return out


# An overall ceiling over every per-file limit (limits.py): no collector file
# comes near it, and a larger one is refused before it is read.
MAX_EXPORT_FILE_BYTES = 256 * 1024 * 1024


def _json_limit(name: str) -> int:
    if name == "collector-manifest.json":
        return limits.MANIFEST_MAX_BYTES
    if name == "certs/index.json":
        return limits.CERT_INDEX_MAX_BYTES
    return limits.JSON_MAX_BYTES


def _read_bounded(path: Path, limit: int, label: str) -> bytes:
    """One export file's bytes, or an IngestError (never an OSError / MemoryError)."""
    try:
        return limits.read_bounded(path, min(limit, MAX_EXPORT_FILE_BYTES), label)
    except limits.InputTooLargeError as exc:
        raise IngestError(str(exc)) from exc
    except OSError as exc:
        raise IngestError(f"{label}: cannot be read ({exc.strerror or exc})") from exc


def _load(export_dir: Path, name: str) -> Any:
    """Load one JSON file, tolerating a BOM and a missing file (-> None).

    Size-limited (an oversized file is rejected, never truncated) and
    UTF-8-validated. A JSON object with a repeated key is malformed: ``json``
    would keep only the last value (e.g. one CA's publications silently
    replacing another's). Every decoding failure (encoding, NUL, truncation,
    nesting) is an IngestError.
    """
    path = export_dir / name
    if not path.is_file():
        return None
    raw = _read_bounded(path, _json_limit(name), name)
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise IngestError(f"{name}: not valid UTF-8 (byte {exc.start})") from exc
    try:
        return json.loads(text, object_pairs_hook=_no_duplicate_keys)
    except json.JSONDecodeError as exc:
        raise IngestError(f"{name}: malformed JSON ({exc})") from exc
    except RecursionError as exc:
        raise IngestError(f"{name}: malformed JSON (nested too deeply)") from exc
    except IngestError as exc:
        raise IngestError(f"{name}: {exc}") from exc


# The identity / join keys every row must carry as a non-empty string, per file
# (collector >= PROVEN_READS_VERSION). Mirrors the collector's OBJECT_SCHEMA
# (tests/test_object_schema.py checks the two agree): a row without its key
# would join to nothing or under '' - an IngestError, never a skipped row.
REQUIRED_KEYS: dict[str, tuple[str, ...]] = {
    "ca-config.json": ("name",),
    "templates.json": ("name", "oid"),
    "oid-objects.json": ("oid",),
    "pki-acls.json": ("object_dn",),
    "principal-mappings.json": ("dn",),
    "dc-config.json": ("name",),
    "web-endpoints.json": ("name",),
    # kind decides lifecycle checks: never defaulted for a proven export. A
    # CRL's tier is derived at ingest from the AIA certificates (by ca_name).
    "certs/index.json:certs": ("file", "ca_name", "kind"),
    "certs/index.json:crls": ("file", "source", "ca_name"),
}


def _require_keys(file: str, rows: list[Any], *, proven: bool) -> None:
    if not proven:
        return
    for row in rows:
        if not isinstance(row, dict):
            continue  # the row parser rejects it with a precise message
        for key in REQUIRED_KEYS[file]:
            value = row.get(key)
            if not isinstance(value, str) or not value.strip():
                raise IngestError(
                    f"{file}: a row has no {key!r} (got {value!r}): collector >= "
                    f"{PROVEN_READS_VERSION} fails an object without its identity "
                    "rather than writing it"
                )


def _rows(export_dir: Path, name: str, *, proven: bool) -> list[Any]:
    """The rows of one list file, each carrying its required keys (REQUIRED_KEYS)."""
    rows = _require_list(export_dir, name, _load(export_dir, name))
    _require_keys(name, rows, proven=proven)
    return rows


def _require_list(export_dir: Path, name: str, data: Any) -> list[Any]:
    if data is None:
        return []
    if isinstance(data, list):
        return data
    raise IngestError(f"{name}: expected a JSON array, got {type(data).__name__}")


def _ace(d: Any, *, proven: bool, flags_required: bool = False) -> AceEntry:
    if not isinstance(d, dict):
        raise IngestError(f"ACE entry must be an object, got {type(d).__name__}")
    f = _Fields(d, "ACE entry", proven=proven)
    # Collector >= 0.12.0 writes whether each ACE was inherited and whether it
    # is inherit-only (review round 2, Sol B2); an older export did not.
    inherited = f.flag("inherited", required=flags_required, default=False, since="0.12.0")
    inherit_only = f.flag("inherit_only", required=flags_required, default=False, since="0.12.0")
    ace_type_value = f.text("ace_type", required=proven, default="Allow")
    try:
        ace_type = AceType(ace_type_value)
    except ValueError as exc:
        raise IngestError(f"invalid ace_type: {ace_type_value!r}") from exc
    return AceEntry(
        trustee_sid=normalize_sid(f.text("trustee_sid", required=proven)),
        trustee_name=f.text("trustee_name", required=proven),
        rights=f.strs("rights", required=proven),
        ace_type=ace_type,
        inherited=inherited,
        inherit_only=inherit_only,
    )


def _aces(items: Any, *, proven: bool, flags_required: bool = False) -> tuple[AceEntry, ...]:
    if items is None:
        return ()
    if not isinstance(items, list):
        raise IngestError(f"expected a list of ACEs, got {type(items).__name__}")
    # DACL order is kept: the access check evaluates ACEs in sequence.
    return tuple(_ace(d, proven=proven, flags_required=flags_required) for d in items)


_NULL: Any = object()


class _Fields:
    """Read one export row strictly.

    A JSON ``null`` is the collector's statement that a read failed: the key is
    recorded in :attr:`unobtained` (where the field allows it) and the model gets
    a placeholder no detector may read as a value. For a collector >=
    PROVEN_READS_VERSION (*proven*) every key the row type declares is required
    and values are type-checked without coercion. Older exports keep their
    documented defaults for absent keys, but a present value must still have the
    right shape — a string where an array belongs is an error, never iterated
    character by character.
    """

    def __init__(self, row: dict[str, Any], context: str, *, proven: bool) -> None:
        self.row = row
        self.context = context
        self.proven = proven
        self.unobtained: set[str] = set()

    def _get(self, key: str, *, required: bool, nullable: bool) -> Any:
        if key not in self.row:
            if required:
                raise IngestError(f"{self.context} is missing {key}")
            return _ABSENT
        value = self.row[key]
        if value is None:
            if not nullable:
                raise IngestError(f"{self.context}: {key} must not be null")
            self.unobtained.add(key)
            return _NULL
        return value

    def strs(self, key: str, *, required: bool, nullable: bool = False) -> tuple[str, ...]:
        value = self._get(key, required=required, nullable=nullable)
        if value is _ABSENT or value is _NULL:
            return ()
        if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
            raise IngestError(f"{self.context}: {key} must be an array of strings, got {value!r}")
        if self.proven:
            if any(not x.strip() for x in value):
                # AD returns no empty values; an empty element is a mangled read.
                raise IngestError(f"{self.context}: {key} contains an empty string")
            # Values are kept exactly as read (a key is never trimmed to make it
            # match); one carrying surrounding whitespace is not what any
            # comparison expects, so the field is not obtained.
            if any(x != x.strip() for x in value):
                self.unobtained.add(key)
            return tuple(value)
        return tuple(x.strip() for x in value)

    def text(self, key: str, *, required: bool, nullable: bool = False, default: str = "") -> str:
        value = self._get(key, required=required, nullable=nullable)
        if value is _ABSENT or value is _NULL:
            return default
        if not isinstance(value, str):
            if self.proven:
                raise IngestError(f"{self.context}: {key} must be a string, got {value!r}")
            return _coerce_str(value)
        # A reads-proven export's strings are kept exactly as read: names and
        # OIDs are join keys, compared exactly (see normalize.resolve_join).
        return value if self.proven else value.strip()

    def optional_text(self, key: str, *, required: bool) -> str | None:
        """A string whose null is a value (e.g. no group link), not a failed read."""
        if key not in self.row:
            if required:
                raise IngestError(f"{self.context} is missing {key}")
            return None
        value = self.row[key]
        if value is None or value == "":
            return None
        if not isinstance(value, str):
            raise IngestError(f"{self.context}: {key} must be a string or null, got {value!r}")
        return value if self.proven else value.strip()

    def flag(
        self, key: str, *, required: bool, default: bool, nullable: bool = False, since: str = ""
    ) -> bool:
        # Coverage/configuration booleans decide whether an absence means "clean"
        # or "not evaluated", so they never fail toward "collected": a JSON
        # boolean is the only accepted value (null only where the field allows a
        # failed read).
        if key not in self.row:
            if required:
                raise IngestError(
                    f"{self.context} {key} is missing: collector >= "
                    f"{since or MIN_COLLECTOR_VERSION} always writes it, so the export is "
                    "malformed"
                )
            return default
        value = self.row[key]
        if value is None and nullable:
            self.unobtained.add(key)
            return default
        if not isinstance(value, bool):
            raise IngestError(f"{self.context} {key} must be a JSON boolean, got {value!r}")
        return value

    def integer(
        self, key: str, *, required: bool, nullable: bool = False, label: str = ""
    ) -> int | None:
        value = self._get(key, required=required, nullable=nullable)
        if value is _ABSENT or value is _NULL:
            return None
        label = label or f"{self.context} {key}"
        if self.proven and (isinstance(value, bool) or not isinstance(value, int)):
            raise IngestError(f"invalid {label}: {value!r} (expected an integer)")
        return _coerce_int(value, label)

    def enum(
        self, key: str, enum: type[Any], *, required: bool, default: str, nullable: bool = False
    ) -> Any:
        value = self._get(key, required=required, nullable=nullable)
        if value is _ABSENT or value is _NULL:
            return _kind("", enum, f"{self.context} {key}", default=default)
        if self.proven and not isinstance(value, str):
            raise IngestError(f"{self.context}: {key} must be a string, got {value!r}")
        return _kind(value, enum, f"{self.context} {key}", default=default)

    def aces(
        self, key: str, *, required: bool, nullable: bool = False, flags_required: bool = False
    ) -> tuple[AceEntry, ...]:
        value = self._get(key, required=required, nullable=nullable)
        if value is _ABSENT or value is _NULL:
            return ()
        return _aces(value, proven=self.proven, flags_required=flags_required)


def _kind(value: Any, enum: type[Any], context: str, default: str | None = None) -> Any:
    s = _coerce_str(value)
    if not s:
        s = default or ""
    else:
        # Enum values are lower-case (see model.py); tolerate collector casing
        # (PowerShell/certutil frequently emit TitleCase) by matching on the
        # lower-cased input first, then a case-insensitive fallback against the
        # enum value strings so a stray casing drift never raises IngestError.
        lowered = s.lower()
        try:
            return enum(lowered)
        except ValueError:
            pass
        for member in enum:
            if isinstance(member.value, str) and member.value.lower() == lowered:
                return member
    try:
        return enum(s)
    except ValueError as exc:
        raise IngestError(f"invalid {context}: {s!r}") from exc


def _try_load_certs() -> Any:
    """Import the optional cert parser, or return None when [certs] is absent."""
    try:
        from adcs_lens import certs

        return certs
    except ImportError:
        return None


def _cert_file_path(base: Path, entry: Any) -> Path:
    """Resolve a cert/CRL entry's file path and reject directory traversal."""
    if not isinstance(entry, dict):
        raise IngestError("certs/index.json entry must be an object")
    name = entry.get("file")
    if not name:
        raise IngestError("certs/index.json entry missing 'file'")
    name_str = str(name)
    certs_dir = (base / "certs").resolve()
    resolved = (certs_dir / name_str).resolve()
    if not resolved.is_relative_to(certs_dir):
        raise IngestError(f"cert file escapes certs/ directory: {name_str}")
    return resolved


def _read_manifest(base: Path) -> tuple[dict[str, Any], tuple[str, ...]]:
    """Load and validate collector-manifest.json; return it with its skipped passes.

    The manifest is the export's statement of what was (and was not) collected,
    so its absence is fatal: without it the core cannot tell a skipped pass from
    a clean one, and a mistyped path would otherwise read as an empty, "clean"
    estate. ``skipped_passes`` must be an array of strings (a bare string would
    otherwise be iterated character by character and silently claim coverage).
    """
    if not base.is_dir():
        raise IngestError(f"export directory not found: {base}")
    raw = _load(base, "collector-manifest.json")
    if raw is None:
        raise IngestError(
            "collector-manifest.json is missing: not a collector export (or a partial "
            "copy). The manifest records which passes ran; without it a skipped pass is "
            "indistinguishable from a clean one."
        )
    if not isinstance(raw, dict):
        raise IngestError("collector-manifest.json must be a JSON object")
    skipped_raw = raw.get("skipped_passes", [])
    if skipped_raw is None:
        skipped_raw = []
    if not isinstance(skipped_raw, list) or not all(isinstance(p, str) for p in skipped_raw):
        raise IngestError("collector-manifest.json: skipped_passes must be an array of strings")
    skipped = tuple(_coerce_str(p) for p in skipped_raw)
    unknown = sorted(set(skipped) - KNOWN_PASSES)
    if unknown:
        # A misspelt pass would otherwise be ignored and its coverage loss read
        # as a clean evaluation.
        raise IngestError(
            f"collector-manifest.json: unknown pass name(s) in skipped_passes: {unknown}; "
            f"known passes are {sorted(KNOWN_PASSES)}"
        )
    version = raw.get("collector_version", "unknown")
    if not isinstance(version, str):
        raise IngestError(
            "collector-manifest.json: collector_version must be a string "
            f"(the collector always writes one), got {version!r}"
        )
    return raw, skipped


def _missing_passes(
    base: Path, skipped: tuple[str, ...], status: CollectorVersionStatus
) -> tuple[str, ...]:
    """Passes whose export file is absent although the manifest did not skip them.

    A current collector always writes every non-skipped pass's file
    (``scripts/Export-AdcsEstate.ps1``), so an absent one means a truncated or
    partial copy: ingest refuses it rather than reading the gap as an empty,
    clean list. An older/unknown collector may legitimately predate a pass, so
    its absent files are returned as explicit degradations instead; detectors
    treat them exactly like skipped passes and a note names each one.
    """
    missing: list[str] = []
    for pass_name, file_name in PASS_FILES.items():
        if pass_name in skipped or (base / file_name).is_file():
            continue
        if status is CollectorVersionStatus.CURRENT:
            raise IngestError(
                f"{file_name} is missing, but collector-manifest.json does not list pass "
                f"{pass_name!r} in skipped_passes: the export is partial or truncated. "
                "Re-copy the complete export (or re-run the collector)."
            )
        missing.append(pass_name)
    return tuple(missing)


def ingest(export_dir: str | Path) -> Estate:
    """Parse a collector export directory into a normalized :class:`Estate`.

    Every way an export can be malformed - unreadable, not UTF-8, not JSON,
    truncated, oversized, the wrong shape or types - is an :class:`IngestError`
    (the CLI's exit 4), never a traceback: a parser fault on untrusted input
    that slipped past a specific check is reported as a rejected export too.
    """
    try:
        return _ingest(Path(export_dir))
    except IngestError:
        raise
    except (
        ValueError,
        TypeError,
        KeyError,
        IndexError,
        AttributeError,
        OverflowError,
        RecursionError,
    ) as exc:
        raise IngestError(f"malformed export ({type(exc).__name__}: {exc})") from exc


def _ingest(base: Path) -> Estate:

    raw_manifest, skipped_passes = _read_manifest(base)
    collector_version = _coerce_str(raw_manifest.get("collector_version", "unknown"))
    version_status = collector_version_status(collector_version)
    missing_passes = _missing_passes(base, skipped_passes, version_status)
    # Coverage markers are required for a current collector (it always writes
    # them); an older/unknown one may predate them.
    strict = version_status is CollectorVersionStatus.CURRENT
    # A collector >= PROVEN_READS_VERSION writes every declared field (null for a
    # failed read) and proven enumeration markers; everything is required.
    proven = version_proves_reads(collector_version)
    guid_required = version_has_guid_identity(collector_version)
    # A collector >= HOST_ATTRIBUTION_VERSION names each endpoint's host and each
    # enrollment service's CA host account (WI-044).
    attributed = version_attributes_hosts(collector_version)
    certs_mod = _try_load_certs()

    # --- certificates & CRLs (optional [certs] path) ---
    # Joined to the CA rows below (JOINS["cert-ca"]) and to the CRLs (crl-tier).
    certs_read: list[_IndexedCert] = []
    crls: list[Crl] = []
    crl_refs: list[tuple[int, str]] = []  # (CRL position, its CDP cn) of a proven export
    index = None if "certs" in skipped_passes else _load(base, "certs/index.json")
    # ``certs_parsed`` reports whether lifecycle (cert/CRL) data was actually
    # parsed — not merely whether the [certs] extra is installed. An installed
    # extra against an export that ships no certs/index.json must degrade to a
    # LIFECYCLE_NOT_EVALUATED note rather than silently passing as "clean".
    certs_parsed = False
    # Index rows, counted whether or not the [certs] extra can parse them: the
    # enumeration markers describe what the collector wrote.
    index_rows = {"certs": 0, "crls": 0}
    if index is not None:
        if not isinstance(index, dict):
            raise IngestError("certs/index.json must be an object with 'certs'/'crls' arrays")
        for kind_name in index_rows:
            entries = _require_list(base, "certs/index.json", index.get(kind_name, []))
            _require_keys(f"certs/index.json:{kind_name}", entries, proven=proven)
            index_rows[kind_name] = len(entries)
    if certs_mod is not None and index is not None:
        for entry in _require_list(base, "certs/index.json", index.get("certs", [])):
            path = _cert_file_path(base, entry)
            der = _read_bounded(path, limits.CERT_MAX_BYTES, f"certs/{path.name}")
            kind = _kind(entry.get("kind", "other"), CertKind, "cert kind", default="other")
            try:
                lifecycle = certs_mod.parse_cert(der, kind=kind)
            except certs_mod.UnparseableDer as exc:
                raise IngestError(f"certs/{path.name}: not a DER certificate ({exc})") from exc
            certs_read.append(
                _IndexedCert(_key(entry.get("ca_name", ""), proven=proven), lifecycle)
            )
            certs_parsed = True
        for entry in _require_list(base, "certs/index.json", index.get("crls", [])):
            path = _cert_file_path(base, entry)
            der = _read_bounded(path, limits.CRL_MAX_BYTES, f"certs/{path.name}")
            # A reads-proven export's tier is derived below from the AIA
            # certificates (JOINS["crl-tier"]); an older collector wrote one.
            tier = None if proven else _legacy_crl_tier(entry)
            if proven:
                crl_refs.append((len(crls), _key(entry["ca_name"], proven=proven)))
            try:
                crl = certs_mod.parse_crl(
                    der,
                    tier=tier,
                    source=_coerce_str(entry.get("source", "")),
                )
            except certs_mod.UnparseableDer as exc:
                raise IngestError(f"certs/{path.name}: not a DER CRL ({exc})") from exc
            crl_guid = _guid(
                entry.get("object_guid", _ABSENT),
                f"certs/index.json: CRL {path.name!r}",
                required=guid_required,
            )
            crls.append(replace(crl, object_guid=crl_guid))
            certs_parsed = True

    # --- CA configuration + security + roles ---
    ca_security_collected = "ca-security" not in skipped_passes
    ca_security = _load(base, "ca-security.json") if ca_security_collected else None
    if ca_security is None:
        ca_security = {}
    if not isinstance(ca_security, dict):
        raise IngestError("ca-security.json must be an object mapping CA name to ACEs")

    cas: list[CertAuthority] = []
    for row in _rows(base, "ca-config.json", proven=proven):
        cas.append(
            _ca(
                row,
                proven=proven,
                strict=strict,
                guid_required=guid_required,
                ca_security=ca_security,
                ca_security_collected=ca_security_collected,
                certs=(),  # attached below, once every CA row is known
            )
        )
    _reject_duplicate_guids("ca-config.json", [c.object_guid for c in cas])
    # Every join to a CA is by its cn. AD keeps sibling cns unique ignoring case,
    # so two CA rows whose names fold together cannot come from one Enrollment
    # Services container: ambiguous for every version, an error.
    folded_names = [join_fold(c.name) for c in cas]
    duplicated = sorted({c.name for c in cas if folded_names.count(join_fold(c.name)) > 1})
    if duplicated:
        raise IngestError(f"ca-config.json: duplicate CA name(s) {duplicated}")
    cas, unattached = _join_certs(cas, certs_read)
    if proven:
        # ca-security.json, enrollment-services.json and certs join to a CA by
        # name: two CAs with one name, or an entry naming no CA, is ambiguous.
        (key,) = JOIN_KEYS["ca-security"]
        names = [getattr(c, key) for c in cas]
        orphans = sorted(set(ca_security) - set(names))
        # (A skipped ca-config pass leaves nothing to join to: CA checks are
        # unevaluated, not the joins wrong.)
        if orphans and "ca-config" not in skipped_passes:
            raise IngestError(f"ca-security.json: entries {orphans} name no CA in ca-config.json")
    _reject_duplicate_guids("certs/index.json (CRLs)", [c.object_guid for c in crls])

    # --- templates + which enrollment service publishes them ---
    publication_refs: list[tuple[str, str]] = []  # (template reference, CA name)
    enrollment_services_path = base / "enrollment-services.json"
    # A declared skip dominates a stray file: the manifest is the coverage record.
    enrollment_services_available = (
        enrollment_services_path.is_file() and "enrollment-services" not in skipped_passes
    )
    enrollment_services = _load(base, "enrollment-services.json")
    if enrollment_services is None and not enrollment_services_available:
        enrollment_services = {}
    if not isinstance(enrollment_services, dict):
        raise IngestError("enrollment-services.json must be an object")
    for ca_name, tmpls in enrollment_services.items():
        if not isinstance(tmpls, list):
            raise IngestError(
                "enrollment-services.json mapping values must be arrays of strings "
                f"(CA {ca_name!r} has {type(tmpls).__name__})"
            )
        if not all(isinstance(ref, str) for ref in tmpls):
            raise IngestError(
                "enrollment-services.json mapping values must be arrays of strings "
                f"(CA {ca_name!r} contains a non-string template reference)"
            )
        normalized_ca_name = _key(ca_name, proven=proven)
        refs = [_key(ref, proven=proven) for ref in tmpls]
        if not normalized_ca_name.strip() or not all(r.strip() for r in refs):
            # A blank publisher or template reference joins to nothing: the
            # publication data is not trustworthy, never a silently skipped row.
            if proven:
                raise IngestError(
                    "enrollment-services.json: a blank CA name or template reference "
                    f"(CA {ca_name!r}): collector >= {PROVEN_READS_VERSION} never writes one"
                )
            enrollment_services_available = False
            continue
        publication_refs.extend((ref, normalized_ca_name) for ref in refs)
    if proven and enrollment_services_available and "ca-config" not in skipped_passes:
        services = {_key(k, proven=proven) for k in enrollment_services}
        (key,) = JOIN_KEYS["publisher-ca"]
        enterprise = {getattr(c, key) for c in cas if c.enrollment_service}
        if services != enterprise:
            raise IngestError(
                "enrollment-services.json does not join to ca-config.json: publishers "
                f"{sorted(services - enterprise)} have no CA row, enterprise CAs "
                f"{sorted(enterprise - services)} have no publication entry"
            )

    template_security = "template-security" not in skipped_passes
    templates = [
        _template(
            t,
            proven=proven,
            strict=strict,
            guid_required=guid_required,
            security_collected=template_security,
            ra_required=version_reads_ra_signatures(collector_version),
        )
        for t in _rows(base, "templates.json", proven=proven)
    ]
    templates = _join_publication(templates, publication_refs, proven=proven)
    _reject_duplicate_guids("templates.json", [t.object_guid for t in templates])

    acls = tuple(
        _pki_acl(
            a,
            proven=proven,
            strict=strict,
            guid_required=guid_required,
            attributed=attributed,
            current=version_reads_ra_signatures(collector_version),
        )
        for a in _rows(base, "pki-acls.json", proven=proven)
    )
    _reject_duplicate_guids("pki-acls.json", [a.object_guid for a in acls])

    collector_host = _coerce_str(raw_manifest.get("host", ""))
    written_fqdn = _host_fqdn(raw_manifest, attributed=attributed)
    # The FQDN must name the collector host itself: its first label is the
    # manifest's host (DS / Sol round 2). One that does not - a reverse-DNS
    # lookup that answered for another machine, or an altered manifest - or
    # that host comparison does not support (DS round 3) is not believed: the
    # export is then attributed to its short host name, which matches a CA host
    # only when unambiguous.
    host_fqdn = written_fqdn if fqdn_names_host(written_fqdn, collector_host) else ""
    endpoints = tuple(
        _endpoint(
            e,
            proven=proven,
            strict=strict,
            attributed=attributed,
            collector_host=collector_host,
            written_fqdn=written_fqdn,
            iis_host=host_fqdn or collector_host,
        )
        for e in _rows(base, "web-endpoints.json", proven=proven)
    )

    oids = tuple(
        _oid(o, proven=proven, guid_required=guid_required)
        for o in _rows(base, "oid-objects.json", proven=proven)
    )
    _reject_duplicate_guids("oid-objects.json", [o.object_guid for o in oids])

    # --- DC configuration (ESC10) ---
    dcs = tuple(
        _dc(
            d,
            proven=proven,
            strict=strict,
            guid_required=guid_required,
            current=version_reads_ra_signatures(collector_version),
        )
        for d in _rows(base, "dc-config.json", proven=proven)
    )
    _reject_duplicate_guids("dc-config.json", [d.object_guid for d in dcs])

    # --- Principal mappings (ESC14) ---
    principal_mappings = tuple(
        _principal(p, proven=proven, strict=strict, guid_required=guid_required)
        for p in _rows(base, "principal-mappings.json", proven=proven)
    )
    _reject_duplicate_guids("principal-mappings.json", [p.object_guid for p in principal_mappings])

    uncollected = frozenset(skipped_passes) | frozenset(missing_passes)
    row_counts = {
        "ca-config": len(cas),
        "enrollment-services": len(enrollment_services),
        "templates": len(templates),
        "oid-objects": len(oids),
        "pki-acls": len(acls),
        "web-endpoints": len(endpoints),
        "dc-config": len(dcs),
        "principal-mappings": len(principal_mappings),
        "certs": index_rows["certs"],
        "crls": index_rows["crls"],
    }
    enumeration_complete = _enumeration_complete(
        raw_manifest,
        uncollected=uncollected,
        counts=row_counts,
        proven=proven,
    )
    oid_values = [o.oid for o in oids]
    if len({join_fold(v) for v in oid_values}) != len(oid_values):
        # Two issuance-policy objects share an OID (or fold to one): the
        # template -> group join is ambiguous, so the container cannot vouch
        # for an absent link.
        enumeration_complete -= {"oid-objects"}
    if "ca-config" not in enumeration_complete or endpoint_scope_gaps(
        host_fqdn or collector_host, [(c.name, c.dns, c.enrollment_service) for c in cas]
    ):
        # IIS is read on the collector host only: the endpoint list cannot vouch
        # for an absent endpoint unless that host is the only CA host (WI-044),
        # whatever the collector's marker says (a 0.10.0 collector marked a
        # non-CA IIS host's empty list complete), and that is known only from a
        # complete CA list.
        enumeration_complete -= {"web-endpoints"}
    if proven:
        crls = _derive_crl_tiers(
            crls, crl_refs, certs_read, source_complete="certs" in enumeration_complete
        )
    manifest = Manifest(
        collector_version=collector_version,
        collected_at=_coerce_str(raw_manifest.get("collected_at", "")),
        host=collector_host,
        host_fqdn=host_fqdn,
        domain=_coerce_str(raw_manifest.get("domain", "")),
        skipped_passes=skipped_passes,
        certs_parsed=certs_parsed,
        enrollment_services_available=enrollment_services_available,
        missing_passes=missing_passes,
        enumeration_complete=enumeration_complete,
        ds_heuristics=_ds_heuristics(
            raw_manifest, required=version_reads_ra_signatures(collector_version)
        ),
    )

    return Estate(
        unattached_certs=unattached,
        cas=tuple(cas),
        templates=tuple(templates),
        acls=acls,
        oids=oids,
        crls=tuple(crls),
        endpoints=endpoints,
        dcs=dcs,
        principal_mappings=principal_mappings,
        manifest=manifest,
    )


def _legacy_crl_tier(entry: Any) -> CrlTier:
    """The tier an older collector wrote (it defaulted to issuing on a miss;
    such an export never resolves a finding). A reads-proven export's tier is
    derived at ingest instead (_derive_crl_tiers)."""
    tier: CrlTier = _kind(entry.get("tier", "issuing"), CrlTier, "CRL tier", default="issuing")
    return tier


def _row_name(row: Any, file: str) -> str:
    if not isinstance(row, dict):
        raise IngestError(f"{file} entries must be objects, got {type(row).__name__}")
    return _coerce_str(row.get("name", ""))


def _fields(row: Any, file: str, label_key: str, *, proven: bool) -> _Fields:
    # A malformed row is rejected, never silently filtered: a filtered object
    # would read as "evaluated, nothing there".
    if not isinstance(row, dict):
        raise IngestError(f"{file} entries must be objects, got {type(row).__name__}")
    return _Fields(row, f"{file}: {_coerce_str(row.get(label_key, ''))!r}", proven=proven)


def _require_null(f: _Fields, keys: tuple[str, ...], why: str) -> None:
    present = [k for k in keys if k not in f.unobtained]
    if present:
        raise IngestError(f"{f.context}: {why}, yet it carries {', '.join(present)}")


_CA_REGISTRY_KEYS = (
    "kind",  # CAType: an enterprise CA may be a root or a subordinate
    "edit_flags",
    "interface_flags",
    "audit_filter",
    "disabled_extensions",
    "owner_sid",
    "security",
)


def _ca(
    row: Any,
    *,
    proven: bool,
    strict: bool,
    guid_required: bool,
    ca_security: dict[str, Any],
    ca_security_collected: bool,
    certs: tuple[CertLifecycle, ...],
) -> CertAuthority:
    f = _fields(row, "ca-config.json", "name", proven=proven)
    name = f.text("name", required=proven)
    registry_collected = f.flag("registry_config_collected", required=strict, default=True)
    # The hive was read locally, so a detector-read field must be present: an
    # omitted key must not default to clean and let ESC6/ESC11/ESC16 decide a CA
    # they never read. (A genuine empty list is fine; null is a failed read.)
    reg_required = proven or (strict and registry_collected)
    edit_flags = f.strs("edit_flags", required=reg_required, nullable=True)
    interface_flags = f.strs("interface_flags", required=reg_required, nullable=True)
    disabled_extensions = f.strs("disabled_extensions", required=reg_required, nullable=True)
    audit_filter = f.integer("audit_filter", required=proven, nullable=True, label="CA AuditFilter")
    owner_sid = f.text("owner_sid", required=proven, nullable=True)
    kind = f.enum("kind", CaKind, required=proven, default="issuing", nullable=proven)
    enrollment_service = f.flag(
        "enrollment_service", required=guid_required, default=True, since=GUID_IDENTITY_VERSION
    )
    security: tuple[AceEntry, ...] = ()
    security_collected = name in ca_security
    if ca_security_collected and proven and not security_collected:
        raise IngestError(
            f"ca-security.json has no entry for {name!r}: collector >= "
            f"{PROVEN_READS_VERSION} writes one per CA (null when unread)"
        )
    if security_collected:
        if ca_security[name] is None:
            f.unobtained.add("security")
        else:
            security = _aces(ca_security[name], proven=proven)
    elif proven:
        f.unobtained.add("security")
    if proven and not registry_collected:
        _require_null(
            f,
            _CA_REGISTRY_KEYS,
            "registry_config_collected is false (the hive is read on the CA host)",
        )
    return CertAuthority(
        name=name,
        dns=f.text("dns", required=proven),
        config_string=f.text("config_string", required=proven),
        kind=kind,
        edit_flags=frozenset(edit_flags),
        interface_flags=frozenset(interface_flags),
        audit_filter=audit_filter,
        security=security,
        certs=certs,
        disabled_extensions=frozenset(disabled_extensions),
        ca_patch_state=f.enum("ca_patch_state", CaPatchState, required=proven, default="unknown"),
        owner_sid=normalize_sid(owner_sid),
        registry_config_collected=registry_collected,
        # The collector writes a (possibly empty) entry for every CA; an
        # absent entry means this CA's descriptor never reached the export.
        security_collected=security_collected,
        enrollment_service=enrollment_service,
        object_guid=_guid(
            row.get("object_guid", _ABSENT),
            f.context,
            # A GUID is exempt only for a standalone CA: not an enrollment
            # service (no AD object), and CAType-derived kind root /
            # standalone (an enterprise issuing CA is always in Enrollment
            # Services and carries a GUID).
            required=guid_required and not _ca_guid_exempt(enrollment_service, kind),
        ),
        unobtained=frozenset(f.unobtained),
    )


def _template(
    t: Any,
    *,
    proven: bool,
    strict: bool,
    guid_required: bool,
    security_collected: bool,
    ra_required: bool = False,
) -> CertTemplate:
    f = _fields(t, "templates.json", "name", proven=proven)
    # msPKI-RA-Signature (collector >= 0.12.0): required, null when not
    # obtained; a count below zero is no count the collector writes.
    ra_signatures = f.integer("ra_signatures", required=ra_required, nullable=True)
    if ra_signatures is not None and ra_signatures < 0:
        raise IngestError(f"{f.context}: ra_signatures {ra_signatures} is negative")
    # The raw flag values (collector >= 0.12.0, review round 2): the core
    # decodes them with its own tables, so a decoding correction never needs a
    # collector change. AD stores both as 32-bit integers (signed).
    name_flags_raw = f.integer("name_flags_raw", required=ra_required)
    enrollment_flags_raw = f.integer("enrollment_flags_raw", required=ra_required)
    for raw_key, raw_value in (
        ("name_flags_raw", name_flags_raw),
        ("enrollment_flags_raw", enrollment_flags_raw),
    ):
        if raw_value is not None and not -(2**31) <= raw_value < 2**32:
            raise IngestError(f"{f.context}: {raw_key} {raw_value} is not a 32-bit value")
    # The collector's own decoded names are still read (and type-checked); the
    # raw value, when present, decides.
    listed_name_flags = frozenset(f.strs("name_flags", required=strict))
    listed_enrollment_flags = frozenset(f.strs("enrollment_flags", required=strict))
    name = f.text("name", required=proven)
    oid = f.text("oid", required=proven)
    if proven:
        schema_version = f.integer("schema_version", required=True)
    else:
        raw_version = t.get("schema_version", 1)
        try:
            schema_version = int(raw_version) if raw_version is not None else 1
        except (TypeError, ValueError) as exc:
            raise IngestError(
                f"invalid schema_version for template {name!r}: {raw_version!r}"
            ) from exc
    acl_obtained = f.flag("acl_obtained", required=strict, default=True)
    security = f.aces(
        "security", required=strict and acl_obtained, nullable=True, flags_required=ra_required
    )
    owner_sid = f.text("owner_sid", required=proven, nullable=True)
    if proven:
        if acl_obtained == ("security" in f.unobtained):
            raise IngestError(
                f"{f.context}: acl_obtained={acl_obtained} contradicts security "
                f"{'null' if 'security' in f.unobtained else 'present'}"
            )
        if not acl_obtained:
            _require_null(f, ("owner_sid",), "its security descriptor was not obtained")
    if not security_collected:
        # template-security declared skipped: no descriptor was read at all.
        f.unobtained |= {"security", "owner_sid"}
    return CertTemplate(
        object_guid=_guid(t.get("object_guid", _ABSENT), f.context, required=guid_required),
        name=name,
        display_name=f.text("display_name", required=proven, default=name),
        schema_version=schema_version if schema_version is not None else 1,
        oid=oid,
        ekus=f.strs("ekus", required=strict),
        name_flags=(
            decode_flags(name_flags_raw, TEMPLATE_NAME_FLAGS)
            if name_flags_raw is not None
            else listed_name_flags
        ),
        enrollment_flags=(
            decode_flags(enrollment_flags_raw, TEMPLATE_ENROLLMENT_FLAGS)
            if enrollment_flags_raw is not None
            else listed_enrollment_flags
        ),
        name_flags_raw=name_flags_raw,
        enrollment_flags_raw=enrollment_flags_raw,
        min_key_size=f.integer("min_key_size", required=proven, nullable=True),
        issuance_policy_oids=f.strs("issuance_policy_oids", required=strict),
        security=security,
        published_by=(),  # joined by _join_publication
        acl_obtained=acl_obtained,
        csp=f.text("csp", required=proven).lower(),
        owner_sid=normalize_sid(owner_sid),
        ra_signatures=ra_signatures,
        unobtained=frozenset(f.unobtained),
    )


# The template keys an enrollment service's publication reference may name.
# MS-WCCE: each certificateTemplates value is identical to a template's cn, and
# the CA issues only for an identical match. The collector copies the values
# verbatim, so a reads-proven export joins on cn alone, exactly. Older exports
# (and hand-built ones) were also matched on the template OID; there both
# kinds are candidates and a reference must match one template across them.
PUBLICATION_KEYS_PROVEN: tuple[str, ...] = JOIN_KEYS["publication"]
PUBLICATION_KEYS_LEGACY: tuple[str, ...] = JOIN_KEYS["publication-legacy"]


def _join_publication(
    templates: list[CertTemplate], refs: list[tuple[str, str]], *, proven: bool
) -> list[CertTemplate]:
    """Attach each publication reference to the ONE template it names
    (JOINS["publication"]; compared by normalize.resolve_join).

    A reference matching no template names a template that is not in the
    export (published but deleted): it attaches nowhere. A reference matching
    more than one template, or folding to a cn it is not identical to (" X ",
    "x"), is ambiguous: every such template gets published_by not obtained,
    never the publisher of an arbitrary match.
    """
    keys = JOIN_KEYS["publication"] if proven else JOIN_KEYS["publication-legacy"]
    candidates = [(getattr(t, kind), i) for i, t in enumerate(templates) for kind in keys]
    candidates = [(k, i) for k, i in candidates if k]
    publishers: dict[int, set[str]] = {}
    ambiguous: set[int] = set()
    for ref, ca_name in refs:
        state, matches = resolve_join(ref, candidates)
        # One template answering through two key kinds (its cn equal to its
        # own OID) is still one template.
        if (
            state == JOIN_AMBIGUOUS
            and len(set(matches)) == 1
            and ref in {getattr(templates[matches[0]], k) for k in keys}
        ):
            state = JOIN_ONE
        if state == JOIN_ONE:
            publishers.setdefault(matches[0], set()).add(ca_name)
        elif state == JOIN_AMBIGUOUS:
            ambiguous |= set(matches)
    out = []
    for i, t in enumerate(templates):
        if i in ambiguous:
            out.append(replace(t, published_by=(), unobtained=t.unobtained | {"published_by"}))
        else:
            out.append(replace(t, published_by=tuple(sorted(publishers.get(i, ())))))
    return out


class _IndexedCert(NamedTuple):
    """A certs/index.json row: the AIA object's cn and its certificate."""

    ca_name: str
    cert: CertLifecycle


def _derive_crl_tiers(
    crls: list[Crl],
    refs: list[tuple[int, str]],
    certs: list[_IndexedCert],
    *,
    source_complete: bool,
) -> list[Crl]:
    """A CRL's tier from the AIA certificates of its CA (JOINS["crl-tier"]).

    Root when every certificate published under the one AIA cn identical to
    the CRL's CDP cn is self-signed, issuing when none is. Null (not obtained)
    when the AIA enumeration was not complete, the cn names no AIA object or
    is ambiguous (another cn folds to it), or the certificates disagree.
    """
    (key,) = JOIN_KEYS["crl-tier"]
    kinds: dict[str, set[CertKind]] = {}
    for c in certs:
        kinds.setdefault(getattr(c, key), set()).add(c.cert.kind)
    candidates = [(name, name) for name in kinds]
    out = list(crls)
    for i, ref in refs:
        tier: CrlTier | None = None
        if source_complete:
            state, matches = resolve_join(ref, candidates)
            if state == JOIN_ONE:
                found = kinds[matches[0]]
                if found == {CertKind.ROOT_CA}:
                    tier = CrlTier.ROOT
                elif found == {CertKind.ISSUING_CA}:
                    tier = CrlTier.ISSUING
        out[i] = replace(out[i], tier=tier)
    return out


def _join_certs(
    cas: list[CertAuthority], certs: list[_IndexedCert]
) -> tuple[list[CertAuthority], tuple[tuple[str, CertLifecycle], ...]]:
    """Attach each certificate to the ONE CA whose cn is its ca_name
    (JOINS["cert-ca"]). No CA, or an ambiguous one (a name that only folds to
    a CA's), leaves it unattached: its CA kind is not obtained."""
    (key,) = JOIN_KEYS["cert-ca"]
    candidates = [(getattr(ca, key), i) for i, ca in enumerate(cas)]
    attached: dict[int, list[CertLifecycle]] = {}
    unattached: list[tuple[str, CertLifecycle]] = []
    for ca_name, cert in certs:
        state, matches = resolve_join(ca_name, candidates)
        if state == JOIN_ONE:
            attached.setdefault(matches[0], []).append(cert)
        else:
            unattached.append((ca_name, cert))
    out = [replace(ca, certs=tuple(attached.get(i, ()))) for i, ca in enumerate(cas)]
    return out, tuple(sorted(unattached, key=lambda u: u[0]))


# The shape of a domain account's SID (a domain SID with a relative identifier).
# The shape cannot tell a computer account from a group: AD does not encode the
# object class in a SID. That the SID is the CA host's computer account rests on
# the collector, which resolves it from the one computer object whose
# dNSHostName is identical to the enrollment service's (_caHost).
_DOMAIN_ACCOUNT_SID = re.compile(r"S-1-5-21-\d+-\d+-\d+-\d+")


def _ds_heuristics(raw_manifest: dict[str, Any], *, required: bool) -> str | None:
    """The manifest's ``ds_heuristics`` (required from collector >= 0.12.0):
    the forest's dSHeuristics string, "" when not set, None when not read."""
    if "ds_heuristics" not in raw_manifest:
        if required:
            raise IngestError(
                "collector-manifest.json is missing ds_heuristics: collector >= 0.12.0 "
                "reads the forest's dSHeuristics"
            )
        return None
    value = raw_manifest["ds_heuristics"]
    if value is not None and not isinstance(value, str):
        raise IngestError(f"collector-manifest.json: ds_heuristics must be a string, got {value!r}")
    return value


def _host_fqdn(raw_manifest: dict[str, Any], *, attributed: bool) -> str:
    """The manifest's ``host_fqdn`` (required from collector >= 0.11.0)."""
    value = raw_manifest.get("host_fqdn", _ABSENT)
    if value is _ABSENT:
        if attributed:
            raise IngestError(
                "collector-manifest.json is missing host_fqdn: collector >= 0.11.0 names "
                "the host its IIS pass read"
            )
        return ""
    if not isinstance(value, str):
        raise IngestError(f"collector-manifest.json: host_fqdn must be a string, got {value!r}")
    # A name host comparison does not support (an IDN U-label, a malformed or
    # over-long name) is not refused: it is simply not believed (DS round 3), so
    # the export is attributed to its short host name.
    return value


def _same_written_host(a: str, b: str) -> bool:
    """Whether two host names the collector wrote from one value agree: equal
    as DNS names when supported (DS round 3), else equal as written."""
    key = host_key(a)
    return key == host_key(b) if key else a.strip() == b.strip()


def _pki_acl(
    a: Any,
    *,
    proven: bool,
    strict: bool,
    guid_required: bool,
    attributed: bool = False,
    current: bool = False,
) -> PkiObjectAcl:
    f = _fields(a, "pki-acls.json", "object_dn", proven=proven)
    acl_obtained = f.flag("acl_obtained", required=strict, default=True)
    security = f.aces(
        "security", required=strict and acl_obtained, nullable=True, flags_required=current
    )
    owner_sid = f.text("owner_sid", required=proven, nullable=True)
    # Provenance (collector >= 0.11.0): True only on a row the Enrollment
    # Services search returned. Only such a row carries the CA host's
    # computer-account SID - resolved (a domain account SID) or null (not
    # obtained) - and every other row carries ''. ca_host_sid exempts one
    # trustee from ESC5 on this object, so any other combination is refused:
    # it could allowlist a principal on an object the collector never tied to a
    # CA host. Ingest checks this consistency and the SID's shape; it cannot
    # check that the SID is a computer account or that the flag is true.
    enrollment_service = f.flag(
        "enrollment_service", required=attributed, default=False, since="0.11.0"
    )
    ca_host_sid = f.text("ca_host_sid", required=attributed, nullable=True)
    unresolved = "ca_host_sid" in f.unobtained
    kind_value = a.get("kind")
    if enrollment_service:
        if kind_value != AclKind.CA_OBJECT.value:
            raise IngestError(f"{f.context}: an enrollment service row must be a ca_object")
        if not unresolved and not _DOMAIN_ACCOUNT_SID.fullmatch(normalize_sid(ca_host_sid)):
            raise IngestError(
                f"{f.context}: ca_host_sid {ca_host_sid!r} on an enrollment service row must "
                "be a domain account SID, or null when it could not be resolved"
            )
    elif ca_host_sid or unresolved:
        raise IngestError(
            f"{f.context}: ca_host_sid is allowed only on an enrollment service row "
            "(enrollment_service: true)"
        )
    if proven:
        if acl_obtained == ("security" in f.unobtained):
            raise IngestError(
                f"{f.context}: acl_obtained={acl_obtained} contradicts security "
                f"{'null' if 'security' in f.unobtained else 'present'}"
            )
        if not acl_obtained:
            _require_null(f, ("owner_sid",), "its security descriptor was not obtained")
    return PkiObjectAcl(
        object_dn=f.text("object_dn", required=proven),
        kind=f.enum("kind", AclKind, required=proven, default="pks_container"),
        security=security,
        owner_sid=normalize_sid(owner_sid),
        ca_host_sid=normalize_sid(ca_host_sid),
        enrollment_service=enrollment_service,
        acl_obtained=acl_obtained,
        object_guid=_guid(
            a.get("object_guid", _ABSENT),
            f.context,
            # A GUID is exempt only for an UNREADABLE fixed container
            # (acl_obtained=false and one of the well-known container kinds,
            # never an enumerated ca_object, which is always read with a GUID).
            required=guid_required and not _pki_guid_exempt(a),
        ),
        unobtained=frozenset(f.unobtained),
    )


def _endpoint(
    e: Any,
    *,
    proven: bool,
    strict: bool,
    attributed: bool = False,
    collector_host: str = "",
    written_fqdn: str = "",
    iis_host: str = "",
) -> EnrollmentEndpoint:
    f = _fields(e, "web-endpoints.json", "name", proven=proven)
    # The current collector always writes these; a missing input must not
    # default to a benign value (ESC8 would read it as clean). A collector >=
    # PROVEN_READS_VERSION writes null for an IIS read that failed.
    if "inputs_obtained" in e and not isinstance(e["inputs_obtained"], bool):
        raise IngestError(f"{f.context} inputs_obtained must be a JSON boolean")
    endpoint = EnrollmentEndpoint(
        kind=f.enum("kind", EndpointKind, required=proven, default="web_enrollment"),
        name=f.text("name", required=proven),
        transports=frozenset(
            t.lower() for t in f.strs("transports", required=strict, nullable=True) if t
        ),
        ssl_required=f.flag("ssl_required", required=strict, default=False, nullable=proven),
        windows_auth=f.flag("windows_auth", required=strict, default=False, nullable=proven),
        auth_providers=frozenset(
            p.lower() for p in f.strs("auth_providers", required=strict, nullable=True) if p
        ),
        epa=f.enum("epa", EpaPolicy, required=strict, default="unknown", nullable=True),
        # An older collector read IIS on its own host too: the manifest names it.
        host=f.text("host", required=attributed, default=collector_host),
    )
    if attributed:
        # The collector writes every row's host and the manifest's host_fqdn
        # from one value: a row naming another host was altered after
        # collection (DS / Sol round 2).
        if not _same_written_host(endpoint.host, written_fqdn):
            raise IngestError(
                f"{f.context}: host {endpoint.host!r} is not the host the export's IIS pass "
                f"read (host_fqdn {written_fqdn!r}): the export was altered after collection"
            )
        endpoint = replace(endpoint, host=iis_host)
    if proven:
        for key in ("ssl_required", "windows_auth"):
            if key not in e:
                raise IngestError(f"{f.context} is missing {key}")
    return replace(endpoint, unobtained=frozenset(f.unobtained))


def _oid(o: Any, *, proven: bool, guid_required: bool) -> IssuanceOid:
    f = _fields(o, "oid-objects.json", "oid", proven=proven)
    return IssuanceOid(
        oid=f.text("oid", required=proven),
        name=f.text("name", required=proven),
        # msDS-OIDToGroupLink is a group DN (not a SID) — store it verbatim.
        group_link=f.optional_text("group_link", required=proven),
        object_guid=_guid(o.get("object_guid", _ABSENT), f.context, required=guid_required),
    )


def _raw_dword(row: dict[str, Any], context: str, key: str, required: bool) -> int | None:
    """A raw registry DWORD the collector copied (collector >= 0.12.0): an
    integer, or null when the value is not set or was not read - which the
    decoded field already records, so a null here is not a failed read. Either
    sign is accepted and normalised to the unsigned value (review round 3, DS
    N5): the collector casts the value to a signed [int] (today a DWORD with bit
    31 set fails that cast, so the DC's value arrives null - not obtained -
    rather than negative)."""
    if key not in row:
        if required:
            raise IngestError(f"{context} is missing {key}")
        return None
    value = row[key]
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not -(2**31) <= value < 2**32:
        raise IngestError(f"{context}: {key} must be a 32-bit integer or null")
    return int(value) & 0xFFFFFFFF


def _dc(
    d: Any, *, proven: bool, strict: bool, guid_required: bool, current: bool = False
) -> DcConfiguration:
    f = _fields(d, "dc-config.json", "name", proven=proven)
    binding = f.enum(
        "strong_certificate_binding_enforcement",
        StrongCertBinding,
        required=strict,
        default="unknown",
        nullable=True,
    )
    methods = f.strs("schannel_mapping_methods", required=strict, nullable=True)
    decoded_methods = frozenset(
        _kind(m, SchannelMappingMethod, "SchannelMappingMethod", default="unknown")
        for m in methods
    )
    # The raw DWORDs (collector >= 0.12.0; null when the value is not set or was
    # not read, which the decoded fields already say): the core decodes them.
    binding_raw = _raw_dword(d, f.context, "strong_certificate_binding_enforcement_raw", current)
    methods_raw = _raw_dword(d, f.context, "schannel_mapping_methods_raw", current)
    if binding_raw is not None:
        binding = {
            0: StrongCertBinding.DISABLED,
            1: StrongCertBinding.PERMISSIVE,
            2: StrongCertBinding.STRICT,
        }.get(binding_raw, StrongCertBinding.UNKNOWN)
    if methods_raw is not None:
        decoded_methods = frozenset(
            SchannelMappingMethod(name)
            for name in decode_flags(methods_raw, SCHANNEL_MAPPING_BITS)
        )
    return DcConfiguration(
        name=f.text("name", required=proven),
        strong_certificate_binding_enforcement=binding,
        schannel_mapping_methods=decoded_methods,
        object_guid=_guid(d.get("object_guid", _ABSENT), f.context, required=guid_required),
        unobtained=frozenset(f.unobtained),
    )


def _principal(p: Any, *, proven: bool, strict: bool, guid_required: bool) -> PrincipalMapping:
    f = _fields(p, "principal-mappings.json", "dn", proven=proven)
    return PrincipalMapping(
        dn=f.text("dn", required=proven),
        mappings=f.strs("mappings", required=strict),
        object_guid=_guid(p.get("object_guid", _ABSENT), f.context, required=guid_required),
    )
