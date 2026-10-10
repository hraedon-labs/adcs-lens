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
from pathlib import Path
from typing import Any

from adcs_lens.model import (
    KNOWN_PASSES,
    MIN_COLLECTOR_VERSION,
    PASS_FILES,
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
)
from adcs_lens.normalize import normalize_sid


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
    return "" if value is None else str(value).strip()


_ABSENT: Any = object()


def _marker_bool(value: Any, context: str, *, required: bool, default: bool) -> bool:
    """Read a coverage/configuration boolean strictly.

    These fields decide whether an absence means "clean" or "not evaluated", so
    they never fail toward "collected": a JSON boolean is the only accepted
    value. Absent is allowed only for an older/unknown collector
    (*required* False, which also puts the whole export under a wildcard
    coverage gap); anything else — strings such as ``"false"``, numbers,
    ``null`` — is an :class:`IngestError`.
    """
    if isinstance(value, bool):
        return value
    if value is _ABSENT:
        if required:
            raise IngestError(
                f"{context} is missing: collector >= {MIN_COLLECTOR_VERSION} always "
                "writes it, so the export is malformed"
            )
        return default
    raise IngestError(f"{context} must be a JSON boolean, got {value!r}")


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


def _load(export_dir: Path, name: str) -> Any:
    """Load one JSON file, tolerating a BOM and a missing file (-> None)."""
    path = export_dir / name
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as exc:
        raise IngestError(f"{name}: malformed JSON ({exc})") from exc


def _require_list(export_dir: Path, name: str, data: Any) -> list[Any]:
    if data is None:
        return []
    if isinstance(data, list):
        return data
    raise IngestError(f"{name}: expected a JSON array, got {type(data).__name__}")


def _ace(d: Any) -> AceEntry:
    if not isinstance(d, dict):
        raise IngestError(f"ACE entry must be an object, got {type(d).__name__}")
    ace_type_value = _coerce_str(d.get("ace_type", "Allow"))
    try:
        ace_type = AceType(ace_type_value)
    except ValueError as exc:
        raise IngestError(f"invalid ace_type: {ace_type_value!r}") from exc
    return AceEntry(
        trustee_sid=normalize_sid(_coerce_str(d.get("trustee_sid", ""))),
        trustee_name=_coerce_str(d.get("trustee_name", "")),
        rights=tuple(_coerce_str(r) for r in d.get("rights", [])),
        ace_type=ace_type,
    )


def _aces(items: Any) -> tuple[AceEntry, ...]:
    if items is None:
        return ()
    if not isinstance(items, list):
        raise IngestError(f"expected a list of ACEs, got {type(items).__name__}")
    return tuple(_ace(d) for d in items)


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
    """Parse a collector export directory into a normalized :class:`Estate`."""
    base = Path(export_dir)

    raw_manifest, skipped_passes = _read_manifest(base)
    collector_version = _coerce_str(raw_manifest.get("collector_version", "unknown"))
    version_status = collector_version_status(collector_version)
    missing_passes = _missing_passes(base, skipped_passes, version_status)
    # Coverage markers are required for a current collector (it always writes
    # them); an older/unknown one may predate them.
    strict = version_status is CollectorVersionStatus.CURRENT
    certs_mod = _try_load_certs()

    # --- certificates & CRLs (optional [certs] path) ---
    cert_by_ca: dict[str, list[CertLifecycle]] = {}
    crls: list[Crl] = []
    index = None if "certs" in skipped_passes else _load(base, "certs/index.json")
    # ``certs_parsed`` reports whether lifecycle (cert/CRL) data was actually
    # parsed — not merely whether the [certs] extra is installed. An installed
    # extra against an export that ships no certs/index.json must degrade to a
    # LIFECYCLE_NOT_EVALUATED note rather than silently passing as "clean".
    certs_parsed = False
    if certs_mod is not None and index is not None:
        if not isinstance(index, dict):
            raise IngestError("certs/index.json must be an object with 'certs'/'crls' arrays")
        for entry in _require_list(base, "certs/index.json", index.get("certs", [])):
            path = _cert_file_path(base, entry)
            try:
                der = path.read_bytes()
            except OSError as exc:
                raise IngestError(f"cannot read cert file {path.name}: {exc}") from exc
            kind = _kind(entry.get("kind", "other"), CertKind, "cert kind", default="other")
            lifecycle = certs_mod.parse_cert(der, kind=kind)
            cert_by_ca.setdefault(_coerce_str(entry.get("ca_name", "")), []).append(lifecycle)
            certs_parsed = True
        for entry in _require_list(base, "certs/index.json", index.get("crls", [])):
            path = _cert_file_path(base, entry)
            try:
                der = path.read_bytes()
            except OSError as exc:
                raise IngestError(f"cannot read CRL file {path.name}: {exc}") from exc
            tier = _kind(entry.get("tier", "issuing"), CrlTier, "CRL tier", default="issuing")
            crls.append(
                certs_mod.parse_crl(
                    der,
                    tier=tier,
                    source=_coerce_str(entry.get("source", "")),
                )
            )
            certs_parsed = True

    # --- CA configuration + security + roles ---
    ca_security = _load(base, "ca-security.json") or {}
    if not isinstance(ca_security, dict):
        raise IngestError("ca-security.json must be an object mapping CA name to ACEs")

    cas: list[CertAuthority] = []
    for ca in _require_list(base, "ca-config.json", _load(base, "ca-config.json")):
        if not isinstance(ca, dict):
            raise IngestError("ca-config.json entries must be objects")
        name = _coerce_str(ca.get("name", ""))
        kind = _kind(ca.get("kind", "issuing"), CaKind, "CA kind", default="issuing")
        cas.append(
            CertAuthority(
                name=name,
                dns=_coerce_str(ca.get("dns", "")),
                config_string=_coerce_str(ca.get("config_string", "")),
                kind=kind,
                edit_flags=frozenset(_coerce_str(f) for f in ca.get("edit_flags", [])),
                interface_flags=frozenset(_coerce_str(f) for f in ca.get("interface_flags", [])),
                audit_filter=_coerce_int(ca.get("audit_filter"), "CA AuditFilter"),
                security=_aces(ca_security.get(name)),
                certs=tuple(cert_by_ca.get(name, [])),
                disabled_extensions=frozenset(
                    _coerce_str(o) for o in ca.get("disabled_extensions", [])
                ),
                ca_patch_state=_kind(
                    ca.get("ca_patch_state", "unknown"),
                    CaPatchState,
                    "CA patch state",
                    default="unknown",
                ),
                owner_sid=normalize_sid(_coerce_str(ca.get("owner_sid", ""))),
                registry_config_collected=_marker_bool(
                    ca.get("registry_config_collected", _ABSENT),
                    f"ca-config.json: {name!r} registry_config_collected",
                    required=strict,
                    default=True,
                ),
                # The collector writes a (possibly empty) entry for every CA; an
                # absent entry means this CA's descriptor never reached the export.
                security_collected=name in ca_security,
            )
        )

    # --- templates + which enrollment service publishes them ---
    published_by: dict[str, list[str]] = {}
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
        normalized_ca_name = _coerce_str(ca_name)
        if not normalized_ca_name:
            continue
        for ref in tmpls:
            normalized_ref = _coerce_str(ref)
            if normalized_ref:
                published_by.setdefault(normalized_ref, []).append(normalized_ca_name)

    templates: list[CertTemplate] = []
    for t in _require_list(base, "templates.json", _load(base, "templates.json")):
        if not isinstance(t, dict):
            raise IngestError("templates.json entries must be objects")
        oid = _coerce_str(t.get("oid", ""))
        name = _coerce_str(t.get("name", ""))
        pubs = published_by.get(oid) or published_by.get(name) or []
        schema_version = t.get("schema_version", 1)
        try:
            schema_version = int(schema_version) if schema_version is not None else 1
        except (TypeError, ValueError) as exc:
            raise IngestError(
                f"invalid schema_version for template {name!r}: {schema_version!r}"
            ) from exc
        templates.append(
            _template(
                t,
                strict=strict,
                oid=oid,
                name=name,
                published_by=tuple(sorted(set(pubs))),
                schema_version=schema_version,
            )
        )

    acls_data = _require_list(base, "pki-acls.json", _load(base, "pki-acls.json"))
    acls = tuple(
        PkiObjectAcl(
            object_dn=_coerce_str(a.get("object_dn", "")),
            kind=_kind(a.get("kind", ""), AclKind, "PKI ACL kind", default="pks_container"),
            security=_aces(a.get("security")),
            owner_sid=normalize_sid(_coerce_str(a.get("owner_sid", ""))),
            acl_obtained=_marker_bool(
                a.get("acl_obtained", _ABSENT),
                f"pki-acls.json: {_coerce_str(a.get('object_dn', ''))!r} acl_obtained",
                required=strict,
                default=True,
            ),
        )
        for a in acls_data
    )

    endpoints = tuple(
        EnrollmentEndpoint(
            kind=_kind(e.get("kind", ""), EndpointKind, "endpoint kind", default="web_enrollment"),
            name=_coerce_str(e.get("name", "")),
            transports=frozenset(
                _coerce_str(t).lower() for t in e.get("transports", []) if _coerce_str(t)
            ),
            ssl_required=_marker_bool(
                e.get("ssl_required", _ABSENT),
                f"web-endpoints.json: {_coerce_str(e.get('name', ''))!r} ssl_required",
                required=strict,
                default=False,
            ),
            windows_auth=_marker_bool(
                e.get("windows_auth", _ABSENT),
                f"web-endpoints.json: {_coerce_str(e.get('name', ''))!r} windows_auth",
                required=strict,
                default=False,
            ),
            auth_providers=frozenset(
                _coerce_str(p).lower() for p in e.get("auth_providers", []) if _coerce_str(p)
            ),
            epa=_kind(e.get("epa", "unknown"), EpaPolicy, "EPA policy", default="unknown"),
        )
        for e in _require_list(base, "web-endpoints.json", _load(base, "web-endpoints.json"))
        if isinstance(e, dict)
    )

    oids = tuple(
        IssuanceOid(
            oid=_coerce_str(o.get("oid", "")),
            name=_coerce_str(o.get("name", "")),
            # msDS-OIDToGroupLink is a group DN (not a SID) — store it verbatim.
            group_link=_coerce_str(o["group_link"]) if o.get("group_link") else None,
        )
        for o in _require_list(base, "oid-objects.json", _load(base, "oid-objects.json"))
    )

    # --- DC configuration (ESC10) ---
    dcs = tuple(
        DcConfiguration(
            name=_coerce_str(d.get("name", "")),
            strong_certificate_binding_enforcement=_kind(
                d.get("strong_certificate_binding_enforcement", "unknown"),
                StrongCertBinding,
                "StrongCertificateBindingEnforcement",
                default="unknown",
            ),
            schannel_mapping_methods=frozenset(
                _kind(m, SchannelMappingMethod, "SchannelMappingMethod", default="unknown")
                for m in d.get("schannel_mapping_methods", [])
            ),
        )
        for d in _require_list(base, "dc-config.json", _load(base, "dc-config.json"))
    )

    # --- Principal mappings (ESC14) ---
    principal_mappings = tuple(
        PrincipalMapping(
            dn=_coerce_str(p.get("dn", "")),
            mappings=tuple(_coerce_str(m) for m in p.get("mappings", [])),
        )
        for p in _require_list(
            base, "principal-mappings.json", _load(base, "principal-mappings.json")
        )
    )

    manifest = Manifest(
        collector_version=collector_version,
        collected_at=_coerce_str(raw_manifest.get("collected_at", "")),
        host=_coerce_str(raw_manifest.get("host", "")),
        domain=_coerce_str(raw_manifest.get("domain", "")),
        skipped_passes=skipped_passes,
        certs_parsed=certs_parsed,
        enrollment_services_available=enrollment_services_available,
        missing_passes=missing_passes,
    )

    ca_names = {ca.name for ca in cas}
    unattached = tuple(
        (ca_name, cert)
        for ca_name in sorted(cert_by_ca)
        if ca_name not in ca_names
        for cert in cert_by_ca[ca_name]
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


def _template(
    t: dict[str, Any],
    *,
    strict: bool,
    oid: str,
    name: str,
    published_by: tuple[str, ...],
    schema_version: int,
) -> CertTemplate:
    acl_obtained = _marker_bool(
        t.get("acl_obtained", _ABSENT),
        f"templates.json: {name!r} acl_obtained",
        required=strict,
        default=True,
    )
    return CertTemplate(
        name=name,
        display_name=_coerce_str(t.get("display_name", name)),
        schema_version=schema_version,
        oid=oid,
        ekus=tuple(_coerce_str(e) for e in t.get("ekus", [])),
        name_flags=frozenset(_coerce_str(f) for f in t.get("name_flags", [])),
        enrollment_flags=frozenset(_coerce_str(f) for f in t.get("enrollment_flags", [])),
        min_key_size=_coerce_int(t.get("min_key_size"), "template min_key_size"),
        issuance_policy_oids=tuple(_coerce_str(p) for p in t.get("issuance_policy_oids", [])),
        security=_aces(t.get("security")),
        published_by=published_by,
        acl_obtained=acl_obtained,
        csp=_coerce_str(t.get("csp", "")).lower(),
        owner_sid=normalize_sid(_coerce_str(t.get("owner_sid", ""))),
    )
