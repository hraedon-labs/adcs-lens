"""Round 7: one table of what every LDAP-enumerated object must carry.

scripts/Export-AdcsEstate.ps1 declares $OBJECT_SCHEMA - per container, every
attribute it requests, its type, the export field it feeds and whether it is
required (identity / join / deciding), optional (AD omits an attribute that has
no value), a placeholder (a DC's dNSHostName) or the security descriptor. The
collector turns a returned object that breaks it into an object failure (no
row, the container marked incomplete); ingest mirrors the key columns in
REQUIRED_KEYS. This module checks the three agree with each other and with the
inputs detection.CHECKS declares, then runs the real collector body once per
container x attribute x corruption and diffs the result against a clean run:
no corrupted object may ever surface as a new, resolved or worsened finding,
and the run must report coverage lost (exit 3).
(Sol round 6's probe is replayed in tests/test_reviewer_probes_r6.py.)
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from adcs_lens.cli import main
from adcs_lens.detection import _TYPE_CONTAINER, CHECKS, evaluate
from adcs_lens.ingest import REQUIRED_KEYS, IngestError, ingest

_ROOT = Path(__file__).resolve().parent.parent
_COLLECTOR = _ROOT / "scripts" / "Export-AdcsEstate.ps1"
_SIMULATE = _ROOT / "tests" / "collector" / "simulate.ps1"
_PWSH = shutil.which("pwsh")


_SOURCE = _COLLECTOR.read_text(encoding="utf-8")


def _table(name: str) -> dict[str, Any]:
    m = re.search(rf"\${name} = ConvertFrom-Json @'\r?\n(.*?)\r?\n'@", _SOURCE, re.S)
    assert m, f"the collector no longer declares ${name}"
    table: dict[str, Any] = json.loads(m.group(1))
    return table


SCHEMA: dict[str, dict[str, dict[str, str]]] = _table("OBJECT_SCHEMA")
# subject.field -> {by, from, containers, join, miss[, text]}
DERIVED: dict[str, dict[str, Any]] = _table("DERIVED_FIELDS")
# name -> {field, by, from, to, keys, compare, none, ambiguous}
JOINS: dict[str, dict[str, Any]] = _table("JOINS")

# The export file each schema container's rows land in (ingest's REQUIRED_KEYS).
_FILE = {
    "enrollment-services": "ca-config.json",
    "templates": "templates.json",
    "oid-objects": "oid-objects.json",
    "pki-acls": "pki-acls.json",
    "certs": "certs/index.json:certs",
    "crls": "certs/index.json:crls",
    "principal-mappings": "principal-mappings.json",
    "dc-config": "dc-config.json",
}
# Key columns the collector writes itself, not from an LDAP attribute.
_GENERATED_KEYS = {
    ("certs/index.json:certs", "file"),
    ("certs/index.json:certs", "kind"),  # from the DER (self-signed or not)
    ("certs/index.json:crls", "file"),
}
# The (identity) distinguishedName is the fallback name of a DC whose
# dNSHostName is a placeholder failure.
_IDENTITY_FALLBACK = {("dc-config.json", "name")}

# Detection inputs that do not come from an LDAP attribute of the subject's own
# object: each is read elsewhere, and the read is proven separately (null = not
# obtained), so it is outside this table by design.
_NOT_LDAP: dict[str, dict[str, str]] = {
    "ca": {
        f: "CA registry (certutil -getreg / CA\\Security)"
        for f in (
            "audit_filter",
            "ca_patch_state",
            "disabled_extensions",
            "edit_flags",
            "interface_flags",
            "kind",  # CAType (null for a remote CA)
            "owner_sid",
            "security",
        )
    },
    "template": {"owner_sid": "security descriptor owner (sd)"},
    "pki": {"kind": "the collector's fixed container kind", "owner_sid": "sd"},
    "dc": {
        "schannel_mapping_methods": "DC registry over WMI",
        "strong_certificate_binding_enforcement": "DC registry over WMI",
    },
    "endpoint": {
        f: "IIS configuration"
        for f in ("auth_providers", "epa", "kind", "ssl_required", "windows_auth")
    },
    "cert": {
        f: "the DER certificate"
        for f in (
            "aia_urls",
            "cdp_urls",
            "key_alg",
            "key_bits",
            "kind",
            "not_after",
            "ocsp_urls",
            "sig_alg",
        )
    },
    "crl": {"next_update": "the DER CRL", "this_update": "the DER CRL"},
}
# The schema containers that source each detection subject type.
_SUBJECT_SOURCES = {
    "ca": ("enrollment-services",),
    "template": ("templates",),
    "oid": ("oid-objects",),
    "pki": ("pki-acls",),
    "principal": ("principal-mappings",),
    "dc": ("dc-config",),
    "endpoint": (),
    "cert": ("certs",),
    "crl": ("crls",),
}


def _declared_inputs() -> dict[str, set[str]]:
    by_subject: defaultdict[str, set[str]] = defaultdict(set)
    for inputs in CHECKS.values():
        by_subject[inputs.subject] |= inputs.fields | inputs.text
        for subject, fields in inputs.deps.items():
            by_subject[subject] |= fields
    return by_subject


def test_every_schema_container_is_a_detection_container() -> None:
    assert set(_SUBJECT_SOURCES) == set(_TYPE_CONTAINER)
    sourced = {c for cs in _SUBJECT_SOURCES.values() for c in cs}
    assert sourced == set(SCHEMA), "a schema container no check reads, or a missing one"
    for container, attrs in SCHEMA.items():
        assert attrs["distinguishedname"]["need"] == "required", container
        for attr, rule in attrs.items():
            assert rule["type"] in {"string", "strings", "guid", "int", "bytes"}, (container, attr)
            assert rule["need"] in {"required", "optional", "placeholder", "sd"}, (container, attr)


def test_every_declared_detection_input_has_one_source() -> None:
    """Each field detection.CHECKS declares comes from exactly one place: an
    attribute of the subject's own object (schema), a named own-object read
    (registry, WMI, IIS, DER, descriptor), or a declared derivation from
    another object or container ($DERIVED_FIELDS). A field derived without a
    declared provenance has no source here and fails."""
    for subject, fields in _declared_inputs().items():
        schema_fields = {
            rule["field"] for c in _SUBJECT_SOURCES[subject] for rule in SCHEMA[c].values()
        }
        for field in fields:
            sources = [
                field in schema_fields,
                field in _NOT_LDAP.get(subject, {}),
                f"{subject}.{field}" in DERIVED,
            ]
            assert sum(sources) == 1, (subject, field, sources)


def test_every_derived_field_names_its_sources() -> None:
    for key, entry in DERIVED.items():
        subject, _, field = key.partition(".")
        assert subject in _TYPE_CONTAINER and field, key
        assert entry["by"] in {"collector", "ingest"}, key
        assert entry["from"] and entry["join"] and entry["miss"], key
        known = set(_TYPE_CONTAINER.values()) | {c for i in CHECKS.values() for c in i.containers}
        assert set(entry["containers"]) <= known, key
        assert "default" not in entry["miss"], key  # a miss is null / unknown


def test_every_check_reading_a_derived_field_declares_its_source_containers() -> None:
    """Sol round 7: CRL_EXPIRY read a tier derived from the AIA certificates but
    declared only the CRL container, so a partial AIA read became a verified
    critical -> high improvement. A deciding read of a derived field must name
    every source container; a text-only read must say how the text degrades."""
    for (check, variant), inputs in CHECKS.items():
        reads = {(inputs.subject, f) for f in inputs.fields} | {
            (t, f) for t, fs in inputs.deps.items() for f in fs
        }
        for subject, field in reads:
            entry = DERIVED.get(f"{subject}.{field}")
            if entry is not None:
                missing = set(entry["containers"]) - inputs.containers
                assert not missing, (check, variant, field, missing)
        for field in inputs.text:
            entry = DERIVED.get(f"{inputs.subject}.{field}")
            if entry is not None and not set(entry["containers"]) <= inputs.containers:
                assert entry.get("text"), (check, variant, field)


# Maps the collector body looks objects up in. A map built in one loop and read
# while writing another container's rows is a derivation and must be declared.
_LOOKUPS = {
    "enumeration": "the markers being written (bookkeeping, not a row field)",
    "enrollmentServices": "written by the enrollment-services loop, never read",
    "caSecurity": "written per CA row, never read",
    "script:localSecurity": "the local CA's own CA\\Security read (miss = null)",
    "caKindByName": "crl.tier",
}


def test_every_collector_lookup_is_declared() -> None:
    body = _SOURCE[_SOURCE.index("if ($PSCmdlet.ParameterSetName -eq 'SelfTest') { return }") :]
    used = set(re.findall(r"\$([A-Za-z:]+)(?:\.ContainsKey\(|\[\$)", body))
    assert used <= set(_LOOKUPS), sorted(used - set(_LOOKUPS))
    for name, purpose in _LOOKUPS.items():
        if "." in purpose.split()[0]:
            assert purpose in DERIVED, (name, purpose)


def test_ingest_required_keys_mirror_the_schema() -> None:
    """A key column ingest rejects when blank is required collector-side, and back."""
    for container, file in _FILE.items():
        required = {r["field"] for r in SCHEMA[container].values() if r["need"] == "required"}
        placeholder = {r["field"] for r in SCHEMA[container].values() if r["need"] == "placeholder"}
        for key in REQUIRED_KEYS[file]:
            if (file, key) in _GENERATED_KEYS:
                continue
            if (file, key) in _IDENTITY_FALLBACK:
                assert key in placeholder and "(identity)" in required, (file, key)
                continue
            assert key in required, (file, key)
        # Every required column that is a join or identity key is enforced at
        # ingest; deciding fields (mappings, the CRL tier) are typed by _Fields.
        keys = set(REQUIRED_KEYS[file])
        for field in required - keys - {"(identity)", "object_guid"}:
            if field.startswith("("):
                continue  # a join key of a derived field, see $DERIVED_FIELDS
            assert field in _declared_inputs()[_subject_of(container)], (container, field)


def _subject_of(container: str) -> str:
    return next(s for s, cs in _SUBJECT_SOURCES.items() if cs and cs[0] == container)


# --- the generic corruption matrix ------------------------------------------------


def _cases() -> list[tuple[str, str, str]]:
    cases = []
    for container, attrs in SCHEMA.items():
        for attr, rule in attrs.items():
            if rule["need"] == "sd":
                continue  # an unreadable descriptor is a null read (test_collector_simulated)
            modes = ("empty", "wrongtype")
            if rule["need"] in ("required", "placeholder"):
                modes = ("missing", *modes)
            cases += [(container, attr, mode) for mode in modes]
    return cases


CASES = _cases()

# For every derived field, a collector run in which its source is lost (the
# source container incomplete, or the parent read failing).
SOURCE_LOSS: dict[str, tuple[str, ...]] = {
    "crl.tier": ("-Omit", "certs:cn:missing"),  # the root's AIA object fails
    "cert.ca_kind": ("-Omit", "enrollment-services:cn:missing"),  # its CA row fails
    "template.published_by": ("-Omit", "enrollment-services:cn:missing"),
    "endpoint.transports": ("-BrokenBindings",),  # the site's bindings read nothing
}


def test_every_derived_field_has_a_source_loss_case() -> None:
    assert set(SOURCE_LOSS) == set(DERIVED)


# For every join, a collector run in which one reference matches two objects
# (differing only in case), and what that must yield.
AMBIGUITY: dict[str, tuple[str, ...] | None] = {
    "publication": ("-Ambiguous", "publication"),
    "crl-tier": ("-Ambiguous", "crl-tier"),
    "oid-link": ("-Ambiguous", "oid-link"),
    # Two CA rows sharing a name break all three CA-name joins: an ingest error.
    "cert-ca": ("-Ambiguous", "cert-ca"),
    "ca-security": ("-Ambiguous", "cert-ca"),
    "publisher-ca": ("-Ambiguous", "cert-ca"),
    "app-site": None,  # impossible: an application is enumerated under its site
}
_AMBIGUITY_IS_AN_ERROR = {"cert-ca", "ca-security", "publisher-ca"}


def test_every_join_declares_its_keys_and_has_an_ambiguity_case() -> None:
    """Sol round 8: the publication join matched "oid or cn" without proving
    one template answered, so a template's dotted cn equal to another's OID
    attached the publisher to both. Every join names the keys it compares and
    what zero / several matches yield, and has an ambiguity run."""
    assert set(AMBIGUITY) == set(JOINS)
    for name, join in JOINS.items():
        assert join["keys"] and join["compare"] and join["none"] and join["ambiguous"], name
        assert "arbitrary" not in join["ambiguous"] and "first" not in join["ambiguous"], name
        if AMBIGUITY[name] is None:
            assert join["ambiguous"].startswith("impossible"), name
    # Every derived field is the result of a declared join.
    assert set(DERIVED) <= {j["field"] for j in JOINS.values()}


def test_the_publication_join_compares_cn_only_for_a_proven_export() -> None:
    from adcs_lens.ingest import PUBLICATION_KEYS_LEGACY, PUBLICATION_KEYS_PROVEN

    assert JOINS["publication"]["keys"] == ["cn"] and PUBLICATION_KEYS_PROVEN == ("name",)
    assert JOINS["publication"]["legacy_keys"] == ["cn", "oid"]
    assert PUBLICATION_KEYS_LEGACY == ("name", "oid")


def _write_der(directory: Path) -> None:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.x509.oid import NameOID

    now = datetime.now(UTC)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "LAB Root CA")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=365))
        .not_valid_after(now + timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )
    # Inside CRL_EXPIRY's early-warning window, where the derived tier decides
    # the severity (root CRITICAL, issuing HIGH): Sol round 7.
    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(name)
        .last_update(now - timedelta(days=89))
        .next_update(now + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    # The issuing CA's certificate, without OCSP / AIA / CDP extensions: the
    # OCSP_URL_ABSENT and CDP_AIA_ABSENT checks read its CA's kind (ca_kind).
    iss_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    issuing = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "LAB Issuing CA")]))
        .issuer_name(name)
        .public_key(iss_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=365))
        .not_valid_after(now + timedelta(days=1825))
        .sign(key, hashes.SHA256())
    )
    # A cross-certificate of the root (same subject, another issuer), for the
    # crl-tier ambiguity run.
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cross = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "LAB Partner Root")]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=30))
        .not_valid_after(now + timedelta(days=1825))
        .sign(other_key, hashes.SHA256())
    )
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "cross.cer").write_bytes(cross.public_bytes(Encoding.DER))
    (directory / "root.cer").write_bytes(cert.public_bytes(Encoding.DER))
    (directory / "root.crl").write_bytes(crl.public_bytes(Encoding.DER))
    (directory / "issuing.cer").write_bytes(issuing.public_bytes(Encoding.DER))


def _simulate(out: Path, *args: str) -> Path:
    assert _PWSH is not None
    proc = subprocess.run(
        [_PWSH, "-NoProfile", "-NonInteractive", "-File", str(_SIMULATE), "-OutDir", str(out)]
        + list(args),
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return out


def _case_id(case: tuple[str, str, str]) -> str:
    return ":".join(case)


@pytest.fixture(scope="module")
def runs(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    """The clean baseline and one export per case, collected in parallel."""
    if _PWSH is None:
        pytest.skip("pwsh is not installed")
    base = tmp_path_factory.mktemp("schema")
    der = base / "der"
    _write_der(der)
    jobs = {"baseline": (base / "baseline", ("-DerDir", str(der)))}
    for i, case in enumerate(CASES):
        jobs[_case_id(case)] = (
            base / f"case{i:03d}",
            ("-DerDir", str(der), "-Omit", _case_id(case)),
        )
    for key, args in SOURCE_LOSS.items():
        jobs[f"source-loss:{key}"] = (base / f"loss-{key}", ("-DerDir", str(der), *args))
    for name, amb in AMBIGUITY.items():
        if amb is not None:
            jobs[f"ambiguous:{name}"] = (base / f"amb-{name}", ("-DerDir", str(der), *amb))
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {name: pool.submit(_simulate, out, *args) for name, (out, args) in jobs.items()}
        return {name: f.result() for name, f in futures.items()}


def _diff(old: Path, new: Path, capsys: pytest.CaptureFixture[str]) -> tuple[int, dict[str, Any]]:
    capsys.readouterr()
    rc = main(["diff", str(old), str(new), "--exit-code", "--json"])
    return rc, json.loads(capsys.readouterr().out)


def test_the_baseline_has_an_object_in_every_container(runs: dict[str, Path]) -> None:
    estate = ingest(runs["baseline"])
    assert estate.manifest.enumeration_complete >= set(SCHEMA) | {"ca-config"}
    assert estate.unattached_certs and estate.crls and estate.oids
    assert estate.principal_mappings and estate.dcs


@pytest.mark.parametrize("case", CASES, ids=_case_id)
def test_a_corrupted_object_is_never_a_finding_change(
    case: tuple[str, str, str],
    runs: dict[str, Path],
    capsys: pytest.CaptureFixture[str],
) -> None:
    container, attr, _mode = case
    out = runs[_case_id(case)]
    manifest = json.loads((out / "collector-manifest.json").read_text(encoding="utf-8"))
    placeholder = SCHEMA[container][attr]["need"] == "placeholder"
    lost = {_TYPE_CONTAINER[_subject_of(container)], container}
    if container == "enrollment-services":
        lost.add("ca-config")
    if placeholder:
        # The DC stays as an identity-bearing row with its deciding fields null.
        assert manifest["enumeration"][container]["complete"] is True
    else:
        for c in lost:
            marker = manifest["enumeration"][c]
            assert marker["complete"] is False, (c, marker)
            assert attr in marker["reason"], marker["reason"]
    ingest(out)  # never an ingest error: an honest collector's export is well-formed
    rc, env = _diff(runs["baseline"], out, capsys)
    assert env["new"] == [], env["new"]
    assert env["resolved"] == [], env["resolved"]
    assert not [c for c in env["changed"] if c["worsened"]], env["changed"]
    assert not [c for c in env["changed"] if c["old_severity"] != c["new_severity"]]
    assert env["summary"]["coverage_lost"] is True
    not_reevaluated = {u["check"] for u in env["unevaluated"]} | {
        i["check"] for i in env["indeterminate"]
    }
    # Only checks that read the corrupted container lose their verdicts.
    relying = {check for (check, _v), inputs in CHECKS.items() if inputs.containers & lost}
    assert not_reevaluated and not_reevaluated <= relying, not_reevaluated - relying
    if placeholder:
        assert {"ESC10", "ESC14"} <= not_reevaluated
    assert rc == 3


def _assert_no_verdict_moved(env: dict[str, Any], rc: int) -> None:
    assert env["new"] == [], env["new"]
    assert env["resolved"] == [], env["resolved"]
    assert not [c for c in env["changed"] if c["worsened"]], env["changed"]
    assert not [c for c in env["changed"] if c["old_severity"] != c["new_severity"]]
    assert env["summary"]["coverage_lost"] is True
    assert rc == 3


@pytest.mark.parametrize("key", sorted(SOURCE_LOSS))
def test_a_lost_source_never_moves_a_derived_verdict(
    key: str, runs: dict[str, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    """Sol round 7 generalised: a derived field whose source is incomplete is
    not obtained, so every check reading it is withheld - no verdict improves,
    resolves or worsens - and each such check the baseline decided (a usable
    verdict) is reported as not re-evaluated."""
    subject, _, field = key.partition(".")
    rc, env = _diff(runs["baseline"], runs[f"source-loss:{key}"], capsys)
    _assert_no_verdict_moved(env, rc)
    readers = {
        check
        for (check, _v), inputs in CHECKS.items()
        if (inputs.subject == subject and field in inputs.fields)
        or field in inputs.deps.get(subject, frozenset())
    }
    baseline = {v.check for v in evaluate(ingest(runs["baseline"])).verdicts if v.usable}
    flagged = readers & baseline
    assert flagged, f"the baseline decides no check reading {key}"
    not_reevaluated = {u["check"] for u in env["unevaluated"]} | {
        i["check"] for i in env["indeterminate"]
    }
    assert flagged <= not_reevaluated, flagged - not_reevaluated


@pytest.mark.parametrize("name", sorted(n for n, a in AMBIGUITY.items() if a is not None))
def test_an_ambiguous_join_never_moves_a_verdict(
    name: str, runs: dict[str, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    """One reference answering two objects: the joined field is not obtained for
    every object it matches (or the export is rejected) - never attached to
    an arbitrary match - so no verdict improves, resolves or worsens and each
    check reading the field that the baseline decided is not re-evaluated."""
    out = runs[f"ambiguous:{name}"]
    if name in _AMBIGUITY_IS_AN_ERROR:
        with pytest.raises(IngestError):
            ingest(out)
        return
    rc, env = _diff(runs["baseline"], out, capsys)
    _assert_no_verdict_moved(env, rc)
    subject, _, field = JOINS[name]["field"].partition(".")
    readers = {
        check
        for (check, _v), inputs in CHECKS.items()
        if (inputs.subject == subject and field in inputs.fields)
        or field in inputs.deps.get(subject, frozenset())
    }
    baseline = {v.check for v in evaluate(ingest(runs["baseline"])).verdicts if v.usable}
    decided = readers & baseline
    assert decided, f"the baseline decides no check reading {JOINS[name]['field']}"
    not_reevaluated = {u["check"] for u in env["unevaluated"]} | {
        i["check"] for i in env["indeterminate"]
    }
    assert decided <= not_reevaluated, decided - not_reevaluated
