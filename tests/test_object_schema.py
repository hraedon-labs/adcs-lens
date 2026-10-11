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
from adcs_lens.detection import _TYPE_CONTAINER, CHECKS
from adcs_lens.ingest import REQUIRED_KEYS, ingest

_ROOT = Path(__file__).resolve().parent.parent
_COLLECTOR = _ROOT / "scripts" / "Export-AdcsEstate.ps1"
_SIMULATE = _ROOT / "tests" / "collector" / "simulate.ps1"
_PWSH = shutil.which("pwsh")


def _schema() -> dict[str, dict[str, dict[str, str]]]:
    source = _COLLECTOR.read_text(encoding="utf-8")
    m = re.search(r"\$OBJECT_SCHEMA = ConvertFrom-Json @'\r?\n(.*?)\r?\n'@", source, re.S)
    assert m, "the collector no longer declares $OBJECT_SCHEMA"
    schema: dict[str, dict[str, dict[str, str]]] = json.loads(m.group(1))
    return schema


SCHEMA = _schema()

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
            "kind",
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
        for f in ("auth_providers", "epa", "kind", "ssl_required", "transports", "windows_auth")
    },
    "cert": {
        f: "the DER certificate"
        for f in (
            "aia_urls",
            "ca_kind",
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
    "template": ("templates", "enrollment-services"),  # published_by is the CA's list
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
    """Each field detection.CHECKS declares comes from the schema or a named non-LDAP read."""
    for subject, fields in _declared_inputs().items():
        schema_fields = {
            rule["field"] for c in _SUBJECT_SOURCES[subject] for rule in SCHEMA[c].values()
        }
        for field in fields:
            from_schema = field in schema_fields
            elsewhere = field in _NOT_LDAP.get(subject, {})
            assert from_schema != elsewhere, (subject, field, from_schema, elsewhere)


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
    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(name)
        .last_update(now - timedelta(days=1))
        .next_update(now + timedelta(days=90))
        .sign(key, hashes.SHA256())
    )
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "root.cer").write_bytes(cert.public_bytes(Encoding.DER))
    (directory / "root.crl").write_bytes(crl.public_bytes(Encoding.DER))


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
