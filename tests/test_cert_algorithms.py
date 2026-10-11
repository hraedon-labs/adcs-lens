"""A valid certificate the library cannot fully interpret still ingests.

Both reviewers, round 11: a structurally valid DER certificate whose signature
algorithm the library does not support raised UnsupportedAlgorithm out of
certs.py - a traceback and exit 1. Now only an unloadable file rejects the
export (exit 4); a field the library cannot derive from a loaded certificate
is not obtained, so exactly the checks that read it are undecided (never a
guessed "weak" or "strong"), and the rest of the certificate is evaluated.

The certificates are generated for every key type and signature algorithm the
cryptography library produces, plus hand-edited DER (an unknown signature OID,
an unknown key OID, a duplicated extension), and each is run through ingest,
doctor and diff.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("cryptography")

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import (  # noqa: E402
    dsa,
    ec,
    ed448,
    ed25519,
    padding,
    rsa,
)
from cryptography.hazmat.primitives.serialization import Encoding  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

from adcs_lens.certs import UnparseableDer, parse_cert  # noqa: E402
from adcs_lens.cli import EXIT_DATA_ERROR, main  # noqa: E402
from adcs_lens.detection import evaluate  # noqa: E402
from adcs_lens.ingest import ingest  # noqa: E402
from adcs_lens.model import CertKind  # noqa: E402
from tests.conftest import NOW  # noqa: E402
from tests.test_diff_coverage import build_full_export  # noqa: E402

_NAME = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "LAB Root CA")])
_SHA256_RSA = bytes.fromhex("06092a864886f70d01010b")  # sha256WithRSAEncryption
_UNKNOWN_SIG = bytes.fromhex("06092a864886f70d01017f")  # same length, unassigned
# sha1WithRSAEncryption (same length): the local OpenSSL refuses to SIGN with
# SHA-1, so the OID is swapped in; nothing verifies the signature.
_SHA1_RSA = bytes.fromhex("06092a864886f70d010105")
_RSA_KEY = bytes.fromhex("06092a864886f70d010101")  # rsaEncryption
_UNKNOWN_KEY = bytes.fromhex("06092a864886f70d01017e")
_SKI = bytes.fromhex("0603551d0e")  # subjectKeyIdentifier
_CDP = bytes.fromhex("0603551d1f")  # cRLDistributionPoints (same length)


def _build(key: Any, algorithm: Any, *, rsa_padding: Any = None, extensions: bool = True) -> bytes:
    now = datetime.now(UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(_NAME)
        .issuer_name(_NAME)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=30))
        .not_valid_after(now + timedelta(days=3650))
    )
    if extensions:
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        ).add_extension(
            x509.CRLDistributionPoints(
                [
                    x509.DistributionPoint(
                        full_name=[x509.UniformResourceIdentifier("http://crl.example/r.crl")],
                        relative_name=None,
                        reasons=None,
                        crl_issuer=None,
                    )
                ]
            ),
            critical=False,
        )
    kwargs = {"rsa_padding": rsa_padding} if rsa_padding is not None else {}
    return builder.sign(key, algorithm, **kwargs).public_bytes(Encoding.DER)


def _rsa(bits: int) -> Any:
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def _replace(der: bytes, old: bytes, new: bytes) -> bytes:
    assert old in der
    return der.replace(old, new)


# name -> (DER factory, fields expected NOT obtained)
_CASES: dict[str, tuple[Callable[[], bytes], frozenset[str]]] = {
    "rsa2048-sha256": (lambda: _build(_rsa(2048), hashes.SHA256()), frozenset()),
    "rsa2048-sha1": (
        lambda: _replace(_build(_rsa(2048), hashes.SHA256()), _SHA256_RSA, _SHA1_RSA),
        frozenset(),
    ),
    "rsa2048-sha384": (lambda: _build(_rsa(2048), hashes.SHA384()), frozenset()),
    "rsa2048-sha512": (lambda: _build(_rsa(2048), hashes.SHA512()), frozenset()),
    "rsa1024-sha256": (lambda: _build(_rsa(1024), hashes.SHA256()), frozenset()),
    "rsa2048-pss-sha256": (
        lambda: _build(
            _rsa(2048),
            hashes.SHA256(),
            rsa_padding=padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        ),
        frozenset(),
    ),
    "ec-p256-sha256": (
        lambda: _build(ec.generate_private_key(ec.SECP256R1()), hashes.SHA256()),
        frozenset(),
    ),
    "ec-p384-sha384": (
        lambda: _build(ec.generate_private_key(ec.SECP384R1()), hashes.SHA384()),
        frozenset(),
    ),
    "ec-p521-sha512": (
        lambda: _build(ec.generate_private_key(ec.SECP521R1()), hashes.SHA512()),
        frozenset(),
    ),
    "dsa2048-sha256": (
        lambda: _build(dsa.generate_private_key(key_size=2048), hashes.SHA256()),
        frozenset(),
    ),
    # No separate signature hash; a key type without a graded size.
    "ed25519": (
        lambda: _build(ed25519.Ed25519PrivateKey.generate(), None),
        frozenset({"sig_alg", "key_bits", "key_alg"}),
    ),
    "ed448": (
        lambda: _build(ed448.Ed448PrivateKey.generate(), None),
        frozenset({"sig_alg", "key_bits", "key_alg"}),
    ),
    # Hand-edited DER: still loadable, but the library cannot interpret a part.
    "unknown-signature-oid": (
        lambda: _replace(_build(_rsa(2048), hashes.SHA256()), _SHA256_RSA, _UNKNOWN_SIG),
        frozenset({"sig_alg"}),
    ),
    "unknown-key-oid": (
        lambda: _replace(_build(_rsa(2048), hashes.SHA256()), _RSA_KEY, _UNKNOWN_KEY),
        frozenset({"key_bits", "key_alg"}),
    ),
    "duplicate-extension": (
        lambda: _replace(_build(_rsa(2048), hashes.SHA256()), _SKI, _CDP),
        frozenset({"ocsp_urls", "aia_urls", "cdp_urls"}),
    ),
}
# The check(s) reading each field (detection.CHECKS for the cert subject).
_READERS = {
    "sig_alg": {"WEAK_SIG_ALG"},
    "key_bits": {"WEAK_KEY_SIZE"},
    "key_alg": {"WEAK_KEY_SIZE"},
}


@pytest.fixture(scope="module")
def seed(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return build_full_export(tmp_path_factory.mktemp("algs") / "seed")


@pytest.fixture(scope="module")
def ders() -> dict[str, bytes]:
    return {name: make() for name, (make, _) in _CASES.items()}


def _with_root(seed: Path, out: Path, der: bytes) -> Path:
    shutil.copytree(seed, out)
    (out / "certs" / "root.cer").write_bytes(der)
    return out


@pytest.mark.parametrize("name", sorted(_CASES))
def test_every_field_is_derived_or_not_obtained(ders: dict[str, bytes], name: str) -> None:
    lifecycle = parse_cert(ders[name], kind=CertKind.ROOT_CA)
    assert lifecycle.unobtained == _CASES[name][1]
    if "sig_alg" not in lifecycle.unobtained:
        assert lifecycle.sig_alg not in ("", "unknown")
    if "key_bits" not in lifecycle.unobtained:
        assert lifecycle.key_bits
    assert lifecycle.not_after is not None and lifecycle.fingerprint


@pytest.mark.parametrize("name", sorted(_CASES))
def test_a_valid_certificate_ingests_and_only_its_readers_are_undecided(
    seed: Path, tmp_path: Path, ders: dict[str, bytes], name: str
) -> None:
    export = _with_root(seed, tmp_path / name, ders[name])
    estate = ingest(export)
    ev = evaluate(estate, now=NOW)
    lost = _CASES[name][1]
    root_keys = {f"a:cert:sha256:{hashlib.sha256(ders[name]).hexdigest()}"}
    by_check = {v.check: v for v in ev.verdicts if v.key in root_keys}
    assert "CA_CERT_EXPIRY" in by_check, "the root certificate was not evaluated"
    # Expiry reads only not_after (obtained): always decided.
    assert by_check["CA_CERT_EXPIRY"].state != "undecided"
    for field, checks in _READERS.items():
        for check in checks:
            if field in lost:
                assert by_check[check].state == "undecided", (check, field)
                assert not by_check[check].usable
    # A field never turns into a guessed finding: an undecided check has none.
    flagged = {f.check for f in ev.findings if f.subject.endswith("LAB Root CA")}
    assert not flagged & {c for f in lost for c in _READERS.get(f, set())}


@pytest.mark.parametrize("name", sorted(_CASES))
def test_every_command_handles_the_certificate_without_a_traceback(
    seed: Path,
    tmp_path: Path,
    ders: dict[str, bytes],
    capsys: pytest.CaptureFixture[str],
    name: str,
) -> None:
    export = _with_root(seed, tmp_path / name, ders[name])
    for argv in (
        ["ingest", str(export)],
        ["doctor", str(export), "--json"],
        ["diff", str(seed), str(export), "--exit-code", "--json"],
        ["diff", str(export), str(seed), "--exit-code"],
    ):
        capsys.readouterr()
        rc = main(argv)
        err = capsys.readouterr().err
        assert rc in (0, 1, 3), (argv, rc, err)
        assert "Traceback" not in err and "error:" not in err, err


def test_weak_algorithms_are_still_flagged(
    seed: Path, tmp_path: Path, ders: dict[str, bytes]
) -> None:
    """Obtained values decide as before: SHA-1 and a 1024-bit RSA key flag."""
    for name, check in (("rsa2048-sha1", "WEAK_SIG_ALG"), ("rsa1024-sha256", "WEAK_KEY_SIZE")):
        estate = ingest(_with_root(seed, tmp_path / name, ders[name]))
        flagged = {
            f.check for f in evaluate(estate, now=NOW).findings if "LAB Root CA" in f.subject
        }
        assert check in flagged, name


@pytest.mark.parametrize(
    "corrupt",
    [
        lambda d: d[: len(d) // 2],
        lambda d: b"\x30\x82\xff\xff" + d,
        lambda d: b"not DER",
    ],
    ids=["truncated", "bad-length", "text"],
)
def test_only_an_unloadable_file_rejects_the_export(
    seed: Path,
    tmp_path: Path,
    ders: dict[str, bytes],
    capsys: pytest.CaptureFixture[str],
    corrupt: Callable[[bytes], bytes],
) -> None:
    der = corrupt(ders["rsa2048-sha256"])
    with pytest.raises(UnparseableDer):
        parse_cert(der, kind=CertKind.ROOT_CA)
    export = _with_root(seed, tmp_path / "bad", der)
    capsys.readouterr()
    assert main(["doctor", str(export)]) == EXIT_DATA_ERROR
    assert capsys.readouterr().err.startswith("error: certs/root.cer: not a DER certificate")


def test_the_cases_cover_every_key_type_the_library_signs_with() -> None:
    names = " ".join(_CASES)
    for family in ("rsa", "pss", "ec-", "dsa", "ed25519", "ed448", "unknown-signature"):
        assert family in names
    assert json.dumps(sorted(_READERS))  # the readers table is not empty


def test_an_unreadable_extension_leaves_only_the_url_checks_undecided(
    seed: Path, tmp_path: Path
) -> None:
    """The issuing CA's certificate (attached, so OCSP_URL_ABSENT and
    CDP_AIA_ABSENT decide it) with a duplicated extension: its URLs are not
    obtained - never "absent" - while expiry and key size still decide."""
    key = _rsa(2048)
    issuing = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "LAB Issuing CA")])
    now = datetime.now(UTC)
    der = (
        x509.CertificateBuilder()
        .subject_name(issuing)
        .issuer_name(_NAME)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=30))
        .not_valid_after(now + timedelta(days=1825))
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.CRLDistributionPoints(
                [
                    x509.DistributionPoint(
                        full_name=[x509.UniformResourceIdentifier("http://crl.example/i.crl")],
                        relative_name=None,
                        reasons=None,
                        crl_issuer=None,
                    )
                ]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
        .public_bytes(Encoding.DER)
    )
    der = _replace(der, _SKI, _CDP)
    out = tmp_path / "dup"
    shutil.copytree(seed, out)
    (out / "certs" / "issuing.cer").write_bytes(der)
    ev = evaluate(ingest(out), now=NOW)
    key_ref = f"a:cert:sha256:{hashlib.sha256(der).hexdigest()}"
    by_check = {v.check: v for v in ev.verdicts if v.key == key_ref}
    assert by_check["OCSP_URL_ABSENT"].state == "undecided"
    assert by_check["CDP_AIA_ABSENT"].state == "undecided"
    assert by_check["CA_CERT_EXPIRY"].state != "undecided"
    assert by_check["WEAK_KEY_SIZE"].state != "undecided"


def _crl(key: Any, algorithm: Any) -> bytes:
    now = datetime.now(UTC)
    return (
        x509.CertificateRevocationListBuilder()
        .issuer_name(_NAME)
        .last_update(now - timedelta(days=1))
        .next_update(now + timedelta(days=7))
        .sign(key, algorithm)
        .public_bytes(Encoding.DER)
    )


@pytest.mark.parametrize(
    "make",
    [
        lambda: _crl(_rsa(2048), hashes.SHA256()),
        lambda: _crl(ec.generate_private_key(ec.SECP384R1()), hashes.SHA384()),
        lambda: _crl(dsa.generate_private_key(key_size=2048), hashes.SHA256()),
        lambda: _crl(ed25519.Ed25519PrivateKey.generate(), None),
        lambda: _crl(ed448.Ed448PrivateKey.generate(), None),
        lambda: _replace(_crl(_rsa(2048), hashes.SHA256()), _SHA256_RSA, _UNKNOWN_SIG),
    ],
    ids=["rsa", "ec", "dsa", "ed25519", "ed448", "unknown-signature-oid"],
)
def test_a_crl_of_any_signature_algorithm_ingests(
    seed: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str], make: Callable[[], bytes]
) -> None:
    out = tmp_path / "crl"
    shutil.copytree(seed, out)
    (out / "certs" / "root.crl").write_bytes(make())
    crl = next(c for c in ingest(out).crls if "LAB Root CA" in c.issuer)
    assert crl.this_update is not None and crl.next_update is not None
    capsys.readouterr()
    assert main(["diff", str(seed), str(out), "--exit-code"]) in (0, 1, 3)
    assert "Traceback" not in capsys.readouterr().err
