"""Optional cert/CRL (DER) parsing — the ``[certs]`` extra.

This is the *only* module permitted to import a third-party dependency
(``cryptography``). It is imported lazily by :mod:`adcs_lens.ingest` inside a
``try/except ImportError`` so the deterministic core stays stdlib-only and
air-gappable; when the extra is absent, lifecycle fields are ``None`` and the
lifecycle detector degrades to a note.

Nothing here makes a network call — it parses bytes already on disk.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID

from adcs_lens.model import CertKind, CertLifecycle, Crl, CrlTier


class UnparseableDer(ValueError):
    """The bytes are not a DER certificate / CRL the library can load at all."""


def _derive[T](field: str, derive: Callable[[], T], unobtained: set[str], placeholder: T) -> T:
    """One field of a loaded certificate / CRL, or *placeholder* + not obtained.

    A structurally valid certificate can still name something the library
    cannot interpret (an unknown signature OID, an unsupported key type, a
    malformed extension): that field is not obtained, so only the checks that
    read it are undecided - never a guessed weak or strong value - and the rest
    of the certificate is still evaluated. Any library exception counts (they
    are not a closed set: UnsupportedAlgorithm, ValueError, TypeError,
    NotImplementedError, ...).
    """
    try:
        return derive()
    except Exception:  # noqa: BLE001 - see above: a field the library cannot derive
        unobtained.add(field)
        return placeholder


def _key_bits(cert: x509.Certificate) -> int | None:
    pub = cert.public_key()
    if isinstance(pub, (rsa.RSAPublicKey, dsa.DSAPublicKey)):
        return pub.key_size
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return pub.curve.key_size
    return None


def _sig_alg(cert: x509.Certificate) -> str:
    algo = cert.signature_hash_algorithm
    if not isinstance(algo, hashes.HashAlgorithm):
        # Ed25519 / Ed448 sign without a separate hash: not a hash to grade.
        raise ValueError("no signature hash algorithm")
    return algo.name.lower()


def _key_bits_of(cert: x509.Certificate) -> int:
    bits = _key_bits(cert)
    if bits is None:
        raise ValueError("no key size for this key type")
    return bits


def _key_alg(cert: x509.Certificate) -> str:
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        return "rsa"
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return "ecdsa"
    if isinstance(pub, dsa.DSAPublicKey):
        return "dsa"
    raise ValueError(f"unclassified key type {type(pub).__name__}")


def _uri_from_access_location(location: x509.GeneralName) -> str | None:
    """Extract a URI string from an AIA/CRL access location GeneralName."""
    if isinstance(location, x509.UniformResourceIdentifier):
        return location.value
    return None


def _aia_urls(cert: x509.Certificate) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Return ``(ocsp_urls, aia_ca_urls)`` parsed from the AIA extension.

    OCSP URLs come from AccessDescription entries whose access_method is
    ``ad_ocsp``; CA Issuer URLs from ``ad_ca_issuers`` entries. Both are
    ``uniformResourceIdentifier`` GeneralNames.
    """
    ocsp: list[str] = []
    ca_issuers: list[str] = []
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
    except x509.ExtensionNotFound:
        return (), ()
    aia = ext.value
    if not isinstance(aia, x509.AuthorityInformationAccess):
        return (), ()
    for desc in aia:
        if desc.access_method == AuthorityInformationAccessOID.OCSP:
            uri = _uri_from_access_location(desc.access_location)
            if uri:
                ocsp.append(uri)
        elif desc.access_method == AuthorityInformationAccessOID.CA_ISSUERS:
            uri = _uri_from_access_location(desc.access_location)
            if uri:
                ca_issuers.append(uri)
    return tuple(ocsp), tuple(ca_issuers)


def _cdp_urls(cert: x509.Certificate) -> tuple[str, ...]:
    """Return CRL Distribution Point URLs parsed from the CRL DP extension."""
    urls: list[str] = []
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
    except x509.ExtensionNotFound:
        return ()
    cdp = ext.value
    if not isinstance(cdp, x509.CRLDistributionPoints):
        return ()
    for dp in cdp:
        if dp.full_name is None:
            continue
        for name in dp.full_name:
            if isinstance(name, x509.UniformResourceIdentifier):
                urls.append(name.value)
    return tuple(urls)


def parse_cert(der: bytes, *, kind: CertKind) -> CertLifecycle:
    """Parse a DER certificate into :class:`CertLifecycle`.

    Raises :class:`UnparseableDer` only when the bytes cannot be loaded at all;
    a field that cannot be derived from a loaded certificate is not obtained.
    """
    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception as exc:  # noqa: BLE001 - any loader failure is an unloadable file
        raise UnparseableDer(f"{type(exc).__name__}: {exc}") from exc
    lost: set[str] = set()
    no_urls: tuple[tuple[str, ...], tuple[str, ...]] = ((), ())
    ocsp_urls, aia_urls = _derive("ocsp_urls", lambda: _aia_urls(cert), lost, no_urls)
    if "ocsp_urls" in lost:
        lost.add("aia_urls")  # one extension carries both
    return CertLifecycle(
        fingerprint=hashlib.sha256(der).hexdigest(),
        subject=_derive("subject", lambda: cert.subject.rfc4514_string(), set(), ""),
        kind=kind,
        not_before=_derive("not_before", lambda: cert.not_valid_before_utc, lost, None),
        not_after=_derive("not_after", lambda: cert.not_valid_after_utc, lost, None),
        sig_alg=_derive("sig_alg", lambda: _sig_alg(cert), lost, "unknown"),
        key_bits=_derive("key_bits", lambda: _key_bits_of(cert), lost, None),
        key_alg=_derive("key_alg", lambda: _key_alg(cert), lost, "unknown"),
        ocsp_urls=ocsp_urls,
        cdp_urls=_derive("cdp_urls", lambda: _cdp_urls(cert), lost, ()),
        aia_urls=aia_urls,
        unobtained=frozenset(lost),
    )


def parse_crl(der: bytes, *, tier: CrlTier | None, source: str) -> Crl:
    """Parse a DER CRL into :class:`Crl` (see :func:`parse_cert` for failures)."""
    try:
        crl = x509.load_der_x509_crl(der)
    except Exception as exc:  # noqa: BLE001 - any loader failure is an unloadable file
        raise UnparseableDer(f"{type(exc).__name__}: {exc}") from exc
    lost: set[str] = set()  # this_update / next_update: None is "not obtained"
    return Crl(
        issuer=_derive("issuer", lambda: crl.issuer.rfc4514_string(), lost, ""),
        this_update=_derive("this_update", lambda: crl.last_update_utc, lost, None),
        next_update=_derive("next_update", lambda: crl.next_update_utc, lost, None),
        tier=tier,
        source=source,
    )
