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

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID

from adcs_lens.model import CertKind, CertLifecycle, Crl, CrlTier


def _key_bits(cert: x509.Certificate) -> int | None:
    pub = cert.public_key()
    if isinstance(pub, (rsa.RSAPublicKey, dsa.DSAPublicKey)):
        return pub.key_size
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return pub.curve.key_size
    return None


def _sig_alg(cert: x509.Certificate) -> str:
    algo = cert.signature_hash_algorithm
    name = algo.name if isinstance(algo, hashes.HashAlgorithm) else "unknown"
    return name.lower()


def _key_alg(cert: x509.Certificate) -> str:
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        return "rsa"
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return "ecdsa"
    if isinstance(pub, dsa.DSAPublicKey):
        return "dsa"
    return "unknown"


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
    """Parse a DER certificate into :class:`CertLifecycle`."""
    cert = x509.load_der_x509_certificate(der)
    ocsp_urls, aia_urls = _aia_urls(cert)
    return CertLifecycle(
        fingerprint=hashlib.sha256(der).hexdigest(),
        subject=cert.subject.rfc4514_string(),
        kind=kind,
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
        sig_alg=_sig_alg(cert),
        key_bits=_key_bits(cert),
        key_alg=_key_alg(cert),
        ocsp_urls=ocsp_urls,
        cdp_urls=_cdp_urls(cert),
        aia_urls=aia_urls,
    )


def parse_crl(der: bytes, *, tier: CrlTier | None, source: str) -> Crl:
    """Parse a DER CRL into :class:`Crl`."""
    crl = x509.load_der_x509_crl(der)
    return Crl(
        issuer=crl.issuer.rfc4514_string(),
        this_update=crl.last_update_utc,
        next_update=crl.next_update_utc,
        tier=tier,
        source=source,
    )
