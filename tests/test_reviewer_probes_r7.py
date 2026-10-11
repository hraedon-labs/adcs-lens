"""Round-7 reviewer probe, replayed with the real collector body.

Kept free of round-8 test helpers so it runs unchanged against older commits
(it fails at 2ba72dd and passes from the round-8 commit on).
"""

from __future__ import annotations

import json
import shutil
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from adcs_lens.cli import main
from adcs_lens.ingest import ingest

_SIMULATE = Path(__file__).resolve().parent / "collector" / "simulate.ps1"
_PWSH = shutil.which("pwsh")
pytestmark = pytest.mark.skipif(_PWSH is None, reason="pwsh is not installed")


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


def _root_cert_and_crl_in_warning_window(directory: Path) -> None:
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
        .last_update(now - timedelta(days=89))
        .next_update(now + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "root.cer").write_bytes(cert.public_bytes(Encoding.DER))
    (directory / "root.crl").write_bytes(crl.public_bytes(Encoding.DER))


def test_sol_r7_partial_aia_read_does_not_improve_a_root_crl(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Sol round 7 NEW BLOCKING 1 (.review/probe_crl_tier_r7.py), replayed.

    Both exports carry the same root CRL inside its early-warning window. In the
    newer one the root's AIA object fails (no cn). At 2ba72dd the collector
    defaulted the CRL's tier to 'issuing' under a complete crls marker,
    CRL_EXPIRY declared only the CRL container, and diff reported a verified
    critical -> high change. Now the tier is null (not obtained), CRL_EXPIRY
    depends on the AIA container, and the older finding is withheld.
    """
    pytest.importorskip("cryptography")
    der = tmp_path / "der"
    _root_cert_and_crl_in_warning_window(der)
    old = _simulate(tmp_path / "old", "-DerDir", str(der))
    new = _simulate(tmp_path / "new", "-DerDir", str(der), "-Omit", "certs:cn:missing")
    assert [c.tier for c in ingest(new).crls] == [None]
    capsys.readouterr()
    rc = main(["diff", str(old), str(new), "--exit-code", "--json"])
    env = json.loads(capsys.readouterr().out)
    assert not [c for c in env["changed"] if c["old_severity"] != c["new_severity"]]
    assert env["new"] == [] and env["resolved"] == []
    assert "CRL_EXPIRY" in {i["check"] for i in env["indeterminate"]}
    assert env["summary"]["coverage_lost"] is True
    assert rc == 3
