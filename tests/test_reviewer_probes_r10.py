"""Round-10 reviewer probes, replayed.

Kept free of round-11 test helpers so they run unchanged against older commits
(both fail at c66f4d2 and pass from the round-11 commit on).
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

_ROOT = Path(__file__).resolve().parent.parent
_SIMULATE = _ROOT / "tests" / "collector" / "simulate.ps1"
_COLLECTOR = _ROOT / "scripts" / "Export-AdcsEstate.ps1"
_PWSH = shutil.which("pwsh")


def _write_der(directory: Path, *, fresh: bool) -> None:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.x509.oid import NameOID

    now = datetime.now(UTC)
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "LAB Root CA")])
    root = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=365))
        .not_valid_after(now + timedelta(days=3650))
        .sign(root_key, hashes.SHA256())
    )
    partner_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    partner = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "LAB Partner Root")])
    cross = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(partner)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=30))
        .not_valid_after(now + timedelta(days=1825))
        .sign(partner_key, hashes.SHA256())
    )
    last, nxt = (
        (now - timedelta(days=1), now + timedelta(days=89))
        if fresh
        else (
            now - timedelta(days=89),
            now + timedelta(days=1),
        )
    )
    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(root_name)
        .last_update(last)
        .next_update(nxt)
        .sign(root_key, hashes.SHA256())
    )
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "root.cer").write_bytes(root.public_bytes(Encoding.DER))
    (directory / "cross.cer").write_bytes(cross.public_bytes(Encoding.DER))
    (directory / "root.crl").write_bytes(crl.public_bytes(Encoding.DER))


def _simulate(script: Path, out: Path, der: Path, *extra: str) -> Path:
    assert _PWSH is not None
    proc = subprocess.run(
        [_PWSH, "-NoProfile", "-NonInteractive", "-File", str(script), "-OutDir", str(out)]
        + ["-DerDir", str(der), *extra],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return out


@pytest.mark.skipif(_PWSH is None, reason="pwsh is not installed")
def test_sol_r10_a_unicode_case_fold_twin_makes_the_crl_tier_unknown(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Sol round 10 NEW BLOCKING 1 (.review/probe_casefold_r10.py).

    AIA holds "Straße Root CA" (the self-signed root) and "STRASSE Root CA" (a
    cross-certificate); the CDP object is "Straße Root CA". Under Unicode case
    folding the two AIA names are one, so the tier source is ambiguous. At
    c66f4d2 the collector folded with ToLowerInvariant (no ß -> ss), wrote
    tier root, and diff resolved the older in-window CRL finding (exit 0). The
    collector no longer folds anything: ingest decides, the tier is not
    obtained, and the older finding is withheld (exit 3).
    """
    pytest.importorskip("cryptography")
    source = _SIMULATE.read_text(encoding="utf-8")
    for old, new in (
        ("Join-Path $PSScriptRoot '../../scripts/Export-AdcsEstate.ps1'", f"'{_COLLECTOR}'"),
        ("@{ cn = @('LAB Root CA'); cacertificate", "@{ cn = @('Straße Root CA'); cacertificate"),
        ("@{ cn = @('LAB Root CA'); objectguid", "@{ cn = @('Straße Root CA'); objectguid"),
        ("$twin = @{ cn = @('lab root ca');", "$twin = @{ cn = @('STRASSE Root CA');"),
    ):
        assert old in source, f"simulator layout changed: {old}"
        source = source.replace(old, new)
    script = tmp_path / "simulate-casefold.ps1"
    script.write_text(source, encoding="utf-8-sig")
    old_der, new_der = tmp_path / "old-der", tmp_path / "new-der"
    _write_der(old_der, fresh=False)
    _write_der(new_der, fresh=True)
    old = _simulate(script, tmp_path / "old", old_der)
    new = _simulate(script, tmp_path / "new", new_der, "-Ambiguous", "crl-tier")
    assert [c.tier for c in ingest(new).crls] == [None]
    capsys.readouterr()
    rc = main(["diff", str(old), str(new), "--exit-code", "--json"])
    env = json.loads(capsys.readouterr().out)
    assert "CRL_EXPIRY" not in {f["check"] for f in env["resolved"]}
    assert "CRL_EXPIRY" in {i["check"] for i in env["indeterminate"]}
    assert rc == 3


@pytest.mark.parametrize("command", ["ingest", "doctor", "diff"])
def test_sol_r10_invalid_utf8_is_exit_4_not_a_traceback(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], command: str
) -> None:
    """Sol round 10 NEW BLOCKING 2: a manifest that is not valid UTF-8 raised
    UnicodeDecodeError through every command (exit 1, a traceback)."""
    export = tmp_path / "invalid-utf8"
    export.mkdir()
    (export / "collector-manifest.json").write_bytes(b"\xff")
    argv = {
        "ingest": ["ingest", str(export)],
        "doctor": ["doctor", str(export)],
        "diff": ["diff", str(export), str(export), "--exit-code"],
    }[command]
    capsys.readouterr()
    assert main(argv) == 4
    err = capsys.readouterr().err
    assert err.startswith("error:") and len(err.strip().splitlines()) == 1
