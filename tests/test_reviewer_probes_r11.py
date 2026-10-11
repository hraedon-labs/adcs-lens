"""Round-11 reviewer probes (Sol NEW BLOCKING 1, DeepSeek B1), replayed.

Kept free of round-12 test helpers so they run unchanged against older commits
(they fail at 2977888 and pass from the round-12 commit on).
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from adcs_lens.cli import main
from adcs_lens.detection import evaluate
from adcs_lens.ingest import ingest
from tests.conftest import NOW
from tests.test_diff_coverage import build_full_export

pytest.importorskip("cryptography")

_SHA256_RSA = bytes.fromhex("06092a864886f70d01010b")


@pytest.mark.parametrize(
    "unknown",
    ["06092a864886f70d01017f", "06092a864886f70d010163"],  # 1.2.840.113549.1.1.127 / .99
    ids=["sol-1.1.127", "deepseek-1.1.99"],
)
def test_r11_a_certificate_with_an_unknown_signature_oid_still_ingests(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], unknown: str
) -> None:
    """A structurally valid root certificate whose signature OID the library
    does not know raised UnsupportedAlgorithm through every command at 2977888
    (exit 1, a traceback). It ingests; only its signature algorithm is not
    obtained, so WEAK_SIG_ALG is undecided on it and nothing else changes."""
    seed = build_full_export(tmp_path / "seed")
    bad = tmp_path / "bad"
    shutil.copytree(seed, bad)
    path = bad / "certs" / "root.cer"
    der = path.read_bytes()
    assert der.count(_SHA256_RSA) == 2
    path.write_bytes(der.replace(_SHA256_RSA, bytes.fromhex(unknown)))
    for argv in (
        ["ingest", str(bad)],
        ["doctor", str(bad)],
        ["diff", str(seed), str(bad), "--exit-code"],
    ):
        capsys.readouterr()
        rc = main(argv)
        err = capsys.readouterr().err
        assert rc in (0, 1, 3) and "Traceback" not in err and "error:" not in err, (argv, rc)
    estate = ingest(bad)
    every = [c for ca in estate.cas for c in ca.certs] + [c for _, c in estate.unattached_certs]
    root = next(c for c in every if "LAB Root CA" in c.subject)
    assert root.unobtained == frozenset({"sig_alg"})
    weak_sig = [
        v
        for v in evaluate(estate, now=NOW).verdicts
        if v.check == "WEAK_SIG_ALG" and root.fingerprint in v.key
    ]
    assert weak_sig and all(v.state == "undecided" for v in weak_sig)
