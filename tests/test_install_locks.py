"""The Windows installer's hash-locked requirement files match uv.lock.

scripts/install-windows.ps1 installs third-party wheels with
``pip install --require-hashes`` from files exported from uv.lock, then adcs-lens
itself with ``--no-deps``. These tests fail when a lock file drifts from uv.lock
(regenerate with the commands in docs/install.md) or the installer stops using them.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
LOCKS = ROOT / "scripts" / "locks"
INSTALLER = ROOT / "scripts" / "install-windows.ps1"

EXPORTS = {
    "requirements-certs.lock.txt": ["--extra", "certs", "--no-dev"],
    "requirements-build.lock.txt": ["--only-group", "build"],
}


def _uv() -> str:
    uv = shutil.which("uv")
    if uv is None:
        if os.environ.get("CI"):
            pytest.fail("uv is required in CI to check the installer lock files")
        pytest.skip("uv not installed")
    return uv


@pytest.mark.parametrize("name", sorted(EXPORTS))
def test_installer_lock_matches_uv_lock(tmp_path: Path, name: str) -> None:
    exported = tmp_path / name
    subprocess.run(
        [
            _uv(),
            "export",
            "--locked",
            *EXPORTS[name],
            "--no-emit-project",
            "--no-header",
            "--format",
            "requirements-txt",
            "-o",
            str(exported),
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        timeout=120,
    )
    assert exported.read_bytes() == (LOCKS / name).read_bytes(), (
        f"scripts/locks/{name} is out of date with uv.lock; regenerate it (docs/install.md)"
    )


@pytest.mark.parametrize("name", sorted(EXPORTS))
def test_every_locked_requirement_carries_hashes(name: str) -> None:
    lines = (LOCKS / name).read_text(encoding="utf-8").splitlines()
    pins = [i for i, line in enumerate(lines) if line and not line.startswith((" ", "#"))]
    assert pins
    for i in pins:
        assert "==" in lines[i], lines[i]  # exact pins only
        # --require-hashes refuses a requirement without a hash; so does this check.
        assert lines[i + 1].strip().startswith("--hash=sha256:"), lines[i]


def test_build_group_mirrors_the_build_backend_requirement() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert project["dependency-groups"]["build"] == project["build-system"]["requires"]


def test_installer_installs_from_the_locks_without_resolving() -> None:
    installer = INSTALLER.read_text(encoding="utf-8")
    assert "pip install --require-hashes -r $buildLock" in installer
    assert "pip install --require-hashes -r $certsLock" in installer
    assert "pip install --upgrade --no-build-isolation --no-deps $repoRoot" in installer
    # No unlocked install of the package or its extras remains.
    assert "pip install --upgrade $pkg" not in installer
    assert '"$repoRoot[certs]"' not in installer
    # The build backend is installed before the package that needs it, and the
    # [certs] lock is skipped (the core has no other dependencies) under -NoCerts.
    build = installer.index("pip install --require-hashes -r $buildLock")
    certs = installer.index("pip install --require-hashes -r $certsLock")
    package = installer.index("--no-build-isolation --no-deps $repoRoot")
    assert build < certs < package
    skip_if_no_certs = installer.replace("\r\n", "\n").splitlines()
    certs_line = next(n for n, line in enumerate(skip_if_no_certs) if "-r $certsLock" in line)
    assert skip_if_no_certs[certs_line - 1].strip() == "if (-not $NoCerts) {"
