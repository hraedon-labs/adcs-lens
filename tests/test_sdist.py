"""The sdist is self-sufficient: its own test suite collects and runs.

Builds the sdist exactly as release.yml does (locked hatchling,
--no-isolation), extracts it, collects every test from the extracted tree and
runs the tests that read repository files (scripts, workflows, metadata). A
file the tests need but the explicit include list omits fails here.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
_FILE_READING_TESTS = [
    "tests/test_action_pins.py",
    "tests/test_release_identity.py",
    "tests/test_metadata_drift.py",
    "tests/test_input_limits.py",
    "tests/test_architecture.py",
    "tests/test_check_identifiers.py",
]


def _require_build_tools() -> None:
    try:
        import build  # noqa: F401
        import hatchling  # noqa: F401
    except ImportError:
        if os.environ.get("CI"):
            pytest.fail("build + hatchling (uv sync --group release) are required in CI")
        pytest.skip("release build tools not installed (uv sync --group release)")


def test_sdist_runs_its_own_tests(tmp_path: Path) -> None:
    _require_build_tools()
    dist = tmp_path / "dist"
    subprocess.run(
        [sys.executable, "-m", "build", "--sdist", "--no-isolation", "--outdir", str(dist)],
        cwd=ROOT, check=True, capture_output=True, timeout=300,
    )
    (sdist,) = dist.glob("adcs_lens-*.tar.gz")
    with tarfile.open(sdist) as tf:
        tf.extractall(tmp_path / "x", filter="data")
    (tree,) = (tmp_path / "x").iterdir()
    env = {**os.environ, "PYTHONPATH": str(tree / "src")}
    base = [sys.executable, "-m", "pytest", "-q", "-o", "addopts=", "-p", "no:cacheprovider",
            "--basetemp", str(tmp_path / "pt")]
    collect = subprocess.run([*base, "--collect-only", "tests"], cwd=tree, env=env,
                             capture_output=True, text=True, timeout=300)
    assert collect.returncode == 0, collect.stdout[-3000:] + collect.stderr[-2000:]
    run = subprocess.run([*base, *_FILE_READING_TESTS], cwd=tree, env=env,
                         capture_output=True, text=True, timeout=600)
    assert run.returncode == 0, run.stdout[-3000:] + run.stderr[-2000:]
