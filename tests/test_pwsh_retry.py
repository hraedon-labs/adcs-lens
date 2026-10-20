"""Unit tests for tests/_pwsh.run_pwsh, using a fake command instead of pwsh."""

from __future__ import annotations

import subprocess
import sys
import warnings
from collections.abc import Callable
from pathlib import Path

import pytest

from tests._pwsh import run_pwsh

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX signal semantics")

# argv: counter file, out dir, number of leading SIGSEGV deaths, exit code after.
# A leftover file in the out dir from an earlier attempt makes it exit 99.
_FAKE = """
import os, signal, sys
from pathlib import Path
counter, out = Path(sys.argv[1]), Path(sys.argv[2])
crashes, code = int(sys.argv[3]), int(sys.argv[4])
n = int(counter.read_text()) if counter.exists() else 0
counter.write_text(str(n + 1))
if out.exists() and any(out.iterdir()):
    print("STALE", file=sys.stderr)
    sys.exit(99)
out.mkdir(exist_ok=True)
(out / "partial.json").write_text("{")
if n < crashes:
    os.kill(os.getpid(), signal.SIGSEGV)
sys.exit(code)
"""


def _run(
    tmp_path: Path,
    crashes: int,
    code: int = 0,
    cleanup: Callable[[], None] | None = None,
) -> tuple[subprocess.CompletedProcess[str], int]:
    script = tmp_path / "fake.py"
    script.write_text(_FAKE)
    counter = tmp_path / "count"
    out = tmp_path / "out"
    proc = run_pwsh(
        [sys.executable, str(script), str(counter), str(out), str(crashes), str(code)],
        out_dir=out,
        cleanup=cleanup,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    return proc, int(counter.read_text())


def test_succeeds_first_time_without_warning(tmp_path: Path) -> None:
    with warnings.catch_warnings(record=True) as rec:
        warnings.simplefilter("always")
        proc, attempts = _run(tmp_path, crashes=0)
    assert (proc.returncode, attempts, len(rec)) == (0, 1, 0)


def test_retries_on_signal_then_stops_on_success(tmp_path: Path) -> None:
    with pytest.warns(RuntimeWarning, match="SIGSEGV") as rec:
        proc, attempts = _run(tmp_path, crashes=2)
    assert (proc.returncode, attempts, len(rec)) == (0, 3, 2)
    assert proc.stderr == ""  # out dir was wiped between attempts (else exit 99)


def test_does_not_retry_a_positive_exit_code(tmp_path: Path) -> None:
    proc, attempts = _run(tmp_path, crashes=0, code=1)
    assert (proc.returncode, attempts) == (1, 1)


def test_gives_up_after_three_and_returns_the_signal_result(tmp_path: Path) -> None:
    with pytest.warns(RuntimeWarning):
        proc, attempts = _run(tmp_path, crashes=10)
    assert (proc.returncode, attempts) == (-11, 3)


def test_cleanup_callable_runs_before_each_retry(tmp_path: Path) -> None:
    calls: list[int] = []
    with pytest.warns(RuntimeWarning):
        proc, attempts = _run(tmp_path, crashes=1, cleanup=lambda: calls.append(1))
    assert (proc.returncode, attempts, len(calls)) == (0, 2, 1)


def test_timeout_is_not_retried(tmp_path: Path) -> None:
    script = tmp_path / "sleep.py"
    script.write_text("import time; time.sleep(30)")
    with pytest.raises(subprocess.TimeoutExpired):
        run_pwsh([sys.executable, str(script)], timeout=1)
