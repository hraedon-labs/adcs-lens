"""Run PowerShell from tests, tolerating pwsh runtime crashes.

pwsh 7.6.x intermittently dies with SIGSEGV (negative return code, empty
stdout/stderr) under load. That is a runtime crash, not a defect in the script
under test, so a command killed by a signal is re-run. Anything else (a normal
exit code, a timeout) is a real result and is never retried.
"""

from __future__ import annotations

import shutil
import signal
import subprocess
import warnings
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any


def _signal_name(returncode: int) -> str:
    try:
        return signal.Signals(-returncode).name
    except ValueError:
        return f"signal {-returncode}"


def run_pwsh(
    argv: Sequence[str],
    *,
    attempts: int = 3,
    out_dir: Path | None = None,
    cleanup: Callable[[], None] | None = None,
    **kwargs: Any,
) -> subprocess.CompletedProcess[Any]:
    """``subprocess.run(argv, **kwargs)``, re-run only when killed by a signal.

    Retries only when ``returncode < 0``, up to ``attempts`` runs in total.
    Never retries a positive exit code; ``subprocess.TimeoutExpired`` propagates
    immediately. Before each retry ``out_dir`` (the ``-OutDir`` the crashed run
    may have partly written) is removed and ``cleanup`` is called, so a partial
    tree can never be read as a result. A ``warnings.warn`` names each signal.
    If every attempt dies by signal, the last result is returned so the
    caller's assertion fails as it would have without the helper.
    """
    if attempts < 1:
        raise ValueError("attempts must be >= 1")
    proc = subprocess.run(argv, **kwargs)
    for attempt in range(1, attempts):
        if proc.returncode >= 0:
            break
        warnings.warn(
            f"pwsh killed by {_signal_name(proc.returncode)} "
            f"(attempt {attempt}/{attempts}); retrying",
            RuntimeWarning,
            stacklevel=2,
        )
        if out_dir is not None:
            shutil.rmtree(out_dir, ignore_errors=True)
        if cleanup is not None:
            cleanup()
        proc = subprocess.run(argv, **kwargs)
    return proc
