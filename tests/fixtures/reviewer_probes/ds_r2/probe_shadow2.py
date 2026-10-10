#!/usr/bin/env python3
"""More collector-gate edges: $OutDir param shadow, command shadowing detail."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path("/home/itadmin/wt/scratch/sibling-review/adcs-chore-sibling-review-2026-10-09-ds")
OUT = ROOT / ".review" / "tmp" / "probe_out"
spec = importlib.util.spec_from_file_location("tcr", ROOT / "tests" / "test_collector_readonly.py")
tcr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tcr)
TEXT = tcr._collector_text()

CASES = {
    # A function param named $OutDir shadows the script parameter; _writeJson's
    # dynamic lookup then resolves $OutDir to the shadowed value.
    "fn-param-OutDir-writejson": (
        "function evil([string]$OutDir) { _writeJson @{} 'a.json' }\n"
        "evil 'C:\\Windows\\Temp'"
    ),
    # Same with a param named $outPath passed to New-Item/WriteAllText.
    "fn-param-outpath-newitem-parent": (
        "function evil([string]$outPath) { "
        "New-Item -ItemType Directory -Force -Path $outPath }\n"
        "evil 'C:\\Windows\\Temp'"
    ),
    # Scriptblock param shadow inside ForEach-Object, fed by pipeline var.
    "sb-param-certdir-pipeline": (
        "$evilDirs | ForEach-Object { param($certDir) "
        "New-Item -ItemType Directory -Force -Path $certDir }"
    ),
    # Command-name shadowing of an allowlisted cmdlet, called with positional args.
    "shadow-certutil-positional": (
        "function certutil { [IO.File]::WriteAllText((Join-Path $OutDir $outName), 'x') }\n"
        "certutil -getreg x"
    ),
    # Shadow Join-Path and use it as a write target derivation.
    "shadow-joinpath-write": (
        "function Join-Path { 'C:\\Windows\\Temp\\evil.json' }\n"
        "$q = Join-Path $OutDir $outName\n[IO.File]::WriteAllText($q, 'x')"
    ),
    # Write target via a global alias variable already used by collector.
    "writeallbytes-alt-certfile": (
        "[IO.File]::WriteAllBytes((Join-Path $certDir '..\\..\\evil.cer'), $der)"
    ),
    # New-Item -Path with a variable derived by indirection.
    "new-item-indirect-path": "$d = $OutDir\nNew-Item -ItemType Directory -Force -Path $d",
    # _writeJson name as a variable holding a scriptblock.
    "writejson-via-amp": "$f = { [IO.File]::WriteAllText('C:\\evil','x') }\n& $f",
}


def main() -> int:
    for name, snip in CASES.items():
        p = OUT / "collector-plus.ps1"
        p.write_text(TEXT + "\n" + snip + "\n", encoding="utf-8")
        d = tcr._dump(p)
        v = tcr.violations(d, p.read_text(encoding="utf-8"))
        print(("FLAGGED" if v else "BYPASS "), name)
        for line in v:
            print("         ", line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
