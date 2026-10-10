#!/usr/bin/env python3
"""Probe: function/scriptblock *parameters* that shadow write-target names."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path("/home/itadmin/wt/scratch/sibling-review/adcs-chore-sibling-review-2026-10-09-ds")
OUT = ROOT / ".review" / "tmp" / "probe_out"
OUT.mkdir(parents=True, exist_ok=True)

spec = importlib.util.spec_from_file_location("tcr", ROOT / "tests" / "test_collector_readonly.py")
tcr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tcr)
TEXT = tcr._collector_text()


def check(snippet: str):
    p = OUT / "collector-plus.ps1"
    p.write_text(TEXT + "\n" + snippet + "\n", encoding="utf-8")
    dump = tcr._dump(p)
    v = tcr.violations(dump, p.read_text(encoding="utf-8"))
    return v, dump


CASES = {
    "fn-param-outpath": (
        "function evil([string]$outPath) { [IO.File]::WriteAllText($outPath, 'x') }\n"
        "evil 'C:\\Windows\\Temp\\evil.json'"
    ),
    "fn-param-outpath-default": (
        "function evil { param([string]$outPath='C:\\Windows\\Temp\\evil.json') "
        "[IO.File]::WriteAllText($outPath, 'x') }\nevil"
    ),
    "fn-param-certdir": (
        "function evil([string]$certDir) { New-Item -ItemType Directory -Force -Path $certDir }\n"
        "evil 'C:\\Windows\\Temp'"
    ),
    "fn-param-certfile": (
        "function evil([string]$certFile) { "
        "[IO.File]::WriteAllBytes((Join-Path $certDir $certFile), $der) }\n"
        "evil '..\\..\\evil.cer'"
    ),
    "fn-param-certdir-joinpath": (
        "function evil([string]$certDir) { "
        "[IO.File]::WriteAllBytes((Join-Path $certDir $certFile), $der) }\n"
        "evil 'C:\\Windows\\Temp'"
    ),
    "fn-param-outname-writejson-ok": (
        "function evil([string]$outName) { _writeJson @{} $outName }\nevil 'a.json'"
    ),
    "fn-param-null": (
        "function evil([string]$null) { [IO.File]::WriteAllText($null, 'x') }\n"
        "evil 'C:\\Windows\\Temp\\evil.json'"
    ),
    "fn-param-certfile-plus-outpath": (
        "function evil([string]$outPath) { [IO.File]::WriteAllText($outPath, 'x') }\n"
        "evil 'C:\\Windows\\Temp\\evil.json'\n"
        "Write-Output 'done'"
    ),
    "sb-param-outpath-foreach": (
        "1..2 | ForEach-Object { param($outPath) [IO.File]::WriteAllText($outPath,'x') }"
    ),
    "fn-param-outpath-call-name": (
        "function evil([string]$outPath) { [IO.File]::WriteAllText($outPath, 'x') }\n"
        "evil -outPath 'C:\\Windows\\Temp\\evil.json'"
    ),
    "fn-param-outpath-splat": (
        "function evil([string]$outPath) { [IO.File]::WriteAllText($outPath, 'x') }\n"
        "evil @{ outPath = 'C:\\Windows\\Temp\\evil.json' }"
    ),
    "fn-param-outpath-pipeline": (
        "function evil([string]$outPath) { [IO.File]::WriteAllText($outPath, 'x') }\n"
        "'C:\\Windows\\Temp\\evil.json' | evil"
    ),
}


def main() -> int:
    for name, snip in CASES.items():
        v, dump = check(snip)
        status = "FLAGGED" if v else "BYPASS "
        print(f"{status} {name}")
        if v:
            for line in v:
                print("         ", line)
        else:
            print("          params:", sorted(set(dump["parameters"])))
            print("          assignments outPath:", [a["value"] for a in dump["assignments"] if a["variable"] == "outPath"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
