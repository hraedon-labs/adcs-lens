import importlib.util
from pathlib import Path
ROOT = Path("/home/itadmin/wt/scratch/sibling-review/adcs-chore-sibling-review-2026-10-09-ds")
spec = importlib.util.spec_from_file_location("tcr", ROOT/"tests"/"test_collector_readonly.py")
tcr = importlib.util.module_from_spec(spec); spec.loader.exec_module(tcr)
TEXT = tcr._collector_text(); OUT = ROOT/".review"/"tmp"/"probe_out"
cases = {
 "destructure-outpath": "$outPath, $junk = 'C:\\Windows\\Temp\\evil.json', 'x'\n[IO.File]::WriteAllText($outPath, 'y')",
 "paren-outpath": "($outPath) = 'C:\\Windows\\Temp\\evil.json'\n[IO.File]::WriteAllText($outPath, 'y')",
 "destructure-certdir": "$certDir, $junk = 'C:\\Windows\\Temp', 'x'\nNew-Item -ItemType Directory -Force -Path $certDir",
 "destructure-certfile": "$certFile, $junk = '..\\..\\evil.cer', 'x'\n[IO.File]::WriteAllBytes((Join-Path $certDir $certFile), $der)",
 "cast-target": "[string]$outPath = 'C:\\Windows\\Temp\\evil.json'\n[IO.File]::WriteAllText($outPath, 'y')",
 "destructure-script-scope": "$script:outPath, $junk = 'C:\\evil.json', 'x'",
 "destructure-swap": "$outPath, $junk = $junk, $outPath",
}
for n,s in cases.items():
    p = OUT/"collector-plus.ps1"; p.write_text(TEXT+"\n"+s+"\n", encoding="utf-8")
    d = tcr._dump(p); v = tcr.violations(d, p.read_text(encoding="utf-8"))
    got = [a["value"] for a in d["assignments"] if a["variable"] == "outPath"]
    print(("FLAGGED" if v else "BYPASS "), n, "| outPath-count:", got)
    if v: print("         ", v[0])
