import importlib.util
from pathlib import Path
ROOT = Path("/home/itadmin/wt/scratch/sibling-review/adcs-chore-sibling-review-2026-10-09-ds")
spec = importlib.util.spec_from_file_location("tcr", ROOT/"tests"/"test_collector_readonly.py")
tcr = importlib.util.module_from_spec(spec); spec.loader.exec_module(tcr)
TEXT = tcr._collector_text(); OUT = ROOT/".review"/"tmp"/"probe_out"
cases = {
 "adsi-commit": "[adsi]'LDAP://x'.CommitChanges()",
 "adsi-put": "[adsi]'LDAP://x'.Put('a','b')",
 "wmi-accel-set": "[wmi]$x.SetDWORDValue(1,'k','v',1)",
 "xml-type": "$x = [xml]'<a/>'",
 "regex-type": "$x = [regex]'a'",
 "ordered-type": "$x = [ordered]@{a=1}",
 "byte-array": "$x = [byte[]]@(1)",
 "char-type": "$x = [char]65",
 "datetime-type": "$x = [datetime]::UtcNow",
 "guid-type": "$x = [guid]::NewGuid()",
 "convert-parse": "[int]'5'",
 "text-encoding": "[Text.Encoding]::ASCII",
 "file-accel-write": "[File]::WriteAllText('C:\\evil','x')",
 "io-file-ok": "[IO.File]::WriteAllText($outPath,'x')",
}
for n,s in cases.items():
    p = OUT/"collector-plus.ps1"; p.write_text(TEXT+"\n"+s+"\n", encoding="utf-8")
    d = tcr._dump(p); v = tcr.violations(d, p.read_text(encoding="utf-8"))
    print(("FLAGGED" if v else "BYPASS "), n, "" if not v else v[0].split(": ",1)[-1])
