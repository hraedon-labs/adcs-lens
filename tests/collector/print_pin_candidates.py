"""Print CANDIDATE values for the gate's hand-maintained pin tables.

    .venv/bin/python tests/collector/print_pin_candidates.py [--collector PATH]

For rebuilding the tables after a deliberate, reviewed collector change (e.g. a
new collector version). It only prints to stdout; it never writes any file, and
tests/collector/regen_inventory.py never calls it. The printed values describe
what the collector DOES, not what it SHOULD do: a person must read every entry
(each write root, receiver, guarded operation with its guards, constructor,
.NET call and helper body digest) before pasting it into
tests/test_collector_readonly.py. Pasting without reading defeats the gate.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from tests.test_collector_readonly import (  # noqa: E402
    ALLOWED_INSTANCE,
    COLLECTOR,
    _bindings_by_var,
    _dump,
    _function_body_digests,
    _guarded_ops,
    _member_call_key,
    _required_vars,
    _secret_closure,
    _secret_uses,
)


def render(collector: Path) -> str:
    d = _dump(collector)
    lines: list[str] = []
    receivers: dict[str, set[str]] = {}
    for m in d["members"]:
        if not m["static"] and m["member"] in ALLOWED_INSTANCE:
            receivers.setdefault(m["member"], set()).add(m["receiver_root"] or "")
    lines.append("INSTANCE_RECEIVERS: dict[str, frozenset[str]] = {")
    lines += [f"    {k!r}: frozenset({sorted(v)!r})," for k, v in sorted(receivers.items())]
    lines.append("}")
    required = _required_vars(d)
    bindings = _bindings_by_var(d)
    lines.append("PINNED_BINDINGS: dict[str, list[tuple[str, str]]] = {")
    for key in sorted(required):
        lines.append(f"    # {required[key]}")
        items = sorted(bindings.get(key, []))
        lines.append(f"    {key!r}: [" + ("" if items else "],"))
        if items:
            lines += [f"        {it!r}," for it in items]
            lines.append("    ],")
    lines.append("}")
    lines.append("GUARDED_OPS: tuple[tuple[str, tuple[str, ...]], ...] = (")
    lines += [f"    ({op!r}, {ctx!r})," for op, ctx in _guarded_ops(d)]
    lines.append(")")
    lines.append("PINNED_MEMBER_CALLS: tuple[tuple[str, ...], ...] = (")
    lines += [f"    {k!r}," for k in sorted(_member_call_key(m) for m in d["members"])]
    lines.append(")")
    lines.append("LOCAL_FUNCTION_BODIES: dict[str, str] = {")
    lines += [f"    {k!r}: {v!r}," for k, v in _function_body_digests(d).items()]
    lines.append("}")
    secret = _secret_closure(d)
    lines.append("SECRET_VARIABLES: frozenset[str] = frozenset(")
    lines.append("    {")
    lines += [f"        {k!r}," for k in sorted(secret)]
    lines.append("    }")
    lines.append(")")
    lines.append("SECRET_USES: dict[str, list[tuple[str, str]]] = {")
    for key, uses in sorted(_secret_uses(d, secret).items()):
        lines.append(f"    {key!r}: [")
        lines += [f"        {u!r}," for u in sorted(uses)]
        lines.append("    ],")
    lines.append("}")
    lines.append(f"HEADER_SHA256 = {d['header_sha256']!r}")
    lines.append("LOCAL_FUNCTIONS: tuple[str, ...] = (")
    lines += [f"    {f['name']!r}," for f in d["functions"]]
    lines.append(")")
    lines.append("# New-Object argument vectors (for NEW_OBJECT_VECTORS):")
    for c in d["commands"]:
        if (c["name"] or "").lower() == "new-object":
            lines.append(f"#   {tuple(c['args'])!r}")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--collector", type=Path, default=COLLECTOR)
    args = parser.parse_args(argv)
    sys.stdout.write(render(args.collector))
    return 0


if __name__ == "__main__":
    sys.exit(main())
