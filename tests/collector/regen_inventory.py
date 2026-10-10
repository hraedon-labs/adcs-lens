"""Regenerate tests/collector/collector-inventory.json from the collector.

    .venv/bin/python tests/collector/regen_inventory.py

Refuses to write unless every semantic check of the read-only gate passes on
the current scripts/Export-AdcsEstate.ps1 — the inventory can only ever pin a
collector the gate accepts. Review the resulting diff like code.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from tests.test_collector_readonly import (  # noqa: E402
    COLLECTOR,
    INVENTORY,
    _dump,
    render_inventory,
    violations,
)


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--collector", type=Path, default=COLLECTOR)
    parser.add_argument("--out", type=Path, default=INVENTORY)
    args = parser.parse_args(argv)
    dump = _dump(args.collector)
    found = violations(dump)
    if found:
        print("refusing to write the inventory; semantic violations:", file=sys.stderr)
        for v in found:
            print(f"  {v}", file=sys.stderr)
        return 1
    args.out.write_text(render_inventory(dump), encoding="utf-8")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
