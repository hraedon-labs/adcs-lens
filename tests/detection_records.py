"""Residual structural guard for detection.py's evaluation records.

Drift resolves a finding only on a positive evaluation record (``_evaluated``)
emitted by the detector, so anything that skips work BEFORE the record point —
a gate, an early ``return``, a ``filter``, a helper — merely leaves the object
unrecorded, and its older findings are withheld. That is safe by construction
and needs no analysis.

What remains is code AFTER the record point: there, a skip would leave an
object recorded as evaluated while it was not, and its finding could then be
reported resolved. This module finds every such construct:

* in each ``detect_*`` function, every node after the first ``_evaluated(...)``
  call; and
* in every helper that builds a *posture* finding (e.g. ``_expiry_finding``,
  ``_crl_finding``, called after the record point), its whole body;

and reports each condition (if / elif / while / ternary / comprehension
filter), each lambda, and each unconditional ``continue`` / ``break`` /
``return`` that is not the function's final statement, plus any rebinding of
``estate`` or non-append mutation of ``findings``. Conditions and lambdas must
be listed — reviewed as posture logic — in tests/test_detection_records.py;
the rest are violations outright.
"""

from __future__ import annotations

import ast
from collections import Counter


def _posture_builders(tree: ast.Module, notes: frozenset[str]) -> set[str]:
    out: set[str] = set()
    for fn in tree.body:
        if not isinstance(fn, ast.FunctionDef) or fn.name.startswith("detect_"):
            continue
        for node in ast.walk(fn):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "Finding"
            ):
                for kw in node.keywords:
                    if kw.arg == "check" and isinstance(kw.value, ast.Constant):
                        if kw.value.value not in notes:
                            out.add(fn.name)
    return out


def _notes(tree: ast.Module) -> frozenset[str]:
    for node in tree.body:
        target = node.target if isinstance(node, ast.AnnAssign) else None
        if isinstance(target, ast.Name) and target.id == "_DEGRADATION_NOTES":
            assert node.value is not None
            return frozenset(
                n.value for n in ast.walk(node.value)
                if isinstance(n, ast.Constant) and isinstance(n.value, str)
            )
    raise AssertionError("_DEGRADATION_NOTES not found")


def _builds_posture(node: ast.AST, notes: frozenset[str], builders: set[str]) -> bool:
    if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
        return False
    if node.func.id in builders:
        return True
    if node.func.id != "Finding":
        return False
    check = next((kw.value for kw in node.keywords if kw.arg == "check"), None)
    return not (isinstance(check, ast.Constant) and check.value in notes)


def _first_record_line(fn: ast.FunctionDef) -> int | None:
    lines = [
        n.lineno for n in ast.walk(fn)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "_evaluated"
    ]
    return min(lines) if lines else None


def _parents(fn: ast.FunctionDef) -> dict[ast.AST, ast.AST]:
    out: dict[ast.AST, ast.AST] = {}
    for node in ast.walk(fn):
        for child in ast.iter_child_nodes(node):
            out[child] = node
    return out


def analyse(source: str) -> tuple[Counter[tuple[str, str]], list[str]]:
    """(post-record conditions/lambdas by function, outright violations)."""
    tree = ast.parse(source)
    notes = _notes(tree)
    builders = _posture_builders(tree, notes)
    found: Counter[tuple[str, str]] = Counter()
    violations: list[str] = []
    for fn in tree.body:
        if not isinstance(fn, ast.FunctionDef):
            continue
        if fn.name.startswith("detect_"):
            start = _first_record_line(fn)
            if start is None:
                continue  # records nothing: everything it reports absent is withheld
        elif fn.name in builders:
            start = fn.lineno
        else:
            continue
        parents = _parents(fn)
        is_builder = fn.name in builders
        for node in ast.walk(fn):
            line = getattr(node, "lineno", 0)
            if not is_builder and line <= start:
                # Before the record point, only one thing is dangerous: building
                # a posture finding (then recording afterwards would vouch for
                # a loop whose skips the record never saw).
                if _builds_posture(node, notes, builders):
                    violations.append(
                        f"{fn.name}:{line}: posture finding built before the record point"
                    )
                continue
            tests: list[ast.expr] = []
            if isinstance(node, (ast.If, ast.IfExp, ast.While)):
                tests.append(node.test)
            if isinstance(node, ast.comprehension):
                tests.extend(node.ifs)
            for t in tests:
                found[(fn.name, ast.unparse(t))] += 1
            if isinstance(node, ast.Lambda):
                found[(fn.name, "lambda " + ast.unparse(node))] += 1
            if isinstance(node, (ast.Try, ast.Match)):
                violations.append(f"{fn.name}:{line}: {type(node).__name__} after the record point")
            if isinstance(node, (ast.Continue, ast.Break, ast.Return)):
                conditional = False
                p = parents.get(node)
                while p is not None and p is not fn:
                    if isinstance(p, (ast.If, ast.While)):
                        conditional = True
                        break
                    if isinstance(p, (ast.For, ast.comprehension)):
                        break
                    p = parents.get(p)
                final = (
                    isinstance(node, ast.Return)
                    and parents.get(node) is fn
                    and fn.body[-1] is node
                )
                if not conditional and not final:
                    violations.append(
                        f"{fn.name}:{line}: unconditional {type(node).__name__.lower()} "
                        "after the record point"
                    )
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for tgt in targets:
                    if isinstance(tgt, ast.Name) and tgt.id == "estate":
                        violations.append(f"{fn.name}:{line}: estate rebound")
                    if isinstance(tgt, ast.Name) and tgt.id == "findings":
                        value = node.value
                        if not (isinstance(value, ast.List) and not value.elts):
                            violations.append(f"{fn.name}:{line}: findings rebound")
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "findings"
                and node.func.attr not in ("append", "extend")
            ):
                violations.append(f"{fn.name}:{line}: findings.{node.func.attr}()")
            if isinstance(node, ast.Delete):
                violations.append(f"{fn.name}:{line}: del after the record point")
    return found, violations


def problems(source: str, expected: Counter[tuple[str, str]]) -> list[str]:
    found, violations = analyse(source)
    out = list(violations)
    for key, n in sorted((found - expected).items()):
        out.append(f"unclassified post-record construct in {key[0]}: {key[1]!r} (x{n})")
    for key, n in sorted((expected - found).items()):
        out.append(f"stale classified construct in {key[0]}: {key[1]!r} (x{n})")
    return out
