"""Structural analysis of detection.py's conditions (shared by the guard tests).

Every condition in detection.py — each ``if`` / ``elif`` / ``while`` / ternary
test and each comprehension filter, in every module-level function except the
coverage predicates themselves and ``coverage_gaps`` — is either:

* a COVERAGE condition: it calls a function registered in
  ``detection.COVERAGE_PREDICATES``, and every such predicate must also be
  consulted by ``coverage_gaps`` (so the drift coverage map cannot miss a skip
  the detectors make), or
* a POSTURE condition: vulnerability logic, finding-text branching, or type
  narrowing, explicitly listed in tests/test_detection_conditions.py.

A new or edited condition matches neither until someone classifies it. That
is the point: a new skip path (``if not ca.dns: continue``) cannot land
silently — it must either become a registered predicate with a coverage gap,
or be listed, in review, as posture logic.
"""

from __future__ import annotations

import ast
from collections import Counter
from dataclasses import dataclass

_EXCLUDED = {"coverage_gaps", "_object_gap"}


@dataclass(frozen=True)
class Analysis:
    posture: Counter[tuple[str, str]]
    predicates_in_conditions: frozenset[str]
    predicates_in_coverage_gaps: frozenset[str]
    registered: frozenset[str]
    defined_functions: frozenset[str]
    forbidden_nodes: tuple[str, ...]


def _registered(tree: ast.Module) -> frozenset[str]:
    for node in tree.body:
        target = node.target if isinstance(node, ast.AnnAssign) else None
        if isinstance(target, ast.Name) and target.id == "COVERAGE_PREDICATES":
            assert node.value is not None
            return frozenset(
                n.value for n in ast.walk(node.value)
                if isinstance(n, ast.Constant) and isinstance(n.value, str)
            )
    raise AssertionError("COVERAGE_PREDICATES not found")


def _called_names(node: ast.AST) -> set[str]:
    return {
        c.func.id for c in ast.walk(node)
        if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)
    }


def analyse(source: str) -> Analysis:
    tree = ast.parse(source)
    registered = _registered(tree)
    functions = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}
    posture: Counter[tuple[str, str]] = Counter()
    used: set[str] = set()
    forbidden: list[str] = []
    for name, fn in functions.items():
        if name in registered or name in _EXCLUDED:
            continue
        for node in ast.walk(fn):
            if isinstance(node, (ast.Try, ast.Match)):
                # An except/match arm is a skip path no condition analysis sees.
                forbidden.append(f"{name}: {type(node).__name__}")
            tests: list[ast.expr] = []
            if isinstance(node, (ast.If, ast.IfExp, ast.While)):
                tests.append(node.test)
            if isinstance(node, ast.comprehension):
                tests.extend(node.ifs)
            for test in tests:
                hits = _called_names(test) & registered
                if hits:
                    used |= hits
                else:
                    posture[(name, ast.unparse(test))] += 1
    gaps_fn = functions["coverage_gaps"]
    return Analysis(
        posture=posture,
        predicates_in_conditions=frozenset(used),
        predicates_in_coverage_gaps=frozenset(_called_names(gaps_fn) & registered),
        registered=registered,
        defined_functions=frozenset(functions),
        forbidden_nodes=tuple(forbidden),
    )


def problems(source: str, expected_posture: Counter[tuple[str, str]]) -> list[str]:
    """Everything wrong with *source* against the classified table (empty = ok)."""
    a = analyse(source)
    out: list[str] = []
    for key, n in sorted((a.posture - expected_posture).items()):
        out.append(f"unclassified condition in {key[0]}: {key[1]!r} (x{n})")
    for key, n in sorted((expected_posture - a.posture).items()):
        out.append(f"stale classified condition in {key[0]}: {key[1]!r} (x{n})")
    for pred in sorted(a.predicates_in_conditions - a.predicates_in_coverage_gaps):
        out.append(f"coverage predicate {pred} skips a detector but coverage_gaps never uses it")
    for pred in sorted(a.registered - a.defined_functions):
        out.append(f"registered coverage predicate {pred} is not defined")
    for pred in sorted(a.registered - a.predicates_in_coverage_gaps):
        out.append(f"registered coverage predicate {pred} is not used by coverage_gaps")
    out.extend(f"forbidden construct {f}" for f in a.forbidden_nodes)
    return out
