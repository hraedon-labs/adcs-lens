"""Residual structural guard for detection.py's evaluation records.

Drift resolves a finding only on a positive evaluation record (``_evaluated``)
emitted by the detector, so anything that skips work BEFORE the record point —
a gate, an early ``return``, a ``filter``, a helper — merely leaves the object
unrecorded, and its older findings are withheld. That is safe by construction
and needs no analysis.

What remains is code AFTER the record point: there, a skip — or a wrong VALUE —
would leave an object recorded as evaluated while it was not, and its finding
could then be reported resolved. The analysed regions are:

* in each ``detect_*`` function, every node after the first ``_evaluated(...)``
  call; and
* in every helper that builds a *posture* finding (e.g. ``_expiry_finding``,
  ``_crl_finding``), its whole body; and
* in every helper DEFINED in detection.py that is *called after a record point*
  (``_low_priv_enrollers`` and, transitively, what it calls): its whole body.

Records alone cannot see a wrong value (a helper that still runs but returns
nothing looks exactly like a clean object), and no runtime check can tell an
honestly empty helper result from a fabricated one without recomputing it. So
the guard is static, and strict: it pins what it reviews and refuses what it
cannot prove.

**Pinned (classified in tests/test_detection_records.py; a change must be
re-reviewed):** each condition (if / elif / while / ternary / comprehension
filter), each lambda, and each *evidence flow* — every call to a value-returning
detection.py function together with the expression that consumes it (the
statement, the keyword argument, or the f-string field), including its exact
arguments; every binding the verdict reads (traced back from conditions, loop
iterables, evidence arguments and helper return values); and every return of a
whole-body helper (``Finding(...)`` bodies elided — presentation is not pinned).
A helper that stops calling its worker, passes it a different input, or wraps /
slices / negates its result changes a pinned construct.

**Refused outright (cannot be classified away):**

* control flow: an unconditional ``continue`` / ``break`` / ``return`` that is
  not the final statement; ``del``; ``try`` / ``with`` / nested ``def`` /
  ``class`` / ``global`` / ``nonlocal`` / ``yield`` in an analysed region; any
  ``except`` handler or ``suppress`` anywhere in detection.py (an exception
  swallowed after a record leaves the object recorded but unevaluated);
* dataflow, where an *evidence value* is the result of a value-returning
  detection.py call or anything derived from one (by assignment, or by being
  bound / accumulated under a condition or loop that depends on one):
  - an expression statement that discards a value (only accumulation into a
    local — ``x.append`` / ``extend`` / ``add`` / ``update`` — and calls of
    ``-> None`` detection.py procedures such as the record sinks are allowed);
  - an evidence value overwritten by a non-evidence value before it is read,
    rewritten from itself (``x = x[:0]``), cleared / popped / removed in
    place, or bound and then never read;
  - a parameter or an enclosing loop variable rebound;
  - an argument to a value-returning detection.py call that is not derived
    from the enclosing function's parameters and is not a module-level
    constant provably non-empty from its literal definition (``frozenset()``,
    ``""``, an empty or unprovable constant are refused);
  - in a value-returning helper that makes evidence calls, an unconditional
    ``return`` (under no condition, loop, or earlier exiting ``if``) whose value
    does not carry evidence (``x = worker(...); return []``); and any analysed
    value-returning helper whose body can fall off the end. (A conditional
    return is governed by its pinned condition.)
* bindings: a detection.py function defined twice, rebound at module level, or
  decorated when analysed; a module constant used as an evidence argument that
  is bound more than once.

Plus, as before, any rebinding of ``estate`` or non-append mutation of
``findings`` after the record point.
"""

from __future__ import annotations

import ast
import copy
from collections import Counter, defaultdict
from collections.abc import Callable
from dataclasses import dataclass


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


def _defined_functions(tree: ast.Module) -> dict[str, ast.FunctionDef]:
    return {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}


# Record sinks: calls to these are not evidence-bearing, so they are not pinned.
_RECORD_SINKS = frozenset({"_evaluated", "_container_evaluated"})


def _called_defined(node: ast.AST, defined: frozenset[str], *, after_line: int = 0) -> set[str]:
    """Names of detection.py functions called within *node* (after *after_line*)."""
    out: set[str] = set()
    for n in ast.walk(node):
        if (
            isinstance(n, ast.Call)
            and isinstance(n.func, ast.Name)
            and n.func.id in defined
            and n.func.id not in _RECORD_SINKS
            and getattr(n, "lineno", 0) > after_line
        ):
            out.add(n.func.id)
    return out


def _helpers_called_after_records(
    tree: ast.Module, defined: dict[str, ast.FunctionDef]
) -> set[str]:
    """Transitive closure of detection.py helpers reachable from a post-record call.

    A detector's record vouches for every helper that runs after it, so those
    helpers' bodies are part of the evidence and must be analysed too.
    """
    names = frozenset(defined)
    seeds: set[str] = set()
    for fn in defined.values():
        if not fn.name.startswith("detect_"):
            continue
        start = _first_record_line(fn)
        if start is None:
            continue
        seeds |= _called_defined(fn, names, after_line=start)
    closure: set[str] = set()
    stack = list(seeds)
    while stack:
        name = stack.pop()
        if name in closure or name not in defined:
            continue
        closure.add(name)
        stack.extend(_called_defined(defined[name], names))
    return closure


def _notes(tree: ast.Module) -> frozenset[str]:
    for node in tree.body:
        target = node.target if isinstance(node, ast.AnnAssign) else None
        if isinstance(target, ast.Name) and target.id == "_DEGRADATION_NOTES":
            assert node.value is not None
            return frozenset(
                n.value
                for n in ast.walk(node.value)
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
        n.lineno
        for n in ast.walk(fn)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "_evaluated"
    ]
    return min(lines) if lines else None


def _parents(fn: ast.FunctionDef) -> dict[ast.AST, ast.AST]:
    out: dict[ast.AST, ast.AST] = {}
    for node in ast.walk(fn):
        for child in ast.iter_child_nodes(node):
            out[child] = node
    return out


# --- evidence dataflow -------------------------------------------------------
#
# An *evidence value* is the result of a value-returning detection.py call (an
# "evidence call") or anything derived from one: assigned from it, or bound /
# accumulated under a condition or loop that depends on it (including an early
# ``continue`` / ``return`` guarded by it). The analysis is flow-insensitive and
# per-function; positions (line, column) stand in for program order where an
# ordering matters (overwrite / never-read).

# Bare-statement method calls that accumulate into a local (allowed), and the
# methods that also make their receiver carry what they add.
_ACCUMULATE = frozenset({"append", "extend", "add", "update"})
_ACCUMULATE_TAINT = _ACCUMULATE | {"setdefault", "insert"}
# In-place methods that can shrink or empty a collection.
_SHRINK = frozenset(
    {
        "clear",
        "pop",
        "popitem",
        "remove",
        "discard",
        "difference_update",
        "intersection_update",
        "symmetric_difference_update",
        "__delitem__",
        "__setitem__",
        "__init__",
        "__iand__",
        "__isub__",
        "__imul__",
    }
)
_CONSTRUCTORS = frozenset({"frozenset", "set", "tuple", "list", "dict"})
# Never allowed anywhere in detection.py: they can swallow an exception raised
# after a record, or rebind a function / constant out of sight of the AST.
_FORBIDDEN_NAMES = frozenset({"suppress", "globals", "setattr", "exec", "eval", "__import__"})
_FORBIDDEN_IN_REGION: tuple[type[ast.AST], ...] = (
    ast.Try,
    ast.TryStar,
    ast.With,
    ast.AsyncWith,
    ast.FunctionDef,
    ast.AsyncFunctionDef,
    ast.ClassDef,
    ast.Global,
    ast.Nonlocal,
    ast.Yield,
    ast.YieldFrom,
    ast.Await,
)
_EXITS = (ast.Return, ast.Raise, ast.Continue, ast.Break)


def _returns_none(fn: ast.FunctionDef) -> bool:
    return isinstance(fn.returns, ast.Constant) and fn.returns.value is None


def _module_bindings(tree: ast.Module) -> dict[str, list[ast.AST]]:
    """Every module-level binding site, by name (its value node, or the def itself)."""
    out: dict[str, list[ast.AST]] = defaultdict(list)
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out[node.name].append(node)
        elif isinstance(node, ast.Assign):
            for tgt in node.targets:
                for n in _store_names(tgt):
                    out[n.id].append(node.value)
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
            for n in _store_names(node.target):
                out[n.id].append(node.value if node.value is not None else node)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                out[(alias.asname or alias.name).split(".")[0]].append(node)
        else:  # for / with / if / try at module level: any name they bind counts
            for n in ast.walk(node):
                if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
                    out[n.id].append(node)
    return out


def _provably_nonempty(
    expr: ast.AST | None, module: dict[str, list[ast.AST]], depth: int = 0
) -> bool:
    """True only when *expr*'s literal definition is visibly non-empty."""
    if expr is None or depth > 8:
        return False
    if isinstance(expr, ast.Constant):
        return bool(expr.value)
    if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
        return bool(expr.elts)
    if isinstance(expr, ast.Dict):
        return bool(expr.keys)
    if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Name):
        if expr.func.id in _CONSTRUCTORS and len(expr.args) == 1 and not expr.keywords:
            return _provably_nonempty(expr.args[0], module, depth + 1)
        return False
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, (ast.BitOr, ast.Add)):
        return _provably_nonempty(expr.left, module, depth + 1) or _provably_nonempty(
            expr.right, module, depth + 1
        )
    if isinstance(expr, ast.Name):
        sites = module.get(expr.id, [])
        return len(sites) == 1 and _provably_nonempty(sites[0], module, depth + 1)
    return False


def _names(node: ast.AST | None) -> set[str]:
    if node is None:
        return set()
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)}


def _store_names(target: ast.AST) -> list[ast.Name]:
    return [n for n in ast.walk(target) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)]


def _line(node: ast.AST) -> int:
    """A node's line; a comprehension (which has none) takes its target's."""
    if isinstance(node, ast.comprehension):
        return node.target.lineno
    return getattr(node, "lineno", 0)


def _pos(node: ast.AST) -> tuple[int, int]:
    return (getattr(node, "lineno", 0), getattr(node, "col_offset", 0))


def _end(node: ast.AST) -> tuple[int, int]:
    return (getattr(node, "end_lineno", 0) or 0, getattr(node, "end_col_offset", 0) or 0)


@dataclass(frozen=True)
class _Site:
    """One place a name is bound (or accumulated into)."""

    name: str
    node: ast.AST  # the binding statement / expression / accumulating call
    value: ast.AST | None  # what the name is derived from (None: a parameter)
    kind: str  # param, assign, aug, for, comp, walrus, accumulate, item


def _sites(fn: ast.FunctionDef) -> list[_Site]:
    out: list[_Site] = []
    a = fn.args
    for arg in [*a.posonlyargs, *a.args, *a.kwonlyargs, *(x for x in (a.vararg, a.kwarg) if x)]:
        out.append(_Site(arg.arg, fn, None, "param"))
    for node in ast.walk(fn):
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            if node.value is None:
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            kind = "aug" if isinstance(node, ast.AugAssign) else "assign"
            for tgt in targets:
                if isinstance(tgt, (ast.Subscript, ast.Attribute)) and isinstance(
                    tgt.value, ast.Name
                ):
                    out.append(_Site(tgt.value.id, node, node.value, "item"))
                for n in _store_names(tgt):
                    out.append(_Site(n.id, node, node.value, kind))
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            for n in _store_names(node.target):
                out.append(_Site(n.id, node, node.iter, "for"))
        elif isinstance(node, ast.comprehension):
            for n in _store_names(node.target):
                out.append(_Site(n.id, node, node.iter, "comp"))
        elif isinstance(node, ast.NamedExpr):
            out.append(_Site(node.target.id, node, node.value, "walrus"))
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.attr in _ACCUMULATE_TAINT
        ):
            out.append(_Site(node.func.value.id, node, node, "accumulate"))
    return out


def _always_exits(stmts: list[ast.stmt]) -> bool:
    if not stmts:
        return False
    last = stmts[-1]
    if isinstance(last, _EXITS):
        return True
    return isinstance(last, ast.If) and _always_exits(last.body) and _always_exits(last.orelse)


def _control_tests(
    node: ast.AST, fn: ast.FunctionDef, parents: dict[ast.AST, ast.AST]
) -> list[ast.AST]:
    """Conditions / loop iterables *node* is control-dependent on, within *fn*.

    Includes enclosing ``if`` / ``while`` / ternary tests and ``for`` /
    comprehension iterables, and every EARLIER sibling ``if`` that exits on one
    branch (``if not x: continue`` guards everything after it in the block).
    """
    out: list[ast.AST] = []
    child, p = node, parents.get(node)
    while p is not None:
        if isinstance(p, (ast.If, ast.While, ast.IfExp)) and child is not p.test:
            out.append(p.test)
        elif (
            isinstance(p, (ast.For, ast.AsyncFor)) and child is not p.iter and child is not p.target
        ):
            out.append(p.iter)
        elif isinstance(p, ast.comprehension) and child is not p.iter:
            out.append(p.iter)
            out.extend(p.ifs)
        if isinstance(child, ast.stmt):
            for field in ("body", "orelse", "finalbody"):
                block = getattr(p, field, None)
                if isinstance(block, list) and child in block:
                    for sib in block[: block.index(child)]:
                        if isinstance(sib, ast.If) and (
                            _always_exits(sib.body) or _always_exits(sib.orelse)
                        ):
                            out.append(sib.test)
        if p is fn:
            break
        child, p = p, parents.get(p)
    return out


class _Flow:
    """Per-function evidence / input dataflow (flow-insensitive fixpoint)."""

    def __init__(
        self,
        fn: ast.FunctionDef,
        defined: dict[str, ast.FunctionDef],
        parents: dict[ast.AST, ast.AST],
    ) -> None:
        self.fn = fn
        self.parents = parents
        self.sites = _sites(fn)
        self.params = {s.name for s in self.sites if s.kind == "param"}
        self.local = {s.name for s in self.sites}
        self.evidence_fns = frozenset(
            n for n, d in defined.items() if n not in _RECORD_SINKS and not _returns_none(d)
        )
        self.controls = {id(s.node): _control_tests(s.node, fn, parents) for s in self.sites}
        # Names derived from the function's inputs (its parameters).
        self.derived = self._fixpoint(set(self.params), lambda s, d: bool(_names(s.value) & d))
        self.evidence = self._fixpoint(
            set(),
            lambda s, e: (
                self._carries(s.value, e)
                or any(self._carries(t, e) for t in self.controls[id(s.node)])
            ),
        )

    def _fixpoint(self, seed: set[str], rule: Callable[[_Site, set[str]], bool]) -> set[str]:
        names = set(seed)
        changed = True
        while changed:
            changed = False
            for s in self.sites:
                if s.name not in names and s.kind != "param" and rule(s, names):
                    names.add(s.name)
                    changed = True
        return names

    def is_evidence_call(self, node: ast.AST) -> bool:
        return (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in self.evidence_fns
            and node.func.id not in self.local
        )

    def _carries(self, value: ast.AST | None, evidence: set[str]) -> bool:
        if value is None:
            return False
        return bool(_names(value) & evidence) or any(
            self.is_evidence_call(n) for n in ast.walk(value)
        )

    def carries(self, value: ast.AST | None) -> bool:
        """*value* mentions an evidence call or an evidence name (data, not control)."""
        return self._carries(value, self.evidence)


def _flow_context(call: ast.Call, parents: dict[ast.AST, ast.AST]) -> str:
    """The expression that consumes *call*: its statement, keyword, or f-string field."""
    node: ast.AST = call
    while True:
        p = parents.get(node)
        if p is None:
            return ast.unparse(node)
        if isinstance(p, ast.keyword):
            return ast.unparse(p)
        if isinstance(p, ast.FormattedValue):
            return "{" + ast.unparse(p.value) + "}"
        if isinstance(p, (ast.If, ast.While)):
            return f"{type(p).__name__.lower()} {ast.unparse(p.test)}"
        if isinstance(p, (ast.For, ast.AsyncFor)):
            return f"for {ast.unparse(p.target)} in {ast.unparse(p.iter)}"
        if isinstance(p, ast.stmt):
            return _render(p)
        node = p


class _ElideFindings(ast.NodeTransformer):
    """``Finding(...)`` -> ``Finding(...)`` with its (presentation) body elided."""

    def visit_Call(self, node: ast.Call) -> ast.AST:
        if isinstance(node.func, ast.Name) and node.func.id == "Finding":
            return ast.Call(func=node.func, args=[ast.Constant(Ellipsis)], keywords=[])
        return self.generic_visit(node)


def _render(stmt: ast.AST) -> str:
    if isinstance(stmt, (ast.For, ast.AsyncFor)):
        return f"for {ast.unparse(stmt.target)} in {ast.unparse(stmt.iter)}"
    return ast.unparse(_ElideFindings().visit(copy.deepcopy(stmt)))


def _branch_path(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> list[tuple[int, str]]:
    """Root-first list of (ancestor id, field holding the path) for *node*."""
    path: list[tuple[int, str]] = []
    child, p = node, parents.get(node)
    while p is not None:
        for field, value in ast.iter_fields(p):
            if value is child or (isinstance(value, list) and any(v is child for v in value)):
                path.append((id(p), field))
                break
        child, p = p, parents.get(p)
    return path[::-1]


def _exclusive(a: ast.AST, b: ast.AST, parents: dict[ast.AST, ast.AST]) -> bool:
    """True when *a* and *b* sit in opposite branches of one ``if`` / ternary."""
    for (pa, fa), (pb, fb) in zip(_branch_path(a, parents), _branch_path(b, parents), strict=False):
        if pa != pb:
            return False
        if fa != fb:
            return {fa, fb} == {"body", "orelse"}
    return False


def _bare_target(site: _Site, var: str) -> bool:
    """The name is bound directly (``x = ...``), not as a tuple-unpacking element."""
    node = site.node
    if isinstance(node, ast.NamedExpr):
        return True
    if isinstance(node, ast.Assign):
        return any(isinstance(t, ast.Name) and t.id == var for t in node.targets)
    return isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)


def _dataflow(
    fn: ast.FunctionDef,
    start: int,
    defined: dict[str, ast.FunctionDef],
    module: dict[str, list[ast.AST]],
    whole_body: bool,
) -> tuple[list[str], list[str]]:
    """(pinned constructs, outright violations) for one analysed region.

    Pinned: every evidence flow; every binding in the backward slice of a
    verdict (a condition, a loop iterable, an evidence-call argument, or — in a
    whole-body helper — a return value); and every return of a whole-body
    helper. Presentation (Finding bodies, names only they read) is not pinned.
    """
    parents = _parents(fn)
    flow = _Flow(fn, defined, parents)
    pinned: list[str] = []
    out: list[str] = []
    name = fn.name

    def in_region(node: ast.AST) -> bool:
        return whole_body or _line(node) > start

    if whole_body and fn.decorator_list:
        out.append(f"{name}: an analysed helper is decorated")

    seeds: set[str] = set()
    for node in ast.walk(fn):
        if node is fn or not in_region(node):
            continue
        line = getattr(node, "lineno", 0)
        if isinstance(node, _FORBIDDEN_IN_REGION):
            out.append(f"{name}:{line}: {type(node).__name__} in an analysed region")
        if isinstance(node, (ast.If, ast.While, ast.IfExp)):
            seeds |= _names(node.test)
        if isinstance(node, (ast.For, ast.AsyncFor)):
            seeds |= _names(node.iter)
        if isinstance(node, ast.Return) and whole_body:
            seeds |= _names(node.value)
            pinned.append(_render(node))
        # Evidence flows: pinned with their consumer; arguments must be inputs.
        if flow.is_evidence_call(node):
            assert isinstance(node, ast.Call)
            pinned.append("flow: " + _flow_context(node, parents))
            for arg in [*node.args, *(kw.value for kw in node.keywords)]:
                value = arg.value if isinstance(arg, ast.Starred) else arg
                seeds |= _names(value)
                if _names(value) & flow.derived:
                    continue
                consts = [n for n in _names(value) if n not in flow.local and n not in defined]
                if consts and all(_provably_nonempty(ast.Name(c), module) for c in consts):
                    continue
                out.append(
                    f"{name}:{line}: argument {ast.unparse(value)!r} to "
                    f"{ast.unparse(node.func)}() is neither derived from the inputs nor a "
                    "provably non-empty module constant"
                )
        # Expression statements: nothing may be computed and thrown away.
        if isinstance(node, ast.Expr):
            v = node.value
            ok = (
                (isinstance(v, ast.Constant) and isinstance(v.value, str))
                or (
                    isinstance(v, ast.Call)
                    and isinstance(v.func, ast.Name)
                    and v.func.id in defined
                    and _returns_none(defined[v.func.id])
                )
                or (
                    isinstance(v, ast.Call)
                    and isinstance(v.func, ast.Attribute)
                    and isinstance(v.func.value, ast.Name)
                    and v.func.value.id in flow.local
                    and v.func.attr in _ACCUMULATE
                )
            )
            if not ok:
                out.append(f"{name}:{line}: expression statement discards its value")
        # In-place shrinking of an evidence value.
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in flow.evidence
            and node.func.attr in _SHRINK
        ):
            out.append(f"{name}:{line}: evidence {node.func.value.id!r} shrunk in place")

    # Backward slice of the verdict: pin every binding of a name it reads.
    region_sites = [s for s in flow.sites if s.kind != "param" and in_region(s.node)]
    slice_names = set(seeds)
    pinned_sites: set[int] = set()
    changed = True
    while changed:
        changed = False
        for s in region_sites:
            if s.name in slice_names and id(s.node) not in pinned_sites:
                pinned_sites.add(id(s.node))
                # A comprehension is pinned by its consumer; a statement holding
                # an evidence call is already pinned as that call's flow.
                value_calls = s.value is not None and any(
                    flow.is_evidence_call(n) for n in ast.walk(s.value)
                )
                if s.kind != "comp" and not value_calls:
                    pinned.append("bind: " + _render(s.node))
                new = _names(s.value) - slice_names
                if new:
                    slice_names |= new
                changed = True

    by_name: dict[str, list[_Site]] = defaultdict(list)
    for s in flow.sites:
        by_name[s.name].append(s)
    for var, sites in by_name.items():
        mine = [
            s for s in sites if s.kind not in ("param", "comp", "accumulate") and in_region(s.node)
        ]
        # Parameters and enclosing loop variables are the inputs: never rebound.
        if var in flow.params:
            for s in mine:
                out.append(f"{name}:{_pos(s.node)[0]}: parameter {var!r} rebound")
            continue
        for s in mine:
            p = parents.get(s.node)
            while p is not None and p is not fn:
                if isinstance(p, (ast.For, ast.AsyncFor)) and var in {
                    n.id for n in _store_names(p.target)
                }:
                    out.append(f"{name}:{_pos(s.node)[0]}: loop variable {var!r} rebound")
                    break
                p = parents.get(p)
        if var not in flow.evidence:
            continue
        # Evidence is never rewritten from itself (``x = x[:0]``, ``x = f(x)``).
        for s in mine:
            if s.kind in ("assign", "walrus") and var in _names(s.value):
                out.append(f"{name}:{_pos(s.node)[0]}: evidence {var!r} rewritten from itself")
        # Overwritten before it was read: a later non-evidence binding with no
        # read of the name in between.
        loads = sorted(
            _pos(n)
            for n in ast.walk(fn)
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load) and n.id == var
        )
        carrying = [s for s in sites if s.kind != "param" and flow.carries(s.value)]
        for s in mine:
            if flow.carries(s.value) and s.kind == "aug":
                continue
            earlier = [
                c
                for c in carrying
                if _end(c.node) <= _pos(s.node)
                and c is not s
                and not _exclusive(c.node, s.node, parents)
            ]
            if not earlier or flow.carries(s.value):
                continue
            last = max(_end(c.node) for c in earlier)
            if not any(last <= ld < _pos(s.node) for ld in loads):
                out.append(
                    f"{name}:{_pos(s.node)[0]}: evidence {var!r} overwritten before it was read"
                )
        # Bound in the region and never read afterwards.
        for s in mine:
            if s.kind in ("assign", "walrus") and flow.carries(s.value) and _bare_target(s, var):
                if not any(ld >= _end(s.node) for ld in loads):
                    out.append(f"{name}:{_pos(s.node)[0]}: evidence {var!r} is never read")

    # A value-returning helper must return what its evidence computed.
    if whole_body and not _returns_none(fn):
        if not isinstance(fn.body[-1], (ast.Return, ast.Raise)):
            out.append(f"{name}: a value-returning helper can fall off the end")
        if any(flow.is_evidence_call(n) for n in ast.walk(fn)):
            for node in ast.walk(fn):
                if (
                    isinstance(node, ast.Return)
                    and not _control_tests(node, fn, parents)
                    and not flow.carries(node.value)
                ):
                    out.append(
                        f"{name}:{node.lineno}: unconditional return does not carry the "
                        "evidence the helper computes"
                    )
    return pinned, out


def _module_violations(tree: ast.Module, module: dict[str, list[ast.AST]]) -> list[str]:
    out: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler):
            out.append(f"line {node.lineno}: except handler in detection.py")
        if isinstance(node, ast.Name) and node.id in _FORBIDDEN_NAMES:
            out.append(f"line {node.lineno}: {node.id} in detection.py")
        if isinstance(node, ast.Attribute) and node.attr in _FORBIDDEN_NAMES:
            out.append(f"line {node.lineno}: .{node.attr} in detection.py")
    for fn_name, sites in module.items():
        if any(isinstance(s, ast.FunctionDef) for s in sites) and len(sites) > 1:
            out.append(f"{fn_name}: a detection.py function is bound {len(sites)} times")
    return out


def analyse(source: str) -> tuple[Counter[tuple[str, str]], list[str]]:
    """(post-record conditions/lambdas by function, outright violations)."""
    tree = ast.parse(source)
    notes = _notes(tree)
    defined = _defined_functions(tree)
    builders = _posture_builders(tree, notes)
    helpers = _helpers_called_after_records(tree, defined)
    # Whole-body functions: posture-finding builders and post-record helpers.
    whole_body = builders | helpers
    module = _module_bindings(tree)
    found: Counter[tuple[str, str]] = Counter()
    violations: list[str] = _module_violations(tree, module)
    for fn in tree.body:
        if not isinstance(fn, ast.FunctionDef):
            continue
        if fn.name.startswith("detect_"):
            start = _first_record_line(fn)
            if start is None:
                continue  # records nothing: everything it reports absent is withheld
        elif fn.name in whole_body:
            start = fn.lineno
        else:
            continue
        parents = _parents(fn)
        is_builder = fn.name in whole_body
        # Pin every evidence flow (call + consumer + arguments) and refuse what
        # the dataflow cannot prove: for a detector, after its record point; for
        # a whole-body helper, everywhere in it.
        pinned, flow_violations = _dataflow(fn, start, defined, module, is_builder)
        for f in pinned:
            found[(fn.name, f)] += 1
        violations.extend(flow_violations)
        for node in ast.walk(fn):
            line = _line(node)
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
                    isinstance(node, ast.Return) and parents.get(node) is fn and fn.body[-1] is node
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
