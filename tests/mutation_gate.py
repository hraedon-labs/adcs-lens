"""Deterministic mutation testing of the detectors (see tests/test_mutation_gate.py).

A mutant is one small, explicit change to ``src/adcs_lens/detection.py`` or to
the ``normalize.py`` helpers the detectors rely on. It is *killed* when, on some
corpus pair (tests/mutation_corpus.py), ``diff`` reports anything different from
what it reports with the pristine detectors — a finding lost, added, relabelled
or re-worded, a resolution withheld or (the dangerous direction) granted — or
when the mutant raises where the pristine code does not (or vice versa).

Mutants come from two sources, both enumerated deterministically:

* generic AST operators over every function and module constant in scope
  (OPERATORS below: return-empty, negated condition, dropped guard, comparison /
  boolean / arithmetic operator swaps, integer boundary +-1, dropped constant
  element, emptied constant argument, renamed identity literal, removed
  ``_undecided`` call);
* the explicit list HAND_WRITTEN: every reviewer probe and variant from review
  rounds 3 and 4 (post-record helper mutants, indirection through nested
  helpers / lambdas / method aliases / getattr / dict dispatch with Assert sinks,
  check and variant renames) and the round-2 records-design skips, re-anchored
  to the verdict functions.

A mutant id is ``family:scope:source-text#n`` — stable across unrelated edits
and readable in a failure message.
"""

from __future__ import annotations
import __future__

import ast
import contextlib
import dataclasses
import importlib.util
import sys
import time
from collections import Counter
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Any

from adcs_lens import detection, normalize
from adcs_lens import diff as diff_mod
from adcs_lens.detection import Evaluation
from adcs_lens.diff import DriftReport, diff_findings
from adcs_lens.model import Estate
from tests.conftest import NOW
from tests.mutation_corpus import Corpus

DETECTION_SRC = Path(detection.__file__).read_text(encoding="utf-8")
NORMALIZE_SRC = Path(normalize.__file__).read_text(encoding="utf-8")

# Functions that only build explanation text for withheld findings (diff takes
# a gap's reason only on paths that already withhold) — never a decision, so a
# mutant there cannot change what diff resolves.
EXPLANATION_ONLY: frozenset[str] = frozenset(
    {
        "coverage_gaps",
        "_declared_gaps",
        "_object_gap",
        "CoverageGap.covers",
        "same_object",
        # predicates only coverage_gaps calls (the detectors read through _Reader)
        "_owner_captured",
        "_template_key_size_captured",
        "_cert_expiry_readable",
        "_cert_key_size_readable",
        "_crl_next_update_readable",
        "_cert_sig_alg_readable",
        "_cert_key_alg_known",
        "_crl_window_readable",
    }
)
# Module constants read only by those explanation functions.
EXPLANATION_CONSTANTS: frozenset[str] = frozenset(
    {
        "_TEMPLATE_ACL_CHECKS",
        "_TEMPLATE_CHECKS",
        "_CA_AUDIT_CHECKS",
        "_CA_REGISTRY_CHECKS",
        "_LIFECYCLE_CHECKS",
        "_CA_CHECKS",
        "_PASS_COVERAGE",
    }
)


# --- mutant representation ------------------------------------------------------


@dataclass
class Mutant:
    id: str
    family: str
    target: str  # "detection" or "normalize"
    # In-place AST edit and its revert (generic operators), or a source rewrite
    # (hand-written mutants).
    apply: Callable[[], None] | None = None
    revert: Callable[[], None] | None = None
    rewrite: Callable[[str], str] | None = None
    # The top-level function the edit lives in: re-executed alone in a shared
    # host module (fast path). None: recompile the whole module.
    fast: ast.FunctionDef | None = None


def _text(node: ast.AST, limit: int = 90) -> str:
    s = " ".join(ast.unparse(node).split())
    return s if len(s) <= limit else s[: limit - 3] + "..."


def _set(node: ast.AST, attr: str, new: Any) -> tuple[Callable[[], None], Callable[[], None]]:
    old = getattr(node, attr)

    def apply() -> None:
        setattr(node, attr, new)

    def revert() -> None:
        setattr(node, attr, old)

    return apply, revert


def _list_edit(
    owner: ast.AST, attr: str, new_list: list[Any]
) -> tuple[Callable[[], None], Callable[[], None]]:
    return _set(owner, attr, new_list)


def _located(new: ast.AST, like: ast.AST) -> ast.AST:
    ast.copy_location(new, like)
    ast.fix_missing_locations(new)
    for child in ast.walk(new):
        if not hasattr(child, "lineno"):
            ast.copy_location(child, like)
    return new


def _expr(src: str, like: ast.AST) -> ast.expr:
    node = ast.parse(src, mode="eval").body
    return _located(node, like)  # type: ignore[return-value]


# --- scope walking ------------------------------------------------------------------


def _functions(tree: ast.Module) -> Iterator[tuple[str, ast.FunctionDef]]:
    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            yield node.name, node
        elif isinstance(node, ast.ClassDef):
            for item in node.body:
                if isinstance(item, ast.FunctionDef):
                    yield f"{node.name}.{item.name}", item


def _module_constants(tree: ast.Module) -> Iterator[tuple[str, ast.stmt]]:
    for node in tree.body:
        if isinstance(node, ast.Assign | ast.AnnAssign):
            target = node.targets[0] if isinstance(node, ast.Assign) else node.target
            if isinstance(target, ast.Name) and node.value is not None:
                yield target.id, node


def _parents(root: ast.AST) -> dict[ast.AST, tuple[ast.AST, str]]:
    out: dict[ast.AST, tuple[ast.AST, str]] = {}
    for parent in ast.walk(root):
        for name, value in ast.iter_fields(parent):
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, ast.AST):
                        out[item] = (parent, name)
            elif isinstance(value, ast.AST):
                out[value] = (parent, name)
    return out


# --- generic operators -----------------------------------------------------------------

_CMP_SWAP: dict[type, type] = {
    ast.Eq: ast.NotEq,
    ast.NotEq: ast.Eq,
    ast.Lt: ast.LtE,
    ast.LtE: ast.Lt,
    ast.Gt: ast.GtE,
    ast.GtE: ast.Gt,
    ast.In: ast.NotIn,
    ast.NotIn: ast.In,
    ast.Is: ast.IsNot,
    ast.IsNot: ast.Is,
}
_BIN_SWAP: dict[type, type] = {
    ast.Add: ast.Sub,
    ast.Sub: ast.Add,
    ast.Mult: ast.Div,
    ast.Div: ast.Mult,
    ast.BitAnd: ast.BitOr,
    ast.BitOr: ast.BitAnd,
}
_ENUM_RETURNS = {"CaPatchState": ("UNKNOWN", "PATCHED", "UNPATCHED")}


def _empty_returns(annotation: str) -> list[str]:
    a = annotation.replace(" ", "")
    if a in ("None", "NoReturn"):
        return ["None"]
    if a == "bool":
        return ["False", "True"]
    if a.startswith("list["):
        return ["[]"]
    if a.startswith("tuple[") or a == "tuple":
        return ["()"]
    if a.startswith("frozenset["):
        return ["frozenset()"]
    if a.startswith("set["):
        return ["set()"]
    if a.startswith(("dict[", "Mapping[")):
        return ["{}"]
    if a == "str":
        return ["''"]
    if a in ("int", "int|None"):
        return ["0"]
    if a in ("_Result", "FindingBody|None") or a.endswith("|None"):
        return ["None"]
    if a in _ENUM_RETURNS:
        return [f"{a}.{m}" for m in _ENUM_RETURNS[a]]
    return []


def _docstring_free(body: list[ast.stmt]) -> list[ast.stmt]:
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
        return body[:1]
    return []


class _Collector:
    def __init__(self, tree: ast.Module, target: str) -> None:
        self.tree = tree
        self.target = target
        self.mutants: list[Mutant] = []
        self._seen: Counter[str] = Counter()
        self.parents = _parents(tree)
        self._fast: ast.FunctionDef | None = None

    def add(self, family: str, scope: str, text: str, edit: tuple[Callable[[], None], ...]) -> None:
        base = f"{family}:{self.target}.{scope}:{text}"
        self._seen[base] += 1
        mid = f"{base}#{self._seen[base]}"
        self.mutants.append(
            Mutant(mid, family, self.target, apply=edit[0], revert=edit[1], fast=self._fast)
        )

    # -- per-function operators ---------------------------------------------------

    def function(self, scope: str, fn: ast.FunctionDef) -> None:
        # Only a top-level function can be re-executed alone; a method edit
        # recompiles the module (a new class object must replace the old one
        # everywhere it is referenced).
        self._fast = fn if "." not in scope else None
        if fn.name == "__init__":
            pass
        elif fn.returns is not None:
            doc = _docstring_free(fn.body)
            for value in _empty_returns(ast.unparse(fn.returns)):
                ret = ast.Return(value=_expr(value, fn.body[-1]))
                _located(ret, fn.body[-1])
                if len(fn.body) > len(doc):
                    self.add(
                        "return-empty",
                        scope,
                        f"return {value}",
                        _list_edit(fn, "body", [*doc, ret]),
                    )
        annotations = {
            id(n)
            for a in (*fn.args.args, *fn.args.kwonlyargs, fn.args.vararg, fn.args.kwarg)
            if a is not None and a.annotation is not None
            for n in ast.walk(a.annotation)
        }
        annotations |= {id(n) for n in ast.walk(fn.returns)} if fn.returns is not None else set()
        for node in ast.walk(fn):
            if isinstance(node, ast.AnnAssign):
                annotations |= {id(n) for n in ast.walk(node.annotation)}
        for node in ast.walk(fn):
            if id(node) not in annotations:  # never evaluated (postponed annotations)
                self._node(scope, node)

    def _node(self, scope: str, node: ast.AST) -> None:
        if isinstance(node, ast.If | ast.IfExp):
            neg = ast.UnaryOp(op=ast.Not(), operand=node.test)
            _located(neg, node.test)
            self.add("negate-condition", scope, _text(node.test), _set(node, "test", neg))
        if isinstance(node, ast.comprehension):
            for i, cond in enumerate(node.ifs):
                neg = ast.UnaryOp(op=ast.Not(), operand=cond)
                _located(neg, cond)
                new_ifs = list(node.ifs)
                new_ifs[i] = neg
                self.add("negate-condition", scope, _text(cond), _list_edit(node, "ifs", new_ifs))
                dropped = [c for j, c in enumerate(node.ifs) if j != i]
                self.add("drop-guard", scope, f"if {_text(cond)}", _list_edit(node, "ifs", dropped))
        if (
            isinstance(node, ast.If)
            and not node.orelse
            and isinstance(node.body[-1], ast.Return | ast.Continue | ast.Raise | ast.Break)
        ):
            parent, attr = self.parents[node]
            stmts = getattr(parent, attr)
            if isinstance(stmts, list):
                kept = [s for s in stmts if s is not node]
                self.add(
                    "drop-guard", scope, f"if {_text(node.test)}", _list_edit(parent, attr, kept)
                )
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            func = node.value.func
            if isinstance(func, ast.Name) and func.id == "_undecided":
                parent, attr = self.parents[node]
                stmts = getattr(parent, attr)
                ret = _located(ast.Return(value=ast.Constant(value=None)), node)
                new = [ret if s is node else s for s in stmts]
                self.add("drop-undecided", scope, _text(node), _list_edit(parent, attr, new))
        if isinstance(node, ast.Compare) and len(node.ops) == 1:
            swap = _CMP_SWAP.get(type(node.ops[0]))
            if swap is not None:
                self.add("swap-compare", scope, _text(node), _set(node, "ops", [swap()]))
        if isinstance(node, ast.BoolOp):
            other = ast.Or() if isinstance(node.op, ast.And) else ast.And()
            self.add("swap-boolean", scope, _text(node), _set(node, "op", other))
        if isinstance(node, ast.BinOp | ast.AugAssign):
            swap_bin = _BIN_SWAP.get(type(node.op))
            text_concat = isinstance(node, ast.BinOp) and any(
                isinstance(side, ast.Constant | ast.JoinedStr) for side in (node.left, node.right)
            )
            if swap_bin is not None and not text_concat:
                self.add("swap-arithmetic", scope, _text(node), _set(node, "op", swap_bin()))
        if isinstance(node, ast.Compare):
            for side in (node.left, *node.comparators):
                if (
                    isinstance(side, ast.Constant)
                    and isinstance(side.value, int)
                    and not isinstance(side.value, bool)
                ):
                    for delta in (-1, 1):
                        self.add(
                            "int-boundary",
                            scope,
                            f"{_text(node)} [{side.value}{delta:+d}]",
                            _set(side, "value", side.value + delta),
                        )
        if isinstance(node, ast.Call):
            self._call(scope, node)

    def _call(self, scope: str, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Name) and func.id == "_verdicts":
            for idx in (1, 2):
                arg = node.args[idx]
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    self.add(
                        "rename-identity",
                        scope,
                        f"{_text(node)} [arg {idx}]",
                        _set(arg, "value", arg.value + "_RENAMED"),
                    )
        for i, arg in enumerate(node.args):
            if isinstance(arg, ast.Name) and arg.id in self.constants:
                empty = _expr("frozenset()", arg)
                new_args = list(node.args)
                new_args[i] = empty
                self.add(
                    "empty-argument",
                    scope,
                    f"{_text(node)} [{arg.id}]",
                    _list_edit(node, "args", new_args),
                )

    # -- module constants --------------------------------------------------------------

    constants: frozenset[str] = frozenset()

    def constant(self, name: str, stmt: ast.stmt) -> None:
        self._fast = None
        value = stmt.value  # type: ignore[attr-defined]
        scope = f"<{name}>"
        entries = {
            id(elt)
            for node in ast.walk(value)
            if isinstance(node, ast.Set | ast.List | ast.Tuple)
            for elt in node.elts
        }
        for node in ast.walk(value):
            if id(node) in entries and isinstance(node, ast.Tuple):
                continue  # a (type, field) entry: dropped whole, never cut in half
            if isinstance(node, ast.Set | ast.List | ast.Tuple) and len(node.elts) > 0:
                for i, elt in enumerate(node.elts):
                    kept = [e for j, e in enumerate(node.elts) if j != i]
                    if isinstance(node, ast.Set) and not kept:
                        continue  # {} would be a dict
                    self.add("drop-element", scope, _text(elt), _list_edit(node, "elts", kept))
            if isinstance(node, ast.Dict):
                for i, key in enumerate(node.keys):
                    if key is None:
                        continue
                    keys = [k for j, k in enumerate(node.keys) if j != i]
                    values = [v for j, v in enumerate(node.values) if j != i]
                    a1, r1 = _list_edit(node, "keys", keys)
                    a2, r2 = _list_edit(node, "values", values)

                    def apply(a1: Any = a1, a2: Any = a2) -> None:
                        a1()
                        a2()

                    def revert(r1: Any = r1, r2: Any = r2) -> None:
                        r1()
                        r2()

                    self.add("drop-element", scope, f"{_text(key)}: ...", (apply, revert))
            if isinstance(node, ast.Call):
                self._call(scope, node)
            if isinstance(node, ast.Constant) and isinstance(node.value, float):
                for factor in (0.5, 2.0):
                    self.add(
                        "int-boundary",
                        scope,
                        f"{node.value}*{factor}",
                        _set(node, "value", node.value * factor),
                    )


def _import_time_calls(tree: ast.Module) -> frozenset[str]:
    """Names module-level code refers to while the module is imported (e.g.
    ``_inputs`` building CHECKS, marker functions stored in ``_MARKERS``): an
    edit to such a function only takes effect on a full re-import."""
    names: set[str] = set()
    for stmt in tree.body:
        if isinstance(stmt, ast.FunctionDef | ast.ClassDef):
            continue
        for node in ast.walk(stmt):
            if isinstance(node, ast.Name):
                names.add(node.id)
    return frozenset(names)


def generic_mutants(tree: ast.Module, target: str) -> list[Mutant]:
    col = _Collector(tree, target)
    import_time = _import_time_calls(tree)
    constants = {}
    for name, stmt in _module_constants(tree):
        value = stmt.value  # type: ignore[attr-defined]
        if isinstance(value, ast.Call | ast.Set | ast.Dict | ast.Tuple | ast.List):
            constants[name] = stmt
    col.constants = frozenset(
        n
        for n, s in constants.items()
        if isinstance(s.value, ast.Call | ast.Set)  # type: ignore[attr-defined]
        and _text(s.value).startswith(("frozenset", "{"))  # type: ignore[attr-defined]
    )
    for name, fn in _functions(tree):
        if name in EXPLANATION_ONLY:
            continue
        col.function(name, fn)
        if name in import_time:
            for m in col.mutants:
                if m.fast is fn:
                    m.fast = None
    for name, stmt in constants.items():
        if name in EXPLANATION_CONSTANTS or name == "__all__":
            continue
        col.constant(name, stmt)
    return col.mutants


# --- hand-written mutants -----------------------------------------------------------


def _once(old: str, new: str) -> Callable[[str], str]:
    def apply(src: str) -> str:
        assert src.count(old) == 1, f"mutation anchor not unique ({src.count(old)}): {old!r}"
        return src.replace(old, new)

    return apply


def _chain(*fns: Callable[[str], str]) -> Callable[[str], str]:
    def apply(src: str) -> str:
        for f in fns:
            src = f(src)
        return src

    return apply


def _in_fn(header: str, old: str, new: str) -> Callable[[str], str]:
    def apply(src: str) -> str:
        start = src.index(header)
        at = src.index(old, start)
        return src[:at] + new + src[at + len(old) :]

    return apply


_ENROLLERS_DEF = "def _low_priv_enrollers(template: CertTemplate) -> list[AceEntry]:\n"
_ENROLLERS_BODY = "    return _low_priv_allow_aces(template, _ENROLL_RIGHTS)\n"
_ESC1 = "def _esc1(tmpl: CertTemplate, ctx: _Context) -> _Result:\n"
_ESC1_ENROLLERS = "    enrollers = _low_priv_enrollers(tmpl)\n"
_ESC6 = "def _esc6(ca: CertAuthority, ctx: _Context) -> _Result:\n"
_ACES = "    aces = _low_priv_allow_aces(template, _ENROLL_RIGHTS)\n"
_AIN_DEF = "def _low_priv_allow_aces_in(\n"
_AIN_APPEND = "                out.append(ace)\n"


def _body(new: str) -> Callable[[str], str]:
    return _once(_ENROLLERS_BODY, new)


def _indirection(declaration: str, call: str) -> Callable[[str], str]:
    """Sol round 4: a clearing call reached through indirection, read in an Assert."""
    return _chain(_once(_AIN_DEF, declaration + _AIN_DEF), _once(_AIN_APPEND, _AIN_APPEND + call))


def _rename_check(
    check: str, variant: str, new_check: str, new_variant: str
) -> Callable[[str], str]:
    """Rename one (check, variant) consistently in CHECKS and at its _verdicts site."""

    def apply(src: str) -> str:
        key = f'("{check}", "{variant}"): _inputs('
        assert src.count(key) == 1, key
        src = src.replace(key, f'("{new_check}", "{new_variant}"): _inputs(')
        call = f'_verdicts(estate, "{check}", "{variant}",'
        assert src.count(call) == 1, call
        return src.replace(call, f'_verdicts(estate, "{new_check}", "{new_variant}",')

    return apply


HAND_WRITTEN: dict[str, Callable[[str], str]] = {
    # --- review round 3: the post-record helper mutants (Sol B4 / DS NN1) ---------
    "r3:sol_b4_enrollers_return_empty": _body("    return []  # R3 MUTANT\n"),
    "r3:ds_nn1_enrollers_return_empty": _once(
        '    """Allow-ACEs that grant (or imply) enroll to a low-privilege trustee."""\n'
        + _ENROLLERS_BODY,
        '    """MUTANT: silently skip every template."""\n    return []\n',
    ),
    # --- review round 3: the 27 variants that keep the call ------------------------
    "r3v:call_then_discard": _body(
        "    _low_priv_allow_aces(template, _ENROLL_RIGHTS)\n    return []\n"
    ),
    "r3v:bound_then_unused": _body(_ACES + "    return []\n"),
    "r3v:discarded_as_underscore": _body(
        "    _ = _low_priv_allow_aces(template, _ENROLL_RIGHTS)\n    return []\n"
    ),
    "r3v:esc1_call_discarded": _in_fn(
        _ESC1,
        _ESC1_ENROLLERS,
        "    _low_priv_enrollers(tmpl)\n    enrollers: list[AceEntry] = []\n",
    ),
    "r3v:overwritten": _body(_ACES + "    aces = []\n    return aces\n"),
    "r3v:cleared_in_place": _body(_ACES + "    aces.clear()\n    return aces\n"),
    "r3v:rewritten_from_itself": _body(_ACES + "    aces = aces[:0]\n    return aces\n"),
    "r3v:sliced_on_return": _body(
        "    return _low_priv_allow_aces(template, _ENROLL_RIGHTS)[:0]\n"
    ),
    "r3v:esc1_result_overwritten": _in_fn(
        _ESC1, _ESC1_ENROLLERS, _ESC1_ENROLLERS + "    enrollers = []\n"
    ),
    "r3v:esc15_input_overwritten": _once(
        '    patch_state = _worst_ca_patch_state(ctx.dep("ca"))\n',
        '    patch_state = _worst_ca_patch_state(ctx.dep("ca"))\n'
        "    patch_state = CaPatchState.PATCHED\n",
    ),
    # The verdict computed from another object than the one it is recorded for.
    "r3v:loop_variable_rebound": _chain(
        _once(
            "    findings: list[Finding] = []\n    for obj in _SUBJECTS[decl.subject](estate):\n",
            "    findings: list[Finding] = []\n    first = None\n"
            "    for obj in _SUBJECTS[decl.subject](estate):\n",
        ),
        _once(
            "            made = _make_findings(check, variant, ref, decide(reader, ctx))\n",
            "            first = first or reader\n"
            "            made = _make_findings(check, variant, ref, decide(first, ctx))\n",
        ),
    ),
    "r3v:wrong_rights": _body("    return _low_priv_allow_aces(template, frozenset())\n"),
    "r3v:empty_set_literal": _body("    return _low_priv_allow_aces(template, set())\n"),
    "r3v:nonempty_wrong_literal": _body(
        "    return _low_priv_allow_aces(template, frozenset({'read'}))\n"
    ),
    "r3v:local_empty_constant": _body(
        "    rights: frozenset[str] = frozenset()\n"
        "    return _low_priv_allow_aces(template, rights)\n"
    ),
    "r3v:empty_module_constant": _chain(
        _once(_ENROLLERS_DEF, "_NO_RIGHTS: frozenset[str] = frozenset()\n\n\n" + _ENROLLERS_DEF),
        _body("    return _low_priv_allow_aces(template, _NO_RIGHTS)\n"),
    ),
    "r3v:module_constant_emptied_by_union": _body(
        "    return _low_priv_allow_aces(template, frozenset() & _ENROLL_RIGHTS)\n"
    ),
    # Reading another template is an undeclared dependency: UndeclaredInput.
    "r3v:esc1_wrong_object": _in_fn(
        _ESC1, _ESC1_ENROLLERS, '    enrollers = _low_priv_enrollers(ctx.dep("template")[0])\n'
    ),
    "r3v:early_return_before_use": _body("    return []\n" + _ENROLLERS_BODY),
    "r3v:conditional_early_return": _body(
        "    if template.security:\n        return []\n" + _ENROLLERS_BODY
    ),
    "r3v:walrus_then_constant": _body(
        "    if (aces := _low_priv_allow_aces(template, _ENROLL_RIGHTS)) is None:\n"
        "        return aces\n    return []\n"
    ),
    "r3v:try_except_swallow": _body(
        "    try:\n        return _low_priv_allow_aces(template, _ENROLL_RIGHTS)[0:0] + [1 / 0]\n"
        "    except Exception:\n        return []\n"
    ),
    "r3v:suppress_swallow": _chain(
        _once(
            "from contextvars import ContextVar\n",
            "from contextlib import suppress\nfrom contextvars import ContextVar\n",
        ),
        _body(
            "    with suppress(ZeroDivisionError):\n        1 / 0\n"
            "        return _low_priv_allow_aces(template, _ENROLL_RIGHTS)\n    return []\n"
        ),
    ),
    "r3v:esc1_try_swallow": _in_fn(
        _ESC1,
        _ESC1_ENROLLERS,
        "    try:\n        enrollers = _low_priv_enrollers(tmpl)[0:0] + [1 / 0]\n"
        "    except ZeroDivisionError:\n        return None\n",
    ),
    "r3v:redefined_later": lambda src: src + "\n\n" + _ENROLLERS_DEF + "    return []\n",
    "r3v:rebound_later": lambda src: (
        src + "\n\n_low_priv_enrollers = lambda template: []  # noqa: E731\n"
    ),
    "r3v:decorated": _once(
        _ENROLLERS_DEF,
        "def _blank(fn: Any) -> Any:\n    return lambda *a: []\n\n\n@_blank\n" + _ENROLLERS_DEF,
    ),
    # --- review round 4: indirection the static guard could not follow (Sol B3) --
    "r4:nested_helper": _indirection(
        "def _r4_factory():\n    def erase(value):\n        value.clear()\n    return erase\n\n\n"
        "_R4_ERASE = _r4_factory()\n\n\n",
        "                ignored = _R4_ERASE(out)\n                assert ignored is None\n",
    ),
    "r4:module_lambda": _indirection(
        "_R4_ERASE = lambda value: value.clear()\n\n\n",
        "                ignored = _R4_ERASE(out)\n                assert ignored is None\n",
    ),
    "r4:method_alias": _indirection(
        "_R4_ERASE = list.clear\n\n\n",
        "                ignored = _R4_ERASE(out)\n                assert ignored is None\n",
    ),
    "r4:getattr": _indirection(
        '_R4_ERASE = getattr(list, "clear")\n\n\n',
        "                ignored = _R4_ERASE(out)\n                assert ignored is None\n",
    ),
    "r4:dict_dispatch": _indirection(
        '_R4_ERASERS = {"erase": list.clear}\n\n\n',
        '                ignored = _R4_ERASERS["erase"](out)\n'
        "                assert ignored is None\n",
    ),
    "r4:assert_sink": _indirection("", "                assert out.clear() is None\n"),
    # DS round 4 probe_guard.py: every call site rerouted through a dispatch
    # table whose entry returns nothing.
    "r4:ds_dict_dispatch_mutant": lambda src: (
        _chain(
            _once(_ENROLLERS_DEF, "_DISPATCH: dict[str, Any] = {}\n\n\n" + _ENROLLERS_DEF),
            _body("    return []  # MUTANT\n"),
        )(src).replace(
            "    enrollers = _low_priv_enrollers(tmpl)\n",
            '    enrollers = _DISPATCH["enrollers"](tmpl)\n',
        )
        + '\n\n_DISPATCH["enrollers"] = _low_priv_enrollers\n'
    ),
    # Sol round 4: the static guard's slice-on-return pin regenerated blindly.
    "r4:pin_blind_regeneration_slice": _body(
        "    return _low_priv_allow_aces(template, _ENROLL_RIGHTS)[:0]\n"
    ),
    # --- review round 4 blocking 4: finding identity (check / variant) -------------
    "r4:rename_esc1": _rename_check("ESC1", "", "ESC1_RENAMED", ""),
    "r4:mislabel_esc1_as_esc2": _once(
        '_verdicts(estate, "ESC1", "", _esc1)', '_verdicts(estate, "ESC2", "", _esc1)'
    ),
    "r4:rename_esc4_owner_variant": _rename_check("ESC4", "owner", "ESC4", "owner-renamed"),
    "r4:rename_esc7_family": _rename_check("ESC7", "trustee:*", "ESC7", "principal:*"),
    # --- review round 2: records-design skips, now inside verdict functions ------
    "r2:sol_guard_mixed": _in_fn(
        _ESC6, "    if _EDITF_SAN2", "    if not ca.dns:\n        return None\n    if _EDITF_SAN2"
    ),
    "r2:sol_guard_mixed_on_label": _in_fn(
        _ESC6,
        "    if _EDITF_SAN2",
        '    if not ca.name.startswith("LAB"):\n        return None\n    if _EDITF_SAN2',
    ),
    "r2:sol_guard_mixed_undecided": _in_fn(
        _ESC6,
        "    if _EDITF_SAN2",
        '    if not ca.dns:\n        _undecided("x")\n    if _EDITF_SAN2',
    ),
    "r2:sol_guard_early": _in_fn(
        _ESC6, "    if _EDITF_SAN2", "    return None\n    if _EDITF_SAN2"
    ),
    "r2:sol_guard_evidence": _once(
        "        evidence_complete=patch_state is not CaPatchState.UNKNOWN,\n", ""
    ),
    "r2:ds_filter_display": _in_fn(
        _ESC1,
        "    if not (tmpl.name_flags",
        "    if not tmpl.display_name:\n        return None\n    if not (tmpl.name_flags",
    ),
    "r2:ds_wrong_pass_predicate": _in_fn(
        _ESC1,
        "    if not (tmpl.name_flags",
        "    if ctx.publication_data_available:\n        return None\n    if not (tmpl.name_flags",
    ),
    "r2:ds_wrong_purpose_predicate": _in_fn(
        _ESC1,
        "    if not (tmpl.name_flags",
        "    if tmpl.display_name.startswith('Ks'):\n        return None\n"
        "    if not (tmpl.name_flags",
    ),
    "r2:sol_guard_filter_estate": _once(
        '    return _verdicts(estate, "ESC6", "", _esc6)\n',
        "    estate = replace(estate, cas=tuple(c for c in estate.cas if c.dns))\n"
        '    return _verdicts(estate, "ESC6", "", _esc6)\n',
    ),
    "r2:ds_helper_skip": _chain(
        _once(_ESC1, "def _skip_it(t: Any) -> bool:\n    return not t.display_name\n\n\n" + _ESC1),
        _in_fn(
            _ESC1,
            "    if not (tmpl.name_flags",
            "    if _skip_it(tmpl):\n        return None\n    if not (tmpl.name_flags",
        ),
    ),
    "r2:ds_class_method_skip": _chain(
        _once(
            _ESC1,
            "class _Skip:\n    def __init__(self, t: Any) -> None:\n"
            "        self.ok = bool(t.display_name)\n\n\n" + _ESC1,
        ),
        _in_fn(
            _ESC1,
            "    if not (tmpl.name_flags",
            "    if not _Skip(tmpl).ok:\n        return None\n    if not (tmpl.name_flags",
        ),
    ),
    "r2:ds_any_element": _in_fn(
        _ESC1,
        "    if not (tmpl.name_flags",
        '    if any(not t.display_name for t in ctx.dep("template")):\n        return None\n'
        "    if not (tmpl.name_flags",
    ),
    "r2:post_record_findings_filter": _once(
        "    findings.sort(key=lambda f: (SEVERITY_RANK[f.severity], f.check, f.subject))\n",
        "    findings = [f for f in findings if f.subject != 'Lab ESC1']\n"
        "    findings.sort(key=lambda f: (SEVERITY_RANK[f.severity], f.check, f.subject))\n",
    ),
    # --- the verdict framework itself ------------------------------------------------
    "framework:usable_ignores_scope": _once(
        "                scope_complete\n                and state",
        "                True\n                and state",
    ),
    "framework:usable_ignores_fields": _once(
        "                and all(_obtained(obj, f) for f in decl.fields)\n", ""
    ),
    "framework:scope_ignores_deps": _once(
        "    return all(\n        _obtained(o, f)\n",
        "    return True or all(\n        _obtained(o, f)\n",
    ),
    "framework:reader_returns_unobtained": _once(
        '                _undecided(f"{type(self._obj).__name__}.{name} was not obtained")\n',
        "                pass\n",
    ),
    "framework:reader_allows_undeclared": _once(
        "        if name not in self._allowed:\n", "        if False:\n"
    ),
    "framework:catch_all_errors": _once(
        "        except _Undecided:\n", "        except Exception:\n"
    ),
    "framework:evaluate_ignores_proof": _once(
        "    proven = estate.manifest.reads_proven\n", "    proven = True\n"
    ),
}


# --- running a mutant -------------------------------------------------------------------


def _summarize(report: DriftReport, new: Any) -> tuple[Any, ...]:
    """Everything observable about one pair, as order-insensitive multisets."""

    def key(f: Any) -> tuple[str, str, str]:
        ref = f.object_ref
        return (f.check, f.variant, ref.key if ref is not None else f"{f.subject}|{f.source}")

    def text(f: Any) -> tuple[Any, ...]:
        return (
            f.severity.value,
            f.title,
            f.subject,
            f.detail,
            f.source,
            f.sid,
            f.evidence_complete,
            str(f.tier),
        )

    return (
        Counter((*key(f), *text(f)) for f in report.new),
        Counter(key(f) for f in report.resolved),
        Counter(key(i.finding) for i in report.indeterminate),
        Counter((*key(o.finding), *text(o.finding), o.reason) for o in report.first_observed),
        Counter((*key(d.old), *text(d.new)) for d in report.changed),
        Counter(
            (c.direction, c.finding.check, c.finding.subject, c.finding.detail)
            for c in report.coverage_changes
        ),
        report.unchanged,
        # The newer findings themselves, attribute by attribute: a change diff does
        # not report (tier, sid, evidence_complete) still kills.
        Counter((*key(f), *text(f)) for f in new.findings),
        # evaluate()'s whole contract with diff, not only what this pair exercises.
        Counter((v.check, v.variant, v.key, v.state, v.usable) for v in new.verdicts),
        frozenset(new.records),
        frozenset(new.flagged),
        frozenset(new.containers),
        frozenset(new.guid_types),
    )


# --- contract probes ---------------------------------------------------------------
# The verdict framework's own contracts, which a correct detector never trips
# and so no estate exercises: each probe's outcome under the mutant must equal
# its outcome under the pristine code.


def _outcome(fn: Callable[[], Any]) -> str:
    try:
        return repr(fn())
    except Exception as exc:  # noqa: BLE001 - the outcome is the exception type
        return f"raises {type(exc).__name__}"


# (label, collected_at, now, stale_days) for detect_export_age. `now` None means
# the corpus NOW; a naive datetime exercises the tz-aware guard.
_EXPORT_AGE_CASES: list[tuple[str, str, Any, int]] = [
    ("fresh", "2026-06-14T12:00:00+00:00", None, 8),
    ("stale", "2026-05-01T12:00:00+00:00", None, 8),
    ("age-equals-limit", "2026-06-07T12:00:00+00:00", None, 8),
    ("future-within-skew", "2026-06-15T12:05:00+00:00", None, 8),
    ("future-beyond-skew", "2026-06-15T13:00:00+00:00", None, 8),
    ("missing", "", None, 8),
    ("no-offset", "2026-06-14T12:00:00", None, 8),
    ("garbage", "yesterday", None, 8),
    ("stale-days-zero", "2026-06-14T12:00:00+00:00", None, 0),
    ("stale-days-one", "2026-06-14T12:00:00+00:00", None, 1),
    ("stale-days-negative", "2026-06-14T12:00:00+00:00", None, -1),
    ("naive-now", "2026-06-14T12:00:00+00:00", "naive", 8),
]


def _probes(estate: Estate) -> dict[str, Callable[[ModuleType], str]]:
    from datetime import datetime

    def export_age(mod: ModuleType, ts: str, now: Any, days: int) -> Any:
        manifest = dataclasses.replace(estate.manifest, collected_at=ts)
        moment = datetime(2026, 6, 15, 12, 0, 0) if now == "naive" else NOW
        found = mod.detect_export_age(
            dataclasses.replace(estate, manifest=manifest), now=moment, stale_days=days
        )
        return (type(found).__name__, [(f.check, f.severity.value, f.detail) for f in found])

    template = estate.templates[0]

    def body(mod: ModuleType) -> Any:
        return mod.FindingBody(
            severity=detection.Severity.HIGH, title="t", subject="s", detail="d", source="x"
        )

    def ref(mod: ModuleType) -> Any:
        return mod.ObjectRef("ca", "a" * 32, ("cn:x",))

    def ctx(mod: ModuleType) -> Any:
        return mod._Context(estate, mod.CHECKS[("ESC1", "")], "ESC1", NOW, 90)

    def keys(findings: Any) -> Any:
        return sorted((f.check, f.variant, f.subject) for f in findings)

    def trusted(mod: ModuleType) -> Any:
        ref_a = mod.ObjectRef("template", "", ("cn:a",))
        old = [
            mod.Finding("ESC9", detection.Severity.HIGH, "t", "A", "d", "s", object_ref=ref_a),
            mod.Finding("ESC1", detection.Severity.HIGH, "t", "B", "d", "s"),
        ]
        new = [mod.Finding("ESC1", detection.Severity.MEDIUM, "t", "B", "d", "s")]
        with _diff_uses(mod):
            report = diff_findings(old, new)
        return (
            keys(report.resolved),
            keys(report.new),
            [(d.old.check, d.new.severity.value) for d in report.changed],
            keys(i.finding for i in report.indeterminate),
        )

    return {
        "undeclared-read": lambda mod: _outcome(
            lambda: mod._Reader(template, frozenset({"name"}), "T").ekus
        ),
        "dunder-lookup": lambda mod: _outcome(
            lambda: hasattr(mod._Reader(template, frozenset(), "T"), "__len__")
        ),
        "undeclared-dependency": lambda mod: _outcome(lambda: len(ctx(mod).dep("ca"))),
        "undeclared-container": lambda mod: _outcome(lambda: ctx(mod).complete("ca-config")),
        "body-for-a-family": lambda mod: _outcome(
            lambda: keys(mod._make_findings("ESC7", "trustee:*", ref(mod), body(mod)))
        ),
        "map-for-an-exact-variant": lambda mod: _outcome(
            lambda: keys(mod._make_findings("ESC6", "", ref(mod), {"x": body(mod)}))
        ),
        "naive-now": lambda mod: _outcome(
            lambda: keys(mod.detect_infra_cert_expiry(estate, now=datetime(2026, 1, 1)))
        ),
        "trusted-evaluations": lambda mod: _outcome(lambda: trusted(mod)),
        # Export age (merged from the chore branch): every boundary of the
        # stale / future / missing / naive-timestamp rules, the stale_days and
        # naive-now guards, and both notes' degradation-note status.
        **{
            f"export-age:{label}": (
                lambda mod, ts=ts, now=now, days=days: _outcome(
                    lambda: export_age(mod, ts, now, days)
                )
            )
            for label, ts, now, days in _EXPORT_AGE_CASES
        },
        "degradation-notes": lambda mod: _outcome(
            lambda: [
                mod.is_degradation_note(
                    mod.Finding(check, detection.Severity.INFO, "t", "(estate)", "d", "s")
                )
                for check in ("EXPORT_STALE", "EXPORT_TIMESTAMP_INVALID", "ESC1")
            ]
        ),
    }


@dataclass
class Baseline:
    corpus: Corpus
    old: dict[str, Evaluation] = field(default_factory=dict)
    expected: dict[str, tuple[Any, ...]] = field(default_factory=dict)
    raising: str = ""
    probes: dict[str, str] = field(default_factory=dict)
    # Pair indices, best kills-per-second first (adaptive ordering).
    order: list[int] = field(default_factory=list)
    kills: Counter[int] = field(default_factory=Counter)
    cost: dict[int, float] = field(default_factory=dict)

    def reorder(self) -> None:
        self.order.sort(key=lambda i: -(self.kills[i] + 1) / self.cost[i])


def baseline(corpus: Corpus) -> Baseline:
    b = Baseline(corpus)
    for index, pair in enumerate(corpus.pairs):
        old = detection.evaluate(pair.old, now=NOW)
        started = time.perf_counter()
        new = detection.evaluate(pair.new, now=NOW)
        b.expected[pair.name] = _summarize(diff_findings(old, new), new)
        b.cost[index] = time.perf_counter() - started
        b.old[pair.name] = old
    try:
        detection.evaluate(corpus.raising, now=NOW)
    except Exception as exc:  # noqa: BLE001 - the probe's purpose
        b.raising = type(exc).__name__
    assert b.raising, "the raising probe must raise under the pristine detectors"
    b.order = list(range(len(corpus.pairs)))
    b.reorder()
    b.probes = {name: probe(detection) for name, probe in _probes(corpus.raising).items()}
    return b


def _new_module(name: str) -> ModuleType:
    spec = importlib.util.spec_from_loader(name, loader=None)
    assert spec is not None
    return importlib.util.module_from_spec(spec)


def _load(code: Any, name: str, *, normalize_mod: ModuleType | None = None) -> ModuleType:
    mod_name = f"adcs_lens._mutant_{name}"
    mod = _new_module(mod_name)
    sys.modules[mod_name] = mod  # dataclasses resolve their module
    try:
        exec(code, mod.__dict__)
        if normalize_mod is not None:
            # Every name the detector imported from normalize is rebound to the
            # (possibly mutated) module, so a normalize mutant reaches it.
            for attr, value in vars(normalize).items():
                if not attr.startswith("__") and mod.__dict__.get(attr) is value:
                    setattr(mod, attr, getattr(normalize_mod, attr))
    finally:
        sys.modules.pop(mod_name, None)
    return mod


@contextlib.contextmanager
def _diff_uses(mod: ModuleType) -> Iterator[None]:
    """Point diff at the mutant's Evaluation / lifecycle types / note predicate /
    decoder-gap checks."""
    saved = (
        diff_mod.Evaluation,
        diff_mod.LIFECYCLE_TYPES,
        diff_mod.is_degradation_note,
        diff_mod.decoder_gap_checks,
    )
    diff_mod.Evaluation = mod.Evaluation  # type: ignore[attr-defined,misc]
    diff_mod.LIFECYCLE_TYPES = mod.LIFECYCLE_TYPES  # type: ignore[attr-defined,misc]
    diff_mod.is_degradation_note = mod.is_degradation_note  # type: ignore[attr-defined]
    diff_mod.decoder_gap_checks = mod.decoder_gap_checks  # type: ignore[attr-defined]
    try:
        yield
    finally:
        (
            diff_mod.Evaluation,  # type: ignore[misc]
            diff_mod.LIFECYCLE_TYPES,  # type: ignore[misc]
            diff_mod.is_degradation_note,
            diff_mod.decoder_gap_checks,
        ) = saved


def _as(mod: ModuleType, ev: Evaluation) -> Any:
    return mod.Evaluation(**{f.name: getattr(ev, f.name) for f in dataclasses.fields(ev)})


def kill(mod: ModuleType, base: Baseline) -> str | None:
    """Why *mod* is killed on the corpus, or None when it survives."""
    pairs = base.corpus.pairs
    try:
        with _diff_uses(mod):
            for index in list(base.order):
                pair = pairs[index]
                reason = None
                try:
                    new = mod.evaluate(pair.new, now=NOW)
                    report = diff_findings(_as(mod, base.old[pair.name]), new)
                    if _summarize(report, new) != base.expected[pair.name]:
                        reason = f"{pair.name}: diff output differs"
                except Exception as exc:  # noqa: BLE001 - any error kills
                    reason = f"{pair.name}: raised {type(exc).__name__}: {str(exc)[:120]}"
                if reason is not None:
                    base.kills[index] += 1
                    base.reorder()
                    return reason
        try:
            mod.evaluate(base.corpus.raising, now=NOW)
            raised = ""
        except Exception as exc:  # noqa: BLE001
            raised = type(exc).__name__
        if raised != base.raising:
            return f"raising probe: pristine raises {base.raising}, mutant {raised or 'nothing'}"
        for name, probe in _probes(base.corpus.raising).items():
            got = probe(mod)
            if got != base.probes[name]:
                return f"contract probe {name}: {base.probes[name]} -> {got}"
    except Exception as exc:  # noqa: BLE001
        return f"harness: {type(exc).__name__}: {exc}"
    return None


@dataclass
class Result:
    mutant: Mutant
    killed_by: str | None


@dataclass
class Run:
    results: list[Result]
    seconds: float

    @property
    def survivors(self) -> list[str]:
        return [r.mutant.id for r in self.results if r.killed_by is None]


def all_mutants() -> tuple[list[Mutant], dict[str, ast.Module]]:
    trees = {"detection": ast.parse(DETECTION_SRC), "normalize": ast.parse(NORMALIZE_SRC)}
    mutants = generic_mutants(trees["detection"], "detection")
    mutants += generic_mutants(trees["normalize"], "normalize")
    for name, rewrite in HAND_WRITTEN.items():
        mutants.append(Mutant(f"hand:{name}", name.split(":", 1)[0], "detection", rewrite=rewrite))
    return mutants, trees


_FUTURE = __future__.annotations.compiler_flag


def _compile_fn(fn: ast.FunctionDef, name: str) -> Any:
    module = ast.Module(body=[fn], type_ignores=[])
    return compile(module, name, "exec", flags=_FUTURE, dont_inherit=True)


@contextlib.contextmanager
def _swapped(mod: ModuleType, values: dict[str, Any]) -> Iterator[None]:
    saved = {k: mod.__dict__[k] for k in values}
    mod.__dict__.update(values)
    try:
        yield
    finally:
        mod.__dict__.update(saved)


def run(mutants: list[Mutant], trees: dict[str, ast.Module], base: Baseline) -> Run:
    """Run every mutant; a mutant that does not even load is killed."""
    started = time.perf_counter()
    host = _load(
        compile(trees["detection"], "<detection>", "exec"), "host", normalize_mod=normalize
    )
    results: list[Result] = []
    for i, m in enumerate(mutants):
        try:
            if m.rewrite is not None:
                source = m.rewrite(DETECTION_SRC)
                assert source != DETECTION_SRC, f"{m.id} did not change the source"
                results.append(Result(m, kill(_load(compile(source, m.id, "exec"), f"h{i}"), base)))
                continue
            assert m.apply is not None and m.revert is not None
            m.apply()
            try:
                if m.target == "normalize":
                    code = compile(trees["normalize"], m.id, "exec")
                elif m.fast is not None:
                    code = _compile_fn(m.fast, m.id)
                else:
                    code = compile(trees["detection"], m.id, "exec")
            finally:
                m.revert()
            if m.target == "normalize":
                norm = _load(code, f"n{i}")
                # Every name the detector imported from normalize.
                swap = {
                    attr: getattr(norm, attr)
                    for attr, value in vars(normalize).items()
                    if not attr.startswith("__") and host.__dict__.get(attr) is value
                }
                with _swapped(host, swap):
                    results.append(Result(m, kill(host, base)))
            elif m.fast is not None:
                scratch: dict[str, Any] = dict(host.__dict__)
                exec(code, scratch)
                with _swapped(host, {m.fast.name: scratch[m.fast.name]}):
                    # The re-executed function must resolve globals in the host.
                    fn = host.__dict__[m.fast.name]
                    host.__dict__[m.fast.name] = type(fn)(
                        fn.__code__, host.__dict__, fn.__name__, fn.__defaults__, fn.__closure__
                    )
                    results.append(Result(m, kill(host, base)))
            else:
                results.append(Result(m, kill(_load(code, f"g{i}", normalize_mod=normalize), base)))
        except Exception as exc:  # noqa: BLE001 - a mutant that does not load is killed
            results.append(Result(m, f"load: {type(exc).__name__}: {str(exc)[:120]}"))
    return Run(results, time.perf_counter() - started)


__all__ = ["Estate", "HAND_WRITTEN", "all_mutants", "baseline", "run"]
