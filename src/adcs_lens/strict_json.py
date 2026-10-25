"""Strict JSON decoding shared by the export and suppression loaders. Stdlib-only.

``json`` keeps the last value of a repeated object key, so a second ``subject``
in a risk-acceptance rule, or a second CA entry in an export, would silently
replace the first. Both loaders pass :func:`unique_keys_hook` as the decoder's
``object_pairs_hook`` and translate :class:`DuplicateKeyError` into their own
error type and wording.
"""

from __future__ import annotations

from typing import Any

from adcs_lens.limits import bounded_repr


class DuplicateKeyError(ValueError):
    """A JSON object repeats a key. ``key`` holds it; ``shown`` is a bounded repr."""

    key: str
    shown: str


def _duplicate(key: str) -> DuplicateKeyError:
    shown = bounded_repr(key)
    exc = DuplicateKeyError(f"duplicate JSON key {shown}")
    exc.key = key
    exc.shown = shown
    return exc


def unique_keys_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """``object_pairs_hook`` that refuses a repeated key instead of keeping the last."""
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise _duplicate(key)
        out[key] = value
    return out
