"""Input limits: per-file size limits and bounded echoes. Stdlib-only.

Every file adcs-lens reads goes through :func:`read_bounded`. An oversized file
is REJECTED, never truncated: a truncated JSON array or CRL would parse as a
smaller, cleaner estate. The limits are policy choices set generously above
any realistic AD CS export, not measurements (see README "Input limits").

Input text quoted back in an error or warning (a duplicate JSON key, an unknown
suppression key, a collector version) goes through :func:`bounded_repr` or
:func:`shorten`, so a hostile or garbled value cannot turn one stderr line
into megabytes.
"""

from __future__ import annotations

import io
import sys
from pathlib import Path

MIB = 1024 * 1024

# Policy limits, in bytes. Not measured from real exports — chosen so that a
# legitimate export never comes near them while a runaway or hostile file
# cannot exhaust memory.
MANIFEST_MAX_BYTES = 1 * MIB  # collector-manifest.json (a few hundred bytes in practice)
JSON_MAX_BYTES = 64 * MIB  # every other export JSON file (templates, ACLs, mappings, ...)
CERT_INDEX_MAX_BYTES = 16 * MIB  # certs/index.json
CERT_MAX_BYTES = 1 * MIB  # one DER CA certificate
CRL_MAX_BYTES = 256 * MIB  # one DER CRL (large CAs can publish big base CRLs)
SUPPRESSIONS_MAX_BYTES = 4 * MIB  # the --suppressions risk-acceptance file

# Characters of operator- or export-supplied text quoted back in one message.
# Generous for any real key name or version string.
ECHO_MAX_CHARS = 80


class InputTooLargeError(ValueError):
    """A file exceeds its size limit; it was rejected, not truncated."""


def read_bounded(path: Path, limit: int, label: str) -> bytes:
    """Read *path* whole, refusing anything larger than *limit* bytes.

    Checks the size before reading and again after a bounded read (limit + 1
    bytes), so a file that grows between the two cannot slip past the limit.
    """
    size = path.stat().st_size
    if size > limit:
        raise InputTooLargeError(
            f"{label} is {size} bytes, over the {limit}-byte limit; refusing to read it "
            "(files are never truncated)"
        )
    with path.open("rb") as fh:
        data = fh.read(limit + 1)
    if len(data) > limit:
        raise InputTooLargeError(
            f"{label} grew past the {limit}-byte limit while being read; refusing it"
        )
    return data


def shorten(text: str, limit: int = ECHO_MAX_CHARS) -> str:
    """*text*, or its first *limit* characters plus a marker naming how many were cut."""
    if len(text) <= limit:
        return text
    return f"{text[:limit]}...[{len(text) - limit} more chars]"


def bounded_text(text: str, limit: int = ECHO_MAX_CHARS) -> str:
    """*text* with control characters escaped (as :func:`repr` escapes them, without the quotes),
    truncated like :func:`shorten`. For values shown inline, where a newline must not start a
    forged output line and quotes would change the familiar format."""
    escaped = repr(text[:limit])[1:-1]
    if len(text) <= limit:
        return escaped
    return f"{escaped}...[{len(text) - limit} more chars]"


def bounded_repr(text: str, limit: int = ECHO_MAX_CHARS) -> str:
    """``repr(text)``, truncated like :func:`shorten`; the marker stays outside the quotes."""
    if len(text) <= limit:
        return repr(text)
    return f"{text[:limit]!r}...[{len(text) - limit} more chars]"


def escape_unencodable_output() -> None:
    """Escape characters the console cannot encode instead of crashing mid-report.

    Export strings are attacker-adjacent JSON and can carry lone surrogates or characters
    outside the console encoding; the text, HTML and narrative outputs would otherwise die
    with a UnicodeEncodeError traceback half way through. Lives here because this module is
    the one allowed to touch I/O streams.
    """
    for stream in (sys.stdout, sys.stderr):
        if isinstance(stream, io.TextIOWrapper):
            stream.reconfigure(errors="backslashreplace")
