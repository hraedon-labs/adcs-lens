"""Per-file input size limits. Stdlib-only.

Every file adcs-lens reads goes through :func:`read_bounded`. An oversized file
is REJECTED, never truncated: a truncated JSON array or CRL would parse as a
smaller, cleaner estate. The limits are policy choices set generously above
any realistic AD CS export, not measurements (see README "Input limits").
"""

from __future__ import annotations

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
