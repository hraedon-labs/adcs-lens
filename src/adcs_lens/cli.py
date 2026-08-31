"""Command-line front door. Stdlib ``argparse`` only.

    adcs-lens ingest <export-dir>            # parse + summarize an export
    adcs-lens doctor <export-dir> [--json|--sarif|--html]   # prioritized posture + lifecycle
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from datetime import UTC, datetime

from adcs_lens import __version__
from adcs_lens.detection import is_degradation_note, run_all
from adcs_lens.diff import diff_findings, incomplete_coverage_checks
from adcs_lens.display import (
    render_diff_html,
    render_diff_json,
    render_diff_sarif,
    render_diff_text,
    render_html,
    render_json,
    render_sarif,
    render_text,
)
from adcs_lens.ingest import IngestError, collector_compat_warning, ingest
from adcs_lens.model import SEVERITY_RANK, Estate, Severity
from adcs_lens.suppression import (
    apply_suppressions,
    format_suppression_summary,
    load_suppressions,
    suppression_summary,
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="adcs-lens",
        description="Local-first, read-only AD CS / PKI posture analysis.",
    )
    parser.add_argument("--version", action="version", version=f"adcs-lens {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_ingest = sub.add_parser("ingest", help="Parse a collector export and summarize it.")
    p_ingest.add_argument("export_dir", help="Directory produced by the collector.")

    p_doctor = sub.add_parser("doctor", help="Prioritized posture + lifecycle findings.")
    p_doctor.add_argument("export_dir", help="Directory produced by the collector.")
    fmt = p_doctor.add_mutually_exclusive_group()
    fmt.add_argument("--json", action="store_true", help="Emit the JSON envelope.")
    fmt.add_argument(
        "--sarif",
        action="store_true",
        help="Emit SARIF v2.1.0 output for CI / GRC integration.",
    )
    fmt.add_argument(
        "--html",
        action="store_true",
        help="Emit a self-contained HTML evidence report.",
    )
    p_doctor.add_argument(
        "--warn-days",
        type=int,
        default=90,
        help=(
            "Flag CA certificates within this many days of expiry (default: 90). "
            "CRLs use a proportional early-warning window of their own validity period."
        ),
    )
    p_doctor.add_argument(
        "--severity",
        choices=[sev.value for sev in Severity],
        default="info",
        help="Minimum severity to include in output (default: info = all).",
    )
    p_doctor.add_argument(
        "--exit-code",
        action="store_true",
        help="Exit non-zero when any finding meets or exceeds --severity (for CI gating).",
    )
    p_doctor.add_argument(
        "--suppressions",
        metavar="FILE",
        help="JSON file of risk-accepted findings to exclude from the --exit-code gate.",
    )
    p_doctor.add_argument(
        "--narrate",
        action="store_true",
        help="Print a deterministic executive summary to stderr after the findings.",
    )

    p_diff = sub.add_parser(
        "diff", help="Drift between two exports (Stance 2): what got worse / better."
    )
    p_diff.add_argument("old_export", help="The earlier (baseline) export directory.")
    p_diff.add_argument("new_export", help="The later (current) export directory.")
    fmt = p_diff.add_mutually_exclusive_group()
    fmt.add_argument("--json", action="store_true", help="Emit the JSON envelope.")
    fmt.add_argument(
        "--sarif",
        action="store_true",
        help="Emit SARIF v2.1.0 output for CI / GRC integration.",
    )
    fmt.add_argument(
        "--html",
        action="store_true",
        help="Emit a self-contained HTML drift report.",
    )
    p_diff.add_argument(
        "--warn-days",
        type=int,
        default=90,
        help=(
            "Flag CA certificates within this many days of expiry (default: 90). "
            "CRLs use a proportional early-warning window of their own validity period."
        ),
    )
    p_diff.add_argument(
        "--exit-code",
        action="store_true",
        help="Exit non-zero when there are regressions (new or worsened findings). "
        "Content-only changes are reported but do not trip the gate.",
    )
    return parser


def _redact_none(s: str) -> str:
    return s if s not in ("", "None") else "?"


def _compat_warn(estate: Estate) -> None:
    """Warn on stderr when the collector predates the core's minimum (WI-031)."""
    msg = collector_compat_warning(estate.manifest)
    if msg is not None:
        print(f"warning: {msg}", file=sys.stderr)


def _cmd_ingest(export_dir: str) -> int:
    estate = ingest(export_dir)
    _compat_warn(estate)
    m = estate.manifest
    print(f"Ingested export from {_redact_none(m.host)} ({_redact_none(m.domain)})")
    print(
        f"  collected: {_redact_none(m.collected_at)}"
        f"  collector: {_redact_none(m.collector_version)}"
    )
    print(f"  CAs: {len(estate.cas)}   templates: {len(estate.templates)}")
    print(f"  PKI ACLs: {len(estate.acls)}   issuance OIDs: {len(estate.oids)}")
    print(f"  CRLs: {len(estate.crls)}   lifecycle evaluated: {m.certs_parsed}")
    if m.skipped_passes:
        print(f"  skipped passes: {', '.join(m.skipped_passes)}")
    return 0


def _cmd_doctor(
    export_dir: str,
    *,
    as_json: bool,
    as_sarif: bool,
    as_html: bool,
    warn_days: int,
    severity: str,
    exit_code: bool,
    suppressions_path: str | None,
    narrate: bool = False,
) -> int:
    min_rank = SEVERITY_RANK[Severity(severity)]

    estate = ingest(export_dir)
    _compat_warn(estate)
    all_findings = run_all(estate, warn_days=warn_days)

    suppression_payload: dict[str, object] | None = None
    if suppressions_path is not None:
        try:
            rules = load_suppressions(suppressions_path)
        except ValueError as exc:
            return _error(str(exc))
        result = apply_suppressions(all_findings, rules)
        all_findings = list(result.remaining)
        if result.suppressed or result.expired:
            print(format_suppression_summary(result), file=sys.stderr)
        suppression_payload = suppression_summary(result, rules)

    # Lower rank == worse; keep findings at or above the requested floor.
    findings = [f for f in all_findings if SEVERITY_RANK[f.severity] <= min_rank]

    if as_sarif:
        print(render_sarif(findings))
    elif as_html:
        print(render_html(findings))
    elif as_json:
        print(render_json(findings, suppressions=suppression_payload))
    else:
        print(render_text(findings))

    if narrate:
        from adcs_lens.narration import generate_executive_summary

        print(generate_executive_summary(findings), file=sys.stderr)

    # Coverage-gap notes (e.g. LIFECYCLE_NOT_EVALUATED) meet the threshold but are
    # not posture findings, so they do not trip the --exit-code gate.
    if exit_code and any(not is_degradation_note(f) for f in findings):
        return 1
    return 0


def _cmd_diff(
    old_export: str,
    new_export: str,
    *,
    as_json: bool,
    as_sarif: bool,
    as_html: bool,
    warn_days: int,
    exit_code: bool,
) -> int:
    # A single comparison instant keeps cert-expiry "days remaining" titles
    # stable across the two snapshots (a midnight-UTC straddle would otherwise
    # false-flag a content change under WI-028).
    now = datetime.now(UTC)
    old_estate = ingest(old_export)
    new_estate = ingest(new_export)
    _compat_warn(old_estate)
    _compat_warn(new_estate)
    old = run_all(old_estate, now=now, warn_days=warn_days)
    new = run_all(new_estate, now=now, warn_days=warn_days)
    report = diff_findings(
        old,
        new,
        incomplete_checks=incomplete_coverage_checks(new_estate),
    )

    if as_sarif:
        print(render_diff_sarif(report))
    elif as_html:
        print(render_diff_html(report))
    elif as_json:
        print(render_diff_json(report))
    else:
        print(render_diff_text(report))

    # Degradation notes (coverage-gap INFO) are excluded from `regressions` by
    # the DriftReport property itself, so the gate agrees with the JSON/text
    # summary and with `doctor --exit-code` (cli.py:206).
    if exit_code and report.regressions:
        return 1
    return 0


def _error(message: str) -> int:
    print(f"error: {message}", file=sys.stderr)
    return 1


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        if args.command == "ingest":
            return _cmd_ingest(args.export_dir)
        if args.command == "doctor":
            return _cmd_doctor(
                args.export_dir,
                as_json=args.json,
                as_sarif=args.sarif,
                as_html=args.html,
                warn_days=args.warn_days,
                severity=args.severity,
                exit_code=args.exit_code,
                suppressions_path=args.suppressions,
                narrate=args.narrate,
            )
        if args.command == "diff":
            return _cmd_diff(
                args.old_export,
                args.new_export,
                as_json=args.json,
                as_sarif=args.sarif,
                as_html=args.html,
                warn_days=args.warn_days,
                exit_code=args.exit_code,
            )
    except IngestError as exc:
        return _error(str(exc))
    except json.JSONDecodeError as exc:
        return _error(f"malformed JSON in export: {exc}")
    except OSError as exc:
        return _error(f"cannot read export: {exc}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
