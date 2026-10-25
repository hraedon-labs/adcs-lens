"""Ambiguous risk acceptance is refused before findings are rendered."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from adcs_lens import limits
from adcs_lens.cli import EXIT_DATA_ERROR, main
from adcs_lens.suppression import load_suppressions


@pytest.mark.parametrize(
    "document",
    [
        '{"suppressions": [], "suppressions": []}',
        '{"suppressions": [{"check": "ESC8", "check": "ESC6", "reason": "reviewed"}]}',
        '{"suppressions": [{"check": "ESC8", "reason": "reviewed", '
        '"subject": "/synthetic-a", "subject": null}]}',
        '{"suppressions": [{"check": "ESC8", "reason": "first", "reason": "second"}]}',
        '{"suppressions": [{"check": "ESC8", "reason": "reviewed", '
        '"expires": "2020-01-01", "expires": null}]}',
        '{"suppressions": [{"check": "ESC8", "reason": "reviewed", '
        '"subject": "/synthetic-a", "subj\\u0065ct": null}]}',
        '{"suppressions": [], "metadata": {"note": "first", "note": "second"}}',
    ],
    ids=["list", "check", "subject", "reason", "expiry", "escaped-key", "metadata"],
)
def test_repeated_suppression_keys_are_refused_before_interpretation(
    tmp_path: Path, document: str
) -> None:
    path = tmp_path / "suppressions.json"
    path.write_text(document, encoding="utf-8-sig")
    before = path.read_bytes()
    with pytest.raises(ValueError, match="duplicate JSON key"):
        load_suppressions(path)
    assert path.read_bytes() == before


@pytest.mark.parametrize("format_args", [[], ["--json"], ["--sarif"], ["--html"]])
def test_doctor_does_not_render_with_ambiguous_risk_acceptance(
    json_export: Path,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    format_args: list[str],
) -> None:
    path = tmp_path / "suppressions.json"
    path.write_text(
        '{"suppressions": [{"check": "ESC6", "reason": "one synthetic CA", '
        '"subject": "Synthetic CA", "subject": null}]}',
        encoding="utf-8",
    )
    assert main(["doctor", str(json_export), "--suppressions", str(path), *format_args]) == (
        EXIT_DATA_ERROR
    )
    captured = capsys.readouterr()
    assert captured.out == ""
    errors = [line for line in captured.err.splitlines() if line.startswith("error:")]
    assert len(errors) == 1
    assert "duplicate JSON key" in errors[0]
    assert "Traceback" not in captured.err


def _write_deep_json(path: Path) -> None:
    # Small enough for the file bound, but beyond CPython's decoder nesting
    # limit on all supported versions. Do not change process recursion limits.
    path.write_text("[" * 120_000 + "0" + "]" * 120_000, encoding="utf-8")


def test_excessive_json_nesting_is_a_suppression_value_error(tmp_path: Path) -> None:
    path = tmp_path / "deep.json"
    _write_deep_json(path)
    with pytest.raises(ValueError, match="nested too deeply"):
        load_suppressions(path)


@pytest.mark.parametrize("format_args", [[], ["--json"], ["--sarif"], ["--html"]])
def test_doctor_reports_excessive_suppression_nesting_without_rendering(
    json_export: Path,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    format_args: list[str],
) -> None:
    path = tmp_path / "deep.json"
    _write_deep_json(path)
    assert main(["doctor", str(json_export), "--suppressions", str(path), *format_args]) == (
        EXIT_DATA_ERROR
    )
    captured = capsys.readouterr()
    assert captured.out == ""
    errors = [line for line in captured.err.splitlines() if line.startswith("error:")]
    assert len(errors) == 1
    assert "nested too deeply" in errors[0]
    assert "Traceback" not in captured.err


# --- closed key sets ---------------------------------------------------------


def _write(tmp_path: Path, document: object) -> Path:
    path = tmp_path / "suppressions.json"
    text = document if isinstance(document, str) else json.dumps(document)
    path.write_text(text, encoding="utf-8")
    return path


_RULE = {"check": "ESC8", "reason": "reviewed"}


@pytest.mark.parametrize(
    ("rule", "key", "hint"),
    [
        ({**_RULE, "Subject": "/synthetic-a"}, "Subject", "'subject'"),
        ({**_RULE, "Expires": "2020-01-01"}, "Expires", "'expires'"),
        ({**_RULE, "subjects": ["/synthetic-a"]}, "subjects", None),
        ({**_RULE, "expiry": "2020-01-01"}, "expiry", None),
        ({**_RULE, "note": "approved"}, "note", None),
        ({**_RULE, "CHECK": "ESC6"}, "CHECK", "'check'"),
    ],
    ids=["Subject", "Expires", "subjects", "expiry", "note", "CHECK"],
)
def test_unknown_rule_key_is_refused(
    tmp_path: Path, rule: dict[str, object], key: str, hint: str | None
) -> None:
    path = _write(tmp_path, {"suppressions": [rule]})
    with pytest.raises(ValueError) as info:
        load_suppressions(path)
    message = str(info.value)
    assert message.startswith(f"suppression entry 0 has unknown key {key!r}")
    assert "allowed keys: check, subject, reason, expires, metadata" in message
    if hint is not None:
        assert f"case-sensitive; did you mean {hint}?" in message
    else:
        assert "did you mean" not in message


def test_unknown_key_is_reported_before_a_missing_field(tmp_path: Path) -> None:
    # {"Check": ...} names the typo, not just "missing non-empty 'check'".
    path = _write(tmp_path, {"suppressions": [{"Check": "ESC8", "reason": "r"}]})
    with pytest.raises(ValueError, match="unknown key 'Check'"):
        load_suppressions(path)


def test_unknown_key_in_a_later_entry_names_that_entry(tmp_path: Path) -> None:
    path = _write(tmp_path, {"suppressions": [_RULE, {**_RULE, "Subject": "x"}]})
    with pytest.raises(ValueError, match="^suppression entry 1 has unknown key 'Subject'"):
        load_suppressions(path)


@pytest.mark.parametrize("key", ["Suppressions", "rules", "version", "note"])
def test_unknown_top_level_key_is_refused(tmp_path: Path, key: str) -> None:
    path = _write(tmp_path, {"suppressions": [], key: []})
    with pytest.raises(ValueError) as info:
        load_suppressions(path)
    message = str(info.value)
    assert message.startswith(f"suppression file has unknown key {key!r}")
    assert "allowed keys: suppressions, metadata" in message


def test_unknown_key_message_is_bounded(tmp_path: Path) -> None:
    key = "x" * 100_000
    path = _write(tmp_path, {"suppressions": [{**_RULE, key: 1}]})
    with pytest.raises(ValueError) as info:
        load_suppressions(path)
    message = str(info.value)
    assert "[99920 more chars]" in message
    assert len(message) < 300


@pytest.mark.parametrize("value", [{}, {"ticket": "CHG-0001", "nested": {"a": [1, None]}}])
def test_metadata_is_accepted_and_uninterpreted(tmp_path: Path, value: object) -> None:
    path = _write(
        tmp_path,
        {
            "metadata": value,
            "suppressions": [{**_RULE, "subject": "/synthetic-a", "metadata": value}],
        },
    )
    (rule,) = load_suppressions(path)
    assert (rule.check, rule.subject, rule.reason, rule.expires) == (
        "ESC8",
        "/synthetic-a",
        "reviewed",
        None,
    )


def test_metadata_keys_never_reach_the_rule(tmp_path: Path) -> None:
    # Keys inside metadata that look like rule fields are opaque data.
    path = _write(
        tmp_path,
        {"suppressions": [{**_RULE, "metadata": {"subject": "/x", "expires": "2000-01-01"}}]},
    )
    (rule,) = load_suppressions(path)
    assert rule.subject is None
    assert rule.expires is None


@pytest.mark.parametrize("value", [None, "note", [], 1, True])
@pytest.mark.parametrize("where", ["document", "rule"])
def test_metadata_must_be_an_object(tmp_path: Path, value: object, where: str) -> None:
    if where == "document":
        document: dict[str, object] = {"suppressions": [_RULE], "metadata": value}
        expected = "^suppression file 'metadata' must be a JSON object"
    else:
        document = {"suppressions": [{**_RULE, "metadata": value}]}
        expected = "^suppression entry 0 'metadata' must be a JSON object"
    with pytest.raises(ValueError, match=expected):
        load_suppressions(_write(tmp_path, document))


def test_duplicate_key_inside_rule_metadata_is_refused(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        '{"suppressions": [{"check": "ESC8", "reason": "r", '
        '"metadata": {"ticket": "a", "ticket": "b"}}]}',
    )
    with pytest.raises(ValueError, match="duplicate JSON key 'ticket'"):
        load_suppressions(path)


# --- the subject wildcard ------------------------------------------------------


@pytest.mark.parametrize("subject", ["", "   ", "\t\n"])
def test_blank_subject_is_refused_not_a_wildcard(tmp_path: Path, subject: str) -> None:
    path = _write(tmp_path, {"suppressions": [{**_RULE, "subject": subject}]})
    with pytest.raises(ValueError, match=r"^suppression entry 0 'subject' is blank \(omit"):
        load_suppressions(path)


def test_null_subject_is_refused_not_a_wildcard(tmp_path: Path) -> None:
    path = _write(tmp_path, {"suppressions": [{**_RULE, "subject": None}]})
    with pytest.raises(ValueError, match=r"^suppression entry 0 'subject' must be a string \(omit"):
        load_suppressions(path)


def test_omitted_subject_is_the_check_wide_wildcard(tmp_path: Path) -> None:
    (rule,) = load_suppressions(_write(tmp_path, {"suppressions": [_RULE]}))
    assert rule.subject is None


def test_subject_is_still_stripped(tmp_path: Path) -> None:
    path = _write(tmp_path, {"suppressions": [{**_RULE, "subject": "  /synthetic-a "}]})
    (rule,) = load_suppressions(path)
    assert rule.subject == "/synthetic-a"


def test_null_expires_is_refused(tmp_path: Path) -> None:
    path = _write(tmp_path, {"suppressions": [{**_RULE, "expires": None}]})
    with pytest.raises(ValueError, match=r"'expires' must be an ISO date string \(omit"):
        load_suppressions(path)


def test_invalid_expires_echo_is_bounded(tmp_path: Path) -> None:
    path = _write(tmp_path, {"suppressions": [{**_RULE, "expires": "z" * 100_000}]})
    with pytest.raises(ValueError) as info:
        load_suppressions(path)
    message = str(info.value)
    assert message.startswith("suppression entry 0 'expires' is not a valid ISO date: 'zzz")
    assert len(message) < 300


@pytest.mark.parametrize("format_args", [[], ["--json"]])
def test_doctor_refuses_a_typoed_key_without_rendering(
    json_export: Path,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    format_args: list[str],
) -> None:
    path = _write(
        tmp_path,
        {"suppressions": [{"check": "ESC6", "reason": "one CA", "Subject": "Synthetic CA"}]},
    )
    assert main(["doctor", str(json_export), "--suppressions", str(path), *format_args]) == (
        EXIT_DATA_ERROR
    )
    captured = capsys.readouterr()
    assert captured.out == ""
    errors = [line for line in captured.err.splitlines() if line.startswith("error:")]
    assert len(errors) == 1
    assert "unknown key 'Subject'" in errors[0]
    assert "Traceback" not in captured.err


# --- decoder refusals and bounded echoes ------------------------------------------


@pytest.mark.parametrize("where", ["expires", "metadata"])
def test_integer_beyond_the_digit_limit_is_malformed_json(tmp_path: Path, where: str) -> None:
    number = "9" * 5000
    if where == "expires":
        document = '{"suppressions": [{"check": "ESC8", "reason": "r", "expires": ' + number + "}]}"
    else:
        document = '{"suppressions": [], "metadata": {"n": ' + number + "}}"
    path = _write(tmp_path, document)
    with pytest.raises(ValueError, match=r"^suppression file contains malformed JSON \(") as info:
        load_suppressions(path)
    assert not isinstance(info.value, limits.InputTooLargeError)
    assert len(str(info.value)) < 400


def test_oversized_file_is_still_input_too_large(tmp_path: Path) -> None:
    path = tmp_path / "big.json"
    path.write_bytes(b" " * (limits.SUPPRESSIONS_MAX_BYTES + 1))
    with pytest.raises(limits.InputTooLargeError):
        load_suppressions(path)


def test_duplicate_key_message_is_bounded(tmp_path: Path) -> None:
    key = "s" * 100_000
    path = _write(tmp_path, '{"suppressions": [], "' + key + '": 1, "' + key + '": 2}')
    with pytest.raises(ValueError) as info:
        load_suppressions(path)
    message = str(info.value)
    assert message.startswith("suppression file contains duplicate JSON key 'sss")
    assert message.endswith("...[99920 more chars]")
    assert len(message) < 200


def test_both_loaders_share_one_duplicate_key_hook() -> None:
    import adcs_lens.ingest as ingest_module
    import adcs_lens.suppression as suppression_module
    from adcs_lens.strict_json import unique_keys_hook

    for module in (ingest_module, suppression_module):
        source = Path(module.__file__ or "").read_text(encoding="utf-8")
        assert "object_pairs_hook=unique_keys_hook" in source
        assert module.unique_keys_hook is unique_keys_hook


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("", "''"),
        ("a" * 80, repr("a" * 80)),
        ("a" * 81, repr("a" * 80) + "...[1 more chars]"),
    ],
)
def test_bounded_repr(text: str, expected: str) -> None:
    assert limits.bounded_repr(text) == expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("ESC6", "ESC6"),
        ("/CertSrv", "/CertSrv"),
        ("x\nerror: forged\x1b[31m", "x\\nerror: forged\\x1b[31m"),
        ("a" * 81, "a" * 80 + "...[1 more chars]"),
    ],
)
def test_bounded_text(text: str, expected: str) -> None:
    assert limits.bounded_text(text) == expected


def test_expired_rule_echo_cannot_forge_lines_or_grow_unbounded() -> None:
    from datetime import UTC, datetime

    from adcs_lens.suppression import (
        SuppressionRule,
        apply_suppressions,
        format_suppression_summary,
    )

    forged = "x\nerror: forged line\x1b[31m"
    rules = (
        SuppressionRule(
            check=forged, subject=forged, reason="r", expires=datetime(2000, 1, 1, tzinfo=UTC)
        ),
        SuppressionRule(
            check="C" * 100_000,
            subject="S" * 100_000,
            reason="r",
            expires=datetime(2000, 1, 1, tzinfo=UTC),
        ),
    )
    result = apply_suppressions([], rules, now=datetime(2026, 1, 1, tzinfo=UTC))
    for text in (*result.warnings, format_suppression_summary(result)):
        assert "\x1b" not in text
        assert not any(line.startswith("error:") for line in text.splitlines())
        assert max(len(line) for line in text.splitlines()) < 400


def test_stale_collector_version_warning_cannot_forge_lines() -> None:
    from adcs_lens.ingest import collector_compat_warning
    from tests.test_ingest import _manifest  # the existing manifest builder

    msg = collector_compat_warning(_manifest("0.7.0\nwarning: forged"))
    assert msg is not None
    assert "\n" not in msg


def test_shorten() -> None:
    assert limits.shorten("0.13.0") == "0.13.0"
    assert limits.shorten("9" * 100) == "9" * 80 + "...[20 more chars]"


# --- every documented example still loads ---------------------------------------

_REPO = Path(__file__).resolve().parent.parent
_FENCE = re.compile(r"```json\n(.*?)```", re.DOTALL)


def _documented_suppression_examples() -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    for doc in [_REPO / "README.md", *sorted((_REPO / "docs").glob("*.md"))]:
        for n, block in enumerate(_FENCE.findall(doc.read_text(encoding="utf-8"))):
            if '"suppressions"' in block:
                found.append((f"{doc.relative_to(_REPO)}#{n}", block))
    return found


_EXAMPLES = _documented_suppression_examples()


def test_documentation_has_suppression_examples() -> None:
    names = [name for name, _ in _EXAMPLES]
    assert any(name.startswith("docs/operations.md") for name in names), names
    assert any('"metadata"' in block for _, block in _EXAMPLES)


@pytest.mark.parametrize(("name", "block"), _EXAMPLES, ids=[n for n, _ in _EXAMPLES])
def test_documented_suppression_example_loads(tmp_path: Path, name: str, block: str) -> None:
    rules = load_suppressions(_write(tmp_path, block))
    assert rules, name


# --- unencodable characters in export strings never crash a report ---------------


@pytest.mark.parametrize("fmt", [[], ["--html"], ["--narrate"], ["--json"], ["--sarif"]])
def test_lone_surrogate_in_export_text_is_escaped_not_a_traceback(
    tmp_path: Path, fmt: list[str]
) -> None:
    import subprocess
    import sys

    from tests.fixtures.build_fixture import build_export

    export = tmp_path / "export"
    build_export(export)
    manifest = export / "collector-manifest.json"
    data = json.loads(manifest.read_text(encoding="utf-8-sig"))
    data["collector_version"] = "0.10.0\ud800"
    manifest.write_text(json.dumps(data), encoding="utf-8")
    # A raw report field too: the version echoes are escaped on their own, so only a
    # field printed as collected exercises the stream-level escaping.
    templates = export / "templates.json"
    rows = json.loads(templates.read_text(encoding="utf-8-sig"))
    for row in rows:
        row["display_name"] = row["display_name"] + "\ud800"
    templates.write_text(json.dumps(rows), encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, "-m", "adcs_lens.cli", "doctor", str(export), *fmt],
        capture_output=True,
        timeout=300,
    )
    assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")[-2000:]
    assert b"Traceback" not in proc.stderr
    if fmt in ([], ["--html"]):
        assert b"\\ud800" in proc.stdout
