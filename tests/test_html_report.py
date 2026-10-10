"""Self-contained HTML evidence report (WI-018)."""

from __future__ import annotations

from pathlib import Path

import pytest

from adcs_lens.cli import main
from adcs_lens.detection import Finding
from adcs_lens.display import render_html
from adcs_lens.model import CrlTier, Severity
from tests.fixtures.build_fixture import build_minimal_export


def _f(
    check: str,
    severity: Severity,
    *,
    subject: str = "subj",
    title: str = "title",
    detail: str = "detail",
    source: str = "source",
    tier: CrlTier | None = None,
) -> Finding:
    return Finding(
        check=check,
        severity=severity,
        title=title,
        subject=subject,
        detail=detail,
        source=source,
        tier=tier,
    )


# --- CLI structure -----------------------------------------------------------


def test_html_is_selfcontained_document(
    json_export: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rc = main(["doctor", str(json_export), "--html"])
    assert rc == 0
    out = capsys.readouterr().out
    assert out.startswith("<!DOCTYPE html>")
    assert out.rstrip().endswith("</html>")
    # Inline CSS present, no external resource links.
    assert "<style>" in out
    assert '<link rel="stylesheet"' not in out
    assert "<script" not in out
    assert 'src="http' not in out
    assert 'href="http' not in out


def test_html_header_closed_before_main(
    json_export: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    main(["doctor", str(json_export), "--html"])
    out = capsys.readouterr().out
    assert out.count("<header>") == 1
    assert out.count("</header>") == 1
    # <header> must close before <main> opens (HTML5 forbids <main> in <header>).
    assert out.index("</header>") < out.index("<main>")


def test_html_groups_findings_into_severity_bands(
    json_export: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    main(["doctor", str(json_export), "--html"])
    out = capsys.readouterr().out
    # The fixture's CRITICAL ESC6 sits in a critical band section.
    assert 'class="band sev-critical"' in out
    assert "ESC6" in out


def test_html_includes_consequence_block(
    json_export: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    main(["doctor", str(json_export), "--html"])
    out = capsys.readouterr().out
    assert 'class="consequence"' in out
    assert "In plain terms." in out
    assert "Risk." in out
    assert "How to fix." in out


def test_html_and_json_are_mutually_exclusive(
    json_export: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["doctor", str(json_export), "--html", "--json"])
    assert exc_info.value.code == 2
    assert "not allowed with" in capsys.readouterr().err


def test_html_exit_code_trips_on_critical(json_export: Path) -> None:
    assert (
        main(["doctor", str(json_export), "--html", "--exit-code", "--severity", "critical"]) == 1
    )


def test_html_no_findings_page(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # An effectively-empty export yields only INFO notes; a 'critical' floor
    # leaves zero findings, so the HTML shows the clean-state page.
    export = build_minimal_export(tmp_path)
    assert main(["doctor", str(export), "--html", "--severity", "critical"]) == 0
    out = capsys.readouterr().out
    assert "No findings" in out
    assert 'class="band' not in out


# --- Direct unit tests -------------------------------------------------------


def test_render_html_escapes_all_finding_fields() -> None:
    findings = [
        _f(
            check='<script>alert("x")</script>',
            severity=Severity.CRITICAL,
            subject="<b>CA</b>",
            title="A & B",
            detail='detail "quoted"',
            source="src <tag>",
        )
    ]
    out = render_html(findings)
    # No raw dangerous markup reaches the output.
    assert "<script>alert" not in out
    # Every dynamic field is escaped.
    assert "&lt;script&gt;" in out  # check
    assert "<b>CA</b>" not in out
    assert "&lt;b&gt;CA&lt;/b&gt;" in out  # subject
    assert "A &amp; B" in out  # title
    assert "&quot;quoted&quot;" in out  # detail
    assert "&lt;tag&gt;" in out  # source


def test_render_html_escapes_consequence_catalogue(monkeypatch: pytest.MonkeyPatch) -> None:
    # If the catalogue ever carries HTML metacharacters, it must be escaped.
    from adcs_lens import display
    from adcs_lens.consequences import ConsequenceEntry

    monkeypatch.setattr(
        display,
        "consequence_for",
        lambda _check: ConsequenceEntry(
            check="ESC6",
            summary="<i>summary</i>",
            consequence="a & b",
            remediation='fix "it"',
        ),
    )
    out = display.render_html([_f("ESC6", Severity.CRITICAL)])
    assert "<i>summary</i>" not in out
    assert "&lt;i&gt;summary&lt;/i&gt;" in out
    assert "a &amp; b" in out
    assert "&quot;it&quot;" in out


def test_render_html_unknown_check_omits_consequence() -> None:
    out = render_html([_f("BOGUS_CHECK", Severity.HIGH)])
    assert 'class="consequence"' not in out
    assert "In plain terms." not in out


def test_render_html_is_deterministic() -> None:
    findings = [
        _f("ESC9", Severity.HIGH),
        _f("ESC1", Severity.CRITICAL),
    ]
    assert render_html(findings) == render_html(findings)


def test_render_html_bands_worst_first() -> None:
    findings = [
        _f("ESC9", Severity.HIGH),
        _f("ESC1", Severity.CRITICAL),
        _f("ESC8", Severity.MEDIUM),
    ]
    out = render_html(findings)
    crit_pos = out.index('class="band sev-critical"')
    high_pos = out.index('class="band sev-high"')
    med_pos = out.index('class="band sev-medium"')
    assert crit_pos < high_pos < med_pos


def test_render_html_tier_in_subject() -> None:
    out = render_html([_f("CRL_EXPIRY", Severity.CRITICAL, tier=CrlTier.ROOT)])
    assert "(root-tier)" in out


def test_render_html_empty_findings() -> None:
    out = render_html([])
    assert out.startswith("<!DOCTYPE html>")
    assert "No findings" in out
    assert 'class="band' not in out


def test_render_html_counts_in_summary() -> None:
    findings = [
        _f("ESC1", Severity.CRITICAL),
        _f("ESC8", Severity.CRITICAL),
        _f("ESC9", Severity.HIGH),
    ]
    out = render_html(findings)
    # Two critical findings, one high; summary badges carry the counts.
    assert "Critical 2" in out
    assert "High 1" in out
    # Band headings also carry per-band counts.
    assert "Critical <span class=\"count\">(2)</span>" in out


def test_render_html_includes_table_of_contents() -> None:
    findings = [
        _f("ESC1", Severity.CRITICAL),
        _f("ESC9", Severity.HIGH),
        _f("ESC8", Severity.MEDIUM),
    ]
    out = render_html(findings)
    assert '<nav class="toc"' in out
    # TOC links to each band that has findings.
    assert 'href="#critical"' in out
    assert 'href="#high"' in out
    assert 'href="#medium"' in out
    # TOC shows counts (inside a count span).
    assert 'Critical <span class="count">(1)</span>' in out
    assert 'High <span class="count">(1)</span>' in out
    assert 'Medium <span class="count">(1)</span>' in out
    # Bands have matching ids.
    assert '<section class="band sev-critical" id="critical"' in out
    assert '<section class="band sev-high" id="high"' in out
    assert '<section class="band sev-medium" id="medium"' in out


def test_render_html_toc_omits_empty_severity_bands() -> None:
    findings = [_f("ESC1", Severity.CRITICAL)]
    out = render_html(findings)
    assert 'href="#critical"' in out
    assert 'href="#high"' not in out
    assert 'href="#medium"' not in out
    assert 'href="#low"' not in out
    assert 'href="#info"' not in out


def test_render_html_toc_not_shown_when_no_findings() -> None:
    out = render_html([])
    assert '<nav class="toc"' not in out
