# Operating adcs-lens

adcs-lens is a command-line tool, not a service, so "operations" means:
collecting exports on a schedule, analysing them, keeping the exports, and
upgrading. For installation see [`install.md`](install.md). For the meaning of
each finding see the output's consequences text and
[`threat-model.md`](threat-model.md).

## Day to day

```bash
adcs-lens ingest <export>                   # parse and summarize; fails on a bad export
adcs-lens doctor <export>                   # prioritized findings (text)
adcs-lens doctor <export> --json            # stable JSON envelope (schema_version 4)
adcs-lens doctor <export> --sarif           # SARIF v2.1.0 for CI / GRC tools
adcs-lens doctor <export> --html > report.html   # self-contained evidence report
adcs-lens diff <old-export> <new-export>    # what got worse / better since the baseline
```

`--json`, `--sarif` and `--html` are mutually exclusive. Output goes to stdout;
warnings and summaries go to stderr.

### `doctor` options

| Option | Meaning |
|---|---|
| `--severity {critical,high,medium,low,info}` | Minimum severity to show. Default `info` (everything). |
| `--warn-days N` | Flag CA certificates within N days of expiry. Default 90. CRLs use an early-warning window proportional to their own validity period. |
| `--exit-code` | Exit 1 when any posture finding meets `--severity` (for gating). Coverage notes never trip it. |
| `--suppressions FILE` | JSON file of risk-accepted findings, excluded from the `--exit-code` gate (see below). |
| `--narrate` | Print a deterministic executive summary to stderr after the findings. |

`diff` takes `--json`, `--sarif`, `--html`, `--warn-days` and `--exit-code`.

### Exit codes

| Code | `doctor` | `diff` |
|---|---|---|
| 0 | Nothing at or above `--severity`, coverage notes excluded (a run whose only findings are coverage notes exits 0), or no `--exit-code` | No regressions and no coverage loss (or no `--exit-code`) |
| 1 | `--exit-code`: a posture finding meets `--severity` (coverage notes do not count) | `--exit-code`: regressions. This wins over 3. |
| 2 | Usage error, or an invalid `ADCS_LENS_STALE_EXPORT_DAYS` | Same |
| 3 | not used | `--exit-code`: no regressions, but coverage was lost: older findings withheld and/or checks not re-evaluated, even when there was no older finding |
| 4 | The export cannot be read or is rejected, or the `--suppressions` file is unreadable, malformed, invalid or over its size limit | The export cannot be read or is rejected |

Exit 4 prints one `error:` line on stderr and applies with or without
`--exit-code`, so a gate fails closed without mistaking a bad export for a
regression. The README's "Drift and coverage" section has the full meaning of
exit 3 and of "not re-evaluated".

## Configuration reference

There is one environment variable and no configuration file.

| Setting | Default | Effect |
|---|---|---|
| `ADCS_LENS_STALE_EXPORT_DAYS` | `8` | An export older than this many days gets an `EXPORT_STALE` note (also on stderr). A positive integer, 1 to 36500, digits only, no leading zero (`08` is rejected). Anything else exits 2. Set it to match your collection cadence. Export age equals collection age only if the collector host's clock was right. |

Input size limits are policy choices in `src/adcs_lens/limits.py`; the README's
"Input limits" table lists them. A file over its limit is rejected (exit 4),
never truncated.

## Scheduled scans and drift

The pattern the tool is built for: collect an export on a schedule, keep each
one in a dated folder, and `diff` the newest against the previous (or against a
baseline you trust):

```bash
adcs-lens diff <baseline> <latest> --exit-code
```

- The repository ships no scheduled-task or CI wrapper for either half. Not yet
  documented: a tested Task Scheduler definition for the collector. When you
  build one, remember the collector must run where the CA's local registry and
  IIS can be read, under an account with the access described in
  [`install.md`](install.md#what-it-needs-and-why), and that the analysis side
  needs no standing access to AD CS.
- Choose a cadence at or below `ADCS_LENS_STALE_EXPORT_DAYS`, or set the
  variable to match it.
- Use the same collector version on both sides where you can. An export from a
  collector older than 0.10.0 can resolve nothing in `diff`; one older than
  0.13.0 records no value lengths (README, "Drift and coverage" and "A
  published value that is not a certificate or CRL is a finding, not an
  error"). Re-run a current collector after upgrading it.
- Exit 3 means "nothing got worse, but something could not be re-checked".
  Look at the "not re-evaluated" list: it names the missing pass or unread
  object. Do not treat it as clean.
- For SARIF into a GRC or CI tool, use `doctor --sarif` (or `diff --sarif`).
  In SARIF a withheld finding stays open (`baselineState: "unchanged"`).

## Accepting a risk (suppressions)

`doctor --suppressions risks.json` removes reviewed findings from the rendered
output and from the `--exit-code` gate. A summary of what was suppressed, and of
expired rules, is printed on stderr for audit. The file is a JSON object:

```json
{
  "suppressions": [
    {
      "check": "CRL_UNPARSEABLE",
      "subject": "<the finding's subject, exactly as the report shows it>",
      "reason": "Why this is accepted, and who accepted it",
      "expires": "2027-06-30"
    }
  ]
}
```

`check` and `reason` are required; `subject` (omit it to match every finding of
that check) and `expires` are optional. A date-only `expires` stays active
through the end of that day (UTC). An expired rule is not applied and is
reported. The first matching active rule wins. The file limit is 4 MiB.

## Keeping exports

adcs-lens keeps nothing between runs, so the exports are the record. Keep each
export you may need to `diff` or to show an auditor, store it with restricted
access (it describes your PKI and its permissions), and never commit it. There is
no backup or restore procedure for the tool itself. To recover, reinstall it and
point it at the saved exports. Exports are plain files; there is no database to migrate.

## Upgrading and rolling back

1. Read the CHANGELOG entries for every version between yours and the target.
2. Windows: pull the new checkout and re-run `install-windows.ps1` (it upgrades
   in place). pip: reinstall from the new checkout or release.
3. Re-run the **collector** from the same checkout. A newer analyser reads older
   exports, but with less certainty (see "Scheduled scans and drift").
4. `adcs-lens --version`, then `doctor` an existing export to confirm.

To roll back, install the previous release the same way. No data format on disk
belongs to the analyser, so there is nothing to restore. `schema_version` in
the JSON envelope is 4; a consumer that parses it should check the field.

## Logs and health

The tool writes no log files. Everything it has to say is on stdout (the
report) or stderr (`warning:` and `error:` lines, the suppression summary). If
you schedule it, capture both streams. "Is it healthy" means: the last export is
recent (an `EXPORT_STALE` note says otherwise), `ingest` accepts it, and the
export's `skipped_passes` is empty or expected. A scheduled job should alert on
exit 4 and on any export older than your cadence. Not yet documented: a
monitoring integration. The tool never alerts by design.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Exit 4 with `error: suppression entry ...`, `suppression file ...` | The `--suppressions` file is unreadable, not UTF-8 JSON, not an object with a `suppressions` list, has an entry without a non-empty `check` or `reason`, a bad `expires`, or is over 4 MiB. Fix the file; the message names the entry. |
| Exit 4, `error: ...` about an export | The export is partial, altered, too large, malformed JSON, or a `certs/` file cannot be what the collector wrote. Re-copy the export; if it persists, re-run the collector (current version). The message names the file. |
| Exit 4 on an older export, message says to re-copy or re-run collector 0.13.0 | The old collector recorded no value lengths, so a damaged file cannot be told from a value AD holds. Re-run collector 0.13.0 or later. |
| Lifecycle checks are all "not evaluated" (`LIFECYCLE_NOT_EVALUATED`) | The `[certs]` extra is not installed, or the export has no `certs` pass. Install `adcs-lens[certs]`; check `skipped_passes`. |
| `COLLECTOR_VERSION_UNVERIFIED`, `PASS_NOT_COLLECTED` or a `warning:` about the collector version | The export is from a collector older than the minimum (0.8.0), or of unknown version. Re-run the current collector. `diff` withholds every resolution against it. |
| `EXPORT_STALE` | The export is older than 8 days (or `ADCS_LENS_STALE_EXPORT_DAYS`). Collect again, or raise the threshold. `EXPORT_TIMESTAMP_INVALID` means `collected_at` is missing, unparseable or in the future: check the collector host's clock. |
| `*_NOT_EVALUATED` notes (`CA_REGISTRY_NOT_EVALUATED`, `ENROLLMENT_ENDPOINTS_NOT_EVALUATED`, `CA_SECURITY_NOT_EVALUATED`, `PKI_ACL_UNREADABLE`, `TEMPLATE_ACL_UNREADABLE`) | The collector could not read that input: run it on the CA host, under an account with more access, or on each CA. These are coverage notes, not a clean bill of health. |
| `diff` exits 3 | Coverage was lost between the exports. Read the "not re-evaluated" list and fix the collection (a skipped pass, an unreadable ACL, a different host). |
| `diff` exits 1 on a finding you did not change | A regression includes a finding first observed after coverage was gained ("newly visible"). It is labelled apart from new findings in the output. |
| `CRL_UNPARSEABLE` / `CA_CERT_UNPARSEABLE` on a CDP or AIA object | A PKI tool wrote a placeholder byte into an object that holds no CRL or certificate (PSPKI is one known cause). It is a LOW finding about the estate, not a damaged export. Clean up the object or suppress it with a reason. |
| Collector: `refusing to write outside the output directory` or `...through a reparse point` | `-OutDir` is a UNC or device path, or a path inside `-OutDir` passes through a junction or symlink. Use a plain local folder with no links inside it. |
| Collector: nothing from LDAP over SSH | The double-hop problem. Use `-LdapUserB64` / `-LdapPassB64`, or a console / RDP session ([`install.md`](install.md#explicit-credentials-ssh-sessions)). |
| `install-windows.ps1` cannot find Python | Install Python 3.12 or later and run the script from an elevated prompt. If the `[certs]` install fails (no C compiler or no network), use `-NoCerts`; lifecycle checks then degrade to notes. Not yet documented: other installer failures. |
| Windows PowerShell rejects the script as unsigned | Use `-ExecutionPolicy Bypass` for that call, or sign the script. |

If a symptom is not here, run `adcs-lens ingest <export>` first: most problems
are an export problem, and ingest names the file.
