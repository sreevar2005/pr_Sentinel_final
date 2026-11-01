# prscreen

Screens a pull request's diff for suspicious or risky changes and explains the evidence to a
human reviewer. It looks for things like leaked secrets, unexpected network calls, obfuscated
code, dangerous shell commands, weakened security settings and CI changes. It only reports:
it never approves, rejects or edits a pull request, and it never calls code or people malicious.

> **Status: stage 1 of 6.** The diff parser, the finding model, five output formats and the CLI
> are done and tested. One detector (hidden bidirectional characters, "Trojan Source") is in
> place to prove the pipeline end to end. See [Roadmap](#roadmap).

## Quick start

Needs Python 3.12+ and [uv](https://docs.astral.sh/uv/).

```bash
uv sync
uv run pytest
uv run prscreen scan --git origin/main...HEAD
```

Other inputs and outputs:

```bash
git diff main...my-branch | uv run prscreen scan              # diff on stdin
uv run prscreen scan --diff pr.diff --format markdown         # job summary / comment
uv run prscreen scan --diff pr.diff --format sarif --output prscreen.sarif
uv run prscreen explain                                       # list rules
uv run prscreen explain OBF001                                # what a rule means
```

| Format | For |
| --- | --- |
| `text` | terminals and logs |
| `markdown` | GitHub job summary, PR comment |
| `github` | inline annotations on the PR's changed lines (GitHub Actions) |
| `sarif` | GitHub code scanning and other security dashboards |
| `json` | scripts and the evaluation harness |

Exit codes: `0` the scan finished (findings never fail a build), `1` a detector crashed and the
results are incomplete, `2` bad input or usage.

## What a finding looks like

Every finding carries the evidence line, why the pattern may be risky, the common harmless
reasons for it, a severity and a confidence. The harmless reasons are there on purpose: most
findings are honest mistakes or false alarms, and the report should never read as an accusation.

```text
HIGH   OBF001  auth.py:2  Hidden bidirectional control character
      evidence:   if access_level != "user\u202e \u2066// Check if admin\u2069 \u2066":
      detail:     Contains U+202E RLO at column 25, U+2066 LRI at column 27, ...
      why:        Invisible Unicode controls change the order in which text is displayed, ...
      benign if:  Right-to-left text (Arabic, Hebrew, Persian) in strings, comments or ...
      confidence: high
```

## Design decisions

The tool reads hostile input, so it is built to be hard to turn against its users.

- **It never runs pull request code.** It only reads diff text. `--git` disables external diff
  drivers and textconv filters, which a repository's `.gitattributes` could otherwise select.
- **No runtime dependencies.** The core is standard-library Python, so the job that reads
  untrusted diffs pulls in no third-party code.
- **Strict diff parsing.** Hunks are read by their declared line counts, so a removed line like
  `-- note` (shown as `--- note`) cannot fake a file header. Lines split on `\n` only, so
  characters such as U+2028 cannot make one line look like two.
- **Escaped output.** Control, invisible and bidi characters in paths and evidence are shown as
  `\uXXXX`. Markdown output escapes HTML, links and `@mentions`. Annotations escape the
  characters GitHub's workflow-command parser treats specially. Text printed in a GitHub Actions
  log is wrapped in `stop-commands`, so evidence starting with `::` cannot run a workflow command.
- **Noise limits.** At most 20 findings per rule per file; the rest are counted, not listed.
  Findings get a fingerprint that ignores line numbers, for tracking across pushes.
- **Failures are visible.** If one detector crashes, the others still report and the result is
  marked incomplete (exit code 1), instead of looking like a clean scan.

## Roadmap

1. ✅ Diff parser, finding model, output formats, `scan` and `explain` commands
2. Detectors: secrets, dangerous execution and install hooks, CI/workflow weakening, new network
   endpoints, obfuscation, dependency changes, weakened security settings, sensitive paths
3. Evaluation corpus of risky and harmless look-alike PRs, an `eval` command, published
   precision and false-alarm numbers
4. GitHub Action (read-only token, no secrets), CI, threat model, setup guide
5. Optional AI layer that can explain and add questions but never remove a finding, with
   prompt-injection tests
6. Demo repository with one PR per category and a clean PR where the tool stays quiet

## License

MIT
