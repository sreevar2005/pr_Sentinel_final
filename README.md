# prscreen

Screens a pull request's diff for suspicious or risky changes and explains the evidence to a
human reviewer. It looks for things like leaked secrets, unexpected network calls, obfuscated
code, dangerous shell commands, weakened security settings and CI changes. It only reports:
it never approves, rejects or edits a pull request, and it never calls code or people malicious.

**At a glance**

- **45 rules in 8 categories**, measured on 65 labeled cases and 95 real merged pull requests:
  95% recall on the labeled cases, and **0 of 95** real PRs got a medium or high finding
  ([evaluation](#evaluation)).
- **A GitHub Action** that needs only a read-only token and no secrets, so it is safe on pull
  requests from forks ([setup](docs/setup.md), [threat model](docs/threat-model.md)).
- **An optional AI reviewer** that can add questions but never remove a finding
  ([AI design](docs/ai.md)).
- **A demo**: 10 pull requests, each planting one kind of risky change plus one clean one, with the
  findings for each in [docs/demo.md](docs/demo.md).

## Use it on GitHub

```yaml
on:
  pull_request:
permissions:
  contents: read
jobs:
  screen:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0
          persist-credentials: false
      - uses: sreevar2005/pr_Sentinel_final@<commit-sha>
```

Findings appear as annotations on the changed lines and in the job summary. prscreen needs no
secrets and no write access, so it works on pull requests from forks. It never comments, approves,
blocks or edits. [docs/setup.md](docs/setup.md) covers the inputs, SARIF upload, and how to stop a
PR from simply deleting the check.

## What it checks

| Category | Rules | Examples |
| --- | --- | --- |
| Secrets | SEC001–005 | private keys, cloud and SaaS tokens, hardcoded passwords, `.env` files |
| Execution | EXE001–006 | `curl … \| sh`, `eval`, `shell=True`, `pickle.loads`, npm install hooks, `.pth` files |
| CI | CI001–007 | `pull_request_target` with PR checkout, `${{ }}` script injection, unpinned actions |
| Network and data | NET001–005 | raw public IPs, webhook and paste sites, new hosts that receive data, env dumps |
| Obfuscation | OBF001–008 | Trojan Source, invisible characters, homoglyphs, decode-and-exec, binaries, prompt injection |
| Security config | CFG001–005 | TLS verification off, wildcard CORS, CSRF or debug toggles, removed auth checks |
| Dependencies | DEP001–005 | new packages, one-typo names, extra indexes, lockfile-only edits, odd registries |
| Sensitive paths | PATH001–004 | CI config, CODEOWNERS, editor tasks and git hooks, auth and crypto modules |

The full reference, with why each pattern matters and when it is harmless, is in
[docs/rules.md](docs/rules.md) (generated from the code, so it never drifts).

Rules are deliberately conservative where false alarms would be common:

- Matches in test files drop one step in severity and confidence.
- Comments are skipped for code rules.
- Vendored and minified files are skipped by most rules.
- New network hosts are reported once per file.
- Version bumps are not reported as new dependencies.
- Secret values are masked everywhere, including in other rules' evidence.

Scanning prscreen's own source flags its pattern tables (the regexes contain the very strings
they look for). That is expected, and it shows why every finding is a prompt to look rather than
a verdict.

## Quick start

Needs Python 3.12+ and [uv](https://docs.astral.sh/uv/).

**The easy way:** on Windows, double-click `prscreen-gui.bat`; anywhere else, run
`uv run prscreen gui`. A page opens in your browser. Paste a diff, or choose a repository and a
range like `main...HEAD`, then press **Scan**. You get colour-coded findings with the evidence line,
why it matters and when it's harmless. **Try an example** loads sample risky changes, and the
**Rules** tab lists every rule.

The page runs only on your computer. It listens on 127.0.0.1, answers only requests carrying a
one-time token from the link it prints, rejects other host names, and shows pull request text as
text, never as HTML.

**From the command line:**

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
uv run prscreen eval                                          # measure the rules on corpus/
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

## Demo

`scripts/demo.py build` creates a small Flask app with one branch per scenario. The scenarios are
a leaked AWS key, install-time environment exfiltration, a pwn-request workflow, Trojan Source, a
typosquatted dependency with an extra index, weakened TLS/debug/auth settings, an obfuscated
payload, credential theft, and a prompt injection aimed at AI reviewers. There is also an
ordinary pagination feature.

| Pull request | prscreen |
| --- | --- |
| Clean feature (pagination) | quiet |
| Leaked secret | SEC002, SEC003, SEC005 |
| Install-time exfiltration | EXE005, NET002, NET004 |
| Pwn request | CI001, CI002 |
| Trojan Source | OBF001 |
| Typosquat and extra index | DEP002, DEP003 |
| Weakened security | CFG001, CFG003, CFG005 |
| Obfuscated payload | OBF004, OBF005 |
| Credential theft | NET003, NET005 |
| Prompt injection | OBF008 (the admin bypass next to it is not caught: a documented limitation) |

Every payload is inert, and a test re-checks every row against the current rules.
[docs/demo.md](docs/demo.md) has the full findings, and [docs/demo-setup.md](docs/demo-setup.md)
covers publishing it as live pull requests on GitHub.

## Optional AI review

```bash
uv sync --extra claude && uv run prscreen scan --git origin/main...HEAD --ai claude   # or --ai ollama (free, local)
```

A model can add notes to findings and ask up to 5 questions about added lines the rules missed,
which is aimed at logic changes that no pattern catches. The design assumes the model can be
manipulated by the diff, so:

- **It can only add.** Rule findings are fixed before the model runs, and no code path lets its
  reply remove or change them.
- **Every claim is checked.** The reply must match a strict schema, questions must quote a real
  added line, and notes that dismiss a finding ("false positive", "safe to merge") are rejected.
- **What the model sees is controlled.** PR content goes in a nonce-delimited block with secrets
  redacted.
- **Injections are reported anyway.** Rule OBF008 flags text written to AI tools, with or without
  `--ai`.

Ten hostile model replies are tested and none changes a rule finding. The safety properties are
tested; how useful the questions are has not been measured yet, because no live model was
available. Details are in [docs/ai.md](docs/ai.md).

## Evaluation

| Measure | Result |
| --- | --- |
| Labeled cases | 65 (39 risky, 26 harmless look-alikes) |
| Expected findings caught (recall) | 63 / 66 (95.5%) |
| Findings that were expected (precision on labeled cases) | 63 / 64 (98.4%) |
| Real merged PRs scanned | 95 from 10 projects, 8,713 changed lines |
| Real PRs with a medium or high finding | **0 / 95** |
| Low (informational) findings per real PR | 0.67 |

**The corpus** ([corpus/](corpus)) has two parts.

- **Labeled cases.** Each one is a small PR in TOML: recreations of real incidents (Trojan
  Source, event-stream, ua-parser-js, pwn requests, tj-actions, crossenv, dependency confusion,
  invisible-character backdoors, xz-utils) and look-alikes built to trip each rule (`model.eval()`,
  `yaml.safe_load`, emoji joiners, placeholder secrets, safe workflows). Payloads are inert
  stand-ins, and fake credentials are generated at load time.
- **Real PRs.** The 10 most recently merged PRs of each of 10 well-known projects, such as
  requests, Django, Vite and Express (only 5 were available for Flask). They were fetched by a
  fixed rule in [scripts/fetch_real_prs.py](scripts/fetch_real_prs.py) and are used to measure
  noise.

**Read the numbers with care.** I wrote the labeled cases alongside the rules, so they show that
each rule works and they catch regressions, but they are not an independent benchmark. The
corpus records three attacks the rules do not catch: a logic flip from `and` to `or`, DNS
exfiltration, and an xz-style payload in a binary fixture. It also records one accepted false
positive. Full per-rule and per-PR results are in [docs/evaluation.md](docs/evaluation.md),
which is generated by `prscreen eval` and checked by a test.

While building the corpus, the evaluation caught real detector bugs, and each one was fixed in
the rule, not the label:

- JavaScript `exec(` was read as `eval`.
- Flow-style YAML hid a script injection.
- `.pth` files were not treated as code.
- Private-IP URLs were reported as new hosts.

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
- **Bounded running time.** Every regex uses bounded quantifiers, and line-level rules read at
  most 50,000 characters per line. Before this was fixed, one crafted line could keep a scan busy
  for more than 10 minutes; a performance test now checks such lines finish in seconds.
- **Nothing installed, nothing shadowed.** The action runs `python3 -I` on its own source with no
  `pip install`. Isolated mode means a PR cannot shadow prscreen's modules by adding a `prscreen/`
  folder, which a test checks. Inputs reach the program only through environment variables, and a
  test fails if any workflow script in this repository expands `${{ }}` inline.
- **A pipeline that follows its own advice.** This repository's workflows use read-only
  permissions, actions pinned to commit SHAs, and no persisted checkout credentials, and tests
  enforce all three. prscreen also scans its own workflows in the test suite.

The full analysis, including what prscreen cannot protect against, is in
[docs/threat-model.md](docs/threat-model.md).

## Roadmap

1. ✅ Diff parser, finding model, output formats, `scan` and `explain` commands
2. ✅ Detectors: secrets, dangerous execution and install hooks, CI/workflow weakening, new network
   endpoints, obfuscation, dependency changes, weakened security settings, sensitive paths
3. ✅ Evaluation corpus of risky and harmless look-alike PRs, an `eval` command, published
   precision and false-alarm numbers
4. ✅ GitHub Action (read-only token, no secrets), CI, threat model, setup guide
5. ✅ Optional AI layer that can explain and add questions but never remove a finding, with
   prompt-injection tests
6. ✅ Demo repository with one PR per category and a clean PR where the tool stays quiet
   (built locally; publishing it is in [docs/demo-setup.md](docs/demo-setup.md))

**Not done yet, and worth doing next:**

- Push the repositories and watch CI and the action run on GitHub for the first time.
- Measure the AI layer with a live model.
- Collect a labeled set written by someone other than the rule author.

## License

MIT
