# Threat model

prscreen reads diffs written by people it has no reason to trust and shows the result to people
who will act on it. This document lists what it protects, who might attack it or through it, and
what it does about each threat, including the ones it cannot fix.

## What it protects

| Asset | Why it matters |
| --- | --- |
| The repository and its secrets | The CI job that runs prscreen must not become a way to steal tokens or push code. |
| The reviewer's judgement | Reports must not mislead: no false reassurance, no accusations, no hidden content. |
| The reviewer's attention | A tool that cries wolf gets ignored, so noise is a security problem. |
| Contributors | A finding is evidence about a change, never a verdict about a person. |

## Trust boundaries

```text
 pull request author ──► diff text ──► [prscreen in a read-only job] ──► annotations, summary, SARIF ──► reviewer
     (untrusted)          (data)           no secrets, no PR code run        (escaped text)               (decides)
```

- **Untrusted:** everything in the pull request, including file contents, file names, commit
  messages, branch names, `.gitattributes`, and any `prscreen/` folder it adds.
- **Trusted:** the prscreen code at the commit the workflow pins, the workflow file on the base
  branch (see T8 for the limits), and the runner image.

## Threats and mitigations

| # | Threat | Mitigation | Status |
| --- | --- | --- | --- |
| T1 | **Running attacker code in CI.** The scanner builds, installs or imports PR code with access to secrets ("pwn request"). | prscreen never runs PR code: it reads `git diff` text only. The recommended workflow uses `pull_request` with `contents: read` and no secrets, never `pull_request_target`. `git diff` runs with `--no-ext-diff --no-textconv`, so `.gitattributes` cannot choose a program to run. Tested in `test_cli.py`. | Mitigated |
| T2 | **Module shadowing.** The PR adds `prscreen/__init__.py` so that Python imports it instead of the real tool. | The action runs `python3 -I run.py`. Isolated mode ignores the working directory and `PYTHON*` variables, and only the action's own `src/` is put on the path. Nothing is pip-installed. Tested in `test_action.py`. | Mitigated |
| T3 | **Workflow command injection.** Evidence such as `::add-mask::` or `::stop-commands::` printed to the log runs as a runner command. | Annotation values are escaped as the runner requires. Text reports printed inside Actions are wrapped in `stop-commands` with a random token. Control characters, including newlines, are escaped before output. Tested in `test_formats.py` and `test_cli.py`. | Mitigated |
| T4 | **Shell injection through inputs.** A branch name or input is expanded inside the action's script. | Inputs reach the program only through `env:`, and revisions are validated before they reach git. A test fails if any `run:` block in this repo contains `${{`. | Mitigated |
| T5 | **Misleading output.** Trojan Source characters, terminal escapes, Markdown links, HTML or `@mentions` in evidence fool the reader or ping people. | Invisible, bidi and control characters are shown as `\uXXXX`. Markdown output escapes HTML, links and mentions, and puts code in fences longer than any backtick run. | Mitigated |
| T6 | **Secret disclosure by the report.** A finding quotes a leaked token in public annotations, logs or SARIF. | Every finding's evidence passes through the secret redactor, including findings from non-secret rules. Detail text never contains the value. | Mitigated for known formats; unknown formats may show |
| T7 | **Denial of service.** A huge diff or a crafted line makes the scan run for hours. | Diffs are capped at 20 MB and line-level rules see at most 50,000 characters per line (longer lines are reported). Every regex has bounded quantifiers; `test_performance.py` checks 100,000-character adversarial lines finish in seconds. A quadratic regex found in stage 4 took over 10 minutes on one line before this fix. | Mitigated |
| T8 | **Disabling the check.** The PR edits `.github/workflows/prscreen.yml` to remove or neuter the scan. A `pull_request` run uses the PR's own copy of the workflow. | prscreen reports workflow changes itself (PATH001, CI rules). The real fix is outside the tool: make the check required and protect workflow files with CODEOWNERS or an organisation ruleset that requires the workflow. | **Residual**, documented in the setup guide |
| T9 | **Evasion.** A malicious change is written to avoid every pattern: logic bugs, payloads in binaries, values built at runtime, splitting across PRs. | No pattern tool can stop a determined author. The evaluation corpus records three known misses, and the optional AI layer (stage 5) targets logic changes. The README and every report say findings are signals, not verdicts. | **Residual**, measured and documented |
| T10 | **False reassurance.** "No findings" is read as "safe to merge". | prscreen never approves and never reports a green "safe" state. The summary says "No findings in N files" and calls itself advisory. | Mitigated by design; depends on reviewers |
| T11 | **Alert fatigue.** So many findings that real ones are ignored. | Severity and confidence on every finding. Test files are downgraded, comments and vendored files are skipped, findings are capped per rule per file, and duplicates are dropped. Measured: 0 of 95 real merged PRs got a medium or high finding. | Mitigated, measured |
| T12 | **Accusation.** A report labels a contributor malicious. | Every rule states common harmless explanations, shown with each finding. No output uses the word "malicious" about code or people. | Mitigated by design |
| T13 | **Compromise of prscreen itself.** A malicious dependency or a hijacked tag of this action. | No runtime dependencies. Users pin the action to a commit SHA, and Dependabot keeps this repo's own action pins current. Dev tools run only in CI with a read-only token. | Mitigated; users must pin |
| T14 | **Prompt injection (stage 5).** Text in the diff tells the AI layer to hide findings. | Planned design: the AI can only add or annotate findings, never remove rule findings, and every AI claim must quote a real diff line. Injection tests come with that stage. | Not yet built |

## Out of scope

- Runtime behaviour of dependencies: prscreen sees the changed lockfile line, not the package's code.
- Secrets that are already in the repository's history; use a history scanner such as gitleaks.
- Compromised runners or GitHub itself.

## What a reviewer should still do

Read the code. prscreen points at the lines most worth reading and says why; it cannot tell you a
change is safe.
