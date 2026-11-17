# Setting up prscreen on a repository

## 1. Add the workflow

Create `.github/workflows/prscreen.yml`:

```yaml
name: prscreen

on:
  pull_request:

permissions:
  contents: read            # read-only token; prscreen needs nothing else

jobs:
  screen:
    runs-on: ubuntu-24.04   # has Python 3.12; on other runners add actions/setup-python first
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0             # both the base and head commits are needed for the diff
          persist-credentials: false # nothing later in the job needs the token
      - uses: sreevar2005/prscreen@<commit-sha> # pin to a commit, never a tag or branch
```

Do not use `pull_request_target` for this workflow. prscreen does not need secrets or write access,
and `pull_request_target` would hand both to code from forks.

## 2. What you get

- **Annotations** on the changed lines in the PR's *Files changed* tab, for findings at the
  `annotate` level and above (medium by default). GitHub shows at most 10 warnings and 10 errors
  per step, highest severity first.
- **A job summary** on the workflow run page with every finding, the evidence, why it matters and
  the common harmless explanations.
- **Nothing else.** prscreen does not comment, label, approve, request changes or block merging.
  Findings never fail the job; it fails only if the scan itself could not run or was incomplete.

All of this works on pull requests from forks, because it needs no secrets and no write access.

## 3. Inputs and outputs

| Input | Default | Meaning |
| --- | --- | --- |
| `base` | the PR's base commit | Commit to diff from |
| `head` | the PR's head commit | Commit to diff to |
| `annotate` | `medium` | Lowest severity shown inline: `low`, `medium`, `high` or `none` |
| `sarif-file` | empty | Also write SARIF here, relative to the workspace |

| Output | Meaning |
| --- | --- |
| `findings`, `high`, `medium`, `low` | Counts of findings |
| `sarif-file` | Path of the SARIF report, if written |

The outputs let you build your own policy, for example a later step that asks for a second
reviewer when `high` is not `0`. prscreen deliberately leaves that decision to you.

## 4. Optional: code scanning (SARIF)

To list findings under *Security → Code scanning*, write SARIF and upload it. Uploading needs
`security-events: write`, which pull requests from forks never get, so give the upload its own job
or condition:

```yaml
      - uses: sreevar2005/prscreen@<commit-sha>
        with:
          sarif-file: prscreen.sarif
      - if: github.event.pull_request.head.repo.full_name == github.repository
        uses: github/codeql-action/upload-sarif@9b3254085494b55a0f7c4c2b3d2d52cc712ce370 # v4.39.1
        with:
          sarif_file: prscreen.sarif
```

and add `security-events: write` to that job's permissions.

## 5. Make it hard to switch off

A `pull_request` run uses the workflow file from the pull request itself, so a PR can edit
`prscreen.yml` to skip the scan. prscreen reports workflow edits (PATH001 and the CI rules), but
the real protection is repository settings:

1. Make the `prscreen / screen` check **required** in a branch ruleset. A PR that deletes or
   renames the job then cannot merge, because the check never reports.
2. Protect `.github/workflows/` with CODEOWNERS so workflow edits need review from someone who
   owns CI.
3. In an organisation, a ruleset can **require the workflow** from a central repository that
   pull requests cannot edit.

## Optional: AI review in CI

The action is rules-only on purpose: no secrets, nothing installed, safe on forks. If you want the
optional AI review ([ai.md](ai.md)) as well, add a separate job that runs only for pull requests
from branches of your own repository, because fork PRs never receive secrets:

```yaml
  ai-review:
    if: github.event.pull_request.head.repo.full_name == github.repository
    runs-on: ubuntu-24.04
    timeout-minutes: 10
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0
          persist-credentials: false
      - name: AI review (advisory)
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
          PR_TITLE: ${{ github.event.pull_request.title }}   # passed as data, never pasted into the script
          PR_BODY: ${{ github.event.pull_request.body }}
          BASE: ${{ github.event.pull_request.base.sha }}
          HEAD: ${{ github.event.pull_request.head.sha }}
        run: |
          python3 -m venv /tmp/prscreen
          /tmp/prscreen/bin/pip install --quiet "prscreen[claude] @ git+https://github.com/sreevar2005/prscreen@<commit-sha>"
          printf '%s' "$PR_BODY" > /tmp/pr-body.md
          /tmp/prscreen/bin/prscreen scan --git "$BASE...$HEAD" --ai claude \
            --pr-title "$PR_TITLE" --pr-body-file /tmp/pr-body.md \
            --format markdown --output /tmp/report.md
          cat /tmp/report.md >> "$GITHUB_STEP_SUMMARY"
```

Two cautions:

- **The diff is sent to Anthropic.** prscreen redacts the secrets it recognises first. Use
  `--ai ollama` on a self-hosted runner if code must not leave your infrastructure.
- **A `pull_request` run uses the PR's own copy of this workflow.** Anyone who can push a branch
  can edit the job and read `ANTHROPIC_API_KEY`. Use a key with a low spending limit, dedicated to
  this job.

## 6. Run it locally

```bash
uv sync
uv run prscreen scan --git origin/main...HEAD
uv run prscreen scan --git origin/main...HEAD --min-severity medium
```

## Limits

- Diffs over 20 MB are rejected. Lines over 50,000 characters are scanned only up to that length,
  and the report says so.
- Binary files are listed but not inspected.
- prscreen recognises patterns; it does not understand intent. See
  [threat-model.md](threat-model.md) and [evaluation.md](evaluation.md) for what it misses.
