# Publishing prscreen and its demo

These steps put prscreen on GitHub and give it a live demo: a repository whose open pull requests
show prscreen's annotations and job summaries on real GitHub pages. They need your GitHub account,
so they are written for you to run. Nothing here is automated on your behalf.

## 1. Publish prscreen

Create an empty public repository named `prscreen` on GitHub (no README, no license, no
.gitignore), then:

```bash
cd "D:/Semisters/5th Sem/Track/Track_project"
git remote add origin https://github.com/sreevar2005/prscreen.git
git push -u origin main
```

Open the repository's **Actions** tab and check that the **CI** workflow passes: tests on Ubuntu
and Windows with Python 3.12 and 3.13, plus the action smoke test. This is the first time the
workflows run anywhere.

Note the commit to pin:

```bash
git rev-parse HEAD
```

## 2. Build the demo with the action pinned to that commit

A copy built with an unpinned reference already exists at `D:/Semisters/5th Sem/Track/prscreen-demo`.
Rebuild it so the demo follows prscreen's own advice:

```bash
rm -rf "../prscreen-demo"
uv run python scripts/demo.py build ../prscreen-demo --action sreevar2005/prscreen@<commit-sha>
```

## 3. Publish the demo

Create an empty public repository named `prscreen-demo`, then push `main` and every demo branch:

```bash
cd "../prscreen-demo"
git remote add origin https://github.com/sreevar2005/prscreen-demo.git
git push -u origin main
git push origin "refs/heads/demo/*:refs/heads/demo/*"
```

If GitHub's push protection blocks `demo/leaked-secret` because of the fake AWS key, choose
*"It's used in tests"* on the page GitHub links to and push again. That is expected: two layers
caught the same key.

## 4. Open one pull request per branch

Open each link, use the title from the table, and press **Create pull request**:

| Branch | Title |
| --- | --- |
| [demo/clean-feature](https://github.com/sreevar2005/prscreen-demo/compare/main...demo/clean-feature?expand=1) | Add pagination to the notes list |
| [demo/leaked-secret](https://github.com/sreevar2005/prscreen-demo/compare/main...demo/leaked-secret?expand=1) | Hook up S3 backups |
| [demo/install-time-exfiltration](https://github.com/sreevar2005/prscreen-demo/compare/main...demo/install-time-exfiltration?expand=1) | Add build metadata to setup.py |
| [demo/pwn-request](https://github.com/sreevar2005/prscreen-demo/compare/main...demo/pwn-request?expand=1) | Let the test workflow run on PRs from forks |
| [demo/trojan-source](https://github.com/sreevar2005/prscreen-demo/compare/main...demo/trojan-source?expand=1) | Tidy the admin check |
| [demo/typosquat](https://github.com/sreevar2005/prscreen-demo/compare/main...demo/typosquat?expand=1) | Pin HTTP client and add internal mirror |
| [demo/weakened-security](https://github.com/sreevar2005/prscreen-demo/compare/main...demo/weakened-security?expand=1) | Fix SSL errors in staging and simplify the export view |
| [demo/obfuscated-payload](https://github.com/sreevar2005/prscreen-demo/compare/main...demo/obfuscated-payload?expand=1) | Add startup telemetry |
| [demo/credential-theft](https://github.com/sreevar2005/prscreen-demo/compare/main...demo/credential-theft?expand=1) | Add diagnostics endpoint |
| [demo/prompt-injection](https://github.com/sreevar2005/prscreen-demo/compare/main...demo/prompt-injection?expand=1) | Support desk access |

The `demo/pwn-request` PR changes the demo's test workflow to `pull_request_target`. GitHub runs
`pull_request_target` workflows from the base branch, so the change is not executed by opening the
PR. **Never merge the demo PRs.**

## 5. What to look at (and screenshot)

- **Files changed** tab: inline annotations on the flagged lines.
- **Checks → prscreen → Summary**: the full report with evidence, why it matters, and when it is
  harmless.
- The **clean feature** PR: a summary that says "No findings". This matters as much as the noisy
  ones.
- The **prompt-injection** PR: OBF008 flags the comment aimed at AI reviewers, and nothing flags the
  admin bypass beside it. The honest limit of pattern rules, shown in one PR.

[demo.md](demo.md) lists the exact findings each PR should produce.
