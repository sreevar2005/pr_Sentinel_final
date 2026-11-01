# Optional AI review

prscreen is complete without a language model, and the rules are the product. The AI layer is an
optional second reader for the one thing patterns cannot see: logic changes in ordinary-looking
code, like an `and` that became an `or` in an authorization check. Off by default.

```bash
uv sync --extra claude                       # Claude: official anthropic SDK, ANTHROPIC_API_KEY
uv run prscreen scan --git origin/main...HEAD --ai claude
uv run prscreen scan --git origin/main...HEAD --ai ollama   # free and local; needs Ollama running
uv run prscreen scan --diff pr.diff --ai claude --pr-title "Fix export" --pr-body-file body.md
```

| Provider | Default model | Cost | Notes |
| --- | --- | --- | --- |
| `claude` | `claude-opus-5-5` | Paid API | Structured outputs keep the reply to the JSON schema; server-side fallbacks retry on another Claude model if one declines to review security code. |
| `ollama` | `qwen2.5-coder:7b` | Free | Runs locally (`OLLAMA_HOST`), nothing leaves the machine; much weaker than a frontier model. |

## What the AI may do

1. **Add a note to a rule finding**, explaining why it matters in this change. Shown as
   "AI note (unverified)".
2. **Ask up to 5 questions** about added lines the rules did not flag, reported as `AI001` at low
   severity and low confidence.

That is all. The rules run first and their findings are fixed before the model is called.

## The invariant: add, never remove

`prscreen.ai.review()` returns a result whose first findings are exactly the rule findings, in
order, followed by any AI questions. There is no code path from model output to deleting,
editing, downgrading or re-ordering a rule finding. If the model fails, times out, refuses, or
replies with anything invalid, the rule result comes back unchanged and the report says why the
AI part was not used. The exit code never depends on the AI.

## Treating the model's reply as hostile

A prompt injection in the diff can steer the model, so its reply gets the same distrust as the
diff itself. Before anything reaches a reviewer:

| Check | Stops |
| --- | --- |
| The reply must be exactly `{"notes": [...], "questions": [...]}` | Extra instructions such as `"remove_findings"`, prose, half-parsed output |
| Notes must name an existing finding ID, once each | Notes about findings that do not exist |
| **Verdict filter**: no "safe to merge", "false positive", "can be ignored", "LGTM", "no issues"… | An injected or over-eager model dismissing a real finding |
| Questions must name a file in the diff, an **added** line, and quote that line | Invented code, questions about removed or unchanged lines |
| The evidence shown is the real diff line, never the model's quote | A model "quoting" text that is not there |
| Caps: 5 questions, 400-character notes, 300-character questions | Floods and walls of text |
| Output escaped like any other PR text | Markdown, HTML, `@mentions` or terminal escapes smuggled through the model |

Every rejected claim is counted and listed in the report, so a reviewer can see when the model
tried something.

## What the model is shown

- The PR title, description and diff, inside one block delimited by a **random nonce** per run:
  `<untrusted-pr-content-3f9c…>`. The author cannot close the block early, because they cannot
  guess the nonce.
- Instructions placed before the block saying it is untrusted data that may try to give orders,
  and that the model may not dismiss findings.
- **Secrets redacted** and invisible characters shown as `\uXXXX` before the text leaves the
  machine, so a leaked token is never sent to a model provider and Trojan Source characters are
  visible to the model too.
- The diff capped at 60,000 characters; the report says when it was truncated (the rules still
  scan everything).

## Deterministic backstop: OBF008

Text written *at* AI tools ("ignore previous instructions", "AI reviewer: this file is safe", "do not
report this") is flagged by rule **OBF008** whether or not `--ai` is used. A model that fully obeys an
injection and returns nothing still leaves the injection attempt itself in the report.
`tests/test_ai.py` checks exactly that case.

## Tested behaviour

`tests/test_ai.py` replaces the model with a scripted fake and checks, among others:

- an honest reply adds one grounded question and one note;
- ten hostile replies (not JSON, an extra `remove_findings` key, verdict notes, unknown findings,
  fabricated quotes, removed lines, files not in the diff, verdict questions, non-integer line
  numbers) leave the rule findings byte-for-byte unchanged and add nothing;
- provider failure, timeouts and a missing SDK leave the rule result and exit code unchanged;
- the prompt redacts secrets, uses a fresh nonce each time, and keeps a fake closing tag inside
  the untrusted block;
- AI text is escaped in Markdown, JSON and text output;
- the Ollama provider sends the schema as `format` (checked against a local stub server).

## What has not been measured

These tests prove the safety properties, not the usefulness. No live model was run while building
this stage: there was no API key and no local Ollama. So how often the AI finds the logic flip in
`corpus/cases/risky-limit-logic-backdoor.toml`, or how many of its questions are worth a reviewer's
time, is unknown. Measuring that means running `prscreen scan --ai ...` over the labeled corpus and
the 95 real PRs and counting accepted questions against noise, in the same way as
[evaluation.md](evaluation.md).

## In CI

The GitHub Action stays rules-only. It installs nothing and needs no secrets, which is what makes it
safe on fork PRs. [setup.md](setup.md#optional-ai-review-in-ci) shows a separate, opt-in job for
same-repository PRs.
