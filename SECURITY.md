# Security policy

## Reporting a vulnerability

Please report security problems in prscreen privately through GitHub's
**Security → Report a vulnerability** form on this repository rather than in a public issue.
Include the version or commit, the input that triggers the problem, and what happened.

In scope:

- ways to make prscreen run code from the pull request it scans;
- workflow-command, Markdown or terminal injection through its output;
- a secret value that reaches a report unredacted;
- input that makes a scan take unreasonably long;
- anything that lets a pull request change what prscreen reports about it, other than writing
  code that no rule recognises.

A rule that misses an attack is not a vulnerability, but it is a welcome issue: please open one,
ideally with a minimal case for `corpus/cases/`.

## Supported versions

Only the latest commit on `main` is supported. Pin the action to a commit SHA and update it with
Dependabot.
