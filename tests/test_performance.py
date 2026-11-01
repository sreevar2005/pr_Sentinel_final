"""Hostile input must not be able to stall a scan (regular-expression denial of service)."""

import time

import pytest

from prscreen.detectors import MAX_SCAN_LINE_CHARS
from prscreen.diff import parse_diff
from prscreen.engine import scan

N = 100_000
# Each string targets a quantifier that was once quadratic: long word runs, separators, quotes,
# repeated ${{, leading whitespace before a YAML key, IP-like dot runs and unterminated URLs.
ADVERSARIAL = [
    ("app/x.py", "a" * N),
    ("app/x.py", "a-" * (N // 2)),
    ("app/x.py", "1." * (N // 2)),
    ("app/x.py", "password=" * (N // 9)),
    ("app/x.py", '"' * N),
    ("app/x.py", "http://" + "a" * N),
    ("app/x.py", "curl " + "x " * (N // 2)),
    (".github/workflows/x.yml", "${{ " * (N // 4)),
    (".github/workflows/x.yml", " " * N),
    ("package.json", '"' + "a" * N + '": "'),
]


@pytest.mark.parametrize(("path", "line"), ADVERSARIAL, ids=[f"{i}" for i in range(len(ADVERSARIAL))])
def test_long_adversarial_lines_scan_quickly(path, line):
    diff = parse_diff(f"--- a/{path}\n+++ b/{path}\n@@ -0,0 +1 @@\n+{line}\n")
    start = time.perf_counter()
    scan(diff)
    # Linear-time rules take well under a second here; quadratic ones took minutes.
    assert time.perf_counter() - start < 5


def test_overlong_lines_are_reported_as_partly_scanned():
    line = "x = 1  # " + "a" * (MAX_SCAN_LINE_CHARS + 10)
    result = scan(parse_diff(f"--- a/a.py\n+++ b/a.py\n@@ -0,0 +1 @@\n+{line}\n"))
    assert ("a.py", f"line 1 scanned only to {MAX_SCAN_LINE_CHARS:,} characters") in result.skipped
    assert "OBF006" in {f.rule.id for f in result.findings}
