"""Make text from the pull request safe to show.

Evidence, paths and even error messages can be written by an attacker. Before any of it reaches
a terminal, a Markdown comment or a workflow log, invisible and control characters are turned
into visible ``\\uXXXX`` escapes. That stops terminal escape sequences, fake line breaks and
hidden bidi tricks, and it shows the reviewer exactly which character is there.
"""

from __future__ import annotations

import unicodedata

# Cc control, Cf format (bidi, zero-width), Zl/Zp line and paragraph separators,
# Cs lone surrogates, Co private use, Cn unassigned.
_ESCAPED_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp", "Cs", "Co", "Cn"})


def visible(text: str, limit: int | None = None) -> str:
    out: list[str] = []
    for ch in text:
        if ch == "\t":
            out.append("    ")
        elif unicodedata.category(ch) in _ESCAPED_CATEGORIES:
            code = ord(ch)
            out.append(f"\\u{code:04x}" if code <= 0xFFFF else f"\\U{code:08x}")
        else:
            out.append(ch)
    result = "".join(out)
    if limit is not None and len(result) > limit:
        result = result[: limit - 1] + "…"
    return result
