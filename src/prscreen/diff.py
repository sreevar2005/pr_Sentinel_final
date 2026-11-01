"""Parser for unified diffs, as produced by ``git diff`` or the GitHub API.

The diff comes from the pull request author, so the parser treats it as hostile input:

* Hunks are read by their declared line counts, never by guessing from line prefixes. A removed
  line ``-- note`` shows up as ``--- note`` and must not be mistaken for a new file header.
* Lines are split on ``\\n`` only. ``str.splitlines`` also splits on characters such as U+2028
  and U+000C, which an attacker could use to make one line look like two.
* Malformed input stops the current hunk instead of crashing; unknown lines are skipped.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum

_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
_DEV_NULL = "/dev/null"
_C_ESCAPES = {"a": 7, "b": 8, "t": 9, "n": 10, "v": 11, "f": 12, "r": 13, '"': 34, "\\": 92}


class DiffParseError(ValueError):
    pass


class ChangeKind(StrEnum):
    ADDED = "added"
    MODIFIED = "modified"
    DELETED = "deleted"
    RENAMED = "renamed"
    COPIED = "copied"


@dataclass(frozen=True)
class DiffLine:
    number: int
    """Line number in the new file for added lines, in the old file for removed lines."""
    text: str


@dataclass
class FileChange:
    path: str
    """Path after the change. For a deleted file, the path it was deleted from."""
    old_path: str | None = None
    kind: ChangeKind = ChangeKind.MODIFIED
    binary: bool = False
    old_mode: str | None = None
    new_mode: str | None = None
    added: list[DiffLine] = field(default_factory=list)
    removed: list[DiffLine] = field(default_factory=list)

    @property
    def became_executable(self) -> bool:
        return self.new_mode == "100755" and self.old_mode != "100755"


@dataclass
class Diff:
    files: list[FileChange] = field(default_factory=list)


def parse_diff(text: str) -> Diff:
    return _Parser(_split_lines(text)).parse()


def _split_lines(text: str) -> list[str]:
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return [line.removesuffix("\r") for line in lines]


class _Parser:
    def __init__(self, lines: list[str]) -> None:
        self.lines = lines
        self.i = 0
        self.diff = Diff()
        self.current: FileChange | None = None
        # Whether the current file already has its ---/+++ header or a hunk; a further
        # ---/+++ pair then starts a new file (plain ``diff -u`` output has no ``diff --git``).
        self.current_has_body = False
        self.in_git_header = False

    def parse(self) -> Diff:
        while self.i < len(self.lines):
            line = self.lines[self.i]
            if line.startswith("diff --git "):
                self._start_file(_parse_git_header(line[len("diff --git ") :]))
                self.in_git_header = True
                self.i += 1
            elif line.startswith(("diff --cc ", "diff --combined ")):
                raise DiffParseError("combined (merge) diffs are not supported; diff base...head instead")
            elif line.startswith("--- ") and self._next_is("+++ "):
                self._file_paths(line[4:], self.lines[self.i + 1][4:])
                self.i += 2
            elif line.startswith("@@ "):
                self._hunk()
            elif self.in_git_header and self.current is not None:
                self._extended_header(line, self.current)
                self.i += 1
            else:
                self.i += 1
        return self.diff

    def _next_is(self, prefix: str) -> bool:
        return self.i + 1 < len(self.lines) and self.lines[self.i + 1].startswith(prefix)

    def _start_file(self, change: FileChange) -> None:
        self.current = change
        self.current_has_body = False
        self.diff.files.append(change)

    def _file_paths(self, old_raw: str, new_raw: str) -> None:
        old, new = _header_path(old_raw, "a/"), _header_path(new_raw, "b/")
        change = self.current
        if change is None or self.current_has_body:
            change = FileChange(path=new or old or "")
            self._start_file(change)
        if old is None and new is not None:
            change.kind = ChangeKind.ADDED
        elif new is None and old is not None:
            change.kind = ChangeKind.DELETED
        if change.kind is ChangeKind.DELETED:
            change.path = old or change.path
        else:
            change.path = new or change.path
            if old is not None and old != new:
                change.old_path = old
                if change.kind is ChangeKind.MODIFIED:
                    change.kind = ChangeKind.RENAMED
        self.current_has_body = True
        self.in_git_header = False

    def _extended_header(self, line: str, change: FileChange) -> None:
        if line.startswith("new file mode "):
            change.kind = ChangeKind.ADDED
            change.new_mode = line.rsplit(" ", 1)[-1]
        elif line.startswith("deleted file mode "):
            change.kind = ChangeKind.DELETED
            change.old_mode = line.rsplit(" ", 1)[-1]
        elif line.startswith("old mode "):
            change.old_mode = line[len("old mode ") :]
        elif line.startswith("new mode "):
            change.new_mode = line[len("new mode ") :]
        elif line.startswith(("rename from ", "copy from ")):
            change.old_path = _unquote(line.split(" ", 2)[2])
            change.kind = ChangeKind.RENAMED if line.startswith("rename") else ChangeKind.COPIED
        elif line.startswith(("rename to ", "copy to ")):
            change.path = _unquote(line.split(" ", 2)[2])
        elif line.startswith("Binary files ") or line == "GIT binary patch":
            change.binary = True
            # The base85 payload that follows is opaque; skip it until the next file.
            self.in_git_header = False

    def _hunk(self) -> None:
        match = _HUNK_RE.match(self.lines[self.i])
        if match is None or self.current is None:
            raise DiffParseError(f"line {self.i + 1}: hunk header without a valid file header")
        change = self.current
        self.current_has_body = True
        self.in_git_header = False
        old_no, old_left = int(match[1]), int(match[2] or "1")
        new_no, new_left = int(match[3]), int(match[4] or "1")
        self.i += 1
        while (old_left > 0 or new_left > 0) and self.i < len(self.lines):
            line = self.lines[self.i]
            tag, body = line[:1], line[1:]
            if tag == "+" and new_left > 0:
                change.added.append(DiffLine(new_no, body))
                new_no += 1
                new_left -= 1
            elif tag == "-" and old_left > 0:
                change.removed.append(DiffLine(old_no, body))
                old_no += 1
                old_left -= 1
            elif tag in (" ", "") and old_left > 0 and new_left > 0:
                # Some tools strip the single space from empty context lines.
                old_no += 1
                new_no += 1
                old_left -= 1
                new_left -= 1
            elif tag != "\\":
                return  # Malformed or truncated hunk: keep what was read, resync on the next header.
            self.i += 1
        if self.i < len(self.lines) and self.lines[self.i].startswith("\\"):
            self.i += 1  # "\ No newline at end of file" after the last line of the hunk


def _header_path(raw: str, prefix: str) -> str | None:
    if raw.startswith('"'):
        path, _ = _read_quoted(raw)
    else:
        path = raw.split("\t", 1)[0]  # plain diffs append a tab and a timestamp
    if path == _DEV_NULL:
        return None
    return path.removeprefix(prefix)


def _parse_git_header(rest: str) -> FileChange:
    """Best-effort paths from ``diff --git a/X b/Y``.

    Only needed for files without a ``---``/``+++`` pair (binary files, mode-only changes);
    otherwise those lines, or ``rename from``/``rename to``, overwrite the result.
    """
    if rest.startswith('"'):
        old, rest = _read_quoted(rest)
        rest = rest.lstrip(" ")
        new = _read_quoted(rest)[0] if rest.startswith('"') else rest
    elif rest.endswith('"') and ' "' in rest:
        old, quoted = rest.split(' "', 1)
        new = _read_quoted('"' + quoted)[0]
    else:
        # Unquoted paths may contain spaces. When old and new are the same file the line is
        # "a/X b/X", which can be split exactly in the middle.
        half = (len(rest) - 1) // 2
        if len(rest) % 2 == 1 and rest[half] == " " and rest[:half][2:] == rest[half + 1 :][2:]:
            old, new = rest[:half], rest[half + 1 :]
        else:
            old, _, new = rest.partition(" b/")
            new = "b/" + new
    old, new = old.removeprefix("a/"), new.removeprefix("b/")
    return FileChange(path=new, old_path=old if old != new else None)


def _read_quoted(raw: str) -> tuple[str, str]:
    """Decode a git C-style quoted path. Returns the path and the text after the closing quote."""
    out = bytearray()
    i = 1
    while i < len(raw):
        ch = raw[i]
        if ch == '"':
            return out.decode("utf-8", errors="replace"), raw[i + 1 :]
        if ch == "\\" and i + 1 < len(raw):
            nxt = raw[i + 1]
            if nxt in "01234567" and i + 3 < len(raw):
                out.append(int(raw[i + 1 : i + 4], 8) & 0xFF)
                i += 4
                continue
            out.append(_C_ESCAPES.get(nxt, ord(nxt)) if nxt.isascii() else ord("?"))
            i += 2
            continue
        out.extend(ch.encode("utf-8", errors="replace"))
        i += 1
    raise DiffParseError(f"unterminated quoted path: {raw[:80]!r}")


def _unquote(raw: str) -> str:
    return _read_quoted(raw)[0] if raw.startswith('"') else raw
