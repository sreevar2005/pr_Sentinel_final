"""Code that reads differently to a human reviewer than to the machine, or cannot be read at all."""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterator

from prscreen.detectors import Detector, LineDetector
from prscreen.detectors._common import (
    entropy,
    is_comment,
    is_doc,
    is_lockfile,
    is_runnable,
    is_source,
    is_test,
    is_vendored,
    suffix,
)
from prscreen.diff import ChangeKind, Diff, DiffLine, FileChange
from prscreen.models import Category, Confidence, Finding, Rule, Severity

# Embedding, override and isolate controls: the characters used by "Trojan Source"
# (CVE-2021-42574). LRM/RLM/ALM are left out: they are common in real right-to-left text and
# cannot reorder code on their own.
_BIDI_CONTROLS = {
    "\u202a": "LRE",
    "\u202b": "RLE",
    "\u202c": "PDF",
    "\u202d": "LRO",
    "\u202e": "RLO",
    "\u2066": "LRI",
    "\u2067": "RLI",
    "\u2068": "FSI",
    "\u2069": "PDI",
}
# Prose and translation files: a control character there misleads readers, not compilers.
_TEXT_SUFFIXES = (".md", ".rst", ".txt", ".po", ".pot", ".xlf", ".xliff", ".strings", ".resx")

BIDI_CONTROL = Rule(
    id="OBF001",
    title="Hidden bidirectional control character",
    category=Category.OBFUSCATION,
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    rationale=(
        "Invisible Unicode controls change the order in which text is displayed, so code can look "
        "different in review from how the compiler or interpreter reads it ('Trojan Source', "
        "CVE-2021-42574). A comment can appear to close early, or a string can appear to hold "
        "code that actually runs."
    ),
    benign=(
        "Right-to-left text (Arabic, Hebrew, Persian) in strings, comments or translation files "
        "sometimes needs these characters. That is fine when they sit inside readable text and "
        "not around code tokens."
    ),
)
INVISIBLE_CHARACTER = Rule(
    id="OBF002",
    title="Invisible character in code",
    category=Category.OBFUSCATION,
    severity=Severity.MEDIUM,
    confidence=Confidence.MEDIUM,
    rationale=(
        "Zero-width and blank-looking characters (such as U+200B or the Hangul filler U+3164) can "
        "make two identifiers or strings that look identical actually differ, or hide an extra "
        "parameter in plain sight."
    ),
    benign="Copy-pasted text from documents or chat apps often carries stray zero-width spaces.",
)
MIXED_SCRIPT = Rule(
    id="OBF003",
    title="Look-alike letters from another alphabet",
    category=Category.OBFUSCATION,
    severity=Severity.MEDIUM,
    confidence=Confidence.MEDIUM,
    rationale=(
        "A word that mixes Latin letters with Cyrillic or Greek ones (Cyrillic U+0430 in place of "
        "the 'a' in 'paypal') looks normal but is a different identifier, domain or string: a "
        "homoglyph attack."
    ),
    benign="Mathematical code using Greek letter names, or genuine multilingual text.",
)
ENCODED_BLOB = Rule(
    id="OBF004",
    title="Long encoded or escaped blob",
    category=Category.OBFUSCATION,
    severity=Severity.MEDIUM,
    confidence=Confidence.MEDIUM,
    rationale=(
        "Large base64, hex or escape-sequence strings in source code cannot be reviewed by reading. "
        "Malicious changes hide payloads this way and decode them at runtime."
    ),
    benign="Embedded images, fonts, test vectors, certificates and generated data files.",
)
DECODE_AND_RUN = Rule(
    id="OBF005",
    title="Decodes data and runs it as code",
    category=Category.OBFUSCATION,
    severity=Severity.HIGH,
    confidence=Confidence.HIGH,
    rationale=(
        "Decoding a string and immediately executing it means the code that runs is not the code "
        "that was reviewed. Legitimate software almost never needs this."
    ),
    benign="Very rare: some packers and self-extracting installers. It still deserves a close look.",
    supersedes=("EXE002",),
)
LONG_LINE = Rule(
    id="OBF006",
    title="Very long line in hand-written source",
    category=Category.OBFUSCATION,
    severity=Severity.LOW,
    confidence=Confidence.MEDIUM,
    rationale=(
        "A line thousands of characters long in a normal source file usually means minified or "
        "generated code, which hides what it does from reviewers and from diff views."
    ),
    benign="Generated files committed outside a build folder, or long data literals.",
)
OPAQUE_BINARY = Rule(
    id="OBF007",
    title="Compiled binary or archive added",
    category=Category.OBFUSCATION,
    severity=Severity.MEDIUM,
    confidence=Confidence.HIGH,
    rationale=(
        "Executables, libraries, bytecode and archives cannot be reviewed in a pull request. "
        "Whatever is inside will run or be unpacked as-is."
    ),
    benign="Vendored tools, test fixtures or release assets; ideally they are built in CI instead.",
)

_INVISIBLE = {
    "\u200b": "ZERO WIDTH SPACE",
    "\u200c": "ZERO WIDTH NON-JOINER",
    "\u200d": "ZERO WIDTH JOINER",
    "\u2060": "WORD JOINER",
    "\u2061": "FUNCTION APPLICATION",
    "\u2062": "INVISIBLE TIMES",
    "\u2063": "INVISIBLE SEPARATOR",
    "\u2064": "INVISIBLE PLUS",
    "\ufeff": "ZERO WIDTH NO-BREAK SPACE",
    "\u180e": "MONGOLIAN VOWEL SEPARATOR",
    "\u115f": "HANGUL CHOSEONG FILLER",
    "\u1160": "HANGUL JUNGSEONG FILLER",
    "\u3164": "HANGUL FILLER",
    "\uffa0": "HALFWIDTH HANGUL FILLER",
    "\u00ad": "SOFT HYPHEN",
}
_WORD_RE = re.compile(r"[^\W\d_]{2,}")
_SCRIPTS = ("LATIN", "CYRILLIC", "GREEK")

_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{160,}={0,2}|[A-Za-z0-9_\-]{200,}")
_HEX_RE = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}){100,}(?![0-9a-fA-F])")
_ESCAPES_RE = re.compile(
    r"(?:\\x[0-9a-fA-F]{2}){24,}|(?:\\u[0-9a-fA-F]{4}){16,}|(?:\\[0-7]{3}){24,}"
    r"|String\.fromCharCode\((?:\s*\d+\s*,){16,}|(?:chr\(\s*\d+\s*\)\s*\+\s*){10,}"
)
_EMBEDDED_ASSET_RE = re.compile(r"data:(?:image|font|audio|video)/|\bintegrity\b|\bsha(?:256|384|512)-")
_DECODE_AND_RUN_RE = re.compile(
    r"\b(?:exec|eval)\s*\(\s*(?:compile\s*\(\s*)?(?:base64\.\w*decode|codecs\.decode|bytes\.fromhex|"
    r"zlib\.decompress|gzip\.decompress|lzma\.decompress|bz2\.decompress|marshal\.loads|binascii\.\w+|"
    r"__import__\s*\(\s*[\"'](?:base64|zlib|codecs|marshal)[\"']\)|bytearray\.fromhex|\w+\.decode\()"
    r"|\beval\s*\(\s*(?:atob|Buffer\.from|unescape|decodeURIComponent|String\.fromCharCode|escape)\b"
    r"|\b(?:new\s+)?Function\s*\(\s*(?:atob|Buffer\.from)\b"
    r"|(?i:\bpowershell(?:\.exe)?\b.{0,300}\s-(?:e|en|enc|encodedcommand)\s+[A-Za-z0-9+/=]{40,})"
    r"|(?i:\bFromBase64String\b.{0,300}\b(?:iex|Invoke-Expression)\b|\b(?:iex|Invoke-Expression)\b.{0,300}\bFromBase64String\b)"
    r"|\bbase64\s+(?:-d|-D|--decode)\b[^|]{0,300}\|\s*(?:ba|z)?sh\b"
    r"|\becho\s+[\"']?[A-Za-z0-9+/=]{40,}[\"']?\s*\|\s*base64\s+(?:-d|-D|--decode)"
)
_LONG_LINE_CHARS = 1000

_EXECUTABLE_SUFFIXES = frozenset(
    ".exe .dll .so .dylib .bin .elf .o .a .lib .jar .war .ear .class .pyc .pyo .pyd .wasm .node "
    ".msi .deb .rpm .apk .ipa .app .scr .com .sys .ko".split()
)
_ARCHIVE_SUFFIXES = frozenset(".zip .tar .gz .tgz .bz2 .xz .7z .rar .zst .whl .egg .nupkg .gem".split())


class BidiControlDetector(LineDetector):
    name = "bidi-control"
    rules = (BIDI_CONTROL,)

    def check_line(self, change: FileChange, line: DiffLine) -> Iterator[Finding]:
        hits = [(col, ch) for col, ch in enumerate(line.text, start=1) if ch in _BIDI_CONTROLS]
        if not hits:
            return
        names = ", ".join(f"U+{ord(ch):04X} {_BIDI_CONTROLS[ch]} at column {col}" for col, ch in hits[:5])
        if len(hits) > 5:
            names += f" and {len(hits) - 5} more"
        prose = change.path.lower().endswith(_TEXT_SUFFIXES)
        yield BIDI_CONTROL.finding(
            change.path,
            line.number,
            line.text,
            f"Contains {names}.",
            severity=Severity.MEDIUM if prose else None,
            confidence=Confidence.MEDIUM if prose else None,
        )


class LookalikeDetector(LineDetector):
    """Invisible characters and mixed-alphabet words in code and config."""

    name = "lookalikes"
    rules = (INVISIBLE_CHARACTER, MIXED_SCRIPT)

    def applies_to(self, path: str) -> bool:
        return is_runnable(path)

    def check_line(self, change: FileChange, line: DiffLine) -> Iterator[Finding]:
        text = line.text
        for col, ch in enumerate(text, start=1):
            if ch not in _INVISIBLE:
                continue
            if ch == "\ufeff" and line.number == 1 and col == 1:
                continue  # byte order mark at the start of the file
            before, after = text[col - 2 : col - 1], text[col : col + 1]
            if ch in "\u200c\u200d" and not (before.isascii() and after.isascii()):
                continue  # joiners inside emoji sequences and Indic or Persian words
            yield INVISIBLE_CHARACTER.finding(
                change.path, line.number, text, f"U+{ord(ch):04X} {_INVISIBLE[ch]} at column {col}."
            )
            break
        for match in _WORD_RE.finditer(text):
            scripts = {_script(ch) for ch in match[0]}
            if "LATIN" in scripts and scripts & {"CYRILLIC", "GREEK"}:
                odd = [f"'{ch}' U+{ord(ch):04X}" for ch in match[0] if _script(ch) != "LATIN"][:3]
                yield MIXED_SCRIPT.finding(
                    change.path, line.number, text,
                    f"'{match[0]}' mixes Latin with {' and '.join(sorted(scripts - {'LATIN'})).title()} "
                    f"letters: {', '.join(odd)}.",
                )  # fmt: skip
                break


def _script(ch: str) -> str:
    name = unicodedata.name(ch, "")
    return next((s for s in _SCRIPTS if name.startswith(s)), "OTHER")


def _blob_file(path: str) -> bool:
    return is_runnable(path) and not is_lockfile(path) and suffix(path) not in (".svg", ".ipynb", ".json")


class EncodedPayloadDetector(LineDetector):
    name = "encoded-payloads"
    rules = (ENCODED_BLOB, DECODE_AND_RUN, LONG_LINE)

    def check_line(self, change: FileChange, line: DiffLine) -> Iterator[Finding]:
        path, text = change.path, line.text
        if is_doc(path):
            return
        if _DECODE_AND_RUN_RE.search(text) and is_runnable(path) and not is_comment(text):
            yield DECODE_AND_RUN.finding(
                path, line.number, text, "Decodes a string and executes the result.",
                confidence=Confidence.MEDIUM if is_test(path) else None,
            )  # fmt: skip
        if _blob_file(path) and not _EMBEDDED_ASSET_RE.search(text):
            detail = self._blob(text)
            if detail:
                yield ENCODED_BLOB.finding(
                    path, line.number, text, detail,
                    severity=Severity.LOW if is_test(path) else None,
                    confidence=Confidence.LOW if is_test(path) else None,
                )  # fmt: skip
        if len(text) > _LONG_LINE_CHARS and is_source(path):
            yield LONG_LINE.finding(path, line.number, text, f"The line is {len(text):,} characters long.")

    @staticmethod
    def _blob(text: str) -> str | None:
        if (m := _BASE64_RE.search(text)) and entropy(m[0]) >= 4.5:
            return f"{len(m[0]):,} characters of base64-like data."
        if (m := _HEX_RE.search(text)) and entropy(m[0]) >= 3.0:
            return f"{len(m[0]) // 2:,} bytes written as hex."
        if m := _ESCAPES_RE.search(text):
            return f"{len(m[0]):,} characters of escape sequences or character codes."
        return None


class BinaryFileDetector(Detector):
    name = "binaries"
    rules = (OPAQUE_BINARY,)

    def scan(self, diff: Diff) -> Iterator[Finding]:
        for change in diff.files:
            if change.kind is ChangeKind.DELETED:
                continue
            ext = suffix(change.path)
            if ext in _EXECUTABLE_SUFFIXES and (change.binary or not change.added):
                detail = "Adds compiled code that cannot be reviewed as text."
                confidence = None
            elif ext in _ARCHIVE_SUFFIXES:
                detail = "Adds an archive whose contents are not shown in the diff."
                confidence = Confidence.MEDIUM
            else:
                continue
            low = is_test(change.path) or is_vendored(change.path)
            yield OPAQUE_BINARY.finding(
                change.path, None, change.path, detail,
                severity=Severity.LOW if low or ext in _ARCHIVE_SUFFIXES else None,
                confidence=confidence,
            )  # fmt: skip
