"""Terminal-safe rendering of strings that came from the controller or an access point."""

import re
import unicodedata

MAX_CHARS = 64
_ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b[@-Z\\-_]")
# C0/C1 controls, DEL, surrogates, private use, unassigned, format characters (incl. every bidi control),
# and the line/paragraph separators that would break a table row.
UNSAFE_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"})
# The report's own line marks (check and recommendation status, finding severity, neighbour markers, the
# UI-path arrow, the rule). An external string that opens a report line must not start with one of them, or
# an access point named `→ AP settings → …` would read as the tool's own advice.
REPORT_MARKS = frozenset("✓✗?-·!*°~→━")


def safe_text(value: str, max_chars: int = MAX_CHARS) -> str:
    """`value` with escape sequences and every `UNSAFE_CATEGORIES` character turned into U+FFFD, truncated with an
    ellipsis; the bidirectional overrides and isolates that could reorder what the reader sees are format
    characters and fall under the replacement."""
    text = "".join("�" if unicodedata.category(char) in UNSAFE_CATEGORIES else char for char in _ANSI_RE.sub("", value))
    if len(text) > max_chars:
        return text[: max_chars - 1] + "…"
    return text


# Characters that are not format characters but show nothing of their own, or nothing that could hide a
# mark: the Hangul fillers, the braille blank, the null notehead, and the combining marks (a nonspacing
# mark shows nothing of its own; the spacing and enclosing ones attach to the blank before them and are
# skipped too, erring towards the replacement). Skipped when looking for the first visible character, never
# replaced.
INVISIBLE_LEADERS = frozenset("\u115f\u1160\u3164\uffa0\u2800\U0001d159")
_COMBINING = frozenset({"Mn", "Mc", "Me"})


def hides_nothing(char: str) -> bool:
    """A blank, an invisible leader or a combining mark: a character that cannot stand between a mark and
    the eye."""
    return char.isspace() or char in INVISIBLE_LEADERS or unicodedata.category(char) in _COMBINING


def _first_visible(text: str) -> int:
    for index, char in enumerate(text):
        if not hides_nothing(char):
            return index
    return len(text)


def safe_line_start(value: str, max_chars: int = MAX_CHARS) -> str:
    """`safe_text` for a string that opens a report line: its first visible character becomes U+FFFD when it
    is one of `REPORT_MARKS`; leading blanks (also the no-break and ideographic spaces), combining marks and
    the invisible fillers do not hide it. Lookalike glyphs (`➔`, `✔`, `•`) are left alone: they are not the
    report's marks."""
    text = safe_text(value, max_chars)
    first = _first_visible(text)
    if first < len(text) and text[first] in REPORT_MARKS:
        return text[:first] + "�" + text[first + 1 :]
    return text
