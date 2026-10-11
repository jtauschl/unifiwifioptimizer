"""Terminal-safe rendering of strings that came from the controller or an access point."""

import re
import unicodedata

MAX_CHARS = 64
_ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b[@-Z\\-_]")
# C0/C1 controls, DEL, surrogates, private use, unassigned, format characters (incl. every bidi control),
# and the line/paragraph separators that would break a table row.
UNSAFE_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"})


def safe_text(value: str, max_chars: int = MAX_CHARS) -> str:
    """`value` with escape sequences and every `UNSAFE_CATEGORIES` character turned into U+FFFD, truncated with an
    ellipsis; the bidirectional overrides and isolates that could reorder what the reader sees are format
    characters and fall under the replacement."""
    text = "".join("�" if unicodedata.category(char) in UNSAFE_CATEGORIES else char for char in _ANSI_RE.sub("", value))
    if len(text) > max_chars:
        return text[: max_chars - 1] + "…"
    return text
