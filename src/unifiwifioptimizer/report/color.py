"""ANSI colour for the check marks that open a report row. The renderers stay plain text; the command line
applies this only where a person reads the output."""

import re
from collections.abc import Mapping
from typing import TextIO

MARK_COLOURS: Mapping[str, str] = {
    "✓": "32",
    "✗": "31",
    "!": "33",
    "*": "1;33",
    "?": "36",
    "·": "2",
    "-": "2",
}
_ROW = re.compile(r"^( +)([✓✗!*?·-])(?= )", re.MULTILINE)


def wants_colour(stream: TextIO, environ: Mapping[str, str]) -> bool:
    """A terminal, unless the user opted out (NO_COLOR, https://no-color.org) or the terminal is `dumb`."""
    return stream.isatty() and not environ.get("NO_COLOR") and environ.get("TERM") != "dumb"


def colourise(text: str) -> str:
    return _ROW.sub(lambda match: f"{match[1]}\x1b[{MARK_COLOURS[match[2]]}m{match[2]}\x1b[0m", text)
