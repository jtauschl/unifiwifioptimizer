"""Progress on stderr with a single updating scan line in interactive terminals."""

import os
import sys
import unicodedata
from typing import TextIO

from unifiwifioptimizer.domain.scan import ScanFailure, ScanPass
from unifiwifioptimizer.report.safe_text import safe_text


def _cell_width(value: str) -> int:
    return sum(
        0 if unicodedata.combining(char) else 2 if unicodedata.east_asian_width(char) in ("W", "F") else 1
        for char in value
    )


def _fit_status(value: str, columns: int) -> str:
    limit = max(1, columns - 1)
    shown: list[str] = []
    used = 0
    for char in value:
        width = _cell_width(char)
        if used + width > limit:
            break
        shown.append(char)
        used += width
    return "".join(shown)


class StderrProgress:
    def __init__(self, stream: TextIO | None = None) -> None:
        self._stream = stream if stream is not None else sys.stderr
        self._interactive = self._stream.isatty()
        self._status_width = 0
        self._active = 0
        self._pass_of: dict[str, tuple[int, int]] = {}

    def _say(self, text: str) -> None:
        self._clear_status()
        print(text, file=self._stream, flush=True)

    def _clear_status(self) -> None:
        if self._status_width:
            self._stream.write("\r" + " " * self._status_width + "\r")
            self._stream.flush()
            self._status_width = 0

    def finish(self) -> None:
        """Ends an unfinished status line, so an error message never continues it."""
        self._clear_status()

    def site_started(self, site_id: str, scanning: bool) -> None:
        what = "reading and scanning" if scanning else "reading"
        self._say(f"  {what} site {safe_text(site_id)}...")

    def scan_started(self, ap_name: str, pass_index: int, passes: int) -> None:
        self._active += 1
        self._pass_of[ap_name] = (pass_index, passes)
        if not self._interactive:
            return
        try:
            columns = os.get_terminal_size(self._stream.fileno()).columns
        except (OSError, ValueError):
            columns = 80
        prefix, suffix = "  Scanning ", f" · pass {pass_index + 1}/{passes}"
        label_columns = max(1, columns - _cell_width(prefix) - _cell_width(suffix))
        who = safe_text(ap_name, 64) if self._active == 1 else f"{self._active} access points"
        label = _fit_status(who, label_columns)
        line = _fit_status(f"{prefix}{label}{suffix}", columns)
        line_width = _cell_width(line)
        self._stream.write("\r" + line + " " * max(0, self._status_width - line_width))
        self._stream.flush()
        self._status_width = line_width

    def scan_finished(self, ap_name: str, outcome: ScanPass | ScanFailure) -> None:
        self._active -= 1
        if isinstance(outcome, ScanFailure):
            pass_index, passes = self._pass_of[ap_name]
            self._say(f"    {safe_text(ap_name)}: scan failed ({outcome.kind.value}, pass {pass_index + 1}/{passes})")

    def analysis_started(self, site_id: str) -> None:
        self._say(f"  analysing site {safe_text(site_id)}...")
