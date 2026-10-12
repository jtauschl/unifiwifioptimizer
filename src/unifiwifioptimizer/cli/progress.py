"""Progress on stderr: one line per site, scan pass and access point, every external name sanitised."""

import sys
from typing import TextIO

from unifiwifioptimizer.domain.scan import ScanFailure, ScanPass
from unifiwifioptimizer.report.safe_text import safe_text


class StderrProgress:
    def __init__(self, stream: TextIO | None = None) -> None:
        self._stream = stream if stream is not None else sys.stderr

    def _say(self, text: str) -> None:
        print(text, file=self._stream, flush=True)

    def site_started(self, site_id: str, scanning: bool) -> None:
        what = "reading and scanning" if scanning else "reading"
        self._say(f"  {what} site {safe_text(site_id)}...")

    def scan_started(self, ap_name: str, pass_index: int, passes: int) -> None:
        suffix = f" (pass {pass_index + 1}/{passes})" if passes > 1 else ""
        self._say(f"    scanning {safe_text(ap_name)}{suffix}...")

    def scan_finished(self, ap_name: str, outcome: ScanPass | ScanFailure) -> None:
        if isinstance(outcome, ScanFailure):
            self._say(f"    {safe_text(ap_name)}: scan failed ({outcome.kind.value})")

    def analysis_started(self, site_id: str) -> None:
        self._say(f"  analysing site {safe_text(site_id)}...")
