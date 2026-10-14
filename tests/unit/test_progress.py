"""The stderr progress sanitises every external name before it reaches the terminal."""

import io

import pytest

from unifiwifioptimizer.cli.progress import StderrProgress
from unifiwifioptimizer.domain.scan import ScanFailure, ScanFailureKind

RLO = chr(0x202E)


@pytest.mark.security("T12")
def test_stderr_progress_sanitises_names_and_names_the_failure_kind() -> None:
    out = io.StringIO()
    progress = StderrProgress(out)
    hostile = "AP-\x1b[2J" + RLO + "1"
    progress.site_started("site\x1b[0m", scanning=True)
    progress.scan_started(hostile, 0, 3)
    progress.scan_finished(hostile, ScanFailure(kind=ScanFailureKind.TIMEOUT, detail="slow"))
    progress.scan_finished(hostile, ScanFailure(kind=ScanFailureKind.AUTHENTICATION, detail="x"))
    progress.analysis_started("site")
    text = out.getvalue()
    assert "\x1b" not in text and RLO not in text
    safe = "AP-" + chr(0xFFFD) + "1"
    assert text.splitlines() == [
        "  reading and scanning site site...",
        f"    scanning {safe} (pass 1/3)...",
        f"    {safe}: scan failed (timeout)",
        f"    {safe}: scan failed (authentication)",
        "  analysing site site...",
    ]
