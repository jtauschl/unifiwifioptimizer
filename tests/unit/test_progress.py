"""The stderr progress keeps terminals compact and redirected output safe."""

import io
import os

import pytest

from unifiwifioptimizer.cli.progress import StderrProgress, _cell_width
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
    progress.scan_started(hostile, 1, 3)
    progress.scan_finished(hostile, ScanFailure(kind=ScanFailureKind.AUTHENTICATION, detail="x"))
    progress.analysis_started("site")
    text = out.getvalue()
    assert "\x1b" not in text and RLO not in text
    safe = "AP-" + chr(0xFFFD) + "1"
    assert text.splitlines() == [
        "  reading and scanning site site...",
        f"    {safe}: scan failed (timeout, pass 1/3)",
        f"    {safe}: scan failed (authentication, pass 2/3)",
        "  analysing site site...",
    ]


class Terminal(io.StringIO):
    def isatty(self) -> bool:
        return True

    def fileno(self) -> int:
        return 2


def test_interactive_scan_rewrites_one_bounded_line_and_clears_it_before_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    out = Terminal()
    monkeypatch.setattr(os, "get_terminal_size", lambda fd: os.terminal_size((40, 24)))
    progress = StderrProgress(out)
    progress.site_started("site", scanning=True)
    hostile = "AP-\x1b[31m" + RLO + "x" * 70
    progress.scan_started(hostile, 0, 3)
    progress.scan_started("AP", 0, 3)
    progress.scan_finished("AP", ScanFailure(kind=ScanFailureKind.TIMEOUT, detail="slow"))
    progress.scan_finished(hostile, ScanFailure(kind=ScanFailureKind.TIMEOUT, detail="slow"))
    progress.scan_started("無線" * 30, 1, 3)
    progress.analysis_started("site")
    text = out.getvalue()
    assert text.count("Scanning") == 3 and text.count("scan failed") == 2
    assert "\r" in text and "\x1b" not in text and RLO not in text
    assert "    AP: scan failed (timeout, pass 1/3)\n" in text
    assert all(_cell_width(part) <= 39 for part in text.split("\r") if part.startswith("  Scanning"))
    assert "pass 2/3" in text
    assert text.endswith("  analysing site site...\n")


def test_finish_ends_an_unfinished_status_line(monkeypatch: pytest.MonkeyPatch) -> None:
    out = Terminal()
    monkeypatch.setattr(os, "get_terminal_size", lambda fd: os.terminal_size((60, 24)))
    progress = StderrProgress(out)
    progress.scan_started("AP-1", 0, 3)
    assert "Scanning AP-1" in out.getvalue()
    progress.finish()
    out.write("error: interrupted\n")
    assert out.getvalue().endswith("\r" + " " * len("  Scanning AP-1 · pass 1/3") + "\rerror: interrupted\n")
    progress.finish()
    assert out.getvalue().count("\r") == 3


def test_concurrent_scans_are_counted_instead_of_naming_the_last_access_point(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    out = Terminal()
    monkeypatch.setattr(os, "get_terminal_size", lambda fd: os.terminal_size((60, 24)))
    progress = StderrProgress(out)
    for name in ("AP-1", "AP-2", "AP-3"):
        progress.scan_started(name, 0, 3)
    assert out.getvalue().split("\r")[-1].startswith("  Scanning 3 access points · pass 1/3")
    progress.scan_finished("AP-1", ScanFailure(kind=ScanFailureKind.TIMEOUT, detail="slow"))
    progress.scan_started("AP-4", 1, 3)
    assert out.getvalue().split("\r")[-1].startswith("  Scanning 3 access points · pass 2/3")
