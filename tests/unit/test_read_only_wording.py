"""The statement of what the tool leaves untouched is one fact, worded the same on every surface: it changes no
setting on the controller or on an access point, and a scan takes a radio off-channel briefly."""

import re
from pathlib import Path

import pytest

from unifiwifioptimizer.cli.main import build_parser

ROOT = Path(__file__).resolve().parents[2]
SURFACES = {
    "README.md": lambda: (ROOT / "README.md").read_text(encoding="utf-8"),
    "SECURITY.md": lambda: (ROOT / "SECURITY.md").read_text(encoding="utf-8"),
    "pyproject.toml": lambda: (ROOT / "pyproject.toml").read_text(encoding="utf-8"),
    "--help": lambda: build_parser().format_help(),
}


def squeezed(text: str) -> str:
    return " ".join(text.split())


@pytest.mark.parametrize("surface", SURFACES)
def test_every_surface_says_that_no_setting_changes_and_that_a_scan_goes_off_channel(surface: str) -> None:
    text = squeezed(SURFACES[surface]())
    assert re.search(r"never changes a setting|changes no setting", text), surface
    assert "off-channel" in text, surface


@pytest.mark.parametrize("surface", SURFACES)
def test_no_surface_claims_that_the_tool_never_writes_to_an_access_point_or_is_read_only_as_a_whole(
    surface: str,
) -> None:
    text = squeezed(SURFACES[surface]())
    assert not re.search(r"never\W+writes?\W+to\W+the\W+controller\W+or\W+to\W+an\W+access\W+point", text, re.I), (
        surface
    )
    assert "Read-only RF-tuning" not in text and "is a read-only diagnostic tool" not in text, surface
