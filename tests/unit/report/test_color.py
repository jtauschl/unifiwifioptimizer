"""Colour marks the opening symbol of a report row and nothing else."""

import io

import pytest

from unifiwifioptimizer.report.color import MARK_COLOURS, colourise, wants_colour

ESC = "\x1b"


class Terminal(io.StringIO):
    def isatty(self) -> bool:
        return True


@pytest.mark.parametrize(("mark", "code"), sorted(MARK_COLOURS.items()))
def test_each_mark_is_wrapped_in_its_own_colour_and_reset(mark: str, code: str) -> None:
    assert colourise(f"    {mark} Transmit Power   6 dBm") == f"    {ESC}[{code}m{mark}{ESC}[0m Transmit Power   6 dBm"


def test_only_the_leading_mark_of_an_indented_row_is_coloured() -> None:
    text = "  5 GHz\n    ✗ Channel   44 → 100 (set fixed)\n        → AP settings - x ✓\nplain ✓ line\n"
    out = colourise(text)
    assert out.splitlines()[0] == "  5 GHz"
    assert out.splitlines()[1].startswith(f"    {ESC}[31m✗{ESC}[0m Channel")
    assert out.splitlines()[2] == "        → AP settings - x ✓"
    assert out.splitlines()[3] == "plain ✓ line"


def test_a_value_that_starts_with_a_dash_is_not_a_mark() -> None:
    assert colourise("  AP-2   -72 dBm n=3\n    -72 dBm") == "  AP-2   -72 dBm n=3\n    -72 dBm"


def test_text_without_marks_is_unchanged() -> None:
    assert colourise("━━━━\n  Site  default\n") == "━━━━\n  Site  default\n"


@pytest.mark.parametrize(
    ("environ", "expected"),
    [
        ({}, True),
        ({"TERM": "xterm-256color"}, True),
        ({"NO_COLOR": "1"}, False),
        ({"TERM": "dumb"}, False),
        ({"NO_COLOR": ""}, True),
    ],
)
def test_colour_is_for_terminals_unless_the_user_opts_out(environ: dict[str, str], expected: bool) -> None:
    assert wants_colour(Terminal(), environ) is expected


def test_redirected_output_is_never_coloured() -> None:
    assert wants_colour(io.StringIO(), {}) is False
