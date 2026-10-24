"""What the documentation promises about the configuration surface, checked against the code that enforces it."""

import contextlib
import io
import re
import shlex
from pathlib import Path
from unittest import mock

import pytest

from tests.unit.analysis.builders import golden_input
from tests.unit.test_cli_commands import FixtureApi
from unifiwifioptimizer.cli import main as cli
from unifiwifioptimizer.config.load import LoadedConfig
from unifiwifioptimizer.config.loader import parse_yaml
from unifiwifioptimizer.config.locations import ConfigLocation
from unifiwifioptimizer.config.schema import CONTROLLER_KEYS, RF_KEYS, SITE_KEYS, SSH_KEYS, Config

README = Path(__file__).resolve().parents[2] / "README.md"
TABLE = re.compile(r"<!-- config-keys:start -->\n(?P<table>.*?)\n<!-- config-keys:end -->", re.DOTALL)
ROW = re.compile(r"^\| `(?P<key>[^`]+)` \|", re.MULTILINE)


def readme_key_paths() -> list[str]:
    match = TABLE.search(README.read_text(encoding="utf-8"))
    assert match is not None, "the README key table lost its markers"
    return ROW.findall(match.group("table"))


def schema_key_paths() -> set[str]:
    return (
        {f"controller.{key}" for key in CONTROLLER_KEYS}
        | {f"sites.<site>.ssh.{key}" for key in SSH_KEYS}
        | {f"sites.<site>.{key}" for key in SITE_KEYS - {"ssh"}}
        | {f"rf.{key}" for key in RF_KEYS}
    )


def test_the_readme_key_table_lists_every_key_the_schema_accepts_and_no_other() -> None:
    documented = readme_key_paths()
    assert len(documented) == len(set(documented)), "a key is documented twice"
    assert set(documented) == schema_key_paths()


# --- the walkthrough: every output block is real output, every command parses ---------------------------------

ROOT = Path(__file__).resolve().parents[2]
WALKTHROUGH = ROOT / "docs" / "WALKTHROUGH.md"
GOLDEN = ROOT / "tests" / "fixtures" / "golden" / "run_default.txt"
SUMMARY_GOLDEN = ROOT / "tests" / "fixtures" / "golden" / "run_summary.txt"
BLOCK = re.compile(r"<!-- source: (?P<source>[\w-]+) -->\n```(?P<lang>\w+)\n(?P<body>.*?)\n```", re.DOTALL)
ELISION = "[…]"
WHOLE = {"sites": ["sites"], "site": ["site", "default"], "skeleton": ["config", "default"]}


def walkthrough_blocks() -> list[tuple[str, str]]:
    return [(m.group("source"), m.group("body")) for m in BLOCK.finditer(WALKTHROUGH.read_text(encoding="utf-8"))]


def documented_config() -> Config:
    """The walkthrough's configuration through the product's own strict loader."""
    (body,) = [body for source, body in walkthrough_blocks() if source == "config"]
    return Config.from_mapping(parse_yaml(body, "docs/WALKTHROUGH.md"))


def run_cli(argv: list[str]) -> str:
    out = io.StringIO()
    loaded = LoadedConfig(
        config=documented_config(),
        location=ConfigLocation(Path("/cfg/config.yaml"), legacy=False),
        env_ssh_password=None,
    )
    with (
        mock.patch.object(cli, "load_config", lambda explicit=None: loaded),
        mock.patch.object(cli, "_client", lambda loaded_config, args: (FixtureApi(), None)),
        contextlib.redirect_stdout(out),
        contextlib.redirect_stderr(io.StringIO()),
    ):
        assert cli.main(argv) == 0
    return out.getvalue()


def contiguous_in_order(segments: list[list[str]], source: list[str]) -> bool:
    position = 0
    for segment in segments:
        starts = [
            start for start in range(len(source) - len(segment) + 1) if source[start : start + len(segment)] == segment
        ]
        # A segment that occurs twice proves little: it could be quoting either place.
        if len(starts) != 1 or starts[0] < position:
            return False
        position = starts[0] + len(segment)
    return True


def segments_of(body: str) -> list[list[str]]:
    segments: list[list[str]] = [[]]
    for line in body.splitlines():
        if line == ELISION:
            segments.append([])
        else:
            segments[-1].append(line)
    return [segment for segment in segments if segment]


EXPECTED_BLOCKS = {"sites": 1, "site": 1, "skeleton": 1, "config": 1, "no-scan": 2, "golden": 5, "summary": 1}


def test_every_output_block_of_the_walkthrough_carries_a_known_marker_and_is_checked() -> None:
    text = WALKTHROUGH.read_text(encoding="utf-8")
    sources = [source for source, _ in walkthrough_blocks()]
    assert text.count("<!-- source:") == len(sources), "a marker is misspelled or detached from its block"
    assert {source: sources.count(source) for source in set(sources)} == EXPECTED_BLOCKS
    # Every text fence is a checked output block, except the one-line layout diagram.
    assert text.count("```text") == len([source for source in sources if source != "config"]) + 1


@pytest.mark.parametrize("source", sorted(WHOLE))
def test_a_whole_command_output_in_the_walkthrough_is_the_tools_output(source: str) -> None:
    (body,) = [body for name, body in walkthrough_blocks() if name == source]
    assert body.splitlines() == run_cli(WHOLE[source]).strip("\n").splitlines()


def test_the_walkthrough_config_is_accepted_by_the_products_loader_and_describes_the_golden_site() -> None:
    config = documented_config()
    site = config.sites["default"]
    golden = golden_input()
    assert site.ssh is not None and site.ssh.scan_interface_toggle is True
    assert (golden.neighbours, golden.environment, golden.scan_passes) == (
        site.neighbors,
        site.environment,
        site.scan_passes,
    )
    assert dict(site.wlans) == {
        "SSID-1": "Throughput",
        "SSID-2": "Standard",
        "SSID-3": "Hotspot",
    }


def test_every_excerpt_of_the_controller_side_run_is_verbatim_output_in_order() -> None:
    actual = run_cli(["run", "--no-scan", "--details"]).splitlines()
    excerpts = [body for source, body in walkthrough_blocks() if source == "no-scan"]
    for body in excerpts:
        assert contiguous_in_order(segments_of(body), actual), body


def test_every_excerpt_of_the_full_run_is_verbatim_golden_output_in_order() -> None:
    actual = GOLDEN.read_text(encoding="utf-8").splitlines()
    excerpts = [body for source, body in walkthrough_blocks() if source == "golden"]
    for body in excerpts:
        assert contiguous_in_order(segments_of(body), actual), body


def test_the_default_view_in_the_walkthrough_is_the_tools_default_output() -> None:
    (body,) = [body for source, body in walkthrough_blocks() if source == "summary"]
    assert body.splitlines() == SUMMARY_GOLDEN.read_text(encoding="utf-8").strip("\n").splitlines()


def command_lines(path: Path) -> list[list[str]]:
    """The argument lists of every `unifiwifioptimizer …` line in a fenced bash block, redirects dropped."""
    lines: list[list[str]] = []
    fence = re.compile(r"^[ \t]*```bash\n(.*?)\n[ \t]*```", re.DOTALL | re.MULTILINE)
    for block in fence.findall(path.read_text(encoding="utf-8")):
        for raw in block.splitlines():
            line = raw.strip()
            if line.startswith("unifiwifioptimizer"):
                words = shlex.split(line, comments=True)
                if ">>" in words:
                    words = words[: words.index(">>")]
                lines.append([word if not word.startswith("<") else "x" for word in words[1:]])
    return lines


@pytest.mark.parametrize("document", [ROOT / "README.md", WALKTHROUGH])
def test_every_documented_command_parses_against_the_real_command_line(document: Path) -> None:
    commands = command_lines(document)
    assert len(commands) >= 6, f"{document.name}: too few commands found to prove anything"
    for argv in commands:
        try:
            cli.build_parser().parse_args(argv)
        except SystemExit as exit_:
            pytest.fail(f"{document.name}: `unifiwifioptimizer {' '.join(argv)}` is not a valid command ({exit_.code})")


@pytest.mark.parametrize("document", [ROOT / "README.md", WALKTHROUGH, ROOT / "docs" / "ALGORITHM.md"])
def test_no_document_sends_the_reader_to_the_removed_tool_or_the_removed_aggregation(document: Path) -> None:
    text = document.read_text(encoding="utf-8")
    assert "./unifiwifioptimizer" not in text and "trimmed mean" not in text
