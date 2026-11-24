"""The commands the tool prints: where each option sits, how a path is quoted, and that a person can paste them."""

import shlex
import shutil
import subprocess
from pathlib import Path

import pytest

from tests.unit.printed import PLAIN, given
from unifiwifioptimizer.app.run import RunResult, SiteOutcome
from unifiwifioptimizer.app.trust import TrustOutcome, TrustResult, trust_step
from unifiwifioptimizer.cli import main as cli
from unifiwifioptimizer.cli.main import build_parser
from unifiwifioptimizer.cli.printed import printed_commands
from unifiwifioptimizer.config.load import load_config
from unifiwifioptimizer.domain.analysis import PartialReason
from unifiwifioptimizer.domain.commands import PROGRAM, PrintedCommands
from unifiwifioptimizer.domain.errors import MAX_ERROR_CHARS, MAX_PATH_CHARS, ConfigNotFoundError
from unifiwifioptimizer.domain.hostkeys import TrustRefusalKind
from unifiwifioptimizer.domain.scan import ScanFailureKind
from unifiwifioptimizer.report.safe_text import safe_text

CONFIG = "/etc/uwo/home.yaml"
STORE = "/var/lib/uwo/known_hosts"
BOTH = given(config_file=CONFIG, known_hosts=STORE)
PATH_WITH_BACKTICK = "/tmp/a`b"


def test_every_shape_with_no_option_names_the_program_and_nothing_else() -> None:
    assert PLAIN.trust_host_keys("default") == "`unifiwifioptimizer trust-host-keys --site default`"
    assert PLAIN.site("default") == "`unifiwifioptimizer site default`"
    assert PLAIN.config("<site-id>") == "`unifiwifioptimizer config <site-id>`"
    assert PLAIN.controller_fingerprint() == "`unifiwifioptimizer controller-fingerprint`"
    assert PLAIN.init() == "`unifiwifioptimizer init`"


def test_the_global_option_sits_before_the_subcommand_on_every_shape_and_the_store_option_after_its_arguments() -> None:
    config = "--config-file=/etc/uwo/home.yaml"
    assert BOTH.trust_host_keys("d") == (
        f"`unifiwifioptimizer {config} trust-host-keys --site d --known-hosts=/var/lib/uwo/known_hosts`"
    )
    assert BOTH.site("d") == f"`unifiwifioptimizer {config} site d`"
    assert BOTH.config("d") == f"`unifiwifioptimizer {config} config d`"
    assert BOTH.controller_fingerprint() == f"`unifiwifioptimizer {config} controller-fingerprint`"
    assert BOTH.init() == f"`unifiwifioptimizer {config} init`"


def test_only_the_trust_command_carries_the_store_and_only_the_given_option_is_printed() -> None:
    store_only = given(known_hosts=STORE)
    assert store_only.trust_host_keys("d").endswith("trust-host-keys --site d --known-hosts=/var/lib/uwo/known_hosts`")
    assert "--config-file" not in store_only.trust_host_keys("d")
    for command in (
        store_only.site("d"),
        store_only.config("d"),
        store_only.controller_fingerprint(),
        store_only.init(),
    ):
        assert "--known-hosts" not in command
    config_only = given(config_file=CONFIG)
    assert "--known-hosts" not in config_only.trust_host_keys("d")


@pytest.mark.parametrize(
    "path",
    [
        "/etc/uwo/home.yaml",
        "/Volumes/Temp HD/UWO/known hosts",
        "/tmp/it's here/kh",
        "-leading-dash.yaml",
        "/tmp/ünï/kh",
        "/tmp/$(id)/kh",
        "~/kh",
    ],
)
def test_a_printed_command_parses_to_the_files_it_was_built_from(path: str) -> None:
    commands = given(config_file=path, known_hosts=path)
    parser = build_parser()
    for command, subcommand in (
        (commands.trust_host_keys("default"), "trust-host-keys"),
        (commands.site("default"), "site"),
        (commands.config("default"), "config"),
        (commands.controller_fingerprint(), "controller-fingerprint"),
        (commands.init(), "init"),
    ):
        argv = shlex.split(command.strip("`"))
        assert argv[0] == PROGRAM
        args = parser.parse_args(argv[1:])
        assert args.subcommand == subcommand
        assert args.config_file == Path(path)
        assert args.known_hosts == (Path(path) if subcommand == "trust-host-keys" else None)


def test_the_store_option_is_taken_by_exactly_the_subcommands_that_print_it() -> None:
    parser = build_parser()
    taking = set()
    for subcommand, argv in {
        "run": ["run"],
        "sites": ["sites"],
        "site": ["site", "d"],
        "config": ["config", "d"],
        "init": ["init"],
        "controller-fingerprint": ["controller-fingerprint"],
        "trust-host-keys": ["trust-host-keys", "--site", "d"],
    }.items():
        try:
            parser.parse_args([*argv, "--known-hosts", "/kh"])
        except SystemExit:
            continue
        taking.add(subcommand)
    # `run` takes it too, but no printed command is a `run`; every printed command that takes it carries it.
    assert taking == {"run", "trust-host-keys"}


@pytest.mark.parametrize(
    ("path", "kind"),
    [
        ("/tmp/a\x1b[2Jb", "escape"),
        ("/tmp/a\tb", "tab"),
        ("/tmp/a\nb", "newline"),
        ("/tmp/a​b", "zero-width"),
        ("/tmp/a`b", "backtick"),
        ("/" + "d" * MAX_PATH_CHARS, "too long"),
    ],
)
def test_a_path_that_cannot_be_printed_as_typed_inside_a_command_is_withheld_and_named_after_it(
    path: str, kind: str
) -> None:
    commands = printed_commands(Path(path), Path(path))
    assert (commands.config_option, commands.store_option) == (" --config-file=", " --known-hosts="), kind
    assert commands.withheld == ("--config-file", "--known-hosts"), kind
    one = "(the value of {} in this run cannot be printed as typed; fill in the empty option)"
    both = (
        "(the values of --config-file and --known-hosts in this run cannot be printed as typed; "
        "fill in the empty options)"
    )
    assert commands.init() == f"`unifiwifioptimizer --config-file= init` {one.format('--config-file')}"
    assert commands.trust_host_keys("d") == (
        f"`unifiwifioptimizer --config-file= trust-host-keys --site d --known-hosts=` {both}"
    )
    only_store = printed_commands(None, Path(path))
    assert only_store.init() == "`unifiwifioptimizer init`"
    assert only_store.site("d") == "`unifiwifioptimizer site d`"
    assert only_store.config("d") == "`unifiwifioptimizer config d`"
    assert only_store.controller_fingerprint() == "`unifiwifioptimizer controller-fingerprint`"
    assert only_store.trust_host_keys("d") == (
        f"`unifiwifioptimizer trust-host-keys --site d --known-hosts=` {one.format('--known-hosts')}"
    )


def test_a_command_with_a_withheld_option_and_a_printed_one_names_only_the_withheld_one() -> None:
    commands = printed_commands(Path("/tmp/a`b"), Path(STORE))
    assert commands.trust_host_keys("d") == (
        "`unifiwifioptimizer --config-file= trust-host-keys --site d --known-hosts=/var/lib/uwo/known_hosts` "
        "(the value of --config-file in this run cannot be printed as typed; fill in the empty option)"
    )


def quoted_to(length: int) -> str:
    """A path whose shell-quoted word is exactly `length` characters (blanks force the two quotes)."""
    return ("a " * length)[: length - 2]


def test_a_path_at_the_bound_is_printed_whole_and_one_character_more_is_not() -> None:
    at_bound = quoted_to(MAX_PATH_CHARS)
    assert len(shlex.quote(at_bound)) == MAX_PATH_CHARS
    assert printed_commands(Path(at_bound), None).config_option == f" --config-file={shlex.quote(at_bound)}"
    over = printed_commands(Path(quoted_to(MAX_PATH_CHARS + 1)), None)
    assert over.config_option == " --config-file=" and over.withheld == ("--config-file",)


def test_a_path_well_under_the_bound_is_printed_whole() -> None:
    for length in (120, 150, 250):
        assert printed_commands(Path(quoted_to(length)), None).withheld == ()


def test_no_option_is_printed_for_a_run_that_was_given_none() -> None:
    assert printed_commands(None, None) == PLAIN


def outcome(site: str, *, count: int = 2) -> SiteOutcome:
    return SiteOutcome(
        site_id=site,
        scanning=True,
        partial_reasons=(PartialReason.SCAN_FAILED,),
        scanned_ap_count=4,
        verifiable_ap_count=0,
        host_key_failures={ScanFailureKind.HOST_KEY_UNKNOWN: count, ScanFailureKind.HOST_KEY_MISMATCH: count},
    )


def worst_exit_5_line(quoted_length: int) -> tuple[str, PrintedCommands]:
    """Both kinds after the gate (the longest steps), the longest site id, the largest counts a controller can
    report, and both options at `quoted_length`."""
    commands = PrintedCommands(
        config_option=" --config-file=" + "c" * quoted_length,
        store_option=" --known-hosts=" + "s" * quoted_length,
        withheld=(),
    )
    result = RunResult(reports=(), outcomes=(outcome("s" * 64, count=9999),), host_key_gate_ran=True)
    (line,) = cli.host_key_exit_lines(result, commands)
    return line, commands


def test_the_bound_is_below_the_longest_path_that_keeps_the_worst_exit_5_line_whole() -> None:
    def whole(length: int) -> bool:
        line, commands = worst_exit_5_line(length)
        return line.count(commands.trust_host_keys("s" * 64)) == 2

    longest = max(length for length in range(100, 600) if whole(length))
    assert not whole(longest + 1) and longest >= MAX_PATH_CHARS
    assert whole(MAX_PATH_CHARS)


def test_a_result_line_cuts_the_reason_and_never_the_command_beside_it() -> None:
    commands = given(config_file=quoted_to(MAX_PATH_CHARS), known_hosts="x" + quoted_to(MAX_PATH_CHARS - 1))
    step = trust_step(TrustRefusalKind.SEVERAL_STORED_LINES, "s" * 64, commands)
    for raw_path in ("/" + "d" * 1500, "/" + "d" * 4000):
        result = TrustResult(
            ap_name="a" * 128,
            outcome=TrustOutcome.FAILED,
            basis=None,
            detail=f"several entries are stored for this access point (alias x) in {raw_path}",
            next_step=step,
        )
        line = cli._result_line(result)
        assert line.endswith(f"; {step}") and len(line) <= MAX_ERROR_CHARS


def test_the_missing_configuration_error_keeps_its_command_whole_whatever_the_path() -> None:
    for length in (MAX_PATH_CHARS, 1900, 4000):
        named = Path("/uwo-absent/" + "d" * length)
        commands = given(config_file=str(named))
        with pytest.raises(ConfigNotFoundError) as raised:
            load_config(named, commands)
        text = f"{PROGRAM}: error: {raised.value}"
        assert text.endswith(f"not found; {commands.init()} creates it") and len(text) <= MAX_ERROR_CHARS
        assert text == safe_text(text, max_chars=MAX_ERROR_CHARS)


SHELLS = [shell for shell in ("sh", "bash", "dash") if shutil.which(shell)]


@pytest.mark.parametrize("shell", SHELLS)
def test_an_empty_option_value_reaches_the_program_unchanged_in_every_shell(shell: str, tmp_path: Path) -> None:
    commands = printed_commands(Path("/tmp/a`b"), Path("/tmp/c`d"))
    stand_in = tmp_path / "bin" / PROGRAM
    stand_in.parent.mkdir()
    stand_in.write_text(f'#!/bin/sh\nprintf "[%s]" "$@" > "{tmp_path}/argv"\n')
    stand_in.chmod(0o755)
    work = tmp_path / "work"
    work.mkdir()
    for name in ("the", "this", "init"):
        (work / name).write_text("x\n")
    command = commands.trust_host_keys("d").split("` ")[0].strip("`")
    env = {"PATH": f"{stand_in.parent}:/usr/bin:/bin"}
    subprocess.run([shell, "-c", command], cwd=work, env=env, check=True, capture_output=True)
    assert (tmp_path / "argv").read_text() == "[--config-file=][trust-host-keys][--site][d][--known-hosts=]"
    assert sorted(path.name for path in work.iterdir()) == ["init", "the", "this"]


@pytest.mark.parametrize("option", ["--config-file", "--dump-api", "--profiles-file"])
def test_a_global_path_option_with_an_empty_value_is_refused_before_anything_is_read(
    option: str, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as refused:
        cli.main([f"{option}=", "sites"])
    assert refused.value.code == 2
    assert f"argument {option}: needs a value" in capsys.readouterr().err


@pytest.mark.parametrize("argv", [["run"], ["trust-host-keys", "--site", "d"]])
def test_the_store_option_with_an_empty_value_is_refused_before_anything_is_read(
    argv: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as refused:
        cli.main([*argv, "--known-hosts="])
    assert refused.value.code == 2
    assert "argument --known-hosts: needs a value" in capsys.readouterr().err


def test_a_run_given_a_global_option_builds_its_commands_from_it() -> None:
    args = build_parser().parse_args(["--config-file", CONFIG, "run", "--known-hosts", STORE])
    assert cli._commands(args) == BOTH
    plain = build_parser().parse_args(["sites"])
    assert cli._commands(plain) == PrintedCommands(config_option="", store_option="", withheld=())
