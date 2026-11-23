"""Exit code 5 says why and what to do, per kind present, in the words of the failure table."""

import json
from pathlib import Path

import pytest

from tests.unit.test_cli_commands import SCANNING_SITE, FixtureApi, configured
from unifiwifioptimizer.app.run import RunResult, SiteOutcome
from unifiwifioptimizer.cli import main as cli
from unifiwifioptimizer.cli.exit_codes import ExitCode
from unifiwifioptimizer.domain.analysis import PartialReason
from unifiwifioptimizer.domain.scan import ScanFailureKind

UNKNOWN, CHANGED = ScanFailureKind.HOST_KEY_UNKNOWN, ScanFailureKind.HOST_KEY_MISMATCH


def outcome(failures: dict[ScanFailureKind, int], *, site: str = "default", verifiable: int = 0) -> SiteOutcome:
    return SiteOutcome(
        site_id=site,
        scanning=True,
        partial_reasons=(PartialReason.SCAN_FAILED,),
        scanned_ap_count=4,
        verifiable_ap_count=verifiable,
        host_key_failures=failures,
    )


def lines(*outcomes: SiteOutcome, gate_ran: bool = False, options: str = "") -> list[str]:
    return cli.host_key_exit_lines(RunResult(reports=(), outcomes=outcomes, host_key_gate_ran=gate_ran), options)


def test_unknown_keys_name_the_step_and_the_terminal_alternative_when_the_gate_did_not_run() -> None:
    assert lines(outcome({UNKNOWN: 4})) == [
        "unifiwifioptimizer: exit 5: site default: 4 access points with host key not stored "
        "(`trust-host-keys --site default`, or run again in a terminal)"
    ]


def test_after_the_gate_ran_the_step_does_not_send_the_person_in_a_circle() -> None:
    assert lines(outcome({UNKNOWN: 1}, site="office"), gate_ran=True) == [
        "unifiwifioptimizer: exit 5: site office: 1 access point with host key not stored "
        "(the host-key lines above say why a key was refused and what to do; a declined key is asked again on the "
        "next run in a terminal, or stored with `trust-host-keys --site office`)"
    ]


def test_a_changed_key_says_to_find_out_why_before_the_replace_when_the_gate_did_not_run() -> None:
    assert lines(outcome({CHANGED: 1})) == [
        "unifiwifioptimizer: exit 5: site default: 1 access point with changed host key "
        "(find out why the key changed (reset, re-adoption), then `trust-host-keys --site default`)"
    ]


def test_after_the_gate_ran_a_changed_key_keeps_the_cause_hint_and_points_to_the_gate_lines() -> None:
    assert lines(outcome({CHANGED: 1}, site="office"), gate_ran=True) == [
        "unifiwifioptimizer: exit 5: site office: 1 access point with changed host key "
        "(find out why the key changed (reset, re-adoption); the host-key lines above say why a key was refused and "
        "what to do; a declined key is asked again on the next run in a terminal, or replaced with "
        "`trust-host-keys --site office`)"
    ]


def test_both_kinds_come_in_declaration_order_each_with_its_own_step_naming_the_site() -> None:
    (line,) = lines(outcome({CHANGED: 1, UNKNOWN: 2}, site="b"), gate_ran=True)
    assert line.startswith("unifiwifioptimizer: exit 5: site b: 2 access points with host key not stored (")
    assert ", 1 with changed host key (find out why the key changed (reset, re-adoption); the host-key lines" in line
    assert line.count("or stored with `trust-host-keys --site b`") == 1
    assert line.count("or replaced with `trust-host-keys --site b`") == 1
    assert "--site default" not in line
    assert line.index("host key not stored") < line.index("changed host key")


def test_only_the_sites_without_a_verifiable_access_point_get_a_line() -> None:
    result = lines(
        outcome({UNKNOWN: 1}, site="a"),
        outcome({UNKNOWN: 1}, site="b", verifiable=2),
        outcome({}, site="c"),
        outcome({CHANGED: 3}, site="d"),
    )
    assert [line.split("site ")[1].split(":")[0] for line in result] == ["a", "d"]


def test_a_run_that_ends_in_exit_5_prints_the_line_on_stderr_and_keeps_stdout_one_document(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    result = RunResult(reports=(), outcomes=(outcome({UNKNOWN: 1}),), host_key_gate_ran=False)
    monkeypatch.setattr(cli, "load_config", lambda explicit=None: configured({"default": SCANNING_SITE}))
    monkeypatch.setattr(cli, "_client", lambda loaded_config, args: (FixtureApi(), None))
    monkeypatch.setattr(cli, "run_analysis", lambda *args, **kwargs: result)
    assert cli.main(["run", "--json"]) == ExitCode.HOST_KEY
    captured = capsys.readouterr()
    assert json.loads(captured.out)["schema_version"] == 1
    assert "exit 5: site default: 1 access point with host key not stored" in captured.err


@pytest.mark.parametrize("gate_ran", [False, True])
def test_every_command_in_the_line_repeats_the_options_of_the_run(gate_ran: bool) -> None:
    (line,) = lines(outcome({CHANGED: 1, UNKNOWN: 1}), gate_ran=gate_ran, options=" --known-hosts=/kh")
    assert line.count("`trust-host-keys --site default --known-hosts=/kh`") == 2
    assert line.count("trust-host-keys") == 2


@pytest.mark.parametrize("flags", [[], ["--details"]], ids=["overview", "details"])
def test_an_exit_6_run_that_checked_the_keys_prints_the_gate_step_in_the_report_not_the_bare_command(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], flags: list[str]
) -> None:
    from dataclasses import replace

    from tests.unit.analysis.builders import golden_input
    from tests.unit.test_failure_advice import failing
    from unifiwifioptimizer.analysis.site_analyzer import analyze_site

    report = analyze_site(failing(golden_input(), CHANGED))
    result = RunResult(
        reports=(report,), outcomes=(replace(outcome({CHANGED: 1}), verifiable_ap_count=3),), host_key_gate_ran=True
    )
    monkeypatch.setattr(cli, "load_config", lambda explicit=None: configured({"default": SCANNING_SITE}))
    monkeypatch.setattr(cli, "_client", lambda loaded_config, args: (FixtureApi(), None))
    monkeypatch.setattr(cli, "run_analysis", lambda *args, **kwargs: result)
    assert cli.main(["run", *flags, "--known-hosts", "/Volumes/Temp HD/UWO/known hosts"]) == ExitCode.PARTIAL
    out = capsys.readouterr().out
    # The raw output: the command stays on one line, so that pasting it names the same file.
    command = "`trust-host-keys --site default --known-hosts='/Volumes/Temp HD/UWO/known hosts'`"
    assert any(command in line for line in out.splitlines())
    assert "the host-key lines above say why a key was refused and what to do" in " ".join(out.split())


@pytest.mark.parametrize("path", ["/tmp/a\x1b[2Jb", "/tmp/a\tb", "/" + "d" * 1100], ids=["escape", "tab", "too-long"])
def test_a_store_path_that_cannot_be_printed_as_typed_is_named_in_words(path: str) -> None:
    import argparse

    options = cli._command_options(argparse.Namespace(known_hosts=Path(path)))
    assert options == " --known-hosts=<the file of this run>"
    assert cli._command_options(argparse.Namespace(known_hosts=None)) == ""


def test_the_exit_5_line_of_a_run_names_the_store_it_was_given(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    result = RunResult(reports=(), outcomes=(outcome({UNKNOWN: 1}),), host_key_gate_ran=False)
    monkeypatch.setattr(cli, "load_config", lambda explicit=None: configured({"default": SCANNING_SITE}))
    monkeypatch.setattr(cli, "_client", lambda loaded_config, args: (FixtureApi(), None))
    monkeypatch.setattr(cli, "run_analysis", lambda *args, **kwargs: result)
    assert cli.main(["run", "--json", "--known-hosts", "/x y/kh"]) == ExitCode.HOST_KEY
    assert "`trust-host-keys --site default --known-hosts='/x y/kh'`" in capsys.readouterr().err


def test_a_store_path_with_an_escape_sequence_cannot_reach_the_terminal_through_the_report(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from dataclasses import replace

    from tests.unit.analysis.builders import golden_input
    from tests.unit.test_failure_advice import failing
    from unifiwifioptimizer.analysis.site_analyzer import analyze_site

    report = analyze_site(failing(golden_input(), CHANGED))
    result = RunResult(
        reports=(report,), outcomes=(replace(outcome({CHANGED: 1}), verifiable_ap_count=3),), host_key_gate_ran=True
    )
    monkeypatch.setattr(cli, "load_config", lambda explicit=None: configured({"default": SCANNING_SITE}))
    monkeypatch.setattr(cli, "_client", lambda loaded_config, args: (FixtureApi(), None))
    monkeypatch.setattr(cli, "run_analysis", lambda *args, **kwargs: result)
    assert cli.main(["run", "--known-hosts", "/tmp/a\x1b[2Jb"]) == ExitCode.PARTIAL
    assert "\x1b" not in capsys.readouterr().out
