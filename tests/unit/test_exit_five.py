"""Exit code 5 says why and what to do, per kind present, in the words of the failure table."""

import json

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


def lines(*outcomes: SiteOutcome, gate_ran: bool = False) -> list[str]:
    return cli.host_key_exit_lines(RunResult(reports=(), outcomes=outcomes, host_key_gate_ran=gate_ran))


def test_unknown_keys_name_the_step_and_the_terminal_alternative_when_the_gate_did_not_run() -> None:
    assert lines(outcome({UNKNOWN: 4})) == [
        "unifiwifioptimizer: exit 5: site default: 4 access points with host key not stored "
        "(`trust-host-keys --site default`, or run again with the report on a terminal)"
    ]


def test_after_the_gate_ran_the_step_does_not_send_the_person_in_a_circle() -> None:
    assert lines(outcome({UNKNOWN: 1}), gate_ran=True) == [
        "unifiwifioptimizer: exit 5: site default: 1 access point with host key not stored "
        "(the host-key lines above say why; then `trust-host-keys --site default`)"
    ]


def test_a_changed_key_says_to_find_out_why_before_the_replace_and_never_names_a_terminal() -> None:
    assert lines(outcome({CHANGED: 1})) == [
        "unifiwifioptimizer: exit 5: site default: 1 access point with changed host key "
        "(find out why the key changed (reset, re-adoption), then `trust-host-keys --site default`)"
    ]


def test_both_kinds_come_in_declaration_order_each_with_its_own_step() -> None:
    (line,) = lines(outcome({CHANGED: 1, UNKNOWN: 2}), gate_ran=True)
    assert line.startswith("unifiwifioptimizer: exit 5: site default: 2 access points with host key not stored (")
    assert ", 1 with changed host key (find out why the key changed" in line
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
