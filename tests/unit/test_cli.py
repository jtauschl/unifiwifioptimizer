import runpy
import sys
from collections.abc import Iterator
from unittest import mock

import pytest

from unifiwifioptimizer import __version__
from unifiwifioptimizer.cli.exit_codes import ExitCode
from unifiwifioptimizer.cli.main import HANDLERS, SUBCOMMAND_HELP, main
from unifiwifioptimizer.domain.errors import NotImplementedPathError, UwoError

registered_subcommands = sorted(SUBCOMMAND_HELP)


def test_version_flag_prints_installed_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])
    assert exc_info.value.code == ExitCode.OK
    assert capsys.readouterr().out.strip() == f"unifiwifioptimizer {__version__}"


def test_missing_subcommand_is_a_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main([])
    assert exc_info.value.code == ExitCode.USAGE
    assert "<subcommand>" in capsys.readouterr().err


def test_unknown_subcommand_is_a_usage_error() -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["optimise-everything"])
    assert exc_info.value.code == ExitCode.USAGE


def test_every_planned_subcommand_is_registered() -> None:
    expected = ["config", "controller-fingerprint", "init", "run", "site", "sites", "trust-host-keys"]
    assert registered_subcommands == expected
    assert sorted(HANDLERS) == expected


@pytest.mark.parametrize("subcommand", registered_subcommands)
def test_unimplemented_subcommand_fails_loudly(subcommand: str, capsys: pytest.CaptureFixture[str]) -> None:
    code = main([subcommand])
    captured = capsys.readouterr()
    assert code == ExitCode.UNEXPECTED_ERROR
    assert captured.out == ""
    assert captured.err == f"unifiwifioptimizer: error: subcommand '{subcommand}' is not implemented in this build\n"


def test_not_implemented_error_records_the_path() -> None:
    exc = NotImplementedPathError("subcommand 'run'")
    assert isinstance(exc, UwoError)
    assert exc.path == "subcommand 'run'"


def test_keyboard_interrupt_maps_to_130(capsys: pytest.CaptureFixture[str]) -> None:
    def interrupt(_: object) -> ExitCode:
        raise KeyboardInterrupt

    with mock.patch.dict(HANDLERS, {"run": interrupt}):
        code = main(["run"])
    assert code == ExitCode.INTERRUPTED
    assert capsys.readouterr().err == "unifiwifioptimizer: interrupted\n"


@pytest.fixture
def module_argv() -> Iterator[None]:
    with mock.patch.object(sys, "argv", ["unifiwifioptimizer", "sites"]):
        yield


def test_python_m_entry_point_exits_with_main_result(module_argv: None, capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        runpy.run_module("unifiwifioptimizer", run_name="__main__", alter_sys=True)
    assert exc_info.value.code == ExitCode.UNEXPECTED_ERROR
    assert "subcommand 'sites' is not implemented" in capsys.readouterr().err
