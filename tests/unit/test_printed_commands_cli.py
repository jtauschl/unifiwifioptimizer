"""Every printed command, end to end through `main`: a run given `--config-file` prints it with that option."""

from pathlib import Path

import pytest

from tests.unit.app.test_trust import FixtureApi as TrustApi
from tests.unit.app.test_trust import loaded as trust_loaded
from tests.unit.printed import given
from tests.unit.test_cli_commands import FixtureApi, configured
from unifiwifioptimizer.cli import main as cli
from unifiwifioptimizer.cli.exit_codes import ExitCode

CONFIG = "/etc/uwo/home.yaml"
PROGRAM_WITH_CONFIG = f"unifiwifioptimizer --config-file={CONFIG}"


def patch_config(monkeypatch: pytest.MonkeyPatch, config: object, client: object) -> None:
    monkeypatch.setattr(cli, "load_config", lambda explicit=None, commands=None: config)
    monkeypatch.setattr(cli, "_client", lambda loaded_config, args, commands: (client, None))


def test_a_name_that_is_not_on_the_controller_names_the_site_command_of_the_run(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    patch_config(monkeypatch, trust_loaded({"ssh": {}, "neighbors": {"AP-1": ["Gone"]}}), TrustApi())
    argv = ["--config-file", CONFIG, "trust-host-keys", "--site", "default"]
    assert cli.main([*argv, "--ap", "Gone"]) == ExitCode.OK
    assert f"check the spelling; `{PROGRAM_WITH_CONFIG} site default` lists the names" in capsys.readouterr().out
    assert cli.main(argv) in (ExitCode.OK, ExitCode.HOST_KEY)
    assert f"is not on the controller; `{PROGRAM_WITH_CONFIG} site default` lists the names" in capsys.readouterr().out


def test_a_site_without_an_ssh_section_names_the_config_command_of_the_run(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    patch_config(monkeypatch, trust_loaded({}), TrustApi())
    assert cli.main(["--config-file", CONFIG, "trust-host-keys", "--site", "default"]) == ExitCode.CONFIG
    assert f"; `{PROGRAM_WITH_CONFIG} config default` prints a skeleton" in capsys.readouterr().err


def test_a_run_without_a_configured_site_names_the_config_command_of_the_run(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    patch_config(monkeypatch, configured({}), FixtureApi())
    monkeypatch.setattr(cli, "load_profiles", lambda override, location: type("P", (), {"profiles": None})())
    assert cli.main(["--config-file", CONFIG, "run"]) == ExitCode.CONFIG
    assert f"run `{PROGRAM_WITH_CONFIG} config <site-id>` to get a skeleton" in capsys.readouterr().err


def test_init_names_the_config_command_of_the_file_it_wrote(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "run_init", lambda path: path)
    assert cli.main(["--config-file", CONFIG, "init"]) == ExitCode.OK
    assert (
        f"wrote {CONFIG} (mode 0600); `{PROGRAM_WITH_CONFIG} config <site-id>` prints the skeleton of a site to "
        "append to it"
    ) in capsys.readouterr().err
    monkeypatch.setattr(cli, "default_config_path", lambda: Path("/home/u/config.yaml"))
    assert cli.main(["init"]) == ExitCode.OK
    assert "`unifiwifioptimizer config <site-id>` prints the skeleton" in capsys.readouterr().err


def test_init_shows_the_written_path_only_through_safe_text(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "run_init", lambda path: path)
    assert cli.main(["--config-file", "/tmp/a\x1b[2Jb.yaml", "init"]) == ExitCode.OK
    err = capsys.readouterr().err
    assert (
        "\x1b" not in err and "`unifiwifioptimizer --config-file= config <site-id>` (the value of --config-file" in err
    )


def test_init_cuts_the_written_path_before_the_command_and_names_the_withheld_option(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    long_path = "/uwo/" + "d" * 1900 + ".yaml"
    monkeypatch.setattr(cli, "run_init", lambda path: path)
    assert cli.main(["--config-file", long_path, "init"]) == ExitCode.OK
    (line,) = capsys.readouterr().err.splitlines()
    assert line.startswith("unifiwifioptimizer: wrote /uwo/ddd") and "…" in line and len(line) < 600
    assert line.endswith(
        "`unifiwifioptimizer --config-file= config <site-id>` (the value of --config-file in this run cannot be "
        "printed as typed; fill in the empty option) prints the skeleton of a site to append to it"
    )


HANDLERS = [
    ["run"],
    ["sites"],
    ["site", "default"],
    ["config", "default"],
    ["trust-host-keys", "--site", "default"],
    ["controller-fingerprint"],
]


@pytest.mark.parametrize("handler", HANDLERS, ids=lambda argv: argv[0])
def test_a_missing_configuration_names_the_init_command_of_the_run(
    handler: list[str], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    missing = tmp_path / "none.yaml"
    assert cli.main(["--config-file", str(missing), *handler]) == ExitCode.CONFIG
    assert f"`unifiwifioptimizer --config-file={missing} init` creates it" in capsys.readouterr().err


@pytest.mark.parametrize("handler", HANDLERS[:5], ids=lambda argv: argv[0])
def test_the_controller_client_is_built_with_the_commands_of_the_run(
    handler: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[object] = []

    def fake_client(controller: object, policy: object, commands: object, **kwargs: object) -> FixtureApi:
        seen.append(commands)
        return FixtureApi()

    monkeypatch.setattr(cli, "load_config", lambda explicit=None, commands=None: configured({}))
    monkeypatch.setattr(cli, "UnifiClient", fake_client)
    cli.main(["--config-file", CONFIG, *handler])
    assert seen == [given(config_file=CONFIG)]


def test_a_run_that_asks_about_host_keys_builds_the_gate_with_the_commands_of_the_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[object] = []

    def fake_gate(args: object, environ: object, commands: object) -> None:
        seen.append(commands)

    patch_config(monkeypatch, configured({}), FixtureApi())
    monkeypatch.setattr(cli, "_host_key_gate", fake_gate)
    monkeypatch.setattr(cli, "_can_ask_host_keys", lambda args: True)
    monkeypatch.setattr(cli, "load_profiles", lambda override, location: type("P", (), {"profiles": None})())
    cli.main(["--config-file", CONFIG, "run", "--known-hosts", "/var/lib/uwo/kh"])
    assert seen == [given(config_file=CONFIG, known_hosts="/var/lib/uwo/kh")]
