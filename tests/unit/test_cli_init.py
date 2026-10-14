from pathlib import Path

import pytest

from unifiwifioptimizer.cli import init_command
from unifiwifioptimizer.cli import main as cli
from unifiwifioptimizer.cli.exit_codes import ExitCode
from unifiwifioptimizer.cli.init_command import initial_config_text, run_init
from unifiwifioptimizer.config.loader import parse_yaml
from unifiwifioptimizer.config.schema import Config
from unifiwifioptimizer.domain.errors import ConfigError


def test_initial_config_text_is_accepted_by_the_strict_loader_and_schema() -> None:
    text = initial_config_text("https://unifi.example:8443", 'key"with\\quotes', "SHA256:" + "A" * 43)
    config = Config.from_mapping(parse_yaml(text))
    assert config.controller.port == 8443 and config.controller.api_key.reveal() == 'key"with\\quotes'
    assert config.controller.cert_fingerprint is not None and config.sites == {}
    assert "cert_fingerprint" not in initial_config_text("https://u", "k", None)


def test_init_text_plus_config_skeleton_round_trips_through_the_loader() -> None:
    from tests.unit.test_cli_commands import FixtureApi
    from unifiwifioptimizer.app.use_cases import show_site
    from unifiwifioptimizer.config.schema import SshAuth
    from unifiwifioptimizer.report.skeleton import render_skeleton

    text = initial_config_text("https://unifi.example:8443", "k", None)
    text += render_skeleton(show_site(FixtureApi(), "default", with_mgmt=True))
    config = Config.from_mapping(parse_yaml(text))
    site = config.sites["default"]
    assert site.ssh is not None and site.ssh.auth is SshAuth.CONTROLLER and site.scan_passes == 3
    assert set(site.wlans) == {"SSID-1", "SSID-2", "SSID-3", "SSID-4", "SSID-5"} and set(site.wlans.values()) == {
        "Standard"
    }
    assert site.neighbors == {"AP-1": frozenset(), "AP-2": frozenset(), "AP-3": frozenset(), "AP-4": frozenset()}


@pytest.mark.security("T13")
def test_run_init_validates_before_writing(monkeypatch: pytest.MonkeyPatch) -> None:
    written: list[tuple[Path, str]] = []
    monkeypatch.setattr(init_command, "write_new_private_file", lambda path, text: written.append((path, text)))
    answers = iter(["https://unifi.example", ""])
    path = Path("/cfg/unifiwifioptimizer/config.yaml")
    monkeypatch.setattr(Path, "exists", lambda self: False)
    assert run_init(path, prompt=lambda _p: next(answers), secret_prompt=lambda _p: "k") == path
    assert written and written[0][0] == path and 'api_key: "k"' in written[0][1]
    with pytest.raises(ConfigError, match=r"controller\.url"):
        run_init(path, prompt=lambda _p: "ftp://x", secret_prompt=lambda _p: "k")
    assert len(written) == 1


@pytest.mark.security("T13")
def test_run_init_refuses_an_existing_file(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(Path, "exists", lambda self: True)
    with pytest.raises(ConfigError, match="already exists"):
        run_init(Path("/cfg/config.yaml"), prompt=lambda _p: "x", secret_prompt=lambda _p: "y")


def test_init_subcommand_reports_the_written_path(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "run_init", lambda path: path)
    assert cli.main(["--config-file", "/tmp/new.yaml", "init"]) == ExitCode.OK
    assert "wrote /tmp/new.yaml (mode 0600)" in capsys.readouterr().err
