"""The read-only subcommands through `main`, with the configuration and the controller faked."""

import argparse
import json
from collections.abc import Iterator
from pathlib import Path
from unittest import mock

import pytest

from unifiwifioptimizer.adapters.unifi import parse
from unifiwifioptimizer.cli import main as cli
from unifiwifioptimizer.cli.exit_codes import ExitCode
from unifiwifioptimizer.config.load import LoadedConfig
from unifiwifioptimizer.config.locations import ConfigLocation
from unifiwifioptimizer.config.schema import Config
from unifiwifioptimizer.domain.errors import (
    ConfigError,
    ControllerError,
    SchemaError,
    TlsError,
    TlsPinMismatchError,
    ToolEnvironmentError,
    UwoError,
)
from unifiwifioptimizer.domain.models import (
    ApGroup,
    ClientSighting,
    DevicesResult,
    ParsedList,
    SettingsResult,
    Site,
    WlanConfig,
)

FIXTURES = Path(__file__).parents[1] / "fixtures"


def load(name: str) -> object:
    return json.loads((FIXTURES / name).read_text())


class FixtureApi:
    def sites(self) -> ParsedList[Site]:
        return parse.parse_sites(load("sites.json"))

    def devices(self, site_id: str) -> DevicesResult:
        return parse.parse_devices(load("stat_device.json"))

    def wlans(self, site_id: str) -> ParsedList[WlanConfig]:
        return parse.parse_wlans(load("list_wlanconf.json"))

    def ap_groups(self, site_id: str) -> ParsedList[ApGroup]:
        return parse.parse_ap_groups(load("apgroups.json"))

    def settings(self, site_id: str) -> SettingsResult:
        return parse.parse_settings(load("rest_setting.json"))

    def clients(self, site_id: str) -> ParsedList[ClientSighting]:
        return parse.parse_clients(load("stat_sta.json"))


def loaded(legacy: bool = False) -> LoadedConfig:
    config = Config.from_mapping({"controller": {"url": "https://unifi.example", "api_key": "k"}})
    return LoadedConfig(
        config=config, location=ConfigLocation(Path("/cfg/config.yaml"), legacy=legacy), env_ssh_password=None
    )


@pytest.fixture
def faked(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[Path | None]]:
    config_files: list[Path | None] = []

    def fake_load(explicit: Path | None = None) -> LoadedConfig:
        config_files.append(explicit)
        return loaded()

    monkeypatch.setattr(cli, "load_config", fake_load)
    monkeypatch.setattr(cli, "_client", lambda loaded_config, args: (FixtureApi(), None))
    yield config_files


def test_sites_prints_the_table(faked: list[Path | None], capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["--config-file", "/tmp/x.yaml", "sites"]) == ExitCode.OK
    out = capsys.readouterr().out
    assert "Site ID" in out and "default" in out and "site-2" in out and " 4" in out
    assert faked == [Path("/tmp/x.yaml")]


def test_site_prints_wlans_and_access_points(faked: list[Path | None], capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["site", "default"]) == ExitCode.OK
    out = capsys.readouterr().out
    assert "Site Name: Site-1" in out and "SSID-1 (enabled)" in out and "AP-2 (UAPA693" in out


def test_config_prints_a_skeleton_that_the_loader_accepts(
    faked: list[Path | None], capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(["config", "Site-1"]) == ExitCode.OK
    out = capsys.readouterr().out
    assert out.startswith('  "default":\n    ssh:\n') and '"SSID-1": Standard' in out and '"AP-1": []' in out


def test_unknown_site_is_a_configuration_error(faked: list[Path | None], capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["site", "nowhere"]) == ExitCode.CONFIG
    assert "no site 'nowhere'" in capsys.readouterr().err


def test_legacy_location_is_announced_on_stderr(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "load_config", lambda explicit=None: loaded(legacy=True))
    monkeypatch.setattr(cli, "_client", lambda loaded_config, args: (FixtureApi(), None))
    assert cli.main(["sites"]) == ExitCode.OK
    assert "legacy configuration at /cfg/config.yaml" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("error", "code"),
    [
        (ConfigError("controller.url", "bad"), ExitCode.CONFIG),
        (TlsError("handshake"), ExitCode.TLS),
        (TlsPinMismatchError(bytes(32), bytes(32)), ExitCode.TLS),
        (ToolEnvironmentError("no docker"), ExitCode.ENVIRONMENT),
        (ControllerError("/x", "status 500"), ExitCode.UNEXPECTED_ERROR),
        (SchemaError("$.data", "expected a list"), ExitCode.UNEXPECTED_ERROR),
        (UwoError("other"), ExitCode.UNEXPECTED_ERROR),
    ],
)
def test_exit_codes_follow_the_error_class(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], error: UwoError, code: ExitCode
) -> None:
    def failing(explicit: Path | None = None) -> LoadedConfig:
        raise error

    monkeypatch.setattr(cli, "load_config", failing)
    assert cli.main(["sites"]) == code
    assert capsys.readouterr().err.startswith("unifiwifioptimizer: error: ")


def test_dump_api_writes_one_file_per_endpoint(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    directory = Path("/dump")
    monkeypatch.setattr(cli, "load_config", lambda explicit=None: loaded())
    captured: dict[str, object] = {}

    class RecordingDump:
        def __init__(self, directory: Path) -> None:
            captured["directory"] = directory

        def observe_unknown_keys(self, endpoint: str, path: str, count: int) -> None:
            pass

        def write(self, endpoint: str, result: object) -> Path:
            captured["endpoint"] = endpoint
            captured["result"] = result
            return Path("/dev/null")

    monkeypatch.setattr(cli, "DumpWriter", RecordingDump)
    monkeypatch.setattr(cli, "UnifiClient", lambda controller, policy, observe_unknown_keys=None: FixtureApi())
    endpoints: list[object] = []
    assert cli.main(["--dump-api", str(directory), "site", "default"]) == ExitCode.OK
    endpoints.append(captured["endpoint"])
    assert cli.main(["--dump-api", str(directory), "sites"]) == ExitCode.OK
    endpoints.append(captured["endpoint"])
    assert cli.main(["--dump-api", str(directory), "config", "default"]) == ExitCode.OK
    endpoints.append(captured["endpoint"])
    assert captured["directory"] == directory and endpoints == ["s/default", "self/sites", "s/default/config"]


def test_controller_fingerprint_with_url_prints_the_observed_digest(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "observe_fingerprint", lambda host, port: bytes(range(32)))
    assert cli.main(["controller-fingerprint", "--url", "https://unifi.example:8443"]) == ExitCode.OK
    captured = capsys.readouterr()
    assert captured.out == "SHA256:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8\n"
    assert "unifi.example:8443 presented right now (trust on first use)" in captured.err


@pytest.mark.parametrize(
    ("url", "message"),
    [
        ("http://unifi.example", "--url: expected https://"),
        ("https://user:pw@unifi.example", "--url: expected https://<host>[:port] without credentials"),
        ("https://unifi.example:99999", "--url: invalid port"),
        ("https://unifi.example:0", "--url: invalid port"),
        ("https://unifi.example/network", "--url: the URL must not carry a path, query or fragment"),
        ("https://unifi.example#x", "--url: the URL must not carry a path, query or fragment"),
        ("https://[", "--url: expected https://<host>[:port] without credentials"),
        ("https://[TOPSECRET", "--url: expected https://<host>[:port] without credentials"),
    ],
)
def test_controller_fingerprint_rejects_malformed_urls_without_connecting(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], url: str, message: str
) -> None:
    def never(host: str, port: int) -> bytes:
        raise AssertionError("must not connect")

    monkeypatch.setattr(cli, "observe_fingerprint", never)
    assert cli.main(["controller-fingerprint", "--url", url]) == ExitCode.CONFIG
    err = capsys.readouterr().err
    assert message in err and "TOPSECRET" not in err


def test_error_output_never_carries_terminal_escapes_from_a_pasted_skeleton(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from unifiwifioptimizer.config import load as load_module

    monkeypatch.setattr(
        load_module, "resolve_config_location", lambda explicit: ConfigLocation(Path("/cfg/config.yaml"), legacy=False)
    )
    # What `config` writes for a controller name with an OSC 52 (clipboard) sequence, plus a typo under it.
    text = (
        "controller:\n  url: https://unifi.example\n  api_key: k\nsites:\n  default:\n    ssh: {}\n"
        '    neighbors:\n      "AP\\x1b]52;c;ZGFuZ2Vy\\x07": "oops"\n'
    )
    monkeypatch.setattr(load_module, "read_private_file", lambda path: text)
    assert cli.main(["sites"]) == ExitCode.CONFIG
    err = capsys.readouterr().err
    assert "\x1b" not in err and "\x07" not in err and "expected a list of AP names" in err


def test_the_error_printer_itself_strips_escapes_that_arrive_through_a_path(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # The configuration file name is user input and ends up in "invalid YAML" errors verbatim.
    from unifiwifioptimizer.config import load as load_module

    monkeypatch.setattr(load_module, "read_private_file", lambda path: "a: [\n")
    assert cli.main(["--config-file", "/cfg/\x1b[2J\x1b]52;c;ZGFuZ2Vy\x07.yaml", "sites"]) == ExitCode.CONFIG
    err = capsys.readouterr().err
    assert "\x1b" not in err and "\x07" not in err and "invalid YAML" in err and "/cfg/" in err


def test_an_api_key_with_a_control_character_is_refused_through_the_real_loader(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from unifiwifioptimizer.config import load as load_module

    monkeypatch.setattr(
        load_module, "resolve_config_location", lambda explicit: ConfigLocation(Path("/cfg/config.yaml"), legacy=False)
    )
    monkeypatch.setattr(
        load_module,
        "read_private_file",
        lambda path: 'controller:\n  url: https://unifi.example\n  api_key: "TOPSECRET\\rX-Injected: 1"\n',
    )
    assert cli.main(["sites"]) == ExitCode.CONFIG
    err = capsys.readouterr().err
    assert "controller.api_key: must be 1..512 printable ASCII characters without spaces" in err
    assert "TOPSECRET" not in err


def test_controller_fingerprint_falls_back_to_the_configuration(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "load_config", lambda explicit=None: loaded())
    seen: list[tuple[str, int]] = []

    def observe(host: str, port: int) -> bytes:
        seen.append((host, port))
        return bytes(32)

    monkeypatch.setattr(cli, "observe_fingerprint", observe)
    assert cli.main(["controller-fingerprint"]) == ExitCode.OK
    assert seen == [("unifi.example", 443)]


def test_site_subcommands_require_a_site_argument() -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["site"])
    assert exc.value.code == ExitCode.USAGE


def test_client_factory_wires_the_tls_policy_and_the_dump_observer() -> None:
    args = argparse.Namespace(dump_api=None)
    client, dump = cli._client(loaded(), args)
    assert dump is None and client._policy.pin is None and client._policy.ca_file is None
    with mock.patch.object(cli, "DumpWriter") as writer:
        client, dump = cli._client(loaded(), argparse.Namespace(dump_api=Path("/dump")))
    assert dump is not None
    assert dump is writer.return_value
    assert client._observe_unknown_keys == writer.return_value.observe_unknown_keys
