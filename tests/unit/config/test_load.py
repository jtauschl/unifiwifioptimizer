import os
from pathlib import Path

import pytest

from unifiwifioptimizer.config import load as load_module
from unifiwifioptimizer.config.load import (
    API_KEY_ENV,
    SSH_PASSWORD_ENV,
    load_config,
    require_scan_passwords,
    take_env_secret,
)
from unifiwifioptimizer.config.locations import ConfigLocation
from unifiwifioptimizer.domain.errors import MAX_ERROR_CHARS, ConfigError, ConfigNotFoundError
from unifiwifioptimizer.domain.secrets import Secret


@pytest.mark.security("T9")
def test_take_env_secret_reads_once_and_removes_the_variable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("UWO_TEST_SECRET", "value")
    assert take_env_secret("UWO_TEST_SECRET") == "value"
    assert "UWO_TEST_SECRET" not in os.environ and take_env_secret("UWO_TEST_SECRET") is None
    monkeypatch.setenv("UWO_TEST_EMPTY", "")
    assert take_env_secret("UWO_TEST_EMPTY") is None


@pytest.mark.security("T9")
def test_load_config_reads_the_resolved_file_and_consumes_environment_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(API_KEY_ENV, "env-key")
    monkeypatch.setenv(SSH_PASSWORD_ENV, "env-pw")
    monkeypatch.setattr(
        load_module, "resolve_config_location", lambda explicit: ConfigLocation(Path("/cfg/config.yaml"), legacy=True)
    )
    monkeypatch.setattr(load_module, "read_private_file", lambda path: "controller:\n  url: https://unifi.example\n")
    loaded = load_config(Path("/anything"))
    assert loaded.config.controller.api_key == Secret("env-key") and loaded.location.legacy is True
    assert loaded.env_ssh_password == Secret("env-pw") and "env-pw" not in repr(loaded)
    assert API_KEY_ENV not in os.environ and SSH_PASSWORD_ENV not in os.environ


def test_a_missing_configuration_names_the_file_and_the_next_step(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    default = tmp_path / "xdg" / "unifiwifioptimizer" / "config.yaml"
    for create_directory in (False, True):  # the directory is missing, then only the file is
        if create_directory:
            default.parent.mkdir(parents=True, mode=0o700)
        with pytest.raises(ConfigNotFoundError) as exc:
            load_config()
        assert exc.value.path == str(default)
        assert exc.value.detail == "not found; `unifiwifioptimizer init` creates it"
    named = tmp_path / "a dir" / "named.yaml"
    with pytest.raises(ConfigNotFoundError) as named_exc:
        load_config(named)
    assert named_exc.value.path == str(named)
    assert named_exc.value.detail == f"not found; `unifiwifioptimizer --config-file='{named}' init` creates it"


def test_a_long_path_keeps_its_command_while_the_whole_line_fits(tmp_path: Path) -> None:
    named = tmp_path / ("x" * 200) / ("y" * 200) / "n.yaml"
    with pytest.raises(ConfigNotFoundError) as exc:
        load_config(named)
    assert exc.value.detail == f"not found; `unifiwifioptimizer --config-file={named} init` creates it"
    assert len(str(exc.value)) < MAX_ERROR_CHARS


NO_COMMAND = "the init subcommand creates it, with the global --config-file option naming the same file"


@pytest.mark.parametrize(
    ("name", "hint"),
    [
        ("-dash.yaml", "`unifiwifioptimizer --config-file=-dash.yaml init` creates it"),
        ("it's.yaml", """`unifiwifioptimizer --config-file='it'"'"'s.yaml' init` creates it"""),
        ("new\nline.yaml", NO_COMMAND),
        # 380 characters, under the old 400-character cap, but shell quoting makes the printed line longer than allowed
        ("/uwo-absent/" + "'" * 180 + "/" + "'" * 180 + "/c.yaml", NO_COMMAND),
    ],
)
def test_the_creation_hint_names_a_call_that_creates_the_named_file_or_none_when_it_cannot_be_copied(
    tmp_path: Path, name: str, hint: str
) -> None:
    with pytest.raises(ConfigNotFoundError) as exc:
        load_config(Path(name) if name.startswith("/") or "/" not in name else tmp_path / "none" / name)
    assert exc.value.detail == f"not found; {hint}"


PASSWORD_SITE = (
    "controller:\n  url: https://unifi.example\n  api_key: k\n"
    "sites:\n  a:\n    ssh:\n      auth: password\n      user: admin\n"
)


def test_scan_passwords_are_required_before_a_scan_not_at_load_time(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(SSH_PASSWORD_ENV, raising=False)
    monkeypatch.setattr(
        load_module, "resolve_config_location", lambda explicit: ConfigLocation(Path("/cfg/config.yaml"), legacy=False)
    )
    neighbors = "    neighbors:\n      AP-1: [AP-2]\n"
    monkeypatch.setattr(load_module, "read_private_file", lambda path: PASSWORD_SITE + neighbors)
    loaded = load_config()
    assert loaded.env_ssh_password is None
    with pytest.raises(
        ConfigError, match=r"sites\.a\.ssh\.password: missing; set it in the file or in UNIFI_SSH_PASSWORD"
    ):
        require_scan_passwords(loaded, loaded.config.sites.values())
    # Only the sites the run is about to scan are checked: an unselected site needs nothing.
    require_scan_passwords(loaded, [])
    monkeypatch.setenv(SSH_PASSWORD_ENV, "env-pw")
    loaded = load_config()
    assert loaded.env_ssh_password == Secret("env-pw")
    require_scan_passwords(loaded, loaded.config.sites.values())
    monkeypatch.delenv(SSH_PASSWORD_ENV, raising=False)
    in_file = PASSWORD_SITE + "      password: in-file\n" + neighbors
    monkeypatch.setattr(load_module, "read_private_file", lambda path: in_file)
    loaded = load_config()
    assert loaded.env_ssh_password is None
    require_scan_passwords(loaded, loaded.config.sites.values())


def test_a_site_that_does_not_scan_never_needs_an_ssh_password(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(SSH_PASSWORD_ENV, raising=False)
    monkeypatch.setattr(
        load_module, "resolve_config_location", lambda explicit: ConfigLocation(Path("/cfg/config.yaml"), legacy=False)
    )
    monkeypatch.setattr(load_module, "read_private_file", lambda path: PASSWORD_SITE)
    loaded = load_config()
    require_scan_passwords(loaded, loaded.config.sites.values())
    assert loaded.config.sites["a"].ssh is not None and loaded.config.sites["a"].neighbors == {}
    template = PASSWORD_SITE + "    neighbors:\n      AP-1: []\n      AP-2: []\n"
    monkeypatch.setattr(load_module, "read_private_file", lambda path: template)
    loaded = load_config()
    assert loaded.config.sites["a"].scans is False
    require_scan_passwords(loaded, loaded.config.sites.values())
