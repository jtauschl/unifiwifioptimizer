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
from unifiwifioptimizer.domain.errors import ConfigError
from unifiwifioptimizer.domain.secrets import Secret


def test_take_env_secret_reads_once_and_removes_the_variable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("UWO_TEST_SECRET", "value")
    assert take_env_secret("UWO_TEST_SECRET") == "value"
    assert "UWO_TEST_SECRET" not in os.environ and take_env_secret("UWO_TEST_SECRET") is None
    monkeypatch.setenv("UWO_TEST_EMPTY", "")
    assert take_env_secret("UWO_TEST_EMPTY") is None


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
        require_scan_passwords(loaded)
    monkeypatch.setenv(SSH_PASSWORD_ENV, "env-pw")
    loaded = load_config()
    assert loaded.env_ssh_password == Secret("env-pw")
    require_scan_passwords(loaded)
    monkeypatch.delenv(SSH_PASSWORD_ENV, raising=False)
    in_file = PASSWORD_SITE + "      password: in-file\n" + neighbors
    monkeypatch.setattr(load_module, "read_private_file", lambda path: in_file)
    loaded = load_config()
    assert loaded.env_ssh_password is None
    require_scan_passwords(loaded)


def test_a_site_that_does_not_scan_never_needs_an_ssh_password(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(SSH_PASSWORD_ENV, raising=False)
    monkeypatch.setattr(
        load_module, "resolve_config_location", lambda explicit: ConfigLocation(Path("/cfg/config.yaml"), legacy=False)
    )
    monkeypatch.setattr(load_module, "read_private_file", lambda path: PASSWORD_SITE)
    loaded = load_config()
    require_scan_passwords(loaded)
    assert loaded.config.sites["a"].ssh is not None and loaded.config.sites["a"].neighbors == {}
    template = PASSWORD_SITE + "    neighbors:\n      AP-1: []\n      AP-2: []\n"
    monkeypatch.setattr(load_module, "read_private_file", lambda path: template)
    loaded = load_config()
    assert loaded.config.sites["a"].scans is False
    require_scan_passwords(loaded)
