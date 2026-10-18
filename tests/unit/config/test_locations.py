from pathlib import Path

import pytest

from unifiwifioptimizer.config.locations import default_config_path, legacy_config_path, resolve_config_location


def test_explicit_path_wins_and_expands_the_home_directory() -> None:
    location = resolve_config_location(Path("~/x.yaml"), {})
    assert location.path == Path.home() / "x.yaml" and location.legacy is False


def test_xdg_config_home_steers_the_default_path_and_the_legacy_path_is_fixed_under_home() -> None:
    env = {"XDG_CONFIG_HOME": "/cfg", "XDG_DATA_HOME": "/data"}
    assert default_config_path(env) == Path("/cfg/unifiwifioptimizer/config.yaml")
    assert legacy_config_path(Path("/home/u")) == Path("/home/u/.local/share/unifiwifioptimizer/config.yaml")
    assert default_config_path({}) == Path.home() / ".config" / "unifiwifioptimizer" / "config.yaml"


def test_the_legacy_path_ignores_xdg_data_home_because_the_old_installer_did(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_DATA_HOME", "/data")
    assert legacy_config_path(Path("/home/u")) == Path("/home/u/.local/share/unifiwifioptimizer/config.yaml")
