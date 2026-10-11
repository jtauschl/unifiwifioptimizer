from pathlib import Path

from unifiwifioptimizer.config.locations import default_config_path, legacy_config_path, resolve_config_location


def test_explicit_path_wins_and_expands_the_home_directory() -> None:
    location = resolve_config_location(Path("~/x.yaml"), {})
    assert location.path == Path.home() / "x.yaml" and location.legacy is False


def test_xdg_variables_steer_the_default_and_legacy_paths() -> None:
    env = {"XDG_CONFIG_HOME": "/cfg", "XDG_DATA_HOME": "/data"}
    assert default_config_path(env) == Path("/cfg/unifiwifioptimizer/config.yaml")
    assert legacy_config_path(env) == Path("/data/unifiwifioptimizer/config.yaml")
    assert default_config_path({}) == Path.home() / ".config" / "unifiwifioptimizer" / "config.yaml"
