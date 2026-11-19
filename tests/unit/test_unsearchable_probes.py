"""A path whose state cannot be read is reported by the reader that opens it, never raised from a probe.

`Path.exists()` raises `PermissionError` for such a path on Python 3.11 and answers `False` on 3.14, so the probes of
the configuration, the profiles file (one `lstat`), `init` and the known-hosts store ask `Path.stat()` or `lstat()` and
tell a missing path from an unreadable one; the reader that opens the path names the cause, and `init` reports the
failed probe itself. The denial is simulated at `Path.stat` and `Path.lstat`, which also holds when the tests run as
root.
"""

import errno
import shutil
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

from unifiwifioptimizer.adapters.ssh import openssh
from unifiwifioptimizer.adapters.ssh.hostkeys import default_store_path
from unifiwifioptimizer.cli import main as cli
from unifiwifioptimizer.cli.exit_codes import ExitCode
from unifiwifioptimizer.config.loader import expand_user, path_present
from unifiwifioptimizer.config.locations import resolve_config_location
from unifiwifioptimizer.config.profiles import load_profiles
from unifiwifioptimizer.config.schema import Config
from unifiwifioptimizer.domain.errors import ConfigError, ToolEnvironmentError

Deny = Callable[[Path, int], None]


@pytest.fixture
def deny(monkeypatch: pytest.MonkeyPatch) -> Deny:
    real_stat, real_lstat = Path.stat, Path.lstat
    denied: dict[str, int] = {}

    def guarded(real: Callable[..., object]) -> Callable[..., object]:
        def probe(self: Path, *args: object, **kwargs: object) -> object:
            code = denied.get(str(self))
            if code is not None:
                raise OSError(code, "simulated")
            return real(self, *args, **kwargs)

        return probe

    monkeypatch.setattr(Path, "stat", guarded(real_stat))
    monkeypatch.setattr(Path, "lstat", guarded(real_lstat))

    def add(path: Path, code: int) -> None:
        denied[str(path)] = code

    return add


@pytest.mark.parametrize(
    ("code", "present"),
    [
        (errno.EACCES, True),
        (errno.ENAMETOOLONG, True),
        (errno.ELOOP, True),
        (errno.ENOENT, False),
        (errno.ENOTDIR, False),
    ],
)
def test_only_an_absent_path_counts_as_missing(deny: Deny, tmp_path: Path, code: int, present: bool) -> None:
    target = tmp_path / "x"
    deny(target, code)
    assert path_present(target) is present


def test_a_path_that_exists_is_present_and_a_dangling_symlink_is_present_only_without_following(
    tmp_path: Path,
) -> None:
    (tmp_path / "f").write_text("x")
    (tmp_path / "dangling").symlink_to(tmp_path / "nowhere")
    assert path_present(tmp_path / "f") is True and path_present(tmp_path / "dangling") is False
    assert path_present(tmp_path / "dangling", follow=False) is True
    assert (
        path_present(tmp_path / "f" / "below") is False
        and path_present(tmp_path / "f" / "below", follow=False) is False
    )


def test_the_entry_itself_decides_for_the_profiles_file_in_one_probe(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    config = tmp_path / "cfg" / "config.yaml"
    location = resolve_config_location(config)
    config.parent.mkdir()
    (config.parent / "profiles.yaml").symlink_to(tmp_path / "nowhere")

    def is_symlink(self: Path) -> bool:  # a second probe would be a second chance to raise
        raise PermissionError(errno.EACCES, "simulated")

    monkeypatch.setattr(Path, "is_symlink", is_symlink)
    with pytest.raises(ConfigError, match=r"profiles\.yaml: not found"):
        load_profiles(None, location)  # a dangling link is reported by the reader, not skipped and not raised


def test_the_profiles_file_beside_an_unreadable_directory_is_reported_not_skipped(deny: Deny, tmp_path: Path) -> None:
    config = tmp_path / "cfg" / "config.yaml"
    location = resolve_config_location(config)
    assert load_profiles(None, location).override_path is None
    deny(config.parent / "profiles.yaml", errno.EACCES)
    # The probe no longer skips the file; the opener (which sees the real, empty directory) then reports it.
    with pytest.raises(ConfigError, match=r"profiles\.yaml: not found"):
        load_profiles(None, location)


def test_a_missing_helper_directory_is_an_environment_error_not_a_permission_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fake_python = tmp_path / "bin" / "python"
    monkeypatch.setattr(sys, "executable", str(fake_python))
    monkeypatch.setattr(shutil, "which", lambda name: None)

    def is_file(self: Path) -> bool:  # raised on 3.11, answered False on 3.14: simulate the stricter one
        raise PermissionError(errno.EACCES, "simulated")

    monkeypatch.setattr(Path, "is_file", is_file)
    with pytest.raises(ToolEnvironmentError, match="not found; reinstall the package"):
        openssh.locate_askpass()


def test_the_legacy_home_is_looked_up_only_when_the_default_is_absent(
    deny: Deny, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    default = tmp_path / "xdg" / "unifiwifioptimizer" / "config.yaml"
    default.parent.mkdir(parents=True)
    default.write_text("a: 1\n")

    def no_home() -> Path:
        raise RuntimeError("no home")

    monkeypatch.setattr(Path, "home", staticmethod(no_home))
    location = resolve_config_location(None, {"XDG_CONFIG_HOME": str(tmp_path / "xdg")})
    assert location.path == default and location.legacy is False


@pytest.fixture
def no_home(monkeypatch: pytest.MonkeyPatch) -> None:
    def home() -> Path:
        raise RuntimeError("Could not determine home directory.")

    monkeypatch.setattr(Path, "home", staticmethod(home))


def test_without_a_home_directory_an_xdg_variable_still_gives_the_default_and_its_hint(
    no_home: None, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    assert cli.main(["run"]) == ExitCode.CONFIG
    assert capsys.readouterr().err == (
        f"unifiwifioptimizer: error: {tmp_path / 'xdg' / 'unifiwifioptimizer' / 'config.yaml'}: "
        "not found; `unifiwifioptimizer init` creates it\n"
    )


def test_without_a_home_directory_and_without_xdg_the_error_names_the_variables_to_set(
    no_home: None, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    assert cli.main(["run"]) == ExitCode.CONFIG
    assert capsys.readouterr().err == (
        "unifiwifioptimizer: error: home directory: cannot be determined (no HOME and no passwd entry); "
        "set HOME or XDG_CONFIG_HOME\n"
    )
    monkeypatch.delenv("XDG_STATE_HOME", raising=False)
    with pytest.raises(ConfigError, match="set HOME or XDG_STATE_HOME"):
        default_store_path({})
    assert default_store_path({"XDG_STATE_HOME": "/state"}) == Path("/state/unifiwifioptimizer/known_hosts")


def test_an_unknown_user_is_a_configuration_error_in_init_and_in_configured_paths(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    unknown = "~no-such-user-for-uwo/x"
    assert cli.main(["--config-file", unknown, "init"]) == ExitCode.CONFIG
    assert capsys.readouterr().err == (
        f"unifiwifioptimizer: error: {unknown}: cannot expand ~ (no such user or no home directory)\n"
    )
    with pytest.raises(ConfigError) as exc:
        Config.from_mapping(
            {"controller": {"url": "https://unifi.example", "api_key": "k", "ca_cert": unknown}, "sites": {}}
        )
    assert str(exc.value) == "controller.ca_cert: cannot expand ~ (no such user or no home directory)"


def test_an_unknown_user_in_a_path_is_a_configuration_error(capsys: pytest.CaptureFixture[str]) -> None:
    unknown = Path("~no-such-user-for-uwo/config.yaml")
    with pytest.raises(ConfigError) as exc:
        expand_user(unknown)
    assert str(exc.value) == f"{unknown}: cannot expand ~ (no such user or no home directory)"
    assert cli.main(["--config-file", str(unknown), "run"]) == ExitCode.CONFIG
    assert capsys.readouterr().err == (
        f"unifiwifioptimizer: error: {unknown}: cannot expand ~ (no such user or no home directory)\n"
    )
