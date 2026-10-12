"""`--dump-api` on a real file system: modes of files and directories, and the masked models through the CLI."""

import json
import stat
from pathlib import Path

import pytest

from tests.unit.test_cli_commands import SCANNING_SITE, FixtureApi, configured, loaded
from unifiwifioptimizer.adapters.unifi.dump import DumpWriter
from unifiwifioptimizer.cli import main as cli
from unifiwifioptimizer.cli.exit_codes import ExitCode
from unifiwifioptimizer.domain.errors import ConfigError
from unifiwifioptimizer.domain.models import MgmtSettings
from unifiwifioptimizer.domain.secrets import Secret

pytestmark = pytest.mark.integration


def test_an_existing_world_readable_file_is_tightened_to_0600(tmp_path: Path) -> None:
    directory = tmp_path / "dump"
    directory.mkdir(mode=0o700)
    target = directory / "x.json"
    target.write_text("stale")
    target.chmod(0o644)
    written = DumpWriter(directory).write("x", {"a": 1})
    assert written == target and stat.S_IMODE(target.stat().st_mode) == 0o600
    assert json.loads(target.read_text())["models"] == {"a": 1}


@pytest.mark.parametrize("mode", [0o755, 0o750, 0o705, 0o770, 0o707])
def test_a_directory_readable_by_others_is_refused(tmp_path: Path, mode: int) -> None:
    directory = tmp_path / "dump"
    directory.mkdir(mode=mode)
    try:
        with pytest.raises(ConfigError, match=r"--dump-api: the directory must not be accessible to other users"):
            DumpWriter(directory).write("x", {"a": 1})
        assert list(directory.iterdir()) == []
    finally:
        directory.chmod(0o700)


def test_a_symlink_in_place_of_the_dump_file_is_refused(tmp_path: Path) -> None:
    directory = tmp_path / "dump"
    directory.mkdir(mode=0o700)
    elsewhere = tmp_path / "elsewhere.json"
    (directory / "x.json").symlink_to(elsewhere)
    with pytest.raises(ConfigError, match=r"--dump-api: cannot write"):
        DumpWriter(directory).write("x", {"a": 1})
    assert not elsewhere.exists()


def test_a_missing_directory_is_created_private(tmp_path: Path) -> None:
    directory = tmp_path / "new" / "dump"
    DumpWriter(directory).write(
        "x", MgmtSettings(ssh_enabled=True, ssh_password_auth_enabled=True, ssh_user="u", ssh_password=Secret("pw"))
    )
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    text = (directory / "x.json").read_text()
    assert '"ssh_password": "***"' in text and "pw" not in json.loads(text)["models"].values()


def test_the_cli_dump_never_contains_the_controller_managed_ssh_password(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "load_config", lambda explicit=None: loaded())
    monkeypatch.setattr(cli, "UnifiClient", lambda controller, policy, observe_unknown_keys=None: FixtureApi())
    directory = tmp_path / "dump"
    assert cli.main(["--dump-api", str(directory), "config", "default"]) == ExitCode.OK
    written = directory / "s_default_config.json"
    text = written.read_text()
    document = json.loads(text)
    assert document["label"] == "s/default/config" and document["models"]["mgmt"]["ssh_password"] == "***"
    assert document["models"]["mgmt"]["ssh_user"] == "fixture-ssh-user"
    assert "fixture-ssh-password" not in text and "fixture-ssh-password" not in capsys.readouterr().out
    assert stat.S_IMODE(written.stat().st_mode) == 0o600 and [p.name for p in directory.iterdir()] == [
        "s_default_config.json"
    ]


def test_the_cli_run_dump_writes_the_site_report(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(cli, "load_config", lambda explicit=None: configured({"default": SCANNING_SITE}))
    monkeypatch.setattr(cli, "UnifiClient", lambda controller, policy, observe_unknown_keys=None: FixtureApi())
    directory = tmp_path / "dump"
    assert cli.main(["--dump-api", str(directory), "run", "--no-scan"]) == ExitCode.OK
    document = json.loads((directory / "s_default_run.json").read_text())
    assert document["label"] == "s/default/run" and document["models"]["site_id"] == "default"
    assert document["models"]["scan"]["skipped"] is True and "unknown_field_count" in document


def test_a_symlinked_dump_directory_is_refused(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    link = tmp_path / "dump"
    link.symlink_to(real)
    with pytest.raises(ConfigError, match=r"--dump-api: cannot open directory"):
        DumpWriter(link).write("x", {"a": 1})
    assert list(real.iterdir()) == []
