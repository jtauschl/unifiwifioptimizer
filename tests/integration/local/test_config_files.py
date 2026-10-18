"""File-system behaviour of the configuration loader: permissions, symlinks, special files, creation."""

import os
import stat
from collections.abc import Callable
from pathlib import Path

import pytest

from tests.integration.local.race import swap_outcomes
from unifiwifioptimizer.cli.init_command import initial_config_text, run_init
from unifiwifioptimizer.config.loader import MAX_FILE_BYTES, read_private_file, write_new_private_file
from unifiwifioptimizer.config.locations import resolve_config_location
from unifiwifioptimizer.domain.errors import ConfigError

pytestmark = pytest.mark.integration


@pytest.fixture
def private_dir(tmp_path: Path) -> Path:
    directory = tmp_path / "cfg"
    directory.mkdir(mode=0o700)
    return directory


def write(path: Path, text: str, mode: int = 0o600) -> Path:
    path.write_text(text)
    path.chmod(mode)
    return path


def test_private_file_is_read(private_dir: Path) -> None:
    assert read_private_file(write(private_dir / "config.yaml", "a: 1\n")) == "a: 1\n"


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o660, 0o604, 0o620])
@pytest.mark.security("T13")
def test_group_or_world_access_on_the_file_is_an_error(private_dir: Path, mode: int) -> None:
    path = write(private_dir / "config.yaml", "a: 1\n", mode)
    with pytest.raises(ConfigError, match="accessible to other users"):
        read_private_file(path)


@pytest.mark.parametrize("mode", [0o722, 0o702, 0o720, 0o777])
@pytest.mark.security("T13")
def test_group_or_world_writable_directory_is_an_error(private_dir: Path, mode: int) -> None:
    path = write(private_dir / "config.yaml", "a: 1\n")
    private_dir.chmod(mode)
    try:
        with pytest.raises(ConfigError, match="directory is accessible to other users"):
            read_private_file(path)
    finally:
        private_dir.chmod(0o700)


@pytest.mark.security("T13")
def test_symlinked_file_and_symlinked_directory_are_refused(private_dir: Path, tmp_path: Path) -> None:
    real = write(private_dir / "real.yaml", "a: 1\n")
    link = private_dir / "config.yaml"
    link.symlink_to(real)
    with pytest.raises(ConfigError, match="cannot open"):
        read_private_file(link)
    dir_link = tmp_path / "linkdir"
    dir_link.symlink_to(private_dir)
    with pytest.raises(ConfigError, match="cannot open directory"):
        read_private_file(dir_link / "real.yaml")


@pytest.mark.security("T13")
def test_fifo_and_directory_are_not_regular_files(private_dir: Path) -> None:
    fifo = private_dir / "fifo.yaml"
    os.mkfifo(fifo, 0o600)
    with pytest.raises(ConfigError, match=r"cannot open|not a regular file"):
        read_private_file(fifo)
    sub = private_dir / "sub"
    sub.mkdir(mode=0o700)
    with pytest.raises(ConfigError, match=r"cannot open|not a regular file"):
        read_private_file(sub)


@pytest.mark.security("T13")
def test_missing_file_size_cap_and_encoding(private_dir: Path) -> None:
    with pytest.raises(ConfigError, match="not found"):
        read_private_file(private_dir / "missing.yaml")
    big = write(private_dir / "big.yaml", "x" * (MAX_FILE_BYTES + 1))
    with pytest.raises(ConfigError, match=f"larger than {MAX_FILE_BYTES} bytes"):
        read_private_file(big)
    exact = write(private_dir / "exact.yaml", "x" * MAX_FILE_BYTES)
    assert len(read_private_file(exact)) == MAX_FILE_BYTES
    binary = private_dir / "binary.yaml"
    binary.write_bytes(b"\xff\xfe")
    binary.chmod(0o600)
    with pytest.raises(ConfigError, match="not UTF-8"):
        read_private_file(binary)


@pytest.mark.security("T13")
def test_write_new_private_file_creates_0600_in_a_0700_directory_and_never_overwrites(tmp_path: Path) -> None:
    path = tmp_path / "new" / "deeper" / "config.yaml"
    write_new_private_file(path, "a: 1\n")
    assert path.read_text() == "a: 1\n"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    with pytest.raises(ConfigError, match="already exists"):
        write_new_private_file(path, "b: 2\n")
    assert path.read_text() == "a: 1\n"
    assert read_private_file(path) == "a: 1\n"


@pytest.mark.security("T13")
def test_write_new_private_file_refuses_a_symlink_target(tmp_path: Path) -> None:
    target = tmp_path / "elsewhere.yaml"
    link = tmp_path / "config.yaml"
    link.symlink_to(target)
    with pytest.raises(ConfigError, match=r"already exists|cannot create"):
        write_new_private_file(link, "a: 1\n")
    assert not target.exists()


@pytest.mark.security("T13")
def test_init_prompts_validates_and_writes(tmp_path: Path) -> None:
    answers = iter(["https://unifi.example:8443", "SHA256:" + "A" * 43])
    secrets = iter(["my-api-key"])
    path = tmp_path / "xdg" / "unifiwifioptimizer" / "config.yaml"
    assert run_init(path, prompt=lambda _p: next(answers), secret_prompt=lambda _p: next(secrets)) == path
    text = path.read_text()
    assert 'url: "https://unifi.example:8443"' in text and 'api_key: "my-api-key"' in text
    assert 'cert_fingerprint: "SHA256:' in text and stat.S_IMODE(path.stat().st_mode) == 0o600
    with pytest.raises(ConfigError, match="already exists"):
        run_init(path, prompt=lambda _p: "x", secret_prompt=lambda _p: "y")


@pytest.mark.security("T13")
def test_init_rejects_an_invalid_answer_before_writing(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    answers = iter(["http://plain.example", ""])
    with pytest.raises(ConfigError, match=r"controller\.url"):
        run_init(path, prompt=lambda _p: next(answers), secret_prompt=lambda _p: "key")
    assert not path.exists()


def test_initial_config_text_quotes_awkward_values() -> None:
    text = initial_config_text('https://u"x', "k\\y", None)
    assert 'url: "https://u\\"x"' in text and 'api_key: "k\\\\y"' in text and "cert_fingerprint" not in text


def test_default_is_chosen_unless_only_the_legacy_file_exists(tmp_path: Path) -> None:
    env = {"XDG_CONFIG_HOME": str(tmp_path / "cfg"), "XDG_DATA_HOME": str(tmp_path / "xdg-data")}
    home = tmp_path / "home"
    neither = resolve_config_location(None, env, home)
    assert neither.path == tmp_path / "cfg" / "unifiwifioptimizer" / "config.yaml" and neither.legacy is False
    # The 0.4.x installer ignored XDG_DATA_HOME, so a file there is not the legacy file.
    decoy = tmp_path / "xdg-data" / "unifiwifioptimizer" / "config.yaml"
    decoy.parent.mkdir(parents=True)
    decoy.write_text("x")
    assert resolve_config_location(None, env, home) == neither
    legacy = home / ".local" / "share" / "unifiwifioptimizer" / "config.yaml"
    legacy.parent.mkdir(parents=True)
    legacy.write_text("x")
    assert resolve_config_location(None, env, home).path == legacy
    assert resolve_config_location(None, env, home).legacy is True
    default = tmp_path / "cfg" / "unifiwifioptimizer" / "config.yaml"
    default.parent.mkdir(parents=True)
    default.write_text("x")
    assert resolve_config_location(None, env, home).path == default


@pytest.mark.parametrize("mode", [0o610, 0o601])
@pytest.mark.security("T13")
def test_execute_bits_for_others_are_an_error_too(private_dir: Path, mode: int) -> None:
    path = write(private_dir / "config.yaml", "a: 1\n", mode)
    with pytest.raises(ConfigError, match="accessible to other users"):
        read_private_file(path)


@pytest.mark.security("T13")
def test_a_file_or_directory_owned_by_someone_else_is_refused(
    private_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = write(private_dir / "config.yaml", "a: 1\n")
    # The loader compares the descriptor's owner with the process owner; pretend to be another user.
    someone_else = os.getuid() + 1
    monkeypatch.setattr(os, "getuid", lambda: someone_else)
    with pytest.raises(ConfigError, match="not owned by the current user"):
        read_private_file(path)


ORIGINAL = "original: true\n"
ATTACKER = "attacker: true\n"


def _swap_file(private_dir: Path, tmp_path: Path) -> Callable[[], None]:
    attacker = tmp_path / "attacker.yaml"
    attacker.write_text(ATTACKER)
    attacker.chmod(0o644)

    def swap() -> None:
        attacker.replace(private_dir / "config.yaml")

    return swap


def _swap_directory(private_dir: Path, tmp_path: Path) -> Callable[[], None]:
    attacker_dir = tmp_path / "attacker"
    attacker_dir.mkdir(mode=0o700)
    (attacker_dir / "config.yaml").write_text(ATTACKER)
    (attacker_dir / "config.yaml").chmod(0o600)
    parked = tmp_path / "parked"

    def swap() -> None:
        private_dir.rename(parked)
        private_dir.symlink_to(attacker_dir)

    return swap


@pytest.mark.parametrize("case", ["file", "directory"])
@pytest.mark.security("T13")
def test_a_swap_between_check_and_read_never_yields_the_attackers_bytes(
    case: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fresh() -> tuple[Path, Callable[[], None]]:
        base = tmp_path / f"run-{os.urandom(4).hex()}"
        base.mkdir(mode=0o700)
        private_dir = base / "cfg"
        private_dir.mkdir(mode=0o700)
        write(private_dir / "config.yaml", ORIGINAL)
        swap = _swap_file(private_dir, base) if case == "file" else _swap_directory(private_dir, base)
        return private_dir / "config.yaml", swap

    for k, outcome in enumerate(swap_outcomes(monkeypatch, fresh, read_private_file, ORIGINAL), start=1):
        assert outcome != ATTACKER, f"swap after call {k} ({case}) handed over the attacker's bytes"
