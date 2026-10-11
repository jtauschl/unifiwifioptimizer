"""The known_hosts store on a real file system: creation, permissions, symlinks, conflicts, atomic replace."""

import os
import stat
import threading
from pathlib import Path

import pytest

from unifiwifioptimizer.adapters.ssh.hostkeys import KnownHostEntry, KnownHostsStore
from unifiwifioptimizer.domain.errors import ConfigError, HostKeyTrustError

pytestmark = pytest.mark.integration

ALIAS_A = "uwo-" + "aa" * 16
ALIAS_B = "uwo-" + "bb" * 16
ED25519_BLOB = "AAAAC3NzaC1lZDI1NTE5AAAAIGxVt7Hq4oY0q8u2f9KX8c1n7q9Lk8E6o1m4Hc5fQ2Jz"


def test_first_write_creates_a_private_directory_and_file(tmp_path: Path) -> None:
    store = KnownHostsStore(tmp_path / "state" / "unifiwifioptimizer" / "known_hosts")
    assert store.entries() == () and store.has_alias(ALIAS_A) is False
    store.add(KnownHostEntry(ALIAS_A, "ssh-ed25519", ED25519_BLOB))
    assert stat.S_IMODE(store.path.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(store.path.stat().st_mode) == 0o600
    assert store.path.read_text() == f"{ALIAS_A} ssh-ed25519 {ED25519_BLOB}\n"
    assert store.has_alias(ALIAS_A) and store.entry(ALIAS_A) == KnownHostEntry(ALIAS_A, "ssh-ed25519", ED25519_BLOB)
    assert sorted(p.name for p in store.path.parent.iterdir()) == ["known_hosts", "known_hosts.lock"]


def test_adding_the_same_key_twice_is_idempotent_and_a_different_key_is_a_conflict(tmp_path: Path) -> None:
    store = KnownHostsStore(tmp_path / "known_hosts")
    store.add(KnownHostEntry(ALIAS_A, "ssh-ed25519", ED25519_BLOB))
    store.add(KnownHostEntry(ALIAS_A, "ssh-ed25519", ED25519_BLOB))
    store.add(KnownHostEntry(ALIAS_B, "ssh-rsa", ED25519_BLOB))
    assert [e.alias for e in store.entries()] == [ALIAS_A, ALIAS_B]
    with pytest.raises(HostKeyTrustError, match="different host key is already stored"):
        store.add(KnownHostEntry(ALIAS_A, "ssh-ed25519", ED25519_BLOB[:-4] + "ZZZZ"))
    with pytest.raises(HostKeyTrustError):
        store.add(KnownHostEntry(ALIAS_A, "ssh-rsa", ED25519_BLOB))
    assert len(store.entries()) == 2


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o604])
def test_a_store_readable_by_others_is_refused(tmp_path: Path, mode: int) -> None:
    store = KnownHostsStore(tmp_path / "known_hosts")
    store.add(KnownHostEntry(ALIAS_A, "ssh-ed25519", ED25519_BLOB))
    store.path.chmod(mode)
    with pytest.raises(ConfigError, match="accessible to other users"):
        store.entries()


@pytest.mark.parametrize("mode", [0o722, 0o702, 0o777])
def test_a_directory_writable_by_others_is_refused(tmp_path: Path, mode: int) -> None:
    directory = tmp_path / "dir"
    directory.mkdir(mode=0o700)
    store = KnownHostsStore(directory / "known_hosts")
    store.add(KnownHostEntry(ALIAS_A, "ssh-ed25519", ED25519_BLOB))
    directory.chmod(mode)
    try:
        with pytest.raises(ConfigError, match="directory is accessible to other users"):
            store.entries()
        with pytest.raises(ConfigError):
            store.add(KnownHostEntry(ALIAS_B, "ssh-ed25519", ED25519_BLOB))
    finally:
        directory.chmod(0o700)


def test_symlinked_file_and_directory_are_refused(tmp_path: Path) -> None:
    real_dir = tmp_path / "real"
    real_dir.mkdir(mode=0o700)
    target = real_dir / "elsewhere"
    target.write_text(f"{ALIAS_A} ssh-ed25519 {ED25519_BLOB}\n")
    target.chmod(0o600)
    link = real_dir / "known_hosts"
    link.symlink_to(target)
    with pytest.raises(ConfigError, match="cannot open"):
        KnownHostsStore(link).entries()
    dir_link = tmp_path / "dirlink"
    dir_link.symlink_to(real_dir)
    with pytest.raises(ConfigError, match="cannot open directory"):
        KnownHostsStore(dir_link / "other").entries()


def test_a_file_this_tool_did_not_write_is_refused_not_interpreted(tmp_path: Path) -> None:
    store = KnownHostsStore(tmp_path / "known_hosts")
    store.path.write_text(f"192.168.1.20 ssh-ed25519 {ED25519_BLOB}\n")
    store.path.chmod(0o600)
    with pytest.raises(ConfigError, match=r"line 1.*not an entry this tool wrote"):
        store.entries()
    store.path.write_text(f"# comment\n{ALIAS_A} ssh-ed25519 {ED25519_BLOB}\n")
    with pytest.raises(ConfigError, match=r"line 1.*not an entry this tool wrote"):
        store.entries()
    store.path.write_bytes(b"\xff\xfe")
    with pytest.raises(ConfigError, match="not ASCII"):
        store.entries()
    os.mkfifo(tmp_path / "fifo", 0o600)
    with pytest.raises(ConfigError, match=r"cannot open|not a regular file"):
        KnownHostsStore(tmp_path / "fifo").entries()


def test_removing_the_last_entry_by_hand_leaves_a_usable_empty_store(tmp_path: Path) -> None:
    store = KnownHostsStore(tmp_path / "known_hosts")
    store.add(KnownHostEntry(ALIAS_A, "ssh-ed25519", ED25519_BLOB))
    store.path.write_text("")
    assert store.entries() == () and store.has_alias(ALIAS_A) is False
    store.add(KnownHostEntry(ALIAS_B, "ssh-rsa", ED25519_BLOB))
    assert [e.alias for e in store.entries()] == [ALIAS_B]
    store.path.write_text("\n")
    with pytest.raises(ConfigError, match=r"line 1.*blank line"):
        store.entries()


@pytest.mark.parametrize("round_number", range(20))
def test_concurrent_writers_never_lose_an_entry(tmp_path: Path, round_number: int) -> None:
    # Repeated on purpose: Darwin's openat(O_CREAT) raced against concurrent creators roughly one round in
    # five before the lock was created with O_EXCL.
    store = KnownHostsStore(tmp_path / "known_hosts")
    aliases = ["uwo-" + f"{i:02x}" * 16 for i in range(12)]
    errors: list[BaseException] = []

    def add(alias: str) -> None:
        try:
            store.add(KnownHostEntry(alias, "ssh-ed25519", ED25519_BLOB))
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=add, args=(alias,)) for alias in aliases]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    assert sorted(e.alias for e in store.entries()) == sorted(aliases)
    assert [p.name for p in store.path.parent.iterdir() if p.name.startswith(".known_hosts.")] == []
