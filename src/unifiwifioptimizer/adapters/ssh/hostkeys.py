"""The tool's own `known_hosts` and the only way into it: `trust-host-keys`.

Entries are keyed by the per-access-point alias, never by address. The store is read and written through
a descriptor chain like the configuration file (directory and file opened without following symlinks,
owner and mode checked), writes take a lock and replace the file atomically relative to the locked
directory descriptor. Trusting a key means scanning the access point with `ssh-keyscan`, computing the
fingerprints locally, picking the one key that matches what the configuration and the controller expect,
and storing it under the alias.
"""

import fcntl
import os
import re
import secrets
import stat
import subprocess  # nosec B404 — the only two modules that may spawn processes are this one and openssh.py (gate)
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address
from pathlib import Path, PurePath
from typing import Protocol

from unifiwifioptimizer.adapters.ssh.spawn_env import base_child_env
from unifiwifioptimizer.domain.errors import ConfigError, HostKeyTrustError, ToolEnvironmentError
from unifiwifioptimizer.domain.hostkeys import FingerprintAlgorithm, HostKeyFingerprint, key_fingerprints

APP_DIR = "unifiwifioptimizer"
KNOWN_HOSTS_NAME = "known_hosts"
LOCK_NAME = "known_hosts.lock"
MAX_STORE_BYTES = 1_048_576
MAX_KEYSCAN_KEYS = 16
KEYSCAN_TIMEOUT_S = 5
# ssh-keyscan applies `-T` per key type and connection; the whole run gets a bound of its own.
KEYSCAN_TOTAL_TIMEOUT_S = 30
# When nothing can be verified, the stored key is the one OpenSSH negotiates first; one stored key suffices
# because the client prefers the types already known for the alias.
TOFU_KEY_TYPE_PREFERENCE = (
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "ssh-rsa",
)
_ALIAS_RE = re.compile(r"uwo-[0-9a-f]{32}")
_KEY_TYPE_RE = re.compile(r"[a-z0-9][a-z0-9@.+-]{0,63}")
_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{16,4096}={0,2}")


def default_store_path(environ: Mapping[str, str] | None = None) -> Path:
    env = os.environ if environ is None else environ
    base = env.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return Path(base) / APP_DIR / KNOWN_HOSTS_NAME


@dataclass(frozen=True, slots=True)
class KnownHostEntry:
    alias: str
    key_type: str
    key_base64: str

    @property
    def line(self) -> str:
        return f"{self.alias} {self.key_type} {self.key_base64}"


def parse_known_hosts(text: str, path: str) -> tuple[KnownHostEntry, ...]:
    """The store's own format only: `<alias> <key type> <base64>` per line, nothing else — not even a
    comment. Anything else means the file is not ours any more and is refused rather than interpreted. An
    empty file is an empty store: that is what removing the last entry by hand leaves behind."""
    if not text:
        return ()
    entries: list[KnownHostEntry] = []
    for number, line in enumerate(text.split("\n")[:-1] if text.endswith("\n") else text.split("\n"), start=1):
        if not line:
            raise ConfigError(f"{path}, line {number}", "blank line; delete it or the whole file")
        fields = line.split(" ")
        if (
            len(fields) != 3
            or not _ALIAS_RE.fullmatch(fields[0])
            or not _KEY_TYPE_RE.fullmatch(fields[1])
            or not _BASE64_RE.fullmatch(fields[2])
        ):
            raise ConfigError(f"{path}, line {number}", "not an entry this tool wrote (alias, key type, base64)")
        entries.append(KnownHostEntry(fields[0], fields[1], fields[2]))
    return tuple(entries)


def _check_owner(st: os.stat_result, what: str, forbidden_bits: int) -> None:
    if st.st_uid != os.getuid():
        raise ConfigError("known_hosts", f"{what} is not owned by the current user")
    if stat.S_IMODE(st.st_mode) & forbidden_bits:
        raise ConfigError("known_hosts", f"{what} is accessible to other users (fix with chmod)")


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        view = view[written:]


class KnownHostsReader(Protocol):
    """What a scan may know about the store: where it is (ssh reads it by path) and whether an alias is in
    it. Adding a key is not part of this view, and the location is a pure path, so by type the view offers
    neither a way to widen the trust set nor any filesystem operation on the store."""

    @property
    def path(self) -> PurePath: ...

    def has_alias(self, alias: str) -> bool: ...


class KnownHostsStore:
    """`$XDG_STATE_HOME/unifiwifioptimizer/known_hosts`, or any path handed in; created 0600 in a 0700
    directory on the first write."""

    def __init__(self, path: Path) -> None:
        self._path = path

    @property
    def path(self) -> Path:
        return self._path

    def entries(self) -> tuple[KnownHostEntry, ...]:
        if not self._path.parent.exists():
            return ()
        dir_fd = self._open_directory()
        try:
            return self._read(dir_fd)
        finally:
            os.close(dir_fd)

    def has_alias(self, alias: str) -> bool:
        return self.entry(alias) is not None

    def entry(self, alias: str) -> KnownHostEntry | None:
        return next((e for e in self.entries() if e.alias == alias), None)

    def add(self, entry: KnownHostEntry) -> None:
        """Append one entry under a lock; an existing different key under the same alias is a conflict
        the caller has to resolve by hand (the tool never silently rotates a host key)."""
        try:
            self._path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        except OSError as exc:
            raise ConfigError("known_hosts", f"cannot create directory {self._path.parent} ({exc.strerror})") from None
        dir_fd = self._open_directory()
        try:
            lock_fd = self._open_lock(dir_fd)
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX)
                existing = self._read(dir_fd)
                known = next((e for e in existing if e.alias == entry.alias), None)
                if known is not None:
                    if known.key_type == entry.key_type and known.key_base64 == entry.key_base64:
                        return
                    raise HostKeyTrustError(
                        f"a different host key is already stored for alias {entry.alias}; remove it from "
                        f"{self._path} by hand if the access point was really replaced"
                    )
                self._replace(dir_fd, "".join(e.line + "\n" for e in (*existing, entry)))
            finally:
                os.close(lock_fd)
        finally:
            os.close(dir_fd)

    def _open_directory(self) -> int:
        try:
            dir_fd = os.open(self._path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except OSError as exc:
            raise ConfigError("known_hosts", f"cannot open directory {self._path.parent} ({exc.strerror})") from None
        try:
            _check_owner(os.fstat(dir_fd), "the known_hosts directory", 0o022)
        except ConfigError:
            os.close(dir_fd)
            raise
        return dir_fd

    def _open_lock(self, dir_fd: int) -> int:
        # Darwin's openat(O_CREAT) races against a concurrent creator and reports ENOENT; creating with
        # O_EXCL and falling back to a plain open is race-free on every platform.
        try:
            try:
                fd = os.open(LOCK_NAME, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dir_fd)
            except FileExistsError:
                fd = os.open(LOCK_NAME, os.O_RDWR | os.O_NOFOLLOW, dir_fd=dir_fd)
        except OSError as exc:
            raise ConfigError(
                "known_hosts", f"cannot open lock {self._path.parent / LOCK_NAME} ({exc.strerror})"
            ) from None
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise ConfigError("known_hosts", f"{self._path.parent / LOCK_NAME} is not a regular file")
            _check_owner(st, "the known_hosts lock", 0o077)
        except ConfigError:
            os.close(fd)
            raise
        return fd

    def _read(self, dir_fd: int) -> tuple[KnownHostEntry, ...]:
        try:
            fd = os.open(self._path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
        except FileNotFoundError:
            return ()
        except OSError as exc:
            raise ConfigError("known_hosts", f"cannot open {self._path} ({exc.strerror})") from None
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise ConfigError("known_hosts", f"{self._path} is not a regular file")
            _check_owner(st, "the known_hosts file", 0o077)
            if st.st_size > MAX_STORE_BYTES:
                raise ConfigError("known_hosts", f"{self._path} is larger than {MAX_STORE_BYTES} bytes")
            with os.fdopen(fd, "rb") as handle:
                fd = -1
                data = handle.read(MAX_STORE_BYTES + 1)
        finally:
            if fd >= 0:
                os.close(fd)
        try:
            text = data.decode("ascii")
        except UnicodeDecodeError:
            raise ConfigError("known_hosts", f"{self._path} is not ASCII") from None
        return parse_known_hosts(text, str(self._path))

    def _replace(self, dir_fd: int, text: str) -> None:
        # ssh reads the store by path, so the swap has to be atomic for it as well as for us; everything
        # happens relative to the checked directory descriptor so no path component can be swapped meanwhile.
        temp_name = f".{KNOWN_HOSTS_NAME}.{secrets.token_hex(8)}"
        fd = os.open(temp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dir_fd)
        try:
            try:
                _write_all(fd, text.encode("ascii"))
                os.fsync(fd)
            finally:
                os.close(fd)
            os.rename(temp_name, self._path.name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        except BaseException:
            with suppress(OSError):
                os.unlink(temp_name, dir_fd=dir_fd)
            raise
        os.fsync(dir_fd)


# --- trust-host-keys -------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class HostKeyCandidate:
    key_type: str
    key_base64: str
    sha256: HostKeyFingerprint
    md5: HostKeyFingerprint

    def matches(self, expected: HostKeyFingerprint) -> bool:
        mine = self.sha256 if expected.algorithm is FingerprintAlgorithm.SHA256 else self.md5
        return mine.digest == expected.digest

    def entry(self, alias: str) -> KnownHostEntry:
        return KnownHostEntry(alias, self.key_type, self.key_base64)


KeyscanRunner = Callable[[Sequence[str]], str]


def _run_keyscan(argv: Sequence[str]) -> str:
    try:
        completed = subprocess.run(  # noqa: S603 # nosec B603 — fixed argv, the address validated by the schema
            list(argv),
            capture_output=True,
            timeout=KEYSCAN_TOTAL_TIMEOUT_S,
            check=False,
            env=base_child_env(os.environ),
        )
    except FileNotFoundError:
        raise ToolEnvironmentError("ssh-keyscan not found on PATH (part of OpenSSH)") from None
    except subprocess.TimeoutExpired:
        raise HostKeyTrustError(f"ssh-keyscan did not finish within {KEYSCAN_TOTAL_TIMEOUT_S} s") from None
    return completed.stdout.decode("utf-8", errors="replace")


def keyscan(
    address: IPv4Address | IPv6Address, port: int = 22, run: KeyscanRunner = _run_keyscan
) -> tuple[HostKeyCandidate, ...]:
    """Every key `ssh-keyscan` can obtain from the access point, with fingerprints computed locally."""
    output = run(["ssh-keyscan", "-T", str(KEYSCAN_TIMEOUT_S), "-p", str(port), "--", str(address)])
    candidates: list[HostKeyCandidate] = []
    for raw in output.splitlines():
        fields = raw.strip().split()
        if len(fields) != 3 or fields[0].startswith("#"):
            continue
        _host, key_type, key_base64 = fields
        if not _KEY_TYPE_RE.fullmatch(key_type) or not _BASE64_RE.fullmatch(key_base64):
            continue
        try:
            sha256, md5 = key_fingerprints(key_base64)
        except ValueError:
            continue
        candidates.append(HostKeyCandidate(key_type, key_base64, sha256, md5))
        if len(candidates) > MAX_KEYSCAN_KEYS:
            raise HostKeyTrustError(f"{address}: more than {MAX_KEYSCAN_KEYS} host keys offered")
    return tuple(candidates)


class TrustBasis(StrEnum):
    CONFIG_PIN = "configuration pin"
    CONTROLLER = "controller fingerprint"
    UNVERIFIED = "trust on first use (unverified)"


@dataclass(frozen=True, slots=True)
class Expectation:
    """What the chosen key has to satisfy: every fingerprint listed, from the sources named by `basis`."""

    fingerprints: tuple[HostKeyFingerprint, ...]
    basis: TrustBasis

    @property
    def fingerprint(self) -> HostKeyFingerprint | None:
        return self.fingerprints[0] if self.fingerprints else None


def expected_fingerprint(config_pin: bytes | None, controller_fingerprint: HostKeyFingerprint | None) -> Expectation:
    """Configuration pin first, controller fingerprint second; both present and different is an abort,
    because then one of the two sources is wrong and the tool cannot know which. A controller MD5 next to
    a SHA-256 pin cannot be compared here; it stays in the expectation and is checked against the key."""
    if config_pin is not None:
        pin = HostKeyFingerprint(FingerprintAlgorithm.SHA256, config_pin)
        if controller_fingerprint is None:
            return Expectation((pin,), TrustBasis.CONFIG_PIN)
        if controller_fingerprint.algorithm is FingerprintAlgorithm.SHA256:
            if controller_fingerprint.digest != config_pin:
                raise HostKeyTrustError(
                    "the configured host-key pin and the fingerprint the controller reports differ; "
                    "resolve that before trusting the access point"
                )
            return Expectation((pin,), TrustBasis.CONFIG_PIN)
        return Expectation((pin, controller_fingerprint), TrustBasis.CONFIG_PIN)
    if controller_fingerprint is not None:
        return Expectation((controller_fingerprint,), TrustBasis.CONTROLLER)
    return Expectation((), TrustBasis.UNVERIFIED)


def select_candidate(candidates: Sequence[HostKeyCandidate], expectation: Expectation) -> HostKeyCandidate:
    """Exactly the key that satisfies every expected fingerprint; without any, the key OpenSSH would
    negotiate first (`TOFU_KEY_TYPE_PREFERENCE`) — servers offer one key per type, dropbear three."""
    if expectation.fingerprints:
        primary = expectation.fingerprints[0]
        matching = [c for c in candidates if c.matches(primary)]
        if len(matching) != 1:
            raise HostKeyTrustError(
                f"{len(matching)} of {len(candidates)} offered host keys match the {expectation.basis} {primary.text}"
            )
        chosen = matching[0]
        for other in expectation.fingerprints[1:]:
            if not chosen.matches(other):
                raise HostKeyTrustError(
                    f"the key matching the {expectation.basis} does not match the controller's {other.text}; "
                    "resolve that before trusting the access point"
                )
        return chosen
    if not candidates:
        raise HostKeyTrustError("no host key offered")
    by_type = {c.key_type: c for c in candidates}
    if len(by_type) != len(candidates):
        raise HostKeyTrustError("the access point offered several keys of one type; nothing to decide by")
    for key_type in TOFU_KEY_TYPE_PREFERENCE:
        if key_type in by_type:
            return by_type[key_type]
    raise HostKeyTrustError(
        f"no offered key type is one the tool would trust on first use ({', '.join(sorted(by_type))})"
    )
