"""The scanner over an OpenSSH subprocess: fixed argv, allow-listed environment, pinned host key, bounded I/O.

Every option is passed on the command line (`-F none`), so no user, system or agent configuration can
reach the connection; the host key is looked up under a per-access-point alias in the tool's own store,
and a missing alias ends the call before a single packet (`trust-host-keys` is the only way in). The
password travels through `SSH_ASKPASS` to a helper that reads it from the child's environment — never in
argv, never on this process's command line, never in a `repr`. Output is read in threads with cumulative
byte and line caps; a cap or the call budget kills the whole process group.
"""

import os
import re
import shutil
import signal
import subprocess  # nosec B404 — the only two modules that may spawn processes are this one and hostkeys.py (gate)
import sys
import threading
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass, field
from importlib import resources
from ipaddress import IPv4Address, IPv6Address
from pathlib import Path
from typing import IO, Any, Protocol

from unifiwifioptimizer.adapters.ssh.hostkeys import KnownHostsStore
from unifiwifioptimizer.adapters.ssh.iw_parser import parse_scan_output
from unifiwifioptimizer.domain.errors import (
    AddressRefusedError,
    HostKeyMismatchError,
    HostKeyUnknownError,
    RemoteScriptError,
    ScanOutputTooLargeError,
    ScanTimeoutError,
    ScanTransportError,
    SshAuthenticationError,
    ToolEnvironmentError,
)
from unifiwifioptimizer.domain.scan import ScanPass, ScanTarget, SshAuthMethod

OPENSSH_MIN_VERSION = (8, 4)
CALL_TIMEOUT_S = 120.0
CONNECT_TIMEOUT_S = 5
MAX_STDOUT_BYTES = 4 * 1024 * 1024
MAX_STDERR_BYTES = 64 * 1024
MAX_LINE_BYTES = 4096
# Header plus script must fit the pipe buffer of every supported platform (macOS starts at 16 KiB): the
# write then completes without the peer's cooperation, so the writer thread never outlives the call.
MAX_STDIN_BYTES = 16 * 1024
KILL_GRACE_S = 2.0
# Per `iw scan` on the access point; two bands times attempts times this must leave the call budget room to spare.
REMOTE_SCAN_TIMEOUT_MAX_S = 25
REMOTE_SCAN_TIMEOUT_MIN_S = 5
CALL_BUDGET_MARGIN_S = 10
# The variable the askpass helper reads; set only in the child, only in password mode.
PASSWORD_ENV = "UWO_SSH_PASSWORD"  # noqa: S105 # nosec B105 — the name of a variable, not a credential
ASKPASS_PROGRAM = "unifiwifioptimizer-askpass"
SCRIPT_RESOURCE = "remote_scan.sh"
_HEADER_RE = re.compile(r"[A-Z_]+=[0-9]+")
_VERSION_RE = re.compile(r"OpenSSH_(\d+)\.(\d+)")
_ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b[@-Z\\-_]")
_PRINTABLE_RE = re.compile(r"[^\x20-\x7e]+")
MAX_STDERR_DETAIL_CHARS = 200


class Process(Protocol):
    """What the scanner needs from `subprocess.Popen`; a fake stands in for it in unit tests."""

    pid: int
    stdin: IO[bytes] | None
    stdout: IO[bytes] | None
    stderr: IO[bytes] | None
    returncode: int | None

    def wait(self, timeout: float | None = None) -> int: ...

    def poll(self) -> int | None: ...


ProcessFactory = Callable[[Sequence[str], Mapping[str, str]], Process]


def spawn(argv: Sequence[str], env: Mapping[str, str]) -> Process:
    """`Popen` as the scanner uses it: pipes everywhere, its own session (so `killpg` reaches every child
    OpenSSH spawns), `/` as the working directory so no relative path — `./none` under OpenSSH 8.4 — can
    exist, and nothing inherited from this process's environment."""
    return subprocess.Popen(  # noqa: S603 # nosec B603 — argv is a fixed list built by build_invocation, never a shell
        list(argv),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=dict(env),
        cwd="/",
        start_new_session=True,
        close_fds=True,
    )


def check_openssh_version(run: Callable[[Sequence[str]], str] | None = None) -> tuple[int, int]:
    """`ssh -V` must announce OpenSSH ≥ 8.4 (`SSH_ASKPASS_REQUIRE`); anything else is an environment error."""
    try:
        banner = (run or _ssh_version_banner)(["ssh", "-V"])
    except FileNotFoundError:
        raise ToolEnvironmentError("ssh not found on PATH; OpenSSH 8.4 or newer is required") from None
    match = _VERSION_RE.search(banner)
    if match is None:
        raise ToolEnvironmentError(f"cannot read the OpenSSH version from {banner.strip()!r}")
    version = (int(match.group(1)), int(match.group(2)))
    if version < OPENSSH_MIN_VERSION:
        minimum = ".".join(str(part) for part in OPENSSH_MIN_VERSION)
        raise ToolEnvironmentError(f"OpenSSH {version[0]}.{version[1]} found; {minimum} or newer is required")
    return version


def _ssh_version_banner(argv: Sequence[str]) -> str:
    completed = subprocess.run(  # noqa: S603 # nosec B603 — `ssh -V`, a fixed argv
        list(argv), capture_output=True, text=True, timeout=10, check=False
    )
    return completed.stderr + completed.stdout


def locate_askpass() -> Path:
    """The askpass console script of this very installation: the sibling of the running interpreter first,
    so a helper from another installation on PATH is never picked up, then PATH as the fallback."""
    sibling = Path(sys.executable).with_name(ASKPASS_PROGRAM)
    candidate = sibling if sibling.is_file() else Path(shutil.which(ASKPASS_PROGRAM) or sibling)
    if not candidate.is_file():
        raise ToolEnvironmentError(f"{ASKPASS_PROGRAM} not found; reinstall the package (it ships the helper)")
    return candidate.resolve()


def option_path(path: Path) -> str:
    """A path as an `-o` option value: absolute, double-quoted (unquoted whitespace splits into two files),
    `%` doubled (OpenSSH expands `%` tokens in path options); a `"` cannot be quoted and is refused."""
    text = str(path.resolve()) if not path.is_absolute() else str(path)
    if '"' in text or "\x00" in text:
        raise ToolEnvironmentError('a path handed to ssh must not contain `"` or NUL')
    return '"' + text.replace("%", "%%") + '"'


def is_allowed_address(address: IPv4Address | IPv6Address, allow_public: bool) -> bool:
    """Private, link-local or unique-local addresses only, unless the configuration opts in: the address
    comes from the controller, and a compromised controller must not turn the tool into a scanner of the
    internet. An IPv4-mapped IPv6 address is judged as the IPv4 address it carries (CPython before 3.11.10
    classified the whole mapped range as private)."""
    if isinstance(address, IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    if allow_public:
        return not (address.is_multicast or address.is_unspecified or address.is_reserved or address.is_loopback)
    return address.is_private and not (address.is_loopback or address.is_unspecified or address.is_multicast)


AddressGate = Callable[[IPv4Address | IPv6Address], bool]


def private_address_gate(address: IPv4Address | IPv6Address) -> bool:
    return is_allowed_address(address, allow_public=False)


def public_address_gate(address: IPv4Address | IPv6Address) -> bool:
    return is_allowed_address(address, allow_public=True)


def address_gate_for(target: ScanTarget) -> AddressGate:
    return public_address_gate if target.allow_public_address else private_address_gate


def remote_scan_timeout_s(scan_attempts: int, call_timeout_s: float = CALL_TIMEOUT_S) -> int:
    """Seconds one `iw scan` may take on the access point so that two bands times attempts, the pauses between
    attempts and the toggle sleeps still end before the local call budget kills the client."""
    budget = call_timeout_s - CALL_BUDGET_MARGIN_S
    per_band = budget / 2 - (scan_attempts - 1) - 1
    derived = int(per_band // scan_attempts)
    return max(REMOTE_SCAN_TIMEOUT_MIN_S, min(REMOTE_SCAN_TIMEOUT_MAX_S, derived))


@dataclass(frozen=True, slots=True, kw_only=True)
class SshInvocation:
    argv: tuple[str, ...]
    # Holds the password in password mode: kept out of every repr, traceback-with-locals and log line.
    env: Mapping[str, str] = field(repr=False)
    stdin: bytes = field(repr=False)


def build_invocation(
    target: ScanTarget,
    known_hosts: Path,
    askpass: Path,
    script: bytes,
    environ: Mapping[str, str],
    address_gate: AddressGate | None = None,
    call_timeout_s: float = CALL_TIMEOUT_S,
) -> SshInvocation:
    """argv, child environment and stdin for one scan; pure, so a test can pin every option."""
    gate = address_gate if address_gate is not None else address_gate_for(target)
    if not gate(target.address):
        raise AddressRefusedError(f"{target.ap_name}: address {target.address} is not a private network address")
    credentials = target.credentials
    argv: list[str] = [
        "ssh", "-F", "none", "-T",
        "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", f"UserKnownHostsFile={option_path(known_hosts)}",
        "-o", "StrictHostKeyChecking=yes",
        "-o", f"HostKeyAlias={target.host_key_alias}",
        "-o", "VerifyHostKeyDNS=no",
        "-o", "UpdateHostKeys=no",
        "-o", "CanonicalizeHostname=no",
        "-o", "ControlMaster=no",
        "-o", "ControlPath=none",
        "-o", "ProxyCommand=none",
        "-o", "ForwardAgent=no",
        "-o", "ForwardX11=no",
        "-o", "ClearAllForwardings=yes",
        "-o", f"ConnectTimeout={CONNECT_TIMEOUT_S}",
        "-o", "ConnectionAttempts=1",
        "-o", "LogLevel=ERROR",
        "-o", "NumberOfPasswordPrompts=1",
        "-p", str(target.port),
    ]  # fmt: skip
    env: dict[str, str] = {"PATH": environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C"}
    if "HOME" in environ:
        env["HOME"] = environ["HOME"]
    if credentials.method is SshAuthMethod.PASSWORD:
        if credentials.password is None:
            raise ToolEnvironmentError(f"{target.ap_name}: password mode without a password")
        argv += [
            "-o", "PreferredAuthentications=password,keyboard-interactive",
            "-o", "PubkeyAuthentication=no",
            "-o", "IdentityAgent=none",
        ]  # fmt: skip
        env["SSH_ASKPASS"] = str(askpass)
        env["SSH_ASKPASS_REQUIRE"] = "force"
        env[PASSWORD_ENV] = credentials.password.reveal()
    else:
        argv += ["-o", "BatchMode=yes", "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no"]
        if credentials.method is SshAuthMethod.KEY_FILE:
            if credentials.key_file is None:
                raise ToolEnvironmentError(f"{target.ap_name}: key-file mode without a key file")
            key_file = Path(credentials.key_file)
            if not key_file.is_absolute():
                # ssh runs with `/` as its working directory; a relative key would silently point there.
                raise ToolEnvironmentError(f"{target.ap_name}: key_file must be an absolute path")
            argv += ["-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none", "-i", str(key_file)]
        elif "SSH_AUTH_SOCK" in environ:
            env["SSH_AUTH_SOCK"] = environ["SSH_AUTH_SOCK"]
    argv += ["--", f"{credentials.user}@{target.address}", "sh", "-s"]
    header = (
        f"SCAN_ATTEMPTS={target.scan_attempts}\n"
        f"IFACE_TOGGLE={1 if target.interface_toggle else 0}\n"
        f"SCAN_TIMEOUT_S={remote_scan_timeout_s(target.scan_attempts, call_timeout_s)}\n"
    )
    for line in header.splitlines():
        if not _HEADER_RE.fullmatch(line):
            raise ToolEnvironmentError("scan header must be ASCII assignments of digits")
    stdin = header.encode("ascii") + script
    if len(stdin) > MAX_STDIN_BYTES:
        raise ToolEnvironmentError(f"the scan header and script exceed {MAX_STDIN_BYTES} bytes")
    return SshInvocation(argv=tuple(argv), env=env, stdin=stdin)


def load_script() -> bytes:
    return resources.files("unifiwifioptimizer.adapters.ssh").joinpath(SCRIPT_RESOURCE).read_bytes()


class _BoundedReader(threading.Thread):
    """Drains one pipe into memory until EOF, a byte cap or a line cap; a cap sets `exceeded`."""

    def __init__(
        self, stream: IO[bytes], max_bytes: int, max_line_bytes: int | None, on_exceeded: Callable[[], None]
    ) -> None:
        super().__init__(daemon=True)
        self._stream = stream
        self._max_bytes = max_bytes
        self._max_line_bytes = max_line_bytes
        self._on_exceeded = on_exceeded
        self.chunks: list[bytes] = []
        self.exceeded = False

    def run(self) -> None:
        received = 0
        # Length of the line still open at the end of the previous chunk.
        open_line = 0
        while True:
            try:
                chunk = self._stream.read1(65536) if hasattr(self._stream, "read1") else self._stream.read(65536)
            except (OSError, ValueError):
                return
            if not chunk:
                return
            received += len(chunk)
            over_cap = received > self._max_bytes
            if self._max_line_bytes is not None:
                parts = chunk.split(b"\n")
                parts[0] = b"x" * open_line + parts[0]
                over_cap = over_cap or any(len(part) > self._max_line_bytes for part in parts)
                open_line = len(parts[-1])
            if over_cap:
                self.exceeded = True
                self._on_exceeded()
                return
            self.chunks.append(chunk)

    @property
    def data(self) -> bytes:
        return b"".join(self.chunks)


class _Writer(threading.Thread):
    """Hands the script to the child without holding up the call budget: OpenSSH reads stdin only after
    authentication, so a stalled peer would otherwise stall the write before `wait()` ever started."""

    def __init__(self, stream: IO[bytes], data: bytes) -> None:
        super().__init__(daemon=True)
        self._stream = stream
        self._data = data

    def run(self) -> None:
        try:
            self._stream.write(self._data)
        except (OSError, ValueError):
            return
        finally:
            with suppress(OSError, ValueError):
                self._stream.close()


def _terminate(process: Process) -> None:
    """SIGTERM the group, then SIGKILL; `killpg` only while the child is not yet reaped."""
    if process.poll() is not None:
        return
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            return
        try:
            process.wait(timeout=KILL_GRACE_S)
            return
        except subprocess.TimeoutExpired:
            continue


def sanitize_stderr(data: bytes) -> str:
    """OpenSSH's last line, printable ASCII only, capped — it names hosts and files, never a secret, but a
    compromised access point can write anything to it."""
    text = data.decode("utf-8", errors="replace").strip()
    last = text.rsplit("\n", 1)[-1] if text else ""
    return _PRINTABLE_RE.sub("?", _ANSI_RE.sub("", last))[:MAX_STDERR_DETAIL_CHARS]


def classify_exit(returncode: int, stderr: bytes, target_name: str) -> Exception:
    """OpenSSH's own failures come back as 255; the remote script's as its exit status.

    255 is ambiguous by construction: an authenticated remote that prints "Host key verification failed"
    and exits 255 reads as a mismatch. Nothing on this side can tell the two apart; the stored key is not
    touched either way, so the worst case is a wrong label on a failed pass.
    """
    detail = sanitize_stderr(stderr)
    if returncode == 255:
        if "Host key verification failed" in detail or "REMOTE HOST IDENTIFICATION HAS CHANGED" in detail:
            return HostKeyMismatchError(f"{target_name}: host key does not match the stored one ({detail})")
        if "Permission denied" in detail or "Too many authentication failures" in detail:
            return SshAuthenticationError(f"{target_name}: authentication failed ({detail})")
        return ScanTransportError(f"{target_name}: ssh failed ({detail or 'no message'})")
    return RemoteScriptError(
        f"{target_name}: remote scan script exited with status {returncode} ({detail or 'no message'})"
    )


class OpenSshScanner:
    """`Scanner` over OpenSSH; one process per access point and pass."""

    def __init__(
        self,
        known_hosts: KnownHostsStore,
        address_gate: AddressGate | None = None,
        *,
        process_factory: ProcessFactory = spawn,
        askpass: Path | None = None,
        script: bytes | None = None,
        environ: Mapping[str, str] | None = None,
        call_timeout_s: float = CALL_TIMEOUT_S,
        version_check: Callable[[], Any] = check_openssh_version,
    ) -> None:
        self._known_hosts = known_hosts
        # None: the gate follows each target's `allow_public_address`; a callable overrides it (harness).
        self._address_gate = address_gate
        self._process_factory = process_factory
        self._askpass = askpass
        self._script = script
        self._environ = dict(os.environ if environ is None else environ)
        self._call_timeout_s = call_timeout_s
        self._version_check = version_check
        self._version_checked = False

    def scan(self, target: ScanTarget) -> ScanPass:
        if not self._known_hosts.has_alias(target.host_key_alias):
            raise HostKeyUnknownError(
                f"{target.ap_name}: no stored host key for this access point; run `trust-host-keys` first"
            )
        if not self._version_checked:
            self._version_check()
            self._version_checked = True
        askpass = self._askpass if self._askpass is not None else locate_askpass()
        script = self._script if self._script is not None else load_script()
        invocation = build_invocation(
            target, self._known_hosts.path, askpass, script, self._environ, self._address_gate, self._call_timeout_s
        )
        stdout, stderr, returncode = self._run(invocation, target.ap_name)
        if returncode != 0:
            raise classify_exit(returncode, stderr, target.ap_name)
        return parse_scan_output(stdout)

    def _run(self, invocation: SshInvocation, target_name: str) -> tuple[bytes, bytes, int]:
        try:
            process = self._process_factory(invocation.argv, invocation.env)
        except FileNotFoundError:
            raise ToolEnvironmentError("ssh not found on PATH") from None
        exceeded = threading.Event()

        def on_exceeded() -> None:
            exceeded.set()
            _terminate(process)

        # `spawn` asks for all three pipes; this narrows the `Popen` attribute types.
        assert process.stdout is not None and process.stderr is not None and process.stdin is not None  # noqa: S101 # nosec B101
        # Readers first, then the writer: a chatty remote can never deadlock the write, and the call budget
        # starts counting the moment the child exists, not after the script has been accepted.
        out = _BoundedReader(process.stdout, MAX_STDOUT_BYTES, MAX_LINE_BYTES, on_exceeded)
        err = _BoundedReader(process.stderr, MAX_STDERR_BYTES, None, on_exceeded)
        writer = _Writer(process.stdin, invocation.stdin)
        out.start()
        err.start()
        writer.start()
        try:
            try:
                returncode = process.wait(timeout=self._call_timeout_s)
            except subprocess.TimeoutExpired:
                _terminate(process)
                raise ScanTimeoutError(
                    f"{target_name}: scan did not finish within {self._call_timeout_s:g} s"
                ) from None
        finally:
            out.join(timeout=KILL_GRACE_S)
            err.join(timeout=KILL_GRACE_S)
            for pipe in (process.stdin, process.stdout, process.stderr):
                with suppress(OSError, ValueError):
                    pipe.close()
            writer.join(timeout=KILL_GRACE_S)
        if exceeded.is_set():
            raise ScanOutputTooLargeError(
                f"{target_name}: scan output exceeded {MAX_STDOUT_BYTES} bytes, {MAX_STDERR_BYTES} bytes of "
                f"stderr or {MAX_LINE_BYTES} bytes per line"
            )
        return out.data, err.data, returncode
