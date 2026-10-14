"""The OpenSSH scanner with a fake process: argv pinned option by option, environment allow-listed, caps
and the call budget enforced through the kill sequence, exit statuses classified."""

import inspect
import io
import os
import signal
import subprocess
import time
from collections.abc import Mapping, Sequence
from ipaddress import IPv6Address, ip_address
from pathlib import Path, PurePath
from typing import IO

import pytest

from unifiwifioptimizer.adapters.ssh import openssh
from unifiwifioptimizer.adapters.ssh.hostkeys import KnownHostEntry, KnownHostsReader, KnownHostsStore
from unifiwifioptimizer.adapters.ssh.openssh import (
    CALL_TIMEOUT_S,
    MAX_LINE_BYTES,
    MAX_STDERR_BYTES,
    MAX_STDOUT_BYTES,
    PASSWORD_ENV,
    OpenSshScanner,
    build_invocation,
    check_openssh_version,
    classify_exit,
    is_allowed_address,
    load_script,
    option_path,
    public_address_gate,
    remote_scan_timeout_s,
    sanitize_stderr,
)
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
    UwoError,
)
from unifiwifioptimizer.domain.scan import BandScanStatus, ScanTarget, SshAuthMethod, SshCredentials
from unifiwifioptimizer.domain.secrets import Secret

STORE = Path("/state/unifiwifioptimizer/known_hosts")
ASKPASS = Path("/opt/bin/unifiwifioptimizer-askpass")
SCRIPT = b"echo hello\n"
ALIAS = "uwo-" + "ab" * 16
OK_OUTPUT = (
    b"===2GHZ===\nSTATUS=ok\nIFACE=apcli0\nBSS 02:00:00:00:00:a1(on apcli0)\n\tsignal: -60 dBm\n"
    b"===5GHZ===\nSTATUS=no_radio\n===META===\nWATCHDOG=timeout\n"
)


def target(method: SshAuthMethod = SshAuthMethod.PASSWORD, **overrides: object) -> ScanTarget:
    credentials = SshCredentials(
        user="admin",
        method=method,
        password=Secret("s3cret") if method is SshAuthMethod.PASSWORD else None,
        key_file="/home/u/.ssh/id_ed25519" if method is SshAuthMethod.KEY_FILE else None,
    )
    values: dict[str, object] = {
        "site_id": "default",
        "ap_mac": "02:00:00:00:00:04",
        "ap_name": "AP-1",
        "address": ip_address("192.168.1.20"),
        "port": 22,
        "host_key_alias": ALIAS,
        "credentials": credentials,
        "scan_attempts": 2,
        "interface_toggle": False,
        "allow_public_address": False,
    }
    values.update(overrides)
    return ScanTarget(**values)  # type: ignore[arg-type]


ENVIRON = {
    "PATH": "/usr/bin:/bin",
    "HOME": "/home/u",
    "SSH_AUTH_SOCK": "/tmp/agent.sock",
    "LANG": "de_DE.UTF-8",
    "UNIFI_API_KEY": "leak",
}


@pytest.mark.security("T8", "T9", "T16")
def test_argv_is_pinned_option_by_option_for_password_mode() -> None:
    invocation = build_invocation(target(), STORE, ASKPASS, SCRIPT, ENVIRON)
    assert invocation.argv == (
        "ssh", "-F", "none", "-T",
        "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", 'UserKnownHostsFile="/state/unifiwifioptimizer/known_hosts"',
        "-o", "StrictHostKeyChecking=yes",
        "-o", f"HostKeyAlias={ALIAS}",
        "-o", "VerifyHostKeyDNS=no",
        "-o", "UpdateHostKeys=no",
        "-o", "CanonicalizeHostname=no",
        "-o", "ControlMaster=no",
        "-o", "ControlPath=none",
        "-o", "ProxyCommand=none",
        "-o", "ForwardAgent=no",
        "-o", "ForwardX11=no",
        "-o", "ClearAllForwardings=yes",
        "-o", "ConnectTimeout=5",
        "-o", "ConnectionAttempts=1",
        "-o", "LogLevel=ERROR",
        "-o", "NumberOfPasswordPrompts=1",
        "-p", "22",
        "-o", "PreferredAuthentications=password,keyboard-interactive",
        "-o", "PubkeyAuthentication=no",
        "-o", "IdentityAgent=none",
        "--", "admin@192.168.1.20", "sh", "-s",
    )  # fmt: skip
    assert invocation.stdin == b"SCAN_ATTEMPTS=2\nIFACE_TOGGLE=0\nSCAN_TIMEOUT_S=25\n" + SCRIPT
    assert "s3cret" not in " ".join(invocation.argv)
    # The environment carries the password; no rendering of the invocation may.
    assert "s3cret" not in repr(invocation) and "s3cret" not in str(invocation)


@pytest.mark.parametrize("attempts", [1, 2, 3, 4, 5])
def test_the_remote_scan_timeout_keeps_every_allowed_attempt_count_inside_the_call_budget(attempts: int) -> None:
    timeout = remote_scan_timeout_s(attempts)
    assert 5 <= timeout <= 25
    # Two bands, each: attempts times timeout plus (attempts - 1) pauses plus the toggle sleep; margin 10 s.
    worst_case = 2 * (attempts * timeout + (attempts - 1) + 1)
    assert worst_case <= CALL_TIMEOUT_S - 10
    assert remote_scan_timeout_s(1, call_timeout_s=12) == 5


@pytest.mark.security("T16")
def test_a_relative_key_file_is_refused_and_an_oversized_script_too() -> None:
    bad = SshCredentials(user="admin", method=SshAuthMethod.KEY_FILE, password=None, key_file="keys/id")
    with pytest.raises(ToolEnvironmentError, match="key_file must be an absolute path"):
        build_invocation(target(credentials=bad), STORE, ASKPASS, SCRIPT, ENVIRON)
    header_len = len(build_invocation(target(), STORE, ASKPASS, b"", ENVIRON).stdin)
    build_invocation(target(), STORE, ASKPASS, b"x" * (16 * 1024 - header_len), ENVIRON)
    with pytest.raises(ToolEnvironmentError, match="exceed 16384 bytes"):
        build_invocation(target(), STORE, ASKPASS, b"x" * (16 * 1024 - header_len + 1), ENVIRON)
    assert header_len + len(load_script()) <= 16 * 1024


@pytest.mark.security("T9", "T16")
def test_environment_is_an_allowlist_with_the_password_only_in_password_mode() -> None:
    password = build_invocation(target(), STORE, ASKPASS, SCRIPT, ENVIRON).env
    assert password == {
        "PATH": "/usr/bin:/bin",
        "LC_ALL": "C",
        "HOME": "/home/u",
        "SSH_ASKPASS": str(ASKPASS),
        "SSH_ASKPASS_REQUIRE": "force",
        "UWO_SSH_PASSWORD": "s3cret",
    }
    key = build_invocation(target(SshAuthMethod.KEY_FILE), STORE, ASKPASS, SCRIPT, ENVIRON)
    assert key.env == {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "HOME": "/home/u"}
    assert key.argv[-10:] == (
        "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none", "-i", "/home/u/.ssh/id_ed25519",
        "--", "admin@192.168.1.20", "sh", "-s",
    )  # fmt: skip
    assert ("-o", "BatchMode=yes") in zip(key.argv, key.argv[1:], strict=False)
    assert ("-o", "PasswordAuthentication=no") in zip(key.argv, key.argv[1:], strict=False)
    agent = build_invocation(target(SshAuthMethod.AGENT), STORE, ASKPASS, SCRIPT, ENVIRON)
    assert agent.env["SSH_AUTH_SOCK"] == "/tmp/agent.sock" and "SSH_ASKPASS" not in agent.env
    assert "-i" not in agent.argv and "IdentitiesOnly=yes" not in agent.argv


@pytest.mark.security("T16")
def test_paths_handed_to_ssh_are_absolute_quoted_and_percent_escaped() -> None:
    assert option_path(Path("/a b/%d/known_hosts")) == '"/a b/%%d/known_hosts"'
    with pytest.raises(ToolEnvironmentError):
        option_path(Path('/a"b'))
    invocation = build_invocation(target(), Path("/with space/%h/kh"), ASKPASS, SCRIPT, ENVIRON)
    assert 'UserKnownHostsFile="/with space/%%h/kh"' in invocation.argv


@pytest.mark.parametrize(
    ("address", "allow_public", "allowed"),
    [
        ("192.168.1.20", False, True),
        ("10.0.0.1", False, True),
        ("172.16.5.5", False, True),
        ("169.254.1.1", False, True),
        ("fd00::1", False, True),
        ("fe80::1", False, True),
        ("8.8.8.8", False, False),
        ("127.0.0.1", False, False),
        ("0.0.0.0", False, False),  # noqa: S104 — the unspecified address is what the gate must refuse
        ("224.0.0.1", False, False),
        ("8.8.8.8", True, True),
        ("127.0.0.1", True, False),
        ("224.0.0.1", True, False),
        ("240.0.0.1", True, False),
        ("::ffff:8.8.8.8", False, False),
        ("::ffff:127.0.0.1", True, False),
        ("::ffff:192.168.1.1", False, True),
    ],
)
@pytest.mark.security("T15")
def test_address_gate(address: str, allow_public: bool, allowed: bool) -> None:
    assert is_allowed_address(ip_address(address), allow_public) is allowed


@pytest.mark.security("T15")
def test_an_ipv4_mapped_address_is_judged_by_its_ipv4_part_even_where_ipaddress_calls_the_range_private(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # CPython before 3.11.10 listed `::ffff:0:0/96` as private and `is_loopback` only knew `::1`; without
    # the unwrap, a controller could hand over `::ffff:8.8.8.8` and pass the gate.
    monkeypatch.setattr(IPv6Address, "is_private", property(lambda self: True))
    monkeypatch.setattr(IPv6Address, "is_loopback", property(lambda self: self == IPv6Address("::1")))
    assert is_allowed_address(ip_address("::ffff:8.8.8.8"), allow_public=False) is False
    assert is_allowed_address(ip_address("::ffff:127.0.0.1"), allow_public=True) is False
    assert is_allowed_address(ip_address("::ffff:192.168.1.1"), allow_public=False) is True


@pytest.mark.security("T15")
def test_a_public_address_is_refused_before_argv_is_built_unless_the_gate_allows_it() -> None:
    with pytest.raises(AddressRefusedError, match="not a private network address"):
        build_invocation(target(address=ip_address("8.8.8.8")), STORE, ASKPASS, SCRIPT, ENVIRON)
    built = build_invocation(
        target(address=ip_address("8.8.8.8")), STORE, ASKPASS, SCRIPT, ENVIRON, public_address_gate
    )
    assert "admin@8.8.8.8" in built.argv


def test_missing_credentials_for_the_method_are_environment_errors() -> None:
    bad = SshCredentials(user="admin", method=SshAuthMethod.PASSWORD, password=None, key_file=None)
    with pytest.raises(ToolEnvironmentError, match="password mode without a password"):
        build_invocation(target(credentials=bad), STORE, ASKPASS, SCRIPT, ENVIRON)
    bad = SshCredentials(user="admin", method=SshAuthMethod.KEY_FILE, password=None, key_file=None)
    with pytest.raises(ToolEnvironmentError, match="key-file mode without a key file"):
        build_invocation(target(credentials=bad), STORE, ASKPASS, SCRIPT, ENVIRON)


@pytest.mark.security("T19")
def test_version_check_requires_openssh_8_4() -> None:
    assert check_openssh_version(ENVIRON, lambda argv, env: "OpenSSH_8.4p1 Debian-5, OpenSSL 1.1.1n\n") == (8, 4)
    assert check_openssh_version(ENVIRON, lambda argv, env: "OpenSSH_10.3p1, LibreSSL 3.3.6") == (10, 3)
    with pytest.raises(ToolEnvironmentError, match=r"OpenSSH 8\.3 found; 8\.4 or newer"):
        check_openssh_version(ENVIRON, lambda argv, env: "OpenSSH_8.3p1")
    with pytest.raises(ToolEnvironmentError, match="cannot read the OpenSSH version"):
        check_openssh_version(ENVIRON, lambda argv, env: "Dropbear v2022.83")

    def missing(argv: Sequence[str], env: Mapping[str, str]) -> str:
        raise FileNotFoundError

    with pytest.raises(ToolEnvironmentError, match="ssh not found"):
        check_openssh_version(ENVIRON, missing)


@pytest.mark.parametrize(
    ("code", "stderr", "error", "fragment"),
    [
        (255, b"Host key verification failed.\n", HostKeyMismatchError, "does not match the stored one"),
        (
            255,
            b"@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @\nHost key verification failed.",
            HostKeyMismatchError,
            "stored one",
        ),
        (
            255,
            b"admin@192.168.1.20: Permission denied (password,keyboard-interactive).\n",
            SshAuthenticationError,
            "authentication failed",
        ),
        (
            255,
            b"Received disconnect: Too many authentication failures",
            SshAuthenticationError,
            "authentication failed",
        ),
        (
            255,
            b"ssh: connect to host 192.168.1.20 port 22: Connection timed out\n",
            ScanTransportError,
            "Connection timed out",
        ),
        (255, b"", ScanTransportError, "no message"),
        (1, b"sh: iw: not found\n", RemoteScriptError, "status 1"),
        (143, b"", RemoteScriptError, "status 143"),
    ],
)
@pytest.mark.security("T7")
def test_exit_statuses_are_classified_from_the_last_stderr_line(
    code: int, stderr: bytes, error: type[Exception], fragment: str
) -> None:
    exc = classify_exit(code, stderr, "AP-1")
    assert isinstance(exc, error) and fragment in str(exc) and str(exc).startswith("AP-1: ")


@pytest.mark.security("T12")
def test_stderr_detail_is_printable_ascii_capped_and_the_last_line_only() -> None:
    assert sanitize_stderr(b"first\nsecond \x1b[31mred\xff\n") == "second red?"
    assert len(sanitize_stderr(b"x" * 1000)) == 200


class _Stdin(io.BytesIO):
    """Keeps what was written after the scanner closes the pipe."""

    def __init__(self) -> None:
        super().__init__()
        self.written = b""

    def close(self) -> None:
        self.written = self.getvalue()
        super().close()


class FakeProcess:
    """A `Popen` stand-in: scripted stdout/stderr, exit status, optional hang."""

    def __init__(self, stdout: bytes, stderr: bytes = b"", returncode: int = 0, hang: bool = False) -> None:
        self.pid = 4242
        self._stdin = _Stdin()
        self.stdin: IO[bytes] | None = self._stdin
        self.stdout: IO[bytes] | None = io.BytesIO(stdout)
        self.stderr: IO[bytes] | None = io.BytesIO(stderr)
        self.returncode: int | None = None
        self._exit = returncode
        self._hang = hang
        self.killed: list[int] = []

    @property
    def written(self) -> bytes:
        return self._stdin.written

    def wait(self, timeout: float | None = None) -> int:
        if self._hang and not self.killed:
            raise subprocess.TimeoutExpired(cmd="ssh", timeout=timeout or 0)
        self.returncode = self._exit if not self.killed else -self.killed[-1]
        return self.returncode

    def poll(self) -> int | None:
        return self.returncode


def make_scanner(
    process: FakeProcess, store: KnownHostsStore, *, timeout: float = 120.0
) -> tuple[OpenSshScanner, list[tuple[str, ...]]]:
    calls: list[tuple[str, ...]] = []

    def factory(argv: Sequence[str], env: Mapping[str, str]) -> FakeProcess:
        calls.append(tuple(argv))
        return process

    scanner = OpenSshScanner(
        store, process_factory=factory, askpass=ASKPASS, script=SCRIPT, environ=ENVIRON,
        call_timeout_s=timeout, version_check=lambda: (8, 4),
    )  # fmt: skip
    return scanner, calls


class FakeStore(KnownHostsStore):
    def __init__(self, aliases: set[str]) -> None:
        super().__init__(STORE)
        self._aliases = aliases

    def entries(self) -> tuple[KnownHostEntry, ...]:
        return tuple(KnownHostEntry(a, "ssh-ed25519", "AAAA") for a in self._aliases)


def test_a_successful_call_writes_the_whole_script_first_and_parses_the_output() -> None:
    process = FakeProcess(OK_OUTPUT)
    scanner, calls = make_scanner(process, FakeStore({ALIAS}))
    result = scanner.scan(target())
    assert len(calls) == 1 and calls[0][0] == "ssh"
    assert process.written == b"SCAN_ATTEMPTS=2\nIFACE_TOGGLE=0\nSCAN_TIMEOUT_S=25\n" + SCRIPT
    assert result.bands[0].status is BandScanStatus.OK and result.bands[0].readings[0].rssi_dbm == -60
    assert result.meta.watchdog == "timeout"


@pytest.mark.security("T6")
def test_an_unknown_alias_ends_the_call_before_any_process_is_started() -> None:
    checks: list[int] = []
    scanner = OpenSshScanner(
        FakeStore(set()), process_factory=lambda a, e: FakeProcess(OK_OUTPUT), askpass=ASKPASS, script=SCRIPT,
        environ=ENVIRON, version_check=lambda: checks.append(1),
    )  # fmt: skip
    with pytest.raises(HostKeyUnknownError, match="run `trust-host-keys` first"):
        scanner.scan(target())
    # Neither the connection process nor the `ssh -V` probe runs for an alias nobody trusted.
    assert checks == []


@pytest.mark.security("T19")
def test_the_version_check_runs_once_and_blocks_old_clients() -> None:
    checks: list[int] = []

    def failing() -> None:
        checks.append(1)
        raise ToolEnvironmentError("OpenSSH 8.3 found")

    scanner = OpenSshScanner(
        FakeStore({ALIAS}), process_factory=lambda a, e: FakeProcess(OK_OUTPUT), version_check=failing
    )
    with pytest.raises(ToolEnvironmentError):
        scanner.scan(target())
    with pytest.raises(ToolEnvironmentError):
        scanner.scan(target())
    assert checks == [1, 1]
    checks.clear()
    scanner = OpenSshScanner(
        FakeStore({ALIAS}), process_factory=lambda a, e: FakeProcess(OK_OUTPUT), askpass=ASKPASS, script=SCRIPT,
        environ=ENVIRON, version_check=lambda: checks.append(1),
    )  # fmt: skip
    scanner.scan(target())
    scanner.scan(target())
    assert checks == [1]


@pytest.mark.security("T18")
def test_the_call_budget_kills_the_process_group_term_then_kill(monkeypatch: pytest.MonkeyPatch) -> None:
    process = FakeProcess(b"", hang=True)
    sent: list[tuple[int, int]] = []

    def killpg(pgid: int, sig: int) -> None:
        sent.append((pgid, sig))
        process.killed.append(sig)

    monkeypatch.setattr(os, "killpg", killpg)
    scanner, _ = make_scanner(process, FakeStore({ALIAS}), timeout=0.01)
    with pytest.raises(ScanTimeoutError, match=r"did not finish within 0\.01 s"):
        scanner.scan(target())
    assert sent == [(4242, signal.SIGTERM)]


def test_a_blocking_stdin_write_does_not_delay_the_call_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "killpg", lambda pgid, sig: None)

    class SlowStdin(io.BytesIO):
        def write(self, data: bytes) -> int:  # type: ignore[override]
            time.sleep(3)
            return len(data)

    process = FakeProcess(b"", hang=True)
    process.stdin = SlowStdin()
    scanner, _ = make_scanner(process, FakeStore({ALIAS}), timeout=0.05)
    started = time.monotonic()
    with pytest.raises(ScanTimeoutError):
        scanner.scan(target())
    assert time.monotonic() - started < 2.5


def test_a_broken_stdin_pipe_is_closed_and_the_exit_still_classified() -> None:
    class BrokenStdin(io.BytesIO):
        def write(self, data: bytes) -> int:  # type: ignore[override]
            raise BrokenPipeError(32, "Broken pipe")

    process = FakeProcess(b"", b"Permission denied (password).\n", returncode=255)
    process.stdin = BrokenStdin()
    scanner, _ = make_scanner(process, FakeStore({ALIAS}))
    with pytest.raises(SshAuthenticationError):
        scanner.scan(target())
    assert process.stdin.closed and process.stdout is not None and process.stdout.closed


@pytest.mark.security("T18")
def test_sigterm_escalates_to_sigkill_when_the_group_ignores_it(monkeypatch: pytest.MonkeyPatch) -> None:
    sent: list[int] = []

    class Stubborn(FakeProcess):
        def wait(self, timeout: float | None = None) -> int:
            if sent == [signal.SIGTERM]:
                raise subprocess.TimeoutExpired(cmd="ssh", timeout=timeout or 0)
            return super().wait(timeout)

    process = Stubborn(b"", hang=True)

    def killpg(pgid: int, sig: int) -> None:
        sent.append(sig)
        process.killed.append(sig)

    monkeypatch.setattr(os, "killpg", killpg)
    scanner, _ = make_scanner(process, FakeStore({ALIAS}), timeout=0.01)
    with pytest.raises(ScanTimeoutError):
        scanner.scan(target())
    assert sent == [signal.SIGTERM, signal.SIGKILL]


@pytest.mark.security("T18")
def test_output_caps_kill_the_process_and_report_the_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    sent: list[int] = []
    monkeypatch.setattr(os, "killpg", lambda pgid, sig: sent.append(sig))
    for stdout, stderr in [
        (b"x" * (MAX_STDOUT_BYTES + 1), b""),
        (b"", b"e" * (MAX_STDERR_BYTES + 1)),
        (b"===2GHZ===\n" + b"y" * (MAX_LINE_BYTES + 1) + b"\n", b""),
    ]:
        sent.clear()
        scanner, _ = make_scanner(FakeProcess(stdout, stderr), FakeStore({ALIAS}))
        with pytest.raises(ScanOutputTooLargeError, match="exceeded"):
            scanner.scan(target())
        # The breach terminates the whole process group, not only the reader.
        assert sent[:1] == [signal.SIGTERM]
    exact = b"===2GHZ===\nSTATUS=ok\n" + b"z" * MAX_LINE_BYTES + b"\n===5GHZ===\nSTATUS=ok\n===META===\n"
    scanner, _ = make_scanner(FakeProcess(exact), FakeStore({ALIAS}))
    assert scanner.scan(target()).bands[0].status is BandScanStatus.EMPTY


def test_a_failed_exit_is_classified_and_never_parsed() -> None:
    scanner, _ = make_scanner(
        FakeProcess(b"garbage", b"Permission denied (password).\n", returncode=255), FakeStore({ALIAS})
    )
    with pytest.raises(SshAuthenticationError):
        scanner.scan(target())


@pytest.mark.security("T9")
def test_the_askpass_helper_prints_the_environment_password_only(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    from unifiwifioptimizer.cli import askpass

    monkeypatch.setenv("UWO_SSH_PASSWORD", "s3cret")
    assert askpass.main() == 0 and capsys.readouterr().out == "s3cret\n"
    monkeypatch.delenv("UWO_SSH_PASSWORD")
    assert askpass.main() == 1
    captured = capsys.readouterr()
    assert captured.out == "" and "UWO_SSH_PASSWORD is not set" in captured.err


@pytest.mark.security("T16")
def test_spawn_uses_its_own_session_pipes_and_the_root_directory(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    class Recorder:
        def __init__(self, argv: list[str], **kwargs: object) -> None:
            seen.update(kwargs, argv=argv)

    monkeypatch.setattr(subprocess, "Popen", Recorder)
    openssh.spawn(("ssh", "-V"), {"PATH": "/bin"})
    assert seen["argv"] == ["ssh", "-V"] and seen["env"] == {"PATH": "/bin"}
    assert seen["cwd"] == "/" and seen["start_new_session"] is True and seen["close_fds"] is True
    assert seen["stdin"] == subprocess.PIPE and seen["stdout"] == subprocess.PIPE and seen["stderr"] == subprocess.PIPE


@pytest.mark.security("T8")
def test_the_scanner_only_reads_the_store_by_type() -> None:
    # The constructor takes the read-only view: no add(), and a pure path without filesystem methods. What a type
    # cannot stop — open() or os.* on the path — the harness full-scan test catches by comparing the store bytes.
    parameter = inspect.signature(OpenSshScanner.__init__).parameters["known_hosts"]
    assert parameter.annotation is KnownHostsReader
    assert not hasattr(KnownHostsReader, "add")
    assert {name for name in dir(KnownHostsReader) if not name.startswith("_")} == {"path", "has_alias"}
    assert inspect.getattr_static(KnownHostsReader, "path").fget.__annotations__["return"] is PurePath
    assert inspect.signature(build_invocation).parameters["known_hosts"].annotation is PurePath


@pytest.mark.security("T9")
def test_the_version_check_spawns_ssh_from_the_base_environment_only(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[dict[str, str]] = []

    def run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        seen.append(dict(kwargs["env"]))  # type: ignore[call-overload]
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="OpenSSH_9.9p1\n")

    monkeypatch.setattr(subprocess, "run", run)
    environ = {**ENVIRON, PASSWORD_ENV: "s3cret", "PATH": "/opt/ssh/bin"}
    assert check_openssh_version(environ) == (9, 9)
    assert seen == [{"PATH": "/opt/ssh/bin", "LC_ALL": "C"}]
    # The scanner's default check uses the scanner's own environment, so `ssh -V` and `ssh` resolve alike.
    scanner = OpenSshScanner(
        FakeStore({ALIAS}), process_factory=lambda a, e: FakeProcess(OK_OUTPUT), askpass=ASKPASS, script=SCRIPT,
        environ=environ,
    )  # fmt: skip
    seen.clear()
    scanner.scan(target())
    assert seen == [{"PATH": "/opt/ssh/bin", "LC_ALL": "C"}]


@pytest.mark.security("T9")
def test_no_scanner_exception_carries_the_password() -> None:
    password = target().credentials.password
    assert password is not None
    secret = password.reveal()
    failures = [
        FakeProcess(b"", b"Permission denied (password).\n", returncode=255),
        FakeProcess(b"", b"Host key verification failed.\n", returncode=255),
        FakeProcess(b"x" * (MAX_STDOUT_BYTES + 1), b""),
    ]
    for process in failures:
        scanner, _ = make_scanner(process, FakeStore({ALIAS}))
        with pytest.raises(UwoError) as caught:
            scanner.scan(target())
        assert secret not in str(caught.value) and secret not in repr(caught.value)
    passwordless = SshCredentials(user="admin", method=SshAuthMethod.PASSWORD, password=None, key_file=None)
    with pytest.raises(ToolEnvironmentError) as caught:
        build_invocation(target(credentials=passwordless), STORE, ASKPASS, SCRIPT, ENVIRON, lambda a: True, 120.0)
    assert secret not in str(caught.value)


@pytest.mark.security("T15")
def test_a_target_that_opts_in_passes_a_public_address_through_the_default_gate() -> None:
    public = target(address=ip_address("8.8.4.4"), allow_public_address=True)
    invocation = build_invocation(public, STORE, ASKPASS, SCRIPT, ENVIRON, None, 120.0)
    assert "admin@8.8.4.4" in invocation.argv
    with pytest.raises(AddressRefusedError, match="not a private network address"):
        build_invocation(target(address=ip_address("8.8.4.4")), STORE, ASKPASS, SCRIPT, ENVIRON, None, 120.0)


@pytest.mark.security("T16")
def test_option_path_refuses_a_nul_and_resolves_a_relative_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(ToolEnvironmentError, match="NUL"):
        option_path(Path("/var/lib/uwo/known\x00hosts"))
    monkeypatch.chdir(tmp_path)
    assert option_path(Path("state") / "known_hosts") == f'"{(tmp_path / "state" / "known_hosts").resolve()}"'
