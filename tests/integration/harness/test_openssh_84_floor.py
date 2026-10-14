"""The tool's exact argv on the oldest supported client (OpenSSH 8.4p1 inside the `ssh84` container),
against the harness access point: `-F none` next to a file named `none`, a quoted path with a space and a
percent sign, SSH_ASKPASS_REQUIRE=force, and a wrong password."""

import shlex
import subprocess
from collections.abc import Sequence
from ipaddress import IPv4Address
from pathlib import Path

import pytest

from tests.integration.harness.conftest import SCAN_PASSWORD, SCAN_USER, Harness, compose
from unifiwifioptimizer.adapters.ssh.iw_parser import parse_scan_output
from unifiwifioptimizer.adapters.ssh.openssh import build_invocation, load_script
from unifiwifioptimizer.domain.hostkeys import host_key_alias
from unifiwifioptimizer.domain.models import Band
from unifiwifioptimizer.domain.scan import BandScanStatus, ScanTarget, SshAuthMethod, SshCredentials
from unifiwifioptimizer.domain.secrets import Secret

pytestmark = pytest.mark.integration
ORIGIN = "https://unifi.example:443"
MAC = "02:00:00:00:00:84"
ALIAS = host_key_alias(ORIGIN, "default", MAC)
KNOWN_HOSTS = Path("/home/tester/kh dir %h/known_hosts")
ASKPASS_IN_CONTAINER = Path("/usr/local/bin/askpass")


def ssh84(
    *argv: str, stdin: bytes | None = None, env: dict[str, str] | None = None, workdir: str = "/home/tester"
) -> subprocess.CompletedProcess[bytes]:
    env_args: list[str] = []
    for key, value in (env or {}).items():
        env_args += ["-e", f"{key}={value}"]
    return compose("exec", "-T", "-w", workdir, *env_args, "ssh84", *argv, stdin=stdin, check=False)


@pytest.fixture(scope="module")
def ap_address(harness: Harness) -> IPv4Address:
    output = ssh84("getent", "hosts", "ap").stdout.decode().split()
    return IPv4Address(output[0])


@pytest.fixture(scope="module")
def known_hosts(harness: Harness, ap_address: IPv4Address) -> Path:
    """The store inside the ssh84 container: the dropbear key under the alias, path with a space and `%`."""
    scanned = ssh84("ssh-keyscan", "-T", "5", "-p", "22", "--", str(ap_address)).stdout.decode()
    lines = [line for line in scanned.splitlines() if line and not line.startswith("#")]
    assert lines, "ssh-keyscan from the 8.4 container returned nothing"
    _host, key_type, key = lines[0].split()
    content = f"{ALIAS} {key_type} {key}\n"
    result = ssh84(
        "sh", "-c",
        f"mkdir -p {shlex.quote(str(KNOWN_HOSTS.parent))} && cat >{shlex.quote(str(KNOWN_HOSTS))}"
        f" && chmod 600 {shlex.quote(str(KNOWN_HOSTS))}",
        stdin=content.encode(),
    )  # fmt: skip
    assert result.returncode == 0, result.stderr
    return KNOWN_HOSTS


def invocation(ap_address: IPv4Address, password: str = SCAN_PASSWORD) -> tuple[Sequence[str], dict[str, str], bytes]:
    target = ScanTarget(
        site_id="default",
        ap_mac=MAC,
        ap_name="AP-84",
        address=ap_address,
        port=22,
        host_key_alias=ALIAS,
        credentials=SshCredentials(
            user=SCAN_USER, method=SshAuthMethod.PASSWORD, password=Secret(password), key_file=None
        ),
        scan_attempts=1,
        interface_toggle=False,
        allow_public_address=False,
    )
    environ = {"PATH": "/usr/bin:/bin", "HOME": "/home/tester"}
    built = build_invocation(target, KNOWN_HOSTS, ASKPASS_IN_CONTAINER, load_script(), environ)
    return built.argv, dict(built.env), built.stdin


@pytest.mark.security("T17")
def test_the_container_runs_openssh_8_4(harness: Harness) -> None:
    banner = ssh84("ssh", "-V").stderr.decode() + ssh84("ssh", "-V").stdout.decode()
    assert "OpenSSH_8.4" in banner


@pytest.mark.security("T17")
def test_the_exact_argv_scans_through_openssh_8_4_with_askpass_and_a_quoted_store_path(
    fresh_ap: Harness, ap_address: IPv4Address, known_hosts: Path
) -> None:
    argv, env, stdin = invocation(ap_address)
    result = ssh84(*argv, stdin=stdin, env=env)
    assert result.returncode == 0, result.stderr.decode()
    parsed = parse_scan_output(result.stdout)
    two = parsed.band(Band.GHZ_2)
    assert two is not None and two.status is BandScanStatus.OK and len(two.readings) == 3


@pytest.mark.security("T17")
def test_a_file_named_none_in_the_working_directory_changes_nothing(
    fresh_ap: Harness, ap_address: IPv4Address, known_hosts: Path
) -> None:
    # `-F none`, `ControlPath=none` and `ProxyCommand=none` are keywords; a relative file `none` must not be
    # read as any of them. The scanner also runs ssh from `/`, where no such file can exist.
    setup = ssh84(
        "sh", "-c", "mkdir -p /home/tester/trap && printf 'ProxyCommand /bin/false\\n' >/home/tester/trap/none"
    )
    assert setup.returncode == 0
    argv, env, stdin = invocation(ap_address)
    result = ssh84(*argv, stdin=stdin, env=env, workdir="/home/tester/trap")
    assert result.returncode == 0, result.stderr.decode()
    assert parse_scan_output(result.stdout).band(Band.GHZ_2).status is BandScanStatus.OK  # type: ignore[union-attr]


@pytest.mark.security("T9", "T17")
def test_a_wrong_password_through_askpass_is_permission_denied_not_a_prompt(
    fresh_ap: Harness, ap_address: IPv4Address, known_hosts: Path
) -> None:
    argv, env, stdin = invocation(ap_address, password="wrong")
    result = ssh84(*argv, stdin=stdin, env=env)
    assert result.returncode == 255
    assert b"Permission denied" in result.stderr and b"password:" not in result.stdout


@pytest.mark.security("T6")
def test_an_unknown_alias_is_refused_by_strict_host_key_checking(
    fresh_ap: Harness, ap_address: IPv4Address, known_hosts: Path
) -> None:
    argv, env, stdin = invocation(ap_address)
    argv = [a if not a.startswith("HostKeyAlias=") else "HostKeyAlias=uwo-" + "00" * 16 for a in argv]
    result = ssh84(*argv, stdin=stdin, env=env)
    assert result.returncode == 255 and b"Host key verification failed" in result.stderr
