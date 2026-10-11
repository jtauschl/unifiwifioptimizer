"""The Docker harness as pytest fixtures: compose up once per session, the published ports, a stub control."""

import subprocess
import time
from collections.abc import Iterator
from dataclasses import dataclass
from ipaddress import IPv4Address
from pathlib import Path

import pytest

COMPOSE_FILE = Path(__file__).resolve().parents[3] / "docker" / "compose.yaml"
SCAN_USER = "scanuser"
SCAN_PASSWORD = "scan-pass"
LOOPBACK = IPv4Address("127.0.0.1")


def compose(
    *args: str, check: bool = True, stdin: bytes | None = None, timeout: float = 120
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE_FILE), *args],
        capture_output=True,
        input=stdin,
        check=check,
        timeout=timeout,
    )


def published_port(service: str, container_port: int) -> int:
    output = compose("port", service, str(container_port)).stdout.decode().strip()
    return int(output.rsplit(":", 1)[1])


@dataclass(frozen=True)
class Harness:
    dropbear_port: int
    sshd_port: int
    address: IPv4Address

    def exec_ap(self, *argv: str, stdin: bytes | None = None, check: bool = True) -> subprocess.CompletedProcess[bytes]:
        return compose("exec", "-T", "ap", *argv, stdin=stdin, check=check)

    def set_knob(self, name: str, present: bool) -> None:
        self.exec_ap("sh", "-c", f"{'touch' if present else 'rm -f'} /run/stub/{name}")

    def reset(self) -> None:
        # A scan the remote watchdog is still bounding (up to 25 s after a killed call) must not leak into
        # the next test's leftover check.
        self.exec_ap(
            "sh", "-c",
            "pkill -f '^sleep 600' || true; rm -f /run/stub/* /run/ifstate/apclii0.up; : >/run/ifstate/apcli0.up",
        )  # fmt: skip

    def toggles(self) -> list[str]:
        result = self.exec_ap("sh", "-c", "cat /run/stub/toggles 2>/dev/null || true")
        return result.stdout.decode().splitlines()


def wait_until_running(service: str, attempts: int = 60) -> None:
    # `up --wait` returns once the health checks pass; a dependent service may still be starting.
    for _ in range(attempts):
        state = compose("ps", "--format", "{{.State}}", service).stdout.decode().strip()
        if state == "running":
            return
        time.sleep(0.5)
    raise RuntimeError(f"harness service {service} did not reach the running state")


@pytest.fixture(scope="session")
def harness() -> Iterator[Harness]:
    compose("up", "-d", "--wait", "--build", timeout=900)
    wait_until_running("ap")
    wait_until_running("ssh84")
    try:
        yield Harness(dropbear_port=published_port("ap", 22), sshd_port=published_port("ap", 2222), address=LOOPBACK)
    finally:
        compose("down", "--remove-orphans", check=False)


@pytest.fixture
def fresh_ap(harness: Harness) -> Iterator[Harness]:
    harness.reset()
    yield harness
    harness.reset()
