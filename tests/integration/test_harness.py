"""The Docker harness must be reachable and pinned; absence is an error, never a skip."""

import re
import subprocess
from pathlib import Path

import pytest
import yaml

DOCKER_DIR = Path(__file__).resolve().parents[2] / "docker"
COMPOSE_FILE = DOCKER_DIR / "compose.yaml"
_FROM_RE = re.compile(r"^FROM\s+(\S+)", re.MULTILINE)

pytestmark = pytest.mark.integration


def test_docker_daemon_is_reachable() -> None:
    result = subprocess.run(["docker", "info", "--format", "{{.ServerVersion}}"], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip()


def test_compose_file_is_valid_and_every_base_image_is_pinned_by_digest() -> None:
    result = subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE_FILE), "config", "--format", "json"], capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr
    services = yaml.safe_load(result.stdout)["services"]
    assert services
    for name, service in services.items():
        if "build" in service:
            dockerfile = Path(service["build"]["context"]) / service["build"].get("dockerfile", "Dockerfile")
            bases = _FROM_RE.findall(dockerfile.read_text())
            assert bases, f"{name}: Dockerfile without FROM"
            assert all("@sha256:" in base for base in bases), (name, bases)
        else:
            assert "@sha256:" in service["image"], (name, service["image"])
