"""The Docker harness must be reachable and its compose file valid; absence is an error, never a skip."""

import subprocess
from pathlib import Path

import pytest

COMPOSE_FILE = Path(__file__).resolve().parents[2] / "docker" / "compose.yaml"

pytestmark = pytest.mark.integration


def test_docker_daemon_is_reachable() -> None:
    result = subprocess.run(["docker", "info", "--format", "{{.ServerVersion}}"], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip()


def test_compose_file_is_valid_and_pins_every_image_by_digest() -> None:
    result = subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE_FILE), "config", "--images"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    images = result.stdout.split()
    assert images
    assert all("@sha256:" in image for image in images), images
