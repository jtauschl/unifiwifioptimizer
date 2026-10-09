"""Invariants of pyproject.toml that no tool checks on its own."""

import tomllib
from pathlib import Path
from typing import Any

import pytest

PYPROJECT = Path(__file__).resolve().parents[2] / "pyproject.toml"


@pytest.fixture(scope="module")
def pyproject() -> dict[str, Any]:
    return tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))


def test_dev_extra_mirrors_dev_dependency_group(pyproject: dict[str, Any]) -> None:
    # pip/venv contributors install the extra, uv installs the group; a bump reaching only one of them
    # would give the two paths different tool versions.
    assert pyproject["project"]["optional-dependencies"]["dev"] == pyproject["dependency-groups"]["dev"]


def test_dev_dependencies_are_pinned_exactly(pyproject: dict[str, Any]) -> None:
    unpinned = [req for req in pyproject["dependency-groups"]["dev"] if "==" not in req]
    assert unpinned == []


def test_pyyaml_is_the_only_runtime_dependency(pyproject: dict[str, Any]) -> None:
    assert [req.split(">=")[0] for req in pyproject["project"]["dependencies"]] == ["pyyaml"]


def test_python_version_file_is_the_declared_floor(pyproject: dict[str, Any]) -> None:
    floor = pyproject["project"]["requires-python"].removeprefix(">=")
    assert (PYPROJECT.parent / ".python-version").read_text(encoding="utf-8").strip() == floor
