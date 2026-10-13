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


def test_the_version_is_derived_from_the_tag_and_nowhere_committed(pyproject: dict[str, Any]) -> None:
    # One version source: the git tag. A committed version field would drift from the tag the build stamps.
    assert pyproject["project"]["dynamic"] == ["version"]
    assert "version" not in pyproject["project"]
    assert pyproject["tool"]["hatch"]["version"] == {"source": "vcs"}
    sources = (PYPROJECT.parent / "src").rglob("*.py")
    hardcoded = [p.name for p in sources if '__version__ = "' in p.read_text(encoding="utf-8")]
    assert hardcoded == []


def test_python_version_file_is_the_declared_floor(pyproject: dict[str, Any]) -> None:
    floor = pyproject["project"]["requires-python"].removeprefix(">=")
    assert (PYPROJECT.parent / ".python-version").read_text(encoding="utf-8").strip() == floor
