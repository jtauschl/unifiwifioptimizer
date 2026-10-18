"""The two build helpers that `dev` and the release workflow call: SBOM root version and build constraints."""

import json
from pathlib import Path

import pytest

from tests.unit.scripts import load_script

sbom = load_script("sbom_set_root_version")
constraints = load_script("check_build_constraints")

PYPROJECT = '[build-system]\nrequires = ["hatchling>=1.32.4", "hatch-vcs>=0.5.0"]\n'


def write_sbom(path: Path) -> None:
    path.write_text(json.dumps({"metadata": {"component": {"name": "tool", "type": "library"}}}), encoding="utf-8")


def test_the_root_component_gets_the_version_and_becomes_an_application(tmp_path: Path) -> None:
    path = tmp_path / "sbom.cdx.json"
    write_sbom(path)
    sbom.set_root_version(path, " 0.5.0\n")
    component = json.loads(path.read_text(encoding="utf-8"))["metadata"]["component"]
    assert component == {"name": "tool", "type": "application", "version": "0.5.0"}


@pytest.mark.parametrize("version", ["", "  \n"])
def test_an_empty_version_is_an_error_and_leaves_the_file_alone(tmp_path: Path, version: str) -> None:
    path = tmp_path / "sbom.cdx.json"
    write_sbom(path)
    before = path.read_text(encoding="utf-8")
    with pytest.raises(ValueError, match="empty"):
        sbom.set_root_version(path, version)
    assert path.read_text(encoding="utf-8") == before


def test_the_sbom_command_checks_its_arguments_and_writes_in_place(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert sbom.main(["prog"]) == 2 and "usage:" in capsys.readouterr().err
    path = tmp_path / "sbom.cdx.json"
    write_sbom(path)
    assert sbom.main(["prog", str(path), "1.2.3"]) == 0
    assert json.loads(path.read_text(encoding="utf-8"))["metadata"]["component"]["version"] == "1.2.3"


def test_build_constraints_that_match_the_build_system_pass(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(PYPROJECT, encoding="utf-8")
    (tmp_path / "in.txt").write_text("# comment\nhatchling>=1.32.4\n\nhatch-vcs>=0.5.0\n", encoding="utf-8")
    assert constraints.main(["prog", str(tmp_path / "pyproject.toml"), str(tmp_path / "in.txt")]) == 0


def test_a_drifted_build_constraints_file_fails_and_names_both_sets(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "pyproject.toml").write_text(PYPROJECT, encoding="utf-8")
    (tmp_path / "in.txt").write_text("hatchling>=1.30.0\nhatch-vcs>=0.5.0\n", encoding="utf-8")
    assert constraints.main(["prog", str(tmp_path / "pyproject.toml"), str(tmp_path / "in.txt")]) == 1
    err = capsys.readouterr().err
    assert "hatchling>=1.32.4" in err and "hatchling>=1.30.0" in err


def test_the_constraints_command_checks_its_arguments(capsys: pytest.CaptureFixture[str]) -> None:
    assert constraints.main(["prog", "only-one"]) == 2
    assert "usage:" in capsys.readouterr().err
