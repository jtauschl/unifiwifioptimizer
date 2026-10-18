"""The version and content gate between the build and every later release job."""

import io
import re
import tarfile
import zipfile
from collections.abc import Callable
from pathlib import Path

import pytest

from tests.unit.scripts import load_script

check = load_script("dist_check")

VERSION = "0.5.0"
ROOT = f"unifiwifioptimizer-{VERSION}"
SCAN = "src/unifiwifioptimizer/adapters/ssh/remote_scan.sh"
PYPROJECT = """\
[tool.hatch.build.targets.sdist]
include = ["src/unifiwifioptimizer/", "tests/", "docs/", "pyproject.toml", "README.md", "LICENSE"]
"""
SDIST_FILES = {
    "PKG-INFO": f"Metadata-Version: 2.4\nName: unifiwifioptimizer\nVersion: {VERSION}\n\nbody",
    ".gitignore": "*.pyc\n",
    "pyproject.toml": PYPROJECT,
    "README.md": "readme",
    "LICENSE": "mit",
    "docs/ALGORITHM.md": "algorithm",
    "tests/conftest.py": "",
    SCAN: "#!/bin/sh\n",
    "src/unifiwifioptimizer/__init__.py": "",
    "src/unifiwifioptimizer/py.typed": "",
    "src/unifiwifioptimizer/resources/profiles.yaml": "profiles: {}",
}


def write_wheel(
    dist: Path, version: str = VERSION, *, metadata_version: str | None = None, resources: bool = True
) -> None:
    metadata = f"Metadata-Version: 2.4\nName: unifiwifioptimizer\nVersion: {metadata_version or version}\n\nbody"
    with zipfile.ZipFile(dist / f"unifiwifioptimizer-{version}-py3-none-any.whl", "w") as archive:
        archive.writestr(f"unifiwifioptimizer-{version}.dist-info/METADATA", metadata)
        archive.writestr("unifiwifioptimizer/__init__.py", "")
        if resources:
            archive.writestr("unifiwifioptimizer/py.typed", "")
            archive.writestr("unifiwifioptimizer/resources/profiles.yaml", "profiles: {}")
            archive.writestr("unifiwifioptimizer/adapters/ssh/remote_scan.sh", "#!/bin/sh\n")


def write_sdist(
    dist: Path,
    version: str = VERSION,
    mutate: Callable[[dict[str, str]], None] | None = None,
    outside_root: str | None = None,
) -> None:
    files = dict(SDIST_FILES)
    files["PKG-INFO"] = SDIST_FILES["PKG-INFO"].replace(VERSION, version)
    if mutate:
        mutate(files)
    root = f"unifiwifioptimizer-{version}"
    with tarfile.open(dist / f"{root}.tar.gz", "w:gz") as archive:
        for name, content in files.items():
            data = content.encode()
            info = tarfile.TarInfo(f"{root}/{name}")
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
        for directory in ("src/unifiwifioptimizer", "src/unifiwifioptimizer/resources"):
            info = tarfile.TarInfo(f"{root}/{directory}")
            info.type = tarfile.DIRTYPE
            archive.addfile(info)
        if outside_root:
            info = tarfile.TarInfo(outside_root)
            info.size = 0
            archive.addfile(info, io.BytesIO(b""))


def drop(name: str) -> Callable[[dict[str, str]], None]:
    def mutate(files: dict[str, str]) -> None:
        del files[name]

    return mutate


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    (tmp_path / "pyproject.toml").write_text(PYPROJECT, encoding="utf-8")
    (tmp_path / "dist").mkdir()
    return tmp_path


def run_check(tree: Path, version: str = VERSION) -> dict[str, str]:
    hashes: dict[str, str] = check.check_dist(tree / "dist", version, tree / "pyproject.toml")
    return hashes


def good(tree: Path) -> None:
    write_wheel(tree / "dist")
    write_sdist(tree / "dist")


def test_a_complete_pair_passes_and_every_file_gets_a_digest(tree: Path) -> None:
    good(tree)
    hashes = run_check(tree)
    assert sorted(hashes) == [f"{ROOT}-py3-none-any.whl", f"{ROOT}.tar.gz"]
    assert all(len(digest) == 64 for digest in hashes.values())


def test_hidden_files_in_dist_are_ignored(tree: Path) -> None:
    good(tree)
    (tree / "dist" / ".gitignore").write_text("*", encoding="utf-8")
    assert len(run_check(tree)) == 2


def test_the_hash_file_is_in_sha256sum_format() -> None:
    assert check.format_hashes({"b.whl": "2" * 64, "a.whl": "1" * 64}) == f"{'1' * 64}  a.whl\n{'2' * 64}  b.whl\n"


def test_files_of_another_version_than_the_tag_are_refused(tree: Path) -> None:
    write_wheel(tree / "dist", "0.4.1")
    write_sdist(tree / "dist", "0.4.1")
    with pytest.raises(check.DistError, match="expected exactly"):
        run_check(tree)


def test_an_extra_file_in_dist_is_refused(tree: Path) -> None:
    good(tree)
    (tree / "dist" / "unifiwifioptimizer-0.5.0-py3-none-any.whl.bak").write_bytes(b"x")
    with pytest.raises(check.DistError, match="expected exactly"):
        run_check(tree)


def test_a_missing_sdist_is_refused(tree: Path) -> None:
    write_wheel(tree / "dist")
    with pytest.raises(check.DistError, match="expected exactly"):
        run_check(tree)


def test_metadata_with_another_version_than_the_file_name_is_refused(tree: Path) -> None:
    write_wheel(tree / "dist", metadata_version="0.5.1")
    write_sdist(tree / "dist")
    with pytest.raises(check.DistError, match=re.escape("METADATA says version '0.5.1'")):
        run_check(tree)


def test_a_wheel_without_the_package_resources_is_refused(tree: Path) -> None:
    write_wheel(tree / "dist", resources=False)
    write_sdist(tree / "dist")
    with pytest.raises(check.DistError, match=re.escape("unifiwifioptimizer/resources/profiles.yaml")):
        run_check(tree)


def test_a_resource_the_sdist_carries_must_reach_the_wheel(tree: Path) -> None:
    write_wheel(tree / "dist")
    write_sdist(tree / "dist", mutate=lambda files: files.update({"src/unifiwifioptimizer/resources/extra.yaml": "x"}))
    with pytest.raises(check.DistError, match=re.escape("unifiwifioptimizer/resources/extra.yaml")):
        run_check(tree)


def test_python_modules_and_bytecode_are_not_resources(tree: Path) -> None:
    write_wheel(tree / "dist")
    write_sdist(
        tree / "dist",
        mutate=lambda files: files.update(
            {
                "src/unifiwifioptimizer/module.py": "",
                "src/unifiwifioptimizer/__pycache__/module.cpython-311.pyc": "",
            }
        ),
    )
    assert len(run_check(tree)) == 2


def test_a_required_resource_missing_from_the_sdist_is_refused_even_if_the_wheel_lacks_it_too(tree: Path) -> None:
    write_wheel(tree / "dist", resources=False)
    write_sdist(tree / "dist", mutate=drop("src/unifiwifioptimizer/resources/profiles.yaml"))
    with pytest.raises(check.DistError, match=re.escape("required package resources missing: resources/profiles.yaml")):
        run_check(tree)


def test_an_sdist_entry_outside_the_versioned_root_is_refused(tree: Path) -> None:
    write_wheel(tree / "dist")
    write_sdist(tree / "dist", outside_root="elsewhere/payload")
    with pytest.raises(check.DistError, match="entries outside"):
        run_check(tree)


def test_the_sdist_may_not_carry_a_top_level_entry_pyproject_does_not_ask_for(tree: Path) -> None:
    write_wheel(tree / "dist")
    write_sdist(tree / "dist", mutate=lambda files: files.update({"scripts/install.sh": "#!/bin/sh\n"}))
    with pytest.raises(check.DistError, match=r"extra \['scripts'\]"):
        run_check(tree)


def test_the_sdist_must_carry_every_top_level_entry_pyproject_asks_for(tree: Path) -> None:
    write_wheel(tree / "dist")
    write_sdist(tree / "dist", mutate=drop("docs/ALGORITHM.md"))
    with pytest.raises(check.DistError, match=r"missing \['docs'\]"):
        run_check(tree)


def test_a_shell_script_besides_the_scan_script_is_refused(tree: Path) -> None:
    write_wheel(tree / "dist")
    write_sdist(tree / "dist", mutate=lambda files: files.update({"tests/helper.sh": "#!/bin/sh\n"}))
    with pytest.raises(check.DistError, match="shell scripts must be exactly the scan script"):
        run_check(tree)


def test_a_sdist_without_the_scan_script_is_refused(tree: Path) -> None:
    write_wheel(tree / "dist")
    write_sdist(tree / "dist", mutate=drop(SCAN))
    with pytest.raises(check.DistError, match="shell scripts must be exactly the scan script"):
        run_check(tree)


def test_a_config_yaml_anywhere_in_the_sdist_is_refused(tree: Path) -> None:
    write_wheel(tree / "dist")
    write_sdist(tree / "dist", mutate=lambda files: files.update({"tests/fixtures/config.yaml": "api_key: x"}))
    with pytest.raises(check.DistError, match=re.escape("config.yaml must never ship")):
        run_check(tree)


def test_a_sdist_whose_pkg_info_names_another_version_is_refused(tree: Path) -> None:
    write_wheel(tree / "dist")
    write_sdist(
        tree / "dist", mutate=lambda files: files.update({"PKG-INFO": files["PKG-INFO"].replace(VERSION, "0.5.1")})
    )
    with pytest.raises(check.DistError, match=re.escape("PKG-INFO says version '0.5.1'")):
        run_check(tree)


def test_the_command_line_writes_the_hashes_or_names_the_violation(
    tree: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    good(tree)
    out = tree / "hashes.txt"
    argv = ["--dist", str(tree / "dist"), "--version", VERSION, "--hashes-out", str(out)]
    argv += ["--pyproject", str(tree / "pyproject.toml")]
    assert check.main(argv) == 0
    assert len(out.read_text(encoding="utf-8").splitlines()) == 2
    out.unlink()
    assert check.main([*argv[:3], "9.9.9", *argv[4:]]) == 1
    assert "dist_check: dist/ holds" in capsys.readouterr().err and not out.exists()
