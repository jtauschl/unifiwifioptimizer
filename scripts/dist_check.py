"""Version and content gate for the built distributions, standard library only.

The release workflow publishes whatever `uv build` left in `dist/`, so this check runs between the build and
every later job: the files carry the version the tag names, the sdist ships exactly the files `pyproject.toml`
asks for (no shell script besides the scan script, no `config.yaml`), and the wheel ships every non-Python
package resource the sdist carries, among them `profiles.yaml` and the scan script. The resource list comes
from the sdist, which the build filters through the version control ignore rules, so a stray file in a
developer's working tree cannot fail the check. On success it writes the SHA-256 of every file, in
`sha256sum` format, which later jobs verify against.
"""

import argparse
import hashlib
import sys
import tarfile
import tomllib
import zipfile
from collections.abc import Sequence
from pathlib import Path

DISTRIBUTION = "unifiwifioptimizer"
SCAN_SCRIPT = "src/unifiwifioptimizer/adapters/ssh/remote_scan.sh"
# Package resources the tool cannot run without; their absence from the sdist is a build error, not a list shrink.
REQUIRED_RESOURCES = frozenset({"resources/profiles.yaml", "adapters/ssh/remote_scan.sh"})
# What the sdist builder adds beside the configured include list.
IMPLICIT_SDIST_ENTRIES = frozenset({"PKG-INFO", ".gitignore"})


class DistError(Exception):
    """A distribution violates the release contract; the message names the file and the rule."""


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def distribution_files(dist: Path) -> list[Path]:
    """Every regular file in `dist/` except hidden ones (uv drops a `.gitignore` there)."""
    return sorted(p for p in dist.iterdir() if p.is_file() and not p.name.startswith("."))


def sdist_top_level(pyproject: Path) -> set[str]:
    config = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    include = config["tool"]["hatch"]["build"]["targets"]["sdist"]["include"]
    return {entry.strip("/").split("/", 1)[0] for entry in include} | IMPLICIT_SDIST_ENTRIES


def _metadata_version(text: str) -> str | None:
    for line in text.splitlines():
        if line.startswith("Version: "):
            return line.removeprefix("Version: ").strip()
        if not line.strip():
            break
    return None


def check_wheel(wheel: Path, version: str, resources: set[str]) -> None:
    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())
        metadata = f"{DISTRIBUTION}-{version}.dist-info/METADATA"
        if metadata not in names:
            raise DistError(f"{wheel.name}: {metadata} is missing")
        declared = _metadata_version(archive.read(metadata).decode("utf-8"))
        if declared != version:
            raise DistError(f"{wheel.name}: METADATA says version {declared!r}, expected {version!r}")
    missing = sorted(f"{DISTRIBUTION}/{rel}" for rel in resources if f"{DISTRIBUTION}/{rel}" not in names)
    if missing:
        raise DistError(f"{wheel.name}: package resources missing from the wheel: {', '.join(missing)}")


def check_sdist(sdist: Path, version: str, top_level: set[str]) -> set[str]:
    """Check the sdist and return the package-relative paths of its non-Python package files."""
    root = f"{DISTRIBUTION}-{version}"
    with tarfile.open(sdist, "r:gz") as archive:
        members = archive.getmembers()
        names = [member.name for member in members]
        foreign = sorted(name for name in names if name != root and not name.startswith(f"{root}/"))
        if foreign:
            raise DistError(f"{sdist.name}: entries outside {root}/: {', '.join(foreign[:5])}")
        entries = {name.split("/", 2)[1] for name in names if "/" in name}
        if entries != top_level:
            extra, absent = sorted(entries - top_level), sorted(top_level - entries)
            raise DistError(f"{sdist.name}: top-level entries differ from pyproject (extra {extra}, missing {absent})")
        scripts = sorted(name for name in names if name.endswith(".sh"))
        if scripts != [f"{root}/{SCAN_SCRIPT}"]:
            raise DistError(f"{sdist.name}: shell scripts must be exactly the scan script, found {scripts}")
        configs = sorted(name for name in names if name.rsplit("/", 1)[-1] == "config.yaml")
        if configs:
            raise DistError(f"{sdist.name}: a config.yaml must never ship: {', '.join(configs)}")
        pkg_info = archive.extractfile(f"{root}/PKG-INFO")
        if pkg_info is None:
            raise DistError(f"{sdist.name}: PKG-INFO is missing")
        declared = _metadata_version(pkg_info.read().decode("utf-8"))
        if declared != version:
            raise DistError(f"{sdist.name}: PKG-INFO says version {declared!r}, expected {version!r}")
        prefix = f"{root}/src/{DISTRIBUTION}/"
        resources = {
            member.name.removeprefix(prefix)
            for member in members
            if member.isfile()
            and member.name.startswith(prefix)
            and not member.name.endswith(".py")
            and "__pycache__" not in member.name.split("/")
        }
    absent = sorted(REQUIRED_RESOURCES - resources)
    if absent:
        raise DistError(f"{sdist.name}: required package resources missing: {', '.join(absent)}")
    return resources


def check_dist(dist: Path, version: str, pyproject: Path) -> dict[str, str]:
    """Check both distributions and return {file name: sha256}; any violation raises `DistError`."""
    files = distribution_files(dist)
    expected = {f"{DISTRIBUTION}-{version}-py3-none-any.whl", f"{DISTRIBUTION}-{version}.tar.gz"}
    if {f.name for f in files} != expected:
        raise DistError(f"dist/ holds {sorted(f.name for f in files)}, expected exactly {sorted(expected)}")
    resources = check_sdist(dist / f"{DISTRIBUTION}-{version}.tar.gz", version, sdist_top_level(pyproject))
    check_wheel(dist / f"{DISTRIBUTION}-{version}-py3-none-any.whl", version, resources)
    return {f.name: sha256_of(f) for f in files}


def format_hashes(hashes: dict[str, str]) -> str:
    return "".join(f"{digest}  {name}\n" for name, digest in sorted(hashes.items()))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--pyproject", type=Path, required=True)
    parser.add_argument("--hashes-out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        hashes = check_dist(args.dist, args.version, args.pyproject)
    except DistError as error:
        print(f"dist_check: {error}", file=sys.stderr)
        return 1
    args.hashes_out.write_text(format_hashes(hashes), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
