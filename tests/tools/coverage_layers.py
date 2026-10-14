"""Per-layer coverage against the soft targets — the documented tier of the two-tier pattern.

The hard floor is `./dev coverage` on the unit tier. This report reads a combined data file (unit plus
integration, `./dev coverage-layers`) and prints every layer against its target plus the files under
that target, so a low file inside a high layer stays visible. A layer below target never fails the
command; a missing or empty data file does, because an unmeasured tier is a broken measurement.

Run `uv run python -m tests.tools.coverage_layers --data-file .coverage.combined`.
"""

import argparse
import json
import sys
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

import coverage

PACKAGE_DIR = Path(__file__).resolve().parents[2] / "src" / "unifiwifioptimizer"
PYPROJECT = Path(__file__).resolve().parents[2] / "pyproject.toml"

# Every *.py under the package belongs to exactly one layer (test_coverage_layers.py proves the partition).
# A package __init__ follows its package; the top-level __init__/__main__ are the entry points and count as
# I/O. `app/` is not named by the ticket's tiers: it is policy (trust bases, exit-code reduction, scan
# orchestration), so it gets the parsing tier's bar rather than the I/O tier's.
LAYER_TARGETS: dict[str, int] = {"core": 95, "application": 90, "parsing": 90, "report": 85, "io": 70}
CORE_PACKAGES = frozenset({"domain", "rf", "compliance", "analysis", "ports"})
PARSING_FILES = frozenset({"adapters/unifi/parse.py", "adapters/unifi/validate.py", "adapters/ssh/iw_parser.py"})
IO_PACKAGES = frozenset({"cli", "adapters", "resources"})
IO_FILES = frozenset({"__init__.py", "__main__.py"})


def layer_of(relpath: str) -> str:
    """The layer of one source file; a file no layer claims is an error, never a silent default."""
    top = relpath.split("/", 1)[0]
    if top in CORE_PACKAGES:
        return "core"
    if top == "app":
        return "application"
    if top == "config" or relpath in PARSING_FILES:
        return "parsing"
    if top == "report":
        return "report"
    if top in IO_PACKAGES or relpath in IO_FILES:
        return "io"
    raise ValueError(f"{relpath} belongs to no coverage layer; assign it in tests/tools/coverage_layers.py")


@dataclass(frozen=True)
class FileCoverage:
    relpath: str
    covered: int
    total: int

    @property
    def percent(self) -> float:
        return 100.0 if self.total == 0 else 100.0 * self.covered / self.total


@dataclass(frozen=True)
class LayerReport:
    name: str
    target: int
    files: tuple[FileCoverage, ...]

    @property
    def covered(self) -> int:
        return sum(f.covered for f in self.files)

    @property
    def total(self) -> int:
        return sum(f.total for f in self.files)

    @property
    def percent(self) -> float:
        return 100.0 if self.total == 0 else 100.0 * self.covered / self.total

    @property
    def below_target(self) -> tuple[FileCoverage, ...]:
        return tuple(f for f in self.files if f.percent < self.target)


def file_coverages(data_file: Path) -> list[FileCoverage]:
    """Lines plus branches per file, with the project's report configuration (exclusions) applied."""
    if not data_file.is_file() or data_file.stat().st_size == 0:
        raise FileNotFoundError(f"coverage data file {data_file} is missing or empty")
    cov = coverage.Coverage(data_file=str(data_file), config_file=str(PYPROJECT))
    cov.load()
    with tempfile.TemporaryDirectory() as scratch:
        report = Path(scratch) / "coverage.json"
        cov.json_report(outfile=str(report))
        files = json.loads(report.read_text(encoding="utf-8"))["files"]
    result = []
    for name, entry in files.items():
        summary = entry["summary"]
        relpath = Path(name).resolve().relative_to(PACKAGE_DIR).as_posix()
        result.append(
            FileCoverage(
                relpath,
                summary["covered_lines"] + summary.get("covered_branches", 0),
                summary["num_statements"] + summary.get("num_branches", 0),
            )
        )
    if not result:
        raise FileNotFoundError(f"coverage data file {data_file} holds no measured file")
    return sorted(result, key=lambda f: f.relpath)


def layer_reports(files: Iterable[FileCoverage]) -> list[LayerReport]:
    grouped: dict[str, list[FileCoverage]] = {name: [] for name in LAYER_TARGETS}
    for file in files:
        grouped[layer_of(file.relpath)].append(file)
    return [LayerReport(name, target, tuple(grouped[name])) for name, target in LAYER_TARGETS.items()]


def render(reports: Iterable[LayerReport]) -> str:
    lines = []
    for report in reports:
        verdict = "OK" if report.percent >= report.target else "BELOW"
        ratio = f"{report.covered:>5}/{report.total:<5}"
        lines.append(f"{report.name:<12} {ratio} {report.percent:5.1f} %  target {report.target} %  {verdict}")
        lines.extend(f"    {f.relpath:<40} {f.percent:5.1f} %" for f in report.below_target)
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="per-layer coverage against the soft targets")
    parser.add_argument("--data-file", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        files = file_coverages(args.data_file)
    except FileNotFoundError as exc:
        print(f"coverage-layers: {exc}", file=sys.stderr)
        return 2
    sys.stdout.write(render(layer_reports(files)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
