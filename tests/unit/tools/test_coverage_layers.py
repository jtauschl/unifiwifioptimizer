"""The layer partition of the coverage report and its rendering."""

from collections import Counter
from pathlib import Path

import pytest

from tests.tools import coverage_layers
from tests.tools.coverage_layers import FileCoverage, LayerReport, layer_of, layer_reports, render
from tests.unit import test_architecture

SOURCE_FILES = sorted(
    p.relative_to(coverage_layers.PACKAGE_DIR).as_posix() for p in coverage_layers.PACKAGE_DIR.rglob("*.py")
)


def test_every_source_file_belongs_to_exactly_one_layer() -> None:
    assert SOURCE_FILES
    assigned = {relpath: layer_of(relpath) for relpath in SOURCE_FILES}
    assert set(assigned.values()) <= set(coverage_layers.LAYER_TARGETS)
    # Every layer the targets name is populated; an empty layer would hide a renamed package behind "100 %".
    assert Counter(assigned.values()).keys() == coverage_layers.LAYER_TARGETS.keys()


@pytest.mark.parametrize(
    ("relpath", "layer"),
    [
        ("domain/models.py", "core"),
        ("rf/__init__.py", "core"),
        ("app/trust.py", "application"),
        ("config/loader.py", "parsing"),
        ("adapters/unifi/parse.py", "parsing"),
        ("adapters/ssh/iw_parser.py", "parsing"),
        ("report/text.py", "report"),
        ("adapters/unifi/tls.py", "io"),
        ("adapters/ssh/__init__.py", "io"),
        ("cli/main.py", "io"),
        ("__init__.py", "io"),
        ("__main__.py", "io"),
        ("resources/__init__.py", "io"),
    ],
)
def test_layer_assignment(relpath: str, layer: str) -> None:
    assert layer_of(relpath) == layer


def test_a_file_outside_every_layer_is_an_error() -> None:
    with pytest.raises(ValueError, match="belongs to no coverage layer"):
        layer_of("storage/cache.py")


def test_the_core_set_is_the_architecture_gates_core_set() -> None:
    assert coverage_layers.CORE_PACKAGES == test_architecture.CORE_PACKAGES


def test_the_report_lists_the_files_under_a_layers_target() -> None:
    files = [FileCoverage("rf/a.py", 100, 100), FileCoverage("rf/b.py", 50, 100), FileCoverage("cli/c.py", 7, 10)]
    reports = {r.name: r for r in layer_reports(files)}
    assert reports["core"].percent == 75.0 and reports["core"].below_target == (files[1],)
    assert reports["io"].percent == 70.0 and reports["io"].below_target == ()
    text = render(reports.values())
    assert "core           150/200    75.0 %  target 95 %  BELOW" in text
    assert "    rf/b.py" in text and "rf/a.py" not in text
    assert "io               7/10     70.0 %  target 70 %  OK" in text


def test_a_layer_without_files_counts_as_fully_covered() -> None:
    assert LayerReport("report", 85, ()).percent == 100.0


def test_a_missing_or_empty_data_file_is_a_failure_not_a_soft_miss(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert coverage_layers.main(["--data-file", str(tmp_path / "absent")]) == 2
    empty = tmp_path / ".coverage.empty"
    empty.write_bytes(b"")
    assert coverage_layers.main(["--data-file", str(empty)]) == 2
    assert "missing or empty" in capsys.readouterr().err
