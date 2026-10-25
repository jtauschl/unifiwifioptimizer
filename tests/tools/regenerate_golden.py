"""Regenerate the report golden files from the deterministic golden input.

Run `uv run python -m tests.tools.regenerate_golden` after an intentional change to the analysis or the
renderers, then review the diff of tests/fixtures/golden/ like any other change. The tests never regenerate.
"""

import sys
from dataclasses import replace
from pathlib import Path

from tests.unit.analysis.builders import golden_input
from unifiwifioptimizer.analysis.site_analyzer import analyze_site
from unifiwifioptimizer.report.json import render_json
from unifiwifioptimizer.report.text import render_overview, render_report

GOLDEN = Path(__file__).parents[1] / "fixtures" / "golden"


def main() -> int:
    report = analyze_site(golden_input())
    GOLDEN.mkdir(exist_ok=True)
    (GOLDEN / "run_default.txt").write_text(render_report(report), encoding="utf-8")
    (GOLDEN / "run_default.json").write_text(render_json([report]), encoding="utf-8")
    (GOLDEN / "run_overview.txt").write_text(render_overview(report), encoding="utf-8")
    extended = analyze_site(replace(golden_input(), extended=True))
    (GOLDEN / "run_overview_extended.txt").write_text(render_overview(extended), encoding="utf-8")
    print(f"wrote the four golden files in {GOLDEN}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
