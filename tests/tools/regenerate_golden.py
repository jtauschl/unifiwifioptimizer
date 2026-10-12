"""Regenerate the report golden files from the deterministic golden input.

Run `uv run python -m tests.tools.regenerate_golden` after an intentional change to the analysis or the
renderers, then review the diff of tests/fixtures/golden/ like any other change. The tests never regenerate.
"""

import sys
from pathlib import Path

from tests.unit.analysis.builders import golden_input
from unifiwifioptimizer.analysis.site_analyzer import analyze_site
from unifiwifioptimizer.report.json import render_json
from unifiwifioptimizer.report.text import render_report

GOLDEN = Path(__file__).parents[1] / "fixtures" / "golden"


def main() -> int:
    report = analyze_site(golden_input())
    GOLDEN.mkdir(exist_ok=True)
    (GOLDEN / "run_default.txt").write_text(render_report(report), encoding="utf-8")
    (GOLDEN / "run_default.json").write_text(render_json([report]), encoding="utf-8")
    print(f"wrote {GOLDEN / 'run_default.txt'} and {GOLDEN / 'run_default.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
