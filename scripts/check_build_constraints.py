"""Assert that build-constraints.in declares exactly the build backend pyproject.toml requires.

The hashed build-constraints.txt is compiled from the .in file; if the two inputs drift apart, a release
build would silently constrain a backend set that is not the one hatchling actually resolves.
"""

import sys
import tomllib
from pathlib import Path


def requirement_lines(text: str) -> set[str]:
    return {line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")}


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(f"usage: {argv[0]} <pyproject.toml> <build-constraints.in>", file=sys.stderr)
        return 2
    pyproject = tomllib.loads(Path(argv[1]).read_text(encoding="utf-8"))
    declared = {str(req) for req in pyproject["build-system"]["requires"]}
    constrained = requirement_lines(Path(argv[2]).read_text(encoding="utf-8"))
    if declared != constrained:
        print(
            f"build-system.requires {sorted(declared)} differs from {argv[2]} {sorted(constrained)}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
