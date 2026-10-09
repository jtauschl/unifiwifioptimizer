"""Write the project's own version into a CycloneDX SBOM produced by `uv export`.

uv leaves `metadata.component.version` out for a dynamically versioned project, so the SBOM could not
say which release of the tool it describes, and it types the root as `library` although the tool is
an application. The version comes from hatch-vcs in CI and from the tag in a release build; the file is
rewritten in place and a missing or empty version is an error.
"""

import json
import sys
from pathlib import Path


def set_root_version(sbom_path: Path, version: str) -> None:
    if not version.strip():
        raise ValueError("root component version is empty")
    sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
    component = sbom["metadata"]["component"]
    component["version"] = version.strip()
    component["type"] = "application"
    sbom_path.write_text(json.dumps(sbom, indent=2) + "\n", encoding="utf-8")


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(f"usage: {argv[0]} <sbom.cdx.json> <version>", file=sys.stderr)
        return 2
    set_root_version(Path(argv[1]), argv[2])
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
