"""What the documentation promises about the configuration surface, checked against the code that enforces it."""

import re
from pathlib import Path

from unifiwifioptimizer.config.schema import CONTROLLER_KEYS, RF_KEYS, SITE_KEYS, SSH_KEYS

README = Path(__file__).resolve().parents[2] / "README.md"
TABLE = re.compile(r"<!-- config-keys:start -->\n(?P<table>.*?)\n<!-- config-keys:end -->", re.DOTALL)
ROW = re.compile(r"^\| `(?P<key>[^`]+)` \|", re.MULTILINE)


def readme_key_paths() -> list[str]:
    match = TABLE.search(README.read_text(encoding="utf-8"))
    assert match is not None, "the README key table lost its markers"
    return ROW.findall(match.group("table"))


def schema_key_paths() -> set[str]:
    return (
        {f"controller.{key}" for key in CONTROLLER_KEYS}
        | {f"sites.<site>.ssh.{key}" for key in SSH_KEYS}
        | {f"sites.<site>.{key}" for key in SITE_KEYS - {"ssh"}}
        | {f"rf.{key}" for key in RF_KEYS}
    )


def test_the_readme_key_table_lists_every_key_the_schema_accepts_and_no_other() -> None:
    documented = readme_key_paths()
    assert len(documented) == len(set(documented)), "a key is documented twice"
    assert set(documented) == schema_key_paths()
