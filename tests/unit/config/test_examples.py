"""The starter files in the repository must be accepted by the loader as they are."""

from pathlib import Path
from typing import Any

import pytest

from unifiwifioptimizer.config.loader import parse_yaml
from unifiwifioptimizer.config.schema import Config, SshAuth
from unifiwifioptimizer.domain.errors import ConfigError

ROOT = Path(__file__).resolve().parents[3]


def load(name: str) -> Config:
    path = ROOT / name
    return Config.from_mapping(parse_yaml(path.read_text(encoding="utf-8"), name))


def test_the_minimal_starter_is_a_valid_controller_only_configuration() -> None:
    config = load("config.minimal.yaml")
    assert config.controller.host == "unifi.example.com" and config.sites == {}


def test_the_complete_example_is_valid_and_shows_the_safe_defaults() -> None:
    config = load("config.example.yaml")
    site = config.sites["YOUR_SITE_ID"]
    assert site.ssh is not None and site.ssh.auth is SshAuth.CONTROLLER
    assert site.ssh.scan_interface_toggle is False and site.ssh.allow_public_ap_addresses is False
    assert site.ssh.scan_concurrency == 1 and site.ssh.scan_attempts == 2
    assert site.scan_passes == 3 and site.scans


@pytest.mark.parametrize(
    "uncomment",
    [
        ("  # cert_fingerprint:", "  cert_fingerprint:"),
        ("  # ca_cert:", "  ca_cert:"),
    ],
)
def test_each_commented_controller_option_is_valid_when_enabled(uncomment: tuple[str, str]) -> None:
    text = (ROOT / "config.example.yaml").read_text(encoding="utf-8").replace(*uncomment, 1)
    Config.from_mapping(parse_yaml(text, "example"))


def test_the_commented_rf_block_matches_the_defaults_it_documents() -> None:
    lines = (ROOT / "config.example.yaml").read_text(encoding="utf-8").splitlines()
    block = [line.removeprefix("# ").removeprefix("#") for line in lines[lines.index("# rf:") :]]
    text = "\n".join(["controller:", "  url: https://unifi.example.com", "  api_key: k", *block])
    documented = Config.from_mapping(parse_yaml(text, "example"))
    defaults = Config.from_mapping(
        parse_yaml("controller:\n  url: https://unifi.example.com\n  api_key: k\n", "defaults")
    )
    assert documented.rf == defaults.rf


# Every range and default the example file states in a comment, against the schema that enforces it.
SITE = "sites.YOUR_SITE_ID"
DOCUMENTED = {
    "controller.timeout_s": (1, 120, 15, "(1..120, default 15)"),
    f"{SITE}.ssh.scan_concurrency": (1, 8, 1, "(1..8, default 1)"),
    f"{SITE}.ssh.scan_attempts": (1, 5, 2, "(1..5, default 2)"),
    f"{SITE}.scan_passes": (1, 10, 1, "(1..10, default 1)"),
}
DOCUMENTED_RF = {
    "noise_floor_dbm": (-105, -80),
    "required_snr_db": (10, 40),
    "client_tx_dbm": (0, 30),
    "client_tx_dbm_5g_upper": (0, 30),
    "min_rssi_offset_db": (0, 30),
    "roam_offset_db": (0, 30),
    "roam_margin_db": (0, 30),
}


def comment_above(key: str) -> str:
    """The comment block directly above the example's `key:` line (the line itself excluded)."""
    lines = (ROOT / "config.example.yaml").read_text(encoding="utf-8").splitlines()
    index = next(i for i, line in enumerate(lines) if line.strip().startswith(f"{key}:"))
    block: list[str] = []
    for line in reversed(lines[:index]):
        if not line.strip().startswith("#"):
            break
        block.append(line)
    return "\n".join(reversed(block))


def example_document() -> dict[str, Any]:
    document = parse_yaml((ROOT / "config.example.yaml").read_text(encoding="utf-8"), "example")
    assert isinstance(document, dict)
    return document


def with_value(path: str, value: object) -> dict[str, Any]:
    document = example_document()
    node: Any = document
    *parents, leaf = path.split(".")
    for part in parents:
        node = node.setdefault(part, {})
    node[leaf] = value
    return document


def accepted(document: dict[str, Any]) -> bool:
    try:
        Config.from_mapping(document)
    except ConfigError:
        return False
    return True


@pytest.mark.parametrize(("path", "bounds"), sorted(DOCUMENTED.items()))
def test_a_documented_range_is_exactly_what_the_schema_accepts(path: str, bounds: tuple[int, int, int, str]) -> None:
    low, high, _, phrase = bounds
    assert phrase in comment_above(path.rsplit(".", 1)[-1])
    assert accepted(with_value(path, low)) and accepted(with_value(path, high))
    assert not accepted(with_value(path, low - 1)) and not accepted(with_value(path, high + 1))


@pytest.mark.parametrize(("key", "bounds"), sorted(DOCUMENTED_RF.items()))
def test_a_documented_rf_range_is_exactly_what_the_schema_accepts(key: str, bounds: tuple[int, int]) -> None:
    low, high = bounds
    line = next(
        line
        for line in (ROOT / "config.example.yaml").read_text(encoding="utf-8").splitlines()
        if f"#   {key}:" in line
    )
    assert f"{low}..{high}" in line
    assert accepted(with_value(f"rf.{key}", low)) and accepted(with_value(f"rf.{key}", high))
    assert not accepted(with_value(f"rf.{key}", low - 1)) and not accepted(with_value(f"rf.{key}", high + 1))


def test_the_documented_roaming_bounds_are_the_schema_bounds_and_the_floor_stays_below_the_ceiling() -> None:
    text = (ROOT / "config.example.yaml").read_text(encoding="utf-8")
    assert "roam_floor_dbm: -75       # lowest roaming trigger, -95..-50, below the ceiling" in text
    assert "roam_ceiling_dbm: -65     # highest roaming trigger, -95..-50" in text

    def rf(floor: int, ceiling: int) -> dict[str, Any]:
        document = example_document()
        document["rf"] = {"roam_floor_dbm": floor, "roam_ceiling_dbm": ceiling}
        return document

    assert accepted(rf(-95, -50))
    assert not accepted(rf(-96, -50)) and not accepted(rf(-95, -49))
    assert not accepted(rf(-60, -65)), "a floor above the ceiling must be refused"


def test_the_documented_defaults_are_what_an_absent_key_gives() -> None:
    text = (ROOT / "config.example.yaml").read_text(encoding="utf-8")
    bare = Config.from_mapping(
        {
            "controller": {"url": "https://u.example", "api_key": "k"},
            "sites": {"s": {"ssh": {}, "neighbors": {"A": ["B"], "B": ["A"]}}},
        }
    )
    ssh = bare.sites["s"].ssh
    assert ssh is not None and ssh.auth is SshAuth.CONTROLLER
    assert bare.controller.timeout_s == DOCUMENTED["controller.timeout_s"][2]
    assert ssh.scan_concurrency == DOCUMENTED[f"{SITE}.ssh.scan_concurrency"][2]
    assert ssh.scan_attempts == DOCUMENTED[f"{SITE}.ssh.scan_attempts"][2]
    assert bare.sites["s"].scan_passes == DOCUMENTED[f"{SITE}.scan_passes"][2]
    assert ssh.scan_interface_toggle is False and ssh.allow_public_ap_addresses is False
    assert "(default false)" in comment_above("scan_interface_toggle")
    assert "(default false)" in comment_above("allow_public_ap_addresses")
    assert text.count("default false") == 2
