import json
from pathlib import Path

import pytest

from unifiwifioptimizer.adapters.unifi import parse
from unifiwifioptimizer.app.use_cases import SiteOverview
from unifiwifioptimizer.config.loader import parse_yaml
from unifiwifioptimizer.config.schema import Config, SshAuth
from unifiwifioptimizer.domain.models import AccessPoint, MgmtSettings, Site, WlanConfig
from unifiwifioptimizer.report.skeleton import render_skeleton

FIXTURES = Path(__file__).parents[2] / "fixtures"


def overview(
    *,
    aps: tuple[AccessPoint, ...] | None = None,
    wlans: tuple[WlanConfig, ...] | None = None,
    mgmt: MgmtSettings | None = None,
) -> SiteOverview:
    devices = parse.parse_devices(json.loads((FIXTURES / "stat_device.json").read_text()))
    parsed_wlans = parse.parse_wlans(json.loads((FIXTURES / "list_wlanconf.json").read_text()))
    return SiteOverview(
        site=Site(id="default", description="Site-1", hidden_id="default", device_count=11),
        wlans=parsed_wlans.items if wlans is None else wlans,
        access_points=devices.access_points if aps is None else aps,
        unparsable_devices=(),
        mgmt=mgmt,
        problems=(),
    )


def test_skeleton_round_trips_through_the_strict_loader_and_schema() -> None:
    text = render_skeleton(overview())
    document = parse_yaml("controller:\n  url: https://unifi.example\n  api_key: k\nsites:\n" + text)
    config = Config.from_mapping(document)
    site = config.sites["default"]
    assert site.ssh is not None and site.ssh.auth is SshAuth.CONTROLLER and site.scan_passes == 3
    assert set(site.wlans) == {"SSID-1", "SSID-2", "SSID-3", "SSID-4", "SSID-5"}
    assert site.neighbors == {"AP-1": frozenset(), "AP-2": frozenset(), "AP-3": frozenset(), "AP-4": frozenset()}


def test_skeleton_quotes_names_the_loader_would_otherwise_retype() -> None:
    import dataclasses

    base = overview()
    tricky = tuple(
        dataclasses.replace(w, name=name) for w, name in zip(base.wlans[:3], ("off", "12", "a: b"), strict=False)
    )
    text = render_skeleton(overview(wlans=tricky))
    config = Config.from_mapping(parse_yaml("controller:\n  url: https://unifi.example\n  api_key: k\nsites:\n" + text))
    assert set(config.sites["default"].wlans) == {"off", "12", "a: b"}


def test_skeleton_handles_empty_sites_and_disabled_ssh() -> None:
    mgmt = MgmtSettings(ssh_enabled=False, ssh_password_auth_enabled=None, ssh_user=None, ssh_password=None)
    text = render_skeleton(overview(aps=(), wlans=(), mgmt=mgmt))
    assert "# no WLANs reported" in text and "# no access points reported" in text and "SSH is disabled" in text
    Config.from_mapping(parse_yaml("controller:\n  url: https://unifi.example\n  api_key: k\nsites:\n" + text))


ODD_NAMES = [
    "del\x7f", "csi\x9bred", "nel\x85", "sep\u2028", "para\u2029", "noncharacter\ufffe", "rlo\u202e",
    "bom\ufeff", "nul\x00", "esc\x1b[31m", "quote\"back\\slash", "emoji \U0001f600", "lone\ud800",
    "private\ue000", "unassigned\U000e0080", "trailing space ", "  leading", "tab\there", "newline\nhere",
]  # fmt: skip


@pytest.mark.parametrize("name", ODD_NAMES)
@pytest.mark.security("T12")
def test_every_controller_name_round_trips_and_prints_without_raw_unsafe_characters(name: str) -> None:
    import dataclasses
    import unicodedata

    from unifiwifioptimizer.report.safe_text import UNSAFE_CATEGORIES

    base = overview()
    text = render_skeleton(
        overview(
            wlans=(dataclasses.replace(base.wlans[0], name=name),),
            aps=(dataclasses.replace(base.access_points[0], name=name),),
        )
    )
    assert all(char == "\n" or unicodedata.category(char) not in UNSAFE_CATEGORIES for char in text)
    config = Config.from_mapping(parse_yaml("controller:\n  url: https://unifi.example\n  api_key: k\nsites:\n" + text))
    assert set(config.sites["default"].wlans) == {name} and set(config.sites["default"].neighbors) == {name}


def test_duplicate_names_do_not_produce_duplicate_keys() -> None:
    import dataclasses

    base = overview()
    wlans = tuple(dataclasses.replace(w, name="Same") for w in base.wlans[:2])
    aps = tuple(dataclasses.replace(ap, name="Twin") for ap in base.access_points[:3])
    text = render_skeleton(overview(wlans=wlans, aps=aps))
    assert text.count('"Same": Standard') == 1 and text.count('"Twin": []') == 1
    assert "# 3 access points share this name" in text
    config = Config.from_mapping(parse_yaml("controller:\n  url: https://unifi.example\n  api_key: k\nsites:\n" + text))
    assert set(config.sites["default"].wlans) == {"Same"} and set(config.sites["default"].neighbors) == {"Twin"}
