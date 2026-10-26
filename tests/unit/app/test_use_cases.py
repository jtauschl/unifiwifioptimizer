import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from unifiwifioptimizer.adapters.unifi import parse
from unifiwifioptimizer.app.snapshot import build_snapshot
from unifiwifioptimizer.app.use_cases import list_sites, resolve_site, show_site
from unifiwifioptimizer.domain.errors import ConfigError
from unifiwifioptimizer.domain.models import (
    ApGroup,
    ClientSighting,
    DevicesResult,
    FieldProblem,
    Network,
    ParsedList,
    SettingsResult,
    Site,
    WlanConfig,
)

FIXTURES = Path(__file__).parents[2] / "fixtures"


def load(name: str) -> object:
    return json.loads((FIXTURES / name).read_text())


class FixtureApi:
    """`ControllerApi` backed by the committed fixtures; every site answers with the same data."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def sites(self) -> ParsedList[Site]:
        self.calls.append("sites")
        return parse.parse_sites(load("sites.json"))

    def devices(self, site_id: str) -> DevicesResult:
        self.calls.append(f"devices:{site_id}")
        return parse.parse_devices(load("stat_device.json"))

    def wlans(self, site_id: str) -> ParsedList[WlanConfig]:
        self.calls.append(f"wlans:{site_id}")
        return parse.parse_wlans(load("list_wlanconf.json"))

    def ap_groups(self, site_id: str) -> ParsedList[ApGroup]:
        self.calls.append(f"ap_groups:{site_id}")
        return parse.parse_ap_groups(load("apgroups.json"))

    def networks(self, site_id: str) -> ParsedList[Network]:
        self.calls.append(f"networks:{site_id}")
        return parse.parse_networks(load("networkconf.json"))

    def settings(self, site_id: str) -> SettingsResult:
        self.calls.append(f"settings:{site_id}")
        return parse.parse_settings(load("rest_setting.json"))

    def clients(self, site_id: str) -> ParsedList[ClientSighting]:
        self.calls.append(f"clients:{site_id}")
        return parse.parse_clients(load("stat_sta.json"))


class FixedClock:
    def now(self) -> datetime:
        return datetime(2026, 10, 10, 12, 0, tzinfo=UTC)


def test_list_sites_counts_access_points_per_site() -> None:
    api = FixtureApi()
    overview = list_sites(api)
    assert [(s.site.id, s.access_point_count, s.unparsable_count) for s in overview.sites] == [
        ("default", 4, 0),
        ("site-2", 4, 0),
    ]
    assert overview.problems == () and api.calls == ["sites", "devices:default", "devices:site-2"]


def test_resolve_site_by_id_hidden_id_or_description_and_reject_ambiguity() -> None:
    api = FixtureApi()
    assert resolve_site(api, "site-2").id == "site-2"
    assert resolve_site(api, "Site-1").id == "default"
    assert resolve_site(api, "default").id == "default"
    with pytest.raises(ConfigError, match="no site 'nope'"):
        resolve_site(api, "nope")

    class Ambiguous(FixtureApi):
        def sites(self) -> ParsedList[Site]:
            site = Site(id="a", description="Same", hidden_id=None, device_count=0)
            other = Site(id="b", description="Same", hidden_id=None, device_count=0)
            return ParsedList(items=(site, other), problems=())

    with pytest.raises(ConfigError, match="more than one site"):
        resolve_site(Ambiguous(), "Same")

    class Hidden(FixtureApi):
        def sites(self) -> ParsedList[Site]:
            return ParsedList(
                items=(Site(id="abc123", description="Home", hidden_id="home-hidden", device_count=1),), problems=()
            )

    assert resolve_site(Hidden(), "home-hidden").id == "abc123"
    assert resolve_site(Hidden(), "abc123").id == "abc123" and resolve_site(Hidden(), "Home").id == "abc123"


def test_show_site_reads_devices_and_wlans_and_mgmt_only_on_request() -> None:
    api = FixtureApi()
    overview = show_site(api, "default")
    assert [ap.name for ap in overview.access_points] == ["AP-1", "AP-2", "AP-3", "AP-4"]
    assert len(overview.wlans) == 5 and overview.mgmt is None and overview.problems == ()
    assert api.calls == ["sites", "devices:default", "wlans:default"]
    with_mgmt = show_site(FixtureApi(), "default", with_mgmt=True)
    assert with_mgmt.mgmt is not None and with_mgmt.mgmt.ssh_user == "fixture-ssh-user"


def test_build_snapshot_collects_every_endpoint_and_problem() -> None:
    api = FixtureApi()
    site = Site(id="default", description="Site-1", hidden_id="default", device_count=11)
    snapshot = build_snapshot(api, site, FixedClock(), with_clients=True)
    assert snapshot.captured_at == datetime(2026, 10, 10, 12, 0, tzinfo=UTC)
    assert len(snapshot.access_points) == 4 and len(snapshot.wlans) == 5 and len(snapshot.ap_groups) == 1
    assert snapshot.settings.country_code == 276 and snapshot.mgmt is not None
    assert snapshot.clients is not None and len(snapshot.clients) == 26 and snapshot.problems == ()
    assert snapshot.bssids.lookup(snapshot.access_points[0].vaps[0].bssid) == (
        snapshot.access_points[0].mac,
        snapshot.access_points[0].vaps[0].band,
    )
    without = build_snapshot(api, site, FixedClock(), with_clients=False)
    assert without.clients is None and "clients:default" in api.calls and api.calls.count("clients:default") == 1


def test_build_snapshot_carries_client_problems_only_when_clients_were_read() -> None:
    problem = FieldProblem("$.data[0].signal", "out of range")

    class Flawed(FixtureApi):
        def clients(self, site_id: str) -> ParsedList[ClientSighting]:
            return ParsedList(items=(), problems=(problem,))

    site = Site(id="default", description="Site-1", hidden_id="default", device_count=11)
    assert problem in build_snapshot(Flawed(), site, FixedClock(), with_clients=True).problems
    assert problem not in build_snapshot(Flawed(), site, FixedClock(), with_clients=False).problems
