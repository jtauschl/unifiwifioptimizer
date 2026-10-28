"""The `run` use case: site selection, the pre-scan order, the verdict reduction, scanning only after every
credential is resolved, the n6 error text, and two sites with two corridors."""

import json
from collections.abc import Mapping
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from unifiwifioptimizer.adapters.unifi import parse
from unifiwifioptimizer.app.run import RunResult, RunVerdict, SiteOutcome, run_analysis, select_sites
from unifiwifioptimizer.config.load import LoadedConfig
from unifiwifioptimizer.config.locations import ConfigLocation
from unifiwifioptimizer.config.schema import Config
from unifiwifioptimizer.domain.analysis import PartialReason
from unifiwifioptimizer.domain.errors import (
    ConfigError,
    HostKeyUnknownError,
    ScanError,
    ScanTimeoutError,
    SshAuthenticationError,
    ToolEnvironmentError,
)
from unifiwifioptimizer.domain.models import (
    ApGroup,
    ClientSighting,
    DevicesResult,
    Network,
    ParsedList,
    SettingsResult,
    Site,
    WlanConfig,
)
from unifiwifioptimizer.domain.scan import ScanFailure, ScanPass, ScanTarget
from unifiwifioptimizer.domain.secrets import Secret

from ..analysis.builders import PROFILES, hears, scan_pass

FIXTURES = Path(__file__).parents[2] / "fixtures"


def load(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text())


class FakeApi:
    """The fixture controller with two sites; `calls` records the endpoint order."""

    def __init__(self, devices_payload: Any | None = None, mgmt_user: str | None = None) -> None:
        self.calls: list[str] = []
        self._devices = devices_payload if devices_payload is not None else load("stat_device.json")
        self._mgmt_user = mgmt_user

    def sites(self) -> ParsedList[Site]:
        self.calls.append("sites")
        return parse.parse_sites(load("sites.json"))

    def devices(self, site_id: str) -> DevicesResult:
        self.calls.append(f"devices:{site_id}")
        return parse.parse_devices(self._devices)

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
        payload = load("rest_setting.json")
        if self._mgmt_user is not None:
            for record in payload["data"]:
                if record.get("key") == "mgmt":
                    record["x_ssh_username"] = self._mgmt_user
        return parse.parse_settings(payload)

    def clients(self, site_id: str) -> ParsedList[ClientSighting]:
        self.calls.append(f"clients:{site_id}")
        return parse.parse_clients(load("stat_sta.json"))


class FakeScanner:
    def __init__(self, failures: Mapping[str, ScanError] | None = None, api: FakeApi | None = None) -> None:
        self.calls: list[str] = []
        self.failures = failures or {}
        self._api = api

    def scan(self, target: ScanTarget) -> ScanPass:
        self.calls.append(target.ap_name)
        if self._api is not None:
            self._api.calls.append(f"scan:{target.ap_name}")
        error = self.failures.get(target.ap_name)
        if error is not None:
            raise error
        return scan_pass()


class RecordingProgress:
    def __init__(self) -> None:
        self.events: list[tuple[str, ...]] = []

    def site_started(self, site_id: str, scanning: bool) -> None:
        self.events.append(("site", site_id, str(scanning)))

    def scan_started(self, ap_name: str, pass_index: int, passes: int) -> None:
        self.events.append(("scan", ap_name, str(pass_index), str(passes)))

    def scan_finished(self, ap_name: str, outcome: ScanPass | ScanFailure) -> None:
        self.events.append(("done", ap_name, type(outcome).__name__))

    def analysis_started(self, site_id: str) -> None:
        self.events.append(("analysis", site_id))


class FixedClock:
    def now(self) -> datetime:
        return datetime(2026, 10, 12, 21, 0, tzinfo=UTC)


NEIGHBOURS = {"AP-1": ["AP-2"], "AP-2": ["AP-3"], "AP-3": ["AP-4"]}


def loaded(sites: dict[str, dict[str, Any]] | None = None, env_password: str | None = None) -> LoadedConfig:
    document = {"controller": {"url": "https://unifi.example", "api_key": "k"}, "sites": sites or {}}
    return LoadedConfig(
        config=Config.from_mapping(document),
        location=ConfigLocation(Path("/cfg/config.yaml"), legacy=False),
        env_ssh_password=Secret(env_password) if env_password else None,
    )


def scanning_site(**overrides: Any) -> dict[str, Any]:
    return {"ssh": {}, "neighbors": NEIGHBOURS, "scan_passes": 1, "wlans": {"SSID-1": "Standard"}, **overrides}


def run(
    cfg: LoadedConfig,
    api: FakeApi | None = None,
    scanner: FakeScanner | None = None,
    **kwargs: Any,
) -> tuple[RunResult, FakeApi, FakeScanner, RecordingProgress]:
    api = api or FakeApi()
    scanner = scanner or FakeScanner(api=api)
    progress = RecordingProgress()
    result = run_analysis(cfg, PROFILES, api, lambda: scanner, FixedClock(), lambda s: None, progress, **kwargs)
    return result, api, scanner, progress


# --- selection and the pre-scan order -------------------------------------------------------------------------


def test_sites_are_selected_by_configured_id_and_nothing_else() -> None:
    cfg = loaded({"default": scanning_site(), "site-2": {"wlans": {"SSID-1": "Standard"}}})
    assert [s.id for s in select_sites(cfg, None)] == ["default", "site-2"]
    assert [s.id for s in select_sites(cfg, ["site-2", "site-2"])] == ["site-2"]
    with pytest.raises(ConfigError, match="not a configured site id"):
        select_sites(cfg, ["Site-1"])
    with pytest.raises(ConfigError, match="no site configured"):
        select_sites(loaded({}), None)


@pytest.mark.security("T19")
def test_the_environment_is_checked_before_the_passwords_and_only_when_a_site_scans() -> None:
    cfg = loaded({"default": scanning_site(ssh={"auth": "password", "user": "u"})})
    order: list[str] = []

    def broken_environment() -> None:
        order.append("environment")
        raise ToolEnvironmentError("ssh too old")

    with pytest.raises(ToolEnvironmentError):
        run(cfg, environment_check=broken_environment)
    # Both faults present: the environment fails first (priority 7 over 3).
    assert order == ["environment"]
    with pytest.raises(ConfigError, match="UNIFI_SSH_PASSWORD"):
        run(cfg, environment_check=lambda: order.append("ok"))
    # A site that does not scan triggers neither check.
    quiet = loaded({"default": {"wlans": {"SSID-1": "Standard"}}})
    result, api, scanner, _ = run(quiet, environment_check=broken_environment)
    assert result.verdict is RunVerdict.OK and scanner.calls == [] and "scan:AP-1" not in api.calls
    # `--no-scan` skips both checks as well.
    result, _, scanner, _ = run(cfg, skip_scan=True, environment_check=broken_environment)
    assert scanner.calls == [] and result.reports[0].scan.skipped


def test_every_site_is_resolved_read_and_prepared_before_the_first_scan() -> None:
    cfg = loaded({"default": scanning_site(), "site-2": scanning_site()})
    result, api, _, progress = run(cfg)
    first_scan = api.calls.index("scan:AP-1")
    reads = list(api.calls[:first_scan])
    assert any(c.startswith("devices:site-2") for c in reads) and any(c.startswith("settings:site-2") for c in reads)
    assert all(not c.startswith("scan:") for c in reads)
    # Sites run serially in configuration order; the scan of site-2 starts only after site 1 is analysed.
    assert [e for e in progress.events if e[0] in ("site", "analysis")] == [
        ("site", "default", "True"),
        ("analysis", "default"),
        ("site", "site-2", "True"),
        ("analysis", "site-2"),
    ]
    assert [r.site_id for r in result.reports] == ["default", "site-2"]
    assert ("scan", "AP-1", "0", "1") in progress.events and ("done", "AP-1", "ScanPass") in progress.events


def test_a_configured_name_shared_by_two_access_points_is_refused_before_any_scan() -> None:
    payload = load("stat_device.json")
    twin = next(d for d in payload["data"] if d["type"] == "uap")
    payload["data"].append({**twin, "mac": "02:00:00:00:00:77", "_id": "000000000000000000000077"})
    cfg = loaded({"default": scanning_site()})
    with pytest.raises(ConfigError, match="share a configured name"):
        run(cfg, api=FakeApi(devices_payload=payload))
    # The rule is about the configuration, not about scanning: `--no-scan` refuses it as well.
    with pytest.raises(ConfigError, match="share a configured name"):
        run(cfg, api=FakeApi(devices_payload=payload), skip_scan=True)


def test_only_the_selected_scanning_sites_need_a_scan_password() -> None:
    cfg = loaded({"default": scanning_site(), "site-2": scanning_site(ssh={"auth": "password", "user": "u"})})
    with pytest.raises(ConfigError, match="UNIFI_SSH_PASSWORD"):
        run(cfg)
    result, _, scanner, _ = run(cfg, sites=["default"])
    assert [r.site_id for r in result.reports] == ["default"] and scanner.calls == ["AP-1", "AP-2", "AP-3", "AP-4"]


def test_a_rejected_controller_ssh_user_is_named_as_such() -> None:
    cfg = loaded({"default": scanning_site()})
    with pytest.raises(ConfigError, match="SSH user was rejected"):
        run(cfg, api=FakeApi(mgmt_user="ad min"))


# --- the verdict table ----------------------------------------------------------------------------------------


def outcome(**overrides: Any) -> SiteOutcome:
    values: dict[str, Any] = {
        "site_id": "default",
        "scanning": True,
        "partial_reasons": (),
        "scanned_ap_count": 4,
        "verifiable_ap_count": 4,
        "host_key_failed_ap_count": 0,
    }
    values.update(overrides)
    return SiteOutcome(**values)


@pytest.mark.parametrize(
    ("outcomes", "verdict"),
    [
        ([outcome()], RunVerdict.OK),
        ([outcome(partial_reasons=(PartialReason.BAND_EMPTY,))], RunVerdict.PARTIAL),
        (
            [outcome(verifiable_ap_count=0, host_key_failed_ap_count=4, partial_reasons=(PartialReason.SCAN_FAILED,))],
            RunVerdict.NO_VERIFIABLE_AP,
        ),
        # Host key plus timeout, nobody verified: still the host-key code.
        (
            [outcome(verifiable_ap_count=0, host_key_failed_ap_count=1, partial_reasons=(PartialReason.SCAN_FAILED,))],
            RunVerdict.NO_VERIFIABLE_AP,
        ),
        # Every access point timed out: a scan failure, not a host-key problem.
        (
            [outcome(verifiable_ap_count=0, host_key_failed_ap_count=0, partial_reasons=(PartialReason.SCAN_FAILED,))],
            RunVerdict.PARTIAL,
        ),
        # One host-key failure among verified access points is partial, not 5.
        (
            [outcome(verifiable_ap_count=3, host_key_failed_ap_count=1, partial_reasons=(PartialReason.SCAN_FAILED,))],
            RunVerdict.PARTIAL,
        ),
        # One access point verified (its key matched before a later pass failed), three host-key failures: 6.
        (
            [outcome(verifiable_ap_count=1, host_key_failed_ap_count=3, partial_reasons=(PartialReason.SCAN_FAILED,))],
            RunVerdict.PARTIAL,
        ),
        # A scanning site whose members are all offline or unknown scanned nobody.
        (
            [outcome(scanned_ap_count=0, verifiable_ap_count=0, partial_reasons=(PartialReason.AP_NOT_FOUND,))],
            RunVerdict.PARTIAL,
        ),
        ([outcome(scanning=False, scanned_ap_count=0, verifiable_ap_count=0)], RunVerdict.OK),
        (
            [outcome(), outcome(site_id="b", verifiable_ap_count=0, host_key_failed_ap_count=1)],
            RunVerdict.NO_VERIFIABLE_AP,
        ),
    ],
)
def test_the_verdict_reduction(outcomes: list[SiteOutcome], verdict: RunVerdict) -> None:
    assert RunResult(reports=(), outcomes=tuple(outcomes)).verdict is verdict


@given(
    st.permutations(
        [
            outcome(),
            outcome(site_id="b", partial_reasons=(PartialReason.BAND_EMPTY,)),
            outcome(site_id="c", verifiable_ap_count=0, host_key_failed_ap_count=2),
        ]
    )
)
def test_the_verdict_is_independent_of_the_site_order(outcomes: list[SiteOutcome]) -> None:
    assert RunResult(reports=(), outcomes=tuple(outcomes)).verdict is RunVerdict.NO_VERIFIABLE_AP


@pytest.mark.security("T7")
def test_host_key_failures_everywhere_give_no_verifiable_access_point_and_timeouts_give_partial() -> None:
    cfg = loaded({"default": scanning_site()})
    unknown = {name: HostKeyUnknownError(f"{name}: no key") for name in ("AP-1", "AP-2", "AP-3", "AP-4")}
    result, *_ = run(cfg, scanner=FakeScanner(unknown))
    assert result.verdict is RunVerdict.NO_VERIFIABLE_AP and result.outcomes[0].host_key_failed_ap_count == 4
    mixed = {**unknown, "AP-2": ScanTimeoutError("AP-2: slow")}
    assert run(cfg, scanner=FakeScanner(mixed))[0].verdict is RunVerdict.NO_VERIFIABLE_AP
    timeouts = {name: ScanTimeoutError(f"{name}: slow") for name in unknown}
    timed_out, *_ = run(cfg, scanner=FakeScanner(timeouts))
    assert timed_out.verdict is RunVerdict.PARTIAL and timed_out.outcomes[0].verifiable_ap_count == 0
    # An authentication failure happens after the host key matched: the access point counts as verified.
    authenticated = {name: SshAuthenticationError(f"{name}: denied") for name in unknown}
    assert run(cfg, scanner=FakeScanner(authenticated))[0].outcomes[0].verifiable_ap_count == 4


def test_offline_access_points_are_not_scanned_and_do_not_make_the_run_partial() -> None:
    payload = load("stat_device.json")
    for device in payload["data"]:
        if device["type"] == "uap":
            device["state"] = 0
    cfg = loaded({"default": scanning_site()})
    result, _, scanner, _ = run(cfg, api=FakeApi(devices_payload=payload))
    assert scanner.calls == [] and result.outcomes[0].scanned_ap_count == 0
    assert result.verdict is RunVerdict.OK and PartialReason.SCAN_FAILED not in result.outcomes[0].partial_reasons


def test_multi_site_tx_lo_isolation() -> None:
    # Each site aggregates with its own corridor.
    cfg = loaded(
        {
            "default": scanning_site(environment="Open"),
            "site-2": scanning_site(environment="Obstructed"),
        }
    )
    result, *_ = run(cfg, skip_scan=True)
    by_site = {r.site_id: r for r in result.reports}
    from unifiwifioptimizer.domain.models import Band

    assert by_site["default"].corridors[Band.GHZ_2].low_dbm == -72
    assert by_site["site-2"].corridors[Band.GHZ_2].low_dbm == -76
    assert by_site["default"].corridors[Band.GHZ_5].low_dbm == by_site["site-2"].corridors[Band.GHZ_5].low_dbm == -67


def test_clients_are_read_only_on_request() -> None:
    cfg = loaded({"default": scanning_site()})
    _, api, _, _ = run(cfg, skip_scan=True)
    assert not any(c.startswith("clients:") for c in api.calls)
    result, api, _, _ = run(cfg, skip_scan=True, with_clients=True)
    assert "clients:default" in api.calls and result.reports[0].aps


def test_a_scanning_run_feeds_the_matrix_and_reports_what_the_scanner_heard() -> None:
    cfg = loaded({"default": scanning_site(scan_passes=2)})
    api = FakeApi()

    class Hearing(FakeScanner):
        def scan(self, target: ScanTarget) -> ScanPass:
            self.calls.append(target.ap_name)
            snapshot_devices = parse.parse_devices(load("stat_device.json")).access_points
            from datetime import UTC as _UTC

            from unifiwifioptimizer.domain.models import SiteSnapshot

            snap = SiteSnapshot(
                site=Site(id="default", description="d", hidden_id=None, device_count=None),
                captured_at=datetime.now(_UTC),
                access_points=snapshot_devices,
                unparsable_devices=(),
                wlans=(),
                ap_groups=(),
                networks=(),
                settings=parse.parse_settings(load("rest_setting.json")).settings,
                mgmt=None,
                clients=None,
                problems=(),
            )
            peers = {p for a, ps in NEIGHBOURS.items() for p in ([a, *ps] if target.ap_name in (a, *ps) else [])}
            heard = {p: {Band.GHZ_2: -70, Band.GHZ_5: -70} for p in peers if p != target.ap_name}
            return hears(snap, target.ap_name, **heard)

    from unifiwifioptimizer.domain.models import Band

    result, _, scanner, _ = run(cfg, api=api, scanner=Hearing(api=api))
    assert scanner.calls == ["AP-1", "AP-2", "AP-3", "AP-4"] * 2
    report = result.reports[0]
    assert report.scan.passes == 2 and report.scan.successes_by_ap == {"AP-1": 2, "AP-2": 2, "AP-3": 2, "AP-4": 2}
    one_2g = next(b for ap in report.aps for b in ap.bands if ap.name == "AP-1" and b.band is Band.GHZ_2)
    assert one_2g.neighbours and one_2g.neighbours[0].rssi_dbm == -70 and one_2g.neighbours[0].samples == 2
    assert result.verdict is RunVerdict.OK
    assert replace(result.outcomes[0], site_id="x").scanned_ap_count == 4
