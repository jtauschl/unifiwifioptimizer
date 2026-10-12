"""Builders for analysis tests: the anonymised four-AP site plus synthetic scans.

Fixture facts the tests lean on (tests/fixtures/stat_device.json): AP-1 runs both radios in `auto` with stale
configured powers (2.4 GHz configured 6 / observed 17, 5 GHz 19 / 20, channels 6 and 44); AP-2 is Custom at
6 / 24 dBm with the 5 GHz radio capped at 18 dBm (channel 60, DFS); AP-3 is Custom 11 / 23 (channels 6 and
104, DFS); AP-4 is Custom 10 / 24 capped at 18 (channels 11 and 40). Every radio reports min 6 dBm, max 23
or 24 dBm. Each AP broadcasts one VAP per band.
"""

import json
from collections.abc import Mapping, Sequence
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from unifiwifioptimizer.adapters.unifi import parse
from unifiwifioptimizer.config.profiles import shipped_profiles
from unifiwifioptimizer.domain.models import AccessPoint, Band, Radio, RadioStats, SiteSnapshot
from unifiwifioptimizer.domain.scan import (
    ApScan,
    BandScan,
    BandScanStatus,
    ScanFailure,
    ScanMeta,
    ScanPass,
    ScanReading,
    SiteScan,
)
from unifiwifioptimizer.rf.channels import center_frequency_mhz

if TYPE_CHECKING:
    from unifiwifioptimizer.analysis.inputs import SiteAnalysisInput

FIXTURES = Path(__file__).parents[2] / "fixtures"
PROFILES = shipped_profiles()
SITE_ID = "default"


def fixture(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text())


def fixture_snapshot(*, clients: bool = False, extra_devices: list[dict[str, Any]] | None = None) -> SiteSnapshot:
    devices_payload = fixture("stat_device.json")
    if extra_devices:
        devices_payload = {**devices_payload, "data": [*devices_payload["data"], *extra_devices]}
    devices = parse.parse_devices(devices_payload)
    wlans = parse.parse_wlans(fixture("list_wlanconf.json"))
    groups = parse.parse_ap_groups(fixture("apgroups.json"))
    settings = parse.parse_settings(fixture("rest_setting.json"))
    sta = parse.parse_clients(fixture("stat_sta.json")) if clients else None
    sites = parse.parse_sites(fixture("sites.json"))
    return SiteSnapshot(
        site=sites.items[0],
        captured_at=datetime(2026, 10, 12, 20, 0, tzinfo=UTC),
        access_points=devices.access_points,
        unparsable_devices=devices.unparsable,
        wlans=wlans.items,
        ap_groups=groups.items,
        settings=settings.settings,
        mgmt=settings.mgmt,
        clients=sta.items if sta is not None else None,
        problems=devices.problems + wlans.problems + groups.problems + settings.problems,
    )


def ap_named(snapshot: SiteSnapshot, name: str) -> AccessPoint:
    return next(ap for ap in snapshot.access_points if ap.name == name)


def with_ap(snapshot: SiteSnapshot, ap: AccessPoint) -> SiteSnapshot:
    """The snapshot with `ap` replacing the access point of the same MAC."""
    aps = tuple(ap if existing.mac == ap.mac else existing for existing in snapshot.access_points)
    return replace(snapshot, access_points=aps)


def with_radio(ap: AccessPoint, band: Band, **overrides: Any) -> AccessPoint:
    radios = tuple(replace(r, **overrides) if r.band is band else r for r in ap.radios)
    return replace(ap, radios=radios)


def with_stats(ap: AccessPoint, band: Band, **overrides: Any) -> AccessPoint:
    stats = tuple(replace(s, **overrides) if s.band is band else s for s in ap.radio_stats)
    return replace(ap, radio_stats=stats)


def without_stats(ap: AccessPoint, band: Band) -> AccessPoint:
    return replace(ap, radio_stats=tuple(s for s in ap.radio_stats if s.band is not band))


def bssid_of(ap: AccessPoint, band: Band) -> str:
    return next(v.bssid for v in ap.vaps if v.band is band)


def reading(snapshot: SiteSnapshot, heard_ap: str, band: Band, rssi: int, frequency: int | None = -1) -> ScanReading:
    """A reading of `heard_ap`'s BSSID on `band`; the frequency defaults to that AP's current primary channel."""
    ap = ap_named(snapshot, heard_ap)
    if frequency == -1:
        stats = ap.stats(band)
        frequency = center_frequency_mhz(band, stats.channel) if stats is not None else None
    return ScanReading(bssid=bssid_of(ap, band), rssi_dbm=rssi, frequency_mhz=frequency, ssid="SSID-1")


def foreign(band: Band, rssi: int, channel: int, n: int = 1) -> ScanReading:
    return ScanReading(
        bssid=f"02:00:00:00:ff:{n:02x}", rssi_dbm=rssi, frequency_mhz=center_frequency_mhz(band, channel), ssid=None
    )


def band_scan(
    band: Band, readings: tuple[ScanReading, ...] = (), status: BandScanStatus = BandScanStatus.OK
) -> BandScan:
    return BandScan(band=band, status=status, readings=readings, interface="ra0" if band is Band.GHZ_2 else "rai0")


def scan_pass(two: BandScan | None = None, five: BandScan | None = None, cac: str | None = None) -> ScanPass:
    bands = tuple(b for b in (two or band_scan(Band.GHZ_2), five or band_scan(Band.GHZ_5)))
    return ScanPass(bands=bands, meta=ScanMeta(model_name="U7-Lite", dfs_cac_5g=cac, watchdog="timeout"))


def site_scan(
    snapshot: SiteSnapshot, passes: Mapping[str, Sequence[ScanPass | ScanFailure]], unknown: tuple[str, ...] = ()
) -> SiteScan:
    """`passes` keyed by AP name; an AP not in the mapping has no scan entry at all."""
    scans = tuple(
        ApScan(ap_mac=ap_named(snapshot, name).mac, ap_name=name, passes=tuple(ap_passes))
        for name, ap_passes in passes.items()
    )
    return SiteScan(site_id=SITE_ID, scans=scans, unknown_names=unknown)


def hears(snapshot: SiteSnapshot, scanner: str, **heard: dict[Band, int]) -> ScanPass:
    """One pass of `scanner` in which it heard the named APs at the given RSSI per band; both bands `ok`."""
    two = tuple(
        reading(snapshot, ap, Band.GHZ_2, levels[Band.GHZ_2]) for ap, levels in heard.items() if Band.GHZ_2 in levels
    )
    five = tuple(
        reading(snapshot, ap, Band.GHZ_5, levels[Band.GHZ_5]) for ap, levels in heard.items() if Band.GHZ_5 in levels
    )
    return scan_pass(band_scan(Band.GHZ_2, two), band_scan(Band.GHZ_5, five))


def radio_of(ap: AccessPoint, band: Band) -> Radio:
    radio = ap.radio(band)
    assert radio is not None
    return radio


def stats_of(ap: AccessPoint, band: Band) -> RadioStats:
    stats = ap.stats(band)
    assert stats is not None
    return stats


def golden_input(*, clients: bool = False, skip_scan: bool = False) -> "SiteAnalysisInput":
    """The anonymised four-AP site with a synthetic three-pass scan: the chain AP-1 — AP-2 — AP-3 — AP-4, every
    pair heard in both directions on both bands except AP-3 at AP-4 on 5 GHz (missed both ways), AP-4's 2.4 GHz
    band `empty` in every pass, plus a few foreign BSSs. Deterministic, so the golden files are stable."""
    from unifiwifioptimizer.analysis.inputs import SiteAnalysisInput
    from unifiwifioptimizer.rf.corridor import PathLossModel
    from unifiwifioptimizer.rf.settings import RfSettings

    snap = fixture_snapshot(clients=clients)
    levels = {
        ("AP-1", "AP-2"): (-70, -72),
        ("AP-2", "AP-1"): (-69, -71),
        ("AP-2", "AP-3"): (-74, -68),
        ("AP-3", "AP-2"): (-75, -69),
        ("AP-3", "AP-4"): (-66, None),
        ("AP-4", "AP-3"): (-77, None),
    }
    passes: dict[str, list[ScanPass | ScanFailure]] = {}
    for index in range(3):
        for scanner in ("AP-1", "AP-2", "AP-3", "AP-4"):
            two: list[ScanReading] = [foreign(Band.GHZ_2, -60 - index, 1 if scanner != "AP-2" else 6, 1)]
            five: list[ScanReading] = [foreign(Band.GHZ_5, -75, 100, 2)]
            for (subject, peer), (rssi_2g, rssi_5g) in levels.items():
                if peer != scanner:
                    continue
                if rssi_2g is not None:
                    two.append(reading(snap, subject, Band.GHZ_2, rssi_2g + (index - 1)))
                if rssi_5g is not None:
                    five.append(reading(snap, subject, Band.GHZ_5, rssi_5g + (index - 1)))
            if scanner == "AP-4":
                passes.setdefault(scanner, []).append(
                    scan_pass(band_scan(Band.GHZ_2, (), BandScanStatus.EMPTY), band_scan(Band.GHZ_5, tuple(five)))
                )
            else:
                passes.setdefault(scanner, []).append(
                    scan_pass(band_scan(Band.GHZ_2, tuple(two)), band_scan(Band.GHZ_5, tuple(five)))
                )
    neighbours = {"AP-1": frozenset({"AP-2"}), "AP-2": frozenset({"AP-3"}), "AP-3": frozenset({"AP-4"})}
    return SiteAnalysisInput(
        snapshot=snap,
        scan=None if skip_scan else site_scan(snap, passes),
        scan_skipped=skip_scan,
        neighbours=neighbours,
        environment=PathLossModel.from_preset("Residential"),
        rf=RfSettings(),
        scan_passes=3,
        wlan_profiles={"SSID-1": "Throughput", "SSID-2": "Standard", "SSID-3": "Hotspot"},
        profiles=PROFILES,
    )
