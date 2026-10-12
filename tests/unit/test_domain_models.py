import dataclasses
from datetime import UTC, datetime
from ipaddress import ip_address

import pytest

from unifiwifioptimizer.domain.models import (
    AccessPoint,
    Band,
    BssidIndex,
    ChannelAiSettings,
    DeviceState,
    Radio,
    RadioStats,
    Site,
    SiteSettings,
    SiteSnapshot,
    TxPowerMode,
    Vap,
)


def test_band_values_and_labels() -> None:
    assert [(b.value, b.label) for b in Band] == [("2g", "2.4 GHz"), ("5g", "5 GHz"), ("6g", "6 GHz")]


def radio(band: Band, channel: int) -> Radio:
    return Radio(
        band=band,
        interface_name="ra0",
        channel=channel,
        width_mhz=20,
        configured_tx_dbm=6,
        tx_power_mode=TxPowerMode.CUSTOM,
        min_tx_dbm=6,
        max_tx_dbm=23,
        min_rssi_enabled=False,
        min_rssi_dbm=None,
        antenna_gain_dbi=3,
        spatial_streams=2,
        dfs_capable=None,
    )


def stats(band: Band, observed_tx: int) -> RadioStats:
    return RadioStats(
        band=band,
        channel=1,
        width_mhz=20,
        extension_channel=0,
        observed_tx_dbm=observed_tx,
        channel_utilisation_pct=None,
        self_rx_utilisation_pct=None,
        self_tx_utilisation_pct=None,
        tx_retries_pct=None,
        satisfaction_pct=None,
        state="RUN",
        client_count=None,
    )


def vap(band: Band, bssid: str) -> Vap:
    return Vap(
        band=band,
        bssid=bssid,
        essid="SSID-1",
        channel=1,
        width_mhz=20,
        up=True,
        wlan_id=None,
        is_guest=False,
        client_count=None,
    )


def access_point(mac: str, bands: tuple[Band, ...]) -> AccessPoint:
    return AccessPoint(
        mac=mac,
        name="AP",
        ip=ip_address("192.0.2.1"),
        model="UAL6",
        firmware=None,
        state_code=1,
        uplink_type="wire",
        uplink_mac="02:00:00:00:00:03",
        radios=tuple(radio(b, 1) for b in bands),
        radio_stats=tuple(stats(b, 10) for b in bands),
        vaps=tuple(vap(b, f"02:00:00:00:{i:02x}:{mac[-2:]}") for i, b in enumerate(bands, start=1)),
        ssh_host_key_fingerprint=None,
    )


def test_access_point_looks_up_radio_and_stats_by_band() -> None:
    ap = access_point("02:00:00:00:00:01", (Band.GHZ_2, Band.GHZ_5))
    assert ap.bands == {Band.GHZ_2, Band.GHZ_5}
    without_stats = AccessPoint(
        mac=ap.mac, name=ap.name, ip=ap.ip, model=ap.model, firmware=None, state_code=None, uplink_type=None,
        uplink_mac=None, radios=(*ap.radios, radio(Band.GHZ_6, 5)), radio_stats=(stats(Band.GHZ_2, 6),), vaps=(),
        ssh_host_key_fingerprint=None,
    )  # fmt: skip
    assert without_stats.bands == {Band.GHZ_2, Band.GHZ_5, Band.GHZ_6}
    stats_only = AccessPoint(
        mac=ap.mac, name=ap.name, ip=ap.ip, model=ap.model, firmware=None, state_code=4, uplink_type=None,
        uplink_mac=None, radios=(radio(Band.GHZ_2, 1),), radio_stats=(stats(Band.GHZ_5, 10),), vaps=(),
        ssh_host_key_fingerprint=None,
    )  # fmt: skip
    assert stats_only.bands == {Band.GHZ_2}
    assert ap.radio(Band.GHZ_5) is ap.radios[1]
    assert ap.stats(Band.GHZ_2) is ap.radio_stats[0]


def test_only_an_explicit_disconnected_state_is_offline() -> None:
    connected = access_point("02:00:00:00:00:01", (Band.GHZ_2,))
    assert connected.state is DeviceState.CONNECTED and connected.offline is False
    for code, state in ((0, DeviceState.DISCONNECTED), (4, DeviceState.OTHER), (11, DeviceState.OTHER)):
        ap = dataclasses.replace(connected, state_code=code)
        assert ap.state is state and ap.offline is (code == 0)
    # An older controller without the field: analysed normally, never called offline.
    absent = dataclasses.replace(connected, state_code=None)
    assert absent.state is None and absent.offline is False
    assert ap.radio(Band.GHZ_6) is None
    assert ap.stats(Band.GHZ_6) is None


def test_bssid_index_maps_every_vap_to_its_access_point_and_band() -> None:
    first = access_point("02:00:00:00:00:01", (Band.GHZ_2, Band.GHZ_5))
    second = access_point("02:00:00:00:00:02", (Band.GHZ_5,))
    index = BssidIndex.from_access_points((first, second))
    assert index.lookup(first.vaps[1].bssid) == (first.mac, Band.GHZ_5)
    assert index.lookup(second.vaps[0].bssid) == (second.mac, Band.GHZ_5)
    assert index.lookup("02:00:00:00:ff:ff") is None
    assert index.bssids_of(first.mac, Band.GHZ_2) == {first.vaps[0].bssid}
    assert index.bssids_of(second.mac, Band.GHZ_2) == frozenset()


def test_snapshot_exposes_the_bssid_index_and_distinguishes_uncollected_clients() -> None:
    ap = access_point("02:00:00:00:00:01", (Band.GHZ_2,))
    snapshot = SiteSnapshot(
        site=Site(id="default", description="Site-1", hidden_id=None, device_count=1),
        captured_at=datetime(2026, 1, 1, tzinfo=UTC),
        access_points=(ap,),
        unparsable_devices=(),
        wlans=(),
        ap_groups=(),
        settings=SiteSettings(country_code=276, channel_ai=None, mlo_mesh_enabled=None, outdoor_mode_enabled=None),
        mgmt=None,
        clients=None,
        problems=(),
    )
    assert snapshot.clients is None and snapshot.problems == ()
    assert snapshot.bssids.lookup(ap.vaps[0].bssid) == (ap.mac, Band.GHZ_2)


def test_mapping_fields_are_read_only_even_when_constructed_from_a_live_dict() -> None:
    entries = {"02:00:00:00:00:05": ("02:00:00:00:00:01", Band.GHZ_2)}
    index = BssidIndex(entries=entries)
    entries["02:00:00:00:ff:ff"] = ("x", Band.GHZ_2)
    assert "02:00:00:00:ff:ff" not in index.entries
    with pytest.raises(TypeError):
        index.entries["02:00:00:00:ff:ff"] = ("x", Band.GHZ_2)  # type: ignore[index]
    channels = {Band.GHZ_2: frozenset({1})}
    widths = {Band.GHZ_2: frozenset({20})}
    ai = ChannelAiSettings(
        enabled=True, auto_enabled=None, optimize=frozenset(), cron_expr=None, channels=channels,
        width_candidates_mhz=widths, excluded_devices=frozenset(), blacklist=frozenset(),
    )  # fmt: skip
    channels[Band.GHZ_5] = frozenset()
    widths[Band.GHZ_5] = frozenset()
    assert Band.GHZ_5 not in ai.channels and Band.GHZ_5 not in ai.width_candidates_mhz
    with pytest.raises(TypeError):
        ai.width_candidates_mhz[Band.GHZ_2] = frozenset()  # type: ignore[index]


def test_models_are_immutable() -> None:
    ap = access_point("02:00:00:00:00:01", (Band.GHZ_2,))
    with pytest.raises(AttributeError):
        ap.name = "other"  # type: ignore[misc]
