import contextlib
import json
import re
from collections.abc import Callable
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from unifiwifioptimizer.adapters.unifi import parse
from unifiwifioptimizer.adapters.unifi.validate import (
    ANTENNA_GAIN_RANGE,
    CHANNEL_RANGE,
    CLIENT_COUNT_RANGE,
    COUNTRY_RANGE,
    DEVICE_COUNT_RANGE,
    DTIM_RANGE,
    EXTENSION_CHANNEL_RANGE,
    GROUP_REKEY_RANGE,
    MAX_AP_GROUPS,
    MAX_BLACKLIST,
    MAX_CHANNEL_LIST,
    MAX_CLIENTS,
    MAX_DEPTH,
    MAX_DEVICES,
    MAX_RADIOS_PER_DEVICE,
    MAX_SETTINGS,
    MAX_SITES,
    MAX_VAPS_PER_DEVICE,
    MAX_WIDTH_LIST,
    MAX_WLANS,
    MINRATE_KBPS_RANGE,
    NOISE_RANGE,
    PERCENT_RANGE,
    RSSI_RANGE,
    SAE_COUNTER_RANGE,
    SPATIAL_STREAMS_RANGE,
    TX_POWER_RANGE,
    FieldProblem,
    Fields,
)
from unifiwifioptimizer.domain.errors import SchemaError
from unifiwifioptimizer.domain.models import Band, TxPowerMode, UnparsableDevice
from unifiwifioptimizer.domain.secrets import Secret

FIXTURES = Path(__file__).parents[2] / "fixtures"
AP_MAC = "02:00:00:00:00:04"
Payload = dict[str, object]


def fixture(name: str) -> object:
    return json.loads((FIXTURES / name).read_text())


def radio(**overrides: object) -> Payload:
    record: Payload = {
        "radio": "na",
        "name": "rai0",
        "channel": 36,
        "ht": "80",
        "tx_power": 20,
        "tx_power_mode": "custom",
        "min_txpower": 6,
        "max_txpower": 24,
        "min_rssi_enabled": True,
        "min_rssi": -75,
        "antenna_gain": 5,
        "nss": 2,
        "has_dfs": True,
    }
    record.update(overrides)
    return record


def device(**overrides: object) -> Payload:
    record: Payload = {
        "type": "uap",
        "mac": AP_MAC,
        "name": "AP-1",
        "ip": "192.0.2.1",
        "model": "UAL6",
        "version": "6.7.57",
        "uplink": {"type": "wire"},
        "radio_table": [radio()],
        "unknown_field": {"nested": [1, 2, 3]},
    }
    record.update(overrides)
    return record


def envelope(*records: object) -> Payload:
    return {"meta": {"rc": "ok"}, "data": list(records)}


def stats(**overrides: object) -> Payload:
    record: Payload = {"radio": "ng", "channel": 6, "bw": 20, "tx_power": 6, "satisfaction": -1, "extchannel": 0}
    record.update(overrides)
    return record


def vap(**overrides: object) -> Payload:
    record: Payload = {
        "radio": "ng",
        "bssid": "02:00:00:00:00:10",
        "essid": "SSID-2",
        "channel": 6,
        "bw": 20,
        "up": True,
    }
    record.update(overrides)
    return record


def wlan(**overrides: object) -> Payload:
    record: Payload = {"_id": "0" * 24, "name": "SSID-1", "enabled": True, "wlan_bands": ["2g", "5g", "6g"]}
    record.update(overrides)
    return record


def setting(key: str, **fields: object) -> Payload:
    return {"key": key, "_id": "0" * 24, **fields}


def client(**overrides: object) -> Payload:
    record: Payload = {
        "is_wired": False,
        "ap_mac": AP_MAC,
        "radio": "ng",
        "essid": "SSID-1",
        "channel": 6,
        "signal": -60,
        "noise": -95,
        "satisfaction": -1,
        "is_11r": True,
        "mac": "02:00:00:00:00:99",
        "hostname": "phone",
    }
    record.update(overrides)
    return record


# --- fixtures from the live controller -----------------------------------------------------------------


def test_fixture_devices_parse_into_four_access_points_without_problems() -> None:
    result = parse.parse_devices(fixture("stat_device.json"))
    assert result.unparsable == ()
    assert result.problems == ()
    assert [ap.model for ap in result.access_points] == ["UAL6", "UAPA693", "UAL6", "UAPA693"]
    assert [ap.name for ap in result.access_points] == ["AP-1", "AP-2", "AP-3", "AP-4"]
    assert all(ap.bands == {Band.GHZ_2, Band.GHZ_5} for ap in result.access_points)
    assert all(ap.uplink_type == "wire" for ap in result.access_points)


def test_fixture_u7_lite_runs_below_its_configured_5ghz_power() -> None:
    result = parse.parse_devices(fixture("stat_device.json"))
    u7 = result.access_points[1]
    radio_5g = u7.radio(Band.GHZ_5)
    stats_5g = u7.stats(Band.GHZ_5)
    assert radio_5g is not None and stats_5g is not None
    assert (radio_5g.configured_tx_dbm, radio_5g.max_tx_dbm, stats_5g.observed_tx_dbm) == (24, 24, 18)
    assert (radio_5g.channel, radio_5g.width_mhz, stats_5g.extension_channel) == (60, 80, 1)
    assert radio_5g.tx_power_mode is TxPowerMode.CUSTOM
    assert (stats_5g.channel_utilisation_pct, stats_5g.tx_retries_pct, stats_5g.client_count) == (1, 21.3, 4)


def test_fixture_auto_radio_has_no_configured_channel_and_runs_above_its_stale_power() -> None:
    result = parse.parse_devices(fixture("stat_device.json"))
    u6 = result.access_points[0]
    radio_2g, stats_2g, radio_5g, stats_5g = (
        u6.radio(Band.GHZ_2),
        u6.stats(Band.GHZ_2),
        u6.radio(Band.GHZ_5),
        u6.stats(Band.GHZ_5),
    )
    assert radio_2g is not None and stats_2g is not None and radio_5g is not None and stats_5g is not None
    # Live probe 2026-10-10: channel `auto`, width still numeric (an int here), the configured power is the
    # stale custom value while the radio runs 11 dB above it.
    assert (radio_2g.channel, radio_2g.width_mhz, radio_2g.tx_power_mode, radio_2g.configured_tx_dbm) == (
        None,
        20,
        TxPowerMode.AUTO,
        6,
    )
    assert (stats_2g.channel, stats_2g.observed_tx_dbm, stats_2g.state) == (6, 17, "RUN")
    assert (
        radio_5g.channel,
        radio_5g.width_mhz,
        radio_5g.configured_tx_dbm,
        stats_5g.channel,
        stats_5g.observed_tx_dbm,
    ) == (None, 80, 19, 44, 20)
    assert stats_2g.satisfaction_pct is None and stats_5g.extension_channel == 1


def test_fixture_sentinels_and_string_widths_are_normalised() -> None:
    result = parse.parse_devices(fixture("stat_device.json"))
    u7 = result.access_points[1]
    radio_2g, stats_2g = u7.radio(Band.GHZ_2), u7.stats(Band.GHZ_2)
    assert radio_2g is not None and stats_2g is not None
    assert (radio_2g.width_mhz, radio_2g.channel, radio_2g.configured_tx_dbm) == (20, 1, 6)
    assert stats_2g.satisfaction_pct is None and stats_2g.state == "RUN"
    busy = result.access_points[2].stats(Band.GHZ_5)
    assert busy is not None and busy.satisfaction_pct == 96 and busy.extension_channel == -1


def test_fixture_vaps_carry_real_bssids_distinct_from_the_device_mac() -> None:
    result = parse.parse_devices(fixture("stat_device.json"))
    for ap in result.access_points:
        assert len(ap.vaps) == 2
        assert {v.band for v in ap.vaps} == {Band.GHZ_2, Band.GHZ_5}
        assert all(v.bssid != ap.mac and v.up and v.wlan_id is not None and v.essid == "SSID-1" for v in ap.vaps)


def test_fixture_wlans() -> None:
    result = parse.parse_wlans(fixture("list_wlanconf.json"))
    assert result.problems == ()
    assert [(w.name, w.enabled) for w in result.items] == [
        ("SSID-1", True),
        ("SSID-2", False),
        ("SSID-3", False),
        ("SSID-4", False),
        ("SSID-5", False),
    ]
    first = result.items[0]
    assert first.bands == {Band.GHZ_2, Band.GHZ_5}
    assert (first.security, first.wpa_mode, first.pmf_mode) == ("wpapsk", "wpa2", "optional")
    assert (first.minrate_ng_data_rate_kbps, first.dtim_na, first.band_steering) == (12000, 3, True)
    assert first.ap_group_mode == "all" and len(first.ap_group_ids) == 1
    assert (first.roaming_assistant_na_enabled, first.roaming_assistant_na_rssi) == (True, -75)
    assert (result.items[1].roaming_assistant_na_enabled, result.items[1].roaming_assistant_na_rssi) == (False, None)
    assert result.items[2].security == "open" and result.items[2].wpa_mode is None


def test_fixture_ap_groups_bare_list() -> None:
    result = parse.parse_ap_groups(fixture("apgroups.json"))
    assert result.problems == ()
    (group,) = result.items
    assert group.name == "Group-1"
    assert group.device_macs == {"02:00:00:00:00:04", "02:00:00:00:00:08", "02:00:00:00:00:0e", "02:00:00:00:00:11"}


def test_fixture_settings() -> None:
    result = parse.parse_settings(fixture("rest_setting.json"))
    assert result.problems == ()
    assert result.settings.country_code == 276
    assert result.settings.mlo_mesh_enabled is False and result.settings.outdoor_mode_enabled is False
    ai = result.settings.channel_ai
    assert ai is not None
    assert (ai.enabled, ai.auto_enabled, ai.optimize, ai.cron_expr) == (
        True,
        False,
        frozenset({"channel"}),
        "0 5 * * *",
    )
    assert ai.channels[Band.GHZ_2] == {1, 6, 11}
    assert ai.channels[Band.GHZ_5] == {36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128}
    assert len(ai.channels[Band.GHZ_6]) == 24
    assert ai.width_candidates_mhz == {Band.GHZ_2: {20}, Band.GHZ_5: {20, 40}}
    assert ai.excluded_devices == frozenset()
    assert len(ai.blacklist) == 14 and (Band.GHZ_5, 132, 20) in ai.blacklist and (Band.GHZ_2, 14, 20) in ai.blacklist
    assert result.mgmt is not None
    assert (result.mgmt.ssh_enabled, result.mgmt.ssh_password_auth_enabled) == (True, True)
    assert result.mgmt.ssh_user == "fixture-ssh-user"
    assert result.mgmt.ssh_password == Secret("fixture-ssh-password")
    assert "fixture-ssh-password" not in repr(result)


def test_fixture_clients_are_wireless_only_and_carry_no_identifiers() -> None:
    result = parse.parse_clients(fixture("stat_sta.json"))
    assert result.problems == ()
    assert len(result.items) == 26
    first = result.items[0]
    assert (first.band, first.channel, first.signal_dbm, first.noise_dbm) == (Band.GHZ_2, 11, -49, -94)
    assert (first.satisfaction_pct, first.fast_transition, first.essid) == (100, False, "SSID-1")
    assert first.ap_mac == "02:00:00:00:00:11"
    assert all(hasattr(c, name) is False for c in result.items for name in ("mac", "hostname", "ip"))


def test_fixture_sites() -> None:
    result = parse.parse_sites(fixture("sites.json"))
    assert result.problems == ()
    assert [(s.id, s.description, s.hidden_id, s.device_count) for s in result.items] == [
        ("default", "Site-1", "default", 11),
        ("site-2", "Site-2", None, 0),
    ]


# --- devices -------------------------------------------------------------------------------------------


def test_only_access_points_are_read_and_unknown_fields_are_ignored() -> None:
    payload = envelope({"type": "usw", "mac": "not a mac"}, device(), {"type": "udm", "is_access_point": False})
    result = parse.parse_devices(payload)
    assert len(result.access_points) == 1 and result.unparsable == () and result.problems == ()
    ap = result.access_points[0]
    assert (ap.mac, ap.name, str(ap.ip), ap.firmware, ap.uplink_type) == (AP_MAC, "AP-1", "192.0.2.1", "6.7.57", "wire")
    assert ap.radio_stats == () and ap.vaps == ()


def test_a_gateway_with_a_built_in_radio_counts_as_an_access_point() -> None:
    result = parse.parse_devices(
        envelope(device(type="udm", is_access_point=True), device(type="udm", is_access_point="yes"))
    )
    assert len(result.access_points) == 1 and result.access_points[0].mac == AP_MAC
    flagged = parse.parse_devices(
        envelope(device(type=None, is_access_point=True), device(type=7, is_access_point=True))
    )
    assert flagged.access_points == ()
    assert [d.reason for d in flagged.unparsable] == [
        "$.data[0].type: expected a string",
        "$.data[1].type: expected a string",
    ]


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"mac": None}, "$.data[0].mac: expected a string"),
        ({"name": 5}, "$.data[0].name: expected a string"),
        ({"ip": "nope"}, "$.data[0].ip: expected an IP address"),
        ({"radio_table": [radio(radio="wifi7")]}, "$.data[0].radio_table[0].radio: unknown radio"),
        ({"radio_table": [radio(radio=[1])]}, "$.data[0].radio_table[0].radio: unknown radio"),
        ({"radio_table": [radio(channel=None)]}, "$.data[0].radio_table[0].channel: expected an integer"),
        ({"radio_table": [radio(ht="30")]}, "$.data[0].radio_table[0].ht: unknown channel width"),
        ({"radio_table": [radio(ht=True)]}, "$.data[0].radio_table[0].ht: unknown channel width"),
        ({"radio_table": [radio(ht="²")]}, "$.data[0].radio_table[0].ht: unknown channel width"),
        ({"radio_table": [radio(ht="8" * 5000)]}, "$.data[0].radio_table[0].ht: unknown channel width"),
        ({"radio_table": [radio(ht="٨٠")]}, "$.data[0].radio_table[0].ht: unknown channel width"),
        ({"radio_table": [radio(channel=300)]}, "$.data[0].radio_table[0].channel: outside 1..253"),
        ({"radio_table": [radio(channel="36")]}, "$.data[0].radio_table[0].channel: expected an integer"),
        ({"radio_table": "none"}, "$.data[0].radio_table: expected a list"),
        ({"radio_table": [1]}, "$.data[0].radio_table[0]: expected an object"),
    ],
)
def test_a_mandatory_field_failure_makes_the_device_unparsable(overrides: Payload, reason: str) -> None:
    result = parse.parse_devices(envelope(device(**overrides), device(mac="02:00:00:00:00:05")))
    expected_mac = None if "mac" in overrides else AP_MAC
    expected_name = None if "name" in overrides else "AP-1"
    assert result.unparsable == (UnparsableDevice(mac=expected_mac, name=expected_name, reason=reason),)
    assert [ap.mac for ap in result.access_points] == ["02:00:00:00:00:05"]


def test_unparsable_reasons_never_echo_controller_text() -> None:
    secret = "TOPSECRET-" + "x" * 100_000
    result = parse.parse_devices(
        envelope(device(radio_table=[radio(radio=secret)]), device(ip=secret), device(radio_table=[radio(ht=secret)]))
    )
    assert len(result.unparsable) == 3
    assert all("TOPSECRET" not in d.reason and len(d.reason) < 100 for d in result.unparsable)
    result = parse.parse_devices(envelope(device(radio_table=[radio(tx_power_mode=secret, nss=secret)])))
    assert [p.path for p in result.problems] == [
        "$.data[0].radio_table[0].tx_power_mode",
        "$.data[0].radio_table[0].nss",
    ]
    assert all("TOPSECRET" not in p.message for p in result.problems)
    short = parse.parse_devices(envelope(device(radio_table=[radio(tx_power_mode="TOPSECRET", nss="TOPSECRET")])))
    assert short.problems == (
        FieldProblem("$.data[0].radio_table[0].tx_power_mode", "unknown power mode"),
        FieldProblem("$.data[0].radio_table[0].nss", "expected an integer"),
    )


def test_problem_paths_count_every_record_including_skipped_ones() -> None:
    result = parse.parse_devices(envelope({"type": "usw"}, device(mac=None), device(radio_table=[radio(nss=0)])))
    assert result.unparsable[0].reason == "$.data[1].mac: expected a string"
    assert result.problems == (FieldProblem("$.data[2].radio_table[0].nss", "outside 1..8"),)


def test_a_radio_keeps_only_band_and_width_mandatory() -> None:
    bare = {"radio": "ng", "channel": "auto", "ht": "20"}
    result = parse.parse_devices(envelope(device(radio_table=[bare], model=None)))
    (ap,) = result.access_points
    (parsed,) = ap.radios
    assert (parsed.band, parsed.channel, parsed.width_mhz) == (Band.GHZ_2, None, 20)
    assert parsed.tx_power_mode is None and parsed.configured_tx_dbm is None and parsed.interface_name is None
    assert parsed.min_tx_dbm is None and parsed.max_tx_dbm is None and parsed.min_rssi_enabled is False
    assert ap.model is None and result.problems == ()


def test_an_invalid_optional_field_is_dropped_with_a_problem() -> None:
    bad_radio = radio(tx_power_mode="loud", min_rssi=-150, nss="two", has_dfs=1, tx_power="20", name=7)
    result = parse.parse_devices(envelope(device(radio_table=[bad_radio], version=7, model=["UAL6"])))
    (ap,) = result.access_points
    (parsed,) = ap.radios
    assert parsed.tx_power_mode is None and parsed.configured_tx_dbm is None and parsed.interface_name is None
    assert parsed.min_rssi_dbm is None and parsed.spatial_streams is None and parsed.dfs_capable is None
    assert ap.firmware is None and ap.model is None
    assert sorted(p.path for p in result.problems) == [
        "$.data[0].model",
        "$.data[0].radio_table[0].has_dfs",
        "$.data[0].radio_table[0].min_rssi",
        "$.data[0].radio_table[0].name",
        "$.data[0].radio_table[0].nss",
        "$.data[0].radio_table[0].tx_power",
        "$.data[0].radio_table[0].tx_power_mode",
        "$.data[0].version",
    ]


def test_huge_integers_never_escape_as_overflow_errors() -> None:
    payload = envelope(
        device(
            radio_table_stats=[stats(tx_retries_pct=10**400, cu_total=10**400)], radio_table=[radio(tx_power=10**4300)]
        )
    )
    result = parse.parse_devices(payload)
    assert result.unparsable == () and len(result.access_points) == 1
    assert [p.path for p in result.problems] == [
        "$.data[0].radio_table[0].tx_power",
        "$.data[0].radio_table_stats[0].cu_total",
        "$.data[0].radio_table_stats[0].tx_retries_pct",
    ]


def test_stats_and_vaps_accept_integer_widths_and_the_satisfaction_sentinel() -> None:
    result = parse.parse_devices(envelope(device(radio_table_stats=[stats()], vap_table=[vap()], uplink="wire")))
    (ap,) = result.access_points
    assert ap.uplink_type is None
    (parsed_stats,) = ap.radio_stats
    assert (parsed_stats.width_mhz, parsed_stats.satisfaction_pct, parsed_stats.state) == (20, None, None)
    (parsed_vap,) = ap.vaps
    assert (parsed_vap.band, parsed_vap.is_guest, parsed_vap.wlan_id, parsed_vap.client_count) == (
        Band.GHZ_2,
        False,
        None,
        None,
    )
    down = parse.parse_devices(envelope(device(vap_table=[{"radio": "ng", "bssid": "02:00:00:00:00:10"}])))
    assert down.access_points[0].vaps[0].up is False
    assert result.problems == (FieldProblem("$.data[0].uplink", "expected an object"),)
    nested = parse.parse_devices(envelope(device(uplink={"type": 5})))
    assert nested.access_points[0].uplink_type is None
    assert nested.problems == (FieldProblem("$.data[0].uplink.type", "expected a string"),)


def test_a_bad_stats_or_vap_entry_is_skipped_not_the_device() -> None:
    payload = envelope(
        device(
            radio_table_stats=[stats(), stats(radio="x"), stats(bw=30), stats(channel=None), stats(tx_power=99)],
            vap_table=[vap(), vap(bssid="nope"), vap(radio=None), vap(bw=30, essid=1, channel=999)],
        )
    )
    result = parse.parse_devices(payload)
    (ap,) = result.access_points
    assert len(ap.radio_stats) == 2 and ap.radio_stats[1].observed_tx_dbm is None
    assert len(ap.vaps) == 2
    lenient = ap.vaps[1]
    assert (lenient.width_mhz, lenient.essid, lenient.channel) == (None, None, None)
    bare = parse.parse_devices(envelope(device(vap_table=[{"radio": "ng", "bssid": "02:00:00:00:00:10"}])))
    assert bare.access_points[0].vaps[0].width_mhz is None and bare.problems == ()
    assert [p.path for p in result.problems] == [
        "$.data[0].radio_table_stats[1].radio",
        "$.data[0].radio_table_stats[2].bw",
        "$.data[0].radio_table_stats[3].channel",
        "$.data[0].radio_table_stats[4].tx_power",
        "$.data[0].vap_table[1].bssid",
        "$.data[0].vap_table[2].radio",
        "$.data[0].vap_table[3].essid",
        "$.data[0].vap_table[3].channel",
        "$.data[0].vap_table[3].bw",
    ]


def test_an_invalid_entry_list_is_dropped_with_one_problem() -> None:
    result = parse.parse_devices(envelope(device(radio_table_stats="x", vap_table=[1])))
    (ap,) = result.access_points
    assert ap.radio_stats == () and ap.vaps == ()
    assert result.problems == (
        FieldProblem("$.data[0].radio_table_stats", "expected a list"),
        FieldProblem("$.data[0].vap_table[0]", "expected an object"),
    )


def test_width_of_rejects_booleans_unknown_widths_and_non_ascii_digits() -> None:
    assert parse.width_of(Fields({"ht": "160"}, "$"), "ht") == 160
    assert parse.width_of(Fields({"bw": 320}, "$"), "bw") == 320
    for bad in (True, 30, "x", None, 20.0, "²", "\uff18\uff10", "9" * 5000, "0020", "+20"):
        with pytest.raises(SchemaError, match="unknown channel width"):
            parse.width_of(Fields({"ht": bad}, "$"), "ht")


# --- wlans ---------------------------------------------------------------------------------------------


def test_wlan_bands_come_from_the_list_then_the_shorthand() -> None:
    assert parse.parse_wlan(Fields(wlan(), "$")).bands == {Band.GHZ_2, Band.GHZ_5, Band.GHZ_6}
    assert parse.parse_wlan(Fields(wlan(wlan_bands=["6e"]), "$")).bands == {Band.GHZ_6}
    both = Fields(wlan(wlan_bands=["2g", "5g", "6g"], wlan_band="both"), "$")
    assert parse.parse_wlan(both).bands == {Band.GHZ_2, Band.GHZ_5, Band.GHZ_6} and both.problems == []
    assert parse.parse_wlan(Fields(wlan(wlan_bands=[], wlan_band="both"), "$")).bands == {Band.GHZ_2, Band.GHZ_5}
    fields = Fields(wlan(wlan_bands=[5, "xx", "5g"]), "$")
    assert parse.parse_wlan(fields).bands == {Band.GHZ_5}
    assert fields.problems == [
        FieldProblem("$.wlan_bands[0]", "expected a string"),
        FieldProblem("$.wlan_bands[1]", "unknown band"),
    ]
    fields = Fields(wlan(wlan_bands=None, wlan_band="all"), "$")
    with pytest.raises(SchemaError, match=r"\$\.wlan_bands: no band information"):
        parse.parse_wlan(fields)
    assert fields.problems == [FieldProblem("$.wlan_band", "unknown band")]
    fields = Fields(wlan(wlan_bands=[]), "$")
    with pytest.raises(SchemaError, match=r"\$\.wlan_bands: no band information"):
        parse.parse_wlan(fields)
    assert fields.problems == []


def test_wlan_enabled_defaults_to_true_and_optional_fields_to_none() -> None:
    parsed = parse.parse_wlan(Fields(wlan(enabled=None), "$"))
    assert parsed.enabled is True
    assert parsed.security is None and parsed.ap_group_ids == () and parsed.dtim_6e is None
    assert parse.parse_wlan(Fields(wlan(enabled=False), "$")).enabled is False


def test_parse_wlans_isolates_a_broken_record_and_collects_problems() -> None:
    result = parse.parse_wlans(envelope(wlan(dtim_ng=0), wlan(_id=None), wlan(group_rekey="never")))
    assert [w.dtim_ng for w in result.items] == [None, None]
    assert result.problems == (
        FieldProblem("$.data[0].dtim_ng", "outside 1..255"),
        FieldProblem("$.data[1]._id", "expected a string"),
        FieldProblem("$.data[2].group_rekey", "expected an integer"),
    )


# --- ap groups, settings, clients, sites -----------------------------------------------------------------


def test_ap_groups_drop_invalid_macs_and_isolate_broken_records() -> None:
    result = parse.parse_ap_groups(
        [{"_id": "0" * 24, "name": "Group-1", "device_macs": ["02:00:00:00:00:04", "x"]}, {"_id": 1, "name": "Group-2"}]
    )
    assert [g.name for g in result.items] == ["Group-1"]
    assert result.items[0].device_macs == {"02:00:00:00:00:04"}
    assert result.problems == (
        FieldProblem("$[0].device_macs[1]", "expected a MAC address"),
        FieldProblem("$[1]._id", "expected a string"),
    )
    with pytest.raises(SchemaError, match=r"\$: expected a list"):
        parse.parse_ap_groups({"data": []})
    mixed = parse.parse_ap_groups([1, {"_id": "0" * 24, "name": "Group-1"}])
    assert [g.name for g in mixed.items] == ["Group-1"]
    assert mixed.problems == (FieldProblem("$[0]", "expected an object"),)


def test_settings_without_the_four_records_are_all_none() -> None:
    result = parse.parse_settings(envelope({"key": "radius", "_id": "0" * 24, "x_secret": "s"}, {"key": 1}))
    assert result.settings.country_code is None and result.settings.channel_ai is None
    assert result.settings.mlo_mesh_enabled is None and result.settings.outdoor_mode_enabled is None
    assert result.mgmt is None
    assert result.problems == (FieldProblem("$.data[1].key", "expected a string"),)


def test_duplicate_setting_records_are_reported_and_the_first_wins() -> None:
    result = parse.parse_settings(envelope(setting("country", code="276"), setting("country", code="840")))
    assert result.settings.country_code == 276
    assert result.problems == (FieldProblem("$.data[1].key", "duplicate setting record"),)


def test_connectivity_and_mgmt_flags_come_from_their_own_records() -> None:
    result = parse.parse_settings(
        envelope(
            setting("connectivity", mlo_mesh_enabled=True, enabled=False), setting("mgmt", outdoor_mode_enabled=True)
        )
    )
    assert result.settings.mlo_mesh_enabled is True and result.settings.outdoor_mode_enabled is True


@pytest.mark.parametrize(
    ("code", "expected", "problem"),
    [
        ("276", 276, None),
        (840, 840, None),
        ("DE", None, "expected a numeric country code"),
        ("1000", None, "expected a numeric country code"),
        ("٢٧٦", None, "expected a numeric country code"),
        ("2" * 5000, None, "expected a numeric country code"),
        (1000, None, "outside 0..999"),
        (None, None, None),
    ],
)
def test_country_code_accepts_string_and_integer_forms(code: object, expected: int | None, problem: str | None) -> None:
    fields = Fields({"code": code}, "$")
    assert parse.country_code(fields) == expected
    assert fields.problems == ([FieldProblem("$.code", problem)] if problem else [])


def test_channel_ai_reports_every_rejected_channel_width_and_blacklist_entry() -> None:
    record = setting(
        "radio_ai",
        enabled=True,
        channels_ng=["1", "auto", "6", "300", "²"],
        ht_modes_na=["20", "40", "wide", "30"],
        channels_blacklist=[
            {"radio": "ng", "channel": "2", "channel_width": "20"},
            {"radio": "6e", "channel": "x", "channel_width": "20"},
            {"radio": "ax", "channel": "2", "channel_width": "20"},
            {"radio": "na", "channel": 52, "channel_width": "20"},
            {"radio": "na", "channel": "999", "channel_width": "20"},
            {"radio": "na", "channel": "52", "channel_width": "30"},
            {"radio": "na", "channel": "5" * 5000, "channel_width": "20"},
        ],
        exclude_devices=["02:00:00:00:00:04"],
    )
    result = parse.parse_settings(envelope(record))
    ai = result.settings.channel_ai
    assert ai is not None
    assert ai.channels == {Band.GHZ_2: {1, 6}}
    assert ai.width_candidates_mhz == {Band.GHZ_5: {20, 40}}
    assert ai.blacklist == frozenset({(Band.GHZ_2, 2, 20)})
    assert ai.excluded_devices == {"02:00:00:00:00:04"}
    assert [(p.path, p.message) for p in result.problems] == [
        ("$.data[0].channels_ng[1]", "not an allowed number"),
        ("$.data[0].channels_ng[3]", "not an allowed number"),
        ("$.data[0].channels_ng[4]", "not an allowed number"),
        ("$.data[0].ht_modes_na[2]", "not an allowed number"),
        ("$.data[0].ht_modes_na[3]", "not an allowed number"),
        *((f"$.data[0].channels_blacklist[{i}]", "invalid blacklist entry") for i in range(1, 7)),
    ]


def test_channel_ai_skips_a_blacklist_element_that_is_not_an_object() -> None:
    record = setting("radio_ai", channels_blacklist=[{"radio": "ng", "channel": "2", "channel_width": "20"}, "junk"])
    result = parse.parse_settings(envelope(record))
    assert result.settings.channel_ai is not None
    assert result.settings.channel_ai.blacklist == frozenset({(Band.GHZ_2, 2, 20)})
    assert result.settings.channel_ai.enabled is False
    assert result.problems == (FieldProblem("$.data[0].channels_blacklist[1]", "expected an object"),)


def test_channel_ai_lists_keep_valid_siblings_and_integers() -> None:
    record = setting("radio_ai", channels_ng=["1", "6", "12345", True], ht_modes_na=["80", 160, "x"], channels_na="36")
    result = parse.parse_settings(envelope(record))
    ai = result.settings.channel_ai
    assert ai is not None
    assert ai.channels == {Band.GHZ_2: {1, 6}}
    assert ai.width_candidates_mhz == {Band.GHZ_5: {80, 160}}
    assert [(p.path, p.message) for p in result.problems] == [
        ("$.data[0].channels_ng[2]", "not an allowed number"),
        ("$.data[0].channels_ng[3]", "not an allowed number"),
        ("$.data[0].channels_na", "expected a list"),
        ("$.data[0].ht_modes_na[2]", "not an allowed number"),
    ]


def test_channel_ai_empty_lists_are_kept_as_empty_sets() -> None:
    result = parse.parse_settings(envelope(setting("radio_ai", channels_ng=[], ht_modes_na=[], exclude_devices=[])))
    ai = result.settings.channel_ai
    assert ai is not None and result.problems == ()
    assert ai.channels == {Band.GHZ_2: frozenset()} and ai.width_candidates_mhz == {Band.GHZ_5: frozenset()}
    assert ai.excluded_devices == frozenset()


def test_channel_ai_list_caps_turn_into_problems() -> None:
    record = setting(
        "radio_ai",
        channels_ng=["1"] * (MAX_CHANNEL_LIST + 1),
        ht_modes_ng=["20"] * (MAX_WIDTH_LIST + 1),
        channels_blacklist=[{"radio": "ng", "channel": "2", "channel_width": "20"}] * (MAX_BLACKLIST + 1),
        exclude_devices=[AP_MAC, "x", "02:00:00:00:00:05"],
    )
    result = parse.parse_settings(envelope(record))
    ai = result.settings.channel_ai
    assert ai is not None and ai.channels == {} and ai.blacklist == frozenset()
    assert ai.excluded_devices == {AP_MAC, "02:00:00:00:00:05"}
    assert result.problems == (
        FieldProblem("$.data[0].channels_ng", f"more than {MAX_CHANNEL_LIST} items"),
        FieldProblem("$.data[0].ht_modes_ng", f"more than {MAX_WIDTH_LIST} items"),
        FieldProblem("$.data[0].channels_blacklist", f"more than {MAX_BLACKLIST} items"),
        FieldProblem("$.data[0].exclude_devices[1]", "expected a MAC address"),
    )
    exact = setting("radio_ai", channels_ng=["1"] * MAX_CHANNEL_LIST, ht_modes_ng=["20"] * MAX_WIDTH_LIST)
    assert parse.parse_settings(envelope(exact)).problems == ()


def test_channel_ai_mappings_are_read_only() -> None:
    ai = parse.parse_settings(envelope(setting("radio_ai", channels_ng=["1"]))).settings.channel_ai
    assert ai is not None
    with pytest.raises(TypeError):
        ai.channels[Band.GHZ_5] = frozenset()  # type: ignore[index]


def test_mgmt_without_a_password_has_no_secret() -> None:
    result = parse.parse_settings(envelope(setting("mgmt", x_ssh_enabled=False, x_ssh_password="")))
    assert result.mgmt is not None and result.mgmt.ssh_password is None and result.mgmt.ssh_enabled is False


def test_clients_without_an_access_point_or_band_are_counted_not_modelled() -> None:
    payload = envelope(
        client(),
        client(is_wired=True),
        client(ap_mac=None),
        client(radio="6e"),
        client(radio="x"),
        client(ap_mac="bad"),
        client(ap_mac=None, radio=None),
        {"ap_mac": AP_MAC, "radio": "ng"},
        client(is_wired="false"),
    )
    result = parse.parse_clients(payload)
    assert len(result.items) == 2
    assert result.items[0].satisfaction_pct is None and result.items[0].fast_transition is True
    assert result.items[1].band is Band.GHZ_6
    assert [(p.path, p.message) for p in result.problems] == [
        ("$.data[2].ap_mac", "client without an access point"),
        ("$.data[4].radio", "unknown radio"),
        ("$.data[5].ap_mac", "expected a MAC address"),
        ("$.data[6].ap_mac", "client without an access point"),
        ("$.data[6].radio", "unknown radio"),
        ("$.data[7].is_wired", "expected a boolean"),
        ("$.data[8].is_wired", "expected a boolean"),
    ]


def test_sites_fall_back_to_the_name_as_description_and_reject_unsafe_ids() -> None:
    payload = envelope(
        {"name": "abc"},
        {"name": "def", "desc": "", "device_count": "many"},
        {"name": "../x"},
        {"name": "a?b"},
        {"name": "a/b"},
        {"name": "x" * 65},
        {"name": ".."},
        {"name": "."},
        {"name": ""},
        {"name": "x" * 64},
    )
    result = parse.parse_sites(payload)
    assert [(s.id, s.description) for s in result.items] == [("abc", "abc"), ("def", "def"), ("x" * 64, "x" * 64)]
    assert result.problems == (
        FieldProblem("$.data[1].device_count", "expected an integer"),
        FieldProblem("$.data[2].name", "not a site id"),
        FieldProblem("$.data[3].name", "not a site id"),
        FieldProblem("$.data[4].name", "not a site id"),
        FieldProblem("$.data[5].name", "longer than 64 bytes"),
        FieldProblem("$.data[6].name", "not a site id"),
        FieldProblem("$.data[7].name", "not a site id"),
        FieldProblem("$.data[8].name", "not a site id"),
    )


# --- the limit table, pinned through the parsers ---------------------------------------------------------

Parser = Callable[[object], object]
RANGE_CASES: list[tuple[str, Callable[[int], object], str, range]] = [
    (
        "device.radio.tx_power",
        lambda v: envelope(device(radio_table=[radio(tx_power=v)])),
        "radio_table[0].tx_power",
        TX_POWER_RANGE,
    ),
    (
        "device.radio.min_rssi",
        lambda v: envelope(device(radio_table=[radio(min_rssi=v)])),
        "radio_table[0].min_rssi",
        RSSI_RANGE,
    ),
    (
        "device.stats.cu_total",
        lambda v: envelope(device(radio_table_stats=[stats(cu_total=v)])),
        "radio_table_stats[0].cu_total",
        PERCENT_RANGE,
    ),
    (
        "device.stats.tx_power",
        lambda v: envelope(device(radio_table_stats=[stats(tx_power=v)])),
        "radio_table_stats[0].tx_power",
        TX_POWER_RANGE,
    ),
    (
        "device.radio.antenna_gain",
        lambda v: envelope(device(radio_table=[radio(antenna_gain=v)])),
        "radio_table[0].antenna_gain",
        ANTENNA_GAIN_RANGE,
    ),
    (
        "device.radio.nss",
        lambda v: envelope(device(radio_table=[radio(nss=v)])),
        "radio_table[0].nss",
        SPATIAL_STREAMS_RANGE,
    ),
    (
        "device.stats.extchannel",
        lambda v: envelope(device(radio_table_stats=[stats(extchannel=v)])),
        "radio_table_stats[0].extchannel",
        EXTENSION_CHANNEL_RANGE,
    ),
    (
        "device.stats.num_sta",
        lambda v: envelope(device(radio_table_stats=[stats(num_sta=v)])),
        "radio_table_stats[0].num_sta",
        CLIENT_COUNT_RANGE,
    ),
    (
        "wlan.minrate_ng",
        lambda v: envelope(wlan(minrate_ng_data_rate_kbps=v)),
        "minrate_ng_data_rate_kbps",
        MINRATE_KBPS_RANGE,
    ),
    ("wlan.group_rekey", lambda v: envelope(wlan(group_rekey=v)), "group_rekey", GROUP_REKEY_RANGE),
    ("wlan.sae_sync", lambda v: envelope(wlan(sae_sync=v)), "sae_sync", SAE_COUNTER_RANGE),
    ("site.device_count", lambda v: envelope({"name": "abc", "device_count": v}), "device_count", DEVICE_COUNT_RANGE),
    ("wlan.dtim_ng", lambda v: envelope(wlan(dtim_ng=v)), "dtim_ng", DTIM_RANGE),
    (
        "wlan.roaming_rssi",
        lambda v: envelope(wlan(roaming_assistant_na_rssi=v)),
        "roaming_assistant_na_rssi",
        RSSI_RANGE,
    ),
    ("client.signal", lambda v: envelope(client(signal=v)), "signal", RSSI_RANGE),
    ("client.noise", lambda v: envelope(client(noise=v)), "noise", NOISE_RANGE),
    ("country.code", lambda v: envelope(setting("country", code=v)), "code", COUNTRY_RANGE),
]
PARSER_FOR_PREFIX: dict[str, Parser] = {
    "device": parse.parse_devices,
    "wlan": parse.parse_wlans,
    "client": parse.parse_clients,
    "country": parse.parse_settings,
    "site": parse.parse_sites,
}


def problems_of(result: object) -> tuple[FieldProblem, ...]:
    problems = getattr(result, "problems")  # noqa: B009
    assert isinstance(problems, tuple)
    return problems


@pytest.mark.parametrize(("name", "build", "field", "allowed"), RANGE_CASES, ids=[c[0] for c in RANGE_CASES])
def test_optional_ranges_are_inclusive_at_both_ends(
    name: str, build: Callable[[int], object], field: str, allowed: range
) -> None:
    parser = PARSER_FOR_PREFIX[name.split(".")[0]]
    for ok in (allowed.start, allowed.stop - 1):
        assert problems_of(parser(build(ok))) == ()
    for bad in (allowed.start - 1, allowed.stop):
        assert problems_of(parser(build(bad))) == (
            FieldProblem(f"$.data[0].{field}", f"outside {allowed.start}..{allowed.stop - 1}"),
        )


CAP_CASES: list[tuple[str, Parser, Callable[[int], object], str, int]] = [
    ("devices", parse.parse_devices, lambda n: envelope(*[{"type": "usw"}] * n), "$.data", MAX_DEVICES),
    ("wlans", parse.parse_wlans, lambda n: envelope(*[wlan()] * n), "$.data", MAX_WLANS),
    ("clients", parse.parse_clients, lambda n: envelope(*[{"is_wired": True}] * n), "$.data", MAX_CLIENTS),
    ("sites", parse.parse_sites, lambda n: envelope(*[{"name": "abc"}] * n), "$.data", MAX_SITES),
    ("settings", parse.parse_settings, lambda n: envelope(*[{"key": "x"}] * n), "$.data", MAX_SETTINGS),
    ("ap groups", parse.parse_ap_groups, lambda n: [{"_id": "0" * 24, "name": "g"}] * n, "$", MAX_AP_GROUPS),
]


@pytest.mark.parametrize(("name", "parser", "build", "path", "cap"), CAP_CASES, ids=[c[0] for c in CAP_CASES])
def test_item_caps_admit_exactly_the_cap(
    name: str, parser: Parser, build: Callable[[int], object], path: str, cap: int
) -> None:
    parser(build(cap))
    with pytest.raises(SchemaError, match=re.escape(f"{path}: more than {cap} items")):
        parser(build(cap + 1))


def test_mandatory_channel_range_and_radio_cap_make_the_device_unparsable() -> None:
    for ok in (CHANNEL_RANGE.start, CHANNEL_RANGE.stop - 1):
        assert parse.parse_devices(envelope(device(radio_table=[radio(channel=ok)]))).unparsable == ()
    for bad in (CHANNEL_RANGE.start - 1, CHANNEL_RANGE.stop):
        result = parse.parse_devices(envelope(device(radio_table=[radio(channel=bad)])))
        assert result.unparsable[0].reason == "$.data[0].radio_table[0].channel: outside 1..253"
    assert parse.parse_devices(envelope(device(radio_table=[radio()] * MAX_RADIOS_PER_DEVICE))).unparsable == ()
    result = parse.parse_devices(envelope(device(radio_table=[radio()] * (MAX_RADIOS_PER_DEVICE + 1))))
    assert result.unparsable[0].reason == f"$.data[0].radio_table: more than {MAX_RADIOS_PER_DEVICE} items"


def test_satisfaction_sentinel_sits_just_below_the_percent_range() -> None:
    def satisfaction(value: int) -> tuple[int | None, tuple[FieldProblem, ...]]:
        result = parse.parse_clients(envelope(client(satisfaction=value)))
        return (result.items[0].satisfaction_pct if result.items else None), result.problems

    assert satisfaction(0) == (0, ()) and satisfaction(100) == (100, ())
    assert satisfaction(-1) == (None, ())
    assert satisfaction(-2) == (None, (FieldProblem("$.data[0].satisfaction", "outside 0..100"),))
    assert satisfaction(101) == (None, (FieldProblem("$.data[0].satisfaction", "outside 0..100"),))


def test_vaps_and_stats_caps_turn_into_problems() -> None:
    result = parse.parse_devices(
        envelope(
            device(
                vap_table=[vap()] * (MAX_VAPS_PER_DEVICE + 1), radio_table_stats=[stats()] * (MAX_RADIOS_PER_DEVICE + 1)
            )
        )
    )
    assert result.problems == (
        FieldProblem("$.data[0].radio_table_stats", f"more than {MAX_RADIOS_PER_DEVICE} items"),
        FieldProblem("$.data[0].vap_table", f"more than {MAX_VAPS_PER_DEVICE} items"),
    )
    assert (
        len(parse.parse_devices(envelope(device(vap_table=[vap()] * MAX_VAPS_PER_DEVICE))).access_points[0].vaps)
        == MAX_VAPS_PER_DEVICE
    )


BYTE_CAP_CASES: list[tuple[str, Parser, Callable[[str], object], str, int]] = [
    ("vap.essid", parse.parse_devices, lambda t: envelope(device(vap_table=[vap(essid=t)])), "vap_table[0].essid", 32),
    (
        "vap.wlanconf_id",
        parse.parse_devices,
        lambda t: envelope(device(vap_table=[vap(wlanconf_id=t)])),
        "vap_table[0].wlanconf_id",
        64,
    ),
    ("device.model", parse.parse_devices, lambda t: envelope(device(model=t)), "model", 128),
    ("apgroup.name", parse.parse_ap_groups, lambda t: [{"_id": "0" * 24, "name": t}], "name", 128),
    ("wlan.name", parse.parse_wlans, lambda t: envelope(wlan(name=t)), "name", 32),
    ("client.essid", parse.parse_clients, lambda t: envelope(client(essid=t)), "essid", 32),
    ("device.version", parse.parse_devices, lambda t: envelope(device(version=t)), "version", 64),
    ("device.uplink.type", parse.parse_devices, lambda t: envelope(device(uplink={"type": t})), "uplink.type", 16),
    (
        "radio.name",
        parse.parse_devices,
        lambda t: envelope(device(radio_table=[radio(name=t)])),
        "radio_table[0].name",
        32,
    ),
    (
        "stats.state",
        parse.parse_devices,
        lambda t: envelope(device(radio_table_stats=[stats(state=t)])),
        "radio_table_stats[0].state",
        32,
    ),
    ("wlan.security", parse.parse_wlans, lambda t: envelope(wlan(security=t)), "security", 32),
    ("wlan.pmf_mode", parse.parse_wlans, lambda t: envelope(wlan(pmf_mode=t)), "pmf_mode", 16),
    ("radio_ai.cron_expr", parse.parse_settings, lambda t: envelope(setting("radio_ai", cron_expr=t)), "cron_expr", 64),
    (
        "mgmt.x_ssh_username",
        parse.parse_settings,
        lambda t: envelope(setting("mgmt", x_ssh_username=t)),
        "x_ssh_username",
        32,
    ),
    (
        "mgmt.x_ssh_password",
        parse.parse_settings,
        lambda t: envelope(setting("mgmt", x_ssh_password=t)),
        "x_ssh_password",
        256,
    ),
    (
        "site.attr_hidden_id",
        parse.parse_sites,
        lambda t: envelope({"name": "abc", "attr_hidden_id": t}),
        "attr_hidden_id",
        64,
    ),
    ("site.desc", parse.parse_sites, lambda t: envelope({"name": "abc", "desc": t}), "desc", 128),
]


@pytest.mark.parametrize(
    ("name", "parser", "build", "field", "cap"), BYTE_CAP_CASES, ids=[c[0] for c in BYTE_CAP_CASES]
)
def test_byte_caps_admit_exactly_the_cap(
    name: str, parser: Parser, build: Callable[[str], object], field: str, cap: int
) -> None:
    root = "$[0]" if parser is parse.parse_ap_groups else "$.data[0]"
    assert problems_of(parser(build("x" * cap))) == ()
    assert problems_of(parser(build("x" * (cap + 1)))) == (FieldProblem(f"{root}.{field}", f"longer than {cap} bytes"),)


def test_mandatory_byte_caps_make_the_device_unparsable() -> None:
    for field, cap in (("type", 16), ("name", 128)):
        ok = parse.parse_devices(envelope(device(is_access_point=True, **{field: "x" * cap})))
        assert ok.unparsable == () and len(ok.access_points) == 1
        result = parse.parse_devices(envelope(device(is_access_point=True, **{field: "x" * (cap + 1)})))
        assert result.unparsable[0].reason == f"$.data[0].{field}: longer than {cap} bytes"
    assert parse.parse_settings(envelope({"key": "k" * 64})).problems == ()
    assert parse.parse_settings(envelope({"key": "k" * 65})).problems == (
        FieldProblem("$.data[0].key", "longer than 64 bytes"),
    )
    assert parse.parse_sites(envelope({"name": "s" * 64})).problems == ()
    assert parse.parse_sites(envelope({"name": "s" * 65})).problems == (
        FieldProblem("$.data[0].name", "longer than 64 bytes"),
    )


LIST_CAP_CASES: list[tuple[str, Parser, Callable[[int], object], str, int]] = [
    (
        "wlan.wlan_bands",
        parse.parse_wlans,
        lambda n: envelope(wlan(wlan_bands=["2g"] * n, wlan_band="both")),
        "wlan_bands",
        4,
    ),
    (
        "wlan.ap_group_ids",
        parse.parse_wlans,
        lambda n: envelope(wlan(ap_group_ids=["0" * 24] * n)),
        "ap_group_ids",
        MAX_AP_GROUPS,
    ),
    (
        "radio_ai.optimize",
        parse.parse_settings,
        lambda n: envelope(setting("radio_ai", optimize=["channel"] * n)),
        "optimize",
        8,
    ),
    (
        "radio_ai.exclude_devices",
        parse.parse_settings,
        lambda n: envelope(setting("radio_ai", exclude_devices=[AP_MAC] * n)),
        "exclude_devices",
        MAX_DEVICES,
    ),
    (
        "apgroup.device_macs",
        parse.parse_ap_groups,
        lambda n: [{"_id": "0" * 24, "name": "g", "device_macs": [AP_MAC] * n}],
        "device_macs",
        MAX_DEVICES,
    ),
]


@pytest.mark.parametrize(
    ("name", "parser", "build", "field", "cap"), LIST_CAP_CASES, ids=[c[0] for c in LIST_CAP_CASES]
)
def test_optional_list_caps_turn_into_one_problem(
    name: str, parser: Parser, build: Callable[[int], object], field: str, cap: int
) -> None:
    root = "$[0]" if parser is parse.parse_ap_groups else "$.data[0]"
    assert problems_of(parser(build(cap))) == ()
    assert problems_of(parser(build(cap + 1))) == (FieldProblem(f"{root}.{field}", f"more than {cap} items"),)


def test_ssh_credentials_have_their_own_caps() -> None:
    result = parse.parse_settings(envelope(setting("mgmt", x_ssh_username="u" * 33, x_ssh_password="p" * 257)))
    assert result.mgmt is not None and result.mgmt.ssh_user is None and result.mgmt.ssh_password is None
    assert [p.path for p in result.problems] == ["$.data[0].x_ssh_username", "$.data[0].x_ssh_password"]
    assert all("ppp" not in p.message for p in result.problems)


def deep(kind: str, depth: int) -> object:
    value: object = 0
    for _ in range(depth):
        value = [value] if kind == "list" else {"k": value}
    return value


@pytest.mark.parametrize("kind", ["list", "dict"])
@pytest.mark.parametrize(
    "parser",
    [
        parse.parse_devices,
        parse.parse_wlans,
        parse.parse_ap_groups,
        parse.parse_settings,
        parse.parse_clients,
        parse.parse_sites,
    ],
)
def test_every_parser_rejects_deep_nesting_before_reading(parser: Parser, kind: str) -> None:
    with pytest.raises(SchemaError, match=f"nesting deeper than {MAX_DEPTH}"):
        parser(
            {"data": [{"x": deep(kind, MAX_DEPTH)}]}
            if parser is not parse.parse_ap_groups
            else [{"x": deep(kind, MAX_DEPTH)}]
        )
    parser(
        {"data": [{"x": deep(kind, MAX_DEPTH - 3)}]}
        if parser is not parse.parse_ap_groups
        else [{"x": deep(kind, MAX_DEPTH - 3)}]
    )


# --- robustness: arbitrary JSON never escapes as anything but SchemaError -------------------------------

digit_texts = st.sampled_from(["²", "٨٠", "\uff18\uff10", "auto", "9" * 5000, "0", "-1", " 20", "20\n"])
huge_numbers = st.sampled_from([10**400, -(10**400), 10**4000])
json_values = st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats() | st.text(max_size=12) | digit_texts | huge_numbers,
    lambda children: st.lists(children, max_size=4) | st.dictionaries(st.text(max_size=8), children, max_size=4),
    max_leaves=20,
)
KNOWN_KEYS = (
    "type",
    "is_access_point",
    "mac",
    "name",
    "ip",
    "model",
    "version",
    "uplink",
    "radio_table",
    "radio_table_stats",
    "vap_table",
    "radio",
    "channel",
    "ht",
    "bw",
    "tx_power",
    "tx_power_mode",
    "min_txpower",
    "max_txpower",
    "min_rssi",
    "bssid",
    "essid",
    "up",
    "wlanconf_id",
    "_id",
    "enabled",
    "wlan_bands",
    "wlan_band",
    "key",
    "code",
    "channels_ng",
    "ht_modes_na",
    "channels_blacklist",
    "channel_width",
    "x_ssh_password",
    "is_wired",
    "ap_mac",
    "signal",
    "device_macs",
    "desc",
    "data",
    "meta",
    "tx_retries_pct",
    "exclude_devices",
    "optimize",
)
shaped_records = st.lists(
    st.fixed_dictionaries({}, optional=dict.fromkeys(KNOWN_KEYS, json_values)).map(
        lambda r: {**r, "type": "uap", "is_wired": False, "key": "radio_ai"} if "type" in r else r
    ),
    max_size=3,
)
payloads = json_values | st.fixed_dictionaries({"data": shaped_records}) | shaped_records


@settings(max_examples=200, deadline=None)
@given(payloads)
def test_parsers_only_raise_schema_errors(payload: object) -> None:
    for function in (
        parse.parse_devices,
        parse.parse_wlans,
        parse.parse_ap_groups,
        parse.parse_settings,
        parse.parse_clients,
        parse.parse_sites,
    ):
        with contextlib.suppress(SchemaError):
            function(payload)
