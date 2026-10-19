"""Roaming Assistant targets per WLAN, plus the seam into the compliance check. The fixtures use TX_LO -73,
margin 5, floor -78, ceiling -67 and equal AP/client power: a 2.4-GHz-like corridor on 5 GHz and
`client_tx_dbm` equal to the radios' effective power, so the uplink values equal the downlink values and
every expected threshold can be derived by hand from those round numbers."""

from collections.abc import Mapping
from dataclasses import replace

from unifiwifioptimizer.analysis.neighbors import build_matrix
from unifiwifioptimizer.analysis.roaming_targets import (
    WlanRoamingTarget,
    broadcasting_aps,
    downlink_trigger_for,
    roaming_target,
    roaming_targets,
    threshold_above_guidance,
    thresholds_for_compliance,
)
from unifiwifioptimizer.compliance.roaming_check import roaming_assistant_check
from unifiwifioptimizer.domain.analysis import ReadingSource, RoamingCap, WlanRoamingStatus
from unifiwifioptimizer.domain.models import ApGroup, Band, SiteSnapshot, WlanConfig
from unifiwifioptimizer.domain.report import CheckStatus
from unifiwifioptimizer.domain.scan import ScanFailure, ScanPass, SiteScan
from unifiwifioptimizer.rf.corridor import Corridor
from unifiwifioptimizer.rf.roaming import RoamingTunables
from unifiwifioptimizer.rf.settings import RfSettings

from ..compliance.builders import profile, wlan
from .builders import ap_named, fixture_snapshot, hears, scan_pass, site_scan, with_ap, with_stats

CORRIDOR = Corridor(low=-73)
TUNABLES = RoamingTunables(offset_db=0, margin_db=5, floor_dbm=-78, ceiling_dbm=-67)
EQUAL_POWER = 15
RF = RfSettings(client_tx_dbm=EQUAL_POWER, roaming=TUNABLES)
GROUP = "000000000000000000000011"
# Every fixture radio at the same effective 5 GHz power, so uplink == downlink.
SNAP = fixture_snapshot()
for _name in ("AP-1", "AP-2", "AP-3", "AP-4"):
    SNAP = with_ap(SNAP, with_stats(ap_named(SNAP, _name), Band.GHZ_5, observed_tx_dbm=EQUAL_POWER))
MACS = {name: ap_named(SNAP, name).mac for name in ("AP-1", "AP-2", "AP-3", "AP-4")}


def groups_wlan(
    name: str = "Corp", *groups: str, bands: frozenset[Band] = frozenset({Band.GHZ_5}), **overrides: object
) -> WlanConfig:
    values: dict[str, object] = {
        "id": f"id-{name}",
        "name": name,
        "bands": bands,
        "roaming_assistant_na_enabled": True,
        "roaming_assistant_na_rssi": -67,
        "ap_group_mode": "groups",
        "ap_group_ids": tuple(groups) or (GROUP,),
    }
    values.update(overrides)
    return wlan(**values)


def with_groups(snapshot: SiteSnapshot, *groups: tuple[str, tuple[str, ...]]) -> SiteSnapshot:
    return replace(
        snapshot,
        ap_groups=tuple(
            ApGroup(id=gid, name=gid, device_macs=frozenset(MACS[n] for n in names)) for gid, names in groups
        ),
    )


def sightings(snapshot: SiteSnapshot, *pairs: tuple[str, str, int]) -> SiteScan:
    """(scanner, heard AP, RSSI on 5 GHz): one pass per scanner; every other AP scans and hears nothing."""
    passes: dict[str, list[ScanPass | ScanFailure]] = {}
    for scanner, heard, rssi in pairs:
        passes.setdefault(scanner, []).append(hears(snapshot, scanner, **{heard: {Band.GHZ_5: rssi}}))
    for scanner in ("AP-1", "AP-2", "AP-3", "AP-4"):
        passes.setdefault(scanner, [scan_pass()])
    return site_scan(snapshot, passes)


def target(
    snapshot: SiteSnapshot, w: WlanConfig, neighbours: Mapping[str, frozenset[str]], scan: SiteScan
) -> WlanRoamingTarget | None:
    matrix = build_matrix(snapshot, scan, neighbours, scan_skipped=False)
    return roaming_target(w, snapshot, matrix, CORRIDOR, RF)


# --- target derivation per WLAN ---------------------------------------------------------------------------


def test_ssid_peer_filtering() -> None:
    # AP-1 and AP-2 broadcast the WLAN; AP-3 is a neighbour of AP-1 but does not. Its weak sighting is ignored.
    snap = with_groups(SNAP, ("g1", ("AP-1", "AP-2")))
    neighbours = {"AP-1": frozenset({"AP-2", "AP-3"}), "AP-2": frozenset({"AP-1"}), "AP-3": frozenset({"AP-1"})}
    scan = sightings(snap, ("AP-2", "AP-1", -70), ("AP-3", "AP-1", -95), ("AP-1", "AP-2", -70))
    result = target(snap, groups_wlan("Guest", "g1"), neighbours, scan)
    assert result is not None and result.status is WlanRoamingStatus.OK and result.threshold_dbm == -73


def test_asymmetric_direction() -> None:
    # A's signal at B is -70 (no cap for A); B's signal at A is -82 (caps B). B is the limiting AP.
    snap = with_groups(SNAP, ("g1", ("AP-1", "AP-2")))
    neighbours = {"AP-1": frozenset({"AP-2"}), "AP-2": frozenset({"AP-1"})}
    scan = sightings(snap, ("AP-2", "AP-1", -70), ("AP-1", "AP-2", -82))
    result = target(snap, groups_wlan("Corp", "g1"), neighbours, scan)
    assert result is not None and result.limiting == ("AP-2",)
    b = next(d for d in result.per_ap if d.ap == "AP-2")
    assert (b.weakest_peer, b.weakest_rssi_dbm, b.cap) == ("AP-1", -82, RoamingCap.FLOOR)
    assert result.threshold_dbm == -78


def test_tie_handling_floor_clamp() -> None:
    snap = with_groups(SNAP, ("g1", ("AP-1", "AP-2", "AP-3")))
    neighbours = {"AP-1": frozenset({"AP-3"}), "AP-2": frozenset({"AP-3"}), "AP-3": frozenset({"AP-1", "AP-2"})}
    scan = sightings(snap, ("AP-3", "AP-1", -95), ("AP-3", "AP-2", -95), ("AP-1", "AP-3", -70), ("AP-2", "AP-3", -70))
    result = target(snap, groups_wlan("Corp", "g1"), neighbours, scan)
    assert result is not None and result.limiting == ("AP-1", "AP-2") and result.threshold_dbm == -78


def test_incomplete_no_relevant_neighbor() -> None:
    # AP-3 broadcasts the WLAN but its only neighbour AP-4 does not.
    snap = with_groups(SNAP, ("g1", ("AP-1", "AP-2", "AP-3")))
    neighbours = {
        "AP-1": frozenset({"AP-2"}),
        "AP-2": frozenset({"AP-1"}),
        "AP-3": frozenset({"AP-4"}),
        "AP-4": frozenset({"AP-3"}),
    }
    scan = sightings(snap, ("AP-2", "AP-1", -70), ("AP-1", "AP-2", -70))
    result = target(snap, groups_wlan("Guest", "g1"), neighbours, scan)
    assert result is not None and result.status is WlanRoamingStatus.INCOMPLETE and result.threshold_dbm is None
    assert "AP-3 has no configured neighbour broadcasting this WLAN" in result.reasons


def test_incomplete_missing_sighting() -> None:
    snap = with_groups(SNAP, ("g1", ("AP-1", "AP-2")))
    neighbours = {"AP-1": frozenset({"AP-2"}), "AP-2": frozenset({"AP-1"})}
    # AP-2 scanned and heard nothing of AP-1; AP-1 heard AP-2. Reciprocity substitutes AP-1 at AP-2 — so the
    # shell case needs the reverse direction missing too: AP-1's 5 GHz scan saw nothing of AP-2 either.
    scan = sightings(snap)
    result = target(snap, groups_wlan("Guest", "g1"), neighbours, scan)
    assert result is not None and result.status is WlanRoamingStatus.INCOMPLETE
    assert any(r.startswith("AP-1: no reading of neighbour AP-2 (") for r in result.reasons)


def test_na_2g_only_wlan() -> None:
    snap = with_groups(SNAP, ("g1", ("AP-1", "AP-2")))
    result = target(
        snap, groups_wlan("IoT", "g1", bands=frozenset({Band.GHZ_2})), {"AP-1": frozenset({"AP-2"})}, sightings(snap)
    )
    assert (
        result is not None and result.status is WlanRoamingStatus.NOT_APPLICABLE_NO_5G and result.threshold_dbm is None
    )


def test_na_single_ap_wlan() -> None:
    snap = with_groups(SNAP, ("g1", ("AP-1",)))
    result = target(snap, groups_wlan("Solo", "g1", ap_group_mode="specific"), {}, sightings(snap))
    assert result is not None and result.status is WlanRoamingStatus.NOT_APPLICABLE_SINGLE_AP
    assert "only one access point broadcasts" in result.reasons[0]


def test_missing_new_field_no_row() -> None:
    # Older API: no roaming_assistant_na_* at all → no target; the compliance check reports INCOMPLETE itself.
    snap = with_groups(SNAP, ("g1", ("AP-1", "AP-2")))
    older = groups_wlan("Corp", "g1", roaming_assistant_na_enabled=None, roaming_assistant_na_rssi=None)
    assert target(snap, older, {"AP-1": frozenset({"AP-2"})}, sightings(snap)) is None
    check = roaming_assistant_check(profile("Standard"), older, None)
    assert check.status is CheckStatus.INCOMPLETE and "older API" in check.detail


def test_incomplete_partial_missing_sighting() -> None:
    # AP-1 has two SSID peers: AP-2 sighted, AP-3 missed in both directions.
    snap = with_groups(SNAP, ("g1", ("AP-1", "AP-2", "AP-3")))
    neighbours = {"AP-1": frozenset({"AP-2", "AP-3"}), "AP-2": frozenset({"AP-1"}), "AP-3": frozenset({"AP-1"})}
    scan = sightings(snap, ("AP-2", "AP-1", -70), ("AP-1", "AP-2", -70))
    result = target(snap, groups_wlan("Corp", "g1"), neighbours, scan)
    assert result is not None and result.status is WlanRoamingStatus.INCOMPLETE
    assert any(r.startswith("AP-1: no reading of neighbour AP-3 (") for r in result.reasons)


def test_a_reciprocity_value_counts_for_roaming_with_its_source_shown() -> None:
    # AP-3 heard AP-1 at -70 but AP-1's own scan failed: AP-3 at AP-1 is predicted by reciprocity (equal power).
    snap = with_groups(SNAP, ("g1", ("AP-1", "AP-3")))
    neighbours = {"AP-1": frozenset({"AP-3"}), "AP-3": frozenset({"AP-1"})}
    passes = {
        "AP-3": [hears(snap, "AP-3", **{"AP-1": {Band.GHZ_5: -70}})],
        "AP-2": [scan_pass()],
        "AP-4": [scan_pass()],
    }
    result = target(snap, groups_wlan("Corp", "g1"), neighbours, site_scan(snap, passes))
    assert result is not None and result.status is WlanRoamingStatus.OK
    ap3 = next(d for d in result.per_ap if d.ap == "AP-3")
    assert (ap3.source, ap3.weakest_rssi_dbm) == (ReadingSource.RECIPROCITY, -70)


def test_incomplete_unconfigured_broadcasting_ap() -> None:
    # The group names a MAC that is no access point of the site.
    snap = replace(
        SNAP,
        ap_groups=(
            ApGroup(id="g1", name="g1", device_macs=frozenset({MACS["AP-1"], MACS["AP-2"], "de:ad:be:ef:00:01"})),
        ),
    )
    neighbours = {"AP-1": frozenset({"AP-2"}), "AP-2": frozenset({"AP-1"})}
    scan = sightings(snap, ("AP-2", "AP-1", -70), ("AP-1", "AP-2", -70))
    result = target(snap, groups_wlan("Corp", "g1"), neighbours, scan)
    assert result is not None and result.status is WlanRoamingStatus.INCOMPLETE
    assert any("de:ad:be:ef:00:01" in r for r in result.reasons)


def test_2g_only_site_no_fallback_trigger() -> None:
    # The per-radio fallback is gone: a 2.4 GHz-only WLAN is N/A, nothing else happens site-wide.
    snap = with_groups(SNAP, ("g1", ("AP-1", "AP-2")))
    two = groups_wlan("IoT", "g1", bands=frozenset({Band.GHZ_2}))
    targets = roaming_targets(
        replace(snap, wlans=(two,)), build_matrix(snap, None, {}, scan_skipped=True), CORRIDOR, RF
    )
    assert targets["IoT"].status is WlanRoamingStatus.NOT_APPLICABLE_NO_5G and thresholds_for_compliance(targets) == {}


def test_overlapping_groups_deduplicated() -> None:
    snap = with_groups(SNAP, ("all", ("AP-1",)), ("specific", ("AP-1",)))
    result = target(snap, groups_wlan("Solo", "all", "specific"), {}, sightings(snap))
    assert (
        result is not None
        and result.status is WlanRoamingStatus.NOT_APPLICABLE_SINGLE_AP
        and result.broadcasting == ("AP-1",)
    )


def test_incomplete_unknown_group_id() -> None:
    snap = with_groups(SNAP, ("g1", ("AP-1", "AP-2")))
    neighbours = {"AP-1": frozenset({"AP-2"}), "AP-2": frozenset({"AP-1"})}
    scan = sightings(snap, ("AP-2", "AP-1", -70), ("AP-1", "AP-2", -70))
    result = target(snap, groups_wlan("Corp", "g1", "missing-group"), neighbours, scan)
    assert result is not None and result.status is WlanRoamingStatus.INCOMPLETE
    assert any("missing-group" in r for r in result.reasons) and result.threshold_dbm is None


def test_multi_site_tx_lo_isolation() -> None:
    # Two corridors, same sightings: each site aggregates to its own default.
    snap = with_groups(SNAP, ("g1", ("AP-1", "AP-2")))
    neighbours = {"AP-1": frozenset({"AP-2"}), "AP-2": frozenset({"AP-1"})}
    matrix = build_matrix(
        snap, sightings(snap, ("AP-2", "AP-1", -60), ("AP-1", "AP-2", -60)), neighbours, scan_skipped=False
    )
    w = groups_wlan("Corp", "g1")
    open_site = roaming_target(w, snap, matrix, Corridor(low=-72), RF)
    obstructed = roaming_target(w, snap, matrix, Corridor(low=-76), RF)
    assert open_site is not None and obstructed is not None
    assert (open_site.threshold_dbm, obstructed.threshold_dbm) == (-72, -76)


def test_field_present_but_apgroups_empty_still_produces_row() -> None:
    snap = replace(SNAP, ap_groups=())
    result = target(snap, groups_wlan("Corp", "g1"), {"AP-1": frozenset({"AP-2"})}, sightings(snap))
    assert result is not None and result.status is WlanRoamingStatus.INCOMPLETE
    assert any("g1" in r for r in result.reasons)


def test_incomplete_all_group_ids_unknown() -> None:
    snap = replace(SNAP, ap_groups=())
    result = target(snap, groups_wlan("Corp", "missing-a", "missing-b"), {"AP-1": frozenset({"AP-2"})}, sightings(snap))
    assert result is not None and result.status is WlanRoamingStatus.INCOMPLETE
    assert any("missing-a" in r for r in result.reasons) and any("missing-b" in r for r in result.reasons)


# --- the seam into the compliance check and the `all` mode -------------------------------------------------


def test_all_mode_means_every_access_point_of_the_site() -> None:
    all_mode = wlan(
        id="w",
        name="Corp",
        bands=frozenset({Band.GHZ_5}),
        roaming_assistant_na_enabled=True,
        ap_group_mode="all",
        ap_group_ids=(GROUP,),
    )
    assert broadcasting_aps(all_mode, replace(SNAP, ap_groups=())) == (("AP-1", "AP-2", "AP-3", "AP-4"), ())


def test_an_incomplete_target_leaves_an_expected_off_wlan_judged_on_the_switch_alone() -> None:
    snap = with_groups(SNAP, ("g1", ("AP-1", "AP-2")))
    w = groups_wlan("Guest", "g1", roaming_assistant_na_enabled=False, roaming_assistant_na_rssi=None)
    result = target(snap, w, {"AP-1": frozenset({"AP-2"})}, sightings(snap))
    assert result is not None and result.status is WlanRoamingStatus.INCOMPLETE
    threshold = thresholds_for_compliance({"Guest": result}).get("Guest")
    check = roaming_assistant_check(profile("IoT"), w, threshold)
    assert (check.status, check.expected, check.actual) == (CheckStatus.PASSED, "Disabled", "Disabled")
    on = replace(w, roaming_assistant_na_enabled=True, roaming_assistant_na_rssi=-67)
    assert roaming_assistant_check(profile("IoT"), on, threshold).status is CheckStatus.FAILED


def test_only_an_ok_target_carries_a_value_into_the_compliance_check() -> None:
    # AP-3 broadcasts the WLAN without a configured neighbour: the target stays INCOMPLETE although AP-1 and
    # AP-2 were evaluated, and an incomplete target hands the compliance check no value at all.
    snap = with_groups(SNAP, ("g1", ("AP-1", "AP-2", "AP-3")))
    neighbours = {"AP-1": frozenset({"AP-2"}), "AP-2": frozenset({"AP-1"})}
    scan = sightings(snap, ("AP-1", "AP-2", -70), ("AP-2", "AP-1", -70))
    incomplete = target(snap, groups_wlan("Corp", "g1"), neighbours, scan)
    assert incomplete is not None and incomplete.status is WlanRoamingStatus.INCOMPLETE
    assert [d.ap for d in incomplete.per_ap] == ["AP-1", "AP-2"] and incomplete.threshold_dbm is None
    complete = target(with_groups(SNAP, ("g1", ("AP-1", "AP-2"))), groups_wlan("Corp", "g1"), neighbours, scan)
    assert complete is not None and complete.status is WlanRoamingStatus.OK and complete.threshold_dbm == -73
    assert thresholds_for_compliance({"Partial": incomplete, "Complete": complete}) == {"Complete": -73}


def test_the_downlink_trigger_is_the_wlan_threshold_seen_from_each_access_point() -> None:
    snap = with_groups(SNAP, ("g1", ("AP-1", "AP-2")))
    neighbours = {"AP-1": frozenset({"AP-2"}), "AP-2": frozenset({"AP-1"})}
    scan = sightings(snap, ("AP-2", "AP-1", -70), ("AP-1", "AP-2", -82))
    result = target(snap, groups_wlan("Corp", "g1"), neighbours, scan)
    # AP-1's own value is -73 (inside the corridor, default), AP-2's -78 (floor); the WLAN applies -78 to both.
    assert result is not None and result.threshold_dbm == -78 and result.limiting == ("AP-2",)
    assert [(d.ap, d.recommendation.downlink_dbm) for d in result.per_ap] == [("AP-1", -73), ("AP-2", -78)]
    assert downlink_trigger_for(result, "AP-2") == -78 and downlink_trigger_for(result, "AP-1") == -78
    # At 22 dBm AP-1's uplink value is -73 - (22 - 15) = -80, now the WLAN minimum: AP-2's clients are let go 2 dB
    # below AP-2's own derived trigger, and AP-1 sees the threshold at -73 on the downlink again.
    strong = with_ap(snap, with_stats(ap_named(snap, "AP-1"), Band.GHZ_5, observed_tx_dbm=22))
    result = target(strong, groups_wlan("Corp", "g1"), neighbours, scan)
    assert result is not None and result.threshold_dbm == -80 and result.limiting == ("AP-1",)
    assert result.derived_dbm is None
    assert downlink_trigger_for(result, "AP-1") == -73 and downlink_trigger_for(result, "AP-2") == -80
    assert downlink_trigger_for(result, "AP-9") is None and downlink_trigger_for(None, "AP-1") is None
    # An incomplete target has no threshold the controller could apply, so no trigger either.
    three = with_groups(SNAP, ("g1", ("AP-1", "AP-2", "AP-3")))
    incomplete = target(three, groups_wlan("Corp", "g1"), neighbours, scan)
    assert incomplete is not None and incomplete.status is WlanRoamingStatus.INCOMPLETE and incomplete.per_ap
    assert downlink_trigger_for(incomplete, "AP-1") is None


def test_an_offline_broadcasting_access_point_is_skipped_not_incomplete() -> None:
    snap = with_groups(SNAP, ("g1", ("AP-1", "AP-2", "AP-3")))
    snap = with_ap(snap, replace(ap_named(snap, "AP-3"), state_code=0))
    neighbours = {"AP-1": frozenset({"AP-2", "AP-3"}), "AP-2": frozenset({"AP-1"}), "AP-3": frozenset({"AP-1"})}
    scan = sightings(snap, ("AP-2", "AP-1", -70), ("AP-1", "AP-2", -70))
    result = target(snap, groups_wlan("Corp", "g1"), neighbours, scan)
    assert result is not None and result.status is WlanRoamingStatus.OK and result.limiting == ("AP-1", "AP-2")


def test_a_derived_value_below_what_the_controller_accepts_is_raised_to_the_limit() -> None:
    snap = with_groups(SNAP, ("g1", ("AP-1", "AP-2")))
    neighbours = {"AP-1": frozenset({"AP-2"}), "AP-2": frozenset({"AP-1"})}
    scan = sightings(snap, ("AP-2", "AP-1", -70), ("AP-1", "AP-2", -82))
    # At 23 dBm AP-1's uplink value is -73 - (23 - 15) = -81, one dB below the lowest value the controller takes.
    strong = with_ap(snap, with_stats(ap_named(snap, "AP-1"), Band.GHZ_5, observed_tx_dbm=23))
    result = target(strong, groups_wlan("Corp", "g1"), neighbours, scan)
    assert result is not None and result.status is WlanRoamingStatus.OK
    assert (result.threshold_dbm, result.derived_dbm, result.limiting) == (-80, -81, ("AP-1",))
    assert [(d.ap, d.recommendation.uplink_dbm) for d in result.per_ap] == [("AP-1", -81), ("AP-2", -78)]
    # The controller applies -80, so that is where the trigger fires at each AP.
    assert downlink_trigger_for(result, "AP-1") == -72 and downlink_trigger_for(result, "AP-2") == -80
    assert thresholds_for_compliance({"Corp": result}) == {"Corp": -80}
    configured = groups_wlan("Corp", "g1", roaming_assistant_na_rssi=-80)
    check = roaming_assistant_check(profile("Throughput"), configured, -80)
    assert check.status is CheckStatus.PASSED


def test_a_derived_value_exactly_at_the_limit_is_not_reported_as_raised() -> None:
    snap = with_groups(SNAP, ("g1", ("AP-1", "AP-2")))
    neighbours = {"AP-1": frozenset({"AP-2"}), "AP-2": frozenset({"AP-1"})}
    scan = sightings(snap, ("AP-2", "AP-1", -70), ("AP-1", "AP-2", -82))
    at_limit = with_ap(snap, with_stats(ap_named(snap, "AP-1"), Band.GHZ_5, observed_tx_dbm=22))
    result = target(at_limit, groups_wlan("Corp", "g1"), neighbours, scan)
    assert result is not None and (result.threshold_dbm, result.derived_dbm) == (-80, None)


def test_a_derived_value_above_what_the_controller_accepts_is_lowered_to_the_limit() -> None:
    # Floor -58 and ceiling -55 with equal power: both access points derive -58 on the uplink, above the
    # slider's upper stop of -60.
    rf = RfSettings(
        client_tx_dbm=EQUAL_POWER, roaming=RoamingTunables(offset_db=0, margin_db=5, floor_dbm=-58, ceiling_dbm=-55)
    )
    snap = with_groups(SNAP, ("g1", ("AP-1", "AP-2")))
    neighbours = {"AP-1": frozenset({"AP-2"}), "AP-2": frozenset({"AP-1"})}
    scan = sightings(snap, ("AP-2", "AP-1", -70), ("AP-1", "AP-2", -70))
    matrix = build_matrix(snap, scan, neighbours, scan_skipped=False)
    result = roaming_target(groups_wlan("Corp", "g1"), snap, matrix, CORRIDOR, rf)
    assert result is not None and result.status is WlanRoamingStatus.OK
    assert (result.threshold_dbm, result.derived_dbm) == (-60, -58)
    exact = RfSettings(
        client_tx_dbm=EQUAL_POWER, roaming=RoamingTunables(offset_db=0, margin_db=5, floor_dbm=-60, ceiling_dbm=-55)
    )
    at_limit = roaming_target(groups_wlan("Corp", "g1"), snap, matrix, CORRIDOR, exact)
    assert at_limit is not None and (at_limit.threshold_dbm, at_limit.derived_dbm) == (-60, None)


def test_a_threshold_not_below_minus_70_is_above_ubiquitis_guidance() -> None:
    snap = with_groups(SNAP, ("g1", ("AP-1", "AP-2")))
    neighbours = {"AP-1": frozenset({"AP-2"}), "AP-2": frozenset({"AP-1"})}
    scan = sightings(snap, ("AP-2", "AP-1", -70), ("AP-1", "AP-2", -70))
    result = target(snap, groups_wlan("Corp", "g1"), neighbours, scan)
    assert result is not None and result.status is WlanRoamingStatus.OK
    assert [threshold_above_guidance(replace(result, threshold_dbm=value)) for value in (-71, -70, -69, -60)] == [
        False,
        True,
        True,
        True,
    ]
    assert not threshold_above_guidance(replace(result, status=WlanRoamingStatus.INCOMPLETE, threshold_dbm=-60))
    assert not threshold_above_guidance(replace(result, threshold_dbm=None))
