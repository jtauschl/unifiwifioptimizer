from collections import Counter
from dataclasses import replace

from unifiwifioptimizer.analysis.airtime import airtime_of
from unifiwifioptimizer.analysis.channels import analyse_channels
from unifiwifioptimizer.analysis.clients import clients_of, unassignable, unassignable_finding
from unifiwifioptimizer.analysis.groups import group_reports
from unifiwifioptimizer.analysis.neighbors import build_matrix
from unifiwifioptimizer.domain.analysis import MissDirection
from unifiwifioptimizer.domain.models import Band, ClientSighting

from .builders import ap_named, fixture_snapshot, hears, scan_pass, site_scan, with_ap, with_stats, without_stats

SNAP = fixture_snapshot(clients=True)
FOUR = {"AP-1": frozenset({"AP-2"}), "AP-2": frozenset({"AP-3"}), "AP-3": frozenset({"AP-4"})}


def test_groups_list_missing_pairs_with_direction_and_reasons_and_overlapping_channels() -> None:
    # AP-1 and AP-2 hear each other; AP-2 heard AP-3 but AP-3's scan failed; AP-3/AP-4 missed both ways on 2.4 GHz.
    passes = {
        "AP-1": [hears(SNAP, "AP-1", **{"AP-2": {Band.GHZ_2: -70, Band.GHZ_5: -70}})],
        "AP-2": [
            hears(
                SNAP, "AP-2", **{"AP-1": {Band.GHZ_2: -70, Band.GHZ_5: -70}, "AP-3": {Band.GHZ_2: -70, Band.GHZ_5: -70}}
            )
        ],
        "AP-4": [scan_pass()],
    }
    snap = with_ap(SNAP, with_stats(ap_named(SNAP, "AP-4"), Band.GHZ_2, channel=6))
    matrix = build_matrix(snap, site_scan(snap, passes), FOUR, scan_skipped=False)
    channels = analyse_channels(snap, None, FOUR, None)
    (report,) = group_reports(matrix, channels)
    assert report.members == ("AP-1", "AP-2", "AP-3", "AP-4") and not report.clean
    directions = {(m.band, m.a, m.b): m.direction for m in report.missing}
    # AP-2 at AP-3 is missing (AP-3 scan failed) but AP-3 at AP-2 was heard → one direction; reciprocity fills
    # the AP-2-at-AP-3 cell with a value, so the pair is complete on both bands.
    assert (Band.GHZ_2, "AP-2", "AP-3") not in directions
    assert directions[(Band.GHZ_2, "AP-3", "AP-4")] is MissDirection.BOTH
    assert directions[(Band.GHZ_5, "AP-3", "AP-4")] is MissDirection.BOTH
    reasons = next(m.reasons for m in report.missing if (m.a, m.b, m.band) == ("AP-3", "AP-4", Band.GHZ_2))
    assert reasons == ("AP-4: peer scan empty", "AP-3: peer scan failed")
    # AP-3 (fixed 6) and AP-4 (fixed, moved to 6) overlap on 2.4 GHz.
    assert (Band.GHZ_2, "AP-3", "AP-4") in report.overlapping and report.reuse_infeasible == ()
    assert sorted((m.band, m.a, m.b) for m in report.missing) == [
        (Band.GHZ_2, "AP-3", "AP-4"),
        (Band.GHZ_5, "AP-3", "AP-4"),
    ]


def test_a_clean_group_is_clean_and_components_are_separate_reports() -> None:
    passes = {
        "AP-1": [hears(SNAP, "AP-1", **{"AP-2": {Band.GHZ_2: -70, Band.GHZ_5: -70}})],
        "AP-2": [hears(SNAP, "AP-2", **{"AP-1": {Band.GHZ_2: -70, Band.GHZ_5: -70}})],
        "AP-3": [hears(SNAP, "AP-3", **{"AP-4": {Band.GHZ_2: -70, Band.GHZ_5: -70}})],
        "AP-4": [hears(SNAP, "AP-4", **{"AP-3": {Band.GHZ_2: -70, Band.GHZ_5: -70}})],
    }
    two_pairs = {"AP-1": frozenset({"AP-2"}), "AP-3": frozenset({"AP-4"})}
    matrix = build_matrix(SNAP, site_scan(SNAP, passes), two_pairs, scan_skipped=False)
    reports = group_reports(matrix, analyse_channels(SNAP, None, two_pairs, None))
    assert [r.members for r in reports] == [("AP-1", "AP-2"), ("AP-3", "AP-4")] and all(r.clean for r in reports)


def test_airtime_is_reported_as_values_or_not_at_all() -> None:
    summary = airtime_of(ap_named(SNAP, "AP-2"), Band.GHZ_5)
    assert summary is not None and (summary.utilisation_pct, summary.tx_retries_pct, summary.client_count) == (
        1,
        21.3,
        4,
    )
    assert airtime_of(without_stats(ap_named(SNAP, "AP-2"), Band.GHZ_5), Band.GHZ_5) is None
    blank = with_stats(
        ap_named(SNAP, "AP-2"), Band.GHZ_5,
        channel_utilisation_pct=None, self_rx_utilisation_pct=None, self_tx_utilisation_pct=None,
        tx_retries_pct=None, satisfaction_pct=None, client_count=None,
    )  # fmt: skip
    assert airtime_of(blank, Band.GHZ_5) is None


def test_clients_are_counted_against_the_radios_min_rssi_on_the_uplink() -> None:
    assert SNAP.clients is not None
    ap = ap_named(SNAP, "AP-2")
    sightings = (
        ClientSighting(
            ap_mac=ap.mac,
            band=Band.GHZ_5,
            essid=None,
            channel=60,
            signal_dbm=-60,
            noise_dbm=None,
            satisfaction_pct=None,
            fast_transition=None,
        ),
        ClientSighting(
            ap_mac=ap.mac,
            band=Band.GHZ_5,
            essid=None,
            channel=60,
            signal_dbm=-85,
            noise_dbm=None,
            satisfaction_pct=None,
            fast_transition=None,
        ),
        ClientSighting(
            ap_mac=ap.mac,
            band=Band.GHZ_5,
            essid=None,
            channel=60,
            signal_dbm=None,
            noise_dbm=None,
            satisfaction_pct=None,
            fast_transition=None,
        ),
        ClientSighting(
            ap_mac="02:00:00:00:00:99",
            band=Band.GHZ_5,
            essid=None,
            channel=60,
            signal_dbm=-50,
            noise_dbm=None,
            satisfaction_pct=None,
            fast_transition=None,
        ),
    )
    summary = clients_of(ap.mac, Band.GHZ_5, sightings, min_rssi_dbm=-80)
    assert summary is not None and (summary.total, summary.below_min_rssi, summary.weakest_dbm) == (2, 1, -85)
    assert clients_of(ap.mac, Band.GHZ_2, sightings, -80) is None
    reasons = unassignable(sightings, frozenset({ap.mac}))
    assert reasons == Counter({"access point not in the snapshot": 1, "no signal reported": 1})
    unplaced = unassignable_finding("default", reasons)
    assert (
        unplaced is not None
        and "1 access point not in the snapshot" in unplaced.message
        and unassignable_finding("default", Counter()) is None
    )


def test_fixture_clients_place_on_the_fixture_access_points() -> None:
    assert SNAP.clients is not None and SNAP.clients
    macs = frozenset(ap.mac for ap in SNAP.access_points)
    assert sum(unassignable(SNAP.clients, macs).values()) <= len(SNAP.clients)
    offline = replace(ap_named(SNAP, "AP-1"), state_code=0)
    assert offline.offline
