"""The neighbour matrix: direction, aggregation on the peer's primary frequency, mixed pass statuses, every
missing reason in priority order, reciprocity, the DFS evidence rule, receiver offsets, the heard graph."""

from dataclasses import replace

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from unifiwifioptimizer.analysis.neighbors import (
    NOT_RECIPROCITY_ELIGIBLE,
    BandUsage,
    NeighbourMatrix,
    PeerReading,
    asymmetric_pairs,
    build_matrix,
    heard_graph_edges,
    notable_receiver_offset,
    peers_on_band,
    reduce_band_passes,
    symmetric_neighbours,
)
from unifiwifioptimizer.domain.analysis import MissingReason, ReadingSource
from unifiwifioptimizer.domain.models import Band
from unifiwifioptimizer.domain.scan import ApScan, BandScanStatus, ScanFailure, ScanFailureKind, ScanPass
from unifiwifioptimizer.rf.constants import CCA_PREAMBLE_DETECT_DBM, RCPI_ACCURACY_DB

from .builders import (
    ap_named,
    band_scan,
    fixture_snapshot,
    foreign,
    hears,
    reading,
    scan_pass,
    site_scan,
    with_ap,
    with_stats,
    without_stats,
)

SNAP = fixture_snapshot()
FOUR = {
    "AP-1": frozenset({"AP-2"}),
    "AP-2": frozenset({"AP-1", "AP-3"}),
    "AP-3": frozenset({"AP-2", "AP-4"}),
    "AP-4": frozenset({"AP-3"}),
}
PAIR = {"AP-1": frozenset({"AP-2"})}


def cell(matrix: NeighbourMatrix, ap: str, band: Band, peer: str) -> PeerReading:
    return next(c for c in matrix.of(ap, band) if c.peer == peer)


Passes = dict[str, list[ScanPass | ScanFailure]]


def test_the_adjacency_is_symmetrised_and_one_sided_pairs_are_named() -> None:
    one_sided = {"AP-1": frozenset({"AP-2", "AP-3"}), "AP-3": frozenset({"AP-1"})}
    assert symmetric_neighbours(one_sided) == {
        "AP-1": frozenset({"AP-2", "AP-3"}),
        "AP-2": frozenset({"AP-1"}),
        "AP-3": frozenset({"AP-1"}),
    }
    assert asymmetric_pairs(one_sided) == (("AP-1", "AP-2"),)
    assert asymmetric_pairs(FOUR) == ()


def test_a_reading_is_the_subject_as_measured_at_the_peer_not_the_reverse() -> None:
    # AP-2 heard AP-1 at -70 on both bands; AP-1 heard AP-2 at -60. The cell "AP-1 at AP-2" is -70.
    scan = site_scan(
        SNAP,
        {
            "AP-2": [hears(SNAP, "AP-2", **{"AP-1": {Band.GHZ_2: -70, Band.GHZ_5: -71}})],
            "AP-1": [hears(SNAP, "AP-1", **{"AP-2": {Band.GHZ_2: -60, Band.GHZ_5: -61}})],
        },
    )
    matrix = build_matrix(SNAP, scan, PAIR, scan_skipped=False)
    one_at_two = cell(matrix, "AP-1", Band.GHZ_2, "AP-2")
    two_at_one = cell(matrix, "AP-2", Band.GHZ_2, "AP-1")
    assert (one_at_two.rssi_dbm, one_at_two.source, one_at_two.samples) == (-70, ReadingSource.MEASURED, 1)
    assert (two_at_one.rssi_dbm, two_at_one.source) == (-60, ReadingSource.MEASURED)
    assert cell(matrix, "AP-1", Band.GHZ_5, "AP-2").rssi_dbm == -71


def test_readings_are_the_median_over_passes_on_the_subjects_primary_frequency() -> None:
    passes = [
        hears(SNAP, "AP-2", **{"AP-1": {Band.GHZ_2: -70}}),
        hears(SNAP, "AP-2", **{"AP-1": {Band.GHZ_2: -64}}),
        hears(SNAP, "AP-2", **{"AP-1": {Band.GHZ_2: -40}}),
    ]
    # A fourth pass heard AP-1 on another channel (a channel move mid-run): not comparable, ignored.
    moved = scan_pass(band_scan(Band.GHZ_2, (reading(SNAP, "AP-1", Band.GHZ_2, -30, frequency=2412),)))
    matrix = build_matrix(SNAP, site_scan(SNAP, {"AP-2": [*passes, moved]}), PAIR, scan_skipped=False)
    one_at_two = cell(matrix, "AP-1", Band.GHZ_2, "AP-2")
    assert (one_at_two.rssi_dbm, one_at_two.samples) == (-64, 3)


def test_reduce_band_passes_prefers_usable_then_empty_then_the_last_status() -> None:
    ok = hears(SNAP, "AP-2", **{"AP-1": {Band.GHZ_2: -70}})
    empty = scan_pass(band_scan(Band.GHZ_2, (), BandScanStatus.EMPTY))
    ok_without_readings = scan_pass(band_scan(Band.GHZ_2, (), BandScanStatus.OK))
    failed = scan_pass(band_scan(Band.GHZ_2, (), BandScanStatus.FAILED))
    down = scan_pass(band_scan(Band.GHZ_2, (), BandScanStatus.INTERFACE_DOWN))

    def usage(*passes: ScanPass) -> BandUsage:
        return reduce_band_passes(ApScan(ap_mac="02:00:00:00:00:08", ap_name="AP-2", passes=tuple(passes)), Band.GHZ_2)

    assert usage(failed, ok, empty).status is BandScanStatus.OK and len(usage(failed, ok, empty).usable_passes) == 1
    assert usage(failed, empty).status is BandScanStatus.EMPTY
    assert usage(ok_without_readings).status is BandScanStatus.EMPTY
    assert usage(failed, down).status is BandScanStatus.INTERFACE_DOWN
    assert usage(down, failed).status is BandScanStatus.FAILED
    assert usage().status is None
    only_failures = ApScan(ap_mac="x", ap_name="AP-2", passes=(ScanFailure(kind=ScanFailureKind.TIMEOUT, detail="t"),))
    assert reduce_band_passes(only_failures, Band.GHZ_2).status is None
    assert reduce_band_passes(None, Band.GHZ_2).status is None


def test_a_pass_whose_scanner_is_in_cac_is_not_usable_on_5_ghz() -> None:
    in_cac = scan_pass(five=band_scan(Band.GHZ_5, (reading(SNAP, "AP-1", Band.GHZ_5, -60),)), cac="active")
    usage = reduce_band_passes(ApScan(ap_mac="x", ap_name="AP-2", passes=(in_cac,)), Band.GHZ_5)
    assert usage.usable_passes == () and usage.cac_active_in_every_pass is True
    # The 2.4 GHz readings of the same pass stay usable.
    two = scan_pass(two=band_scan(Band.GHZ_2, (reading(SNAP, "AP-1", Band.GHZ_2, -60),)), cac="active")
    assert reduce_band_passes(ApScan(ap_mac="x", ap_name="AP-2", passes=(two,)), Band.GHZ_2).status is BandScanStatus.OK


@pytest.mark.parametrize(
    ("make", "expected"),
    [
        ("skipped", MissingReason.SCAN_SKIPPED),
        ("self_offline", MissingReason.SELF_OFFLINE),
        ("peer_offline", MissingReason.PEER_OFFLINE),
        ("peer_unknown", MissingReason.PEER_UNKNOWN),
        ("self_dfs_wait", MissingReason.SELF_DFS_WAIT),
        ("peer_dfs_wait", MissingReason.PEER_DFS_WAIT),
        ("peer_cac_every_pass", MissingReason.PEER_DFS_WAIT),
        ("peer_scan_says_no_radio", MissingReason.PEER_NO_RADIO),
        ("peer_not_scanned", MissingReason.PEER_SCAN_FAILED),
        ("peer_interface_down", MissingReason.PEER_INTERFACE_DOWN),
        ("peer_failed", MissingReason.PEER_SCAN_FAILED),
        ("peer_empty", MissingReason.PEER_SCAN_EMPTY),
        ("no_dfs_evidence", MissingReason.NO_DFS_EVIDENCE),
        ("not_sighted", MissingReason.NOT_SIGHTED),
    ],
)
def test_every_missing_reason_in_priority_order(make: str, expected: MissingReason) -> None:
    # Subject AP-3 (5 GHz on DFS channel 104), peer AP-2. The peer's pass heard other APs but not AP-3.
    snap = SNAP
    heard_others = hears(snap, "AP-2", **{"AP-1": {Band.GHZ_2: -60, Band.GHZ_5: -60}})
    passes: Passes = {"AP-2": [heard_others]}
    neighbours = {"AP-3": frozenset({"AP-2"})}
    skipped = False
    band = Band.GHZ_5
    if make == "skipped":
        skipped = True
    elif make == "self_offline":
        snap = with_ap(snap, replace(ap_named(snap, "AP-3"), state_code=0))
    elif make == "peer_offline":
        snap = with_ap(snap, replace(ap_named(snap, "AP-2"), state_code=0))
    elif make == "peer_unknown":
        neighbours = {"AP-3": frozenset({"Ghost"})}
    elif make == "self_dfs_wait":
        snap = with_ap(snap, with_stats(ap_named(snap, "AP-3"), band, state="DFS_WAIT"))
    elif make == "peer_dfs_wait":
        snap = with_ap(snap, with_stats(ap_named(snap, "AP-2"), band, state="DFS_WAIT"))
    elif make == "peer_cac_every_pass":
        passes = {"AP-2": [scan_pass(five=band_scan(band, (reading(snap, "AP-1", band, -60),)), cac="active")]}
    elif make == "peer_scan_says_no_radio":
        # The controller lists a 5 GHz radio on AP-2, the scan found no interface for it.
        passes = {"AP-2": [scan_pass(five=band_scan(band, (), BandScanStatus.NO_RADIO))]}
    elif make == "peer_not_scanned":
        passes = {}
    elif make == "peer_interface_down":
        passes = {"AP-2": [scan_pass(five=band_scan(band, (), BandScanStatus.INTERFACE_DOWN))]}
    elif make == "peer_failed":
        passes = {"AP-2": [scan_pass(five=band_scan(band, (), BandScanStatus.FAILED))]}
    elif make == "peer_empty":
        passes = {"AP-2": [scan_pass(five=band_scan(band, (), BandScanStatus.EMPTY))]}
    elif make == "no_dfs_evidence":
        # AP-2 heard AP-1 (channel 44, not DFS) and nothing on any DFS channel.
        pass
    elif make == "not_sighted":
        # AP-2 heard a foreign BSS on DFS channel 100: the scanner can see DFS channels.
        passes = {"AP-2": [scan_pass(five=band_scan(band, (foreign(band, -80, 100),)))]}
    peer_name = "Ghost" if make == "peer_unknown" else "AP-2"
    matrix = build_matrix(snap, site_scan(snap, passes), neighbours, scan_skipped=skipped)
    c = cell(matrix, "AP-3", band, peer_name)
    assert c.rssi_dbm is None and c.source is None and c.reason is expected


def test_peers_without_a_radio_on_the_band_are_no_peers_but_unknown_and_offline_ones_stay() -> None:
    peer = ap_named(SNAP, "AP-2")
    no_5g = replace(peer, radios=tuple(r for r in peer.radios if r.band is not Band.GHZ_5))
    offline = replace(ap_named(SNAP, "AP-4"), state_code=0)
    by_name = {"AP-2": no_5g, "AP-4": offline}
    assert peers_on_band(["AP-2", "AP-4", "Ghost"], by_name, Band.GHZ_5) == ("AP-4", "Ghost")
    assert peers_on_band(["AP-2", "AP-4", "Ghost"], by_name, Band.GHZ_2) == ("AP-2", "AP-4", "Ghost")
    matrix = build_matrix(with_ap(SNAP, no_5g), None, {"AP-3": frozenset({"AP-2"})}, scan_skipped=True)
    assert matrix.of("AP-3", Band.GHZ_5) == () and [c.peer for c in matrix.of("AP-3", Band.GHZ_2)] == ["AP-2"]


def test_a_one_way_miss_is_substituted_by_reciprocity_with_the_reason_kept() -> None:
    # AP-1 heard AP-2 at -70 on 2.4 GHz; AP-2's 2.4 GHz scan failed. AP-1 runs 17 dBm, AP-2 6 dBm, so
    # AP-1 at AP-2 is predicted as -70 + 17 - 6 = -59.
    scan = site_scan(
        SNAP,
        {
            "AP-1": [hears(SNAP, "AP-1", **{"AP-2": {Band.GHZ_2: -70}})],
            "AP-2": [scan_pass(two=band_scan(Band.GHZ_2, (), BandScanStatus.FAILED))],
        },
    )
    matrix = build_matrix(SNAP, scan, PAIR, scan_skipped=False)
    predicted = cell(matrix, "AP-1", Band.GHZ_2, "AP-2")
    assert (predicted.rssi_dbm, predicted.source, predicted.reason) == (
        -59,
        ReadingSource.RECIPROCITY,
        MissingReason.PEER_SCAN_FAILED,
    )
    assert predicted.rssi_dbm is not None and not predicted.blocking
    measured = cell(matrix, "AP-2", Band.GHZ_2, "AP-1")
    assert (measured.rssi_dbm, measured.source, measured.reason) == (-70, ReadingSource.MEASURED, None)


def test_reciprocity_never_substitutes_when_the_subject_could_not_have_been_heard() -> None:
    expected = {
        MissingReason.SCAN_SKIPPED,
        MissingReason.SELF_OFFLINE,
        MissingReason.SELF_DFS_WAIT,
        MissingReason.PEER_UNKNOWN,
        MissingReason.PEER_OFFLINE,
    }
    assert expected == NOT_RECIPROCITY_ELIGIBLE
    in_cac = with_ap(SNAP, with_stats(ap_named(SNAP, "AP-1"), Band.GHZ_5, state="DFS_WAIT"))
    scan = site_scan(in_cac, {"AP-1": [hears(in_cac, "AP-1", **{"AP-2": {Band.GHZ_5: -70}})], "AP-2": [scan_pass()]})
    c = cell(build_matrix(in_cac, scan, PAIR, scan_skipped=False), "AP-1", Band.GHZ_5, "AP-2")
    assert c.rssi_dbm is None and c.reason is MissingReason.SELF_DFS_WAIT


def test_reciprocity_needs_both_effective_powers() -> None:
    no_power = with_ap(SNAP, with_stats(ap_named(SNAP, "AP-2"), Band.GHZ_2, observed_tx_dbm=None))
    scan = site_scan(
        no_power,
        {
            "AP-1": [hears(no_power, "AP-1", **{"AP-2": {Band.GHZ_2: -70}})],
            "AP-2": [scan_pass(two=band_scan(Band.GHZ_2, (), BandScanStatus.EMPTY))],
        },
    )
    c = cell(build_matrix(no_power, scan, PAIR, scan_skipped=False), "AP-1", Band.GHZ_2, "AP-2")
    assert c.rssi_dbm is None and c.reason is MissingReason.PEER_SCAN_EMPTY


def test_a_both_way_miss_is_a_verdict_not_a_blocking_peer() -> None:
    both_scanned_saw_others: Passes = {
        "AP-1": [scan_pass(two=band_scan(Band.GHZ_2, (foreign(Band.GHZ_2, -60, 1),)))],
        "AP-2": [scan_pass(two=band_scan(Band.GHZ_2, (foreign(Band.GHZ_2, -60, 6),)))],
    }
    matrix = build_matrix(SNAP, site_scan(SNAP, both_scanned_saw_others), PAIR, scan_skipped=False)
    c = cell(matrix, "AP-1", Band.GHZ_2, "AP-2")
    assert c.reason is MissingReason.NOT_SIGHTED and c.reverse_reason is MissingReason.NOT_SIGHTED
    assert c.both_way_miss and not c.blocking
    # A one-way miss without a reciprocity value blocks.
    one_way = build_matrix(
        SNAP,
        site_scan(SNAP, {"AP-2": both_scanned_saw_others["AP-2"]}),
        PAIR,
        scan_skipped=False,
    )
    one_way_cell = cell(one_way, "AP-1", Band.GHZ_2, "AP-2")
    assert one_way_cell.reason is MissingReason.NOT_SIGHTED
    assert one_way_cell.reverse_reason is MissingReason.PEER_SCAN_FAILED
    assert one_way_cell.blocking is True and not one_way_cell.both_way_miss
    unknown = cell(
        build_matrix(SNAP, None, {"AP-1": frozenset({"Ghost"})}, scan_skipped=False), "AP-1", Band.GHZ_2, "Ghost"
    )
    assert unknown.reason is MissingReason.PEER_UNKNOWN and unknown.blocking
    offline = with_ap(SNAP, replace(ap_named(SNAP, "AP-2"), state_code=0))
    assert cell(build_matrix(offline, None, PAIR, scan_skipped=False), "AP-1", Band.GHZ_2, "AP-2").blocking is False


def test_the_receiver_offset_is_carried_always_and_notable_only_at_the_rcpi_tolerance() -> None:
    # AP-1 (17 dBm) at AP-2: -70; AP-2 (6 dBm) at AP-1: -83 → offset -70 - (-83) - (17 - 6) = 2 dB.
    scan = site_scan(
        SNAP,
        {
            "AP-2": [hears(SNAP, "AP-2", **{"AP-1": {Band.GHZ_2: -70}})],
            "AP-1": [hears(SNAP, "AP-1", **{"AP-2": {Band.GHZ_2: -83}})],
        },
    )
    matrix = build_matrix(SNAP, scan, PAIR, scan_skipped=False)
    small = cell(matrix, "AP-1", Band.GHZ_2, "AP-2")
    assert small.receiver_offset_db == 2 and not notable_receiver_offset(small)
    assert cell(matrix, "AP-2", Band.GHZ_2, "AP-1").receiver_offset_db == -2
    louder = site_scan(
        SNAP,
        {
            "AP-2": [hears(SNAP, "AP-2", **{"AP-1": {Band.GHZ_2: -70}})],
            "AP-1": [hears(SNAP, "AP-1", **{"AP-2": {Band.GHZ_2: -86}})],
        },
    )
    big = cell(build_matrix(SNAP, louder, PAIR, scan_skipped=False), "AP-1", Band.GHZ_2, "AP-2")
    assert big.receiver_offset_db == RCPI_ACCURACY_DB and notable_receiver_offset(big)


def test_without_stats_the_majority_frequency_decides() -> None:
    no_stats = with_ap(SNAP, without_stats(ap_named(SNAP, "AP-1"), Band.GHZ_2))
    passes: list[ScanPass | ScanFailure] = [
        scan_pass(two=band_scan(Band.GHZ_2, (reading(no_stats, "AP-1", Band.GHZ_2, -70, frequency=2437),))),
        scan_pass(two=band_scan(Band.GHZ_2, (reading(no_stats, "AP-1", Band.GHZ_2, -72, frequency=2437),))),
        scan_pass(two=band_scan(Band.GHZ_2, (reading(no_stats, "AP-1", Band.GHZ_2, -40, frequency=2412),))),
    ]
    matrix = build_matrix(no_stats, site_scan(no_stats, {"AP-2": passes}), PAIR, scan_skipped=False)
    assert cell(matrix, "AP-1", Band.GHZ_2, "AP-2").rssi_dbm == -71


def test_the_heard_graph_covers_unconfigured_pairs_with_the_median_rule() -> None:
    # AP-1 and AP-4 are not configured neighbours; AP-4 heard AP-1 at -82 once and -90 once → median -86: no edge.
    scan = site_scan(
        SNAP,
        {
            "AP-4": [
                hears(SNAP, "AP-4", **{"AP-1": {Band.GHZ_2: -82}}),
                hears(SNAP, "AP-4", **{"AP-1": {Band.GHZ_2: -90}}),
            ],
            "AP-2": [hears(SNAP, "AP-2", **{"AP-1": {Band.GHZ_2: -70, Band.GHZ_5: -90}})],
        },
    )
    edges = heard_graph_edges(SNAP, scan, CCA_PREAMBLE_DETECT_DBM)
    assert edges[Band.GHZ_2] == {frozenset({"AP-1", "AP-2"})} and edges[Band.GHZ_5] == frozenset()
    # One reading of -82 alone (median -82) is an edge; the median rule, not a single-pass maximum, decides.
    one = site_scan(SNAP, {"AP-4": [hears(SNAP, "AP-4", **{"AP-1": {Band.GHZ_2: -82}})]})
    assert heard_graph_edges(SNAP, one, CCA_PREAMBLE_DETECT_DBM)[Band.GHZ_2] == {frozenset({"AP-1", "AP-4"})}


rssi_values = st.integers(-99, -30)


@settings(max_examples=60, deadline=None)
@given(
    heard=st.lists(
        st.tuples(
            st.sampled_from(["AP-1", "AP-2", "AP-3", "AP-4"]),
            st.sampled_from(["AP-1", "AP-2", "AP-3", "AP-4"]),
            rssi_values,
        ),
        max_size=12,
    ),
    skipped=st.booleans(),
)
def test_the_matrix_is_total_over_random_pass_sets(heard: list[tuple[str, str, int]], skipped: bool) -> None:
    passes: Passes = {name: [] for name in ("AP-1", "AP-2", "AP-3", "AP-4")}
    for scanner, subject, rssi in heard:
        if scanner != subject:
            passes[scanner].append(hears(SNAP, scanner, **{subject: {Band.GHZ_2: rssi, Band.GHZ_5: rssi}}))
    matrix = build_matrix(SNAP, site_scan(SNAP, passes), FOUR, scan_skipped=skipped)
    for name, peers in FOUR.items():
        for band in (Band.GHZ_2, Band.GHZ_5):
            cells = matrix.of(name, band)
            assert sorted(c.peer for c in cells) == sorted(peers)
            for c in cells:
                assert (c.rssi_dbm is None) == (c.source is None)
                assert c.rssi_dbm is not None or c.reason is not None
                if skipped:
                    assert c.reason is MissingReason.SCAN_SKIPPED
