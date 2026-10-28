"""The transmit-power decision table, one test per row in table order, plus the predicates that cut across
rows (blocking peers, the effective maximum under each mode, the mesh guard) and the ported shell cases."""

from dataclasses import replace

import pytest
from hypothesis import example, given, settings
from hypothesis import strategies as st

from unifiwifioptimizer.analysis.neighbors import PeerReading
from unifiwifioptimizer.analysis.txpower import (
    BandTxResult,
    analyse_band_tx,
    apply_mesh_guard,
    effective_maximum,
    summarise,
)
from unifiwifioptimizer.domain.analysis import BandTxOutcome, MissingReason, NeighbourMarker, ReadingSource
from unifiwifioptimizer.domain.models import AccessPoint, Band, TxPowerMode
from unifiwifioptimizer.domain.report import RecommendationKind, Severity
from unifiwifioptimizer.rf.constants import HYSTERESIS_DOWN_DB
from unifiwifioptimizer.rf.corridor import Corridor
from unifiwifioptimizer.rf.txpower import effective_max_tx

from .builders import ap_named, fixture_snapshot, with_radio, with_stats, without_stats

SNAP = fixture_snapshot()
FIVE = Corridor(low=-67)
TWO = Corridor(low=-73)


def measured(peer: str, rssi: int, band: Band = Band.GHZ_5) -> PeerReading:
    return PeerReading(peer=peer, band=band, rssi_dbm=rssi, source=ReadingSource.MEASURED, samples=1, reason=None)


def predicted(peer: str, rssi: int, band: Band = Band.GHZ_5) -> PeerReading:
    return PeerReading(
        peer=peer,
        band=band,
        rssi_dbm=rssi,
        source=ReadingSource.RECIPROCITY,
        samples=0,
        reason=MissingReason.PEER_SCAN_FAILED,
    )


def missing(peer: str, reason: MissingReason, band: Band = Band.GHZ_5) -> PeerReading:
    """A cell without a value; a `NOT_SIGHTED` cell is a both-way miss (the reverse direction missed too)."""
    reverse = MissingReason.NOT_SIGHTED if reason is MissingReason.NOT_SIGHTED else None
    return PeerReading(
        peer=peer, band=band, rssi_dbm=None, source=None, samples=0, reason=reason, reverse_reason=reverse
    )


def custom(
    name: str, band: Band, current: int, configured: int | None = None, max_tx: int = 24, min_tx: int = 6
) -> AccessPoint:
    """The fixture AP with its radio set to Custom at `configured` (defaults to `current`) and the given range."""
    ap = ap_named(SNAP, name)
    ap = with_radio(
        ap,
        band,
        tx_power_mode=TxPowerMode.CUSTOM,
        configured_tx_dbm=configured or current,
        min_tx_dbm=min_tx,
        max_tx_dbm=max_tx,
    )
    return with_stats(ap, band, observed_tx_dbm=current, state="RUN")


def auto(name: str, band: Band, current: int, configured: int, max_tx: int = 24) -> AccessPoint:
    ap = with_radio(
        ap_named(SNAP, name), band, tx_power_mode=TxPowerMode.AUTO, configured_tx_dbm=configured, max_tx_dbm=max_tx
    )
    return with_stats(ap, band, observed_tx_dbm=current, state="RUN")


def run(
    ap: AccessPoint, cells: list[PeerReading], corridor: Corridor = FIVE, band: Band = Band.GHZ_5, skipped: bool = False
) -> BandTxResult:
    return analyse_band_tx(ap, band, cells, corridor, scan_skipped=skipped)


def codes(result: BandTxResult) -> list[str]:
    return [f.code for f in result.findings]


# --- the effective maximum -----------------------------------------------------------------------------------


def test_the_effective_maximum_follows_the_configured_power_only_under_custom() -> None:
    capped = summarise(custom("AP-2", Band.GHZ_5, current=18, configured=24, max_tx=24), Band.GHZ_5)
    assert (capped.effective_max_dbm, capped.effective_max_verified) == (18, True)
    at_configured_max = summarise(custom("AP-3", Band.GHZ_5, current=23, configured=23, max_tx=23), Band.GHZ_5)
    assert (at_configured_max.effective_max_dbm, at_configured_max.effective_max_verified) == (23, True)
    below_max = summarise(custom("AP-3", Band.GHZ_5, current=15, configured=15, max_tx=23), Band.GHZ_5)
    assert (below_max.effective_max_dbm, below_max.effective_max_verified) == (23, False)
    # Fixture AP-1: auto, configured 19 below the observed 20 — never a cap, never verified.
    stale = summarise(ap_named(SNAP, "AP-1"), Band.GHZ_5)
    assert (stale.mode, stale.configured_dbm, stale.effective_dbm) == (TxPowerMode.AUTO, 19, 20)
    assert (stale.effective_max_dbm, stale.effective_max_verified) == (23, False)
    no_configured = summarise(
        with_radio(custom("AP-3", Band.GHZ_5, 15), Band.GHZ_5, configured_tx_dbm=None), Band.GHZ_5
    )
    assert (no_configured.effective_max_dbm, no_configured.effective_max_verified) == (24, False)
    assert effective_maximum(summarise(without_stats(ap_named(SNAP, "AP-3"), Band.GHZ_5), Band.GHZ_5)) is None


def test_auto_mode_with_a_stale_configured_power_above_the_effective_one_is_never_a_coverage_gap() -> None:
    # Configured 19 while running 18: under Custom this would be a verified cap at 18; under auto it is not.
    ap = auto("AP-1", Band.GHZ_5, current=18, configured=19, max_tx=23)
    result = run(ap, [measured("AP-2", -80)])
    assert result.outcome is BandTxOutcome.RAISE_TO_MAXIMUM
    assert result.recommendation is not None and result.recommendation.recommended == 23
    assert result.recommendation.unverified_headroom is True and "headroom_unverified" in codes(result)
    assert result.recommendation.current_mode is TxPowerMode.AUTO


# --- rows 1-5 -------------------------------------------------------------------------------------------------


def test_row_1_scan_skipped_judges_nothing() -> None:
    result = run(ap_named(SNAP, "AP-3"), [missing("AP-2", MissingReason.SCAN_SKIPPED)], skipped=True)
    assert result.outcome is BandTxOutcome.SCAN_SKIPPED and result.recommendation is None and result.findings == ()


def test_row_2_an_offline_access_point_judges_nothing() -> None:
    result = run(replace(ap_named(SNAP, "AP-3"), state_code=0), [measured("AP-2", -70)])
    assert result.outcome is BandTxOutcome.OFFLINE and result.recommendation is None and result.findings == ()


def test_row_3_a_radio_in_cac_gets_the_info_with_the_channel_aware_wait() -> None:
    weather = with_stats(ap_named(SNAP, "AP-3"), Band.GHZ_5, state="DFS_WAIT", channel=124, width_mhz=20)
    result = run(weather, [measured("AP-2", -70)])
    assert result.outcome is BandTxOutcome.DFS_WAIT and result.recommendation is None
    (info,) = result.findings
    assert info.severity is Severity.INFO and info.code == "dfs_cac" and "channel 124" in info.message
    assert "up to 600 s" in info.message
    sixty = with_stats(ap_named(SNAP, "AP-3"), Band.GHZ_5, state="DFS_WAIT", channel=104, width_mhz=20)
    assert "up to 60 s" in run(sixty, [measured("AP-2", -70)]).findings[0].message


@pytest.mark.parametrize(
    ("make", "expect"),
    [
        (lambda ap: with_stats(ap, Band.GHZ_5, observed_tx_dbm=None), "tx_power"),
        (lambda ap: with_radio(ap, Band.GHZ_5, min_tx_dbm=None), "min_txpower"),
        (lambda ap: with_radio(ap, Band.GHZ_5, max_tx_dbm=None), "max_txpower"),
        (lambda ap: with_stats(ap, Band.GHZ_5, observed_tx_dbm=30), "outside the setting range 6..24"),
        (
            lambda ap: with_stats(
                with_radio(ap, Band.GHZ_5, tx_power_mode=TxPowerMode.AUTO), Band.GHZ_5, observed_tx_dbm=3
            ),
            "outside",
        ),
    ],
)
def test_row_4_missing_or_inconsistent_numbers_are_not_evaluable_without_defaults(make, expect: str) -> None:  # type: ignore[no-untyped-def]
    result = run(make(custom("AP-4", Band.GHZ_5, 18, 24)), [measured("AP-2", -70)])
    assert result.outcome is BandTxOutcome.NOT_EVALUABLE and result.recommendation is None
    (warning,) = result.findings
    assert warning.severity is Severity.WARNING and warning.code == "tx_not_evaluable" and expect in warning.message


@pytest.mark.parametrize(
    ("observed", "gain", "hint"),
    [(30, 5, True), (29, 5, True), (31, 5, False), (30, None, False), (30, 0, False)],
)
def test_row_4_names_an_eirp_only_where_the_reading_fits_the_setting_range_plus_the_antenna(
    observed: int, gain: int | None, hint: bool
) -> None:
    ap = with_stats(
        with_radio(custom("AP-4", Band.GHZ_5, 18, 24), Band.GHZ_5, antenna_gain_dbi=gain),
        Band.GHZ_5,
        observed_tx_dbm=observed,
    )
    (warning,) = run(ap, [measured("AP-2", -70)]).findings
    assert f"the controller reports {observed} dBm, outside the setting range 6..24 dBm" in warning.message
    assert ("as an EIRP it would fit 24 dBm plus 5 dBi" in warning.message) is hint


def test_row_5_no_peer_on_the_band_emits_nothing() -> None:
    result = run(custom("AP-3", Band.GHZ_5, 15), [])
    assert result.outcome is BandTxOutcome.NO_PEERS and result.recommendation is None and result.findings == ()


# --- row 6: a miss in both directions -------------------------------------------------------------------------


def test_zero_sightings_with_peer_goes_to_max() -> None:
    # No sighting of the configured peer in either direction, radio below its maximum.
    result = run(custom("AP-3", Band.GHZ_5, 15, max_tx=23), [missing("AP-2", MissingReason.NOT_SIGHTED)])
    assert result.outcome is BandTxOutcome.NO_SIGHTING
    rec = result.recommendation
    assert rec is not None and (rec.recommended, rec.kind) == (23, RecommendationKind.CHANGE)
    assert rec.unverified_headroom is True and "AP-2" in rec.reason and codes(result) == []


def test_zero_sightings_no_peer_unchanged() -> None:
    # Without a configured peer there is no target to reach.
    assert run(custom("AP-3", Band.GHZ_5, 15), []).recommendation is None


def test_row_6_at_the_maximum_is_a_coverage_gap_held_and_every_missed_peer_is_named() -> None:
    at_max = custom("AP-2", Band.GHZ_5, current=18, configured=24, max_tx=24)
    cells = [
        missing("AP-1", MissingReason.NOT_SIGHTED),
        measured("AP-3", -66),
        missing("AP-4", MissingReason.NOT_SIGHTED),
    ]
    result = run(at_max, cells)
    assert result.outcome is BandTxOutcome.NO_SIGHTING
    assert result.recommendation is not None and result.recommendation.kind is RecommendationKind.HELD
    gap = next(f for f in result.findings if f.code == "coverage_gap")
    assert gap.severity is Severity.WARNING and gap.peers == ("AP-1", "AP-4") and "18 dBm" in gap.message
    # The both-way misses are row 6's own evidence, not blocking peers.
    assert "peers_not_evaluated" not in codes(result)


def test_row_6_wins_over_other_peers_but_a_blocking_peer_is_still_named() -> None:
    cells = [missing("AP-1", MissingReason.NOT_SIGHTED), missing("AP-4", MissingReason.PEER_SCAN_FAILED)]
    result = run(custom("AP-3", Band.GHZ_5, 15, max_tx=23), cells)
    assert result.outcome is BandTxOutcome.NO_SIGHTING and codes(result) == ["peers_not_evaluated"]
    assert result.findings[0].peers == ("AP-4",)


# --- row 7: nothing evaluable ---------------------------------------------------------------------------------


def test_row_7_a_one_way_miss_without_reciprocity_is_not_evaluable_never_the_maximum() -> None:
    # B scanned and did not hear A; A's own scan failed, so no reverse reading exists (round-2 B1 hole).
    cells = [missing("AP-2", MissingReason.PEER_SCAN_FAILED)]
    result = run(custom("AP-3", Band.GHZ_5, 15, max_tx=23), cells)
    assert result.outcome is BandTxOutcome.NOT_EVALUABLE and result.recommendation is None
    (warning,) = result.findings
    assert (
        warning.code == "peers_not_evaluated" and warning.peers == ("AP-2",) and "peer scan failed" in warning.message
    )
    mixed = [missing("AP-2", MissingReason.PEER_SCAN_EMPTY), missing("AP-4", MissingReason.PEER_UNKNOWN)]
    assert run(custom("AP-3", Band.GHZ_5, 15), mixed).outcome is BandTxOutcome.NOT_EVALUABLE
    only_offline = [missing("AP-2", MissingReason.PEER_OFFLINE)]
    assert run(custom("AP-3", Band.GHZ_5, 15), only_offline).outcome is BandTxOutcome.NOT_EVALUABLE


# --- rows 8/9: inside the corridor ----------------------------------------------------------------------------


def test_in_corridor_unchanged() -> None:
    # CONFIRMED only when every peer on the band is evaluable.
    result = run(custom("AP-3", Band.GHZ_5, 15), [measured("AP-2", -65), predicted("AP-4", -62)])
    assert result.outcome is BandTxOutcome.IN_CORRIDOR
    rec = result.recommendation
    assert rec is not None and (rec.current, rec.recommended, rec.kind) == (15, 15, RecommendationKind.CONFIRMED)
    assert result.findings == () and result.markers == {}


def test_row_9_in_corridor_with_a_blocking_peer_is_held_not_confirmed() -> None:
    cells = [measured("AP-2", -65), missing("AP-4", MissingReason.PEER_UNKNOWN)]
    result = run(custom("AP-3", Band.GHZ_5, 15), cells)
    assert result.outcome is BandTxOutcome.IN_CORRIDOR_PARTIAL
    assert result.recommendation is not None and result.recommendation.kind is RecommendationKind.HELD
    (warning,) = result.findings
    assert warning.code == "peers_not_evaluated" and warning.peers == ("AP-4",) and "peer unknown" in warning.message
    # An offline peer is neither blocking nor dropped: CONFIRMED stays possible.
    with_offline = [measured("AP-2", -65), missing("AP-4", MissingReason.PEER_OFFLINE)]
    assert run(custom("AP-3", Band.GHZ_5, 15), with_offline).outcome is BandTxOutcome.IN_CORRIDOR


# --- rows 10/11: the corridor is out of reach upwards ---------------------------------------------------------


def test_row_10_at_a_verified_cap_the_gap_is_a_design_finding_with_the_shortfall() -> None:
    # AP-2 5 GHz: configured 24, runs 18 (regulatory cap), weakest neighbour -76: 9 dB below the edge.
    result = run(
        custom("AP-2", Band.GHZ_5, current=18, configured=24, max_tx=24), [measured("AP-3", -76), measured("AP-1", -66)]
    )
    assert result.outcome is BandTxOutcome.COVERAGE_GAP
    assert result.recommendation is not None and result.recommendation.kind is RecommendationKind.HELD
    (gap,) = result.findings
    assert (
        gap.code == "coverage_gap"
        and gap.peers == ("AP-3",)
        and "9 dB short" in gap.message
        and "cell edge" in gap.message
    )
    assert result.markers == {"AP-3": NeighbourMarker.BELOW_UNFIXABLE}


def test_row_10_at_the_maximum_under_auto_is_a_coverage_gap_too_not_a_phantom_change() -> None:
    result = run(auto("AP-1", Band.GHZ_5, current=23, configured=19, max_tx=23), [measured("AP-2", -80)])
    assert result.outcome is BandTxOutcome.COVERAGE_GAP
    assert result.recommendation is not None and result.recommendation.kind is RecommendationKind.HELD
    assert result.recommendation.is_change is False


def test_row_10_uses_the_band_wording_on_2_4_ghz() -> None:
    result = run(
        custom("AP-3", Band.GHZ_2, current=23, configured=23, max_tx=23),
        [measured("AP-2", -90, Band.GHZ_2)],
        TWO,
        Band.GHZ_2,
    )
    assert result.outcome is BandTxOutcome.COVERAGE_GAP and "2.4 GHz corridor floor" in result.findings[0].message


def test_row_11_below_the_maximum_recommends_the_maximum_and_marks_unverified_headroom() -> None:
    result = run(custom("AP-3", Band.GHZ_5, current=15, configured=15, max_tx=23), [measured("AP-2", -80)])
    assert result.outcome is BandTxOutcome.RAISE_TO_MAXIMUM
    rec = result.recommendation
    assert rec is not None and (rec.recommended, rec.kind, rec.unverified_headroom) == (
        23,
        RecommendationKind.CHANGE,
        True,
    )
    assert codes(result) == ["headroom_unverified"]
    assert result.markers == {"AP-2": NeighbourMarker.BELOW_UNFIXABLE}


def test_row_11_with_a_blocking_peer_still_raises_and_names_the_peer() -> None:
    cells = [measured("AP-2", -80), missing("AP-4", MissingReason.PEER_SCAN_EMPTY)]
    result = run(custom("AP-3", Band.GHZ_5, 15, max_tx=23), cells)
    assert result.outcome is BandTxOutcome.RAISE_TO_MAXIMUM and result.recommendation is not None
    assert result.recommendation.is_change and set(codes(result)) == {"peers_not_evaluated", "headroom_unverified"}


# --- row 12: too strong at the minimum ------------------------------------------------------------------------


def test_row_12_too_strong_at_the_minimum_names_the_neighbours_and_the_excess() -> None:
    # Weakest -50 at 11 dBm: at the minimum 6 dBm it would still read -55, 6 dB above the corridor top -61.
    result = run(
        custom("AP-3", Band.GHZ_5, current=11, configured=11, max_tx=23), [measured("AP-2", -50), measured("AP-4", -40)]
    )
    assert result.outcome is BandTxOutcome.TOO_STRONG_AT_MINIMUM
    (warning,) = result.findings
    assert (
        warning.code == "too_strong_at_minimum"
        and warning.peers == ("AP-2", "AP-4")
        and "6 dB above" in warning.message
    )
    rec = result.recommendation
    assert rec is not None and (rec.recommended, rec.kind) == (6, RecommendationKind.CHANGE)
    assert result.markers == {"AP-2": NeighbourMarker.ABOVE_UNFIXABLE, "AP-4": NeighbourMarker.ABOVE_UNFIXABLE}


def test_row_12_already_at_the_minimum_is_held_with_the_real_reason() -> None:
    result = run(custom("AP-3", Band.GHZ_5, current=6, configured=6, max_tx=23), [measured("AP-2", -50)])
    assert result.outcome is BandTxOutcome.TOO_STRONG_AT_MINIMUM
    rec = result.recommendation
    assert rec is not None and rec.kind is RecommendationKind.HELD and "minimum" in rec.reason
    hysteresis = run(custom("AP-3", Band.GHZ_5, current=8, configured=8, max_tx=23), [measured("AP-2", -50)])
    assert hysteresis.recommendation is not None and hysteresis.recommendation.kind is RecommendationKind.HELD
    assert f"{HYSTERESIS_DOWN_DB} dB" in hysteresis.recommendation.reason


def test_row_12_with_a_blocking_peer_blocks_the_reduction_or_holds_without_a_too_strong_claim() -> None:
    cells = [measured("AP-2", -50), missing("AP-4", MissingReason.PEER_UNKNOWN)]
    blocked = run(custom("AP-3", Band.GHZ_5, 11, max_tx=23), cells)
    assert blocked.outcome is BandTxOutcome.REDUCTION_BLOCKED
    assert blocked.recommendation is not None and blocked.recommendation.kind is RecommendationKind.HELD
    assert codes(blocked) == ["reduction_blocked"] and blocked.findings[0].peers == ("AP-4",)
    at_min = run(custom("AP-3", Band.GHZ_5, 6, max_tx=23), cells)
    assert at_min.outcome is BandTxOutcome.OUT_OF_CORRIDOR and codes(at_min) == ["peers_not_evaluated"]
    under_hysteresis = run(custom("AP-3", Band.GHZ_5, 8, max_tx=23), cells)
    assert under_hysteresis.outcome is BandTxOutcome.OUT_OF_CORRIDOR
    assert under_hysteresis.recommendation is not None and "hysteresis" in under_hysteresis.recommendation.reason


# --- row 13 ---------------------------------------------------------------------------------------------------


def test_row_13_an_ordinary_change_in_either_direction() -> None:
    up = run(custom("AP-3", Band.GHZ_5, 15, max_tx=23), [measured("AP-2", -70)])
    assert up.outcome is BandTxOutcome.OUT_OF_CORRIDOR and up.recommendation is not None
    assert (up.recommendation.recommended, up.recommendation.kind) == (21, RecommendationKind.CHANGE)
    assert up.recommendation.unverified_headroom is True and up.markers == {"AP-2": NeighbourMarker.BELOW_FIXED}
    down = run(custom("AP-3", Band.GHZ_5, 15, max_tx=23), [measured("AP-2", -58)])
    assert down.recommendation is not None and (down.recommendation.recommended, down.recommendation.kind) == (
        9,
        RecommendationKind.CHANGE,
    )
    assert down.recommendation.unverified_headroom is False and down.markers == {}


def test_row_13_a_reduction_with_a_blocking_peer_is_blocked_and_an_increase_is_not() -> None:
    cells_down = [measured("AP-2", -58), missing("AP-4", MissingReason.PEER_INTERFACE_DOWN)]
    blocked = run(custom("AP-3", Band.GHZ_5, 15, max_tx=23), cells_down)
    assert blocked.outcome is BandTxOutcome.REDUCTION_BLOCKED and codes(blocked) == ["reduction_blocked"]
    assert blocked.recommendation is not None and blocked.recommendation.kind is RecommendationKind.HELD
    assert "peer interface down" in blocked.findings[0].message
    cells_up = [measured("AP-2", -70), missing("AP-4", MissingReason.PEER_INTERFACE_DOWN)]
    raised = run(custom("AP-3", Band.GHZ_5, 15, max_tx=23), cells_up)
    assert raised.outcome is BandTxOutcome.OUT_OF_CORRIDOR and raised.recommendation is not None
    assert raised.recommendation.is_change and codes(raised) == ["peers_not_evaluated"]


def test_row_13_a_reduction_held_by_hysteresis_says_so() -> None:
    # Weakest -59 is 2 dB above the top (-61): shift -5 would land at 10, clamped to the minimum 6 → delta -9?
    # Use a radio whose minimum is just below: current 8, min 6 → reduction 2 dB, dropped.
    result = run(custom("AP-3", Band.GHZ_5, 8, min_tx=6, max_tx=23), [measured("AP-2", -60)])
    assert result.outcome is BandTxOutcome.OUT_OF_CORRIDOR and result.recommendation is not None
    assert result.recommendation.kind is RecommendationKind.HELD and "hysteresis" in result.recommendation.reason


# --- the mesh guard -------------------------------------------------------------------------------------------


def test_the_mesh_guard_turns_a_reduction_into_a_held_recommendation_and_leaves_increases_alone() -> None:
    ap = custom("AP-3", Band.GHZ_5, 15, max_tx=23)
    reduction = run(ap, [measured("AP-2", -58)])
    guarded = apply_mesh_guard(ap, Band.GHZ_5, reduction)
    assert guarded.outcome is reduction.outcome and guarded.recommendation is not None
    assert (guarded.recommendation.recommended, guarded.recommendation.kind) == (15, RecommendationKind.HELD)
    assert codes(guarded) == ["mesh_uplink_guard"] and guarded.recommendation.is_change is False
    increase = run(ap, [measured("AP-2", -70)])
    assert apply_mesh_guard(ap, Band.GHZ_5, increase) == increase


def test_row_13_hold_names_the_dropped_reduction_and_marks_only_a_neighbour_too_strong_at_the_minimum() -> None:
    custom = with_stats(
        with_radio(
            ap_named(SNAP, "AP-3"),
            Band.GHZ_5,
            tx_power_mode=TxPowerMode.CUSTOM,
            configured_tx_dbm=10,
            min_tx_dbm=8,
            max_tx_dbm=24,
        ),
        Band.GHZ_5,
        observed_tx_dbm=10,
        state="RUN",
    )
    # Weakest -59 against -67..-61: the shift to the centre (-5 dB) clamps at the minimum 8 dBm, a 2 dB reduction
    # under the 3 dB step; at 8 dBm the neighbour would read -61, inside the corridor — fixable, no marker.
    held = analyse_band_tx(custom, Band.GHZ_5, [measured("AP-2", -59)], FIVE, scan_skipped=False)
    assert held.outcome is BandTxOutcome.OUT_OF_CORRIDOR and held.recommendation is not None
    assert held.recommendation.kind is RecommendationKind.HELD and held.recommendation.recommended == 10
    assert held.recommendation.reason == (
        f"held by hysteresis (the 2 dB reduction to the minimum 8 dBm is below the {HYSTERESIS_DOWN_DB} dB step)"
    )
    assert held.markers == {}
    # One dB stronger and the neighbour stays above the corridor even at the minimum: row 12 with the marker.
    too_strong = analyse_band_tx(custom, Band.GHZ_5, [measured("AP-2", -58)], FIVE, scan_skipped=False)
    assert too_strong.outcome is BandTxOutcome.TOO_STRONG_AT_MINIMUM
    assert too_strong.markers == {"AP-2": NeighbourMarker.ABOVE_UNFIXABLE}


# --- properties -----------------------------------------------------------------------------------------------

peer_cells = st.lists(
    st.one_of(
        st.builds(measured, st.sampled_from(["AP-1", "AP-2", "AP-4"]), st.integers(-99, -30)),
        st.builds(missing, st.sampled_from(["AP-1", "AP-2", "AP-4"]), st.sampled_from(list(MissingReason))),
    ),
    max_size=4,
)
# Current, minimum and maximum drawn independently, so the out-of-range inputs of row 4 occur; the configured
# value is independent as well (None, below, equal to or above the effective power), so the capped Custom path
# (observed below configured) occurs too.
radios = st.tuples(st.integers(1, 30), st.integers(1, 10), st.integers(10, 30))
configured_values = st.one_of(st.none(), st.integers(1, 30))


@settings(max_examples=200, deadline=None)
@given(
    cells=peer_cells,
    radio=radios,
    configured=configured_values,
    mode=st.sampled_from(list(TxPowerMode)),
    low=st.integers(-85, -55),
)
# Custom at the configured maximum, running at it: the maximum is demonstrated, hence verified.
@example(cells=[measured("AP-2", -70)], radio=(20, 5, 20), configured=20, mode=TxPowerMode.CUSTOM, low=-67)
# Custom below the configured value: the demonstrated power is the verified cap.
@example(cells=[measured("AP-2", -70)], radio=(18, 5, 24), configured=24, mode=TxPowerMode.CUSTOM, low=-67)
def test_exactly_one_outcome_never_raises_and_the_recommendation_stays_in_range(
    cells: list[PeerReading], radio: tuple[int, int, int], configured: int | None, mode: TxPowerMode, low: int
) -> None:
    current, min_tx, max_tx = radio
    ap = with_stats(
        with_radio(
            ap_named(SNAP, "AP-3"),
            Band.GHZ_5,
            tx_power_mode=mode,
            configured_tx_dbm=configured,
            min_tx_dbm=min_tx,
            max_tx_dbm=max_tx,
        ),
        Band.GHZ_5,
        observed_tx_dbm=current,
        state="RUN",
    )
    result = analyse_band_tx(ap, Band.GHZ_5, cells, Corridor(low=low), scan_skipped=False)
    assert result.outcome in BandTxOutcome
    rec = result.recommendation
    if not min_tx <= current <= max_tx:
        assert result.outcome is BandTxOutcome.NOT_EVALUABLE and rec is None
    if rec is not None:
        effective_max = result.summary.effective_max_dbm
        assert effective_max is not None and min_tx <= rec.recommended <= effective_max <= max_tx
        if mode is TxPowerMode.CUSTOM and configured is not None:
            cap = effective_max_tx(max_tx, configured, current)
            assert (effective_max, result.summary.effective_max_verified) == (cap.dbm, cap.verified)
        else:
            assert effective_max == max_tx and result.summary.effective_max_verified is False
        assert rec.is_change == (rec.recommended != rec.current)
        blocking = [c for c in cells if c.blocking]
        if rec.recommended < current or rec.kind is RecommendationKind.CONFIRMED:
            assert blocking == []
        if rec.kind is RecommendationKind.CONFIRMED:
            assert result.outcome is BandTxOutcome.IN_CORRIDOR
    if result.outcome is BandTxOutcome.TOO_STRONG_AT_MINIMUM:
        assert not any(c.blocking for c in cells)
    if result.outcome is BandTxOutcome.NO_SIGHTING:
        assert any(c.both_way_miss for c in cells)
