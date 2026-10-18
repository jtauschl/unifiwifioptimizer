import pytest
from hypothesis import given
from hypothesis import strategies as st

from unifiwifioptimizer.rf.constants import HYSTERESIS_DOWN_DB
from unifiwifioptimizer.rf.corridor import Corridor
from unifiwifioptimizer.rf.txpower import (
    EffectiveMax,
    TxRecommendation,
    clamp_tx,
    effective_max_tx,
    predict_reverse_rssi,
    recommend_tx,
    tx_shift,
)

OBSTRUCTED = Corridor(low=-76)
rssi = st.integers(min_value=-100, max_value=-30)
corridors = st.builds(Corridor, low=st.integers(min_value=-90, max_value=-50))


def tx_ranges() -> st.SearchStrategy[tuple[int, int, int]]:
    return st.tuples(st.integers(1, 10), st.integers(10, 30)).flatmap(
        lambda r: st.tuples(st.integers(r[0], r[1]), st.just(r[0]), st.just(r[1]))
    )


# --- TX recommendation -------------------------------------------------------------------------------


def test_in_corridor_unchanged() -> None:
    # Weakest reading -73 inside [-76, -70]: no change.
    assert recommend_tx(19, 6, 23, -73, OBSTRUCTED) == TxRecommendation(recommended=19, uncapped=19)


# --- examples ------------------------------------------------------------------------------------------


@pytest.mark.parametrize("weakest", [-76, -70])
def test_a_reading_exactly_on_a_corridor_edge_changes_nothing(weakest: int) -> None:
    assert recommend_tx(10, 6, 23, weakest, OBSTRUCTED).recommended == 10


def test_a_reading_just_above_the_upper_edge_lowers_tx_by_four() -> None:
    # Centre -73, reading -69: shift -4, applied.
    assert recommend_tx(10, 6, 23, -69, OBSTRUCTED) == TxRecommendation(recommended=6, uncapped=6)


def test_a_reading_just_below_the_lower_edge_raises_tx_by_four() -> None:
    assert recommend_tx(10, 6, 23, -77, OBSTRUCTED) == TxRecommendation(recommended=14, uncapped=14)


def test_a_two_db_decrease_at_the_radio_minimum_is_suppressed() -> None:
    # Reading -60 is far above the corridor: shift -13 clamps to the minimum 6, a 2 dB step below the
    # current 8 dBm, which the 3 dB rule suppresses.
    assert recommend_tx(8, 6, 23, -60, OBSTRUCTED) == TxRecommendation(recommended=8, uncapped=-5)


def test_a_three_db_decrease_at_the_radio_minimum_is_applied() -> None:
    assert recommend_tx(9, 6, 23, -60, OBSTRUCTED).recommended == 6


def test_an_increase_is_never_suppressed_even_at_one_db() -> None:
    assert recommend_tx(22, 6, 23, -85, OBSTRUCTED) == TxRecommendation(recommended=23, uncapped=34)


def test_clamp_rejects_an_inverted_range() -> None:
    with pytest.raises(ValueError):
        clamp_tx(10, 20, 6)


@pytest.mark.parametrize(
    ("configured_max", "configured", "observed", "expected"),
    [
        (24, 24, 18, EffectiveMax(18, verified=True)),
        (24, 20, 18, EffectiveMax(18, verified=True)),
        # Observed equals configured below the maximum: the cap lies somewhere above, unverified.
        (24, 18, 18, EffectiveMax(24, verified=False)),
        (24, 12, 12, EffectiveMax(24, verified=False)),
        # Running at the configured maximum and reaching it: the maximum is demonstrated.
        (23, 23, 23, EffectiveMax(23, verified=True)),
        # An observed value above the configured one is not a physical reading and proves nothing.
        (24, 18, 20, EffectiveMax(24, verified=False)),
    ],
)
def test_effective_max_is_the_observed_cap_when_the_radio_falls_short(
    configured_max: int, configured: int, observed: int, expected: EffectiveMax
) -> None:
    assert effective_max_tx(configured_max, configured, observed) == expected


def test_reverse_rssi_follows_reciprocity() -> None:
    # A hears B at -70; A transmits 6 dB stronger than B, so B hears A at -64.
    assert predict_reverse_rssi(-70, 18, 12) == -64
    assert predict_reverse_rssi(-70, 12, 18) == -76


# --- invariants ----------------------------------------------------------------------------------------


@given(rssi, corridors)
def test_shift_moves_the_weakest_reading_exactly_to_the_centre(weakest: int, corridor: Corridor) -> None:
    assert weakest + tx_shift(weakest, corridor) == corridor.center


@given(rssi, corridors)
def test_a_shift_out_of_the_corridor_is_at_least_four_db(weakest: int, corridor: Corridor) -> None:
    # An integer reading outside [low, low + 6] is at least 4 dB from the centre low + 3.
    if not corridor.contains(weakest):
        assert abs(tx_shift(weakest, corridor)) >= 4


@given(tx_ranges(), rssi, corridors)
def test_recommendation_stays_within_the_radio_range(
    tx_range: tuple[int, int, int], weakest: int, corridor: Corridor
) -> None:
    current, min_tx, max_tx = tx_range
    assert min_tx <= recommend_tx(current, min_tx, max_tx, weakest, corridor).recommended <= max_tx


@given(tx_ranges(), rssi, corridors)
def test_decreases_are_zero_or_at_least_the_hysteresis(
    tx_range: tuple[int, int, int], weakest: int, corridor: Corridor
) -> None:
    current, min_tx, max_tx = tx_range
    delta = recommend_tx(current, min_tx, max_tx, weakest, corridor).recommended - current
    assert delta >= 0 or -delta >= HYSTERESIS_DOWN_DB


@given(tx_ranges(), rssi, corridors)
def test_a_reading_inside_the_corridor_changes_nothing(
    tx_range: tuple[int, int, int], weakest: int, corridor: Corridor
) -> None:
    current, min_tx, max_tx = tx_range
    if corridor.contains(weakest):
        assert recommend_tx(current, min_tx, max_tx, weakest, corridor) == TxRecommendation(current, current)


@given(tx_ranges(), rssi, corridors)
def test_a_reading_below_the_corridor_never_lowers_tx(
    tx_range: tuple[int, int, int], weakest: int, corridor: Corridor
) -> None:
    current, min_tx, max_tx = tx_range
    if weakest < corridor.low:
        assert recommend_tx(current, min_tx, max_tx, weakest, corridor).recommended >= current


@given(tx_ranges(), rssi, corridors)
def test_a_reading_above_the_corridor_never_raises_tx(
    tx_range: tuple[int, int, int], weakest: int, corridor: Corridor
) -> None:
    current, min_tx, max_tx = tx_range
    if weakest > corridor.high:
        assert recommend_tx(current, min_tx, max_tx, weakest, corridor).recommended <= current


@given(tx_ranges(), rssi, corridors)
def test_an_unclamped_recommendation_lands_the_reading_on_the_centre(
    tx_range: tuple[int, int, int], weakest: int, corridor: Corridor
) -> None:
    current, min_tx, max_tx = tx_range
    result = recommend_tx(current, min_tx, max_tx, weakest, corridor)
    if not corridor.contains(weakest) and not result.clamped:
        assert weakest + (result.recommended - current) == corridor.center
        assert (
            recommend_tx(result.recommended, min_tx, max_tx, corridor.center, corridor).recommended
            == result.recommended
        )


@given(st.integers(40, 110), st.integers(0, 30), st.integers(0, 30))
def test_reciprocity_predicts_the_other_direction_through_the_same_path_loss(loss: int, tx_a: int, tx_b: int) -> None:
    # A hears B at P_B - L; the same path loss L applies to what B hears of A.
    heard_by_a = tx_b - loss
    assert predict_reverse_rssi(heard_by_a, tx_a, tx_b) == tx_a - loss
