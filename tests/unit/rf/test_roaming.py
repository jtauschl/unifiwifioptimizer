import pytest
from hypothesis import given
from hypothesis import strategies as st

from unifiwifioptimizer.domain.analysis import RoamingCap
from unifiwifioptimizer.rf.corridor import Corridor
from unifiwifioptimizer.rf.roaming import RoamingRecommendation, RoamingTunables, recommend_roaming

RESIDENTIAL = Corridor(low=-73)
TEST_TUNABLES = RoamingTunables(offset_db=0, margin_db=5, floor_dbm=-78, ceiling_dbm=-67)
# Equal AP and client power: uplink == downlink, so the expected values read directly as downlink values.
EQUAL_POWER = 15


def tunables() -> st.SearchStrategy[RoamingTunables]:
    return st.tuples(st.integers(-95, -51), st.integers(0, 30), st.integers(0, 30)).flatmap(
        lambda t: st.builds(
            RoamingTunables,
            offset_db=st.just(t[1]),
            margin_db=st.just(t[2]),
            floor_dbm=st.just(t[0]),
            ceiling_dbm=st.integers(t[0] + 1, -50),
        )
    )


# --- Roaming Assistant threshold derivation ------------------------------------------------------------


def test_calculate_roaming_recommendation_default() -> None:
    result = recommend_roaming(RESIDENTIAL, None, EQUAL_POWER, EQUAL_POWER, TEST_TUNABLES)
    assert result == RoamingRecommendation(-73, -73, RoamingCap.NONE, None)


def test_calculate_roaming_recommendation_margin_cap() -> None:
    # Weakest neighbour -76 is below TX_LO -73: -76 - 5 = -81, clamped to the floor -78.
    result = recommend_roaming(RESIDENTIAL, -76, EQUAL_POWER, EQUAL_POWER, TEST_TUNABLES)
    assert result == RoamingRecommendation(-78, -78, RoamingCap.FLOOR, -81)


# --- examples ------------------------------------------------------------------------------------------


def test_default_tunables_are_the_documented_values() -> None:
    assert RoamingTunables() == RoamingTunables(offset_db=0, margin_db=5, floor_dbm=-75, ceiling_dbm=-65)


def test_tunable_range_bounds_are_accepted() -> None:
    assert RoamingTunables(offset_db=30, margin_db=30, floor_dbm=-95, ceiling_dbm=-50).floor_dbm == -95
    assert RoamingTunables(offset_db=0, margin_db=0, floor_dbm=-51, ceiling_dbm=-50).ceiling_dbm == -50


def test_cap_values_are_the_report_vocabulary() -> None:
    assert [c.value for c in RoamingCap] == ["none", "capped_by_margin", "capped_by_floor"]


def test_margin_cap_above_the_floor_is_reported_as_margin() -> None:
    deep_floor = RoamingTunables(offset_db=0, margin_db=5, floor_dbm=-85, ceiling_dbm=-67)
    result = recommend_roaming(RESIDENTIAL, -74, EQUAL_POWER, EQUAL_POWER, deep_floor)
    assert result == RoamingRecommendation(-79, -79, RoamingCap.MARGIN, -79)


def test_a_neighbour_inside_the_corridor_does_not_cap() -> None:
    assert recommend_roaming(RESIDENTIAL, -73, EQUAL_POWER, EQUAL_POWER, TEST_TUNABLES).cap is RoamingCap.NONE
    assert recommend_roaming(RESIDENTIAL, -60, EQUAL_POWER, EQUAL_POWER, TEST_TUNABLES).cap is RoamingCap.NONE


def test_uplink_value_accounts_for_the_power_difference() -> None:
    # 5 GHz radio at 18 dBm, client at 15 dBm: the controller must be set 3 dB lower than the client trigger.
    result = recommend_roaming(Corridor(low=-67), None, tx_eff_ap_dbm=18, client_tx_dbm=15)
    assert (result.downlink_dbm, result.uplink_dbm) == (-67, -70)
    # 2.4 GHz radio at 6 dBm: the uplink arrives 9 dB stronger, so the setting is 9 dB higher.
    result = recommend_roaming(RESIDENTIAL, None, tx_eff_ap_dbm=6, client_tx_dbm=15)
    assert (result.downlink_dbm, result.uplink_dbm) == (-73, -64)


def test_offset_raises_the_default_threshold() -> None:
    # Offset 9 at Obstructed reproduces the legacy -67 dBm target; a negative direction would give -85.
    result = recommend_roaming(Corridor(low=-76), None, EQUAL_POWER, EQUAL_POWER, RoamingTunables(offset_db=9))
    assert result.downlink_dbm == -67


def test_ceiling_clamps_a_high_default() -> None:
    assert recommend_roaming(Corridor(low=-60), None, EQUAL_POWER, EQUAL_POWER).downlink_dbm == -65


@pytest.mark.parametrize(
    "kwargs",
    [
        {"offset_db": -1},
        {"offset_db": 31},
        {"margin_db": 31},
        {"floor_dbm": -96},
        {"ceiling_dbm": -49},
        {"floor_dbm": -65, "ceiling_dbm": -65},
        {"floor_dbm": -60, "ceiling_dbm": -70},
    ],
)
def test_tunables_outside_their_ranges_are_rejected(kwargs: dict[str, int]) -> None:
    with pytest.raises(ValueError):
        RoamingTunables(**kwargs)


def test_range_messages_name_the_inclusive_bounds() -> None:
    with pytest.raises(ValueError, match=r"0\.\.30 dB"):
        RoamingTunables(offset_db=31)
    with pytest.raises(ValueError, match=r"-95\.\.-50 dBm"):
        RoamingTunables(floor_dbm=-96)


# --- invariants ----------------------------------------------------------------------------------------


@given(
    st.integers(-90, -50),
    st.one_of(st.none(), st.integers(-100, -30)),
    st.integers(0, 30),
    st.integers(0, 30),
    tunables(),
)
def test_downlink_threshold_lies_within_floor_and_ceiling(
    low: int, weakest: int | None, tx_ap: int, client: int, t: RoamingTunables
) -> None:
    result = recommend_roaming(Corridor(low=low), weakest, tx_ap, client, t)
    assert t.floor_dbm <= result.downlink_dbm <= t.ceiling_dbm
    assert result.uplink_dbm == result.downlink_dbm - (tx_ap - client)


@given(st.integers(-90, -50), st.integers(-100, -30), st.integers(0, 40), tunables())
def test_threshold_is_monotone_in_the_weakest_neighbour(low: int, weakest: int, step: int, t: RoamingTunables) -> None:
    corridor = Corridor(low=low)
    lower = recommend_roaming(corridor, weakest, EQUAL_POWER, EQUAL_POWER, t).downlink_dbm
    higher = recommend_roaming(corridor, weakest + step, EQUAL_POWER, EQUAL_POWER, t).downlink_dbm
    assert lower <= higher


@given(st.integers(-90, -50), st.one_of(st.none(), st.integers(-100, -30)), tunables())
def test_threshold_never_exceeds_the_uncapped_default(low: int, weakest: int | None, t: RoamingTunables) -> None:
    result = recommend_roaming(Corridor(low=low), weakest, EQUAL_POWER, EQUAL_POWER, t)
    clamped_default = max(t.floor_dbm, min(low + t.offset_db, t.ceiling_dbm))
    assert result.downlink_dbm <= clamped_default
    if weakest is None or weakest >= low:
        assert result.downlink_dbm == clamped_default


@given(st.integers(-90, -50), st.integers(-100, -30), tunables())
def test_cap_kind_matches_the_raw_cap_against_the_floor(low: int, weakest: int, t: RoamingTunables) -> None:
    result = recommend_roaming(Corridor(low=low), weakest, EQUAL_POWER, EQUAL_POWER, t)
    if result.cap is RoamingCap.NONE:
        assert result.raw_cap_dbm is None
    else:
        assert result.raw_cap_dbm == weakest - t.margin_db
        assert (result.cap is RoamingCap.FLOOR) == (result.raw_cap_dbm < t.floor_dbm)
