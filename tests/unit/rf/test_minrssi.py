import pytest
from hypothesis import given
from hypothesis import strategies as st

from unifiwifioptimizer.rf.corridor import Corridor
from unifiwifioptimizer.rf.minrssi import recommend_min_rssi, uplink_threshold


def test_uplink_threshold_follows_reciprocity() -> None:
    # A 2.4 GHz radio at 6 dBm against a 15 dBm client: the uplink is 9 dB stronger than the downlink.
    assert uplink_threshold(-78, tx_eff_ap_dbm=6, client_tx_dbm=15) == -69
    # A 5 GHz radio at 18 dBm: the uplink is 3 dB weaker.
    assert uplink_threshold(-72, tx_eff_ap_dbm=18, client_tx_dbm=15) == -75


def test_default_offset_sits_five_db_below_the_corridor_before_the_uplink_conversion() -> None:
    assert recommend_min_rssi(Corridor(low=-73), tx_eff_ap_dbm=15, client_tx_dbm=15) == -78
    assert recommend_min_rssi(Corridor(low=-73), tx_eff_ap_dbm=6, client_tx_dbm=15) == -69


def test_the_default_client_power_is_14_dbm() -> None:
    # An access point at the client's power derives the downlink value unchanged: -73 - 5.
    assert recommend_min_rssi(Corridor(low=-73), tx_eff_ap_dbm=14) == -78


def test_zero_offset_collapses_onto_the_corridor_edge() -> None:
    assert recommend_min_rssi(Corridor(low=-73), tx_eff_ap_dbm=15, client_tx_dbm=15, offset_db=0) == -73


@pytest.mark.parametrize("offset", [-1, 31])
def test_offset_outside_the_documented_range_is_rejected(offset: int) -> None:
    with pytest.raises(ValueError):
        recommend_min_rssi(Corridor(low=-73), 15, offset_db=offset)


@pytest.mark.parametrize("client_tx", [-1, 31])
def test_client_tx_outside_its_range_is_rejected(client_tx: int) -> None:
    with pytest.raises(ValueError):
        uplink_threshold(-73, 15, client_tx)


@given(st.integers(-90, -50), st.integers(0, 30), st.integers(0, 30), st.integers(0, 30))
def test_min_rssi_is_offset_below_the_edge_shifted_by_the_power_difference(
    low: int, tx_ap: int, client: int, offset: int
) -> None:
    assert recommend_min_rssi(Corridor(low=low), tx_ap, client, offset) == low - offset - (tx_ap - client)


@given(st.integers(-100, -30), st.integers(0, 30))
def test_equal_powers_leave_the_threshold_unchanged(target: int, power: int) -> None:
    assert uplink_threshold(target, power, power) == target
