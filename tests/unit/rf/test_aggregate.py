import random
import statistics

from hypothesis import given
from hypothesis import strategies as st

from unifiwifioptimizer.rf.aggregate import Sighting, aggregate_passes, aggregate_rssi, consensus_readings

rssi = st.integers(min_value=-100, max_value=-30)
frequency = st.sampled_from([5180, 5200, 5500])
sightings = st.lists(st.builds(Sighting, rssi_dbm=rssi, frequency_mhz=st.one_of(st.none(), frequency)), max_size=9)
same_channel = st.lists(st.builds(Sighting, rssi_dbm=rssi, frequency_mhz=st.just(5180)), min_size=1, max_size=9)


def test_a_single_reading_is_returned_as_is() -> None:
    assert aggregate_rssi([Sighting(-70)]) == -70


def test_two_readings_give_their_median_not_the_maximum() -> None:
    assert aggregate_rssi([Sighting(-70), Sighting(-64)]) == -67


def test_two_readings_at_a_half_step_round_half_to_even() -> None:
    # Median -67.5 rounds to -68; half-up would give -67.
    assert aggregate_rssi([Sighting(-70), Sighting(-65)]) == -68
    assert aggregate_rssi([Sighting(-69), Sighting(-64)]) == -66


def test_an_outlier_does_not_move_the_median() -> None:
    assert aggregate_rssi([Sighting(-90), Sighting(-70), Sighting(-72), Sighting(-40)]) == -71


def test_the_peer_channel_selects_the_readings_when_known() -> None:
    readings = [Sighting(-70, 5180), Sighting(-40, 5500), Sighting(-42, 5500)]
    assert aggregate_rssi(readings, expected_frequency_mhz=5180) == -70
    assert aggregate_rssi(readings, expected_frequency_mhz=5200) is None
    # A reading without a frequency cannot be attributed to the peer's channel.
    assert aggregate_rssi([Sighting(-70, 5180), Sighting(-40)], expected_frequency_mhz=5180) == -70


def test_without_the_peer_channel_a_strict_majority_decides() -> None:
    assert aggregate_rssi([Sighting(-70, 5180), Sighting(-72, 5180), Sighting(-40, 5500)]) == -71
    assert aggregate_rssi([Sighting(-70, 5180), Sighting(-40, 5500)]) is None


def test_frequency_less_readings_count_against_the_majority() -> None:
    assert aggregate_rssi([Sighting(-70, 5180), Sighting(-60), Sighting(-50)]) is None


def test_frequency_less_readings_never_become_values() -> None:
    assert consensus_readings([Sighting(-70, 5180), Sighting(-72, 5180), Sighting(-60)]) == [-70, -72]
    readings = [Sighting(-70, 5180), Sighting(-72, 5180), Sighting(-74, 5180), Sighting(-40), Sighting(-40)]
    assert aggregate_rssi(readings) == -72


def test_no_readings_give_none() -> None:
    assert aggregate_rssi([]) is None


def test_readings_without_a_frequency_are_all_used() -> None:
    assert consensus_readings([Sighting(-70), Sighting(-60)]) == [-70, -60]


def test_passes_drop_bssids_without_a_usable_reading_and_honour_expected_channels() -> None:
    result = aggregate_passes(
        {
            "a": [Sighting(-70, 5180), Sighting(-40, 5500)],
            "b": [Sighting(-66)],
            "c": [Sighting(-50, 5500), Sighting(-72, 5180)],
        },
        expected_frequency_by_bssid={"c": 5180},
    )
    assert result == {"b": -66, "c": -72}


@given(sightings)
def test_aggregate_is_the_rounded_median_of_the_consensus_readings(readings: list[Sighting]) -> None:
    consensus = consensus_readings(readings)
    value = aggregate_rssi(readings)
    if not consensus:
        assert value is None
    else:
        assert value == round(statistics.median(consensus))
        assert min(consensus) <= value <= max(consensus)


@given(sightings, st.randoms())
def test_aggregate_is_permutation_invariant(readings: list[Sighting], rng: random.Random) -> None:
    shuffled = list(readings)
    rng.shuffle(shuffled)
    assert aggregate_rssi(shuffled) == aggregate_rssi(readings)


@given(same_channel, st.integers(-100, -30))
def test_a_single_outlier_cannot_pull_the_median_outside_three_or_more_readings(
    readings: list[Sighting], outlier: int
) -> None:
    with_outlier = aggregate_rssi([*readings, Sighting(outlier, 5180)])
    values = [s.rssi_dbm for s in readings]
    assert with_outlier is not None
    assert min([*values, outlier]) <= with_outlier <= max([*values, outlier])
    if len(values) >= 3:
        assert min(values) <= with_outlier <= max(values)


@given(st.integers(1, 5), st.integers(1, 5))
def test_two_channels_count_only_with_a_strict_majority(n_a: int, n_b: int) -> None:
    readings = [Sighting(-70, 5180)] * n_a + [Sighting(-40, 5500)] * n_b
    value = aggregate_rssi(readings)
    if n_a == n_b:
        assert value is None
    else:
        assert value == (-70 if n_a > n_b else -40)
