"""Per-PHY candidate power inference never promotes an unverified limit to a measured TX value."""

import pytest

from unifiwifioptimizer.domain.analysis import MaxReason
from unifiwifioptimizer.domain.models import Band
from unifiwifioptimizer.rf.channel_power import calibrated_ceilings, candidate_ceiling, reported_ceiling


def limits() -> tuple[tuple[int, float], ...]:
    return tuple((channel, 23.0) for channel in (36, 40, 44, 48, 52, 56, 60, 64)) + tuple(
        (channel, 30.0) for channel in (100, 104, 108, 112, 116, 120, 124, 128)
    )


def test_u7_calibration_yields_six_db_upper_band_headroom() -> None:
    result = calibrated_ceilings(52, 80, 18, 24, 24, 5, limits(), (52, 120))
    assert result is not None and result.current_dbm == 18
    assert result.candidates == ((52, 18), (120, 24))


def test_missing_constituent_or_zero_u6_table_is_unknown() -> None:
    table = dict(limits())
    table.pop(124)
    assert candidate_ceiling(120, 80, table, 24, 24, 5) is None
    assert calibrated_ceilings(52, 80, 20, 23, 23, 3, tuple((c, 0.0) for c in table), (52, 120)) is None


def test_configured_hardware_and_antenna_limits_and_mismatch() -> None:
    assert calibrated_ceilings(52, 80, 18, 24, 24, 5, limits(), (52, 120)) is not None
    assert calibrated_ceilings(52, 80, 21, 24, 24, 5, limits(), (52, 120)) is None
    assert candidate_ceiling(120, 80, dict(limits()), 20, 24, 5) == 20
    assert candidate_ceiling(120, 80, dict(limits()), 24, 22, 5) == 22


def test_candidates_are_shifted_by_the_rounding_step_between_the_observed_power_and_the_projection() -> None:
    # The projection of channel 52 is 18 dBm. A radio reporting 17 or 19 dBm there is accepted, and a candidate in
    # the same sub-band shows no gain or loss at all (a step of 1 dB is rounding, not headroom).
    for observed, same_band, upper_band in ((17, 17, 23), (18, 18, 24), (19, 19, 24)):
        result = calibrated_ceilings(52, 80, observed, 24, 24, 5, limits(), (36, 52, 120))
        assert result is not None and result.current_dbm == observed
        assert result.candidates == ((36, same_band), (52, same_band), (120, upper_band))


def test_a_shifted_ceiling_never_exceeds_the_setting_or_the_hardware() -> None:
    result = calibrated_ceilings(52, 80, 19, 24, 24, 5, limits(), (120,))
    assert result is not None and result.ceiling(120) == 24
    capped = calibrated_ceilings(52, 80, 19, 19, 24, 5, limits(), (120,))
    assert capped is not None and capped.ceiling(120) == 19


# --- the reported ceiling of the current channel -------------------------------------------------------------


def limits_2g(dbm: float = 20.0) -> tuple[tuple[int, float], ...]:
    return tuple((channel, dbm) for channel in range(1, 14))


@pytest.mark.parametrize(("gain", "expected"), [(3, 17), (4, 16)])
def test_a_2_4_ghz_limit_of_20_dbm_less_the_antenna_gain(gain: int, expected: int) -> None:
    assert reported_ceiling(Band.GHZ_2, 11, 20, None, limits_2g(), 23, gain) == expected


def test_a_5_ghz_limit_less_the_antenna_gain_and_capped_by_the_model_maximum() -> None:
    assert reported_ceiling(Band.GHZ_5, 52, 20, None, limits(), 24, 5) == 18
    # 30 dBm minus 5 dBi is 25, above the model maximum 24.
    assert reported_ceiling(Band.GHZ_5, 120, 20, None, limits(), 24, 5) == 24


def test_a_bonded_5_ghz_block_uses_its_weakest_constituent() -> None:
    mixed = tuple((c, 20.0 if c == 124 else 30.0) for c in (100, 104, 108, 112, 116, 120, 124, 128))
    assert reported_ceiling(Band.GHZ_5, 120, 80, None, mixed, 24, 5) == 15
    assert reported_ceiling(Band.GHZ_5, 120, 20, None, mixed, 24, 5) == 24


@pytest.mark.parametrize(
    ("limit_table", "gain", "reason"),
    [
        (tuple((c, 0.0) for c in range(1, 14)), 3, MaxReason.NO_LIMIT),
        ((), 3, MaxReason.NO_LIMIT),
        (limits_2g(3.0), 3, MaxReason.NO_LIMIT),
        (limits_2g(), None, MaxReason.NO_ANTENNA_GAIN),
        (limits_2g(), -1, MaxReason.NO_ANTENNA_GAIN),
    ],
)
def test_no_ceiling_without_a_positive_limit_or_a_usable_antenna_gain(
    limit_table: tuple[tuple[int, float], ...], gain: int | None, reason: MaxReason
) -> None:
    assert reported_ceiling(Band.GHZ_2, 6, 20, None, limit_table, 23, gain) is reason


def test_a_5_ghz_block_with_a_missing_or_unknown_constituent_has_no_ceiling() -> None:
    without_124 = tuple(entry for entry in limits() if entry[0] != 124)
    assert reported_ceiling(Band.GHZ_5, 120, 80, None, without_124, 24, 5) is MaxReason.NO_LIMIT
    assert reported_ceiling(Band.GHZ_5, 7, 20, None, limits(), 24, 5) is MaxReason.NO_LIMIT


def test_a_40_mhz_2_4_ghz_block_counts_its_secondary_or_the_weaker_side() -> None:
    uneven = tuple((c, 17.0 if c == 10 else 20.0) for c in range(1, 14))
    assert reported_ceiling(Band.GHZ_2, 6, 40, 1, uneven, 23, 3) == 14
    assert reported_ceiling(Band.GHZ_2, 6, 40, -1, uneven, 23, 3) == 17
    assert reported_ceiling(Band.GHZ_2, 6, 40, None, uneven, 23, 3) == 14
    assert reported_ceiling(Band.GHZ_2, 6, 20, 1, uneven, 23, 3) == 17


def test_an_occupied_2_4_ghz_secondary_without_a_listed_limit_proves_no_freedom() -> None:
    primary_only = ((6, 20.0),)
    assert reported_ceiling(Band.GHZ_2, 6, 40, 1, primary_only, 23, 3) is MaxReason.NO_LIMIT
    assert reported_ceiling(Band.GHZ_2, 6, 40, -1, primary_only, 23, 3) is MaxReason.NO_LIMIT
    assert reported_ceiling(Band.GHZ_2, 6, 40, None, primary_only, 23, 3) is MaxReason.NO_LIMIT
    assert reported_ceiling(Band.GHZ_2, 6, 20, None, primary_only, 23, 3) == 17
    without_10 = tuple(entry for entry in limits_2g() if entry[0] != 10)
    assert reported_ceiling(Band.GHZ_2, 6, 40, 1, without_10, 23, 3) is MaxReason.NO_LIMIT
    assert reported_ceiling(Band.GHZ_2, 6, 40, -1, without_10, 23, 3) == 17


def test_a_secondary_beyond_the_band_is_impossible_when_named_and_ignored_when_the_side_is_unknown() -> None:
    assert reported_ceiling(Band.GHZ_2, 11, 40, 1, limits_2g(), 23, 3) is MaxReason.NO_LIMIT
    assert reported_ceiling(Band.GHZ_2, 11, 40, None, limits_2g(), 23, 3) == 17
    assert reported_ceiling(Band.GHZ_2, 14, 20, None, limits_2g(), 23, 3) is MaxReason.NO_LIMIT


def test_channel_14_is_never_a_secondary_so_primary_10_at_40_mhz_needs_only_the_lower_side() -> None:
    assert reported_ceiling(Band.GHZ_2, 10, 40, None, limits_2g(), 23, 3) == 17
    with_14 = (*limits_2g(), (14, 10.0))
    assert reported_ceiling(Band.GHZ_2, 10, 40, None, with_14, 23, 3) == 17
    assert reported_ceiling(Band.GHZ_2, 10, 40, 1, limits_2g(), 23, 3) is MaxReason.NO_LIMIT
