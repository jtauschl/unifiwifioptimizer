"""Per-PHY candidate power inference never promotes an unverified limit to a measured TX value."""

from unifiwifioptimizer.rf.channel_power import calibrated_ceilings, candidate_ceiling


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
