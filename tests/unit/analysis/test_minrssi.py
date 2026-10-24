from unifiwifioptimizer.analysis.minrssi import min_rssi_before_roaming, recommend_band_min_rssi
from unifiwifioptimizer.domain.models import Band
from unifiwifioptimizer.domain.report import RecommendationKind, Severity
from unifiwifioptimizer.rf.corridor import Corridor
from unifiwifioptimizer.rf.settings import RfSettings

from .builders import ap_named, fixture_snapshot, with_radio, with_stats

SNAP = fixture_snapshot()
FIVE = Corridor(low=-67)
RF = RfSettings(client_tx_dbm=15)


def test_a_disabled_min_rssi_is_conditional_with_the_uplink_value_to_use() -> None:
    # Fixture AP-3 5 GHz runs 23 dBm; downlink target -67 - 5 = -72 → uplink -72 - (23 - 15) = -80.
    rec = recommend_band_min_rssi(ap_named(SNAP, "AP-3"), Band.GHZ_5, FIVE, tx_eff_dbm=23, rf=RF)
    assert (rec.current, rec.recommended, rec.kind) == (None, -80, RecommendationKind.CONDITIONAL)
    assert rec.is_change is False and rec.setting == "min_rssi" and rec.band is Band.GHZ_5


def test_an_enabled_min_rssi_is_confirmed_at_the_value_and_a_change_elsewhere() -> None:
    at_value = with_radio(ap_named(SNAP, "AP-3"), Band.GHZ_5, min_rssi_enabled=True, min_rssi_dbm=-80)
    confirmed = recommend_band_min_rssi(at_value, Band.GHZ_5, FIVE, 23, RF)
    assert (confirmed.current, confirmed.kind) == (-80, RecommendationKind.CONFIRMED)
    elsewhere = with_radio(ap_named(SNAP, "AP-3"), Band.GHZ_5, min_rssi_enabled=True, min_rssi_dbm=-75)
    change = recommend_band_min_rssi(elsewhere, Band.GHZ_5, FIVE, 23, RF)
    assert (change.current, change.recommended, change.kind) == (-75, -80, RecommendationKind.CHANGE)


def test_the_client_power_and_the_offset_move_the_uplink_value() -> None:
    tuned = RfSettings(client_tx_dbm=20, min_rssi_offset_db=8)
    rec = recommend_band_min_rssi(ap_named(SNAP, "AP-3"), Band.GHZ_5, FIVE, 23, tuned)
    # Downlink -75; uplink -75 - (23 - 20) = -78.
    assert rec.recommended == -78


def test_upper_5g_client_power_applies_to_min_rssi_and_its_reverse_advisory() -> None:
    rf = RfSettings(client_tx_dbm=18, client_tx_dbm_5g_upper=20)
    upper = with_radio(ap_named(SNAP, "AP-3"), Band.GHZ_5, min_rssi_enabled=True, min_rssi_dbm=-75)
    upper_rec = recommend_band_min_rssi(upper, Band.GHZ_5, FIVE, 23, rf)
    assert upper_rec.recommended == -75
    late = min_rssi_before_roaming(upper, Band.GHZ_5, upper_rec, -73, 23, rf, coverage_gap=False)
    assert late is not None and "(-72 dBm)" in late.message

    lower = with_stats(upper, Band.GHZ_5, channel=44)
    lower_rec = recommend_band_min_rssi(lower, Band.GHZ_5, FIVE, 23, rf)
    assert lower_rec.recommended == -77
    two_ghz = recommend_band_min_rssi(lower, Band.GHZ_2, Corridor(low=-73), 11, rf)
    assert two_ghz.recommended == -71  # -73 - 5 - (11 - 18)


def test_the_ordering_advisory_fires_only_for_an_enabled_5_ghz_min_rssi() -> None:
    enabled = with_radio(ap_named(SNAP, "AP-3"), Band.GHZ_5, min_rssi_enabled=True, min_rssi_dbm=-80)
    rec = recommend_band_min_rssi(enabled, Band.GHZ_5, FIVE, 23, RF)
    # Min RSSI downlink target -72; a roaming trigger at -75 would fire after the disconnect.
    late = min_rssi_before_roaming(enabled, Band.GHZ_5, rec, -75, 23, RF, coverage_gap=False)
    assert late is not None and late.severity is Severity.ADVISORY and late.code == "min_rssi_before_roaming"
    assert "-75 dBm" in late.message and "-72 dBm" in late.message
    assert min_rssi_before_roaming(enabled, Band.GHZ_5, rec, -70, 23, RF, coverage_gap=False) is None
    assert min_rssi_before_roaming(enabled, Band.GHZ_5, rec, None, 23, RF, coverage_gap=False) is None
    gap = min_rssi_before_roaming(enabled, Band.GHZ_5, rec, -70, 23, RF, coverage_gap=True)
    assert gap is not None and "coverage gap" in gap.message
    disabled = recommend_band_min_rssi(ap_named(SNAP, "AP-3"), Band.GHZ_5, FIVE, 23, RF)
    assert min_rssi_before_roaming(ap_named(SNAP, "AP-3"), Band.GHZ_5, disabled, -75, 23, RF, coverage_gap=True) is None
    enabled_2g = with_radio(enabled, Band.GHZ_2, min_rssi_enabled=True, min_rssi_dbm=-80)
    two = recommend_band_min_rssi(enabled_2g, Band.GHZ_2, Corridor(low=-73), 11, RF)
    assert two.kind is not RecommendationKind.CONDITIONAL
    # The same late trigger and coverage gap that fire on 5 GHz stay silent on 2.4 GHz: no roaming band.
    assert min_rssi_before_roaming(enabled_2g, Band.GHZ_2, two, -80, 6, RF, coverage_gap=True) is None


def test_a_derived_value_outside_what_the_controller_accepts_moves_to_the_nearer_end() -> None:
    ap = ap_named(SNAP, "AP-3")
    # Downlink -72; a weak 6 dBm radio derives -72 + (15 - 6) = -63, above the upper stop of -67.
    weak = recommend_band_min_rssi(ap, Band.GHZ_5, FIVE, 6, RF)
    assert (weak.recommended, weak.derived_dbm) == (-67, -63)
    # A 23 dBm radio with a 0 dBm client derives -72 - 23 = -95, below the lower stop of -90.
    strong = recommend_band_min_rssi(ap, Band.GHZ_5, FIVE, 23, RfSettings(client_tx_dbm=0))
    assert (strong.recommended, strong.derived_dbm) == (-90, -95)


def test_a_derived_value_exactly_at_a_stop_is_not_reported_as_moved() -> None:
    ap = ap_named(SNAP, "AP-3")
    upper = recommend_band_min_rssi(ap, Band.GHZ_5, FIVE, 10, RF)
    assert (upper.recommended, upper.derived_dbm) == (-67, None)
    lower = recommend_band_min_rssi(ap, Band.GHZ_5, FIVE, 18, RfSettings(client_tx_dbm=0))
    assert (lower.recommended, lower.derived_dbm) == (-90, None)


def test_an_enabled_min_rssi_at_the_stop_is_confirmed_although_the_derived_value_lies_beyond() -> None:
    at_stop = with_radio(ap_named(SNAP, "AP-3"), Band.GHZ_5, min_rssi_enabled=True, min_rssi_dbm=-67)
    rec = recommend_band_min_rssi(at_stop, Band.GHZ_5, FIVE, 6, RF)
    assert (rec.kind, rec.current, rec.derived_dbm) == (RecommendationKind.CONFIRMED, -67, -63)


def test_the_ordering_advisory_judges_a_min_rssi_moved_into_the_controller_range_as_set() -> None:
    # A 6 dBm radio derives -63 on the uplink, above the stop of -67: -67 is what gets set, and on the downlink
    # that is -67 + (6 - 15) = -76, not the corridor-derived -72.
    enabled = with_radio(ap_named(SNAP, "AP-3"), Band.GHZ_5, min_rssi_enabled=True, min_rssi_dbm=-67)
    rec = recommend_band_min_rssi(enabled, Band.GHZ_5, FIVE, 6, RF)
    assert (rec.recommended, rec.derived_dbm) == (-67, -63)
    assert min_rssi_before_roaming(enabled, Band.GHZ_5, rec, -74, 6, RF, coverage_gap=False) is None
    late = min_rssi_before_roaming(enabled, Band.GHZ_5, rec, -78, 6, RF, coverage_gap=False)
    assert late is not None and "-78 dBm" in late.message and "(-76 dBm)" in late.message
