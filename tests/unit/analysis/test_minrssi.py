from unifiwifioptimizer.analysis.minrssi import min_rssi_before_roaming, recommend_band_min_rssi
from unifiwifioptimizer.domain.models import Band
from unifiwifioptimizer.domain.report import RecommendationKind, Severity
from unifiwifioptimizer.rf.corridor import Corridor
from unifiwifioptimizer.rf.settings import RfSettings

from .builders import ap_named, fixture_snapshot, with_radio

SNAP = fixture_snapshot()
FIVE = Corridor(low=-67)
RF = RfSettings()


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


def test_the_ordering_advisory_fires_only_for_an_enabled_5_ghz_min_rssi() -> None:
    enabled = with_radio(ap_named(SNAP, "AP-3"), Band.GHZ_5, min_rssi_enabled=True, min_rssi_dbm=-80)
    rec = recommend_band_min_rssi(enabled, Band.GHZ_5, FIVE, 23, RF)
    # Min RSSI downlink target -72; a roaming trigger at -75 would fire after the disconnect.
    late = min_rssi_before_roaming(enabled, Band.GHZ_5, rec, -75, FIVE, RF, coverage_gap=False)
    assert late is not None and late.severity is Severity.ADVISORY and late.code == "min_rssi_before_roaming"
    assert "-75 dBm" in late.message and "-72 dBm" in late.message
    assert min_rssi_before_roaming(enabled, Band.GHZ_5, rec, -70, FIVE, RF, coverage_gap=False) is None
    assert min_rssi_before_roaming(enabled, Band.GHZ_5, rec, None, FIVE, RF, coverage_gap=False) is None
    gap = min_rssi_before_roaming(enabled, Band.GHZ_5, rec, -70, FIVE, RF, coverage_gap=True)
    assert gap is not None and "coverage gap" in gap.message
    disabled = recommend_band_min_rssi(ap_named(SNAP, "AP-3"), Band.GHZ_5, FIVE, 23, RF)
    assert (
        min_rssi_before_roaming(ap_named(SNAP, "AP-3"), Band.GHZ_5, disabled, -75, FIVE, RF, coverage_gap=True) is None
    )
    enabled_2g = with_radio(enabled, Band.GHZ_2, min_rssi_enabled=True, min_rssi_dbm=-80)
    two = recommend_band_min_rssi(enabled_2g, Band.GHZ_2, Corridor(low=-73), 11, RF)
    assert two.kind is not RecommendationKind.CONDITIONAL
    # The same late trigger and coverage gap that fire on 5 GHz stay silent on 2.4 GHz: no roaming band.
    assert min_rssi_before_roaming(enabled_2g, Band.GHZ_2, two, -80, Corridor(low=-73), RF, coverage_gap=True) is None
