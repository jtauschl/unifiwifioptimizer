from dataclasses import replace

import pytest

from unifiwifioptimizer.analysis.minrssi import (
    min_rssi_before_roaming,
    min_rssi_without_alternative,
    recommend_band_min_rssi,
)
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
    late = min_rssi_before_roaming(upper, Band.GHZ_5, upper_rec, -73, 23, rf)
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
    late = min_rssi_before_roaming(enabled, Band.GHZ_5, rec, -75, 23, RF)
    assert late is not None and late.severity is Severity.ADVISORY and late.code == "min_rssi_before_roaming"
    assert "-75 dBm" in late.message and "-72 dBm" in late.message
    assert min_rssi_before_roaming(enabled, Band.GHZ_5, rec, -70, 23, RF) is None
    assert min_rssi_before_roaming(enabled, Band.GHZ_5, rec, None, 23, RF) is None
    disabled = recommend_band_min_rssi(ap_named(SNAP, "AP-3"), Band.GHZ_5, FIVE, 23, RF)
    assert min_rssi_before_roaming(ap_named(SNAP, "AP-3"), Band.GHZ_5, disabled, -75, 23, RF) is None
    enabled_2g = with_radio(enabled, Band.GHZ_2, min_rssi_enabled=True, min_rssi_dbm=-80)
    two = recommend_band_min_rssi(enabled_2g, Band.GHZ_2, Corridor(low=-73), 11, RF)
    assert two.kind is not RecommendationKind.CONDITIONAL
    # The same late trigger that fires on 5 GHz stays silent on 2.4 GHz: no roaming band.
    assert min_rssi_before_roaming(enabled_2g, Band.GHZ_2, two, -80, 6, RF) is None


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
    assert min_rssi_before_roaming(enabled, Band.GHZ_5, rec, -74, 6, RF) is None
    late = min_rssi_before_roaming(enabled, Band.GHZ_5, rec, -78, 6, RF)
    assert late is not None and "-78 dBm" in late.message and "(-76 dBm)" in late.message


# --- the advisory for a radio whose clients have no other access point ---------------------------------------------


def _alternative(ap, band: Band, **facts):  # type: ignore[no-untyped-def]
    values = {"configured": True, "has_neighbours": True, "coverage_gap": False, "floor_wording": "the cell edge"}
    return min_rssi_without_alternative(ap, band, **{**values, **facts})


def _enabled(band: Band):  # type: ignore[no-untyped-def]
    return with_radio(ap_named(SNAP, "AP-3"), band, min_rssi_enabled=True, min_rssi_dbm=-80)


@pytest.mark.parametrize("band", [Band.GHZ_2, Band.GHZ_5])
def test_an_enabled_min_rssi_without_a_configured_neighbour_gets_the_advisory(band: Band) -> None:
    finding = _alternative(_enabled(band), band, has_neighbours=False)
    assert (
        finding is not None and finding.code == "min_rssi_without_alternative" and finding.severity is Severity.ADVISORY
    )
    assert finding.band is band and finding.subject == "AP-3"
    assert finding.message == (
        "Minimum RSSI is enabled on this radio and no neighbour is configured on this band: the access point "
        "disconnects a client below the threshold and leaves it to the client to find another access point"
    )


@pytest.mark.parametrize(("band", "floor"), [(Band.GHZ_5, "the cell edge"), (Band.GHZ_2, "the 2.4 GHz corridor floor")])
def test_a_structural_coverage_gap_gets_the_advisory_on_both_bands_with_the_band_floor(band: Band, floor: str) -> None:
    finding = _alternative(_enabled(band), band, coverage_gap=True, floor_wording=floor)
    assert finding is not None
    assert f"the weakest neighbour stays below {floor} even at the effective maximum" in finding.message


def test_the_advisory_stays_silent_where_there_is_an_alternative_or_nothing_to_warn_about() -> None:
    enabled = _enabled(Band.GHZ_5)
    assert _alternative(enabled, Band.GHZ_5) is None
    disabled = ap_named(SNAP, "AP-3")
    assert _alternative(disabled, Band.GHZ_5, has_neighbours=False, coverage_gap=True) is None
    assert _alternative(enabled, Band.GHZ_5, configured=False, has_neighbours=False, coverage_gap=True) is None
    switched_off = with_radio(enabled, Band.GHZ_5, min_rssi_enabled=False)
    assert _alternative(switched_off, Band.GHZ_5, has_neighbours=False) is None
    no_radio = replace(enabled, radios=tuple(r for r in enabled.radios if r.band is not Band.GHZ_5))
    assert _alternative(no_radio, Band.GHZ_5, has_neighbours=False) is None
