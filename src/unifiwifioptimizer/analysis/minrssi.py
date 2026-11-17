"""Minimum RSSI per radio: the uplink value that corresponds to the corridor's lower edge minus the margin.

Enabling it is a deployment choice (docs/ALGORITHM.md §6): a disabled Min RSSI is CONDITIONAL — the value
to use if it is switched on — never a pending change. Two advisories speak for an enabled Min RSSI: the §6 ordering
advisory warns where a hard disconnect would fire before the roaming trigger it is meant to follow, and the
alternative advisory where no other access point can take the client over.
"""

from unifiwifioptimizer.domain.models import AccessPoint, Band
from unifiwifioptimizer.domain.report import MIN_RSSI, Finding, Recommendation, RecommendationKind, Severity
from unifiwifioptimizer.rf.constants import MIN_RSSI_MAX_DBM, MIN_RSSI_MIN_DBM
from unifiwifioptimizer.rf.corridor import Corridor
from unifiwifioptimizer.rf.minrssi import recommend_min_rssi
from unifiwifioptimizer.rf.settings import RfSettings


def recommend_band_min_rssi(
    ap: AccessPoint, band: Band, corridor: Corridor, tx_eff_dbm: int, rf: RfSettings
) -> Recommendation:
    radio = ap.radio(band)
    stats = ap.stats(band)
    enabled = radio is not None and radio.min_rssi_enabled
    current = radio.min_rssi_dbm if radio is not None and enabled else None
    assumed_client_tx = rf.client_tx_assumption(
        band, stats.channel if stats is not None else None, stats.width_mhz if stats is not None else None
    )
    derived = recommend_min_rssi(corridor, tx_eff_dbm, assumed_client_tx, rf.min_rssi_offset_db)
    recommended = min(max(derived, MIN_RSSI_MIN_DBM), MIN_RSSI_MAX_DBM)
    if not enabled:
        kind, reason = RecommendationKind.CONDITIONAL, "disabled; the value to use if enabled"
    elif current == recommended:
        kind, reason = RecommendationKind.CONFIRMED, "enabled at the recommended uplink value"
    else:
        kind, reason = RecommendationKind.CHANGE, "enabled at another value than the corridor-derived one"
    return Recommendation(
        code=MIN_RSSI,
        subject=ap.name,
        band=band,
        setting=MIN_RSSI,
        current=current,
        recommended=recommended,
        kind=kind,
        reason=reason,
        derived_dbm=derived if derived != recommended else None,
    )


def min_rssi_before_roaming(
    ap: AccessPoint,
    band: Band,
    min_rssi: Recommendation,
    roaming_downlink_dbm: int | None,
    tx_eff_dbm: int,
    rf: RfSettings,
) -> Finding | None:
    """ALGORITHM §6: an enabled Min RSSI on a 5 GHz radio must not kick a client before the roaming trigger
    (compared on the downlink). The Min RSSI side is the value that can be set, converted back to the downlink,
    so a value moved into the controller's range is judged as set."""
    if band is not Band.GHZ_5 or min_rssi.kind is RecommendationKind.CONDITIONAL:
        return None
    stats = ap.stats(band)
    assumed_client_tx = rf.client_tx_assumption(
        band, stats.channel if stats is not None else None, stats.width_mhz if stats is not None else None
    )
    min_rssi_downlink = min_rssi.recommended + (tx_eff_dbm - assumed_client_tx)
    if roaming_downlink_dbm is None or roaming_downlink_dbm >= min_rssi_downlink:
        return None
    message = (
        f"the roaming trigger ({roaming_downlink_dbm} dBm at the client) lies below the Minimum RSSI target "
        f"({min_rssi_downlink} dBm): the disconnect would fire before the hand-off suggestion"
    )
    return Finding(
        severity=Severity.ADVISORY, code="min_rssi_before_roaming", message=message, subject=ap.name, band=band
    )


def min_rssi_without_alternative(
    ap: AccessPoint, band: Band, *, configured: bool, has_neighbours: bool, coverage_gap: bool, floor_wording: str
) -> Finding | None:
    """ALGORITHM §6: an enabled Min RSSI on a radio whose clients have no other access point to go to. Only the
    configured neighbours count (the WLAN-level view of the alternative is §7); an access point missing from the
    neighbour configuration keeps its own finding and gets nothing here."""
    radio = ap.radio(band)
    if not configured or radio is None or not radio.min_rssi_enabled:
        return None
    if not has_neighbours:
        cause = "no neighbour is configured on this band"
    elif coverage_gap:
        cause = f"the weakest neighbour stays below {floor_wording} even at the effective maximum"
    else:
        return None
    message = (
        f"Minimum RSSI is enabled on this radio and {cause}: the access point disconnects a client below the "
        "threshold and leaves it to the client to find another access point"
    )
    return Finding(
        severity=Severity.ADVISORY, code="min_rssi_without_alternative", message=message, subject=ap.name, band=band
    )
