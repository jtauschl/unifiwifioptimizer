"""Minimum RSSI per radio: the uplink value that corresponds to the corridor's lower edge minus the margin.

Enabling it is a deployment choice (docs/ALGORITHM.md §6): a disabled Min RSSI is CONDITIONAL — the value
to use if it is switched on — never a pending change. The §6 ordering advisory warns where a hard
disconnect would fire before the roaming trigger it is meant to follow.
"""

from unifiwifioptimizer.domain.models import AccessPoint, Band
from unifiwifioptimizer.domain.report import MIN_RSSI, Finding, Recommendation, RecommendationKind, Severity
from unifiwifioptimizer.rf.corridor import Corridor
from unifiwifioptimizer.rf.minrssi import recommend_min_rssi
from unifiwifioptimizer.rf.settings import RfSettings


def recommend_band_min_rssi(
    ap: AccessPoint, band: Band, corridor: Corridor, tx_eff_dbm: int, rf: RfSettings
) -> Recommendation:
    radio = ap.radio(band)
    enabled = radio is not None and radio.min_rssi_enabled
    current = radio.min_rssi_dbm if radio is not None and enabled else None
    recommended = recommend_min_rssi(corridor, tx_eff_dbm, rf.client_tx_dbm, rf.min_rssi_offset_db)
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
    )


def min_rssi_before_roaming(
    ap: AccessPoint,
    band: Band,
    min_rssi: Recommendation,
    roaming_downlink_dbm: int | None,
    corridor: Corridor,
    rf: RfSettings,
    coverage_gap: bool,
) -> Finding | None:
    """ALGORITHM §6: an enabled Min RSSI on a 5 GHz radio must not kick a client before the roaming trigger
    (compared on the downlink, where both are derived) or on a radio with a coverage gap."""
    if band is not Band.GHZ_5 or min_rssi.kind is RecommendationKind.CONDITIONAL:
        return None
    min_rssi_downlink = corridor.low - rf.min_rssi_offset_db
    if coverage_gap:
        message = (
            "Minimum RSSI is enabled on a radio with a coverage gap; the hard disconnect would fire before any "
            "neighbour can take over"
        )
    elif roaming_downlink_dbm is not None and roaming_downlink_dbm < min_rssi_downlink:
        message = (
            f"the roaming trigger ({roaming_downlink_dbm} dBm at the client) lies below the Minimum RSSI target "
            f"({min_rssi_downlink} dBm): the disconnect would fire before the hand-off suggestion"
        )
    else:
        return None
    return Finding(
        severity=Severity.ADVISORY, code="min_rssi_before_roaming", message=message, subject=ap.name, band=band
    )
