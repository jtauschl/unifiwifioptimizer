"""TX power recommendation (docs/ALGORITHM.md §4).

The coverage condition holds per neighbour pair, so the corridor is tested against the weakest
configured neighbour's reading of this AP; a 1 dB change in transmit power moves that reading by 1 dB
as long as the radio is below its effective maximum.
"""

from dataclasses import dataclass

from unifiwifioptimizer.domain.analysis import MaxReason, MaxSource
from unifiwifioptimizer.domain.models import TxPowerMode
from unifiwifioptimizer.rf.constants import HYSTERESIS_DOWN_DB, ROUNDING_TOLERANCE_DB
from unifiwifioptimizer.rf.corridor import Corridor


def clamp_tx(tx: int, min_tx: int, max_tx: int) -> int:
    if min_tx > max_tx:
        raise ValueError(f"min_tx {min_tx} exceeds max_tx {max_tx}")
    return min(max(tx, min_tx), max_tx)


@dataclass(frozen=True, slots=True)
class EffectiveMax:
    dbm: int
    source: MaxSource
    # Set exactly for MODEL: the reason no reported ceiling was usable.
    reason: MaxReason | None = None
    # Set exactly for REPORTED: the ceiling the table gives; `dbm` exceeds it by the rounding step when the
    # radio runs at one dB above it.
    limit_dbm: int | None = None

    @property
    def verified(self) -> bool:
        return self.source is MaxSource.DEMONSTRATED


def effective_max_tx(
    mode: TxPowerMode | None, configured: int | None, observed: int | None, model_max: int, ceiling: int | MaxReason
) -> EffectiveMax:
    """The power the radio can reach on its current channel, with the evidence behind it.

    Demonstrated: a Custom radio below its configured power runs at its cap (regulatory EIRP limits minus
    antenna gain), so the observed value is the cap; so does a High radio below the model maximum, because High
    asks for the highest power the channel allows; a radio at the model maximum has reached it. Reported:
    the serving PHY's own limit, which no setting changes; a radio running more than the rounding step above
    it contradicts the table, which is then dropped. The configured value is only meaningful in Custom mode,
    under the automatic modes it is stale. `observed` is None when the radio gives no usable reading: nothing
    is demonstrated or refuted then, and the reported or model level stands.
    """
    if observed is not None:
        setting = configured if mode is TxPowerMode.CUSTOM else None
        if (setting is not None and observed < setting) or (mode is TxPowerMode.HIGH and observed < model_max):
            return EffectiveMax(observed, MaxSource.DEMONSTRATED)
        if observed == model_max or setting == model_max:
            return EffectiveMax(model_max, MaxSource.DEMONSTRATED)
    if isinstance(ceiling, MaxReason):
        return EffectiveMax(model_max, MaxSource.MODEL, ceiling)
    if observed is not None and observed > ceiling + ROUNDING_TOLERANCE_DB:
        return EffectiveMax(model_max, MaxSource.MODEL, MaxReason.REFUTED)
    return EffectiveMax(max(ceiling, observed or 0), MaxSource.REPORTED, limit_dbm=ceiling)


def predict_reverse_rssi(heard_rssi: int, tx_eff_self: int, tx_eff_peer: int) -> int:
    """RSSI the peer would measure from this AP, from what this AP measured of the peer (reciprocity:
    the path loss is the same in both directions, only the transmit powers differ)."""
    return heard_rssi + tx_eff_self - tx_eff_peer


def tx_shift(weakest_rssi: int, corridor: Corridor) -> int:
    """Signed shift that moves the weakest neighbour's reading to the corridor centre."""
    return corridor.center - weakest_rssi


@dataclass(frozen=True, slots=True)
class TxRecommendation:
    recommended: int
    # Pre-clamp value; the caller projects per-neighbour RSSI from it to diagnose coverage gaps.
    uncapped: int

    @property
    def clamped(self) -> bool:
        return self.recommended != self.uncapped


def recommend_tx(current_tx: int, min_tx: int, max_tx: int, weakest_rssi: int, corridor: Corridor) -> TxRecommendation:
    """Recommend a TX power from the weakest reading any configured neighbour took of this AP.

    Inside the corridor nothing changes. Otherwise the shift is applied and clamped to the effective
    radio range; a reduction that clamping has shrunk below HYSTERESIS_DOWN_DB is dropped.
    """
    if corridor.contains(weakest_rssi):
        return TxRecommendation(recommended=current_tx, uncapped=current_tx)
    uncapped = current_tx + tx_shift(weakest_rssi, corridor)
    recommended = clamp_tx(uncapped, min_tx, max_tx)
    delta = recommended - current_tx
    if delta < 0 and -delta < HYSTERESIS_DOWN_DB:
        recommended = current_tx
    return TxRecommendation(recommended=recommended, uncapped=uncapped)
