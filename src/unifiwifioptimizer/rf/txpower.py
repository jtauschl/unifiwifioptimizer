"""TX power recommendation (ADR-002 D8, docs/ALGORITHM.md §4).

The coverage condition holds per neighbour pair, so the corridor is tested against the weakest
configured neighbour's reading of this AP; a 1 dB change in transmit power moves that reading by 1 dB
as long as the radio is below its effective maximum.
"""

from dataclasses import dataclass

from unifiwifioptimizer.rf.constants import HYSTERESIS_DOWN_DB
from unifiwifioptimizer.rf.corridor import Corridor


def clamp_tx(tx: int, min_tx: int, max_tx: int) -> int:
    if min_tx > max_tx:
        raise ValueError(f"min_tx {min_tx} exceeds max_tx {max_tx}")
    return min(max(tx, min_tx), max_tx)


@dataclass(frozen=True, slots=True)
class EffectiveMax:
    dbm: int
    # True when the value was reached or demonstrated on the current channel; False when it is only the
    # configured maximum, and anything above the configured power is headroom nobody has verified.
    verified: bool


def effective_max_tx(configured_max: int, configured: int, observed: int) -> EffectiveMax:
    """The power the radio can actually reach on its current channel.

    Regulatory EIRP limits minus antenna gain cap a radio below its configured maximum; that shows as
    an observed power below the configured one, and the observed value is then the cap. The observed
    power is a conducted total and never exceeds the configured one; the adapter guarantees that order.
    """
    if observed < configured:
        return EffectiveMax(dbm=observed, verified=True)
    return EffectiveMax(dbm=configured_max, verified=configured == configured_max)


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
