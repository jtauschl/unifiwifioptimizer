"""Per-AP Roaming Assistant (Handoff Suggestions) threshold (ADR-002 D8, docs/ALGORITHM.md §7).

The threshold is derived on the downlink, where the published client roaming triggers live, clamped
there, and then converted to the uplink the controller evaluates it on.
"""

from dataclasses import dataclass
from enum import StrEnum

from unifiwifioptimizer.rf.constants import (
    DB_TUNABLE_RANGE,
    DBM_TUNABLE_RANGE,
    DEFAULT_CLIENT_TX_DBM,
    DEFAULT_ROAM_CEILING_DBM,
    DEFAULT_ROAM_FLOOR_DBM,
    DEFAULT_ROAM_MARGIN_DB,
    DEFAULT_ROAM_OFFSET_DB,
    span,
)
from unifiwifioptimizer.rf.corridor import Corridor
from unifiwifioptimizer.rf.minrssi import uplink_threshold


@dataclass(frozen=True, slots=True)
class RoamingTunables:
    offset_db: int = DEFAULT_ROAM_OFFSET_DB
    margin_db: int = DEFAULT_ROAM_MARGIN_DB
    floor_dbm: int = DEFAULT_ROAM_FLOOR_DBM
    ceiling_dbm: int = DEFAULT_ROAM_CEILING_DBM

    def __post_init__(self) -> None:
        for name in ("offset_db", "margin_db"):
            if getattr(self, name) not in DB_TUNABLE_RANGE:
                raise ValueError(f"{name} must be in {span(DB_TUNABLE_RANGE)} dB, got {getattr(self, name)}")
        for name in ("floor_dbm", "ceiling_dbm"):
            if getattr(self, name) not in DBM_TUNABLE_RANGE:
                raise ValueError(f"{name} must be in {span(DBM_TUNABLE_RANGE)} dBm, got {getattr(self, name)}")
        if self.floor_dbm >= self.ceiling_dbm:
            raise ValueError(f"floor {self.floor_dbm} dBm must be below ceiling {self.ceiling_dbm} dBm")


DEFAULT_TUNABLES = RoamingTunables()


class RoamingCap(StrEnum):
    NONE = "none"
    # The weakest neighbour minus the margin pulled the threshold below the default, at or above the floor.
    MARGIN = "capped_by_margin"
    # The weakest neighbour minus the margin fell below the floor and was clamped to it.
    FLOOR = "capped_by_floor"


@dataclass(frozen=True, slots=True)
class RoamingRecommendation:
    # Client-side trigger after the cap and the clamp.
    downlink_dbm: int
    # The same trigger as the AP measures it on the uplink; this is the value to configure.
    uplink_dbm: int
    cap: RoamingCap
    # The unclamped `weakest - margin` value when a cap engaged, for the report's explanation.
    raw_cap_dbm: int | None


def recommend_roaming(
    corridor: Corridor,
    weakest_neighbour_rssi: int | None,
    tx_eff_ap_dbm: int,
    client_tx_dbm: int = DEFAULT_CLIENT_TX_DBM,
    tunables: RoamingTunables = DEFAULT_TUNABLES,
) -> RoamingRecommendation:
    """Downlink threshold = corridor.low + offset, capped by the weakest neighbour only when that
    neighbour is below the corridor, clamped to [floor, ceiling], then converted to the uplink."""
    default = corridor.low + tunables.offset_db
    threshold = default
    cap = RoamingCap.NONE
    raw_cap: int | None = None
    if weakest_neighbour_rssi is not None and weakest_neighbour_rssi < corridor.low:
        # weakest < low <= default and margin >= 0, so the cap is always below the default.
        threshold = raw_cap = weakest_neighbour_rssi - tunables.margin_db
        cap = RoamingCap.FLOOR if threshold < tunables.floor_dbm else RoamingCap.MARGIN
    threshold = min(max(threshold, tunables.floor_dbm), tunables.ceiling_dbm)
    return RoamingRecommendation(
        downlink_dbm=threshold,
        uplink_dbm=uplink_threshold(threshold, tx_eff_ap_dbm, client_tx_dbm),
        cap=cap,
        raw_cap_dbm=raw_cap,
    )
