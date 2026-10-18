"""Cell edge and TX corridor derivation (docs/ALGORITHM.md §5).

The corridor is the RSSI band a neighbouring AP should measure from this AP. On 5 GHz it starts at the
cell edge itself: the secondary-coverage rule (every point served by two APs at or above the edge)
has its worst point for the second-strongest signal at an AP's own location, so the neighbour must
hear this AP at the edge there. On 2.4 GHz it starts lower by the extra path loss from 60 % of the AP
distance to the full distance (20 %-overlap rule with the ITU-R P.1238 log-distance model), because
three channels make full overlap harmful.
"""

import math
from dataclasses import dataclass

from unifiwifioptimizer.domain.models import Band
from unifiwifioptimizer.rf.constants import (
    CORRIDOR_WIDTH_DB,
    DEFAULT_NOISE_FLOOR_DBM,
    DEFAULT_REQUIRED_SNR_DB,
    NOISE_FLOOR_RANGE,
    OVERLAP_DISTANCE_PERCENT,
    PATH_LOSS_PRESETS,
    SNR_RANGE,
    span,
)


@dataclass(frozen=True, slots=True)
class CellEdge:
    """Minimum usable downlink RSSI, derived from the noise floor and the SNR the target rate needs."""

    noise_floor_dbm: int = DEFAULT_NOISE_FLOOR_DBM
    required_snr_db: int = DEFAULT_REQUIRED_SNR_DB

    def __post_init__(self) -> None:
        if self.noise_floor_dbm not in NOISE_FLOOR_RANGE:
            raise ValueError(f"noise floor must be in {span(NOISE_FLOOR_RANGE)} dBm, got {self.noise_floor_dbm}")
        if self.required_snr_db not in SNR_RANGE:
            raise ValueError(f"required SNR must be in {span(SNR_RANGE)} dB, got {self.required_snr_db}")

    @property
    def dbm(self) -> int:
        return self.noise_floor_dbm + self.required_snr_db


DEFAULT_CELL_EDGE = CellEdge()


@dataclass(frozen=True, slots=True)
class PathLossModel:
    """Path-loss exponent n of a site, either a named preset or a custom positive number."""

    exponent: float
    preset: str | None = None

    def __post_init__(self) -> None:
        if not math.isfinite(self.exponent) or self.exponent <= 0:
            raise ValueError(f"path-loss exponent must be a finite positive number, got {self.exponent!r}")

    @classmethod
    def from_preset(cls, name: str) -> "PathLossModel":
        """Case-insensitive lookup; `preset` keeps the canonical spelling."""
        for canonical, exponent in PATH_LOSS_PRESETS.items():
            if canonical.casefold() == name.casefold():
                return cls(exponent, preset=canonical)
        raise ValueError(f"unknown environment preset {name!r}; expected one of {sorted(PATH_LOSS_PRESETS)}")

    @classmethod
    def custom(cls, exponent: float) -> "PathLossModel":
        return cls(float(exponent))

    @property
    def delta_db(self) -> float:
        """Extra path loss from 60 % of the AP-to-AP distance to the full distance."""
        return 10 * self.exponent * math.log10(100 / OVERLAP_DISTANCE_PERCENT)


@dataclass(frozen=True, slots=True)
class Corridor:
    """Inclusive RSSI band [low, high] in dBm that a neighbour should measure from this AP."""

    low: int

    @property
    def high(self) -> int:
        return self.low + CORRIDOR_WIDTH_DB

    @property
    def center(self) -> int:
        return self.low + CORRIDOR_WIDTH_DB // 2

    def contains(self, rssi_dbm: int) -> bool:
        return self.low <= rssi_dbm <= self.high


def corridor_for(band: Band, model: PathLossModel, edge: CellEdge = DEFAULT_CELL_EDGE) -> Corridor:
    if band is Band.GHZ_5:
        return Corridor(low=edge.dbm)
    if band is Band.GHZ_2:
        return Corridor(low=round(edge.dbm - model.delta_db))
    raise ValueError(f"{band.label} has no corridor: the band is detected but not evaluated")
