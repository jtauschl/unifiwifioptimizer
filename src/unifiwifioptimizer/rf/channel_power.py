"""Per-channel TX ceilings from a serving PHY's `iw` limits: the reported ceiling of the current channel for
the effective maximum (docs/ALGORITHM.md §4) and the calibrated candidate ceilings of the optional 5 GHz plan
(docs/ALGORITHM.md §8)."""

from dataclasses import dataclass
from math import floor

from unifiwifioptimizer.domain.analysis import MaxReason
from unifiwifioptimizer.domain.models import Band
from unifiwifioptimizer.rf.channels import occupied_channels_5g
from unifiwifioptimizer.rf.constants import ROUNDING_TOLERANCE_DB

# A 20 MHz secondary channel sits four 5 MHz channel numbers from the primary.
SECONDARY_OFFSET_2G = 4
# Channel 14 (2484 MHz) is off the 5 MHz grid and never a secondary: primary 10 plus four would not be 2484 MHz.
SECONDARY_CHANNELS_2G = frozenset(range(1, 14))


@dataclass(frozen=True, slots=True, kw_only=True)
class PowerCeilings:
    """Observed current conducted TX and calibrated, unverified future conducted ceilings."""

    current_dbm: int
    candidates: tuple[tuple[int, int], ...]

    def ceiling(self, channel: int) -> int | None:
        return next((power for candidate, power in self.candidates if candidate == channel), None)


def candidate_ceiling(
    channel: int,
    width_mhz: int,
    limits: dict[int, float],
    setting_cap_dbm: int,
    hardware_max_dbm: int,
    antenna_gain_dbi: int,
) -> int | None:
    """Use the weakest occupied 20 MHz limit; the result is a ceiling, never achieved future TX."""
    try:
        powers = [limits[subchannel] for subchannel in occupied_channels_5g(channel, width_mhz)]
    except (KeyError, ValueError):
        return None
    if any(power <= 0 for power in powers):
        return None
    ceiling = min(setting_cap_dbm, hardware_max_dbm, floor(min(powers) - antenna_gain_dbi))
    return ceiling if ceiling > 0 else None


def _occupied_channels_2g(channel: int, width_mhz: int, extension_channel: int | None) -> tuple[int, ...]:
    """The primary channel and, at 40 MHz, its secondary: the side the controller names, else every side that
    is a channel of the band."""
    if width_mhz <= 20:
        return (channel,)
    sides = (extension_channel,) if extension_channel in (-1, 1) else (-1, 1)
    secondaries = (channel + SECONDARY_OFFSET_2G * side for side in sides)
    named = extension_channel in (-1, 1)
    return (channel, *(c for c in secondaries if named or c in SECONDARY_CHANNELS_2G))


def reported_ceiling(
    band: Band,
    channel: int,
    width_mhz: int,
    extension_channel: int | None,
    limits: tuple[tuple[int, float], ...],
    model_max_dbm: int,
    antenna_gain_dbi: int | None,
) -> int | MaxReason:
    """The conducted power the serving PHY's limits allow on the occupied channels: the weakest limit minus the
    antenna gain, floored and capped by the model maximum. Every occupied channel needs a limit: a table that
    lacks one proves no freedom there."""
    if antenna_gain_dbi is None or antenna_gain_dbi < 0:
        return MaxReason.NO_ANTENNA_GAIN
    table = dict(limits)
    try:
        occupied = (
            occupied_channels_5g(channel, width_mhz)
            if band is Band.GHZ_5
            else _occupied_channels_2g(channel, width_mhz, extension_channel)
        )
    except ValueError:
        return MaxReason.NO_LIMIT
    if not set(occupied) <= table.keys():
        return MaxReason.NO_LIMIT
    powers = [table[c] for c in occupied]
    ceiling = min(model_max_dbm, floor(min(powers) - antenna_gain_dbi))
    return ceiling if ceiling > 0 else MaxReason.NO_LIMIT


def calibrated_ceilings(
    current_channel: int,
    width_mhz: int,
    observed_dbm: int | None,
    setting_cap_dbm: int | None,
    hardware_max_dbm: int | None,
    antenna_gain_dbi: int | None,
    limits: tuple[tuple[int, float], ...],
    candidates: tuple[int, ...],
) -> PowerCeilings | None:
    """Reject a driver/table whose current reading does not fit the candidate projection. The projection of the
    current channel is within a rounding step of the observed power; every candidate is shifted by that step, so
    the observed power and the projections agree and only the table's differences between channels remain."""
    if observed_dbm is None or setting_cap_dbm is None or hardware_max_dbm is None or antenna_gain_dbi is None:
        return None
    if observed_dbm <= 0 or setting_cap_dbm <= 0 or hardware_max_dbm <= 0 or antenna_gain_dbi < 0:
        return None
    table = dict(limits)
    current = candidate_ceiling(current_channel, width_mhz, table, setting_cap_dbm, hardware_max_dbm, antenna_gain_dbi)
    if current is None or abs(current - observed_dbm) > ROUNDING_TOLERANCE_DB:
        return None
    shift = observed_dbm - current
    limit = min(setting_cap_dbm, hardware_max_dbm)
    projected = tuple(
        (candidate, min(ceiling + shift, limit))
        for candidate in candidates
        if (
            ceiling := candidate_ceiling(
                candidate, width_mhz, table, setting_cap_dbm, hardware_max_dbm, antenna_gain_dbi
            )
        )
        is not None
        and ceiling + shift > 0
    )
    return PowerCeilings(current_dbm=observed_dbm, candidates=projected)
