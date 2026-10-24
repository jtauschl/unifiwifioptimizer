"""Conservative per-channel TX ceiling inference for the optional 5 GHz plan (docs/ALGORITHM.md §8)."""

from dataclasses import dataclass
from math import floor

from unifiwifioptimizer.rf.channels import occupied_channels_5g

ROUNDING_TOLERANCE_DB = 1


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
