"""Aggregation of repeated neighbour sightings across scan passes (docs/ALGORITHM.md §2).

Readings taken on different channels are not comparable (a channel move mid-run changes the path), so
only readings on the peer's channel count. The estimator is the median: under Gaussian reading noise of
2 to 3 dB (the repeatability a static ceiling path shows; IEEE 802.11 allows ±5 dB absolute RCPI error),
a maximum of the 2 to 4 samples a run produces is biased high by 1 to 3 dB, the median is unbiased.
"""

import statistics
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Sighting:
    rssi_dbm: int
    # None when the scan line carried no frequency.
    frequency_mhz: int | None = None


def consensus_readings(sightings: Iterable[Sighting], expected_frequency_mhz: int | None = None) -> list[int]:
    """RSSI readings on the peer's channel.

    With `expected_frequency_mhz` (the controller's current channel for the peer) only readings on that
    frequency count. Without it, the frequency seen by a strict majority of all readings wins
    (frequency-less readings count in the denominator but never as values); all readings count when
    none carries a frequency; a tie yields nothing (incomparable channels).
    """
    readings = list(sightings)
    if expected_frequency_mhz is not None:
        return [s.rssi_dbm for s in readings if s.frequency_mhz == expected_frequency_mhz]
    with_frequency = [s.frequency_mhz for s in readings if s.frequency_mhz is not None]
    if not with_frequency:
        return [s.rssi_dbm for s in readings]
    frequency, count = Counter(with_frequency).most_common(1)[0]
    if count * 2 <= len(readings):
        return []
    return [s.rssi_dbm for s in readings if s.frequency_mhz == frequency]


def aggregate_rssi(sightings: Iterable[Sighting], expected_frequency_mhz: int | None = None) -> int | None:
    """One RSSI per neighbour: the median of the usable readings, rounded half to even; None without any."""
    readings = consensus_readings(sightings, expected_frequency_mhz)
    if not readings:
        return None
    return round(statistics.median(readings))


def aggregate_passes(
    sightings_by_bssid: Mapping[str, Iterable[Sighting]],
    expected_frequency_by_bssid: Mapping[str, int] | None = None,
) -> dict[str, int]:
    """Per-BSSID aggregate; a BSSID without a usable reading is dropped."""
    result: dict[str, int] = {}
    for bssid, sightings in sightings_by_bssid.items():
        expected = expected_frequency_by_bssid.get(bssid) if expected_frequency_by_bssid else None
        aggregated = aggregate_rssi(sightings, expected)
        if aggregated is not None:
            result[bssid] = aggregated
    return result
