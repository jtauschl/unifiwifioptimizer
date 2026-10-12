"""Channel geometry: centre frequencies, bonded 5 GHz blocks, spectral overlap, DFS, channel-reuse
feasibility (IEEE 802.11 Annex E, EN 301 893; docs/ALGORITHM.md §8 and §9)."""

from collections.abc import Hashable, Iterable, Mapping
from dataclasses import dataclass
from typing import TypeVar

from unifiwifioptimizer.domain.models import Band

Node = TypeVar("Node", bound=Hashable)

# The three non-overlapping 20 MHz channels of the 2.4 GHz band.
CLEAN_2G_CHANNELS = frozenset({1, 6, 11})
# 2.4 GHz channels sit 5 MHz apart; a guard band keeps 1/6/11 at 20 MHz non-overlapping while any
# closer pair is flagged.
GUARD_2G_MHZ = 2

CHANNELS_2G = frozenset(range(1, 15))
# UNII-1/2A, UNII-2C and UNII-3/4 as (first channel, number of 20 MHz channels): a bonded block never
# crosses one of these ranges. The set is a superset of any one regulatory domain.
_5G_RANGES = ((36, 8), (100, 12), (149, 8))
CHANNELS_5G = frozenset(ch for base, n in _5G_RANGES for ch in range(base, base + 4 * n, 4))
# Channels 52-144 (5250-5730 MHz) are the union of the DFS channels of the ETSI, FCC and Japanese rules
# (144 itself lies outside the ETSI 5470-5725 MHz band). The channel availability check durations are
# the EN 301 893 figures: 60 s, and 10 minutes on the 5600-5650 MHz weather-radar sub-band (FCC uses
# 60 s throughout). Radar detection covers the whole occupied bandwidth, so a bonded block is judged by
# every 20 MHz channel it contains.
DFS_CHANNELS_5G = frozenset(range(52, 65, 4)) | frozenset(range(100, 145, 4))
WEATHER_RADAR_CHANNELS_5G = frozenset({120, 124, 128})
CAC_SECONDS = 60
WEATHER_RADAR_CAC_SECONDS = 600
WIDTHS_2G = frozenset({20, 40})
WIDTHS_5G = frozenset({20, 40, 80, 160})
# Wi-Fi 7 punctured widths the controller may report but the geometry does not model.
PUNCTURED_WIDTHS_5G = frozenset({240, 320})


def center_frequency_mhz(band: Band, channel: int) -> int:
    if band is Band.GHZ_2:
        if channel not in CHANNELS_2G:
            raise ValueError(f"no 2.4 GHz channel {channel}")
        return 2484 if channel == 14 else 2407 + 5 * channel
    if band is Band.GHZ_5:
        if channel not in CHANNELS_5G:
            raise ValueError(f"no 5 GHz channel {channel}")
        return 5000 + 5 * channel
    raise ValueError(f"{band.label} channel geometry is not evaluated")


def center_frequency_or_none(band: Band, channel: int) -> int | None:
    """`center_frequency_mhz` for a channel the controller reported, None when it is not one of the band's."""
    try:
        return center_frequency_mhz(band, channel)
    except ValueError:
        return None


def channel_from_frequency(band: Band, frequency_mhz: int) -> int | None:
    """The 20 MHz channel number a scan reported by its frequency; None off the band's grid."""
    if band is Band.GHZ_2:
        if frequency_mhz == 2484:
            return 14
        channel, rest = divmod(frequency_mhz - 2407, 5)
        return channel if rest == 0 and channel in CHANNELS_2G else None
    if band is Band.GHZ_5:
        channel, rest = divmod(frequency_mhz - 5000, 5)
        return channel if rest == 0 and channel in CHANNELS_5G else None
    return None


@dataclass(frozen=True, slots=True)
class ChannelBlock:
    """Inclusive range of 20 MHz channel numbers a bonded 5 GHz channel occupies."""

    low: int
    high: int

    def overlaps(self, other: "ChannelBlock") -> bool:
        return self.high >= other.low and other.high >= self.low


def _unii_range(channel: int) -> tuple[int, int]:
    """(first channel, channel count) of the UNII range holding `channel`."""
    for base, count in _5G_RANGES:
        if base <= channel < base + 4 * count and (channel - base) % 4 == 0:
            return base, count
    raise ValueError(f"no 5 GHz channel {channel}")


def channel_block_5g(channel: int, width_mhz: int) -> ChannelBlock:
    """The bonded block containing `channel`; a block must lie inside one UNII range."""
    base, count = _unii_range(channel)
    if width_mhz in PUNCTURED_WIDTHS_5G:
        raise ValueError(f"unsupported {width_mhz} MHz width (Wi-Fi 7 punctured channel, not modelled)")
    if width_mhz not in WIDTHS_5G:
        raise ValueError(f"unsupported 5 GHz width {width_mhz} MHz")
    size = width_mhz // 20
    index = (channel - base) // 4
    start = index - index % size
    if start + size > count:
        raise ValueError(f"channel {channel} has no {width_mhz} MHz block inside its UNII range")
    return ChannelBlock(low=base + 4 * start, high=base + 4 * (start + size - 1))


def occupied_channels_5g(channel: int, width_mhz: int = 20) -> frozenset[int]:
    block = channel_block_5g(channel, width_mhz)
    return frozenset(range(block.low, block.high + 1, 4))


def is_dfs_channel(channel: int, width_mhz: int = 20) -> bool:
    return bool(occupied_channels_5g(channel, width_mhz) & DFS_CHANNELS_5G)


def cac_seconds(channel: int, width_mhz: int = 20) -> int | None:
    """Channel availability check a radio must complete before transmitting a block on `channel`;
    None when no part of the block needs one."""
    occupied = occupied_channels_5g(channel, width_mhz)
    if occupied & WEATHER_RADAR_CHANNELS_5G:
        return WEATHER_RADAR_CAC_SECONDS
    if occupied & DFS_CHANNELS_5G:
        return CAC_SECONDS
    return None


def block_center_frequency_2g_mhz(channel: int, width_mhz: int, extension_channel: int | None) -> int:
    """Centre of the occupied 2.4 GHz block. A 40 MHz block is the primary 20 MHz channel plus the secondary
    above (`extension_channel` 1) or below (-1), so its centre sits 10 MHz off the primary; without the
    secondary's position the primary's frequency is the best available centre (a known inexactness)."""
    if width_mhz not in WIDTHS_2G:
        raise ValueError(f"unsupported 2.4 GHz width {width_mhz} MHz")
    frequency = center_frequency_mhz(Band.GHZ_2, channel)
    if width_mhz == 40 and extension_channel in (-1, 1):
        return frequency + 10 * extension_channel
    return frequency


def channels_overlap(
    band: Band,
    channel_a: int,
    width_a: int,
    channel_b: int,
    width_b: int,
    extension_a: int | None = None,
    extension_b: int | None = None,
) -> bool:
    """Whether two channel/width pairs occupy overlapping spectrum; on 2.4 GHz the 40 MHz block centres follow
    the extension channels when they are known."""
    if band is Band.GHZ_5:
        return channel_block_5g(channel_a, width_a).overlaps(channel_block_5g(channel_b, width_b))
    if band is Band.GHZ_2:
        half_a = width_a // 2 + GUARD_2G_MHZ
        half_b = width_b // 2 + GUARD_2G_MHZ
        freq_a = block_center_frequency_2g_mhz(channel_a, width_a, extension_a)
        freq_b = block_center_frequency_2g_mhz(channel_b, width_b, extension_b)
        return freq_a + half_a > freq_b - half_b and freq_b + half_b > freq_a - half_a
    raise ValueError(f"{band.label} channel geometry is not evaluated")


def channel_reuse_feasible(adjacency: Mapping[Node, Iterable[Node]], channels: int) -> bool:
    """Whether every AP in the adjacency graph can get a channel distinct from all its neighbours using
    at most `channels` channels (proper graph colouring; exact search, the graphs are small)."""
    nodes = sorted(adjacency, key=str)
    neighbours: dict[Node, set[Node]] = {n: set() for n in nodes}
    for n in nodes:
        for m in adjacency[n]:
            # A neighbour that is not itself a node has no channel of its own to conflict with.
            if m in neighbours:
                neighbours[n].add(m)
                neighbours[m].add(n)
    colour: dict[Node, int] = {}

    def assign(index: int) -> bool:
        if index == len(nodes):
            return True
        node = nodes[index]
        for candidate in range(channels):
            if all(colour.get(m) != candidate for m in neighbours[node]):
                colour[node] = candidate
                if assign(index + 1):
                    return True
                del colour[node]
        return False

    return assign(0)
