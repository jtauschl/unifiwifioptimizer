import itertools

import pytest
from hypothesis import given
from hypothesis import strategies as st

from unifiwifioptimizer.domain.models import Band
from unifiwifioptimizer.rf.channels import (
    CHANNELS_2G,
    CHANNELS_5G,
    CLEAN_2G_CHANNELS,
    DFS_CHANNELS_5G,
    WEATHER_RADAR_CHANNELS_5G,
    WIDTHS_2G,
    WIDTHS_5G,
    ChannelBlock,
    cac_seconds,
    center_frequency_mhz,
    channel_block_5g,
    channel_reuse_feasible,
    channels_overlap,
    is_dfs_channel,
)

channels_2g = st.sampled_from(sorted(CHANNELS_2G))
channels_5g = st.sampled_from(sorted(CHANNELS_5G))
widths_2g = st.sampled_from(sorted(WIDTHS_2G))


def blocks_5g() -> st.SearchStrategy[tuple[int, int]]:
    """(channel, width) pairs that form a valid bonded block."""
    return st.tuples(channels_5g, st.sampled_from(sorted(WIDTHS_5G))).filter(lambda p: _valid(*p))


def _valid(channel: int, width: int) -> bool:
    try:
        channel_block_5g(channel, width)
    except ValueError:
        return False
    return True


@pytest.mark.parametrize(("channel", "mhz"), [(1, 2412), (6, 2437), (11, 2462), (13, 2472), (14, 2484)])
def test_2g_centre_frequencies(channel: int, mhz: int) -> None:
    assert center_frequency_mhz(Band.GHZ_2, channel) == mhz


@pytest.mark.parametrize(("channel", "mhz"), [(36, 5180), (100, 5500), (149, 5745), (165, 5825), (177, 5885)])
def test_5g_centre_frequencies(channel: int, mhz: int) -> None:
    assert center_frequency_mhz(Band.GHZ_5, channel) == mhz


@pytest.mark.parametrize(
    ("band", "channel"), [(Band.GHZ_2, 0), (Band.GHZ_2, 15), (Band.GHZ_5, 38), (Band.GHZ_5, 181), (Band.GHZ_6, 5)]
)
def test_unknown_channels_and_6ghz_are_rejected(band: Band, channel: int) -> None:
    with pytest.raises(ValueError):
        center_frequency_mhz(band, channel)


@pytest.mark.parametrize(
    ("channel", "width", "block"),
    [
        (36, 20, (36, 36)),
        (40, 40, (36, 40)),
        (144, 40, (140, 144)),
        (161, 40, (157, 161)),
        (48, 80, (36, 48)),
        (144, 80, (132, 144)),
        (153, 80, (149, 161)),
        (165, 40, (165, 169)),
        (173, 80, (165, 177)),
        (64, 160, (36, 64)),
        (128, 160, (100, 128)),
        (177, 160, (149, 177)),
    ],
)
def test_5g_blocks_match_the_bonding_table(channel: int, width: int, block: tuple[int, int]) -> None:
    assert channel_block_5g(channel, width) == ChannelBlock(*block)


@pytest.mark.parametrize("channel", [32, 34, 38, 66, 68, 96, 148, 181])
def test_block_of_a_non_channel_is_rejected(channel: int) -> None:
    with pytest.raises(ValueError, match="no 5 GHz channel"):
        channel_block_5g(channel, 20)


@pytest.mark.parametrize(("channel", "width"), [(144, 160), (165, 10), (36, 30)])
def test_blocks_that_leave_their_unii_range_are_rejected(channel: int, width: int) -> None:
    with pytest.raises(ValueError):
        channel_block_5g(channel, width)


def test_5g_channel_set_is_the_superset_of_the_regulatory_domains() -> None:
    assert sorted(CHANNELS_5G) == [*range(36, 65, 4), *range(100, 145, 4), *range(149, 178, 4)]


def test_dfs_channels_are_52_to_144_with_the_weather_radar_subset() -> None:
    assert sorted(DFS_CHANNELS_5G) == [*range(52, 65, 4), *range(100, 145, 4)]
    assert WEATHER_RADAR_CHANNELS_5G < DFS_CHANNELS_5G
    assert [is_dfs_channel(c) for c in (36, 48, 52, 144, 149)] == [False, False, True, True, False]


@pytest.mark.parametrize(
    ("channel", "seconds"),
    [(36, None), (52, 60), (116, 60), (120, 600), (124, 600), (128, 600), (132, 60), (149, None)],
)
def test_cac_duration_per_channel(channel: int, seconds: int | None) -> None:
    assert cac_seconds(channel) == seconds


def test_dfs_and_cac_consider_the_whole_bonded_block() -> None:
    # 116/40 occupies 116 and 120: the weather-radar channel sets the CAC.
    assert cac_seconds(116, 40) == 600
    # 36/160 occupies 36-64, which includes the DFS channels 52-64.
    assert is_dfs_channel(36, 160) and not is_dfs_channel(36, 80)
    assert cac_seconds(36, 160) == 60 and cac_seconds(36, 80) is None


def test_punctured_widths_fail_with_a_specific_message() -> None:
    with pytest.raises(ValueError, match="punctured"):
        channel_block_5g(36, 240)
    with pytest.raises(ValueError, match="punctured"):
        channel_block_5g(36, 320)


def test_clean_2g_channels_are_1_6_11() -> None:
    assert {1, 6, 11} == CLEAN_2G_CHANNELS


def test_clean_2g_channels_are_pairwise_disjoint_at_20_mhz() -> None:
    clean = sorted(CLEAN_2G_CHANNELS)
    for a in clean:
        for b in clean:
            assert channels_overlap(Band.GHZ_2, a, 20, b, 20) == (a == b)


def test_the_guard_band_makes_channel_14_overlap_channel_11() -> None:
    # 2484 - 2462 = 22 MHz: disjoint without the 2 MHz guard, overlapping with it.
    assert channels_overlap(Band.GHZ_2, 11, 20, 14, 20)
    assert not channels_overlap(Band.GHZ_2, 10, 20, 14, 20)


def test_adjacent_2g_channels_overlap_and_40_mhz_overlaps_its_neighbours() -> None:
    assert channels_overlap(Band.GHZ_2, 1, 20, 5, 20)
    assert channels_overlap(Band.GHZ_2, 1, 40, 6, 20)
    assert not channels_overlap(Band.GHZ_2, 1, 20, 6, 20)


def test_5g_blocks_overlap_only_when_they_share_a_channel() -> None:
    assert channels_overlap(Band.GHZ_5, 36, 80, 44, 20)
    assert not channels_overlap(Band.GHZ_5, 36, 80, 52, 80)
    assert channels_overlap(Band.GHZ_5, 100, 160, 128, 20)


def test_6ghz_overlap_is_not_evaluated() -> None:
    with pytest.raises(ValueError):
        channels_overlap(Band.GHZ_6, 5, 20, 5, 20)


@pytest.mark.parametrize("width", [10, 80])
def test_unsupported_2g_width_is_rejected(width: int) -> None:
    with pytest.raises(ValueError):
        channels_overlap(Band.GHZ_2, 1, width, 6, 20)


def test_a_star_of_any_size_fits_three_channels() -> None:
    assert channel_reuse_feasible({"hub": ["a", "b", "c", "d", "e"], "a": [], "b": [], "c": [], "d": [], "e": []}, 3)


def test_a_triangle_needs_three_channels_and_a_k4_needs_four() -> None:
    triangle = {"a": ["b", "c"], "b": ["c"], "c": []}
    assert not channel_reuse_feasible(triangle, 2)
    assert channel_reuse_feasible(triangle, 3)
    k4 = {"a": ["b", "c", "d"], "b": ["c", "d"], "c": ["d"], "d": []}
    assert not channel_reuse_feasible(k4, 3)
    assert channel_reuse_feasible(k4, 4)


def test_adjacency_is_treated_as_undirected_and_unknown_peers_are_ignored() -> None:
    assert not channel_reuse_feasible({"a": ["b"], "b": []}, 1)
    assert channel_reuse_feasible({"a": ["b", "ghost"], "b": ["a"]}, 2)
    assert channel_reuse_feasible({"a": ["a"]}, 1)


def test_an_empty_graph_is_feasible() -> None:
    assert channel_reuse_feasible({}, 3)


def test_colouring_backtracks_where_a_greedy_order_would_fail() -> None:
    # Both graphs are 2-colourable; a greedy assignment in node order paints a and b alike and then
    # cannot place d (first graph) or e (second graph).
    assert channel_reuse_feasible({"a": ["d"], "b": ["c"], "c": ["d"], "d": []}, 2)
    assert channel_reuse_feasible({"a": ["d", "e"], "b": ["c"], "c": ["e"], "d": [], "e": []}, 2)


def brute_force_colourable(adjacency: dict[str, list[str]], colours: int) -> bool:
    nodes = sorted(adjacency)
    edges = {(n, m) for n in nodes for m in adjacency[n] if m in adjacency and m != n}
    return any(
        all(assignment[nodes.index(n)] != assignment[nodes.index(m)] for n, m in edges)
        for assignment in itertools.product(range(colours), repeat=len(nodes))
    )


@given(
    st.integers(1, 6).flatmap(
        lambda n: st.lists(st.frozensets(st.integers(0, n - 1), max_size=2), min_size=n, max_size=n)
    ),
    st.integers(1, 4),
)
def test_colouring_agrees_with_brute_force(edge_lists: list[frozenset[int]], colours: int) -> None:
    nodes = [f"ap{i}" for i in range(len(edge_lists))]
    adjacency = {n: [nodes[j] for j in edge_lists[i]] for i, n in enumerate(nodes)}
    assert channel_reuse_feasible(adjacency, colours) == brute_force_colourable(adjacency, colours)


@given(st.integers(2, 6), st.integers(1, 6))
def test_a_clique_needs_exactly_its_size_in_channels(size: int, channels: int) -> None:
    nodes = [f"ap{i}" for i in range(size)]
    clique = {n: [m for m in nodes if m != n] for n in nodes}
    assert channel_reuse_feasible(clique, channels) == (channels >= size)


@given(st.integers(2, 8), st.integers(1, 4))
def test_a_path_needs_two_channels(length: int, channels: int) -> None:
    nodes = [f"ap{i}" for i in range(length)]
    path = {n: ([nodes[i + 1]] if i + 1 < length else []) for i, n in enumerate(nodes)}
    assert channel_reuse_feasible(path, channels) == (channels >= 2)


@given(channels_2g, widths_2g, channels_2g, widths_2g)
def test_2g_overlap_is_symmetric_and_reflexive(a: int, wa: int, b: int, wb: int) -> None:
    assert channels_overlap(Band.GHZ_2, a, wa, b, wb) == channels_overlap(Band.GHZ_2, b, wb, a, wa)
    assert channels_overlap(Band.GHZ_2, a, wa, a, wa)


@given(blocks_5g(), blocks_5g())
def test_5g_overlap_is_symmetric_reflexive_and_means_a_shared_channel(a: tuple[int, int], b: tuple[int, int]) -> None:
    assert channels_overlap(Band.GHZ_5, *a, *b) == channels_overlap(Band.GHZ_5, *b, *a)
    assert channels_overlap(Band.GHZ_5, *a, *a)
    block_a, block_b = channel_block_5g(*a), channel_block_5g(*b)
    shared = set(range(block_a.low, block_a.high + 1, 4)) & set(range(block_b.low, block_b.high + 1, 4))
    assert channels_overlap(Band.GHZ_5, *a, *b) == bool(shared)


@given(blocks_5g())
def test_a_5g_block_contains_its_channel_and_has_the_declared_width(pair: tuple[int, int]) -> None:
    channel, width = pair
    block = channel_block_5g(channel, width)
    assert block.low <= channel <= block.high
    assert (block.high - block.low) // 4 + 1 == width // 20
    assert all(c in CHANNELS_5G for c in range(block.low, block.high + 1, 4))
