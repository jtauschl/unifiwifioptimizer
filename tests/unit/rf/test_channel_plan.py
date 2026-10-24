"""Site-wide channel search: residual reuse, signal ranking, bonded geometry and bounded search."""

import time
from itertools import combinations, product

from hypothesis import given, settings
from hypothesis import strategies as st

from unifiwifioptimizer.domain.models import Band
from unifiwifioptimizer.rf.channel_plan import (
    HEURISTIC_LIMIT,
    PlanEdge,
    PlanRadio,
    canonical_candidates,
    optimize,
)


def radio(
    name: str,
    current: int = 1,
    choices: tuple[int, ...] = (1, 6, 11),
    foreign: tuple[tuple[int, int], ...] = (),
) -> PlanRadio:
    return PlanRadio(name=name, band=Band.GHZ_2, current=current, width_mhz=20, candidates=choices, foreign=foreign)


def test_five_mutually_heard_access_points_reuse_channels_and_show_residual_conflicts() -> None:
    radios = tuple(radio(f"AP-{i}") for i in range(5))
    edges = tuple(PlanEdge(a=a.name, b=b.name, rssi_dbm=-70) for i, a in enumerate(radios) for b in radios[i + 1 :])
    plan = optimize(radios, edges)
    assert plan.method == "exact" and plan.improved
    assert plan.before.own_conflicts == 10 and plan.after.own_conflicts == 2
    assert len(set(plan.after.channels)) == 3


def test_strong_overlap_is_avoided_before_weak_overlap() -> None:
    radios = (radio("A", choices=(1, 6)), radio("B", choices=(1, 6)), radio("C", choices=(1, 6)))
    edges = (
        PlanEdge(a="A", b="B", rssi_dbm=-55),
        PlanEdge(a="A", b="C", rssi_dbm=-80),
        PlanEdge(a="B", b="C", rssi_dbm=-81),
    )
    plan = optimize(radios, edges)
    assert plan.after.channels[0] != plan.after.channels[1]
    assert plan.after.own_conflicts == 1 and plan.after.own_pressure == 2


def test_bonded_eighty_mhz_primaries_collapse_and_overlap_as_whole_blocks() -> None:
    choices = canonical_candidates(Band.GHZ_5, 80, (36, 40, 44, 48, 52, 56, 60, 64), 44)
    assert choices == (44, 52)
    a = PlanRadio(name="A", band=Band.GHZ_5, current=44, width_mhz=80, candidates=choices)
    b = PlanRadio(name="B", band=Band.GHZ_5, current=48, width_mhz=80, candidates=(48, 52))
    plan = optimize((a, b), (PlanEdge(a="A", b="B", rssi_dbm=-60),))
    assert plan.before.own_conflicts == 1 and plan.after.own_conflicts == 0


def test_foreign_observations_only_break_ties_and_no_own_gain_means_no_change() -> None:
    a = radio("A", choices=(1, 6), foreign=((1, -50),))
    b = radio("B", choices=(1, 6), foreign=((6, -60),))
    plan = optimize((a, b), (PlanEdge(a="A", b="B", rssi_dbm=-70),))
    assert plan.after.channels == (6, 1)
    without_own_edge = optimize((a,), ())
    assert without_own_edge.after.channels == (1,) and not without_own_edge.improved


def test_input_permutations_do_not_change_assignment() -> None:
    radios = (radio("C"), radio("A"), radio("B"))
    edges = (PlanEdge(a="B", b="C", rssi_dbm=-70), PlanEdge(a="A", b="B", rssi_dbm=-60))
    first = optimize(radios, edges)
    second = optimize(tuple(reversed(radios)), tuple(reversed(edges)))
    assert first == second


def test_large_product_uses_bounded_heuristic() -> None:
    radios = tuple(radio(f"AP-{i:02d}") for i in range(16))
    edges = tuple(PlanEdge(a=radios[i].name, b=radios[i + 1].name, rssi_dbm=-65) for i in range(15))
    plan = optimize(radios, edges)
    assert plan.method == "heuristic" and plan.evaluations <= HEURISTIC_LIMIT
    assert plan.after.own_pressure == 0


def test_possible_power_increase_can_create_an_edge_below_the_current_cca_threshold() -> None:
    radios = (
        PlanRadio(
            name="A",
            band=Band.GHZ_5,
            current=52,
            width_mhz=80,
            candidates=(52, 120),
            current_power_dbm=18,
            candidate_ceilings=((52, 18), (120, 24)),
        ),
        PlanRadio(name="B", band=Band.GHZ_5, current=52, width_mhz=80, candidates=(52,)),
        PlanRadio(name="C", band=Band.GHZ_5, current=120, width_mhz=80, candidates=(120,)),
    )
    edges = (
        PlanEdge(a="A", b="B", rssi_dbm=-70, a_at_b_dbm=-70),
        PlanEdge(a="A", b="C", rssi_dbm=-84, a_at_b_dbm=-84),
    )
    plan = optimize(radios, edges)
    assert plan.improved and plan.after.channels == (120, 52, 120)
    assert plan.after.own_pressure == 0 and plan.after.power_risk == 5
    blocked = optimize(radios, (edges[0], PlanEdge(a="A", b="C", rssi_dbm=-75, a_at_b_dbm=-75)))
    assert not blocked.improved and blocked.after == blocked.before


def test_known_power_loss_blocks_an_otherwise_good_move() -> None:
    radios = (
        PlanRadio(
            name="A",
            band=Band.GHZ_5,
            current=120,
            width_mhz=80,
            candidates=(52, 120),
            current_power_dbm=24,
            candidate_ceilings=((52, 18), (120, 24)),
        ),
        PlanRadio(name="B", band=Band.GHZ_5, current=120, width_mhz=80, candidates=(120,)),
    )
    plan = optimize(radios, (PlanEdge(a="A", b="B", rssi_dbm=-70),))
    assert not plan.improved and plan.after == plan.before


def test_exact_search_keeps_a_safe_secondary_solution_when_lowest_measured_pressure_is_risky() -> None:
    radios = (
        PlanRadio(
            name="A",
            band=Band.GHZ_5,
            current=52,
            width_mhz=80,
            candidates=(52, 100, 120),
            current_power_dbm=18,
            candidate_ceilings=((52, 18), (100, 18), (120, 36)),
        ),
        PlanRadio(name="B", band=Band.GHZ_5, current=52, width_mhz=80, candidates=(52,)),
        PlanRadio(name="C", band=Band.GHZ_5, current=120, width_mhz=80, candidates=(120,)),
        PlanRadio(name="D", band=Band.GHZ_5, current=100, width_mhz=80, candidates=(100,)),
    )
    edges = (
        PlanEdge(a="A", b="B", rssi_dbm=-70),
        PlanEdge(a="A", b="C", rssi_dbm=-84, a_at_b_dbm=-84),
        PlanEdge(a="A", b="D", rssi_dbm=-81, a_at_b_dbm=-81),
    )
    plan = optimize(radios, edges)
    assert plan.improved and plan.after.channels[0] == 100


def _weight(rssi_dbm: int) -> int:
    return max(0, rssi_dbm + 83)


@st.composite
def _small_sites(draw: st.DrawFn) -> tuple[tuple[PlanRadio, ...], tuple[PlanEdge, ...]]:
    channels = (1, 6, 11)
    names = ("A", "B", "C", "D", "E")[: draw(st.integers(min_value=2, max_value=5))]
    radios = tuple(
        radio(
            name,
            current=(own := draw(st.sampled_from(channels))),
            # A radio with a single candidate is a constant of the search.
            choices=tuple(sorted({own, *draw(st.lists(st.sampled_from(channels), max_size=2))})),
            foreign=tuple(
                draw(
                    st.lists(
                        st.tuples(st.sampled_from(channels), st.integers(min_value=-95, max_value=-45)), max_size=3
                    )
                )
            ),
        )
        for name in names
    )
    edges = tuple(
        PlanEdge(a=a.name, b=b.name, rssi_dbm=draw(st.integers(min_value=-95, max_value=-50)))
        for a, b in combinations(radios, 2)
        if draw(st.booleans())
    )
    return radios, edges


def _oracle(radios: tuple[PlanRadio, ...], edges: tuple[PlanEdge, ...]) -> tuple[int, int, int, tuple[int, ...]]:
    """The documented ranking by brute force over every assignment, written without the optimizer's helpers:
    own pressure, foreign pressure, moved radios, channel tuple; a change needs strictly less own pressure."""
    position = {r.name: i for i, r in enumerate(radios)}

    def key(values: tuple[int, ...]) -> tuple[int, int, int, tuple[int, ...]]:
        own = sum(_weight(e.rssi_dbm) for e in edges if values[position[e.a]] == values[position[e.b]])
        foreign = sum(
            _weight(rssi) for i, r in enumerate(radios) for primary, rssi in r.foreign if primary == values[i]
        )
        moved = sum(value != r.current for value, r in zip(values, radios, strict=True))
        return own, foreign, moved, values

    before = key(tuple(r.current for r in radios))
    better = [key(v) for v in product(*(r.candidates for r in radios)) if key(v)[0] < before[0]]
    return min(better) if better else before


@settings(max_examples=150, deadline=None)
@given(_small_sites())
def test_exact_search_matches_the_brute_force_ranking(site: tuple[tuple[PlanRadio, ...], tuple[PlanEdge, ...]]) -> None:
    radios, edges = site
    plan = optimize(radios, edges)
    ordered = tuple(sorted(radios, key=lambda r: r.name))
    assert plan.method == "exact"
    assert (
        plan.after.own_pressure,
        plan.after.foreign_pressure,
        plan.after.moved,
        plan.after.channels,
    ) == _oracle(ordered, edges)


def test_radios_with_a_single_candidate_do_not_multiply_the_search() -> None:
    # 16 radios with two candidates (65,536 assignments, exact) next to 112 radios that cannot move, all mutually
    # heard: a search that revisited the fixed radios for every combination took minutes.
    free = [radio(f"A{i:03d}", current=1, choices=(1, 6)) for i in range(16)]
    fixed = [radio(f"B{i:03d}", current=11, choices=(11,)) for i in range(112)]
    radios = (*free, *fixed)
    edges = tuple(PlanEdge(a=a.name, b=b.name, rssi_dbm=-60) for a, b in combinations(radios, 2))
    started = time.perf_counter()
    plan = optimize(radios, edges)
    assert time.perf_counter() - started < 20
    assert plan.method == "exact" and plan.evaluations <= 2**16
    assert plan.improved and plan.after.channels[16:] == (11,) * 112


@st.composite
def _large_sites(draw: st.DrawFn) -> tuple[tuple[PlanRadio, ...], tuple[PlanEdge, ...]]:
    # 3**11 assignments: past the exact limit, so the heuristic runs.
    radios = tuple(radio(f"R{i:02d}", current=draw(st.sampled_from((1, 6, 11)))) for i in range(11))
    edges = tuple(
        PlanEdge(a=a.name, b=b.name, rssi_dbm=draw(st.integers(min_value=-80, max_value=-50)))
        for a, b in combinations(radios, 2)
        if draw(st.integers(min_value=0, max_value=3)) == 0
    )
    return radios, edges


@settings(max_examples=40, deadline=None)
@given(_large_sites())
def test_the_heuristic_never_misses_a_single_move_that_improves_the_observed_layout(
    site: tuple[tuple[PlanRadio, ...], tuple[PlanEdge, ...]],
) -> None:
    radios, edges = site
    position = {r.name: i for i, r in enumerate(radios)}

    def own(values: tuple[int, ...]) -> int:
        return sum(_weight(e.rssi_dbm) for e in edges if values[position[e.a]] == values[position[e.b]])

    observed = tuple(r.current for r in radios)
    one_move_better = any(
        own((*observed[:i], channel, *observed[i + 1 :])) < own(observed)
        for i in range(len(radios))
        for channel in (1, 6, 11)
    )
    plan = optimize(radios, edges)
    assert plan.method == "heuristic"
    assert plan.after.own_pressure <= plan.before.own_pressure
    assert plan.improved or not one_move_better


def test_the_heuristic_also_searches_from_the_observed_layout() -> None:
    # 3**11 assignments, past the exact limit. The greedy seed ends at own pressure 11 and its local search cannot
    # leave that minimum; single moves from the observed layout reach 0.
    observed = (11, 6, 11, 6, 11, 11, 11, 11, 1, 6, 1)
    links = (
        (0, 1, -52), (0, 3, -69), (0, 7, -62), (0, 9, -57), (1, 7, -76), (2, 3, -53), (2, 4, -74),
        (3, 9, -69), (4, 8, -70), (4, 10, -61), (5, 7, -71), (7, 9, -72), (7, 10, -50), (9, 10, -63),
    )  # fmt: skip
    radios = tuple(radio(f"R{i:02d}", current=channel) for i, channel in enumerate(observed))
    edges = tuple(PlanEdge(a=f"R{a:02d}", b=f"R{b:02d}", rssi_dbm=rssi) for a, b, rssi in links)
    plan = optimize(radios, edges)
    assert plan.method == "heuristic" and plan.before.own_pressure == 56
    assert plan.after.own_pressure == 0 and plan.improved
