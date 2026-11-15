"""Site-wide channel search: residual reuse, signal ranking, bonded geometry and bounded search."""

import random
import time
from itertools import combinations, product

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from unifiwifioptimizer.domain.models import Band
from unifiwifioptimizer.rf.channel_plan import (
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


def test_a_large_product_is_proven_exactly_when_the_pruning_allows_it_and_bounded_otherwise() -> None:
    radios = tuple(radio(f"AP-{i:02d}") for i in range(16))
    edges = tuple(PlanEdge(a=radios[i].name, b=radios[i + 1].name, rssi_dbm=-65) for i in range(15))
    unlimited = optimize(radios, edges)
    assert unlimited.method == "exact" and unlimited.after.own_pressure == 0
    greedy_seed = 16 * 3
    bounded = optimize(radios, edges, budget=50)
    assert bounded.method == "heuristic" and bounded.after.own_pressure == 0
    assert bounded.evaluations <= greedy_seed + 50


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


def test_power_risk_outranks_foreign_pressure_among_equal_own_pressure() -> None:
    radios = (
        PlanRadio(
            name="A",
            band=Band.GHZ_5,
            current=36,
            width_mhz=20,
            candidates=(36, 52, 100),
            foreign=((52, -60),),
            current_power_dbm=18,
            candidate_ceilings=((36, 18), (52, 18), (100, 24)),
        ),
        PlanRadio(name="B", band=Band.GHZ_5, current=36, width_mhz=20, candidates=(36,)),
        PlanRadio(name="C", band=Band.GHZ_5, current=100, width_mhz=20, candidates=(100,)),
    )
    edges = (
        PlanEdge(a="A", b="B", rssi_dbm=-70),
        PlanEdge(a="A", b="C", rssi_dbm=-84, a_at_b_dbm=-84),
    )
    plan = optimize(radios, edges)
    assert plan.after.channels[0] == 52
    assert plan.after.power_risk == 0 and plan.after.foreign_pressure > 0


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


def _measured_edge(a: str, b: str, rssi_dbm: int) -> PlanEdge:
    """The shape the analysis layer produces: both directions carry the measured level."""
    return PlanEdge(a=a, b=b, rssi_dbm=rssi_dbm, a_at_b_dbm=rssi_dbm, b_at_a_dbm=rssi_dbm)


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
        _measured_edge(a.name, b.name, draw(st.integers(min_value=-95, max_value=-50)))
        for a, b in combinations(radios, 2)
        if draw(st.booleans())
    )
    return radios, edges


def _oracle(radios: tuple[PlanRadio, ...], edges: tuple[PlanEdge, ...]) -> tuple[int, int, int, tuple[int, ...]]:
    """The documented ranking by brute force, written without the optimizer's helpers: radios coupled by a
    measured conflict form a group; each group takes the assignment with the least own pressure, then foreign
    pressure, then moved radios, then the channel tuple, if its own pressure strictly drops, else it stays."""
    usable = {r.name: {*r.candidates, r.current} for r in radios}
    coupled = [e for e in edges if _weight(e.rssi_dbm) > 0 and usable[e.a] & usable[e.b]]
    groups: list[set[str]] = []
    for r in radios:
        touching = [
            g for g in groups if any((e.a in g and e.b == r.name) or (e.b in g and e.a == r.name) for e in coupled)
        ]
        merged = {r.name}.union(*touching) if touching else {r.name}
        groups = [g for g in groups if g not in touching] + [merged]

    own_total = foreign_total = moved_total = 0
    chosen: dict[str, int] = {}
    for group in groups:
        members = [r for r in radios if r.name in group]
        inside = [e for e in coupled if e.a in group]

        def key(
            values: tuple[int, ...], members: list[PlanRadio] = members, inside: list[PlanEdge] = inside
        ) -> tuple[int, int, int, tuple[int, ...]]:
            at = {r.name: v for r, v in zip(members, values, strict=True)}
            own = sum(_weight(e.rssi_dbm) for e in inside if at[e.a] == at[e.b])
            foreign = sum(
                _weight(rssi)
                for r, v in zip(members, values, strict=True)
                for primary, rssi in r.foreign
                if primary == v
            )
            moved = sum(v != r.current for r, v in zip(members, values, strict=True))
            return own, foreign, moved, values

        before = key(tuple(r.current for r in members))
        better = [key(v) for v in product(*(r.candidates for r in members)) if key(v)[0] < before[0]]
        best = min(better) if better else before
        own_total, foreign_total, moved_total = own_total + best[0], foreign_total + best[1], moved_total + best[2]
        chosen.update({r.name: v for r, v in zip(members, best[3], strict=True)})
    return own_total, foreign_total, moved_total, tuple(chosen[r.name] for r in radios)


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
    assert plan.method == "exact" and plan.exact_evaluations <= 2 ** (16 + 1)
    assert plan.improved and plan.after.channels[16:] == (11,) * 112


@st.composite
def _large_sites(draw: st.DrawFn) -> tuple[tuple[PlanRadio, ...], tuple[PlanEdge, ...]]:
    # 3**11 assignments in one group of radios chained by measured conflicts.
    radios = tuple(radio(f"R{i:02d}", current=draw(st.sampled_from((1, 6, 11)))) for i in range(11))
    edges = tuple(
        PlanEdge(a=a.name, b=b.name, rssi_dbm=draw(st.integers(min_value=-80, max_value=-50)))
        for (i, a), (j, b) in combinations(enumerate(radios), 2)
        if j == i + 1 or draw(st.integers(min_value=0, max_value=3)) == 0
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
    plan = optimize(radios, edges, heuristic_only=True)
    assert plan.method == ("heuristic" if own(observed) else "exact")
    assert plan.after.own_pressure <= plan.before.own_pressure
    assert plan.improved or not one_move_better


def test_the_heuristic_also_searches_from_the_observed_layout() -> None:
    # 3**11 assignments in one group. The greedy seed ends at own pressure 11 and its local search cannot leave
    # that minimum; single moves from the observed layout reach 0.
    observed = (11, 6, 11, 6, 11, 11, 11, 11, 1, 6, 1)
    links = (
        (0, 1, -52), (0, 3, -69), (0, 7, -62), (0, 9, -57), (1, 7, -76), (2, 3, -53), (2, 4, -74),
        (3, 9, -69), (4, 8, -70), (4, 10, -61), (5, 7, -71), (7, 9, -72), (7, 10, -50), (9, 10, -63),
        (1, 6, -82),
    )  # fmt: skip
    radios = tuple(radio(f"R{i:02d}", current=channel) for i, channel in enumerate(observed))
    edges = tuple(PlanEdge(a=f"R{a:02d}", b=f"R{b:02d}", rssi_dbm=rssi) for a, b, rssi in links)
    plan = optimize(radios, edges, heuristic_only=True)
    assert plan.method == "heuristic" and plan.before.own_pressure == 56
    assert plan.after.own_pressure == 0 and plan.improved
    assert optimize(radios, edges).after.own_pressure == 0


def test_independent_groups_are_searched_separately_and_stay_exact() -> None:
    # Three groups of five mutually heard radios: 3**15 assignments as a product, 3 * 3**5 as a sum.
    radios = tuple(radio(f"G{g}R{i}") for g in range(3) for i in range(5))
    edges = tuple(
        _measured_edge(f"G{g}R{i}", f"G{g}R{j}", -70) for g in range(3) for i in range(5) for j in range(i + 1, 5)
    )
    plan = optimize(radios, edges)
    assert plan.groups == 3 and plan.method == "exact" and plan.exact_evaluations <= 3 * (3 + 3**2 + 3**3 + 3**4 + 3**5)
    assert plan.before.own_conflicts == 30 and plan.after.own_conflicts == 6
    assert [len(set(plan.after.channels[g * 5 : g * 5 + 5])) for g in range(3)] == [3, 3, 3]


def test_a_group_without_measured_conflict_keeps_its_channels_while_another_group_improves() -> None:
    clean = (
        radio("C1", choices=(1, 6), foreign=((1, -50),)),
        radio("C2", current=6, choices=(1, 6)),
    )
    busy = (radio("B1", current=1), radio("B2", current=1))
    plan = optimize(
        (*clean, *busy),
        (_measured_edge("B1", "B2", -60), _measured_edge("C1", "C2", -90)),
    )
    assert plan.improved and plan.after.channels[:2] == (1, 6)
    assert plan.after.channels[2] != plan.after.channels[3]


def test_a_weak_edge_with_power_evidence_still_couples_two_radios() -> None:
    # A's move to channel 120 removes its conflict with B (pressure 3) but could raise its level at C, which is heard
    # below the CCA threshold, to a risk of 5. Apart from C the move would look free and be recommended.
    a = PlanRadio(
        name="A",
        band=Band.GHZ_5,
        current=52,
        width_mhz=80,
        candidates=(52, 120),
        current_power_dbm=18,
        candidate_ceilings=((52, 18), (120, 24)),
    )
    b = PlanRadio(name="B", band=Band.GHZ_5, current=52, width_mhz=80, candidates=(52,))
    c = PlanRadio(name="C", band=Band.GHZ_5, current=120, width_mhz=80, candidates=(120,))
    heard_by_c = PlanEdge(a="A", b="C", rssi_dbm=-84, a_at_b_dbm=-84)
    with_c = optimize((a, b, c), (PlanEdge(a="A", b="B", rssi_dbm=-80), heard_by_c))
    assert not with_c.improved
    without_c = optimize((a, b), (PlanEdge(a="A", b="B", rssi_dbm=-80),))
    assert without_c.improved and without_c.after.channels == (120, 52)


def test_zero_own_pressure_is_labelled_exact_whatever_the_number_of_assignments() -> None:
    radios = tuple(radio(f"R{i:02d}", current=(1, 6, 11)[i % 3]) for i in range(12))
    edges = tuple(PlanEdge(a=radios[i].name, b=radios[i + 1].name, rssi_dbm=-65) for i in range(11))
    plan = optimize(radios, edges)
    assert plan.before.own_pressure == 0 and plan.method == "exact" and plan.evaluations == 0


def test_the_search_stops_at_its_budget_and_the_shares_are_never_exceeded() -> None:
    radios = tuple(radio(f"R{i:02d}") for i in range(16))
    edges = tuple(PlanEdge(a=radios[i].name, b=radios[i + 1].name, rssi_dbm=-65) for i in range(15))
    greedy_seed = 16 * 3
    for budget in (0, 1, 7, 50, 400):
        plan = optimize(radios, edges, budget)
        assert plan.method == "heuristic" or plan.exact_evaluations <= (budget + 1) // 2
        assert plan.exact_evaluations <= (budget + 1) // 2
        assert plan.evaluations <= greedy_seed + budget
    assert optimize(radios, edges, 0).evaluations == greedy_seed


def test_measured_but_inaudible_edges_between_cliques_do_not_merge_their_searches() -> None:
    # Three cliques of five, joined by edges heard at -95 dBm in both directions, as the analysis layer reports every
    # sighting: still 3 * 3**5 assignments and an exact search.
    radios = tuple(radio(f"G{g}R{i}") for g in range(3) for i in range(5))
    inside = tuple(
        _measured_edge(f"G{g}R{i}", f"G{g}R{j}", -70) for g in range(3) for i in range(5) for j in range(i + 1, 5)
    )
    between = (_measured_edge("G0R0", "G1R0", -95), _measured_edge("G1R1", "G2R1", -95))
    plan = optimize(radios, (*inside, *between))
    assert plan.groups == 3 and plan.method == "exact"
    assert plan.exact_evaluations <= 3 * (3 + 3**2 + 3**3 + 3**4 + 3**5)


def _powered(name: str, current: int, candidates: tuple[int, ...], ceiling: int) -> PlanRadio:
    return PlanRadio(
        name=name,
        band=Band.GHZ_5,
        current=current,
        width_mhz=20,
        candidates=candidates,
        current_power_dbm=18,
        candidate_ceilings=tuple((channel, 18 if channel == current else ceiling) for channel in candidates),
    )


def _fixed(name: str, channel: int, choices: tuple[int, ...] | None = None) -> PlanRadio:
    return PlanRadio(name=name, band=Band.GHZ_5, current=channel, width_mhz=20, candidates=choices or (channel,))


def _offsetting_site(a_choices: tuple[int, ...], a_ceilings: dict[int, int]) -> tuple[list[PlanRadio], list[PlanEdge]]:
    """A (on 36, 18 dBm) leaves its conflict with D, but a move to 52 could raise its level at E to a risk of 5, which
    its own gain of 1 does not cover. B and C are an independent pair whose conflict C can fix (gain 13): if the two
    searches merge, that gain pays for A's risk and A moves."""
    sender = PlanRadio(
        name="A",
        band=Band.GHZ_5,
        current=36,
        width_mhz=20,
        candidates=a_choices,
        current_power_dbm=18,
        candidate_ceilings=tuple((c, 18 if c == 36 else a_ceilings.get(c, 18)) for c in a_choices),
    )
    radios = [sender, _fixed("B", 149), _fixed("C", 149, (149, 100)), _fixed("D", 36), _fixed("E", 52)]
    edges = [
        PlanEdge(a="A", b="D", rssi_dbm=-82, a_at_b_dbm=-82),
        PlanEdge(a="A", b="E", rssi_dbm=-84, a_at_b_dbm=-84),
        PlanEdge(a="B", b="C", rssi_dbm=-70),
    ]
    if 149 in a_choices:
        radios.append(_fixed("F", 149))
        edges.append(PlanEdge(a="A", b="F", rssi_dbm=-50))
    return radios, edges


_STAYS = (36, 149, 100, 36, 52)


def _channels(site: tuple[list[PlanRadio], list[PlanEdge]], *extra: PlanEdge) -> tuple[int, ...]:
    radios, edges = site
    return optimize(tuple(radios), (*edges, *extra)).after.channels[:5]


def test_the_offsetting_site_keeps_a_on_its_channel_when_nothing_links_the_searches() -> None:
    assert _channels(_offsetting_site((36, 52), {52: 24})) == _STAYS


@pytest.mark.parametrize(
    ("a_choices", "a_ceilings", "extra"),
    [
        pytest.param(
            (36, 52), {52: 24}, PlanEdge(a="A", b="B", rssi_dbm=-60), id="heard-strongly-but-never-overlapping"
        ),
        pytest.param(
            (36, 52),
            {52: 24},
            PlanEdge(a="B", b="A", rssi_dbm=-90, b_at_a_dbm=-90),
            id="the-other-side-never-overlapping",
        ),
        pytest.param(
            (36, 52, 149),
            {52: 24, 149: 24},
            PlanEdge(a="A", b="B", rssi_dbm=-95, a_at_b_dbm=-95),
            id="a-raised-level-that-stays-below-the-threshold",
        ),
        pytest.param(
            (36, 52, 149),
            {52: 24, 149: 18},
            PlanEdge(a="A", b="B", rssi_dbm=-90, a_at_b_dbm=-90),
            id="a-ceiling-equal-to-the-current-power",
        ),
        pytest.param((36, 52, 149), {52: 24}, PlanEdge(a="A", b="B", rssi_dbm=-83), id="just-below-the-cca-threshold"),
        pytest.param(
            (36, 52, 149),
            {52: 24, 149: 18},
            PlanEdge(a="A", b="B", rssi_dbm=-83, a_at_b_dbm=-83),
            id="an-equal-ceiling-at-the-edge-of-the-threshold",
        ),
    ],
)
def test_an_edge_that_can_never_cost_does_not_merge_two_searches(
    a_choices: tuple[int, ...], a_ceilings: dict[int, int], extra: PlanEdge
) -> None:
    assert _channels(_offsetting_site(a_choices, a_ceilings), extra) == _STAYS


def test_an_audible_pair_that_can_overlap_merges_two_searches() -> None:
    site = _offsetting_site((36, 52, 149), {52: 24})
    assert _channels(site, PlanEdge(a="A", b="B", rssi_dbm=-82)) != _STAYS


@pytest.mark.parametrize("sender_is_a", [True, False])
def test_either_direction_of_an_edge_can_couple_through_a_power_increase(sender_is_a: bool) -> None:
    # S leaves its conflict with B (pressure 3) for channel 120, where a higher power could be heard by C below the CCA
    # threshold (risk 5). The weak S-C edge couples them whichever side of the edge S is on, so the move is refused.
    sender = _powered("S", 52, (52, 120), 24)
    b = PlanRadio(name="B", band=Band.GHZ_5, current=52, width_mhz=20, candidates=(52,))
    c = PlanRadio(name="C", band=Band.GHZ_5, current=120, width_mhz=20, candidates=(120,))
    conflict = PlanEdge(a="B", b="S", rssi_dbm=-80)
    weak = (
        PlanEdge(a="S", b="C", rssi_dbm=-84, a_at_b_dbm=-84)
        if sender_is_a
        else PlanEdge(a="C", b="S", rssi_dbm=-84, b_at_a_dbm=-84)
    )
    assert not optimize((sender, b, c), (conflict, weak)).improved
    assert optimize((sender, b), (conflict,)).improved


def test_the_merged_label_is_heuristic_when_any_group_is() -> None:
    small = tuple(radio(f"S{i}") for i in range(3))
    large = tuple(radio(f"L{i:02d}") for i in range(12))
    edges = (
        *(_measured_edge(small[i].name, small[j].name, -70) for i in range(3) for j in range(i + 1, 3)),
        *(_measured_edge(large[i].name, large[i + 1].name, -65) for i in range(11)),
    )
    budget = 80
    assert optimize(small, edges[:3], budget).method == "exact"
    assert optimize(large, edges[3:], budget).method == "heuristic"
    plan = optimize((*small, *large), edges, budget)
    assert plan.groups == 2 and plan.method == "heuristic"


# --- the effort budget -----------------------------------------------------------------------------------------


@st.composite
def _one_group(draw: st.DrawFn) -> tuple[tuple[PlanRadio, ...], tuple[PlanEdge, ...]]:
    """One coupled group by construction: a complete graph heard at -75 dBm or stronger on candidate channels that
    every radio shares (one common candidate), with the observed channel among the candidates, foreign observations,
    current power and candidate ceilings. At most 5 radios with 4 candidates, so the brute force stays small."""
    channels = (36, 52, 100, 116)
    count = draw(st.integers(min_value=2, max_value=5))
    shared = draw(st.sampled_from(channels))
    radios = []
    for index in range(count):
        current = draw(st.sampled_from(channels))
        choices = tuple(sorted({current, shared, *draw(st.lists(st.sampled_from(channels), max_size=2))}))
        with_power = draw(st.booleans())
        radios.append(
            PlanRadio(
                name=f"R{index}",
                band=Band.GHZ_5,
                current=current,
                width_mhz=20,
                candidates=choices,
                foreign=tuple(
                    draw(
                        st.lists(
                            st.tuples(st.sampled_from(channels), st.integers(min_value=-95, max_value=-60)), max_size=3
                        )
                    )
                ),
                current_power_dbm=18 if with_power else None,
                candidate_ceilings=tuple((c, draw(st.sampled_from((12, 18, 24)))) for c in choices)
                if with_power
                else (),
            )
        )
    edges = tuple(
        PlanEdge(
            a=a.name,
            b=b.name,
            rssi_dbm=(level := draw(st.integers(min_value=-75, max_value=-50))),
            a_at_b_dbm=level,
            b_at_a_dbm=level - draw(st.integers(min_value=0, max_value=4)),
        )
        for a, b in combinations(radios, 2)
    )
    return tuple(radios), edges


def _brute_force(radios: tuple[PlanRadio, ...], edges: tuple[PlanEdge, ...]) -> tuple[tuple[int, ...], tuple[int, ...]]:
    """Every assignment of one coupled group, ranked by (own pressure, power risk, power loss, foreign pressure, moved,
    channels) and accepted only when own pressure and power risk stay below the observed pressure and no known power
    is lost; written without the optimizer's helpers. Returns (best channels, rank)."""
    ordered = sorted(radios, key=lambda r: r.name)
    index = {r.name: i for i, r in enumerate(ordered)}

    def rank(values: tuple[int, ...]) -> tuple[int, ...]:
        own = risk = 0
        for e in edges:
            a, b = ordered[index[e.a]], ordered[index[e.b]]
            if values[index[e.a]] != values[index[e.b]]:
                continue
            baseline = _weight(e.rssi_dbm)
            raised = []
            for end, at in ((a, e.a_at_b_dbm), (b, e.b_at_a_dbm)):
                if at is None:
                    continue
                ceiling = dict(end.candidate_ceilings).get(values[index[end.name]])
                bump = (
                    max(0, ceiling - end.current_power_dbm)
                    if ceiling is not None
                    and end.current_power_dbm is not None
                    and values[index[end.name]] != end.current
                    else 0
                )
                raised.append(_weight(at + bump))
            own += baseline
            risk += max(0, max(raised, default=baseline) - baseline)
        loss = 0
        for r, v in zip(ordered, values, strict=True):
            ceiling = dict(r.candidate_ceilings).get(v)
            loss += int(
                v != r.current
                and r.current_power_dbm is not None
                and ceiling is not None
                and ceiling < r.current_power_dbm
            )
        foreign = sum(
            1 + rssi + 82
            for r, v in zip(ordered, values, strict=True)
            for primary, rssi in r.foreign
            if primary == v and rssi >= -82
        )
        moved = sum(v != r.current for r, v in zip(ordered, values, strict=True))
        return (own, risk, loss, foreign, moved, *values)

    observed = tuple(r.current for r in ordered)
    before = rank(observed)
    accepted = [
        values
        for values in product(*(sorted(set(r.candidates)) for r in ordered))
        if rank(values)[0] < before[0] and rank(values)[0] + rank(values)[1] < before[0] and rank(values)[2] == 0
    ]
    best = min(accepted, key=rank) if accepted else observed
    return best, rank(best)[:5]


@settings(max_examples=120, deadline=None)
@given(_one_group())
def test_the_unlimited_search_equals_the_brute_force_and_is_never_worse_than_the_heuristic(
    site: tuple[tuple[PlanRadio, ...], tuple[PlanEdge, ...]],
) -> None:
    radios, edges = site
    plan = optimize(radios, edges)
    heuristic = optimize(radios, edges, heuristic_only=True)
    assert plan.groups == 1
    best, key = _brute_force(radios, edges)
    if plan.before.own_pressure == 0:
        assert plan.after.channels == plan.before.channels
        return
    assert plan.method == "exact"
    assert plan.after.channels == best
    assert plan.after.rank[:5] == key
    assert plan.after.rank <= heuristic.after.rank


@settings(max_examples=60, deadline=None)
@given(_one_group(), st.integers(min_value=0, max_value=60))
def test_a_budgeted_search_is_never_worse_than_the_heuristic_and_a_larger_budget_never_loses_a_proof(
    site: tuple[tuple[PlanRadio, ...], tuple[PlanEdge, ...]], budget: int
) -> None:
    radios, edges = site
    # The exact phase starts from the heuristic phase's result of the same budget and can only improve on it.
    heuristic = optimize(radios, edges, budget, heuristic_only=True)
    plan = optimize(radios, edges, budget)
    assert plan.after.rank <= heuristic.after.rank
    if plan.method == "exact":
        for larger in (budget + 1, budget + 2, budget * 2 + 3):
            assert optimize(radios, edges, larger).method == "exact"


def test_the_result_does_not_depend_on_the_order_of_radios_edges_and_candidates() -> None:
    radios = tuple(
        PlanRadio(
            name=f"R{i}",
            band=Band.GHZ_5,
            current=(36, 52, 100)[i % 3],
            width_mhz=20,
            candidates=(36, 52, 100, 116),
            foreign=((52, -70), (100, -75)),
        )
        for i in range(6)
    )
    edges = tuple(_measured_edge(a.name, b.name, -60 - (i % 5)) for i, (a, b) in enumerate(combinations(radios, 2)))
    shuffled = tuple(
        PlanRadio(
            name=r.name,
            band=r.band,
            current=r.current,
            width_mhz=r.width_mhz,
            candidates=(116, 100, 36, 52),
            foreign=r.foreign,
        )
        for r in reversed(radios)
    )
    for budget in (None, 0, 25, 400):
        first = optimize(radios, edges, budget)
        second = optimize(shuffled, tuple(reversed(edges)), budget)
        assert first == second


def test_the_smallest_budget_that_proves_the_optimum_is_a_threshold() -> None:
    radios = tuple(radio(f"R{i}", current=(1, 6, 11)[i % 3]) for i in range(5))
    edges = tuple(_measured_edge(a.name, b.name, -70) for a, b in combinations(radios, 2))
    needed = next(b for b in range(0, 2000) if optimize(radios, edges, b).method == "exact")
    assert needed > 0
    assert optimize(radios, edges, needed - 1).method == "heuristic"
    assert all(optimize(radios, edges, b).method == "exact" for b in range(needed, needed + 40))


def test_a_group_without_a_free_radio_is_exact_at_any_budget() -> None:
    radios = (radio("A", current=1, choices=(1,)), radio("B", current=1, choices=(1,)))
    plan = optimize(radios, (_measured_edge("A", "B", -60),), 0)
    assert plan.method == "exact" and plan.exact_evaluations == 0 and not plan.improved


def test_each_local_search_start_spends_at_most_a_quarter_of_the_budget() -> None:
    radios = tuple(radio(f"R{i:02d}", current=(1, 6, 11)[i % 3]) for i in range(10))
    edges = tuple(_measured_edge(a.name, b.name, -62) for a, b in combinations(radios, 2))
    greedy_seed = 10 * 3
    for budget in (8, 40, 100):
        plan = optimize(radios, edges, budget)
        local = plan.evaluations - greedy_seed - plan.exact_evaluations
        assert 0 <= local <= 2 * (budget // 4)
        assert plan.exact_evaluations <= (budget + 1) // 2


def test_the_local_walk_does_not_depend_on_the_budget_beyond_its_length() -> None:
    radios = tuple(radio(f"R{i:02d}", current=(1, 6, 11)[i % 3]) for i in range(8))
    edges = tuple(_measured_edge(a.name, b.name, -55 - (i % 9)) for i, (a, b) in enumerate(combinations(radios, 2)))
    small = optimize(radios, edges, 16, heuristic_only=True)
    large = optimize(radios, edges, 400, heuristic_only=True)
    assert large.after.rank <= small.after.rank


# --- pinned work counts ----------------------------------------------------------------------------------------


def _pinned_site(
    seed: int, count: int, density: float, ceilings: tuple[int, ...] = (18, 18, 24)
) -> tuple[tuple[PlanRadio, ...], tuple[PlanEdge, ...]]:
    """A reproducible group on four 20 MHz channels with foreign observations, current power and ceilings. The pinned
    work counts depend on the generated data; `random.Random(seed)` has been stable across the supported versions in
    practice but is not guaranteed to be; if a Python release changes the data, regenerate the constants on purpose."""
    rng = random.Random(seed)  # noqa: S311 - a reproducible fixture, not a secret
    channels = (36, 52, 100, 116)
    radios = tuple(
        PlanRadio(
            name=f"R{i:02d}",
            band=Band.GHZ_5,
            current=rng.choice(channels),
            width_mhz=20,
            candidates=channels,
            foreign=tuple((rng.choice(channels), rng.randint(-90, -62)) for _ in range(3)),
            current_power_dbm=18,
            candidate_ceilings=tuple((c, rng.choice(ceilings)) for c in channels),
        )
        for i in range(count)
    )
    edges = tuple(
        PlanEdge(a=a.name, b=b.name, rssi_dbm=(level := rng.randint(-80, -55)), a_at_b_dbm=level, b_at_a_dbm=level - 2)
        for a, b in combinations(radios, 2)
        if rng.random() <= density
    )
    return radios, edges


# (seed, radios, density, ceilings) -> exact evaluations of the unlimited search, as recorded when the pruning was
# written. A prune that gets weaker raises the count and one that gets stronger changes the plan (the oracle tests);
# each prune is exercised by at least one fixture, which its mutant shows: the first two bound the foreign and moved
# keys and the ordering, the last two (ceilings below the current power, which lose power, and ceilings above it,
# which add risk) bound the conditions a plan must meet to be accepted (docs/ALGORITHM.md §8).
PINNED_EXACT_EVALUATIONS = {
    (1, 8, 1.0, (18, 18, 24)): 2144,
    (2, 8, 0.5, (18, 18, 24)): 80,
    (6, 9, 0.8, (18, 18, 24)): 644,
    (1, 6, 1.0, (12, 18, 24)): 212,
    (5, 7, 0.8, (12, 18, 24)): 364,
}


@pytest.mark.parametrize(("key", "expected"), sorted(PINNED_EXACT_EVALUATIONS.items()))
def test_the_exact_search_work_on_pinned_groups_is_unchanged(
    key: tuple[int, int, float, tuple[int, ...]], expected: int
) -> None:
    radios, edges = _pinned_site(*key)
    plan = optimize(radios, edges)
    assert plan.method == "exact" and plan.groups >= 1
    assert plan.exact_evaluations == expected
