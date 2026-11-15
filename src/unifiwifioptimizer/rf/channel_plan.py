"""Bounded site-wide channel assignment over measured receiver-location proxies (docs/ALGORITHM.md §8)."""

from collections.abc import Callable
from dataclasses import dataclass
from functools import cache, lru_cache

from unifiwifioptimizer.domain.analysis import ChannelPlanMethod
from unifiwifioptimizer.domain.models import Band
from unifiwifioptimizer.rf.channels import channel_block_5g, channels_overlap

RADIO_LIMIT = 128
# Each local-search start may spend a quarter of a group's budget, the exact search half (rounded up). Every share is
# non-decreasing in the budget, so a larger budget never loses a proof (docs/ALGORITHM.md §8).
LOCAL_SEARCH_SHARES = 4


class _BudgetSpentError(Exception):
    """Unwinds the exact enumeration when its units are used up."""


@dataclass(frozen=True, slots=True, kw_only=True)
class PlanRadio:
    """One radio with (foreign primary, receiver RSSI) observations deduplicated by the analysis layer."""

    name: str
    band: Band
    current: int
    width_mhz: int
    candidates: tuple[int, ...]
    foreign: tuple[tuple[int, int], ...] = ()
    current_power_dbm: int | None = None
    candidate_ceilings: tuple[tuple[int, int], ...] = ()


@dataclass(frozen=True, slots=True, kw_only=True)
class PlanEdge:
    """One measured pair. `rssi_dbm` is the stronger of the measured directions, as the analysis layer builds it;
    group coupling and acceptance rely on that."""

    a: str
    b: str
    rssi_dbm: int
    a_at_b_dbm: int | None = None
    b_at_a_dbm: int | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class PlanScore:
    own_pressure: int
    power_risk: int
    power_loss: int
    foreign_pressure: int
    moved: int
    channels: tuple[int, ...]
    own_conflicts: int
    foreign_overlaps: int

    @property
    def rank(self) -> tuple[int, int, int, int, int, tuple[int, ...]]:
        return self.own_pressure, self.power_risk, self.power_loss, self.foreign_pressure, self.moved, self.channels


@dataclass(frozen=True, slots=True, kw_only=True)
class OptimizedPlan:
    before: PlanScore
    after: PlanScore
    method: ChannelPlanMethod
    evaluations: int
    exact_evaluations: int = 0
    groups: int = 1

    @property
    def improved(self) -> bool:
        return self.after.own_pressure < self.before.own_pressure


@cache
def _overlap(band: Band, channel_a: int, width_a: int, channel_b: int, width_b: int) -> bool:
    return channels_overlap(band, channel_a, width_a, channel_b, width_b)


def _power_increase(radio: PlanRadio, channel: int) -> int:
    if channel == radio.current or radio.current_power_dbm is None:
        return 0
    ceiling = dict(radio.candidate_ceilings).get(channel)
    return max(0, ceiling - radio.current_power_dbm) if ceiling is not None else 0


def _edge_cost(a: PlanRadio, channel_a: int, b: PlanRadio, channel_b: int, edge: PlanEdge) -> tuple[int, int, int]:
    """(own pressure, possible extra pressure from a higher candidate TX, conflict count) of one measured edge."""
    if not _overlap(a.band, channel_a, a.width_mhz, channel_b, b.width_mhz):
        return 0, 0, 0
    baseline = max(0, edge.rssi_dbm + 83)
    directed = []
    if edge.a_at_b_dbm is not None:
        directed.append(edge.a_at_b_dbm + _power_increase(a, channel_a))
    if edge.b_at_a_dbm is not None:
        directed.append(edge.b_at_a_dbm + _power_increase(b, channel_b))
    possible = max((max(0, rssi + 83) for rssi in directed), default=baseline)
    return baseline, max(0, possible - baseline), int(baseline > 0)


def optimize(
    radios: tuple[PlanRadio, ...],
    edges: tuple[PlanEdge, ...],
    budget: int | None = None,
    *,
    heuristic_only: bool = False,
) -> OptimizedPlan:
    """Find the lexicographic minimum per group of radios that can influence each other.

    Each group is searched for the best plan with a greedy seed and two local searches, then enumerated exactly
    with that result as the first bound. `budget` is the deterministic effort per group in candidates considered
    (None is unlimited, for tests): the exact search proves the optimum only if its enumeration finishes inside
    its share, otherwise the best plan found is returned and the method says optimality is not proven.
    `heuristic_only` skips the exact search.

    A group changes only if it strictly improves, so radios that no costly edge couples to a conflict keep their
    channel and the search space is the sum, not the product, of the group sizes. Callers validate candidate
    geometry, that every radio's current channel is among its candidates, and the 128-radio limit before entering
    this pure function.
    """
    ordered = tuple(sorted(radios, key=lambda r: r.name))
    parent = {r.name: r.name for r in ordered}

    def root(name: str) -> str:
        while parent[name] != name:
            parent[name] = parent[parent[name]]
            name = parent[name]
        return name

    # An edge couples two radios exactly when some assignment of their channels gives it a cost; every other edge is
    # zero under every assignment and cannot link two searches.
    by_name = {r.name: r for r in ordered}
    choices = {r.name: {*r.candidates, r.current} for r in ordered}
    for edge in edges:
        a, b = by_name[edge.a], by_name[edge.b]
        if any(any(_edge_cost(a, x, b, y, edge)) for x in choices[a.name] for y in choices[b.name]):
            parent[root(edge.a)] = root(edge.b)
    groups: dict[str, list[PlanRadio]] = {}
    for radio in ordered:
        groups.setdefault(root(radio.name), []).append(radio)
    group_edges: dict[str, list[PlanEdge]] = {key: [] for key in groups}
    for edge in edges:
        if root(edge.a) == root(edge.b):
            group_edges[root(edge.a)].append(edge)
    plans = {
        key: _optimize_group(tuple(members), tuple(group_edges[key]), budget, heuristic_only)
        for key, members in groups.items()
    }
    if len(plans) == 1:
        return next(iter(plans.values()))

    def merge(pick: Callable[[OptimizedPlan], PlanScore]) -> PlanScore:
        parts = [pick(plan) for plan in plans.values()]
        channel_of = {
            radio.name: channel
            for key, members in groups.items()
            for radio, channel in zip(members, pick(plans[key]).channels, strict=True)
        }
        return PlanScore(
            own_pressure=sum(p.own_pressure for p in parts),
            power_risk=sum(p.power_risk for p in parts),
            power_loss=sum(p.power_loss for p in parts),
            foreign_pressure=sum(p.foreign_pressure for p in parts),
            moved=sum(p.moved for p in parts),
            channels=tuple(channel_of[r.name] for r in ordered),
            own_conflicts=sum(p.own_conflicts for p in parts),
            foreign_overlaps=sum(p.foreign_overlaps for p in parts),
        )

    return OptimizedPlan(
        before=merge(lambda plan: plan.before),
        after=merge(lambda plan: plan.after),
        method=ChannelPlanMethod.HEURISTIC
        if any(plan.method is ChannelPlanMethod.HEURISTIC for plan in plans.values())
        else ChannelPlanMethod.EXACT,
        evaluations=sum(plan.evaluations for plan in plans.values()),
        exact_evaluations=sum(plan.exact_evaluations for plan in plans.values()),
        groups=len(plans),
    )


def _optimize_group(
    radios: tuple[PlanRadio, ...], edges: tuple[PlanEdge, ...], budget: int | None, heuristic_only: bool
) -> OptimizedPlan:
    ordered = tuple(sorted(radios, key=lambda r: r.name))
    index = {r.name: i for i, r in enumerate(ordered)}
    candidates = tuple(tuple(sorted(set(r.candidates))) for r in ordered)

    @cache
    def foreign_overlap(band: Band, channel: int, width_mhz: int, primary: int) -> bool:
        return channels_overlap(band, channel, width_mhz, primary, 20)

    foreign: list[dict[int, tuple[int, int]]] = []
    for radio in ordered:
        scores: dict[int, tuple[int, int]] = {}
        for channel in (*radio.candidates, radio.current):
            hits = [
                rssi
                for primary, rssi in radio.foreign
                if foreign_overlap(radio.band, channel, radio.width_mhz, primary)
            ]
            scores[channel] = (sum(1 + rssi + 82 for rssi in hits if rssi >= -82), len(hits))
        foreign.append(scores)
    measured_edges = tuple((index[e.a], index[e.b], e) for e in edges)
    incident: list[list[tuple[int, PlanEdge]]] = [[] for _ in ordered]
    for a, b, edge in measured_edges:
        incident[a].append((b, edge))
        incident[b].append((a, edge))
    ceilings = tuple(dict(r.candidate_ceilings) for r in ordered)

    def loses_power(i: int, channel: int) -> int:
        if channel == ordered[i].current:
            return 0
        current = ordered[i].current_power_dbm
        ceiling = ceilings[i].get(channel)
        return int(current is not None and ceiling is not None and ceiling < current)

    @lru_cache(maxsize=100_000)
    def edge_cost(a: int, channel_a: int, b: int, channel_b: int, edge: PlanEdge) -> tuple[int, int, int]:
        return _edge_cost(ordered[a], channel_a, ordered[b], channel_b, edge)

    def pair_cost(i: int, channel: int, peer: int, peer_channel: int, edge: PlanEdge) -> tuple[int, int, int]:
        if edge.a == ordered[i].name:
            return edge_cost(i, channel, peer, peer_channel, edge)
        return edge_cost(peer, peer_channel, i, channel, edge)

    def score(channels: tuple[int, ...]) -> PlanScore:
        hits = [edge_cost(a, channels[a], b, channels[b], edge) for a, b, edge in measured_edges]
        foreign_scores = [foreign[i][channel] for i, channel in enumerate(channels)]
        return PlanScore(
            own_pressure=sum(base for base, _, _ in hits),
            power_risk=sum(risk for _, risk, _ in hits),
            power_loss=sum(loses_power(i, channel) for i, channel in enumerate(channels)),
            foreign_pressure=sum(p for p, _ in foreign_scores),
            moved=sum(channel != r.current for channel, r in zip(channels, ordered, strict=True)),
            channels=channels,
            own_conflicts=sum(conflict for _, _, conflict in hits),
            foreign_overlaps=sum(count for _, count in foreign_scores),
        )

    def acceptable(candidate: PlanScore) -> bool:
        return (
            candidate.own_pressure < before.own_pressure
            and candidate.own_pressure + candidate.power_risk < before.own_pressure
            and candidate.power_loss == 0
        )

    before = score(tuple(r.current for r in ordered))
    if before.own_pressure == 0:
        return OptimizedPlan(
            before=before,
            after=before,
            method=ChannelPlanMethod.EXACT,
            evaluations=0,
        )

    # The search order is stable under controller and scan ordering. Greedy assignments only inspect already
    # assigned neighbours; subsequent local improvement considers the complete measured graph.
    order = sorted(
        range(len(ordered)), key=lambda i: (-sum(max(0, e.rssi_dbm + 83) for _, e in incident[i]), ordered[i].name)
    )
    assigned: dict[int, int] = {}
    evaluations = 0
    for i in order:
        radio = ordered[i]
        chosen = min(
            candidates[i],
            key=lambda channel: (
                sum(
                    pair_cost(i, channel, peer, assigned[peer], edge)[0]
                    for peer, edge in incident[i]
                    if peer in assigned
                ),
                sum(
                    pair_cost(i, channel, peer, assigned[peer], edge)[1]
                    for peer, edge in incident[i]
                    if peer in assigned
                ),
                loses_power(i, channel),
                foreign[i][channel][0],
                channel != radio.current,
                channel,
            ),
        )
        evaluations += len(candidates[i])
        assigned[i] = chosen
    greedy = tuple(assigned[i] for i in range(len(ordered)))
    best_safe = before
    local_share = None if budget is None else budget // LOCAL_SEARCH_SHARES

    def improve(start: tuple[int, ...]) -> None:
        """Local search over single-radio moves from `start`, at most `local_share` trial moves; keeps the best
        acceptable assignment seen. The walk steers by its own best only and never reads the incumbent, so a larger
        share only continues the same walk."""
        nonlocal best_safe, evaluations
        spent = 0
        current = start
        best = score(current)
        if acceptable(best) and best.rank < best_safe.rank:
            best_safe = best
        while True:
            improved = False
            for i in order:
                for channel in candidates[i]:
                    if local_share is not None and spent >= local_share:
                        return
                    spent += 1
                    evaluations += 1
                    trial = (*current[:i], channel, *current[i + 1 :])
                    old = current[i]
                    changes = [
                        (
                            pair_cost(i, channel, peer, current[peer], edge),
                            pair_cost(i, old, peer, current[peer], edge),
                        )
                        for peer, edge in incident[i]
                    ]
                    candidate = PlanScore(
                        own_pressure=best.own_pressure + sum(new[0] - old_cost[0] for new, old_cost in changes),
                        power_risk=best.power_risk + sum(new[1] - old_cost[1] for new, old_cost in changes),
                        power_loss=best.power_loss + loses_power(i, channel) - loses_power(i, old),
                        foreign_pressure=best.foreign_pressure + foreign[i][channel][0] - foreign[i][old][0],
                        moved=best.moved + (channel != ordered[i].current) - (old != ordered[i].current),
                        channels=trial,
                        own_conflicts=best.own_conflicts + sum(new[2] - old_cost[2] for new, old_cost in changes),
                        foreign_overlaps=best.foreign_overlaps + foreign[i][channel][1] - foreign[i][old][1],
                    )
                    if candidate.rank < best.rank:
                        best, current, improved = candidate, trial, True
                        if acceptable(candidate) and candidate.rank < best_safe.rank:
                            best_safe = candidate
            if not improved:
                return

    # A greedy seed can end in a local minimum that is worse than the observed layout, so the observed layout is a
    # second start: the result is never worse than either.
    improve(greedy)
    improve(before.channels)
    if heuristic_only:
        return OptimizedPlan(
            before=before, after=best_safe, method=ChannelPlanMethod.HEURISTIC, evaluations=evaluations
        )
    exact_share = None if budget is None else (budget + 1) // 2
    return _exact(
        ordered, candidates, incident, foreign, before, acceptable, pair_cost, edge_cost, loses_power,
        incumbent=best_safe, units=exact_share, spent_before=evaluations,
    )  # fmt: skip


def _exact(
    ordered: tuple[PlanRadio, ...],
    candidates: tuple[tuple[int, ...], ...],
    incident: list[list[tuple[int, PlanEdge]]],
    foreign: list[dict[int, tuple[int, int]]],
    before: PlanScore,
    acceptable: Callable[[PlanScore], bool],
    pair_cost: Callable[[int, int, int, int, PlanEdge], tuple[int, int, int]],
    edge_cost: Callable[[int, int, int, int, PlanEdge], tuple[int, int, int]],
    loses_power: Callable[[int, int], int],
    *,
    incumbent: PlanScore,
    units: int | None,
    spent_before: int,
) -> OptimizedPlan:
    """Enumerate the assignments of the radios that have a choice, pruning every partial assignment that cannot beat
    the incumbent, and say whether the enumeration ran to its end. A radio with one candidate is a constant: its own
    terms are added once and its edges to a free radio become a per-candidate cost of that radio, so the work follows
    the number of assignments and not the number of radios.

    Every key of the rank is a sum of non-negative terms, so a partial assignment whose keys already exceed the
    incumbent's first five (lexicographically) can only grow worse, and so can one that has lost power or whose own
    pressure plus power risk is no longer below the observed own pressure, the two conditions `acceptable` demands.
    One unit is one candidate considered, counted before the prune tests; the search stops when a unit is needed and
    none is left.
    """
    fixed = {i: c[0] for i, c in enumerate(candidates) if len(c) == 1}
    # Heavily coupled radios first: their choices cost the most, so the bound bites early. Ties by position.
    free = sorted(
        (i for i in range(len(ordered)) if i not in fixed),
        key=lambda i: (-sum(max(0, e.rssi_dbm + 83) for _, e in incident[i]), i),
    )
    slot = {radio: position for position, radio in enumerate(free)}
    constant = [0, 0, 0, 0, 0, 0, 0]
    for i, channel in fixed.items():
        fp, fh = foreign[i][channel]
        constant[3] += fp
        constant[4] += fh
        constant[5] += channel != ordered[i].current
        constant[6] += loses_power(i, channel)
        for peer, edge in incident[i]:
            if peer in fixed and peer > i:
                cost = (
                    edge_cost(i, channel, peer, fixed[peer], edge)
                    if edge.a == ordered[i].name
                    else edge_cost(peer, fixed[peer], i, channel, edge)
                )
                constant[0] += cost[0]
                constant[1] += cost[1]
                constant[2] += cost[2]
    unary: dict[tuple[int, int], tuple[int, int, int]] = {}
    for i in free:
        for channel in candidates[i]:
            costs = [pair_cost(i, channel, peer, fixed[peer], edge) for peer, edge in incident[i] if peer in fixed]
            unary[i, channel] = (
                sum(c[0] for c in costs),
                sum(c[1] for c in costs),
                sum(c[2] for c in costs),
            )
    earlier = {i: [(peer, edge) for peer, edge in incident[i] if peer in slot and slot[peer] < slot[i]] for i in free}
    best = incumbent
    considered = 0
    chosen: list[int] = []

    def full_channels() -> tuple[int, ...]:
        by_radio = dict(fixed)
        by_radio.update(zip(free, chosen, strict=True))
        return tuple(by_radio[i] for i in range(len(ordered)))

    def enumerate_assignments(position: int, totals: tuple[int, int, int, int, int, int, int]) -> None:
        nonlocal best, considered
        pressure, risk, conflicts, foreign_pressure, foreign_hits, moved, power_loss = totals
        if position == len(free):
            if (pressure, risk, power_loss, foreign_pressure, moved) > best.rank[:5]:
                return
            candidate = PlanScore(
                own_pressure=pressure,
                power_risk=risk,
                power_loss=power_loss,
                foreign_pressure=foreign_pressure,
                moved=moved,
                channels=full_channels(),
                own_conflicts=conflicts,
                foreign_overlaps=foreign_hits,
            )
            if acceptable(candidate) and candidate.rank < best.rank:
                best = candidate
            return
        i = free[position]
        for channel in candidates[i]:
            if units is not None and considered >= units:
                raise _BudgetSpentError
            considered += 1
            hits = [pair_cost(i, channel, peer, chosen[slot[peer]], edge) for peer, edge in earlier[i]]
            base, extra, conflict = unary[i, channel]
            next_pressure = pressure + base + sum(h[0] for h in hits)
            next_risk = risk + extra + sum(h[1] for h in hits)
            next_loss = power_loss + loses_power(i, channel)
            fp, fh = foreign[i][channel]
            next_foreign = foreign_pressure + fp
            next_moved = moved + (channel != ordered[i].current)
            if next_loss > 0 or next_pressure + next_risk >= before.own_pressure:
                continue
            if (next_pressure, next_risk, next_loss, next_foreign, next_moved) > best.rank[:5]:
                continue
            chosen.append(channel)
            enumerate_assignments(
                position + 1,
                (
                    next_pressure,
                    next_risk,
                    conflicts + conflict + sum(h[2] for h in hits),
                    next_foreign,
                    foreign_hits + fh,
                    next_moved,
                    next_loss,
                ),
            )
            chosen.pop()

    completed = True
    try:
        enumerate_assignments(0, (*constant,))  # type: ignore[arg-type]
    except _BudgetSpentError:
        completed = False
    return OptimizedPlan(
        before=before,
        after=best,
        method=ChannelPlanMethod.EXACT if completed else ChannelPlanMethod.HEURISTIC,
        evaluations=spent_before + considered,
        exact_evaluations=considered,
    )


def canonical_candidates(band: Band, width_mhz: int, channels: tuple[int, ...], current: int) -> tuple[int, ...]:
    """One primary per occupied block; keep the observed primary when its block is represented."""
    if band is Band.GHZ_2:
        return tuple(sorted(set(channels)))
    blocks: dict[tuple[int, int], int] = {}
    for channel in sorted(set(channels)):
        block = channel_block_5g(channel, width_mhz)
        key = block.low, block.high
        if key not in blocks or channel == current:
            blocks[key] = channel
    return tuple(sorted(blocks.values()))
