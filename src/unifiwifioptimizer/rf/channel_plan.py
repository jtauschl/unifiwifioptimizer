"""Bounded site-wide channel assignment over measured receiver-location proxies (docs/ALGORITHM.md §8)."""

from collections.abc import Callable
from dataclasses import dataclass
from functools import cache, lru_cache
from math import prod

from unifiwifioptimizer.domain.analysis import ChannelPlanMethod
from unifiwifioptimizer.domain.models import Band
from unifiwifioptimizer.rf.channels import channel_block_5g, channels_overlap

EXACT_LIMIT = 100_000
HEURISTIC_LIMIT = 20_000
RADIO_LIMIT = 128


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

    @property
    def improved(self) -> bool:
        return self.after.own_pressure < self.before.own_pressure


def optimize(radios: tuple[PlanRadio, ...], edges: tuple[PlanEdge, ...]) -> OptimizedPlan:
    """Find the lexicographic minimum, exactly for small products and with bounded local search otherwise.

    Callers validate candidate geometry and the 128-radio limit before entering this pure function.
    """
    ordered = tuple(sorted(radios, key=lambda r: r.name))
    index = {r.name: i for i, r in enumerate(ordered)}
    candidates = tuple(r.candidates for r in ordered)

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

    @cache
    def geometry_overlap(channel_a: int, width_a: int, channel_b: int, width_b: int) -> bool:
        return channels_overlap(ordered[0].band, channel_a, width_a, channel_b, width_b)

    def overlaps(a: int, channel_a: int, b: int, channel_b: int) -> bool:
        return geometry_overlap(channel_a, ordered[a].width_mhz, channel_b, ordered[b].width_mhz)

    def increase(i: int, channel: int) -> int:
        if channel == ordered[i].current:
            return 0
        current = ordered[i].current_power_dbm
        ceiling = ceilings[i].get(channel)
        return max(0, ceiling - current) if current is not None and ceiling is not None else 0

    def loses_power(i: int, channel: int) -> int:
        if channel == ordered[i].current:
            return 0
        current = ordered[i].current_power_dbm
        ceiling = ceilings[i].get(channel)
        return int(current is not None and ceiling is not None and ceiling < current)

    @lru_cache(maxsize=100_000)
    def edge_cost(a: int, channel_a: int, b: int, channel_b: int, edge: PlanEdge) -> tuple[int, int, int]:
        if not overlaps(a, channel_a, b, channel_b):
            return 0, 0, 0
        baseline = max(0, edge.rssi_dbm + 83)
        directed = []
        if edge.a_at_b_dbm is not None:
            directed.append(edge.a_at_b_dbm + increase(a, channel_a))
        if edge.b_at_a_dbm is not None:
            directed.append(edge.b_at_a_dbm + increase(b, channel_b))
        possible = max((max(0, rssi + 83) for rssi in directed), default=baseline)
        return baseline, max(0, possible - baseline), int(baseline > 0)

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
    size = prod(map(len, candidates))
    if before.own_pressure == 0:
        return OptimizedPlan(
            before=before,
            after=before,
            method=ChannelPlanMethod.EXACT if size <= EXACT_LIMIT else ChannelPlanMethod.HEURISTIC,
            evaluations=0,
        )
    if size <= EXACT_LIMIT:
        return _exact(ordered, candidates, incident, foreign, before, acceptable, pair_cost, edge_cost, loses_power)

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

    def improve(start: tuple[int, ...]) -> None:
        """Local search over single-radio moves from `start`; keeps the best acceptable assignment seen."""
        nonlocal best_safe, evaluations
        current = start
        best = score(current)
        if acceptable(best) and best.rank < best_safe.rank:
            best_safe = best
        while evaluations < HEURISTIC_LIMIT:
            improved = False
            for i in order:
                for channel in candidates[i]:
                    if evaluations >= HEURISTIC_LIMIT:
                        break
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
                if evaluations >= HEURISTIC_LIMIT:
                    break
            if not improved:
                break

    # A greedy seed can end in a local minimum that is worse than the observed layout, so the observed layout is a
    # second start: the result is never worse than either.
    improve(greedy)
    improve(before.channels)
    return OptimizedPlan(before=before, after=best_safe, method=ChannelPlanMethod.HEURISTIC, evaluations=evaluations)


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
) -> OptimizedPlan:
    """Enumerate every assignment of the radios that have a choice. A radio with one candidate is a constant: its
    own terms are added once and its edges to a free radio become a per-candidate cost of that radio, so the run
    time follows the number of assignments and not the number of radios."""
    fixed = {i: c[0] for i, c in enumerate(candidates) if len(c) == 1}
    free = [i for i in range(len(ordered)) if i not in fixed]
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
    best = before
    evaluated = 0
    chosen: list[int] = []

    def full_channels() -> tuple[int, ...]:
        by_radio = dict(fixed)
        by_radio.update(zip(free, chosen, strict=True))
        return tuple(by_radio[i] for i in range(len(ordered)))

    def enumerate_assignments(position: int, totals: tuple[int, int, int, int, int, int, int]) -> None:
        nonlocal best, evaluated
        pressure, risk, conflicts, foreign_pressure, foreign_hits, moved, power_loss = totals
        if position == len(free):
            evaluated += 1
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
            hits = [pair_cost(i, channel, peer, chosen[slot[peer]], edge) for peer, edge in earlier[i]]
            base, extra, conflict = unary[i, channel]
            next_pressure = pressure + base + sum(h[0] for h in hits)
            if next_pressure > best.own_pressure:
                continue
            fp, fh = foreign[i][channel]
            chosen.append(channel)
            enumerate_assignments(
                position + 1,
                (
                    next_pressure,
                    risk + extra + sum(h[1] for h in hits),
                    conflicts + conflict + sum(h[2] for h in hits),
                    foreign_pressure + fp,
                    foreign_hits + fh,
                    moved + (channel != ordered[i].current),
                    power_loss + loses_power(i, channel),
                ),
            )
            chosen.pop()

    enumerate_assignments(
        0, (constant[0], constant[1], constant[2], constant[3], constant[4], constant[5], constant[6])
    )
    return OptimizedPlan(before=before, after=best, method=ChannelPlanMethod.EXACT, evaluations=evaluated)


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
