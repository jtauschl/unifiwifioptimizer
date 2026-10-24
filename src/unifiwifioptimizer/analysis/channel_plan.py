"""Evidence gate and aggregation for the optional site-wide channel proposal (docs/ALGORITHM.md §8)."""

from collections import Counter, defaultdict
from collections.abc import Mapping
from statistics import median

from unifiwifioptimizer.analysis.channels import candidate_set, channel_blacklisted, geometry_of
from unifiwifioptimizer.analysis.neighbors import (
    EVALUATED_BANDS,
    BandUsage,
    measured,
    reduce_band_passes,
    symmetric_neighbours,
)
from unifiwifioptimizer.domain.models import DFS_WAIT_STATE, SETTINGS_ENDPOINT, Band, Radio, SiteSnapshot, TxPowerMode
from unifiwifioptimizer.domain.report import (
    BEACON_EVIDENCE_GAP,
    BandChannelPlan,
    ChannelAssignment,
    ChannelPlanStatus,
    ExtendedChannelPlan,
    PowerOpportunity,
)
from unifiwifioptimizer.domain.scan import ApScan, PhyChannelPower, SiteScan
from unifiwifioptimizer.rf.channel_plan import RADIO_LIMIT, PlanEdge, PlanRadio, canonical_candidates, optimize
from unifiwifioptimizer.rf.channel_power import calibrated_ceilings
from unifiwifioptimizer.rf.channels import (
    DFS_CHANNELS_5G,
    WIDTHS_2G,
    cac_seconds,
    center_frequency_mhz,
    channel_block_5g,
    channel_from_frequency,
    channels_overlap,
)


def _unavailable(band: Band, reason: str) -> BandChannelPlan:
    return BandChannelPlan(
        band=band,
        status=ChannelPlanStatus.UNAVAILABLE,
        reason=reason,
        method=None,
        assignments=(),
        own_conflicts_before=None,
        own_conflicts_after=None,
        own_pressure_before=None,
        own_pressure_after=None,
        foreign_overlaps_before=None,
        foreign_overlaps_after=None,
        data_gaps=(),
    )


def _foreign(usage: BandUsage, band: Band, own_bssids: frozenset[str]) -> tuple[tuple[tuple[int, int], ...], int]:
    sightings: dict[str, list[tuple[int | None, int]]] = defaultdict(list)
    for band_scan in usage.usable_passes:
        for reading in band_scan.readings:
            if reading.bssid not in own_bssids:
                sightings[reading.bssid].append((reading.frequency_mhz, reading.rssi_dbm))
    observations: list[tuple[int, int]] = []
    gaps = 0
    for values in sightings.values():
        frequency, count = (
            Counter(f for f, _ in values if f is not None).most_common(1)[0]
            if any(f is not None for f, _ in values)
            else (None, 0)
        )
        channel = channel_from_frequency(band, frequency) if frequency is not None else None
        if channel is None or count * 2 <= len(values):
            gaps += 1
            continue
        observations.append((channel, round(median(rssi for f, rssi in values if f == frequency))))
    return tuple(sorted(observations)), gaps


def _setting_cap(radio: Radio) -> int | None:
    """What the power setting itself allows: the configured value only in Custom mode (it is stale otherwise, see
    docs/ALGORITHM.md §4), the hardware maximum under High and Auto. The fixed Low and Medium levels differ per
    channel group and are unknown."""
    if radio.tx_power_mode is TxPowerMode.CUSTOM:
        return radio.configured_tx_dbm
    if radio.tx_power_mode in (TxPowerMode.HIGH, TxPowerMode.AUTO):
        return radio.max_tx_dbm
    return None


def _stable_power(ap_scan: ApScan | None) -> PhyChannelPower | None:
    if ap_scan is None:
        return None
    passes = ap_scan.successful_passes
    if not passes or passes[0].power_5g is None:
        return None
    first = passes[0].power_5g
    return first if all(p.power_5g == first for p in passes) else None


def _band(
    band: Band, snapshot: SiteSnapshot, scan: SiteScan | None, neighbours: Mapping[str, frozenset[str]]
) -> BandChannelPlan:
    if scan is None:
        return _unavailable(band, "neighbour scan was not run")
    if snapshot.unparsable_devices:
        return _unavailable(band, "one or more access points could not be parsed")
    names = {ap.name for ap in snapshot.access_points}
    if len(names) != len(snapshot.access_points):
        return _unavailable(band, "access point names are not unique")
    aps = tuple(
        sorted((ap for ap in snapshot.access_points if not ap.offline and ap.radio(band)), key=lambda a: a.name)
    )
    if len(aps) < 2:
        return _unavailable(band, "fewer than two online radios participate")
    if len(aps) > RADIO_LIMIT:
        return _unavailable(band, "site exceeds the bounded planner size")
    adjacency = symmetric_neighbours(neighbours)
    if adjacency.keys() - names or scan.unknown_names:
        return _unavailable(band, "a configured access point is absent from the controller snapshot")
    offline = tuple(sorted(ap.name for ap in snapshot.access_points if ap.offline and ap.radio(band)))
    if any(adjacency.get(name, frozenset()) & {ap.name for ap in aps} for name in offline):
        return _unavailable(band, "a configured neighbour of a participating access point is offline")
    if any(problem.endpoint == SETTINGS_ENDPOINT for problem in snapshot.problems):
        return _unavailable(band, "the controller settings could not be read completely, Channel AI state is uncertain")
    channel_ai = snapshot.settings.channel_ai
    base = candidate_set(band, channel_ai)
    if base is None:
        return _unavailable(band, "controller supplied no channel candidates for this band")
    bssids = snapshot.bssids
    own_bssids = frozenset(bssids.entries)
    usages = {ap.name: reduce_band_passes(scan.scan_of(ap.mac), band) for ap in aps}
    radios: list[PlanRadio] = []
    power_unknown = 0
    gaps = 0
    for ap in aps:
        geom = geometry_of(ap, band)
        configured = ap.radio(band)
        stats = ap.stats(band)
        if geom is None or configured is None or stats is None:
            return _unavailable(band, "a participating radio has unknown channel geometry")
        if stats.state == DFS_WAIT_STATE:
            return _unavailable(band, "a participating radio is waiting for DFS availability")
        if geom.moved:
            return _unavailable(band, "a fixed channel was moved by the controller or radar")
        if band is Band.GHZ_2 and geom.width_mhz == 40:
            return _unavailable(band, "40 MHz on 2.4 GHz has an unknown future extension side")
        if band is Band.GHZ_2 and geom.width_mhz not in WIDTHS_2G:
            return _unavailable(band, "a participating radio has unsupported channel geometry")
        if channel_ai is None and geom.auto:
            return _unavailable(band, "the controller sent no Channel AI state and a radio is on automatic channel")
        if channel_ai is not None and channel_ai.enabled and geom.auto and ap.mac not in channel_ai.excluded_devices:
            return _unavailable(band, "Channel AI manages an automatic radio")
        if not usages[ap.name].usable_passes:
            return _unavailable(band, "a participating access point has no usable band scan")
        try:
            center_frequency_mhz(band, geom.channel)
            if band is Band.GHZ_5:
                channel_block_5g(geom.channel, geom.width_mhz)
        except ValueError:
            return _unavailable(band, "a participating radio has unsupported channel geometry")
        candidates: list[int] = []
        for channel in sorted(base):
            if band is Band.GHZ_5:
                try:
                    block = channel_block_5g(channel, geom.width_mhz)
                    if channel_blacklisted(band, channel, geom.width_mhz, channel_ai):
                        continue
                except ValueError:
                    continue
                if any(c in DFS_CHANNELS_5G for c in range(block.low, block.high + 1, 4)) and (
                    configured.dfs_capable is not True and channel != geom.channel
                ):
                    continue
            else:
                try:
                    center_frequency_mhz(band, channel)
                except ValueError:
                    continue
                if channel_blacklisted(band, channel, geom.width_mhz, channel_ai):
                    continue
            candidates.append(channel)
        if geom.channel not in candidates:
            return _unavailable(band, "observed primary is absent from the permitted candidate set")
        foreign, missing = _foreign(usages[ap.name], band, own_bssids)
        gaps += missing
        canonical = canonical_candidates(band, geom.width_mhz, tuple(candidates), geom.channel)
        power = None
        if band is Band.GHZ_5:
            table = _stable_power(scan.scan_of(ap.mac))
            if table is not None and table.current_frequency_mhz == center_frequency_mhz(band, geom.channel):
                power = calibrated_ceilings(
                    geom.channel,
                    geom.width_mhz,
                    stats.observed_tx_dbm,
                    _setting_cap(configured),
                    configured.max_tx_dbm,
                    configured.antenna_gain_dbi,
                    table.limits,
                    canonical,
                )
            if power is None:
                power_unknown += 1
        radios.append(
            PlanRadio(
                name=ap.name,
                band=band,
                current=geom.channel,
                width_mhz=geom.width_mhz,
                candidates=canonical,
                foreign=foreign,
                current_power_dbm=power.current_dbm if power else None,
                candidate_ceilings=power.candidates if power else (),
            )
        )
    edges: list[PlanEdge] = []
    unknown_pairs = 0
    for pos, a in enumerate(aps):
        for b in aps[pos + 1 :]:
            a_at_b, _ = measured(a, b, band, usages[b.name], bssids)
            b_at_a, _ = measured(b, a, band, usages[a.name], bssids)
            if a_at_b is None and b_at_a is None:
                if b.name in adjacency.get(a.name, frozenset()):
                    return _unavailable(band, "a configured neighbour pair has no measured direction")
                unknown_pairs += 1
                continue
            signal = max(v for v in (a_at_b, b_at_a) if v is not None)
            edges.append(PlanEdge(a=a.name, b=b.name, rssi_dbm=signal, a_at_b_dbm=a_at_b, b_at_a_dbm=b_at_a))
    outcome = optimize(tuple(radios), tuple(edges))
    before, after = outcome.before, outcome.after
    status = ChannelPlanStatus.RECOMMENDED if outcome.improved else ChannelPlanStatus.NO_IMPROVEMENT
    assignments = tuple(
        ChannelAssignment(ap=radio.name, current=radio.current, proposed=after.channels[i], width_mhz=radio.width_mhz)
        for i, radio in enumerate(radios)
    )
    data_gaps = []
    if offline:
        data_gaps.append(f"{len(offline)} offline access point radio(s) are not planned")
    if unknown_pairs:
        data_gaps.append(f"{unknown_pairs} unconfigured AP pair(s) have no measured direction")
    if gaps:
        data_gaps.append(f"{gaps} foreign BSS observation(s) have no majority frequency")
    if power_unknown:
        data_gaps.append(f"{power_unknown} radio(s) lack calibrated channel-power evidence")
    data_gaps.append(BEACON_EVIDENCE_GAP)
    opportunities: list[PowerOpportunity] = []
    if band is Band.GHZ_5:
        by_name = {radio.name: radio for radio in radios}
        for radio in radios:
            current_power = radio.current_power_dbm
            if current_power is None:
                continue
            stronger = [
                (channel, ceiling)
                for channel, ceiling in radio.candidate_ceilings
                if channel != radio.current and ceiling > current_power
            ]
            if not stronger:
                continue
            candidate, ceiling = min(
                stronger,
                key=lambda item: (
                    -(item[1] - current_power),
                    cac_seconds(item[0], radio.width_mhz) or 0,
                    item[0],
                ),
            )
            overlaps = sum(
                channels_overlap(band, candidate, radio.width_mhz, by_name[peer].current, by_name[peer].width_mhz)
                for edge in edges
                if (peer := edge.b if edge.a == radio.name else edge.a if edge.b == radio.name else None) is not None
            )
            opportunities.append(
                PowerOpportunity(
                    ap=radio.name,
                    current_channel=radio.current,
                    candidate_channel=candidate,
                    current_dbm=current_power,
                    candidate_ceiling_dbm=ceiling,
                    overlapping_peers=overlaps,
                    cac_seconds=cac_seconds(candidate, radio.width_mhz),
                )
            )
    return BandChannelPlan(
        band=band,
        status=status,
        reason=None,
        method=outcome.method,
        assignments=assignments,
        own_conflicts_before=before.own_conflicts,
        own_conflicts_after=after.own_conflicts,
        own_pressure_before=before.own_pressure,
        own_pressure_after=after.own_pressure,
        foreign_overlaps_before=before.foreign_overlaps,
        foreign_overlaps_after=after.foreign_overlaps,
        data_gaps=tuple(data_gaps),
        power_opportunities=tuple(opportunities),
        possible_power_pressure_after=after.own_pressure + after.power_risk if band is Band.GHZ_5 else None,
    )


def extended_channel_plan(
    snapshot: SiteSnapshot, scan: SiteScan | None, neighbours: Mapping[str, frozenset[str]]
) -> ExtendedChannelPlan:
    """Provide independent 2.4/5 GHz plans or explicit evidence gaps, without exposing scan identifiers."""
    return ExtendedChannelPlan(bands=tuple(_band(band, snapshot, scan, neighbours) for band in EVALUATED_BANDS))
