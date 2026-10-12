"""Channel checks over the configured and the heard graph (docs/ALGORITHM.md §8/§9).

The geometry in use always comes from the radio statistics (a radar move takes a fixed radio elsewhere).
Overlap between configured neighbours and co-channel contention between any two own access points that
hear each other at or above the CCA level are advisories; a layout that cannot be coloured with the
channels available is one too. Under Channel AI an auto radio's layout is reported, not recommended: the
nightly optimisation would overwrite the advice.
"""

from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from unifiwifioptimizer.analysis.neighbors import (
    EVALUATED_BANDS,
    heard_graph_edges,
    reduce_band_passes,
    symmetric_neighbours,
)
from unifiwifioptimizer.domain.models import AccessPoint, Band, ChannelAiSettings, SiteSnapshot
from unifiwifioptimizer.domain.report import Finding, Severity
from unifiwifioptimizer.domain.scan import SiteScan
from unifiwifioptimizer.rf.channels import (
    CHANNELS_5G,
    CLEAN_2G_CHANNELS,
    PUNCTURED_WIDTHS_5G,
    channel_block_5g,
    channel_from_frequency,
    channel_reuse_feasible,
    channels_overlap,
)
from unifiwifioptimizer.rf.constants import CCA_PREAMBLE_DETECT_DBM


@dataclass(frozen=True, slots=True, kw_only=True)
class RadioGeometry:
    """What a radio occupies right now, and how it got there."""

    ap: str
    band: Band
    channel: int
    width_mhz: int
    extension_channel: int | None
    auto: bool
    configured_channel: int | None

    @property
    def moved(self) -> bool:
        return self.configured_channel is not None and self.configured_channel != self.channel


def geometry_of(ap: AccessPoint, band: Band) -> RadioGeometry | None:
    radio, stats = ap.radio(band), ap.stats(band)
    if radio is None or stats is None:
        return None
    return RadioGeometry(
        ap=ap.name,
        band=band,
        channel=stats.channel,
        width_mhz=stats.width_mhz,
        extension_channel=stats.extension_channel,
        auto=radio.channel is None,
        configured_channel=radio.channel,
    )


def _overlap(a: RadioGeometry, b: RadioGeometry) -> bool | None:
    """None when the geometry cannot be judged (an unmodelled width or channel)."""
    try:
        return channels_overlap(
            a.band, a.channel, a.width_mhz, b.channel, b.width_mhz, a.extension_channel, b.extension_channel
        )
    except ValueError:
        return None


def _finding(severity: Severity, code: str, ap: str, band: Band, message: str, peers: Iterable[str] = ()) -> Finding:
    return Finding(severity=severity, code=code, message=message, subject=ap, band=band, peers=tuple(peers))


def free_candidates(
    band: Band, taken: Iterable[RadioGeometry], candidates: frozenset[int], width_mhz: int
) -> list[int]:
    """Channels of `candidates` on which a radio of `width_mhz` would overlap none of `taken`."""
    free: list[int] = []
    for channel in sorted(candidates):
        probe = RadioGeometry(
            ap="",
            band=band,
            channel=channel,
            width_mhz=width_mhz,
            extension_channel=None,
            auto=False,
            configured_channel=None,
        )
        verdicts = [_overlap(probe, other) for other in taken]
        if all(v is False for v in verdicts):
            free.append(channel)
    return free


def candidate_set(band: Band, channel_ai: ChannelAiSettings | None) -> frozenset[int]:
    """The controller's per-band candidate list when it has one, else the full channel set."""
    if channel_ai is not None and band in channel_ai.channels and channel_ai.channels[band]:
        return channel_ai.channels[band]
    return CLEAN_2G_CHANNELS if band is Band.GHZ_2 else CHANNELS_5G


def colour_count(band: Band, candidates: frozenset[int], width_mhz: int) -> int:
    """How many mutually non-overlapping channels of `width_mhz` the candidate set offers."""
    if band is Band.GHZ_2:
        return len(CLEAN_2G_CHANNELS & candidates) if width_mhz == 20 else 1
    blocks = set()
    for channel in candidates:
        try:
            blocks.add(channel_block_5g(channel, width_mhz))
        except ValueError:
            continue
    return len(blocks)


def components(adjacency: Mapping[str, frozenset[str]]) -> list[frozenset[str]]:
    seen: set[str] = set()
    out: list[frozenset[str]] = []
    for start in sorted(adjacency):
        if start in seen:
            continue
        stack, members = [start], set()
        while stack:
            node = stack.pop()
            if node in members:
                continue
            members.add(node)
            stack.extend(adjacency.get(node, frozenset()))
        seen |= members
        out.append(frozenset(members))
    return out


@dataclass(frozen=True, slots=True, kw_only=True)
class ChannelAnalysis:
    findings: tuple[Finding, ...]
    geometries: Mapping[tuple[str, Band], RadioGeometry]
    heard: Mapping[Band, frozenset[frozenset[str]]]
    reuse_infeasible: Mapping[Band, tuple[frozenset[str], ...]]


def analyse_channels(
    snapshot: SiteSnapshot,
    scan: SiteScan | None,
    neighbours: Mapping[str, frozenset[str]],
    channel_ai: ChannelAiSettings | None,
) -> ChannelAnalysis:
    aps = {ap.name: ap for ap in snapshot.access_points if not ap.offline}
    adjacency_cfg = symmetric_neighbours(neighbours)
    geometries: dict[tuple[str, Band], RadioGeometry] = {}
    for name, ap in aps.items():
        for band in EVALUATED_BANDS:
            geometry = geometry_of(ap, band)
            if geometry is not None:
                geometries[(name, band)] = geometry
    ai_on = channel_ai is not None and channel_ai.enabled
    excluded = frozenset(channel_ai.excluded_devices) if channel_ai is not None else frozenset()
    heard = heard_graph_edges(snapshot, scan, CCA_PREAMBLE_DETECT_DBM)
    findings: list[Finding] = []
    infeasible: dict[Band, list[frozenset[str]]] = defaultdict(list)
    for (name, band), geometry in sorted(geometries.items()):
        ap = aps[name]
        if geometry.moved:
            findings.append(
                _finding(
                    Severity.INFO,
                    "channel_moved",
                    name,
                    band,
                    f"configured channel {geometry.configured_channel}, in use {geometry.channel}",
                )
            )
        if band is Band.GHZ_2 and geometry.width_mhz == 40:
            findings.append(
                _finding(
                    Severity.ADVISORY,
                    "wide_2g",
                    name,
                    band,
                    "40 MHz on 2.4 GHz covers two of the three non-overlapping channels; use 20 MHz",
                )
            )
        if band is Band.GHZ_5 and geometry.width_mhz in PUNCTURED_WIDTHS_5G:
            findings.append(
                _finding(
                    Severity.INFO,
                    "width_not_modelled",
                    name,
                    band,
                    f"{geometry.width_mhz} MHz (Wi-Fi 7 punctured) is detected, its geometry not evaluated",
                )
            )
        if ai_on and ap.mac in excluded:
            findings.append(_finding(Severity.INFO, "channel_ai_excluded", name, band, "excluded from Channel AI"))
        if channel_ai is not None and (band, geometry.channel, geometry.width_mhz) in channel_ai.blacklist:
            findings.append(
                _finding(
                    Severity.ADVISORY,
                    "channel_in_blacklist",
                    name,
                    band,
                    f"channel {geometry.channel}/{geometry.width_mhz} MHz is on the Channel AI blacklist",
                )
            )
        overlapping: list[str] = []
        for peer in sorted(adjacency_cfg.get(name, frozenset())):
            other = geometries.get((peer, band))
            if other is not None and _overlap(geometry, other) is True:
                overlapping.append(peer)
        cochannel = sorted(
            peer
            for pair in heard.get(band, frozenset())
            if name in pair
            for peer in pair - {name}
            if (peer, band) in geometries and _overlap(geometry, geometries[(peer, band)]) is True
        )
        managed = geometry.auto and ai_on and ap.mac not in excluded
        if overlapping or cochannel:
            peers = sorted(set(overlapping) | set(cochannel))
            if managed:
                findings.append(
                    _finding(
                        Severity.INFO, "channel_ai_overlap", name, band,
                        f"channel {geometry.channel} overlaps {', '.join(peers)} under Channel AI; if this persists "
                        "across runs, pin channels or add exclusions",
                        peers,
                    )
                )  # fmt: skip
            elif geometry.auto:
                findings.append(
                    _finding(
                        Severity.ADVISORY, "pin_channels", name, band,
                        f"channel auto without Channel AI overlaps {', '.join(peers)}; nothing manages this layout: "
                        "pin channels",
                        peers,
                    )
                )  # fmt: skip
            else:
                taken = [geometries[(p, band)] for p in peers if (p, band) in geometries]
                free = free_candidates(band, taken, candidate_set(band, channel_ai), geometry.width_mhz)
                hint = (
                    f"; free candidates: {', '.join(str(c) for c in free)}"
                    if free
                    else "; no free candidate at this width"
                )
                if overlapping:
                    findings.append(
                        _finding(
                            Severity.ADVISORY, "channel_overlap", name, band,
                            f"channel {geometry.channel}/{geometry.width_mhz} MHz overlaps the configured "
                            f"neighbour(s) {', '.join(overlapping)}{hint}",
                            overlapping,
                        )
                    )  # fmt: skip
                heard_only = [p for p in cochannel if p not in overlapping]
                if heard_only:
                    findings.append(
                        _finding(
                            Severity.ADVISORY, "cochannel_heard", name, band,
                            f"heard co-channel at or above {CCA_PREAMBLE_DETECT_DBM} dBm by {', '.join(heard_only)}: "
                            f"both defer to each other{hint}",
                            heard_only,
                        )
                    )  # fmt: skip
    # Reuse feasibility over the union of the heard and the configured graph, per component.
    for band in EVALUATED_BANDS:
        union: dict[str, set[str]] = defaultdict(set)
        for name in aps:
            if (name, band) in geometries:
                union.setdefault(name, set())
        for name, configured_peers in adjacency_cfg.items():
            for peer in configured_peers:
                if (name, band) in geometries and (peer, band) in geometries:
                    union[name].add(peer)
                    union[peer].add(name)
        for pair in heard.get(band, frozenset()):
            a, b = sorted(pair)
            if (a, band) in geometries and (b, band) in geometries:
                union[a].add(b)
                union[b].add(a)
        adjacency = {n: frozenset(p) for n, p in union.items()}
        for component in components(adjacency):
            if len(component) < 2:
                continue
            widest = max(geometries[(n, band)].width_mhz for n in component)
            colours = colour_count(band, candidate_set(band, channel_ai), widest)
            sub = {n: frozenset(p for p in adjacency[n] if p in component) for n in component}
            if not channel_reuse_feasible(sub, colours):
                infeasible[band].append(component)
                members: list[str] = sorted(component)
                findings.append(
                    _finding(
                        Severity.ADVISORY, "channel_reuse_infeasible", members[0], band,
                        f"{len(members)} access points that hear each other ({', '.join(members)}) cannot all get "
                        f"distinct channels from the {colours} available at {widest} MHz; reduce the width or accept "
                        "co-channel reuse",
                        members,
                    )
                )  # fmt: skip
    return ChannelAnalysis(
        findings=tuple(findings),
        geometries=geometries,
        heard=heard,
        reuse_infeasible={band: tuple(groups) for band, groups in infeasible.items()},
    )


@dataclass(frozen=True, slots=True, kw_only=True)
class ForeignSummary:
    count: int
    strongest_dbm: int | None
    overlapping_count: int


def foreign_networks(
    ap: AccessPoint, band: Band, scan: SiteScan | None, snapshot: SiteSnapshot
) -> ForeignSummary | None:
    """Foreign BSSs heard by this access point on the band, as counts only (no names leave the scan). A
    foreign BSS counts as overlapping when its 20 MHz primary channel overlaps this radio's block — the scan
    reports no width for it."""
    ap_scan = scan.scan_of(ap.mac) if scan is not None else None
    usage = reduce_band_passes(ap_scan, band)
    if not usage.usable_passes:
        return None
    bssids = snapshot.bssids
    geometry = geometry_of(ap, band)
    strongest: dict[str, int] = {}
    frequencies: dict[str, int | None] = {}
    for band_scan in usage.usable_passes:
        for reading in band_scan.readings:
            if bssids.lookup(reading.bssid) is not None:
                continue
            strongest[reading.bssid] = max(strongest.get(reading.bssid, -200), reading.rssi_dbm)
            frequencies[reading.bssid] = reading.frequency_mhz
    overlapping = 0
    if geometry is not None:
        for frequency in frequencies.values():
            channel = channel_from_frequency(band, frequency) if frequency is not None else None
            if channel is not None and _overlaps_primary(geometry, channel):
                overlapping += 1
    return ForeignSummary(
        count=len(strongest),
        strongest_dbm=max(strongest.values()) if strongest else None,
        overlapping_count=overlapping,
    )


def _overlaps_primary(geometry: RadioGeometry, channel: int) -> bool:
    try:
        return channels_overlap(
            geometry.band, geometry.channel, geometry.width_mhz, channel, 20, geometry.extension_channel, None
        )
    except ValueError:
        return False
