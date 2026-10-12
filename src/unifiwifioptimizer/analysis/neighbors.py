"""The neighbour matrix: for every configured pair (A, B) and band, how strongly B heard A.

`A→B` is the RSSI of A's beacons measured at B, the only direction A's transmit power moves. It is the
median over B's successful passes of every reading of one of A's BSSIDs on A's current primary frequency
(ADR-002 D8: median, peer channel). A cell without a reading names why (`MissingReason`, most fundamental
first) and, where B heard nothing of A but A heard B, carries the reverse reading predicted through
reciprocity instead (same path loss both ways, only the powers differ) — the original reason stays beside
it, because the partial flag of the run still follows the scan failure.
"""

from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from unifiwifioptimizer.domain.analysis import MissingReason, ReadingSource
from unifiwifioptimizer.domain.models import DFS_WAIT_STATE, AccessPoint, Band, BssidIndex, Mac, SiteSnapshot
from unifiwifioptimizer.domain.scan import ApScan, BandScan, BandScanStatus, ScanMeta, SiteScan
from unifiwifioptimizer.rf.aggregate import Sighting, aggregate_rssi, consensus_readings
from unifiwifioptimizer.rf.channels import DFS_CHANNELS_5G, center_frequency_or_none, channel_from_frequency
from unifiwifioptimizer.rf.constants import RCPI_ACCURACY_DB
from unifiwifioptimizer.rf.txpower import predict_reverse_rssi

EVALUATED_BANDS = (Band.GHZ_2, Band.GHZ_5)
CAC_ACTIVE = "active"
# A one-way miss is substituted by reciprocity unless this access point itself could not have been heard, the
# peer is unknown, or the peer is offline (a reading of an offline radio predates its going down and says
# nothing about the current path).
NOT_RECIPROCITY_ELIGIBLE = frozenset(
    {
        MissingReason.SCAN_SKIPPED,
        MissingReason.SELF_OFFLINE,
        MissingReason.SELF_DFS_WAIT,
        MissingReason.PEER_UNKNOWN,
        MissingReason.PEER_OFFLINE,
    }
)


@dataclass(frozen=True, slots=True, kw_only=True)
class PeerReading:
    """One cell of the matrix: what `peer` measured of the subject access point on `band`."""

    peer: str
    band: Band
    rssi_dbm: int | None
    source: ReadingSource | None
    samples: int
    reason: MissingReason | None
    # (A at B) - (B at A) - (tx_eff_A - tx_eff_B) when both directions were measured: the receivers' disagreement.
    receiver_offset_db: int | None = None
    # Why the reverse direction (peer at subject) has no reading, when it has none; a miss in both directions
    # is a verdict of its own (ADR-002 D8), a one-way miss is not.
    reverse_reason: MissingReason | None = None

    @property
    def why(self) -> MissingReason:
        """The reason of a cell without a value; a cell with a reading (measured or predicted) has none to give."""
        if self.reason is None:
            raise ValueError(f"{self.peer}: a cell with a reading carries no missing reason")
        return self.reason

    @property
    def both_way_miss(self) -> bool:
        return (
            self.rssi_dbm is None
            and self.reason is MissingReason.NOT_SIGHTED
            and self.reverse_reason is MissingReason.NOT_SIGHTED
        )

    @property
    def blocking(self) -> bool:
        """A peer whose absence keeps a reduction or a confirmation from being safe: no value, and the reason
        is neither an offline peer (nothing to hear) nor a both-way miss (a verdict of its own)."""
        return self.rssi_dbm is None and self.reason is not MissingReason.PEER_OFFLINE and not self.both_way_miss


@dataclass(frozen=True, slots=True, kw_only=True)
class BandUsage:
    """What one access point's scan said about one band after reducing its passes."""

    status: BandScanStatus | None
    usable_passes: tuple[BandScan, ...]
    cac_active_in_every_pass: bool


def symmetric_neighbours(neighbours: Mapping[str, Iterable[str]]) -> dict[str, frozenset[str]]:
    """The operator's adjacency as an undirected graph: a pair listed on one side counts for both."""
    pairs: dict[str, set[str]] = defaultdict(set)
    for ap, peers in neighbours.items():
        pairs.setdefault(ap, set())
        for peer in peers:
            pairs[ap].add(peer)
            pairs[peer].add(ap)
    return {ap: frozenset(peers) for ap, peers in pairs.items()}


def asymmetric_pairs(neighbours: Mapping[str, Iterable[str]]) -> tuple[tuple[str, str], ...]:
    """Pairs listed on one side only, (lister, unlisted peer), in configuration order."""
    out: list[tuple[str, str]] = []
    for ap, peers in neighbours.items():
        for peer in sorted(peers):
            if ap not in neighbours.get(peer, ()):
                out.append((ap, peer))
    return tuple(out)


def reduce_band_passes(scan: ApScan | None, band: Band) -> BandUsage:
    """Any usable pass (status `ok` with readings) wins; else `empty` (an `ok` pass without readings is one);
    else the last pass's status. A pass whose 5 GHz radio was in its channel availability check is not usable
    on 5 GHz and is counted separately."""
    if scan is None:
        return BandUsage(status=None, usable_passes=(), cac_active_in_every_pass=False)
    band_scans: list[tuple[BandScan, ScanMeta]] = []
    for scan_pass in scan.successful_passes:
        band_scan = scan_pass.band(band)
        if band_scan is not None:
            band_scans.append((band_scan, scan_pass.meta))
    if not band_scans:
        return BandUsage(status=None, usable_passes=(), cac_active_in_every_pass=False)
    cac = [band is Band.GHZ_5 and meta.dfs_cac_5g == CAC_ACTIVE for _, meta in band_scans]
    usable = tuple(b for (b, _), in_cac in zip(band_scans, cac, strict=True) if b.readings and not in_cac)
    if usable:
        return BandUsage(status=BandScanStatus.OK, usable_passes=usable, cac_active_in_every_pass=False)
    if all(cac):
        return BandUsage(status=None, usable_passes=(), cac_active_in_every_pass=True)
    statuses = [b.status for b, _ in band_scans]
    if any(s in (BandScanStatus.OK, BandScanStatus.EMPTY) for s in statuses):
        return BandUsage(status=BandScanStatus.EMPTY, usable_passes=(), cac_active_in_every_pass=False)
    return BandUsage(status=statuses[-1], usable_passes=(), cac_active_in_every_pass=False)


def _effective_tx(ap: AccessPoint, band: Band) -> int | None:
    stats = ap.stats(band)
    return stats.observed_tx_dbm if stats is not None else None


def _in_cac(ap: AccessPoint, band: Band) -> bool:
    stats = ap.stats(band)
    return stats is not None and stats.state == DFS_WAIT_STATE


def _primary_frequency(ap: AccessPoint, band: Band) -> int | None:
    """None without statistics: the aggregation then falls back to the frequency a majority of readings saw."""
    stats = ap.stats(band)
    return center_frequency_or_none(band, stats.channel) if stats is not None else None


def _on_dfs_channel(ap: AccessPoint, band: Band) -> bool:
    stats = ap.stats(band)
    return band is Band.GHZ_5 and stats is not None and stats.channel in DFS_CHANNELS_5G


def _heard_any_dfs(usage: BandUsage) -> bool:
    for band_scan in usage.usable_passes:
        for reading in band_scan.readings:
            if reading.frequency_mhz is None:
                continue
            if channel_from_frequency(Band.GHZ_5, reading.frequency_mhz) in DFS_CHANNELS_5G:
                return True
    return False


def _readings_of(usage: BandUsage, bssids: frozenset[Mac]) -> list[Sighting]:
    return [
        Sighting(reading.rssi_dbm, reading.frequency_mhz)
        for band_scan in usage.usable_passes
        for reading in band_scan.readings
        if reading.bssid in bssids
    ]


def measured(
    subject: AccessPoint, peer: AccessPoint, band: Band, peer_usage: BandUsage, bssids: BssidIndex
) -> tuple[int | None, int]:
    """(median RSSI of `subject` at `peer`, number of readings that counted) from the peer's usable passes."""
    sightings = _readings_of(peer_usage, bssids.bssids_of(subject.mac, band))
    frequency = _primary_frequency(subject, band)
    return aggregate_rssi(sightings, frequency), len(consensus_readings(sightings, frequency))


def missing_reason(
    subject: AccessPoint | None,
    peer: AccessPoint | None,
    band: Band,
    peer_usage: BandUsage,
    scan_skipped: bool,
) -> MissingReason:
    """The most fundamental reason the cell has no reading (the priority order of `MissingReason`)."""
    if scan_skipped:
        return MissingReason.SCAN_SKIPPED
    if subject is None:
        return MissingReason.PEER_UNKNOWN
    if subject.offline:
        return MissingReason.SELF_OFFLINE
    if peer is None:
        return MissingReason.PEER_UNKNOWN
    if peer.offline:
        return MissingReason.PEER_OFFLINE
    if _in_cac(subject, band):
        return MissingReason.SELF_DFS_WAIT
    if peer_usage.cac_active_in_every_pass or _in_cac(peer, band):
        return MissingReason.PEER_DFS_WAIT
    if peer_usage.status is BandScanStatus.NO_RADIO:
        return MissingReason.PEER_NO_RADIO
    if peer_usage.status is None:
        return MissingReason.PEER_SCAN_FAILED
    if peer_usage.status is BandScanStatus.INTERFACE_DOWN:
        return MissingReason.PEER_INTERFACE_DOWN
    if peer_usage.status is BandScanStatus.FAILED:
        return MissingReason.PEER_SCAN_FAILED
    if peer_usage.status is BandScanStatus.EMPTY:
        return MissingReason.PEER_SCAN_EMPTY
    if _on_dfs_channel(subject, band) and not _heard_any_dfs(peer_usage):
        return MissingReason.NO_DFS_EVIDENCE
    return MissingReason.NOT_SIGHTED


@dataclass(frozen=True, slots=True, kw_only=True)
class NeighbourMatrix:
    """`cells[(ap_name, band)]` lists the subject's configured peers on that band in configuration order;
    `neighbours` is the symmetrised adjacency the cells were built from."""

    cells: Mapping[tuple[str, Band], tuple[PeerReading, ...]]
    neighbours: Mapping[str, frozenset[str]]

    def of(self, ap_name: str, band: Band) -> tuple[PeerReading, ...]:
        return self.cells.get((ap_name, band), ())


def peers_on_band(peers: Iterable[str], aps_by_name: Mapping[str, AccessPoint], band: Band) -> tuple[str, ...]:
    """Configured peers minus those the controller knows (any state) and reports without a radio on the band;
    unknown and unparsable peers stay, so they can block what they should block."""
    kept: list[str] = []
    for peer in peers:
        ap = aps_by_name.get(peer)
        if ap is not None and ap.radio(band) is None:
            continue
        kept.append(peer)
    return tuple(kept)


def build_matrix(
    snapshot: SiteSnapshot,
    scan: SiteScan | None,
    neighbours: Mapping[str, Iterable[str]],
    scan_skipped: bool,
) -> NeighbourMatrix:
    aps_by_name: dict[str, AccessPoint] = {}
    for ap in snapshot.access_points:
        aps_by_name.setdefault(ap.name, ap)
    bssids = snapshot.bssids
    adjacency = symmetric_neighbours(neighbours)
    usage: dict[tuple[str, Band], BandUsage] = {}
    for name, ap in aps_by_name.items():
        ap_scan = scan.scan_of(ap.mac) if scan is not None else None
        for band in EVALUATED_BANDS:
            usage[(name, band)] = reduce_band_passes(ap_scan, band)
    direct: dict[tuple[str, str, Band], tuple[int | None, int]] = {}
    for name, peers in adjacency.items():
        subject = aps_by_name.get(name)
        for band in EVALUATED_BANDS:
            for peer_name in peers_on_band(sorted(peers), aps_by_name, band):
                peer = aps_by_name.get(peer_name)
                if subject is None or peer is None or scan_skipped:
                    direct[(name, peer_name, band)] = (None, 0)
                    continue
                direct[(name, peer_name, band)] = measured(subject, peer, band, usage[(peer_name, band)], bssids)
    cells: dict[tuple[str, Band], tuple[PeerReading, ...]] = {}
    for name, peers in adjacency.items():
        subject = aps_by_name.get(name)
        for band in EVALUATED_BANDS:
            rows: list[PeerReading] = []
            for peer_name in peers_on_band(sorted(peers), aps_by_name, band):
                peer = aps_by_name.get(peer_name)
                value, samples = direct[(name, peer_name, band)]
                if value is not None:
                    rows.append(
                        PeerReading(
                            peer=peer_name,
                            band=band,
                            rssi_dbm=value,
                            source=ReadingSource.MEASURED,
                            samples=samples,
                            reason=None,
                            receiver_offset_db=_receiver_offset(subject, peer, band, value, direct),
                        )
                    )
                    continue
                no_usage = BandUsage(status=None, usable_passes=(), cac_active_in_every_pass=False)
                reason = missing_reason(subject, peer, band, usage.get((peer_name, band), no_usage), scan_skipped)
                predicted = _reciprocal(subject, peer, band, reason, direct)
                reverse_value, _ = direct.get((peer_name, name, band), (None, 0))
                reverse_reason = None
                if reverse_value is None:
                    reverse_reason = missing_reason(
                        peer, subject, band, usage.get((name, band), no_usage), scan_skipped
                    )
                rows.append(
                    PeerReading(
                        peer=peer_name,
                        band=band,
                        rssi_dbm=predicted,
                        source=ReadingSource.RECIPROCITY if predicted is not None else None,
                        samples=0,
                        reason=reason,
                        reverse_reason=reverse_reason,
                    )
                )
            cells[(name, band)] = tuple(rows)
    return NeighbourMatrix(cells=cells, neighbours=adjacency)


def _reciprocal(
    subject: AccessPoint | None,
    peer: AccessPoint | None,
    band: Band,
    reason: MissingReason,
    direct: Mapping[tuple[str, str, Band], tuple[int | None, int]],
) -> int | None:
    if subject is None or peer is None or reason in NOT_RECIPROCITY_ELIGIBLE:
        return None
    reverse, _ = direct.get((peer.name, subject.name, band), (None, 0))
    tx_subject, tx_peer = _effective_tx(subject, band), _effective_tx(peer, band)
    if reverse is None or tx_subject is None or tx_peer is None:
        return None
    return predict_reverse_rssi(reverse, tx_subject, tx_peer)


def _receiver_offset(
    subject: AccessPoint | None,
    peer: AccessPoint | None,
    band: Band,
    forward: int,
    direct: Mapping[tuple[str, str, Band], tuple[int | None, int]],
) -> int | None:
    if subject is None or peer is None:
        return None
    reverse, _ = direct.get((peer.name, subject.name, band), (None, 0))
    tx_subject, tx_peer = _effective_tx(subject, band), _effective_tx(peer, band)
    if reverse is None or tx_subject is None or tx_peer is None:
        return None
    return forward - reverse - (tx_subject - tx_peer)


def notable_receiver_offset(cell: PeerReading) -> bool:
    """An offset the two receivers cannot both hide inside their own measurement tolerance."""
    return cell.receiver_offset_db is not None and abs(cell.receiver_offset_db) >= RCPI_ACCURACY_DB


def heard_graph_edges(
    snapshot: SiteSnapshot, scan: SiteScan | None, threshold_dbm: int
) -> dict[Band, frozenset[frozenset[str]]]:
    """Own-AP pairs (configured or not) with a median reading at or above `threshold_dbm` in either direction,
    aggregated like the matrix (median on the subject's primary frequency) — never a single-pass maximum."""
    aps_by_name: dict[str, AccessPoint] = {}
    for ap in snapshot.access_points:
        aps_by_name.setdefault(ap.name, ap)
    bssids = snapshot.bssids
    edges: dict[Band, set[frozenset[str]]] = {band: set() for band in EVALUATED_BANDS}
    for band in EVALUATED_BANDS:
        usage = {
            name: reduce_band_passes(scan.scan_of(ap.mac) if scan is not None else None, band)
            for name, ap in aps_by_name.items()
        }
        for subject_name, subject in aps_by_name.items():
            for peer_name, peer in aps_by_name.items():
                if peer_name == subject_name:
                    continue
                value, _ = measured(subject, peer, band, usage[peer_name], bssids)
                if value is not None and value >= threshold_dbm:
                    edges[band].add(frozenset({subject_name, peer_name}))
    return {band: frozenset(pairs) for band, pairs in edges.items()}
