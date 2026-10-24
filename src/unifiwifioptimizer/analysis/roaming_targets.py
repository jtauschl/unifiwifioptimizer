"""Roaming Assistant (Handoff Suggestions) target per WLAN (docs/ALGORITHM.md §7).

The threshold is a WLAN-level setting on the controller, so it is aggregated over the access points that
broadcast the WLAN: every broadcasting AP gets its own threshold from the weakest reading its SSID peers
(configured neighbours that also broadcast the WLAN) took of it, and the WLAN's target is the minimum, held
inside the range the controller accepts — no AP is judged more optimistically than its own coverage allows.
Incomplete data never produces a silently optimistic value: a missing peer reading marks the WLAN incomplete
and passes no threshold on.
"""

from collections.abc import Mapping
from dataclasses import dataclass

from unifiwifioptimizer.analysis.neighbors import NeighbourMatrix, PeerReading
from unifiwifioptimizer.domain.analysis import ReadingSource, RoamingCap, WlanRoamingStatus
from unifiwifioptimizer.domain.models import AccessPoint, Band, SiteSnapshot, WlanConfig
from unifiwifioptimizer.rf.constants import (
    ROAMING_ASSISTANT_MAX_DBM,
    ROAMING_ASSISTANT_MIN_DBM,
    ROAMING_ASSISTANT_SUGGESTED_BELOW_DBM,
)
from unifiwifioptimizer.rf.corridor import Corridor
from unifiwifioptimizer.rf.roaming import RoamingRecommendation, recommend_roaming
from unifiwifioptimizer.rf.settings import RfSettings

ALL_APS = "all"


@dataclass(frozen=True, slots=True, kw_only=True)
class ApRoamingDetail:
    """One broadcasting access point's own threshold and what bounded it."""

    ap: str
    weakest_peer: str
    weakest_rssi_dbm: int
    source: ReadingSource
    recommendation: RoamingRecommendation
    assumed_client_tx_dbm: int | None = None

    @property
    def cap(self) -> RoamingCap:
        return self.recommendation.cap


@dataclass(frozen=True, slots=True, kw_only=True)
class WlanRoamingTarget:
    wlan: str
    status: WlanRoamingStatus
    # The uplink value to configure, present only when the status is OK.
    threshold_dbm: int | None
    # The derived value when it lies outside what the controller accepts and `threshold_dbm` was moved to the limit.
    derived_dbm: int | None = None
    reasons: tuple[str, ...]
    # Every AP whose own threshold equals the WLAN's minimum, sorted by name.
    limiting: tuple[str, ...]
    per_ap: tuple[ApRoamingDetail, ...]
    broadcasting: tuple[str, ...]


def broadcasting_aps(wlan: WlanConfig, snapshot: SiteSnapshot) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """(names of the APs that broadcast the WLAN, incomplete reasons). `ap_group_mode: all` means every access
    point of the site; any other mode resolves the WLAN's AP groups to their device MACs."""
    by_mac = {ap.mac: ap.name for ap in snapshot.access_points}
    if wlan.ap_group_mode == ALL_APS or (wlan.ap_group_mode is None and not wlan.ap_group_ids):
        return tuple(sorted(by_mac.values())), ()
    groups = {g.id: g for g in snapshot.ap_groups}
    names: set[str] = set()
    reasons: list[str] = []
    seen_macs: set[str] = set()
    for group_id in wlan.ap_group_ids:
        group = groups.get(group_id)
        if group is None:
            reasons.append(f"AP group {group_id} referenced by this WLAN could not be resolved")
            continue
        for mac in sorted(group.device_macs):
            if mac in seen_macs:
                continue
            seen_macs.add(mac)
            name = by_mac.get(mac)
            if name is None:
                reasons.append(f"broadcasting access point {mac} is not among the site's access points")
            else:
                names.add(name)
    return tuple(sorted(names)), tuple(reasons)


def _tx_eff(ap: AccessPoint) -> int | None:
    stats = ap.stats(Band.GHZ_5)
    return stats.observed_tx_dbm if stats is not None else None


@dataclass(frozen=True, slots=True)
class _Weakest:
    rssi_dbm: int
    peer: str
    source: ReadingSource


def _weakest(cells: tuple[PeerReading, ...], ssid_peers: set[str]) -> tuple[_Weakest | None, list[PeerReading]]:
    """(weakest evaluable cell among the SSID peers, SSID-peer cells without a value)."""
    relevant = [c for c in cells if c.peer in ssid_peers]
    missing = [c for c in relevant if c.rssi_dbm is None]
    evaluable = [
        _Weakest(c.rssi_dbm, c.peer, c.source) for c in relevant if c.rssi_dbm is not None and c.source is not None
    ]
    if not evaluable:
        return None, missing
    return min(evaluable, key=lambda w: (w.rssi_dbm, w.peer)), missing


def roaming_target(
    wlan: WlanConfig, snapshot: SiteSnapshot, matrix: NeighbourMatrix, corridor_5g: Corridor, rf: RfSettings
) -> WlanRoamingTarget | None:
    """None for a WLAN without the controller field (older API; the compliance check reports that itself)."""
    if Band.GHZ_5 not in wlan.bands:
        return WlanRoamingTarget(
            wlan=wlan.name,
            status=WlanRoamingStatus.NOT_APPLICABLE_NO_5G,
            threshold_dbm=None,
            reasons=("5 GHz not broadcast",),
            limiting=(),
            per_ap=(),
            broadcasting=(),
        )
    if wlan.roaming_assistant_na_enabled is None and wlan.roaming_assistant_na_rssi is None:
        return None
    broadcasting, reasons = broadcasting_aps(wlan, snapshot)
    if len(broadcasting) == 1 and not reasons:
        return WlanRoamingTarget(
            wlan=wlan.name,
            status=WlanRoamingStatus.NOT_APPLICABLE_SINGLE_AP,
            threshold_dbm=None,
            reasons=("no handoff target: only one access point broadcasts this WLAN",),
            limiting=(),
            per_ap=(),
            broadcasting=broadcasting,
        )
    aps_by_name = {ap.name: ap for ap in snapshot.access_points}
    incomplete = list(reasons)
    details: list[ApRoamingDetail] = []
    for name in broadcasting:
        ap = aps_by_name[name]
        if ap.offline:
            continue
        ssid_peers = {
            p for p in matrix.neighbours.get(name, frozenset()) if p in broadcasting and not aps_by_name[p].offline
        }
        if not ssid_peers:
            incomplete.append(f"{name} has no configured neighbour broadcasting this WLAN")
            continue
        weakest, missing = _weakest(matrix.of(name, Band.GHZ_5), ssid_peers)
        if missing:
            for cell in missing:
                incomplete.append(f"{name}: no reading of neighbour {cell.peer} ({cell.why.words})")
            continue
        tx_eff = _tx_eff(ap)
        if weakest is None or tx_eff is None:
            incomplete.append(f"{name}: no effective 5 GHz power reported")
            continue
        stats = ap.stats(Band.GHZ_5)
        assumed_client_tx = rf.client_tx_assumption(
            Band.GHZ_5, stats.channel if stats is not None else None, stats.width_mhz if stats is not None else None
        )
        recommendation = recommend_roaming(corridor_5g, weakest.rssi_dbm, tx_eff, assumed_client_tx, rf.roaming)
        details.append(
            ApRoamingDetail(
                ap=name,
                weakest_peer=weakest.peer,
                weakest_rssi_dbm=weakest.rssi_dbm,
                source=weakest.source,
                recommendation=recommendation,
                assumed_client_tx_dbm=assumed_client_tx if rf.client_tx_dbm_5g_upper is not None else None,
            )
        )
    if not details or incomplete:
        return WlanRoamingTarget(
            wlan=wlan.name,
            status=WlanRoamingStatus.INCOMPLETE,
            threshold_dbm=None,
            reasons=tuple(incomplete) if incomplete else ("no broadcasting access point could be evaluated",),
            limiting=(),
            per_ap=tuple(details),
            broadcasting=broadcasting,
        )
    minimum = min(d.recommendation.uplink_dbm for d in details)
    settable = min(max(minimum, ROAMING_ASSISTANT_MIN_DBM), ROAMING_ASSISTANT_MAX_DBM)
    limiting = tuple(sorted(d.ap for d in details if d.recommendation.uplink_dbm == minimum))
    return WlanRoamingTarget(
        wlan=wlan.name,
        status=WlanRoamingStatus.OK,
        threshold_dbm=settable,
        derived_dbm=minimum if settable != minimum else None,
        reasons=(),
        limiting=limiting,
        per_ap=tuple(details),
        broadcasting=broadcasting,
    )


def roaming_targets(
    snapshot: SiteSnapshot, matrix: NeighbourMatrix, corridor_5g: Corridor, rf: RfSettings
) -> dict[str, WlanRoamingTarget]:
    """Targets by WLAN name for every WLAN the controller reports with the roaming-assistant field; a WLAN
    name shared by two WLANs keeps the first (the compliance engine reports the ambiguity)."""
    targets: dict[str, WlanRoamingTarget] = {}
    for wlan in snapshot.wlans:
        if wlan.name in targets:
            continue
        target = roaming_target(wlan, snapshot, matrix, corridor_5g, rf)
        if target is not None:
            targets[wlan.name] = target
    return targets


def thresholds_for_compliance(targets: Mapping[str, WlanRoamingTarget]) -> dict[str, int]:
    """Only an OK target carries a value into the compliance check."""
    return {
        name: target.threshold_dbm
        for name, target in targets.items()
        if target.status is WlanRoamingStatus.OK and target.threshold_dbm is not None
    }


def threshold_above_guidance(target: WlanRoamingTarget) -> bool:
    """True when the value to set is not below the one Ubiquiti suggests for Handoff Suggestions."""
    return (
        target.status is WlanRoamingStatus.OK
        and target.threshold_dbm is not None
        and target.threshold_dbm >= ROAMING_ASSISTANT_SUGGESTED_BELOW_DBM
    )


def downlink_trigger_for(target: WlanRoamingTarget | None, ap_name: str) -> int | None:
    """Where the WLAN's threshold fires at `ap_name`, on the downlink, for the Min-RSSI ordering advisory.

    The controller applies one uplink value per WLAN (the minimum over its access points, held inside the range
    the controller accepts), so an access point whose own derived value lies above it fires at a weaker downlink
    signal than derived, and one whose derived value lies below the range fires at a stronger one. Only an OK
    target has a threshold."""
    if target is None or target.status is not WlanRoamingStatus.OK or target.threshold_dbm is None:
        return None
    for detail in target.per_ap:
        if detail.ap == ap_name:
            own = detail.recommendation
            return target.threshold_dbm + (own.downlink_dbm - own.uplink_dbm)
    return None
