"""One site, analysed: the snapshot and the scans become a `SiteReport` (plan OP#2881 §2.2 site_analyzer).

Pure orchestration over the other analysis modules. Access points come in the operator's configuration
order (every name of a neighbour pair, then the rest of the site); an offline access point gets one line
and no bands; the scan-status findings of §2.4 and the partial reasons of §2.5 are derived here.
"""

from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace

from unifiwifioptimizer.analysis.airtime import airtime_of
from unifiwifioptimizer.analysis.channels import ChannelAnalysis, analyse_channels, foreign_networks, geometry_of
from unifiwifioptimizer.analysis.clients import clients_of, unassignable, unassignable_finding
from unifiwifioptimizer.analysis.groups import group_reports
from unifiwifioptimizer.analysis.inputs import SiteAnalysisInput
from unifiwifioptimizer.analysis.minrssi import min_rssi_before_roaming, recommend_band_min_rssi
from unifiwifioptimizer.analysis.neighbors import (
    EVALUATED_BANDS,
    NeighbourMatrix,
    PeerReading,
    asymmetric_pairs,
    build_matrix,
    notable_receiver_offset,
    reduce_band_passes,
    symmetric_neighbours,
)
from unifiwifioptimizer.analysis.roaming_targets import (
    WlanRoamingTarget,
    downlink_trigger_for,
    roaming_targets,
    thresholds_for_compliance,
)
from unifiwifioptimizer.analysis.txpower import BandTxResult, analyse_band_tx, apply_mesh_guard
from unifiwifioptimizer.compliance.engine import evaluate_site
from unifiwifioptimizer.domain.analysis import BandTxOutcome, NeighbourMarker, PartialReason
from unifiwifioptimizer.domain.models import AccessPoint, Band, DeviceState, Mac, SiteSnapshot
from unifiwifioptimizer.domain.report import (
    TX_POWER,
    AirtimeReport,
    ApReport,
    BandReport,
    ClientReport,
    CorridorSummary,
    EnvironmentSummary,
    Finding,
    ForeignReport,
    NeighbourRow,
    Recommendation,
    RfSummary,
    RoamingApDetail,
    ScanSummary,
    Severity,
    SiteReport,
    TxSummaryReport,
    WlanRoamingSummary,
)
from unifiwifioptimizer.domain.scan import BandScanStatus, ScanFailure, ScanFailureKind, SiteScan
from unifiwifioptimizer.rf.channels import DFS_CHANNELS_5G, cac_seconds
from unifiwifioptimizer.rf.corridor import Corridor, corridor_for

WIRELESS_UPLINK = "wireless"
HOST_KEY_KINDS = frozenset({ScanFailureKind.HOST_KEY_UNKNOWN, ScanFailureKind.HOST_KEY_MISMATCH})
# A failure of these kinds happened after the host key matched: one such pass verifies the access point.
VERIFIED_FAILURE_KINDS = frozenset(
    {
        ScanFailureKind.AUTHENTICATION,
        ScanFailureKind.REMOTE_SCRIPT,
        ScanFailureKind.UNPARSABLE_OUTPUT,
        ScanFailureKind.OUTPUT_TOO_LARGE,
    }
)
STATS_PATH_MARKER = ".radio_table_stats"


def _finding(
    severity: Severity, code: str, subject: str, message: str, band: Band | None = None, peers: Iterable[str] = ()
) -> Finding:
    return Finding(severity=severity, code=code, message=message, subject=subject, band=band, peers=tuple(peers))


def ap_order(neighbours: Mapping[str, Iterable[str]], snapshot: SiteSnapshot) -> list[str]:
    """Configured names in configuration order (every name of a pair), then the site's other access points."""
    names: list[str] = []
    for lister, peers in neighbours.items():
        for name in (lister, *sorted(peers)):
            if name not in names:
                names.append(name)
    for access_point in snapshot.access_points:
        if access_point.name not in names:
            names.append(access_point.name)
    return names


@dataclass(frozen=True, slots=True)
class MeshRoles:
    children: frozenset[str]
    parents: frozenset[str]
    unresolved_children: frozenset[str]


def mesh_roles(snapshot: SiteSnapshot) -> MeshRoles:
    """Access points on a wireless uplink and their parents (resolved by device MAC or BSSID)."""
    by_mac: dict[Mac, str] = {ap.mac: ap.name for ap in snapshot.access_points}
    bssids = snapshot.bssids
    children: set[str] = set()
    parents: set[str] = set()
    unresolved: set[str] = set()
    for ap in snapshot.access_points:
        if ap.uplink_type != WIRELESS_UPLINK:
            continue
        children.add(ap.name)
        parent = by_mac.get(ap.uplink_mac) if ap.uplink_mac is not None else None
        if parent is None and ap.uplink_mac is not None:
            hit = bssids.lookup(ap.uplink_mac)
            parent = by_mac.get(hit[0]) if hit is not None else None
        if parent is None:
            unresolved.add(ap.name)
        else:
            parents.add(parent)
    return MeshRoles(
        children=frozenset(children), parents=frozenset(parents), unresolved_children=frozenset(unresolved)
    )


def _tx_summary(result: BandTxResult) -> TxSummaryReport:
    s = result.summary
    return TxSummaryReport(
        effective_dbm=s.effective_dbm,
        configured_dbm=s.configured_dbm,
        mode=s.mode,
        min_dbm=s.min_dbm,
        max_dbm=s.max_dbm,
        effective_max_dbm=s.effective_max_dbm,
        effective_max_verified=s.effective_max_verified,
    )


def _rows(cells: tuple[PeerReading, ...], markers: Mapping[str, NeighbourMarker]) -> tuple[NeighbourRow, ...]:
    return tuple(
        NeighbourRow(
            peer=c.peer,
            rssi_dbm=c.rssi_dbm,
            source=c.source,
            samples=c.samples,
            reason=c.reason,
            marker=markers.get(c.peer),
            receiver_offset_db=c.receiver_offset_db,
        )
        for c in cells
    )


def _band_scan_findings(
    ap: AccessPoint, band: Band, scan: SiteScan | None, configured: bool, partial: list[PartialReason]
) -> tuple[Finding, ...]:
    """§2.4: what the access point's own scan said about this band."""
    if scan is None or not configured or ap.offline:
        return ()
    ap_scan = scan.scan_of(ap.mac)
    if ap_scan is None or not ap_scan.successful_passes:
        return ()
    usage = reduce_band_passes(ap_scan, band)
    if usage.status is BandScanStatus.EMPTY:
        partial.append(PartialReason.BAND_EMPTY)
        return (
            _finding(
                Severity.WARNING,
                "radio_restart_suggested",
                ap.name,
                "the scan saw nothing on this band; restart the radio or the access point before trusting any "
                "conclusion",
                band,
            ),
        )
    if usage.status is BandScanStatus.FAILED:
        partial.append(PartialReason.BAND_FAILED)
        return (_finding(Severity.WARNING, "scan_unusable", ap.name, "every scan attempt on this band failed", band),)
    if usage.status is BandScanStatus.INTERFACE_DOWN:
        partial.append(PartialReason.INTERFACE_DOWN)
        return (
            _finding(
                Severity.WARNING,
                "scan_unusable",
                ap.name,
                "the scan interface is down and `scan_interface_toggle` is off; enable it to scan this band",
                band,
            ),
        )
    if usage.status is BandScanStatus.NO_RADIO and ap.radio(band) is not None:
        partial.append(PartialReason.BAND_FAILED)
        return (
            _finding(
                Severity.WARNING,
                "scan_unusable",
                ap.name,
                "the access point found no scan interface for this band",
                band,
            ),
        )
    return ()


def _scan_summary(
    scan: SiteScan | None, passes: int, skipped: bool, names: Iterable[str]
) -> tuple[ScanSummary, int, int, list[Finding], list[PartialReason]]:
    """The summary plus the verifiable count, the host-key failed count, AP-level findings and partial reasons."""
    failures: dict[str, tuple[ScanFailureKind, ...]] = {}
    successes: dict[str, int] = {}
    findings: list[Finding] = []
    partial: list[PartialReason] = []
    verifiable = 0
    host_key_failed = 0
    if scan is not None:
        for ap_scan in scan.scans:
            kinds = tuple(p.kind for p in ap_scan.passes if isinstance(p, ScanFailure))
            ok = len(ap_scan.successful_passes)
            failures[ap_scan.ap_name] = kinds
            successes[ap_scan.ap_name] = ok
            if any(k in HOST_KEY_KINDS for k in kinds):
                host_key_failed += 1
            if ok > 0 or any(k in VERIFIED_FAILURE_KINDS for k in kinds):
                verifiable += 1
            if kinds and ok == 0:
                partial.append(PartialReason.SCAN_FAILED)
                findings.append(
                    _finding(
                        Severity.WARNING,
                        "scan_failed",
                        ap_scan.ap_name,
                        "every scan pass failed: " + ", ".join(sorted({k.value for k in kinds})),
                    )
                )
            elif kinds:
                findings.append(
                    _finding(
                        Severity.INFO,
                        "scan_partial",
                        ap_scan.ap_name,
                        f"{len(kinds)} of {len(ap_scan.passes)} passes failed "
                        f"({', '.join(sorted({k.value for k in kinds}))}); "
                        "the readings come from the successful passes",
                    )
                )
    summary = ScanSummary(
        passes=passes,
        scanned=tuple(s.ap_name for s in scan.scans) if scan is not None else (),
        unknown_names=tuple(names),
        failures_by_ap=failures,
        successes_by_ap=successes,
        skipped=skipped,
    )
    return summary, verifiable, host_key_failed, findings, partial


def _roaming_summary(target: WlanRoamingTarget, pending_5g: frozenset[str]) -> WlanRoamingSummary:
    return WlanRoamingSummary(
        wlan=target.wlan,
        status=target.status,
        threshold_dbm=target.threshold_dbm,
        reasons=target.reasons,
        limiting=target.limiting,
        broadcasting=target.broadcasting,
        per_ap=tuple(
            RoamingApDetail(
                ap=d.ap,
                weakest_peer=d.weakest_peer,
                weakest_rssi_dbm=d.weakest_rssi_dbm,
                source=d.source,
                downlink_dbm=d.recommendation.downlink_dbm,
                uplink_dbm=d.recommendation.uplink_dbm,
                cap=d.recommendation.cap,
                raw_cap_dbm=d.recommendation.raw_cap_dbm,
            )
            for d in target.per_ap
        ),
        tx_change_pending=any(name in pending_5g for name in target.broadcasting),
    )


def _roaming_trigger(targets: Mapping[str, WlanRoamingTarget], ap_name: str) -> int | None:
    """The lowest client-side trigger derived for `ap_name` over the WLANs it broadcasts."""
    triggers = [t for t in (downlink_trigger_for(target, ap_name) for target in targets.values()) if t is not None]
    return min(triggers) if triggers else None


def _band_report(
    ap: AccessPoint,
    band: Band,
    inp: SiteAnalysisInput,
    matrix: NeighbourMatrix,
    corridor: Corridor,
    channels: ChannelAnalysis,
    targets: Mapping[str, WlanRoamingTarget],
    roles: MeshRoles,
    configured: bool,
    partial: list[PartialReason],
    offsets_reported: set[tuple[frozenset[str], Band]],
) -> BandReport:
    cells = matrix.of(ap.name, band)
    tx = analyse_band_tx(ap, band, cells, corridor, inp.scan_skipped)
    if ap.name in roles.children or ap.name in roles.parents:
        tx = apply_mesh_guard(ap, band, tx)
    findings: list[Finding] = list(tx.findings)
    recommendations: list[Recommendation] = [tx.recommendation] if tx.recommendation is not None else []
    for cell in cells:
        # One pair, one line: the first access point of the pair in report order carries it.
        pair = (frozenset({ap.name, cell.peer}), band)
        if notable_receiver_offset(cell) and cell.receiver_offset_db is not None and pair not in offsets_reported:
            offsets_reported.add(pair)
            findings.append(
                _finding(
                    Severity.INFO,
                    "receiver_offset",
                    ap.name,
                    f"{ap.name} and {cell.peer} disagree by {cell.receiver_offset_db} dB after the power "
                    "difference; one receiver reads the other's beacons systematically off",
                    band,
                    (cell.peer,),
                )
            )
    findings.extend(f for f in channels.findings if f.subject == ap.name and f.band is band)
    findings.extend(_band_scan_findings(ap, band, inp.scan, configured, partial))
    clients_report: ClientReport | None = None
    tx_eff = tx.summary.effective_dbm
    judged = tx.outcome not in (BandTxOutcome.OFFLINE, BandTxOutcome.DFS_WAIT, BandTxOutcome.SCAN_SKIPPED)
    if cells and tx_eff is not None and judged:
        min_rssi = recommend_band_min_rssi(ap, band, corridor, tx_eff, inp.rf)
        recommendations.append(min_rssi)
        advisory = min_rssi_before_roaming(
            ap, band, min_rssi, _roaming_trigger(targets, ap.name), corridor, inp.rf, tx.coverage_gap
        )
        if advisory is not None:
            findings.append(advisory)
        if inp.snapshot.clients is not None:
            summary = clients_of(ap.mac, band, inp.snapshot.clients, min_rssi.recommended)
            if summary is not None:
                clients_report = ClientReport(
                    total=summary.total,
                    below_min_rssi=summary.below_min_rssi,
                    weakest_dbm=summary.weakest_dbm,
                    min_rssi_dbm=min_rssi.recommended,
                )
    airtime = airtime_of(ap, band)
    foreign = foreign_networks(ap, band, inp.scan, inp.snapshot)
    geometry = geometry_of(ap, band)
    stats = ap.stats(band)
    dfs = band is Band.GHZ_5 and stats is not None and stats.channel in DFS_CHANNELS_5G
    cac: int | None = None
    if dfs and stats is not None:
        try:
            cac = cac_seconds(stats.channel, stats.width_mhz)
        except ValueError:
            cac = None
    return BandReport(
        band=band,
        channel=geometry.channel if geometry is not None else None,
        width_mhz=geometry.width_mhz if geometry is not None else None,
        extension_channel=geometry.extension_channel if geometry is not None else None,
        channel_auto=geometry.auto if geometry is not None else False,
        configured_channel=geometry.configured_channel if geometry is not None else None,
        dfs=dfs,
        cac_seconds=cac,
        tx=_tx_summary(tx),
        outcome=tx.outcome,
        weakest_dbm=tx.weakest_dbm,
        neighbours=_rows(cells, tx.markers),
        findings=tuple(findings),
        recommendations=tuple(recommendations),
        airtime=AirtimeReport(
            utilisation_pct=airtime.utilisation_pct,
            self_rx_pct=airtime.self_rx_pct,
            self_tx_pct=airtime.self_tx_pct,
            tx_retries_pct=airtime.tx_retries_pct,
            satisfaction_pct=airtime.satisfaction_pct,
            client_count=airtime.client_count,
        )
        if airtime is not None
        else None,
        clients=clients_report,
        foreign=ForeignReport(
            count=foreign.count, strongest_dbm=foreign.strongest_dbm, overlapping_count=foreign.overlapping_count
        )
        if foreign is not None
        else None,
    )


def _without_shared_names(
    snapshot: SiteSnapshot, partial: list[PartialReason], findings: list[Finding]
) -> tuple[SiteSnapshot, frozenset[str]]:
    """Every analysis map keys by name, so access points that share one are taken out before anything is
    built — named, with their MACs, as an error and a partial reason, never dropped in silence."""
    counts = Counter(ap.name for ap in snapshot.access_points)
    shared = frozenset(name for name, count in counts.items() if count > 1)
    for name in sorted(shared):
        macs = sorted(ap.mac for ap in snapshot.access_points if ap.name == name)
        partial.append(PartialReason.AP_NAME_DUPLICATE)
        findings.append(
            _finding(
                Severity.ERROR,
                "ap_name_duplicate",
                name,
                f"{len(macs)} access points share this name ({', '.join(macs)}); none of them is analysed — "
                "rename them",
            )
        )
    if not shared:
        return snapshot, shared
    return replace(snapshot, access_points=tuple(ap for ap in snapshot.access_points if ap.name not in shared)), shared


def analyze_site(inp: SiteAnalysisInput) -> SiteReport:
    partial: list[PartialReason] = []
    site_findings: list[Finding] = []
    snapshot, shared_names = _without_shared_names(inp.snapshot, partial, site_findings)
    scan = inp.scan
    adjacency = symmetric_neighbours(inp.neighbours)
    matrix = build_matrix(snapshot, scan, inp.neighbours, inp.scan_skipped)
    corridors = {band: corridor_for(band, inp.environment, inp.rf.cell_edge) for band in EVALUATED_BANDS}
    channels = analyse_channels(snapshot, scan, inp.neighbours, snapshot.settings.channel_ai)
    targets = roaming_targets(snapshot, matrix, corridors[Band.GHZ_5], inp.rf)
    compliance = evaluate_site(snapshot.wlans, inp.wlan_profiles, inp.profiles, thresholds_for_compliance(targets))
    roles = mesh_roles(snapshot)
    aps_by_name = {ap.name: ap for ap in snapshot.access_points}
    unparsable_names = {d.name for d in snapshot.unparsable_devices if d.name is not None}
    configured_names = set(adjacency)
    if inp.scan_skipped:
        site_findings.append(
            _finding(
                Severity.INFO,
                "scan_skipped",
                snapshot.site.id,
                "neighbour scans skipped; every scan-dependent block is left out",
            )
        )
    for lister, peer in asymmetric_pairs(inp.neighbours):
        if lister not in aps_by_name or peer not in aps_by_name:
            continue
        site_findings.append(
            _finding(
                Severity.ADVISORY, "neighbours_asymmetric", lister,
                f"lists {peer} as a neighbour, which does not list it back; both directions are evaluated",
                None, (peer,),
            )
        )  # fmt: skip
    for device in snapshot.unparsable_devices:
        label = device.name or device.mac or "unknown device"
        partial.append(PartialReason.AP_UNPARSABLE)
        site_findings.append(_finding(Severity.WARNING, "ap_unparsable", label, f"not usable: {device.reason}"))
    unknown_names: list[str] = []
    for name in ap_order(inp.neighbours, snapshot):
        if name in aps_by_name or name in unparsable_names or name in shared_names:
            continue
        unknown_names.append(name)
        partial.append(PartialReason.AP_NOT_FOUND)
        site_findings.append(
            _finding(
                Severity.ERROR,
                "ap_not_found",
                name,
                "configured under neighbors but not on the controller; check the name",
            )
        )
    scan_summary, verifiable, host_key_failed, scan_findings, scan_partial = _scan_summary(
        scan, inp.scan_passes, inp.scan_skipped, unknown_names
    )
    partial.extend(scan_partial)
    scan_findings_by_ap: dict[str, list[Finding]] = {}
    for finding in scan_findings:
        scan_findings_by_ap.setdefault(finding.subject, []).append(finding)
    pending_5g: set[str] = set()
    ap_reports: list[ApReport] = []
    offsets_reported: set[tuple[frozenset[str], Band]] = set()
    for name in ap_order(inp.neighbours, snapshot):
        if name not in aps_by_name:
            continue
        ap = aps_by_name[name]
        configured = name in configured_names
        ap_findings: list[Finding] = list(scan_findings_by_ap.get(name, ()))
        if ap.offline:
            ap_findings.append(_finding(Severity.WARNING, "ap_offline", name, "offline (no radio statistics)"))
            ap_reports.append(_ap_report(ap, configured, (), ap_findings))
            continue
        if ap.state is DeviceState.OTHER:
            ap_findings.append(_finding(Severity.INFO, "ap_state", name, f"controller device state {ap.state_code}"))
        if not configured:
            ap_findings.append(
                _finding(Severity.INFO, "ap_not_configured", name, "not listed under neighbors; no neighbour analysis")
            )
        if name in roles.unresolved_children:
            ap_findings.append(
                _finding(
                    Severity.INFO,
                    "mesh_parent_unresolved",
                    name,
                    "wireless uplink whose parent could not be resolved; the parent radio is not guarded",
                )
            )
        for radio in ap.radios:
            if radio.band not in EVALUATED_BANDS:
                ap_findings.append(
                    _finding(
                        Severity.INFO,
                        "band_detected_not_evaluated",
                        name,
                        f"{radio.band.label} radio detected; the band is not evaluated",
                        radio.band,
                    )
                )
        bands: list[BandReport] = []
        for band in EVALUATED_BANDS:
            if ap.radio(band) is None:
                continue
            report = _band_report(
                ap, band, inp, matrix, corridors[band], channels, targets, roles, configured, partial, offsets_reported
            )
            bands.append(report)
            if band is Band.GHZ_5 and any(r.setting == TX_POWER and r.is_change for r in report.recommendations):
                pending_5g.add(name)
        ap_reports.append(_ap_report(ap, configured, tuple(bands), ap_findings))
    if snapshot.clients is not None:
        unplaced = unassignable_finding(
            snapshot.site.id, unassignable(snapshot.clients, frozenset(ap.mac for ap in aps_by_name.values()))
        )
        if unplaced is not None:
            site_findings.append(unplaced)
    offline_macs = {ap.mac for ap in snapshot.access_points if ap.offline}
    problems = tuple(p for p in snapshot.problems if not (p.device_mac in offline_macs and STATS_PATH_MARKER in p.path))
    roaming = tuple(_roaming_summary(t, frozenset(pending_5g)) for t in targets.values())
    model = inp.environment
    rf = inp.rf
    return SiteReport(
        site_id=snapshot.site.id,
        site_name=snapshot.site.description,
        captured_at=snapshot.captured_at,
        environment=EnvironmentSummary(preset=model.preset, exponent=model.exponent, delta_db=round(model.delta_db, 2)),
        rf=RfSummary(
            cell_edge_dbm=rf.cell_edge.dbm,
            noise_floor_dbm=rf.cell_edge.noise_floor_dbm,
            required_snr_db=rf.cell_edge.required_snr_db,
            client_tx_dbm=rf.client_tx_dbm,
            min_rssi_offset_db=rf.min_rssi_offset_db,
            roam_offset_db=rf.roaming.offset_db,
            roam_margin_db=rf.roaming.margin_db,
            roam_floor_dbm=rf.roaming.floor_dbm,
            roam_ceiling_dbm=rf.roaming.ceiling_dbm,
        ),
        corridors={band: CorridorSummary(low_dbm=c.low, high_dbm=c.high) for band, c in corridors.items()},
        scan_passes=inp.scan_passes,
        aps=tuple(ap_reports),
        compliance=compliance,
        roaming=roaming,
        groups=group_reports(matrix, channels),
        scan=scan_summary,
        site_findings=tuple(site_findings),
        field_problems=problems,
        unparsable=snapshot.unparsable_devices,
        partial_reasons=tuple(dict.fromkeys(partial)),
        verifiable_ap_count=verifiable,
        host_key_failed_ap_count=host_key_failed,
        scanning=scan is not None,
    )


def _ap_report(ap: AccessPoint, configured: bool, bands: tuple[BandReport, ...], findings: list[Finding]) -> ApReport:
    return ApReport(
        name=ap.name,
        mac=ap.mac,
        model=ap.model,
        state=ap.state,
        state_code=ap.state_code,
        uplink_type=ap.uplink_type,
        configured=configured,
        bands=bands,
        findings=tuple(findings),
    )
