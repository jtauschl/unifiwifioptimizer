"""Adjacency groups: the connected components of the configured neighbour graph, each with the pairs that
miss a sighting (one or both directions, with the reasons), the overlapping adjacent channels per band and
the reuse verdict. The Bash tool's width budgets are gone (ADR-002 D8: colouring instead)."""

from unifiwifioptimizer.analysis.channels import ChannelAnalysis, components
from unifiwifioptimizer.analysis.neighbors import EVALUATED_BANDS, NeighbourMatrix
from unifiwifioptimizer.domain.analysis import MissDirection
from unifiwifioptimizer.domain.models import Band
from unifiwifioptimizer.domain.report import GroupReport, MissingPair


def group_reports(matrix: NeighbourMatrix, channels: ChannelAnalysis) -> tuple[GroupReport, ...]:
    reports: list[GroupReport] = []
    for component in components(matrix.neighbours):
        members = tuple(sorted(component))
        missing: list[MissingPair] = []
        overlapping: list[tuple[Band, str, str]] = []
        for a in members:
            for b in sorted(matrix.neighbours.get(a, frozenset())):
                if b <= a or b not in component:
                    continue
                for band in EVALUATED_BANDS:
                    a_at_b = next((c for c in matrix.of(a, band) if c.peer == b), None)
                    b_at_a = next((c for c in matrix.of(b, band) if c.peer == a), None)
                    a_missing = a_at_b is not None and a_at_b.rssi_dbm is None
                    b_missing = b_at_a is not None and b_at_a.rssi_dbm is None
                    if a_missing or b_missing:
                        reasons = tuple(
                            f"{x.peer}: {x.why.words}" for x in (a_at_b, b_at_a) if x is not None and x.rssi_dbm is None
                        )
                        if a_missing and b_missing:
                            direction = MissDirection.BOTH
                        else:
                            direction = MissDirection.A_TO_B if a_missing else MissDirection.B_TO_A
                        missing.append(MissingPair(band=band, a=a, b=b, direction=direction, reasons=reasons))
                    ga, gb = channels.geometries.get((a, band)), channels.geometries.get((b, band))
                    if ga is not None and gb is not None and _overlaps(channels, a, b, band):
                        overlapping.append((band, a, b))
        infeasible = tuple(
            band for band, groups in channels.reuse_infeasible.items() if any(component & g for g in groups)
        )
        reports.append(
            GroupReport(
                members=members, missing=tuple(missing), overlapping=tuple(overlapping), reuse_infeasible=infeasible
            )
        )
    return tuple(reports)


def _overlaps(channels: ChannelAnalysis, a: str, b: str, band: Band) -> bool:
    for finding in channels.findings:
        if finding.band is not band or finding.code not in ("channel_overlap", "channel_ai_overlap", "pin_channels"):
            continue
        if (finding.subject == a and b in finding.peers) or (finding.subject == b and a in finding.peers):
            return True
    return False
