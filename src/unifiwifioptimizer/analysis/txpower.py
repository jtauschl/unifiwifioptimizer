"""Transmit power per radio: one outcome from an ordered decision table (docs/ALGORITHM.md §4).

The weakest evaluable neighbour reading is an upper bound of the true weakest, so an increase is safe
while a neighbour is unevaluated, but a reduction, a confirmation or a "too strong" claim is not; a peer
missed in both directions with working scans is a verdict of its own (ADR-002 D8: the maximum only after a
miss in both directions). The effective maximum is derived from the configured power only in Custom mode —
outside it the configured value is stale.
"""

from collections.abc import Sequence
from dataclasses import dataclass

from unifiwifioptimizer.analysis.neighbors import PeerReading
from unifiwifioptimizer.domain.analysis import BandTxOutcome, NeighbourMarker
from unifiwifioptimizer.domain.models import DFS_WAIT_STATE, AccessPoint, Band, TxPowerMode
from unifiwifioptimizer.domain.report import TX_POWER, Finding, Recommendation, RecommendationKind, Severity
from unifiwifioptimizer.rf.channels import cac_seconds
from unifiwifioptimizer.rf.constants import HYSTERESIS_DOWN_DB
from unifiwifioptimizer.rf.corridor import Corridor
from unifiwifioptimizer.rf.txpower import EffectiveMax, effective_max_tx, recommend_tx


@dataclass(frozen=True, slots=True, kw_only=True)
class TxSummary:
    effective_dbm: int | None
    configured_dbm: int | None
    mode: TxPowerMode | None
    min_dbm: int | None
    max_dbm: int | None
    effective_max_dbm: int | None
    effective_max_verified: bool


@dataclass(frozen=True, slots=True, kw_only=True)
class BandTxResult:
    outcome: BandTxOutcome
    summary: TxSummary
    recommendation: Recommendation | None
    findings: tuple[Finding, ...]
    # Marker per peer name for the neighbour table; peers without a marker are absent.
    markers: dict[str, NeighbourMarker]
    weakest_dbm: int | None
    # A neighbour stays out of reach even at the effective maximum: the structural rows (6 at the maximum,
    # 10) and every `BELOW_UNFIXABLE` marker. Read by the Min-RSSI ordering advisory.
    coverage_gap: bool


def effective_maximum(ap_band: TxSummary) -> EffectiveMax | None:
    if ap_band.max_dbm is None or ap_band.effective_dbm is None:
        return None
    return _cap(ap_band.mode, ap_band.configured_dbm, ap_band.effective_dbm, ap_band.max_dbm)


def _cap(mode: TxPowerMode | None, configured: int | None, effective: int, max_dbm: int) -> EffectiveMax:
    """The cap only follows the configured value in Custom mode; everywhere else it is the radio maximum,
    unverified."""
    if mode is TxPowerMode.CUSTOM and configured is not None:
        return effective_max_tx(max_dbm, configured, effective)
    return EffectiveMax(dbm=max_dbm, verified=False)


def summarise(ap: AccessPoint, band: Band) -> TxSummary:
    radio, stats = ap.radio(band), ap.stats(band)
    summary = TxSummary(
        effective_dbm=stats.observed_tx_dbm if stats is not None else None,
        configured_dbm=radio.configured_tx_dbm if radio is not None else None,
        mode=radio.tx_power_mode if radio is not None else None,
        min_dbm=radio.min_tx_dbm if radio is not None else None,
        max_dbm=radio.max_tx_dbm if radio is not None else None,
        effective_max_dbm=None,
        effective_max_verified=False,
    )
    cap = effective_maximum(summary)
    if cap is None:
        return summary
    return TxSummary(
        effective_dbm=summary.effective_dbm,
        configured_dbm=summary.configured_dbm,
        mode=summary.mode,
        min_dbm=summary.min_dbm,
        max_dbm=summary.max_dbm,
        effective_max_dbm=cap.dbm,
        effective_max_verified=cap.verified,
    )


def _finding(
    severity: Severity, code: str, ap: AccessPoint, band: Band, message: str, peers: Sequence[str] = ()
) -> Finding:
    return Finding(severity=severity, code=code, message=message, subject=ap.name, band=band, peers=tuple(peers))


def _recommendation(
    ap: AccessPoint, band: Band, summary: TxSummary, current: int, recommended: int, kind: RecommendationKind,
    reason: str, unverified: bool = False,
) -> Recommendation:  # fmt: skip
    return Recommendation(
        code=TX_POWER,
        subject=ap.name,
        band=band,
        setting=TX_POWER,
        current=current,
        recommended=recommended,
        kind=kind,
        reason=reason,
        current_mode=summary.mode,
        unverified_headroom=unverified,
    )


def _names(cells: Sequence[PeerReading]) -> list[str]:
    return [c.peer for c in cells]


def _reason_text(cells: Sequence[PeerReading]) -> str:
    return ", ".join(f"{c.peer}: {c.why.words}" for c in cells)


def _peers_not_evaluated(ap: AccessPoint, band: Band, blocking: Sequence[PeerReading]) -> Finding:
    return _finding(
        Severity.WARNING,
        "peers_not_evaluated",
        ap,
        band,
        f"{len(blocking)} configured neighbour(s) could not be evaluated ({_reason_text(blocking)})",
        _names(blocking),
    )


def _band_floor_wording(band: Band) -> str:
    return "the cell edge" if band is Band.GHZ_5 else "the 2.4 GHz corridor floor (edge minus the overlap allowance)"


def analyse_band_tx(
    ap: AccessPoint,
    band: Band,
    cells: Sequence[PeerReading],
    corridor: Corridor,
    scan_skipped: bool,
) -> BandTxResult:
    """Rows 1-13 of the decision table, first match wins; `cells` are the subject's configured peers on the
    band."""
    summary = summarise(ap, band)
    markers: dict[str, NeighbourMarker] = {}
    weakest = min((c.rssi_dbm for c in cells if c.rssi_dbm is not None), default=None)

    def result(
        outcome: BandTxOutcome,
        recommendation: Recommendation | None = None,
        findings: Sequence[Finding] = (),
        structural: bool = False,
    ) -> BandTxResult:
        return BandTxResult(
            outcome=outcome,
            summary=summary,
            recommendation=recommendation,
            findings=tuple(findings),
            markers=markers,
            weakest_dbm=weakest,
            coverage_gap=structural or NeighbourMarker.BELOW_UNFIXABLE in markers.values(),
        )

    # Rows 1-3: nothing to judge on this radio.
    if scan_skipped:
        return result(BandTxOutcome.SCAN_SKIPPED)
    if ap.offline:
        return result(BandTxOutcome.OFFLINE)
    stats = ap.stats(band)
    if stats is not None and stats.state == DFS_WAIT_STATE:
        try:
            seconds = cac_seconds(stats.channel, stats.width_mhz)
        except ValueError:
            seconds = None
        wait = f"up to {seconds} s" if seconds is not None else "the channel availability check"
        return result(
            BandTxOutcome.DFS_WAIT,
            findings=[
                _finding(
                    Severity.INFO,
                    "dfs_cac",
                    ap,
                    band,
                    f"radio in DFS channel availability check on channel {stats.channel}; re-run after {wait}",
                )
            ],
        )
    # Row 4: the numbers the table needs, consistent with each other.
    current, min_tx, max_tx = summary.effective_dbm, summary.min_dbm, summary.max_dbm
    if current is None or min_tx is None or max_tx is None:
        missing = [
            name
            for name, value in (("tx_power", current), ("min_txpower", min_tx), ("max_txpower", max_tx))
            if value is None
        ]
        return result(
            BandTxOutcome.NOT_EVALUABLE,
            findings=[
                _finding(
                    Severity.WARNING, "tx_not_evaluable", ap, band, f"the controller did not send {', '.join(missing)}"
                )
            ],
        )
    if not min_tx <= current <= max_tx:
        return result(
            BandTxOutcome.NOT_EVALUABLE,
            findings=[
                _finding(
                    Severity.WARNING,
                    "tx_not_evaluable",
                    ap,
                    band,
                    f"the radio runs at {current} dBm outside its own range {min_tx}..{max_tx} dBm",
                )
            ],
        )
    cap = _cap(summary.mode, summary.configured_dbm, current, max_tx)
    eff_max = cap.dbm
    at_max = current >= eff_max
    # Row 5.
    if not cells:
        return result(BandTxOutcome.NO_PEERS)
    blocking = [c for c in cells if c.blocking]
    both_way = [c for c in cells if c.both_way_miss]
    extra: list[Finding] = [_peers_not_evaluated(ap, band, blocking)] if blocking else []
    # Row 6: a miss in both directions with working scans.
    if both_way:
        names = _names(both_way)
        if at_max:
            warning = _finding(
                Severity.WARNING,
                "coverage_gap",
                ap,
                band,
                f"at the effective maximum {eff_max} dBm and still unsighted by {', '.join(names)}: structural, "
                "reposition or add an access point",
                names,
            )
            held = _recommendation(
                ap,
                band,
                summary,
                current,
                current,
                RecommendationKind.HELD,
                "at the effective maximum, neighbour unsighted",
            )
            return result(BandTxOutcome.NO_SIGHTING, held, [warning, *extra], structural=True)
        change = _recommendation(
            ap, band, summary, current, eff_max, RecommendationKind.CHANGE,
            f"no sighting in either direction between {ap.name} and {', '.join(names)}", unverified=not cap.verified,
        )  # fmt: skip
        return result(BandTxOutcome.NO_SIGHTING, change, extra)
    # Row 7: nothing to compare against.
    if weakest is None:
        warning = _finding(
            Severity.WARNING,
            "peers_not_evaluated",
            ap,
            band,
            f"no configured neighbour could be evaluated ({_reason_text(cells)})",
            _names(cells),
        )
        return result(BandTxOutcome.NOT_EVALUABLE, None, [warning])
    plan = recommend_tx(current, min_tx, eff_max, weakest, corridor)
    _mark(markers, cells, corridor, plan.recommended - current, min_tx - current)
    # Rows 8/9.
    if corridor.contains(weakest):
        if blocking:
            held = _recommendation(
                ap, band, summary, current, current, RecommendationKind.HELD, "no change; not fully evaluated"
            )
            return result(BandTxOutcome.IN_CORRIDOR_PARTIAL, held, extra)
        confirmed = _recommendation(
            ap, band, summary, current, current, RecommendationKind.CONFIRMED, "weakest neighbour inside the corridor"
        )
        return result(BandTxOutcome.IN_CORRIDOR, confirmed)
    # Rows 10/11: the corridor is out of reach upwards.
    if plan.uncapped > eff_max:
        short = corridor.low - (weakest + (eff_max - current))
        if at_max:
            below = [c.peer for c in cells if c.rssi_dbm is not None and c.rssi_dbm < corridor.low]
            warning = _finding(
                Severity.WARNING,
                "coverage_gap",
                ap,
                band,
                f"hand-off between {ap.name} and {', '.join(below)} happens below {_band_floor_wording(band)} "
                f"({short} dB short at the effective maximum {eff_max} dBm): add an access point or accept",
                below,
            )
            held = _recommendation(
                ap, band, summary, current, current, RecommendationKind.HELD, "at the effective maximum"
            )
            return result(BandTxOutcome.COVERAGE_GAP, held, [warning, *extra], structural=True)
        findings = list(extra)
        if not cap.verified:
            findings.append(
                _finding(
                    Severity.INFO,
                    "headroom_unverified",
                    ap,
                    band,
                    f"the radio has not demonstrated power above {current} dBm on this channel",
                )
            )
        change = _recommendation(
            ap,
            band,
            summary,
            current,
            eff_max,
            RecommendationKind.CHANGE,
            "weakest neighbour below the corridor",
            unverified=not cap.verified,
        )
        return result(BandTxOutcome.RAISE_TO_MAXIMUM, change, findings)
    reduces = plan.recommended < current
    # Row 12: still above the corridor at the minimum.
    if plan.uncapped < min_tx and weakest + (min_tx - current) > corridor.high:
        if blocking:
            if reduces:
                held = _recommendation(
                    ap,
                    band,
                    summary,
                    current,
                    current,
                    RecommendationKind.HELD,
                    "reduction blocked: neighbours not evaluated",
                )
                blocked = _finding(
                    Severity.WARNING,
                    "reduction_blocked",
                    ap,
                    band,
                    f"a reduction waits until every configured neighbour is evaluated ({_reason_text(blocking)})",
                    _names(blocking),
                )
                return result(BandTxOutcome.REDUCTION_BLOCKED, held, [blocked])
            held = _recommendation(
                ap, band, summary, current, current, RecommendationKind.HELD, _hold_reason(current, min_tx)
            )
            return result(BandTxOutcome.OUT_OF_CORRIDOR, held, extra)
        above = [c.peer for c in cells if c.rssi_dbm is not None and c.rssi_dbm + (min_tx - current) > corridor.high]
        excess = weakest + (min_tx - current) - corridor.high
        warning = _finding(
            Severity.WARNING,
            "too_strong_at_minimum",
            ap,
            band,
            f"even at the minimum {min_tx} dBm, {', '.join(above)} would still hear {ap.name} {excess} dB above "
            "the corridor: reposition, disable the band on a middle access point, or accept the overlap",
            above,
        )
        kind = RecommendationKind.CHANGE if reduces else RecommendationKind.HELD
        reason = "weakest neighbour above the corridor" if reduces else _hold_reason(current, min_tx)
        rec = _recommendation(ap, band, summary, current, plan.recommended, kind, reason)
        return result(BandTxOutcome.TOO_STRONG_AT_MINIMUM, rec, [warning])
    # Row 13.
    if reduces and blocking:
        held = _recommendation(
            ap, band, summary, current, current, RecommendationKind.HELD, "reduction blocked: neighbours not evaluated"
        )
        blocked = _finding(
            Severity.WARNING,
            "reduction_blocked",
            ap,
            band,
            f"a reduction waits until every configured neighbour is evaluated ({_reason_text(blocking)})",
            _names(blocking),
        )
        return result(BandTxOutcome.REDUCTION_BLOCKED, held, [blocked])
    if plan.recommended == current:
        held = _recommendation(
            ap, band, summary, current, current, RecommendationKind.HELD, _hold_reason(current, min_tx)
        )
        return result(BandTxOutcome.OUT_OF_CORRIDOR, held, extra)
    direction = "below" if plan.recommended > current else "above"
    change = _recommendation(
        ap, band, summary, current, plan.recommended, RecommendationKind.CHANGE,
        f"weakest neighbour {direction} the corridor", unverified=plan.recommended > current and not cap.verified,
    )  # fmt: skip
    return result(BandTxOutcome.OUT_OF_CORRIDOR, change, extra)


def _hold_reason(current: int, min_tx: int) -> str:
    """Only a reduction clamped at the radio minimum can fall under the hysteresis step (ALGORITHM §4)."""
    if current == min_tx:
        return "already at the radio minimum"
    return (
        f"held by hysteresis (the {current - min_tx} dB reduction to the minimum {min_tx} dBm is below the "
        f"{HYSTERESIS_DOWN_DB} dB step)"
    )


def _mark(
    markers: dict[str, NeighbourMarker], cells: Sequence[PeerReading], corridor: Corridor, shift: int, to_minimum: int
) -> None:
    """`shift` is the recommended change, `to_minimum` the change down to the radio minimum (≤ 0)."""
    for cell in cells:
        if cell.rssi_dbm is None:
            continue
        if cell.rssi_dbm < corridor.low:
            markers[cell.peer] = (
                NeighbourMarker.BELOW_UNFIXABLE if cell.rssi_dbm + shift < corridor.low else NeighbourMarker.BELOW_FIXED
            )
        elif cell.rssi_dbm + to_minimum > corridor.high:
            markers[cell.peer] = NeighbourMarker.ABOVE_UNFIXABLE


def apply_mesh_guard(ap: AccessPoint, band: Band, result: BandTxResult) -> BandTxResult:
    """Post-table override: a radio carrying a wireless uplink (child or parent) never gets a reduction."""
    rec = result.recommendation
    if rec is None or rec.current is None or rec.recommended >= rec.current:
        return result
    held = Recommendation(
        code=rec.code, subject=rec.subject, band=rec.band, setting=rec.setting, current=rec.current,
        recommended=rec.current, kind=RecommendationKind.HELD, reason="wireless uplink guard",
        current_mode=rec.current_mode,
    )  # fmt: skip
    info = _finding(
        Severity.INFO,
        "mesh_uplink_guard",
        ap,
        band,
        "this radio carries a wireless uplink; no reduction is recommended",
    )
    return BandTxResult(
        outcome=result.outcome,
        summary=result.summary,
        recommendation=held,
        findings=(*result.findings, info),
        markers=result.markers,
        weakest_dbm=result.weakest_dbm,
        coverage_gap=result.coverage_gap,
    )
