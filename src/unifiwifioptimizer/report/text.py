"""Plain-text renderers: the read-only subcommands and the analysis report. No colour codes — the report is
read in terminals and pasted into tickets alike; `--json` exists for machines."""

import re
import textwrap
from collections import Counter
from collections.abc import Callable, Mapping

from unifiwifioptimizer.app.use_cases import SiteOverview, SitesOverview
from unifiwifioptimizer.compliance.rules import RULE_BY_CODE
from unifiwifioptimizer.domain.analysis import (
    BandTxOutcome,
    MissDirection,
    MissingReason,
    NeighbourMarker,
    ReadingSource,
    RoamingCap,
    WlanRoamingStatus,
)
from unifiwifioptimizer.domain.models import Band, DeviceState, FieldProblem, TxPowerMode
from unifiwifioptimizer.domain.report import (
    BEACON_EVIDENCE_GAP,
    MIN_RSSI,
    TX_POWER,
    ApReport,
    BandChannelPlan,
    BandReport,
    ChannelAssignment,
    ChannelPlanStatus,
    CheckResult,
    CheckStatus,
    Deferral,
    Finding,
    NeighbourRow,
    Recommendation,
    RecommendationKind,
    Severity,
    SiteReport,
    WlanRoamingSummary,
)
from unifiwifioptimizer.report.safe_text import REPORT_MARKS, hides_nothing, safe_line_start, safe_text
from unifiwifioptimizer.report.ui_paths import in_ui_order, ui_hint, ui_path
from unifiwifioptimizer.rf.constants import (
    MIN_RSSI_MAX_DBM,
    MIN_RSSI_MIN_DBM,
    MIN_RSSI_VENDOR_START_DBM,
    ROAMING_ASSISTANT_MAX_DBM,
    ROAMING_ASSISTANT_MIN_DBM,
)


def render_sites(overview: SitesOverview) -> str:
    lines = ["", f"  {'Site ID':<20}  {'Site Name':<24}  Access Points"]
    for summary in overview.sites:
        count = str(summary.access_point_count)
        if summary.unparsable_count:
            count += f" (+{summary.unparsable_count} unparsable)"
        lines.append(f"  {safe_text(summary.site.id, 20):<20}  {safe_text(summary.site.description, 24):<24}  {count}")
    if not overview.sites:
        lines.append("  No UniFi sites were returned by the controller.")
    lines.append("")
    return "\n".join(lines) + "\n" + render_problems(overview.problems)


def render_site(overview: SiteOverview) -> str:
    lines = [
        "",
        f"  Site ID:   {safe_text(overview.site.id)}",
        f"  Site Name: {safe_text(overview.site.description)}",
        "",
    ]
    lines.append("  WLANs:")
    wlans = sorted(overview.wlans, key=lambda w: w.name)
    lines += [f"    {safe_text(w.name)} ({'enabled' if w.enabled else 'disabled'})" for w in wlans] or ["    none"]
    lines += ["", "  Access Points:"]
    aps = sorted(overview.access_points, key=lambda ap: ap.name)
    for ap in aps:
        radios = ", ".join(
            f"{r.band.label} ch {r.channel if r.channel is not None else 'auto'}/{r.width_mhz} MHz" for r in ap.radios
        )
        model = safe_text(ap.model) if ap.model is not None else "unknown model"
        lines.append(f"    {safe_text(ap.name)} ({model}, {ap.mac}) {radios}")
    for device in overview.unparsable_devices:
        label = safe_text(device.name) if device.name is not None else (device.mac or "unknown device")
        lines.append(f"    {label}: not usable ({safe_text(device.reason, 120)})")
    if not aps and not overview.unparsable_devices:
        lines.append("    none")
    lines.append("")
    return "\n".join(lines) + "\n" + render_problems(overview.problems)


def render_problems(problems: tuple[FieldProblem, ...]) -> str:
    if not problems:
        return ""
    lines = [f"  Note: {len(problems)} controller field(s) could not be used:"]
    lines += [f"    {safe_text(p.path, 100)}: {safe_text(p.message, 80)}" for p in problems[:20]]
    if len(problems) > 20:
        lines.append(f"    ... and {len(problems) - 20} more")
    return "\n".join(lines) + "\n\n"


# --- the analysis report ---------------------------------------------------------------------------------------

STATUS_MARK: Mapping[CheckStatus, str] = {
    CheckStatus.PASSED: "✓",
    CheckStatus.FAILED: "✗",
    CheckStatus.INCOMPLETE: "?",
    CheckStatus.NOT_EVALUABLE: "?",
    CheckStatus.NOT_APPLICABLE: "-",
}
SEVERITY_MARK: Mapping[Severity, str] = {
    Severity.INFO: "·",
    Severity.ADVISORY: "!",
    Severity.WARNING: "*",
    Severity.ERROR: "✗",
}
KIND_MARK: Mapping[RecommendationKind, str] = {
    RecommendationKind.CHANGE: "✗",
    RecommendationKind.CONFIRMED: "✓",
    RecommendationKind.HELD: "-",
    RecommendationKind.CONDITIONAL: "·",
}
MARKER_GLYPH: Mapping[NeighbourMarker, str] = {
    NeighbourMarker.BELOW_FIXED: "°",
    NeighbourMarker.BELOW_UNFIXABLE: "*",
    NeighbourMarker.ABOVE_UNFIXABLE: "*",
}
RULE = "━" * 64
# Wide enough for the longest check label plus its colon, so every value column starts at the same place.
LABEL = 34
NAME = 24
LINE_MAX = 160
# The report is read in terminals and pasted into tickets; a sentence longer than this is folded with a
# hanging indent so that a value column or a bullet stays recognisable as the start of its line.
WIDTH = 100
SETTING_LABEL: Mapping[str, str] = {TX_POWER: "Transmit Power", MIN_RSSI: "Minimum RSSI"}
CHECK_LABELS: Mapping[str, str] = {
    "wlan_enabled": "WLAN Enabled",
    "roaming_assistant": "Handoff Suggestions (802.11v)",
    "roaming_assistant_6g": "Handoff Suggestions (802.11v) 6 GHz",
}
SCOPE_NOTE = (
    "Scope note: this tool works from UniFi controller configuration and AP-to-AP neighbour scans. It cannot "
    "see non-WiFi RF interference (BLE/Zigbee/microwave -- needs a spectrum analyzer), per-client MCS or retry "
    "statistics, real client roaming timing, or packet captures. Neighbour RSSI is an AP-to-AP beacon reading; "
    "client thresholds are converted to the uplink the controller evaluates with {client_power}, "
    "so a client with a weaker radio is still worse off than the corridor suggests. "
    "Recommendations are static-analysis heuristics, not runtime KPIs."
)


def name(value: str) -> str:
    """An access point or WLAN name wherever the report prints one; names open lines, so they may not start
    with one of the report's own marks."""
    return safe_line_start(value, NAME)


def check_label(code: str) -> str:
    rule = RULE_BY_CODE.get(code)
    if rule is not None:
        return rule.label
    return CHECK_LABELS.get(code, code.replace("_", " "))


def _header(title: str, value: str) -> list[str]:
    return [RULE, f"  {title:<10} {value}", RULE, ""]


def _environment(report: SiteReport) -> list[str]:
    env, rf = report.environment, report.rf
    preset = env.preset if env.preset is not None else "custom"
    lines = [
        RULE,
        "  Environment",
        RULE,
        "",
        f"  {'Path-loss model:':<{LABEL}} {preset} (n = {env.exponent:g}, 2.4 GHz offset {env.delta_db:.2f} dB)",
        f"  {'Cell edge:':<{LABEL}} {rf.cell_edge_dbm} dBm "
        f"(noise floor {rf.noise_floor_dbm} dBm + SNR {rf.required_snr_db} dB)",
    ]
    for band in sorted(report.corridors, key=lambda b: b.value):
        corridor = report.corridors[band]
        lines.append(
            f"  {f'Target RSSI @ neighbour {band.label}:':<{LABEL}} {corridor.low_dbm} dBm to {corridor.high_dbm} dBm"
        )
    min_rssi_line = (
        f"  {'Minimum RSSI:':<{LABEL}} corridor floor - {rf.min_rssi_offset_db} dB, on the uplink "
        f"(client {rf.client_tx_dbm} dBm)"
    )
    if rf.client_tx_dbm_5g_upper is not None:
        min_rssi_line = (
            f"  {'Minimum RSSI:':<{LABEL}} corridor floor - {rf.min_rssi_offset_db} dB, on the uplink "
            "(assumed client TX by channel)"
        )
    lines.append(min_rssi_line)
    if rf.client_tx_dbm_5g_upper is not None:
        lines.append(
            f"  {'Assumed client TX:':<{LABEL}} base {rf.client_tx_dbm} dBm; "
            f"5 GHz blocks within ch 100-140 {rf.client_tx_dbm_5g_upper} dBm"
        )
    lines += [
        f"  {'':<{LABEL}} Ubiquiti: for high density; {MIN_RSSI_VENDOR_START_DBM} dBm as a home/office start",
        f"  {'Roaming trigger bounds:':<{LABEL}} {rf.roam_floor_dbm} dBm .. {rf.roam_ceiling_dbm} dBm "
        f"(margin {rf.roam_margin_db} dB)",
        f"  {'Scan passes:':<{LABEL}} {report.scan_passes}" + (" (scans skipped)" if report.scan.skipped else ""),
        "",
    ]
    return lines


_WAITS_FOR = {
    Deferral.CHANNEL_PLAN: "provisional: re-run after the channel changes are applied",
    Deferral.TX_CHANGE: "provisional: re-run after the transmit-power changes are applied",
}


def _check_line(check: CheckResult, *, hints_only: bool = False) -> list[str]:
    mark = STATUS_MARK[check.status]
    value = check.actual if check.status is CheckStatus.PASSED else check.expected
    if check.status is CheckStatus.FAILED and check.actual is not None:
        value = f"{check.expected} (currently {check.actual})"
    if check.status in (CheckStatus.INCOMPLETE, CheckStatus.NOT_EVALUABLE, CheckStatus.NOT_APPLICABLE):
        value = check.detail or check.status.value
    lines = [f"    {mark} {check_label(check.code):<{LABEL}} {safe_text(value or '', 80)}"]
    if check.status is CheckStatus.FAILED and check.detail:
        lines.append(f"        {safe_text(check.detail, 100)}")
    if check.deferred_by is not None:
        lines.append(f"        {_WAITS_FOR[check.deferred_by]}")
        return lines
    path = ui_hint(check.code) if hints_only else ui_path(check.code)
    if check.status is CheckStatus.FAILED and path is not None:
        lines.append(f"        → {path}")
    return lines


def _finding_line(finding: Finding, indent: str = "    ", with_subject: bool = False) -> str:
    subject = f"{name(finding.subject)}: " if with_subject else ""
    peers = f" [{', '.join(name(p) for p in finding.peers)}]" if finding.peers else ""
    return f"{indent}{SEVERITY_MARK[finding.severity]} {subject}{safe_text(finding.message, LINE_MAX)}{peers}"


def _wlans(report: SiteReport) -> list[str]:
    lines: list[str] = []
    roaming = {r.wlan: r for r in report.roaming}
    for finding in report.compliance.findings:
        lines.append(_finding_line(finding, "  ", with_subject=True))
    if report.compliance.findings:
        lines.append("")
    for evaluation in report.compliance.evaluations:
        lines += _header("WLAN", f"{name(evaluation.wlan)}  (profile {name(evaluation.profile)})")
        for check in in_ui_order(evaluation.checks, lambda item: item.code):
            lines += _check_line(check)
            if check.code == "roaming_assistant":
                lines += _roaming_detail(roaming.get(evaluation.wlan), report)
        for finding in evaluation.findings:
            lines.append(_finding_line(finding))
        lines.append("")
    return lines


def _roaming_detail(summary: WlanRoamingSummary | None, report: SiteReport) -> list[str]:
    if summary is None:
        return []
    lines: list[str] = []
    for detail in summary.per_ap:
        if detail.assumed_client_tx_dbm is not None:
            lines.append(
                f"        {name(detail.ap)}: derived {detail.uplink_dbm} dBm on the uplink "
                f"(assumed client TX {detail.assumed_client_tx_dbm} dBm)"
            )
        if detail.cap is RoamingCap.NONE:
            continue
        where = f"weakest neighbour {name(detail.weakest_peer)} at {detail.weakest_rssi_dbm} dBm"
        # Plain detail lines under the check, like the incomplete reasons and the notes: a bullet glyph
        # here would read as a severity.
        if detail.cap is RoamingCap.FLOOR:
            lines.append(
                f"        {name(detail.ap)}: {where} would give {detail.raw_cap_dbm} dBm at the client, below the "
                f"floor {report.rf.roam_floor_dbm} dBm; clamped to the floor ({detail.uplink_dbm} dBm on the "
                "uplink) — no reachable roaming neighbour, fix placement"
            )
        else:
            lines.append(
                f"        {name(detail.ap)}: lowered to {detail.uplink_dbm} dBm on the uplink; {where} is below "
                "the corridor"
            )
    if summary.limiting and summary.status is WlanRoamingStatus.OK:
        lines.append(f"        limiting access point(s): {', '.join(name(a) for a in summary.limiting)}")
    if summary.derived_dbm is not None:
        lines.append(
            f"        derived {summary.derived_dbm} dBm is outside the range the controller accepts "
            f"({ROAMING_ASSISTANT_MIN_DBM}..{ROAMING_ASSISTANT_MAX_DBM} dBm); set to {summary.threshold_dbm} dBm"
        )
    if summary.status is WlanRoamingStatus.INCOMPLETE:
        lines += [f"        {safe_line_start(reason, LINE_MAX)}" for reason in summary.reasons]
    if summary.tx_change_pending:
        lines.append(
            f"        Note: {report.pending_5g_tx_changes_of(summary.broadcasting)} pending 5 GHz transmit-power "
            "change(s) on the access points of this WLAN; apply those first and re-run; the threshold follows the "
            "effective power"
        )
    return lines


def _tx_value(rec: Recommendation) -> str:
    mode = rec.current_mode
    if rec.kind is RecommendationKind.CHANGE:
        text = f"set to Custom, {rec.recommended} dBm" if mode is not TxPowerMode.CUSTOM else f"{rec.recommended} dBm"
        if rec.current is not None:
            delta = rec.recommended - rec.current
            text += f" ({'raise' if delta > 0 else 'reduce'} by {abs(delta)} dB from {rec.current} dBm)"
        if rec.unverified_headroom:
            text += " — headroom above the demonstrated power is unverified"
        return text
    if rec.kind is RecommendationKind.CONFIRMED:
        return f"{rec.current} dBm" + (
            f" (mode {mode.value})" if mode is not None and mode is not TxPowerMode.CUSTOM else ""
        )
    return f"{rec.current} dBm, no change: {safe_text(rec.reason, 100)}"


def _min_rssi_value(rec: Recommendation) -> str:
    if rec.kind is RecommendationKind.CONDITIONAL:
        text = f"disabled (if enabled: {rec.recommended} dBm on the uplink)"
    elif rec.kind is RecommendationKind.CHANGE:
        text = f"enabled, set {rec.recommended} dBm (currently {rec.current} dBm)"
    else:
        text = f"enabled, {rec.current} dBm"
    if rec.derived_dbm is not None:
        text += (
            f"; derived {rec.derived_dbm} dBm is outside the range the controller accepts "
            f"({MIN_RSSI_MIN_DBM}..{MIN_RSSI_MAX_DBM} dBm)"
        )
    return text


def _band(band: BandReport) -> list[str]:
    tx = band.tx
    channel = "auto" if band.channel is None else str(band.channel)
    if band.channel is not None:
        channel += " (auto)" if band.channel_auto else ""
        if band.configured_channel is not None and band.configured_channel != band.channel:
            channel += f", configured {band.configured_channel}"
    if band.dfs:
        channel += f", DFS (CAC {band.cac_seconds} s)" if band.cac_seconds is not None else ", DFS"
    power = "n/a" if tx.effective_dbm is None else f"{tx.effective_dbm} dBm"
    if tx.mode is not None and tx.mode is not TxPowerMode.CUSTOM:
        power += f" ({tx.mode.value}"
        power += f", configured {tx.configured_dbm} dBm is stale)" if tx.configured_dbm is not None else ")"
    elif tx.configured_dbm is not None and tx.configured_dbm != tx.effective_dbm:
        power += f" (configured {tx.configured_dbm} dBm"
        power += ", regulatory cap)" if tx.effective_max_verified else ")"
    if tx.effective_max_dbm is not None:
        power += f"; max {tx.effective_max_dbm} dBm" + ("" if tx.effective_max_verified else " (unverified)")
    width = f"{band.width_mhz} MHz" if band.width_mhz is not None else "n/a"
    lines = [f"  {band.band.label}  (channel {channel}, width {width}, TX {power})", ""]
    if band.outcome in (BandTxOutcome.OFFLINE, BandTxOutcome.SCAN_SKIPPED):
        return lines
    if band.neighbours:
        lines.append(f"  {'Neighbour AP:':<{NAME}}  RSSI @ neighbour:")
        for row in band.neighbours:
            if row.rssi_dbm is None:
                lines.append(f"  {name(row.peer):<{NAME}}  — ({_missing_reason(row).words})")
                continue
            marker = MARKER_GLYPH[row.marker] if row.marker is not None else ""
            source = " ~" if row.source is ReadingSource.RECIPROCITY else ""
            samples = f" n={row.samples}" if row.samples > 1 else ""
            offset = f" offset {row.receiver_offset_db:+d} dB" if row.receiver_offset_db else ""
            lines.append(f"  {name(row.peer):<{NAME}}  {row.rssi_dbm} dBm{source}{samples}{offset} {marker}".rstrip())
        lines.append("")
    for finding in band.findings:
        lines.append(_finding_line(finding, "  "))
    if band.findings:
        lines.append("")
    if band.recommendations:
        lines.append("  Recommendations:")
        for rec in band.recommendations:
            label = SETTING_LABEL.get(rec.setting, rec.setting)
            value = _tx_value(rec) if rec.setting == TX_POWER else _min_rssi_value(rec)
            if rec.setting == MIN_RSSI and band.assumed_client_tx_dbm is not None:
                value += f"; assumed client TX {band.assumed_client_tx_dbm} dBm"
            lines.append(f"    {KIND_MARK[rec.kind]} {label:<{NAME}} {value}")
            if rec.deferred_by is not None:
                lines.append(f"        {_WAITS_FOR[rec.deferred_by]}")
                continue
            path = ui_path(rec.setting)
            if rec.is_change and path is not None:
                lines.append(f"        → {path}")
        lines.append("")
    extras: list[str] = []
    if band.airtime is not None:
        a = band.airtime
        parts = [
            f"utilisation {a.utilisation_pct} %" if a.utilisation_pct is not None else None,
            f"self rx/tx {a.self_rx_pct}/{a.self_tx_pct} %"
            if a.self_rx_pct is not None or a.self_tx_pct is not None
            else None,
            f"retries {a.tx_retries_pct:g} %" if a.tx_retries_pct is not None else None,
            f"satisfaction {a.satisfaction_pct} %" if a.satisfaction_pct is not None else None,
            f"{a.client_count} client(s)" if a.client_count is not None else None,
        ]
        extras.append("  · airtime: " + ", ".join(p for p in parts if p is not None))
    if band.clients is not None:
        c = band.clients
        extras.append(
            f"  · clients: {c.total} associated, {c.below_min_rssi} below the recommended Minimum RSSI "
            f"{c.min_rssi_dbm} dBm "
            f"(weakest {c.weakest_dbm} dBm)"
        )
    if band.foreign is not None:
        f = band.foreign
        strongest = f" (strongest {f.strongest_dbm} dBm)" if f.strongest_dbm is not None else ""
        extras.append(
            f"  · foreign networks heard: {f.count}{strongest}, {f.overlapping_count} on an overlapping channel"
        )
    if extras:
        lines += [*extras, ""]
    return lines


def _missing_reason(row: NeighbourRow) -> MissingReason:
    if row.reason is None:
        raise ValueError(f"{row.peer}: a neighbour row without a reading carries no reason")
    return row.reason


def _ap(ap: ApReport) -> list[str]:
    model = f" ({safe_text(ap.model)})" if ap.model is not None else ""
    lines = _header("AP", f"{name(ap.name)}{model}")
    lines.insert(2, f"  {'MAC':<10} {ap.mac}")
    if ap.state is DeviceState.DISCONNECTED:
        lines.append("  offline (no radio statistics)")
    for finding in ap.findings:
        lines.append(_finding_line(finding, "  "))
    if ap.findings:
        lines.append("")
    for band in ap.bands:
        lines += _band(band)
    return lines


def _setup_current_tx(band: BandReport) -> str:
    tx = band.tx
    if tx.effective_dbm is None:
        return "effective power unavailable"
    value = f"{tx.effective_dbm} dBm effective"
    if tx.mode is not None and tx.mode is not TxPowerMode.CUSTOM:
        value += f" ({tx.mode.value} mode)"
    if tx.configured_dbm is not None and tx.configured_dbm != tx.effective_dbm:
        value += f", configured {tx.configured_dbm} dBm"
        if tx.mode is not None and tx.mode is not TxPowerMode.CUSTOM:
            value += " is stale"
        elif tx.effective_max_verified:
            value += " (regulatory cap)"
    return value


def _setup_current_min_rssi(rec: Recommendation | None) -> str:
    if rec is None:
        return "state unavailable"
    if rec.kind is RecommendationKind.CONDITIONAL:
        return "disabled"
    return f"enabled at {rec.current} dBm" if rec.current is not None else "state unavailable"


def _setup_band(band: BandReport, plan: BandChannelPlan, assignment: ChannelAssignment | None) -> list[str]:
    channel = "auto" if band.channel is None else str(band.channel)
    width = f"{band.width_mhz} MHz" if band.width_mhz is not None else "width unknown"
    observed = f"ch {channel}/{width}"
    if band.channel_auto and band.channel is not None:
        observed += " (auto)"
    if band.configured_channel is not None and band.configured_channel != band.channel:
        observed += f", configured ch {band.configured_channel}"
    if plan.status is ChannelPlanStatus.UNAVAILABLE:
        channel_value = f"{observed}; plan unavailable"
    elif plan.status is ChannelPlanStatus.NO_IMPROVEMENT:
        channel_value = f"{observed}; no channel change proposed"
    else:
        if assignment is None:
            channel_value = f"{observed}; not in site-wide plan"
        elif assignment.current != assignment.proposed:
            target = f"ch {assignment.proposed}/{assignment.width_mhz} MHz"
            channel_value = f"{observed} → {'set fixed ' if band.channel_auto else ''}{target} (site-wide candidate)"
        elif band.channel_auto:
            channel_value = f"{observed}; set fixed ch {assignment.proposed} to keep the site-wide plan"
        else:
            channel_value = f"{observed}; keep in site-wide plan"
    lines = [f"    {band.band.label}", f"      {'Channel':<{NAME}} {channel_value}"]
    recs = {rec.setting: rec for rec in band.recommendations}
    tx_rec = recs.get(TX_POWER)
    min_rec = recs.get(MIN_RSSI)
    current_tx = _setup_current_tx(band)
    if tx_rec is None:
        tx_value = f"{current_tx}; no recommendation"
    elif tx_rec.deferred_by is Deferral.CHANNEL_PLAN:
        tx_value = f"{current_tx}; reassess after channel changes"
    elif tx_rec.kind is RecommendationKind.CHANGE:
        action = _tx_value(tx_rec)
        if not action.startswith("set to "):
            action = f"set to {action}"
        tx_value = f"{current_tx}; {action}"
    elif tx_rec.kind is RecommendationKind.CONFIRMED:
        tx_value = f"{current_tx}; keep current"
    else:
        tx_value = f"{current_tx}; no change: {safe_text(tx_rec.reason, 100)}"
    if min_rec is None:
        min_value = "state unavailable; no recommendation"
    elif min_rec.deferred_by is Deferral.CHANNEL_PLAN:
        min_value = f"{_setup_current_min_rssi(min_rec)}; reassess after channel changes"
    elif min_rec.deferred_by is Deferral.TX_CHANGE:
        min_value = f"{_setup_current_min_rssi(min_rec)}; reassess after the TX change"
    else:
        min_value = _min_rssi_value(min_rec)
        if band.assumed_client_tx_dbm is not None:
            min_value += f"; assumed client TX {band.assumed_client_tx_dbm} dBm"
    lines += [
        f"      {'Transmit Power':<{NAME}} {tx_value}",
        f"      {'Minimum RSSI':<{NAME}} {min_value}",
    ]
    return lines


def _ap_setup(report: SiteReport) -> list[str]:
    plan = report.extended_channel_plan
    if plan is None:
        return []
    by_band = {item.band: item for item in plan.bands}
    by_ap_band = {(item.band, assignment.ap): assignment for item in plan.bands for assignment in item.assignments}
    changed_bands = {item.band for item in plan.bands if item.has_changes}
    pending_tx = any(
        rec.setting == TX_POWER and rec.is_actionable
        for ap in report.aps
        for band in ap.bands
        for rec in band.recommendations
    )
    lines = [RULE, "  AP setup — current snapshot", RULE, ""]
    if changed_bands:
        labels = ", ".join(item.band.label for item in plan.bands if item.band in changed_bands)
        advice = "TX or Minimum RSSI"
        if Band.GHZ_5 in changed_bands:
            advice = "TX, Minimum RSSI or WLAN Roaming Assistant"
        lines.append(
            f"  Apply the complete site-wide candidate channel assignment for {labels}, then re-run before "
            f"using {advice} advice on those bands."
        )
    if pending_tx:
        lines.append("  After a TX change, re-run before setting Minimum RSSI from the new effective power.")
    if changed_bands or pending_tx:
        lines.append("")
    for item in plan.bands:
        if item.status is ChannelPlanStatus.UNAVAILABLE:
            lines.append(f"  {item.band.label} channel plan unavailable: {safe_text(item.reason or '', LINE_MAX)}")
        elif item.status is ChannelPlanStatus.NO_IMPROVEMENT:
            lines.append(f"  {item.band.label}: no measured own-AP channel improvement")
    if any(item.status is not ChannelPlanStatus.RECOMMENDED for item in plan.bands):
        lines.append("")
    for ap in report.aps:
        model = f" ({safe_text(ap.model)})" if ap.model is not None else ""
        lines.append(f"  AP {name(ap.name)}{model}  MAC {ap.mac}")
        if ap.state is DeviceState.DISCONNECTED:
            lines.append("    offline — no radio statistics")
        for band in ap.bands:
            band_plan = by_band.get(band.band)
            if band_plan is not None:
                lines += _setup_band(band, band_plan, by_ap_band.get((band.band, ap.name)))
        if not ap.bands:
            lines.append("    no evaluated radios")
        for finding in ap.findings:
            if finding.code == "band_detected_not_evaluated" and finding.band is not None:
                lines.append(f"    {finding.band.label} detected, not evaluated")
        lines.append("")
    for device in report.unparsable:
        label = name(device.name) if device.name is not None else (device.mac or "unknown device")
        lines.append(f"  {label}: setup unavailable ({safe_text(device.reason, 120)})")
    if report.unparsable:
        lines.append("")
    return lines


def _groups(report: SiteReport) -> list[str]:
    reported = [g for g in report.groups if not g.clean]
    if not reported:
        return []
    lines = [RULE, "  Adjacency groups", RULE, ""]
    for group in reported:
        lines.append(f"  {', '.join(name(m) for m in group.members)}")
        for pair in group.missing:
            direction = {
                MissDirection.BOTH: f"{name(pair.a)} and {name(pair.b)}: no reading in either direction",
                MissDirection.A_TO_B: f"{name(pair.a)} is not heard by {name(pair.b)}",
                MissDirection.B_TO_A: f"{name(pair.b)} is not heard by {name(pair.a)}",
            }[pair.direction]
            reasons = f" ({'; '.join(safe_text(r, 60) for r in pair.reasons)})" if pair.reasons else ""
            lines.append(f"  ! {pair.band.label}: {direction}{reasons}")
        for band, a, b in group.overlapping:
            lines.append(f"  ! {band.label}: {name(a)} and {name(b)} overlap in channel")
        for band in group.reuse_infeasible:
            lines.append(f"  ! {band.label}: channel reuse infeasible for this group")
        lines.append("")
    return lines


def _scan(report: SiteReport) -> list[str]:
    scan = report.scan
    lines: list[str] = []
    for ap_name, kinds in scan.failures_by_ap.items():
        if kinds:
            ok = scan.successes_by_ap.get(ap_name, 0)
            lines.append(
                f"  ! {name(ap_name)}: {len(kinds)} failed pass(es), {ok} successful "
                f"({', '.join(sorted({k.value for k in kinds}))})"
            )
    for unknown in scan.unknown_names:
        lines.append(f"  ✗ {name(unknown)}: configured under neighbors but not on the controller")
    if lines:
        lines = [RULE, "  Scan", RULE, "", *lines, ""]
    return lines


def _channel_plan(report: SiteReport) -> list[str]:
    plan = report.extended_channel_plan
    if plan is None:
        return []
    lines = [RULE, "  Extended channel plan", RULE, ""]
    for band in plan.bands:
        if band.status is ChannelPlanStatus.UNAVAILABLE:
            lines += [f"  {band.band.label}: unavailable — {safe_text(band.reason or '', LINE_MAX)}", ""]
            continue
        label = (
            "candidate recommendation"
            if band.status is ChannelPlanStatus.RECOMMENDED
            else "no measured own-AP improvement"
        )
        lines.append(f"  {band.band.label}: {label} ({band.method} search)")
        lines.append(
            f"    Consequential own AP overlaps: {band.own_conflicts_before} → {band.own_conflicts_after}; "
            f"signal proxy: {band.own_pressure_before} → {band.own_pressure_after}"
        )
        lines.append(
            f"    Visible foreign BSS overlaps: {band.foreign_overlaps_before} → {band.foreign_overlaps_after}"
        )
        if (
            band.possible_power_pressure_after is not None
            and band.own_pressure_after is not None
            and band.possible_power_pressure_after > band.own_pressure_after
        ):
            lines.append(
                f"    Possible pressure with higher channel power: up to {band.possible_power_pressure_after} "
                "(ceiling, not measured)"
            )
        for assignment in band.assignments:
            lines.append(
                f"    {name(assignment.ap)}: ch {assignment.current} → {assignment.proposed} "
                f"({assignment.width_mhz} MHz)"
            )
        for opportunity in band.power_opportunities:
            cac = f", DFS CAC {opportunity.cac_seconds} s" if opportunity.cac_seconds is not None else ""
            lines.append(
                f"    Downlink power trial for {name(opportunity.ap)}: ch {opportunity.current_channel} "
                f"→ {opportunity.candidate_channel}, current {opportunity.current_dbm} dBm, "
                f"candidate ceiling {opportunity.candidate_ceiling_dbm} dBm "
                f"(up to +{opportunity.candidate_ceiling_dbm - opportunity.current_dbm} dB; "
                f"{opportunity.overlapping_peers} measured AP overlap(s){cac})"
            )
        if band.power_opportunities:
            lines.append("    Trial only: AP TX does not improve client uplink; verify both directions after a change.")
        for gap in band.data_gaps:
            lines.append(f"    Note: {safe_text(gap, LINE_MAX)}")
        lines.append("")
    lines.append("  Re-run after a channel change; DFS moves and channel-specific power limits can change the result.")
    lines.append("")
    return lines


def _footer(report: SiteReport) -> list[str]:
    lines: list[str] = []
    changes = report.actionable_changes
    pending = report.pending_tx_changes
    failed = report.failed_checks
    waiting = report.waiting_items
    channel_change = report.extended_channel_plan is not None and report.extended_channel_plan.has_changes
    if changes or failed:
        lines.append(
            f"  {changes} pending setting change(s) ({pending} transmit power) and {failed} failed WLAN check(s). "
            "After applying changes, run the tool again."
        )
    if channel_change:
        lines.append("  A site-wide channel change is proposed above; apply it and run the tool again.")
    if waiting:
        lines.append(f"  {waiting} further item(s) wait for the changes above; run the tool again after applying them.")
    if not changes and not failed and not channel_change and not waiting:
        if any(f.severity in (Severity.ADVISORY, Severity.WARNING, Severity.ERROR) for f in report.findings):
            lines.append("  No setting changes recommended; RF findings above still need review.")
        else:
            lines.append("  No changes recommended.")
    if report.partial_reasons:
        reasons = ", ".join(r.value.replace("_", " ") for r in report.partial_reasons)
        lines.append(f"  Partial result ({reasons}); the exit code says so.")
    client_power = "a typical client power (`rf.client_tx_dbm`)"
    if report.rf.client_tx_dbm_5g_upper is not None:
        client_power = "an assumed client power (`rf.client_tx_dbm` or `rf.client_tx_dbm_5g_upper` by channel)"
    lines += ["", f"  {SCOPE_NOTE.format(client_power=client_power)}", ""]
    return lines


class _Labels:
    """How the summary names an access point: the shortened name, plus the MAC's last bytes when two names
    shorten to the same text (the summary has no MAC column to tell them apart)."""

    def __init__(self, report: SiteReport) -> None:
        shortened = {ap.name: name(ap.name) for ap in report.aps}
        counts = Counter(shortened.values())
        self._labels = {
            ap.name: shortened[ap.name] if counts[shortened[ap.name]] == 1 else f"{shortened[ap.name]} [{ap.mac[-5:]}]"
            for ap in report.aps
        }

    def __call__(self, ap_name: str) -> str:
        return self._labels.get(ap_name) or name(ap_name)


_SEVERITY_ORDER = {Severity.ERROR: 0, Severity.WARNING: 1, Severity.ADVISORY: 2, Severity.INFO: 3}


def _summary_findings(report: SiteReport, label: Callable[[str], str]) -> list[str]:
    coverage: dict[tuple[Band | None, tuple[str, str]], Severity] = {}
    overlap: dict[tuple[Band | None, tuple[str, str]], Severity] = {}
    reuse: dict[Band, Severity] = {}
    other: list[Finding] = []
    for finding in report.findings:
        if finding.severity not in (Severity.ADVISORY, Severity.WARNING, Severity.ERROR):
            continue
        if finding.code == "neighbours_asymmetric":
            continue
        if finding.code in ("coverage_gap", "cochannel_heard", "channel_overlap") and finding.peers:
            target = coverage if finding.code == "coverage_gap" else overlap
            for peer in finding.peers:
                key = (finding.band, (min(finding.subject, peer), max(finding.subject, peer)))
                if key not in target or _SEVERITY_ORDER[finding.severity] < _SEVERITY_ORDER[target[key]]:
                    target[key] = finding.severity
        elif finding.code == "channel_reuse_infeasible" and finding.band is not None:
            reuse[finding.band] = finding.severity
        else:
            other.append(finding)
    lines: list[str] = ["· Neighbour RF was not evaluated without a scan."] if report.scan.skipped else []
    if report.extended_channel_plan is not None:
        unchanged = [
            plan.band.label
            for plan in report.extended_channel_plan.bands
            if plan.status is ChannelPlanStatus.NO_IMPROVEMENT
        ]
        if unchanged:
            lines.append(f"· Channel plan: no measured improvement on {', '.join(unchanged)} at current widths.")
    for band in Band:
        pairs = sorted((pair, severity) for (found_band, pair), severity in coverage.items() if found_band is band)
        if pairs:
            members = ", ".join(f"{label(a)} / {label(b)}" for (a, b), _ in pairs)
            mark = SEVERITY_MARK[min((s for _, s in pairs), key=_SEVERITY_ORDER.__getitem__)]
            lines.append(f"{mark} {band.label} coverage/roaming gaps: {members}; verify with clients.")
    for band in Band:
        pairs = sorted((pair, severity) for (found_band, pair), severity in overlap.items() if found_band is band)
        if pairs:
            members = ", ".join(f"{label(a)} / {label(b)}" for (a, b), _ in pairs)
            mark = SEVERITY_MARK[min((s for _, s in pairs), key=_SEVERITY_ORDER.__getitem__)]
            lines.append(f"{mark} {band.label} channel overlap: {members}.")
    for band in sorted(reuse, key=lambda value: value.value):
        lines.append(
            f"{SEVERITY_MARK[reuse[band]]} {band.label} cannot give every neighbouring AP a distinct channel "
            "in the current plan."
        )
    other.sort(key=lambda finding: _SEVERITY_ORDER[finding.severity])
    for finding in other[:6]:
        band_label = f" {finding.band.label}" if finding.band is not None else ""
        lines.append(
            f"{SEVERITY_MARK[finding.severity]} {label(finding.subject)}{band_label}: "
            f"{safe_text(finding.message, LINE_MAX)}"
        )
    if len(other) > 6:
        lines.append(f"· {len(other) - 6} further findings: run with --details.")
    return lines


def _summary_evidence(report: SiteReport, label: Callable[[str], str]) -> list[str]:
    lines: list[str] = []
    if report.scan.skipped:
        lines.append("Neighbour scans skipped; RF recommendations are unavailable.")
    else:
        successes = sum(report.scan.successes_by_ap.values())
        expected = len(report.scan.scanned) * report.scan.passes
        lines.append(f"Scan: {len(report.scan.scanned)} APs, {successes}/{expected} passes successful.")
    for ap_name, failures in report.scan.failures_by_ap.items():
        if failures:
            kinds = ", ".join(sorted({kind.value for kind in failures}))
            lines.append(f"Scan failed on {label(ap_name)}: {len(failures)} pass(es) ({kinds}).")
    for ap_name in report.scan.unknown_names:
        lines.append(f"Configured neighbour {label(ap_name)} is absent from the controller.")
    if report.partial_reasons:
        reasons = ", ".join(r.value.replace("_", " ") for r in report.partial_reasons)
        lines.append(f"Partial result ({reasons}); the exit code says so.")
    unevaluated = sorted(
        {check_label(c.code) for c in report.checks if c.status in (CheckStatus.INCOMPLETE, CheckStatus.NOT_EVALUABLE)}
    )
    if unevaluated:
        lines.append(f"WLAN checks that could not be evaluated: {', '.join(unevaluated)}.")
    if report.field_problems:
        lines.append(f"{len(report.field_problems)} controller fields could not be used.")
    if report.unparsable:
        lines.append(f"{len(report.unparsable)} controller devices could not be evaluated.")
    asymmetric = sum(1 for finding in report.site_findings if finding.code == "neighbours_asymmetric")
    if asymmetric:
        lines.append(f"{asymmetric} neighbour links are configured in one direction; both are evaluated.")
    if report.extended_channel_plan is not None:
        gaps = {
            gap for plan in report.extended_channel_plan.bands for gap in plan.data_gaps if gap != BEACON_EVIDENCE_GAP
        }
        lines.extend(safe_text(gap, LINE_MAX) for gap in sorted(gaps))
        unavailable: dict[str, list[str]] = {}
        for plan in report.extended_channel_plan.bands:
            if plan.status is ChannelPlanStatus.UNAVAILABLE:
                unavailable.setdefault(plan.reason or "unknown reason", []).append(plan.band.label)
        lines.extend(
            f"Channel plan unavailable ({', '.join(bands)}): {safe_text(reason, LINE_MAX)}"
            for reason, bands in unavailable.items()
        )
    if not report.scan.skipped:
        lines.append("AP beacon readings do not establish client roaming or channel airtime.")
    return lines


def _overview_wlans(report: SiteReport) -> list[str]:
    """The WLANs as the controller UI lists them; a setting's path is named only where it is hard to find."""
    lines: list[str] = []
    for finding in report.compliance.findings:
        lines.append(_finding_line(finding, "  ", with_subject=True))
    if report.compliance.findings:
        lines.append("")
    for evaluation in report.compliance.evaluations:
        lines += _header("WLAN", f"{name(evaluation.wlan)}  (profile {name(evaluation.profile)})")
        for check in in_ui_order(evaluation.checks, lambda item: item.code):
            lines += _check_line(check, hints_only=True)
        for finding in evaluation.findings:
            lines.append(_finding_line(finding))
        lines.append("")
    return lines


def _row(mark: str, label: str, value: str) -> str:
    return f"    {mark} {label:<{LABEL}} {value}"


def _overview_channel(band: BandReport, plan: BandChannelPlan | None, assignment: ChannelAssignment | None) -> str:
    channel = "auto" if band.channel is None else str(band.channel)
    observed = channel + (" (auto)" if band.channel_auto and band.channel is not None else "")
    if band.dfs:
        observed += ", DFS"
    if band.configured_channel is not None and band.configured_channel != band.channel:
        observed += f", configured {band.configured_channel}"
    if plan is None:
        return _row("·", "Channel", observed)
    if plan.status is ChannelPlanStatus.UNAVAILABLE:
        return _row("·", "Channel", f"{observed}; plan unavailable")
    if plan.status is ChannelPlanStatus.NO_IMPROVEMENT:
        return _row("·", "Channel", f"{observed}; no change proposed")
    if assignment is None:
        return _row("·", "Channel", f"{observed}; not in site-wide plan")
    pin = "set fixed " if band.channel_auto else ""
    if assignment.current != assignment.proposed:
        return _row("✗", "Channel", f"{observed} → {pin}{assignment.proposed} (site-wide candidate)")
    if band.channel_auto:
        return _row("✗", "Channel", f"{observed}; set fixed {assignment.proposed} to keep the site-wide plan")
    return _row("✓", "Channel", f"{observed}; keep in site-wide plan")


def _overview_setting(rec: Recommendation | None, label: str, value: str) -> list[str]:
    if rec is None:
        return [_row("·", label, value)]
    lines = [_row(KIND_MARK[rec.kind], label, value)]
    if rec.is_change and rec.deferred_by is not None:
        lines.append(f"        {_WAITS_FOR[rec.deferred_by]}")
    return lines


def _overview_set_tx(band: BandReport) -> str:
    """The transmit power as it is set, with the power the radio actually uses behind it."""
    tx = band.tx
    if tx.mode is None:
        setting = f"{tx.configured_dbm} dBm" if tx.configured_dbm is not None else "setting unavailable"
    elif tx.mode is TxPowerMode.CUSTOM:
        setting = f"Custom, {tx.configured_dbm} dBm" if tx.configured_dbm is not None else "Custom"
    else:
        setting = tx.mode.value.capitalize()
    effective = f"{tx.effective_dbm} dBm" if tx.effective_dbm is not None else "unavailable"
    eirp = (
        f", EIRP {tx.effective_dbm + tx.antenna_gain_dbi} dBm"
        if tx.effective_dbm is not None and tx.antenna_gain_dbi is not None
        else ""
    )
    return f"{setting} (effective {effective}{eirp})"


def _overview_band(band: BandReport, plan: BandChannelPlan | None, assignment: ChannelAssignment | None) -> list[str]:
    recs = {rec.setting: rec for rec in band.recommendations}
    tx_rec = recs.get(TX_POWER)
    min_rec = recs.get(MIN_RSSI)
    set_tx = _overview_set_tx(band)
    if tx_rec is None:
        tx_value = f"{set_tx}; no recommendation"
    elif tx_rec.kind is RecommendationKind.CHANGE:
        target = (
            f"{tx_rec.recommended} dBm" if band.tx.mode is TxPowerMode.CUSTOM else f"Custom, {tx_rec.recommended} dBm"
        )
        tx_value = f"{set_tx} → {target}"
        if tx_rec.unverified_headroom:
            tx_value += " — headroom above the demonstrated power is unverified"
    elif tx_rec.kind is RecommendationKind.CONFIRMED:
        tx_value = set_tx
    else:
        tx_value = f"{set_tx}; no change: {safe_text(tx_rec.reason, 100)}"
    if min_rec is None:
        min_value = "state unavailable; no recommendation"
    else:
        min_value = _min_rssi_value(min_rec)
        if band.assumed_client_tx_dbm is not None:
            min_value += f"; assumed client TX {band.assumed_client_tx_dbm} dBm"
    width = f"{band.width_mhz} MHz" if band.width_mhz is not None else "unknown"
    return [
        f"  {band.band.label}",
        _row("·", "Channel Width", width),
        _overview_channel(band, plan, assignment),
        *_overview_setting(tx_rec, "Transmit Power", tx_value),
        *_overview_setting(min_rec, "Minimum RSSI", min_value),
        "",
    ]


def _overview_aps(report: SiteReport) -> list[str]:
    label = _Labels(report)
    plan = report.extended_channel_plan
    by_band = {item.band: item for item in plan.bands} if plan is not None else {}
    by_ap_band = (
        {(item.band, assignment.ap): assignment for item in plan.bands for assignment in item.assignments}
        if plan is not None
        else {}
    )
    lines: list[str] = []
    for ap in report.aps:
        model = f" ({safe_text(ap.model)})" if ap.model is not None else ""
        lines += _header("AP", f"{label(ap.name)}{model}")
        if ap.state is DeviceState.DISCONNECTED:
            lines += ["    offline — no radio statistics", ""]
            continue
        for band in ap.bands:
            lines += _overview_band(band, by_band.get(band.band), by_ap_band.get((band.band, ap.name)))
        if not ap.bands:
            lines += ["    no evaluated radios", ""]
        for finding in ap.findings:
            if finding.code == "band_detected_not_evaluated" and finding.band is not None:
                lines += [f"    {finding.band.label} detected, not evaluated", ""]
    for device in report.unparsable:
        ref = name(device.name) if device.name is not None else (device.mac or "unknown device")
        lines += [f"  {ref}: setup unavailable ({safe_text(device.reason, 120)})", ""]
    return lines


def _overview_plan(report: SiteReport) -> list[str]:
    plan = report.extended_channel_plan
    if plan is None or not plan.has_changes:
        return []
    lines = ["  Channel plan"]
    for item in plan.bands:
        if not item.has_changes:
            continue
        lines.append(
            f"    {item.band.label} ({item.method} search): own AP overlaps {item.own_conflicts_before} → "
            f"{item.own_conflicts_after}, signal proxy {item.own_pressure_before} → {item.own_pressure_after}"
        )
        if item.own_conflicts_after:
            lines.append(f"      {item.own_conflicts_after} own AP overlap(s) remain after this plan.")
    labels = ", ".join(item.band.label for item in plan.bands if item.has_changes)
    advice = (
        "transmit power, Minimum RSSI or Roaming Assistant"
        if Band.GHZ_5 in {item.band for item in plan.bands if item.has_changes}
        else "transmit power or Minimum RSSI"
    )
    lines += [f"    Apply the complete assignment for {labels}, then re-run before setting {advice} there.", ""]
    return lines


def _overview_footer(report: SiteReport) -> list[str]:
    changes, failed, waiting = report.actionable_changes, report.failed_checks, report.waiting_items
    channel_change = report.extended_channel_plan is not None and report.extended_channel_plan.has_changes
    lines: list[str] = []
    if changes or failed:
        lines.append(
            f"  {changes} pending setting change(s) ({report.pending_tx_changes} transmit power) and {failed} "
            "failed WLAN check(s). After applying changes, run the tool again."
        )
    if waiting:
        lines.append(f"  {waiting} further item(s) wait for the changes above; run the tool again after applying them.")
    if not changes and not failed and not channel_change and not waiting:
        lines.append(
            "  No changes recommended in the available data; see Data quality."
            if report.partial
            else "  No changes recommended."
        )
    lines += ["  Full evidence: run with --details.", ""]
    return lines


def render_overview(report: SiteReport, width: int | None = WIDTH) -> str:
    """The default text report: the WLANs and the access points laid out like the controller UI, then what the
    scan found and how complete the data is. `--details` prints the complete report instead."""
    label = _Labels(report)
    lines: list[str] = [""]
    lines += _header(
        "Site",
        f"{name(report.site_id)}  ({name(report.site_name)}), {report.captured_at.isoformat(timespec='minutes')}",
    )
    lines += _overview_wlans(report)
    lines += _overview_aps(report)
    lines += _overview_plan(report)
    findings = _summary_findings(report, label)
    if findings:
        lines += ["  Notes:", *(f"    {finding}" for finding in findings), ""]
    lines += ["  Data quality:", *(f"    {item}" for item in _summary_evidence(report, label)), ""]
    lines += _overview_footer(report)
    if width is None:
        return "\n".join(lines) + "\n"
    return "\n".join(_fold(line, width) for line in lines) + "\n"


def render_report(report: SiteReport, width: int | None = WIDTH) -> str:
    """The text report; `width` folds longer lines (None keeps every line whole)."""
    lines: list[str] = [""]
    lines += _header(
        "Site",
        f"{name(report.site_id)}  ({name(report.site_name)}), {report.captured_at.isoformat(timespec='minutes')}",
    )
    lines += _environment(report)
    for finding in report.site_findings:
        lines.append(_finding_line(finding, "  ", with_subject=True))
    if report.site_findings:
        lines.append("")
    lines += _ap_setup(report)
    lines += _wlans(report)
    for ap in report.aps:
        lines += _ap(ap)
    lines += _groups(report)
    lines += _scan(report)
    lines += _channel_plan(report)
    if report.unparsable:
        for device in report.unparsable:
            label = safe_text(device.name) if device.name is not None else (device.mac or "unknown device")
            lines.append(f"  ✗ {label}: not usable ({safe_text(device.reason, 120)})")
        lines.append("")
    # One problem per line: the block is split before folding, or the fold would run it into a paragraph.
    lines += render_problems(report.field_problems).rstrip("\n").splitlines()
    if report.field_problems:
        lines.append("")
    lines += _footer(report)
    if width is None:
        return "\n".join(lines) + "\n"
    return "\n".join(_fold(line, width) for line in lines) + "\n"


_VALUE_COLUMN = re.compile(r"  +(?=\S)")


def _glue_marks(line: str) -> tuple[str, list[str]]:
    """Folding must never break before a report mark: a name like `x ✗ Minimum RSSI` would otherwise open a
    continuation line exactly like a check line. Every blank run whose first visible character (blanks,
    invisible leaders and combining marks skipped, as in `safe_line_start`) is a mark becomes NUL for the
    wrap — NUL never survives `safe_text` — and `_unglue` restores the original blanks afterwards."""
    glued: list[str] = []
    blanks: list[str] = []
    index = 0
    while index < len(line):
        if not line[index].isspace():
            glued.append(line[index])
            index += 1
            continue
        end = index
        while end < len(line) and hides_nothing(line[end]):
            end += 1
        run = line[index:end]
        if end < len(line) and line[end] in REPORT_MARKS:
            blanks.extend(char for char in run if char.isspace())
            run = "".join("\x00" if char.isspace() else char for char in run)
        glued.append(run)
        index = end
    return "".join(glued), blanks


def _unglue(folded: str, blanks: list[str]) -> str:
    restored = iter(blanks)
    return "".join(next(restored) if char == "\x00" else char for char in folded)


def _fold(line: str, width: int) -> str:
    """A line longer than `width` continues on the next line under its value column (a label or mark
    padded to a column, as in the check, recommendation and environment lines) or, without one, two
    columns past its leading whitespace, i.e. past a one-character bullet — so the continuation can never
    be mistaken for a new item. Width counts code points, not terminal cells: a line overruns the width on
    screen by up to one column for every East Asian wide character on it. A double space inside a name is taken
    for the value column; the `width // 2` guard keeps such a continuation in the left half."""
    if len(line) <= width:
        return line
    indent = len(line) - len(line.lstrip(" "))
    mark = line[indent:].split(" ", 1)[0]
    column = _VALUE_COLUMN.search(line, indent + len(mark))
    hanging = " " * (column.end() if column is not None and column.end() < width // 2 else indent + 2)
    glued, blanks = _glue_marks(line)
    folded = textwrap.fill(
        glued, width=width, subsequent_indent=hanging, break_long_words=False, break_on_hyphens=False
    )
    return _unglue(folded, blanks)
