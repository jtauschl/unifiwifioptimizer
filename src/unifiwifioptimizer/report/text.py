"""Plain-text renderers: the read-only subcommands and the analysis report. No colour codes — the report is
read in terminals and pasted into tickets alike; `--json` exists for machines."""

import re
import textwrap
from collections.abc import Mapping

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
from unifiwifioptimizer.domain.models import DeviceState, FieldProblem, TxPowerMode
from unifiwifioptimizer.domain.report import (
    MIN_RSSI,
    TX_POWER,
    ApReport,
    BandReport,
    CheckResult,
    CheckStatus,
    Finding,
    NeighbourRow,
    Recommendation,
    RecommendationKind,
    Severity,
    SiteReport,
    WlanRoamingSummary,
)
from unifiwifioptimizer.report.safe_text import REPORT_MARKS, hides_nothing, safe_line_start, safe_text
from unifiwifioptimizer.report.ui_paths import ui_path


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
    "roaming_assistant": "Roaming Assistant",
    "roaming_assistant_6g": "Roaming Assistant 6 GHz",
}
SCOPE_NOTE = (
    "Scope note: this tool works from UniFi controller configuration and AP-to-AP neighbour scans. It cannot "
    "see non-WiFi RF interference (BLE/Zigbee/microwave -- needs a spectrum analyzer), per-client MCS or retry "
    "statistics, real client roaming timing, or packet captures. Neighbour RSSI is an AP-to-AP beacon reading; "
    "client thresholds are converted to the uplink the controller evaluates with a typical client power "
    "(`rf.client_tx_dbm`), so a client with a weaker radio is still worse off than the corridor suggests. "
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
    lines += [
        f"  {'Minimum RSSI:':<{LABEL}} corridor floor - {rf.min_rssi_offset_db} dB, on the uplink "
        f"(client {rf.client_tx_dbm} dBm)",
        f"  {'Roaming trigger bounds:':<{LABEL}} {rf.roam_floor_dbm} dBm .. {rf.roam_ceiling_dbm} dBm "
        f"(margin {rf.roam_margin_db} dB)",
        f"  {'Scan passes:':<{LABEL}} {report.scan_passes}" + (" (scans skipped)" if report.scan.skipped else ""),
        "",
    ]
    return lines


def _check_line(check: CheckResult) -> list[str]:
    mark = STATUS_MARK[check.status]
    value = check.actual if check.status is CheckStatus.PASSED else check.expected
    if check.status is CheckStatus.FAILED and check.actual is not None:
        value = f"{check.expected} (currently {check.actual})"
    if check.status in (CheckStatus.INCOMPLETE, CheckStatus.NOT_EVALUABLE, CheckStatus.NOT_APPLICABLE):
        value = check.detail or check.status.value
    lines = [f"    {mark} {check_label(check.code):<{LABEL}} {safe_text(value or '', 80)}"]
    if check.status is CheckStatus.FAILED and check.detail:
        lines.append(f"        {safe_text(check.detail, 100)}")
    path = ui_path(check.code)
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
        for check in evaluation.checks:
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
    if summary.status is WlanRoamingStatus.INCOMPLETE:
        lines += [f"        {safe_line_start(reason, LINE_MAX)}" for reason in summary.reasons]
    if summary.tx_change_pending:
        lines.append(
            f"        Note: {report.pending_tx_changes} pending transmit-power change(s) on this site; apply those "
            "first "
            "and re-run; the threshold follows the effective power"
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
        return f"disabled (if enabled: {rec.recommended} dBm on the uplink)"
    if rec.kind is RecommendationKind.CHANGE:
        return f"enabled, set {rec.recommended} dBm (currently {rec.current} dBm)"
    return f"enabled, {rec.current} dBm"


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
            lines.append(f"    {KIND_MARK[rec.kind]} {label:<{NAME}} {value}")
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


def _footer(report: SiteReport) -> list[str]:
    lines: list[str] = []
    pending = report.pending_tx_changes
    changes = sum(1 for r in report.recommendations if r.is_change)
    failed = sum(1 for c in report.checks if c.status is CheckStatus.FAILED)
    if changes or failed:
        lines.append(
            f"  {changes} pending setting change(s) ({pending} transmit power) and {failed} failed WLAN check(s). "
            "After applying changes, run the tool again."
        )
    else:
        lines.append("  No changes recommended.")
    if report.partial_reasons:
        reasons = ", ".join(r.value.replace("_", " ") for r in report.partial_reasons)
        lines.append(f"  Partial result ({reasons}); the exit code says so.")
    lines += ["", f"  {SCOPE_NOTE}", ""]
    return lines


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
    lines += _wlans(report)
    for ap in report.aps:
        lines += _ap(ap)
    lines += _groups(report)
    lines += _scan(report)
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
