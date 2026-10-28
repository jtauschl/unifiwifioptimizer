"""The text and JSON renderers of the site report: golden files, sanitising per token, the pending note,
the footer, one JSON document for several sites, ASCII-only JSON, no secret in the output."""

import json
from dataclasses import replace
from pathlib import Path

import pytest

from unifiwifioptimizer.analysis.deferral import apply_deferrals
from unifiwifioptimizer.analysis.site_analyzer import analyze_site
from unifiwifioptimizer.domain.analysis import (
    ChannelPlanMethod,
    PartialReason,
    ReadingSource,
    RoamingCap,
    WlanRoamingStatus,
)
from unifiwifioptimizer.domain.models import Band, DeviceState, FieldProblem, MgmtSettings, UnparsableDevice
from unifiwifioptimizer.domain.report import (
    BandChannelPlan,
    ChannelAssignment,
    ChannelPlanStatus,
    CheckStatus,
    Deferral,
    ExtendedChannelPlan,
    Finding,
    Recommendation,
    RecommendationKind,
    RoamingApDetail,
    Severity,
    SiteReport,
    WlanRoamingSummary,
)
from unifiwifioptimizer.domain.scan import ScanFailure, ScanFailureKind
from unifiwifioptimizer.domain.secrets import Secret
from unifiwifioptimizer.report.json import SCHEMA_VERSION, plain, render_json
from unifiwifioptimizer.report.safe_text import INVISIBLE_LEADERS, REPORT_MARKS, safe_line_start
from unifiwifioptimizer.report.text import _fold, _min_rssi_value, render_overview, render_report
from unifiwifioptimizer.report.ui_paths import HINTED, UI_PATHS, ui_hint
from unifiwifioptimizer.rf.settings import RfSettings

from ..analysis.builders import ap_named, golden_input, with_ap

GOLDEN_DIR = Path(__file__).parents[2] / "fixtures" / "golden"
# Built from the code point so no bidirectional override sits literally in this source file.
RLO = chr(0x202E)
REPORT = analyze_site(golden_input())


def test_the_text_report_matches_the_golden_file() -> None:
    expected = (GOLDEN_DIR / "run_default.txt").read_text(encoding="utf-8")
    assert render_report(REPORT) == expected


def test_the_default_overview_matches_the_golden_file() -> None:
    expected = (GOLDEN_DIR / "run_overview.txt").read_text(encoding="utf-8")
    assert render_overview(REPORT) == expected


def test_the_extended_overview_matches_the_golden_file() -> None:
    expected = (GOLDEN_DIR / "run_overview_extended.txt").read_text(encoding="utf-8")
    assert render_overview(analyze_site(replace(golden_input(), extended=True))) == expected


def _section(text: str, start: str, end: str) -> list[str]:
    return text.split(start, 1)[1].split(end, 1)[0].splitlines()


def test_overview_lists_the_wlans_before_the_access_points_and_the_radio_rows_in_ui_order() -> None:
    text = render_overview(REPORT, width=None)
    assert text.index("WLAN       SSID-1") < text.index("AP         AP-1") < text.index("Data quality:")
    rows = [
        line.split()[1] if line.split()[0] in "·✓✗-" else line.strip() for line in _section(text, "  5 GHz\n", "\n\n")
    ]
    assert rows[:4] == ["Channel", "Channel", "Transmit", "Minimum"]
    assert "Neighbour AP:" not in text and "Recommendations:" not in text and "Environment" not in text


def test_overview_names_the_ui_path_only_where_the_setting_is_hard_to_find() -> None:
    text = render_overview(REPORT, width=None)
    assert "→ WLAN edit → Advanced → Behavior Controls → Auto 802.11 DTIM Period" in text
    assert "Minimum Data Rate → 5 GHz slider" not in text and "→ AP settings" not in text
    assert (
        "Multicast to Unicast" in text
        and "→ WLAN edit → Advanced → Hi-Capacity Tuning → Multicast to Unicast" not in text
    )
    assert "→ WLAN edit" in render_report(REPORT) and "→ AP settings" in render_report(REPORT)


def test_the_hinted_settings_are_known_ui_paths_and_the_radio_rows_are_not_among_them() -> None:
    assert set(UI_PATHS) >= HINTED
    assert not {"tx_power", "min_rssi"} & HINTED
    assert ui_hint("dtim_mode") == UI_PATHS["dtim_mode"] and ui_hint("tx_power") is None


def test_overview_says_no_changes_without_hiding_diagnostic_findings() -> None:
    aps = tuple(
        replace(
            ap,
            bands=tuple(
                replace(
                    band,
                    recommendations=tuple(replace(rec, kind=RecommendationKind.HELD) for rec in band.recommendations),
                )
                for band in ap.bands
            ),
        )
        for ap in REPORT.aps
    )
    evaluations = tuple(
        replace(evaluation, checks=tuple(replace(check, status=CheckStatus.PASSED) for check in evaluation.checks))
        for evaluation in REPORT.compliance.evaluations
    )
    report = replace(REPORT, aps=aps, compliance=replace(REPORT.compliance, evaluations=evaluations))
    text = render_overview(report)
    assert "Notes:" in text and "coverage/roaming gaps:" in text
    assert "No changes recommended in the available data; see Data quality." in text
    assert "No setting changes recommended; RF findings above still need review." in render_report(report)


def test_overview_does_not_call_a_partial_result_clean() -> None:
    aps = tuple(
        replace(ap, findings=(), bands=tuple(replace(band, findings=()) for band in ap.bands)) for ap in REPORT.aps
    )
    evaluations = tuple(replace(item, findings=()) for item in REPORT.compliance.evaluations)
    report = replace(
        REPORT,
        aps=aps,
        site_findings=(),
        compliance=replace(REPORT.compliance, findings=(), evaluations=evaluations),
    )
    assert report.partial
    text = render_overview(report)
    assert "Partial result (band empty); the exit code says so." in text
    assert "Notes:" not in text


def test_overview_names_scan_failures_and_missing_configured_aps() -> None:
    scan = replace(
        REPORT.scan,
        failures_by_ap={"AP-2": (ScanFailureKind.TIMEOUT, ScanFailureKind.TIMEOUT)},
        unknown_names=("AP-missing",),
    )
    text = render_overview(replace(REPORT, scan=scan))
    assert "Scan failed on AP-2: 2 pass(es) (timeout)." in text
    assert "Configured neighbour AP-missing is absent from the controller." in text


def test_overview_keeps_5ghz_advice_actionable_after_a_24ghz_tx_change() -> None:
    aps = tuple(
        replace(
            ap,
            bands=tuple(
                replace(
                    band,
                    recommendations=tuple(
                        replace(rec, kind=RecommendationKind.HELD, deferred_by=None)
                        if rec.setting == "tx_power" and band.band is Band.GHZ_5
                        else replace(rec, kind=RecommendationKind.CHANGE, deferred_by=None)
                        if rec.setting == "min_rssi" and band.band is Band.GHZ_5 and ap.name == "AP-1"
                        else rec
                        for rec in band.recommendations
                    ),
                )
                for band in ap.bands
            ),
        )
        for ap in REPORT.aps
    )
    evaluations = tuple(
        replace(
            item,
            checks=tuple(
                replace(check, status=CheckStatus.FAILED) if check.code == "roaming_assistant" else check
                for check in item.checks
            ),
        )
        for item in REPORT.compliance.evaluations
    )
    # The 2.4 GHz power changes of AP-2..AP-4 stay; no 5 GHz power changes, so nothing in 5 GHz waits.
    marked = _with_plan(None, replace(REPORT, aps=aps, compliance=replace(REPORT.compliance, evaluations=evaluations)))
    assert not any(
        rec.deferred_by for ap in marked.aps for b in ap.bands if b.band is Band.GHZ_5 for rec in b.recommendations
    )
    assert not any(check.deferred_by for check in marked.checks)
    text = render_overview(marked)
    assert "provisional" not in text
    assert "✗ Minimum RSSI" in text and "✗ Handoff Suggestions (802.11v)" in text


def _plan(*assignments: ChannelAssignment, after: int = 0) -> ExtendedChannelPlan:
    return ExtendedChannelPlan(
        bands=(
            BandChannelPlan(
                band=Band.GHZ_5,
                status=ChannelPlanStatus.RECOMMENDED,
                reason=None,
                method=ChannelPlanMethod.EXACT,
                assignments=assignments,
                own_conflicts_before=1,
                own_conflicts_after=after,
                own_pressure_before=10,
                own_pressure_after=0,
                foreign_overlaps_before=2,
                foreign_overlaps_after=2,
                data_gaps=(),
            ),
        )
    )


def _with_plan(plan: ExtendedChannelPlan | None, report: SiteReport = REPORT) -> SiteReport:
    deferred = apply_deferrals(
        report.aps,
        report.compliance,
        {summary.wlan: summary.broadcasting for summary in report.roaming},
        {evaluation.wlan for evaluation in report.compliance.evaluations},
        plan,
    )
    return replace(report, aps=deferred.aps, compliance=deferred.compliance, extended_channel_plan=plan)


def _ap_block(text: str, ap: str) -> str:
    after = text.split(f"  AP         {ap}", 1)[1].split("\n", 2)[2]
    return after.split("\n━━━", 1)[0]


def _ap_rows(text: str, ap: str, band: str) -> list[str]:
    return _section(_ap_block(text, ap), f"  {band}\n", "\n\n")


def test_overview_labels_the_candidate_plan_pins_auto_radios_and_defers_power_on_a_changed_band() -> None:
    plan = _plan(
        ChannelAssignment(ap="AP-1", current=44, proposed=100, width_mhz=80),
        ChannelAssignment(ap="AP-2", current=60, proposed=60, width_mhz=80),
    )
    text = render_overview(_with_plan(plan), width=None)
    assert _section(text, "  Channel plan\n", "\n\n") == [
        "    5 GHz (exact search): own AP overlaps 1 → 0, signal proxy 10 → 0",
        "    Apply the complete assignment for 5 GHz, then re-run before setting transmit power, Minimum RSSI or "
        "Roaming Assistant there.",
    ]
    # AP-1 (5 GHz, Auto) must be pinned or the controller may move it again; AP-2 stays where it is.
    rows = _ap_rows(text, "AP-1", "5 GHz")
    assert "    ✗ Channel                            44 (auto) → set fixed 100 (site-wide candidate)" in rows
    assert "        provisional: re-run after the channel changes are applied" in rows
    assert any(
        "Channel" in row and row.startswith("    ✓") and "keep in site-wide plan" in row
        for row in _ap_rows(text, "AP-2", "5 GHz")
    )


def test_overview_pins_an_auto_radio_that_keeps_its_channel_and_names_remaining_overlaps() -> None:
    plan = _plan(
        ChannelAssignment(ap="AP-1", current=44, proposed=44, width_mhz=80),
        ChannelAssignment(ap="AP-2", current=60, proposed=100, width_mhz=80),
        after=2,
    )
    text = render_overview(_with_plan(plan), width=None)
    assert "    ✗ Channel                            44 (auto); set fixed 44 to keep the site-wide plan" in _ap_rows(
        text, "AP-1", "5 GHz"
    )
    assert "    ✗ Channel                            60, DFS → 100 (site-wide candidate)" in _ap_rows(
        text, "AP-2", "5 GHz"
    )
    assert "      2 own AP overlap(s) remain after this plan." in text


def test_overview_tells_access_points_apart_when_their_shortened_names_collide() -> None:
    long_a, long_b = "Building-A-Floor-2-Corridor-East", "Building-A-Floor-2-Corridor-West"
    renamed = tuple(
        replace(ap, name=long_name, mac=f"02:00:00:00:{index:02x}:{index:02x}")
        for index, (ap, long_name) in enumerate(zip(REPORT.aps[:2], (long_a, long_b), strict=True), start=1)
    )
    text = render_overview(replace(REPORT, aps=(*renamed, *REPORT.aps[2:])), width=None)
    assert "Building-A-Floor-2-Corr… [01:01]" in text and "Building-A-Floor-2-Corr… [02:02]" in text
    assert "  AP         AP-3 (UAL6)" in text and "AP-3 [" not in text


def test_overview_marks_severity_and_says_what_could_not_be_evaluated() -> None:
    text = render_overview(REPORT, width=None)
    assert "* 5 GHz coverage/roaming gaps: AP-1 / AP-2, AP-2 / AP-3, AP-3 / AP-4; verify with clients." in text
    assert "WLAN checks that could not be evaluated: Handoff Suggestions (802.11v)." in text
    assert "Partial result (band empty); the exit code says so." in text


def test_overview_shows_an_offline_access_point_as_offline() -> None:
    offline = replace(REPORT.aps[0], state=DeviceState.DISCONNECTED, bands=())
    table = render_overview(replace(REPORT, aps=(offline, *REPORT.aps[1:])), width=None)
    assert "    offline — no radio statistics" in _ap_block(table, "AP-1")


def test_the_footer_counts_only_advice_that_can_be_applied_now() -> None:
    plan = _plan(ChannelAssignment(ap="AP-1", current=44, proposed=100, width_mhz=80))
    moved = _with_plan(plan)
    text = render_report(moved, width=None)
    waiting = [r for r in moved.recommendations if r.is_change and r.deferred_by is not None]
    # Golden site: four power changes, one of them on the moved 5 GHz band; the channel move waits for nothing.
    assert [r.subject for r in waiting] == ["AP-1"] and waiting[0].setting == "tx_power"
    assert "3 pending setting change(s) (3 transmit power) and 5 failed WLAN check(s)." in text
    assert "1 further item(s) wait for the changes above" in text
    assert moved.pending_tx_changes == 3 and moved.waiting_items == 1


def test_the_json_report_matches_the_golden_file_and_pins_the_schema_version() -> None:
    expected = (GOLDEN_DIR / "run_default.json").read_text(encoding="utf-8")
    text = render_json([REPORT])
    assert text == expected
    document = json.loads(text)
    assert document["schema_version"] == SCHEMA_VERSION == 1 and len(document["sites"]) == 1
    site = document["sites"][0]
    assert site["derived"]["pending_tx_changes"] == REPORT.pending_tx_changes
    assert site["aps"][0]["bands"][0]["outcome"] == "in_corridor" and site["scan"]["passes"] == 3


def test_configured_upper_client_tx_is_labelled_per_ap_in_text_and_json() -> None:
    inp = replace(golden_input(), rf=RfSettings(client_tx_dbm=18, client_tx_dbm_5g_upper=20))
    report = analyze_site(inp)
    encoded = json.loads(render_json([report]))["sites"][0]
    assert encoded["rf"]["client_tx_dbm"] == 18 and encoded["rf"]["client_tx_dbm_5g_upper"] == 20
    bands = {ap["name"]: {band["band"]: band for band in ap["bands"]} for ap in encoded["aps"]}
    assert bands["AP-1"]["5g"]["assumed_client_tx_dbm"] == 18
    assert bands["AP-3"]["5g"]["assumed_client_tx_dbm"] == 20
    assert bands["AP-3"]["2g"]["assumed_client_tx_dbm"] == 18
    assert all(detail["assumed_client_tx_dbm"] in (18, 20) for wlan in encoded["roaming"] for detail in wlan["per_ap"])
    text = render_report(report, width=None)
    assert "Assumed client TX:" in text and "5 GHz blocks within ch 100-140 20 dBm" in text
    assert "assumed client TX 18 dBm" in text and "assumed client TX 20 dBm" in text
    assert "`rf.client_tx_dbm_5g_upper` by channel" in text


@pytest.mark.security("T12")
def test_external_names_are_sanitised_per_token_not_truncated_as_a_line() -> None:
    inp = golden_input()
    hostile = "AP-" + RLO + "2\x1b[31m" + "x" * 40
    snap = inp.snapshot
    renamed = with_ap(snap, replace(ap_named(snap, "AP-2"), name=hostile))
    neighbours = {k: frozenset(hostile if p == "AP-2" else p for p in v) for k, v in inp.neighbours.items()}
    neighbours = {(hostile if k == "AP-2" else k): v for k, v in neighbours.items()}
    report = analyze_site(replace(inp, snapshot=renamed, neighbours=neighbours))
    text = render_report(report, width=None)  # whole lines: this test reads a line's composition
    # The override becomes U+FFFD, the escape sequence is stripped, and the name is cut per token only.
    safe = "AP-" + chr(0xFFFD) + "2xxxx"
    assert RLO not in text and "\x1b" not in text and safe in text
    # A composed line keeps its tail: the receiver-offset line of AP-1 ends with the sanitised peer in brackets.
    offset_lines = [line for line in text.splitlines() if "disagree by" in line]
    assert any(f"[{safe}" in line and line.endswith("]") for line in offset_lines)
    summary = render_overview(report, width=None)
    assert RLO not in summary and "\x1b" not in summary and safe in summary


@pytest.mark.security("T11")
def test_json_keeps_non_ascii_escaped_and_refuses_secrets() -> None:
    inp = golden_input()
    renamed = with_ap(inp.snapshot, replace(ap_named(inp.snapshot, "AP-2"), name="AP-" + RLO + "2"))
    text = render_json([analyze_site(replace(inp, snapshot=renamed))])
    assert "\\u202e" in text and RLO not in text and text.isascii()
    with pytest.raises(TypeError):
        plain(Secret("hunter2"))


@pytest.mark.security("T11")
def test_no_secret_plaintext_reaches_either_output() -> None:
    inp = golden_input()
    mgmt = MgmtSettings(
        ssh_enabled=True, ssh_password_auth_enabled=True, ssh_user="admin", ssh_password=Secret("s3cr3t-pl41n")
    )
    report = analyze_site(replace(inp, snapshot=replace(inp.snapshot, mgmt=mgmt)))
    assert "s3cr3t-pl41n" not in render_report(report)
    assert "s3cr3t-pl41n" not in render_overview(report)
    assert "s3cr3t-pl41n" not in render_json([report])


def test_one_json_document_for_several_sites() -> None:
    document = json.loads(render_json([REPORT, REPORT]))
    assert [s["site_id"] for s in document["sites"]] == ["default", "default"]


def test_the_pending_tx_note_appears_on_a_roaming_check_when_a_5_ghz_change_is_pending() -> None:
    text = render_report(REPORT)
    # Four power changes on the site, one of them in 5 GHz: only that one moves the threshold.
    assert REPORT.pending_tx_changes == 4
    assert text.count("Note: 1 pending 5 GHz transmit-power change(s) on the access points of this WLAN") == 1


def test_tx_pending_note_appears_when_incomplete_and_pending() -> None:
    # The incomplete roaming verdict is printed, and the note follows it.
    text = render_report(REPORT)
    assert (
        "Handoff Suggestions (802.11v)" in text
        and "threshold not available" in text
        and "pending 5 GHz transmit-power change" in text
    )


def test_tx_pending_note_absent_when_no_pending() -> None:
    # Without a pending 5 GHz change the note does not appear.
    report = analyze_site(golden_input(skip_scan=True))
    assert report.pending_tx_changes == 0 and "pending 5 GHz transmit-power change" not in render_report(report)


def test_print_rec_tx_zero_sightings_flags_real_change() -> None:
    # A radio below its maximum with a both-way miss is raised and flagged.
    inp = golden_input()
    lowered = with_ap(
        inp.snapshot,
        replace(
            ap_named(inp.snapshot, "AP-3"),
            radio_stats=tuple(
                replace(s, observed_tx_dbm=15) if s.band is Band.GHZ_5 else s
                for s in ap_named(inp.snapshot, "AP-3").radio_stats
            ),
        ),
    )
    lowered = with_ap(
        lowered,
        replace(
            ap_named(lowered, "AP-3"),
            radios=tuple(
                replace(r, configured_tx_dbm=15) if r.band is Band.GHZ_5 else r
                for r in ap_named(lowered, "AP-3").radios
            ),
        ),
    )
    report = analyze_site(replace(inp, snapshot=lowered))
    rec = next(
        r for r in report.recommendations if r.subject == "AP-3" and r.band is Band.GHZ_5 and r.setting == "tx_power"
    )
    assert rec.kind is RecommendationKind.CHANGE and rec.recommended == 23
    assert f"✗ {'Transmit Power':<24} 23 dBm (raise by 8 dB from 15 dBm)" in render_report(report)


def test_print_rec_tx_zero_sightings_no_flag_when_already_at_max() -> None:
    # At the maximum with a both-way miss nothing is flagged as a change.
    rec = next(
        r for r in REPORT.recommendations if r.subject == "AP-3" and r.band is Band.GHZ_5 and r.setting == "tx_power"
    )
    assert rec.kind is RecommendationKind.HELD and rec.is_change is False
    text = render_report(REPORT)
    assert f"- {'Transmit Power':<24} 23 dBm, no change: at the effective maximum, neighbour unsighted" in text
    assert "structural" in text


def test_site_level_findings_offline_unparsable_and_failed_scans_carry_their_names() -> None:
    inp = golden_input()
    assert inp.scan is not None
    offline = with_ap(inp.snapshot, replace(ap_named(inp.snapshot, "AP-2"), state_code=0))
    ghost = UnparsableDevice(mac="02:00:00:00:00:77", name="Ghost", reason="$.data[9].ip: missing")
    scans = tuple(
        replace(s, passes=(ScanFailure(kind=ScanFailureKind.HOST_KEY_UNKNOWN, detail="no key"),) * 3)
        if s.ap_name == "AP-1"
        else s
        for s in inp.scan.scans
        if s.ap_name != "AP-2"
    )
    report = analyze_site(
        replace(
            inp,
            snapshot=replace(offline, unparsable_devices=(ghost,)),
            scan=replace(inp.scan, scans=scans),
            neighbours={**inp.neighbours, "AP-4": frozenset({"Ghost", "Phantom"})},
        )
    )
    text = render_report(report)
    assert "  ✗ Phantom: configured under neighbors but not on the controller; check the name" in text
    assert "  * Ghost: not usable: $.data[9].ip: missing" in text
    assert "  offline (no radio statistics)" in text and "  * offline (no radio statistics)" in text
    assert "  ! AP-1: 3 failed pass(es), 0 successful (host_key_unknown)" in text
    assert "  ✗ Phantom: configured under neighbors but not on the controller" in text
    assert "  ✗ Ghost: not usable ($.data[9].ip: missing)" in text


def test_the_roaming_cap_line_keeps_client_and_uplink_values_apart_and_the_ui_paths_follow_changes() -> None:
    text = render_report(REPORT, width=None)  # whole lines: this test reads a line's composition
    floor = next(d for r in REPORT.roaming for d in r.per_ap if d.cap.value == "capped_by_floor")
    assert (
        f"would give {floor.raw_cap_dbm} dBm at the client, below the floor {REPORT.rf.roam_floor_dbm} dBm; "
        f"clamped to the floor ({floor.uplink_dbm} dBm on the uplink)"
    ) in text
    assert "        → AP settings → Radios → Transmit Power (2.4/5 GHz) -- set to Custom, then the dBm field" in text
    assert "        → WLAN edit → Enabled toggle" in text
    # Confirmed and held recommendations and passed checks carry no path.
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if line.startswith("        → "):
            assert lines[index - 1].lstrip().startswith("✗") or lines[index - 2].lstrip().startswith("✗")


def test_clients_and_missing_pairs_are_rendered() -> None:
    text = render_report(analyze_site(golden_input(clients=True)))
    assert "  · clients: " in text and "below the recommended Minimum RSSI" in text
    assert "  ! 5 GHz: AP-3 and AP-4: no reading in either direction" in text


def test_the_footer_names_the_partial_reasons_and_the_counts() -> None:
    text = render_report(REPORT)
    assert REPORT.partial_reasons == (PartialReason.BAND_EMPTY,)
    assert "Partial result (band empty)" in text and "pending setting change(s) (4 transmit power)" in text
    clean = render_report(analyze_site(golden_input(skip_scan=True)))
    assert "Partial result" not in clean


def test_long_lines_fold_at_the_width_with_a_hanging_indent_and_whole_lines_on_request() -> None:
    folded = render_report(REPORT).splitlines()
    whole = render_report(REPORT, width=None).splitlines()
    assert max(len(line) for line in folded) <= 100 < max(len(line) for line in whole)
    assert len(folded) > len(whole)
    # A continuation sits past its item's mark, so the bullet column stays free for the next item.
    cap = next(i for i, line in enumerate(folded) if line.startswith("        AP-") and "weakest neighbour" in line)
    assert folded[cap].startswith("        AP-")
    assert folded[cap + 1].startswith("          ") and not folded[cap + 1].startswith("           ")
    finding = next(i for i, line in enumerate(folded) if line.startswith("  * hand-off"))
    assert folded[finding + 1].startswith("    ") and not folded[finding + 1].startswith("     ")
    # No word is ever broken, and both renderings carry the same words.
    assert " ".join(" ".join(folded).split()) == " ".join(" ".join(whole).split())
    # A label/value line continues under its value column, not under the label.
    rec = next(i for i, line in enumerate(folded) if "✗ Transmit Power" in line and "headroom" in line)
    column = folded[rec].index("set to Custom") if "set to Custom" in folded[rec] else folded[rec].index(" dBm") - 2
    assert folded[rec + 1].startswith(" " * column) and not folded[rec + 1].startswith(" " * (column + 1))
    assert folded[rec + 1].lstrip().startswith(("the demonstrated", "power is", "— headroom", "headroom"))


def test_controller_field_problems_stay_one_per_line_after_folding() -> None:
    problems = tuple(
        FieldProblem(path=f"stat/device[{n}].radio_table[0].tx_power", message="not an integer " * 6) for n in range(3)
    )
    text = render_report(replace(REPORT, field_problems=problems))
    lines = text.splitlines()
    note = lines.index("  Note: 3 controller field(s) could not be used:")
    assert all(lines[note + 1 + 2 * n].startswith(f"    stat/device[{n}].") for n in range(3))
    assert all(len(line) <= 100 for line in lines)


def test_both_roaming_cap_kinds_render_as_plain_detail_lines() -> None:
    detail = RoamingApDetail(
        ap="AP-9", weakest_peer="AP-8", weakest_rssi_dbm=-70, source=ReadingSource.MEASURED, downlink_dbm=-75,
        uplink_dbm=-80, cap=RoamingCap.MARGIN, raw_cap_dbm=None,
    )  # fmt: skip
    summary = WlanRoamingSummary(
        wlan="SSID-1", status=WlanRoamingStatus.OK, threshold_dbm=-80, derived_dbm=None, reasons=(),
        limiting=("AP-9",), broadcasting=("AP-9",), per_ap=(detail,), tx_change_pending=False,
    )  # fmt: skip
    text = render_report(replace(REPORT, roaming=(summary,)), width=None)
    assert (
        "        AP-9: lowered to -80 dBm on the uplink; weakest neighbour AP-8 at -70 dBm is below the corridor"
        in text
    )
    assert "        * AP-9" not in text


def test_a_double_space_inside_a_name_never_pushes_the_continuation_past_the_left_half() -> None:
    # The value-column heuristic takes the first run of two spaces; a name carrying one would otherwise
    # drag the continuation far right. The guard keeps it left of the middle, never under the bullet.
    label = "  * " + "x" * 60 + "  " + "y" * 60
    folded = _fold(label, 100).splitlines()
    assert len(folded) == 2 and folded[1].startswith("    ") and not folded[1].startswith("     ")
    value_line = "    ✓ Short label                        " + "z " * 60
    continuation = _fold(value_line, 100).splitlines()[1]
    assert continuation.startswith(" " * 41 + "z") and len(continuation) <= 100


SEPARATORS = ("", " ", "\u00a0", "\u2002", "\u3000", "\u034f", "\u0301", "\u3164", "\u2800", " \u034f ")


def test_folding_never_opens_a_continuation_with_a_report_mark() -> None:
    # A word opening with a mark stays glued to the word before it, whatever the break position and whatever
    # blank, invisible leader or combining mark sits between the blank and the mark.
    for mark in sorted(REPORT_MARKS):
        for separator in SEPARATORS:
            for pad in range(1, 40):
                line = "  ! " + "a" * pad + " " + ("word " * 30) + f"x {separator}{mark} Minimum RSSI tail"
                folded = _fold(line, 100)
                for continuation in folded.splitlines()[1:]:
                    first = continuation.strip()
                    first = first[len(first) - len(first.lstrip(separator)) :] if separator else first
                    assert first[:1] not in REPORT_MARKS, (mark, separator, pad, continuation)
                assert "\x00" not in folded and "".join(folded.split()) == "".join(line.split())
    glued = _fold("  ! " + "b " * 48 + "x\u00a0\u034f✗ y", 100)
    assert "\u00a0\u034f✗" in glued


def test_a_hostile_name_in_a_list_cannot_open_a_folded_line_like_a_check() -> None:
    inp = golden_input()
    snap = inp.snapshot
    hostile = "x ✗ Minimum RSSI"
    renamed = with_ap(snap, replace(ap_named(snap, "AP-2"), name=hostile))
    neighbours = {k: frozenset(hostile if p == "AP-2" else p for p in v) for k, v in inp.neighbours.items()}
    neighbours = {(hostile if k == "AP-2" else k): v for k, v in neighbours.items()}
    whole = render_report(analyze_site(replace(inp, snapshot=renamed, neighbours=neighbours)), width=None)
    assert hostile in whole
    for width in (60, 80, 100):
        for line in whole.splitlines():
            for continuation in _fold(line, width).splitlines()[1:]:
                assert continuation.lstrip()[:1] not in REPORT_MARKS, (width, continuation)


@pytest.mark.parametrize("leader", [*sorted(INVISIBLE_LEADERS), "\u0301", "\u0903", "\u20dd"])
def test_every_invisible_leader_and_combining_category_is_skipped(leader: str) -> None:
    assert safe_line_start(f"{leader}✗ x") == f"{leader}� x"


def test_a_threshold_raised_to_the_controller_limit_says_what_was_derived() -> None:
    summary = WlanRoamingSummary(
        wlan="SSID-1", status=WlanRoamingStatus.OK, threshold_dbm=-80, derived_dbm=-83, reasons=(),
        limiting=("AP-9",), broadcasting=("AP-9",), per_ap=(), tx_change_pending=False,
    )  # fmt: skip
    text = render_report(replace(REPORT, roaming=(summary,)), width=None)
    assert "        derived -83 dBm is outside the range the controller accepts (-80..-60 dBm); set to -80 dBm" in text
    plain = replace(summary, derived_dbm=None)
    assert "derived" not in render_report(replace(REPORT, roaming=(plain,)), width=None)


def test_a_min_rssi_moved_into_the_controller_range_names_the_derived_value() -> None:
    conditional = Recommendation(
        code="min_rssi", subject="AP-9", band=Band.GHZ_5, setting="min_rssi", current=None, recommended=-67,
        kind=RecommendationKind.CONDITIONAL, reason="disabled; the value to use if enabled", derived_dbm=-63,
    )  # fmt: skip
    assert _min_rssi_value(conditional) == (
        "disabled (if enabled: -67 dBm on the uplink); derived -63 dBm is outside the range the controller accepts "
        "(-90..-67 dBm)"
    )
    assert _min_rssi_value(replace(conditional, derived_dbm=None)) == "disabled (if enabled: -67 dBm on the uplink)"


def test_the_json_report_carries_the_same_deferrals_and_counts_as_the_text() -> None:
    moved = _with_plan(_plan(ChannelAssignment(ap="AP-1", current=44, proposed=100, width_mhz=80)))
    site = json.loads(render_json([moved]))["sites"][0]
    marked = {
        (r["subject"], r["band"], r["code"]): r["deferred_by"]
        for r in site["derived"]["recommendations"]
        if r.get("deferred_by") is not None
    }
    # Every 5 GHz verdict of the moved band waits for the plan; the 2.4 GHz Minimum RSSI of the APs that change
    # their 2.4 GHz power waits for that power.
    assert marked == {
        **{
            (ap, "5g", code): "channel_plan"
            for ap in ("AP-1", "AP-2", "AP-3", "AP-4")
            for code in ("tx_power", "min_rssi")
        },
        **{(ap, "2g", "min_rssi"): "tx_change" for ap in ("AP-2", "AP-3", "AP-4")},
    }
    assert site["derived"]["pending_tx_changes"] == 3 and site["derived"]["waiting_items"] == 1
    assert "3 pending setting change(s) (3 transmit power)" in render_report(moved, width=None)


def test_the_detailed_text_marks_deferred_advice_as_provisional_and_offers_no_ui_path_for_it() -> None:
    plan = _plan(ChannelAssignment(ap="AP-1", current=44, proposed=100, width_mhz=80))
    evaluations = tuple(
        replace(
            evaluation,
            checks=tuple(
                replace(check, status=CheckStatus.FAILED) if check.code == "roaming_assistant" else check
                for check in evaluation.checks
            ),
        )
        for evaluation in REPORT.compliance.evaluations
    )
    moved = _with_plan(plan, replace(REPORT, compliance=replace(REPORT.compliance, evaluations=evaluations)))
    deferred = [r for r in moved.recommendations if r.deferred_by is not None]
    deferred_checks = [c for c in moved.checks if c.deferred_by is not None]
    assert deferred and deferred_checks
    lines = render_report(moved, width=None).splitlines()
    marks = [i for i, line in enumerate(lines) if "provisional: re-run after the channel changes" in line]
    assert len(marks) == len([r for r in deferred if r.deferred_by is Deferral.CHANNEL_PLAN]) + len(
        [c for c in deferred_checks if c.deferred_by is Deferral.CHANNEL_PLAN]
    )
    assert all(not lines[i + 1].lstrip().startswith("→") for i in marks)


def test_the_transmit_power_row_shows_the_set_value_first_and_the_effective_power_behind_it() -> None:
    text = render_overview(REPORT, width=None)
    assert (
        "✓ Transmit Power                     Auto (effective 17 dBm, EIRP 20 dBm)"
        in _ap_rows(text, "AP-1", "2.4 GHz")[2]
    )
    assert _ap_rows(text, "AP-2", "2.4 GHz")[2].startswith(
        "    ✗ Transmit Power                     Custom, 6 dBm (effective 6 dBm, EIRP 10 dBm) → 10 dBm — headroom"
    )
    assert _ap_rows(text, "AP-1", "5 GHz")[2].startswith(
        "    ✗ Transmit Power                     Auto (effective 20 dBm, EIRP 23 dBm) → Custom, 23 dBm"
    )


def test_overview_states_the_channel_reuse_shortfall_with_the_channel_list_as_its_cause() -> None:
    finding = Finding(
        severity=Severity.ADVISORY,
        code="channel_reuse_infeasible",
        message="4 access points that hear each other (AP-1, AP-2) cannot all get distinct channels: the "
        "controller's Channel AI list offers 2 80 MHz blocks, 3 would be needed; add channels to the Channel AI "
        "list, reduce the width or accept co-channel reuse",
        subject="AP-1",
        band=Band.GHZ_5,
        peers=("AP-1", "AP-2"),
    )
    text = render_overview(replace(REPORT, site_findings=(*REPORT.site_findings, finding)), width=None)
    assert (
        "    ! 5 GHz: 4 access points that hear each other (AP-1, AP-2) cannot all get distinct channels: the "
        "controller's Channel AI list offers 2 80 MHz blocks, 3 would be needed; add channels to the Channel AI "
        "list, reduce the width or accept co-channel reuse"
    ) in text


def test_the_wlan_title_names_the_network_and_its_vlan_and_says_untagged_without_one() -> None:
    def titles(network: str | None, vlan: int | None) -> list[str]:
        evaluations = tuple(replace(e, network=network, vlan=vlan) for e in REPORT.compliance.evaluations)
        text = render_overview(replace(REPORT, compliance=replace(REPORT.compliance, evaluations=evaluations)))
        return [line for line in text.splitlines() if line.startswith("  WLAN       SSID-1")]

    assert titles("Network-9", 40) == ["  WLAN       SSID-1  (profile Standard)  → network Network-9, VLAN 40"]
    assert titles("Network-9", None) == ["  WLAN       SSID-1  (profile Standard)  → network Network-9, untagged"]
    assert titles(None, None) == ["  WLAN       SSID-1  (profile Standard)"]
