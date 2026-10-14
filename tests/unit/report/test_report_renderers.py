"""The text and JSON renderers of the site report: golden files, sanitising per token, the pending note,
the footer, one JSON document for several sites, ASCII-only JSON, no secret in the output."""

import json
from dataclasses import replace
from pathlib import Path

import pytest

from unifiwifioptimizer.analysis.site_analyzer import analyze_site
from unifiwifioptimizer.domain.analysis import PartialReason
from unifiwifioptimizer.domain.models import Band, MgmtSettings, UnparsableDevice
from unifiwifioptimizer.domain.report import RecommendationKind
from unifiwifioptimizer.domain.scan import ScanFailure, ScanFailureKind
from unifiwifioptimizer.domain.secrets import Secret
from unifiwifioptimizer.report.json import SCHEMA_VERSION, plain, render_json
from unifiwifioptimizer.report.text import render_report

from ..analysis.builders import ap_named, golden_input, with_ap

GOLDEN_DIR = Path(__file__).parents[2] / "fixtures" / "golden"
# Built from the code point so no bidirectional override sits literally in this source file.
RLO = chr(0x202E)
REPORT = analyze_site(golden_input())


def test_the_text_report_matches_the_golden_file() -> None:
    expected = (GOLDEN_DIR / "run_default.txt").read_text(encoding="utf-8")
    assert render_report(REPORT) == expected


def test_the_json_report_matches_the_golden_file_and_pins_the_schema_version() -> None:
    expected = (GOLDEN_DIR / "run_default.json").read_text(encoding="utf-8")
    text = render_json([REPORT])
    assert text == expected
    document = json.loads(text)
    assert document["schema_version"] == SCHEMA_VERSION == 1 and len(document["sites"]) == 1
    site = document["sites"][0]
    assert site["derived"]["pending_tx_changes"] == REPORT.pending_tx_changes
    assert site["aps"][0]["bands"][0]["outcome"] == "in_corridor" and site["scan"]["passes"] == 3


@pytest.mark.security("T12")
def test_external_names_are_sanitised_per_token_not_truncated_as_a_line() -> None:
    inp = golden_input()
    hostile = "AP-" + RLO + "2\x1b[31m" + "x" * 40
    snap = inp.snapshot
    renamed = with_ap(snap, replace(ap_named(snap, "AP-2"), name=hostile))
    neighbours = {k: frozenset(hostile if p == "AP-2" else p for p in v) for k, v in inp.neighbours.items()}
    neighbours = {(hostile if k == "AP-2" else k): v for k, v in neighbours.items()}
    report = analyze_site(replace(inp, snapshot=renamed, neighbours=neighbours))
    text = render_report(report)
    # The override becomes U+FFFD, the escape sequence is stripped, and the name is cut per token only.
    safe = "AP-" + chr(0xFFFD) + "2xxxx"
    assert RLO not in text and "\x1b" not in text and safe in text
    # A composed line keeps its tail: the receiver-offset line of AP-1 ends with the sanitised peer in brackets.
    offset_lines = [line for line in text.splitlines() if "disagree by" in line]
    assert any(f"[{safe}" in line and line.endswith("]") for line in offset_lines)


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
    assert "s3cr3t-pl41n" not in render_report(report) and "s3cr3t-pl41n" not in render_json([report])


def test_one_json_document_for_several_sites() -> None:
    document = json.loads(render_json([REPORT, REPORT]))
    assert [s["site_id"] for s in document["sites"]] == ["default", "default"]


def test_the_pending_tx_note_appears_on_a_roaming_check_when_a_5_ghz_change_is_pending() -> None:
    text = render_report(REPORT)
    assert REPORT.pending_tx_changes == 4
    assert f"Note: {REPORT.pending_tx_changes} pending transmit-power change(s)" in text


def test_tx_pending_note_appears_when_incomplete_and_pending() -> None:
    # Ported from tx_test.sh: the incomplete roaming verdict is printed, and the note follows it.
    text = render_report(REPORT)
    assert "Roaming Assistant" in text and "threshold not available" in text and "pending transmit-power change" in text


def test_tx_pending_note_absent_when_no_pending() -> None:
    # Ported from tx_test.sh: without a pending 5 GHz change the note does not appear.
    report = analyze_site(golden_input(skip_scan=True))
    assert report.pending_tx_changes == 0 and "pending transmit-power change" not in render_report(report)


def test_print_rec_tx_zero_sightings_flags_real_change() -> None:
    # Ported from tx_test.sh: a radio below its maximum with a both-way miss is raised and flagged.
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
    # Ported from tx_test.sh: at the maximum with a both-way miss nothing is flagged as a change.
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
    text = render_report(REPORT)
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
