"""The site analyzer end to end on the anonymised site: ordering, offline and unparsable access points, the
scan-status findings and partial reasons, the pending count, the mesh guard, the roaming seam."""

from collections import Counter
from dataclasses import replace

import pytest

from unifiwifioptimizer.analysis.site_analyzer import analyze_site, ap_order, mesh_roles
from unifiwifioptimizer.domain.analysis import (
    BandTxOutcome,
    MissingReason,
    NeighbourMarker,
    PartialReason,
    ReadingSource,
    WlanRoamingStatus,
)
from unifiwifioptimizer.domain.models import Band, ClientSighting, FieldProblem, UnparsableDevice
from unifiwifioptimizer.domain.report import TX_POWER, RecommendationKind, Severity, SiteReport
from unifiwifioptimizer.domain.scan import BandScanStatus, ScanFailure, ScanFailureKind
from unifiwifioptimizer.rf.constants import MIN_RSSI_MAX_DBM, MIN_RSSI_MIN_DBM
from unifiwifioptimizer.rf.settings import RfSettings

from .builders import (
    ap_named,
    band_scan,
    fixture,
    fixture_snapshot,
    golden_input,
    hears,
    scan_pass,
    site_scan,
    with_ap,
    with_radio,
    with_stats,
)
from .test_roaming_targets import groups_wlan, with_groups

GOLDEN = analyze_site(golden_input())


def codes(findings) -> list[str]:  # type: ignore[no-untyped-def]
    return [f.code for f in findings]


def statuses(report: SiteReport) -> Counter[str]:
    return Counter(band.outcome.value for ap in report.aps for band in ap.bands)


def band_of(report, ap: str, band: Band):  # type: ignore[no-untyped-def]
    return next(b for a in report.aps for b in a.bands if a.name == ap and b.band is band)


def test_access_points_come_in_configuration_order_then_the_rest() -> None:
    assert ap_order({"AP-3": frozenset({"AP-4"}), "AP-1": frozenset({"AP-2"})}, fixture_snapshot()) == [
        "AP-3",
        "AP-4",
        "AP-1",
        "AP-2",
    ]
    assert [ap.name for ap in GOLDEN.aps] == ["AP-1", "AP-2", "AP-3", "AP-4"]
    assert all(ap.configured for ap in GOLDEN.aps) and GOLDEN.site_id == "default" and GOLDEN.scanning


def test_the_golden_site_outcomes_and_counts_are_pinned() -> None:
    # AP-1 2.4 GHz: auto at 17 dBm, heard at -70 → inside the Residential corridor (-73..-67): confirmed.
    one_2g = band_of(GOLDEN, "AP-1", Band.GHZ_2)
    assert (
        one_2g.outcome is BandTxOutcome.IN_CORRIDOR and one_2g.recommendations[0].kind is RecommendationKind.CONFIRMED
    )
    assert one_2g.recommendations[0].current_mode is not None and one_2g.neighbours[0].samples == 3
    # AP-3 5 GHz: AP-4 missed both ways, radio at its configured maximum 23 → coverage gap, held.
    three_5g = band_of(GOLDEN, "AP-3", Band.GHZ_5)
    assert three_5g.outcome is BandTxOutcome.NO_SIGHTING and "coverage_gap" in codes(three_5g.findings)
    assert three_5g.recommendations[0].kind is RecommendationKind.HELD
    # AP-4 2.4 GHz: own scan empty in every pass → restart suggested, partial; AP-3 at AP-4 is a scan reason.
    four_2g = band_of(GOLDEN, "AP-4", Band.GHZ_2)
    assert "radio_restart_suggested" in codes(four_2g.findings)
    three_2g = band_of(GOLDEN, "AP-3", Band.GHZ_2)
    at_four = next(row for row in three_2g.neighbours if row.peer == "AP-4")
    assert at_four.reason is MissingReason.PEER_SCAN_EMPTY and at_four.source is ReadingSource.RECIPROCITY
    assert GOLDEN.partial_reasons == (PartialReason.BAND_EMPTY,) and GOLDEN.partial
    assert statuses(GOLDEN) == Counter(
        {"in_corridor": 1, "raise_to_maximum": 1, "out_of_corridor": 3, "coverage_gap": 1, "no_sighting": 2}
    )
    # Disabled Min RSSI never counts as a change; the pending count is the TX changes alone.
    assert all(r.kind is RecommendationKind.CONDITIONAL for r in GOLDEN.recommendations if r.setting == "min_rssi")
    assert GOLDEN.pending_tx_changes == sum(
        1 for r in GOLDEN.recommendations if r.setting == "tx_power" and r.is_change
    )
    assert GOLDEN.pending_tx_changes == 4 and GOLDEN.has_changes
    assert GOLDEN.verifiable_ap_count == 4 and GOLDEN.host_key_failed_ap_count == 0


def test_the_roaming_seam_feeds_the_compliance_check_and_flags_pending_tx() -> None:
    by_wlan = {r.wlan: r for r in GOLDEN.roaming}
    assert set(by_wlan) == {"SSID-1", "SSID-2", "SSID-3", "SSID-4", "SSID-5"}
    main = by_wlan["SSID-1"]
    # Every WLAN is on `all`: AP-3 has no 5 GHz value (AP-4 both-way miss) → incomplete, no threshold.
    assert main.status is WlanRoamingStatus.INCOMPLETE and main.threshold_dbm is None
    assert main.tx_change_pending is True
    roaming_check = next(
        c
        for e in GOLDEN.compliance.evaluations
        if e.wlan == "SSID-1"
        for c in e.checks
        if c.code == "roaming_assistant"
    )
    assert roaming_check.status.value == "incomplete"


def test_an_offline_access_point_gets_one_line_no_bands_and_explains_its_neighbours_misses() -> None:
    inp = golden_input()
    offline = with_ap(inp.snapshot, replace(ap_named(inp.snapshot, "AP-2"), state_code=0))
    problems = (
        FieldProblem(
            "$.data[3].radio_table_stats[0].channel",
            "expected an integer",
            "stat/device",
            ap_named(inp.snapshot, "AP-2").mac,
        ),
        FieldProblem("$.data[3].x", "bad", "stat/device", ap_named(inp.snapshot, "AP-2").mac),
        FieldProblem(
            "$.data[5].radio_table_stats[0].channel",
            "expected an integer",
            "stat/device",
            ap_named(inp.snapshot, "AP-3").mac,
        ),
    )
    # An offline access point is not scanned (`build_targets` leaves it out), so its scan entry is absent too.
    assert inp.scan is not None
    scan = replace(inp.scan, scans=tuple(s for s in inp.scan.scans if s.ap_name != "AP-2"))
    report = analyze_site(replace(inp, snapshot=replace(offline, problems=problems), scan=scan))
    two = next(ap for ap in report.aps if ap.name == "AP-2")
    assert two.bands == () and codes(two.findings) == ["ap_offline"] and two.findings[0].severity is Severity.WARNING
    assert PartialReason.SCAN_FAILED not in report.partial_reasons
    # Only the offline AP's stats problems are dropped; its other problem and the connected AP's stay.
    assert [p.path for p in report.field_problems] == ["$.data[3].x", "$.data[5].radio_table_stats[0].channel"]
    one_2g = band_of(report, "AP-1", Band.GHZ_2)
    (row,) = one_2g.neighbours
    assert row.reason is MissingReason.PEER_OFFLINE and one_2g.outcome is BandTxOutcome.NOT_EVALUABLE
    assert "peers_not_evaluated" in codes(one_2g.findings)


def test_other_states_and_missing_states_are_analysed_normally() -> None:
    inp = golden_input()
    upgrading = with_ap(inp.snapshot, replace(ap_named(inp.snapshot, "AP-2"), state_code=4))
    report = analyze_site(replace(inp, snapshot=upgrading))
    two = next(ap for ap in report.aps if ap.name == "AP-2")
    assert two.bands != () and "ap_state" in codes(two.findings) and "4" in two.findings[0].message
    absent = with_ap(inp.snapshot, replace(ap_named(inp.snapshot, "AP-2"), state_code=None))
    two_absent = next(ap for ap in analyze_site(replace(inp, snapshot=absent)).aps if ap.name == "AP-2")
    assert two_absent.bands != () and "ap_state" not in codes(two_absent.findings)


def test_unparsable_and_unknown_access_points_are_partial_and_named_once() -> None:
    inp = golden_input()
    snap = replace(
        inp.snapshot,
        unparsable_devices=(UnparsableDevice(mac="02:00:00:00:00:77", name="Ghost", reason="$.data[9].ip: missing"),),
    )
    report = analyze_site(
        replace(inp, snapshot=snap, neighbours={**inp.neighbours, "AP-4": frozenset({"Ghost", "Phantom"})})
    )
    site_codes = codes(report.site_findings)
    assert site_codes.count("ap_unparsable") == 1 and site_codes.count("ap_not_found") == 1
    assert next(f for f in report.site_findings if f.code == "ap_not_found").subject == "Phantom"
    assert set(report.partial_reasons) == {
        PartialReason.AP_UNPARSABLE,
        PartialReason.AP_NOT_FOUND,
        PartialReason.BAND_EMPTY,
    }
    assert report.scan.unknown_names == ("Phantom",)


def test_dfs_wait_skips_the_band_with_an_info_and_the_peers_miss_is_explained() -> None:
    inp = golden_input()
    waiting = with_ap(
        inp.snapshot,
        with_stats(ap_named(inp.snapshot, "AP-2"), Band.GHZ_5, state="DFS_WAIT", channel=120, width_mhz=20),
    )
    report = analyze_site(replace(inp, snapshot=waiting))
    two_5g = band_of(report, "AP-2", Band.GHZ_5)
    assert (
        two_5g.outcome is BandTxOutcome.DFS_WAIT
        # The channel was moved onto 120 for the test, which the channel analysis reports as well.
        and codes(two_5g.findings) == ["dfs_cac", "channel_moved"]
        and "600 s" in two_5g.findings[0].message
    )
    assert two_5g.recommendations == ()
    # AP-2's own rows explain its misses by its own check; its neighbours still hold their measured readings.
    assert [(row.peer, row.rssi_dbm, row.reason) for row in two_5g.neighbours] == [
        ("AP-1", None, MissingReason.SELF_DFS_WAIT),
        ("AP-3", None, MissingReason.SELF_DFS_WAIT),
    ]
    at_one = next(row for row in band_of(report, "AP-1", Band.GHZ_5).neighbours if row.peer == "AP-2")
    assert at_one.rssi_dbm == -72 and at_one.reason is None


def test_scan_failures_make_the_run_partial_and_count_verifiable_access_points() -> None:
    inp = golden_input()
    assert inp.scan is not None
    scans = list(inp.scan.scans)
    host_key = replace(scans[0], passes=(ScanFailure(kind=ScanFailureKind.HOST_KEY_UNKNOWN, detail="no key"),) * 3)
    timeout = replace(scans[1], passes=(ScanFailure(kind=ScanFailureKind.TIMEOUT, detail="slow"), *scans[1].passes[1:]))
    report = analyze_site(replace(inp, scan=replace(inp.scan, scans=(host_key, timeout, *scans[2:]))))
    one = next(ap for ap in report.aps if ap.name == "AP-1")
    assert "scan_failed" in codes(one.findings) and PartialReason.SCAN_FAILED in report.partial_reasons
    two = next(ap for ap in report.aps if ap.name == "AP-2")
    assert "scan_partial" in codes(two.findings)
    assert report.verifiable_ap_count == 3 and report.host_key_failed_ap_count == 1
    assert (
        report.scan.failures_by_ap["AP-1"] == (ScanFailureKind.HOST_KEY_UNKNOWN,) * 3
        and report.scan.successes_by_ap["AP-2"] == 2
    )


def test_one_pass_that_reached_authentication_verifies_the_access_point_despite_a_timeout() -> None:
    inp = golden_input()
    assert inp.scan is not None
    scans = list(inp.scan.scans)
    mixed = replace(
        scans[0],
        passes=(
            ScanFailure(kind=ScanFailureKind.TIMEOUT, detail="slow"),
            ScanFailure(kind=ScanFailureKind.AUTHENTICATION, detail="denied"),
            ScanFailure(kind=ScanFailureKind.AUTHENTICATION, detail="denied"),
        ),
    )
    mismatched = [
        replace(s, passes=(ScanFailure(kind=ScanFailureKind.HOST_KEY_MISMATCH, detail="changed"),) * 3)
        for s in scans[1:]
    ]
    report = analyze_site(replace(inp, scan=replace(inp.scan, scans=(mixed, *mismatched))))
    # AP-1's host key matched before the authentication failed: verified; the other three are host-key failures.
    assert report.verifiable_ap_count == 1 and report.host_key_failed_ap_count == 3
    assert report.partial_reasons == (PartialReason.SCAN_FAILED,)


@pytest.mark.parametrize(
    ("status", "reason", "message"),
    [
        (BandScanStatus.FAILED, PartialReason.BAND_FAILED, "every scan attempt on this band failed"),
        (BandScanStatus.INTERFACE_DOWN, PartialReason.INTERFACE_DOWN, "`scan_interface_toggle` is off"),
        (BandScanStatus.NO_RADIO, PartialReason.BAND_FAILED, "found no scan interface for this band"),
    ],
)
def test_a_failed_down_or_missing_scan_interface_is_a_partial_result_with_its_own_line(
    status: BandScanStatus, reason: PartialReason, message: str
) -> None:
    inp = golden_input()
    assert inp.scan is not None
    broken = tuple(scan_pass(two=band_scan(Band.GHZ_2, (), status)) for _ in range(3))
    scans = tuple(replace(s, passes=broken) if s.ap_name == "AP-1" else s for s in inp.scan.scans)
    report = analyze_site(replace(inp, scan=replace(inp.scan, scans=scans)))
    one_2g = band_of(report, "AP-1", Band.GHZ_2)
    unusable = next(f for f in one_2g.findings if f.code == "scan_unusable")
    assert unusable.severity is Severity.WARNING and message in unusable.message and unusable.band is Band.GHZ_2
    assert reason in report.partial_reasons and report.partial_reasons.count(reason) == 1
    assert "scan_unusable" not in codes(band_of(report, "AP-1", Band.GHZ_5).findings)


def test_access_points_sharing_a_name_are_named_with_their_macs_and_left_out() -> None:
    payload = fixture("stat_device.json")
    three = next(d for d in payload["data"] if d.get("name") == "AP-3")
    twin = {**three, "mac": "02:00:00:00:00:77", "_id": "000000000000000000000077"}
    inp = golden_input()
    snap = fixture_snapshot(extra_devices=[twin])
    report = analyze_site(replace(inp, snapshot=replace(inp.snapshot, access_points=snap.access_points)))
    duplicate = next(f for f in report.site_findings if f.code == "ap_name_duplicate")
    assert duplicate.severity is Severity.ERROR and duplicate.subject == "AP-3"
    assert three["mac"] in duplicate.message and "02:00:00:00:00:77" in duplicate.message
    assert [ap.name for ap in report.aps] == ["AP-1", "AP-2", "AP-4"]
    assert PartialReason.AP_NAME_DUPLICATE in report.partial_reasons and "ap_not_found" not in codes(
        report.site_findings
    )
    # The configured neighbour AP-3 is an unknown, blocking peer for AP-2 and AP-4, not a reading.
    at_two = next(row for row in band_of(report, "AP-2", Band.GHZ_5).neighbours if row.peer == "AP-3")
    assert at_two.rssi_dbm is None and at_two.reason is MissingReason.PEER_UNKNOWN
    assert report.scan.unknown_names == ()


def test_skipping_the_scan_leaves_the_controller_side_and_one_info() -> None:
    report = analyze_site(golden_input(skip_scan=True))
    assert codes(report.site_findings)[0] == "scan_skipped" and report.scan.skipped and not report.scanning
    assert set(codes(report.site_findings)) == {"scan_skipped", "neighbours_asymmetric"}
    assert all(b.outcome is BandTxOutcome.SCAN_SKIPPED for ap in report.aps for b in ap.bands)
    assert report.recommendations == () and report.partial_reasons == ()
    assert report.compliance.evaluations and report.roaming


def test_the_mesh_guard_covers_child_and_parent_and_names_an_unresolved_parent() -> None:
    inp = golden_input()
    child = replace(
        ap_named(inp.snapshot, "AP-3"), uplink_type="wireless", uplink_mac=ap_named(inp.snapshot, "AP-2").mac
    )
    roles = mesh_roles(with_ap(inp.snapshot, child))
    assert roles.children == {"AP-3"} and roles.parents == {"AP-2"} and roles.unresolved_children == frozenset()
    by_bssid = replace(child, uplink_mac=ap_named(inp.snapshot, "AP-2").vaps[0].bssid)
    assert mesh_roles(with_ap(inp.snapshot, by_bssid)).parents == {"AP-2"}
    lost = replace(child, uplink_mac="02:00:00:00:00:99")
    report = analyze_site(replace(inp, snapshot=with_ap(inp.snapshot, lost)))
    three = next(ap for ap in report.aps if ap.name == "AP-3")
    assert "mesh_parent_unresolved" in codes(three.findings)
    guarded = analyze_site(replace(inp, snapshot=with_ap(inp.snapshot, child)))
    for ap in guarded.aps:
        if ap.name in ("AP-2", "AP-3"):
            for band in ap.bands:
                for rec in band.recommendations:
                    assert not (rec.setting == "tx_power" and rec.current is not None and rec.recommended < rec.current)


def test_asymmetric_neighbours_are_evaluated_both_ways_and_named() -> None:
    inp = golden_input()
    report = analyze_site(replace(inp, neighbours={"AP-1": frozenset({"AP-2"}), "AP-3": frozenset({"AP-2", "AP-4"})}))
    pairs = [(f.subject, f.peers) for f in report.site_findings if f.code == "neighbours_asymmetric"]
    assert pairs == [("AP-1", ("AP-2",)), ("AP-3", ("AP-2",)), ("AP-3", ("AP-4",))]
    assert [c.peer for c in band_of(report, "AP-2", Band.GHZ_2).neighbours] == ["AP-1", "AP-3"]
    # A pair with an unknown name is reported as `ap_not_found` only, not as asymmetric on top.
    ghost = analyze_site(replace(inp, neighbours={**inp.neighbours, "AP-4": frozenset({"Ghost"})}))
    asymmetric = [f for f in ghost.site_findings if f.code == "neighbours_asymmetric"]
    assert "ap_not_found" in codes(ghost.site_findings) and not any("Ghost" in f.peers for f in asymmetric)


def test_a_6_ghz_radio_is_detected_not_evaluated() -> None:
    inp = golden_input()
    payload = fixture("stat_device.json")
    six = next(d for d in payload["data"] if d["type"] == "uap")
    six["radio_table"].append({**six["radio_table"][1], "radio": "6e", "name": "rai1", "channel": 37, "ht": "80"})
    from unifiwifioptimizer.adapters.unifi import parse

    ap = parse.parse_devices({"data": [six]}).access_points[0]
    report = analyze_site(replace(inp, snapshot=with_ap(inp.snapshot, ap)))
    one = next(a for a in report.aps if a.name == "AP-1")
    assert "band_detected_not_evaluated" in codes(one.findings) and [b.band for b in one.bands] == [
        Band.GHZ_2,
        Band.GHZ_5,
    ]


def test_clients_are_reported_per_radio_only_when_requested() -> None:
    without = analyze_site(golden_input())
    assert all(b.clients is None for ap in without.aps for b in ap.bands)
    inp = golden_input(clients=True)
    with_clients = analyze_site(inp)
    assert any(b.clients is not None for ap in with_clients.aps for b in ap.bands)
    assert "clients_unassignable" not in codes(with_clients.site_findings)
    assert inp.snapshot.clients is not None
    stray = ClientSighting(
        ap_mac="02:00:00:00:00:99",
        band=Band.GHZ_5,
        essid=None,
        channel=60,
        signal_dbm=-50,
        noise_dbm=None,
        satisfaction_pct=None,
        fast_transition=None,
    )
    unplaced = analyze_site(replace(inp, snapshot=replace(inp.snapshot, clients=(*inp.snapshot.clients, stray))))
    finding = next(f for f in unplaced.site_findings if f.code == "clients_unassignable")
    assert finding.message == "client sightings not placed on a radio: 1 access point not in the snapshot"


def test_the_min_rssi_ordering_advisory_fires_on_a_structural_gap_and_on_a_late_wlan_trigger() -> None:
    # Three gaps on 5 GHz: AP-1 is raised to its maximum with AP-2 still below the corridor (row 11, marker
    # `*`), AP-2 sits at its effective maximum (row 10), AP-3 is unsighted by AP-4 at the maximum (row 6). An
    # enabled Minimum RSSI on each of them gets the advisory.
    inp = golden_input()
    snap = inp.snapshot
    for name in ("AP-1", "AP-2", "AP-3"):
        snap = with_ap(snap, with_radio(ap_named(snap, name), Band.GHZ_5, min_rssi_enabled=True, min_rssi_dbm=-80))
    report = analyze_site(replace(inp, snapshot=snap))
    one_5g, two_5g, three_5g = (band_of(report, name, Band.GHZ_5) for name in ("AP-1", "AP-2", "AP-3"))
    assert (one_5g.outcome, two_5g.outcome, three_5g.outcome) == (
        BandTxOutcome.RAISE_TO_MAXIMUM,
        BandTxOutcome.COVERAGE_GAP,
        BandTxOutcome.NO_SIGHTING,
    )
    assert next(r for r in one_5g.neighbours if r.peer == "AP-2").marker is NeighbourMarker.BELOW_UNFIXABLE
    for band in (one_5g, two_5g, three_5g):
        advisory = next(f for f in band.findings if f.code == "min_rssi_before_roaming")
        assert advisory.severity is Severity.ADVISORY and "coverage gap" in advisory.message
    # The late trigger: AP-1 (20 dBm, heard at -66) and AP-2 (23 dBm, heard at -80) alone broadcast the WLAN.
    # AP-2's floor-clamped uplink value -83 is below what the controller accepts, so the WLAN threshold is -80;
    # at AP-1 it fires at -75 on the downlink, below AP-1's Minimum RSSI target of -72.
    pair = with_groups(fixture_snapshot(), ("g1", ("AP-1", "AP-2")))
    pair = with_ap(pair, with_radio(ap_named(pair, "AP-1"), Band.GHZ_5, min_rssi_enabled=True, min_rssi_dbm=-80))
    pair = with_ap(pair, with_stats(ap_named(pair, "AP-2"), Band.GHZ_5, observed_tx_dbm=23))
    pair = replace(pair, wlans=(groups_wlan("SSID-1", "g1"),))
    scan = site_scan(
        pair,
        {
            "AP-1": [hears(pair, "AP-1", **{"AP-2": {Band.GHZ_2: -70, Band.GHZ_5: -80}})],
            "AP-2": [hears(pair, "AP-2", **{"AP-1": {Band.GHZ_2: -70, Band.GHZ_5: -66}})],
        },
    )
    neighbours = {"AP-1": frozenset({"AP-2"}), "AP-2": frozenset({"AP-1"})}
    late = analyze_site(replace(inp, snapshot=pair, scan=scan, neighbours=neighbours))
    (target,) = late.roaming
    assert (target.status, target.threshold_dbm, target.limiting) == (WlanRoamingStatus.OK, -80, ("AP-2",))
    assert target.derived_dbm == -83
    advisory = next(f for f in band_of(late, "AP-1", Band.GHZ_5).findings if f.code == "min_rssi_before_roaming")
    assert "(-75 dBm at the client)" in advisory.message and "(-72 dBm)" in advisory.message
    # Both heard inside the corridor: the WLAN threshold (-75, AP-2's uplink value) fires at -70 on AP-1's
    # downlink and at -67 on AP-2's, both above the -72 targets, and no neighbour is out of reach: no advisory.
    both = with_ap(pair, with_radio(ap_named(pair, "AP-2"), Band.GHZ_5, min_rssi_enabled=True, min_rssi_dbm=-80))
    scan = site_scan(
        both,
        {
            "AP-1": [hears(both, "AP-1", **{"AP-2": {Band.GHZ_2: -70, Band.GHZ_5: -66}})],
            "AP-2": [hears(both, "AP-2", **{"AP-1": {Band.GHZ_2: -70, Band.GHZ_5: -66}})],
        },
    )
    quiet = analyze_site(replace(inp, snapshot=both, scan=scan, neighbours=neighbours))
    (target,) = quiet.roaming
    assert (target.status, target.threshold_dbm) == (WlanRoamingStatus.OK, -75)
    for name in ("AP-1", "AP-2"):
        band = band_of(quiet, name, Band.GHZ_5)
        assert band.outcome is BandTxOutcome.IN_CORRIDOR
        assert band.recommendations[1].setting == "min_rssi" and band.recommendations[1].current == -80
        assert "min_rssi_before_roaming" not in codes(band.findings)


def test_prepare_site_tx_checks_counts_zero_sightings() -> None:
    # A radio below its maximum with a both-way miss is one pending TX change.
    inp = golden_input()
    snap = inp.snapshot
    lowered = ap_named(snap, "AP-3")
    lowered = replace(
        lowered,
        radios=tuple(replace(r, configured_tx_dbm=15) if r.band is Band.GHZ_5 else r for r in lowered.radios),
        radio_stats=tuple(replace(s, observed_tx_dbm=15) if s.band is Band.GHZ_5 else s for s in lowered.radio_stats),
    )
    report = analyze_site(replace(inp, snapshot=with_ap(snap, lowered)))
    three_5g = band_of(report, "AP-3", Band.GHZ_5)
    assert three_5g.outcome is BandTxOutcome.NO_SIGHTING and three_5g.recommendations[0].is_change
    assert report.pending_tx_changes == GOLDEN.pending_tx_changes + 1


def test_prepare_site_tx_checks_zero_when_all_ok() -> None:
    # Every band in its corridor counts nothing. Every TX recommendation of the golden
    # site turned into a confirmation leaves eight TX recommendations and a pending count of zero.
    def confirmed(rec):  # type: ignore[no-untyped-def]
        if rec.setting != TX_POWER or rec.current is None:
            return rec
        return replace(rec, kind=RecommendationKind.CONFIRMED, recommended=rec.current)

    all_ok = replace(
        GOLDEN,
        aps=tuple(
            replace(
                ap, bands=tuple(replace(b, recommendations=tuple(map(confirmed, b.recommendations))) for b in ap.bands)
            )
            for ap in GOLDEN.aps
        ),
    )
    assert sum(1 for r in all_ok.recommendations if r.setting == TX_POWER) == 8 and all_ok.pending_tx_changes == 0
    assert GOLDEN.pending_tx_changes == 4


def test_clients_are_counted_against_the_min_rssi_that_can_be_set() -> None:
    # A 30 dBm client pushes the derived uplink values above the controller's upper stop.
    report = analyze_site(replace(golden_input(clients=True), rf=RfSettings(client_tx_dbm=30)))
    moved = 0
    for ap in report.aps:
        for band in ap.bands:
            if band.clients is None:
                continue
            rec = next(r for r in band.recommendations if r.setting == "min_rssi")
            assert band.clients.min_rssi_dbm == rec.recommended
            assert MIN_RSSI_MIN_DBM <= rec.recommended <= MIN_RSSI_MAX_DBM
            moved += rec.derived_dbm is not None
    assert moved


def test_a_client_between_the_set_value_and_the_derived_value_is_not_counted_below_min_rssi() -> None:
    inp = replace(golden_input(clients=True), rf=RfSettings(client_tx_dbm=30))
    assert inp.snapshot.clients is not None
    base = analyze_site(inp)
    target = next(
        (ap.name, band.band, rec)
        for ap in base.aps
        for band in ap.bands
        if band.clients is not None
        for rec in band.recommendations
        if rec.setting == "min_rssi" and rec.derived_dbm is not None and rec.derived_dbm > rec.recommended
    )
    name, band_of_target, rec = target
    assert rec.derived_dbm is not None
    stray = ClientSighting(
        ap_mac=ap_named(inp.snapshot, name).mac,
        band=band_of_target,
        essid=None,
        channel=60,
        signal_dbm=rec.derived_dbm - 1,
        noise_dbm=None,
        satisfaction_pct=None,
        fast_transition=None,
    )
    more = analyze_site(replace(inp, snapshot=replace(inp.snapshot, clients=(*inp.snapshot.clients, stray))))
    before, after = band_of(base, name, band_of_target).clients, band_of(more, name, band_of_target).clients
    assert before is not None and after is not None
    # Below the derived value, but not below the -67 that is actually set.
    assert (after.total, after.below_min_rssi) == (before.total + 1, before.below_min_rssi)


def test_a_missing_5_ghz_channel_list_is_a_site_finding_and_not_an_access_point_one() -> None:
    inp = golden_input()
    ai = inp.snapshot.settings.channel_ai
    assert ai is not None
    snapshot = replace(inp.snapshot, settings=replace(inp.snapshot.settings, channel_ai=replace(ai, channels={})))
    report = analyze_site(replace(inp, snapshot=snapshot))
    unknown = [f for f in report.site_findings if f.code == "channel_candidates_unknown"]
    assert [(f.subject, f.band) for f in unknown] == [(snapshot.site.id, Band.GHZ_5)]
    assert all(f.code != "channel_candidates_unknown" for ap in report.aps for b in ap.bands for f in b.findings)
