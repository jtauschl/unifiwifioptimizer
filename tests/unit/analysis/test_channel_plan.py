"""Evidence gating and privacy for the optional channel plan."""

import json
from collections.abc import Callable
from dataclasses import replace

import pytest

from unifiwifioptimizer.analysis.channel_plan import _foreign, extended_channel_plan
from unifiwifioptimizer.analysis.neighbors import reduce_band_passes
from unifiwifioptimizer.analysis.site_analyzer import analyze_site
from unifiwifioptimizer.cli.main import build_parser
from unifiwifioptimizer.domain.models import (
    SETTINGS_ENDPOINT,
    Band,
    DeviceState,
    FieldProblem,
    SiteSnapshot,
    TxPowerMode,
)
from unifiwifioptimizer.domain.report import BandChannelPlan, ChannelPlanStatus
from unifiwifioptimizer.domain.scan import BandScanStatus, PhyChannelPower, SiteScan
from unifiwifioptimizer.report.json import render_json
from unifiwifioptimizer.report.text import render_report
from unifiwifioptimizer.rf.settings import RfSettings

from .builders import (
    ap_named,
    band_scan,
    fixture_snapshot,
    foreign,
    golden_input,
    reading,
    scan_pass,
    site_scan,
    with_ap,
    with_radio,
    with_stats,
)


def pair_site() -> tuple[SiteSnapshot, SiteScan]:
    snap = fixture_snapshot()
    first, second = (ap_named(snap, name) for name in ("AP-1", "AP-2"))
    second = with_stats(with_radio(second, Band.GHZ_2, channel=6), Band.GHZ_2, channel=6)
    ai = snap.settings.channel_ai
    assert ai is not None
    snap = replace(
        snap, access_points=(first, second), settings=replace(snap.settings, channel_ai=replace(ai, enabled=False))
    )
    passes = {
        "AP-1": (scan_pass(band_scan(Band.GHZ_2, (reading(snap, "AP-2", Band.GHZ_2, -65),))),),
        "AP-2": (scan_pass(band_scan(Band.GHZ_2, (reading(snap, "AP-1", Band.GHZ_2, -66),))),),
    }
    return snap, site_scan(snap, passes)


def band_result(snap: SiteSnapshot, scan: SiteScan | None, band: Band = Band.GHZ_2) -> BandChannelPlan:
    return next(b for b in extended_channel_plan(snap, scan, {"AP-1": frozenset({"AP-2"})}).bands if b.band is band)


def unavailable_reason(snap: SiteSnapshot, scan: SiteScan | None, band: Band = Band.GHZ_2) -> str:
    result = band_result(snap, scan, band)
    assert result.status == "unavailable" and result.reason is not None
    return result.reason


def test_measured_pair_produces_read_only_candidate_and_no_scan_explains_unavailable() -> None:
    snap, scan = pair_site()
    plan = band_result(snap, scan)
    assert plan.status == "recommended" and plan.own_conflicts_before == 1 and plan.own_conflicts_after == 0
    assert len([a for a in plan.assignments if a.current != a.proposed]) == 1
    assert unavailable_reason(snap, None) == "neighbour scan was not run"


def test_missing_scan_and_configured_pair_without_reading_suppress_the_band() -> None:
    snap, scan = pair_site()
    assert band_result(snap, site_scan(snap, {"AP-1": scan.scans[0].passes})).status == "unavailable"
    foreign_only = site_scan(
        snap,
        {name: (scan_pass(band_scan(Band.GHZ_2, (foreign(Band.GHZ_2, -60, 1),))),) for name in ("AP-1", "AP-2")},
    )
    assert "configured neighbour pair" in unavailable_reason(snap, foreign_only)


@pytest.mark.parametrize(
    ("mutate", "reason"),
    [
        (lambda snap: with_ap(snap, with_stats(ap_named(snap, "AP-2"), Band.GHZ_2, width_mhz=40)), "40 MHz"),
        (lambda snap: with_ap(snap, with_stats(ap_named(snap, "AP-2"), Band.GHZ_2, channel=11)), "moved"),
        (lambda snap: with_ap(snap, with_stats(ap_named(snap, "AP-2"), Band.GHZ_2, width_mhz=80)), "unsupported"),
    ],
)
def test_unknown_or_unstable_geometry_suppresses_band(
    mutate: Callable[[SiteSnapshot], SiteSnapshot], reason: str
) -> None:
    snap, scan = pair_site()
    assert reason in unavailable_reason(mutate(snap), scan)


def test_channel_ai_managed_auto_radio_suppresses_band() -> None:
    snap, scan = pair_site()
    ai = snap.settings.channel_ai
    assert ai is not None
    snap = replace(snap, settings=replace(snap.settings, channel_ai=replace(ai, enabled=True)))
    assert "Channel AI" in unavailable_reason(snap, scan)


def test_candidate_blacklist_and_unknown_five_ghz_list_are_explicit_gates() -> None:
    snap, scan = pair_site()
    ai = snap.settings.channel_ai
    assert ai is not None
    no_five = replace(
        snap, settings=replace(snap.settings, channel_ai=replace(ai, channels={Band.GHZ_2: frozenset({1, 6, 11})}))
    )
    assert "no channel candidates" in unavailable_reason(no_five, scan, Band.GHZ_5)
    blacklisted = replace(ai, blacklist=ai.blacklist | {(Band.GHZ_2, 6, 20)})
    snap = replace(snap, settings=replace(snap.settings, channel_ai=blacklisted))
    assert "absent from the permitted" in unavailable_reason(snap, scan)
    blocked_block = replace(ai, blacklist=ai.blacklist | {(Band.GHZ_5, 36, 80)})
    snap = replace(snap, settings=replace(snap.settings, channel_ai=blocked_block))
    five_scan = site_scan(
        snap,
        {name: (scan_pass(five=band_scan(Band.GHZ_5, (foreign(Band.GHZ_5, -70, 44),))),) for name in ("AP-1", "AP-2")},
    )
    assert "absent from the permitted" in unavailable_reason(snap, five_scan, Band.GHZ_5)
    blocked_constituent = replace(ai, blacklist=ai.blacklist | {(Band.GHZ_5, 40, 20)})
    snap = replace(snap, settings=replace(snap.settings, channel_ai=blocked_constituent))
    assert "absent from the permitted" in unavailable_reason(snap, five_scan, Band.GHZ_5)


def test_dfs_wait_and_radio_capability_are_respected() -> None:
    snap, original_scan = pair_site()
    ap2 = ap_named(snap, "AP-2")
    waiting = with_ap(snap, with_stats(ap2, Band.GHZ_2, state="DFS_WAIT"))
    assert "DFS" in unavailable_reason(waiting, original_scan)

    ap2 = with_stats(with_radio(ap2, Band.GHZ_5, channel=44, dfs_capable=False), Band.GHZ_5, channel=44)
    snap = with_ap(snap, ap2)
    ai = snap.settings.channel_ai
    assert ai is not None
    ai = replace(ai, channels={Band.GHZ_2: frozenset({1, 6, 11}), Band.GHZ_5: frozenset({44, 60})})
    snap = replace(snap, settings=replace(snap.settings, channel_ai=ai))
    scans = site_scan(
        snap,
        {
            "AP-1": (scan_pass(five=band_scan(Band.GHZ_5, (reading(snap, "AP-2", Band.GHZ_5, -60),))),),
            "AP-2": (scan_pass(five=band_scan(Band.GHZ_5, (reading(snap, "AP-1", Band.GHZ_5, -61),))),),
        },
    )
    result = band_result(snap, scans, Band.GHZ_5)
    assert result.status == "recommended"
    assert next(a.proposed for a in result.assignments if a.ap == "AP-2") == 44


def test_more_than_128_radios_are_rejected_before_pair_search() -> None:
    snap, scan = pair_site()
    template = ap_named(snap, "AP-1")

    def clones(count: int) -> SiteSnapshot:
        return replace(
            snap,
            access_points=tuple(
                replace(template, name=f"AP-{i:03d}", mac=f"02:00:00:00:01:{i:02x}") for i in range(count)
            ),
        )

    assert "bounded planner size" in unavailable_reason(clones(129), scan)
    # 128 is inside the limit: the band is rejected for another reason (no scans for the clones), not its size.
    assert "bounded planner size" not in unavailable_reason(clones(128), scan)


def test_incomplete_site_inventory_suppresses_site_wide_plan() -> None:
    snap, scan = pair_site()
    duplicate = replace(ap_named(snap, "AP-2"), name="AP-1")
    assert "not unique" in unavailable_reason(replace(snap, access_points=(*snap.access_points, duplicate)), scan)
    unknown = replace(scan, unknown_names=("AP-missing",))
    assert "absent from the controller" in unavailable_reason(snap, unknown)


def test_foreign_bssid_is_median_deduplicated_and_frequency_tie_is_counted_without_identity() -> None:
    snap, _ = pair_site()
    foreign_a = foreign(Band.GHZ_2, -60, 1)
    foreign_tie = foreign(Band.GHZ_2, -70, 6, 2)
    passes = []
    for rssi, channel in ((-60, 6), (-66, 11), (-62, 1)):
        passes.append(
            scan_pass(
                band_scan(
                    Band.GHZ_2,
                    (
                        replace(foreign_a, rssi_dbm=rssi),
                        replace(foreign_tie, frequency_mhz=foreign(Band.GHZ_2, -70, channel, 2).frequency_mhz),
                    ),
                )
            )
        )
    scan = site_scan(snap, {"AP-1": passes})
    usage = reduce_band_passes(scan.scan_of(ap_named(snap, "AP-1").mac), Band.GHZ_2)
    obs, gaps = _foreign(usage, Band.GHZ_2, frozenset(snap.bssids.entries))
    assert obs == ((1, -62),) and gaps == 1


def test_extended_output_is_additive_and_hides_bssid_and_ssid() -> None:
    inp = golden_input()
    report = analyze_site(replace(inp, extended=True))
    text, encoded = render_report(report), render_json([report])
    data = json.loads(encoded)["sites"][0]["extended_channel_plan"]
    assert "Extended channel plan" in text
    assert data["bands"][0]["status"] == "unavailable"
    assert "02:00:00:00:ff" not in text + encoded
    assert "SSID-1" not in json.dumps(data)
    no_scan = analyze_site(replace(golden_input(skip_scan=True), extended=True))
    assert no_scan.extended_channel_plan is not None
    assert all(b.status == "unavailable" for b in no_scan.extended_channel_plan.bands)


def test_a_populated_plan_carries_foreign_counts_but_neither_bssid_nor_ssid() -> None:
    snap, _ = pair_site()
    neighbour = replace(foreign(Band.GHZ_2, -55, 6, 7), ssid="Neighbour-Secret-Net")
    own_one = reading(snap, "AP-2", Band.GHZ_2, -65)
    own_two = reading(snap, "AP-1", Band.GHZ_2, -66)
    scan = site_scan(
        snap,
        {
            "AP-1": (scan_pass(band_scan(Band.GHZ_2, (own_one, neighbour))),),
            "AP-2": (scan_pass(band_scan(Band.GHZ_2, (own_two, neighbour))),),
        },
    )
    report = analyze_site(
        replace(golden_input(), snapshot=snap, scan=scan, neighbours={"AP-1": frozenset({"AP-2"})}, extended=True)
    )
    plan = next(b for b in report.extended_channel_plan.bands if b.band is Band.GHZ_2)  # type: ignore[union-attr]
    assert plan.status == "recommended" and plan.foreign_overlaps_before == 2
    exposed = render_report(report) + render_json([report])
    for secret in (neighbour.bssid, "Neighbour-Secret-Net"):
        assert secret not in exposed


def test_ap_setup_groups_actions_and_defers_every_radio_on_a_changed_band() -> None:
    snap, scan = pair_site()
    inp = replace(
        golden_input(),
        snapshot=snap,
        scan=scan,
        neighbours={"AP-1": frozenset({"AP-2"})},
        extended=True,
    )
    report = analyze_site(inp)
    text = render_report(report, width=None)
    setup = text.split("  AP setup — current snapshot", 1)[1].split("  WLAN       ", 1)[0]
    assert text.index("  AP setup — current snapshot") < text.index("  WLAN       ")
    assert "Apply the complete site-wide candidate channel assignment for 2.4 GHz" in setup
    assert "After a TX change" not in setup
    first = setup.split("  AP AP-1", 1)[1].split("  AP AP-2", 1)[0]
    second = setup.split("  AP AP-2", 1)[1]
    assert "ch 6/20 MHz (auto) → set fixed ch 1/20 MHz (site-wide candidate)" in first
    assert "ch 6/20 MHz; keep in site-wide plan" in second
    for block in (first, second):
        two = block.split("    2.4 GHz", 1)[1].split("    5 GHz", 1)[0]
        assert "Transmit Power" in two and "reassess after channel changes" in two
        assert "Minimum RSSI" in two and "reassess after channel changes" in two
        assert "set to Custom" not in two
    assert "5 GHz channel plan unavailable" in setup
    assert "disabled (if enabled:" in first


@pytest.mark.parametrize("rf", [RfSettings(), RfSettings(client_tx_dbm=18, client_tx_dbm_5g_upper=20)])
def test_5g_channel_move_defers_roaming_advice_with_or_without_client_power_override(rf: RfSettings) -> None:
    snap, _ = pair_site()
    second = with_stats(with_radio(ap_named(snap, "AP-2"), Band.GHZ_5, channel=44), Band.GHZ_5, channel=44)
    snap = with_ap(snap, second)
    scan = site_scan(
        snap,
        {
            "AP-1": (scan_pass(band_scan(Band.GHZ_5, (reading(snap, "AP-2", Band.GHZ_5, -65),))),),
            "AP-2": (scan_pass(band_scan(Band.GHZ_5, (reading(snap, "AP-1", Band.GHZ_5, -66),))),),
        },
    )
    report = analyze_site(
        replace(
            golden_input(),
            snapshot=snap,
            scan=scan,
            neighbours={"AP-1": frozenset({"AP-2"})},
            rf=rf,
            extended=True,
        )
    )
    assert report.extended_channel_plan is not None
    assert next(b for b in report.extended_channel_plan.bands if b.band is Band.GHZ_5).has_changes
    text = render_report(report, width=None)
    assert "re-run before using TX, Minimum RSSI or WLAN Roaming Assistant advice on those bands" in text


def test_ap_setup_pins_an_unchanged_auto_radio_in_the_candidate_plan() -> None:
    snap, scan = pair_site()
    auto = with_ap(snap, with_radio(ap_named(snap, "AP-2"), Band.GHZ_2, channel=None))
    report = analyze_site(
        replace(
            golden_input(),
            snapshot=auto,
            scan=scan,
            neighbours={"AP-1": frozenset({"AP-2"})},
            extended=True,
        )
    )
    setup = render_report(report, width=None).split("  AP setup — current snapshot", 1)[1].split("  WLAN       ", 1)[0]
    assert "ch 6/20 MHz (auto); set fixed ch 6 to keep the site-wide plan" in setup


def test_ap_setup_preserves_unavailable_states_and_tx_sequence() -> None:
    report = analyze_site(replace(golden_input(), extended=True))
    setup = render_report(report, width=None).split("  AP setup — current snapshot", 1)[1].split("  WLAN       ", 1)[0]
    assert "2.4 GHz channel plan unavailable: Channel AI manages an automatic radio" in setup
    assert "5 GHz channel plan unavailable: Channel AI manages an automatic radio" in setup
    assert "After a TX change, re-run before setting Minimum RSSI" in setup
    assert "set to 10 dBm" in setup
    assert "17 dBm effective (auto mode), configured 6 dBm is stale" in setup
    assert "18 dBm effective, configured 24 dBm (regulatory cap)" in setup
    assert "disabled; reassess after the TX change" in setup
    assert "site-wide candidate" not in setup


def test_ap_setup_does_not_turn_no_improvement_or_offline_data_into_actions() -> None:
    snap, scan = pair_site()
    report = analyze_site(
        replace(
            golden_input(),
            snapshot=snap,
            scan=scan,
            neighbours={"AP-1": frozenset({"AP-2"})},
            extended=True,
        )
    )
    assert report.extended_channel_plan is not None
    first, second = report.extended_channel_plan.bands
    fake_assignment = replace(first, status=ChannelPlanStatus.NO_IMPROVEMENT)
    offline = replace(report.aps[1], state=DeviceState.DISCONNECTED, bands=())
    report = replace(
        report,
        aps=(report.aps[0], offline),
        extended_channel_plan=replace(report.extended_channel_plan, bands=(fake_assignment, second)),
    )
    setup = render_report(report, width=None).split("  AP setup — current snapshot", 1)[1].split("  WLAN       ", 1)[0]
    assert "2.4 GHz: no measured own-AP channel improvement" in setup
    assert "no channel change proposed" in setup
    assert "offline — no radio statistics\n    no evaluated radios" in setup
    assert "site-wide candidate" not in setup
    assert "→ ch 1/20 MHz" not in setup


def test_power_opportunity_is_a_trial_not_an_automatic_channel_change() -> None:
    snap, _ = pair_site()
    table = PhyChannelPower(
        phy_index=2,
        current_frequency_mhz=5300,
        limits=tuple((channel, 23.0) for channel in (52, 56, 60, 64))
        + tuple((channel, 30.0) for channel in (100, 104, 108, 112, 116, 120, 124, 128)),
    )
    ap1_pass = scan_pass(five=band_scan(Band.GHZ_5, (reading(snap, "AP-2", Band.GHZ_5, -70),)))
    ap2_pass = replace(scan_pass(five=band_scan(Band.GHZ_5, (reading(snap, "AP-1", Band.GHZ_5, -72),))), power_5g=table)
    scan = site_scan(snap, {"AP-1": (ap1_pass,), "AP-2": (ap2_pass,)})
    result = band_result(snap, scan, Band.GHZ_5)
    assert result.status == "no_improvement" and not result.has_changes
    assert len(result.power_opportunities) == 1
    trial = result.power_opportunities[0]
    assert (trial.ap, trial.current_channel, trial.candidate_channel) == ("AP-2", 60, 100)
    assert (trial.current_dbm, trial.candidate_ceiling_dbm) == (18, 24)

    inconsistent = replace(table, phy_index=3)
    changed_scan = site_scan(snap, {"AP-1": (ap1_pass,), "AP-2": (ap2_pass, replace(ap2_pass, power_5g=inconsistent))})
    assert not band_result(snap, changed_scan, Band.GHZ_5).power_opportunities
    empty = site_scan(
        snap,
        {
            "AP-1": (replace(ap1_pass, bands=(band_scan(Band.GHZ_5, status=BandScanStatus.EMPTY),)),),
            "AP-2": (ap2_pass,),
        },
    )
    assert band_result(snap, empty, Band.GHZ_5).status == "unavailable"


@pytest.mark.security("T12")
def test_extended_text_sanitises_external_ap_names() -> None:
    inp = golden_input()
    hostile = "AP-" + chr(0x202E) + "2\x1b[31m"
    renamed = with_ap(inp.snapshot, replace(ap_named(inp.snapshot, "AP-2"), name=hostile))
    neighbours = {
        (hostile if name == "AP-2" else name): frozenset(hostile if peer == "AP-2" else peer for peer in peers)
        for name, peers in inp.neighbours.items()
    }
    report = analyze_site(replace(inp, snapshot=renamed, neighbours=neighbours, extended=True))
    text = render_report(report)
    assert "Extended channel plan" in text and "\x1b" not in text and chr(0x202E) not in text
    assert chr(0x202E) not in render_json([report])


def test_cli_accepts_extended_with_json_and_no_scan() -> None:
    args = build_parser().parse_args(["run", "--extended", "--json", "--no-scan"])
    assert args.extended and args.json and args.no_scan


def _fixed_pair(snap: SiteSnapshot) -> SiteSnapshot:
    """Both radios pinned to a channel: the plan does not depend on Channel AI for them."""
    return with_ap(
        with_ap(snap, with_radio(ap_named(snap, "AP-1"), Band.GHZ_2, channel=6)),
        with_radio(ap_named(snap, "AP-2"), Band.GHZ_2, channel=6),
    )


def test_a_missing_channel_ai_record_suppresses_a_band_with_an_automatic_radio_only() -> None:
    snap, scan = pair_site()
    without_ai = replace(snap, settings=replace(snap.settings, channel_ai=None))
    assert "no Channel AI state" in unavailable_reason(without_ai, scan)
    assert band_result(_fixed_pair(without_ai), scan).status == "recommended"


def test_a_settings_field_problem_means_the_channel_ai_state_is_uncertain() -> None:
    snap, scan = pair_site()
    unreadable = FieldProblem("$.data[3].enabled", "not a boolean", endpoint=SETTINGS_ENDPOINT)
    assert "Channel AI state is uncertain" in unavailable_reason(replace(snap, problems=(unreadable,)), scan)
    unrelated = FieldProblem("$.data[3].name", "bad", endpoint="stat/device")
    assert band_result(replace(snap, problems=(unrelated,)), scan).status == "recommended"


def test_an_offline_access_point_is_named_and_blocks_the_plan_when_a_neighbour_depends_on_it() -> None:
    snap, scan = pair_site()
    offline = replace(ap_named(fixture_snapshot(), "AP-3"), state_code=0)
    with_offline = replace(snap, access_points=(*snap.access_points, offline))
    plan = extended_channel_plan(with_offline, scan, {"AP-1": frozenset({"AP-2"})})
    band = next(b for b in plan.bands if b.band is Band.GHZ_2)
    assert band.status == "recommended" and "1 offline access point radio(s) are not planned" in band.data_gaps
    blocked = extended_channel_plan(with_offline, scan, {"AP-1": frozenset({"AP-2", "AP-3"})})
    reason = next(b.reason for b in blocked.bands if b.band is Band.GHZ_2)
    assert reason == "a configured neighbour of a participating access point is offline"


def test_a_foreign_bssid_needs_a_strict_majority_on_one_frequency() -> None:
    snap, _ = pair_site()

    def observed(channels: tuple[int, ...]) -> tuple[tuple[tuple[int, int], ...], int]:
        passes = [scan_pass(band_scan(Band.GHZ_2, (foreign(Band.GHZ_2, -60, channel, 2),))) for channel in channels]
        scan = site_scan(snap, {"AP-1": passes})
        usage = reduce_band_passes(scan.scan_of(ap_named(snap, "AP-1").mac), Band.GHZ_2)
        return _foreign(usage, Band.GHZ_2, frozenset(snap.bssids.entries))

    assert observed((1, 1, 6, 6)) == ((), 1)
    assert observed((1, 1, 1, 6)) == (((1, -60),), 0)


def test_an_access_point_excluded_from_channel_ai_does_not_block_the_band() -> None:
    snap, scan = pair_site()
    ai = snap.settings.channel_ai
    assert ai is not None
    managed = replace(snap, settings=replace(snap.settings, channel_ai=replace(ai, enabled=True)))
    assert "Channel AI manages" in unavailable_reason(managed, scan)
    excluded = replace(
        snap,
        settings=replace(
            snap.settings,
            channel_ai=replace(ai, enabled=True, excluded_devices=frozenset({ap_named(snap, "AP-1").mac})),
        ),
    )
    assert band_result(excluded, scan).status == "recommended"


def _power_scan(snap: SiteSnapshot, frequency_mhz: int = 5300) -> SiteScan:
    table = PhyChannelPower(
        phy_index=2,
        current_frequency_mhz=frequency_mhz,
        limits=tuple((channel, 23.0) for channel in (52, 56, 60, 64))
        + tuple((channel, 30.0) for channel in (100, 104, 108, 112, 116, 120, 124, 128)),
    )
    ap1_pass = scan_pass(five=band_scan(Band.GHZ_5, (reading(snap, "AP-2", Band.GHZ_5, -70),)))
    ap2_pass = replace(scan_pass(five=band_scan(Band.GHZ_5, (reading(snap, "AP-1", Band.GHZ_5, -72),))), power_5g=table)
    return site_scan(snap, {"AP-1": (ap1_pass,), "AP-2": (ap2_pass,)})


@pytest.mark.parametrize(
    ("mode", "configured", "trial"),
    [
        (TxPowerMode.CUSTOM, 24, True),
        (TxPowerMode.CUSTOM, 6, False),
        (TxPowerMode.AUTO, 6, True),
        (TxPowerMode.HIGH, 6, True),
        (TxPowerMode.MEDIUM, 24, False),
        (TxPowerMode.LOW, 24, False),
    ],
)
def test_the_configured_power_only_caps_the_ceilings_in_custom_mode(
    mode: TxPowerMode, configured: int, trial: bool
) -> None:
    snap, _ = pair_site()
    changed = with_ap(
        snap, with_radio(ap_named(snap, "AP-2"), Band.GHZ_5, tx_power_mode=mode, configured_tx_dbm=configured)
    )
    result = band_result(changed, _power_scan(changed), Band.GHZ_5)
    assert bool(result.power_opportunities) is trial


def test_a_power_table_for_another_frequency_than_the_controller_reports_is_unknown() -> None:
    snap, _ = pair_site()
    matching = band_result(snap, _power_scan(snap), Band.GHZ_5)
    assert matching.power_opportunities and "1 radio(s) lack calibrated channel-power evidence" in matching.data_gaps
    # The AP's table says it serves channel 52 while the controller reports channel 60.
    other = band_result(snap, _power_scan(snap, 5260), Band.GHZ_5)
    assert not other.power_opportunities and "2 radio(s) lack calibrated channel-power evidence" in other.data_gaps
