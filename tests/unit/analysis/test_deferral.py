"""Which advice waits for which change: the mark that the text, the footer and the JSON all read."""

from dataclasses import replace

from unifiwifioptimizer.analysis.deferral import apply_deferrals
from unifiwifioptimizer.analysis.site_analyzer import analyze_site
from unifiwifioptimizer.domain.analysis import ChannelPlanMethod
from unifiwifioptimizer.domain.models import Band
from unifiwifioptimizer.domain.report import (
    MIN_RSSI,
    TX_POWER,
    BandChannelPlan,
    ChannelAssignment,
    ChannelPlanStatus,
    CheckStatus,
    Deferral,
    ExtendedChannelPlan,
    RecommendationKind,
    SiteReport,
)

from .builders import golden_input

GOLDEN = analyze_site(golden_input())
# The golden site changes the 5 GHz power of AP-1 only; AP-2..AP-4 change their 2.4 GHz power.
ALL_APS = ("AP-1", "AP-2", "AP-3", "AP-4")


def _plan(band: Band, *moves: tuple[str, int, int]) -> ExtendedChannelPlan:
    return ExtendedChannelPlan(
        bands=(
            BandChannelPlan(
                band=band,
                status=ChannelPlanStatus.RECOMMENDED,
                reason=None,
                method=ChannelPlanMethod.EXACT,
                assignments=tuple(
                    ChannelAssignment(ap=ap, current=current, proposed=proposed, width_mhz=20)
                    for ap, current, proposed in moves
                ),
                own_conflicts_before=1,
                own_conflicts_after=0,
                own_pressure_before=1,
                own_pressure_after=0,
                foreign_overlaps_before=0,
                foreign_overlaps_after=0,
                data_gaps=(),
            ),
        )
    )


def _with_failed_assistant(report: SiteReport, wlan: str) -> SiteReport:
    evaluations = tuple(
        replace(
            evaluation,
            checks=tuple(
                replace(check, status=CheckStatus.FAILED) if check.code == "roaming_assistant" else check
                for check in evaluation.checks
            ),
        )
        if evaluation.wlan == wlan
        else evaluation
        for evaluation in report.compliance.evaluations
    )
    return replace(report, compliance=replace(report.compliance, evaluations=evaluations))


def _assistant_marks(report: SiteReport, wlan: str) -> list[Deferral | None]:
    return [check.deferred_by for check in report.checks if check.subject == wlan and check.code == "roaming_assistant"]


def _defer(
    broadcasting: dict[str, tuple[str, ...]], plan: ExtendedChannelPlan | None, wants: tuple[str, ...] = ("SSID-1",)
) -> SiteReport:
    base = _with_failed_assistant(GOLDEN, "SSID-1")
    deferred = apply_deferrals(base.aps, base.compliance, broadcasting, wants, plan)
    return replace(base, aps=deferred.aps, compliance=deferred.compliance)


def test_a_5ghz_power_change_on_a_broadcasting_ap_defers_the_failed_assistant_check() -> None:
    report = _defer({"SSID-1": ALL_APS}, None)
    assert _assistant_marks(report, "SSID-1") == [Deferral.TX_CHANGE]


def test_a_power_change_on_an_ap_that_does_not_broadcast_the_wlan_leaves_the_check_actionable() -> None:
    report = _defer({"SSID-1": ("AP-2", "AP-3", "AP-4")}, None)
    assert _assistant_marks(report, "SSID-1") == [None]


def test_a_24ghz_power_change_does_not_defer_the_assistant_check() -> None:
    base = _with_failed_assistant(GOLDEN, "SSID-1")
    only_24 = tuple(
        replace(
            ap,
            bands=tuple(
                replace(
                    band,
                    recommendations=tuple(
                        replace(rec, kind=RecommendationKind.HELD) if band.band is Band.GHZ_5 else rec
                        for rec in band.recommendations
                    ),
                )
                for band in ap.bands
            ),
        )
        for ap in base.aps
    )
    deferred = apply_deferrals(only_24, base.compliance, {"SSID-1": ALL_APS}, ("SSID-1",), None)
    marks = [c.deferred_by for e in deferred.compliance.evaluations for c in e.checks if c.code == "roaming_assistant"]
    assert marks == [None]
    assert deferred.actionable_tx_5g == frozenset()


def test_a_failed_check_of_a_wlan_that_must_not_use_the_assistant_never_waits_for_a_radio_change() -> None:
    # Switching the assistant off depends on neither the power nor the channel.
    report = _defer({"SSID-1": ALL_APS}, _plan(Band.GHZ_5, ("AP-1", 44, 100)), wants=())
    assert _assistant_marks(report, "SSID-1") == [None]


def test_a_channel_move_of_a_broadcasting_ap_defers_the_check_by_the_plan() -> None:
    # Neither AP changes its 5 GHz power: only the move itself can defer the threshold.
    report = _defer({"SSID-1": ("AP-2", "AP-3")}, _plan(Band.GHZ_5, ("AP-2", 60, 36)))
    assert _assistant_marks(report, "SSID-1") == [Deferral.CHANNEL_PLAN]


def test_a_power_change_that_waits_for_the_channel_plan_hands_its_reason_to_the_check() -> None:
    # AP-1 does not move, but its band does: its power change is provisional, so the threshold is too.
    report = _defer({"SSID-1": ("AP-1",)}, _plan(Band.GHZ_5, ("AP-2", 60, 36)))
    assert _assistant_marks(report, "SSID-1") == [Deferral.CHANNEL_PLAN]


def test_a_member_whose_held_power_verdict_waits_for_the_plan_defers_the_check() -> None:
    # AP-3 and AP-4 keep their 5 GHz power (held), but the move of AP-2 makes that verdict provisional.
    report = _defer({"SSID-1": ("AP-3", "AP-4")}, _plan(Band.GHZ_5, ("AP-2", 60, 36)))
    assert _assistant_marks(report, "SSID-1") == [Deferral.CHANNEL_PLAN]


def test_a_24ghz_channel_move_leaves_the_5ghz_threshold_alone() -> None:
    report = _defer({"SSID-1": ("AP-2", "AP-3")}, _plan(Band.GHZ_2, ("AP-2", 1, 6)))
    assert _assistant_marks(report, "SSID-1") == [None]


def test_every_minimum_rssi_verdict_of_a_band_with_a_power_change_waits_for_it() -> None:
    marks = {
        (ap.name, band.band): rec.deferred_by
        for ap in GOLDEN.aps
        for band in ap.bands
        for rec in band.recommendations
        if rec.setting == MIN_RSSI
    }
    assert marks == {
        ("AP-1", Band.GHZ_2): None,
        ("AP-1", Band.GHZ_5): Deferral.TX_CHANGE,
        ("AP-2", Band.GHZ_2): Deferral.TX_CHANGE,
        ("AP-2", Band.GHZ_5): None,
        ("AP-3", Band.GHZ_2): Deferral.TX_CHANGE,
        ("AP-3", Band.GHZ_5): None,
        ("AP-4", Band.GHZ_2): Deferral.TX_CHANGE,
        ("AP-4", Band.GHZ_5): None,
    }


def test_a_channel_move_defers_power_and_minimum_rssi_of_its_band_only() -> None:
    report = _defer({"SSID-1": ALL_APS}, _plan(Band.GHZ_5, ("AP-2", 60, 36)))
    by_band = {
        band.band: {rec.setting: rec.deferred_by for rec in band.recommendations}
        for ap in report.aps
        for band in ap.bands
        if ap.name == "AP-1"
    }
    assert by_band[Band.GHZ_5] == {TX_POWER: Deferral.CHANNEL_PLAN, MIN_RSSI: Deferral.CHANNEL_PLAN}
    assert by_band[Band.GHZ_2][TX_POWER] is None


def test_only_power_changes_that_can_be_applied_now_are_reported_actionable() -> None:
    plan = _plan(Band.GHZ_5, ("AP-2", 60, 36))
    base = _with_failed_assistant(GOLDEN, "SSID-1")
    assert apply_deferrals(base.aps, base.compliance, {}, (), None).actionable_tx_5g == frozenset({"AP-1"})
    assert apply_deferrals(base.aps, base.compliance, {}, (), plan).actionable_tx_5g == frozenset()


def test_the_report_counts_follow_the_marks() -> None:
    report = _defer({"SSID-1": ALL_APS}, _plan(Band.GHZ_5, ("AP-2", 60, 36)))
    waiting_recs = [r for r in report.recommendations if r.is_change and r.deferred_by is not None]
    assert report.waiting_items == len(waiting_recs) + 1
    assert report.pending_tx_changes == sum(
        1 for r in report.recommendations if r.setting == TX_POWER and r.deferred_by is None and r.is_change
    )


def test_a_failed_check_of_a_wlan_without_broadcast_data_is_never_deferred() -> None:
    base = _with_failed_assistant(GOLDEN, "SSID-1")
    failed = [c for c in base.checks if c.code == "roaming_assistant" and c.status is CheckStatus.FAILED]
    assert len(failed) == 1
    deferred = apply_deferrals(base.aps, base.compliance, {}, ("SSID-1",), _plan(Band.GHZ_5, ("AP-1", 44, 100)))
    assert all(c.deferred_by is None for e in deferred.compliance.evaluations for c in e.checks)
