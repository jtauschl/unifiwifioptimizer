"""Advice that rests on a setting another recommendation changes first is marked, not dropped: after a channel
move or a transmit-power change the effective power, the neighbour readings and with them Minimum RSSI and the
Roaming Assistant threshold are stale (docs/ALGORITHM.md §7 and §8). The renderers and the JSON read the mark."""

from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass, replace

from unifiwifioptimizer.domain.models import Band
from unifiwifioptimizer.domain.report import (
    MIN_RSSI,
    TX_POWER,
    ApReport,
    BandReport,
    CheckResult,
    CheckStatus,
    Deferral,
    ExtendedChannelPlan,
    SiteCompliance,
)

ROAMING_ASSISTANT = "roaming_assistant"


@dataclass(frozen=True, slots=True)
class Deferred:
    aps: tuple[ApReport, ...]
    compliance: SiteCompliance
    # Access points whose 5 GHz transmit-power change can be applied now.
    actionable_tx_5g: frozenset[str]


def apply_deferrals(
    aps: Sequence[ApReport],
    compliance: SiteCompliance,
    broadcasting: Mapping[str, Collection[str]],
    wants_handoff: Collection[str],
    plan: ExtendedChannelPlan | None,
) -> Deferred:
    moved_bands = frozenset(item.band for item in plan.bands if item.has_changes) if plan is not None else frozenset()
    moved_5g = (
        frozenset(
            a.ap for item in plan.bands if item.band is Band.GHZ_5 for a in item.assignments if a.current != a.proposed
        )
        if plan is not None and Band.GHZ_5 in moved_bands
        else frozenset()
    )
    marked = tuple(replace(ap, bands=tuple(_band(band, moved_bands) for band in ap.bands)) for ap in aps)
    changing: set[str] = set()
    blocked: set[str] = set()
    actionable: set[str] = set()
    for ap in marked:
        for band in ap.bands:
            for rec in band.recommendations:
                if rec.setting != TX_POWER or rec.band is not Band.GHZ_5:
                    continue
                # A verdict of any kind is provisional after a channel move, and the threshold follows it.
                if rec.deferred_by is Deferral.CHANNEL_PLAN:
                    blocked.add(ap.name)
                if rec.is_change:
                    changing.add(ap.name)
                    if rec.deferred_by is None:
                        actionable.add(ap.name)

    def reason(wlan: str) -> Deferral | None:
        if wlan not in broadcasting or wlan not in wants_handoff:
            return None
        members = set(broadcasting[wlan])
        if members & moved_5g or members & blocked:
            return Deferral.CHANNEL_PLAN
        if members & changing:
            return Deferral.TX_CHANGE
        return None

    def mark(wlan: str, check: CheckResult) -> CheckResult:
        if check.code != ROAMING_ASSISTANT or check.status is not CheckStatus.FAILED:
            return check
        return replace(check, deferred_by=reason(wlan))

    evaluations = tuple(
        replace(evaluation, checks=tuple(mark(evaluation.wlan, check) for check in evaluation.checks))
        for evaluation in compliance.evaluations
    )
    return Deferred(marked, replace(compliance, evaluations=evaluations), frozenset(actionable))


def _band(band: BandReport, moved: frozenset[Band]) -> BandReport:
    """After a channel move every transmit-power and Minimum RSSI verdict of the band is provisional; after a
    transmit-power change only the Minimum RSSI verdict is (it follows the effective power)."""
    if band.band in moved:
        return replace(
            band,
            recommendations=tuple(
                replace(rec, deferred_by=Deferral.CHANNEL_PLAN) if rec.setting in (TX_POWER, MIN_RSSI) else rec
                for rec in band.recommendations
            ),
        )
    if not any(rec.setting == TX_POWER and rec.is_change for rec in band.recommendations):
        return band
    return replace(
        band,
        recommendations=tuple(
            replace(rec, deferred_by=Deferral.TX_CHANGE) if rec.setting == MIN_RSSI else rec
            for rec in band.recommendations
        ),
    )
