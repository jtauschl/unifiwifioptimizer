"""WiFi Speed Limit: the speed-limit profile a WLAN uses, listed with its caps and never judged — a cap is a
policy of the site, and no value is right for every WLAN."""

from collections.abc import Sequence

from unifiwifioptimizer.domain.models import UserGroup, WlanConfig
from unifiwifioptimizer.domain.report import CheckResult, CheckStatus

CODE = "speed_limit"
LABEL = "WiFi Speed Limit"
NOTE = "caps each client's rate on this WLAN; the right cap depends on the site"


def _rate(kbps: int | None) -> str:
    if kbps is None:
        return "unlimited"
    return f"{kbps / 1000:g} Mbit/s"


def speed_limit_check(wlan: WlanConfig, groups: Sequence[UserGroup]) -> CheckResult:
    group = next((g for g in groups if g.id == wlan.usergroup_id), None) if wlan.usergroup_id is not None else None
    if group is None:
        shown = None
    elif group.down_kbps is None and group.up_kbps is None:
        shown = "Off"
    else:
        shown = f"On: {group.name}, {_rate(group.down_kbps)} down, {_rate(group.up_kbps)} up"
    return CheckResult(code=CODE, subject=wlan.name, status=CheckStatus.NOT_PRESCRIBED, detail=NOTE, actual=shown)
