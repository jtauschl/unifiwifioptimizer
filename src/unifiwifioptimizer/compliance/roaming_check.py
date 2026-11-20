"""Roaming Assistant ("Handoff Suggestions (802.11v)") compliance. The profile decides only whether the
feature is expected on; the threshold comes from the site's RF analysis and is handed in by the caller
(ALGORITHM.md §7). A WLAN without 5 GHz has no band to hand a client to, so the suggestions should be off
whatever the profile says; a WLAN that only one access point broadcasts has no access point to hand a client to, so
the expectation to enable them does not apply. Both N/A cases take priority over the profile's expectation."""

from unifiwifioptimizer.compliance.rules import SIX_GHZ_DETECT_ONLY
from unifiwifioptimizer.domain.analysis import RoamingThreshold, WlanRoamingStatus
from unifiwifioptimizer.domain.models import Band, WlanConfig
from unifiwifioptimizer.domain.profile import Profile
from unifiwifioptimizer.domain.report import CheckResult, CheckStatus

CODE = "roaming_assistant"
CODE_6G = "roaming_assistant_6g"
LABEL = "Handoff Suggestions (802.11v)"
NO_5GHZ_TO_HAND_OFF_TO = "the WLAN has no 5 GHz band to hand a client to"
RSSI_NOT_SENT = "the controller did not send the RSSI threshold"


def _result(
    wlan: WlanConfig, status: CheckStatus, detail: str, expected: str | None, actual: str | None
) -> CheckResult:
    return CheckResult(code=CODE, subject=wlan.name, status=status, detail=detail, expected=expected, actual=actual)


def _actual(wlan: WlanConfig) -> str:
    if wlan.roaming_assistant_na_enabled is not True:
        return "Disabled"
    if wlan.roaming_assistant_na_rssi is None:
        return "Enabled"
    return f"Enabled, {wlan.roaming_assistant_na_rssi} dBm"


def roaming_assistant_6g_check(wlan: WlanConfig) -> CheckResult | None:
    """The 6 GHz switch (`roaming_assistant_6e_enabled`) exists only for a WLAN on 6 GHz and is reported, never
    judged: 6 GHz is detect-only, so neither the profile's expectation nor a threshold applies to it — not
    even its absence is a finding, as with the 6 GHz DTIM value."""
    if Band.GHZ_6 not in wlan.bands:
        return None
    switch = wlan.roaming_assistant_6e_enabled
    return CheckResult(
        code=CODE_6G,
        subject=wlan.name,
        status=CheckStatus.NOT_EVALUABLE,
        detail=SIX_GHZ_DETECT_ONLY,
        expected=None,
        actual=None if switch is None else ("Enabled" if switch else "Disabled"),
    )


def roaming_assistant_checks(
    profile: Profile, wlan: WlanConfig, threshold: RoamingThreshold | None
) -> tuple[CheckResult, ...]:
    """The 5 GHz judgement plus, for a WLAN on 6 GHz, the detect-only 6 GHz result."""
    six = roaming_assistant_6g_check(wlan)
    five = roaming_assistant_check(profile, wlan, threshold)
    return (five,) if six is None else (five, six)


def roaming_assistant_check(profile: Profile, wlan: WlanConfig, threshold: RoamingThreshold | None) -> CheckResult:
    """The 5 GHz judgement. `threshold` is what the site analysis derived for this WLAN: the value to set, or the
    reasons it could not; the on/off expectation is still judged when there is no value. A switched-on assistant
    without a reported RSSI is a deviation of its own, never a coerced number."""
    enabled = wlan.roaming_assistant_na_enabled
    if Band.GHZ_5 not in wlan.bands:
        if enabled is None:
            return _result(wlan, CheckStatus.NOT_APPLICABLE, "5 GHz not broadcast", None, None)
        if not enabled:
            return _result(wlan, CheckStatus.PASSED, "off without 5 GHz", "Disabled", "Disabled")
        return _result(wlan, CheckStatus.FAILED, NO_5GHZ_TO_HAND_OFF_TO, "Disabled", _actual(wlan))
    if enabled is None:
        return _result(wlan, CheckStatus.INCOMPLETE, "older API without roaming_assistant_na_*", None, None)
    actual = _actual(wlan)
    if not profile.roaming_assistant:
        if not enabled:
            return _result(wlan, CheckStatus.PASSED, "disabled per profile", "Disabled", actual)
        return _result(wlan, CheckStatus.FAILED, "enabled, but the profile expects it disabled", "Disabled", actual)
    if threshold is not None and threshold.status is WlanRoamingStatus.NOT_APPLICABLE_SINGLE_AP:
        return _result(wlan, CheckStatus.NOT_APPLICABLE, threshold.reasons[0], None, actual)
    dbm = threshold.dbm if threshold is not None else None
    # The derived threshold is the value to set, so it is part of the expectation whenever the analysis
    # produced one — also when the assistant is off or the controller reports no value.
    expected = "Enabled" if dbm is None else f"Enabled, {dbm} dBm"
    if not enabled:
        return _result(wlan, CheckStatus.FAILED, "the profile expects it enabled", expected, actual)
    if wlan.roaming_assistant_na_rssi is None:
        return _result(wlan, CheckStatus.FAILED, RSSI_NOT_SENT, expected, actual)
    if dbm is None:
        reasons = threshold.reasons if threshold is not None else ()
        detail = f"threshold not derived: {reasons[0]}" if reasons else "threshold not derived"
        return _result(wlan, CheckStatus.INCOMPLETE, detail, "Enabled", actual)
    status = CheckStatus.PASSED if wlan.roaming_assistant_na_rssi == dbm else CheckStatus.FAILED
    return _result(wlan, status, "", expected, actual)
