"""Profile compliance for a site: every configured WLAN against its profile, pure."""

from collections.abc import Mapping, Sequence

from unifiwifioptimizer.compliance.advisories import evaluate_advisories
from unifiwifioptimizer.compliance.roaming_check import roaming_assistant_checks
from unifiwifioptimizer.compliance.rules import evaluate_rules
from unifiwifioptimizer.domain.models import WlanConfig
from unifiwifioptimizer.domain.profile import Profile, ProfileSet
from unifiwifioptimizer.domain.report import (
    CheckResult,
    CheckStatus,
    Finding,
    Severity,
    SiteCompliance,
    WlanEvaluation,
)


def evaluate_wlan(wlan: WlanConfig, profile: Profile, roaming_threshold_dbm: int | None = None) -> WlanEvaluation:
    """A disabled WLAN is reported as exactly that and nothing else: its other settings are moot."""
    if not wlan.enabled:
        disabled = CheckResult(
            code="wlan_enabled",
            subject=wlan.name,
            status=CheckStatus.FAILED,
            detail="the WLAN is disabled on the controller",
            expected="Enabled",
            actual="Disabled",
        )
        return WlanEvaluation(wlan=wlan.name, profile=profile.name, checks=(disabled,), findings=())
    checks = (*evaluate_rules(profile, wlan), *roaming_assistant_checks(profile, wlan, roaming_threshold_dbm))
    return WlanEvaluation(
        wlan=wlan.name, profile=profile.name, checks=checks, findings=evaluate_advisories(profile, wlan)
    )


RETIRED_PROFILES: Mapping[str, str] = {
    "Throughput": "it was renamed to Standard",
    "Latency": "it was removed; define it in your own profiles file with dtim_mode: custom and dtim_24/dtim_5 set to 1",
}


def _retired_hint(profile_name: str) -> str:
    reason = RETIRED_PROFILES.get(profile_name)
    return f"; {reason}" if reason else ""


def evaluate_site(
    wlans: Sequence[WlanConfig],
    mapping: Mapping[str, str],
    profiles: ProfileSet,
    roaming_thresholds_dbm: Mapping[str, int] | None = None,
) -> SiteCompliance:
    """`mapping` is the site's `wlans: {name: profile}`; iteration follows it so the report order is the
    operator's. A WLAN name that occurs twice on the controller is ambiguous and reported as such."""
    by_name: dict[str, list[WlanConfig]] = {}
    for wlan in wlans:
        by_name.setdefault(wlan.name, []).append(wlan)
    thresholds = roaming_thresholds_dbm or {}
    evaluations: list[WlanEvaluation] = []
    findings: list[Finding] = []
    for name, profile_name in mapping.items():
        profile = profiles.get(profile_name)
        candidates = by_name.get(name, [])
        if profile is None:
            findings.append(
                Finding(
                    severity=Severity.ERROR,
                    code="profile_unknown",
                    message=f"profile {profile_name!r} is not defined{_retired_hint(profile_name)}",
                    subject=name,
                )
            )
            continue
        if not candidates:
            findings.append(
                Finding(
                    severity=Severity.ERROR,
                    code="wlan_not_found",
                    message="configured WLAN does not exist on the controller; check the wlans mapping",
                    subject=name,
                )
            )
            continue
        if len(candidates) > 1:
            findings.append(
                Finding(
                    severity=Severity.ERROR,
                    code="wlan_ambiguous",
                    message=f"{len(candidates)} WLANs on the controller share this name; the mapping is ambiguous",
                    subject=name,
                )
            )
            continue
        evaluations.append(evaluate_wlan(candidates[0], profile, thresholds.get(name)))
    return SiteCompliance(evaluations=tuple(evaluations), findings=tuple(findings))
