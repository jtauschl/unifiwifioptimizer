from unifiwifioptimizer.domain.models import Band, TxPowerMode
from unifiwifioptimizer.domain.report import (
    CheckResult,
    CheckStatus,
    Finding,
    Recommendation,
    RecommendationKind,
    Severity,
    SiteCompliance,
    WlanEvaluation,
)


def recommendation(kind: RecommendationKind, current: int | None = 18, recommended: int = 14) -> Recommendation:
    return Recommendation(
        code="tx_power",
        subject="AP-1",
        band=Band.GHZ_5,
        setting="tx_power",
        current=current,
        recommended=recommended,
        kind=kind,
        reason="corridor",
    )


def check(status: CheckStatus) -> CheckResult:
    return CheckResult(code="pmf", subject="SSID-1", status=status, detail="")


def test_only_a_change_recommendation_is_a_change() -> None:
    assert recommendation(RecommendationKind.CHANGE).is_change is True
    for kind in (RecommendationKind.CONFIRMED, RecommendationKind.HELD, RecommendationKind.CONDITIONAL):
        # A disabled Min RSSI has no current value and is still not a change: the kind decides, not the values.
        assert recommendation(kind, current=None).is_change is False


def test_recommendation_defaults_leave_mode_and_headroom_unset() -> None:
    plain = recommendation(RecommendationKind.CHANGE)
    assert plain.current_mode is None and plain.unverified_headroom is False
    auto = Recommendation(
        code="tx_power",
        subject="AP-1",
        band=Band.GHZ_2,
        setting="tx_power",
        current=17,
        recommended=6,
        kind=RecommendationKind.CHANGE,
        reason="corridor",
        current_mode=TxPowerMode.AUTO,
    )
    assert auto.current_mode is TxPowerMode.AUTO


def test_finding_carries_peers_structured_and_empty_by_default() -> None:
    finding = Finding(severity=Severity.WARNING, code="coverage_gap", message="m", subject="AP-1", band=Band.GHZ_5)
    assert finding.peers == ()
    named = Finding(severity=Severity.INFO, code="x", message="m", subject="AP-1", peers=("AP-2", "AP-3"))
    assert named.peers == ("AP-2", "AP-3")


def test_site_compliance_has_failures_from_a_failed_check_or_a_site_finding() -> None:
    def site(status: CheckStatus, findings: tuple[Finding, ...] = ()) -> SiteCompliance:
        evaluation = WlanEvaluation(wlan="SSID-1", profile="Standard", checks=(check(status),), findings=())
        return SiteCompliance(evaluations=(evaluation,), findings=findings)

    for status in CheckStatus:
        assert site(status).has_failures is (status is CheckStatus.FAILED)
    missing = Finding(severity=Severity.ERROR, code="wlan_not_found", message="m", subject="SSID-2")
    assert site(CheckStatus.PASSED, (missing,)).has_failures is True
