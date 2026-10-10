from unifiwifioptimizer.domain.models import Band
from unifiwifioptimizer.domain.report import CheckResult, CheckStatus, Recommendation, Report


def recommendation(current: int | None, recommended: int) -> Recommendation:
    return Recommendation(
        code="tx_power",
        subject="AP-1",
        band=Band.GHZ_5,
        setting="tx_power",
        current=current,
        recommended=recommended,
        reason="corridor",
    )


def check(status: CheckStatus) -> CheckResult:
    return CheckResult(code="pmf", subject="SSID-1", status=status, detail="")


def test_recommendation_is_a_change_only_when_the_value_differs() -> None:
    assert recommendation(18, 18).is_change is False
    assert recommendation(18, 14).is_change is True
    assert recommendation(None, 14).is_change is True


def test_report_has_changes_from_a_changing_recommendation_or_a_failed_check() -> None:
    confirmed = Report(site_id="default", findings=(), checks=(), recommendations=(recommendation(18, 18),))
    assert confirmed.has_changes is False
    changing = Report(site_id="default", findings=(), checks=(), recommendations=(recommendation(18, 14),))
    assert changing.has_changes is True
    for status in CheckStatus:
        report = Report(site_id="default", findings=(), checks=(check(status),), recommendations=())
        assert report.has_changes is (status is CheckStatus.FAILED)
