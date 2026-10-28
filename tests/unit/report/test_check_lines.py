"""How a WLAN check row reads: the value column, and the line under a setting that is listed but not judged."""

from unifiwifioptimizer.domain.report import CheckResult, CheckStatus
from unifiwifioptimizer.report.text import _check_line


def check(status: CheckStatus, **fields: str | None) -> CheckResult:
    return CheckResult(code="mac_filter", subject="SSID-1", status=status, **{"detail": "", **fields})  # type: ignore[arg-type]


def test_a_setting_the_profile_does_not_set_shows_its_value_and_what_it_does_on_one_line() -> None:
    lines = _check_line(check(CheckStatus.NOT_PRESCRIBED, actual="Disabled", detail="adds little security"))
    assert lines == ["    · MAC Address Filter                   Disabled (not set by profile: adds little security)"]


def test_an_unset_setting_the_controller_did_not_send_says_so() -> None:
    lines = _check_line(check(CheckStatus.NOT_PRESCRIBED, actual=None, detail="adds little security"))
    assert lines == [
        "    · MAC Address Filter                   not sent by the controller "
        "(not set by profile: adds little security)"
    ]


def test_a_setting_that_does_not_apply_shows_its_value_and_the_reason() -> None:
    lines = _check_line(check(CheckStatus.NOT_APPLICABLE, actual="Enabled", detail="the WLAN has no second band"))
    assert lines == ["    - MAC Address Filter                   Enabled (not applicable: the WLAN has no second band)"]


def test_a_not_applicable_check_without_a_value_keeps_its_reason_in_the_value_column() -> None:
    assert _check_line(check(CheckStatus.NOT_APPLICABLE, detail="5 GHz not broadcast")) == [
        "    - MAC Address Filter                   5 GHz not broadcast"
    ]
