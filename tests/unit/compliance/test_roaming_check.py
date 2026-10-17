from unifiwifioptimizer.compliance.roaming_check import (
    roaming_assistant_6g_check,
    roaming_assistant_check,
    roaming_assistant_checks,
)
from unifiwifioptimizer.domain.models import Band
from unifiwifioptimizer.domain.report import CheckStatus

from .builders import profile, wlan

EXPECTS_ON = profile("Throughput")
EXPECTS_OFF = profile("IoT")


def test_not_applicable_and_incomplete_take_priority_over_the_profile() -> None:
    only_2g = wlan(bands=frozenset({Band.GHZ_2}), roaming_assistant_na_enabled=False)
    for p in (EXPECTS_ON, EXPECTS_OFF):
        result = roaming_assistant_check(p, only_2g, -70)
        assert result.status is CheckStatus.NOT_APPLICABLE and result.detail == "5 GHz not broadcast"
        older = roaming_assistant_check(p, wlan(roaming_assistant_na_enabled=None), -70)
        assert older.status is CheckStatus.INCOMPLETE and "older API" in older.detail


def test_profile_expecting_it_off() -> None:
    off = roaming_assistant_check(EXPECTS_OFF, wlan(roaming_assistant_na_enabled=False), None)
    assert off.status is CheckStatus.PASSED and (off.expected, off.actual) == ("Disabled", "Disabled")
    on = roaming_assistant_check(
        EXPECTS_OFF, wlan(roaming_assistant_na_enabled=True, roaming_assistant_na_rssi=-75), -70
    )
    assert on.status is CheckStatus.FAILED and on.actual == "Enabled, -75 dBm"


def test_profile_expecting_it_on_without_a_threshold_judges_only_the_switch() -> None:
    disabled = roaming_assistant_check(EXPECTS_ON, wlan(roaming_assistant_na_enabled=False), None)
    assert disabled.status is CheckStatus.FAILED and disabled.expected == "Enabled"
    enabled = roaming_assistant_check(
        EXPECTS_ON, wlan(roaming_assistant_na_enabled=True, roaming_assistant_na_rssi=-75), None
    )
    assert enabled.status is CheckStatus.INCOMPLETE and enabled.actual == "Enabled, -75 dBm"


def test_profile_expecting_it_on_with_a_threshold() -> None:
    match = roaming_assistant_check(
        EXPECTS_ON, wlan(roaming_assistant_na_enabled=True, roaming_assistant_na_rssi=-70), -70
    )
    assert match.status is CheckStatus.PASSED and match.expected == "Enabled, -70 dBm"
    off_by_one = roaming_assistant_check(
        EXPECTS_ON, wlan(roaming_assistant_na_enabled=True, roaming_assistant_na_rssi=-71), -70
    )
    assert off_by_one.status is CheckStatus.FAILED and off_by_one.actual == "Enabled, -71 dBm"
    disabled = roaming_assistant_check(EXPECTS_ON, wlan(roaming_assistant_na_enabled=False), -70)
    assert disabled.status is CheckStatus.FAILED and disabled.actual == "Disabled"
    # The derived threshold is the value to set once switched on, so the expectation carries it.
    assert disabled.expected == "Enabled, -70 dBm"
    no_rssi = roaming_assistant_check(EXPECTS_ON, wlan(roaming_assistant_na_enabled=True), -70)
    assert no_rssi.status is CheckStatus.FAILED and no_rssi.expected == "Enabled, -70 dBm"


def test_a_switched_on_assistant_without_a_reported_rssi_is_its_own_deviation_never_a_number() -> None:
    for threshold in (-70, None):
        blank = roaming_assistant_check(
            EXPECTS_ON, wlan(roaming_assistant_na_enabled=True, roaming_assistant_na_rssi=None), threshold
        )
        assert blank.status is CheckStatus.FAILED and blank.actual == "Enabled"
        assert blank.detail == "the controller did not send the RSSI threshold"
        assert "None" not in blank.actual and "None" not in blank.detail


def test_the_6_ghz_switch_is_reported_as_detect_only_and_never_judged() -> None:
    six_only = wlan(bands=frozenset({Band.GHZ_6}), roaming_assistant_6e_enabled=False)
    results = roaming_assistant_checks(EXPECTS_ON, six_only, -70)
    assert [(r.code, r.status) for r in results] == [
        ("roaming_assistant", CheckStatus.NOT_APPLICABLE),
        ("roaming_assistant_6g", CheckStatus.NOT_EVALUABLE),
    ]
    assert (
        results[1].actual == "Disabled" and results[1].expected is None and results[1].detail == "6 GHz is detect-only"
    )
    both = wlan(
        bands=frozenset({Band.GHZ_5, Band.GHZ_6}),
        roaming_assistant_na_enabled=True,
        roaming_assistant_na_rssi=-70,
        roaming_assistant_6e_enabled=True,
    )
    results = roaming_assistant_checks(EXPECTS_ON, both, -70)
    assert [(r.code, r.status, r.actual) for r in results] == [
        ("roaming_assistant", CheckStatus.PASSED, "Enabled, -70 dBm"),
        ("roaming_assistant_6g", CheckStatus.NOT_EVALUABLE, "Enabled"),
    ]
    # Profile expectation and threshold play no part on 6 GHz.
    assert roaming_assistant_6g_check(both) == roaming_assistant_6g_check(
        wlan(bands=frozenset({Band.GHZ_6}), roaming_assistant_6e_enabled=True)
    )
    # Absence of the 6 GHz field is no finding either: the band is detect-only through and through.
    unsent = roaming_assistant_6g_check(wlan(bands=frozenset({Band.GHZ_6})))
    assert unsent is not None and unsent.status is CheckStatus.NOT_EVALUABLE and unsent.actual is None
    assert roaming_assistant_6g_check(wlan()) is None
    assert (
        len(
            roaming_assistant_checks(
                EXPECTS_ON, wlan(roaming_assistant_na_enabled=True, roaming_assistant_na_rssi=-70), -70
            )
        )
        == 1
    )
