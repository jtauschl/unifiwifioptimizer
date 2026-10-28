"""The rule table: every rule passes on a matching WLAN, fails on a deviating one, reports INCOMPLETE when
the controller did not send the setting, and is absent where it does not apply. A second table pins the
fixed controller mapping of the optional keys with values that differ from their neighbours."""

from dataclasses import replace
from typing import Any

import pytest

from unifiwifioptimizer.compliance.rules import RULE_BY_CODE, RULES, RuleGroup, evaluate_rules
from unifiwifioptimizer.domain.models import Band, WlanConfig
from unifiwifioptimizer.domain.profile import DtimMode, MinRateMode, PmfMode, SecurityProtocol
from unifiwifioptimizer.domain.report import CheckResult, CheckStatus

from .builders import profile, wlan
from .builders import standard_wlan as shipped_standard_wlan

# The shipped Standard profile uses the controller's DTIM defaults, which switches the DTIM rules off; these
# tests need every rule to apply, so they fix the DTIM values.
STANDARD = replace(profile("Standard"), dtim_mode=DtimMode.CUSTOM, dtim_24=3, dtim_5=3)


def standard_wlan(**overrides: Any) -> WlanConfig:
    return shipped_standard_wlan(**{"dtim_mode": "custom", "dtim_ng": 3, "dtim_na": 3, **overrides})


# Rule → the WLAN field(s) that make it fail and the field that, missing, makes it INCOMPLETE.
DEVIATIONS: dict[str, tuple[dict[str, Any], str]] = {
    "wifi_bands": ({"bands": frozenset({Band.GHZ_5})}, ""),
    "fast_roaming": ({"fast_roaming_enabled": False}, "fast_roaming_enabled"),
    "minrate_mode": ({"minrate_setting_preference": "auto"}, "minrate_setting_preference"),
    "minrate_24": ({"minrate_ng_data_rate_kbps": 6000}, "minrate_ng_data_rate_kbps"),
    "minrate_5": ({"minrate_na_data_rate_kbps": 24000}, "minrate_na_data_rate_kbps"),
    "multicast_suppressor_mode": ({"multicast_suppressor_mode": "aggressive"}, "multicast_suppressor_mode"),
    "multicast_to_unicast": ({"mcastenhance_enabled": False}, "mcastenhance_enabled"),
    "proxy_arp": ({"proxy_arp": False}, "proxy_arp"),
    "security_protocol": ({"wpa3_support": False}, "security"),
    "pmf": ({"pmf_mode": "disabled"}, "pmf_mode"),
    "hide_wifi_name": ({"hide_ssid": True}, "hide_ssid"),
    "client_device_isolation": ({"l2_isolation": True}, "l2_isolation"),
    "sae_anti_clogging": ({"sae_anti_clogging": 6}, "sae_anti_clogging"),
    "sae_sync_time": ({"sae_sync": 4}, "sae_sync"),
    "mlo": ({"mlo_enabled": True}, "mlo_enabled"),
    "band_steering": ({"band_steering": False}, "band_steering"),
    "bss_transition": ({"bss_transition": False}, "bss_transition"),
    "uapsd": ({"uapsd_enabled": True}, "uapsd_enabled"),
    "dtim_mode": ({"dtim_mode": "default"}, "dtim_mode"),
    "dtim_24": ({"dtim_ng": 1}, "dtim_ng"),
    "dtim_5": ({"dtim_na": 1}, "dtim_na"),
    "group_rekey": ({"group_rekey": 0}, "group_rekey"),
    "ap_name_in_beacon": ({"advertise_device_name_in_beacon": True}, "advertise_device_name_in_beacon"),
}
APPLICABLE_TO_STANDARD = frozenset(DEVIATIONS)

# A profile that sets every optional key, with neighbouring controller fields deliberately unequal so a
# rule reading the wrong field cannot pass by accident.
STRICT = replace(
    STANDARD,
    iot_dtim_lock=False,
    iot_channel_lock=True,
    enhanced_iot=False,
    dns_assistance_mode="auto",
    mdns_proxy_mode="custom",
    multicast_suppressor_mode="conservative",
    ppsk=False,
    wpa3_enhanced_192=True,
)
STRICT_WLAN_FIELDS: dict[str, Any] = {
    "iot_dtim_lock": False,
    "iot_channel_lock": True,
    "enhanced_iot": False,
    "optimize_iot_wifi_connectivity": True,
    "dns_assistance_mode": "auto",
    "mdns_proxy_mode": "custom",
    "multicast_suppressor_mode": "conservative",
    "private_preshared_keys_enabled": False,
    "wpa3_enhanced_192": True,
}
OPTIONAL_DEVIATIONS: dict[str, tuple[dict[str, Any], str]] = {
    "iot_dtim_lock": ({"iot_dtim_lock": True}, "iot_dtim_lock"),
    "iot_channel_lock": ({"iot_channel_lock": False}, "iot_channel_lock"),
    "enhanced_iot": ({"enhanced_iot": True}, "enhanced_iot"),
    "dns_assistance_mode": ({"dns_assistance_mode": "off"}, "dns_assistance_mode"),
    "mdns_proxy_mode": ({"mdns_proxy_mode": "auto"}, "mdns_proxy_mode"),
    "ppsk": ({"private_preshared_keys_enabled": True}, "private_preshared_keys_enabled"),
    "wpa3_enhanced_192": ({"wpa3_enhanced_192": False}, "wpa3_enhanced_192"),
}


def by_code(results: tuple[CheckResult, ...]) -> dict[str, CheckResult]:
    return {r.code: r for r in results}


def test_a_matching_wlan_passes_exactly_the_applicable_rules() -> None:
    results = by_code(evaluate_rules(STANDARD, standard_wlan()))
    assert set(results) == APPLICABLE_TO_STANDARD
    assert all(r.status is CheckStatus.PASSED for r in results.values()), [
        (c, r.status, r.expected, r.actual) for c, r in results.items() if r.status is not CheckStatus.PASSED
    ]
    assert all(r.subject == "SSID-1" for r in results.values())


@pytest.mark.parametrize("code", sorted(DEVIATIONS))
def test_each_rule_fails_on_its_deviation_and_is_incomplete_without_its_field(code: str) -> None:
    deviation, missing = DEVIATIONS[code]
    failed = by_code(evaluate_rules(STANDARD, standard_wlan(**deviation)))[code]
    assert failed.status is CheckStatus.FAILED and failed.expected is not None and failed.actual is not None
    assert failed.expected != failed.actual
    if missing:
        incomplete = by_code(evaluate_rules(STANDARD, standard_wlan(**{missing: None})))[code]
        assert incomplete.status is CheckStatus.INCOMPLETE and incomplete.actual is None
        assert incomplete.detail == "the controller did not send this setting"


def test_every_optional_key_passes_on_the_strict_profile_against_its_own_controller_field() -> None:
    results = by_code(evaluate_rules(STRICT, standard_wlan(**STRICT_WLAN_FIELDS)))
    assert set(OPTIONAL_DEVIATIONS) <= set(results)
    assert {results[code].status for code in OPTIONAL_DEVIATIONS} == {CheckStatus.PASSED}
    assert results["dns_assistance_mode"].actual == "Auto" and results["mdns_proxy_mode"].actual == "Custom"


@pytest.mark.parametrize("code", sorted(OPTIONAL_DEVIATIONS))
def test_each_optional_rule_fails_on_its_deviation_and_is_incomplete_without_its_field(code: str) -> None:
    deviation, missing = OPTIONAL_DEVIATIONS[code]
    failed = by_code(evaluate_rules(STRICT, standard_wlan(**{**STRICT_WLAN_FIELDS, **deviation})))[code]
    assert failed.status is CheckStatus.FAILED and failed.expected != failed.actual
    incomplete = by_code(evaluate_rules(STRICT, standard_wlan(**{**STRICT_WLAN_FIELDS, missing: None})))[code]
    assert incomplete.status is CheckStatus.INCOMPLETE and incomplete.actual is None


def test_expected_and_actual_are_human_readable() -> None:
    results = by_code(evaluate_rules(STANDARD, standard_wlan(minrate_na_data_rate_kbps=6000, group_rekey=0)))
    assert (results["minrate_5"].expected, results["minrate_5"].actual) == ("12 Mbps", "6 Mbps")
    assert (results["group_rekey"].expected, results["group_rekey"].actual) == ("3600 s", "Disabled")
    assert results["security_protocol"].expected == "WPA2/WPA3, WPA2/WPA3 Enterprise, WPA3, WPA3 Enterprise"
    assert results["wifi_bands"].actual == "2.4 GHz, 5 GHz"
    assert results["fast_roaming"].expected == "Enabled" and results["minrate_mode"].expected == "Manual"


def test_a_combination_the_controller_sent_but_the_tool_cannot_name_fails_with_the_raw_pair() -> None:
    results = by_code(evaluate_rules(STANDARD, standard_wlan(wpa_mode="wpa1", wpa3_support=False)))
    assert results["security_protocol"].status is CheckStatus.FAILED
    assert results["security_protocol"].actual == "wpapsk/wpa1"
    assert results["security_protocol"].detail == "the controller sent a value or combination this tool has no name for"
    assert {"sae_anti_clogging", "sae_sync_time"}.isdisjoint(results)
    pmf = by_code(evaluate_rules(STANDARD, standard_wlan(pmf_mode="Disabled")))["pmf"]
    assert pmf.status is CheckStatus.FAILED and pmf.actual == "Disabled"
    mode = by_code(evaluate_rules(STANDARD, standard_wlan(minrate_setting_preference="Manual")))["minrate_mode"]
    assert mode.status is CheckStatus.FAILED and mode.actual == "Manual"


def test_a_rate_that_is_not_enforced_fails_before_its_value_is_compared() -> None:
    result = by_code(evaluate_rules(STANDARD, standard_wlan(minrate_ng_enabled=False, minrate_ng_data_rate_kbps=None)))
    assert result["minrate_24"].status is CheckStatus.FAILED and result["minrate_24"].actual == "not enforced"
    enabled_without_value = by_code(evaluate_rules(STANDARD, standard_wlan(minrate_ng_data_rate_kbps=None)))
    assert enabled_without_value["minrate_24"].status is CheckStatus.INCOMPLETE
    flag_unknown = by_code(evaluate_rules(STANDARD, standard_wlan(minrate_ng_enabled=None)))
    assert flag_unknown["minrate_24"].status is CheckStatus.INCOMPLETE and flag_unknown["minrate_24"].actual is None


def test_rates_and_dtim_values_apply_only_under_the_matching_mode_and_band() -> None:
    # The mode alone decides; values left on the profile (the loader forbids that, a caller might not) stay unused.
    auto = replace(STANDARD, minrate_mode=MinRateMode.AUTO)
    assert {"minrate_24", "minrate_5"}.isdisjoint(by_code(evaluate_rules(auto, standard_wlan())))
    default = replace(STANDARD, dtim_mode=DtimMode.DEFAULT)
    assert {"dtim_24", "dtim_5"}.isdisjoint(by_code(evaluate_rules(default, standard_wlan())))
    five_only = replace(STANDARD, wifi_bands=frozenset({Band.GHZ_5}), minrate_24_kbps=None, dtim_24=None)
    codes = set(by_code(evaluate_rules(five_only, standard_wlan())))
    assert "minrate_5" in codes and "dtim_5" in codes and "minrate_24" not in codes and "dtim_24" not in codes


def test_a_6_ghz_dtim_value_is_detect_only_never_passed_or_failed() -> None:
    with_6g = replace(STANDARD, wifi_bands=frozenset({Band.GHZ_2, Band.GHZ_5, Band.GHZ_6}), dtim_6=2)
    for dtim_6e in (2, 3, None):
        result = by_code(evaluate_rules(with_6g, standard_wlan(dtim_6e=dtim_6e, dtim_na=3)))["dtim_6"]
        assert result.status is CheckStatus.NOT_EVALUABLE and result.detail == "6 GHz is detect-only"
        assert result.expected == "2" and result.actual == (None if dtim_6e is None else str(dtim_6e))
    assert "dtim_6" not in by_code(evaluate_rules(STANDARD, standard_wlan(dtim_6e=3)))


def test_sae_counters_are_checked_only_for_sae_protocols() -> None:
    enterprise = standard_wlan(security="wpaeap")
    assert {"sae_anti_clogging", "sae_sync_time"}.isdisjoint(by_code(evaluate_rules(STANDARD, enterprise)))
    unknown = standard_wlan(security=None)
    assert {"sae_anti_clogging", "sae_sync_time"}.isdisjoint(by_code(evaluate_rules(STANDARD, unknown)))
    assert by_code(evaluate_rules(STANDARD, unknown))["security_protocol"].status is CheckStatus.INCOMPLETE


def test_optional_keys_are_checked_only_when_the_profile_sets_them() -> None:
    # Standard sets none of them; they stay out even when the controller sends them.
    results = by_code(evaluate_rules(STANDARD, standard_wlan(**STRICT_WLAN_FIELDS)))
    assert set(OPTIONAL_DEVIATIONS) & set(results) == set()


def test_set_rules_accept_any_listed_value() -> None:
    hotspot = profile("Hotspot")
    owe = wlan(security="open", wpa3_support=True, wpa3_transition=False, pmf_mode="required")
    plain = wlan(security="open", wpa3_support=False, pmf_mode="disabled")
    for w in (owe, plain):
        results = by_code(evaluate_rules(hotspot, w))
        assert results["security_protocol"].status is CheckStatus.PASSED and results["pmf"].status is CheckStatus.PASSED
    wpa2 = wlan(security="wpapsk", wpa_mode="wpa2", pmf_mode="optional")
    results = by_code(evaluate_rules(hotspot, wpa2))
    assert results["security_protocol"].status is CheckStatus.FAILED and results["security_protocol"].actual == "WPA2"
    assert set(hotspot.security_protocols) == {
        SecurityProtocol.OPEN,
        SecurityProtocol.OWE,
        SecurityProtocol.OWE_TRANSITION,
    } and set(hotspot.pmf) == {PmfMode.DISABLED, PmfMode.OPTIONAL, PmfMode.REQUIRED}
    iot = profile("IoT")
    transition = wlan(
        bands=frozenset({Band.GHZ_2}),
        security="wpapsk",
        wpa_mode="wpa2",
        wpa3_support=True,
        wpa3_transition=True,
        pmf_mode="optional",
    )
    results = by_code(evaluate_rules(iot, transition))
    # IoT expects WPA2: a transition WLAN cannot switch PMF off, which Ubiquiti's IoT guidance asks for.
    assert results["security_protocol"].status is CheckStatus.FAILED and results["pmf"].status is CheckStatus.PASSED
    for pmf in ("disabled", "optional"):
        wpa2_only = wlan(bands=frozenset({Band.GHZ_2}), security="wpapsk", wpa_mode="wpa2", pmf_mode=pmf)
        results = by_code(evaluate_rules(iot, wpa2_only))
        assert results["security_protocol"].status is CheckStatus.PASSED and results["pmf"].status is CheckStatus.PASSED


def test_rule_codes_are_unique_grouped_and_labelled() -> None:
    codes = [rule.code for rule in RULES]
    assert len(set(codes)) == len(codes) == len(RULE_BY_CODE) == 31
    assert all(rule.label and isinstance(rule.group, RuleGroup) for rule in RULES)
    assert set(DEVIATIONS) | set(OPTIONAL_DEVIATIONS) == set(codes) - {"dtim_6"}


def test_an_open_or_owe_wlan_without_a_group_rekey_interval_is_not_judged_on_it() -> None:
    hotspot = profile("Hotspot")
    open_family = {
        "open": wlan(security="open", wpa3_support=False, pmf_mode="disabled", group_rekey=None),
        "owe": wlan(security="open", wpa3_support=True, wpa3_transition=False, pmf_mode="required", group_rekey=None),
        "owe transition": wlan(
            security="open", wpa3_support=True, wpa3_transition=True, pmf_mode="optional", group_rekey=None
        ),
    }
    for name, silent in open_family.items():
        assert "group_rekey" not in by_code(evaluate_rules(hotspot, silent)), name
    sent = by_code(evaluate_rules(hotspot, wlan(security="open", wpa3_support=False, group_rekey=0)))
    assert sent["group_rekey"].status is CheckStatus.FAILED and sent["group_rekey"].actual == "Disabled"
    psk = wlan(security="wpapsk", wpa_mode="wpa2", group_rekey=None)
    assert by_code(evaluate_rules(profile("Standard"), psk))["group_rekey"].status is CheckStatus.INCOMPLETE


def test_band_steering_is_judged_only_on_a_wlan_with_2_4_ghz_and_another_band() -> None:
    iot = profile("IoT")
    stored_on = wlan(bands=frozenset({Band.GHZ_2}), band_steering=True)
    assert "band_steering" not in by_code(evaluate_rules(iot, stored_on))
    for bands in ({Band.GHZ_5}, {Band.GHZ_5, Band.GHZ_6}):
        assert "band_steering" not in by_code(evaluate_rules(iot, wlan(bands=frozenset(bands), band_steering=True)))
    for bands in ({Band.GHZ_2, Band.GHZ_5}, {Band.GHZ_2, Band.GHZ_6}):
        dual = wlan(bands=frozenset(bands), band_steering=True)
        assert by_code(evaluate_rules(iot, dual))["band_steering"].status is CheckStatus.FAILED


def test_a_text_setting_is_shown_with_the_word_of_the_controller_ui() -> None:
    manual = by_code(evaluate_rules(STRICT, standard_wlan(**{**STRICT_WLAN_FIELDS, "dns_assistance_mode": "manual"})))
    assert manual["dns_assistance_mode"].actual == "Manual" and manual["dns_assistance_mode"].expected == "Auto"
    custom = by_code(evaluate_rules(STRICT, standard_wlan(**STRICT_WLAN_FIELDS)))["mdns_proxy_mode"]
    assert custom.expected == "Custom"
