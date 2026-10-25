"""Cross-setting advisories, including the MLO cases."""

from unifiwifioptimizer.compliance.advisories import (
    ADVISORIES,
    advanced_set_to_auto,
    evaluate_advisories,
    fast_roaming_on_2g_only_wlan,
    fast_roaming_without_bss_transition,
    iot_locks_on_dual_band_wlan,
    mdns_proxy_with_isolation,
    min_rate_2g,
    mlo_requires_wpa3_pmf,
    pmf_matches_protocol,
    ppsk_requires_psk,
    wpa3_192_requires_enterprise,
)
from unifiwifioptimizer.domain.models import Band
from unifiwifioptimizer.domain.report import Severity

from .builders import profile, throughput_wlan, wlan


def mlo(security: str, wpa3: bool, transition: bool, pmf: str, enabled: bool = True) -> str | None:
    w = wlan(
        mlo_enabled=enabled,
        security=security,
        wpa_mode="wpa2",
        wpa3_support=wpa3,
        wpa3_transition=transition,
        pmf_mode=pmf,
    )
    finding = mlo_requires_wpa3_pmf(profile(), w)
    return None if finding is None else finding.message


def test_mlo_advisory_silent_when_compliant() -> None:
    assert mlo("wpapsk", True, False, "required") is None


def test_mlo_advisory_silent_when_wpa3_enterprise_and_required() -> None:
    assert mlo("wpaeap", True, False, "required") is None


def test_mlo_advisory_fires_on_wpa2_only() -> None:
    message = mlo("wpapsk", False, False, "required")
    assert message is not None and message.startswith("MLO requires WPA3-only + PMF Required (Wi-Fi 7 certification)")


def test_mlo_advisory_fires_on_pmf_optional() -> None:
    message = mlo("wpapsk", True, False, "optional")
    assert message is not None and "current: WPA3/Optional" in message


def test_mlo_advisory_silent_when_mlo_disabled() -> None:
    assert mlo("wpapsk", False, False, "disabled", enabled=False) is None
    assert mlo_requires_wpa3_pmf(profile(), wlan(mlo_enabled=None, security="wpapsk", wpa_mode="wpa2")) is None


def test_mlo_advisory_silent_for_6ghz_default_config() -> None:
    # UniFi's own default for a 6 GHz-capable multiband WLAN without MLO: WPA2/WPA3 + PMF Optional at WLAN level.
    w = wlan(
        bands=frozenset({Band.GHZ_2, Band.GHZ_5, Band.GHZ_6}),
        mlo_enabled=False,
        security="wpapsk",
        wpa_mode="wpa2",
        wpa3_support=True,
        wpa3_transition=True,
        pmf_mode="optional",
    )
    assert mlo_requires_wpa3_pmf(profile(), w) is None


def test_mlo_advisory_fires_for_a_transition_mode_whatever_its_pmf() -> None:
    # A transition mode runs PMF optional by specification; MLO needs WPA3-only, so neither setting satisfies it.
    assert mlo("wpapsk", True, True, "optional") is not None and mlo("wpapsk", True, True, "required") is not None
    assert mlo("wpaeap", True, True, "required") is not None
    message = mlo("wpapsk", True, True, "required")
    assert message is not None and message.startswith("MLO requires WPA3-only + PMF Required")


def test_mlo_advisory_names_unknowns_and_unrecognised_pairs_instead_of_guessing() -> None:
    finding = mlo_requires_wpa3_pmf(profile(), wlan(mlo_enabled=True))
    assert finding is not None and "current: unknown/unknown" in finding.message
    odd = mlo_requires_wpa3_pmf(profile(), wlan(mlo_enabled=True, security="wep", wpa_mode="wpa2", pmf_mode="required"))
    assert odd is not None and "current: wep/wpa2/Required" in odd.message


def test_pmf_matches_protocol_follows_the_specification_per_protocol() -> None:
    def finding(security: str, wpa3: bool, transition: bool, pmf: str) -> str | None:
        f = pmf_matches_protocol(
            profile(),
            wlan(security=security, wpa_mode="wpa2", wpa3_support=wpa3, wpa3_transition=transition, pmf_mode=pmf),
        )
        return None if f is None else f.message

    # OWE-only and WPA3-only need PMF required; a WPA3 transition exactly optional, an OWE transition at least
    # optional; Open cannot use it.
    assert (
        finding("open", True, False, "disabled")
        == "Enhanced Open (OWE) needs PMF Required by specification — current: Disabled."
    )
    assert finding("open", True, False, "required") is None
    assert finding("open", True, True, "disabled") is not None and finding("open", True, True, "optional") is None
    assert (
        finding("open", False, False, "required")
        == "Open carries no RSN, so PMF has nothing to protect — current: Required."
    )
    assert finding("open", False, False, "disabled") is None
    assert finding("wpapsk", True, False, "optional") is not None and finding("wpapsk", True, False, "required") is None
    assert finding("wpapsk", True, True, "disabled") is not None and finding("wpapsk", True, True, "optional") is None
    # PMF required in a transition mode locks out the WPA2 clients the mode exists for.
    assert (
        finding("wpapsk", True, True, "required")
        == "WPA2/WPA3 needs PMF Optional by specification — current: Required."
    )
    assert finding("wpaeap", True, True, "required") is not None
    assert finding("wpaeap", True, False, "optional") is not None and finding("wpaeap", True, True, "optional") is None
    for pmf in ("disabled", "optional", "required"):
        assert finding("wpapsk", False, False, pmf) is None and finding("wpaeap", False, False, pmf) is None
    # Nothing to say without both facts, or with an unrecognised pair.
    assert pmf_matches_protocol(profile(), wlan(security="open", wpa3_support=True)) is None
    assert pmf_matches_protocol(profile(), wlan(pmf_mode="required")) is None
    assert pmf_matches_protocol(profile(), wlan(security="wep", wpa_mode="wpa2", pmf_mode="required")) is None


def test_fast_roaming_without_bss_transition_fires_only_when_both_facts_are_known() -> None:
    assert (
        fast_roaming_without_bss_transition(profile(), wlan(fast_roaming_enabled=True, bss_transition=False))
        is not None
    )
    assert fast_roaming_without_bss_transition(profile(), wlan(fast_roaming_enabled=True, bss_transition=True)) is None
    assert fast_roaming_without_bss_transition(profile(), wlan(fast_roaming_enabled=True, bss_transition=None)) is None
    assert (
        fast_roaming_without_bss_transition(profile(), wlan(fast_roaming_enabled=False, bss_transition=False)) is None
    )


def test_fast_roaming_on_a_2g_only_wlan_is_judged_on_the_controller_bands_not_the_profile() -> None:
    only_2g = frozenset({Band.GHZ_2})
    assert (
        fast_roaming_on_2g_only_wlan(profile("Throughput"), wlan(bands=only_2g, fast_roaming_enabled=True)) is not None
    )
    assert fast_roaming_on_2g_only_wlan(profile("IoT"), wlan(fast_roaming_enabled=True)) is None
    assert fast_roaming_on_2g_only_wlan(profile("IoT"), wlan(bands=only_2g, fast_roaming_enabled=False)) is None
    finding = fast_roaming_on_2g_only_wlan(profile("IoT"), wlan(bands=only_2g, fast_roaming_enabled=True))
    assert finding is not None and finding.band is Band.GHZ_2 and finding.severity is Severity.ADVISORY


def test_min_rate_2g_speaks_only_for_a_fixed_2g_rate_with_802_11b_known_to_be_on() -> None:
    def code(kbps: int | None, **fields: object) -> str | None:
        base: dict[str, object] = {
            "minrate_setting_preference": "manual",
            "minrate_ng_enabled": True,
            "minrate_ng_data_rate_kbps": kbps,
            "b_supported": True,
        }
        f = min_rate_2g(profile(), wlan(**{**base, **fields}))
        return None if f is None else f.code

    assert code(1000) == "min_rate_2g_dsss" and code(5500) == "min_rate_2g_dsss" and code(11000) == "min_rate_2g_dsss"
    assert code(6000) == "min_rate_2g_below_recommended" and code(9000) == "min_rate_2g_below_recommended"
    assert code(12000) is None and code(24000) is None and code(None) is None
    # Under `auto` the stored value is inert; the live preset WLANs carry 1000 kbps there.
    assert code(1000, minrate_setting_preference="auto") is None and code(1000, minrate_setting_preference=None) is None
    assert code(1000, minrate_ng_enabled=False) is None and code(1000, minrate_ng_enabled=None) is None
    # 802.11b off: the DSSS rates cannot be used; unknown: not assumed either way.
    assert code(1000, b_supported=False) is None and code(1000, b_supported=None) is None
    # A WLAN without 2.4 GHz has no 2.4 GHz rate to talk about, whatever stale value is stored.
    assert code(1000, bands=frozenset({Band.GHZ_5})) is None
    message = min_rate_2g(
        profile(),
        wlan(
            minrate_setting_preference="manual",
            minrate_ng_enabled=True,
            minrate_ng_data_rate_kbps=5500,
            b_supported=True,
        ),
    )
    assert message is not None and message.message.startswith("5.5 Mbps is an 802.11b DSSS rate")


def test_iot_locks_are_an_advisory_only_on_a_profile_that_expects_5_ghz() -> None:
    both = wlan(iot_channel_lock=True, iot_dtim_lock=True)
    finding = iot_locks_on_dual_band_wlan(profile("Throughput"), both)
    assert finding is not None and "IoT Channel Lock and IoT DTIM Lock" in finding.message
    assert iot_locks_on_dual_band_wlan(profile("IoT"), both) is None
    assert iot_locks_on_dual_band_wlan(profile("Throughput"), wlan(iot_channel_lock=False, iot_dtim_lock=None)) is None
    one = iot_locks_on_dual_band_wlan(profile("Throughput"), wlan(iot_dtim_lock=True))
    assert one is not None and one.message.startswith("IoT DTIM Lock enabled")


def test_advanced_set_to_auto_is_information_only_under_auto() -> None:
    finding = advanced_set_to_auto(profile(), wlan(setting_preference="auto"))
    assert finding is not None and finding.severity is Severity.INFO and finding.code == "advanced_set_to_auto"
    assert advanced_set_to_auto(profile(), wlan(setting_preference="manual")) is None
    assert advanced_set_to_auto(profile(), wlan(setting_preference=None)) is None


def test_mdns_proxy_with_isolation() -> None:
    assert mdns_proxy_with_isolation(profile(), wlan(l2_isolation=True, mdns_proxy_mode="auto")) is not None
    assert mdns_proxy_with_isolation(profile(), wlan(l2_isolation=True, mdns_proxy_mode="off")) is None
    assert mdns_proxy_with_isolation(profile(), wlan(l2_isolation=True, mdns_proxy_mode=None)) is None
    assert mdns_proxy_with_isolation(profile(), wlan(l2_isolation=False, mdns_proxy_mode="custom")) is None


def test_ppsk_requires_a_psk_handshake() -> None:
    def finding(security: str, wpa3: bool, transition: bool) -> bool:
        w = wlan(
            private_preshared_keys_enabled=True,
            security=security,
            wpa_mode="wpa2",
            wpa3_support=wpa3,
            wpa3_transition=transition,
        )
        return ppsk_requires_psk(profile(), w) is not None

    assert finding("wpapsk", False, False) is False and finding("wpapsk", True, True) is False
    assert finding("wpapsk", True, False) is True and finding("wpaeap", True, True) is True
    assert ppsk_requires_psk(profile(), wlan(private_preshared_keys_enabled=True)) is None
    assert (
        ppsk_requires_psk(profile(), wlan(private_preshared_keys_enabled=True, security="wep", wpa_mode="wpa2")) is None
    )
    assert ppsk_requires_psk(profile(), wlan(private_preshared_keys_enabled=False, security="open")) is None


def test_wpa3_192_requires_wpa3_enterprise_without_transition() -> None:
    def finding(security: str, wpa3: bool, transition: bool) -> bool:
        w = wlan(
            wpa3_enhanced_192=True, security=security, wpa_mode="wpa2", wpa3_support=wpa3, wpa3_transition=transition
        )
        return wpa3_192_requires_enterprise(profile(), w) is not None

    assert finding("wpaeap", True, False) is False
    assert finding("wpaeap", True, True) is True and finding("wpaeap", False, False) is True
    assert finding("wpapsk", True, False) is True
    assert wpa3_192_requires_enterprise(profile(), wlan(wpa3_enhanced_192=False, security="wpapsk")) is None
    assert wpa3_192_requires_enterprise(profile(), wlan(wpa3_enhanced_192=True)) is None


def test_a_compliant_throughput_wlan_raises_no_advisory_and_codes_are_unique() -> None:
    assert evaluate_advisories(profile(), throughput_wlan()) == ()
    codes = [a.__name__ for a in ADVISORIES]
    assert len(set(codes)) == len(codes) == 10
