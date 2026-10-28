"""The profile rule table: one entry per checked WLAN setting, evaluated to a `CheckResult`.

A rule returns None when it does not apply (a band the profile does not expect, a rate value under
`auto` mode, an optional key the profile leaves unset), `INCOMPLETE` when the controller did not send
the setting, `NOT_EVALUABLE` for a 6 GHz value (detect-only), and `PASSED`/`FAILED` otherwise — a
combination the controller sent but the tool has no name for fails and shows the raw combination. UI paths
are the renderer's business and stay out of here.
"""

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import StrEnum

from unifiwifioptimizer.compliance.normalize import (
    Unrecognised,
    bands_label,
    dtim_mode,
    minrate_mode,
    pmf_mode,
    rate_label,
    rekey_label,
    security_protocol,
)
from unifiwifioptimizer.domain.models import Band, WlanConfig
from unifiwifioptimizer.domain.profile import DtimMode, MinRateMode, Profile, SecurityProtocol
from unifiwifioptimizer.domain.report import CheckResult, CheckStatus

NOT_SENT = "the controller did not send this setting"
UNRECOGNISED = "the controller sent a value or combination this tool has no name for"
SIX_GHZ_DETECT_ONLY = "6 GHz is detect-only"


class RuleGroup(StrEnum):
    RADIO = "Radio Setup"
    ROAMING = "Roaming Assistance"
    CAPACITY = "Hi-Capacity Tuning"
    SECURITY = "Security"
    BEHAVIOUR = "Behaviour Controls"


Evaluator = Callable[[Profile, WlanConfig], CheckResult | None]


@dataclass(frozen=True, slots=True)
class Rule:
    code: str
    label: str
    group: RuleGroup
    evaluate: Evaluator


def _result(
    code: str, wlan: WlanConfig, status: CheckStatus, expected: str, actual: str | None, detail: str = ""
) -> CheckResult:
    return CheckResult(code=code, subject=wlan.name, status=status, detail=detail, expected=expected, actual=actual)


def _compare(code: str, wlan: WlanConfig, expected: str, actual: str | None, matches: bool) -> CheckResult:
    if actual is None:
        return _result(code, wlan, CheckStatus.INCOMPLETE, expected, None, NOT_SENT)
    return _result(code, wlan, CheckStatus.PASSED if matches else CheckStatus.FAILED, expected, actual)


def _compare_vocabulary(
    code: str, wlan: WlanConfig, expected: str, have: StrEnum | Unrecognised | None, accepted: Iterable[StrEnum]
) -> CheckResult:
    if isinstance(have, Unrecognised):
        return _result(code, wlan, CheckStatus.FAILED, expected, have.text, UNRECOGNISED)
    return _compare(code, wlan, expected, None if have is None else have.value, have in tuple(accepted))


def on_off(value: bool) -> str:
    return "Enabled" if value else "Disabled"


def _bool_rule(
    code: str,
    label: str,
    group: RuleGroup,
    expected: Callable[[Profile], bool | None],
    actual: Callable[[WlanConfig], bool | None],
    applies: Callable[[Profile, WlanConfig], bool] = lambda profile, wlan: True,
) -> Rule:
    def evaluate(profile: Profile, wlan: WlanConfig) -> CheckResult | None:
        want = expected(profile)
        if want is None or not applies(profile, wlan):
            return None
        have = actual(wlan)
        return _compare(code, wlan, on_off(want), None if have is None else on_off(have), have == want)

    return Rule(code, label, group, evaluate)


def _text_rule(
    code: str,
    label: str,
    group: RuleGroup,
    expected: Callable[[Profile], str | None],
    actual: Callable[[WlanConfig], str | None],
) -> Rule:
    """Values are shown capitalised, as the controller UI writes them (Off, Auto, Manual)."""

    def show(value: str) -> str:
        return value.capitalize()

    def evaluate(profile: Profile, wlan: WlanConfig) -> CheckResult | None:
        want = expected(profile)
        if want is None:
            return None
        have = actual(wlan)
        return _compare(code, wlan, show(want), None if have is None else show(have), have == want)

    return Rule(code, label, group, evaluate)


def _int_rule(
    code: str,
    label: str,
    group: RuleGroup,
    expected: Callable[[Profile], int | None],
    actual: Callable[[WlanConfig], int | None],
    applies: Callable[[Profile, WlanConfig], bool] = lambda profile, wlan: True,
    render: Callable[[int], str] = str,
) -> Rule:
    def evaluate(profile: Profile, wlan: WlanConfig) -> CheckResult | None:
        want = expected(profile)
        if want is None or not applies(profile, wlan):
            return None
        have = actual(wlan)
        return _compare(code, wlan, render(want), None if have is None else render(have), have == want)

    return Rule(code, label, group, evaluate)


def _rate_rule(code: str, label: str, band: Band) -> Rule:
    """A minimum data rate is only a rule when the profile fixes rates and expects the band; the
    controller's per-band enable flag counts as a deviation when off, as in the UI."""

    def expected(profile: Profile) -> int | None:
        if profile.minrate_mode is not MinRateMode.MANUAL or band not in profile.wifi_bands:
            return None
        return profile.minrate_24_kbps if band is Band.GHZ_2 else profile.minrate_5_kbps

    def evaluate(profile: Profile, wlan: WlanConfig) -> CheckResult | None:
        want = expected(profile)
        if want is None:
            return None
        enabled = wlan.minrate_ng_enabled if band is Band.GHZ_2 else wlan.minrate_na_enabled
        kbps = wlan.minrate_ng_data_rate_kbps if band is Band.GHZ_2 else wlan.minrate_na_data_rate_kbps
        if enabled is None:
            return _result(code, wlan, CheckStatus.INCOMPLETE, rate_label(want), None, NOT_SENT)
        if not enabled:
            return _result(code, wlan, CheckStatus.FAILED, rate_label(want), "not enforced")
        if kbps is None:
            return _result(code, wlan, CheckStatus.INCOMPLETE, rate_label(want), None, NOT_SENT)
        return _compare(code, wlan, rate_label(want), rate_label(kbps), kbps == want)

    return Rule(code, label, RuleGroup.CAPACITY, evaluate)


def _dtim_rule(code: str, label: str, band: Band) -> Rule:
    def expected(profile: Profile) -> int | None:
        if profile.dtim_mode is not DtimMode.CUSTOM or band not in profile.wifi_bands:
            return None
        return {Band.GHZ_2: profile.dtim_24, Band.GHZ_5: profile.dtim_5, Band.GHZ_6: profile.dtim_6}[band]

    def actual(wlan: WlanConfig) -> int | None:
        return {Band.GHZ_2: wlan.dtim_ng, Band.GHZ_5: wlan.dtim_na, Band.GHZ_6: wlan.dtim_6e}[band]

    def evaluate(profile: Profile, wlan: WlanConfig) -> CheckResult | None:
        want = expected(profile)
        if want is None:
            return None
        have = actual(wlan)
        if band is Band.GHZ_6:
            return _result(
                code,
                wlan,
                CheckStatus.NOT_EVALUABLE,
                str(want),
                None if have is None else str(have),
                SIX_GHZ_DETECT_ONLY,
            )
        return _compare(code, wlan, str(want), None if have is None else str(have), have == want)

    return Rule(code, label, RuleGroup.BEHAVIOUR, evaluate)


def _bands_rule() -> Rule:
    def evaluate(profile: Profile, wlan: WlanConfig) -> CheckResult | None:
        return _compare(
            "wifi_bands",
            wlan,
            bands_label(profile.wifi_bands),
            bands_label(wlan.bands),
            wlan.bands == profile.wifi_bands,
        )

    return Rule("wifi_bands", "Radio Band", RuleGroup.RADIO, evaluate)


def _security_protocol_rule() -> Rule:
    def evaluate(profile: Profile, wlan: WlanConfig) -> CheckResult | None:
        expected = ", ".join(sorted(p.value for p in profile.security_protocols))
        return _compare_vocabulary(
            "security_protocol", wlan, expected, security_protocol(wlan), profile.security_protocols
        )

    return Rule("security_protocol", "Security Protocol", RuleGroup.SECURITY, evaluate)


def _pmf_rule() -> Rule:
    def evaluate(profile: Profile, wlan: WlanConfig) -> CheckResult | None:
        expected = ", ".join(sorted(p.value for p in profile.pmf))
        return _compare_vocabulary("pmf", wlan, expected, pmf_mode(wlan), profile.pmf)

    return Rule("pmf", "PMF", RuleGroup.SECURITY, evaluate)


def _mode_rule(
    code: str,
    label: str,
    group: RuleGroup,
    expected: Callable[[Profile], StrEnum],
    actual: Callable[[WlanConfig], StrEnum | Unrecognised | None],
) -> Rule:
    def evaluate(profile: Profile, wlan: WlanConfig) -> CheckResult | None:
        want = expected(profile)
        have = actual(wlan)
        if isinstance(have, Unrecognised):
            return _result(code, wlan, CheckStatus.FAILED, want.value.capitalize(), have.text, UNRECOGNISED)
        return _compare(
            code, wlan, want.value.capitalize(), None if have is None else have.value.capitalize(), have == want
        )

    return Rule(code, label, group, evaluate)


def _rekey_rule() -> Rule:
    return _int_rule(
        "group_rekey",
        "Group Rekey Interval",
        RuleGroup.BEHAVIOUR,
        lambda profile: profile.group_rekey_s,
        lambda wlan: wlan.group_rekey,
        applies=_has_group_rekey,
        render=rekey_label,
    )


def _has_group_rekey(profile: Profile, wlan: WlanConfig) -> bool:
    """The controller does not send the interval for an open or OWE WLAN, so its absence is not incomplete."""
    protocol = security_protocol(wlan)
    return wlan.group_rekey is not None or not (isinstance(protocol, SecurityProtocol) and protocol.is_open_family)


def _steers_between_bands(profile: Profile, wlan: WlanConfig) -> bool:
    """Steering moves a client from 2.4 GHz to another band; a WLAN without both has nothing to steer between."""
    return Band.GHZ_2 in wlan.bands and len(wlan.bands) > 1


def _uses_sae(profile: Profile, wlan: WlanConfig) -> bool:
    protocol = security_protocol(wlan)
    return not isinstance(protocol, Unrecognised) and protocol is not None and protocol.uses_sae


RULES: tuple[Rule, ...] = (
    _bands_rule(),
    _bool_rule(
        "fast_roaming",
        "Fast Roaming (802.11r)",
        RuleGroup.ROAMING,
        lambda p: p.fast_roaming,
        lambda w: w.fast_roaming_enabled,
    ),
    _mode_rule("minrate_mode", "Minimum Data Rate Mode", RuleGroup.CAPACITY, lambda p: p.minrate_mode, minrate_mode),
    _rate_rule("minrate_24", "Minimum Data Rate 2.4 GHz", Band.GHZ_2),
    _rate_rule("minrate_5", "Minimum Data Rate 5 GHz", Band.GHZ_5),
    _bool_rule(
        "multicast_to_unicast",
        "Multicast to Unicast",
        RuleGroup.CAPACITY,
        lambda p: p.multicast_to_unicast,
        lambda w: w.mcastenhance_enabled,
    ),
    _bool_rule("proxy_arp", "Proxy ARP", RuleGroup.CAPACITY, lambda p: p.proxy_arp, lambda w: w.proxy_arp),
    _security_protocol_rule(),
    _pmf_rule(),
    _bool_rule(
        "hide_wifi_name", "Hide WiFi Name", RuleGroup.SECURITY, lambda p: p.hide_wifi_name, lambda w: w.hide_ssid
    ),
    _bool_rule(
        "client_device_isolation",
        "Client Device Isolation",
        RuleGroup.SECURITY,
        lambda p: p.client_device_isolation,
        lambda w: w.l2_isolation,
    ),
    _int_rule(
        "sae_anti_clogging",
        "SAE Anti-clogging",
        RuleGroup.SECURITY,
        lambda p: p.sae_anti_clogging,
        lambda w: w.sae_anti_clogging,
        applies=_uses_sae,
    ),
    _int_rule(
        "sae_sync_time",
        "SAE Sync Time",
        RuleGroup.SECURITY,
        lambda p: p.sae_sync_time,
        lambda w: w.sae_sync,
        applies=_uses_sae,
    ),
    _bool_rule(
        "ppsk",
        "Private Pre-Shared Keys",
        RuleGroup.SECURITY,
        lambda p: p.ppsk,
        lambda w: w.private_preshared_keys_enabled,
    ),
    _bool_rule(
        "wpa3_enhanced_192",
        "WPA3 Enhanced 192-bit",
        RuleGroup.SECURITY,
        lambda p: p.wpa3_enhanced_192,
        lambda w: w.wpa3_enhanced_192,
    ),
    _bool_rule("mlo", "MLO", RuleGroup.BEHAVIOUR, lambda p: p.mlo, lambda w: w.mlo_enabled),
    _bool_rule(
        "band_steering",
        "Band Steering",
        RuleGroup.BEHAVIOUR,
        lambda p: p.band_steering,
        lambda w: w.band_steering,
        applies=_steers_between_bands,
    ),
    _bool_rule(
        "bss_transition", "BSS Transition", RuleGroup.BEHAVIOUR, lambda p: p.bss_transition, lambda w: w.bss_transition
    ),
    _bool_rule("uapsd", "UAPSD", RuleGroup.BEHAVIOUR, lambda p: p.uapsd, lambda w: w.uapsd_enabled),
    _mode_rule("dtim_mode", "Auto 802.11 DTIM Period", RuleGroup.BEHAVIOUR, lambda p: p.dtim_mode, dtim_mode),
    _dtim_rule("dtim_24", "DTIM Period 2.4 GHz", Band.GHZ_2),
    _dtim_rule("dtim_5", "DTIM Period 5 GHz", Band.GHZ_5),
    _dtim_rule("dtim_6", "DTIM Period 6 GHz", Band.GHZ_6),
    _rekey_rule(),
    _bool_rule(
        "ap_name_in_beacon",
        "Show Access Point Name in Beacon",
        RuleGroup.BEHAVIOUR,
        lambda p: p.ap_name_in_beacon,
        lambda w: w.advertise_device_name_in_beacon,
    ),
    _bool_rule(
        "iot_dtim_lock", "DTIM Interval Lock", RuleGroup.BEHAVIOUR, lambda p: p.iot_dtim_lock, lambda w: w.iot_dtim_lock
    ),
    _bool_rule(
        "iot_channel_lock",
        "Lock 2.4 GHz to Channel 6 (All APs)",
        RuleGroup.BEHAVIOUR,
        lambda p: p.iot_channel_lock,
        lambda w: w.iot_channel_lock,
    ),
    _bool_rule(
        "enhanced_iot", "Force WiFi 4 Mode", RuleGroup.BEHAVIOUR, lambda p: p.enhanced_iot, lambda w: w.enhanced_iot
    ),
    _text_rule(
        "dns_assistance_mode",
        "DNS Assistance",
        RuleGroup.BEHAVIOUR,
        lambda p: p.dns_assistance_mode,
        lambda w: w.dns_assistance_mode,
    ),
    _text_rule(
        "mdns_proxy_mode",
        "Multicast Filtering",
        RuleGroup.BEHAVIOUR,
        lambda p: p.mdns_proxy_mode,
        lambda w: w.mdns_proxy_mode,
    ),
    _text_rule(
        "multicast_suppressor_mode",
        "Multicast Suppression",
        RuleGroup.BEHAVIOUR,
        lambda p: p.multicast_suppressor_mode,
        lambda w: w.multicast_suppressor_mode,
    ),
)

RULE_BY_CODE: dict[str, Rule] = {rule.code: rule for rule in RULES}


def evaluate_rules(profile: Profile, wlan: WlanConfig, rules: Iterable[Rule] = RULES) -> tuple[CheckResult, ...]:
    return tuple(result for rule in rules if (result := rule.evaluate(profile, wlan)) is not None)
