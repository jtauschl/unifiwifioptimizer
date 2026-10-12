"""Advisories: cross-setting observations about a WLAN that no single profile key expresses. Each is
judged on the controller's actual configuration (and the profile only where the rationale needs it) and
returns a `Finding` or None. An advisory speaks only when every fact it rests on was sent."""

from collections.abc import Callable, Iterable

from unifiwifioptimizer.compliance.normalize import Unrecognised, minrate_mode, pmf_mode, rate_label, security_protocol
from unifiwifioptimizer.domain.models import Band, WlanConfig
from unifiwifioptimizer.domain.profile import (
    DSSS_RATES_KBPS,
    MIN_OFDM_RATE_KBPS,
    MinRateMode,
    PmfMode,
    Profile,
    SecurityProtocol,
)
from unifiwifioptimizer.domain.report import Finding, Severity

Advisory = Callable[[Profile, WlanConfig], Finding | None]
WPA3_ONLY = frozenset({SecurityProtocol.WPA3, SecurityProtocol.WPA3_ENTERPRISE})


def _advisory(code: str, wlan: WlanConfig, message: str, band: Band | None = None) -> Finding:
    return Finding(severity=Severity.ADVISORY, code=code, message=message, subject=wlan.name, band=band)


def _known_protocol(wlan: WlanConfig) -> SecurityProtocol | None:
    protocol = security_protocol(wlan)
    return None if isinstance(protocol, Unrecognised) else protocol


def _shown(value: SecurityProtocol | PmfMode | Unrecognised | None) -> str:
    if value is None:
        return "unknown"
    return value.text if isinstance(value, Unrecognised) else value.value


def mlo_requires_wpa3_pmf(profile: Profile, wlan: WlanConfig) -> Finding | None:
    """Multi-link operation needs a WPA3-only protocol (Personal or Enterprise, no WPA2 transition) with PMF
    required: IEEE 802.11be defines MLO but does not mandate a security suite, and the Wi-Fi Alliance
    Wi-Fi CERTIFIED 7 programme (and the controller UI, which forces the pair when MLO is switched on)
    requires WPA3-only there. A transition mode runs PMF optional by specification, so it can never satisfy
    MLO. Read from memory; the certification document is not archived in the project.

    6 GHz has the same requirement by certification but is not judged here: the WLAN-level fields are shared
    across bands, the controller shows WPA2/WPA3 + PMF Optional for a legitimate multiband WLAN and enforces
    WPA3-only + PMF Required on the 6 GHz radio internally, with no per-band field to read."""
    if wlan.mlo_enabled is not True:
        return None
    protocol = security_protocol(wlan)
    pmf = pmf_mode(wlan)
    if protocol in WPA3_ONLY and pmf is PmfMode.REQUIRED:
        return None
    return _advisory(
        "mlo_requires_wpa3_pmf",
        wlan,
        f"MLO requires WPA3-only + PMF Required (Wi-Fi 7 certification) — current: {_shown(protocol)}/{_shown(pmf)}.",
    )


def pmf_matches_protocol(profile: Profile, wlan: WlanConfig) -> Finding | None:
    """PMF is not free-standing: WPA3-only and OWE-only need it required, a WPA3 transition mode exactly
    optional, an OWE transition optional or required, plain Open cannot use it (Wi-Fi Alliance WPA3
    Specification and Wi-Fi Enhanced Open); the profile's accepted sets are checked separately, so a pair
    that is each acceptable alone still gets this check."""
    protocol = _known_protocol(wlan)
    pmf = pmf_mode(wlan)
    if protocol is None or not isinstance(pmf, PmfMode) or pmf in protocol.required_pmf:
        return None
    if protocol is SecurityProtocol.OPEN:
        message = f"Open carries no RSN, so PMF has nothing to protect — current: {pmf.value}."
    else:
        allowed = " or ".join(sorted(p.value for p in protocol.required_pmf))
        message = f"{protocol.value} needs PMF {allowed} by specification — current: {pmf.value}."
    return _advisory("pmf_matches_protocol", wlan, message)


def fast_roaming_without_bss_transition(profile: Profile, wlan: WlanConfig) -> Finding | None:
    """802.11r speeds up the re-association; without 802.11v the client still has to find the target itself."""
    if wlan.fast_roaming_enabled is not True or wlan.bss_transition is not False:
        return None
    return _advisory(
        "fast_roaming_without_bss_transition",
        wlan,
        "802.11r Fast Transition works best paired with 802.11v (BSS Transition) — currently disabled.",
    )


def fast_roaming_on_2g_only_wlan(profile: Profile, wlan: WlanConfig) -> Finding | None:
    """A WLAN that broadcasts only on 2.4 GHz serves the IoT class of clients, some of which (ESP32-era
    chipsets, older printers, first-generation speakers) drop off when 802.11r IEs are present."""
    if wlan.fast_roaming_enabled is not True or wlan.bands != frozenset({Band.GHZ_2}):
        return None
    return _advisory(
        "fast_roaming_on_2g_only_wlan",
        wlan,
        "802.11r Fast Transition is known to break some IoT clients (ESP32, older printers, Sonos gen1) — "
        "a 2.4 GHz-only WLAN usually serves them; rely on BSS Transition (802.11v) alone there.",
        band=Band.GHZ_2,
    )


def min_rate_2g(profile: Profile, wlan: WlanConfig) -> Finding | None:
    """A fixed 2.4 GHz minimum below the lowest OFDM rate keeps 802.11b protection on every frame. Only a
    WLAN that broadcasts on 2.4 GHz, fixes its rates (`manual`; under `auto` the stored value is inert)
    and has 802.11b support switched on can be affected; an unknown `b_supported` is not assumed either
    way."""
    if (
        Band.GHZ_2 not in wlan.bands
        or minrate_mode(wlan) is not MinRateMode.MANUAL
        or wlan.minrate_ng_enabled is not True
        or wlan.minrate_ng_data_rate_kbps is None
        or wlan.b_supported is not True
    ):
        return None
    kbps = wlan.minrate_ng_data_rate_kbps
    if kbps in DSSS_RATES_KBPS:
        return _advisory(
            "min_rate_2g_dsss",
            wlan,
            f"{rate_label(kbps)} is an 802.11b DSSS rate — raising to {rate_label(MIN_OFDM_RATE_KBPS)} (lowest OFDM "
            "rate) ends 802.11b support and cuts broadcast airtime.",
            band=Band.GHZ_2,
        )
    if kbps < MIN_OFDM_RATE_KBPS:
        return _advisory(
            "min_rate_2g_below_ofdm",
            wlan,
            f"{rate_label(kbps)} is below the {rate_label(MIN_OFDM_RATE_KBPS)} recommendation — raising it cuts "
            "broadcast airtime, though this rate does not itself admit 802.11b clients.",
            band=Band.GHZ_2,
        )
    return None


def iot_locks_on_dual_band_wlan(profile: Profile, wlan: WlanConfig) -> Finding | None:
    """The IoT channel and DTIM locks pin 2.4 GHz behaviour for low-power clients; on a WLAN the profile
    expects on 5 GHz too, they hold back every dual-band client with it."""
    if Band.GHZ_5 not in profile.wifi_bands and Band.GHZ_6 not in profile.wifi_bands:
        return None
    locks = [
        name for name, on in (("IoT Channel Lock", wlan.iot_channel_lock), ("IoT DTIM Lock", wlan.iot_dtim_lock)) if on
    ]
    if not locks:
        return None
    return _advisory(
        "iot_locks_on_dual_band_wlan",
        wlan,
        f"{' and '.join(locks)} enabled on a WLAN meant for 5 GHz clients — these locks suit 2.4 GHz-only IoT WLANs.",
    )


def mdns_proxy_with_isolation(profile: Profile, wlan: WlanConfig) -> Finding | None:
    """Client isolation blocks the very peer-to-peer discovery an mDNS proxy exists to relay."""
    if wlan.l2_isolation is not True or wlan.mdns_proxy_mode in (None, "off"):
        return None
    return _advisory(
        "mdns_proxy_with_isolation",
        wlan,
        f"mDNS proxy is {wlan.mdns_proxy_mode} while Client Device Isolation is on — isolated clients cannot use what "
        "the proxy advertises.",
    )


def ppsk_requires_psk(profile: Profile, wlan: WlanConfig) -> Finding | None:
    """Private pre-shared keys ride on the WPA2 four-way handshake; WPA3-only (SAE) and Enterprise have none."""
    if wlan.private_preshared_keys_enabled is not True:
        return None
    protocol = _known_protocol(wlan)
    if protocol is None or protocol.is_personal_psk:
        return None
    return _advisory(
        "ppsk_requires_psk",
        wlan,
        f"Private Pre-Shared Keys need WPA2 or WPA2/WPA3 (a PSK handshake) — current: {protocol.value}.",
    )


def wpa3_192_requires_enterprise(profile: Profile, wlan: WlanConfig) -> Finding | None:
    """WPA3 Enhanced 192-bit (CNSA suite) is defined for WPA3-Enterprise only, without a WPA2 transition."""
    if wlan.wpa3_enhanced_192 is not True:
        return None
    protocol = _known_protocol(wlan)
    if protocol is None or protocol is SecurityProtocol.WPA3_ENTERPRISE:
        return None
    return _advisory(
        "wpa3_192_requires_enterprise",
        wlan,
        f"WPA3 Enhanced 192-bit is defined for WPA3 Enterprise only (no transition) — current: {protocol.value}.",
    )


ADVISORIES: tuple[Advisory, ...] = (
    mlo_requires_wpa3_pmf,
    pmf_matches_protocol,
    fast_roaming_without_bss_transition,
    fast_roaming_on_2g_only_wlan,
    min_rate_2g,
    iot_locks_on_dual_band_wlan,
    mdns_proxy_with_isolation,
    ppsk_requires_psk,
    wpa3_192_requires_enterprise,
)


def evaluate_advisories(
    profile: Profile, wlan: WlanConfig, advisories: Iterable[Advisory] = ADVISORIES
) -> tuple[Finding, ...]:
    return tuple(finding for advisory in advisories if (finding := advisory(profile, wlan)) is not None)
