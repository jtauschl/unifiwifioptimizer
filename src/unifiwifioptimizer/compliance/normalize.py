"""Controller field combinations turned into the vocabulary the profiles use.

Three outcomes are kept apart: the recognised value, `None` when the controller did not send what the
derivation needs (a check reports `INCOMPLETE`), and `Unrecognised` when it sent a combination the tool has
no name for (a check reports `FAILED` and shows the raw combination) — a WPA/TKIP WLAN is a deviation, not
missing data."""

from dataclasses import dataclass

from unifiwifioptimizer.domain.models import Band, WlanConfig
from unifiwifioptimizer.domain.profile import DtimMode, MinRateMode, PmfMode, SecurityProtocol

ENTERPRISE_SECURITY = frozenset({"wpaeap", "wpa-enterprise", "enterprise"})
PSK_SECURITY = "wpapsk"
OPEN_SECURITY = "open"


@dataclass(frozen=True, slots=True)
class Unrecognised:
    """A controller combination outside the known vocabulary, kept verbatim for the report."""

    text: str


def security_protocol(wlan: WlanConfig) -> SecurityProtocol | Unrecognised | None:
    """The UI's protocol name for the WLAN's `security`/`wpa_mode`/`wpa3_*` combination.

    `wpa3_transition` is only meaningful next to `wpa3_support`; an absent flag counts as off, because the
    controller omits flags it has never set, while an absent `security` leaves the protocol unknown."""
    security = wlan.security
    if security is None:
        return None
    wpa3 = wlan.wpa3_support is True
    transition = wpa3 and wlan.wpa3_transition is True
    if security == OPEN_SECURITY:
        if transition:
            return SecurityProtocol.OWE_TRANSITION
        return SecurityProtocol.OWE if wpa3 else SecurityProtocol.OPEN
    if security in ENTERPRISE_SECURITY:
        if transition:
            return SecurityProtocol.WPA2_WPA3_ENTERPRISE
        if wpa3:
            return SecurityProtocol.WPA3_ENTERPRISE
        if wlan.wpa_mode == "wpa2":
            return SecurityProtocol.WPA2_ENTERPRISE
    elif security == PSK_SECURITY:
        if transition:
            return SecurityProtocol.WPA2_WPA3
        if wpa3:
            return SecurityProtocol.WPA3
        if wlan.wpa_mode == "wpa2":
            return SecurityProtocol.WPA2
    return Unrecognised(f"{security}/{wlan.wpa_mode or '-'}")


def pmf_mode(wlan: WlanConfig) -> PmfMode | Unrecognised | None:
    match wlan.pmf_mode:
        case None:
            return None
        case "required":
            return PmfMode.REQUIRED
        case "optional":
            return PmfMode.OPTIONAL
        case "disabled":
            return PmfMode.DISABLED
        case other:
            return Unrecognised(other)


def minrate_mode(wlan: WlanConfig) -> MinRateMode | Unrecognised | None:
    match wlan.minrate_setting_preference:
        case None:
            return None
        case "auto":
            return MinRateMode.AUTO
        case "manual":
            return MinRateMode.MANUAL
        case other:
            return Unrecognised(other)


def dtim_mode(wlan: WlanConfig) -> DtimMode | Unrecognised | None:
    match wlan.dtim_mode:
        case None:
            return None
        case "default":
            return DtimMode.DEFAULT
        case "custom":
            return DtimMode.CUSTOM
        case other:
            return Unrecognised(other)


def rate_label(kbps: int) -> str:
    """`12000` → `12 Mbps`, `5500` → `5.5 Mbps`, `1050` → `1.05 Mbps`."""
    whole, rem = divmod(kbps, 1000)
    if rem == 0:
        return f"{whole} Mbps"
    return f"{whole}.{f'{rem:03d}'.rstrip('0')} Mbps"


def rekey_label(seconds: int) -> str:
    return "Disabled" if seconds == 0 else f"{seconds} s"


def bands_label(bands: frozenset[Band]) -> str:
    """`2.4 GHz, 5 GHz` in band order; `n/a` for no band."""
    ordered = sorted(bands, key=lambda band: band.value)
    return ", ".join(band.label for band in ordered) if ordered else "n/a"
