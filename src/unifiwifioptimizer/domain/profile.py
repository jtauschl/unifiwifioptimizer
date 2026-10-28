"""WLAN profiles: the expected shape of a WLAN, compared against the controller's `wlanconf` by the
compliance engine. A profile is a recommendation with an evidence tier per key, never a controller
snapshot; the shipped set lives in `resources/profiles.yaml` and a site may override it."""

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum

from unifiwifioptimizer.domain.models import Band


class SecurityProtocol(StrEnum):
    """The controller UI's security-protocol names, derived from `security`, `wpa_mode`, `wpa3_support` and
    `wpa3_transition` by the compliance normaliser."""

    OPEN = "Open"
    OWE = "Enhanced Open (OWE)"
    OWE_TRANSITION = "Enhanced Open with Transition"
    WPA2 = "WPA2"
    WPA3 = "WPA3"
    WPA2_WPA3 = "WPA2/WPA3"
    WPA2_ENTERPRISE = "WPA2 Enterprise"
    WPA3_ENTERPRISE = "WPA3 Enterprise"
    WPA2_WPA3_ENTERPRISE = "WPA2/WPA3 Enterprise"

    @property
    def uses_sae(self) -> bool:
        """WPA3-Personal only: Enterprise authenticates over 802.1X/EAP and has no SAE counters."""
        return self in (SecurityProtocol.WPA3, SecurityProtocol.WPA2_WPA3)

    @property
    def is_open_family(self) -> bool:
        """Open and Enhanced Open: the controller does not send a group rekey interval for these."""
        return self in (SecurityProtocol.OPEN, SecurityProtocol.OWE, SecurityProtocol.OWE_TRANSITION)

    @property
    def uses_wpa3(self) -> bool:
        """Any WPA3 variant, Personal or Enterprise, transition or WPA3-only."""
        return self in (
            SecurityProtocol.WPA3,
            SecurityProtocol.WPA2_WPA3,
            SecurityProtocol.WPA3_ENTERPRISE,
            SecurityProtocol.WPA2_WPA3_ENTERPRISE,
        )

    @property
    def is_personal_psk(self) -> bool:
        """A pre-shared-key handshake exists (WPA2 or a WPA2/WPA3 transition); WPA3-only uses SAE alone."""
        return self in (SecurityProtocol.WPA2, SecurityProtocol.WPA2_WPA3)

    @property
    def required_pmf(self) -> frozenset["PmfMode"]:
        """The PMF settings the protocol admits. WPA3-only and OWE-only: required. A WPA3 transition mode:
        exactly optional (MFPC=1, MFPR=0 — required would lock out the WPA2 clients the mode exists for).
        OWE transition: optional or required (the OWE BSS protects, the Open twin cannot). Plain Open: no
        RSN, so PMF has nothing to protect. WPA2: either way. (Wi-Fi Alliance WPA3 Specification and Wi-Fi
        Enhanced Open; read from memory, the documents are not archived in the project.)"""
        if self in (SecurityProtocol.WPA3, SecurityProtocol.WPA3_ENTERPRISE, SecurityProtocol.OWE):
            return frozenset({PmfMode.REQUIRED})
        if self in (SecurityProtocol.WPA2_WPA3, SecurityProtocol.WPA2_WPA3_ENTERPRISE):
            return frozenset({PmfMode.OPTIONAL})
        if self is SecurityProtocol.OWE_TRANSITION:
            return frozenset({PmfMode.OPTIONAL, PmfMode.REQUIRED})
        if self is SecurityProtocol.OPEN:
            return frozenset({PmfMode.DISABLED})
        return frozenset(PmfMode)


class PmfMode(StrEnum):
    DISABLED = "Disabled"
    OPTIONAL = "Optional"
    REQUIRED = "Required"


class MinRateMode(StrEnum):
    AUTO = "auto"
    MANUAL = "manual"


class DtimMode(StrEnum):
    DEFAULT = "default"
    CUSTOM = "custom"


class EvidenceTier(StrEnum):
    """How well a profile key's recommendation is backed: a published standard (IEEE 802.11, Wi-Fi
    Alliance, IETF), reproducible official vendor guidance, or community practice."""

    STANDARD = "standard"
    VENDOR = "vendor"
    PRACTICE = "practice"


DNS_ASSISTANCE_MODES = frozenset({"off", "auto", "manual"})
MDNS_PROXY_MODES = frozenset({"off", "auto", "custom"})
MULTICAST_SUPPRESSOR_MODES = frozenset({"off", "conservative", "aggressive"})
# 6 and 9 Mbit/s are OFDM rates below the recommendation; unlike DSSS rates, they do not admit 802.11b clients.
DSSS_RATES_KBPS = frozenset({1000, 2000, 5500, 11000})
RECOMMENDED_MIN_RATE_2G_KBPS = 12000


@dataclass(frozen=True, slots=True, kw_only=True)
class Evidence:
    tier: EvidenceTier
    source: str


@dataclass(frozen=True, slots=True, kw_only=True)
class Profile:
    """Expected WLAN settings. A key whose value is None is not checked for this profile. `evidence` holds
    the keys whose tier differs for this profile from the set's global entry (a compatibility choice that
    a standard argues against is `practice` here even where the mechanism itself is a standard)."""

    name: str
    wifi_bands: frozenset[Band]
    security_protocols: frozenset[SecurityProtocol]
    pmf: frozenset[PmfMode]
    fast_roaming: bool
    bss_transition: bool
    roaming_assistant: bool
    band_steering: bool
    mlo: bool
    uapsd: bool
    proxy_arp: bool
    multicast_to_unicast: bool
    hide_wifi_name: bool
    client_device_isolation: bool
    ap_name_in_beacon: bool
    minrate_mode: MinRateMode
    minrate_24_kbps: int | None
    minrate_5_kbps: int | None
    dtim_mode: DtimMode
    dtim_24: int | None
    dtim_5: int | None
    dtim_6: int | None
    group_rekey_s: int
    sae_anti_clogging: int
    sae_sync_time: int
    iot_dtim_lock: bool | None = None
    iot_channel_lock: bool | None = None
    enhanced_iot: bool | None = None
    dns_assistance_mode: str | None = None
    mdns_proxy_mode: str | None = None
    multicast_suppressor_mode: str | None = None
    ppsk: bool | None = None
    wpa3_enhanced_192: bool | None = None
    evidence: Mapping[str, Evidence] = field(default_factory=dict)


@dataclass(frozen=True, slots=True, kw_only=True)
class ProfileSet:
    """The profiles a run compares against, plus the evidence tier recorded for every profile key."""

    profiles: Mapping[str, Profile]
    evidence: Mapping[str, Evidence]

    def get(self, name: str) -> Profile | None:
        return self.profiles.get(name)

    def evidence_for(self, profile: Profile, key: str) -> Evidence | None:
        """The profile's own entry wins over the set-wide one."""
        return profile.evidence.get(key) or self.evidence.get(key)
