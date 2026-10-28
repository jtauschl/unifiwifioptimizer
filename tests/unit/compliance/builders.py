"""Builders for compliance tests: a WLAN as the controller would report it, matched to a shipped profile."""

from dataclasses import fields, replace
from typing import Any

from unifiwifioptimizer.config.profiles import shipped_profiles
from unifiwifioptimizer.domain.models import Band, WlanConfig
from unifiwifioptimizer.domain.profile import Profile

PROFILES = shipped_profiles()


def wlan(**overrides: Any) -> WlanConfig:
    """Every optional field None unless overridden; `enabled` and both bands by default."""
    values: dict[str, Any] = {f.name: None for f in fields(WlanConfig)}
    values.update(id="w1", name="SSID-1", enabled=True, bands=frozenset({Band.GHZ_2, Band.GHZ_5}), ap_group_ids=())
    values.update(overrides)
    return WlanConfig(**values)


def standard_wlan(**overrides: Any) -> WlanConfig:
    """A WLAN that passes every rule of the shipped `Standard` profile."""
    base = wlan(
        security="wpapsk",
        wpa_mode="wpa2",
        wpa3_support=True,
        wpa3_transition=True,
        pmf_mode="optional",
        hide_ssid=False,
        l2_isolation=False,
        proxy_arp=True,
        bss_transition=True,
        fast_roaming_enabled=True,
        roaming_assistant_na_enabled=True,
        roaming_assistant_na_rssi=-70,
        uapsd_enabled=False,
        mcastenhance_enabled=True,
        bc_filter_enabled=False,
        multicast_suppressor_mode="off",
        dns_assistance_mode="off",
        minrate_setting_preference="manual",
        minrate_ng_enabled=True,
        minrate_ng_data_rate_kbps=12000,
        minrate_na_enabled=True,
        minrate_na_data_rate_kbps=12000,
        dtim_mode="default",
        dtim_ng=1,
        dtim_na=3,
        group_rekey=3600,
        sae_anti_clogging=5,
        sae_sync=5,
        band_steering=True,
        advertise_device_name_in_beacon=False,
        mlo_enabled=False,
    )
    return replace(base, **overrides)


def profile(name: str = "Standard", **overrides: Any) -> Profile:
    return replace(PROFILES.profiles[name], **overrides)
