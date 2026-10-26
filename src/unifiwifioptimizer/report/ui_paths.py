"""Where a checked setting lives in the controller UI, keyed by check code, so a failed line is
actionable without a hunt. Silent (None) for a code without a known path rather than a guess."""

from collections.abc import Callable, Iterable, Mapping
from typing import TypeVar

_Item = TypeVar("_Item")

WLAN_EDIT = "WLAN edit"
ADVANCED = f"{WLAN_EDIT} → Advanced"

UI_PATHS: Mapping[str, str] = {
    "wlan_enabled": f"{WLAN_EDIT} → Enabled toggle",
    "wifi_bands": f"{WLAN_EDIT} → Radio Band checkboxes (above Advanced)",
    "fast_roaming": f"{ADVANCED} → Roaming Assistance → Fast Roaming (802.11r)",
    "roaming_assistant": f"{ADVANCED} → Roaming Assistance → Handoff Suggestions (802.11v)",
    "roaming_assistant_6g": f"{ADVANCED} → Roaming Assistance → Handoff Suggestions (802.11v) → 6 GHz",
    "minrate_mode": f"{ADVANCED} → Hi-Capacity Tuning → Minimum Data Rate (Basic & Multicast)",
    "minrate_24": f"{ADVANCED} → Hi-Capacity Tuning → Minimum Data Rate → 2.4 GHz slider",
    "minrate_5": f"{ADVANCED} → Hi-Capacity Tuning → Minimum Data Rate → 5 GHz slider",
    "multicast_broadcast_blocker": f"{ADVANCED} → Hi-Capacity Tuning → Multicast Filtering",
    "multicast_to_unicast": f"{ADVANCED} → Hi-Capacity Tuning → Multicast to Unicast",
    "proxy_arp": f"{ADVANCED} → Hi-Capacity Tuning → Proxy ARP",
    "security_protocol": f"{WLAN_EDIT} → Security Protocol dropdown (above Advanced)",
    "pmf": f"{ADVANCED} → Security → PMF",
    "hide_wifi_name": f"{ADVANCED} → Security → Hide WiFi Name",
    "client_device_isolation": f"{ADVANCED} → Security → Client Device Isolation",
    "sae_anti_clogging": f"{ADVANCED} → Security → SAE Anti-clogging",
    "sae_sync_time": f"{ADVANCED} → Security → SAE Sync Time",
    "ppsk": f"{ADVANCED} → Security → Private Pre-Shared Keys",
    "wpa3_enhanced_192": f"{WLAN_EDIT} → Security Protocol → WPA3 Enterprise → Enhanced 192-bit",
    "mlo": (
        f"{ADVANCED} → Behavior Controls → MLO (note: toggling MLO also silently sets PMF Required, drops WPA2 "
        "fallback, and disables Fast Roaming -- verify those three afterward)"
    ),
    "band_steering": f"{ADVANCED} → Behavior Controls → Band Steering",
    "bss_transition": f"{ADVANCED} → Behavior Controls → BSS Transition",
    "uapsd": f"{ADVANCED} → Behavior Controls → UAPSD",
    "dtim_mode": f"{ADVANCED} → Behavior Controls → Auto 802.11 DTIM Period",
    "dtim_24": f"{ADVANCED} → Behavior Controls → Auto 802.11 DTIM Period → 2.4 GHz field",
    "dtim_5": f"{ADVANCED} → Behavior Controls → Auto 802.11 DTIM Period → 5 GHz field",
    "dtim_6": f"{ADVANCED} → Behavior Controls → Auto 802.11 DTIM Period → 6 GHz field",
    "group_rekey": f"{ADVANCED} → Behavior Controls → Group Rekey Interval",
    "ap_name_in_beacon": f"{ADVANCED} → Behavior Controls → Show Access Point Name in Beacon",
    "iot_dtim_lock": f"{ADVANCED} → IoT Optimization → DTIM Interval Lock",
    "iot_channel_lock": f"{ADVANCED} → IoT Optimization → Lock 2.4 GHz to Channel 6 (All APs)",
    "enhanced_iot": f"{ADVANCED} → Behavior Controls → Enhanced IoT Connectivity",
    "b_supported": f"{ADVANCED} → Behavior Controls → 802.11b Support",
    "dns_assistance_mode": f"{ADVANCED} → Behavior Controls → DNS Assistance",
    "mdns_proxy_mode": f"{ADVANCED} → mDNS Proxy",
    "multicast_suppressor_mode": f"{ADVANCED} → Hi-Capacity Tuning → Multicast Suppression",
    "tx_power": "AP settings → Radios → Transmit Power (2.4/5 GHz) -- set to Custom, then the dBm field",
    "min_rssi": "AP settings → Radios → Minimum RSSI checkbox (2.4/5 GHz)",
}


# Settings whose place a reader cannot guess from the label: the label differs from the UI's, the switch sits behind
# another one, or the toggle has side effects. Everything else sits where the report's own row order puts it.
HINTED = frozenset(
    {
        "roaming_assistant",
        "roaming_assistant_6g",
        "minrate_mode",
        "multicast_broadcast_blocker",
        "mlo",
        "dtim_mode",
        "dtim_24",
        "dtim_5",
        "dtim_6",
        "iot_dtim_lock",
        "iot_channel_lock",
        "enhanced_iot",
        "b_supported",
        "dns_assistance_mode",
        "mdns_proxy_mode",
        "ppsk",
        "wpa3_enhanced_192",
    }
)


# The order of the controller UI's WLAN editor, so a report row sits where the setting does.
UI_ORDER: tuple[str, ...] = (
    "wlan_enabled",
    "wifi_bands",
    "fast_roaming",
    "roaming_assistant",
    "roaming_assistant_6g",
    "minrate_mode",
    "minrate_24",
    "minrate_5",
    "b_supported",
    "multicast_broadcast_blocker",
    "multicast_to_unicast",
    "proxy_arp",
    "multicast_suppressor_mode",
    "iot_channel_lock",
    "enhanced_iot",
    "iot_dtim_lock",
    "security_protocol",
    "wpa3_enhanced_192",
    "pmf",
    "ppsk",
    "hide_wifi_name",
    "client_device_isolation",
    "sae_anti_clogging",
    "sae_sync_time",
    "dns_assistance_mode",
    "mlo",
    "band_steering",
    "bss_transition",
    "uapsd",
    "dtim_mode",
    "dtim_24",
    "dtim_5",
    "dtim_6",
    "group_rekey",
    "ap_name_in_beacon",
    "mdns_proxy_mode",
)
_RANK = {code: index for index, code in enumerate(UI_ORDER)}


def in_ui_order(items: Iterable[_Item], code_of: Callable[[_Item], str]) -> list[_Item]:
    """Stable: a code the table does not know keeps its place after the known ones."""
    return sorted(items, key=lambda item: _RANK.get(code_of(item), len(UI_ORDER)))


def ui_path(code: str) -> str | None:
    return UI_PATHS.get(code)


def ui_hint(code: str) -> str | None:
    """The path of a setting that is hard to find; None for one whose row already says where it is."""
    return UI_PATHS.get(code) if code in HINTED else None
