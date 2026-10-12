"""Where a checked setting lives in the controller UI, keyed by check code, so a failed line is
actionable without a hunt. Silent (None) for a code without a known path rather than a guess."""

from collections.abc import Mapping

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
    "multicast_broadcast_blocker": f"{ADVANCED} → Hi-Capacity Tuning → Multicast and Broadcast Blocker",
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
    "iot_dtim_lock": f"{ADVANCED} → Behavior Controls → IoT DTIM Lock",
    "iot_channel_lock": f"{ADVANCED} → Behavior Controls → IoT Channel Lock",
    "enhanced_iot": f"{ADVANCED} → Behavior Controls → Enhanced IoT Connectivity",
    "b_supported": f"{ADVANCED} → Behavior Controls → 802.11b Support",
    "dns_assistance_mode": f"{ADVANCED} → DNS Assistance",
    "mdns_proxy_mode": f"{ADVANCED} → mDNS Proxy",
    "channel_layout": "AP settings → Radios → Channel dropdown (2.4/5 GHz)",
    "tx_power": "AP settings → Radios → Transmit Power (2.4/5 GHz) -- set to Custom, then the dBm field",
    "min_rssi": "AP settings → Radios → Minimum RSSI checkbox (2.4/5 GHz)",
}


def ui_path(code: str) -> str | None:
    return UI_PATHS.get(code)
