"""Render the settings matrix of docs/PROFILES.md from the shipped profiles.

Run `uv run python -m tests.tools.profile_matrix` after an intentional change to profiles.yaml or to a
description below; the docs test compares the block between the markers with this output and never writes.
"""

import sys
from pathlib import Path

from unifiwifioptimizer.compliance.normalize import bands_label, rate_label
from unifiwifioptimizer.config.profiles import shipped_profiles
from unifiwifioptimizer.domain.profile import Profile, ProfileSet

DOC = Path(__file__).parents[2] / "docs" / "PROFILES.md"
START = "<!-- profile-matrix:start -->"
END = "<!-- profile-matrix:end -->"
NOT_CHECKED = "\u2013"

Row = tuple[str, str, str]  # profile key, controller UI label, what it does
GROUPS: tuple[tuple[str, tuple[Row, ...]], ...] = (
    (
        "Network",
        (("wifi_bands", "Radio Band", "Bands the WLAN broadcasts on; the list must match exactly."),),
    ),
    (
        "Security",
        (
            (
                "security_protocols",
                "Security Protocol",
                "Accepted security modes, any listed one passes. WPA2/WPA3 is the transition mode that serves both "
                "generations of clients.",
            ),
            (
                "pmf",
                "PMF",
                "Protected Management Frames (802.11w) stop forged disconnects. WPA3 requires them; a WPA2-only "
                "client that fails on them needs them off.",
            ),
            ("hide_wifi_name", "Hide WiFi Name", "Hiding the name adds no security."),
        ),
    ),
    (
        "Roaming",
        (
            (
                "fast_roaming",
                "Fast Roaming (802.11r)",
                "Fast BSS Transition: a client joins the next access point without a full handshake. Old drivers can "
                "fail on it.",
            ),
            (
                "bss_transition",
                "BSS Transition (802.11v)",
                "Lets an access point suggest a better access point to a client; the basis of Handoff Suggestions "
                "and band steering.",
            ),
            (
                "roaming_assistant",
                "Handoff Suggestions (802.11v)",
                "Whether the controller sends the suggestions. The signal threshold comes from the site's RF model, "
                "not from the profile.",
            ),
            (
                "band_steering",
                "Band Steering",
                "Moves clients from 2.4 GHz to the other bands; not judged without 2.4 GHz plus another band.",
            ),
        ),
    ),
    (
        "Data rates and beacons",
        (
            (
                "minrate_mode",
                "Minimum Data Rate Mode",
                "auto lets clients use every rate; manual fixes the lowest rate an access point accepts.",
            ),
            (
                "minrate_24_kbps",
                "Minimum Data Rate 2.4 GHz",
                "Only with manual rates. A higher floor saves airtime and shrinks the cell; weak clients drop out.",
            ),
            (
                "minrate_5_kbps",
                "Minimum Data Rate 5 GHz",
                "Only with manual rates, same trade-off as on 2.4 GHz.",
            ),
            (
                "b_supported",
                "802.11b Support",
                "Off removes 802.11b-only clients and their airtime cost. The controller does not report it under "
                "automatic rates.",
            ),
            (
                "dtim_mode",
                "Auto 802.11 DTIM Period",
                "default keeps the controller's interval; custom pins one per band.",
            ),
            (
                "group_rekey_s",
                "Group Rekey Interval",
                "How often the group key is renewed. Not judged on an open or OWE WLAN when the controller sends none.",
            ),
        ),
    ),
    (
        "Multicast and airtime",
        (
            ("proxy_arp", "Proxy ARP", "The access point answers ARP for sleeping clients; less broadcast traffic."),
            (
                "multicast_to_unicast",
                "Multicast to Unicast",
                "Turns multicast into unicast. Helps casting and streaming discovery; some smart-home devices need "
                "it off.",
            ),
            (
                "multicast_broadcast_blocker",
                "Multicast Filtering",
                "Blocks multicast and broadcast towards clients; mDNS and DHCP need them.",
            ),
            ("uapsd", "UAPSD", "Client power saving; can break legacy clients."),
        ),
    ),
    (
        "Isolation and information",
        (
            (
                "client_device_isolation",
                "Client Device Isolation",
                "Stops clients on the same access point from talking to each other; for guests.",
            ),
            ("ap_name_in_beacon", "Show Access Point Name in Beacon", "Information leak with no benefit to clients."),
            ("mlo", "MLO", "Wi-Fi 7 multi-link operation; needs WPA3 and Wi-Fi 7 clients."),
            ("mdns_proxy_mode", "mDNS Proxy", "Service discovery across VLANs; never on isolated WLANs."),
        ),
    ),
    (
        "IoT optimization",
        (
            (
                "iot_channel_lock",
                "Lock 2.4 GHz to Channel 6 (All APs)",
                "Pins the 2.4 GHz radio of every access point, for every SSID on it, to channel 6; off keeps the "
                "channel plan.",
            ),
        ),
    ),
    (
        "WPA3 handshake",
        (
            (
                "sae_anti_clogging",
                "SAE Anti-clogging",
                "Protects the WPA3 handshake against floods; keep the controller default.",
            ),
            ("sae_sync_time", "SAE Sync Time", "WPA3 handshake timing; keep the controller default."),
        ),
    ),
)
# Keys that stay unset in every shipped profile: they are checked only when a profile of your own sets them.
UNSET_BY_DEFAULT = frozenset(
    {
        "dtim_24",
        "dtim_5",
        "dtim_6",
        "iot_dtim_lock",
        "enhanced_iot",
        "dns_assistance_mode",
        "multicast_suppressor_mode",
        "ppsk",
        "wpa3_enhanced_192",
        "evidence",
        "name",
    }
)


def _on_off(value: bool) -> str:
    return "on" if value else "off"


def cell(profile: Profile, key: str) -> str:
    value = getattr(profile, key)
    if value is None:
        return NOT_CHECKED
    if key == "wifi_bands":
        return bands_label(value)
    if key in ("security_protocols", "pmf"):
        return ", ".join(sorted(item.value for item in value))
    if key == "group_rekey_s":
        return "off" if value == 0 else f"{value} s"
    if key.startswith("minrate_") and key.endswith("_kbps"):
        return rate_label(value)
    if isinstance(value, bool):
        return _on_off(value)
    return str(value.value if hasattr(value, "value") else value)


def render_matrix(profiles: ProfileSet) -> str:
    ordered = list(profiles.profiles.values())
    header = ["Group", "Setting", *(f"`{p.name}`" for p in ordered), "What it does"]
    lines = ["| " + " | ".join(header) + " |", "| " + " | ".join("---" for _ in header) + " |"]
    for group, rows in GROUPS:
        for index, (key, label, description) in enumerate(rows):
            cells = [cell(p, key) for p in ordered]
            lines.append("| " + " | ".join([group if index == 0 else "", label, *cells, description]) + " |")
    return "\n".join(lines)


def covered_keys() -> frozenset[str]:
    return frozenset(key for _, rows in GROUPS for key, _, _ in rows)


def block(profiles: ProfileSet) -> str:
    return f"{START}\n{render_matrix(profiles)}\n{END}"


def main() -> int:
    text = DOC.read_text(encoding="utf-8")
    start, end = text.index(START), text.index(END) + len(END)
    DOC.write_text(text[:start] + block(shipped_profiles()) + text[end:], encoding="utf-8")
    print(f"wrote the profile matrix into {DOC}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
