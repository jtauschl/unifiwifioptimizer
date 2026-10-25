# Profiles

A profile describes how a WLAN of one kind should be configured. The compliance check compares every
WLAN you map to a profile (`sites.<id>.wlans` in `config.yaml`) against that profile and reports each
deviation with the controller UI path to fix it.

Profiles are **recommendations with a stated evidence tier per key**, not snapshots of controller
defaults. A finding therefore means "this differs from a well-founded baseline", never merely "this
differs from the factory preset".

## Shipped profiles

| Profile | Intent | Key choices |
| --- | --- | --- |
| `Standard` | Everyday WLAN for phones and laptops on 2.4 + 5 GHz | WPA2/WPA3 transition with PMF Optional, 802.11r + 802.11v, Roaming Assistant on, band steering on, Proxy ARP on, multicast-to-unicast on |
| `IoT` | 2.4 GHz-only WLAN for legacy clients with compatibility issues | WPA2 (a WPA2/WPA3 transition is accepted too), PMF off or optional, no 802.11r, no active steering, no band steering, no group rekey — Ubiquiti recommends these compatibility settings when legacy IoT devices have trouble on Wi-Fi 7 |
| `Hotspot` | Guest WLAN | Enhanced Open (OWE, preferably in transition mode) or plain Open for captive portals, client isolation on, mDNS proxy off |
| `Throughput` | Primary WLAN tuned for airtime | WPA2/WPA3 (Personal or Enterprise), fixed minimum rate 12 Mbit/s on both bands, 802.11b off, the controller's DTIM defaults, group rekey 3600 s, Proxy ARP and multicast-to-unicast on |
| `Latency` | Primary WLAN tuned for responsiveness | As Throughput, with DTIM 1 on both bands |

Print the effective set, comments and evidence included:

```sh
unifiwifioptimizer config --profiles
```

## Your own profiles

Put a `profiles.yaml` next to the configuration file the run uses (`--config-file` or the XDG path; the
legacy data directory is never searched, because the 0.4.x installer left its own, differently shaped
`profiles.yaml` there) or pass `--profiles-file PATH`; a symlink to a regular file is fine. The file has the same
shape as the shipped one. A profile with a shipped name **replaces that profile whole** — no per-key
merge, so the file shows the complete expectation; new names are added; `evidence` entries replace the
shipped ones key by key, and a profile may carry its own `evidence` block for keys whose tier differs for
that profile. Unknown keys, unknown values and missing required keys are errors; the legacy key
`group_rekey` is reported as renamed to `group_rekey_s`, a scalar `pmf`/`security_protocols` as needing a
list.

```yaml
profiles:
  Media:
    wifi_bands: [5g]
    security_protocols: ["WPA2/WPA3"]
    pmf: [Optional]
    fast_roaming: false
    bss_transition: true
    roaming_assistant: false
    band_steering: false
    mlo: false
    uapsd: false
    proxy_arp: true
    multicast_broadcast_blocker: false
    multicast_to_unicast: true
    hide_wifi_name: false
    client_device_isolation: false
    ap_name_in_beacon: false
    minrate_mode: auto
    dtim_mode: default
    group_rekey_s: 3600
    sae_anti_clogging: 5
    sae_sync_time: 5
    evidence:
      multicast_to_unicast: {tier: practice, source: "our streaming boxes drop frames without it"}
```

## Keys

| Key | Compared against | Values |
| --- | --- | --- |
| `wifi_bands` | the WLAN's bands | list of `2g`, `5g`, `6g`; must match exactly |
| `security_protocols` | `security` + `wpa_mode` + `wpa3_support` + `wpa3_transition` | list; any listed protocol passes: `Open`, `Enhanced Open (OWE)`, `Enhanced Open with Transition`, `WPA2`, `WPA3`, `WPA2/WPA3`, `WPA2 Enterprise`, `WPA3 Enterprise`, `WPA2/WPA3 Enterprise` |
| `pmf` | `pmf_mode` | list of `Disabled`, `Optional`, `Required` |
| `fast_roaming` | `fast_roaming_enabled` (802.11r) | bool |
| `bss_transition` | `bss_transition` (802.11v BTM support) | bool |
| `roaming_assistant` | `roaming_assistant_na_enabled` | bool — only whether Handoff Suggestions should be on; the RSSI threshold always comes from the site's RF model (ALGORITHM.md §7). For a WLAN on 6 GHz the `roaming_assistant_6e_enabled` switch is shown as a separate, not evaluable result |
| `band_steering` | `no2ghz_oui` | bool |
| `mlo`, `uapsd`, `proxy_arp`, `multicast_broadcast_blocker`, `multicast_to_unicast`, `hide_wifi_name`, `client_device_isolation`, `ap_name_in_beacon` | the matching controller flag | bool |
| `minrate_mode` | `minrate_setting_preference` | `auto` or `manual` |
| `minrate_24_kbps`, `minrate_5_kbps` | `minrate_ng/na_enabled` + `_data_rate_kbps` | required when `manual` and the band is listed; a rate that is not enforced fails |
| `dtim_mode` | `dtim_mode` | `default` or `custom` |
| `dtim_24`, `dtim_5`, `dtim_6` | `dtim_ng`, `dtim_na`, `dtim_6e` | required when `custom` and the band is listed |
| `group_rekey_s` | `group_rekey` | seconds, 0 = disabled |
| `sae_anti_clogging`, `sae_sync_time` | `sae_anti_clogging`, `sae_sync` | checked only when the WLAN uses SAE (WPA3 or WPA2/WPA3 Personal) |
| `iot_dtim_lock`, `iot_channel_lock`, `enhanced_iot`, `b_supported`, `ppsk`, `wpa3_enhanced_192` | the matching controller flag | optional bool; unset = not checked |
| `dns_assistance_mode`, `mdns_proxy_mode` | the matching controller field | optional `off`, `auto`, `custom`; unset = not checked |
| `multicast_suppressor_mode` | Multicast Suppression | optional `off`, `conservative`, `aggressive`; unset = not checked |

A setting the controller did not send is reported as **incomplete**, never as a pass or a deviation. A
combination the controller did send but the tool has no name for (for example `wpapsk/wpa1`) is a
**deviation** and shows the raw pair. 6 GHz values (`dtim_6`) are **not evaluable** (6 GHz is detect-only).

## Evidence tiers

Every key carries a tier in the `evidence` section of the profiles file; a profile overrides it for keys
where its value is a compatibility choice (the IoT profile's PMF and protocol entries are `practice`
although the mechanisms are standards, because the standard argues for the stricter setting):

- **standard** — a published standard requires or defines exactly this value; today the `pmf` and
  `wpa3_enhanced_192` keys (IEEE 802.11w, Wi-Fi Alliance WPA3). A standard that defines a *mechanism* (802.11r,
  802.11v, Proxy ARP, WPA3 transition mode, OWE) does not recommend switching it on; that advice is vendor guidance.
- **vendor** — reproducible official guidance for this value or setting, each entry naming the document: Cisco
  Catalyst 9800 best practices (mandatory rates), Apple router settings, Ubiquiti help articles, including their
  advice to keep a default.
- **practice** — habit without a published derivation: DTIM values, U-APSD, isolation, the
  compatibility choices of the IoT profile. These are the tunables to adjust first when your environment disagrees.

## Advisories

Beyond the per-key comparison, the check reports cross-setting observations on the WLAN's actual
configuration:

| Advisory | Fires when |
| --- | --- |
| `mlo_requires_wpa3_pmf` | MLO is on without a WPA3-only protocol (Personal or Enterprise, no transition) and PMF Required (Wi-Fi Alliance Wi-Fi 7 certification; IEEE 802.11be itself does not mandate a security suite) |
| `pmf_matches_protocol` | PMF does not fit the protocol: WPA3-only and OWE-only need Required, a WPA3 transition mode exactly Optional (Required would lock out its WPA2 clients), OWE transition Optional or Required, plain Open has no RSN for PMF to protect (Wi-Fi Alliance WPA3 Specification, Wi-Fi Enhanced Open) |
| `fast_roaming_without_bss_transition` | 802.11r is on and 802.11v is off |
| `fast_roaming_on_2g_only_wlan` | 802.11r is on for a WLAN that broadcasts only on 2.4 GHz (IoT-class clients) |
| `min_rate_2g_dsss`, `min_rate_2g_below_recommended` | the WLAN broadcasts on 2.4 GHz with a fixed (`manual`) minimum rate that is a DSSS rate or below 12 Mbit/s, and 802.11b support is known to be on; silent under `auto` and while `b_supported` is unknown |
| `iot_locks_on_dual_band_wlan` | an IoT lock is on for a WLAN whose profile expects 5 or 6 GHz |
| `mdns_proxy_with_isolation` | the mDNS proxy is on while clients are isolated |
| `advanced_set_to_auto` | the WLAN's Advanced switch is on Auto (information; the stored values are reported as they are) |
| `ppsk_requires_psk` | Private Pre-Shared Keys are on without a PSK handshake (WPA2 or WPA2/WPA3) |
| `wpa3_192_requires_enterprise` | Enhanced 192-bit is on for anything but WPA3 Enterprise without transition (WPA2 Enterprise and WPA2/WPA3 Enterprise included) |

6 GHz is not judged for the WPA3/PMF requirement: the WLAN-level fields are shared across bands and the
controller enforces WPA3-only + PMF Required on the 6 GHz radio internally.

## References

- IEEE Std 802.11-2020 (incl. 802.11r/v/w/e); IEEE 802.11be
- Wi-Fi Alliance: WPA3 Specification; Wi-Fi Enhanced Open; WMM Power Save
- IETF RFC 8110 — Opportunistic Wireless Encryption
- Ubiquiti: [UniFi WiFi SSID and AP Settings Overview](https://help.ui.com/hc/en-us/articles/32065480092951-UniFi-WiFi-SSID-level-Settings-Overview)
- Cisco: [Catalyst 9800 Series Configuration Best Practices](https://www.cisco.com/c/en/us/products/collateral/wireless/catalyst-9800-series-wireless-controllers/guide-c07-743627.html)
- Apple: [Recommended settings for Wi-Fi routers and access points](https://support.apple.com/en-ie/102766)
- Ubiquiti: [Using PPSK / RADIUS for Multiple VLANs on an SSID](https://help.ui.com/hc/en-us/articles/29887064407319)
- Ubiquiti: [UniFi Wireless Guest Network Setup](https://help.ui.com/hc/en-us/articles/115000166827-UniFi-Wireless-Guest-Network-Setup)
- Ubiquiti: [Setting Up Passpoint on UniFi Network](https://help.ui.com/hc/en-us/articles/25473982758551-Setting-Up-Passpoint-on-UniFi-Network)
