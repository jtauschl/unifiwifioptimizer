# Profiles

A profile describes how a WLAN of one kind should be configured. The compliance check compares every
WLAN you map to a profile (`sites.<id>.wlans` in `config.yaml`) against that profile and reports each
deviation with the controller UI path to fix it.

Profiles are **recommendations with a stated evidence tier per key**, not snapshots of controller
defaults. A finding therefore means "this differs from a well-founded baseline", never merely "this
differs from the factory preset".

## Which profile for which device

A profile is chosen by how the devices behave, not by the network they sit in. The VLAN or firewall zone of a
WLAN is a network decision; the profile only says which WLAN settings those devices need. Map each WLAN in
`sites.<id>.wlans`; a second WLAN is only worth its airtime (each SSID adds beacons on every band) when its
devices need different settings or a different network.

| Device class | Profile | Why |
| --- | --- | --- |
| Phones, tablets, laptops | `Standard` | Move between access points, so roaming helps; modern security. |
| Smart TVs, streaming boxes, speakers, game consoles | `Compat` | Mostly stationary and often older firmware: no fast roaming, automatic rates, WPA2 accepted, multicast help for casting and discovery. |
| Printers and scanners with 5 GHz | `Compat` | Same as above; discovery relies on multicast. |
| Printers, plugs, sensors, thermostats, cameras on 2.4 GHz only | `IoT` | 2.4 GHz only, WPA2, PMF off or optional, nothing active (Ubiquiti's IoT checklist). |
| Visitors' devices | `Hotspot` | Enhanced Open (OWE) or Open, clients isolated. |

Old laptops and phones that fail on `Standard` belong on `Compat`; a device that only speaks 2.4 GHz and
a plain password belongs on `IoT`. Isolation of a network from the rest of the house is firewall work (VLAN and
zone rules), not a WLAN profile setting.

## Shipped profiles

| Profile | Intent |
| --- | --- |
| `Standard` | Everyday WLAN for modern clients on 2.4 + 5 GHz: 802.11r + 802.11v, Handoff Suggestions and band steering on, fixed 12 Mbit/s minimum rate, 802.11b off; WPA2/WPA3 (WPA3-only accepted) |
| `Compat` | The same WLAN for clients that dislike 802.11r, fixed rates or WPA3: 802.11r off, automatic rates, WPA2 accepted, PMF optional or off |
| `IoT` | 2.4 GHz-only WLAN for IoT clients: WPA2, PMF off or optional, no roaming features, no steering, no group rekey |
| `Hotspot` | Guest WLAN: Enhanced Open (OWE, preferably in transition mode) or plain Open for captive portals, client isolation, Proxy ARP, mDNS proxy off |

### Settings by profile

The table is generated from `profiles.yaml`; a test fails when the two differ. A dash means the profile does not
check the setting.

<!-- profile-matrix:start -->
| Group | Setting | `Standard` | `Compat` | `IoT` | `Hotspot` | What it does |
| --- | --- | --- | --- | --- | --- | --- |
| Network | Radio Band | 2.4 GHz, 5 GHz | 2.4 GHz, 5 GHz | 2.4 GHz | 2.4 GHz, 5 GHz | Bands the WLAN broadcasts on; the list must match exactly. |
| Security | Security Protocol | WPA2/WPA3, WPA2/WPA3 Enterprise, WPA3, WPA3 Enterprise | WPA2, WPA2 Enterprise, WPA2/WPA3, WPA2/WPA3 Enterprise | WPA2 | Enhanced Open (OWE), Enhanced Open with Transition, Open | Accepted security modes, any listed one passes. WPA2/WPA3 is the transition mode that serves both generations of clients. |
|  | PMF | Optional, Required | Disabled, Optional | Disabled, Optional | Disabled, Optional, Required | Protected Management Frames (802.11w) stop forged disconnects. WPA3 requires them; a WPA2-only client that fails on them needs them off. |
|  | Hide WiFi Name | off | off | off | off | Hiding the name adds no security. |
| Roaming | Fast Roaming (802.11r) | on | off | off | off | Fast BSS Transition: a client joins the next access point without a full handshake. Old drivers can fail on it. |
|  | BSS Transition (802.11v) | on | on | off | on | Lets an access point suggest a better access point to a client; the basis of Handoff Suggestions and band steering. |
|  | Handoff Suggestions (802.11v) | on | on | off | on | Whether the controller sends the suggestions. The signal threshold comes from the site's RF model, not from the profile. |
|  | Band Steering | on | on | off | on | Moves clients from 2.4 GHz to the other bands; not judged without 2.4 GHz plus another band. |
| Data rates and beacons | Minimum Data Rate Mode | manual | auto | auto | auto | auto lets clients use every rate; manual fixes the lowest rate an access point accepts. |
|  | Minimum Data Rate 2.4 GHz | 12 Mbps | – | – | – | Only with manual rates. A higher floor saves airtime and shrinks the cell; 12 Mbps ends 802.11b. |
|  | Minimum Data Rate 5 GHz | 12 Mbps | – | – | – | Only with manual rates, same trade-off as on 2.4 GHz. |
|  | Auto 802.11 DTIM Period | default | default | default | default | default keeps the controller's interval; custom pins one per band. |
|  | Group Rekey Interval | 3600 s | 3600 s | off | 3600 s | How often the group key is renewed. Not judged on an open or OWE WLAN when the controller sends none. |
| Multicast and airtime | Multicast Filtering | – | – | – | off | Service discovery: Auto within the WLAN's VLAN, Custom across VLANs by rules; never when isolated. |
|  | Multicast to Unicast | on | on | off | off | Turns multicast into unicast. Helps casting and streaming discovery; some smart-home devices need it off. |
|  | Proxy ARP | on | on | off | on | The access point answers ARP for sleeping clients; less broadcast traffic. |
|  | Multicast Suppression | off | off | off | off | Limits multicast and broadcast traffic: Conservative prevents storms, Aggressive blocks all but DHCP and ARP unless a device is allowlisted. |
|  | UAPSD | off | off | off | off | Client power saving; can break legacy clients. |
| Isolation and information | Client Device Isolation | off | off | off | on | Stops clients on the same access point from talking to each other; for guests. |
|  | Show Access Point Name in Beacon | off | off | off | off | Information leak with no benefit to clients. |
|  | MLO | off | off | off | off | Wi-Fi 7 multi-link operation; needs WPA3 and Wi-Fi 7 clients. |
| IoT optimization | Lock 2.4 GHz to Channel 6 (All APs) | – | – | off | – | Pins the 2.4 GHz radio of every access point, for every SSID on it, to channel 6; off keeps the channel plan. |
| WPA3 handshake | SAE Anti-clogging | 5 | 5 | 5 | 5 | Protects the WPA3 handshake against floods; keep the controller default. |
|  | SAE Sync Time | 5 | 5 | 5 | 5 | WPA3 handshake timing; keep the controller default. |
<!-- profile-matrix:end -->

Each value carries an evidence tier and a source in `profiles.yaml` (see "Evidence tiers" below).

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
    multicast_suppressor_mode: "off"
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
| `pmf` | `pmf_mode` | list of `Disabled`, `Optional`, `Required`; judged separately from the protocol, the advisory `pmf_matches_protocol` judges the pair (so `Standard` accepting `Required` still reports a WPA2/WPA3 transition WLAN that has it) |
| `fast_roaming` | `fast_roaming_enabled` (802.11r) | bool |
| `bss_transition` | `bss_transition` (802.11v BTM support) | bool |
| `roaming_assistant` | `roaming_assistant_na_enabled` | bool — only whether Handoff Suggestions should be on; the RSSI threshold always comes from the site's RF model (ALGORITHM.md §7). For a WLAN on 6 GHz the `roaming_assistant_6e_enabled` switch is shown as a separate, not evaluable result |
| `band_steering` | `no2ghz_oui` | bool |
| `mlo`, `uapsd`, `proxy_arp`, `multicast_to_unicast`, `hide_wifi_name`, `client_device_isolation`, `ap_name_in_beacon` | the matching controller flag | bool |
| `minrate_mode` | `minrate_setting_preference` | `auto` or `manual` |
| `minrate_24_kbps`, `minrate_5_kbps` | `minrate_ng/na_enabled` + `_data_rate_kbps` | required when `manual` and the band is listed; a rate that is not enforced fails |
| `dtim_mode` | `dtim_mode` | `default` or `custom` |
| `dtim_24`, `dtim_5`, `dtim_6` | `dtim_ng`, `dtim_na`, `dtim_6e` | required when `custom` and the band is listed |
| `group_rekey_s` | `group_rekey` | seconds, 0 = disabled |
| `sae_anti_clogging`, `sae_sync_time` | `sae_anti_clogging`, `sae_sync` | checked only when the WLAN uses SAE (WPA3 or WPA2/WPA3 Personal) |
| `iot_dtim_lock`, `iot_channel_lock`, `enhanced_iot`, `ppsk`, `wpa3_enhanced_192` | the matching controller flag | optional bool; unset = not checked |
| `dns_assistance_mode`, `mdns_proxy_mode` (Multicast Filtering) | the matching controller field | optional `off`, `auto`, `custom`; unset = not checked |
| `multicast_suppressor_mode` | Multicast Suppression | optional `off`, `conservative`, `aggressive`; unset = not checked |

A setting the controller did not send is reported as **incomplete**, never as a pass or a deviation. A
combination the controller did send but the tool has no name for (for example `wpapsk/wpa1`) is a
**deviation** and shows the raw pair. 6 GHz values (`dtim_6`) are **not evaluable** (6 GHz is detect-only).

## Evidence tiers

Every key carries a tier in the `evidence` section of the profiles file; a profile overrides it for keys
where its value differs from the set-wide entry (the `Compat` profile quotes Ubiquiti's legacy-client
checklist for 802.11r and the minimum rate, `IoT` its IoT checklist, `Hotspot` Ubiquiti's guest guidance):

- **standard** — a published standard requires or defines exactly this value; today the `pmf` and
  `wpa3_enhanced_192` keys and the Open/OWE fast-roaming entry of `Hotspot` (IEEE 802.11w and 802.11r, Wi-Fi Alliance WPA3). A standard that defines a *mechanism* (802.11r,
  802.11v, Proxy ARP, WPA3 transition mode, OWE) does not recommend switching it on; that advice is vendor guidance.
- **vendor** — reproducible official guidance for this value or setting, each entry naming the document: Cisco
  Catalyst 9800 best practices (mandatory rates), Apple router settings, Ubiquiti help articles, including their
  advice to keep a default.
- **practice** — habit without a published derivation: multicast filtering, the access point name in the beacon, the
  mDNS proxy, multicast suppression, DTIM values, the IoT channel lock and the IoT roaming assistant (inferred from the BSS transition entry), multicast conversion for isolated guests. These are the tunables to
  adjust first when your environment disagrees.

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
- Ubiquiti: [Unable to Connect to WiFi](https://help.ui.com/hc/en-us/articles/23283660456599-Unable-to-Connect-to-WiFi) (IoT and legacy-client checklist)
- Ubiquiti: [Best Practices: Guest WiFi](https://help.ui.com/hc/en-us/articles/23948850278295-Best-Practices-Guest-WiFi)
- Ubiquiti: [Ensure Your IoT Devices Work with WiFi 7 on U7 Access Points](https://help.ui.com/hc/en-us/articles/27053048844055-Ensure-Your-IoT-Devices-Work-with-WiFi-7-on-U7-Access-Points)
- Ubiquiti: [Optimizing WiFi Connectivity and Reducing Latency](https://help.ui.com/hc/en-us/articles/221029967-Optimizing-WiFi-Connectivity-and-Reducing-Latency)
