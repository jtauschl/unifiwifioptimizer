# Profiles

`profiles.yaml` defines the shipped WLAN baselines used by `UniFi WiFi Optimizer`.

Profiles ship ready to use and can be adjusted if your environment or policy requires different WLAN settings.

## Included Profiles

| Profile | Intent |
|---|---|
| `Standard` | General-purpose baseline mirroring the UniFi WLAN preset `Application: Standard` with `Advanced: Auto` on 2.4/5 GHz. Intended as a broadly compatible default for normal client WLANs. |
| `IoT` | Compatibility-oriented baseline mirroring the UniFi WLAN preset `Application: IoT` with `Advanced: Auto` on 2.4 GHz. Intended for IoT and lower-capability clients that benefit from 2.4 GHz coverage, simpler security and roaming behavior, and more compatibility-oriented settings. |
| `Hotspot` | Public WiFi baseline for restaurants, cafes, hotels, retail, and similar guest-facing environments. Intended for guest/public deployments, including Captive Portal or Passpoint setups, where compatibility and isolation matter more than aggressive performance tuning. |
| `Throughput` | Optimized primary WLAN profile for higher throughput and better airtime efficiency. Intended for client WLANs where raw throughput matters more than latency. |
| `Latency` | Optimized primary WLAN profile for lower latency and faster client responsiveness. Intended for voice, VoIP, gaming, and similar realtime traffic where responsiveness matters more than maximum throughput. |

## Example

```yaml
profiles:
  Throughput:
    wifi_bands:
      - 2g
      - 5g
    fast_roaming: true
    minrate_mode: manual
    minrate_24_kbps: 11000
    minrate_5_kbps: 24000
    multicast_broadcast_blocker: false
    multicast_to_unicast: false
    proxy_arp: true
    security_protocols:
      - WPA2/WPA3
      - WPA2/WPA3 Enterprise
    pmf: Optional
    hide_wifi_name: false
    client_device_isolation: false
    sae_anti_clogging: 10
    sae_sync_time: 5
    mlo: false
    bss_transition: true
    uapsd: false
    dtim_mode: custom
    dtim_24: 3
    dtim_5: 3
    group_rekey: 3600
    ap_name_in_beacon: false
```

## Field Guide

- `wifi_bands`: expected band availability
- `fast_roaming`, `mlo`, `bss_transition`, `uapsd`: roaming and client behavior controls
- `minrate_mode`, `minrate_*`: minimum data rate mode and per-band values
- `dtim_mode`, `dtim_*`: DTIM mode and per-band DTIM values
- `group_rekey`: group rekey interval, always checked
- `multicast_*`, `proxy_arp`, `client_device_isolation`: broadcast and multicast handling plus client isolation
- `security_protocols`, `pmf`, `sae_*`: security posture and WPA3/SAE-related expectations
- `hide_wifi_name`, `ap_name_in_beacon`: SSID visibility and beacon presentation

## Notes

- `minrate_*` is only required when `minrate_mode: manual`
- `dtim_*` is only required when `dtim_mode: custom`
- `minrate_*` and `dtim_*` only apply to bands listed in `wifi_bands`
- `group_rekey: 0` renders as `Disabled`
- `mlo: false` is the shipped default for all current profiles
- Configure `Band Steering` manually in UniFi Network to match your deployment policy.

## References

- Ubiquiti: [UniFi WiFi SSID and AP Settings Overview](https://help.ui.com/hc/en-us/articles/32065480092951-UniFi-WiFi-SSID-level-Settings-Overview)
- Ubiquiti: [UniFi Wireless Guest Network Setup](https://help.ui.com/hc/en-us/articles/115000166827-UniFi-Wireless-Guest-Network-Setup)
- Ubiquiti: [Setting Up Passpoint on UniFi Network](https://help.ui.com/hc/en-us/articles/25473982758551-Setting-Up-Passpoint-on-UniFi-Network)
