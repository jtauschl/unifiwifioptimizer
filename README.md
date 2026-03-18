# UniFi WiFi Optimizer

> RF tuning and WLAN baseline review for UniFi access points — transmit power, roaming, and minimum RSSI recommendations derived from AP-to-AP neighbor scans.

<p align="center">
  <img src="docs/img/UniFiWiFiOptimizer.png" alt="UniFi WiFi Optimizer – RF tuning tool for UniFi access points" width="600">
</p>

`UniFiWiFiOptimizer` is a Bash tool for post-placement UniFi WLAN review and RF tuning.
It reads radio configuration and WLAN settings from the UniFi Network API, compares them against shipped WLAN profiles, collects AP-to-AP neighbor scan data via SSH, and generates recommendations for:

- profile-based WLAN best practices for Standard, IoT, Hotspot, Throughput, and Latency profiles
- access point settings: `Transmit Power`, `Roaming Assistant`, `Minimum RSSI`

It does not write changes back to the controller — all recommendations must be applied manually. The SSH neighbor scan uses dedicated scan interfaces, so normal client WiFi service should remain unaffected on supported UniFi APs and firmware.

→ See [docs/EXAMPLE.md](docs/EXAMPLE.md) for a complete five-AP example with sample output.

## Requirements

- UniFi Network Application 8.0+ with API key support
- UniFi access points managed by that application, with `Device SSH Authentication` enabled
- local tools: `bash`, `awk`, `curl`, `python3`, `ruby`, `ssh`
- `sshpass` — optional, only needed for password-based SSH login

## Quick Start

1. In UniFi Network, enable `Device SSH Authentication` and either set a password or add an SSH key.
2. Create a UniFi Network API key.
3. Copy `config.minimal.yaml` to `config.yaml` and fill only the controller connection:

```bash
cp config.minimal.yaml config.yaml
```

4. Discover the site and generate a site skeleton:

```bash
./UniFiWiFiOptimizer --sites
./UniFiWiFiOptimizer --site <siteid>
./UniFiWiFiOptimizer --config <siteid> >> config.yaml
```

5. Complete `environment`, `wlans`, and `neighbors`, then run `./UniFiWiFiOptimizer`.

## Configuration

Site configuration lives in `config.yaml`. Reusable WLAN baselines live in `profiles.yaml`.

Starter files:

- `config.minimal.yaml`: controller-only starter config
- `config.example.yaml`: complete example config

`config.yaml`:

```yaml
controller:
  url: https://unifi.example.local
  api_key: ...

sites:
  default:
    ssh:
      user: ubnt
      password: ...

    environment: Residential

    wlans:
      Main: Throughput
      IoT: IoT
      Guest: Hotspot

    neighbors:
      AP1: [AP2, AP4]
      AP2: [AP1, AP3, AP4, AP5]
      AP3: [AP2, AP5]
      AP4: [AP1, AP2, AP5]
      AP5: [AP2, AP3, AP4]
```

Recommended flow:

1. Copy `config.minimal.yaml` to `config.yaml` and fill `controller.url` and `controller.api_key`.
2. Run `./UniFiWiFiOptimizer --sites` to list valid UniFi site IDs.
3. Run `./UniFiWiFiOptimizer --site <siteid>` to inspect WLANs and access points for that site.
4. Run `./UniFiWiFiOptimizer --config <siteid> >> config.yaml` to append a site-specific config skeleton.
5. Adjust `environment`, WLAN profile mappings, and AP neighbors.

Key settings:

| Key | Description |
|---|---|
| `controller.url` | Base URL of the UniFi Network application |
| `controller.api_key` | API key for all read-only controller requests |
| `sites.<site>.ssh.user` | SSH username from `Device SSH Authentication` for that site |
| `sites.<site>.ssh.password` | SSH password for password-based login for that site; omit to use key/agent auth |
| `sites.<site>.environment` | RF environment preset or custom path loss exponent used to derive the TX corridor |
| `sites.<site>.wlans` | Maps UniFi WLAN names to profile names |
| `sites.<site>.neighbors` | AP-to-AP neighbor model; names must match UniFi device names exactly (case-sensitive) |

Notes:

- Use the UniFi site ID as the key under `sites:` in `config.yaml`.
- `--sites` lists the available site IDs from the UniFi controller.
- `--site <siteid>` shows WLANs and access points for exactly that site ID.
- `--config <siteid>` prints a config skeleton for exactly that site ID.
- `--config <siteid> >> config.yaml` is safe when `config.yaml` still contains only the controller section from `config.minimal.yaml`.
- The generated skeleton auto-fills `ssh.user` from UniFi `Device SSH Authentication` when available.

Environment presets:

- `Open`: large open spaces, retail, low attenuation
- `Residential`: homes and apartments
- `Office`: typical office floorplans
- `Obstructed`: concrete, brick, multi-wall layouts
- custom value: typical practical values are around `2.0` to `4.0`

`config.yaml` contains the API key and optionally the SSH password — protect it accordingly:

```bash
chmod 600 config.yaml
```

For SSH, prefer key-based authentication (see [SSH Access](#ssh-access)).

`profiles.yaml`:

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
    bss_transition: true
    uapsd: false
    dtim_mode: custom
    dtim_24: 3
    dtim_5: 3
    group_rekey: 3600
    ap_name_in_beacon: false
```

Profiles ship ready-to-use and can be adjusted if your environment or policy requires different WLAN settings. The shipped presets are `Standard`, `IoT`, `Hotspot`, `Throughput`, and `Latency`. Boolean and enum fields are compared directly against the controller; `minrate_mode` and `dtim_mode` decide whether the per-band numeric values are checked.

Common field groups in `profiles.yaml`:

- `wifi_bands`: expected band availability
- `fast_roaming`, `bss_transition`, `uapsd`: roaming and client behavior controls
- `minrate_mode`, `minrate_*`: minimum data rate mode and per-band values
- `dtim_mode`, `dtim_*`, `group_rekey`: DTIM mode, per-band DTIM values, and group rekey
- `multicast_*`, `proxy_arp`, `client_device_isolation`: broadcast/multicast handling and client isolation
- `security_protocols`, `pmf`, `sae_*`: security posture and WPA3/SAE-related expectations
- `hide_wifi_name`, `ap_name_in_beacon`: SSID visibility and beacon presentation

- `minrate_*` is only required when `minrate_mode: manual`
- `dtim_*` is only required when `dtim_mode: custom`
- `minrate_*` and `dtim_*` only apply to bands listed in `wifi_bands`
- `group_rekey: 0` renders as `Disabled`

## Profiles

| Profile | Intent |
|---|---|
| `Standard` | Mirrors the current UniFi `Standard/Auto` baseline on 2.4/5 GHz |
| `IoT` | Mirrors the current UniFi `IoT/Auto` baseline on 2.4 GHz |
| `Hotspot` | Public hotspot baseline with client isolation, proxy ARP, and broadcast blocker enabled |
| `Throughput` | Throughput-oriented primary WLAN profile with manual rates and less frequent DTIM beacons |
| `Latency` | Latency-oriented primary WLAN profile for voice/VoIP with UAPSD enabled and frequent DTIM beacons |

## SSH Access

SSH key authentication is recommended:

```bash
ssh-copy-id ubnt@your-ap.local
```

Password-based login also works — set `sites.<site>.ssh.password` in `config.yaml`. In that case, `sshpass` must be installed. If the key is omitted, key/agent auth is used automatically.

## Recommended Workflow

1. Set up API access and device SSH access in UniFi Network.
2. Copy `config.minimal.yaml` to `config.yaml` and enter the controller details.
3. Discover the site with `--sites` and inspect it with `--site <siteid>`.
4. Generate and append a site skeleton with `--config <siteid> >> config.yaml`.
5. Complete WLAN mappings and AP neighbors.
6. Let UniFi handle channel planning first if you want a baseline (for example Channel AI).
7. Run `./UniFiWiFiOptimizer`.
8. Fix per-WLAN profile deviations first.
9. Apply per-AP RF recommendations that make sense for your site.
10. Re-test with real clients.

## Output

Each site report is structured in three parts:

- **Environment**: site-level RF target corridor derived from `environment`
- **WLAN**: per-SSID/profile best-practice comparison from `profiles.yaml`
- **Access Points**: per-AP neighbor RSSI data and RF recommendations

## Algorithm

TX Power targets the center of a corridor derived from the RF environment and AP-to-AP neighbor RSSI:

```
TX_LO = ROAM_TARGET − 10 · n · log₁₀(100 / 60)
TX_HI = TX_LO + CORRIDOR_WIDTH
```

The path loss exponent `n` is set per site via `environment:`. Values are based on ITU-R P.1238-13.

| Recommendation | Value |
|---|---|
| TX Power target | corridor center (`TX_LO + 3 dBm`) |
| Roaming Assistant | `ROAM_TARGET` = −67 dBm (Cisco VoWLAN guideline) |
| Minimum RSSI | `TX_LO` when you choose to enforce a hard disconnect threshold |

For the full derivation, see [docs/ALGORITHM.md](docs/ALGORITHM.md).

## Scope and Limits

Designed for homelabs, homes, apartments, and small to medium offices with manually managed UniFi deployments and known AP neighbor relationships.

Does not replace AP placement, channel planning, site surveys, capacity planning, or client-side validation.

- AP recommendations cover 2.4 GHz and 5 GHz; 6 GHz is profile-only
- Depends on model-/firmware-specific AP scan interface naming and MAC offset conventions
- `Band Steering` is not evaluated (not available via API) — review manually in UniFi Network

## References

- Ubiquiti: [UniFi WiFi SSID and AP Settings Overview](https://help.ui.com/hc/en-us/articles/32065480092951-UniFi-WiFi-SSID-level-Settings-Overview)
- Ubiquiti: [Understanding and Implementing Minimum RSSI](https://help.ui.com/hc/en-us/articles/221321728-Understanding-and-Implementing-Minimum-RSSI)
- Cisco: [Site Survey Guidelines for WLAN Deployment](https://www.cisco.com/c/en/us/support/docs/wireless/5500-series-wireless-controllers/116057-site-survey-guidelines-wlan-00.html)
- ITU-R P.1238-13: Indoor propagation path loss exponents by environment
