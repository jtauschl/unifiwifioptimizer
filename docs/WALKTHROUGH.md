# Walkthrough

This walkthrough uses a five-AP example for `UniFi WiFi Optimizer`.
It starts with a minimal controller-only config, then shows how to discover the site, generate a site config block, and complete the `neighbors` model.

<p align="center">
  <img src="img/Example.png" alt="Example layout with five access points" width="600">
</p>

## Example Layout

- upper row: `AP1`, `AP2`, `AP3`
- lower row: `AP4`, `AP5`

`AP2` sits at the center and overlaps with all four surrounding APs.
The outer APs overlap only with their direct neighbors.

## Neighbor Model

The neighbor list describes where clients are expected to roam between APs:

- `AP1`: `AP2`, `AP4`
- `AP2`: `AP1`, `AP3`, `AP4`, `AP5`
- `AP3`: `AP2`, `AP5`
- `AP4`: `AP1`, `AP2`, `AP5`
- `AP5`: `AP2`, `AP3`, `AP4`

## 1. Set Up API and SSH Access

In the UniFi Network Application (web UI):

- enable `Device SSH Authentication`
- set a device SSH password there, or keep passwordless SSH
- if you want passwordless SSH, add your public key under `Settings` -> `System` -> `Advanced` -> `Device Authentication` -> `SSH Keys`
- create a UniFi Network API key under `Integrations` or `Control Plane` -> `Integrations`, depending on the version

Create `config.yaml` from the minimal starter:

```bash
cp config.minimal.yaml config.yaml
```

Then enter your controller URL and API key in `config.yaml`.

## 2. Discover the Site and Generate a Config Block

List the available site IDs:

```bash
./unifiwifioptimizer --sites
```

Example output:

```text
  Site ID               Site Name                 Access Points
  default               Default                   5
```

Inspect one site:

```bash
./unifiwifioptimizer --site default
```

Example output:

```text
  Site ID:   default
  Site Name: Default

  WLANs:
    General (enabled)
    IoT (enabled)
    Guest (enabled)

  Access Points:
    Device Name   State   IP             MAC
    AP1           ONLINE  172.20.1.101   f4:92:bf:aa:11:22
    AP2           ONLINE  172.20.1.102   f4:92:bf:aa:33:44
    AP3           ONLINE  172.20.1.103   f4:92:bf:aa:55:66
    AP4           ONLINE  172.20.1.104   f4:92:bf:aa:77:88
    AP5           ONLINE  172.20.1.105   f4:92:bf:aa:99:aa
```

Generate a site-specific config skeleton:

```bash
./unifiwifioptimizer --config default >> config.yaml
```

This appends a site block to `config.yaml`. At this point, no backup is needed because `config.yaml` still only contains the controller settings from `config.minimal.yaml`.

The appended block looks like this:

```yaml
sites:
  default:
    ssh:
      user: ubnt
      # Set a password or remove this line for SSH key-based login.
      password: YOUR_SSH_PASSWORD

    # Open, Residential, Office, Obstructed, or a custom path-loss exponent
    environment: Residential

    # Standard, IoT, Hotspot, Throughput, or Latency
    wlans:
      General: Throughput
      IoT: IoT
      Guest: Hotspot

    # Add neighbor AP names as a comma-separated list in brackets.
    neighbors:
      AP1: []
      AP2: []
      AP3: []
      AP4: []
      AP5: []
```

## 3. Complete the Site Config

Use the floorplan or layout sketch to define AP neighbors and verify the WLAN profile mapping.

Final `config.yaml`:

```yaml
controller:
  url: https://unifi.example.local
  api_key: YOUR_API_KEY

sites:
  default:
    ssh:
      user: ubnt
      password: YOUR_SSH_PASSWORD

    environment: Residential

    wlans:
      General: Throughput
      IoT: IoT
      Guest: Hotspot

    neighbors:
      AP1: [AP2, AP4]
      AP2: [AP1, AP3, AP4, AP5]
      AP3: [AP2, AP5]
      AP4: [AP1, AP2, AP5]
      AP5: [AP2, AP3, AP4]
```

## 4. Example Output (abbreviated)

Run the script with the completed configuration:

```bash
./unifiwifioptimizer
```

The script first shows the site-level RF parameters, then checks each WLAN against its profile, and finally produces per-AP recommendations.

### Environment Summary

```text
Environment:               Residential
Target RSSI @ Neighbor:    -73 dBm to -67 dBm
Roaming Assistant:         -67 dBm
Minimum RSSI:              -73 dBm
```

These values are derived from `environment: Residential` and are the same for all APs on the site.

### Per-WLAN Profile Check

Each WLAN is checked against its assigned profile:

```text
WLAN       General
Profile    Throughput

  Radio Setup:
  ✓ WiFi Band                        2.4 GHz, 5 GHz
  Roaming Assistance:
  ✓ Fast Roaming                     Enabled
  Hi-Capacity Tuning:
  ✓ Minimum Data Rate Mode           Manual
  ✓ Minimum Data Rate 2.4 GHz        11 Mbps
  ✓ Minimum Data Rate 5 GHz          24 Mbps
  ✓ Multicast and Broadcast Blocker  Disabled
  ✓ Multicast to Unicast             Disabled
  ✓ Proxy ARP                        Enabled
  Security:
  ✓ Security Protocol                WPA2/WPA3
  ✓ PMF                              Optional
  ✓ Hide WiFi Name                   Disabled
  ✓ Client Device Isolation          Disabled
  ✓ SAE Anti-clogging                10
  ✓ SAE Sync Time                    5
  Behaviour Controls:
  ✓ MLO                              Disabled
  ✓ BSS Transition                   Enabled
  ✓ UAPSD                            Disabled
  ✓ DTIM Mode                        Custom
  ✓ DTIM Period 2.4 GHz              3
  ✓ DTIM Period 5 GHz                3
  ✓ Group Rekey Interval             3600 s
  ✓ Show Access Point Name in Beacon Disabled
```

Mismatches between the WLAN and its profile are flagged with `✗`.

### Per-AP Recommendations

An outer AP with two neighbors, both within the corridor:

```text
AP        AP1
MAC       f4:92:bf:aa:11:22

2.4 GHz  (Channel Width: 20 MHz, Channel: 1, TX Power: 9 dBm)

Neighbor AP:    RSSI @ Neighbor:
AP2             -71 dBm
AP4             -73 dBm

Recommendations:
  ✓ Transmit Power           Custom, 9 dBm
  ✓ Minimum RSSI             Disabled
```

The center AP with four neighbors and a TX power adjustment:

```text
AP        AP2
MAC       f4:92:bf:aa:33:44

5 GHz  (Channel Width: 80 MHz, Channel: 44, TX Power: 23 dBm)

Neighbor AP:    RSSI @ Neighbor:
AP1             -66 dBm
AP3             -65 dBm
AP4             -68 dBm
AP5             -67 dBm

Recommendations:
  ✗ Transmit Power           Custom, 19 dBm (reduce by 4 dBm)
  ✓ Roaming Assistant        Enabled, -67 dBm
  ✓ Minimum RSSI             Disabled
```

Here the integer-averaged neighbor RSSI (−66 dBm) is above the corridor center (−70 dBm), so the script recommends reducing TX power by 4 dBm (shift −4, applied directly in 1 dBm steps).

An outer AP hitting the hardware maximum:

```text
AP        AP3
MAC       f4:92:bf:aa:55:66

5 GHz  (Channel Width: 80 MHz, Channel: 149, TX Power: 23 dBm)

Neighbor AP:    RSSI @ Neighbor:
AP2             -72 dBm
AP5             -78 dBm *

* Coverage gap – signal too weak at: AP5
  Consider repositioning this AP or adding a neighbor AP.

Recommendations:
  ✓ Transmit Power           Custom, 23 dBm
  ✓ Roaming Assistant        Enabled, -67 dBm
  ✓ Minimum RSSI             Disabled
```

The coverage warning appears because TX power is at the hardware maximum. `AP5` is projected below `TX_LO` (−73 dBm) even at full power.

## Notes

- AP names in `neighbors` must match the UniFi device names exactly (case-sensitive).
- AP names must be unique within the UniFi site.
- Keep neighbors symmetric when the physical overlap is symmetric.
- For multi-floor environments, include only APs that are meaningful RF neighbors across floors.
