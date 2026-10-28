# Walkthrough

This walkthrough follows one run on an example site with four access points: from the first command to the
changes you make in UniFi Network. Every output block below is real output of the tool for that site; the
site's names are synthetic (`AP-1`, `SSID-1`, …); an omission inside a block is marked `[…]`.

## Example Layout

The four access points sit in a row; each can hear its direct neighbours:

```text
AP-1 ── AP-2 ── AP-3 ── AP-4
```

The **neighbour model** tells the tool which pairs to measure: where clients are expected to roam between access
points. Listing each pair once is enough; the tool evaluates both directions, and the report prints one `!` note
per pair that is listed on one side only, which needs no action.

- `AP-1`: `AP-2`
- `AP-2`: `AP-3`
- `AP-3`: `AP-4`

## 1. Set Up API and SSH Access

In the UniFi Network Application (web UI):

- enable `Device SSH Authentication`
- create a UniFi Network API key for an account with the full Administrator role (under `Integrations` or `Control Plane` → `Integrations`, depending on the version); the tool reads the controller-managed SSH credentials of the access points through it, which a View Only account cannot read

On your computer, install the tool (`uv tool install unifiwifioptimizer`; see the [README](../README.md#install)). If the controller still has its factory certificate, get its fingerprint and compare it with the certificate view in the controller:

```bash
unifiwifioptimizer controller-fingerprint --url https://unifi.example.com
```

Then create the configuration file. `init` asks for the controller URL, the API key and the fingerprint, and writes `~/.config/unifiwifioptimizer/config.yaml` with mode `0600`:

```bash
unifiwifioptimizer init
```

## 2. Discover the Site

List the available site IDs:

```bash
unifiwifioptimizer sites
```

<!-- source: sites -->
```text
  Site ID               Site Name                 Access Points
  default               Site-1                    4
  site-2                Site-2                    4
```

Inspect one site:

```bash
unifiwifioptimizer site default
```

<!-- source: site -->
```text
  Site ID:   default
  Site Name: Site-1

  WLANs:
    SSID-1 (enabled)
    SSID-2 (disabled)
    SSID-3 (disabled)
    SSID-4 (disabled)
    SSID-5 (disabled)

  Access Points:
    AP-1 (UAL6, 02:00:00:00:00:04) 2.4 GHz ch auto/20 MHz, 5 GHz ch auto/80 MHz
    AP-2 (UAPA693, 02:00:00:00:00:08) 2.4 GHz ch 1/20 MHz, 5 GHz ch 60/80 MHz
    AP-3 (UAL6, 02:00:00:00:00:0e) 2.4 GHz ch 6/20 MHz, 5 GHz ch 104/80 MHz
    AP-4 (UAPA693, 02:00:00:00:00:11) 2.4 GHz ch 11/20 MHz, 5 GHz ch 40/80 MHz
```

## 3. Generate and Complete the Site Config

Print a skeleton for the site and append it to the configuration file, below the `sites:` line:

```bash
unifiwifioptimizer config default >> ~/.config/unifiwifioptimizer/config.yaml
```

<!-- source: skeleton -->
```text
  "default":
    ssh:
      # controller: use the SSH credentials the controller manages for its access points;
      # key: your own key (set user, optionally key_file); password: user + password.
      auth: controller

    # Open, Residential, Office, Obstructed, or a custom path-loss exponent
    environment: Residential

    # Round-robin scan passes per run; readings are aggregated as the median,
    # so 3 or more passes outvote a single outlier.
    scan_passes: 3

    # Standard, Compat, IoT, or Hotspot (docs/PROFILES.md says which fits which device)
    wlans:
      "SSID-1": Standard
      "SSID-2": Standard
      "SSID-3": Standard
      "SSID-4": Standard
      "SSID-5": Standard

    # Which access points can hear each other: fill in the neighbours of every access point;
    # the tool cannot know your floor plan. Scans run between the listed pairs only.
    neighbors:
      "AP-1": []
      "AP-2": []
      "AP-3": []
      "AP-4": []
```

Complete it with the layout above and the profile each WLAN should follow; a WLAN you leave out is not checked. The final file:

<!-- source: config -->
```yaml
controller:
  url: https://unifi.example.com
  api_key: YOUR_API_KEY
  cert_fingerprint: "SHA256:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxA"

sites:
  "default":
    ssh:
      auth: controller
      scan_interface_toggle: true
    environment: Residential
    scan_passes: 3
    wlans:
      "SSID-1": Standard
      "SSID-2": Compat
      "SSID-3": Hotspot
    neighbors:
      "AP-1": ["AP-2"]
      "AP-2": ["AP-3"]
      "AP-3": ["AP-4"]
```

`environment` picks the indoor path-loss model (`Open`, `Residential`, `Office`, `Obstructed`, or your own exponent); the profile names are described in [PROFILES.md](PROFILES.md). `AP-1` and `AP-3` are U6 Lites, which keep their scan interfaces down at rest; `scan_interface_toggle: true` lets the scan bring them up for the scan and put them down again afterwards. Keep the file private: the tool refuses a configuration that others can read.

## 4. Run the Controller-Side Analysis

`run --no-scan` needs no SSH access: it checks the WLAN settings and shows the access points as the controller reports them. The examples below use `--details` to show the complete evidence; the default text output lists the WLANs and the access points as the controller UI does.

```bash
unifiwifioptimizer run --no-scan --details
```

The header of the report shows the RF target the later recommendations are measured against:

<!-- source: no-scan -->
```text
  Path-loss model:                   Residential (n = 2.8, 2.4 GHz offset 6.21 dB)
  Cell edge:                         -67 dBm (noise floor -92 dBm + SNR 25 dB)
  Target RSSI @ neighbour 2.4 GHz:   -73 dBm to -67 dBm
  Target RSSI @ neighbour 5 GHz:     -67 dBm to -61 dBm
  Minimum RSSI:                      corridor floor - 5 dB, on the uplink (client 14 dBm)
                                     Ubiquiti: for high density; -80 dBm as a home/office start
  Roaming trigger bounds:            -75 dBm .. -65 dBm (margin 5 dB)
  Scan passes:                       3 (scans skipped)
```

Every WLAN is compared with its profile. `✓` matches, `✗` deviates and says where to change it, `?` cannot be judged (data is missing, here the scan):

<!-- source: no-scan -->
```text
  WLAN       SSID-1  (profile Standard)  → network Network-1, VLAN 40
[…]
    ✓ Fast Roaming (802.11r)             Enabled
    ? Handoff Suggestions (802.11v)      threshold not available without neighbour data
        AP-1: no reading of neighbour AP-2 (scan skipped)
[…]
  WLAN       SSID-2  (profile Compat)  → network Network-1, VLAN 40
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    ✗ WLAN Enabled                       Enabled (currently Disabled)
        the WLAN is disabled on the controller
        → WLAN edit → Enabled toggle
```

The Handoff Suggestions threshold depends on how strongly the access points hear each other, so it needs the scan. These checks do not depend on the scan. Here `SSID-2` and `SSID-3` are switched off on the controller: enable them if they should broadcast, or remove them from `wlans:`. `SSID-1` still has the 5 GHz minimum data rate at 24 Mbit/s, multicast-to-unicast off and a custom DTIM, where the `Standard` profile expects 12 Mbit/s, on and the controller's DTIM default; change them or switch to a profile of your own (`docs/PROFILES.md`). The full report below was taken before these changes.

## 5. Trust the Access Points' Host Keys and Scan

The scan connects to every access point over SSH and refuses one whose host key it does not know. Store the keys once; the command asks per access point before it stores a key:

```bash
unifiwifioptimizer trust-host-keys --site default
```

Then run the full analysis. Scans run one access point at a time and take a while:

```bash
unifiwifioptimizer run
```

The default output lists the WLANs and the access points the way the controller UI does, then the RF notes and the data quality:

<!-- source: overview -->
```text
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Site       default  (Site-1), 2026-10-12T20:00+00:00
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  WLAN       SSID-1  (profile Standard)  → network Network-1, VLAN 40
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    ✓ Radio Band                         2.4 GHz, 5 GHz
    ✓ Fast Roaming (802.11r)             Enabled
    ? Handoff Suggestions (802.11v)      threshold not available without neighbour data
    ✓ Minimum Data Rate Mode             Manual
    ✓ Minimum Data Rate 2.4 GHz          12 Mbps
    ✗ Minimum Data Rate 5 GHz            12 Mbps (currently 24 Mbps)
    ✓ 802.11b Support                    Disabled
    ✓ Multicast Filtering                Disabled
    ✗ Multicast to Unicast               Enabled (currently Disabled)
    ✓ Proxy ARP                          Enabled
    ✓ Security Protocol                  WPA2/WPA3
    ✓ PMF                                Optional
    ✓ Hide WiFi Name                     Disabled
    ✓ Client Device Isolation            Disabled
    ✓ SAE Anti-clogging                  5
    ✓ SAE Sync Time                      5
    ✓ MLO                                Disabled
    ✓ Band Steering                      Enabled
    ✓ BSS Transition                     Enabled
    ✓ UAPSD                              Disabled
    ✗ Auto 802.11 DTIM Period            Default (currently Custom)
        → WLAN edit → Advanced → Behavior Controls → Auto 802.11 DTIM Period
    ✓ Group Rekey Interval               3600 s
    ✓ Show Access Point Name in Beacon   Disabled

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  WLAN       SSID-2  (profile Compat)  → network Network-1, VLAN 40
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    ✗ WLAN Enabled                       Enabled (currently Disabled)
        the WLAN is disabled on the controller

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  WLAN       SSID-3  (profile Hotspot)  → network Network-1, VLAN 40
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    ✗ WLAN Enabled                       Enabled (currently Disabled)
        the WLAN is disabled on the controller

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  AP         AP-1 (UAL6)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  2.4 GHz
    · Channel Width                      20 MHz
    · Channel                            6 (auto)
    ✓ Transmit Power                     Auto (effective 17 dBm, EIRP 20 dBm)
    · Minimum RSSI                       disabled (if enabled: -81 dBm on the uplink)

  5 GHz
    · Channel Width                      80 MHz
    · Channel                            44 (auto)
    ✗ Transmit Power                     Auto (effective 20 dBm, EIRP 23 dBm) → Custom, 23 dBm —
                                         headroom above the demonstrated power is unverified
    · Minimum RSSI                       disabled (if enabled: -78 dBm on the uplink)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  AP         AP-2 (UAPA693)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  2.4 GHz
    · Channel Width                      20 MHz
    · Channel                            1
    ✗ Transmit Power                     Custom, 6 dBm (effective 6 dBm, EIRP 10 dBm) → 10 dBm —
                                         headroom above the demonstrated power is unverified
    · Minimum RSSI                       disabled (if enabled: -70 dBm on the uplink)

  5 GHz
    · Channel Width                      80 MHz
    · Channel                            60, DFS
    - Transmit Power                     Custom, 24 dBm (effective 18 dBm, EIRP 23 dBm); no change:
                                         at the effective maximum
    · Minimum RSSI                       disabled (if enabled: -76 dBm on the uplink)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  AP         AP-3 (UAL6)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  2.4 GHz
    · Channel Width                      20 MHz
    · Channel                            6
    ✗ Transmit Power                     Custom, 11 dBm (effective 11 dBm, EIRP 14 dBm) → 17 dBm —
                                         headroom above the demonstrated power is unverified
    · Minimum RSSI                       disabled (if enabled: -75 dBm on the uplink)

  5 GHz
    · Channel Width                      80 MHz
    · Channel                            104, DFS
    - Transmit Power                     Custom, 23 dBm (effective 23 dBm, EIRP 26 dBm); no change:
                                         at the effective maximum, neighbour unsighted
    · Minimum RSSI                       disabled (if enabled: -81 dBm on the uplink)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  AP         AP-4 (UAPA693)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  2.4 GHz
    · Channel Width                      20 MHz
    · Channel                            11
    ✗ Transmit Power                     Custom, 10 dBm (effective 10 dBm, EIRP 14 dBm) → 17 dBm —
                                         headroom above the demonstrated power is unverified
    · Minimum RSSI                       disabled (if enabled: -74 dBm on the uplink)

  5 GHz
    · Channel Width                      80 MHz
    · Channel                            40
    - Transmit Power                     Custom, 24 dBm (effective 18 dBm, EIRP 23 dBm); no change:
                                         at the effective maximum, neighbour unsighted
    · Minimum RSSI                       disabled (if enabled: -76 dBm on the uplink)

  Notes:
    * 5 GHz coverage/roaming gaps: AP-1 / AP-2, AP-2 / AP-3, AP-3 / AP-4; verify with clients.
    * AP-4 2.4 GHz: the scan saw nothing on this band; restart the radio or the access point before
      trusting any conclusion

  Data quality:
    Scan: 4 APs, 12/12 passes successful.
    Partial result (band empty); the exit code says so.
    WLAN checks that could not be evaluated: Handoff Suggestions (802.11v).
    3 neighbour links are configured in one direction; both are evaluated.
    AP beacon readings do not establish client roaming or channel airtime.

  4 pending setting change(s) (4 transmit power) and 5 failed WLAN check(s). After applying changes,
    run the tool again.
  Full evidence: run with --details.
```

Add `--details` for the complete per-band evidence that the next section reads:

```bash
unifiwifioptimizer run --details
```

An off-channel scan interrupts service on the scanning access point for its duration; run it off hours. A U6 Lite needs `scan_interface_toggle: true`, as in the file above; without it a band whose interface is down is reported as `interface_down` and left alone.

## 6. Read the Report

The report is built per access point and band. The first access point shows the typical elements:

<!-- source: golden -->
```text
  AP         AP-1 (UAL6)
  MAC        02:00:00:00:00:04
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  2.4 GHz  (channel 6 (auto), width 20 MHz, TX 17 dBm (auto, configured 6 dBm is stale); max 23 dBm
           (unverified))

  Neighbour AP:             RSSI @ neighbour:
  AP-2                      -70 dBm n=3 offset -12 dB
[…]
  5 GHz  (channel 44 (auto), width 80 MHz, TX 20 dBm (auto, configured 19 dBm is stale); max 23 dBm
         (unverified))

  Neighbour AP:             RSSI @ neighbour:
  AP-2                      -72 dBm n=3 offset -3 dB *

  · the radio has not demonstrated power above 20 dBm on this channel

  Recommendations:
    ✗ Transmit Power           set to Custom, 23 dBm (raise by 3 dB from 20 dBm) — headroom above
                               the demonstrated power is unverified
        → AP settings → Radios → Transmit Power (2.4/5 GHz) -- set to Custom, then the dBm field
    · Minimum RSSI             disabled (if enabled: -78 dBm on the uplink)
```

- **TX and `max`**: the radio's effective transmit power is what counts. In automatic mode the configured value is stale, so the tool judges the effective one and phrases a change as "set to Custom, N dBm". `max … (unverified)` marks a ceiling the radio has not demonstrated yet.
- **Neighbour table**: `RSSI @ neighbour` is how strongly the neighbour hears this access point's beacons, the median of `n` readings taken on this access point's channel. `offset` is the two receivers' disagreement after the power difference; from 5 dB on the report adds a line saying that one reads systematically high or low. `*` marks a pair that stays outside the corridor even after the recommended change, `°` one that is outside now and inside after it, and `~` a reading predicted from the opposite direction because the neighbour did not hear this access point.
- **Recommendations**: `✗` is a change to make, with the UniFi path under it; `✓` confirms the current value; `-` is a decision without a change; `·` is information. Findings under a band are marked `*` (warning), `!` (worth checking) and `·` (information). A disabled Minimum RSSI is shown with the value to use if you enable it.
- **`regulatory cap`**: the radio runs below its configured power, so the lower power is its verified maximum.

Two situations deserve a closer look. A pair that is below the cell edge even at the radio's effective maximum cannot be fixed with power:

<!-- source: golden -->
```text
  5 GHz  (channel 60, DFS (CAC 60 s), width 80 MHz, TX 18 dBm (configured 24 dBm, regulatory cap);
         max 18 dBm)
[…]
  * hand-off between AP-2 and AP-1, AP-3 happens below the cell edge (4 dB short at the effective
    maximum 18 dBm): add an access point or accept [AP-1, AP-3]
```

A neighbour that is not heard at all, in either direction, at the maximum power is a placement question:

<!-- source: golden -->
```text
  * at the effective maximum 23 dBm and still unsighted by AP-4: structural, reposition or add an
    access point [AP-4]

  Recommendations:
    - Transmit Power           23 dBm, no change: at the effective maximum, neighbour unsighted
```

A band whose scan comes back empty is reported as such, and its recommendations wait for a re-run after a restart:

<!-- source: golden -->
```text
  * the scan saw nothing on this band; restart the radio or the access point before trusting any
    conclusion
```

The end of the report summarises the site:

<!-- source: golden -->
```text
  Adjacency groups
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  AP-1, AP-2, AP-3, AP-4
  ! 5 GHz: AP-3 and AP-4: no reading in either direction (AP-4: not sighted; AP-3: not sighted)

  4 pending setting change(s) (4 transmit power) and 5 failed WLAN check(s). After applying changes,
    run the tool again.
  Partial result (band empty); the exit code says so.
```

A partial result ends with exit code 6; the [README](../README.md#exit-codes) lists every code.

## 7. Apply and Re-Run

1. Fix the WLAN deviations first: they are quick and independent of the RF settings. A WLAN you do not want checked belongs out of `wlans:`, not in the controller's settings.
2. Change the transmit power as recommended, except on a band the report marks as empty: restart that radio or access point and re-run first. The Roaming Assistant threshold and the Minimum RSSI follow the effective power, so apply the power changes first and re-run before you touch them.
3. Re-run `unifiwifioptimizer run` and repeat until the recommendations stop changing.
4. Re-test with real clients. The report works from controller configuration and access-point-to-access-point readings; it cannot see non-WiFi interference or what a client experiences.
