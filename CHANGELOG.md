# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0] - Unreleased

Give UniFi operators verified, actionable RF and WLAN-profile recommendations on current controller releases — including the WLAN-level Handoff Suggestions check, the extended profile schema, and secure-by-default controller and AP access — by rebuilding the optimizer as a typed, tested Python package.

### Added
- `unifiwifioptimizer run [--site ID]... [--json] [--no-scan] [--clients]`: the analysis itself — controller snapshot plus AP-to-AP neighbour scans per site, the transmit-power, Minimum-RSSI and Roaming-Assistant recommendations, the WLAN profile checks, channel checks and a plain-text report; `--json` prints one document (`schema_version` 1) for every site; `--no-scan` analyses the controller side only (the natural first run, before `trust-host-keys`); `--clients` adds the associated clients per radio as signal counts (never identities). Exit codes: 0 ok, 1 unexpected, 2 usage, 3 configuration, 4 TLS, 5 host keys kept every access point of a site unverified, 6 partial result (a finding in the report says why), 7 environment, 130 interrupted.
- Neighbour matrix with the reason for every missing reading (offline, DFS wait, scan failed/empty/interface down, no DFS evidence, not sighted), reciprocity for one-way misses (the reverse reading plus the power difference), and the receivers' disagreement per pair as information from 5 dB.
- Transmit power as a decision table: in corridor, out of corridor, raise to the maximum, coverage gap at the effective maximum (a design finding, not a value), too strong even at the minimum, reduction blocked while a neighbour is unevaluated, no sighting in both directions; a radio in automatic power mode is judged by its effective power and phrased as "set to Custom, N dBm".
- Channel checks over the configured and the heard graph (own access points heard at or above the IEEE 802.11 CCA level of −82 dBm): overlap with free candidates, co-channel contention, reuse feasibility by graph colouring with the controller's candidate channels, Channel AI awareness (an auto radio under Channel AI is reported, not recommended), blacklist, 40 MHz on 2.4 GHz, foreign-network counts.
- Per-radio Minimum RSSI on the uplink (corridor floor minus the margin, converted with `rf.client_tx_dbm`); disabled is reported as the value to use, never as a pending change; an advisory when an enabled Minimum RSSI would disconnect before the roaming trigger.
- Airtime figures per radio, the "fix TX power first" note on a Roaming Assistant check whenever a 5 GHz transmit-power change is pending, offline access points as one line, radios in DFS wait with the channel-aware re-run hint, an `empty` scan band as a restart suggestion.
- Two controller devices sharing an access point name: a name listed under `neighbors` is a configuration error for every selected site (exit 3, before any scan); any other shared name is an error finding naming both MACs, neither device is analysed, and the run is partial (exit 6).
- WLAN profiles carry an evidence tier per key (`standard`, `vendor`, `practice`) with its source in the `evidence` section; `unifiwifioptimizer config --profiles` prints the effective profiles with those annotations.
- Your own `profiles.yaml` next to `config.yaml` (or `--profiles-file PATH`) extends the shipped profiles or replaces a shipped profile whole; unknown keys and values are errors.
- Optional profile keys checked only when set: `iot_dtim_lock`, `iot_channel_lock`, `enhanced_iot`, `b_supported`, `dns_assistance_mode`, `mdns_proxy_mode`, `ppsk`, `wpa3_enhanced_192`.
- Advisories for IoT locks on a WLAN meant for 5 GHz clients, an mDNS proxy on an isolated WLAN, Private Pre-Shared Keys without a PSK handshake, WPA3 Enhanced 192-bit on anything but WPA3 Enterprise, and a PMF setting that does not fit the protocol in use (WPA3-only/OWE need Required, a WPA3 transition mode exactly Optional, OWE transition Optional or Required, Open none).
- A WLAN setting the controller did not send is reported as `incomplete` instead of being compared against an assumed default; a combination it did send but the tool cannot name (e.g. `wpapsk/wpa1`) is a deviation showing the raw pair.
- A profile may carry its own `evidence` block for keys whose tier differs from the set-wide one (the IoT profile's compatibility choices are `practice`).
- Terminology note in `docs/ALGORITHM.md` clarifying that UniFi's "Handoff Suggestions (802.11v)" UI label refers to the same setting this tool calls Roaming Assistant.
- TX power for an AP/band with a configured neighbor but no sighting yet now jumps straight to the radio's maximum, to maximize the chance of a sighting on the next run; once already at maximum with no sighting, this is reported as a distinct informational state.
- "Fix TX power first" note next to an `Incomplete`/`Not evaluable` Roaming Assistant verdict when the site still has pending TX power recommendations.
- New `roaming_assistant` profile field controlling whether Roaming Assistant should be enabled for a WLAN. Shipped: enabled for `Standard`/`Throughput`/`Latency`, disabled for `IoT`/`Hotspot`.
- New `band_steering` profile field controlling whether dual-band clients are steered away from 2.4 GHz. Shipped defaults: enabled for `Standard`/`Throughput`/`Latency`, disabled for `IoT`/`Hotspot`.
- Advisory when a WLAN's 2.4 GHz minimum data rate is below 12 Mbps, since lower rates keep legacy 802.11b protection overhead active.
- Advisory when 802.11r Fast Transition is enabled on an `IoT`-profile WLAN, since it is known to break specific IoT client classes.
- Advisory when a WLAN has MLO enabled without a WPA3-only protocol (Personal or Enterprise, no WPA2 transition — a transition mode runs PMF optional and cannot satisfy MLO) and PMF Required.
- Advisory when 802.11r Fast Transition is enabled but 802.11v (BSS Transition) is disabled, since 802.11r's fast handoff depends on it.
- Security Protocol recognition for `Enhanced Open (OWE)` and `Enhanced Open with Transition` — previously any open-security WLAN was reported as plain `Open` regardless of its actual OWE encryption state.
- A line under every ✗ compliance check and TX/roaming/channel recommendation naming exactly where in the UniFi UI to make the change.
- Scope statement at the end of every run clarifying that this tool works from controller configuration and AP-to-AP neighbor scans, and cannot see non-WiFi RF interference, per-client statistics, real roaming timing, or packet captures.
- `docs/ALGORITHM.md` and the scope statement now note that neighbor RSSI is an AP-to-AP beacon reading, not a client link-budget proxy, and cannot detect a weak client's uplink being marginal even when the corridor looks compliant.

### Fixed
- WLANs using WPA3 Enterprise / WPA2/WPA3 Enterprise no longer have SAE Anti-clogging/Sync Time incorrectly checked against the profile baseline, since Enterprise doesn't use the SAE handshake.
- `Throughput`/`Latency` profiles: `sae_anti_clogging` corrected from 10 to 5, matching the controller default already used by the other profiles.
- A non-compliant 6 GHz DTIM period is now flagged with a UI-path hint, matching its 2.4/5 GHz counterparts.
- A WLAN matched to the `Standard` profile broadcasting only on 2.4 GHz with Fast Roaming enabled now gets the same IoT-client-breakage advisory as an `IoT`-profile WLAN.
- `Standard` and `Hotspot` profile baselines corrected to match UniFi's actual default presets, verified against a real controller.
- Site-level pending TX-power count no longer inflates on APs whose 5 GHz radio is inactive.
- Roaming Assistant recommendations silently stopped working on current UniFi firmware.
- Fixed a rare crash or incorrect Roaming Assistant compliance result for a WLAN whose aggregated signal value was empty.
- Roaming Assistant compliance no longer reports a false deviation for a WLAN with Roaming Assistant enabled but no RSSI threshold set yet.
- A Ctrl-C during the installer's SSH password prompt no longer leaves the terminal not echoing typed input afterward.
- A UniFi AP group ID or MAC address containing special shell characters no longer causes incorrect behavior during analysis.
- `Throughput` and `Latency` profiles: minimum 2.4 GHz data rate raised from 11 Mbps to 12 Mbps, dropping legacy 802.11b compatibility in favor of Cisco/Aruba/Ubiquiti's "kill 802.11b" guidance.
- Roaming Assistant and Minimum RSSI defaults recalibrated to match Apple's published roaming triggers, reducing premature disconnects on iOS/macOS clients.
- Minimum RSSI recommendation is now set with a safety margin below the roaming trigger instead of equal to it, preventing disconnect loops on 802.11v-capable clients.
- The installer now creates `config.yaml` (and its backups) with restrictive file permissions, since it holds an API key and optionally an SSH password.
- `SECURITY.md` corrected: SSH host-key verification and TLS certificate trust are disabled by design for this tool, not enforced as previously documented.
- Coverage-gap warnings are now shown for every neighbor still below the target signal corridor, instead of only when TX power itself hit its hardware limit — a real coverage problem could previously be understated.

### Changed
- **Breaking:** recommendations rest on the effective transmit power (`radio_table_stats.tx_power`), not the configured one; the weakest configured neighbour decides, not the mean; the missing-peer +1 dB nudge is gone; a zero sighting raises to the maximum only after a miss in both directions with working scans; readings are the median over passes on the peer's channel.
- **Breaking:** the width budgets (60/320 MHz) and the "more than three 2.4 GHz peers" rule are replaced by the colouring check; the per-radio Roaming Assistant fallback for controllers without the WLAN-level field is gone (the check reports the older API instead); an enabled Minimum RSSI is no longer flagged by itself.
- **Breaking:** the report is plain text without colour codes; `--json` is the machine format. A controller endpoint that fails (for example `apgroups`) aborts the run with exit 1 instead of being skipped.
- Scans run site after site, access points serial within a site; a configured access point the controller reports as disconnected is not contacted.
- **Breaking:** the shipped profiles are recommendations, not controller-default snapshots. `Standard` now expects WPA2/WPA3 (transition) with PMF Optional, 802.11r, 802.11v, Roaming Assistant on and a 3600 s group rekey; `Hotspot` expects Enhanced Open (OWE, transition preferred) with plain Open still accepted, the mDNS proxy off and a 3600 s group rekey; `IoT` accepts WPA2 or WPA2/WPA3 with PMF off or optional (no longer WPA2-only with PMF off); `Throughput` and `Latency` expect 802.11b support off. A WLAN that matched the old `Standard`/`Hotspot` baseline will show these deviations.
- **Breaking:** `profiles.yaml` ships inside the package; the file next to the executable is no longer read. Local adjustments move to a `profiles.yaml` next to the configuration file in use (never the legacy data directory, where the 0.4.x installer's copy stays unread), or `--profiles-file`.
- **Breaking:** `security_protocols` and `pmf` are lists of accepted values; `group_rekey` became `group_rekey_s`.
- The 802.11r-on-IoT advisory is judged on the WLAN's bands (2.4 GHz only) rather than on the profile's name; the 2.4 GHz minimum-rate advisory speaks only for a fixed (`manual`) rate on a WLAN that broadcasts on 2.4 GHz with 802.11b support known to be on — never under `auto`, where the stored value is inert.
- A 6 GHz DTIM value in a profile is reported as not evaluable (6 GHz is detect-only); a WLAN on 6 GHz shows its `roaming_assistant_6e_enabled` switch as a separate, not evaluable result for the same reason.
- Roaming Assistant migrated from a per-AP RF-tuning recommendation to a per-WLAN compliance check next to Fast Roaming, matching UniFi's move of the setting from radio level (`radio_table`) to WLAN level (`wlanconf.roaming_assistant_na_*`). The target threshold is still computed from the same site-aware corridor as before, aggregated (as a conservative minimum) across the APs that broadcast each WLAN, restricted to each AP's configured RF neighbors that also broadcast that SSID.
- WLANs whose broadcasting APs have incomplete data (a broadcasting AP with no SSID-relevant RF neighbor, or a missing neighbor sighting) are reported `Incomplete` with the specific reason, instead of a ✓/✗ verdict computed from a partial data set.
- On older controllers where no WLAN exposes the new field, the tool falls back site-wide to the previous per-AP behavior.

## [0.4.0] - 2026-05-06

Per-AP Roaming Assistant computed from the site-aware corridor instead of a
fixed -67 dBm, plus split coverage diagnostics.

### Added
- Per-AP Roaming Assistant threshold: default `TX_LO + ROAM_OFFSET_DB`, capped
  against the weakest neighbor when that neighbor falls below the corridor,
  then clamped to `[ROAM_FLOOR, ROAM_CEILING]`.
- Two distinct cap warnings with explicit reasons: `Roaming Assistant lowered
  to X dBm` (margin cap) and `Roaming Assistant clamped to ROAM_FLOOR` (floor
  cap).
- Softer coverage marker `°` **Below corridor before TX adjustment** for
  neighbors whose raw RSSI is below `TX_LO` but where the TX recommendation
  may still bring them back into the corridor.
- Environment variables `ROAM_OFFSET_DB`, `ROAM_MARGIN_DB`, `ROAM_FLOOR`,
  `ROAM_CEILING` for tuning the per-AP threshold. All four are validated
  early (integer + plausible range).

### Changed
- Site header no longer shows a single global Roaming Assistant value; the
  per-AP value lives in the AP's *Recommendations* block.
- `*` **Coverage gap** is now reserved for unfixable cases only: TX is at the
  radio limit and the projected RSSI is still below `TX_LO`.
- `docs/ALGORITHM.md` and `README.md` updated for the new algorithm, the
  three-way coverage diagnosis, and the explicit note that WLAN profiles are
  SSID-layer and do not influence Roaming Assistant or Minimum RSSI.

### Fixed
- `print_neighbor_row` no longer hard-codes the `*` marker; the caller-passed
  marker is rendered as-is.

## [0.3.0] - 2026-04-09

Scan reliability and adjacency group diagnostics.

### Added
- Adjacency group diagnostics in the scan output.
- `--help` in the CLI usage output.
- Note printed when the UniFi API is unavailable.
- Adjacency Groups section in `README.md`.

### Changed
- Multi-pass scan reliability improved and hysteresis tightened.
- TX power recommendations refined.
- Internal cleanup: simplified `iw` scanning logic.

## [0.2.0] - 2026-03-23

U7 support, installer, and documentation overhaul.

### Added
- U7 family SSH neighbor scan via `SET_SCAN_DWELL` (Qualcomm AP interfaces).
- Active band detection — inactive bands are skipped in scan and evaluation.
- DFS CAC warning when neighbor data is missing on a DFS channel.
- TX power limits read from UniFi API (`max_txpower`).
- Interactive install/uninstall scripts (`scripts/install.sh`,
  `scripts/uninstall.sh`).
- Restructured documentation: `docs/ALGORITHM.md`, `docs/PROFILES.md`,
  `docs/WALKTHROUGH.md`.

### Changed
- Executable renamed to `unifiwifioptimizer`.

## [0.1.0] - 2026-03-20

First public release.

### Added
- RF optimization engine based on ITU-R P.1238 path loss model.
- AP-to-AP neighbor scan via SSH (U6 family, MediaTek).
- WLAN profile validation against five shipped baselines (Standard, IoT,
  Hotspot, Throughput, Latency).
- TX Power, Roaming Assistant, and Minimum RSSI recommendations.
- UniFi Network API integration (read-only).
- Multi-site support.

[0.5.0]: https://github.com/jtauschl/unifiwifioptimizer/compare/v0.4.0...release/0.5.0
[0.4.0]: https://github.com/jtauschl/unifiwifioptimizer/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/jtauschl/unifiwifioptimizer/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/jtauschl/unifiwifioptimizer/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/jtauschl/unifiwifioptimizer/releases/tag/v0.1.0
