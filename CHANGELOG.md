# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0] - Unreleased

Give UniFi operators verified, actionable RF and WLAN-profile recommendations on current controller releases — including the WLAN-level Handoff Suggestions check, the extended profile schema, and secure-by-default controller and AP access — by rebuilding the optimizer as a typed, tested Python package.

### Added
- Terminology note in `docs/ALGORITHM.md` clarifying that UniFi's "Handoff Suggestions (802.11v)" UI label refers to the same setting this tool calls Roaming Assistant.
- TX power for an AP/band with a configured neighbor but no sighting yet now jumps straight to the radio's maximum, to maximize the chance of a sighting on the next run; once already at maximum with no sighting, this is reported as a distinct informational state.
- "Fix TX power first" note next to an `Incomplete`/`Not evaluable` Roaming Assistant verdict when the site still has pending TX power recommendations.
- New `roaming_assistant` profile field controlling whether Roaming Assistant should be enabled for a WLAN. Shipped defaults: disabled for `Standard`/`IoT`/`Hotspot`, enabled for `Throughput`/`Latency`.
- New `band_steering` profile field controlling whether dual-band clients are steered away from 2.4 GHz. Shipped defaults: enabled for `Standard`/`Throughput`/`Latency`, disabled for `IoT`/`Hotspot`.
- Advisory when a WLAN's 2.4 GHz minimum data rate is below 12 Mbps, since lower rates keep legacy 802.11b protection overhead active.
- Advisory when 802.11r Fast Transition is enabled on an `IoT`-profile WLAN, since it is known to break specific IoT client classes.
- Advisory when a WLAN has MLO enabled but doesn't meet its WPA3 + PMF Required security requirement.
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
