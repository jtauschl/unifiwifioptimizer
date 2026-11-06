# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0] - Unreleased

Give UniFi operators verified, actionable RF and WLAN-profile recommendations on current controller releases — including the WLAN-level Handoff Suggestions check, the extended profile schema, and secure-by-default controller and AP access — by rebuilding the optimizer as a typed, tested Python package.

### Added
- The WLAN rows list every WLAN-editor setting in the controller's order; a setting the profile leaves open shows its value and a note.
- New WLAN rows: Broadcasting APs, MAC Address Filter, RADIUS MAC Authentication, WiFi Blackout Schedule and WiFi Speed Limit (reads `rest/usergroup`, GET).
- A WLAN without 5 GHz is expected to have Handoff Suggestions off, whatever its profile says.
- A profile can pin `multicast_suppressor_mode` (`off`, `conservative`, `aggressive`).
- The information finding `advanced_set_to_auto` marks a WLAN whose Advanced switch is on Auto.
- The transmit-power row shows the set value, the effective power and the EIRP, e.g. `Auto (effective 17 dBm, EIRP 20 dBm)`.
- Each WLAN title names its network and VLAN (`→ network IoT, VLAN 30`); the JSON evaluation carries `network` and `vlan` (reads `rest/networkconf`, GET).
- The channel-reuse finding names its cause and remedy: add channels to the Channel AI list, reduce the width or accept co-channel reuse.
- Check marks are coloured on a terminal; redirected output, `--json`, `NO_COLOR` and `TERM=dumb` stay plain.
- `run --details` prints the complete text evidence.
- An interactive terminal shows one updating scan line during a scan, ended before any error message.
- Optional `rf.client_tx_dbm_5g_upper` sets the assumed client power for 5 GHz channels 100–140; Minimum RSSI and Roaming Assistant show it.
- Advice that depends on another pending change carries a `deferred_by` mark in the text, the JSON and the footer counts.
- `derived.pending_tx_changes` counts only the power changes that can be applied now; `derived.waiting_items` counts the items that wait.
- `run --extended` groups channel, power and Minimum RSSI guidance by access point in `--details` and tells an Auto radio to be pinned until a fresh run.
- The scan script reads the serving 5 GHz PHY's channel-power limits on every scan (read-only queries; see `SECURITY.md`).
- The optional 5 GHz channel plan uses those limits, calibrates them against observed TX and labels higher-power channels as downlink trials, not guaranteed range gains.
- `run --extended` adds a read-only site-wide 2.4/5 GHz channel proposal from the scan evidence and says when a band lacks the evidence.
- The Minimum RSSI header line names Ubiquiti's guidance (−80 dBm as a home or office starting point).
- The `info` finding `roaming_threshold_above_guidance` appears when the Handoff Suggestions threshold to set is not below −70 dBm.
- `rf.client_tx_dbm` defaults to 14 dBm (Cisco: a typical client transmits about 13–14 dBm).
- The Roaming Assistant threshold and the per-radio Minimum RSSI stay inside the controller's accepted ranges (−80 to −60 and −90 to −67 dBm).
- A derived value outside the accepted range moves to the nearer end; the report and the JSON (`derived_dbm`) name the derived value.
- New subcommand `init` creates the configuration file interactively and never overwrites one.
- New subcommand `controller-fingerprint [--url URL]` prints the controller's certificate fingerprint for pinning.
- New subcommand `trust-host-keys --site ID [--ap NAME]... [--yes] [--accept-unverified]` stores the access points' SSH host keys after verifying them.
- `config --profiles` prints the effective WLAN profiles with their evidence annotations.
- Global options: `--config-file PATH`, `--profiles-file PATH` and `--dump-api DIR` (models with secrets masked, plus counts of unused fields).
- `run` and `trust-host-keys` take `--known-hosts PATH` for the host-key store.
- New `controller` keys: `ca_cert`, `cert_fingerprint`, `timeout_s`.
- New per-site `ssh` keys: `auth`, `key_file`, `host_keys`, `scan_interface_toggle`, `allow_public_ap_addresses`, `scan_concurrency`, `scan_attempts`.
- New `rf:` section: `noise_floor_dbm`, `required_snr_db`, `client_tx_dbm`, `min_rssi_offset_db`, `roam_offset_db`, `roam_margin_db`, `roam_floor_dbm`, `roam_ceiling_dbm`.
- `UNIFI_API_KEY` and `UNIFI_SSH_PASSWORD` override the secrets in the file and are removed from the process environment once read.
- `run [--site ID]... [--json] [--no-scan] [--clients]` analyses the controller snapshot and the AP-to-AP neighbour scans of each site.
- `--json` prints one document (`schema_version` 1) for every site.
- `--no-scan` analyses the controller side only, the natural first run before `trust-host-keys`.
- `--clients` adds the associated clients per radio as signal counts, never identities.
- Exit codes: 0 ok, 1 unexpected, 2 usage, 3 configuration, 4 TLS, 5 host keys, 6 partial result, 7 environment, 130 interrupted.
- The neighbour matrix gives the reason for every missing reading (offline, DFS wait, scan failed or empty, interface down, not sighted).
- One-way misses use reciprocity (reverse reading plus power difference); receivers that disagree about a pair show as information from 5 dB.
- Transmit power is a decision table: in corridor, out of corridor, raise to maximum, coverage gap, too strong at minimum, blocked, no sighting.
- A radio in automatic power mode is judged by its effective power and phrased as "set to Custom, N dBm".
- Channel checks run over the configured and the heard graph (own access points heard at or above the IEEE 802.11 CCA level of −82 dBm).
- They report overlap with free candidates, co-channel contention and reuse feasibility by graph colouring with the controller's candidate channels.
- An auto radio under Channel AI is reported, not recommended; a channel blacklist, 40 MHz on 2.4 GHz and foreign-network counts are reported too.
- Without a 5 GHz channel list, the free-channel hints and the 5 GHz reuse check are skipped and the `info` finding `channel_candidates_unknown` says so.
- Per-radio Minimum RSSI on the uplink (corridor floor minus margin, converted with `rf.client_tx_dbm`); a disabled setting is reported as the value to use.
- An advisory flags an enabled Minimum RSSI that would disconnect before the roaming trigger.
- Airtime figures per radio.
- A Roaming Assistant check carries the "fix TX power first" note while a 5 GHz power change is pending.
- Offline access points are one line; radios in DFS wait get the channel-aware re-run hint; an `empty` scan band gets a restart suggestion.
- A name listed under `neighbors` that two controller devices share is a configuration error (exit 3, before any scan).
- Any other shared access point name is an error finding naming both MACs; neither device is analysed and the run is partial (exit 6).
- WLAN profiles carry an evidence tier per key (`standard`, `vendor`, `practice`) with its source in the `evidence` section.
- A profile may carry its own `evidence` block for keys whose tier or source differs from the set-wide one.
- Your own `profiles.yaml` next to `config.yaml` (or `--profiles-file PATH`) extends the shipped profiles or replaces one whole; unknown keys and values are errors.
- Optional profile keys, checked only when set: `iot_dtim_lock`, `iot_channel_lock`, `enhanced_iot`, `dns_assistance_mode`, `mdns_proxy_mode`, `ppsk`, `wpa3_enhanced_192`.
- Advisory for IoT locks on a WLAN meant for 5 GHz clients.
- Advisory for an mDNS proxy on an isolated WLAN.
- Advisory for Private Pre-Shared Keys without a PSK handshake.
- Advisory for WPA3 Enhanced 192-bit on anything but WPA3 Enterprise.
- Advisory for a PMF setting that does not fit the protocol: WPA3-only and OWE need Required, WPA3 transition exactly Optional, Open none.
- A WLAN setting the controller did not send is reported as `incomplete`, not compared against an assumed default.
- A combination the controller sent but the tool cannot name (e.g. `wpapsk/wpa1`) is a deviation showing the raw pair.
- `docs/ALGORITHM.md` notes that UniFi's "Handoff Suggestions (802.11v)" label is the setting this tool calls Roaming Assistant.
- New `roaming_assistant` profile field: whether Roaming Assistant should be enabled for a WLAN.
- New `band_steering` profile field: whether dual-band clients are steered away from 2.4 GHz.
- Advisories `min_rate_2g_dsss` and `min_rate_2g_below_recommended` flag a 2.4 GHz minimum data rate that is an 802.11b rate or below 12 Mbps.
- Advisory when 802.11r Fast Transition is enabled on an `IoT`-profile WLAN, since it breaks specific IoT client classes.
- Advisory when a WLAN has MLO enabled without a WPA3-only protocol and PMF Required.
- Advisory when 802.11r Fast Transition is enabled but 802.11v is disabled, since the fast handoff depends on it.
- Security Protocol recognition for `Enhanced Open (OWE)` and `Enhanced Open with Transition`.
- A line under every ✗ compliance check and recommendation names where in the UniFi UI to make the change.
- A scope statement ends every run: the tool cannot see non-WiFi interference, per-client statistics, real roaming timing or packet captures.
- `docs/ALGORITHM.md` notes that neighbour RSSI is an AP-to-AP beacon reading, not a client link-budget proxy.

### Fixed
- WPA3 Enterprise WLANs no longer have SAE Anti-clogging/Sync Time checked against the profile; Enterprise has no SAE handshake.
- `Standard`: `sae_anti_clogging` corrected from 10 to 5, matching the controller default the other profiles use.
- A non-compliant 6 GHz DTIM period gets a UI-path hint like its 2.4/5 GHz counterparts.
- A `Standard` WLAN broadcasting only on 2.4 GHz with Fast Roaming gets the same IoT-client-breakage advisory as an `IoT` WLAN.
- The site-level pending TX-power count no longer inflates on access points whose 5 GHz radio is inactive.
- Roaming Assistant recommendations work again on current UniFi firmware.
- A WLAN whose aggregated signal value was empty no longer crashes or gives a wrong Roaming Assistant result.
- Roaming Assistant compliance no longer reports a false deviation when it is enabled but no RSSI threshold is set yet.
- Roaming Assistant and Minimum RSSI defaults match Apple's published roaming triggers, reducing premature disconnects on iOS and macOS.
- The Minimum RSSI recommendation sits a safety margin below the roaming trigger, not equal to it, preventing disconnect loops on 802.11v clients.
- Coverage-gap warnings show for every neighbour below the target corridor, not only when TX power hit its hardware limit.

### Changed
- `run` prints the WLANs first, then each access point's radios, the RF notes and the limits of the data; `--details` prints the complete report.
- **Breaking:** TLS certificates are always verified; a controller with a self-signed certificate fails with exit 4. Set `controller.cert_fingerprint` or `controller.ca_cert` ([migration](https://github.com/jtauschl/unifiwifioptimizer/blob/main/docs/MIGRATION.md#tls-certificates)).
- **Breaking:** SSH host keys are always verified; run `trust-host-keys --site <site-id>` once per site before scanning ([migration](https://github.com/jtauschl/unifiwifioptimizer/blob/main/docs/MIGRATION.md#ssh-host-keys)).
- **Breaking:** the Bash tool, `install.sh`, Ruby and `sshpass` are gone; install with `uv tool install unifiwifioptimizer` (Python 3.11, OpenSSH 8.4). Move your configuration first ([migration](https://github.com/jtauschl/unifiwifioptimizer/blob/main/docs/MIGRATION.md#installation)).
- **Breaking:** the command line is subcommand-based; the analysis is `unifiwifioptimizer run` and usage errors exit 2. Update scripts and cron entries ([migration](https://github.com/jtauschl/unifiwifioptimizer/blob/main/docs/MIGRATION.md#command-line)).
- **Breaking:** the configuration file is `~/.config/unifiwifioptimizer/config.yaml` or `--config-file`, mode `0600`. Move it and `chmod 600` it ([migration](https://github.com/jtauschl/unifiwifioptimizer/blob/main/docs/MIGRATION.md#configuration-file)).
- **Breaking:** the `ROAM_*` environment variables became `rf.*` configuration keys, and the floor and ceiling defaults moved to −75/−65 dBm ([migration](https://github.com/jtauschl/unifiwifioptimizer/blob/main/docs/MIGRATION.md#roaming-variables)).
- **Breaking:** `ssh.auth` is explicit; a `user` without a password is now an error. Add `auth: key` or `auth: controller` ([migration](https://github.com/jtauschl/unifiwifioptimizer/blob/main/docs/MIGRATION.md#ssh-authentication)).
- **Breaking:** a scan interface that is down is no longer brought up unless `ssh.scan_interface_toggle: true` ([migration](https://github.com/jtauschl/unifiwifioptimizer/blob/main/docs/MIGRATION.md#scan-interface-toggle)).
- All passes of one site run before the next site starts, and access points are scanned one at a time; `ssh.scan_concurrency` opts in to more.
- **Breaking:** 6 GHz radios are their own band and reported as not evaluated; 0.4.x could take a lone `6e` radio for the 5 GHz one ([migration](https://github.com/jtauschl/unifiwifioptimizer/blob/main/docs/MIGRATION.md#6-ghz-radios)).
- **Breaking:** YAML booleans are `true` and `false` only; a yes/no key in a hand-written `profiles.yaml` refuses `yes`, `no`, `on` and `off` ([migration](https://github.com/jtauschl/unifiwifioptimizer/blob/main/docs/MIGRATION.md#yaml-booleans)).
- **Breaking:** recommendations rest on the effective transmit power (`radio_table_stats.tx_power`), not the configured one ([migration](https://github.com/jtauschl/unifiwifioptimizer/blob/main/docs/MIGRATION.md#recommendation-basis)).
- **Breaking:** the weakest configured neighbour decides, not the mean, and the missing-peer +1 dB nudge is gone ([migration](https://github.com/jtauschl/unifiwifioptimizer/blob/main/docs/MIGRATION.md#recommendation-basis)).
- **Breaking:** a zero sighting raises to the maximum only after a miss in both directions with working scans ([migration](https://github.com/jtauschl/unifiwifioptimizer/blob/main/docs/MIGRATION.md#recommendation-basis)).
- **Breaking:** readings are the median over passes on the peer's channel ([migration](https://github.com/jtauschl/unifiwifioptimizer/blob/main/docs/MIGRATION.md#recommendation-basis)).
- **Breaking:** the colouring check replaces the 60/320 MHz width budgets and the "more than three 2.4 GHz peers" rule ([migration](https://github.com/jtauschl/unifiwifioptimizer/blob/main/docs/MIGRATION.md#channel-and-roaming-checks)).
- **Breaking:** Roaming Assistant is read from the WLAN only, not per radio as in 0.4.x; a controller without the WLAN field reports the older API ([migration](https://github.com/jtauschl/unifiwifioptimizer/blob/main/docs/MIGRATION.md#channel-and-roaming-checks)).
- An enabled Minimum RSSI is no longer flagged by itself.
- **Breaking:** the report is plain text without the 0.4.x colour codes in files and pipes; `--json` is the machine format ([migration](https://github.com/jtauschl/unifiwifioptimizer/blob/main/docs/MIGRATION.md#output-and-failures)).
- **Breaking:** 0.5.0 also reads `apgroups`, `networkconf`, `usergroup` and `setting`; a failing endpoint aborts the run with exit 1 ([migration](https://github.com/jtauschl/unifiwifioptimizer/blob/main/docs/MIGRATION.md#output-and-failures)).
- A configured access point the controller reports as disconnected is not contacted.
- **Breaking:** the shipped profiles are recommendations grouped by device class (`Standard`, `Compat`, `IoT`, `Hotspot`); review the deviations they report ([profile changes](https://github.com/jtauschl/unifiwifioptimizer/blob/main/docs/MIGRATION.md#shipped-profiles)).
- **Breaking:** `Throughput` is now `Standard` and `Latency` is removed; a WLAN mapped to either name reports "profile is not defined" ([migration](https://github.com/jtauschl/unifiwifioptimizer/blob/main/docs/MIGRATION.md#profile-names)).
- A group rekey interval is not judged on an open or Enhanced Open WLAN when the controller does not send it.
- Band Steering is not judged on a WLAN that does not broadcast on 2.4 GHz together with another band.
- `docs/PROFILES.md` shows which profile fits which device class and every setting by profile, generated from `profiles.yaml` and checked by a test.
- **Breaking:** `profiles.yaml` ships inside the package; local adjustments go to a `profiles.yaml` next to the configuration file or `--profiles-file` ([migration](https://github.com/jtauschl/unifiwifioptimizer/blob/main/docs/MIGRATION.md#profile-file)).
- **Breaking:** `security_protocols` and `pmf` are lists of accepted values; `group_rekey` became `group_rekey_s`, `multicast_broadcast_blocker` became `multicast_suppressor_mode` ([migration](https://github.com/jtauschl/unifiwifioptimizer/blob/main/docs/MIGRATION.md#profile-keys)).
- **Breaking:** a profile in an override file replaces the shipped one whole and must set `roaming_assistant` and `band_steering` ([migration](https://github.com/jtauschl/unifiwifioptimizer/blob/main/docs/MIGRATION.md#profile-keys)).
- The 802.11r-on-IoT advisory is judged on the WLAN's bands (2.4 GHz only), not on the profile's name.
- The 2.4 GHz minimum-rate advisory speaks only for a fixed rate on a WLAN with 802.11b support on, never under `auto`.
- A 6 GHz DTIM value in a profile and `roaming_assistant_6e_enabled` are reported as not evaluable, because 6 GHz is detect-only.
- Roaming Assistant is a per-WLAN compliance check next to Fast Roaming, matching UniFi's move of the setting to WLAN level.
- Its target threshold is the conservative minimum of the site-aware corridor over the broadcasting access points' RF neighbours that carry the SSID.
- A WLAN whose broadcasting access points have incomplete data is reported `Incomplete` with the reason, not a ✓/✗ verdict from partial data.
- The text report folds lines longer than 100 columns; a continuation starts under the value column or past the bullet.
- `ssh.auth: controller` (the default) reads the controller-managed SSH password through the API key, which must belong to a full Administrator.

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
