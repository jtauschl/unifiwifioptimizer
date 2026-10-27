# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0] - Unreleased

Give UniFi operators verified, actionable RF and WLAN-profile recommendations on current controller releases — including the WLAN-level Handoff Suggestions check, the extended profile schema, and secure-by-default controller and AP access — by rebuilding the optimizer as a typed, tested Python package.

### Added
- A profile can pin `multicast_suppressor_mode` (`off`, `conservative`, `aggressive`; Multicast Suppression), and an information finding `advanced_set_to_auto` marks a WLAN whose Advanced switch is on Auto.
- The transmit-power row of the default report shows the set value, the effective power and the EIRP (effective power plus the antenna gain the controller reports), e.g. `Auto (effective 17 dBm, EIRP 20 dBm)`.
- The title of each WLAN names the network it is attached to and its VLAN (`→ network IoT, VLAN 30`, or `untagged`); the JSON evaluation carries `network` and `vlan`. The tool reads one more endpoint (`rest/networkconf`, GET) for it.
- The channel-reuse finding names its cause and the remedy: with the controller's Channel AI list it states how many blocks of the widest width the list offers and how many the access points that hear each other would need, and tells you to add channels to the list, reduce the width or accept co-channel reuse; on 2.4 GHz only 1/6/11 count.
- The WLAN rows of the text report follow the order and the wording of the controller's WLAN editor (Radio Band, Fast Roaming (802.11r), Handoff Suggestions (802.11v), Minimum Data Rate, Multicast Filtering, … Group Rekey Interval), so a setting sits where it does in the UI.
- The check marks of the text report are coloured on a terminal; redirected output, `--json`, `NO_COLOR` and `TERM=dumb` stay plain.
- `run --details` prints the complete text evidence. An interactive terminal shows one updating scan line during a scan, which is ended before any error message.
- An optional `rf.client_tx_dbm_5g_upper` assumption for current 5 GHz blocks within channels 100–140; Minimum RSSI and Roaming Assistant use each AP's assumed client power and show it when the override is configured.
- Advice that rests on a setting another recommendation changes first (power and Minimum RSSI after a site-wide channel move, Minimum RSSI after a power change of the same band, a failed Roaming Assistant check of a WLAN whose broadcasting access points move their 5 GHz channel or change their 5 GHz power) carries a `deferred_by` mark in the text, the JSON and the footer counts; `derived.pending_tx_changes` counts only the power changes that can be applied now and `derived.waiting_items` the items that wait. `run --extended` also groups channel, transmit-power and Minimum RSSI guidance by access point in `--details`, and an Auto radio is told to be pinned until a fresh run.
- The scan script reads the serving 5 GHz PHY's channel-power limits on every scan (read-only queries; see `SECURITY.md`). The optional 5 GHz channel plan uses them, calibrates them against observed TX, accounts for possible added co-channel pressure and known power loss, and labels higher-power channels as downlink trials rather than guaranteed range improvements.
- `run --extended` adds an optional read-only site-wide 2.4/5 GHz channel proposal from existing scan evidence. It preserves radio widths, reports measured own-AP conflict changes and residual reuse, and explains when a band lacks enough evidence for a concrete proposal.
- The Minimum RSSI line of the report header names Ubiquiti's guidance (generally only for high-density deployments; −80 dBm as a starting point at home or in an office), and an `info` finding `roaming_threshold_above_guidance` appears when the Handoff Suggestions threshold to set is not below the −70 dBm Ubiquiti suggests. `rf.client_tx_dbm` defaults to 14 dBm (Cisco: a typical client transmits about 13–14 dBm).
- The Roaming Assistant threshold and the per-radio Minimum RSSI stay inside the range the controller accepts (−80 to −60 dBm and −90 to −67 dBm). A derived value outside it moves to the nearer end and the report names the derived value (JSON: `derived_dbm` on the WLAN roaming summary and on each recommendation, `null` when nothing moved); a setting at the end passes the check or counts as confirmed, and the Minimum RSSI ordering advisory and the client counts judge the value that can be set.
- Subcommands replace the 0.4.x flags: `sites` (was `--sites`), `site <site>` (was `--site`), `config <site>` (was `--config`), plus `init` (creates the configuration file interactively and never overwrites one), `controller-fingerprint [--url URL]` (prints the controller's certificate fingerprint for pinning) and `trust-host-keys --site ID [--ap NAME]... [--yes] [--accept-unverified]` (stores the access points' SSH host keys after verifying them). `config --profiles` prints the effective WLAN profiles. Global options: `--config-file PATH`, `--profiles-file PATH` and `--dump-api DIR` (the models read from each endpoint with secrets masked, and a count of the fields the tool does not use). `run` and `trust-host-keys` take `--known-hosts PATH` for the host-key store.
- Configuration keys: `controller.ca_cert`, `controller.cert_fingerprint`, `controller.timeout_s`; per site `ssh.auth`, `ssh.key_file`, `ssh.host_keys`, `ssh.scan_interface_toggle`, `ssh.allow_public_ap_addresses`, `ssh.scan_concurrency`, `ssh.scan_attempts`; the `rf:` section (`noise_floor_dbm`, `required_snr_db`, `client_tx_dbm`, `min_rssi_offset_db`, `roam_offset_db`, `roam_margin_db`, `roam_floor_dbm`, `roam_ceiling_dbm`). The environment variables `UNIFI_API_KEY` and `UNIFI_SSH_PASSWORD` replace the API key and the SSH password in the file and are removed from the process environment once read.
- `unifiwifioptimizer run [--site ID]... [--json] [--no-scan] [--clients]`: the analysis itself — controller snapshot plus AP-to-AP neighbour scans per site, the transmit-power, Minimum-RSSI and Roaming-Assistant recommendations, the WLAN profile checks, channel checks and a plain-text report; `--json` prints one document (`schema_version` 1) for every site; `--no-scan` analyses the controller side only (the natural first run, before `trust-host-keys`); `--clients` adds the associated clients per radio as signal counts (never identities). Exit codes: 0 ok, 1 unexpected, 2 usage, 3 configuration, 4 TLS, 5 host keys kept every access point of a site unverified, 6 partial result (a finding in the report says why), 7 environment, 130 interrupted.
- Neighbour matrix with the reason for every missing reading (offline, DFS wait, scan failed/empty/interface down, no DFS evidence, not sighted), reciprocity for one-way misses (the reverse reading plus the power difference), and the receivers' disagreement per pair as information from 5 dB.
- Transmit power as a decision table: in corridor, out of corridor, raise to the maximum, coverage gap at the effective maximum (a design finding, not a value), too strong even at the minimum, reduction blocked while a neighbour is unevaluated, no sighting in both directions; a radio in automatic power mode is judged by its effective power and phrased as "set to Custom, N dBm".
- Channel checks over the configured and the heard graph (own access points heard at or above the IEEE 802.11 CCA level of −82 dBm): overlap with free candidates, co-channel contention, reuse feasibility by graph colouring with the controller's candidate channels, Channel AI awareness (an auto radio under Channel AI is reported, not recommended), blacklist, 40 MHz on 2.4 GHz, foreign-network counts. Without a 5 GHz channel list from the controller, the free-channel hints and the reuse check for 5 GHz are skipped and an `info` finding `channel_candidates_unknown` says so, because the usable 5 GHz channels depend on the country.
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
- New `roaming_assistant` profile field controlling whether Roaming Assistant should be enabled for a WLAN. Shipped: enabled for `Standard`/`Throughput`/`Latency`, disabled for `IoT`/`Hotspot`.
- New `band_steering` profile field controlling whether dual-band clients are steered away from 2.4 GHz. Shipped defaults: enabled for `Standard`/`Throughput`/`Latency`, disabled for `IoT`/`Hotspot`.
- Advisory when a WLAN's 2.4 GHz minimum data rate is an 802.11b rate (it admits 802.11b clients) or below 12 Mbps (it keeps broadcast frames on slow rates); the advisory codes are `min_rate_2g_dsss` and `min_rate_2g_below_recommended`.
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
- Site-level pending TX-power count no longer inflates on APs whose 5 GHz radio is inactive.
- Roaming Assistant recommendations no longer silently stop working on current UniFi firmware.
- Fixed a rare crash or incorrect Roaming Assistant compliance result for a WLAN whose aggregated signal value was empty.
- Roaming Assistant compliance no longer reports a false deviation for a WLAN with Roaming Assistant enabled but no RSSI threshold set yet.
- Roaming Assistant and Minimum RSSI defaults recalibrated to match Apple's published roaming triggers, reducing premature disconnects on iOS/macOS clients.
- Minimum RSSI recommendation is now set with a safety margin below the roaming trigger instead of equal to it, preventing disconnect loops on 802.11v-capable clients.
- Coverage-gap warnings are now shown for every neighbor still below the target signal corridor, instead of only when TX power itself hit its hardware limit — a real coverage problem could previously be understated.

### Changed
- `run` prints the WLANs first, with their settings in the controller UI's wording and order, then each access point's radios (width, channel, transmit power, Minimum RSSI), the RF notes and the limits of the data. A setting's UI path appears only where it is hard to find. `--details` prints the complete text report.
- **Breaking:** TLS certificates are verified, always. 0.4.x ran `curl -k`. A controller that still has its factory (self-signed) certificate now fails with exit code 4. Migration: run `unifiwifioptimizer controller-fingerprint`, compare the result with the certificate view in the controller, and set `controller.cert_fingerprint`; or set `controller.ca_cert` to the CA that signed the certificate. There is no switch to turn verification off.
- **Breaking:** SSH host keys are verified, always. 0.4.x ran `StrictHostKeyChecking=no`. A scan refuses an access point whose key it does not know and never stores one itself. Migration: run `unifiwifioptimizer trust-host-keys --site <site-id>` once per site; a key is accepted against a pin in `ssh.host_keys`, against the fingerprint the controller reports, or — only with your confirmation or `--accept-unverified` — on first use.
- **Breaking:** the tool installs as a Python package: `uv tool install unifiwifioptimizer` or `pipx install unifiwifioptimizer`. The Bash tool, `install.sh`, `uninstall.sh`, the Ruby dependency and `sshpass` are gone; Python 3.11 and OpenSSH 8.4 are required. Migration: if you installed 0.4.x with `install.sh`, move your configuration and any edited `profiles.yaml` first, because the 0.4.x uninstaller deletes the directory they live in; if you ran it from a clone, move them out of the clone. Then uninstall 0.4.x and install the package (see "Upgrading from 0.4.x" in the README).
- **Breaking:** the command line is subcommand-based. The analysis is `unifiwifioptimizer run`; a bare call no longer runs it. `--sites`, `--site` and `--config` became `sites`, `site` and `config`, and exit codes follow the table in the README (usage errors are 2, not 1). Migration: update scripts and cron entries.
- **Breaking:** the configuration file is `$XDG_CONFIG_HOME/unifiwifioptimizer/config.yaml` (usually `~/.config/unifiwifioptimizer/config.yaml`) or the path given with `--config-file`; the working directory is never searched. The 0.4.x installer's location, `~/.local/share/unifiwifioptimizer/config.yaml`, is still read, with a notice, as long as the new location has no file; the 0.4.x installer did not make the file private, so until you `chmod 600` it every command that reads it stops with exit code 3. The file must be a regular file you own with mode `0600` or stricter, in a directory others cannot write to; anything else is an error. Migration: move the file and `chmod 600` it.
- **Breaking:** the `ROAM_OFFSET_DB`, `ROAM_MARGIN_DB`, `ROAM_FLOOR` and `ROAM_CEILING` environment variables are replaced by `rf.roam_offset_db`, `rf.roam_margin_db`, `rf.roam_floor_dbm` and `rf.roam_ceiling_dbm` in the configuration file. Migration: set the keys you used. The floor and ceiling defaults moved from −78/−67 dBm to −75/−65 dBm, and both now bound the client-side trigger before it is converted to the uplink value UniFi applies (`docs/ALGORITHM.md` §7), so re-derive a value you had tuned instead of copying it.
- **Breaking:** `ssh.auth` is explicit. A site whose `ssh` section sets no `user`, `password` or `key_file` uses `controller` (the controller-managed credentials). `user` plus `password` is password login. `user` without a password used to mean key or agent login and is now an error that tells you to set `auth: key`. Migration: add `auth: key` (or `auth: controller`) to such sites.
- **Breaking:** a scan interface that is down is no longer brought up for the scan unless you ask for it; 0.4.x did that on its own and put the interface down again afterwards. Migration: set `ssh.scan_interface_toggle: true` for a site with access points that keep their scan interfaces down at rest (the U6 Lite); without it such a band is reported as `interface_down`.
- All passes of one site run before the next site starts (0.4.x ran pass 1 over every site, then pass 2); access points are scanned one at a time, because an access point scanning off-channel stops beaconing and concurrent neighbours would under-count each other. `ssh.scan_concurrency` opts in to more.
- **Breaking:** 6 GHz radios are recognised as their own band and reported as not evaluated; 0.4.x had no 6 GHz band and could take a lone `6e` radio for the 5 GHz one. Migration: none; the 2.4 GHz and 5 GHz radios of the same access point are analysed as before.
- **Breaking:** YAML booleans are `true` and `false` only; `yes`, `no`, `on` and `off` are plain strings (so `dns_assistance_mode: off` stays the text `off`). A 0.4.x `config.yaml` has no such values; a hand-written `profiles.yaml` may. Migration: quote or rewrite a value that relied on the old reading.
- **Breaking:** recommendations rest on the effective transmit power (`radio_table_stats.tx_power`), not the configured one; the weakest configured neighbour decides, not the mean; the missing-peer +1 dB nudge is gone; a zero sighting raises to the maximum only after a miss in both directions with working scans; readings are the median over passes on the peer's channel.
- **Breaking:** the width budgets (60/320 MHz) and the "more than three 2.4 GHz peers" rule are replaced by the colouring check; the per-radio Roaming Assistant fallback for controllers without the WLAN-level field is gone (the check reports the older API instead); an enabled Minimum RSSI is no longer flagged by itself.
- **Breaking:** the report is plain text, without the 0.4.x colour codes in files and pipes (the check marks are coloured only on a terminal); `--json` is the machine format. A controller endpoint that fails (for example `apgroups`) aborts the run with exit 1 instead of being skipped.
- A configured access point the controller reports as disconnected is not contacted.
- **Breaking:** the shipped profiles are recommendations, not controller-default snapshots. `Standard` now expects WPA2/WPA3 (transition) with PMF Optional, 802.11r, 802.11v, Roaming Assistant on and a 3600 s group rekey; `Hotspot` expects Enhanced Open (OWE, transition preferred) with plain Open still accepted, the mDNS proxy off and a 3600 s group rekey; `IoT` accepts WPA2 or WPA2/WPA3 with PMF off or optional (no longer WPA2-only with PMF off); `Throughput` and `Latency` expect 802.11b support off and a minimum data rate of 12 Mbps on both bands (it was 11 Mbps on 2.4 GHz and 24 Mbps on 5 GHz; Cisco recommends 24 Mbps only for well-designed high-density networks); `Throughput` keeps the controller's DTIM defaults (it expected custom 3/3); U-APSD is off in `Latency` (it expected on); `Standard`, `Throughput` and `Latency` expect Proxy ARP and multicast-to-unicast on (`Standard` expected both off). A WLAN that matched the old baselines will show these deviations; the cause is each profile's evidence text (`unifiwifioptimizer config --profiles`).
- **Breaking:** `profiles.yaml` ships inside the package; the file next to the executable is no longer read. Local adjustments move to a `profiles.yaml` next to the configuration file in use (never the legacy data directory, where the 0.4.x installer's copy stays unread), or `--profiles-file`.
- **Breaking:** `security_protocols` and `pmf` are lists of accepted values (a plain string is refused); `group_rekey` became `group_rekey_s`; `roaming_assistant` and `band_steering` are required in every profile of an override file, which replaces a shipped profile whole.
- The 802.11r-on-IoT advisory is judged on the WLAN's bands (2.4 GHz only) rather than on the profile's name; the 2.4 GHz minimum-rate advisory speaks only for a fixed (`manual`) rate on a WLAN that broadcasts on 2.4 GHz with 802.11b support known to be on — never under `auto`, where the stored value is inert.
- A 6 GHz DTIM value in a profile is reported as not evaluable (6 GHz is detect-only); a WLAN on 6 GHz shows its `roaming_assistant_6e_enabled` switch as a separate, not evaluable result for the same reason.
- Roaming Assistant migrated from a per-AP RF-tuning recommendation to a per-WLAN compliance check next to Fast Roaming, matching UniFi's move of the setting from radio level (`radio_table`) to WLAN level (`wlanconf.roaming_assistant_na_*`). The target threshold is still computed from the same site-aware corridor as before, aggregated (as a conservative minimum) across the APs that broadcast each WLAN, restricted to each AP's configured RF neighbors that also broadcast that SSID.
- WLANs whose broadcasting APs have incomplete data (a broadcasting AP with no SSID-relevant RF neighbor, or a missing neighbor sighting) are reported `Incomplete` with the specific reason, instead of a ✓/✗ verdict computed from a partial data set.
- The text report folds lines longer than 100 columns; a continuation starts under the line's value column or past its bullet, never where a new item would.
- `ssh.auth: controller` (the default) reads the controller-managed SSH password through the API key, so the key must belong to a full Administrator; a View Only key cannot see device secrets, and the error says so.

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
