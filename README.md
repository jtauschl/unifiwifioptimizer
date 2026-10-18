# UniFi WiFi Optimizer

> RF tuning and WLAN baseline review for UniFi access points — transmit power, roaming, and minimum RSSI recommendations derived from AP-to-AP neighbor scans.

<p align="center">
  <img src="https://raw.githubusercontent.com/jtauschl/unifiwifioptimizer/main/docs/img/UniFiWiFiOptimizer.png" alt="UniFi WiFi Optimizer – RF tuning tool for UniFi access points" width="600">
</p>

`UniFi WiFi Optimizer` is a command-line tool for post-placement UniFi WLAN review and RF tuning.
It reads radio configuration and WLAN settings from the UniFi Network API, compares them against shipped WLAN profiles, collects AP-to-AP neighbor scan data via SSH, and generates recommendations for:

- profile-based WLAN best practices for Standard, IoT, Hotspot, Throughput, and Latency profiles, including a Roaming Assistant compliance check
- access point settings: `Transmit Power`, `Minimum RSSI`
- channel plan checks: overlap, co-channel contention, reuse feasibility

The tool **never writes** to the controller or to an access point. You apply every recommendation yourself in UniFi Network.

The shipped profiles are recommendations with an evidence tier per setting (standard, vendor, practice) for everyday WLANs, 2.4 GHz-only IoT WLANs, public hotspots, throughput-focused WLANs, and low-latency WLANs; see [docs/PROFILES.md](https://github.com/jtauschl/unifiwifioptimizer/blob/main/docs/PROFILES.md).

AP recommendations are derived from AP-to-AP neighbor scan RSSI against a cell edge of `noise floor + required SNR` (default −92 dBm + 25 dB = −67 dBm), adjusted for the configured RF environment such as open space, office, or obstructed layouts. The Roaming Assistant threshold is computed per WLAN from that corridor and aggregated, conservatively, across the access points that broadcast the WLAN. (UniFi's controller UI calls this setting "Handoff Suggestions (802.11v)" since Network Application 10.4.57.)

AP-level recommendations (TX power, Minimum RSSI) are radio-scoped in UniFi and are not derived from the WLAN profile assigned to an SSID; Roaming Assistant is WLAN-scoped and appears as a profile compliance check instead.

For the full RF derivation, see [docs/ALGORITHM.md](https://github.com/jtauschl/unifiwifioptimizer/blob/main/docs/ALGORITHM.md).

## Requirements

- Python 3.11 or newer and OpenSSH 8.4 or newer (`ssh`) on the machine that runs the tool. No other tool is needed.
- A **UniFi OS gateway** (for example a UDM or Cloud Gateway) running UniFi Network Application **10.x**. The tool is verified against 10.6.106. It does not check the version: a setting the controller does not send is reported as `incomplete` instead of being compared with an assumed default. A self-hosted standalone Network Application without UniFi OS is not supported in this release.
- A UniFi Network API key of an account with the **full Administrator role**: `ssh.auth: controller` reads the controller-managed SSH credentials through that key, which a View Only account is not allowed to see.
- UniFi access points managed by that application, with `Device SSH Authentication` enabled. Firmware `6.7.x` or later (U6 series) / `8.0.x` or later (U7 series) for the SSH neighbor scan.

## Tested Hardware

| Model | API | SSH Neighbor Scan | Notes |
|---|---|---|---|
| U6 Lite | ✅ | ✅ | Dedicated scan interfaces (`apcli0`/`apclii0`); keeps them down at rest, so set `ssh.scan_interface_toggle: true` |
| U7 Lite | ✅ | ✅ | AP interfaces (`wifi0ap0`/`wifi1ap1`) via `SET_SCAN_DWELL` (Qualcomm) |

Models in the same UniFi firmware family share the same kernel and driver architecture and are expected to be compatible:

- **U6 family** (firmware 6.x, MediaTek): U6 Lite, U6-LR, U6+, UAP-nanoHD, IW-HD, FlexHD, BeaconHD
- **U7 family** (firmware 8.x, Qualcomm): U7 Lite, U7 Outdoor, U7 In-Wall, U7 Pro, U7 Pro Wall, U7 Pro Max, U7 Pro Outdoor, U7 Pro XG, U7 Pro XG-Wall, U7 Pro XGS, E7, E7-Campus, E7-Audience

An off-channel scan interrupts service on the scanning access point for the duration of the scan. Radios on 6 GHz are recognised as their own band and reported as not evaluated; U7 Pro, E7, and other models with a 6 GHz radio are analyzed on 2.4 GHz and 5 GHz.

## Install

```bash
uv tool install unifiwifioptimizer
```

or

```bash
pipx install unifiwifioptimizer
```

Check the installation with `unifiwifioptimizer --version`. Upgrade with `uv tool upgrade unifiwifioptimizer` (or `pipx upgrade unifiwifioptimizer`) and remove with `uv tool uninstall unifiwifioptimizer` (or `pipx uninstall unifiwifioptimizer`). To check that a downloaded file was built by this repository's release workflow, see [SECURITY.md](https://github.com/jtauschl/unifiwifioptimizer/blob/main/SECURITY.md#release-verification).

## Upgrading from 0.4.x

0.5.0 is a rewrite. The Bash tool, `install.sh` and the Ruby dependency are gone, and several defaults became safer. The command line is subcommand-based now: the analysis is `unifiwifioptimizer run` (a bare call no longer runs it), and `--sites`, `--site` and `--config` became `sites`, `site` and `config`; update scripts and cron entries. Do the steps in this order — the 0.4.x uninstaller deletes `~/.local/share/unifiwifioptimizer`, where an installed 0.4.x keeps its `config.yaml` and `profiles.yaml`:

1. **Move your configuration** to the new location and keep it private:

   ```bash
   mkdir -p ~/.config/unifiwifioptimizer
   mv ~/.local/share/unifiwifioptimizer/config.yaml ~/.config/unifiwifioptimizer/config.yaml
   chmod 600 ~/.config/unifiwifioptimizer/config.yaml
   ```

   (With `XDG_CONFIG_HOME` set, use `$XDG_CONFIG_HOME/unifiwifioptimizer/` instead; the notice 0.5.0 prints names the exact target.)

   If you ran 0.4.x from a git clone instead, your `config.yaml` (and an edited `profiles.yaml`) is in the clone: move it the same way, because 0.5.0 never looks in the working directory. If you edited `profiles.yaml`, copy it next to the new `config.yaml` as well and port it to the new schema: `group_rekey` is `group_rekey_s`, `security_protocols` and `pmf` are lists of accepted values, and every profile must set `roaming_assistant` and `band_steering`. A profile in your file replaces the shipped one whole, so starting from `unifiwifioptimizer config --profiles` and re-applying your edits is simplest. As long as the new location holds no file, 0.5.0 still reads `~/.local/share/unifiwifioptimizer/config.yaml` and says so; until you `chmod 600` it, every command that reads it stops with exit code 3. A `profiles.yaml` in that directory is never read.
2. **Remove 0.4.x**: run `unifiwifioptimizer-uninstall`, or delete `~/.local/bin/unifiwifioptimizer` and `~/.local/bin/unifiwifioptimizer-uninstall` yourself. `uv tool install` and `pipx` do not overwrite a command they did not create.
3. **Install 0.5.0** as described above.
4. **Adjust the configuration**:
   - A site with `ssh.user` but no `ssh.password` is an error now, and it makes every command that reads the file fail with exit code 3. Fix this first: add `auth: key` (your key or agent) or `auth: controller` (the controller-managed credentials). `user` plus `password` keeps working as password login.
   - A controller with a self-signed certificate now fails with exit code 4. Run `unifiwifioptimizer controller-fingerprint --url <controller url>`, compare the result with the controller's certificate view, and set `controller.cert_fingerprint` (or `controller.ca_cert`).
   - The `ROAM_OFFSET_DB`, `ROAM_MARGIN_DB`, `ROAM_FLOOR` and `ROAM_CEILING` environment variables are replaced by `rf.roam_offset_db`, `rf.roam_margin_db`, `rf.roam_floor_dbm` and `rf.roam_ceiling_dbm`. The floor and ceiling defaults moved from −78/−67 dBm to −75/−65 dBm, and both now bound the client-side trigger before it is converted to the uplink value UniFi applies ([docs/ALGORITHM.md](https://github.com/jtauschl/unifiwifioptimizer/blob/main/docs/ALGORITHM.md) §7), so re-derive a value you had tuned instead of copying it. See [Configuration](https://github.com/jtauschl/unifiwifioptimizer#configuration).
   - Boolean values in YAML are `true` and `false` only; `yes`, `no`, `on` and `off` are plain strings.
   - A U6 Lite needs `ssh.scan_interface_toggle: true`; the toggle is off by default now.
5. **Trust the access points' host keys once**: `unifiwifioptimizer trust-host-keys --site <site-id>`. A scan refuses an access point whose key it does not know.

## Workflow

For a complete step-by-step example, see [docs/WALKTHROUGH.md](https://github.com/jtauschl/unifiwifioptimizer/blob/main/docs/WALKTHROUGH.md).

1. In the UniFi Network Application (web UI), enable `Device SSH Authentication` and create a UniFi Network API key for an account with the full Administrator role.
2. If the controller has its factory certificate, get the fingerprint first and compare it with the controller's certificate view:

   ```bash
   unifiwifioptimizer controller-fingerprint --url https://unifi.example.com
   ```

   Then create the configuration file. `init` asks for the controller URL, the API key and the certificate fingerprint (empty for a certificate that chains to a public root), and writes `~/.config/unifiwifioptimizer/config.yaml` with mode `0600`. It never overwrites an existing file:

   ```bash
   unifiwifioptimizer init
   ```

3. Discover the available site IDs:

   ```bash
   unifiwifioptimizer sites
   ```

4. Verify that you selected the correct site:

   ```bash
   unifiwifioptimizer site <site-id>
   ```

5. Generate a site skeleton and append it to the configuration file, below `sites:`:

   ```bash
   unifiwifioptimizer config <site-id> >> ~/.config/unifiwifioptimizer/config.yaml
   ```

6. Complete `environment`, `wlans`, and `neighbors`, then run the controller-side analysis, which needs no SSH access:

   ```bash
   unifiwifioptimizer run --no-scan
   ```

7. Store the access points' SSH host keys once, then run the full analysis:

   ```bash
   unifiwifioptimizer trust-host-keys --site <site-id>
   unifiwifioptimizer run
   ```

   `trust-host-keys` asks per access point before it stores a key. `--yes` skips the question for a key that matches a configured pin or the fingerprint the controller reports; `--accept-unverified` skips it for a key nothing can verify (trust on first use). Without a terminal it declines every question it would ask, so only keys covered by `--yes` or `--accept-unverified` are stored; a declined key does not change the exit code. It exits 5 when an access point failed (a key that does not match or differs from the stored one, a public address, a failed key scan); a name that is not on the controller is reported and exits 0.

8. If you want a controller baseline first, let UniFi handle channel planning (for example Channel AI).
9. Fix per-WLAN profile deviations first.
10. Apply the per-AP RF recommendations that make sense for your site.
11. Re-test with real clients.

## Commands

```text
unifiwifioptimizer [--version] [--config-file PATH] [--dump-api DIR] [--profiles-file PATH] <subcommand>
```

| Subcommand | Purpose |
|---|---|
| `run [--site ID]... [--json] [--no-scan] [--clients] [--known-hosts PATH]` | analyse every configured site (or the listed ones) and print recommendations |
| `sites` | list the sites the controller exposes |
| `site <site>` | show one site's access points and WLANs |
| `config <site>` / `config --profiles` | print a configuration skeleton for a site, or the effective WLAN profiles |
| `init` | create the configuration file interactively; never overwrites an existing one |
| `controller-fingerprint [--url URL]` | print the controller's TLS certificate fingerprint for pinning |
| `trust-host-keys --site ID [--ap NAME]... [--yes] [--accept-unverified] [--known-hosts PATH]` | record the access points' SSH host keys after verifying them |

Global options go before the subcommand: `--config-file PATH` selects the configuration file, `--profiles-file PATH` your own WLAN profiles, and `--dump-api DIR` writes what was read from each endpoint (models only, secrets masked) into `DIR` for the commands that read the controller; `DIR` must be yours and closed to others (`chmod 700`), or the command stops with exit code 3.

### Running the analysis

```bash
unifiwifioptimizer run                    # every configured site: snapshot, neighbour scans, report
unifiwifioptimizer run --site default     # one configured site (repeatable)
unifiwifioptimizer run --no-scan          # controller side only: WLAN checks, channel checks, airtime
unifiwifioptimizer run --clients          # add the associated clients per radio (signal counts, no identities; scanned radios only)
unifiwifioptimizer run --json             # one JSON document for every site (`schema_version` 1)
```

`--no-scan` is the natural first run: it needs no SSH access and no stored host keys. A scanning run needs `trust-host-keys` first and OpenSSH 8.4 or newer on the host. By default scans run site after site and access point after access point (`ssh.scan_concurrency` allows more at once); an access point the controller reports as disconnected is not contacted.

Each site report provides the values you use as the basis for your UniFi WLAN and access point configuration:

- **Environment**: the site-wide RF target corridor derived from the configured environment
- **WLAN**: per-SSID profile checks that show which settings already match and which should be corrected, including the Roaming Assistant target aggregated across the APs broadcasting that WLAN
- **Access Points**: neighbor RSSI (with the reason for every missing reading), overlap or coverage issues, and per-radio recommendations for transmit power and minimum RSSI
- **Adjacency Groups**: group-level diagnostics — missing peer sightings per direction, spectral overlap between adjacent APs, and whether the group can be coloured with the channels available

Client counts appear only for radios that receive a Minimum RSSI recommendation: configured neighbours, scanned, not offline and not in DFS wait. `run --no-scan --clients` therefore shows none.

Apply the relevant changes in UniFi Network, run the tool again, and use the updated output to iteratively converge on a better result.

### Exit codes

Part of the public contract; scripts may branch on them.

| Code | Meaning | When |
| --- | --- | --- |
| 0 | ok | report printed, nothing missing |
| 1 | unexpected error | anything the tool did not foresee, incl. a controller endpoint that fails |
| 2 | usage | bad command line |
| 3 | configuration | file, key or site problem; the scan password missing; a configured access point name two controller devices share — all before the first SSH connection |
| 4 | TLS | the controller connection was refused by the TLS policy |
| 5 | host keys | `run`: a scanning site had no verifiable access point and a host key (unknown or mismatched) was the reason; run `trust-host-keys`. `trust-host-keys`: an access point could not be handled |
| 6 | partial | the report exists, but a finding says what is missing: an access point unparsable, not on the controller or sharing its name with another, a scan that failed, a band that was empty, failed or down |
| 7 | environment | `ssh` missing or older than 8.4 (checked right after the configuration is read, before the scan password check, only when a site scans) |
| 130 | interrupted | Ctrl-C |

Code 5 is narrower than "no access point verified": a site whose every scan timed out is a partial result (6), not a host-key problem.

## Configuration

The configuration file is `$XDG_CONFIG_HOME/unifiwifioptimizer/config.yaml` (usually `~/.config/unifiwifioptimizer/config.yaml`), or the path you give with `--config-file`. The working directory is never searched. The file must be a regular file that only you can read (mode `0600`) in a directory that is not writable by others; the tool refuses anything else. The WLAN profiles ship inside the package (`unifiwifioptimizer config --profiles` prints them); a `profiles.yaml` next to the configuration file in use, or `--profiles-file`, extends or replaces them.

Two environment variables can replace secrets in the file; the tool removes them from its environment as soon as it has read them:

- `UNIFI_API_KEY` — used when `controller.api_key` is not set.
- `UNIFI_SSH_PASSWORD` — used by every site in `auth: password` mode that has no `ssh.password`.

Starter files: [config.minimal.yaml](https://github.com/jtauschl/unifiwifioptimizer/blob/main/config.minimal.yaml) (controller only) and [config.example.yaml](https://github.com/jtauschl/unifiwifioptimizer/blob/main/config.example.yaml) (every key, with defaults and ranges).

```yaml
controller:
  url: https://unifi.example.local
  api_key: ...
  cert_fingerprint: "SHA256:..."

sites:
  default:
    ssh:
      auth: controller

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

Keys (every key not listed is an error):

<!-- config-keys:start -->
| Key | Description |
|---|---|
| `controller.url` | Base URL of the UniFi Network application (`https://host[:port]`) |
| `controller.api_key` | API key for all read-only controller requests; or `UNIFI_API_KEY` |
| `controller.ca_cert` | Absolute path (or `~/...`) of a CA file that signed the controller's certificate; not together with `cert_fingerprint` |
| `controller.cert_fingerprint` | SHA-256 fingerprint of the controller's certificate (pin), from `controller-fingerprint`; not together with `ca_cert` |
| `controller.timeout_s` | Seconds per controller request, 1..120, default 15 |
| `sites.<site>.ssh.auth` | `controller`, `key` or `password`; left out, it is `controller` when the `ssh` section sets no `user`, `password` or `key_file`, and `password` when it sets `user` and `password`; see below |
| `sites.<site>.ssh.user` | SSH user name; required for `key` and `password`; for `controller` it must match the controller's own SSH user if set |
| `sites.<site>.ssh.password` | SSH password for `auth: password`; omit to use `UNIFI_SSH_PASSWORD` |
| `sites.<site>.ssh.key_file` | Absolute path (or `~/...`) of your private key for `auth: key`; omit to use your ssh-agent |
| `sites.<site>.ssh.host_keys` | Pins the host key of an access point: lower-case MAC -> `SHA256:...` fingerprint |
| `sites.<site>.ssh.scan_interface_toggle` | `true` lets the scan bring a scan interface that is down up and put it down again; default `false` |
| `sites.<site>.ssh.allow_public_ap_addresses` | `true` allows access points with a public address; default `false` |
| `sites.<site>.ssh.scan_concurrency` | Access points scanned at the same time, 1..8, default 1 (see [docs/ALGORITHM.md](https://github.com/jtauschl/unifiwifioptimizer/blob/main/docs/ALGORITHM.md) §2) |
| `sites.<site>.ssh.scan_attempts` | Consecutive `iw scan` runs per band in one connection, 1..5, default 2 |
| `sites.<site>.environment` | RF environment preset (case-insensitive) or custom path-loss exponent used to derive the TX corridor; default `Residential` |
| `sites.<site>.scan_passes` | Round-robin scan passes per run, 1..10, default 1; the readings are aggregated as the median, so 3 or more passes outvote a single outlier |
| `sites.<site>.wlans` | Maps UniFi WLAN names to profile names |
| `sites.<site>.neighbors` | AP-to-AP neighbor model; names must match UniFi device names exactly (case-sensitive) |
| `rf.noise_floor_dbm` | Receiver noise floor, default -92 |
| `rf.required_snr_db` | SNR required at the cell edge, default 25 |
| `rf.client_tx_dbm` | Typical client transmit power for the uplink conversion, default 15 |
| `rf.min_rssi_offset_db` | Distance of Minimum RSSI below the roaming trigger, default 5 |
| `rf.roam_offset_db` | Shift of the Roaming Assistant threshold, default 0 |
| `rf.roam_margin_db` | Margin of the Roaming Assistant threshold below a weak neighbour, default 5 |
| `rf.roam_floor_dbm` | Lowest roaming trigger, default -75; must be below the ceiling |
| `rf.roam_ceiling_dbm` | Highest roaming trigger, default -65 |
<!-- config-keys:end -->

`ssh.auth` decides where the access-point credentials come from:

| `auth` | Credentials | Needs |
|---|---|---|
| `controller` | the SSH credentials the controller manages for its access points | an API key with the full Administrator role; `Device SSH Authentication` enabled |
| `key` | your own key or agent | `user`; optionally `key_file`; no `password` |
| `password` | a password | `user` and a password in the file or in `UNIFI_SSH_PASSWORD`; no `key_file` |

Notes:

- Use the UniFi site ID as the key under `sites:`. `sites` lists the available site IDs from the controller, `site <site-id>` shows WLANs and access points for that site (an unambiguous site description works too), and `config <site-id>` prints a skeleton for it.
- Without `ca_cert` or `cert_fingerprint` the controller's certificate must chain to a public root. The factory certificate does not; pin it.
- A scanning site needs an `ssh` section; `ssh: {}` is enough for `auth: controller`.
- The skeleton's empty neighbour lists are a template: a site scans only when at least one neighbour pair is listed.

Environment presets:

- `Open`: large open spaces, retail, low attenuation
- `Residential`: homes and apartments
- `Office`: typical office floorplans
- `Obstructed`: concrete, brick, multi-wall layouts
- custom value: typical practical values are around `2.0` to `4.0`

For environment details, see [docs/ALGORITHM.md](https://github.com/jtauschl/unifiwifioptimizer/blob/main/docs/ALGORITHM.md).

Profile presets:

- `Standard`
- `IoT`
- `Hotspot`
- `Throughput`
- `Latency`

For profile details, see [docs/PROFILES.md](https://github.com/jtauschl/unifiwifioptimizer/blob/main/docs/PROFILES.md).

## Security Notes

- **TLS is always verified.** There is no switch to turn it off. A self-signed controller certificate is accepted only when you pin its fingerprint (`controller.cert_fingerprint`) or give its CA (`controller.ca_cert`).
- **SSH host keys are always verified.** The tool keeps its own `known_hosts` (`$XDG_STATE_HOME/unifiwifioptimizer/known_hosts`), a scan never adds a key, and `trust-host-keys` is the only way to store one.
- **Secrets stay out of arguments, logs and temporary files.** The SSH password reaches `ssh` only through `SSH_ASKPASS`; the configuration file must be private (`0600`).
- The tool performs `GET` requests against the controller and no write; on an access point it runs one scan script and, only with `scan_interface_toggle: true`, brings a scan interface up and down.

The threat model, the trust boundaries and the release verification are in [SECURITY.md](https://github.com/jtauschl/unifiwifioptimizer/blob/main/SECURITY.md).

## Scope and Limits

Designed for homelabs, homes, apartments, and small to medium offices with manually managed UniFi deployments and known AP neighbor relationships.

Does not replace AP placement, channel planning, site surveys, capacity planning, or client-side validation.

## References

- Ubiquiti: [UniFi WiFi SSID and AP Settings Overview](https://help.ui.com/hc/en-us/articles/32065480092951-UniFi-WiFi-SSID-level-Settings-Overview)

## Contributing

See [CONTRIBUTING.md](https://github.com/jtauschl/unifiwifioptimizer/blob/main/CONTRIBUTING.md) for the local workflow (`./dev ci` gate, commit conventions) and PR expectations. Questions go to [GitHub Discussions](https://github.com/jtauschl/unifiwifioptimizer/discussions); bugs and feature requests to [GitHub Issues](https://github.com/jtauschl/unifiwifioptimizer/issues).

### What runs where

- **Locally, before every push:** `./dev ci` is the full gate: shellcheck/shfmt/`bash -n` over every shell script, actionlint, gitleaks, ruff, mypy, bandit, unit tests under the coverage floor, integration tests against the Docker harness, the per-layer coverage report over both, the lower-bound dependency probe, lockfile and build-constraint checks, the runtime license gate, and a build with a content check plus a wheel smoke test. The maintainer runs it through a machine-wide git `pre-push` hook (`git config --global core.hooksPath`); a fresh clone without that hook runs nothing automatically, and `git push --no-verify` bypasses it.
- **In CI, on every push and pull request:** Semgrep SAST and an SBOM job (CycloneDX of the shipped dependency graph, stamped with the project version). On a pull request only, a Linux job additionally re-runs `./dev ci` for contributors whose clone has no hook. Weekly, `security.yml` runs gitleaks over the full history and `pip-audit` over the locked graph and the build backend. The local and hosted sets overlap; neither is a superset of the other.
- **On a release tag:** `release.yml` runs the same gate once more, builds the sdist and wheel, writes the SBOM and build-provenance attestations, publishes to PyPI through trusted publishing and creates the GitHub Release. A push to a release branch that touches a file the release build depends on dry-runs the gate, build and SBOM jobs.

## Security

Report suspected vulnerabilities privately — see [SECURITY.md](https://github.com/jtauschl/unifiwifioptimizer/blob/main/SECURITY.md). Do not open a public GitHub issue for a suspected vulnerability.

## License

MIT — see [LICENSE](https://github.com/jtauschl/unifiwifioptimizer/blob/main/LICENSE).
