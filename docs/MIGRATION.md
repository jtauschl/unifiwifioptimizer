# Migrating from 0.4.x to 0.5.0

Every breaking change of 0.5.0 with what changed and what to do. The order of the steps for the move itself
(configuration first, then uninstall, then install) is in "Upgrading from 0.4.x" in the
[README](../README.md#upgrading-from-04x). The changelog entry of each change links here.

## TLS certificates

0.4.x ran `curl -k`. 0.5.0 always verifies the controller's certificate and has no switch to turn that off. A
controller that still has its factory (self-signed) certificate now fails with exit code 4.

1. Run `unifiwifioptimizer controller-fingerprint`.
2. Compare the result with the certificate view in the controller.
3. Set `controller.cert_fingerprint` to it, or set `controller.ca_cert` to the CA that signed the certificate.

## SSH host keys

0.4.x ran `StrictHostKeyChecking=no`. 0.5.0 refuses an access point whose key it does not know and never stores
one while scanning.

Run `unifiwifioptimizer trust-host-keys --site <site-id>` once per site. A key is accepted against a pin in
`ssh.host_keys`, against the fingerprint the controller reports, or, only with your confirmation or
`--accept-unverified`, on first use.

## Installation

The tool installs as a Python package: `uv tool install unifiwifioptimizer` or `pipx install unifiwifioptimizer`.
The Bash tool, `install.sh`, `uninstall.sh`, the Ruby dependency and `sshpass` are gone. Python 3.11 and OpenSSH 8.4
are required.

If you installed 0.4.x with `install.sh`, move your configuration and any edited `profiles.yaml` first: the 0.4.x
uninstaller deletes the directory they live in. If you ran the tool from a clone, move them out of the clone. Then
uninstall 0.4.x and install the package.

## Command line

The analysis is `unifiwifioptimizer run`; a bare call no longer runs it. `--sites`, `--site` and `--config` became
the subcommands `sites`, `site` and `config`. Exit codes follow the table in the README, and usage errors are 2, not 1.

Update scripts and cron entries.

## Configuration file

The file is `$XDG_CONFIG_HOME/unifiwifioptimizer/config.yaml` (usually `~/.config/unifiwifioptimizer/config.yaml`)
or the path given with `--config-file`; the working directory is never searched.

The location of the 0.4.x installer, `~/.local/share/unifiwifioptimizer/config.yaml`, is still read, with a notice,
as long as the new location has no file. The 0.4.x installer did not make the file private, so until you
`chmod 600` it, every command that reads it stops with exit code 3. The file must be a regular file you own with
mode `0600` or stricter, in a directory others cannot write to; anything else is an error.

Move the file to the new location and `chmod 600` it.

## Roaming variables

`ROAM_OFFSET_DB`, `ROAM_MARGIN_DB`, `ROAM_FLOOR` and `ROAM_CEILING` are replaced by `rf.roam_offset_db`,
`rf.roam_margin_db`, `rf.roam_floor_dbm` and `rf.roam_ceiling_dbm` in the configuration file. Set the keys you used.

The floor and ceiling defaults moved from −78/−67 dBm to −75/−65 dBm, and both now bound the client-side trigger
before it is converted to the uplink value UniFi applies (`docs/ALGORITHM.md` §7). Re-derive a value you had tuned
instead of copying it.

## SSH authentication

`ssh.auth` is explicit:

| `ssh` section | Result |
| --- | --- |
| no `user`, `password` or `key_file` | `controller`: the controller-managed credentials |
| `user` and `password` | password login |
| `user` without a password | an error that tells you to set `auth: key` |

Add `auth: key` (or `auth: controller`) to a site that relied on key or agent login without saying so.

## Scan interface toggle

0.4.x brought a scan interface that was down up for the scan on its own and put it down again afterwards. 0.5.0
does that only when you ask for it. Set `ssh.scan_interface_toggle: true` for a site with access points that keep
their scan interfaces down at rest (the U6 Lite). Without it, such a band is reported as `interface_down`.

## Shipped profiles

The shipped profiles are recommendations, not controller-default snapshots, and there are four, grouped by device
class. `docs/PROFILES.md` lists them with every setting; the cause of each deviation is the profile's evidence text
(`unifiwifioptimizer config --profiles`).

- `Standard` (modern clients) carries the values of the former `Throughput`, updated: WPA2/WPA3 (WPA3-only
  accepted) with PMF Optional or Required, 802.11r, 802.11v, Handoff Suggestions and band steering on, a fixed
  minimum data rate of 12 Mbps on both bands (it was 11 Mbps on 2.4 GHz and 24 Mbps on 5 GHz; Cisco recommends
  24 Mbps only for well-designed high-density networks), 802.11b support off, Proxy ARP and multicast-to-unicast on
  (`Throughput` expected multicast-to-unicast off), the controller's DTIM defaults (it expected custom 3/3), a
  3600 s group rekey and SAE anti-clogging 5 (it was 10).
- The 0.4.x `Standard` (WPA2 with PMF off, no 802.11r, Proxy ARP off) is closest to the new `Compat`: 802.11r off,
  automatic minimum rates, WPA2 accepted, PMF optional or off.
- `IoT` expects WPA2 with PMF off or optional (it expected PMF off), no roaming features, no steering, no group
  rekey and the 2.4 GHz channel lock off.
- `Hotspot` expects Enhanced Open (OWE, transition preferred) with plain Open still accepted (it expected Open),
  client isolation, Proxy ARP and Handoff Suggestions on (Proxy ARP follows Ubiquiti's guest guidance), multicast
  filtering off (it expected on) and the mDNS proxy off.

## Profile names

`Throughput` is now `Standard`, and `Latency` is removed: it differed from `Throughput` only by DTIM 1 and U-APSD
on, which do not by themselves lower latency. A WLAN mapped to either name reports "profile is not defined" with a
pointer.

- Change `Throughput` to `Standard` in `wlans:` and review the deviations it now reports.
- For `Latency`, define your own profile with `dtim_mode: custom` and `dtim_24`/`dtim_5` set to 1 (see
  `docs/PROFILES.md`).
- A WLAN that matched the old `Standard` belongs on `Compat`.

## Profile file

`profiles.yaml` ships inside the package; the file next to the executable is no longer read. Put local adjustments
in a `profiles.yaml` next to the configuration file in use (never the legacy data directory, where the copy of the
0.4.x installer stays unread), or pass `--profiles-file`.

## Profile keys

- `security_protocols` and `pmf` are lists of accepted values; a plain string is refused.
- `group_rekey` became `group_rekey_s`.
- `multicast_broadcast_blocker` became `multicast_suppressor_mode` (`off`, `conservative` or `aggressive`; the
  controller's Multicast Suppression).
- `roaming_assistant` and `band_steering` are required in every profile of an override file, which replaces a shipped
  profile whole.

## 6 GHz radios

A 6 GHz radio is its own band and is reported as not evaluated. 0.4.x had no 6 GHz band and could take a lone `6e`
radio for the 5 GHz one.

No action: the 2.4 GHz and 5 GHz radios of the same access point are still analysed.

## YAML booleans

YAML booleans are `true` and `false` only; `yes`, `no`, `on` and `off` are plain strings, so
`dns_assistance_mode: off` stays the text `off`. A 0.4.x `config.yaml` has no such values.

In a hand-written `profiles.yaml`, write `true` or `false` on a yes/no key; `yes`, `no`, `on` and `off` there are refused
with exit code 3. A mode such as `dns_assistance_mode: off` needs no change.

## Recommendation basis

The recommendations changed their inputs, so the numbers differ from 0.4.x on the same site:

- Transmit power rests on the effective power (`radio_table_stats.tx_power`), not the configured one.
- The weakest configured neighbour decides, not the mean; the missing-peer +1 dB nudge is gone.
- A zero sighting raises to the maximum only after a miss in both directions with working scans.
- Readings are the median over passes on the peer's channel.

No configuration change is needed. Treat 0.4.x results as obsolete and read the first 0.5.0 report as a fresh
baseline (`docs/ALGORITHM.md` has the derivation).

## Channel and roaming checks

- The colouring check replaces the 60/320 MHz width budgets and the "more than three 2.4 GHz peers" rule.
- Roaming Assistant is read from the WLAN only; 0.4.x read it per radio. On a controller without the WLAN-level field
  the check reports the older API instead of a verdict.
- An enabled Minimum RSSI is no longer flagged by itself: it is a change only when it differs from the value to set
  (the derived value moved into the controller's range; a setting at that end counts as confirmed). On a 5 GHz radio
  an advisory appears when the disconnect would fire before a neighbour can take over (`docs/ALGORITHM.md` §6).

No configuration change is needed.

## Output and failures

- The report is plain text without the 0.4.x colour codes in files and pipes; the check marks are coloured only on a
  terminal. Use `--json` where a script reads the result.
- 0.5.0 reads `apgroups`, `networkconf`, `usergroup` and `setting` in addition to the endpoints 0.4.x read. A failing
  endpoint aborts the run with exit code 1; the error text names it. Fix the cause, then run again.
