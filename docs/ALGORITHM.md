# Algorithm

This document describes the RF model behind `UniFi WiFi Optimizer`: the design target, the derivation of
the corridor, and how AP-to-AP neighbour readings become recommendations for transmit power, Minimum RSSI
and the Roaming Assistant (Handoff Suggestions) threshold. Every rule names its source; a value that has
no standard behind it is a documented tunable, never a hidden constant.

WLAN profile checks (docs/PROFILES.md) sit next to this model and do not influence it.

## 1. Design Goal

The best client experience, grounded in standards. The tool uses AP-to-AP neighbour RSSI as a proxy for
cell overlap:

- **Transmit power** moves the weakest configured neighbour's reading of an AP into a corridor derived
  from the cell edge.
- **Roaming Assistant** is a WLAN-level threshold, aggregated conservatively over the APs that broadcast
  the WLAN, converted to the uplink the controller evaluates.
- **Minimum RSSI** sits a margin below the roaming trigger, on the uplink as well.

## 2. Data Sources

1. **UniFi API** — radio settings (channel, width, configured power and mode, limits, Minimum RSSI),
   radio statistics (channel in use, effective power, utilisation, retries, state), VAP BSSIDs, WLAN
   settings (Roaming Assistant per WLAN), AP groups, Channel AI settings, optionally the associated
   clients.
2. **SSH** — AP-to-AP neighbour BSS scans on 2.4 and 5 GHz, several passes per run.

A pass is one SSH call per access point; passes run round-robin over the site's access points so the
readings of one pass are close in time. Within a site the access points are scanned one after the other:
an access point in an off-channel scan sends no beacons, so two neighbours scanning at the same moment
systematically miss each other. Per band, the remote script repeats `iw scan` (`scan_attempts`) and
merges the attempts by the strongest reading per BSSID; the passes are then aggregated as the **median**
of the readings taken on the peer's **current primary frequency**: a reading on another
channel predates a channel move and is not comparable, and a maximum over 2–4 noisy samples is biased
1–3 dB high while the median is unbiased. 6 GHz radios are detected and reported, not evaluated.

## 3. Neighbour Evaluation

For a configured pair (A, B) and band the matrix holds **A at B**: the RSSI of A's beacons measured by
B's scan. This is the only direction A's transmit power moves. The statistic per radio is the **weakest
configured neighbour** — a design choice, not Cisco's method: Cisco's TPC (version 1) judges the *third* loudest
neighbour against a −70 dBm threshold, with 6 dB hysteresis for a decrease and 3 dB for an increase (Cisco RRM white
paper). Like any order statistic the weakest neighbour avoids the mean, which hides one overlap next to one gap.

A cell without a reading names why, most fundamental reason first: scan skipped, this AP offline, the peer
offline, the peer unknown to the controller, this AP in its DFS channel-availability check, the peer in
its check, the peer without a scan interface on the band, the peer's interface down, the peer's scan failed,
the peer's scan empty, no DFS evidence (A sits on a DFS channel and the peer's passive scan heard nothing
on any DFS channel), or simply not sighted.

**Reciprocity.** The path loss is the same in both directions; only the transmit powers differ. When B
did not hear A but A heard B, `A at B ≈ (B at A) + P_A − P_B` substitutes the missing reading and is
marked as predicted. It is not applied when A itself could not have been heard (offline, in its DFS
check), when the peer is unknown, or when the peer is offline (a reading of an offline radio is stale).

**Receiver offset.** When both directions were measured, `(A at B) − (B at A) − (P_A − P_B)` is the two
receivers' disagreement. It is carried per pair; at 5 dB or more (IEEE 802.11 RCPI accuracy is ±5 dB per
receiver) the report says so, because every AP is then judged by the other chipset's receiver.

## 4. Transmit Power

### Effective power and the effective maximum

The radio's **effective** power (`radio_table_stats.tx_power`) is the basis; the configured value is only
read in Custom mode. A radio under Custom whose effective power lies below the configured one has hit a
cap — the regulatory EIRP limit of the channel group minus the antenna gain (Germany, wireless-regdb and
EN 301 893: 23 dBm EIRP on 5150–5250 MHz; on 5250–5350 MHz 23 dBm with TPC and 20 dBm without; on 5470–5725 MHz
30 dBm with TPC and 27 dBm without; a U7 Lite with its 5 dBi antenna at 23 dBm EIRP is 18 dBm conducted,
live-verified on channels 40 and 60) — and the effective power is then the **verified** maximum — as it is when the
radio runs at the configured maximum itself. A maximum verified on one channel group does not carry over to
another. In every other case the configured radio maximum is the maximum, **unverified**: nobody has shown
the radio reaching it on this channel, and an increase above the demonstrated power is marked as unverified
headroom.

### Corridor test and decision table

One `recommend_tx` evaluation per radio: inside the corridor nothing changes; otherwise the shift that
moves the weakest reading to the corridor centre is applied and clamped to the radio's range, and a
reduction smaller than 3 dB is dropped (hysteresis against reading noise; an integer reading outside a
6 dB corridor already demands at least 4 dB, so the rule bites only at the clamp). The outcome of a radio
is the first matching row:

| # | Condition | Outcome |
| --- | --- | --- |
| 1–3 | scan skipped; AP offline; radio in its DFS channel-availability check | nothing judged (the DFS case says how long to wait: 60 s, 600 s on channels 120–128) |
| 4 | effective power, minimum or maximum missing, or the effective power outside the radio's own range | not evaluable, no defaults |
| 5 | no configured neighbour on the band | nothing |
| 6 | a neighbour missed in **both** directions with working scans | below the maximum: raise to the maximum; at the maximum: coverage gap, structural |
| 7 | no evaluable neighbour at all | not evaluable; every neighbour named with its reason |
| 8 | weakest inside the corridor, every neighbour evaluable | confirmed |
| 9 | weakest inside the corridor, a neighbour unevaluated | no change, not fully evaluated |
| 10 | corridor out of reach upwards, radio at its effective maximum | **coverage gap**: hand-off happens below the edge, add an access point or accept |
| 11 | corridor out of reach upwards, radio below its maximum | raise to the maximum; a neighbour still below the corridor after the raise (`*`) is a coverage gap too |
| 12 | weakest still above the corridor at the radio minimum | **too strong at the minimum**: reposition, disable the band on a middle AP, or accept; the reduction to the minimum is still recommended |
| 13 | otherwise | the clamped shift |

The weakest evaluable reading is an upper bound of the true weakest, so an **increase** is safe while a
neighbour is unevaluated; a reduction, a confirmation or a "too strong" verdict is not, and the report
names the unevaluated neighbours instead. A radio carrying a wireless uplink (child or parent) never
gets a reduction.

### Zero sightings

The maximum is recommended only after a miss in **both** directions with scans that demonstrably worked
(the peer saw other networks). A one-way miss is substituted by reciprocity; a miss with a failed, empty
or down scan is not evaluable. A radio already at its maximum and still unsighted is a structural finding:
reposition or add an access point, never "raise" again on every run.

### Per-neighbour markers

- `°` below the corridor before the change, inside it after;
- `*` below the corridor even after the change (coverage), or above the corridor even at the minimum.

## 5. Corridor Derivation

The cell edge is derived: `edge = noise_floor + required_snr`, by default −92 dBm + 25 dB = −67 dBm. These are
Cisco's figures for **voice** deployments, measured at the client (document 116057: a minimum SNR of 25 dB, −67 dBm
at a noise level of −92 dBm, and for voice "at least two APs heard at −67 dBm"), a design target and not a general
standard. A cross-check: thermal noise over 20 MHz is kTB ≈ −101 dBm, a receiver noise figure of about 9 dB gives
−92 dBm, and IEEE 802.11-2020 Table 17-18 lists −65 dBm minimum sensitivity for 64-QAM 3/4, about 26 dB SNR once a
noise figure and an implementation margin are assumed — close to Cisco's 25 dB. Applying the figure to AP-to-AP
beacon readings instead of client measurements is this tool's proxy (§10). Both inputs are tunables
(`rf.noise_floor_dbm`, `rf.required_snr_db`).

**5 GHz** (the roaming band): the secondary-coverage rule — every point served by two access points at or
above the edge — has its worst point for the second-strongest signal at an access point's own location,
so the neighbour must hear this AP at the edge there: `TX_LO = edge`, independent of the environment.

**2.4 GHz**: three non-overlapping channels make full overlap harmful, so the corridor starts lower by the
extra path loss from 60 % of the AP distance to the full distance (the one-dimensional reading of "about
20 % overlap"; two equal cells overlap only about 8 % of their area at that distance):

```text
Δ     = 10 · n · log₁₀(100 / 60)
TX_LO = edge − Δ
TX_HI = TX_LO + 6
```

| Preset | n | Δ | 2.4 GHz corridor | ITU-R P.1238-10 |
| --- | --- | --- | --- | --- |
| `Open` | 2.2 | 4.88 | −72 … −66 | "about 20" for large open rooms; 22 is the commercial value of the 1.25/1.9/4 GHz rows (no 2.4 GHz commercial entry) |
| `Residential` | 2.8 | 6.21 | −73 … −67 | Table 2, 2.4 GHz residential 28 *(default)* |
| `Office` | 3.0 | 6.66 | −74 … −68 | Table 2, 2.4 GHz office 30 |
| `Obstructed` | 4.0 | 8.87 | −76 … −70 | body text "about 40" |
| `<number>` | x | — | — | custom n |

The 60 % reading, the corridor width of 6 dB and the presets are this tool's design: ITU-R P.1238 supplies the
table values for residential and office at 2.4 GHz, and the Open and Obstructed values come from its text. The corridor
width of 6 dB is a tolerance for normal variation; the presets are second-order (2.2 dB per
unit of n, at most 1.3 dB between bands), which is why one site-wide `environment` suffices.

## 6. Minimum RSSI

The controller evaluates Minimum RSSI on the client's **uplink** as received by the AP. The target is
derived on the downlink (the corridor floor minus `rf.min_rssi_offset_db`, default 5 dB: a design choice for the
gap between the soft-roam trigger and the hard disconnect; no source gives this value) and converted by link
reciprocity, `RSSI_up − RSSI_down = P_client − P_AP`, with a typical client power (`rf.client_tx_dbm`,
default 15 dBm, a typical phone figure without a standard behind it, a tunable):

```text
min_rssi_uplink = (TX_LO − offset) − (P_AP_effective − P_client)
```

On 2.4 GHz, where access points often run 6 dBm against clients at 15–20 dBm, the uplink is 9–14 dB
stronger than the downlink; without the conversion a Minimum RSSI never fires usefully there.

The controller accepts −90 to −67 dBm for Minimum RSSI (verified on U6 Lite and U7 Lite, both bands). A derived
value outside that range moves to the nearer end, and the report names the derived value next to it. An
enabled Minimum RSSI set to that end counts as confirmed.

Ubiquiti's own guidance is more cautious than the derived values: "It's safe to say -80dBm would be a starting
point for standard home or office configurations" (Understanding and Implementing Minimum RSSI), and its SSID
settings overview calls the hard kick "generally not recommended unless running a high density deployment".

Enabling it is a deployment choice: a disabled Minimum RSSI is reported as the value to use if it is
switched on, never as a pending change; enabled at the derived value it is confirmed, elsewhere it is a
change. An enabled Minimum RSSI on a 5 GHz radio with a coverage gap, or whose roaming trigger lies below
the Minimum RSSI target, gets an advisory: the disconnect would fire before any neighbour can take over.
The comparison is between the recommended values at the radio's current effective power — the WLAN
threshold of §7 and the Minimum RSSI value to set (moved into the controller's range where needed), converted back
to the downlink — not the values configured today; a pending
transmit-power change moves the trigger on the downlink. "Coverage gap" here means rows 6 (at the maximum)
and 10 of §4 and any neighbour marked `*` below the corridor. The trigger compared is the WLAN's threshold
as this radio sees it on the downlink — the controller applies one uplink value per WLAN (§7), so at an access
point whose own derived value lies above it, it fires at a weaker signal than that derived value would, and at one
whose derived value lies below the controller's range, at a stronger signal.

## 7. Roaming Assistant

> **Terminology note:** since UniFi Network Application 10.4.57, the controller UI labels this setting
> "Handoff Suggestions (802.11v)" instead of "Roaming Assistant". The API field (`roaming_assistant_na_*`)
> and this tool's terminology are unchanged. The controller also sends a `roaming_assistant_6e_enabled`
> counterpart (live-verified on 10.6.106); for a WLAN on 6 GHz the compliance check shows it as a separate,
> not evaluable result, because 6 GHz is detect-only.

Roaming Assistant lives on the WLAN (`roaming_assistant_na_enabled`/`_rssi` in `wlanconf`): one value per
SSID, broadcast across the access points its AP groups name (`ap_group_mode: all` means every access point
of the site). The tool reports it as a **compliance check** next to Fast Roaming, with a target aggregated
over the broadcasting access points:

```text
SSID_peers(AP) = configured neighbours(AP) ∩ broadcasting_APs(WLAN), online ones only

for each broadcasting AP with SSID peers:
    weakest   = min(SSID peer readings of this AP at the peer)   # measured or predicted by reciprocity
    downlink  = TX_LO(5 GHz) + ROAM_OFFSET_DB
    if weakest < TX_LO: downlink = weakest − ROAM_MARGIN_DB      # capped by coverage
    downlink  = clamp(downlink, ROAM_FLOOR, ROAM_CEILING)
    uplink    = downlink − (P_AP_effective − P_client)             # what the controller compares against

WLAN target = clamp(min(uplink over the broadcasting APs), ROAMING_ASSISTANT_MIN, ROAMING_ASSISTANT_MAX)
```

`ROAMING_ASSISTANT_MIN` and `ROAMING_ASSISTANT_MAX` are −80 and −60 dBm, the stops of the controller's Handoff
Suggestions slider (observed on Network 10.6.106). A value outside that range cannot be configured: an access
point at 23 dBm on 5 GHz derives −83 dBm from the −75 dBm floor (−75 − (23 − 15)). The report then names the
derived value and the range, the target is the nearer end, and a WLAN set to it passes the check.

Defaults: offset 0 (the trigger sits at the lower corridor edge; Apple's published client scan triggers are
−70 dBm on iPhone/iPad and −75 dBm on Mac, support document 102002 — they start the client's own search for a better
access point and are not a controller threshold), margin 5 dB, floor −75 dBm (the macOS trigger), ceiling −65
dBm (a design choice with no standard behind it: higher would make clients roam while well inside a
cell). All four are tunables under `rf.*`. Every AP whose value equals the minimum is a limiting AP; ties are
all reported.

Ubiquiti describes the mechanism as BSS transition frames that tell a client it will be dissociated once it drops
below the threshold, and suggests a value "below -70 dBm" (UniFi WiFi SSID and AP Settings Overview). A
low-power access point can derive a value above that guidance; the report prints the derived value either way.

Incomplete data never produces a silently optimistic value: a broadcasting AP without a configured neighbour
that also broadcasts the WLAN, a missing peer reading, an unresolvable AP group or a group member that is
not an access point of the site mark the WLAN `Incomplete` with the reason, and no threshold is passed to the
check. A WLAN not broadcasting 5 GHz is `N/A`; a single-AP WLAN has no hand-off target and is `N/A` too.
Whenever a 5 GHz transmit-power change is pending on a broadcasting AP, the report notes that the threshold
follows the effective power — apply the power change first.

The `roaming_assistant` profile field decides only whether the assistant is expected **enabled**; the
threshold itself is never profile-driven. The check's expectation carries the derived threshold whenever the
analysis produced one (`Enabled, -78 dBm`), also when the assistant is off or the controller reports no value,
so the report always shows the value to set. There is no per-radio fallback: a controller without the WLAN-level
field gets an `Incomplete` check that says so.

## 8. Channel Checks

Geometry in use always comes from the radio statistics (a radar move takes a fixed radio elsewhere; a
configured channel that differs from the one in use is reported). Two graphs over the site's access
points: the configured adjacency, and the **heard graph** — own access points whose median reading of each
other is at or above −82 dBm, the IEEE 802.11 CCA level at which an OFDM receiver must defer to a 20 MHz
transmission (equal to the 6 Mb/s minimum sensitivity of Table 17-18). The level is the one for the primary 20 MHz
channel; the check applies it to any overlap, including overlap only in a secondary channel, where the standard's
levels differ. It is a simplified contention indicator, not a prediction of what a receiver defers to.

- **Overlap** between configured neighbours (5 GHz: bonded blocks within a UNII range; 2.4 GHz: 20 MHz
  plus a 2 MHz guard, this tool's choice, so the common 1/6/11 plan stays disjoint; a 40 MHz block follows the secondary channel when the
  controller reports it) is an advisory with the free candidate channels from the controller's own
  candidate list.
- **Co-channel contention** between any two own access points that hear each other at or above the CCA
  level on an overlapping channel is an advisory, configured pair or not.
- **Reuse feasibility**: the component of the union graph (heard ∪ configured) must be colourable with the
  channels available — three on 2.4 GHz, the number of disjoint blocks of the widest width inside the
  candidate set on 5 GHz. The old width budgets (60/320 MHz) are gone. Without a channel list from the controller
  the 5 GHz hints and this check are skipped and the report says so, because the usable 5 GHz channels depend on the
  country.
- **Channel AI**: an auto radio managed by Channel AI is reported, not recommended — Ubiquiti documents it as
  changing channels only ("channel width and transmit power remain unchanged"), and a Channel AI run would overwrite
  channel advice; the layout is an information line ("if this persists across
  runs, pin channels or add exclusions"). An auto radio without Channel AI gets a "pin channels" advisory;
  a fixed radio is always judged. A channel on the Channel AI blacklist is an advisory.
- **40 MHz on 2.4 GHz** covers two of the three non-overlapping channels and is an advisory by itself.
- **DFS**: channels 52–144 (union of the ETSI, FCC and Japanese rules); a radio in its channel availability
  check is skipped with the wait time (60 s, 600 s on 120–128).
- **Foreign networks** are counted per radio (strongest reading, how many overlap the channel in use); no
  foreign name leaves the scan.
- **6 GHz** radios are detected and reported as their own band but not evaluated: no corridor, power or channel
  rule applies to them until a 6 GHz scan model and test hardware exist.

## 9. Airtime and Clients

**Airtime.** Per radio the report shows the channel utilisation, the access point's own receive and transmit
share, the transmit retry rate, the satisfaction score and the client count, as values. No sourced threshold
separates a busy radio from a troubled one, so nothing is judged and no recommendation rests on these figures. A
value the controller marks as absent (satisfaction `-1`) is shown as absent, not as zero.

**Clients** (`--clients`). The associated clients are read as signal strengths only; no MAC address, host name or
IP address is read, kept or printed. Only wireless clients count, and only those whose signal is a plausible
reading (strictly between −100 and 0 dBm) and whose access point and radio the snapshot knows. Per radio the
report shows how many clients there are, the weakest signal, and how many sit below that radio's recommended
Minimum RSSI. The comparison uses the same reference as the controller: the signal an access point measures from
its client, the uplink. Client counts appear only for a radio that receives a Minimum RSSI recommendation: it has
configured neighbours and a known effective power, was scanned, and is neither offline nor waiting for the DFS
channel availability check; with `--no-scan` none appear. Sightings that cannot be placed on a radio (an unknown
access point, no signal) are counted once per site and named as such.

## 10. Model Limits

- AP-to-AP RSSI is a proxy for cell overlap at the neighbour's location, not a client link budget: a
  client transmits with less power than an access point (the `rf.client_tx_dbm` conversion assumes a
  typical phone), loses 1–7 dB to the body, and sits at desk height under a ceiling antenna's elevation
  pattern — effects as large as the whole preset span.
- Beacons are 20 MHz frames at the radio's full target power; 80/160 MHz data at the same total power has
  6/9 dB less power per 20 MHz, and the high MCS rates are backed off and do not follow a reduction until
  the configured power drops below their own target. A reduction shrinks the roaming footprint more than
  the throughput footprint.
- The ITU-R P.1238 model is defined for a base station and a portable terminal; the tool applies it to
  the ceiling-to-ceiling path. The exponent enters only through the 60 % reading on 2.4 GHz, so the error
  is the ceiling-to-client offset, not n.
- MediaTek (U6) and Qualcomm (U7) receivers read the same beacons with systematic offsets of several dB;
  the receiver-offset line makes that visible, the model does not correct it.
- Under automatic power or Channel AI the advice competes with the controller; the report says which
  mode a radio runs in and judges the effective state.
- Off-channel scans interrupt service on the serving radios; run scans off hours.
- The tool sees no non-WiFi interference, no client MCS or retry statistics, no roaming timing, no packet
  captures. Recommendations are static-analysis heuristics, not runtime KPIs.

## References

- **IEEE 802.11-2020**: Table 17-18 (minimum sensitivity, 6 Mb/s −82 dBm), OFDM PHY CCA requirements
  (17.3.10.6), RCPI measurement accuracy (±5 dB), Annex E channel sets
- **ITU-R P.1238-10**: [Propagation data and prediction methods for the planning of indoor radiocommunication systems and radio local area networks in the frequency range 300 MHz to 450 GHz](https://www.itu.int/dms_pubrec/itu-r/rec/p/R-REC-P.1238-10-201908-S!!PDF-E.pdf), Table 2 and §3
- **ETSI EN 301 893** (5 GHz EIRP limits, TPC, channel availability check durations) and the Linux
  `wireless-regdb` (`country DE`)
- **Cisco**: [Site Survey Guidelines for WLAN Deployment](https://www.cisco.com/c/en/us/support/docs/wireless/5500-series-wireless-controllers/116057-site-survey-guidelines-wlan-00.html) — 25 dB SNR, −67 dBm edge, at least two access points heard at −67 dBm, 20 percent cell overlap
- **Apple**: [Wi-Fi roaming for iPhone, iPad and Mac](https://support.apple.com/en-us/102002) — client roaming triggers
- **Ubiquiti**: [Understanding and Implementing Minimum RSSI](https://help.ui.com/hc/en-us/articles/221321728-Understanding-and-Implementing-Minimum-RSSI), the U6 Lite and U7 Lite tech specs (transmit power, antenna gain)
- **Cisco**: [RRM white paper, TPC](https://www.cisco.com/c/en/us/td/docs/wireless/controller/technotes/8-1/mobility_express/b_RRM_White_Paper/b_RRM_White_Paper_chapter_0101.html) — third loudest neighbour, −70 dBm default threshold, 6 dB and 3 dB hysteresis
- **Ubiquiti**: [UniFi WiFi SSID and AP Settings Overview](https://help.ui.com/hc/en-us/articles/32065480092951-UniFi-WiFi-SSID-and-AP-Settings-Overview) (Handoff Suggestions below −70 dBm, Minimum RSSI), [UniFi Channel AI](https://help.ui.com/hc/en-us/articles/37367741854743-UniFi-Channel-AI-and-Automated-WiFi-Optimization)
