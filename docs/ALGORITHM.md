# Algorithm

This document describes the RF model used by `UniFi WiFi Optimizer`.
It explains the practical design target behind the calculations, the mathematical derivation of the RF corridor, and how the script turns AP-to-AP neighbor RSSI into concrete recommendations for transmit power, roaming assistance, and minimum RSSI.

The model targets the long-established practical design goal of about 20% cell overlap at `-67 dBm`, adjusted for the configured RF environment such as open space, office, or obstructed layouts.

WLAN profile checks provide supporting best-practice guidance alongside the RF calculation described here.

## 1. Design Goal

The script uses AP-to-AP neighbor RSSI as a proxy for cell overlap:

- **TX Power** targets the center of a corridor derived from the RF environment
- **Roaming Assistant** is per WLAN, aggregated (as a conservative minimum) across the APs broadcasting that SSID: each AP's own value is `TX_LO + ROAM_OFFSET_DB`, capped against its weakest SSID-relevant neighbor when that neighbor is below the target corridor, then clamped to `[ROAM_FLOOR, ROAM_CEILING]` (see §7; falls back to a per-AP recommendation on controllers without the newer WLAN-level API field)
- **Minimum RSSI** is derived from the lower corridor bound (`TX_LO`) and can be enabled selectively

The script implements this by comparing measured neighbor RSSI against a derived target corridor and converting the delta into per-radio recommendations.

## 2. Data Sources

1. **UniFi API** — radio settings: channel, TX power, TX limits, TX mode, Minimum RSSI; WLAN settings: Roaming Assistant (per SSID, see §7)
2. **SSH** — AP-to-AP neighbor BSS scans on 2.4 and 5 GHz

The script detects scan-capable interfaces automatically via `iface_can_scan()`: on MediaTek-based APs (U6 family) it uses the dedicated managed interfaces (`apcli0`/`apclii0`); on Qualcomm-based APs (U7 family) it uses AP interfaces that advertise the `SET_SCAN_DWELL` PHY capability. Only active bands are scanned. Target BSSIDs are derived from the AP base MAC via offsets `+1` and `+2`.

Each AP is scanned serially. Per band, the script can repeat `iw scan` multiple times (`SCAN_ATTEMPTS`, default `2`) and merges the results by keeping the strongest RSSI per BSSID.

### Multi-Pass Scanning

The `scan_passes` config option (per site, default `1`) controls how many full round-robin scan cycles are performed before analysis. Each pass scans every AP in sequence, so the measurements are spread over time rather than taken in a single burst.

When `scan_passes >= 3`, a **trimmed mean** is applied per BSSID: the highest and lowest measurements across passes are discarded, and the remaining values are averaged. This removes single-measurement outliers (e.g. a spike caused by a temporary obstruction or a DFS channel change mid-run) without requiring an odd number of passes.

Additionally, the channel (frequency) seen per BSSID is tracked across passes. If the channel changes between passes — as happens with DFS automatic channel selection — measurements from different channels are not averaged together. Instead, only the measurements from the most common channel are used, discarding the cross-channel readings as physically incomparable.

For `scan_passes` of 1 or 2, the original behavior applies: the strongest RSSI per BSSID is kept.

**Recommended usage:**
- `scan_passes: 1` — initial setup, fast convergence
- `scan_passes: 3` — fine-tuning, noise-filtered stable measurements

## 3. Neighbor Evaluation

For each neighbor relationship, the script collects:

- **RSSI @ Neighbor**: signal from the *current AP* measured at the *neighbor AP*

This is the only direction affected by the current AP's TX power. From all values per band, the script derives `avg_neighbor_rssi`.

## 4. TX Power Heuristic

### Calculation

```text
corridor_center = TX_LO + CORRIDOR_WIDTH / 2
shift           = corridor_center - avg_neighbor_rssi

if avg_neighbor_rssi is already within [TX_LO, TX_HI]:
    recommended_tx = current_tx          # already in corridor, no change
else:
    recommended_tx = clamp(current_tx + shift, radio_min_tx, radio_max_tx)
```

The in-corridor check takes priority: if the average neighbor RSSI already falls within the target corridor, no recommendation is made regardless of the shift value. This prevents unnecessary changes when the signal is at a corridor boundary.

The derived TX shift uses **ceiling rounding** before the clamp is applied. Half steps therefore prefer the next higher whole-dBm recommendation instead of rounding down.

### TX Power Hysteresis

The hysteresis is asymmetric:

- increases are applied from `+1 dBm`
- reductions are suppressed until at least `-3 dBm`
- hardware limits still win immediately

In simplified form:

```text
if delta_tx > 0 and delta_tx < 1 and recommended_tx != radio_max_tx:
    recommended_tx = current_tx

if delta_tx < 0 and |delta_tx| < 3:
    recommended_tx = current_tx
```

The asymmetry reflects the cost difference: insufficient TX power causes coverage gaps and dropped connections, while slightly excessive TX power only creates mild cell overlap. The reduction threshold of 3 dBm is chosen to exceed the typical `iw scan` measurement noise of ±2–3 dBm, so that a reduction is only recommended when the signal is genuinely above the corridor.

Minimum RSSI is a fixed value — no hysteresis. Roaming Assistant is per WLAN, aggregated across broadcasting APs (see §7), and does not use hysteresis either: the recommendation is computed from the latest scan, the same way `TX_LO` is derived.

### Zero-sighting recovery

The corridor calculation above assumes at least one neighbor sighting (`count_nbr > 0`). When a configured neighbor exists (`peer_count > 0`) but the scan found **zero** sightings of it (`count_nbr == 0`), there is no RSSI measurement to compute a shift from — the hysteresis and corridor logic cannot run at all. In this case:

```text
if count_nbr == 0 and peer_count > 0:
    recommended_tx = radio_max_tx        # jump straight to maximum, bypass hysteresis
```

This is a deliberate departure from the tool's usual "prefer slight extra TX over creating a coverage gap" caution, and from common vendor guidance (e.g. Aruba's VRD for 802.11ac RF and roaming optimization recommends capping the spread between a radio's minimum and maximum TX power at around 6 dB). The tool jumps directly to `radio_max_tx` instead of a bounded step for one reason: without a single sighting, there is no measurement to be cautious *about* — a smaller step is not a more conservative choice, it is simply a slower way to find out whether the neighbor is reachable at all. Once a sighting exists, the normal corridor logic and asymmetric hysteresis take back over on the next run, including reducing TX again if the neighbor turns out to be much closer than expected.

If `peer_count == 0` (no neighbor configured for this AP/band at all), nothing changes — there is no target to reach.

This recommendation cannot distinguish a temporary scan miss (e.g. a DFS channel change mid-scan, an SSH timeout) from a neighbor pair that is genuinely out of range (e.g. separated by floors or exterior walls). If TX is already at `radio_max_tx` and a run still shows zero sightings, the tool has nothing further to recommend — it reports this as a distinct informational state (not a repeated ✗ "raised to maximum" on every run, since nothing is being raised) and points at repositioning or adding an AP instead of leaving TX pinned at maximum indefinitely.

### Coverage warnings

Two distinct diagnoses are emitted per neighbor:

- `*` **Coverage gap** — emitted when even at the radio's TX limit the projected RSSI stays below `TX_LO` (`tx_uncapped > radio_max_tx` and projected RSSI < `TX_LO`). This means TX adjustment cannot fix the situation; the AP placement, antenna orientation, or an additional AP needs to be considered.
- `*` **Excess overlap** — emitted when even at the radio's TX minimum the projected RSSI stays above `TX_HI` (`tx_uncapped < radio_min_tx` and projected RSSI > `TX_HI`). Symmetric counterpart of the coverage gap.
- `°` **Below corridor before TX adjustment** — emitted when the *raw* measured RSSI is below `TX_LO`, regardless of whether the TX recommendation can correct it. This is informational: the recommended TX shift may or may not lift the projected signal back into the corridor, and the Roaming Assistant cap (§7) reflects this neighbor as an input.

The `°` marker is suppressed for a neighbor that is already flagged with `*`, since the harder coverage-gap statement supersedes it.

## 5. TX Corridor Derivation

The corridor is derived from a common voice-oriented WLAN design rule of thumb: target about **20% cell overlap at −67 dBm**. At 60% of the AP-to-AP distance, the received signal must be at least −67 dBm.

The additional path loss from the 60% point to the full distance depends on the **path loss exponent n**:

```text
ΔdB   = 10 · n · log₁₀(100 / 60)
TX_LO = ROAM_TARGET − ΔdB
TX_HI = TX_LO + CORRIDOR_WIDTH
```

### Design constants

| Constant | Value | Source |
|----------|-------|--------|
| `ROAM_TARGET` | −67 dBm | Cisco VoWLAN cell-edge anchor for the path-loss model (not the per-AP threshold) |
| `OVERLAP_DIST` | 60% | ~20% cell area overlap → 60% of AP-to-AP distance |
| `CORRIDOR_WIDTH` | 6 dB | Symmetric tolerance around corridor center |
| `ROAM_OFFSET_DB` | 0 | Roaming Assistant offset relative to `TX_LO`, applied per broadcasting AP before aggregation (set to 9 to reproduce the legacy −67 dBm value at Obstructed) |
| `ROAM_MARGIN_DB` | 5 | Safety margin between weakest neighbor RSSI and the capped threshold |
| `ROAM_FLOOR` | −75 dBm | Stability floor — below this, Roaming Assistant becomes pointless. Matches Apple's macOS BTM trigger (iOS/iPad trigger at −70 dBm) |
| `ROAM_CEILING` | −65 dBm | Hard ceiling for the Roaming Assistant recommendation |
| `MIN_RSSI_OFFSET_DB` | 5 dB | How far below `TX_LO` the Minimum RSSI hard-disconnect threshold sits, giving BTM a lead time before the disconnect (range `0..30`) |

`CORRIDOR_WIDTH` is a practical tolerance around the target overlap corridor. The current value of `6 dB` provides enough margin for normal variation and asymmetry without making the target corridor too loose to be useful.

`ROAM_FLOOR` and `ROAM_CEILING` are expert knobs (allowed range −95..−50 dBm). `ROAM_FLOOR` should normally stay at or below `TX_LO` for the configured environment; raising it (e.g. `ROAM_FLOOR=-60` on a `Residential` site with `TX_LO=-73`) clamps the site-aware default upward and turns the floor into an active, more aggressive trigger.

### Environment Presets

Path loss exponent `n` is set per site in `config.yaml` via `environment:`. The script uses the usual path loss exponent form, while ITU-R P.1238 Table 2 lists the corresponding distance loss coefficient `N` in the form `L = L(d0) + N*log10(d/d0) + Lf`. In other words, `N = 10*n`, so the implementation uses `2.8` where ITU lists `28`, `3.0` where ITU lists `30`, and so on.

| Preset | n | ΔdB | TX_LO | TX_HI | ITU-R P.1238 category |
|--------|---|-----|-------|-------|-----------------------|
| `Open` | 2.2 | 4.88 | −72 | −66 | Commercial (large open spaces, retail) |
| `Residential` | 2.8 | 6.21 | −73 | −67 | Residential *(default)* |
| `Office` | 3.0 | 6.65 | −74 | −68 | Office |
| `Obstructed` | 4.0 | 8.87 | −76 | −70 | Obstructed (concrete, brick, multi-wall) |
| `<number>` | x | — | — | — | Custom n |

The same TX_LO/TX_HI apply to all bands.

## 6. Minimum RSSI

```text
recommended_min_rssi = TX_LO - MIN_RSSI_OFFSET_DB
```

Fixed value from the corridor, not from measurements. `MIN_RSSI_OFFSET_DB` (default `5`, range `0..30`) sits Minimum RSSI below `TX_LO` — vendor consensus is that the hard-disconnect threshold needs a safety margin below the BTM (soft-roam) trigger; a value of `0` reproduces the old TX_LO-equals-Minimum-RSSI behavior. Acts as a hard disconnect threshold — the AP stops serving a client when its signal drops below `TX_LO - MIN_RSSI_OFFSET_DB`.

### Relationship to Roaming Assistant

**With the default `MIN_RSSI_OFFSET_DB=5` and `ROAM_OFFSET_DB=0`, Minimum RSSI sits 5 dB below Roaming Assistant's `TX_LO` trigger, giving BTM a lead time before the hard disconnect. Setting `MIN_RSSI_OFFSET_DB=0` removes that margin; a positive `ROAM_OFFSET_DB` widens it further by raising the Roaming Assistant trigger instead.**

The default targets SOHO deployments where voice-style roaming is rare and Minimum RSSI is typically left disabled. Voice or realtime use cases that need a deliberate BTM lead time can rely on the default `MIN_RSSI_OFFSET_DB` margin, or increase `ROAM_OFFSET_DB` for more.

For the default environment presets (`Open`, `Residential`, `Office`, `Obstructed`), `TX_LO` is between −72 and −76 dBm and `ROAM_FLOOR` is `−75`, so on APs where the coverage-gap cap engages, Roaming Assistant can drop below `TX_LO`. In that case the BTM request would be issued *after* Minimum RSSI would already have disconnected the client, so enabling Minimum RSSI on coverage-gap APs is not recommended. With a custom path-loss exponent that produces `TX_LO ≤ ROAM_FLOOR`, the cap cannot push Roaming Assistant below `TX_LO` at all.

The recommendation is always derived, but whether you enable it is a deployment choice. It is most useful when cells are planned, overlap exists, and sticky clients need to be reduced.

### Why WLAN profiles do not influence the Roaming Assistant threshold or Minimum RSSI

The shipped WLAN profiles (Standard, IoT, Hotspot, Throughput, Latency) control SSID-level settings: authentication, DTIM, UAPSD, fast-roaming toggle, minimum data rate, multicast handling. Minimum RSSI is a radio-level setting — one value per radio, regardless of how many SSIDs the radio carries. Roaming Assistant *was* radio-level too, but UniFi moved it to SSID level (see §7) — even so, its target **threshold** stays a computed RF-model value, not a profile-driven one: the aggregation in §7 uses the same site-aware corridor as every other recommendation here, so a per-profile Roaming value still cannot be inferred cleanly from profile assignments alone. The decision stays explicit (via `ROAM_OFFSET_DB`) instead of being tied to a profile.

This is a distinct question from *whether Roaming Assistant should be enabled at all* for a given WLAN, which — unlike the threshold — the `roaming_assistant` profile field does control (see §7 "Enable/disable expectation").

## 7. Roaming Assistant

> **Terminology note:** since UniFi Network Application 10.4.57, the controller UI labels this setting "Handoff Suggestions (802.11v)" instead of "Roaming Assistant". The underlying API field name (`roaming_assistant_na_*`) and this tool's terminology are unchanged — "Roaming Assistant" is used throughout this document and the tool's output. The controller also sends a `roaming_assistant_6e_enabled` counterpart (live-verified on 10.6.106, present even with 6 GHz disabled); the compliance check shows it for a WLAN on 6 GHz as a separate, not evaluable result, because 6 GHz is detect-only (see [UWO-13](https://op.nutrilytics.de/projects/unifi-wifi-optimizer) for 6 GHz band support in general).

### Data source and site scope

Confirmed against a live controller (Network Application with AP firmware 6.7.54 and 8.7.11): Roaming Assistant is no longer exposed per radio — the `assisted_roaming_enabled`/`assisted_roaming_rssi` fields on `radio_table` are absent from the API. The setting now lives on the WLAN (`roaming_assistant_na_enabled`/`roaming_assistant_na_rssi` in `wlanconf`), which changes the model from "one value per radio" to "one value per SSID, broadcast across a subset of a site's APs" (`ap_group_mode`: `all`, `group`, or `specific` — all three resolve uniformly through the same AP-group membership). The controller UI rename to "Handoff Suggestions (802.11v)" is documented as happening in Network Application 10.4.57 (see the terminology note above); the exact version where the underlying API field moved from radio to WLAN level is **not** confirmed to be the same release — only the current (post-10.4.57) state was verified live. The tool's site-wide fallback to the per-radio path (below) exists precisely because the version boundary is unknown.

The optimizer reports Roaming Assistant as a **compliance check** next to Fast Roaming, using a target value computed the same way as before, but aggregated over the APs that actually broadcast each WLAN:

```text
SSID_peers(AP) = RF_neighbors(AP) ∩ broadcasting_APs(WLAN)
```

Only RF neighbors configured in `config.yaml` that also broadcast the same WLAN count toward that AP's threshold — a configured neighbor that doesn't carry the SSID is not a real handoff target and must not limit the value.

For each broadcasting AP with a non-empty `SSID_peers` set, the threshold is computed exactly as before (weakest sighting among its SSID peers, direction identical to the TX/coverage calculation — the AP's own signal as seen at the peer, not the reverse, since RSSI is not symmetric):

```text
default = TX_LO + ROAM_OFFSET_DB

if min(SSID_peer_rssi) < TX_LO:                # weakest SSID peer below corridor
    cap = min(SSID_peer_rssi) - ROAM_MARGIN_DB
    threshold = min(default, cap)
else:
    threshold = default

threshold = clamp(threshold, ROAM_FLOOR, ROAM_CEILING)
```

The WLAN's target is the **minimum** across all its broadcasting APs' thresholds — conservative, so no AP is judged more optimistically than its own coverage situation allows. Every AP whose own value equals that minimum is a **limiting AP** for the WLAN; if several APs tie (common after a `ROAM_FLOOR` clamp), all of them are reported, not just one.

`ROAM_OFFSET_DB=0` keeps the threshold at the lower corridor edge, which matches the published roaming triggers of common clients (Apple iPhone/iPad ~−70 dBm, Mac ~−75 dBm; Aruba ClientMatch sticky-min default −70 dBm). The legacy fixed value of −67 dBm can be reproduced by setting `ROAM_OFFSET_DB=9` at Obstructed.

### Coverage warnings

When a cap engages for a limiting AP, the report shows one of two warnings, naming both the limiting AP and the weakest SSID peer that caused the cap:

- **`Roaming Assistant lowered to X dBm`** — the weakest SSID peer is below `TX_LO`, so `min(peer) − ROAM_MARGIN_DB` is used (and is still above `ROAM_FLOOR`). The threshold tracks coverage but stays in usable territory.
- **`Roaming Assistant clamped to ROAM_FLOOR (X dBm)`** — `min(peer) − ROAM_MARGIN_DB` would fall below `ROAM_FLOOR` and is clamped. This is a stability floor, not a quality target: it prevents aggressive BTM requests at APs that have no reachable roaming neighbor, but it does not fix the underlying coverage problem.

The Roaming Assistant sends an 802.11v BSS Transition Management (BTM) request when a client's signal drops to the threshold. BTM is advisory — the client may ignore it.

### Applicability and incomplete data

- **Band applicability** is decided from the WLAN's *actual* configured bands, never its profile's expected bands — a WLAN that deviates from its profile on band is already flagged separately by the "WiFi Band" check, so this avoids reporting the same deviation twice. A WLAN not broadcasting 5 GHz is reported `N/A`.
- **Single-AP WLANs** (only one AP broadcasts the SSID) have no handoff target and are reported `N/A`.
- **Incomplete data never produces a silently optimistic value.** If a broadcasting AP has no configured RF neighbor that also broadcasts the WLAN, or a relevant peer's sighting is missing from the current scan, the WLAN is reported `Incomplete` with the specific reason (naming the AP and, where relevant, the missing peer) instead of a ✓/✗ verdict computed from a partial data set.
- **A missing sighting is often a TX power problem, not a roaming problem.** When the verdict is `Incomplete` or `Not evaluable` and the site still has pending TX power recommendations (see §4 "Zero-sighting recovery" and the site-wide precompute in `prepare_site_tx_checks()`), the report adds a note pointing at those pending changes first — a neighbor that a scan never sights is frequently just out of reach at the AP's current TX power, and applying the TX recommendation may resolve the missing sighting before any roaming-specific tuning is needed.

### Enable/disable expectation

Three distinct 802.11 mechanisms sit under the controller UI's "Roaming Assistance" section, easy to conflate since they all address client roaming:

- **`fast_roaming`** (profile field) — 802.11r Fast BSS Transition, a faster re-authentication handshake during roaming.
- **`bss_transition`** (profile field) — 802.11v BSS Transition Management protocol support itself: whether the AP/client can exchange BTM frames at all.
- **Roaming Assistant / "Handoff Suggestions (802.11v)"** (`roaming_assistant_na_enabled`/`_na_rssi`) — whether the controller actively *sends* a BTM request, and at what RSSI threshold. This is the one mechanism covered by this section; it depends on `bss_transition` being supported to have any effect, but is a separate on/off switch with its own RSSI trigger.

The `roaming_assistant` profile field (`true`/`false`) controls only whether Roaming Assistant is expected to be **enabled**, compared against the WLAN's actual `roaming_assistant_na_enabled`:

- `roaming_assistant: false` and the WLAN has it disabled → ✓ `Disabled (per profile)`. No RSSI comparison — the threshold from §7 above is not applicable when the profile expects the feature off.
- `roaming_assistant: false` but the WLAN has it enabled anyway → ✗ `Enabled, but profile expects disabled`, flagged the same way any other profile deviation is.
- `roaming_assistant: true` → the full compliance check above runs unchanged (✓/✗ against the computed threshold, `Incomplete`/`Not evaluable` handling, the "fix TX power first" hint).

The `N/A` cases (5 GHz not broadcast; older API without `roaming_assistant_na_*`) take priority over the profile's enable/disable expectation — a WLAN that cannot support Roaming Assistant at all does not become "compliant" just because a profile expects it disabled.

Shipped profile defaults: `Standard`, `IoT`, `Hotspot` expect it disabled (2.4 GHz-centric or short-lived guest/IoT sessions get little benefit from active BTM steering); `Throughput`, `Latency` expect it enabled (primary client WLANs where actively steering sticky clients toward a stronger AP is worthwhile).

### Fallback for older controllers

If no WLAN on a site exposes `roaming_assistant_na_*` at all (an older Network Application/API version), the tool falls back — for that entire site — to the previous per-radio behavior: Roaming Assistant appears as a per-AP recommendation in the 5 GHz RF-tuning section, computed the same way but from the full RF-neighbor set rather than an SSID-filtered one. The fallback is site-wide, not per WLAN, since mixing the two aggregation models within one site would compare incompatible targets.

The `roaming_assistant` profile field (enable/disable expectation, see above) has **no effect** on this fallback path — the per-radio recommendation always appears, regardless of what any profile expects. This mirrors the pre-existing rule that WLAN profiles never influenced the old radio-level behavior either (§6): the per-radio model predates SSID-level profiles entirely and was never profile-aware to begin with, so the fallback intentionally does not retrofit that awareness. This only matters on sites still running an older Network Application/API version; once the controller exposes `roaming_assistant_na_*`, the per-WLAN model (and the profile field) takes over automatically.

| Recommendation | Value | Enabled by default? |
|----------------|-------|---------------------|
| Roaming Assistant threshold | per WLAN, `min()` over broadcasting APs' `TX_LO + ROAM_OFFSET_DB`, clamped to `[ROAM_FLOOR, ROAM_CEILING]` (per-AP fallback on older controllers) | Yes (5 GHz only) |
| Minimum RSSI | `TX_LO` | Use selectively |

The RSSI threshold itself is not profile-driven; see §6 for the rationale. Whether Roaming Assistant is expected to be enabled at all IS profile-driven, via the `roaming_assistant` field — see "Enable/disable expectation" above.

## 8. Channel Width Planning

The optimizer does not currently compute a target channel width.

Instead, it uses the configured adjacency graph only for two hard checks:

- **2.4 GHz overcrowding**: more than three adjacent APs share only the clean channels `1 / 6 / 11`
- **local width budget exceeded**: the currently configured widths of an AP and its direct neighbors no longer fit into the clean spectrum budget

Current local spectrum budgets:

- **2.4 GHz**: `60 MHz` (`3 x 20 MHz`)
- **5 GHz**: `320 MHz` (`2 x 160 MHz`, equivalently `4 x 80 MHz`)

These checks are informational guardrails. The script warns when the current layout is structurally too wide, but it does not derive a hard replacement width from that alone.

## 9. Channel Overlap Check

The optimizer also checks whether adjacent APs overlap spectrally even when the configured channel width itself is acceptable.

- **5 GHz** uses channel center frequency plus configured width to detect overlapping occupied spectrum
- **2.4 GHz** uses the same approach, with a small guard band so that the normal clean reuse pattern `1 / 6 / 11` stays non-overlapping while closer channels are flagged

This is evaluated against the explicitly configured adjacency list, using the controller-reported channel and width of the peer APs. As a result, channel overlap warnings are independent of whether a live neighbor scan happened to return data in that run.

## 10. Model Limits

- uses AP-to-AP RSSI as a proxy for cell overlap
- evaluates explicitly configured neighbor relationships
- **AP-to-AP RSSI is not a client link-budget proxy.** Every measurement in this model is a directional AP-beacon reading taken by another AP's radio, not a client uplink or downlink reading. Client devices typically transmit at lower power than AP radios, so a corridor tuned from AP-to-AP RSSI alone can look compliant while a weak client's uplink to the AP is still marginal — the model has no visibility into client-side TX power, antenna gain, or body loss, and cannot detect this asymmetric link-budget case.

## References

- **ITU-R P.1238-10**: [Propagation data and prediction methods for the planning of indoor radiocommunication systems and radio local area networks in the frequency range 300 MHz to 450 GHz](https://www.itu.int/dms_pubrec/itu-r/rec/p/R-REC-P.1238-10-201908-S!!PDF-E.pdf)
- **Cisco**: [Site Survey Guidelines for WLAN Deployment](https://www.cisco.com/c/en/us/support/docs/wireless/5500-series-wireless-controllers/116057-site-survey-guidelines-wlan-00.html) — voice cell edge at −67 dBm, 20% overlap
- **Ubiquiti**: [Understanding and Implementing Minimum RSSI](https://help.ui.com/hc/en-us/articles/221321728-Understanding-and-Implementing-Minimum-RSSI)
