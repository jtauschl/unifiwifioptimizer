# Algorithm

Manual RF recommendations for UniFi access points. Does not write controller configuration and is not a replacement for site surveys.

## 1. Design goal

The script uses AP-to-AP neighbor RSSI as a proxy for cell overlap:

- **TX Power** targets the center of a corridor derived from the RF environment
- **Roaming Assistant** is fixed at the design overlap point (`ROAM_TARGET` = −67 dBm)
- **Minimum RSSI** is derived from the lower corridor bound (`TX_LO`) and can be enabled selectively

Recommendations need validation against real client requirements.

## 2. Data sources

1. **UniFi API** — radio settings: channel, TX power, TX limits, TX mode, Minimum RSSI, Roaming Assistant
2. **SSH** — AP-to-AP neighbor BSS scans on 2.4 and 5 GHz

Assumptions: scan interfaces `apcli0`/`apclii0`, BSSIDs derived from base MAC via offsets +1/+2.

## 3. Neighbor evaluation

For each neighbor relationship, the script collects:

- **RSSI @ Neighbor**: signal from the *current AP* measured at the *neighbor AP*

This is the only direction affected by the current AP's TX power. From all values per band, the script derives `avg_neighbor_rssi`.

## 4. TX Power heuristic

### Calculation

```text
corridor_center = TX_LO + CORRIDOR_WIDTH / 2
shift           = corridor_center - avg_neighbor_rssi
quantized_shift = quantize_bias_high(shift)
recommended_tx  = clamp(current_tx + quantized_shift, radio_min_tx, radio_max_tx)
```

The quantization bias favors stronger TX: positive shifts round up (ceiling), negative shifts round towards zero.

### TX Power hysteresis

±1 dBm changes to the suggested TX power are suppressed unless the result hits a hardware boundary:

```text
if |recommended_tx - current_tx| <= 1
   AND recommended_tx != radio_max_tx
   AND recommended_tx != radio_min_tx:
     recommended_tx = current_tx
```

Roaming Assistant and Minimum RSSI are fixed values — no hysteresis.

### Coverage warnings

Warnings appear only when the uncapped TX recommendation **exceeds a hardware limit** and neighbors are still outside the corridor:

- `tx_uncapped > radio_max_tx` and projected RSSI < `TX_LO` → **coverage gap**
- `tx_uncapped < radio_min_tx` and projected RSSI > `TX_HI` → **excess overlap**

Affected neighbors are flagged with `*`. This typically indicates uneven AP spacing or obstacles.

## 5. TX corridor derivation

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
| `ROAM_TARGET` | −67 dBm | Cisco VoWLAN design guideline: −67 dBm cell edge |
| `OVERLAP_DIST` | 60% | ~20% cell area overlap → 60% of AP-to-AP distance |
| `CORRIDOR_WIDTH` | 6 dB | Symmetric tolerance around corridor center |

### Environment presets

Path loss exponent `n` is set per site in `config.yaml` via `environment:`. Values are based on ITU-R P.1238-13, Table 2 (1.8–2.0 GHz):

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
recommended_min_rssi = TX_LO
```

Fixed value from the corridor, not from measurements. Acts as a hard disconnect threshold — the AP stops serving a client when its signal drops below `TX_LO`. This gives a `CORRIDOR_WIDTH` (6 dB) margin below the roaming threshold.

The recommendation is always derived, but whether you enable it is a deployment choice. It is most useful when cells are planned, overlap exists, and sticky clients need to be reduced.

## 7. Roaming Assistant

```text
roaming_assistant = ROAM_TARGET = −67 dBm
```

Fixed, independent of environment or band. Sends an 802.11v BSS Transition Management (BTM) request when a client's signal drops to `ROAM_TARGET`. BTM is advisory — the client may ignore it. If the client turns around, signal improves and no roaming is triggered.

The asymmetric 60%/40% overlap design reduces ping-pong risk:

- current AP sees client at −67 dBm → sends BTM
- client is already closer to neighbor → neighbor receives client above −67 dBm
- after roaming, client is well above threshold on new AP → no immediate BTM

| Recommendation | Value | Enabled by default? |
|----------------|-------|---------------------|
| Roaming Assistant | −67 dBm | Yes |
| Minimum RSSI | `TX_LO` | Use selectively |

## 8. Limits

- does not write controller configuration — generates recommendations only
- uses AP-to-AP RSSI as proxy, not client telemetry
- assumes known neighbor relationship
- does not evaluate channel planning, SNR, retry rate, or capacity
- AP recommendations cover 2.4 and 5 GHz; 6 GHz is profile-only
- depends on model-specific interface naming and MAC derivation

## References

- **ITU-R P.1238-13**: indoor path loss exponents by environment
- **Cisco**: [Site Survey Guidelines for WLAN Deployment](https://www.cisco.com/c/en/us/support/docs/wireless/5500-series-wireless-controllers/116057-site-survey-guidelines-wlan-00.html) — voice cell edge at −67 dBm, 20% overlap
- **Ubiquiti**: [Understanding and Implementing Minimum RSSI](https://help.ui.com/hc/en-us/articles/221321728-Understanding-and-Implementing-Minimum-RSSI)
- **Ubiquiti**: [UniFi WiFi SSID and AP Settings Overview](https://help.ui.com/hc/en-us/articles/32065480092951-UniFi-WiFi-SSID-level-Settings-Overview)
