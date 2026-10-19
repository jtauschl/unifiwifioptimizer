"""Design constants of the RF model (docs/ALGORITHM.md §5).

Every value is either derived from a standard or marked as a vendor figure exposed as a tunable.
"""

from types import MappingProxyType

# Cisco site-survey guidance (document 116057): "require a minimum SNR of 25 dB (25 = -92 dBm noise
# level with -67 dBm signal)". Cross-checked against physics and the standard: thermal noise over
# 20 MHz is kTB = -101 dBm, a receiver noise figure of ~9 dB gives -92 dBm; IEEE 802.11-2020
# Table 17-18 lists -65 dBm minimum sensitivity for 64-QAM 3/4 at an assumed 10 dB noise figure, i.e.
# ~26 dB SNR including the standard's 5 dB implementation margin, within 1 dB of Cisco's figure.
DEFAULT_NOISE_FLOOR_DBM = -92
DEFAULT_REQUIRED_SNR_DB = 25
# 2.4 GHz only: the cell edge sits at this share of the AP-to-AP distance (the one-dimensional reading of
# "about 20 % overlap"; two equal circles overlap ~8 % of one cell's area at this distance). 5 GHz uses
# the two-AP rule instead, which puts the edge at the neighbouring AP itself.
OVERLAP_DISTANCE_PERCENT = 60
CORRIDOR_WIDTH_DB = 6
# Minimum reduction once clamping at the radio minimum shrinks a shift; an integer reading outside a
# 6 dB corridor already demands a shift of at least 4 dB, and increases are never suppressed.
HYSTERESIS_DOWN_DB = 3

# Path-loss exponent n per environment preset (ITU-R P.1238-10 Table 2 lists N = 10·n). "Open" is
# the commercial value of the 1.25/1.9/4 GHz rows (no 2.4 GHz commercial value exists), "Obstructed"
# is the body-text figure "about 40".
PATH_LOSS_PRESETS = MappingProxyType(
    {
        "Open": 2.2,
        "Residential": 2.8,
        "Office": 3.0,
        "Obstructed": 4.0,
    }
)

# Vendor figure, no standard: typical smartphone transmit power. Enters the uplink conversion of
# thresholds the AP evaluates on received client signal.
DEFAULT_CLIENT_TX_DBM = 15

DEFAULT_ROAM_OFFSET_DB = 0
DEFAULT_ROAM_MARGIN_DB = 5
# Apple's published roam-scan threshold for macOS (iOS/iPadOS: -70 dBm); a client-side (downlink) value.
DEFAULT_ROAM_FLOOR_DBM = -75
# Design choice, no standard behind it: a trigger above this would make clients roam while still well
# inside a cell. Tunable.
DEFAULT_ROAM_CEILING_DBM = -65
# Range of the Handoff Suggestions threshold the controller accepts (the slider's stops on Network 10.6.106).
# A derived uplink value outside it cannot be configured, so the recommendation stops at the nearer end.
ROAMING_ASSISTANT_MIN_DBM = -80
ROAMING_ASSISTANT_MAX_DBM = -60
# Range of the per-radio Minimum RSSI the controller accepts (verified on U6 Lite and U7 Lite, both bands).
MIN_RSSI_MIN_DBM = -90
MIN_RSSI_MAX_DBM = -67
# Vendor consensus margin between the soft-roam trigger and the hard disconnect (Cisco uses ~10 dB).
DEFAULT_MIN_RSSI_OFFSET_DB = 5

# IEEE 802.11-2020 OFDM PHY CCA requirements (17.3.10.6): the start of a valid 20 MHz OFDM transmission at or
# above the 6 Mb/s minimum sensitivity (-82 dBm, Table 17-18) must make CCA report busy. Two access points
# that hear each other at this level or above cannot transmit co-channel at the same time; receivers defer
# well below it, so a check at this threshold under-reports contention rather than inventing it.
CCA_PREAMBLE_DETECT_DBM = -82
# IEEE 802.11 RCPI measurement accuracy: +/- 5 dB at 95 % confidence (stated in every PHY's RCPI clause). A
# receiver-offset estimate below this is within one receiver's own tolerance.
RCPI_ACCURACY_DB = 5


def span(allowed: range) -> str:
    """Human-readable inclusive bounds of a range, for validation messages."""
    return f"{allowed.start}..{allowed.stop - 1}"


DB_TUNABLE_RANGE = range(0, 31)
DBM_TUNABLE_RANGE = range(-95, -49)
NOISE_FLOOR_RANGE = range(-105, -79)
SNR_RANGE = range(10, 41)
CLIENT_TX_RANGE = range(0, 31)
