"""Design constants of the RF model (ADR-002 D8, docs/ALGORITHM.md §5).

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
# Design choice carried over from the shell tool, no standard behind it: a trigger above this would make
# clients roam while still well inside a cell. Tunable.
DEFAULT_ROAM_CEILING_DBM = -65
# Vendor consensus margin between the soft-roam trigger and the hard disconnect (Cisco uses ~10 dB).
DEFAULT_MIN_RSSI_OFFSET_DB = 5


def span(allowed: range) -> str:
    """Human-readable inclusive bounds of a range, for validation messages."""
    return f"{allowed.start}..{allowed.stop - 1}"


DB_TUNABLE_RANGE = range(0, 31)
DBM_TUNABLE_RANGE = range(-95, -49)
NOISE_FLOOR_RANGE = range(-105, -79)
SNR_RANGE = range(10, 41)
CLIENT_TX_RANGE = range(0, 31)
