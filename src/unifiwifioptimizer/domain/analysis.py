"""The vocabulary the analysis speaks and the report carries: outcome classes, the reasons a neighbour
reading can be missing, where a reading came from, why a run is partial, and how a roaming threshold was
capped. These live in the domain so the report model can name them without importing the layers that
compute them (the report is data; `rf` and `analysis` import this module, never the other way round)."""

from enum import StrEnum


class ChannelPlanMethod(StrEnum):
    EXACT = "exact"
    HEURISTIC = "heuristic"


class ReadingSource(StrEnum):
    """`MEASURED`: the peer's scan heard this access point. `RECIPROCITY`: the peer did not, but this access
    point heard the peer, and the reverse reading is predicted from the power difference (same path loss in
    both directions)."""

    MEASURED = "measured"
    RECIPROCITY = "reciprocity"


class MissingReason(StrEnum):
    """Why a neighbour cell has no reading, in priority order from the most to the least fundamental."""

    SCAN_SKIPPED = "scan_skipped"
    SELF_OFFLINE = "self_offline"
    PEER_OFFLINE = "peer_offline"
    PEER_UNKNOWN = "peer_unknown"
    SELF_DFS_WAIT = "self_dfs_wait"
    PEER_DFS_WAIT = "peer_dfs_wait"
    PEER_NO_RADIO = "peer_no_radio"
    PEER_INTERFACE_DOWN = "peer_interface_down"
    PEER_SCAN_FAILED = "peer_scan_failed"
    PEER_SCAN_EMPTY = "peer_scan_empty"
    NO_DFS_EVIDENCE = "no_dfs_evidence"
    NOT_SIGHTED = "not_sighted"

    @property
    def words(self) -> str:
        return self.value.replace("_", " ")


class BandTxOutcome(StrEnum):
    """The row of the transmit-power decision table that applied to one radio."""

    SCAN_SKIPPED = "scan_skipped"
    OFFLINE = "offline"
    DFS_WAIT = "dfs_wait"
    NOT_EVALUABLE = "not_evaluable"
    NO_PEERS = "no_peers"
    NO_SIGHTING = "no_sighting"
    IN_CORRIDOR = "in_corridor"
    IN_CORRIDOR_PARTIAL = "in_corridor_partial"
    COVERAGE_GAP = "coverage_gap"
    RAISE_TO_MAXIMUM = "raise_to_maximum"
    TOO_STRONG_AT_MINIMUM = "too_strong_at_minimum"
    REDUCTION_BLOCKED = "reduction_blocked"
    OUT_OF_CORRIDOR = "out_of_corridor"


class PartialReason(StrEnum):
    """What made a run a partial success (exit code 6): a finding in the report, never an abort."""

    AP_UNPARSABLE = "ap_unparsable"
    AP_NOT_FOUND = "ap_not_found"
    SCAN_FAILED = "scan_failed"
    BAND_EMPTY = "band_empty"
    BAND_FAILED = "band_failed"
    INTERFACE_DOWN = "interface_down"
    AP_NAME_DUPLICATE = "ap_name_duplicate"


class WlanRoamingStatus(StrEnum):
    """Whether a WLAN's Roaming Assistant threshold could be derived."""

    OK = "ok"
    INCOMPLETE = "incomplete"
    NOT_APPLICABLE_SINGLE_AP = "not_applicable_single_ap"
    NOT_APPLICABLE_NO_5G = "not_applicable_no_5g"


class NeighbourMarker(StrEnum):
    """How a neighbour's reading relates to the corridor after the recommended change."""

    # Below the corridor before the change, inside it after.
    BELOW_FIXED = "below_fixed"
    # Below the corridor even after the change: a coverage gap towards this neighbour.
    BELOW_UNFIXABLE = "below_unfixable"
    # Above the corridor even at the radio minimum: only placement or a disabled band helps.
    ABOVE_UNFIXABLE = "above_unfixable"


class MissDirection(StrEnum):
    """Which reading(s) of a configured pair are missing."""

    BOTH = "both"
    A_TO_B = "a_to_b"
    B_TO_A = "b_to_a"


class RoamingCap(StrEnum):
    """How the weakest neighbour bounded a Roaming Assistant threshold."""

    NONE = "none"
    # The weakest neighbour minus the margin pulled the threshold below the default, at or above the floor.
    MARGIN = "capped_by_margin"
    # The weakest neighbour minus the margin fell below the floor and was clamped to it.
    FLOOR = "capped_by_floor"
