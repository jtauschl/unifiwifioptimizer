"""The RF tunables of a run as one value, built by the configuration layer and consumed by the analysis.

Every member is a documented tunable of the RF model (docs/ALGORITHM.md §5, §6, §7): the cell edge (noise
floor + required SNR), the typical client transmit power for the uplink conversion, the Min-RSSI margin
below the roaming trigger, and the roaming threshold bounds.
"""

from dataclasses import dataclass

from unifiwifioptimizer.rf.constants import DEFAULT_CLIENT_TX_DBM, DEFAULT_MIN_RSSI_OFFSET_DB
from unifiwifioptimizer.rf.corridor import DEFAULT_CELL_EDGE, CellEdge
from unifiwifioptimizer.rf.roaming import DEFAULT_TUNABLES, RoamingTunables


@dataclass(frozen=True, slots=True, kw_only=True)
class RfSettings:
    cell_edge: CellEdge = DEFAULT_CELL_EDGE
    client_tx_dbm: int = DEFAULT_CLIENT_TX_DBM
    min_rssi_offset_db: int = DEFAULT_MIN_RSSI_OFFSET_DB
    roaming: RoamingTunables = DEFAULT_TUNABLES


DEFAULT_RF_SETTINGS = RfSettings()
