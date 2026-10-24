"""The RF tunables of a run as one value, built by the configuration layer and consumed by the analysis.

Every member is a documented tunable of the RF model (docs/ALGORITHM.md §5, §6, §7): the cell edge (noise
floor + required SNR), the assumed client transmit power and optional upper-5-GHz override for the uplink
conversion, the Min-RSSI margin below the roaming trigger, and the roaming threshold bounds.
"""

from dataclasses import dataclass

from unifiwifioptimizer.domain.models import Band
from unifiwifioptimizer.rf.channels import occupied_channels_5g
from unifiwifioptimizer.rf.constants import DEFAULT_CLIENT_TX_DBM, DEFAULT_MIN_RSSI_OFFSET_DB
from unifiwifioptimizer.rf.corridor import DEFAULT_CELL_EDGE, CellEdge
from unifiwifioptimizer.rf.roaming import DEFAULT_TUNABLES, RoamingTunables


@dataclass(frozen=True, slots=True, kw_only=True)
class RfSettings:
    cell_edge: CellEdge = DEFAULT_CELL_EDGE
    client_tx_dbm: int = DEFAULT_CLIENT_TX_DBM
    client_tx_dbm_5g_upper: int | None = None
    min_rssi_offset_db: int = DEFAULT_MIN_RSSI_OFFSET_DB
    roaming: RoamingTunables = DEFAULT_TUNABLES

    def client_tx_assumption(self, band: Band, channel: int | None, width_mhz: int | None) -> int:
        """Assumed client TX on the current operating block; unknown geometry uses the base value."""
        if (
            band is Band.GHZ_5
            and self.client_tx_dbm_5g_upper is not None
            and channel is not None
            and width_mhz is not None
        ):
            try:
                occupied = occupied_channels_5g(channel, width_mhz)
            except ValueError:
                pass
            else:
                if all(100 <= subchannel <= 140 for subchannel in occupied):
                    return self.client_tx_dbm_5g_upper
        return self.client_tx_dbm


DEFAULT_RF_SETTINGS = RfSettings()
