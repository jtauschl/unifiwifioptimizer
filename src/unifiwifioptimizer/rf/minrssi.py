"""Minimum RSSI recommendation (ADR-002 D8, docs/ALGORITHM.md §6).

The controller evaluates Minimum RSSI on the client's uplink as received by the AP. A downlink target
is converted by link reciprocity: RSSI_up - RSSI_down = P_client - P_AP.
"""

from unifiwifioptimizer.rf.constants import (
    CLIENT_TX_RANGE,
    DB_TUNABLE_RANGE,
    DEFAULT_CLIENT_TX_DBM,
    DEFAULT_MIN_RSSI_OFFSET_DB,
    span,
)
from unifiwifioptimizer.rf.corridor import Corridor


def uplink_threshold(downlink_target_dbm: int, tx_eff_ap_dbm: int, client_tx_dbm: int = DEFAULT_CLIENT_TX_DBM) -> int:
    """The uplink RSSI at the AP that corresponds to `downlink_target_dbm` at the client."""
    if client_tx_dbm not in CLIENT_TX_RANGE:
        raise ValueError(f"client TX must be in {span(CLIENT_TX_RANGE)} dBm, got {client_tx_dbm}")
    return downlink_target_dbm - (tx_eff_ap_dbm - client_tx_dbm)


def recommend_min_rssi(
    corridor: Corridor,
    tx_eff_ap_dbm: int,
    client_tx_dbm: int = DEFAULT_CLIENT_TX_DBM,
    offset_db: int = DEFAULT_MIN_RSSI_OFFSET_DB,
) -> int:
    """Hard-disconnect threshold `offset_db` below the corridor's lower edge (the soft-roam trigger),
    expressed on the uplink the AP measures."""
    if offset_db not in DB_TUNABLE_RANGE:
        raise ValueError(f"min_rssi offset must be in {span(DB_TUNABLE_RANGE)} dB, got {offset_db}")
    return uplink_threshold(corridor.low - offset_db, tx_eff_ap_dbm, client_tx_dbm)
