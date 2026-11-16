"""The serving PHY's per-channel limits of one access point and band, accepted only when every successful
pass agrees and the table's current frequency is the channel the controller reports."""

from unifiwifioptimizer.domain.analysis import MaxReason
from unifiwifioptimizer.domain.models import Band
from unifiwifioptimizer.domain.scan import ApScan, PhyChannelPower
from unifiwifioptimizer.rf.channels import center_frequency_or_none


def serving_table(ap_scan: ApScan | None, band: Band, channel: int | None) -> PhyChannelPower | MaxReason:
    passes = ap_scan.successful_passes if ap_scan is not None else ()
    if not passes:
        return MaxReason.SCAN_FAILED
    tables = [p.power(band) for p in passes]
    first = tables[0]
    if all(t is None for t in tables):
        return MaxReason.NO_TABLE
    if first is None or any(t != first for t in tables):
        return MaxReason.UNSTABLE
    frequency = center_frequency_or_none(band, channel) if channel is not None else None
    if frequency is None or first.current_frequency_mhz != frequency:
        return MaxReason.CHANNEL_MISMATCH
    return first
