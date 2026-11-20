"""The serving table of one access point and band: accepted only when every successful pass agrees and the
table belongs to the channel the controller reports; otherwise the reason says which."""

from dataclasses import replace

import pytest

from unifiwifioptimizer.analysis.phy_power import serving_table
from unifiwifioptimizer.domain.analysis import MaxReason
from unifiwifioptimizer.domain.models import Band
from unifiwifioptimizer.domain.scan import ApScan, PhyChannelPower, ScanFailure, ScanFailureKind, ScanPass

from .builders import scan_pass

AP_MAC = "02:00:00:00:00:04"


def table(frequency_mhz: int, dbm: float = 20.0) -> PhyChannelPower:
    return PhyChannelPower(phy_index=1, current_frequency_mhz=frequency_mhz, limits=((6, dbm), (11, dbm)))


def with_tables(two: PhyChannelPower | None, five: PhyChannelPower | None = None) -> ScanPass:
    return replace(scan_pass(), power_2g=two, power_5g=five)


def ap_scan(*passes: ScanPass | ScanFailure) -> ApScan:
    return ApScan(ap_mac=AP_MAC, ap_name="AP-1", passes=passes, interface_toggle=False)


FAILED = ScanFailure(kind=ScanFailureKind.TIMEOUT, detail="timed out")


def test_a_table_every_pass_agrees_on_and_that_matches_the_channel_is_served() -> None:
    served = table(2437)
    scan = ap_scan(with_tables(served), with_tables(served))
    assert serving_table(scan, Band.GHZ_2, 6) == served
    assert serving_table(scan, Band.GHZ_5, 6) is MaxReason.NO_TABLE


@pytest.mark.parametrize("scan", [None, ap_scan(), ap_scan(FAILED, FAILED)])
def test_no_successful_pass_is_a_failed_scan(scan: ApScan | None) -> None:
    assert serving_table(scan, Band.GHZ_2, 6) is MaxReason.SCAN_FAILED


def test_a_failed_pass_among_good_ones_does_not_disturb_the_table() -> None:
    served = table(2437)
    assert serving_table(ap_scan(FAILED, with_tables(served)), Band.GHZ_2, 6) == served


@pytest.mark.parametrize(
    "passes",
    [
        (with_tables(None), with_tables(None)),
        (with_tables(None),),
    ],
)
def test_every_pass_without_a_table_is_no_table(passes: tuple[ScanPass, ...]) -> None:
    assert serving_table(ap_scan(*passes), Band.GHZ_2, 6) is MaxReason.NO_TABLE


def test_passes_that_mix_a_table_with_none_or_disagree_are_unstable_in_either_order() -> None:
    served = table(2437)
    assert serving_table(ap_scan(with_tables(served), with_tables(None)), Band.GHZ_2, 6) is MaxReason.UNSTABLE
    assert serving_table(ap_scan(with_tables(None), with_tables(served)), Band.GHZ_2, 6) is MaxReason.UNSTABLE
    other = table(2437, dbm=17.0)
    assert serving_table(ap_scan(with_tables(served), with_tables(other)), Band.GHZ_2, 6) is MaxReason.UNSTABLE


@pytest.mark.parametrize("channel", [None, 11, 99])
def test_a_table_of_another_frequency_or_without_a_controller_channel_belongs_to_no_channel(
    channel: int | None,
) -> None:
    scan = ap_scan(with_tables(table(2437)))
    assert serving_table(scan, Band.GHZ_2, channel) is MaxReason.CHANNEL_MISMATCH
