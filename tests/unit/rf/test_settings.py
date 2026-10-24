import pytest

from unifiwifioptimizer.domain.models import Band
from unifiwifioptimizer.rf.settings import RfSettings


@pytest.mark.parametrize(
    ("band", "channel", "width", "expected"),
    [
        (Band.GHZ_2, 11, 20, 18),
        (Band.GHZ_5, 36, 80, 18),
        (Band.GHZ_5, 60, 80, 18),
        (Band.GHZ_5, 100, 20, 20),
        (Band.GHZ_5, 120, 80, 20),
        (Band.GHZ_5, 128, 160, 20),
        (Band.GHZ_5, 140, 20, 20),
        (Band.GHZ_5, 140, 40, 18),
        (Band.GHZ_5, 144, 80, 18),
        (Band.GHZ_5, 149, 80, 18),
        (Band.GHZ_5, None, 80, 18),
        (Band.GHZ_5, 100, None, 18),
        (Band.GHZ_5, 100, 320, 18),
        (Band.GHZ_5, 34, 20, 18),
        (Band.GHZ_6, 5, 20, 18),
    ],
)
def test_client_tx_override_requires_a_wholly_upper_5g_block(
    band: Band, channel: int | None, width: int | None, expected: int
) -> None:
    rf = RfSettings(client_tx_dbm=18, client_tx_dbm_5g_upper=20)
    assert rf.client_tx_assumption(band, channel, width) == expected


def test_default_client_tx_assumption_is_unchanged() -> None:
    assert RfSettings().client_tx_assumption(Band.GHZ_5, 120, 80) == 14
