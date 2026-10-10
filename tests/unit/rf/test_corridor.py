import math

import pytest
from hypothesis import given
from hypothesis import strategies as st

from unifiwifioptimizer.domain.models import Band
from unifiwifioptimizer.rf.constants import CORRIDOR_WIDTH_DB, PATH_LOSS_PRESETS
from unifiwifioptimizer.rf.corridor import DEFAULT_CELL_EDGE, CellEdge, Corridor, PathLossModel, corridor_for

exponents = st.floats(min_value=0.1, max_value=10, allow_nan=False, allow_infinity=False)
edges = st.builds(CellEdge, noise_floor_dbm=st.integers(-105, -80), required_snr_db=st.integers(10, 40))


def test_default_cell_edge_is_minus_67_from_noise_floor_and_snr() -> None:
    assert CellEdge(noise_floor_dbm=-92, required_snr_db=25) == DEFAULT_CELL_EDGE
    assert DEFAULT_CELL_EDGE.dbm == -67


@pytest.mark.parametrize(
    "kwargs", [{"noise_floor_dbm": -106}, {"noise_floor_dbm": -79}, {"required_snr_db": 9}, {"required_snr_db": 41}]
)
def test_cell_edge_primitives_outside_their_ranges_are_rejected(kwargs: dict[str, int]) -> None:
    with pytest.raises(ValueError):
        CellEdge(**kwargs)


def test_5ghz_corridor_starts_at_the_cell_edge_for_every_environment() -> None:
    for preset in PATH_LOSS_PRESETS:
        assert corridor_for(Band.GHZ_5, PathLossModel.from_preset(preset)) == Corridor(low=-67)


@pytest.mark.parametrize(
    ("preset", "delta_db", "low", "high"),
    [
        ("Open", 4.88, -72, -66),
        ("Residential", 6.21, -73, -67),
        ("Office", 6.66, -74, -68),
        ("Obstructed", 8.87, -76, -70),
    ],
)
def test_2ghz_presets_reproduce_the_documented_corridors(preset: str, delta_db: float, low: int, high: int) -> None:
    model = PathLossModel.from_preset(preset)
    corridor = corridor_for(Band.GHZ_2, model)
    assert model.preset == preset
    assert round(model.delta_db, 2) == delta_db
    assert (corridor.low, corridor.high) == (low, high)


def test_custom_exponent_matches_the_documented_example() -> None:
    model = PathLossModel.custom(3.5)
    assert model.preset is None
    assert corridor_for(Band.GHZ_2, model).low == -75


def test_6ghz_has_no_corridor() -> None:
    with pytest.raises(ValueError, match="not evaluated"):
        corridor_for(Band.GHZ_6, PathLossModel.from_preset("Residential"))


@pytest.mark.parametrize(
    ("name", "canonical"), [("open", "Open"), ("OBSTRUCTED", "Obstructed"), ("residential", "Residential")]
)
def test_preset_lookup_ignores_case_and_keeps_the_canonical_name(name: str, canonical: str) -> None:
    model = PathLossModel.from_preset(name)
    assert model.preset == canonical
    assert model.exponent == PATH_LOSS_PRESETS[canonical]


@pytest.mark.parametrize("name", ["Residental", "", "Custom", "Open "])
def test_unknown_preset_is_rejected(name: str) -> None:
    with pytest.raises(ValueError, match="unknown environment preset"):
        PathLossModel.from_preset(name)


@pytest.mark.parametrize("exponent", [0.0, -2.8, math.nan, math.inf, -math.inf])
def test_non_positive_or_non_finite_exponent_is_rejected(exponent: float) -> None:
    with pytest.raises(ValueError, match="finite positive"):
        PathLossModel.custom(exponent)


@pytest.mark.parametrize(
    ("rssi", "inside"), [(-76, True), (-70, True), (-73, True), (-77, False), (-69, False), (-30, False), (-100, False)]
)
def test_corridor_edges_are_inclusive(rssi: int, inside: bool) -> None:
    assert Corridor(low=-76).contains(rssi) is inside


@given(st.sampled_from(sorted(Band)), exponents, edges)
def test_corridor_is_six_db_wide_with_integer_centre(band: Band, exponent: float, edge: CellEdge) -> None:
    if band is Band.GHZ_6:
        return
    corridor = corridor_for(band, PathLossModel.custom(exponent), edge)
    assert corridor.high - corridor.low == CORRIDOR_WIDTH_DB
    assert corridor.center == corridor.low + CORRIDOR_WIDTH_DB // 2


@given(exponents, exponents, edges)
def test_2ghz_corridor_low_is_monotone_decreasing_in_the_exponent(a: float, b: float, edge: CellEdge) -> None:
    low_a = corridor_for(Band.GHZ_2, PathLossModel.custom(a), edge).low
    low_b = corridor_for(Band.GHZ_2, PathLossModel.custom(b), edge).low
    assert (a <= b) == (low_a >= low_b) or low_a == low_b


@given(exponents, edges)
def test_2ghz_corridor_lies_below_the_5ghz_corridor(exponent: float, edge: CellEdge) -> None:
    model = PathLossModel.custom(exponent)
    assert corridor_for(Band.GHZ_2, model, edge).low <= corridor_for(Band.GHZ_5, model, edge).low == edge.dbm


@given(exponents, edges)
def test_2ghz_corridor_is_the_edge_minus_the_rounded_path_loss_delta(exponent: float, edge: CellEdge) -> None:
    model = PathLossModel.custom(exponent)
    assert corridor_for(Band.GHZ_2, model, edge).low == round(edge.dbm - model.delta_db)
