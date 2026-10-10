from unifiwifioptimizer.domain.models import Band


def test_band_values_and_labels() -> None:
    assert [(b.value, b.label) for b in Band] == [("2g", "2.4 GHz"), ("5g", "5 GHz"), ("6g", "6 GHz")]
