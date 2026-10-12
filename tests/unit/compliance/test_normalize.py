"""The controller-field → profile-vocabulary mapping, including the cases the legacy shell suite pinned."""

import pytest
from hypothesis import given
from hypothesis import strategies as st

from unifiwifioptimizer.compliance.normalize import (
    Unrecognised,
    bands_label,
    dtim_mode,
    minrate_mode,
    pmf_mode,
    rate_label,
    rekey_label,
    security_protocol,
)
from unifiwifioptimizer.domain.models import Band
from unifiwifioptimizer.domain.profile import DtimMode, MinRateMode, PmfMode, SecurityProtocol

from .builders import wlan


def protocol(security: str | None, wpa_mode: str | None, wpa3: bool | None, transition: bool | None) -> object:
    result = security_protocol(
        wlan(security=security, wpa_mode=wpa_mode, wpa3_support=wpa3, wpa3_transition=transition)
    )
    return result.value if isinstance(result, SecurityProtocol) else result


def test_state_wpa3_enterprise() -> None:
    assert protocol("wpaeap", None, True, False) == "WPA3 Enterprise"


def test_state_wpa2_wpa3_enterprise() -> None:
    assert protocol("wpaeap", None, True, True) == "WPA2/WPA3 Enterprise"


def test_state_wpa3_personal() -> None:
    assert protocol("wpapsk", None, True, False) == "WPA3"


def test_state_wpa2_wpa3_personal() -> None:
    assert protocol("wpapsk", None, True, True) == "WPA2/WPA3"


def test_state_owe() -> None:
    assert protocol("open", None, True, False) == "Enhanced Open (OWE)"


def test_state_owe_transition() -> None:
    assert protocol("open", None, True, True) == "Enhanced Open with Transition"


def test_state_open_wpa2_and_wpa2_enterprise() -> None:
    assert protocol("open", None, False, False) == "Open"
    assert protocol("open", None, None, None) == "Open"
    assert protocol("wpapsk", "wpa2", False, False) == "WPA2"
    assert protocol("wpapsk", "wpa2", None, None) == "WPA2"
    assert protocol("wpaeap", "wpa2", False, False) == "WPA2 Enterprise"
    assert protocol("wpa-enterprise", "wpa2", None, None) == "WPA2 Enterprise"
    # A transition flag without WPA3 support is meaningless and ignored.
    assert protocol("wpapsk", "wpa2", False, True) == "WPA2"


def test_state_not_sent_is_none_and_sent_but_unknown_is_unrecognised_with_the_raw_pair() -> None:
    assert protocol(None, "wpa2", True, True) is None
    assert protocol("wpapsk", "wpa1", False, False) == Unrecognised("wpapsk/wpa1")
    assert protocol("wpapsk", "auto", None, None) == Unrecognised("wpapsk/auto")
    assert protocol("wpapsk", None, None, None) == Unrecognised("wpapsk/-")
    assert protocol("wpaeap", "wpa1", False, False) == Unrecognised("wpaeap/wpa1")
    assert protocol("wpaeap", None, False, False) == Unrecognised("wpaeap/-")
    # Non-PSK security values are never read as WPA2, whatever wpa_mode says.
    assert protocol("wep", "wpa2", False, False) == Unrecognised("wep/wpa2")
    assert protocol("osen", "wpa2", True, True) == Unrecognised("osen/wpa2")


def test_sae_matches_wpa3_personal() -> None:
    assert SecurityProtocol.WPA3.uses_sae


def test_sae_matches_wpa2_wpa3_personal() -> None:
    assert SecurityProtocol.WPA2_WPA3.uses_sae


def test_sae_rejects_wpa3_enterprise() -> None:
    assert not SecurityProtocol.WPA3_ENTERPRISE.uses_sae


def test_sae_rejects_wpa2_wpa3_enterprise() -> None:
    assert not SecurityProtocol.WPA2_WPA3_ENTERPRISE.uses_sae


def test_sae_rejects_owe() -> None:
    assert not SecurityProtocol.OWE.uses_sae and not SecurityProtocol.OWE_TRANSITION.uses_sae


def test_wpa3_matches_all_four_variants() -> None:
    assert all(
        p.uses_wpa3
        for p in (
            SecurityProtocol.WPA3,
            SecurityProtocol.WPA2_WPA3,
            SecurityProtocol.WPA3_ENTERPRISE,
            SecurityProtocol.WPA2_WPA3_ENTERPRISE,
        )
    )


def test_wpa3_rejects_wpa2_and_owe() -> None:
    assert not any(
        p.uses_wpa3
        for p in (
            SecurityProtocol.WPA2,
            SecurityProtocol.WPA2_ENTERPRISE,
            SecurityProtocol.OPEN,
            SecurityProtocol.OWE,
            SecurityProtocol.OWE_TRANSITION,
        )
    )


def test_protocol_families_and_their_pmf_requirements() -> None:
    assert {p for p in SecurityProtocol if p.is_personal_psk} == {SecurityProtocol.WPA2, SecurityProtocol.WPA2_WPA3}
    required = {PmfMode.REQUIRED}
    at_least_optional = {PmfMode.OPTIONAL, PmfMode.REQUIRED}
    assert SecurityProtocol.WPA3.required_pmf == required
    assert SecurityProtocol.WPA3_ENTERPRISE.required_pmf == required
    assert SecurityProtocol.OWE.required_pmf == required
    assert SecurityProtocol.WPA2_WPA3.required_pmf == {PmfMode.OPTIONAL}
    assert SecurityProtocol.WPA2_WPA3_ENTERPRISE.required_pmf == {PmfMode.OPTIONAL}
    assert SecurityProtocol.OWE_TRANSITION.required_pmf == at_least_optional
    assert SecurityProtocol.OPEN.required_pmf == {PmfMode.DISABLED}
    assert SecurityProtocol.WPA2.required_pmf == set(PmfMode)
    assert SecurityProtocol.WPA2_ENTERPRISE.required_pmf == set(PmfMode)


@given(
    security=st.one_of(
        st.none(), st.sampled_from(["open", "wpapsk", "wpaeap", "wpa-enterprise", "enterprise"]), st.text()
    ),
    wpa_mode=st.one_of(st.none(), st.sampled_from(["wpa1", "wpa2", "wpa3"]), st.text()),
    wpa3=st.one_of(st.none(), st.booleans()),
    transition=st.one_of(st.none(), st.booleans()),
)
def test_security_protocol_is_total_and_never_guesses(
    security: str | None, wpa_mode: str | None, wpa3: bool | None, transition: bool | None
) -> None:
    result = security_protocol(
        wlan(security=security, wpa_mode=wpa_mode, wpa3_support=wpa3, wpa3_transition=transition)
    )
    if security is None:
        assert result is None
    else:
        assert isinstance(result, SecurityProtocol | Unrecognised)
    if isinstance(result, SecurityProtocol):
        if wpa3 is not True:
            assert not result.uses_wpa3
        if security not in ("open", "wpapsk", "wpaeap", "wpa-enterprise", "enterprise"):
            raise AssertionError(f"{security!r} must not map to a protocol")


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("required", PmfMode.REQUIRED),
        ("optional", PmfMode.OPTIONAL),
        ("disabled", PmfMode.DISABLED),
        (None, None),
        ("Required", Unrecognised("Required")),
    ],
)
def test_pmf_mode_maps_only_the_controller_tokens(raw: str | None, expected: object) -> None:
    assert pmf_mode(wlan(pmf_mode=raw)) == expected


def test_minrate_and_dtim_modes_keep_not_sent_and_unknown_apart() -> None:
    assert minrate_mode(wlan(minrate_setting_preference="auto")) is MinRateMode.AUTO
    assert minrate_mode(wlan(minrate_setting_preference="manual")) is MinRateMode.MANUAL
    assert minrate_mode(wlan(minrate_setting_preference=None)) is None
    assert minrate_mode(wlan(minrate_setting_preference="Manual")) == Unrecognised("Manual")
    assert dtim_mode(wlan(dtim_mode="default")) is DtimMode.DEFAULT
    assert dtim_mode(wlan(dtim_mode="custom")) is DtimMode.CUSTOM
    assert dtim_mode(wlan(dtim_mode=None)) is None
    assert dtim_mode(wlan(dtim_mode="auto")) == Unrecognised("auto")


def test_labels() -> None:
    assert rate_label(12000) == "12 Mbps" and rate_label(5500) == "5.5 Mbps" and rate_label(1000) == "1 Mbps"
    assert rate_label(1050) == "1.05 Mbps" and rate_label(1005) == "1.005 Mbps"
    assert rekey_label(0) == "Disabled" and rekey_label(3600) == "3600 s"
    assert bands_label(frozenset({Band.GHZ_5, Band.GHZ_2})) == "2.4 GHz, 5 GHz"
    assert bands_label(frozenset()) == "n/a"
