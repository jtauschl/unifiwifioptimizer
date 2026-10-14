import json
import unicodedata
from dataclasses import replace
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from unifiwifioptimizer.adapters.unifi import parse
from unifiwifioptimizer.app.use_cases import SiteOverview, SitesOverview, SiteSummary
from unifiwifioptimizer.domain.models import FieldProblem, Site, UnparsableDevice
from unifiwifioptimizer.report.safe_text import UNSAFE_CATEGORIES, safe_text
from unifiwifioptimizer.report.text import render_problems, render_site, render_sites

FIXTURES = Path(__file__).parents[2] / "fixtures"


@pytest.mark.security("T12")
def test_safe_text_strips_escapes_controls_and_bidi_and_truncates() -> None:
    assert safe_text("plain name") == "plain name"
    assert safe_text("\x1b[31mred\x1b[0m") == "red"
    assert safe_text("a\x00b\x7fc\nd") == "a�b�c�d"
    assert safe_text("x\u202ey\u2066z\u200f") == "x�y�z�"
    assert safe_text("Küche Ü", 10) == "Küche Ü"
    assert safe_text("a" * 70) == "a" * 63 + "…"
    assert len(safe_text("a" * 70, 10)) == 10


@pytest.mark.security("T12")
def test_render_sites_table_and_empty_case() -> None:
    site = Site(id="default", description="Site-1\x1b[0m", hidden_id=None, device_count=11)
    overview = SitesOverview(sites=(SiteSummary(site=site, access_point_count=4, unparsable_count=1),), problems=())
    text = render_sites(overview)
    assert "Site ID" in text and "default" in text and "Site-1" in text and "4 (+1 unparsable)" in text
    assert "\x1b" not in text
    assert "No UniFi sites" in render_sites(SitesOverview(sites=(), problems=()))


@pytest.mark.security("T12")
def test_render_site_lists_wlans_access_points_radios_and_unparsable_devices() -> None:
    devices = parse.parse_devices(json.loads((FIXTURES / "stat_device.json").read_text()))
    wlans = parse.parse_wlans(json.loads((FIXTURES / "list_wlanconf.json").read_text()))
    overview = SiteOverview(
        site=Site(id="default", description="Site-1", hidden_id="default", device_count=11),
        wlans=wlans.items,
        access_points=devices.access_points,
        unparsable_devices=(UnparsableDevice(mac=None, name="Attic\x00AP", reason="$.data[9].mac: expected a string"),),
        mgmt=None,
        problems=(FieldProblem("$.data[0].x", "outside 0..1"),),
    )
    text = render_site(overview)
    assert "SSID-1 (enabled)" in text and "SSID-2 (disabled)" in text
    assert "AP-1 (UAL6, 02:00:00:00:00:04) 2.4 GHz ch auto/20 MHz, 5 GHz ch auto/80 MHz" in text
    assert "AP-2 (UAPA693, 02:00:00:00:00:08) 2.4 GHz ch 1/20 MHz, 5 GHz ch 60/80 MHz" in text
    assert "Attic�AP: not usable ($.data[9].mac: expected a string)" in text
    assert "1 controller field(s) could not be used" in text and "$.data[0].x: outside 0..1" in text


def test_render_problems_caps_the_list() -> None:
    problems = tuple(FieldProblem(f"$.data[{i}].x", "bad") for i in range(25))
    text = render_problems(problems)
    assert "25 controller field(s)" in text and "... and 5 more" in text and render_problems(()) == ""


@pytest.mark.security("T12")
@given(st.text(min_size=0, max_size=200))
def test_no_unsafe_character_survives_safe_text(value: str) -> None:
    rendered = safe_text(value, max_chars=400)
    assert all(unicodedata.category(char) not in UNSAFE_CATEGORIES for char in rendered)
    assert "\x1b" not in rendered


@pytest.mark.security("T12")
def test_an_ssid_with_escapes_is_sanitised_in_the_site_text() -> None:
    wlans = parse.parse_wlans(json.loads((FIXTURES / "list_wlanconf.json").read_text()))
    hostile = replace(wlans.items[0], name="\x1b]0;pwn\x07SSID‮-X")
    overview = SiteOverview(
        site=Site(id="default", description="Site-1", hidden_id="default", device_count=1),
        wlans=(hostile,),
        access_points=(),
        unparsable_devices=(),
        mgmt=None,
        problems=(),
    )
    text = render_site(overview)
    assert "\x1b" not in text and "\x07" not in text and "‮" not in text
    assert "0;pwn�SSID�-X" in text
