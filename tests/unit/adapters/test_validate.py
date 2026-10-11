import math
from ipaddress import IPv4Address, IPv6Address

import pytest
from hypothesis import given
from hypothesis import strategies as st

from unifiwifioptimizer.adapters.unifi import validate
from unifiwifioptimizer.adapters.unifi.validate import (
    MAX_DEPTH,
    MAX_LIST_ITEMS,
    Fields,
    data_list,
    iter_records,
    require_bool,
    require_int,
    require_ip,
    require_list,
    require_mac,
    require_mapping,
    require_str,
    walk_depth,
)
from unifiwifioptimizer.domain.errors import SchemaError
from unifiwifioptimizer.domain.models import FieldProblem

octets = st.integers(0, 255)


def test_require_int_accepts_integers_and_integral_floats_only() -> None:
    assert require_int(5, "$.x") == 5
    assert require_int(5.0, "$.x") == 5 and type(require_int(6.0, "$.x")) is int
    for bad in (True, False, 5.5, math.nan, math.inf, "5", None, [5]):
        with pytest.raises(SchemaError) as exc:
            require_int(bad, "$.x")
        assert exc.value.path == "$.x"


@given(st.integers(-200, 200))
def test_require_int_range_is_inclusive_of_both_ends(value: int) -> None:
    allowed = range(-100, 0)
    if value in allowed:
        assert require_int(value, "$", allowed) == value
    else:
        with pytest.raises(SchemaError, match=r"outside -100\.\.-1"):
            require_int(value, "$", allowed)


def test_require_str_limits_utf8_bytes_not_characters() -> None:
    assert require_str("äöü", "$", 6) == "äöü"
    with pytest.raises(SchemaError, match="longer than 5 bytes"):
        require_str("äöü", "$", 5)
    with pytest.raises(SchemaError, match="expected a string"):
        require_str(1, "$", 5)


def test_require_bool_rejects_everything_but_booleans() -> None:
    assert require_bool(True, "$") is True
    for bad in (1, 0, "true", None):
        with pytest.raises(SchemaError):
            require_bool(bad, "$")


@given(st.lists(octets, min_size=6, max_size=6), st.booleans())
def test_require_mac_normalises_case(parts: list[int], upper: bool) -> None:
    text = ":".join(f"{p:02x}" for p in parts)
    assert require_mac(text.upper() if upper else text, "$") == text


@pytest.mark.parametrize("bad", ["02:00:00:00:00", "02-00-00-00-00-01", "0200.0000.0001", "", "zz:00:00:00:00:01"])
def test_require_mac_rejects_other_shapes(bad: str) -> None:
    with pytest.raises(SchemaError, match="expected a MAC address"):
        require_mac(bad, "$")


def test_require_ip_accepts_both_families() -> None:
    assert require_ip("192.0.2.1", "$") == IPv4Address("192.0.2.1")
    assert require_ip("fe80::1", "$") == IPv6Address("fe80::1")
    with pytest.raises(SchemaError, match="expected an IP address"):
        require_ip("192.0.2.256", "$")


def test_require_list_admits_exactly_the_cap() -> None:
    assert require_list([1, 2, 3], "$", 3) == [1, 2, 3]
    walk_depth({"data": [0] * MAX_LIST_ITEMS})


def test_has_treats_an_explicit_null_as_absent() -> None:
    fields = Fields({"a": None, "b": 0}, "$")
    assert not fields.has("a") and fields.has("b") and fields.opt_records("a", 5) == []


def test_opt_records_skips_non_objects_and_reports_an_invalid_list_once() -> None:
    fields = Fields({"items": "x", "ok": [{"k": 1}], "mixed": [{"a": 1}, 1, {"b": 2}]}, "$")
    assert fields.opt_records("items", 5) == []
    assert [f.path_self for f in fields.opt_records("ok", 5)] == ["$.ok[0]"]
    assert [f.path_self for f in fields.opt_records("mixed", 5)] == ["$.mixed[0]", "$.mixed[2]"]
    assert fields.problems == [
        FieldProblem("$.items", "expected a list"),
        FieldProblem("$.mixed[1]", "expected an object"),
    ]


def test_require_mapping_and_list_name_the_path() -> None:
    with pytest.raises(SchemaError, match=r"\$\.data\[3\]: expected an object"):
        require_mapping([], "$.data[3]")
    with pytest.raises(SchemaError, match="expected a list"):
        require_list({}, "$", 1)
    with pytest.raises(SchemaError, match="more than 1 items"):
        require_list([1, 2], "$", 1)


def test_walk_depth_rejects_deep_nesting_without_recursing() -> None:
    nested: object = []
    for _ in range(5000):
        nested = [nested]
    with pytest.raises(SchemaError, match=f"nesting deeper than {MAX_DEPTH}"):
        walk_depth(nested)
    exactly: object = 0
    for _ in range(MAX_DEPTH):
        exactly = {"k": exactly}
    walk_depth(exactly)
    with pytest.raises(SchemaError, match=f"nesting deeper than {MAX_DEPTH}"):
        walk_depth({"k": exactly})
    with pytest.raises(SchemaError, match=f"more than {MAX_LIST_ITEMS} items"):
        walk_depth({"data": [0] * (MAX_LIST_ITEMS + 1)})


def test_data_list_requires_the_envelope_shape() -> None:
    assert data_list({"data": [{"a": 1}]}, 5) == [{"a": 1}]
    with pytest.raises(SchemaError, match=r"\$\.data: expected a list"):
        data_list({"data": {}}, 5)
    with pytest.raises(SchemaError, match=r"\$\.data: more than 1 items"):
        data_list({"data": [{}, {}]}, 1)
    assert data_list({"data": [1]}, 5) == [1]
    with pytest.raises(SchemaError, match=r"\$: expected an object"):
        data_list([], 5)


def test_required_accessors_raise_with_the_field_path() -> None:
    fields = Fields({"mac": "02:00:00:00:00:01", "n": 3, "ip": "192.0.2.1", "items": [1]}, "$.data[0]")
    assert fields.string("mac") == "02:00:00:00:00:01"
    assert fields.mac("mac") == "02:00:00:00:00:01"
    assert fields.integer("n", range(0, 10)) == 3
    assert fields.ip("ip") == IPv4Address("192.0.2.1")
    assert fields.sequence("items", 5) == [1]
    assert fields.has("n") and not fields.has("missing")
    assert fields.raw("missing") is None
    with pytest.raises(SchemaError, match=r"\$\.data\[0\]\.missing: expected a string"):
        fields.string("missing")
    assert fields.problems == []


def test_optional_accessors_record_a_problem_and_return_none() -> None:
    record = {"s": 1, "i": "x", "b": "no", "m": "nope", "f": "1.5", "l": [1, "ok"], "ok": 7, "neg": -1}
    fields = Fields(record, "$")
    assert fields.opt_string("s") is None
    assert fields.opt_integer("i") is None
    assert fields.opt_bool("b") is None
    assert fields.opt_mac("m") is None
    assert fields.opt_float("f", 0, 10) is None
    assert fields.opt_string_list("l", 5) == ("ok",)
    assert fields.opt_integer("ok", range(0, 10)) == 7
    assert fields.opt_integer("neg", range(0, 10), sentinel=-1) is None
    assert fields.opt_integer("absent") is None
    assert fields.opt_string_list("absent", 5) == ()
    assert fields.opt_sequence("absent", 5) is None
    assert fields.flag("absent") is False and fields.flag("absent", default=True) is True
    assert fields.opt_object("absent") is None
    assert fields.opt_object("s") is None
    nested = Fields({"inner": {"k": 1}}, "$", fields.problems).opt_object("inner")
    assert nested is not None and nested.integer("k") == 1 and nested.path("k") == "$.inner.k"
    assert [p.path for p in fields.problems] == ["$.s", "$.i", "$.b", "$.m", "$.f", "$.l[0]", "$.s"]


def test_optional_lists_skip_invalid_elements_and_report_invalid_lists_once() -> None:
    fields = Fields({"texts": ["a", 1, "b" * 65, "c"], "long": [1, 2, 3], "notalist": "x"}, "$")
    assert fields.opt_string_list("texts", 5) == ("a", "c")
    assert fields.opt_string_list("long", 2) == ()
    assert fields.opt_string_list("notalist", 5) == ()
    assert fields.problems == [
        FieldProblem("$.texts[1]", "expected a string"),
        FieldProblem("$.texts[2]", "longer than 64 bytes"),
        FieldProblem("$.long", "more than 2 items"),
        FieldProblem("$.notalist", "expected a list"),
    ]


def test_optional_range_and_float_checks_report_the_value() -> None:
    fields = Fields({"i": 200, "f": math.nan, "g": 101.0, "h": 2}, "$")
    assert fields.opt_integer("i", range(0, 100)) is None
    assert fields.opt_float("f", 0, 100) is None
    assert fields.opt_float("g", 0, 100) is None
    assert fields.opt_float("h", 0, 100) == 2.0
    assert fields.problems == [
        FieldProblem("$.i", "outside 0..99"),
        FieldProblem("$.f", "expected a finite number"),
        FieldProblem("$.g", "outside 0..100"),
    ]
    assert Fields({"h": 100.0, "b": True}, "$").opt_float("h", 0, 100) == 100.0
    bools = Fields({"b": True}, "$")
    assert bools.opt_float("b", 0, 100) is None and bools.problems == [FieldProblem("$.b", "expected a finite number")]


def test_iter_records_numbers_paths_and_skips_non_objects() -> None:
    problems: list[FieldProblem] = []
    assert [f.path("x") for f in iter_records([{}, 1, {}], "$.data", problems)] == ["$.data[0].x", "$.data[2].x"]
    assert problems == [FieldProblem("$.data[1]", "expected an object")]


def test_require_ip_rejects_ipv6_zone_ids() -> None:
    for bad in ("fe80::1%en0", "fe80::1%-oProxyCommand=sh", "fe80::1%ü"):
        with pytest.raises(SchemaError, match="expected an IP address"):
            require_ip(bad, "$")


def test_depth_error_paths_mask_controller_keys() -> None:
    hostile: object = 0
    for _ in range(MAX_DEPTH + 1):
        hostile = {"TOPSECRET.example.com": hostile}
    with pytest.raises(SchemaError) as exc:
        walk_depth({"ok_key": hostile})
    assert "TOPSECRET" not in str(exc.value) and exc.value.path.startswith("$.ok_key.<key>.<key>")
    nested_list: object = [[0]]
    for _ in range(MAX_DEPTH):
        nested_list = {"k": [nested_list]}
    with pytest.raises(SchemaError, match=r"\$\.k\[0\]\.k\[0\]"):
        walk_depth(nested_list)


def test_depth_error_paths_show_plain_keys_up_to_64_characters() -> None:
    deep: object = 0
    for _ in range(MAX_DEPTH + 1):
        deep = [deep]
    with pytest.raises(SchemaError) as exc:
        walk_depth({"k" * 64: deep})
    assert exc.value.path.startswith("$." + "k" * 64 + "[0]")
    with pytest.raises(SchemaError) as exc:
        walk_depth({"k" * 65: deep})
    assert exc.value.path.startswith("$.<key>[0]")


def test_opt_items_reads_element_by_element() -> None:
    fields = Fields({"macs": ["02:00:00:00:00:01", "x", "02:00:00:00:00:02"], "bad": 1}, "$")
    assert fields.opt_items("macs", 5, require_mac) == ("02:00:00:00:00:01", "02:00:00:00:00:02")
    assert fields.opt_items("bad", 5, require_mac) is None
    assert fields.opt_items("absent", 5, require_mac) is None
    assert Fields({"empty": []}, "$").opt_items("empty", 5, require_mac) == ()
    assert fields.problems == [
        FieldProblem("$.macs[1]", "expected a MAC address"),
        FieldProblem("$.bad", "expected a list"),
    ]


def test_opt_float_handles_huge_integers_without_overflow() -> None:
    fields = Fields({"huge": 10**400, "neg": -(10**400), "ok": 5}, "$")
    assert fields.opt_float("huge", 0, 100) is None and fields.opt_float("neg", 0, 100) is None
    assert fields.opt_float("ok", 0, 100) == 5.0
    assert fields.problems == [FieldProblem("$.huge", "outside 0..100"), FieldProblem("$.neg", "outside 0..100")]


def test_the_limit_table_matches_the_plan_literally() -> None:
    limits = {
        "MAX_DEPTH": 32, "MAX_DEVICES": 1000, "MAX_WLANS": 200, "MAX_SITES": 500, "MAX_CLIENTS": 5000,
        "MAX_AP_GROUPS": 500, "MAX_SETTINGS": 500, "MAX_RADIOS_PER_DEVICE": 8, "MAX_VAPS_PER_DEVICE": 64,
        "MAX_SSID_BYTES": 32, "MAX_NAME_BYTES": 128, "MAX_ID_BYTES": 64, "MAX_LIST_ITEMS": 10_000,
        "MAX_CHANNEL_LIST": 256, "MAX_WIDTH_LIST": 8, "MAX_BLACKLIST": 1024, "MAX_WLAN_BANDS": 4,
        "MAX_OPTIMIZE_TARGETS": 8, "MAX_TOKEN_BYTES": 16, "MAX_SHORT_TEXT_BYTES": 32, "MAX_PASSWORD_BYTES": 256,
    }  # fmt: skip
    assert {name: getattr(validate, name) for name in limits} == limits
    ranges = {
        "RSSI_RANGE": range(-99, 0), "TX_POWER_RANGE": range(0, 41), "CHANNEL_RANGE": range(1, 254),
        "PERCENT_RANGE": range(0, 101), "DTIM_RANGE": range(1, 256), "COUNTRY_RANGE": range(0, 1000),
        "NOISE_RANGE": range(-120, 0), "EXTENSION_CHANNEL_RANGE": range(-1, 2), "ANTENNA_GAIN_RANGE": range(0, 31),
        "SPATIAL_STREAMS_RANGE": range(1, 9), "CLIENT_COUNT_RANGE": range(0, 10_001),
        "DEVICE_COUNT_RANGE": range(0, 100_001), "MINRATE_KBPS_RANGE": range(1000, 1_000_001),
        "GROUP_REKEY_RANGE": range(0, 86_401), "SAE_COUNTER_RANGE": range(0, 1001),
    }  # fmt: skip
    assert {name: getattr(validate, name) for name in ranges} == ranges
    assert {20, 40, 80, 160, 240, 320} == validate.WIDTHS_MHZ


def test_fields_remember_read_keys_and_count_unread_ones_recursively() -> None:
    record = {"a": 1, "b": {"x": 1, "y": 2}, "c": [{"p": 1, "q": 2}, {"p": 3}], "d": 4}
    fields = Fields(record, "$")
    assert fields.integer("a") == 1
    child = fields.opt_object("b")
    assert child is not None and child.integer("x") == 1
    for entry in fields.opt_records("c", 5):
        entry.opt_integer("p")
    assert fields.read_keys == {"a", "b", "c"}
    # d (own) + y (b) + q (c[0]) = 3; c[1] has nothing unread.
    assert fields.unknown_key_count() == 3
    assert [c.path_self for c in fields.children] == ["$.b", "$.c[0]", "$.c[1]"]


def test_walk_depth_refuses_lone_surrogates_in_values_and_keys() -> None:
    with pytest.raises(SchemaError) as exc:
        walk_depth({"data": [{"name": "ok"}, {"name": "x\ud800y"}]})
    assert exc.value.path == "$.data[1].name" and exc.value.detail == "invalid Unicode"
    with pytest.raises(SchemaError, match="invalid Unicode in a key"):
        walk_depth({"data": [{"\udcff": 1}]})
    walk_depth({"data": [{"name": "\U0001f600 ok"}]})
