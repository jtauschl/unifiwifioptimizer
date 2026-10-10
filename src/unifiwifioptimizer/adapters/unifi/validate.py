"""Limits and typed accessors for controller JSON (plan: untrusted-input table).

Every accessor names the path of the offending element in its `SchemaError`; an invalid optional field
is reported through `FieldProblem` so the caller can drop the field and keep the record. Error texts
carry the path and a static description, never a controller value.
"""

import math
import re
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import TypeVar

from unifiwifioptimizer.domain.errors import SchemaError

T = TypeVar("T")

MAX_DEPTH = 32
MAX_DEVICES = 1000
MAX_WLANS = 200
MAX_SITES = 500
MAX_CLIENTS = 5000
MAX_AP_GROUPS = 500
MAX_SETTINGS = 500
MAX_RADIOS_PER_DEVICE = 8
MAX_VAPS_PER_DEVICE = 64
MAX_CHANNEL_LIST = 256
MAX_WIDTH_LIST = 8
MAX_BLACKLIST = 1024
MAX_WLAN_BANDS = 4
MAX_OPTIMIZE_TARGETS = 8
# Byte caps by kind of text: enumerated tokens, short technical names, identifiers/versions/cron, display
# names and model codes (plan: names/models ≤ 128), the controller-managed SSH password.
MAX_TOKEN_BYTES = 16
MAX_SHORT_TEXT_BYTES = 32
MAX_ID_BYTES = 64
MAX_NAME_BYTES = 128
MAX_SSID_BYTES = 32
MAX_PASSWORD_BYTES = 256
MAX_LIST_ITEMS = 10_000

# The plan's open interval -100 < x < 0.
RSSI_RANGE = range(-99, 0)
NOISE_RANGE = range(-120, 0)
TX_POWER_RANGE = range(0, 41)
CHANNEL_RANGE = range(1, 254)
# HT40 secondary position: below, none, above.
EXTENSION_CHANNEL_RANGE = range(-1, 2)
WIDTHS_MHZ = frozenset({20, 40, 80, 160, 240, 320})
PERCENT_RANGE = range(0, 101)
DTIM_RANGE = range(1, 256)
COUNTRY_RANGE = range(0, 1000)
ANTENNA_GAIN_RANGE = range(0, 31)
SPATIAL_STREAMS_RANGE = range(1, 9)
CLIENT_COUNT_RANGE = range(0, 10_001)
DEVICE_COUNT_RANGE = range(0, 100_001)
MINRATE_KBPS_RANGE = range(1000, 1_000_001)
GROUP_REKEY_RANGE = range(0, 86_401)
SAE_COUNTER_RANGE = range(0, 1001)

_MAC_RE = re.compile(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}")
_PLAIN_KEY_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")

Json = object
Accessor = Callable[[Json, str], T]


@dataclass(frozen=True, slots=True)
class FieldProblem:
    """An optional field that was present but invalid; the record keeps None in its place."""

    path: str
    message: str


def _segment(key: object) -> str:
    # Error paths end up in reports, so a controller-chosen key is shown only when it is a plain identifier.
    if isinstance(key, int):
        return f"[{key}]"
    return f".{key}" if isinstance(key, str) and _PLAIN_KEY_RE.fullmatch(key) else ".<key>"


def walk_depth(value: Json) -> None:
    """Reject nesting deeper than `MAX_DEPTH`, iteratively so the check itself cannot overflow the stack.

    The stack carries parent links instead of rendered paths, so a long controller key is referenced
    once rather than copied into every descendant's path; the path is rendered only for the error.
    """
    links: list[tuple[int, object]] = []
    stack: list[tuple[Json, int, int]] = [(value, 0, -1)]
    while stack:
        node, depth, link = stack.pop()
        if depth > MAX_DEPTH:
            raise SchemaError(_render(links, link), f"nesting deeper than {MAX_DEPTH}")
        if isinstance(node, dict):
            for key, child in node.items():
                links.append((link, key))
                stack.append((child, depth + 1, len(links) - 1))
        elif isinstance(node, list):
            if len(node) > MAX_LIST_ITEMS:
                raise SchemaError(_render(links, link), f"more than {MAX_LIST_ITEMS} items")
            for i, child in enumerate(node):
                links.append((link, i))
                stack.append((child, depth + 1, len(links) - 1))


def _render(links: Sequence[tuple[int, object]], link: int) -> str:
    segments: list[str] = []
    while link >= 0:
        parent, key = links[link]
        segments.append(_segment(key))
        link = parent
    return "$" + "".join(reversed(segments))


def data_list(payload: Json, max_items: int) -> list[Json]:
    """The `data` array of a controller response; its elements are checked by the caller."""
    walk_depth(payload)
    body = require_mapping(payload, "$")
    items = body.get("data")
    if not isinstance(items, list):
        raise SchemaError("$.data", "expected a list")
    if len(items) > max_items:
        raise SchemaError("$.data", f"more than {max_items} items")
    return items


def require_mapping(value: Json, path: str) -> Mapping[str, Json]:
    if not isinstance(value, dict):
        raise SchemaError(path, "expected an object")
    return value


def require_list(value: Json, path: str, max_items: int) -> list[Json]:
    if not isinstance(value, list):
        raise SchemaError(path, "expected a list")
    if len(value) > max_items:
        raise SchemaError(path, f"more than {max_items} items")
    return value


def require_str(value: Json, path: str, max_bytes: int) -> str:
    if not isinstance(value, str):
        raise SchemaError(path, "expected a string")
    if len(value.encode("utf-8")) > max_bytes:
        raise SchemaError(path, f"longer than {max_bytes} bytes")
    return value


def require_int(value: Json, path: str, allowed: range | None = None) -> int:
    # bool is an int subclass in Python; a flag is never a valid number here.
    if isinstance(value, bool) or not isinstance(value, int):
        # NaN and ±inf are not integral, so `is_integer()` already rejects them.
        if isinstance(value, float) and value.is_integer():
            value = int(value)
        else:
            raise SchemaError(path, "expected an integer")
    if allowed is not None and value not in allowed:
        raise SchemaError(path, f"outside {allowed.start}..{allowed.stop - 1}")
    return value


def require_bool(value: Json, path: str) -> bool:
    if not isinstance(value, bool):
        raise SchemaError(path, "expected a boolean")
    return value


def require_mac(value: Json, path: str) -> str:
    text = require_str(value, path, 17).lower()
    if not _MAC_RE.fullmatch(text):
        raise SchemaError(path, "expected a MAC address")
    return text


def require_ip(value: Json, path: str) -> IPv4Address | IPv6Address:
    text = require_str(value, path, 45)
    try:
        address = ip_address(text)
    except ValueError:
        raise SchemaError(path, "expected an IP address") from None
    # An IPv6 zone id is free text that would travel into the ssh argv and the report.
    if isinstance(address, IPv6Address) and address.scope_id is not None:
        raise SchemaError(path, "expected an IP address")
    return address


class Fields:
    """Typed access to one record; optional accessors collect problems instead of raising."""

    def __init__(self, record: Mapping[str, Json], path: str, problems: list[FieldProblem] | None = None) -> None:
        self._record = record
        self._path = path
        self.problems: list[FieldProblem] = [] if problems is None else problems

    def path(self, key: str) -> str:
        return f"{self._path}.{key}"

    @property
    def path_self(self) -> str:
        return self._path

    def raw(self, key: str) -> Json:
        return self._record.get(key)

    def has(self, key: str) -> bool:
        return key in self._record and self._record[key] is not None

    def string(self, key: str, max_bytes: int = MAX_NAME_BYTES) -> str:
        return require_str(self._record.get(key), self.path(key), max_bytes)

    def integer(self, key: str, allowed: range | None = None) -> int:
        return require_int(self._record.get(key), self.path(key), allowed)

    def mac(self, key: str) -> str:
        return require_mac(self._record.get(key), self.path(key))

    def ip(self, key: str) -> IPv4Address | IPv6Address:
        return require_ip(self._record.get(key), self.path(key))

    def sequence(self, key: str, max_items: int) -> list[Json]:
        return require_list(self._record.get(key), self.path(key), max_items)

    def records(self, key: str, max_items: int) -> list["Fields"]:
        """A mandatory list of objects; the children report their problems into this record's list."""
        path = self.path(key)
        items = self.sequence(key, max_items)
        return [
            Fields(require_mapping(item, f"{path}[{i}]"), f"{path}[{i}]", self.problems) for i, item in enumerate(items)
        ]

    def opt_sequence(self, key: str, max_items: int) -> list[Json] | None:
        """An optional list: absent → None; not a list or too long → None plus one problem."""
        if not self.has(key):
            return None
        try:
            return self.sequence(key, max_items)
        except SchemaError as exc:
            self.problems.append(FieldProblem(exc.path, exc.detail))
            return None

    def opt_records(self, key: str, max_items: int) -> list["Fields"]:
        """Optional list of objects; an element that is not an object is skipped with its own problem."""
        children = self.opt_items(key, max_items, lambda v, p: Fields(require_mapping(v, p), p, self.problems))
        return list(children or ())

    def opt_items(self, key: str, max_items: int, accessor: Accessor[T]) -> tuple[T, ...] | None:
        """Optional list read element by element: an invalid element is one problem and is skipped, an
        absent or invalid list is None (plus one problem when invalid)."""
        items = self.opt_sequence(key, max_items)
        if items is None:
            return None
        values: list[T] = []
        for i, item in enumerate(items):
            try:
                values.append(accessor(item, f"{self.path(key)}[{i}]"))
            except SchemaError as exc:
                self.problems.append(FieldProblem(exc.path, exc.detail))
        return tuple(values)

    def opt_object(self, key: str) -> "Fields | None":
        value = self._record.get(key)
        if value is None:
            return None
        if not isinstance(value, dict):
            self.problems.append(FieldProblem(self.path(key), "expected an object"))
            return None
        return Fields(value, self.path(key), self.problems)

    def opt_string(self, key: str, max_bytes: int = MAX_NAME_BYTES) -> str | None:
        return self._optional(key, lambda v, p: require_str(v, p, max_bytes))

    def opt_integer(self, key: str, allowed: range | None = None, sentinel: int | None = None) -> int | None:
        value = self._optional(key, lambda v, p: require_int(v, p, None))
        if value is None or value == sentinel:
            return None
        if allowed is not None and value not in allowed:
            self.problems.append(FieldProblem(self.path(key), f"outside {allowed.start}..{allowed.stop - 1}"))
            return None
        return value

    def opt_float(self, key: str, low: float, high: float) -> float | None:
        value = self._record.get(key)
        if value is None:
            return None
        # `isfinite` only on floats: it converts an int and overflows past 1e308; the comparison below is
        # exact for any int.
        if (
            isinstance(value, bool)
            or not isinstance(value, int | float)
            or (isinstance(value, float) and not math.isfinite(value))
        ):
            self.problems.append(FieldProblem(self.path(key), "expected a finite number"))
            return None
        if not low <= value <= high:
            self.problems.append(FieldProblem(self.path(key), f"outside {low}..{high}"))
            return None
        return float(value)

    def opt_bool(self, key: str) -> bool | None:
        return self._optional(key, require_bool)

    def flag(self, key: str, default: bool = False) -> bool:
        """An optional boolean read as a flag: absent or invalid counts as `default`."""
        value = self.opt_bool(key)
        return default if value is None else value

    def opt_mac(self, key: str) -> str | None:
        return self._optional(key, require_mac)

    def opt_string_list(self, key: str, max_items: int, max_bytes: int = MAX_ID_BYTES) -> tuple[str, ...]:
        return self.opt_items(key, max_items, lambda v, p: require_str(v, p, max_bytes)) or ()

    def _optional(self, key: str, accessor: Accessor[T]) -> T | None:
        value = self._record.get(key)
        if value is None:
            return None
        try:
            return accessor(value, self.path(key))
        except SchemaError as exc:
            self.problems.append(FieldProblem(exc.path, exc.detail))
            return None


def iter_records(items: Sequence[Json], path: str, problems: list[FieldProblem]) -> Iterator[Fields]:
    """The objects of a record list; an element that is not an object becomes a problem and is skipped."""
    for index, item in enumerate(items):
        if isinstance(item, dict):
            yield Fields(item, f"{path}[{index}]", problems)
        else:
            problems.append(FieldProblem(f"{path}[{index}]", "expected an object"))
