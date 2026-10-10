"""Secret values and the key patterns that identify them in controller data."""

import re
from typing import NoReturn

# Keys whose values are secrets wherever they appear in controller JSON: the controller's own `x_`
# convention plus the shapes observed live outside it (RADIUS `server_certificate_key`, `dh_key`,
# `utm_token`, `peer_to_peer.psk`). Matched case-insensitively against the full key.
SECRET_KEY_PATTERNS: tuple[str, ...] = (
    r"x_.*",
    r".*secret.*",
    r".*_keys?",
    r".*psk.*",
    r".*passphrase.*",
    r".*token.*",
    r".*password.*",
    r".*credential.*",
)
_SECRET_KEY_RE = re.compile("|".join(f"(?:{p})" for p in SECRET_KEY_PATTERNS), re.IGNORECASE)


def is_secret_key(key: str) -> bool:
    return _SECRET_KEY_RE.fullmatch(key) is not None


class Secret:
    """A credential that never leaves through `repr`, `str`, `format`, `dataclasses.asdict` or pickling.

    Deliberately not a dataclass: `asdict` would copy the value into a plain dict. Copies return the same
    object, so a projection of a model carries the opaque `Secret` (and `json.dumps` fails loudly) instead
    of the text. The value is reachable only through `reveal()`, which keeps every disclosure site greppable.
    """

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "Secret(***)"

    def __str__(self) -> str:
        return "***"

    def __bool__(self) -> bool:
        return bool(self._value)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Secret) and other._value == self._value

    def __hash__(self) -> int:
        return hash(("Secret", self._value))

    def __copy__(self) -> "Secret":
        return self

    def __deepcopy__(self, memo: dict[int, object]) -> "Secret":
        return self

    def __reduce__(self) -> NoReturn:
        raise TypeError("Secret cannot be pickled")
