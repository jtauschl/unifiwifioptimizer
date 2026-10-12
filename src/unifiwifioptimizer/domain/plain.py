"""The models as plain JSON-ready values, one walker for every consumer.

Not `dataclasses.asdict`: that deep-copies and fails on the read-only mappings the models carry. Enums
become their values, datetimes ISO 8601, addresses text, bytes hex, sets sorted lists, mappings objects.
A `Secret` is the only value the walker decides about: the report refuses it (none is reachable from a
report, and a renderer must never learn otherwise by printing one), the diagnostic dump masks it.
"""

import dataclasses
from collections.abc import Mapping
from datetime import datetime
from enum import Enum
from ipaddress import IPv4Address, IPv6Address
from types import MappingProxyType
from typing import Any

from unifiwifioptimizer.domain.secrets import Secret

MASK = "***"


class SecretPolicy(Enum):
    REFUSE = "refuse"
    MASK = "mask"


def plain(value: object, secrets: SecretPolicy) -> Any:
    if isinstance(value, Secret):
        if secrets is SecretPolicy.REFUSE:
            raise TypeError("a secret has no place in a report")
        return MASK
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {f.name: plain(getattr(value, f.name), secrets) for f in dataclasses.fields(value)}
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Mapping | MappingProxyType):
        return {str(plain(k, secrets)): plain(v, secrets) for k, v in value.items()}
    if isinstance(value, frozenset | set):
        return sorted((plain(v, secrets) for v in value), key=repr)
    if isinstance(value, list | tuple):
        return [plain(v, secrets) for v in value]
    if isinstance(value, IPv4Address | IPv6Address):
        return str(value)
    if isinstance(value, bytes):
        return value.hex()
    return value
