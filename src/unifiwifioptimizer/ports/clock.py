"""Time as a port, so snapshots are reproducible in tests."""

from datetime import datetime
from typing import Protocol


class Clock(Protocol):
    def now(self) -> datetime: ...
