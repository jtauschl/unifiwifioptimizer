"""Domain value types shared by the core."""

from enum import StrEnum


class Band(StrEnum):
    """Radio band; the controller's radio names (`ng`, `na`, `6e`) are mapped to these by the adapter."""

    GHZ_2 = "2g"
    GHZ_5 = "5g"
    GHZ_6 = "6g"

    @property
    def label(self) -> str:
        return {Band.GHZ_2: "2.4 GHz", Band.GHZ_5: "5 GHz", Band.GHZ_6: "6 GHz"}[self]
