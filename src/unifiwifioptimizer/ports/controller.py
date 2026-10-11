"""The controller as the core sees it: typed records per endpoint, never raw JSON."""

from typing import Protocol

from unifiwifioptimizer.domain.models import (
    ApGroup,
    ClientSighting,
    DevicesResult,
    ParsedList,
    SettingsResult,
    Site,
    WlanConfig,
)


class ControllerApi(Protocol):
    """Read-only access to one UniFi Network Application; every call maps one endpoint onto models."""

    def sites(self) -> ParsedList[Site]: ...

    def devices(self, site_id: str) -> DevicesResult: ...

    def wlans(self, site_id: str) -> ParsedList[WlanConfig]: ...

    def ap_groups(self, site_id: str) -> ParsedList[ApGroup]: ...

    def settings(self, site_id: str) -> SettingsResult: ...

    def clients(self, site_id: str) -> ParsedList[ClientSighting]: ...
