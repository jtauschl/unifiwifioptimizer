"""The read-only use cases behind `sites`, `site` and `config`."""

from dataclasses import dataclass

from unifiwifioptimizer.domain.errors import ConfigError
from unifiwifioptimizer.domain.models import AccessPoint, FieldProblem, MgmtSettings, Site, UnparsableDevice, WlanConfig
from unifiwifioptimizer.ports.controller import ControllerApi


@dataclass(frozen=True, slots=True, kw_only=True)
class SiteSummary:
    site: Site
    access_point_count: int
    unparsable_count: int


@dataclass(frozen=True, slots=True, kw_only=True)
class SitesOverview:
    sites: tuple[SiteSummary, ...]
    problems: tuple[FieldProblem, ...]


def list_sites(api: ControllerApi) -> SitesOverview:
    """Every site with the number of access points the controller reports for it."""
    result = api.sites()
    summaries: list[SiteSummary] = []
    problems = list(result.problems)
    for site in result.items:
        devices = api.devices(site.id)
        problems.extend(devices.problems)
        summaries.append(
            SiteSummary(
                site=site, access_point_count=len(devices.access_points), unparsable_count=len(devices.unparsable)
            )
        )
    return SitesOverview(sites=tuple(summaries), problems=tuple(problems))


def resolve_site(api: ControllerApi, selector: str) -> Site:
    """The site whose id, hidden id or description equals `selector`; ambiguity is an error."""
    result = api.sites()
    matches = [s for s in result.items if selector in (s.id, s.hidden_id, s.description)]
    if not matches:
        raise ConfigError("site", f"no site {selector!r} on this controller")
    if len(matches) > 1:
        raise ConfigError("site", f"{selector!r} matches more than one site; use the site id")
    return matches[0]


@dataclass(frozen=True, slots=True, kw_only=True)
class SiteOverview:
    site: Site
    wlans: tuple[WlanConfig, ...]
    access_points: tuple[AccessPoint, ...]
    unparsable_devices: tuple[UnparsableDevice, ...]
    mgmt: MgmtSettings | None
    problems: tuple[FieldProblem, ...]


def show_site(api: ControllerApi, selector: str, with_mgmt: bool = False) -> SiteOverview:
    site = resolve_site(api, selector)
    devices = api.devices(site.id)
    wlans = api.wlans(site.id)
    mgmt = api.settings(site.id) if with_mgmt else None
    problems = devices.problems + wlans.problems + (mgmt.problems if mgmt is not None else ())
    return SiteOverview(
        site=site,
        wlans=wlans.items,
        access_points=devices.access_points,
        unparsable_devices=devices.unparsable,
        mgmt=mgmt.mgmt if mgmt is not None else None,
        problems=problems,
    )
