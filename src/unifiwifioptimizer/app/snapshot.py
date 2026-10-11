"""One site, read completely through the controller port."""

from unifiwifioptimizer.domain.models import Site, SiteSnapshot
from unifiwifioptimizer.ports.clock import Clock
from unifiwifioptimizer.ports.controller import ControllerApi


def build_snapshot(api: ControllerApi, site: Site, clock: Clock, with_clients: bool) -> SiteSnapshot:
    """Every endpoint the analysis needs; the client picture only on request (it is the privacy-heavy one)."""
    devices = api.devices(site.id)
    wlans = api.wlans(site.id)
    groups = api.ap_groups(site.id)
    settings = api.settings(site.id)
    clients = api.clients(site.id) if with_clients else None
    problems = devices.problems + wlans.problems + groups.problems + settings.problems
    if clients is not None:
        problems += clients.problems
    return SiteSnapshot(
        site=site,
        captured_at=clock.now(),
        access_points=devices.access_points,
        unparsable_devices=devices.unparsable,
        wlans=wlans.items,
        ap_groups=groups.items,
        settings=settings.settings,
        mgmt=settings.mgmt,
        clients=clients.items if clients is not None else None,
        problems=problems,
    )
