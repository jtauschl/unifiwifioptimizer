"""The `run` use case: every selected site read, scanned and analysed, in a fixed order.

Everything that can refuse the run happens before the first scan: the environment (OpenSSH) when a site
scans, the scan passwords, every site's existence, every snapshot, every site's credentials and targets.
Then the sites are scanned one after the other (access points serial within a site, docs/ALGORITHM.md §2) and
analysed. The outcome per site is typed; the command line maps it onto exit codes.
"""

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import StrEnum

from unifiwifioptimizer.analysis.inputs import SiteAnalysisInput
from unifiwifioptimizer.analysis.site_analyzer import analyze_site
from unifiwifioptimizer.app.scanning import ScanOrchestrator, build_targets, configured_access_points
from unifiwifioptimizer.app.snapshot import build_snapshot
from unifiwifioptimizer.app.use_cases import resolve_site
from unifiwifioptimizer.config.load import LoadedConfig, require_scan_passwords
from unifiwifioptimizer.config.schema import SiteConfig
from unifiwifioptimizer.domain.analysis import PartialReason
from unifiwifioptimizer.domain.errors import ConfigError
from unifiwifioptimizer.domain.models import Site, SiteSnapshot
from unifiwifioptimizer.domain.profile import ProfileSet
from unifiwifioptimizer.domain.report import SiteReport
from unifiwifioptimizer.domain.scan import ScanTarget, SiteScan
from unifiwifioptimizer.ports.clock import Clock
from unifiwifioptimizer.ports.controller import ControllerApi
from unifiwifioptimizer.ports.progress import Progress
from unifiwifioptimizer.ports.scanner import Scanner

Sleep = Callable[[float], None]
ScannerFactory = Callable[[], Scanner]
EnvironmentCheck = Callable[[], object]


class RunVerdict(StrEnum):
    """What the run as a whole came to; the command line turns it into the exit code."""

    OK = "ok"
    PARTIAL = "partial"
    NO_VERIFIABLE_AP = "no_verifiable_ap"


@dataclass(frozen=True, slots=True, kw_only=True)
class SiteOutcome:
    site_id: str
    scanning: bool
    partial_reasons: tuple[PartialReason, ...]
    scanned_ap_count: int
    verifiable_ap_count: int
    # Access points with at least one host-key failure (unknown or mismatched key), not failures.
    host_key_failed_ap_count: int

    @property
    def no_verifiable_ap(self) -> bool:
        """Exit 5 territory: the site scanned, nobody was verified, and a host key was the reason."""
        return (
            self.scanning
            and self.scanned_ap_count > 0
            and self.verifiable_ap_count == 0
            and self.host_key_failed_ap_count > 0
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class RunResult:
    reports: tuple[SiteReport, ...]
    outcomes: tuple[SiteOutcome, ...]

    @property
    def verdict(self) -> RunVerdict:
        """Order-independent reduction over the sites: no verifiable access point beats partial beats ok."""
        if any(o.no_verifiable_ap for o in self.outcomes):
            return RunVerdict.NO_VERIFIABLE_AP
        if any(o.partial_reasons for o in self.outcomes):
            return RunVerdict.PARTIAL
        return RunVerdict.OK


def select_sites(loaded: LoadedConfig, selectors: Sequence[str] | None) -> list[SiteConfig]:
    """The configured sites to run, every selector matched against the configured site ids."""
    configured = loaded.config.sites
    if not configured:
        raise ConfigError("sites", "no site configured; run `config <site>` to get a skeleton")
    if not selectors:
        return list(configured.values())
    chosen: list[SiteConfig] = []
    for selector in selectors:
        if selector not in configured:
            raise ConfigError("sites", f"{selector!r} is not a configured site id")
        if configured[selector] not in chosen:
            chosen.append(configured[selector])
    return chosen


@dataclass(frozen=True, slots=True, kw_only=True)
class _Prepared:
    site: Site
    config: SiteConfig
    snapshot: SiteSnapshot
    targets: tuple[ScanTarget, ...]
    unknown_names: tuple[str, ...]
    scanning: bool


def run_analysis(
    loaded: LoadedConfig,
    profiles: ProfileSet,
    api: ControllerApi,
    scanner_factory: ScannerFactory,
    clock: Clock,
    sleep: Sleep,
    progress: Progress,
    *,
    sites: Sequence[str] | None = None,
    with_clients: bool = False,
    skip_scan: bool = False,
    environment_check: EnvironmentCheck | None = None,
) -> RunResult:
    selected = select_sites(loaded, sites)
    scanning_sites = [s for s in selected if s.scans and not skip_scan]
    if scanning_sites:
        if environment_check is not None:
            environment_check()
        require_scan_passwords(loaded, scanning_sites)
    # Every site resolved and read before anything is contacted over SSH.
    prepared: list[_Prepared] = []
    for site_cfg in selected:
        site = resolve_site(api, site_cfg.id)
        snapshot = build_snapshot(api, site, clock, with_clients)
        # The shared-name rule is a property of the configuration, so it holds for a site that does not scan too.
        configured_access_points(snapshot, site_cfg)
        scanning = site_cfg in scanning_sites
        targets: tuple[ScanTarget, ...] = ()
        unknown: tuple[str, ...] = ()
        if scanning:
            targets, unknown = build_targets(snapshot, site_cfg, loaded)
        prepared.append(
            _Prepared(
                site=site, config=site_cfg, snapshot=snapshot, targets=targets, unknown_names=unknown, scanning=scanning
            )
        )
    orchestrator = ScanOrchestrator(scanner_factory(), sleep) if scanning_sites else None
    reports: list[SiteReport] = []
    outcomes: list[SiteOutcome] = []
    for item in prepared:
        progress.site_started(item.site.id, item.scanning)
        scan: SiteScan | None = None
        if item.scanning and orchestrator is not None:
            ssh = item.config.ssh
            concurrency = ssh.scan_concurrency if ssh is not None else 1
            scan = orchestrator.scan_site(
                item.site.id, item.targets, item.unknown_names, item.config.scan_passes, concurrency, progress
            )
        progress.analysis_started(item.site.id)
        report = analyze_site(
            SiteAnalysisInput(
                snapshot=item.snapshot,
                scan=scan,
                scan_skipped=skip_scan and item.config.scans,
                neighbours=item.config.neighbors,
                environment=item.config.environment,
                rf=loaded.config.rf,
                scan_passes=item.config.scan_passes,
                wlan_profiles=item.config.wlans,
                profiles=profiles,
            )
        )
        reports.append(report)
        outcomes.append(
            SiteOutcome(
                site_id=item.site.id,
                scanning=item.scanning,
                partial_reasons=report.partial_reasons,
                scanned_ap_count=len(item.targets),
                verifiable_ap_count=report.verifiable_ap_count,
                host_key_failed_ap_count=report.host_key_failed_ap_count,
            )
        )
    return RunResult(reports=tuple(reports), outcomes=tuple(outcomes))
