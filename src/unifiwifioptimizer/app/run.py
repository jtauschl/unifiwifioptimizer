"""The `run` use case: every selected site read, scanned and analysed, in a fixed order.

Everything that can refuse the run happens before the first scan: the environment (OpenSSH) when a site
scans, the scan passwords, every site's existence, every snapshot, every site's credentials and targets.
With a terminal, the host-key questions come next (`host_key_gate`), once, for every target of every site.
Then the sites are scanned one after the other (access points serial within a site, docs/ALGORITHM.md §2) and
analysed. The outcome per site is typed; the command line maps it onto exit codes.
"""

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum

from unifiwifioptimizer.analysis.inputs import SiteAnalysisInput
from unifiwifioptimizer.analysis.site_analyzer import analyze_site
from unifiwifioptimizer.app.scanning import ScanOrchestrator, build_targets, configured_access_points
from unifiwifioptimizer.app.snapshot import build_snapshot
from unifiwifioptimizer.app.trust import TrustSubject, subject_for_target
from unifiwifioptimizer.app.use_cases import resolve_site
from unifiwifioptimizer.config.load import LoadedConfig, require_scan_passwords
from unifiwifioptimizer.config.schema import SiteConfig
from unifiwifioptimizer.domain.analysis import PartialReason
from unifiwifioptimizer.domain.commands import PrintedCommands
from unifiwifioptimizer.domain.errors import ConfigError
from unifiwifioptimizer.domain.models import Site, SiteSnapshot
from unifiwifioptimizer.domain.profile import ProfileSet
from unifiwifioptimizer.domain.report import SiteReport
from unifiwifioptimizer.domain.scan import NoScanConfigured, ScanFailureKind, ScanInput, ScanSkipped, ScanTarget
from unifiwifioptimizer.ports.clock import Clock
from unifiwifioptimizer.ports.controller import ControllerApi
from unifiwifioptimizer.ports.progress import Progress
from unifiwifioptimizer.ports.scanner import Scanner

Sleep = Callable[[float], None]
ScannerFactory = Callable[[], Scanner]
EnvironmentCheck = Callable[[], object]
HostKeyGate = Callable[[Sequence[TrustSubject]], None]


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
    # Per host-key kind (unknown, changed), the access points with a pass that failed on it; only kinds above zero.
    host_key_failures: Mapping[ScanFailureKind, int]

    @property
    def no_verifiable_ap(self) -> bool:
        """Exit 5 territory: the site scanned, nobody was verified, and a host key was the reason."""
        return (
            self.scanning
            and self.scanned_ap_count > 0
            and self.verifiable_ap_count == 0
            and bool(self.host_key_failures)
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class RunResult:
    reports: tuple[SiteReport, ...]
    outcomes: tuple[SiteOutcome, ...]
    # Whether the host-key gate ran in this run (it asked, or refused an access point without asking).
    host_key_gate_ran: bool

    @property
    def verdict(self) -> RunVerdict:
        """Order-independent reduction over the sites: no verifiable access point beats partial beats ok."""
        if any(o.no_verifiable_ap for o in self.outcomes):
            return RunVerdict.NO_VERIFIABLE_AP
        if any(o.partial_reasons for o in self.outcomes):
            return RunVerdict.PARTIAL
        return RunVerdict.OK


def select_sites(loaded: LoadedConfig, selectors: Sequence[str] | None, commands: PrintedCommands) -> list[SiteConfig]:
    """The configured sites to run, every selector matched against the configured site ids."""
    configured = loaded.config.sites
    if not configured:
        raise ConfigError("sites", f"no site configured; run {commands.config('<site-id>')} to get a skeleton")
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
    commands: PrintedCommands,
    sites: Sequence[str] | None = None,
    with_clients: bool = False,
    skip_scan: bool = False,
    extended: bool = False,
    environment_check: EnvironmentCheck | None = None,
    host_key_gate: HostKeyGate | None = None,
) -> RunResult:
    selected = select_sites(loaded, sites, commands)
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
    host_key_gate_ran = False
    if host_key_gate is not None:
        # After every site is prepared: a configuration error in a later site must not follow a store write.
        subjects = [
            subject_for_target(target, access_points[target.ap_mac], item.config)
            for item in prepared
            for access_points in [{ap.mac: ap for ap in item.snapshot.access_points}]
            for target in item.targets
        ]
        if subjects:
            host_key_gate(subjects)
            host_key_gate_ran = True
    orchestrator = ScanOrchestrator(scanner_factory(), sleep) if scanning_sites else None
    reports: list[SiteReport] = []
    outcomes: list[SiteOutcome] = []
    for item in prepared:
        progress.site_started(item.site.id, item.scanning)
        scan: ScanInput = NoScanConfigured() if not item.config.scans else ScanSkipped()
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
                neighbours=item.config.neighbors,
                environment=item.config.environment,
                rf=loaded.config.rf,
                scan_passes=item.config.scan_passes,
                wlan_profiles=item.config.wlans,
                profiles=profiles,
                extended=extended,
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
                host_key_failures=report.scan.host_key_failures,
            )
        )
    return RunResult(reports=tuple(reports), outcomes=tuple(outcomes), host_key_gate_ran=host_key_gate_ran)
