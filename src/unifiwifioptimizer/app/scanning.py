"""Neighbour scans for one site: which access points, with which credentials, how many passes.

Passes are round-robin over the access points (pass 1 on every access point, then pass 2, …) so the
readings of one pass are close in time. Within a site the access points are scanned serially by default:
an access point in an off-channel scan sends no beacons, and two neighbours scanning at the same moment
systematically miss each other. Every `ScanError` is isolated to its access point and pass; anything
else propagates.
"""

from collections.abc import Callable, Iterator, Sequence
from concurrent.futures import ThreadPoolExecutor

from unifiwifioptimizer.config.load import LoadedConfig
from unifiwifioptimizer.config.schema import ControllerConfig, SiteConfig, SshAuth, SshConfig
from unifiwifioptimizer.domain.errors import (
    AddressRefusedError,
    ConfigError,
    HostKeyMismatchError,
    HostKeyUnknownError,
    RemoteScriptError,
    ScanError,
    ScanOutputTooLargeError,
    ScanParseError,
    ScanTimeoutError,
    ScanTransportError,
    SshAuthenticationError,
)
from unifiwifioptimizer.domain.hostkeys import host_key_alias
from unifiwifioptimizer.domain.models import AccessPoint, MgmtSettings, SiteSnapshot
from unifiwifioptimizer.domain.scan import (
    ApScan,
    ScanFailure,
    ScanFailureKind,
    ScanPass,
    ScanTarget,
    SiteScan,
    SshAuthMethod,
    SshCredentials,
)
from unifiwifioptimizer.ports.progress import ScanProgress
from unifiwifioptimizer.ports.scanner import Scanner

Sleep = Callable[[float], None]
PASS_PAUSE_S = 1.0
SSH_PORT = 22

_FAILURE_KINDS: tuple[tuple[type[ScanError], ScanFailureKind], ...] = (
    (HostKeyUnknownError, ScanFailureKind.HOST_KEY_UNKNOWN),
    (HostKeyMismatchError, ScanFailureKind.HOST_KEY_MISMATCH),
    (SshAuthenticationError, ScanFailureKind.AUTHENTICATION),
    (ScanTimeoutError, ScanFailureKind.TIMEOUT),
    (ScanOutputTooLargeError, ScanFailureKind.OUTPUT_TOO_LARGE),
    (RemoteScriptError, ScanFailureKind.REMOTE_SCRIPT),
    (ScanParseError, ScanFailureKind.UNPARSABLE_OUTPUT),
    (AddressRefusedError, ScanFailureKind.ADDRESS_REFUSED),
    (ScanTransportError, ScanFailureKind.TRANSPORT),
)


def failure_kind(error: ScanError) -> ScanFailureKind:
    return next(kind for cls, kind in _FAILURE_KINDS if isinstance(error, cls))


def controller_origin(controller: ControllerConfig) -> str:
    """The controller identity that goes into every host-key alias: scheme, host and port, nothing else."""
    return f"https://{controller.host}:{controller.port}"


def resolve_credentials(
    ssh: SshConfig, mgmt: MgmtSettings | None, loaded: LoadedConfig, site_id: str
) -> SshCredentials:
    """The configuration's auth mode turned into what the scanner needs; every gap is a configuration error,
    never a guess (plan §3)."""
    path = f"sites.{site_id}.ssh"
    if ssh.auth is SshAuth.CONTROLLER:
        if mgmt is None or mgmt.ssh_enabled is not True:
            raise ConfigError(
                f"{path}.auth", "controller mode, but the controller reports SSH disabled on its access points"
            )
        if mgmt.ssh_password_auth_enabled is False:
            raise ConfigError(
                f"{path}.auth", "controller mode, but the controller has password authentication disabled"
            )
        if mgmt.ssh_user_rejected:
            raise ConfigError(
                f"{path}.auth", "controller mode, but the controller's SSH user was rejected (not a user name)"
            )
        if mgmt.ssh_user is None or mgmt.ssh_password is None:
            raise ConfigError(
                f"{path}.auth",
                "controller mode, but the controller reports no SSH user or password (the API key needs the "
                "full Administrator role; a View Only key cannot read device secrets)",
            )
        if ssh.user is not None and ssh.user != mgmt.ssh_user:
            raise ConfigError(f"{path}.user", "differs from the SSH user the controller manages")
        return SshCredentials(
            user=mgmt.ssh_user, method=SshAuthMethod.PASSWORD, password=mgmt.ssh_password, key_file=None
        )
    assert ssh.user is not None, "resolve_auth admits key and password mode only with a user"  # noqa: S101 # nosec B101
    user = ssh.user
    if ssh.auth is SshAuth.PASSWORD:
        password = ssh.password if ssh.password is not None else loaded.env_ssh_password
        if password is None:
            raise ConfigError(f"{path}.password", "missing; set it in the file or in UNIFI_SSH_PASSWORD")
        return SshCredentials(user=user, method=SshAuthMethod.PASSWORD, password=password, key_file=None)
    if ssh.key_file is not None:
        return SshCredentials(user=user, method=SshAuthMethod.KEY_FILE, password=None, key_file=str(ssh.key_file))
    return SshCredentials(user=user, method=SshAuthMethod.AGENT, password=None, key_file=None)


def scan_members(site: SiteConfig) -> tuple[str, ...]:
    """Every access point that takes part in a neighbour pair, by name, in configuration order."""
    names: list[str] = []
    for ap, peers in site.neighbors.items():
        for name in (ap, *sorted(peers)):
            if name not in names:
                names.append(name)
    return tuple(names)


def configured_access_points(
    snapshot: SiteSnapshot, site: SiteConfig
) -> tuple[dict[str, AccessPoint], tuple[str, ...]]:
    """The access point behind every configured name the controller knows, and the names it does not.

    The neighbour matrix keys by name, so a configured name two controller devices share is a configuration
    error — raised before any scan, for scanning and controller-only sites alike."""
    by_name: dict[str, list[AccessPoint]] = {}
    for candidate in snapshot.access_points:
        by_name.setdefault(candidate.name, []).append(candidate)
    found: dict[str, AccessPoint] = {}
    unknown: list[str] = []
    for name in scan_members(site):
        candidates = by_name.get(name, [])
        if len(candidates) > 1:
            raise ConfigError(f"sites.{site.id}.neighbors", f"{len(candidates)} access points share a configured name")
        if candidates:
            found[name] = candidates[0]
        else:
            unknown.append(name)
    return found, tuple(unknown)


def build_targets(
    snapshot: SiteSnapshot, site: SiteConfig, loaded: LoadedConfig
) -> tuple[tuple[ScanTarget, ...], tuple[str, ...]]:
    """Targets for the configured members found on the controller, and the names that were not.

    An access point the controller reports as disconnected is left out (nothing answers there; the analysis
    reports it as offline)."""
    if site.ssh is None:
        raise ConfigError(f"sites.{site.id}.ssh", "neighbour scans need an ssh section")
    credentials = resolve_credentials(site.ssh, snapshot.mgmt, loaded, site.id)
    origin = controller_origin(loaded.config.controller)
    found, unknown = configured_access_points(snapshot, site)
    targets: list[ScanTarget] = []
    for ap in found.values():
        if ap.offline:
            continue
        targets.append(
            ScanTarget(
                site_id=site.id,
                ap_mac=ap.mac,
                ap_name=ap.name,
                address=ap.ip,
                port=SSH_PORT,
                host_key_alias=host_key_alias(origin, site.id, ap.mac),
                credentials=credentials,
                scan_attempts=site.ssh.scan_attempts,
                interface_toggle=site.ssh.scan_interface_toggle,
                allow_public_address=site.ssh.allow_public_ap_addresses,
            )
        )
    return tuple(targets), unknown


class ScanOrchestrator:
    """Runs `scan_passes` round-robin passes over a site's access points through one `Scanner`."""

    def __init__(self, scanner: Scanner, sleep: Sleep, pass_pause_s: float = PASS_PAUSE_S) -> None:
        self._scanner = scanner
        self._sleep = sleep
        self._pass_pause_s = pass_pause_s

    def scan_site(
        self,
        site_id: str,
        targets: Sequence[ScanTarget],
        unknown_names: Sequence[str],
        passes: int,
        concurrency: int = 1,
        progress: ScanProgress | None = None,
    ) -> SiteScan:
        """Runs the passes over targets that were built (and whose credentials were resolved) beforehand, so
        nothing is resolved after the first scan has started."""
        results: dict[str, list[ScanPass | ScanFailure]] = {t.ap_mac: [] for t in targets}
        for index in range(passes):
            if index:
                self._sleep(self._pass_pause_s)
            for target, outcome in self._run_pass(targets, concurrency, progress, index, passes):
                results[target.ap_mac].append(outcome)
        scans = tuple(ApScan(ap_mac=t.ap_mac, ap_name=t.ap_name, passes=tuple(results[t.ap_mac])) for t in targets)
        return SiteScan(site_id=site_id, scans=scans, unknown_names=tuple(unknown_names))

    def _run_pass(
        self,
        targets: Sequence[ScanTarget],
        concurrency: int,
        progress: ScanProgress | None,
        index: int,
        passes: int,
    ) -> Iterator[tuple[ScanTarget, ScanPass | ScanFailure]]:
        """Progress events come from this (the coordinating) thread only; the serial path reports each access
        point as it is reached, the pool reports every start first because the pool decides the order."""
        if concurrency <= 1 or len(targets) <= 1:
            for target in targets:
                if progress is not None:
                    progress.scan_started(target.ap_name, index, passes)
                outcome = self._scan_one(target)
                if progress is not None:
                    progress.scan_finished(target.ap_name, outcome)
                yield target, outcome
            return
        if progress is not None:
            for target in targets:
                progress.scan_started(target.ap_name, index, passes)
        # Opt-in only (`scan_concurrency` > 1): concurrent scans make neighbours miss each other's beacons.
        with ThreadPoolExecutor(max_workers=min(concurrency, len(targets))) as pool:
            for target, outcome in zip(targets, pool.map(self._scan_one, targets), strict=True):
                if progress is not None:
                    progress.scan_finished(target.ap_name, outcome)
                yield target, outcome

    def _scan_one(self, target: ScanTarget) -> ScanPass | ScanFailure:
        try:
            return self._scanner.scan(target)
        except ScanError as exc:
            return ScanFailure(kind=failure_kind(exc), detail=str(exc))
