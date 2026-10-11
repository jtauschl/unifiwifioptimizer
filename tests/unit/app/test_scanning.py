"""The scan orchestrator with a fake scanner: targets, credential resolution, round-robin passes, isolation."""

import json
import threading
import time
from pathlib import Path

import pytest

from unifiwifioptimizer.adapters.unifi import parse
from unifiwifioptimizer.app.scanning import (
    ScanOrchestrator,
    build_targets,
    controller_origin,
    failure_kind,
    resolve_credentials,
    scan_members,
)
from unifiwifioptimizer.config.load import LoadedConfig
from unifiwifioptimizer.config.locations import ConfigLocation
from unifiwifioptimizer.config.schema import Config
from unifiwifioptimizer.domain.errors import (
    ConfigError,
    HostKeyUnknownError,
    ScanError,
    ScanTimeoutError,
    SshAuthenticationError,
)
from unifiwifioptimizer.domain.hostkeys import host_key_alias
from unifiwifioptimizer.domain.models import Band, MgmtSettings, Site, SiteSnapshot
from unifiwifioptimizer.domain.scan import (
    BandScan,
    BandScanStatus,
    ScanFailure,
    ScanFailureKind,
    ScanMeta,
    ScanPass,
    ScanTarget,
    SshAuthMethod,
)
from unifiwifioptimizer.domain.secrets import Secret

FIXTURES = Path(__file__).parents[2] / "fixtures"
MGMT = MgmtSettings(
    ssh_enabled=True, ssh_password_auth_enabled=True, ssh_user="fixture-ssh-user", ssh_password=Secret("pw")
)


def snapshot(mgmt: MgmtSettings | None = MGMT) -> SiteSnapshot:
    devices = parse.parse_devices(json.loads((FIXTURES / "stat_device.json").read_text()))
    settings = parse.parse_settings(json.loads((FIXTURES / "rest_setting.json").read_text()))
    from datetime import UTC, datetime

    return SiteSnapshot(
        site=Site(id="default", description="Site-1", hidden_id="default", device_count=11),
        captured_at=datetime(2026, 10, 11, tzinfo=UTC),
        access_points=devices.access_points,
        unparsable_devices=(),
        wlans=(),
        ap_groups=(),
        settings=settings.settings,
        mgmt=mgmt,
        clients=None,
        problems=(),
    )


def loaded(site: dict[str, object], env_password: str | None = None) -> LoadedConfig:
    config = Config.from_mapping(
        {"controller": {"url": "https://unifi.example:8443", "api_key": "k"}, "sites": {"default": site}}
    )
    return LoadedConfig(
        config=config,
        location=ConfigLocation(Path("/cfg/config.yaml"), legacy=False),
        env_ssh_password=Secret(env_password) if env_password else None,
    )


NEIGHBOURS = {"AP-1": ["AP-2", "AP-3"], "AP-2": ["AP-1"], "Ghost": ["AP-4"]}


def empty_pass() -> ScanPass:
    bands = tuple(
        BandScan(band=b, status=BandScanStatus.EMPTY, readings=(), interface=None) for b in (Band.GHZ_2, Band.GHZ_5)
    )
    return ScanPass(bands=bands, meta=ScanMeta(model_name=None, dfs_cac_5g=None, watchdog=None))


class FakeScanner:
    def __init__(self, failures: dict[tuple[str, int], ScanError] | None = None, delay_s: float = 0.0) -> None:
        self.calls: list[tuple[str, float, str]] = []
        self.failures = failures or {}
        self._delay_s = delay_s
        self._lock = threading.Lock()

    def scan(self, target: ScanTarget) -> ScanPass:
        with self._lock:
            index = sum(1 for name, _, _ in self.calls if name == target.ap_name)
            self.calls.append((target.ap_name, time.monotonic(), threading.current_thread().name))
        time.sleep(self._delay_s)
        error = self.failures.get((target.ap_name, index))
        if error is not None:
            raise error
        return empty_pass()


def test_scan_members_are_every_name_in_a_pair_in_configuration_order() -> None:
    site = loaded({"ssh": {}, "neighbors": NEIGHBOURS}).config.sites["default"]
    assert scan_members(site) == ("AP-1", "AP-2", "AP-3", "Ghost", "AP-4")


def test_targets_carry_alias_address_credentials_and_report_unknown_names() -> None:
    cfg = loaded({"ssh": {"scan_attempts": 3, "scan_interface_toggle": True}, "neighbors": NEIGHBOURS})
    targets, unknown = build_targets(snapshot(), cfg.config.sites["default"], cfg)
    assert [t.ap_name for t in targets] == ["AP-1", "AP-2", "AP-3", "AP-4"] and unknown == ("Ghost",)
    first = targets[0]
    assert first.host_key_alias == host_key_alias("https://unifi.example:8443", "default", first.ap_mac)
    assert first.credentials.method is SshAuthMethod.PASSWORD and first.credentials.user == "fixture-ssh-user"
    assert first.credentials.password == Secret("pw") and first.scan_attempts == 3 and first.interface_toggle is True
    assert first.allow_public_address is False
    public = loaded({"ssh": {"allow_public_ap_addresses": True}, "neighbors": NEIGHBOURS})
    assert build_targets(snapshot(), public.config.sites["default"], public)[0][0].allow_public_address is True
    assert str(first.address) == str(snapshot().access_points[0].ip)
    assert controller_origin(cfg.config.controller) == "https://unifi.example:8443"


def test_controller_mode_needs_the_controller_to_offer_ssh_credentials() -> None:
    cfg = loaded({"ssh": {}, "neighbors": NEIGHBOURS})
    site = cfg.config.sites["default"]
    assert site.ssh is not None
    for mgmt, message in [
        (None, "controller reports SSH disabled"),
        (
            MgmtSettings(ssh_enabled=False, ssh_password_auth_enabled=True, ssh_user="u", ssh_password=Secret("p")),
            "SSH disabled",
        ),
        (
            MgmtSettings(ssh_enabled=None, ssh_password_auth_enabled=True, ssh_user="u", ssh_password=Secret("p")),
            "SSH disabled",
        ),
        (
            MgmtSettings(ssh_enabled=True, ssh_password_auth_enabled=False, ssh_user="u", ssh_password=Secret("p")),
            "password authentication disabled",
        ),
        (
            MgmtSettings(ssh_enabled=True, ssh_password_auth_enabled=True, ssh_user=None, ssh_password=Secret("p")),
            "no SSH user or password",
        ),
        (
            MgmtSettings(ssh_enabled=True, ssh_password_auth_enabled=True, ssh_user="u", ssh_password=None),
            "no SSH user or password",
        ),
    ]:
        with pytest.raises(ConfigError, match=message):
            resolve_credentials(site.ssh, mgmt, cfg, "default")
    unknown_auth = MgmtSettings(
        ssh_enabled=True, ssh_password_auth_enabled=None, ssh_user="u", ssh_password=Secret("p")
    )
    assert resolve_credentials(site.ssh, unknown_auth, cfg, "default").user == "u"
    mismatch = loaded({"ssh": {"auth": "controller", "user": "other"}, "neighbors": NEIGHBOURS})
    with pytest.raises(
        ConfigError, match=r"sites\.default\.ssh\.user: differs from the SSH user the controller manages"
    ):
        build_targets(snapshot(), mismatch.config.sites["default"], mismatch)


def test_password_key_and_agent_modes_resolve_from_the_configuration() -> None:
    cfg = loaded({"ssh": {"auth": "password", "user": "admin", "password": "file-pw"}, "neighbors": NEIGHBOURS})
    creds = resolve_credentials(cfg.config.sites["default"].ssh, None, cfg, "default")  # type: ignore[arg-type]
    assert creds.method is SshAuthMethod.PASSWORD and creds.password == Secret("file-pw") and creds.user == "admin"
    cfg = loaded({"ssh": {"auth": "password", "user": "admin"}, "neighbors": NEIGHBOURS}, env_password="env-pw")
    assert resolve_credentials(cfg.config.sites["default"].ssh, None, cfg, "default").password == Secret("env-pw")  # type: ignore[arg-type]
    cfg = loaded({"ssh": {"auth": "password", "user": "admin"}, "neighbors": NEIGHBOURS})
    with pytest.raises(ConfigError, match=r"sites\.default\.ssh\.password: missing"):
        resolve_credentials(cfg.config.sites["default"].ssh, None, cfg, "default")  # type: ignore[arg-type]
    cfg = loaded({"ssh": {"auth": "key", "user": "admin", "key_file": "/home/u/.ssh/id"}, "neighbors": NEIGHBOURS})
    creds = resolve_credentials(cfg.config.sites["default"].ssh, None, cfg, "default")  # type: ignore[arg-type]
    assert creds.method is SshAuthMethod.KEY_FILE and creds.key_file == "/home/u/.ssh/id" and creds.password is None
    cfg = loaded({"ssh": {"auth": "key", "user": "admin"}, "neighbors": NEIGHBOURS})
    assert resolve_credentials(cfg.config.sites["default"].ssh, None, cfg, "default").method is SshAuthMethod.AGENT  # type: ignore[arg-type]


def test_passes_are_round_robin_serial_and_failures_are_isolated_per_access_point_and_pass() -> None:
    scanner = FakeScanner(
        {
            ("AP-2", 0): SshAuthenticationError("AP-2: authentication failed"),
            ("AP-3", 1): ScanTimeoutError("AP-3: slow"),
        }
    )
    sleeps: list[float] = []
    cfg = loaded({"ssh": {}, "scan_passes": 2, "neighbors": NEIGHBOURS})
    result = ScanOrchestrator(scanner, sleeps.append).scan_site(snapshot(), cfg.config.sites["default"], cfg)
    assert [name for name, _, _ in scanner.calls] == ["AP-1", "AP-2", "AP-3", "AP-4"] * 2
    assert len({thread for _, _, thread in scanner.calls}) == 1 and sleeps == [1.0]
    assert result.site_id == "default" and result.unknown_names == ("Ghost",)
    by_name = {s.ap_name: s for s in result.scans}
    assert len(by_name["AP-1"].successful_passes) == 2 and by_name["AP-1"].failures == ()
    (failure,) = by_name["AP-2"].failures
    assert failure == ScanFailure(kind=ScanFailureKind.AUTHENTICATION, detail="AP-2: authentication failed")
    assert isinstance(by_name["AP-2"].passes[0], ScanFailure) and isinstance(by_name["AP-2"].passes[1], ScanPass)
    assert (
        isinstance(by_name["AP-3"].passes[1], ScanFailure) and by_name["AP-3"].passes[1].kind is ScanFailureKind.TIMEOUT
    )


def test_scan_concurrency_above_one_uses_a_pool_and_keeps_the_order_of_results() -> None:
    scanner = FakeScanner(delay_s=0.2)
    cfg = loaded({"ssh": {"scan_concurrency": 4}, "neighbors": NEIGHBOURS})
    started = time.monotonic()
    result = ScanOrchestrator(scanner, lambda s: None).scan_site(snapshot(), cfg.config.sites["default"], cfg)
    elapsed = time.monotonic() - started
    assert [s.ap_name for s in result.scans] == ["AP-1", "AP-2", "AP-3", "AP-4"]
    assert len({thread for _, _, thread in scanner.calls}) > 1 and elapsed < 0.6
    serial = FakeScanner(delay_s=0.05)
    cfg = loaded({"ssh": {}, "neighbors": NEIGHBOURS})
    started = time.monotonic()
    ScanOrchestrator(serial, lambda s: None).scan_site(snapshot(), cfg.config.sites["default"], cfg)
    assert time.monotonic() - started >= 0.2 and len({thread for _, _, thread in serial.calls}) == 1


def test_errors_that_are_not_scan_errors_propagate() -> None:
    class Broken(FakeScanner):
        def scan(self, target: ScanTarget) -> ScanPass:
            raise RuntimeError("bug")

    cfg = loaded({"ssh": {}, "neighbors": NEIGHBOURS})
    with pytest.raises(RuntimeError):
        ScanOrchestrator(Broken(), lambda s: None).scan_site(snapshot(), cfg.config.sites["default"], cfg)


def test_every_scan_error_maps_onto_a_failure_kind() -> None:
    assert failure_kind(HostKeyUnknownError("x")) is ScanFailureKind.HOST_KEY_UNKNOWN
    from unifiwifioptimizer.domain import errors

    for name in (
        "HostKeyMismatchError", "SshAuthenticationError", "ScanTimeoutError", "ScanOutputTooLargeError",
        "ScanTransportError", "RemoteScriptError", "ScanParseError", "AddressRefusedError",
    ):  # fmt: skip
        assert isinstance(failure_kind(getattr(errors, name)("x")), ScanFailureKind)


def test_a_site_without_ssh_cannot_be_scanned() -> None:
    cfg = loaded({"neighbors": {"AP-1": [], "AP-2": []}})
    with pytest.raises(ConfigError, match=r"sites\.default\.ssh: neighbour scans need an ssh section"):
        build_targets(snapshot(), cfg.config.sites["default"], cfg)
