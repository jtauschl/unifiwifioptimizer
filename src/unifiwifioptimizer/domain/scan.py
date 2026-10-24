"""What one access point reports when asked to look around: per-band neighbour readings, nothing more.

A reading carries a BSSID, an RSSI and, when the radio reported it, the frequency; SSIDs are kept only
so the report can name foreign networks in aggregate. Nothing here identifies a client.
"""

from dataclasses import dataclass
from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address

from unifiwifioptimizer.domain.models import Band, Mac
from unifiwifioptimizer.domain.secrets import Secret


class BandScanStatus(StrEnum):
    """Why a band did or did not produce readings."""

    OK = "ok"
    # The access point runs no radio on this band (no AP-mode interface for it).
    NO_RADIO = "no_radio"
    # A scan-capable interface exists but is down, and the configuration forbids toggling it.
    INTERFACE_DOWN = "interface_down"
    # The scan ran and saw nothing; distinct from OK with an empty list only in the report wording.
    EMPTY = "empty"
    # Every scan attempt failed or hit the remote watchdog.
    FAILED = "failed"


@dataclass(frozen=True, slots=True, kw_only=True)
class ScanReading:
    """One neighbour as seen from one access point; `frequency_mhz` is None when the radio did not report it
    and `ssid` when it was absent or longer than a WLAN allows."""

    bssid: Mac
    rssi_dbm: int
    frequency_mhz: int | None
    ssid: str | None


@dataclass(frozen=True, slots=True, kw_only=True)
class BandScan:
    """`interface` names the scan interface the readings came from; None when the band produced none."""

    band: Band
    status: BandScanStatus
    readings: tuple[ScanReading, ...]
    interface: str | None


@dataclass(frozen=True, slots=True, kw_only=True)
class ScanMeta:
    """`dfs_cac_5g` is `active` (CAC running), `ready` or `unknown` (the U6 kernel log is the only source);
    `watchdog` is how the access point bounded `iw scan`: `timeout` (busybox applet) or `watcher`."""

    model_name: str | None
    dfs_cac_5g: str | None
    watchdog: str | None


@dataclass(frozen=True, slots=True, kw_only=True)
class PhyChannelPower:
    """One serving PHY's per-20 MHz `iw` ceiling; its conducted-power meaning needs calibration."""

    phy_index: int
    current_frequency_mhz: int
    limits: tuple[tuple[int, float], ...]


@dataclass(frozen=True, slots=True, kw_only=True)
class ScanPass:
    """One SSH call on one access point: both bands plus the metadata block."""

    bands: tuple[BandScan, ...]
    meta: ScanMeta
    power_5g: PhyChannelPower | None = None

    def band(self, band: Band) -> BandScan | None:
        return next((b for b in self.bands if b.band is band), None)


class ScanFailureKind(StrEnum):
    HOST_KEY_UNKNOWN = "host_key_unknown"
    HOST_KEY_MISMATCH = "host_key_mismatch"
    AUTHENTICATION = "authentication"
    TIMEOUT = "timeout"
    OUTPUT_TOO_LARGE = "output_too_large"
    TRANSPORT = "transport"
    REMOTE_SCRIPT = "remote_script"
    UNPARSABLE_OUTPUT = "unparsable_output"
    ADDRESS_REFUSED = "address_refused"


@dataclass(frozen=True, slots=True, kw_only=True)
class ScanFailure:
    """One pass that produced nothing; `detail` is static text or sanitised stderr, never a secret."""

    kind: ScanFailureKind
    detail: str


@dataclass(frozen=True, slots=True, kw_only=True)
class ApScan:
    """Every pass the orchestrator ran against one access point, in order."""

    ap_mac: Mac
    ap_name: str
    passes: tuple[ScanPass | ScanFailure, ...]

    @property
    def successful_passes(self) -> tuple[ScanPass, ...]:
        return tuple(p for p in self.passes if isinstance(p, ScanPass))

    @property
    def failures(self) -> tuple[ScanFailure, ...]:
        return tuple(p for p in self.passes if isinstance(p, ScanFailure))


@dataclass(frozen=True, slots=True, kw_only=True)
class SiteScan:
    """What a site's scan produced: one `ApScan` per access point that exists on the controller, plus the
    configured names the controller does not know (a configuration drift, reported, not fatal)."""

    site_id: str
    scans: tuple[ApScan, ...]
    unknown_names: tuple[str, ...]

    def scan_of(self, ap_mac: Mac) -> ApScan | None:
        return next((s for s in self.scans if s.ap_mac == ap_mac), None)


class SshAuthMethod(StrEnum):
    """How the scanner authenticates; the configuration's `controller` mode resolves to PASSWORD with the
    credentials the controller manages."""

    PASSWORD = "password"  # noqa: S105 # nosec B105 — the name of a method, not a credential
    KEY_FILE = "key_file"
    AGENT = "agent"


@dataclass(frozen=True, slots=True, kw_only=True)
class SshCredentials:
    """`key_file` is an absolute path as text: the core never touches the file system, the adapter does."""

    user: str
    method: SshAuthMethod
    password: Secret | None
    key_file: str | None


@dataclass(frozen=True, slots=True, kw_only=True)
class ScanTarget:
    """Everything one SSH call needs; the alias, not the address, identifies the host key to expect.

    `port` is 22 on an access point (the test harness maps containers to other ports);
    `allow_public_address` mirrors the site's `allow_public_ap_addresses`.
    """

    site_id: str
    ap_mac: Mac
    ap_name: str
    address: IPv4Address | IPv6Address
    port: int
    host_key_alias: str
    credentials: SshCredentials
    scan_attempts: int
    interface_toggle: bool
    allow_public_address: bool
