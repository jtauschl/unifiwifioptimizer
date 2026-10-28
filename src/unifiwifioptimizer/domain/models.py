"""Domain value types shared by the core: what the controller reports, typed and bounded."""

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address
from types import MappingProxyType
from typing import Generic, TypeVar

from unifiwifioptimizer.domain.secrets import Secret

T = TypeVar("T")


class Band(StrEnum):
    """Radio band; the controller's radio names (`ng`, `na`, `6e`) are mapped to these by the adapter."""

    GHZ_2 = "2g"
    GHZ_5 = "5g"
    GHZ_6 = "6g"

    @property
    def label(self) -> str:
        return {Band.GHZ_2: "2.4 GHz", Band.GHZ_5: "5 GHz", Band.GHZ_6: "6 GHz"}[self]


class TxPowerMode(StrEnum):
    AUTO = "auto"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    CUSTOM = "custom"


class DeviceState(StrEnum):
    """The controller's device `state` integer, classified: 1 is connected, 0 disconnected (both live-verified);
    every other value (upgrading, provisioning, isolated, ...) is `OTHER` and carried with its raw code."""

    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    OTHER = "other"

    @classmethod
    def of(cls, code: int) -> "DeviceState":
        if code == 1:
            return cls.CONNECTED
        if code == 0:
            return cls.DISCONNECTED
        return cls.OTHER


# Lower-case, colon-separated MAC address as the controller prints it; validated by the adapter.
Mac = str
# A site id becomes a request-path segment; anything outside this alphabet is rejected at every boundary.
SITE_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")
# A login name as it goes into ssh's `user@host`: controllers hand out mixed-case names, so POSIX's
# lower-case-only rule would reject real controllers; letters, digits, `_`, `.` and `-` only.
SSH_USER_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}")


@dataclass(frozen=True, slots=True, kw_only=True)
class Radio:
    """A radio's configuration (`radio_table`); only band and width are guaranteed."""

    band: Band
    interface_name: str | None
    # None when the controller reports `auto`; the channel in use is in `RadioStats`.
    channel: int | None
    width_mhz: int
    configured_tx_dbm: int | None
    tx_power_mode: TxPowerMode | None
    min_tx_dbm: int | None
    max_tx_dbm: int | None
    min_rssi_enabled: bool
    min_rssi_dbm: int | None
    antenna_gain_dbi: int | None
    spatial_streams: int | None
    dfs_capable: bool | None


# The controller's radio state while a 5 GHz radio runs its DFS channel availability check.
DFS_WAIT_STATE = "DFS_WAIT"
# The controller endpoint of the site settings; its field problems say a setting such as Channel AI is uncertain.
SETTINGS_ENDPOINT = "rest/setting"


@dataclass(frozen=True, slots=True, kw_only=True)
class RadioStats:
    """A radio's live state (`radio_table_stats`); `observed_tx_dbm` is the power the radio runs at."""

    band: Band
    channel: int
    width_mhz: int
    # HT40 secondary channel position on 2.4 GHz: -1 below, 1 above, 0 or None without a secondary.
    extension_channel: int | None
    observed_tx_dbm: int | None
    channel_utilisation_pct: int | None
    self_rx_utilisation_pct: int | None
    self_tx_utilisation_pct: int | None
    tx_retries_pct: float | None
    # The controller sends -1 when no clients contribute; that sentinel becomes None.
    satisfaction_pct: int | None
    state: str | None
    client_count: int | None


@dataclass(frozen=True, slots=True, kw_only=True)
class Vap:
    """One BSS the access point broadcasts (`vap_table`)."""

    band: Band
    bssid: Mac
    essid: str | None
    channel: int | None
    width_mhz: int | None
    up: bool
    wlan_id: str | None
    is_guest: bool
    client_count: int | None


@dataclass(frozen=True, slots=True, kw_only=True)
class AccessPoint:
    mac: Mac
    name: str
    ip: IPv4Address | IPv6Address
    model: str | None
    firmware: str | None
    # The device `state` integer as sent; None when the controller did not send it (an older API).
    state_code: int | None
    uplink_type: str | None
    # `uplink.uplink_mac`: the switch for a wired uplink (live-verified); for a wireless uplink it names the
    # parent access point (semantics unverified until a mesh dump exists).
    uplink_mac: Mac | None
    radios: tuple[Radio, ...]
    radio_stats: tuple[RadioStats, ...]
    vaps: tuple[Vap, ...]
    # `x_ssh_hostkey_fingerprint` as the controller reports it (SHA256:… or MD5 colon-hex), None when the
    # controller has not learnt the key; compared, never trusted, by `trust-host-keys`.
    ssh_host_key_fingerprint: str | None

    @property
    def state(self) -> DeviceState | None:
        return DeviceState.of(self.state_code) if self.state_code is not None else None

    @property
    def offline(self) -> bool:
        """Only an explicit `disconnected` counts; an absent or unfamiliar state is analysed normally."""
        return self.state is DeviceState.DISCONNECTED

    def radio(self, band: Band) -> Radio | None:
        return next((r for r in self.radios if r.band is band), None)

    def stats(self, band: Band) -> RadioStats | None:
        return next((s for s in self.radio_stats if s.band is band), None)

    @property
    def bands(self) -> frozenset[Band]:
        return frozenset(r.band for r in self.radios)


@dataclass(frozen=True, slots=True)
class FieldProblem:
    """An optional field the controller sent but the adapter could not use; the model keeps None there.
    `endpoint` names the controller endpoint and `device_mac` the device record the field belongs to, so a
    problem can be attributed after the snapshot has merged every endpoint's list."""

    path: str
    message: str
    endpoint: str | None = None
    device_mac: Mac | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class UnparsableDevice:
    """An access point the parser could not model; the site analysis continues without it."""

    mac: Mac | None
    name: str | None
    reason: str


@dataclass(frozen=True, slots=True, kw_only=True)
class BssidIndex:
    """BSSID → (access point MAC, band), built from the real `vap_table` entries."""

    entries: Mapping[Mac, tuple[Mac, Band]]

    def __post_init__(self) -> None:
        # A frozen model must not stay mutable through the dict the caller still holds.
        object.__setattr__(self, "entries", MappingProxyType(dict(self.entries)))

    @classmethod
    def from_access_points(cls, access_points: Iterable[AccessPoint]) -> "BssidIndex":
        entries: dict[Mac, tuple[Mac, Band]] = {}
        for ap in access_points:
            for vap in ap.vaps:
                entries[vap.bssid] = (ap.mac, vap.band)
        return cls(entries=entries)

    def lookup(self, bssid: Mac) -> tuple[Mac, Band] | None:
        return self.entries.get(bssid)

    def bssids_of(self, ap_mac: Mac, band: Band) -> frozenset[Mac]:
        return frozenset(b for b, (mac, bnd) in self.entries.items() if mac == ap_mac and bnd is band)


@dataclass(frozen=True, slots=True, kw_only=True)
class WlanConfig:
    """A WLAN (`wlanconf`) with every field a profile check or an advisory reads. Fields the controller
    did not send are None."""

    id: str
    name: str
    enabled: bool
    bands: frozenset[Band]
    security: str | None
    wpa_mode: str | None
    wpa_enc: str | None
    wpa3_support: bool | None
    wpa3_transition: bool | None
    wpa3_fast_roaming: bool | None
    wpa3_enhanced_192: bool | None
    pmf_mode: str | None
    hide_ssid: bool | None
    l2_isolation: bool | None
    proxy_arp: bool | None
    bss_transition: bool | None
    fast_roaming_enabled: bool | None
    roaming_assistant_na_enabled: bool | None
    roaming_assistant_na_rssi: int | None
    roaming_assistant_6e_enabled: bool | None
    uapsd_enabled: bool | None
    mcastenhance_enabled: bool | None
    bc_filter_enabled: bool | None
    minrate_setting_preference: str | None
    minrate_ng_enabled: bool | None
    minrate_ng_data_rate_kbps: int | None
    minrate_na_enabled: bool | None
    minrate_na_data_rate_kbps: int | None
    dtim_mode: str | None
    dtim_ng: int | None
    dtim_na: int | None
    dtim_6e: int | None
    group_rekey: int | None
    sae_anti_clogging: int | None
    sae_sync: int | None
    band_steering: bool | None
    advertise_device_name_in_beacon: bool | None
    iot_channel_lock: bool | None
    iot_dtim_lock: bool | None
    enhanced_iot: bool | None
    optimize_iot_wifi_connectivity: bool | None
    b_supported: bool | None
    dns_assistance_mode: str | None
    mdns_proxy_mode: str | None
    multicast_suppressor_mode: str | None
    setting_preference: str | None
    private_preshared_keys_enabled: bool | None
    mlo_enabled: bool | None
    hotspot2conf_enabled: bool | None
    mac_filter_enabled: bool | None
    radius_mac_auth_enabled: bool | None
    rrm_enabled: bool | None
    is_guest: bool | None
    ap_group_mode: str | None
    ap_group_ids: tuple[str, ...]
    network_id: str | None


@dataclass(frozen=True, slots=True, kw_only=True)
class ApGroup:
    id: str
    name: str
    device_macs: frozenset[Mac]


@dataclass(frozen=True, slots=True, kw_only=True)
class Network:
    """A network (`networkconf`) as far as the report names it: its name and its VLAN (None when untagged)."""

    id: str
    name: str
    vlan: int | None


@dataclass(frozen=True, slots=True, kw_only=True)
class ChannelAiSettings:
    """`rest/setting/radio_ai`. `enabled` is the switch behind the UI's scheduled "Channel AI Optimization"
    (`cron_expr` is its start time, `channels`/`width_candidates_mhz` its per-band candidate sets);
    `auto_enabled` is a separate flag whose UI counterpart is not established, so it is carried as is."""

    enabled: bool
    auto_enabled: bool | None
    optimize: frozenset[str]
    cron_expr: str | None
    channels: Mapping[Band, frozenset[int]]
    width_candidates_mhz: Mapping[Band, frozenset[int]]
    excluded_devices: frozenset[Mac]
    blacklist: frozenset[tuple[Band, int, int]]

    def __post_init__(self) -> None:
        object.__setattr__(self, "channels", MappingProxyType(dict(self.channels)))
        object.__setattr__(self, "width_candidates_mhz", MappingProxyType(dict(self.width_candidates_mhz)))


@dataclass(frozen=True, slots=True, kw_only=True)
class SiteSettings:
    country_code: int | None
    channel_ai: ChannelAiSettings | None
    mlo_mesh_enabled: bool | None
    outdoor_mode_enabled: bool | None


@dataclass(frozen=True, slots=True, kw_only=True)
class MgmtSettings:
    """`rest/setting/mgmt`: the controller-managed SSH credentials for the access points."""

    ssh_enabled: bool | None
    ssh_password_auth_enabled: bool | None
    ssh_user: str | None
    ssh_password: Secret | None
    # The controller sent a user name the tool refuses to put into ssh's `user@host`; `ssh_user` is None then.
    ssh_user_rejected: bool = False


@dataclass(frozen=True, slots=True, kw_only=True)
class ClientSighting:
    """One associated wireless client as the AP sees it; deliberately without any client identifier."""

    ap_mac: Mac
    band: Band
    essid: str | None
    channel: int | None
    # Uplink RSSI measured by the AP, the quantity the controller compares thresholds against.
    signal_dbm: int | None
    noise_dbm: int | None
    satisfaction_pct: int | None
    fast_transition: bool | None


@dataclass(frozen=True, slots=True, kw_only=True)
class Site:
    id: str
    description: str
    hidden_id: str | None
    device_count: int | None


@dataclass(frozen=True, slots=True, kw_only=True)
class ParsedList(Generic[T]):
    """Records that parsed, plus every problem — including one per record that could not be parsed."""

    items: tuple[T, ...]
    problems: tuple[FieldProblem, ...]


@dataclass(frozen=True, slots=True, kw_only=True)
class DevicesResult:
    access_points: tuple[AccessPoint, ...]
    unparsable: tuple[UnparsableDevice, ...]
    problems: tuple[FieldProblem, ...]


@dataclass(frozen=True, slots=True, kw_only=True)
class SettingsResult:
    settings: SiteSettings
    mgmt: MgmtSettings | None
    problems: tuple[FieldProblem, ...]


@dataclass(frozen=True, slots=True, kw_only=True)
class SiteSnapshot:
    """Everything the controller said about one site at one moment."""

    site: Site
    captured_at: datetime
    access_points: tuple[AccessPoint, ...]
    unparsable_devices: tuple[UnparsableDevice, ...]
    wlans: tuple[WlanConfig, ...]
    ap_groups: tuple[ApGroup, ...]
    networks: tuple[Network, ...]
    settings: SiteSettings
    mgmt: MgmtSettings | None
    # None when the client picture was not collected, as opposed to a site without wireless clients.
    clients: tuple[ClientSighting, ...] | None
    # Every optional field the adapter dropped while building this snapshot.
    problems: tuple[FieldProblem, ...]

    @property
    def bssids(self) -> BssidIndex:
        return BssidIndex.from_access_points(self.access_points)
