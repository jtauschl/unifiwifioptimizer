"""The configuration as typed values.

`Config.from_mapping` is the trust boundary for `config.yaml`: every key is known, every value is typed and
in range, and secrets become `Secret` on the way in. Error texts name the key path; they never echo a
value, because a mistyped secret is still a secret.
"""

import re
from base64 import b64decode
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import urlsplit

from unifiwifioptimizer.domain.errors import ConfigError
from unifiwifioptimizer.domain.models import SITE_ID_RE, SSH_USER_RE
from unifiwifioptimizer.domain.secrets import Secret
from unifiwifioptimizer.rf.constants import (
    CLIENT_TX_RANGE,
    DB_TUNABLE_RANGE,
    DBM_TUNABLE_RANGE,
    DEFAULT_CLIENT_TX_DBM,
    DEFAULT_MIN_RSSI_OFFSET_DB,
    DEFAULT_NOISE_FLOOR_DBM,
    DEFAULT_REQUIRED_SNR_DB,
    DEFAULT_ROAM_CEILING_DBM,
    DEFAULT_ROAM_FLOOR_DBM,
    DEFAULT_ROAM_MARGIN_DB,
    DEFAULT_ROAM_OFFSET_DB,
    NOISE_FLOOR_RANGE,
    SNR_RANGE,
)
from unifiwifioptimizer.rf.corridor import PathLossModel
from unifiwifioptimizer.rf.roaming import RoamingTunables

Value = object

DEFAULT_TIMEOUT_S = 15
TIMEOUT_RANGE = range(1, 121)
SCAN_PASSES_RANGE = range(1, 11)
SCAN_ATTEMPTS_RANGE = range(1, 6)
SCAN_CONCURRENCY_RANGE = range(1, 9)
MAX_SITES = 64
MAX_WLANS_PER_SITE = 64
MAX_NEIGHBOUR_ENTRIES = 256
MAX_HOST_KEYS = 256
# ITU-R P.1238 tabulates distance power loss coefficients up to the low forties, i.e. exponents below 5.
MAX_PATH_LOSS_EXPONENT = 10
# An HTTP header value: printable ASCII without spaces, so a stray control character cannot reach
# http.client, whose ValueError would echo the key.
API_KEY_RE = re.compile(r"[\x21-\x7e]{1,512}")
MAC_RE = re.compile(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}")
# RFC 1123 letters-digits-hyphen labels; IPv6 literals are refused until something needs them.
HOST_LABEL_RE = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?")
PLAIN_KEY_RE = re.compile(r"[A-Za-z0-9_.-]{1,64}")
SHA256_HEX_RE = re.compile(r"[0-9a-fA-F]{64}")
SHA256_B64_RE = re.compile(r"SHA256:[A-Za-z0-9+/]{43}=?")
MAX_NAME_CHARS = 128
MAX_PATH_CHARS = 1024


class SshAuth(StrEnum):
    CONTROLLER = "controller"
    KEY = "key"
    # The name of a mode, not a credential.
    PASSWORD = "password"  # noqa: S105 # nosec B105


def _mapping(value: Value, path: str) -> Mapping[str, Value]:
    if not isinstance(value, dict):
        raise ConfigError(path, "expected a mapping")
    for key in value:
        if not isinstance(key, str):
            raise ConfigError(path, "every key must be a string")
    return value


def _label(key: str) -> str:
    """A key as it may appear in an error text: plain identifiers verbatim, anything else escaped, so a
    controller-chosen name pasted from the skeleton cannot carry a terminal escape into stderr."""
    return key if PLAIN_KEY_RE.fullmatch(key) else ascii(key)


def _reject_unknown(mapping: Mapping[str, Value], path: str, known: frozenset[str]) -> None:
    unknown = sorted(set(mapping) - known)
    if unknown:
        raise ConfigError(path, f"unknown key(s): {', '.join(_label(key) for key in unknown)}")


def _text(mapping: Mapping[str, Value], path: str, key: str, max_chars: int = MAX_NAME_CHARS) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value:
        raise ConfigError(f"{path}.{key}", "expected a non-empty string (quote the value)")
    if len(value) > max_chars:
        raise ConfigError(f"{path}.{key}", f"longer than {max_chars} characters")
    return value


def _opt_text(mapping: Mapping[str, Value], path: str, key: str, max_chars: int = MAX_NAME_CHARS) -> str | None:
    return _text(mapping, path, key, max_chars) if mapping.get(key) is not None else None


def _integer(mapping: Mapping[str, Value], path: str, key: str, allowed: range, default: int) -> int:
    value = mapping.get(key)
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"{path}.{key}", "expected an integer")
    if value not in allowed:
        raise ConfigError(f"{path}.{key}", f"outside {allowed.start}..{allowed.stop - 1}")
    return value


def _flag(mapping: Mapping[str, Value], path: str, key: str, default: bool) -> bool:
    value = mapping.get(key)
    if value is None:
        return default
    if not isinstance(value, bool):
        raise ConfigError(f"{path}.{key}", "expected true or false")
    return value


def _path(mapping: Mapping[str, Value], path: str, key: str) -> Path | None:
    text = _opt_text(mapping, path, key, MAX_PATH_CHARS)
    if text is None:
        return None
    # OpenSSH expands `%` in path options and a quote would end the quoting the argv builder applies.
    if '"' in text or "%" in text or "\x00" in text:
        raise ConfigError(f"{path}.{key}", 'a path must not contain `"`, `%` or NUL')
    resolved = Path(text).expanduser()
    if not resolved.is_absolute():
        # ssh runs from `/`; a relative path would silently point there, not next to the configuration file.
        raise ConfigError(f"{path}.{key}", "a path must be absolute (or start with ~)")
    return resolved


def parse_fingerprint(text: str, path: str) -> bytes:
    """A SHA-256 certificate or host-key fingerprint as 32 bytes, from `SHA256:<base64>` or 64 hex digits."""
    if SHA256_HEX_RE.fullmatch(text):
        return bytes.fromhex(text)
    if SHA256_B64_RE.fullmatch(text):
        return b64decode(text[len("SHA256:") :].rstrip("=") + "=")
    raise ConfigError(path, "expected `SHA256:<base64>` or 64 hex digits")


@dataclass(frozen=True, slots=True, kw_only=True)
class ControllerConfig:
    host: str
    port: int
    api_key: Secret
    ca_cert: Path | None
    cert_fingerprint: bytes | None
    timeout_s: int


def parse_controller_url(text: str, path: str) -> tuple[str, int]:
    """`https://host[:port]` → (host, port); credentials, path, query and fragment are refused."""
    if len(text) > MAX_PATH_CHARS:
        raise ConfigError(path, f"longer than {MAX_PATH_CHARS} characters")
    # urlsplit silently strips tabs and newlines (WHATWG), so they must be refused before it runs.
    if not text.isascii() or not text.isprintable() or " " in text:
        raise ConfigError(path, "expected https://<host>[:port] without credentials")
    try:
        url = urlsplit(text)
        # The properties parse lazily; an unbalanced `[` surfaces as ValueError only here.
        host, username, password = url.hostname, url.username, url.password
    except ValueError:
        raise ConfigError(path, "expected https://<host>[:port] without credentials") from None
    if url.scheme != "https" or not host or username is not None or password is not None:
        raise ConfigError(path, "expected https://<host>[:port] without credentials")
    # urlsplit strips the brackets of an IP literal from `hostname`; IPv6 and IPvFuture are out by design.
    if "[" in url.netloc:
        raise ConfigError(path, "expected a host name (ASCII; an IDN host as its xn-- form) or an IPv4 address")
    if url.path not in ("", "/") or url.query or url.fragment:
        raise ConfigError(path, "the URL must not carry a path, query or fragment")
    if not _is_host(host):
        raise ConfigError(path, "expected a host name (ASCII; an IDN host as its xn-- form) or an IPv4 address")
    try:
        port = url.port
    except ValueError:
        raise ConfigError(path, "invalid port") from None
    if port is None:
        return host, 443
    if not 1 <= port <= 65535:
        raise ConfigError(path, "invalid port")
    return host, port


def _is_host(host: str) -> bool:
    if ":" in host:
        return False
    try:
        ip_address(host)
        return True
    except ValueError:
        pass
    labels = host.split(".")
    # RFC 3696 §2: a final label that is all digits is not a host name; `0x`/`0o` labels and anything
    # `inet_aton` would read as a legacy IPv4 spelling (`127.1`, `0x7f.1`) are refused the same way.
    if labels[-1].isdigit() or any(label[:2] in ("0x", "0o") for label in labels):
        return False
    return len(host) <= 253 and all(HOST_LABEL_RE.fullmatch(label) for label in labels)


def _controller(value: Value, env_api_key: str | None) -> ControllerConfig:
    path = "controller"
    mapping = _mapping(value, path)
    _reject_unknown(mapping, path, frozenset({"url", "api_key", "ca_cert", "cert_fingerprint", "timeout_s"}))
    host, port = parse_controller_url(_text(mapping, path, "url", MAX_PATH_CHARS), f"{path}.url")
    api_key = _opt_text(mapping, path, "api_key", 512)
    if api_key is None:
        api_key = env_api_key
    if not api_key:
        raise ConfigError(f"{path}.api_key", "missing; set it in the file or in UNIFI_API_KEY")
    if not API_KEY_RE.fullmatch(api_key):
        raise ConfigError(f"{path}.api_key", "must be 1..512 printable ASCII characters without spaces")
    ca_cert = _path(mapping, path, "ca_cert")
    fingerprint_text = _opt_text(mapping, path, "cert_fingerprint")
    if ca_cert is not None and fingerprint_text is not None:
        raise ConfigError(path, "set either ca_cert or cert_fingerprint, not both")
    return ControllerConfig(
        host=host,
        port=port,
        api_key=Secret(api_key),
        ca_cert=ca_cert,
        cert_fingerprint=parse_fingerprint(fingerprint_text, f"{path}.cert_fingerprint") if fingerprint_text else None,
        timeout_s=_integer(mapping, path, "timeout_s", TIMEOUT_RANGE, DEFAULT_TIMEOUT_S),
    )


@dataclass(frozen=True, slots=True, kw_only=True)
class SshConfig:
    auth: SshAuth
    user: str | None
    password: Secret | None
    key_file: Path | None
    host_keys: Mapping[str, bytes]
    scan_interface_toggle: bool
    allow_public_ap_addresses: bool
    scan_concurrency: int
    scan_attempts: int


def resolve_auth(
    auth: str | None, user: str | None, password: Secret | None, key_file: Path | None, path: str
) -> SshAuth:
    """The plan's decision table; every ambiguous combination is a `ConfigError`, never a guess."""
    if auth is None:
        if key_file is not None:
            raise ConfigError(f"{path}.auth", "set `auth: key` explicitly when key_file is given")
        if user is None and password is None:
            return SshAuth.CONTROLLER
        if user is not None and password is not None:
            return SshAuth.PASSWORD
        if user is not None:
            raise ConfigError(f"{path}.auth", "user without password: set `auth: key` or `auth: controller`")
        raise ConfigError(f"{path}.user", "missing (a password needs a user)")
    try:
        mode = SshAuth(auth)
    except ValueError:
        raise ConfigError(f"{path}.auth", "expected controller, key or password") from None
    if mode is SshAuth.CONTROLLER and (password is not None or key_file is not None):
        raise ConfigError(f"{path}.auth", "controller mode takes no password or key_file")
    if mode is SshAuth.KEY and (user is None or password is not None):
        raise ConfigError(f"{path}.auth", "key mode needs a user and takes no password")
    if mode is SshAuth.PASSWORD and (user is None or key_file is not None):
        raise ConfigError(f"{path}.auth", "password mode needs a user and takes no key_file")
    return mode


def _ssh(value: Value, path: str) -> SshConfig:
    mapping = _mapping(value, path)
    known = frozenset(
        {
            "auth", "user", "password", "key_file", "host_keys", "scan_interface_toggle", "allow_public_ap_addresses",
            "scan_concurrency", "scan_attempts",
        }
    )  # fmt: skip
    _reject_unknown(mapping, path, known)
    user = _opt_text(mapping, path, "user", 32)
    if user is not None and not SSH_USER_RE.fullmatch(user):
        raise ConfigError(f"{path}.user", "expected a user name (letters, digits, `_`, `.`, `-`)")
    password_text = _opt_text(mapping, path, "password", 256)
    key_file = _path(mapping, path, "key_file")
    password = Secret(password_text) if password_text else None
    auth = resolve_auth(_opt_text(mapping, path, "auth", 16), user, password, key_file, path)
    host_keys: dict[str, bytes] = {}
    raw_keys = mapping.get("host_keys")
    if raw_keys is not None:
        key_map = _mapping(raw_keys, f"{path}.host_keys")
        if len(key_map) > MAX_HOST_KEYS:
            raise ConfigError(f"{path}.host_keys", f"more than {MAX_HOST_KEYS} entries")
        for mac, fingerprint in key_map.items():
            if not MAC_RE.fullmatch(mac):
                raise ConfigError(f"{path}.host_keys", "keys must be lower-case colon-separated MAC addresses")
            if not isinstance(fingerprint, str):
                raise ConfigError(f"{path}.host_keys.{mac}", "expected a fingerprint string")
            host_keys[mac] = parse_fingerprint(fingerprint, f"{path}.host_keys.{mac}")
    return SshConfig(
        auth=auth,
        user=user,
        password=password,
        key_file=key_file,
        host_keys=host_keys,
        scan_interface_toggle=_flag(mapping, path, "scan_interface_toggle", False),
        allow_public_ap_addresses=_flag(mapping, path, "allow_public_ap_addresses", False),
        scan_concurrency=_integer(mapping, path, "scan_concurrency", SCAN_CONCURRENCY_RANGE, 1),
        scan_attempts=_integer(mapping, path, "scan_attempts", SCAN_ATTEMPTS_RANGE, 2),
    )


def _environment(value: Value, path: str) -> PathLossModel:
    if isinstance(value, str):
        try:
            return PathLossModel.from_preset(value)
        except ValueError:
            raise ConfigError(
                path, f"expected Open, Residential, Office, Obstructed or a number in (0, {MAX_PATH_LOSS_EXPONENT:g}]"
            ) from None
    # Compared, not converted: an arbitrarily long YAML integer must not reach float().
    if isinstance(value, bool) or not isinstance(value, int | float) or not 0 < value <= MAX_PATH_LOSS_EXPONENT:
        raise ConfigError(
            path, f"expected Open, Residential, Office, Obstructed or a number in (0, {MAX_PATH_LOSS_EXPONENT:g}]"
        )
    return PathLossModel.custom(float(value))


@dataclass(frozen=True, slots=True, kw_only=True)
class SiteConfig:
    """One site; `scans` is the single definition of "this site runs neighbour scans": at least one
    neighbour pair is listed (the skeleton's empty lists are a template, not a scan)."""

    id: str
    ssh: SshConfig | None
    environment: PathLossModel
    scan_passes: int
    wlans: Mapping[str, str]
    neighbors: Mapping[str, frozenset[str]]

    @property
    def scans(self) -> bool:
        return any(self.neighbors.values())


def _site(site_id: str, value: Value) -> SiteConfig:
    path = f"sites.{site_id}"
    if not SITE_ID_RE.fullmatch(site_id):
        raise ConfigError("sites", "a site id may contain letters, digits, `_` and `-` only")
    mapping = _mapping(value, path)
    _reject_unknown(mapping, path, frozenset({"ssh", "environment", "scan_passes", "wlans", "neighbors"}))
    wlans: dict[str, str] = {}
    raw_wlans = mapping.get("wlans")
    if raw_wlans is not None:
        wlan_map = _mapping(raw_wlans, f"{path}.wlans")
        if len(wlan_map) > MAX_WLANS_PER_SITE:
            raise ConfigError(f"{path}.wlans", f"more than {MAX_WLANS_PER_SITE} entries")
        for name, profile in wlan_map.items():
            if not name or len(name) > MAX_NAME_CHARS:
                raise ConfigError(f"{path}.wlans", "WLAN names must be 1..128 characters")
            if not isinstance(profile, str) or not 0 < len(profile) <= MAX_NAME_CHARS:
                raise ConfigError(f"{path}.wlans.{_label(name)}", "expected a profile name of 1..128 characters")
            wlans[name] = profile
    neighbors: dict[str, frozenset[str]] = {}
    raw_neighbors = mapping.get("neighbors")
    if raw_neighbors is not None:
        neighbor_map = _mapping(raw_neighbors, f"{path}.neighbors")
        if len(neighbor_map) > MAX_NEIGHBOUR_ENTRIES:
            raise ConfigError(f"{path}.neighbors", f"more than {MAX_NEIGHBOUR_ENTRIES} entries")
        for ap, peers in neighbor_map.items():
            if not ap or len(ap) > MAX_NAME_CHARS:
                raise ConfigError(f"{path}.neighbors", "AP names must be 1..128 characters")
            if not isinstance(peers, list) or not all(
                isinstance(peer, str) and 0 < len(peer) <= MAX_NAME_CHARS for peer in peers
            ):
                raise ConfigError(f"{path}.neighbors.{_label(ap)}", "expected a list of AP names of 1..128 characters")
            if len(peers) > MAX_NEIGHBOUR_ENTRIES:
                raise ConfigError(f"{path}.neighbors.{_label(ap)}", f"more than {MAX_NEIGHBOUR_ENTRIES} peers")
            if ap in peers:
                raise ConfigError(f"{path}.neighbors.{_label(ap)}", "an AP cannot be its own neighbour")
            neighbors[ap] = frozenset(peers)
    ssh = _ssh(mapping["ssh"], f"{path}.ssh") if mapping.get("ssh") is not None else None
    environment = mapping.get("environment")
    site = SiteConfig(
        id=site_id,
        ssh=ssh,
        environment=_environment("Residential" if environment is None else environment, f"{path}.environment"),
        scan_passes=_integer(mapping, path, "scan_passes", SCAN_PASSES_RANGE, 1),
        wlans=wlans,
        neighbors=neighbors,
    )
    if site.scans and site.ssh is None:
        raise ConfigError(f"{path}.ssh", "neighbour scans need an ssh section (`auth: controller` is the minimum)")
    return site


@dataclass(frozen=True, slots=True, kw_only=True)
class RfConfig:
    client_tx_dbm: int
    noise_floor_dbm: int
    required_snr_db: int
    min_rssi_offset_db: int
    roaming: RoamingTunables


def _rf(value: Value) -> RfConfig:
    path = "rf"
    mapping = _mapping(value, path) if value is not None else {}
    known = frozenset(
        {
            "client_tx_dbm", "noise_floor_dbm", "required_snr_db", "min_rssi_offset_db", "roam_offset_db",
            "roam_margin_db", "roam_floor_dbm", "roam_ceiling_dbm",
        }
    )  # fmt: skip
    _reject_unknown(mapping, path, known)
    floor = _integer(mapping, path, "roam_floor_dbm", DBM_TUNABLE_RANGE, DEFAULT_ROAM_FLOOR_DBM)
    ceiling = _integer(mapping, path, "roam_ceiling_dbm", DBM_TUNABLE_RANGE, DEFAULT_ROAM_CEILING_DBM)
    try:
        roaming = RoamingTunables(
            offset_db=_integer(mapping, path, "roam_offset_db", DB_TUNABLE_RANGE, DEFAULT_ROAM_OFFSET_DB),
            margin_db=_integer(mapping, path, "roam_margin_db", DB_TUNABLE_RANGE, DEFAULT_ROAM_MARGIN_DB),
            floor_dbm=floor,
            ceiling_dbm=ceiling,
        )
    except ValueError as exc:
        raise ConfigError(path, str(exc)) from None
    return RfConfig(
        client_tx_dbm=_integer(mapping, path, "client_tx_dbm", CLIENT_TX_RANGE, DEFAULT_CLIENT_TX_DBM),
        noise_floor_dbm=_integer(mapping, path, "noise_floor_dbm", NOISE_FLOOR_RANGE, DEFAULT_NOISE_FLOOR_DBM),
        required_snr_db=_integer(mapping, path, "required_snr_db", SNR_RANGE, DEFAULT_REQUIRED_SNR_DB),
        min_rssi_offset_db=_integer(mapping, path, "min_rssi_offset_db", DB_TUNABLE_RANGE, DEFAULT_MIN_RSSI_OFFSET_DB),
        roaming=roaming,
    )


@dataclass(frozen=True, slots=True, kw_only=True)
class Config:
    controller: ControllerConfig
    sites: Mapping[str, SiteConfig]
    rf: RfConfig

    @classmethod
    def from_mapping(cls, document: Value, env_api_key: str | None = None) -> "Config":
        root = _mapping(document, "$")
        _reject_unknown(root, "$", frozenset({"controller", "sites", "rf"}))
        if "controller" not in root:
            raise ConfigError("controller", "missing")
        sites: dict[str, SiteConfig] = {}
        raw_sites = root.get("sites")
        if raw_sites is not None:
            site_map = _mapping(raw_sites, "sites")
            if len(site_map) > MAX_SITES:
                raise ConfigError("sites", f"more than {MAX_SITES} sites")
            for site_id, site_value in site_map.items():
                sites[site_id] = _site(site_id, site_value)
        return cls(controller=_controller(root["controller"], env_api_key), sites=sites, rf=_rf(root.get("rf")))
