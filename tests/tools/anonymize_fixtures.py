"""Project live controller dumps onto committable fixtures.

Only keys named in a spec survive (positive projection), so an identifier the specs do not know about
cannot leak. Surviving identifiers are rewritten through one deterministic mapping per run, which keeps
cross-endpoint references (device MAC, `ap_mac`, `device_macs`, `wlanconf_id`) consistent.

`check_fixture` is the inverse contract and is what the fixture gate runs: every key must be in the spec,
every identifier must have its synthetic shape, every text must match its key's closed vocabulary or
format, and a secret key may only carry the synthetic SSH credentials. `keep` never passes text, so a
hostname, URL or credential cannot hide in a field the spec forgot to constrain; a spec that would keep a
secret key verbatim is itself a violation.

Usage: python -m tests.tools.anonymize_fixtures --source <dir with live_*.json> --dest tests/fixtures
"""

import argparse
import base64
import hashlib
import json
import re
import sys
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from unifiwifioptimizer.domain.secrets import is_secret_key

Json = object
Record = Mapping[str, Json]

SYNTHETIC_MAC_PREFIX = "02:00:00:00:"
SYNTHETIC_IP_PREFIX = "192.0.2."
SYNTHETIC_ID_LEADING_ZEROS = 16
FIXTURE_SSH_USER = "fixture-ssh-user"
# A fixture credential, not a secret: it exists so the parser's Secret path is exercised.
FIXTURE_SSH_PASSWORD = "fixture-ssh-password"  # noqa: S105
HOSTKEY_SEED = "fixture-hostkey:"
MAX_SYNTHETIC_HOSTKEYS = 64

MAC_RE = re.compile(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}", re.IGNORECASE)
OBJECT_ID_RE = re.compile(r"[0-9a-f]{24}")
IPV4_RE = re.compile(r"[0-9]{1,3}(\.[0-9]{1,3}){3}")
SHA256_FINGERPRINT_RE = re.compile(r"SHA256:[A-Za-z0-9+/]{43}")
MD5_FINGERPRINT_RE = re.compile(r"[0-9a-f]{2}(:[0-9a-f]{2}){15}")


def synthetic_sha256_fingerprint(n: int) -> str:
    digest = hashlib.sha256(f"{HOSTKEY_SEED}{n}".encode()).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


def synthetic_md5_fingerprint(n: int) -> str:
    digest = hashlib.md5(f"{HOSTKEY_SEED}{n}".encode(), usedforsecurity=False).hexdigest()
    return ":".join(digest[i : i + 2] for i in range(0, 32, 2))


SYNTHETIC_HOSTKEYS = frozenset(
    fingerprint(n)
    for n in range(1, MAX_SYNTHETIC_HOSTKEYS + 1)
    for fingerprint in (synthetic_sha256_fingerprint, synthetic_md5_fingerprint)
)


class SpecError(ValueError):
    """A live value outside the specs; the message names the path and the rule, never the value."""

    def __init__(self, path: str, message: str) -> None:
        super().__init__(f"{path}: {message}")
        self.path = path
        self.message = message

    def within(self, segment: str) -> "SpecError":
        return SpecError(segment + self.path, self.message)


class Anonymizer:
    """One deterministic identifier mapping per run plus the count of dropped keys."""

    def __init__(self) -> None:
        self._tables: dict[str, dict[str, str]] = {}
        self.dropped: Counter[str] = Counter()

    def _map(self, kind: str, value: str, render: Callable[[int], str]) -> str:
        table = self._tables.setdefault(kind, {})
        if value not in table:
            table[value] = render(len(table) + 1)
        return table[value]

    def mac(self, value: str) -> str:
        if not MAC_RE.fullmatch(value):
            raise ValueError("expected a MAC address")
        return self._map("mac", value.lower(), lambda n: f"{SYNTHETIC_MAC_PREFIX}{n >> 8:02x}:{n & 0xFF:02x}")

    def object_id(self, value: str) -> str:
        if not OBJECT_ID_RE.fullmatch(value):
            raise ValueError("expected a 24-hex object id")
        return self._map("id", value, lambda n: f"{n:024x}")

    def ip(self, value: str) -> str:
        if not IPV4_RE.fullmatch(value):
            raise ValueError("expected an IPv4 address")

        def render(n: int) -> str:
            if n > 254:
                raise ValueError("more than 254 distinct IPv4 addresses")
            return f"{SYNTHETIC_IP_PREFIX}{n}"

        return self._map("ip", value, render)

    def ssid(self, value: str) -> str:
        return self._map("ssid", value, lambda n: f"SSID-{n}")

    def ap_name(self, value: str) -> str:
        return self._map("ap_name", value, lambda n: f"AP-{n}")

    def group_name(self, value: str) -> str:
        return self._map("group_name", value, lambda n: f"Group-{n}")

    def site_description(self, value: str) -> str:
        return self._map("site_description", value, lambda n: f"Site-{n}")

    def site_name(self, value: str) -> str:
        # `default` is the controller's well-known first site; every other site id is a random token.
        return value if value == "default" else self._map("site_name", value, lambda n: f"site-{n}")

    def hostkey_fingerprint(self, value: str) -> str:
        # The empty and whitespace-only variants are controller quirks worth keeping verbatim.
        if not value.strip():
            return value
        if SHA256_FINGERPRINT_RE.fullmatch(value):
            return self._map("hostkey", value, synthetic_sha256_fingerprint)
        if MD5_FINGERPRINT_RE.fullmatch(value):
            return self._map("hostkey", value, synthetic_md5_fingerprint)
        raise ValueError("unknown host key fingerprint format")


Apply = Callable[[Anonymizer, Json], Json]
Check = Callable[[Json, str], list[str]]


@dataclass(frozen=True, slots=True)
class Rule:
    apply: Apply
    check: Check
    keeps_verbatim: bool = False


Spec = Mapping[str, Rule]
Selector = Callable[[Record], Spec]


def _text(value: Json) -> str:
    if not isinstance(value, str):
        raise TypeError("expected a string")
    return value


def _items(value: Json) -> Sequence[Json]:
    if not isinstance(value, list):
        raise TypeError("expected a list")
    return value


def _mapping(value: Json) -> Record:
    if not isinstance(value, dict):
        raise TypeError("expected an object")
    return value


def _check_kept_scalar(value: Json, path: str) -> list[str]:
    # Only non-text scalars pass `keep`; a list under a kept key needs its own rule and fails loudly.
    if value is None or isinstance(value, bool | int | float):
        return []
    return [f"{path}: kept value of unexpected type {type(value).__name__}"]


def _pattern_like_check(accept: Callable[[str], bool], what: str) -> Check:
    def check(value: Json, path: str) -> list[str]:
        if value is None or (isinstance(value, str) and accept(value)):
            return []
        return [f"{path}: expected {what}"]

    return check


def _pattern_check(compiled: re.Pattern[str], what: str) -> Check:
    return _pattern_like_check(lambda text: compiled.fullmatch(text) is not None, what)


def _string_rule(method: Callable[[Anonymizer, str], str], check: Check) -> Rule:
    return Rule(lambda ctx, value: method(ctx, _text(value)), check)


def _string_list_rule(method: Callable[[Anonymizer, str], str], check: Check) -> Rule:
    def apply(ctx: Anonymizer, value: Json) -> Json:
        return [method(ctx, _text(item)) for item in _items(value)]

    def check_list(value: Json, path: str) -> list[str]:
        if not isinstance(value, list):
            return [f"{path}: expected a list"]
        return [problem for i, item in enumerate(value) for problem in check(item, f"{path}[{i}]")]

    return Rule(apply, check_list)


SYNTHETIC_MAC_RE = re.compile(rf"{re.escape(SYNTHETIC_MAC_PREFIX)}[0-9a-f]{{2}}:[0-9a-f]{{2}}")
SYNTHETIC_ID_RE = re.compile(rf"0{{{SYNTHETIC_ID_LEADING_ZEROS},}}[0-9a-f]{{{24 - SYNTHETIC_ID_LEADING_ZEROS}}}")
SYNTHETIC_IP_RE = re.compile(rf"{re.escape(SYNTHETIC_IP_PREFIX)}(1?[0-9]?[0-9]|2[0-4][0-9]|25[0-4])")


def _keep(_ctx: Anonymizer, value: Json) -> Json:
    problems = _check_kept_scalar(value, "")
    if problems:
        raise TypeError("expected a non-text scalar")
    return value


keep = Rule(_keep, _check_kept_scalar, keeps_verbatim=True)


def _text_rule(accept: Callable[[str], bool], what: str) -> Rule:
    def apply(_ctx: Anonymizer, value: Json) -> Json:
        text = _text(value)
        if not accept(text):
            raise ValueError(f"expected {what}")
        return text

    return Rule(apply, _pattern_like_check(accept, what), keeps_verbatim=True)


def _text_list_rule(accept: Callable[[str], bool], what: str) -> Rule:
    item_check = _pattern_like_check(accept, what)

    def apply(_ctx: Anonymizer, value: Json) -> Json:
        texts: list[str] = []
        for i, item in enumerate(_items(value)):
            if not isinstance(item, str) or not accept(item):
                raise SpecError(f"[{i}]", f"expected {what}")
            texts.append(item)
        return texts

    def check(value: Json, path: str) -> list[str]:
        if not isinstance(value, list):
            return [f"{path}: expected a list"]
        return [problem for i, item in enumerate(value) for problem in item_check(item, f"{path}[{i}]")]

    return Rule(apply, check, keeps_verbatim=True)


def vocab(*values: str) -> Rule:
    """Text from a closed set; an unknown controller value fails the run so the spec is extended knowingly."""
    allowed = frozenset(values)
    return _text_rule(allowed.__contains__, "one of the allowed values")


def vocab_list(*values: str) -> Rule:
    allowed = frozenset(values)
    return _text_list_rule(allowed.__contains__, "one of the allowed values")


def pattern(regex: str, what: str) -> Rule:
    compiled = re.compile(regex)
    return _text_rule(lambda text: compiled.fullmatch(text) is not None, what)


def pattern_list(regex: str, what: str) -> Rule:
    compiled = re.compile(regex)
    return _text_list_rule(lambda text: compiled.fullmatch(text) is not None, what)


def _check_flag(value: Json, path: str) -> list[str]:
    return [] if isinstance(value, bool) else [f"{path}: expected a boolean flag"]


def _flag(_ctx: Anonymizer, value: Json) -> Json:
    if not isinstance(value, bool):
        raise TypeError("expected a boolean flag")
    return value


# A boolean under a secret-looking key (`x_ssh_enabled`, `passphrase_autogenerated`) is a flag, not a secret.
flag = Rule(_flag, _check_flag)
mac = _string_rule(Anonymizer.mac, _pattern_check(SYNTHETIC_MAC_RE, "a synthetic MAC address"))
mac_list = _string_list_rule(Anonymizer.mac, _pattern_check(SYNTHETIC_MAC_RE, "a synthetic MAC address"))
object_id = _string_rule(Anonymizer.object_id, _pattern_check(SYNTHETIC_ID_RE, "a synthetic object id"))
object_id_list = _string_list_rule(Anonymizer.object_id, _pattern_check(SYNTHETIC_ID_RE, "a synthetic object id"))
ip = _string_rule(Anonymizer.ip, _pattern_check(SYNTHETIC_IP_RE, "a TEST-NET-1 address"))
ssid = _string_rule(Anonymizer.ssid, _pattern_check(re.compile(r"SSID-[0-9]+"), "a synthetic SSID"))
ap_name = _string_rule(Anonymizer.ap_name, _pattern_check(re.compile(r"AP-[0-9]+"), "a synthetic AP name"))
group_name = _string_rule(Anonymizer.group_name, _pattern_check(re.compile(r"Group-[0-9]+"), "a synthetic group name"))
site_description = _string_rule(
    Anonymizer.site_description, _pattern_check(re.compile(r"Site-[0-9]+"), "a synthetic site description")
)
site_name = _string_rule(
    Anonymizer.site_name, _pattern_check(re.compile(r"default|site-[0-9]+"), "a synthetic site id")
)


def _check_hostkey(value: Json, path: str) -> list[str]:
    if isinstance(value, str) and (not value.strip() or value in SYNTHETIC_HOSTKEYS):
        return []
    return [f"{path}: expected a synthetic host key fingerprint"]


hostkey_fingerprint = _string_rule(Anonymizer.hostkey_fingerprint, _check_hostkey)


def constant(value: str) -> Rule:
    def check(actual: Json, path: str) -> list[str]:
        return [] if actual == value else [f"{path}: expected the fixture constant"]

    return Rule(lambda _ctx, _value: value, check)


def project(ctx: Anonymizer, record: Record, spec: Spec) -> dict[str, Json]:
    out: dict[str, Json] = {}
    for key, value in record.items():
        rule = spec.get(key)
        if rule is None:
            ctx.dropped[key] += 1
            continue
        try:
            out[key] = None if value is None else rule.apply(ctx, value)
        except SpecError as exc:
            raise exc.within(f".{key}") from None
        except (TypeError, ValueError) as exc:
            raise SpecError(f".{key}", str(exc)) from None
    return out


def check_record(record: Json, spec: Spec, path: str) -> list[str]:
    if not isinstance(record, dict):
        return [f"{path}: expected an object"]
    problems: list[str] = []
    for key, value in record.items():
        rule = spec.get(key)
        if rule is None:
            problems.append(f"{path}.{key}: key is not in the fixture spec")
        elif rule.keeps_verbatim and is_secret_key(key):
            problems.append(f"{path}.{key}: secret key kept verbatim")
        elif value is not None:
            problems.extend(rule.check(value, f"{path}.{key}"))
    return problems


def nested(spec: Spec) -> Rule:
    return Rule(
        lambda ctx, value: project(ctx, _mapping(value), spec), lambda value, path: check_record(value, spec, path)
    )


def records(selector: Selector) -> Rule:
    """A list of records whose spec depends on a discriminator the spec itself keeps."""

    def apply(ctx: Anonymizer, value: Json) -> Json:
        projected: list[Json] = []
        for i, item in enumerate(_items(value)):
            try:
                projected.append(project(ctx, _mapping(item), selector(_mapping(item))))
            except SpecError as exc:
                raise exc.within(f"[{i}]") from None
            except TypeError as exc:
                raise SpecError(f"[{i}]", str(exc)) from None
        return projected

    def check(value: Json, path: str) -> list[str]:
        if not isinstance(value, list):
            return [f"{path}: expected a list"]
        problems: list[str] = []
        for i, item in enumerate(value):
            if not isinstance(item, dict):
                problems.append(f"{path}[{i}]: expected an object")
            else:
                problems.extend(check_record(item, selector(item), f"{path}[{i}]"))
        return problems

    return Rule(apply, check)


def list_of(spec: Spec) -> Rule:
    return records(lambda _record: spec)


def kept(*names: str) -> Spec:
    return dict.fromkeys(names, keep)


def envelope(data: Rule) -> Spec:
    return {"meta": nested({"rc": vocab("ok")}), "data": data}


DIGITS = r"[0-9]{1,4}"
# Model codes are upper-case alphanumerics but never twelve hex digits (a serial / MAC without colons).
MODEL = r"(?![0-9A-F]{12}$)[A-Z0-9]{3,12}"
# Firmware versions have three or four dotted groups whose last group is a long build number, unlike IPv4.
VERSION = r"[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,3}(\.[0-9]{4,6})?"
# Five cron fields; an atom is `*` or at most two digits, joined by `-`, `,` or `/` — a phone number is not.
CRON_ATOM = r"(\*|[0-9]{1,2})([-,/](\*|[0-9]{1,2}))*"
CRON = rf"({CRON_ATOM} ){{4}}{CRON_ATOM}"
RADIO_STATE = vocab("RUN", "INIT", "DOWN", "DISABLED", "UNKNOWN")
INTERFACE = r"(ra|rai|wifi)[0-9](ap[0-9])?"
RADIO = vocab("ng", "na", "6e")
RADIO_SPEC: Spec = {
    **kept(
        "channel", "tx_power", "min_txpower", "max_txpower", "min_rssi_enabled", "min_rssi", "antenna_gain",
        "antenna_id", "builtin_antenna", "builtin_ant_gain", "current_antenna_gain", "nss", "has_dfs", "has_eht240",
        "is_11be", "sens_level_enabled", "hard_noise_floor_enabled", "radio_caps", "radio_caps2", "vwire_enabled",
    ),
    "radio": RADIO,
    "name": pattern(INTERFACE, "a radio interface name"),
    "ht": pattern(DIGITS, "a channel width"),
    "tx_power_mode": vocab("auto", "high", "medium", "low", "custom"),
}  # fmt: skip
RADIO_STATS_SPEC: Spec = {
    **kept(
        "channel", "bw", "extchannel", "tx_power", "last_tx_power", "last_channel", "cu_total", "cu_self_rx",
        "cu_self_tx", "tx_retries_pct", "tx_retries", "tx_packets", "satisfaction", "num_sta", "user-num_sta",
        "guest-num_sta", "gain",
    ),
    "radio": RADIO,
    "name": pattern(INTERFACE, "a radio interface name"),
    "state": RADIO_STATE,
}  # fmt: skip
VAP_SPEC: Spec = {
    **kept(
        "channel", "bw", "extchannel", "up", "is_guest", "is_wep", "num_sta", "satisfaction", "avg_client_signal",
        "ccq", "tx_power",
    ),
    "radio": RADIO,
    "radio_name": pattern(INTERFACE, "a radio interface name"),
    "name": pattern(INTERFACE, "a radio interface name"),
    "state": RADIO_STATE,
    "usage": vocab("user", "guest"),
    "t": vocab("vap"),
    "bssid": mac,
    "ap_mac": mac,
    "essid": ssid,
    "wlanconf_id": object_id,
    "site_id": object_id,
}  # fmt: skip
UPLINK_SPEC: Spec = {
    **kept("up", "speed", "full_duplex", "num_port", "port_idx"),
    "type": vocab("wire", "wireless"),
    "name": pattern(r"eth[0-9]", "an ethernet interface name"),
    "mac": mac,
    "uplink_mac": mac,
}
ACCESS_POINT_SPEC: Spec = {
    **kept("adopted", "state", "satisfaction", "num_sta", "country_code", "is_access_point", "support_wifi6e"),
    "type": vocab("uap", "udm", "ugw", "uxg"),
    "model": pattern(MODEL, "a model code"),
    "version": pattern(VERSION, "a firmware version"),
    "_id": object_id,
    "mac": mac,
    "name": ap_name,
    "ip": ip,
    "site_id": object_id,
    "wlangroup_id_na": object_id,
    "wlangroup_id_ng": object_id,
    "x_has_ssh_hostkey": flag,
    "x_ssh_hostkey_fingerprint": hostkey_fingerprint,
    "uplink": nested(UPLINK_SPEC),
    "radio_table": list_of(RADIO_SPEC),
    "radio_table_stats": list_of(RADIO_STATS_SPEC),
    "vap_table": list_of(VAP_SPEC),
}  # fmt: skip
OTHER_DEVICE_SPEC: Spec = {
    "type": vocab("usw", "udm", "ugw", "uxg", "uck", "uph", "ubb", "usg"),
    "model": pattern(MODEL, "a model code"),
    "is_access_point": keep,
    "mac": mac,
    "_id": object_id,
}
WLAN_SPEC: Spec = {
    **kept(
        "enabled", "wpa3_support", "wpa3_transition", "wpa3_fast_roaming", "wpa3_enhanced_192", "hide_ssid",
        "l2_isolation", "proxy_arp", "bss_transition", "fast_roaming_enabled", "roaming_assistant_na_enabled",
        "roaming_assistant_na_rssi", "roaming_assistant_6e_enabled", "uapsd_enabled", "mcastenhance_enabled",
        "bc_filter_enabled", "minrate_ng_enabled", "minrate_ng_data_rate_kbps", "minrate_ng_advertising_rates",
        "minrate_na_enabled", "minrate_na_data_rate_kbps", "minrate_na_advertising_rates", "dtim_ng", "dtim_na",
        "dtim_6e", "group_rekey", "sae_anti_clogging", "sae_sync", "no2ghz_oui", "advertise_device_name_in_beacon",
        "iot_channel_lock", "iot_dtim_lock", "enhanced_iot", "optimize_iot_wifi_connectivity", "b_supported",
        "private_preshared_keys_enabled", "mlo_enabled", "hotspot2conf_enabled", "rrm_enabled", "is_guest",
        "tdls_prohibit", "mac_filter_enabled", "radius_mac_auth_enabled", "name_combine_enabled", "vlan_enabled",
        "country_beacon",
    ),
    "wlan_band": vocab("both", "2g", "5g", "6g"),
    "wlan_bands": vocab_list("2g", "5g", "6g", "6e"),
    "security": vocab("open", "wpapsk", "wpaeap", "wep", "owe"),
    "wpa_mode": vocab("wpa1", "wpa2", "wpa3", "auto"),
    "wpa_enc": vocab("ccmp", "tkip", "auto", "gcmp"),
    "pmf_mode": vocab("disabled", "optional", "required"),
    "minrate_setting_preference": vocab("auto", "manual"),
    "setting_preference": vocab("auto", "manual"),
    "dtim_mode": vocab("default", "custom"),
    "dns_assistance_mode": vocab("auto", "off", "custom"),
    "mdns_proxy_mode": vocab("off", "all", "custom"),
    "mac_filter_policy": vocab("allow", "deny"),
    "ap_group_mode": vocab("all", "custom"),
    "_id": object_id,
    "name": ssid,
    "passphrase_autogenerated": flag,
    "ap_group_ids": object_id_list,
    "networkconf_id": object_id,
    "usergroup_id": object_id,
    "site_id": object_id,
}  # fmt: skip
AP_GROUP_SPEC: Spec = {
    "_id": object_id,
    "name": group_name,
    "attr_hidden_id": vocab("default"),
    "attr_no_delete": keep,
    "for_wlanconf": keep,
    "device_macs": mac_list,
}
# The controller's setting record names, closed so that free text cannot hide under `key`.
SETTING_KEY = vocab(
    "auto_speedtest", "connectivity", "country", "dashboard", "device_supervision", "doh", "dpi", "element_adopt",
    "ether_lighting", "global_nat", "global_network", "global_switch", "guest_access", "igmp_snooping", "ips",
    "ips_suppression", "ipsec", "lcm", "locale", "magic_site_to_site_vpn", "mdns", "mgmt", "netflow",
    "network_optimization", "ntp", "openvpn", "peer_to_peer", "radio_ai", "radius", "rsyslogd", "snmp",
    "ssl_inspection", "super_cloudaccess", "super_fabric_system_log", "super_fwupdate", "super_identity",
    "super_mail", "super_mgmt", "super_sdn", "super_smtp", "teleport", "test_and_commit", "traffic_flow", "ugw",
    "usg", "usg_geo", "wifi_ai", "baresip", "provider_capabilities", "porta", "broadcast", "ulp_go", "cybersecure",
)  # fmt: skip
SETTING_STUB_SPEC: Spec = {"key": SETTING_KEY, "_id": object_id, "site_id": object_id}
BLACKLIST_ENTRY_SPEC: Spec = {
    "channel": pattern(DIGITS, "a channel number"),
    "channel_width": pattern(DIGITS, "a channel width"),
    "radio": RADIO,
}
RADIO_AI_SPEC: Spec = {
    **SETTING_STUB_SPEC,
    **kept("enabled", "auto_enabled", "default", "auto_adjust_channels_to_country"),
    "optimize": vocab_list("channel", "power"),
    "cron_expr": pattern(CRON, "a cron expression"),
    "channels_ng": pattern_list(DIGITS, "a channel number"),
    "channels_na": pattern_list(DIGITS, "a channel number"),
    "channels_6e": pattern_list(DIGITS, "a channel number"),
    "ht_modes_ng": pattern_list(DIGITS, "a channel width"),
    "ht_modes_na": pattern_list(DIGITS, "a channel width"),
    "ht_modes_6e": pattern_list(DIGITS, "a channel width"),
    "radios": vocab_list("ng", "na", "6e"),
    "setting_preference": vocab("auto", "manual"),
    "auto_channel_presets_type": vocab("maximum_speed", "maximum_range", "balanced", "custom"),
    "channels_blacklist": list_of(BLACKLIST_ENTRY_SPEC),
    "radios_configuration": list_of({"dfs": keep, "channel_width": keep, "radio": RADIO}),
    "exclude_devices": mac_list,
}  # fmt: skip
COUNTRY_SPEC: Spec = {**SETTING_STUB_SPEC, "code": pattern(DIGITS, "a numeric country code")}
CONNECTIVITY_SPEC: Spec = {
    **SETTING_STUB_SPEC,
    "mlo_mesh_enabled": keep,
    "enabled": keep,
    "uplink_type": vocab("gateway", "wan", "none"),
}
MGMT_SPEC: Spec = {
    **SETTING_STUB_SPEC,
    **kept(
        "outdoor_mode_enabled", "led_enabled", "auto_upgrade", "auto_upgrade_hour", "alert_enabled",
        "advanced_feature_enabled", "debug_tools_enabled", "direct_connect_enabled", "unifi_idp_enabled",
        "wifiman_enabled",
    ),
    "x_ssh_enabled": flag,
    "x_ssh_auth_password_enabled": flag,
    "x_ssh_bind_wildcard": flag,
    "x_ssh_username": constant(FIXTURE_SSH_USER),
    "x_ssh_password": constant(FIXTURE_SSH_PASSWORD),
}  # fmt: skip
SETTING_SPECS: Mapping[str, Spec] = {
    "radio_ai": RADIO_AI_SPEC,
    "country": COUNTRY_SPEC,
    "connectivity": CONNECTIVITY_SPEC,
    "mgmt": MGMT_SPEC,
}
WIRELESS_CLIENT_SPEC: Spec = {
    **kept(
        "is_wired", "channel", "channel_width", "signal", "noise", "rssi", "satisfaction", "is_11r", "is_guest",
        "is_mlo", "tx_power", "tx_rate", "rx_rate", "nss", "powersave_enabled", "wifi_tx_retries_percentage",
        "tx_retries", "ccq", "vlan",
    ),
    "radio": RADIO,
    "radio_proto": vocab("ng", "na", "ac", "ax", "be"),
    "radio_name": pattern(INTERFACE, "a radio interface name"),
    "_id": object_id,
    "ap_mac": mac,
    "bssid": mac,
    "essid": ssid,
    "wlanconf_id": object_id,
    "site_id": object_id,
}  # fmt: skip
WIRED_CLIENT_SPEC: Spec = {"is_wired": keep, "is_guest": keep, "vlan": keep, "_id": object_id, "site_id": object_id}
SITE_SPEC: Spec = {
    "_id": object_id,
    "name": site_name,
    "desc": site_description,
    "attr_hidden_id": vocab("default"),
    "attr_no_delete": keep,
    "role": vocab("admin", "readonly"),
    "device_count": keep,
}


def device_spec(record: Record) -> Spec:
    if record.get("type") == "uap" or record.get("is_access_point") is True:
        return ACCESS_POINT_SPEC
    return OTHER_DEVICE_SPEC


def setting_spec(record: Record) -> Spec:
    key = record.get("key")
    return SETTING_SPECS.get(key, SETTING_STUB_SPEC) if isinstance(key, str) else SETTING_STUB_SPEC


def client_spec(record: Record) -> Spec:
    return WIRELESS_CLIENT_SPEC if record.get("is_wired") is False else WIRED_CLIENT_SPEC


@dataclass(frozen=True, slots=True)
class Endpoint:
    fixture: str
    live_name: str | None
    rule: Rule


ENDPOINTS: tuple[Endpoint, ...] = (
    Endpoint("stat_device.json", "live_api_s_{site}_stat_device.json", nested(envelope(records(device_spec)))),
    Endpoint("list_wlanconf.json", "live_api_s_{site}_list_wlanconf.json", nested(envelope(list_of(WLAN_SPEC)))),
    Endpoint("apgroups.json", "live_v2_api_site_{site}_apgroups.json", list_of(AP_GROUP_SPEC)),
    Endpoint("rest_setting.json", "live_api_s_{site}_rest_setting.json", nested(envelope(records(setting_spec)))),
    Endpoint("stat_sta.json", "live_api_s_{site}_stat_sta.json", nested(envelope(records(client_spec)))),
    # `self/sites` has no live dump; the fixture is hand-written and only checked.
    Endpoint("sites.json", None, nested(envelope(list_of(SITE_SPEC)))),
)
ENDPOINTS_BY_FIXTURE: Mapping[str, Endpoint] = {endpoint.fixture: endpoint for endpoint in ENDPOINTS}


def check_fixture(fixture_name: str, payload: Json) -> list[str]:
    """Every violation of the fixture contract, or an empty list for a clean fixture."""
    endpoint = ENDPOINTS_BY_FIXTURE.get(fixture_name)
    if endpoint is None:
        return [f"{fixture_name}: no fixture spec for this file"]
    return endpoint.rule.check(payload, "$")


def anonymize(payloads: Mapping[str, Json]) -> tuple[dict[str, Json], Counter[str]]:
    """Fixture name → anonymized payload for every live payload given by fixture name, plus dropped-key counts."""
    ctx = Anonymizer()
    out: dict[str, Json] = {}
    for endpoint in ENDPOINTS:
        if endpoint.fixture in payloads:
            try:
                out[endpoint.fixture] = endpoint.rule.apply(ctx, payloads[endpoint.fixture])
            except SpecError as exc:
                raise exc.within(f"{endpoint.fixture} $") from None
            except (TypeError, ValueError) as exc:
                raise SpecError(f"{endpoint.fixture} $", str(exc)) from None
    return out, ctx.dropped


@dataclass
class _Args:
    source: Path = field(default_factory=Path)
    dest: Path = field(default_factory=Path)
    site: str = "default"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source", type=Path, required=True, help="directory holding the live_*.json dumps")
    parser.add_argument("--dest", type=Path, required=True, help="fixture directory to write into")
    parser.add_argument("--site", default="default", help="site id used in the live dump file names")
    args = parser.parse_args(argv, namespace=_Args())
    payloads: dict[str, Json] = {}
    for endpoint in ENDPOINTS:
        if endpoint.live_name is None:
            continue
        source = args.source / endpoint.live_name.format(site=args.site)
        if source.exists():
            payloads[endpoint.fixture] = json.loads(source.read_text())
        else:
            print(f"skip {endpoint.fixture}: {source.name} not found", file=sys.stderr)
    try:
        fixtures, dropped = anonymize(payloads)
    except SpecError as exc:
        # A value outside the specs' vocabulary: the maintainer extends the spec knowingly or drops the key.
        print(f"error: {exc}; nothing written", file=sys.stderr)
        return 1
    violations = [f"{name} {problem}" for name, payload in fixtures.items() for problem in check_fixture(name, payload)]
    print(f"dropped {sum(dropped.values())} values under {len(dropped)} distinct keys", file=sys.stderr)
    if violations:
        for line in violations:
            print(f"VIOLATION {line}", file=sys.stderr)
        print("nothing written", file=sys.stderr)
        return 1
    for name, payload in fixtures.items():
        (args.dest / name).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        print(f"wrote {name}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
