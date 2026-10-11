"""Controller JSON → domain models.

Each `parse_*` function takes the already-decoded response body (the client decodes exactly once),
applies the limits in `validate`, and returns typed models. The mandatory set is minimal (plan): a device
needs `type`/`mac`/`name`/`ip` and each radio `radio`/`ht` plus `channel` unless the controller reports
`auto`; a mandatory-field failure turns the device into an `UnparsableDevice`. Every other field is
optional: invalid means None plus a `FieldProblem`; an invalid list element — a `radio_table_stats` or
`vap_table` entry, a channel, a MAC — is skipped the same way without touching its valid siblings. Error
texts carry the path and a static description, never the offending value — a controller string must not
travel into a report through an error message. Secrets are moved into `Secret` the moment they are read.
"""

from collections.abc import Callable, Mapping, Sequence
from typing import TypeVar

from unifiwifioptimizer.adapters.unifi.validate import (
    ANTENNA_GAIN_RANGE,
    CHANNEL_RANGE,
    CLIENT_COUNT_RANGE,
    COUNTRY_RANGE,
    DEVICE_COUNT_RANGE,
    DTIM_RANGE,
    EXTENSION_CHANNEL_RANGE,
    GROUP_REKEY_RANGE,
    MAX_AP_GROUPS,
    MAX_BLACKLIST,
    MAX_CHANNEL_LIST,
    MAX_CLIENTS,
    MAX_DEVICES,
    MAX_ID_BYTES,
    MAX_NAME_BYTES,
    MAX_OPTIMIZE_TARGETS,
    MAX_PASSWORD_BYTES,
    MAX_RADIOS_PER_DEVICE,
    MAX_SETTINGS,
    MAX_SHORT_TEXT_BYTES,
    MAX_SITES,
    MAX_SSID_BYTES,
    MAX_TOKEN_BYTES,
    MAX_VAPS_PER_DEVICE,
    MAX_WIDTH_LIST,
    MAX_WLAN_BANDS,
    MAX_WLANS,
    MINRATE_KBPS_RANGE,
    NOISE_RANGE,
    PERCENT_RANGE,
    RSSI_RANGE,
    SAE_COUNTER_RANGE,
    SPATIAL_STREAMS_RANGE,
    TX_POWER_RANGE,
    WIDTHS_MHZ,
    Accessor,
    Fields,
    Json,
    Observer,
    data_list,
    iter_records,
    require_list,
    require_mac,
    require_str,
    walk_depth,
)
from unifiwifioptimizer.domain.errors import SchemaError
from unifiwifioptimizer.domain.models import (
    SITE_ID_RE,
    SSH_USER_RE,
    AccessPoint,
    ApGroup,
    Band,
    ChannelAiSettings,
    ClientSighting,
    DevicesResult,
    FieldProblem,
    MgmtSettings,
    ParsedList,
    Radio,
    RadioStats,
    SettingsResult,
    Site,
    SiteSettings,
    TxPowerMode,
    UnparsableDevice,
    Vap,
    WlanConfig,
)
from unifiwifioptimizer.domain.secrets import Secret

T = TypeVar("T")

# The controller names radios by their legacy 802.11 amendment letters.
RADIO_BANDS: Mapping[str, Band] = {"ng": Band.GHZ_2, "na": Band.GHZ_5, "6e": Band.GHZ_6}
WLAN_BANDS: Mapping[str, Band] = {"2g": Band.GHZ_2, "5g": Band.GHZ_5, "6g": Band.GHZ_6, "6e": Band.GHZ_6}
WLAN_BAND_SHORTHANDS: Mapping[str, frozenset[Band]] = {
    "both": frozenset({Band.GHZ_2, Band.GHZ_5}),
    "2g": frozenset({Band.GHZ_2}),
    "5g": frozenset({Band.GHZ_5}),
    "6g": frozenset({Band.GHZ_6}),
}
# `radio_table_stats.satisfaction` and `stat/sta.satisfaction` carry -1 when nothing contributes.
NO_VALUE_SENTINEL = -1
# Channel numbers, widths and country codes have at most three digits; the cap also keeps `int()` away
# from strings long enough to exceed the interpreter's digit limit.
MAX_NUMERIC_TEXT_LENGTH = 3
AUTO_CHANNEL = "auto"
SETTING_KEYS = frozenset({"radio_ai", "country", "connectivity", "mgmt"})


def small_int(text: str) -> int | None:
    """A short ASCII digit string as an integer; anything else is None."""
    if text.isascii() and text.isdigit() and len(text) <= MAX_NUMERIC_TEXT_LENGTH:
        return int(text)
    return None


def band_of(fields: Fields, key: str) -> Band:
    raw = fields.raw(key)
    if not isinstance(raw, str) or raw not in RADIO_BANDS:
        raise SchemaError(fields.path(key), "unknown radio")
    return RADIO_BANDS[raw]


def width_value(raw: Json) -> int | None:
    # `radio_table.ht` is a string ("80"), `radio_table_stats.bw` an integer; a bool is never in the set.
    width = small_int(raw) if isinstance(raw, str) else raw
    return width if isinstance(width, int) and width in WIDTHS_MHZ else None


def width_of(fields: Fields, key: str) -> int:
    width = width_value(fields.raw(key))
    if width is None:
        raise SchemaError(fields.path(key), "unknown channel width")
    return width


def opt_width(fields: Fields, key: str) -> int | None:
    raw = fields.raw(key)
    if raw is None:
        return None
    width = width_value(raw)
    if width is None:
        fields.problems.append(FieldProblem(fields.path(key), "unknown channel width"))
    return width


def allowed_number(allowed: Callable[[int], bool]) -> Accessor[int]:
    """Accessor for a number given as a short digit string (`channels_na`) or an integer."""

    def read(item: Json, path: str) -> int:
        value = small_int(item) if isinstance(item, str) else item
        if isinstance(value, bool) or not isinstance(value, int) or not allowed(value):
            raise SchemaError(path, "not an allowed number")
        return value

    return read


def numeric_set(fields: Fields, key: str, max_items: int, allowed: Callable[[int], bool]) -> frozenset[int] | None:
    """Each invalid element is one problem and is skipped; an absent or invalid list is None."""
    values = fields.opt_items(key, max_items, allowed_number(allowed))
    return None if values is None else frozenset(values)


def configured_channel(fields: Fields) -> int | None:
    # Auto-channel radios report the string `auto`; their current channel is in `radio_table_stats`.
    if fields.raw("channel") == AUTO_CHANNEL:
        return None
    return fields.integer("channel", CHANNEL_RANGE)


def is_access_point(fields: Fields) -> bool:
    # Gateways with a built-in radio (UDR, UX) report their own `type` but flag `is_access_point`.
    return fields.raw("type") == "uap" or fields.raw("is_access_point") is True


def parse_radio(fields: Fields) -> Radio:
    mode: TxPowerMode | None = None
    mode_raw = fields.opt_string("tx_power_mode", MAX_TOKEN_BYTES)
    if mode_raw is not None:
        try:
            mode = TxPowerMode(mode_raw)
        except ValueError:
            fields.problems.append(FieldProblem(fields.path("tx_power_mode"), "unknown power mode"))
    return Radio(
        band=band_of(fields, "radio"),
        interface_name=fields.opt_string("name", MAX_SHORT_TEXT_BYTES),
        channel=configured_channel(fields),
        width_mhz=width_of(fields, "ht"),
        configured_tx_dbm=fields.opt_integer("tx_power", TX_POWER_RANGE),
        tx_power_mode=mode,
        min_tx_dbm=fields.opt_integer("min_txpower", TX_POWER_RANGE),
        max_tx_dbm=fields.opt_integer("max_txpower", TX_POWER_RANGE),
        min_rssi_enabled=fields.flag("min_rssi_enabled"),
        min_rssi_dbm=fields.opt_integer("min_rssi", RSSI_RANGE),
        antenna_gain_dbi=fields.opt_integer("antenna_gain", ANTENNA_GAIN_RANGE),
        spatial_streams=fields.opt_integer("nss", SPATIAL_STREAMS_RANGE),
        dfs_capable=fields.opt_bool("has_dfs"),
    )


def parse_radio_stats(fields: Fields) -> RadioStats:
    return RadioStats(
        band=band_of(fields, "radio"),
        channel=fields.integer("channel", CHANNEL_RANGE),
        width_mhz=width_of(fields, "bw"),
        extension_channel=fields.opt_integer("extchannel", EXTENSION_CHANNEL_RANGE),
        observed_tx_dbm=fields.opt_integer("tx_power", TX_POWER_RANGE),
        channel_utilisation_pct=fields.opt_integer("cu_total", PERCENT_RANGE),
        self_rx_utilisation_pct=fields.opt_integer("cu_self_rx", PERCENT_RANGE),
        self_tx_utilisation_pct=fields.opt_integer("cu_self_tx", PERCENT_RANGE),
        tx_retries_pct=fields.opt_float("tx_retries_pct", 0.0, 100.0),
        satisfaction_pct=fields.opt_integer("satisfaction", PERCENT_RANGE, sentinel=NO_VALUE_SENTINEL),
        state=fields.opt_string("state", MAX_SHORT_TEXT_BYTES),
        client_count=fields.opt_integer("num_sta", CLIENT_COUNT_RANGE),
    )


def parse_vap(fields: Fields) -> Vap:
    return Vap(
        band=band_of(fields, "radio"),
        bssid=fields.mac("bssid"),
        essid=fields.opt_string("essid", MAX_SSID_BYTES),
        channel=fields.opt_integer("channel", CHANNEL_RANGE),
        width_mhz=opt_width(fields, "bw"),
        up=fields.flag("up"),
        wlan_id=fields.opt_string("wlanconf_id", MAX_ID_BYTES),
        is_guest=fields.flag("is_guest"),
        client_count=fields.opt_integer("num_sta", CLIENT_COUNT_RANGE),
    )


def parse_entries(fields: Fields, key: str, max_items: int, parser: Callable[[Fields], T]) -> tuple[T, ...]:
    """Optional list of records; an entry that fails its own mandatory fields is skipped with a problem."""
    parsed: list[T] = []
    for entry in fields.opt_records(key, max_items):
        try:
            parsed.append(parser(entry))
        except SchemaError as exc:
            fields.problems.append(FieldProblem(exc.path, exc.detail))
    return tuple(parsed)


def _host_key_fingerprint(fields: Fields) -> str | None:
    # The controller sends "\n" for a key it has not learnt yet; whitespace-only is "none".
    text = fields.opt_string("x_ssh_hostkey_fingerprint", MAX_NAME_BYTES)
    return text.strip() or None if text is not None else None


def parse_access_point(fields: Fields) -> AccessPoint:
    fields.string("type", MAX_TOKEN_BYTES)
    radios = tuple(parse_radio(r) for r in fields.records("radio_table", MAX_RADIOS_PER_DEVICE))
    uplink = fields.opt_object("uplink")
    return AccessPoint(
        mac=fields.mac("mac"),
        name=fields.string("name"),
        ip=fields.ip("ip"),
        model=fields.opt_string("model", MAX_NAME_BYTES),
        firmware=fields.opt_string("version", MAX_ID_BYTES),
        uplink_type=uplink.opt_string("type", MAX_TOKEN_BYTES) if uplink is not None else None,
        radios=radios,
        radio_stats=parse_entries(fields, "radio_table_stats", MAX_RADIOS_PER_DEVICE, parse_radio_stats),
        vaps=parse_entries(fields, "vap_table", MAX_VAPS_PER_DEVICE, parse_vap),
        ssh_host_key_fingerprint=_host_key_fingerprint(fields),
    )


def parse_devices(payload: Json, observe: Observer | None = None) -> DevicesResult:
    """`stat/device`: access points only (`type == "uap"` or `is_access_point`); other devices are dropped
    before anything is read."""
    access_points: list[AccessPoint] = []
    unparsable: list[UnparsableDevice] = []
    problems: list[FieldProblem] = []
    for fields in iter_records(data_list(payload, MAX_DEVICES), "$.data", problems):
        if not is_access_point(fields):
            continue
        try:
            access_points.append(parse_access_point(fields))
        except SchemaError as exc:
            device = UnparsableDevice(mac=fields.opt_mac("mac"), name=fields.opt_string("name"), reason=str(exc))
            unparsable.append(device)
        if observe is not None:
            observe(fields)
    return DevicesResult(access_points=tuple(access_points), unparsable=tuple(unparsable), problems=tuple(problems))


def wlan_band(item: Json, path: str) -> Band:
    name = require_str(item, path, MAX_TOKEN_BYTES)
    if name not in WLAN_BANDS:
        raise SchemaError(path, "unknown band")
    return WLAN_BANDS[name]


def wlan_bands(fields: Fields) -> frozenset[Band]:
    bands = frozenset(fields.opt_items("wlan_bands", MAX_WLAN_BANDS, wlan_band) or ())
    if bands:
        return bands
    shorthand = fields.opt_string("wlan_band", MAX_TOKEN_BYTES)
    if shorthand is not None:
        if shorthand in WLAN_BAND_SHORTHANDS:
            return WLAN_BAND_SHORTHANDS[shorthand]
        fields.problems.append(FieldProblem(fields.path("wlan_band"), "unknown band"))
    raise SchemaError(fields.path("wlan_bands"), "no band information")


def parse_wlan(fields: Fields) -> WlanConfig:
    return WlanConfig(
        id=fields.string("_id", MAX_ID_BYTES),
        name=fields.string("name", MAX_SSID_BYTES),
        enabled=fields.flag("enabled", default=True),
        bands=wlan_bands(fields),
        security=fields.opt_string("security", MAX_SHORT_TEXT_BYTES),
        wpa_mode=fields.opt_string("wpa_mode", MAX_SHORT_TEXT_BYTES),
        wpa_enc=fields.opt_string("wpa_enc", MAX_SHORT_TEXT_BYTES),
        wpa3_support=fields.opt_bool("wpa3_support"),
        wpa3_transition=fields.opt_bool("wpa3_transition"),
        wpa3_fast_roaming=fields.opt_bool("wpa3_fast_roaming"),
        wpa3_enhanced_192=fields.opt_bool("wpa3_enhanced_192"),
        pmf_mode=fields.opt_string("pmf_mode", MAX_TOKEN_BYTES),
        hide_ssid=fields.opt_bool("hide_ssid"),
        l2_isolation=fields.opt_bool("l2_isolation"),
        proxy_arp=fields.opt_bool("proxy_arp"),
        bss_transition=fields.opt_bool("bss_transition"),
        fast_roaming_enabled=fields.opt_bool("fast_roaming_enabled"),
        roaming_assistant_na_enabled=fields.opt_bool("roaming_assistant_na_enabled"),
        roaming_assistant_na_rssi=fields.opt_integer("roaming_assistant_na_rssi", RSSI_RANGE),
        roaming_assistant_6e_enabled=fields.opt_bool("roaming_assistant_6e_enabled"),
        uapsd_enabled=fields.opt_bool("uapsd_enabled"),
        mcastenhance_enabled=fields.opt_bool("mcastenhance_enabled"),
        bc_filter_enabled=fields.opt_bool("bc_filter_enabled"),
        minrate_setting_preference=fields.opt_string("minrate_setting_preference", MAX_TOKEN_BYTES),
        minrate_ng_enabled=fields.opt_bool("minrate_ng_enabled"),
        minrate_ng_data_rate_kbps=fields.opt_integer("minrate_ng_data_rate_kbps", MINRATE_KBPS_RANGE),
        minrate_na_enabled=fields.opt_bool("minrate_na_enabled"),
        minrate_na_data_rate_kbps=fields.opt_integer("minrate_na_data_rate_kbps", MINRATE_KBPS_RANGE),
        dtim_mode=fields.opt_string("dtim_mode", MAX_TOKEN_BYTES),
        dtim_ng=fields.opt_integer("dtim_ng", DTIM_RANGE),
        dtim_na=fields.opt_integer("dtim_na", DTIM_RANGE),
        dtim_6e=fields.opt_integer("dtim_6e", DTIM_RANGE),
        group_rekey=fields.opt_integer("group_rekey", GROUP_REKEY_RANGE),
        sae_anti_clogging=fields.opt_integer("sae_anti_clogging", SAE_COUNTER_RANGE),
        sae_sync=fields.opt_integer("sae_sync", SAE_COUNTER_RANGE),
        band_steering=fields.opt_bool("no2ghz_oui"),
        advertise_device_name_in_beacon=fields.opt_bool("advertise_device_name_in_beacon"),
        iot_channel_lock=fields.opt_bool("iot_channel_lock"),
        iot_dtim_lock=fields.opt_bool("iot_dtim_lock"),
        enhanced_iot=fields.opt_bool("enhanced_iot"),
        optimize_iot_wifi_connectivity=fields.opt_bool("optimize_iot_wifi_connectivity"),
        b_supported=fields.opt_bool("b_supported"),
        dns_assistance_mode=fields.opt_string("dns_assistance_mode", MAX_TOKEN_BYTES),
        mdns_proxy_mode=fields.opt_string("mdns_proxy_mode", MAX_TOKEN_BYTES),
        private_preshared_keys_enabled=fields.opt_bool("private_preshared_keys_enabled"),
        mlo_enabled=fields.opt_bool("mlo_enabled"),
        hotspot2conf_enabled=fields.opt_bool("hotspot2conf_enabled"),
        rrm_enabled=fields.opt_bool("rrm_enabled"),
        is_guest=fields.opt_bool("is_guest"),
        ap_group_mode=fields.opt_string("ap_group_mode", MAX_TOKEN_BYTES),
        ap_group_ids=fields.opt_string_list("ap_group_ids", MAX_AP_GROUPS),
    )


def parse_isolated(
    items: Sequence[Json], path: str, parser: Callable[[Fields], T], observe: Observer | None = None
) -> ParsedList[T]:
    """One record's mandatory-field failure becomes a problem; the other records are still parsed."""
    parsed: list[T] = []
    problems: list[FieldProblem] = []
    for fields in iter_records(items, path, problems):
        try:
            parsed.append(parser(fields))
        except SchemaError as exc:
            problems.append(FieldProblem(exc.path, exc.detail))
            continue
        if observe is not None:
            observe(fields)
    return ParsedList(items=tuple(parsed), problems=tuple(problems))


def parse_wlans(payload: Json, observe: Observer | None = None) -> ParsedList[WlanConfig]:
    return parse_isolated(data_list(payload, MAX_WLANS), "$.data", parse_wlan, observe)


def mac_set(fields: Fields, key: str, max_items: int) -> frozenset[str]:
    return frozenset(fields.opt_items(key, max_items, require_mac) or ())


def parse_ap_group(fields: Fields) -> ApGroup:
    return ApGroup(
        id=fields.string("_id", MAX_ID_BYTES),
        name=fields.string("name"),
        device_macs=mac_set(fields, "device_macs", MAX_DEVICES),
    )


def parse_ap_groups(payload: Json, observe: Observer | None = None) -> ParsedList[ApGroup]:
    """`v2/api/site/<id>/apgroups` answers with a bare list, not a `data` envelope."""
    walk_depth(payload)
    return parse_isolated(require_list(payload, "$", MAX_AP_GROUPS), "$", parse_ap_group, observe)


def blacklist_entry(entry: Fields) -> tuple[Band, int, int] | None:
    radio, channel, width = entry.raw("radio"), entry.raw("channel"), entry.raw("channel_width")
    if not (isinstance(radio, str) and radio in RADIO_BANDS and isinstance(channel, str) and isinstance(width, str)):
        return None
    channel_number, width_mhz = small_int(channel), small_int(width)
    if channel_number is None or channel_number not in CHANNEL_RANGE or width_mhz not in WIDTHS_MHZ:
        return None
    return RADIO_BANDS[radio], channel_number, width_mhz


def parse_channel_ai(fields: Fields) -> ChannelAiSettings:
    channels: dict[Band, frozenset[int]] = {}
    widths: dict[Band, frozenset[int]] = {}
    for radio_name, band in RADIO_BANDS.items():
        channel_set = numeric_set(fields, f"channels_{radio_name}", MAX_CHANNEL_LIST, CHANNEL_RANGE.__contains__)
        if channel_set is not None:
            channels[band] = channel_set
        width_set = numeric_set(fields, f"ht_modes_{radio_name}", MAX_WIDTH_LIST, WIDTHS_MHZ.__contains__)
        if width_set is not None:
            widths[band] = width_set
    blacklist: set[tuple[Band, int, int]] = set()
    for entry in fields.opt_records("channels_blacklist", MAX_BLACKLIST):
        triple = blacklist_entry(entry)
        if triple is None:
            fields.problems.append(FieldProblem(entry.path_self, "invalid blacklist entry"))
        else:
            blacklist.add(triple)
    return ChannelAiSettings(
        enabled=fields.flag("enabled"),
        auto_enabled=fields.opt_bool("auto_enabled"),
        optimize=frozenset(fields.opt_string_list("optimize", MAX_OPTIMIZE_TARGETS, MAX_TOKEN_BYTES)),
        cron_expr=fields.opt_string("cron_expr", MAX_ID_BYTES),
        channels=channels,
        width_candidates_mhz=widths,
        excluded_devices=mac_set(fields, "exclude_devices", MAX_DEVICES),
        blacklist=frozenset(blacklist),
    )


def country_code(fields: Fields) -> int | None:
    # The live controller sends the numeric code as a string ("276"); older builds sent an integer.
    raw = fields.raw("code")
    if isinstance(raw, str):
        value = small_int(raw)
        if value is None or value not in COUNTRY_RANGE:
            fields.problems.append(FieldProblem(fields.path("code"), "expected a numeric country code"))
            return None
        return value
    return fields.opt_integer("code", COUNTRY_RANGE)


def parse_mgmt(fields: Fields) -> MgmtSettings:
    user = fields.opt_string("x_ssh_username", MAX_SHORT_TEXT_BYTES)
    if user is not None and not SSH_USER_RE.fullmatch(user):
        # It goes into ssh's `user@host`; anything that is not a plain user name is dropped, loudly.
        fields.problems.append(FieldProblem(fields.path("x_ssh_username"), "not a user name"))
        user = None
    password = fields.opt_string("x_ssh_password", MAX_PASSWORD_BYTES)
    return MgmtSettings(
        ssh_enabled=fields.opt_bool("x_ssh_enabled"),
        ssh_password_auth_enabled=fields.opt_bool("x_ssh_auth_password_enabled"),
        ssh_user=user,
        ssh_password=Secret(password) if password else None,
    )


def parse_settings(payload: Json, observe: Observer | None = None) -> SettingsResult:
    """`rest/setting`: only the `radio_ai`, `country`, `connectivity` and `mgmt` records are read; every
    other record is discarded unread. A duplicate of one of the four keys is a problem; the first wins."""
    by_key: dict[str, Fields] = {}
    problems: list[FieldProblem] = []
    for fields in iter_records(data_list(payload, MAX_SETTINGS), "$.data", problems):
        key = fields.opt_string("key", MAX_ID_BYTES)
        if key in SETTING_KEYS:
            if key in by_key:
                problems.append(FieldProblem(fields.path("key"), "duplicate setting record"))
            else:
                by_key[key] = fields
    radio_ai = by_key.get("radio_ai")
    country = by_key.get("country")
    connectivity = by_key.get("connectivity")
    mgmt_fields = by_key.get("mgmt")
    settings = SiteSettings(
        country_code=country_code(country) if country is not None else None,
        channel_ai=parse_channel_ai(radio_ai) if radio_ai is not None else None,
        mlo_mesh_enabled=connectivity.opt_bool("mlo_mesh_enabled") if connectivity is not None else None,
        outdoor_mode_enabled=mgmt_fields.opt_bool("outdoor_mode_enabled") if mgmt_fields is not None else None,
    )
    mgmt = parse_mgmt(mgmt_fields) if mgmt_fields is not None else None
    if observe is not None:
        for fields in by_key.values():
            observe(fields)
    return SettingsResult(settings=settings, mgmt=mgmt, problems=tuple(problems))


def parse_clients(payload: Json, observe: Observer | None = None) -> ParsedList[ClientSighting]:
    """`stat/sta`: wireless clients only, reduced to the per-AP signal picture; identifiers are never read."""
    clients: list[ClientSighting] = []
    problems: list[FieldProblem] = []
    for fields in iter_records(data_list(payload, MAX_CLIENTS), "$.data", problems):
        wired = fields.raw("is_wired")
        if not isinstance(wired, bool):
            problems.append(FieldProblem(fields.path("is_wired"), "expected a boolean"))
            continue
        if wired:
            continue
        ap_mac = fields.opt_mac("ap_mac")
        if ap_mac is None and not fields.has("ap_mac"):
            fields.problems.append(FieldProblem(fields.path("ap_mac"), "client without an access point"))
        radio = fields.raw("radio")
        band = RADIO_BANDS.get(radio) if isinstance(radio, str) else None
        if band is None:
            fields.problems.append(FieldProblem(fields.path("radio"), "unknown radio"))
        if ap_mac is None or band is None:
            continue
        clients.append(
            ClientSighting(
                ap_mac=ap_mac,
                band=band,
                essid=fields.opt_string("essid", MAX_SSID_BYTES),
                channel=fields.opt_integer("channel", CHANNEL_RANGE),
                signal_dbm=fields.opt_integer("signal", RSSI_RANGE),
                noise_dbm=fields.opt_integer("noise", NOISE_RANGE),
                satisfaction_pct=fields.opt_integer("satisfaction", PERCENT_RANGE, sentinel=NO_VALUE_SENTINEL),
                fast_transition=fields.opt_bool("is_11r"),
            )
        )
        if observe is not None:
            observe(fields)
    return ParsedList(items=tuple(clients), problems=tuple(problems))


def parse_site(fields: Fields) -> Site:
    name = fields.string("name", MAX_ID_BYTES)
    if SITE_ID_RE.fullmatch(name) is None:
        raise SchemaError(fields.path("name"), "not a site id")
    return Site(
        id=name,
        description=fields.opt_string("desc") or name,
        hidden_id=fields.opt_string("attr_hidden_id", MAX_ID_BYTES),
        device_count=fields.opt_integer("device_count", DEVICE_COUNT_RANGE),
    )


def parse_sites(payload: Json, observe: Observer | None = None) -> ParsedList[Site]:
    """`self/sites`."""
    return parse_isolated(data_list(payload, MAX_SITES), "$.data", parse_site, observe)
