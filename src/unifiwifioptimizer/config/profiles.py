"""The WLAN profiles: the shipped `resources/profiles.yaml`, optionally overridden by a user file.

An override file has the same shape. A profile with a shipped name replaces that profile whole (no
per-key merge, so a reader of the override sees the complete expectation); new names are added; its
`evidence` entries replace the shipped ones key by key. Unknown keys, unknown vocabulary and missing
required keys are errors — a profile that silently meant something else would make every compliance
finding worthless. The override lives next to the configuration file that is actually in use.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import TypeVar

from unifiwifioptimizer.config.loader import parse_yaml, read_text_file
from unifiwifioptimizer.config.locations import ConfigLocation
from unifiwifioptimizer.domain.errors import ConfigError
from unifiwifioptimizer.domain.models import Band
from unifiwifioptimizer.domain.profile import (
    DNS_ASSISTANCE_MODES,
    MDNS_PROXY_MODES,
    MULTICAST_SUPPRESSOR_MODES,
    DtimMode,
    Evidence,
    EvidenceTier,
    MinRateMode,
    PmfMode,
    Profile,
    ProfileSet,
    SecurityProtocol,
)

RESOURCE_NAME = "profiles.yaml"
MAX_PROFILES = 64
MAX_PROFILE_NAME_CHARS = 64
MAX_SOURCE_CHARS = 512
MAX_PROFILES_FILE_BYTES = 256 * 1024
MINRATE_KBPS_RANGE = range(1000, 1_000_001)
DTIM_RANGE = range(1, 256)
GROUP_REKEY_RANGE = range(0, 86_401)
SAE_COUNTER_RANGE = range(0, 1001)

BOOL_KEYS = (
    "fast_roaming",
    "bss_transition",
    "roaming_assistant",
    "band_steering",
    "mlo",
    "uapsd",
    "proxy_arp",
    "multicast_to_unicast",
    "hide_wifi_name",
    "client_device_isolation",
    "ap_name_in_beacon",
)
OPTIONAL_BOOL_KEYS = ("iot_dtim_lock", "iot_channel_lock", "enhanced_iot", "ppsk", "wpa3_enhanced_192")
OPTIONAL_TEXT_KEYS: Mapping[str, frozenset[str]] = {
    "dns_assistance_mode": DNS_ASSISTANCE_MODES,
    "mdns_proxy_mode": MDNS_PROXY_MODES,
    "multicast_suppressor_mode": MULTICAST_SUPPRESSOR_MODES,
}
REQUIRED_KEYS = frozenset(
    {
        "wifi_bands",
        "security_protocols",
        "pmf",
        *BOOL_KEYS,
        "minrate_mode",
        "dtim_mode",
        "group_rekey_s",
        "sae_anti_clogging",
        "sae_sync_time",
    }
)
CONDITIONAL_KEYS = frozenset({"minrate_24_kbps", "minrate_5_kbps", "dtim_24", "dtim_5", "dtim_6"})
PROFILE_KEYS = frozenset({*REQUIRED_KEYS, *CONDITIONAL_KEYS, *OPTIONAL_BOOL_KEYS, *OPTIONAL_TEXT_KEYS})
# Per-profile evidence overrides live under this key inside a profile; it is not a checked setting.
EVIDENCE_KEY = "evidence"
# Keys of the legacy profiles file and what replaced them, so a migrating file gets a pointer, not a riddle.
RENAMED_KEYS: Mapping[str, str] = {
    "group_rekey": "group_rekey_s",
    "multicast_broadcast_blocker": "multicast_suppressor_mode (off, conservative or aggressive)",
}
Value = object
T = TypeVar("T")


def profiles_path_beside(location: ConfigLocation) -> Path | None:
    """`profiles.yaml` in the directory of the configuration file actually in use — except for the legacy
    data directory: the pre-rewrite installer put its own, differently shaped `profiles.yaml` there, which
    must not be read as an override."""
    return None if location.legacy else location.path.with_name(RESOURCE_NAME)


def shipped_profiles_text() -> str:
    return resources.files("unifiwifioptimizer.resources").joinpath(RESOURCE_NAME).read_text(encoding="utf-8")


def _mapping(value: Value, path: str) -> Mapping[str, Value]:
    if not isinstance(value, Mapping):
        raise ConfigError(path, "expected a mapping")
    for key in value:
        if not isinstance(key, str):
            raise ConfigError(path, "keys must be strings")
    return value


def _bool(mapping: Mapping[str, Value], path: str, key: str) -> bool:
    value = mapping[key]
    if not isinstance(value, bool):
        raise ConfigError(f"{path}.{key}", "expected true or false")
    return value


def _int(mapping: Mapping[str, Value], path: str, key: str, allowed: range) -> int:
    value = mapping[key]
    if isinstance(value, bool) or not isinstance(value, int) or value not in allowed:
        raise ConfigError(f"{path}.{key}", f"expected an integer {allowed.start}..{allowed.stop - 1}")
    return value


def _text_list(mapping: Mapping[str, Value], path: str, key: str) -> list[str]:
    value = mapping[key]
    if isinstance(value, str):
        raise ConfigError(f"{path}.{key}", "expected a list of accepted values, one per entry (e.g. [WPA2])")
    if not isinstance(value, list) or not value or not all(isinstance(item, str) for item in value):
        raise ConfigError(f"{path}.{key}", "expected a non-empty list of names")
    if len(set(value)) != len(value):
        raise ConfigError(f"{path}.{key}", "duplicate entry")
    return value


def _enum(path: str, key: str, text: Value, options: Mapping[str, T], what: str) -> T:
    if not isinstance(text, str) or text not in options:
        raise ConfigError(f"{path}.{key}", f"expected one of {', '.join(sorted(options))} ({what})")
    return options[text]


def _conditional_int(mapping: Mapping[str, Value], path: str, key: str, wanted: bool, allowed: range) -> int | None:
    if not wanted:
        if key in mapping:
            raise ConfigError(f"{path}.{key}", "only meaningful with the matching mode and band; remove it")
        return None
    if key not in mapping:
        raise ConfigError(f"{path}.{key}", "required by the mode and the bands of this profile")
    return _int(mapping, path, key, allowed)


def parse_profile(name: str, value: Value, path: str) -> Profile:
    mapping = _mapping(value, path)
    unknown = set(mapping) - PROFILE_KEYS - {EVIDENCE_KEY}
    if unknown:
        key = sorted(unknown)[0]
        if key in RENAMED_KEYS:
            raise ConfigError(f"{path}.{key}", f"renamed to {RENAMED_KEYS[key]}")
        raise ConfigError(f"{path}.{key}", "unknown profile key")
    missing = REQUIRED_KEYS - set(mapping)
    if missing:
        raise ConfigError(f"{path}.{sorted(missing)[0]}", "missing")
    bands = frozenset(
        _enum(path, "wifi_bands", band, {b.value: b for b in Band}, "band")
        for band in _text_list(mapping, path, "wifi_bands")
    )
    protocols = frozenset(
        _enum(path, "security_protocols", p, {s.value: s for s in SecurityProtocol}, "security protocol")
        for p in _text_list(mapping, path, "security_protocols")
    )
    pmf = frozenset(
        _enum(path, "pmf", m, {p.value: p for p in PmfMode}, "PMF mode") for m in _text_list(mapping, path, "pmf")
    )
    minrate = _enum(path, "minrate_mode", mapping["minrate_mode"], {m.value: m for m in MinRateMode}, "mode")
    dtim = _enum(path, "dtim_mode", mapping["dtim_mode"], {m.value: m for m in DtimMode}, "mode")
    manual = minrate is MinRateMode.MANUAL
    custom = dtim is DtimMode.CUSTOM

    def flag(key: str) -> bool:
        return _bool(mapping, path, key)

    def optional_flag(key: str) -> bool | None:
        return _bool(mapping, path, key) if key in mapping else None

    def optional_mode(key: str) -> str | None:
        vocab = OPTIONAL_TEXT_KEYS[key]
        return _enum(path, key, mapping[key], {v: v for v in vocab}, "mode") if key in mapping else None

    return Profile(
        name=name,
        wifi_bands=bands,
        security_protocols=protocols,
        pmf=pmf,
        fast_roaming=flag("fast_roaming"),
        bss_transition=flag("bss_transition"),
        roaming_assistant=flag("roaming_assistant"),
        band_steering=flag("band_steering"),
        mlo=flag("mlo"),
        uapsd=flag("uapsd"),
        proxy_arp=flag("proxy_arp"),
        multicast_to_unicast=flag("multicast_to_unicast"),
        hide_wifi_name=flag("hide_wifi_name"),
        client_device_isolation=flag("client_device_isolation"),
        ap_name_in_beacon=flag("ap_name_in_beacon"),
        minrate_mode=minrate,
        minrate_24_kbps=_conditional_int(
            mapping, path, "minrate_24_kbps", manual and Band.GHZ_2 in bands, MINRATE_KBPS_RANGE
        ),
        minrate_5_kbps=_conditional_int(
            mapping, path, "minrate_5_kbps", manual and Band.GHZ_5 in bands, MINRATE_KBPS_RANGE
        ),
        dtim_mode=dtim,
        dtim_24=_conditional_int(mapping, path, "dtim_24", custom and Band.GHZ_2 in bands, DTIM_RANGE),
        dtim_5=_conditional_int(mapping, path, "dtim_5", custom and Band.GHZ_5 in bands, DTIM_RANGE),
        dtim_6=_conditional_int(mapping, path, "dtim_6", custom and Band.GHZ_6 in bands, DTIM_RANGE),
        group_rekey_s=_int(mapping, path, "group_rekey_s", GROUP_REKEY_RANGE),
        sae_anti_clogging=_int(mapping, path, "sae_anti_clogging", SAE_COUNTER_RANGE),
        sae_sync_time=_int(mapping, path, "sae_sync_time", SAE_COUNTER_RANGE),
        iot_dtim_lock=optional_flag("iot_dtim_lock"),
        iot_channel_lock=optional_flag("iot_channel_lock"),
        enhanced_iot=optional_flag("enhanced_iot"),
        ppsk=optional_flag("ppsk"),
        wpa3_enhanced_192=optional_flag("wpa3_enhanced_192"),
        dns_assistance_mode=optional_mode("dns_assistance_mode"),
        mdns_proxy_mode=optional_mode("mdns_proxy_mode"),
        multicast_suppressor_mode=optional_mode("multicast_suppressor_mode"),
        evidence=parse_evidence(mapping[EVIDENCE_KEY], f"{path}.{EVIDENCE_KEY}") if EVIDENCE_KEY in mapping else {},
    )


def parse_evidence(value: Value, path: str) -> dict[str, Evidence]:
    mapping = _mapping(value, path)
    unknown = set(mapping) - PROFILE_KEYS
    if unknown:
        raise ConfigError(f"{path}.{sorted(unknown)[0]}", "not a profile key")
    entries: dict[str, Evidence] = {}
    for key, raw in mapping.items():
        entry = _mapping(raw, f"{path}.{key}")
        if set(entry) != {"tier", "source"}:
            raise ConfigError(f"{path}.{key}", "expected exactly tier and source")
        tier = _enum(f"{path}.{key}", "tier", entry["tier"], {t.value: t for t in EvidenceTier}, "tier")
        source = entry["source"]
        if not isinstance(source, str) or not 0 < len(source) <= MAX_SOURCE_CHARS:
            raise ConfigError(f"{path}.{key}.source", f"expected text of 1..{MAX_SOURCE_CHARS} characters")
        entries[key] = Evidence(tier=tier, source=source)
    return entries


def parse_profiles_document(document: Value, source: str, require_complete_evidence: bool) -> ProfileSet:
    root = _mapping(document, source)
    unknown = set(root) - {"profiles", "evidence"}
    if unknown:
        raise ConfigError(f"{source}.{sorted(unknown)[0]}", "unknown top-level key (expected profiles, evidence)")
    if "profiles" not in root:
        raise ConfigError(f"{source}.profiles", "missing")
    raw_profiles = _mapping(root["profiles"], f"{source}.profiles")
    if not raw_profiles:
        raise ConfigError(f"{source}.profiles", "no profiles defined")
    if len(raw_profiles) > MAX_PROFILES:
        raise ConfigError(f"{source}.profiles", f"more than {MAX_PROFILES} profiles")
    profiles: dict[str, Profile] = {}
    for name, value in raw_profiles.items():
        if not 0 < len(name) <= MAX_PROFILE_NAME_CHARS:
            raise ConfigError(f"{source}.profiles", f"profile names must be 1..{MAX_PROFILE_NAME_CHARS} characters")
        profiles[name] = parse_profile(name, value, f"{source}.profiles.{name}")
    evidence = parse_evidence(root["evidence"], f"{source}.evidence") if "evidence" in root else {}
    if require_complete_evidence:
        missing = PROFILE_KEYS - set(evidence)
        if missing:
            raise ConfigError(f"{source}.evidence.{sorted(missing)[0]}", "every profile key needs an evidence entry")
    return ProfileSet(profiles=profiles, evidence=evidence)


def shipped_profiles() -> ProfileSet:
    return parse_profiles_document(parse_yaml(shipped_profiles_text(), RESOURCE_NAME), RESOURCE_NAME, True)


@dataclass(frozen=True, slots=True, kw_only=True)
class LoadedProfiles:
    """`override_text` is the override file exactly as validated, so what is printed is what is compared."""

    profiles: ProfileSet
    override_path: Path | None
    override_text: str | None


def load_profiles(override: Path | None, location: ConfigLocation) -> LoadedProfiles:
    """The effective profile set. An explicit `override` must exist; otherwise `profiles.yaml` beside the
    configuration file is used when something is there (a dangling symlink included, so it is reported
    rather than silently skipped)."""
    shipped = shipped_profiles()
    path = override if override is not None else profiles_path_beside(location)
    if path is None or (override is None and not (path.exists() or path.is_symlink())):
        return LoadedProfiles(profiles=shipped, override_path=None, override_text=None)
    text = read_text_file(path, MAX_PROFILES_FILE_BYTES)
    extra = parse_profiles_document(parse_yaml(text, str(path)), str(path), False)
    merged = ProfileSet(
        profiles={**shipped.profiles, **extra.profiles}, evidence={**shipped.evidence, **extra.evidence}
    )
    return LoadedProfiles(profiles=merged, override_path=path, override_text=text)
