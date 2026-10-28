"""The profiles loader: the shipped file, its evidence coverage, the schema's refusals, the override."""

import copy
import os
import threading
from pathlib import Path
from typing import Any

import pytest

from unifiwifioptimizer.config.loader import parse_yaml
from unifiwifioptimizer.config.locations import ConfigLocation
from unifiwifioptimizer.config.profiles import (
    MAX_PROFILES_FILE_BYTES,
    PROFILE_KEYS,
    load_profiles,
    parse_profiles_document,
    profiles_path_beside,
    shipped_profiles,
    shipped_profiles_text,
)
from unifiwifioptimizer.domain.errors import ConfigError
from unifiwifioptimizer.domain.models import Band
from unifiwifioptimizer.domain.profile import DtimMode, EvidenceTier, MinRateMode, PmfMode, SecurityProtocol

Document = dict[str, Any]


def shipped_document() -> Document:
    document = parse_yaml(shipped_profiles_text(), "profiles.yaml")
    assert isinstance(document, dict)
    return copy.deepcopy(document)


def test_the_shipped_profiles_load_and_cover_every_key_with_evidence() -> None:
    profiles = shipped_profiles()
    assert sorted(profiles.profiles) == ["Compat", "Hotspot", "IoT", "Standard"]
    assert set(profiles.evidence) == PROFILE_KEYS
    assert {e.tier for e in profiles.evidence.values()} == set(EvidenceTier)
    assert "ADR-" not in shipped_profiles_text() and "in this release" not in shipped_profiles_text()


def test_the_shipped_baselines_follow_the_decided_recommendations() -> None:
    p = shipped_profiles().profiles
    standard, compat, iot, hotspot = p["Standard"], p["Compat"], p["IoT"], p["Hotspot"]
    assert standard.security_protocols == {
        SecurityProtocol.WPA2_WPA3,
        SecurityProtocol.WPA3,
        SecurityProtocol.WPA2_WPA3_ENTERPRISE,
        SecurityProtocol.WPA3_ENTERPRISE,
    }
    assert standard.pmf == {PmfMode.OPTIONAL, PmfMode.REQUIRED}
    assert standard.fast_roaming and standard.roaming_assistant and standard.group_rekey_s == 3600
    assert standard.minrate_mode is MinRateMode.MANUAL
    assert (standard.minrate_24_kbps, standard.minrate_5_kbps) == (12000, 12000)
    assert standard.wifi_bands == {Band.GHZ_2, Band.GHZ_5}
    assert standard.dtim_mode is DtimMode.DEFAULT and standard.dtim_24 is None and standard.dtim_6 is None
    # Compat is Standard for clients that dislike 802.11r, fixed rates and WPA3.
    assert compat.fast_roaming is False and compat.minrate_mode is MinRateMode.AUTO
    assert SecurityProtocol.WPA2 in compat.security_protocols and PmfMode.DISABLED in compat.pmf
    assert compat.wifi_bands == standard.wifi_bands
    assert compat.bss_transition and compat.band_steering and compat.roaming_assistant
    assert hotspot.security_protocols == {
        SecurityProtocol.OWE_TRANSITION,
        SecurityProtocol.OWE,
        SecurityProtocol.OPEN,
    }
    assert hotspot.client_device_isolation and hotspot.mdns_proxy_mode == "off" and hotspot.proxy_arp
    assert iot.wifi_bands == {Band.GHZ_2}
    assert iot.security_protocols == {SecurityProtocol.WPA2}
    assert iot.pmf == {PmfMode.DISABLED, PmfMode.OPTIONAL} and iot.group_rekey_s == 0
    assert iot.fast_roaming is False and iot.band_steering is False
    assert iot.iot_channel_lock is False and iot.iot_dtim_lock is None and iot.enhanced_iot is None
    assert not any(profile.uapsd for profile in p.values())
    assert {p[name].proxy_arp for name in ("Standard", "Compat", "Hotspot")} == {True}
    assert {p[name].multicast_to_unicast for name in ("Standard", "Compat")} == {True}
    assert not iot.multicast_to_unicast and not hotspot.multicast_to_unicast


def test_per_profile_evidence_overrides_the_set_wide_tier_for_compatibility_choices() -> None:
    profiles = shipped_profiles()
    iot, standard = profiles.profiles["IoT"], profiles.profiles["Standard"]
    assert profiles.evidence["pmf"].tier is EvidenceTier.STANDARD
    iot_pmf = profiles.evidence_for(iot, "pmf")
    assert iot_pmf is not None and iot_pmf.tier is EvidenceTier.VENDOR
    assert profiles.evidence_for(standard, "pmf") == profiles.evidence["pmf"]
    assert set(iot.evidence) == {
        "wifi_bands",
        "security_protocols",
        "pmf",
        "fast_roaming",
        "bss_transition",
        "roaming_assistant",
        "band_steering",
        "mlo",
        "uapsd",
        "client_device_isolation",
        "multicast_suppressor_mode",
        "dns_assistance_mode",
        "minrate_mode",
        "dtim_mode",
        "group_rekey_s",
        "iot_channel_lock",
        "proxy_arp",
        "multicast_to_unicast",
    }
    assert profiles.evidence_for(iot, "no_such_key") is None


@pytest.mark.parametrize("key", ["proxy_arp", "multicast_to_unicast"])
def test_a_profile_that_switches_a_vendor_advised_setting_off_carries_its_own_entry(key: str) -> None:
    # The set-wide entry gives vendor guidance for the setting being on; a profile that switches it off must
    # say why itself.
    profiles = shipped_profiles()
    assert profiles.evidence[key].tier is EvidenceTier.VENDOR
    for name, profile in profiles.profiles.items():
        own = profiles.evidence_for(profile, key)
        assert own is not None
        if getattr(profile, key):
            assert own.tier is EvidenceTier.VENDOR, name
        else:
            assert key in profile.evidence and own != profiles.evidence[key], name


def mutate(path: str, value: Any, delete: bool = False, also: dict[str, Any] | None = None) -> Document:
    """Set (or delete) one value of the shipped document; `also` sets sibling keys of the same profile."""
    document = shipped_document()
    node = document
    *parents, leaf = path.split(".")
    for key in parents:
        node = node[key]
    if delete:
        del node[leaf]
    else:
        node[leaf] = value
    node.update(also or {})
    return document


P = "profiles.yaml.profiles."
INVALID: list[tuple[Document, str, str]] = [
    (mutate("profiles.Standard.fast_roaming", "yes"), P + "Standard.fast_roaming", "true or false"),
    (mutate("profiles.Standard.fast_roaming", None, delete=True), P + "Standard.fast_roaming", "missing"),
    (mutate("profiles.Standard.colour", "blue"), P + "Standard.colour", "unknown profile key"),
    (mutate("profiles.Standard.group_rekey", 0), P + "Standard.group_rekey", "renamed to group_rekey_s"),
    (mutate("profiles.Standard.pmf", "Optional"), P + "Standard.pmf", "list of accepted values"),
    (mutate("profiles.Standard.wifi_bands", ["2g", "7g"]), P + "Standard.wifi_bands", "band"),
    (mutate("profiles.Standard.wifi_bands", ["2g", "2g"]), P + "Standard.wifi_bands", "duplicate"),
    (mutate("profiles.Standard.wifi_bands", []), P + "Standard.wifi_bands", "non-empty"),
    (mutate("profiles.Standard.security_protocols", ["WPA4"]), P + "Standard.security_protocols", "security protocol"),
    (mutate("profiles.Standard.pmf", ["Maybe"]), P + "Standard.pmf", "PMF mode"),
    (mutate("profiles.Standard.minrate_mode", "Manual"), P + "Standard.minrate_mode", "mode"),
    (mutate("profiles.Compat.minrate_24_kbps", 12000), P + "Compat.minrate_24_kbps", "remove it"),
    (mutate("profiles.Standard.minrate_24_kbps", None, delete=True), P + "Standard.minrate_24_kbps", "required"),
    (mutate("profiles.Standard.minrate_24_kbps", 500), P + "Standard.minrate_24_kbps", "integer"),
    (
        mutate("profiles.Standard.dtim_mode", "custom", also={"dtim_24": 1, "dtim_5": 1, "dtim_6": 3}),
        P + "Standard.dtim_6",
        "remove it",
    ),
    (
        mutate("profiles.Standard.dtim_mode", "custom", also={"dtim_24": 0, "dtim_5": 1}),
        P + "Standard.dtim_24",
        "integer",
    ),
    (mutate("profiles.Standard.group_rekey_s", True), P + "Standard.group_rekey_s", "integer"),
    (mutate("profiles.Standard.group_rekey_s", 90000), P + "Standard.group_rekey_s", "integer"),
    (mutate("profiles.Standard.sae_sync_time", -1), P + "Standard.sae_sync_time", "integer"),
    (mutate("profiles.Standard.mdns_proxy_mode", "on"), P + "Standard.mdns_proxy_mode", "mode"),
    (
        mutate("profiles.IoT.evidence.colour", {"tier": "practice", "source": "x"}),
        P + "IoT.evidence.colour",
        "not a profile key",
    ),
    (mutate("profiles.IoT.evidence.pmf", {"tier": "gospel", "source": "x"}), P + "IoT.evidence.pmf.tier", "tier"),
    (mutate("profiles", {}), "profiles.yaml.profiles", "no profiles"),
    (mutate("profiles", None, delete=True), "profiles.yaml.profiles", "missing"),
    (mutate("extra", 1), "profiles.yaml.extra", "unknown top-level key"),
    (
        mutate("evidence.colour", {"tier": "practice", "source": "x"}),
        "profiles.yaml.evidence.colour",
        "not a profile key",
    ),
    (mutate("evidence.pmf", {"tier": "gospel", "source": "x"}), "profiles.yaml.evidence.pmf.tier", "tier"),
    (mutate("evidence.pmf", {"tier": "standard"}), "profiles.yaml.evidence.pmf", "exactly tier and source"),
    (mutate("evidence.pmf", {"tier": "standard", "source": ""}), "profiles.yaml.evidence.pmf.source", "1..512"),
    (mutate("evidence.pmf", None, delete=True), "profiles.yaml.evidence.pmf", "every profile key needs"),
]


@pytest.mark.parametrize(("document", "path", "detail"), INVALID)
def test_every_invalid_document_names_the_offending_key(document: Document, path: str, detail: str) -> None:
    with pytest.raises(ConfigError) as exc:
        parse_profiles_document(document, "profiles.yaml", True)
    assert exc.value.path == path and detail in exc.value.detail


def test_a_profile_name_longer_than_the_cap_is_refused() -> None:
    document = shipped_document()
    document["profiles"]["x" * 65] = document["profiles"]["Standard"]
    with pytest.raises(ConfigError) as exc:
        parse_profiles_document(document, "profiles.yaml", True)
    assert exc.value.path == "profiles.yaml.profiles"


OVERRIDE = """
profiles:
  Standard:
    wifi_bands: [5g]
    security_protocols: [WPA3]
    pmf: [Required]
    fast_roaming: true
    bss_transition: true
    roaming_assistant: true
    band_steering: false
    mlo: false
    uapsd: false
    proxy_arp: false
    multicast_suppressor_mode: "off"
    multicast_to_unicast: false
    hide_wifi_name: false
    client_device_isolation: false
    ap_name_in_beacon: false
    minrate_mode: auto
    dtim_mode: default
    group_rekey_s: 0
    sae_anti_clogging: 5
    sae_sync_time: 5
  Media:
    wifi_bands: [5g]
    security_protocols: ["WPA2/WPA3"]
    pmf: [Optional]
    fast_roaming: false
    bss_transition: true
    roaming_assistant: false
    band_steering: false
    mlo: false
    uapsd: false
    proxy_arp: true
    multicast_suppressor_mode: "off"
    multicast_to_unicast: true
    hide_wifi_name: false
    client_device_isolation: false
    ap_name_in_beacon: false
    minrate_mode: auto
    dtim_mode: default
    group_rekey_s: 3600
    sae_anti_clogging: 5
    sae_sync_time: 5
    evidence:
      multicast_to_unicast: {tier: practice, source: "our streaming boxes drop frames without it"}
evidence:
  proxy_arp: {tier: practice, source: "we saw no difference"}
"""


def test_an_override_file_replaces_whole_profiles_adds_new_ones_and_updates_evidence(tmp_path: Path) -> None:
    path = tmp_path / "mine.yaml"
    path.write_text(OVERRIDE)
    loaded = load_profiles(path, at(tmp_path / "elsewhere" / "config.yaml"))
    assert loaded.override_path == path and loaded.override_text == OVERRIDE
    profiles = loaded.profiles
    assert sorted(profiles.profiles) == ["Compat", "Hotspot", "IoT", "Media", "Standard"]
    assert (
        profiles.profiles["Standard"].wifi_bands == {Band.GHZ_5}
        and profiles.profiles["Standard"].band_steering is False
    )
    assert profiles.profiles["Media"].multicast_to_unicast is True
    assert profiles.evidence["proxy_arp"].source == "we saw no difference"
    media_evidence = profiles.evidence_for(profiles.profiles["Media"], "multicast_to_unicast")
    assert media_evidence is not None and media_evidence.source.startswith("our streaming")
    assert profiles.evidence["pmf"] == shipped_profiles().evidence["pmf"]


def at(config_path: Path, legacy: bool = False) -> ConfigLocation:
    return ConfigLocation(config_path, legacy=legacy)


def test_the_default_override_sits_beside_the_configuration_file_in_use(tmp_path: Path) -> None:
    config_path = tmp_path / "cfg" / "config.yaml"
    assert profiles_path_beside(at(config_path)) == tmp_path / "cfg" / "profiles.yaml"
    loaded = load_profiles(None, at(config_path))
    assert loaded.override_path is None and loaded.override_text is None
    assert sorted(loaded.profiles.profiles) == sorted(shipped_profiles().profiles)
    (tmp_path / "cfg").mkdir()
    (tmp_path / "cfg" / "profiles.yaml").write_text(OVERRIDE)
    loaded = load_profiles(None, at(config_path))
    assert loaded.override_path == tmp_path / "cfg" / "profiles.yaml" and "Media" in loaded.profiles.profiles


def test_the_legacy_data_directory_is_never_searched_for_an_override(tmp_path: Path) -> None:
    # The pre-rewrite installer leaves its own profiles.yaml (old key names) next to the legacy config.
    legacy = tmp_path / "share" / "unifiwifioptimizer" / "config.yaml"
    legacy.parent.mkdir(parents=True)
    legacy.with_name("profiles.yaml").write_text("profiles:\n  Standard:\n    group_rekey: 0\n")
    assert profiles_path_beside(at(legacy, legacy=True)) is None
    loaded = load_profiles(None, at(legacy, legacy=True))
    assert loaded.override_path is None and sorted(loaded.profiles.profiles) == sorted(shipped_profiles().profiles)
    # The same file beside a current-layout configuration is an override and its old key is named.
    with pytest.raises(ConfigError, match="renamed to group_rekey_s"):
        load_profiles(None, at(legacy))


def test_a_dangling_symlink_beside_the_configuration_is_reported_not_skipped(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    (tmp_path / "profiles.yaml").symlink_to(tmp_path / "gone.yaml")
    with pytest.raises(ConfigError, match="not found"):
        load_profiles(None, at(config_path))


def test_an_explicit_override_must_exist_and_be_a_regular_file_of_bounded_size(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="not found"):
        load_profiles(tmp_path / "missing.yaml", at(tmp_path / "config.yaml"))
    target = tmp_path / "real.yaml"
    target.write_text(OVERRIDE)
    # Dotfile managers link the profiles file; a symlink to a regular file is fine for a non-secret.
    link = tmp_path / "link.yaml"
    link.symlink_to(target)
    assert "Media" in load_profiles(link, at(tmp_path / "config.yaml")).profiles.profiles
    with pytest.raises(ConfigError, match="not a regular file"):
        load_profiles(tmp_path, at(tmp_path / "config.yaml"))
    fifo = tmp_path / "fifo.yaml"
    os.mkfifo(fifo, 0o600)
    # A FIFO without a writer would block a plain open; the loader must refuse it promptly, so the call is
    # bounded by a thread rather than left to hang the suite.
    outcome: list[BaseException | None] = []

    def attempt() -> None:
        try:
            load_profiles(fifo, at(tmp_path / "config.yaml"))
            outcome.append(None)
        except ConfigError as exc:
            outcome.append(exc)

    worker = threading.Thread(target=attempt, daemon=True)
    worker.start()
    worker.join(timeout=5)
    assert not worker.is_alive(), "opening the FIFO blocked"
    assert isinstance(outcome[0], ConfigError) and "not a regular file" in outcome[0].detail
    binary = tmp_path / "binary.yaml"
    binary.write_bytes(b"\xff\xfe profiles:")
    with pytest.raises(ConfigError, match="not UTF-8"):
        load_profiles(binary, at(tmp_path / "config.yaml"))
    big = tmp_path / "big.yaml"
    big.write_text(OVERRIDE + "#" + "x" * (256 * 1024) + "\n")
    with pytest.raises(ConfigError, match=rf"larger than {MAX_PROFILES_FILE_BYTES} bytes"):
        load_profiles(big, at(tmp_path / "config.yaml"))


def test_an_override_with_an_invalid_profile_names_the_file_and_key(tmp_path: Path) -> None:
    path = tmp_path / "profiles.yaml"
    path.write_text(OVERRIDE.replace("    pmf: [Required]\n", "    pmf: [Required]\n    colour: blue\n", 1))
    with pytest.raises(ConfigError) as exc:
        load_profiles(path, at(tmp_path / "config.yaml"))
    assert exc.value.path == f"{path}.profiles.Standard.colour"
