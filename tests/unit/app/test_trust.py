"""`trust-host-keys` with a fake keyscan and an in-memory store: precedence, confirmation, conflicts."""

import base64
import json
from collections.abc import Callable, Sequence
from pathlib import Path

import pytest

from unifiwifioptimizer.adapters.ssh.hostkeys import HostKeyCandidate, KnownHostEntry, KnownHostsStore, TrustBasis
from unifiwifioptimizer.adapters.unifi import parse
from unifiwifioptimizer.app.trust import TrustOutcome, TrustResult, trust_host_keys
from unifiwifioptimizer.config.load import LoadedConfig
from unifiwifioptimizer.config.locations import ConfigLocation
from unifiwifioptimizer.config.schema import Config
from unifiwifioptimizer.domain.errors import ConfigError
from unifiwifioptimizer.domain.hostkeys import host_key_alias, key_fingerprints, normalize_fingerprint
from unifiwifioptimizer.domain.models import (
    AccessPoint,
    ApGroup,
    ClientSighting,
    DevicesResult,
    ParsedList,
    SettingsResult,
    Site,
    WlanConfig,
)

FIXTURES = Path(__file__).parents[2] / "fixtures"


def load(name: str) -> object:
    return json.loads((FIXTURES / name).read_text())


class FixtureApi:
    def sites(self) -> ParsedList[Site]:
        return parse.parse_sites(load("sites.json"))

    def devices(self, site_id: str) -> DevicesResult:
        return parse.parse_devices(load("stat_device.json"))

    def wlans(self, site_id: str) -> ParsedList[WlanConfig]:
        return parse.parse_wlans(load("list_wlanconf.json"))

    def ap_groups(self, site_id: str) -> ParsedList[ApGroup]:
        return parse.parse_ap_groups(load("apgroups.json"))

    def settings(self, site_id: str) -> SettingsResult:
        return parse.parse_settings(load("rest_setting.json"))

    def clients(self, site_id: str) -> ParsedList[ClientSighting]:
        return parse.parse_clients(load("stat_sta.json"))


class MemoryStore(KnownHostsStore):
    def __init__(self) -> None:
        super().__init__(Path("/state/known_hosts"))
        self.rows: list[KnownHostEntry] = []

    def entries(self) -> tuple[KnownHostEntry, ...]:
        return tuple(self.rows)

    def add(self, entry: KnownHostEntry) -> None:
        known = self.entry(entry.alias)
        if known is not None and known != entry:
            from unifiwifioptimizer.domain.errors import HostKeyTrustError

            raise HostKeyTrustError("a different host key is already stored")
        if known is None:
            self.rows.append(entry)


def key_for(seed: int) -> HostKeyCandidate:
    blob = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00 " + bytes([seed]) * 32
    b64 = base64.b64encode(blob).decode()
    sha, md5 = key_fingerprints(b64)
    return HostKeyCandidate("ssh-ed25519", b64, sha, md5)


def loaded(site: dict[str, object]) -> LoadedConfig:
    config = Config.from_mapping(
        {"controller": {"url": "https://unifi.example", "api_key": "k"}, "sites": {"default": site}}
    )
    return LoadedConfig(config=config, location=ConfigLocation(Path("/cfg"), legacy=False), env_ssh_password=None)


def access_points() -> list[AccessPoint]:
    return list(FixtureApi().devices("default").access_points)


def controller_fingerprints() -> dict[str, str | None]:
    return {ap.name: ap.ssh_host_key_fingerprint for ap in access_points()}


def test_fixture_access_points_cover_sha256_md5_and_unknown_controller_fingerprints() -> None:
    forms = controller_fingerprints()
    kinds = {name: (normalize_fingerprint(text).algorithm.value if text else None) for name, text in forms.items()}  # type: ignore[union-attr]
    assert sorted(kinds.values(), key=str) == [None, "md5", "sha256", "sha256"]


def test_verified_keys_are_stored_under_the_alias_and_the_basis_is_reported() -> None:
    aps = access_points()
    by_name = {ap.name: ap for ap in aps}
    # One candidate per access point whose SHA-256 is exactly the fingerprint the controller reports.
    offered: dict[str, Sequence[HostKeyCandidate]] = {}
    for ap in aps:
        fingerprint = normalize_fingerprint(ap.ssh_host_key_fingerprint) if ap.ssh_host_key_fingerprint else None
        decoy = key_for(99)
        if fingerprint is None:
            offered[ap.name] = [key_for(1)]
        else:
            match = HostKeyCandidate("ssh-ed25519", key_for(2).key_base64, fingerprint, fingerprint)
            offered[ap.name] = [decoy, match]
    store = MemoryStore()
    asked: list[str] = []

    def confirm(question: str) -> bool:
        asked.append(question)
        return False

    cfg = loaded({"ssh": {}, "neighbors": {"AP-1": ["AP-2", "AP-3", "AP-4"]}})
    report = trust_host_keys(
        FixtureApi(), cfg, store, "default", [], assume_yes=True, accept_unverified=False, confirm=confirm,
        scan=lambda ap: offered[ap.name],
    )  # fmt: skip
    outcomes = {r.ap_name: (r.outcome, r.basis) for r in report.results}
    verified = [name for name, text in controller_fingerprints().items() if text]
    unverified = [name for name, text in controller_fingerprints().items() if not text]
    for name in verified:
        assert outcomes[name] == (TrustOutcome.STORED, TrustBasis.CONTROLLER)
    for name in unverified:
        assert outcomes[name] == (TrustOutcome.DECLINED, TrustBasis.UNVERIFIED) and any(name in q for q in asked)
    assert {e.alias for e in store.rows} == {
        host_key_alias("https://unifi.example:443", "default", by_name[n].mac) for n in verified
    }
    assert report.failed is False


def test_config_pin_wins_and_a_conflict_with_the_controller_aborts_that_access_point() -> None:
    aps = access_points()
    with_controller = next(
        ap for ap in aps if ap.ssh_host_key_fingerprint and ap.ssh_host_key_fingerprint.startswith("SHA256:")
    )
    pinned = key_for(7)
    cfg = loaded(
        {"ssh": {"host_keys": {with_controller.mac: pinned.sha256.text}}, "neighbors": {with_controller.name: []}}
    )
    store = MemoryStore()
    report = trust_host_keys(
        FixtureApi(), cfg, store, "default", [with_controller.name], assume_yes=True, accept_unverified=False,
        confirm=lambda q: False, scan=lambda ap: [pinned],
    )  # fmt: skip
    (result,) = report.results
    assert (
        result.outcome is TrustOutcome.FAILED
        and "pin and the fingerprint the controller reports differ" in result.detail
    )
    assert report.failed is True and store.rows == []
    without_controller = next(ap for ap in aps if not ap.ssh_host_key_fingerprint)
    cfg = loaded(
        {"ssh": {"host_keys": {without_controller.mac: pinned.sha256.text}}, "neighbors": {without_controller.name: []}}
    )
    report = trust_host_keys(
        FixtureApi(), cfg, store, "default", [], assume_yes=False, accept_unverified=False,
        confirm=lambda q: "matches the configuration pin" in q, scan=lambda ap: [key_for(3), pinned],
    )  # fmt: skip
    (result,) = report.results
    assert (
        result.outcome is TrustOutcome.STORED
        and result.basis is TrustBasis.CONFIG_PIN
        and result.detail == pinned.sha256.text
    )


def test_unverified_keys_need_the_flag_or_a_yes_and_yes_alone_is_not_enough() -> None:
    aps = access_points()
    unverified = next(ap for ap in aps if not ap.ssh_host_key_fingerprint)
    cfg = loaded({"ssh": {}, "neighbors": {unverified.name: []}})
    store = MemoryStore()

    def run(*, assume_yes: bool, accept_unverified: bool, confirm: Callable[[str], bool]) -> TrustResult:
        return trust_host_keys(
            FixtureApi(), cfg, store, "default", [], assume_yes=assume_yes, accept_unverified=accept_unverified,
            confirm=confirm, scan=lambda ap: [key_for(5)],
        ).results[0]  # fmt: skip

    assert run(assume_yes=True, accept_unverified=False, confirm=lambda q: False).outcome is TrustOutcome.DECLINED
    assert (
        run(assume_yes=False, accept_unverified=False, confirm=lambda q: "on first use" in q).outcome
        is TrustOutcome.STORED
    )
    assert (
        run(assume_yes=False, accept_unverified=False, confirm=lambda q: False).outcome is TrustOutcome.ALREADY_STORED
    )
    store.rows.clear()
    assert run(assume_yes=False, accept_unverified=True, confirm=lambda q: False).outcome is TrustOutcome.STORED
    assert (
        run(
            assume_yes=False,
            accept_unverified=True,
            confirm=lambda q: False,
        ).outcome
        is TrustOutcome.ALREADY_STORED
    )


def test_ambiguity_a_stored_different_key_and_unknown_names_are_reported_not_fatal() -> None:
    aps = access_points()
    unverified = next(ap for ap in aps if not ap.ssh_host_key_fingerprint)
    cfg = loaded({"ssh": {}, "neighbors": {unverified.name: ["Ghost"]}})
    store = MemoryStore()
    report = trust_host_keys(
        FixtureApi(), cfg, store, "default", [], assume_yes=True, accept_unverified=True, confirm=lambda q: True,
        scan=lambda ap: [key_for(1), key_for(2)],
    )  # fmt: skip
    outcomes = {r.ap_name: r for r in report.results}
    assert (
        outcomes[unverified.name].outcome is TrustOutcome.FAILED
        and "several keys of one type" in outcomes[unverified.name].detail
    )
    assert outcomes["Ghost"].outcome is TrustOutcome.NOT_ON_CONTROLLER
    alias = host_key_alias("https://unifi.example:443", "default", unverified.mac)
    store.rows.append(KnownHostEntry(alias, "ssh-ed25519", key_for(9).key_base64))
    report = trust_host_keys(
        FixtureApi(), cfg, store, "default", [unverified.name], assume_yes=True, accept_unverified=True,
        confirm=lambda q: True, scan=lambda ap: [key_for(1)],
    )  # fmt: skip
    assert (
        report.results[0].outcome is TrustOutcome.FAILED
        and "different host key is already stored" in report.results[0].detail
    )


def test_trust_on_first_use_takes_the_preferred_key_type_from_a_multi_key_server() -> None:
    aps = access_points()
    unverified = next(ap for ap in aps if not ap.ssh_host_key_fingerprint)
    cfg = loaded({"ssh": {}, "neighbors": {unverified.name: []}})
    store = MemoryStore()
    rsa = HostKeyCandidate("ssh-rsa", key_for(1).key_base64, key_for(1).sha256, key_for(1).md5)
    ed = HostKeyCandidate("ssh-ed25519", key_for(2).key_base64, key_for(2).sha256, key_for(2).md5)
    report = trust_host_keys(
        FixtureApi(), cfg, store, "default", [], assume_yes=False, accept_unverified=True, confirm=lambda q: False,
        scan=lambda ap: [rsa, ed],
    )  # fmt: skip
    (result,) = report.results
    assert result.outcome is TrustOutcome.STORED and result.detail == ed.sha256.text
    assert store.rows[0].key_type == "ssh-ed25519"


def test_a_public_address_is_refused_before_any_keyscan_unless_the_site_opts_in() -> None:
    import dataclasses
    from ipaddress import ip_address

    aps = access_points()
    public = dataclasses.replace(aps[0], ip=ip_address("8.8.8.8"), ssh_host_key_fingerprint=None)

    class Api(FixtureApi):
        def devices(self, site_id: str) -> DevicesResult:
            result = super().devices(site_id)
            return dataclasses.replace(result, access_points=(public, *result.access_points[1:]))

    scanned: list[str] = []

    def scan(ap: AccessPoint) -> list[HostKeyCandidate]:
        scanned.append(ap.name)
        return [key_for(1)]

    cfg = loaded({"ssh": {}, "neighbors": {public.name: []}})
    report = trust_host_keys(
        Api(),
        cfg,
        MemoryStore(),
        "default",
        [],
        assume_yes=True,
        accept_unverified=True,
        confirm=lambda q: True,
        scan=scan,
    )
    assert (
        report.results[0].outcome is TrustOutcome.FAILED and "not a private network address" in report.results[0].detail
    )
    assert scanned == []
    cfg = loaded({"ssh": {"allow_public_ap_addresses": True}, "neighbors": {public.name: []}})
    report = trust_host_keys(
        Api(),
        cfg,
        MemoryStore(),
        "default",
        [],
        assume_yes=True,
        accept_unverified=True,
        confirm=lambda q: True,
        scan=scan,
    )
    assert report.results[0].outcome is TrustOutcome.STORED and scanned == [public.name]


def test_sites_without_ssh_or_without_pairs_are_configuration_errors() -> None:
    with pytest.raises(ConfigError, match=r"sites\.default\.ssh: no ssh section"):
        trust_host_keys(
            FixtureApi(),
            loaded({}),
            MemoryStore(),
            "default",
            [],
            assume_yes=True,
            accept_unverified=False,
            confirm=lambda q: True,
        )
    with pytest.raises(ConfigError, match=r"sites\.default\.neighbors: no access points take part"):
        trust_host_keys(
            FixtureApi(),
            loaded({"ssh": {}}),
            MemoryStore(),
            "default",
            [],
            assume_yes=True,
            accept_unverified=False,
            confirm=lambda q: True,
        )
    with pytest.raises(ConfigError, match="no site 'nowhere'"):
        trust_host_keys(
            FixtureApi(),
            loaded({"ssh": {}}),
            MemoryStore(),
            "nowhere",
            [],
            assume_yes=True,
            accept_unverified=False,
            confirm=lambda q: True,
        )


def test_a_garbled_controller_fingerprint_fails_that_access_point_only() -> None:
    import dataclasses

    aps = access_points()
    garbled = dataclasses.replace(aps[0], ssh_host_key_fingerprint="SHA256:not-really")

    class Api(FixtureApi):
        def devices(self, site_id: str) -> DevicesResult:
            result = super().devices(site_id)
            return dataclasses.replace(result, access_points=(garbled, *result.access_points[1:]))

    cfg = loaded({"ssh": {}, "neighbors": {garbled.name: []}})
    report = trust_host_keys(
        Api(),
        cfg,
        MemoryStore(),
        "default",
        [],
        assume_yes=True,
        accept_unverified=True,
        confirm=lambda q: True,
        scan=lambda ap: [key_for(1)],
    )
    assert report.results[0].outcome is TrustOutcome.FAILED and "unknown form" in report.results[0].detail
