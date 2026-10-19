from collections.abc import Callable
from pathlib import Path

import pytest

from unifiwifioptimizer.config.schema import Config, SshAuth, parse_fingerprint, resolve_auth
from unifiwifioptimizer.domain.errors import ConfigError
from unifiwifioptimizer.domain.secrets import Secret
from unifiwifioptimizer.rf.corridor import PathLossModel

FINGERPRINT_HEX = "ab" * 32
Document = dict[str, object]


def minimal(**controller: object) -> Document:
    return {"controller": {"url": "https://unifi.example", "api_key": "k", **controller}}


def with_site(site: Document, **controller: object) -> Document:
    document = minimal(**controller)
    document["sites"] = {"default": site}
    return document


def error_path(document: Document, env_api_key: str | None = None) -> str:
    with pytest.raises(ConfigError) as exc:
        Config.from_mapping(document, env_api_key)
    return exc.value.path


def test_minimal_configuration_fills_every_default() -> None:
    config = Config.from_mapping(minimal())
    assert (config.controller.host, config.controller.port, config.controller.timeout_s) == ("unifi.example", 443, 15)
    assert config.controller.api_key == Secret("k") and config.controller.port == 443
    assert config.controller.ca_cert is None and config.controller.cert_fingerprint is None
    assert config.sites == {}
    assert (config.rf.client_tx_dbm, config.rf.cell_edge.noise_floor_dbm, config.rf.cell_edge.required_snr_db) == (
        14,
        -92,
        25,
    )
    assert (config.rf.roaming.floor_dbm, config.rf.roaming.ceiling_dbm, config.rf.min_rssi_offset_db) == (-75, -65, 5)


def test_full_site_configuration() -> None:
    site: Document = {
        "ssh": {
            "auth": "password",
            "user": "admin",
            "password": "pw",
            "host_keys": {"02:00:00:00:00:04": "SHA256:" + "A" * 43},
            "scan_interface_toggle": True,
            "scan_concurrency": 2,
            "scan_attempts": 3,
        },
        "environment": "obstructed",
        "scan_passes": 3,
        "wlans": {"SSID-1": "Throughput"},
        "neighbors": {"AP-1": ["AP-2"], "AP-2": ["AP-1"]},
    }
    config = Config.from_mapping(with_site(site, url="https://unifi.example:8443", timeout_s=30))
    assert config.controller.port == 8443 and config.controller.timeout_s == 30
    parsed = config.sites["default"]
    assert parsed.ssh is not None and parsed.ssh.auth is SshAuth.PASSWORD and parsed.ssh.user == "admin"
    assert parsed.ssh.password == Secret("pw") and "pw" not in repr(parsed)
    assert parsed.ssh.host_keys == {"02:00:00:00:00:04": parse_fingerprint("SHA256:" + "A" * 43, "x")}
    assert (parsed.ssh.scan_interface_toggle, parsed.ssh.scan_concurrency, parsed.ssh.scan_attempts) == (True, 2, 3)
    assert parsed.environment == PathLossModel.from_preset("Obstructed") and parsed.scan_passes == 3
    assert parsed.wlans == {"SSID-1": "Throughput"} and parsed.neighbors == {"AP-1": {"AP-2"}, "AP-2": {"AP-1"}}


def test_api_key_falls_back_to_the_environment_only_when_absent() -> None:
    document: Document = {"controller": {"url": "https://unifi.example"}}
    assert Config.from_mapping(document, env_api_key="from-env").controller.api_key == Secret("from-env")
    assert Config.from_mapping(minimal(), env_api_key="from-env").controller.api_key == Secret("k")
    assert error_path(document) == "controller.api_key"
    assert error_path(document, env_api_key="") == "controller.api_key"


@pytest.mark.parametrize(
    ("document", "path"),
    [
        ({}, "controller"),
        ([], "$"),
        ({"controller": {}, "extra": 1}, "$"),
        ({"controller": {"url": "https://unifi.example", "api_key": "k", "verify": False}}, "controller"),
        ({"controller": "x"}, "controller"),
        (minimal(url="http://unifi.example"), "controller.url"),
        (minimal(url="https://user:pw@unifi.example"), "controller.url"),
        (minimal(url="https://unifi.example/network"), "controller.url"),
        (minimal(url="https://unifi.example/?x=1"), "controller.url"),
        (minimal(url="https://unifi.example:99999"), "controller.url"),
        (minimal(url="https://unifi.example:0"), "controller.url"),
        (minimal(url="https://unifi.example:4a3"), "controller.url"),
        (minimal(url="https://:pw@unifi.example"), "controller.url"),
        (minimal(url="https://unifi.example#fragment"), "controller.url"),
        (minimal(url="https://" + "a" * 1017), "controller.url"),
        (minimal(url="https://h h"), "controller.url"),
        (minimal(url="https://-host"), "controller.url"),
        (minimal(url="https://host-"), "controller.url"),
        (minimal(url="https://ho%73t"), "controller.url"),
        (minimal(url="https://host."), "controller.url"),
        (minimal(url="https://[::1]:8443"), "controller.url"),
        (minimal(url="https://[v1.x]"), "controller.url"),
        (minimal(url="https://[unifi.example]"), "controller.url"),
        (minimal(url="https://0x7f.1"), "controller.url"),
        (minimal(url="https://127.1"), "controller.url"),
        (minimal(url="https://2130706433"), "controller.url"),
        (minimal(url="https://01.02.03.04"), "controller.url"),
        (minimal(url="https://1.2.3.256"), "controller.url"),
        (minimal(url="https://h\nost"), "controller.url"),
        (minimal(url="https://h\tost"), "controller.url"),
        (minimal(url="https://unifi.example\r"), "controller.url"),
        (minimal(url="https://üni.example"), "controller.url"),
        (minimal(url="https://["), "controller.url"),
        (minimal(url="https://]"), "controller.url"),
        (minimal(url="https://[TOPSECRET"), "controller.url"),
        (minimal(url="https://[::1"), "controller.url"),
        (minimal(url="https://" + "a" * 64 + ".example"), "controller.url"),
        (minimal(url="https://" + ".".join(["a" * 63] * 4)), "controller.url"),
        (minimal(api_key="key with space"), "controller.api_key"),
        (minimal(api_key="key\rinjected"), "controller.api_key"),
        (minimal(api_key="schlüssel"), "controller.api_key"),
        (minimal(api_key="k" * 513), "controller.api_key"),
        (minimal(ca_cert="/a\x00b"), "controller.ca_cert"),
        (minimal(ca_cert=""), "controller.ca_cert"),
        (minimal(cert_fingerprint=""), "controller.cert_fingerprint"),
        (minimal(url=""), "controller.url"),
        (minimal(url=5), "controller.url"),
        (minimal(api_key=""), "controller.api_key"),
        (minimal(api_key=123), "controller.api_key"),
        (minimal(timeout_s=0), "controller.timeout_s"),
        (minimal(timeout_s=121), "controller.timeout_s"),
        (minimal(timeout_s=True), "controller.timeout_s"),
        (minimal(timeout_s="15"), "controller.timeout_s"),
        (minimal(ca_cert="/a", cert_fingerprint=FINGERPRINT_HEX), "controller"),
        (minimal(ca_cert='/a"b'), "controller.ca_cert"),
        (minimal(ca_cert="/a%d"), "controller.ca_cert"),
        (minimal(cert_fingerprint="abc"), "controller.cert_fingerprint"),
        (minimal(cert_fingerprint="SHA256:" + "A" * 42), "controller.cert_fingerprint"),
        ({**minimal(), "sites": []}, "sites"),
        ({**minimal(), "sites": {"bad site": {}}}, "sites"),
        ({**minimal(), "sites": {"../x": {}}}, "sites"),
        ({**minimal(), "sites": {"a": {"unknown": 1}}}, "sites.a"),
        ({**minimal(), "sites": {"a": {"environment": "Cave"}}}, "sites.a.environment"),
        ({**minimal(), "sites": {"a": {"environment": 0}}}, "sites.a.environment"),
        ({**minimal(), "sites": {"a": {"environment": True}}}, "sites.a.environment"),
        ({**minimal(), "sites": {"a": {"environment": 11}}}, "sites.a.environment"),
        ({**minimal(), "sites": {"a": {"environment": 10.5}}}, "sites.a.environment"),
        ({**minimal(), "sites": {"a": {"environment": float("inf")}}}, "sites.a.environment"),
        ({**minimal(), "sites": {"a": {"environment": float("nan")}}}, "sites.a.environment"),
        ({**minimal(), "sites": {"a": {"environment": 10**400}}}, "sites.a.environment"),
        ({**minimal(), "sites": {"a": {"environment": -(10**400)}}}, "sites.a.environment"),
        ({**minimal(), "sites": {"a": {"scan_passes": 0}}}, "sites.a.scan_passes"),
        ({**minimal(), "sites": {"a": {"scan_passes": 11}}}, "sites.a.scan_passes"),
        ({**minimal(), "sites": {"a": {"wlans": {"": "Standard"}}}}, "sites.a.wlans"),
        ({**minimal(), "sites": {"a": {"wlans": {"x": 1}}}}, "sites.a.wlans.x"),
        ({**minimal(), "sites": {"a": {"wlans": {"x": "p" * 129}}}}, "sites.a.wlans.x"),
        ({**minimal(), "sites": {"a": {"ssh": {}, "neighbors": {"x": ["y" * 129]}}}}, "sites.a.neighbors.x"),
        ({**minimal(), "sites": {"a": {"wlans": {"x": "Standard"}, "neighbors": {"x": "y"}}}}, "sites.a.neighbors.x"),
        ({**minimal(), "sites": {"a": {"neighbors": {"x": ["x"]}}}}, "sites.a.neighbors.x"),
        ({**minimal(), "sites": {"a": {"neighbors": {"x": [1]}}}}, "sites.a.neighbors.x"),
        ({**minimal(), "sites": {"a": {"neighbors": {"x": ["y"]}}}}, "sites.a.ssh"),
        ({**minimal(), "sites": {"a": {"ssh": {"auth": "magic"}}}}, "sites.a.ssh.auth"),
        ({**minimal(), "sites": {"a": {"ssh": {"user": "a b"}}}}, "sites.a.ssh.user"),
        ({**minimal(), "sites": {"a": {"ssh": {"user": "x@y"}}}}, "sites.a.ssh.user"),
        ({**minimal(), "sites": {"a": {"ssh": {"user": "-dash"}}}}, "sites.a.ssh.user"),
        (
            {**minimal(), "sites": {"a": {"ssh": {"auth": "key", "user": "u", "key_file": "keys/id"}}}},
            "sites.a.ssh.key_file",
        ),
        (minimal(ca_cert="certs/ca.pem"), "controller.ca_cert"),
        (
            {**minimal(), "sites": {"a": {"ssh": {"auth": "password", "user": "u", "password": ""}}}},
            "sites.a.ssh.password",
        ),
        ({**minimal(), "sites": {"a": {"ssh": {"auth": "key", "user": "u", "key_file": ""}}}}, "sites.a.ssh.key_file"),
        ({**minimal(), "sites": {"a": {"ssh": {"user": "a" * 33}}}}, "sites.a.ssh.user"),
        ({**minimal(), "sites": {"a": {"ssh": {"host_keys": {"F4:92:BF:00:00:01": "x"}}}}}, "sites.a.ssh.host_keys"),
        (
            {**minimal(), "sites": {"a": {"ssh": {"host_keys": {"02:00:00:00:00:04": 1}}}}},
            "sites.a.ssh.host_keys.02:00:00:00:00:04",
        ),
        (
            {**minimal(), "sites": {"a": {"ssh": {"host_keys": {"02:00:00:00:00:04": "nope"}}}}},
            "sites.a.ssh.host_keys.02:00:00:00:00:04",
        ),
        ({**minimal(), "sites": {"a": {"ssh": {"scan_concurrency": 9}}}}, "sites.a.ssh.scan_concurrency"),
        ({**minimal(), "sites": {"a": {"ssh": {"scan_attempts": 0}}}}, "sites.a.ssh.scan_attempts"),
        ({**minimal(), "sites": {"a": {"ssh": {"scan_interface_toggle": "yes"}}}}, "sites.a.ssh.scan_interface_toggle"),
        ({**minimal(), "rf": {"client_tx_dbm": 31}}, "rf.client_tx_dbm"),
        ({**minimal(), "rf": {"noise_floor_dbm": -106}}, "rf.noise_floor_dbm"),
        ({**minimal(), "rf": {"required_snr_db": 9}}, "rf.required_snr_db"),
        ({**minimal(), "rf": {"roam_floor_dbm": -60, "roam_ceiling_dbm": -70}}, "rf"),
        ({**minimal(), "rf": {"hysteresis": 3}}, "rf"),
        ({**minimal(), "rf": 3}, "rf"),
    ],
)
def test_every_invalid_document_names_the_offending_key(document: Document, path: str) -> None:
    assert error_path(document) == path


def test_api_key_accepts_the_whole_printable_ascii_range_up_to_512_characters() -> None:
    key = "".join(chr(c) for c in range(0x21, 0x7F))
    assert Config.from_mapping(minimal(api_key=key)).controller.api_key == Secret(key)
    assert Config.from_mapping(minimal(api_key="k" * 512)).controller.api_key == Secret("k" * 512)
    assert Config.from_mapping(minimal(url="https://unifi.example:1")).controller.port == 1
    assert Config.from_mapping(minimal(url="https://unifi.example:65535/")).controller.port == 65535
    assert Config.from_mapping(with_site({"environment": 10})).sites["default"].environment.exponent == 10.0
    residential = PathLossModel.from_preset("Residential")
    assert Config.from_mapping(with_site({"environment": None})).sites["default"].environment == residential
    for host in ("192.0.2.1", "unifi", "a.b-c.example", "x" * 63 + ".example", ".".join(["a" * 61] * 4)):
        assert Config.from_mapping(minimal(url=f"https://{host}")).controller.host == host
    assert Config.from_mapping(with_site({"wlans": {"x": "p" * 128}})).sites["default"].wlans == {"x": "p" * 128}
    assert Config.from_mapping(with_site({"ssh": {}, "neighbors": {"x": ["y" * 128]}})).sites["default"].scans is True


def test_scans_means_at_least_one_neighbour_pair_and_only_then_is_ssh_required() -> None:
    template = Config.from_mapping(with_site({"neighbors": {"AP-1": [], "AP-2": []}})).sites["default"]
    assert template.scans is False and template.ssh is None
    assert Config.from_mapping(with_site({})).sites["default"].scans is False
    assert error_path(with_site({"neighbors": {"AP-1": ["AP-2"]}})) == "sites.default.ssh"
    real = Config.from_mapping(with_site({"ssh": {}, "neighbors": {"AP-1": ["AP-2"], "AP-2": []}})).sites["default"]
    assert real.scans is True


def mac(index: int) -> str:
    return f"02:00:00:00:{index // 256:02x}:{index % 256:02x}"


@pytest.mark.parametrize(
    ("build", "path", "cap"),
    [
        (lambda n: {**minimal(), "sites": {f"s{i}": {} for i in range(n)}}, "sites", 64),
        (lambda n: with_site({"wlans": {f"w{i}": "Standard" for i in range(n)}}), "sites.default.wlans", 64),
        (
            lambda n: with_site({"ssh": {}, "neighbors": {f"ap{i}": [] for i in range(n)}}),
            "sites.default.neighbors",
            256,
        ),
        (
            lambda n: with_site({"ssh": {}, "neighbors": {"hub": [f"ap{i}" for i in range(n)]}}),
            "sites.default.neighbors.hub",
            256,
        ),
        (
            lambda n: with_site({"ssh": {"host_keys": {mac(i): "SHA256:" + "A" * 43 for i in range(n)}}}),
            "sites.default.ssh.host_keys",
            256,
        ),
    ],
)
def test_collection_caps_admit_exactly_the_cap(build: Callable[[int], Document], path: str, cap: int) -> None:
    Config.from_mapping(build(cap))
    with pytest.raises(ConfigError) as exc:
        Config.from_mapping(build(cap + 1))
    assert exc.value.path == path and "more than" in exc.value.detail


def test_name_caps_admit_exactly_128_characters() -> None:
    Config.from_mapping(with_site({"wlans": {"w" * 128: "Standard"}}))
    assert error_path(with_site({"wlans": {"w" * 129: "Standard"}})) == "sites.default.wlans"
    Config.from_mapping(with_site({"ssh": {}, "neighbors": {"a" * 128: ["b" * 128]}}))
    assert error_path(with_site({"ssh": {}, "neighbors": {"a" * 129: []}})) == "sites.default.neighbors"
    Config.from_mapping(with_site({"ssh": {"user": "u" * 32, "auth": "key"}}))
    Config.from_mapping(with_site({"ssh": {"user": "Admin", "auth": "key"}}))
    assert error_path(with_site({"ssh": {"password": "p" * 257, "user": "u"}})) == "sites.default.ssh.password"
    Config.from_mapping(with_site({"ssh": {"password": "p" * 256, "user": "u"}}))


@pytest.mark.security("T9")
def test_error_messages_never_echo_the_value() -> None:
    with pytest.raises(ConfigError) as exc:
        Config.from_mapping(minimal(cert_fingerprint="TOPSECRET-looking-value"))
    assert "TOPSECRET" not in str(exc.value)
    with pytest.raises(ConfigError) as exc:
        Config.from_mapping(with_site({"ssh": {"auth": "TOPSECRET"}}))
    assert "TOPSECRET" not in str(exc.value)


def test_fingerprint_formats() -> None:
    assert parse_fingerprint(FINGERPRINT_HEX, "x") == bytes.fromhex(FINGERPRINT_HEX)
    assert parse_fingerprint(FINGERPRINT_HEX.upper(), "x") == bytes.fromhex(FINGERPRINT_HEX)
    digest = bytes(range(32))
    import base64

    assert parse_fingerprint("SHA256:" + base64.b64encode(digest).decode().rstrip("="), "x") == digest
    assert parse_fingerprint("SHA256:" + base64.b64encode(digest).decode(), "x") == digest
    for bad in ("", "SHA256:", "sha256:" + "A" * 43, "ab" * 31, "zz" * 32):
        with pytest.raises(ConfigError):
            parse_fingerprint(bad, "x")


def test_environment_accepts_presets_case_insensitively_and_custom_exponents() -> None:
    assert Config.from_mapping(with_site({"environment": "OFFICE"})).sites["default"].environment.exponent == 3.0
    assert Config.from_mapping(with_site({"environment": 2.5})).sites["default"].environment.exponent == 2.5
    assert Config.from_mapping(with_site({"environment": 3})).sites["default"].environment.exponent == 3.0
    assert Config.from_mapping(with_site({})).sites["default"].environment == PathLossModel.from_preset("Residential")


SECRET = Secret("pw")
KEY = Path("/k")


@pytest.mark.parametrize(
    ("auth", "user", "password", "key_file", "expected"),
    [
        (None, None, None, None, SshAuth.CONTROLLER),
        (None, "u", None, None, "sites.a.ssh.auth"),
        (None, "u", SECRET, None, SshAuth.PASSWORD),
        (None, None, SECRET, None, "sites.a.ssh.user"),
        (None, None, None, KEY, "sites.a.ssh.auth"),
        (None, "u", SECRET, KEY, "sites.a.ssh.auth"),
        ("controller", None, None, None, SshAuth.CONTROLLER),
        ("controller", "u", None, None, SshAuth.CONTROLLER),
        ("controller", None, SECRET, None, "sites.a.ssh.auth"),
        ("controller", None, None, KEY, "sites.a.ssh.auth"),
        ("key", "u", None, None, SshAuth.KEY),
        ("key", "u", None, KEY, SshAuth.KEY),
        ("key", None, None, KEY, "sites.a.ssh.auth"),
        ("key", "u", SECRET, None, "sites.a.ssh.auth"),
        ("password", "u", SECRET, None, SshAuth.PASSWORD),
        ("password", "u", None, None, SshAuth.PASSWORD),
        ("password", None, SECRET, None, "sites.a.ssh.auth"),
        ("password", "u", SECRET, KEY, "sites.a.ssh.auth"),
        ("token", "u", None, None, "sites.a.ssh.auth"),
    ],
)
def test_auth_decision_table(
    auth: str | None, user: str | None, password: Secret | None, key_file: Path | None, expected: SshAuth | str
) -> None:
    if isinstance(expected, SshAuth):
        assert resolve_auth(auth, user, password, key_file, "sites.a.ssh") is expected
    else:
        with pytest.raises(ConfigError) as exc:
            resolve_auth(auth, user, password, key_file, "sites.a.ssh")
        assert exc.value.path == expected


@pytest.mark.parametrize("neighbors", [None, {}, {"AP-1": ["AP-2"]}])
def test_the_auth_table_does_not_depend_on_whether_the_site_scans(neighbors: dict[str, list[str]] | None) -> None:
    site: Document = {"ssh": {"auth": "password", "user": "admin"}}
    if neighbors is not None:
        site["neighbors"] = neighbors
    ssh = Config.from_mapping(with_site(site)).sites["default"].ssh
    assert ssh is not None and ssh.auth is SshAuth.PASSWORD and ssh.password is None
    site["ssh"] = {"auth": "controller", "password": "pw"}
    assert error_path(with_site(site)) == "sites.default.ssh.auth"


def test_controller_mode_matching_the_user_is_allowed_and_user_alone_is_not() -> None:
    config = Config.from_mapping(with_site({"ssh": {"auth": "controller", "user": "admin"}}))
    assert config.sites["default"].ssh is not None and config.sites["default"].ssh.auth is SshAuth.CONTROLLER
    assert error_path(with_site({"ssh": {"user": "admin"}})) == "sites.default.ssh.auth"


def test_password_mode_without_a_password_in_the_file_is_allowed_for_the_environment() -> None:
    config = Config.from_mapping(with_site({"ssh": {"auth": "password", "user": "admin"}}))
    ssh = config.sites["default"].ssh
    assert ssh is not None and ssh.auth is SshAuth.PASSWORD and ssh.password is None


def test_key_file_expands_the_home_directory() -> None:
    config = Config.from_mapping(with_site({"ssh": {"auth": "key", "user": "admin", "key_file": "~/.ssh/id_ed25519"}}))
    ssh = config.sites["default"].ssh
    assert ssh is not None and ssh.key_file == Path.home() / ".ssh" / "id_ed25519"


def test_error_texts_show_user_chosen_keys_only_when_they_are_plain() -> None:
    evil = "AP\x1b]52;c;ZGFuZ2Vy\x07\x1b[2J"
    with pytest.raises(ConfigError) as exc:
        Config.from_mapping(with_site({"ssh": {}, "neighbors": {evil: [evil]}}))
    assert "\x1b" not in str(exc.value) and "AP\\x1b]52;c;ZGFuZ2Vy\\x07" in exc.value.path
    with pytest.raises(ConfigError) as exc:
        Config.from_mapping(with_site({"wlans": {evil: 1}}))
    assert "\x1b" not in str(exc.value)
    with pytest.raises(ConfigError) as exc:
        Config.from_mapping({**minimal(), evil: 1})
    assert "\x1b" not in str(exc.value) and "unknown key(s): 'AP" in exc.value.detail
    with pytest.raises(ConfigError) as exc:
        Config.from_mapping(with_site({"neighbors": {"Living-Room_2.4": ["Living-Room_2.4"]}}))
    assert exc.value.path == "sites.default.neighbors.Living-Room_2.4"
