"""The known_hosts format, the trust decision and `ssh-keyscan` parsing — without touching the file system."""

import base64
import hashlib
import os
from collections.abc import Sequence
from ipaddress import ip_address

import pytest

from unifiwifioptimizer.adapters.ssh.hostkeys import (
    MAX_KEYSCAN_KEYS,
    Expectation,
    HostKeyCandidate,
    KnownHostEntry,
    TrustBasis,
    default_store_path,
    expected_fingerprint,
    keyscan,
    parse_known_hosts,
    select_candidate,
)
from unifiwifioptimizer.domain.errors import ConfigError, HostKeyTrustError
from unifiwifioptimizer.domain.hostkeys import FingerprintAlgorithm, HostKeyFingerprint, key_fingerprints

ALIAS = "uwo-" + "ab" * 16


def key(seed: int) -> tuple[str, HostKeyFingerprint, HostKeyFingerprint]:
    blob = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00 " + bytes([seed]) * 32
    b64 = base64.b64encode(blob).decode()
    sha256, md5 = key_fingerprints(b64)
    return b64, sha256, md5


def candidate(seed: int, key_type: str = "ssh-ed25519") -> HostKeyCandidate:
    b64, sha256, md5 = key(seed)
    return HostKeyCandidate(key_type, b64, sha256, md5)


@pytest.mark.security("T14")
def test_known_hosts_format_round_trips_and_refuses_foreign_lines() -> None:
    b64 = key(1)[0]
    text = f"{ALIAS} ssh-ed25519 {b64}\n"
    (entry,) = parse_known_hosts(text, "/kh")
    assert entry == KnownHostEntry(ALIAS, "ssh-ed25519", b64) and entry.line == f"{ALIAS} ssh-ed25519 {b64}"
    for bad in (
        f"192.168.1.20 ssh-ed25519 {b64}",
        f"|1|hashed|salt ssh-ed25519 {b64}",
        f"{ALIAS} ssh-ed25519 {b64} comment",
        f"{ALIAS} SSH-ED25519 {b64}",
        f"{ALIAS} ssh-ed25519 not*base64",
        f"@cert-authority {ALIAS} ssh-ed25519 {b64}",
        "# a comment",
        f"  {ALIAS} ssh-ed25519 {b64}",
    ):
        with pytest.raises(ConfigError, match=r"line 1.*not an entry this tool wrote"):
            parse_known_hosts(bad + "\n", "/kh")
    with pytest.raises(ConfigError, match=r"line 2.*blank line"):
        parse_known_hosts(text + "\n", "/kh")
    assert parse_known_hosts("", "/kh") == ()


def test_default_store_path_follows_xdg_state_home() -> None:
    assert default_store_path({"XDG_STATE_HOME": "/state"}).as_posix() == "/state/unifiwifioptimizer/known_hosts"
    assert default_store_path({}).as_posix().endswith("/.local/state/unifiwifioptimizer/known_hosts")


@pytest.mark.security("T8")
def test_expected_fingerprint_precedence_config_then_controller_then_tofu() -> None:
    pin = bytes(range(32))
    controller = HostKeyFingerprint(FingerprintAlgorithm.SHA256, pin)
    assert expected_fingerprint(pin, controller) == Expectation((controller,), TrustBasis.CONFIG_PIN)
    assert expected_fingerprint(pin, None) == Expectation((controller,), TrustBasis.CONFIG_PIN)
    assert expected_fingerprint(None, controller) == Expectation((controller,), TrustBasis.CONTROLLER)
    assert expected_fingerprint(None, None) == Expectation((), TrustBasis.UNVERIFIED)
    other = HostKeyFingerprint(FingerprintAlgorithm.SHA256, bytes(32))
    with pytest.raises(HostKeyTrustError, match="pin and the fingerprint the controller reports differ"):
        expected_fingerprint(pin, other)
    # A controller MD5 cannot be compared with a SHA-256 pin here; both travel on to the key.
    md5 = HostKeyFingerprint(FingerprintAlgorithm.MD5, bytes(16))
    assert expected_fingerprint(pin, md5) == Expectation((controller, md5), TrustBasis.CONFIG_PIN)


@pytest.mark.security("T8")
def test_select_candidate_wants_exactly_one_match_that_also_satisfies_the_controller() -> None:
    first, second = candidate(1), candidate(2, "ssh-rsa")
    assert select_candidate([first, second], Expectation((first.sha256,), TrustBasis.CONTROLLER)) is first
    assert select_candidate([first, second], Expectation((second.md5,), TrustBasis.CONTROLLER)) is second
    with pytest.raises(HostKeyTrustError, match="0 of 2 offered host keys match the controller fingerprint SHA256:"):
        select_candidate([first, second], Expectation((candidate(3).sha256,), TrustBasis.CONTROLLER))
    with pytest.raises(HostKeyTrustError, match="2 of 2 offered host keys match"):
        select_candidate([first, first], Expectation((first.sha256,), TrustBasis.CONFIG_PIN))
    # Pin and controller MD5 of the same key: fine; of different keys: a conflict, never a guess.
    assert select_candidate([first, second], Expectation((first.sha256, first.md5), TrustBasis.CONFIG_PIN)) is first
    with pytest.raises(HostKeyTrustError, match="does not match the controller's MD5:"):
        select_candidate([first, second], Expectation((first.sha256, second.md5), TrustBasis.CONFIG_PIN))


def test_trust_on_first_use_picks_the_key_openssh_negotiates_first() -> None:
    rsa, ecdsa, ed25519 = candidate(1, "ssh-rsa"), candidate(2, "ecdsa-sha2-nistp256"), candidate(3, "ssh-ed25519")
    unverified = Expectation((), TrustBasis.UNVERIFIED)
    assert select_candidate([rsa, ecdsa, ed25519], unverified) is ed25519
    assert select_candidate([rsa, ecdsa], unverified) is ecdsa
    assert select_candidate([rsa], unverified) is rsa
    with pytest.raises(HostKeyTrustError, match="no host key offered"):
        select_candidate([], unverified)
    with pytest.raises(HostKeyTrustError, match="several keys of one type"):
        select_candidate([candidate(1), candidate(2)], unverified)
    with pytest.raises(HostKeyTrustError, match="no offered key type is one the tool would trust"):
        select_candidate([candidate(1, "ssh-dss")], unverified)


@pytest.mark.security("T9", "T19")
def test_keyscan_runner_failures_become_domain_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    import subprocess

    from unifiwifioptimizer.adapters.ssh import hostkeys as module
    from unifiwifioptimizer.domain.errors import ToolEnvironmentError

    def missing(*args: object, **kwargs: object) -> None:
        raise FileNotFoundError("ssh-keyscan")

    monkeypatch.setattr(subprocess, "run", missing)
    with pytest.raises(ToolEnvironmentError, match="ssh-keyscan not found"):
        module._run_keyscan(["ssh-keyscan"])

    def slow(*args: object, **kwargs: object) -> None:
        raise subprocess.TimeoutExpired(cmd="ssh-keyscan", timeout=30)

    monkeypatch.setattr(subprocess, "run", slow)
    with pytest.raises(HostKeyTrustError, match="ssh-keyscan did not finish within 30 s"):
        module._run_keyscan(["ssh-keyscan"])

    seen: dict[str, object] = {}

    class Completed:
        stdout = b"h ssh-ed25519 \xff\xfe\n"

    def record(argv: list[str], **kwargs: object) -> Completed:
        seen.update(kwargs, argv=argv)
        return Completed()

    monkeypatch.setattr(subprocess, "run", record)
    assert module._run_keyscan(["ssh-keyscan", "--", "x"]) == "h ssh-ed25519 \ufffd\ufffd\n"
    assert seen["env"] == {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C"} and seen["timeout"] == 30


def test_keyscan_parses_every_offered_key_and_fingerprints_it_locally() -> None:
    b64_a, sha_a, _ = key(1)
    b64_b, _, md5_b = key(2)
    output = (
        f"# 192.168.1.20:22 SSH-2.0-dropbear\n"
        f"192.168.1.20 ssh-ed25519 {b64_a}\n"
        f"192.168.1.20 ssh-rsa {b64_b}\n"
        f"192.168.1.20 ssh-rsa not*base64\n"
        f"garbage line\n"
        f"192.168.1.20 ecdsa-sha2-nistp256 {b64_a} trailing\n"
    )
    seen: list[Sequence[str]] = []

    def run(argv: Sequence[str]) -> str:
        seen.append(argv)
        return output

    candidates = keyscan(ip_address("192.168.1.20"), 2222, run)
    assert seen == [["ssh-keyscan", "-T", "5", "-p", "2222", "--", "192.168.1.20"]]
    assert [(c.key_type, c.key_base64) for c in candidates] == [("ssh-ed25519", b64_a), ("ssh-rsa", b64_b)]
    assert candidates[0].sha256 == sha_a and candidates[1].md5 == md5_b
    assert candidates[0].entry(ALIAS) == KnownHostEntry(ALIAS, "ssh-ed25519", b64_a)
    assert hashlib.sha256(base64.b64decode(b64_a)).digest() == sha_a.digest


def test_keyscan_caps_the_number_of_offered_keys() -> None:
    lines = "\n".join(f"h ssh-rsa {key(i % 250 + 1)[0]}" for i in range(MAX_KEYSCAN_KEYS + 1))
    with pytest.raises(HostKeyTrustError, match=f"more than {MAX_KEYSCAN_KEYS} host keys"):
        keyscan(ip_address("192.168.1.20"), run=lambda argv: lines)
    assert keyscan(ip_address("192.168.1.20"), run=lambda argv: "") == ()
