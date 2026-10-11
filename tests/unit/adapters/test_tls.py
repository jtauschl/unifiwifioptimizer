from pathlib import Path

import pytest

from unifiwifioptimizer.adapters.unifi.tls import (
    PinnedHTTPSConnection,
    TlsMode,
    TlsPolicy,
    open_connection,
)
from unifiwifioptimizer.domain.errors import ConfigError, TlsError, TlsPinMismatchError
from unifiwifioptimizer.domain.fingerprints import format_fingerprint

PIN = bytes(range(32))


def test_policy_from_options_picks_exactly_one_mode() -> None:
    assert TlsPolicy.from_options(None, None).mode is TlsMode.SYSTEM_ROOTS
    assert TlsPolicy.from_options(Path("/ca.pem"), None) == TlsPolicy(mode=TlsMode.CA_FILE, ca_file=Path("/ca.pem"))
    assert TlsPolicy.from_options(None, PIN) == TlsPolicy(mode=TlsMode.PIN, pin=PIN)
    with pytest.raises(ValueError, match="mutually exclusive"):
        TlsPolicy.from_options(Path("/ca.pem"), PIN)
    with pytest.raises(ValueError, match="32-byte"):
        TlsPolicy.from_options(None, b"short")


def test_pinned_connection_requires_a_32_byte_pin_or_none() -> None:
    with pytest.raises(ValueError, match="32-byte"):
        PinnedHTTPSConnection("unifi.example", 443, pin=b"abc")
    connection = PinnedHTTPSConnection("unifi.example", 443, pin=PIN)
    assert connection.peer_fingerprint is None and connection.host == "unifi.example" and connection.port == 443


def test_observation_connection_refuses_to_carry_requests() -> None:
    connection = PinnedHTTPSConnection("unifi.example", 443, pin=None)
    with pytest.raises(TlsError, match="cannot carry requests"):
        connection.request("GET", "/")
    with pytest.raises(ValueError, match="pin mode without a pin"):
        open_connection(TlsPolicy(mode=TlsMode.PIN, pin=None), "h", 443)


def test_open_connection_returns_the_pinned_class_only_for_a_pin() -> None:
    assert isinstance(open_connection(TlsPolicy.from_options(None, PIN), "h", 443), PinnedHTTPSConnection)
    plain = open_connection(TlsPolicy.from_options(None, None), "h", 8443, timeout=3.0)
    assert not isinstance(plain, PinnedHTTPSConnection) and plain.port == 8443 and plain.timeout == 3.0


def test_ca_file_that_does_not_exist_is_a_configuration_error() -> None:
    with pytest.raises(ConfigError, match=r"controller\.ca_cert: cannot load the CA bundle"):
        open_connection(TlsPolicy.from_options(Path("/nonexistent/ca.pem"), None), "h", 443)


def test_observation_connection_refuses_every_write_path() -> None:
    connection = PinnedHTTPSConnection("unifi.example", 443, pin=None)
    with pytest.raises(TlsError, match="cannot carry requests"):
        connection.send(b"GET / HTTP/1.1\r\n")
    with pytest.raises(TlsError, match="cannot carry requests"):
        connection.putrequest("GET", "/")
        connection.endheaders()


def test_pin_mismatch_shows_both_digests_in_the_form_the_configuration_takes() -> None:
    error = TlsPinMismatchError(bytes(32), bytes(range(32)))
    assert str(error) == (
        "controller certificate fingerprint mismatch: "
        "expected SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA, "
        "observed SHA256:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
    )
    assert format_fingerprint(bytes(range(32))) == "SHA256:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
