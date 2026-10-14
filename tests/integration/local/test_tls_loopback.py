"""The TLS policy against a real loopback HTTPS server with a certificate generated on the fly."""

import hashlib
import http.server
import json
import socket
import ssl
import subprocess
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

import pytest

from unifiwifioptimizer.adapters.unifi.client import ClientOptions, UnifiClient
from unifiwifioptimizer.adapters.unifi.dump import DumpWriter
from unifiwifioptimizer.adapters.unifi.tls import (
    AbortableHTTPSConnection,
    PinnedHTTPSConnection,
    TlsPolicy,
    observe_fingerprint,
)
from unifiwifioptimizer.config.schema import ControllerConfig
from unifiwifioptimizer.domain.errors import ControllerError, ResponseTooLargeError, TlsError, TlsPinMismatchError
from unifiwifioptimizer.domain.secrets import Secret

pytestmark = pytest.mark.integration
FIXTURES = Path(__file__).parents[2] / "fixtures"


@dataclass(frozen=True)
class Certificate:
    cert: Path
    key: Path
    fingerprint: bytes


def make_certificate(directory: Path, subject_alt_name: str) -> Certificate:
    cert, key = directory / "cert.pem", directory / "key.pem"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
            "-keyout", str(key), "-out", str(cert), "-days", "2", "-subj", "/CN=localhost",
            "-addext", f"subjectAltName={subject_alt_name}",
        ],
        check=True,
        capture_output=True,
    )  # fmt: skip
    der = subprocess.run(
        ["openssl", "x509", "-in", str(cert), "-outform", "DER"], check=True, capture_output=True
    ).stdout
    return Certificate(cert=cert, key=key, fingerprint=hashlib.sha256(der).digest())


@pytest.fixture(scope="module")
def certificate(tmp_path_factory: pytest.TempPathFactory) -> Certificate:
    return make_certificate(tmp_path_factory.mktemp("tls"), "DNS:localhost,IP:127.0.0.1")


@pytest.fixture(scope="module")
def dns_only_certificate(tmp_path_factory: pytest.TempPathFactory) -> Certificate:
    return make_certificate(tmp_path_factory.mktemp("tls-dns"), "DNS:localhost")


class Handler(http.server.BaseHTTPRequestHandler):
    routes: ClassVar[dict[str, tuple[int, dict[str, str], bytes]]] = {}
    seen_headers: ClassVar[list[dict[str, str]]] = []

    def do_GET(self) -> None:
        Handler.seen_headers.append(dict(self.headers.items()))
        status, headers, body = self.routes.get(self.path, (404, {}, b""))
        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name, value)
        if "Content-Length" not in headers:
            self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        pass


def serve(certificate: Certificate) -> Iterator[tuple[str, int]]:
    httpd = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(certificate.cert), str(certificate.key))
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield "127.0.0.1", httpd.server_address[1]
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


@pytest.fixture(scope="module")
def server(certificate: Certificate) -> Iterator[tuple[str, int]]:
    yield from serve(certificate)


@pytest.fixture
def dns_only_server(dns_only_certificate: Certificate) -> Iterator[tuple[str, int]]:
    yield from serve(dns_only_certificate)


def controller(port: int, **overrides: object) -> ControllerConfig:
    base = {
        "host": "127.0.0.1",
        "port": port,
        "api_key": Secret("k"),
        "ca_cert": None,
        "cert_fingerprint": None,
        "timeout_s": 5,
    }
    base.update(overrides)
    return ControllerConfig(**base)  # type: ignore[arg-type]


def payload(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


@pytest.fixture(autouse=True)
def routes() -> Iterator[None]:
    Handler.routes = {
        "/proxy/network/api/self/sites": (200, {"Content-Type": "application/json"}, payload("sites.json"))
    }
    Handler.seen_headers = []
    yield


@pytest.mark.security("T3")
def test_observe_fingerprint_returns_the_certificate_sha256(server: tuple[str, int], certificate: Certificate) -> None:
    assert observe_fingerprint(*server) == certificate.fingerprint


@pytest.mark.security("T3")
def test_pin_mode_accepts_the_right_certificate_and_sends_the_api_key(
    server: tuple[str, int], certificate: Certificate
) -> None:
    policy = TlsPolicy.from_options(None, certificate.fingerprint)
    client = UnifiClient(controller(server[1], cert_fingerprint=certificate.fingerprint), policy)
    sites = client.sites()
    assert [s.id for s in sites.items] == ["default", "site-2"]
    assert Handler.seen_headers[-1]["X-API-KEY"] == "k" and Handler.seen_headers[-1]["Accept-Encoding"] == "identity"


@pytest.mark.security("T3")
def test_pin_mismatch_closes_before_any_request(server: tuple[str, int]) -> None:
    policy = TlsPolicy.from_options(None, bytes(32))
    client = UnifiClient(controller(server[1]), policy)
    with pytest.raises(TlsPinMismatchError):
        client.sites()
    assert Handler.seen_headers == []


@pytest.mark.security("T1")
def test_system_roots_reject_the_self_signed_certificate(server: tuple[str, int]) -> None:
    client = UnifiClient(controller(server[1]), TlsPolicy.from_options(None, None))
    with pytest.raises(TlsError, match="certificate verification failed"):
        client.sites()
    assert Handler.seen_headers == []


@pytest.mark.security("T2")
def test_ca_file_mode_verifies_chain_and_hostname(server: tuple[str, int], certificate: Certificate) -> None:
    policy = TlsPolicy.from_options(certificate.cert, None)
    client = UnifiClient(controller(server[1]), policy)
    assert len(client.sites().items) == 2
    also_named = UnifiClient(controller(server[1], host="localhost"), policy)
    assert len(also_named.sites().items) == 2
    with pytest.raises(ControllerError, match=r"127\.0\.0\.1:1: cannot connect"):
        observe_fingerprint("127.0.0.1", 1)


@pytest.mark.security("T2")
def test_ca_file_mode_rejects_a_certificate_that_does_not_name_the_host(
    dns_only_server: tuple[str, int], dns_only_certificate: Certificate
) -> None:
    policy = TlsPolicy.from_options(dns_only_certificate.cert, None)
    client = UnifiClient(controller(dns_only_server[1]), policy)
    with pytest.raises(TlsError, match=r"certificate verification failed for 127\.0\.0\.1"):
        client.sites()
    assert Handler.seen_headers == []
    assert len(UnifiClient(controller(dns_only_server[1], host="localhost"), policy).sites().items) == 2


@pytest.mark.security("T4", "T5")
def test_redirect_encoding_and_body_cap_over_the_wire(server: tuple[str, int], certificate: Certificate) -> None:
    policy = TlsPolicy.from_options(None, certificate.fingerprint)
    Handler.routes["/redirect"] = (302, {"Location": "https://evil.example/"}, b"")
    Handler.routes["/gzip"] = (200, {"Content-Encoding": "gzip"}, b"{}")
    Handler.routes["/big"] = (200, {}, b"[" + b"1," * 100 + b"1]")
    client = UnifiClient(controller(server[1]), policy, ClientOptions(max_body_bytes=100))
    with pytest.raises(ControllerError, match="redirect refused"):
        client.get("/redirect")
    with pytest.raises(ControllerError, match="Content-Encoding"):
        client.get("/gzip")
    with pytest.raises(ResponseTooLargeError):
        client.get("/big")


def test_gateway_errors_are_retried_over_the_wire(server: tuple[str, int], certificate: Certificate) -> None:
    policy = TlsPolicy.from_options(None, certificate.fingerprint)
    Handler.routes["/flaky"] = (503, {}, b"")
    sleeps: list[float] = []
    client = UnifiClient(controller(server[1]), policy, sleep=sleeps.append)
    with pytest.raises(ControllerError, match="gateway status 503"):
        client.get("/flaky")
    assert sleeps == [0.5, 1.0, 2.0] and len(Handler.seen_headers) == 4


GIVE_UP_S = 3.0


def trickle_server(
    certificate: Certificate, raw: bytes, delay_s: float, at_once: bytes = b"", handshake: bool = True
) -> Iterator[tuple[str, int]]:
    """Accept TLS connections and send `at_once`, then `raw` one byte at a time, slower than any budget,
    closing after `GIVE_UP_S` so a client without a working deadline fails fast instead of hanging for
    hours; with `handshake=False` the server accepts TCP and never speaks TLS."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(certificate.cert), str(certificate.key))
    stop = threading.Event()
    accepted: list[socket.socket] = []

    def serve() -> None:
        while not stop.is_set():
            try:
                conn, _ = listener.accept()
            except OSError:
                return
            accepted.append(conn)
            if not handshake:
                continue
            started = time.monotonic()
            try:
                with context.wrap_socket(conn, server_side=True) as tls:
                    tls.sendall(at_once)
                    for byte in raw:
                        if stop.is_set() or time.monotonic() - started > GIVE_UP_S:
                            break
                        tls.sendall(bytes([byte]))
                        time.sleep(delay_s)
            except OSError:
                continue

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield "127.0.0.1", listener.getsockname()[1]
    finally:
        stop.set()
        listener.close()
        for conn in accepted:
            conn.close()
        thread.join(timeout=5)


BODY = b"[" + b"1," * 100000
TRICKLES = [
    ("headers", b"", b"HTTP/1.1 200 OK\r\nContent-Length: 200000\r\nX-A: " + b"a" * 5000),
    ("body after keep-alive headers", b"HTTP/1.1 200 OK\r\nContent-Length: 200000\r\n\r\n", BODY),
    ("body after Connection: close", b"HTTP/1.1 200 OK\r\nContent-Length: 200000\r\nConnection: close\r\n\r\n", BODY),
    (
        "chunked body after Connection: close",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
        b"30d40\r\n" + BODY,
    ),
    ("HTTP/1.0 body without Content-Length", b"HTTP/1.0 200 OK\r\n\r\n", BODY),
    ("body read to EOF", b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n", BODY),
]  # fmt: skip


@pytest.mark.parametrize(("label", "at_once", "raw"), TRICKLES, ids=[t[0] for t in TRICKLES])
def test_a_server_that_trickles_bytes_is_cut_off_at_the_exchange_deadline(
    certificate: Certificate, label: str, at_once: bytes, raw: bytes
) -> None:
    # The header block arrives at once, so http.client has already dropped its socket reference for the
    # close/1.0/EOF cases when the body starts to trickle.
    policy = TlsPolicy.from_options(None, certificate.fingerprint)
    budget = 1
    for host, port in trickle_server(certificate, raw, delay_s=0.05, at_once=at_once):
        client = UnifiClient(controller(port, host=host, timeout_s=budget), policy)
        started = time.monotonic()
        with pytest.raises(ControllerError, match=f"response deadline of {budget} s exceeded"):
            client.sites()
        elapsed = time.monotonic() - started
        assert elapsed < budget + 1, f"{label}: {elapsed:.2f} s"


def test_an_abort_before_the_socket_exists_stops_the_connection_right_after_the_tcp_connect() -> None:
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    try:
        connection = AbortableHTTPSConnection(
            "127.0.0.1", listener.getsockname()[1], timeout=30, context=ssl.create_default_context()
        )
        connection.abort()
        started = time.monotonic()
        with pytest.raises(ConnectionAbortedError):
            connection.connect()
        assert time.monotonic() - started < 1.0
        connection.dispose()
    finally:
        listener.close()


def test_an_abort_during_name_resolution_or_tcp_connect_takes_effect_once_the_socket_exists() -> None:
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    try:
        connection = AbortableHTTPSConnection(
            "127.0.0.1", listener.getsockname()[1], timeout=30, context=ssl.create_default_context()
        )
        real = connection._create_connection  # type: ignore[attr-defined]

        def resolving_slowly(*args: object, **kwargs: object) -> socket.socket:
            connection.abort()  # the watchdog fires while getaddrinfo()/connect() are still running
            return real(*args, **kwargs)  # type: ignore[no-any-return]

        connection._create_connection = resolving_slowly  # type: ignore[attr-defined]
        with pytest.raises(ConnectionAbortedError):
            connection.connect()
        connection.dispose()
    finally:
        listener.close()


def test_a_stalled_handshake_ends_at_the_deadline_without_a_retry(certificate: Certificate) -> None:
    policy = TlsPolicy.from_options(None, certificate.fingerprint)
    budget = 1
    sleeps: list[float] = []
    for host, port in trickle_server(certificate, b"", delay_s=0, handshake=False):
        options = ClientOptions(read_timeout_s=budget, connect_timeout_s=30)
        client = UnifiClient(controller(port, host=host, timeout_s=budget), policy, options, sleep=sleeps.append)
        started = time.monotonic()
        with pytest.raises(ControllerError, match=f"response deadline of {budget} s exceeded"):
            client.sites()
        elapsed = time.monotonic() - started
        assert elapsed < budget + 1, f"handshake: {elapsed:.2f} s"
    assert sleeps == []


@pytest.mark.security("T10")
def test_dump_writer_writes_masked_models_and_unknown_counts(
    server: tuple[str, int], certificate: Certificate, tmp_path: Path
) -> None:
    Handler.routes["/proxy/network/api/s/default/rest/setting"] = (200, {}, payload("rest_setting.json"))
    dump = DumpWriter(tmp_path / "dump")
    policy = TlsPolicy.from_options(None, certificate.fingerprint)
    client = UnifiClient(controller(server[1]), policy, observe_unknown_keys=dump.observe_unknown_keys)
    result = client.settings("default")
    written = dump.write("s/default/settings", result)
    document = json.loads(written.read_text())
    assert written.name == "s_default_settings.json" and document["label"] == "s/default/settings"
    assert document["models"]["mgmt"]["ssh_password"] == "***" and "fixture-ssh-password" not in written.read_text()
    counts = document["unknown_field_count"]["/proxy/network/api/s/default/rest/setting"]
    # Only the four modelled setting records are counted, never the other 42 the controller sends.
    assert len(counts) == 4 and all(count >= 0 for count in counts.values())
    again = json.loads(dump.write("s/default/empty", result).read_text())
    assert again["unknown_field_count"] == {}
    assert (written.stat().st_mode & 0o777) == 0o600


@pytest.mark.security("T1")
def test_system_roots_accept_a_chain_the_platform_store_trusts_and_still_check_the_hostname(
    server: tuple[str, int],
    dns_only_server: tuple[str, int],
    certificate: Certificate,
    dns_only_certificate: Certificate,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # System-roots mode is OpenSSL's default store; SSL_CERT_FILE is how that store is pointed at a test CA
    # without touching the machine. The macOS Keychain is not consulted on this path either way.
    monkeypatch.delenv("SSL_CERT_DIR", raising=False)
    policy = TlsPolicy.from_options(None, None)
    monkeypatch.setenv("SSL_CERT_FILE", str(certificate.cert))
    assert len(UnifiClient(controller(server[1]), policy).sites().items) == 2
    # Trusted chain, wrong name: the hostname check is what rejects, not the chain.
    monkeypatch.setenv("SSL_CERT_FILE", str(dns_only_certificate.cert))
    with pytest.raises(
        TlsError, match=r"verification failed for 127\.0\.0\.1: .*(IP address mismatch|Hostname mismatch)"
    ):
        UnifiClient(controller(dns_only_server[1]), policy).sites()
    assert len(UnifiClient(controller(dns_only_server[1], host="localhost"), policy).sites().items) == 2
    # Right name, untrusted chain: the chain check rejects.
    with pytest.raises(TlsError, match=r"verification failed for localhost: .*self.signed"):
        UnifiClient(controller(server[1], host="localhost"), policy).sites()


@pytest.mark.security("T3")
def test_a_pin_mismatch_in_connect_leaves_no_socket_behind(server: tuple[str, int]) -> None:
    connection = PinnedHTTPSConnection(server[0], server[1], bytes(32))
    try:
        with pytest.raises(TlsPinMismatchError):
            connection.connect()
        assert connection.sock is None
    finally:
        # The abort descriptor duplicates the socket; the client releases it with the connection.
        connection.dispose()


@contextmanager
def eof_recording_server(
    certificate: Certificate,
) -> Iterator[tuple[tuple[str, int], list[tuple[bytes, float]], threading.Event]]:
    """Accept one TLS connection, then wait for the client's first bytes: records what arrived (EOF = b"") and
    how long it took. No session tickets, so the only thing the client can send after the handshake is a
    request or a close."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(certificate.cert), str(certificate.key))
    context.num_tickets = 0
    seen: list[tuple[bytes, float]] = []
    done = threading.Event()

    def serve() -> None:
        try:
            conn, _ = listener.accept()
        except OSError:
            return
        started = time.monotonic()
        try:
            with context.wrap_socket(conn, server_side=True) as tls:
                tls.settimeout(5.0)
                seen.append((tls.recv(16), time.monotonic() - started))
        except OSError as exc:
            seen.append((repr(exc).encode(), time.monotonic() - started))
        finally:
            done.set()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield ("127.0.0.1", listener.getsockname()[1]), seen, done
    finally:
        listener.close()
        thread.join(timeout=5)


@pytest.mark.security("T3")
def test_a_pin_mismatch_closes_the_connection_at_once_with_zero_request_bytes(certificate: Certificate) -> None:
    with eof_recording_server(certificate) as ((_host, port), seen, done):
        client = UnifiClient(controller(port), TlsPolicy.from_options(None, bytes(32)))
        with pytest.raises(TlsPinMismatchError):
            client.sites()
        assert done.wait(1.0), "the server never saw the client close"
        assert len(seen) == 1 and seen[0][0] == b"" and seen[0][1] < 1.0


@contextmanager
def endless_body_server(certificate: Certificate) -> Iterator[tuple[tuple[str, int], list[str]]]:
    """A response without Content-Length whose body never ends: the only way for a client to stop is to
    give up while streaming. Records how the client went away."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(certificate.cert), str(certificate.key))
    outcome: list[str] = []

    def serve() -> None:
        try:
            conn, _ = listener.accept()
        except OSError:
            return
        started = time.monotonic()
        try:
            with context.wrap_socket(conn, server_side=True) as tls:
                tls.settimeout(1.0)
                tls.recv(4096)
                tls.sendall(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")
                while time.monotonic() - started < GIVE_UP_S:
                    tls.sendall(b"[" + b"1," * 32768)
                outcome.append("gave up")
        except OSError as exc:
            outcome.append(f"client gone ({type(exc).__name__})")

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield ("127.0.0.1", listener.getsockname()[1]), outcome
    finally:
        listener.close()
        thread.join(timeout=GIVE_UP_S + 5)


@pytest.mark.security("T5")
def test_the_streamed_cap_stops_a_body_that_never_ends(certificate: Certificate) -> None:
    with endless_body_server(certificate) as ((_host, port), outcome):
        policy = TlsPolicy.from_options(None, certificate.fingerprint)
        options = ClientOptions(max_body_bytes=200_000, read_timeout_s=2.0)
        client = UnifiClient(controller(port), policy, options)
        started = time.monotonic()
        with pytest.raises(ResponseTooLargeError, match="exceeds 200000 bytes"):
            client.get("/endless")
        # Stopped by the cap, not by the deadline: a client that read to EOF would hit the deadline instead.
        assert time.monotonic() - started < 2.0
        deadline = time.monotonic() + GIVE_UP_S + 2
        while not outcome and time.monotonic() < deadline:
            time.sleep(0.05)
        assert outcome and outcome[0].startswith("client gone")
