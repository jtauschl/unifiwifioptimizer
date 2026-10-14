import http.client
import json
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from unifiwifioptimizer.adapters.unifi import client as client_module
from unifiwifioptimizer.adapters.unifi.client import ClientOptions, UnifiClient, UnknownKeyObserver, decode_json
from unifiwifioptimizer.adapters.unifi.tls import AbortableHTTPSConnection, TlsPolicy
from unifiwifioptimizer.config.schema import ControllerConfig
from unifiwifioptimizer.domain.errors import ControllerError, ResponseTooLargeError, SchemaError, TlsError
from unifiwifioptimizer.domain.secrets import Secret

FIXTURES = Path(__file__).parents[2] / "fixtures"
CONTROLLER = ControllerConfig(
    host="unifi.example", port=8443, api_key=Secret("k3y"), ca_cert=None, cert_fingerprint=None, timeout_s=15
)
POLICY = TlsPolicy.from_options(None, None)


class FakeResponse:
    def __init__(
        self, status: int, body: bytes, headers: dict[str, str] | None = None, chunk: int | None = None
    ) -> None:
        self.status = status
        self._body = body
        self._headers = {k.lower(): v for k, v in (headers or {}).items()}
        self._offset = 0

    def getheader(self, name: str, default: str | None = None) -> str | None:
        return self._headers.get(name.lower(), default)

    def read(self, amount: int) -> bytes:
        chunk = self._body[self._offset : self._offset + amount]
        self._offset += len(chunk)
        return chunk

    def close(self) -> None:
        self.closed = True


class FakeSocket:
    def __init__(self) -> None:
        self.timeouts: list[float] = []

    def settimeout(self, value: float) -> None:
        self.timeouts.append(value)


class ConnectFails:
    def __init__(self, exc: BaseException) -> None:
        self.exc = exc


Step = Callable[[], FakeResponse] | ConnectFails
# Keys of the fixture's first access point (incl. nested radio/stats/vap records) the parser never reads.
AP_UNREAD_KEYS = 73
# Keys of a wireless client record the parser never reads (28 keys, 9 read).
CLIENT_UNREAD_KEYS = 19


class FakeConnection:
    """Stands in for `http.client.HTTPSConnection`; `script` yields what each connect attempt does."""

    def __init__(self, script: Iterator[Step], log: list[str]) -> None:
        self._script = script
        self._log = log
        self.sock: FakeSocket | None = None
        self.requests: list[tuple[str, str, dict[str, str]]] = []
        self.host = CONTROLLER.host
        self.aborts = 0

    def abort(self) -> None:
        self._log.append("abort")
        self.aborts += 1

    def connect(self) -> None:
        self._log.append("connect")
        step = next(self._script)
        if isinstance(step, ConnectFails):
            raise step.exc
        self._step = step
        self.sock = self.last_sock = FakeSocket()

    def request(self, method: str, url: str, body: object = None, headers: dict[str, str] | None = None) -> None:
        self.requests.append((method, url, dict(headers or {})))

    def getresponse(self) -> FakeResponse:
        self.response = self._step()
        # http.client drops its socket reference as soon as the response will close the connection — which
        # every answer to our own `Connection: close` does.
        self.sock = None
        return self.response

    def dispose(self) -> None:
        self._log.append("dispose")


class FakeWatchdog:
    """Records how the client arms the exchange watchdog; `fire()` runs the deadline action on demand."""

    def __init__(self, log: list[str]) -> None:
        self.log = log
        self.armed: list[float] = []
        self.action: Callable[[], None] | None = None
        self.cancelled = 0

    def __call__(self, seconds: float, action: Callable[[], None]) -> "FakeWatchdog":
        self.armed.append(seconds)
        self.action = action
        self.log.append("arm")
        return self

    def fire(self) -> None:
        assert self.action is not None
        self.action()

    def cancel(self) -> None:
        self.cancelled += 1
        self.log.append("cancel")


def make_client(
    *steps: Step,
    options: ClientOptions | None = None,
    observe: UnknownKeyObserver | None = None,
    watchdog: FakeWatchdog | None = None,
) -> tuple[UnifiClient, list[str], list[float], list[FakeConnection]]:
    log: list[str] = []
    sleeps: list[float] = []
    connections: list[FakeConnection] = []
    script = iter(steps)
    if watchdog is not None:
        watchdog.log = log

    def factory(policy: TlsPolicy, host: str, port: int, timeout: float) -> AbortableHTTPSConnection:
        assert (policy, host, port) == (POLICY, "unifi.example", 8443)
        connection = FakeConnection(script, log)
        connections.append(connection)
        return connection  # type: ignore[return-value]

    client = UnifiClient(
        CONTROLLER,
        POLICY,
        options,
        sleep=sleeps.append,
        observe_unknown_keys=observe,
        connection_factory=factory,
        watchdog=watchdog or FakeWatchdog(log),
    )
    return client, log, sleeps, connections


def ok(payload: object, **headers: str) -> Callable[[], FakeResponse]:
    body = json.dumps(payload).encode()
    return lambda: FakeResponse(200, body, {"Content-Length": str(len(body)), **headers})


def status(code: int) -> Callable[[], FakeResponse]:
    return lambda: FakeResponse(code, b"", {})


def raising(exc: BaseException) -> Callable[[], FakeResponse]:
    def step() -> FakeResponse:
        raise exc

    return step


def test_get_sends_the_api_key_identity_encoding_and_closes_the_connection() -> None:
    client, log, sleeps, connections = make_client(ok({"data": []}))
    assert client.get("/proxy/network/api/self/sites") == {"data": []}
    (connection,) = connections
    method, url, headers = connection.requests[0]
    assert (method, url) == ("GET", "/proxy/network/api/self/sites")
    assert (
        headers["X-API-KEY"] == "k3y" and headers["Accept-Encoding"] == "identity" and headers["Connection"] == "close"
    )
    assert connection.last_sock.timeouts == [15.0] and connection.sock is None
    # The watchdog spans the whole exchange: armed before connect, cancelled before the connection closes.
    assert log == ["arm", "connect", "cancel", "dispose"] and sleeps == []


@pytest.mark.security("T11")
def test_api_key_never_appears_in_the_client_repr() -> None:
    client, *_ = make_client()
    assert "k3y" not in repr(client) and "k3y" not in repr(vars(client))


@pytest.mark.parametrize(
    ("code", "message"),
    [
        (299, "unexpected status"),
        (300, "redirect refused"),
        (301, "redirect refused"),
        (302, "redirect refused"),
        (303, "redirect refused"),
        (307, "redirect refused"),
        (308, "redirect refused"),
        (399, "redirect refused"),
        (400, "unexpected status"),
        (401, "unexpected status 401"),
        (500, "unexpected status 500"),
    ],
)
@pytest.mark.security("T4")
def test_redirects_and_other_statuses_are_errors_without_retry(code: int, message: str) -> None:
    client, log, sleeps, _ = make_client(status(code))
    with pytest.raises(ControllerError, match=message) as exc:
        client.get("/x")
    assert exc.value.status == code and sleeps == [] and log == ["arm", "connect", "cancel", "dispose"]


def test_gateway_errors_and_connect_timeouts_are_retried_with_backoff_then_raised() -> None:
    client, log, sleeps, _ = make_client(status(502), ConnectFails(TimeoutError()), ok({"data": []}))
    assert client.get("/x") == {"data": []}
    assert sleeps == [0.5, 1.0] and log.count("connect") == 3 and log.count("dispose") == 3
    client, log, sleeps, _ = make_client(status(503), status(504), status(503), status(502))
    with pytest.raises(ControllerError, match="gateway status 502") as exc:
        client.get("/x")
    assert exc.value.status == 502 and sleeps == [0.5, 1.0, 2.0] and log.count("connect") == 4


def test_connect_timeout_is_raised_after_the_last_attempt() -> None:
    client, log, sleeps, _ = make_client(*(ConnectFails(TimeoutError()) for _ in range(4)))
    with pytest.raises(ControllerError, match="connect timeout"):
        client.get("/x")
    assert sleeps == [0.5, 1.0, 2.0] and log.count("connect") == 4 and log.count("dispose") == 4


def test_read_timeout_and_transport_failures_are_not_retried() -> None:
    client, _, sleeps, _ = make_client(raising(TimeoutError()))
    with pytest.raises(ControllerError, match="read timeout"):
        client.get("/x")
    assert sleeps == []
    client, _, sleeps, _ = make_client(raising(http.client.RemoteDisconnected("closed")))
    with pytest.raises(ControllerError, match="transport failure"):
        client.get("/x")
    assert sleeps == []


def test_tls_errors_propagate_untouched() -> None:
    def factory(policy: TlsPolicy, host: str, port: int, timeout: float) -> AbortableHTTPSConnection:
        class Refusing(FakeConnection):
            def connect(self) -> None:
                raise TlsError("handshake failed")

        return Refusing(iter(()), [])  # type: ignore[return-value]

    client = UnifiClient(CONTROLLER, POLICY, connection_factory=factory)
    with pytest.raises(TlsError, match="handshake failed"):
        client.get("/x")


def test_other_os_errors_at_connect_are_controller_errors() -> None:
    def factory(policy: TlsPolicy, host: str, port: int, timeout: float) -> AbortableHTTPSConnection:
        class Refusing(FakeConnection):
            def connect(self) -> None:
                raise ConnectionRefusedError(61, "Connection refused")

        return Refusing(iter(()), [])  # type: ignore[return-value]

    client = UnifiClient(CONTROLLER, POLICY, connection_factory=factory)
    with pytest.raises(ControllerError, match="cannot connect"):
        client.get("/x")


@pytest.mark.security("T5")
def test_content_encoding_other_than_identity_is_refused_and_the_response_is_closed() -> None:
    client, _, _, connections = make_client(ok({"data": []}, **{"Content-Encoding": "gzip"}))
    with pytest.raises(ControllerError, match="Content-Encoding"):
        client.get("/x")
    assert connections[0].response.closed is True
    client, *_ = make_client(ok({"data": []}, **{"Content-Encoding": "identity"}))
    assert client.get("/x") == {"data": []}


@pytest.mark.security("T5")
def test_body_cap_is_enforced_on_the_declared_length_and_while_streaming() -> None:
    options = ClientOptions(max_body_bytes=100)
    client, *_ = make_client(lambda: FakeResponse(200, b"[]", {"Content-Length": "101"}), options=options)
    with pytest.raises(ResponseTooLargeError, match="declared body exceeds 100"):
        client.get("/x")
    big = b"[" + b"1," * 60 + b"1]"
    client, *_ = make_client(lambda: FakeResponse(200, big, {}), options=options)
    with pytest.raises(ResponseTooLargeError, match="body exceeds 100"):
        client.get("/x")
    one_over = b"[" + b"1," * 49 + b"1]"
    assert len(one_over) == 101
    client, *_ = make_client(lambda: FakeResponse(200, one_over, {}), options=options)
    with pytest.raises(ResponseTooLargeError, match="body exceeds 100"):
        client.get("/x")
    exact = b"[" + b"1," * 48 + b"1]"
    assert len(exact) <= 100
    client, *_ = make_client(lambda: FakeResponse(200, exact, {}), options=options)
    assert client.get("/x") == [1] * 49


@pytest.mark.parametrize("declared", ["x", "\u00b2", "2, 2", "-1", "1" * 21, "", " 2", "0x10"])
@pytest.mark.security("T5")
def test_malformed_content_length_is_refused_before_any_body_byte_is_read(declared: str) -> None:
    body = b"[1]"
    client, _, _, connections = make_client(lambda: FakeResponse(200, body, {"Content-Length": declared}))
    with pytest.raises(ControllerError, match="malformed Content-Length"):
        client.get("/x")
    assert connections[0].response._offset == 0
    client, *_ = make_client(lambda: FakeResponse(200, body, {"Content-Length": "1" * 20}))
    with pytest.raises(ResponseTooLargeError, match="declared body exceeds"):
        client.get("/x")


def test_the_watchdog_tears_the_socket_down_and_the_failure_reads_as_the_deadline() -> None:
    watchdog = FakeWatchdog([])

    class Stalled(FakeResponse):
        def read(self, amount: int) -> bytes:
            # What http.client raises once the watchdog shut the socket down under it.
            watchdog.fire()
            raise ConnectionResetError(54, "Connection reset by peer")

    client, log, sleeps, connections = make_client(lambda: Stalled(200, b"", {}), watchdog=watchdog)
    with pytest.raises(ControllerError, match=r"response deadline of 15 s exceeded"):
        client.get("/x")
    assert watchdog.armed == [15.0] and watchdog.cancelled == 1 and sleeps == []
    assert connections[0].response.closed is True and log[-3:] == ["abort", "cancel", "dispose"]
    assert connections[0].aborts == 1 and connections[0].sock is None


def test_a_stalled_header_phase_reads_as_the_deadline() -> None:
    watchdog = FakeWatchdog([])

    class HeadersStall(FakeConnection):
        def getresponse(self) -> FakeResponse:
            watchdog.fire()
            raise TimeoutError()

    def factory_headers(policy: TlsPolicy, host: str, port: int, timeout: float) -> AbortableHTTPSConnection:
        return HeadersStall(iter([ok({"data": []})]), [])  # type: ignore[return-value]

    client = UnifiClient(CONTROLLER, POLICY, connection_factory=factory_headers, watchdog=watchdog)
    with pytest.raises(ControllerError, match="response deadline of 15 s exceeded"):
        client.get("/x")
    assert watchdog.cancelled == 1


def test_a_gateway_status_that_arrives_after_the_deadline_is_not_retried() -> None:
    watchdog = FakeWatchdog([])

    class LateGateway(FakeConnection):
        def getresponse(self) -> FakeResponse:
            watchdog.fire()
            return super().getresponse()

    def factory(policy: TlsPolicy, host: str, port: int, timeout: float) -> AbortableHTTPSConnection:
        return LateGateway(iter([status(503)] * 4), [])  # type: ignore[return-value]

    sleeps: list[float] = []
    client = UnifiClient(CONTROLLER, POLICY, connection_factory=factory, watchdog=watchdog, sleep=sleeps.append)
    with pytest.raises(ControllerError, match="response deadline of 15 s exceeded"):
        client.get("/x")
    assert sleeps == [] and watchdog.cancelled == 1


def test_a_deadline_that_fires_during_a_successful_connect_still_ends_the_exchange() -> None:
    watchdog = FakeWatchdog([])

    class ConnectsLate(FakeConnection):
        def connect(self) -> None:
            super().connect()
            watchdog.fire()

    def factory(policy: TlsPolicy, host: str, port: int, timeout: float) -> AbortableHTTPSConnection:
        return ConnectsLate(iter([ok({"data": []})]), [])  # type: ignore[return-value]

    client = UnifiClient(CONTROLLER, POLICY, connection_factory=factory, watchdog=watchdog)
    with pytest.raises(ControllerError, match="response deadline of 15 s exceeded"):
        client.get("/x")


def test_a_handshake_that_outlives_the_deadline_is_not_retried() -> None:
    watchdog = FakeWatchdog([])

    class HandshakeTimesOut(FakeConnection):
        def connect(self) -> None:
            watchdog.fire()
            raise TimeoutError()

    def factory(policy: TlsPolicy, host: str, port: int, timeout: float) -> AbortableHTTPSConnection:
        return HandshakeTimesOut(iter(()), [])  # type: ignore[return-value]

    sleeps: list[float] = []
    client = UnifiClient(CONTROLLER, POLICY, connection_factory=factory, watchdog=watchdog, sleep=sleeps.append)
    with pytest.raises(ControllerError, match="response deadline of 15 s exceeded"):
        client.get("/x")
    assert sleeps == [] and watchdog.cancelled == 1


def test_a_body_completed_only_after_the_deadline_is_not_decoded() -> None:
    watchdog = FakeWatchdog([])

    class CompletesLate(FakeResponse):
        def read(self, amount: int) -> bytes:
            chunk = super().read(amount)
            if not chunk:
                watchdog.fire()
            return chunk

    client, *_ = make_client(lambda: CompletesLate(200, b'{"data": []}', {}), watchdog=watchdog)
    with pytest.raises(ControllerError, match="response deadline of 15 s exceeded"):
        client.get("/x")


def test_the_read_timeout_option_is_the_watchdog_budget() -> None:
    watchdog = FakeWatchdog([])
    client, *_ = make_client(ok({"data": []}), options=ClientOptions(read_timeout_s=2.5), watchdog=watchdog)
    assert client.get("/x") == {"data": []} and watchdog.armed == [2.5]


@pytest.mark.security("T5")
def test_a_body_shorter_than_its_declared_length_is_refused() -> None:
    client, *_ = make_client(lambda: FakeResponse(200, b"[1]", {"Content-Length": "4"}))
    with pytest.raises(ControllerError, match="body shorter than Content-Length"):
        client.get("/x")
    client, *_ = make_client(lambda: FakeResponse(200, b"[1]", {"Content-Length": "3"}))
    assert client.get("/x") == [1]


@pytest.mark.parametrize(
    "body",
    [
        b"{",
        b"NaN",
        b"[Infinity]",
        b"\xff",
        b"[" * 40 + b"]" * 40,
        "[1]".encode("utf-16"),
        b"\xef\xbb\xbf[1]",
        b'{"data": [{"name": "\\ud800"}]}',
        b'{"data": [{"\\udcff": 1}]}',
        b'["\\ud83d"]',
    ],
)
@pytest.mark.security("T5")
def test_decoding_rejects_bad_json_constants_and_deep_nesting(body: bytes) -> None:
    with pytest.raises(SchemaError):
        decode_json(body, "/x")


@pytest.mark.security("T5")
def test_decode_json_never_echoes_the_body() -> None:
    with pytest.raises(SchemaError) as exc:
        decode_json(b'{"TOPSECRET": ', "/x")
    assert "TOPSECRET" not in str(exc.value)


def test_endpoints_map_onto_the_parsers_and_report_unread_keys() -> None:
    payloads = {
        "/proxy/network/api/self/sites": json.loads((FIXTURES / "sites.json").read_text()),
        "/proxy/network/api/s/default/stat/device": json.loads((FIXTURES / "stat_device.json").read_text()),
        "/proxy/network/api/s/default/list/wlanconf": json.loads((FIXTURES / "list_wlanconf.json").read_text()),
        "/proxy/network/v2/api/site/default/apgroups": json.loads((FIXTURES / "apgroups.json").read_text()),
        "/proxy/network/api/s/default/rest/setting": json.loads((FIXTURES / "rest_setting.json").read_text()),
        "/proxy/network/api/s/default/stat/sta": json.loads((FIXTURES / "stat_sta.json").read_text()),
    }
    observed: list[tuple[str, str, int]] = []
    requested: list[str] = []

    def factory(policy: TlsPolicy, host: str, port: int, timeout: float) -> AbortableHTTPSConnection:
        class Routing(FakeConnection):
            def request(
                self, method: str, url: str, body: object = None, headers: dict[str, str] | None = None
            ) -> None:
                requested.append(url)
                self._payload = payloads[url]

            def getresponse(self) -> FakeResponse:
                data = json.dumps(self._payload).encode()
                return FakeResponse(200, data, {"Content-Length": str(len(data))})

        connection = Routing(iter([lambda: FakeResponse(200, b"", {})] * 10), [])
        return connection  # type: ignore[return-value]

    client = UnifiClient(
        CONTROLLER, POLICY, connection_factory=factory, observe_unknown_keys=lambda e, p, n: observed.append((e, p, n))
    )
    assert [s.id for s in client.sites().items] == ["default", "site-2"]
    assert len(client.devices("default").access_points) == 4
    assert len(client.wlans("default").items) == 5
    assert len(client.ap_groups("default").items) == 1
    assert client.settings("default").settings.country_code == 276
    assert len(client.clients("default").items) == 26
    assert len(requested) == 6
    by_endpoint = {endpoint for endpoint, _, _ in observed}
    assert by_endpoint == set(payloads)
    sites_counts = [(p, n) for e, p, n in observed if e.endswith("self/sites")]
    assert sites_counts == [("$.data[0]", 3), ("$.data[1]", 2)]
    # Only modelled records are counted: the switches and the gateway at $.data[0..2] never reach the dump.
    device_counts = {p: n for e, p, n in observed if e.endswith("stat/device")}
    assert set(device_counts) == {"$.data[3]", "$.data[5]", "$.data[9]", "$.data[10]"}
    assert device_counts["$.data[3]"] == AP_UNREAD_KEYS
    # Wireless clients only, counted after the parser read its fields.
    client_counts = {p: n for e, p, n in observed if e.endswith("stat/sta")}
    assert len(client_counts) == 26 and set(client_counts.values()) == {CLIENT_UNREAD_KEYS}


def test_site_ids_are_validated_before_they_become_a_path() -> None:
    client, *_ = make_client()
    for bad in ("../admin", "a/b", "", "x" * 65, "a?b"):
        with pytest.raises(ControllerError, match="not a site id"):
            client.devices(bad)


def test_default_read_timeout_follows_the_controller_configuration() -> None:
    client, _, _, connections = make_client(ok({"data": []}))
    client.get("/x")
    assert connections[0].last_sock.timeouts == [float(CONTROLLER.timeout_s)]
    assert client_module.RETRY_BACKOFF_S == (0.5, 1.0, 2.0) and client_module.RETRY_ATTEMPTS == 4
