"""The UniFi Network Application over HTTPS: GET only, bounded, decoded exactly once.

Every response passes four gates before a parser sees it: the TLS policy, the status/redirect/encoding
checks, the body cap enforced while streaming, and `json.loads` with constants rejected. Retries cover
only what is safe to repeat: a connect timeout or a 502-504 from a gateway in front of the controller.
"""

import http.client
import json
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from unifiwifioptimizer.adapters.unifi import parse
from unifiwifioptimizer.adapters.unifi.tls import AbortableHTTPSConnection, TlsPolicy, connect, open_connection
from unifiwifioptimizer.adapters.unifi.validate import Fields, Json, walk_depth
from unifiwifioptimizer.config.schema import ControllerConfig
from unifiwifioptimizer.domain.errors import ControllerError, ResponseTooLargeError, SchemaError, TlsError
from unifiwifioptimizer.domain.models import (
    SITE_ID_RE,
    ApGroup,
    ClientSighting,
    DevicesResult,
    Network,
    ParsedList,
    SettingsResult,
    Site,
    WlanConfig,
)

MAX_BODY_BYTES = 64 * 1024 * 1024
CHUNK_BYTES = 64 * 1024
CONNECT_TIMEOUT_S = 5.0
RETRY_BACKOFF_S = (0.5, 1.0, 2.0)
RETRY_ATTEMPTS = len(RETRY_BACKOFF_S) + 1
RETRY_STATUSES = frozenset({502, 503, 504})
API_PREFIX = "/proxy/network/api"
V2_PREFIX = "/proxy/network/v2/api"
USER_AGENT = "unifiwifioptimizer"

Sleep = Callable[[float], None]


class Watchdog(Protocol):
    def cancel(self) -> None: ...


# (seconds, action) → a started watchdog that runs `action` once unless cancelled first.
WatchdogFactory = Callable[[float, Callable[[], None]], Watchdog]
# (policy, host, port, connect timeout) → an unconnected connection; injectable so the transport can be
# exercised without sockets.
ConnectionFactory = Callable[[TlsPolicy, str, int, float], AbortableHTTPSConnection]
# One observation per (endpoint path, record path): how many keys the parser never read.
UnknownKeyObserver = Callable[[str, str, int], None]


def _timer(seconds: float, action: Callable[[], None]) -> Watchdog:
    timer = threading.Timer(seconds, action)
    timer.daemon = True
    timer.start()
    return timer


def _reject_constant(name: str) -> None:
    raise ValueError(f"JSON constant {name} is not allowed")


def decode_json(body: bytes, path: str) -> Json:
    """`json.loads` as the single decode point: NaN/Infinity rejected, depth bounded afterwards."""
    try:
        # RFC 8259 §8.1: UTF-8 only; `json.loads(bytes)` would also sniff UTF-16/32.
        payload: Json = json.loads(body.decode("utf-8"), parse_constant=_reject_constant)
    except (ValueError, RecursionError) as exc:
        raise SchemaError(path, f"invalid JSON ({type(exc).__name__})") from None
    walk_depth(payload)
    return payload


@dataclass(frozen=True, slots=True, kw_only=True)
class ClientOptions:
    read_timeout_s: float = 15.0
    connect_timeout_s: float = CONNECT_TIMEOUT_S
    max_body_bytes: int = MAX_BODY_BYTES


def _site_path(site_id: str) -> str:
    if SITE_ID_RE.fullmatch(site_id) is None:
        raise ControllerError(site_id, "not a site id")
    return site_id


class UnifiClient:
    """`ControllerApi` over `http.client`; one connection per request, nothing cached."""

    def __init__(
        self,
        controller: ControllerConfig,
        policy: TlsPolicy,
        options: ClientOptions | None = None,
        sleep: Sleep = time.sleep,
        observe_unknown_keys: UnknownKeyObserver | None = None,
        connection_factory: ConnectionFactory = open_connection,
        watchdog: WatchdogFactory = _timer,
    ) -> None:
        self._controller = controller
        self._policy = policy
        self._options = options or ClientOptions(read_timeout_s=float(controller.timeout_s))
        self._sleep = sleep
        self._watchdog = watchdog
        self._observe_unknown_keys = observe_unknown_keys
        self._connection_factory = connection_factory

    # --- ControllerApi -------------------------------------------------------------------------------

    def sites(self) -> ParsedList[Site]:
        path = f"{API_PREFIX}/self/sites"
        return parse.parse_sites(self.get(path), self._observer(path))

    def devices(self, site_id: str) -> DevicesResult:
        path = f"{API_PREFIX}/s/{_site_path(site_id)}/stat/device"
        return parse.parse_devices(self.get(path), self._observer(path))

    def wlans(self, site_id: str) -> ParsedList[WlanConfig]:
        path = f"{API_PREFIX}/s/{_site_path(site_id)}/list/wlanconf"
        return parse.parse_wlans(self.get(path), self._observer(path))

    def ap_groups(self, site_id: str) -> ParsedList[ApGroup]:
        path = f"{V2_PREFIX}/site/{_site_path(site_id)}/apgroups"
        return parse.parse_ap_groups(self.get(path), self._observer(path))

    def networks(self, site_id: str) -> ParsedList[Network]:
        path = f"{API_PREFIX}/s/{_site_path(site_id)}/rest/networkconf"
        return parse.parse_networks(self.get(path), self._observer(path))

    def settings(self, site_id: str) -> SettingsResult:
        path = f"{API_PREFIX}/s/{_site_path(site_id)}/rest/setting"
        return parse.parse_settings(self.get(path), self._observer(path))

    def clients(self, site_id: str) -> ParsedList[ClientSighting]:
        path = f"{API_PREFIX}/s/{_site_path(site_id)}/stat/sta"
        return parse.parse_clients(self.get(path), self._observer(path))

    def _observer(self, endpoint: str) -> Callable[[Fields], None] | None:
        observe = self._observe_unknown_keys
        if observe is None:
            return None
        return lambda fields: observe(endpoint, fields.path_self, fields.unknown_key_count())

    # --- transport ------------------------------------------------------------------------------------

    def get(self, path: str) -> Json:
        """One GET, decoded; retried on a connect timeout or a gateway 502-504, never otherwise."""
        for attempt in range(RETRY_ATTEMPTS):
            try:
                return self._get_once(path)
            except _RetryableError as exc:
                if attempt == RETRY_ATTEMPTS - 1:
                    raise exc.error from None
                self._sleep(RETRY_BACKOFF_S[attempt])
        raise AssertionError("unreachable")  # pragma: no cover

    def _get_once(self, path: str) -> Json:
        connection = self._connection_factory(
            self._policy, self._controller.host, self._controller.port, self._options.connect_timeout_s
        )
        expired = threading.Event()

        def expire() -> None:
            # Socket timeouts are per recv; http.client keeps receiving until a chunk or a header line is
            # complete, so a trickling server is stopped only by tearing the connection down from outside.
            expired.set()
            connection.abort()

        def deadline_error() -> ControllerError:
            return ControllerError(path, f"response deadline of {self._options.read_timeout_s:g} s exceeded")

        watchdog = self._watchdog(self._options.read_timeout_s, expire)
        try:
            try:
                connect(connection)
            except TimeoutError:
                if expired.is_set():
                    raise deadline_error() from None
                raise _RetryableError(ControllerError(path, "connect timeout")) from None
            except (OSError, TlsError) as exc:
                if expired.is_set():
                    raise deadline_error() from None
                if isinstance(exc, TlsError):
                    raise
                raise ControllerError(path, f"cannot connect ({exc.strerror or exc})") from None
            if expired.is_set():
                raise deadline_error()
            if connection.sock is not None:
                connection.sock.settimeout(self._options.read_timeout_s)
            try:
                connection.request("GET", path, headers=self._headers())
                response = connection.getresponse()
                try:
                    body = self._read(response, path)
                finally:
                    # The response owns a buffered reader over the socket; closing the connection alone
                    # leaves the descriptor open until garbage collection.
                    response.close()
            except _RetryableError:
                if expired.is_set():
                    raise deadline_error() from None
                raise
            except TimeoutError:
                if expired.is_set():
                    raise deadline_error() from None
                raise ControllerError(path, "read timeout") from None
            except (http.client.HTTPException, OSError) as exc:
                if expired.is_set():
                    raise deadline_error() from None
                raise ControllerError(path, f"transport failure ({type(exc).__name__})") from None
            # A read-to-EOF body that the shutdown truncated is complete-looking bytes, not the response.
            if expired.is_set():
                raise deadline_error()
            return decode_json(body, path)
        finally:
            watchdog.cancel()
            connection.dispose()

    def _headers(self) -> Mapping[str, Any]:
        return {
            "X-API-KEY": self._controller.api_key.reveal(),
            "Accept": "application/json",
            # Compressed bodies would defeat the byte cap; the server must send the bytes it means.
            "Accept-Encoding": "identity",
            "User-Agent": USER_AGENT,
            "Connection": "close",
        }

    def _read(self, response: http.client.HTTPResponse, path: str) -> bytes:
        status = response.status
        if status in RETRY_STATUSES:
            raise _RetryableError(ControllerError(path, f"gateway status {status}", status))
        if 300 <= status < 400:
            raise ControllerError(path, f"redirect refused (status {status})", status)
        if status != 200:
            raise ControllerError(path, f"unexpected status {status}", status)
        encoding = response.getheader("Content-Encoding", "identity").lower()
        if encoding != "identity":
            raise ControllerError(path, "unexpected Content-Encoding", status)
        declared = response.getheader("Content-Length")
        cap = self._options.max_body_bytes
        if declared is not None:
            if not (declared.isascii() and declared.isdigit() and len(declared) <= 20):
                raise ControllerError(path, "malformed Content-Length", status)
            if int(declared) > cap:
                raise ResponseTooLargeError(path, f"declared body exceeds {cap} bytes", status)
        chunks: list[bytes] = []
        received = 0
        while chunk := response.read(CHUNK_BYTES):
            received += len(chunk)
            if received > cap:
                raise ResponseTooLargeError(path, f"body exceeds {cap} bytes", status)
            chunks.append(chunk)
        # `read(amt)` returns what arrived before EOF without raising IncompleteRead.
        if declared is not None and received < int(declared):
            raise ControllerError(path, "body shorter than Content-Length", status)
        return b"".join(chunks)


class _RetryableError(Exception):
    def __init__(self, error: ControllerError) -> None:
        super().__init__(str(error))
        self.error = error
