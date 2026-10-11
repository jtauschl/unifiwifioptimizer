"""TLS towards the controller: verified by the system roots, by a private CA, or by a certificate pin.

There is no "skip verification" mode. The pin mode is the only place that disables certificate-chain
verification, and it does so inside one constructor; the connection then refuses to carry a request
until `connect()` has compared the peer certificate's SHA-256 against the pin. The same class observes
a fingerprint for the `controller-fingerprint` helper, which is trust-on-first-use by definition.
"""

import hashlib
import hmac
import http.client
import os
import socket
import ssl
import threading
from contextlib import suppress
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, cast

from unifiwifioptimizer.domain.errors import ConfigError, ControllerError, TlsError, TlsPinMismatchError

CONNECT_TIMEOUT_S = 5.0
FINGERPRINT_BYTES = 32


class TlsMode(StrEnum):
    SYSTEM_ROOTS = "system-roots"
    CA_FILE = "ca-file"
    PIN = "pin"


@dataclass(frozen=True, slots=True, kw_only=True)
class TlsPolicy:
    mode: TlsMode
    ca_file: Path | None = None
    pin: bytes | None = None

    @classmethod
    def from_options(cls, ca_file: Path | None, pin: bytes | None) -> "TlsPolicy":
        if ca_file is not None and pin is not None:
            raise ValueError("ca_file and pin are mutually exclusive")
        if pin is not None:
            if len(pin) != FINGERPRINT_BYTES:
                raise ValueError("a pin is the 32-byte SHA-256 of the DER certificate")
            return cls(mode=TlsMode.PIN, pin=pin)
        if ca_file is not None:
            return cls(mode=TlsMode.CA_FILE, ca_file=ca_file)
        return cls(mode=TlsMode.SYSTEM_ROOTS)


def verified_context(ca_file: Path | None) -> ssl.SSLContext:
    """A hostname-checking context: the system roots, or the given CA bundle alone.

    A CA file that cannot be loaded is a configuration error (exit 3), not a TLS failure: nothing was
    contacted yet.
    """
    try:
        return ssl.create_default_context(cafile=str(ca_file) if ca_file is not None else None)
    except (OSError, ssl.SSLError) as exc:
        raise ConfigError("controller.ca_cert", f"cannot load the CA bundle ({exc.__class__.__name__})") from None


class AbortableHTTPSConnection(http.client.HTTPSConnection):
    """An HTTPS connection whose exchange can be cut off from another thread, whatever phase it is in.

    `http.client` hides the socket during the phases that matter: `wrap_socket()` detaches the plain TCP
    socket for the handshake, and `getresponse()` drops `sock` as soon as a response says it will close the
    connection — which is every response to our own `Connection: close`. `abort()` therefore works on a
    duplicate descriptor taken right after the TCP connect: a socket-level shutdown on it ends the connection
    for every holder of the underlying socket, while the `SSLSocket` keeps its TLS state, so anything read
    afterwards still has to be a TLS record.
    """

    def __init__(self, host: str, port: int, *, timeout: float, context: ssl.SSLContext) -> None:
        super().__init__(host, port, timeout=timeout, context=context)
        self._tls_context = context
        self._abort_fd: int | None = None
        self._aborted = False
        self._abort_lock = threading.Lock()

    def connect(self) -> None:
        # Nothing here can shorten the phase before a socket exists: getaddrinfo() has no timeout at all
        # and the connect timeout applies per address candidate. An abort that arrives meanwhile is
        # latched and takes effect the moment the socket is there.
        http.client.HTTPConnection.connect(self)
        # HTTPConnection.connect() either set the socket or raised; the Optional is typing only.
        tcp = cast(socket.socket, self.sock)
        with self._abort_lock:
            if self._aborted:
                tcp.close()
                raise ConnectionAbortedError("aborted before the connection was established")
            self._abort_fd = os.dup(tcp.fileno())
        self.sock = self._tls_context.wrap_socket(tcp, server_hostname=self.host)

    def abort(self) -> None:
        """Shut the connection down for every phase, including a handshake or a body `http.client` is
        reading after it has already forgotten the socket; before the socket exists (name resolution, TCP
        connect) the abort is latched and `connect()` fails as soon as it has one."""
        with self._abort_lock:
            self._aborted = True
            if self._abort_fd is None:
                return
            with suppress(OSError):
                duplicate = socket.socket(fileno=os.dup(self._abort_fd))
                try:
                    duplicate.shutdown(socket.SHUT_RDWR)
                finally:
                    duplicate.close()

    def dispose(self) -> None:
        """`close()` plus the abort descriptor; `close()` alone is what `http.client` calls on its own as
        soon as a response announces `Connection: close`, while the body is still being read."""
        self.close()
        with self._abort_lock:
            if self._abort_fd is not None:
                os.close(self._abort_fd)
                self._abort_fd = None


class PinnedHTTPSConnection(AbortableHTTPSConnection):
    """HTTPS to one host whose certificate is identified by its SHA-256 instead of a chain.

    `pin=None` builds an observation connection: it completes the handshake and exposes
    `peer_fingerprint`, but `send()` — which every request path ends in — refuses to write to it.
    """

    def __init__(self, host: str, port: int, pin: bytes | None, timeout: float = CONNECT_TIMEOUT_S) -> None:
        if pin is not None and len(pin) != FINGERPRINT_BYTES:
            raise ValueError("a pin is the 32-byte SHA-256 of the DER certificate")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        # Chain verification is replaced by the fingerprint comparison in connect(); hostname checking
        # must be switched off before the verify mode, or ssl raises.
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        super().__init__(host, port, timeout=timeout, context=context)
        self._pin = pin
        self.peer_fingerprint: bytes | None = None

    def connect(self) -> None:
        super().connect()
        der = self.sock.getpeercert(binary_form=True)
        if not der:
            self.close()
            raise TlsError("the controller presented no certificate")
        observed = hashlib.sha256(der).digest()
        self.peer_fingerprint = observed
        if self._pin is not None and not hmac.compare_digest(observed, self._pin):
            self.close()
            raise TlsPinMismatchError(self._pin, observed)

    def send(self, data: Any) -> None:
        if self._pin is None:
            raise TlsError("an observation connection cannot carry requests")
        super().send(data)


def observe_fingerprint(host: str, port: int, timeout: float = CONNECT_TIMEOUT_S) -> bytes:
    """The SHA-256 of the certificate the controller presents right now (trust on first use)."""
    connection = PinnedHTTPSConnection(host, port, pin=None, timeout=timeout)
    try:
        try:
            connection.connect()
        except ssl.SSLError as exc:
            raise TlsError(f"TLS handshake with {host}:{port} failed: {exc.reason or exc}") from None
        except OSError as exc:
            raise ControllerError(f"{host}:{port}", f"cannot connect ({exc.strerror or exc})") from None
        if connection.peer_fingerprint is None:
            raise TlsError("the controller presented no certificate")
        return connection.peer_fingerprint
    finally:
        connection.dispose()


def connect(connection: AbortableHTTPSConnection) -> None:
    """Complete the TCP and TLS handshake; a verification failure is a `TlsError`, a timeout stays one."""
    try:
        connection.connect()
    except ssl.SSLCertVerificationError as exc:
        connection.close()
        raise TlsError(f"certificate verification failed for {connection.host}: {exc.verify_message}") from None
    except ssl.SSLError as exc:
        connection.close()
        raise TlsError(f"TLS handshake with {connection.host} failed: {exc.reason or exc}") from None


def open_connection(
    policy: TlsPolicy, host: str, port: int, timeout: float = CONNECT_TIMEOUT_S
) -> AbortableHTTPSConnection:
    """An unconnected HTTPS connection whose verification follows `policy`."""
    if policy.mode is TlsMode.PIN:
        if policy.pin is None:
            raise ValueError("pin mode without a pin")
        return PinnedHTTPSConnection(host, port, pin=policy.pin, timeout=timeout)
    return AbortableHTTPSConnection(host, port, timeout=timeout, context=verified_context(policy.ca_file))
