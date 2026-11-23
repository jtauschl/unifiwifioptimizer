"""Error hierarchy shared by every layer.

Each subclass names one failure class; the command line decides the exit code. A message is written
for the operator and never embeds secrets or raw external strings.
"""

from unifiwifioptimizer.domain.fingerprints import format_fingerprint
from unifiwifioptimizer.domain.hostkeys import TrustRefusalKind


class UwoError(Exception):
    """Base class for every error the tool raises on purpose."""


class SchemaError(UwoError):
    """Controller data violates the schema or a limit; `path` names the offending element."""

    def __init__(self, path: str, message: str) -> None:
        super().__init__(f"{path}: {message}")
        self.path = path
        self.detail = message


# The most of an error text that the command line prints (`main` caps it there).
MAX_ERROR_CHARS = 2048


class ConfigError(UwoError):
    """The user's configuration cannot be used; `path` names the offending key or file."""

    def __init__(self, path: str, message: str) -> None:
        super().__init__(f"{path}: {message}")
        self.path = path
        self.detail = message


class ConfigNotFoundError(ConfigError):
    """The configuration file, or the directory that should hold it, does not exist."""


class ConfigTimeoutError(ConfigError):
    """Parsing the configuration exceeded its deadline."""


class TlsError(UwoError):
    """The TLS layer refused the controller connection."""


class TlsVerificationError(TlsError):
    """The controller's certificate did not verify against the roots or the CA file in use."""

    def __init__(self, message: str, verify_code: int, verify_message: str) -> None:
        super().__init__(message)
        self.verify_code = verify_code
        self.verify_message = verify_message


class TlsPinMismatchError(TlsError):
    """The controller presented a certificate whose SHA-256 differs from the pinned one."""

    def __init__(self, expected: bytes, observed: bytes) -> None:
        super().__init__(
            "controller certificate fingerprint mismatch: "
            f"expected {format_fingerprint(expected)}, observed {format_fingerprint(observed)}; the certificate "
            "changed or this is not your controller: compare it with the certificate view of the controller before "
            "you change `controller.cert_fingerprint`"
        )
        self.expected = expected
        self.observed = observed


class ControllerError(UwoError):
    """The controller did not answer a request as expected; `status` is the HTTP status when there was one."""

    def __init__(self, path: str, message: str, status: int | None = None) -> None:
        super().__init__(f"{path}: {message}")
        self.path = path
        self.detail = message
        self.status = status


class ResponseTooLargeError(ControllerError):
    """A response body exceeded the cap and the connection was closed without reading it."""


class ToolEnvironmentError(UwoError):
    """The host lacks something the tool needs (a binary, a version, a writable directory)."""


class ScanError(UwoError):
    """A neighbour scan on one access point failed; the run isolates it and continues with the others.

    `cause` is the display-ready text that says why, with its origin named and any text the access point chose quoted
    (`domain/scan.py` `ap_said`); None when the message already says everything.
    """

    def __init__(self, message: str, cause: str | None = None) -> None:
        super().__init__(message)
        self.cause = cause


class HostKeyUnknownError(ScanError):
    """No host key is stored for the access point's alias; nothing was sent.

    A terminal run asks to store it; otherwise run `trust-host-keys`.
    """


class HostKeyMismatchError(ScanError):
    """OpenSSH refused the access point's host key against the stored one; nothing was authenticated."""


class SshAuthenticationError(ScanError):
    """The access point rejected the credentials."""


class ScanTimeoutError(ScanError):
    """The SSH call did not finish within its budget and was killed."""


class ScanOutputTooLargeError(ScanError):
    """The access point produced more output than the caps allow; the call was killed."""


class ScanTransportError(ScanError):
    """OpenSSH could not connect or ended abnormally for a reason other than the ones above."""


class RemoteScriptError(ScanError):
    """The remote scan script ended with a non-zero status of its own."""


class ScanParseError(ScanError):
    """The access point's output did not follow the scan protocol."""

    def __init__(self, message: str) -> None:
        super().__init__(message, cause=message)


class AddressRefusedError(ScanError):
    """The tool does not connect to the address the controller reports for the access point."""


class HostKeyTrustError(UwoError):
    """The trust step cannot handle an access point (no match, ambiguity, conflicting sources, a store that changed).
    `kind` names the refusal; `domain/hostkeys.py` `TRUST_ADVICE` gives its next step."""

    def __init__(self, kind: TrustRefusalKind, message: str) -> None:
        super().__init__(message)
        self.kind = kind
