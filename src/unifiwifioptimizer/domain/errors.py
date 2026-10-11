"""Error hierarchy shared by every layer.

Each subclass names one failure class; the command line decides the exit code. A message is written
for the operator and never embeds secrets or raw external strings.
"""

from unifiwifioptimizer.domain.fingerprints import format_fingerprint


class UwoError(Exception):
    """Base class for every error the tool raises on purpose."""


class NotImplementedPathError(UwoError):
    """A code path that exists in the interface but has no implementation in this build."""

    def __init__(self, path: str) -> None:
        super().__init__(f"{path} is not implemented in this build")
        self.path = path


class SchemaError(UwoError):
    """Controller data violates the schema or a limit; `path` names the offending element."""

    def __init__(self, path: str, message: str) -> None:
        super().__init__(f"{path}: {message}")
        self.path = path
        self.detail = message


class ConfigError(UwoError):
    """The user's configuration cannot be used; `path` names the offending key or file."""

    def __init__(self, path: str, message: str) -> None:
        super().__init__(f"{path}: {message}")
        self.path = path
        self.detail = message


class ConfigTimeoutError(ConfigError):
    """Parsing the configuration exceeded its deadline."""


class TlsError(UwoError):
    """The TLS layer refused the controller connection."""


class TlsPinMismatchError(TlsError):
    """The controller presented a certificate whose SHA-256 differs from the pinned one."""

    def __init__(self, expected: bytes, observed: bytes) -> None:
        super().__init__(
            "controller certificate fingerprint mismatch: "
            f"expected {format_fingerprint(expected)}, observed {format_fingerprint(observed)}"
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
    """A neighbour scan on one access point failed; the run isolates it and continues with the others."""


class HostKeyUnknownError(ScanError):
    """No host key is stored for the access point's alias; nothing was sent (run `trust-host-keys`)."""


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


class AddressRefusedError(ScanError):
    """The access point's address is not private and `allow_public_ap_addresses` is off."""


class HostKeyTrustError(UwoError):
    """`trust-host-keys` cannot decide which key to trust (no match, ambiguity, conflicting sources)."""
