"""The neighbour scanner as the core sees it: one access point in, one pass out, or a `ScanError`."""

from typing import Protocol

from unifiwifioptimizer.domain.scan import ScanPass, ScanTarget


class Scanner(Protocol):
    """Runs the remote scan on one access point and returns both bands plus the metadata block.

    Failures surface as `ScanError` subclasses (host key unknown or mismatched, authentication, timeout,
    output cap, transport, remote script, unparsable output); the caller isolates them per access point.
    """

    def scan(self, target: ScanTarget) -> ScanPass: ...
