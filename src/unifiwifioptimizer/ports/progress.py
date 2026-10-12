"""Progress as a port: the application reports what it is doing, the command line decides how to show it.

Events are emitted from the coordinating thread only — with a pool (`scan_concurrency` > 1) the
orchestrator reports as it consumes the results, never from a worker — so an implementation needs no
locking.
"""

from typing import Protocol

from unifiwifioptimizer.domain.scan import ScanFailure, ScanPass


class ScanProgress(Protocol):
    def scan_started(self, ap_name: str, pass_index: int, passes: int) -> None: ...

    def scan_finished(self, ap_name: str, outcome: ScanPass | ScanFailure) -> None: ...


class Progress(ScanProgress, Protocol):
    def site_started(self, site_id: str, scanning: bool) -> None: ...

    def analysis_started(self, site_id: str) -> None: ...
