"""What one site analysis needs, assembled by the application layer from the configuration, the snapshot and
the scans; the core never sees the configuration types themselves."""

from collections.abc import Mapping
from dataclasses import dataclass

from unifiwifioptimizer.domain.models import SiteSnapshot
from unifiwifioptimizer.domain.profile import ProfileSet
from unifiwifioptimizer.domain.scan import SiteScan
from unifiwifioptimizer.rf.corridor import PathLossModel
from unifiwifioptimizer.rf.settings import RfSettings


@dataclass(frozen=True, slots=True, kw_only=True)
class SiteAnalysisInput:
    """`scan` is None when the site does not scan or the scan was skipped; `scan_skipped` tells the two
    apart. `neighbours` is the operator's adjacency as configured (one direction is enough; the analysis
    symmetrises it)."""

    snapshot: SiteSnapshot
    scan: SiteScan | None
    scan_skipped: bool
    neighbours: Mapping[str, frozenset[str]]
    environment: PathLossModel
    rf: RfSettings
    scan_passes: int
    wlan_profiles: Mapping[str, str]
    profiles: ProfileSet
