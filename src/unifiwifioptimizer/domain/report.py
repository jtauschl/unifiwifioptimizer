"""Report values: what the analysis and the compliance engine produce and the renderers print."""

from collections.abc import Collection, Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from types import MappingProxyType

from unifiwifioptimizer.domain.analysis import (
    BandTxOutcome,
    ChannelPlanMethod,
    MissDirection,
    MissingReason,
    NeighbourMarker,
    PartialReason,
    ReadingSource,
    RoamingCap,
    WlanRoamingStatus,
)
from unifiwifioptimizer.domain.models import Band, DeviceState, FieldProblem, TxPowerMode, UnparsableDevice
from unifiwifioptimizer.domain.scan import ScanFailureKind


class Severity(StrEnum):
    INFO = "info"
    ADVISORY = "advisory"
    WARNING = "warning"
    ERROR = "error"


class CheckStatus(StrEnum):
    """`INCOMPLETE`: the controller did not send a field the check needs; `NOT_EVALUABLE`: the tool has no
    rule for this case yet (6 GHz detect-only); `NOT_APPLICABLE`: the check does not apply to this subject."""

    PASSED = "passed"
    FAILED = "failed"
    INCOMPLETE = "incomplete"
    NOT_EVALUABLE = "not_evaluable"
    NOT_APPLICABLE = "not_applicable"


class RecommendationKind(StrEnum):
    """`CHANGE`: the setting should move to `recommended`. `CONFIRMED`: the setting is right and fully
    evaluated. `HELD`: no change is recommended, but not because the setting was confirmed (a hysteresis
    hold, a neighbour that could not be evaluated, a blocked reduction, a radio already at its maximum).
    `CONDITIONAL`: the setting is off by choice; `recommended` is the value to use if it is switched on."""

    CHANGE = "change"
    CONFIRMED = "confirmed"
    HELD = "held"
    CONDITIONAL = "conditional"


@dataclass(frozen=True, slots=True, kw_only=True)
class Finding:
    """`subject` and `peers` carry the external names structured, so the renderer can sanitise each token
    instead of truncating a composed line."""

    severity: Severity
    code: str
    message: str
    subject: str
    band: Band | None = None
    peers: tuple[str, ...] = ()


class Deferral(StrEnum):
    """Why advice is provisional: it rests on a setting that another recommendation changes first."""

    CHANNEL_PLAN = "channel_plan"
    TX_CHANGE = "tx_change"


@dataclass(frozen=True, slots=True, kw_only=True)
class CheckResult:
    code: str
    subject: str
    status: CheckStatus
    detail: str
    expected: str | None = None
    actual: str | None = None
    deferred_by: Deferral | None = None


# The limit of every channel plan, said once per band: beacon observations show presence, not airtime.
BEACON_EVIDENCE_GAP = "scan beacons do not establish channel airtime or absence on unsurveyed channels"

# The two radio settings a recommendation can address.
TX_POWER = "tx_power"
MIN_RSSI = "min_rssi"


@dataclass(frozen=True, slots=True, kw_only=True)
class Recommendation:
    """A setting verdict. `kind` is derived by the analysis from the values and the evaluation state; only
    `CHANGE` counts as a pending change. `current_mode` is the radio's transmit-power mode when the setting
    is a transmit power (a non-Custom radio is phrased as "set to Custom, N dBm"). `unverified_headroom`
    marks an increase above the power the radio has demonstrated on its channel."""

    code: str
    subject: str
    band: Band | None
    setting: str
    current: int | None
    recommended: int
    kind: RecommendationKind
    reason: str
    current_mode: TxPowerMode | None = None
    unverified_headroom: bool = False
    # The corridor-derived value when `recommended` was moved into the range the controller accepts.
    derived_dbm: int | None = None
    deferred_by: Deferral | None = None

    @property
    def is_change(self) -> bool:
        return self.kind is RecommendationKind.CHANGE

    @property
    def is_actionable(self) -> bool:
        return self.is_change and self.deferred_by is None


@dataclass(frozen=True, slots=True, kw_only=True)
class WlanEvaluation:
    wlan: str
    profile: str
    checks: tuple[CheckResult, ...]
    findings: tuple[Finding, ...]
    # The network the WLAN is attached to; the VLAN is None for an untagged network.
    network: str | None = None
    vlan: int | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class SiteCompliance:
    """`findings` carries the site-level problems (a configured WLAN the controller does not have, an
    unknown profile name); the per-WLAN advisories sit inside each evaluation."""

    evaluations: tuple[WlanEvaluation, ...]
    findings: tuple[Finding, ...]

    @property
    def has_failures(self) -> bool:
        return bool(self.findings) or any(
            check.status is CheckStatus.FAILED for evaluation in self.evaluations for check in evaluation.checks
        )


# --- the structured site report -------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True, kw_only=True)
class EnvironmentSummary:
    preset: str | None
    exponent: float
    # Extra path loss from 60 % of the AP distance to the full distance, the 2.4 GHz corridor offset.
    delta_db: float


@dataclass(frozen=True, slots=True, kw_only=True)
class CorridorSummary:
    low_dbm: int
    high_dbm: int


@dataclass(frozen=True, slots=True, kw_only=True)
class RfSummary:
    cell_edge_dbm: int
    noise_floor_dbm: int
    required_snr_db: int
    client_tx_dbm: int
    min_rssi_offset_db: int
    roam_offset_db: int
    roam_margin_db: int
    roam_floor_dbm: int
    roam_ceiling_dbm: int
    client_tx_dbm_5g_upper: int | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class NeighbourRow:
    peer: str
    rssi_dbm: int | None
    source: ReadingSource | None
    samples: int
    reason: MissingReason | None
    marker: NeighbourMarker | None
    receiver_offset_db: int | None


@dataclass(frozen=True, slots=True, kw_only=True)
class TxSummaryReport:
    antenna_gain_dbi: int | None
    effective_dbm: int | None
    configured_dbm: int | None
    mode: TxPowerMode | None
    min_dbm: int | None
    max_dbm: int | None
    effective_max_dbm: int | None
    effective_max_verified: bool


@dataclass(frozen=True, slots=True, kw_only=True)
class AirtimeReport:
    utilisation_pct: int | None
    self_rx_pct: int | None
    self_tx_pct: int | None
    tx_retries_pct: float | None
    satisfaction_pct: int | None
    client_count: int | None


@dataclass(frozen=True, slots=True, kw_only=True)
class ClientReport:
    total: int
    below_min_rssi: int
    weakest_dbm: int | None
    min_rssi_dbm: int


@dataclass(frozen=True, slots=True, kw_only=True)
class ForeignReport:
    count: int
    strongest_dbm: int | None
    overlapping_count: int


@dataclass(frozen=True, slots=True, kw_only=True)
class BandReport:
    band: Band
    channel: int | None
    width_mhz: int | None
    extension_channel: int | None
    channel_auto: bool
    configured_channel: int | None
    dfs: bool
    cac_seconds: int | None
    tx: TxSummaryReport
    outcome: BandTxOutcome
    weakest_dbm: int | None
    neighbours: tuple[NeighbourRow, ...]
    findings: tuple[Finding, ...]
    recommendations: tuple[Recommendation, ...]
    airtime: AirtimeReport | None
    clients: ClientReport | None
    foreign: ForeignReport | None
    assumed_client_tx_dbm: int | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class ApReport:
    name: str
    mac: str
    model: str | None
    state: DeviceState | None
    state_code: int | None
    uplink_type: str | None
    configured: bool
    bands: tuple[BandReport, ...]
    findings: tuple[Finding, ...]


@dataclass(frozen=True, slots=True, kw_only=True)
class RoamingApDetail:
    ap: str
    weakest_peer: str
    weakest_rssi_dbm: int
    source: ReadingSource
    downlink_dbm: int
    uplink_dbm: int
    cap: RoamingCap
    raw_cap_dbm: int | None
    assumed_client_tx_dbm: int | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class WlanRoamingSummary:
    wlan: str
    status: WlanRoamingStatus
    threshold_dbm: int | None
    # The derived value when `threshold_dbm` was moved to the nearest value the controller accepts.
    derived_dbm: int | None
    reasons: tuple[str, ...]
    limiting: tuple[str, ...]
    broadcasting: tuple[str, ...]
    per_ap: tuple[RoamingApDetail, ...]
    # A pending 5 GHz TX change on a broadcasting AP makes even an OK threshold stale.
    tx_change_pending: bool


@dataclass(frozen=True, slots=True, kw_only=True)
class MissingPair:
    band: Band
    a: str
    b: str
    direction: MissDirection
    reasons: tuple[str, ...]


@dataclass(frozen=True, slots=True, kw_only=True)
class GroupReport:
    members: tuple[str, ...]
    missing: tuple[MissingPair, ...]
    overlapping: tuple[tuple[Band, str, str], ...]
    reuse_infeasible: tuple[Band, ...]

    @property
    def clean(self) -> bool:
        return not self.missing and not self.overlapping and not self.reuse_infeasible


@dataclass(frozen=True, slots=True, kw_only=True)
class ScanSummary:
    passes: int
    scanned: tuple[str, ...]
    unknown_names: tuple[str, ...]
    # AP name -> the failure kinds of its failed passes (empty tuple: every pass succeeded).
    failures_by_ap: Mapping[str, tuple[ScanFailureKind, ...]]
    # AP name -> number of successful passes.
    successes_by_ap: Mapping[str, int]
    skipped: bool

    def __post_init__(self) -> None:
        object.__setattr__(self, "failures_by_ap", MappingProxyType(dict(self.failures_by_ap)))
        object.__setattr__(self, "successes_by_ap", MappingProxyType(dict(self.successes_by_ap)))


class ChannelPlanStatus(StrEnum):
    UNAVAILABLE = "unavailable"
    NO_IMPROVEMENT = "no_improvement"
    RECOMMENDED = "recommended"


@dataclass(frozen=True, slots=True, kw_only=True)
class ChannelAssignment:
    ap: str
    current: int
    proposed: int
    width_mhz: int


@dataclass(frozen=True, slots=True, kw_only=True)
class PowerOpportunity:
    ap: str
    current_channel: int
    candidate_channel: int
    current_dbm: int
    candidate_ceiling_dbm: int
    overlapping_peers: int
    cac_seconds: int | None


@dataclass(frozen=True, slots=True, kw_only=True)
class BandChannelPlan:
    band: Band
    status: ChannelPlanStatus
    reason: str | None
    method: ChannelPlanMethod | None
    assignments: tuple[ChannelAssignment, ...]
    own_conflicts_before: int | None
    own_conflicts_after: int | None
    own_pressure_before: int | None
    own_pressure_after: int | None
    foreign_overlaps_before: int | None
    foreign_overlaps_after: int | None
    data_gaps: tuple[str, ...]
    power_opportunities: tuple[PowerOpportunity, ...] = ()
    possible_power_pressure_after: int | None = None

    @property
    def has_changes(self) -> bool:
        return self.status is ChannelPlanStatus.RECOMMENDED and any(a.current != a.proposed for a in self.assignments)


@dataclass(frozen=True, slots=True, kw_only=True)
class ExtendedChannelPlan:
    bands: tuple[BandChannelPlan, ...]

    @property
    def has_changes(self) -> bool:
        return any(b.has_changes for b in self.bands)


@dataclass(frozen=True, slots=True, kw_only=True)
class SiteReport:
    """Everything the renderers print for one site; the flat views are derived from the nested blocks so
    there is one source of truth."""

    site_id: str
    site_name: str
    captured_at: datetime
    environment: EnvironmentSummary
    rf: RfSummary
    corridors: Mapping[Band, CorridorSummary]
    scan_passes: int
    aps: tuple[ApReport, ...]
    compliance: SiteCompliance
    roaming: tuple[WlanRoamingSummary, ...]
    groups: tuple[GroupReport, ...]
    scan: ScanSummary
    site_findings: tuple[Finding, ...]
    field_problems: tuple[FieldProblem, ...]
    unparsable: tuple[UnparsableDevice, ...]
    partial_reasons: tuple[PartialReason, ...]
    verifiable_ap_count: int
    host_key_failed_ap_count: int
    # Whether neighbour scans ran for this site (False under `--no-scan` and for a controller-only site).
    scanning: bool
    extended_channel_plan: ExtendedChannelPlan | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "corridors", MappingProxyType(dict(self.corridors)))

    @property
    def findings(self) -> tuple[Finding, ...]:
        nested = [f for ap in self.aps for band in ap.bands for f in band.findings]
        ap_level = [f for ap in self.aps for f in ap.findings]
        wlan_level = [f for e in self.compliance.evaluations for f in e.findings]
        return (*self.site_findings, *self.compliance.findings, *wlan_level, *ap_level, *nested)

    @property
    def recommendations(self) -> tuple[Recommendation, ...]:
        return tuple(r for ap in self.aps for band in ap.bands for r in band.recommendations)

    @property
    def checks(self) -> tuple[CheckResult, ...]:
        return tuple(c for e in self.compliance.evaluations for c in e.checks)

    @property
    def actionable_changes(self) -> int:
        return sum(1 for r in self.recommendations if r.is_actionable)

    @property
    def pending_tx_changes(self) -> int:
        """Transmit-power changes that can be applied now."""
        return sum(1 for r in self.recommendations if r.setting == TX_POWER and r.is_actionable)

    def pending_5g_tx_changes_of(self, aps: Collection[str]) -> int:
        """5 GHz transmit-power changes that can be applied now on the given access points."""
        return sum(
            1
            for r in self.recommendations
            if r.setting == TX_POWER and r.band is Band.GHZ_5 and r.is_actionable and r.subject in aps
        )

    @property
    def failed_checks(self) -> int:
        """Failed WLAN checks that can be fixed now."""
        return sum(1 for c in self.checks if c.status is CheckStatus.FAILED and c.deferred_by is None)

    @property
    def waiting_items(self) -> int:
        """Changes and failed checks that wait for another change to be applied first."""
        return sum(1 for r in self.recommendations if r.is_change and r.deferred_by is not None) + sum(
            1 for c in self.checks if c.status is CheckStatus.FAILED and c.deferred_by is not None
        )

    @property
    def has_changes(self) -> bool:
        return (
            (self.extended_channel_plan is not None and self.extended_channel_plan.has_changes)
            or any(r.is_change for r in self.recommendations)
            or any(c.status is CheckStatus.FAILED for c in self.checks)
        )

    @property
    def partial(self) -> bool:
        return bool(self.partial_reasons)
