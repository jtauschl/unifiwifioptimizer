"""`trust-host-keys`: learn the access points' SSH host keys into the tool's store, verified where possible.

For every access point that takes part in a neighbour pair, the keys `ssh-keyscan` can obtain are compared
against the expected fingerprint — the configuration pin first, the fingerprint the controller reports
second. A verified match is stored under the access point's alias; an unverified key (nothing to compare
against) is stored only after an explicit confirmation per access point or `--accept-unverified`.
`--yes` confirms verified matches only. Any ambiguity or conflict aborts for that access point.
"""

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import StrEnum

from unifiwifioptimizer.adapters.ssh.hostkeys import (
    HostKeyCandidate,
    KnownHostsStore,
    TrustBasis,
    expected_fingerprint,
    keyscan,
    select_candidate,
)
from unifiwifioptimizer.adapters.ssh.openssh import is_allowed_address
from unifiwifioptimizer.app.scanning import controller_origin, scan_members
from unifiwifioptimizer.app.use_cases import resolve_site
from unifiwifioptimizer.config.load import LoadedConfig
from unifiwifioptimizer.config.schema import SiteConfig
from unifiwifioptimizer.domain.errors import ConfigError, HostKeyTrustError
from unifiwifioptimizer.domain.hostkeys import host_key_alias, normalize_fingerprint
from unifiwifioptimizer.domain.models import AccessPoint
from unifiwifioptimizer.ports.controller import ControllerApi

Keyscan = Callable[[AccessPoint], Sequence[HostKeyCandidate]]
Confirm = Callable[[str], bool]


class TrustOutcome(StrEnum):
    STORED = "stored"
    ALREADY_STORED = "already stored"
    DECLINED = "declined"
    FAILED = "failed"
    NOT_ON_CONTROLLER = "not on the controller"


@dataclass(frozen=True, slots=True, kw_only=True)
class TrustResult:
    ap_name: str
    outcome: TrustOutcome
    basis: TrustBasis | None
    # The stored or offered key's SHA-256 in `SHA256:<base64>` form, or the reason for a failure.
    detail: str


@dataclass(frozen=True, slots=True, kw_only=True)
class TrustReport:
    site_id: str
    results: tuple[TrustResult, ...]

    @property
    def failed(self) -> bool:
        return any(r.outcome is TrustOutcome.FAILED for r in self.results)


def default_keyscan(ap: AccessPoint) -> Sequence[HostKeyCandidate]:
    return keyscan(ap.ip)


def trust_host_keys(
    api: ControllerApi,
    loaded: LoadedConfig,
    store: KnownHostsStore,
    selector: str,
    only: Sequence[str],
    *,
    assume_yes: bool,
    accept_unverified: bool,
    confirm: Confirm,
    scan: Keyscan = default_keyscan,
) -> TrustReport:
    site = resolve_site(api, selector)
    site_config = loaded.config.sites.get(site.id)
    if site_config is None or site_config.ssh is None:
        raise ConfigError(f"sites.{site.id}.ssh", "no ssh section for this site; nothing to trust")
    devices = api.devices(site.id)
    by_name = {ap.name: ap for ap in devices.access_points}
    names = tuple(only) if only else scan_members(site_config)
    if not names:
        raise ConfigError(f"sites.{site.id}.neighbors", "no access points take part in a neighbour pair")
    origin = controller_origin(loaded.config.controller)
    results = tuple(
        _trust_one(by_name.get(name), name, site_config, origin, store, assume_yes, accept_unverified, confirm, scan)
        for name in names
    )
    return TrustReport(site_id=site.id, results=results)


def _trust_one(
    ap: AccessPoint | None,
    name: str,
    site: SiteConfig,
    origin: str,
    store: KnownHostsStore,
    assume_yes: bool,
    accept_unverified: bool,
    confirm: Confirm,
    scan: Keyscan,
) -> TrustResult:
    if ap is None:
        return TrustResult(ap_name=name, outcome=TrustOutcome.NOT_ON_CONTROLLER, basis=None, detail="")
    alias = host_key_alias(origin, site.id, ap.mac)
    pins = site.ssh.host_keys if site.ssh is not None else {}
    allow_public = site.ssh.allow_public_ap_addresses if site.ssh is not None else False
    if not is_allowed_address(ap.ip, allow_public):
        # The same rule as the scan: a controller-supplied address must not make the tool probe the internet.
        return TrustResult(
            ap_name=name, outcome=TrustOutcome.FAILED, basis=None,
            detail=f"address {ap.ip} is not a private network address",
        )  # fmt: skip
    try:
        controller_fingerprint = (
            normalize_fingerprint(ap.ssh_host_key_fingerprint) if ap.ssh_host_key_fingerprint is not None else None
        )
    except ValueError:
        return TrustResult(
            ap_name=name, outcome=TrustOutcome.FAILED, basis=None,
            detail="the controller reports a host-key fingerprint in an unknown form",
        )  # fmt: skip
    try:
        expectation = expected_fingerprint(pins.get(ap.mac), controller_fingerprint)
        candidates = scan(ap)
        chosen = select_candidate(candidates, expectation)
    except HostKeyTrustError as exc:
        return TrustResult(ap_name=name, outcome=TrustOutcome.FAILED, basis=None, detail=str(exc))
    fingerprint = chosen.sha256.text
    known = store.entry(alias)
    if known is not None:
        if known.key_type == chosen.key_type and known.key_base64 == chosen.key_base64:
            return TrustResult(
                ap_name=name, outcome=TrustOutcome.ALREADY_STORED, basis=expectation.basis, detail=fingerprint
            )
        return TrustResult(
            ap_name=name, outcome=TrustOutcome.FAILED, basis=expectation.basis,
            detail=f"a different host key is already stored for this access point ({fingerprint} offered now)",
        )  # fmt: skip
    verified = expectation.basis is not TrustBasis.UNVERIFIED
    if verified:
        accepted = assume_yes or confirm(f"{name}: store host key {fingerprint} (matches the {expectation.basis})?")
    else:
        accepted = accept_unverified or confirm(
            f"{name}: nothing to verify {fingerprint} against — store it on first use anyway?"
        )
    if not accepted:
        return TrustResult(ap_name=name, outcome=TrustOutcome.DECLINED, basis=expectation.basis, detail=fingerprint)
    try:
        store.add(chosen.entry(alias))
    except HostKeyTrustError as exc:
        return TrustResult(ap_name=name, outcome=TrustOutcome.FAILED, basis=expectation.basis, detail=str(exc))
    return TrustResult(ap_name=name, outcome=TrustOutcome.STORED, basis=expectation.basis, detail=fingerprint)
