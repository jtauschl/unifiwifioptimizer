"""The trust step: learn an access point's SSH host key into the tool's store, verified where possible.

For every access point that takes part in a neighbour pair, the keys `ssh-keyscan` can obtain are compared
against the expected fingerprint — the configuration pin first, the fingerprint the controller reports
second. `plan_trust` turns what is stored, what is offered and what is expected into one decision; the caller's
policy (a typed answer, `--yes`, `--accept-unverified`) decides whether it is applied. A verified key is stored
or replaced on a confirmation, or on `--yes`; an unverified key is stored on a confirmation or
`--accept-unverified` and never replaces a stored key without a confirmation.

Two entry points share this code: `trust-host-keys`, and `run` when a terminal answers the questions. Only
this module (and the composition root that builds the writer) changes the store.
"""

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address

from unifiwifioptimizer.adapters.ssh.hostkeys import (
    Expectation,
    HostKeyCandidate,
    KnownHostEntry,
    KnownHostsWriter,
    TrustBasis,
    expected_fingerprint,
    keyscan,
    select_candidate,
)
from unifiwifioptimizer.adapters.ssh.openssh import is_allowed_address
from unifiwifioptimizer.app.scanning import SSH_PORT, controller_origin, scan_members
from unifiwifioptimizer.app.use_cases import resolve_site
from unifiwifioptimizer.config.load import LoadedConfig
from unifiwifioptimizer.config.schema import SiteConfig
from unifiwifioptimizer.domain.errors import ConfigError, HostKeyTrustError
from unifiwifioptimizer.domain.hostkeys import host_key_alias, key_fingerprints, normalize_fingerprint
from unifiwifioptimizer.domain.models import AccessPoint
from unifiwifioptimizer.domain.scan import ScanTarget
from unifiwifioptimizer.ports.controller import ControllerApi

Address = IPv4Address | IPv6Address
# (address, port, key type or None for the types of the full scan)
Keyscan = Callable[[Address, int, str | None], Sequence[HostKeyCandidate]]


class PromptKind(StrEnum):
    NEW = "new"
    REPLACE = "replace"


@dataclass(frozen=True, slots=True, kw_only=True)
class Prompt:
    """One question for the person at the terminal. The app layer decides what is asked; the command line
    decides how the answer is given (`y/N`, or the typed fingerprint prefix for a replace)."""

    kind: PromptKind
    text: str
    # SHA-256 of the key that would be stored, in `SHA256:<base64>` form.
    new_fingerprint: str


Confirm = Callable[[Prompt], bool]


class TrustOutcome(StrEnum):
    STORED = "stored"
    REPLACED = "replaced"
    ALREADY_STORED = "already stored"
    DECLINED = "declined"
    FAILED = "failed"
    NOT_ON_CONTROLLER = "not on the controller"


@dataclass(frozen=True, slots=True, kw_only=True)
class TrustResult:
    ap_name: str
    outcome: TrustOutcome
    basis: TrustBasis | None
    # The stored or offered key's SHA-256 in `SHA256:<base64>` form ("old -> new" for a replace), or the
    # reason for a failure.
    detail: str


@dataclass(frozen=True, slots=True, kw_only=True)
class TrustReport:
    site_id: str
    results: tuple[TrustResult, ...]

    @property
    def failed(self) -> bool:
        return any(r.outcome is TrustOutcome.FAILED for r in self.results)


@dataclass(frozen=True, slots=True, kw_only=True)
class TrustPolicy:
    assume_yes: bool
    accept_unverified: bool
    confirm: Confirm


@dataclass(frozen=True, slots=True, kw_only=True)
class TrustSubject:
    """What the trust step needs to know about one access point."""

    site_id: str
    name: str
    alias: str
    address: Address
    port: int
    allow_public_address: bool
    config_pin: bytes | None
    controller_fingerprint: str | None


@dataclass(frozen=True, slots=True)
class StoreNew:
    chosen: HostKeyCandidate
    basis: TrustBasis


@dataclass(frozen=True, slots=True)
class Replace:
    old: KnownHostEntry
    chosen: HostKeyCandidate
    basis: TrustBasis


@dataclass(frozen=True, slots=True)
class AlreadyStored:
    chosen_fingerprint: str
    basis: TrustBasis


@dataclass(frozen=True, slots=True)
class Refused:
    reason: str
    basis: TrustBasis | None = None


TrustDecision = StoreNew | Replace | AlreadyStored | Refused


def default_keyscan(address: Address, port: int, key_type: str | None) -> Sequence[HostKeyCandidate]:
    return keyscan(address, port, key_type=key_type)


def _satisfies(candidate: HostKeyCandidate, expectation: Expectation) -> bool:
    return all(candidate.matches(fingerprint) for fingerprint in expectation.fingerprints)


def _stored_candidate(entry: KnownHostEntry) -> HostKeyCandidate:
    sha256, md5 = key_fingerprints(entry.key_base64)
    return HostKeyCandidate(entry.key_type, entry.key_base64, sha256, md5)


def _same_key(entry: KnownHostEntry, candidate: HostKeyCandidate) -> bool:
    return entry.key_type == candidate.key_type and entry.key_base64 == candidate.key_base64


def plan_trust(
    stored: Sequence[KnownHostEntry], offered: Sequence[HostKeyCandidate], expectation: Expectation
) -> TrustDecision:
    """The decision for one access point, first matching rule wins:

    1. several stored lines for the alias: refused (OpenSSH trusts any of them);
    2. nothing offered: refused;
    3. an expectation exists and no offered key satisfies it: refused, even when the stored key still works;
    4. exactly one stored line that satisfies the expectation (or none exists) and is still offered: nothing to do;
    5. nothing stored: store the chosen key;
    6. otherwise: replace the stored key by the chosen one.

    The chosen key is only computed for rules 5 and 6, so an ambiguous trust-on-first-use choice never blocks
    rule 4.
    """
    basis = expectation.basis
    if len(stored) > 1:
        return Refused("several entries are stored for this access point; remove the extra lines by hand", basis)
    if not offered:
        return Refused("no host key offered", basis)
    if expectation.fingerprints and not any(_satisfies(c, expectation) for c in offered):
        return Refused(f"none of the {len(offered)} offered host keys matches the {basis}", basis)
    if stored:
        held = stored[0]
        if _satisfies(_stored_candidate(held), expectation) and any(_same_key(held, c) for c in offered):
            return AlreadyStored(_stored_candidate(held).sha256.text, basis)
    try:
        chosen = select_candidate(offered, expectation)
    except HostKeyTrustError as exc:
        return Refused(str(exc), basis)
    if not stored:
        return StoreNew(chosen, basis)
    return Replace(stored[0], chosen, basis)


def inspect_access_point(subject: TrustSubject, writer: KnownHostsWriter, scan: Keyscan) -> TrustDecision:
    """Everything up to the decision: address check, expectation, the keyscan (one connection for the stored
    key's type when that key is trusted already, the full scan otherwise) and `plan_trust`."""
    if not is_allowed_address(subject.address, subject.allow_public_address):
        # The same rule as the scan: a controller-supplied address must not make the tool probe the internet.
        return Refused(f"address {subject.address} is not used for SSH")
    try:
        controller = (
            normalize_fingerprint(subject.controller_fingerprint)
            if subject.controller_fingerprint is not None
            else None
        )
    except ValueError:
        return Refused("the controller reports a host-key fingerprint in an unknown form")
    try:
        expectation = expected_fingerprint(subject.config_pin, controller)
        stored = writer.entries_for(subject.alias)
        if len(stored) == 1 and _satisfies(_stored_candidate(stored[0]), expectation):
            quick = scan(subject.address, subject.port, stored[0].key_type)
            if any(_same_key(stored[0], c) for c in quick):
                return AlreadyStored(_stored_candidate(stored[0]).sha256.text, expectation.basis)
        offered = scan(subject.address, subject.port, None)
    except HostKeyTrustError as exc:
        return Refused(str(exc))
    return plan_trust(stored, offered, expectation)


def apply_decision(
    subject: TrustSubject, decision: TrustDecision, writer: KnownHostsWriter, policy: TrustPolicy
) -> TrustResult:
    name = subject.name
    label = f"{subject.site_id}: {name}"
    match decision:
        case Refused(reason, basis):
            return TrustResult(ap_name=name, outcome=TrustOutcome.FAILED, basis=basis, detail=reason)
        case AlreadyStored(fingerprint, basis):
            return TrustResult(ap_name=name, outcome=TrustOutcome.ALREADY_STORED, basis=basis, detail=fingerprint)
        case StoreNew(chosen, basis):
            fingerprint = chosen.sha256.text
            if basis is not TrustBasis.UNVERIFIED:
                accepted = policy.assume_yes or policy.confirm(
                    Prompt(
                        kind=PromptKind.NEW,
                        text=f"{label}: store host key {fingerprint} (matches the {basis})?",
                        new_fingerprint=fingerprint,
                    )
                )
            else:
                accepted = policy.accept_unverified or policy.confirm(
                    Prompt(
                        kind=PromptKind.NEW,
                        text=f"{label}: nothing to verify {fingerprint} against — store it on first use anyway?",
                        new_fingerprint=fingerprint,
                    )
                )
            if not accepted:
                return TrustResult(ap_name=name, outcome=TrustOutcome.DECLINED, basis=basis, detail=fingerprint)
            return _write(name, basis, fingerprint, lambda: writer.add(chosen.entry(subject.alias)))
        case Replace(old, chosen, basis):
            old_fingerprint = _stored_candidate(old).sha256.text
            fingerprint = chosen.sha256.text
            detail = f"{old_fingerprint} -> {fingerprint}"
            verified = basis is not TrustBasis.UNVERIFIED
            accepted = (verified and policy.assume_yes) or policy.confirm(
                Prompt(
                    kind=PromptKind.REPLACE,
                    text=(
                        f"{label}: the stored host key {old_fingerprint} is not the key the access point offers "
                        f"({basis}): {fingerprint} — replace it?"
                    ),
                    new_fingerprint=fingerprint,
                )
            )
            if not accepted:
                return TrustResult(ap_name=name, outcome=TrustOutcome.DECLINED, basis=basis, detail=detail)
            return _write(
                name, basis, detail, lambda: writer.replace(chosen.entry(subject.alias), old), TrustOutcome.REPLACED
            )


def _write(
    name: str,
    basis: TrustBasis,
    detail: str,
    action: Callable[[], None],
    outcome: TrustOutcome = TrustOutcome.STORED,
) -> TrustResult:
    try:
        action()
    except HostKeyTrustError as exc:
        return TrustResult(ap_name=name, outcome=TrustOutcome.FAILED, basis=basis, detail=str(exc))
    return TrustResult(ap_name=name, outcome=outcome, basis=basis, detail=detail)


def subject_for(site_id: str, site: SiteConfig, origin: str, ap: AccessPoint, port: int = SSH_PORT) -> TrustSubject:
    ssh = site.ssh
    return TrustSubject(
        site_id=site_id,
        name=ap.name,
        alias=host_key_alias(origin, site_id, ap.mac),
        address=ap.ip,
        port=port,
        allow_public_address=ssh.allow_public_ap_addresses if ssh is not None else False,
        config_pin=ssh.host_keys.get(ap.mac) if ssh is not None else None,
        controller_fingerprint=ap.ssh_host_key_fingerprint,
    )


def trust_host_keys(
    api: ControllerApi,
    loaded: LoadedConfig,
    writer: KnownHostsWriter,
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
    names = tuple(dict.fromkeys(only)) if only else scan_members(site_config)
    if not names:
        raise ConfigError(f"sites.{site.id}.neighbors", "no access points take part in a neighbour pair")
    origin = controller_origin(loaded.config.controller)
    policy = TrustPolicy(assume_yes=assume_yes, accept_unverified=accept_unverified, confirm=confirm)
    results: list[TrustResult] = []
    for name in names:
        ap = by_name.get(name)
        if ap is None:
            results.append(TrustResult(ap_name=name, outcome=TrustOutcome.NOT_ON_CONTROLLER, basis=None, detail=""))
            continue
        subject = subject_for(site.id, site_config, origin, ap)
        results.append(apply_decision(subject, inspect_access_point(subject, writer, scan), writer, policy))
    return TrustReport(site_id=site.id, results=tuple(results))


def subject_for_target(target: ScanTarget, ap: AccessPoint, site: SiteConfig) -> TrustSubject:
    ssh = site.ssh
    return TrustSubject(
        site_id=target.site_id,
        name=target.ap_name,
        alias=target.host_key_alias,
        address=target.address,
        port=target.port,
        allow_public_address=target.allow_public_address,
        config_pin=ssh.host_keys.get(target.ap_mac) if ssh is not None else None,
        controller_fingerprint=ap.ssh_host_key_fingerprint,
    )


def check_host_keys(
    subjects: Sequence[TrustSubject],
    writer: KnownHostsWriter,
    policy: TrustPolicy,
    report: Callable[[TrustResult], None],
    scan: Keyscan = default_keyscan,
) -> None:
    """The questions a scanning `run` asks before its first scan. Every result except "already stored" is
    reported; a refusal or a decline changes nothing and the scan then reports the access point as it always did."""
    for subject in subjects:
        result = apply_decision(subject, inspect_access_point(subject, writer, scan), writer, policy)
        if result.outcome is not TrustOutcome.ALREADY_STORED:
            report(result)
