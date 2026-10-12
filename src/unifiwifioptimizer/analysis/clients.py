"""Associated clients against each radio's recommended Minimum RSSI — the same uplink reference the
controller would apply — as counts per radio. Sightings without an access point, band or signal are
counted once per site. No identifier is read or kept."""

from collections import Counter
from dataclasses import dataclass

from unifiwifioptimizer.domain.models import Band, ClientSighting, Mac
from unifiwifioptimizer.domain.report import Finding, Severity


@dataclass(frozen=True, slots=True, kw_only=True)
class ClientSummary:
    total: int
    below_min_rssi: int
    weakest_dbm: int | None


def clients_of(ap_mac: Mac, band: Band, clients: tuple[ClientSighting, ...], min_rssi_dbm: int) -> ClientSummary | None:
    population = [c for c in clients if c.ap_mac == ap_mac and c.band is band and c.signal_dbm is not None]
    if not population:
        return None
    signals = [c.signal_dbm for c in population if c.signal_dbm is not None]
    return ClientSummary(
        total=len(signals), below_min_rssi=sum(1 for s in signals if s < min_rssi_dbm), weakest_dbm=min(signals)
    )


def unassignable(clients: tuple[ClientSighting, ...], known_aps: frozenset[Mac]) -> Counter[str]:
    """Why sightings could not be placed on a radio: unknown access point, or no signal."""
    reasons: Counter[str] = Counter()
    for client in clients:
        if client.ap_mac not in known_aps:
            reasons["access point not in the snapshot"] += 1
        elif client.signal_dbm is None:
            reasons["no signal reported"] += 1
    return reasons


def unassignable_finding(site_id: str, reasons: Counter[str]) -> Finding | None:
    if not reasons:
        return None
    text = "; ".join(f"{count} {reason}" for reason, count in sorted(reasons.items()))
    return Finding(
        severity=Severity.INFO,
        code="clients_unassignable",
        message=f"client sightings not placed on a radio: {text}",
        subject=site_id,
    )
