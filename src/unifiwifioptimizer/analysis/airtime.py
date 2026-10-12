"""Airtime figures per radio as information: utilisation, retries, satisfaction, clients. No thresholds —
no sourced figure separates a busy radio from a troubled one, so the values are shown, never judged."""

from dataclasses import dataclass

from unifiwifioptimizer.domain.models import AccessPoint, Band


@dataclass(frozen=True, slots=True, kw_only=True)
class AirtimeSummary:
    utilisation_pct: int | None
    self_rx_pct: int | None
    self_tx_pct: int | None
    tx_retries_pct: float | None
    satisfaction_pct: int | None
    client_count: int | None

    @property
    def empty(self) -> bool:
        return all(
            v is None
            for v in (
                self.utilisation_pct,
                self.self_rx_pct,
                self.self_tx_pct,
                self.tx_retries_pct,
                self.satisfaction_pct,
                self.client_count,
            )
        )


def airtime_of(ap: AccessPoint, band: Band) -> AirtimeSummary | None:
    stats = ap.stats(band)
    if stats is None:
        return None
    summary = AirtimeSummary(
        utilisation_pct=stats.channel_utilisation_pct,
        self_rx_pct=stats.self_rx_utilisation_pct,
        self_tx_pct=stats.self_tx_utilisation_pct,
        tx_retries_pct=stats.tx_retries_pct,
        satisfaction_pct=stats.satisfaction_pct,
        client_count=stats.client_count,
    )
    return None if summary.empty else summary
