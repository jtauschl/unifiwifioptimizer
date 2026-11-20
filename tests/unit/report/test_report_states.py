"""What the default report says for each state in which the evidence is missing, empty or skipped: the exact rows,
because a phrase check passes for any other wrong wording."""

from collections.abc import Callable
from dataclasses import replace

import pytest

from tests.unit.analysis.builders import (
    ap_named,
    band_scan,
    golden_input,
    scan_pass,
    with_ap,
    with_radio,
    with_stats,
)
from unifiwifioptimizer.analysis.inputs import SiteAnalysisInput
from unifiwifioptimizer.analysis.site_analyzer import analyze_site
from unifiwifioptimizer.domain.analysis import BandTxOutcome
from unifiwifioptimizer.domain.models import Band
from unifiwifioptimizer.domain.report import ScanState
from unifiwifioptimizer.domain.scan import BandScanStatus, NoScanConfigured, SiteScan
from unifiwifioptimizer.report.text import MISSING_PRECONDITION, render_overview, render_report

TX = "Transmit Power"
MIN_RSSI = "Minimum RSSI"


def overview_lines(inp: SiteAnalysisInput) -> list[str]:
    return render_overview(analyze_site(inp), width=None).splitlines()


def band_rows(inp: SiteAnalysisInput, ap: str, band: Band) -> dict[str, str]:
    """The `Transmit Power` and `Minimum RSSI` rows of one band of one access point, each with its wait line."""
    lines = overview_lines(inp)
    start = next(i for i, line in enumerate(lines) if line.startswith("  AP ") and line.split()[1] == ap)
    end = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("  AP ")), len(lines))
    section = lines[start:end]
    first = section.index(f"  {band.label}")
    rows: dict[str, str] = {}
    label = ""
    for line in section[first + 1 :]:
        if line.startswith("  ") and not line.startswith("    "):
            break
        for known in (TX, MIN_RSSI):
            if line[6:].startswith(known):
                label = known
                rows[label] = line
        if label and line.startswith("        ") and rows[label] != line:
            rows[label] += "\n" + line
    return rows


def with_two_failed_scans(inp: SiteAnalysisInput) -> SiteAnalysisInput:
    assert isinstance(inp.scan, SiteScan)
    failed = tuple(scan_pass(two=band_scan(Band.GHZ_2, (), BandScanStatus.FAILED)) for _ in range(3))
    scans = tuple(replace(s, passes=failed) if s.ap_name in ("AP-1", "AP-2") else s for s in inp.scan.scans)
    return replace(inp, scan=replace(inp.scan, scans=scans))


def with_changed_radio(inp: SiteAnalysisInput, ap: str, band: Band, **overrides: object) -> SiteAnalysisInput:
    changed = with_radio(ap_named(inp.snapshot, ap), band, **overrides)
    return replace(inp, snapshot=with_ap(inp.snapshot, changed))


def without_neighbour_pairs(inp: SiteAnalysisInput) -> SiteAnalysisInput:
    return replace(inp, scan=NoScanConfigured(), neighbours={})


def in_dfs_check(inp: SiteAnalysisInput) -> SiteAnalysisInput:
    waiting = with_stats(ap_named(inp.snapshot, "AP-2"), Band.GHZ_5, state="DFS_WAIT")
    return replace(inp, snapshot=with_ap(inp.snapshot, waiting))


def outside_the_pairs(inp: SiteAnalysisInput) -> SiteAnalysisInput:
    return replace(inp, neighbours={"AP-1": frozenset({"AP-2"}), "AP-2": frozenset({"AP-3"})})


def peer_without_the_band(inp: SiteAnalysisInput) -> SiteAnalysisInput:
    five_only = replace(
        ap_named(inp.snapshot, "AP-4"),
        radios=tuple(r for r in ap_named(inp.snapshot, "AP-4").radios if r.band is Band.GHZ_5),
    )
    return replace(inp, snapshot=with_ap(inp.snapshot, five_only), neighbours={"AP-3": frozenset({"AP-4"})})


def without_effective_power(inp: SiteAnalysisInput, ap: str = "AP-3") -> SiteAnalysisInput:
    stats = with_stats(ap_named(inp.snapshot, ap), Band.GHZ_2, observed_tx_dbm=None)
    return replace(inp, snapshot=with_ap(inp.snapshot, stats))


# (state, how to build it, access point, band, transmit-power row, minimum-RSSI row)
CASES: list[tuple[str, Callable[[SiteAnalysisInput], SiteAnalysisInput], str, Band, str, str]] = [
    (
        "scan skipped",
        lambda inp: golden_input(skip_scan=True),
        "AP-1",
        Band.GHZ_2,
        "Auto (effective 17 dBm, EIRP 20 dBm); no scan ran",
        "disabled; no scan ran",
    ),
    (
        "no neighbour pairs",
        without_neighbour_pairs,
        "AP-1",
        Band.GHZ_2,
        "Auto (effective 17 dBm, EIRP 20 dBm); no configured neighbour on this band",
        "disabled; no configured neighbour on this band",
    ),
    (
        "access point outside the pairs",
        outside_the_pairs,
        "AP-4",
        Band.GHZ_2,
        "Custom, 10 dBm (effective 10 dBm, EIRP 14 dBm); no configured neighbour on this band",
        "disabled; no configured neighbour on this band",
    ),
    (
        "peer without a radio on the band",
        peer_without_the_band,
        "AP-3",
        Band.GHZ_2,
        "Custom, 11 dBm (effective 11 dBm, EIRP 14 dBm); no configured neighbour on this band",
        "disabled; no configured neighbour on this band",
    ),
    (
        "radio in its DFS availability check",
        in_dfs_check,
        "AP-2",
        Band.GHZ_5,
        "Custom, 24 dBm (effective 18 dBm, EIRP 23 dBm); radio in its DFS channel availability check",
        "disabled; radio in its DFS channel availability check",
    ),
    (
        "power values missing (row 4)",
        lambda inp: with_changed_radio(inp, "AP-3", Band.GHZ_2, max_tx_dbm=None),
        "AP-3",
        Band.GHZ_2,
        "Custom, 11 dBm (effective 11 dBm, EIRP 14 dBm); the controller's power values are missing or outside "
        "the radio's range",
        "disabled (if enabled: -75 dBm on the uplink)",
    ),
    (
        "no effective power, neighbours present",
        without_effective_power,
        "AP-3",
        Band.GHZ_2,
        "Custom, 11 dBm (effective unavailable); "
        "the controller's power values are missing or outside the radio's range",
        "disabled; the controller reports no effective power",
    ),
    (
        "no effective power, outside the pairs: the missing neighbour is named first",
        lambda inp: without_effective_power(outside_the_pairs(inp), "AP-4"),
        "AP-4",
        Band.GHZ_2,
        "Custom, 10 dBm (effective unavailable); "
        "the controller's power values are missing or outside the radio's range",
        "disabled; no configured neighbour on this band",
    ),
    (
        "no neighbour could be evaluated (row 7)",
        with_two_failed_scans,
        "AP-1",
        Band.GHZ_2,
        "Auto (effective 17 dBm, EIRP 20 dBm); no configured neighbour could be evaluated",
        "disabled (if enabled: -81 dBm on the uplink)",
    ),
]


@pytest.mark.parametrize(
    ("state", "build", "ap", "band", "tx_value", "min_value"), CASES, ids=[case[0] for case in CASES]
)
def test_a_band_without_a_recommendation_states_what_it_lacks_and_the_minimum_rssi_state_it_has(
    state: str,
    build: Callable[[SiteAnalysisInput], SiteAnalysisInput],
    ap: str,
    band: Band,
    tx_value: str,
    min_value: str,
) -> None:
    rows = band_rows(build(golden_input()), ap, band)
    assert rows[TX] == f"    · {TX:<34} {tx_value}", state
    assert rows[MIN_RSSI] == f"    · {MIN_RSSI:<34} {min_value}", state


def test_every_outcome_that_can_reach_a_band_row_without_a_recommendation_has_its_precondition_text() -> None:
    # `OFFLINE` is the one outcome without a text: an offline access point reports no bands.
    expected = {o for o in BandTxOutcome if not o.carries_recommendation} - {BandTxOutcome.OFFLINE}
    assert set(MISSING_PRECONDITION) == expected


def test_an_offline_access_point_carries_no_bands() -> None:
    inp = golden_input()
    offline = replace(ap_named(inp.snapshot, "AP-2"), state_code=0)
    report = analyze_site(replace(inp, snapshot=with_ap(inp.snapshot, offline)))
    assert next(ap for ap in report.aps if ap.name == "AP-2").bands == ()


def test_a_site_without_neighbour_pairs_says_that_no_scan_ran_and_never_a_clean_verdict() -> None:
    inp = replace(without_neighbour_pairs(golden_input()), wlan_profiles={})
    assert analyze_site(inp).scan.state is ScanState.NOT_CONFIGURED
    text = "\n".join(overview_lines(inp))
    assert "    No scan ran: RF recommendations need neighbour pairs (docs/WALKTHROUGH.md section 3)." in text
    assert "0/0" not in text and "AP beacon readings" not in text
    assert "  No changes recommended in the available data; see Data quality." in text
    assert "Scan passes:                       no scan configured" in render_report(analyze_site(inp), width=None)


def test_a_scanning_site_that_scanned_nobody_names_why_instead_of_a_pass_ratio() -> None:
    inp = golden_input()
    ghosts = replace(
        inp,
        neighbours={"Ghost-1": frozenset({"Ghost-2"})},
        scan=SiteScan(site_id="default", scans=(), unknown_names=("Ghost-1", "Ghost-2")),
    )
    text = "\n".join(overview_lines(ghosts))
    assert "    No access point was scanned (2 absent from the controller)." in text
    assert "0/0" not in text and "AP beacon readings" not in text


def test_a_minimum_rssi_that_the_controller_enabled_without_a_value_is_named_as_that() -> None:
    inp = with_changed_radio(golden_input(), "AP-2", Band.GHZ_2, min_rssi_enabled=True, min_rssi_dbm=None)
    assert band_rows(inp, "AP-2", Band.GHZ_2)[MIN_RSSI] == (
        f"    ✗ {MIN_RSSI:<34} enabled, set -70 dBm (the controller sent no value)\n"
        "        provisional: re-run after the transmit-power changes are applied"
    )


def test_a_confirmed_minimum_rssi_below_a_pending_power_change_is_marked_provisional() -> None:
    inp = with_changed_radio(golden_input(), "AP-2", Band.GHZ_2, min_rssi_enabled=True, min_rssi_dbm=-70)
    assert band_rows(inp, "AP-2", Band.GHZ_2)[MIN_RSSI] == (
        f"    ✓ {MIN_RSSI:<34} enabled, -70 dBm\n"
        "        provisional: re-run after the transmit-power changes are applied"
    )
