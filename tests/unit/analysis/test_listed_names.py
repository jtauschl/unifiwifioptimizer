"""A sentence that lists names has a length of its own: the list is bounded by count, the advice after it is never the
part a renderer bound cuts. The worst case of every such sentence is derived from its pure function, because the
analysis cannot build it (a clique of eleven access points does not return within a test's time)."""

import re
from collections.abc import Callable
from dataclasses import replace

import pytest

from unifiwifioptimizer.adapters.unifi.validate import MAX_NAME_BYTES
from unifiwifioptimizer.analysis import listing
from unifiwifioptimizer.analysis.channels import (
    ChannelAnalysis,
    _auto_overlap_text,
    _configured_overlap_text,
    _free_hint,
    _heard_cochannel_text,
    _overlap_under_ai_text,
    _reuse_infeasible_text,
    _reuse_remedy,
    _reuse_supply,
    analyse_channels,
)
from unifiwifioptimizer.analysis.listing import MAX_LISTED_NAMES, listed
from unifiwifioptimizer.analysis.neighbors import PeerReading
from unifiwifioptimizer.analysis.site_analyzer import _shared_name_text, analyze_site
from unifiwifioptimizer.analysis.txpower import (
    BandTxResult,
    _coverage_gap_text,
    _no_neighbour_evaluable_text,
    _no_sighting_reason,
    _not_evaluated_text,
    _reason_text,
    _reduction_blocked_text,
    _too_strong_text,
)
from unifiwifioptimizer.domain.analysis import MissingReason
from unifiwifioptimizer.domain.models import Band, ChannelAiSettings, SiteSnapshot
from unifiwifioptimizer.report.text import SENTENCE_MAX

from .builders import (
    ap_named,
    fixture,
    fixture_snapshot,
    golden_input,
    hears,
    site_scan,
    with_ap,
    with_radio,
    with_stats,
)
from .test_txpower import custom, measured, missing, run

NAME = "n" * MAX_NAME_BYTES
MANY = MAX_LISTED_NAMES + 1000
LONGEST_REASON = max(MissingReason, key=lambda reason: len(reason.words))
# The largest free-candidate list the channel model offers: 28 blocks on 5 GHz, written with three digits each.
FREE_HINT = _free_hint([177] * 28)


def names(count: int) -> list[str]:
    return [f"{index:04d}-{NAME}"[:MAX_NAME_BYTES] for index in range(count)]


def cells(count: int) -> list[PeerReading]:
    return [
        PeerReading(
            peer=name,
            band=Band.GHZ_5,
            rssi_dbm=None,
            source=None,
            samples=0,
            reason=LONGEST_REASON,
        )
        for name in names(count)
    ]


# Each entry builds the sentence from `count` names (or cells) and names the words of its advice, which must end it.
Producer = Callable[[int], str]
PRODUCERS: dict[str, tuple[Producer, str]] = {
    "overlap under Channel AI": (
        lambda n: _overlap_under_ai_text(165, names(n)),
        "pin channels or add exclusions",
    ),
    "auto overlap": (lambda n: _auto_overlap_text(names(n)), "pin channels"),
    "configured overlap": (
        lambda n: _configured_overlap_text(165, 160, names(n), FREE_HINT),
        FREE_HINT,
    ),
    "heard co-channel": (lambda n: _heard_cochannel_text(names(n), FREE_HINT), FREE_HINT),
    "reuse infeasible, 5 GHz": (
        lambda n: _reuse_infeasible_text(names(n), _reuse_supply(Band.GHZ_5, 28, 160), 1000, _reuse_remedy(Band.GHZ_5)),
        "reduce the width or accept co-channel reuse",
    ),
    "reuse infeasible, 2.4 GHz": (
        lambda n: _reuse_infeasible_text(names(n), _reuse_supply(Band.GHZ_2, 1, 20), 1000, _reuse_remedy(Band.GHZ_2)),
        "accept co-channel reuse",
    ),
    "coverage gap": (
        lambda n: _coverage_gap_text(
            "-100 dBm, within rounding of the access point's reported limit -100 dBm", names(n)
        ),
        "then reposition or add an access point",
    ),
    "no sighting": (lambda n: _no_sighting_reason(NAME, names(n)), " more"),
    "too strong": (
        lambda n: _too_strong_text(-100, names(n), NAME, 1000),
        "or accept the overlap",
    ),
    "no neighbour evaluable": (lambda n: _no_neighbour_evaluable_text(cells(n)), ")"),
    "reduction blocked": (lambda n: _reduction_blocked_text(cells(n)), ")"),
    "not evaluated": (lambda n: _not_evaluated_text(cells(n)), ")"),
    "shared name": (
        lambda n: _shared_name_text([f"02:00:00:00:{index // 256:02x}:{index % 256:02x}" for index in range(n)]),
        "none of them is analysed — rename them",
    ),
}


def test_listed_names_stop_at_the_count_and_state_how_many_more() -> None:
    assert listed([]) == ""
    assert listed(["a"]) == "a"
    five = [f"AP-{i}" for i in range(MAX_LISTED_NAMES)]
    assert listed(five) == ", ".join(five)
    assert listed([*five, "AP-x"]) == ", ".join(five) + " and 1 more"
    assert listed([*five, *("AP-x",) * 1000]) == ", ".join(five) + " and 1000 more"


def test_the_count_is_the_largest_that_fits() -> None:
    assert MAX_LISTED_NAMES == 5


@pytest.mark.parametrize("label", PRODUCERS)
def test_a_sentence_with_a_thousand_names_is_below_the_sentence_bound_and_keeps_its_advice(label: str) -> None:
    build, advice = PRODUCERS[label]
    sentence = build(MANY)
    assert len(sentence) < SENTENCE_MAX, len(sentence)
    assert sentence.endswith(advice)
    assert f"and {MANY - MAX_LISTED_NAMES} more" in sentence


@pytest.mark.parametrize("label", PRODUCERS)
def test_the_sentence_with_five_names_fits_the_bound(label: str) -> None:
    build, _ = PRODUCERS[label]
    assert len(build(MAX_LISTED_NAMES)) <= SENTENCE_MAX


def test_the_longest_sentence_would_not_fit_with_six_names(monkeypatch: pytest.MonkeyPatch) -> None:
    longest = max(PRODUCERS.items(), key=lambda item: len(item[1][0](MANY)))
    monkeypatch.setattr(listing, "MAX_LISTED_NAMES", MAX_LISTED_NAMES + 1)
    assert len(longest[1][0](MANY)) > SENTENCE_MAX, longest[0]


def test_the_reasons_of_the_neighbour_cells_are_listed_by_count() -> None:
    text = _reason_text(cells(MANY))
    assert text.count(LONGEST_REASON.words) == MAX_LISTED_NAMES
    assert text.endswith(f"and {MANY - MAX_LISTED_NAMES} more")


# --- the channel analysis lists its peers through the same function ----------------------------------------------


def crowd(count: int, *, auto: bool = False) -> SiteSnapshot:
    """The fixture site plus `count` clones of AP-2, all on 2.4 GHz channel 6, named PEER-0, PEER-1, ..."""
    snapshot = fixture_snapshot()
    base = ap_named(snapshot, "AP-2")
    made = []
    for index in range(count):
        clone = replace(
            base,
            name=f"PEER-{index}",
            mac=f"02:00:00:00:10:{index:02x}",
            vaps=tuple(replace(v, bssid=f"02:00:00:01:{index:02x}:{n:02x}") for n, v in enumerate(base.vaps)),
        )
        clone = with_radio(clone, Band.GHZ_2, channel=None if auto else 6)
        made.append(with_stats(clone, Band.GHZ_2, channel=6))
    return replace(snapshot, access_points=(*snapshot.access_points, *made))


def peers_of(snapshot: SiteSnapshot) -> list[str]:
    return [ap.name for ap in snapshot.access_points if ap.name.startswith("PEER-")]


def channel_ai(snapshot: SiteSnapshot, *, enabled: bool) -> ChannelAiSettings:
    ai = snapshot.settings.channel_ai
    assert ai is not None
    return replace(ai, enabled=enabled)


def message_of(analysis: ChannelAnalysis, code: str, subject: str) -> str:
    return next(f.message for f in analysis.findings if f.code == code and f.subject == subject)


def test_fixed_overlap_lists_five_configured_neighbours_and_counts_the_rest() -> None:
    snapshot = crowd(8)
    fixed = with_ap(
        snapshot, with_stats(with_radio(ap_named(snapshot, "AP-2"), Band.GHZ_2, channel=6), Band.GHZ_2, channel=6)
    )
    analysis = analyse_channels(fixed, None, {"AP-2": frozenset(peers_of(fixed))}, channel_ai(fixed, enabled=False))
    message = message_of(analysis, "channel_overlap", "AP-2")
    assert "PEER-0, PEER-1, PEER-2, PEER-3, PEER-4 and 3 more" in message and "PEER-5" not in message
    assert message.endswith("free candidates: 1, 11")


def test_auto_overlap_lists_five_peers_and_counts_the_rest_with_and_without_channel_ai() -> None:
    snapshot = crowd(8, auto=True)
    adjacency = {"AP-1": frozenset(peers_of(snapshot))}
    managed = analyse_channels(snapshot, None, adjacency, channel_ai(snapshot, enabled=True))
    assert "PEER-4 and 3 more under Channel AI" in message_of(managed, "channel_ai_overlap", "AP-1")
    unmanaged = analyse_channels(snapshot, None, adjacency, channel_ai(snapshot, enabled=False))
    assert "PEER-4 and 3 more; nothing manages this layout" in message_of(unmanaged, "pin_channels", "AP-1")


def test_heard_cochannel_lists_five_access_points_and_counts_the_rest() -> None:
    snapshot = crowd(8)
    scan = site_scan(
        snapshot, {"AP-3": [hears(snapshot, "AP-3", **{name: {Band.GHZ_2: -60} for name in peers_of(snapshot)})]}
    )
    analysis = analyse_channels(snapshot, scan, {}, channel_ai(snapshot, enabled=False))
    message = message_of(analysis, "cochannel_heard", "AP-3")
    assert "by PEER-0, PEER-1, PEER-2, PEER-3, PEER-4 and 3 more: both defer to each other" in message


def test_reuse_infeasible_lists_five_access_points_and_counts_the_rest() -> None:
    snapshot = crowd(6)
    members = [*peers_of(snapshot), "AP-1", "AP-2"]
    passes = {
        scanner: [hears(snapshot, scanner, **{other: {Band.GHZ_2: -60} for other in members if other != scanner})]
        for scanner in members
    }
    analysis = analyse_channels(snapshot, site_scan(snapshot, passes), {}, channel_ai(snapshot, enabled=False))
    (advisory,) = (f for f in analysis.findings if f.code == "channel_reuse_infeasible" and f.band is Band.GHZ_2)
    assert advisory.message.startswith(
        "8 access points that hear each other (AP-1, AP-2, PEER-0, PEER-1, PEER-2 and 3 more)"
    )
    assert advisory.message.endswith("accept co-channel reuse")
    assert len(advisory.peers) == 8


def test_access_points_sharing_a_name_are_listed_by_their_macs_by_count() -> None:
    payload = fixture("stat_device.json")
    three = next(d for d in payload["data"] if d.get("name") == "AP-3")
    twins = [
        {**three, "mac": f"02:00:00:00:00:{0x70 + i:02x}", "_id": f"0000000000000000000000{0x70 + i:02x}"}
        for i in range(6)
    ]
    inp = golden_input()
    snap = fixture_snapshot(extra_devices=twins)
    report = analyze_site(replace(inp, snapshot=replace(inp.snapshot, access_points=snap.access_points)))
    duplicate = next(f for f in report.site_findings if f.code == "ap_name_duplicate")
    assert (
        "and 2 more) ; none" not in duplicate.message and "and 2 more); none of them is analysed" in duplicate.message
    )


# --- the transmit-power decision lists its names through the same function ---------------------------------------


def with_peers(kind: str, count: int) -> list[PeerReading]:
    build = {
        "both-way": lambda n: missing(n, MissingReason.NOT_SIGHTED),
        "blocking": lambda n: missing(n, LONGEST_REASON),
    }
    return [build[kind](name) for name in names(count)]


def messages(result: BandTxResult) -> dict[str, str]:
    found = {f.code: f.message for f in result.findings}
    if result.recommendation is not None:
        found["recommendation"] = result.recommendation.reason
    return found


TX_SCENARIOS: dict[str, tuple[Callable[[int], BandTxResult], str, str]] = {
    "coverage gap at the maximum": (
        lambda n: run(custom("AP-2", Band.GHZ_5, current=18, configured=24, max_tx=24), with_peers("both-way", n)),
        "coverage_gap",
        "then reposition or add an access point",
    ),
    "no sighting below the maximum": (
        lambda n: run(custom("AP-3", Band.GHZ_5, 15, max_tx=23), with_peers("both-way", n)),
        "recommendation",
        " more",
    ),
    "no neighbour evaluable": (
        lambda n: run(custom("AP-3", Band.GHZ_5, 15, max_tx=23), with_peers("blocking", n)),
        "peers_not_evaluated",
        " more)",
    ),
    "neighbours not evaluated beside a both-way miss": (
        lambda n: run(
            custom("AP-3", Band.GHZ_5, 15, max_tx=23),
            [missing("MISS", MissingReason.NOT_SIGHTED), *with_peers("blocking", n)],
        ),
        "peers_not_evaluated",
        " more)",
    ),
    "reduction blocked": (
        lambda n: run(custom("AP-3", Band.GHZ_5, 11, max_tx=23), [measured("AP-2", -50), *with_peers("blocking", n)]),
        "reduction_blocked",
        " more)",
    ),
    "reduction blocked after an ordinary reduction": (
        lambda n: run(custom("AP-3", Band.GHZ_5, 15, max_tx=23), [measured("AP-2", -58), *with_peers("blocking", n)]),
        "reduction_blocked",
        " more)",
    ),
    "too strong at the minimum": (
        lambda n: run(
            custom("AP-3", Band.GHZ_5, current=11, configured=11, max_tx=23),
            [measured(name, -50) for name in names(n)],
        ),
        "too_strong_at_minimum",
        "or accept the overlap",
    ),
}


@pytest.mark.parametrize("label", TX_SCENARIOS)
def test_the_transmit_power_decision_lists_a_thousand_neighbours_by_count(label: str) -> None:
    scenario, key, ending = TX_SCENARIOS[label]
    message = messages(scenario(MANY))[key]
    assert len(message) < SENTENCE_MAX and message.endswith(ending), message[-120:]
    assert f"and {MANY - MAX_LISTED_NAMES} more" in message
    assert re.findall(r"(\d{4})-n", message) == [f"{index:04d}" for index in range(MAX_LISTED_NAMES)]
