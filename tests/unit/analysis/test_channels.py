"""Channel checks: in-use geometry from the statistics, the four Channel AI x mode cases, overlap and
co-channel advisories with free candidates, reuse feasibility over the union of the heard and the configured
graph, blacklist, foreign counts without names."""

from dataclasses import replace

from unifiwifioptimizer.analysis.channels import (
    ChannelAnalysis,
    analyse_channels,
    candidate_set,
    colour_count,
    components,
    foreign_networks,
    free_candidates,
    geometry_of,
)
from unifiwifioptimizer.domain.models import Band, ChannelAiSettings
from unifiwifioptimizer.domain.report import Finding, Severity
from unifiwifioptimizer.rf.channels import CLEAN_2G_CHANNELS

from .builders import (
    ap_named,
    band_scan,
    fixture_snapshot,
    foreign,
    hears,
    scan_pass,
    site_scan,
    with_ap,
    with_radio,
    with_stats,
)

SNAP = fixture_snapshot()
_AI = SNAP.settings.channel_ai
assert _AI is not None
AI: ChannelAiSettings = _AI
AI_OFF = replace(AI, enabled=False)
PAIR = {"AP-1": frozenset({"AP-2"})}


def by_code(analysis: ChannelAnalysis, code: str) -> list[Finding]:
    return [f for f in analysis.findings if f.code == code]


def test_geometry_comes_from_the_statistics_and_reports_a_moved_fixed_radio() -> None:
    auto = geometry_of(ap_named(SNAP, "AP-1"), Band.GHZ_2)
    assert auto is not None and (auto.channel, auto.auto, auto.configured_channel, auto.moved) == (6, True, None, False)
    fixed = geometry_of(ap_named(SNAP, "AP-2"), Band.GHZ_5)
    assert fixed is not None and (fixed.channel, fixed.width_mhz, fixed.extension_channel, fixed.auto) == (
        60,
        80,
        1,
        False,
    )
    moved = geometry_of(with_stats(ap_named(SNAP, "AP-2"), Band.GHZ_5, channel=100), Band.GHZ_5)
    assert moved is not None and moved.moved and moved.channel == 100
    analysis = analyse_channels(
        with_ap(SNAP, with_stats(ap_named(SNAP, "AP-2"), Band.GHZ_5, channel=100)), None, {}, AI
    )
    (info,) = by_code(analysis, "channel_moved")
    assert info.severity is Severity.INFO and "configured channel 60, in use 100" in info.message


def test_fixed_radios_overlapping_get_an_advisory_with_free_candidates() -> None:
    # AP-2 and AP-3 both fixed; move AP-3's 2.4 GHz radio onto channel 1 next to AP-2 (channel 1).
    snap = with_ap(SNAP, with_stats(with_radio(ap_named(SNAP, "AP-3"), Band.GHZ_2, channel=1), Band.GHZ_2, channel=1))
    analysis = analyse_channels(snap, None, {"AP-2": frozenset({"AP-3"})}, AI_OFF)
    overlaps = by_code(analysis, "channel_overlap")
    assert [(f.subject, f.peers) for f in overlaps] == [("AP-2", ("AP-3",)), ("AP-3", ("AP-2",))]
    assert overlaps[0].severity is Severity.ADVISORY and "free candidates: 6, 11" in overlaps[0].message
    # The same pair under Channel AI with fixed radios still gets the advisory: Channel AI does not manage them.
    assert len(by_code(analyse_channels(snap, None, {"AP-2": frozenset({"AP-3"})}, AI), "channel_overlap")) == 2


def test_auto_radios_under_channel_ai_get_an_info_and_without_it_a_pin_advisory() -> None:
    # Make AP-2's 2.4 GHz radio auto on channel 6, the same as AP-1 (auto, 6).
    auto_two = with_stats(with_radio(ap_named(SNAP, "AP-2"), Band.GHZ_2, channel=None), Band.GHZ_2, channel=6)
    snap = with_ap(SNAP, auto_two)
    managed = analyse_channels(snap, None, PAIR, AI)
    infos = by_code(managed, "channel_ai_overlap")
    assert [(f.subject, f.peers, f.severity) for f in infos] == [
        ("AP-1", ("AP-2",), Severity.INFO),
        ("AP-2", ("AP-1",), Severity.INFO),
    ]
    assert "persists across runs" in infos[0].message and by_code(managed, "channel_overlap") == []
    unmanaged = analyse_channels(snap, None, PAIR, AI_OFF)
    pins = by_code(unmanaged, "pin_channels")
    assert [f.subject for f in pins] == ["AP-1", "AP-2"] and pins[0].severity is Severity.ADVISORY
    # A mixed pair (AP-1 auto, AP-2 fixed on 6) follows the auto side: INFO for AP-1, advisory for the fixed AP-2.
    mixed = analyse_channels(with_ap(SNAP, with_stats(ap_named(SNAP, "AP-2"), Band.GHZ_2, channel=6)), None, PAIR, AI)
    assert [f.subject for f in by_code(mixed, "channel_ai_overlap")] == ["AP-1"]
    assert [f.subject for f in by_code(mixed, "channel_overlap")] == ["AP-2"]


def test_an_excluded_access_point_is_not_managed_by_channel_ai() -> None:
    excluded = replace(AI, excluded_devices=frozenset({ap_named(SNAP, "AP-1").mac}))
    auto_two = with_stats(with_radio(ap_named(SNAP, "AP-2"), Band.GHZ_2, channel=None), Band.GHZ_2, channel=6)
    analysis = analyse_channels(with_ap(SNAP, auto_two), None, PAIR, excluded)
    assert [f.subject for f in by_code(analysis, "channel_ai_excluded")] == ["AP-1", "AP-1"]
    assert [f.subject for f in by_code(analysis, "pin_channels")] == ["AP-1"]
    assert [f.subject for f in by_code(analysis, "channel_ai_overlap")] == ["AP-2"]


def test_wide_2g_and_the_extension_channel_decide_the_2_4_ghz_overlap() -> None:
    # AP-2 on channel 1 at 40 MHz with the secondary above covers 1..9; AP-3 on channel 6 overlaps it.
    wide = with_stats(ap_named(SNAP, "AP-2"), Band.GHZ_2, width_mhz=40, extension_channel=1)
    analysis = analyse_channels(with_ap(SNAP, wide), None, {"AP-2": frozenset({"AP-3"})}, AI_OFF)
    assert [f.subject for f in by_code(analysis, "wide_2g")] == ["AP-2"]
    assert [f.subject for f in by_code(analysis, "channel_overlap")] == ["AP-2", "AP-3"]
    # With the secondary below (impossible for channel 1 in practice) the block is centred lower: no overlap with 6.
    below = with_stats(ap_named(SNAP, "AP-2"), Band.GHZ_2, width_mhz=40, extension_channel=-1)
    assert (
        by_code(analyse_channels(with_ap(SNAP, below), None, {"AP-2": frozenset({"AP-3"})}, AI_OFF), "channel_overlap")
        == []
    )


def test_blacklisted_channels_are_advisories_with_the_band_channel_width_key() -> None:
    on_blacklist = with_stats(ap_named(SNAP, "AP-2"), Band.GHZ_2, channel=3)
    (advisory,) = by_code(analyse_channels(with_ap(SNAP, on_blacklist), None, {}, AI), "channel_in_blacklist")
    assert advisory.subject == "AP-2" and "channel 3/20 MHz" in advisory.message
    wider = with_stats(ap_named(SNAP, "AP-2"), Band.GHZ_2, channel=3, width_mhz=40)
    assert by_code(analyse_channels(with_ap(SNAP, wider), None, {}, AI), "channel_in_blacklist") == []
    five = replace(AI, blacklist=AI.blacklist | {(Band.GHZ_5, 56, 20)})
    advisories = by_code(analyse_channels(SNAP, None, {}, five), "channel_in_blacklist")
    assert [(finding.subject, finding.band) for finding in advisories] == [("AP-2", Band.GHZ_5)]
    disjoint = replace(AI, blacklist=AI.blacklist | {(Band.GHZ_5, 132, 20)})
    assert by_code(analyse_channels(SNAP, None, {}, disjoint), "channel_in_blacklist") == []


def test_cochannel_heard_covers_unconfigured_pairs_at_the_cca_level() -> None:
    # AP-1 (auto 6) and AP-3 (fixed 6) are not configured neighbours; AP-3 heard AP-1 at -80 on 2.4 GHz.
    scan = site_scan(SNAP, {"AP-3": [hears(SNAP, "AP-3", **{"AP-1": {Band.GHZ_2: -80}})]})
    analysis = analyse_channels(SNAP, scan, {}, AI_OFF)
    heard = by_code(analysis, "cochannel_heard")
    assert [(f.subject, f.peers) for f in heard] == [("AP-3", ("AP-1",))]
    assert "-82 dBm" in heard[0].message and heard[0].severity is Severity.ADVISORY
    # AP-1 is auto without Channel AI: it gets the pin advisory instead of the co-channel one.
    assert [f.subject for f in by_code(analysis, "pin_channels")] == ["AP-1"]
    quiet = site_scan(SNAP, {"AP-3": [hears(SNAP, "AP-3", **{"AP-1": {Band.GHZ_2: -83}})]})
    assert by_code(analyse_channels(SNAP, quiet, {}, AI_OFF), "cochannel_heard") == []


def test_reuse_infeasible_over_the_union_graph() -> None:
    # Four APs that all hear each other on 2.4 GHz need four channels; only 1/6/11 exist.
    names = ["AP-1", "AP-2", "AP-3", "AP-4"]
    passes = {
        scanner: [hears(SNAP, scanner, **{other: {Band.GHZ_2: -60} for other in names if other != scanner})]
        for scanner in names
    }
    analysis = analyse_channels(SNAP, site_scan(SNAP, passes), {}, AI_OFF)
    (advisory,) = by_code(analysis, "channel_reuse_infeasible")
    assert advisory.peers == ("AP-1", "AP-2", "AP-3", "AP-4")
    assert advisory.message == (
        "4 access points that hear each other (AP-1, AP-2, AP-3, AP-4) cannot all get distinct channels: "
        "only 3 of the 1/6/11 channels are usable, 4 would be needed; accept co-channel reuse"
    )
    assert analysis.reuse_infeasible[Band.GHZ_2] == (frozenset(names),)
    # A triangle plus a pendant is 3-colourable: no advisory.
    chain = {"AP-1": frozenset({"AP-2", "AP-3"}), "AP-2": frozenset({"AP-3"}), "AP-4": frozenset({"AP-3"})}
    assert by_code(analyse_channels(SNAP, None, chain, AI_OFF), "channel_reuse_infeasible") == []


def test_candidate_sets_and_colour_counts_follow_the_controller_lists() -> None:
    assert (
        candidate_set(Band.GHZ_2, AI) == frozenset({1, 6, 11}) and candidate_set(Band.GHZ_2, None) == CLEAN_2G_CHANNELS
    )
    assert candidate_set(Band.GHZ_5, None) is None and candidate_set(Band.GHZ_5, replace(AI, channels={})) is None
    assert (
        colour_count(Band.GHZ_2, frozenset({1, 6, 11}), 20) == 3
        and colour_count(Band.GHZ_2, frozenset({1, 6, 11}), 40) == 1
    )
    # The fixture's 5 GHz list 36..128 holds four 80 MHz blocks and two 160 MHz blocks.
    listed = candidate_set(Band.GHZ_5, AI)
    assert listed is not None
    assert colour_count(Band.GHZ_5, listed, 80) == 4
    assert colour_count(Band.GHZ_5, listed, 160) == 2
    assert components({"a": frozenset({"b"}), "b": frozenset({"a"}), "c": frozenset()}) == [
        frozenset({"a", "b"}),
        frozenset({"c"}),
    ]


def test_free_candidates_avoid_every_taken_block() -> None:
    taken = [
        g
        for g in (geometry_of(ap_named(SNAP, "AP-2"), Band.GHZ_5), geometry_of(ap_named(SNAP, "AP-4"), Band.GHZ_5))
        if g is not None
    ]
    listed = candidate_set(Band.GHZ_5, AI)
    assert listed is not None
    free = free_candidates(Band.GHZ_5, taken, listed, 80)
    # AP-2 occupies 52..64, AP-4 36..48: the free 80 MHz blocks are 100..112 and 116..128.
    assert free == [100, 104, 108, 112, 116, 120, 124, 128]


def test_foreign_networks_are_counted_without_names() -> None:
    passes = {
        "AP-3": [
            scan_pass(
                two=band_scan(
                    Band.GHZ_2,
                    (
                        foreign(Band.GHZ_2, -50, 6, 1),
                        foreign(Band.GHZ_2, -84, 1, 2),
                        hears(SNAP, "AP-3", **{"AP-1": {Band.GHZ_2: -70}}).bands[0].readings[0],
                    ),
                )
            ),
            scan_pass(two=band_scan(Band.GHZ_2, (foreign(Band.GHZ_2, -55, 6, 1),))),
        ]
    }
    summary = foreign_networks(ap_named(SNAP, "AP-3"), Band.GHZ_2, site_scan(SNAP, passes), SNAP)
    assert summary is not None and (summary.count, summary.strongest_dbm, summary.overlapping_count) == (2, -50, 1)
    assert foreign_networks(ap_named(SNAP, "AP-3"), Band.GHZ_5, site_scan(SNAP, passes), SNAP) is None


def test_a_foreign_bss_overlaps_by_the_radio_block_not_by_a_frequency_distance() -> None:
    # An 80 MHz radio on 44 occupies 36-48: a foreign primary on 40 overlaps, one on 52 (40 MHz away) does not.
    wide = with_ap(SNAP, with_stats(ap_named(SNAP, "AP-1"), Band.GHZ_5, channel=44, width_mhz=80))
    passes = {
        "AP-1": [
            scan_pass(
                five=band_scan(
                    Band.GHZ_5,
                    (
                        foreign(Band.GHZ_5, -60, 40, 1),
                        foreign(Band.GHZ_5, -50, 52, 2),
                        foreign(Band.GHZ_5, -70, 149, 3),
                    ),
                )
            )
        ]
    }
    summary = foreign_networks(ap_named(wide, "AP-1"), Band.GHZ_5, site_scan(wide, passes), wide)
    assert summary is not None and (summary.count, summary.overlapping_count) == (3, 1)


def test_an_offline_access_point_has_no_geometry_in_the_analysis() -> None:
    offline = with_ap(SNAP, replace(ap_named(SNAP, "AP-2"), state_code=0))
    analysis = analyse_channels(offline, None, {"AP-2": frozenset({"AP-3"})}, AI_OFF)
    assert ("AP-2", Band.GHZ_2) not in analysis.geometries and analysis.findings == ()


def test_a_punctured_width_is_detected_not_evaluated() -> None:
    punctured = with_stats(ap_named(SNAP, "AP-2"), Band.GHZ_5, width_mhz=240)
    analysis = analyse_channels(with_ap(SNAP, punctured), None, {"AP-2": frozenset({"AP-4"})}, AI_OFF)
    assert [f.subject for f in by_code(analysis, "width_not_modelled")] == ["AP-2"]
    assert by_code(analysis, "channel_overlap") == []


def test_channel_ai_settings_type_is_the_models_one() -> None:
    assert isinstance(AI, ChannelAiSettings)


def test_without_a_controller_channel_list_5_ghz_hints_and_reuse_are_skipped_and_said_so() -> None:
    no_list = replace(AI_OFF, channels={})
    clash = with_ap(SNAP, with_stats(ap_named(SNAP, "AP-4"), Band.GHZ_5, channel=56))
    neighbours = {"AP-2": frozenset({"AP-4"})}
    analysis = analyse_channels(clash, None, neighbours, no_list)
    overlaps = [f for f in by_code(analysis, "channel_overlap") if f.band is Band.GHZ_5]
    assert [f.subject for f in overlaps] == ["AP-2", "AP-4"]
    assert all("candidate" not in f.message for f in overlaps)
    listed = analyse_channels(clash, None, neighbours, AI_OFF)
    assert by_code(listed, "channel_candidates_unknown") == []
    assert all("free candidate" in f.message for f in by_code(listed, "channel_overlap") if f.band is Band.GHZ_5)


def test_the_5_ghz_reuse_check_runs_with_a_list_and_is_skipped_and_named_at_site_level_without_one() -> None:
    # Three access points that all hear each other at 160 MHz need three colours; the fixture's 36..128 list
    # offers two 160 MHz blocks.
    triangle = SNAP
    for name in ("AP-1", "AP-2", "AP-3"):
        triangle = with_ap(triangle, with_stats(ap_named(triangle, name), Band.GHZ_5, channel=36, width_mhz=160))
    chain = {"AP-1": frozenset({"AP-2", "AP-3"}), "AP-2": frozenset({"AP-3"})}
    listed = analyse_channels(triangle, None, chain, AI_OFF)
    assert [f.band for f in by_code(listed, "channel_reuse_infeasible")] == [Band.GHZ_5]
    assert by_code(listed, "channel_reuse_infeasible")[0].message == (
        "3 access points that hear each other (AP-1, AP-2, AP-3) cannot all get distinct channels: the controller's "
        "Channel AI list offers 2 160 MHz blocks, 3 would be needed; add channels to the Channel AI list, reduce "
        "the width or accept co-channel reuse"
    )
    assert len(listed.reuse_infeasible[Band.GHZ_5]) == 1
    assert by_code(listed, "channel_candidates_unknown") == []
    for channel_ai in (replace(AI_OFF, channels={}), None):
        skipped = analyse_channels(triangle, None, chain, channel_ai)
        assert by_code(skipped, "channel_reuse_infeasible") == []
        assert Band.GHZ_5 not in skipped.reuse_infeasible
        unknown = by_code(skipped, "channel_candidates_unknown")
        assert [(f.subject, f.band, f.severity) for f in unknown] == [(SNAP.site.id, Band.GHZ_5, Severity.INFO)]
