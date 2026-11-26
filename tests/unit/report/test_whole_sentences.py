"""A sentence the tool composes reaches the reader whole; only text a hostile controller shaped meets the bound.

The guard works from the output side. It gives every field that carries a tool sentence a unique sentence longer than
the largest bound of a bare token, one start word and one end word, renders both reports (and the site view), and
requires that wherever a start word is printed its end word is printed too, and that the text between the two is the
sentence the field was given. The reference is the same render with the bound out of reach, so the test needs no list
of sites: a cut at any call of the renderer loses an end word."""

import re
from collections import Counter
from collections.abc import Callable
from dataclasses import fields, is_dataclass, replace
from typing import Any

import pytest

from tests.unit.analysis.builders import ap_named, band_scan, golden_input, scan_pass, with_ap
from tests.unit.compliance.builders import PROFILES, standard_wlan
from tests.unit.printed import PLAIN_STEPS
from unifiwifioptimizer.analysis.site_analyzer import analyze_site
from unifiwifioptimizer.app.use_cases import SiteOverview
from unifiwifioptimizer.compliance.engine import evaluate_site
from unifiwifioptimizer.config.schema import MAX_NAME_CHARS
from unifiwifioptimizer.domain.analysis import WlanRoamingStatus
from unifiwifioptimizer.domain.models import Band, FieldProblem, Site, UnparsableDevice
from unifiwifioptimizer.domain.report import (
    ChannelPlanStatus,
    CheckStatus,
    Finding,
    Severity,
    SiteReport,
)
from unifiwifioptimizer.domain.scan import BandScanStatus, SiteScan
from unifiwifioptimizer.report import text
from unifiwifioptimizer.report.safe_text import MAX_CHARS
from unifiwifioptimizer.report.text import SENTENCE_MAX, WIDTH, render_overview, render_report, render_site

# The old bound of a tool sentence and the widest bound of a bare token: a tool sentence longer than both is cut by
# any site that fell back to either.
OLD_BOUND = 160
FILLER = "lorem ipsum " * 15
SENTENCE_FIELDS = frozenset(
    {
        ("Finding", "message"),
        ("CheckResult", "detail"),
        ("CheckResult", "expected"),
        ("CheckResult", "actual"),
        ("Recommendation", "reason"),
        ("WlanRoamingSummary", "reasons"),
        ("MissingPair", "reasons"),
        ("BandChannelPlan", "reason"),
        ("BandChannelPlan", "data_gaps"),
        ("UnparsableDevice", "reason"),
        ("FieldProblem", "path"),
        ("FieldProblem", "message"),
    }
)


# Fields that are None on most results; a None stays None, so a check keeps the status line it has.
OPTIONAL_FIELDS = frozenset({("CheckResult", "expected"), ("CheckResult", "actual")})


def sentence(tag: str) -> str:
    return f"START<{tag}> {FILLER}END<{tag}>"


def rebuild(node: Any, path: str, make: Callable[[str, Any], Any]) -> Any:
    if is_dataclass(node) and not isinstance(node, type):
        changes: dict[str, Any] = {}
        for field in fields(node):
            value = getattr(node, field.name)
            where = f"{path}/{field.name}"
            key = (type(node).__name__, field.name)
            if key in SENTENCE_FIELDS:
                if value is not None or key not in OPTIONAL_FIELDS:
                    changes[field.name] = make(where, value)
            else:
                rebuilt = rebuild(value, where, make)
                if rebuilt is not value:
                    changes[field.name] = rebuilt
        return replace(node, **changes) if changes else node
    if isinstance(node, tuple):
        items = tuple(rebuild(item, f"{path}[{index}]", make) for index, item in enumerate(node))
        return items if any(new is not old for new, old in zip(items, node, strict=True)) else node
    return node


def loud(tag: str, value: Any) -> Any:
    if isinstance(value, tuple):
        return tuple(sentence(f"{tag}[{i}]") for i in range(max(len(value), 2)))
    return sentence(tag)


def with_every_sentence(report: SiteReport, make: Callable[[str, Any], Any]) -> SiteReport:
    reuse = Finding(
        severity=Severity.WARNING,
        code="channel_reuse_infeasible",
        message="",
        subject="AP-1",
        band=Band.GHZ_5,
        peers=("AP-1", "AP-2"),
    )
    other = Finding(severity=Severity.ERROR, code="custom", message="", subject="AP-1", band=Band.GHZ_2)
    extended = report.extended_channel_plan
    assert extended is not None
    first, second = extended.bands
    plan = replace(
        extended,
        bands=(
            replace(first, reason="x"),
            replace(second, status=ChannelPlanStatus.RECOMMENDED, reason=None, data_gaps=("x",)),
        ),
    )
    padded = replace(
        report,
        site_findings=(*report.site_findings, reuse, other),
        extended_channel_plan=plan,
        field_problems=(FieldProblem("x", "x"),),
        unparsable=(UnparsableDevice(mac=None, name=None, reason="x"),),
    )
    made: SiteReport = rebuild(padded, "report", make)
    summaries = {s.wlan: s for s in made.roaming}
    evaluations = tuple(
        replace(
            evaluation,
            checks=tuple(
                # The overview states the first reason of the target in the incomplete check itself.
                replace(check, detail=summaries[evaluation.wlan].reasons[0])
                if check.code == "roaming_assistant" and check.status is CheckStatus.INCOMPLETE
                else check
                for check in evaluation.checks
            ),
        )
        for evaluation in made.compliance.evaluations
    )
    return replace(made, compliance=replace(made.compliance, evaluations=evaluations))


def rendered(report: SiteReport, width: int | None) -> list[str]:
    # A fold may break a line between two words.
    return [
        " ".join(render_overview(report, width, steps=PLAIN_STEPS).split()),
        " ".join(render_report(report, width, steps=PLAIN_STEPS).split()),
    ]


def printed_tags(output: str, word: str) -> Counter[str]:
    """Each tag with the number of places that print it: one sentence is printed by several views of the report."""
    return Counter(re.findall(rf"{word}<([^>]+)>", output))


def printed_sentences(output: str) -> Counter[str]:
    """Each sentence from its start word to its end word, whole, with the number of places that print it: a word
    lost in the middle changes the text and leaves both counts of tags as they were."""
    return Counter(match.group(0) for match in re.finditer(r"START<([^>]+)> .*?END<\1>", output))


def as_given(printed: str) -> str:
    """The sentence the test gave to the field the printed one came from, as the whitespace-normalised output has it."""
    tag = re.match(r"START<([^>]+)>", printed)
    assert tag is not None
    return " ".join(sentence(tag.group(1)).split())


@pytest.fixture(scope="module")
def loud_report() -> SiteReport:
    return with_every_sentence(analyze_site(_extended()), loud)


def _extended() -> Any:
    return replace(golden_input(), extended=True)


@pytest.mark.parametrize("width", [None, WIDTH])
def test_every_printed_sentence_ends_where_it_ends(
    loud_report: SiteReport, width: int | None, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = rendered(loud_report, width)
    monkeypatch.setattr(text, "SENTENCE_MAX", 10**6)
    reference = rendered(loud_report, width)
    for real_output, reference_output in zip(real, reference, strict=True):
        started = printed_tags(reference_output, "START")
        assert started, "the reference run printed no sentence"
        assert printed_tags(real_output, "START") == started
        assert printed_tags(real_output, "END") == started, sorted((started - printed_tags(real_output, "END")).keys())
        assert printed_sentences(real_output) == printed_sentences(reference_output)
        assert [p for p in printed_sentences(real_output) if p != as_given(p)] == []
        assert sum(printed_sentences(reference_output).values()) == sum(started.values())


def test_the_guard_reaches_every_kind_of_sentence(loud_report: SiteReport, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(text, "SENTENCE_MAX", 10**6)
    overview, details = rendered(loud_report, None)
    reached = {
        "overview": set(printed_tags(overview, "START")),
        "details": set(printed_tags(details, "START")),
    }
    expected = {
        "overview": [
            r"^report/site_findings\[\d+\]/message$",
            r"^report/aps\[\d+\]/bands\[\d+\]/findings\[\d+\]/message$",
            r"^report/compliance/evaluations\[\d+\]/checks\[\d+\]/detail$",
            r"^report/roaming\[\d+\]/reasons\[0\]$",
            r"^report/extended_channel_plan/bands\[\d+\]/reason$",
            r"^report/extended_channel_plan/bands\[\d+\]/data_gaps\[\d+\]$",
            r"^report/compliance/evaluations\[\d+\]/checks\[\d+\]/actual$",
            r"^report/compliance/evaluations\[\d+\]/checks\[\d+\]/expected$",
            r"^report/aps\[\d+\]/bands\[\d+\]/recommendations\[\d+\]/reason$",
            r"^report/unparsable\[\d+\]/reason$",
        ],
        "details": [
            r"^report/site_findings\[\d+\]/message$",
            r"^report/aps\[\d+\]/bands\[\d+\]/findings\[\d+\]/message$",
            r"^report/aps\[\d+\]/bands\[\d+\]/recommendations\[\d+\]/reason$",
            r"^report/compliance/evaluations\[\d+\]/checks\[\d+\]/detail$",
            r"^report/compliance/evaluations\[\d+\]/checks\[\d+\]/actual$",
            r"^report/compliance/evaluations\[\d+\]/checks\[\d+\]/expected$",
            r"^report/roaming\[\d+\]/reasons\[1\]$",
            r"^report/groups\[\d+\]/missing\[\d+\]/reasons\[\d+\]$",
            r"^report/extended_channel_plan/bands\[\d+\]/reason$",
            r"^report/extended_channel_plan/bands\[\d+\]/data_gaps\[\d+\]$",
            r"^report/unparsable\[\d+\]/reason$",
            r"^report/field_problems\[\d+\]/(path|message)$",
        ],
    }
    for view, patterns in expected.items():
        for pattern in patterns:
            assert any(re.search(pattern, tag) for tag in reached[view]), (view, pattern)


def test_the_site_view_prints_its_sentences_whole() -> None:
    site = Site(id="default", description="Site-1", hidden_id="default", device_count=1)
    tags = ("unparsable", "path", "message")
    overview = SiteOverview(
        site=site,
        wlans=(),
        access_points=(),
        unparsable_devices=(UnparsableDevice(mac=None, name=None, reason=sentence(tags[0])),),
        mgmt=None,
        problems=(FieldProblem(sentence(tags[1]), sentence(tags[2])),),
    )
    output = " ".join(render_site(overview).split())
    assert set(printed_tags(output, "END")) == set(tags)
    assert [p for p in printed_sentences(output) if p != as_given(p)] == []
    assert sum(printed_sentences(output).values()) == len(tags)


def test_the_longest_sentence_is_longer_than_every_bound_of_a_bare_token() -> None:
    assert len(sentence("x")) > max(OLD_BOUND, MAX_CHARS, text.NAME, text.SITE_ID_COLUMN, text.SITE_NAME_COLUMN)


# --- a hostile controller still meets the sanitiser and the bound ------------------------------------------------


HOSTILE = "\x1b[31mred\x1b[0m‮evil\x00"


def hostile(tag: str, value: Any) -> Any:
    if isinstance(value, tuple):
        return tuple(f"{HOSTILE}{tag}[{i}]" for i in range(max(len(value), 2)))
    return f"{HOSTILE}{tag}"


def test_a_hostile_string_in_any_sentence_field_is_sanitised(loud_report: SiteReport) -> None:
    report = with_every_sentence(analyze_site(_extended()), hostile)
    for output in rendered(report, None) + rendered(report, WIDTH):
        assert not any(bad in output for bad in ("\x1b", "‮", "\x00"))
        assert "�evil�" in output


@pytest.mark.parametrize("length", [SENTENCE_MAX - 1, SENTENCE_MAX, SENTENCE_MAX + 1, 3 * SENTENCE_MAX])
def test_a_string_beyond_the_bound_ends_in_an_ellipsis_at_the_bound(length: int) -> None:
    value = "w" * length
    kept = value if length <= SENTENCE_MAX else value[: SENTENCE_MAX - 1] + "…"
    overview = SiteOverview(
        site=Site(id="default", description="Site-1", hidden_id="default", device_count=1),
        wlans=(),
        access_points=(),
        unparsable_devices=(UnparsableDevice(mac=None, name=None, reason=value),),
        mgmt=None,
        problems=(),
    )
    assert f"not usable ({kept})" in render_site(overview)


def test_the_fixture_reaches_incomplete_roaming_and_two_bands_of_plan() -> None:
    report = analyze_site(_extended())
    assert any(s.status is WlanRoamingStatus.INCOMPLETE and len(s.reasons) >= 2 for s in report.roaming)
    assert [b.status for b in report.extended_channel_plan.bands] == [ChannelPlanStatus.UNAVAILABLE] * 2  # type: ignore[union-attr]


def test_the_note_for_an_empty_5_ghz_band_of_the_measured_model_reaches_the_reader_whole() -> None:
    inp = golden_input()
    assert isinstance(inp.scan, SiteScan)
    lite = replace(ap_named(inp.snapshot, "AP-1"), model="UAL6", firmware="6.7.57.15670")
    empty = tuple(
        scan_pass(two=band_scan(Band.GHZ_2), five=band_scan(Band.GHZ_5, (), BandScanStatus.EMPTY)) for _ in range(3)
    )
    scans = tuple(replace(s, passes=empty) if s.ap_name == "AP-1" else s for s in inp.scan.scans)
    report = analyze_site(replace(inp, snapshot=with_ap(inp.snapshot, lite), scan=replace(inp.scan, scans=scans)))
    for output in rendered(report, WIDTH) + rendered(report, None):
        assert "restart it and scan before the next quick scan" in output
        assert "…" not in output


def test_a_profile_name_the_sanitiser_replaces_does_not_hide_the_diagnosis(loud_report: SiteReport) -> None:
    unprintable = "\U000e0001" * MAX_NAME_CHARS
    compliance = evaluate_site([standard_wlan(id="a", name="Main")], {"Main": unprintable}, PROFILES)
    report = replace(loud_report, compliance=compliance)
    for output in rendered(report, WIDTH) + rendered(report, None):
        assert f"profile '{'�' * MAX_NAME_CHARS}' is not defined" in output
        assert "…" not in output


def test_a_name_longer_than_the_width_stays_whole_and_only_its_line_overruns() -> None:
    name = "n" * 128
    line = f"    ! {name}: shares its name with another access point; rename one of them to tell them apart"
    folded = text._fold(line, WIDTH)
    assert " ".join(folded.split()) == " ".join(line.split())
    assert [row for row in folded.splitlines() if len(row) > WIDTH and name not in row] == []
    assert any(name in row for row in folded.splitlines())
