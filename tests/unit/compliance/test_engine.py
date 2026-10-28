import json
from dataclasses import replace
from pathlib import Path

from unifiwifioptimizer.adapters.unifi import parse
from unifiwifioptimizer.compliance.engine import evaluate_site, evaluate_wlan
from unifiwifioptimizer.domain.models import Band
from unifiwifioptimizer.domain.report import CheckStatus, Severity

from .builders import PROFILES, profile, standard_wlan, wlan

FIXTURES = Path(__file__).parents[2] / "fixtures"


def test_a_disabled_wlan_is_reported_as_that_and_nothing_else() -> None:
    evaluation = evaluate_wlan(wlan(enabled=False), profile())
    assert [c.code for c in evaluation.checks] == ["wlan_enabled"]
    assert evaluation.checks[0].status is CheckStatus.FAILED and evaluation.findings == ()
    assert (evaluation.wlan, evaluation.profile) == ("SSID-1", "Standard")


def test_a_compliant_wlan_has_only_passed_checks_plus_the_roaming_check_and_no_advisory() -> None:
    evaluation = evaluate_wlan(standard_wlan(), profile(), roaming_threshold_dbm=-70)
    statuses = {c.code: c.status for c in evaluation.checks}
    assert statuses.pop("roaming_assistant") is CheckStatus.PASSED
    assert set(statuses.values()) == {CheckStatus.PASSED} and evaluation.findings == ()


def test_a_wlan_on_6_ghz_gets_the_detect_only_roaming_result_through_the_engine() -> None:
    both = standard_wlan(bands=frozenset({Band.GHZ_2, Band.GHZ_5, Band.GHZ_6}), roaming_assistant_6e_enabled=True)
    evaluation = evaluate_wlan(both, profile(), roaming_threshold_dbm=-70)
    by_code = {c.code: c for c in evaluation.checks}
    assert len(by_code) == len(evaluation.checks)
    assert by_code["roaming_assistant"].status is CheckStatus.PASSED
    six = by_code["roaming_assistant_6g"]
    assert six.status is CheckStatus.NOT_EVALUABLE and six.actual == "Enabled" and six.detail == "6 GHz is detect-only"
    assert "roaming_assistant_6g" not in {c.code for c in evaluate_wlan(standard_wlan(), profile(), -70).checks}


def test_evaluate_site_follows_the_mapping_and_reports_each_configuration_problem() -> None:
    wlans = [standard_wlan(id="a", name="Main"), wlan(id="b", name="Twin"), wlan(id="c", name="Twin")]
    mapping = {"Main": "Standard", "Ghost": "IoT", "Twin": "IoT", "Main2": "NoSuchProfile"}
    compliance = evaluate_site(wlans, mapping, PROFILES, roaming_thresholds_dbm={"Main": -70})
    assert [e.wlan for e in compliance.evaluations] == ["Main"]
    assert [(f.code, f.subject, f.severity) for f in compliance.findings] == [
        ("wlan_not_found", "Ghost", Severity.ERROR),
        ("wlan_ambiguous", "Twin", Severity.ERROR),
        ("profile_unknown", "Main2", Severity.ERROR),
    ]
    assert compliance.has_failures
    clean = evaluate_site(wlans[:1], {"Main": "Standard"}, PROFILES, {"Main": -70})
    assert clean.has_failures is False


def fixture_wlans() -> list:  # type: ignore[type-arg]
    # The anonymised preset WLANs are disabled on the live site; enabled copies exercise every rule.
    return [
        replace(w, enabled=True)
        for w in parse.parse_wlans(json.loads((FIXTURES / "list_wlanconf.json").read_text())).items
    ]


def test_the_anonymised_controller_fixture_yields_a_pinned_golden_result() -> None:
    wlans = fixture_wlans()
    assert len(wlans) == 5
    compliance = evaluate_site(wlans, {w.name: "Standard" for w in wlans}, PROFILES)
    assert compliance.findings == ()
    golden = {
        e.wlan: (
            sorted(c.code for c in e.checks if c.status is CheckStatus.FAILED),
            sorted(c.code for c in e.checks if c.status is CheckStatus.INCOMPLETE),
            sorted(f.code for f in e.findings),
        )
        for e in compliance.evaluations
    }
    # SSID-1 is the live main WLAN (WPA2/WPA3, 12 Mbit/s on 2.4 GHz and 24 on 5 GHz, custom DTIM, proxy ARP on,
    # multicast-to-unicast off); SSID-2 the old Standard preset; SSID-3 the Hotspot preset; SSID-4/5 the OWE and
    # OWE-transition presets. Open and OWE WLANs send no group rekey interval and no 802.11b flag under automatic
    # rates: the first is not judged, the second is incomplete.
    assert golden == {
        "SSID-1": (["dtim_mode", "minrate_5", "multicast_to_unicast"], ["roaming_assistant"], []),
        "SSID-2": (
            [
                "fast_roaming",
                "group_rekey",
                "minrate_24",
                "minrate_5",
                "minrate_mode",
                "multicast_to_unicast",
                "pmf",
                "proxy_arp",
                "roaming_assistant",
                "security_protocol",
            ],
            ["ap_name_in_beacon", "b_supported", "mlo", "multicast_broadcast_blocker"],
            ["advanced_set_to_auto"],
        ),
        "SSID-3": (
            [
                "client_device_isolation",
                "fast_roaming",
                "minrate_24",
                "minrate_5",
                "minrate_mode",
                "multicast_to_unicast",
                "pmf",
                "proxy_arp",
                "roaming_assistant",
                "security_protocol",
            ],
            ["b_supported"],
            [],
        ),
        "SSID-4": (
            [
                "fast_roaming",
                "minrate_24",
                "minrate_5",
                "minrate_mode",
                "multicast_to_unicast",
                "proxy_arp",
                "roaming_assistant",
                "security_protocol",
            ],
            ["b_supported"],
            [],
        ),
        "SSID-5": (
            [
                "fast_roaming",
                "minrate_24",
                "minrate_5",
                "minrate_mode",
                "multicast_to_unicast",
                "proxy_arp",
                "roaming_assistant",
                "security_protocol",
            ],
            ["b_supported"],
            [],
        ),
    }
    for evaluation in compliance.evaluations:
        codes = [c.code for c in evaluation.checks]
        assert len(set(codes)) == len(codes)


def test_a_retired_profile_name_gets_a_pointer_to_its_successor() -> None:
    compliance = evaluate_site([standard_wlan(id="a", name="Main")], {"Main": "Throughput"}, PROFILES)
    (finding,) = compliance.findings
    assert finding.code == "profile_unknown"
    assert finding.message == "profile 'Throughput' is not defined; it was renamed to Standard"
    latency = evaluate_site([standard_wlan(id="a", name="Main")], {"Main": "Latency"}, PROFILES).findings[0].message
    assert latency.startswith("profile 'Latency' is not defined; it was removed;")
    other = evaluate_site([standard_wlan(id="a", name="Main")], {"Main": "Mine"}, PROFILES).findings[0].message
    assert other == "profile 'Mine' is not defined"
