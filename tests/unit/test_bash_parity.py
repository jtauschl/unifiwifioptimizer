"""Inventory gate between the legacy shell test suites and their pytest counterparts.

Every `test_*` function in tests/*_test.sh must be accounted for: ported to a named pytest test that
exists, assigned to the ticket of the rewrite that owns its layer, or recorded as superseded by a design
decision. Every pytest test named here must exist, so a rename or deletion on either side fails this
gate rather than silently dropping coverage.
"""

import re
from pathlib import Path

import pytest

TESTS_DIR = Path(__file__).resolve().parents[1]
SHELL_SUITES = sorted(TESTS_DIR.glob("*_test.sh"))

TX = "unit/rf/test_txpower.py::"
ROAMING = "unit/rf/test_roaming.py::"
NORMALIZE = "unit/compliance/test_normalize.py::"
ADVISORIES = "unit/compliance/test_advisories.py::"
# Bash test → pytest node (module::function) or the ticket that ports it.
PORTED: dict[str, str] = {
    "security_test.sh::test_state_wpa3_enterprise": NORMALIZE + "test_state_wpa3_enterprise",
    "security_test.sh::test_state_wpa2_wpa3_enterprise": NORMALIZE + "test_state_wpa2_wpa3_enterprise",
    "security_test.sh::test_state_wpa3_personal": NORMALIZE + "test_state_wpa3_personal",
    "security_test.sh::test_state_wpa2_wpa3_personal": NORMALIZE + "test_state_wpa2_wpa3_personal",
    "security_test.sh::test_state_owe": NORMALIZE + "test_state_owe",
    "security_test.sh::test_state_owe_transition": NORMALIZE + "test_state_owe_transition",
    "security_test.sh::test_sae_matches_wpa3_personal": NORMALIZE + "test_sae_matches_wpa3_personal",
    "security_test.sh::test_sae_matches_wpa2_wpa3_personal": NORMALIZE + "test_sae_matches_wpa2_wpa3_personal",
    "security_test.sh::test_sae_rejects_wpa3_enterprise": NORMALIZE + "test_sae_rejects_wpa3_enterprise",
    "security_test.sh::test_sae_rejects_wpa2_wpa3_enterprise": NORMALIZE + "test_sae_rejects_wpa2_wpa3_enterprise",
    "security_test.sh::test_sae_rejects_owe": NORMALIZE + "test_sae_rejects_owe",
    "security_test.sh::test_wpa3_matches_all_four_variants": NORMALIZE + "test_wpa3_matches_all_four_variants",
    "security_test.sh::test_wpa3_rejects_wpa2_and_owe": NORMALIZE + "test_wpa3_rejects_wpa2_and_owe",
    "security_test.sh::test_mlo_advisory_silent_when_compliant": ADVISORIES + "test_mlo_advisory_silent_when_compliant",
    "security_test.sh::test_mlo_advisory_silent_when_wpa3_enterprise_and_required": ADVISORIES
    + "test_mlo_advisory_silent_when_wpa3_enterprise_and_required",
    "security_test.sh::test_mlo_advisory_fires_on_wpa2_only": ADVISORIES + "test_mlo_advisory_fires_on_wpa2_only",
    "security_test.sh::test_mlo_advisory_fires_on_pmf_optional": ADVISORIES + "test_mlo_advisory_fires_on_pmf_optional",
    "security_test.sh::test_mlo_advisory_silent_when_mlo_disabled": ADVISORIES
    + "test_mlo_advisory_silent_when_mlo_disabled",
    "security_test.sh::test_mlo_advisory_silent_for_6ghz_default_config": ADVISORIES
    + "test_mlo_advisory_silent_for_6ghz_default_config",
    "tx_test.sh::test_in_corridor_unchanged": TX + "test_in_corridor_unchanged",
    "roaming_test.sh::test_calculate_roaming_recommendation_default": ROAMING
    + "test_calculate_roaming_recommendation_default",
    "roaming_test.sh::test_calculate_roaming_recommendation_margin_cap": ROAMING
    + "test_calculate_roaming_recommendation_margin_cap",
}
# Behaviour the standards-grounded model (ADR-002 D8) replaced; the shell test documents the old rule.
SUPERSEDED: dict[str, str] = {
    "tx_test.sh::test_partial_missing_peer_nudge_preserved": "ADR-002 D8: weakest-neighbour statistic, no nudge",
}
# Tests of report rendering, site aggregation and controller fetch paths follow their layers' tickets.
DEFERRED: dict[str, str] = {
    "tx_test.sh::test_zero_sightings_with_peer_goes_to_max": "OP#2881 analysis (reciprocity-first zero sightings)",
    "tx_test.sh::test_zero_sightings_no_peer_unchanged": "OP#2881 analysis",
    "tx_test.sh::test_print_rec_tx_zero_sightings_flags_real_change": "OP#2881 report",
    "tx_test.sh::test_print_rec_tx_zero_sightings_no_flag_when_already_at_max": "OP#2881 report",
    "tx_test.sh::test_prepare_site_tx_checks_counts_zero_sightings": "OP#2881 analysis",
    "tx_test.sh::test_prepare_site_tx_checks_zero_when_all_ok": "OP#2881 analysis",
    "tx_test.sh::test_tx_pending_note_appears_when_incomplete_and_pending": "OP#2881 report",
    "tx_test.sh::test_tx_pending_note_absent_when_no_pending": "OP#2881 report",
    "tx_test.sh::test_tx_pending_note_absent_on_normal_verdict": "OP#2881 report",
    "tx_test.sh::test_expected_disabled_and_actually_disabled_is_ok": "OP#2881 compliance",
    "tx_test.sh::test_expected_disabled_but_actually_enabled_is_flagged": "OP#2881 compliance",
    "tx_test.sh::test_expected_disabled_ignores_incomplete_aggregation": "OP#2881 compliance",
    "tx_test.sh::test_na_band_not_broadcast_ignores_expected_false": "OP#2881 compliance",
    "tx_test.sh::test_na_older_api_ignores_expected_false": "OP#2881 compliance",
    "tx_test.sh::test_na_band_not_broadcast_ignores_expected_true": "OP#2881 compliance",
    "tx_test.sh::test_na_older_api_ignores_expected_true": "OP#2881 compliance",
    "roaming_test.sh::test_ssid_peer_filtering": "OP#2881 analysis",
    "roaming_test.sh::test_asymmetric_direction": "OP#2881 analysis",
    "roaming_test.sh::test_tie_handling_floor_clamp": "OP#2881 analysis",
    "roaming_test.sh::test_incomplete_no_relevant_neighbor": "OP#2881 analysis",
    "roaming_test.sh::test_incomplete_missing_sighting": "OP#2881 analysis",
    "roaming_test.sh::test_na_2g_only_wlan": "OP#2881 analysis",
    "roaming_test.sh::test_na_single_ap_wlan": "OP#2881 analysis",
    "roaming_test.sh::test_missing_new_field_no_row": "OP#2881 analysis",
    "roaming_test.sh::test_incomplete_partial_missing_sighting": "OP#2881 analysis",
    "roaming_test.sh::test_incomplete_unconfigured_broadcasting_ap": "OP#2881 analysis",
    "roaming_test.sh::test_2g_only_site_no_fallback_trigger": "OP#2881 analysis",
    "roaming_test.sh::test_overlapping_groups_deduplicated": "OP#2881 analysis",
    "roaming_test.sh::test_incomplete_unknown_group_id": "OP#2881 analysis",
    "roaming_test.sh::test_fetch_site_apgroups_survives_unreachable_endpoint": "OP#2878 controller adapter",
    "roaming_test.sh::test_site_wide_fallback_flag_set_when_any_wlan_has_field": "OP#2881 analysis",
    "roaming_test.sh::test_multi_site_tx_lo_isolation": "OP#2881 analysis",
    "roaming_test.sh::test_field_present_but_apgroups_empty_still_produces_row": "OP#2881 analysis",
    "roaming_test.sh::test_incomplete_all_group_ids_unknown": "OP#2881 analysis",
    "roaming_test.sh::test_fetch_site_apgroups_survives_malformed_response": "OP#2878 controller adapter",
}

SHELL_TEST = re.compile(r"^(?:function\s+)?(test_[a-z0-9_]+)\s*(?:\(\))?\s*\{", re.MULTILINE)
PYTEST_TEST = re.compile(r"^def (test_[a-z0-9_]+)\(", re.MULTILINE)


def shell_tests() -> set[str]:
    return {
        f"{suite.name}::{name}"
        for suite in SHELL_SUITES
        for name in SHELL_TEST.findall(suite.read_text(encoding="utf-8"))
    }


def pytest_tests() -> set[str]:
    found: set[str] = set()
    for module in TESTS_DIR.rglob("test_*.py"):
        rel = module.relative_to(TESTS_DIR).as_posix()
        found.update(f"{rel}::{name}" for name in PYTEST_TEST.findall(module.read_text(encoding="utf-8")))
    return found


def test_shell_suites_are_present_until_the_cut_over() -> None:
    assert [s.name for s in SHELL_SUITES] == ["roaming_test.sh", "security_test.sh", "tx_test.sh"]


def test_every_shell_test_is_ported_or_assigned_to_a_ticket() -> None:
    inventory = set(PORTED) | set(DEFERRED) | set(SUPERSEDED)
    assert len(inventory) == len(PORTED) + len(DEFERRED) + len(SUPERSEDED)
    unaccounted = shell_tests() - inventory
    assert unaccounted == set()


def test_every_inventory_entry_names_an_existing_shell_test() -> None:
    assert (set(PORTED) | set(DEFERRED) | set(SUPERSEDED)) - shell_tests() == set()


@pytest.mark.parametrize("target", sorted(set(PORTED.values())))
def test_every_ported_target_exists(target: str) -> None:
    assert target in pytest_tests()
