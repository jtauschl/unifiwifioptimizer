from unifiwifioptimizer.compliance.roaming_check import CODE as ROAMING_CODE
from unifiwifioptimizer.compliance.roaming_check import CODE_6G as ROAMING_6G_CODE
from unifiwifioptimizer.compliance.rules import RULES
from unifiwifioptimizer.report.ui_paths import UI_PATHS, ui_path


def test_every_profile_check_code_has_a_ui_path() -> None:
    for rule in RULES:
        assert ui_path(rule.code), rule.code
    assert ui_path(ROAMING_CODE) and ui_path(ROAMING_6G_CODE) and ui_path("wlan_enabled")
    assert ui_path("no_such_check") is None
    assert all(path.startswith(("WLAN edit", "AP settings")) for path in UI_PATHS.values())
