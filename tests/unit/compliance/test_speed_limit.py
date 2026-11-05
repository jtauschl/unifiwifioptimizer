from unifiwifioptimizer.compliance.speed_limit import speed_limit_check
from unifiwifioptimizer.domain.models import UserGroup
from unifiwifioptimizer.domain.report import CheckStatus

from .builders import wlan

UNLIMITED = UserGroup(id="g1", name="Unlimited", down_kbps=None, up_kbps=None)
GUESTS = UserGroup(id="g2", name="Guests", down_kbps=20000, up_kbps=2500)
DOWN_ONLY = UserGroup(id="g3", name="Down", down_kbps=10000, up_kbps=None)


def shown(group_id: str | None, *groups: UserGroup) -> str | None:
    return speed_limit_check(wlan(usergroup_id=group_id), groups).actual


def test_a_group_without_caps_is_shown_as_off() -> None:
    assert shown("g1", UNLIMITED, GUESTS) == "Off"


def test_a_group_with_a_cap_names_the_group_and_both_rates() -> None:
    assert shown("g2", UNLIMITED, GUESTS) == "On: Guests, 20 Mbit/s down, 2.5 Mbit/s up"
    assert shown("g3", DOWN_ONLY) == "On: Down, 10 Mbit/s down, unlimited up"


def test_a_group_the_controller_did_not_list_or_a_wlan_without_one_is_incomplete() -> None:
    for group_id in ("missing", None):
        result = speed_limit_check(wlan(usergroup_id=group_id), (UNLIMITED,))
        assert result.status is CheckStatus.INCOMPLETE and result.actual is None


def test_the_limit_is_listed_with_a_note_and_never_judged() -> None:
    result = speed_limit_check(wlan(usergroup_id="g1"), (UNLIMITED,))
    assert result.status is CheckStatus.NOT_PRESCRIBED and result.expected is None and result.detail
