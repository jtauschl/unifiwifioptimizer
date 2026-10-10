"""Gate: every committed fixture satisfies the anonymizer's contract (spec-closed, synthetic identifiers)."""

import json
from pathlib import Path

import pytest

from tests.tools.anonymize_fixtures import ENDPOINTS_BY_FIXTURE, check_fixture

FIXTURES = Path(__file__).parents[1] / "fixtures"
FIXTURE_FILES = sorted(p.name for p in FIXTURES.glob("*.json"))


def test_every_endpoint_has_a_committed_fixture() -> None:
    assert sorted(ENDPOINTS_BY_FIXTURE) == FIXTURE_FILES


@pytest.mark.parametrize("name", FIXTURE_FILES)
def test_fixture_is_anonymous(name: str) -> None:
    payload = json.loads((FIXTURES / name).read_text())
    assert check_fixture(name, payload) == []


@pytest.mark.parametrize("name", FIXTURE_FILES)
def test_fixture_is_canonically_formatted(name: str) -> None:
    text = (FIXTURES / name).read_text()
    assert text == json.dumps(json.loads(text), indent=2, sort_keys=True) + "\n"
