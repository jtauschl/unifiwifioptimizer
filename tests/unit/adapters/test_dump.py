import json
from datetime import UTC, datetime

import pytest

from unifiwifioptimizer.adapters.unifi.dump import redact
from unifiwifioptimizer.analysis.site_analyzer import analyze_site
from unifiwifioptimizer.domain.models import Band, MgmtSettings
from unifiwifioptimizer.domain.plain import MASK, SecretPolicy, plain
from unifiwifioptimizer.domain.secrets import Secret

from ..analysis.builders import golden_input


def _plain(value: object) -> object:
    return plain(value, SecretPolicy.MASK)


def test_plain_projection_masks_secrets_and_flattens_models() -> None:
    mgmt = MgmtSettings(ssh_enabled=True, ssh_password_auth_enabled=None, ssh_user="u", ssh_password=Secret("pw"))
    projected = _plain(mgmt)
    assert projected == {
        "ssh_enabled": True,
        "ssh_password_auth_enabled": None,
        "ssh_user": "u",
        "ssh_password": MASK,
        "ssh_user_rejected": False,
    }
    assert _plain(Band.GHZ_5) == "5g"
    assert _plain({Band.GHZ_2: frozenset({6, 1, 11})}) == {"2g": [1, 11, 6]}
    assert _plain((1, "a", b"\x01\xff")) == [1, "a", "01ff"]
    from ipaddress import ip_address

    assert _plain(ip_address("192.0.2.1")) == "192.0.2.1"


@pytest.mark.security("T10")
def test_redact_masks_every_secret_looking_key_at_any_depth() -> None:
    document = {"x_passphrase": "a", "nested": [{"server_certificate_key": "b", "name": "c"}], "name": "d"}
    assert redact(document) == {
        "x_passphrase": MASK,
        "nested": [{"server_certificate_key": MASK, "name": "c"}],
        "name": "d",
    }


@pytest.mark.security("T11")
def test_the_run_dump_of_a_site_report_is_json_with_the_capture_time_in_iso_8601() -> None:
    assert _plain(datetime(2026, 10, 12, 15, 11, 32, tzinfo=UTC)) == "2026-10-12T15:11:32+00:00"
    report = analyze_site(golden_input(skip_scan=True))
    document = json.loads(json.dumps(redact(_plain(report))))
    assert document["captured_at"] == report.captured_at.isoformat() and document["site_id"] == report.site_id
    with pytest.raises(TypeError, match="no place in a report"):
        plain(Secret("pw"), SecretPolicy.REFUSE)
