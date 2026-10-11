from unifiwifioptimizer.adapters.unifi.dump import MASK, _plain, redact
from unifiwifioptimizer.domain.models import Band, MgmtSettings
from unifiwifioptimizer.domain.secrets import Secret


def test_plain_projection_masks_secrets_and_flattens_models() -> None:
    mgmt = MgmtSettings(ssh_enabled=True, ssh_password_auth_enabled=None, ssh_user="u", ssh_password=Secret("pw"))
    projected = _plain(mgmt)
    assert projected == {"ssh_enabled": True, "ssh_password_auth_enabled": None, "ssh_user": "u", "ssh_password": MASK}
    assert _plain(Band.GHZ_5) == "5g"
    assert _plain({Band.GHZ_2: frozenset({6, 1, 11})}) == {"2g": [1, 11, 6]}
    assert _plain((1, "a", b"\x01\xff")) == [1, "a", "01ff"]
    from ipaddress import ip_address

    assert _plain(ip_address("192.0.2.1")) == "192.0.2.1"


def test_redact_masks_every_secret_looking_key_at_any_depth() -> None:
    document = {"x_passphrase": "a", "nested": [{"server_certificate_key": "b", "name": "c"}], "name": "d"}
    assert redact(document) == {
        "x_passphrase": MASK,
        "nested": [{"server_certificate_key": MASK, "name": "c"}],
        "name": "d",
    }
