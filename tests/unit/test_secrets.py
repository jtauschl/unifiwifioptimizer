import copy
import json
import pickle
from dataclasses import asdict

import pytest

from unifiwifioptimizer.domain.models import MgmtSettings
from unifiwifioptimizer.domain.secrets import Secret, is_secret_key


@pytest.mark.parametrize(
    "key",
    [
        "x_ssh_password",
        "X_PASSPHRASE",
        "x_authkey",
        "client_secret",
        "server_certificate_key",
        "dh_key",
        "utm_key",
        "utm_token",
        "psk",
        "x_mesh_psk",
        "passphrase",
        "api_token",
        "password",
        "admin_password_hash",
        "x_ssh_keys",
        "private_preshared_keys",
        "authorized_keys",
        "credentials",
        "wan_credential",
    ],
)
@pytest.mark.security("T10")
def test_secret_keys_are_recognised(key: str) -> None:
    assert is_secret_key(key)


@pytest.mark.parametrize("key", ["name", "mac", "keyboard", "key", "keys", "tx_power", "_id", "essid", "channel"])
def test_ordinary_keys_are_not_secret(key: str) -> None:
    assert not is_secret_key(key)


@pytest.mark.security("T11")
def test_secret_hides_its_value_from_repr_str_and_format() -> None:
    secret = Secret("hunter2")
    assert repr(secret) == "Secret(***)"
    assert str(secret) == "***"
    assert f"{secret}" == "***"
    assert "hunter2" not in repr([secret]) + str({"k": secret}) + repr({"k": secret})
    assert secret.reveal() == "hunter2"


def test_secret_equality_and_truthiness_follow_the_value() -> None:
    assert Secret("a") == Secret("a")
    assert Secret("a") != Secret("b")
    assert Secret("a") != "a"
    assert len({Secret("a"), Secret("a"), Secret("b")}) == 2
    assert Secret("a")
    assert not Secret("")


@pytest.mark.security("T11")
def test_secret_survives_model_projection_and_copy_as_an_opaque_object() -> None:
    mgmt = MgmtSettings(ssh_enabled=True, ssh_password_auth_enabled=True, ssh_user="u", ssh_password=Secret("hunter2"))
    projected = asdict(mgmt)
    assert projected["ssh_password"] is mgmt.ssh_password
    assert "hunter2" not in repr(projected)
    with pytest.raises(TypeError):
        json.dumps(projected)
    assert copy.copy(mgmt.ssh_password) is mgmt.ssh_password and copy.deepcopy(mgmt) == mgmt
    with pytest.raises(TypeError, match="cannot be pickled"):
        pickle.dumps(mgmt.ssh_password)
