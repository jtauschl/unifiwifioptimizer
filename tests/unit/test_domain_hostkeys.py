import base64
import hashlib

import pytest
from hypothesis import given
from hypothesis import strategies as st

from unifiwifioptimizer.domain.hostkeys import (
    ALIAS_DIGEST_CHARS,
    FingerprintAlgorithm,
    HostKeyFingerprint,
    host_key_alias,
    key_fingerprints,
    normalize_fingerprint,
)

ORIGIN = "https://unifi.example:443"
MAC = "02:00:00:00:00:04"


def test_alias_is_a_prefixed_sha256_truncation_and_is_case_insensitive_on_the_mac() -> None:
    alias = host_key_alias(ORIGIN, "default", MAC)
    assert alias.startswith("uwo-") and len(alias) == 4 + ALIAS_DIGEST_CHARS
    assert alias == host_key_alias(ORIGIN, "default", MAC.upper())
    assert all(c in "0123456789abcdef" for c in alias[4:])


@pytest.mark.parametrize(
    ("a", "b"),
    [
        (("https://u", "site-a", MAC), ("https://usite", "-a", MAC)),
        (("https://u", "site", "a" + MAC[1:]), ("https://ua", "site", MAC)),
        (("https://u", "site1", MAC), ("https://u", "site", "1" + MAC)),
        (("https://u", "", MAC), ("https://u", MAC, "")),
        (("1:x", "y", MAC), ("1", ":xy", MAC)),
    ],
)
def test_alias_fields_cannot_be_reassembled_into_a_colliding_triple(
    a: tuple[str, str, str], b: tuple[str, str, str]
) -> None:
    assert host_key_alias(*a) != host_key_alias(*b)


@given(
    st.tuples(st.text(max_size=20), st.text(max_size=20), st.text(max_size=20)),
    st.tuples(st.text(max_size=20), st.text(max_size=20), st.text(max_size=20)),
)
def test_distinct_triples_give_distinct_aliases(a: tuple[str, str, str], b: tuple[str, str, str]) -> None:
    normalised_a = (a[0], a[1], a[2].lower())
    normalised_b = (b[0], b[1], b[2].lower())
    assert (host_key_alias(*a) == host_key_alias(*b)) == (normalised_a == normalised_b)


def test_fingerprint_forms_normalise_to_one_comparable_value() -> None:
    digest = bytes(range(32))
    b64 = base64.b64encode(digest).decode()
    expected = HostKeyFingerprint(FingerprintAlgorithm.SHA256, digest)
    assert normalize_fingerprint("SHA256:" + b64.rstrip("=")) == expected
    assert normalize_fingerprint("  SHA256:" + b64 + "\n") == expected
    assert normalize_fingerprint(digest.hex()) == expected
    assert expected.text == "SHA256:" + b64.rstrip("=")
    md5 = bytes(range(16))
    colon = ":".join(f"{b:02x}" for b in md5)
    expected_md5 = HostKeyFingerprint(FingerprintAlgorithm.MD5, md5)
    assert normalize_fingerprint(colon) == expected_md5
    assert normalize_fingerprint("MD5:" + colon.upper()) == expected_md5
    assert normalize_fingerprint(md5.hex()) == expected_md5
    assert expected_md5.text == "MD5:" + colon
    assert normalize_fingerprint("\n") is None and normalize_fingerprint("") is None


@pytest.mark.parametrize(
    "text", ["abc", "SHA256:" + "A" * 42, "sha256:" + "A" * 43, "00:11", "x" * 64, "SHA256:" + "A" * 43 + "=="]
)
def test_garbled_fingerprints_raise_instead_of_reading_as_unknown(text: str) -> None:
    with pytest.raises(ValueError, match="not a SHA-256 or MD5"):
        normalize_fingerprint(text)


def test_key_fingerprints_match_ssh_keygen_semantics() -> None:
    blob = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00 " + bytes(range(32))
    key_b64 = base64.b64encode(blob).decode()
    sha256, md5 = key_fingerprints(key_b64)
    assert sha256 == HostKeyFingerprint(FingerprintAlgorithm.SHA256, hashlib.sha256(blob).digest())
    assert md5 == HostKeyFingerprint(FingerprintAlgorithm.MD5, hashlib.md5(blob, usedforsecurity=False).digest())
    with pytest.raises(ValueError):
        key_fingerprints("not*base64")
