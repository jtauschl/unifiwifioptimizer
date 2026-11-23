"""Host-key identity of an access point: the alias OpenSSH looks up and the fingerprint forms we compare.

An access point is pinned by (controller origin, site id, MAC), never by its IP: IPs move, and a
hostname-based entry would let a controller-supplied address pick which key is trusted.
"""

import hashlib
import re
from base64 import b64decode, b64encode
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType

from unifiwifioptimizer.domain.scan import FAILURE_ADVICE, ScanFailureKind

ALIAS_PREFIX = "uwo-"
ALIAS_DIGEST_CHARS = 32
_SHA256_B64_RE = re.compile(r"SHA256:([A-Za-z0-9+/]{43})=?")
_MD5_COLON_RE = re.compile(r"(?:MD5:)?((?:[0-9a-fA-F]{2}:){15}[0-9a-fA-F]{2})")
_HEX_RE = re.compile(r"[0-9a-fA-F]+")


def host_key_alias(controller_origin: str, site_id: str, mac: str) -> str:
    """`uwo-<32 hex>`: SHA-256 over a length-prefixed concatenation of the three fields, so no two
    (origin, site, mac) triples can serialise to the same bytes whatever characters they contain."""
    serialised = "".join(f"{len(part)}:{part}" for part in (controller_origin, site_id, mac.lower()))
    return ALIAS_PREFIX + hashlib.sha256(serialised.encode("utf-8")).hexdigest()[:ALIAS_DIGEST_CHARS]


class FingerprintAlgorithm(StrEnum):
    SHA256 = "sha256"
    MD5 = "md5"


@dataclass(frozen=True, slots=True)
class HostKeyFingerprint:
    algorithm: FingerprintAlgorithm
    digest: bytes

    @property
    def text(self) -> str:
        if self.algorithm is FingerprintAlgorithm.SHA256:
            return "SHA256:" + b64encode(self.digest).decode().rstrip("=")
        return "MD5:" + ":".join(f"{b:02x}" for b in self.digest)


def normalize_fingerprint(text: str) -> HostKeyFingerprint | None:
    """The fingerprint a controller or `ssh-keygen -l` printed, in one comparable form.

    Accepts `SHA256:<base64>`, `MD5:` or bare colon-separated hex (what older controllers report), or bare
    hex of either length; surrounding whitespace is ignored. Returns None for an empty value (the
    controller sends `"\\n"` for an access point whose key it has not learnt) and raises `ValueError` for
    anything else, so a reader cannot mistake a garbled value for "unknown".
    """
    stripped = text.strip()
    if not stripped:
        return None
    if m := _SHA256_B64_RE.fullmatch(stripped):
        return HostKeyFingerprint(FingerprintAlgorithm.SHA256, b64decode(m.group(1) + "="))
    if m := _MD5_COLON_RE.fullmatch(stripped):
        return HostKeyFingerprint(FingerprintAlgorithm.MD5, bytes.fromhex(m.group(1).replace(":", "")))
    if _HEX_RE.fullmatch(stripped) and len(stripped) == 64:
        return HostKeyFingerprint(FingerprintAlgorithm.SHA256, bytes.fromhex(stripped))
    if _HEX_RE.fullmatch(stripped) and len(stripped) == 32:
        return HostKeyFingerprint(FingerprintAlgorithm.MD5, bytes.fromhex(stripped))
    raise ValueError("not a SHA-256 or MD5 host-key fingerprint")


def key_fingerprints(key_base64: str) -> tuple[HostKeyFingerprint, HostKeyFingerprint]:
    """SHA-256 and MD5 of a public key blob as `ssh-keygen -l` prints them: the digests of the decoded
    base64, so no external tool is needed to compare a scanned key against a pin."""
    blob = b64decode(key_base64, validate=True)
    return (
        HostKeyFingerprint(FingerprintAlgorithm.SHA256, hashlib.sha256(blob).digest()),
        HostKeyFingerprint(FingerprintAlgorithm.MD5, hashlib.md5(blob, usedforsecurity=False).digest()),
    )


class TrustRefusalKind(StrEnum):
    """Why the trust step refused an access point, named by what the person does next."""

    ADDRESS_NOT_USED = "address_not_used"
    FINGERPRINT_FORM = "fingerprint_form"
    NO_KEY_OFFERED = "no_key_offered"
    KEYSCAN_TIMEOUT = "keyscan_timeout"
    KEYSCAN_TOO_MANY = "keyscan_too_many"
    KEY_MISMATCH_PIN = "key_mismatch_pin"
    KEY_MISMATCH_CONTROLLER = "key_mismatch_controller"
    STORED_KEY_REJECTED_PIN = "stored_key_rejected_pin"
    STORED_KEY_REJECTED_CONTROLLER = "stored_key_rejected_controller"
    SOURCES_DISAGREE = "sources_disagree"
    UNUSABLE_KEYS = "unusable_keys"
    SEVERAL_STORED_LINES = "several_stored_lines"
    STORE_CHANGED = "store_changed"
    NOT_ON_CONTROLLER_NAMED = "not_on_controller_named"
    NOT_ON_CONTROLLER_CONFIGURED = "not_on_controller_configured"


_REPORT_WITH_FIRMWARE = "report it with the access point's firmware version"
_COMPARE_ELSEWHERE = "from a source other than this tool"

# The next step per kind; `{site}` is the controller's site id. A step that the scan side has too is read from
# `FAILURE_ADVICE`, not copied.
TRUST_ADVICE: Mapping[TrustRefusalKind, str] = MappingProxyType(
    {
        TrustRefusalKind.ADDRESS_NOT_USED: FAILURE_ADVICE[ScanFailureKind.ADDRESS_REFUSED].next_step,
        TrustRefusalKind.FINGERPRINT_FORM: (
            "report it with the controller version; this access point cannot be trusted or re-trusted until the "
            "controller reports a SHA-256 or an MD5 fingerprint, or none (a pin does not override it); a key already "
            "stored keeps working"
        ),
        TrustRefusalKind.NO_KEY_OFFERED: FAILURE_ADVICE[ScanFailureKind.TRANSPORT].next_step,
        TrustRefusalKind.KEYSCAN_TIMEOUT: FAILURE_ADVICE[ScanFailureKind.TIMEOUT].next_step,
        TrustRefusalKind.KEYSCAN_TOO_MANY: _REPORT_WITH_FIRMWARE,
        TrustRefusalKind.KEY_MISMATCH_PIN: (
            "the pin is wrong (a typo, another access point's fingerprint) or the access point was reset or "
            "re-adopted; if none of these holds, someone else may answer at this address: store nothing; correct "
            f"`sites.{{site}}.ssh.host_keys` only with a fingerprint {_COMPARE_ELSEWHERE}"
        ),
        TrustRefusalKind.KEY_MISMATCH_CONTROLLER: (
            "the access point was reset or re-adopted, or the controller's value is stale; this key is stored only "
            "once the controller reports it; if none of these holds, someone else may answer at this address: store "
            "nothing"
        ),
        TrustRefusalKind.STORED_KEY_REJECTED_PIN: (
            "the stored key still answers and the scan keeps using it; the pin in `sites.{site}.ssh.host_keys` names "
            "another key: check that value (a typo, another access point's fingerprint) before you change anything"
        ),
        TrustRefusalKind.STORED_KEY_REJECTED_CONTROLLER: (
            "the stored key still answers and the scan keeps using it; the fingerprint the controller reports names "
            "another key: check that value (stale, another device) before you change anything"
        ),
        TrustRefusalKind.SOURCES_DISAGREE: (
            f"compare both values with the access point's key {_COMPARE_ELSEWHERE}; correct "
            "`sites.{site}.ssh.host_keys` when the pin is wrong, otherwise find out why the controller reports "
            "another key (reset, re-adoption); the two may also name different key types of the same access point: "
            "then pin the key the controller reports"
        ),
        TrustRefusalKind.UNUSABLE_KEYS: _REPORT_WITH_FIRMWARE,
        TrustRefusalKind.SEVERAL_STORED_LINES: (
            "delete every line of that alias from that file (OpenSSH trusts any of them), then run "
            "`trust-host-keys --site {site}{options}`, which handles the key as one not yet stored"
        ),
        TrustRefusalKind.STORE_CHANGED: (
            "the store changed while this access point was being handled (another run of the tool, or an edit by "
            "hand); run again"
        ),
        TrustRefusalKind.NOT_ON_CONTROLLER_NAMED: (
            "check the spelling; `unifiwifioptimizer site {site}` lists the names (quote a name with blanks)"
        ),
        TrustRefusalKind.NOT_ON_CONTROLLER_CONFIGURED: (
            "the name under `sites.{site}.neighbors` is not on the controller; `unifiwifioptimizer site {site}` lists "
            "the names"
        ),
    }
)
