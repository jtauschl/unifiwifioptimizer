"""Host-key identity of an access point: the alias OpenSSH looks up and the fingerprint forms we compare.

An access point is pinned by (controller origin, site id, MAC), never by its IP: IPs move, and a
hostname-based entry would let a controller-supplied address pick which key is trusted.
"""

import hashlib
import re
from base64 import b64decode, b64encode
from dataclasses import dataclass
from enum import StrEnum

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
