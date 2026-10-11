"""The one textual form of a SHA-256 fingerprint the tool shows and accepts."""

import base64


def format_fingerprint(digest: bytes) -> str:
    """OpenSSH's `SHA256:<unpadded base64>` form, which the configuration schema accepts verbatim."""
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")
