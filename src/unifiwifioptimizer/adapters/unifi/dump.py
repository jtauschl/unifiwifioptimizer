"""`--dump-api`: what the tool read, per endpoint, without the controller's raw payload.

Each file holds the typed models the adapter produced (secrets masked) plus, per record path, the count
of keys the parser never read. Field names or values the tool does not use are never written — the count
alone shows controller drift; the operator fetches the raw endpoint with curl when a name is needed.
"""

import json
import os
import stat
from collections import defaultdict
from pathlib import Path
from typing import Any

from unifiwifioptimizer.domain.errors import ConfigError
from unifiwifioptimizer.domain.plain import MASK, SecretPolicy, plain
from unifiwifioptimizer.domain.secrets import is_secret_key


def redact(value: Any) -> Any:
    """Mask every value under a secret-looking key, at any depth; a second line of defence after the projection."""
    if isinstance(value, dict):
        return {k: (MASK if isinstance(k, str) and is_secret_key(k) else redact(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    return value


class DumpWriter:
    """Collects unread-key counts per endpoint while the client parses, then writes one file per endpoint."""

    def __init__(self, directory: Path) -> None:
        self._directory = directory
        self._unknown: dict[str, dict[str, int]] = defaultdict(dict)

    def observe_unknown_keys(self, endpoint: str, record_path: str, count: int) -> None:
        self._unknown[endpoint][record_path] = count

    def write(self, label: str, result: object) -> Path:
        """One file named after `label` with the models and the unread-key counts of every endpoint the
        client touched for it (`{endpoint: {record path: count}}`)."""
        name = label.strip("/").replace("/", "_") + ".json"
        document = {
            "label": label,
            "models": redact(plain(result, SecretPolicy.MASK)),
            "unknown_field_count": {
                endpoint: dict(sorted(records.items())) for endpoint, records in sorted(self._unknown.items())
            },
        }
        self._unknown.clear()
        target = self._directory / name
        try:
            self._directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            # Same chain as the configuration file: the directory itself (no symlink, ours, private), then
            # the file relative to that descriptor, so nothing can be swapped in between.
            dir_fd = os.open(self._directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except OSError as exc:
            raise ConfigError("--dump-api", f"cannot open directory {self._directory} ({exc.strerror})") from None
        try:
            st = os.fstat(dir_fd)
            if st.st_uid != os.getuid():
                raise ConfigError("--dump-api", "the directory is not owned by the current user")
            if stat.S_IMODE(st.st_mode) & 0o077:
                raise ConfigError("--dump-api", "the directory must not be accessible to other users (chmod 700)")
            try:
                fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600, dir_fd=dir_fd)
            except OSError as exc:
                raise ConfigError("--dump-api", f"cannot write {target} ({exc.strerror})") from None
        finally:
            os.close(dir_fd)
        try:
            # O_CREAT's mode applies to new files only; an existing file keeps its mode unless told otherwise.
            os.fchmod(fd, 0o600)
        except OSError as exc:
            os.close(fd)
            raise ConfigError("--dump-api", f"cannot write {target} ({exc.strerror})") from None
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(document, handle, indent=2, sort_keys=True)
            handle.write("\n")
        return target
