"""Where the configuration file lives: explicit path, XDG config home, or the legacy data directory."""

import os
from dataclasses import dataclass
from pathlib import Path

APP_DIR = "unifiwifioptimizer"
FILE_NAME = "config.yaml"


@dataclass(frozen=True, slots=True)
class ConfigLocation:
    path: Path
    # The pre-rewrite install put the file under the data directory; it is still honoured, with a notice.
    legacy: bool


def default_config_path(environ: dict[str, str] | os._Environ[str] = os.environ) -> Path:
    base = environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / APP_DIR / FILE_NAME


def legacy_config_path(home: Path | None = None) -> Path:
    """Where the 0.4.x installer put the file: fixed under the home directory, whatever XDG_DATA_HOME says."""
    return (home or Path.home()) / ".local" / "share" / APP_DIR / FILE_NAME


def resolve_config_location(
    explicit: Path | None, environ: dict[str, str] | os._Environ[str] = os.environ, home: Path | None = None
) -> ConfigLocation:
    """`--config-file` wins; otherwise the XDG path, or the legacy path when only that one exists.

    The working directory is never searched: a repository checkout must not become a configuration source.
    """
    if explicit is not None:
        return ConfigLocation(explicit.expanduser(), legacy=False)
    default = default_config_path(environ)
    legacy = legacy_config_path(home)
    if not default.exists() and legacy.exists():
        return ConfigLocation(legacy, legacy=True)
    return ConfigLocation(default, legacy=False)
