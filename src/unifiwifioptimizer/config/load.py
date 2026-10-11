"""Configuration entry point: locate, read, parse, type; environment secrets consumed on the way."""

import os
from dataclasses import dataclass
from pathlib import Path

from unifiwifioptimizer.config.loader import parse_yaml, read_private_file
from unifiwifioptimizer.config.locations import ConfigLocation, resolve_config_location
from unifiwifioptimizer.config.schema import Config, SshAuth
from unifiwifioptimizer.domain.errors import ConfigError
from unifiwifioptimizer.domain.secrets import Secret

API_KEY_ENV = "UNIFI_API_KEY"
# The variable's name, not a credential.
SSH_PASSWORD_ENV = "UNIFI_SSH_PASSWORD"  # noqa: S105 # nosec B105


@dataclass(frozen=True, slots=True)
class LoadedConfig:
    config: Config
    location: ConfigLocation
    # The `UNIFI_SSH_PASSWORD` value; it applies to every site in password mode whose file entry has no
    # password and is ignored by the other sites.
    env_ssh_password: Secret | None


def take_env_secret(name: str, environ: os._Environ[str] = os.environ) -> str | None:
    """Read and remove an environment secret so child processes never inherit it."""
    return environ.pop(name, None) or None


def load_config(explicit: Path | None = None) -> LoadedConfig:
    location = resolve_config_location(explicit)
    text = read_private_file(location.path)
    document = parse_yaml(text, str(location.path))
    config = Config.from_mapping(document, env_api_key=take_env_secret(API_KEY_ENV))
    env_password = take_env_secret(SSH_PASSWORD_ENV)
    return LoadedConfig(
        config=config, location=location, env_ssh_password=Secret(env_password) if env_password else None
    )


def require_scan_passwords(loaded: LoadedConfig) -> None:
    """Every site that scans in password mode has a password, in the file or in the environment.

    Checked once by `run` before the first scan and never by the controller-only subcommands or by
    `trust-host-keys` (which authenticates nothing): an SSH password that is merely absent must not keep
    `sites` or `site` from working.
    """
    for site in loaded.config.sites.values():
        if (
            site.scans
            and site.ssh is not None
            and site.ssh.auth is SshAuth.PASSWORD
            and site.ssh.password is None
            and loaded.env_ssh_password is None
        ):
            raise ConfigError(f"sites.{site.id}.ssh.password", f"missing; set it in the file or in {SSH_PASSWORD_ENV}")
