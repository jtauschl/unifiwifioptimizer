"""Configuration entry point: locate, read, parse, type; environment secrets consumed on the way."""

import os
import shlex
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from unifiwifioptimizer.config.loader import parse_yaml, read_private_file
from unifiwifioptimizer.config.locations import ConfigLocation, resolve_config_location
from unifiwifioptimizer.config.schema import Config, SiteConfig, SshAuth
from unifiwifioptimizer.domain.errors import MAX_ERROR_CHARS, ConfigError, ConfigNotFoundError
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


def _creation_hint(explicit: Path | None, found_at: str) -> str:
    """The command that creates the missing file. `--config-file` is a global option (before the subcommand) and
    `init` writes where it points; the `=` form also takes a name that starts with a dash. A name with a character the
    terminal would not show as typed, or one whose complete error line would be cut at `MAX_ERROR_CHARS` (the path
    is printed twice, and shell quoting can lengthen it), gets no command to copy: the text that reaches the terminal
    is sanitised and capped."""
    if explicit is None:
        return "`unifiwifioptimizer init` creates it"
    text = str(explicit)
    command = f"not found; `unifiwifioptimizer --config-file={shlex.quote(text)} init` creates it"
    if text.isprintable() and len(f"{found_at}: {command}") <= MAX_ERROR_CHARS:
        return command.removeprefix("not found; ")
    return "the init subcommand creates it, with the global --config-file option naming the same file"


def load_config(explicit: Path | None = None) -> LoadedConfig:
    location = resolve_config_location(explicit)
    try:
        text = read_private_file(location.path)
    except ConfigNotFoundError as exc:
        raise ConfigNotFoundError(exc.path, f"not found; {_creation_hint(explicit, exc.path)}") from None
    document = parse_yaml(text, str(location.path))
    config = Config.from_mapping(document, env_api_key=take_env_secret(API_KEY_ENV))
    env_password = take_env_secret(SSH_PASSWORD_ENV)
    return LoadedConfig(
        config=config, location=location, env_ssh_password=Secret(env_password) if env_password else None
    )


def require_scan_passwords(loaded: LoadedConfig, sites: Iterable[SiteConfig]) -> None:
    """Every one of `sites` that scans in password mode has a password, in the file or in the environment.

    Checked once by `run` for the sites it is about to scan and never by the controller-only subcommands or
    by `trust-host-keys` (which authenticates nothing): an SSH password that is merely absent must not keep
    `sites` or `site` from working, nor a site the run was not asked for.
    """
    for site in sites:
        if (
            site.scans
            and site.ssh is not None
            and site.ssh.auth is SshAuth.PASSWORD
            and site.ssh.password is None
            and loaded.env_ssh_password is None
        ):
            raise ConfigError(f"sites.{site.id}.ssh.password", f"missing; set it in the file or in {SSH_PASSWORD_ENV}")
