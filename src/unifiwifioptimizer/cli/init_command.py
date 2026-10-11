"""`init`: write a first configuration file interactively, never over an existing one."""

import getpass
from collections.abc import Callable
from pathlib import Path

from unifiwifioptimizer.config.loader import parse_yaml, write_new_private_file
from unifiwifioptimizer.config.schema import Config
from unifiwifioptimizer.domain.errors import ConfigError
from unifiwifioptimizer.report.skeleton import yaml_scalar

Prompt = Callable[[str], str]


def initial_config_text(url: str, api_key: str, fingerprint: str | None) -> str:
    """The minimal file; the parser must accept it, so every value goes through the strict scalar quoting."""
    lines = ["controller:", f"  url: {yaml_scalar(url)}", f"  api_key: {yaml_scalar(api_key)}"]
    if fingerprint:
        lines.append(f"  cert_fingerprint: {yaml_scalar(fingerprint)}")
    lines += [
        "",
        "# Add sites with `unifiwifioptimizer config <site-id> >> <this file>` once the connection works;",
        "# the skeleton that command prints is indented to sit under this key.",
        "sites:",
        "",
    ]
    return "\n".join(lines)


def run_init(path: Path, prompt: Prompt = input, secret_prompt: Prompt = getpass.getpass) -> Path:
    """Ask for the controller URL, the API key and an optional certificate fingerprint; validate; write 0600."""
    if path.exists():
        raise ConfigError(str(path), "already exists; remove it first or edit it in place")
    url = prompt("Controller URL (https://host[:port]): ").strip()
    api_key = secret_prompt("API key (input hidden): ").strip()
    fingerprint = prompt("Certificate fingerprint from `controller-fingerprint` (empty for CA verification): ").strip()
    text = initial_config_text(url, api_key, fingerprint or None)
    Config.from_mapping(parse_yaml(text, "init"))
    write_new_private_file(path, text)
    return path
