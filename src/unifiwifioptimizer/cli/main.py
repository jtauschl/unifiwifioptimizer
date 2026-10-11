"""Argument parsing and dispatch; every subcommand is wired here and nowhere else.

`_exit_code_for` implements the exit-code contract of `cli/exit_codes.py`: configuration and environment
failures end the run before anything is contacted, TLS failures carry their own code, and everything the
tool did not foresee is 1.
"""

import argparse
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

from unifiwifioptimizer import __version__
from unifiwifioptimizer.adapters.unifi.client import UnifiClient
from unifiwifioptimizer.adapters.unifi.dump import DumpWriter
from unifiwifioptimizer.adapters.unifi.tls import TlsPolicy, observe_fingerprint
from unifiwifioptimizer.app import use_cases
from unifiwifioptimizer.cli.exit_codes import ExitCode
from unifiwifioptimizer.cli.init_command import run_init
from unifiwifioptimizer.config.load import LoadedConfig, load_config
from unifiwifioptimizer.config.locations import resolve_config_location
from unifiwifioptimizer.config.schema import parse_controller_url
from unifiwifioptimizer.domain.errors import (
    ConfigError,
    NotImplementedPathError,
    TlsError,
    ToolEnvironmentError,
    UwoError,
)
from unifiwifioptimizer.domain.fingerprints import format_fingerprint
from unifiwifioptimizer.report.safe_text import safe_text
from unifiwifioptimizer.report.skeleton import render_skeleton
from unifiwifioptimizer.report.text import render_site, render_sites

PROG = "unifiwifioptimizer"

SUBCOMMAND_HELP: dict[str, str] = {
    "run": "analyse every configured site and print recommendations",
    "sites": "list the sites the controller exposes",
    "site": "show one site's access points and WLANs",
    "config": "print a configuration skeleton for a site",
    "init": "create a configuration file interactively",
    "controller-fingerprint": "print the controller's TLS certificate fingerprint for pinning",
    "trust-host-keys": "record the access points' SSH host keys after verifying them",
}
SITE_SUBCOMMANDS = frozenset({"site", "config"})
MAX_ERROR_CHARS = 2048

Handler = Callable[[argparse.Namespace], ExitCode]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROG,
        description="Read-only RF-tuning and WLAN-baseline recommendations for UniFi access points.",
    )
    parser.add_argument("--version", action="version", version=f"{PROG} {__version__}")
    parser.add_argument(
        "--config-file",
        type=Path,
        metavar="PATH",
        help="configuration file (default: $XDG_CONFIG_HOME/%(prog)s/config.yaml)",
    )
    parser.add_argument(
        "--dump-api", type=Path, metavar="DIR", help="write what was read from each endpoint (models, masked) into DIR"
    )
    subparsers = parser.add_subparsers(dest="subcommand", metavar="<subcommand>", required=True)
    for name, help_text in SUBCOMMAND_HELP.items():
        sub = subparsers.add_parser(name, help=help_text, description=help_text)
        if name in SITE_SUBCOMMANDS:
            sub.add_argument("site", help="site id (or its description when unambiguous)")
        if name == "controller-fingerprint":
            sub.add_argument("--url", help="controller URL when no configuration file exists yet")
    return parser


def _client(loaded: LoadedConfig, args: argparse.Namespace) -> tuple[UnifiClient, DumpWriter | None]:
    controller = loaded.config.controller
    policy = TlsPolicy.from_options(controller.ca_cert, controller.cert_fingerprint)
    dump = DumpWriter(args.dump_api) if args.dump_api is not None else None
    client = UnifiClient(controller, policy, observe_unknown_keys=dump.observe_unknown_keys if dump else None)
    return client, dump


def _sites(args: argparse.Namespace) -> ExitCode:
    loaded = load_config(args.config_file)
    _warn_legacy(loaded)
    client, dump = _client(loaded, args)
    overview = use_cases.list_sites(client)
    if dump is not None:
        dump.write("self/sites", overview)
    print(render_sites(overview), end="")
    return ExitCode.OK


def _site(args: argparse.Namespace) -> ExitCode:
    loaded = load_config(args.config_file)
    _warn_legacy(loaded)
    client, dump = _client(loaded, args)
    overview = use_cases.show_site(client, args.site)
    if dump is not None:
        dump.write(f"s/{overview.site.id}", overview)
    print(render_site(overview), end="")
    return ExitCode.OK


def _config(args: argparse.Namespace) -> ExitCode:
    loaded = load_config(args.config_file)
    _warn_legacy(loaded)
    client, dump = _client(loaded, args)
    overview = use_cases.show_site(client, args.site, with_mgmt=True)
    if dump is not None:
        dump.write(f"s/{overview.site.id}/config", overview)
    print(render_skeleton(overview), end="")
    return ExitCode.OK


def _init(args: argparse.Namespace) -> ExitCode:
    location = resolve_config_location(args.config_file)
    path = run_init(location.path)
    print(f"{PROG}: wrote {path} (mode 0600)", file=sys.stderr)
    return ExitCode.OK


def _controller_fingerprint(args: argparse.Namespace) -> ExitCode:
    if args.url is not None:
        host, port = parse_controller_url(args.url, "--url")
    else:
        controller = load_config(args.config_file).config.controller
        host, port = controller.host, controller.port
    digest = observe_fingerprint(host, port)
    print(format_fingerprint(digest))
    print(
        f"{PROG}: this is what {host}:{port} presented right now (trust on first use); "
        "compare it against the controller's own certificate view before pinning it as controller.cert_fingerprint",
        file=sys.stderr,
    )
    return ExitCode.OK


def _warn_legacy(loaded: LoadedConfig) -> None:
    if loaded.location.legacy:
        print(
            f"{PROG}: reading the legacy configuration at {loaded.location.path}; move it to "
            "$XDG_CONFIG_HOME/unifiwifioptimizer/config.yaml",
            file=sys.stderr,
        )


def _not_implemented(name: str) -> Handler:
    def handler(_: argparse.Namespace) -> ExitCode:
        raise NotImplementedPathError(f"subcommand '{name}'")

    return handler


HANDLERS: dict[str, Handler] = {
    "run": _not_implemented("run"),
    "sites": _sites,
    "site": _site,
    "config": _config,
    "init": _init,
    "controller-fingerprint": _controller_fingerprint,
    "trust-host-keys": _not_implemented("trust-host-keys"),
}


def _exit_code_for(exc: UwoError) -> ExitCode:
    if isinstance(exc, ConfigError):
        return ExitCode.CONFIG
    if isinstance(exc, TlsError):
        return ExitCode.TLS
    if isinstance(exc, ToolEnvironmentError):
        return ExitCode.ENVIRONMENT
    return ExitCode.UNEXPECTED_ERROR


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(HANDLERS[args.subcommand](args))
    except UwoError as exc:
        # Error texts carry user and controller strings; the terminal gets them only through safe_text.
        print(f"{PROG}: error: {safe_text(str(exc), max_chars=MAX_ERROR_CHARS)}", file=sys.stderr)
        return int(_exit_code_for(exc))
    except KeyboardInterrupt:
        print(f"{PROG}: interrupted", file=sys.stderr)
        return int(ExitCode.INTERRUPTED)
