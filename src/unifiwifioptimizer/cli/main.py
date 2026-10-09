"""Argument parsing and dispatch; every subcommand is wired here and nowhere else."""

import argparse
import sys
from collections.abc import Callable, Sequence

from unifiwifioptimizer import __version__
from unifiwifioptimizer.cli.exit_codes import ExitCode
from unifiwifioptimizer.domain.errors import NotImplementedPathError, UwoError

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

Handler = Callable[[argparse.Namespace], ExitCode]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROG,
        description="Read-only RF-tuning and WLAN-baseline recommendations for UniFi access points.",
    )
    parser.add_argument("--version", action="version", version=f"{PROG} {__version__}")
    subparsers = parser.add_subparsers(dest="subcommand", metavar="<subcommand>", required=True)
    for name, help_text in SUBCOMMAND_HELP.items():
        subparsers.add_parser(name, help=help_text, description=help_text)
    return parser


def _not_implemented(name: str) -> Handler:
    def handler(_: argparse.Namespace) -> ExitCode:
        raise NotImplementedPathError(f"subcommand '{name}'")

    return handler


HANDLERS: dict[str, Handler] = {name: _not_implemented(name) for name in SUBCOMMAND_HELP}


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(HANDLERS[args.subcommand](args))
    except UwoError as exc:
        print(f"{PROG}: error: {exc}", file=sys.stderr)
        return int(ExitCode.UNEXPECTED_ERROR)
    except KeyboardInterrupt:
        print(f"{PROG}: interrupted", file=sys.stderr)
        return int(ExitCode.INTERRUPTED)
