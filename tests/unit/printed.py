"""Printed-command values for tests: the plain one (a run given no file option) and the CLI builder's own."""

from pathlib import Path

from unifiwifioptimizer.cli.printed import printed_commands
from unifiwifioptimizer.domain.commands import PrintedCommands
from unifiwifioptimizer.domain.scan import TrustStepContext

PLAIN = PrintedCommands(config_option="", store_option="", withheld=())
PLAIN_STEPS = TrustStepContext(gate_ran=False, commands=PLAIN)


def given(*, config_file: str | None = None, known_hosts: str | None = None) -> PrintedCommands:
    """The commands of a run given these options, built as the CLI builds them."""
    return printed_commands(
        Path(config_file) if config_file is not None else None, Path(known_hosts) if known_hosts is not None else None
    )
