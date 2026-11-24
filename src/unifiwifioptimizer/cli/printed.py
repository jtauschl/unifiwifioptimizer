"""The printed commands of one invocation: the one place that quotes a user path for a command line.

A path is printed as typed, quoted for a POSIX shell, when the terminal shows it as typed and a person can paste it
back whole. A path that is not printable, that holds a backtick (it would end the backticked command span early, and a
fold inside the quotes would name another file), or whose quoted word exceeds the bound is withheld: the option is
printed with an empty value and a note after the command says to fill it in. Every stand-in a shell can read does
something in some shell (`<…>` reads a file, `(…)` runs in `zsh` with `SH_GLOB`); an empty value reaches the parser
unchanged in every shell tried, and the parser refuses it before anything is read.
"""

import shlex
from pathlib import Path

from unifiwifioptimizer.domain.commands import CONFIG_FILE_OPTION, KNOWN_HOSTS_OPTION, PrintedCommands
from unifiwifioptimizer.domain.errors import MAX_PATH_CHARS


def printed_commands(config_file: Path | None, known_hosts: Path | None) -> PrintedCommands:
    config_option, config_withheld = _option(CONFIG_FILE_OPTION, config_file)
    store_option, store_withheld = _option(KNOWN_HOSTS_OPTION, known_hosts)
    return PrintedCommands(
        config_option=config_option,
        store_option=store_option,
        withheld=tuple(
            name
            for name, withheld in ((CONFIG_FILE_OPTION, config_withheld), (KNOWN_HOSTS_OPTION, store_withheld))
            if withheld
        ),
    )


def _option(name: str, path: Path | None) -> tuple[str, bool]:
    """The option text with its leading blank, and whether the value was withheld."""
    if path is None:
        return "", False
    text = str(path)
    quoted = shlex.quote(text)
    if not text.isprintable() or "`" in text or len(quoted) > MAX_PATH_CHARS:
        return f" {name}=", True
    return f" {name}={quoted}", False
